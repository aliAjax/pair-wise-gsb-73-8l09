import type {
  ControlEvidence,
  ReviewDecision,
  Risk,
  Severity,
  Threat,
  ThreatModelState,
  ValidationIssue,
  VersionDifference,
  VersionSnapshot,
} from '@/models/domain'

const TODAY = new Date('2026-09-29T00:00:00+08:00')

export const riskScore = (risk: Risk): number => risk.likelihood * risk.impact

export const riskLevel = (score: number): Severity => {
  if (score >= 20) return 'critical'
  if (score >= 12) return 'high'
  if (score >= 6) return 'medium'
  return 'low'
}

export const isExpired = (date?: string): boolean =>
  Boolean(date && new Date(`${date}T23:59:59+08:00`).getTime() < TODAY.getTime())

export const evidenceIsExpired = (evidence: ControlEvidence): boolean => isExpired(evidence.expiresAt)

export const getValidationIssues = (state: ThreatModelState): ValidationIssue[] => {
  const issues: ValidationIssue[] = []
  const coveredComponentIds = new Set(state.threats.flatMap((threat) => threat.componentIds))
  const coveredFlowIds = new Set(state.threats.flatMap((threat) => threat.flowIds))

  state.components
    .filter((component) => !coveredComponentIds.has(component.id))
    .forEach((component) => {
      issues.push({
        id: `coverage-component-${component.id}`,
        kind: 'uncovered_component',
        severity: component.criticality,
        title: `${component.name} 尚无关联威胁`,
        detail: '该组件位于建模边界内，但当前威胁清单没有覆盖它。',
        entityId: component.id,
      })
    })

  state.flows
    .filter((flow) => !coveredFlowIds.has(flow.id))
    .forEach((flow) => {
      issues.push({
        id: `coverage-flow-${flow.id}`,
        kind: 'uncovered_component',
        severity: flow.crossesTrustBoundary ? 'high' : 'medium',
        title: `${flow.name} 尚无关联威胁`,
        detail: '该数据流未进入威胁分析，请确认是否需要补充威胁场景。',
        entityId: flow.id,
      })
    })

  state.controls
    .filter((control) => control.status === 'failed' || control.status === 'degraded')
    .forEach((control) => {
      issues.push({
        id: `control-${control.id}`,
        kind: 'control_failed',
        severity: control.status === 'failed' ? 'critical' : 'high',
        title: `${control.name} 控制${control.status === 'failed' ? '已失效' : '能力降级'}`,
        detail: '控制状态低于设计目标，相关缓解措施必须重新验证。',
        entityId: control.id,
      })
    })

  state.controls
    .filter((control) => {
      if (control.evidenceIds.length === 0) return true
      const validEvidence = control.evidenceIds
        .map((id) => state.evidence.find((item) => item.id === id))
        .filter((item): item is ControlEvidence => Boolean(item))
        .filter((item) => item.valid && !evidenceIsExpired(item))
      return validEvidence.length === 0
    })
    .forEach((control) => {
      issues.push({
        id: `evidence-${control.id}`,
        kind: 'missing_evidence',
        severity: control.status === 'planned' ? 'medium' : 'high',
        title: `${control.name} 缺少有效证据`,
        detail: '未找到未过期且状态有效的控制证据，暂不能判定控制持续有效。',
        entityId: control.id,
      })
    })

  state.risks
    .filter((risk) => risk.status === 'accepted' && isExpired(risk.acceptanceExpiresAt))
    .forEach((risk) => {
      issues.push({
        id: `expired-${risk.id}`,
        kind: 'risk_acceptance_expired',
        severity: riskLevel(riskScore(risk)),
        title: `${risk.code} 风险接受已过期`,
        detail: `接受到期日为 ${risk.acceptanceExpiresAt ?? '未设置'}，需要重新评审或转为处置。`,
        entityId: risk.id,
      })
    })

  // 风险接受的修订依据落后于关联威胁当前修订：控制/证据改动后已失效，需要重新接受并重新会签
  state.threats.forEach((threat) => {
    threat.riskIds.forEach((riskId) => {
      const risk = state.risks.find((item) => item.id === riskId)
      if (!risk) return
      // 风险接受的修订依据落后于关联威胁：控制/证据改动使接受失效（状态已转回处置中）
      if (
        risk.status !== 'accepted' &&
        typeof risk.acceptanceRevision === 'number' &&
        !isRiskAcceptanceCurrent(risk, threat.revision)
      ) {
        issues.push({
          id: `acceptance-stale-${risk.id}`,
          kind: 'risk_acceptance_invalidated',
          severity: riskLevel(riskScore(risk)),
          title: `${risk.code} 风险接受已随修订失效`,
          detail: `接受依据为 v1.${risk.acceptanceRevision}，关联威胁已进入 v1.${threat.revision}，需在新修订上重新接受并会签。`,
          entityId: risk.id,
        })
      }
    })
  })

  // 并发保存后保留为草稿、待确认的威胁
  state.threats
    .filter((threat) => threat.pendingConfirmation)
    .forEach((threat) => {
      issues.push({
        id: `pending-confirmation-${threat.id}`,
        kind: 'pending_confirmation',
        severity: 'high',
        title: `${threat.code} 存在待确认的并发修订`,
        detail: '该威胁在另一标签页已被保存，当前草稿被保留为待确认，需选择采用草稿或放弃。',
        entityId: threat.id,
      })
    })

  const taskGroups = new Map<string, typeof state.mitigations>()
  state.mitigations.forEach((task) => {
    if (!task.conflictGroup) return
    const key = `${task.threatId}:${task.conflictGroup}`
    const group = taskGroups.get(key) ?? []
    group.push(task)
    taskGroups.set(key, group)
  })

  taskGroups.forEach((tasks) => {
    const actions = new Set(tasks.map((task) => task.action))
    const hasAllow = actions.has('allow_with_condition')
    const hasRestrictiveAction = actions.has('restrict') || actions.has('isolate')
    if (hasAllow && hasRestrictiveAction) {
      issues.push({
        id: `conflict-${tasks[0]?.conflictGroup ?? 'unknown'}`,
        kind: 'mitigation_conflict',
        severity: 'high',
        title: '缓解措施处置方向冲突',
        detail: tasks.map((task) => task.title).join('；'),
        entityId: tasks[0]?.threatId ?? '',
      })
    }
  })

  return issues.sort((a, b) => {
    const rank: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 }
    return rank[b.severity] - rank[a.severity]
  })
}

export const decisionsForThreat = (
  decisions: ReviewDecision[],
  threatId: string,
  revision: number,
): ReviewDecision[] =>
  decisions.filter((decision) => decision.threatId === threatId && decision.revision === revision)

/** 当前有效修订上的会签意见（旧修订上的会签不再生效） */
export const effectiveDecisionsForThreat = (
  state: ThreatModelState,
  threat: Threat,
): ReviewDecision[] => decisionsForThreat(state.decisions, threat.id, threat.revision)

/** 风险接受是否仍建立在威胁当前修订之上 */
export const isRiskAcceptanceCurrent = (risk: Risk, threatRevision: number): boolean =>
  typeof risk.acceptanceRevision === 'number' && risk.acceptanceRevision >= threatRevision

/** 威胁的任一关联风险存在失效/过期接受，放行（三方 approved）前必须先处理 */
export const threatHasStaleAcceptance = (state: ThreatModelState, threat: Threat): boolean =>
  threat.riskIds.some((riskId) => {
    const risk = state.risks.find((item) => item.id === riskId)
    if (!risk) return false
    if (typeof risk.acceptanceRevision !== 'number') return false
    // 依据修订落后（接受已随控制/证据改动失效）或接受仍在但已过期
    return (
      !isRiskAcceptanceCurrent(risk, threat.revision) ||
      (risk.status === 'accepted' && isExpired(risk.acceptanceExpiresAt))
    )
  })

/** 该威胁当前是否需要在最新修订上重新会签 */
export const threatNeedsResign = (state: ThreatModelState, threat: Threat): boolean => {
  const decisions = effectiveDecisionsForThreat(state, threat)
  const roles = new Set(decisions.map((decision) => decision.role))
  const threeRoles = roles.size >= 3
  const approved =
    threeRoles && decisions.every((decision) => decision.decision === 'approved')
  return (
    !threat.pendingConfirmation &&
    threat.reviewStatus !== 'draft' &&
    (!approved || threatHasStaleAcceptance(state, threat))
  )
}

/** 需要进入会签中心的威胁：审核中/被驳回/三方未齐/风险接受失效，且不含待确认草稿 */
export const reviewQueue = (state: ThreatModelState): Threat[] =>
  state.threats.filter(
    (threat) =>
      !threat.pendingConfirmation &&
      (threat.reviewStatus === 'in_review' ||
        threat.reviewStatus === 'rejected' ||
        threatHasStaleAcceptance(state, threat)),
  )

/** 并发保存后待确认的威胁草稿 */
export const pendingConfirmationThreats = (state: ThreatModelState): Threat[] =>
  state.threats.filter((threat) => threat.pendingConfirmation)

export const reviewProgress = (decisions: ReviewDecision[]): number => {
  const roles = new Set(decisions.map((decision) => decision.role))
  return Math.round((roles.size / 3) * 100)
}

export const compareSnapshots = (from: VersionSnapshot, to: VersionSnapshot): VersionDifference => {
  const compare = (
    category: string,
    before: string[],
    after: string[],
  ): { added: VersionDifference['added']; removed: VersionDifference['removed'] } => {
    const beforeSet = new Set(before)
    const afterSet = new Set(after)
    return {
      added: after.filter((id) => !beforeSet.has(id)).map((id) => ({ category, id })),
      removed: before.filter((id) => !afterSet.has(id)).map((id) => ({ category, id })),
    }
  }

  const componentDiff = compare('组件', from.componentIds, to.componentIds)
  const flowDiff = compare('数据流', from.flowIds, to.flowIds)
  const threatDiff = compare('威胁', from.threatIds, to.threatIds)
  const controlDiff = compare('控制', from.controlIds, to.controlIds)
  const riskDiff = compare('风险', from.riskIds, to.riskIds)
  const affectedBefore = new Set(from.affectedThreatIds)
  const affectedAfter = new Set(to.affectedThreatIds)

  return {
    added: [
      ...componentDiff.added,
      ...flowDiff.added,
      ...threatDiff.added,
      ...controlDiff.added,
      ...riskDiff.added,
    ],
    removed: [
      ...componentDiff.removed,
      ...flowDiff.removed,
      ...threatDiff.removed,
      ...controlDiff.removed,
      ...riskDiff.removed,
    ],
    changed: [
      `受影响威胁：${from.affectedThreatIds.length} → ${to.affectedThreatIds.length}`,
      `新增进入审核：${[...affectedAfter].filter((id) => !affectedBefore.has(id)).join('、') || '无'}`,
      `退出审核：${[...affectedBefore].filter((id) => !affectedAfter.has(id)).join('、') || '无'}`,
      `版本说明：${to.notes || '未填写'}`,
    ],
  }
}

export const threatCoverage = (state: ThreatModelState): number => {
  if (state.components.length === 0) return 100
  const covered = new Set(state.threats.flatMap((threat) => threat.componentIds))
  return Math.round((covered.size / state.components.length) * 100)
}

export const openCriticalThreats = (threats: Threat[]): number =>
  threats.filter((threat) => threat.severity === 'critical' && threat.status !== 'mitigated').length

export interface DashboardMetrics {
  components: number
  threats: number
  critical: number
  coverage: number
  openIssues: number
  pendingReviews: number
}

export const dashboardMetrics = (state: ThreatModelState): DashboardMetrics => ({
  components: state.components.length,
  threats: state.threats.length,
  critical: openCriticalThreats(state.threats),
  coverage: threatCoverage(state),
  openIssues: getValidationIssues(state).length,
  pendingReviews: state.threats.filter((threat) => threat.reviewStatus === 'in_review').length,
})
