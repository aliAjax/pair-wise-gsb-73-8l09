import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import type {
  ActorRole,
  AuditEvent,
  DecisionType,
  RevisionOperation,
  RevisionReason,
  Risk,
  SecurityControl,
  Threat,
  ThreatModelState,
  VersionSnapshot,
} from '@/models/domain'
import {
  commitRevision,
  createId,
  getRevisionChain,
  loadState,
  readCommittedState,
  resetState,
  saveState,
} from '@/services/repository'
import {
  dashboardMetrics,
  decisionsForThreat,
  effectiveDecisionsForThreat,
  getValidationIssues,
  pendingConfirmationThreats,
  reviewProgress,
  reviewQueue,
  threatHasStaleAcceptance,
} from '@/services/selectors'

type SimpleCollectionKey = 'zones' | 'dependencies' | 'mitigations' | 'components' | 'flows'

interface IdentifiedEntity {
  id: string
}

const REQUIRED_ROLES: ActorRole[] = ['development', 'security', 'business']

export interface SaveOutcome {
  conflict: boolean
  recoveredEntries: number
}

export const useThreatModelStore = defineStore('threat-model', () => {
  const initial = loadState()
  const data = ref<ThreatModelState>(initial.state)
  const lastSavedAt = ref(new Date().toISOString())
  const lastRecoveryNote = ref(
    initial.recoveredEntries > 0
      ? `检测到上次写入未完成，已从修订链补写 ${initial.recoveredEntries} 条记录`
      : initial.migrated
        ? '旧数据已回填修订依据并接入修订链'
        : '',
  )

  const metrics = computed(() => dashboardMetrics(data.value))
  const issues = computed(() => getValidationIssues(data.value))
  const pendingReviews = computed(() => reviewQueue(data.value))
  const pendingConfirmations = computed(() => pendingConfirmationThreats(data.value))
  const revisionChain = computed(() => data.value.revisionChain)

  const persist = (): void => {
    saveState(data.value)
    lastSavedAt.value = new Date().toISOString()
  }

  const appendAudit = (
    entityType: string,
    entityId: string,
    action: string,
    detail: string,
  ): AuditEvent => ({
    id: createId('aud'),
    entityType,
    entityId,
    action,
    actor: '当前用户',
    createdAt: new Date().toISOString(),
    detail,
  })

  /** 不进入修订链的普通集合（信任区、外部依赖、缓解任务）仍直接保存 */
  const saveEntity = (collection: SimpleCollectionKey, item: IdentifiedEntity): void => {
    const target = data.value[collection] as unknown as IdentifiedEntity[]
    const index = target.findIndex((entry) => entry.id === item.id)
    if (index >= 0) {
      target[index] = item
    } else {
      target.unshift(item)
    }
    const label = 'name' in item && typeof item.name === 'string' ? item.name : item.id
    data.value.audit.unshift(
      appendAudit(collection, item.id, index >= 0 ? '更新' : '新增', `${label} 已保存`),
    )
    persist()
  }

  const removeEntity = (collection: SimpleCollectionKey, id: string): void => {
    const target = data.value[collection] as unknown as IdentifiedEntity[]
    const index = target.findIndex((entry) => entry.id === id)
    if (index < 0) return
    target.splice(index, 1)
    data.value.audit.unshift(appendAudit(collection, id, '删除', '记录已从当前版本移除'))
    persist()
  }

  const updateBoundary = (boundary: ThreatModelState['boundary']): void => {
    data.value.boundary = boundary
    data.value.audit.unshift(
      appendAudit('boundary', boundary.id, '更新', `${boundary.name} 的系统边界已更新`),
    )
    persist()
  }

  /* ------------------------------ 修订链提交 ------------------------------ */

  /**
   * 与其他标签页已持久化的最新修订对齐后，原子提交一条修订。
   * 任何威胁/控制/证据/风险接受/会签的写入都走这里。
   */
  const commit = (
    reason: RevisionReason,
    detail: string,
    operations: RevisionOperation[],
    options: {
      bump?: boolean
      baseRevision?: number
      pending?: { threatId: string; winner: Threat }
    } = {},
  ): SaveOutcome => {
    const result = commitRevision(data.value, {
      reason,
      detail,
      operations,
      bump: options.bump ?? true,
      baseRevision: options.baseRevision,
      pending: options.pending
        ? { threatId: options.pending.threatId, winner: options.pending.winner }
        : undefined,
    })
    data.value = result.state
    lastSavedAt.value = new Date().toISOString()
    if (result.recoveredEntries > 0) {
      lastRecoveryNote.value = `主仓库写入失败，已从完整修订链补写 ${result.recoveredEntries} 条记录`
    }
    return { conflict: false, recoveredEntries: result.recoveredEntries }
  }

  /** 计算需要因组件/数据流/控制/证据改动而失效重算的威胁与风险（基于最新已提交状态） */
  const buildInvalidation = (
    base: ThreatModelState,
    revision: number,
    scope: {
      componentIds?: string[]
      flowIds?: string[]
      controlIds?: string[]
      evidenceControlIds?: string[]
    },
    reasonDetail: string,
    label: string,
  ): RevisionOperation[] => {
    const componentIds = new Set(scope.componentIds ?? [])
    const flowIds = new Set(scope.flowIds ?? [])
    const controlIds = new Set(scope.controlIds ?? [])

    // 证据改动：沿证据 -> 控制 -> 组件 传播
    ;(scope.evidenceControlIds ?? []).forEach((controlId) => {
      controlIds.add(controlId)
      const control = base.controls.find((item) => item.id === controlId)
      if (control?.componentId) componentIds.add(control.componentId)
    })
    // 控制改动：控制所属组件同样受影响
    controlIds.forEach((controlId) => {
      const control = base.controls.find((item) => item.id === controlId)
      if (control?.componentId) componentIds.add(control.componentId)
    })

    const affectedThreats = base.threats.filter(
      (threat) =>
        threat.componentIds.some((id) => componentIds.has(id)) ||
        threat.flowIds.some((id) => flowIds.has(id)) ||
        threat.controlIds.some((id) => controlIds.has(id)),
    )
    if (affectedThreats.length === 0) return []

    const affectedRiskIds = new Set(affectedThreats.flatMap((threat) => threat.riskIds))
    const operations: RevisionOperation[] = []

    affectedThreats.forEach((threat) => {
      operations.push({
        kind: 'upsert',
        collection: 'threats',
        item: {
          ...structuredClone(threat),
          revision,
          reviewStatus: 'in_review',
          pendingConfirmation: false,
          pendingBaseSnapshot: undefined,
        },
      })
    })

    affectedRiskIds.forEach((riskId) => {
      const risk = base.risks.find((item) => item.id === riskId)
      if (!risk || risk.status !== 'accepted') return
      operations.push({
        kind: 'upsert',
        collection: 'risks',
        item: {
          ...structuredClone(risk),
          // 接受立即失效：转回处置中，接受条件保留以便在新修订上重新接受
          status: 'mitigating' as Risk['status'],
        },
      })
    })

    operations.push({
      kind: 'upsert',
      collection: 'audit',
      item: appendAudit(
        'revision',
        `rev-${revision}`,
        label,
        `${reasonDetail}；${affectedThreats.length} 条关联威胁与风险接受失效，需在 v1.${revision} 重新会签。`,
      ),
    })
    return operations
  }

  /* --------------------------------- 威胁 --------------------------------- */

  /**
   * 保存威胁。编辑器打开时记住 baseRevision：
   * 若另一标签页已先保存（持久化修订更高），后到的保留草稿并转待确认。
   */
  const saveThreat = (threat: Threat, baseRevision: number): SaveOutcome => {
    const committed = readCommittedState()
    const existing = committed.threats.find((item) => item.id === threat.id)
    const isNew = !existing

    // 并发：本页打开后，该威胁在其他标签页已被保存到更高修订
    if (!isNew && existing.revision > baseRevision && !existing.pendingConfirmation) {
      const loser: Threat = {
        ...structuredClone(threat),
        revision: existing.revision, // 草稿挂在先到者的修订上，不再推进全局修订
        reviewStatus: 'draft',
        pendingConfirmation: true,
        pendingBaseSnapshot: structuredClone(existing),
      }
      const operations: RevisionOperation[] = [
        { kind: 'upsert', collection: 'threats', item: loser as unknown as Record<string, unknown> },
        {
          kind: 'upsert',
          collection: 'audit',
          item: appendAudit(
            'threat',
            loser.id,
            '并发保存待确认',
            `另一标签页已先保存 v1.${existing.revision}，后到草稿已保留并转待确认。`,
          ),
        },
      ]
      const outcome = commit(
        'threat_conflict',
        `${threat.code} 并发保存，后到草稿待确认`,
        operations,
        // 冲突本身不推进全局修订：草稿挂在先到者修订上，采用草稿时才推进
        { bump: false, pending: { threatId: loser.id, winner: structuredClone(existing) } },
      )
      return { ...outcome, conflict: true }
    }

    const revision = isNew
      ? committed.currentRevision
      : Math.max(committed.currentRevision, existing?.revision ?? 0) + 1
    const saved: Threat = {
      ...structuredClone(threat),
      revision,
      reviewStatus: isNew ? threat.reviewStatus : 'in_review',
      pendingConfirmation: false,
      pendingBaseSnapshot: undefined,
    }
    const operations: RevisionOperation[] = [
      { kind: 'upsert', collection: 'threats', item: saved as unknown as Record<string, unknown> },
      {
        kind: 'upsert',
        collection: 'audit',
        item: appendAudit(
          'threat',
          saved.id,
          isNew ? '新增' : '更新',
          isNew ? `${saved.title} 已登记为草稿` : `${saved.code} 修订到 v1.${revision}，进入重新审核`,
        ),
      },
    ]
    return commit(
      'threat_edit',
      isNew ? `新增威胁 ${saved.code}` : `${saved.code} 编辑触发 v1.${revision}`,
      operations,
      { bump: !isNew, baseRevision },
    )
  }

  /** 待确认草稿处理：采用草稿则推进到新修订并重新会签；放弃则恢复先到保存的版本 */
  const resolveThreatConflict = (
    threatId: string,
    resolution: 'apply_draft' | 'discard_draft',
    draft: Threat,
  ): SaveOutcome => {
    const committed = readCommittedState()
    const winner = committed.threats.find((item) => item.id === threatId)?.pendingBaseSnapshot
    if (!winner) return { conflict: false, recoveredEntries: 0 }

    if (resolution === 'discard_draft') {
      const restored: Threat = {
        ...structuredClone(winner),
        pendingConfirmation: false,
        pendingBaseSnapshot: undefined,
      }
      const operations: RevisionOperation[] = [
        { kind: 'upsert', collection: 'threats', item: restored as unknown as Record<string, unknown> },
        {
          kind: 'upsert',
          collection: 'audit',
          item: appendAudit('threat', threatId, '放弃并发草稿', `恢复先到保存的 v1.${winner.revision} 版本。`),
        },
      ]
      return commit('threat_edit', `${restored.code} 放弃并发草稿`, operations, { bump: false })
    }

    const revision = committed.currentRevision + 1
    const applied: Threat = {
      ...structuredClone(draft),
      id: threatId,
      revision,
      reviewStatus: 'in_review',
      pendingConfirmation: false,
      pendingBaseSnapshot: undefined,
    }
    const operations: RevisionOperation[] = [
      { kind: 'upsert', collection: 'threats', item: applied as unknown as Record<string, unknown> },
      {
        kind: 'upsert',
        collection: 'audit',
        item: appendAudit(
          'threat',
          threatId,
          '采用并发草稿',
          `草稿作为 v1.${revision} 生效，三方需在新修订上重新会签。`,
        ),
      },
    ]
    return commit('threat_edit', `${applied.code} 采用并发草稿进入 v1.${revision}`, operations, {
      bump: true,
    })
  }

  /* -------------------------------- 控制/证据 ------------------------------ */

  const saveControl = (control: SecurityControl, previous?: SecurityControl): SaveOutcome => {
    const committed = readCommittedState()
    const revision = committed.currentRevision + 1
    const saved: SecurityControl = {
      ...structuredClone(control),
      id: control.id || createId('ctl'),
      revision,
    }
    const operations: RevisionOperation[] = [
      { kind: 'upsert', collection: 'controls', item: saved as unknown as Record<string, unknown> },
      {
        kind: 'upsert',
        collection: 'audit',
        item: appendAudit(
          'control',
          saved.id,
          previous ? '控制变更' : '新增控制',
          `${saved.name} 修订到 v1.${revision}，关联威胁与风险接受立即失效重算。`,
        ),
      },
      ...buildInvalidation(
        committed,
        revision,
        {
          controlIds: [saved.id],
          componentIds: [saved.componentId, previous?.componentId].filter(
            (id): id is string => Boolean(id),
          ),
        },
        `控制 ${saved.name} 变更`,
        '控制变更联动失效',
      ),
    ]
    return commit('control_change', `控制 ${saved.name} 变更到 v1.${revision}`, operations, {
      bump: true,
    })
  }

  const saveEvidence = (
    evidence: ThreatModelState['evidence'][number],
    previous?: ThreatModelState['evidence'][number],
  ): SaveOutcome => {
    const committed = readCommittedState()
    const revision = committed.currentRevision + 1
    const saved = {
      ...structuredClone(evidence),
      id: evidence.id || createId('ev'),
      revision,
    }
    const operations: RevisionOperation[] = [
      { kind: 'upsert', collection: 'evidence', item: saved },
      {
        kind: 'upsert',
        collection: 'audit',
        item: appendAudit(
          'evidence',
          saved.id,
          previous ? '证据变更' : '登记证据',
          `${saved.title} 修订到 v1.${revision}，所属控制的关联威胁与风险接受立即失效重算。`,
        ),
      },
      ...buildInvalidation(
        committed,
        revision,
        {
          evidenceControlIds: [saved.controlId, previous?.controlId].filter(
            (id): id is string => Boolean(id),
          ),
        },
        `证据 ${saved.title} 变更`,
        '证据变更联动失效',
      ),
    ]
    return commit('evidence_change', `证据 ${saved.title} 变更到 v1.${revision}`, operations, {
      bump: true,
    })
  }

  /** 组件/数据流改动也让直接关联的威胁失效重算 */
  const saveArchitectureEntity = (
    collection: 'components' | 'flows',
    item: IdentifiedEntity,
    previous?: IdentifiedEntity,
  ): SaveOutcome => {
    const committed = readCommittedState()
    const revision = committed.currentRevision + 1
    const operations: RevisionOperation[] = [
      { kind: 'upsert', collection, item: item as unknown as Record<string, unknown> },
      ...buildInvalidation(
        committed,
        revision,
        collection === 'components'
          ? { componentIds: [item.id, previous?.id].filter((id): id is string => Boolean(id)) }
          : { flowIds: [item.id, previous?.id].filter((id): id is string => Boolean(id)) },
        'name' in item && typeof item.name === 'string' ? item.name : item.id,
        collection === 'components' ? '组件变更联动失效' : '数据流变更联动失效',
      ),
    ]
    return commit(
      collection === 'components' ? 'component_change' : 'flow_change',
      `架构实体 ${item.id} 变更到 v1.${revision}`,
      operations,
      { bump: true },
    )
  }

  /* --------------------------------- 会签 --------------------------------- */

  type SubmitDecisionResult =
    | { ok: true; reviewStatus: Threat['reviewStatus']; recoveredEntries: number }
    | { ok: false; reason: 'not_found' | 'pending_confirmation' | 'stale_acceptance'; message: string }

  const submitDecision = (
    threatId: string,
    role: ActorRole,
    decision: DecisionType,
    actor: string,
    comment: string,
  ): SubmitDecisionResult => {
    const committed = readCommittedState()
    const threat = committed.threats.find((item) => item.id === threatId)
    if (!threat) return { ok: false, reason: 'not_found', message: '威胁不存在' }
    if (threat.pendingConfirmation) {
      return { ok: false, reason: 'pending_confirmation', message: '该威胁存在待确认的并发草稿，请先处理后再会签' }
    }
    // 风险接受已失效或过期时，三方不能在新修订上直接放行
    if (decision === 'approved' && threatHasStaleAcceptance(committed, threat)) {
      return {
        ok: false,
        reason: 'stale_acceptance',
        message: '关联风险接受已随修订失效或过期，需在风险矩阵重新接受后才能放行',
      }
    }

    const reviewDecision = {
      id: createId('dec'),
      threatId,
      role,
      actor,
      decision,
      comment,
      createdAt: new Date().toISOString(),
      revision: threat.revision,
    }
    const current = decisionsForThreat(committed.decisions, threatId, threat.revision)
    const nextDecisions = [
      reviewDecision,
      ...current.filter((item) => item.role !== role),
    ]
    let reviewStatus: Threat['reviewStatus']
    if (nextDecisions.some((item) => item.decision === 'rejected')) {
      reviewStatus = 'rejected'
    } else if (
      REQUIRED_ROLES.every((requiredRole) =>
        nextDecisions.some((item) => item.role === requiredRole),
      ) &&
      nextDecisions.every((item) => item.decision === 'approved')
    ) {
      reviewStatus = 'approved'
    } else {
      reviewStatus = 'in_review'
    }

    const operations: RevisionOperation[] = [
      {
        kind: 'replace_decision',
        threatId,
        role,
        revision: threat.revision,
        item: reviewDecision,
      },
      {
        kind: 'upsert',
        collection: 'threats',
        item: {
          ...structuredClone(threat),
          reviewStatus,
        } as unknown as Record<string, unknown>,
      },
      {
        kind: 'upsert',
        collection: 'audit',
        item: appendAudit(
          'threat',
          threatId,
          '会签意见',
          `${actor}（${role}）在 v1.${threat.revision} 提交会签意见`,
        ),
      },
    ]
    const outcome = commit(
      'decision',
      `${threat.code} 会签意见（v1.${threat.revision}）`,
      operations,
      { bump: false },
    )
    return { ok: true, reviewStatus, recoveredEntries: outcome.recoveredEntries }
  }

  /* -------------------------------- 风险接受 ------------------------------- */

  const acceptRisk = (riskId: string, expiresAt: string, condition: string): SaveOutcome => {
    const committed = readCommittedState()
    const risk = committed.risks.find((item) => item.id === riskId)
    if (!risk) return { conflict: false, recoveredEntries: 0 }
    // 接受依据 = 关联威胁当前所处修订；新接受绑定到最新有效修订
    const linkedRevision = Math.max(
      0,
      ...committed.threats
        .filter((threat) => threat.riskIds.includes(riskId))
        .map((threat) => threat.revision),
    )
    const saved: Risk = {
      ...structuredClone(risk),
      status: 'accepted',
      acceptanceExpiresAt: expiresAt,
      acceptanceCondition: condition,
      acceptanceRevision: linkedRevision,
    }
    const operations: RevisionOperation[] = [
      { kind: 'upsert', collection: 'risks', item: saved as unknown as Record<string, unknown> },
      {
        kind: 'upsert',
        collection: 'audit',
        item: appendAudit(
          'risk',
          risk.id,
          '接受风险',
          `接受依据 v1.${linkedRevision}，有效至 ${expiresAt}：${condition}`,
        ),
      },
    ]
    return commit('risk_accept', `${risk.code} 在 v1.${linkedRevision} 记录风险接受`, operations, {
      bump: false,
    })
  }

  const closeRisk = (riskId: string): SaveOutcome => {
    const committed = readCommittedState()
    const risk = committed.risks.find((item) => item.id === riskId)
    if (!risk) return { conflict: false, recoveredEntries: 0 }
    const operations: RevisionOperation[] = [
      {
        kind: 'upsert',
        collection: 'risks',
        item: { ...structuredClone(risk), status: 'closed' } as unknown as Record<string, unknown>,
      },
      {
        kind: 'upsert',
        collection: 'audit',
        item: appendAudit('risk', risk.id, '关闭风险', '风险已关闭并从开放风险中移除'),
      },
    ]
    return commit('risk_accept', `${risk.code} 风险关闭`, operations, { bump: false })
  }

  /* --------------------------------- 版本 --------------------------------- */

  const createVersion = (
    label: string,
    notes: string,
    affectedThreatIds: string[],
  ): VersionSnapshot => {
    const committed = readCommittedState()
    const revision = committed.currentRevision + 1
    const snapshot: VersionSnapshot = {
      id: createId('ver'),
      revision,
      label,
      createdAt: new Date().toISOString(),
      author: '当前用户',
      notes,
      threatIds: committed.threats.map((threat) => threat.id),
      componentIds: committed.components.map((component) => component.id),
      flowIds: committed.flows.map((flow) => flow.id),
      controlIds: committed.controls.map((control) => control.id),
      riskIds: committed.risks.map((risk) => risk.id),
      affectedThreatIds,
    }
    const operations: RevisionOperation[] = [
      { kind: 'upsert', collection: 'versions', item: snapshot as unknown as Record<string, unknown> },
      ...committed.threats
        .filter((threat) => affectedThreatIds.includes(threat.id))
        .map((threat) => ({
          kind: 'upsert' as const,
          collection: 'threats' as const,
          item: {
            ...structuredClone(threat),
            revision,
            reviewStatus: 'in_review' as Threat['reviewStatus'],
            pendingConfirmation: false,
            pendingBaseSnapshot: undefined,
          },
        })),
      {
        kind: 'upsert',
        collection: 'audit',
        item: appendAudit(
          'version',
          snapshot.id,
          '创建版本',
          `${label} 已创建，${affectedThreatIds.length} 条威胁进入 v1.${revision} 重新审核`,
        ),
      },
    ]
    commit('version', `${label} 创建`, operations, { bump: true })
    return snapshot
  }

  /* ------------------------------- 缓解任务状态 ----------------------------- */

  const updateMitigationStatus = (
    taskId: string,
    status: ThreatModelState['mitigations'][number]['status'],
  ): void => {
    const task = data.value.mitigations.find((item) => item.id === taskId)
    if (!task) return
    task.status = status
    data.value.audit.unshift(
      appendAudit('mitigation', task.id, '更新状态', `${task.title} 更新为 ${status}`),
    )
    persist()
  }

  const resetDemo = (): void => {
    data.value = resetState()
    lastRecoveryNote.value = ''
    lastSavedAt.value = new Date().toISOString()
  }

  /** 其他标签页写入后，本页对齐到最新持久化状态（保留当前页未保存编辑由组件层处理冲突） */
  const syncFromStorage = (): void => {
    data.value = readCommittedState()
    lastSavedAt.value = new Date().toISOString()
  }

  const effectiveDecisions = (threat: Threat) => effectiveDecisionsForThreat(data.value, threat)

  const exportReport = (): string => {
    const lines = [
      `# ${data.value.boundary.name} 威胁建模报告`,
      '',
      `生成时间：${new Date().toISOString()}`,
      `当前版本：v1.${data.value.currentRevision}`,
      `建模范围：${data.value.boundary.inScope}`,
      `排除范围：${data.value.boundary.outOfScope}`,
      '',
      '## 风险摘要',
      `- 资产与组件：${data.value.components.length}`,
      `- 威胁：${data.value.threats.length}`,
      `- 开放关键威胁：${metrics.value.critical}`,
      `- 威胁覆盖率：${metrics.value.coverage}%`,
      `- 待处理校验问题：${issues.value.length}`,
      '',
      '## 威胁清单',
      ...data.value.threats.map(
        (threat) =>
          `- ${threat.code} [${threat.severity}/${threat.reviewStatus}] v1.${threat.revision} ${threat.title}：${threat.description}`,
      ),
      '',
      '## 风险接受',
      ...data.value.risks
        .filter((risk) => typeof risk.acceptanceRevision === 'number')
        .map((risk) => {
          const linkedThreat = data.value.threats.find((threat) => threat.riskIds.includes(risk.id))
          const current = linkedThreat
            ? (risk.acceptanceRevision ?? 0) >= linkedThreat.revision
            : true
          return `- ${risk.code} ${risk.title}，接受依据 v1.${risk.acceptanceRevision ?? 0}${current ? '' : '（已随修订失效）'}，当前状态 ${risk.status}，有效至 ${risk.acceptanceExpiresAt ?? '未设置'}，条件：${risk.acceptanceCondition ?? '未填写'}`
        }),
      '',
      '## 校验问题',
      ...issues.value.map((issue) => `- [${issue.severity}] ${issue.title}：${issue.detail}`),
      '',
      '## 当前有效修订会签记录',
      ...data.value.threats.flatMap((threat) =>
        effectiveDecisionsForThreat(data.value, threat).map(
          (decision) =>
            `- v1.${decision.revision} ${decision.createdAt} ${decision.actor}（${decision.role}）${decision.decision}：${decision.comment}`,
        ),
      ),
    ]
    return lines.join('\n')
  }

  return {
    data,
    lastSavedAt,
    lastRecoveryNote,
    metrics,
    issues,
    pendingReviews,
    pendingConfirmations,
    revisionChain,
    saveEntity,
    removeEntity,
    updateBoundary,
    saveThreat,
    resolveThreatConflict,
    saveControl,
    saveEvidence,
    saveArchitectureEntity,
    createVersion,
    submitDecision,
    updateMitigationStatus,
    acceptRisk,
    closeRisk,
    resetDemo,
    syncFromStorage,
    effectiveDecisions,
    getRevisionChain,
    exportReport,
    reviewProgress,
  }
})
