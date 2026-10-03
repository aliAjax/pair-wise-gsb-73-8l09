import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import type {
  ActorRole,
  AuditEvent,
  ChainCollectionKey,
  ControlEvidence,
  DecisionType,
  ReviewDecision,
  SecurityControl,
  Threat,
  ThreatModelState,
  RevisionChainEntry,
  VersionSnapshot,
} from '@/models/domain'
import {
  createId,
  loadChain,
  loadState,
  readState,
  resetState,
  saveState,
  writeChain,
} from '@/services/repository'
import {
  cascadeForControls,
  cascadeForEvidence,
  cascadeForLinks,
  foldEntry,
  reviewStatusFromDecisions,
  riskEffectiveRevision,
} from '@/services/revisionChain'
import {
  dashboardMetrics,
  getValidationIssues,
  reviewProgress,
} from '@/services/selectors'

type CollectionKey = ChainCollectionKey

interface IdentifiedEntity {
  id: string
}

interface CommitInput {
  type: RevisionChainEntry['type']
  detail: string
  revision: number
  payload?: Partial<RevisionChainEntry>
}

export interface CommitOutcome {
  entry: RevisionChainEntry
  conflict: boolean
}

export interface SaveThreatInput {
  threat: Threat
  /** 编辑打开时记住的修订号（乐观锁基线） */
  baseRevision: number
}

export const useThreatModelStore = defineStore('threat-model', () => {
  const initial = loadState()
  const data = ref<ThreatModelState>(initial.state)
  const lastSavedAt = ref(new Date().toISOString())
  const lastRecoveredCount = ref(initial.recoveredCount)

  const metrics = computed(() => dashboardMetrics(data.value))
  const issues = computed(() => getValidationIssues(data.value))
  const pendingReviews = computed(() =>
    data.value.threats.filter(
      (threat) => threat.reviewStatus === 'in_review' || threat.reviewStatus === 'pending_confirmation',
    ),
  )

  /** 拉取其他标签页已落盘、本标签页尚缺的修订链增量，返回最新链基线。 */
  const pullRemoteChain = (): RevisionChainEntry[] => {
    const storedChain = loadChain().sort((a, b) => a.seq - b.seq)
    const localSeqs = new Set(data.value.revisionChain.map((entry) => entry.seq))
    const remoteOnly = storedChain.filter((entry) => !localSeqs.has(entry.seq))
    for (const remote of remoteOnly) {
      foldEntry(data.value, remote)
    }
    return remoteOnly.length > 0
      ? storedChain
      : [...data.value.revisionChain].sort((a, b) => a.seq - b.seq)
  }

  const commit = (input: CommitInput): CommitOutcome => {
    // 两阶段提交：先把完整后像以 applied:false 追加到修订链并落盘，
    // 再折叠进内存状态并写状态快照，最后把链记录置 applied:true。
    // 以 localStorage 中最新修订链为基础，避免多标签页互相覆盖。
    const baseChain = pullRemoteChain()
    const seq = baseChain.length === 0 ? 1 : baseChain[baseChain.length - 1].seq + 1
    const entry: RevisionChainEntry = {
      id: createId('chn'),
      seq,
      revision: input.revision,
      type: input.type,
      actor: '当前用户',
      createdAt: new Date().toISOString(),
      detail: input.detail,
      applied: false,
      ...input.payload,
    }

    // 阶段一：修订链追加未完成记录（含全部后像）
    writeChain([...baseChain, entry])
    // 阶段二：折叠进当前状态并持久化状态快照
    foldEntry(data.value, entry)
    if (entry.revision > data.value.currentRevision) data.value.currentRevision = entry.revision
    data.value.revisionChain = [...baseChain, entry]
    saveState(data.value)
    // 阶段三：标记完成
    const appliedEntry = { ...entry, applied: true }
    const appliedChain = [...baseChain, appliedEntry]
    writeChain(appliedChain)
    data.value.revisionChain = appliedChain
    saveState(data.value)
    lastSavedAt.value = new Date().toISOString()
    return { entry: appliedEntry, conflict: input.type === 'threat_conflict' }
  }

  const makeAudit = (
    entityType: string,
    entityId: string,
    action: string,
    detail: string,
    createdAt?: string,
  ): AuditEvent => ({
    id: createId('aud'),
    entityType,
    entityId,
    action,
    actor: '当前用户',
    createdAt: createdAt ?? new Date().toISOString(),
    detail,
  })

  const entityName = (item: IdentifiedEntity): string =>
    'name' in item && typeof item.name === 'string' ? item.name : item.id

  /** 组件/数据流/外部依赖的增删改都使引用它们的威胁在新修订重签。 */
  const linkCascadeForItem = (
    collection: ChainCollectionKey,
    item: IdentifiedEntity,
    newRevision: number,
  ) => {
    if (collection === 'components') {
      return cascadeForLinks(data.value, newRevision, { componentIds: [item.id] })
    }
    if (collection === 'flows') {
      return cascadeForLinks(data.value, newRevision, { flowIds: [item.id] })
    }
    if (collection === 'dependencies') {
      return cascadeForLinks(data.value, newRevision, { dependencyIds: [item.id] })
    }
    return null
  }

  /** 不触发级联的普通实体保存（组件、数据流、依赖、任务等）。 */
  const saveEntity = (collection: CollectionKey, item: IdentifiedEntity): void => {
    pullRemoteChain()
    const exists = (data.value[collection] as unknown as IdentifiedEntity[]).some(
      (entry) => entry.id === item.id,
    )
    const isNew = !exists
    const isLink = collection === 'components' || collection === 'flows' || collection === 'dependencies'
    const revision = isLink ? data.value.currentRevision + 1 : data.value.currentRevision
    const stamped = {
      ...(item as object),
      basisRevision: revision,
    } as unknown as IdentifiedEntity
    const audit = makeAudit(
      collection,
      item.id,
      isNew ? '新增' : '更新',
      `${entityName(item)} 已保存`,
    )
    const cascade = isLink
      ? linkCascadeForItem(collection, item, revision)
      : null
    commit({
      type: 'entity_save',
      revision,
      detail: audit.detail,
      payload: {
        entities: [{ collection: collection as ChainCollectionKey, item: stamped as unknown as Record<string, unknown> }],
        threats: cascade?.threats,
        risks: cascade?.risks,
        affectedThreatIds: cascade?.affectedThreatIds,
        audit,
      },
    })
  }

  const removeEntity = (collection: CollectionKey, id: string): void => {
    pullRemoteChain()
    const target = data.value[collection] as unknown as IdentifiedEntity[]
    const item = target.find((entry) => entry.id === id)
    if (!item) return
    const isLink = collection === 'components' || collection === 'flows' || collection === 'dependencies'
    const revision = isLink ? data.value.currentRevision + 1 : data.value.currentRevision
    const cascade = isLink ? linkCascadeForItem(collection, item, revision) : null
    const audit = makeAudit(collection, id, '删除', '记录已从当前版本移除')
    commit({
      type: 'entity_remove',
      revision,
      detail: audit.detail,
      payload: {
        removed: [{ collection: collection as ChainCollectionKey, id }],
        threats: cascade?.threats,
        risks: cascade?.risks,
        affectedThreatIds: cascade?.affectedThreatIds,
        audit,
      },
    })
  }

  const updateBoundary = (boundary: ThreatModelState['boundary']): void => {
    pullRemoteChain()
    const audit = makeAudit('boundary', boundary.id, '更新', `${boundary.name} 的系统边界已更新`)
    commit({
      type: 'boundary',
      revision: data.value.currentRevision,
      detail: audit.detail,
      payload: { boundary, audit },
    })
  }

  /**
   * 保存威胁。若打开后该威胁已在另一标签页产生新修订（或已存在待确认冲突），
   * 后到的保存不覆盖先到结果：编辑内容保留为冲突草稿，威胁转“待确认”。
   */
  const saveThreat = (input: SaveThreatInput): { conflict: boolean } => {
    // 先同步其他标签页的已提交修订，再据此判断本编辑是否基于过期修订
    pullRemoteChain()
    const edited = input.threat
    const existing = data.value.threats.find((item) => item.id === edited.id)
    const isNew = !existing

    if (!isNew) {
      const effectiveRevision = existing.revision
      const stale = input.baseRevision < effectiveRevision
      const alreadyPending = existing.reviewStatus === 'pending_confirmation'
      if (stale || alreadyPending) {
        const conflictDraft: Threat = {
          ...edited,
          id: existing.id,
          revision: input.baseRevision,
          reviewStatus: 'draft',
          conflictDraft: undefined,
          conflictBaseRevision: undefined,
          basisRevision: input.baseRevision,
        }
        const held: Threat = {
          ...existing,
          reviewStatus: 'pending_confirmation',
          conflictDraft,
          conflictBaseRevision: input.baseRevision,
        }
        const audit = makeAudit(
          'threat',
          existing.id,
          '并发冲突',
          `检测到 r${effectiveRevision} 已有新保存，后到编辑保留为草稿并转待确认`,
        )
        commit({
          type: 'threat_conflict',
          revision: data.value.currentRevision,
          detail: audit.detail,
          payload: { threats: [held], audit, affectedThreatIds: [existing.id] },
        })
        return { conflict: true }
      }
    }

    const newRevision = isNew ? data.value.currentRevision : data.value.currentRevision + 1
    const saved: Threat = {
      ...edited,
      id: edited.id || createId('thr'),
      revision: isNew ? data.value.currentRevision : newRevision,
      reviewStatus: isNew
        ? edited.reviewStatus === 'approved'
          ? 'in_review'
          : edited.reviewStatus
        : 'in_review',
      conflictDraft: undefined,
      conflictBaseRevision: undefined,
      basisRevision: isNew ? data.value.currentRevision : newRevision,
    }
    const label = isNew ? saved.title : `${saved.code} 修订至 r${newRevision} 并重新会签`
    const audit = makeAudit('threats', saved.id, isNew ? '新增' : '更新', `${label} 已保存`)
    commit({
      type: 'threat_save',
      revision: newRevision,
      detail: audit.detail,
      payload: { threats: [saved], audit, affectedThreatIds: [saved.id] },
    })
    return { conflict: false }
  }

  /** 确认合并冲突草稿：在当前有效修订上形成新一版编辑，进入重新会签。 */
  const resolveConflict = (threatId: string, merge: boolean): void => {
    pullRemoteChain()
    const current = data.value.threats.find((item) => item.id === threatId)
    if (!current?.conflictDraft) return
    const newRevision = data.value.currentRevision + 1
    if (merge) {
      const draft = current.conflictDraft
      const merged: Threat = {
        ...current,
        ...draft,
        id: current.id,
        code: current.code,
        revision: newRevision,
        reviewStatus: 'in_review',
        conflictDraft: undefined,
        conflictBaseRevision: undefined,
        basisRevision: newRevision,
      }
      const audit = makeAudit(
        'threats',
        threatId,
        '冲突合并',
        `已在 r${newRevision} 上合并后到草稿，重新进入会签`,
      )
      commit({
        type: 'threat_save',
        revision: newRevision,
        detail: audit.detail,
        payload: { threats: [merged], audit, affectedThreatIds: [threatId] },
      })
    } else {
      const discarded: Threat = {
        ...current,
        reviewStatus: current.revision >= newRevision ? current.reviewStatus : 'in_review',
        conflictDraft: undefined,
        conflictBaseRevision: undefined,
      }
      const audit = makeAudit('threats', threatId, '冲突放弃', '已放弃后到草稿，保留先到保存的有效修订')
      commit({
        type: 'threat_save',
        revision: data.value.currentRevision,
        detail: audit.detail,
        payload: { threats: [discarded], audit, affectedThreatIds: [threatId] },
      })
    }
  }

  /** 保存控制：关联威胁与风险接受立即失效，全部推上新修订重新会签。 */
  const saveControl = (control: SecurityControl): void => {
    pullRemoteChain()
    const newRevision = data.value.currentRevision + 1
    const stamped: SecurityControl = {
      ...control,
      id: control.id || createId('ctl'),
      basisRevision: newRevision,
    }
    const cascade = cascadeForControls(data.value, newRevision, [stamped.id])
    const audit = makeAudit(
      'controls',
      stamped.id,
      '控制变更',
      `${stamped.name} 变更至 r${newRevision}，${cascade.affectedThreatIds.length} 条关联威胁重新会签`,
    )
    commit({
      type: 'control_save',
      revision: newRevision,
      detail: audit.detail,
      payload: {
        controls: [stamped],
        threats: cascade.threats,
        risks: cascade.risks,
        audit,
        affectedThreatIds: cascade.affectedThreatIds,
      },
    })
  }

  /** 保存证据：所属控制、关联威胁与风险接受一起进入新修订。 */
  const saveEvidence = (evidence: ControlEvidence): void => {
    pullRemoteChain()
    const newRevision = data.value.currentRevision + 1
    const stamped: ControlEvidence = {
      ...evidence,
      id: evidence.id || createId('ev'),
      basisRevision: newRevision,
    }
    const cascade = cascadeForEvidence(data.value, newRevision, stamped)
    const audit = makeAudit(
      'evidence',
      stamped.id,
      '证据变更',
      `${stamped.title} 变更至 r${newRevision}，${cascade.affectedThreatIds.length} 条关联威胁重新会签`,
    )
    commit({
      type: 'evidence_save',
      revision: newRevision,
      detail: audit.detail,
      payload: {
        evidence: [stamped],
        controls: cascade.controls,
        threats: cascade.threats,
        risks: cascade.risks,
        audit,
        affectedThreatIds: cascade.affectedThreatIds,
      },
    })
  }

  const createVersion = (
    label: string,
    notes: string,
    affectedThreatIds: string[],
  ): VersionSnapshot => {
    pullRemoteChain()
    const revision = data.value.currentRevision + 1
    const snapshot: VersionSnapshot = {
      id: createId('ver'),
      revision,
      label,
      createdAt: new Date().toISOString(),
      author: '当前用户',
      notes,
      threatIds: data.value.threats.map((threat) => threat.id),
      componentIds: data.value.components.map((component) => component.id),
      flowIds: data.value.flows.map((flow) => flow.id),
      controlIds: data.value.controls.map((control) => control.id),
      riskIds: data.value.risks.map((risk) => risk.id),
      affectedThreatIds,
    }
    const affected = new Set(affectedThreatIds)
    const threats = data.value.threats.map((threat) =>
      affected.has(threat.id)
        ? { ...threat, revision, reviewStatus: 'in_review' as const, basisRevision: revision }
        : { ...threat, revision, basisRevision: revision },
    )
    const risks = data.value.risks
      .filter(
        (risk) =>
          risk.status === 'accepted' &&
          threats.some((threat) => affected.has(threat.id) && threat.riskIds.includes(risk.id)),
      )
      .map((risk) => ({
        ...risk,
        status: 'mitigating' as const,
        supersededAcceptance:
          risk.acceptanceExpiresAt || risk.acceptanceCondition
            ? {
                expiresAt: risk.acceptanceExpiresAt ?? '',
                condition: risk.acceptanceCondition ?? '',
                revision: risk.acceptanceRevision ?? risk.basisRevision ?? revision - 1,
              }
            : risk.supersededAcceptance,
        acceptanceExpiresAt: undefined,
        acceptanceCondition: undefined,
        acceptanceRevision: undefined,
        basisRevision: revision,
      }))
    const audit = makeAudit(
      'version',
      snapshot.id,
      '创建版本',
      `${label} 已创建，${affectedThreatIds.length} 条威胁进入重新审核`,
    )
    commit({
      type: 'version',
      revision,
      detail: audit.detail,
      payload: { snapshot, threats, risks, audit, affectedThreatIds },
    })
    return snapshot
  }

  const submitDecision = (
    threatId: string,
    role: ActorRole,
    decision: DecisionType,
    actor: string,
    comment: string,
  ): { ok: boolean; reason?: string } => {
    pullRemoteChain()
    const threat = data.value.threats.find((item) => item.id === threatId)
    if (!threat) return { ok: false, reason: '威胁不存在' }
    if (threat.reviewStatus === 'pending_confirmation') {
      return { ok: false, reason: '该威胁存在并发冲突草稿，需先确认合并后才能会签' }
    }

    const decisionRecord: ReviewDecision = {
      id: createId('dec'),
      threatId,
      role,
      actor,
      decision,
      comment,
      createdAt: new Date().toISOString(),
      revision: threat.revision,
    }

    const updatedThreats = data.value.threats.map((item) => {
      if (item.id !== threatId) return item
      const provisionalDecisions = [
        decisionRecord,
        ...data.value.decisions.filter(
          (existing) =>
            !(existing.threatId === threatId && existing.role === role && existing.revision === threat.revision),
        ),
      ]
      return {
        ...item,
        reviewStatus: reviewStatusFromDecisions(provisionalDecisions, threatId, threat.revision),
      }
    })

    const decisionLabel: Record<DecisionType, string> = {
      accept: '接受',
      degrade: '降级',
      evidence_required: '要求补证',
      approved: '会签通过',
      rejected: '驳回',
    }
    const audit = makeAudit(
      'threat',
      threatId,
      decisionLabel[decision],
      `${actor}（${role}）在 r${threat.revision} 提交会签意见`,
    )
    commit({
      type: 'decision',
      revision: data.value.currentRevision,
      detail: audit.detail,
      payload: {
        decision: decisionRecord,
        threats: updatedThreats.filter((item) => item.id === threatId),
        audit,
        affectedThreatIds: [threatId],
      },
    })
    return { ok: true }
  }

  const updateMitigationStatus = (
    taskId: string,
    status: ThreatModelState['mitigations'][number]['status'],
  ): void => {
    const task = data.value.mitigations.find((item) => item.id === taskId)
    if (!task) return
    const updated = { ...task, status }
    const audit = makeAudit('mitigations', task.id, '更新状态', `${task.title} 更新为 ${status}`)
    commit({
      type: 'entity_save',
      revision: data.value.currentRevision,
      detail: audit.detail,
      payload: {
        entities: [{ collection: 'mitigations', item: updated as unknown as Record<string, unknown> }],
        audit,
      },
    })
  }

  const acceptRisk = (riskId: string, expiresAt: string, condition: string): void => {
    pullRemoteChain()
    const risk = data.value.risks.find((item) => item.id === riskId)
    if (!risk) return
    const basisRevision = riskEffectiveRevision(data.value, riskId)
    const updated: ThreatModelState['risks'][number] = {
      ...risk,
      status: 'accepted',
      acceptanceExpiresAt: expiresAt,
      acceptanceCondition: condition,
      acceptanceRevision: basisRevision,
      supersededAcceptance: undefined,
      basisRevision: data.value.currentRevision,
    }
    const audit = makeAudit(
      'risks',
      risk.id,
      '接受风险',
      `在 r${basisRevision} 上接受，有效至 ${expiresAt}：${condition}`,
    )
    commit({
      type: 'risk_accept',
      revision: data.value.currentRevision,
      detail: audit.detail,
      payload: { risks: [updated], audit },
    })
  }

  const closeRisk = (riskId: string): void => {
    pullRemoteChain()
    const risk = data.value.risks.find((item) => item.id === riskId)
    if (!risk) return
    const updated: ThreatModelState['risks'][number] = {
      ...risk,
      status: 'closed',
      basisRevision: data.value.currentRevision,
    }
    const audit = makeAudit('risks', risk.id, '关闭风险', '风险已关闭并从开放风险中移除')
    commit({
      type: 'risk_close',
      revision: data.value.currentRevision,
      detail: audit.detail,
      payload: { risks: [updated], audit },
    })
  }

  /** 跨标签页：其他标签页提交后，按其修订链增量同步到本标签页内存状态。 */
  const syncFromStorage = (): boolean => {
    const remote = readState()
    if (!remote) return false
    const localSeqs = new Set(data.value.revisionChain.map((entry) => entry.seq))
    const incoming = (remote.revisionChain ?? []).filter((entry) => !localSeqs.has(entry.seq))
    if (incoming.length === 0 && remote.currentRevision === data.value.currentRevision) return false
    for (const entry of [...incoming].sort((a, b) => a.seq - b.seq)) {
      foldEntry(data.value, entry)
    }
    data.value.revisionChain = remote.revisionChain ?? data.value.revisionChain
    data.value.currentRevision = remote.currentRevision
    return incoming.length > 0
  }

  const resetDemo = (): void => {
    data.value = resetState()
    lastSavedAt.value = new Date().toISOString()
    lastRecoveredCount.value = 0
  }

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
          `- ${threat.code} [r${threat.revision}/${threat.reviewStatus}] ${threat.title}：${threat.description}`,
      ),
      '',
      '## 风险接受',
      ...data.value.risks
        .filter((risk) => risk.status === 'accepted')
        .map(
          (risk) =>
            `- ${risk.code} ${risk.title}（依据 r${risk.acceptanceRevision ?? '?'}），有效至 ${risk.acceptanceExpiresAt ?? '未设置'}，条件：${risk.acceptanceCondition ?? '未填写'}`,
        ),
      '',
      '## 失效的历史接受',
      ...data.value.risks
        .filter((risk) => risk.supersededAcceptance)
        .map(
          (risk) =>
            `- ${risk.code} ${risk.title}：r${risk.supersededAcceptance?.revision} 的接受已随修订失效，需在新修订上重新签署`,
        ),
      '',
      '## 校验问题',
      ...issues.value.map((issue) => `- [${issue.severity}] ${issue.title}：${issue.detail}`),
      '',
      '## 会签记录',
      ...data.value.decisions.map(
        (decision) =>
          `- r${decision.revision} ${decision.createdAt} ${decision.actor}（${decision.role}）${decision.decision}：${decision.comment}`,
      ),
    ]
    return lines.join('\n')
  }

  return {
    data,
    lastSavedAt,
    lastRecoveredCount,
    metrics,
    issues,
    pendingReviews,
    saveEntity,
    removeEntity,
    updateBoundary,
    saveThreat,
    resolveConflict,
    saveControl,
    saveEvidence,
    createVersion,
    submitDecision,
    updateMitigationStatus,
    acceptRisk,
    closeRisk,
    syncFromStorage,
    resetDemo,
    exportReport,
    reviewProgress,
  }
})
