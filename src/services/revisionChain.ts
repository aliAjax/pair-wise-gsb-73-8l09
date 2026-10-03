import type {
  ActorRole,
  ChainCollectionKey,
  ControlEvidence,
  ReviewDecision,
  ReviewStatus,
  Risk,
  SecurityControl,
  Threat,
  ThreatModelState,
  RevisionChainEntry,
} from '@/models/domain'
import { createSeedState } from '@/models/seed'
import { decisionsForThreat } from '@/services/selectors'

export const CHAIN_STORAGE_KEY = 'scapex-revision-chain-v1'

// JSON 克隆：实体均为可序列化数据，同时解包 Vue 响应式代理。
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T

const upsert = <T extends { id: string }>(list: T[], item: T): void => {
  const index = list.findIndex((entry) => entry.id === item.id)
  if (index >= 0) {
    list[index] = item
  } else {
    list.unshift(item)
  }
}

const entityCollections: ChainCollectionKey[] = [
  'zones',
  'components',
  'dependencies',
  'flows',
  'controls',
  'evidence',
  'threats',
  'attackPaths',
  'risks',
  'mitigations',
]

const replaceCollection = (
  state: ThreatModelState,
  collection: ChainCollectionKey,
  items: Record<string, unknown>[],
): void => {
  ;(state[collection] as unknown[]) = clone(items as unknown[])
}

/**
 * 把一条修订链记录折叠进状态。所有写入路径与崩溃恢复都走这里，
 * 按 id 幂等覆盖，保证未完成对象可补齐、追加类记录不重复。
 */
export const foldEntry = (state: ThreatModelState, rawEntry: RevisionChainEntry): void => {
  const entry = clone(rawEntry)

  switch (entry.type) {
    case 'baseline': {
      if (entry.boundary) state.boundary = clone(entry.boundary)
      if (entry.threats) replaceCollection(state, 'threats', entry.threats as unknown as Record<string, unknown>[])
      if (entry.controls) replaceCollection(state, 'controls', entry.controls as unknown as Record<string, unknown>[])
      if (entry.evidence) replaceCollection(state, 'evidence', entry.evidence as unknown as Record<string, unknown>[])
      if (entry.risks) replaceCollection(state, 'risks', entry.risks as unknown as Record<string, unknown>[])
      for (const payload of entry.entities ?? []) {
        const list = state[payload.collection] as unknown as { id: string }[]
        upsert(list, clone(payload.item) as { id: string })
      }
      state.decisions = clone(entry.decisions ?? [])
      state.versions = clone(entry.snapshots ?? [])
      state.audit = clone(entry.auditEvents ?? [])
      state.currentRevision = entry.revision
      return
    }
    case 'entity_remove': {
      for (const removed of entry.removed ?? []) {
        const list = state[removed.collection] as unknown as { id: string }[]
        const index = list.findIndex((item) => item.id === removed.id)
        if (index >= 0) list.splice(index, 1)
      }
      break
    }
    case 'decision': {
      if (entry.decision) {
        const decision = entry.decision
        state.decisions = state.decisions.filter(
          (item) =>
            item.id !== decision.id &&
            !(item.threatId === decision.threatId && item.role === decision.role && item.revision === decision.revision),
        )
        state.decisions.unshift(clone(decision))
      }
      break
    }
    case 'version': {
      if (entry.snapshot) upsert(state.versions, clone(entry.snapshot))
      break
    }
    case 'entity_save': {
      for (const payload of entry.entities ?? []) {
        const list = state[payload.collection] as unknown as { id: string }[]
        upsert(list, clone(payload.item) as { id: string })
      }
      break
    }
  }

  // 各类型通用后像：威胁/控制/证据/风险/边界可随任意记录携带（如会签回写威胁状态）
  if (entry.boundary) state.boundary = clone(entry.boundary)
  for (const threat of entry.threats ?? []) upsert(state.threats, clone(threat))
  for (const control of entry.controls ?? []) upsert(state.controls, clone(control))
  for (const evidence of entry.evidence ?? []) upsert(state.evidence, clone(evidence))
  for (const risk of entry.risks ?? []) upsert(state.risks, clone(risk))

  if (entry.snapshot && entry.type !== 'version') upsert(state.versions, clone(entry.snapshot))
  for (const decision of entry.decisions ?? []) {
    if (!state.decisions.some((item) => item.id === decision.id)) {
      state.decisions.unshift(clone(decision))
    }
  }
  if (entry.audit && !state.audit.some((event) => event.id === entry.audit?.id)) {
    state.audit.unshift(clone(entry.audit))
  }
  if (entry.revision > state.currentRevision) state.currentRevision = entry.revision
}

/** 从完整修订链重建状态；先以种子骨架兜底，基线记录再整体替换。 */
export const replayChain = (chain: RevisionChainEntry[]): ThreatModelState => {
  const state = createSeedState()
  const ordered = [...chain].sort((a, b) => a.seq - b.seq)
  for (const entry of ordered) {
    foldEntry(state, entry)
  }
  state.revisionChain = ordered
  return state
}

export const lastEntry = (chain: RevisionChainEntry[]): RevisionChainEntry | undefined =>
  chain.length === 0 ? undefined : [...chain].sort((a, b) => b.seq - a.seq)[0]

/** 依据当前会签意见重算威胁审核状态。 */
export const reviewStatusFromDecisions = (
  decisions: ReviewDecision[],
  threatId: string,
  revision: number,
): ReviewStatus => {
  const current = decisionsForThreat(decisions, threatId, revision)
  const requiredRoles: ActorRole[] = ['development', 'security', 'business']
  const allSubmitted = requiredRoles.every((role) => current.some((item) => item.role === role))
  if (current.some((item) => item.decision === 'rejected')) return 'rejected'
  if (allSubmitted && current.every((item) => item.decision === 'approved')) return 'approved'
  return 'in_review'
}

const threatsReferencingControl = (state: ThreatModelState, controlIds: string[]): Threat[] =>
  state.threats.filter((threat) => threat.controlIds.some((id) => controlIds.includes(id)))

const controlsReferencingEvidence = (
  state: ThreatModelState,
  evidenceId: string,
  evidence: ControlEvidence | undefined,
): SecurityControl[] =>
  state.controls.filter(
    (control) =>
      control.evidenceIds.includes(evidenceId) ||
      (evidence && control.id === evidence.controlId && !control.evidenceIds.includes(evidenceId)),
  )

/** 把此前接受、但修订依据已落后于关联威胁的风险接受标记失效，保留历史接受条件。 */
export const invalidateRiskAcceptances = (
  state: ThreatModelState,
  affectedThreats: Threat[],
  newRevision: number,
): Risk[] => {
  const affectedRiskIds = new Set(affectedThreats.flatMap((threat) => threat.riskIds))
  const result: Risk[] = []
  for (const risk of state.risks) {
    if (!affectedRiskIds.has(risk.id)) continue
    if (risk.status !== 'accepted') continue
    const acceptedAt = risk.acceptanceRevision
    if (acceptedAt !== undefined && acceptedAt >= newRevision) continue
    const superseded: Risk = {
      ...risk,
      status: 'mitigating',
      supersededAcceptance:
        risk.acceptanceExpiresAt || risk.acceptanceCondition
          ? {
              expiresAt: risk.acceptanceExpiresAt ?? '',
              condition: risk.acceptanceCondition ?? '',
              revision: acceptedAt ?? risk.basisRevision ?? newRevision - 1,
            }
          : risk.supersededAcceptance,
      acceptanceExpiresAt: undefined,
      acceptanceCondition: undefined,
      acceptanceRevision: undefined,
      basisRevision: newRevision,
    }
    result.push(superseded)
  }
  return result
}

const bumpThreats = (threats: Threat[], newRevision: number): Threat[] =>
  threats.map((threat) => {
    if (threat.revision >= newRevision) return threat
    const reviewStatus: ReviewStatus =
      threat.reviewStatus === 'draft' || threat.reviewStatus === 'pending_confirmation'
        ? threat.reviewStatus
        : 'in_review'
    return { ...threat, revision: newRevision, reviewStatus, basisRevision: newRevision }
  })

export interface CascadeResult {
  affectedThreatIds: string[]
  threats: Threat[]
  risks: Risk[]
  controls: SecurityControl[]
}

/** 控制改动：关联威胁推上新修订并重新会签，关联风险接受立即失效。 */
export const cascadeForControls = (
  state: ThreatModelState,
  newRevision: number,
  controlIds: string[],
): CascadeResult => {
  const affected = threatsReferencingControl(state, controlIds)
  const threats = bumpThreats(affected, newRevision)
  const risks = invalidateRiskAcceptances(state, threats, newRevision)
  return { affectedThreatIds: affected.map((threat) => threat.id), threats, risks, controls: [] }
}

/** 证据改动：证据所属/引用控制、关联威胁与风险接受一起进入新修订。 */
export const cascadeForEvidence = (
  state: ThreatModelState,
  newRevision: number,
  evidence: ControlEvidence,
): CascadeResult => {
  const controls = controlsReferencingEvidence(state, evidence.id, evidence).map((control) => ({
    ...control,
    basisRevision: newRevision,
  }))
  const affected = threatsReferencingControl(
    state,
    controls.map((control) => control.id),
  )
  const threats = bumpThreats(affected, newRevision)
  const risks = invalidateRiskAcceptances(state, threats, newRevision)
  return { affectedThreatIds: affected.map((threat) => threat.id), threats, risks, controls }
}

/** 风险接受所依据的有效修订：取引用该风险的威胁的最高修订。 */
export const riskEffectiveRevision = (state: ThreatModelState, riskId: string): number => {
  const revisions = state.threats
    .filter((threat) => threat.riskIds.includes(riskId))
    .map((threat) => threat.revision)
  return revisions.length === 0 ? state.currentRevision : Math.max(...revisions)
}

export interface AssociationLinks {
  componentIds?: string[]
  flowIds?: string[]
  dependencyIds?: string[]
}

/**
 * 组件/数据流/外部依赖改动：引用这些对象的威胁同样进入新修订重新会签，
 * 其风险接受一并失效。
 */
export const cascadeForLinks = (
  state: ThreatModelState,
  newRevision: number,
  links: AssociationLinks,
): CascadeResult => {
  const componentIds = new Set(links.componentIds ?? [])
  const flowIds = new Set(links.flowIds ?? [])
  const dependencyIds = new Set(links.dependencyIds ?? [])
  const affected = state.threats.filter(
    (threat) =>
      threat.componentIds.some((id) => componentIds.has(id)) ||
      threat.flowIds.some((id) => flowIds.has(id)) ||
      threat.externalDependencyIds.some((id) => dependencyIds.has(id)),
  )
  const threats = bumpThreats(affected, newRevision)
  const risks = invalidateRiskAcceptances(state, threats, newRevision)
  return { affectedThreatIds: affected.map((threat) => threat.id), threats, risks, controls: [] }
}

/** 风险接受是否仍落在有效修订上（用于防御性校验与展示）。 */
export const riskAcceptanceIsCurrent = (state: ThreatModelState, risk: Risk): boolean => {
  if (risk.status !== 'accepted' || risk.acceptanceRevision === undefined) return false
  return risk.acceptanceRevision >= riskEffectiveRevision(state, risk.id)
}

/**
 * 旧数据首次打开时回填修订依据：把当前全量状态固化为基线记录，
 * 实体补上 basisRevision，已接受风险补上 acceptanceRevision。
 */
export const buildBaselineEntry = (state: ThreatModelState): RevisionChainEntry => {
  const revision = state.currentRevision
  const stamp = <T extends { basisRevision?: number }>(item: T): T => ({
    ...item,
    basisRevision: item.basisRevision ?? revision,
  })
  const threats = state.threats.map(stamp)
  const controls = state.controls.map(stamp)
  const evidence = state.evidence.map(stamp)
  const risks = state.risks.map((risk) =>
    risk.status === 'accepted' && risk.acceptanceRevision === undefined
      ? { ...stamp(risk), acceptanceRevision: revision }
      : stamp(risk),
  )
  const entities = entityCollections
    .filter((collection) => !['threats', 'controls', 'evidence', 'risks'].includes(collection))
    .flatMap((collection) =>
      (state[collection] as unknown as { id: string }[]).map((item) => ({
        collection,
        item: {
          ...(item as unknown as Record<string, unknown>),
          basisRevision: revision,
        },
      })),
    )

  return {
    id: 'chn-baseline',
    seq: 0,
    revision,
    type: 'baseline',
    actor: '系统',
    createdAt: new Date().toISOString(),
    detail: `旧数据首次打开，回填 r${revision} 修订依据基线`,
    applied: true,
    threats,
    controls,
    evidence,
    risks,
    entities,
    decisions: clone(state.decisions),
    snapshots: clone(state.versions),
    auditEvents: clone(state.audit),
    boundary: clone(state.boundary),
  }
}
