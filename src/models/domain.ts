export type Severity = 'critical' | 'high' | 'medium' | 'low'
export type ReviewStatus = 'draft' | 'in_review' | 'pending_confirmation' | 'approved' | 'rejected'
export type ThreatStatus = 'open' | 'mitigating' | 'mitigated' | 'accepted'
export type ControlStatus = 'effective' | 'degraded' | 'failed' | 'planned'
export type ActorRole = 'development' | 'security' | 'business'
export type DecisionType = 'accept' | 'degrade' | 'evidence_required' | 'approved' | 'rejected'

export interface SystemBoundary {
  id: string
  name: string
  description: string
  owner: string
  inScope: string
  outOfScope: string
}

export interface TrustZone {
  id: string
  name: string
  level: 'internet' | 'dmz' | 'internal' | 'restricted'
  description: string
}

export interface ArchitectureComponent {
  id: string
  name: string
  type: 'service' | 'asset' | 'data_store' | 'gateway' | 'client'
  zoneId: string
  criticality: Severity
  owner: string
  description: string
}

export interface ExternalDependency {
  id: string
  name: string
  vendor: string
  purpose: string
  dataClass: 'public' | 'internal' | 'confidential' | 'restricted'
  owner: string
  status: 'active' | 'review_due' | 'retired'
}

export interface DataFlow {
  id: string
  name: string
  sourceId: string
  targetId: string
  protocol: string
  dataClass: 'public' | 'internal' | 'confidential' | 'restricted'
  crossesTrustBoundary: boolean
  description: string
}

export interface ControlEvidence {
  id: string
  controlId: string
  title: string
  kind: 'test' | 'config' | 'ticket' | 'scan' | 'attestation'
  reference: string
  collectedAt: string
  expiresAt: string
  owner: string
  valid: boolean
  /** 修订依据：证据最后随哪一条修订链记录落盘 */
  basisRevision?: number
}

export interface SecurityControl {
  id: string
  name: string
  type: 'preventive' | 'detective' | 'corrective'
  status: ControlStatus
  owner: string
  componentId: string
  description: string
  evidenceIds: string[]
  /** 修订依据：控制最后随哪一条修订链记录落盘 */
  basisRevision?: number
}

export interface AttackPath {
  id: string
  name: string
  entryPoint: string
  target: string
  steps: string[]
  likelihood: 1 | 2 | 3 | 4 | 5
}

export interface Risk {
  id: string
  code: string
  title: string
  likelihood: 1 | 2 | 3 | 4 | 5
  impact: 1 | 2 | 3 | 4 | 5
  status: 'open' | 'mitigating' | 'accepted' | 'closed'
  owner: string
  acceptanceExpiresAt?: string
  acceptanceCondition?: string
  /** 风险接受所依据的修订；关联威胁/控制进入新修订后立即失效 */
  acceptanceRevision?: number
  /** 上一条有效接受（因修订链推进而失效时保留，便于重新确认） */
  supersededAcceptance?: {
    expiresAt: string
    condition: string
    revision: number
  }
  /** 修订依据：本条记录最后随哪一条修订链记录落盘 */
  basisRevision?: number
}

export interface Threat {
  id: string
  code: string
  title: string
  category: 'spoofing' | 'tampering' | 'repudiation' | 'information_disclosure' | 'denial_of_service' | 'elevation'
  description: string
  severity: Severity
  status: ThreatStatus
  componentIds: string[]
  flowIds: string[]
  externalDependencyIds: string[]
  attackPathIds: string[]
  controlIds: string[]
  riskIds: string[]
  reviewStatus: ReviewStatus
  revision: number
  /** 后到标签页基于过期修订保存时保留下来的草稿，等待人工确认合并 */
  conflictDraft?: Threat
  /** 冲突草稿所依据的过期修订号 */
  conflictBaseRevision?: number
  /** 修订依据：本条记录最后随哪一条修订链记录落盘 */
  basisRevision?: number
}

export interface MitigationTask {
  id: string
  threatId: string
  title: string
  owner: string
  dueAt: string
  status: 'todo' | 'in_progress' | 'verifying' | 'done'
  action: 'restrict' | 'monitor' | 'encrypt' | 'isolate' | 'allow_with_condition'
  detail: string
  evidenceIds: string[]
  conflictGroup?: string
}

export interface ReviewDecision {
  id: string
  threatId: string
  actor: string
  role: ActorRole
  decision: DecisionType
  comment: string
  createdAt: string
  revision: number
}

export interface VersionSnapshot {
  id: string
  revision: number
  label: string
  createdAt: string
  author: string
  notes: string
  threatIds: string[]
  componentIds: string[]
  flowIds: string[]
  controlIds: string[]
  riskIds: string[]
  affectedThreatIds: string[]
}

export interface AuditEvent {
  id: string
  entityType: string
  entityId: string
  action: string
  actor: string
  createdAt: string
  detail: string
}

/** 可写入修订链的实体集合 */
export type ChainCollectionKey =
  | 'zones'
  | 'components'
  | 'dependencies'
  | 'flows'
  | 'controls'
  | 'evidence'
  | 'threats'
  | 'attackPaths'
  | 'risks'
  | 'mitigations'

/**
 * 修订链记录：只追加（WAL）。写入分两阶段——先落 applied:false 的记录与完整后像，
 * 再把后像补进状态并置 applied:true。启动恢复时按 seq 重放，按 id 幂等合并，
 * 因此未完成的对象会被补齐而审计、会签等追加记录不会重复。
 */
export interface RevisionChainEntry {
  id: string
  seq: number
  /** 该记录所属修订号；不推进修订的记录沿用当前修订 */
  revision: number
  type:
    | 'baseline'
    | 'threat_save'
    | 'threat_conflict'
    | 'control_save'
    | 'evidence_save'
    | 'entity_save'
    | 'entity_remove'
    | 'decision'
    | 'risk_accept'
    | 'risk_close'
    | 'boundary'
    | 'version'
  actor: string
  createdAt: string
  detail: string
  applied: boolean
  /** 级联失效时被推上新修订、需要重新会签的威胁 */
  affectedThreatIds?: string[]
  /** 各实体的完整后像（恢复时按 id 覆盖） */
  threats?: Threat[]
  controls?: SecurityControl[]
  evidence?: ControlEvidence[]
  risks?: Risk[]
  entities?: { collection: ChainCollectionKey; item: Record<string, unknown> }[]
  removed?: { collection: ChainCollectionKey; id: string }[]
  decision?: ReviewDecision
  decisions?: ReviewDecision[]
  audit?: AuditEvent
  auditEvents?: AuditEvent[]
  boundary?: SystemBoundary
  snapshot?: VersionSnapshot
  snapshots?: VersionSnapshot[]
}

export interface ThreatModelState {
  boundary: SystemBoundary
  zones: TrustZone[]
  components: ArchitectureComponent[]
  dependencies: ExternalDependency[]
  flows: DataFlow[]
  controls: SecurityControl[]
  evidence: ControlEvidence[]
  threats: Threat[]
  attackPaths: AttackPath[]
  risks: Risk[]
  mitigations: MitigationTask[]
  decisions: ReviewDecision[]
  versions: VersionSnapshot[]
  audit: AuditEvent[]
  currentRevision: number
  /** 只追加的完整修订链，权威恢复来源 */
  revisionChain: RevisionChainEntry[]
}

export interface ValidationIssue {
  id: string
  kind:
    | 'uncovered_component'
    | 'control_failed'
    | 'risk_acceptance_expired'
    | 'risk_acceptance_superseded'
    | 'mitigation_conflict'
    | 'missing_evidence'
  severity: Severity
  title: string
  detail: string
  entityId: string
}

export interface VersionChange {
  category: string
  id: string
}

export interface VersionDifference {
  added: VersionChange[]
  removed: VersionChange[]
  changed: string[]
}
