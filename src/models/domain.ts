export type Severity = 'critical' | 'high' | 'medium' | 'low'
export type ReviewStatus = 'draft' | 'in_review' | 'approved' | 'rejected'
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
  revision: number
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
  revision: number
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
  /** 风险接受所依据的修订号；低于关联威胁当前修订即失效 */
  acceptanceRevision?: number
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
  /** 并发保存时后到者被保留为草稿并标记待确认 */
  pendingConfirmation?: boolean
  /** 待确认期间先到保存（已生效）的完整威胁快照 */
  pendingBaseSnapshot?: Threat
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

/**
 * 修订链上的一次原子写入。所有威胁、控制、证据、风险接受和会签的修改
 * 都必须先追加到修订链，再落主仓库；主仓库写入失败时可按链顺序补写。
 */
export type RevisionCollection =
  | 'components'
  | 'flows'
  | 'controls'
  | 'evidence'
  | 'threats'
  | 'risks'
  | 'decisions'
  | 'versions'
  | 'audit'

export type RevisionOperation =
  | { kind: 'upsert'; collection: RevisionCollection; item: object }
  | { kind: 'remove'; collection: RevisionCollection; id: string }
  | {
      kind: 'replace_decision'
      threatId: string
      role: ActorRole
      revision: number
      item: ReviewDecision
    }

export type RevisionReason =
  | 'threat_edit'
  | 'threat_conflict'
  | 'control_change'
  | 'evidence_change'
  | 'component_change'
  | 'flow_change'
  | 'risk_accept'
  | 'decision'
  | 'version'

export interface RevisionEntry {
  id: string
  revision: number
  reason: RevisionReason
  createdAt: string
  actor: string
  detail: string
  operations: RevisionOperation[]
  /** 并发保存时后到草稿的待确认快照（已生效版本 + 草稿） */
  pending?: {
    threatId: string
    winner: Threat
  }
}

export const CURRENT_SCHEMA_VERSION = 2

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
  /** 完整修订链，主仓库写入失败后据此补写 */
  revisionChain: RevisionEntry[]
  schemaVersion: number
}

export interface ValidationIssue {
  id: string
  kind:
    | 'uncovered_component'
    | 'control_failed'
    | 'risk_acceptance_expired'
    | 'risk_acceptance_invalidated'
    | 'mitigation_conflict'
    | 'missing_evidence'
    | 'pending_confirmation'
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
