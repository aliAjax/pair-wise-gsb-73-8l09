import {
  CURRENT_SCHEMA_VERSION,
  type RevisionEntry,
  type RevisionOperation,
  type RevisionReason,
  type ThreatModelState,
} from '@/models/domain'
import { createSeedState } from '@/models/seed'

const STORAGE_KEY = 'scapex-threat-model-v1'
const CHAIN_STORAGE_KEY = 'scapex-revision-chain-v1'

const clone = <T>(value: T): T => structuredClone(value)

export const createId = (prefix: string): string =>
  `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`

/* ---------------------------------- 迁移 ---------------------------------- */

const asRecord = (value: unknown): Record<string, unknown> | null =>
  value && typeof value === 'object' ? (value as Record<string, unknown>) : null

/**
 * 旧数据首次打开时回填修订依据：
 * 控制、证据、风险接受没有修订号的，按当时的当前修订回填，保证不会被误判失效。
 */
const migrateState = (raw: Record<string, unknown>): ThreatModelState => {
  const currentRevision =
    typeof raw.currentRevision === 'number' ? raw.currentRevision : 1

  const backfill = <T>(list: T[] | undefined, fallback: number): T[] =>
    (list ?? []).map((entry) => {
      const record = asRecord(entry)
      if (record && typeof record.revision !== 'number') {
        record.revision = fallback
      }
      return entry
    })

  return {
    ...(raw as Partial<ThreatModelState>),
    controls: backfill(
      raw.controls as ThreatModelState['controls'] | undefined,
      currentRevision,
    ),
    evidence: backfill(
      raw.evidence as ThreatModelState['evidence'] | undefined,
      currentRevision,
    ),
    risks: (raw.risks as ThreatModelState['risks'] | undefined)?.map((risk) =>
      risk.status === 'accepted' && typeof risk.acceptanceRevision !== 'number'
        ? { ...risk, acceptanceRevision: currentRevision }
        : risk,
    ) ?? [],
    revisionChain: Array.isArray(raw.revisionChain)
      ? (raw.revisionChain as RevisionEntry[])
      : [],
    schemaVersion: CURRENT_SCHEMA_VERSION,
  } as ThreatModelState
}

/* ------------------------------ 修订链落盘读取 ----------------------------- */

const readChain = (): RevisionEntry[] => {
  const raw = localStorage.getItem(CHAIN_STORAGE_KEY)
  if (!raw) return []
  try {
    const parsed = JSON.parse(raw)
    return Array.isArray(parsed) ? (parsed as RevisionEntry[]) : []
  } catch {
    return []
  }
}

const writeChain = (chain: RevisionEntry[]): void => {
  localStorage.setItem(CHAIN_STORAGE_KEY, JSON.stringify(chain))
}

/* ------------------------------ 操作幂等补写 ------------------------------ */

const upsertById = (
  state: ThreatModelState,
  op: RevisionOperation & { kind: 'upsert' },
): boolean => {
  const collection = state[op.collection] as unknown as Record<string, unknown>[]
  const item = op.item as Record<string, unknown> & { id?: string }
  const index = collection.findIndex((entry) => entry.id === item.id)
  if (op.collection === 'audit') {
    // 审计为只追加记录：链重放时已存在则不重复追加
    return index < 0 ? (collection.unshift(item), true) : false
  }
  if (index >= 0) {
    collection[index] = item
    return true
  }
  collection.unshift(item)
  return true
}

const removeById = (state: ThreatModelState, op: RevisionOperation & { kind: 'remove' }): void => {
  const collection = state[op.collection] as unknown as Record<string, unknown>[]
  const index = collection.findIndex((entry) => entry.id === op.id)
  if (index >= 0) collection.splice(index, 1)
}

const applyOperation = (state: ThreatModelState, op: RevisionOperation): void => {
  if (op.kind === 'upsert') {
    upsertById(state, op)
    return
  }
  if (op.kind === 'remove') {
    removeById(state, op)
    return
  }
  // replace_decision：同一威胁、同一角色、同一修订只保留最新一条
  state.decisions = state.decisions.filter(
    (decision) =>
      !(
        decision.threatId === op.threatId &&
        decision.role === op.role &&
        decision.revision === op.revision
      ),
  )
  state.decisions.unshift(op.item)
}

/**
 * 从完整修订链恢复：按链顺序只补未完成对象，已写入的记录不重复追加。
 * 通过比较主仓库已记录的链长度判断从哪里开始补写。
 */
export const recoverState = (
  state: ThreatModelState,
  chain: RevisionEntry[],
): { state: ThreatModelState; recoveredEntries: number } => {
  // 主仓库中已落盘的链前缀长度（主仓库写入失败时会短于完整链）
  const appliedPrefix = Array.isArray(state.revisionChain) ? state.revisionChain.length : 0
  const pending = chain.slice(Math.min(appliedPrefix, chain.length))

  const next = clone(state)
  pending.forEach((entry) => {
    entry.operations.forEach((op) => applyOperation(next, op))
    next.currentRevision = Math.max(next.currentRevision, entry.revision)
  })
  next.revisionChain = clone(chain)
  return { state: next, recoveredEntries: pending.length }
}

/* --------------------------------- 装载 ---------------------------------- */

const readPersistedState = (): ThreatModelState | null => {
  const raw = localStorage.getItem(STORAGE_KEY)
  if (!raw) return null
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>
    return migrateState(parsed)
  } catch {
    return null
  }
}

export interface LoadedState {
  state: ThreatModelState
  /** 首次打开旧数据回填后是否需要立即落盘 */
  migrated: boolean
  /** 从修订链补写的条目数（上次主仓库写入失败的残留） */
  recoveredEntries: number
}

/** 页面打开时：读取主仓库并从修订链补齐未完成写入，旧数据回填修订依据 */
export const loadState = (): LoadedState => {
  const chain = readChain()
  const persisted = readPersistedState()

  if (!persisted) {
    const seed = createSeedState()
    saveState(seed)
    writeChain(seed.revisionChain)
    return { state: seed, migrated: false, recoveredEntries: 0 }
  }

  const migrated =
    (persisted as unknown as Record<string, unknown>).schemaVersion !== CURRENT_SCHEMA_VERSION

  const { state, recoveredEntries } = recoverState(persisted, chain)
  if (migrated || recoveredEntries > 0) saveState(state)
  return { state, migrated, recoveredEntries }
}

/** 读取最新持久化状态（不做迁移落盘），用于提交前与其他标签页对齐 */
export const readCommittedState = (): ThreatModelState => {
  const persisted = readPersistedState()
  if (!persisted) return createSeedState()
  const chain = readChain()
  return recoverState(persisted, chain).state
}

export const saveState = (state: ThreatModelState): void => {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(clone(state)))
}

export const resetState = (): ThreatModelState => {
  const seed = createSeedState()
  saveState(seed)
  writeChain(seed.revisionChain)
  return seed
}

/* -------------------------------- 修订提交 -------------------------------- */

export interface CommitRevisionInput {
  /** 提交所基于的修订号（页面打开/编辑器打开时记住的修订号） */
  baseRevision?: number
  reason: RevisionReason
  detail: string
  actor?: string
  /** 是否推进全局修订号 */
  bump: boolean
  operations: RevisionOperation[]
  pending?: RevisionEntry['pending']
}

export interface CommitRevisionResult {
  state: ThreatModelState
  entry: RevisionEntry
  /** 主仓库写入失败后从修订链恢复，补写的条目数（0 表示正常） */
  recoveredEntries: number
}

/**
 * 两阶段写入：
 * 1. 先把原子修订追加到修订链并落盘；
 * 2. 再把完整状态写入主仓库；主仓库失败时按链恢复，只补未完成对象。
 */
export const commitRevision = (
  base: ThreatModelState,
  input: CommitRevisionInput,
): CommitRevisionResult => {
  const committed = readCommittedState()
  const starting: ThreatModelState = clone(committed ?? base)

  const revision = input.bump ? starting.currentRevision + 1 : starting.currentRevision
  const entry: RevisionEntry = {
    id: createId('rev'),
    revision,
    reason: input.reason,
    createdAt: new Date().toISOString(),
    actor: input.actor ?? '当前用户',
    detail: input.detail,
    operations: input.operations,
    pending: input.pending,
  }

  // 阶段一：修订链先落盘（即便主仓库随后写入失败也不会丢）
  const chain = [...readChain(), entry]
  writeChain(chain)

  // 在内存状态上执行本次写入
  const next = clone(starting)
  entry.operations.forEach((op) => applyOperation(next, op))
  next.currentRevision = revision
  next.revisionChain = chain

  let recoveredEntries = 0
  try {
    saveState(next)
  } catch {
    // 阶段二失败：从完整修订链恢复，只补未完成对象，不重复追加记录
    const recovered = recoverState(starting, chain)
    recoveredEntries = recovered.recoveredEntries
    saveState(recovered.state)
    return { state: recovered.state, entry, recoveredEntries }
  }

  return { state: next, entry, recoveredEntries }
}

export const getRevisionChain = (): RevisionEntry[] => readChain()
