import type { ThreatModelState, RevisionChainEntry } from '@/models/domain'
import { createSeedState } from '@/models/seed'
import { CHAIN_STORAGE_KEY, buildBaselineEntry, foldEntry, lastEntry, replayChain } from '@/services/revisionChain'

export const STORAGE_KEY = 'scapex-threat-model-v1'

// 状态全部为可 JSON 序列化数据；JSON 克隆同时解包 Vue 响应式代理，语义与最终落盘一致。
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T

const readChain = (): RevisionChainEntry[] | null => {
  const raw = localStorage.getItem(CHAIN_STORAGE_KEY)
  if (!raw) return null
  try {
    const parsed = JSON.parse(raw)
    if (!Array.isArray(parsed)) return null
    return parsed as RevisionChainEntry[]
  } catch {
    return null
  }
}

/** 读取修订链最新落盘值（提交时以它为基础，避免多标签页互相覆盖）。 */
export const loadChain = (): RevisionChainEntry[] => readChain() ?? []

export const writeChain = (chain: RevisionChainEntry[]): void => {
  localStorage.setItem(CHAIN_STORAGE_KEY, JSON.stringify(clone(chain)))
}

export const readState = (): ThreatModelState | null => {
  const raw = localStorage.getItem(STORAGE_KEY)
  if (!raw) return null
  try {
    return JSON.parse(raw) as ThreatModelState
  } catch {
    return null
  }
}

/**
 * 写入失败/崩溃后的恢复：以完整修订链为准重放，只补 applied:false 的未完成记录。
 * 重放按 id 幂等，已经补进状态的对象不会被重复追加。
 */
const recoverFromChain = (
  parsedState: ThreatModelState,
  chain: RevisionChainEntry[],
): { state: ThreatModelState; recovered: number } => {
  const state = clone(parsedState)
  state.revisionChain = [...chain].sort((a, b) => a.seq - b.seq)
  const pending = chain.filter((entry) => !entry.applied).sort((a, b) => a.seq - b.seq)
  for (const entry of pending) {
    foldEntry(state, entry)
  }
  state.currentRevision = lastEntry(chain)?.revision ?? state.currentRevision
  return { state, recovered: pending.length }
}

/** 旧数据回填：把基线镜像（含 basisRevision）应用到状态本身。 */
const applyBaselineToState = (state: ThreatModelState, baseline: RevisionChainEntry): ThreatModelState => {
  foldEntry(state, baseline)
  state.revisionChain = [baseline]
  return state
}

const persistState = (state: ThreatModelState): ThreatModelState => {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(clone(state)))
  return state
}

export const loadState = (): { state: ThreatModelState; recoveredCount: number } => {
  const chain = readChain()
  const parsed = readState()

  // 全新环境：生成种子，并固化为基线修订
  if (!parsed && !chain) {
    const seed = createSeedState()
    const baseline = buildBaselineEntry(seed)
    const initialized = applyBaselineToState(seed, baseline)
    writeChain([baseline])
    return { state: persistState(initialized), recoveredCount: 0 }
  }

  // 修订链丢失：以当前状态回填基线（旧数据迁移路径的兜底）
  if (parsed && !chain) {
    const baseline = buildBaselineEntry(parsed)
    const migrated = applyBaselineToState(clone(parsed), baseline)
    writeChain([baseline])
    return { state: persistState(migrated), recoveredCount: 0 }
  }

  const validChain = chain ?? []

  // 状态快照损坏或缺失：从完整修订链整体重建
  if (!parsed) {
    const rebuilt = replayChain(validChain)
    const normalizedChain = rebuilt.revisionChain.map((entry) => ({ ...entry, applied: true }))
    rebuilt.revisionChain = normalizedChain
    writeChain(normalizedChain)
    return { state: persistState(rebuilt), recoveredCount: normalizedChain.length }
  }

  // 旧数据首次打开：尚无修订链字段，回填修订依据基线
  if (!Array.isArray(parsed.revisionChain)) {
    const baseline = buildBaselineEntry(parsed)
    const migrated = applyBaselineToState(clone(parsed), baseline)
    const nextChain = [baseline, ...validChain.filter((entry) => entry.type !== 'baseline')]
      .sort((a, b) => a.seq - b.seq)
    migrated.revisionChain = nextChain
    writeChain(nextChain)
    return { state: persistState(migrated), recoveredCount: 0 }
  }

  // 常规路径：补齐写入中途未完成（applied:false）的记录
  const { state, recovered } = recoverFromChain(parsed, validChain)
  if (recovered > 0) {
    const normalizedChain = validChain.map((entry) => ({ ...entry, applied: true }))
    state.revisionChain = normalizedChain
    writeChain(normalizedChain)
  }
  return { state: persistState(state), recoveredCount: recovered }
}

export const saveState = (state: ThreatModelState): void => {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(clone(state)))
}

export const resetState = (): ThreatModelState => {
  const seed = createSeedState()
  const baseline = buildBaselineEntry(seed)
  const initialized = applyBaselineToState(seed, baseline)
  writeChain([baseline])
  saveState(initialized)
  return initialized
}

export const createId = (prefix: string): string =>
  `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`
