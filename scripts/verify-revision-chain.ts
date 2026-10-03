// 修订链核心场景验证：级联失效、并发冲突、崩溃恢复、旧数据回填
// 通过 esbuild 打包后在 node 中运行，localStorage 用内存 shim 模拟。
import assert from 'node:assert/strict'
import type { ThreatModelState } from '../src/models/domain'
import { createSeedState } from '../src/models/seed'
import { loadState, saveState, writeChain } from '../src/services/repository'
import {
  buildBaselineEntry,
  cascadeForControls,
  cascadeForEvidence,
  foldEntry,
  replayChain,
  reviewStatusFromDecisions,
  riskEffectiveRevision,
} from '../src/services/revisionChain'

// ---- localStorage shim ----
const mem = new Map<string, string>()
const localStorage = {
  getItem: (k: string) => (mem.has(k) ? mem.get(k)! : null),
  setItem: (k: string, v: string) => void mem.set(k, v),
  removeItem: (k: string) => void mem.delete(k),
  clear: () => mem.clear(),
}
;(globalThis as Record<string, unknown>).localStorage = localStorage

const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T

// ---------- 场景 1：全新环境回填基线 ----------
mem.clear()
const loaded = loadState()
assert.equal(loaded.state.currentRevision, 2, '种子当前修订为 2')
assert.equal(loaded.state.revisionChain.length, 1, '应固化一条基线记录')
assert.equal(loaded.state.revisionChain[0].type, 'baseline')
assert.ok(loaded.state.threats.every((t) => t.basisRevision === 2), '威胁回填 basisRevision')
const risk03 = loaded.state.risks.find((r) => r.id === 'risk-03')!
assert.equal(risk03.acceptanceRevision, 2, '已接受风险回填 acceptanceRevision')
console.log('✓ 场景1 首次打开回填修订依据基线')

// ---------- 场景 2：控制改动 → 关联威胁新修订、风险接受失效 ----------
let state = clone(loadState().state)
const control = clone(state.controls.find((c) => c.id === 'ctl-02')!)
control.status = 'failed'
const cascade = cascadeForControls(state, 3, ['ctl-02'])
// ctl-02 关联 thr-02
assert.deepEqual(cascade.affectedThreatIds.sort(), ['thr-02'])
const t02 = cascade.threats.find((t) => t.id === 'thr-02')!
assert.equal(t02.revision, 3)
assert.equal(t02.reviewStatus, 'in_review', '已通过威胁回到审核中')
// risk-02 原本 mitigating；找一个 accepted 的关联：thr-02 -> risk-02 mitigating，不会失效
// 用 ctl-03 关联 thr-02/thr-03（risk-03 accepted 挂在 thr-03）
const cascade3 = cascadeForControls(state, 3, ['ctl-03'])
assert.deepEqual(cascade3.affectedThreatIds.sort(), ['thr-02', 'thr-03'])
const invalidated = cascade3.risks.find((r) => r.id === 'risk-03')!
assert.equal(invalidated.status, 'mitigating', '风险接受失效回到处置中')
assert.equal(invalidated.acceptanceExpiresAt, undefined, '接受条件已清空')
assert.ok(invalidated.supersededAcceptance, '保留历史接受')
assert.equal(invalidated.supersededAcceptance.revision, 2)
console.log('✓ 场景2 控制变更级联：威胁重签 + 风险接受失效保留历史')

// ---------- 场景 3：证据改动 → 所属控制与威胁一起级联 ----------
state = clone(loadState().state)
const ev = clone(state.evidence.find((e) => e.id === 'ev-01')!)
ev.valid = false
const evCascade = cascadeForEvidence(state, 3, ev)
// ev-01 属于 ctl-01，ctl-01 关联 thr-01 (risk-01 mitigating)
assert.ok(evCascade.controls.some((c) => c.id === 'ctl-01' && c.basisRevision === 3))
assert.deepEqual(evCascade.affectedThreatIds, ['thr-01'])
assert.equal(evCascade.threats[0].revision, 3)
console.log('✓ 场景3 证据变更级联到所属控制与关联威胁')

// ---------- 场景 4：模拟完整提交链重放 ----------
mem.clear()
{
  const seed = createSeedState()
  const baseline = buildBaselineEntry(seed)
  seed.revisionChain = [baseline]
  writeChain([baseline])
  saveState(seed)
}
{
  const s = loadState().state
  // 保存一条新控制（直接构造链记录，模拟 store.commit 的阶段一/二）
  const newControl = { ...clone(s.controls[0]), status: 'degraded', basisRevision: 3 }
  const c = cascadeForControls(s, 3, [newControl.id])
  const entry = {
    id: 'chn-test-1',
    seq: 1,
    revision: 3,
    type: 'control_save' as const,
    actor: '测试',
    createdAt: new Date().toISOString(),
    detail: '测试控制变更',
    applied: false,
    controls: [newControl],
    threats: c.threats,
    risks: c.risks,
    affectedThreatIds: c.affectedThreatIds,
  }
  const chain = [...s.revisionChain, entry]
  writeChain(chain) // 只写链，未写状态 → 模拟写入中途失败
}
{
  const recovered = loadState()
  assert.ok(recovered.recoveredCount >= 1, '应检测到未完成记录')
  const ctl = recovered.state.controls.find((c) => c.id === 'ctl-01')!
  assert.equal(ctl.status, 'degraded', '控制后像被补齐')
  const t = recovered.state.threats.find((x) => x.id === 'thr-01')!
  assert.equal(t.revision, 3, '威胁被推到 r3')
  assert.equal(t.reviewStatus, 'in_review')
  // 再次加载：不重复追加
  const again = loadState()
  assert.equal(again.recoveredCount, 0, '完成记录不再恢复')
  assert.equal(
    again.state.audit.filter((a) => a.detail === '测试控制变更').length,
    0,
    '无审计重复（测试记录未带 audit）',
  )
}
console.log('✓ 场景4 写入失败从修订链恢复，不重复追加')

// ---------- 场景 5：修订链整体重建（状态快照损坏） ----------
{
  mem.set('scapex-threat-model-v1', '{损坏的json')
  const rebuilt = loadState()
  assert.equal(rebuilt.state.currentRevision, 3, '从链重建到 r3')
  const t = rebuilt.state.threats.find((x) => x.id === 'thr-01')!
  assert.equal(t.revision, 3)
  assert.equal(rebuilt.state.controls.find((c) => c.id === 'ctl-01')!.status, 'degraded')
}
console.log('✓ 场景5 状态快照损坏时从完整修订链重建')

// ---------- 场景 6：后到标签页冲突 → 保留草稿待确认，不覆盖先到 ----------
{
  const s = loadState().state
  // 标签页A先把 thr-01 保存到 r4
  const aSave: ThreatModelState['threats'][number] = {
    ...s.threats.find((t) => t.id === 'thr-01')!,
    title: 'A标签页的修改',
    revision: 4,
    reviewStatus: 'in_review',
    basisRevision: 4,
  }
  const aEntry = {
    id: 'chn-a',
    seq: s.revisionChain.at(-1)!.seq + 1,
    revision: 4,
    type: 'threat_save' as const,
    actor: 'A',
    createdAt: new Date().toISOString(),
    detail: 'A保存',
    applied: true,
    threats: [aSave],
  }
  foldEntry(s, aEntry)
  s.currentRevision = 4
  s.revisionChain = [...s.revisionChain, aEntry]
  writeChain(s.revisionChain)
  saveState(s)

  // 标签页B基于打开时记住的 r3 保存
  const fresh = loadState().state
  const current = fresh.threats.find((t) => t.id === 'thr-01')!
  const baseRevision = 3
  const bDraft: ThreatModelState['threats'][number] = {
    ...current,
    title: 'B标签页的修改',
    revision: baseRevision,
  }
  // 复用 store.saveThreat 的冲突判定逻辑
  const stale = baseRevision < current.revision
  assert.ok(stale, 'B 基于过期修订')
  const held: ThreatModelState['threats'][number] = {
    ...current,
    reviewStatus: 'pending_confirmation',
    conflictDraft: { ...bDraft, reviewStatus: 'draft' },
    conflictBaseRevision: baseRevision,
  }
  const bEntry = {
    id: 'chn-b',
    seq: fresh.revisionChain.at(-1)!.seq + 1,
    revision: fresh.currentRevision,
    type: 'threat_conflict' as const,
    actor: 'B',
    createdAt: new Date().toISOString(),
    detail: 'B后到',
    applied: true,
    threats: [held],
    affectedThreatIds: ['thr-01'],
  }
  foldEntry(fresh, bEntry)
  const after = fresh.threats.find((t) => t.id === 'thr-01')!
  assert.equal(after.title, 'A标签页的修改', '先到保存保持有效')
  assert.equal(after.reviewStatus, 'pending_confirmation', '转待确认')
  assert.equal(after.conflictDraft?.title, 'B标签页的修改', '后到编辑保留为草稿')
}
console.log('✓ 场景6 并发保存：后到保留草稿并转待确认')

// ---------- 场景 7：会签状态重算必须在同一修订 ----------
{
  const s = loadState().state
  const decisions = [
    {
      id: 'd1',
      threatId: 'thr-01',
      actor: '赵恺',
      role: 'development' as const,
      decision: 'approved' as const,
      comment: 'ok',
      createdAt: '',
      revision: 3,
    },
  ]
  // 旧修订的通过不能作用于 r4
  assert.equal(reviewStatusFromDecisions(decisions, 'thr-01', 4), 'in_review', '新修订无意见=审核中')
  assert.equal(reviewStatusFromDecisions(decisions, 'thr-01', 3), 'in_review', '仅一方=审核中')
  const all3 = [
    ...decisions,
    { ...decisions[0], id: 'd2', role: 'security' as const },
    { ...decisions[0], id: 'd3', role: 'business' as const },
  ]
  assert.equal(reviewStatusFromDecisions(all3, 'thr-01', 3), 'approved', '三方齐备才放行')
}
console.log('✓ 场景7 三方须在同一有效修订上齐备才放行')

// ---------- 场景 8：旧数据（无 revisionChain 字段）回填 ----------
{
  mem.clear()
  const legacy = createSeedState()
  delete (legacy as Partial<ThreatModelState>).revisionChain
  mem.set('scapex-threat-model-v1', JSON.stringify(legacy))
  // 同时没有链 key
  const migrated = loadState()
  assert.equal(migrated.state.revisionChain.length, 1)
  assert.equal(migrated.state.revisionChain[0].type, 'baseline')
  assert.ok(migrated.state.controls.every((c) => typeof c.basisRevision === 'number'))
  assert.equal(migrated.state.risks.find((r) => r.id === 'risk-03')!.acceptanceRevision, 2)
  // 二次加载不重复回填
  assert.equal(loadState().state.revisionChain.length, 1)
}
console.log('✓ 场景8 旧数据首次打开回填且幂等')

// ---------- 场景 9：风险接受有效修订随关联威胁变化 ----------
{
  const s = loadState().state
  const rev = riskEffectiveRevision(s, 'risk-03')
  assert.equal(rev, 2, '初始有效修订为 2')
}

// ---------- 场景 10：replayChain 全量重建结果与状态一致 ----------
{
  const s = loadState().state
  const rebuilt = replayChain(s.revisionChain.map((e) => ({ ...e, applied: true })))
  assert.equal(rebuilt.threats.length, s.threats.length)
  assert.equal(rebuilt.currentRevision, s.currentRevision)
  assert.equal(rebuilt.decisions.length, s.decisions.length)
  assert.equal(rebuilt.audit.length, s.audit.length)
}
console.log('✓ 场景9/10 有效修订计算与全链重放一致')

console.log('\n全部修订链场景验证通过 ✅')
