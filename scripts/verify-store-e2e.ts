// 端到端：直接驱动真实 store（setActivePinia），验证完整提交/级联/冲突/恢复闭环。
import assert from 'node:assert/strict'
import { createPinia, setActivePinia } from 'pinia'
import { useThreatModelStore } from '../src/stores/threatModel'

const mem = new Map<string, string>()
const localStorage = {
  getItem: (k: string) => (mem.has(k) ? mem.get(k)! : null),
  setItem: (k: string, v: string) => void mem.set(k, v),
  removeItem: (k: string) => void mem.delete(k),
  clear: () => mem.clear(),
}
;(globalThis as Record<string, unknown>).localStorage = localStorage

const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T

const freshStore = () => {
  setActivePinia(createPinia())
  return useThreatModelStore()
}

// 初始基线
mem.clear()
{
  const store = freshStore()
  assert.equal(store.data.currentRevision, 2)
  assert.equal(store.data.revisionChain[0].type, 'baseline')
  console.log('✓ store 初始化带基线')
}

// 编辑控制 → 级联
{
  const store = freshStore()
  const ctl03 = clone(store.data.controls.find((c) => c.id === 'ctl-03')!)
  ctl03.status = 'failed'
  store.saveControl(ctl03)
  assert.equal(store.data.currentRevision, 3)
  const t2 = store.data.threats.find((t) => t.id === 'thr-02')!
  const t3 = store.data.threats.find((t) => t.id === 'thr-03')!
  assert.equal(t2.revision, 3)
  assert.equal(t3.revision, 3)
  assert.equal(t2.reviewStatus, 'in_review')
  assert.equal(t3.reviewStatus, 'in_review', '原 in_review 保持审核中但换新修订')
  // risk-03 的接受失效
  const r3 = store.data.risks.find((r) => r.id === 'risk-03')!
  assert.equal(r3.status, 'mitigating')
  assert.ok(r3.supersededAcceptance)
  // 旧修订决策不再作用
  const oldDecisions = store.data.decisions.filter(
    (d) => d.threatId === 'thr-02' && d.revision === 2,
  )
  assert.ok(oldDecisions.length >= 1, '旧修订意见保留可追溯')
  // 链记录 applied
  assert.ok(store.data.revisionChain.at(-1)!.applied)
  console.log('✓ 控制保存：r3 级联，威胁重签，旧会签保留不作用，风险接受失效')
}

// 三方在 r3 重新会签 thr-03 才放行
{
  const store = freshStore()
  const t3 = store.data.threats.find((t) => t.id === 'thr-03')!
  assert.equal(t3.revision, 3)
  store.submitDecision('thr-03', 'security', 'approved', '王岚', '安全确认')
  let cur = store.data.threats.find((t) => t.id === 'thr-03')!
  assert.equal(cur.reviewStatus, 'in_review', '单方不够')
  store.submitDecision('thr-03', 'development', 'approved', '赵恺', '开发确认')
  store.submitDecision('thr-03', 'business', 'approved', '宋雨', '业务确认')
  cur = store.data.threats.find((t) => t.id === 'thr-03')!
  assert.equal(cur.reviewStatus, 'approved', '三方齐备放行')
  assert.equal(cur.revision, 3)
  // 同角色重复提交只替换不重复
  store.submitDecision('thr-03', 'security', 'approved', '王岚', '安全再次确认')
  const sec = store.data.decisions.filter((d) => d.threatId === 'thr-03' && d.role === 'security' && d.revision === 3)
  assert.equal(sec.length, 1, '同角色同修订不重复追加')
  console.log('✓ 三方在同一新修订齐备才放行，同角色重提幂等')
}

// 放行后再改证据 → 已放行立即回到审核中，接受再次失效
{
  const store = freshStore()
  const ev = clone(store.data.evidence.find((e) => e.id === 'ev-03')!) // 属于 ctl-03
  ev.valid = false
  store.saveEvidence(ev)
  assert.equal(store.data.currentRevision, 4)
  const t3 = store.data.threats.find((t) => t.id === 'thr-03')!
  assert.equal(t3.revision, 4)
  assert.equal(t3.reviewStatus, 'in_review', '已通过被打回')
  const r3 = store.data.risks.find((r) => r.id === 'risk-03')!
  assert.equal(r3.status, 'mitigating', '重新接受也再次失效')
  console.log('✓ 证据变更使已放行威胁与风险接受再次失效')
}

// 在新修订重新接受风险
{
  const store = freshStore()
  store.acceptRisk('risk-03', '2027-01-01', '新条件')
  const r3 = store.data.risks.find((r) => r.id === 'risk-03')!
  assert.equal(r3.status, 'accepted')
  assert.equal(r3.acceptanceRevision, 4, '接受绑定威胁当前修订 r4')
  assert.equal(r3.supersededAcceptance, undefined)
  console.log('✓ 风险接受绑定当前有效修订')
}

// 并发：两个 store 实例（模拟两标签页），打开时记住修订，后到转待确认
{
  mem.clear()
  const tabA = freshStore()
  const tabB = freshStore() // 另一标签页载入相同状态
  // A 先保存 thr-01（基于 r2）
  const thrA = clone(tabA.data.threats.find((t) => t.id === 'thr-01')!)
  thrA.title = 'A 先到标题'
  const ra = tabA.saveThreat({ threat: thrA, baseRevision: 2 })
  assert.equal(ra.conflict, false)
  assert.equal(tabA.data.currentRevision, 3)
  // B 仍记住 r2，随后保存
  const thrB = clone(tabB.data.threats.find((t) => t.id === 'thr-01')!)
  thrB.title = 'B 后到标题'
  const rb = tabB.saveThreat({ threat: thrB, baseRevision: 2 })
  assert.equal(rb.conflict, true)
  const held = tabB.data.threats.find((t) => t.id === 'thr-01')!
  assert.equal(held.title, 'A 先到标题', '先到内容保留')
  assert.equal(held.reviewStatus, 'pending_confirmation')
  assert.equal(held.conflictDraft?.title, 'B 后到标题')
  // B 不能在待确认状态会签
  const blocked = tabB.submitDecision('thr-01', 'security', 'approved', '王岚', '尝试签署')
  assert.equal(blocked.ok, false)
  // 合并草稿 → 新修订重新会签
  tabB.resolveConflict('thr-01', true)
  const merged = tabB.data.threats.find((t) => t.id === 'thr-01')!
  assert.equal(merged.title, 'B 后到标题', '草稿合并生效')
  assert.equal(merged.revision, 4)
  assert.equal(merged.reviewStatus, 'in_review')
  assert.equal(merged.conflictDraft, undefined)
  // A 标签页通过 storage 同步
  const synced = tabA.syncFromStorage()
  assert.ok(synced)
  assert.equal(tabA.data.threats.find((t) => t.id === 'thr-01')!.title, 'B 后到标题')
  assert.equal(tabA.data.currentRevision, 4)
  console.log('✓ 双标签页并发：后到草稿待确认 → 合并到新修订 → 跨页同步')
}

// 放弃草稿路径
{
  mem.clear()
  const tabA = freshStore()
  const tabB = freshStore()
  const thrA = clone(tabA.data.threats.find((t) => t.id === 'thr-01')!)
  thrA.title = 'A'
  tabA.saveThreat({ threat: thrA, baseRevision: 2 })
  const thrB = clone(tabB.data.threats.find((t) => t.id === 'thr-01')!)
  thrB.title = 'B'
  tabB.saveThreat({ threat: thrB, baseRevision: 2 })
  tabB.resolveConflict('thr-01', false)
  const kept = tabB.data.threats.find((t) => t.id === 'thr-01')!
  assert.equal(kept.title, 'A', '放弃后保留先到')
  assert.equal(kept.conflictDraft, undefined)
  console.log('✓ 放弃后到草稿，保留先到有效修订')
}

// 崩溃恢复：阶段一后链 applied:false，新 store 打开自动补齐
{
  mem.clear()
  const store = freshStore()
  // 直接篡改存储，制造未完成记录
  const chain = JSON.parse(mem.get('scapex-revision-chain-v1')!)
  const pending = {
    ...clone(chain.at(-1)),
    id: 'chn-pending',
    seq: chain.at(-1).seq + 1,
    revision: 9,
    type: 'threat_save',
    applied: false,
    threats: [
      {
        ...clone(store.data.threats[0]),
        revision: 9,
        reviewStatus: 'in_review',
        basisRevision: 9,
        title: '崩溃前未完成保存',
      },
    ],
  }
  chain.push(pending)
  mem.set('scapex-revision-chain-v1', JSON.stringify(chain))
  // 状态快照不含该威胁更新（模拟阶段二前崩溃）
  const reopened = freshStore()
  assert.ok(reopened.lastRecoveredCount >= 1)
  const t = reopened.data.threats.find((x) => x.id === store.data.threats[0].id)!
  assert.equal(t.title, '崩溃前未完成保存', '未完成对象被补齐')
  assert.equal(t.revision, 9)
  assert.equal(reopened.data.currentRevision, 9)
  // 再打开不重复
  const again = freshStore()
  assert.equal(again.lastRecoveredCount, 0)
  console.log('✓ 写入中断后打开自动补齐未完成对象且不重复')
}

// 普通实体保存也入链、可重放
{
  mem.clear()
  const store = freshStore()
  const before = store.data.audit.length
  store.saveEntity('mitigations', {
    ...clone(store.data.mitigations[0]),
    title: '更新后的缓解任务',
  })
  assert.equal(store.data.mitigations[0].title, '更新后的缓解任务')
  assert.equal(store.data.audit.length, before + 1)
  assert.equal(store.data.revisionChain.at(-1)!.type, 'entity_save')
  console.log('✓ 普通实体与审计统一入修订链')
}

// 组件改动也级联（thr-01 关联 cmp-01/cmp-02）
{
  mem.clear()
  const store = freshStore()
  const cmp = clone(store.data.components.find((c) => c.id === 'cmp-02')!)
  cmp.owner = '新团队'
  store.saveEntity('components', cmp)
  assert.equal(store.data.currentRevision, 3)
  const t1 = store.data.threats.find((t) => t.id === 'thr-01')!
  assert.equal(t1.revision, 3)
  assert.equal(t1.reviewStatus, 'in_review')
  console.log('✓ 组件变更同样使关联威胁在新修订重签')
}

console.log('\n全部 store 端到端场景验证通过 ✅')
