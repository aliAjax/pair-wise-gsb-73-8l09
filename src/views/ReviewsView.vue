<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import Button from 'primevue/button'
import Dialog from 'primevue/dialog'
import InputText from 'primevue/inputtext'
import ProgressBar from 'primevue/progressbar'
import Select from 'primevue/select'
import Textarea from 'primevue/textarea'
import { useToast } from 'primevue/usetoast'
import PageHeader from '@/components/PageHeader.vue'
import StatusTag from '@/components/StatusTag.vue'
import type { ActorRole, DecisionType, Threat } from '@/models/domain'
import { decisionsForThreat, reviewProgress } from '@/services/selectors'
import { useThreatModelStore } from '@/stores/threatModel'

const store = useThreatModelStore()
const toast = useToast()
const selectedThreatId = ref('')
const decisionVisible = ref(false)

const roleOptions: { label: string; value: ActorRole; actor: string }[] = [
  { label: '开发负责人', value: 'development', actor: '赵恺' },
  { label: '安全负责人', value: 'security', actor: '王岚' },
  { label: '业务负责人', value: 'business', actor: '宋雨' },
]
const decisionOptions = [
  { label: '通过', value: 'approved' },
  { label: '接受条件', value: 'accept' },
  { label: '同意降级', value: 'degrade' },
  { label: '要求补证', value: 'evidence_required' },
  { label: '驳回', value: 'rejected' },
]

const form = reactive<{
  role: ActorRole
  decision: DecisionType
  actor: string
  comment: string
}>({
  role: 'security',
  decision: 'approved',
  actor: '王岚',
  comment: '',
})

const latestVersion = computed(() => store.data.versions[0])
const effectiveRevision = computed(() => store.data.currentRevision)
const affectedThreats = computed(() => {
  const ids = new Set(latestVersion.value?.affectedThreatIds ?? store.data.threats.map((threat) => threat.id))
  // 仅展示当前有效修订上仍需会签（审核中或待确认）的威胁
  return store.data.threats.filter(
    (threat) =>
      ids.has(threat.id) &&
      (threat.reviewStatus === 'in_review' || threat.reviewStatus === 'pending_confirmation'),
  )
})
const selectedThreat = computed(
  () => store.data.threats.find((threat) => threat.id === selectedThreatId.value) ?? null,
)
const currentDecisions = computed(() =>
  selectedThreat.value
    ? decisionsForThreat(
        store.data.decisions,
        selectedThreat.value.id,
        selectedThreat.value.revision,
      )
    : [],
)

const statusForRole = (threat: Threat, role: ActorRole): DecisionType | 'pending' =>
  decisionsForThreat(store.data.decisions, threat.id, threat.revision).find(
    (decision) => decision.role === role,
  )?.decision ?? 'pending'

const openDecision = (): void => {
  if (!selectedThreat.value) return
  if (selectedThreat.value.reviewStatus === 'pending_confirmation') {
    toast.add({
      severity: 'warn',
      summary: '存在并发冲突',
      detail: '请先在威胁详情确认合并或放弃草稿，再在新修订上会签',
      life: 3500,
    })
    return
  }
  form.comment = ''
  form.role = 'security'
  form.actor = '王岚'
  form.decision = 'approved'
  decisionVisible.value = true
}

const changeRole = (): void => {
  form.actor = roleOptions.find((item) => item.value === form.role)?.actor ?? form.actor
}

const submitDecision = (): void => {
  if (!selectedThreat.value) return
  if (!form.comment.trim()) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '会签意见不能为空', life: 3000 })
    return
  }
  const result = store.submitDecision(
    selectedThreat.value.id,
    form.role,
    form.decision,
    form.actor,
    form.comment,
  )
  if (!result.ok) {
    toast.add({ severity: 'warn', summary: '暂不能会签', detail: result.reason ?? '请稍后再试', life: 3500 })
    return
  }
  decisionVisible.value = false
  toast.add({
    severity: 'success',
    summary: '会签意见已提交',
    detail: `已记录到 r${selectedThreat.value.revision}，三方在同一修订上齐备后放行`,
    life: 2500,
  })
}

const resolveSelected = (merge: boolean): void => {
  if (!selectedThreat.value) return
  store.resolveConflict(selectedThreat.value.id, merge)
}

const decisionLabel = (decision: DecisionType | 'pending'): string =>
  decision === 'pending'
    ? '待提交'
    : decisionOptions.find((item) => item.value === decision)?.label ?? decision
</script>

<template>
  <div class="page">
    <PageHeader
      eyebrow="受影响范围"
      title="逐项会签中心"
      :description="`所有意见按同一有效修订 r${effectiveRevision} 展示；控制或证据变更后，关联威胁必须在新修订上重新三方会签。`"
    />

    <section class="version-context">
      <div>
        <span>当前有效修订</span>
        <strong>r{{ effectiveRevision }}</strong>
      </div>
      <div>
        <span>审核基线</span>
        <strong>{{ latestVersion?.label ?? '尚未建立版本' }}</strong>
      </div>
      <div>
        <span>有效修订待会签</span>
        <strong>{{ affectedThreats.length }} 条</strong>
      </div>
    </section>

    <div class="review-board">
      <section class="review-list">
        <article
          v-for="threat in affectedThreats"
          :key="threat.id"
          class="review-card"
          :class="{ selected: selectedThreatId === threat.id }"
          @click="selectedThreatId = threat.id"
        >
          <div class="review-card-head">
            <div>
              <span class="mono">{{ threat.code }} · r{{ threat.revision }}</span>
              <h2>{{ threat.title }}</h2>
            </div>
            <StatusTag :value="threat.reviewStatus" kind="review" />
          </div>
          <div v-if="threat.reviewStatus === 'pending_confirmation'" class="pending-note">
            <i class="pi pi-exclamation-triangle"></i>
            并发保存待确认：后到标签页的编辑已保留为草稿，确认后才会进入会签
          </div>
          <div class="role-grid">
            <div v-for="role in roleOptions" :key="role.value" class="role-state">
              <span>{{ role.label }}</span>
              <strong :class="{ pending: statusForRole(threat, role.value) === 'pending' }">
                {{ decisionLabel(statusForRole(threat, role.value)) }}
              </strong>
            </div>
          </div>
          <ProgressBar
            :value="reviewProgress(decisionsForThreat(store.data.decisions, threat.id, threat.revision))"
            :show-value="false"
            class="review-progress"
          />
        </article>
      </section>

      <aside class="decision-panel">
        <template v-if="selectedThreat">
          <div class="decision-head">
            <div>
              <span class="mono">{{ selectedThreat.code }} · 有效修订 r{{ selectedThreat.revision }}</span>
              <h2>{{ selectedThreat.title }}</h2>
            </div>
            <StatusTag :value="selectedThreat.reviewStatus" kind="review" />
          </div>
          <p class="decision-description">{{ selectedThreat.description }}</p>

          <section v-if="selectedThreat.reviewStatus === 'pending_confirmation'" class="conflict-box">
            <strong>并发冲突草稿（基于 r{{ selectedThreat.conflictBaseRevision }}）</strong>
            <p>{{ selectedThreat.conflictDraft?.description }}</p>
            <div class="conflict-actions">
              <Button label="合并草稿并进入新会签" icon="pi pi-check" size="small" @click="resolveSelected(true)" />
              <Button
                label="放弃草稿"
                icon="pi pi-times"
                size="small"
                severity="secondary"
                outlined
                @click="resolveSelected(false)"
              />
            </div>
          </section>

          <Button
            label="提交会签意见"
            icon="pi pi-pencil"
            :disabled="selectedThreat.reviewStatus === 'pending_confirmation'"
            @click="openDecision"
          />

          <section class="decision-history">
            <h3>有效修订 r{{ selectedThreat.revision }} 会签记录</h3>
            <article v-for="decision in currentDecisions" :key="decision.id" class="decision-entry">
              <div>
                <strong>{{ decision.actor }}</strong>
                <span>{{ roleOptions.find((role) => role.value === decision.role)?.label }}</span>
              </div>
              <StatusTag :value="decision.decision" kind="review" />
              <p>{{ decision.comment }}</p>
              <time>{{ new Date(decision.createdAt).toLocaleString('zh-CN') }}</time>
            </article>
            <div v-if="currentDecisions.length === 0" class="empty-state">
              旧修订会签已随控制/证据变更失效，请三方在 r{{ selectedThreat.revision }} 上重新签署。
            </div>
          </section>
        </template>
        <div v-else class="empty-state">从左侧选择一条有效修订上的待会签威胁。</div>
      </aside>
    </div>

    <Dialog v-model:visible="decisionVisible" header="提交会签意见" modal :style="{ width: '620px' }">
      <div class="editor-form">
        <div class="field">
          <label>会签角色</label>
          <Select
            v-model="form.role"
            :options="roleOptions"
            option-label="label"
            option-value="value"
            @change="changeRole"
          />
        </div>
        <div class="field">
          <label>会签人</label>
          <InputText v-model="form.actor" />
        </div>
        <div class="field field-wide">
          <label>意见类型</label>
          <Select
            v-model="form.decision"
            :options="decisionOptions"
            option-label="label"
            option-value="value"
          />
        </div>
        <div class="field field-wide">
          <label>意见与条件</label>
          <Textarea
            v-model="form.comment"
            rows="5"
            placeholder="通过、降级、接受或补证都需要写明具体条件"
          />
        </div>
      </div>
      <template #footer>
        <Button label="取消" severity="secondary" outlined @click="decisionVisible = false" />
        <Button label="提交意见" icon="pi pi-check" @click="submitDecision" />
      </template>
    </Dialog>
  </div>
</template>

<style scoped>
.version-context {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 1px;
  overflow: hidden;
  border: 1px solid #dfe4eb;
  border-radius: 6px;
  background: #dfe4eb;
}

.version-context > div {
  display: grid;
  gap: 7px;
  padding: 14px 16px;
  background: #fff;
}

.version-context span {
  color: #717c8f;
  font-size: 11px;
}

.review-board {
  display: grid;
  grid-template-columns: minmax(0, 1.25fr) minmax(390px, 0.75fr);
  gap: 16px;
  align-items: start;
}

.review-list {
  display: grid;
  gap: 12px;
}

.review-card {
  padding: 16px;
  border: 1px solid #dde2ea;
  border-radius: 7px;
  background: #fff;
  cursor: pointer;
}

.review-card:hover,
.review-card.selected {
  border-color: #7898bb;
  box-shadow: 0 0 0 1px rgba(70, 108, 150, 0.1);
}

.review-card-head,
.decision-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 18px;
}

.review-card h2,
.decision-head h2 {
  margin: 6px 0 0;
  font-size: 16px;
}

.role-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 8px;
  margin-top: 16px;
}

.role-state {
  display: grid;
  gap: 4px;
  padding: 9px 10px;
  border: 1px solid #e2e6ec;
  border-radius: 5px;
  background: #f9fafb;
}

.role-state span {
  color: #737e91;
  font-size: 10px;
}

.role-state strong {
  color: #2e684f;
  font-size: 11px;
}

.role-state strong.pending {
  color: #a05a00;
}

.review-progress {
  height: 4px;
  margin-top: 14px;
}

.pending-note {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  margin-top: 12px;
  padding: 9px 10px;
  border: 1px solid #f2c78f;
  border-radius: 5px;
  background: #fffaf0;
  color: #8a5a17;
  font-size: 11px;
  line-height: 1.5;
}

.pending-note > i {
  margin-top: 2px;
}

.conflict-box {
  display: grid;
  gap: 8px;
  margin-bottom: 14px;
  padding: 12px;
  border: 1px solid #f2c78f;
  border-left: 4px solid #d97706;
  border-radius: 6px;
  background: #fffaf0;
}

.conflict-box strong {
  font-size: 12px;
  color: #8a5a17;
}

.conflict-box p {
  margin: 0;
  color: #7b5d2c;
  font-size: 12px;
  line-height: 1.6;
}

.conflict-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.decision-panel {
  position: sticky;
  top: 82px;
  padding: 18px;
  border: 1px solid #dde2ea;
  border-radius: 7px;
  background: #fff;
}

.decision-description {
  margin: 14px 0 18px;
  color: #59657a;
  font-size: 13px;
  line-height: 1.65;
}

.decision-history {
  margin-top: 22px;
  padding-top: 18px;
  border-top: 1px solid #e5e9ef;
}

.decision-history h3 {
  margin: 0 0 12px;
  font-size: 13px;
}

.decision-entry {
  position: relative;
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 8px;
  padding: 11px 0;
  border-bottom: 1px solid #eef0f3;
}

.decision-entry > div {
  display: grid;
  gap: 3px;
}

.decision-entry span,
.decision-entry time {
  color: #7a8496;
  font-size: 10px;
}

.decision-entry p {
  grid-column: 1 / -1;
  margin: 0;
  color: #566176;
  font-size: 12px;
  line-height: 1.5;
}
</style>
