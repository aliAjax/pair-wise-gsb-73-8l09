<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import Button from 'primevue/button'
import Column from 'primevue/column'
import DataTable from 'primevue/datatable'
import Dialog from 'primevue/dialog'
import InputText from 'primevue/inputtext'
import MultiSelect from 'primevue/multiselect'
import Select from 'primevue/select'
import Textarea from 'primevue/textarea'
import { useToast } from 'primevue/usetoast'
import PageHeader from '@/components/PageHeader.vue'
import StatusTag from '@/components/StatusTag.vue'
import type { Threat } from '@/models/domain'
import { createId } from '@/services/repository'
import { useThreatModelStore } from '@/stores/threatModel'

const store = useThreatModelStore()
const toast = useToast()

const keyword = ref('')
const severityFilter = ref<string | null>(null)
const statusFilter = ref<string | null>(null)
const categoryFilter = ref<string | null>(null)
const selectedId = ref(store.data.threats[0]?.id ?? '')
const editorVisible = ref(false)
/** 页面/编辑器打开时记住的修订号，用于检测两个标签页的并发保存 */
const editingBaseRevision = ref(store.data.currentRevision)

const severityOptions = [
  { label: '严重', value: 'critical' },
  { label: '高', value: 'high' },
  { label: '中', value: 'medium' },
  { label: '低', value: 'low' },
]
const statusOptions = [
  { label: '开放', value: 'open' },
  { label: '处置中', value: 'mitigating' },
  { label: '已缓解', value: 'mitigated' },
  { label: '已接受', value: 'accepted' },
]
const reviewOptions = [
  { label: '草稿', value: 'draft' },
  { label: '审核中', value: 'in_review' },
  { label: '已通过', value: 'approved' },
  { label: '已驳回', value: 'rejected' },
]
const categoryOptions = [
  { label: '身份伪造', value: 'spoofing' },
  { label: '数据篡改', value: 'tampering' },
  { label: '否认操作', value: 'repudiation' },
  { label: '信息泄露', value: 'information_disclosure' },
  { label: '拒绝服务', value: 'denial_of_service' },
  { label: '权限提升', value: 'elevation' },
]

const threatForm = reactive<Threat>({
  id: '',
  code: '',
  title: '',
  category: 'information_disclosure',
  description: '',
  severity: 'medium',
  status: 'open',
  componentIds: [],
  flowIds: [],
  externalDependencyIds: [],
  attackPathIds: [],
  controlIds: [],
  riskIds: [],
  reviewStatus: 'draft',
  revision: store.data.currentRevision,
})

const filteredThreats = computed(() => {
  const normalized = keyword.value.trim().toLowerCase()
  return store.data.threats.filter((threat) => {
    const textMatches =
      !normalized ||
      threat.title.toLowerCase().includes(normalized) ||
      threat.code.toLowerCase().includes(normalized) ||
      threat.description.toLowerCase().includes(normalized)
    return (
      textMatches &&
      (!severityFilter.value || threat.severity === severityFilter.value) &&
      (!statusFilter.value || threat.status === statusFilter.value) &&
      (!categoryFilter.value || threat.category === categoryFilter.value)
    )
  })
})

const selectedThreat = computed(
  () => store.data.threats.find((threat) => threat.id === selectedId.value) ?? null,
)
const currentDecisions = computed(() =>
  selectedThreat.value ? store.effectiveDecisions(selectedThreat.value) : [],
)
const staleDecisionCount = computed(() => {
  if (!selectedThreat.value) return 0
  return store.data.decisions.filter(
    (decision) =>
      decision.threatId === selectedThreat.value?.id &&
      decision.revision < selectedThreat.value.revision,
  ).length
})
const revisionBasisRisks = computed(() => {
  if (!selectedThreat.value) return []
  return selectedThreat.value.riskIds
    .map((id) => store.data.risks.find((risk) => risk.id === id))
    .filter((risk): risk is NonNullable<typeof risk> => Boolean(risk))
    .map((risk) => ({
      ...risk,
      stale:
        typeof risk.acceptanceRevision === 'number' &&
        (risk.acceptanceRevision ?? 0) < (selectedThreat.value?.revision ?? 0),
    }))
})
const relatedComponents = computed(
  () =>
    selectedThreat.value?.componentIds
      .map((id) => store.data.components.find((component) => component.id === id))
      .filter(Boolean) ?? [],
)
const relatedControls = computed(
  () =>
    selectedThreat.value?.controlIds
      .map((id) => store.data.controls.find((control) => control.id === id))
      .filter(Boolean) ?? [],
)
const relatedPaths = computed(
  () =>
    selectedThreat.value?.attackPathIds
      .map((id) => store.data.attackPaths.find((path) => path.id === id))
      .filter(Boolean) ?? [],
)

const clearFilters = (): void => {
  keyword.value = ''
  severityFilter.value = null
  statusFilter.value = null
  categoryFilter.value = null
}

const editThreat = (): void => {
  if (!selectedThreat.value) return
  Object.assign(threatForm, structuredClone(selectedThreat.value))
  // 打开编辑器时记住当前修订号
  editingBaseRevision.value = selectedThreat.value.revision
  editorVisible.value = true
}

const addThreat = (): void => {
  const sequence = store.data.threats.length + 1
  Object.assign(threatForm, {
    id: '',
    code: `TM-${String(sequence).padStart(3, '0')}`,
    title: '',
    category: 'information_disclosure',
    description: '',
    severity: 'medium',
    status: 'open',
    componentIds: [],
    flowIds: [],
    externalDependencyIds: [],
    attackPathIds: [],
    controlIds: [],
    riskIds: [],
    reviewStatus: 'draft',
    revision: store.data.currentRevision,
    pendingConfirmation: false,
    pendingBaseSnapshot: undefined,
  } satisfies Threat)
  editingBaseRevision.value = store.data.currentRevision
  editorVisible.value = true
}

const saveThreat = (): void => {
  if (!threatForm.code.trim() || !threatForm.title.trim() || !threatForm.description.trim()) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '编号、标题和描述不能为空', life: 3000 })
    return
  }
  if (threatForm.componentIds.length === 0 && threatForm.flowIds.length === 0) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '至少关联一个组件或数据流', life: 3000 })
    return
  }
  const duplicateCode = store.data.threats.some(
    (threat) => threat.code === threatForm.code && threat.id !== threatForm.id,
  )
  if (duplicateCode) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '威胁编号已存在', life: 3000 })
    return
  }

  const candidate: Threat = {
    ...threatForm,
    id: threatForm.id || createId('thr'),
  }
  const outcome = store.saveThreat(candidate, editingBaseRevision.value)
  if (outcome.recoveredEntries > 0) {
    toast.add({
      severity: 'warn',
      summary: '已从修订链恢复',
      detail: `主仓库写入失败，仅补写未完成对象 ${outcome.recoveredEntries} 条，未重复追加记录`,
      life: 4000,
    })
  }
  if (outcome.conflict) {
    selectedId.value = candidate.id
    editorVisible.value = false
    toast.add({
      severity: 'warn',
      summary: '检测到并发保存',
      detail: '另一标签页已先保存该威胁，你的草稿已保留并转待确认',
      life: 4500,
    })
    return
  }
  selectedId.value = candidate.id
  editorVisible.value = false
  toast.add({
    severity: 'success',
    summary: '威胁已保存',
    detail: threatForm.id ? `已进入 v1.${store.data.currentRevision} 重新审核` : threatForm.title,
    life: 3000,
  })
}

const resolveConflict = (resolution: 'apply_draft' | 'discard_draft'): void => {
  if (!selectedThreat.value) return
  store.resolveThreatConflict(selectedThreat.value.id, resolution, selectedThreat.value)
  toast.add({
    severity: 'success',
    summary: resolution === 'apply_draft' ? '已采用草稿' : '已放弃草稿',
    detail:
      resolution === 'apply_draft'
        ? '草稿在新修订上生效，三方需重新会签'
        : '已恢复另一标签页先保存的版本',
    life: 3000,
  })
}
</script>

<template>
  <div class="page">
    <PageHeader
      eyebrow="威胁分析"
      title="威胁清单"
      description="把威胁、攻击路径、现有控制和风险关联到具体组件或数据流，并跟踪修订后的审核状态。"
    />

    <section class="panel filter-panel">
      <div class="toolbar-row">
        <div class="toolbar-field keyword-field">
          <span>关键词</span>
          <InputText v-model="keyword" placeholder="搜索编号、标题或描述" />
        </div>
        <div class="toolbar-field">
          <span>严重级别</span>
          <Select
            v-model="severityFilter"
            :options="severityOptions"
            option-label="label"
            option-value="value"
            placeholder="全部"
            show-clear
          />
        </div>
        <div class="toolbar-field">
          <span>处置状态</span>
          <Select
            v-model="statusFilter"
            :options="statusOptions"
            option-label="label"
            option-value="value"
            placeholder="全部"
            show-clear
          />
        </div>
        <div class="toolbar-field">
          <span>威胁类别</span>
          <Select
            v-model="categoryFilter"
            :options="categoryOptions"
            option-label="label"
            option-value="value"
            placeholder="全部"
            show-clear
          />
        </div>
        <div class="filter-actions">
          <Button label="清空" severity="secondary" text @click="clearFilters" />
          <Button label="新增威胁" icon="pi pi-plus" @click="addThreat" />
        </div>
      </div>
    </section>

    <div class="threat-workspace">
      <section class="panel list-panel">
        <div class="panel-header">
          <h2 class="panel-title">威胁结果 {{ filteredThreats.length }} 条</h2>
        </div>
        <DataTable
          :value="filteredThreats"
          dataKey="id"
          selectionMode="single"
          :selection="selectedThreat"
          size="small"
          scrollable
          scrollHeight="640px"
          @row-click="({ data }) => (selectedId = data.id)"
        >
          <Column field="code" header="编号" style="width: 92px">
            <template #body="{ data }">
              <strong class="threat-code">{{ data.code }}</strong>
            </template>
          </Column>
          <Column field="title" header="威胁" />
          <Column header="级别" style="width: 74px">
            <template #body="{ data }">
              <StatusTag :value="data.severity" kind="severity" />
            </template>
          </Column>
          <Column header="状态" style="width: 90px">
            <template #body="{ data }">
              <StatusTag :value="data.status" kind="status" />
            </template>
          </Column>
          <template #empty>
            <div class="empty-state">没有符合条件的威胁。</div>
          </template>
        </DataTable>
      </section>

      <aside class="panel detail-panel">
        <template v-if="selectedThreat">
          <div v-if="selectedThreat.pendingConfirmation" class="conflict-strip">
            <div>
              <strong>并发保存 · 待确认</strong>
              <span>
                另一标签页已先保存为 v1.{{ selectedThreat.pendingBaseSnapshot?.revision }}；
                当前内容是你的草稿，需选择采用草稿（进入新修订重新会签）或放弃草稿。
              </span>
            </div>
            <div class="conflict-actions">
              <Button label="采用草稿" size="small" @click="resolveConflict('apply_draft')" />
              <Button
                label="放弃草稿"
                size="small"
                severity="secondary"
                outlined
                @click="resolveConflict('discard_draft')"
              />
            </div>
          </div>
          <div class="detail-head">
            <div>
              <div class="threat-code">{{ selectedThreat.code }}</div>
              <h2>{{ selectedThreat.title }}</h2>
            </div>
            <Button icon="pi pi-pencil" label="编辑" outlined @click="editThreat" />
          </div>
          <div class="status-line">
            <StatusTag :value="selectedThreat.severity" kind="severity" />
            <StatusTag :value="selectedThreat.status" kind="status" />
            <StatusTag :value="selectedThreat.reviewStatus" kind="review" />
            <span class="muted">有效修订 v1.{{ selectedThreat.revision }}</span>
            <span v-if="selectedThreat.revision < store.data.currentRevision" class="muted">
              · 基线 v1.{{ store.data.currentRevision }}
            </span>
          </div>

          <p class="description">{{ selectedThreat.description }}</p>

          <section class="detail-section">
            <h3>修订依据</h3>
            <div class="revision-basis">
              <div v-for="risk in revisionBasisRisks" :key="risk.id" class="basis-row" :class="{ stale: risk.stale }">
                <strong>{{ risk.code }} {{ risk.title }}</strong>
                <span v-if="typeof risk.acceptanceRevision === 'number'">
                  风险接受依据 v1.{{ risk.acceptanceRevision }}
                  <em v-if="risk.stale">（已随修订失效，需重新接受并会签）</em>
                  <em v-else>（有效）</em>
                </span>
                <span v-else class="muted">未接受风险</span>
              </div>
            </div>
          </section>

          <section class="detail-section">
            <h3>关联组件</h3>
            <div class="relation-list">
              <div v-for="component in relatedComponents" :key="component?.id" class="relation-item">
                <strong>{{ component?.name }}</strong>
                <span>{{ component?.type }} · {{ component?.owner }}</span>
              </div>
            </div>
          </section>

          <section class="detail-section">
            <h3>攻击路径</h3>
            <div v-for="path in relatedPaths" :key="path?.id" class="path-item">
              <strong>{{ path?.name }}</strong>
              <ol>
                <li v-for="step in path?.steps" :key="step">{{ step }}</li>
              </ol>
            </div>
            <div v-if="relatedPaths.length === 0" class="muted">尚未关联攻击路径。</div>
          </section>

          <section class="detail-section">
            <h3>现有控制</h3>
            <div v-for="control in relatedControls" :key="control?.id" class="control-line">
              <div>
                <strong>{{ control?.name }}</strong>
                <span>{{ control?.type }} · {{ control?.owner }} · v1.{{ control?.revision }}</span>
              </div>
              <StatusTag v-if="control" :value="control.status" kind="status" />
            </div>
          </section>

          <section class="detail-section">
            <h3>当前有效修订会签（{{ currentDecisions.length }}/3）</h3>
            <div v-for="decision in currentDecisions" :key="decision.id" class="decision-line">
              <strong>{{ decision.actor }}</strong>
              <StatusTag :value="decision.decision" kind="review" />
              <span class="muted">{{ decision.comment }}</span>
            </div>
            <div v-if="currentDecisions.length === 0" class="muted">
              v1.{{ selectedThreat.revision }} 上尚无会签，三方需重新签署。
            </div>
            <div v-if="staleDecisionCount > 0" class="stale-note">
              另有 {{ staleDecisionCount }} 条旧修订会签意见已随 v1.{{ selectedThreat.revision }} 失效。
            </div>
          </section>
        </template>
        <div v-else class="empty-state">从左侧选择一条威胁查看分析详情。</div>
      </aside>
    </div>

    <Dialog
      v-model:visible="editorVisible"
      :header="threatForm.id ? '编辑威胁并触发重新审核' : '新增威胁'"
      modal
      :style="{ width: '860px' }"
    >
      <div class="editor-form">
        <div class="field">
          <label>威胁编号</label>
          <InputText v-model="threatForm.code" />
        </div>
        <div class="field">
          <label>严重级别</label>
          <Select
            v-model="threatForm.severity"
            :options="severityOptions"
            option-label="label"
            option-value="value"
          />
        </div>
        <div class="field field-wide">
          <label>威胁标题</label>
          <InputText v-model="threatForm.title" />
        </div>
        <div class="field">
          <label>威胁类别</label>
          <Select
            v-model="threatForm.category"
            :options="categoryOptions"
            option-label="label"
            option-value="value"
          />
        </div>
        <div class="field">
          <label>处置状态</label>
          <Select
            v-model="threatForm.status"
            :options="statusOptions"
            option-label="label"
            option-value="value"
          />
        </div>
        <div class="field field-wide">
          <label>威胁描述</label>
          <Textarea v-model="threatForm.description" rows="4" />
        </div>
        <div class="field field-wide">
          <label>关联组件</label>
          <MultiSelect
            v-model="threatForm.componentIds"
            :options="store.data.components"
            option-label="name"
            option-value="id"
            display="chip"
            filter
          />
        </div>
        <div class="field">
          <label>关联数据流</label>
          <MultiSelect
            v-model="threatForm.flowIds"
            :options="store.data.flows"
            option-label="name"
            option-value="id"
            display="chip"
            filter
          />
        </div>
        <div class="field">
          <label>外部依赖</label>
          <MultiSelect
            v-model="threatForm.externalDependencyIds"
            :options="store.data.dependencies"
            option-label="name"
            option-value="id"
            display="chip"
          />
        </div>
        <div class="field">
          <label>攻击路径</label>
          <MultiSelect
            v-model="threatForm.attackPathIds"
            :options="store.data.attackPaths"
            option-label="name"
            option-value="id"
            display="chip"
          />
        </div>
        <div class="field">
          <label>现有控制</label>
          <MultiSelect
            v-model="threatForm.controlIds"
            :options="store.data.controls"
            option-label="name"
            option-value="id"
            display="chip"
          />
        </div>
        <div class="field">
          <label>关联风险</label>
          <MultiSelect
            v-model="threatForm.riskIds"
            :options="store.data.risks"
            option-label="title"
            option-value="id"
            display="chip"
          />
        </div>
        <div class="field">
          <label>审核状态</label>
          <Select
            v-model="threatForm.reviewStatus"
            :options="reviewOptions"
            option-label="label"
            option-value="value"
          />
        </div>
      </div>
      <template #footer>
        <Button label="取消" severity="secondary" outlined @click="editorVisible = false" />
        <Button label="保存威胁" icon="pi pi-check" @click="saveThreat" />
      </template>
    </Dialog>
  </div>
</template>

<style scoped>
.filter-panel {
  padding: 14px 16px;
}

.keyword-field {
  min-width: 280px;
}

.threat-workspace {
  display: grid;
  grid-template-columns: minmax(620px, 1.2fr) minmax(390px, 0.8fr);
  gap: 16px;
  align-items: start;
}

.list-panel {
  min-width: 0;
  overflow: hidden;
}

.threat-code {
  color: #3268a6;
  font-family: monospace;
  font-size: 12px;
}

.detail-panel {
  position: sticky;
  top: 82px;
  max-height: calc(100vh - 106px);
  overflow: auto;
}

.detail-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 18px;
  padding: 18px;
  border-bottom: 1px solid #e5e9ef;
}

.detail-head h2 {
  margin: 6px 0 0;
  font-size: 18px;
  line-height: 1.4;
}

.status-line {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 18px;
}

.description {
  margin: 0;
  padding: 0 18px 18px;
  color: #4f5b70;
  font-size: 13px;
  line-height: 1.7;
}

.detail-section {
  padding: 16px 18px;
  border-top: 1px solid #e8ebf0;
}

.detail-section h3 {
  margin: 0 0 12px;
  font-size: 13px;
}

.relation-list {
  display: grid;
  gap: 8px;
}

.relation-item,
.control-line {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 10px;
  border: 1px solid #e2e6ec;
  border-radius: 5px;
}

.relation-item {
  display: grid;
  justify-content: stretch;
}

.relation-item span,
.control-line span {
  color: #727d90;
  font-size: 11px;
}

.path-item {
  padding: 11px;
  border-left: 3px solid #8aa4c3;
  background: #f7f9fb;
}

.path-item strong {
  font-size: 12px;
}

.path-item ol {
  margin: 8px 0 0;
  padding-left: 19px;
  color: #5b687d;
  font-size: 12px;
  line-height: 1.7;
}

.control-line + .control-line {
  margin-top: 8px;
}

.conflict-strip {
  display: grid;
  gap: 10px;
  padding: 14px 18px;
  border-bottom: 1px solid #f0d2a8;
  background: #fff7ec;
}

.conflict-strip > div:first-child {
  display: grid;
  gap: 5px;
}

.conflict-strip strong {
  color: #b45309;
  font-size: 13px;
}

.conflict-strip span {
  color: #7b5d2c;
  font-size: 12px;
  line-height: 1.6;
}

.conflict-actions {
  display: flex;
  gap: 8px;
}

.revision-basis {
  display: grid;
  gap: 8px;
}

.basis-row {
  display: grid;
  gap: 4px;
  padding: 9px 10px;
  border: 1px solid #e2e6ec;
  border-radius: 5px;
}

.basis-row strong {
  font-size: 12px;
}

.basis-row span {
  color: #5b687d;
  font-size: 11px;
}

.basis-row em {
  font-style: normal;
  color: #b45309;
}

.basis-row.stale {
  border-color: #f0d2a8;
  background: #fffaf2;
}

.decision-line {
  display: grid;
  grid-template-columns: 70px auto 1fr;
  align-items: center;
  gap: 8px;
  padding: 7px 0;
  border-bottom: 1px solid #eef0f3;
  font-size: 12px;
}

.stale-note {
  margin-top: 8px;
  color: #b45309;
  font-size: 11px;
}
</style>
