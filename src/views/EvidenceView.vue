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
import type { ControlEvidence, SecurityControl } from '@/models/domain'
import { createId } from '@/services/repository'
import { evidenceIsExpired } from '@/services/selectors'
import { useThreatModelStore } from '@/stores/threatModel'

const store = useThreatModelStore()
const toast = useToast()
const evidenceVisible = ref(false)
const controlVisible = ref(false)
const validityFilter = ref<string | null>(null)
const controlFilter = ref<string | null>(null)

const kindOptions = [
  { label: '测试记录', value: 'test' },
  { label: '配置快照', value: 'config' },
  { label: '工单记录', value: 'ticket' },
  { label: '扫描报告', value: 'scan' },
  { label: '签署证明', value: 'attestation' },
]
const validityOptions = [
  { label: '有效', value: 'valid' },
  { label: '已过期', value: 'expired' },
  { label: '已失效', value: 'invalid' },
]
const controlTypeOptions = [
  { label: '预防性', value: 'preventive' },
  { label: '检测性', value: 'detective' },
  { label: '纠正性', value: 'corrective' },
]
const controlStatusOptions = [
  { label: '有效', value: 'effective' },
  { label: '降级', value: 'degraded' },
  { label: '失效', value: 'failed' },
  { label: '计划中', value: 'planned' },
]

const evidenceForm = reactive<ControlEvidence>({
  id: '',
  controlId: '',
  title: '',
  kind: 'test',
  reference: '',
  collectedAt: '',
  expiresAt: '',
  owner: '',
  valid: true,
})

const controlForm = reactive<SecurityControl>({
  id: '',
  name: '',
  type: 'preventive',
  status: 'effective',
  owner: '',
  componentId: '',
  description: '',
  evidenceIds: [],
})

const filteredEvidence = computed(() =>
  store.data.evidence.filter((evidence) => {
    const validity = evidenceIsExpired(evidence) ? 'expired' : evidence.valid ? 'valid' : 'invalid'
    return (
      (!controlFilter.value || evidence.controlId === controlFilter.value) &&
      (!validityFilter.value || validity === validityFilter.value)
    )
  }),
)

const effectiveControls = computed(
  () =>
    store.data.controls.filter((control) =>
      control.evidenceIds.some((id) => {
        const evidence = store.data.evidence.find((item) => item.id === id)
        return evidence?.valid && !evidenceIsExpired(evidence)
      }),
    ).length,
)

const impactedThreatCount = (controlId: string): number =>
  store.data.threats.filter((threat) => threat.controlIds.includes(controlId)).length

const controlName = (id: string): string =>
  store.data.controls.find((control) => control.id === id)?.name ?? id

const validity = (evidence: ControlEvidence): string =>
  evidenceIsExpired(evidence) ? 'expired' : evidence.valid ? 'valid' : 'invalid'

const openEvidenceEditor = (evidence?: ControlEvidence): void => {
  Object.assign(
    evidenceForm,
    evidence
      ? structuredClone(evidence)
      : {
          id: '',
          controlId: store.data.controls[0]?.id ?? '',
          title: '',
          kind: 'test',
          reference: '',
          collectedAt: new Date().toISOString().slice(0, 10),
          expiresAt: '',
          owner: '',
          valid: true,
        },
  )
  evidenceVisible.value = true
}

const saveEvidence = (): void => {
  if (
    !evidenceForm.title.trim() ||
    !evidenceForm.controlId ||
    !evidenceForm.reference.trim() ||
    !evidenceForm.owner.trim()
  ) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '控制、标题、引用编号和责任人不能为空', life: 3000 })
    return
  }
  if (!evidenceForm.collectedAt || !evidenceForm.expiresAt) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '采集日与到期日不能为空', life: 3000 })
    return
  }
  if (new Date(evidenceForm.expiresAt) <= new Date(evidenceForm.collectedAt)) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '到期日必须晚于采集日', life: 3000 })
    return
  }
  store.saveEvidence({ ...evidenceForm, id: evidenceForm.id || createId('ev') })
  evidenceVisible.value = false
  toast.add({
    severity: 'success',
    summary: '证据已保存',
    detail: '关联威胁与风险接受已在新修订上失效，等待重新会签',
    life: 3200,
  })
}

const openControlEditor = (control?: SecurityControl): void => {
  Object.assign(
    controlForm,
    control
      ? structuredClone(control)
      : {
          id: '',
          name: '',
          type: 'preventive',
          status: 'planned',
          owner: '',
          componentId: store.data.components[0]?.id ?? '',
          description: '',
          evidenceIds: [],
        },
  )
  controlVisible.value = true
}

const saveControl = (): void => {
  if (!controlForm.name.trim() || !controlForm.owner.trim() || !controlForm.componentId) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '控制名称、责任人和所属组件不能为空', life: 3000 })
    return
  }
  store.saveControl({ ...controlForm, id: controlForm.id || createId('ctl') })
  controlVisible.value = false
  toast.add({
    severity: 'success',
    summary: '控制已保存',
    detail: `已触发新修订，${impactedThreatCount(controlForm.id)} 条关联威胁需重新三方会签`,
    life: 3200,
  })
}
</script>

<template>
  <div class="page">
    <PageHeader
      eyebrow="控制保障"
      title="控制与证据"
      description="维护安全控制及其证据。控制或证据一改动，关联威胁会签与风险接受立即在新修订上失效，三方重新签署后才能放行。"
    />

    <div class="evidence-metrics">
      <div>
        <span>控制总数</span>
        <strong>{{ store.data.controls.length }}</strong>
      </div>
      <div>
        <span>具备有效证据</span>
        <strong>{{ effectiveControls }}</strong>
      </div>
      <div>
        <span>过期证据</span>
        <strong class="danger-text">{{ store.data.evidence.filter(evidenceIsExpired).length }}</strong>
      </div>
      <div>
        <span>证据缺口</span>
        <strong>{{ store.issues.filter((issue) => issue.kind === 'missing_evidence').length }}</strong>
      </div>
    </div>

    <section class="panel">
      <div class="panel-header">
        <h2 class="panel-title">安全控制</h2>
        <Button label="新增/编辑控制" icon="pi pi-plus" @click="openControlEditor()" />
      </div>
      <DataTable :value="store.data.controls" dataKey="id" size="small" stripedRows>
        <Column field="name" header="控制" />
        <Column header="类型" style="width: 100px">
          <template #body="{ data }">
            {{ controlTypeOptions.find((item) => item.value === data.type)?.label }}
          </template>
        </Column>
        <Column header="状态" style="width: 90px">
          <template #body="{ data }">
            <StatusTag :value="data.status" kind="status" />
          </template>
        </Column>
        <Column header="修订依据" style="width: 100px">
          <template #body="{ data }">
            <span class="mono">r{{ data.basisRevision ?? store.data.currentRevision }}</span>
          </template>
        </Column>
        <Column header="关联威胁" style="width: 100px">
          <template #body="{ data }">{{ impactedThreatCount(data.id) }} 条</template>
        </Column>
        <Column field="owner" header="责任人" style="width: 120px" />
        <Column header="操作" style="width: 100px">
          <template #body="{ data }">
            <Button label="编辑" size="small" text @click="openControlEditor(data)" />
          </template>
        </Column>
      </DataTable>
    </section>

    <section class="panel filter-panel">
      <div class="toolbar-row">
        <div class="toolbar-field">
          <span>关联控制</span>
          <Select
            v-model="controlFilter"
            :options="store.data.controls"
            option-label="name"
            option-value="id"
            placeholder="全部控制"
            show-clear
          />
        </div>
        <div class="toolbar-field">
          <span>有效性</span>
          <Select
            v-model="validityFilter"
            :options="validityOptions"
            option-label="label"
            option-value="value"
            placeholder="全部状态"
            show-clear
          />
        </div>
        <div class="filter-actions">
          <Button label="登记证据" icon="pi pi-plus" @click="openEvidenceEditor()" />
        </div>
      </div>
    </section>

    <section class="panel">
      <div class="panel-header">
        <h2 class="panel-title">证据清单</h2>
        <span class="muted">{{ filteredEvidence.length }} 条</span>
      </div>
      <DataTable :value="filteredEvidence" dataKey="id" size="small" stripedRows>
        <Column field="title" header="证据" />
        <Column header="关联控制" style="width: 210px">
          <template #body="{ data }">{{ controlName(data.controlId) }}</template>
        </Column>
        <Column header="类型" style="width: 100px">
          <template #body="{ data }">
            {{ kindOptions.find((item) => item.value === data.kind)?.label }}
          </template>
        </Column>
        <Column field="reference" header="引用编号" style="width: 145px" />
        <Column field="owner" header="责任人" style="width: 120px" />
        <Column field="collectedAt" header="采集日" style="width: 110px" />
        <Column field="expiresAt" header="到期日" style="width: 110px" />
        <Column header="状态" style="width: 110px">
          <template #body="{ data }">
            <StatusTag
              :value="validity(data) === 'valid' ? 'effective' : validity(data) === 'expired' ? 'high' : 'failed'"
              kind="status"
            />
          </template>
        </Column>
        <Column header="操作" style="width: 100px">
          <template #body="{ data }">
            <Button label="编辑" size="small" text @click="openEvidenceEditor(data)" />
          </template>
        </Column>
      </DataTable>
    </section>

    <Dialog
      v-model:visible="controlVisible"
      :header="controlForm.id ? '编辑控制（将触发重新会签）' : '新增控制'"
      modal
      :style="{ width: '720px' }"
    >
      <div class="editor-form">
        <div class="field field-wide">
          <label>控制名称</label>
          <InputText v-model="controlForm.name" />
        </div>
        <div class="field">
          <label>控制类型</label>
          <Select
            v-model="controlForm.type"
            :options="controlTypeOptions"
            option-label="label"
            option-value="value"
          />
        </div>
        <div class="field">
          <label>控制状态</label>
          <Select
            v-model="controlForm.status"
            :options="controlStatusOptions"
            option-label="label"
            option-value="value"
          />
        </div>
        <div class="field">
          <label>所属组件</label>
          <Select
            v-model="controlForm.componentId"
            :options="store.data.components"
            option-label="name"
            option-value="id"
            filter
          />
        </div>
        <div class="field">
          <label>责任人</label>
          <InputText v-model="controlForm.owner" />
        </div>
        <div class="field field-wide">
          <label>关联证据</label>
          <MultiSelect
            v-model="controlForm.evidenceIds"
            :options="store.data.evidence"
            option-label="title"
            option-value="id"
            display="chip"
            filter
          />
        </div>
        <div class="field field-wide">
          <label>控制说明</label>
          <Textarea v-model="controlForm.description" rows="3" />
        </div>
        <small class="muted">
          保存即生成新修订：引用该控制的威胁会签意见全部失效，关联风险接受回到处置中，三方需在新修订重新签署。
        </small>
      </div>
      <template #footer>
        <Button label="取消" severity="secondary" outlined @click="controlVisible = false" />
        <Button label="保存控制" icon="pi pi-check" @click="saveControl" />
      </template>
    </Dialog>

    <Dialog
      v-model:visible="evidenceVisible"
      :header="evidenceForm.id ? '编辑控制证据（将触发重新会签）' : '登记控制证据'"
      modal
      :style="{ width: '720px' }"
    >
      <div class="editor-form">
        <div class="field field-wide">
          <label>证据标题</label>
          <InputText v-model="evidenceForm.title" />
        </div>
        <div class="field">
          <label>关联控制</label>
          <Select
            v-model="evidenceForm.controlId"
            :options="store.data.controls"
            option-label="name"
            option-value="id"
          />
        </div>
        <div class="field">
          <label>证据类型</label>
          <Select
            v-model="evidenceForm.kind"
            :options="kindOptions"
            option-label="label"
            option-value="value"
          />
        </div>
        <div class="field">
          <label>引用编号</label>
          <InputText v-model="evidenceForm.reference" />
        </div>
        <div class="field">
          <label>责任人</label>
          <InputText v-model="evidenceForm.owner" />
        </div>
        <div class="field">
          <label>采集日期</label>
          <InputText v-model="evidenceForm.collectedAt" type="date" />
        </div>
        <div class="field">
          <label>到期日期</label>
          <InputText v-model="evidenceForm.expiresAt" type="date" />
        </div>
        <div class="field field-wide">
          <label>证据状态</label>
          <Select
            v-model="evidenceForm.valid"
            :options="[
              { label: '有效', value: true },
              { label: '失效', value: false },
            ]"
            option-label="label"
            option-value="value"
          />
        </div>
      </div>
      <template #footer>
        <Button label="取消" severity="secondary" outlined @click="evidenceVisible = false" />
        <Button label="保存证据" icon="pi pi-check" @click="saveEvidence" />
      </template>
    </Dialog>
  </div>
</template>

<style scoped>
.evidence-metrics {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 1px;
  overflow: hidden;
  border: 1px solid #dfe4eb;
  border-radius: 6px;
  background: #dfe4eb;
}

.evidence-metrics > div {
  display: grid;
  gap: 9px;
  padding: 15px 16px;
  background: #fff;
}

.evidence-metrics span {
  color: #6d788c;
  font-size: 12px;
}

.evidence-metrics strong {
  font-size: 24px;
}

.filter-panel {
  margin-top: 16px;
  padding: 14px 16px;
}

.mono {
  color: #3268a6;
  font-family: monospace;
  font-size: 12px;
}
</style>
