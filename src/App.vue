<script setup lang="ts">
import { onBeforeUnmount, onMounted } from 'vue'
import ConfirmDialog from 'primevue/confirmdialog'
import Toast from 'primevue/toast'
import { CHAIN_STORAGE_KEY } from '@/services/revisionChain'
import { STORAGE_KEY } from '@/services/repository'
import { useThreatModelStore } from '@/stores/threatModel'

const store = useThreatModelStore()

// 另一标签页提交修订后，本标签页按修订链增量同步，看板/详情/会签随之展示同一有效修订
const handleStorage = (event: StorageEvent): void => {
  if (event.key !== CHAIN_STORAGE_KEY && event.key !== STORAGE_KEY) return
  store.syncFromStorage()
}

onMounted(() => window.addEventListener('storage', handleStorage))
onBeforeUnmount(() => window.removeEventListener('storage', handleStorage))
</script>

<template>
  <RouterView />
  <Toast position="top-right" />
  <ConfirmDialog />
</template>
