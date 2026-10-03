<script setup lang="ts">
import { onMounted, onUnmounted } from 'vue'
import ConfirmDialog from 'primevue/confirmdialog'
import Toast from 'primevue/toast'
import { useThreatModelStore } from '@/stores/threatModel'

const store = useThreatModelStore()

// 其他标签页保存后，本页对齐到修订链上的最新有效修订
const onStorage = (event: StorageEvent): void => {
  if (event.key === 'scapex-threat-model-v1' || event.key === 'scapex-revision-chain-v1') {
    store.syncFromStorage()
  }
}

onMounted(() => window.addEventListener('storage', onStorage))
onUnmounted(() => window.removeEventListener('storage', onStorage))
</script>

<template>
  <RouterView />
  <Toast position="top-right" />
  <ConfirmDialog />
</template>
