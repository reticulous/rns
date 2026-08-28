<!-- IfacePills — the interface-class pills in the top bar: one letter and a
     count per medium that is switched on. `L3` is three peers on LoRa, the same
     three `lora n` lists; `T0` is TCP configured and not connected.

     Nothing about any medium lives here. Each interface straddle publishes its
     own pill — text, colour and placement — under rns.pill.<id>.*, and this
     renders whatever is there, so a medium added later needs no edit to this
     file. The on-device status bar reads exactly the same keys. -->
<template>
  <div v-if="pills.length" class="iface-pills">
    <span v-for="p in pills" :key="p.id" class="pill"
          :style="{ color: `#${p.color}`, borderColor: `#${p.color}` }">{{ p.text }}</span>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useDeviceStore } from 'spangap-browser/stores/device'

const device = useDeviceStore()

/* Empty text is a pill taken down (the firmware empties rather than deletes, so
 * the display's subscriber hears about it), which is not the same as one that
 * was never published. Both render as nothing here. */
const pills = computed(() => {
  const tree = device.get('rns.pill') as Record<string, any> | undefined
  if (!tree) return []
  return Object.entries(tree)
    .map(([id, v]) => ({
      id,
      text: String(v?.text ?? ''),
      color: String(v?.color || '888888'),
      order: Number(v?.order ?? 0),
    }))
    .filter(p => p.text !== '')
    .sort((a, b) => a.order - b.order || a.id.localeCompare(b.id))
})
</script>

<style scoped>
.iface-pills {
  display: inline-flex;
  align-items: center;
  gap: 4px;
}
.pill {
  font: 600 11px/1 ui-monospace, SFMono-Regular, Menlo, monospace;
  padding: 3px 5px;
  border: 1px solid;
  border-radius: 4px;
  opacity: 0.9;
  white-space: nowrap;
}
</style>
