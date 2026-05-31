<template>
  <FloatingWindow
    id="map"
    :title="title"
    :visible="visible"
    :default-geom="defaultGeom"
    :min-size="{ w: 20, h: 12 }"
    @update:visible="v => emit('update:visible', v)"
  >
    <template #default>
      <div class="map-body">
        <div v-if="rows.length === 0" class="empty">
          No paths known yet. Configure a TCP peer in Settings → Transports → TCP
          and wait for announces to arrive.
        </div>
        <table v-else class="map-table">
          <thead>
            <tr>
              <th>Destination</th>
              <th>Iface</th>
              <th>Neighbor</th>
              <th>Hops</th>
              <th>Last announce</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="r in rows" :key="r.hash">
              <td class="mono trunc">{{ r.hash }}</td>
              <td>{{ r.iface || '-' }}</td>
              <td class="mono trunc">{{ r.neighbor || '-' }}</td>
              <td class="num">{{ r.hops }}</td>
              <td class="num">{{ formatAge(r.lastAnnounce) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>
  </FloatingWindow>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import FloatingWindow from 'spangap-browser/components/FloatingWindow.vue'
import { useDeviceStore } from 'spangap-browser/stores/device'

defineProps<{ visible: boolean; title: string }>()
const emit = defineEmits<{ 'update:visible': [value: boolean] }>()

const defaultGeom = { x: 10, y: 8, w: 80, h: 70 }

interface Row {
  hash: string
  iface: string
  neighbor: string
  hops: number
  lastAnnounce: number
}

const device = useDeviceStore()

/* rnsd.paths is an array of `{dest, next_hop, next_hop_addr, hops, last_announce}`.
 * Sort by hops asc / last_announce desc. */
const rows = computed<Row[]>(() => {
  const arr = device.get('rnsd.paths')
  if (!Array.isArray(arr)) return []
  return arr.map((p: any) => ({
    hash:         String(p?.dest ?? ''),
    iface:        String(p?.next_hop ?? ''),
    neighbor:     String(p?.next_hop_addr ?? ''),
    hops:         Number(p?.hops ?? 0),
    lastAnnounce: Number(p?.last_announce ?? 0),
  })).sort((a, b) => a.hops - b.hops || b.lastAnnounce - a.lastAnnounce)
})

function formatAge(epochSecs: number): string {
  if (!epochSecs) return '-'
  const ageS = Math.round(Date.now() / 1000 - epochSecs)
  if (ageS < 0) return `${Math.round(epochSecs)}`
  if (ageS < 60)    return `${ageS}s ago`
  if (ageS < 3600)  return `${Math.floor(ageS / 60)}m ago`
  if (ageS < 86400) return `${Math.floor(ageS / 3600)}h ago`
  return `${Math.floor(ageS / 86400)}d ago`
}
</script>

<style scoped>
.map-body {
  height: 100%;
  overflow: auto;
  padding: 8px;
  color: #d8d8d8;
  font-size: 13px;
}
.empty {
  color: #888;
  font-style: italic;
  padding: 12px;
  text-align: center;
}
.map-table {
  width: 100%;
  border-collapse: collapse;
}
.map-table th, .map-table td {
  text-align: left;
  padding: 4px 8px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.08);
}
.map-table th {
  position: sticky;
  top: 0;
  background: #1f1f1f;
  color: #aaa;
  font-weight: 600;
  font-size: 12px;
}
.map-table .mono {
  font-family: 'JetBrains Mono', 'Menlo', monospace;
  font-size: 12px;
}
.map-table .trunc {
  max-width: 220px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.map-table .num {
  text-align: right;
  font-variant-numeric: tabular-nums;
}
</style>
