<template>
  <FloatingWindow
    id="nodes"
    :title="title"
    :visible="visible"
    :default-geom="defaultGeom"
    :min-size="{ w: 20, h: 12 }"
    @update:visible="v => emit('update:visible', v)"
  >
    <template #default>
      <div class="nodes-body">
        <div v-if="rows.length === 0" class="empty">
          No nodes seen yet. Connect a TCP peer and wait for announces.
        </div>
        <table v-else class="nodes-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Destination</th>
              <th class="num">Hops</th>
              <th class="num">Count</th>
              <th class="num">Last seen</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="r in rows" :key="r.dest">
              <td class="name" :title="`identity ${r.identity}`">{{ r.name || '—' }}</td>
              <td class="mono trunc" :title="r.dest">{{ r.dest }}</td>
              <td class="num">{{ r.hops === HOPS_UNKNOWN ? '?' : r.hops }}</td>
              <td class="num">{{ r.count }}</td>
              <td class="num">{{ formatAge(r.lastSeen) }}</td>
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

const defaultGeom = { x: 8, y: 6, w: 84, h: 75 }
const HOPS_UNKNOWN = 128       /* µR PATHFINDER_M */

interface Row {
  dest: string
  identity: string
  name: string
  hops: number
  count: number
  lastSeen: number
}

const device = useDeviceStore()

const rows = computed<Row[]>(() => {
  const arr = device.get('rnsd.nodes')
  if (!Array.isArray(arr)) return []
  return arr.map((n: any) => ({
    dest:     String(n?.dest ?? ''),
    identity: String(n?.identity ?? ''),
    name:     String(n?.name ?? ''),
    hops:     Number(n?.hops ?? HOPS_UNKNOWN),
    count:    Number(n?.count ?? 0),
    lastSeen: Number(n?.last_seen ?? 0),
  })).sort((a, b) => b.lastSeen - a.lastSeen)
})

function formatAge(epochSecs: number): string {
  if (!epochSecs) return '—'
  const ageS = Math.round(Date.now() / 1000 - epochSecs)
  if (ageS < 0)     return `${Math.round(epochSecs)}`
  if (ageS < 60)    return `${ageS}s ago`
  if (ageS < 3600)  return `${Math.floor(ageS / 60)}m ago`
  if (ageS < 86400) return `${Math.floor(ageS / 3600)}h ago`
  return `${Math.floor(ageS / 86400)}d ago`
}
</script>

<style scoped>
.nodes-body {
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
.nodes-table {
  width: 100%;
  border-collapse: collapse;
}
.nodes-table th, .nodes-table td {
  text-align: left;
  padding: 4px 8px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.08);
}
.nodes-table th {
  position: sticky;
  top: 0;
  background: #1f1f1f;
  color: #aaa;
  font-weight: 600;
  font-size: 12px;
}
.nodes-table .mono {
  font-family: 'JetBrains Mono', 'Menlo', monospace;
  font-size: 12px;
  color: #b8b8b8;
}
.nodes-table .trunc {
  max-width: 180px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.nodes-table .num {
  text-align: right;
  font-variant-numeric: tabular-nums;
}
.nodes-table .name {
  font-weight: 500;
  color: #e8e8e8;
}
</style>
