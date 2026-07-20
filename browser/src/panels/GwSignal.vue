<!-- GwSignal — top-bar indicator for the gateway/infrastructure signal level:
     the received RSSI/SNR of the transport node that last relayed a packet to
     us (rnsd.gw.*, published by rnsd for the last packet that arrived on a
     signal-capable interface, for one of our destinations, with hops > 0).
     Four ascending amber link-quality bars, matching the LXMF message bubble
     and the on-device status bar. Collapses to nothing until a sample lands. -->
<template>
  <div v-if="bars > 0 && opacity > 0" class="gw-sig" :style="{ opacity }"
       title="Network signal — last transport node to relay to us">
    <i v-for="n in 4" :key="n" :class="{ on: n <= bars }" :style="{ height: `${2 + n * 2}px` }"></i>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, onMounted, onUnmounted } from 'vue'
import { useDeviceStore } from 'spangap-browser/stores/device'

const device = useDeviceStore()

function num(v: unknown): number | null {
  if (v === null || v === undefined || v === '') return null
  const n = Number(v)
  return Number.isFinite(n) ? n : null
}

/* Age-fade: the bars fade linearly to 0 over 30 min from rnsd.gw.timestamp
 * (device unix seconds). A coarse ticking clock re-evaluates opacity between
 * packets; a fresh sample resets the timestamp and so the fade. */
const FADE_S = 30 * 60
const nowSec = ref(Math.floor(Date.now() / 1000))
let timer: ReturnType<typeof setInterval> | undefined
onMounted(() => { timer = setInterval(() => { nowSec.value = Math.floor(Date.now() / 1000) }, 20000) })
onUnmounted(() => { if (timer) clearInterval(timer) })

const opacity = computed(() => {
  const ts = num(device.get('rnsd.gw.timestamp'))
  if (ts === null) return 1
  const age = nowSec.value - ts
  if (age <= 0) return 1
  if (age >= FADE_S) return 0
  return 1 - age / FADE_S
})

/* Fold RSSI (dBm) + SNR (dB) into 1..4 bars; 0 = no signal data. Same endpoints
 * as the LXMF message bars and the on-device status bar, so a link scores
 * identically on every surface. */
const bars = computed(() => {
  const rssi = num(device.get('rnsd.gw.rssi'))
  const snr = num(device.get('rnsd.gw.snr'))
  if (rssi === null && snr === null) return 0
  const clamp01 = (x: number) => (x < 0 ? 0 : x > 1 ? 1 : x)
  let q = 1
  if (rssi !== null) q = Math.min(q, clamp01((rssi + 120) / 60)) // -120 … -60 dBm
  if (snr !== null) q = Math.min(q, clamp01((snr + 15) / 25)) //  -15 … +10 dB
  return 1 + Math.floor(q * 3.999)
})
</script>

<style scoped>
.gw-sig {
  display: inline-flex;
  align-items: flex-end;
  gap: 2px;
  height: 16px;
}
.gw-sig i {
  width: 3px;
  background: #4a441c; /* dim amber (unlit) */
  border-radius: 1px;
  display: block;
}
.gw-sig i.on {
  background: #ffd400; /* lit */
}
</style>
