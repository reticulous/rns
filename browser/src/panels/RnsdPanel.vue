<template>
  <div class="q-gutter-y-md">
    <PanelHeading title="Reticulum" />

    <div class="q-gutter-y-sm">
      <div class="text-caption text-grey-5">Identity hash</div>
      <div class="text-mono identity-hash">{{ identityHash || '(generating…)' }}</div>
    </div>

    <q-separator dark />

    <SettingToggle label="Enable" k="s.rnsd.enable" />
    <SettingToggle label="Act as transport node — forward packets for others"
                   k="s.rnsd.transport_enabled" />
    <SettingText label="Node name (optional)" k="s.rnsd.name" />
    <SettingSlider label="Announce interval (s)" k="s.rnsd.announce.interval"
                   :min="0" :max="21600" :step="600" />
    <div class="text-caption text-grey-5">0 = on demand only.</div>

    <q-separator dark />

    <SettingSlider label="Path table capacity" k="s.rnsd.path.max"
                   :min="64" :max="512" :step="64" />
    <SettingSlider label="Path TTL (s)" k="s.rnsd.path.ttl"
                   :min="3600" :max="604800" :step="3600" />
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useDeviceStore } from 'spangap-browser/stores/device'

const device = useDeviceStore()
const identityHash = computed(() => String(device.get('rnsd.identity_hash') ?? ''))
</script>

<style scoped>
.identity-hash {
  font-family: 'JetBrains Mono', 'Menlo', monospace;
  font-size: 0.85em;
  word-break: break-all;
  color: #b8d8a8;
}
.text-mono { font-family: monospace; }
</style>
