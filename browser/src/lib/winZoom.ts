/**
 * Per-window font-zoom — the LXMF / Nomad analogue of the Log/CLI `-`/`+`
 * zoom buttons. Returns a reactive unitless `scale` (bind to a `--rfs` CSS
 * custom property on the window root; child styles use
 * `font-size: calc(<px> * var(--rfs, 1))`, and because custom properties
 * cascade across scoped-style boundaries it reaches every descendant
 * component) plus zoomIn/zoomOut. The step is persisted per window in
 * localStorage. Default is intentionally > 1 so text starts larger.
 */
import { ref, computed } from 'vue'

export function useWinZoom(key: string, defStep = 2) {
  const lsKey = `diptych.win.${key}.zoom`
  const stored = localStorage.getItem(lsKey)
  const step = ref(stored !== null ? (Number(stored) || 0) : defStep)

  const scale = computed(() => Math.max(0.7, 1 + step.value * 0.1))

  const persist = () => { try { localStorage.setItem(lsKey, String(step.value)) } catch { /* */ } }
  const zoomIn  = () => { step.value = Math.min(step.value + 1, 14); persist() }
  const zoomOut = () => { step.value = Math.max(step.value - 1, -3); persist() }

  return { scale, zoomIn, zoomOut }
}
