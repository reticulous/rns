<!-- NetGraph — the neighbourhood as a picture: this node in the middle, one
     circle per node around it, one line per LINK.

     Two things a plain node-link drawing does not do, and the reasons for both:

     - Lines take the MEDIUM's colour, the same colour its status-line pill uses
       (rns.pill.<class>.color, read live). One vocabulary for "which medium" on
       every surface, and no palette in this file.
     - Two nodes joined by more than one interface get one ARC PER LINK rather
       than one line. Parallel links are the interesting case on a mesh — a peer
       reachable over both LoRa and Bluetooth is a peer that stays reachable —
       and a single line would hide exactly that.

     The join behind "the same node over two media" is a shared destination
     hash, not a guess: see lib/netGraph.ts. Layout is lib/forceLayout.ts, the
     one seam a different engine would replace. -->
<template>
  <FloatingWindow
    id="netgraph"
    :title="title"
    :visible="visible"
    :focus-token="focusToken"
    :default-geom="defaultGeom"
    :min-size="{ w: 24, h: 20 }"
    @update:visible="v => emit('update:visible', v)"
  >
    <div ref="boxRef" class="ng-body">
      <svg class="ng-svg" :viewBox="`0 0 ${W} ${H}`" preserveAspectRatio="xMidYMid meet">
        <!-- Edges first, so a circle always sits on top of the lines into it. -->
        <g class="ng-edges">
          <path v-for="(e, i) in drawnEdges" :key="i" :d="e.d" :stroke="e.color"
                :stroke-dasharray="e.stale ? '4 4' : undefined" fill="none">
            <title>{{ e.tip }}</title>
          </path>
        </g>
        <g class="ng-nodes">
          <g v-for="(n, i) in drawnNodes" :key="n.key"
             :class="{ sel: i === selected }" @click="selected = i === selected ? -1 : i">
            <circle :cx="n.x" :cy="n.y" :r="n.r" :class="n.us ? 'us' : 'peer'" />
            <!-- A transport node forwards for others, which is the one property
                 of a node that changes what the graph MEANS: an edge through it
                 reaches further than itself. A second ring says so. -->
            <circle v-if="n.transport" :cx="n.x" :cy="n.y" :r="n.r + 4" class="transit" />
          </g>
        </g>
        <!-- Captions last, so a knockout covers the lines rather than the other
             way round, and above every circle for the same reason. -->
        <g class="ng-labels">
          <g v-for="l in labels" :key="l.key">
            <rect v-if="l.boxed" :x="l.bx" :y="l.by" :width="l.bw" :height="l.bh" rx="2" />
            <text :x="l.tx" :y="l.ty" :text-anchor="l.anchor">{{ l.text }}</text>
          </g>
        </g>
      </svg>

      <div v-if="!graph.edges.length" class="ng-empty">
        No neighbours yet. Nodes appear here as soon as an interface with a
        community radius reports a peer.
      </div>

      <!-- Which colour is which medium. Built from the pills that exist, so it
           names exactly the media this node has switched on. -->
      <div class="ng-legend">
        <span v-for="c in classes" :key="c.cls" class="ng-key">
          <i :style="{ background: c.color }"></i>{{ c.cls }}
        </span>
      </div>

      <div v-if="detail" class="ng-detail">
        <div class="ng-dt-head">
          <b>{{ detail.label }}</b>
          <span v-if="detail.transport" class="ng-tag">TRANSPORT</span>
          <button class="ng-close" @click="selected = -1">×</button>
        </div>
        <div v-for="a in detail.addresses" :key="a" class="ng-dt-row ng-dim">{{ a }}</div>
        <div v-for="l in detail.links" :key="l.iface" class="ng-dt-row">
          <i :style="{ background: l.color }"></i>{{ l.iface }}
          <span class="ng-dim">{{ l.detail }}</span>
        </div>
        <div v-for="d in detail.dests" :key="d.dest" class="ng-dt-row">
          <span class="ng-hash">{{ d.dest }}</span>
          <span class="ng-dim">{{ d.aspect }}</span>
          <span v-if="d.name">“{{ d.name }}”</span>
        </div>
      </div>
    </div>
  </FloatingWindow>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import FloatingWindow from 'spangap-browser/components/FloatingWindow.vue'
import { useDeviceStore } from 'spangap-browser/stores/device'
import { buildGraph } from '../lib/netGraph'
import { layout } from '../lib/forceLayout'

defineProps<{ visible: boolean; title: string; focusToken?: number }>()
const emit = defineEmits<{ 'update:visible': [value: boolean] }>()

const device = useDeviceStore()
const boxRef = ref<HTMLElement | null>(null)
const selected = ref(-1)
const defaultGeom = { x: 22, y: 10, w: 52, h: 70 }

/* A fixed viewBox with preserveAspectRatio: the layout runs in graph units and
 * the browser scales the result, so a resize never re-runs the simulation and
 * the picture never jumps under the hand doing the resizing. */
const W = 600
const H = 460

/* Recomputed whenever the mirrored store changes — the whole graph is a pure
 * function of rnsd's published tables, so there is nothing to keep in step. */
const graph = computed(() => buildGraph())

const classes = computed(() => {
  const seen = new Map<string, string>()
  for (const e of graph.value.edges) if (!seen.has(e.cls)) seen.set(e.cls, e.color)
  return [...seen].map(([cls, color]) => ({ cls, color })).sort((a, b) => a.cls.localeCompare(b.cls))
})

const positions = computed(() => {
  const g = graph.value
  return layout(
    g.nodes.map((n, i) => i === 0
      ? { fixed: true, x: W / 2, y: H / 2 }        /* us, pinned in the middle */
      : {}),
    g.edges.map(e => ({ source: 0, target: e.to })),
    { width: W, height: H },
  )
})

const drawnNodes = computed(() => {
  const g = graph.value
  const p = positions.value
  return g.nodes.map((n, i) => ({
    key: n.key,
    label: n.label,
    us: n.us,
    transport: n.transport,
    r: n.us ? 13 : 9,
    x: p[i]?.x ?? W / 2,
    y: p[i]?.y ?? H / 2,
  }))
})

/* ── label placement ──
 *
 * A caption printed straight under its circle lands on whatever happens to run
 * there, and on a graph the thing running there is usually an edge — the lines
 * all converge on this node, so the space around it is the busiest on the
 * canvas. So each label is TRIED in a ring of spots and takes the first clear
 * one; a label with nowhere clear to go is drawn on a knockout instead, which
 * is the honest fallback — a dense graph has no clear spot, and moving the
 * caption somewhere misleading to find one is worse than covering a line.
 *
 * All of it is straight-line geometry against sampled curves. The graph is a
 * neighbourhood — a handful of vertices — so the cost is nothing and there is
 * no reason to do it more cleverly. */
interface Pt { x: number; y: number }
interface Rect { x: number; y: number; w: number; h: number }

/** A quadratic Bézier as a short polyline. */
function samplePts(a: Pt, c: Pt, b: Pt): Pt[] {
  const N = 8
  const out: Pt[] = []
  for (let i = 0; i <= N; i++) {
    const t = i / N, u = 1 - t
    out.push({
      x: u * u * a.x + 2 * u * t * c.x + t * t * b.x,
      y: u * u * a.y + 2 * u * t * c.y + t * t * b.y,
    })
  }
  return out
}

function rectsOverlap(a: Rect, b: Rect): boolean {
  return a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h
}

function segsCross(p1: Pt, p2: Pt, p3: Pt, p4: Pt): boolean {
  const d = (p2.x - p1.x) * (p4.y - p3.y) - (p2.y - p1.y) * (p4.x - p3.x)
  if (Math.abs(d) < 1e-9) return false          // parallel; touching is not a hit
  const t = ((p3.x - p1.x) * (p4.y - p3.y) - (p3.y - p1.y) * (p4.x - p3.x)) / d
  const u = ((p3.x - p1.x) * (p2.y - p1.y) - (p3.y - p1.y) * (p2.x - p1.x)) / d
  return t >= 0 && t <= 1 && u >= 0 && u <= 1
}

function segHitsRect(p: Pt, q: Pt, r: Rect): boolean {
  const inside = (t: Pt) => t.x >= r.x && t.x <= r.x + r.w && t.y >= r.y && t.y <= r.y + r.h
  if (inside(p) || inside(q)) return true
  const c = [
    { x: r.x, y: r.y }, { x: r.x + r.w, y: r.y },
    { x: r.x + r.w, y: r.y + r.h }, { x: r.x, y: r.y + r.h },
  ]
  for (let i = 0; i < 4; i++) if (segsCross(p, q, c[i], c[(i + 1) % 4])) return true
  return false
}

/* Text is measured by the glyph budget rather than by the DOM: the labels are
 * names and hex, the face is one known size, and a layout that had to mount the
 * text before it could place it would place it a frame late. */
const CHAR_W = 6.1
const LINE_H = 12

function ago(heard: number): string {
  if (!heard) return 'no announce yet'
  const s = Math.max(0, Math.floor(Date.now() / 1000) - heard)
  if (s < 120) return `${s}s ago`
  if (s < 7200) return `${Math.floor(s / 60)}m ago`
  return `${Math.floor(s / 3600)}h ago`
}

/* Stale after an hour without an announce — dashed rather than hidden, because
 * "was here and has gone quiet" is a different thing from "not here". */
const STALE_S = 3600

const drawnEdges = computed(() => {
  const g = graph.value
  const p = positions.value
  const now = Math.floor(Date.now() / 1000)

  /* Parallel links get arcs. The whole bundle between one pair is collected
   * first, so the curvatures can be spread symmetrically about the straight
   * line — done per edge in isolation they would all bend the same way. */
  const bundles = new Map<number, number[]>()
  g.edges.forEach((e, i) => {
    const b = bundles.get(e.to) ?? []
    b.push(i)
    bundles.set(e.to, b)
  })

  const out: { d: string; color: string; stale: boolean; tip: string; pts: Pt[] }[] = []
  for (const [to, idxs] of bundles) {
    const a = p[0] ?? { x: W / 2, y: H / 2 }
    const b = p[to] ?? { x: W / 2, y: H / 2 }
    const dx = b.x - a.x, dy = b.y - a.y
    const len = Math.hypot(dx, dy) || 1
    /* Unit normal: the direction an arc bows away from the straight line. */
    const nx = -dy / len, ny = dx / len
    const spread = Math.min(26, len / 5)
    idxs.forEach((ei, k) => {
      const e = g.edges[ei]
      /* …, -1, 0, 1, … about the centre: one link is straight, two bow either
       * side of where the straight line would have been, and so on. */
      const off = (k - (idxs.length - 1) / 2) * spread
      const mx = (a.x + b.x) / 2 + nx * off * 2
      const my = (a.y + b.y) / 2 + ny * off * 2
      const sig = e.rssi ? `  ${e.rssi} dBm${e.snr ? ` / ${e.snr} dB` : ''}` : ''
      out.push({
        d: `M${a.x.toFixed(1)},${a.y.toFixed(1)} Q${mx.toFixed(1)},${my.toFixed(1)} ${b.x.toFixed(1)},${b.y.toFixed(1)}`,
        color: e.color,
        stale: e.heard > 0 && now - e.heard > STALE_S,
        tip: `${e.iface}${e.label ? `  ${e.label}` : ''}  ·  ${e.peers} destination${e.peers === 1 ? '' : 's'}  ·  ${ago(e.heard)}${sig}`,
        /* The same curve as a polyline, for the label placer to keep clear of.
         * Sampled rather than solved: a quadratic against a rectangle has a
         * closed form nobody needs here, and eight chords are already finer
         * than the 2 px the line is drawn at. */
        pts: samplePts(a, { x: mx, y: my }, b),
      })
    })
  }
  return out
})

/* One placed caption per vertex. Runs after the edges, because where the edges
 * went is the whole question. */
const labels = computed(() => {
  const nodes = drawnNodes.value
  const edges = drawnEdges.value
  const placed: Rect[] = []

  return nodes.map(n => {
    const w = Math.max(n.label.length * CHAR_W, 8)
    /* Below first — it is where a caption belongs, and the ring only exists
     * because that spot is often taken. Then above, then the sides, then the
     * diagonals: each step further from the convention, and taken only when
     * everything nearer it is blocked. */
    const cands: { tx: number; ty: number; anchor: string; x: number }[] = [
      { tx: n.x, ty: n.y + n.r + 12, anchor: 'middle', x: n.x - w / 2 },
      { tx: n.x, ty: n.y - n.r - 5,  anchor: 'middle', x: n.x - w / 2 },
      { tx: n.x + n.r + 6, ty: n.y + 4, anchor: 'start', x: n.x + n.r + 6 },
      { tx: n.x - n.r - 6, ty: n.y + 4, anchor: 'end',   x: n.x - n.r - 6 - w },
      { tx: n.x + n.r + 4, ty: n.y + n.r + 12, anchor: 'start', x: n.x + n.r + 4 },
      { tx: n.x - n.r - 4, ty: n.y + n.r + 12, anchor: 'end',   x: n.x - n.r - 4 - w },
      { tx: n.x + n.r + 4, ty: n.y - n.r - 5,  anchor: 'start', x: n.x + n.r + 4 },
      { tx: n.x - n.r - 4, ty: n.y - n.r - 5,  anchor: 'end',   x: n.x - n.r - 4 - w },
    ]

    let chosen = cands[0]
    let boxed = true
    for (const c of cands) {
      const r: Rect = { x: c.x - 2, y: c.ty - 9, w: w + 4, h: LINE_H }
      /* Off the canvas is not a clear spot — a caption cropped by the edge of
       * the picture is as unreadable as one under a line. */
      if (r.x < 2 || r.y < 2 || r.x + r.w > W - 2 || r.y + r.h > H - 2) continue
      let hit = false
      for (const e of edges) {
        for (let i = 0; i + 1 < e.pts.length && !hit; i++)
          if (segHitsRect(e.pts[i], e.pts[i + 1], r)) hit = true
        if (hit) break
      }
      /* And clear of the other circles, and of every caption already placed —
       * two overlapping names are no more readable than a name on a line. */
      if (!hit) for (const o of nodes) {
        if (o === n) continue
        if (rectsOverlap(r, { x: o.x - o.r, y: o.y - o.r, w: o.r * 2, h: o.r * 2 })) { hit = true; break }
      }
      if (!hit) for (const p of placed) if (rectsOverlap(r, p)) { hit = true; break }
      if (!hit) { chosen = c; boxed = false; placed.push(r); break }
    }
    if (boxed) placed.push({ x: chosen.x - 2, y: chosen.ty - 9, w: w + 4, h: LINE_H })

    return {
      key: n.key, text: n.label, anchor: chosen.anchor,
      tx: chosen.tx, ty: chosen.ty,
      /* Nowhere clear: keep the conventional spot and knock the lines out
       * behind the text instead of hiding the caption or moving it somewhere it
       * would read as belonging to another circle. */
      boxed,
      bx: chosen.x - 2, by: chosen.ty - 9, bw: w + 4, bh: LINE_H,
    }
  })
})

const detail = computed(() => {
  const g = graph.value
  const i = selected.value
  if (i < 0 || i >= g.nodes.length) return null
  const n = g.nodes[i]
  return {
    label: n.label,
    transport: n.transport,
    addresses: n.us && device.get('rnsd.identity_hash')
      ? [`identity ${device.get('rnsd.identity_hash')}`]
      : n.addresses,
    links: g.edges.filter(e => e.to === i).map(e => ({
      iface: e.iface,
      color: e.color,
      detail: `${e.peers} destination${e.peers === 1 ? '' : 's'} · ${ago(e.heard)}`,
    })),
    dests: n.dests,
  }
})
</script>

<style scoped>
.ng-body {
  position: relative;
  width: 100%;
  height: 100%;
  overflow: hidden;
  background: #0e1319;
}
.ng-svg { width: 100%; height: 100%; display: block; }
.ng-edges path { stroke-width: 2; opacity: 0.85; }
.ng-nodes g { cursor: pointer; }
.ng-nodes circle.peer { fill: #1b2836; stroke: #7f8b99; stroke-width: 2; }
.ng-nodes circle.us   { fill: #244055; stroke: #eef3f8; stroke-width: 2.5; }
.ng-nodes circle.transit { fill: none; stroke: #7f8b99; stroke-width: 1; opacity: 0.55; }
.ng-nodes g.sel circle.peer,
.ng-nodes g.sel circle.us { stroke: #ffd400; }
/* The captions are decoration over the picture: a click belongs to the circle
 * under them, and a knockout must not swallow one. */
.ng-labels { pointer-events: none; }
.ng-labels text {
  fill: #cfd8e3;
  font: 11px/1 ui-sans-serif, system-ui, sans-serif;
}
/* Only under a caption that found nowhere clear. Black rather than the panel's
 * own background: it is meant to read as a deliberate knockout over the lines,
 * not as a hole in the picture. */
.ng-labels rect { fill: #000; opacity: 0.82; }
.ng-empty {
  position: absolute; inset: auto 12px 44px 12px;
  color: #8b97a5; font-size: 12px; text-align: center;
}
.ng-legend {
  position: absolute; left: 8px; bottom: 6px;
  display: flex; flex-wrap: wrap; gap: 8px;
  font: 11px/1.6 ui-monospace, SFMono-Regular, Menlo, monospace; color: #8b97a5;
}
.ng-key i, .ng-dt-row i {
  display: inline-block; width: 8px; height: 8px; border-radius: 2px;
  margin-right: 4px; vertical-align: middle;
}
.ng-detail {
  position: absolute; right: 8px; top: 8px; max-width: 62%;
  background: #131a22ee; border: 1px solid #2a3542; border-radius: 6px;
  padding: 6px 8px; font: 11px/1.6 ui-sans-serif, system-ui, sans-serif;
  color: #cfd8e3; max-height: 70%; overflow: auto;
}
.ng-dt-head { display: flex; align-items: center; gap: 6px; margin-bottom: 2px; }
.ng-tag {
  font: 9px/1.4 ui-monospace, monospace; color: #ffd400;
  border: 1px solid #ffd40066; border-radius: 3px; padding: 0 3px;
}
.ng-close {
  margin-left: auto; background: none; border: none; color: #8b97a5;
  cursor: pointer; font-size: 14px; line-height: 1;
}
.ng-dt-row { white-space: nowrap; }
.ng-hash { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.ng-dim { color: #8b97a5; }
</style>
