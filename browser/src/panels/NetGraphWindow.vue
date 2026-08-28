<!-- NetGraph — the community as a picture: this node in the middle, one circle
     per node around it, one line per LINK — including links between two other
     nodes, over a mesh this browser is not on.

     Two things a plain node-link drawing does not do, and the reasons for both:

     - Lines take the MEDIUM's colour, the same colour its status-line pill uses
       (rns.pill.<class>.color, read live), and the legend names it with the
       title that straddle publishes beside it. One vocabulary for "which
       medium" on every surface, and no palette and no table of media here.
     - Two nodes joined by more than one interface get one ARC PER LINK rather
       than one line. Parallel links are the interesting case on a mesh — a peer
       reachable over both LoRa and Bluetooth is a peer that stays reachable —
       and a single line would hide exactly that. Both ends of a link report it
       independently, and both arcs are drawn: asymmetric hearing is information.

     This file DRAWS. Every join behind the picture happened on the device, which
     is the only place that holds every node's own report of itself; lib/
     netGraph.ts just reads the rows out. Layout is lib/forceLayout.ts, the one
     seam a different engine would replace. -->
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
      <svg class="ng-svg" :viewBox="viewBox" preserveAspectRatio="xMidYMid meet">
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
            <!-- Outside the community: a box with the address in it, in the
                 colour of the medium that reaches it. It is not one of us and
                 must not read as one, and the address IS its name — there is no
                 caption to place, because there is nothing else to call it. -->
            <template v-if="n.kind === 'uplink'">
              <rect :x="n.x - n.boxW / 2" :y="n.y - n.boxH / 2"
                    :width="n.boxW" :height="n.boxH" rx="3"
                    class="uplink" :stroke="n.color" />
              <text :x="n.x" :y="n.y + 3.5" text-anchor="middle" class="uplink-t">{{ n.label }}</text>
            </template>
            <circle v-else :cx="n.x" :cy="n.y" :r="n.r"
                    :class="n.stub ? 'stub' : n.kind === 'routed' ? 'routed'
                                              : n.us ? 'us' : 'peer'" />
            <!-- A transport node forwards for others, which is the one property
                 of a node that changes what the graph MEANS: an edge through it
                 reaches further than itself. A second ring says so. -->
            <circle v-if="n.transport && n.kind !== 'uplink'"
                    :cx="n.x" :cy="n.y" :r="n.r + TRANSIT_GAP" class="transit" />
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
        No links yet. Nodes appear here as soon as this device builds its own
        record, or hears another node's.
      </div>

      <!-- Which colour is which medium. Built from the pills that exist, so it
           names exactly the media this node has switched on. -->
      <div class="ng-legend">
        <span v-for="c in classes" :key="c.cls" class="ng-key">
          <i :style="{ background: c.color }"></i>{{ c.title }}
        </span>
      </div>

      <div v-if="detail" class="ng-detail">
        <div class="ng-dt-head">
          <b>{{ detail.label }}</b>
          <span v-if="detail.transport" class="ng-tag">TRANSPORT</span>
          <button class="ng-close" @click="selected = -1">×</button>
        </div>
        <div v-for="a in detail.addresses" :key="a" class="ng-dt-row ng-hash ng-dim">{{ a }}</div>
        <div v-if="detail.age" class="ng-dt-row ng-dim">record {{ detail.age }}</div>
        <!-- What the node says about its own interfaces: the class, the
             registered name, and whatever that class considers its
             configuration — verbatim, because only that class's straddle knows
             what those fields mean. -->
        <div v-for="f in detail.ifs" :key="f.name" class="ng-dt-row">
          <i :style="{ background: f.color }"></i>{{ f.name }}
          <span v-if="f.detail" class="ng-dim">{{ f.detail }}</span>
        </div>
        <div v-for="l in detail.links" :key="l.key" class="ng-dt-row">
          <i :style="{ background: l.color }"></i>{{ l.iface }}
          <span class="ng-dim">{{ l.detail }}</span>
        </div>
      </div>
    </div>
  </FloatingWindow>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
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

/* The layout runs in these graph units and the browser scales the result, so a
 * resize never re-runs the simulation and the picture never jumps under the
 * hand doing the resizing. What DOES follow the window is the viewBox below,
 * which frames the drawing rather than the coordinate space. */
const W = 600
const H = 460

/* The panel's shape, watched so the frame can match it. A viewBox of a fixed
 * aspect inside a window of another letterboxes: the graph sits in a band with
 * empty margins the drawing could have used. */
const aspect = ref(W / H)
let ro: ResizeObserver | null = null
onMounted(() => {
  if (!boxRef.value || typeof ResizeObserver === 'undefined') return
  ro = new ResizeObserver(entries => {
    const r = entries[0]?.contentRect
    if (r && r.width > 0 && r.height > 0) aspect.value = r.width / r.height
  })
  ro.observe(boxRef.value)
})
onBeforeUnmount(() => { ro?.disconnect(); ro = null })

/* Recomputed whenever the mirrored store changes — the whole graph is a pure
 * function of the device's published tables, so there is nothing to keep in
 * step. */
const graph = computed(() => buildGraph())

/* A medium is named the way its own straddle names it (rns.pill.<class>.title),
 * for the same reason the colour comes from there: this file holds no table of
 * media. The class slug is the fallback — it is a program's word for the medium
 * and reads like one, but it is never wrong. */
const pillTitle = (cls: string) => String(device.get(`rns.pill.${cls}.title`) ?? '') || cls

const classes = computed(() => {
  const seen = new Map<string, string>()
  for (const e of graph.value.edges) if (!seen.has(e.cls)) seen.set(e.cls, e.color)
  return [...seen].map(([cls, color]) => ({ cls, color, title: pillTitle(cls) }))
    .sort((a, b) => a.title.localeCompare(b.title))
})

/* Text is measured by the glyph budget rather than the DOM — see CHAR_W below.
 * An uplink's address is written WHOLE, in a smaller face than the captions,
 * and the box grows to hold it: half a host:port names nothing, and the reader
 * cannot tell an elision from an address that really is that short. A long one
 * costs room in the picture, which the layout is told about through `clear` —
 * and the operator can shorten it by naming the interface something shorter. */
const UPLINK_CHAR_W = 5.4
function uplinkBox(label: string): { w: number; h: number } {
  return { w: label.length * UPLINK_CHAR_W + 10, h: 15 }
}

const positions = computed(() => {
  const g = graph.value
  /* NOTHING is pinned. A community graph has no natural centre, and forcing
   * this device into one drags the rest into whatever shape that leaves — a
   * node at the edge of a chain ends up in the middle of a triangle of its own
   * neighbours, which is a picture of the pin rather than of the network. Where
   * this device is is said by its colour instead. */
  return layout(
    /* Per vertex, because an uplink is a captioned BOX and needs the room its
     * text takes, not the room a circle takes. */
    g.nodes.map(n => n.kind === 'uplink'
      ? { clear: Math.hypot(uplinkBox(n.label).w, uplinkBox(n.label).h) / 2 + 4 }
      : {}),
    g.edges.map(e => ({ source: e.from, target: e.to })),
    /* nodeClear is the biggest thing drawn at an ordinary vertex — the 13 px
     * "us" circle plus its 4 px transport ring — with room for the stroke. An
     * edge closer than this to a vertex it does not end at reads as a
     * connection that is not in the data, so the layout treats it as a harder
     * fault than a crossing. Keep it in step with the radii in drawnNodes. */
    { width: W, height: H, nodeClear: 22 },
  )
})

const drawnNodes = computed(() => {
  const g = graph.value
  const p = positions.value
  return g.nodes.map((n, i) => {
    const box = n.kind === 'uplink' ? uplinkBox(n.label) : { w: 0, h: 0 }
    return {
      key: n.key,
      kind: n.kind,
      /* A stub stands for a peer whose own record has not arrived; it is drawn
       * so the degree of the node reporting it stays honest, and left
       * unlabelled because there is nothing yet to call it. An uplink carries
       * its name INSIDE its box, so it has no caption to place either. */
      label: n.stub ? '' : n.label,
      caption: n.kind === 'uplink' || n.stub ? '' : n.label,
      us: n.us,
      stub: n.stub,
      transport: n.transport,
      r: n.us ? 13 : n.stub ? 4 : 9,
      boxW: box.w,
      boxH: box.h,
      /* The medium that reaches it, which is the only thing we know about it
       * beyond its address. */
      color: g.edges.find(e => e.to === i || e.from === i)?.color ?? '#888888',
      x: p[i]?.x ?? W / 2,
      y: p[i]?.y ?? H / 2,
    }
  })
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
/* How far the transport ring stands off the circle. Here rather than in the
 * template alone, because the caption placer has to know how big a vertex
 * actually draws. */
const TRANSIT_GAP = 4

function ago(ts: number): string {
  if (!ts) return 'never'
  const s = Math.max(0, Math.floor(Date.now() / 1000) - ts)
  if (s < 120) return `${s}s ago`
  if (s < 7200) return `${Math.floor(s / 60)}m ago`
  return `${Math.floor(s / 3600)}h ago`
}

/* The freshness the REPORTER measured, against its own record's timestamp —
 * coarse on purpose, so a bucket never moves on its own and forces a node to
 * re-flood its record. */
const FRESH = ['under 5 min', 'under an hour', 'under 6 hours', 'over 6 hours']

const drawnEdges = computed(() => {
  const g = graph.value
  const p = positions.value

  /* Parallel links get arcs. The whole bundle between one PAIR is collected
   * first, so the curvatures can be spread symmetrically about the straight
   * line — done per edge in isolation they would all bend the same way. The key
   * is unordered, because a link reported from both ends is two edges between
   * the same two circles and they must not land on top of each other. */
  const bundles = new Map<string, number[]>()
  g.edges.forEach((e, i) => {
    const key = e.from < e.to ? `${e.from}-${e.to}` : `${e.to}-${e.from}`
    const b = bundles.get(key) ?? []
    b.push(i)
    bundles.set(key, b)
  })

  const out: { d: string; color: string; stale: boolean; tip: string; pts: Pt[] }[] = []
  for (const idxs of bundles.values()) {
    const first = g.edges[idxs[0]]
    const a = p[first.from] ?? { x: W / 2, y: H / 2 }
    const b = p[first.to] ?? { x: W / 2, y: H / 2 }
    const dx = b.x - a.x, dy = b.y - a.y
    const len = Math.hypot(dx, dy) || 1
    /* Unit normal: the direction an arc bows away from the straight line. */
    const nx = -dy / len, ny = dx / len
    const spread = Math.min(26, len / 5)
    idxs.forEach((ei, k) => {
      const e = g.edges[ei]
      /* Every arc in the bundle is drawn between the SAME two points, in the
       * bundle's own direction, so a link reported from the far end bows beside
       * its twin instead of over it. */
      const off = (k - (idxs.length - 1) / 2) * spread
      const mx = (a.x + b.x) / 2 + nx * off * 2
      const my = (a.y + b.y) / 2 + ny * off * 2
      const from = g.nodes[e.from], to = g.nodes[e.to]
      out.push({
        d: `M${a.x.toFixed(1)},${a.y.toFixed(1)} Q${mx.toFixed(1)},${my.toFixed(1)} ${b.x.toFixed(1)},${b.y.toFixed(1)}`,
        color: e.color,
        /* Dashed when the link has gone quiet, or when the record that reports
         * it is itself getting old — "was here and has gone quiet" being a
         * different thing from "not here". */
        stale: e.inferred || (e.fresh !== null && e.fresh >= 2) || from.stale,
        /* Only what somebody actually reported. A link nobody dated says
         * nothing about when it was heard, and a link whose far end cannot
         * report says nothing about being one-ended. */
        tip: `${from.label} ${e.oneWay ? '→' : '↔'} ${to.label}  ·  ${e.ifaces.join(' / ')}`
           + (e.fresh !== null ? `  ·  heard ${FRESH[e.fresh] ?? '?'}` : '')
           + (e.oneWay ? '  ·  one end reporting' : '')
           + (e.inferred ? '  ·  inferred from routing, not reported' : ''),
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
    /* A stub has no caption to place — there is nothing to call it yet. */
    if (!n.caption) return { key: n.key, text: '', anchor: 'middle', tx: n.x, ty: n.y,
                             boxed: false, bx: 0, by: 0, bw: 0, bh: 0 }
    const w = Math.max(n.caption.length * CHAR_W, 8)
    /* Offsets are from the OUTERMOST thing drawn at the vertex, which for a
     * transport node is its second ring rather than its circle — a caption set
     * off the circle alone reads as touching the ring. */
    const r = n.r + (n.transport ? TRANSIT_GAP + 1 : 0)
    /* Below first — it is where a caption belongs, and the ring only exists
     * because that spot is often taken. Then above, then the sides, then the
     * diagonals: each step further from the convention, and taken only when
     * everything nearer it is blocked. */
    const cands: { tx: number; ty: number; anchor: string; x: number }[] = [
      { tx: n.x, ty: n.y + r + 12, anchor: 'middle', x: n.x - w / 2 },
      { tx: n.x, ty: n.y - r - 5,  anchor: 'middle', x: n.x - w / 2 },
      { tx: n.x + r + 6, ty: n.y + 4, anchor: 'start', x: n.x + r + 6 },
      { tx: n.x - r - 6, ty: n.y + 4, anchor: 'end',   x: n.x - r - 6 - w },
      { tx: n.x + r + 4, ty: n.y + r + 12, anchor: 'start', x: n.x + r + 4 },
      { tx: n.x - r - 4, ty: n.y + r + 12, anchor: 'end',   x: n.x - r - 4 - w },
      { tx: n.x + r + 4, ty: n.y - r - 5,  anchor: 'start', x: n.x + r + 4 },
      { tx: n.x - r - 4, ty: n.y - r - 5,  anchor: 'end',   x: n.x - r - 4 - w },
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
        /* An uplink is a box, not a circle, and a caption over its address is
         * as unreadable as one over a line. */
        const or = o.r + (o.transport ? TRANSIT_GAP + 1 : 0)
        const ow = o.kind === 'uplink' ? o.boxW : or * 2
        const oh = o.kind === 'uplink' ? o.boxH : or * 2
        if (rectsOverlap(r, { x: o.x - ow / 2, y: o.y - oh / 2, w: ow, h: oh })) { hit = true; break }
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

/* ── the frame ──
 *
 * The viewBox is the drawing's own bounds — circles, boxes and the captions
 * already placed — grown on one axis to the panel's shape, so the picture fills
 * the window and keeps filling it as the window changes. It frames rather than
 * scales anything: the layout, and every size in it, stays in graph units.
 *
 * Bounded magnification, because a two-vertex community has bounds a few tens
 * of units across and a frame that tight would blow the captions up to
 * headlines. Below FRAME_MIN the frame stops shrinking and the drawing sits in
 * the middle of it at a sane size. */
const FRAME_MIN = 320
const FRAME_PAD = 10

const viewBox = computed(() => {
  let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity
  const grow = (ax: number, ay: number, bx: number, by: number) => {
    if (ax < x0) x0 = ax
    if (ay < y0) y0 = ay
    if (bx > x1) x1 = bx
    if (by > y1) y1 = by
  }
  for (const n of drawnNodes.value) {
    const hw = n.kind === 'uplink' ? n.boxW / 2 : n.r + (n.transport ? TRANSIT_GAP + 1 : 0)
    const hh = n.kind === 'uplink' ? n.boxH / 2 : n.r + (n.transport ? TRANSIT_GAP + 1 : 0)
    grow(n.x - hw, n.y - hh, n.x + hw, n.y + hh)
  }
  for (const l of labels.value) {
    if (!l.text) continue
    grow(l.bx, l.by, l.bx + l.bw, l.by + l.bh)
  }
  if (!Number.isFinite(x0)) return `0 0 ${W} ${H}`

  x0 -= FRAME_PAD; y0 -= FRAME_PAD; x1 += FRAME_PAD; y1 += FRAME_PAD
  let w = Math.max(x1 - x0, 1), h = Math.max(y1 - y0, 1)
  if (w < FRAME_MIN) { x0 -= (FRAME_MIN - w) / 2; w = FRAME_MIN }
  if (h < FRAME_MIN) { y0 -= (FRAME_MIN - h) / 2; h = FRAME_MIN }
  /* Grow the axis that is short for the panel's shape — never crop the other,
   * which would put a vertex outside the picture. */
  const a = aspect.value > 0 ? aspect.value : W / H
  if (w / h < a) { const nw = h * a; x0 -= (nw - w) / 2; w = nw }
  else           { const nh = w / a; y0 -= (nh - h) / 2; h = nh }
  return `${x0.toFixed(1)} ${y0.toFixed(1)} ${w.toFixed(1)} ${h.toFixed(1)}`
})

const pillColor = (cls: string) => `#${String(device.get(`rns.pill.${cls}.color`) ?? '') || '888888'}`

const detail = computed(() => {
  const g = graph.value
  const i = selected.value
  if (i < 0 || i >= g.nodes.length) return null
  const n = g.nodes[i]
  return {
    label: n.stub ? `unresolved ${n.label}` : n.label,
    transport: n.transport,
    addresses: n.addresses,
    /* How old the node's own report of itself is — the one number that says
     * whether anything else in this panel can still be believed. */
    age: n.ts ? ago(n.ts) : '',
    ifs: n.ifs.map(f => ({
      name: f.name,
      detail: f.detail,
      color: pillColor(f.cls),
    })),
    /* Every link this node is an end of, named by the far end. Both ends of a
     * merged link list it, which is right — it is a link of each of them. */
    links: g.edges
      .filter(e => e.from === i || e.to === i)
      .map((e, k) => {
        const far = e.from === i ? e.to : e.from
        return {
          key: `${e.cls}:${far}:${k}`,
          iface: e.ifaces[e.from === i ? 0 : e.ifaces.length - 1],
          color: e.color,
          detail: (g.nodes[far]?.label ?? '?')
                + (e.fresh !== null ? ` · heard ${FRESH[e.fresh] ?? '?'}` : '')
                + (e.oneWay ? ' · one end reporting' : ''),
        }
      }),
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
/* This device. Nothing about the layout says which circle is ours — the graph
 * is the community's and has no centre — so the colour is what says it. */
.ng-nodes circle.us   { fill: #b3202a; stroke: #ff6b6b; stroke-width: 2.5; }
/* A far end nobody has claimed yet: present, so the degree is honest, and
 * plainly not a node anyone can tell you about. */
.ng-nodes circle.stub { fill: none; stroke: #56636f; stroke-width: 1.5; }
/* Seen, not heard from: a node routing knows about that has never sent a record
   of its own. A dashed outline says the circle is real and its account of
   itself is missing. */
.ng-nodes circle.routed {
  fill: #1b2836; stroke: #7f8b99; stroke-width: 1.5; stroke-dasharray: 3 3;
}
/* Outside the community: a box rather than a circle, outlined in the colour of
 * the medium that reaches it. The shape says "not one of us"; the colour says
 * "over what". */
.ng-nodes rect.uplink { fill: #131a22; stroke-width: 1.5; }
/* Smaller than a caption: it is an address rather than a name, it is written in
 * full however long it runs, and it sits inside its own box where nothing else
 * competes with it. Keep UPLINK_CHAR_W in step with this size. */
.ng-nodes text.uplink-t {
  fill: #cfd8e3; pointer-events: none;
  font: 9.5px/1 ui-monospace, SFMono-Regular, Menlo, monospace;
}
.ng-nodes circle.transit { fill: none; stroke: #7f8b99; stroke-width: 1; opacity: 0.55; }
.ng-nodes g.sel circle.peer,
.ng-nodes g.sel circle.stub,
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
  display: flex; flex-wrap: wrap; gap: 24px;
  font: 12px/1.6 ui-monospace, SFMono-Regular, Menlo, monospace; color: #8b97a5;
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
