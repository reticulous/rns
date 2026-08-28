/**
 * forceLayout — where the vertices go.
 *
 * THE ONE SEAM. NetGraph draws its own edges (per-interface colour, arcs for
 * parallel links, labels), so all it wants from a layout engine is a position
 * per vertex. That is this module's whole surface — `layout(n, links, opts)` in,
 * an `{x, y}` per vertex out — and swapping in a library means replacing this
 * file and nothing else.
 *
 * What is here is a plain velocity-Verlet spring embedder: repulsion between
 * every pair, a spring along every link, and a weak pull to the centre. It runs
 * to convergence in one synchronous call because the graph is a neighbourhood —
 * a handful of vertices, bounded by rnsd's own node table — and at that size a
 * few hundred ticks of an O(n²) sweep is under a millisecond. It is not a
 * general-purpose engine and does not try to be; it is the amount of layout a
 * neighbourhood needs, with no dependency behind it.
 */

export interface LayoutNode {
  /** Pinned vertices (this device) are placed and never moved. */
  fixed?: boolean
  x?: number
  y?: number
}

export interface LayoutLink {
  source: number
  target: number
}

export interface LayoutOpts {
  width: number
  height: number
  /** Natural link length, in the same units as width/height. */
  linkDistance?: number
  iterations?: number
}

export interface Point { x: number; y: number }

/** Deterministic scatter for the initial ring: a golden-angle spiral, so a
 *  fresh graph opens laid out rather than exploding out of one point, and the
 *  same graph opens the same way twice. No Math.random anywhere — a layout that
 *  jitters between redraws reads as data changing. */
function seed(i: number, n: number, w: number, h: number): Point {
  const a = i * 2.399963229728653          // golden angle, radians
  const r = (Math.min(w, h) / 2.6) * Math.sqrt((i + 0.5) / Math.max(n, 1))
  return { x: w / 2 + r * Math.cos(a), y: h / 2 + r * Math.sin(a) }
}

export function layout(nodes: LayoutNode[], links: LayoutLink[], opts: LayoutOpts): Point[] {
  const n = nodes.length
  const { width: w, height: h } = opts
  const dist = opts.linkDistance ?? Math.min(w, h) / 3.2
  const iters = opts.iterations ?? 320
  if (n === 0) return []

  const px = new Float64Array(n)
  const py = new Float64Array(n)
  const vx = new Float64Array(n)
  const vy = new Float64Array(n)
  for (let i = 0; i < n; i++) {
    const s = nodes[i].x !== undefined && nodes[i].y !== undefined
      ? { x: nodes[i].x!, y: nodes[i].y! }
      : seed(i, n, w, h)
    px[i] = s.x
    py[i] = s.y
  }

  const repel = dist * dist * 0.9
  /* Cooling: the step shrinks over the run, so early ticks untangle and late
   * ticks settle instead of oscillating around the answer. */
  for (let it = 0; it < iters; it++) {
    const cool = 1 - it / iters
    const fx = new Float64Array(n)
    const fy = new Float64Array(n)

    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        let dx = px[i] - px[j]
        let dy = py[i] - py[j]
        let d2 = dx * dx + dy * dy
        /* Two vertices exactly on top of each other have no direction to push
         * apart along; nudge deterministically by index rather than randomly. */
        if (d2 < 1e-6) { dx = (i - j) * 0.01 || 0.01; dy = 0.01; d2 = dx * dx + dy * dy }
        const f = repel / d2
        const d = Math.sqrt(d2)
        fx[i] += (dx / d) * f; fy[i] += (dy / d) * f
        fx[j] -= (dx / d) * f; fy[j] -= (dy / d) * f
      }
    }

    for (const l of links) {
      const a = l.source, b = l.target
      if (a === b || a < 0 || b < 0 || a >= n || b >= n) continue
      const dx = px[b] - px[a]
      const dy = py[b] - py[a]
      const d = Math.hypot(dx, dy) || 1e-3
      const f = (d - dist) * 0.08
      fx[a] += (dx / d) * f; fy[a] += (dy / d) * f
      fx[b] -= (dx / d) * f; fy[b] -= (dy / d) * f
    }

    for (let i = 0; i < n; i++) {
      fx[i] += (w / 2 - px[i]) * 0.012
      fy[i] += (h / 2 - py[i]) * 0.012
      if (nodes[i].fixed) { vx[i] = vy[i] = 0; continue }
      vx[i] = (vx[i] + fx[i]) * 0.82
      vy[i] = (vy[i] + fy[i]) * 0.82
      px[i] += vx[i] * cool
      py[i] += vy[i] * cool
    }
  }

  const out: Point[] = []
  for (let i = 0; i < n; i++) out.push({ x: px[i], y: py[i] })
  return out
}
