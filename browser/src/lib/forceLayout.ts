/**
 * forceLayout — where the vertices go.
 *
 * THE ONE SEAM. NetGraph draws its own edges (per-interface colour, arcs for
 * parallel links, labels), so all it wants from a layout engine is a position
 * per vertex. That is this module's whole surface — `layout(n, links, opts)` in,
 * an `{x, y}` per vertex out — and swapping in a library means replacing this
 * file and nothing else.
 *
 * Two stages, and the second is the whole reason this is more than a spring
 * embedder:
 *
 *  1. A velocity-Verlet spring embedder — repulsion between every pair, a spring
 *     along every link, a weak pull to the centre. It settles the SHAPE.
 *  2. A local search that relocates one vertex at a time, ranked strictly:
 *       a. no edge may pass through a vertex it does not end at,
 *       b. then fewest crossings,
 *       c. then the widest fan of edges at any vertex,
 *       d. then the evenest edge lengths.
 *
 * Stage 2 exists because none of a-c is a force. Whether two edges cross, or an
 * edge runs through a circle, or a corner is pinched into a sliver, are all
 * properties of the whole drawing rather than of a pair of vertices, so a spring
 * embedder cannot see them and cannot be taught to. Three mutually-connected
 * nodes plus one outlier is the case that shows it: the outlier settles on
 * whichever side its starting angle chose, and on the wrong side its one edge
 * cuts through links it need not touch. The energy is not wrong there; the
 * picture just reads as a knot that is not in the data.
 *
 * An angular-resolution FORCE — each vertex pushing its neighbours apart
 * tangentially towards an even fan — was tried and removed. It measured worse
 * than the local search at every strength: gentle, it barely moved the worst
 * angle; strong enough to matter, it fought the springs into new crossings and
 * drove the worst angle to zero. The search reaches ~55° where the force
 * reached ~9°, and costs no crossings to do it, because it can refuse a move
 * that breaks something a force can only shove at.
 *
 * It runs to convergence in one synchronous call because the graph is a
 * community — tens of vertices, bounded by the record store — and at that size a
 * few hundred ticks of an O(n²) sweep is well under a millisecond. Deterministic
 * throughout: no Math.random anywhere, and the retries vary the seed by index
 * rather than by chance, so the same graph opens the same way twice. A layout
 * that jitters between redraws reads as data changing.
 */

export interface LayoutNode {
  /** Pinned vertices are placed and never moved — by the springs or by the
   *  untangler. */
  fixed?: boolean
  x?: number
  y?: number
  /** How much room this vertex needs, overriding `LayoutOpts.nodeClear`. A
   *  vertex drawn as a captioned box needs far more than one drawn as a small
   *  circle, and only the drawer knows which is which. */
  clear?: number
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
  /** How close an edge may pass to a vertex it does not touch, in the same
   *  units. The drawer knows its own circle radii and captions; this module
   *  only knows points, so the clearance comes from the caller. */
  nodeClear?: number
}

export interface Point { x: number; y: number }

/** Deterministic scatter for the initial ring: a golden-angle spiral, so a
 *  fresh graph opens laid out rather than exploding out of one point, and the
 *  same graph opens the same way twice. `phase` rotates the whole spiral — that
 *  is how a retry starts somewhere genuinely different without a random number
 *  anywhere in the module. */
function seed(i: number, n: number, w: number, h: number, phase: number): Point {
  const a = i * 2.399963229728653 + phase * 1.7          // golden angle, radians
  const r = (Math.min(w, h) / 2.6) * Math.sqrt((i + 0.5) / Math.max(n, 1))
  return { x: w / 2 + r * Math.cos(a), y: h / 2 + r * Math.sin(a) }
}

/* ── crossings ──
 *
 * Two edges cross when their segments properly intersect. Edges that share an
 * endpoint are never a crossing — they meet there by construction — and neither
 * are parallel or collinear ones, because a crossing count is about knots in
 * the drawing, not about lines that touch. */

function segsCross(ax: number, ay: number, bx: number, by: number,
                   cx: number, cy: number, dx: number, dy: number): boolean {
  const d = (bx - ax) * (dy - cy) - (by - ay) * (dx - cx)
  if (Math.abs(d) < 1e-9) return false                   // parallel; touching is not a hit
  const t = ((cx - ax) * (dy - cy) - (cy - ay) * (dx - cx)) / d
  const u = ((cx - ax) * (by - ay) - (cy - ay) * (bx - ax)) / d
  return t > 0 && t < 1 && u > 0 && u < 1
}

function pairCrosses(e: number, f: number, px: Float64Array, py: Float64Array,
                     links: LayoutLink[]): boolean {
  const l1 = links[e], l2 = links[f]
  if (l1.source === l2.source || l1.source === l2.target ||
      l1.target === l2.source || l1.target === l2.target) return false
  return segsCross(px[l1.source], py[l1.source], px[l1.target], py[l1.target],
                   px[l2.source], py[l2.source], px[l2.target], py[l2.target])
}

function totalCrossings(px: Float64Array, py: Float64Array, links: LayoutLink[]): number {
  let n = 0
  for (let i = 0; i < links.length; i++)
    for (let j = i + 1; j < links.length; j++)
      if (pairCrosses(i, j, px, py, links)) n++
  return n
}

function totalLength(px: Float64Array, py: Float64Array, links: LayoutLink[]): number {
  let s = 0
  for (const l of links) s += Math.hypot(px[l.target] - px[l.source], py[l.target] - py[l.source])
  return s
}

function linkLen(l: LayoutLink, px: Float64Array, py: Float64Array): number {
  return Math.hypot(px[l.target] - px[l.source], py[l.target] - py[l.source])
}

/* ── even lengths ──
 *
 * Two drawings can be equally free of faults and equally open at their corners
 * and still read differently: the one whose lines are all about the same length
 * looks like a network, and the one with a 200 px line beside a 40 px one looks
 * like it is saying something about distance. It is NOT saying anything about
 * distance — nothing in a record is a distance — so evenness is the honest
 * default, and it ranks below every fault and above nothing but total length.
 *
 * Measured as the mean squared deviation from the mean length, which is scale
 * free in the sense that matters: it does not care what the springs' rest
 * length was, only whether the lines agree with each other. */
function lengthSpread(px: Float64Array, py: Float64Array, links: LayoutLink[]): number {
  if (links.length < 2) return 0
  let sum = 0
  for (const l of links) sum += linkLen(l, px, py)
  const mean = sum / links.length
  let v = 0
  for (const l of links) { const d = linkLen(l, px, py) - mean; v += d * d }
  return v / links.length
}

/** Pull every edge toward the drawing's mean length, half the correction at
 *  each end, a few dozen sweeps. A distance-constraint relaxation rather than a
 *  force: it moves along the edge and nothing else, so it evens the lengths
 *  without rotating anything — the shape the embedder settled on survives, and
 *  a chain comes out with equal links instead of one that is an eighth of its
 *  neighbour for no reason in the data. The springs alone cannot do this: their
 *  rest length is one number for the whole drawing, and repulsion from
 *  everything else bends it by however much the local crowd demands. */
function relaxLengths(px: Float64Array, py: Float64Array, nodes: LayoutNode[],
                      links: LayoutLink[], w: number, h: number,
                      clear: Float64Array, iters: number): void {
  const n = nodes.length
  if (links.length < 2) return
  for (let it = 0; it < iters; it++) {
    let mean = 0
    for (const l of links) mean += linkLen(l, px, py)
    mean /= links.length
    for (const l of links) {
      const a = l.source, b = l.target
      if (a === b || a < 0 || b < 0 || a >= n || b >= n) continue
      const dx = px[b] - px[a], dy = py[b] - py[a]
      const d = Math.hypot(dx, dy) || 1e-3
      /* Half the error to each end, damped: an edge shares both its vertices
       * with other edges pulling the other way, and taking the whole
       * correction every sweep makes the pass ring instead of settle. */
      const k = ((d - mean) / d) * 0.25
      const cx = dx * k, cy = dy * k
      if (!nodes[a].fixed) { px[a] += cx; py[a] += cy }
      if (!nodes[b].fixed) { px[b] -= cx; py[b] -= cy }
    }
    for (let i = 0; i < n; i++) {
      if (nodes[i].fixed) continue
      const m = clear[i] + 2
      px[i] = Math.min(Math.max(px[i], m), w - m)
      py[i] = Math.min(Math.max(py[i], m), h - m)
    }
  }
}

/* ── overlaps: an edge passing through a vertex it does not touch ──
 *
 * A HARDER fault than a crossing, and ranked above it everywhere below. Two
 * edges crossing is a drawing that could be clearer. An edge running through a
 * circle is a drawing that is WRONG: it reads as a connection that is not in
 * the data, and there is no angle from which the reader can tell otherwise. A
 * flattened triangle is the usual way to get one — and it is exactly the shape
 * a crossings-only search will reach for, since collapsing a triangle onto a
 * line is a cheap way to stop its edges crossing anything. */

function pointSegDist(x: number, y: number,
                      ax: number, ay: number, bx: number, by: number): number {
  const dx = bx - ax, dy = by - ay
  const len2 = dx * dx + dy * dy
  if (len2 < 1e-9) return Math.hypot(x - ax, y - ay)
  let t = ((x - ax) * dx + (y - ay) * dy) / len2
  t = t < 0 ? 0 : t > 1 ? 1 : t
  return Math.hypot(x - (ax + t * dx), y - (ay + t * dy))
}

function edgeHitsVertex(e: number, v: number, px: Float64Array, py: Float64Array,
                        links: LayoutLink[], clear: Float64Array): boolean {
  const l = links[e]
  if (l.source === v || l.target === v) return false        // it ends there, by construction
  return pointSegDist(px[v], py[v], px[l.source], py[l.source],
                      px[l.target], py[l.target]) < clear[v]
}

function totalOverlaps(px: Float64Array, py: Float64Array, links: LayoutLink[],
                       n: number, clear: Float64Array): number {
  let c = 0
  for (let e = 0; e < links.length; e++)
    for (let v = 0; v < n; v++)
      if (edgeHitsVertex(e, v, px, py, links, clear)) c++
  return c
}

/** The narrowest fan anywhere in the drawing, in radians — how pinched its
 *  worst corner is. Used to choose between arrangements that are equally free
 *  of faults. */
function worstAngle(px: Float64Array, py: Float64Array, links: LayoutLink[], n: number): number {
  const adj: number[][] = []
  for (let i = 0; i < n; i++) adj.push([])
  for (const l of links) {
    const a = l.source, b = l.target
    if (a === b || a < 0 || b < 0 || a >= n || b >= n) continue
    if (!adj[a].includes(b)) adj[a].push(b)
    if (!adj[b].includes(a)) adj[b].push(a)
  }
  let m = Math.PI * 2
  for (let v = 0; v < n; v++) m = Math.min(m, minAngleAt(v, px, py, adj))
  return m
}

/* ── the untangler ──
 *
 * Moving one vertex can only change crossings on the edges that touch it, so
 * every candidate position is scored against those edges alone. That is what
 * makes a local search affordable here: O(degree × |E|) per candidate instead of
 * O(|E|²), and a vertex whose own edges cross nothing is skipped outright —
 * moving it could not improve anything it is part of. */

function crossingsAt(v: number, px: Float64Array, py: Float64Array,
                     links: LayoutLink[], inc: number[][], isInc: Uint8Array[]): number {
  let n = 0
  for (const e of inc[v])
    for (let f = 0; f < links.length; f++) {
      if (isInc[v][f]) continue        // shares v — meets there, never a crossing
      if (pairCrosses(e, f, px, py, links)) n++
    }
  return n
}

/** Every overlap that moving `v` can change: `v` sitting on somebody else's
 *  edge, and `v`'s own edges running through somebody else. Nothing outside
 *  those two sets moves when `v` does, so this is an exact incremental score. */
function overlapsAt(v: number, px: Float64Array, py: Float64Array, links: LayoutLink[],
                    inc: number[][], isInc: Uint8Array[], n: number, clear: Float64Array): number {
  let c = 0
  for (let e = 0; e < links.length; e++)
    if (!isInc[v][e] && edgeHitsVertex(e, v, px, py, links, clear)) c++
  for (const e of inc[v])
    for (let w = 0; w < n; w++)
      if (w !== v && edgeHitsVertex(e, w, px, py, links, clear)) c++
  return c
}

/** How far this vertex's own edges sit from the length the drawing has settled
 *  on, squared and summed. The local form of lengthSpread: everything outside
 *  `v`'s incident edges is unchanged by moving `v`, so this is an exact
 *  incremental score against a mean held fixed for the sweep. */
function evenAt(v: number, px: Float64Array, py: Float64Array,
                links: LayoutLink[], inc: number[][], mean: number): number {
  let s = 0
  for (const e of inc[v]) {
    const d = linkLen(links[e], px, py) - mean
    s += d * d
  }
  return s
}

/** The smallest angle between two edges meeting at `v`, in radians. A vertex
 *  with one edge has nothing to pinch, so it never constrains anything. */
function minAngleAt(v: number, px: Float64Array, py: Float64Array, adj: number[][]): number {
  const nb = adj[v]
  if (nb.length < 2) return Math.PI * 2
  const as: number[] = []
  for (const u of nb) {
    const dx = px[u] - px[v], dy = py[u] - py[v]
    if (Math.hypot(dx, dy) < 1e-6) continue
    as.push(Math.atan2(dy, dx))
  }
  if (as.length < 2) return Math.PI * 2
  as.sort((a, b) => a - b)
  let m = as[0] + Math.PI * 2 - as[as.length - 1]
  for (let i = 0; i + 1 < as.length; i++) m = Math.min(m, as[i + 1] - as[i])
  return m
}

/** Every angle moving `v` can pinch: the fan at `v`, and the fan at each of its
 *  neighbours — swinging `v` around rotates one spoke of each of those too. */
function localAngle(v: number, px: Float64Array, py: Float64Array, adj: number[][]): number {
  let m = minAngleAt(v, px, py, adj)
  for (const u of adj[v]) m = Math.min(m, minAngleAt(u, px, py, adj))
  return m
}

const RING = 16          // candidate directions around the neighbour centroid
const SWEEPS = 4         // passes over the vertices; a move can free up its neighbours
/* Worth about a degree before it counts as an improvement — without a floor the
 * search would keep taking microscopic gains and never settle. */
const ANGLE_EPS = 0.02

function untangle(px: Float64Array, py: Float64Array, nodes: LayoutNode[],
                  links: LayoutLink[], w: number, h: number, dist: number,
                  clear: Float64Array, spreadAngles: boolean): void {
  const n = nodes.length
  const inc: number[][] = []
  const isInc: Uint8Array[] = []
  const adj: number[][] = []
  for (let i = 0; i < n; i++) { inc.push([]); isInc.push(new Uint8Array(links.length)); adj.push([]) }
  links.forEach((l, i) => {
    if (l.source === l.target) return
    if (l.source < 0 || l.target < 0 || l.source >= n || l.target >= n) return
    inc[l.source].push(i); isInc[l.source][i] = 1
    inc[l.target].push(i); isInc[l.target][i] = 1
    if (!adj[l.source].includes(l.target)) adj[l.source].push(l.target)
    if (!adj[l.target].includes(l.source)) adj[l.target].push(l.source)
  })

  const margin = 24
  const minSep = dist * 0.35
  /* Worth 2% of a natural link's length squared before an evenness gain counts
   * — the same job ANGLE_EPS does for the fans, and for the same reason. */
  const evenEps = dist * dist * 0.02

  for (let sweep = 0; sweep < SWEEPS; sweep++) {
    let moved = false
    /* The length the drawing has settled on, held fixed across the sweep so
     * every vertex in it is judged against one target rather than against a
     * mean that moves under the vertex before it. */
    let mean = 0
    for (const l of links) mean += linkLen(l, px, py)
    mean = links.length ? mean / links.length : dist

    for (let v = 0; v < n; v++) {
      if (nodes[v].fixed || inc[v].length === 0) continue
      const baseOver  = overlapsAt(v, px, py, links, inc, isInc, n, clear)
      const baseCross = crossingsAt(v, px, py, links, inc, isInc)
      /* Nothing this vertex is part of is knotted or run through. On a graph
       * too big for the full search, that is where it ends — the candidate
       * sweep is what costs, and it is spent on faults first. On a small one a
       * clean vertex may still be sitting in a pinched fan worth opening, or
       * on the one edge that is twice everybody else's length. */
      if (baseOver === 0 && baseCross === 0 && !spreadAngles) continue
      const baseAngle = spreadAngles ? localAngle(v, px, py, adj) : 0
      const baseEven  = evenAt(v, px, py, links, inc, mean)

      /* Candidates ring the CENTROID OF ITS NEIGHBOURS, which for the outlier
       * case is simply "somewhere else around the node it hangs off". */
      let cx = 0, cy = 0
      const nb: number[] = []
      for (const e of inc[v]) {
        const o = links[e].source === v ? links[e].target : links[e].source
        nb.push(o); cx += px[o]; cy += py[o]
      }
      cx /= nb.length; cy /= nb.length

      const r0 = Math.hypot(px[v] - cx, py[v] - cy)
      const radii = [Math.max(r0, dist * 0.6), dist]
      const ox = px[v], oy = py[v]
      let bestX = ox, bestY = oy
      let bestOver = baseOver
      let bestCross = baseCross
      let bestAngle = baseAngle
      let bestEven = baseEven

      for (const rad of radii) {
        for (let k = 0; k < RING; k++) {
          const a = (k / RING) * Math.PI * 2
          const x = cx + rad * Math.cos(a)
          const y = cy + rad * Math.sin(a)
          if (x < margin || y < margin || x > w - margin || y > h - margin) continue
          /* Never land on somebody: two circles on the same spot is a worse
           * drawing than a crossing. */
          let clash = false
          for (let o = 0; o < n && !clash; o++)
            if (o !== v && Math.hypot(px[o] - x, py[o] - y) < Math.max(minSep, clear[o] + clear[v]))
              clash = true
          if (clash) continue

          px[v] = x; py[v] = y
          const o = overlapsAt(v, px, py, links, inc, isInc, n, clear)
          const c = crossingsAt(v, px, py, links, inc, isInc)
          const ang = spreadAngles ? localAngle(v, px, py, adj) : 0
          const even = evenAt(v, px, py, links, inc, mean)
          px[v] = ox; py[v] = oy
          /* Strictly ranked, worst fault first: never run an edge through a
           * circle to save a crossing, and never take a crossing to open an
           * angle. Only below both does the widest fan win, and below that the
           * edges that agree best with every other edge's length — which for
           * an outlier is what keeps it a neighbour's distance away rather
           * than out at the margin. */
          if (o < bestOver ||
              (o === bestOver && c < bestCross) ||
              (o === bestOver && c === bestCross && ang > bestAngle + ANGLE_EPS) ||
              (o === bestOver && c === bestCross && ang > bestAngle - ANGLE_EPS
                              && even < bestEven - 1e-6)) {
            bestOver = o; bestCross = c; bestAngle = ang; bestEven = even; bestX = x; bestY = y
          }
        }
      }

      /* Only a genuine improvement moves a vertex. Evenness counts as one —
       * unlike shortening, which pulls against the springs, it pulls the same
       * way they do and only settles what they left uneven — but it counts
       * last, and never at the cost of a fan the search just opened. */
      if (bestOver < baseOver ||
          (bestOver === baseOver && bestCross < baseCross) ||
          (bestOver === baseOver && bestCross === baseCross
                                 && bestAngle > baseAngle + ANGLE_EPS) ||
          (bestOver === baseOver && bestCross === baseCross
                                 && bestAngle > baseAngle - ANGLE_EPS
                                 && bestEven < baseEven - evenEps)) {
        px[v] = bestX; py[v] = bestY; moved = true
      }
    }
    if (!moved) break
  }
}

/* ── the embedder ── */

function embed(nodes: LayoutNode[], links: LayoutLink[],
               w: number, h: number, dist: number, iters: number,
               phase: number, clear: Float64Array): { px: Float64Array; py: Float64Array } {
  const n = nodes.length
  const px = new Float64Array(n)
  const py = new Float64Array(n)
  const vx = new Float64Array(n)
  const vy = new Float64Array(n)
  for (let i = 0; i < n; i++) {
    const s = nodes[i].x !== undefined && nodes[i].y !== undefined
      ? { x: nodes[i].x!, y: nodes[i].y! }
      : seed(i, n, w, h, phase)
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
      /* Inside the canvas, by this vertex's OWN size: the centring pull is a
       * force like any other and loses to a crowd, and a vertex that ends up
       * past the edge is not drawn — a captioned box is wide enough that its
       * centre can sit comfortably inside while half the box is gone. */
      const m = clear[i] + 2
      px[i] = Math.min(Math.max(px[i], m), w - m)
      py[i] = Math.min(Math.max(py[i], m), h - m)
    }
  }
  return { px, py }
}

/** Retries. The untangler is a LOCAL search — it fixes a vertex on the wrong
 *  side of something, not a shape that came out wrong as a whole — so where
 *  crossings survive it, the cheapest remaining move is to start the springs
 *  from a different arrangement and try again. Bounded, and only worth it while
 *  the graph is small enough that a crossing-free drawing plausibly exists at
 *  all; past that the retries would just be spending time to confirm it does
 *  not. */
const RETRY_MAX = 4
const RETRY_VERTS = 24
const RETRY_LINKS = 48

export function layout(nodes: LayoutNode[], links: LayoutLink[], opts: LayoutOpts): Point[] {
  const n = nodes.length
  const { width: w, height: h } = opts
  const dist = opts.linkDistance ?? Math.min(w, h) / 3.2
  const iters = opts.iterations ?? 320
  if (n === 0) return []

  /* Per vertex, because a captioned box and a small circle need very different
   * room and only the drawer knows which is which. */
  const defClear = opts.nodeClear ?? 22
  const clear = new Float64Array(n)
  for (let i = 0; i < n; i++) clear[i] = nodes[i].clear ?? defClear

  /* Spreading the angles is a search over every vertex rather than only the
   * faulty ones, so it is gated to the sizes where it is affordable — and where
   * a fan can actually be opened. Past that the graph is dense enough that its
   * angles are decided by how many edges meet, not by where anything sits. */
  const small = n <= RETRY_VERTS && links.length <= RETRY_LINKS
  const tries = small ? RETRY_MAX : 1
  let best: { px: Float64Array; py: Float64Array
              over: number; cross: number; angle: number
              spread: number; len: number } | null = null

  for (let t = 0; t < tries; t++) {
    const { px, py } = embed(nodes, links, w, h, dist, iters, t, clear)
    /* Even the lengths before the untangler runs, so what it judges is the
     * drawing the reader will get; then again after, because relocating a
     * vertex is exactly the move that leaves one edge long and one short. The
     * second pass is guarded: evenness is the LAST criterion, and it may not
     * buy itself a crossing or an edge through a circle. */
    relaxLengths(px, py, nodes, links, w, h, clear, 60)
    untangle(px, py, nodes, links, w, h, dist, clear, small)
    const keepX = Float64Array.from(px), keepY = Float64Array.from(py)
    const faultsOver = totalOverlaps(px, py, links, n, clear)
    const faultsCross = totalCrossings(px, py, links)
    relaxLengths(px, py, nodes, links, w, h, clear, 30)
    if (totalOverlaps(px, py, links, n, clear) > faultsOver ||
        totalCrossings(px, py, links) > faultsCross) { px.set(keepX); py.set(keepY) }
    const over = totalOverlaps(px, py, links, n, clear)
    const cross = totalCrossings(px, py, links)
    const angle = worstAngle(px, py, links, n)
    const spread = lengthSpread(px, py, links)
    const len = totalLength(px, py, links)
    /* Same ranking the untangler uses, over whole drawings rather than one
     * vertex — with total length kept as the last word, so two equally even
     * arrangements settle on the compact one. */
    if (!best || over < best.over ||
        (over === best.over && cross < best.cross) ||
        (over === best.over && cross === best.cross && angle > best.angle + ANGLE_EPS) ||
        (over === best.over && cross === best.cross && angle > best.angle - ANGLE_EPS
                            && spread < best.spread - 1e-6) ||
        (over === best.over && cross === best.cross && angle > best.angle - ANGLE_EPS
                            && spread < best.spread + 1e-6 && len < best.len - 1e-6))
      best = { px, py, over, cross, angle, spread, len }
    /* No edge through a circle, no crossing, and no pinched fan left: as good
     * as this module gets, and another start could only tie it. */
    if (over === 0 && cross === 0 && angle > 0.5) break
  }

  const out: Point[] = []
  for (let i = 0; i < n; i++) out.push({ x: best!.px[i], y: best!.py[i] })
  return out
}
