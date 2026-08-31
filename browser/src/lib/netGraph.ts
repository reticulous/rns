/**
 * netGraph — the community's graph, as the device resolved it.
 *
 * The device joins four classes of evidence into one row schema and publishes
 * the result as `netgraph.*` rows. This module reads those rows and nothing
 * else: vertices from `netgraph.nodes.*`, edges from `netgraph.links.*`,
 * per-node interfaces from `netgraph.ifs.*`. There is no join here, and no
 * per-medium knowledge — a medium added tomorrow appears the moment the device
 * files it, because every class has one shape.
 *
 * LINE STYLE IS A PURE FUNCTION OF `ev`, AND NOTHING ELSE STYLES A LINE. There
 * is no style for "old": evidence that has expired is removed by the device
 * rather than dimmed here, so anything drawn is current by construction.
 *
 * WHAT IS DRAWN IS NOT ONLY THIS NODE'S NEIGHBOURHOOD. A `route2` edge runs
 * between two other nodes, and a crawled edge is a third party's report about
 * itself, pulled over a mesh this browser is not on.
 *
 * An edge whose far end names a destination nothing claims is kept and marked:
 * `b` is -1 and `bref` is the four-byte prefix that went unmatched. It gets a
 * small unlabelled stub vertex, so a node's degree stays honest while whatever
 * would name the other end is still missing.
 */
import { useDeviceStore } from 'spangap-browser/stores/device'

/** The four evidence classes. The device publishes exactly these words. */
export type Evidence = 'route1' | 'route2' | 'heard' | 'record'

export interface GraphIface {
  cls: string
  name: string
  /** The class's own configuration fields, pipe-separated, verbatim. Opaque to
   *  everyone but that class — rendered as it arrived. */
  detail: string
}

export interface GraphEdge {
  /** Indices into `nodes`. `from` is the REPORTING side: the node whose
   *  evidence this is. For `route2` that is the via-node, not us. */
  from: number
  to: number
  /** The reporting sides' own interface names — one entry when only one end
   *  filed it, two when both did. */
  ifaces: string[]
  cls: string
  color: string
  /** Which class of evidence this is, and therefore how it is drawn. */
  ev: Evidence
  /** Either endpoint is a transport node, as the other described it. */
  transport: boolean
  /** Seconds since this evidence was last refreshed, or `null` where the
   *  evidence carries no date — a route's presence in the table is the whole of
   *  its currency. Not a zero: "just now" is a claim, and we would be making it
   *  up. */
  ageS: number | null
  /** Whose statement this is: the crawled node's identity hash, or `''` for
   *  this device's own evidence. `from` cannot answer it — a `route2` anchors
   *  at the via-node either way. */
  src: string
  /** No row reports the reverse direction yet, so the line is drawn from `from`
   *  and stopped short of `to`. We know how `from` gets there; how `to` gets
   *  back is a separate fact that arrives when that node is visited. */
  stopsShort: boolean
}

export interface GraphNode {
  /** Stable across redraws so the layout can keep a vertex where it was. */
  key: string
  /** Never empty — a circle with no caption is a mystery. */
  label: string
  /** Longer identification for the detail panel. */
  addresses: string[]
  ifs: GraphIface[]
  transport: boolean
  us: boolean
  /** Hops from the viewing device; 0 is us, `null` where nothing joined it up. */
  dist: number | null
  /** Its remote-management announce carried a signature by the community key. */
  member: boolean
  /** Unix seconds of the last crawl visit, 0 for never. */
  visited: number
  /** A placeholder for the far end of an edge nothing has claimed yet. */
  stub: boolean
}

export interface Graph {
  nodes: GraphNode[]
  edges: GraphEdge[]
  /** Index of this device, or -1 before rnsd has an identity. */
  self: number
  /** The community radius in force, for the crawl button's caption. */
  radius: number
}

function s(v: unknown): string { return v === undefined || v === null ? '' : String(v) }
function num(v: unknown): number { const n = Number(v); return Number.isFinite(n) ? n : 0 }
/** Empty means "no answer", which an integer cannot say — 0 is a real value for
 *  both `dist` (us) and `age_s` (this second). */
function optNum(v: unknown): number | null {
  const t = s(v)
  return t === '' ? null : num(t)
}

const EVIDENCE: Evidence[] = ['route1', 'route2', 'heard', 'record']
function evidence(v: unknown): Evidence {
  const t = s(v)
  return (EVIDENCE as string[]).includes(t) ? (t as Evidence) : 'record'
}

/** Build the graph from the mirrored store. Pure — no subscriptions, no state;
 *  the caller re-runs it when the store changes. */
export function buildGraph(): Graph {
  const device = useDeviceStore()
  const pill = (cls: string) => `#${s(device.get(`rns.pill.${cls}.color`)) || '888888'}`

  const me = s(device.get('netgraph.self'))
  const slots = num(device.get('netgraph.nodes.slots'))

  const nodes: GraphNode[] = []
  /* Row index → vertex index. They coincide for published rows, but the stub
   * vertices appended below do not exist in the rows, so the map is what keeps
   * the edge endpoints honest. */
  const rowToNode = new Map<number, number>()

  for (let i = 0; i < slots; i++) {
    const t = device.get(`netgraph.nodes.${i}`)
    if (!t) continue
    const id = s(t.id)
    const name = s(t.name)
    const label = s(t.label)

    const ifs: GraphIface[] = []
    const nifs = num(device.get(`netgraph.ifs.${i}.count`))
    for (let k = 0; k < nifs; k++) {
      const f = device.get(`netgraph.ifs.${i}.${k}`)
      if (!f) continue
      ifs.push({ cls: s(f.cls), name: s(f.name), detail: s(f.detail) })
    }

    const addresses: string[] = []
    if (id) addresses.push(id)
    if (label && label !== id) addresses.push(label)

    rowToNode.set(i, nodes.length)
    nodes.push({
      key: id || `addr:${label}:${i}`,
      /* Best evidence first: what it called itself, then the address it was
       * reached at, then the identity it announced under. */
      label: name || label || (id ? id.slice(0, 8) : '?'),
      addresses,
      ifs,
      transport: num(t.transport) !== 0,
      us: !!id && id === me,
      dist: optNum(t.dist),
      member: num(t.member) !== 0,
      visited: num(t.visited),
      stub: false,
    })
  }

  /* ── links ──
   * Both directions of an adjacency are separate rows, because they are two
   * independent statements: one node's evidence about how it reaches another
   * says nothing about the return path. Where both rows are present they merge
   * into one line that touches both circles. Where only one is, the line is
   * drawn from the reporting end and stopped a vertex-radius short of the far
   * one — the gap is the visible half of the invariant.
   *
   * The pair key includes the class, so two nodes joined over both LoRa and
   * Bluetooth stay two lines, which is the fact worth seeing. */
  const edges: GraphEdge[] = []
  const stubs = new Map<string, number>()
  const seen = new Map<string, number[]>()   // pair+cls → edge indices
  const nLinks = num(device.get('netgraph.links.count'))
  for (let j = 0; j < nLinks; j++) {
    const t = device.get(`netgraph.links.${j}`)
    if (!t) continue
    const from = rowToNode.get(num(t.a))
    if (from === undefined) continue

    let to: number | undefined
    if (num(t.b) >= 0) {
      to = rowToNode.get(num(t.b))
    } else {
      const ref = s(t.bref)
      if (!ref) continue
      to = stubs.get(ref)
      if (to === undefined) {
        to = nodes.length
        stubs.set(ref, to)
        nodes.push({
          key: `stub:${ref}`, label: ref, addresses: [ref], ifs: [],
          transport: false, us: false, dist: null, member: false,
          visited: 0, stub: true,
        })
      }
    }
    if (to === undefined) continue

    const cls = s(t.cls)
    const iface = s(t.iface)
    const ev = evidence(t.ev)
    const transport = num(t.transport) !== 0
    const ageS = optNum(t.age_s)
    const src = s(t.src)

    /* Bucket by the PAIR, not by pair-and-class. A row whose class is empty
     * still describes the same adjacency: a crawled edge carries no class,
     * because the medium it names belongs to the reporting node's vocabulary
     * and not to ours. Keying the bucket on the class put such a row in a
     * bucket of its own, so a neighbour's report of a link we already draw in
     * its medium's colour arrived as a second, uncoloured arc beside it —
     * "routed, 1 hop" in parallel with the lora line that says the same thing. */
    const key = from < to ? `${from}-${to}` : `${to}-${from}`
    const bucket = seen.get(key) ?? []
    /* Merge into the first edge in this bucket that is the OTHER way round, is
     * still waiting for its reverse, and does not contradict this one's medium.
     * An empty class contradicts nothing — it is an absence of a claim, not a
     * claim of absence. */
    const mate = bucket.find(i => {
      const e = edges[i]
      return e.from === to && e.stopsShort && (!e.cls || !cls || e.cls === cls)
    })
    if (mate !== undefined) {
      const e = edges[mate]
      e.stopsShort = false
      if (iface) e.ifaces.push(iface)
      if (transport) e.transport = true
      /* Whichever side actually knew the medium names it. */
      if (!e.cls && cls) { e.cls = cls; e.color = pill(cls); e.ev = ev }
      /* The freshest either side dated — and a dated sighting beats none. */
      if (ageS !== null && (e.ageS === null || ageS < e.ageS)) e.ageS = ageS
      if (!e.src && src) e.src = src
      continue
    }
    bucket.push(edges.length)
    seen.set(key, bucket)
    edges.push({
      from, to, ifaces: [iface], cls,
      /* `route2` has no class: our interface name says what WE transmit on,
       * not what the via-node used, so its medium is genuinely unknown and
       * colouring it would assert one. */
      color: ev === 'route2' ? '#d8dee6' : pill(cls),
      ev, transport, ageS, src, stopsShort: true,
    })
  }

  /* ── the reach rule is about the ADJACENCY, not about one medium ──
   *
   * The gap says "we know how `a` gets there; how `b` gets back is not known".
   * That question is answered by ANY row running the other way, whatever medium
   * carries it: two nodes joined over both LoRa and Bluetooth, where `a` routes
   * out over one and `b` routes back over the other, know perfectly well how to
   * reach each other — and drawing two arcs both stopped short says the
   * opposite. Merging per class is right for how many LINES there are; it is
   * the wrong question for whether the return path exists.
   *
   * So closure is decided per unordered pair, over every row, before the
   * per-class merge above has anything to say about it. */
  const reaches = new Set<string>()
  for (let j = 0; j < nLinks; j++) {
    const t = device.get(`netgraph.links.${j}`)
    if (!t) continue
    const from = rowToNode.get(num(t.a))
    const to = num(t.b) >= 0 ? rowToNode.get(num(t.b)) : undefined
    if (from !== undefined && to !== undefined) reaches.add(`${from}>${to}`)
  }
  for (const e of edges) if (reaches.has(`${e.to}>${e.from}`)) e.stopsShort = false

  /* A stub cannot report, so one-endedness there is the definition rather than
   * an observation — stopping short of it would read as a fault. */
  for (const e of edges) if (nodes[e.to]?.stub) e.stopsShort = false

  const self = nodes.findIndex(n => n.us)
  return { nodes, edges, self, radius: num(device.get('netgraph.radius')) }
}
