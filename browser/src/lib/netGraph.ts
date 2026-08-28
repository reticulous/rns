/**
 * netGraph — the community's graph, as the device resolved it.
 *
 * The device holds every node's self-report, joins them on evidence and
 * publishes the result as `netgraph.*` rows. This module reads those rows and
 * nothing else: vertices from `netgraph.nodes.*`, edges from `netgraph.links.*`,
 * per-node interfaces from `netgraph.ifs.*`. There is no join here, and no
 * per-medium knowledge — a medium added tomorrow appears the moment the device
 * files it, because the record format has one shape for all of them.
 *
 * WHAT IS DRAWN IS THE WHOLE COMMUNITY, not this node's neighbourhood: an edge
 * between two other nodes is here because both of them said so, over a mesh
 * this browser is not on. The one thing this device knows that nobody else can
 * — a neighbour that has attached but never announced — arrives as a local-only
 * vertex in the same rows.
 *
 * An edge whose far end names a destination no record claims is kept and
 * marked: `b` is -1 and `bref` is the four-byte prefix that went unmatched. It
 * gets a small unlabelled stub vertex, so a node's degree stays honest while
 * the record that would name the other end is still missing.
 */
import { useDeviceStore } from 'spangap-browser/stores/device'

export interface GraphIface {
  cls: string
  name: string
  /** The class's own configuration fields, pipe-separated, verbatim. Opaque to
   *  everyone but that class — rendered as it arrived. */
  detail: string
}

export interface GraphEdge {
  /** Indices into `nodes`. One LINK, not one report: where both endpoints filed
   *  the same link, their two rows are merged here and `from`/`to` is simply
   *  the direction of the first one seen. */
  from: number
  to: number
  /** The reporting sides' own interface names — one entry when only one end
   *  filed it, two when both did. */
  ifaces: string[]
  cls: string
  color: string
  /** Either endpoint is a transport node, as the other described it. */
  transport: boolean
  /** Freshest bucket either side measured: 0 ≤ 5 min, 1 ≤ 1 h, 2 ≤ 6 h, 3 older.
   *  `null` where nobody measured one — an uplink is dialled rather than heard,
   *  and a local-only neighbour has never announced. Not a zero: "just now" is
   *  a claim, and we would be making it up. */
  fresh: number | null
  /** Only one end reports this link — which is only a FACT about a link whose
   *  far end is something that files records at all. An uplink's far end is
   *  outside the community and a local-only vertex has never announced; neither
   *  will ever report, so one-endedness there is the definition rather than an
   *  observation, and saying it would read as a fault. */
  oneWay: boolean
  /** Nobody reported this link — it was inferred from the routing table, which
   *  is all a node that does not speak netgraph ever gives us. Drawn dotted: a
   *  route is evidence of adjacency, not a statement of one. */
  inferred: boolean
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
  /** The device says the record behind this vertex is getting old. */
  stale: boolean
  /** Record timestamp, device unix-seconds. 0 for a local-only vertex. */
  ts: number
  /** A placeholder for the far end of an edge no record has claimed yet. */
  stub: boolean
  /** What this vertex IS, which decides how it is drawn:
   *  - `member` — speaks for itself through a record.
   *  - `local`  — a neighbour of the viewing node that has never announced, so
   *               only that node can see it.
   *  - `uplink` — not in the community at all: the far end of a standing
   *               connection out, named only by its transport address.
   *  - `stub`   — a peer some record named whose own record has not arrived.
   *  - `routed` — routing knows it and nobody has heard it speak for itself:
   *               a node that does not run netgraph at all. */
  kind: 'member' | 'local' | 'uplink' | 'stub' | 'routed'
}

export interface Graph {
  nodes: GraphNode[]
  edges: GraphEdge[]
  /** Index of this device, or -1 before its own record exists. */
  self: number
}

function s(v: unknown): string { return v === undefined || v === null ? '' : String(v) }
function num(v: unknown): number { const n = Number(v); return Number.isFinite(n) ? n : 0 }

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

    const kindRaw = s(t.kind)
    const kind = (kindRaw === 'uplink' || kindRaw === 'local' || kindRaw === 'routed')
    ? kindRaw : 'member'

    rowToNode.set(i, nodes.length)
    nodes.push({
      key: id || `${kind}:${label}:${i}`,
      /* Best evidence first: what it called itself, then the address it was
       * reached at, then the identity it announced under. An uplink only ever
       * has the address. */
      label: name || label || (id ? id.slice(0, 8) : '?'),
      addresses,
      ifs,
      transport: num(t.transport) !== 0,
      us: !!id && id === me,
      stale: num(t.stale) !== 0,
      ts: num(t.ts),
      stub: false,
      kind,
    })
  }

  /* ── links ──
   * A link between two nodes is reported TWICE, once by each end, because each
   * end only ever writes about itself. That is the right thing for the device
   * to store — it is two independent statements — but it is one line on a
   * picture, so the two are merged here. The key is the unordered vertex pair
   * plus the medium: two nodes joined over both LoRa and Bluetooth stay two
   * lines, which is the fact worth seeing.
   *
   * Rows arriving in the same direction are NOT merged, so a node with two
   * radios on the same class still contributes two lines. */
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
          transport: false, us: false, stale: false, ts: 0, stub: true,
          kind: 'stub',
        })
      }
    }
    if (to === undefined) continue

    const cls = s(t.cls)
    const iface = s(t.iface)
    /* Empty means "nobody measured one", which is not the same as bucket 0. */
    const fresh = s(t.fresh) === '' ? null : num(t.fresh)
    const transport = num(t.transport) !== 0
    const inferred = num(t.inferred) !== 0

    const key = from < to ? `${from}-${to}-${cls}` : `${to}-${from}-${cls}`
    const bucket = seen.get(key) ?? []
    /* Merge into the first edge in this bucket that is the OTHER way round and
     * has not been paired up yet — that one is this same link, seen from its
     * far end. */
    const mate = bucket.find(i => edges[i].from === to && edges[i].oneWay)
    if (mate !== undefined) {
      const e = edges[mate]
      e.oneWay = false
      e.ifaces.push(iface)
      if (transport) e.transport = true
      /* The freshest either side measured — and a measurement beats none. */
      if (fresh !== null && (e.fresh === null || fresh < e.fresh)) e.fresh = fresh
      continue
    }
    bucket.push(edges.length)
    seen.set(key, bucket)
    edges.push({
      from, to, ifaces: [iface], cls, color: pill(cls),
      transport, fresh, oneWay: true, inferred,
    })
  }

  /* One-endedness is only an observation about a link between two things that
   * REPORT. An uplink's far end is outside the community and a local-only
   * vertex has never announced — neither will ever file a record, so a link to
   * one is one-ended by construction and saying so would read as a fault. */
  for (const e of edges) {
    const far = nodes[e.to]
    if (e.inferred) { e.oneWay = false; continue }
    if (far && (far.kind === 'uplink' || far.kind === 'local')) e.oneWay = false
  }

  const self = nodes.findIndex(n => n.us)
  return { nodes, edges, self }
}
