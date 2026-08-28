/**
 * netGraph — rnsd's neighbourhood, as a graph.
 *
 * Reads the standardised tables rnsd publishes (`rnsd.nodes.*`, `rnsd.peers.*`)
 * and turns them into vertices and edges. Nothing device-specific and no
 * per-medium knowledge: a medium added tomorrow appears here the moment rnsd
 * files its peers, because every one of them fills the same shape.
 *
 * ONE VERTEX PER PHYSICAL NODE, NOT PER INTERFACE. rnsd files a node per
 * (interface, peer) — the same device reached over LoRa and over Bluetooth is
 * two rows there, correctly, because those are two different links. On a graph
 * they are one circle with two lines to it, and the join is EVIDENCE rather than
 * a guess: a destination hash is a cryptographic identity, so two rnsd nodes
 * that have announced the same destination are the same device. Nothing else
 * merges them.
 *
 * Each rnsd node then contributes its own EDGE, coloured by the medium it sits
 * on — so parallel links stay visible as parallel lines.
 */
import { useDeviceStore } from 'spangap-browser/stores/device'

/** The interface CLASS behind a registered name: `lora/0` → `lora`,
 *  `tcp_in/1.2.3.4#0` → `tcp`, `ble/aabbccdd` → `ble`. It is what keys the
 *  status-line pill, which is where the colour comes from. */
export function ifaceClass(iface: string): string {
  return (iface || '').split('/')[0].split('_')[0]
}

export interface GraphEdge {
  /** Index into `nodes`. */
  to: number
  iface: string
  cls: string
  color: string
  transport: boolean
  label: string
  /** Destinations announced over this link. */
  peers: number
  heard: number
  rssi: string
  snr: string
}

export interface GraphNode {
  /** Stable across redraws so the layout can keep a vertex where it was. */
  key: string
  /** Announced name where one is known, else the transport address, else the
   *  destination hash. Never empty — a circle with no caption is a mystery. */
  label: string
  /** Longer identification for the detail panel. */
  addresses: string[]
  dests: { dest: string; aspect: string; name: string; heard: number }[]
  transport: boolean
  us: boolean
  /** Newest `heard` across everything filed under it, device unix-seconds. */
  heard: number
}

export interface Graph {
  nodes: GraphNode[]
  /** Edges out of the local node, one per link. Index 0 of `nodes` is us. */
  edges: GraphEdge[]
}

function s(v: unknown): string { return v === undefined || v === null ? '' : String(v) }
function num(v: unknown): number { const n = Number(v); return Number.isFinite(n) ? n : 0 }

/** Build the graph from the mirrored store. Pure — no subscriptions, no state;
 *  the caller re-runs it when the store changes. */
export function buildGraph(): Graph {
  const device = useDeviceStore()
  const pill = (cls: string) => `#${s(device.get(`rns.pill.${cls}.color`)) || '888888'}`

  /* rnsd's own tables, read as published. Node indices are TABLE SLOTS (a peer
   * names its node by one), so the walk is over slots and holes are normal. */
  const slots = num(device.get('rnsd.nodes.slots'))
  type RnsdNode = {
    slot: number; iface: string; label: string; transport: boolean; heard: number
  }
  const rnsdNodes: RnsdNode[] = []
  for (let i = 0; i < slots; i++) {
    const t = device.get(`rnsd.nodes.${i}`)
    if (!t || !s(t.iface)) continue
    rnsdNodes.push({
      slot: i,
      iface: s(t.iface),
      label: s(t.label),
      transport: num(t.transport) !== 0,
      heard: num(t.heard),
    })
  }

  const nPeers = num(device.get('rnsd.peers.count'))
  type RnsdPeer = {
    node: number; iface: string; dest: string; aspect: string; name: string
    heard: number; rssi: string; snr: string
  }
  const peers: RnsdPeer[] = []
  for (let i = 0; i < nPeers; i++) {
    const t = device.get(`rnsd.peers.${i}`)
    if (!t || !s(t.dest)) continue
    peers.push({
      node: t.node === undefined ? -1 : num(t.node),
      iface: s(t.iface),
      dest: s(t.dest),
      aspect: s(t.aspect),
      name: s(t.name),
      heard: num(t.heard),
      rssi: s(t.rssi),
      snr: s(t.snr),
    })
  }

  /* ── the join ──
   * A "unit" is one thing at the far end of one link: an rnsd node, or an
   * unattributed peer on a medium that cannot say who transmitted (a radio),
   * which stands for a node of its own because that is all that is known.
   * Units that share a destination hash are one device. */
  interface Unit {
    id: string
    iface: string
    label: string
    transport: boolean
    heard: number
    dests: RnsdPeer[]
  }
  const units: Unit[] = rnsdNodes.map(n => ({
    id: `n${n.slot}`,
    iface: n.iface,
    label: n.label,
    transport: n.transport,
    heard: n.heard,
    dests: [],
  }))
  const bySlot = new Map<number, Unit>()
  rnsdNodes.forEach((n, i) => bySlot.set(n.slot, units[i]))

  for (const p of peers) {
    const u = p.node >= 0 ? bySlot.get(p.node) : undefined
    if (u) { u.dests.push(p); if (p.heard > u.heard) u.heard = p.heard; continue }
    units.push({
      id: `p${p.dest}@${p.iface}`,
      iface: p.iface,
      label: '',
      transport: false,
      heard: p.heard,
      dests: [p],
    })
  }

  /* Union-find over the destination hashes. A hash seen under two units makes
   * them one device; a unit with no destinations joins nothing, which is right —
   * an attached peer that has not announced has proved nothing about itself. */
  const parent = units.map((_, i) => i)
  const find = (i: number): number => { while (parent[i] !== i) { parent[i] = parent[parent[i]]; i = parent[i] } return i }
  const union = (a: number, b: number) => { const ra = find(a), rb = find(b); if (ra !== rb) parent[rb] = ra }
  const seenDest = new Map<string, number>()
  units.forEach((u, i) => {
    for (const d of u.dests) {
      const prev = seenDest.get(d.dest)
      if (prev === undefined) seenDest.set(d.dest, i)
      else union(prev, i)
    }
  })

  /* ── vertices ──
   * Index 0 is always this device, whether or not anything is attached: a graph
   * of a neighbourhood with no centre is a graph of somebody else's. */
  const me = s(device.get('rnsd.identity_hash'))
  const nodes: GraphNode[] = [{
    key: 'us',
    label: s(device.get('s.net.hostname')) || 'this node',
    addresses: me ? [me] : [],
    dests: [],
    transport: num(device.get('s.rnsd.transport_enabled')) !== 0,
    us: true,
    heard: 0,
  }]
  const edges: GraphEdge[] = []

  const groupIndex = new Map<number, number>()   // union root → vertex index
  for (let i = 0; i < units.length; i++) {
    const root = find(i)
    let vi = groupIndex.get(root)
    if (vi === undefined) {
      vi = nodes.length
      groupIndex.set(root, vi)
      nodes.push({
        key: units[root].id, label: '', addresses: [], dests: [],
        transport: false, us: false, heard: 0,
      })
    }
    const v = nodes[vi]
    const u = units[i]
    if (u.transport) v.transport = true
    if (u.heard > v.heard) v.heard = u.heard
    if (u.label && !v.addresses.includes(u.label)) v.addresses.push(u.label)
    for (const d of u.dests)
      if (!v.dests.some(x => x.dest === d.dest))
        v.dests.push({ dest: d.dest, aspect: d.aspect, name: d.name, heard: d.heard })

    const cls = ifaceClass(u.iface)
    edges.push({
      to: vi,
      iface: u.iface,
      cls,
      color: pill(cls),
      transport: u.transport,
      label: u.label,
      peers: u.dests.length,
      heard: u.heard,
      rssi: u.dests.find(d => d.rssi)?.rssi ?? '',
      snr: u.dests.find(d => d.snr)?.snr ?? '',
    })
  }

  /* A caption for every vertex, best evidence first: what it called itself, then
   * the address it was reached at, then the hash it announced under. */
  for (const v of nodes) {
    if (v.us) continue
    const named = v.dests.find(d => d.name)
    v.label = named?.name || v.addresses[0] || (v.dests[0]?.dest.slice(0, 8) ?? '?')
  }
  return { nodes, edges }
}
