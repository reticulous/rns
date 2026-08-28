#pragma once
/**
 * rnsd_peers — the neighbourhood (nodes and their direct peers), private half.
 *
 * The public surface (rnsd_peer_t, rnsd_node_t, the walks, the printer, the
 * pill publisher) is in rnsd.h, because interface straddles are its callers.
 * What is here is the seam between rnsd.cpp and rnsd_peers.cpp: the announce
 * and interface hooks one calls on the other, and the interface walk the other
 * needs back.
 */
#include "rnsd.h"

#include <cstddef>
#include <cstdint>

/** A peer is reachable under `iface`, or has gone. `key` is the origin key
 *  inbound frames from it are prefixed with — all-zero for a point-to-point
 *  interface, where the interface itself is the node. `label` is its transport
 *  address, shown until an announce gives it a name.
 *
 *  Called when an interface registers (from `rnsd_iface_t.peer_label`) and on
 *  every RNSD_IFACE_AUX_PEER. Declaring a node twice refreshes its label. */
void rnsdNodeDeclare(const char* iface, const uint8_t key[RNSD_NODE_KEY_LEN],
                     const char* label, bool up);

/** One validated announce, as seen by rnsd's own announce handler. Called on
 *  the rnsd task, in Transport::inbound's call stack, for EVERY announce —
 *  the table itself decides what is worth keeping (direct, on an interface
 *  with a community).
 *
 *  `iface` is the registered interface name ("lora/0", "tcp_in/…"), empty for
 *  an announce with no interface behind it. `origin` is the key of the peer it
 *  came from, or null on a medium that cannot attribute one. `hops` is the raw
 *  RNS count, so 1 is the node at the other end of the wire — anything above
 *  that arrived through a peer that FORWARDS, which is how a node is known to
 *  be a transport node without asking it. `rssi`/`snr10` are the receiving
 *  interface's own last-packet sample, valid only while `have_signal`. */
void rnsdPeersObserve(const char* iface, uint8_t community_radius, uint8_t hops,
                      const uint8_t* origin,
                      const uint8_t dest[RNSD_DEST_HASH_LEN],
                      const uint8_t name_hash[RNSD_NAME_HASH_LEN],
                      const uint8_t* app_data, size_t app_n,
                      bool have_signal, int16_t rssi, int16_t snr10);

/** An interface has deregistered: forget its nodes and their peers. A BLE peer
 *  and a TCP connection are each their own interface, so this is how a peer
 *  that has gone away stops being listed — nothing announces a departure. */
void rnsdPeersIfaceGone(const char* iface);

/** Age out and re-publish, when anything changed. Called from rnsd's
 *  housekeeping tick. */
void rnsdPeersTick(void);

/** The registered interface table, in registration order — implemented in
 *  rnsd.cpp, where the table lives. `radius` is the interface's community
 *  radius, which is what decides whether it has a neighbourhood at all.
 *
 *  Lock-free, single-writer: the table is only ever written on the rnsd task,
 *  and this reads it in place. Off that task it is therefore ADVISORY — a name
 *  read while a slot is being recycled can be torn, and the answer is right
 *  again the next time it is asked. Fine for a listing or for composing a
 *  network-graph record; never state to act on. */
void rnsdIfaceWalk(void (*cb)(const char* name, uint8_t radius, void* ctx), void* ctx);

/** One interface's community radius, 0 for an unregistered name. Also in
 *  rnsd.cpp: the listing needs it per node, to tell "nobody has announced yet"
 *  from "this is an uplink and its destinations are deliberately not tracked".
 *  Same lock-free, advisory-off-task read as rnsdIfaceWalk. */
uint8_t rnsdIfaceRadius(const char* name);
