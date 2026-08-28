#pragma once
/**
 * netgraph — every node holds the community's whole graph.
 *
 *   push (continuous, unsolicited, mesh-wide):
 *     every node:  ANNOUNCE netgraph.discovery  app_data = own record, abridged
 *                  — flooded and rate-limited by ordinary RNS announce mechanics
 *
 *   sync (on demand, over one Reticulum Channel between two nodes):
 *     I → R   DIGEST        every (origin, seq) I hold
 *     R → I   RECORD_PART*  records I lack or hold older
 *     R → I   WANT          origins R lacks or holds older
 *     I → R   RECORD_PART*  those records
 *     both    DONE          then the initiator closes the channel
 *
 * Each node publishes ONE record describing only itself — its name, its
 * interfaces, its links, the destinations it announces — and never writes into
 * another node's. The graph everyone sees is the union of everyone's records,
 * resolved on device into the `netgraph.*` rows the browser NetGraph app, the
 * display and any on-device logic read. Newer seq wins; that is the whole
 * conflict story.
 *
 * The record format, the resolver and the sync engine live in netgraph.cpp;
 * this header is the two things outside it: the boot registration, and the way
 * an interface straddle contributes its own configuration to its `if` line.
 */
#include "service.h"

#include <cstddef>

/** Installs the netgraph component: seeds `s.netgraph.*`, registers the CLI
 *  verb, and joins the RNS lifecycle as a client (RNS_PHASE_CLIENT), so the
 *  record builder, store, resolver and sync engine come up with rnsd and go
 *  down with it. Gated at run time by `s.netgraph.enable`. */
class NetgraphService : public Service {
public:
    void onInit() override;
};

/* ──────────────── interface detail contribution ────────────────
 *
 * A record's `if` line names an interface's class and its registered name, and
 * then whatever that class considers its configuration — the frequency and
 * spreading factor of a radio, say. Only the class's own straddle knows what
 * those are, and netgraph has no business learning: the straddle contributes
 * FIELDS and the builder composes the line, the same division of labour as
 * rnsdPillSet one layer up. A straddle never sees a record.
 *
 * CONFIGURATION ONLY. Frequency, spreading factor, whether a mode is on: yes.
 * RSSI, negotiated budgets, traffic counters: no — those change constantly, and
 * a record that moved with them would keep every digest in the community
 * permanently mismatched. The test for a field is whether a change to it
 * deserves waking the whole mesh.
 */

/** Fill `out` with this class's tail for `iface_name`'s `if` line: pipe-
 *  separated UTF-8 fields, no leading or trailing `|`, no newline
 *  ("868.5|7|125|4/5|s"). Return the number of bytes written, or 0 for "nothing
 *  to say". Runs on the netgraph task at rebuild time — read published state,
 *  do not block. */
typedef size_t (*netgraph_iface_detail_t)(const char* iface_name,
                                          char* out, size_t outsz);

/** Register `cb` as the detail source for interface class `cls` ("lora",
 *  "tcp") — the same class word that keys the status-line pill. `cls` must be a
 *  static string. Call from the straddle's onInit(); last registration for a
 *  class wins. Safe to call before or after netgraph's own onInit. */
void netgraphContributeIface(const char* cls, netgraph_iface_detail_t cb);
