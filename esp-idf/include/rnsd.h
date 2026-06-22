/**
 * rnsd — RNS protocol task.
 *
 * Owns: identity, destinations, path table, transport state machine,
 *       links, resources. Zero networking/radio dependencies — receives
 *       RNS-format packets via ITS streams from transport tasks and
 *       sends them back the same way.
 *
 * This header also exposes a small byte-array C-style API that
 * encapsulates every piece of mR (microReticulum) the rest of the
 * project would otherwise need to know about: SHA-256, identity
 * generate/sign/recall, destination-hash derivation, async path
 * request. Consumers (lxmf, etc.) include only `rnsd.h` and operate
 * on raw byte arrays — never on `RNS::Identity` / `RNS::Bytes` /
 * `RNS::Destination`. The underlying crypto / protocol library can
 * therefore be swapped (mR → upstream RNS, or anything else) without
 * touching consumers.
 *
 * Threading: every function in this header is safe to call from any
 * task. Pure-crypto helpers (sha256/sign/verify/dest_hash) execute
 * inline on the caller's task. The mR-state functions (`recall*`)
 * take a recursive mutex around mR's `_known_destinations` table.
 * `rnsdRequestPath` writes a storage sentinel; the work runs on
 * rnsd's task asynchronously.
 *
 * See docs/component-plan.md §4 / §5.1 / §9 / §11.
 */
#pragma once

#include <cstdint>
#include <cstddef>

/* ──────────────── constants ──────────────── */

constexpr size_t RNSD_DEST_HASH_LEN  = 16;   /* 16-byte destination hash */
constexpr size_t RNSD_IDENT_HASH_LEN = 16;   /* 16-byte truncated identity hash */
constexpr size_t RNSD_PUBKEY_LEN     = 64;   /* Ed25519(32) + X25519(32) public key */
constexpr size_t RNSD_PRIVKEY_LEN    = 64;   /* Ed25519(32) + X25519(32) private key */
constexpr size_t RNSD_SIG_LEN        = 64;   /* Ed25519 signature */
constexpr size_t RNSD_HASH_LEN       = 32;   /* SHA-256 */

/* ──────────────── task bring-up ──────────────── */

/** Bring up the rnsd task. Called from app_main between spangapInit()
 *  and spangapPostAppInit(). */
void rnsdInit(void);

/* ──────────────── pure crypto (caller-task safe) ──────────────── */

/** SHA-256 of arbitrary bytes. Output is exactly RNSD_HASH_LEN. */
void rnsdSha256(const uint8_t* data, size_t n, uint8_t out[RNSD_HASH_LEN]);

/** Compute the conventional 16-byte destination hash for
 *  (identity, app_name, aspect). The identity is loaded from
 *  `identity_key` (a storage path holding the 128-hex private key,
 *  same convention as the `identity_key` arg to rnsdDestOpen).
 *  Returns true on success. */
bool rnsdDestinationHash(const char* identity_key,
                         const char* app_name, const char* aspect,
                         uint8_t out[RNSD_DEST_HASH_LEN]);

/** Sign `data` with the private key at `identity_key`. Output is
 *  exactly RNSD_SIG_LEN. Returns true on success. */
bool rnsdSign(const char* identity_key,
              const uint8_t* data, size_t n,
              uint8_t out_sig[RNSD_SIG_LEN]);

/** Verify a signature against a public key. Returns true iff valid. */
bool rnsdVerify(const uint8_t pubkey[RNSD_PUBKEY_LEN],
                const uint8_t* data, size_t n,
                const uint8_t sig[RNSD_SIG_LEN]);

/* ──────────────── identity management ──────────────── */

/** Generate a fresh identity and persist its 64-byte private key
 *  (as 128-hex) at `identity_key`. Returns true on success.
 *  Idempotent: if a valid identity already exists at that key, this
 *  is a no-op and returns true. Use rnsdIdentityErase first to force
 *  a re-generation. */
bool rnsdIdentityGenerate(const char* identity_key);

/** True iff the identity at `identity_key` is present and loadable. */
bool rnsdIdentityExists(const char* identity_key);

/** Compute the 16-byte truncated identity hash for the identity at
 *  `identity_key`. Returns true on success. */
bool rnsdIdentityHash(const char* identity_key,
                      uint8_t out[RNSD_IDENT_HASH_LEN]);

/** Wipe the identity at `identity_key`. */
void rnsdIdentityErase(const char* identity_key);

/* ──────────────── recall / path request ──────────────── */

/** Look up the public key for a destination in rnsd's identity cache
 *  (populated by mR as announces arrive). Takes a recursive mutex
 *  around mR's `_known_destinations` table — safe from any task.
 *  Returns true if known and populates `out_pubkey`; false if not
 *  yet heard. The standard recovery pattern on false is to call
 *  rnsdRequestPath(dest_hash) and retry later. */
bool rnsdRecallPubkey(const uint8_t dest_hash[RNSD_DEST_HASH_LEN],
                      uint8_t out_pubkey[RNSD_PUBKEY_LEN]);

/** Issue an async path request for `dest_hash`. Writes a storage
 *  sentinel; rnsd's task processes it (mR's Transport::request_path
 *  must run on the task that owns Transport state, otherwise the
 *  outbound packet silently drops). Returns immediately; the request
 *  has no return value — the caller polls via rnsdRecallPubkey or
 *  the path table. */
void rnsdRequestPath(const uint8_t dest_hash[RNSD_DEST_HASH_LEN]);

/* ──────────────── destination / link client API ────────────────
 *
 * Higher-level protocols (lxmf, rnprobe, custom apps) talk to rnsd
 * through typed ITS connections. The functions below wrap the
 * itsConnect / aux-msg machinery so callers don't have to know about
 * port numbers or connect-payload struct shapes — same pattern as
 * net's TCP_DIAL or web's path registration in spangap-core.
 *
 * The handle returned is bidirectional and packet-mode. Disconnect
 * with `itsDisconnect(handle)` — rnsd deregisters the underlying
 * mR destination / link automatically. */

/** Open an IN destination on rnsd (RNSD_PORT_DEST). The aspect is a
 *  dotted name like "lxmf.delivery"; rnsd splits it at the first dot
 *  for mR's `app_name` / `aspects` constructor arguments.
 *
 *  `identity_key` is the storage path of the 128-hex private key for
 *  this destination's identity (e.g. "secrets.lxmf.id.0.privkey").
 *  Pass nullptr or "" to use rnsd's default identity
 *  ("secrets.rnsd.identity"), which is the right choice for things
 *  like rnprobe.
 *
 *  `dest_type` is 0 = SINGLE (the usual choice), 1 = PLAIN, 2 = GROUP.
 *
 *  `ref` is opaque to rnsd; ITS passes it back to the callbacks so
 *  callers can identify which destination an event belongs to.
 *
 *  Returns the ITS handle on success (≥ 0), or a negative value if the
 *  connect failed (rnsd not up, slot full, identity load failed).
 *
 *  On the handle, exchange frames per the RNSD_DEST_* opcodes in
 *  ports.h — OUT_PACKET / IN_PACKET / ANNOUNCE / OUT_RESULT / etc. */
int rnsdDestOpen(const char* aspect,
                 const char* identity_key,
                 uint8_t     dest_type,
                 int         ref,
                 void (*on_recv)(int handle, size_t bytes_avail),
                 void (*on_disconnect)(int handle));

/** Open an outbound Reticulum Link to a remote destination
 *  (RNSD_PORT_LINK). Returned ITS handle is packet-mode: each
 *  itsSend is one Link packet, each itsRecv is one Link packet.
 *  No framing bytes — the bytes are the Link plaintext.
 *
 *  The connect **accepts immediately** — the handle comes back before
 *  the Reticulum handshake (path request → LR → LRPROOF → key
 *  derivation) completes. The Link sits in "establishing" state; the
 *  caller watches `rnsd.links.<tag>.state` (storage, browser-synced)
 *  for the transition to "active" / "failed". Sends queued before the
 *  Link is active are buffered (one-packet outbox) and flushed on
 *  establishment, or dropped with `rnsd.links.<tag>.last_error` set.
 *
 *  `tag` is a caller-chosen short id (≤ 23 chars), unique per concurrent
 *  in-flight link for that caller (e.g. "lxmf.id0.4"). It keys the
 *  link's storage state tree `rnsd.links.<tag>.*` so the caller and the
 *  browser can watch progress before the link_id is even derived.
 *
 *  `aspect` is the remote's dotted aspect ("lxmf.delivery"); rnsd splits
 *  at the first dot for mR's Destination ctor. `identity_key` is the
 *  storage path of our 128-hex identity private key, or "" for rnsd's
 *  default ("secrets.rnsd.identity"). `path_timeout_ms` overrides the
 *  path-wait budget; 0 = use `s.rnsd.link.path_timeout_s` (default 30).
 *
 *  `link_timeout_ms` overrides the establishment timeout (how long the Link
 *  may sit "establishing" before it is failed). When non-zero it is **the**
 *  timeout — used verbatim, neither floored nor capped by rnsd, and it also
 *  governs mR's own link watchdog. When 0, rnsd computes the Python-reference
 *  outbound budget: the next hop's first-hop timeout plus 6 s per hop.
 *
 *  Returns the ITS handle (≥ 0) on accept, or negative on immediate
 *  failure (rnsd down, slot table full, duplicate tag, bad args). */
int rnsdLinkOpen(const uint8_t dest_hash[RNSD_DEST_HASH_LEN],
                 const char*   aspect,
                 const char*   identity_key,
                 const char*   tag,
                 uint32_t      path_timeout_ms,
                 uint32_t      link_timeout_ms,
                 int           ref,
                 void (*on_recv)(int handle, size_t bytes_avail),
                 void (*on_disconnect)(int handle));

/** Explicitly tear down the outbound Link identified by `tag` and free
 *  its slot + `rnsd.links.<tag>.*` state. Use this — not bare
 *  itsDisconnect — when the consumer is truly done with the Link:
 *  itsDisconnect only *parks* it for `s.rnsd.link.orphan_ttl_s` so a
 *  returning consumer can re-attach (§10a.1). Returns true if the
 *  teardown aux was queued to rnsd (not whether the Link existed). */
bool rnsdLinkTeardown(const char* tag);

/** Tell rnsd to forward incoming Reticulum Links for the destination
 *  behind `dest_handle` (obtained from rnsdDestOpen) to ITS port
 *  `target_port` on the *same task* that owns `dest_handle`. rnsd
 *  flips accepts_links(true) on the destination and, when a remote
 *  completes the LR/LRPROOF handshake, opens a fresh ITS connection
 *  to (owning_task, target_port) with a `rnsd_link_incoming_t`
 *  connect payload describing the remote.
 *
 *  No target_taskname argument because rnsd already knows the owning
 *  task — the dest handle was created by an ITS connect from that
 *  task. Registering links this way means you can't accidentally
 *  forward Links for a destination you don't own.
 *
 *  NOT YET IMPLEMENTED: needs mR Link support. Returns false until
 *  Link support lands. */
bool rnsdDestListenLinks(int      dest_handle,
                         uint16_t target_port);

/* ──────────────── Resource transfer (Phase F, link.md §9) ────────────────
 *
 * Messages larger than a single Link packet (~440 B encrypted) ride a
 * Reticulum Resource instead. The data path is NOT the packet-mode ITS
 * handle (which is KB-capped) — it is a shared-memory hand-off:
 *
 *  • Inbound: rnsd accepts the advertised Resource (size-gated by
 *    `s.lxmf.max_resource_size`, default 262144), reassembles it, then
 *    opens a one-shot ITS connection to the consumer's
 *    LXMF_LINK_RESOURCE_AUX_PORT with an `rnsd_link_resource_done_t`
 *    (ports.h). On RNSD_LINK_RESOURCE_INBOUND_DONE the consumer owns
 *    `buf` and must rnsdResourceRelease() it.
 *
 *  • Outbound: the consumer hands rnsd a heap buffer; rnsd wraps it in
 *    a Resource on the named link. rnsd takes ownership of the buffer
 *    and frees it once the engine has copied it. */

/** Send `buf`/`len` as a Resource on the outbound Link identified by
 *  `tag` (the rnsdLinkOpen tag). rnsd takes ownership of `buf` (a heap
 *  pointer in the shared address space) and frees it after the Resource
 *  engine has copied it into encrypted parts — the caller must not
 *  touch `buf` after this returns. `opaque_id` is echoed back in the
 *  RNSD_LINK_RESOURCE_OUTBOUND_DONE aux so the caller can correlate.
 *  Returns true if the aux was queued to rnsd (not delivery success). */
bool rnsdLinkSendResource(const char* tag, void* buf, size_t len,
                          uint32_t opaque_id);

/** Free a buffer received via RNSD_LINK_RESOURCE_INBOUND_DONE. Thin
 *  wrapper over free() — a symmetry hook in case the allocator changes. */
void rnsdResourceRelease(void* buf);

/* ──────────────── request / response (nomad page fetch, nomad.md §1) ────────────────
 *
 * Reticulum's request/response layer rides an established Link: the
 * consumer issues `link.request(path, data)`, the remote's registered
 * handler returns response bytes. This is the NomadNet page-fetch path
 * (`/page/<rel>.mu`, `/file/<rel>`) and also `rnstatus -R` / `rnpath -R`.
 * rnsd bridges it to the byte-array world so consumers never see mR
 * types — same contract as the Resource transfer API above. */

/** Issue a request on the outbound Link identified by `tag` (already
 *  opened via rnsdLinkOpen). `path` is the request path string (e.g.
 *  "/page/index.mu"). `data`/`data_len` is the request payload (packed
 *  by the caller per the target protocol); pass nullptr/0 for a plain
 *  GET (the request envelope's data element is empty).
 *
 *  The response is delivered as one aux frame (rnsd_link_resource_done_t,
 *  opcode RNSD_LINK_REQUEST_RESPONSE) to `resp_port` on the *calling*
 *  task — the consumer owns `buf` and must rnsdResourceRelease() it.
 *  Failure or timeout → RNSD_LINK_REQUEST_FAILED (buf null). The aux's
 *  `opaque_id` echoes the returned request id so the consumer correlates.
 *
 *  If the Link is not yet ACTIVE the request is held (one pending request
 *  per link) and issued on establishment — mirrors the pre-active
 *  packet / Resource outboxes, so a consumer can rnsdLinkOpen() then
 *  rnsdLinkRequest() back-to-back.
 *
 *  v1 limit: path+data are sent inline in the aux, so they must fit
 *  ITS_MAX_MSG_DATA (ample for a page GET; large form uploads as a
 *  request-Resource are a later phase). One in-flight request per link.
 *
 *  `data_packed` (default false): when true, `data` is already a complete
 *  msgpack object (e.g. a NomadNet `{field_*,var_*}` form map built by the
 *  caller) and is spliced as the request envelope's 3rd element verbatim,
 *  rather than bin-wrapped. False is the plain GET/bin path.
 *
 *  Returns a non-negative request id (echoed as the aux opaque_id), or
 *  negative on bad args / oversize inline payload / aux-send failure. */
int rnsdLinkRequest(const char* tag, const char* path,
                    const void* data, size_t data_len,
                    uint16_t resp_port, bool data_packed = false);
