/**
 * rnsd — RNS protocol task.
 *
 * Owns: identity, destinations, path table, transport state machine,
 *       links, resources. Zero networking/radio dependencies — receives
 *       RNS-format packets via ITS streams from interface tasks and
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
 * read rnsd's directory lock-free from any task.
 * `rnsdRequestPath` writes a storage sentinel; the work runs on
 * rnsd's task asynchronously.
 */
#pragma once

#include "service.h"

#include <cstdint>
#include <cstddef>

/* ──────────────── constants ──────────────── */

constexpr size_t RNSD_DEST_HASH_LEN  = 16;   /* 16-byte destination hash */
constexpr size_t RNSD_IDENT_HASH_LEN = 16;   /* 16-byte truncated identity hash */
constexpr size_t RNSD_PUBKEY_LEN     = 64;   /* Ed25519(32) + X25519(32) public key */
constexpr size_t RNSD_PRIVKEY_LEN    = 64;   /* Ed25519(32) + X25519(32) private key */
constexpr size_t RNSD_SIG_LEN        = 64;   /* Ed25519 signature */
constexpr size_t RNSD_HASH_LEN       = 32;   /* SHA-256 */
constexpr size_t RNSD_RATCHET_LEN    = 32;   /* X25519 announce ratchet, public half */

/* ──────────────── task bring-up ──────────────── */

/** Bring up the rnsd task. Called from app_main between spangapInit()
 *  and spangapPostAppInit(). */
class RnsdService : public Service {
public:
    void onInit() override;
};

/* ──────────────── RNS ecosystem lifecycle ────────────────
 *
 * The whole RNS ecosystem (rnsd + every iface and client) starts and stops as a
 * unit, orchestrated in one place. A component registers a start/stop hook pair
 * from its onInit() — instead of self-spawning a task that waits for rnsd — and
 * the orchestrator drives them: start walks registration order (deps first),
 * stop walks it in reverse (dependents first). `rnsd.up` is the observable
 * up/down signal. A stop hook stops abruptly and frees all held memory.
 *
 * Every task an ecosystem component spawns runs at FreeRTOS priority 1. The
 * ecosystem is a pipeline — an interface produces what rnsd consumes, rnsd
 * produces what a client consumes — and FreeRTOS does not time-slice across
 * priorities: a producer placed above its consumer owns the core outright
 * whenever it has work, and the consumer never runs to drain it. Backpressure
 * then feeds itself, because the fuller the consumer's link is the more work
 * the producer has failing to fill it, and the condition can only clear on the
 * CPU the producer is holding. One level for the whole ecosystem makes the
 * scheduler round-robin them instead, which is the only arrangement where that
 * resolves. A higher priority is for work that should genuinely starve while
 * the device is busy; nothing that carries packets qualifies. */
typedef void (*rns_hook_t)(void);

/** Lifecycle phases, low-to-high. Interfaces come up first and go down LAST, so a
 *  client's link/destination teardown still has an interface to ride on when it
 *  stops; clients come up after interfaces and stop before them. */
enum { RNS_PHASE_IFACE = 0, RNS_PHASE_CLIENT = 1 };

/** Register a component in the RNS lifecycle. Call from onInit(). `name` must be
 *  a static string; either hook may be null. `phase` orders start (ascending) and
 *  stop (descending) — interfaces pass RNS_PHASE_IFACE, clients take the default.
 *  Single-threaded (boot) only. */
void rnsServiceRegister(const char* name, rns_hook_t start, rns_hook_t stop,
                        int phase = RNS_PHASE_CLIENT);

/** Bring the whole ecosystem up (no-op if already up) / take it down (no-op if
 *  already down). Also driven by the `rns start` / `rns stop` CLI verbs. */
void rnsStart(void);
void rnsStop(void);

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

/** Export the 64-byte public key blob (X25519 ‖ Ed25519) of the identity
 *  at `identity_key`. Returns false on missing/malformed identity. */
bool rnsdIdentityPubkey(const char* identity_key,
                        uint8_t out[RNSD_PUBKEY_LEN]);

/** Compute the 16-byte truncated identity hash from a raw 64-byte public
 *  key (X25519 ‖ Ed25519) — no private key or storage involved. This is
 *  how a consumer checks a pubkey it received against a known identity
 *  hash (e.g. a link peer's advertised identity). */
bool rnsdIdentityHashFromPubkey(const uint8_t pubkey[RNSD_PUBKEY_LEN],
                                uint8_t out[RNSD_IDENT_HASH_LEN]);

/** Compute the conventional destination hash for (pubkey, app, aspect)
 *  from a raw 64-byte public key — the counterpart of rnsdDestinationHash
 *  for identities we don't hold. Lets a consumer derive a peer's
 *  destination on any aspect from a pubkey it received in-band, without
 *  the peer being in the announce cache. */
bool rnsdDestinationHashFromPubkey(const uint8_t pubkey[RNSD_PUBKEY_LEN],
                                   const char* app_name, const char* aspect,
                                   uint8_t out[RNSD_DEST_HASH_LEN]);

/** Compute the conventional destination hash for (identity hash, app, aspect)
 *  from nothing but the peer's 16-byte IDENTITY hash.
 *
 *  The address derivation only ever consumed the identity's hash — the public
 *  key never enters it — so this needs neither the key nor an announce, which
 *  is what makes it the right entry point for an operator-supplied hash.
 *  `rnstatus -R <hash>` and `rnpath -R <hash>` take exactly this argument
 *  upstream, and a remote-management address is derived this way and no other.
 *
 *  Deriving an address is not the same as being able to reach it: the returned
 *  hash still needs a path, and a link to it still needs the peer's key. Both
 *  arrive by the ordinary means (rnsdRequestPath, then the announce that
 *  answers it). */
bool rnsdDestinationHashFromIdentityHash(const uint8_t ident_hash[RNSD_IDENT_HASH_LEN],
                                         const char* app_name, const char* aspect,
                                         uint8_t out[RNSD_DEST_HASH_LEN]);

/* ──────────────── payload encryption ────────────────
 *
 * mR Identity token encryption (ephemeral X25519 ECDH + HKDF +
 * AES-128-CBC + HMAC), the same construction RNS uses for opportunistic
 * packet payloads — so a token encrypted here is decryptable by any RNS
 * identity holder, and vice versa. The intended use is store-and-forward
 * payloads that must be opaque to the forwarder.
 * Pure-crypto: runs inline on the caller's task. */

/** Encrypt `in` for the identity whose 64-byte public key is `pubkey`.
 *  `out` must have room for `in_len + RNSD_ENCRYPT_OVERHEAD` bytes;
 *  `*out_len` receives the token size. Returns false on malformed key or
 *  crypto failure.
 *
 *  `dest_hash` names the destination the payload is for, so this can
 *  encrypt to the ratchet that destination last announced (forward
 *  secrecy) instead of its long-term key. Pass null only when there is no
 *  destination to name — a payload encrypted to the static key is
 *  readable forever by anyone who later obtains the recipient's identity,
 *  which for store-and-forward mail sitting on a third party is exactly
 *  the exposure ratchets exist to close. The recipient trial-decrypts, so
 *  either choice interoperates. */
#define RNSD_ENCRYPT_OVERHEAD 96   /* ephemeral pub 32 + IV 16 + pad ≤16 + HMAC 32 */
bool rnsdEncryptFor(const uint8_t pubkey[RNSD_PUBKEY_LEN],
                    const uint8_t dest_hash[RNSD_DEST_HASH_LEN],
                    const uint8_t* in, size_t in_len,
                    uint8_t* out, size_t* out_len);

/** Decrypt a token produced by rnsdEncryptFor (or any RNS Identity
 *  encryption) with the private identity at `identity_key`. `out` must
 *  have room for `in_len` bytes; `*out_len` receives the plaintext size.
 *  Returns false if the token is malformed or not for this identity.
 *
 *  `dest_hash` names one of our hosted destinations; its retained ratchet
 *  private keys are tried before the identity key, which is what makes a
 *  ratchet-encrypted payload readable. Pass null for a payload that
 *  cannot have been ratcheted. */
bool rnsdDecryptSelf(const char* identity_key,
                     const uint8_t dest_hash[RNSD_DEST_HASH_LEN],
                     const uint8_t* in, size_t in_len,
                     uint8_t* out, size_t* out_len);

/* ──────────────── recall / path request ──────────────── */

/** Look up the public key for a destination in rnsd's directory, populated by
 *  mR as announces arrive. Lock-free from any task — the directory is
 *  single-writer with a per-record sequence counter, and this copies out.
 *  Returns true if known and populates `out_pubkey`; false if not yet heard.
 *  The standard recovery pattern on false is to call rnsdRequestPath(dest_hash)
 *  and retry later. */
bool rnsdRecallPubkey(const uint8_t dest_hash[RNSD_DEST_HASH_LEN],
                      uint8_t out_pubkey[RNSD_PUBKEY_LEN]);

/** Seed a (dest_hash → public_key) mapping learned OFF the network.
 *
 *  Everything reachable by announce arrives on its own; this exists for the
 *  one case that cannot: a key that came in over an authenticated side
 *  channel, such as a mailbox owner's key carried in a signed authentication
 *  frame. Nothing else should call it — a key cached without a path saves no
 *  work, because acquiring a path means a path request and the path response
 *  *is* an announce carrying the key.
 *
 *  Arguments:
 *    dest_hash  the peer's RNS destination hash — RNSD_DEST_HASH_LEN (16) bytes,
 *               the same value rnsdRecallPubkey / rnsdDestHash use as the key.
 *    pubkey     the peer's public key — RNSD_PUBKEY_LEN (64) bytes, X25519(32) ‖
 *               Ed25519(32), exactly the layout rnsdRecallPubkey returns.
 *
 *  Threading: safe from any task. The write is marshalled to the rnsd task, so
 *  it is asynchronous — the key is not necessarily recallable the instant this
 *  returns. Returns false only on a malformed argument. */
bool rnsdSeedPubkey(const uint8_t dest_hash[RNSD_DEST_HASH_LEN],
                    const uint8_t pubkey[RNSD_PUBKEY_LEN]);

/* ──────────────── remote management ────────────────
 *
 * Reticulum's own management service, served from this node:
 *
 *   any RNS installation → us
 *     ← ANNOUNCE rnstransport.remote.management   (ours, on the stock beat)
 *     ─ LINK ─────────────────────────────────►
 *     ─ IDENTIFY ─────────────────────────────►   checked against the allow list
 *     ─ REQUEST /path | /status ──────────────►
 *     ◄ RESPONSE (upstream's shapes, from Transport's own tables)
 *
 * The address is the stock one — `rnstransport.remote.management` on this
 * node's transport identity — so `rnstatus -R <our identity hash>` from an
 * unmodified `pip install rns` works with nothing on the other side but that
 * hash in a config file.
 *
 * THE HANDLERS LIVE HERE, not in the consumer that turns them on. µR's
 * response generator returns its answer synchronously, inside
 * Link::handle_request on the rnsd task; marshalling that to another task and
 * back would mean blocking rnsd for the round trip. The answers are Transport's
 * own path table and interface statistics, so there is nothing to marshal —
 * this is where the data already is. A consumer supplies the POLICY (whether to
 * serve at all, and who may ask) and rnsd supplies the answers. */

/** Start serving remote management. Idempotent. Returns false if the identity
 *  is not loaded or the destination could not be constructed. */
bool rnsdRemoteManagementStart(void);

/** Stop serving it and deregister the destination. Idempotent. */
void rnsdRemoteManagementStop(void);

/** Replace the allow list: the identity hashes permitted to invoke `/path` and
 *  `/status`. An unidentified link is refused outright, and so is an identity
 *  that is not on this list — upstream's ALLOW_LIST, with the same meaning.
 *  Passing n = 0 leaves the service reachable but refusing everyone, which is
 *  the correct state for a node that is serving with no community configured
 *  and no hashes granted. */
void rnsdRemoteManagementAllow(const uint8_t (*hashes)[RNSD_IDENT_HASH_LEN], int n);

/** True while the destination is up. */
bool rnsdRemoteManagementServing(void);

/** Set the `app_data` this node's management announce carries — a community
 *  membership signature, say. Upstream announces this destination with no
 *  app_data and stock clients ignore whatever is there, so anything put here
 *  breaks nothing. Pass nullptr/0 to carry none. Airs one announce. */
void rnsdRemoteManagementAnnounceData(const uint8_t* data, size_t n);

/** The `-R` half: ask ANOTHER node instead of ourselves.
 *
 *  `rnstatus -R <hash>` and `rnpath -R <hash>` take a transport identity hash
 *  exactly as upstream does, and the destination is derived the stock way. The
 *  asking is done by whoever registered here — rnsd owns the tables and the
 *  Link, but not the policy about which identity to present or what to do with
 *  the answer — so the CLI verbs call through this and print nothing but an
 *  acknowledgement. Unregistered, `-R` says the facility is not available
 *  rather than failing obscurely.
 *
 *  The callback runs on the CLI task and must not block: it queues the visit
 *  and returns. Answers land in the log, because a LoRa node may take a minute
 *  to reply and the CLI session that asked may be long gone. */
typedef void (*rnsd_remote_ask_t)(const uint8_t ident[RNSD_IDENT_HASH_LEN]);
void rnsdSetRemoteAsker(rnsd_remote_ask_t cb);

/** What a DEVICE is called, given the identity behind one of its destinations.
 *
 *  rnsd names a destination from the display name its announce advertised,
 *  which is what LXMF and NomadNet put there — a person's name, on a person's
 *  address. A node's own addresses carry none: a probe announce is empty and a
 *  management announce is not text. So `rnpath -r` on the very destinations
 *  that ARE a device could only ever print an aspect.
 *
 *  A device name is a different fact, learned elsewhere and by whoever tracks
 *  devices. Registering a resolver here lets the path table say it without rnsd
 *  learning what a device is. Return false when the identity is not one you
 *  know; the caller falls back to what it had.
 *
 *  Runs on the CLI task against whatever the resolver's own storage is, so it
 *  must copy out and not block. */
typedef bool (*rnsd_name_resolve_t)(const uint8_t ident[RNSD_IDENT_HASH_LEN],
                                    char* out, size_t outsz);
void rnsdSetNameResolver(rnsd_name_resolve_t cb);

/* ──────────────── directory claims ────────────────
 *
 * A claim tells rnsd that a destination matters to you, so that when memory
 * runs short the records it drops are the ones nobody asked for. It is a
 * preference, not a lifetime: retention is the maximum over all claims on a
 * record, and rnsd may still break any of them under pressure. There is
 * deliberately no expiry argument — a duration reads as a guarantee, and a
 * guarantee is the first thing that has to break at 88% memory.
 *
 * The invariant that keeps this safe: an unbounded claim population may not
 * carry a long duration. Claim your contacts (bounded by the address book) and
 * your mesh neighbours (bounded by the mesh). Never claim what arrives from
 * the network at large.
 *
 * Claims are advisory and fire-and-forget, so none of these report failure.
 * They are not durable state either: the authoritative record of "this is a
 * contact" is your own, and you re-assert at startup. */

enum {
    RNSD_CLAIM_LXMF  = 0,
    RNSD_CLAIM_NOMAD = 1,
    RNSD_CLAIM_RNSH  = 2,
    RNSD_CLAIM_RLPG  = 3,
    RNSD_CLAIM_RNSD  = 4,
    /** netgraph, on the management destinations it wants to be able to reach.
     *  The announce table evicts by memory pressure and never by time, so an
     *  unclaimed announce sits early on the eviction ladder — and recalling a
     *  two-hourly announce reliably means claiming it. */
    RNSD_CLAIM_NETGRAPH = 5,
};

/** PERSIST outranks EPHEMERAL under eviction; an EPHEMERAL claim also lapses
 *  once `decay_s` has passed since its last touch. */
#define RNSD_CLAIM_EPHEMERAL 0
#define RNSD_CLAIM_PERSIST   1

/** DIR keeps who the destination is; DIR_BLOB additionally asks rnsd to keep
 *  the raw signed announce, which is what lets this node answer a path request
 *  for it. */
#define RNSD_CLAIM_LAYER_DIR      1
#define RNSD_CLAIM_LAYER_DIR_BLOB 3

/** Assert or refresh `consumer`'s claim on `dest_hash`. `decay_s` is the
 *  ordering scale for EPHEMERAL claims (0 = rnsd's default); it is ignored for
 *  PERSIST. */
void rnsdClaim(const uint8_t dest_hash[RNSD_DEST_HASH_LEN],
               uint8_t consumer, uint8_t klass, uint8_t layers, uint32_t decay_s);

/** Restamp an existing claim without changing its terms — "still interested". */
void rnsdClaimTouch(const uint8_t dest_hash[RNSD_DEST_HASH_LEN], uint8_t consumer);

/** Release this consumer's claim. Other consumers' claims are untouched. */
void rnsdClaimDrop(const uint8_t dest_hash[RNSD_DEST_HASH_LEN], uint8_t consumer);

/** Recall the last-heard announce app_data for a destination. This reads the
 *  retained raw announce, so it answers only while rnsd still holds one for
 *  that destination — knowing who a destination is does not imply still having
 *  its announce. Consumers that need app_data reliably should take it from the
 *  announce fan-out, which carries it on arrival, and keep their own copy.
 *  Copies up to `*inout_len` bytes into `out` and writes the actual length
 *  back. Returns false if the destination is unknown, its announce is no longer
 *  retained, it carried no app_data, or the payload exceeds the supplied
 *  buffer. app_data is opaque here — the consumer parses it. */
bool rnsdRecallAppData(const uint8_t dest_hash[RNSD_DEST_HASH_LEN],
                       uint8_t* out, size_t* inout_len);

/** Issue an async path request for `dest_hash`. Writes a storage
 *  sentinel; rnsd's task processes it (mR's Transport::request_path
 *  must run on the task that owns Transport state, otherwise the
 *  outbound packet silently drops). Returns immediately; the request
 *  has no return value — the caller polls via rnsdRecallPubkey or
 *  the path table. */
void rnsdRequestPath(const uint8_t dest_hash[RNSD_DEST_HASH_LEN]);

/** Evict `dest_hash` from the path table (mR's Transport::remove_path).
 *  Same async storage-sentinel discipline as rnsdRequestPath — the removal
 *  runs on rnsd's task, which owns the path table. Fire-and-forget; no return.
 *  Intended for a deliberate "forget the route and rediscover it" step, e.g.
 *  lxmf's delivery retry after a proof/response timeout, so the next send
 *  triggers a fresh path lookup instead of reusing a stale/dead route. */
void rnsdDropPath(const uint8_t dest_hash[RNSD_DEST_HASH_LEN]);

/* ──────────────── rx-signal-report capability ────────────────
 *
 * A reticulous node can append its own rx signal (rssi/snr) and antenna tx
 * power to the delivery proof it emits for a direct radio message, so the
 * sender learns how well it was heard and at what power the answer left (the
 * "extended proof", Packet::prove_report). A vanilla RNS node would
 * length-reject that longer
 * proof, so rnsd only emits it to peers KNOWN to accept it — those that
 * advertised the rx-report capability (LXMF announce caps bit1). lxmf owns that
 * knowledge (it parses announces); rnsd owns the proof path. These two calls
 * bridge the two: lxmf records the capability per peer here, rnsd consults it
 * when proving. Receiving an rx report is unconditional — we accept and process
 * reports from anyone; the capability gates only what WE emit. */

/** Record whether the peer at `dest_hash` (its lxmf.delivery destination hash)
 *  accepts rx-signal-report delivery proofs. Set from each parsed announce
 *  (true when LXMF caps bit1 is present, false otherwise). RAM-only, reset on
 *  reboot and refreshed by the next announce. Safe from any task. */
void rnsdSetRxReportCap(const uint8_t dest_hash[RNSD_DEST_HASH_LEN], bool capable);

/** Query the flag set by rnsdSetRxReportCap. Returns false when the peer is
 *  unknown (no announce with a caps element heard since boot) or not capable.
 *  Safe from any task. */
bool rnsdGetRxReportCap(const uint8_t dest_hash[RNSD_DEST_HASH_LEN]);

/* ──────────────── the announce beat ────────────────
 *
 * How often this node says who it is belongs to the MEDIUM, not to any
 * application. An application's job is to keep its stored announce current —
 * `RNSD_DEST_ANNOUNCE` sets it, and rnsd holds the bytes; when to put those
 * bytes on the air is the interface's call, because only the interface knows
 * what airtime costs there. So lxmf, rnsh and rlpg carry no timer, and each
 * interface straddle drives its own beat from its own setting.
 *
 * rnsd never schedules an announce on its own. It announces when:
 *
 *   - an interface registers (the pinned replay, debounced ~1.5 s),
 *   - an interface asks, through the two calls below,
 *   - an application sets a new stored announce — coalesced for a minute and
 *     then sent on every interface, so a boot that brings up four applications
 *     spends one sweep rather than four.
 *
 * Both calls are fire-and-forget and safe from any task, including a storage
 * subscription hosted on the storage task (which is what an "Announce now"
 * button's sentinel handler is). */

/** Replay every hosted destination's stored announce onto the interfaces whose
 *  registered name starts with `prefix` — `"lora/0"` for one radio, `"lora"`
 *  for every radio, `"ble"` for every Bluetooth peer, `"tcp"` for every
 *  connection inbound and out, `""` for the lot. See rnsd_iface_announce_t. */
void rnsdIfaceAnnounceNow(const char* prefix);

/** The beat itself, for an interface straddle to call from its own loop:
 *  fires rnsdIfaceAnnounceNow(prefix) once every `interval_min` minutes ± 10 %,
 *  the jitter being what stops a fleet powered up together from announcing in
 *  lockstep forever.
 *
 *  `*next_ms` is caller-owned state, zero-initialised. The first call ARMS it
 *  rather than announcing — the registration replay has just covered this
 *  interface, and repeating it a tick later would be pure noise. `interval_min`
 *  0 means never on the interface's own account, which is not a long interval:
 *  the node then announces only when an application changes what it says or
 *  somebody presses the button. */
void rnsdAnnounceBeat(uint32_t* next_ms, int interval_min, const char* prefix);

/* ──────────────── direct peers — the neighbourhood ────────────────
 *
 * Who is one hop away, per interface. Every interface has the same question to
 * answer and the same evidence to answer it with — an announce that arrived
 * with hops == 1 came from the node that transmitted it — so the table lives
 * here rather than once per interface straddle. It is populated from rnsd's own
 * announce handler and therefore covers every medium, present and future,
 * without an interface writing a line of code for it.
 *
 * Kept only for an interface with a COMMUNITY (`community_radius > 0`): a
 * radius-0 interface is an uplink, whose far end is a route rather than a
 * neighbourhood, and whose announce firehose would fill the table with the
 * whole wide network's direct-to-it peers.
 *
 * A peer here is a DESTINATION. A NODE is the thing at the far end, and the two
 * are only the same on a medium that cannot tell them apart. Where an interface
 * can say WHICH peer a packet came from — a point-to-point one, because there
 * is only one; a multi-peer one that sets `rx_origin` and prefixes each frame
 * with an origin key — rnsd groups that peer's destinations under one node, and
 * the listing shows one numbered block per node with its destinations under it.
 * On a shared broadcast medium with no such attribution (a radio) it cannot:
 * two identities announced into the air are indistinguishable from two nodes,
 * and merging on a guess would put the wrong lines on a graph. Only a medium
 * with a node-level protocol of its own can do better there, which is why
 * [iface-lora] keeps its own SUPE-clustered table.
 *
 * A node exists from the moment it is REACHABLE, not from its first announce:
 * an interface declares it (`rnsd_iface_t.peer_label`, or RNSD_IFACE_AUX_PEER
 * for a multi-peer medium) with the transport address to show until an announce
 * gives it a name. A peer that has attached and said nothing is a row rather
 * than a silence.
 */

constexpr size_t RNSD_NAME_HASH_LEN  = 10;  /* aspect name hash carried by an announce */
constexpr size_t RNSD_PEER_IFACE_MAX = 24;  /* == rnsd_iface_t::name */
/* Long enough for the longest aspect this firmware speaks —
 * "rnstransport.remote.management", 30 characters — plus the NUL, rounded up.
 * An aspect that does not fit is not merely displayed short: it is copied
 * truncated into the peer and hosted-destination rows, so the name no longer
 * matches the one every other table and every log line uses. */
constexpr size_t RNSD_PEER_ASPECT_MAX = 32;
constexpr size_t RNSD_PEER_NAME_MAX  = 32;  /* announced display name */
constexpr size_t RNSD_NODE_KEY_LEN   = 16;  /* == rnsd_iface_peer_t::key */
constexpr size_t RNSD_NODE_LABEL_MAX = 48;  /* == rnsd_iface_peer_t::label */

/** One direct peer — a destination one hop away — as handed to a walk callback. */
typedef struct {
    uint8_t  dest[RNSD_DEST_HASH_LEN];
    uint8_t  name_hash[RNSD_NAME_HASH_LEN];
    char     iface[RNSD_PEER_IFACE_MAX];    /* registered name: "lora/0", "tcp_in/…" */
    /** The aspect in words where rnsd knows the name behind the hash
     *  ("lxmf.delivery"), empty where it does not — a name hash is one-way, so
     *  an unknown aspect can only ever be shown as its hash. */
    char     aspect[RNSD_PEER_ASPECT_MAX];
    /** Display name out of the announce's app_data (LXMF msgpack, NomadNet
     *  plain UTF-8), empty when the announce carried none. */
    char     name[RNSD_PEER_NAME_MAX];
    uint32_t heard;         /* device unix-seconds of the last announce */
    uint32_t announces;     /* announces heard from this peer since boot */
    uint8_t  hops;          /* 1 — a direct peer, by construction */
    /** Which node announced it, as an index into the node table, or -1 on a
     *  medium that cannot attribute a packet to a peer. */
    int16_t  node;
    bool     have_signal;   /* the medium measured the reception below */
    int16_t  rssi;          /* dBm */
    int16_t  snr10;         /* dB × 10 */
} rnsd_peer_t;

/** One node — the thing at the far end of an interface, or one of the peers
 *  under a multi-peer one. */
typedef struct {
    char     iface[RNSD_PEER_IFACE_MAX];
    /** Origin key, all-zero when the interface IS the node (point-to-point). */
    uint8_t  key[RNSD_NODE_KEY_LEN];
    /** Transport address in an operator's terms — a Bluetooth MAC, host:port,
     *  a link-local address. What the listing shows until an announce names it,
     *  and what identifies the node on a graph regardless. */
    char     label[RNSD_NODE_LABEL_MAX];
    /** It forwards for others: an announce more than one hop old arrived
     *  through it, which nothing but a transport node can produce. */
    bool     transport;
    uint32_t heard;         /* device unix-seconds of the last announce through it */
    uint16_t peers;         /* destinations it has announced */
} rnsd_node_t;

/** Walk the direct peers whose interface name starts with `iface_prefix`
 *  (`"lora"` every radio, `"tcp"` every connection in and out, `""` the lot),
 *  most recently heard first. Returns how many were visited. The callback runs
 *  on the caller's task against a private copy; it must not call back in. */
int rnsdPeersForEach(const char* iface_prefix,
                     void (*cb)(const rnsd_peer_t*, void*), void* ctx);

/** How many direct peers match `iface_prefix`. */
int rnsdPeersCount(const char* iface_prefix);

/** The same walk over NODES, in declaration order (which is the order they
 *  became reachable). Returns how many were visited. */
int rnsdNodesForEach(const char* iface_prefix,
                     void (*cb)(int idx, const rnsd_node_t*, void*), void* ctx);

/** How many nodes match `iface_prefix` — the count a status-line pill wants on
 *  a medium whose peers are nodes. */
int rnsdNodesCount(const char* iface_prefix);

/** Print the neighbourhood — the body of every interface's `n[eighbors]` verb,
 *  written once here so every medium answers in one format. `title` is what the
 *  medium is called in an operator's terms ("Bluetooth", "TCP"): the interface
 *  registrations under it are an implementation detail of the straddle, and a
 *  listing that named them would be reporting its own plumbing. */
void rnsdPeersPrint(const char* iface_prefix, const char* title, bool verbose);

/** The listing's row indent, shared so every medium's neighbourhood — this
 *  printer's and iface-lora's own richer one — lines up in the same columns.
 *  `RNSD_PEER_ROW_FMT` takes the node's number on its first line and "" on
 *  every continuation; `RNSD_PEER_ROW_PAD` is that column's width in spaces. */
#define RNSD_PEER_ROW_FMT "   %-5s"
#define RNSD_PEER_ROW_PAD "        "

/** True for `n`, `neighbors` or `neighbours` — so every interface's CLI spells
 *  the verb, and abbreviates it, identically. */
bool rnsdIsNeighborsVerb(const char* tok);

/** The whole `n[eighbors] [-v]` verb for one interface straddle's command:
 *  returns false if `args` is something else (the caller carries on), true once
 *  the listing has been printed. One line per interface CLI, so the media
 *  cannot drift apart in spelling, in flags, or in output. */
bool rnsdPeersCli(const char* args, const char* iface_prefix, const char* title);

/** The aspect behind an announce's name hash, or nullptr when rnsd does not
 *  know the name. A name hash is SHA-256(aspect)[:10] and therefore one-way;
 *  this is a lookup against the aspects this firmware speaks, nothing more. */
const char* rnsdAspectLabel(const uint8_t name_hash[RNSD_NAME_HASH_LEN]);

/** The display name an announce's app_data carries, or "" when it carries
 *  none. LXMF wraps the name in msgpack (behind the ratchet when present);
 *  NomadNet and older clients send raw UTF-8. Always NUL-terminates. */
void rnsdAnnounceName(const uint8_t* app_data, size_t n, char* out, size_t outsz);

/* ──────────────── what this node announces ────────────────
 *
 * The mirror of the neighbourhood above: not who is out there, but which
 * addresses THIS node has been heard announcing. A peer's report of a link
 * names the destination it heard, so joining that report to a node means
 * asking each node which destinations are its own — which is this walk. */

/** One destination this node hosts. */
typedef struct {
    uint8_t dest[RNSD_DEST_HASH_LEN];
    char    aspect[RNSD_PEER_ASPECT_MAX];  /* "lxmf.delivery", "rnstransport.probe" */
} rnsd_hosted_dest_t;

/** Walk every destination this node currently hosts — those opened through
 *  rnsdDestOpen plus rnsd's own transport probe where it is up. Returns how
 *  many were visited. The callback runs on the caller's task against a private
 *  copy, so this is safe from any task; it must not call back in. */
int rnsdHostedDestsForEach(void (*cb)(const rnsd_hosted_dest_t*, void*), void* ctx);

/* ──────────────── the routing table, as evidence ────────────────
 *
 * What the path table knows that the neighbourhood does not: nodes nobody has
 * told us about directly. A stock RNS node announces its destinations and
 * nothing else — no self-report, no record — so routing is the only evidence
 * it exists at all, and the only evidence of where it hangs off.
 *
 * The identity is the useful part. A destination is one address of a node; the
 * identity behind it is the node, and it is the same value a network-graph
 * record is originated by — so a routed destination can be matched to a node
 * that DOES speak for itself, or stood up as one that does not, without
 * guessing. */
typedef struct {
    uint8_t dest[RNSD_DEST_HASH_LEN];
    uint8_t identity[RNSD_IDENT_HASH_LEN];   /* valid iff have_identity */
    uint8_t via[RNSD_DEST_HASH_LEN];         /* next hop's transport id */
    char    iface[RNSD_PEER_IFACE_MAX];      /* the interface we would send on */
    /** The aspect in words where rnsd knows the name behind the hash
     *  ("rnstransport.probe"), empty where it does not.
     *
     *  WHAT KIND OF THING this address is, which the identity alone does not
     *  say. A device hosts several identities — its transport one, LXMF's, one
     *  per application — so "the identity behind a destination" is the owner of
     *  an ADDRESS and not the device. The aspect is what separates a node-level
     *  destination from an application's. */
    char    aspect[RNSD_PEER_ASPECT_MAX];
    /** When the announce that established this path was heard, and when the
     *  path stops being valid — device unix-seconds, both 0 where there is no
     *  route.
     *
     *  A PATH OUTLIVES THE THING THAT MADE IT. The table holds an entry for its
     *  full TTL whether or not the node at the far end is still there, still
     *  announcing, or still has that interface switched on. Without a date on
     *  it, "the path table says so" cannot tell a live neighbour from one that
     *  was here this morning. */
    uint32_t timestamp;
    uint32_t expires;
    uint8_t hops;
    bool    have_identity;                   /* the announce carried a usable key */
    bool    have_route;
} rnsd_dir_entry_t;

/** Walk every destination the directory holds — routed or not. Returns how many
 *  were visited. The callback runs on the caller's task against a private copy,
 *  so this is safe from any task; it must not call back in.
 *
 *  The identity is why this exists. Every other table in the system speaks in
 *  DESTINATIONS, and a destination is one address of a node rather than the
 *  node; this is the one place that says which node an address belongs to, for
 *  every address this device has ever heard. */
int rnsdDirForEach(void (*cb)(const rnsd_dir_entry_t*, void*), void* ctx);

/* ──────────────── status-line pills ────────────────
 *
 * One pill per interface CLASS in the top status line, on the display and in
 * the browser alike: a letter for the medium and how many peers are on it —
 * `L3` is three peers on LoRa. It appears the moment the class is enabled (at
 * `0`, which is a fact worth showing) and vanishes when it is switched off.
 *
 * The count is the straddle's OWN notion of a peer, not this node's neighbour
 * table: what a medium counts as a peer is a property of the medium — a LoRa
 * radio counts the nodes it hears, TCP counts connections in and out — and only
 * the straddle knows it.
 *
 * rnsd holds no table of media and no palette. It composes the text, and the
 * keys the two renderers read are all it owns:
 *
 *     rns.pill.<id>.text   "L3"      the finished pill; empty = no pill
 *     rns.pill.<id>.color  "ffd400"  rrggbb, the class's colour
 *     rns.pill.<id>.order  4         left-to-right placement
 *     rns.pill.<id>.title  "LoRa"    the medium in an operator's words
 */

/** Publish (or update) this class's pill. `id` is a short stable slug owned by
 *  the calling straddle (`"lora"`, `"tcp"`); `letter` and `count` compose the
 *  text; `color` is `"rrggbb"`; `order` places it among the others — use the
 *  straddle's own settings `order:` so the pills read left to right in the same
 *  sequence the Interfaces pane lists them. Safe from any task. */
void rnsdPillSet(const char* id, char letter, int count, const char* color, int order);

/** Take this class's pill down — the interface is disabled. */
void rnsdPillClear(const char* id);

/** Publish this class's colour, placement and title WITHOUT a pill. Call once
 *  from the straddle's onInit, with the same `color`/`order` its rnsdPillSet
 *  uses.
 *
 *  `title` is the medium as an OPERATOR says it — "LoRa", "TCP",
 *  "AutoInterface (LAN)" — for the legends and listings that name a medium
 *  rather than abbreviating it to a pill. The class slug is a program's word
 *  for the medium and reads like one; only the straddle knows the other. A
 *  static string, and empty where the slug is already the operator's word.
 *
 *  A pill is about this node: it appears when the medium is switched on here.
 *  A COLOUR is about the medium itself, and the network graph draws media this
 *  node does not run — a LoRa link between two other nodes is still a LoRa
 *  link, and rendering it grey because this node has no radio switched on says
 *  something false about the network. So the colour is published from the
 *  moment the straddle is staged and the pill still only from the moment the
 *  class is enabled; both renderers gate on `text`, which this never writes. */
void rnsdPillColor(const char* id, const char* color, int order, const char* title);

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

/** Open an outbound Reticulum **Channel** to a remote destination
 *  (RNSD_PORT_CHANNEL). Identical call shape and lifecycle to rnsdLinkOpen(),
 *  but the returned packet-mode ITS handle carries *reliable, in-order Channel
 *  messages*: each itsSend is one message that rnsd retransmits until the peer
 *  proves it, and each itsRecv is one message delivered exactly once in send
 *  order. rnsd owns the underlying Link internally and never exposes it — the
 *  consumer interacts only with the channel, exactly as it would a link today.
 *
 *  The connect accepts immediately; watch `rnsd.chan.<tag>.state` for the
 *  transition to "active"/"failed". Messages sent before the channel is active
 *  are buffered and flushed on establishment (bounded outbox; overflow sets
 *  `rnsd.chan.<tag>.last_error`). A message must fit the channel MDU (Link MDU
 *  minus 6) — oversize sends are rejected with `last_error`.
 *
 *  Each ITS message on the returned handle is framed `[msgtype:2 BE][payload]`:
 *  the 16-bit value is the Channel envelope's message type, so a consumer can
 *  speak a typed application protocol (rnsh, byte-identical to upstream
 *  Reticulum) — choosing the msgtype per send and seeing the peer's per recv.
 *  Opaque-bytes consumers just prefix RNS::Channel::MSGTYPE_RAW (0x0100). When
 *  `identity_key` is non-empty rnsd identifies the link to the remote once
 *  active, so a listener that gates on allowed initiator identities admits it.
 *
 *  `tag`, `aspect`, `identity_key`, `path_timeout_ms`, `link_timeout_ms`, `ref`
 *  and the callbacks all behave as in rnsdLinkOpen(). Returns the ITS handle
 *  (>= 0) on accept, or negative on immediate failure. */
int rnsdChannelOpen(const uint8_t dest_hash[RNSD_DEST_HASH_LEN],
                    const char*   aspect,
                    const char*   identity_key,
                    const char*   tag,
                    uint32_t      path_timeout_ms,
                    uint32_t      link_timeout_ms,
                    int           ref,
                    void (*on_recv)(int handle, size_t bytes_avail),
                    void (*on_disconnect)(int handle));

/** Like rnsdDestListenLinks(), but forwards a reliable **Channel** (obtained
 *  from the accepted inbound Link) to `target_port` instead of raw link
 *  packets. On each accepted inbound Link, rnsd opens its Channel and connects
 *  to (owning_task, target_port) with an `rnsd_link_incoming_t` payload; the
 *  handle then carries Channel messages both ways. Used by the rnsh server to
 *  accept incoming shell sessions. Returns true if the request was queued. */
bool rnsdDestListenChannels(int      dest_handle,
                            uint16_t target_port);

/** bz2-decompress `in_len` bytes at `in` into at most `max_out` bytes at `out`.
 *  For rnsh StreamData frames whose `compressed` bit is set (upstream peers
 *  bz2-compress chunks > 32 B); the chunk carries no uncompressed length, so
 *  the caller bounds the output (RawChannelWriter.MAX_CHUNK_LEN = 16384).
 *  Returns the decompressed length, or 0 on error / overflow. */
size_t rnsdBz2Decompress(const uint8_t* in, size_t in_len, uint8_t* out, size_t max_out);

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
 *  Returns true if the listen request was queued to rnsd (an in-band
 *  frame on `dest_handle`), false on bad args or a full ITS buffer. */
bool rnsdDestListenLinks(int      dest_handle,
                         uint16_t target_port);

/* ──────────────── Resource transfer ────────────────
 *
 * Messages larger than a single Link packet (~440 B encrypted) ride a
 * Reticulum Resource instead. The data path is NOT the packet-mode ITS
 * handle (which is KB-capped) — it is a shared-memory hand-off:
 *
 *  • Inbound: rnsd accepts the advertised Resource (size-gated by
 *    `s.lxmf.max_resource_size`, default 262144), reassembles it, then
 *    opens a one-shot ITS connection to the consumer's
 *    RNSD_LINK_RESOURCE_AUX_PORT with an `rnsd_link_resource_done_t`
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

/** Identify to the remote peer on the outbound Link `tag`, signing with the
 *  identity at `identity_key` (a storage path; "" → the identity the link was
 *  opened with, itself "" → rnsd's default). WHO a link says it is need not
 *  be whose link it is — µR signs the LINKIDENTIFY with whatever identity it
 *  is handed — which is how nomad browses on rnsd's identity and identifies
 *  as one of the LXMF ones. Upstream LXMF calls this "backchannel
 *  identification": after a delivery, the recipient learns which identity
 *  is on the link and can reuse it for reverse traffic instead of
 *  establishing its own Link back. Initiator-side links only (µR's
 *  Link::identify is a no-op otherwise); idempotence is the caller's job —
 *  each call sends one LINKIDENTIFY packet.
 *
 *  Callable the moment rnsdLinkOpen() returns: a link still awaiting a path
 *  or establishing holds the identify and runs it at establishment, ahead of
 *  a request deferred the same way — so a caller that identifies for the
 *  whole session (nomad's ID button) has the peer know who is asking before
 *  it answers the first request. On the receiving node, a
 *  validated LINKIDENTIFY publishes rnsd.links.<tag>.remote_identity
 *  (identity hash) and .remote_dest (the peer's destination hash on this
 *  link's aspect). Returns true if the aux was queued to rnsd. */
bool rnsdLinkIdentify(const char* tag, const char* identity_key = "");

/* ──────────────── request / response (nomad page fetch) ────────────────
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
 *  request-Resource are not yet implemented). One in-flight request per link.
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
