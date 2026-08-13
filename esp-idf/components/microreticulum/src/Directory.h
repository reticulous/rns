/*
 * Directory — one arena, three pools, replacing the identity cache and the
 * path table.
 *
 * The store is a flat arena of packed fixed-size records owned by whoever
 * drives Transport (here: the rnsd task), read lock-free by every other task,
 * and persisted as a raw image. It depends only on µR types and the platform
 * hook struct below — no filesystem, no allocator policy, no configuration
 * store, no logging beyond µR's own macros.
 *
 * Three pools, joined only by the destination hash. No pool stores an index
 * into another: a stored link would be a second expression of a relationship
 * the key already carries, and therefore a consistency obligation across a
 * lock-free reader and a raw persisted image.
 *
 *   guard      "I have seen this announce"    28 B   replay + recency
 *   directory  "I know who this is"          160 B   keys, names, routing
 *   blob       "I can answer for this"       320 B   the raw signed announce
 *
 * Eviction removes them in reverse order under pressure, so losing the ability
 * to serve a path request for a destination degrades before losing the ability
 * to say who it is.
 *
 * Concurrency: single writer, many readers. Only the directory pool is read
 * cross-task, and only it carries a sequence counter (§ rdirPeekEntry). Guard
 * and blob records are touched exclusively on the writer's task.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

/* ── sizes ─────────────────────────────────────────────────────────────── */

#define RDIR_DEST_LEN        16
#define RDIR_PUBKEY_LEN      64
#define RDIR_NAME_HASH_LEN   10
#define RDIR_BLOB_LEN        10   /* announce random blob */

#define RDIR_GUARD_SLOT_SZ   28
#define RDIR_DIR_SLOT_SZ    160
#define RDIR_BLOB_SLOT_DEF  320   /* default; tunable, carried in the image */

/* Slot counts are derived from a byte budget in fixed proportion 8:4:1
 * (guard : directory : blob). One "unit" of that proportion costs: */
#define RDIR_BUDGET_UNIT    (8 * RDIR_GUARD_SLOT_SZ + 4 * RDIR_DIR_SLOT_SZ + RDIR_BLOB_SLOT_DEF)

/* ── record flags (directory) ──────────────────────────────────────────── */

#define RDIR_F_USED    0x01   /* slot occupied */
#define RDIR_F_ROUTE   0x02   /* routing fields valid */
#define RDIR_F_EDGE    0x04   /* retained because the ingress interface is an
                               * edge we are custodian of (§ retain policy) */
#define RDIR_F_PUBKEY  0x08   /* public key present */

/* ── claims ────────────────────────────────────────────────────────────── */

/* A claim is a preference, not a lifetime. Retention is the maximum over all
 * claims on a record; the store arbitrates and may break any of them under
 * pressure. There is deliberately no expires_at — a duration reads as a
 * guarantee and is the first thing that has to break at 88% memory.
 *
 * The invariant that keeps this safe: an unbounded claim population may not
 * carry a long duration. Contacts are bounded by the address book, mesh
 * neighbours by the size of the mesh; internet announces are unbounded and
 * therefore carry no claim at all. */

enum {
    RDIR_CONSUMER_LXMF  = 0,
    RDIR_CONSUMER_NOMAD = 1,
    RDIR_CONSUMER_RNSH  = 2,
    RDIR_CONSUMER_RLPG  = 3,
    RDIR_CONSUMER_RNSD  = 4,
    RDIR_CONSUMER_COUNT = 8,      /* width of each per-consumer bit field */
};

enum { RDIR_CLASS_EPHEMERAL = 0, RDIR_CLASS_PERSIST = 1 };

/* Layer bits, shared by rdir_claim_t::layers and rdirIngest()'s `layers`. */
#define RDIR_LAYER_DIR       0x01
#define RDIR_LAYER_BLOB      0x02
#define RDIR_LAYER_DIR_BLOB  (RDIR_LAYER_DIR | RDIR_LAYER_BLOB)

/* Layout of the record's 32-bit claim mask. Per-consumer bit fields so
 * rdirClaimDrop can clear one consumer without consulting the others. */
#define RDIR_CLAIM_PRESENT_SHIFT   0    /* bits  0..7  consumer holds a claim */
#define RDIR_CLAIM_PERSIST_SHIFT   8    /* bits  8..15 that claim is PERSIST  */
#define RDIR_CLAIM_BLOB_SHIFT     16    /* bits 16..23 that claim wants a blob */
#define RDIR_CLAIM_PRESENT_MASK   (0xFFu << RDIR_CLAIM_PRESENT_SHIFT)
#define RDIR_CLAIM_PERSIST_MASK   (0xFFu << RDIR_CLAIM_PERSIST_SHIFT)
#define RDIR_CLAIM_BLOB_MASK      (0xFFu << RDIR_CLAIM_BLOB_SHIFT)
/* Reserved now so adding it later doesn't force a format_ver bump and a
 * discarded arena — on a gateway, at exactly the moment an empty directory
 * hurts most. Set when we have advertised a destination onto a mesh and are
 * therefore obliged to answer path requests for it. */
#define RDIR_CLAIM_ANSWER_FOR     (1u << 24)

typedef struct {
    uint8_t  consumer;   /* RDIR_CONSUMER_*                       */
    uint8_t  klass;      /* RDIR_CLASS_PERSIST | _EPHEMERAL       */
    uint8_t  layers;     /* RDIR_LAYER_DIR | RDIR_LAYER_DIR_BLOB  */
    uint32_t decay_s;    /* ordering scale since last touch; 0 = store default */
} rdir_claim_t;

/* ── eviction categories, first evicted → last ─────────────────────────── */

enum {
    RDIR_CAT_GUARD_ONLY  = 1,   /* guard pool only, ordered by local_age    */
    RDIR_CAT_UNCLAIMED   = 2,   /* no claim, no live route; by last_heard   */
    RDIR_CAT_EPH_LAPSED  = 3,   /* ephemeral claim past decay; claim_touch  */
    RDIR_CAT_EPH_LIVE    = 4,   /* ephemeral claim, live;     claim_touch   */
    RDIR_CAT_EDGE        = 5,   /* interface-retained, unclaimed; last_heard */
    RDIR_CAT_PERSIST     = 6,   /* persist claims;            claim_touch   */
    RDIR_CAT_IN_USE      = 7,   /* route used recently;       last_used     */
    RDIR_CAT_COUNT       = 8,
};

/* ── copy-out views ────────────────────────────────────────────────────── */

typedef struct {
    uint8_t  received_from[RDIR_DEST_LEN];   /* next-hop transport id */
    uint8_t  iface_hash[RDIR_DEST_LEN];      /* receiving interface   */
    uint8_t  hops;
    uint32_t expires;       /* Unix seconds */
    uint32_t last_used;
    uint32_t timestamp;     /* announce time */
} rdir_route_t;

typedef struct {
    uint8_t  dest[RDIR_DEST_LEN];
    uint8_t  pubkey[RDIR_PUBKEY_LEN];
    uint8_t  name_hash[RDIR_NAME_HASH_LEN];
    uint32_t last_heard;
    uint32_t claims;
    uint32_t claim_touch;
    uint8_t  hops;
    uint8_t  flags;
    uint8_t  prio;
    bool     has_pubkey;
    bool     has_route;
    rdir_route_t route;
} rdir_entry_t;

/* What rdirIngest stores. Pointers are borrowed for the duration of the call;
 * the store copies everything it keeps. */
typedef struct {
    const uint8_t* pubkey;          /* RDIR_PUBKEY_LEN,    may be null */
    const uint8_t* name_hash;       /* RDIR_NAME_HASH_LEN, may be null */
    const uint8_t* received_from;   /* RDIR_DEST_LEN,      may be null */
    const uint8_t* iface_hash;      /* RDIR_DEST_LEN,      may be null */
    const uint8_t* raw;             /* announce packet as received     */
    uint16_t raw_len;
    uint8_t  hops;
    bool     edge;                  /* ingress interface retains on announce */
    /* We are this destination's custodian: it is reachable via an interface
     * whose policy says we route for it, so we are obliged to answer path
     * requests for it and must not let churn we merely overhear evict it. */
    bool     answer_for;
    uint32_t timestamp;             /* announce time, Unix seconds */
    uint32_t expires;               /* Unix seconds */
} rdir_announce_t;

/* ── counters ──────────────────────────────────────────────────────────── */

typedef struct {
    uint32_t guard_drop_fp;        /* suppressed: random blob already seen   */
    uint32_t guard_drop_emitted;   /* suppressed: emission ordering          */
    uint32_t guard_bypass;         /* path-response bypass taken             */
    uint32_t guard_resets;         /* collision heuristic reset an entry     */
    uint32_t evict_guard;
    uint32_t evict_dir[RDIR_CAT_COUNT];   /* indexed by RDIR_CAT_*           */
    uint32_t evict_blob;
    uint32_t recall_miss;          /* pubkey asked for, not held             */
    uint32_t seq_retries;          /* reader lost a race with the writer     */
    uint32_t snapshots;
} rdir_stats_t;

/* ── platform hooks ────────────────────────────────────────────────────── */

/* The only things the store may not do for itself. Writing the image is NOT a
 * hook: the embedder calls rdirSnapshot and owns the file. */
typedef struct {
    /* Called exactly once, from rdirInit. */
    void* (*arena_alloc)(size_t);
    /* Boot only. Fill `buf` with the persisted image; *len is the buffer
     * capacity on entry and the image length on return. Return false (or
     * report zero) when there is no image. May be null. */
    bool  (*image_load)(void* buf, size_t* len);
    /* Coarse local clock in wrapping minutes — the basis for guard aging and
     * eviction ordering. Nothing else in a guard record is on our clock:
     * `emitted` is originator-time and only comparable within one
     * destination. */
    uint16_t (*local_minutes)(void);
} rdir_platform_t;

/* Build the arena and, if a hook is supplied, load the persisted image over
 * it. `byte_budget` is split across the pools in fixed proportion; slot counts
 * land in the image header. Returns false if allocation failed. */
bool   rdirInit(const rdir_platform_t* platform, size_t byte_budget);
bool   rdirReady(void);

/* Blob slot size, in bytes. Must be set before rdirInit; changing it discards
 * a loaded image (it is a structural property, carried in the header). */
void   rdirSetBlobSlotSize(size_t bytes);

/* ── readers — any task ────────────────────────────────────────────────── */

bool   rdirPeekRoute (const uint8_t dest[RDIR_DEST_LEN], rdir_route_t* out);
bool   rdirPeekPubkey(const uint8_t dest[RDIR_DEST_LEN], uint8_t out[RDIR_PUBKEY_LEN]);
bool   rdirPeekEntry (const uint8_t dest[RDIR_DEST_LEN], rdir_entry_t* out);
bool   rdirHasClaim  (const uint8_t dest[RDIR_DEST_LEN]);
bool   rdirInUse     (const uint8_t dest[RDIR_DEST_LEN]);
/* 0 = no blob held. Copies at most `cap` bytes. */
size_t rdirCopyBlob  (const uint8_t dest[RDIR_DEST_LEN], uint8_t* buf, size_t cap);
/* Walks occupied directory slots, handing each a stable copy. The callback
 * runs with no lock held and must not call back into the store. */
void   rdirForEach   (void (*cb)(const rdir_entry_t*, void*), void* ctx);

size_t rdirCount(void);        /* occupied directory slots  */
size_t rdirSlots(void);
size_t rdirGuardCount(void);
size_t rdirGuardSlots(void);
size_t rdirBlobCount(void);
size_t rdirBlobSlots(void);
size_t rdirBlobSlotSize(void);
size_t rdirArenaBytes(void);   /* the three pools, without the image header */
size_t rdirImageBytes(void);   /* a full snapshot of what is held right now */
void   rdirGetStats(rdir_stats_t* out);

/* Bumped by every write that changes directory or blob content — the signal a
 * debouncing embedder watches to decide whether an image is worth rewriting.
 * Guard-pool updates deliberately do NOT bump it: they happen on every
 * announce a busy node hears, and losing them costs at most one duplicate
 * forward, which is not worth a flash write per minute. */
uint32_t rdirGeneration(void);

/* ── writer — the task that drives Transport ───────────────────────────── */

/* Replay and recency suppression for every destination whose announce we have
 * validated, whether or not we retain anything else about it. Returns true if
 * the announce is novel enough to act on (forward, retransmit).
 *
 * `bypass` skips the fingerprint check while still updating the ring and
 * `emitted`: a requested PATH_RESPONSE is answered by a relay from its cached
 * announce and therefore always carries an already-seen blob. Treating it as a
 * replay makes path discovery work exactly once and then go silent. */
bool   rdirGuardFresh(const uint8_t dest[RDIR_DEST_LEN],
                      const uint8_t blob[RDIR_BLOB_LEN],
                      uint32_t emitted, bool bypass);

/* Store (or refresh) what we know about a destination, at the requested
 * layers. Silently degrades: a full pool means the weaker layer only. */
void   rdirIngest    (const uint8_t dest[RDIR_DEST_LEN],
                      const rdir_announce_t* announce, uint8_t layers);

/* Stamp outbound use, and slide the route's expiry out to `expires` (Unix
 * seconds; 0 leaves it alone). A path carrying traffic must not age out from
 * under it just because nobody has re-announced lately — the whole point of
 * tracking use is that use is evidence the route is good. */
void   rdirTouchUsed (const uint8_t dest[RDIR_DEST_LEN], uint32_t expires);
/* Drop the routing layer, keeping identity. This is what "forget the path"
 * means once the two tables are one record. */
bool   rdirClearRoute(const uint8_t dest[RDIR_DEST_LEN]);
/* Drop the whole record (and its blob). */
bool   rdirForget    (const uint8_t dest[RDIR_DEST_LEN]);

void   rdirClaim     (const uint8_t dest[RDIR_DEST_LEN], const rdir_claim_t*);
void   rdirClaimTouch(const uint8_t dest[RDIR_DEST_LEN], uint8_t consumer);
void   rdirClaimDrop (const uint8_t dest[RDIR_DEST_LEN], uint8_t consumer);
/* Seed a key learned out of band (not from an announce) — creates a
 * directory-only record if none exists. */
void   rdirSeedPubkey(const uint8_t dest[RDIR_DEST_LEN], const uint8_t pk[RDIR_PUBKEY_LEN]);

/* Evict until each pool is at or below the given occupied-slot target. */
void   rdirEvictTo   (size_t dir_target, size_t blob_target);

/* Write the live set into a caller-owned buffer on the writer's task —
 * consistent by construction, no lock. Records go out in eviction order, most
 * valuable last-to-go first, so `cap` is a real budget and not a failure
 * condition: a buffer smaller than rdirImageBytes() persists the top of the
 * store and drops the tail the store would drop next anyway. The guard pool
 * is never written (its clock does not survive a boot). Returns bytes
 * written, 0 only if `cap` cannot hold the header. */
size_t rdirSnapshot  (void* buf, size_t cap);
