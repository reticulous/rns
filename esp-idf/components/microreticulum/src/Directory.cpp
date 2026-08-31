/*
 * Directory — see Directory.h for the model. This file is the whole store:
 * three flat pools in one arena, a seqlock on the directory pool, in-record
 * eviction, and the raw image format.
 *
 * Rules this file keeps, deliberately:
 *   - no allocation after rdirInit (one arena, from the platform hook);
 *   - no locking — a single writer task, seqlocked readers;
 *   - no pointer into the arena ever escapes; every reader copies out;
 *   - no dependency outside µR's own types and the platform hook struct.
 */

#include "Directory.h"

#include "Log.h"
#include "Type.h"
#include "Utilities/OS.h"

#include <string.h>
#include <stddef.h>

/* ── on-arena record layouts ───────────────────────────────────────────── */

#pragma pack(push, 1)

typedef struct {
    uint32_t dest4;       /* truncated destination hash, big-endian first 4 B */
    uint32_t emitted;     /* announce emission time from the random hash, s   */
    uint16_t local_age;   /* coarse local time (wrapping minutes) at update   */
    uint8_t  fp[16];      /* 4 x 4-byte random-blob fingerprints, ring        */
    uint8_t  cursor;      /* ring write position (bits 0-1) + count (bits 2-4)*/
    uint8_t  flags;       /* bit0 in-use; bits 1-2 suppression run; rest zero */
} rdir_guard_rec_t;

typedef struct {
    uint8_t  dest[RDIR_DEST_LEN];
    uint8_t  pubkey[RDIR_PUBKEY_LEN];
    uint8_t  name_hash[RDIR_NAME_HASH_LEN];
    uint32_t last_heard;
    uint8_t  hops;
    uint8_t  flags;
    uint32_t claims;
    uint8_t  received_from[RDIR_DEST_LEN];
    uint8_t  iface_hash[RDIR_DEST_LEN];
    uint32_t expires;
    uint32_t last_used;
    uint32_t timestamp;
    uint16_t seq;
    uint8_t  prio;
    uint8_t  pad;
    uint32_t claim_touch;
    uint32_t claim_decay;   /* carved from the reserve; 0 = store default */
    uint8_t  reserved[4];
} rdir_dir_rec_t;

/* The image carries live records, not the arena: counts, not slot geometry.
 * A node that knows twelve destinations writes twelve records whatever its
 * pools are sized at, and an image made on one budget loads on another. The
 * guard pool is not in it at all (see rdirSnapshot). */
typedef struct {
    char     magic[4];
    uint16_t format_ver;    /* structural; mismatch discards the whole image */
    uint16_t feature_ver;   /* additive; lower is accepted, unknown fields 0 */
    uint16_t dir_slot_sz;
    uint16_t dir_count;     /* directory records following the header */
    uint16_t blob_slot_sz;
    uint16_t blob_count;    /* blob slots following those */
} rdir_img_hdr_t;

#pragma pack(pop)

/* Reserved bytes give a false sense of layout safety while the compiler can
 * still pad elsewhere, so assert the offset of every named field, not just the
 * record size. */
static_assert(sizeof(rdir_guard_rec_t) == RDIR_GUARD_SLOT_SZ, "guard record size");
static_assert(offsetof(rdir_guard_rec_t, dest4)     ==  0, "guard dest4");
static_assert(offsetof(rdir_guard_rec_t, emitted)   ==  4, "guard emitted");
static_assert(offsetof(rdir_guard_rec_t, local_age) ==  8, "guard local_age");
static_assert(offsetof(rdir_guard_rec_t, fp)        == 10, "guard fp");
static_assert(offsetof(rdir_guard_rec_t, cursor)    == 26, "guard cursor");
static_assert(offsetof(rdir_guard_rec_t, flags)     == 27, "guard flags");

static_assert(sizeof(rdir_dir_rec_t) == RDIR_DIR_SLOT_SZ, "directory record size");
static_assert(offsetof(rdir_dir_rec_t, dest)          ==   0, "dir dest");
static_assert(offsetof(rdir_dir_rec_t, pubkey)        ==  16, "dir pubkey");
static_assert(offsetof(rdir_dir_rec_t, name_hash)     ==  80, "dir name_hash");
static_assert(offsetof(rdir_dir_rec_t, last_heard)    ==  90, "dir last_heard");
static_assert(offsetof(rdir_dir_rec_t, hops)          ==  94, "dir hops");
static_assert(offsetof(rdir_dir_rec_t, flags)         ==  95, "dir flags");
static_assert(offsetof(rdir_dir_rec_t, claims)        ==  96, "dir claims");
static_assert(offsetof(rdir_dir_rec_t, received_from) == 100, "dir received_from");
static_assert(offsetof(rdir_dir_rec_t, iface_hash)    == 116, "dir iface_hash");
static_assert(offsetof(rdir_dir_rec_t, expires)       == 132, "dir expires");
static_assert(offsetof(rdir_dir_rec_t, last_used)     == 136, "dir last_used");
static_assert(offsetof(rdir_dir_rec_t, timestamp)     == 140, "dir timestamp");
static_assert(offsetof(rdir_dir_rec_t, seq)           == 144, "dir seq");
static_assert(offsetof(rdir_dir_rec_t, prio)          == 146, "dir prio");
static_assert(offsetof(rdir_dir_rec_t, claim_touch)   == 148, "dir claim_touch");
static_assert(offsetof(rdir_dir_rec_t, claim_decay)   == 152, "dir claim_decay");
/* seq is loaded and stored atomically, so it must be naturally aligned. That
 * holds because its offset is a multiple of 4, both preceding pools are whole
 * multiples of 4 bytes, and the arena itself comes back 4-aligned. */
static_assert(offsetof(rdir_dir_rec_t, seq) % 4 == 0, "seq alignment");
static_assert(RDIR_GUARD_SLOT_SZ % 4 == 0, "guard pool stride alignment");
static_assert(RDIR_DIR_SLOT_SZ % 4 == 0, "directory pool stride alignment");

static_assert(sizeof(rdir_img_hdr_t) == 16, "image header size");

/* Blob slot: a 20-byte prefix then the raw announce. The slot size is a
 * tunable, so the pool is addressed by offset rather than by a struct. */
#define RDIR_BLOB_OFF_DEST   0
#define RDIR_BLOB_OFF_LEN    16
#define RDIR_BLOB_OFF_FLAGS  18
#define RDIR_BLOB_OFF_RAW    20
#define RDIR_BLOB_PREFIX     20

#define RDIR_FORMAT_VER   2
#define RDIR_FEATURE_VER  1

/* Guard record flag bits beyond in-use. Zero must stay the safe,
 * legacy-equivalent meaning of anything carved out of the reserve: a
 * suppression run of zero is exactly what an older image means. */
#define RDIR_G_USED         0x01
#define RDIR_G_RUN_SHIFT    1
#define RDIR_G_RUN_MASK     0x06
#define RDIR_G_RUN_LIMIT    2      /* consecutive suppressions before reset */

/* Ephemeral claims with no explicit decay lapse after this long untouched. */
#define RDIR_DEFAULT_DECAY_S  (24 * 60 * 60)

/* A reader that loses this many races with the writer gives up and reports a
 * miss. The writer's critical sections are a few dozen bytes of memcpy, so
 * losing twice already means something pathological. */
#define RDIR_SEQ_TRIES  8

/* ── arena ─────────────────────────────────────────────────────────────── */

static rdir_platform_t s_plat;
static bool     s_ready       = false;
static uint8_t* s_arena       = nullptr;
static size_t   s_alloc_bytes = 0;

static rdir_guard_rec_t* s_guard = nullptr;
static rdir_dir_rec_t*   s_dir   = nullptr;
static uint8_t*          s_blob  = nullptr;

static uint16_t s_guard_slots = 0;
static uint16_t s_dir_slots   = 0;
static uint16_t s_blob_slots  = 0;
static uint16_t s_blob_slot_sz = RDIR_BLOB_SLOT_DEF;

static rdir_stats_t s_stats;
static uint32_t s_generation = 0;

static inline size_t guardBytes() { return (size_t)s_guard_slots * RDIR_GUARD_SLOT_SZ; }
static inline size_t dirBytes()   { return (size_t)s_dir_slots   * RDIR_DIR_SLOT_SZ; }
static inline size_t blobBytes()  { return (size_t)s_blob_slots  * s_blob_slot_sz; }

static inline uint8_t* blobSlot(uint16_t i) { return s_blob + (size_t)i * s_blob_slot_sz; }
static inline uint16_t blobLen(const uint8_t* slot) {
    uint16_t v; memcpy(&v, slot + RDIR_BLOB_OFF_LEN, 2); return v;
}
static inline uint16_t blobFlags(const uint8_t* slot) {
    uint16_t v; memcpy(&v, slot + RDIR_BLOB_OFF_FLAGS, 2); return v;
}
static inline bool blobUsed(const uint8_t* slot) { return (blobFlags(slot) & 1) != 0; }

static inline uint32_t nowUnix() { return (uint32_t)RNS::Utilities::OS::time(); }
static inline uint16_t nowMinutes() {
    return s_plat.local_minutes ? s_plat.local_minutes() : (uint16_t)(nowUnix() / 60);
}

/* ── seqlock ───────────────────────────────────────────────────────────── */

static inline volatile uint16_t* seqPtr(const rdir_dir_rec_t* rec) {
    return (volatile uint16_t*)((uint8_t*)rec + offsetof(rdir_dir_rec_t, seq));
}
/* Writer: odd while the payload is in flux, even when it is coherent. The
 * closing store is a release so neither the compiler nor the other core can
 * sink a payload write past it. */
static inline void writeBegin(rdir_dir_rec_t* rec) {
    volatile uint16_t* p = seqPtr(rec);
    uint16_t s = __atomic_load_n(p, __ATOMIC_RELAXED);
    __atomic_store_n(p, (uint16_t)(s | 1u), __ATOMIC_RELEASE);
}
static inline void writeEnd(rdir_dir_rec_t* rec) {
    volatile uint16_t* p = seqPtr(rec);
    uint16_t s = __atomic_load_n(p, __ATOMIC_RELAXED);
    __atomic_store_n(p, (uint16_t)((s + 1u) & ~1u), __ATOMIC_RELEASE);
    s_generation++;
}

/* Wipe a record's payload while leaving its sequence counter alone. A counter
 * that restarted at zero on reuse could match a value a reader captured before
 * the reuse, and that reader would accept a torn record. Call between
 * writeBegin and writeEnd. */
static void recClear(rdir_dir_rec_t* r) {
    uint16_t s = *seqPtr(r);
    memset(r, 0, sizeof(*r));
    *seqPtr(r) = s;
}

/* Reader: copy the record out and re-check the counter. Slots never relocate,
 * and eviction marks a slot free without compaction, so a reader racing a
 * reuse retries rather than tearing. */
static bool recCopy(const rdir_dir_rec_t* rec, rdir_dir_rec_t* out) {
    volatile uint16_t* p = seqPtr(rec);
    for (int i = 0; i < RDIR_SEQ_TRIES; i++) {
        uint16_t s1 = __atomic_load_n(p, __ATOMIC_ACQUIRE);
        if (s1 & 1u) { s_stats.seq_retries++; continue; }
        memcpy(out, rec, sizeof(*out));
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        uint16_t s2 = __atomic_load_n(p, __ATOMIC_RELAXED);
        if (s1 == s2) return true;
        s_stats.seq_retries++;
    }
    return false;
}

/* ── lookup ────────────────────────────────────────────────────────────── */

static rdir_dir_rec_t* dirFind(const uint8_t dest[RDIR_DEST_LEN]) {
    for (uint16_t i = 0; i < s_dir_slots; i++) {
        rdir_dir_rec_t* r = &s_dir[i];
        if (!(r->flags & RDIR_F_USED)) continue;
        if (memcmp(r->dest, dest, RDIR_DEST_LEN) == 0) return r;
    }
    return nullptr;
}

/* Reader-side lookup: the scan itself is racy (a slot can be reused while we
 * walk), so the candidate is confirmed inside the seqlocked copy. */
static bool dirLookup(const uint8_t dest[RDIR_DEST_LEN], rdir_dir_rec_t* out) {
    if (!s_ready) return false;
    for (uint16_t i = 0; i < s_dir_slots; i++) {
        const rdir_dir_rec_t* r = &s_dir[i];
        if (!(r->flags & RDIR_F_USED)) continue;
        if (memcmp(r->dest, dest, RDIR_DEST_LEN) != 0) continue;
        if (!recCopy(r, out)) return false;
        if (!(out->flags & RDIR_F_USED)) return false;
        if (memcmp(out->dest, dest, RDIR_DEST_LEN) != 0) return false;
        return true;
    }
    return false;
}

static uint8_t* blobFind(const uint8_t dest[RDIR_DEST_LEN]) {
    for (uint16_t i = 0; i < s_blob_slots; i++) {
        uint8_t* slot = blobSlot(i);
        if (!blobUsed(slot)) continue;
        if (memcmp(slot + RDIR_BLOB_OFF_DEST, dest, RDIR_DEST_LEN) == 0) return slot;
    }
    return nullptr;
}

static rdir_guard_rec_t* guardFind(uint32_t dest4) {
    for (uint16_t i = 0; i < s_guard_slots; i++) {
        rdir_guard_rec_t* g = &s_guard[i];
        if (!(g->flags & RDIR_G_USED)) continue;
        if (g->dest4 == dest4) return g;
    }
    return nullptr;
}

/* ── eviction ──────────────────────────────────────────────────────────── */

/* The claim vocabulary is compiled into `prio` at assert time; this is the
 * static class it compiles to. Eviction reads only in-record data, which is
 * what keeps the store portable while the vocabulary stays outside it. */
static uint8_t dirStaticPrio(const rdir_dir_rec_t* r) {
    /* An obligation we took on outranks anything we merely heard. Without
     * this, a gateway's own segment competes on equal terms with a large
     * network's announce churn for the same slots — and loses, continuously,
     * because the churn is what keeps arriving. */
    if (r->claims & RDIR_CLAIM_ANSWER_FOR) return RDIR_CAT_PERSIST;
    if (r->claims & RDIR_CLAIM_PRESENT_MASK)
        return (r->claims & RDIR_CLAIM_PERSIST_MASK) ? RDIR_CAT_PERSIST
                                                     : RDIR_CAT_EPH_LIVE;
    if (r->flags & RDIR_F_EDGE) return RDIR_CAT_EDGE;
    return RDIR_CAT_UNCLAIMED;
}

/* The two time-dependent promotions on top of the compiled class: an
 * ephemeral claim lapses, and a route in active use outranks everything. */
static uint8_t dirCategory(const rdir_dir_rec_t* r, uint32_t now) {
    uint8_t cat = r->prio ? r->prio : dirStaticPrio(r);
    if (cat == RDIR_CAT_EPH_LIVE) {
        uint32_t decay = r->claim_decay ? r->claim_decay : RDIR_DEFAULT_DECAY_S;
        if ((uint32_t)(now - r->claim_touch) > decay) cat = RDIR_CAT_EPH_LAPSED;
    }
    if ((r->flags & RDIR_F_ROUTE) && r->last_used &&
        (uint32_t)(now - r->last_used) < RNS::Type::Transport::PATH_LAST_USED_STALE)
        cat = RDIR_CAT_IN_USE;
    return cat;
}

/* Ordering within a category: recency of whatever made the record worth
 * keeping. Oldest goes first. */
static uint32_t dirOrder(const rdir_dir_rec_t* r, uint8_t cat) {
    switch (cat) {
        case RDIR_CAT_IN_USE:     return r->last_used;
        case RDIR_CAT_EPH_LAPSED:
        case RDIR_CAT_EPH_LIVE:
            return r->claim_touch;
        case RDIR_CAT_PERSIST:
            /* Custody alone carries no claim_touch — nothing consumer-side
             * ever touched it — so rank those by when we last heard from the
             * node instead of by a zero that would sort them all oldest. */
            return (r->claims & RDIR_CLAIM_PRESENT_MASK) ? r->claim_touch : r->last_heard;
        default:                  return r->last_heard;
    }
}

static size_t dirUsed() {
    size_t n = 0;
    for (uint16_t i = 0; i < s_dir_slots; i++)
        if (s_dir[i].flags & RDIR_F_USED) n++;
    return n;
}

static size_t blobUsedCount() {
    size_t n = 0;
    for (uint16_t i = 0; i < s_blob_slots; i++)
        if (blobUsed(blobSlot(i))) n++;
    return n;
}

static void blobFree(uint8_t* slot) {
    memset(slot, 0, s_blob_slot_sz);
    s_generation++;
}

/* Select-min instead of building a sort index: the store allocates nothing
 * after init, and at these pool sizes a linear pass per eviction is cheaper
 * than the vector it would replace. Usually one record goes per announce. */
static bool evictOneDir(uint32_t now) {
    rdir_dir_rec_t* victim = nullptr;
    uint8_t  vcat = 0xFF;
    uint32_t vord = 0;
    for (uint16_t i = 0; i < s_dir_slots; i++) {
        rdir_dir_rec_t* r = &s_dir[i];
        if (!(r->flags & RDIR_F_USED)) continue;
        uint8_t  cat = dirCategory(r, now);
        uint32_t ord = dirOrder(r, cat);
        if (!victim || cat < vcat || (cat == vcat && ord < vord)) {
            victim = r; vcat = cat; vord = ord;
        }
    }
    if (!victim) return false;
    uint8_t* blob = blobFind(victim->dest);
    if (blob) { blobFree(blob); s_stats.evict_blob++; }
    writeBegin(victim);
    recClear(victim);
    writeEnd(victim);
    if (vcat < RDIR_CAT_COUNT) s_stats.evict_dir[vcat]++;
    return true;
}

/* Blob slots free in the same category order among blob-holding records:
 * dropping a blob demotes "can answer" to "know who", it never touches the
 * directory entry. A blob with no directory record behind it goes first. */
static bool evictOneBlob(uint32_t now) {
    uint8_t* victim = nullptr;
    uint8_t  vcat = 0xFF;
    uint32_t vord = 0;
    for (uint16_t i = 0; i < s_blob_slots; i++) {
        uint8_t* slot = blobSlot(i);
        if (!blobUsed(slot)) continue;
        const rdir_dir_rec_t* r = dirFind(slot + RDIR_BLOB_OFF_DEST);
        uint8_t  cat = r ? dirCategory(r, now) : 0;
        uint32_t ord = r ? dirOrder(r, cat) : 0;
        if (!victim || cat < vcat || (cat == vcat && ord < vord)) {
            victim = slot; vcat = cat; vord = ord;
        }
    }
    if (!victim) return false;
    blobFree(victim);
    s_stats.evict_blob++;
    return true;
}

void rdirEvictTo(size_t dir_target, size_t blob_target) {
    if (!s_ready) return;
    uint32_t now = nowUnix();
    size_t n = dirUsed();
    while (n > dir_target && evictOneDir(now)) n--;
    n = blobUsedCount();
    while (n > blob_target && evictOneBlob(now)) n--;
}

static rdir_dir_rec_t* dirAlloc(const uint8_t dest[RDIR_DEST_LEN]) {
    for (uint16_t i = 0; i < s_dir_slots; i++)
        if (!(s_dir[i].flags & RDIR_F_USED)) return &s_dir[i];
    if (!evictOneDir(nowUnix())) return nullptr;
    for (uint16_t i = 0; i < s_dir_slots; i++)
        if (!(s_dir[i].flags & RDIR_F_USED)) return &s_dir[i];
    (void)dest;
    return nullptr;
}

static uint8_t* blobAlloc(void) {
    for (uint16_t i = 0; i < s_blob_slots; i++) {
        uint8_t* slot = blobSlot(i);
        if (!blobUsed(slot)) return slot;
    }
    if (!evictOneBlob(nowUnix())) return nullptr;
    for (uint16_t i = 0; i < s_blob_slots; i++) {
        uint8_t* slot = blobSlot(i);
        if (!blobUsed(slot)) return slot;
    }
    return nullptr;
}

/* Guard eviction is by local_age alone — the pool is sized by the announce
 * traffic we are exposed to, not by what we care about, and losing an entry
 * costs at most one duplicate forward. */
static rdir_guard_rec_t* guardAlloc(uint32_t dest4) {
    rdir_guard_rec_t* pick = nullptr;
    uint16_t oldest = 0;
    uint16_t now = nowMinutes();
    for (uint16_t i = 0; i < s_guard_slots; i++) {
        rdir_guard_rec_t* g = &s_guard[i];
        if (!(g->flags & RDIR_G_USED)) { pick = g; oldest = 0xFFFF; break; }
        uint16_t age = (uint16_t)(now - g->local_age);
        if (!pick || age > oldest) { pick = g; oldest = age; }
    }
    if (!pick) return nullptr;
    if (pick->flags & RDIR_G_USED) s_stats.evict_guard++;
    memset(pick, 0, sizeof(*pick));
    pick->dest4 = dest4;
    pick->flags = RDIR_G_USED;
    return pick;
}

/* ── guard ─────────────────────────────────────────────────────────────── */

static inline uint32_t dest4Of(const uint8_t dest[RDIR_DEST_LEN]) {
    return ((uint32_t)dest[0] << 24) | ((uint32_t)dest[1] << 16) |
           ((uint32_t)dest[2] << 8)  |  (uint32_t)dest[3];
}

/* The first four bytes of the random blob; bytes 5..9 are the emission
 * timebase and carry no entropy worth fingerprinting. */
static inline void fingerprint(const uint8_t blob[RDIR_BLOB_LEN], uint8_t out[4]) {
    memcpy(out, blob, 4);
}

static bool ringHas(const rdir_guard_rec_t* g, const uint8_t fp[4]) {
    uint8_t count = (uint8_t)((g->cursor >> 2) & 0x07);
    if (count > 4) count = 4;
    for (uint8_t i = 0; i < count; i++)
        if (memcmp(&g->fp[i * 4], fp, 4) == 0) return true;
    return false;
}

static void ringPush(rdir_guard_rec_t* g, const uint8_t fp[4]) {
    uint8_t pos   = (uint8_t)(g->cursor & 0x03);
    uint8_t count = (uint8_t)((g->cursor >> 2) & 0x07);
    memcpy(&g->fp[pos * 4], fp, 4);
    pos = (uint8_t)((pos + 1) & 0x03);
    if (count < 4) count++;
    g->cursor = (uint8_t)(pos | (count << 2));
}

static inline uint8_t runOf(const rdir_guard_rec_t* g) {
    return (uint8_t)((g->flags & RDIR_G_RUN_MASK) >> RDIR_G_RUN_SHIFT);
}
static inline void runSet(rdir_guard_rec_t* g, uint8_t v) {
    g->flags = (uint8_t)((g->flags & ~RDIR_G_RUN_MASK) |
                         ((v & 0x03) << RDIR_G_RUN_SHIFT));
}

bool rdirGuardFresh(const uint8_t dest[RDIR_DEST_LEN], const uint8_t blob[RDIR_BLOB_LEN],
                    uint32_t emitted, bool bypass)
{
    /* Fail open: with no store, every announce is novel — the old behaviour. */
    if (!s_ready || s_guard_slots == 0) return true;

    uint8_t fp[4];
    fingerprint(blob, fp);
    uint32_t d4 = dest4Of(dest);
    uint16_t now = nowMinutes();

    rdir_guard_rec_t* g = guardFind(d4);
    if (!g) {
        g = guardAlloc(d4);
        if (!g) return true;
        g->emitted   = emitted;
        g->local_age = now;
        ringPush(g, fp);
        return true;
    }

    bool seen = ringHas(g, fp);

    if (bypass) {
        /* A requested path response is answered by a relay from its cached
         * announce, so its blob is necessarily one we have already heard. */
        s_stats.guard_bypass++;
        if (!seen) ringPush(g, fp);
        if ((int32_t)(emitted - g->emitted) > 0) g->emitted = emitted;
        g->local_age = now;
        runSet(g, 0);
        return true;
    }

    if (seen) {
        s_stats.guard_drop_fp++;
        g->local_age = now;
        runSet(g, 0);
        return false;
    }

    if ((int32_t)(emitted - g->emitted) < 0) {
        /* Novel blob but an older emission than we hold. Legitimately this is
         * a looped copy. Under a dest4 collision it is instead the losing
         * destination being suppressed *persistently* while the winner keeps
         * refreshing, so a run of them resets the entry and we treat the
         * destination as new. The cost of being wrong is one duplicate
         * forward. */
        uint8_t run = (uint8_t)(runOf(g) + 1);
        if (run >= RDIR_G_RUN_LIMIT) {
            s_stats.guard_resets++;
            memset(g, 0, sizeof(*g));
            g->dest4     = d4;
            g->flags     = RDIR_G_USED;
            g->emitted   = emitted;
            g->local_age = now;
            ringPush(g, fp);
            return true;
        }
        runSet(g, run);
        s_stats.guard_drop_emitted++;
        g->local_age = now;
        return false;
    }

    g->emitted   = emitted;
    g->local_age = now;
    ringPush(g, fp);
    runSet(g, 0);
    return true;
}

/* ── ingest ────────────────────────────────────────────────────────────── */

void rdirIngest(const uint8_t dest[RDIR_DEST_LEN], const rdir_announce_t* a, uint8_t layers)
{
    if (!s_ready || !a) return;
    uint32_t now = nowUnix();

    if (layers & RDIR_LAYER_DIR) {
        rdir_dir_rec_t* r = dirFind(dest);
        if (!r) {
            r = dirAlloc(dest);
            if (!r) return;
            writeBegin(r);
            recClear(r);
        } else {
            writeBegin(r);
        }

        memcpy(r->dest, dest, RDIR_DEST_LEN);
        if (a->pubkey) {
            memcpy(r->pubkey, a->pubkey, RDIR_PUBKEY_LEN);
            r->flags |= RDIR_F_PUBKEY;
        }
        if (a->name_hash) memcpy(r->name_hash, a->name_hash, RDIR_NAME_HASH_LEN);
        r->last_heard = now;
        r->hops       = a->hops;
        r->timestamp  = a->timestamp;
        r->expires    = a->expires;
        if (a->received_from && a->iface_hash) {
            memcpy(r->received_from, a->received_from, RDIR_DEST_LEN);
            memcpy(r->iface_hash,    a->iface_hash,    RDIR_DEST_LEN);
            r->flags |= RDIR_F_ROUTE;
        }
        if (a->edge) r->flags |= RDIR_F_EDGE;
        /* Custody is a property of the route, so it is re-evaluated on every
         * announce rather than latched: a destination that moves to an
         * interface we do not route for stops being our obligation. */
        if (a->answer_for) r->claims |=  RDIR_CLAIM_ANSWER_FOR;
        else               r->claims &= ~RDIR_CLAIM_ANSWER_FOR;
        r->flags |= RDIR_F_USED;
        r->prio = dirStaticPrio(r);
        writeEnd(r);
    }

    if ((layers & RDIR_LAYER_BLOB) && a->raw && a->raw_len > 0) {
        /* An announce whose raw form exceeds the slot is simply not retained;
         * a path request for it falls through to normal discovery. */
        if (a->raw_len + RDIR_BLOB_PREFIX <= s_blob_slot_sz) {
            uint8_t* slot = blobFind(dest);
            if (!slot) slot = blobAlloc();
            if (slot) {
                memset(slot, 0, s_blob_slot_sz);
                memcpy(slot + RDIR_BLOB_OFF_DEST, dest, RDIR_DEST_LEN);
                uint16_t len = a->raw_len;
                uint16_t fl  = 1;
                memcpy(slot + RDIR_BLOB_OFF_LEN,   &len, 2);
                memcpy(slot + RDIR_BLOB_OFF_FLAGS, &fl,  2);
                memcpy(slot + RDIR_BLOB_OFF_RAW,   a->raw, len);
                s_generation++;
            }
        }
    }
}

void rdirTouchUsed(const uint8_t dest[RDIR_DEST_LEN], uint32_t expires) {
    if (!s_ready) return;
    rdir_dir_rec_t* r = dirFind(dest);
    if (!r) return;
    writeBegin(r);
    r->last_used = nowUnix();
    if (expires > r->expires) r->expires = expires;
    writeEnd(r);
}

bool rdirClearRoute(const uint8_t dest[RDIR_DEST_LEN]) {
    if (!s_ready) return false;
    rdir_dir_rec_t* r = dirFind(dest);
    if (!r || !(r->flags & RDIR_F_ROUTE)) return false;
    writeBegin(r);
    memset(r->received_from, 0, RDIR_DEST_LEN);
    memset(r->iface_hash,    0, RDIR_DEST_LEN);
    r->flags &= (uint8_t)~RDIR_F_ROUTE;
    r->expires   = 0;
    r->last_used = 0;
    r->hops      = 0;
    writeEnd(r);
    return true;
}

size_t rdirClearAllRoutes(void) {
    if (!s_ready) return 0;
    size_t n = 0;
    for (uint16_t i = 0; i < s_dir_slots; i++) {
        rdir_dir_rec_t* r = &s_dir[i];
        if (!(r->flags & RDIR_F_USED)) continue;
        if (!(r->flags & RDIR_F_ROUTE)) continue;
        writeBegin(r);
        memset(r->received_from, 0, RDIR_DEST_LEN);
        memset(r->iface_hash,    0, RDIR_DEST_LEN);
        r->flags &= (uint8_t)~RDIR_F_ROUTE;
        r->expires   = 0;
        r->last_used = 0;
        r->hops      = 0;
        writeEnd(r);
        n++;
    }
    return n;
}

bool rdirForget(const uint8_t dest[RDIR_DEST_LEN]) {
    if (!s_ready) return false;
    uint8_t* blob = blobFind(dest);
    if (blob) blobFree(blob);
    rdir_dir_rec_t* r = dirFind(dest);
    if (!r) return blob != nullptr;
    writeBegin(r);
    memset(r, 0, sizeof(*r));
    writeEnd(r);
    return true;
}

/* ── claims ────────────────────────────────────────────────────────────── */

void rdirClaim(const uint8_t dest[RDIR_DEST_LEN], const rdir_claim_t* c) {
    if (!s_ready || !c || c->consumer >= RDIR_CONSUMER_COUNT) return;
    rdir_dir_rec_t* r = dirFind(dest);
    if (!r) {
        /* Claiming a destination we have never heard from is legitimate — a
         * contact restored from the address book at boot. Hold the intent on
         * an otherwise empty record so the first announce lands on it. */
        r = dirAlloc(dest);
        if (!r) return;
        writeBegin(r);
        recClear(r);
        memcpy(r->dest, dest, RDIR_DEST_LEN);
        r->flags |= RDIR_F_USED;
        r->last_heard = nowUnix();
    } else {
        writeBegin(r);
    }
    uint32_t bit = 1u << c->consumer;
    r->claims |= bit << RDIR_CLAIM_PRESENT_SHIFT;
    if (c->klass == RDIR_CLASS_PERSIST) r->claims |= bit << RDIR_CLAIM_PERSIST_SHIFT;
    else                                r->claims &= ~(bit << RDIR_CLAIM_PERSIST_SHIFT);
    if (c->layers & RDIR_LAYER_BLOB)    r->claims |= bit << RDIR_CLAIM_BLOB_SHIFT;
    else                                r->claims &= ~(bit << RDIR_CLAIM_BLOB_SHIFT);
    if (c->decay_s > r->claim_decay)    r->claim_decay = c->decay_s;
    r->claim_touch = nowUnix();
    r->prio = dirStaticPrio(r);
    writeEnd(r);
}

void rdirClaimTouch(const uint8_t dest[RDIR_DEST_LEN], uint8_t consumer) {
    if (!s_ready || consumer >= RDIR_CONSUMER_COUNT) return;
    rdir_dir_rec_t* r = dirFind(dest);
    if (!r) return;
    if (!(r->claims & ((1u << consumer) << RDIR_CLAIM_PRESENT_SHIFT))) return;
    writeBegin(r);
    r->claim_touch = nowUnix();
    writeEnd(r);
}

void rdirClaimDrop(const uint8_t dest[RDIR_DEST_LEN], uint8_t consumer) {
    if (!s_ready || consumer >= RDIR_CONSUMER_COUNT) return;
    rdir_dir_rec_t* r = dirFind(dest);
    if (!r) return;
    uint32_t bit = 1u << consumer;
    writeBegin(r);
    r->claims &= ~((bit << RDIR_CLAIM_PRESENT_SHIFT) |
                   (bit << RDIR_CLAIM_PERSIST_SHIFT) |
                   (bit << RDIR_CLAIM_BLOB_SHIFT));
    if (!(r->claims & RDIR_CLAIM_PRESENT_MASK)) r->claim_decay = 0;
    r->prio = dirStaticPrio(r);
    writeEnd(r);
}

void rdirSeedPubkey(const uint8_t dest[RDIR_DEST_LEN], const uint8_t pk[RDIR_PUBKEY_LEN]) {
    if (!s_ready || !pk) return;
    rdir_dir_rec_t* r = dirFind(dest);
    if (!r) {
        r = dirAlloc(dest);
        if (!r) return;
        writeBegin(r);
        recClear(r);
        memcpy(r->dest, dest, RDIR_DEST_LEN);
        r->last_heard = nowUnix();
        r->flags |= RDIR_F_USED;
        r->prio = dirStaticPrio(r);
    } else {
        writeBegin(r);
    }
    memcpy(r->pubkey, pk, RDIR_PUBKEY_LEN);
    r->flags |= RDIR_F_PUBKEY;
    writeEnd(r);
}

/* ── readers ───────────────────────────────────────────────────────────── */

static void fillRoute(const rdir_dir_rec_t* r, rdir_route_t* out) {
    memcpy(out->received_from, r->received_from, RDIR_DEST_LEN);
    memcpy(out->iface_hash,    r->iface_hash,    RDIR_DEST_LEN);
    out->hops      = r->hops;
    out->expires   = r->expires;
    out->last_used = r->last_used;
    out->timestamp = r->timestamp;
}

bool rdirPeekRoute(const uint8_t dest[RDIR_DEST_LEN], rdir_route_t* out) {
    rdir_dir_rec_t rec;
    if (!dirLookup(dest, &rec)) return false;
    if (!(rec.flags & RDIR_F_ROUTE)) return false;
    if (out) fillRoute(&rec, out);
    return true;
}

bool rdirPeekPubkey(const uint8_t dest[RDIR_DEST_LEN], uint8_t out[RDIR_PUBKEY_LEN]) {
    rdir_dir_rec_t rec;
    if (!dirLookup(dest, &rec) || !(rec.flags & RDIR_F_PUBKEY)) {
        s_stats.recall_miss++;
        return false;
    }
    if (out) memcpy(out, rec.pubkey, RDIR_PUBKEY_LEN);
    return true;
}

static void fillEntry(const rdir_dir_rec_t* r, rdir_entry_t* out) {
    memcpy(out->dest,      r->dest,      RDIR_DEST_LEN);
    memcpy(out->pubkey,    r->pubkey,    RDIR_PUBKEY_LEN);
    memcpy(out->name_hash, r->name_hash, RDIR_NAME_HASH_LEN);
    out->last_heard  = r->last_heard;
    out->claims      = r->claims;
    out->claim_touch = r->claim_touch;
    out->hops        = r->hops;
    out->flags       = r->flags;
    out->prio        = r->prio;
    out->has_pubkey  = (r->flags & RDIR_F_PUBKEY) != 0;
    out->has_route   = (r->flags & RDIR_F_ROUTE) != 0;
    fillRoute(r, &out->route);
}

bool rdirPeekEntry(const uint8_t dest[RDIR_DEST_LEN], rdir_entry_t* out) {
    rdir_dir_rec_t rec;
    if (!dirLookup(dest, &rec)) return false;
    if (out) fillEntry(&rec, out);
    return true;
}

bool rdirHasClaim(const uint8_t dest[RDIR_DEST_LEN]) {
    rdir_dir_rec_t rec;
    if (!dirLookup(dest, &rec)) return false;
    return (rec.claims & RDIR_CLAIM_PRESENT_MASK) != 0;
}

bool rdirInUse(const uint8_t dest[RDIR_DEST_LEN]) {
    rdir_dir_rec_t rec;
    if (!dirLookup(dest, &rec)) return false;
    if (!(rec.flags & RDIR_F_ROUTE) || rec.last_used == 0) return false;
    return (uint32_t)(nowUnix() - rec.last_used) < RNS::Type::Transport::PATH_LAST_USED_STALE;
}

size_t rdirCopyBlob(const uint8_t dest[RDIR_DEST_LEN], uint8_t* buf, size_t cap) {
    if (!s_ready) return 0;
    const uint8_t* slot = blobFind(dest);
    if (!slot) return 0;
    uint16_t len = blobLen(slot);
    if (len == 0 || len > cap) return 0;
    memcpy(buf, slot + RDIR_BLOB_OFF_RAW, len);
    return len;
}

void rdirForEach(void (*cb)(const rdir_entry_t*, void*), void* ctx) {
    if (!s_ready || !cb) return;
    for (uint16_t i = 0; i < s_dir_slots; i++) {
        const rdir_dir_rec_t* r = &s_dir[i];
        if (!(r->flags & RDIR_F_USED)) continue;
        rdir_dir_rec_t copy;
        if (!recCopy(r, &copy)) continue;
        if (!(copy.flags & RDIR_F_USED)) continue;
        rdir_entry_t e;
        fillEntry(&copy, &e);
        cb(&e, ctx);
    }
}

size_t rdirCount(void)        { return s_ready ? dirUsed() : 0; }
size_t rdirSlots(void)        { return s_dir_slots; }
size_t rdirGuardSlots(void)   { return s_guard_slots; }
size_t rdirBlobSlots(void)    { return s_blob_slots; }
size_t rdirBlobSlotSize(void) { return s_blob_slot_sz; }
size_t rdirArenaBytes(void)   { return guardBytes() + dirBytes() + blobBytes(); }
/* What a full snapshot of the *current* content costs — it tracks what the
 * node actually knows, not how big its pools are. */
size_t rdirImageBytes(void)   {
    if (!s_ready) return 0;
    return sizeof(rdir_img_hdr_t) + dirUsed() * RDIR_DIR_SLOT_SZ
                                  + blobUsedCount() * (size_t)s_blob_slot_sz;
}
bool   rdirReady(void)        { return s_ready; }

size_t rdirGuardCount(void) {
    if (!s_ready) return 0;
    size_t n = 0;
    for (uint16_t i = 0; i < s_guard_slots; i++)
        if (s_guard[i].flags & RDIR_G_USED) n++;
    return n;
}

size_t rdirBlobCount(void) { return s_ready ? blobUsedCount() : 0; }

void     rdirGetStats(rdir_stats_t* out) { if (out) *out = s_stats; }
uint32_t rdirGeneration(void) { return s_generation; }

/* ── image ─────────────────────────────────────────────────────────────── */

/* Ranking key for "what is worth persisting", most valuable first. The
 * eviction order is the same judgement, so it is the same two functions; the
 * slot index breaks ties, which makes the ordering total and lets the walk
 * below pick successive maxima without a visited set (no allocation). */
typedef struct { uint8_t cat; uint32_t order; uint16_t slot; } rdir_rank_t;

static inline bool rankLess(const rdir_rank_t& a, const rdir_rank_t& b) {
    if (a.cat   != b.cat)   return a.cat   < b.cat;
    if (a.order != b.order) return a.order < b.order;
    return a.slot < b.slot;
}

/* The greatest used record ranking strictly below `hi`, or false when none is
 * left. Passing the previous winner walks the pool in descending rank. */
static bool dirNextBelow(const rdir_rank_t* hi, uint32_t now, rdir_rank_t* out) {
    bool found = false;
    for (uint16_t i = 0; i < s_dir_slots; i++) {
        const rdir_dir_rec_t* r = &s_dir[i];
        if (!(r->flags & RDIR_F_USED)) continue;
        rdir_rank_t k = { dirCategory(r, now), 0, i };
        k.order = dirOrder(r, k.cat);
        if (hi && !rankLess(k, *hi)) continue;
        if (found && !rankLess(*out, k)) continue;
        *out = k;
        found = true;
    }
    return found;
}

/* The image is the live set, best-first, truncated to `cap` — not the arena.
 *
 * Three consequences, all deliberate. The guard pool is never written: its
 * ages are on the local uptime clock, which restarts at boot, so a reloaded
 * guard record dates itself ~45 days old and is evicted before anything
 * fresh — bytes spent to persist nothing. Records go out in eviction order,
 * most valuable first, so a `cap` short of the whole set drops exactly what
 * the store would drop next anyway. And blobs follow all the directory
 * records rather than riding with each one, so a tight budget keeps knowing
 * *who* everyone is and gives up answering path requests for them — the
 * degradation order the pools are ranked in.
 *
 * Returns bytes written, 0 if `cap` cannot hold even the header. */
size_t rdirSnapshot(void* buf, size_t cap) {
    if (!s_ready || !buf) return 0;
    if (cap < sizeof(rdir_img_hdr_t)) return 0;

    uint8_t* out = (uint8_t*)buf;
    size_t   at  = sizeof(rdir_img_hdr_t);
    uint32_t now = nowUnix();

    /* Pass 1: directory records, descending rank. */
    uint16_t n_dir = 0;
    rdir_rank_t k;
    bool have = dirNextBelow(nullptr, now, &k);
    while (have && at + RDIR_DIR_SLOT_SZ <= cap) {
        memcpy(out + at, &s_dir[k.slot], RDIR_DIR_SLOT_SZ);
        at += RDIR_DIR_SLOT_SZ;
        n_dir++;
        have = dirNextBelow(&k, now, &k);
    }

    /* Pass 2: the blob for each record written, in the same order. A blob
     * whose record did not make the cut is not worth carrying — nothing could
     * look it up. */
    uint16_t n_blob = 0;
    const uint8_t* recs = out + sizeof(rdir_img_hdr_t);
    for (uint16_t i = 0; i < n_dir && at + s_blob_slot_sz <= cap; i++) {
        const uint8_t* slot = blobFind(recs + (size_t)i * RDIR_DIR_SLOT_SZ);
        if (!slot) continue;
        memcpy(out + at, slot, s_blob_slot_sz);
        at += s_blob_slot_sz;
        n_blob++;
    }

    rdir_img_hdr_t hdr;
    memcpy(hdr.magic, "RDIR", 4);
    hdr.format_ver   = RDIR_FORMAT_VER;
    hdr.feature_ver  = RDIR_FEATURE_VER;
    hdr.dir_slot_sz  = RDIR_DIR_SLOT_SZ;
    hdr.dir_count    = n_dir;
    hdr.blob_slot_sz = s_blob_slot_sz;
    hdr.blob_count   = n_blob;
    memcpy(out, &hdr, sizeof(hdr));

    s_stats.snapshots++;
    return at;
}

/* The image is read into the front of the arena, then slid to the back so
 * every section moves *down* into its final position. That single ordering
 * removes the overlap question: directory records, then blobs, each followed
 * by zero-filling the slots the image did not have. The guard pool is not in
 * the image and starts empty. */
static bool imageLoad(void) {
    if (!s_plat.image_load) return false;

    size_t len = s_alloc_bytes;
    if (!s_plat.image_load(s_arena, &len)) return false;
    if (len < sizeof(rdir_img_hdr_t)) return false;

    rdir_img_hdr_t hdr;
    memcpy(&hdr, s_arena, sizeof(hdr));
    if (memcmp(hdr.magic, "RDIR", 4) != 0) {
        WARNING("rdir: image has no RDIR magic, discarding");
        return false;
    }
    if (hdr.format_ver != RDIR_FORMAT_VER) {
        WARNINGF("rdir: image format %u != %u, discarding", (unsigned)hdr.format_ver, RDIR_FORMAT_VER);
        return false;
    }
    if (hdr.dir_slot_sz != RDIR_DIR_SLOT_SZ || hdr.blob_slot_sz != s_blob_slot_sz) {
        WARNING("rdir: image slot sizes differ from configured, discarding");
        return false;
    }
    /* Fewer records than we have slots is the normal case — the image is the
     * live set, not the pools. More than fit is not: there is nowhere to put
     * them, and silently dropping the tail would be a lie about what loaded. */
    if (hdr.dir_count > s_dir_slots || hdr.blob_count > s_blob_slots) {
        WARNINGF("rdir: image holds %u/%u records, pools take %u/%u, discarding",
                 (unsigned)hdr.dir_count, (unsigned)hdr.blob_count,
                 (unsigned)s_dir_slots,   (unsigned)s_blob_slots);
        return false;
    }

    size_t d_disk = (size_t)hdr.dir_count  * RDIR_DIR_SLOT_SZ;
    size_t b_disk = (size_t)hdr.blob_count * s_blob_slot_sz;
    size_t expect = sizeof(rdir_img_hdr_t) + d_disk + b_disk;
    if (len < expect) {
        WARNINGF("rdir: image truncated (%u < %u), discarding", (unsigned)len, (unsigned)expect);
        return false;
    }

    size_t tail = s_alloc_bytes - expect;      /* >= sizeof(hdr), see below */
    memmove(s_arena + tail, s_arena, expect);

    const uint8_t* src = s_arena + tail + sizeof(rdir_img_hdr_t);
    memset((uint8_t*)s_guard, 0, guardBytes());
    memmove((uint8_t*)s_dir, src, d_disk);
    memset((uint8_t*)s_dir + d_disk, 0, dirBytes() - d_disk);
    src += d_disk;
    memmove(s_blob, src, b_disk);
    memset(s_blob + b_disk, 0, blobBytes() - b_disk);

    /* A snapshot is taken on the writer's task with every record coherent, so
     * no sequence counter can be odd on disk — but a truncated or hand-edited
     * image must not leave a reader spinning. */
    for (uint16_t i = 0; i < s_dir_slots; i++) s_dir[i].seq &= (uint16_t)~1u;

    VERBOSEF("rdir: loaded image, %u directory / %u blob records",
             (unsigned)dirUsed(), (unsigned)blobUsedCount());
    return true;
}

void rdirSetBlobSlotSize(size_t bytes) {
    if (s_ready) return;
    if (bytes < RDIR_BLOB_PREFIX + 64) bytes = RDIR_BLOB_PREFIX + 64;
    if (bytes > 2048) bytes = 2048;
    s_blob_slot_sz = (uint16_t)((bytes + 3) & ~(size_t)3);
}

bool rdirInit(const rdir_platform_t* platform, size_t byte_budget) {
    if (s_ready) return true;
    if (!platform || !platform->arena_alloc) return false;
    s_plat = *platform;
    memset(&s_stats, 0, sizeof(s_stats));

    /* Slot counts come from a byte budget, never from constants: constants
     * tuned on an 8 MB board and inherited by a 2 MB one are the defect this
     * design exists to prevent. The split is a fixed 8:4:1 proportion of slot
     * counts (guard : directory : blob). */
    size_t unit_bytes = 8 * RDIR_GUARD_SLOT_SZ + 4 * RDIR_DIR_SLOT_SZ + s_blob_slot_sz;
    size_t units = byte_budget / unit_bytes;
    if (units < 4) units = 4;
    if (units > 2048) units = 2048;

    s_guard_slots = (uint16_t)(units * 8);
    s_dir_slots   = (uint16_t)(units * 4);
    s_blob_slots  = (uint16_t)units;

    /* One extra header's worth of slack: the image is read into the arena and
     * then slid to the back, and an image whose pools exactly match ours is
     * the arena plus its header. */
    s_alloc_bytes = guardBytes() + dirBytes() + blobBytes() + sizeof(rdir_img_hdr_t);
    s_arena = (uint8_t*)s_plat.arena_alloc(s_alloc_bytes);
    if (!s_arena) {
        ERRORF("rdir: could not allocate %u B arena", (unsigned)s_alloc_bytes);
        s_guard_slots = s_dir_slots = s_blob_slots = 0;
        return false;
    }
    memset(s_arena, 0, s_alloc_bytes);

    s_guard = (rdir_guard_rec_t*)s_arena;
    s_dir   = (rdir_dir_rec_t*)(s_arena + guardBytes());
    s_blob  = s_arena + guardBytes() + dirBytes();
    s_ready = true;

    if (!imageLoad()) {
        memset(s_arena, 0, s_alloc_bytes);
    }

    INFOF("rdir: %u B arena — guard %u x %u, directory %u x %u, blob %u x %u",
          (unsigned)rdirArenaBytes(),
          (unsigned)s_guard_slots, (unsigned)RDIR_GUARD_SLOT_SZ,
          (unsigned)s_dir_slots,   (unsigned)RDIR_DIR_SLOT_SZ,
          (unsigned)s_blob_slots,  (unsigned)s_blob_slot_sz);
    return true;
}
