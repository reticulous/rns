/*
 * MsgPack shim — narrow re-implementation of the surface
 * `attermann/microReticulum`'s upstream `Link.cpp` uses from the
 * hideakitai/MsgPack Arduino library.
 *
 * Spangap's microreticulum fork needs these wire shapes:
 *   - serialize/deserialize a single `double`            (LRRTT echo)
 *   - serialize a single `bin_t<uint8_t>`                (transfer-size probe)
 *   - to_array(double, RNS::Bytes, RNS::Bytes)           (REQUEST)
 *   - from_request(double, bin, payload)                 (REQUEST decode)
 *   - to_array(RNS::Bytes, RNS::Bytes)                   (RESPONSE)
 *   - from_response(bin, payload)                        (RESPONSE decode)
 *
 * …and, for Reticulum's own remote-management service, whole objects in both
 * directions: an argument list carrying strings, integers, booleans and nil,
 * and a response of maps and arrays whose keys are read selectively.
 *
 *   - to_array("table", nil, 1)                          (/path request)
 *   - MapReader over a /status answer                    (response decode)
 *
 * The envelopes' trailing `payload` slot is typed by the protocol spoken
 * over the link, not by this shim — see detail::unpack_blob_or_object.
 *
 * The implementation directly emits/consumes the msgpack wire format
 * (https://github.com/msgpack/msgpack/blob/master/spec.md). No upstream
 * Arduino dep.
 */
#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "Bytes.h"

namespace MsgPack {

template <class T>
using bin_t = std::vector<T>;

namespace detail {

inline void put_be16(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>(v >> 8));
    out.push_back(static_cast<uint8_t>(v & 0xff));
}

inline void put_be32(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
    out.push_back(static_cast<uint8_t>(v & 0xff));
}

inline uint16_t get_be16(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

inline uint32_t get_be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}

inline void pack_double(std::vector<uint8_t>& out, double v) {
    uint64_t bits;
    std::memcpy(&bits, &v, sizeof(bits));
    out.push_back(0xcb);
    for (int i = 7; i >= 0; --i) {
        out.push_back(static_cast<uint8_t>((bits >> (i * 8)) & 0xff));
    }
}

inline void pack_bin(std::vector<uint8_t>& out, const uint8_t* data, size_t n) {
    if (n <= 0xff) {
        out.push_back(0xc4);
        out.push_back(static_cast<uint8_t>(n));
    } else if (n <= 0xffff) {
        out.push_back(0xc5);
        put_be16(out, static_cast<uint16_t>(n));
    } else {
        out.push_back(0xc6);
        put_be32(out, static_cast<uint32_t>(n));
    }
    if (n > 0) out.insert(out.end(), data, data + n);
}

inline void pack_array_header(std::vector<uint8_t>& out, size_t n) {
    if (n <= 15) {
        out.push_back(static_cast<uint8_t>(0x90 | n));
    } else if (n <= 0xffff) {
        out.push_back(0xdc);
        put_be16(out, static_cast<uint16_t>(n));
    } else {
        out.push_back(0xdd);
        put_be32(out, static_cast<uint32_t>(n));
    }
}

// Map shape — small extension for ResourceAdvertisement's dict wire format.
inline void pack_map_header(std::vector<uint8_t>& out, size_t n) {
    if (n <= 15) {
        out.push_back(static_cast<uint8_t>(0x80 | n));
    } else if (n <= 0xffff) {
        out.push_back(0xde);
        put_be16(out, static_cast<uint16_t>(n));
    } else {
        out.push_back(0xdf);
        put_be32(out, static_cast<uint32_t>(n));
    }
}

inline void pack_nil(std::vector<uint8_t>& out) {
    out.push_back(0xc0);
}

inline void pack_bool(std::vector<uint8_t>& out, bool v) {
    out.push_back(v ? 0xc3 : 0xc2);
}

// Pack a signed integer. Upstream's umsgpack picks the narrowest form that
// holds the value and prefers the unsigned encodings for non-negative ones, so
// this defers to pack_uint whenever it can and only reaches for the signed tags
// where the value is actually negative.
inline void pack_uint(std::vector<uint8_t>& out, uint64_t v);
inline void pack_int(std::vector<uint8_t>& out, int64_t v) {
    if (v >= 0) { pack_uint(out, static_cast<uint64_t>(v)); return; }
    if (v >= -32) { out.push_back(static_cast<uint8_t>(0xe0 | (v + 32))); return; }
    if (v >= -128) {
        out.push_back(0xd0);
        out.push_back(static_cast<uint8_t>(static_cast<int8_t>(v)));
        return;
    }
    if (v >= -32768) {
        out.push_back(0xd1);
        put_be16(out, static_cast<uint16_t>(static_cast<int16_t>(v)));
        return;
    }
    if (v >= -2147483648LL) {
        out.push_back(0xd2);
        put_be32(out, static_cast<uint32_t>(static_cast<int32_t>(v)));
        return;
    }
    out.push_back(0xd3);
    for (int i = 7; i >= 0; --i) out.push_back(static_cast<uint8_t>((static_cast<uint64_t>(v) >> (i * 8)) & 0xff));
}

// Pack a non-negative integer in the most compact form upstream Reticulum's
// `umsgpack.packb` emits. Always positive (fields t/d/n/i/l/f are unsigned).
inline void pack_uint(std::vector<uint8_t>& out, uint64_t v) {
    if (v <= 0x7f) {
        out.push_back(static_cast<uint8_t>(v));
    } else if (v <= 0xff) {
        out.push_back(0xcc);
        out.push_back(static_cast<uint8_t>(v));
    } else if (v <= 0xffff) {
        out.push_back(0xcd);
        put_be16(out, static_cast<uint16_t>(v));
    } else if (v <= 0xffffffffULL) {
        out.push_back(0xce);
        put_be32(out, static_cast<uint32_t>(v));
    } else {
        out.push_back(0xcf);
        for (int i = 7; i >= 0; --i) out.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xff));
    }
}

// Short ASCII key (fixstr — only shape we need; ResourceAdvertisement keys
// are 1 char each).
inline void pack_fixstr(std::vector<uint8_t>& out, const char* s, size_t n) {
    if (n > 31) throw std::runtime_error("MsgPack: pack_fixstr len > 31");
    out.push_back(static_cast<uint8_t>(0xa0 | n));
    if (n > 0) out.insert(out.end(), reinterpret_cast<const uint8_t*>(s), reinterpret_cast<const uint8_t*>(s) + n);
}

// A string of any length. The map KEYS of a status dict all fit fixstr, but the
// values do not — an interface's `name` is whatever the operator called it, and
// truncating it there would misname the thing the whole answer is about.
inline void pack_str(std::vector<uint8_t>& out, const char* s, size_t n) {
    if (n <= 31) {
        out.push_back(static_cast<uint8_t>(0xa0 | n));
    } else if (n <= 0xff) {
        out.push_back(0xd9);
        out.push_back(static_cast<uint8_t>(n));
    } else if (n <= 0xffff) {
        out.push_back(0xda);
        put_be16(out, static_cast<uint16_t>(n));
    } else {
        out.push_back(0xdb);
        put_be32(out, static_cast<uint32_t>(n));
    }
    if (n > 0) out.insert(out.end(), reinterpret_cast<const uint8_t*>(s), reinterpret_cast<const uint8_t*>(s) + n);
}

// Unpack a non-negative integer in any positive-integer msgpack form.
// Rejects negative ints and other non-integer types.
inline size_t unpack_uint(const uint8_t* p, size_t n, uint64_t& v) {
    if (n < 1) throw std::runtime_error("MsgPack: short uint");
    uint8_t t = p[0];
    if ((t & 0x80) == 0) { v = t; return 1; }            // positive fixint
    if (t == 0xcc) {
        if (n < 2) throw std::runtime_error("MsgPack: short uint8");
        v = p[1]; return 2;
    }
    if (t == 0xcd) {
        if (n < 3) throw std::runtime_error("MsgPack: short uint16");
        v = get_be16(p + 1); return 3;
    }
    if (t == 0xce) {
        if (n < 5) throw std::runtime_error("MsgPack: short uint32");
        v = get_be32(p + 1); return 5;
    }
    if (t == 0xcf) {
        if (n < 9) throw std::runtime_error("MsgPack: short uint64");
        uint64_t r = 0;
        for (int i = 0; i < 8; ++i) r = (r << 8) | p[1 + i];
        v = r;
        return 9;
    }
    throw std::runtime_error("MsgPack: expected uint");
}

inline size_t unpack_str(const uint8_t* p, size_t n, std::string& out) {
    if (n < 1) throw std::runtime_error("MsgPack: short str");
    size_t hdr;
    size_t len;
    uint8_t t = p[0];
    if ((t & 0xe0) == 0xa0) {
        len = t & 0x1f;
        hdr = 1;
    } else if (t == 0xd9) {
        if (n < 2) throw std::runtime_error("MsgPack: short str8");
        len = p[1]; hdr = 2;
    } else if (t == 0xda) {
        if (n < 3) throw std::runtime_error("MsgPack: short str16");
        len = get_be16(p + 1); hdr = 3;
    } else if (t == 0xdb) {
        if (n < 5) throw std::runtime_error("MsgPack: short str32");
        len = get_be32(p + 1); hdr = 5;
    } else {
        throw std::runtime_error("MsgPack: expected str");
    }
    if (n < hdr + len) throw std::runtime_error("MsgPack: short str payload");
    out.assign(reinterpret_cast<const char*>(p + hdr), len);
    return hdr + len;
}

inline size_t unpack_map_header(const uint8_t* p, size_t n, size_t& count) {
    if (n < 1) throw std::runtime_error("MsgPack: short map header");
    uint8_t t = p[0];
    if ((t & 0xf0) == 0x80) { count = t & 0x0f; return 1; }
    if (t == 0xde) {
        if (n < 3) throw std::runtime_error("MsgPack: short map16");
        count = get_be16(p + 1); return 3;
    }
    if (t == 0xdf) {
        if (n < 5) throw std::runtime_error("MsgPack: short map32");
        count = get_be32(p + 1); return 5;
    }
    throw std::runtime_error("MsgPack: expected map");
}

// Forward decl — `skip_value` recurses into arrays/maps via these.
inline size_t unpack_array_header(const uint8_t* p, size_t n, size_t& count);

// Skip an arbitrary msgpack value (used when ResourceAdvertisement::unpack
// hits an unknown key — peers can extend the dict).
inline size_t skip_value(const uint8_t* p, size_t n) {
    if (n < 1) throw std::runtime_error("MsgPack: short skip");
    uint8_t t = p[0];
    if (t == 0xc0 || t == 0xc2 || t == 0xc3) return 1;                  // nil/false/true
    if ((t & 0x80) == 0)        return 1;                                // positive fixint
    if ((t & 0xe0) == 0xe0)     return 1;                                // negative fixint
    if (t == 0xcc || t == 0xd0) return 2;                                // uint8/int8
    if (t == 0xcd || t == 0xd1) return 3;                                // uint16/int16
    if (t == 0xce || t == 0xd2 || t == 0xca) return 5;                   // uint32/int32/float32
    if (t == 0xcf || t == 0xd3 || t == 0xcb) return 9;                   // uint64/int64/float64
    if ((t & 0xe0) == 0xa0) return 1 + (t & 0x1f);                       // fixstr
    if (t == 0xd9) { if (n < 2) throw std::runtime_error("MsgPack: short str8 skip");  return 2 + p[1]; }
    if (t == 0xda) { if (n < 3) throw std::runtime_error("MsgPack: short str16 skip"); return 3 + get_be16(p + 1); }
    if (t == 0xdb) { if (n < 5) throw std::runtime_error("MsgPack: short str32 skip"); return 5 + get_be32(p + 1); }
    if (t == 0xc4) { if (n < 2) throw std::runtime_error("MsgPack: short bin8 skip");  return 2 + p[1]; }
    if (t == 0xc5) { if (n < 3) throw std::runtime_error("MsgPack: short bin16 skip"); return 3 + get_be16(p + 1); }
    if (t == 0xc6) { if (n < 5) throw std::runtime_error("MsgPack: short bin32 skip"); return 5 + get_be32(p + 1); }
    if ((t & 0xf0) == 0x90 || t == 0xdc || t == 0xdd) {
        size_t count = 0;
        size_t off = unpack_array_header(p, n, count);
        for (size_t i = 0; i < count; ++i) off += skip_value(p + off, n - off);
        return off;
    }
    if ((t & 0xf0) == 0x80 || t == 0xde || t == 0xdf) {
        size_t count = 0;
        size_t off = unpack_map_header(p, n, count);
        for (size_t i = 0; i < count; ++i) {
            off += skip_value(p + off, n - off);   // key
            off += skip_value(p + off, n - off);   // value
        }
        return off;
    }
    throw std::runtime_error("MsgPack: unknown tag in skip");
}

/* A nil, as something that can be PASSED. `to_array(nil, x)` has to be able to
 * say "this slot is absent" — a remote-management /path request is literally
 * ["table", nil, 1] — and there is no C++ value that means nil on its own. */
struct nil_t {};
inline constexpr nil_t nil{};

// Per-type packers — overload set used by the fold expressions below.
inline void pack_one(std::vector<uint8_t>& out, double v)                  { pack_double(out, v); }
inline void pack_one(std::vector<uint8_t>& out, const bin_t<uint8_t>& b)   { pack_bin(out, b.data(), b.size()); }
inline void pack_one(std::vector<uint8_t>& out, const RNS::Bytes& b)       { pack_bin(out, b.data(), b.size()); }
inline void pack_one(std::vector<uint8_t>& out, nil_t)                     { pack_nil(out); }
inline void pack_one(std::vector<uint8_t>& out, bool v)                    { pack_bool(out, v); }
inline void pack_one(std::vector<uint8_t>& out, const char* s)             { pack_str(out, s, s ? std::strlen(s) : 0); }
inline void pack_one(std::vector<uint8_t>& out, const std::string& s)      { pack_str(out, s.data(), s.size()); }

/* Every integral type but bool, which has its own exact overload above and must
 * not arrive here as 0/1. Exact-match beats the double conversion, so an int
 * argument packs as an integer rather than as a float64 — which matters,
 * because upstream reads `hops` with an integer type check. */
template <class T, class = typename std::enable_if<std::is_integral<T>::value &&
                                                   !std::is_same<T, bool>::value>::type>
inline void pack_one(std::vector<uint8_t>& out, T v) {
    if (std::is_signed<T>::value) pack_int(out, static_cast<int64_t>(v));
    else                          pack_uint(out, static_cast<uint64_t>(v));
}

// Per-type unpackers — return number of bytes consumed, or throw on
// mismatch. Caller passes the buffer + cursor.
inline size_t unpack_double(const uint8_t* p, size_t n, double& v) {
    if (n < 9 || p[0] != 0xcb) {
        throw std::runtime_error("MsgPack: expected float64");
    }
    uint64_t bits = 0;
    for (int i = 0; i < 8; ++i) bits = (bits << 8) | p[1 + i];
    std::memcpy(&v, &bits, sizeof(v));
    return 9;
}

inline size_t unpack_bin(const uint8_t* p, size_t n, bin_t<uint8_t>& out) {
    if (n < 1) throw std::runtime_error("MsgPack: short bin header");
    size_t hdr;
    size_t len;
    if (p[0] == 0xc4) {
        if (n < 2) throw std::runtime_error("MsgPack: short bin8");
        len = p[1];
        hdr = 2;
    } else if (p[0] == 0xc5) {
        if (n < 3) throw std::runtime_error("MsgPack: short bin16");
        len = get_be16(p + 1);
        hdr = 3;
    } else if (p[0] == 0xc6) {
        if (n < 5) throw std::runtime_error("MsgPack: short bin32");
        len = get_be32(p + 1);
        hdr = 5;
    } else {
        throw std::runtime_error("MsgPack: expected bin");
    }
    if (n < hdr + len) throw std::runtime_error("MsgPack: short bin payload");
    out.assign(p + hdr, p + hdr + len);
    return hdr + len;
}

inline size_t unpack_array_header(const uint8_t* p, size_t n, size_t& count) {
    if (n < 1) throw std::runtime_error("MsgPack: short array header");
    if ((p[0] & 0xf0) == 0x90) {
        count = p[0] & 0x0f;
        return 1;
    }
    if (p[0] == 0xdc) {
        if (n < 3) throw std::runtime_error("MsgPack: short array16");
        count = get_be16(p + 1);
        return 3;
    }
    if (p[0] == 0xdd) {
        if (n < 5) throw std::runtime_error("MsgPack: short array32");
        count = get_be32(p + 1);
        return 5;
    }
    throw std::runtime_error("MsgPack: expected array");
}

// Per-type unpack dispatchers used by the fold expression in from_array.
inline size_t unpack_one(const uint8_t* p, size_t n, double& v)         { return unpack_double(p, n, v); }
inline size_t unpack_one(const uint8_t* p, size_t n, bin_t<uint8_t>& v) {
    // Reference RNS packs optional payload slots (Link REQUEST/RESPONSE
    // request_data / response_data) as `None` → msgpack nil when the
    // caller passes no data. Treat nil as an empty bin so a data-less
    // request decodes instead of throwing "expected bin" and dropping
    // the request. Lower-level unpack_bin stays strict for the callers
    // that demand bin (Resource.cpp), which never see nil here.
    if (n >= 1 && p[0] == 0xc0) { v.clear(); return 1; }
    return unpack_bin(p, n, v);
}

/* The trailing payload slot of a Link REQUEST/RESPONSE envelope, whose
 * msgpack type is chosen by the protocol spoken over the link and not by
 * this shim: reference RNS puts whatever the remote handler was handed (or
 * returned) straight into that element.
 *
 *   - bin/str  → the blob's bytes, which is a NomadNet page body.
 *   - anything structured (array, map, int, bool, float) → the element's own
 *     msgpack encoding, verbatim, so the consumer that speaks that protocol
 *     parses the object itself. An LXMF propagation node answers `/get` with
 *     an array (transient ids, or message blobs) and refuses with a bare
 *     int; demanding bin here silently dropped every such response.
 *   - nil → empty.
 *
 * The verbatim path is the inbound mirror of Link::request's `data_packed`,
 * which splices an already-packed object into the outbound envelope. */
inline size_t unpack_blob_or_object(const uint8_t* p, size_t n, bin_t<uint8_t>& out) {
    if (n < 1) throw std::runtime_error("MsgPack: short payload slot");
    uint8_t t = p[0];
    if (t == 0xc0) { out.clear(); return 1; }                        // nil
    size_t hdr, len;
    if ((t & 0xe0) == 0xa0) { hdr = 1; len = t & 0x1f; }             // fixstr
    else if (t == 0xd9 || t == 0xc4) {
        if (n < 2) throw std::runtime_error("MsgPack: short payload blob8");
        hdr = 2; len = p[1];
    }
    else if (t == 0xda || t == 0xc5) {
        if (n < 3) throw std::runtime_error("MsgPack: short payload blob16");
        hdr = 3; len = get_be16(p + 1);
    }
    else if (t == 0xdb || t == 0xc6) {
        if (n < 5) throw std::runtime_error("MsgPack: short payload blob32");
        hdr = 5; len = get_be32(p + 1);
    }
    else {
        size_t elem = skip_value(p, n);
        if (elem > n) throw std::runtime_error("MsgPack: short payload object");
        out.assign(p, p + elem);
        return elem;
    }
    if (n < hdr + len) throw std::runtime_error("MsgPack: short payload blob");
    out.assign(p + hdr, p + hdr + len);
    return hdr + len;
}

inline size_t unpack_bool(const uint8_t* p, size_t n, bool& v) {
    if (n < 1) throw std::runtime_error("MsgPack: short bool");
    if (p[0] == 0xc2) { v = false; return 1; }
    if (p[0] == 0xc3) { v = true;  return 1; }
    throw std::runtime_error("MsgPack: expected bool");
}

/* Any msgpack number as a double, whichever encoding it arrived in. Upstream
 * writes a status dict from Python, where the width of an integer is not a
 * decision anyone made — a byte counter is a fixint until it is not — so a
 * reader that demanded one width would work until the counter grew. */
inline size_t unpack_number(const uint8_t* p, size_t n, double& v) {
    if (n < 1) throw std::runtime_error("MsgPack: short number");
    uint8_t t = p[0];
    if (t == 0xcb) return unpack_double(p, n, v);
    if (t == 0xca) {
        if (n < 5) throw std::runtime_error("MsgPack: short float32");
        uint32_t bits = get_be32(p + 1);
        float f;
        std::memcpy(&f, &bits, sizeof(f));
        v = f;
        return 5;
    }
    if ((t & 0xe0) == 0xe0) { v = static_cast<int8_t>(t); return 1; }   // negative fixint
    if (t == 0xd0) {
        if (n < 2) throw std::runtime_error("MsgPack: short int8");
        v = static_cast<int8_t>(p[1]); return 2;
    }
    if (t == 0xd1) {
        if (n < 3) throw std::runtime_error("MsgPack: short int16");
        v = static_cast<int16_t>(get_be16(p + 1)); return 3;
    }
    if (t == 0xd2) {
        if (n < 5) throw std::runtime_error("MsgPack: short int32");
        v = static_cast<int32_t>(get_be32(p + 1)); return 5;
    }
    if (t == 0xd3) {
        if (n < 9) throw std::runtime_error("MsgPack: short int64");
        uint64_t r = 0;
        for (int i = 0; i < 8; ++i) r = (r << 8) | p[1 + i];
        v = static_cast<double>(static_cast<int64_t>(r));
        return 9;
    }
    uint64_t u = 0;
    size_t   k = unpack_uint(p, n, u);
    v = static_cast<double>(u);
    return k;
}

} // namespace detail

/* ── reading a map ──
 *
 * "Walk a map, dispatch on the string keys we want, skip the rest." That last
 * clause is the whole design: a status dict from a node running a newer
 * Reticulum carries keys this firmware has never heard of, and a reader that
 * treated an unknown key as an error would break on every upstream release.
 * skip_value already recurses arrays and maps, so an unknown key's value is
 * stepped over whatever shape it is.
 *
 * Usage — the cursor advances past the whole map either way:
 *
 *   MsgPack::MapReader m(p, n);
 *   while (m.next()) {
 *       if      (m.key_is("name"))   m.value_str(name);
 *       else if (m.key_is("status")) m.value_bool(up);
 *       else if (m.key_is("rxb"))    m.value_num(rxb);
 *       else                         m.skip_value();
 *   }
 *
 * A branch that reads no value MUST call skip_value(); next() cannot do it for
 * you, because it has already handed you the key and does not know whether you
 * consumed the value. Reading the wrong type throws, which is the right
 * outcome — a value that is not the shape the protocol says is not something to
 * paper over.
 */
class MapReader {
public:
    MapReader(const uint8_t* p, size_t n) : _p(p), _n(n) {
        _off = detail::unpack_map_header(p, n, _count);
    }

    /** Advance to the next pair and read its key. False at the end of the map. */
    bool next() {
        if (_seen >= _count) return false;
        _seen++;
        _off += detail::unpack_str(_p + _off, _n - _off, _key);
        _pending = true;
        return true;
    }

    const std::string& key() const { return _key; }
    bool key_is(const char* k) const { return _key == k; }

    void value_str(std::string& out)  { take(detail::unpack_str(_p + _off, _n - _off, out)); }
    void value_bool(bool& out)        { take(detail::unpack_bool(_p + _off, _n - _off, out)); }
    void value_num(double& out)       { take(detail::unpack_number(_p + _off, _n - _off, out)); }
    void value_bin(bin_t<uint8_t>& o) { take(detail::unpack_bin(_p + _off, _n - _off, o)); }

    /** A key we do not read, or a value shape we do not want. Also the way to
     *  step over a nested map or array without descending into it. */
    void skip_value() { take(detail::skip_value(_p + _off, _n - _off)); }

    /** True where the current value is nil. Upstream writes nil for "this
     *  interface has no such property", which is a different answer from zero
     *  and must not be read as one. */
    bool value_is_nil() const { return _off < _n && _p[_off] == 0xc0; }

    /** Descend into the current value as a map, or as an array of maps. The
     *  caller reads it with a MapReader of its own over the returned span. */
    const uint8_t* value_ptr() const { return _p + _off; }
    size_t         value_len() const { return _n - _off; }

    /** Bytes consumed so far, so a caller that descended can resume. */
    size_t offset() const { return _off; }

    /** Step over whatever is left, leaving the cursor past the map's end. */
    size_t finish() {
        if (_pending) skip_value();
        while (_seen < _count) {
            _seen++;
            _off += detail::skip_value(_p + _off, _n - _off);   // key
            _off += detail::skip_value(_p + _off, _n - _off);   // value
        }
        return _off;
    }

private:
    void take(size_t k) { _off += k; _pending = false; }

    const uint8_t* _p;
    size_t         _n;
    size_t         _off   = 0;
    size_t         _count = 0;
    size_t         _seen  = 0;
    bool           _pending = false;   /* key read, value not yet consumed */
    std::string    _key;
};

/** The array counterpart: element count plus a cursor the caller advances. */
class ArrayReader {
public:
    ArrayReader(const uint8_t* p, size_t n) : _p(p), _n(n) {
        _off = detail::unpack_array_header(p, n, _count);
    }
    size_t count() const { return _count; }
    bool   next()  { if (_seen >= _count) return false; _seen++; return true; }
    const uint8_t* value_ptr() const { return _p + _off; }
    size_t         value_len() const { return _n - _off; }
    void   advance(size_t k) { _off += k; }
    void   skip_value() { _off += detail::skip_value(_p + _off, _n - _off); }
    size_t offset() const { return _off; }

private:
    const uint8_t* _p;
    size_t         _n;
    size_t         _off   = 0;
    size_t         _count = 0;
    size_t         _seen  = 0;
};

class Packer {
public:
    template <class... Args>
    void serialize(Args&&... args) {
        // Concatenate one msgpack object per arg, no array wrapper.
        (detail::pack_one(_buf, std::forward<Args>(args)), ...);
    }

    template <class... Args>
    void to_array(Args&&... args) {
        detail::pack_array_header(_buf, sizeof...(Args));
        (detail::pack_one(_buf, std::forward<Args>(args)), ...);
    }

    const uint8_t* data() const { return _buf.data(); }
    size_t         size() const { return _buf.size(); }

private:
    std::vector<uint8_t> _buf;
};

class Unpacker {
public:
    void feed(const uint8_t* p, size_t n) {
        _raw.assign(p, p + n);
        _off = 0;
    }

    template <class T>
    void deserialize(T& out) {
        if (_off > _raw.size()) throw std::runtime_error("MsgPack: cursor past end");
        _off += detail::unpack_one(_raw.data() + _off, _raw.size() - _off, out);
    }

    /** REQUEST envelope: [float64 requested_at, bin path_hash, payload]. */
    bool from_request(double& requested_at, bin_t<uint8_t>& path_hash,
                      bin_t<uint8_t>& payload) {
        size_t count = open_array(3);
        consume_one(requested_at);
        consume_one(path_hash);
        consume_payload(payload);
        skip_rest(3, count);
        return true;
    }

    /** RESPONSE envelope: [bin request_id, payload]. */
    bool from_response(bin_t<uint8_t>& request_id, bin_t<uint8_t>& payload) {
        size_t count = open_array(2);
        consume_one(request_id);
        consume_payload(payload);
        skip_rest(2, count);
        return true;
    }

private:
    size_t open_array(size_t least) {
        if (_off > _raw.size()) throw std::runtime_error("MsgPack: cursor past end");
        size_t count = 0;
        _off += detail::unpack_array_header(_raw.data() + _off, _raw.size() - _off, count);
        if (count < least) {
            throw std::runtime_error("MsgPack: array shorter than expected");
        }
        return count;
    }

    template <class T>
    void consume_one(T& out) {
        _off += detail::unpack_one(_raw.data() + _off, _raw.size() - _off, out);
    }

    void consume_payload(bin_t<uint8_t>& out) {
        _off += detail::unpack_blob_or_object(_raw.data() + _off,
                                              _raw.size() - _off, out);
    }

    /* Trailing members we didn't ask for — peers can extend the envelope. */
    void skip_rest(size_t taken, size_t count) {
        for (size_t i = taken; i < count; ++i)
            _off += detail::skip_value(_raw.data() + _off, _raw.size() - _off);
    }

    std::vector<uint8_t> _raw;
    size_t               _off = 0;
};

} // namespace MsgPack
