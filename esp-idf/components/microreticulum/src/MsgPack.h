/*
 * MsgPack shim — narrow re-implementation of the surface
 * `attermann/microReticulum`'s upstream `Link.cpp` uses from the
 * hideakitai/MsgPack Arduino library.
 *
 * Diptych's microreticulum fork only needs four wire shapes:
 *   - serialize/deserialize a single `double`            (LRRTT echo)
 *   - serialize a single `bin_t<uint8_t>`                (transfer-size probe)
 *   - to_array(double, RNS::Bytes, RNS::Bytes)           (REQUEST)
 *   - from_array(double, bin_t<uint8_t>, bin_t<uint8_t>) (REQUEST decode)
 *   - to_array(RNS::Bytes, RNS::Bytes)                   (RESPONSE)
 *   - from_array(bin_t<uint8_t>, bin_t<uint8_t>)         (RESPONSE decode)
 *
 * The implementation directly emits/consumes the msgpack wire format
 * (https://github.com/msgpack/msgpack/blob/master/spec.md): float64,
 * fixarray/array16/array32, bin8/bin16/bin32. No upstream Arduino dep.
 */
#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <stdexcept>
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

// Per-type packers — overload set used by the fold expressions below.
inline void pack_one(std::vector<uint8_t>& out, double v)                  { pack_double(out, v); }
inline void pack_one(std::vector<uint8_t>& out, const bin_t<uint8_t>& b)   { pack_bin(out, b.data(), b.size()); }
inline void pack_one(std::vector<uint8_t>& out, const RNS::Bytes& b)       { pack_bin(out, b.data(), b.size()); }

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

} // namespace detail

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

    template <class... Args>
    bool from_array(Args&... args) {
        if (_off > _raw.size()) throw std::runtime_error("MsgPack: cursor past end");
        size_t count = 0;
        _off += detail::unpack_array_header(_raw.data() + _off, _raw.size() - _off, count);
        if (count < sizeof...(Args)) {
            throw std::runtime_error("MsgPack: array shorter than expected");
        }
        (consume_one(args), ...);
        // Skip any trailing array members we didn't ask for (defensive — peers
        // can extend the array).
        for (size_t i = sizeof...(Args); i < count; ++i) skip_one();
        return true;
    }

private:
    template <class T>
    void consume_one(T& out) {
        _off += detail::unpack_one(_raw.data() + _off, _raw.size() - _off, out);
    }

    void skip_one() {
        // Minimal best-effort skip: only the types we know how to pack.
        if (_off >= _raw.size()) throw std::runtime_error("MsgPack: short skip");
        uint8_t tag = _raw[_off];
        if (tag == 0xcb) { double tmp; consume_one(tmp); return; }
        if (tag == 0xc4 || tag == 0xc5 || tag == 0xc6) {
            bin_t<uint8_t> tmp;
            consume_one(tmp);
            return;
        }
        throw std::runtime_error("MsgPack: unsupported trailing element");
    }

    std::vector<uint8_t> _raw;
    size_t               _off = 0;
};

} // namespace MsgPack
