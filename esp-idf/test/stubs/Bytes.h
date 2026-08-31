/* Host stand-in for microreticulum's Bytes.h.
 *
 * The real one reaches ESP-IDF's heap_caps and the microStore codec through
 * Utilities/Memory.h, none of which exists off-device. MsgPack.h — the only
 * thing in this build that wants Bytes — uses just data() and size() on it, so
 * that is all this provides. If a future test needs more of Bytes than this,
 * that is the signal to stub the allocator properly rather than to grow this. */
#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>

namespace RNS {
class Bytes {
public:
    Bytes() = default;
    Bytes(const uint8_t* p, size_t n) : _v(p, p + n) {}
    const uint8_t* data() const { return _v.data(); }
    size_t size() const { return _v.size(); }
private:
    std::vector<uint8_t> _v;
};
}
