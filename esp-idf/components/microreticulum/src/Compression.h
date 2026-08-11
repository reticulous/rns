/*
 * bz2 (de)compression helpers shared across the port.
 *
 * Reticulum compresses two things with Python's bz2: Resource payloads
 * (Resource.cpp) and rnsh stream chunks (StreamDataMessage.compressed).
 * Every peer speaks it, so both a client reading a stock listener and a
 * listener reading a stock client must decompress. No stdio surface
 * (BZ_NO_STDIO); bzip2's malloc lands in PSRAM on this platform, and the
 * decompressors cap its working set against the caller's output bound.
 */
#pragma once

#include "Bytes.h"

#include <cstddef>

namespace RNS {

	// Decompress `in` into exactly `out_size` bytes (the length is known ahead
	// of time, e.g. a Resource advertisement's `d`). false on error.
	bool bz2_decompress(const Bytes& in, size_t out_size, Bytes& out);

	// Decompress `in` into at most `max_out` bytes when the uncompressed length
	// is not known ahead of time (an rnsh stream chunk carries no length; the
	// bound is RawChannelWriter.MAX_CHUNK_LEN). false on error or overflow.
	bool bz2_decompress_bounded(const Bytes& in, size_t max_out, Bytes& out);

	// Compress `in`; fills `out` and returns true only if compression succeeded
	// AND shrank the data (else the caller sends it uncompressed).
	bool bz2_compress(const Bytes& in, Bytes& out);

}
