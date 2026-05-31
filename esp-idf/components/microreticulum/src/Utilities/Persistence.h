/*
 * Copyright (c) 2023 Chad Attermann
 * Apache-2.0. Full license in LICENSE.upstream at component root.
 *
 * Spangap fork: ArduinoJson dependency removed entirely. The Persistence
 * layer was upstream's hourly auto-save mechanism for destination_table /
 * packet_hashlist / known_destinations / tunnels — written through
 * OS::read_file / OS::write_file (now no-op'd, see plan §10.5) using
 * ArduinoJson + msgpack as the wire format.
 *
 * Per plan §10.5, "rnsd owns persistence end-to-end via the CLI/cron
 * path". Upstream's serialization machinery is therefore dead code in our
 * configuration. The function signatures here are kept (Transport.cpp
 * still references `Persistence::serialize` and `Persistence::deserialize`
 * via templates) but the bodies short-circuit to 0 / empty. When we add
 * back a real persistence path it'll be a fresh cJSON/msgpack-c
 * implementation, not a port of this code.
 */

#pragma once

#include "Type.h"
#include "Utilities/Crc.h"
#include "Persistence/DestinationEntry.h"

#include <map>
#include <vector>
#include <set>
#include <string>

namespace RNS { namespace Persistence {

	// Upstream maintained a process-wide _document + _buffer. Both gone
	// in the spangap fork — kept as comments here so future readers know
	// where to look for the upstream serialization model.
	//   static JsonDocument _document;
	//   static Bytes _buffer(Type::Persistence::BUFFER_MAXSIZE);

	// All four entry points become no-ops. CRC of an empty buffer is 0;
	// serialize/deserialize "wrote/read 0 bytes" — callers (Transport.cpp)
	// already handle that as the "nothing in cache" path.
	template <typename T> uint32_t crc(const T& /*obj*/) { return 0; }
	template <typename T> size_t serialize(const T& /*obj*/, const char* /*file_path*/) { return 0; }
	template <typename T> size_t deserialize(T& /*obj*/, const char* /*file_path*/) { return 0; }

	template <typename T, typename Compare, typename Allocator>
	uint32_t crc(std::map<Bytes, T, Compare, Allocator>& /*map*/) { return 0; }

	template <typename T, typename Compare, typename Allocator>
	size_t serialize(std::map<Bytes, T, Compare, Allocator>& /*map*/, const char* /*file_path*/, uint32_t& crc_out) {
		crc_out = 0;
		return 0;
	}

	template <typename T, typename Compare, typename Allocator>
	size_t serialize(std::map<Bytes, T, Compare, Allocator>& map, const char* file_path) {
		uint32_t crc_out;
		return serialize(map, file_path, crc_out);
	}

	template <typename T, typename Compare, typename Allocator>
	size_t deserialize(std::map<Bytes, T, Compare, Allocator>& map, const char* /*file_path*/, uint32_t& crc_out) {
		map.clear();
		crc_out = 0;
		return 0;
	}

	template <typename T, typename Compare, typename Allocator>
	size_t deserialize(std::map<Bytes, T, Compare, Allocator>& map, const char* file_path) {
		uint32_t crc_out;
		return deserialize(map, file_path, crc_out);
	}

} }
