/*
 * Copyright (c) 2023 Chad Attermann
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 */

#pragma once

/* The live routing store is the directory pool (src/Directory.h). What
 * remains here is the record shape the legacy in-memory path table and the
 * tunnel table are declared in terms of — neither is populated in this build,
 * and neither is on any packet path. */

#include "Interface.h"
#include "Packet.h"
#include "Bytes.h"

#include <set>
#include <map>

namespace RNS { namespace Persistence {

class DestinationEntry {
public:
	DestinationEntry() {}
	DestinationEntry(double timestamp, const RNS::Bytes& received_from, uint8_t announce_hops, double expires, const std::set<RNS::Bytes>& random_blobs, const Interface& receiving_interface, const Packet& announce_packet) :
		_timestamp(timestamp),
		_received_from(received_from),
		_hops(announce_hops),
		_expires(expires),
		_random_blobs(random_blobs),
		_receiving_interface(receiving_interface),
		_announce_packet(announce_packet)
	{
	}
	inline operator bool() const {
		return (_receiving_interface && _announce_packet);
	}
	inline bool operator < (const DestinationEntry& entry) const {
		// sort by ascending timestamp (oldest entries at the top)
		return _timestamp < entry._timestamp;
	}
public:
	inline Interface& receiving_interface() { return _receiving_interface; }
	inline Packet& announce_packet() { return _announce_packet; }
	// Getters and setters for receiving_interface_hash and announce_packet_hash
	inline RNS::Bytes receiving_interface_hash() const { if (_receiving_interface) return _receiving_interface.get_hash(); return {RNS::Type::NONE}; }
	inline RNS::Bytes announce_packet_hash() const { if (_announce_packet) return _announce_packet.get_hash(); return {RNS::Type::NONE}; }
public:
	double _timestamp = 0;
	// Last outbound use of this path via Transport; 0 = never used. Kept
	// separate from _timestamp, which stays the announce time.
	double _last_used = 0;
	RNS::Bytes _received_from;
	uint8_t _hops = 0;
	double _expires = 0;
	std::set<RNS::Bytes> _random_blobs;
	Interface _receiving_interface = {Type::NONE};
	Packet _announce_packet = {Type::NONE};
public:
#ifndef NDEBUG
	inline std::string debugString() const {
		std::string dump;
		dump = "DestinationEntry: timestamp=" + std::to_string(_timestamp) +
			" received_from=" + _received_from.toHex() +
			" hops=" + std::to_string(_hops) +
			" expires=" + std::to_string(_expires) +
			//" random_blobs=" + _random_blobs +
			" receiving_interface=" + receiving_interface_hash().toHex() +
			" announce_packet=" + announce_packet_hash().toHex();
		dump += " random_blobs=(";
		for (auto& blob : _random_blobs) {
			dump += blob.toHex() + ",";
		}
		dump += ")";
		return dump;
	}
#endif
};
using PathTable = std::map<RNS::Bytes, DestinationEntry, std::less<RNS::Bytes>, Utilities::Memory::ContainerAllocator<std::pair<const RNS::Bytes, DestinationEntry>>>;

} }
