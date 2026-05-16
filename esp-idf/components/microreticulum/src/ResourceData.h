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

#include "Resource.h"

#include "Interface.h"
#include "Packet.h"
#include "Destination.h"
#include "Bytes.h"
#include "Type.h"
#include "Cryptography/Fernet.h"

#include <vector>
#include <array>
#include <cstdint>

namespace RNS {

	class ResourceData {
	public:
		ResourceData(const Link& link) : _link(link) {}
		virtual ~ResourceData() {}
	private:
		Link _link;
		Bytes _hash;                       // resource_hash (32 B) as Bytes
		Bytes _request_id;
		Bytes _data;                       // inbound: assembled plaintext
		Type::Resource::status _status = Type::Resource::NONE;
		size_t _size = 0;                  // on-wire (encrypted) size
		size_t _total_size = 0;            // original (plaintext) size
		Resource::Callbacks _callbacks;

		// --- Phase F transfer-engine state (ratspeak algorithm) ---
		bool     _outbound = false;
		std::vector<Bytes> _parts;         // out: encrypted chunks; in: received slots
		Bytes    _hashmap;                 // concatenated 4-byte map hashes
		uint8_t  _resource_hash[32] = {};
		uint8_t  _random_hash[4] = {};
		uint8_t  _original_hash[32] = {};
		Bytes    _expected_proof;          // outbound
		std::vector<std::array<uint8_t, 4>> _map_hashes;  // inbound
		size_t   _transfer_size = 0;
		size_t   _data_size = 0;
		size_t   _total_parts = 0;
		size_t   _received = 0;
		size_t   _requested = 0;            // inbound: map-hash indices requested so far
		size_t   _window = Type::Resource::WINDOW;
		ResourceFlags _flags;
		double   _started_at = 0.0;
		double   _timeout = 0.0;

	friend class Resource;
	friend class ResourceAdvertisement;
	};

}
