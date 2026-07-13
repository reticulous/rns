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
		// inbound: per-part map hashes, sized to _total_parts. Only the
		// first HASHMAP_MAX_LEN arrive in the advertisement; the rest are
		// pulled segment-by-segment via RESOURCE_HMU (multi-segment).
		std::vector<std::array<uint8_t, 4>> _map_hashes;
		std::vector<uint8_t> _hash_known;   // 1 where _map_hashes[i] is valid
		size_t   _transfer_size = 0;
		size_t   _data_size = 0;
		size_t   _total_parts = 0;
		size_t   _received = 0;
		long     _consec = -1;              // consecutive_completed_height
		size_t   _hashmap_height = 0;       // count of known map hashes
		bool     _waiting_hmu = false;      // awaiting a hashmap-update segment
		size_t   _window = Type::Resource::WINDOW;
		ResourceFlags _flags;
		double   _started_at = 0.0;
		double   _timeout = 0.0;

		// --- Upstream watchdog state (RNS Resource.py __watchdog_job) ---
		// Times are OS::time() seconds; 0 / negative sentinels mirror
		// upstream's `None`.
		double   _last_activity = 0.0;
		double   _adv_sent = 0.0;           // outbound: last advertisement tx
		double   _last_part_sent = 0.0;     // outbound: last part tx
		double   _req_sent = 0.0;           // inbound: last RESOURCE_REQ tx
		double   _req_resp = -1.0;          // inbound: first part after req; <0 == None
		double   _rtt = 0.0;                // measured resource rtt; 0 == None
		int      _retries_left = 0;
		uint8_t  _timeout_factor = 1;       // link traffic_timeout_factor at init
		uint8_t  _part_timeout_factor = Type::Resource::PART_TIMEOUT_FACTOR;
		// Adaptive window (inbound).
		size_t   _window_max = Type::Resource::WINDOW_MAX_SLOW;
		size_t   _window_min = Type::Resource::WINDOW_MIN;
		size_t   _window_flexibility = Type::Resource::WINDOW_FLEXIBILITY;
		uint8_t  _fast_rate_rounds = 0;
		uint8_t  _very_slow_rate_rounds = 0;
		size_t   _outstanding_parts = 0;    // inbound: parts requested, not yet seen
		// Rate tracking (inbound) for eifr / window-max escalation.
		size_t   _req_sent_bytes = 0;
		size_t   _rtt_rxd_bytes = 0;
		size_t   _rtt_rxd_bytes_at_part_req = 0;
		double   _req_resp_rtt_rate = 0.0;
		double   _req_data_rtt_rate = 0.0;
		double   _eifr = 0.0;               // expected in-flight rate (bits/s)
		// Outbound: which parts have been sent at least once (drives the
		// TRANSFERRING → AWAITING_PROOF transition, upstream `sent_parts`).
		std::vector<uint8_t> _part_sent;
		size_t   _sent_parts = 0;

	friend class Resource;
	friend class ResourceAdvertisement;
	};

}
