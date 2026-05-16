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

#include "Destination.h"
#include "Type.h"

#include <memory>
#include <cassert>
#include <vector>
#include <array>
#include <cstdint>

namespace RNS {

	class ResourceData;
	class Packet;
	class Destination;
	class Link;
	class Resource;

	// Resource flag byte. Bit layout matches upstream RNS / ratspeak and
	// the `f` byte assembled by ResourceAdvertisement below:
	//   bit0 encrypted, bit1 compressed, bit2 split,
	//   bit3 is_request, bit4 is_response, bit5 has_metadata.
	struct ResourceFlags {
		bool encrypted    = true;
		bool compressed   = false;
		bool split        = false;
		bool is_request   = false;
		bool is_response  = false;
		bool has_metadata = false;

		uint8_t to_byte() const {
			return (uint8_t)(
				(encrypted    ? 0x01 : 0) |
				(compressed   ? 0x02 : 0) |
				(split        ? 0x04 : 0) |
				(is_request   ? 0x08 : 0) |
				(is_response  ? 0x10 : 0) |
				(has_metadata ? 0x20 : 0));
		}
		static ResourceFlags from_byte(uint8_t b) {
			return { (b & 0x01) != 0, (b & 0x02) != 0, (b & 0x04) != 0,
			         (b & 0x08) != 0, (b & 0x10) != 0, (b & 0x20) != 0 };
		}
	};

	class Resource {

	public:
		class Callbacks {
		public:
			// CBA std::function apparently not implemented in NRF52 framework
			//typedef std::function<void(const Resource& resource)> concluded;
			using concluded = void(*)(const Resource& resource);
			using progress = void(*)(const Resource& resource);
		public:
			concluded _concluded = nullptr;
			progress _progress = nullptr;
		friend class Resource;
		};

	public:
		Resource(Type::NoneConstructor none) {
			MEM("Resource NONE object created");
		}
		Resource(const Resource& resource) : _object(resource._object) {
			MEM("Resource object copy created");
		}
		//Resource(const Link& link = {Type::NONE});
		Resource(const Bytes& data, const Link& link, const Bytes& request_id, bool is_response, double timeout);
		Resource(const Bytes& data, const Link& link, bool advertise = true, bool auto_compress = true, Callbacks::concluded callback = nullptr, Callbacks::progress progress_callback = nullptr, double timeout = 0.0, int segment_index = 1, const Bytes& original_hash = {Type::NONE}, const Bytes& request_id = {Type::NONE}, bool is_response = false);
		virtual ~Resource(){
			MEM("Resource object destroyed");
		}

		Resource& operator = (const Resource& resource) {
			_object = resource._object;
			return *this;
		}
		operator bool() const {
			return _object.get() != nullptr;
		}
		bool operator < (const Resource& resource) const {
			return _object.get() < resource._object.get();
			//return _object->_hash < resource._object->_hash;
		}

	public:
		// --- Phase F resource transfer engine ---
		// ratspeak (Apache-2.0) algorithm folded into ResourceData per the
		// approach-A decision in docs/plans/phase-f-resource-port.md. The
		// attermann-shaped Resource/ResourceData/ResourceAdvertisement API
		// Link.cpp already calls is preserved; only the bodies are real now.

		// Inbound: build a receiver Resource from a decrypted RESOURCE_ADV
		// packet (link recovered from packet.link()), register it on the
		// link, and emit the initial part request. Returns a NONE Resource
		// if the advertisement is unusable.
		static Resource accept(const Packet& advertisement_packet,
		                       Callbacks::concluded concluded_callback = nullptr,
		                       Callbacks::progress progress_callback = nullptr,
		                       const Bytes& request_id = {Type::NONE});

		// Outbound: (re)send this resource's RESOURCE_ADV on its link.
		void advertise();

		// Inbound: feed one raw RESOURCE-context part. Returns true if the
		// part matched an outstanding map hash. On the final part this
		// assembles, decrypts, fires the concluded callback and sends the
		// RESOURCE_PRF proof.
		bool receive_part(const Bytes& part_data);

		// Outbound: handle a RESOURCE_REQ payload — resolve requested map
		// hashes to parts and send them as RESOURCE-context packets.
		void request(const Bytes& request_data);

		// Inbound: apply a RESOURCE_HMU hashmap-update packet
		// (resource_hash(32) || msgpack[segment, hashmap_bytes]) for
		// multi-segment resources, then resume the pull.
		void hashmap_update_packet(const Bytes& plaintext);

		// Inbound: SHA256(assembled_ciphertext || resource_hash).
		Bytes generate_proof() const;

		bool is_outbound() const;
		bool is_request() const;
		bool is_response() const;
		size_t num_parts() const;

		// Outbound: validate an inbound RESOURCE_PRF; conclude on match.
		void validate_proof(const Bytes& proof_data);
		void cancel();
		float get_progress() const;
		void set_concluded_callback(Callbacks::concluded callback);
		void set_progress_callback(Callbacks::progress callback);

		std::string toString() const;

		// getters
		const Bytes& hash() const;
		const Bytes& request_id() const;
		const Bytes& data() const;
		Type::Resource::status status() const;
		size_t size() const;
		size_t total_size() const;

		// setters

	private:
		// Shared outbound construction: encrypt with the link session key,
		// chunk into SDU parts, build the hashmap, compute resource hash +
		// expected proof, register on the link, optionally advertise.
		void _init_outbound(const Bytes& plaintext, bool advertise,
		                     const Bytes& request_id, bool is_request,
		                     bool is_response);

		// Inbound: send a RESOURCE_REQ for the next window of map hashes
		// ([_requested, _requested+_window)) and advance _requested.
		// Drives the windowed pull until every part is received.
		void _request_window();

	protected:
		std::shared_ptr<ResourceData> _object;

	};


	// ResourceAdvertisement — msgpack-shaped header that precedes a Resource
	// transfer on a Link. Wire format matches upstream Reticulum
	// `RNS/Resource.py:1234` (an 11-key msgpack map: t/d/n/h/r/o/i/l/q/f/m).
	//
	// Construction modes:
	//   - `ResourceAdvertisement()`               — empty, fill fields then pack().
	//   - `ResourceAdvertisement(const Resource&, request_id, is_response)`
	//                                              — populate fields from a Resource.
	//   - `ResourceAdvertisement::unpack(bytes)`  — decode wire bytes.
	//
	// Flat value type; no shared_ptr indirection — instances are short-lived
	// (constructed, packed, discarded — or unpacked, consumed, discarded).
	class ResourceAdvertisement {

	public:
		// Numeric fields (positive integers on the wire).
		uint32_t t = 0;            // Transfer size (compressed / on-wire bytes)
		uint32_t d = 0;            // Total uncompressed data size
		uint32_t n = 0;            // Number of parts
		uint32_t i = 1;            // Segment index (1-based)
		uint32_t l = 1;            // Total segments
		uint8_t  f = 0;            // Flags byte (assembled from c/e/s/u/p/x)

		// Byte-sequence fields.
		Bytes h;                   // Resource hash (32 B)
		Bytes r;                   // Random hash (typically 16 B)
		Bytes o;                   // Original (first-segment) hash
		Bytes m;                   // Hashmap segment payload
		Bytes q;                   // Request ID (empty == nil on the wire)

		// Decoded flag bits (also re-derived in unpack()).
		bool e = false;            // Encrypted          (bit 0)
		bool c = false;            // Compressed         (bit 1)
		bool s = false;            // Split              (bit 2)
		bool u = false;            // Is request flag    (bit 3)
		bool p = false;            // Is response flag   (bit 4)
		bool x = false;            // Has metadata       (bit 5)

		// Optional back-pointer; mirrors Python's `self.link`. Set by the
		// receive path (Link.cpp) after unpack() so callbacks see which
		// Link the advertisement arrived on. Not on the wire.
		Link* link = nullptr;

		ResourceAdvertisement() = default;

		// Populate from a transmit-side Resource. Mirrors upstream
		// `ResourceAdvertisement.__init__(resource, request_id, is_response)`.
		ResourceAdvertisement(const Resource& resource,
		                      const Bytes& request_id = {Type::NONE},
		                      bool is_response = false);

		// Serialize this advertisement to msgpack bytes. `segment` selects a
		// hashmap window when the full hashmap exceeds HASHMAP_MAX_LEN; for
		// simple single-segment resources callers can leave it at 0.
		Bytes pack(uint32_t segment = 0) const;

		// Parse msgpack bytes into a ResourceAdvertisement. Throws
		// `std::runtime_error` on a malformed wire — Link.cpp's receive path
		// catches that and drops the packet.
		static ResourceAdvertisement unpack(const Bytes& data);

		// Convenience accessors (match upstream's getter shape).
		uint32_t get_transfer_size() const { return t; }
		uint32_t get_data_size()     const { return d; }
		uint32_t get_parts()         const { return n; }
		uint32_t get_segments()      const { return l; }
		const Bytes& get_hash()      const { return h; }
		bool is_compressed()         const { return c; }
		bool is_encrypted()          const { return e; }
		bool is_split()              const { return s; }
		bool is_request()            const { return u && (bool)q; }
		bool is_response()           const { return p && (bool)q; }
		bool has_metadata()          const { return x; }
		const Bytes& request_id()    const { return q; }

		// Static peek helpers that mirror upstream's classmethod surface —
		// used by Link.cpp's RESOURCE_ADV / RESOURCE_REQ paths. Each
		// unpacks the packet plaintext and returns the requested field.
		static bool     is_request(const Packet& advertisement_packet);
		static bool     is_response(const Packet& advertisement_packet);
		static Bytes    read_request_id(const Packet& advertisement_packet);
		static uint32_t read_transfer_size(const Packet& advertisement_packet);
		static uint32_t read_size(const Packet& advertisement_packet);
	};

}
