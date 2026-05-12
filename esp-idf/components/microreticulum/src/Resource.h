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

namespace RNS {

	class ResourceData;
	class Packet;
	class Destination;
	class Link;
	class Resource;

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
	    //p static def accept(advertisement_packet, callback=None, progress_callback = None, request_id = None):

	public:
//p def hashmap_update_packet(self, plaintext):
//p def hashmap_update(self, segment, hashmap):
//p def get_map_hash(self, data):
//p def advertise(self):
//p def __advertise_job(self):
//p def watchdog_job(self):
//p def __watchdog_job(self):
//p def assemble(self):
//p def prove(self):
		void validate_proof(const Bytes& proof_data);
//p def receive_part(self, packet):
//p def request_next(self):
//p def request(self, request_data):
		void cancel();
//p def set_callback(self, callback):
//p def progress_callback(self, callback):
		float get_progress() const;
//p def get_transfer_size(self):
//p def get_data_size(self):
//p def get_parts(self):
//p def get_segments(self):
//p def get_hash(self):
//p def is_compressed(self):
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
