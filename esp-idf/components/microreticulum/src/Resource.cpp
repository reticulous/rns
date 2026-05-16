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

#include "Resource.h"

#include "ResourceData.h"
#include "Reticulum.h"
#include "Transport.h"
#include "Link.h"
#include "Identity.h"
#include "Packet.h"
#include "Log.h"
#include "MsgPack.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <string>
#include <type_traits>
#include <vector>

using namespace RNS;
using namespace RNS::Type::Resource;
using namespace RNS::Utilities;

// ----------------------------------------------------------------------
// Phase F transfer-engine helpers (ratspeak algorithm, Apache-2.0)
// ----------------------------------------------------------------------
namespace {

// SHA256(data || random_hash)[:MAPHASH_LEN]
void rns_map_hash(const uint8_t* data, size_t data_len,
                  const uint8_t* rh, size_t rh_len, uint8_t out[4]) {
	Bytes in(data, data_len);
	in.append(rh, rh_len);
	const Bytes h = Identity::full_hash(in);
	std::memcpy(out, h.data(), Type::Resource::MAPHASH_LEN);
}

// SHA256(encrypted || random_hash) — full 32-byte resource hash
Bytes rns_resource_hash(const Bytes& enc, const uint8_t rh[4]) {
	Bytes in(enc.data(), enc.size());
	in.append(rh, Type::Resource::RANDOM_HASH_SIZE);
	return Identity::full_hash(in);
}

// SHA256(encrypted || resource_hash) — expected proof
Bytes rns_expected_proof(const Bytes& enc, const uint8_t rhash[32]) {
	Bytes in(enc.data(), enc.size());
	in.append(rhash, 32);
	return Identity::full_hash(in);
}

} // namespace

void Resource::_init_outbound(const Bytes& plaintext, bool advertise,
                              const Bytes& request_id, bool is_request,
                              bool is_response) {
	assert(_object);
	ResourceData& d = *_object;
	d._outbound = true;
	d._request_id = request_id;
	d._data_size = plaintext.size();
	d._total_size = plaintext.size();
	d._flags.encrypted = true;
	d._flags.compressed = false;            // bz2 deliberately disabled on this build
	d._flags.is_request = is_request;
	d._flags.is_response = is_response;

	const Bytes rh = Identity::get_random_hash();
	std::memcpy(d._random_hash, rh.data(), Type::Resource::RANDOM_HASH_SIZE);

	Bytes to_encrypt(d._random_hash, Type::Resource::RANDOM_HASH_SIZE);
	to_encrypt.append(plaintext.data(), plaintext.size());

	const Bytes encrypted = d._link.encrypt(to_encrypt);
	if (!encrypted) {
		d._status = Type::Resource::FAILED;
		ERROR("Resource: link.encrypt failed for outbound resource");
		return;
	}

	d._transfer_size = encrypted.size();
	d._size = encrypted.size();

	const Bytes rhf = rns_resource_hash(encrypted, d._random_hash);
	std::memcpy(d._resource_hash, rhf.data(), 32);
	std::memcpy(d._original_hash, d._resource_hash, 32);
	d._hash = Bytes(d._resource_hash, 32);
	d._expected_proof = rns_expected_proof(encrypted, d._resource_hash);

	const size_t sdu = Type::Resource::SDU;
	const size_t num = (encrypted.size() + sdu - 1) / sdu;
	d._parts.clear();
	d._parts.reserve(num);
	Bytes hashmap;
	for (size_t i = 0; i < num; ++i) {
		const size_t off  = i * sdu;
		const size_t clen = std::min(sdu, encrypted.size() - off);
		Bytes chunk(encrypted.data() + off, clen);
		uint8_t mh[Type::Resource::MAPHASH_LEN];
		rns_map_hash(chunk.data(), chunk.size(), d._random_hash,
		             Type::Resource::RANDOM_HASH_SIZE, mh);
		hashmap.append(mh, Type::Resource::MAPHASH_LEN);
		d._parts.push_back(chunk);
	}
	d._hashmap = hashmap;
	d._total_parts = d._parts.size();
	d._status = Type::Resource::ADVERTISED;

	d._link.register_outgoing_resource(*this);
	if (advertise) {
		this->advertise();
	}
}

Resource::Resource(const Bytes& data, const Link& link, const Bytes& request_id, bool is_response, double timeout) :
	_object(new ResourceData(link))
{
	assert(_object);
	MEM("Resource object created");
	_object->_timeout = timeout;
	// Request/response carried as a resource (Link::request / response path).
	_init_outbound(data, /*advertise=*/true, request_id,
	               /*is_request=*/!is_response, is_response);
}

Resource::Resource(const Bytes& data, const Link& link, bool advertise /*= true*/, bool auto_compress /*= true*/, Callbacks::concluded callback /*= nullptr*/, Callbacks::progress progress_callback /*= nullptr*/, double timeout /*= 0.0*/, int segment_index /*= 1*/, const Bytes& original_hash /*= {Type::NONE}*/, const Bytes& request_id /*= {Type::NONE}*/, bool is_response /*= false*/) :
	_object(new ResourceData(link))
{
	assert(_object);
	MEM("Resource object created");
	(void)auto_compress;        // bz2 unsupported on this build — see _init_outbound
	(void)segment_index;        // single-segment only (v1)
	(void)original_hash;
	_object->_timeout = timeout;
	_object->_callbacks._concluded = callback;
	_object->_callbacks._progress = progress_callback;
	_init_outbound(data, advertise, request_id,
	               /*is_request=*/((bool)request_id && !is_response), is_response);
}

void Resource::advertise() {
	assert(_object);
	ResourceData& d = *_object;
	ResourceAdvertisement adv;
	adv.t = static_cast<uint32_t>(d._transfer_size);
	adv.d = static_cast<uint32_t>(d._data_size);
	adv.n = static_cast<uint32_t>(d._total_parts);
	adv.h = Bytes(d._resource_hash, 32);
	adv.r = Bytes(d._random_hash, Type::Resource::RANDOM_HASH_SIZE);
	adv.o = Bytes(d._original_hash, 32);
	adv.i = 1;
	adv.l = 1;
	adv.q = d._request_id;
	adv.m = d._hashmap;
	adv.e = d._flags.encrypted;
	adv.c = d._flags.compressed;
	adv.s = d._flags.split;
	adv.u = d._flags.is_request;
	adv.p = d._flags.is_response;
	adv.x = d._flags.has_metadata;
	adv.f = d._flags.to_byte();
	const Bytes packed = adv.pack();
	Packet adv_packet(d._link, packed, Type::Packet::DATA, Type::Packet::RESOURCE_ADV);
	adv_packet.send();
}

Resource Resource::accept(const Packet& advertisement_packet,
                          Callbacks::concluded concluded_callback,
                          Callbacks::progress progress_callback,
                          const Bytes& request_id) {
	const Link& src_link = advertisement_packet.link();
	if (!src_link) {
		ERROR("Resource::accept: advertisement packet has no link");
		return {Type::NONE};
	}
	ResourceAdvertisement adv;
	try {
		adv = ResourceAdvertisement::unpack(
			const_cast<Packet&>(advertisement_packet).plaintext());
	}
	catch (const std::exception& e) {
		ERRORF("Resource::accept: malformed advertisement: %s", e.what());
		return {Type::NONE};
	}
	if (adv.h.size() < 32 || adv.r.size() < Type::Resource::RANDOM_HASH_SIZE) {
		ERROR("Resource::accept: advertisement missing hash/random_hash");
		return {Type::NONE};
	}

	Link link(src_link);                       // mutable handle, shares LinkData
	Resource resource{Type::NONE};
	resource._object.reset(new ResourceData(link));
	ResourceData& d = *resource._object;

	d._outbound = false;
	d._transfer_size = adv.t;
	d._size = adv.t;
	d._data_size = adv.d;
	d._total_size = adv.d;
	d._total_parts = adv.n;
	d._request_id = (bool)request_id ? request_id : adv.q;
	std::memcpy(d._resource_hash, adv.h.data(), 32);
	std::memcpy(d._random_hash, adv.r.data(), Type::Resource::RANDOM_HASH_SIZE);
	if (adv.o.size() >= 32) std::memcpy(d._original_hash, adv.o.data(), 32);
	d._hash = Bytes(d._resource_hash, 32);
	d._flags = ResourceFlags::from_byte(static_cast<uint8_t>(adv.f));
	d._received = 0;
	d._window = Type::Resource::WINDOW;
	d._callbacks._concluded = concluded_callback;
	d._callbacks._progress = progress_callback;
	d._started_at = OS::time();

	// Split the advertised hashmap into 4-byte map hashes.
	d._map_hashes.clear();
	for (size_t i = 0; i + Type::Resource::MAPHASH_LEN <= adv.m.size();
	     i += Type::Resource::MAPHASH_LEN) {
		std::array<uint8_t, Type::Resource::MAPHASH_LEN> mh{};
		std::memcpy(mh.data(), adv.m.data() + i, Type::Resource::MAPHASH_LEN);
		d._map_hashes.push_back(mh);
	}
	d._parts.assign(d._total_parts, Bytes());
	d._status = Type::Resource::TRANSFERRING;

	link.register_incoming_resource(resource);

	// Emit the initial part request:
	//   [HASHMAP_IS_NOT_EXHAUSTED][resource_hash(32)][wanted map hashes…]
	Bytes req;
	req.append((uint8_t)Type::Resource::HASHMAP_IS_NOT_EXHAUSTED);
	req.append(d._resource_hash, 32);
	const size_t want = std::min(static_cast<size_t>(d._window),
	                             d._map_hashes.size());
	for (size_t i = 0; i < want; ++i) {
		req.append(d._map_hashes[i].data(), Type::Resource::MAPHASH_LEN);
	}
	Packet req_packet(link, req, Type::Packet::DATA, Type::Packet::RESOURCE_REQ);
	req_packet.send();

	return resource;
}

bool Resource::receive_part(const Bytes& part_data) {
	assert(_object);
	ResourceData& d = *_object;
	if (d._outbound) return false;

	uint8_t mh[Type::Resource::MAPHASH_LEN];
	rns_map_hash(part_data.data(), part_data.size(), d._random_hash,
	             Type::Resource::RANDOM_HASH_SIZE, mh);

	bool accepted = false;
	for (size_t i = 0; i < d._map_hashes.size() && i < d._parts.size(); ++i) {
		if (d._parts[i].size() == 0 &&
		    std::memcmp(d._map_hashes[i].data(), mh,
		                Type::Resource::MAPHASH_LEN) == 0) {
			d._parts[i] = part_data;
			++d._received;
			accepted = true;
			break;
		}
	}
	if (!accepted) return false;

	if (d._callbacks._progress) d._callbacks._progress(*this);

	if (d._total_parts > 0 && d._received >= d._total_parts) {
		Bytes assembled;
		bool ok = true;
		for (size_t i = 0; i < d._total_parts; ++i) {
			if (d._parts[i].size() == 0) { ok = false; break; }
			assembled.append(d._parts[i].data(), d._parts[i].size());
		}
		if (!ok) {
			d._status = Type::Resource::CORRUPT;
		}
		else {
			const Bytes decrypted = d._link.decrypt(assembled);
			if (!decrypted ||
			    decrypted.size() <= Type::Resource::RANDOM_HASH_SIZE) {
				d._status = Type::Resource::CORRUPT;
			}
			else if (d._flags.compressed) {
				WARNING("Resource: dropping compressed inbound payload "
				        "(bz2 not supported on this build)");
				d._status = Type::Resource::CORRUPT;
			}
			else {
				d._data = Bytes(
					decrypted.data() + Type::Resource::RANDOM_HASH_SIZE,
					decrypted.size() - Type::Resource::RANDOM_HASH_SIZE);
				d._status = Type::Resource::COMPLETE;
				// Prove receipt over the assembled ciphertext.
				const Bytes proof = generate_proof();
				Packet proof_packet(d._link, proof, Type::Packet::PROOF,
				                    Type::Packet::RESOURCE_PRF);
				proof_packet.send();
			}
		}
		if (d._callbacks._concluded) d._callbacks._concluded(*this);
	}
	return true;
}

void Resource::request(const Bytes& request_data) {
	assert(_object);
	ResourceData& d = *_object;
	if (!d._outbound) return;
	if (request_data.size() < 1 + 32) return;

	size_t pos = 0;
	const uint8_t exhausted = request_data.data()[pos++];
	if (exhausted == Type::Resource::HASHMAP_IS_EXHAUSTED &&
	    request_data.size() > pos + Type::Resource::MAPHASH_LEN) {
		pos += Type::Resource::MAPHASH_LEN;        // skip last_map_hash
	}
	if (pos + 32 > request_data.size()) return;
	pos += 32;                                      // skip resource_hash

	while (pos + Type::Resource::MAPHASH_LEN <= request_data.size()) {
		uint8_t wanted[Type::Resource::MAPHASH_LEN];
		std::memcpy(wanted, request_data.data() + pos,
		            Type::Resource::MAPHASH_LEN);
		pos += Type::Resource::MAPHASH_LEN;
		for (size_t i = 0; i < d._parts.size(); ++i) {
			uint8_t mh[Type::Resource::MAPHASH_LEN];
			rns_map_hash(d._parts[i].data(), d._parts[i].size(),
			             d._random_hash, Type::Resource::RANDOM_HASH_SIZE, mh);
			if (std::memcmp(mh, wanted, Type::Resource::MAPHASH_LEN) == 0) {
				Packet part_packet(d._link, d._parts[i],
				                   Type::Packet::DATA, Type::Packet::RESOURCE);
				part_packet.send();
				break;
			}
		}
	}
	d._status = Type::Resource::TRANSFERRING;
}

Bytes Resource::generate_proof() const {
	assert(_object);
	const ResourceData& d = *_object;
	Bytes assembled;
	for (size_t i = 0; i < d._parts.size(); ++i) {
		assembled.append(d._parts[i].data(), d._parts[i].size());
	}
	Bytes in(assembled.data(), assembled.size());
	in.append(d._resource_hash, 32);
	return Identity::full_hash(in);
}

void Resource::validate_proof(const Bytes& proof_data) {
	assert(_object);
	ResourceData& d = *_object;
	if (proof_data.size() >= 32 && d._expected_proof.size() >= 32 &&
	    std::memcmp(proof_data.data(), d._expected_proof.data(), 32) == 0) {
		d._status = Type::Resource::COMPLETE;
		if (d._callbacks._concluded) d._callbacks._concluded(*this);
	}
}

void Resource::cancel() {
	if (!_object) return;
	if (_object->_status != Type::Resource::COMPLETE) {
		_object->_status = Type::Resource::FAILED;
	}
	if (_object->_callbacks._concluded) _object->_callbacks._concluded(*this);
}

bool Resource::is_outbound() const {
	return _object && _object->_outbound;
}

size_t Resource::num_parts() const {
	return _object ? _object->_total_parts : 0;
}

/*
:returns: The current progress of the resource transfer as a *float* between 0.0 and 1.0.
*/
float Resource::get_progress() const {
	if (!_object) return 0.0f;
	const ResourceData& d = *_object;
	if (d._status == Type::Resource::COMPLETE) return 1.0f;
	// v1 has no per-part TX accounting on the outbound side; report
	// 0 until the proof flips us to COMPLETE.
	if (d._outbound || d._total_parts == 0) return 0.0f;
	return static_cast<float>(d._received) / static_cast<float>(d._total_parts);
}

void Resource::set_concluded_callback(Callbacks::concluded callback) {
	assert(_object);
	_object->_callbacks._concluded = callback;
}

void Resource::set_progress_callback(Callbacks::progress callback) {
	assert(_object);
	_object->_callbacks._progress = callback;
}


std::string Resource::toString() const {
	if (!_object) {
		return "";
	}
    //return "<"+RNS.hexrep(self.hash,delimit=False)+"/"+RNS.hexrep(self.link.link_id,delimit=False)+">"
	//return "{Resource:" + _object->_hash.toHex() + "}";
	return "{Resource: unknown}";
}

// getters
const Bytes& Resource::hash() const {
	assert(_object);
	return _object->_hash;
}

const Bytes& Resource::request_id() const {
	assert(_object);
	return _object->_request_id;
}

const Bytes& Resource::data() const {
	assert(_object);
	return _object->_data;
}

Type::Resource::status Resource::status() const {
	assert(_object);
	return _object->_status;
}

size_t Resource::size() const {
	assert(_object);
	return _object->_size;
}

size_t Resource::total_size() const {
	assert(_object);
	return _object->_total_size;
}

// setters

// ----------------------------------------------------------------------
// ResourceAdvertisement
// ----------------------------------------------------------------------
//
// Wire format mirrors upstream `RNS/Resource.py::ResourceAdvertisement`
// (an 11-key msgpack map). Key/value shapes per Reticulum 0.9.x:
//
//   "t" uint    transfer size (compressed/on-wire bytes)
//   "d" uint    total uncompressed size
//   "n" uint    number of parts
//   "h" bin     resource hash (32 B)
//   "r" bin     random hash (typically 16 B)
//   "o" bin     original (first-segment) hash
//   "m" bin     hashmap window
//   "f" uint    flags byte (encrypted/compressed/split/req/resp/has_meta)
//   "i" uint    segment index (1-based)
//   "l" uint    total segments
//   "q" bin|nil request id, or nil if not request/response
//
// Field semantics line up 1:1 with upstream's `__init__` and `unpack`.
//
// Wrapped in `namespace RNS` because Resource.cpp's top-level
// `using namespace RNS::Type::Resource;` exposes the inner
// `Type::Resource::ResourceAdvertisement` *namespace* (constants),
// which would otherwise shadow our class name in qualified
// definitions below.

namespace RNS {

ResourceAdvertisement::ResourceAdvertisement(const Resource& resource,
                                             const Bytes& request_id /*= {Type::NONE}*/,
                                             bool is_response /*= false*/) {
	// Pull what the µR Resource currently exposes. Fields without an
	// underlying accessor in our slim ResourceData (random_hash,
	// original_hash, hashmap, segment_index, total_segments) stay at
	// their default values until Phase F fleshes Resource out — wire
	// shape is preserved either way (nil/0/empty bin on the wire).
	t = static_cast<uint32_t>(resource.size());
	d = static_cast<uint32_t>(resource.total_size());
	n = 0;                          // total_parts: not yet tracked on the µR side
	h = resource.hash();
	// r, o, m: defaulted (empty Bytes / will pack as bin8 with len 0).
	i = 1;
	l = 1;
	q = request_id;

	if ((bool)q) {
		if (is_response) { p = true;  u = false; }
		else             { u = true;  p = false; }
	}

	// Assemble flag byte to match upstream's bit layout.
	f = static_cast<uint8_t>(
	      (x ? (1u << 5) : 0u) |
	      (p ? (1u << 4) : 0u) |
	      (u ? (1u << 3) : 0u) |
	      (s ? (1u << 2) : 0u) |
	      (c ? (1u << 1) : 0u) |
	      (e ? (1u << 0) : 0u));
}

Bytes ResourceAdvertisement::pack(uint32_t /*segment*/) const {
	// Single-segment pack: emit `m` verbatim. Multi-segment slicing is a
	// Phase F concern; the field shape on the wire is identical.

	std::vector<uint8_t> out;
	MsgPack::detail::pack_map_header(out, 11);

	auto put_key = [&](const char* k) {
		MsgPack::detail::pack_fixstr(out, k, std::strlen(k));
	};
	auto put_uint = [&](const char* k, uint64_t v) {
		put_key(k);
		MsgPack::detail::pack_uint(out, v);
	};
	auto put_bin = [&](const char* k, const Bytes& b) {
		put_key(k);
		MsgPack::detail::pack_bin(out, b.data(), b.size());
	};
	auto put_bin_or_nil = [&](const char* k, const Bytes& b) {
		put_key(k);
		if ((bool)b) MsgPack::detail::pack_bin(out, b.data(), b.size());
		else         MsgPack::detail::pack_nil(out);
	};

	put_uint("t", t);
	put_uint("d", d);
	put_uint("n", n);
	put_bin ("h", h);
	put_bin ("r", r);
	put_bin ("o", o);
	put_uint("i", i);
	put_uint("l", l);
	put_bin_or_nil("q", q);
	put_uint("f", f);
	put_bin ("m", m);

	return Bytes(out.data(), out.size());
}

ResourceAdvertisement ResourceAdvertisement::unpack(const Bytes& data) {
	ResourceAdvertisement adv;
	const uint8_t* p = data.data();
	size_t         n_left = data.size();
	size_t         off = 0;

	size_t count = 0;
	off = MsgPack::detail::unpack_map_header(p, n_left, count);

	auto read_uint_into = [&](auto& dst) {
		uint64_t v = 0;
		off += MsgPack::detail::unpack_uint(p + off, n_left - off, v);
		dst = static_cast<typename std::remove_reference<decltype(dst)>::type>(v);
	};

	auto read_bin_into = [&](Bytes& dst) {
		MsgPack::bin_t<uint8_t> tmp;
		off += MsgPack::detail::unpack_bin(p + off, n_left - off, tmp);
		dst = Bytes(tmp.data(), tmp.size());
	};

	auto read_bin_or_nil_into = [&](Bytes& dst) {
		if (off >= n_left) throw std::runtime_error("ResourceAdvertisement: short value");
		if (p[off] == 0xc0) { off += 1; dst = Bytes(); return; }   // nil
		read_bin_into(dst);
	};

	for (size_t k = 0; k < count; ++k) {
		std::string key;
		off += MsgPack::detail::unpack_str(p + off, n_left - off, key);
		if (key.size() != 1) {
			// Unexpected multi-char key — skip its value defensively.
			off += MsgPack::detail::skip_value(p + off, n_left - off);
			continue;
		}
		switch (key[0]) {
			case 't': read_uint_into(adv.t);          break;
			case 'd': read_uint_into(adv.d);          break;
			case 'n': read_uint_into(adv.n);          break;
			case 'i': read_uint_into(adv.i);          break;
			case 'l': read_uint_into(adv.l);          break;
			case 'f': read_uint_into(adv.f);          break;
			case 'h': read_bin_into(adv.h);           break;
			case 'r': read_bin_into(adv.r);           break;
			case 'o': read_bin_into(adv.o);           break;
			case 'm': read_bin_into(adv.m);           break;
			case 'q': read_bin_or_nil_into(adv.q);    break;
			default:
				off += MsgPack::detail::skip_value(p + off, n_left - off);
				break;
		}
	}

	// Re-derive flag bits from the assembled byte (matches upstream's
	// unpack tail).
	adv.e = (adv.f       & 0x01) != 0;
	adv.c = ((adv.f >> 1) & 0x01) != 0;
	adv.s = ((adv.f >> 2) & 0x01) != 0;
	adv.u = ((adv.f >> 3) & 0x01) != 0;
	adv.p = ((adv.f >> 4) & 0x01) != 0;
	adv.x = ((adv.f >> 5) & 0x01) != 0;

	return adv;
}

bool ResourceAdvertisement::is_request(const Packet& advertisement_packet) {
	ResourceAdvertisement adv = unpack(const_cast<Packet&>(advertisement_packet).plaintext());
	return adv.u && (bool)adv.q;
}

bool ResourceAdvertisement::is_response(const Packet& advertisement_packet) {
	ResourceAdvertisement adv = unpack(const_cast<Packet&>(advertisement_packet).plaintext());
	return adv.p && (bool)adv.q;
}

Bytes ResourceAdvertisement::read_request_id(const Packet& advertisement_packet) {
	return unpack(const_cast<Packet&>(advertisement_packet).plaintext()).q;
}

uint32_t ResourceAdvertisement::read_transfer_size(const Packet& advertisement_packet) {
	return unpack(const_cast<Packet&>(advertisement_packet).plaintext()).t;
}

uint32_t ResourceAdvertisement::read_size(const Packet& advertisement_packet) {
	return unpack(const_cast<Packet&>(advertisement_packet).plaintext()).d;
}

} // namespace RNS
