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
#include "bzlib.h"

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
// Phase F transfer-engine helpers — UPSTREAM Reticulum wire (RNS/Resource.py).
//
// ratspeak/microReticulum (the algorithm reference the spec named) hashes
// the *whole ciphertext* with a single random hash. Upstream Reticulum —
// the wire we must interop with (the echo is real
// Python LXMF) — instead uses TWO 4-byte random hashes:
//
//   • a "stream" random hash, prepended to the plaintext, encrypted into
//     the stream, and stripped by the receiver after decrypt;
//   • the advertised random_hash (`adv.r`), used to derive the resource
//     hash, the per-part map hashes and the proof — over the PLAINTEXT
//     and per-chunk ciphertext, never over the whole ciphertext.
//
// We follow upstream where it diverges from ratspeak.
// ----------------------------------------------------------------------
namespace {

// SHA256(data || rh)[:MAPHASH_LEN] — map hash over an encrypted chunk.
void rns_map_hash(const uint8_t* data, size_t data_len,
                  const uint8_t* rh, size_t rh_len, uint8_t out[4]) {
	Bytes in(data, data_len);
	in.append(rh, rh_len);
	const Bytes h = Identity::full_hash(in);
	std::memcpy(out, h.data(), Type::Resource::MAPHASH_LEN);
}

// SHA256(a || b) — full 32 bytes.
Bytes rns_full_hash2(const Bytes& a, const uint8_t* b, size_t blen) {
	Bytes in(a.data(), a.size());
	in.append(b, blen);
	return Identity::full_hash(in);
}

// bz2 (de)compression for Resource payloads — Reticulum/NomadNet compress
// Resource data with Python bz2; every client speaks it. Buffer-to-buffer
// only (BZ_NO_STDIO). bzip2's malloc lands in PSRAM on this platform.

// Decompress `in` into exactly `out_size` bytes (we know the uncompressed
// size from the advertisement's `d`). small=1 trades speed for ~1/3 the
// working set so a level-9 stream stays well within PSRAM. false on error.
bool rns_bz2_decompress(const Bytes& in, size_t out_size, Bytes& out) {
	if (out_size == 0) { out = Bytes(); return true; }
	std::vector<uint8_t> buf(out_size);
	unsigned int dlen = static_cast<unsigned int>(out_size);
	int r = BZ2_bzBuffToBuffDecompress(
		reinterpret_cast<char*>(buf.data()), &dlen,
		reinterpret_cast<char*>(const_cast<uint8_t*>(in.data())),
		static_cast<unsigned int>(in.size()), /*small=*/1, /*verbosity=*/0);
	if (r != BZ_OK || dlen != out_size) return false;
	out = Bytes(buf.data(), dlen);
	return true;
}

// Compress `in`; fills `out` and returns true only if compression succeeded
// AND shrank the data (else the caller sends it uncompressed). blockSize100k=1
// bounds our working set (~1 MB); any bz2 decompressor handles any block size.
bool rns_bz2_compress(const Bytes& in, Bytes& out) {
	if (in.size() == 0) return false;
	unsigned int cap = static_cast<unsigned int>(in.size() + in.size() / 100 + 600);
	std::vector<uint8_t> buf(cap);
	unsigned int clen = cap;
	int r = BZ2_bzBuffToBuffCompress(
		reinterpret_cast<char*>(buf.data()), &clen,
		reinterpret_cast<char*>(const_cast<uint8_t*>(in.data())),
		static_cast<unsigned int>(in.size()),
		/*blockSize100k=*/1, /*verbosity=*/0, /*workFactor=*/0);
	if (r != BZ_OK || clen >= in.size()) return false;
	out = Bytes(buf.data(), clen);
	return true;
}

} // namespace

void Resource::_init_outbound(const Bytes& plaintext, bool advertise,
                              const Bytes& request_id, bool is_request,
                              bool is_response, bool auto_compress) {
	assert(_object);
	ResourceData& d = *_object;
	d._outbound = true;
	d._request_id = request_id;
	// adv.d / total size are always the *uncompressed* length.
	d._data_size = plaintext.size();
	d._total_size = plaintext.size();
	d._flags.encrypted = true;
	d._flags.is_request = is_request;
	d._flags.is_response = is_response;

	// bz2-compress when it helps (every Reticulum/NomadNet client decompresses).
	// Compression only affects the *encrypted stream payload*; the resource
	// hash + proof are over the ORIGINAL uncompressed `plaintext` (upstream
	// Resource.py: self.hash = full_hash(data + random_hash) where `data` is
	// the uncompressed arg — Resource.py:404-443). map hashes are over the
	// encrypted chunks (below), independent of compression.
	Bytes compressed;
	d._flags.compressed = (auto_compress &&
	                       plaintext.size() <= Type::Resource::AUTO_COMPRESS_MAX_SIZE &&
	                       rns_bz2_compress(plaintext, compressed));
	const Bytes& on_wire = d._flags.compressed ? compressed : plaintext;
	if (d._flags.compressed)
		INFOF("Resource: bz2 %zu -> %zu B", plaintext.size(), on_wire.size());

	// Stream randomiser: prepended to the on-wire payload and encrypted into
	// the stream; the receiver strips it after decrypt. Distinct from the
	// advertised random_hash (upstream Resource.py uses two independent
	// 4-byte random hashes for these two unrelated jobs).
	const Bytes srh = Identity::get_random_hash();
	Bytes to_encrypt(srh.data(), Type::Resource::RANDOM_HASH_SIZE);
	to_encrypt.append(on_wire.data(), on_wire.size());

	const Bytes encrypted = d._link.encrypt(to_encrypt);
	if (!encrypted) {
		d._status = Type::Resource::FAILED;
		ERROR("Resource: link.encrypt failed for outbound resource");
		return;
	}

	d._transfer_size = encrypted.size();
	d._size = encrypted.size();

	// Advertised random_hash drives resource_hash / map hashes / proof.
	const Bytes rh = Identity::get_random_hash();
	std::memcpy(d._random_hash, rh.data(), Type::Resource::RANDOM_HASH_SIZE);

	// resource_hash = full_hash(plaintext || random_hash)  (UNCOMPRESSED domain)
	const Bytes rhf = rns_full_hash2(plaintext, d._random_hash,
	                                 Type::Resource::RANDOM_HASH_SIZE);
	std::memcpy(d._resource_hash, rhf.data(), 32);
	std::memcpy(d._original_hash, d._resource_hash, 32);
	d._hash = Bytes(d._resource_hash, 32);
	// expected_proof = full_hash(on_wire || resource_hash)
	d._expected_proof = rns_full_hash2(on_wire, d._resource_hash, 32);

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
	d._part_sent.assign(d._parts.size(), 0);
	d._sent_parts = 0;
	d._status = Type::Resource::ADVERTISED;

	// Watchdog parameters (upstream Resource.__init__ / __advertise_job).
	d._timeout_factor = d._link.traffic_timeout_factor();
	if (d._timeout <= 0.0) {
		d._timeout = d._link.rtt() * d._timeout_factor;
	}
	d._retries_left = Type::Resource::MAX_ADV_RETRIES;

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
	(void)segment_index;        // single-segment only (v1)
	(void)original_hash;
	_object->_timeout = timeout;
	_object->_callbacks._concluded = callback;
	_object->_callbacks._progress = progress_callback;
	_init_outbound(data, advertise, request_id,
	               /*is_request=*/((bool)request_id && !is_response), is_response,
	               auto_compress);
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
	// Window the advertised hashmap to the first segment (upstream
	// ResourceAdvertisement.pack(segment=0)). For >HASHMAP_MAX_LEN parts
	// the full hashmap won't fit one packet; the receiver pulls the rest
	// segment-by-segment via RESOURCE_REQ(exhausted) → RESOURCE_HMU.
	{
		const size_t seg_len =
			Type::Resource::ResourceAdvertisement::HASHMAP_MAX_LEN;
		const size_t adv_parts =
			std::min<size_t>(d._total_parts, seg_len);
		adv.m = Bytes(d._hashmap.data(),
		              adv_parts * Type::Resource::MAPHASH_LEN);
	}
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

	// Stamp watchdog state (upstream __advertise_job / the adv retry path
	// both refresh these). retries_left is set by the caller: _init_outbound
	// starts it at MAX_ADV_RETRIES, watchdog() decrements before re-calling.
	d._adv_sent = OS::time();
	d._last_activity = d._adv_sent;
	d._rtt = 0.0;
	d._status = Type::Resource::ADVERTISED;
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

	// Per-part map-hash table sized to the full part count. The
	// advertisement carries only the first HASHMAP_MAX_LEN hashes;
	// the rest arrive segment-by-segment via RESOURCE_HMU.
	d._map_hashes.assign(d._total_parts,
	                     std::array<uint8_t, Type::Resource::MAPHASH_LEN>{});
	d._hash_known.assign(d._total_parts, 0);
	size_t adv_hashes = adv.m.size() / Type::Resource::MAPHASH_LEN;
	for (size_t i = 0; i < adv_hashes && i < d._total_parts; ++i) {
		std::memcpy(d._map_hashes[i].data(),
		            adv.m.data() + i * Type::Resource::MAPHASH_LEN,
		            Type::Resource::MAPHASH_LEN);
		d._hash_known[i] = 1;
	}
	d._hashmap_height = std::min(adv_hashes, d._total_parts);
	d._consec       = -1;
	d._waiting_hmu  = false;
	d._parts.assign(d._total_parts, Bytes());
	d._status = Type::Resource::TRANSFERRING;

	// Watchdog / adaptive-window parameters (upstream Resource.accept).
	d._last_activity = d._started_at;
	d._retries_left = Type::Resource::MAX_RETRIES;
	d._timeout_factor = link.traffic_timeout_factor();
	d._part_timeout_factor = Type::Resource::PART_TIMEOUT_FACTOR;
	d._window_max = Type::Resource::WINDOW_MAX_SLOW;
	d._window_min = Type::Resource::WINDOW_MIN;
	d._window_flexibility = Type::Resource::WINDOW_FLEXIBILITY;
	d._req_resp = -1.0;

	link.register_incoming_resource(resource);

	INFOF("Resource::accept t=%u d=%u n=%u advhashes=%zu/%zu window=%zu",
	      (unsigned)adv.t, (unsigned)adv.d, (unsigned)adv.n,
	      d._hashmap_height, d._total_parts, d._window);
	resource._request_window();   // initial request

	return resource;
}

// Inbound request-next (upstream Resource.request_next). Scans up to
// _window missing parts from _consec+1, collecting their map hashes. If
// a needed hash is not yet known, sets the HASHMAP_IS_EXHAUSTED flag and
// appends the last known map hash so the sender replies with the next
// hashmap segment (RESOURCE_HMU). Wire:
//   [flag(1)] [last_map_hash(4) iff exhausted] [resource_hash(32)]
//   [requested map hashes (N*4)]
void Resource::_request_window() {
	assert(_object);
	ResourceData& d = *_object;
	if (d._outbound || d._waiting_hmu) return;
	if (d._status != Type::Resource::TRANSFERRING) return;

	uint8_t flag = Type::Resource::HASHMAP_IS_NOT_EXHAUSTED;
	Bytes requested;
	size_t i = 0;
	long pn = d._consec + 1;
	d._outstanding_parts = 0;
	for (size_t s = 0; s < (size_t)d._window; ++s) {
		if (pn < 0 || (size_t)pn >= d._total_parts) break;
		if (d._parts[(size_t)pn].size() == 0) {
			if (d._hash_known[(size_t)pn]) {
				requested.append(d._map_hashes[(size_t)pn].data(),
				                 Type::Resource::MAPHASH_LEN);
				++d._outstanding_parts;
				++i;
			} else {
				flag = Type::Resource::HASHMAP_IS_EXHAUSTED;
			}
		}
		++pn;
		if (i >= (size_t)d._window ||
		    flag == Type::Resource::HASHMAP_IS_EXHAUSTED) break;
	}

	if (requested.size() == 0 &&
	    flag != Type::Resource::HASHMAP_IS_EXHAUSTED)
		return;   // window already satisfied; nothing to ask for

	Bytes req;
	req.append(flag);
	if (flag == Type::Resource::HASHMAP_IS_EXHAUSTED) {
		if (d._hashmap_height > 0)
			req.append(d._map_hashes[d._hashmap_height - 1].data(),
			           Type::Resource::MAPHASH_LEN);
		else
			req.append(d._resource_hash, Type::Resource::MAPHASH_LEN);
		d._waiting_hmu = true;
	}
	req.append(d._resource_hash, 32);
	req.append(requested.data(), requested.size());
	Packet req_packet(d._link, req, Type::Packet::DATA,
	                  Type::Packet::RESOURCE_REQ);
	req_packet.send();

	// Request round-trip bookkeeping (upstream request_next). The payload
	// size stands in for upstream's len(request_packet.raw) — header/crypto
	// overhead is a few dozen bytes and only skews the rate estimate.
	d._last_activity = OS::time();
	d._req_sent = d._last_activity;
	d._req_sent_bytes = req.size();
	d._rtt_rxd_bytes_at_part_req = d._rtt_rxd_bytes;
	d._req_resp = -1.0;
	INFOF("Resource::request_next consec=%ld want=%zu exhausted=%d "
	      "known=%zu/%zu", d._consec, i,
	      (int)(flag == Type::Resource::HASHMAP_IS_EXHAUSTED),
	      d._hashmap_height, d._total_parts);
}

// Apply a RESOURCE_HMU packet: resource_hash(32) || msgpack[segment,
// hashmap_bytes]. Fills _map_hashes at segment*HASHMAP_MAX_LEN and
// resumes the pull (upstream hashmap_update_packet / hashmap_update).
void Resource::hashmap_update_packet(const Bytes& plaintext) {
	assert(_object);
	ResourceData& d = *_object;
	if (d._status == Type::Resource::FAILED) return;
	if (plaintext.size() <= 32) return;
	d._last_activity = OS::time();

	const uint8_t* p = plaintext.data() + 32;
	size_t n = plaintext.size() - 32;
	try {
		size_t off = 0, count = 0;
		off += MsgPack::detail::unpack_array_header(p + off, n - off, count);
		if (count < 2) return;
		uint64_t segment = 0;
		off += MsgPack::detail::unpack_uint(p + off, n - off, segment);
		MsgPack::bin_t<uint8_t> hm;
		off += MsgPack::detail::unpack_bin(p + off, n - off, hm);

		const size_t seg_len =
			RNS::Type::Resource::ResourceAdvertisement::HASHMAP_MAX_LEN;
		const size_t hashes = hm.size() / Type::Resource::MAPHASH_LEN;
		for (size_t i = 0; i < hashes; ++i) {
			size_t idx = i + (size_t)segment * seg_len;
			if (idx >= d._total_parts) break;
			if (!d._hash_known[idx]) {
				std::memcpy(d._map_hashes[idx].data(),
				            hm.data() + i * Type::Resource::MAPHASH_LEN,
				            Type::Resource::MAPHASH_LEN);
				d._hash_known[idx] = 1;
				if (idx + 1 > d._hashmap_height) d._hashmap_height = idx + 1;
			}
		}
		INFOF("Resource::hashmap_update seg=%llu +%zu known=%zu/%zu",
		      (unsigned long long)segment, hashes,
		      d._hashmap_height, d._total_parts);
	}
	catch (const std::exception& e) {
		WARNINGF("Resource::hashmap_update parse failed: %s", e.what());
		return;
	}
	d._waiting_hmu = false;
	_request_window();
}

bool Resource::receive_part(const Bytes& part_data) {
	assert(_object);
	ResourceData& d = *_object;
	if (d._outbound) return false;

	const double now = OS::time();
	d._last_activity = now;
	d._retries_left = Type::Resource::MAX_RETRIES;

	// First part after a request: take an rtt sample and derive the
	// request→response rate (upstream receive_part's req_resp block).
	if (d._req_resp < 0.0) {
		d._req_resp = now;
		const double rtt_sample = d._req_resp - d._req_sent;
		d._part_timeout_factor = Type::Resource::PART_TIMEOUT_FACTOR_AFTER_RTT;
		if (d._rtt <= 0.0) {
			d._rtt = d._link.rtt();
		}
		else if (rtt_sample < d._rtt) {
			d._rtt = std::max(d._rtt - d._rtt * 0.05, rtt_sample);
		}
		else if (rtt_sample > d._rtt) {
			d._rtt = std::min(d._rtt + d._rtt * 0.05, rtt_sample);
		}
		if (rtt_sample > 0.0) {
			// part_data.size() stands in for len(packet.raw); see the
			// matching note in _request_window().
			const double req_resp_cost = (double)(part_data.size() + d._req_sent_bytes);
			d._req_resp_rtt_rate = req_resp_cost / rtt_sample;
			if (d._req_resp_rtt_rate > Type::Resource::RATE_FAST &&
			    d._fast_rate_rounds < Type::Resource::FAST_RATE_THRESHOLD) {
				++d._fast_rate_rounds;
				if (d._fast_rate_rounds == Type::Resource::FAST_RATE_THRESHOLD) {
					d._window_max = Type::Resource::WINDOW_MAX_FAST;
				}
			}
		}
	}

	uint8_t mh[Type::Resource::MAPHASH_LEN];
	rns_map_hash(part_data.data(), part_data.size(), d._random_hash,
	             Type::Resource::RANDOM_HASH_SIZE, mh);

	bool accepted = false;
	for (size_t i = 0; i < d._total_parts; ++i) {
		if (d._hash_known[i] && d._parts[i].size() == 0 &&
		    std::memcmp(d._map_hashes[i].data(), mh,
		                Type::Resource::MAPHASH_LEN) == 0) {
			d._parts[i] = part_data;
			++d._received;
			d._rtt_rxd_bytes += part_data.size();
			if (d._outstanding_parts > 0) --d._outstanding_parts;
			accepted = true;
			break;
		}
	}
	if (!accepted) return false;

	// Advance the consecutive-completed height.
	while (d._consec + 1 < (long)d._total_parts &&
	       d._parts[(size_t)(d._consec + 1)].size() != 0)
		++d._consec;

	if ((d._received % 16) == 0 || d._received == d._total_parts)
		INFOF("Resource::receive_part %zu/%zu consec=%ld",
		      d._received, d._total_parts, d._consec);

	if (d._callbacks._progress) d._callbacks._progress(*this);

	// Request the next window only when the current one has drained
	// (upstream receive_part: `elif self.outstanding_parts == 0`). Asking
	// again while parts are still in flight makes the sender resend them.
	if (d._received < d._total_parts && !d._waiting_hmu &&
	    d._outstanding_parts == 0) {
		// Window adaptation: grow toward window_max; track the achieved
		// request→data rate to escalate window_max (fast links) or cap it
		// (very slow links).
		if (d._window < d._window_max) {
			++d._window;
			if ((d._window - d._window_min) > (d._window_flexibility - 1)) {
				++d._window_min;
			}
		}
		if (d._req_sent > 0.0) {
			const double round_rtt = now - d._req_sent;
			const size_t transferred = d._rtt_rxd_bytes - d._rtt_rxd_bytes_at_part_req;
			if (round_rtt > 0.0) {
				d._req_data_rtt_rate = (double)transferred / round_rtt;
				_update_eifr();
				d._rtt_rxd_bytes_at_part_req = d._rtt_rxd_bytes;
				if (d._req_data_rtt_rate > Type::Resource::RATE_FAST &&
				    d._fast_rate_rounds < Type::Resource::FAST_RATE_THRESHOLD) {
					++d._fast_rate_rounds;
					if (d._fast_rate_rounds == Type::Resource::FAST_RATE_THRESHOLD) {
						d._window_max = Type::Resource::WINDOW_MAX_FAST;
					}
				}
				if (d._fast_rate_rounds == 0 &&
				    d._req_data_rtt_rate < Type::Resource::RATE_VERY_SLOW &&
				    d._very_slow_rate_rounds < Type::Resource::VERY_SLOW_RATE_THRESHOLD) {
					++d._very_slow_rate_rounds;
					if (d._very_slow_rate_rounds == Type::Resource::VERY_SLOW_RATE_THRESHOLD) {
						d._window_max = Type::Resource::WINDOW_MAX_VERY_SLOW;
					}
				}
			}
		}
		_request_window();
	}

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
			else {
				// Strip the 4-byte stream randomiser prepended pre-encrypt to
				// get the on-wire payload (bz2-compressed when adv.c was set).
				const Bytes onwire(
					decrypted.data() + Type::Resource::RANDOM_HASH_SIZE,
					decrypted.size() - Type::Resource::RANDOM_HASH_SIZE);
				// Decompress FIRST: upstream computes resource_hash + proof over
				// the *uncompressed* data (Resource.py:404-443), so the
				// integrity check and proof must be over the decompressed bytes,
				// not the on-wire (compressed) ones.
				Bytes data;
				bool data_ok = true;
				if (d._flags.compressed) {
					if (!rns_bz2_decompress(onwire, d._total_size, data)) {
						WARNING("Resource: bz2 decompress failed — corrupt");
						data_ok = false;
					}
				} else {
					data = onwire;
				}
				if (!data_ok) {
					d._status = Type::Resource::CORRUPT;
				}
				else {
					// Integrity: full_hash(data || random_hash) == resource_hash.
					const Bytes calc = rns_full_hash2(
						data, d._random_hash, Type::Resource::RANDOM_HASH_SIZE);
					if (calc.size() < 32 ||
					    std::memcmp(calc.data(), d._resource_hash, 32) != 0) {
						WARNING("Resource: assembled-hash mismatch — corrupt");
						d._status = Type::Resource::CORRUPT;
					}
					else {
						d._data = data;
						d._status = Type::Resource::COMPLETE;
						// proof_data = resource_hash || full_hash(data || resource_hash),
						// over the decompressed data — matches the sender's
						// expected_proof (Resource.py: over uncompressed data).
						const Bytes proof = generate_proof();
						Bytes proof_data(d._resource_hash, 32);
						proof_data.append(proof.data(), proof.size());
						Packet proof_packet(d._link, proof_data,
						                    Type::Packet::PROOF,
						                    Type::Packet::RESOURCE_PRF);
						proof_packet.send();
					}
				}
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
	if (d._status == Type::Resource::FAILED) return;
	if (request_data.size() < 1 + 32) return;

	// A part request answers our advertisement: first one measures the
	// resource rtt; every one proves the receiver is alive (upstream
	// Resource.request head).
	const double req_now = OS::time();
	if (d._rtt <= 0.0 && d._adv_sent > 0.0) {
		d._rtt = req_now - d._adv_sent;
	}
	d._status = Type::Resource::TRANSFERRING;
	d._retries_left = Type::Resource::MAX_RETRIES;

	size_t pos = 0;
	const uint8_t exhausted = request_data.data()[pos++];
	const bool wants_more_hashmap =
		(exhausted == Type::Resource::HASHMAP_IS_EXHAUSTED);
	uint8_t last_map_hash[Type::Resource::MAPHASH_LEN] = {0};
	if (wants_more_hashmap) {
		if (request_data.size() < pos + Type::Resource::MAPHASH_LEN + 32)
			return;
		std::memcpy(last_map_hash, request_data.data() + pos,
		            Type::Resource::MAPHASH_LEN);
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
				if (i < d._part_sent.size() && !d._part_sent[i]) {
					d._part_sent[i] = 1;
					++d._sent_parts;
				}
				d._last_activity = OS::time();
				d._last_part_sent = d._last_activity;
				break;
			}
		}
	}

	// Peer's known hashmap is exhausted: reply with the next segment as a
	// RESOURCE_HMU (upstream Resource.request's wants_more_hashmap branch).
	// last_map_hash is the last hash the receiver knows; the part it maps
	// to is at index k, so part_index = k+1 must land on a segment
	// boundary and the next segment to send is part_index/HASHMAP_MAX_LEN.
	if (wants_more_hashmap) {
		const size_t mhl    = Type::Resource::MAPHASH_LEN;
		const size_t seglen =
			Type::Resource::ResourceAdvertisement::HASHMAP_MAX_LEN;
		size_t part_index = 0;
		bool   found      = false;
		for (size_t i = 0; i < d._total_parts &&
		                    (i + 1) * mhl <= d._hashmap.size(); ++i) {
			if (std::memcmp(d._hashmap.data() + i * mhl,
			                last_map_hash, mhl) == 0) {
				part_index = i + 1;
				found = true;
				break;
			}
		}
		if (!found || seglen == 0 || (part_index % seglen) != 0) {
			WARNINGF("Resource::request HMU sequencing error "
			         "(found=%d part_index=%zu seglen=%zu) — cancelling",
			         (int)found, part_index, seglen);
			cancel();
			return;
		}
		const size_t segment = part_index / seglen;
		const size_t hm_start = segment * seglen;
		const size_t hm_end   =
			std::min((segment + 1) * seglen, (size_t)d._total_parts);

		std::vector<uint8_t> mp;
		MsgPack::detail::pack_array_header(mp, 2);
		MsgPack::detail::pack_uint(mp, (uint64_t)segment);
		if (hm_end > hm_start &&
		    hm_end * mhl <= d._hashmap.size()) {
			MsgPack::detail::pack_bin(mp,
				d._hashmap.data() + hm_start * mhl,
				(hm_end - hm_start) * mhl);
		} else {
			MsgPack::detail::pack_bin(mp, nullptr, 0);
		}

		Bytes hmu(d._resource_hash, 32);
		hmu.append(mp.data(), mp.size());
		Packet hmu_packet(d._link, hmu, Type::Packet::DATA,
		                  Type::Packet::RESOURCE_HMU);
		hmu_packet.send();
		d._last_activity = OS::time();
		INFOF("Resource::request HMU seg=%zu parts[%zu..%zu) of %zu",
		      segment, hm_start, hm_end, (size_t)d._total_parts);
	}

	// Every part has been sent at least once — the rest of the transfer is
	// retransmits and the proof; switch the watchdog to the proof timeout
	// (upstream: status = AWAITING_PROOF, retries_left = 3).
	if (d._sent_parts >= d._parts.size()) {
		d._status = Type::Resource::AWAITING_PROOF;
		d._retries_left = 3;
	}
}

Bytes Resource::generate_proof() const {
	assert(_object);
	const ResourceData& d = *_object;
	// proof = full_hash(payload || resource_hash)  (payload == assembled
	// plaintext, == upstream Resource.prove's full_hash(self.data+self.hash)).
	return rns_full_hash2(d._data, d._resource_hash, 32);
}

void Resource::validate_proof(const Bytes& proof_data) {
	assert(_object);
	ResourceData& d = *_object;
	// proof_data on the wire is resource_hash(32) || proof(32); the proof
	// is the trailing 32 bytes (upstream Resource.validate_proof).
	if (proof_data.size() >= 64 && d._expected_proof.size() >= 32 &&
	    std::memcmp(proof_data.data() + 32, d._expected_proof.data(), 32) == 0) {
		d._status = Type::Resource::COMPLETE;
		if (d._callbacks._concluded) d._callbacks._concluded(*this);
	}
}

void Resource::cancel() {
	if (!_object) return;
	if (_object->_status != Type::Resource::COMPLETE) {
		_object->_status = Type::Resource::FAILED;
		// Tell the receiver we gave up so it can drop its inbound state
		// (upstream cancel: RESOURCE_ICL from the initiator).
		if (_object->_outbound) {
			Packet cancel_packet(_object->_link, Bytes(_object->_resource_hash, 32),
			                     Type::Packet::DATA, Type::Packet::RESOURCE_ICL);
			cancel_packet.send();
		}
	}
	if (_object->_callbacks._concluded) _object->_callbacks._concluded(*this);
}

// Upstream update_eifr: expected in-flight rate in bits/s. Before any
// request→data rate sample exists, estimate from the link establishment
// cost over one rtt (upstream also consults the link's previous-resource
// eifr, which this port doesn't track).
void Resource::_update_eifr() {
	assert(_object);
	ResourceData& d = *_object;
	const double rtt = d._rtt > 0.0 ? d._rtt : d._link.rtt();
	double eifr;
	if (d._req_data_rtt_rate != 0.0) {
		eifr = d._req_data_rtt_rate * 8.0;
	}
	else if (rtt > 0.0) {
		eifr = (double)d._link.establishment_cost() * 8.0 / rtt;
	}
	else {
		eifr = 0.0;
	}
	d._eifr = eifr;
}

// Poll-driven port of upstream Resource.__watchdog_job. Each state's
// deadline arithmetic matches upstream line-for-line; instead of a thread
// sleeping until the deadline, Transport::jobs calls this periodically and
// the deadline is re-checked against `now`. Retries send packets through
// Transport::outbound, so this must never run inside the jobs lock (see
// the call site in Transport::jobs).
void Resource::watchdog(double now) {
	if (!_object) return;
	ResourceData& d = *_object;

	switch (d._status) {

	case Type::Resource::ADVERTISED: {
		// Sender: no part request answered our advertisement yet.
		double tmo = d._timeout;
		if (tmo <= 0.0) tmo = d._link.rtt() * d._timeout_factor;
		if (tmo <= 0.0) return;   // link rtt not yet measured; check next tick
		if (now > d._adv_sent + tmo + Type::Resource::PROCESSING_GRACE) {
			if (d._retries_left <= 0) {
				DEBUG("Resource transfer timeout after sending advertisement");
				cancel();
			}
			else {
				DEBUGF("Resource %s: no part requests received, retrying advertisement (%d left)",
					d._hash.toHex().c_str(), d._retries_left);
				--d._retries_left;
				advertise();   // re-stamps _adv_sent/_last_activity
			}
		}
		break;
	}

	case Type::Resource::TRANSFERRING: {
		if (!d._outbound) {
			// Receiver: re-request outstanding parts when the expected
			// time-of-flight (from the expected in-flight rate) has passed.
			const int retries_used = Type::Resource::MAX_RETRIES - d._retries_left;
			const double extra_wait = retries_used * Type::Resource::PER_RETRY_DELAY;
			_update_eifr();
			if (d._eifr <= 0.0) return;   // no rate estimate yet
			const double sdu_bits = (double)Type::Resource::SDU * 8.0;
			const double expected_hmu_wait =
				(d._waiting_hmu || d._outstanding_parts == 0)
					? (sdu_bits * Type::Resource::HMU_WAIT_FACTOR) / d._eifr : 0.0;
			const double expected_tof =
				((double)d._outstanding_parts * sdu_bits) / d._eifr;
			double deadline;
			if (d._req_resp_rtt_rate != 0.0) {
				deadline = d._last_activity +
					d._part_timeout_factor * expected_tof + expected_hmu_wait +
					Type::Resource::RETRY_GRACE_TIME + extra_wait;
			}
			else {
				// Pre-rate-sample fallback; the missing *8 on the sdu term
				// is upstream's formula verbatim (Resource.py __watchdog_job).
				deadline = d._last_activity +
					d._part_timeout_factor * ((3.0 * Type::Resource::SDU) / d._eifr) +
					Type::Resource::RETRY_GRACE_TIME + extra_wait;
			}
			if (now > deadline) {
				if (d._retries_left > 0) {
					DEBUGF("Resource %s: timed out waiting for %zu parts, requesting retry (%d left)",
						d._hash.toHex().c_str(), d._outstanding_parts, d._retries_left);
					if (d._window > d._window_min) {
						--d._window;
						if (d._window_max > d._window_min) {
							--d._window_max;
							if ((d._window_max - d._window) > (d._window_flexibility - 1)) {
								--d._window_max;
							}
						}
					}
					--d._retries_left;
					d._waiting_hmu = false;
					_request_window();
				}
				else {
					cancel();
				}
			}
		}
		else {
			// Sender: give the receiver its full retry budget plus grace
			// before declaring the transfer dead.
			const double rtt = d._rtt > 0.0 ? d._rtt : d._link.rtt();
			const int mr = Type::Resource::MAX_RETRIES;
			const double max_extra_wait =
				Type::Resource::PER_RETRY_DELAY * (mr * (mr + 1) / 2.0);
			const double max_wait = rtt * d._timeout_factor * mr +
				Type::Resource::SENDER_GRACE_TIME + max_extra_wait;
			if (now > d._last_activity + max_wait) {
				DEBUGF("Resource %s: timed out waiting for part requests",
					d._hash.toHex().c_str());
				cancel();
			}
		}
		break;
	}

	case Type::Resource::AWAITING_PROOF: {
		// Sender: all parts sent, waiting for the receiver's proof. Proof
		// packets are much smaller than a req/resp round trip, hence the
		// reduced timeout factor. Upstream spends its retries querying the
		// network packet cache (Transport.cache_request); this port has no
		// packet cache, so each retry just extends the wait window before
		// giving up.
		const double rtt = d._rtt > 0.0 ? d._rtt : d._link.rtt();
		if (rtt <= 0.0) return;
		if (now > d._last_part_sent +
		          rtt * Type::Resource::PROOF_TIMEOUT_FACTOR +
		          Type::Resource::SENDER_GRACE_TIME) {
			if (d._retries_left <= 0) {
				DEBUGF("Resource %s: timed out waiting for proof",
					d._hash.toHex().c_str());
				cancel();
			}
			else {
				DEBUGF("Resource %s: no proof received, extending wait (%d left)",
					d._hash.toHex().c_str(), d._retries_left);
				--d._retries_left;
				d._last_part_sent = now;
			}
		}
		break;
	}

	default:
		break;
	}
}

bool Resource::is_outbound() const {
	return _object && _object->_outbound;
}

bool Resource::is_request() const {
	return _object && _object->_flags.is_request;
}

bool Resource::is_response() const {
	return _object && _object->_flags.is_response;
}

size_t Resource::num_parts() const {
	return _object ? _object->_total_parts : 0;
}

// Spangap fork: RESOURCE_REQ packet-hash dedupe (backport of upstream
// attermann/microReticulum 032c751 req_hashlist). Upstream keeps the list
// unbounded; over half-duplex LoRa a request can be retransmitted many
// times across a long transfer, so bound it to the most recent
// REQ_HASHLIST_MAX hashes — a retransmit always arrives within a few RTTs
// of the original, so an evicted-then-replayed request only costs a
// redundant part resend (the pre-fork behaviour), never a correctness bug.
static const size_t REQ_HASHLIST_MAX = 64;

bool Resource::has_request_hash(const Bytes& packet_hash) const {
	assert(_object);
	for (const auto& seen : _object->_req_hashlist) {
		if (seen == packet_hash) return true;
	}
	return false;
}

void Resource::note_request_hash(const Bytes& packet_hash) {
	assert(_object);
	if (_object->_req_hashlist.size() >= REQ_HASHLIST_MAX) {
		_object->_req_hashlist.erase(_object->_req_hashlist.begin());
	}
	_object->_req_hashlist.push_back(packet_hash);
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
