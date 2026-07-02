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

#include "Channel.h"

#include "Link.h"
#include "Packet.h"
#include "Log.h"
#include "Utilities/OS.h"

#include <list>
#include <algorithm>
#include <cmath>

using namespace RNS;
using namespace RNS::Utilities;

namespace RNS {

	// Backing object for the Channel handle. The Link⇄Channel "outlet" logic
	// (Channel.py's LinkChannelOutlet) is folded inline here — the object holds
	// the Link and speaks to it directly.
	class ChannelData {
	public:
		struct Envelope {
			uint16_t sequence = 0;
			Bytes    raw;                    // TX: packed 6B header + payload.
			                                 // RX: extracted payload only.
			Packet   packet{Type::NONE};     // TX only: the sent link packet.
			int      tries = 0;
			double   deadline = 0.0;         // TX only: OS::time of next retry.
		};

		ChannelData(const Link& link) : _link(link) {}

		Link                 _link;
		std::list<Envelope>  _tx_ring;
		std::list<Envelope>  _rx_ring;
		uint16_t             _next_sequence = 0;
		uint16_t             _next_rx_sequence = 0;
		uint16_t             _window = Channel::WINDOW;
		Channel::Receive     _recv_cb = nullptr;
		void*                _recv_ctx = nullptr;
	};

}

// Per-envelope retransmit timeout, ported from Channel._get_packet_timeout_time.
static double channelTimeoutTime(ChannelData& d, int tries) {
	double rtt = d._link.rtt();
	double base = std::max(rtt * 2.5, 0.025);
	double factor = std::pow(1.5, (double)(tries - 1));
	return factor * base * ((double)d._tx_ring.size() + 1.5);
}

Channel::Channel(const Link& link) {
	_object = std::make_shared<ChannelData>(link);
}

void Channel::set_receive_callback(Receive callback, void* ctx) {
	if (!_object) return;
	_object->_recv_cb = callback;
	_object->_recv_ctx = ctx;
}

uint16_t Channel::mdu() const {
	if (!_object) return 0;
	uint16_t link_mdu = _object->_link.get_mdu();
	if (link_mdu <= 6) return 0;
	return (uint16_t)(link_mdu - 6);
}

size_t Channel::outstanding() const {
	if (!_object) return 0;
	return _object->_tx_ring.size();
}

bool Channel::is_ready_to_send() const {
	if (!_object) return false;
	ChannelData& d = *_object;
	if (d._link.status() != Type::Link::ACTIVE) return false;
	size_t outstanding = 0;
	for (auto& env : d._tx_ring) {
		Type::PacketReceipt::Status st = Type::PacketReceipt::FAILED;
		if (env.packet && env.packet.receipt()) st = env.packet.receipt().status();
		if (st != Type::PacketReceipt::DELIVERED) outstanding++;
	}
	return outstanding < d._window;
}

bool Channel::send(const Bytes& data) {
	if (!_object) return false;
	ChannelData& d = *_object;
	if (!is_ready_to_send()) return false;

	uint16_t seq = d._next_sequence;
	uint16_t len = (uint16_t)data.size();
	uint8_t hdr[6];
	hdr[0] = (uint8_t)(MSGTYPE_RAW >> 8);
	hdr[1] = (uint8_t)(MSGTYPE_RAW & 0xFF);
	hdr[2] = (uint8_t)(seq >> 8);
	hdr[3] = (uint8_t)(seq & 0xFF);
	hdr[4] = (uint8_t)(len >> 8);
	hdr[5] = (uint8_t)(len & 0xFF);
	Bytes raw(hdr, 6);
	raw.append(data);

	uint16_t link_mdu = d._link.get_mdu();
	if (link_mdu == 0 || raw.size() > (size_t)link_mdu) {
		WARNINGF("Channel: packed message too big for packet (%u > %u)",
			(unsigned)raw.size(), (unsigned)link_mdu);
		return false;
	}

	d._next_sequence = (uint16_t)((d._next_sequence + 1) % Channel::SEQ_MODULUS);

	ChannelData::Envelope env;
	env.sequence = seq;
	env.raw = raw;
	env.packet = Packet(d._link, raw, Type::Packet::DATA, Type::Packet::CHANNEL);
	env.packet.send();
	env.tries = 1;
	env.deadline = OS::time() + channelTimeoutTime(d, 1);
	d._tx_ring.push_back(env);
	return true;
}

void Channel::poll() {
	if (!_object) return;
	ChannelData& d = *_object;
	double now = OS::time();
	for (auto it = d._tx_ring.begin(); it != d._tx_ring.end(); ) {
		ChannelData::Envelope& env = *it;
		Type::PacketReceipt::Status st = Type::PacketReceipt::FAILED;
		if (env.packet && env.packet.receipt()) st = env.packet.receipt().status();

		if (st == Type::PacketReceipt::DELIVERED) {
			it = d._tx_ring.erase(it);
			continue;
		}
		if (now >= env.deadline || st == Type::PacketReceipt::CULLED) {
			if (env.tries >= Channel::MAX_TRIES) {
				WARNINGF("Channel: retry count exceeded on link %s, tearing down",
					d._link.toString().c_str());
				Link link = d._link;
				_shutdown();
				link.teardown();
				return;
			}
			env.tries += 1;
			if (env.packet) env.packet.resend();
			env.deadline = now + channelTimeoutTime(d, env.tries);
		}
		++it;
	}
}

// Insert into the RX ring sorted by sequence, dropping duplicates. Ported from
// Channel._emplace_envelope; the wrap-aware compare mirrors the Python.
static bool channelRxEmplace(std::list<ChannelData::Envelope>& ring,
                             const ChannelData::Envelope& env, uint16_t next_rx) {
	for (auto it = ring.begin(); it != ring.end(); ++it) {
		if (env.sequence == it->sequence) return false;  // duplicate
		if (env.sequence < it->sequence &&
		    !((int)(next_rx - env.sequence) > (Channel::SEQ_MAX / 2))) {
			ring.insert(it, env);
			return true;
		}
	}
	ring.push_back(env);
	return true;
}

void Channel::_receive(const Bytes& raw) {
	if (!_object) return;
	ChannelData& d = *_object;
	if (raw.size() < 6) return;
	const uint8_t* p = raw.data();
	uint16_t seq = (uint16_t)((p[2] << 8) | p[3]);
	uint16_t len = (uint16_t)((p[4] << 8) | p[5]);
	size_t avail = raw.size() - 6;
	if (len > avail) len = (uint16_t)avail;

	// Out-of-window / stale-sequence guard (Channel.py _receive).
	if (seq < d._next_rx_sequence) {
		uint16_t window_overflow =
			(uint16_t)((d._next_rx_sequence + Channel::WINDOW_MAX) % Channel::SEQ_MODULUS);
		if (window_overflow < d._next_rx_sequence) {
			if (seq > window_overflow) {
				DEBUGF("Channel: invalid packet sequence %u received", (unsigned)seq);
				return;
			}
		} else {
			DEBUGF("Channel: invalid packet sequence %u received", (unsigned)seq);
			return;
		}
	}

	ChannelData::Envelope env;
	env.sequence = seq;
	env.raw = Bytes(p + 6, len);   // payload only for RX envelopes
	if (!channelRxEmplace(d._rx_ring, env, d._next_rx_sequence)) {
		DEBUGF("Channel: duplicate message (seq %u) received", (unsigned)seq);
		return;
	}

	// Deliver the contiguous run starting at _next_rx_sequence, in order.
	for (;;) {
		auto it = d._rx_ring.begin();
		for (; it != d._rx_ring.end(); ++it)
			if (it->sequence == d._next_rx_sequence) break;
		if (it == d._rx_ring.end()) break;
		Bytes payload = it->raw;
		d._rx_ring.erase(it);
		d._next_rx_sequence = (uint16_t)((d._next_rx_sequence + 1) % Channel::SEQ_MODULUS);
		if (d._recv_cb) d._recv_cb(d._recv_ctx, payload);
	}
}

void Channel::_shutdown() {
	if (!_object) return;
	_object->_recv_cb = nullptr;
	_object->_recv_ctx = nullptr;
	_object->_tx_ring.clear();
	_object->_rx_ring.clear();
}
