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
			uint16_t msgtype = Channel::MSGTYPE_RAW;  // RX: envelope msgtype.
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
		uint16_t             _window_max = Channel::WINDOW_MAX_SLOW;
		uint16_t             _window_min = Channel::WINDOW_MIN;
		uint16_t             _window_flexibility = Channel::WINDOW_FLEXIBILITY;
		uint16_t             _fast_rate_rounds = 0;
		uint16_t             _medium_rate_rounds = 0;
		Channel::Receive     _recv_cb = nullptr;
		void*                _recv_ctx = nullptr;
	};

}

// The window opens by one on every delivered envelope, and the ceiling it opens
// toward is the link's round trip: FAST_RATE_THRESHOLD deliveries in a row
// inside RTT_MEDIUM earn the medium ceiling, inside RTT_FAST the fast one, and
// anything slower resets the count. Ported from Channel._packet_tx_op.
static void channelWindowOpen(ChannelData& d) {
	if (d._window < d._window_max) d._window += 1;
	const double rtt = d._link.rtt();
	if (rtt == 0.0) return;
	if (rtt > Channel::RTT_FAST) {
		d._fast_rate_rounds = 0;
		if (rtt > Channel::RTT_MEDIUM) {
			d._medium_rate_rounds = 0;
			return;
		}
		d._medium_rate_rounds += 1;
		if (d._window_max < Channel::WINDOW_MAX_MEDIUM &&
		    d._medium_rate_rounds == Channel::FAST_RATE_THRESHOLD) {
			d._window_max = Channel::WINDOW_MAX_MEDIUM;
			d._window_min = Channel::WINDOW_MIN_LIMIT_MEDIUM;
		}
		return;
	}
	d._fast_rate_rounds += 1;
	if (d._window_max < Channel::WINDOW_MAX_FAST &&
	    d._fast_rate_rounds == Channel::FAST_RATE_THRESHOLD) {
		d._window_max = Channel::WINDOW_MAX_FAST;
		d._window_min = Channel::WINDOW_MIN_LIMIT_FAST;
	}
}

// And closes by one on every retry, the ceiling following it down for as long as
// it keeps more than the flexibility's slack above the floor. Ported from
// Channel._packet_timeout.
static void channelWindowClose(ChannelData& d) {
	if (d._window <= d._window_min) return;
	d._window -= 1;
	if (d._window_max > (uint16_t)(d._window_min + d._window_flexibility)) d._window_max -= 1;
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

bool Channel::send(uint16_t msgtype, const Bytes& data) {
	if (!_object) return false;
	ChannelData& d = *_object;
	if (!is_ready_to_send()) return false;

	uint16_t seq = d._next_sequence;
	uint16_t len = (uint16_t)data.size();
	uint8_t hdr[6];
	hdr[0] = (uint8_t)(msgtype >> 8);
	hdr[1] = (uint8_t)(msgtype & 0xFF);
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
			channelWindowOpen(d);
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
			channelWindowClose(d);
			const double wait = channelTimeoutTime(d, env.tries);
			/* The resend is otherwise silent, and it is the one thing that
			 * distinguishes a stalled channel from an idle one: the window
			 * counts every envelope whose receipt is not DELIVERED, so a proof
			 * that does not come back stops the sender until this fires. */
			const char* stname = st == Type::PacketReceipt::SENT      ? "still sent"
			                   : st == Type::PacketReceipt::FAILED    ? "proof timed out"
			                   : st == Type::PacketReceipt::CULLED    ? "culled"
			                   : "delivered";
			DEBUGF("Channel: seq %u unproved (%s, %u outstanding, link rtt %.2f s), "
				"resend %u of %u, next in %.1f s, window %u/%u",
				(unsigned)env.sequence, stname, (unsigned)d._tx_ring.size(),
				d._link.rtt(), (unsigned)env.tries, (unsigned)Channel::MAX_TRIES, wait,
				(unsigned)d._window, (unsigned)d._window_max);
			if (env.packet) env.packet.resend();
			env.deadline = now + wait;
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
	uint16_t msgtype = (uint16_t)((p[0] << 8) | p[1]);
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
	env.msgtype = msgtype;
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
		uint16_t mt = it->msgtype;
		d._rx_ring.erase(it);
		d._next_rx_sequence = (uint16_t)((d._next_rx_sequence + 1) % Channel::SEQ_MODULUS);
		if (d._recv_cb) d._recv_cb(d._recv_ctx, mt, payload);
	}
}

void Channel::_shutdown() {
	if (!_object) return;
	_object->_recv_cb = nullptr;
	_object->_recv_ctx = nullptr;
	_object->_tx_ring.clear();
	_object->_rx_ring.clear();
}
