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

// Channel — reliable, sequenced, windowed messaging that rides inside a Link.
//
// This is a device-native port of RNS/Channel.py. The wire format is
// byte-identical to upstream Reticulum: every Channel message is exactly one
// Link Packet with context CHANNEL (0x0E) whose plaintext is a 6-byte
// big-endian envelope header `>HHH` (msgtype, sequence, length) followed by the
// message payload. Reliability is provided by the underlying Link packet's
// delivery proof (PacketReceipt): a delivered envelope is removed from the TX
// ring; an un-proven envelope is retransmitted up to _max_tries, after which the
// Link is torn down.
//
// Port adaptations from the Python original:
//   * No threads and no per-packet closures. mR's PacketReceipt callbacks are
//     plain C function pointers with no userdata, so delivery/timeout are driven
//     by polling each envelope's receipt status from poll(), exactly as rnsd
//     already polls link tx receipts — no global receipt registry.
//   * A single receive callback carrying an opaque ctx pointer replaces the
//     Python message-handler list; the rnsd bridge sets ctx to its channel slot.
//   * The message layer is generic opaque bytes (one internal MSGTYPE); callers
//     frame their own application protocol inside the payload.

#include "Bytes.h"
#include "Type.h"

#include <memory>

namespace RNS {

	class Link;
	class ChannelData;

	class Channel {

	public:
		// Internal envelope message type for opaque consumer bytes. Unique and
		// < 0xf000 (upstream reserves >= 0xf000 for system types).
		static const uint16_t MSGTYPE_RAW = 0x0100;

		// Initial / bounded window. v1 uses a small fixed window (adaptive RTT
		// growth from Channel.py is intentionally not ported yet).
		static const uint16_t WINDOW      = 2;
		// Only used as the guard span for the inbound out-of-window sequence
		// check (mirrors Channel.py, which uses the global max window here).
		static const uint16_t WINDOW_MAX  = 48;
		static const uint16_t SEQ_MAX     = 0xFFFF;
		static const uint32_t SEQ_MODULUS = 0x10000;
		static const uint8_t  MAX_TRIES   = 5;

		// Signature of the delivered-message sink. `data` is the message payload
		// (envelope contents, not the header). Delivered in strict sequence order.
		using Receive = void(*)(void* ctx, const Bytes& data);

	public:
		Channel(Type::NoneConstructor none) {}
		Channel(const Channel& channel) : _object(channel._object) {}
		// Construct a Channel bound to `link` (obtained via Link::get_channel()).
		Channel(const Link& link);
		virtual ~Channel() {}

		Channel& operator = (const Channel& channel) {
			_object = channel._object;
			return *this;
		}
		operator bool() const {
			return _object.get() != nullptr;
		}
		bool operator < (const Channel& channel) const {
			return _object.get() < channel._object.get();
		}

	public:
		// True when the TX window has room for another send.
		bool is_ready_to_send() const;
		// Wrap `data` in an envelope and transmit as one CHANNEL link packet.
		// Returns false (and sends nothing) if not ready or the packed size
		// exceeds the channel MDU — the caller should buffer and retry.
		bool send(const Bytes& data);
		// Fed by Link::receive() with the decrypted plaintext of an inbound
		// CHANNEL packet. Handles sequencing/dedup and fires the receive callback
		// for each in-order message.
		void _receive(const Bytes& raw);
		// Drive delivery-proof detection and retransmit/timeout. Safe to call
		// often; a no-op when the TX ring is empty.
		void poll();
		// Register the delivered-message sink.
		void set_receive_callback(Receive callback, void* ctx);
		// Bytes available for a single message payload (Link MDU minus 6).
		uint16_t mdu() const;
		// Count of un-delivered envelopes currently in flight.
		size_t outstanding() const;
		// Drop callbacks and rings (called from Link teardown/close).
		void _shutdown();

	private:
		std::shared_ptr<ChannelData> _object;

	friend class Link;
	};

}
