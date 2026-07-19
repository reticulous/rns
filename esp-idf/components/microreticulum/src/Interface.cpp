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

#include "Interface.h"

#include "Identity.h"
#include "Transport.h"
#include "Utilities/OS.h"

using namespace RNS;
using namespace RNS::Utilities;
using namespace RNS::Type::Interface;

/*static*/ uint8_t Interface::DISCOVER_PATHS_FOR = MODE_ACCESS_POINT | MODE_GATEWAY;

void InterfaceImpl::handle_outgoing(const Bytes& data) {
	//TRACEF("InterfaceImpl.handle_outgoing: data: %s", data.toHex().c_str());
	//TRACE("InterfaceImpl.handle_outgoing");
	_txb += data.size();
}

void InterfaceImpl::handle_incoming(const Bytes& data) {
	//TRACEF("InterfaceImpl.handle_incoming: data: %s", data.toHex().c_str());
	//TRACE("InterfaceImpl.handle_incoming");
	_rxb += data.size();
	// Create temporary Interface encapsulating our own shared impl
	std::shared_ptr<InterfaceImpl> self = shared_from_this();
	Interface interface(self);
	// Pass data on to transport for handling
	Transport::inbound(data, interface);
}

void Interface::send_outgoing(const Bytes& data) {
	assert(_impl);
	//TRACEF("Interface.send_outgoing: data: %s", data.toHex().c_str());
	//TRACE("Interface.send_outgoing");
	// Catch exceptions from calls into Interface implementation
	try {
		_impl->send_outgoing(data);
    }
    catch (const std::bad_alloc&) {
		ERROR("Interface::send_outgoing: bad_alloc - OUT OF MEMORY");
		// Critical OOM, restarting
#if defined(ESP32)
		ESP.restart();
#elif defined(ARDUINO_ARCH_NRF52) || defined(ARDUINO_NRF52_ADAFRUIT)
		NVIC_SystemReset();
#endif
    }
    catch (const std::exception& e) {
		ERRORF("Interface::send_outgoing: %s", e.what());
    }
}

void Interface::handle_incoming(const Bytes& data) {
	assert(_impl);
	//TRACEF("Interface.handle_incoming: data: %s", data.toHex().c_str());
	//TRACE("Interface.handle_incoming");
/*
	_impl->_rxb += data.size();
	// Pass data on to transport for handling
	Transport::inbound(data, *this);
*/
	// Catch exceptions from calls into Interface implementation
	try {
		_impl->handle_incoming(data);
    }
    catch (const std::bad_alloc&) {
		ERROR("Interface::handle_incoming: bad_alloc - OUT OF MEMORY");
		// Critical OOM, restarting
#if defined(ESP32)
		ESP.restart();
#elif defined(ARDUINO_ARCH_NRF52) || defined(ARDUINO_NRF52_ADAFRUIT)
		NVIC_SystemReset();
#endif
    }
    catch (const std::exception& e) {
		ERRORF("Interface::handle_incoming: %s", e.what());
    }
}

// Emit at most one held announce from this interface's bandwidth-cap queue,
// then arm announce_allowed_at for the next one. Upstream RNS reschedules
// itself with a threading.Timer; mR has no timers, so Transport::jobs() polls
// announce_allowed_at and calls this once per due interface (see jobs()).
// Announces with fewer hops are prioritised, oldest-first within a hop count.
void Interface::process_announce_queue() {
	assert(_impl);
	if (_impl->_announce_queue.empty()) {
		return;
	}
	try {
		double now = OS::time();

		// Drop entries that have outlived the queue lifetime.
		_impl->_announce_queue.remove_if([now](const AnnounceEntry& a) {
			return now > a._time + Type::Reticulum::QUEUED_ANNOUNCE_LIFE;
		});
		if (_impl->_announce_queue.empty()) {
			return;
		}

		// Select the lowest hop count, breaking ties toward the oldest entry.
		auto selected = _impl->_announce_queue.begin();
		for (auto it = _impl->_announce_queue.begin(); it != _impl->_announce_queue.end(); ++it) {
			if (it->_hops < selected->_hops ||
			    (it->_hops == selected->_hops && it->_time < selected->_time)) {
				selected = it;
			}
		}

		double wait_time = 0;
		if (_impl->_bitrate > 0 && _impl->_announce_cap > 0) {
			double tx_time = (double)(selected->_raw.size() * 8) / (double)_impl->_bitrate;
			wait_time = tx_time / _impl->_announce_cap;
		}
		_impl->_announce_allowed_at = now + wait_time;

		Bytes raw = selected->_raw;
		_impl->_announce_queue.erase(selected);

		DEBUGF("Emitting held announce on %s, %lu still queued",
			toString().c_str(), (unsigned long)_impl->_announce_queue.size());
		send_outgoing(raw);
	}
	catch (const std::exception& e) {
		_impl->_announce_queue.clear();
		ERRORF("Error while processing announce queue on %s: %s. The queue has been cleared.",
			toString().c_str(), e.what());
	}
}

/*
void ArduinoJson::convertFromJson(JsonVariantConst src, RNS::Interface& dst) {
	TRACE(">>> Deserializing Interface");
TRACEF(">>> Interface pre: %s", dst.debugString().c_str());
	if (!src.isNull()) {
		RNS::Bytes hash;
		hash.assignHex(src.as<const char*>());
		TRACEF(">>> Querying Transport for Interface hash %s", hash.toHex().c_str());
		// Query transport for matching interface
		dst = Transport::find_interface_from_hash(hash);
TRACEF(">>> Interface post: %s", dst.debugString().c_str());
	}
	else {
		dst = {RNS::Type::NONE};
TRACEF(">>> Interface post: %s", dst.debugString().c_str());
	}
}
*/
