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

#include "Transport.h"

#include "Reticulum.h"
#include "Destination.h"
#include "Identity.h"
#include "Link.h"
#include "Packet.h"
#include "Interface.h"
#include "Log.h"
#include "Cryptography/Random.h"
#include "Cryptography/HKDF.h"
#include "Utilities/OS.h"
#include "Utilities/Persistence.h"

#include <algorithm>
#include <tuple>
#include <cstring>
#include <unistd.h>
#include <time.h>

using namespace RNS;
using namespace RNS::Type::Transport;
using namespace RNS::Utilities;
using namespace RNS::Persistence;

/* Spangap: announce-processing and incoming-path-request DEBUGFs route
 * through this and fire at VERBOSE, not DEBUG. Busy TCP peers deliver
 * hundreds of announces and path requests — every per-packet announce log
 * (heard/rebroadcast/held/dropped/replaced/now-N-hops-away) and every
 * received-path-request log (the request itself, dedup/tagless drops,
 * not-answering decisions, discovery/forwarding on behalf of others,
 * no-path drops, waiting-PR culls) is other people's traffic, so debug
 * level stays readable and surfaces only packets that involve this node.
 * (This used to be switchable via `s.rnsd.debug.only_local`; the demotion
 * is now unconditional.) The exception — kept at INFOF so it is never
 * suppressed — is a path request answered for a destination local to this
 * system, which does concern us. */
#define DBGF_DEMOTE(...) VERBOSEF(__VA_ARGS__)
#define DBG_DEMOTE(msg) VERBOSE(msg)

#ifndef RNS_PATH_TABLE_MAX
#define RNS_PATH_TABLE_MAX 100
#endif

#ifndef RNS_PATH_TABLE_SEGMENT_SIZE
#define RNS_PATH_TABLE_SEGMENT_SIZE 65536
#endif

#ifndef RNS_PATH_TABLE_SEGMENT_COUNT
#define RNS_PATH_TABLE_SEGMENT_COUNT 8
#endif

#ifndef RNS_ANNOUNCE_TABLE_MAX
#define RNS_ANNOUNCE_TABLE_MAX 100
#endif

/* Announce emissions per jobs() pass. The whole ring coming due at once is one
 * uninterrupted run of pack + per-interface decision + transmit on the rnsd
 * task, with no yield in it; this bounds that run. The pass repeats at least
 * once a second and the re-arm interval is seconds, so the table still drains
 * as fast as it is allowed to. */
#ifndef ANNOUNCE_EMITS_PER_PASS
#define ANNOUNCE_EMITS_PER_PASS 8
#endif

/* Entries removed per table-cull sweep. Expiry is not urgent — an entry a pass
 * late is still expired — but the sweep runs on the rnsd task, and while it
 * runs nothing drains the ITS inbox. */
#ifndef CULL_PER_PASS
#define CULL_PER_PASS 32
#endif

#ifndef RNS_HASHLIST_MAX
#define RNS_HASHLIST_MAX 100
#endif

#ifndef RNS_PR_TAGS_MAX
// Dedup window for forwarded path-request tags. Must be large enough that a
// request still circulating the network (e.g. across several TCP uplinks that
// reach each other) is still remembered when its echo returns, or the node
// re-forwards it and joins a path-request storm. 32 was far too small once a
// node bridges a busy transport network.
#define RNS_PR_TAGS_MAX	 256
#endif

/*static*/ Transport::InterfaceTable Transport::_interfaces;
/*static*/ Transport::DestinationTable Transport::_destinations;
/*static*/ std::set<Link> Transport::_pending_links;
/*static*/ std::set<Link> Transport::_active_links;
/*static*/ std::set<Bytes> Transport::_packet_hashlist;
/*static*/ std::list<PacketReceipt> Transport::_receipts;

/*static*/ Transport::AnnounceRec* Transport::_announce_ring = nullptr;
/*static*/ uint16_t Transport::_announce_slots = 0;
/*static*/ PathTable Transport::_path_table;
/*static*/ std::map<Bytes, Transport::ReverseEntry> Transport::_reverse_table;
/*static*/ std::map<Bytes, Transport::LinkEntry> Transport::_link_table;
/*static*/ std::set<HAnnounceHandler> Transport::_announce_handlers;
/*static*/ std::map<Bytes, Transport::TunnelEntry> Transport::_tunnels;
/*static*/ std::map<Bytes, Transport::RateEntry> Transport::_announce_rate_table;
/*static*/ std::map<Bytes, double> Transport::_path_requests;

/*static*/ std::map<Bytes, Transport::PathRequestEntry> Transport::_discovery_path_requests;
/*static*/ std::set<Bytes> Transport::_discovery_pr_tags;
/*static*/ std::list<Bytes> Transport::_discovery_pr_tags_order;

/*static*/ std::set<Destination> Transport::_control_destinations;
/*static*/ std::set<Bytes> Transport::_control_hashes;

///*static*/ std::set<Interface> Transport::_local_client_interfaces;
/*static*/ std::set<std::reference_wrapper<const Interface>, std::less<const Interface>> Transport::_local_client_interfaces;

/*static*/ std::map<Bytes, const Interface> Transport::_pending_local_path_requests;

// CBA
/*static*/ std::map<Bytes, Transport::PacketEntry> Transport::_packet_table;

/*static*/ uint16_t Transport::_LOCAL_CLIENT_CACHE_MAXSIZE = 512;

/*static*/ double Transport::_start_time				= 0.0;
/*static*/ bool Transport::_jobs_locked					= false;
/*static*/ bool Transport::_jobs_running				= false;
/*static*/ float Transport::_job_interval				= 0.250;
/*static*/ double Transport::_jobs_last_run				= 0.0;
/*static*/ double Transport::_links_last_checked		= 0.0;
/*static*/ float Transport::_links_check_interval		= 1.0;
/*static*/ double Transport::_receipts_last_checked		= 0.0;
/*static*/ float Transport::_receipts_check_interval	= 1.0;
/*static*/ double Transport::_announces_last_checked	= 0.0;
/*static*/ float Transport::_announces_check_interval	= 1.0;
/*static*/ double Transport::_tables_last_culled		= 0.0;
// CBA MCU
/*static*/ //float Transport::_tables_cull_interval		= 5.0;
/*static*/ float Transport::_tables_cull_interval		= 60.0;
/*static*/ bool Transport::_saving_path_table			= false;
// CBA ACCUMULATES
// CBA MCU
/*static*/ uint16_t Transport::_hashlist_maxsize		= RNS_HASHLIST_MAX;
// CBA ACCUMULATES
// CBA MCU
/*static*/ uint16_t Transport::_max_pr_tags				= RNS_PR_TAGS_MAX;

// CBA
// CBA ACCUMULATES
/*static*/ uint16_t Transport::_path_table_maxsize		= RNS_PATH_TABLE_MAX;
// CBA ACCUMULATES
/*static*/ uint16_t Transport::_path_table_maxpersist	= RNS_PATH_TABLE_MAX;
/*static*/ double Transport::_last_saved				= 0.0;
/*static*/ float Transport::_save_interval				= 3600.0;
/*static*/ uint32_t Transport::_path_table_crc	= 0;
/*static*/ uint16_t Transport::_announce_table_maxsize	= RNS_ANNOUNCE_TABLE_MAX;
// Spangap: runtime-tunable path TTLs, seeded from the Type::Transport defaults.
/*static*/ uint32_t Transport::_destination_timeout	= Type::Transport::DESTINATION_TIMEOUT;
/*static*/ uint32_t Transport::_ap_path_time		= Type::Transport::AP_PATH_TIME;
/*static*/ uint32_t Transport::_custody_path_time	= 86400;   /* s.rnsd.path.ttl_custody */
/*static*/ Transport::PathEscalation Transport::_path_escalations[Transport::PATH_ESCALATIONS_MAX] = {};
/*static*/ uint32_t Transport::_path_escalate_time	= 3;       /* s.rnsd.path.escalate_s */
/*static*/ uint32_t Transport::_path_cheap_bitrate	= 50000;   /* s.rnsd.path.cheap_bps  */
/*static*/ uint32_t Transport::_roaming_path_time	= Type::Transport::ROAMING_PATH_TIME;

/*static*/ Reticulum Transport::_owner({Type::NONE});
/*static*/ Identity Transport::_identity({Type::NONE});

// CBA
/*static*/ Transport::Callbacks Transport::_callbacks;

// CBA Stats
/*static*/ uint32_t Transport::_packets_sent = 0;
/*static*/ uint32_t Transport::_packets_received = 0;
/*static*/ uint32_t Transport::_destinations_added = 0;
/*static*/ size_t Transport::_last_memory = 0;
/*static*/ size_t Transport::_last_psram = 0;
/*static*/ size_t Transport::_last_flash = 0;

/*static*/ bool Transport::cleaning_caches = false;

/* The aspect filter is compiled to its name hash here, once. Destination
 * splits an aspect string at the first dot into µR's app_name + aspects ctor
 * args, and name_hash() is computed with a NONE identity — so it is a pure
 * function of the aspect text, and every announce for that aspect carries the
 * same ten bytes whoever sent it. */
AnnounceHandler::AnnounceHandler(const char* aspect_filter /*= nullptr*/) {
	if (aspect_filter == nullptr) return;
	_aspect_filter = aspect_filter;
	auto dot = _aspect_filter.find('.');
	std::string app = (dot == std::string::npos) ? _aspect_filter : _aspect_filter.substr(0, dot);
	std::string asp = (dot == std::string::npos) ? std::string()  : _aspect_filter.substr(dot + 1);
	_name_hash_filter = Destination::name_hash(app.c_str(), asp.c_str());
}

/*static*/ void Transport::start(const Reticulum& reticulum_instance) {
	INFO("Transport starting...");
	_jobs_running = true;
	_owner = reticulum_instance;

	// Initialize time-based variables *after* time offset update
	_jobs_last_run = OS::time();
	_links_last_checked = OS::time();
	_receipts_last_checked = OS::time();
	_announces_last_checked = OS::time();
	_tables_last_culled = OS::time();
	_last_saved = OS::time();

	// Ensure required directories exist
	if (!OS::directory_exists(Reticulum::_cachepath)) {
		VERBOSE("No cache directory, creating...");
		OS::create_directory(Reticulum::_cachepath);
	}

	// Load transport identity
	if (!_identity) {
		char transport_identity_path[Type::Reticulum::FILEPATH_MAXSIZE];
		int tip_n = snprintf(transport_identity_path, Type::Reticulum::FILEPATH_MAXSIZE, "%s/transport_identity", Reticulum::_storagepath);
		if (tip_n < 0 || (size_t)tip_n >= (size_t)Type::Reticulum::FILEPATH_MAXSIZE) {
			ERROR("Transport identity path truncated; skipping identity load");
		}
		else {
		DEBUG("Checking for transport identity...");
		try {
			if (OS::file_exists(transport_identity_path)) {
				_identity = Identity::from_file(transport_identity_path);
			}

			if (!_identity) {
				VERBOSE("No valid Transport Identity in storage, creating...");
				_identity = Identity();
				_identity.to_file(transport_identity_path);
			}
			else {
				VERBOSE("Loaded Transport Identity from storage");
			}
		}
		catch (const std::exception& e) {
			ERRORF("Failed to check for transport identity, the contained exception was: %s", e.what());
		}
		}
	}

// TODO
/*
	// Load packet hashlist
	packet_hashlist_path = Reticulum::storagepath + "/packet_hashlist";
	if (!owner.is_connected_to_shared_instance()) {
		if (os.path.isfile(packet_hashlist_path)) {
			try {
				//p file = open(packet_hashlist_path, "rb")
				//p Transport.packet_hashlist = umsgpack.unpackb(file.read())
				//p file.close()
			}
			catch (const std::exception& e) {
				ERRORF("Could not load packet hashlist from storage, the contained exception was: %s", e.what());
			}
		}
	}
*/

	/* One allocation for the whole retransmission queue, sized from the cap in
	 * force now (rnsd applies s.rnsd.announce.table_max before start()). Raising
	 * the cap later clamps to this ring rather than growing it — the queue is
	 * bounded work, not a cache, and a live resize would buy nothing. */
	if (!_announce_ring) {
		_announce_slots = _announce_table_maxsize > 0 ? _announce_table_maxsize : 1;
		_announce_ring = new (std::nothrow) AnnounceRec[_announce_slots];
		if (!_announce_ring) {
			ERRORF("Could not allocate the %u-slot announce queue", (unsigned)_announce_slots);
			_announce_slots = 0;
		}
		else {
			memset(_announce_ring, 0, (size_t)_announce_slots * sizeof(AnnounceRec));
			VERBOSEF("Announce queue: %u slots x %u B", (unsigned)_announce_slots, (unsigned)sizeof(AnnounceRec));
		}
	}

	// Create transport-specific destination for path request
	Destination path_request_destination({Type::NONE}, Type::Destination::IN, Type::Destination::PLAIN, APP_NAME, "path.request");
	path_request_destination.set_packet_callback(path_request_handler);
	// CBA ACCUMULATES
	_control_destinations.insert(path_request_destination);
	// CBA ACCUMULATES
	_control_hashes.insert(path_request_destination.hash());
	DEBUGF("Created transport-specific path request destination %s", path_request_destination.hash().toHex().c_str());

	// Create transport-specific destination for tunnel synthesize
	Destination tunnel_synthesize_destination({Type::NONE}, Type::Destination::IN, Type::Destination::PLAIN, APP_NAME, "tunnel.synthesize");
	tunnel_synthesize_destination.set_packet_callback(tunnel_synthesize_handler);
	// CBA BUG?
    //p Transport.control_destinations.append(Transport.tunnel_synthesize_handler)
	// CBA ACCUMULATES
	_control_destinations.insert(tunnel_synthesize_destination);
	// CBA ACCUMULATES
	_control_hashes.insert(tunnel_synthesize_destination.hash());
	DEBUGF("Created transport-specific tunnel synthesize destination %s", tunnel_synthesize_destination.hash().toHex().c_str());

	// Start job loops
	_jobs_running = false;
	// CBA Threading
	//p thread = threading.Thread(target=Transport.jobloop, daemon=True)
	//p thread.start()

	// Load transport-related data
	if (Reticulum::transport_enabled()) {
		INFO("Transport mode is enabled");

		/* Routing state comes back from the arena image, which the embedder
		 * loads through the store's platform hooks before Transport starts —
		 * there is nothing to read here. */

		// CBA The following write and clean is very resource intensive so skip at startup
		// and let a later (optimized) scheduled write and clean take care of it.
		// Write path table back and clean caches in case any entries are invalid
		//DEBUG("Writing path table and cleaning caches to clean-up any orphaned paths/files");
		//write_path_table();
		//clean_caches();

		// Read in tunnel table
		read_tunnel_table();

		// Create transport-specific destination for probe requests
		if (Reticulum::probe_destination_enabled()) {
			Destination probe_destination(_identity, Type::Destination::IN, Type::Destination::SINGLE, APP_NAME, "probe");
			probe_destination.accepts_links(false);
			probe_destination.set_proof_strategy(Type::Destination::PROVE_ALL);
			DEBUGF("Created probe responder destination %s", probe_destination.hash().toHex().c_str());
			probe_destination.announce();
			NOTICEF("Transport Instance will respond to probe requests on %s", probe_destination.toString().c_str());
		}

		VERBOSEF("Transport instance %s started", _identity.toString().c_str());
		_start_time = OS::time();
	}
	else {
		INFO("Transport mode is disabled");
	}

	// CBA TODO
	// Sort interfaces according to bitrate
	//p Transport.prioritize_interfaces()

// TODO
/*p
	// Synthesize tunnels for any interfaces wanting it
	for interface in Transport.interfaces:
		interface.tunnel_id = None
		if hasattr(interface, "wants_tunnel") and interface.wants_tunnel:
			Transport.synthesize_tunnel(interface)
*/

//#ifndef NDEBUG
	// CBA DEBUG
	dump_stats();
//#endif
}

/*static*/ void Transport::loop() {
	if (OS::time() > (_jobs_last_run + _job_interval)) {
		jobs();
		_jobs_last_run = OS::time();
	}
}

/*static*/ void Transport::jobs() {
	//TRACE("Transport::jobs()");

	std::vector<Packet> outgoing;
	std::set<Bytes> path_requests;
	/* Spangap: half-open links reaped below must be torn down AFTER
	 * _jobs_running is cleared. teardown() sends a LINKCLOSE via
	 * Transport::outbound(), which spins on `while (_jobs_running)`; calling it
	 * inline here would self-deadlock jobs() (the spin can never observe
	 * _jobs_running == false because jobs() is what clears it). Collect and
	 * defer, matching the outgoing/path_requests pattern. */
	std::vector<Link> reap_links;
	/* Spangap: links whose in-flight Resources need a watchdog poll this
	 * tick (upstream runs a thread per resource; we poll on the links-check
	 * cadence, which matches upstream's WATCHDOG_MAX_SLEEP of 1 s). Same
	 * deferral as reap_links: retries send packets via Transport::outbound,
	 * which spins on _jobs_running. */
	std::vector<Link> watchdog_links;
	int count;
	_jobs_running = true;

	try {
		if (!_jobs_locked) {

			// Process active and pending link lists
			if (OS::time() > (_links_last_checked + _links_check_interval)) {
				std::set<Link> pending_links(_pending_links);
				for (auto& link : pending_links) {
					if (link.status() == Type::Link::CLOSED) {
						// If we are not a Transport Instance, finding a pending link
						// that was never activated will trigger an expiry of the path
						// to the destination, and an attempt to rediscover the path.
						if (!Reticulum::transport_enabled()) {
							expire_path(link.destination().hash());

							// If we are connected to a shared instance, it will take
							// care of sending out a new path request. If not, we will
							// send one directly.
							if (!_owner.is_connected_to_shared_instance()) {
								double last_path_request = 0;
								auto iter = _path_requests.find(link.destination().hash());
								if (iter != _path_requests.end()) {
									last_path_request = (*iter).second;
								}

								if ((OS::time() - last_path_request) > Type::Transport::PATH_REQUEST_MI) {
									DEBUGF("Trying to rediscover path for %s since an attempted link was never established", link.destination().hash().toHex().c_str());
									//if (path_requests.find(link.destination().hash()) == path_requests.end()) {
									if (path_requests.count(link.destination().hash()) == 0) {
										// CBA ACCUMULATES
										path_requests.insert(link.destination().hash());
									}
								}
							}
						}

						_pending_links.erase(link);
					}
					/* Spangap: same establishment-timeout reaping for outbound (initiator)
					 * Links that were never proved — without the watchdog they never reach
					 * CLOSED, so the loop above never cleans them up. */
					else if ((link.status() == Type::Link::PENDING || link.status() == Type::Link::HANDSHAKE) &&
					         link.establishment_timeout() > 0 &&
					         OS::time() >= link.request_time() + link.establishment_timeout()) {
						WARNINGF("Reaping half-open outbound link %s (status=%d): establishment timed out after %.1fs",
							link.link_id().toHex().c_str(), (int)link.status(), link.establishment_timeout());
						reap_links.push_back(link);
						_pending_links.erase(link);
					}
				}
				std::set<Link> active_links(_active_links);
				for (auto& link : active_links) {
					if (link.status() == Type::Link::CLOSED) {
						_active_links.erase(link);
					}
					/* Spangap: reap a half-open link. Recipient Links enter _active_links
					 * at HANDSHAKE (register_link) and only reach ACTIVE when the
					 * initiator's RTT packet arrives and fires the establishment callback
					 * that wires the packet callback. link_watchdog() covers only the
					 * ACTIVE/STALE phases, so establishment timeouts are enforced here:
					 * without this a stuck HANDSHAKE Link would live forever and
					 * Link::receive would keep decrypting-and-dropping (now un-proved)
					 * its data. teardown() sends a LINKCLOSE for a HANDSHAKE link so the
					 * initiator drops its side and the next send re-establishes cleanly. */
					else if ((link.status() == Type::Link::PENDING || link.status() == Type::Link::HANDSHAKE) &&
					         link.establishment_timeout() > 0 &&
					         OS::time() >= link.request_time() + link.establishment_timeout()) {
						WARNINGF("Reaping half-open link %s (status=%d): establishment timed out after %.1fs",
							link.link_id().toHex().c_str(), (int)link.status(), link.establishment_timeout());
						reap_links.push_back(link);
						_active_links.erase(link);
					}
				}

				for (auto& link : _active_links) {
					watchdog_links.push_back(link);
				}

				_links_last_checked = OS::time();
			}

			// Process receipts list for timed-out packets
			if (OS::time() > (_receipts_last_checked + _receipts_check_interval)) {
				while (_receipts.size() > Type::Transport::MAX_RECEIPTS) {
					//p culled_receipt = Transport.receipts.pop(0)
					PacketReceipt culled_receipt = _receipts.front();
					_receipts.pop_front();
					culled_receipt.set_timeout(-1);
					culled_receipt.check_timeout();
				}

				std::list<PacketReceipt> cull_receipts;
				for (auto& receipt : _receipts) {
					receipt.check_timeout();
					if (receipt.status() != Type::PacketReceipt::SENT) {
						//p if receipt in Transport.receipts:
						//p 	Transport.receipts.remove(receipt)
						cull_receipts.push_back(receipt);
					}
				}
				// CBA since modifying of collection while iterating is forbidden
				for (auto& receipt : cull_receipts) {
					_receipts.remove(receipt);
				}

				_receipts_last_checked = OS::time();
			}

			// Process announces needing retransmission
			if (OS::time() > (_announces_last_checked + _announces_check_interval)) {
				// Only a transport node re-broadcasts third-party announces. If
				// transport was just disabled at runtime, drop whatever is still
				// pending so it takes effect immediately — otherwise the table
				// and per-interface queues that filled while enabled keep
				// trickling out for minutes (looking like the toggle did nothing
				// until a reboot cleared them).
				if (!Reticulum::transport_enabled()) {
					for (uint16_t i = 0; i < _announce_slots; i++)
						memset(&_announce_ring[i], 0, sizeof(AnnounceRec));
					drop_announce_queues();
				}
				else {
				/* Spangap deviation: bounded work per pass, round-robin.
				 *
				 * The walk emits through the whole outbound path — pack,
				 * per-interface decision, transmit — and nothing in it yields.
				 * A full ring coming due together therefore ran ~100 emissions
				 * back to back on the rnsd task, which starved IDLE0 into the
				 * task watchdog and dropped ITS sends underneath it. Emitting a
				 * few per pass and resuming at the cursor next tick keeps the
				 * table draining (the re-arm interval is seconds, the tick is
				 * at most one) with a hard ceiling on time spent per pass. */
				static uint16_t announce_cursor = 0;
				uint8_t emit_budget = ANNOUNCE_EMITS_PER_PASS;
				for (uint16_t step = 0; step < _announce_slots && emit_budget > 0; step++) {
					uint16_t slot = (uint16_t)((announce_cursor + step) % _announce_slots);
					AnnounceRec& rec = _announce_ring[slot];
					if (!(rec.flags & ANNOUNCE_F_USED)) continue;
					/* A held entry is waiting for the path response ahead of it
					 * to go out; it is re-armed below, not emitted here. */
					if (rec.flags & ANNOUNCE_F_HELD) continue;

					Bytes destination_hash(rec.dest, Type::Reticulum::DESTINATION_LENGTH);

					if (rec.retries > 0 && rec.retries >= Type::Transport::LOCAL_REBROADCASTS_MAX) {
						TRACEF("Completed announce processing for %s, local rebroadcast limit reached", destination_hash.toHex().c_str());
						memset(&rec, 0, sizeof(rec));
						continue;
					}
					if (rec.retries > Type::Transport::PATHFINDER_R) {
						TRACEF("Completed announce processing for %s, retry limit reached", destination_hash.toHex().c_str());
						memset(&rec, 0, sizeof(rec));
						continue;
					}
					if (OS::time() <= rec.retransmit_at) continue;

					/* An emission is the expensive step, so it is what the
					 * budget counts; the skips and expiries above are free.
					 * Resume past this slot next pass so a ring that is always
					 * over budget still serves every entry in turn. */
					emit_budget--;
					announce_cursor = (uint16_t)((slot + 1) % _announce_slots);

					TRACEF("Performing announce processing for %s...", destination_hash.toHex().c_str());
					rec.retransmit_at = OS::time() + Type::Transport::PATHFINDER_G + Type::Transport::PATHFINDER_RW;
					rec.retries += 1;

					bool block_rebroadcasts = (rec.flags & ANNOUNCE_F_BLOCK) != 0;
					Type::Packet::context_types announce_context =
						block_rebroadcasts ? Type::Packet::PATH_RESPONSE : Type::Packet::CONTEXT_NONE;
					Interface attached_interface = (rec.flags & ANNOUNCE_F_ATTACHED)
						? find_interface_from_hash_prefix(rec.attached_iface) : Interface({Type::NONE});

					Identity announce_identity(Identity::recall(destination_hash));
					Destination announce_destination(announce_identity, Type::Destination::OUT, Type::Destination::SINGLE, destination_hash);

					Packet new_packet(
						announce_destination,
						attached_interface,
						Bytes(rec.data, rec.data_len),
						Type::Packet::ANNOUNCE,
						announce_context,
						Type::Transport::TRANSPORT,
						Type::Packet::HEADER_2,
						Transport::_identity.hash(),
						true,
						(Type::Packet::context_flags)rec.context_flag
					);

					new_packet.hops(rec.hops);
					// Carry the interface this announce arrived on onto the
					// rebroadcast, so outbound()'s point-to-point echo suppression
					// can stop it going back out that same interface. This
					// is the reliable source signal — the interface the original
					// packet was received on — as opposed to a path lookup that
					// can miss after evictions or interface reconnects.
					new_packet.receiving_interface(find_interface_from_hash_prefix(rec.recv_iface));
					if (block_rebroadcasts) {
						/* Serving someone else's route request — verbose, like
						 * the rest of the path-request processing. */
						VERBOSEF("Sent requested route for %s to transport %s (hop count %d)",
							announce_destination.hash().toHex().c_str(),
							attached_interface ? attached_interface.toString().c_str() : "<all>",
							new_packet.hops());
					}
					else {
						DBGF_DEMOTE("Rebroadcasting announce for %s with hop count %d", announce_destination.hash().toHex().c_str(), new_packet.hops());
					}

					outgoing.push_back(new_packet);

					// This handles an edge case where a peer sends a path
					// request for a destination just after an announce for said
					// destination has arrived, but before it has been
					// rebroadcast locally. In such a case the actual announce is
					// temporarily held, and re-armed once the path request has
					// been served to the peer.
					AnnounceRec* held = announce_find(destination_hash, /*held=*/true);
					if (held) {
						memset(&rec, 0, sizeof(rec));
						held->flags &= (uint8_t)~ANNOUNCE_F_HELD;
						DBG_DEMOTE("Re-arming held announce");
					}
				}
				}

				_announces_last_checked = OS::time();
			}

			// Drain the per-interface announce hold queues that the bandwidth
			// cap fills (outbound() defers announces exceeding announce_cap into
			// interface.announce_queue). Upstream RNS reschedules a per-queue
			// threading.Timer; mR has no timers, so poll each interface here and
			// emit one held announce once its announce_allowed_at has elapsed.
			// Cheap when queues are empty (the common case: cap not exceeded, or
			// AP/roaming interfaces that never queue). Only a transport node has
			// anything here — the queues only ever hold forwarded announces.
			if (Reticulum::transport_enabled()) {
				for (auto& [interface_hash, interface] : _interfaces) {
					if (!interface.announce_queue().empty() && OS::time() > interface.announce_allowed_at()) {
						interface.process_announce_queue();
					}
				}
			}

			// Cull the packet hashlist if it has reached its max size
			if (_packet_hashlist.size() > _hashlist_maxsize) {
				std::set<Bytes>::iterator iter = _packet_hashlist.begin();
				std::advance(iter, _packet_hashlist.size() - _hashlist_maxsize);
				_packet_hashlist.erase(_packet_hashlist.begin(), iter);
			}

			// Cull the path request tags list if it has reached its max size.
			// Evict oldest-first (FIFO via _discovery_pr_tags_order): std::set
			// orders by tag content, so erasing from its begin() would drop
			// tags at random w.r.t. recency and could forget a request still
			// circulating — re-forwarding it and sustaining a path-request storm.
			while (_discovery_pr_tags.size() > _max_pr_tags && !_discovery_pr_tags_order.empty()) {
				_discovery_pr_tags.erase(_discovery_pr_tags_order.front());
				_discovery_pr_tags_order.pop_front();
			}

			if (OS::time() > (_tables_last_culled + _tables_cull_interval)) {

				// CBA Disabled following since we're calling immediately after adding to path table now
				// Cull the path table if it has reached its max size
				//cull_path_table();

				// Cull the reverse table according to timeout
				try {
					std::vector<Bytes> stale_reverse_entries;
					stale_reverse_entries.reserve(_reverse_table.size());
					for (const auto& [packet_hash, reverse_entry] : _reverse_table) {
						if (OS::time() > (reverse_entry._timestamp + REVERSE_TIMEOUT)) {
							stale_reverse_entries.push_back(packet_hash);
						}
					}
					remove_reverse_entries(stale_reverse_entries);
				}
				catch (const std::bad_alloc&) {
					ERROR("jobs: bad_alloc - out of memory culling reverse table");
				}
				catch (const std::exception& e) {
					ERRORF("jobs: failed to cull reverse table: %s", e.what());
				}

				// Cull the link table according to timeout
				try {
					std::vector<Bytes> stale_links;
					stale_links.reserve(_link_table.size());
					for (const auto& [link_id, link_entry] : _link_table) {
						if (link_entry._validated) {
							if (OS::time() > (link_entry._timestamp + LINK_TIMEOUT)) {
								stale_links.push_back(link_id);
							}
						}
						else {
							if (OS::time() > link_entry._proof_timeout) {
								stale_links.push_back(link_id);

								double last_path_request = 0.0;
								const auto& iter = _path_requests.find(link_entry._destination_hash);
								if (iter != _path_requests.end()) {
									last_path_request = (*iter).second;
								}

								uint8_t lr_taken_hops = link_entry._hops;

								bool path_request_throttle = (OS::time() - last_path_request) < PATH_REQUEST_MI;
								bool path_request_conditions = false;
								
								// If the path has been invalidated between the time of
								// making the link request and now, try to rediscover it
								if (!has_path(link_entry._destination_hash)) {
									DEBUGF("Trying to rediscover path for %s since an attempted link was never established, and path is now missing", link_entry._destination_hash.toHex().c_str());
									path_request_conditions = true;
								}

								// If this link request was originated from a local client
								// attempt to rediscover a path to the destination, if this
								// has not already happened recently.
								else if (!path_request_throttle && lr_taken_hops == 0) {
									DEBUGF("Trying to rediscover path for %s since an attempted local client link was never established", link_entry._destination_hash.toHex().c_str());
									path_request_conditions = true;
								}

								// If the link destination was previously only 1 hop
								// away, this likely means that it was local to one
								// of our interfaces, and that it roamed somewhere else.
								// In that case, try to discover a new path.
								else if (!path_request_throttle && hops_to(link_entry._destination_hash) == 1) {
									DEBUGF("Trying to rediscover path for %s since an attempted link was never established, and destination was previously local to an interface on this instance", link_entry._destination_hash.toHex().c_str());
									path_request_conditions = true;
								}

								// If the link destination was previously only 1 hop
								// away, this likely means that it was local to one
								// of our interfaces, and that it roamed somewhere else.
								// In that case, try to discover a new path.
								else if ( !path_request_throttle and lr_taken_hops == 1) {
									DEBUGF("Trying to rediscover path for %s since an attempted link was never established, and link initiator is local to an interface on this instance", link_entry._destination_hash.toHex().c_str());
									path_request_conditions = true;
								}

								if (path_request_conditions) {
									if (path_requests.count(link_entry._destination_hash) == 0) {
										// CBA ACCUMULATES
										path_requests.insert(link_entry._destination_hash);
									}

									if (!Reticulum::transport_enabled()) {
										// Drop current path if we are not a transport instance, to
										// allow using higher-hop count paths or reused announces
										// from newly adjacent transport instances.
										expire_path(link_entry._destination_hash);
									}
								}
							}
						}
					}
					remove_links(stale_links);
				}
				catch (const std::bad_alloc&) {
					ERROR("jobs: bad_alloc - out of memory culling link table");
				}
				catch (const std::exception& e) {
					ERRORF("jobs: failed to cull link table: %s", e.what());
				}

				/* Spangap: no periodic path sweep. Both checks the old one did
				 * are now lazy and per-lookup, in peek_live_route(): an expired
				 * record and one naming an interface that no longer exists both
				 * clear their routing fields and report a miss on first use, so
				 * the caller path-requests instead of black-holing. Cap
				 * eviction is cull_path_table() at the announce-insert site.
				 *
				VERBOSE("Culling path table...");
				try {
					std::vector<Bytes> stale_paths;
					stale_paths.reserve(_path_table.size());
					for (auto& [destination_hash, destination_entry] : _path_table) {
						const Interface& attached_interface = destination_entry.receiving_interface();
						double destination_expiry;
						if (attached_interface && attached_interface.mode() == Type::Interface::MODE_ACCESS_POINT) {
							destination_expiry = destination_entry._timestamp + AP_PATH_TIME;
						}
						else if (attached_interface && attached_interface.mode() == Type::Interface::MODE_ROAMING) {
							destination_expiry = destination_entry._timestamp + ROAMING_PATH_TIME;
						}
						else {
							destination_expiry = destination_entry._timestamp + DESTINATION_TIMEOUT;
						}

						if (OS::time() > destination_expiry) {
							stale_paths.push_back(destination_hash);
							DBGF_DEMOTE("Path to %s timed out and was removed", destination_hash.toHex().c_str());
						}
						else if (_interfaces.count(attached_interface.get_hash()) == 0) {
							stale_paths.push_back(destination_hash);
							DBGF_DEMOTE("Path to %s was removed since the attached interface no longer exists", destination_hash.toHex().c_str());
						}
					}
					remove_paths(stale_paths);
				}
				catch (const std::bad_alloc&) {
					ERROR("jobs: bad_alloc - out of memory culling path table");
				}
				catch (const std::exception& e) {
					ERRORF("jobs: failed to cull path table: %s", e.what());
				}
				*/

				/* Path-request escalation MOVED below the _jobs_running clear:
				 * it transmits through request_path → Packet::send →
				 * Transport::outbound, which spins on _jobs_running — from
				 * here that is the livelock the teardown comment at the
				 * bottom of this function warns about, and it wedged the rnsd
				 * task solid on hardware. The culls below still see a
				 * resolved entry cleared on the pass after it resolved, one
				 * tick later than before. */

				// Cull the pending discovery path requests table.
				//
				// Spangap deviation: one line for the sweep, not one per entry.
				// A busy peer leaves hundreds of these pending at once, and
				// they expire together — the per-entry line made an expiry a
				// burst of blocking log writes on the rnsd task, long enough
				// that nothing drained the ITS inbox and interfaces logged
				// `ITS send dropped` underneath it. The removals are bounded
				// per sweep for the same reason; whatever is left is expired
				// just as much on the next pass. `OS::time()` is hoisted: it
				// was a call per entry to compare against a value that cannot
				// change during the walk.
				try {
					double cull_now = OS::time();
					std::vector<Bytes> stale_discovery_path_requests;
					for (const auto& [destination_hash, path_entry] : _discovery_path_requests) {
						if (cull_now > path_entry._timeout) {
							stale_discovery_path_requests.push_back(destination_hash);
							if (stale_discovery_path_requests.size() >= CULL_PER_PASS) break;
						}
					}
					if (!stale_discovery_path_requests.empty()) {
						DBGF_DEMOTE("Expired %u waiting path requests (%u still pending)",
							(unsigned)stale_discovery_path_requests.size(),
							(unsigned)(_discovery_path_requests.size() - stale_discovery_path_requests.size()));
						remove_discovery_path_requests(stale_discovery_path_requests);
					}
				}
				catch (const std::bad_alloc&) {
					ERROR("jobs: bad_alloc - out of memory culling discovery path requests");
				}
				catch (const std::exception& e) {
					ERRORF("jobs: failed to cull discovery path requests: %s", e.what());
				}

				// Cull the path requests table (bounded per sweep, as above).
				try {
					double cull_now = OS::time();
					std::vector<Bytes> stale_path_requests;
					for (const auto& [destination_hash, timestamp] : _path_requests) {
						if (cull_now > (timestamp + DESTINATION_TIMEOUT)) {
							stale_path_requests.push_back(destination_hash);
							if (stale_path_requests.size() >= CULL_PER_PASS) break;
						}
					}
					for (const Bytes& destination_hash : stale_path_requests) {
						_path_requests.erase(destination_hash);
					}
				}
				catch (const std::exception& e) {
					ERRORF("jobs: failed to cull path requests: %s", e.what());
				}

				// Cull the tunnel table
				try {
					count = 0;
					std::vector<Bytes> stale_tunnels;
					stale_tunnels.reserve(_tunnels.size());
					for (const auto& [tunnel_id, tunnel_entry] : _tunnels) {
						if (OS::time() > tunnel_entry._expires) {
							stale_tunnels.push_back(tunnel_id);
							TRACEF("Tunnel %s timed out and was removed", tunnel_id.toHex().c_str());
						}
						else {
							std::vector<Bytes> stale_tunnel_paths;
							for (const auto& [destination_hash, destination_entry] : tunnel_entry._serialised_paths) {
								if (OS::time() > (destination_entry._timestamp + DESTINATION_TIMEOUT)) {
									stale_tunnel_paths.push_back(destination_hash);
									TRACEF("Tunnel path to %s timed out and was removed", destination_hash.toHex().c_str());
								}
							}

							//for (const auto& destination_hash : stale_tunnel_paths) {
							for (const Bytes& destination_hash : stale_tunnel_paths) {
								const_cast<TunnelEntry&>(tunnel_entry)._serialised_paths.erase(destination_hash);
								++count;
							}
						}
					}
					if (count > 0) {
						TRACEF("Removed %d tunnel paths", count);
					}
					remove_tunnels(stale_tunnels);
				}
				catch (const std::bad_alloc&) {
					ERROR("jobs: bad_alloc - out of memory culling tunnel table");
				}
				catch (const std::exception& e) {
					ERRORF("jobs: failed to cull tunnel table: %s", e.what());
				}

//#ifndef NDEBUG
				dump_stats();
//#endif

				_tables_last_culled = OS::time();
			}

			// CBA Periodically persist data
			//if (OS::time() > (_last_saved + _save_interval)) {
			//	persist_data();
			//	_last_saved = OS::time();
			//}
		}
		else {
			// Transport jobs were locked, do nothing
			//p pass
		}
	}
	catch (const std::exception& e) {
		ERROR("An exception occurred while running Transport jobs.");
		ERRORF("The contained exception was: %s", e.what());
	}

	_jobs_running = false;

	/* Escalate our own unanswered path requests to the expensive interfaces.
	 * Deferred past the _jobs_running clear like everything below: the
	 * escalation transmits through Transport::outbound(), which spins on
	 * _jobs_running — calling it above the clear wedged the rnsd task in a
	 * permanent sleep loop. */
	escalate_path_requests(OS::time());

	// Spangap: tear down reaped half-open links now that _jobs_running is
	// cleared. teardown() -> LINKCLOSE -> Transport::outbound() spins on
	// _jobs_running, so this MUST run after the assignment above.
	for (auto& link : reap_links) {
		link.teardown();
	}

	// Spangap: poll Resource retransmission watchdogs (adv retries, part
	// re-requests, proof timeouts). Also deferred past the _jobs_running
	// clear — retries transmit through Transport::outbound().
	for (auto& link : watchdog_links) {
		link.resource_watchdogs();
		// Keepalive + stale-link teardown for the ACTIVE/STALE phases.
		// Deferred past _jobs_running like resource_watchdogs: send_keepalive
		// and the STALE teardown transmit through Transport::outbound().
		link.link_watchdog();
	}

	// CBA send announce retransmission packets
	for (auto& packet : outgoing) {
		packet.send();
	}

	// CBA send link-related path requests. Send per-OUT-interface rather than a
	// single broadcast so the point-to-point echo suppression in request_path
	// can skip re-asking a link's own peer. These are this node's own errands,
	// so every OUT interface is asked — the destination may as well be a
	// community member on the radio as a node behind the uplink.
	for (auto& destination_hash : path_requests) {
		for (auto& [interface_hash, interface] : _interfaces) {
			if (interface.OUT()) {
				request_path(destination_hash, interface);
			}
		}
	}
}

// IFAC salt — fixed constant shared by all Reticulum nodes (RNS Reticulum.IFAC_SALT).
// Built once from its hex; kept here (rather than Type.h) to avoid header ODR issues.
static const Bytes& ifac_salt() {
	static const Bytes salt = []{
		Bytes b;
		b.appendHex("adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8");
		return b;
	}();
	return salt;
}

/*static*/ void Transport::derive_ifac(Interface& interface, const std::string& network_name,
		const std::string& passphrase, uint16_t ifac_size) {
	// No network_name and no passphrase => leave the interface open (no IFAC).
	if (network_name.empty() && passphrase.empty()) return;

	if (ifac_size < 1) ifac_size = Type::Reticulum::IFAC_MIN_SIZE;
	if (ifac_size > 64) ifac_size = 64;   // sig is 64 bytes; cap the access-code length

	// ifac_origin = full_hash(network_name) ++ full_hash(passphrase), each only if set.
	Bytes ifac_origin;
	if (!network_name.empty()) ifac_origin.append(Identity::full_hash(Bytes(network_name)));
	if (!passphrase.empty())   ifac_origin.append(Identity::full_hash(Bytes(passphrase)));

	Bytes ifac_origin_hash = Identity::full_hash(ifac_origin);
	Bytes ifac_key = Cryptography::hkdf(64, ifac_origin_hash, ifac_salt(), {Bytes::NONE});

	Identity ifac_identity(false);   // false => do not auto-generate keys
	if (!ifac_identity.load_private_key(ifac_key)) {
		ERRORF("Failed to load IFAC identity for %s", interface.toString().c_str());
		return;
	}

	interface.ifac_size(ifac_size);
	interface.ifac_key(ifac_key);
	interface.ifac_identity(ifac_key);                 // non-empty => IFAC enabled
	interface.ifac_identity_obj(ifac_identity);
	interface.ifac_signature(ifac_identity.sign(Identity::full_hash(ifac_key)));
}

/*static*/ void Transport::transmit(Interface& interface, const Bytes& raw) {
	TRACE("Transport::transmit()");
	// CBA
	if (_callbacks._transmit_packet) {
		try {
			_callbacks._transmit_packet(raw, interface);
		}
		catch (const std::exception& e) {
			DEBUGF("Error while executing transmit packet callback. The contained exception was: %s", e.what());
		}
	}
	try {
		//if hasattr(interface, "ifac_identity") and interface.ifac_identity != None:
		if (interface.ifac_identity()) {
			const uint16_t ifac_size = interface.ifac_size();

			// Access code: the last ifac_size bytes of the Ed25519 signature over
			// the raw packet. Inbound authenticates by recomputing this signature,
			// which relies on the signer being DETERMINISTIC (RFC 8032 Ed25519) —
			// do not swap in a randomized/hedged signer or every inbound IFAC
			// packet will fail verification and be dropped silently.
			Bytes ifac = interface.ifac_identity_obj().sign(raw).right(ifac_size);

			// Mask = HKDF(len(raw)+ifac_size, derive_from=ifac, salt=ifac_key).
			Bytes mask = Cryptography::hkdf(raw.size() + ifac_size, ifac,
				interface.ifac_key(), {Bytes::NONE});

			// new_raw = [raw[0]|0x80, raw[1]] + ifac + raw[2:]
			Bytes new_raw;
			new_raw.append((uint8_t)(raw[0] | 0x80));
			new_raw.append(raw[1]);
			new_raw.append(ifac);
			new_raw.append(raw.mid(2));

			// Mask every byte except the ifac field (indices 2..ifac_size+1),
			// keeping the IFAC flag set on byte 0 after masking.
			Bytes masked_raw;
			for (size_t i = 0; i < new_raw.size(); ++i) {
				uint8_t b = new_raw[i];
				if (i == 0)
					masked_raw.append((uint8_t)((b ^ mask[i]) | 0x80));
				else if (i == 1 || i > (size_t)(ifac_size + 1))
					masked_raw.append((uint8_t)(b ^ mask[i]));
				else
					masked_raw.append(b);
			}

			interface.send_outgoing(masked_raw);
		}
		else {
			interface.send_outgoing(raw);
		}
	}
	catch (const std::exception& e) {
		ERRORF("Error while transmitting on %s. The contained exception was: %s", interface.toString().c_str(), e.what());
	}
}

/*static*/ bool Transport::outbound(Packet& packet) {
	TRACE("Transport::outbound()");
	++_packets_sent;

	if (!packet.destination()) {
		//throw std::invalid_argument("Can not send packet with no destination.");
		ERROR("Can not send packet with no destination");
		return false;
	}

	TRACEF("Transport::outbound: destination=%s hops=%d", packet.destination_hash().toHex().c_str(), packet.hops());

	while (_jobs_running) {
		TRACE("Transport::outbound: sleeping...");
		OS::sleep(0.0005);
	}
	_jobs_locked = true;

	bool sent = false;
	// An announce deferred into an interface's bandwidth-cap queue is handled,
	// not failed — it will be emitted later by process_announce_queue(). Track
	// that separately so outbound() doesn't report it as undeliverable (which
	// made Packet::send log a spurious "No interfaces could process" error for
	// every capped announce).
	bool deferred = false;
	double outbound_time = OS::time();

	// Check if we have a known path for the destination in the path table
    //if packet.packet_type != RNS.Packet.ANNOUNCE and packet.destination.type != RNS.Destination.PLAIN and packet.destination.type != RNS.Destination.GROUP and packet.destination_hash in Transport.destination_table:
	/* This is the per-packet path. It copies a fixed-size route out of the
	 * directory pool and resolves one interface — it allocates nothing and
	 * constructs no Packet. */
	rdir_route_t route;
	Interface outbound_interface = {Type::NONE};
	bool have_route = false;
	if (packet.packet_type() != Type::Packet::ANNOUNCE && packet.destination().type() != Type::Destination::PLAIN && packet.destination().type() != Type::Destination::GROUP) {
		have_route = peek_live_route(packet.destination_hash(), route, outbound_interface);
	}
	if (have_route) {
		TRACE("Transport::outbound: Path to destination is known");
        //outbound_interface = Transport.destination_table[packet.destination_hash][5]
		Bytes received_from(route.received_from, RDIR_DEST_LEN);

		// If there's more than one hop to the destination, and we know
		// a path, we insert the packet into transport by adding the next
		// transport nodes address to the header, and modifying the flags.
		// This rule applies both for "normal" transport, and when connected
		// to a local shared Reticulum instance.
        //if Transport.destination_table[packet.destination_hash][2] > 1:
		if (route.hops > 1) {
			TRACE("Forwarding packet to next closest interface...");
			if (packet.header_type() == Type::Packet::HEADER_1) {
				// Insert packet into transport
                //new_flags = (RNS.Packet.HEADER_2) << 6 | (Transport.TRANSPORT) << 4 | (packet.flags & 0b00001111)
				uint8_t new_flags = (Type::Packet::HEADER_2) << 6 | (Type::Transport::TRANSPORT) << 4 | (packet.flags() & 0b00001111);
				// CBA RESERVE
				//Bytes new_raw;
				Bytes new_raw(512);
				//new_raw = struct.pack("!B", new_flags)
				new_raw << new_flags;
				//new_raw += packet.raw[1:2]
				new_raw << packet.raw().mid(1,1);
				//new_raw += Transport.destination_table[packet.destination_hash][1]
				new_raw << received_from;
				//new_raw += packet.raw[2:]
				new_raw << packet.raw().mid(2);
				transmit(outbound_interface, new_raw);
				//_path_table[packet.destination_hash][0] = time.time()
				/* Upstream refreshes the path timestamp here; `timestamp` stays
				 * the announce time and outbound use is stamped on the stored
				 * record below instead. */
				sent = true;
			}
		}

		// In the special case where we are connected to a local shared
		// Reticulum instance, and the destination is one hop away, we
		// also add transport headers to inject the packet into transport
		// via the shared instance. Normally a packet for a destination
		// one hop away would just be broadcast directly, but since we
		// are "behind" a shared instance, we need to get that instance
		// to transport it onto the network.
        //elif Transport.destination_table[packet.destination_hash][2] == 1 and Transport.owner.is_connected_to_shared_instance:
		else if (route.hops == 1 && _owner.is_connected_to_shared_instance()) {
			TRACE("Transport::outbound: Sending packet for directly connected interface to shared instance...");
			if (packet.header_type() == Type::Packet::HEADER_1) {
				// Insert packet into transport
				//new_flags = (RNS.Packet.HEADER_2) << 6 | (Transport.TRANSPORT) << 4 | (packet.flags & 0b00001111)
				uint8_t new_flags = (Type::Packet::HEADER_2) << 6 | (Type::Transport::TRANSPORT) << 4 | (packet.flags() & 0b00001111);
				// CBA RESERVE
				//Bytes new_raw;
				Bytes new_raw(512);
				//new_raw = struct.pack("!B", new_flags)
				new_raw << new_flags;
				//new_raw += packet.raw[1:2]
				new_raw << packet.raw().mid(1, 1);
				//new_raw += Transport.destination_table[packet.destination_hash][1]
				new_raw << received_from;
				//new_raw += packet.raw[2:]
				new_raw << packet.raw().mid(2);
				transmit(outbound_interface, new_raw);
				//Transport.destination_table[packet.destination_hash][0] = time.time()
				/* See the transport case above: outbound use is stamped on the
				 * stored record below instead. */
				sent = true;
			}
		}

		// If none of the above applies, we know the destination is
		// directly reachable, and also on which interface, so we
		// simply transmit the packet directly on that one.
		else {
			TRACE("Transport::outbound: Sending packet over directly connected interface...");
			transmit(outbound_interface, packet.raw());
			sent = true;
		}

		/* Record outbound use on the stored record, so eviction ranks a route
		 * we actively send to above one we merely heard announced. Coarse on
		 * purpose (PATH_LAST_USED_GRANULARITY): only eviction ordering and the
		 * in-use test read it, and it saves a write per packet. */
		uint32_t now_s = (uint32_t)outbound_time;
		if (sent && (uint32_t)(now_s - route.last_used) >= Type::Transport::PATH_LAST_USED_GRANULARITY) {
			rdirTouchUsed(packet.destination_hash().data(),
			              now_s + path_ttl_for(outbound_interface, route.hops));
		}
	}
	// If we don't have a known path for the destination, we'll
	// broadcast the packet on all outgoing interfaces, or the
	// just the relevant interface if the packet has an attached
	// interface, or belongs to a link.
	else {
		TRACE("Transport::outbound: Path to destination is unknown");
		bool stored_hash = false;
		/* Fail-open link pin: only enforce the Link's interface pin if that
		 * interface is actually among our current OUT interfaces. The pin is
		 * packet.destination_link().attached_interface() == the interface the
		 * link traffic arrived on, which can be a per-connection SPAWNED child
		 * (a TCP-accepted socket, a shared-instance client) or a replaced impl
		 * that never appears in _interfaces (keyed by name-hash) under that
		 * name. Enforcing an unmatchable pin drops link DATA/PROOF on every
		 * interface — a black hole. Broadcasting in that case restores delivery
		 * (pre-pin behaviour) while keeping the restriction whenever the pin is
		 * honorable. */
		std::string link_pin;
		bool link_pin_matchable = false;
		if (packet.destination().type() == Type::Destination::LINK && packet.destination_link()) {
			const Interface& link_iface = packet.destination_link().attached_interface();
			if (link_iface) {
				link_pin = link_iface.toString();
				for (auto& [h2, if2] : _interfaces)
					if (if2.OUT() && if2.toString() == link_pin) { link_pin_matchable = true; break; }
			}
		}
		for (auto& [hash, interface] : _interfaces) {
			TRACEF("Transport::outbound: Checking interface %s", interface.toString().c_str());
			if (interface.OUT()) {
				bool should_transmit = true;

				if (packet.destination().type() == Type::Destination::LINK) {
					if (!packet.destination_link()) throw std::invalid_argument("Packet is not associated with a Link");
					if (packet.destination_link().status() == Type::Link::CLOSED) {
						TRACE("Transport::outbound: Pscket destination is link-closed, not transmitting");
						should_transmit = false;
					}
					/* Link traffic follows the interface the Link is pinned to
					 * (upstream checks packet.destination.attached_interface;
					 * here the pin lives on the Link, which re-pins when the
					 * peer shows up on another interface — see Link::receive).
					 * Compare by name, not impl identity: a reconnect creates
					 * a new impl with the same name and must keep carrying the
					 * link. No pin yet (pre-proof) → broadcast on all OUT
					 * interfaces, as for any other unknown-path packet. */
					if (should_transmit && link_pin_matchable && interface.toString() != link_pin) {
						TRACE("Transport::outbound: Interface is not the link's attached interface, not transmitting");
						should_transmit = false;
					}
				}
				
				if (packet.attached_interface() && interface != packet.attached_interface()) {
					TRACE("Transport::outbound: Packet has wrong attached interface, not transmitting");
					should_transmit = false;
				}

				if (packet.packet_type() == Type::Packet::ANNOUNCE) {
					if (!packet.attached_interface()) {
						TRACE("Transport::outbound: Packet has no attached interface");
						/* Community radius: relay work is done for the members
						 * on the egress interface, so a forwarded announce is
						 * re-broadcast only within their radius — the uplink's
						 * firehose is never sprayed across a radio, and an
						 * interface with no community (radius 0) relays
						 * nothing. Instance-local destinations are exempt:
						 * this node's own announces are a trickle, and they
						 * must reach every interface or the node can never be
						 * discovered there. */
						if (_destinations.find(packet.destination_hash()) == _destinations.end()
						    && packet.hops() > interface.community_radius()) {
							TRACEF("Blocking announce broadcast on %s beyond its community radius", interface.toString().c_str());
							should_transmit = false;
						}
						else if (interface.mode() == Type::Interface::MODE_ROAMING) {
							//local_destination = next((d for d in Transport.destinations if d.hash == packet.destination_hash), None)
							//Destination local_destination({Type::NONE});
							auto iter = _destinations.find(packet.destination_hash());
							//if (iter != _destinations.end()) {
							//	local_destination = (*iter).second;
							//}
							if (iter != _destinations.end()) {
								TRACE("Allowing announce broadcast on roaming-mode interface from instance-local destination");
							}
							else {
								const Interface& from_interface = next_hop_interface(packet.destination_hash());
								//if from_interface == None or not hasattr(from_interface, "mode"):
								if (!from_interface || from_interface.mode() == Type::Interface::MODE_NONE) {
									should_transmit = false;
									if (!from_interface) {
										TRACEF("Blocking announce broadcast on %s since next hop interface doesn't exist", interface.toString().c_str());
									}
									else if (from_interface.mode() == Type::Interface::MODE_NONE) {
										TRACEF("Blocking announce broadcast on %s since next hop interface has no mode configured", interface.toString().c_str());
									}
								}
								else {
									if (from_interface.mode() == Type::Interface::MODE_ROAMING) {
										TRACEF("Blocking announce broadcast on %s due to roaming-mode next-hop interface", interface.toString().c_str());
										should_transmit = false;
									}
									else if (from_interface.mode() == Type::Interface::MODE_BOUNDARY) {
										TRACEF("Blocking announce broadcast on %s due to boundary-mode next-hop interface", interface.toString().c_str());
										should_transmit = false;
									}
								}
							}
						}
						else if (interface.mode() == Type::Interface::MODE_BOUNDARY) {
							//local_destination = next((d for d in Transport.destinations if d.hash == packet.destination_hash), None)
							// next and filter pattern?
							// next(iterable, default)
							// list comprehension: [x for x in xyz if x in a]
							// CBA TODO confirm that above pattern just selects the first matching destination
							auto iter = _destinations.find(packet.destination_hash());
							if (iter != _destinations.end()) {
								TRACE("Allowing announce broadcast on boundary-mode interface from instance-local destination");
							}
							else {
								const Interface& from_interface = next_hop_interface(packet.destination_hash());
								if (!from_interface || from_interface.mode() == Type::Interface::MODE_NONE) {
									should_transmit = false;
									if (!from_interface) {
										TRACEF("Blocking announce broadcast on %s since next hop interface doesn't exist", interface.toString().c_str());
									}
									else if (from_interface.mode() == Type::Interface::MODE_NONE) {
										TRACEF("Blocking announce broadcast on %s since next hop interface has no mode configured", interface.toString().c_str());
									}
								}
								else {
									if (from_interface.mode() == Type::Interface::MODE_ROAMING) {
										TRACEF("Blocking announce broadcast on %s due to roaming-mode next-hop interface", interface.toString().c_str());
										should_transmit = false;
									}
								}
							}
						}
						else {
							// Currently, annouces originating locally are always
							// allowed, and do not conform to bandwidth caps.
							// TODO: Rethink whether this is actually optimal.
							if (packet.hops() > 0) {

// TODO
/*p
								if not hasattr(interface, "announce_cap"):
									interface.announce_cap = RNS.Reticulum.ANNOUNCE_CAP

								if not hasattr(interface, "announce_allowed_at"):
									interface.announce_allowed_at = 0

								if not hasattr(interface, "announce_queue"):
										interface.announce_queue = []
*/

								// Echo suppression, only on interfaces with no hidden-
								// node problem (point_to_point: TCP, switched LAN).
								// There, echoing a forwarded announce back out the
								// interface it arrived on just returns it to the single
								// peer that already has it. On shared radio (LoRa,
								// ESP-NOW) point_to_point is false, so we still
								// re-broadcast — that is how a node hidden from the
								// origin, but in range of us, hears the announce.
								// Keyed on the announce's receiving interface (carried
								// on the rebroadcast packet), not a path-table lookup,
								// so it holds even after path culls / interface
								// reconnects.
								const Interface& received_on = packet.receiving_interface();
								bool p2p_echo = interface.point_to_point() && received_on
									&& received_on.get_hash() == interface.get_hash();

								bool queued_announces = (interface.announce_queue().size() > 0);
								if (p2p_echo) {
									should_transmit = false;
								}
								else if (!queued_announces && outbound_time > interface.announce_allowed_at()) {
									// Seconds, in floating point: a frame's airtime is
									// well under 1 s on fast links, so integer math here
									// truncated tx_time (and thus wait_time) to 0 and the
									// cap never engaged. announce_allowed_at is a double.
									double wait_time = 0;
									if (interface.bitrate() > 0 && interface.announce_cap() > 0) {
										double tx_time = (double)(packet.raw().size() * 8) / (double)interface.bitrate();
										wait_time = tx_time / interface.announce_cap();
									}
									interface.announce_allowed_at(outbound_time + wait_time);
								}
								else {
									should_transmit = false;
									if (interface.announce_queue().size() < Type::Reticulum::MAX_QUEUED_ANNOUNCES) {
										bool should_queue = true;
										for (auto& entry : interface.announce_queue()) {
											if (entry._destination == packet.destination_hash()) {
												uint64_t emission_timestamp = announce_emitted(packet);
												should_queue = false;
												if (emission_timestamp > entry._emitted) {
													entry._time = outbound_time;
													entry._hops = packet.hops();
													entry._emitted = emission_timestamp;
													entry._raw = packet.raw();
												}
												break;
											}
										}
										if (should_queue) {
											RNS::AnnounceEntry entry(
												packet.destination_hash(),
												outbound_time,
												packet.hops(),
												announce_emitted(packet),
												packet.raw()
											);

											queued_announces = (interface.announce_queue().size() > 0);
											// CBA ACCUMULATES
											interface.add_announce(entry);
											deferred = true;

											if (!queued_announces) {
												double wait_time = std::max(interface.announce_allowed_at() - OS::time(), (double)0);

												// CBA TODO THREAD?
												//z timer = threading.Timer(wait_time, interface.process_announce_queue)
												//z timer.start()

												if (wait_time < 1000) {
													TRACEF("Added announce to queue (height %lu) on %s for processing in %d ms", interface.announce_queue().size(), interface.toString().c_str(), (int)wait_time);
												}
												else {
													TRACEF("Added announce to queue (height %lu) on %s for processing in %.1f s", interface.announce_queue().size(), interface.toString().c_str(), OS::round(wait_time/1000,1));
												}
											}
											else {
												double wait_time = std::max(interface.announce_allowed_at() - OS::time(), (double)0);
												if (wait_time < 1000) {
													TRACEF("Added announce to queue (height %lu) on %s for processing in %d ms", interface.announce_queue().size(), interface.toString().c_str(), (int)wait_time);
												}
												else {
													TRACEF("Added announce to queue (height %lu) on %s for processing in %.1f s", interface.announce_queue().size(), interface.toString().c_str(), OS::round(wait_time/1000,1));
												}
											}
										}
									}
									else {
										//p pass
									}
								}
							}
							else {
								//p pass
							}
						}
					}
				}
						
				if (should_transmit) {
					TRACE("Transport::outbound: Packet transmission allowed");
					if (!stored_hash) {
						// CBA ACCUMULATES
						_packet_hashlist.insert(packet.packet_hash());
						stored_hash = true;
					}

					// TODO: Re-evaluate potential for blocking
					// def send_packet():
					//     Transport.transmit(interface, packet.raw)
					// thread = threading.Thread(target=send_packet)
					// thread.daemon = True
					// thread.start()

					transmit(interface, packet.raw());
					sent = true;
				}
				else {
					TRACE("Transport::outbound: Packet transmission refused");
				}
			}
		}
	}

	if (sent) {
		packet.sent(true);
		packet.sent_at(OS::time());

		// Don't generate receipt if it has been explicitly disabled
		if (packet.create_receipt() &&
			// Only generate receipts for DATA packets
			packet.packet_type() == Type::Packet::DATA &&
			// Don't generate receipts for PLAIN destinations
			packet.destination().type() != Type::Destination::PLAIN &&
			// Don't generate receipts for link-related packets
			!(packet.context() >= Type::Packet::KEEPALIVE && packet.context() <= Type::Packet::LRPROOF) &&
			// Don't generate receipts for resource packets
			!(packet.context() >= Type::Packet::RESOURCE && packet.context() <= Type::Packet::RESOURCE_RCL)) {

			PacketReceipt receipt(packet);
			packet.receipt(receipt);
			// CBA ACCUMULATES
			_receipts.push_back(receipt);
		}

		cache_packet(packet);
	}

	// A forwarded announce (hops>0) that this node chose not to re-broadcast on
	// any interface — AP mode, an over-full cap queue, point-to-point echo
	// suppression — is a
	// routing decision, not a delivery failure. Treat it as handled so
	// Packet::send doesn't log "No interfaces could process" for it. Own
	// announces (hops==0) that reach no interface are still reported honestly.
	// Say so in one line rather than leaving the caller to claim it was sent:
	// "handled" is not "transmitted", and a log that conflates them is how a
	// node that relayed nothing for hours still read as working.
	if (!sent && !deferred && packet.packet_type() == Type::Packet::ANNOUNCE && packet.hops() > 0) {
		VERBOSEF("Transport::outbound: announce %s hops=%d not relayed on any interface",
			packet.destination_hash().toHex().c_str(), (int)packet.hops());
		deferred = true;
	}

	_jobs_locked = false;
	return sent || deferred;
}

#if 0
/*static*/ bool Transport::packet_filter(const Packet& packet) {
	// TODO: Think long and hard about this.
	// Is it even strictly necessary with the current
	// transport rules?
	if (packet.context() == Type::Packet::KEEPALIVE) {
		return true;
	}
	if (packet.context() == Type::Packet::RESOURCE_REQ) {
		return true;
	}
	if (packet.context() == Type::Packet::RESOURCE_PRF) {
		return true;
	}
	if (packet.context() == Type::Packet::RESOURCE) {
		return true;
	}
	if (packet.context() == Type::Packet::CACHE_REQUEST) {
		return true;
	}
	if (packet.context() == Type::Packet::CHANNEL) {
		return true;
	}

	if (packet.destination_type() == Type::Destination::PLAIN) {
		if (packet.packet_type() != Type::Packet::ANNOUNCE) {
			if (packet.hops() > 1) {
				DEBUGF("Dropped PLAIN packet %s with %d hops", packet.packet_hash().toHex().c_str(), packet.hops());
				return false;
			}
			else {
				return true;
			}
		}
		else {
			DBG_DEMOTE("Dropped invalid PLAIN announce packet");
			return false;
		}
	}

	if (packet.destination_type() == Type::Destination::GROUP) {
		if (packet.packet_type() != Type::Packet::ANNOUNCE) {
			if (packet.hops() > 1) {
				DEBUGF("Dropped GROUP packet %s with %d hops", packet.packet_hash().toHex().c_str(), packet.hops());
				return false;
			}
			else {
				return true;
			}
		}
		else {
			DBG_DEMOTE("Dropped invalid GROUP announce packet");
			return false;
		}
	}

	if (_packet_hashlist.find(packet.packet_hash()) == _packet_hashlist.end()) {
		TRACE("Transport::packet_filter: packet not previously seen");
		return true;
	}
	else {
		if (packet.packet_type() == Type::Packet::ANNOUNCE) {
			if (packet.destination_type() == Type::Destination::SINGLE) {
				TRACE("Transport::packet_filter: packet previously seen but is SINGLE ANNOUNCE");
				return true;
			}
			else {
				DBG_DEMOTE("Dropped invalid announce packet");
				return false;
			}
		}
	}

	DEBUGF("Filtered packet with hash %s", packet.packet_hash().toHex().c_str());
	return false;
}
#endif

/*static*/ bool Transport::packet_filter(const Packet& packet) {

	// If connected to a shared instance, it will handle
	// packet filtering
	if (_owner && _owner.is_connected_to_shared_instance()) return true;

	// Filter packets intended for other transport instances
	if (packet.transport_id() && packet.packet_type() != Type::Packet::ANNOUNCE) {
		if (packet.transport_id() != Transport::identity().hash()) {
			TRACEF("Ignored packet %s in transport for other transport instance", packet.packet_hash().toHex().c_str());
			return false;
		}
	}

	switch (packet.context()) {
		case Type::Packet::KEEPALIVE: return true;
		case Type::Packet::RESOURCE_REQ: return true;
		case Type::Packet::RESOURCE_PRF: return true;
		case Type::Packet::RESOURCE: return true;
		case Type::Packet::CACHE_REQUEST: return true;
		case Type::Packet::CHANNEL: return true;
		default: break;
	}

	if (packet.destination_type() == Type::Destination::PLAIN) {
		if (packet.packet_type() != Type::Packet::ANNOUNCE) {
			if (packet.hops() > 1) {
				DBGF_DEMOTE("Dropped PLAIN packet %s with %u hops", packet.packet_hash().toHex().c_str(), packet.hops());
				return false;
			}
			else {
				return true;
			}
		}
		else {
			DBG_DEMOTE("Dropped invalid PLAIN announce packet");
			return false;
		}
	}

	if (packet.destination_type() == Type::Destination::GROUP) {
		if (packet.packet_type() != Type::Packet::ANNOUNCE) {
			if (packet.hops() > 1) {
				DBGF_DEMOTE("Dropped GRPUP packet %s with %u hops", packet.packet_hash().toHex().c_str(), packet.hops());
				return false;
			}
			else {
				return true;
			}
		}
		else {
			DBG_DEMOTE("Dropped invalid GROUP announce packet");
			return false;
		}
	}

	//p if not packet.packet_hash in Transport.packet_hashlist and not packet.packet_hash in Transport.packet_hashlist_prev:
	if (_packet_hashlist.find(packet.packet_hash()) == _packet_hashlist.end()) {
		TRACE("Transport::packet_filter: packet not previously seen");
		return true;
	}
	else {
		if (packet.packet_type() == Type::Packet::ANNOUNCE) {
			if (packet.destination_type() == Type::Destination::SINGLE) {
				TRACE("Transport::packet_filter: packet previously seen but is SINGLE ANNOUNCE");
				return true;
			}
			else {
				DBG_DEMOTE("Dropped invalid announce packet");
				return false;
			}
		}
	}

	DEBUGF("Filtered packet with hash %s", packet.packet_hash().toHex().c_str());
	return false;
}

/*static*/ void Transport::inbound(const Bytes& raw_in, const Interface& interface /*= {Type::NONE}*/) {
	// Mutable working copy: the IFAC block below rewrites it in place to the
	// de-IFAC'd packet, which the rest of this function then decodes.
	Bytes raw = raw_in;
	TRACEF("Transport::inbound: received %d bytes", raw.size());
	++_packets_received;
	// CBA
	if (_callbacks._receive_packet) {
		try {
			_callbacks._receive_packet(raw, interface);
		}
		catch (const std::exception& e) {
			DEBUGF("Error while executing receive packet callback. The contained exception was: %s", e.what());
		}
	}
	// IFAC (Interface Access Codes): on interfaces with an IFAC network
	// configured, authenticate and de-mask every packet; drop anything that
	// doesn't verify. Mirrors upstream RNS Transport.inbound byte-for-byte.
	if (raw.size() > 2) {
		if (interface && interface.ifac_identity()) {
			// IFAC enabled on this interface — the IFAC flag must be set.
			if ((raw[0] & 0x80) == 0x80) {
				const uint16_t ifac_size = interface.ifac_size();
				if (raw.size() > (size_t)(2 + ifac_size)) {
					// Extract the (unmasked) IFAC field.
					Bytes ifac = raw.mid(2, ifac_size);

					// Mask = HKDF(len(raw), derive_from=ifac, salt=ifac_key).
					Bytes mask = Cryptography::hkdf(raw.size(), ifac,
						interface.ifac_key(), {Bytes::NONE});

					// Unmask everything except the ifac field itself.
					Bytes unmasked_raw;
					for (size_t i = 0; i < raw.size(); ++i) {
						uint8_t b = raw[i];
						if (i <= 1 || i > (size_t)(ifac_size + 1))
							unmasked_raw.append((uint8_t)(b ^ mask[i]));
						else
							unmasked_raw.append(b);
					}

					// Clear the IFAC flag and strip the ifac field to reconstruct
					// the exact bytes the sender signed.
					Bytes new_raw;
					new_raw.append((uint8_t)(unmasked_raw[0] & 0x7f));
					new_raw.append(unmasked_raw[1]);
					new_raw.append(unmasked_raw.mid(2 + ifac_size));

					Bytes expected_ifac =
						interface.ifac_identity_obj().sign(new_raw).right(ifac_size);

					if (ifac == expected_ifac) {
						raw = new_raw;
					}
					else {
						TRACE("Transport::inbound: IFAC authentication failed, dropping packet");
						return;
					}
				}
				else {
					return;
				}
			}
			else {
				// IFAC flag not set but this interface requires IFAC — drop.
				return;
			}
		}
		else {
			// Open (non-IFAC) interface — reject any packet that carries the
			// IFAC flag (it belongs to an access-coded network).
			if ((raw[0] & 0x80) == 0x80) {
				return;
			}
		}
	}
	else {
		return;
	}

	while (_jobs_running) {
		TRACE("Transport::inbound: sleeping...");
		OS::sleep(0.0005);
	}

	if (!_identity) {
		WARNING("Transport::inbound: No identity!");
		return;
	}

	/* Release the lock on every exit path — this function has multiple
	 * early returns (malformed packet, cache request, link MTU clamp);
	 * a leaked _jobs_locked = true permanently disables Transport::jobs()
	 * because it gates on `if (!_jobs_locked)`. RAII guard ensures the
	 * lock matches the function's scope. */
	struct JobsLockGuard { ~JobsLockGuard() { _jobs_locked = false; } };
	_jobs_locked = true;
	JobsLockGuard _jl;

	Packet packet(RNS::Destination(RNS::Type::NONE), raw);
	if (!packet.unpack()) {
		/* Malformed inbound packets often arrive in floods (a peer
		 * retransmitting the same bad frame every second). De-dup on
		 * interface + size + first 8 bytes: warn once per distinct
		 * signature, count silent repeats, and emit a one-line summary
		 * when the signature changes. Interface is named here because
		 * Packet::unpack() has no view of where the bytes came from. */
		static std::string s_lastSig;
		static uint32_t s_suppressed = 0;
		static double s_firstTime = 0.0;

		const std::string ifname = interface ? interface.name() : "<unknown>";
		char hex[32] = {0};
		size_t dump = raw.size() < 8 ? raw.size() : 8;
		for (size_t i = 0; i < dump; ++i)
			std::snprintf(hex + 3*i, 4, "%02x ", raw.data()[i]);
		std::string sig = ifname + "|" + std::to_string(raw.size()) + "|" + hex;

		if (sig == s_lastSig) {
			++s_suppressed;
		}
		else {
			if (s_suppressed > 0)
				WARNINGF("Transport::inbound: dropped %lu more malformed packet(s) over %.0fs",
				         (unsigned long)s_suppressed, OS::time() - s_firstTime);
			WARNINGF("Transport::inbound: dropping malformed packet on [%s] (%zuB, first=%s)",
			         ifname.c_str(), raw.size(), hex);
			s_lastSig = sig;
			s_suppressed = 0;
			s_firstTime = OS::time();
		}
		return;
	}
#ifndef NDEBUG
	TRACEF("Transport::inbound: packet: %s", packet.debugString().c_str());
#endif

	TRACEF("Transport::inbound: destination=%s hops=%d", packet.destination_hash().toHex().c_str(), packet.hops());

	packet.receiving_interface(interface);
	packet.hops(packet.hops() + 1);

	// Attach the receiving interface's last-packet radio signal (set by the
	// driver just before handle_incoming). Consumers read packet.rssi()/snr();
	// Link.cpp copies them onto the Link so they survive to link callbacks. The
	// upstream local_client_rssi_cache (shared-instance RPC) is not used here.
	if (interface) {
		if (!Type::isNan(interface.r_stat_rssi())) packet.rssi(interface.r_stat_rssi());
		if (!Type::isNan(interface.r_stat_snr()))  packet.snr(interface.r_stat_snr());
	}

	if (_local_client_interfaces.size() > 0) {
		if (is_local_client_interface(interface)) {
			packet.hops(packet.hops() - 1);
		}
	}
	else if (interface_to_shared_instance(interface)) {
		packet.hops(packet.hops() - 1);
	}

	//if (packet_filter(packet)) {
	// CBA
	bool accept = true;
	if (_callbacks._filter_packet) {
		try {
			accept = _callbacks._filter_packet(packet);
		}
		catch (const std::exception& e) {
			DEBUGF("Error while executing filter packet callback. The contained exception was: %s", e.what());
		}
	}
	if (accept) {
		accept = packet_filter(packet);
	}
	if (accept) {
		TRACE("Transport::inbound: Packet accepted by filter");

		// Defer hashlist insertion for packets belonging to links in
		// our link table, and for LRPROOF packets. On shared-medium
		// interfaces (e.g. LoRa), a packet may arrive on the "wrong"
		// interface first. Premature hash insertion would cause the
		// correct arrival to be filtered as a duplicate.
		// Reference: Python Transport.py lines 1362-1373
		bool remember_packet_hash = true;
		if (_link_table.find(packet.destination_hash()) != _link_table.end()) {
			remember_packet_hash = false;
		}
		if (packet.packet_type() == Type::Packet::PROOF && packet.context() == Type::Packet::LRPROOF) {
			remember_packet_hash = false;
		}
		if (remember_packet_hash) {
			// CBA ACCUMULATES
			_packet_hashlist.insert(packet.packet_hash());
		}

		// CBA Currently this packet cache is a noop since it's not forced
		cache_packet(packet);
		
		// Check special conditions for local clients connected
		// through a shared Reticulum instance
		//p from_local_client         = (packet.receiving_interface in Transport.local_client_interfaces)
		bool from_local_client         = (_local_client_interfaces.find(packet.receiving_interface()) != _local_client_interfaces.end());
		//p for_local_client          = (packet.packet_type != RNS.Packet.ANNOUNCE) and (packet.destination_hash in Transport.destination_table and Transport.destination_table[packet.destination_hash][2] == 0)
		//p for_local_client_link     = (packet.packet_type != RNS.Packet.ANNOUNCE) and (packet.destination_hash in Transport.link_table and Transport.link_table[packet.destination_hash][4] in Transport.local_client_interfaces)
		//p for_local_client_link    |= (packet.packet_type != RNS.Packet.ANNOUNCE) and (packet.destination_hash in Transport.link_table and Transport.link_table[packet.destination_hash][2] in Transport.local_client_interfaces)

		// If packet is anything besides ANNOUNCE then determine if it's destinated for a local destination or link
		bool for_local_client = false;
		bool for_local_client_link = false;
		if (packet.packet_type() != Type::Packet::ANNOUNCE) {
			rdir_route_t route;
			if (rdirPeekRoute(packet.destination_hash().data(), &route) && route.hops == 0) {
				// Destined for a local destination
				for_local_client = true;
			}
			auto link_iter = _link_table.find(packet.destination_hash());
			if (link_iter != _link_table.end()) {
				LinkEntry link_entry = (*link_iter).second;
			 	if (_local_client_interfaces.find(link_entry._receiving_interface) != _local_client_interfaces.end()) {
					// Destined for a local link
					for_local_client_link = true;
				}
			 	if (_local_client_interfaces.find(link_entry._outbound_interface) != _local_client_interfaces.end()) {
					// Destined for a local link
					for_local_client_link = true;
				}
			}
		}

		// Determine if packet is proof for local destination???
		//p proof_for_local_client    = (packet.destination_hash in Transport.reverse_table) and (Transport.reverse_table[packet.destination_hash][0] in Transport.local_client_interfaces)
		bool proof_for_local_client = false;
		auto reverse_iter = _reverse_table.find(packet.destination_hash());
		if (reverse_iter != _reverse_table.end()) {
			ReverseEntry reverse_entry = (*reverse_iter).second;
			if (_local_client_interfaces.find(reverse_entry._receiving_interface) != _local_client_interfaces.end()) {
				// Proof for local destination???
				proof_for_local_client = true;
			}
		}

		// Plain broadcast packets from local clients are sent
		// directly on all attached interfaces, since they are
		// never injected into transport.

		// If packet is not destined for a local transport-specific destination
		if (_control_hashes.find(packet.destination_hash()) == _control_hashes.end()) {
			// If packet is destination type PLAIN and transport type BROADCAST
			if (packet.destination_type() == Type::Destination::PLAIN && packet.transport_type() == Type::Transport::BROADCAST) {
				// Send to all interfaces except the one the packet was recieved on
				if (from_local_client) {
					for (auto& [hash, interface] : _interfaces) {
						if (interface != packet.receiving_interface()) {
							TRACEF("Transport::inbound: Broadcasting packet on %s", interface.toString().c_str());
							transmit(interface, packet.raw());
						}
					}
				}
				// If the packet was not from a local client, send
				// it directly to all local clients
				else {
					for (const Interface& interface : _local_client_interfaces) {
						TRACEF("Transport::inbound: Broadcasting packet on %s", interface.toString().c_str());
						transmit(const_cast<Interface&>(interface), packet.raw());
					}
				}
			}
		}

		////////////////////////////////
		// TRANSPORT HANDLING
		////////////////////////////////

		// General transport handling. Takes care of directing
		// packets according to transport tables and recording
		// entries in reverse and link tables.
		if (Reticulum::transport_enabled() || from_local_client || for_local_client || for_local_client_link) {
			TRACE("Transport::inbound: Performing general transport handling");

			// If there is no transport id, but the packet is
			// for a local client, we generate the transport
			// id (it was stripped on the previous hop, since
			// we "spoof" the hop count for clients behind a
			// shared instance, so they look directly reach-
			// able), and reinsert, so the normal transport
			// implementation can handle the packet.
			if (!packet.transport_id() && for_local_client) {
				TRACE("Transport::inbound: Regenerating transport id");
				packet.transport_id(_identity.hash());
			}

			// If this is a cache request, and we can fullfill
			// it, do so and stop processing. Otherwise resume
			// normal processing.
			if (packet.context() == Type::Packet::CACHE_REQUEST) {
				if (cache_request_packet(packet)) {
					TRACE("Transport::inbound: Cached packet");
					return;
				}
			}

			// If the packet is in transport, check whether we
			// are the designated next hop, and process it
			// accordingly if we are.
			if (packet.transport_id() && packet.packet_type() != Type::Packet::ANNOUNCE) {
				TRACE("Transport::inbound: Packet is in transport...");
				if (packet.transport_id() == _identity.hash()) {
					TRACE("Transport::inbound: We are designated next-hop");
					rdir_route_t fwd_route;
					Interface fwd_interface = {Type::NONE};
					if (peek_live_route(packet.destination_hash(), fwd_route, fwd_interface)) {
						TRACE("Transport::inbound: Found next-hop path to destination");
						Bytes next_hop(fwd_route.received_from, RDIR_DEST_LEN);
						uint8_t remaining_hops = fwd_route.hops;

						// CBA RESERVE
						//Bytes new_raw;
						Bytes new_raw(512);
						if (remaining_hops > 1) {
							// Just increase hop count and transmit
							//new_raw  = packet.raw[0:1]
							new_raw << packet.raw().left(1);
							//new_raw += struct.pack("!B", packet.hops)
							new_raw << packet.hops();
							//new_raw += next_hop
							new_raw << next_hop;
							//new_raw += packet.raw[(RNS.Identity.TRUNCATED_HASHLENGTH//8)+2:]
							new_raw << packet.raw().mid((Type::Identity::TRUNCATED_HASHLENGTH/8)+2);
						}
						else if (remaining_hops == 1) {
							// Strip transport headers and transmit
							//new_flags = (RNS.Packet.HEADER_1) << 6 | (Transport.BROADCAST) << 4 | (packet.flags & 0b00001111)
							uint8_t new_flags = (Type::Packet::HEADER_1) << 6 | (Type::Transport::BROADCAST) << 4 | (packet.flags() & 0b00001111);
							//new_raw = struct.pack("!B", new_flags)
							new_raw << new_flags;
							//new_raw += struct.pack("!B", packet.hops)
							new_raw << packet.hops();
							//new_raw += packet.raw[(RNS.Identity.TRUNCATED_HASHLENGTH//8)+2:]
							new_raw << packet.raw().mid((Type::Identity::TRUNCATED_HASHLENGTH/8)+2);
						}
						else if (remaining_hops == 0) {
							// Just increase hop count and transmit
							//new_raw  = packet.raw[0:1]
							new_raw << packet.raw().left(1);
							//new_raw += struct.pack("!B", packet.hops)
							new_raw << packet.hops();
							//new_raw += packet.raw[2:]
							new_raw << packet.raw().mid(2);
						}

						Interface outbound_interface = fwd_interface;

						if (packet.packet_type() == Type::Packet::LINKREQUEST) {
							TRACE("Transport::inbound: Packet is next-hop LINKREQUEST");
							double now = OS::time();
							double proof_timeout  = extra_link_proof_timeout(packet.receiving_interface());
							proof_timeout += now + Type::Link::ESTABLISHMENT_TIMEOUT_PER_HOP * std::max((uint8_t)1, remaining_hops);
							uint16_t path_mtu = Link::mtu_from_lr_packet(packet);
							Type::Link::link_mode mode = Link::mode_from_lr_packet(packet);
							uint16_t ph_mtu = 0;
							if (interface) {
								ph_mtu = interface.HW_MTU();
							}
							uint16_t nh_mtu = outbound_interface.HW_MTU();
							if (path_mtu != 0) {
								if (outbound_interface.HW_MTU() == 0) {
									DEBUG("No next-hop HW MTU, disabling link MTU upgrade");
									path_mtu = 0;
									new_raw  = new_raw.left(new_raw.size()-Type::Link::LINK_MTU_SIZE);
								}
								else if (outbound_interface.AUTOCONFIGURE_MTU() == 0 && outbound_interface.FIXED_MTU() == 0) {
									DEBUG("Outbound interface doesn't support MTU autoconfiguration, disabling link MTU upgrade");
									path_mtu = 0;
									new_raw  = new_raw.left(new_raw.size()-Type::Link::LINK_MTU_SIZE);
								}
								else {
									if (nh_mtu < path_mtu || (ph_mtu != 0 && ph_mtu < path_mtu)) {
										try {
											path_mtu = std::min(nh_mtu, (ph_mtu > 0) ? ph_mtu : nh_mtu);
											Bytes clamped_mtu = Link::signalling_bytes(path_mtu, mode);
											DEBUGF("Clamping link MTU to %u", path_mtu);
											new_raw  = new_raw.left(new_raw.size()-Type::Link::LINK_MTU_SIZE)+clamped_mtu;
										}
										catch (const std::exception& e) {
											WARNINGF("Dropping link request packet. The contained exception was: %s", e.what());
											return;
										}
									}
								}
							}
							LinkEntry link_entry(
								now,
								next_hop,
								outbound_interface,
								remaining_hops,
								packet.receiving_interface(),
								packet.hops(),
								packet.destination_hash(),
								false,
								proof_timeout
							);
							// CBA ACCUMULATES
							_link_table.insert({Link::link_id_from_lr_packet(packet), link_entry});
						}
						else {
							TRACE("Transport::inbound: Packet is next-hop other type");
							ReverseEntry reverse_entry(
								packet.receiving_interface(),
								outbound_interface,
								OS::time()
							);
							// CBA ACCUMULATES
							_reverse_table.insert({packet.getTruncatedHash(), reverse_entry});
						}
						TRACE("Transport::outbound: Sending packet to next hop...");
						transmit(outbound_interface, new_raw);
						/* Transiting for someone else still counts as use: it
						 * is what makes this record worth keeping. */
						rdirTouchUsed(packet.destination_hash().data(),
						              (uint32_t)OS::time() + path_ttl_for(fwd_interface, fwd_route.hops));
					}
					else {
						// TODO: There should probably be some kind of REJECT
						// mechanism here, to signal to the source that their
						// expected path failed.
						TRACEF("Got packet in transport, but no known path to final destination %s. Dropping packet.", packet.destination_hash().toHex().c_str());
					}
				}
				else {
					TRACE("Transport::inbound: We are not designated next-hop so not transporting");
				}
			}
			else {
				TRACE("Transport::inbound: Either packet is announce or packet has no next-hop (possibly for a local destination)");
			}

			// Link transport handling. Directs packets according
			// to entries in the link tables
			if (packet.packet_type() != Type::Packet::ANNOUNCE && packet.packet_type() != Type::Packet::LINKREQUEST && packet.context() != Type::Packet::LRPROOF) {
				TRACE("Transport::inbound: Checking if packet is meant for link transport...");
				auto link_iter = _link_table.find(packet.destination_hash());
				if (link_iter != _link_table.end()) {
					TRACE("Transport::inbound: Found link entry, handling link transport");
					LinkEntry& link_entry = (*link_iter).second;
					// If receiving and outbound interface is
					// the same for this link, direction doesn't
					// matter, and we simply send the packet on.
					Interface outbound_interface({Type::NONE});
					if (link_entry._outbound_interface == link_entry._receiving_interface) {
						// But check that taken hops matches one
						// of the expectede values.
						if (packet.hops() == link_entry._remaining_hops || packet.hops() == link_entry._hops) {
							TRACE("Transport::inbound: Link inbound/outbound interfaes are same, transporting on same interface");
							outbound_interface = link_entry._outbound_interface;
						}
					}
					else {
						// If interfaces differ, we transmit on
						// the opposite interface of what the
						// packet was received on.
						if (packet.receiving_interface() == link_entry._outbound_interface) {
							// Also check that expected hop count matches
							if (packet.hops() == link_entry._remaining_hops) {
								TRACE("Transport::inbound: Link transporting on inbound interface");
								outbound_interface = link_entry._receiving_interface;
							}
						}
						else if (packet.receiving_interface() == link_entry._receiving_interface) {
							// Also check that expected hop count matches
							if (packet.hops() == link_entry._hops) {
								TRACE("Transport::inbound: Link transporting on outbound interface");
								outbound_interface = link_entry._outbound_interface;
							}
						}
					}

					if (outbound_interface) {
						TRACE("Transport::inbound: Transmitting link transport packet");
						// CBA RESERVE
						//Bytes new_raw;
						Bytes new_raw(512);
						//new_raw = packet.raw[0:1]
						new_raw << packet.raw().left(1);
						//new_raw += struct.pack("!B", packet.hops)
						new_raw << packet.hops();
						//new_raw += packet.raw[2:]
						new_raw << packet.raw().mid(2);
						transmit(outbound_interface, new_raw);
						link_entry._timestamp = OS::time();
						// Deferred hashlist insertion for link transport packets
						_packet_hashlist.insert(packet.packet_hash());
					}
					else {
						//p pass
					}
				}
			}
		}

		////////////////////////////////
		// LOCAL HANDLING
		////////////////////////////////

		// Announce handling. Handles logic related to incoming
		// announces, queueing rebroadcasts of these, and removal
		// of queued announce rebroadcasts once handed to the next node.
		if (packet.packet_type() == Type::Packet::ANNOUNCE) {
			TRACE("Transport::inbound: Packet is ANNOUNCE");
			Bytes received_from;
			//p local_destination = next((d for d in Transport.destinations if d.hash == packet.destination_hash), None)
			auto iter = _destinations.find(packet.destination_hash());
			if (iter == _destinations.end() && Identity::validate_announce(packet)) {
				TRACE("Transport::inbound: Packet is announce for non-local destination, processing...");
				if (packet.transport_id()) {
					received_from = packet.transport_id();
					
					// Check if this is a next retransmission from
					// another node. If it is, we're removing the
					// announce in question from our pending table
					AnnounceRec* queued = Reticulum::transport_enabled()
						? announce_find(packet.destination_hash(), /*held=*/false) : nullptr;
					if (queued) {
						bool announce_erased = false;
						if ((packet.hops() - 1) == queued->hops) {
							DBGF_DEMOTE("Heard a local rebroadcast of announce for %s", packet.destination_hash().toHex().c_str());
							queued->local_rebroadcasts += 1;
							if (queued->local_rebroadcasts >= LOCAL_REBROADCASTS_MAX) {
								DBGF_DEMOTE("Max local rebroadcasts of announce for %s reached, dropping announce from our queue", packet.destination_hash().toHex().c_str());
								memset(queued, 0, sizeof(*queued));
								announce_erased = true;
							}
						}

						if (!announce_erased && (packet.hops() - 1) == (queued->hops + 1) && queued->retries > 0) {
							double now = OS::time();
							if (now < queued->timestamp) {
								DBGF_DEMOTE("Rebroadcasted announce for %s has been passed on to another node, no further tries needed", packet.destination_hash().toHex().c_str());
								memset(queued, 0, sizeof(*queued));
							}
						}
					}
				}
				else {
					received_from = packet.destination_hash();
				}

				/* The single test that used to gate the retransmission
				 * queue, the immediate rebroadcasts and the path-table insert
				 * splits in two. `fresh` is a forwarding input, computed over
				 * every announce we have ever validated — the guard pool —
				 * rather than over whatever we happened to retain. `retain` is
				 * a storage decision, taken per ingress interface plus
				 * whatever we have been asked to keep. */
				bool fresh  = false;
				bool retain = false;

				// First, check that the announce is not for a destination
				// local to this system, and that hops are less than the max
				// CBA TODO determine why packet destination hash is being searched in destinations again since we entered this logic becuase it did not exist above
				//if (not any(packet.destination_hash == d.hash for d in Transport.destinations) and packet.hops < Transport.PATHFINDER_M+1):
				auto iter = _destinations.find(packet.destination_hash());
				if (iter == _destinations.end() && packet.hops() < (PATHFINDER_M+1)) {
					uint64_t announce_emitted = Transport::announce_emitted(packet);

					//p random_blob = packet.data[RNS.Identity.KEYSIZE//8+RNS.Identity.NAME_HASH_LENGTH//8:RNS.Identity.KEYSIZE//8+RNS.Identity.NAME_HASH_LENGTH//8+10]
					Bytes random_blob = packet.data().mid(Type::Identity::KEYSIZE/8 + Type::Identity::NAME_HASH_LENGTH/8, Type::Identity::RANDOM_HASH_LENGTH/8);

					/* A relay answers an explicit path request from its own
					 * cached announce, so a requested PATH_RESPONSE always
					 * carries a random blob we have already heard. Treating it
					 * as a replay makes path discovery work exactly once and
					 * then go silent; upstream escapes via
					 * path_is_unresponsive, which this port lacks, so we key on
					 * the outstanding request instead. Scoped to paths no worse
					 * than what we hold — a looped longer copy arrives as a
					 * requested PATH_RESPONSE too, and must not displace a good
					 * direct one. */
					rdir_route_t known;
					bool have_known  = rdirPeekRoute(packet.destination_hash().data(), &known);
					bool have_record = rdirPeekEntry(packet.destination_hash().data(), nullptr);
					bool requested =
						packet.context() == Type::Packet::PATH_RESPONSE &&
						_path_requests.find(packet.destination_hash()) != _path_requests.end();
					bool bypass = requested && (!have_known || packet.hops() <= known.hops);

					fresh = random_blob.size() == Type::Identity::RANDOM_HASH_LENGTH/8 &&
					        rdirGuardFresh(packet.destination_hash().data(), random_blob.data(),
					                       (uint32_t)announce_emitted, bypass);

					/* A longer path never displaces a shorter one while the
					 * shorter one is still valid. Once it expires the freshest
					 * announce wins, whatever its hop count — that is how a
					 * destination that moved gets rediscovered. */
					bool route_better = !have_known || packet.hops() <= known.hops ||
					                    (known.expires != 0 && (uint32_t)OS::time() >= known.expires);

					/* `requested` is the "resolved on demand" arm, and it is what
					 * keeps a non-retaining interface usable at all: without it a
					 * node whose only link is a cheap one would discard the very
					 * path response it just asked for, and could never send. */
					/* Re-storing an announce we have already seen and already
					 * hold buys nothing and costs a record write — which on a
					 * mesh where several neighbours rebroadcast the same
					 * announce is most of the traffic. Store when the announce
					 * is new to us, or when we hold nothing for the
					 * destination (the record was evicted since). */
					/* The neighborhood arm: an announce ORIGINATED by the node
					 * at the other end of this link (ingress already
					 * incremented hops, so wire-hops 0 reads as 1 here) is
					 * kept even on an interface with no community — the direct
					 * peer's own destinations are the local neighborhood, and
					 * the mesh firehose is structurally >= 2 by now. The hops
					 * field is unsigned, so only the direct peer itself could
					 * lie its relays down to 0 — and that peer is the trust
					 * boundary already; the bounded directory arena caps what
					 * a hostile one could cost. */
					/* The community arm: an announce from within the ingress
					 * interface's community radius is this node's to keep —
					 * custody is what lets it answer path requests for the
					 * members. Beyond the radius (a leak from another gateway,
					 * the uplink's firehose) nothing is stored unrequested. */
					retain = route_better && (fresh || !have_record) &&
					         (requested ||
					          packet.hops() == 1 ||
					          (packet.receiving_interface() &&
					           packet.hops() <= packet.receiving_interface().community_radius()) ||
					          rdirHasClaim(packet.destination_hash().data()) ||
					          rdirInUse(packet.destination_hash().data()));

					if (fresh || retain) {
						double now = OS::time();

						bool rate_blocked = false;

// TODO
/*p
						if packet.context != RNS.Packet.PATH_RESPONSE and packet.receiving_interface.announce_rate_target != None:
							if not packet.destination_hash in Transport.announce_rate_table:
								rate_entry = { "last": now, "rate_violations": 0, "blocked_until": 0, "timestamps": [now]}
								Transport.announce_rate_table[packet.destination_hash] = rate_entry

							else:
								rate_entry = Transport.announce_rate_table[packet.destination_hash]
								rate_entry["timestamps"].append(now)

								while len(rate_entry["timestamps"]) > Transport.MAX_RATE_TIMESTAMPS:
									rate_entry["timestamps"].pop(0)

								current_rate = now - rate_entry["last"]

								if now > rate_entry["blocked_until"]:

									if current_rate < packet.receiving_interface.announce_rate_target:
										rate_entry["rate_violations"] += 1

									else:
										rate_entry["rate_violations"] = std::max(0, rate_entry["rate_violations"]-1)

									if rate_entry["rate_violations"] > packet.receiving_interface.announce_rate_grace:
										rate_target = packet.receiving_interface.announce_rate_target
										rate_penalty = packet.receiving_interface.announce_rate_penalty
										rate_entry["blocked_until"] = rate_entry["last"] + rate_target + rate_penalty
										rate_blocked = True
									else:
										rate_entry["last"] = now

								else:
									rate_blocked = True
*/

						uint8_t retries = 0;
						uint8_t announce_hops = packet.hops();
						/* Why this announce will or will not be re-broadcast,
						 * reported as a clause on the line below rather than
						 * as a line of its own. */
						const char* relay_note = "";
						bool block_rebroadcasts = false;
						Interface attached_interface = {Type::NONE};
						
						double retransmit_timeout = now + (Cryptography::random() * PATHFINDER_RW);

						/* Path lifetime, from the runtime-tunable TTLs. The
						 * blob ring that used to live beside it is now the
						 * guard pool, which every announce updates whether or
						 * not we retain anything else about the destination. */
						uint32_t path_ttl = path_ttl_for(packet.receiving_interface(), announce_hops);

						if (fresh && (Reticulum::transport_enabled() || Transport::from_local_client(packet)) && packet.context() != Type::Packet::PATH_RESPONSE) {
							// Insert announce into announce table for retransmission

							if (rate_blocked) {
								DBGF_DEMOTE("Blocking rebroadcast of announce from %s due to excessive announce rate", packet.destination_hash().toHex().c_str());
							}
							/* Nothing could carry a re-broadcast — don't take a
							 * table slot and PATHFINDER_R emission attempts to
							 * discover that once per announce. The decision is
							 * a clause on the announce's own line below, not a
							 * line of its own: one announce, one line. */
							else if (!announce_relay_possible(packet.destination_hash(),
							                                  packet.receiving_interface(),
							                                  announce_hops)) {
								relay_note = ", not relayed (no egress)";
							}
							else {
								if (Transport::from_local_client(packet)) {
									// If the announce is from a local client,
									// it is announced immediately, but only one time.
									retransmit_timeout = now;
									retries = PATHFINDER_R;
								}
								AnnounceRec* slot = announce_find(packet.destination_hash(), /*held=*/false);
								if (!slot) slot = announce_alloc();
								announce_store(slot, packet.destination_hash(), packet, now,
								               retransmit_timeout, retries, announce_hops,
								               block_rebroadcasts, attached_interface);
								cull_announce_table();
							}
						}
						// TODO: Check from_local_client once and store result
						else if (fresh && Transport::from_local_client(packet) && packet.context() == Type::Packet::PATH_RESPONSE) {
							// If this is a path response from a local client,
							// check if any external interfaces have pending
							// path requests.
							//p if packet.destination_hash in Transport.pending_local_path_requests:
							auto iter = _pending_local_path_requests.find(packet.destination_hash());
							if (iter != _pending_local_path_requests.end()) {
								//p desiring_interface = Transport.pending_local_path_requests.pop(packet.destination_hash)
								//const Interface& desiring_interface = (*iter).second;
								_pending_local_path_requests.erase(iter);
								retransmit_timeout = now;
								retries = PATHFINDER_R;

								AnnounceRec* slot = announce_find(packet.destination_hash(), /*held=*/false);
								if (!slot) slot = announce_alloc();
								announce_store(slot, packet.destination_hash(), packet, now,
								               retransmit_timeout, retries, announce_hops,
								               block_rebroadcasts, attached_interface);
								cull_announce_table();
							}
						}

						// If we have any local clients connected, we re-
						// transmit the announce to them immediately
						if (fresh && _local_client_interfaces.size() > 0) {
							Identity announce_identity(Identity::recall(packet.destination_hash()));
							//Destination announce_destination(announce_identity, Type::Destination::OUT, Type::Destination::SINGLE, "unknown", "unknown");
							//announce_destination.hash(packet.destination_hash());
							Destination announce_destination(announce_identity, Type::Destination::OUT, Type::Destination::SINGLE, packet.destination_hash());
							//announce_destination.hexhash(announce_destination.hash().toHex());
							Type::Packet::context_types announce_context = Type::Packet::CONTEXT_NONE;
							Bytes announce_data = packet.data();

							// TODO: Shouldn't the context be PATH_RESPONSE in the first case here?
							if (Transport::from_local_client(packet) && packet.context() == Type::Packet::PATH_RESPONSE) {
								for (const Interface& local_interface : _local_client_interfaces) {
									if (packet.receiving_interface() != local_interface) {
										Packet new_announce(
											announce_destination,
											local_interface,
											announce_data,
											Type::Packet::ANNOUNCE,
											announce_context,
											Type::Transport::TRANSPORT,
											Type::Packet::HEADER_2,
											_identity.hash(),
											true,
											packet.context_flag()
										);

										new_announce.hops(packet.hops());
										new_announce.send();
									}
								}
							}
							else {
								for (const Interface& local_interface : _local_client_interfaces) {
									if (packet.receiving_interface() != local_interface) {
										Packet new_announce(
											announce_destination,
											local_interface,
											announce_data,
											Type::Packet::ANNOUNCE,
											announce_context,
											Type::Transport::TRANSPORT,
											Type::Packet::HEADER_2,
											_identity.hash(),
											true,
											packet.context_flag()
										);

										new_announce.hops(packet.hops());
										new_announce.send();
									}
								}
							}
						}

						// If we have any waiting discovery path requests
						// for this destination, we retransmit to that
						// interface immediately
						auto iter = _discovery_path_requests.find(packet.destination_hash());
						if (fresh && iter != _discovery_path_requests.end()) {
							PathRequestEntry& pr_entry = (*iter).second;
							attached_interface = pr_entry._requesting_interface;

							DBGF_DEMOTE("Got matching announce, answering waiting discovery path request for %s on %s", packet.destination_hash().toHex().c_str(), attached_interface.toString().c_str());
							Identity announce_identity(Identity::recall(packet.destination_hash()));
							//Destination announce_destination(announce_identity, Type::Destination::OUT, Type::Destination::SINGLE, "unknown", "unknown");
							//announce_destination.hash(packet.destination_hash());
							Destination announce_destination(announce_identity, Type::Destination::OUT, Type::Destination::SINGLE, packet.destination_hash());
							//announce_destination.hexhash(announce_destination.hash().toHex());
							Bytes announce_data = packet.data();

							Packet new_announce(
								announce_destination,
								attached_interface,
								announce_data,
								Type::Packet::ANNOUNCE,
								Type::Packet::PATH_RESPONSE,
								Type::Transport::TRANSPORT,
								Type::Packet::HEADER_2,
								_identity.hash(),
								true,
								packet.context_flag()
							);

							new_announce.hops(packet.hops());
							new_announce.send();
						}

						/* Storage decision. The guard pool already recorded
						 * that we saw this announce; what lands here is the
						 * directory record — identity, name, routing — and,
						 * when it fits a blob slot, the raw signed announce we
						 * would need to answer a path request for this
						 * destination. Nothing is retained per-consumer: one
						 * record serves everyone. */
						if (retain) {
							TRACEF("Adding destination %s to directory", packet.destination_hash().toHex().c_str());
							const Bytes& adata = packet.data();
							/* Truncated to the record's 16-byte field; resolved back
							 * with find_interface_from_hash_prefix(). */
							Bytes iface_hash;
							if (packet.receiving_interface()) iface_hash = packet.receiving_interface().get_hash();

							rdir_announce_t ann = {};
							if (adata.size() >= (size_t)(Type::Identity::KEYSIZE/8 + Type::Identity::NAME_HASH_LENGTH/8)) {
								ann.pubkey    = adata.data();
								ann.name_hash = adata.data() + Type::Identity::KEYSIZE/8;
							}
							ann.received_from = received_from.size() == RDIR_DEST_LEN ? received_from.data() : nullptr;
							ann.iface_hash    = iface_hash.size()    >= RDIR_DEST_LEN ? iface_hash.data()    : nullptr;
							ann.raw           = packet.raw().data();
							ann.raw_len       = (uint16_t)packet.raw().size();
							ann.hops          = announce_hops;
							/* A community member: we answer path requests for
							 * it, so it must outrank the churn of everything
							 * we merely overhear. */
							bool in_community = packet.receiving_interface() &&
							                    announce_hops <= packet.receiving_interface().community_radius();
							ann.edge          = in_community;
							ann.answer_for    = in_community;
							ann.timestamp     = (uint32_t)now;
							ann.expires       = (uint32_t)now + path_ttl;

							rdirIngest(packet.destination_hash().data(), &ann, RDIR_LAYER_DIR_BLOB);
							++_destinations_added;
							cull_path_table();
						}

						DBGF_DEMOTE("Destination %s is now %d hops away via %s on %s%s", packet.destination_hash().toHex().c_str(), announce_hops, received_from.toHex().c_str(), packet.receiving_interface().toString().c_str(), relay_note);
						//TRACEF("Transport::inbound: Destination %s has data: %s", packet.destination_hash().toHex().c_str(), packet.data().toHex().c_str());
						//TRACEF("Transport::inbound: Destination %s has text: %s", packet.destination_hash().toHex().c_str(), packet.data().toString().c_str());

// TODO
/*
						// If the receiving interface is a tunnel, we add the
						// announce to the tunnels table
						if (packet.receiving_interface().tunnel_id()) {
							tunnel_entry = Transport.tunnels[packet.receiving_interface.tunnel_id];
							paths = tunnel_entry[2];
							paths[packet.destination_hash] = destination_table_entry;
							expires = OS::time() + Transport::DESTINATION_TIMEOUT;
							tunnel_entry[3] = expires;
							DBGF_DEMOTE("Path to %s associated with tunnel %s", packet.destination_hash().toHex().c_str(), packet.receiving_interface().tunnel_id().toHex().c_str());
						}
*/

						// Call externally registered callbacks from apps
						// wanting to know when an announce arrives
						if (fresh && packet.context() != Type::Packet::PATH_RESPONSE) {
							TRACE("Transport::inbound: Not path response, sending to announce handler...");
							/* Everything a handler needs is in the announce we are
							 * holding: recalling it back out of a store would
							 * depend on having retained it, and would hash the
							 * destination once per subscriber per announce —
							 * which is what stalled the browser transport during
							 * announce bursts. */
							const Bytes& announce_data = packet.data();
							const size_t announce_prefix = Type::Identity::KEYSIZE/8 +
							                               Type::Identity::NAME_HASH_LENGTH/8 +
							                               Type::Identity::RANDOM_HASH_LENGTH/8 +
							                               Type::Identity::SIGLENGTH/8;
							Identity announce_identity(false);
							Bytes announce_name_hash;
							Bytes announce_app_data;
							if (announce_data.size() >= announce_prefix) {
								announce_identity.load_public_key(announce_data.left(Type::Identity::KEYSIZE/8));
								announce_name_hash = announce_data.mid(Type::Identity::KEYSIZE/8, Type::Identity::NAME_HASH_LENGTH/8);
								if (announce_data.size() > announce_prefix)
									announce_app_data = announce_data.mid(announce_prefix);
							}
							for (auto& handler : _announce_handlers) {
								TRACE("Transport::inbound: Checking filter of announce handler...");
								try {
									// Check that the announced destination matches
									// the handlers aspect filter. validate_announce
									// has already proven dest_hash ==
									// full_hash(carried_name_hash ‖ identity)[:16],
									// so matching the carried name hash against the
									// precompiled filter is exactly equivalent to
									// recomputing the destination hash — at the cost
									// of a ten-byte comparison.
									bool execute_callback =
										handler->aspect_filter().empty() ||
										handler->name_hash_filter() == announce_name_hash;
									if (execute_callback) {
										handler->received_announce(
											packet.destination_hash(),
											announce_identity,
											announce_app_data,
											announce_name_hash,
											packet.hops()
										);
									}
								}
								catch (const std::exception& e) {
									ERROR("Error while processing external announce callback.");
									ERRORF("The contained exception was: %s", e.what());
								}
							}
						}
					}
				}
				else {
					TRACE("Transport::inbound: Packet is announce for local destination, not processing");
				}
			}
			else {
				TRACE("Transport::inbound: Packet is announce for local destination, not processing");
			}
		}

		// Handling for link requests to local destinations
		else if (packet.packet_type() == Type::Packet::LINKREQUEST) {
			TRACE("Transport::inbound: Packet is LINKREQUEST");
			if (!packet.transport_id() || packet.transport_id() == _identity.hash()) {
				TRACE("Transport::inbound: Checking if LINKREQUEST is for local destination");
				auto iter = _destinations.find(packet.destination_hash());
				if (iter != _destinations.end()) {
					auto& destination = (*iter).second;
					if (destination.type() == packet.destination_type()) {
						TRACE("Transport::inbound: Found local destination for LINKREQUEST");
						packet.destination(destination);
						// CBA iterator over std::set is always const so need to make temporarily mutable
						//destination.receive(packet);
						destination.receive(packet);
					}
				}
			}
		}
		
		// Handling for data packets to local destinations
		else if (packet.packet_type() == Type::Packet::DATA) {
			TRACE("Transport::inbound: Packet is DATA");
			if (packet.destination_type() == Type::Destination::LINK) {
				// Data is destined for a link
				TRACE("Transport::inbound: Packet is DATA for a LINK");
				std::set<Link> active_links(_active_links);
				for (auto& link : active_links) {
					if (link.link_id() == packet.destination_hash()) {
						TRACE("Transport::inbound: Packet is DATA for an active LINK");
						packet.link(link);
						const_cast<Link&>(link).receive(packet);
					}
				}
			}
			else {
				// Data is basic (not destined for a link)
				auto iter = _destinations.find(packet.destination_hash());
				if (iter == _destinations.end()) {
					/* Spangap diagnostic: log every DATA packet that reaches
					 * us but doesn't match a registered local destination.
					 * Transit traffic that we'd forward has already been
					 * handled by the transport block above and would not
					 * fall through here unless we were not the designated
					 * next-hop. Useful for diagnosing "echo never replies"
					 * by distinguishing "packet never arrived" from "packet
					 * arrived for a hash we don't own". */
					INFOF("DATA arrived for dest %s on %s (hops=%u, %zuB) — no local destination",
					      packet.destination_hash().toHex().c_str(),
					      packet.receiving_interface() ? packet.receiving_interface().toString().c_str() : "<none>",
				      packet.hops(), packet.data().size());
				}
				if (iter != _destinations.end()) {
					/* Spangap: INFOF for app destinations (LXMF, our-dest,
					 * etc.) — this is the "a DATA packet for us arrived"
					 * signal. For mR's own control destinations (path.request,
					 * tunnel.synthesize) the hit fires on every incoming
					 * path request and is just path-request scaffolding,
					 * so route it through DBGF_DEMOTE. */
					if (_control_hashes.find(packet.destination_hash()) != _control_hashes.end()) {
						TRACEF("Packet destination %s found, destination is local (control)", packet.destination_hash().toHex().c_str());
					} else {
						INFOF("Packet destination %s found, destination is local", packet.destination_hash().toHex().c_str());
					}
					auto& destination = (*iter).second;
					if (destination.type() != packet.destination_type()) {
						INFOF("DATA for dest %s: type mismatch (got=%d want=%d)",
						      packet.destination_hash().toHex().c_str(),
						      (int)packet.destination_type(), (int)destination.type());
					}
					if (destination.type() == packet.destination_type()) {
						TRACEF("Transport::inbound: Packet destination type %d matched, processing", packet.destination_type());
						packet.destination(destination);
						destination.receive(packet);

						if (destination.proof_strategy() == Type::Destination::PROVE_ALL) {
							packet.prove();
						}
						else if (destination.proof_strategy() == Type::Destination::PROVE_APP) {
							if (destination.callbacks()._proof_requested) {
								try {
									if (destination.callbacks()._proof_requested(packet)) {
										packet.prove();
									}
								}
								catch (const std::exception& e) {
									ERRORF("Error while executing proof request callback. The contained exception was: %s", e.what());
								}
							}
						}
					}
					else {
						DEBUGF("Transport::inbound: Packet destination type %d mismatch, ignoring", packet.destination_type());
					}
				}
				else {
					DEBUGF("Transport::inbound: Local destination %s not found, not handling packet locally", packet.destination_hash().toHex().c_str());
				}
			}
		}

		// Handling for proofs and link-request proofs
		else if (packet.packet_type() == Type::Packet::PROOF) {
			TRACE("Transport::inbound: Packet is PROOF");
			if (packet.context() == Type::Packet::LRPROOF) {
				TRACE("Transport::inbound: Packet is LINK PROOF");
				// This is a link request proof, check if it
				// needs to be transported
				if ((Reticulum::transport_enabled() || for_local_client_link || from_local_client) && _link_table.find(packet.destination_hash()) != _link_table.end()) {
					TRACE("Handling link request proof...");
					LinkEntry& link_entry = (*_link_table.find(packet.destination_hash())).second;
					if (packet.receiving_interface() == link_entry._outbound_interface) {
						try {
							if (packet.data().size() == (Type::Identity::SIGLENGTH/8 + Type::Link::ECPUBSIZE/2) || packet.data().size() == (Type::Identity::SIGLENGTH/8 + Type::Link::ECPUBSIZE/2 + Type::Link::LINK_MTU_SIZE)) {
								Bytes signalling_bytes;
								if (packet.data().size() == (Type::Identity::SIGLENGTH/8 + Type::Link::ECPUBSIZE/2 + Type::Link::LINK_MTU_SIZE)) {
									signalling_bytes = Link::signalling_bytes(Link::mtu_from_lp_packet(packet), Link::mode_from_lp_packet(packet));
								}
								Bytes peer_pub_bytes = packet.data().mid(Type::Identity::SIGLENGTH/8, Type::Link::ECPUBSIZE/2);
								/* recall() answers "not known" with an unset identity,
								 * and both get_public_key() and validate() assert on
								 * one of those. The hash comes off the air, so a
								 * proof naming a destination this node has never
								 * recalled would abort it. An unprovable proof is a
								 * dropped proof — the else below already says so. */
								Identity peer_identity = Identity::recall(link_entry._destination_hash);
								Bytes peer_sig_pub_bytes = peer_identity
									? peer_identity.get_public_key().mid(Type::Link::ECPUBSIZE/2, Type::Link::ECPUBSIZE/2)
									: Bytes();

								Bytes signed_data = packet.destination_hash() + peer_pub_bytes + peer_sig_pub_bytes + signalling_bytes;
								Bytes signature = packet.data().left(Type::Identity::SIGLENGTH/8);

								if (peer_identity && peer_identity.validate(signature, signed_data)) {
									TRACEF("Link request proof validated for transport via %s", link_entry._receiving_interface.toString().c_str());
									//p new_raw = packet.raw[0:1]
									// CBA RESERVE
									//Bytes new_raw = packet.raw().left(1);
									Bytes new_raw(512);
									new_raw << packet.raw().left(1);
									//p new_raw += struct.pack("!B", packet.hops)
									new_raw << packet.hops();
									//p new_raw += packet.raw[2:]
									new_raw << packet.raw().mid(2);
									link_entry._validated = true;
									transmit(link_entry._receiving_interface, new_raw);
								}
								else {
									DEBUGF("Invalid link request proof in transport for link %s, dropping proof.", packet.destination_hash().toHex().c_str());
								}
							}
						}
						catch (const std::exception& e) {
							ERRORF("Error while transporting link request proof. The contained exception was: %s", e.what());
						}
					}
					else {
						DEBUG("Link request proof received on wrong interface, not transporting it.");
					}
				}
				else {
					// Check if we can deliver it to a local
					// pending link
					TRACEF("Handling proof for link request %s", packet.destination_hash().toHex().c_str());
					// CBA Must make a copy of _pending_links before traversing since it gets modified
					//for (auto link : _pending_links) {
					std::set<Link> pending_links(_pending_links);
					for (auto& link : pending_links) {
						TRACEF("Checking for link request handling by pending link %s", link.link_id().toHex().c_str());
						if (link.link_id() == packet.destination_hash()) {
							TRACE("Requesting pending link to validate proof");
							const_cast<Link&>(link).validate_proof(packet);
						}
					}
				}
			}
			else if (packet.context() == Type::Packet::RESOURCE_PRF) {
				TRACE("Transport::inbound: Packet is RESOURCE PROOF");
				std::set<Link> active_links(_active_links);
				for (auto& link : active_links) {
					if (link.link_id() == packet.destination_hash()) {
						const_cast<Link&>(link).receive(packet);
					}
				}
			}
			else {
				TRACE("Transport::inbound: Packet is regular PROOF");
				if (packet.destination_type() == Type::Destination::LINK) {
					std::set<Link> active_links(_active_links);
					for (auto& link : active_links) {
						if (link.link_id() == packet.destination_hash()) {
							packet.link(link);
						}
					}
				}

				Bytes proof_hash;
				// EXPL_LENGTH (+5 for a reticulous rx-report trailer) is an
				// explicit proof; the hash is its first HASHLENGTH bytes.
				if (packet.data().size() == Type::PacketReceipt::EXPL_LENGTH ||
				    packet.data().size() == Type::PacketReceipt::EXPL_LENGTH + 5) {
					proof_hash = packet.data().left(Type::Identity::HASHLENGTH/8);
				}

				// Check if this proof needs to be transported
				if ((Reticulum::transport_enabled() || from_local_client || proof_for_local_client) && _reverse_table.find(packet.destination_hash()) != _reverse_table.end()) {
					ReverseEntry reverse_entry = (*_reverse_table.find(packet.destination_hash())).second;
					if (packet.receiving_interface() == reverse_entry._outbound_interface) {
						TRACEF("Proof received on correct interface, transporting it via %s", reverse_entry._receiving_interface.toString().c_str());
						//p new_raw = packet.raw[0:1]
						// CBA RESERVE
						//Bytes new_raw = packet.raw().left(1);
						Bytes new_raw(512);
						new_raw << packet.raw().left(1);
						//p new_raw += struct.pack("!B", packet.hops)
						new_raw << packet.hops();
						//p new_raw += packet.raw[2:]
						new_raw << packet.raw().mid(2);
						transmit(reverse_entry._receiving_interface, new_raw);
					}
					else {
						DEBUG("Proof received on wrong interface, not transporting it.");
					}
				}
				else {
					TRACE("Proof is not candidate for transporting");
				}

				std::list<PacketReceipt> cull_receipts;
				for (auto& receipt : _receipts) {
					bool receipt_validated = false;
					if (proof_hash) {
						// Only test validation if hash matches
						if (receipt.hash() == proof_hash) {
							receipt_validated = receipt.validate_proof_packet(packet);
						}
					}
					else {
						// TODO: This looks like it should actually
						// be rewritten when implicit proofs are added.

						// In case of an implicit proof, we have
						// to check every single outstanding receipt
						receipt_validated = receipt.validate_proof_packet(packet);
					}

					// CBA TODO requires modifying of collection while iterating which is forbidden
					if (receipt_validated) {
						//p if receipt in Transport.receipts:
						//p 	Transport.receipts.remove(receipt)
						cull_receipts.push_back(receipt);
					}
				}
				// CBA since modifying of collection while iterating is forbidden
				for (auto& receipt : cull_receipts) {
					_receipts.remove(receipt);
				}

				// A proof nobody was waiting for. Ordinary on a shared medium
				// (every neighbour's proofs land here too), but it is also what
				// a proof arriving past its receipt's timeout looks like — the
				// receipt is culled by then, so the send reports PROOF_TIMEOUT
				// with the proof sitting plainly in the rx log.
				if (cull_receipts.empty()) {
					DEBUGF("Proof for %s matched none of %u outstanding receipt(s)",
						packet.destination_hash().toHex().c_str(),
						(unsigned)_receipts.size());
				}
			}
		}
	}

	/* _jobs_locked = false handled by JobsLockGuard dtor at scope exit. */
}

/*static*/ void Transport::synthesize_tunnel(const Interface& interface) {
// TODO
/*p
	Bytes interface_hash = interface.get_hash();
	Bytes public_key     = _identity.get_public_key();
	Bytes random_hash    = Identity::get_random_hash();
	
	tunnel_id_data = public_key+interface_hash
	tunnel_id      = RNS.Identity.full_hash(tunnel_id_data)

	signed_data    = tunnel_id_data+random_hash
	signature      = Transport.identity.sign(signed_data)
	
	data           = signed_data+signature

	tnl_snth_dst   = RNS.Destination(None, RNS.Destination.OUT, RNS.Destination.PLAIN, Transport.APP_NAME, "tunnel", "synthesize")

	packet = RNS.Packet(tnl_snth_dst, data, packet_type = RNS.Packet.DATA, transport_type = RNS.Transport.BROADCAST, header_type = RNS.Packet.HEADER_1, attached_interface = interface)
	packet.send()

	interface.wants_tunnel = False
*/
}

/*static*/ void Transport::tunnel_synthesize_handler(const Bytes& data, const Packet& packet) {
// TODO
/*p
	try:
		expected_length = RNS.Identity.KEYSIZE//8+RNS.Identity.HASHLENGTH//8+RNS.Reticulum.TRUNCATED_HASHLENGTH//8+RNS.Identity.SIGLENGTH//8
		if len(data) == expected_length:
			public_key     = data[:RNS.Identity.KEYSIZE//8]
			interface_hash = data[RNS.Identity.KEYSIZE//8:RNS.Identity.KEYSIZE//8+RNS.Identity.HASHLENGTH//8]
			tunnel_id_data = public_key+interface_hash
			tunnel_id      = RNS.Identity.full_hash(tunnel_id_data)
			random_hash    = data[RNS.Identity.KEYSIZE//8+RNS.Identity.HASHLENGTH//8:RNS.Identity.KEYSIZE//8+RNS.Identity.HASHLENGTH//8+RNS.Reticulum.TRUNCATED_HASHLENGTH//8]
			
			signature      = data[RNS.Identity.KEYSIZE//8+RNS.Identity.HASHLENGTH//8+RNS.Reticulum.TRUNCATED_HASHLENGTH//8:expected_length]
			signed_data    = tunnel_id_data+random_hash

			remote_transport_identity = RNS.Identity(create_keys=False)
			remote_transport_identity.load_public_key(public_key)

			if remote_transport_identity.validate(signature, signed_data):
				Transport.handle_tunnel(tunnel_id, packet.receiving_interface)

	except Exception as e:
		RNS.log("An error occurred while validating tunnel establishment packet.", RNS.LOG_DEBUG)
		RNS.log("The contained exception was: "+str(e), RNS.LOG_DEBUG)
*/
}

/*static*/ void Transport::handle_tunnel(const Bytes& tunnel_id, const Interface& interface) {
// TODO
/*p
	expires = time.time() + Transport.DESTINATION_TIMEOUT
	if not tunnel_id in Transport.tunnels:
		RNS.log("Tunnel endpoint "+RNS.prettyhexrep(tunnel_id)+" established.", RNS.LOG_DEBUG)
		paths = {}
		tunnel_entry = [tunnel_id, interface, paths, expires]
		interface.tunnel_id = tunnel_id
		Transport.tunnels[tunnel_id] = tunnel_entry
	else:
		RNS.log("Tunnel endpoint "+RNS.prettyhexrep(tunnel_id)+" reappeared. Restoring paths...", RNS.LOG_DEBUG)
		tunnel_entry = Transport.tunnels[tunnel_id]
		tunnel_entry[1] = interface
		tunnel_entry[3] = expires
		interface.tunnel_id = tunnel_id
		paths = tunnel_entry[2]

		deprecated_paths = []
		for destination_hash, path_entry in paths.items():
			received_from = path_entry[1]
			announce_hops = path_entry[2]
			expires = path_entry[3]
			random_blobs = path_entry[4]
			receiving_interface = interface
			packet = path_entry[6]
			new_entry = [time.time(), received_from, announce_hops, expires, random_blobs, receiving_interface, packet]

			should_add = False
			if destination_hash in Transport.destination_table:
				old_entry = Transport.destination_table[destination_hash]
				old_hops = old_entry[2]
				old_expires = old_entry[3]
				if announce_hops <= old_hops or time.time() > old_expires:
					should_add = True
				else:
					RNS.log("Did not restore path to "+RNS.prettyhexrep(packet.destination_hash)+" because a newer path with fewer hops exist", RNS.LOG_DEBUG)
			else:
				if time.time() < expires:
					should_add = True
				else:
					RNS.log("Did not restore path to "+RNS.prettyhexrep(packet.destination_hash)+" because it has expired", RNS.LOG_DEBUG)

			if should_add:
				Transport.destination_table[destination_hash] = new_entry
				RNS.log("Restored path to "+RNS.prettyhexrep(packet.destination_hash)+" is now "+str(announce_hops)+" hops away via "+RNS.prettyhexrep(received_from)+" on "+str(receiving_interface), RNS.LOG_DEBUG)
			else:
				deprecated_paths.append(destination_hash)

		for deprecated_path in deprecated_paths:
			RNS.log("Removing path to "+RNS.prettyhexrep(deprecated_path)+" from tunnel "+RNS.prettyhexrep(tunnel_id), RNS.LOG_DEBUG)
			paths.pop(deprecated_path)
*/
}

/*static*/ void Transport::register_interface(Interface& interface) {
	TRACEF("Transport: Registering interface %s %s", interface.get_hash().toHex().c_str(), interface.toString().c_str());
	_interfaces.insert({interface.get_hash(), interface});
	// CBA TODO set or add transport as listener on interface to receive incoming packets?
}

/*static*/ void Transport::deregister_interface(const Interface& interface) {
	TRACEF("Transport: Deregistering interface %s", interface.toString().c_str());
	auto iter = _interfaces.find(interface.get_hash());
	if (iter != _interfaces.end()) {
		TRACEF("Transport::deregister_interface: Found and removing interface %s", (*iter).second.toString().c_str());
		_interfaces.erase(iter);
	}
}

/*static*/ void Transport::register_destination(Destination& destination) {
	//TRACE("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
	TRACEF("Transport: Registering destination %s", destination.toString().c_str());
	destination.mtu(Type::Reticulum::MTU);
	if (destination.direction() == Type::Destination::IN) {
		auto iter = _destinations.find(destination.hash());
		if (iter != _destinations.end()) {
			//p raise KeyError("Attempt to register an already registered destination.")
			throw std::runtime_error("Attempt to register an already registered destination.");
		}

		// CBA ACCUMULATES
		_destinations.insert({destination.hash(), destination});

		if (_owner && _owner.is_connected_to_shared_instance()) {
			if (destination.type() == Type::Destination::SINGLE) {
				TRACEF("Transport:register_destination: Announcing destination %s", destination.toString().c_str());
				destination.announce({}, true);
			}
		}
	}
	else {
		TRACEF("Transport:register_destination: Skipping registration (not direction IN) of destination %s", destination.toString().c_str());
	}

/*
	for (auto& [hash, destination] : _destinations) {
		TRACEF("Transport::register_destination: Listed destination %s", destination.toString().c_str());
	}
*/
	//TRACE("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
}

/*static*/ void Transport::deregister_destination(const Destination& destination) {
	TRACEF("Transport: Deregistering destination %s", destination.toString().c_str());
	auto iter = _destinations.find(destination.hash());
	if (iter != _destinations.end()) {
		TRACEF("Transport::deregister_destination: Found and removing destination %s", (*iter).second.toString().c_str());
		_destinations.erase(iter);
	}
}

/*static*/ void Transport::register_link(Link& link) {
	TRACEF("Transport: Registering link %s", link.toString().c_str());
	if (link.initiator()) {
		// CBA ACCUMULATES
		_pending_links.insert(link);
	}
	else {
		// CBA ACCUMULATES
		_active_links.insert(link);
	}
}

/*static*/ void Transport::activate_link(Link& link) {
	TRACEF("Transport: Activating link %s", link.toString().c_str());
	if (_pending_links.find(link) != _pending_links.end()) {
		if (link.status() != Type::Link::ACTIVE) {
			throw std::runtime_error("Invalid link state for link activation: " + std::to_string(link.status()));
		}
		_pending_links.erase(link);
		// CBA ACCUMULATES
		_active_links.insert(link);
		link.status(Type::Link::ACTIVE);
	}
	else {
		ERROR("Attempted to activate a link that was not in the pending table");
	}
}

/*
Registers an announce handler.

:param handler: Must be an object with an *aspect_filter* attribute and a *received_announce(destination_hash, announced_identity, app_data)* callable. See the :ref:`Announce Example<example-announce>` for more info.
*/
/*static*/ void Transport::register_announce_handler(HAnnounceHandler handler) {
	TRACEF("Transport: Registering announce handler %s", handler->aspect_filter().c_str());
	_announce_handlers.insert(handler);
}

/*
Deregisters an announce handler.

:param handler: The announce handler to be deregistered.
*/
/*static*/ void Transport::deregister_announce_handler(HAnnounceHandler handler) {
	TRACEF("Transport: Deregistering announce handler %s", handler->aspect_filter().c_str());
	if (_announce_handlers.find(handler) != _announce_handlers.end()) {
		TRACEF("Transport::deregister_announce_handler: Found and removing handler%s", handler->aspect_filter().c_str());
		_announce_handlers.erase(handler);
	}
}

/*static*/ bool Transport::is_interface_from_hash(const Bytes& interface_hash) {
	auto iter = _interfaces.find(interface_hash);
	if (iter != _interfaces.end()) {
		return true;
	}

	return false;
}

/*static*/ Interface Transport::find_interface_from_hash(const Bytes& interface_hash) {
	auto iter = _interfaces.find(interface_hash);
	if (iter != _interfaces.end()) {
		//TRACEF("Transport::find_interface_from_hash: Found interface %s", (*iter).second.toString().c_str());
		return (*iter).second;
	}

	return {Type::NONE};
}

/*static*/ Interface Transport::find_interface_from_hash_prefix(const uint8_t prefix[RDIR_DEST_LEN]) {
	for (auto& [hash, interface] : _interfaces) {
		if (hash.size() >= RDIR_DEST_LEN && memcmp(hash.data(), prefix, RDIR_DEST_LEN) == 0) {
			return interface;
		}
	}
	return {Type::NONE};
}

/*static*/ bool Transport::should_cache_packet(const Packet& packet) {
	// TODO: Rework the caching system. It's currently
	// not very useful to even cache Resource proofs,
	// disabling it for now, until redesigned.
	// if packet.context == RNS.Packet.RESOURCE_PRF:
	//     return True

	return false;
}

// When caching packets to storage, they are written
// exactly as they arrived over their interface. This
// means that they have not had their hop count
// increased yet! Take note of this when reading from
// the packet cache.
/*static*/ bool Transport::cache_packet(const Packet& packet, bool force_cache /*= false*/) {
	//TRACEF("Checking to see if packet %s should be cached", packet.get_hash().toHex().c_str());
#if defined(RNS_USE_FS) && defined(RNS_PERSIST_PATHS)
	if (should_cache_packet(packet) || force_cache) {
		TRACEF("Saving packet %s to storage", packet.get_hash().toHex().c_str());
		try {
			char packet_cache_path[Type::Reticulum::FILEPATH_MAXSIZE];
			snprintf(packet_cache_path, Type::Reticulum::FILEPATH_MAXSIZE, "%s/%s", Reticulum::_cachepath, packet.get_hash().toHex().c_str());
			return (Persistence::serialize(packet, packet_cache_path) > 0);
		}
		catch (const std::exception& e) {
			ERRORF("Error writing packet to cache. The contained exception was: %s", e.what());
		}
	}
#endif
	return false;
}

/*static*/ bool Transport::is_cached_packet(const Bytes& packet_hash) {
#if defined(RNS_USE_FS) && defined(RNS_PERSIST_PATHS)
	try {
		char packet_cache_path[Type::Reticulum::FILEPATH_MAXSIZE];
		snprintf(packet_cache_path, Type::Reticulum::FILEPATH_MAXSIZE, "%s/%s", Reticulum::_cachepath, packet_hash.toHex().c_str());
		return OS::file_exists(packet_cache_path);
	}
	catch (const std::exception& e) {
		ERRORF("Exception occurred while getting cached packet: %s", e.what());
	}
#endif
	return false;
}

/*static*/ Packet Transport::get_cached_packet(const Bytes& packet_hash) {
	TRACEF("Loading packet %s from cache storage", packet_hash.toHex().c_str());
#if defined(RNS_USE_FS) && defined(RNS_PERSIST_PATHS)
	try {
		char packet_cache_path[Type::Reticulum::FILEPATH_MAXSIZE];
		snprintf(packet_cache_path, Type::Reticulum::FILEPATH_MAXSIZE, "%s/%s", Reticulum::_cachepath, packet_hash.toHex().c_str());
		Packet packet({Type::NONE});
		if (Persistence::deserialize(packet, packet_cache_path) > 0) {
			packet.update_hash();
		}
		return packet;
	}
	catch (const std::exception& e) {
		ERRORF("Exception occurred while getting cached packet: %s", e.what());
	}
#endif
	return {Type::NONE};
}

/*static*/ bool Transport::clear_cached_packet(const Bytes& packet_hash) {
	TRACEF("Clearing packet %s from cache storage", packet_hash.toHex().c_str());
#if defined(RNS_USE_FS) && defined(RNS_PERSIST_PATHS)
	try {
		char packet_cache_path[Type::Reticulum::FILEPATH_MAXSIZE];
		snprintf(packet_cache_path, Type::Reticulum::FILEPATH_MAXSIZE, "%s/%s", Reticulum::_cachepath, packet_hash.toHex().c_str());
		double start_time = OS::time();
		bool success = RNS::Utilities::OS::remove_file(packet_cache_path);
		double diff_time = OS::time() - start_time;
		if (diff_time < 1.0) {
			DEBUGF("Remove cached packet in %d ms", (int)(diff_time*1000));
		}
		else {
			DEBUGF("Remove cached packet in %f s", diff_time);
		}
	}
	catch (const std::exception& e) {
		ERROR("Exception occurred while clearing cached packet.");
		ERRORF("The contained exception was: %s", e.what());
	}
#endif
	return false;
}

/*static*/ bool Transport::cache_request_packet(const Packet& packet) {
	if (packet.data().size() == Type::Identity::HASHLENGTH/8) {
		const Packet& cached_packet = get_cached_packet(packet.data());

		if (cached_packet) {
			// If the packet was retrieved from the local
			// cache, replay it to the Transport instance,
			// so that it can be directed towards it original
			// destination.
			inbound(cached_packet.raw(), cached_packet.receiving_interface());
			return true;
		}
		else {
			return false;
		}
	}
	else {
		return false;
	}
}

/*static*/ void Transport::cache_request(const Bytes& packet_hash, const Destination& destination) {
	const Packet& cached_packet = get_cached_packet(packet_hash);
	if (cached_packet) {
		// The packet was found in the local cache,
		// replay it to the Transport instance.
		inbound(cached_packet.raw(), cached_packet.receiving_interface());
	}
	else {
		// The packet is not in the local cache,
		// query the network.
		Packet request(destination, packet_hash, Type::Packet::DATA, Type::Packet::CACHE_REQUEST);
		request.send();
	}
}

/*static*/ uint32_t Transport::path_ttl_for(const Interface& interface, uint8_t hops) {
	/* A destination we are custodian of outlives one we merely heard about.
	 * Mode gets this backwards for a gateway: it hands the SHORTEST lifetime
	 * to the access-point radio, whose destinations are the most expensive to
	 * re-acquire and the ones we are obliged to answer for. Custody is the
	 * community: within the interface's radius, the custody lifetime. */
	if (interface && hops <= interface.community_radius() && interface.community_radius() > 0)
		return _custody_path_time;
	if (interface && interface.mode() == Type::Interface::MODE_ACCESS_POINT) return _ap_path_time;
	if (interface && interface.mode() == Type::Interface::MODE_ROAMING)      return _roaming_path_time;
	return _destination_timeout;
}

/* The one place a stored route becomes usable. A loaded image — or a live
 * table across an interface reconnect — can name an iface_hash that no longer
 * resolves, which would leave has_path() true while every send silently
 * dropped. Clearing the record's routing fields on the first failed resolve
 * turns that black hole into a path request. Writer-task only. */
/*static*/ bool Transport::peek_live_route(const Bytes& destination_hash, rdir_route_t& route, Interface& outbound_interface) {
	outbound_interface = {Type::NONE};
	if (!rdirPeekRoute(destination_hash.data(), &route)) return false;

	if (route.expires != 0 && (uint32_t)OS::time() >= route.expires) {
		DBGF_DEMOTE("Path to %s has expired, dropping route", destination_hash.toHex().c_str());
		rdirClearRoute(destination_hash.data());
		return false;
	}

	outbound_interface = find_interface_from_hash_prefix(route.iface_hash);
	if (!outbound_interface) {
		DBGF_DEMOTE("Path to %s names an interface that no longer exists, dropping route", destination_hash.toHex().c_str());
		rdirClearRoute(destination_hash.data());
		return false;
	}
	return true;
}

/* "Forget the path" now means dropping the routing layer, not the record: we
 * may still know who the destination is, and the identity is what makes the
 * next path response cheap. */
/*static*/ bool Transport::remove_path(const Bytes& destination_hash) {
	return rdirClearRoute(destination_hash.data());
}

/*
:param destination_hash: A destination hash as *bytes*.
:returns: *True* if a path to the destination is known, otherwise *False*.
*/
/*static*/ bool Transport::has_path(const Bytes& destination_hash) {
	rdir_route_t route;
	Interface iface = {Type::NONE};
	return peek_live_route(destination_hash, route, iface);
}

/*
:param destination_hash: A destination hash as *bytes*.
:returns: The number of hops to the specified destination, or ``RNS.Transport.PATHFINDER_M`` if the number of hops is unknown.
*/
/*static*/ uint8_t Transport::hops_to(const Bytes& destination_hash) {
	rdir_route_t route;
	if (rdirPeekRoute(destination_hash.data(), &route)) {
		return route.hops;
	}
	else {
		return PATHFINDER_M;
	}
}

/*
:param destination_hash: A destination hash as *bytes*.
:returns: The destination hash as *bytes* for the next hop to the specified destination, or *None* if the next hop is unknown.
*/
/*static*/ Bytes Transport::next_hop(const Bytes& destination_hash) {
	rdir_route_t route;
	if (rdirPeekRoute(destination_hash.data(), &route)) {
		return Bytes(route.received_from, RDIR_DEST_LEN);
	}
	else {
		return {};
	}
}

/*
:param destination_hash: A destination hash as *bytes*.
:returns: The interface for the next hop to the specified destination, or *None* if the interface is unknown.
*/
/*static*/ Interface Transport::next_hop_interface(const Bytes& destination_hash) {
	rdir_route_t route;
	Interface iface = {Type::NONE};
	peek_live_route(destination_hash, route, iface);
	return iface;
}

/*static*/ uint32_t Transport::next_hop_interface_bitrate(const Bytes& destination_hash) {
	const Interface& interface = next_hop_interface(destination_hash);
	if (interface) {
		return interface.bitrate();
	}
	else {
		return 0;
	}
}

/*static*/ uint16_t Transport::next_hop_interface_hw_mtu(const Bytes& destination_hash) {
	const Interface& interface = next_hop_interface(destination_hash);
	if (interface) {
		if (interface.AUTOCONFIGURE_MTU() || interface.FIXED_MTU()) return interface.HW_MTU();
		else return 0;
	}
	else {
		return 0;
	}
}

/*static*/ double Transport::next_hop_per_bit_latency(const Bytes& destination_hash) {
	uint32_t bitrate = next_hop_interface_bitrate(destination_hash);
	if (bitrate > 0) {
		return (1.0/(double)bitrate);
	}
	else {
		return 0.0;
	}
}

/*static*/ double Transport::next_hop_per_byte_latency(const Bytes& destination_hash) {
	double per_bit_latency = next_hop_per_bit_latency(destination_hash);
	if (per_bit_latency > 0.0) {
		return per_bit_latency*8.0;
	}
	else {
		return 0.0;
	}
}

/*static*/ double Transport::first_hop_timeout(const Bytes& destination_hash) {
	double latency = next_hop_per_byte_latency(destination_hash);
	if (latency > 0.0) {
		return RNS::Type::Reticulum::MTU * latency + RNS::Type::Reticulum::DEFAULT_PER_HOP_TIMEOUT;
	}
	else {
		return RNS::Type::Reticulum::DEFAULT_PER_HOP_TIMEOUT;
	}
}

/*static*/ double Transport::extra_link_proof_timeout(const Interface& interface) {
	if (interface) {
		return ((1.0/(double)interface.bitrate())*8.0)*RNS::Type::Reticulum::MTU;
	}
	else {
		return 0.0;
	}
}

/*static*/ bool Transport::expire_path(const Bytes& destination_hash) {
	/* Upstream zeroes the entry timestamp and lets the next jobs() cull sweep
	 * it; there is no such sweep here, so drop the routing layer directly. */
	return remove_path(destination_hash);
}

/*p

    @staticmethod
    def mark_path_unresponsive(destination_hash):
        if destination_hash in Transport.destination_table:
            Transport.path_states[destination_hash] = Transport.STATE_UNRESPONSIVE
            return True
        else:
            return False

    @staticmethod
    def mark_path_responsive(destination_hash):
        if destination_hash in Transport.destination_table:
            Transport.path_states[destination_hash] = Transport.STATE_RESPONSIVE
            return True
        else:
            return False

    @staticmethod
    def mark_path_unknown_state(destination_hash):
        if destination_hash in Transport.destination_table:
            Transport.path_states[destination_hash] = Transport.STATE_UNKNOWN
            return True
        else:
            return False

    @staticmethod
    def path_is_unresponsive(destination_hash):
        if destination_hash in Transport.path_states:
            if Transport.path_states[destination_hash] == Transport.STATE_UNRESPONSIVE:
                return True

        return False

*/

/*
Requests a path to the destination from the network. If
another reachable peer on the network knows a path, it
will announce it.

:param destination_hash: A destination hash as *bytes*.
:param on_interface: If specified, the path request will only be sent on this interface. In normal use, Reticulum handles this automatically, and this parameter should not be used.
*/
///*static*/ void Transport::request_path(const Bytes& destination_hash, const Interface& on_interface /*= {Type::NONE}*/, const Bytes& tag /*= {}*/, bool recursive /*= false*/) {
/*static*/ void Transport::request_path(const Bytes& destination_hash, const Interface& on_interface, const Bytes& tag /*= {}*/, bool recursive /*= false*/) {
	// No echo on point-to-point links: don't ask a single-peer link
	// (TCP, switched LAN) for a path to a destination we already learned via
	// that very link — its one peer is exactly who told us. Genuine discovery
	// of an unknown destination still goes out (next_hop_interface() is NONE
	// then), and shared radio interfaces are not point_to_point, so hidden-node
	// re-broadcast is unaffected.
	if (on_interface && on_interface.point_to_point()) {
		const Interface& learned_on = next_hop_interface(destination_hash);
		if (learned_on && learned_on.get_hash() == on_interface.get_hash()) {
			TRACEF("Not requesting path for %s back over point-to-point interface %s it was learned on", destination_hash.toHex().c_str(), on_interface.toString().c_str());
			return;
		}
	}

	Bytes request_tag;
	if (!tag) {
		request_tag = Identity::get_random_hash();
	}
	else {
		request_tag = tag;
	}

	Bytes path_request_data;
	if (Reticulum::transport_enabled()) {
		path_request_data = destination_hash + _identity.hash() + request_tag;
	}
	else {
		path_request_data = destination_hash + request_tag;
	}

	Destination path_request_dst({Type::NONE}, Type::Destination::OUT, Type::Destination::PLAIN, Type::Transport::APP_NAME, "path.request");
	Packet packet(path_request_dst, on_interface, path_request_data, Type::Packet::DATA, Type::Packet::CONTEXT_NONE, Type::Transport::BROADCAST, Type::Packet::HEADER_1);

	if (on_interface && recursive) {
// TODO
/*p
		if not hasattr(on_interface, "announce_cap"):
			on_interface.announce_cap = RNS.Reticulum.ANNOUNCE_CAP

		if not hasattr(on_interface, "announce_allowed_at"):
			on_interface.announce_allowed_at = 0

		if not hasattr(on_interface, "announce_queue"):
			on_interface.announce_queue = []
*/

		bool queued_announces = (on_interface.announce_queue().size() > 0);
		if (queued_announces) {
			TRACEF("Blocking recursive path request on %s due to queued announces", on_interface.toString().c_str());
			return;
		}
		else {
			double now = OS::time();
			if (now < on_interface.announce_allowed_at()) {
				TRACEF("Blocking recursive path request on %s due to active announce cap", on_interface.toString().c_str());
				return;
			}
			else {
				//p tx_time   = ((len(path_request_data)+RNS.Reticulum.HEADER_MINSIZE)*8) / on_interface.bitrate
				// Seconds, floating point — integer math truncated this to 0
				// on any sub-1s frame, defeating the cap (see outbound()).
				double wait_time = 0;
				if ( on_interface.bitrate() > 0 && on_interface.announce_cap() > 0) {
					double tx_time = (double)((path_request_data.size() + Type::Reticulum::HEADER_MINSIZE)*8) / (double)on_interface.bitrate();
					wait_time = tx_time / on_interface.announce_cap();
				}
				const_cast<Interface&>(on_interface).announce_allowed_at(now + wait_time);
			}
		}
	}

	packet.send();
	_path_requests[destination_hash] = OS::time();
}

/* Spangap deviation: cheapest-first discovery, with escalation.
 *
 * A path request we originate is our own errand — no transit policy suppresses
 * it, and outbound()'s access-point block covers announces only, so this used
 * to broadcast onto every interface including the radio. But nearly every
 * answer comes back over the cheap link, and the airtime was spent before we
 * knew that. So ask the cheap interfaces first and register the destination;
 * the sweep below either finds the path arrived — the radio never touched — or
 * escalates once the grace elapses. The cost of being wrong is that a
 * genuinely radio-only destination resolves `escalate_s` later.
 *
 * Cheap is bitrate against a threshold, not interface type: a metered or slow
 * uplink gets the same treatment as a radio without naming either, and rnsd
 * stays medium-agnostic. */
/*static*/ bool Transport::interface_is_cheap(const Interface& interface) {
	/* An interface that never declared a bitrate is treated as cheap: an
	 * unknown cost must not become a reason to delay discovery. */
	if (interface.bitrate() == 0) return true;
	return (uint32_t)interface.bitrate() >= _path_cheap_bitrate;
}

/*static*/ void Transport::request_path(const Bytes& destination_hash) {
	bool asked_cheap = false;
	bool have_expensive = false;
	for (auto& [hash, interface] : _interfaces) {
		if (!interface.OUT()) continue;
		if (interface_is_cheap(interface)) {
			request_path(destination_hash, interface);
			asked_cheap = true;
		}
		else have_expensive = true;
	}

	/* Nothing cheap to ask, or nothing expensive to protect: the tiering has
	 * no work to do and the request goes out as it always did. A radio-only
	 * node lands here, and pays no grace period. */
	if (!asked_cheap || !have_expensive) {
		if (!asked_cheap) request_path(destination_hash, {Type::NONE});
		return;
	}

	double due = OS::time() + _path_escalate_time;
	PathEscalation* free_slot = nullptr;
	for (uint16_t i = 0; i < PATH_ESCALATIONS_MAX; i++) {
		PathEscalation& e = _path_escalations[i];
		if (!e.used) { if (!free_slot) free_slot = &e; continue; }
		if (memcmp(e.dest, destination_hash.data(), Type::Reticulum::DESTINATION_LENGTH) == 0) {
			e.due = due;      /* re-asked before the grace ran out — restart it */
			return;
		}
	}
	if (!free_slot) {
		/* Table full. Fail OPEN: ask everything now rather than silently
		 * dropping the expensive half of a request we were asked to make. */
		for (auto& [hash, interface] : _interfaces)
			if (interface.OUT() && !interface_is_cheap(interface))
				request_path(destination_hash, interface);
		return;
	}
	memcpy(free_slot->dest, destination_hash.data(), Type::Reticulum::DESTINATION_LENGTH);
	free_slot->due  = due;
	free_slot->used = true;
}

/* Runs on the jobs() sweep. Bounded by construction — the table is a fixed 16
 * slots, and only requests we originated ever enter it. */
/*static*/ void Transport::escalate_path_requests(double now) {
	for (uint16_t i = 0; i < PATH_ESCALATIONS_MAX; i++) {
		PathEscalation& e = _path_escalations[i];
		if (!e.used) continue;
		Bytes destination_hash(e.dest, Type::Reticulum::DESTINATION_LENGTH);
		if (has_path(destination_hash)) {
			/* The cheap link answered. This is the whole point. */
			e.used = false;
			continue;
		}
		if (now < e.due) continue;
		e.used = false;
		DBGF_DEMOTE("path request %s: no answer in %us, escalating to expensive interfaces",
			destination_hash.toHex().c_str(), (unsigned)_path_escalate_time);
		for (auto& [hash, interface] : _interfaces)
			if (interface.OUT() && !interface_is_cheap(interface))
				request_path(destination_hash, interface);
	}
}

/*static*/ void Transport::path_request_handler(const Bytes& data, const Packet& packet) {
	TRACE("Transport::path_request_handler");
	try {
		// If there is at least bytes enough for a destination
		// hash in the packet, we assume those bytes are the
		// destination being requested.
		if (data.size() >= Type::Identity::TRUNCATED_HASHLENGTH/8) {
			Bytes destination_hash = data.left(Type::Identity::TRUNCATED_HASHLENGTH/8);
			//TRACEF("Transport::path_request_handler: destination_hash: %s", destination_hash.toHex().c_str());
			// If there is also enough bytes for a transport
			// instance ID and at least one tag byte, we
			// assume the next bytes to be the trasport ID
			// of the requesting transport instance.
			Bytes requesting_transport_instance;
			if (data.size() > (Type::Identity::TRUNCATED_HASHLENGTH/8)*2) {
				requesting_transport_instance = data.mid(Type::Identity::TRUNCATED_HASHLENGTH/8, Type::Identity::TRUNCATED_HASHLENGTH/8);
				//TRACEF("Transport::path_request_handler: requesting_transport_instance: %s", requesting_transport_instance.toHex().c_str());
			}

			Bytes tag_bytes;
			if (data.size() > Type::Identity::TRUNCATED_HASHLENGTH/8*2) {
				tag_bytes = data.mid(Type::Identity::TRUNCATED_HASHLENGTH/8*2);
			}
			else if (data.size() > Type::Identity::TRUNCATED_HASHLENGTH/8) {
				tag_bytes = data.mid(Type::Identity::TRUNCATED_HASHLENGTH/8);
			}

			if (tag_bytes) {
				//TRACEF("Transport::path_request_handler: tag_bytes: %s", tag_bytes.toHex().c_str());
				if (tag_bytes.size() > Type::Identity::TRUNCATED_HASHLENGTH/8) {
					tag_bytes = tag_bytes.left(Type::Identity::TRUNCATED_HASHLENGTH/8);
				}

				Bytes unique_tag = destination_hash + tag_bytes;
				//TRACEF("Transport::path_request_handler: unique_tag: %s", unique_tag.toHex().c_str());

				if (_discovery_pr_tags.find(unique_tag) == _discovery_pr_tags.end()) {
					// CBA ACCUMULATES
					_discovery_pr_tags.insert(unique_tag);
					_discovery_pr_tags_order.push_back(unique_tag);

					path_request(
						destination_hash,
						from_local_client(packet),
						packet.receiving_interface(),
						requesting_transport_instance,
						tag_bytes
					);
				}
				else {
					DBGF_DEMOTE("Ignoring duplicate path request for %s with tag %s", destination_hash.toHex().c_str(), unique_tag.toHex().c_str());
				}
			}
			else {
				DBGF_DEMOTE("Ignoring tagless path request for %s", destination_hash.toHex().c_str());
			}
		}
	}
	catch (const std::exception& e) {
		ERRORF("Error while handling path request. The contained exception was: %s", e.what());
	}
}

/*static*/ void Transport::path_request(const Bytes& destination_hash, bool is_from_local_client, const Interface& attached_interface, const Bytes& requestor_transport_id /*= {}*/, const Bytes& tag /*= {}*/) {
	TRACE("Transport::path_request");
	bool should_search_for_unknown = false;
	std::string interface_str;

	if (attached_interface) {
		if (Reticulum::transport_enabled() && (attached_interface.mode() & Interface::DISCOVER_PATHS_FOR) > 0) {
			TRACE("Transport::path_request_handler: interface allows searching for unknown paths");
			should_search_for_unknown = true;
		}

		interface_str = " on " + attached_interface.toString();
	}

	TRACEF("Transport::path_request: for destination %s%s", destination_hash.toHex().c_str(), interface_str.c_str());

	bool destination_exists_on_local_client = false;
	(void)destination_exists_on_local_client;	// set for future use; not yet consumed
	rdir_route_t route;
	Interface receiving_interface = {Type::NONE};
	bool have_route = peek_live_route(destination_hash, route, receiving_interface);

	if (_local_client_interfaces.size() > 0) {
		if (have_route) {
			TRACEF("Transport::path_request_handler: entry found for destination %s", destination_hash.toHex().c_str());
			if (is_local_client_interface(receiving_interface)) {
				destination_exists_on_local_client = true;
				// CBA ACCUMULATES
				_pending_local_path_requests.insert({destination_hash, attached_interface});
			}
		}
		else {
			TRACEF("Transport::path_request_handler: entry not found for destination %s", destination_hash.toHex().c_str());
		}
	}

	//local_destination = next((d for d in Transport.destinations if d.hash == destination_hash), None)
	auto destinations_iter = _destinations.find(destination_hash);
	if (destinations_iter != _destinations.end()) {
		auto& local_destination = (*destinations_iter).second;
		local_destination.announce({Bytes::NONE}, true, attached_interface, tag);
		INFOF("Answering path request for destination %s%s, destination is local to this system", destination_hash.toHex().c_str(), interface_str.c_str());
	}
    //p elif (RNS.Reticulum.transport_enabled() or is_from_local_client) and (destination_hash in Transport.destination_table):
	else if ((Reticulum::transport_enabled() || is_from_local_client) && have_route) {
		TRACEF("Transport::path_request_handler: entry found for destination %s", destination_hash.toHex().c_str());
		/* A path response IS the original signed announce, so only a node
		 * still holding those bytes can answer one. That is what the blob pool
		 * is for; a destination whose blob has been evicted (or whose announce
		 * never fitted a slot) falls through to normal discovery. */
		uint8_t blob_raw[Type::Reticulum::MTU];
		size_t blob_n = rdirCopyBlob(destination_hash.data(), blob_raw, sizeof(blob_raw));
		if (blob_n == 0) {
			DBGF_DEMOTE("No retained announce for %s, not answering path request", destination_hash.toHex().c_str());
			return;
		}
		Packet announce_packet(Bytes(blob_raw, blob_n));
		if (!announce_packet.unpack()) {
			DBGF_DEMOTE("Retained announce for %s is unusable, not answering path request", destination_hash.toHex().c_str());
			return;
		}
		/* Replaying a cached announce is equivalent to receiving it again over
		 * an interface, so the hop count advances; it is stored with its
		 * non-increased count. */
		announce_packet.hops(announce_packet.hops() + 1);
TRACEF("announce_packet destination_hash: %s", announce_packet.destination_hash().toHex().c_str());
TRACEF("announce_packet hops: %u", announce_packet.hops());
TRACEF("announce_packet str: %s", announce_packet.toString().c_str());
		Bytes next_hop(route.received_from, RDIR_DEST_LEN);

		if (attached_interface.mode() == Type::Interface::MODE_ROAMING && attached_interface == receiving_interface) {
			DBG_DEMOTE("Not answering path request on roaming-mode interface, since next hop is on same roaming-mode interface");
		}
		else {
			if (requestor_transport_id && next_hop == requestor_transport_id) {
				// TODO: Find a bandwidth efficient way to invalidate our
				// known path on this signal. The obvious way of signing
				// path requests with transport instance keys is quite
				// inefficient. There is probably a better way. Doing
				// path invalidation here would decrease the network
				// convergence time. Maybe just drop it?
				DBGF_DEMOTE("Not answering path request for destination %s%s, since next hop is the requestor", destination_hash.toHex().c_str(), interface_str.c_str());
			}
			// Only re-emit a path back out the *same* interface the request
			// arrived on when we are the destination's direct neighbor on
			// that medium (1 hop, learned on that interface). Re-emitting a
			// multi-hop path onto a shared/broadcast medium is what
			// propagates looped/long paths (the gateway hops=5,
			// next-hop-unknown pollution). On point-to-point links the only
			// "1 hop on that interface" path is the requesting peer itself,
			// already handled above — so this also suppresses the pointless
			// p2p echo without needing to tag interface kinds.
			// Cross-interface answering (learned on iface A, answer on B) is
			// legitimate transport bridging and is unaffected.
			else if (attached_interface == receiving_interface && route.hops > 1) {
				DBGF_DEMOTE("Not answering path request for destination %s%s back out its own interface: path is %u hops, not a direct neighbor on that medium", destination_hash.toHex().c_str(), interface_str.c_str(), (unsigned)route.hops);
			}
			else {
				/* Transporting on behalf of others — verbose, like the rest
				 * of the path-request processing. The local-destination case
				 * above stays at INFOF: that one concerns this node. */
				VERBOSEF("Answering path request for destination %s%s, path is known", destination_hash.toHex().c_str(), interface_str.c_str());

				double now = OS::time();
				uint8_t retries = Type::Transport::PATHFINDER_R;
				bool block_rebroadcasts = true;
				// CBA TODO Determine if okay to take hops directly from DestinationEntry
				uint8_t announce_hops = announce_packet.hops();

				double retransmit_timeout = 0;
				if (is_from_local_client) {
					retransmit_timeout = now;
				}
				else {
					// TODO: Look at this timing
					retransmit_timeout = now + Type::Transport::PATH_REQUEST_GRACE /*+ (RNS.rand() * Transport.PATHFINDER_RW)*/;
				}

				// This handles an edge case where a peer sends a path request
				// for a destination just after an announce for said destination
				// has arrived, but before it has been rebroadcast locally. In
				// such a case the actual announce is marked held and re-armed
				// once the path request has been served to the peer.
				AnnounceRec* pending = announce_find(announce_packet.destination_hash(), /*held=*/false);
				if (pending) {
					/* Only one can wait: a second path request while one is
					 * already held would otherwise strand the first. */
					AnnounceRec* stale = announce_find(announce_packet.destination_hash(), /*held=*/true);
					if (stale) memset(stale, 0, sizeof(*stale));
					pending->flags |= ANNOUNCE_F_HELD;
				}

				AnnounceRec* slot = announce_alloc();
				announce_store(slot, announce_packet.destination_hash(), announce_packet, now,
				               retransmit_timeout, retries, announce_hops,
				               block_rebroadcasts, attached_interface);
				cull_announce_table();

				// Send PATH_RESPONSE immediately for local client requests
				// rather than waiting for the jobs() loop. On resource-
				// constrained platforms (e.g. ESP32), continuous TCP backbone
				// data can starve the cooperative jobs() loop for many
				// seconds, causing path discovery timeouts for local clients.
				if (is_from_local_client) {
					Identity imm_identity(Identity::recall(announce_packet.destination_hash()));
					if (imm_identity) {
						Destination imm_destination(imm_identity, Type::Destination::OUT, Type::Destination::SINGLE, announce_packet.destination_hash());
						Packet imm_packet(
							imm_destination,
							attached_interface,
							announce_packet.data(),
							Type::Packet::ANNOUNCE,
							Type::Packet::PATH_RESPONSE,
							Type::Transport::TRANSPORT,
							Type::Packet::HEADER_2,
							_identity.hash(),
							true,
							announce_packet.context_flag()
						);
						imm_packet.hops(announce_hops);
						imm_packet.send();
						AnnounceRec* sent = announce_find(announce_packet.destination_hash(), /*held=*/false);
						if (sent) memset(sent, 0, sizeof(*sent));
					}
				}
			}
		}
	}
	else if (is_from_local_client) {
		// Forward path request on all interfaces
		// except the local client
		if (!path_search_possible(attached_interface)) {
			DBGF_DEMOTE("path request %s%s from local client: nowhere to forward", destination_hash.toHex().c_str(), interface_str.c_str());
			return;
		}
		DBGF_DEMOTE("path request %s%s from local client: forwarding", destination_hash.toHex().c_str(), interface_str.c_str());
		Bytes request_tag = Identity::get_random_hash();
		for (auto& [hash, interface] : _interfaces) {
			// A local client's search is this node's own errand: every OUT
			// interface except the client's own is asked. Whose errands get
			// run at all is the requestor-side gate in path_search_possible.
			if (interface != attached_interface) {
				request_path(destination_hash, interface, request_tag);
			}
		}
	}
	else if (should_search_for_unknown) {
		TRACEF("Transport::path_request_handler: searching for unknown path to %s", destination_hash.toHex().c_str());
		if (_discovery_path_requests.find(destination_hash) != _discovery_path_requests.end()) {
			DBGF_DEMOTE("path request %s%s: already searching", destination_hash.toHex().c_str(), interface_str.c_str());
		}
		else if (!path_search_possible(attached_interface)) {
			DBGF_DEMOTE("path request %s%s: not searched, nowhere to forward", destination_hash.toHex().c_str(), interface_str.c_str());
		}
		else {
			// Forward path request on all interfaces
			// except the requestor interface
			DBGF_DEMOTE("path request %s%s: searching", destination_hash.toHex().c_str(), interface_str.c_str());
			//p pr_entry = { "destination_hash": destination_hash, "timeout": time.time()+Transport.PATH_REQUEST_TIMEOUT, "requesting_interface": attached_interface }
			//p _discovery_path_requests[destination_hash] = pr_entry;
			// CBA ACCUMULATES
			_discovery_path_requests.insert({destination_hash, {
				destination_hash,
				OS::time() + Type::Transport::PATH_REQUEST_TIMEOUT,
				attached_interface
			}});

			for (auto& [hash, interface] : _interfaces) {
				// No path known here, so by the same-interface rule we must
				// NOT re-flood the request back out the interface it came in
				// on — that is what built the LoRa↔TCP path loop (every
				// transport re-flooding into the others, hop counts to 127).
				// Discovery still forwards out *other* interfaces (stock
				// Reticulum behaviour); genuine multi-hop LoRa paths still
				// propagate via normal announce flooding through transports.
				// Whose requests get searched at all is the requestor-side
				// community gate in path_search_possible; a search we did
				// take on goes out everywhere it might be answered.
				if (interface == attached_interface) {
					TRACEF("Transport::path_request: not requesting path on same interface %s", interface.toString().c_str());
				}
				else {
					TRACEF("Transport::path_request: requesting path on interface %s", interface.toString().c_str());
					// Use the previously extracted tag from this path request
					// on the new path requests as well, to avoid potential loops
					request_path(destination_hash, interface, tag, true);
				}
			}
		}
	}
	else if (!is_from_local_client && _local_client_interfaces.size() > 0) {
		// Forward the path request on all local
		// client interfaces
		DBGF_DEMOTE("Forwarding path request for destination %s%s to local clients", destination_hash.toHex().c_str(), interface_str.c_str());
		for (const Interface& interface : _local_client_interfaces) {
			request_path(destination_hash, interface);
		}
	}
	else {
		DBGF_DEMOTE("Ignoring path request for destination %s%s, no path known", destination_hash.toHex().c_str(), interface_str.c_str());
	}
}

/*static*/ bool Transport::from_local_client(const Packet& packet) {
	if (packet.receiving_interface().parent_interface()) {
		return is_local_client_interface(packet.receiving_interface());
	}
	else {
		return false;
	}
}

/*static*/ bool Transport::is_local_client_interface(const Interface& interface) {
	if (interface.parent_interface()) {
		if (interface.parent_interface()->is_local_shared_instance()) {
			return true;
		}
		else {
			return false;
		}
	}
	else {
		return false;
	}
}

/*static*/ bool Transport::interface_to_shared_instance(const Interface& interface) {
	if (interface.is_connected_to_shared_instance()) {
		return true;
	}
	else {
		return false;
	}
}

/*static*/ void Transport::detach_interfaces() {
// TODO
/*p
	detachable_interfaces = []

	for interface in Transport.interfaces:
		// Currently no rules are being applied
		// here, and all interfaces will be sent
		// the detach call on RNS teardown.
		if True:
			detachable_interfaces.append(interface)
		else:
			pass
	
	for interface in Transport.local_client_interfaces:
		// Currently no rules are being applied
		// here, and all interfaces will be sent
		// the detach call on RNS teardown.
		if True:
			detachable_interfaces.append(interface)
		else:
			pass

	for interface in detachable_interfaces:
		interface.detach()
*/
}

/*static*/ void Transport::shared_connection_disappeared() {
// TODO
/*p
	for link in Transport.active_links:
		link.teardown()

	for link in Transport.pending_links:
		link.teardown()

	Transport.announce_table    = {}
	Transport.destination_table = {}
	Transport.reverse_table     = {}
	Transport.link_table        = {}
	Transport.held_announces    = {}
	Transport.announce_handlers = []
	Transport.tunnels           = {}
*/
}

/*static*/ void Transport::shared_connection_reappeared() {
// TODO
/*p
	if Transport.owner.is_connected_to_shared_instance:
		for registered_destination in Transport.destinations:
			if registered_destination.type == RNS.Destination.SINGLE:
				registered_destination.announce(path_response=True)
*/
}

/*static*/ void Transport::drop_announce_queues() {
	for (auto& [interface_hash, interface] : _interfaces) {
		size_t na = interface.announce_queue().size();
		if (na > 0) {
			interface.announce_queue().clear();
			VERBOSEF("Dropped %lu queued announce%s on %s", (unsigned long)na, na == 1 ? "" : "s", interface.toString().c_str());
		}
	}
}

/*static*/ uint64_t Transport::announce_emitted(const Packet& packet) {
	//p random_blob = packet.data[RNS.Identity.KEYSIZE//8+RNS.Identity.NAME_HASH_LENGTH//8:RNS.Identity.KEYSIZE//8+RNS.Identity.NAME_HASH_LENGTH//8+10]
	//p announce_emitted = int.from_bytes(random_blob[5:10], "big")
	Bytes random_blob = packet.data().mid(RNS::Type::Identity::KEYSIZE/8+RNS::Type::Identity::NAME_HASH_LENGTH/8, 10);
	if (random_blob) {
		return OS::from_bytes_big_endian(random_blob.data() + 5, 5);
	}
	return 0;
}

/*static*/ void Transport::write_packet_hashlist() {
#if defined(RNS_USE_FS) && defined(RNS_PERSIST_PATHS)
// TODO
/*p
	if not Transport.owner.is_connected_to_shared_instance:
		if hasattr(Transport, "saving_packet_hashlist"):
			wait_interval = 0.2
			wait_timeout = 5
			wait_start = time.time()
			while Transport.saving_packet_hashlist:
				time.sleep(wait_interval)
				if time.time() > wait_start+wait_timeout:
					RNS.log("Could not save packet hashlist to storage, waiting for previous save operation timed out.", RNS.LOG_ERROR)
					return False

		try:
			Transport.saving_packet_hashlist = True
			save_start = time.time()

			if not RNS.Reticulum.transport_enabled():
				Transport.packet_hashlist = []
			else:
				RNS.log("Saving packet hashlist to storage...", RNS.LOG_DEBUG)

			packet_hashlist_path = RNS.Reticulum.storagepath+"/packet_hashlist"
			file = open(packet_hashlist_path, "wb")
			file.write(umsgpack.packb(Transport.packet_hashlist))
			file.close()

			DEBUGF("Saved packet hashlist in %.3f seconds", OS::round(time.time() - save_start))

		except Exception as e:
			RNS.log("Could not save packet hashlist to storage, the contained exception was: "+str(e), RNS.LOG_ERROR)

		Transport.saving_packet_hashlist = False
*/
#endif
}

//#define CUSTOM 1

/*static*/ bool Transport::read_path_table() {
	DEBUG("Transport::read_path_table");
#if defined(RNS_USE_FS) && defined(RNS_PERSIST_PATHS)
	char destination_table_path[Type::Reticulum::FILEPATH_MAXSIZE];
	snprintf(destination_table_path, Type::Reticulum::FILEPATH_MAXSIZE, "%s/destination_table", Reticulum::_storagepath);
	if (!_owner.is_connected_to_shared_instance() && OS::file_exists(destination_table_path)) {
		try {
#if CUSTOM
TRACEF("Transport::read_path_table: buffer capacity %d bytes", Persistence::_buffer.capacity());
			if (RNS::Utilities::OS::read_file(destination_table_path, Persistence::_buffer) > 0) {
				TRACEF("Transport::read_path_table: read: %d bytes", Persistence::_buffer.size());
#ifndef NDEBUG
				// CBA DEBUG Dump path table
TRACEF("Transport::read_path_table: buffer addr: 0x%X", Persistence::_buffer.data());
TRACEF("Transport::read_path_table: buffer size %d bytes", Persistence::_buffer.size());
				//TRACE("SERIALIZED: destination_table");
				//TRACE(Persistence::_buffer.toString().c_str());
#endif
#ifdef USE_MSGPACK
				DeserializationError error = deserializeMsgPack(Persistence::_document, Persistence::_buffer.data());
#else
				DeserializationError error = deserializeJson(Persistence::_document, Persistence::_buffer.data());
#endif
				TRACEF("Transport::read_path_table: doc size: %d bytes", Persistence::_buffer.size());
				if (!error) {
					// Calculate crc for dirty-checking before write
					_path_table_crc = Crc::crc32(0, Persistence::_buffer.data(), Persistence::_buffer.size());
					_path_table = Persistence::_document.as<PathTable>();
#else	// CUSTOM
				// Calculate crc for dirty-checking before later write
				if (Persistence::deserialize(_path_table, destination_table_path, _path_table_crc) > 0) {
#endif	// CUSTOM

					TRACEF("Transport::read_path_table: successfully deserialized path table with %d entries", _path_table.size());
					std::vector<Bytes> invalid_paths;
					for (auto& [destination_hash, destination_entry] : _path_table) {
#ifndef NDEBUG
						TRACEF("Transport::read_path_table: hash: %s entry: {%s}", destination_hash.toHex().c_str(), destination_entry.debugString().c_str());
#endif
						// CBA Avoid accessing announce_packet() and receiving_interface() until actually needed in order to
						// take advantage of lazy loading and avoid incurring memory hit to store if not actually needed.

						// CBA Optimized to not check for a valid cached announce packet,
						// and instead checking if/when the path is actually used.
						/*
						// CBA If announce packet is not cached then remove destination entry (it's useless without announce packet)
						if (!is_cached_packet(destination_entry.announce_packet_hash())) {
							// remove destination
							WARNINGF("Transport::read_path_table: removing invalid path to %s due to missing announce packet", destination_hash.toHex().c_str());
							invalid_paths.push_back(destination_hash);
							continue;
						}
						*/
						// CBA If receiving interface is not present then remove destination entry (it's useless without receiving interface)
						if (!is_interface_from_hash(destination_entry.receiving_interface_hash())) {
							// remove destination
							WARNINGF("Transport::read_path_table: removing invalid path to %s due to missing receiving interface", destination_hash.toHex().c_str());
							invalid_paths.push_back(destination_hash);
							continue;
						}
						DEBUGF("Loaded path table entry for %s from storage", destination_hash.toHex().c_str());
						OS::reset_watchdog();
					}
					for (const auto& destination_hash : invalid_paths) {
						_path_table.erase(destination_hash);
					}
                    VERBOSEF("Loaded %lu path table entries from storage", _path_table.size());
					return true;
				}
				else {
					TRACE("Transport::read_path_table: failed to deserialize");
				}
#if CUSTOM
			}
			else {
				TRACE("Transport::read_path_table: destination table read failed");
			}
#else	// CUSTOM
#endif	// CUSTOM
		}
		catch (const std::exception& e) {
			ERRORF("Could not load destination table from storage, the contained exception was: %s", e.what());
		}
	}
#endif
	return false;
}

/*static*/ bool Transport::write_path_table() {
	DEBUG("Transport::write_path_table");

	if (Transport::_owner.is_connected_to_shared_instance()) {
		return true;
	}

	bool success = false;
#if defined(RNS_USE_FS) && defined(RNS_PERSIST_PATHS)
	if (_saving_path_table) {
		double wait_interval = 0.2;
		double wait_timeout = 5;
		double wait_start = OS::time();
		while (_saving_path_table) {
			OS::sleep(wait_interval);
			if (OS::time() > (wait_start + wait_timeout)) {
				ERROR("Could not save path table to storage, waiting for previous save operation timed out.");
				return false;
			}
		}
	}

	try {
		_saving_path_table = true;
		double save_start = OS::time();

/*p
		serialised_destinations = []
		for destination_hash in Transport.destination_table:
			// Get the destination entry from the destination table
			de = Transport.destination_table[destination_hash]
			interface_hash = de[5].get_hash()

			// Only store destination table entry if the associated
			// interface is still active
			interface = Transport.find_interface_from_hash(interface_hash)
			if interface != None:
				// Get the destination entry from the destination table
				de = Transport.destination_table[destination_hash]
				timestamp = de[0]
				received_from = de[1]
				hops = de[2]
				expires = de[3]
				random_blobs = de[4]
				packet_hash = de[6].get_hash()

				serialised_entry = [
					destination_hash,
					timestamp,
					received_from,
					hops,
					expires,
					random_blobs,
					interface_hash,
					packet_hash
				]

				serialised_destinations.append(serialised_entry)

				Transport.cache(de[6], force_cache=True)

		destination_table_path = RNS.Reticulum.storagepath+"/destination_table"
		file = open(destination_table_path, "wb")
		file.write(umsgpack.packb(serialised_destinations))
		file.close()
*/

#if CUSTOM
		{
			Persistence::_document.set(_path_table);
			TRACEF("Transport::write_path_table: doc size %d bytes", Persistence::_document.memoryUsage());

			//size_t size = 8192;
			size_t size = Persistence::_buffer.capacity();
TRACEF("Transport::write_path_table: obtaining buffer size %lu bytes", size);
			uint8_t* buffer = Persistence::_buffer.writable(size);
TRACEF("Transport::write_path_table: buffer addr: %ld", (long)buffer);
#ifdef USE_MSGPACK
			size_t length = serializeMsgPack(Persistence::_document, buffer, size);
#else
			size_t length = serializeJson(Persistence::_document, buffer, size);
#endif
			TRACEF("Transport::write_path_table: serialized %d bytes", length);
			if (length < size) {
				Persistence::_buffer.resize(length);
			}
		}
		if (Persistence::_buffer.size() > 0) {
#ifndef NDEBUG
			// CBA DEBUG Dump path table
TRACEF("Transport::write_path_table: buffer addr: %ld", (long)Persistence::_buffer.data());
TRACEF("Transport::write_path_table: buffer size %lu bytes", Persistence::_buffer.size());
			//TRACE("SERIALIZED: destination_table");
			//TRACE(Persistence::_buffer.toString().c_str());
#endif
			// Check crc to see if data has changed before writing
			uint32_t crc = Crc::crc32(0, Persistence::_buffer.data(), Persistence::_buffer.size());
			if (_path_table_crc > 0 && crc == _path_table_crc) {
				TRACE("Transport::write_path_table: no change detected, skipping write");
			}
			else {
				TRACE("Transport::write_path_table: change detected, writing...");
				DEBUGF("Saving %d path table entries to storage...", _path_table.size());
				char destination_table_path[Type::Reticulum::FILEPATH_MAXSIZE];
				snprintf(destination_table_path, Type::Reticulum::FILEPATH_MAXSIZE, "%s/destination_table", Reticulum::_storagepath);
				if (RNS::Utilities::OS::write_file(destination_table_path, Persistence::_buffer) == Persistence::_buffer.size()) {
					TRACEF("Transport::write_path_table: wrote %d entries, %d bytes", _path_table.size(), Persistence::_buffer.size());
					_path_table_crc = crc;
					success = true;

#ifndef NDEBUG
					// CBA DEBUG Dump path table
					//TRACE("FILE: destination_table");
					//if (OS::read_file("/destination_table", Persistence::_buffer) > 0) {
					//	TRACE(Persistence::_buffer.toString().c_str());
					//}
#endif
				}
				else {
					ERROR("Transport::write_path_table: write failed");
				}
			}
		}
		else {
			ERROR("Transport::write_path_table: failed to serialize");
		}
#else	// CUSTOM
		uint32_t crc = Persistence::crc(_path_table);
		if (_path_table_crc > 0 && crc == _path_table_crc) {
			TRACE("Transport::write_path_table: no change detected, skipping write");
		}
		else {
			TRACE("Transport::write_path_table: change detected, writing...");
			DEBUGF("Saving %d path table entries to storage...", _path_table.size());
			char destination_table_path[Type::Reticulum::FILEPATH_MAXSIZE];
			snprintf(destination_table_path, Type::Reticulum::FILEPATH_MAXSIZE, "%s/destination_table", Reticulum::_storagepath);
			size_t len = Persistence::serialize(_path_table, destination_table_path, _path_table_crc);
			if (len > 0) {
				TRACEF("Transport::write_path_table: wrote %d entries, %d bytes", _path_table.size(), len);
				success = true;
			}
			else {
				ERROR("Transport::write_path_table: serialize failed");
			}
		}
#endif	// CUSTOM

		if (success) {
			DEBUGF("Saved %lu path table entries in %.3f seconds", _path_table.size(), OS::round(OS::time() - save_start, 3));
		}
	}
	catch (const std::exception& e) {
		ERRORF("Could not save path table to storage, the contained exception was: %s", e.what());
	}
#endif

	_saving_path_table = false;

	return success;
}

/*static*/ void Transport::read_tunnel_table() {
	DEBUG("Transport::read_tunnel_table");
#if defined(RNS_USE_FS) && defined(RNS_PERSIST_PATHS)
// TODO
/*p
		tunnel_table_path = RNS.Reticulum.storagepath+"/tunnels"
		if os.path.isfile(tunnel_table_path) and not Transport.owner.is_connected_to_shared_instance:
			serialised_tunnels = []
			try:
				file = open(tunnel_table_path, "rb")
				serialised_tunnels = umsgpack.unpackb(file.read())
				file.close()

				for serialised_tunnel in serialised_tunnels:
					tunnel_id = serialised_tunnel[0]
					interface_hash = serialised_tunnel[1]
					serialised_paths = serialised_tunnel[2]
					expires = serialised_tunnel[3]

					tunnel_paths = {}
					for serialised_entry in serialised_paths:
						destination_hash = serialised_entry[0]
						timestamp = serialised_entry[1]
						received_from = serialised_entry[2]
						hops = serialised_entry[3]
						expires = serialised_entry[4]
						random_blobs = serialised_entry[5]
						receiving_interface = Transport.find_interface_from_hash(serialised_entry[6])
						announce_packet = Transport.get_cached_packet(serialised_entry[7])

						if announce_packet != None:
							announce_packet.unpack()
							// We increase the hops, since reading a packet
							// from cache is equivalent to receiving it again
							// over an interface. It is cached with it's non-
							// increased hop-count.
							announce_packet.hops += 1

							tunnel_path = [timestamp, received_from, hops, expires, random_blobs, receiving_interface, announce_packet]
							tunnel_paths[destination_hash] = tunnel_path

					tunnel = [tunnel_id, None, tunnel_paths, expires]
					Transport.tunnels[tunnel_id] = tunnel

				if len(Transport.destination_table) == 1:
					specifier = "entry"
				else:
					specifier = "entries"

				RNS.log("Loaded "+str(len(Transport.tunnels))+" tunnel table "+specifier+" from storage", RNS.LOG_VERBOSE)

			except Exception as e:
				RNS.log("Could not load tunnel table from storage, the contained exception was: "+str(e), RNS.LOG_ERROR)
*/
#endif
}

/*static*/ void Transport::write_tunnel_table() {
#if defined(RNS_USE_FS) && defined(RNS_PERSIST_PATHS)
// TODO
/*p
	if not Transport.owner.is_connected_to_shared_instance:
		if hasattr(Transport, "saving_tunnel_table"):
			wait_interval = 0.2
			wait_timeout = 5
			wait_start = time.time()
			while Transport.saving_tunnel_table:
				time.sleep(wait_interval)
				if time.time() > wait_start+wait_timeout:
					RNS.log("Could not save tunnel table to storage, waiting for previous save operation timed out.", RNS.LOG_ERROR)
					return False

		try:
			Transport.saving_tunnel_table = True
			save_start = time.time()
			RNS.log("Saving tunnel table to storage...", RNS.LOG_DEBUG)

			serialised_tunnels = []
			for tunnel_id in Transport.tunnels:
				te = Transport.tunnels[tunnel_id]
				interface = te[1]
				tunnel_paths = te[2]
				expires = te[3]

				if interface != None:
					interface_hash = interface.get_hash()
				else:
					interface_hash = None

				serialised_paths = []
				for destination_hash in tunnel_paths:
					de = tunnel_paths[destination_hash]

					timestamp = de[0]
					received_from = de[1]
					hops = de[2]
					expires = de[3]
					random_blobs = de[4]
					packet_hash = de[6].get_hash()

					serialised_entry = [
						destination_hash,
						timestamp,
						received_from,
						hops,
						expires,
						random_blobs,
						interface_hash,
						packet_hash
					]

					serialised_paths.append(serialised_entry)

					Transport.cache(de[6], force_cache=True)


				serialised_tunnel = [tunnel_id, interface_hash, serialised_paths, expires]
				serialised_tunnels.append(serialised_tunnel)

			tunnels_path = RNS.Reticulum.storagepath+"/tunnels"
			file = open(tunnels_path, "wb")
			file.write(umsgpack.packb(serialised_tunnels))
			file.close()

			DEBUGF("Saved %lu tunnel table entries in %.3f seconds", serialised_tunnels.size(), OS::round(OS::time() - save_start))
		except Exception as e:
			ERRORF("Could not save tunnel table to storage, the contained exception was: %s", e.what())

		Transport.saving_tunnel_table = False
*/
#endif
}

/*static*/ void Transport::persist_data() {
	TRACE("Transport::persist_data()");
	write_packet_hashlist();
	write_path_table();
	write_tunnel_table();
}

/*static*/ void Transport::clean_caches() {

	// If currently cleaning caches then disregard
	if (cleaning_caches) {
		WARNING("Transport::clean_caches: already cleaning!");
		return;
	}
	cleaning_caches = true;

	TRACE("Transport::clean_caches()");
#if defined(RNS_USE_FS) && defined(RNS_PERSIST_PATHS)
	// CBA Remove cached packets no longer in path list
	std::list<std::string> remove_list;
	OS::list_directory(Reticulum::_cachepath, [&remove_list](const char* file_name) {
		TRACEF("Transport::clean_caches: Checking for use of cached packet %s", file_name);
		bool found = false;
		for (auto& [destination_hash, destination_entry] : _path_table) {
			if (strcasecmp(file_name, destination_entry.announce_packet_hash().toHex().c_str()) == 0) {
				found = true;
				break;
			}
		}
		if (!found) {
			remove_list.push_back(file_name);
		}
		//OS::reset_watchdog();
		OS::run_loop();
	});
    for (auto& file_name : remove_list) {
		TRACEF("Transport::clean_caches: No matching path found, removing cached packet %s", file_name.c_str());
		char packet_cache_path[Type::Reticulum::FILEPATH_MAXSIZE];
		snprintf(packet_cache_path, Type::Reticulum::FILEPATH_MAXSIZE, "%s/%s", Reticulum::_cachepath, file_name.c_str());
		OS::remove_file(packet_cache_path);
		//OS::reset_watchdog();
		OS::run_loop();
	}
#endif

	cleaning_caches = false;
}

/*static*/ void Transport::dump_stats() {

	Memory::dump_heap_stats();

	size_t memory = Memory::heap_available();
	uint8_t memory_pct = 0;
	size_t memory_size = Memory::heap_size();
	if (memory_size >0 ) memory_pct = (uint8_t)((double)memory / (double)memory_size * 100.0);
	if (_last_memory == 0) {
		_last_memory = memory;
	}

#if defined(ESP32)
	// CBA NOTE It appears that ESP.getFreePsram() may not accurately reflect available availabe PSRAM
	// because it appears to always decrease (even to zero) as if PSRAM is being leaked. Maybe it doesn't
	// accurately reflect PSRAM freed with calls to free()???
	size_t psram = ESP.getFreePsram();
	uint8_t psram_pct = 0;
	size_t psram_size = ESP.getPsramSize();
	if (psram_size > 0) psram_pct = (uint8_t)((double)psram / (double)psram_size * 100.0);
	if (_last_psram == 0) {
		_last_psram = psram;
	}
#else
	size_t psram = 0;
	uint8_t psram_pct = 0;
#endif

	size_t flash = OS::storage_available();
	if (_last_flash == 0) {
		_last_flash = flash;
	}
	uint8_t flash_pct = 0;
	size_t flash_size = OS::storage_size();
	if (flash_size > 0) flash_pct = (uint8_t)((double)flash / (double)flash_size * 100.0);

	// memory
	// storage
	// _destinations
	// _path_table
	// _reverse_table
	HEADF(LOG_VERBOSE, "sram: %u (%u%%) [%d] psram: %u (%u%%) [%d] flash: %u (%u%%) [%d] paths: %u dsts: %u revr: %u annc: %u held: %u", memory, memory_pct, memory - _last_memory, psram, psram_pct, psram - _last_psram, flash, flash_pct, flash - _last_flash, rdirCount(), _destinations.size(), _reverse_table.size(), announce_count(false), announce_count(true));

	// _path_requests
	// _discovery_path_requests
	// _pending_local_path_requests
	// _discovery_pr_tags
	// _control_destinations
	// _control_hashes
	VERBOSEF("preqs: %u dpreqs: %u ppreqs: %u dprt: %u cdsts: %u chshs: %u", _path_requests.size(), _discovery_path_requests.size(), _pending_local_path_requests.size(), _discovery_pr_tags.size(), _control_destinations.size(), _control_hashes.size());

	// _packet_hashlist
	// _receipts
	// _link_table
	// _pending_links
	// _active_links
	// _tunnels
	uint32_t destination_path_responses = 0;
	for (auto& [destination_hash, destination] : _destinations) {
		destination_path_responses += destination.path_responses().size();
	}
	uint32_t interface_announces = 0;
	for (auto& [interface_hash, interface] : _interfaces) {
		interface_announces += interface.announce_queue().size();
	}
	VERBOSEF("phl: %u rcp: %u lt: %u pl: %u al: %u tun: %u", _packet_hashlist.size(), _receipts.size(), _link_table.size(), _pending_links.size(), _active_links.size(), _tunnels.size());
	VERBOSEF("pin: %u pout: %u padd: %u dpr: %u ia: %u\r\n", _packets_received, _packets_sent, _destinations_added, destination_path_responses, interface_announces);

	_last_memory = memory;
	_last_psram = psram;
	_last_flash = flash;

	VERBOSEF("dir: %u/%u guard: %u/%u blob: %u/%u\r\n",
	         rdirCount(), rdirSlots(), rdirGuardCount(), rdirGuardSlots(),
	         rdirBlobCount(), rdirBlobSlots());
}

/*static*/ void Transport::exit_handler() {
	TRACE("Transport::exit_handler()");
	if (!_owner.is_connected_to_shared_instance()) {
		persist_data();
	}
}

/*static*/ Destination Transport::find_destination_from_hash(const Bytes& destination_hash) {
	TRACEF("Transport::find_destination_from_hash: Searching for destination %s", destination_hash.toHex().c_str());
	auto iter = _destinations.find(destination_hash);
	if (iter != _destinations.end()) {
		TRACEF("Transport::find_destination_from_hash: Found destination %s", (*iter).second.toString().c_str());
		return (*iter).second;
	}

	return {Type::NONE};
}

/* The directory pool's slot count is the hard bound; this enforces the softer
 * `s.rnsd.path.max` on top of it. Ordering, budgeting and the blob demotion all
 * live in the store — it reads only in-record data, so the claim vocabulary can
 * stay outside µR entirely. */
/*static*/ void Transport::cull_path_table() {
	TRACE("Transport::cull_path_table()");
	size_t dir_target = _path_table_maxsize;
	if (dir_target > rdirSlots()) dir_target = rdirSlots();
	rdirEvictTo(dir_target, rdirBlobSlots());
}

/*static*/ size_t Transport::announce_count(bool held) {
	size_t n = 0;
	for (uint16_t i = 0; i < _announce_slots; i++) {
		const AnnounceRec& r = _announce_ring[i];
		if (!(r.flags & ANNOUNCE_F_USED)) continue;
		if (((r.flags & ANNOUNCE_F_HELD) != 0) == held) n++;
	}
	return n;
}

/*static*/ Transport::AnnounceRec* Transport::announce_find(const Bytes& destination_hash, bool held) {
	if (destination_hash.size() != Type::Reticulum::DESTINATION_LENGTH) return nullptr;
	for (uint16_t i = 0; i < _announce_slots; i++) {
		AnnounceRec& r = _announce_ring[i];
		if (!(r.flags & ANNOUNCE_F_USED)) continue;
		if (((r.flags & ANNOUNCE_F_HELD) != 0) != held) continue;
		if (memcmp(r.dest, destination_hash.data(), Type::Reticulum::DESTINATION_LENGTH) == 0) return &r;
	}
	return nullptr;
}

/* A full ring evicts its oldest entry rather than refusing the new one: the
 * newest announce is the one worth propagating. */
/*static*/ Transport::AnnounceRec* Transport::announce_alloc() {
	for (uint16_t i = 0; i < _announce_slots; i++)
		if (!(_announce_ring[i].flags & ANNOUNCE_F_USED)) return &_announce_ring[i];
	AnnounceRec* oldest = nullptr;
	for (uint16_t i = 0; i < _announce_slots; i++) {
		AnnounceRec& r = _announce_ring[i];
		if (!(r.flags & ANNOUNCE_F_USED)) continue;
		if (!oldest || r.timestamp < oldest->timestamp) oldest = &r;
	}
	if (!oldest) return nullptr;
	memset(oldest, 0, sizeof(*oldest));
	return oldest;
}

/*static*/ void Transport::announce_store(AnnounceRec* rec, const Bytes& destination_hash,
                                          const Packet& packet, double timestamp, double retransmit_at,
                                          uint8_t retries, uint8_t hops, bool block_rebroadcasts,
                                          const Interface& attached_interface) {
	if (!rec) return;
	memset(rec, 0, sizeof(*rec));
	memcpy(rec->dest, destination_hash.data(), Type::Reticulum::DESTINATION_LENGTH);
	const Bytes& data = packet.data();
	uint16_t n = (uint16_t)(data.size() > ANNOUNCE_DATA_MAX ? ANNOUNCE_DATA_MAX : data.size());
	if (n > 0) memcpy(rec->data, data.data(), n);
	rec->data_len      = n;
	rec->timestamp     = timestamp;
	rec->retransmit_at = retransmit_at;
	rec->retries       = retries;
	rec->hops          = hops;
	rec->context_flag  = (uint8_t)packet.context_flag();
	rec->flags         = ANNOUNCE_F_USED | (block_rebroadcasts ? ANNOUNCE_F_BLOCK : 0);
	/* Interfaces are named by hash prefix, not held: a handle would pin a dead
	 * impl across a reconnect, and the emitting side has to resolve by name
	 * anyway. */
	if (packet.receiving_interface()) {
		Bytes h = packet.receiving_interface().get_hash();
		if (h.size() >= Type::Reticulum::DESTINATION_LENGTH)
			memcpy(rec->recv_iface, h.data(), Type::Reticulum::DESTINATION_LENGTH);
	}
	if (attached_interface) {
		Bytes h = attached_interface.get_hash();
		if (h.size() >= Type::Reticulum::DESTINATION_LENGTH) {
			memcpy(rec->attached_iface, h.data(), Type::Reticulum::DESTINATION_LENGTH);
			rec->flags |= ANNOUNCE_F_ATTACHED;
		}
	}
}

/* Spangap deviation: a necessary condition for relaying, checked at ingress.
 *
 * A node can be structurally unable to re-broadcast anything it hears — an
 * access-point radio blocks the transport flood by design, and a point-to-point
 * interface never echoes back out what arrived on it. On such a node every
 * heard announce was still stored in the announce table and retried until its
 * retry limit, walking the full outbound path each time and refusing on every
 * interface: pure churn, refilled from the ingress faster than it drained,
 * with no yield in the walk. Suppressing the *duplicates* cannot fix that —
 * on a node bridged to a large network the announce population is orders of
 * magnitude past any pool we could hold, so essentially every announce is
 * novel and the work is proportional to the whole network's announce rate.
 * The fix has to be "do not take on work that cannot produce a packet".
 *
 * This is a NECESSARY condition, not the whole rule: it tests only the
 * structural blocks that no later state can lift (OUT, the community radius,
 * point-to-point echo). Rate caps, queue depth, and the roaming/boundary next-hop rules
 * stay where they were — they depend on state at emission time, and the
 * authoritative decision remains outbound()'s. So this never admits an
 * announce outbound() would drop for a structural reason, and never rejects
 * one outbound() might have sent. */
/*static*/ bool Transport::announce_relay_possible(const Bytes& destination_hash,
                                                   const Interface& received_on,
                                                   uint8_t hops) {
	/* Our own destinations are exempt from the community-radius block (see
	 * outbound), so they are always relayable — a trickle, not a flood. */
	if (_destinations.find(destination_hash) != _destinations.end()) return true;

	for (auto& [hash, interface] : _interfaces) {
		if (!interface.OUT()) continue;
		/* Relay work is done for the members on the egress interface: a
		 * forwarded announce is re-broadcast only within their community
		 * radius. An interface with no community (radius 0 — an uplink)
		 * relays nothing; the world reaches its members through path
		 * requests answered from custody. */
		if (hops > interface.community_radius()) continue;
		/* On a point-to-point link, echoing the announce back out
		 * the interface it came in on returns it to the one peer that has it.
		 * A medium fact, not policy — the radius has no vote here. */
		if (interface.point_to_point() && received_on &&
		    received_on.get_hash() == interface.get_hash()) continue;
		return true;
	}
	return false;
}

/* Spangap deviation: the same necessary condition, for path discovery.
 *
 * Searching on someone's behalf means forwarding their request onward, and
 * the forwarding loop excludes the interface it came in on (no echo on
 * point-to-point). When that is all of them the search reaches
 * nobody — but a `_discovery_path_requests` entry was still booked, logged,
 * and later expired, once per request, for a search that never left the node.
 * A node whose only interface is the requestor's does this for every path
 * request it is asked, which is where the expiry storm came from: the cleanup
 * was rate-limited, the work never should have existed.
 *
 * Mirrors the forwarding loop's own exclusions, and nothing else — the rest of
 * request_path()'s decisions (its point-to-point learned-on check) still apply
 * per interface at send time. */
/*static*/ bool Transport::path_search_possible(const Interface& requestor) {
	/* Searching is asymmetric with relaying, and the asymmetry is the point.
	 * Relaying is about the egress side — the members listening there.
	 * Searching is about the REQUESTOR side: we look things up on behalf of
	 * our community. A request arriving on an interface with no community
	 * (radius 0) is not our errand, however well we could run it — otherwise
	 * the wider network's discovery load lands on this node, which is exactly
	 * what being an uplink's customer must not mean. A search we do take on
	 * goes out every other interface — the answer may as well live behind
	 * the uplink as deeper in the community. */
	if (requestor && !is_local_client_interface(requestor)
	    && requestor.community_radius() == 0) return false;

	for (auto& [hash, interface] : _interfaces) {
		if (!interface.OUT()) continue;
		if (requestor && interface == requestor) continue;
		return true;
	}
	return false;
}

/*static*/ void Transport::cull_announce_table() {
	TRACE("Transport::cull_announce_table()");
	/* The ring is the hard bound; this enforces the softer s.rnsd.announce.table_max
	 * on top of it, oldest first. Allocation-free by construction — the sort
	 * index this used to build was itself an OOM risk at exactly the moment the
	 * table was full. */
	size_t target = _announce_table_maxsize;
	uint16_t count = 0;
	for (size_t n = announce_count(false) + announce_count(true); n > target; n--) {
		AnnounceRec* oldest = nullptr;
		for (uint16_t i = 0; i < _announce_slots; i++) {
			AnnounceRec& r = _announce_ring[i];
			if (!(r.flags & ANNOUNCE_F_USED)) continue;
			if (!oldest || r.timestamp < oldest->timestamp) oldest = &r;
		}
		if (!oldest) break;
		memset(oldest, 0, sizeof(*oldest));
		++count;
	}
	if (count > 0) DBGF_DEMOTE("Removed %d announce(s) from the retransmission queue", count);
}

/*static*/ uint16_t Transport::remove_reverse_entries(const std::vector<Bytes>& hashes) {
	uint16_t count = 0;
	for (const auto& truncated_packet_hash : hashes) {
		_reverse_table.erase(truncated_packet_hash);
		++count;
	}
	if (count > 0) {
		TRACEF("Released %u reverse table entries", count);
	}
	return count;
}

/*static*/ uint16_t Transport::remove_links(const std::vector<Bytes>& hashes) {
	uint16_t count = 0;
	for (const auto& link_id : hashes) {
		_link_table.erase(link_id);
		++count;
	}
	if (count > 0) {
		TRACEF("Released %u links", count);
	}
	return count;
}

/*static*/ uint16_t Transport::remove_paths(const std::vector<Bytes>& hashes) {
	uint16_t count = 0;
	for (const auto& destination_hash : hashes) {
		//_path_table.erase(destination_hash);
		remove_path(destination_hash);
		++count;
	}
	if (count > 0) {
		TRACEF("Released %u paths", count);
	}
	return count;
}

/*static*/ uint16_t Transport::remove_discovery_path_requests(const std::vector<Bytes>& hashes) {
	uint16_t count = 0;
	for (const auto& destination_hash : hashes) {
		_discovery_path_requests.erase(destination_hash);
		++count;
	}
	if (count > 0) {
		TRACEF("Released %u waiting path requests", count);
	}
	return count;
}

/*static*/ uint16_t Transport::remove_tunnels(const std::vector<Bytes>& hashes) {
	uint16_t count = 0;
	for (const auto& tunnel_id : hashes) {
		_tunnels.erase(tunnel_id);
		++count;
	}
	if (count > 0) {
		TRACEF("Released %u tunnels", count);
	}
	return count;
}
