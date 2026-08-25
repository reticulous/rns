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

#include "Packet.h"
#include "Bytes.h"
#include "Type.h"
#include "Utilities/Memory.h"
#include "Persistence/DestinationEntry.h"
#include "Directory.h"

#include <map>
#include <vector>
#include <list>
#include <set>
#include <array>
#include <memory>
#include <functional>
#include <stdint.h>

#ifndef RNS_LEAN_PATH_TABLE
	#define RNS_LEAN_PATH_TABLE 1
#endif

using namespace RNS::Persistence;

namespace RNS {

	class Reticulum;
	class Identity;
	class Destination;
	class Interface;
	class Link;
	class Packet;
	class PacketReceipt;

	class AnnounceHandler {
	public:
		// The initialisation method takes the optional
		// aspect_filter argument. If aspect_filter is set to
		// None, all announces will be passed to the instance.
		// If only some announces are wanted, it can be set to
		// an aspect string.
		AnnounceHandler(const char* aspect_filter = nullptr);
		virtual ~AnnounceHandler() {}
		// This method will be called by Reticulums Transport
		// system when an announce arrives that matches the
		// configured aspect filter. Filters must be specific,
		// and cannot use wildcards.
		//
		// `name_hash` is the aspect hash the announce itself carries — a pure
		// function of the aspect text, independent of who announced. Handlers
		// that classify announces compare against a value precomputed once,
		// rather than hashing per announce.
		//
		// `hops` is the announce's own hop count. It is passed rather than
		// looked up because a handler runs for every announce, while a route is
		// only stored for the ones this node retains — asking the routing layer
		// would report "unreachable" for everything heard on an interface that
		// forwards without keeping.
		virtual void received_announce(const Bytes& destination_hash, const Identity& announced_identity, const Bytes& app_data, const Bytes& name_hash, uint8_t hops) = 0;
		std::string& aspect_filter() { return _aspect_filter; }
		// The aspect filter compiled to its name hash, once, at construction.
		const Bytes& name_hash_filter() const { return _name_hash_filter; }
	private:
		std::string _aspect_filter;
		Bytes _name_hash_filter;
	};
	using HAnnounceHandler = std::shared_ptr<AnnounceHandler>;

    /*
    Through static methods of this class you can interact with the
    Transport system of Reticulum.
    */
	class Transport {

	public:

		using InterfaceTable = std::map<Bytes, Interface>;
		using DestinationTable = std::map<Bytes, Destination>;

		class Callbacks {
		public:
			using receive_packet = void(*)(const Bytes& raw, const Interface& interface);
			using transmit_packet = void(*)(const Bytes& raw, const Interface& interface);
			using filter_packet = bool(*)(const Packet& packet);
		public:
			receive_packet _receive_packet = nullptr;
			transmit_packet _transmit_packet = nullptr;
			filter_packet _filter_packet = nullptr;
		friend class Transport;
		};

		class PacketEntry {
		public:
			PacketEntry() {}
			PacketEntry(const Bytes& raw, double sent_at, const Bytes& destination_hash) :
				_raw(raw),
				_sent_at(sent_at),
				_destination_hash(destination_hash)
			{
			}
			PacketEntry(const Packet& packet) :
				_raw(packet.raw()),
				_sent_at(packet.sent_at()),
				_destination_hash(packet.destination_hash())
			{
			}
		public:
			Bytes _raw;
			double _sent_at = 0;
			Bytes _destination_hash;
			bool _cached = false;
#ifndef NDEBUG
			inline std::string debugString() const {
				std::string dump;
				dump = "PacketEntry: destination_hash=" + _destination_hash.toHex() +
					" sent_at=" + std::to_string(_sent_at);
				return dump;
			}
#endif
		};
		using PacketTable = std::map<Bytes, PacketEntry>;

		/* The announce retransmission queue.
		 *
		 * This is a work queue, not a cache: an entry exists to be emitted a
		 * bounded number of times and then leave. That is why it keeps its own
		 * storage rather than referencing the directory's blob pool — the two
		 * hold opposite sets. An announce lands here when we are FORWARDING for
		 * someone else, which on a gateway is exactly the traffic the retention
		 * policy declines to keep; and blob slots are evicted under pressure at
		 * any moment, which a queue entry cannot survive.
		 *
		 * One fixed-slot ring, allocated once. Each record carries the announce
		 * payload inline and names its interfaces by hash prefix instead of
		 * holding handles, so an entry costs a flat `sizeof(AnnounceRec)` with
		 * no allocation, no map nodes, and nothing to run out of mid-burst. The
		 * `Packet` copies this replaced held nine separate `Bytes` each, every
		 * one of them its own heap block.
		 *
		 * The data field is sized so an announce is never refused: the largest
		 * payload that can reach us is one MTU minus the biggest header. */
		static constexpr size_t ANNOUNCE_DATA_MAX =
			((Type::Reticulum::MTU - Type::Reticulum::HEADER_MAXSIZE) + 3) & ~(size_t)3;

		enum : uint8_t {
			ANNOUNCE_F_USED     = 0x01,
			ANNOUNCE_F_BLOCK    = 0x02,  /* block_rebroadcasts: emit as PATH_RESPONSE */
			ANNOUNCE_F_ATTACHED = 0x04,  /* attached_iface names one interface, else all */
			/* An announce that arrived while a path request for the same
			 * destination was being served waits here and is re-armed once the
			 * response has gone out. A flag, not a second table: the only thing
			 * that ever differed was which of the two was due next. */
			ANNOUNCE_F_HELD     = 0x08,
		};

#pragma pack(push, 1)
		struct AnnounceRec {
			uint8_t  dest[Type::Reticulum::DESTINATION_LENGTH];
			uint8_t  recv_iface[Type::Reticulum::DESTINATION_LENGTH];
			uint8_t  attached_iface[Type::Reticulum::DESTINATION_LENGTH];
			double   timestamp;        /* insertion time; cull ordering */
			double   retransmit_at;    /* kept a double: the path-request grace is
			                            * sub-second and must not round to zero */
			uint16_t data_len;
			uint8_t  retries;
			uint8_t  hops;
			uint8_t  local_rebroadcasts;
			uint8_t  flags;
			uint8_t  context_flag;
			uint8_t  pad;
			uint8_t  data[ANNOUNCE_DATA_MAX];
		};
#pragma pack(pop)

		// CBA TODO Analyze safety of using Inrerface references here
		class LinkEntry {
		public:
			LinkEntry(double timestamp, const Bytes& next_hop, const Interface& outbound_interface, uint8_t remaining_hops, const Interface& receiving_interface, uint8_t hops, const Bytes& destination_hash, bool validated, double proof_timeout) :
				_timestamp(timestamp),
				_next_hop(next_hop),
				_outbound_interface(outbound_interface),
				_remaining_hops(remaining_hops),
				_receiving_interface(receiving_interface),
				_hops(hops),
				_destination_hash(destination_hash),
				_validated(validated),
				_proof_timeout(proof_timeout)
			{
			}
		public:
			double _timestamp = 0;
			const Bytes _next_hop;
			const Interface _outbound_interface = {Type::NONE};
			uint8_t _remaining_hops = 0;
			Interface _receiving_interface = {Type::NONE};
			uint8_t _hops = 0;
			const Bytes _destination_hash;
			bool _validated = false;
			double _proof_timeout = 0;
		};
		using LinkTable = std::map<Bytes, LinkEntry>;

		// CBA TODO Analyze safety of using Inrerface references here
		class ReverseEntry {
		public:
			ReverseEntry(const Interface& receiving_interface, const Interface& outbound_interface, double timestamp) :
				_receiving_interface(receiving_interface),
				_outbound_interface(outbound_interface),
				_timestamp(timestamp)
			{
			}
		public:
			Interface _receiving_interface = {Type::NONE};
			const Interface _outbound_interface = {Type::NONE};
			double _timestamp = 0;
		};
		using ReverseTable = std::map<Bytes, ReverseEntry>;

		// CBA TODO Analyze safety of using Inrerface references here
		class PathRequestEntry {
		public:
			PathRequestEntry(const Bytes& destination_hash, double timeout, const Interface& requesting_interface) :
				_destination_hash(destination_hash),
				_timeout(timeout),
				_requesting_interface(requesting_interface)
			{
			}
		public:
			const Bytes _destination_hash;
			double _timeout = 0;
			const Interface _requesting_interface = {Type::NONE};
		};
		using PathRequestTable = std::map<Bytes, PathRequestEntry>;

/*
		// CBA TODO Analyze safety of using Inrerface references here
		class SerialisedEntry {
		public:
			SerialisedEntry(const Bytes& destination_hash, double timestamp, const Bytes& received_from, uint8_t announce_hops, double expires, const std::set<Bytes>& random_blobs, Interface& receiving_interface, const Packet& packet) :
				_destination_hash(destination_hash),
				_timestamp(timestamp),
				_hops(announce_hops),
				_expires(expires),
				_random_blobs(random_blobs),
				_receiving_interface(receiving_interface),
				_announce_packet(packet)
			{
			}
		public:
			const Bytes _destination_hash;
			double _timestamp = 0;
			const Bytes _received_from;
			uint8_t _hops = 0;
			double _expires = 0;
			std::set<Bytes> _random_blobs;
			Interface _receiving_interface = {Type::NONE};
			Packet _announce_packet = {Type::NONE};
		};
*/

		// CBA TODO Analyze safety of using Inrerface references here
		class TunnelEntry {
		public:
			TunnelEntry(const Bytes& tunnel_id, const Bytes& interface_hash, double expires) :
				_tunnel_id(tunnel_id),
				_interface_hash(interface_hash),
				_expires(expires)
			{
			}
		public:
			const Bytes _tunnel_id;
			const Bytes _interface_hash;
			PathTable _serialised_paths;
			double _expires = 0;
		};
		using TunnelTable = std::map<Bytes, TunnelEntry>;

		class RateEntry {
		public:
			RateEntry(double now) :
				_last(now)
			{
				_timestamps.push_back(now);
			}
		public:
			double _last = 0.0;
			double _rate_violations = 0.0;
			double _blocked_until = 0.0;
			std::vector<double> _timestamps;
		};
		using RateTable = std::map<Bytes, RateEntry>;

	public:
		static void start(const Reticulum& reticulum_instance);
		static void loop();
		static void jobs();
		static void transmit(Interface& interface, const Bytes& raw);
		static bool outbound(Packet& packet);
		static bool packet_filter(const Packet& packet);
		//static void inbound(const Bytes& raw, const Interface& interface = {Type::NONE});
		static void inbound(const Bytes& raw, const Interface& interface);
		static void inbound(const Bytes& raw);
		static void synthesize_tunnel(const Interface& interface);
		static void tunnel_synthesize_handler(const Bytes& data, const Packet& packet);
		static void handle_tunnel(const Bytes& tunnel_id, const Interface& interface);
		static void register_interface(Interface& interface);
		static void deregister_interface(const Interface& interface);
		// Derive and install IFAC (Interface Access Codes) on an interface from a
		// network_name + passphrase (netkey), byte-compatible with upstream RNS.
		// No-op when both strings are empty (interface stays open/non-IFAC).
		static void derive_ifac(Interface& interface, const std::string& network_name,
		                        const std::string& passphrase,
		                        uint16_t ifac_size = Type::Reticulum::IFAC_MIN_SIZE);
		inline static InterfaceTable& get_interfaces() { return _interfaces; }
		static void register_destination(Destination& destination);
		static void deregister_destination(const Destination& destination);
		static void register_link(Link& link);
		static void activate_link(Link& link);
		static void register_announce_handler(HAnnounceHandler handler);
		static void deregister_announce_handler(HAnnounceHandler handler);
		static bool is_interface_from_hash(const Bytes& interface_hash);
		static Interface find_interface_from_hash(const Bytes& interface_hash);
		/* An interface hash is a full SHA-256, but the directory record carries
		 * only its first 16 bytes — an interface table holds a handful of
		 * entries, so half a hash separates them with room to spare. */
		static Interface find_interface_from_hash_prefix(const uint8_t prefix[RDIR_DEST_LEN]);
		static bool should_cache_packet(const Packet& packet);
		static bool cache_packet(const Packet& packet, bool force_cache = false);
		static bool is_cached_packet(const Bytes& packet_hash);
		static Packet get_cached_packet(const Bytes& packet_hash);
		static bool clear_cached_packet(const Bytes& packet_hash);
		static bool cache_request_packet(const Packet& packet);
		static void cache_request(const Bytes& packet_hash, const Destination& destination);
		/* Routing now lives in the directory pool (Directory.h). This is the
		 * one accessor that turns a stored record into something usable: it
		 * copies the route out, resolves the receiving interface, and — when
		 * the stored iface_hash no longer resolves, which happens whenever an
		 * interface re-registers — clears the record's routing fields and
		 * reports a miss, so the caller path-requests instead of black-holing.
		 * Writer-task only, because of that clear. */
		static bool peek_live_route(const Bytes& destination_hash, rdir_route_t& route, Interface& outbound_interface);
		/* The lifetime a path learned on (or used over) this interface gets,
		 * from the runtime-tunable TTLs. A destination inside the interface's
		 * community (hops <= community_radius) gets the custody lifetime. */
		static uint32_t path_ttl_for(const Interface& interface, uint8_t hops);
		static bool remove_path(const Bytes& destination_hash);
		static bool has_path(const Bytes& destination_hash);
		static uint8_t hops_to(const Bytes& destination_hash);
		static Bytes next_hop(const Bytes& destination_hash);
		static Interface next_hop_interface(const Bytes& destination_hash);
		static uint32_t next_hop_interface_bitrate(const Bytes& destination_hash);
		static uint16_t next_hop_interface_hw_mtu(const Bytes& destination_hash);
		static double next_hop_per_bit_latency(const Bytes& destination_hash);
		static double next_hop_per_byte_latency(const Bytes& destination_hash);
		static double first_hop_timeout(const Bytes& destination_hash);
		static double extra_link_proof_timeout(const Interface& interface);
		static bool expire_path(const Bytes& destination_hash);
		//static void request_path(const Bytes& destination_hash, const Interface& on_interface = {Type::NONE}, const Bytes& tag = {}, bool recursive = false);
		static void request_path(const Bytes& destination_hash, const Interface& on_interface, const Bytes& tag = {}, bool recursive = false);
		static void request_path(const Bytes& destination_hash);
		static void path_request_handler(const Bytes& data, const Packet& packet);
		static void path_request(const Bytes& destination_hash, bool is_from_local_client, const Interface& attached_interface, const Bytes& requestor_transport_id = {}, const Bytes& tag = {});
		static bool from_local_client(const Packet& packet);
		static bool is_local_client_interface(const Interface& interface);
		static bool interface_to_shared_instance(const Interface& interface);
		static void detach_interfaces();
		static void shared_connection_disappeared();
		static void shared_connection_reappeared();
		static void drop_announce_queues();
		static uint64_t announce_emitted(const Packet& packet);
		static void write_packet_hashlist();
		static bool read_path_table();
		static bool write_path_table();
		static void read_tunnel_table();
		static void write_tunnel_table();
		static void persist_data();
		static void clean_caches();
		static void dump_stats();
		static void exit_handler();

		static uint16_t remove_reverse_entries(const std::vector<Bytes>& hashes);
		static uint16_t remove_links(const std::vector<Bytes>& hashes);
		static uint16_t remove_paths(const std::vector<Bytes>& hashes);
		static uint16_t remove_discovery_path_requests(const std::vector<Bytes>& hashes);
		static uint16_t remove_tunnels(const std::vector<Bytes>& hashes);

		static Destination find_destination_from_hash(const Bytes& destination_hash);

		// CBA
		static void cull_path_table();
		static void cull_announce_table();
		static size_t announce_count(bool held);
		static AnnounceRec* announce_find(const Bytes& destination_hash, bool held);
		static AnnounceRec* announce_alloc();
		static void announce_store(AnnounceRec* rec, const Bytes& destination_hash,
		                           const Packet& packet, double timestamp, double retransmit_at,
		                           uint8_t retries, uint8_t hops, bool block_rebroadcasts,
		                           const Interface& attached_interface);
		/* Could a re-broadcast of this announce leave the node on ANY interface?
		 * A cheap necessary condition checked before the announce table is
		 * touched — see the definition for why it is not the whole rule. */
		static bool announce_relay_possible(const Bytes& destination_hash,
		                                    const Interface& received_on,
		                                    uint8_t hops);
		/* Could a forwarded path request reach any interface at all? Same
		 * necessary condition, checked before a discovery entry is booked. */
		static bool path_search_possible(const Interface& requestor);

		/* Cheapest-first discovery. A path request we originate is our own
		 * errand, so no transit policy suppresses it — but it need not cost
		 * airtime to find out that the cheap link knew the answer all along. */
		static bool interface_is_cheap(const Interface& interface);
		static void escalate_path_requests(double now);

		static constexpr uint16_t PATH_ESCALATIONS_MAX = 16;
		struct PathEscalation {
			uint8_t dest[Type::Reticulum::DESTINATION_LENGTH];
			double  due;
			bool    used;
		};

		// getters/setters
		static inline void set_receive_packet_callback(Callbacks::receive_packet callback) { _callbacks._receive_packet = callback; }
		static inline void set_transmit_packet_callback(Callbacks::transmit_packet callback) { _callbacks._transmit_packet = callback; }
		static inline void set_filter_packet_callback(Callbacks::filter_packet callback) { _callbacks._filter_packet = callback; }
		static inline const Reticulum& reticulum() { return _owner; }
		static inline const Identity& identity() { return _identity; }
		inline static uint16_t path_table_maxsize() { return _path_table_maxsize; }
		/* A soft target below the directory pool's own slot count, enforced by
		 * cull_path_table() at the announce-insert site. The pool size is the
		 * hard bound; this lets an operator hold the resident set lower. */
		inline static void path_table_maxsize(uint16_t path_table_maxsize) { _path_table_maxsize = path_table_maxsize; }
		inline static uint16_t announce_table_maxsize() { return _announce_table_maxsize; }
		inline static void announce_table_maxsize(uint16_t announce_table_maxsize) { _announce_table_maxsize = announce_table_maxsize; }
		inline static uint16_t hashlist_maxsize() { return _hashlist_maxsize; }
		inline static void hashlist_maxsize(uint16_t hashlist_maxsize) { _hashlist_maxsize = hashlist_maxsize; }
		inline static uint16_t max_pr_tags() { return _max_pr_tags; }
		inline static void max_pr_tags(uint16_t max_pr_tags) { _max_pr_tags = max_pr_tags; }
		inline static uint16_t path_table_maxpersist() { return _path_table_maxpersist; }
		inline static void path_table_maxpersist(uint16_t value) { _path_table_maxpersist = value; }
		// Spangap: runtime-tunable path-entry TTLs (seconds). Written into the
		// directory record's `expires` at ingest; govern age-based path expiry.
		inline static uint32_t destination_timeout() { return _destination_timeout; }
		inline static void destination_timeout(uint32_t value) { _destination_timeout = value; }
		inline static uint32_t ap_path_time() { return _ap_path_time; }
		inline static void ap_path_time(uint32_t value) { _ap_path_time = value; }
		/* Lifetime for destinations reached via an interface we route for. */
		inline static uint32_t custody_path_time() { return _custody_path_time; }
		inline static void custody_path_time(uint32_t value) { _custody_path_time = value; }
		inline static uint32_t path_escalate_time() { return _path_escalate_time; }
		inline static void path_escalate_time(uint32_t value) { _path_escalate_time = value; }
		inline static uint32_t path_cheap_bitrate() { return _path_cheap_bitrate; }
		inline static void path_cheap_bitrate(uint32_t value) { _path_cheap_bitrate = value; }
		inline static uint32_t roaming_path_time() { return _roaming_path_time; }
		inline static void roaming_path_time(uint32_t value) { _roaming_path_time = value; }
		// Spangap: runtime-tunable jobs() cadence (seconds).
		inline static float job_interval() { return _job_interval; }
		inline static void job_interval(float value) { _job_interval = value; }
		inline static float tables_cull_interval() { return _tables_cull_interval; }
		inline static void tables_cull_interval(float value) { _tables_cull_interval = value; }
		// CBA TEST
		static inline void identity(Identity& identity) { _identity = identity; }

		inline static const PathTable& get_path_table() { return _path_table; }
		inline static const RateTable& get_announce_rate_table() { return _announce_rate_table; }
		inline static const LinkTable& get_link_table() { return _link_table; }

		// Spangap: size getters for the Link-state tables, used by rnsd's
		// `rnsd links` CLI / 1Hz stats publish to surface leaks during Phase B
		// Link bringup. Read-only; std::set::size() is an atomic counter load
		// on supported platforms, and a slightly-stale count is fine for the
		// leak-detection use case.
		inline static size_t pending_links_count() { return _pending_links.size(); }
		inline static size_t active_links_count()  { return _active_links.size(); }

		// Spangap: table-size + stat getters for the `rnsd memory` breakdown.
		inline static size_t path_table_size()     { return rdirCount(); }
		inline static size_t announce_table_size() { return announce_count(false); }
		inline static size_t held_announces_size() { return announce_count(true); }
		inline static size_t announce_table_slots() { return _announce_slots; }
		inline static size_t announce_queue_bytes() { return (size_t)_announce_slots * sizeof(AnnounceRec); }
		inline static size_t hashlist_size()       { return _packet_hashlist.size(); }
		inline static size_t reverse_table_size()  { return _reverse_table.size(); }
		inline static size_t link_table_size()     { return _link_table.size(); }
		inline static size_t tunnels_count()       { return _tunnels.size(); }
		inline static size_t path_requests_count() { return _path_requests.size(); }
		inline static size_t destinations_count()  { return _destinations.size(); }
		inline static size_t interfaces_count()    { return _interfaces.size(); }
		inline static size_t pr_tags_count()       { return _discovery_pr_tags.size(); }
		inline static uint32_t destinations_added(){ return _destinations_added; }
		inline static uint32_t packets_sent()      { return _packets_sent; }
		inline static uint32_t packets_received()  { return _packets_received; }

	private:
		// CBA MUST use references to interfaces here in order for virtul overrides for send/receive to work
		// map is sorted, can use find
		static InterfaceTable _interfaces;			// All active interfaces
		static DestinationTable _destinations;		// All active destinations
		// CBA TODO: Reconsider using std::set for enforcing uniqueness. Maybe consider std::map keyed on hash instead
		static std::set<Link> _pending_links;		// Links that are being established
		static std::set<Link> _active_links;		// Links that are active
		static std::set<Bytes> _packet_hashlist;	// A list of packet hashes for duplicate detection
		static std::list<PacketReceipt> _receipts;	// Receipts of all outgoing packets for proof processing

		static AnnounceRec* _announce_ring;		// Announces waiting to be retransmitted
		static uint16_t _announce_slots;		// Ring capacity, fixed at start()
		static PathTable _path_table;			// A lookup table containing the next hop to a given destination
		static ReverseTable _reverse_table;		// A lookup table for storing packet hashes used to return proofs and replies
		static LinkTable _link_table;			// A lookup table containing hops for links
		static TunnelTable _tunnels;			// A table storing tunnels to other transport instances
		static RateTable _announce_rate_table;	// A table for keeping track of announce rates
		static std::set<HAnnounceHandler> _announce_handlers;	// A table storing externally registered announce handlers
		static std::map<Bytes, double> _path_requests;	// A table for storing path request timestamps

		static PathRequestTable _discovery_path_requests;	// A table for keeping track of path requests on behalf of other nodes
		static std::set<Bytes> _discovery_pr_tags;	// A table for keeping track of tagged path requests
		static std::list<Bytes> _discovery_pr_tags_order;	// insertion order for FIFO eviction of _discovery_pr_tags (std::set orders by content, not recency)

		// Transport control destinations are used
		// for control purposes like path requests
		static std::set<Destination> _control_destinations;
		static std::set<Bytes> _control_hashes;

		// Interfaces for communicating with
		// local clients connected to a shared
		// Reticulum instance
		//static std::set<Interface> _local_client_interfaces;
		static std::set<std::reference_wrapper<const Interface>, std::less<const Interface>> _local_client_interfaces;

		static std::map<Bytes, const Interface> _pending_local_path_requests;

		// CBA
		static PacketTable _packet_table;           // A lookup table containing announce packets for known paths

		//z _local_client_rssi_cache    = []
		//z _local_client_snr_cache     = []
		static uint16_t _LOCAL_CLIENT_CACHE_MAXSIZE;

		static double _start_time;
		static bool _jobs_locked;
		static bool _jobs_running;
		static float _job_interval;
		static double _jobs_last_run;
		static double _links_last_checked;
		static float _links_check_interval;
		static double _receipts_last_checked;
		static float _receipts_check_interval;
		static double _announces_last_checked;
		static float _announces_check_interval;
		static double _tables_last_culled;
		static float _tables_cull_interval;
		static bool _saving_path_table;
		static uint16_t _hashlist_maxsize;
		static uint16_t _max_pr_tags;

		// CBA
		static uint16_t _path_table_maxsize;
		static uint16_t _path_table_maxpersist;
		static double _last_saved;
		static float _save_interval;
		static uint32_t _path_table_crc;
		static uint16_t _announce_table_maxsize;
		// Spangap: runtime-tunable path TTLs (seeded from Type::Transport)
		static uint32_t _destination_timeout;
		static uint32_t _ap_path_time;
		static uint32_t _custody_path_time;
		static PathEscalation _path_escalations[PATH_ESCALATIONS_MAX];
		static uint32_t _path_escalate_time;    /* s.rnsd.path.escalate_s */
		static uint32_t _path_cheap_bitrate;    /* s.rnsd.path.cheap_bps  */
		static uint32_t _roaming_path_time;

		static Reticulum _owner;
		static Identity _identity;

		// CBA
		static Callbacks _callbacks;

		// CBA Stats
		static uint32_t _packets_sent;
		static uint32_t _packets_received;
		static uint32_t _destinations_added;
		static size_t _last_memory;
		static size_t _last_psram;
		static size_t _last_flash;

		// CBA Block re-entrance
		static bool cleaning_caches;
	};

	template <typename M, typename S> 
	void MapToValues(const M& m, S& s) {
		for (typename M::const_iterator it = m.begin(); it != m.end(); ++it) {
			s.insert(it->second);
		}
	}

	template <typename M, typename S> 
	void MapToPairs(const M& m, S& s) {
		for (typename M::const_iterator it = m.begin(); it != m.end(); ++it) {
			s.push_back(*it);
		}
	}
}
