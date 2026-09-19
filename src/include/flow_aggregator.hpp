#pragma once

#include "packet_decoder.hpp"
#include "tcp_reassembly.hpp"
#include <map>
#include <set>
#include <string>
#include <tuple>

namespace packetquapture {
struct FlowEndpoint {
	std::array<uint8_t, 16> ip {};
	uint16_t port = 0;
	bool operator<(const FlowEndpoint &other) const;
	bool operator==(const FlowEndpoint &other) const;
};
struct SessionKey {
	uint32_t interface_id = 0;
	uint8_t ip_version = 0, protocol = 0, vlan_count = 0;
	std::array<uint16_t, 8> vlans {};
	FlowEndpoint low, high;
	bool operator<(const SessionKey &other) const;
};
struct FlowInput {
	uint32_t section = 0, interface_id = 0;
	uint32_t captured_length = 0, original_length = 0;
	PacketStamp stamp;
	DecodedPacket packet;
};
struct FlowCounters {
	uint64_t packets = 0, captured_bytes = 0, reported_bytes = 0, payload_bytes = 0;
	uint16_t flags = 0;
};
struct FlowSummary {
	SessionKey key;
	uint32_t section = 0;
	uint64_t first_packet = 0, last_packet = 0;
	bool orig_is_low = true, has_timestamp = false;
	int64_t first_timestamp = 0, last_timestamp = 0;
	uint64_t missing_timestamps = 0, late_packets = 0;
	FlowCounters orig, resp;
	bool handshake_complete = false, simultaneous_open = false, equal_endpoints = false;
	bool syn_seen = false, fin_seen = false, reset_seen = false;
	std::string originator_basis, finalized_by;
};
struct FlowLimits {
	int64_t tcp_idle_us = 300000000, udp_idle_us = 60000000;
	size_t max_flows = 16384, max_scopes = 65536;
};
// One input occurrence, capture order, no payload storage. Push one record and
// call Next until false before pushing another. Each Next emits at most one row.
// Finish also drains one row at a time. Scope clocks include ineligible records.
class FlowAggregator {
public:
	explicit FlowAggregator(FlowLimits limits = FlowLimits());
	void Push(FlowInput input);
	void Finish(uint32_t final_section);
	bool Next(FlowSummary &output);
	size_t ActiveCount() const;
	size_t ExpiryCount() const;
	static size_t StateSize();

private:
	struct State {
		FlowSummary row;
		bool syn[2] = {false, false}, syn_ack[2] = {false, false};
		uint32_t sequence[2] = {0, 0};
		bool scheduled = false, handshake_closed = false;
		int64_t deadline = 0;
	};
	struct Scope {
		bool has_watermark = false;
		int64_t watermark = 0;
		std::set<std::pair<int64_t, SessionKey>> expiry;
	};
	using States = std::map<SessionKey, State>;
	void Unschedule(State &state);
	void Schedule(State &state);
	bool Emit(States::iterator it, const char *reason, FlowSummary &output);
	void Account(State &state, bool from_low);
	FlowLimits limits;
	States states;
	std::map<uint32_t, Scope> scopes;
	FlowInput pending_input;
	bool pending = false;
	uint32_t section = 0, final_section = 0;
	bool have_section = false, prepared = false, late = false, finishing = false;
};
} // namespace packetquapture
