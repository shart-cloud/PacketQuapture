#include "flow_aggregator.hpp"

#include "pq_assert.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace packetquapture {
bool FlowEndpoint::operator<(const FlowEndpoint &other) const {
	return std::tie(ip, port) < std::tie(other.ip, other.port);
}
bool FlowEndpoint::operator==(const FlowEndpoint &other) const {
	return ip == other.ip && port == other.port;
}
bool SessionKey::operator<(const SessionKey &other) const {
	return std::tie(interface_id, ip_version, protocol, vlan_count, vlans, low, high) <
	       std::tie(other.interface_id, other.ip_version, other.protocol, other.vlan_count, other.vlans, other.low,
	                other.high);
}
static void AddChecked(uint64_t &target, uint64_t amount) {
	if (amount > std::numeric_limits<uint64_t>::max() - target) {
		throw std::overflow_error("Flow counter exceeds UBIGINT capacity");
	}
	target += amount;
}
FlowAggregator::FlowAggregator(FlowLimits limits_p) : limits(limits_p) {
	if (limits.tcp_idle_us < 0 || limits.udp_idle_us < 0 || !limits.max_flows || !limits.max_scopes) {
		throw std::invalid_argument("Invalid flow limits");
	}
}
void FlowAggregator::Push(FlowInput input) {
	if (pending || finishing) {
		throw std::logic_error("Drain flow output before pushing another record");
	}
	if (!input.stamp.number) {
		throw std::invalid_argument("Invalid flow packet number");
	}
	pending_input = std::move(input);
	pending = true;
	prepared = false;
}
void FlowAggregator::Finish(uint32_t final_section_p) {
	if (pending) {
		throw std::logic_error("Drain flow output before Finish");
	}
	finishing = true;
	final_section = final_section_p;
}
size_t FlowAggregator::ActiveCount() const {
	return states.size();
}
size_t FlowAggregator::ExpiryCount() const {
	size_t count = 0;
	for (const auto &scope : scopes) {
		count += scope.second.expiry.size();
	}
	return count;
}
size_t FlowAggregator::StateSize() {
	return sizeof(State);
}
void FlowAggregator::Unschedule(State &state) {
	if (state.scheduled) {
		const auto erased = scopes.at(state.row.key.interface_id).expiry.erase({state.queued, state.row.key});
		PQ_ASSERT(erased == 1);
		state.scheduled = false;
	}
}
// Called after every packet a session accounts. Its deadline only moves later
// (last_timestamp is a maximum), so a queued session keeps its entry and only
// records the new deadline; Refresh moves the entry once it reaches the front.
// Moving it here cost an erase and an insert per packet.
void FlowAggregator::Schedule(State &state) {
	const auto timeout = state.row.key.protocol == 6 ? limits.tcp_idle_us : limits.udp_idle_us;
	if (!timeout || state.row.missing_timestamps || !state.row.has_timestamp ||
	    state.row.last_timestamp > std::numeric_limits<int64_t>::max() - timeout) {
		Unschedule(state);
		return;
	}
	const auto deadline = state.row.last_timestamp + timeout;
	if (state.scheduled) {
		PQ_ASSERT(deadline >= state.deadline);
		state.deadline = deadline;
		return;
	}
	state.deadline = state.queued = deadline;
	scopes.at(state.row.key.interface_id).expiry.emplace(deadline, state.row.key);
	state.scheduled = true;
}
// Re-queues stale entries at the front at their sessions' real deadlines, so the
// front is the session that truly expires first. Each entry moves at most once
// per call before its real deadline orders it.
void FlowAggregator::Refresh(Scope &scope) {
	while (!scope.expiry.empty()) {
		const auto entry = *scope.expiry.begin();
		auto it = states.find(entry.second);
		PQ_ASSERT(it != states.end());
		auto &state = it->second;
		PQ_ASSERT(state.scheduled);
		PQ_ASSERT(state.queued == entry.first);
		if (state.deadline == entry.first) {
			return;
		}
		PQ_ASSERT(state.deadline > entry.first);
		scope.expiry.erase(scope.expiry.begin());
		scope.expiry.emplace(state.deadline, entry.second);
		state.queued = state.deadline;
	}
}
// The session to give up when the table is full: the one nearest its idle
// deadline on this packet's interface, else on any interface, else (when none can
// expire, for want of timestamps or a timeout) the first in key order.
FlowAggregator::States::iterator FlowAggregator::Evictable(uint32_t interface_id) {
	PQ_ASSERT(!states.empty());
	const std::pair<int64_t, SessionKey> *soonest = nullptr;
	auto scope = scopes.find(interface_id);
	if (scope != scopes.end() && !scope->second.expiry.empty()) {
		Refresh(scope->second);
		soonest = &*scope->second.expiry.begin();
	} else {
		for (auto &entry : scopes) {
			Refresh(entry.second);
			if (!entry.second.expiry.empty() && (soonest == nullptr || *entry.second.expiry.begin() < *soonest)) {
				soonest = &*entry.second.expiry.begin();
			}
		}
	}
	if (soonest == nullptr) {
		return states.begin();
	}
	auto it = states.find(soonest->second);
	PQ_ASSERT(it != states.end());
	return it;
}

bool FlowAggregator::Emit(States::iterator it, const char *reason, FlowSummary &output) {
	PQ_ASSERT(it != states.end());
	Unschedule(it->second);
	it->second.row.finalized_by = reason;
	output = std::move(it->second.row);
	states.erase(it);
	return true;
}
void FlowAggregator::Account(State &state, bool from_low) {
	const auto &input = pending_input;
	const auto &p = input.packet;
	auto &row = state.row;
	const bool orig = from_low == row.orig_is_low;
	auto &counts = orig ? row.orig : row.resp;
	AddChecked(counts.packets, 1);
	AddChecked(counts.captured_bytes, input.captured_length);
	AddChecked(counts.reported_bytes, input.original_length);
	AddChecked(counts.payload_bytes, p.payload_length);
	row.last_packet = input.stamp.number;
	if (input.stamp.has_timestamp) {
		row.first_timestamp =
		    row.has_timestamp ? std::min(row.first_timestamp, input.stamp.timestamp) : input.stamp.timestamp;
		row.last_timestamp =
		    row.has_timestamp ? std::max(row.last_timestamp, input.stamp.timestamp) : input.stamp.timestamp;
		row.has_timestamp = true;
		if (late) {
			AddChecked(row.late_packets, 1);
		}
	} else {
		AddChecked(row.missing_timestamps, 1);
	}
	if (p.tcp) {
		counts.flags |= p.tcp_flags;
		if (!(p.tcp_flags & TCP_SYN) && ((p.tcp_flags & TCP_ACK) || p.payload_length)) {
			state.handshake_closed = true;
		}
		row.syn_seen |= (p.tcp_flags & TCP_SYN) != 0;
		row.fin_seen |= (p.tcp_flags & TCP_FIN) != 0;
		row.reset_seen |= (p.tcp_flags & TCP_RST) != 0;
		const size_t side = orig ? 0 : 1, other = 1 - side;
		if ((p.tcp_flags & (TCP_SYN | TCP_ACK)) == TCP_SYN) {
			if (state.syn[other]) {
				row.simultaneous_open = true;
			}
			state.syn[side] = true;
			state.sequence[side] = p.tcp_seq;
		} else if ((p.tcp_flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK)) {
			if (state.syn[other] && p.tcp_ack == state.sequence[other] + uint32_t(1)) {
				state.syn_ack[side] = true;
				state.sequence[side] = p.tcp_seq;
			}
		} else if ((p.tcp_flags & TCP_ACK) && state.syn[side] && state.syn_ack[other] &&
		           p.tcp_ack == state.sequence[other] + uint32_t(1) &&
		           p.tcp_seq == state.sequence[side] + uint32_t(1)) {
			row.handshake_complete = true;
		}
	}
}
// The session key of an eligible packet, with its endpoints in canonical order;
// from_low says whether the packet travels from the low endpoint.
static SessionKey MakeKey(const FlowInput &input, bool &from_low) {
	const auto &p = input.packet;
	SessionKey key;
	key.interface_id = input.interface_id;
	key.ip_version = p.ip_version;
	key.protocol = p.tcp ? 6 : 17;
	static_assert(VlanStack::CAPACITY == std::tuple_size<decltype(key.vlans)>::value, "a session key holds any stack");
	key.vlan_count = static_cast<uint8_t>(p.vlan_ids.size());
	std::copy(p.vlan_ids.begin(), p.vlan_ids.end(), key.vlans.begin());
	FlowEndpoint src, dst;
	src.ip = p.src_ip;
	src.port = p.src_port;
	dst.ip = p.dst_ip;
	dst.port = p.dst_port;
	from_low = !(dst < src);
	key.low = from_low ? src : dst;
	key.high = from_low ? dst : src;
	return key;
}
// Advances the pending packet's scope clock, once per pushed record.
void FlowAggregator::Prepare() {
	const auto &input = pending_input;
	if (!scopes.count(input.interface_id) && scopes.size() >= limits.max_scopes) {
		throw std::runtime_error("Flow scope capacity exceeded");
	}
	auto &scope = scopes[input.interface_id];
	late = input.stamp.has_timestamp && scope.has_watermark && input.stamp.timestamp < scope.watermark;
	if (input.stamp.has_timestamp) {
		scope.watermark =
		    scope.has_watermark ? std::max(scope.watermark, input.stamp.timestamp) : input.stamp.timestamp;
		scope.has_watermark = true;
	}
	prepared = true;
}
// Whether the pending SYN starts a new session on a tuple already in use, rather
// than retransmitting or simultaneously opening the existing one.
bool FlowAggregator::Reused(const State &state, bool from_low) const {
	const auto &p = pending_input.packet;
	const size_t side = from_low == state.row.orig_is_low ? 0 : 1;
	const bool active_handshake = !state.handshake_closed && !state.row.handshake_complete && !state.row.fin_seen;
	const bool retransmit = active_handshake && state.syn[side] && state.sequence[side] == p.tcp_seq;
	const bool simultaneous = active_handshake && !state.syn[side] && state.syn[1 - side] && !state.syn_ack[side];
	return !retransmit && !simultaneous;
}
FlowAggregator::States::iterator FlowAggregator::Open(const SessionKey &key, bool from_low) {
	const auto &input = pending_input;
	const auto &p = input.packet;
	State state;
	auto &row = state.row;
	row.key = key;
	row.section = section;
	row.first_packet = input.stamp.number;
	row.orig_is_low = from_low;
	row.equal_endpoints = key.low == key.high;
	row.originator_basis = "first_packet";
	if (p.tcp && (p.tcp_flags & TCP_SYN)) {
		row.originator_basis = (p.tcp_flags & TCP_ACK) ? "syn_ack" : "syn";
		if (p.tcp_flags & TCP_ACK) {
			row.orig_is_low = !from_low;
		}
	}
	return states.emplace(key, std::move(state)).first;
}
bool FlowAggregator::Next(FlowSummary &output) {
	if (finishing) {
		if (states.empty()) {
			scopes.clear();
			return false;
		}
		return Emit(states.begin(), final_section == section ? "eof" : "section_boundary", output);
	}
	if (!pending) {
		return false;
	}
	const auto &input = pending_input;
	if (have_section && section != input.section) {
		if (!states.empty()) {
			return Emit(states.begin(), "section_boundary", output);
		}
		scopes.clear();
	}
	section = input.section;
	have_section = true;
	if (!prepared) {
		Prepare();
	}
	auto &scope = scopes.at(input.interface_id);
	Refresh(scope);
	if (!scope.expiry.empty() && scope.has_watermark && scope.expiry.begin()->first < scope.watermark) {
		auto expired = states.find(scope.expiry.begin()->second);
		PQ_ASSERT(expired != states.end());
		return Emit(expired, "idle_timeout", output);
	}
	const auto &p = input.packet;
	if (!p.transport || (!p.tcp && !p.udp) || p.ip_fragment_offset || p.ip_more_fragments) {
		pending = false;
		return false;
	}
	bool from_low = false;
	const auto key = MakeKey(input, from_low);
	auto it = states.find(key);
	if (it != states.end() && p.tcp && (p.tcp_flags & (TCP_SYN | TCP_ACK)) == TCP_SYN && Reused(it->second, from_low)) {
		// Keep pending: next call accounts for this packet in a fresh session.
		return Emit(it, "tuple_reuse", output);
	}
	if (it == states.end()) {
		if (states.size() >= limits.max_flows) {
			// A port scan opens more sessions than fit; failing the whole query
			// would lose every other session in the capture. Keep pending: the
			// next call accounts for this packet once a slot is free.
			return Emit(Evictable(input.interface_id), "limit", output);
		}
		it = Open(key, from_low);
	}
	Account(it->second, from_low);
	Schedule(it->second);
	const bool reset = it->second.row.reset_seen;
	pending = false;
	if (reset) {
		return Emit(it, "reset", output);
	}
	return false;
}
} // namespace packetquapture
