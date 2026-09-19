#include "flow_aggregator.hpp"
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
	if (!input.stamp.number || input.packet.vlan_ids.size() > 8) {
		throw std::invalid_argument("Invalid flow packet number or VLAN stack");
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
		scopes.at(state.row.key.interface_id).expiry.erase({state.deadline, state.row.key});
		state.scheduled = false;
	}
}
void FlowAggregator::Schedule(State &state) {
	const auto timeout = state.row.key.protocol == 6 ? limits.tcp_idle_us : limits.udp_idle_us;
	if (!timeout || state.row.missing_timestamps || !state.row.has_timestamp ||
	    state.row.last_timestamp > std::numeric_limits<int64_t>::max() - timeout) {
		return;
	}
	state.deadline = state.row.last_timestamp + timeout;
	scopes.at(state.row.key.interface_id).expiry.emplace(state.deadline, state.row.key);
	state.scheduled = true;
}
bool FlowAggregator::Emit(States::iterator it, const char *reason, FlowSummary &output) {
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
		if (!(p.tcp_flags & 2) && ((p.tcp_flags & 0x10) || p.payload_length)) {
			state.handshake_closed = true;
		}
		row.syn_seen |= (p.tcp_flags & 2) != 0;
		row.fin_seen |= (p.tcp_flags & 1) != 0;
		row.reset_seen |= (p.tcp_flags & 4) != 0;
		const size_t side = orig ? 0 : 1, other = 1 - side;
		if ((p.tcp_flags & 0x12) == 2) {
			if (state.syn[other]) {
				row.simultaneous_open = true;
			}
			state.syn[side] = true;
			state.sequence[side] = p.tcp_seq;
		} else if ((p.tcp_flags & 0x12) == 0x12) {
			if (state.syn[other] && p.tcp_ack == state.sequence[other] + uint32_t(1)) {
				state.syn_ack[side] = true;
				state.sequence[side] = p.tcp_seq;
			}
		} else if ((p.tcp_flags & 0x10) && state.syn[side] && state.syn_ack[other] &&
		           p.tcp_ack == state.sequence[other] + uint32_t(1) &&
		           p.tcp_seq == state.sequence[side] + uint32_t(1)) {
			row.handshake_complete = true;
		}
	}
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
	auto &scope = scopes.at(input.interface_id);
	if (!scope.expiry.empty() && scope.has_watermark && scope.expiry.begin()->first < scope.watermark) {
		return Emit(states.find(scope.expiry.begin()->second), "idle_timeout", output);
	}
	const auto &p = input.packet;
	if (!p.transport || (!p.tcp && !p.udp) || p.ip_fragment_offset || p.ip_more_fragments) {
		pending = false;
		return false;
	}
	SessionKey key;
	key.interface_id = input.interface_id;
	key.ip_version = p.ip_version;
	key.protocol = p.tcp ? 6 : 17;
	key.vlan_count = static_cast<uint8_t>(p.vlan_ids.size());
	std::copy(p.vlan_ids.begin(), p.vlan_ids.end(), key.vlans.begin());
	FlowEndpoint src, dst;
	src.ip = p.src_ip;
	src.port = p.src_port;
	dst.ip = p.dst_ip;
	dst.port = p.dst_port;
	const bool from_low = !(dst < src);
	key.low = from_low ? src : dst;
	key.high = from_low ? dst : src;
	auto it = states.find(key);
	if (it != states.end() && p.tcp && (p.tcp_flags & 0x12) == 2) {
		const auto &state = it->second;
		const size_t side = from_low == state.row.orig_is_low ? 0 : 1;
		const bool active_handshake = !state.handshake_closed && !state.row.handshake_complete && !state.row.fin_seen;
		const bool retransmit = active_handshake && state.syn[side] && state.sequence[side] == p.tcp_seq;
		const bool simultaneous = active_handshake && !state.syn[side] && state.syn[1 - side] && !state.syn_ack[side];
		if (!retransmit && !simultaneous) {
			// Keep pending: next call accounts for this packet in a fresh session.
			return Emit(it, "tuple_reuse", output);
		}
	}
	if (it == states.end()) {
		if (states.size() >= limits.max_flows) {
			throw std::runtime_error("Flow active-session capacity exceeded");
		}
		State state;
		auto &row = state.row;
		row.key = key;
		row.section = section;
		row.first_packet = input.stamp.number;
		row.orig_is_low = from_low;
		row.equal_endpoints = src == dst;
		row.originator_basis = "first_packet";
		if (p.tcp && (p.tcp_flags & 2)) {
			row.originator_basis = (p.tcp_flags & 0x10) ? "syn_ack" : "syn";
			if (p.tcp_flags & 0x10) {
				row.orig_is_low = !from_low;
			}
		}
		it = states.emplace(key, std::move(state)).first;
	}
	Unschedule(it->second);
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
