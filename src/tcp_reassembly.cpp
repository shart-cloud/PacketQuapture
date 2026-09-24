#include "tcp_reassembly.hpp"

#include <algorithm>
#include <iterator>
#include <limits>
#include <tuple>
#include <stdexcept>

namespace packetquapture {

bool TcpFlowKey::operator<(const TcpFlowKey &other) const {
	return std::tie(section, interface_id, ip_version, src_ip, dst_ip, src_port, dst_port, vlans) <
	       std::tie(other.section, other.interface_id, other.ip_version, other.src_ip, other.dst_ip, other.src_port,
	                other.dst_port, other.vlans);
}
TcpFlowKey TcpFlowKey::Reverse() const {
	auto result = *this;
	std::swap(result.src_ip, result.dst_ip);
	std::swap(result.src_port, result.dst_port);
	return result;
}

TcpReassembler::TcpReassembler(TcpReassemblyLimits limits_p) : limits(limits_p) {
}
bool TcpReassembler::Empty() const {
	return flows.empty();
}
size_t TcpReassembler::BufferedBytes() const {
	return buffered_bytes;
}
size_t TcpReassembler::FlowCount() const {
	return flows.size();
}

TcpStream TcpReassembler::Diagnostic(const TcpFlowKey &key, const Flow &flow, const std::string &status,
                                     const std::string &error) const {
	TcpStream result;
	result.key = key;
	result.stream_id = flow.id;
	result.first = flow.first;
	result.last = flow.last;
	result.sequence = flow.syn_sequence + 1;
	result.syn_seen = flow.has_syn;
	result.fin_seen = flow.has_fin;
	result.status = status;
	result.error = error;
	return result;
}

void TcpReassembler::Fail(Flow &flow, const std::string &reason, const std::string &status) {
	buffered_bytes -= flow.bytes;
	flow.bytes = 0;
	buffered_segments -= flow.segments.size();
	std::vector<Segment>().swap(flow.segments);
	flow.failure = reason;
	flow.failure_status = status;
}

void TcpReassembler::Remove(const TcpFlowKey &key, std::vector<TcpStream> &output, const std::string &reason) {
	auto it = flows.find(key);
	if (it == flows.end()) {
		return;
	}
	auto messages = Finish(it->first, it->second);
	for (auto &stream : messages) {
		stream.finalized_by = reason;
	}
	output.insert(output.end(), std::make_move_iterator(messages.begin()), std::make_move_iterator(messages.end()));
	Unschedule(it->first, it->second);
	buffered_bytes -= it->second.bytes;
	buffered_segments -= it->second.segments.size();
	flows.erase(it);
}

void TcpReassembler::Unschedule(const TcpFlowKey &key, Flow &flow) {
	if (!flow.scheduled) {
		return;
	}
	flow.scheduled = false;
	auto scope = scopes.find(ScopeKey(key.section, key.interface_id));
	scope->second.expiry.erase(std::make_pair(flow.deadline, key));
	if (scope->second.expiry.empty()) {
		scopes.erase(scope);
	}
}

// Deadlines only move later, so a packet arriving out of timestamp order cannot
// shorten a direction's life.
void TcpReassembler::Schedule(const TcpFlowKey &key, Flow &flow, const PacketStamp &stamp) {
	if (!stamp.has_timestamp) {
		flow.untimed = true;
	}
	const auto timeout = limits.tcp_idle_us;
	if (flow.untimed || timeout <= 0 || stamp.timestamp > std::numeric_limits<int64_t>::max() - timeout) {
		Unschedule(key, flow);
		return;
	}
	const auto deadline = stamp.timestamp + timeout;
	if (flow.scheduled && flow.deadline >= deadline) {
		return;
	}
	Unschedule(key, flow);
	auto inserted = scopes.emplace(ScopeKey(key.section, key.interface_id), Scope());
	auto &scope = inserted.first->second;
	// A new clock starts at this packet; zero would expire pre-1970 captures at once.
	scope.watermark = inserted.second ? stamp.timestamp : std::max(scope.watermark, stamp.timestamp);
	scope.expiry.emplace(deadline, key);
	flow.deadline = deadline;
	flow.scheduled = true;
}

// Finalizes every direction on this packet's interface that has been quiet for
// longer than the timeout, judged by the latest timestamp seen there.
void TcpReassembler::Expire(const TcpFlowKey &key, const PacketStamp &stamp, std::vector<TcpStream> &output) {
	if (!stamp.has_timestamp) {
		return;
	}
	const ScopeKey id(key.section, key.interface_id);
	auto scope = scopes.find(id);
	if (scope == scopes.end()) {
		return;
	}
	scope->second.watermark = std::max(scope->second.watermark, stamp.timestamp);
	const auto watermark = scope->second.watermark;
	while (scope != scopes.end() && scope->second.expiry.begin()->first < watermark) {
		const auto expired = scope->second.expiry.begin()->second;
		Remove(expired, output, "idle_timeout");
		scope = scopes.find(id);
	}
}

std::vector<TcpStream> TcpReassembler::Add(const TcpFlowKey &key, uint32_t sequence, uint8_t flags,
                                           const uint8_t *payload, size_t captured, uint32_t declared,
                                           PacketStamp stamp) {
	std::vector<TcpStream> output;
	Expire(key, stamp, output);
	const bool syn = (flags & 2U) != 0;
	auto it = flows.find(key);
	const bool new_syn = syn && (it == flows.end() || (it->second.has_syn && it->second.syn_sequence != sequence));
	if (new_syn) {
		Remove(key, output, "tuple_reuse");
		if ((flags & 16U) == 0) {
			Remove(key.Reverse(), output, "tuple_reuse");
		}
		it = flows.end();
	}
	if (it == flows.end()) {
		if (!syn && declared == 0 && captured == 0) {
			if (flags & 4U) {
				Remove(key.Reverse(), output, "reset");
			}
			return output;
		}
		if (next_id == std::numeric_limits<uint64_t>::max()) {
			throw std::overflow_error("TCP stream identifier space exhausted");
		}
		if (flows.size() >= limits.max_flows) {
			Flow overflow;
			overflow.id = next_id++;
			overflow.first = overflow.last = stamp;
			overflow.has_syn = syn;
			overflow.syn_sequence = sequence;
			output.push_back(Diagnostic(key, overflow, "limit", "maximum tracked TCP directions reached"));
			output.back().finalized_by = "limit";
			return output;
		}
		Flow flow;
		flow.id = next_id++;
		flow.first = flow.last = stamp;
		it = flows.emplace(key, std::move(flow)).first;
	}
	auto &flow = it->second;
	flow.last = stamp;
	Schedule(it->first, flow, stamp);
	if (syn) {
		flow.has_syn = true;
		flow.syn_sequence = sequence;
	}
	const auto data_sequence = sequence + (syn ? 1U : 0U);
	if (flags & 1U) {
		const auto fin = data_sequence + declared;
		if (flow.has_fin && flow.fin_sequence != fin) {
			Fail(flow, "conflicting TCP FIN positions", "conflict");
		}
		flow.has_fin = true;
		flow.fin_sequence = fin;
	}
	if (flow.failure.empty() && captured > declared) {
		Fail(flow, "captured TCP bytes exceed declared payload length", "conflict");
	}
	if (flow.failure.empty() && declared > 0) {
		if (captured > declared || captured > limits.max_stream_bytes || captured > limits.max_total_bytes) {
			Fail(flow, "TCP segment exceeds reassembly limits");
		} else {
			bool duplicate = false;
			for (const auto &segment : flow.segments) {
				if (segment.sequence == data_sequence && segment.declared == declared &&
				    segment.bytes.size() == captured &&
				    std::equal(segment.bytes.begin(), segment.bytes.end(), payload)) {
					duplicate = true;
					break;
				}
			}
			if (!duplicate) {
				if (flow.segments.size() >= limits.max_segments || buffered_segments >= limits.max_total_segments ||
				    captured > limits.max_stream_bytes - flow.bytes ||
				    captured > limits.max_total_bytes - buffered_bytes) {
					Fail(flow, "TCP reassembly byte or segment limit reached");
				} else {
					Segment segment;
					segment.sequence = data_sequence;
					segment.declared = declared;
					segment.stamp = stamp;
					if (captured) {
						segment.bytes.assign(payload, payload + captured);
					}
					flow.segments.push_back(std::move(segment));
					++buffered_segments;
					flow.bytes += captured;
					buffered_bytes += captured;
				}
			}
		}
	}
	if (flags & 4U) {
		Remove(key, output, "reset");
		Remove(key.Reverse(), output, "reset");
	}
	return output;
}

static int64_t RelativeSequence(uint32_t sequence, uint32_t base) {
	const auto difference = uint32_t(sequence - base);
	return difference <= uint32_t(std::numeric_limits<int32_t>::max()) ? int64_t(difference)
	                                                                   : int64_t(difference) - (int64_t(1) << 32U);
}

std::vector<TcpStream> TcpReassembler::Finish(const TcpFlowKey &key, Flow &flow) {
	std::vector<TcpStream> result;
	if (!flow.failure.empty()) {
		result.push_back(Diagnostic(key, flow, flow.failure_status, flow.failure));
		return result;
	}
	if (flow.segments.empty() && !flow.has_fin) {
		return result;
	}
	if (!flow.has_syn && flow.segments.empty()) {
		return result;
	}
	auto base = flow.has_syn ? flow.syn_sequence + 1U : flow.segments.front().sequence;
	if (!flow.has_syn) {
		int64_t first_offset = 0;
		for (const auto &segment : flow.segments) {
			first_offset = std::min(first_offset, RelativeSequence(segment.sequence, base));
		}
		base += static_cast<uint32_t>(first_offset);
	}

	size_t extent = 0;
	std::vector<size_t> offsets;
	for (const auto &segment : flow.segments) {
		const auto offset = RelativeSequence(segment.sequence, base);
		if (offset < 0 || uint64_t(offset) > limits.max_stream_bytes ||
		    segment.declared > limits.max_stream_bytes - size_t(offset)) {
			result.push_back(Diagnostic(key, flow, "limit", "TCP sequence span exceeds bounded reassembly window"));
			return result;
		}
		offsets.push_back(size_t(offset));
		extent = std::max(extent, size_t(offset) + segment.declared);
	}
	if (flow.has_fin) {
		const auto end = RelativeSequence(flow.fin_sequence, base);
		if (end < 0 || uint64_t(end) > limits.max_stream_bytes) {
			result.push_back(Diagnostic(key, flow, "limit", "TCP FIN exceeds bounded reassembly window"));
			return result;
		}
		if (size_t(end) < extent) {
			result.push_back(Diagnostic(key, flow, "conflict", "captured TCP data extends beyond FIN"));
			return result;
		}
		extent = size_t(end);
	}
	std::vector<uint8_t> bytes(extent);
	const auto missing = std::numeric_limits<uint32_t>::max();
	std::vector<uint32_t> owners(extent, missing);
	for (size_t i = 0; i < flow.segments.size(); ++i) {
		const auto &segment = flow.segments[i];
		for (size_t j = 0; j < segment.bytes.size(); ++j) {
			const auto pos = offsets[i] + j;
			if (owners[pos] != missing && bytes[pos] != segment.bytes[j]) {
				result.push_back(Diagnostic(key, flow, "conflict", "overlapping TCP segments contain different bytes"));
				return result;
			}
			if (owners[pos] == missing) {
				owners[pos] = static_cast<uint32_t>(i);
				bytes[pos] = segment.bytes[j];
			}
		}
	}
	TcpStream stream = Diagnostic(key, flow, "contiguous", "");
	stream.sequence = base;
	stream.expected_bytes = static_cast<uint32_t>(extent);
	size_t offset = 0;
	while (offset < extent) {
		const auto begin = offset;
		if (owners[offset] == missing) {
			while (offset < extent && owners[offset] == missing) {
				++offset;
			}
			TcpGap gap;
			gap.offset = static_cast<uint32_t>(begin);
			gap.length = static_cast<uint32_t>(offset - begin);
			stream.gaps.push_back(gap);
			continue;
		}
		TcpStreamChunk chunk;
		chunk.offset = static_cast<uint32_t>(begin);
		chunk.sequence = base + chunk.offset;
		while (offset < extent && owners[offset] != missing) {
			const auto owner = owners[offset];
			const auto origin_begin = offset;
			while (offset < extent && owners[offset] == owner) {
				++offset;
			}
			TcpByteOrigin origin;
			origin.offset = origin_begin - begin;
			origin.length = offset - origin_begin;
			origin.stamp = flow.segments[owner].stamp;
			chunk.origins.push_back(origin);
		}
		chunk.data.assign(bytes.begin() + begin, bytes.begin() + offset);
		stream.captured_bytes += static_cast<uint32_t>(chunk.data.size());
		stream.chunks.push_back(std::move(chunk));
	}
	if (!flow.has_syn) {
		stream.status = "unanchored";
		stream.error = "TCP SYN was not captured; offsets start at the earliest observed sequence";
	} else if (!stream.gaps.empty()) {
		stream.status = "gapped";
		stream.error = "missing TCP bytes leave sequence gaps";
	}
	if (extent > 0) {
		result.push_back(std::move(stream));
	}

	return result;
}

std::pair<PacketStamp, PacketStamp> TcpStreamChunk::Provenance(size_t offset, size_t length) const {
	PacketStamp first, last;
	bool found = false;
	if (length == 0 || offset > data.size() || length > data.size() - offset) {
		return {first, last};
	}
	for (const auto &origin : origins) {
		if (origin.offset >= offset + length || origin.offset + origin.length <= offset) {
			continue;
		}
		if (!found || origin.stamp.number < first.number) {
			first = origin.stamp;
		}
		if (!found || origin.stamp.number > last.number) {
			last = origin.stamp;
		}
		found = true;
	}
	return {first, last};
}

std::vector<TcpStream> TcpReassembler::FinishNext() {
	std::vector<TcpStream> result;
	if (!flows.empty()) {
		Remove(flows.begin()->first, result, "eof");
	}
	return result;
}
} // namespace packetquapture
