#include "tcp_reassembly.hpp"

#include "pq_assert.hpp"

#include <algorithm>
#include <iterator>
#include <limits>
#include <tuple>
#include <stdexcept>

namespace packetquapture {

// Marks a reassembled byte that no segment supplied.
static const uint32_t UNOWNED = std::numeric_limits<uint32_t>::max();

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
	// Stream offsets, extents and segment owners are stored as uint32_t, and
	// UINT32_MAX marks a byte no segment owns.
	PQ_ASSERT(limits.max_stream_bytes <= std::numeric_limits<uint32_t>::max());
	PQ_ASSERT(limits.max_segments < std::numeric_limits<uint32_t>::max());
	PQ_ASSERT(limits.tcp_idle_us >= 0);
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

TcpStream TcpReassembler::Diagnostic(const TcpFlowKey &key, const Flow &flow, TcpStreamStatus status,
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

void TcpReassembler::Fail(Flow &flow, const std::string &reason, TcpStreamStatus status) {
	PQ_ASSERT(buffered_bytes >= flow.bytes);
	PQ_ASSERT(buffered_segments >= flow.segments.size());
	buffered_bytes -= flow.bytes;
	flow.bytes = 0;
	buffered_segments -= flow.segments.size();
	std::vector<Segment>().swap(flow.segments);
	std::vector<std::pair<uint64_t, uint32_t>>().swap(flow.segment_order);
	flow.failure = reason;
	flow.failure_status = status;
}

void TcpReassembler::Remove(const TcpFlowKey &key, std::vector<TcpStream> &output, const std::string &reason) {
	auto it = flows.find(key);
	if (it == flows.end()) {
		return;
	}
	PQ_ASSERT(buffered_bytes >= it->second.bytes);
	PQ_ASSERT(buffered_segments >= it->second.segments.size());
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
	PQ_ASSERT(scope != scopes.end());
	const auto erased = scope->second.expiry.erase(std::make_pair(flow.queued, key));
	PQ_ASSERT(erased == 1);
	if (scope->second.expiry.empty()) {
		scopes.erase(scope);
	}
}

// Deadlines only move later, so a packet arriving out of timestamp order cannot
// shorten a direction's life. A direction already queued keeps its entry and only
// records the later deadline: Expire re-queues an entry it finds stale, so a
// packet costs no tree operations, where moving the entry cost an erase and an
// insert per packet.
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
	auto inserted = scopes.emplace(ScopeKey(key.section, key.interface_id), Scope());
	auto &scope = inserted.first->second;
	// A new clock starts at this packet; zero would expire pre-1970 captures at once.
	scope.watermark = inserted.second ? stamp.timestamp : std::max(scope.watermark, stamp.timestamp);
	flow.deadline = deadline;
	if (flow.scheduled) {
		PQ_ASSERT(!inserted.second); // its queued entry keeps the scope alive
		PQ_ASSERT(flow.queued < deadline);
		return;
	}
	scope.expiry.emplace(deadline, key);
	flow.queued = deadline;
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
	auto &clock = scope->second.watermark;
	// A packet further behind than the timeout means the clock stepped back. The
	// clock restarts from it, or every direction opened since would look idle at
	// once; directions from before the step wait until the new clock catches up.
	const bool stepped_back =
	    stamp.timestamp < clock && uint64_t(clock) - uint64_t(stamp.timestamp) > uint64_t(limits.tcp_idle_us);
	clock = stepped_back ? stamp.timestamp : std::max(clock, stamp.timestamp);
	const auto watermark = clock;
	// Each pass either re-queues a stale entry at its direction's real, later
	// deadline, or removes the earliest direction, which Remove unschedules. An
	// entry is re-queued at most once before it is removed or passes the
	// watermark, so the loop runs at most twice per scheduled direction. Were a
	// scheduled key ever missing from flows, this would spin; the assertion makes
	// that a failure instead.
	while (scope != scopes.end() && scope->second.expiry.begin()->first < watermark) {
		auto &expiry = scope->second.expiry;
		const auto entry = *expiry.begin();
		auto it = flows.find(entry.second);
		PQ_ASSERT(it != flows.end());
		auto &flow = it->second;
		PQ_ASSERT(flow.scheduled);
		PQ_ASSERT(flow.queued == entry.first);
		PQ_ASSERT(flow.deadline >= flow.queued);
		if (flow.deadline > entry.first) {
			expiry.erase(expiry.begin());
			expiry.emplace(flow.deadline, entry.second);
			flow.queued = flow.deadline;
			continue;
		}
		Remove(entry.second, output, "idle_timeout");
		scope = scopes.find(id);
	}
}

std::vector<TcpStream> TcpReassembler::Add(const TcpFlowKey &key, uint32_t sequence, uint8_t flags,
                                           const uint8_t *payload, size_t captured, uint32_t declared,
                                           PacketStamp stamp) {
	std::vector<TcpStream> output;
	Expire(key, stamp, output);
	const bool syn = (flags & TCP_SYN) != 0;
	auto it = flows.find(key);
	const bool new_syn = syn && (it == flows.end() || (it->second.has_syn && it->second.syn_sequence != sequence));
	if (new_syn) {
		Remove(key, output, "tuple_reuse");
		if ((flags & TCP_ACK) == 0) {
			Remove(key.Reverse(), output, "tuple_reuse");
		}
		it = flows.end();
	}
	if (it == flows.end()) {
		if (!syn && declared == 0 && captured == 0) {
			if (flags & TCP_RST) {
				Remove(key.Reverse(), output, "reset");
			}
			return output;
		}
		it = Track(key, syn, sequence, stamp, output);
		if (it == flows.end()) {
			return output;
		}
	}
	auto &flow = it->second;
	flow.last = stamp;
	Schedule(it->first, flow, stamp);
	if (syn) {
		flow.has_syn = true;
		flow.syn_sequence = sequence;
	}
	const auto data_sequence = sequence + (syn ? 1U : 0U);
	if (flags & TCP_FIN) {
		const auto fin = data_sequence + declared;
		if (flow.has_fin && flow.fin_sequence != fin) {
			Fail(flow, "conflicting TCP FIN positions", TcpStreamStatus::CONFLICT);
		}
		flow.has_fin = true;
		flow.fin_sequence = fin;
	}
	if (flow.failure.empty() && captured > declared) {
		Fail(flow, "captured TCP bytes exceed declared payload length", TcpStreamStatus::CONFLICT);
	}
	if (flow.failure.empty() && declared > 0) {
		Segment segment;
		segment.sequence = data_sequence;
		segment.declared = declared;
		segment.stamp = stamp;
		Buffer(flow, segment, payload, captured);
	}
	if (flags & TCP_RST) {
		Remove(key, output, "reset");
		Remove(key.Reverse(), output, "reset");
	}
	return output;
}

// Starts tracking a direction, or reports it as a limit diagnostic and returns
// flows.end() when the table is full.
TcpReassembler::Flows::iterator TcpReassembler::Track(const TcpFlowKey &key, bool syn, uint32_t sequence,
                                                      PacketStamp stamp, std::vector<TcpStream> &output) {
	if (next_id == std::numeric_limits<uint64_t>::max()) {
		throw std::overflow_error("TCP stream identifier space exhausted");
	}
	if (flows.size() >= limits.max_flows) {
		Flow overflow;
		overflow.id = next_id++;
		overflow.first = overflow.last = stamp;
		overflow.has_syn = syn;
		overflow.syn_sequence = sequence;
		output.push_back(Diagnostic(key, overflow, TcpStreamStatus::LIMIT, "maximum tracked TCP directions reached"));
		output.back().finalized_by = "limit";
		return flows.end();
	}
	Flow flow;
	flow.id = next_id++;
	flow.first = flow.last = stamp;
	return flows.emplace(key, std::move(flow)).first;
}

// Keeps a data segment for Finish. segment carries the sequence, declared length
// and stamp; its bytes are copied from payload only once it is known to be new.
void TcpReassembler::Buffer(Flow &flow, Segment &segment, const uint8_t *payload, size_t captured) {
	PQ_ASSERT(captured <= segment.declared); // a larger capture failed the flow in Add
	if (captured > limits.max_stream_bytes || captured > limits.max_total_bytes) {
		Fail(flow, "TCP segment exceeds reassembly limits");
		return;
	}
	// A retransmission repeats sequence, length and bytes; anything else is
	// kept, and overlaps are judged in Finish.
	PQ_ASSERT(flow.segment_order.size() == flow.segments.size());
	const uint64_t position = (uint64_t(segment.sequence) << 32U) | segment.declared;
	auto first =
	    std::lower_bound(flow.segment_order.begin(), flow.segment_order.end(), std::make_pair(position, uint32_t(0)));
	for (auto entry = first; entry != flow.segment_order.end() && entry->first == position; ++entry) {
		const auto &existing = flow.segments[entry->second];
		if (existing.bytes.size() == captured && std::equal(existing.bytes.begin(), existing.bytes.end(), payload)) {
			return;
		}
	}
	PQ_ASSERT(flow.bytes <= limits.max_stream_bytes);
	PQ_ASSERT(buffered_bytes <= limits.max_total_bytes);
	if (flow.segments.size() >= limits.max_segments || buffered_segments >= limits.max_total_segments ||
	    captured > limits.max_stream_bytes - flow.bytes || captured > limits.max_total_bytes - buffered_bytes) {
		Fail(flow, "TCP reassembly byte or segment limit reached");
		return;
	}
	if (captured) {
		segment.bytes.assign(payload, payload + captured);
	}
	const auto index = static_cast<uint32_t>(flow.segments.size());
	flow.segments.push_back(std::move(segment));
	flow.segment_order.insert(std::upper_bound(flow.segment_order.begin(), flow.segment_order.end(),
	                                           std::make_pair(position, std::numeric_limits<uint32_t>::max())),
	                          std::make_pair(position, index));
	++buffered_segments;
	flow.bytes += captured;
	buffered_bytes += captured;
}

static int64_t RelativeSequence(uint32_t sequence, uint32_t base) {
	const auto difference = uint32_t(sequence - base);
	return difference <= uint32_t(std::numeric_limits<int32_t>::max()) ? int64_t(difference)
	                                                                   : int64_t(difference) - (int64_t(1) << 32U);
}

// The sequence number of stream offset zero: just past the SYN, or without one,
// the earliest sequence any segment starts at.
uint32_t TcpReassembler::StreamBase(const Flow &flow) {
	auto base = flow.has_syn ? flow.syn_sequence + 1U : flow.segments.front().sequence;
	if (!flow.has_syn) {
		int64_t first_offset = 0;
		for (const auto &segment : flow.segments) {
			first_offset = std::min(first_offset, RelativeSequence(segment.sequence, base));
		}
		base += static_cast<uint32_t>(first_offset);
	}
	return base;
}

// Places every segment and the FIN relative to base, setting each segment's
// offset and the stream extent. On failure, pushes the diagnostic and returns false.
bool TcpReassembler::Measure(const TcpFlowKey &key, const Flow &flow, uint32_t base, std::vector<size_t> &offsets,
                             size_t &extent, std::vector<TcpStream> &result) const {
	for (const auto &segment : flow.segments) {
		const auto offset = RelativeSequence(segment.sequence, base);
		if (offset < 0 || uint64_t(offset) > limits.max_stream_bytes ||
		    segment.declared > limits.max_stream_bytes - size_t(offset)) {
			result.push_back(
			    Diagnostic(key, flow, TcpStreamStatus::LIMIT, "TCP sequence span exceeds bounded reassembly window"));
			return false;
		}
		offsets.push_back(size_t(offset));
		extent = std::max(extent, size_t(offset) + segment.declared);
	}
	if (flow.has_fin) {
		const auto end = RelativeSequence(flow.fin_sequence, base);
		if (end < 0 || uint64_t(end) > limits.max_stream_bytes) {
			result.push_back(
			    Diagnostic(key, flow, TcpStreamStatus::LIMIT, "TCP FIN exceeds bounded reassembly window"));
			return false;
		}
		if (size_t(end) < extent) {
			result.push_back(Diagnostic(key, flow, TcpStreamStatus::CONFLICT, "captured TCP data extends beyond FIN"));
			return false;
		}
		extent = size_t(end);
	}
	return true;
}

// Copies each segment's bytes to its offset, recording the first segment to
// supply each byte. Returns false when overlapping segments disagree.
bool TcpReassembler::Overlay(const Flow &flow, const std::vector<size_t> &offsets, std::vector<uint8_t> &bytes,
                             std::vector<uint32_t> &owners) {
	for (size_t i = 0; i < flow.segments.size(); ++i) {
		const auto &segment = flow.segments[i];
		for (size_t j = 0; j < segment.bytes.size(); ++j) {
			const auto pos = offsets[i] + j;
			if (owners[pos] != UNOWNED && bytes[pos] != segment.bytes[j]) {
				return false;
			}
			if (owners[pos] == UNOWNED) {
				owners[pos] = static_cast<uint32_t>(i);
				bytes[pos] = segment.bytes[j];
			}
		}
	}
	return true;
}

// Splits the overlaid bytes into gaps and chunks, each chunk with one origin
// per run of bytes from the same segment.
void TcpReassembler::Emit(const Flow &flow, const std::vector<uint8_t> &bytes, const std::vector<uint32_t> &owners,
                          TcpStream &stream) {
	const auto extent = bytes.size();
	size_t offset = 0;
	while (offset < extent) {
		const auto begin = offset;
		if (owners[offset] == UNOWNED) {
			while (offset < extent && owners[offset] == UNOWNED) {
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
		chunk.sequence = stream.sequence + chunk.offset;
		while (offset < extent && owners[offset] != UNOWNED) {
			const auto owner = owners[offset];
			const auto origin_begin = offset;
			while (offset < extent && owners[offset] == owner) {
				++offset;
			}
			TcpByteOrigin origin;
			origin.offset = static_cast<uint32_t>(origin_begin - begin); // extent fits 32 bits
			origin.length = static_cast<uint32_t>(offset - origin_begin);
			origin.stamp = flow.segments[owner].stamp;
			chunk.origins.push_back(origin);
		}
		chunk.data.assign(bytes.begin() + begin, bytes.begin() + offset);
		stream.captured_bytes += static_cast<uint32_t>(chunk.data.size());
		stream.chunks.push_back(std::move(chunk));
	}
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
	const auto base = StreamBase(flow);
	size_t extent = 0;
	std::vector<size_t> offsets;
	if (!Measure(key, flow, base, offsets, extent, result)) {
		return result;
	}
	PQ_ASSERT(extent <= limits.max_stream_bytes);
	std::vector<uint8_t> bytes(extent);
	std::vector<uint32_t> owners(extent, UNOWNED);
	if (!Overlay(flow, offsets, bytes, owners)) {
		result.push_back(
		    Diagnostic(key, flow, TcpStreamStatus::CONFLICT, "overlapping TCP segments contain different bytes"));
		return result;
	}
	TcpStream stream = Diagnostic(key, flow, TcpStreamStatus::CONTIGUOUS, "");
	stream.sequence = base;
	stream.expected_bytes = static_cast<uint32_t>(extent);
	Emit(flow, bytes, owners, stream);
	if (!flow.has_syn) {
		stream.status = TcpStreamStatus::UNANCHORED;
		stream.error = "TCP SYN was not captured; offsets start at the earliest observed sequence";
	} else if (!stream.gaps.empty()) {
		stream.status = TcpStreamStatus::GAPPED;
		stream.error = "missing TCP bytes leave sequence gaps";
	}
	if (extent > 0) {
		result.push_back(std::move(stream));
	}

	return result;
}

// Finish builds origins contiguous and in offset order, so the first one that
// overlaps is found by binary search and a lookup touches only the origins it
// overlaps. A linear scan made a stream of many small messages cost messages x
// packets, which a hostile stream of 1-byte records turns into ~10^10 steps.
std::pair<PacketStamp, PacketStamp> TcpStreamChunk::Provenance(size_t offset, size_t length) const {
	PacketStamp first, last;
	if (length == 0 || offset > data.size() || length > data.size() - offset) {
		return {first, last};
	}
	auto origin = std::upper_bound(origins.begin(), origins.end(), offset,
	                               [](size_t value, const TcpByteOrigin &entry) { return value < entry.offset; });
	PQ_ASSERT(origin != origins.begin());
	--origin;
	bool found = false;
	size_t expected = origin->offset;
	for (; origin != origins.end() && origin->offset < offset + length; ++origin) {
		PQ_ASSERT(origin->offset == expected);
		PQ_ASSERT(origin->length > 0);
		expected = origin->offset + origin->length;
		if (!found || origin->stamp.number < first.number) {
			first = origin->stamp;
		}
		if (!found || origin->stamp.number > last.number) {
			last = origin->stamp;
		}
		found = true;
	}
	PQ_ASSERT(found);
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
