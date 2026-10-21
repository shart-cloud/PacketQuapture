#pragma once

#include "packet_decoder.hpp"
#include "pq_assert.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>
#include <utility>

namespace packetquapture {

struct TcpFlowKey {
	uint32_t section = 0, interface_id = 0;
	uint8_t ip_version = 0;
	std::array<uint8_t, 16> src_ip {}, dst_ip {};
	uint16_t src_port = 0, dst_port = 0;
	VlanStack vlans;
	bool operator<(const TcpFlowKey &other) const;
	TcpFlowKey Reverse() const;
};

struct PacketStamp {
	uint64_t number = 0;
	bool has_timestamp = false;
	int64_t timestamp = 0;
};

// A run of a chunk's bytes that one packet supplied. Offsets are within the
// chunk, 32 bits like every stream offset (max_stream_bytes fits them).
struct TcpByteOrigin {
	uint32_t offset = 0, length = 0;
	PacketStamp stamp;
};
struct TcpStreamChunk {
	uint32_t offset = 0, sequence = 0;
	std::vector<uint8_t> data;
	std::vector<TcpByteOrigin> origins;
	std::pair<PacketStamp, PacketStamp> Provenance(size_t offset, size_t length) const;
};
struct TcpGap {
	uint32_t offset = 0, length = 0;
};
// How completely a direction was reconstructed. UNSET is a stream no reassembler
// has judged; every stream the reassembler emits carries one of the others.
enum class TcpStreamStatus : uint8_t { UNSET, CONTIGUOUS, GAPPED, UNANCHORED, CONFLICT, LIMIT };

// The reassembly_status text SQL reports for a status.
inline const char *TcpStreamStatusName(TcpStreamStatus status) {
	switch (status) {
	case TcpStreamStatus::UNSET:
		return "";
	case TcpStreamStatus::CONTIGUOUS:
		return "contiguous";
	case TcpStreamStatus::GAPPED:
		return "gapped";
	case TcpStreamStatus::UNANCHORED:
		return "unanchored";
	case TcpStreamStatus::CONFLICT:
		return "conflict";
	case TcpStreamStatus::LIMIT:
		return "limit";
	}
	PQ_ASSERT(false);
	return "";
}

struct TcpStream {
	TcpFlowKey key;
	uint64_t stream_id = 0;
	uint32_t sequence = 0, expected_bytes = 0, captured_bytes = 0;
	bool syn_seen = false, fin_seen = false;
	PacketStamp first, last;
	TcpStreamStatus status = TcpStreamStatus::UNSET;
	std::string error, finalized_by;
	std::vector<TcpStreamChunk> chunks;
	std::vector<TcpGap> gaps;
};

struct TcpReassemblyLimits {
	size_t max_flows = 1024;
	size_t max_total_bytes = 32 * 1024 * 1024;
	size_t max_stream_bytes = 1024 * 1024;
	size_t max_segments = 4096;
	size_t max_total_segments = 65536;
	// A direction with no packet for this long, by its interface's clock, is finalized
	// as idle_timeout, as read_flows does. Zero disables eviction.
	int64_t tcp_idle_us = 300000000;
};

// File-scoped offline reconstruction. Output is delayed until EOF, reset, tuple reuse or idle timeout
// so conflicting retransmissions can invalidate a direction before reconstructed bytes are emitted. No application
// protocol is interpreted.
class TcpReassembler {
public:
	explicit TcpReassembler(TcpReassemblyLimits limits_p = TcpReassemblyLimits());
	std::vector<TcpStream> Add(const TcpFlowKey &key, uint32_t sequence, uint8_t flags, const uint8_t *payload,
	                           size_t captured, uint32_t declared, PacketStamp stamp);
	bool Empty() const;
	std::vector<TcpStream> FinishNext();
	size_t BufferedBytes() const;
	size_t FlowCount() const;

private:
	struct Segment {
		uint32_t sequence;
		uint32_t declared;
		PacketStamp stamp;
		std::vector<uint8_t> bytes;
	};
	struct Flow {
		uint64_t id = 0;
		bool has_syn = false, has_fin = false;
		uint32_t syn_sequence = 0, fin_sequence = 0;
		PacketStamp first, last;
		size_t bytes = 0;
		std::string failure;
		TcpStreamStatus failure_status = TcpStreamStatus::UNSET;
		std::vector<Segment> segments;
		// Indices into segments, sorted by (sequence, declared), so a duplicate is
		// found by binary search. In-order data appends at the end; a linear scan
		// made a direction of n segments cost n^2 / 2 comparisons.
		std::vector<std::pair<uint64_t, uint32_t>> segment_order;
		// Scheduled for idle eviction; a direction that ever lacks a timestamp never is.
		// deadline is the real one; queued is where its expiry entry sits, which
		// may be earlier, since entries move only when Expire reaches them.
		bool scheduled = false, untimed = false;
		int64_t deadline = 0, queued = 0;
	};
	// One clock per capture interface: the latest timestamp seen on it, and the
	// directions on it in deadline order. Dropped once nothing is scheduled.
	struct Scope {
		int64_t watermark = 0;
		std::set<std::pair<int64_t, TcpFlowKey>> expiry;
	};
	using ScopeKey = std::pair<uint32_t, uint32_t>;
	using Flows = std::map<TcpFlowKey, Flow>;
	TcpStream Diagnostic(const TcpFlowKey &key, const Flow &flow, TcpStreamStatus status,
	                     const std::string &error) const;
	Flows::iterator Track(const TcpFlowKey &key, bool syn, uint32_t sequence, PacketStamp stamp,
	                      std::vector<TcpStream> &output);
	void Buffer(Flow &flow, Segment &segment, const uint8_t *payload, size_t captured);
	std::vector<TcpStream> Finish(const TcpFlowKey &key, Flow &flow);
	static uint32_t StreamBase(const Flow &flow);
	bool Measure(const TcpFlowKey &key, const Flow &flow, uint32_t base, std::vector<size_t> &offsets, size_t &extent,
	             std::vector<TcpStream> &result) const;
	static bool Overlay(const Flow &flow, const std::vector<size_t> &offsets, std::vector<uint8_t> &bytes,
	                    std::vector<uint32_t> &owners);
	static void Emit(const Flow &flow, const std::vector<uint8_t> &bytes, const std::vector<uint32_t> &owners,
	                 TcpStream &stream);
	void Remove(const TcpFlowKey &key, std::vector<TcpStream> &output, const std::string &reason);
	void Fail(Flow &flow, const std::string &reason, TcpStreamStatus status = TcpStreamStatus::LIMIT);
	void Expire(const TcpFlowKey &key, const PacketStamp &stamp, std::vector<TcpStream> &output);
	void Schedule(const TcpFlowKey &key, Flow &flow, const PacketStamp &stamp);
	void Unschedule(const TcpFlowKey &key, Flow &flow);
	TcpReassemblyLimits limits;
	size_t buffered_bytes = 0, buffered_segments = 0;
	uint64_t next_id = 1;
	Flows flows;
	std::map<ScopeKey, Scope> scopes;
};
} // namespace packetquapture
