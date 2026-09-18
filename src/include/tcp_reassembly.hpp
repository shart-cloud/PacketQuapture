#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>
#include <utility>

namespace packetquapture {

struct TcpFlowKey {
	uint32_t section = 0, interface_id = 0;
	uint8_t ip_version = 0;
	std::array<uint8_t, 16> src_ip {}, dst_ip {};
	uint16_t src_port = 0, dst_port = 0;
	std::vector<uint16_t> vlans;
	bool operator<(const TcpFlowKey &other) const;
	TcpFlowKey Reverse() const;
};

struct PacketStamp {
	uint64_t number = 0;
	bool has_timestamp = false;
	int64_t timestamp = 0;
};

struct TcpByteOrigin {
	size_t offset = 0, length = 0;
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
struct TcpStream {
	TcpFlowKey key;
	uint64_t stream_id = 0;
	uint32_t sequence = 0, expected_bytes = 0, captured_bytes = 0;
	bool syn_seen = false, fin_seen = false;
	PacketStamp first, last;
	std::string status, error, finalized_by;
	std::vector<TcpStreamChunk> chunks;
	std::vector<TcpGap> gaps;
};

struct TcpReassemblyLimits {
	size_t max_flows = 1024;
	size_t max_total_bytes = 32 * 1024 * 1024;
	size_t max_stream_bytes = 1024 * 1024;
	size_t max_segments = 4096;
	size_t max_total_segments = 65536;
};

// File-scoped offline reconstruction. Output is delayed until EOF, reset, or tuple reuse
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
		std::string failure, failure_status;
		std::vector<Segment> segments;
	};
	TcpStream Diagnostic(const TcpFlowKey &key, const Flow &flow, const std::string &status,
	                     const std::string &error) const;
	std::vector<TcpStream> Finish(const TcpFlowKey &key, Flow &flow);
	void Remove(const TcpFlowKey &key, std::vector<TcpStream> &output, const std::string &reason);
	void Fail(Flow &flow, const std::string &reason, const std::string &status = "limit");
	TcpReassemblyLimits limits;
	size_t buffered_bytes = 0, buffered_segments = 0;
	uint64_t next_id = 1;
	std::map<TcpFlowKey, Flow> flows;
};
} // namespace packetquapture
