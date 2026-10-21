#pragma once

#include "tcp_reassembly.hpp"

namespace packetquapture {

// The outcome of framing one DNS message. UNSET is a message nothing has judged.
// CONFLICT and LIMIT also carry a failed TCP stream's status through unchanged.
enum class DnsFrameStatus : uint8_t { UNSET, COMPLETE, INCOMPLETE, INVALID, UNANCHORED, CONFLICT, LIMIT };

// The reassembly_status text SQL reports for a status.
inline const char *DnsFrameStatusName(DnsFrameStatus status) {
	switch (status) {
	case DnsFrameStatus::UNSET:
		return "";
	case DnsFrameStatus::COMPLETE:
		return "complete";
	case DnsFrameStatus::INCOMPLETE:
		return "incomplete";
	case DnsFrameStatus::INVALID:
		return "invalid";
	case DnsFrameStatus::UNANCHORED:
		return "unanchored";
	case DnsFrameStatus::CONFLICT:
		return "conflict";
	case DnsFrameStatus::LIMIT:
		return "limit";
	}
	PQ_ASSERT(false);
	return "";
}

struct TcpDnsMessage {
	TcpFlowKey key;
	bool tcp = true;
	uint64_t stream_id = 0, message_number = 0;
	uint32_t sequence = 0;
	PacketStamp first, last;
	DnsFrameStatus status = DnsFrameStatus::UNSET;
	std::string error;
	std::vector<uint8_t> data;
};

struct DnsFramingLimits {
	size_t max_messages = 4096;
};

// Stateless application framing over transport output. Does not own flows, reorder
// segments, interpret TCP flags, or decide how retransmissions/overlaps are handled.
std::vector<TcpDnsMessage> FrameTcpDns(const TcpStream &stream, DnsFramingLimits limits = DnsFramingLimits());
std::vector<TcpDnsMessage> FrameTcpDns(const std::vector<TcpStream> &streams,
                                       DnsFramingLimits limits = DnsFramingLimits());

} // namespace packetquapture
