#pragma once

#include "tcp_reassembly.hpp"

namespace packetquapture {

struct TcpDnsMessage {
	TcpFlowKey key;
	bool tcp = true;
	uint64_t stream_id = 0, message_number = 0;
	uint32_t sequence = 0;
	PacketStamp first, last;
	std::string status, error;
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
