#include "dns_tcp_framer.hpp"

#include <iterator>

namespace packetquapture {
namespace {
TcpDnsMessage Diagnostic(const TcpStream &stream, const std::string &status, const std::string &error) {
	TcpDnsMessage result;
	result.key = stream.key;
	result.stream_id = stream.stream_id;
	result.sequence = stream.sequence;
	result.first = stream.first;
	result.last = stream.last;
	result.status = status;
	result.error = error;
	return result;
}
} // namespace

std::vector<TcpDnsMessage> FrameTcpDns(const TcpStream &stream, DnsFramingLimits limits) {
	std::vector<TcpDnsMessage> result;
	if (stream.status == "conflict" || stream.status == "limit") {
		result.push_back(Diagnostic(stream, stream.status, stream.error));
		return result;
	}
	if (!stream.syn_seen) {
		result.push_back(
		    Diagnostic(stream, "unanchored", "TCP SYN was not captured; DNS message alignment is unknown"));
		return result;
	}
	const auto *chunk = !stream.chunks.empty() && stream.chunks.front().offset == 0 ? &stream.chunks.front() : nullptr;
	const size_t available = chunk ? chunk->data.size() : 0;
	size_t offset = 0;
	uint64_t number = 0;
	while (available - offset >= 2) {
		const size_t length = (uint16_t(chunk->data[offset]) << 8U) | chunk->data[offset + 1];
		if (length < 12) {
			auto diagnostic = Diagnostic(stream, "invalid", "DNS TCP frame length is shorter than the DNS header");
			diagnostic.sequence += static_cast<uint32_t>(offset);
			result.push_back(std::move(diagnostic));
			return result;
		}
		if (length > available - offset - 2) {
			break;
		}
		if (number >= limits.max_messages) {
			result.clear();
			result.push_back(Diagnostic(stream, "limit", "DNS message count exceeds per-direction limit"));
			return result;
		}
		auto message = Diagnostic(stream, "complete", "");
		message.message_number = ++number;
		message.sequence += static_cast<uint32_t>(offset);
		const auto provenance = chunk->Provenance(offset, length + 2);
		message.first = provenance.first;
		message.last = provenance.second;
		message.data.assign(chunk->data.begin() + offset + 2, chunk->data.begin() + offset + length + 2);
		result.push_back(std::move(message));
		offset += length + 2;
	}
	if (offset != stream.expected_bytes) {
		auto diagnostic = Diagnostic(stream, "incomplete",
		                             !stream.gaps.empty() ? "missing TCP bytes leave a sequence gap"
		                                                  : "incomplete DNS TCP frame at end of stream");
		diagnostic.sequence += static_cast<uint32_t>(offset);
		result.push_back(std::move(diagnostic));
	}
	return result;
}

std::vector<TcpDnsMessage> FrameTcpDns(const std::vector<TcpStream> &streams, DnsFramingLimits limits) {
	std::vector<TcpDnsMessage> result;
	for (const auto &stream : streams) {
		auto messages = FrameTcpDns(stream, limits);
		result.insert(result.end(), std::make_move_iterator(messages.begin()), std::make_move_iterator(messages.end()));
	}
	return result;
}
} // namespace packetquapture
