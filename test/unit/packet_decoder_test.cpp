#include "packet_decoder.hpp"

#include <cassert>
#include <fstream>
#include <iostream>
#include <iterator>
#include <random>
#include <tuple>
#include <vector>

using namespace packetquapture;

static uint32_t Little32(const uint8_t *p) {
	return uint32_t(p[0]) | (uint32_t(p[1]) << 8U) | (uint32_t(p[2]) << 16U) | (uint32_t(p[3]) << 24U);
}

class TrackingSource : public PacketSource {
public:
	explicit TrackingSource(const std::vector<uint8_t> &bytes_p) : bytes(bytes_p) {
	}
	size_t Size() const override {
		return bytes.size();
	}
	const uint8_t *ReadPrefix(size_t length) override {
		assert(length <= bytes.size());
		if (length > prefix.size()) {
			// Deliberate reallocations expose stale decoder pointers under ASan.
			std::vector<uint8_t>(bytes.begin(), bytes.begin() + length).swap(prefix);
		}
		return prefix.data();
	}
	size_t ReadBytes() const {
		return prefix.size();
	}

private:
	const std::vector<uint8_t> &bytes;
	std::vector<uint8_t> prefix;
};

static bool Equal(const DecodedPacket &a, const DecodedPacket &b) {
	return std::tie(a.ethernet, a.network, a.transport, a.tcp, a.udp, a.src_mac, a.dst_mac, a.ether_type, a.vlan_ids,
	                a.ip_version, a.ip_protocol, a.ip_ttl, a.src_ip, a.dst_ip, a.ip_fragment_offset, a.ip_id,
	                a.ip_more_fragments, a.has_ip_id, a.src_port, a.dst_port, a.tcp_flags, a.udp_length, a.tcp_seq,
	                a.tcp_ack, a.tcp_header_length, a.payload_offset, a.payload_length) ==
	       std::tie(b.ethernet, b.network, b.transport, b.tcp, b.udp, b.src_mac, b.dst_mac, b.ether_type, b.vlan_ids,
	                b.ip_version, b.ip_protocol, b.ip_ttl, b.src_ip, b.dst_ip, b.ip_fragment_offset, b.ip_id,
	                b.ip_more_fragments, b.has_ip_id, b.src_port, b.dst_port, b.tcp_flags, b.udp_length, b.tcp_seq,
	                b.tcp_ack, b.tcp_header_length, b.payload_offset, b.payload_length);
}

static void Check(const std::vector<uint8_t> &bytes, uint32_t link) {
	const PacketView view {bytes.data(), bytes.size(), link};
	const auto none = DecodePacket(view, DecodeDepth::NONE);
	assert(!none.ethernet && !none.network && !none.transport);
	const auto ethernet = DecodePacket(view, DecodeDepth::LINK);
	assert(!ethernet.network && !ethernet.transport);
	const auto network = DecodePacket(view, DecodeDepth::NETWORK);
	assert(!network.transport);
	const auto transport = DecodePacket(view, DecodeDepth::TRANSPORT);
	for (const auto depth : {DecodeDepth::NONE, DecodeDepth::LINK, DecodeDepth::NETWORK, DecodeDepth::TRANSPORT}) {
		TrackingSource source(bytes);
		assert(Equal(DecodePacket(source, link, depth), DecodePacket(view, depth)));
		// Eight VLAN tags, IPv6 base header, sixteen maximum-sized extensions, and TCP options.
		assert(source.ReadBytes() <= 14 + 8 * 4 + 40 + 16 * 2048 + 60);
	}
	assert(ethernet.ethernet == network.ethernet && network.ethernet == transport.ethernet);
	assert(network.network == transport.network);
	if (transport.transport) {
		assert(transport.network && (transport.tcp != transport.udp));
		assert(!transport.ip_more_fragments && transport.ip_fragment_offset == 0);
		assert(transport.payload_offset <= bytes.size());
		assert(transport.payload_length <= bytes.size() - transport.payload_offset);
	}
}

int main() {
	std::ifstream input("test/data/protocols/ethernet.pcap", std::ios::binary);
	assert(input.good());
	const std::vector<uint8_t> capture((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
	std::mt19937 random(1234567);
	size_t offset = 24;
	unsigned packets = 0;
	while (offset < capture.size()) {
		assert(capture.size() - offset >= 16);
		const auto size = Little32(capture.data() + offset + 8);
		offset += 16;
		assert(size <= capture.size() - offset);
		std::vector<uint8_t> packet(capture.begin() + offset, capture.begin() + offset + size);
		offset += size;
		++packets;
		if (packets == 1) {
			const auto decoded = DecodePacket({packet.data(), packet.size(), 1}, DecodeDepth::TRANSPORT);
			assert(decoded.src_port == 12345 && decoded.dst_port == 443);
			assert(decoded.tcp_seq == 0x01020304 && decoded.tcp_ack == 0x05060708);
			assert(decoded.payload_offset == 54 && decoded.payload_length == 5);
			const size_t expected[] = {0, 14, 34, 54};
			for (unsigned depth = 0; depth < 4; ++depth) {
				TrackingSource source(packet);
				DecodePacket(source, 1, static_cast<DecodeDepth>(depth));
				assert(source.ReadBytes() == expected[depth]);
			}
		}
		for (size_t length = 0; length <= packet.size(); ++length) {
			Check(std::vector<uint8_t>(packet.begin(), packet.begin() + length), 1);
		}
		for (unsigned i = 0; i < 2000; ++i) {
			auto mutated = packet;
			for (unsigned j = 0; j < 4 && !mutated.empty(); ++j) {
				mutated[random() % mutated.size()] = static_cast<uint8_t>(random());
			}
			Check(mutated, 1);
		}
	}
	assert(packets == 34);
	for (unsigned i = 0; i < 20000; ++i) {
		std::vector<uint8_t> bytes(random() % 256);
		for (auto &byte : bytes) {
			byte = static_cast<uint8_t>(random());
		}
		for (auto link : {1U, 101U, 113U, 228U, 229U, 276U, 999U}) {
			Check(bytes, link);
		}
	}
	std::cout << "Decoder checks passed: fixture prefixes, 68,000 mutations, 140,000 random link cases\n";
}
