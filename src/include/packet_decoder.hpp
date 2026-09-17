#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace packetquapture {

// Non-owning view: the source bytes must outlive decoding and result consumption.
struct PacketView {
	const uint8_t *data;
	size_t size;
	uint32_t link_type;
};

enum class DecodeDepth : uint8_t { NONE, LINK, NETWORK, TRANSPORT };

struct DecodedPacket {
	bool ethernet = false;
	bool network = false;
	bool transport = false;
	bool tcp = false;
	bool udp = false;
	std::array<uint8_t, 6> src_mac {}, dst_mac {};
	uint16_t ether_type = 0;
	std::vector<uint16_t> vlan_ids;
	uint8_t ip_version = 0, ip_protocol = 0, ip_ttl = 0;
	std::array<uint8_t, 16> src_ip {}, dst_ip {};
	uint32_t ip_fragment_offset = 0, ip_id = 0;
	bool ip_more_fragments = false, has_ip_id = false;
	uint16_t src_port = 0, dst_port = 0, tcp_flags = 0, udp_length = 0;
	uint32_t tcp_seq = 0, tcp_ack = 0;
	uint8_t tcp_header_length = 0;
	uint32_t payload_offset = 0, payload_length = 0;
};

// Prefix access lets a decoder request headers without reading payload bytes.
// Returned storage remains valid until the next ReadPrefix call.
class PacketSource {
public:
	virtual ~PacketSource() = default;
	virtual size_t Size() const = 0;
	virtual const uint8_t *ReadPrefix(size_t length) = 0;
};

DecodedPacket DecodePacket(PacketSource &source, uint32_t link_type, DecodeDepth depth);
DecodedPacket DecodePacket(PacketView packet, DecodeDepth depth);

} // namespace packetquapture
