#pragma once

#include "pq_assert.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <vector>

namespace packetquapture {

// Non-owning view: the source bytes must outlive decoding and result consumption.
struct PacketView {
	const uint8_t *data;
	size_t size;
	uint32_t link_type;
};

enum class DecodeDepth : uint8_t { NONE, LINK, NETWORK, TRANSPORT };

// TCP header flag bits (RFC 9293 3.1), as DecodedPacket::tcp_flags holds them.
static const uint16_t TCP_FIN = 0x01;
static const uint16_t TCP_SYN = 0x02;
static const uint16_t TCP_RST = 0x04;
static const uint16_t TCP_ACK = 0x10;

enum class DecodeOutcome : uint8_t { NOT_REQUESTED, DECODED, MALFORMED, UNSUPPORTED, FRAGMENT };

// The 802.1Q tags of one packet, outermost first. Deeper stacks decode as
// UNSUPPORTED. Fixed storage keeps decoded packets and the flow keys copied from
// them free of heap allocation; a vector here allocated on every key copy.
class VlanStack {
public:
	static const size_t CAPACITY = 8;
	VlanStack() {
	}
	VlanStack(std::initializer_list<uint16_t> values) {
		for (const auto value : values) {
			push_back(value);
		}
	}
	size_t size() const {
		return count;
	}
	bool empty() const {
		return count == 0;
	}
	const uint16_t *data() const {
		return ids.data();
	}
	const uint16_t *begin() const {
		return ids.data();
	}
	const uint16_t *end() const {
		return ids.data() + count;
	}
	uint16_t operator[](size_t index) const {
		PQ_ASSERT(index < count);
		return ids[index];
	}
	void push_back(uint16_t value) {
		PQ_ASSERT(count < CAPACITY);
		ids[count++] = value;
	}
	// Only the tags in use take part, so stale storage never affects a key.
	bool operator<(const VlanStack &other) const {
		return std::lexicographical_compare(begin(), end(), other.begin(), other.end());
	}
	bool operator==(const VlanStack &other) const {
		return count == other.count && std::equal(begin(), end(), other.begin());
	}

private:
	std::array<uint16_t, CAPACITY> ids {};
	uint8_t count = 0;
};

struct DecodedPacket {
	DecodeOutcome outcome = DecodeOutcome::NOT_REQUESTED;
	bool ethernet = false;
	bool network = false;
	bool transport = false;
	bool tcp = false;
	bool udp = false;
	std::array<uint8_t, 6> src_mac {}, dst_mac {};
	uint16_t ether_type = 0;
	VlanStack vlan_ids;
	uint8_t ip_version = 0, ip_protocol = 0, ip_ttl = 0;
	std::array<uint8_t, 16> src_ip {}, dst_ip {};
	uint32_t ip_fragment_offset = 0, ip_id = 0;
	bool ip_more_fragments = false, has_ip_id = false;
	uint16_t src_port = 0, dst_port = 0, tcp_flags = 0, udp_length = 0;
	uint32_t tcp_seq = 0, tcp_ack = 0;
	uint8_t tcp_header_length = 0;
	uint32_t payload_offset = 0, payload_length = 0, payload_declared_length = 0;
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
