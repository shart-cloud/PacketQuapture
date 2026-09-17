#include "packet_decoder.hpp"

#include <algorithm>

namespace packetquapture {
namespace {

uint16_t U16(const uint8_t *p) {
	return (uint16_t(p[0]) << 8U) | p[1];
}

uint32_t U32(const uint8_t *p) {
	return (uint32_t(U16(p)) << 16U) | U16(p + 2);
}

bool Has(size_t size, size_t offset, size_t length) {
	return offset <= size && length <= size - offset;
}

bool IsExtension(uint8_t protocol) {
	return protocol == 0 || protocol == 43 || protocol == 60 || protocol == 44 || protocol == 51;
}

} // namespace

DecodedPacket DecodePacket(PacketSource &source, uint32_t link_type, DecodeDepth depth) {
	DecodedPacket result;
	if (depth == DecodeDepth::NONE) {
		return result;
	}
	const auto size = source.Size();
	const uint8_t *data = nullptr;
	auto ensure = [&](size_t start, size_t length) {
		if (!Has(size, start, length)) {
			return false;
		}
		data = source.ReadPrefix(start + length);
		return true;
	};
	if (depth == DecodeDepth::LINK && link_type != 1) {
		return result;
	}
	size_t offset = 0;
	uint16_t type = 0;
	if (link_type == 1) {
		if (!ensure(0, 14)) {
			return result;
		}
		std::copy_n(data, 6, result.dst_mac.begin());
		std::copy_n(data + 6, 6, result.src_mac.begin());
		type = U16(data + 12);
		offset = 14;
		while (type == 0x8100 || type == 0x88a8) {
			if (result.vlan_ids.size() == 8 || !ensure(offset, 4)) {
				return DecodedPacket();
			}
			result.vlan_ids.push_back(U16(data + offset) & 0x0fffU);
			type = U16(data + offset + 2);
			offset += 4;
		}
		result.ethernet = true;
		result.ether_type = type;
	} else if (link_type == 101) { // LINKTYPE_RAW
		if (!ensure(0, 1)) {
			return result;
		}
		type = (data[0] >> 4U) == 4 ? 0x0800 : ((data[0] >> 4U) == 6 ? 0x86dd : 0);
	} else if (link_type == 228 || link_type == 229) {
		type = link_type == 228 ? 0x0800 : 0x86dd;
	} else if (link_type == 113 || link_type == 276) { // Linux cooked v1/v2
		const size_t length = link_type == 113 ? 16 : 20;
		if (!ensure(0, length)) {
			return result;
		}
		type = U16(data + (link_type == 113 ? 14 : 0));
		offset = length;
	} else {
		return result;
	}
	if (depth == DecodeDepth::LINK) {
		return result;
	}

	// Commit network fields only after validating the complete IP header chain.
	auto network = result;
	size_t end = 0;
	if (type == 0x0800) {
		if (!ensure(offset, 20) || (data[offset] >> 4U) != 4) {
			return result;
		}
		const size_t header_length = (data[offset] & 0x0fU) * 4U;
		const size_t total_length = U16(data + offset + 2);
		if (header_length < 20 || total_length < header_length || !ensure(offset, header_length)) {
			return result;
		}
		end = offset + total_length;
		network.ip_version = 4;
		network.ip_protocol = data[offset + 9];
		network.ip_ttl = data[offset + 8];
		network.ip_id = U16(data + offset + 4);
		network.has_ip_id = true;
		const auto fragment = U16(data + offset + 6);
		network.ip_fragment_offset = (fragment & 0x1fffU) * 8U;
		network.ip_more_fragments = (fragment & 0x2000U) != 0;
		std::copy_n(data + offset + 12, 4, network.src_ip.begin());
		std::copy_n(data + offset + 16, 4, network.dst_ip.begin());
		offset += header_length;
	} else if (type == 0x86dd) {
		if (!ensure(offset, 40) || (data[offset] >> 4U) != 6) {
			return result;
		}
		end = offset + 40 + U16(data + offset + 4);
		network.ip_version = 6;
		network.ip_protocol = data[offset + 6];
		network.ip_ttl = data[offset + 7];
		std::copy_n(data + offset + 8, 16, network.src_ip.begin());
		std::copy_n(data + offset + 24, 16, network.dst_ip.begin());
		offset += 40;
		unsigned extensions = 0;
		while (IsExtension(network.ip_protocol)) {
			if (++extensions > 16 || (!Has(end, offset, 8) || !ensure(offset, 8))) {
				return result;
			}
			const auto protocol = network.ip_protocol;
			size_t length = (size_t(data[offset + 1]) + 1) * 8;
			if (protocol == 44) {
				if (network.has_ip_id) {
					return result;
				}
				length = 8;
				const auto fragment = U16(data + offset + 2);
				network.ip_fragment_offset = fragment & 0xfff8U;
				network.ip_more_fragments = (fragment & 1U) != 0;
				network.ip_id = U32(data + offset + 4);
				network.has_ip_id = true;
			} else if (protocol == 51) {
				length = (size_t(data[offset + 1]) + 2) * 4;
				if (length < 12) {
					return result;
				}
			}
			if ((!Has(end, offset, length) || !ensure(offset, length))) {
				return result;
			}
			network.ip_protocol = data[offset];
			offset += length;
			// Later fragments do not start with the next header indicated by the fragment header.
			if (network.ip_fragment_offset != 0) {
				break;
			}
		}
	} else {
		return result;
	}
	network.network = true;
	result = network;
	if (depth == DecodeDepth::NETWORK || result.ip_fragment_offset != 0 || result.ip_more_fragments) {
		return result;
	}

	size_t header_length;
	if (result.ip_protocol == 6) {
		if ((!Has(end, offset, 20) || !ensure(offset, 20))) {
			return result;
		}
		header_length = (data[offset + 12] >> 4U) * 4U;
		if (header_length < 20 || (!Has(end, offset, header_length) || !ensure(offset, header_length))) {
			return result;
		}
		result.tcp = true;
		result.tcp_flags = data[offset + 13];
		result.tcp_seq = U32(data + offset + 4);
		result.tcp_ack = U32(data + offset + 8);
		result.tcp_header_length = static_cast<uint8_t>(header_length);
	} else if (result.ip_protocol == 17) {
		header_length = 8;
		if ((!Has(end, offset, header_length) || !ensure(offset, header_length))) {
			return result;
		}
		const auto length = U16(data + offset + 4);
		if (length < 8 || !Has(end, offset, length)) {
			return result;
		}
		result.udp = true;
		result.udp_length = length;
		end = offset + length;
	} else {
		return result;
	}
	result.transport = true;
	result.src_port = U16(data + offset);
	result.dst_port = U16(data + offset + 2);
	result.payload_offset = static_cast<uint32_t>(offset + header_length);
	result.payload_declared_length = static_cast<uint32_t>(end - offset - header_length);
	result.payload_length = static_cast<uint32_t>(std::min(end, size) - offset - header_length);
	return result;
}

DecodedPacket DecodePacket(PacketView packet, DecodeDepth depth) {
	class MemorySource : public PacketSource {
	public:
		explicit MemorySource(PacketView view_p) : view(view_p) {
		}
		size_t Size() const override {
			return view.size;
		}
		const uint8_t *ReadPrefix(size_t) override {
			return view.data;
		}

	private:
		PacketView view;
	};
	MemorySource source(packet);
	return DecodePacket(source, packet.link_type, depth);
}

} // namespace packetquapture
