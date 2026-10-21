#include "packet_decoder.hpp"

#include "byte_order.hpp"

#include <algorithm>

namespace packetquapture {
namespace {

bool Has(size_t size, size_t offset, size_t length) {
	return offset <= size && length <= size - offset;
}

bool IsExtension(uint8_t protocol) {
	return protocol == 0 || protocol == 43 || protocol == 60 || protocol == 44 || protocol == 51;
}

// Reads only the packet prefix a header needs, so decoding never pulls payload
// bytes from the source. data is valid until the next Ensure call.
struct PrefixReader {
	PacketSource &source;
	size_t size;
	const uint8_t *data;

	explicit PrefixReader(PacketSource &source_p) : source(source_p), size(source_p.Size()), data(nullptr) {
	}
	bool Ensure(size_t start, size_t length) {
		if (!Has(size, start, length)) {
			return false;
		}
		data = source.ReadPrefix(start + length);
		return true;
	}
	// As Ensure, but the header must also lie within the IP datagram ending at end.
	bool EnsureWithin(size_t end, size_t start, size_t length) {
		return Has(end, start, length) && Ensure(start, length);
	}
};

// The position of the next header and the end of the IP datagram that holds it.
struct Cursor {
	size_t offset = 0;
	size_t end = 0;
	uint16_t type = 0;
};

DecodeOutcome DecodeEthernet(PrefixReader &reader, DecodedPacket &result, Cursor &cursor) {
	if (!reader.Ensure(0, 14)) {
		return DecodeOutcome::MALFORMED;
	}
	std::copy_n(reader.data, 6, result.dst_mac.begin());
	std::copy_n(reader.data + 6, 6, result.src_mac.begin());
	cursor.type = ReadBigEndian16(reader.data + 12);
	cursor.offset = 14;
	while (cursor.type == 0x8100 || cursor.type == 0x88a8) {
		if (result.vlan_ids.size() == VlanStack::CAPACITY || !reader.Ensure(cursor.offset, 4)) {
			const auto outcome =
			    result.vlan_ids.size() == VlanStack::CAPACITY ? DecodeOutcome::UNSUPPORTED : DecodeOutcome::MALFORMED;
			// A rejected VLAN stack reports nothing decoded before it.
			result = DecodedPacket();
			return outcome;
		}
		result.vlan_ids.push_back(ReadBigEndian16(reader.data + cursor.offset) & 0x0fffU);
		cursor.type = ReadBigEndian16(reader.data + cursor.offset + 2);
		cursor.offset += 4;
	}
	result.ethernet = true;
	result.ether_type = cursor.type;
	return DecodeOutcome::DECODED;
}

DecodeOutcome DecodeLink(PrefixReader &reader, uint32_t link_type, DecodedPacket &result, Cursor &cursor) {
	if (link_type == 1) {
		return DecodeEthernet(reader, result, cursor);
	}
	if (link_type == 101) { // LINKTYPE_RAW
		if (!reader.Ensure(0, 1)) {
			return DecodeOutcome::MALFORMED;
		}
		const auto version = reader.data[0] >> 4U;
		cursor.type = version == 4 ? 0x0800 : (version == 6 ? 0x86dd : 0);
	} else if (link_type == 228 || link_type == 229) {
		cursor.type = link_type == 228 ? 0x0800 : 0x86dd;
	} else if (link_type == 113 || link_type == 276) { // Linux cooked v1/v2
		const size_t length = link_type == 113 ? 16 : 20;
		if (!reader.Ensure(0, length)) {
			return DecodeOutcome::MALFORMED;
		}
		cursor.type = ReadBigEndian16(reader.data + (link_type == 113 ? 14 : 0));
		cursor.offset = length;
	} else {
		return DecodeOutcome::UNSUPPORTED;
	}
	return DecodeOutcome::DECODED;
}

bool DecodeIPv4(PrefixReader &reader, DecodedPacket &network, Cursor &cursor) {
	const auto offset = cursor.offset;
	if (!reader.Ensure(offset, 20) || (reader.data[offset] >> 4U) != 4) {
		return false;
	}
	const size_t header_length = (reader.data[offset] & 0x0fU) * 4U;
	const size_t total_length = ReadBigEndian16(reader.data + offset + 2);
	if (header_length < 20 || total_length < header_length || !reader.Ensure(offset, header_length)) {
		return false;
	}
	const auto data = reader.data;
	cursor.end = offset + total_length;
	network.ip_version = 4;
	network.ip_protocol = data[offset + 9];
	network.ip_ttl = data[offset + 8];
	network.ip_id = ReadBigEndian16(data + offset + 4);
	network.has_ip_id = true;
	const auto fragment = ReadBigEndian16(data + offset + 6);
	network.ip_fragment_offset = (fragment & 0x1fffU) * 8U;
	network.ip_more_fragments = (fragment & 0x2000U) != 0;
	std::copy_n(data + offset + 12, 4, network.src_ip.begin());
	std::copy_n(data + offset + 16, 4, network.dst_ip.begin());
	cursor.offset += header_length;
	return true;
}

// Consumes one IPv6 extension header, whose type is network.ip_protocol.
bool DecodeIPv6Extension(PrefixReader &reader, DecodedPacket &network, Cursor &cursor) {
	const auto offset = cursor.offset;
	const auto protocol = network.ip_protocol;
	size_t length = (size_t(reader.data[offset + 1]) + 1) * 8;
	if (protocol == 44) {
		if (network.has_ip_id) {
			return false;
		}
		length = 8;
		const auto fragment = ReadBigEndian16(reader.data + offset + 2);
		network.ip_fragment_offset = fragment & 0xfff8U;
		network.ip_more_fragments = (fragment & 1U) != 0;
		network.ip_id = ReadBigEndian32(reader.data + offset + 4);
		network.has_ip_id = true;
	} else if (protocol == 51) {
		length = (size_t(reader.data[offset + 1]) + 2) * 4;
		if (length < 12) {
			return false;
		}
	}
	if (!reader.EnsureWithin(cursor.end, offset, length)) {
		return false;
	}
	network.ip_protocol = reader.data[offset];
	cursor.offset += length;
	return true;
}

DecodeOutcome DecodeIPv6(PrefixReader &reader, DecodedPacket &network, Cursor &cursor) {
	const auto offset = cursor.offset;
	if (!reader.Ensure(offset, 40) || (reader.data[offset] >> 4U) != 6) {
		return DecodeOutcome::MALFORMED;
	}
	const auto data = reader.data;
	cursor.end = offset + 40 + ReadBigEndian16(data + offset + 4);
	network.ip_version = 6;
	network.ip_protocol = data[offset + 6];
	network.ip_ttl = data[offset + 7];
	std::copy_n(data + offset + 8, 16, network.src_ip.begin());
	std::copy_n(data + offset + 24, 16, network.dst_ip.begin());
	cursor.offset += 40;
	unsigned extensions = 0;
	while (IsExtension(network.ip_protocol)) {
		if (++extensions > 16) {
			return DecodeOutcome::UNSUPPORTED;
		}
		if (!reader.EnsureWithin(cursor.end, cursor.offset, 8) || !DecodeIPv6Extension(reader, network, cursor)) {
			return DecodeOutcome::MALFORMED;
		}
		// Later fragments do not start with the next header indicated by the fragment header.
		if (network.ip_fragment_offset != 0) {
			break;
		}
	}
	return DecodeOutcome::DECODED;
}

// Leaves result untouched unless the complete IP header chain validates.
DecodeOutcome DecodeNetwork(PrefixReader &reader, uint32_t link_type, DecodedPacket &result, Cursor &cursor) {
	auto network = result;
	auto outcome = DecodeOutcome::MALFORMED;
	if (cursor.type == 0x0800) {
		outcome = DecodeIPv4(reader, network, cursor) ? DecodeOutcome::DECODED : DecodeOutcome::MALFORMED;
	} else if (cursor.type == 0x86dd) {
		outcome = DecodeIPv6(reader, network, cursor);
	} else {
		outcome = (link_type == 101 && !cursor.type) ? DecodeOutcome::MALFORMED : DecodeOutcome::UNSUPPORTED;
	}
	if (outcome != DecodeOutcome::DECODED) {
		return outcome;
	}
	network.network = true;
	result = network;
	return DecodeOutcome::DECODED;
}

DecodeOutcome DecodeTransport(PrefixReader &reader, DecodedPacket &result, Cursor cursor) {
	const auto offset = cursor.offset;
	auto end = cursor.end;
	size_t header_length;
	if (result.ip_protocol == 6) {
		if (!reader.EnsureWithin(end, offset, 20)) {
			return DecodeOutcome::MALFORMED;
		}
		header_length = (reader.data[offset + 12] >> 4U) * 4U;
		if (header_length < 20 || !reader.EnsureWithin(end, offset, header_length)) {
			return DecodeOutcome::MALFORMED;
		}
		result.tcp = true;
		result.tcp_flags = reader.data[offset + 13];
		result.tcp_seq = ReadBigEndian32(reader.data + offset + 4);
		result.tcp_ack = ReadBigEndian32(reader.data + offset + 8);
		result.tcp_header_length = static_cast<uint8_t>(header_length);
	} else if (result.ip_protocol == 17) {
		header_length = 8;
		if (!reader.EnsureWithin(end, offset, header_length)) {
			return DecodeOutcome::MALFORMED;
		}
		const auto length = ReadBigEndian16(reader.data + offset + 4);
		if (length < 8 || !Has(end, offset, length)) {
			return DecodeOutcome::MALFORMED;
		}
		result.udp = true;
		result.udp_length = length;
		end = offset + length;
	} else {
		return DecodeOutcome::UNSUPPORTED;
	}
	result.transport = true;
	result.src_port = ReadBigEndian16(reader.data + offset);
	result.dst_port = ReadBigEndian16(reader.data + offset + 2);
	result.payload_offset = static_cast<uint32_t>(offset + header_length);
	result.payload_declared_length = static_cast<uint32_t>(end - offset - header_length);
	result.payload_length = static_cast<uint32_t>(std::min(end, reader.size) - offset - header_length);
	return DecodeOutcome::DECODED;
}

} // namespace

DecodedPacket DecodePacket(PacketSource &source, uint32_t link_type, DecodeDepth depth) {
	DecodedPacket result;
	if (depth == DecodeDepth::NONE) {
		return result;
	}
	PrefixReader reader(source);
	if (depth == DecodeDepth::LINK && link_type != 1) {
		result.outcome = DecodeOutcome::UNSUPPORTED;
		return result;
	}
	Cursor cursor;
	result.outcome = DecodeLink(reader, link_type, result, cursor);
	if (result.outcome != DecodeOutcome::DECODED || depth == DecodeDepth::LINK) {
		return result;
	}
	result.outcome = DecodeNetwork(reader, link_type, result, cursor);
	if (result.outcome != DecodeOutcome::DECODED) {
		return result;
	}
	if (depth == DecodeDepth::NETWORK || result.ip_fragment_offset != 0 || result.ip_more_fragments) {
		result.outcome =
		    result.ip_fragment_offset || result.ip_more_fragments ? DecodeOutcome::FRAGMENT : DecodeOutcome::DECODED;
		return result;
	}
	result.outcome = DecodeTransport(reader, result, cursor);
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
