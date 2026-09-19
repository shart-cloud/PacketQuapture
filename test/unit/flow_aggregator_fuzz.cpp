#include "flow_aggregator.hpp"
#include <cassert>
#include <cstddef>
#include <cstdint>
using namespace packetquapture;
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size > 4096)
		return 0;
	FlowLimits limits;
	limits.tcp_idle_us = limits.udp_idle_us = size ? data[0] : 0;
	FlowAggregator a(limits);
	uint64_t expected = 0, packets = 0, captured = 0, reported = 0, payload = 0;
	uint32_t section = 1;
	auto drain = [&] {
		FlowSummary row;
		while (a.Next(row)) {
			packets += row.orig.packets + row.resp.packets;
			captured += row.orig.captured_bytes + row.resp.captured_bytes;
			reported += row.orig.reported_bytes + row.resp.reported_bytes;
			payload += row.orig.payload_bytes + row.resp.payload_bytes;
			assert(!row.has_timestamp || row.last_timestamp >= row.first_timestamp);
		}
		assert(a.ExpiryCount() <= a.ActiveCount());
	};
	for (size_t i = 0; i + 16 <= size; i += 16) {
		const auto *b = data + i;
		FlowInput x;
		section += b[0] == 255;
		x.section = section;
		x.interface_id = b[1] % 8;
		x.stamp.number = i / 16 + 1;
		x.stamp.has_timestamp = b[2] != 0;
		x.stamp.timestamp = int64_t(b[3]) * 256 + b[4] - 32768;
		x.captured_length = 64;
		x.original_length = 80;
		auto &p = x.packet;
		p.transport = b[5] != 0;
		p.tcp = (b[5] & 1) != 0;
		p.udp = !p.tcp;
		p.ip_version = b[6] & 1 ? 4 : 6;
		p.src_port = b[7] % 8;
		p.dst_port = b[8] % 8;
		p.src_ip[0] = b[9] % 2;
		p.dst_ip[0] = b[10] % 2;
		p.tcp_seq = b[11];
		p.tcp_ack = b[12];
		p.tcp_flags = b[13];
		p.payload_length = 10;
		p.ip_more_fragments = b[14] == 255;
		p.vlan_ids = {uint16_t(b[15] % 2)};
		expected += p.transport && !p.ip_more_fragments;
		a.Push(std::move(x));
		drain();
	}
	a.Finish(section);
	drain();
	assert(packets == expected && captured == packets * 64 && reported == packets * 80 && payload == packets * 10);
	return 0;
}
