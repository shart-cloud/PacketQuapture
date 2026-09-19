#include "flow_aggregator.hpp"
#include <cassert>
#include <iostream>
#include <limits>
#include <random>
#include <vector>
using namespace packetquapture;
static FlowInput Packet(uint64_t n, int64_t t, bool tcp = false, uint16_t flags = 0, bool reverse = false) {
	FlowInput x;
	x.section = 1;
	x.stamp = {n, true, t};
	x.captured_length = 64;
	x.original_length = 80;
	auto &p = x.packet;
	p.transport = p.network = true;
	p.tcp = tcp;
	p.udp = !tcp;
	p.ip_version = 4;
	p.src_ip[0] = reverse ? 2 : 1;
	p.dst_ip[0] = reverse ? 1 : 2;
	p.src_port = reverse ? 443 : 50000;
	p.dst_port = reverse ? 50000 : 443;
	p.payload_length = 10;
	p.tcp_flags = flags;
	p.tcp_seq = reverse ? 200 : 100;
	return x;
}
static void Push(FlowAggregator &a, FlowInput x, std::vector<FlowSummary> &rows) {
	a.Push(std::move(x));
	FlowSummary row;
	while (a.Next(row))
		rows.push_back(std::move(row));
	assert(a.ExpiryCount() <= a.ActiveCount());
}
static void Finish(FlowAggregator &a, std::vector<FlowSummary> &rows, uint32_t section = 1) {
	a.Finish(section);
	FlowSummary row;
	while (a.Next(row))
		rows.push_back(std::move(row));
	assert(a.ActiveCount() == 0 && a.ExpiryCount() == 0);
}
int main() {
	FlowLimits limits;
	limits.tcp_idle_us = limits.udp_idle_us = 10;
	{
		FlowAggregator a(limits);
		std::vector<FlowSummary> rows;
		Push(a, Packet(1, 0), rows);
		Push(a, Packet(2, 10, false, 0, true), rows); // exact threshold stays
		Push(a, Packet(3, 21), rows);                 // strictly beyond threshold splits
		assert(rows.size() == 1 && rows[0].finalized_by == "idle_timeout");
		assert(rows[0].orig.packets == 1 && rows[0].resp.packets == 1);
		Push(a, Packet(4, 19), rows); // late joins active
		Finish(a, rows);
		assert(rows.size() == 2 && rows[1].late_packets == 1);
		assert(rows[1].first_timestamp == 19 && rows[1].last_timestamp == 21);
	}
	{
		FlowAggregator a(limits);
		std::vector<FlowSummary> rows;
		Push(a, Packet(1, 10), rows);
		auto missing = Packet(2, 0);
		missing.stamp.has_timestamp = false;
		Push(a, missing, rows);
		auto other = Packet(3, 1000);
		other.packet.transport = false;
		Push(a, other, rows);
		Push(a, Packet(4, 0), rows);
		Finish(a, rows);
		assert(rows.size() == 1 && rows[0].missing_timestamps == 1 && rows[0].late_packets == 1);
		assert(rows[0].orig.packets == 3 && rows[0].first_timestamp == 0);
	}
	{
		FlowAggregator a(limits);
		std::vector<FlowSummary> rows;
		Push(a, Packet(1, 0), rows);
		auto ineligible = Packet(2, 11);
		ineligible.packet.transport = false;
		Push(a, ineligible, rows);
		assert(rows.size() == 1 && rows[0].last_packet == 1);
		Push(a, Packet(3, 1), rows);
		Finish(a, rows);
		assert(rows[1].late_packets == 1 && rows[1].first_packet == 3);
	}
	{
		FlowAggregator a(limits);
		std::vector<FlowSummary> rows;
		Push(a, Packet(1, 0, true, 2), rows);
		Push(a, Packet(2, 1, true, 2), rows); // initiating retransmission
		auto synack = Packet(3, 2, true, 0x12, true);
		synack.packet.tcp_ack = 101;
		Push(a, synack, rows);
		auto ack = Packet(4, 3, true, 0x10);
		ack.packet.tcp_seq = 101;
		ack.packet.tcp_ack = 201;
		Push(a, ack, rows);
		Push(a, Packet(5, 4, true, 1), rows);
		Push(a, Packet(6, 5, true, 0x10, true), rows); // FIN tail
		Push(a, Packet(7, 6, true, 2), rows);          // same sequence after handshake splits
		assert(rows.size() == 1 && rows[0].handshake_complete && rows[0].fin_seen);
		assert(rows[0].orig.packets == 4 && rows[0].resp.packets == 2);
		Push(a, Packet(8, 7, true, 4, true), rows);
		assert(rows.size() == 2 && rows[1].reset_seen && rows[1].finalized_by == "reset");
		Push(a, Packet(9, 8, true, 0x10), rows);
		Finish(a, rows);
		assert(rows[2].originator_basis == "first_packet");
	}
	{
		FlowAggregator a(limits);
		std::vector<FlowSummary> rows;
		Push(a, Packet(1, 0, true, 2), rows);
		Push(a, Packet(2, 1, true, 2, true), rows);
		auto different = Packet(3, 2, true, 2);
		different.packet.tcp_seq++;
		Push(a, different, rows);
		Finish(a, rows);
		assert(rows.size() == 2 && rows[0].simultaneous_open && rows[0].finalized_by == "tuple_reuse");
	}
	{
		FlowAggregator a(limits);
		std::vector<FlowSummary> rows;
		Push(a, Packet(1, 0, true, 0x12, true), rows);
		Push(a, Packet(2, 1, true, 0x10), rows);
		Finish(a, rows);
		assert(rows[0].originator_basis == "syn_ack" && rows[0].orig.packets == 1 && rows[0].resp.packets == 1);
		assert(!rows[0].handshake_complete);
	}
	{
		FlowAggregator a(limits);
		std::vector<FlowSummary> rows;
		Push(a, Packet(1, 0), rows);
		auto x = Packet(2, 1000);
		x.interface_id = 1;
		Push(a, x, rows); // other interface cannot expire interface zero
		x = Packet(3, 1);
		x.packet.vlan_ids = {2, 3};
		Push(a, x, rows);
		assert(rows.empty() && a.ActiveCount() == 3);
		x = Packet(4, -100);
		x.section = 2;
		Push(a, x, rows);
		assert(rows.size() == 3);
		for (auto &r : rows)
			assert(r.finalized_by == "section_boundary");
		Finish(a, rows, 3); // trailing empty section still finalizes at boundary
		assert(rows[3].late_packets == 0 && rows[3].finalized_by == "section_boundary");
	}
	{
		FlowAggregator a(limits);
		std::vector<FlowSummary> rows;
		auto x = Packet(1, std::numeric_limits<int64_t>::max());
		x.packet.dst_ip = x.packet.src_ip;
		x.packet.dst_port = x.packet.src_port;
		Push(a, x, rows);
		assert(a.ExpiryCount() == 0);
		Finish(a, rows);
		assert(rows[0].equal_endpoints);
	}
	{
		auto small = limits;
		small.max_flows = 1;
		FlowAggregator a(small);
		std::vector<FlowSummary> rows;
		Push(a, Packet(1, 0), rows);
		auto x = Packet(2, 0);
		x.packet.src_port++;
		bool failed = false;
		try {
			Push(a, x, rows);
		} catch (const std::runtime_error &) {
			failed = true;
		}
		assert(failed);
	}

	{
		FlowAggregator a(limits);
		std::vector<FlowSummary> rows;
		Push(a, Packet(1, 0, true, 2), rows);
		Push(a, Packet(2, 1, true, 0x10), rows); // handshake response was missed
		Push(a, Packet(3, 2, true, 2), rows);    // sequence reuse after ACK splits
		Finish(a, rows);
		assert(rows.size() == 2 && rows[0].finalized_by == "tuple_reuse" && !rows[0].handshake_complete);
	}
	// Independent single-tuple UDP reference: capture-order timeout, late and missing
	// timestamps, extrema, byte conservation. Also stress repeated expiry updates.
	std::mt19937 rng(93452);
	for (int run = 0; run < 200; ++run) {
		auto l = limits;
		if (run % 3 == 0)
			l.udp_idle_us = 0;
		FlowAggregator a(l);
		std::vector<FlowSummary> rows;
		struct Ref {
			uint64_t packets = 0, missing = 0, late = 0;
			int64_t lo = 0, hi = 0;
			bool timed = false;
		} current;
		std::vector<Ref> expected;
		int64_t watermark = 0;
		bool has_watermark = false;
		for (uint64_t n = 1; n <= 2000; ++n) {
			auto x = Packet(n, static_cast<int64_t>(n * 3) - rng() % 30);
			x.stamp.has_timestamp = rng() % 1000 != 0;
			bool late = x.stamp.has_timestamp && has_watermark && x.stamp.timestamp < watermark;
			if (x.stamp.has_timestamp) {
				watermark = has_watermark ? std::max(watermark, x.stamp.timestamp) : x.stamp.timestamp;
				has_watermark = true;
			}
			if (current.packets && current.timed && !current.missing && l.udp_idle_us &&
			    watermark > current.hi + l.udp_idle_us) {
				expected.push_back(current);
				current = Ref();
			}
			++current.packets;
			current.late += late;
			if (x.stamp.has_timestamp) {
				current.lo = current.timed ? std::min(current.lo, x.stamp.timestamp) : x.stamp.timestamp;
				current.hi = current.timed ? std::max(current.hi, x.stamp.timestamp) : x.stamp.timestamp;
				current.timed = true;
			} else
				++current.missing;
			Push(a, x, rows);
		}
		expected.push_back(current);
		Finish(a, rows);
		assert(expected.size() == rows.size());
		uint64_t total = 0;
		for (size_t i = 0; i < rows.size(); ++i) {
			const auto &r = rows[i];
			const auto &e = expected[i];
			assert(r.orig.packets == e.packets && r.orig.captured_bytes == e.packets * 64);
			assert(r.orig.reported_bytes == e.packets * 80 && r.orig.payload_bytes == e.packets * 10);
			assert(r.missing_timestamps == e.missing && r.late_packets == e.late);
			assert(r.has_timestamp == e.timed && r.first_timestamp == e.lo && r.last_timestamp == e.hi);
			total += r.orig.packets;
		}
		assert(total == 2000);
	}
	std::cout << "flow fixtures and 400000 reference packets passed; state=" << FlowAggregator::StateSize()
	          << " bytes\n";
}
