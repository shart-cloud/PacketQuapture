#include "tcp_reassembly.hpp"

#include <algorithm>
#include <cassert>
#include <iostream>
#include <random>

using namespace packetquapture;

static TcpFlowKey Key() {
	TcpFlowKey key;
	key.src_port = 50000;
	key.dst_port = 443;
	return key;
}
static PacketStamp Stamp(uint64_t number) {
	PacketStamp stamp;
	stamp.number = number;
	return stamp;
}
static void Add(TcpReassembler &r, uint32_t sequence, const std::vector<uint8_t> &data, uint64_t number,
                uint8_t flags = 0x18) {
	assert(r.Add(Key(), sequence, flags, data.data(), data.size(), static_cast<uint32_t>(data.size()), Stamp(number))
	           .empty());
}

static TcpFlowKey Client(uint16_t port, uint32_t interface_id = 0) {
	auto key = Key();
	key.src_port = port;
	key.interface_id = interface_id;
	return key;
}
static PacketStamp At(uint64_t number, int64_t seconds) {
	auto stamp = Stamp(number);
	stamp.has_timestamp = true;
	stamp.timestamp = seconds * 1000000;
	return stamp;
}
static std::vector<TcpStream> Send(TcpReassembler &r, const TcpFlowKey &key, uint32_t sequence, uint8_t flags,
                                   const std::vector<uint8_t> &data, PacketStamp stamp) {
	return r.Add(key, sequence, flags, data.data(), data.size(), static_cast<uint32_t>(data.size()), stamp);
}

// Directions that go quiet, such as scans and abandoned connections, must not hold
// the table forever. Idle ones are finalized as idle_timeout, as read_flows does.
static void TestIdleEviction() {
	const int64_t idle = TcpReassemblyLimits().tcp_idle_us / 1000000;
	assert(idle == 300);
	{
		// A full table of half-open directions no longer turns later traffic into limit rows.
		TcpReassembler r;
		for (uint16_t i = 0; i < 1024; ++i) {
			assert(Send(r, Client(static_cast<uint16_t>(10000 + i)), 100, 2, {}, At(i + 1, 0)).empty());
		}
		assert(r.FlowCount() == 1024);
		auto full = Send(r, Client(9000), 100, 2, {}, At(2000, idle));
		assert(full.size() == 1 && full[0].status == "limit"); // exactly the timeout is not yet idle
		auto streams = Send(r, Client(9001), 100, 2, {}, At(2001, idle + 1));
		assert(streams.empty()); // bare SYNs carry no bytes to report
		assert(r.FlowCount() == 1);
		Send(r, Client(9001), 101, 0x18, {'h', 'i'}, At(2002, idle + 1));
		auto rest = r.FinishNext();
		assert(rest.size() == 1 && rest[0].status == "contiguous" && rest[0].finalized_by == "eof");
		assert(r.Empty());
	}
	{
		// An idle direction with data is reported with its bytes, not as a diagnostic.
		TcpReassembler r;
		Send(r, Client(1), 100, 2, {}, At(1, 0));
		Send(r, Client(1), 101, 0x18, {'a', 'b', 'c'}, At(2, 10));
		Send(r, Client(2), 100, 2, {}, At(3, 200));
		Send(r, Client(2), 101, 0x18, {'x'}, At(4, 250)); // activity moves the deadline
		auto evicted = Send(r, Client(3), 100, 2, {}, At(5, 10 + idle + 1));
		assert(evicted.size() == 1 && evicted[0].key.src_port == 1);
		assert(evicted[0].status == "contiguous" && evicted[0].finalized_by == "idle_timeout");
		assert(evicted[0].chunks.size() == 1 && evicted[0].chunks[0].data == std::vector<uint8_t>({'a', 'b', 'c'}));
		assert(r.FlowCount() == 2 && r.BufferedBytes() == 1);
		// Traffic after eviction starts a new direction, which lacks its SYN.
		Send(r, Client(1), 104, 0x18, {'d'}, At(6, 10 + idle + 2));
		assert(r.FlowCount() == 3);
		std::vector<TcpStream> rest;
		while (!r.Empty()) {
			auto next = r.FinishNext();
			rest.insert(rest.end(), next.begin(), next.end());
		}
		size_t resumed = 0;
		for (const auto &stream : rest) {
			if (stream.key.src_port == 1) {
				assert(stream.status == "unanchored" && stream.stream_id != evicted[0].stream_id);
				++resumed;
			}
		}
		assert(resumed == 1 && r.BufferedBytes() == 0);
	}
	{
		// Without timestamps there is no clock, so nothing is evicted.
		TcpReassembler r;
		Send(r, Client(1), 100, 2, {}, Stamp(1));
		Send(r, Client(1), 101, 0x18, {'a'}, Stamp(2));
		assert(Send(r, Client(2), 100, 2, {}, At(3, 10 * idle)).empty());
		assert(r.FlowCount() == 2);
	}
	{
		// Each interface keeps its own clock, as read_flows does: one interface's
		// timestamps say nothing about how long another has been quiet.
		TcpReassembler r;
		Send(r, Client(1, 0), 100, 2, {}, At(1, 0));
		Send(r, Client(1, 0), 101, 0x18, {'a'}, At(2, 0));
		assert(Send(r, Client(2, 1), 100, 2, {}, At(3, 10 * idle)).empty());
		assert(r.FlowCount() == 2);
		auto evicted = Send(r, Client(3, 0), 100, 2, {}, At(4, idle + 1));
		assert(evicted.size() == 1 && evicted[0].key.src_port == 1 && evicted[0].finalized_by == "idle_timeout");
	}
	{
		// Timestamps before 1970 are negative; a direction is not idle just for that.
		TcpReassembler r;
		Send(r, Client(1), 100, 2, {}, At(1, -1000));
		Send(r, Client(1), 101, 0x18, {'a'}, At(2, -1000));
		assert(Send(r, Client(2), 100, 2, {}, At(3, -999)).empty());
		assert(r.FlowCount() == 2);
	}
	{
		// A zero timeout disables eviction.
		TcpReassemblyLimits limits;
		limits.tcp_idle_us = 0;
		TcpReassembler r(limits);
		Send(r, Client(1), 100, 2, {}, At(1, 0));
		Send(r, Client(1), 101, 0x18, {'a'}, At(2, 0));
		assert(Send(r, Client(2), 100, 2, {}, At(3, 10 * idle)).empty());
		assert(r.FlowCount() == 2);
	}
}

int main() {
	std::mt19937 random(998877);
	for (unsigned run = 0; run < 1000; ++run) {
		TcpReassembler r;
		std::vector<uint8_t> data(256);
		for (auto &byte : data) {
			byte = static_cast<uint8_t>(random());
		}
		const uint32_t base = run % 3 ? 100 : 0xfffffff8U;
		const bool syn = (run % 2) == 0;
		if (syn) {
			Add(r, base - 1, {}, 1, 2);
		}
		std::vector<size_t> offsets;
		for (size_t i = 0; i < data.size(); i += 31) {
			offsets.push_back(i);
		}
		std::shuffle(offsets.begin(), offsets.end(), random);
		for (size_t i = 0; i < offsets.size(); ++i) {
			const auto offset = offsets[i];
			std::vector<uint8_t> bytes(data.begin() + offset, data.begin() + std::min(offset + 31, data.size()));
			Add(r, base + static_cast<uint32_t>(offset), bytes, i + 2);
			Add(r, base + static_cast<uint32_t>(offset), bytes, i + 100);
		}
		auto streams = r.FinishNext();
		assert(streams.size() == 1);
		const auto &stream = streams[0];
		assert(stream.status == (syn ? "contiguous" : "unanchored"));
		assert(stream.syn_seen == syn && stream.sequence == base);
		assert(stream.chunks.size() == 1 && stream.chunks[0].data == data && stream.gaps.empty());
		assert(stream.captured_bytes == 256 && stream.expected_bytes == 256 && stream.finalized_by == "eof");
		assert(stream.chunks[0].Provenance(0, 256).second.number < 100);
		assert(r.Empty() && r.BufferedBytes() == 0);
	}
	for (bool syn : {false, true}) {
		TcpReassembler r;
		if (syn) {
			Add(r, 100, {}, 1, 2);
		}
		Add(r, 105, {'E', 'F'}, 2);
		Add(r, 101, {'A', 'B'}, 3);
		auto stream = r.FinishNext()[0];
		assert(stream.sequence == 101 && stream.chunks.size() == 2);
		assert(stream.gaps.size() == 1 && stream.gaps[0].offset == 2 && stream.gaps[0].length == 2);
		assert(stream.chunks[0].offset == 0 && stream.chunks[1].offset == 4);
		assert(stream.chunks[0].data == std::vector<uint8_t>({'A', 'B'}));
		assert(stream.chunks[1].data == std::vector<uint8_t>({'E', 'F'}));
		assert(stream.captured_bytes == 4 && stream.expected_bytes == 6);
		assert(stream.status == (syn ? "gapped" : "unanchored"));
	}
	{
		TcpReassembler r;
		Add(r, 100, {}, 1, 2);
		Add(r, 101, {0, 255, 0}, 2);
		Add(r, 102, {254}, 3);
		auto stream = r.FinishNext()[0];
		assert(stream.status == "conflict" && stream.chunks.empty());
	}
	TestIdleEviction();
	std::cout << "Protocol-neutral TCP checks passed: 1,000 arbitrary binary streams, midstream capture, gaps, "
	             "conflicts, and idle eviction\n";
}
