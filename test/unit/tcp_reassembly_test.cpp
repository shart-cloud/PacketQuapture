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
	std::cout << "Protocol-neutral TCP checks passed: 1,000 arbitrary binary streams, midstream capture, gaps, and "
	             "conflicts\n";
}
