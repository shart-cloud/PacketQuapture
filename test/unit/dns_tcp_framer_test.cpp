#include "dns_tcp_framer.hpp"

#include <algorithm>
#include <cassert>
#include <iostream>
#include <random>
#include <vector>

using namespace packetquapture;

static TcpFlowKey Key(uint16_t port = 40000) {
	TcpFlowKey key;
	key.ip_version = 4;
	key.src_ip[0] = 10;
	key.dst_ip[0] = 20;
	key.src_port = port;
	key.dst_port = 53;
	return key;
}
static PacketStamp Stamp(uint64_t number) {
	PacketStamp stamp;
	stamp.number = number;
	stamp.has_timestamp = true;
	stamp.timestamp = static_cast<int64_t>(number * 1000);
	return stamp;
}
static std::vector<TcpDnsMessage> Add(TcpReassembler &r, TcpFlowKey key, uint32_t seq, uint8_t flags,
                                      const std::vector<uint8_t> &bytes, uint64_t stamp = 1) {
	return FrameTcpDns(
	    r.Add(key, seq, flags, bytes.data(), bytes.size(), static_cast<uint32_t>(bytes.size()), Stamp(stamp)));
}
static std::vector<TcpDnsMessage> Finish(TcpReassembler &r) {
	std::vector<TcpDnsMessage> messages;
	while (!r.Empty()) {
		auto batch = FrameTcpDns(r.FinishNext());
		messages.insert(messages.end(), batch.begin(), batch.end());
	}
	assert(r.BufferedBytes() == 0 && r.FlowCount() == 0);
	return messages;
}

int main() {
	std::vector<uint8_t> frame(31, 7);
	frame[0] = 0;
	frame[1] = 29;
	std::vector<uint8_t> body(frame.begin() + 2, frame.end());
	std::mt19937 random(123456);
	for (unsigned iteration = 0; iteration < 2000; ++iteration) {
		TcpReassembler r;
		const uint32_t syn = iteration % 2 ? 0xfffffff8U : 100U;
		std::vector<uint8_t> stream = frame;
		stream.insert(stream.end(), frame.begin(), frame.end());
		std::vector<size_t> offsets;
		for (size_t offset = 0; offset < stream.size(); offset += 3) {
			offsets.push_back(offset);
		}
		std::shuffle(offsets.begin(), offsets.end(), random);
		if (iteration % 3) {
			Add(r, Key(), syn, 2, {});
		}
		for (size_t i = 0; i < offsets.size(); ++i) {
			const auto offset = offsets[i];
			std::vector<uint8_t> bytes(stream.begin() + offset, stream.begin() + std::min(offset + 3, stream.size()));
			assert(Add(r, Key(), syn + 1 + static_cast<uint32_t>(offset), 0x18, bytes, i + 2).empty());
			assert(Add(r, Key(), syn + 1 + static_cast<uint32_t>(offset), 0x18, bytes, i + 100).empty());
		}
		if (iteration % 3 == 0) {
			Add(r, Key(), syn, 2, {});
		}
		Add(r, Key(), syn + 1 + static_cast<uint32_t>(stream.size()), 1, {});
		auto messages = Finish(r);
		assert(messages.size() == 2);
		for (size_t i = 0; i < 2; ++i) {
			assert(messages[i].status == "complete" && messages[i].data == body);
			assert(messages[i].sequence == static_cast<uint32_t>(syn + 1 + i * frame.size()));
			assert(messages[i].message_number == i + 1);
		}
	}
	{
		TcpReassembler r;
		Add(r, Key(), 100, 2, {});
		Add(r, Key(), 101, 0x18, frame);
		auto bad = frame;
		bad[10] ^= 1;
		Add(r, Key(), 101, 0x18, bad);
		auto messages = Finish(r);
		assert(messages.size() == 1 && messages[0].status == "conflict");
	}
	{
		TcpReassembler r;
		Add(r, Key(), 100, 2, {});
		Add(r, Key(), 101, 0x18, std::vector<uint8_t>(frame.begin(), frame.begin() + 10));
		Add(r, Key(), 112, 0x18, std::vector<uint8_t>(frame.begin() + 11, frame.end()));
		auto messages = Finish(r);
		assert(messages.size() == 1 && messages[0].status == "incomplete");
	}
	{
		TcpReassembler r;
		Add(r, Key(), 101, 0x18, frame);
		assert(Finish(r)[0].status == "unanchored");
	}
	{
		TcpReassembler r;
		Add(r, Key(), 100, 2, frame);
		auto messages = Add(r, Key(), 200, 2, {});
		assert(messages.size() == 1 && messages[0].data == body);
		Add(r, Key(), 201, 0x18, frame);
		auto next = Finish(r);
		assert(next.size() == 1 && next[0].stream_id != messages[0].stream_id);
	}
	{
		TcpReassembler r;
		Add(r, Key(), 100, 2, {});
		Add(r, Key().Reverse(), 200, 0x12, {});
		Add(r, Key(), 101, 0x18, {0});
		Add(r, Key().Reverse(), 201, 0x18, {0});
		auto messages = Add(r, Key(), 102, 4, {});
		assert(messages.size() == 2 && r.Empty());
		assert(messages[0].status == "incomplete" && messages[1].status == "incomplete");
		assert(r.BufferedBytes() == 0);
	}
	for (unsigned kind = 0; kind < 5; ++kind) {
		TcpReassemblyLimits limits;
		if (kind == 0) {
			limits.max_stream_bytes = 10;
		}
		if (kind == 1) {
			limits.max_total_bytes = 10;
		}
		if (kind == 2) {
			limits.max_segments = 0;
		}
		if (kind == 3) {
			limits.max_total_segments = 0;
		}
		if (kind == 4) {
			limits.max_flows = 0;
		}
		TcpReassembler r(limits);
		auto immediate = Add(r, Key(), 100, 2, frame);
		auto messages = kind == 4 ? immediate : Finish(r);
		assert(messages.size() == 1 && messages[0].status == "limit");
		assert(r.BufferedBytes() == 0);
	}
	{
		TcpReassemblyLimits limits;
		limits.max_total_bytes = frame.size();
		TcpReassembler r(limits);
		Add(r, Key(), 100, 2, frame);
		Add(r, Key(40001), 100, 2, frame);
		auto messages = Finish(r);
		assert(messages.size() == 2 && messages[0].status == "complete" && messages[1].status == "limit");
	}
	{
		TcpReassemblyLimits limits;
		limits.max_flows = 16;
		limits.max_total_bytes = 8192;
		limits.max_stream_bytes = 512;
		limits.max_segments = 16;
		limits.max_total_segments = 128;
		TcpReassembler r(limits);
		for (unsigned i = 0; i < 20000; ++i) {
			std::vector<uint8_t> data(random() % 64);
			for (auto &byte : data) {
				byte = static_cast<uint8_t>(random());
			}
			const auto declared = static_cast<uint32_t>(data.size() + random() % 8);
			auto messages =
			    r.Add(Key(static_cast<uint16_t>(40000 + random() % 20)), random() % 1024,
			          static_cast<uint8_t>(random() & 0x1fU), data.data(), data.size(), declared, Stamp(i + 1));
			assert(r.BufferedBytes() <= limits.max_total_bytes && r.FlowCount() <= limits.max_flows);
			for (const auto &message : messages) {
				assert(!message.status.empty() && message.captured_bytes <= limits.max_stream_bytes);
			}
			if (i % 300 == 0) {
				Finish(r);
			}
		}
		Finish(r);
	}
	{
		TcpReassembler r;
		Add(r, Key(), 100, 2, frame);
		DnsFramingLimits limits;
		limits.max_messages = 0;
		auto messages = FrameTcpDns(r.FinishNext(), limits);
		assert(messages.size() == 1 && messages[0].status == "limit");
	}
	std::cout << "TCP reassembly checks passed: 2,000 reordered/retransmitted/wrapped streams and 20,000 bounded "
	             "random packets\n";
}
