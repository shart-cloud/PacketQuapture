#include "pcap_writer.hpp"
#include <algorithm>
#include <fstream>
#include <functional>
#include <iostream>
#include <limits>
#include <memory>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>
#ifdef PCAP_ORACLE
#include <pcap/pcap.h>
#endif
using namespace packetquapture;
static void Require(bool value, const char *message) {
	if (!value)
		throw std::runtime_error(message);
}
template <class F>
static void Reject(F operation) {
	bool threw = false;
	try {
		operation();
	} catch (const std::exception &) {
		threw = true;
	}
	Require(threw, "Expected rejection");
}
struct MemoryOutput : PcapOutput {
	std::vector<uint8_t> data;
	size_t position = 0, written = 0, calls = 0, largest = 0;
	size_t short_limit = std::numeric_limits<size_t>::max();
	size_t fail_after = std::numeric_limits<size_t>::max();
	unsigned seeks = 0, fail_seek = 0;
	bool zero = false, excessive = false;
	size_t Write(const uint8_t *source, size_t size) override {
		++calls;
		largest = std::max(largest, size);
		if (zero)
			return 0;
		if (excessive)
			return size + 1;
		if (written >= fail_after)
			throw std::runtime_error("injected disk full/interruption");
		auto count = std::min(std::min(size, short_limit), fail_after - written);
		if (position + count > data.size())
			data.resize(position + count);
		std::copy(source, source + count, data.begin() + position);
		position += count;
		written += count;
		return count;
	}
	void Seek(uint64_t offset) override {
		if (++seeks == fail_seek)
			throw std::runtime_error("injected seek failure");
		if (offset > data.size())
			throw std::runtime_error("seek beyond output");
		position = static_cast<size_t>(offset);
	}
};
static uint32_t U32(const std::vector<uint8_t> &data, size_t offset) {
	Require(offset + 4 <= data.size(), "Missing encoded field");
	return uint32_t(data[offset]) | uint32_t(data[offset + 1]) << 8 | uint32_t(data[offset + 2]) << 16 |
	       uint32_t(data[offset + 3]) << 24;
}
static const int64_t LAST_TIME = int64_t(0xffffffffULL * 1000000ULL + 999999);
static void Save(const std::string &path, const MemoryOutput &out) {
	std::ofstream stream(path, std::ios::binary);
	stream.write(reinterpret_cast<const char *>(out.data.data()), out.data.size());
	stream.close();
	Require(!stream.fail(), "Test fixture output failed");
}
int main(int argc, char **argv) {
	try {
		const uint8_t payload[] = {0, 128, 255};
		const uint8_t expected_header[] = {0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0,
		                                   0,    0,    0,    0,    3, 0, 0, 0, 1, 0, 0, 0};
		MemoryOutput normal;
		PcapWriter writer(normal, PcapWriterOptions(1));
		const std::vector<int64_t> times = {0, 999999, 1000000, 2147483647999999LL, 2147483648000000LL, LAST_TIME};
		for (auto t : times)
			writer.WritePacket(t, 3, 5, 1, payload, 3);
		writer.Finish();
		Require(writer.Finished() && writer.PacketCount() == times.size() &&
		            writer.BytesWritten() == 24 + times.size() * 19,
		        "Writer counters");
		Require(normal.position == normal.data.size() && normal.seeks == 2, "Final patch did not restore EOF");
		Require(std::equal(expected_header, expected_header + 24, normal.data.begin()), "Byte-exact PCAP header");
		for (size_t i = 0; i < times.size(); ++i) {
			auto offset = 24 + i * 19;
			Require(U32(normal.data, offset) == uint64_t(times[i]) / 1000000 &&
			            U32(normal.data, offset + 4) == uint64_t(times[i]) % 1000000,
			        "Timestamp encoding");
			Require(U32(normal.data, offset + 8) == 3 && U32(normal.data, offset + 12) == 5, "Length encoding");
			Require(std::equal(payload, payload + 3, normal.data.begin() + offset + 16), "Payload preservation");
		}
		Reject([&] { writer.Finish(); });
		Reject([&] { writer.WritePacket(0, 0, 0, 1, nullptr, 0); });
		MemoryOutput empty;
		PcapWriter empty_writer(empty, PcapWriterOptions(101));
		empty_writer.Finish();
		Require(empty.data.size() == 24 && U32(empty.data, 16) == 1 && U32(empty.data, 20) == 101, "Empty PCAP");
		MemoryOutput zero;
		PcapWriter zero_writer(zero, PcapWriterOptions(1));
		zero_writer.WritePacket(0, 0, 0xffffffffULL, 1, nullptr, 0);
		zero_writer.Finish();
		Require(zero.data.size() == 40 && U32(zero.data, 36) == 0xffffffffU, "Zero capture/maximum reported length");
		for (auto link : {0U, 1U, 101U, 276U, 65535U}) {
			MemoryOutput out;
			PcapWriter explicit_writer(out, PcapWriterOptions(link));
			explicit_writer.Finish();
			Require(U32(out.data, 20) == link, "Link type encoding");
		}
		for (auto link : {65536U, 0x04000001U, 0x20000001U, 0xffffffffU}) {
			MemoryOutput out;
			Reject([&] { PcapWriter bad(out, PcapWriterOptions(link)); });
			Require(out.calls == 0, "Bad options wrote header");
		}
		{
			MemoryOutput out;
			PcapWriterOptions options(1);
			options.has_snaplen = true;
			Reject([&] { PcapWriter bad(out, options); });
			Require(out.calls == 0, "Zero explicit snaplen wrote header");
			options.snaplen = 3;
			PcapWriter explicit_writer(out, options);
			explicit_writer.WritePacket(1, 3, 5, 1, payload, 3);
			explicit_writer.Finish();
			Require(out.seeks == 0 && U32(out.data, 16) == 3, "Explicit snaplen changed");
		}
		using BadPacket = std::function<void(PcapWriter &)>;
		std::vector<BadPacket> invalid = {
		    [&](PcapWriter &w) { w.WritePacket(-1, 3, 5, 1, payload, 3); },
		    [&](PcapWriter &w) { w.WritePacket(LAST_TIME + 1, 3, 5, 1, payload, 3); },
		    [&](PcapWriter &w) { w.WritePacket(std::numeric_limits<int64_t>::max(), 3, 5, 1, payload, 3); },
		    [&](PcapWriter &w) { w.WritePacket(std::numeric_limits<int64_t>::min(), 3, 5, 1, payload, 3); },
		    [&](PcapWriter &w) { w.WritePacket(1, 3, 2, 1, payload, 3); },
		    [&](PcapWriter &w) { w.WritePacket(1, 3, 5, 101, payload, 3); },
		    [&](PcapWriter &w) { w.WritePacket(1, 3, 5, 0x04000001, payload, 3); },
		    [&](PcapWriter &w) { w.WritePacket(1, 4, 5, 1, payload, 3); },
		    [&](PcapWriter &w) { w.WritePacket(1, 3, 5, 1, nullptr, 3); },
		    [&](PcapWriter &w) { w.WritePacket(1, 0x100000000ULL, 0x100000000ULL, 1, payload, 3); },
		    [&](PcapWriter &w) {
			    w.WritePacket(1, 3, 0x100000000ULL, 1, payload, 3);
		    }};
		{
			MemoryOutput out;
			{
				PcapWriter w(out, PcapWriterOptions(1));
				w.WritePacket(0, 3, 5, 1, payload, 3);
				const auto size = out.data.size();
				Reject([&] { w.WritePacket(-1, 3, 5, 1, payload, 3); });
				Require(w.Failed() && w.PacketCount() == 1 && out.data.size() == size,
				        "Failed later row altered prior records");
			}
			Require(out.seeks == 0, "Destructor must not finalize or publish");
		}
		for (auto &operation : invalid) {
			MemoryOutput out;
			PcapWriter w(out, PcapWriterOptions(1));
			Reject([&] { operation(w); });
			Require(w.Failed() && out.data.size() == 24 && w.PacketCount() == 0,
			        "Invalid row modified output or remained usable");
			Reject([&] { w.Finish(); });
			Reject([&] { w.WritePacket(0, 0, 0, 1, nullptr, 0); });
		}
		{
			MemoryOutput out;
			PcapWriterOptions options(1);
			options.has_snaplen = true;
			options.snaplen = 2;
			PcapWriter w(out, options);
			Reject([&] { w.WritePacket(0, 3, 5, 1, payload, 3); });
			Require(w.Failed() && out.data.size() == 24, "SNAPLEN overflow was truncated");
		}
		// Every byte of header, packet and final header patch can fail. Partial
		// writes are allowed, but no failed writer may subsequently finish.
		for (size_t cut = 0; cut < 47; ++cut) {
			MemoryOutput out;
			out.fail_after = cut;
			if (cut < 24)
				Reject([&] { PcapWriter w(out, PcapWriterOptions(1)); });
			else {
				PcapWriter w(out, PcapWriterOptions(1));
				Reject([&] {
					w.WritePacket(0, 3, 5, 1, payload, 3);
					w.Finish();
				});
				Require(w.Failed(), "I/O failure did not poison writer");
				Reject([&] { w.Finish(); });
			}
		}
		for (unsigned seek : {1U, 2U}) {
			MemoryOutput out;
			out.fail_seek = seek;
			PcapWriter w(out, PcapWriterOptions(1));
			Reject([&] { w.Finish(); });
			Require(w.Failed(), "Seek failure did not poison writer");
		}
		for (bool excessive : {false, true}) {
			MemoryOutput out;
			PcapWriter w(out, PcapWriterOptions(1));
			out.zero = !excessive;
			out.excessive = excessive;
			Reject([&] { w.WritePacket(0, 3, 5, 1, payload, 3); });
			Require(w.Failed(), "Invalid write count accepted");
		}
		for (size_t limit : {size_t(1), size_t(7), size_t(65536)}) {
			MemoryOutput out;
			out.short_limit = limit;
			PcapWriter w(out, PcapWriterOptions(1));
			std::vector<uint8_t> large(1024 * 1024 + 13, 0xab);
			w.WritePacket(1234567, large.size(), large.size(), 1, large.data(), large.size());
			w.Finish();
			Require(out.largest <= PcapWriter::WRITE_CHUNK_SIZE && out.data.size() == large.size() + 40,
			        "Unbounded/lost payload writes");
			Require(std::equal(large.begin(), large.end(), out.data.begin() + 40), "Short write lost bytes");
		}
		// Deterministic randomized record sequences independently decoded below.
		std::mt19937 rng(20260919);
		for (unsigned trial = 0; trial < 1000; ++trial) {
			MemoryOutput out;
			out.short_limit = 1 + rng() % 100;
			PcapWriter w(out, PcapWriterOptions(1));
			uint32_t largest = 1;
			size_t offset = 24;
			for (unsigned n = 0; n < 10; ++n) {
				std::vector<uint8_t> bytes(rng() % 1024);
				for (auto &b : bytes)
					b = static_cast<uint8_t>(rng());
				auto seconds = rng();
				auto micros = rng() % 1000000;
				auto original = bytes.size() + rng() % 100;
				w.WritePacket(int64_t(seconds) * 1000000 + micros, bytes.size(), original, 1, bytes.data(),
				              bytes.size());
				Require(U32(out.data, offset) == seconds && U32(out.data, offset + 4) == micros &&
				            U32(out.data, offset + 8) == bytes.size() && U32(out.data, offset + 12) == original,
				        "Random record fields");
				Require(std::equal(bytes.begin(), bytes.end(), out.data.begin() + offset + 16), "Random payload");
				largest = std::max(largest, static_cast<uint32_t>(bytes.size()));
				offset += 16 + bytes.size();
			}
			w.Finish();
			Require(U32(out.data, 16) == largest && out.data.size() == offset, "Random final snaplen/size");
		}
		if (argc == 2) {
			std::string directory = argv[1];
			Save(directory + "/oracle.pcap", normal);
			Save(directory + "/empty.pcap", empty);
			Save(directory + "/zero.pcap", zero);
			const uint8_t udp_frame[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0,    1,    2,    3,    4, 5, 8,   0,
			                             0x45, 0,    0,    28,   0,    0,    0,    0,    64,   17,   0, 0, 192, 0,
			                             2,    1,    192,  0,    2,    2,    0x30, 0x39, 0x27, 0x0f, 0, 8, 0,   0};
			MemoryOutput udp_output;
			PcapWriter udp_writer(udp_output, PcapWriterOptions(1));
			udp_writer.WritePacket(1000001, sizeof(udp_frame), sizeof(udp_frame), 1, udp_frame, sizeof(udp_frame));
			udp_writer.Finish();
			Save(directory + "/udp.pcap", udp_output);

#ifdef PCAP_ORACLE
			char error[PCAP_ERRBUF_SIZE];
			std::unique_ptr<pcap_t, decltype(&pcap_close)> owner(
			    pcap_open_offline((directory + "/oracle.pcap").c_str(), error), &pcap_close);
			auto *capture = owner.get();
			Require(capture != nullptr, error);
			Require(pcap_datalink(capture) == DLT_EN10MB && pcap_snapshot(capture) == 3, "libpcap header mismatch");
			for (auto t : times) {
				struct pcap_pkthdr *header;
				const u_char *bytes;
				Require(pcap_next_ex(capture, &header, &bytes) == 1, "libpcap missing record");
				const auto seconds = t / 1000000;
				// libpcap 1.10.4 exposes the seconds field as signed int32 on
				// native-endian reads. Verify that documented compatibility
				// limitation explicitly; byte-level and DuckDB checks stay unsigned.
				const auto decoded = int64_t(header->ts.tv_sec);
				Require(decoded == seconds || (seconds >= 2147483648LL && decoded == seconds - 4294967296LL),
				        "libpcap seconds mismatch");
				Require(header->ts.tv_usec == t % 1000000 && header->caplen == 3 && header->len == 5 &&
				            std::equal(payload, payload + 3, bytes),
				        "libpcap record mismatch");
				if (decoded != seconds)
					std::cout << "libpcap signed-seconds compatibility limit observed at " << seconds << "\n";
			}
			struct pcap_pkthdr *header;
			const u_char *bytes;
			Require(pcap_next_ex(capture, &header, &bytes) == -2, "libpcap trailing data");
			owner.reset();
			owner.reset(pcap_open_offline((directory + "/empty.pcap").c_str(), error));
			capture = owner.get();
			Require(capture != nullptr, error);
			Require(pcap_next_ex(capture, &header, &bytes) == -2, "libpcap empty output");
			owner.reset();
			std::cout << "Independent libpcap round trips passed\n";
#endif
		}
		std::cout << "PCAP exact bytes, bounds, failure injection, bounded short writes, and 10000 randomized records "
		             "passed\n";
	} catch (const std::exception &e) {
		std::cerr << e.what() << "\n";
		return 1;
	}
}
