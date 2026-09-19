#include "pcap_writer.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace packetquapture {
namespace {
void Put32(uint8_t *target, uint32_t value) {
	for (unsigned i = 0; i < 4; ++i)
		target[i] = static_cast<uint8_t>(value >> (8 * i));
}
} // namespace
constexpr size_t PcapWriter::WRITE_CHUNK_SIZE;

PcapWriter::PcapWriter(PcapOutput &output_p, PcapWriterOptions options_p) : output(output_p), options(options_p) {
	if (options.link_type > 0xffffU)
		throw std::invalid_argument("PCAP LINKTYPE must fit 16 bits; FCS and additional metadata are unsupported");
	if (options.has_snaplen && options.snaplen == 0)
		throw std::invalid_argument("PCAP SNAPLEN must be positive");
	uint8_t header[24] = {};
	Put32(header, 0xa1b2c3d4U);
	header[4] = 2;
	header[6] = 4;
	Put32(header + 16, Snaplen());
	Put32(header + 20, options.link_type);
	WriteAll(header, sizeof(header));
}
void PcapWriter::RequireOpen() const {
	if (state != State::OPEN)
		throw std::logic_error("PCAP writer is finalized or failed");
}
void PcapWriter::WriteAll(const uint8_t *data, size_t size) {
	while (size) {
		const auto requested = std::min(size, WRITE_CHUNK_SIZE);
		const auto written = output.Write(data, requested);
		if (written == 0 || written > requested)
			throw std::runtime_error("PCAP output made invalid write progress");
		data += written;
		size -= written;
	}
}
void PcapWriter::WritePacket(int64_t timestamp_us, uint64_t captured_length, uint64_t original_length,
                             uint32_t link_type, const uint8_t *data, size_t data_size) {
	RequireOpen();
	try {
		const auto limit = std::numeric_limits<uint32_t>::max();
		if (timestamp_us < 0 || static_cast<uint64_t>(timestamp_us) / 1000000 > limit)
			throw std::invalid_argument("PCAP timestamp is outside unsigned 32-bit seconds range");
		if (link_type != options.link_type)
			throw std::invalid_argument("PCAP packet LINKTYPE does not match output LINKTYPE");
		if (captured_length > limit || original_length > limit || captured_length > original_length)
			throw std::invalid_argument("PCAP packet lengths are invalid or exceed 32 bits");
		if (captured_length != data_size || (data_size && !data))
			throw std::invalid_argument("PCAP captured_length must equal the present payload size");
		if (options.has_snaplen && captured_length > options.snaplen)
			throw std::invalid_argument("PCAP captured_length exceeds SNAPLEN");
		if (bytes > std::numeric_limits<uint64_t>::max() - 16 - captured_length ||
		    packets == std::numeric_limits<uint64_t>::max())
			throw std::overflow_error("PCAP output counters overflow");
		uint8_t header[16];
		Put32(header, static_cast<uint32_t>(timestamp_us / 1000000));
		Put32(header + 4, static_cast<uint32_t>(timestamp_us % 1000000));
		Put32(header + 8, static_cast<uint32_t>(captured_length));
		Put32(header + 12, static_cast<uint32_t>(original_length));
		WriteAll(header, sizeof(header));
		WriteAll(data, data_size);
		maximum_capture = std::max(maximum_capture, static_cast<uint32_t>(captured_length));
		bytes += 16 + captured_length;
		++packets;
	} catch (...) {
		state = State::FAILED;
		throw;
	}
}
void PcapWriter::Finish() {
	RequireOpen();
	try {
		if (!options.has_snaplen) {
			uint8_t snaplen[4];
			Put32(snaplen, maximum_capture);
			output.Seek(16);
			WriteAll(snaplen, sizeof(snaplen));
			output.Seek(bytes);
		}
		state = State::FINISHED;
	} catch (...) {
		state = State::FAILED;
		throw;
	}
}
} // namespace packetquapture
