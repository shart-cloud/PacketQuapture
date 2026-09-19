#pragma once

#include <cstddef>
#include <cstdint>

namespace packetquapture {

// Caller-owned seekable staging output. Write may return a positive short count;
// zero, an excessive count, or an exception fails the writer. Seek is absolute.
// Implementations must throw on I/O failure and may check cancellation per call.
class PcapOutput {
public:
	virtual ~PcapOutput() = default;
	virtual size_t Write(const uint8_t *data, size_t size) = 0;
	virtual void Seek(uint64_t offset) = 0;
};

struct PcapWriterOptions {
	explicit PcapWriterOptions(uint32_t link_type_p) : link_type(link_type_p) {
	}
	uint32_t link_type;
	bool has_snaplen = false;
	uint32_t snaplen = 0;
};

// Classic PCAP 2.4, little endian, microsecond timestamps. No filesystem or
// DuckDB dependency, retained payload, ownership, implicit close, or publication.
// The caller supplies an empty output positioned at zero and serializes calls in
// desired record order. On any failure it must discard the owned staging output.
class PcapWriter {
public:
	static constexpr size_t WRITE_CHUNK_SIZE = 64 * 1024;
	PcapWriter(PcapOutput &output, PcapWriterOptions options);
	PcapWriter(const PcapWriter &) = delete;
	PcapWriter &operator=(const PcapWriter &) = delete;

	// Scalar fields are non-null; the SQL adapter must reject NULL separately.
	// A null data pointer is allowed only for a present, zero-length payload.
	// data_size bytes must be readable for the duration of this call.
	void WritePacket(int64_t timestamp_us, uint64_t captured_length, uint64_t original_length, uint32_t link_type,
	                 const uint8_t *data, size_t data_size);
	// Patches inferred snaplen and restores EOF. No flush/close/publication.
	void Finish();
	bool Finished() const {
		return state == State::FINISHED;
	}
	bool Failed() const {
		return state == State::FAILED;
	}
	uint64_t PacketCount() const {
		return packets;
	}
	uint64_t BytesWritten() const {
		return bytes;
	}
	uint32_t Snaplen() const {
		return options.has_snaplen ? options.snaplen : maximum_capture;
	}

private:
	enum class State { OPEN, FINISHED, FAILED };
	void RequireOpen() const;
	void WriteAll(const uint8_t *data, size_t size);
	PcapOutput &output;
	PcapWriterOptions options;
	State state = State::OPEN;
	uint64_t packets = 0, bytes = 24;
	uint32_t maximum_capture = 1;
};

} // namespace packetquapture
