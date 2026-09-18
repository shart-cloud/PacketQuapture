#define DUCKDB_EXTENSION_MAIN

#include "packetquapture_extension.hpp"
#include "capture_progress.hpp"
#include "stream_scan_budget.hpp"
#include "packet_decoder.hpp"
#include "dns_decoder.hpp"
#include "tcp_reassembly.hpp"
#include "dns_tcp_framer.hpp"
#include "duckdb/execution/expression_executor.hpp"
#include "duckdb/execution/execution_context.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/client_config.hpp"
#include "duckdb/planner/expression/bound_reference_expression.hpp"
#include "duckdb/planner/table_filter.hpp"
#include "duckdb/planner/expression/bound_columnref_expression.hpp"
#include "duckdb/planner/expression/bound_comparison_expression.hpp"
#include "duckdb/planner/expression/bound_conjunction_expression.hpp"
#include "duckdb/planner/expression/bound_constant_expression.hpp"
#include "duckdb/planner/expression/bound_operator_expression.hpp"
#include <functional>

#include "duckdb/common/exception.hpp"
#include "duckdb/common/error_data.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/multi_file/multi_file_reader.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "duckdb/function/function_set.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/storage/caching_file_system.hpp"
#include "duckdb/storage/buffer/buffer_handle.hpp"

#include <array>
#include <atomic>
#include <cmath>
#include <cstring>
#include <cstdio>
#include <limits>

namespace duckdb {
namespace {

// Bound each remote reader pin; the remaining windows are evictable in DuckDB's shared cache.
constexpr idx_t REMOTE_READ_WINDOW_SIZE = 4ULL * 1024ULL * 1024ULL;
constexpr idx_t MAX_CAPTURED_PACKET_SIZE = 256ULL * 1024ULL * 1024ULL;
constexpr idx_t MAX_INTERFACE_BLOCK_SIZE = 16ULL * 1024ULL * 1024ULL;
constexpr uint32_t PCAPNG_INTERFACE_DESCRIPTION = 0x00000001;
constexpr uint32_t PCAPNG_SIMPLE_PACKET = 0x00000003;
constexpr uint32_t PCAPNG_ENHANCED_PACKET = 0x00000006;

enum class ByteOrder : uint8_t { LITTLE, BIG };
enum class CaptureFormat : uint8_t { PCAP, PCAPNG };

struct PacketRecord {
	string filename;
	uint64_t packet_number = 0;
	bool has_timestamp = false;
	timestamp_t timestamp;
	uint32_t captured_length = 0;
	uint32_t original_length = 0;
	uint32_t link_type = 0;
	uint32_t interface_id = 0;
	uint64_t packet_offset = 0;
	CaptureFormat format = CaptureFormat::PCAP;
	vector<uint8_t> packet_data;
	vector<uint8_t> transport_data;
	uint32_t section_number = 0;
	packetquapture::DecodedPacket decoded;
	packetquapture::DnsMessage dns;
	bool selected = true;
};

struct PcapNgInterface {
	uint32_t link_type = 0;
	uint32_t snap_length = 0;
	long double ticks_per_second = 1000000.0L;
};

static uint16_t ReadU16(const uint8_t *data, ByteOrder order) {
	if (order == ByteOrder::LITTLE) {
		return static_cast<uint16_t>(data[0]) | (static_cast<uint16_t>(data[1]) << 8U);
	}
	return (static_cast<uint16_t>(data[0]) << 8U) | static_cast<uint16_t>(data[1]);
}

static uint32_t ReadU32(const uint8_t *data, ByteOrder order) {
	if (order == ByteOrder::LITTLE) {
		return static_cast<uint32_t>(data[0]) | (static_cast<uint32_t>(data[1]) << 8U) |
		       (static_cast<uint32_t>(data[2]) << 16U) | (static_cast<uint32_t>(data[3]) << 24U);
	}
	return (static_cast<uint32_t>(data[0]) << 24U) | (static_cast<uint32_t>(data[1]) << 16U) |
	       (static_cast<uint32_t>(data[2]) << 8U) | static_cast<uint32_t>(data[3]);
}

static idx_t AlignTo32Bits(idx_t size) {
	return (size + 3U) & ~idx_t(3U);
}

static void SetRecordValue(Vector &vector, idx_t row, column_t column, const PacketRecord &record);

static unsigned ColumnStage(column_t column) {
	if (column == 9) {
		return 5;
	}
	if (column >= 40) {
		return 4;
	}
	if (column >= 23) {
		return 3;
	}
	if (column >= 15) {
		return 2;
	}
	if (column >= 11) {
		return 1;
	}
	return 0;
}

struct ScanOptions {
	bool materialize_packet_data = false;
	bool dns_scan = false, decode_dns = false;
	bool reassemble_dns = false, reassemble_tcp = false;
	packetquapture::DecodeDepth decode_depth = packetquapture::DecodeDepth::NONE;
	std::array<bool, 6> filter_stages {};
	std::function<bool(const PacketRecord &, unsigned)> matches;
};

class PacketFilter {
public:
	PacketFilter(ClientContext &context, column_t column_p, const LogicalType &type, const TableFilter &filter)
	    : column(column_p), stage(ColumnStage(column_p)) {
		BoundReferenceExpression reference(type, 0);
		expression = filter.ToExpression(reference);
		executor = make_uniq<ExpressionExecutor>(context, *expression);
		input.Initialize(context, {type});
	}
	bool Matches(const PacketRecord &record) {
		input.Reset();
		input.SetCardinality(1);
		SetRecordValue(input.data[0], 0, column, record);
		SelectionVector selected(1);
		return executor->SelectExpression(input, selected) == 1;
	}
	column_t column;
	unsigned stage;

private:
	unique_ptr<Expression> expression;
	unique_ptr<ExpressionExecutor> executor;
	DataChunk input;
};

struct CaptureGlobalState : public GlobalTableFunctionState {
	CaptureProgress progress;
};

static double CaptureScanProgress(ClientContext &, const FunctionData *, const GlobalTableFunctionState *state) {
	return state ? static_cast<const CaptureGlobalState &>(*state).progress.Percentage() : -1;
}

class CaptureReader {
public:
	CaptureReader(ClientContext &context, const OpenFileInfo &file_p, const ScanOptions &options_p,
	              CaptureProgress *progress_p = nullptr, idx_t file_index = 0)
	    : file(file_p), context(context), fs(FileSystem::GetFileSystem(context)), options(options_p),
	      progress(progress_p && progress_p->Enabled() ? progress_p : nullptr) {
		if (FileSystem::IsRemoteFile(file.path)) {
			caching_fs = make_uniq<CachingFileSystem>(fs, *context.db);
			// The window already supplies read-ahead; avoid a second HTTP read buffer.
			cached_handle =
			    caching_fs->OpenFile(context, file, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
		} else {
			handle = fs.OpenFile(file, FileFlags::FILE_FLAGS_READ);
		}
		auto &raw_handle = RawHandle();
		if (raw_handle.CanSeek() && !raw_handle.IsPipe()) {
			const auto size = fs.GetFileSize(raw_handle);
			if (size >= 0) {
				seekable_size = static_cast<uint64_t>(size);
				can_skip_by_seek = true;
			}
		}
		if (progress) {
			progress->CheckSize(file_index, can_skip_by_seek, seekable_size);
		}
		Initialize();
	}

	bool Next(PacketRecord &record) {
		try {
			const bool found = format == CaptureFormat::PCAP ? NextPcap(record) : NextPcapNg(record);
			if (!found && progress && progress->Enabled()) {
				PublishProgress(true);
				progress->CompleteFile();
			}
			return found;
		} catch (const std::exception &exception) {
			ErrorData error(exception);
			if (error.Type() == ExceptionType::INTERRUPT) {
				throw;
			}
			error.Throw(StringUtil::Format("Capture '%s', packet cursor %llu, byte cursor %llu: ", file.path,
			                               packet_number, position));
		}
	}

private:
	void PublishProgress(bool force = false) {
		if (progress && progress->Enabled() && (force || position - published_position >= 64 * 1024)) {
			progress->Advance(position - published_position);
			published_position = position;
		}
	}

	FileHandle &RawHandle() {
		return cached_handle ? cached_handle->GetFileHandle() : *handle;
	}

	// Explicit offsets keep parser skips independent of the underlying handle cursor.
	// Hold the pin until copying is complete, and release it before allocating another.
	idx_t ReadRemoteWindow(void *buffer, idx_t length, uint64_t offset) {
		if (offset >= seekable_size) {
			return 0;
		}
		if (!window.IsValid() || offset < window_start || offset - window_start >= window_length) {
			window.Destroy();
			window_data = nullptr;
			window_start = offset - offset % REMOTE_READ_WINDOW_SIZE;
			window_length = MinValue<idx_t>(REMOTE_READ_WINDOW_SIZE, seekable_size - window_start);
			window = cached_handle->Read(window_data, window_length, window_start);
		}
		const auto within_window = offset - window_start;
		const auto count = MinValue<idx_t>(length, window_length - within_window);
		memcpy(buffer, window_data + within_window, count);
		return count;
	}

	void Initialize() {
		std::array<uint8_t, 4> magic {};
		if (!ReadMaybe(magic.data(), magic.size())) {
			throw IOException("Capture file '%s' is empty", file.path);
		}
		if (magic == std::array<uint8_t, 4> {0xD4, 0xC3, 0xB2, 0xA1}) {
			InitializePcap(ByteOrder::LITTLE, false);
		} else if (magic == std::array<uint8_t, 4> {0xA1, 0xB2, 0xC3, 0xD4}) {
			InitializePcap(ByteOrder::BIG, false);
		} else if (magic == std::array<uint8_t, 4> {0x4D, 0x3C, 0xB2, 0xA1}) {
			InitializePcap(ByteOrder::LITTLE, true);
		} else if (magic == std::array<uint8_t, 4> {0xA1, 0xB2, 0x3C, 0x4D}) {
			InitializePcap(ByteOrder::BIG, true);
		} else if (magic == std::array<uint8_t, 4> {0x0A, 0x0D, 0x0D, 0x0A}) {
			format = CaptureFormat::PCAPNG;
			ReadInitialSectionHeader();
		} else {
			throw InvalidInputException("File '%s' is not a PCAP or PCAPNG capture", file.path);
		}
	}

	void InitializePcap(ByteOrder order_p, bool nanosecond_timestamps_p) {
		format = CaptureFormat::PCAP;
		order = order_p;
		nanosecond_timestamps = nanosecond_timestamps_p;
		std::array<uint8_t, 20> header {};
		ReadExact(header.data(), header.size(), "PCAP global header");
		const auto major_version = ReadU16(header.data(), order);
		if (major_version != 2) {
			throw InvalidInputException("Unsupported PCAP version %d in '%s'", major_version, file.path);
		}
		pcap_link_type = ReadU32(header.data() + 16, order);
	}

	void ReadInitialSectionHeader() {
		std::array<uint8_t, 8> prefix {};
		ReadExact(prefix.data(), prefix.size(), "PCAPNG section header");
		SetPcapNgByteOrder(prefix.data() + 4);
		const auto block_length = ReadU32(prefix.data(), order);
		FinishSectionHeader(block_length);
	}

	void ReadSectionHeaderAfterHeader(const std::array<uint8_t, 8> &header) {
		std::array<uint8_t, 4> byte_order_magic {};
		ReadExact(byte_order_magic.data(), byte_order_magic.size(), "PCAPNG section header");
		SetPcapNgByteOrder(byte_order_magic.data());
		const auto block_length = ReadU32(header.data() + 4, order);
		FinishSectionHeader(block_length);
	}

	void SetPcapNgByteOrder(const uint8_t *magic) {
		if (std::memcmp(magic, "\x4d\x3c\x2b\x1a", 4) == 0) {
			order = ByteOrder::LITTLE;
		} else if (std::memcmp(magic, "\x1a\x2b\x3c\x4d", 4) == 0) {
			order = ByteOrder::BIG;
		} else {
			throw InvalidInputException("Invalid PCAPNG byte-order magic in '%s'", file.path);
		}
	}

	void FinishSectionHeader(uint32_t block_length) {
		ValidateBlockLength(block_length, 28, "section header");
		std::array<uint8_t, 12> fixed {};
		ReadExact(fixed.data(), fixed.size(), "PCAPNG section header");
		Skip(block_length - 28, "PCAPNG section options");
		ReadAndValidateTrailer(block_length);
		const auto major_version = ReadU16(fixed.data(), order);
		if (major_version != 1) {
			throw InvalidInputException("Unsupported PCAPNG version %d in '%s'", major_version, file.path);
		}
		interfaces.clear();
		section_number++;
	}

	bool NextPcap(PacketRecord &record) {
		std::array<uint8_t, 16> header {};
		if (!ReadMaybe(header.data(), header.size())) {
			return false;
		}
		const auto seconds = ReadU32(header.data(), order);
		const auto fractional = ReadU32(header.data() + 4, order);
		const auto captured_length = ReadU32(header.data() + 8, order);
		const auto original_length = ReadU32(header.data() + 12, order);
		ValidatePacketLength(captured_length);

		record = PacketRecord();
		record.filename = file.path;
		record.packet_number = ++packet_number;
		record.has_timestamp = true;
		record.timestamp = TimestampFromParts(seconds, fractional, nanosecond_timestamps ? 1000000000.0L : 1000000.0L);
		record.captured_length = captured_length;
		record.original_length = original_length;
		record.link_type = pcap_link_type;
		record.packet_offset = position;
		record.format = CaptureFormat::PCAP;
		record.section_number = 1;
		ReadPacketData(record, captured_length);
		return true;
	}

	bool NextPcapNg(PacketRecord &record) {
		while (true) {
			std::array<uint8_t, 8> header {};
			if (!ReadMaybe(header.data(), header.size())) {
				return false;
			}
			if (std::memcmp(header.data(), "\x0a\x0d\x0d\x0a", 4) == 0) {
				ReadSectionHeaderAfterHeader(header);
				continue;
			}
			const auto block_type = ReadU32(header.data(), order);
			const auto block_length = ReadU32(header.data() + 4, order);
			ValidateBlockLength(block_length, 12, "block");
			if (block_type == PCAPNG_INTERFACE_DESCRIPTION) {
				ReadInterfaceDescription(block_length);
				continue;
			}
			if (block_type == PCAPNG_ENHANCED_PACKET) {
				ReadEnhancedPacket(block_length, record);
				return true;
			}
			if (block_type == PCAPNG_SIMPLE_PACKET) {
				ReadSimplePacket(block_length, record);
				return true;
			}
			Skip(block_length - 12, "PCAPNG block body");
			ReadAndValidateTrailer(block_length);
		}
	}

	void ReadInterfaceDescription(uint32_t block_length) {
		const idx_t body_size = block_length - 12;
		if (body_size < 8 || body_size > MAX_INTERFACE_BLOCK_SIZE) {
			throw InvalidInputException("Invalid PCAPNG interface block length %d in '%s'", block_length, file.path);
		}
		vector<uint8_t> body(body_size);
		ReadExact(body.data(), body.size(), "PCAPNG interface block");
		ReadAndValidateTrailer(block_length);

		PcapNgInterface interface;
		interface.link_type = ReadU16(body.data(), order);
		interface.snap_length = ReadU32(body.data() + 4, order);
		idx_t offset = 8;
		while (offset + 4 <= body.size()) {
			const auto option_code = ReadU16(body.data() + offset, order);
			const auto option_length = ReadU16(body.data() + offset + 2, order);
			offset += 4;
			if (option_code == 0) {
				break;
			}
			const auto padded_length = AlignTo32Bits(option_length);
			if (offset + padded_length > body.size()) {
				throw InvalidInputException("Invalid PCAPNG interface option in '%s'", file.path);
			}
			if (option_code == 9 && option_length == 1) {
				const auto resolution = body[offset];
				if ((resolution & 0x80U) != 0) {
					interface.ticks_per_second = std::pow(2.0L, static_cast<int>(resolution & 0x7FU));
				} else {
					interface.ticks_per_second = std::pow(10.0L, static_cast<int>(resolution));
				}
			}
			offset += padded_length;
		}
		// Bound stream-worker metadata independently of capture size.
		if ((options.reassemble_tcp || options.reassemble_dns) && interfaces.size() >= 65536) {
			throw InvalidInputException("Stream scan exceeds 65536 PCAPNG interfaces per section in '%s'", file.path);
		}
		interfaces.push_back(interface);
	}

	void ReadEnhancedPacket(uint32_t block_length, PacketRecord &record) {
		const idx_t body_size = block_length - 12;
		if (body_size < 20) {
			throw InvalidInputException("Invalid PCAPNG enhanced packet block in '%s'", file.path);
		}
		std::array<uint8_t, 20> body_prefix {};
		ReadExact(body_prefix.data(), body_prefix.size(), "PCAPNG enhanced packet block");
		const auto interface_id = ReadU32(body_prefix.data(), order);
		if (interface_id >= interfaces.size()) {
			throw InvalidInputException("PCAPNG packet references missing interface %d in '%s'", interface_id,
			                            file.path);
		}
		const auto captured_length = ReadU32(body_prefix.data() + 12, order);
		const auto original_length = ReadU32(body_prefix.data() + 16, order);
		ValidatePacketLength(captured_length);
		const auto padded_length = AlignTo32Bits(captured_length);
		if (20 + padded_length > body_size) {
			throw InvalidInputException("Truncated PCAPNG packet in '%s'", file.path);
		}

		record = PacketRecord();
		record.filename = file.path;
		record.packet_number = ++packet_number;
		record.has_timestamp = true;
		const uint64_t timestamp_ticks = (static_cast<uint64_t>(ReadU32(body_prefix.data() + 4, order)) << 32U) |
		                                 ReadU32(body_prefix.data() + 8, order);
		record.timestamp = TimestampFromTicks(timestamp_ticks, interfaces[interface_id].ticks_per_second);
		record.captured_length = captured_length;
		record.original_length = original_length;
		record.link_type = interfaces[interface_id].link_type;
		record.interface_id = interface_id;
		record.packet_offset = position;
		record.format = CaptureFormat::PCAPNG;
		record.section_number = section_number;
		ReadPacketData(record, captured_length);
		Skip(padded_length - captured_length, "PCAPNG packet padding");
		Skip(body_size - 20 - padded_length, "PCAPNG packet options");
		ReadAndValidateTrailer(block_length);
	}

	void ReadSimplePacket(uint32_t block_length, PacketRecord &record) {
		const idx_t body_size = block_length - 12;
		if (body_size < 4 || interfaces.empty()) {
			throw InvalidInputException("Invalid PCAPNG simple packet block in '%s'", file.path);
		}
		std::array<uint8_t, 4> prefix {};
		ReadExact(prefix.data(), prefix.size(), "PCAPNG simple packet block");
		const auto original_length = ReadU32(prefix.data(), order);
		const auto available = body_size - 4;
		const auto snap_length = interfaces[0].snap_length == 0 ? original_length : interfaces[0].snap_length;
		const auto captured_length = static_cast<uint32_t>(MinValue<idx_t>(original_length, snap_length));
		ValidatePacketLength(captured_length);
		if (AlignTo32Bits(captured_length) > available) {
			throw InvalidInputException("Truncated PCAPNG simple packet in '%s'", file.path);
		}

		record = PacketRecord();
		record.filename = file.path;
		record.packet_number = ++packet_number;
		record.captured_length = captured_length;
		record.original_length = original_length;
		record.link_type = interfaces[0].link_type;
		record.packet_offset = position;
		record.format = CaptureFormat::PCAPNG;
		record.section_number = section_number;
		ReadPacketData(record, captured_length);
		Skip(available - captured_length, "PCAPNG simple packet padding");
		ReadAndValidateTrailer(block_length);
	}

	void ReadPacketData(PacketRecord &record, idx_t length) {
		class HeaderSource : public packetquapture::PacketSource {
		public:
			HeaderSource(CaptureReader &reader_p, idx_t length_p) : reader(reader_p), length(length_p) {
			}
			size_t Size() const override {
				return length;
			}
			const uint8_t *ReadPrefix(size_t requested) override {
				const auto previous = bytes.size();
				if (requested > previous) {
					bytes.resize(requested);
					reader.ReadExact(bytes.data() + previous, requested - previous, "packet header");
				}
				return bytes.data();
			}
			idx_t Consumed() const {
				return bytes.size();
			}
			vector<uint8_t> TakeBytes() {
				return std::move(bytes);
			}

		private:
			CaptureReader &reader;
			idx_t length;
			vector<uint8_t> bytes;
		};
		HeaderSource source(*this, length);
		auto accept = [&](unsigned stage) {
			if (options.filter_stages[stage] && !options.matches(record, stage)) {
				record.selected = false;
				return false;
			}
			return true;
		};
		if (!accept(0)) {
			Skip(length, "packet data");
			return;
		}
		const auto max_depth = static_cast<unsigned>(options.decode_depth);
		for (unsigned stage = 1; stage <= max_depth; ++stage) {
			if (stage != max_depth && !options.filter_stages[stage]) {
				continue;
			}
			record.decoded =
			    packetquapture::DecodePacket(source, record.link_type, static_cast<packetquapture::DecodeDepth>(stage));
			if (!accept(stage)) {
				Skip(length - source.Consumed(), "packet data");
				return;
			}
		}
		if (options.reassemble_dns || options.reassemble_tcp) {
			const auto &packet = record.decoded;
			if (!packet.transport ||
			    (options.reassemble_tcp ? !packet.tcp : (packet.src_port != 53 && packet.dst_port != 53))) {
				record.selected = false;
			} else if (packet.payload_length > 0) {
				const auto *bytes = source.ReadPrefix(packet.payload_offset + packet.payload_length);
				record.transport_data.assign(bytes + packet.payload_offset,
				                             bytes + packet.payload_offset + packet.payload_length);
			}
			Skip(length - source.Consumed(), "packet data");
			return;
		}
		if (options.dns_scan) {
			const auto &packet = record.decoded;
			if (!packet.transport || (packet.src_port != 53 && packet.dst_port != 53) || packet.payload_length == 0) {
				record.selected = false;
				Skip(length - source.Consumed(), "packet data");
				return;
			}
			if (options.decode_dns) {
				const auto *bytes = source.ReadPrefix(packet.payload_offset + packet.payload_length);
				const auto *message = bytes + packet.payload_offset;
				auto message_length = packet.payload_length;
				bool complete = true;
				if (packet.tcp) {
					if (message_length < 2 || ReadU16(message, ByteOrder::BIG) != message_length - 2) {
						complete = false;
						record.dns.error = "TCP DNS requires exactly one complete length-prefixed message per packet";
					} else {
						message += 2;
						message_length -= 2;
					}
				} else if (message_length != packet.udp_length - 8U) {
					complete = false;
					record.dns.error = "truncated UDP DNS payload";
				}
				if (complete) {
					record.dns = packetquapture::DecodeDns(message, message_length);
				}
			}
			if (!accept(4)) {
				Skip(length - source.Consumed(), "packet data");
				return;
			}
		}
		if (options.materialize_packet_data) {
			source.ReadPrefix(length);
			record.packet_data = source.TakeBytes();
			accept(5);
		} else {
			Skip(length - source.Consumed(), "packet data");
		}
	}

	timestamp_t TimestampFromParts(uint64_t seconds, uint64_t fraction, long double ticks_per_second) const {
		const long double micros = static_cast<long double>(seconds) * 1000000.0L +
		                           static_cast<long double>(fraction) * 1000000.0L / ticks_per_second;
		return CheckedTimestamp(micros);
	}

	timestamp_t TimestampFromTicks(uint64_t ticks, long double ticks_per_second) const {
		if (ticks_per_second <= 0 || !std::isfinite(ticks_per_second)) {
			throw InvalidInputException("Invalid PCAPNG timestamp resolution in '%s'", file.path);
		}
		return CheckedTimestamp(static_cast<long double>(ticks) * 1000000.0L / ticks_per_second);
	}

	timestamp_t CheckedTimestamp(long double micros) const {
		if (!std::isfinite(micros) || micros > static_cast<long double>(std::numeric_limits<int64_t>::max())) {
			throw InvalidInputException("Packet timestamp is out of range in '%s'", file.path);
		}
		return Timestamp::FromEpochMicroSeconds(static_cast<int64_t>(micros));
	}

	void ValidatePacketLength(uint32_t length) const {
		if (length > MAX_CAPTURED_PACKET_SIZE) {
			throw InvalidInputException("Captured packet length %d exceeds PacketQuapture's safety limit in '%s'",
			                            length, file.path);
		}
	}

	void ValidateBlockLength(uint32_t length, uint32_t minimum, const char *description) const {
		if (length < minimum || (length % 4) != 0) {
			throw InvalidInputException("Invalid PCAPNG %s length %d in '%s'", description, length, file.path);
		}
	}

	void ValidateTrailer(const uint8_t *trailer, uint32_t expected_length) const {
		if (ReadU32(trailer, order) != expected_length) {
			throw InvalidInputException("PCAPNG block length mismatch in '%s'", file.path);
		}
	}

	void ReadAndValidateTrailer(uint32_t expected_length) {
		std::array<uint8_t, 4> trailer {};
		ReadExact(trailer.data(), trailer.size(), "PCAPNG block trailer");
		ValidateTrailer(trailer.data(), expected_length);
	}

	bool ReadMaybe(void *buffer, idx_t length) {
		idx_t total = 0;
		while (total < length) {
			if (context.IsInterrupted()) {
				throw InterruptException();
			}
			auto destination = static_cast<uint8_t *>(buffer) + total;
			const auto bytes_read = cached_handle && can_skip_by_seek
			                            ? ReadRemoteWindow(destination, length - total, position + total)
			                            : NumericCast<idx_t>(RawHandle().Read(destination, length - total));
			if (bytes_read == 0) {
				if (total == 0) {
					return false;
				}
				throw IOException("Unexpected end of capture file '%s' at byte %d", file.path, position + total);
			}
			total += NumericCast<idx_t>(bytes_read);
		}
		position += length;
		PublishProgress();
		return true;
	}

	void ReadExact(void *buffer, idx_t length, const char *description) {
		if (length > 0 && !ReadMaybe(buffer, length)) {
			throw IOException("Unexpected end of '%s' while reading %s", file.path, description);
		}
	}

	void Skip(idx_t length, const char *description) {
		if (length == 0) {
			return;
		}
		if (can_skip_by_seek) {
			if (position > seekable_size || length > seekable_size - position) {
				throw IOException("Unexpected end of '%s' while reading %s", file.path, description);
			}
			if (!cached_handle) {
				handle->Seek(position + length);
			}
			position += length;
			PublishProgress();
			return;
		}
		std::array<uint8_t, 8192> buffer {};
		while (length > 0) {
			const auto chunk_size = MinValue<idx_t>(length, buffer.size());
			ReadExact(buffer.data(), chunk_size, description);
			length -= chunk_size;
		}
	}

private:
	OpenFileInfo file;
	ClientContext &context;
	FileSystem &fs;
	unique_ptr<FileHandle> handle;
	unique_ptr<CachingFileSystem> caching_fs;
	unique_ptr<CachingFileHandle> cached_handle;
	BufferHandle window;
	data_ptr_t window_data = nullptr;
	idx_t window_start = 0, window_length = 0;
	const ScanOptions &options;
	CaptureProgress *progress;
	uint64_t published_position = 0;
	bool can_skip_by_seek = false;
	uint64_t seekable_size = 0;
	CaptureFormat format = CaptureFormat::PCAP;
	ByteOrder order = ByteOrder::LITTLE;
	bool nanosecond_timestamps = false;
	uint32_t pcap_link_type = 0;
	uint64_t position = 0;
	uint64_t packet_number = 0;
	uint32_t section_number = 0;
	vector<PcapNgInterface> interfaces;
};

struct PcapBindData : public TableFunctionData {
	vector<OpenFileInfo> files;
	vector<LogicalType> types;
	bool dns_scan = false;
	shared_ptr<StreamPlanCount> stream_plan;

	unique_ptr<FunctionData> Copy() const override {
		auto result = make_uniq<PcapBindData>();
		result->files = files;
		result->types = types;
		result->dns_scan = dns_scan;
		result->stream_plan = stream_plan;
		if (stream_plan) {
			stream_plan->scans.fetch_add(1);
		}
		return std::move(result);
	}

	bool Equals(const FunctionData &other_p) const override {
		auto &other = other_p.Cast<PcapBindData>();
		if (files.size() != other.files.size() || types != other.types || dns_scan != other.dns_scan) {
			return false;
		}
		for (idx_t i = 0; i < files.size(); i++) {
			if (files[i].path != other.files[i].path) {
				return false;
			}
		}
		return true;
	}
};

// Every input occurrence is work, including duplicate paths. Bind data owns the
// immutable file list for the lifetime of the global and local scan states.
class FileScheduler {
public:
	explicit FileScheduler(idx_t file_count_p) : file_count(file_count_p) {
	}

	bool Claim(idx_t &index) {
		index = next_file.fetch_add(1, std::memory_order_relaxed);
		return index < file_count;
	}

	idx_t MaxThreads() const {
		// DuckDB still creates one local state for an empty scan.
		return MaxValue<idx_t>(1, file_count);
	}

private:
	const idx_t file_count;
	std::atomic<idx_t> next_file {0};
};

struct PacketFilterDefinition {
	column_t column;
	unique_ptr<TableFilter> filter;
};

struct PcapGlobalState : public CaptureGlobalState {
	explicit PcapGlobalState(idx_t file_count) : scheduler(file_count) {
	}

	idx_t MaxThreads() const override {
		return scheduler.MaxThreads();
	}

	FileScheduler scheduler;
	vector<column_t> column_ids;
	ScanOptions options;
	vector<PacketFilterDefinition> filters;
};

struct PcapLocalState : public LocalTableFunctionState {
	ScanOptions options;
	vector<unique_ptr<PacketFilter>> filters;
	unique_ptr<CaptureReader> reader;
};

static unique_ptr<FunctionData> PcapBind(ClientContext &context, TableFunctionBindInput &input,
                                         vector<LogicalType> &return_types, vector<string> &names) {
	auto result = make_uniq<PcapBindData>();
	auto multi_file_reader = MultiFileReader::Create(input.table_function);
	result->files = multi_file_reader->CreateFileList(context, input.inputs[0])->GetAllFiles();

	names = {"filename",     "packet_number", "timestamp",      "captured_length", "original_length", "link_type",
	         "interface_id", "packet_offset", "capture_format", "packet_data",     "section_number"};
	return_types = {LogicalType::VARCHAR,  LogicalType::UBIGINT,  LogicalType::TIMESTAMP, LogicalType::UINTEGER,
	                LogicalType::UINTEGER, LogicalType::UINTEGER, LogicalType::UINTEGER,  LogicalType::UBIGINT,
	                LogicalType::VARCHAR,  LogicalType::BLOB,     LogicalType::UINTEGER};
	result->types = return_types;
	return std::move(result);
}

static unique_ptr<FunctionData> PacketsBind(ClientContext &context, TableFunctionBindInput &input,
                                            vector<LogicalType> &return_types, vector<string> &names) {
	auto result = PcapBind(context, input, return_types, names);
	const vector<string> decoded_names = {"src_mac",
	                                      "dst_mac",
	                                      "ether_type",
	                                      "vlan_ids",
	                                      "ip_version",
	                                      "src_ip",
	                                      "dst_ip",
	                                      "ip_protocol",
	                                      "ip_ttl",
	                                      "ip_fragment_offset",
	                                      "ip_more_fragments",
	                                      "ip_id",
	                                      "src_port",
	                                      "dst_port",
	                                      "tcp_flags",
	                                      "tcp_seq",
	                                      "tcp_ack",
	                                      "tcp_header_length",
	                                      "udp_length",
	                                      "payload_offset",
	                                      "payload_length"};
	const vector<LogicalType> decoded_types = {LogicalType::VARCHAR,   LogicalType::VARCHAR,
	                                           LogicalType::USMALLINT, LogicalType::LIST(LogicalType::USMALLINT),
	                                           LogicalType::UTINYINT,  LogicalType::VARCHAR,
	                                           LogicalType::VARCHAR,   LogicalType::UTINYINT,
	                                           LogicalType::UTINYINT,  LogicalType::UINTEGER,
	                                           LogicalType::BOOLEAN,   LogicalType::UINTEGER,
	                                           LogicalType::USMALLINT, LogicalType::USMALLINT,
	                                           LogicalType::USMALLINT, LogicalType::UINTEGER,
	                                           LogicalType::UINTEGER,  LogicalType::UTINYINT,
	                                           LogicalType::USMALLINT, LogicalType::UINTEGER,
	                                           LogicalType::UINTEGER};
	names.insert(names.end(), decoded_names.begin(), decoded_names.end());
	return_types.insert(return_types.end(), decoded_types.begin(), decoded_types.end());
	for (const auto *name :
	     {"tcp_fin", "tcp_syn", "tcp_rst", "tcp_psh", "tcp_ack_flag", "tcp_urg", "tcp_ece", "tcp_cwr"}) {
		names.push_back(name);
		return_types.push_back(LogicalType::BOOLEAN);
	}
	result->Cast<PcapBindData>().types = return_types;
	return result;
}

static LogicalType DnsQuestionType() {
	return LogicalType::STRUCT(
	    {{"name", LogicalType::VARCHAR}, {"type", LogicalType::USMALLINT}, {"class", LogicalType::USMALLINT}});
}
static LogicalType DnsRecordType() {
	return LogicalType::STRUCT({{"name", LogicalType::VARCHAR},
	                            {"type", LogicalType::USMALLINT},
	                            {"class", LogicalType::USMALLINT},
	                            {"ttl", LogicalType::UINTEGER},
	                            {"value", LogicalType::VARCHAR},
	                            {"data", LogicalType::BLOB}});
}
static unique_ptr<FunctionData> DnsBind(ClientContext &context, TableFunctionBindInput &input,
                                        vector<LogicalType> &return_types, vector<string> &names) {
	auto result = PacketsBind(context, input, return_types, names);
	const vector<string> dns_names = {"dns_valid",          "dns_id",        "dns_response",      "dns_opcode",
	                                  "dns_rcode",          "dns_truncated", "dns_question_name", "dns_question_type",
	                                  "dns_question_class", "dns_questions", "dns_answers",       "dns_authorities",
	                                  "dns_additionals",    "dns_error"};
	const vector<LogicalType> dns_types = {LogicalType::BOOLEAN,
	                                       LogicalType::USMALLINT,
	                                       LogicalType::BOOLEAN,
	                                       LogicalType::UTINYINT,
	                                       LogicalType::UTINYINT,
	                                       LogicalType::BOOLEAN,
	                                       LogicalType::VARCHAR,
	                                       LogicalType::USMALLINT,
	                                       LogicalType::USMALLINT,
	                                       LogicalType::LIST(DnsQuestionType()),
	                                       LogicalType::LIST(DnsRecordType()),
	                                       LogicalType::LIST(DnsRecordType()),
	                                       LogicalType::LIST(DnsRecordType()),
	                                       LogicalType::VARCHAR};
	names.insert(names.end(), dns_names.begin(), dns_names.end());
	return_types.insert(return_types.end(), dns_types.begin(), dns_types.end());
	result->Cast<PcapBindData>().types = return_types;
	result->Cast<PcapBindData>().dns_scan = true;
	return result;
}

static unique_ptr<GlobalTableFunctionState> PcapInit(ClientContext &context, TableFunctionInitInput &input) {
	auto &bind = input.bind_data->Cast<PcapBindData>();
	auto result = make_uniq<PcapGlobalState>(bind.files.size());
	result->progress.Initialize(context, bind.files);
	result->column_ids = input.column_ids;
	auto &options = result->options;
	options.dns_scan = bind.dns_scan;
	if (bind.dns_scan) {
		options.decode_depth = packetquapture::DecodeDepth::TRANSPORT;
	}
	for (const auto column : result->column_ids) {
		if (column == 9) {
			options.materialize_packet_data = true;
		}
		if (column >= 40 && column < bind.types.size()) {
			options.decode_dns = true;
		}
		if (column >= 11 && column < bind.types.size()) {
			const auto depth = static_cast<packetquapture::DecodeDepth>(MinValue<unsigned>(3, ColumnStage(column)));
			if (depth > options.decode_depth) {
				options.decode_depth = depth;
			}
		}
	}
	if (input.filters) {
		for (const auto &entry : input.filters->filters) {
			const auto &filter = *entry.second;
			// These are advisory filters; the remaining join/filter still enforces SQL semantics.
			if (filter.filter_type == TableFilterType::OPTIONAL_FILTER ||
			    filter.filter_type == TableFilterType::DYNAMIC_FILTER ||
			    filter.filter_type == TableFilterType::BLOOM_FILTER) {
				continue;
			}
			const auto column = input.column_ids[entry.first];
			result->filters.push_back({column, filter.Copy()});
			options.filter_stages[ColumnStage(column)] = true;
		}
	}
	return std::move(result);
}

static unique_ptr<LocalTableFunctionState> PcapInitLocal(ExecutionContext &context, TableFunctionInitInput &input,
                                                         GlobalTableFunctionState *global_state) {
	auto &global = global_state->Cast<PcapGlobalState>();
	auto &bind = input.bind_data->Cast<PcapBindData>();
	auto result = make_uniq<PcapLocalState>();
	result->options = global.options;
	for (const auto &definition : global.filters) {
		result->filters.push_back(make_uniq<PacketFilter>(context.client, definition.column,
		                                                  bind.types[definition.column], *definition.filter));
	}
	auto *state = result.get();
	result->options.matches = [state](const PacketRecord &record, unsigned stage) {
		for (auto &filter : state->filters) {
			if (filter->stage == stage && !filter->Matches(record)) {
				return false;
			}
		}
		return true;
	};
	return std::move(result);
}

static void SetOutputValue(Vector &vector, idx_t row, column_t column_id, const PacketRecord &record) {
	switch (column_id) {
	case 0:
		vector.SetValue(row, record.filename);
		break;
	case 1:
		vector.SetValue(row, Value::UBIGINT(record.packet_number));
		break;
	case 2:
		if (record.has_timestamp) {
			vector.SetValue(row, Value::TIMESTAMP(record.timestamp));
		} else {
			FlatVector::SetNull(vector, row, true);
		}
		break;
	case 3:
		vector.SetValue(row, Value::UINTEGER(record.captured_length));
		break;
	case 4:
		vector.SetValue(row, Value::UINTEGER(record.original_length));
		break;
	case 5:
		vector.SetValue(row, Value::UINTEGER(record.link_type));
		break;
	case 6:
		vector.SetValue(row, Value::UINTEGER(record.interface_id));
		break;
	case 7:
		vector.SetValue(row, Value::UBIGINT(record.packet_offset));
		break;
	case 8:
		vector.SetValue(row, record.format == CaptureFormat::PCAP ? "pcap" : "pcapng");
		break;
	case 9:
		if (record.packet_data.empty()) {
			vector.SetValue(row, Value::BLOB(""));
		} else {
			vector.SetValue(row, Value::BLOB(record.packet_data.data(), record.packet_data.size()));
		}
		break;
	case 10:
		vector.SetValue(row, Value::UINTEGER(record.section_number));
		break;
	default:
		throw InternalException("Unexpected read_pcap column id %d", column_id);
	}
}

template <class T>
static void SetDecodedScalar(Vector &vector, idx_t row, T value) {
	FlatVector::SetNull(vector, row, false);
	FlatVector::GetData<T>(vector)[row] = value;
}

static string MacString(const std::array<uint8_t, 6> &address) {
	char buffer[18];
	std::snprintf(buffer, sizeof(buffer), "%02x:%02x:%02x:%02x:%02x:%02x", address[0], address[1], address[2],
	              address[3], address[4], address[5]);
	return buffer;
}

static string IpString(const std::array<uint8_t, 16> &address, uint8_t version) {
	char buffer[40];
	if (version == 4) {
		std::snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u", address[0], address[1], address[2], address[3]);
	} else {
		std::snprintf(buffer, sizeof(buffer), "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		              address[0], address[1], address[2], address[3], address[4], address[5], address[6], address[7],
		              address[8], address[9], address[10], address[11], address[12], address[13], address[14],
		              address[15]);
	}
	return buffer;
}

static void SetDecodedValue(Vector &vector, idx_t row, column_t column, const packetquapture::DecodedPacket &packet) {
	bool valid = column < 15 ? packet.ethernet : column < 23 ? packet.network : packet.transport;
	if (column >= 32 && column <= 39) {
		if (!packet.tcp) {
			FlatVector::SetNull(vector, row, true);
		} else {
			SetDecodedScalar(vector, row, (packet.tcp_flags & (1U << (column - 32))) != 0);
		}
		return;
	}
	if (column == 22) {
		valid = valid && packet.has_ip_id;
	} else if (column >= 25 && column <= 28) {
		valid = packet.tcp;
	} else if (column == 29) {
		valid = packet.udp;
	}
	if (!valid) {
		FlatVector::SetNull(vector, row, true);
		return;
	}
	switch (column) {
	case 11:
		vector.SetValue(row, MacString(packet.src_mac));
		break;
	case 12:
		vector.SetValue(row, MacString(packet.dst_mac));
		break;
	case 13:
		SetDecodedScalar(vector, row, packet.ether_type);
		break;
	case 14: {
		duckdb::vector<Value> tags;
		for (const auto tag : packet.vlan_ids) {
			tags.push_back(Value::USMALLINT(tag));
		}
		vector.SetValue(row, Value::LIST(LogicalType::USMALLINT, tags));
		break;
	}
	case 15:
		SetDecodedScalar(vector, row, packet.ip_version);
		break;
	case 16:
		vector.SetValue(row, IpString(packet.src_ip, packet.ip_version));
		break;
	case 17:
		vector.SetValue(row, IpString(packet.dst_ip, packet.ip_version));
		break;
	case 18:
		SetDecodedScalar(vector, row, packet.ip_protocol);
		break;
	case 19:
		SetDecodedScalar(vector, row, packet.ip_ttl);
		break;
	case 20:
		SetDecodedScalar(vector, row, packet.ip_fragment_offset);
		break;
	case 21:
		SetDecodedScalar(vector, row, packet.ip_more_fragments);
		break;
	case 22:
		SetDecodedScalar(vector, row, packet.ip_id);
		break;
	case 23:
		SetDecodedScalar(vector, row, packet.src_port);
		break;
	case 24:
		SetDecodedScalar(vector, row, packet.dst_port);
		break;
	case 25:
		SetDecodedScalar(vector, row, packet.tcp_flags);
		break;
	case 26:
		SetDecodedScalar(vector, row, packet.tcp_seq);
		break;
	case 27:
		SetDecodedScalar(vector, row, packet.tcp_ack);
		break;
	case 28:
		SetDecodedScalar(vector, row, packet.tcp_header_length);
		break;
	case 29:
		SetDecodedScalar(vector, row, packet.udp_length);
		break;
	case 30:
		SetDecodedScalar(vector, row, packet.payload_offset);
		break;
	case 31:
		SetDecodedScalar(vector, row, packet.payload_length);
		break;
	default:
		throw InternalException("Unexpected read_packets column id %d", column);
	}
}

static Value DnsRecordsValue(const std::vector<packetquapture::DnsRecord> &records) {
	vector<Value> values;
	for (const auto &record : records) {
		values.push_back(Value::STRUCT(
		    DnsRecordType(),
		    {Value(record.name), Value::USMALLINT(record.type), Value::USMALLINT(record.klass),
		     Value::UINTEGER(record.ttl), record.has_text ? Value(record.text) : Value(LogicalType::VARCHAR),
		     record.data.empty() ? Value::BLOB("") : Value::BLOB(record.data.data(), record.data.size())}));
	}
	return Value::LIST(DnsRecordType(), values);
}

static void SetRecordValue(Vector &vector, idx_t row, column_t column, const PacketRecord &record) {
	if (column < 11) {
		SetOutputValue(vector, row, column, record);
		return;
	}
	if (column < 40) {
		SetDecodedValue(vector, row, column, record.decoded);
		return;
	}
	const auto &dns = record.dns;
	if (column == 40) {
		SetDecodedScalar(vector, row, dns.valid);
		return;
	}
	if (column == 53) {
		if (dns.error.empty()) {
			FlatVector::SetNull(vector, row, true);
		} else {
			vector.SetValue(row, dns.error);
		}
		return;
	}
	if (!dns.valid || (column >= 46 && column <= 48 && dns.questions.empty())) {
		FlatVector::SetNull(vector, row, true);
		return;
	}
	switch (column) {
	case 41:
		SetDecodedScalar(vector, row, dns.id);
		break;
	case 42:
		SetDecodedScalar(vector, row, dns.response);
		break;
	case 43:
		SetDecodedScalar(vector, row, dns.opcode);
		break;
	case 44:
		SetDecodedScalar(vector, row, dns.rcode);
		break;
	case 45:
		SetDecodedScalar(vector, row, dns.truncated);
		break;
	case 46:
		vector.SetValue(row, dns.questions[0].name);
		break;
	case 47:
		SetDecodedScalar(vector, row, dns.questions[0].type);
		break;
	case 48:
		SetDecodedScalar(vector, row, dns.questions[0].klass);
		break;
	case 49: {
		duckdb::vector<Value> questions;
		for (const auto &question : dns.questions) {
			questions.push_back(Value::STRUCT(DnsQuestionType(), {Value(question.name), Value::USMALLINT(question.type),
			                                                      Value::USMALLINT(question.klass)}));
		}
		vector.SetValue(row, Value::LIST(DnsQuestionType(), questions));
		break;
	}
	case 50:
		vector.SetValue(row, DnsRecordsValue(dns.answers));
		break;
	case 51:
		vector.SetValue(row, DnsRecordsValue(dns.authorities));
		break;
	case 52:
		vector.SetValue(row, DnsRecordsValue(dns.additionals));
		break;
	default:
		throw InternalException("Unexpected read_dns column id %d", column);
	}
}

static void NormalizeBooleanFilter(unique_ptr<Expression> &expression) {
	if (expression->GetExpressionClass() == ExpressionClass::BOUND_COLUMN_REF &&
	    expression->return_type == LogicalType::BOOLEAN) {
		expression = make_uniq<BoundComparisonExpression>(ExpressionType::COMPARE_EQUAL, std::move(expression),
		                                                  make_uniq<BoundConstantExpression>(Value(true)));
	} else if (expression->type == ExpressionType::OPERATOR_NOT) {
		auto &op = expression->Cast<BoundOperatorExpression>();
		if (op.children.size() == 1 && op.children[0]->GetExpressionClass() == ExpressionClass::BOUND_COLUMN_REF &&
		    op.children[0]->return_type == LogicalType::BOOLEAN) {
			expression = make_uniq<BoundComparisonExpression>(ExpressionType::COMPARE_EQUAL, std::move(op.children[0]),
			                                                  make_uniq<BoundConstantExpression>(Value(false)));
		}
	} else if (expression->GetExpressionClass() == ExpressionClass::BOUND_CONJUNCTION) {
		for (auto &child : expression->Cast<BoundConjunctionExpression>().children) {
			NormalizeBooleanFilter(child);
		}
	}
}

static void NormalizePacketFilters(ClientContext &, LogicalGet &, FunctionData *,
                                   vector<unique_ptr<Expression>> &filters) {
	for (auto &filter : filters) {
		NormalizeBooleanFilter(filter);
	}
}

static bool SupportsPacketFilter(const FunctionData &data, idx_t column) {
	const auto &types = data.Cast<PcapBindData>().types;
	return column < types.size() && types[column].id() != LogicalTypeId::LIST;
}

static void PcapScan(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
	auto &bind_data = input.bind_data->Cast<PcapBindData>();
	auto &global = input.global_state->Cast<PcapGlobalState>();
	auto &state = input.local_state->Cast<PcapLocalState>();
	idx_t output_count = 0;
	while (output_count < STANDARD_VECTOR_SIZE) {
		if (context.IsInterrupted()) {
			throw InterruptException();
		}
		if (!state.reader) {
			idx_t file_index;
			if (!global.scheduler.Claim(file_index)) {
				break;
			}
			state.reader = make_uniq<CaptureReader>(context, bind_data.files[file_index], state.options,
			                                        &global.progress, file_index);
		}
		PacketRecord record;
		if (!state.reader->Next(record)) {
			state.reader.reset();
			continue;
		}
		if (!record.selected) {
			continue;
		}
		for (idx_t output_column = 0; output_column < global.column_ids.size(); output_column++) {
			SetRecordValue(output.data[output_column], output_count, global.column_ids[output_column], record);
		}
		output_count++;
	}
	output.SetCardinality(output_count);
}

struct StreamGlobalState : public CaptureGlobalState {
	StreamGlobalState(ClientContext &context, const PcapBindData &bind)
	    : scheduler(bind.files.size()), file_count(bind.files.size()) {
		budget = context.registered_state->GetOrCreate<StreamQueryBudget>("packetquapture_stream_budget", context);
		if (bind.stream_plan) {
			bind.stream_plan->sealed.store(true);
			max_workers = MaxValue<idx_t>(1, budget->Slots() / bind.stream_plan->scans.load());
		}
		max_workers = MinValue<idx_t>(max_workers, MaxValue<idx_t>(1, file_count));
		if (file_count) {
			initial = make_uniq<StreamReservation>(budget);
			if (!initial->Acquired()) {
				throw OutOfMemoryException("PacketQuapture cannot reserve 128 MiB for a stream worker. "
				                           "Increase packetquapture_stream_memory_mb or memory_limit; "
				                           "all stream scans in this query share the budget.");
			}
		}
	}
	idx_t MaxThreads() const override {
		return max_workers;
	}
	unique_ptr<StreamReservation> Admit() {
		lock_guard<mutex> guard(lock);
		if (admitted >= max_workers) {
			return nullptr;
		}
		++admitted;
		if (initial) {
			return std::move(initial);
		}
		auto result = make_uniq<StreamReservation>(budget);
		return result->Acquired() ? std::move(result) : nullptr;
	}
	void Drained() {
		if (drained.fetch_add(1, std::memory_order_relaxed) + 1 == file_count) {
			progress.Finish();
		}
	}
	FileScheduler scheduler;
	const idx_t file_count;
	shared_ptr<StreamQueryBudget> budget;
	unique_ptr<StreamReservation> initial;
	mutex lock;
	std::atomic<idx_t> drained {0};
	idx_t max_workers = 1, admitted = 0;
	vector<column_t> columns;
	ScanOptions options;
	bool decode_dns = false;
};

struct StreamScanState : public LocalTableFunctionState {
	// Destroy all worker buffers before releasing the reservation.
	unique_ptr<StreamReservation> reservation;
	idx_t file_index = 0, stream_index = 0;
	bool file_finished = false, initialized = false;
	string filename;
	unique_ptr<CaptureReader> reader;
	packetquapture::TcpReassembler reassembler;
	std::vector<packetquapture::TcpStream> streams;
	idx_t pending_index = 0;
	std::vector<packetquapture::TcpDnsMessage> pending;
};

static unique_ptr<LocalTableFunctionState> StreamInitLocal(ExecutionContext &, TableFunctionInitInput &,
                                                           GlobalTableFunctionState *) {
	// Defer optional admission to execution. Pipeline initialization may interleave;
	// the plan-wide worker ceiling also leaves capacity for later scans.
	return make_uniq<StreamScanState>();
}

static packetquapture::TcpFlowKey FlowKey(const PacketRecord &record) {
	packetquapture::TcpFlowKey key;
	key.section = record.section_number;
	key.interface_id = record.interface_id;
	key.ip_version = record.decoded.ip_version;
	key.src_ip = record.decoded.src_ip;
	key.dst_ip = record.decoded.dst_ip;
	key.src_port = record.decoded.src_port;
	key.dst_port = record.decoded.dst_port;
	key.vlans = record.decoded.vlan_ids;
	return key;
}
static packetquapture::PacketStamp Stamp(const PacketRecord &record) {
	packetquapture::PacketStamp stamp;
	stamp.number = record.packet_number;
	stamp.has_timestamp = record.has_timestamp;
	stamp.timestamp = record.has_timestamp ? record.timestamp.value : 0;
	return stamp;
}
struct StreamEvent {
	bool tcp = false;
	packetquapture::TcpStream stream;
	PacketRecord datagram;
};

// Shared capture iteration and transport lifecycle for every stream-level consumer.
static bool NextStreamEvent(ClientContext &context, const PcapBindData &bind, StreamGlobalState &global,
                            StreamScanState &state, StreamEvent &event) {
	while (true) {
		if (context.IsInterrupted()) {
			throw InterruptException();
		}
		if (state.stream_index < state.streams.size()) {
			event.tcp = true;
			event.stream = std::move(state.streams[state.stream_index++]);
			event.stream.stream_id = StreamScanId(event.stream.stream_id, state.file_index, bind.files.size());
			return true;
		}
		state.streams.clear();
		state.stream_index = 0;
		if (state.file_finished) {
			if (!state.reassembler.Empty()) {
				state.streams = state.reassembler.FinishNext();
				continue;
			}
			state.reader.reset();
			state.file_finished = false;
			global.Drained();
		}
		if (!state.reader) {
			if (!global.scheduler.Claim(state.file_index)) {
				return false;
			}
			const auto &file = bind.files[state.file_index];
			state.filename = file.path;
			state.reassembler = packetquapture::TcpReassembler();
			state.reader = make_uniq<CaptureReader>(context, file, global.options, &global.progress, state.file_index);
		}
		PacketRecord record;
		if (!state.reader->Next(record)) {
			state.file_finished = true;
			continue;
		}
		if (!record.selected) {
			continue;
		}
		const auto &packet = record.decoded;
		if (packet.tcp) {
			state.streams = state.reassembler.Add(
			    FlowKey(record), packet.tcp_seq, static_cast<uint8_t>(packet.tcp_flags), record.transport_data.data(),
			    record.transport_data.size(), packet.payload_declared_length, Stamp(record));
		} else {
			event.tcp = false;
			event.datagram = std::move(record);
			return true;
		}
	}
}

static unique_ptr<FunctionData> DnsMessagesBind(ClientContext &context, TableFunctionBindInput &input,
                                                vector<LogicalType> &types, vector<string> &names) {
	auto result = DnsBind(context, input, types, names);
	vector<LogicalType> dns_types(types.begin() + 40, types.end());
	vector<string> dns_names(names.begin() + 40, names.end());
	names = {"filename",
	         "section_number",
	         "interface_id",
	         "ip_version",
	         "src_ip",
	         "dst_ip",
	         "src_port",
	         "dst_port",
	         "transport",
	         "stream_id",
	         "message_number",
	         "first_packet_number",
	         "last_packet_number",
	         "first_timestamp",
	         "last_timestamp",
	         "tcp_sequence",
	         "reassembly_status",
	         "reassembly_error",
	         "message_data",
	         "vlan_ids"};
	types = {LogicalType::VARCHAR,   LogicalType::UINTEGER,
	         LogicalType::UINTEGER,  LogicalType::UTINYINT,
	         LogicalType::VARCHAR,   LogicalType::VARCHAR,
	         LogicalType::USMALLINT, LogicalType::USMALLINT,
	         LogicalType::VARCHAR,   LogicalType::UBIGINT,
	         LogicalType::UBIGINT,   LogicalType::UBIGINT,
	         LogicalType::UBIGINT,   LogicalType::TIMESTAMP,
	         LogicalType::TIMESTAMP, LogicalType::UINTEGER,
	         LogicalType::VARCHAR,   LogicalType::VARCHAR,
	         LogicalType::BLOB,      LogicalType::LIST(LogicalType::USMALLINT)};
	names.insert(names.end(), dns_names.begin(), dns_names.end());
	types.insert(types.end(), dns_types.begin(), dns_types.end());
	result->Cast<PcapBindData>().types = types;
	result->Cast<PcapBindData>().stream_plan =
	    context.registered_state->GetOrCreate<StreamPlanRegistry>("packetquapture_stream_plans")->Register();
	return result;
}

static unique_ptr<GlobalTableFunctionState> DnsMessagesInit(ClientContext &context, TableFunctionInitInput &input) {
	auto state = make_uniq<StreamGlobalState>(context, input.bind_data->Cast<PcapBindData>());
	state->progress.Initialize(context, input.bind_data->Cast<PcapBindData>().files, true);
	state->columns = input.column_ids;
	state->options.reassemble_dns = true;
	state->options.decode_depth = packetquapture::DecodeDepth::TRANSPORT;
	for (const auto column : state->columns) {
		if (column >= 20 && column < 34) {
			state->decode_dns = true;
		}
	}
	return std::move(state);
}

static void SetMessageValue(Vector &vector, idx_t row, column_t column, const string &filename,
                            const packetquapture::TcpDnsMessage &message, const PacketRecord &dns_record) {
	const auto &key = message.key;
	if (column >= 20 && column < 34) {
		SetRecordValue(vector, row, column + 20, dns_record);
		return;
	}
	switch (column) {
	case 0:
		vector.SetValue(row, filename);
		break;
	case 1:
		SetDecodedScalar(vector, row, key.section);
		break;
	case 2:
		SetDecodedScalar(vector, row, key.interface_id);
		break;
	case 3:
		SetDecodedScalar(vector, row, key.ip_version);
		break;
	case 4:
		vector.SetValue(row, IpString(key.src_ip, key.ip_version));
		break;
	case 5:
		vector.SetValue(row, IpString(key.dst_ip, key.ip_version));
		break;
	case 6:
		SetDecodedScalar(vector, row, key.src_port);
		break;
	case 7:
		SetDecodedScalar(vector, row, key.dst_port);
		break;
	case 8:
		vector.SetValue(row, message.tcp ? "tcp" : "udp");
		break;
	case 9:
		if (message.tcp) {
			SetDecodedScalar(vector, row, message.stream_id);
		} else {
			FlatVector::SetNull(vector, row, true);
		}
		break;
	case 10:
		if (message.message_number) {
			SetDecodedScalar(vector, row, message.message_number);
		} else {
			FlatVector::SetNull(vector, row, true);
		}
		break;
	case 11:
		SetDecodedScalar(vector, row, message.first.number);
		break;
	case 12:
		SetDecodedScalar(vector, row, message.last.number);
		break;
	case 13:
	case 14: {
		const auto &stamp = column == 13 ? message.first : message.last;
		if (stamp.has_timestamp) {
			vector.SetValue(row, Value::TIMESTAMP(timestamp_t(stamp.timestamp)));
		} else {
			FlatVector::SetNull(vector, row, true);
		}
		break;
	}
	case 15:
		if (message.tcp &&
		    (message.status == "complete" || message.status == "incomplete" || message.status == "invalid")) {
			SetDecodedScalar(vector, row, message.sequence);
		} else {
			FlatVector::SetNull(vector, row, true);
		}
		break;
	case 16:
		vector.SetValue(row, message.status);
		break;
	case 17:
		if (message.error.empty()) {
			FlatVector::SetNull(vector, row, true);
		} else {
			vector.SetValue(row, message.error);
		}
		break;
	case 18:
		if (message.status != "complete") {
			FlatVector::SetNull(vector, row, true);
		} else if (message.data.empty()) {
			vector.SetValue(row, Value::BLOB(""));
		} else {
			vector.SetValue(row, Value::BLOB(message.data.data(), message.data.size()));
		}
		break;
	case 19: {
		duckdb::vector<Value> tags;
		for (const auto tag : key.vlans) {
			tags.push_back(Value::USMALLINT(tag));
		}
		vector.SetValue(row, Value::LIST(LogicalType::USMALLINT, tags));
		break;
	}
	default:
		throw InternalException("Unexpected read_dns_messages column id %d", column);
	}
}

static void DnsMessagesScan(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
	auto &bind = input.bind_data->Cast<PcapBindData>();
	auto &global = input.global_state->Cast<StreamGlobalState>();
	auto &state = input.local_state->Cast<StreamScanState>();
	if (!state.initialized) {
		state.initialized = true;
		if (global.file_count) {
			state.reservation = global.Admit();
		}
	}
	if (!state.reservation) {
		return;
	}
	idx_t count = 0, output_bytes = 0;
	while (count < STANDARD_VECTOR_SIZE && output_bytes < STREAM_OUTPUT_BATCH_BYTES) {
		if (context.IsInterrupted()) {
			throw InterruptException();
		}
		if (state.pending_index < state.pending.size()) {
			const auto &message = state.pending[state.pending_index++];
			PacketRecord dns_record;
			if (global.decode_dns) {
				if (message.status == "complete") {
					dns_record.dns = packetquapture::DecodeDns(message.data.data(), message.data.size());
				} else {
					dns_record.dns.error = message.error;
				}
			}
			for (idx_t i = 0; i < global.columns.size(); ++i) {
				SetMessageValue(output.data[i], count, global.columns[i], state.filename, message, dns_record);
			}
			output_bytes += 1024 + state.filename.size() + message.data.size() * 4;
			output_bytes += (dns_record.dns.questions.size() + dns_record.dns.answers.size() +
			                 dns_record.dns.authorities.size() + dns_record.dns.additionals.size()) *
			                4096;
			++count;
			continue;
		}
		state.pending.clear();
		state.pending_index = 0;
		StreamEvent event;
		if (!NextStreamEvent(context, bind, global, state, event)) {
			break;
		}
		if (event.tcp) {
			state.pending = packetquapture::FrameTcpDns(event.stream);
		} else {
			const auto &record = event.datagram;
			const auto &packet = record.decoded;
			packetquapture::TcpDnsMessage message;
			message.key = FlowKey(record);
			message.tcp = false;
			message.first = message.last = Stamp(record);
			message.message_number = 1;
			if (packet.payload_length == packet.payload_declared_length) {
				message.status = "complete";
				message.data.assign(record.transport_data.begin(), record.transport_data.end());
			} else {
				message.status = "incomplete";
				message.error = "truncated UDP DNS payload";
				message.message_number = 0;
			}
			state.pending.push_back(std::move(message));
		}
	}
	output.SetCardinality(count);
	if (!count) {
		std::vector<packetquapture::TcpStream>().swap(state.streams);
		std::vector<packetquapture::TcpDnsMessage>().swap(state.pending);
		state.reassembler = packetquapture::TcpReassembler();
		state.reservation.reset();
	}
}

static LogicalType TcpChunkType() {
	return LogicalType::STRUCT({{"offset", LogicalType::UINTEGER},
	                            {"tcp_sequence", LogicalType::UINTEGER},
	                            {"data", LogicalType::BLOB},
	                            {"first_packet_number", LogicalType::UBIGINT},
	                            {"last_packet_number", LogicalType::UBIGINT}});
}
static LogicalType TcpGapType() {
	return LogicalType::STRUCT({{"offset", LogicalType::UINTEGER}, {"length", LogicalType::UINTEGER}});
}
static unique_ptr<FunctionData> TcpStreamsBind(ClientContext &context, TableFunctionBindInput &input,
                                               vector<LogicalType> &types, vector<string> &names) {
	auto result = PcapBind(context, input, types, names);
	names = {"filename",
	         "section_number",
	         "interface_id",
	         "ip_version",
	         "src_ip",
	         "dst_ip",
	         "src_port",
	         "dst_port",
	         "stream_id",
	         "tcp_sequence",
	         "syn_seen",
	         "fin_seen",
	         "reset_seen",
	         "finalized_by",
	         "reassembly_status",
	         "reassembly_error",
	         "first_packet_number",
	         "last_packet_number",
	         "first_timestamp",
	         "last_timestamp",
	         "expected_bytes",
	         "captured_bytes",
	         "has_gaps",
	         "stream_data",
	         "chunks",
	         "gaps",
	         "vlan_ids"};
	types = {LogicalType::VARCHAR,
	         LogicalType::UINTEGER,
	         LogicalType::UINTEGER,
	         LogicalType::UTINYINT,
	         LogicalType::VARCHAR,
	         LogicalType::VARCHAR,
	         LogicalType::USMALLINT,
	         LogicalType::USMALLINT,
	         LogicalType::UBIGINT,
	         LogicalType::UINTEGER,
	         LogicalType::BOOLEAN,
	         LogicalType::BOOLEAN,
	         LogicalType::BOOLEAN,
	         LogicalType::VARCHAR,
	         LogicalType::VARCHAR,
	         LogicalType::VARCHAR,
	         LogicalType::UBIGINT,
	         LogicalType::UBIGINT,
	         LogicalType::TIMESTAMP,
	         LogicalType::TIMESTAMP,
	         LogicalType::UINTEGER,
	         LogicalType::UINTEGER,
	         LogicalType::BOOLEAN,
	         LogicalType::BLOB,
	         LogicalType::LIST(TcpChunkType()),
	         LogicalType::LIST(TcpGapType()),
	         LogicalType::LIST(LogicalType::USMALLINT)};
	result->Cast<PcapBindData>().types = types;
	result->Cast<PcapBindData>().stream_plan =
	    context.registered_state->GetOrCreate<StreamPlanRegistry>("packetquapture_stream_plans")->Register();
	return result;
}
static unique_ptr<GlobalTableFunctionState> TcpStreamsInit(ClientContext &context, TableFunctionInitInput &input) {
	auto state = make_uniq<StreamGlobalState>(context, input.bind_data->Cast<PcapBindData>());
	state->progress.Initialize(context, input.bind_data->Cast<PcapBindData>().files, true);
	state->columns = input.column_ids;
	state->options.reassemble_tcp = true;
	state->options.decode_depth = packetquapture::DecodeDepth::TRANSPORT;
	return std::move(state);
}
static void SetStreamValue(Vector &vector, idx_t row, column_t column, const string &filename,
                           const packetquapture::TcpStream &stream) {
	const auto &key = stream.key;
	const bool failed = stream.status == "conflict" || stream.status == "limit";
	if (failed && (column == 9 || (column >= 20 && column <= 25))) {
		FlatVector::SetNull(vector, row, true);
		return;
	}
	switch (column) {
	case 0:
		vector.SetValue(row, filename);
		break;
	case 1:
		SetDecodedScalar(vector, row, key.section);
		break;
	case 2:
		SetDecodedScalar(vector, row, key.interface_id);
		break;
	case 3:
		SetDecodedScalar(vector, row, key.ip_version);
		break;
	case 4:
		vector.SetValue(row, IpString(key.src_ip, key.ip_version));
		break;
	case 5:
		vector.SetValue(row, IpString(key.dst_ip, key.ip_version));
		break;
	case 6:
		SetDecodedScalar(vector, row, key.src_port);
		break;
	case 7:
		SetDecodedScalar(vector, row, key.dst_port);
		break;
	case 8:
		SetDecodedScalar(vector, row, stream.stream_id);
		break;
	case 9:
		SetDecodedScalar(vector, row, stream.sequence);
		break;
	case 10:
		SetDecodedScalar(vector, row, stream.syn_seen);
		break;
	case 11:
		SetDecodedScalar(vector, row, stream.fin_seen);
		break;
	case 12:
		SetDecodedScalar(vector, row, stream.finalized_by == "reset");
		break;
	case 13:
		vector.SetValue(row, stream.finalized_by);
		break;
	case 14:
		vector.SetValue(row, stream.status);
		break;
	case 15:
		if (stream.error.empty()) {
			FlatVector::SetNull(vector, row, true);
		} else {
			vector.SetValue(row, stream.error);
		}
		break;
	case 16:
		SetDecodedScalar(vector, row, stream.first.number);
		break;
	case 17:
		SetDecodedScalar(vector, row, stream.last.number);
		break;
	case 18:
	case 19: {
		const auto &stamp = column == 18 ? stream.first : stream.last;
		if (stamp.has_timestamp) {
			vector.SetValue(row, Value::TIMESTAMP(timestamp_t(stamp.timestamp)));
		} else {
			FlatVector::SetNull(vector, row, true);
		}
		break;
	}
	case 20:
		SetDecodedScalar(vector, row, stream.expected_bytes);
		break;
	case 21:
		SetDecodedScalar(vector, row, stream.captured_bytes);
		break;
	case 22:
		SetDecodedScalar(vector, row, !stream.gaps.empty());
		break;
	case 23:
		if (!stream.gaps.empty() || stream.chunks.empty()) {
			FlatVector::SetNull(vector, row, true);
		} else {
			const auto &bytes = stream.chunks[0].data;
			vector.SetValue(row, Value::BLOB(bytes.data(), bytes.size()));
		}
		break;
	case 24: {
		duckdb::vector<Value> values;
		for (const auto &chunk : stream.chunks) {
			const auto stamps = chunk.Provenance(0, chunk.data.size());
			values.push_back(Value::STRUCT(
			    TcpChunkType(), {Value::UINTEGER(chunk.offset), Value::UINTEGER(chunk.sequence),
			                     Value::BLOB(chunk.data.data(), chunk.data.size()), Value::UBIGINT(stamps.first.number),
			                     Value::UBIGINT(stamps.second.number)}));
		}
		vector.SetValue(row, Value::LIST(TcpChunkType(), values));
		break;
	}
	case 25: {
		duckdb::vector<Value> values;
		for (const auto &gap : stream.gaps) {
			values.push_back(Value::STRUCT(TcpGapType(), {Value::UINTEGER(gap.offset), Value::UINTEGER(gap.length)}));
		}
		vector.SetValue(row, Value::LIST(TcpGapType(), values));
		break;
	}
	case 26: {
		duckdb::vector<Value> values;
		for (const auto tag : key.vlans) {
			values.push_back(Value::USMALLINT(tag));
		}
		vector.SetValue(row, Value::LIST(LogicalType::USMALLINT, values));
		break;
	}
	default:
		throw InternalException("Unexpected read_tcp_streams column id %d", column);
	}
}
static void TcpStreamsScan(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
	auto &bind = input.bind_data->Cast<PcapBindData>();
	auto &global = input.global_state->Cast<StreamGlobalState>();
	auto &state = input.local_state->Cast<StreamScanState>();
	if (!state.initialized) {
		state.initialized = true;
		if (global.file_count) {
			state.reservation = global.Admit();
		}
	}
	if (!state.reservation) {
		return;
	}
	idx_t count = 0, output_bytes = 0;
	while (count < STANDARD_VECTOR_SIZE && output_bytes < STREAM_OUTPUT_BATCH_BYTES) {
		if (context.IsInterrupted()) {
			throw InterruptException();
		}
		StreamEvent event;
		if (!NextStreamEvent(context, bind, global, state, event)) {
			break;
		}
		for (idx_t i = 0; i < global.columns.size(); ++i) {
			SetStreamValue(output.data[i], count, global.columns[i], state.filename, event.stream);
		}
		output_bytes += 1024 + state.filename.size() + event.stream.captured_bytes * 4ULL +
		                (event.stream.chunks.size() + event.stream.gaps.size()) * 1024ULL;
		++count;
	}
	output.SetCardinality(count);
	if (!count) {
		std::vector<packetquapture::TcpStream>().swap(state.streams);
		std::vector<packetquapture::TcpDnsMessage>().swap(state.pending);
		state.reassembler = packetquapture::TcpReassembler();
		state.reservation.reset();
	}
}

static TableFunction ReadPcapFunction() {
	TableFunction function("read_pcap", {LogicalType::VARCHAR}, PcapScan, PcapBind, PcapInit, PcapInitLocal);
	function.projection_pushdown = true;
	function.table_scan_progress = CaptureScanProgress;
	function.filter_pushdown = true;
	function.supports_pushdown_type = SupportsPacketFilter;
	function.pushdown_complex_filter = NormalizePacketFilters;
	return function;
}

static void LoadInternal(ExtensionLoader &loader) {
	loader.SetDescription("Query PCAP and PCAPNG packet captures directly from DuckDB");
	DBConfig::GetConfig(loader.GetDatabaseInstance())
	    .AddExtensionOption("packetquapture_stream_memory_mb",
	                        "Query-wide stream-worker admission budget in MiB, capped at half memory_limit",
	                        LogicalType::UBIGINT, Value::UBIGINT(512));
	loader.RegisterFunction(MultiFileReader::CreateFunctionSet(ReadPcapFunction()));
	TableFunction packets("read_packets", {LogicalType::VARCHAR}, PcapScan, PacketsBind, PcapInit, PcapInitLocal);
	packets.projection_pushdown = true;
	packets.table_scan_progress = CaptureScanProgress;
	packets.filter_pushdown = true;
	packets.supports_pushdown_type = SupportsPacketFilter;
	packets.pushdown_complex_filter = NormalizePacketFilters;
	loader.RegisterFunction(MultiFileReader::CreateFunctionSet(packets));
	TableFunction dns("read_dns", {LogicalType::VARCHAR}, PcapScan, DnsBind, PcapInit, PcapInitLocal);
	dns.projection_pushdown = true;
	dns.table_scan_progress = CaptureScanProgress;
	dns.filter_pushdown = true;
	dns.supports_pushdown_type = SupportsPacketFilter;
	dns.pushdown_complex_filter = NormalizePacketFilters;
	loader.RegisterFunction(MultiFileReader::CreateFunctionSet(dns));
	TableFunction messages("read_dns_messages", {LogicalType::VARCHAR}, DnsMessagesScan, DnsMessagesBind,
	                       DnsMessagesInit, StreamInitLocal);
	messages.projection_pushdown = true;
	messages.table_scan_progress = CaptureScanProgress;
	// Segment-level predicates could remove bytes required to reconstruct a matching message.
	loader.RegisterFunction(MultiFileReader::CreateFunctionSet(messages));
	TableFunction streams("read_tcp_streams", {LogicalType::VARCHAR}, TcpStreamsScan, TcpStreamsBind, TcpStreamsInit,
	                      StreamInitLocal);
	streams.projection_pushdown = true;
	streams.table_scan_progress = CaptureScanProgress;
	loader.RegisterFunction(MultiFileReader::CreateFunctionSet(streams));
}

} // namespace

void PacketquaptureExtension::Load(ExtensionLoader &loader) {
	LoadInternal(loader);
}

std::string PacketquaptureExtension::Name() {
	return "packetquapture";
}

std::string PacketquaptureExtension::Version() const {
#ifdef EXT_VERSION_PACKETQUAPTURE
	return EXT_VERSION_PACKETQUAPTURE;
#else
	return "";
#endif
}

} // namespace duckdb

extern "C" {

DUCKDB_CPP_EXTENSION_ENTRY(packetquapture, loader) {
	duckdb::LoadInternal(loader);
}
}
