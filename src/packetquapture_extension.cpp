#define DUCKDB_EXTENSION_MAIN

#include "packetquapture_extension.hpp"
#include "pcap_copy.hpp"
#include "capture_progress.hpp"
#include "stream_scan_budget.hpp"
#include "flow_scan_budget.hpp"
#include "flow_aggregator.hpp"
#include "capture_inventory.hpp"
#include "inventory_scan_budget.hpp"
#include "duckdb/catalog/catalog.hpp"
#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/catalog/catalog_entry/schema_catalog_entry.hpp"
#include "duckdb/parser/qualified_name.hpp"
#include "duckdb/planner/binder.hpp"
#include "duckdb/storage/data_table.hpp"
#include "duckdb/storage/table/scan_state.hpp"
#include "duckdb/transaction/duck_transaction.hpp"
#include "duckdb/common/types/interval.hpp"
#include "duckdb/common/crypto/md5.hpp"
#include "mbedtls_wrapper.hpp"
#include "packet_decoder.hpp"
#include "dns_decoder.hpp"
#include "tls_record.hpp"
#include "tls_handshake.hpp"
#include "tls_fingerprint.hpp"
#include "tcp_reassembly.hpp"
#include "dns_tcp_framer.hpp"
#include "duckdb/execution/expression_executor.hpp"
#include "duckdb/execution/execution_context.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/client_config.hpp"
#include "duckdb/planner/expression/bound_reference_expression.hpp"
#include "duckdb/planner/table_filter.hpp"
#include "duckdb/planner/filter/conjunction_filter.hpp"
#include "duckdb/planner/filter/constant_filter.hpp"
#include "duckdb/storage/statistics/base_statistics.hpp"
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
#include "duckdb/common/hive_partitioning.hpp"
#include "duckdb/planner/operator/logical_get.hpp"
#include "duckdb/storage/statistics/node_statistics.hpp"
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
// Local captures are traversed one record header at a time. Serving those headers from a
// window turns a read and a seek per packet into one positioned read per window.
constexpr idx_t LOCAL_READ_WINDOW_SIZE = 256ULL * 1024ULL;
// Payload gaps at or below this share pages with the headers around them, so reading
// through costs less than the syscall saved by skipping. Larger payloads are still
// skipped exactly, which keeps sparse metadata scans off the payload bytes.
constexpr idx_t LOCAL_SKIP_THRESHOLD = 4ULL * 1024ULL;
constexpr idx_t MAX_CAPTURED_PACKET_SIZE = 256ULL * 1024ULL * 1024ULL;
constexpr idx_t MAX_INTERFACE_BLOCK_SIZE = 16ULL * 1024ULL * 1024ULL;
constexpr uint32_t PCAPNG_INTERFACE_DESCRIPTION = 0x00000001;
constexpr uint32_t PCAPNG_SIMPLE_PACKET = 0x00000003;
constexpr uint32_t PCAPNG_ENHANCED_PACKET = 0x00000006;

// Raised when a capture ends partway through a record, which is what a writer
// killed mid-write leaves behind. Deliberately not a std::exception: it unwinds
// to CaptureReader::Next, which turns it into a clean end-of-capture, and must
// never be swallowed by the generic error decorator there.
struct TruncatedTailSignal {};

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
	packetquapture::TlsRecord tls;
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

// A column's stage names the work a scan must finish before the column can be
// produced. Stages 1-3 mirror DecodeDepth and are cast to it; the others name
// work that sits outside the decode ladder. Each bind records the stage of every
// column it appends, so adding columns never shifts the meaning of existing ones.
enum ColumnStage : uint8_t {
	STAGE_PACKET = 0,
	STAGE_LINK = 1,
	STAGE_NETWORK = 2,
	STAGE_TRANSPORT = 3,
	STAGE_DNS = 4,
	STAGE_TLS = 5,
	STAGE_PACKET_DATA = 6,
	STAGE_COUNT = 7,
};

static_assert(static_cast<unsigned>(packetquapture::DecodeDepth::LINK) == STAGE_LINK &&
                  static_cast<unsigned>(packetquapture::DecodeDepth::NETWORK) == STAGE_NETWORK &&
                  static_cast<unsigned>(packetquapture::DecodeDepth::TRANSPORT) == STAGE_TRANSPORT,
              "stages 1-3 are cast to DecodeDepth");

// read_packets appends the TLS columns after the decoded packet columns, and
// read_dns appends its own after those. Value dispatch is index-based, so the
// boundaries live here rather than as literals at each site.
static const column_t PACKET_COLUMN_COUNT = 11;
static const column_t TLS_COLUMN_BEGIN = 40;
static const column_t TLS_COLUMN_COUNT = 6;
static const column_t DNS_COLUMN_BEGIN = TLS_COLUMN_BEGIN + TLS_COLUMN_COUNT;
static const column_t DNS_COLUMN_COUNT = 14;
// read_dns_messages keeps the same dns_* columns but puts them after its own
// per-message columns, so it remaps into the block above.
static const column_t MESSAGE_DNS_COLUMN_BEGIN = 20;
static const column_t MESSAGE_DNS_COLUMN_END = MESSAGE_DNS_COLUMN_BEGIN + DNS_COLUMN_COUNT;

struct ScanOptions {
	bool materialize_packet_data = false;
	bool flow_scan = false;
	bool inventory_scan = false;
	bool dns_scan = false, decode_dns = false;
	bool decode_tls = false;
	bool reassemble_dns = false, reassemble_tcp = false;
	packetquapture::DecodeDepth decode_depth = packetquapture::DecodeDepth::NONE;
	std::array<bool, STAGE_COUNT> filter_stages {};
	std::function<bool(const PacketRecord &, unsigned)> matches;
};

class PacketFilter {
public:
	PacketFilter(ClientContext &context, column_t column_p, unsigned stage_p, const LogicalType &type,
	             const TableFilter &filter)
	    : column(column_p), stage(stage_p) {
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
		if (FileSystem::IsRemoteFile(file.path) && !options.inventory_scan) {
			caching_fs = make_uniq<CachingFileSystem>(fs, *context.db);
			// The window already supplies read-ahead; avoid a second HTTP read buffer.
			cached_handle =
			    caching_fs->OpenFile(context, file, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
		} else {
			handle = fs.OpenFile(file, options.inventory_scan && FileSystem::IsRemoteFile(file.path)
			                               ? FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO
			                               : FileFlags::FILE_FLAGS_READ);
		}
		auto &raw_handle = RawHandle();
		if (raw_handle.CanSeek() && !raw_handle.IsPipe()) {
			const auto size = fs.GetFileSize(raw_handle);
			if (size >= 0) {
				seekable_size = static_cast<uint64_t>(size);
				can_skip_by_seek = true;
			}
		}
		buffer_locally = can_skip_by_seek && !cached_handle && !FileSystem::IsRemoteFile(file.path);
		if (progress) {
			progress->CheckSize(file_index, can_skip_by_seek, seekable_size);
		}
		if (options.inventory_scan) {
			inventory_before = ReadCaptureIdentity(fs, raw_handle);
		}
		Initialize();
	}

	bool Next(PacketRecord &record) {
		try {
			const bool found = format == CaptureFormat::PCAP ? NextPcap(record) : NextPcapNg(record);
			if (found) {
				++complete_records;
			}
			if (!found && progress && progress->Enabled()) {
				PublishProgress(true);
				progress->CompleteFile();
			}
			return found;
		} catch (const TruncatedTailSignal &) {
			// Stop at the last complete packet. Reported through
			// SawTruncatedTail so capture_inventory can surface it rather than
			// the caller silently receiving a short scan.
			if (progress && progress->Enabled()) {
				PublishProgress(true);
				progress->CompleteFile();
			}
			return false;
		} catch (const std::exception &exception) {
			ErrorData error(exception);
			if (error.Type() == ExceptionType::INTERRUPT) {
				throw;
			}
			error.Throw(StringUtil::Format("Capture '%s', packet cursor %llu, byte cursor %llu: ", file.path,
			                               packet_number, position));
		}
	}

	const CaptureIdentity &InventoryBefore() const {
		return inventory_before;
	}
	CaptureIdentity InventoryAfter() {
		return ReadCaptureIdentity(fs, RawHandle());
	}
	const std::set<uint32_t> &InventoryLinks() const {
		return inventory_links;
	}
	string InventoryFormat() const {
		return format == CaptureFormat::PCAP ? "pcap" : "pcapng";
	}
	// True when the capture ended partway through a record.
	bool SawTruncatedTail() const {
		return truncated_tail;
	}
	uint32_t SectionNumber() const {
		return format == CaptureFormat::PCAP ? 1 : section_number;
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

	// Positioned reads keep the window independent of the handle cursor, so a skipped
	// payload costs no syscall at all: only `position` moves.
	idx_t ReadLocalWindow(void *buffer, idx_t length, uint64_t offset) {
		if (offset >= seekable_size) {
			return 0;
		}
		if (!window_worthwhile) {
			// Sparse traversal, and every scan until a small gap proves otherwise. Reading
			// through the handle cursor keeps the kernel's sequential readahead engaged:
			// positioned reads at a header-sized stride measured materially slower, and
			// filling a window here would read payload bytes this scan never wants.
			return NumericCast<idx_t>(RawHandle().Read(buffer, length));
		}
		const bool cached = local_length > 0 && offset >= local_start && offset - local_start < local_length;
		if (!cached) {
			if (length >= LOCAL_READ_WINDOW_SIZE) {
				const auto direct = MinValue<idx_t>(length, seekable_size - offset);
				fs.Read(*handle, buffer, NumericCast<int64_t>(direct), offset);
				return direct;
			}
			if (!local_window) {
				local_window = make_unsafe_uniq_array<data_t>(LOCAL_READ_WINDOW_SIZE);
			}
			local_start = offset;
			local_length = MinValue<idx_t>(LOCAL_READ_WINDOW_SIZE, seekable_size - offset);
			fs.Read(*handle, local_window.get(), NumericCast<int64_t>(local_length), local_start);
		}
		const auto within_window = offset - local_start;
		const auto count = MinValue<idx_t>(length, local_length - within_window);
		memcpy(buffer, local_window.get() + within_window, count);
		return count;
	}

	void Initialize() {
		std::array<uint8_t, 4> magic {};
		if (!ReadMaybe(magic.data(), magic.size())) {
			// ReadMaybe no longer throws on a short read, so separate a file
			// that stops inside its magic number from one with no bytes at all.
			if (truncated_tail) {
				throw IOException("Capture file '%s' ends inside its magic number", file.path);
			}
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
		header_complete = true;
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
		if (options.inventory_scan) {
			inventory_links.insert(pcap_link_type);
		}
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
			if (truncated_tail) {
				EndOfRecord("packet header");
			}
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
				if (truncated_tail) {
					EndOfRecord("PCAPNG block header");
				}
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
		if ((options.reassemble_tcp || options.reassemble_dns || options.flow_scan || options.inventory_scan) &&
		    interfaces.size() >= 65536) {
			throw InvalidInputException("Stream scan exceeds 65536 PCAPNG interfaces per section in '%s'", file.path);
		}
		interfaces.push_back(interface);
		if (options.inventory_scan) {
			inventory_links.insert(interface.link_type);
		}
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
			if (!accept(STAGE_DNS)) {
				Skip(length - source.Consumed(), "packet data");
				return;
			}
		}
		if (options.decode_tls) {
			const auto &packet = record.decoded;
			// TLS runs over TCP; DTLS frames differently and is not parsed here.
			if (packet.transport && packet.tcp && packet.payload_length > 0) {
				const auto *bytes = source.ReadPrefix(packet.payload_offset + packet.payload_length);
				record.tls = packetquapture::DecodeTlsRecord(bytes + packet.payload_offset, packet.payload_length);
			}
			if (!accept(STAGE_TLS)) {
				Skip(length - source.Consumed(), "packet data");
				return;
			}
		}
		if (options.materialize_packet_data) {
			source.ReadPrefix(length);
			record.packet_data = source.TakeBytes();
			accept(STAGE_PACKET_DATA);
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
			idx_t bytes_read;
			if (cached_handle && can_skip_by_seek) {
				bytes_read = ReadRemoteWindow(destination, length - total, position + total);
			} else if (buffer_locally) {
				bytes_read = ReadLocalWindow(destination, length - total, position + total);
			} else {
				bytes_read = NumericCast<idx_t>(RawHandle().Read(destination, length - total));
			}
			if (bytes_read == 0) {
				if (total > 0) {
					// Ended mid-read. Fatal inside a file or section header,
					// tolerated once record iteration has begun.
					truncated_tail = true;
				}
				return false;
			}
			total += NumericCast<idx_t>(bytes_read);
		}
		position += length;
		PublishProgress();
		return true;
	}

	void ReadExact(void *buffer, idx_t length, const char *description) {
		if (length > 0 && !ReadMaybe(buffer, length)) {
			EndOfRecord(description);
		}
	}

	// A capture that stops inside a record was cut short mid-write, which is
	// ordinary for real captures -- but only once the file has proven itself by
	// yielding a complete record. Before that, a short read is indistinguishable
	// from a misidentified or corrupt file, and a silently empty result would
	// hide that, so it stays a hard error.
	[[noreturn]] void EndOfRecord(const char *description) {
		if (header_complete && complete_records > 0) {
			truncated_tail = true;
			throw TruncatedTailSignal {};
		}
		throw IOException("Unexpected end of '%s' while reading %s", file.path, description);
	}

	void Skip(idx_t length, const char *description) {
		if (length == 0) {
			return;
		}
		if (can_skip_by_seek) {
			if (position > seekable_size || length > seekable_size - position) {
				EndOfRecord(description);
			}
			if (buffer_locally) {
				// A gap this small shares pages with the headers around it, so upcoming
				// records are worth windowing. A wider gap returns the scan to cursor
				// reads, which keeps sparse metadata traversals off the payload bytes.
				window_worthwhile = length <= LOCAL_SKIP_THRESHOLD;
				if (!window_worthwhile) {
					// Window refills are positioned and leave the cursor behind; restore
					// it before the next cursor read.
					handle->Seek(position + length);
				}
			} else if (!cached_handle) {
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
	CaptureIdentity inventory_before;
	std::set<uint32_t> inventory_links;
	OpenFileInfo file;
	ClientContext &context;
	FileSystem &fs;
	unique_ptr<FileHandle> handle;
	unique_ptr<CachingFileSystem> caching_fs;
	unique_ptr<CachingFileHandle> cached_handle;
	BufferHandle window;
	data_ptr_t window_data = nullptr;
	idx_t window_start = 0, window_length = 0;
	unsafe_unique_array<data_t> local_window;
	idx_t local_start = 0, local_length = 0;
	bool buffer_locally = false;
	bool window_worthwhile = false;
	const ScanOptions &options;
	CaptureProgress *progress;
	uint64_t published_position = 0;
	bool can_skip_by_seek = false;
	// Set once the file/section header is parsed; gates tail tolerance.
	bool header_complete = false;
	bool truncated_tail = false;
	// Records returned in full; gates tail tolerance alongside header_complete.
	uint64_t complete_records = 0;
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

static string BindInventoryCatalog(ClientContext &context, const string &name);

struct PcapBindData : public TableFunctionData {
	// Original occurrences stay immutable: stream IDs use their indexes and count.
	vector<OpenFileInfo> files;
	vector<idx_t> selected_indices;
	vector<LogicalType> types;
	// One entry per base column, in column order. Appended to by each bind.
	vector<uint8_t> column_stages;
	idx_t base_column_count = 0;
	bool hive_partitioning = false;
	vector<string> partition_keys;
	vector<vector<Value>> partition_values;

	void AppendStages(ColumnStage stage, idx_t count) {
		column_stages.insert(column_stages.end(), count, static_cast<uint8_t>(stage));
	}

	// Partition and virtual columns sit past the base columns and decode nothing.
	unsigned StageOf(column_t column) const {
		return column < column_stages.size() ? column_stages[column] : STAGE_PACKET;
	}

	vector<OpenFileInfo> SelectedFiles() const {
		vector<OpenFileInfo> result;
		result.reserve(selected_indices.size());
		for (auto index : selected_indices) {
			result.push_back(files[index]);
		}
		return result;
	}

	bool SetPartition(Vector &output, idx_t row, column_t column, idx_t file_index) const {
		if (column < base_column_count || column >= types.size()) {
			return false;
		}
		output.SetValue(row, partition_values[file_index][column - base_column_count]);
		return true;
	}
	string catalog;
	bool catalog_immutable = false;
	bool dns_scan = false;
	shared_ptr<StreamPlanCount> stream_plan;
	shared_ptr<FlowPlanCount> flow_plan;
	packetquapture::FlowLimits flow_limits;
	bool flow_scan = false;

	unique_ptr<FunctionData> Copy() const override {
		auto result = make_uniq<PcapBindData>();
		result->files = files;
		result->types = types;
		result->column_stages = column_stages;
		result->selected_indices = selected_indices;
		result->base_column_count = base_column_count;
		result->hive_partitioning = hive_partitioning;
		result->partition_keys = partition_keys;
		result->partition_values = partition_values;
		result->catalog = catalog;
		result->catalog_immutable = catalog_immutable;
		result->dns_scan = dns_scan;
		result->stream_plan = stream_plan;
		result->flow_plan = flow_plan;
		result->flow_limits = flow_limits;
		result->flow_scan = flow_scan;
		if (flow_plan) {
			flow_plan->scans.fetch_add(1);
		}
		if (stream_plan) {
			stream_plan->scans.fetch_add(1);
		}
		return std::move(result);
	}

	bool Equals(const FunctionData &other_p) const override {
		auto &other = other_p.Cast<PcapBindData>();
		if (catalog != other.catalog || catalog_immutable != other.catalog_immutable || flow_scan != other.flow_scan ||
		    flow_limits.tcp_idle_us != other.flow_limits.tcp_idle_us ||
		    flow_limits.udp_idle_us != other.flow_limits.udp_idle_us ||
		    flow_limits.max_flows != other.flow_limits.max_flows || files.size() != other.files.size() ||
		    types != other.types || column_stages != other.column_stages || dns_scan != other.dns_scan ||
		    selected_indices != other.selected_indices || base_column_count != other.base_column_count ||
		    hive_partitioning != other.hive_partitioning || partition_keys != other.partition_keys ||
		    partition_values.size() != other.partition_values.size()) {
			return false;
		}
		for (idx_t i = 0; i < files.size(); i++) {
			if (files[i].path != other.files[i].path) {
				return false;
			}
		}
		for (idx_t file = 0; file < partition_values.size(); ++file) {
			for (idx_t key = 0; key < partition_keys.size(); ++key) {
				if (!Value::NotDistinctFrom(partition_values[file][key], other.partition_values[file][key])) {
					return false;
				}
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

static vector<idx_t> SelectCatalogFiles(ClientContext &context, const PcapBindData &bind, TableFunctionInitInput &input,
                                        map<string, idx_t> &reasons);

struct PcapGlobalState : public CaptureGlobalState {
	explicit PcapGlobalState(vector<idx_t> selected)
	    : selected_indices(std::move(selected)), scheduler(selected_indices.size()) {
	}

	idx_t MaxThreads() const override {
		return scheduler.MaxThreads();
	}

	vector<idx_t> selected_indices;
	map<string, idx_t> catalog_reasons;
	FileScheduler scheduler;
	vector<column_t> column_ids;
	ScanOptions options;
	vector<PacketFilterDefinition> filters;
};

struct PcapLocalState : public LocalTableFunctionState {
	idx_t file_index = 0;
	ScanOptions options;
	vector<unique_ptr<PacketFilter>> filters;
	unique_ptr<CaptureReader> reader;
};

static idx_t NamedColumn(const vector<string> &names, const char *name) {
	for (idx_t i = 0; i < names.size(); ++i) {
		if (names[i] == name) {
			return i;
		}
	}
	throw InternalException("capture bind has no column named %s", name);
}

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
	result->AppendStages(STAGE_PACKET, return_types.size());
	result->column_stages[NamedColumn(names, "packet_data")] = STAGE_PACKET_DATA;
	return std::move(result);
}

static unique_ptr<FunctionData> PacketsBind(ClientContext &context, TableFunctionBindInput &input,
                                            vector<LogicalType> &return_types, vector<string> &names) {
	auto result = PcapBind(context, input, return_types, names);
	// Grouped by the decode stage that produces them, so a column added to a group
	// takes that group's stage and no other column's stage moves.
	const vector<std::pair<ColumnStage, vector<std::pair<string, LogicalType>>>> decoded = {
	    {STAGE_LINK,
	     {{"src_mac", LogicalType::VARCHAR},
	      {"dst_mac", LogicalType::VARCHAR},
	      {"ether_type", LogicalType::USMALLINT},
	      {"vlan_ids", LogicalType::LIST(LogicalType::USMALLINT)}}},
	    {STAGE_NETWORK,
	     {{"ip_version", LogicalType::UTINYINT},
	      {"src_ip", LogicalType::VARCHAR},
	      {"dst_ip", LogicalType::VARCHAR},
	      {"ip_protocol", LogicalType::UTINYINT},
	      {"ip_ttl", LogicalType::UTINYINT},
	      {"ip_fragment_offset", LogicalType::UINTEGER},
	      {"ip_more_fragments", LogicalType::BOOLEAN},
	      {"ip_id", LogicalType::UINTEGER}}},
	    {STAGE_TRANSPORT,
	     {{"src_port", LogicalType::USMALLINT},
	      {"dst_port", LogicalType::USMALLINT},
	      {"tcp_flags", LogicalType::USMALLINT},
	      {"tcp_seq", LogicalType::UINTEGER},
	      {"tcp_ack", LogicalType::UINTEGER},
	      {"tcp_header_length", LogicalType::UTINYINT},
	      {"udp_length", LogicalType::USMALLINT},
	      {"payload_offset", LogicalType::UINTEGER},
	      {"payload_length", LogicalType::UINTEGER},
	      {"tcp_fin", LogicalType::BOOLEAN},
	      {"tcp_syn", LogicalType::BOOLEAN},
	      {"tcp_rst", LogicalType::BOOLEAN},
	      {"tcp_psh", LogicalType::BOOLEAN},
	      {"tcp_ack_flag", LogicalType::BOOLEAN},
	      {"tcp_urg", LogicalType::BOOLEAN},
	      {"tcp_ece", LogicalType::BOOLEAN},
	      {"tcp_cwr", LogicalType::BOOLEAN}}},
	};
	// Parsed from the TCP payload of each packet on its own, with no reassembly:
	// a field needing bytes from another segment is reported absent, and
	// tls_truncated says whether it was absent or merely out of reach.
	const vector<std::pair<string, LogicalType>> tls = {{"is_tls", LogicalType::BOOLEAN},
	                                                    {"tls_record_type", LogicalType::UTINYINT},
	                                                    {"tls_record_version", LogicalType::USMALLINT},
	                                                    {"tls_handshake_type", LogicalType::UTINYINT},
	                                                    {"tls_sni", LogicalType::VARCHAR},
	                                                    {"tls_truncated", LogicalType::BOOLEAN}};
	auto &bind = result->Cast<PcapBindData>();
	for (const auto &group : decoded) {
		for (const auto &column : group.second) {
			names.push_back(column.first);
			return_types.push_back(column.second);
		}
		bind.AppendStages(group.first, group.second.size());
	}
	if (return_types.size() != TLS_COLUMN_BEGIN || tls.size() != TLS_COLUMN_COUNT) {
		throw InternalException("read_packets column layout does not match the declared TLS boundaries");
	}
	for (const auto &column : tls) {
		names.push_back(column.first);
		return_types.push_back(column.second);
	}
	bind.AppendStages(STAGE_TLS, tls.size());
	bind.types = return_types;
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
	auto &bind = result->Cast<PcapBindData>();
	bind.AppendStages(STAGE_DNS, dns_types.size());
	bind.types = return_types;
	bind.dns_scan = true;
	return result;
}

template <table_function_bind_t BIND>
static unique_ptr<FunctionData> BindCapture(ClientContext &context, TableFunctionBindInput &input,
                                            vector<LogicalType> &types, vector<string> &names) {
	auto result = BIND(context, input, types, names);
	auto &bind = result->Cast<PcapBindData>();
	bind.base_column_count = types.size();
	for (idx_t i = 0; i < bind.files.size(); ++i) {
		bind.selected_indices.push_back(i);
	}
	MultiFileOptions options;
	options.auto_detect_hive_partitioning = false;
	options.hive_types_autocast = false;
	auto reader = MultiFileReader::Create(input.table_function);
	bool has_type_options = false;
	for (auto &entry : input.named_parameters) {
		if (StringUtil::CIEquals(entry.first, "catalog")) {
			if (entry.second.IsNull())
				throw BinderException("catalog must not be NULL");
			bind.catalog = BindInventoryCatalog(context, entry.second.GetValue<string>());
			continue;
		}
		if (StringUtil::CIEquals(entry.first, "catalog_validation")) {
			if (entry.second.IsNull())
				throw BinderException("catalog_validation must not be NULL");
			auto mode = StringUtil::Lower(entry.second.GetValue<string>());
			if (mode != "strict" && mode != "immutable")
				throw BinderException("catalog_validation must be strict or immutable");
			bind.catalog_immutable = mode == "immutable";
			continue;
		}
		if (bind.flow_scan && (StringUtil::CIEquals(entry.first, "tcp_idle_timeout") ||
		                       StringUtil::CIEquals(entry.first, "udp_idle_timeout") ||
		                       StringUtil::CIEquals(entry.first, "max_active_flows"))) {
			continue;
		}
		if (!reader->ParseOption(entry.first, entry.second, options, context)) {
			throw BinderException("Unsupported capture option: %s", entry.first);
		}
		has_type_options |= !StringUtil::CIEquals(entry.first, "hive_partitioning");
	}
	if (bind.catalog.empty() && input.named_parameters.count("catalog_validation"))
		throw BinderException("catalog_validation requires catalog");
	if (has_type_options && !options.hive_partitioning) {
		throw BinderException("Capture partition type options require hive_partitioning=true");
	}
	bind.hive_partitioning = options.hive_partitioning;
	if (!options.hive_partitioning || bind.files.empty()) {
		return result;
	}

	const auto partitions = HivePartitioning::Parse(bind.files[0].path);
	case_insensitive_set_t used_names;
	for (auto &name : names) {
		used_names.insert(name);
	}
	for (auto &entry : partitions) {
		if (!used_names.insert(entry.first).second) {
			throw BinderException("Capture partition column '%s' collides with an existing column", entry.first);
		}
		bind.partition_keys.push_back(entry.first);
	}
	for (auto &entry : options.hive_types_schema) {
		bool found = false;
		for (auto &key : bind.partition_keys) {
			found |= StringUtil::CIEquals(entry.first, key);
		}
		if (!found) {
			throw BinderException("Unknown capture partition in hive_types: %s", entry.first);
		}
	}
	// Validate all path metadata, including files that may later be pruned. No opens.
	for (auto &file : bind.files) {
		if (context.IsInterrupted()) {
			throw InterruptException();
		}
		const auto values = HivePartitioning::Parse(file.path);
		if (values.size() != partitions.size()) {
			throw BinderException("Hive partition mismatch between capture files '%s' and '%s'", bind.files[0].path,
			                      file.path);
		}
		for (auto &key : bind.partition_keys) {
			if (values.find(key) == values.end()) {
				throw BinderException("Hive partition mismatch in capture '%s': key '%s' not found", file.path, key);
			}
		}
	}
	if (options.hive_types_autocast) {
		SimpleMultiFileList files(bind.files);
		options.AutoDetectHiveTypesInternal(files, context);
	}
	for (auto &key : bind.partition_keys) {
		names.push_back(key);
		types.push_back(options.GetHiveLogicalType(key));
	}
	for (auto &file : bind.files) {
		if (context.IsInterrupted()) {
			throw InterruptException();
		}
		const auto values = HivePartitioning::Parse(file.path);
		vector<Value> typed_values;
		for (auto &key : bind.partition_keys) {
			typed_values.push_back(options.GetHivePartitionValue(values.at(key), key, context));
		}
		bind.partition_values.push_back(std::move(typed_values));
	}
	bind.types = types;
	return result;
}

static bool SupportsPacketFilter(const FunctionData &data, idx_t column) {
	const auto &bind = data.Cast<PcapBindData>();
	return column < bind.base_column_count && bind.types[column].id() != LogicalTypeId::LIST;
}

static unique_ptr<GlobalTableFunctionState> PcapInit(ClientContext &context, TableFunctionInitInput &input) {
	auto &bind = input.bind_data->Cast<PcapBindData>();
	map<string, idx_t> reasons;
	auto result = make_uniq<PcapGlobalState>(SelectCatalogFiles(context, bind, input, reasons));
	result->catalog_reasons = std::move(reasons);
	vector<OpenFileInfo> selected_files;
	for (auto index : result->selected_indices)
		selected_files.push_back(bind.files[index]);
	result->progress.Initialize(context, selected_files);
	// DuckDB can keep filter-only columns out of the scan output. Unsupported
	// partition/list filters are restored above the scan with their own projection.
	if (input.projection_ids.empty()) {
		result->column_ids = input.column_ids;
	} else {
		for (auto index : input.projection_ids) {
			result->column_ids.push_back(input.column_ids[index]);
		}
	}
	auto &options = result->options;
	// Every base column of a decoding scan must carry a stage. Without this a bind
	// that appends columns and forgets their stages would silently under-decode them.
	if (bind.column_stages.size() != bind.base_column_count) {
		throw InternalException("capture scan has %llu columns but %llu column stages",
		                        static_cast<uint64_t>(bind.base_column_count),
		                        static_cast<uint64_t>(bind.column_stages.size()));
	}
	options.dns_scan = bind.dns_scan;
	if (bind.dns_scan) {
		options.decode_depth = packetquapture::DecodeDepth::TRANSPORT;
	}
	// Filter-only packet columns still determine the required decode depth.
	for (const auto column : input.column_ids) {
		if (column >= bind.base_column_count) {
			continue;
		}
		const auto stage = bind.StageOf(column);
		if (stage == STAGE_PACKET_DATA) {
			options.materialize_packet_data = true;
			continue;
		}
		if (stage == STAGE_DNS) {
			options.decode_dns = true;
		}
		if (stage == STAGE_TLS) {
			options.decode_tls = true;
		}
		if (stage == STAGE_PACKET) {
			continue;
		}
		// Stages past the decode ladder still need the transport payload located.
		const auto depth = static_cast<packetquapture::DecodeDepth>(MinValue<unsigned>(STAGE_TRANSPORT, stage));
		if (depth > options.decode_depth) {
			options.decode_depth = depth;
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
			// Join filters can arrive after physical planning (including conjunctions
			// of advisory filters). Never interpret partition/list columns as packet fields.
			// Their static predicates remain above the scan; joins enforce dynamic ones.
			if (!SupportsPacketFilter(bind, column)) {
				continue;
			}
			result->filters.push_back({column, filter.Copy()});
			options.filter_stages[bind.StageOf(column)] = true;
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
		                                                  bind.StageOf(definition.column),
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

// A packet that carries no TLS record still produces a row: is_tls is false and
// every other column is NULL, unlike read_dns which drops non-matching packets.
static void SetTlsValue(Vector &vector, idx_t row, column_t slot, const packetquapture::TlsRecord &tls) {
	switch (slot) {
	case 0:
		SetDecodedScalar(vector, row, tls.valid);
		return;
	case 1:
		if (tls.valid) {
			SetDecodedScalar(vector, row, tls.record_type);
			return;
		}
		break;
	case 2:
		if (tls.valid) {
			SetDecodedScalar(vector, row, tls.record_version);
			return;
		}
		break;
	case 3:
		if (tls.has_handshake_type) {
			SetDecodedScalar(vector, row, tls.handshake_type);
			return;
		}
		break;
	case 4:
		if (tls.has_server_name) {
			vector.SetValue(row, tls.server_name);
			return;
		}
		break;
	case 5:
		// Only meaningful for a ClientHello: elsewhere there is nothing whose
		// absence could be explained by the record continuing.
		if (tls.client_hello) {
			SetDecodedScalar(vector, row, tls.truncated);
			return;
		}
		break;
	default:
		throw InternalException("Unexpected TLS column slot %d", slot);
	}
	FlatVector::SetNull(vector, row, true);
}

static void SetRecordValue(Vector &vector, idx_t row, column_t column, const PacketRecord &record) {
	if (column < PACKET_COLUMN_COUNT) {
		SetOutputValue(vector, row, column, record);
		return;
	}
	if (column < TLS_COLUMN_BEGIN) {
		SetDecodedValue(vector, row, column, record.decoded);
		return;
	}
	if (column < DNS_COLUMN_BEGIN) {
		SetTlsValue(vector, row, column - TLS_COLUMN_BEGIN, record.tls);
		return;
	}
	const auto dns_column = column - DNS_COLUMN_BEGIN;
	const auto &dns = record.dns;
	if (dns_column == 0) {
		SetDecodedScalar(vector, row, dns.valid);
		return;
	}
	if (dns_column == 13) {
		if (dns.error.empty()) {
			FlatVector::SetNull(vector, row, true);
		} else {
			vector.SetValue(row, dns.error);
		}
		return;
	}
	if (!dns.valid || (dns_column >= 6 && dns_column <= 8 && dns.questions.empty())) {
		FlatVector::SetNull(vector, row, true);
		return;
	}
	switch (dns_column) {
	case 1:
		SetDecodedScalar(vector, row, dns.id);
		break;
	case 2:
		SetDecodedScalar(vector, row, dns.response);
		break;
	case 3:
		SetDecodedScalar(vector, row, dns.opcode);
		break;
	case 4:
		SetDecodedScalar(vector, row, dns.rcode);
		break;
	case 5:
		SetDecodedScalar(vector, row, dns.truncated);
		break;
	case 6:
		vector.SetValue(row, dns.questions[0].name);
		break;
	case 7:
		SetDecodedScalar(vector, row, dns.questions[0].type);
		break;
	case 8:
		SetDecodedScalar(vector, row, dns.questions[0].klass);
		break;
	case 9: {
		duckdb::vector<Value> questions;
		for (const auto &question : dns.questions) {
			questions.push_back(Value::STRUCT(DnsQuestionType(), {Value(question.name), Value::USMALLINT(question.type),
			                                                      Value::USMALLINT(question.klass)}));
		}
		vector.SetValue(row, Value::LIST(DnsQuestionType(), questions));
		break;
	}
	case 10:
		vector.SetValue(row, DnsRecordsValue(dns.answers));
		break;
	case 11:
		vector.SetValue(row, DnsRecordsValue(dns.authorities));
		break;
	case 12:
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

static void PruneCaptureFiles(ClientContext &context, LogicalGet &get, FunctionData *data,
                              vector<unique_ptr<Expression>> &filters) {
	auto &bind = data->Cast<PcapBindData>();
	HivePartitioningFilterInfo filter_info;
	filter_info.filename_enabled = true;
	filter_info.hive_enabled = bind.hive_partitioning;
	MultiFilePushdownInfo info(get);
	for (idx_t i = 0; i < info.column_ids.size(); ++i) {
		const auto column = info.column_ids[i];
		if (column == 0 || (column >= bind.base_column_count && column < bind.types.size())) {
			filter_info.column_map.emplace(get.names[column], i);
		}
	}
	vector<idx_t> selected;
	// Batches bound cancellation latency in DuckDB's scalar file-filter evaluator.
	for (idx_t start = 0; start < bind.selected_indices.size(); start += 512) {
		if (context.IsInterrupted()) {
			throw InterruptException();
		}
		const auto end = MinValue<idx_t>(start + 512, bind.selected_indices.size());
		vector<OpenFileInfo> files;
		for (idx_t i = start; i < end; ++i) {
			files.push_back(bind.files[bind.selected_indices[i]]);
		}
		vector<unique_ptr<Expression>> copies;
		for (auto &filter : filters) {
			copies.push_back(filter->Copy());
		}
		ExtraOperatorInfo extra;
		MultiFilePushdownInfo batch_info(get.table_index, get.names, info.column_ids, extra);
		HivePartitioning::ApplyFiltersToFileList(context, files, copies, filter_info, batch_info);
		if (!extra.file_filters.empty() && get.extra_info.file_filters.find(extra.file_filters) == string::npos) {
			if (!get.extra_info.file_filters.empty()) {
				get.extra_info.file_filters += "; ";
			}
			get.extra_info.file_filters += extra.file_filters;
		}
		idx_t cursor = start;
		for (auto &file : files) {
			while (cursor < end && bind.files[bind.selected_indices[cursor]].path != file.path) {
				++cursor;
			}
			if (cursor == end) {
				throw InternalException("Capture pruning did not preserve input occurrence order");
			}
			selected.push_back(bind.selected_indices[cursor++]);
		}
	}
	bind.selected_indices = std::move(selected);
	get.extra_info.total_files = bind.files.size();
	get.extra_info.filtered_files = bind.selected_indices.size();
	// Keep residual SQL predicates; the helper evaluated copies, not the original filters.
}

static void NormalizePacketFilters(ClientContext &context, LogicalGet &get, FunctionData *data,
                                   vector<unique_ptr<Expression>> &filters) {
	for (auto &filter : filters) {
		NormalizeBooleanFilter(filter);
	}
	PruneCaptureFiles(context, get, data, filters);
}

static InsertionOrderPreservingMap<string> CaptureToString(TableFunctionToStringInput &input) {
	const auto &bind = input.bind_data->Cast<PcapBindData>();
	InsertionOrderPreservingMap<string> result;
	if (!bind.catalog.empty()) {
		result["Catalog Selection"] = "pending execution; timestamp statistics only";
		result["Catalog Validation"] = bind.catalog_immutable ? "immutable" : "strict (scan fallback)";
	}
	result["Scanning Files"] = StringUtil::Format("%llu/%llu", bind.selected_indices.size(), bind.files.size());
	return result;
}

static unique_ptr<NodeStatistics> CaptureCardinality(ClientContext &, const FunctionData *data) {
	if (data->Cast<PcapBindData>().selected_indices.empty()) {
		return make_uniq<NodeStatistics>(0, 0);
	}
	return nullptr;
}

static void AddCaptureOptions(TableFunction &function) {
	function.named_parameters["hive_partitioning"] = LogicalType::BOOLEAN;
	function.named_parameters["hive_types"] = LogicalType::ANY;
	function.named_parameters["hive_types_autocast"] = LogicalType::BOOLEAN;
	function.to_string = CaptureToString;
	function.cardinality = CaptureCardinality;
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
			state.file_index = global.selected_indices[file_index];
			state.reader = make_uniq<CaptureReader>(context, bind_data.files[state.file_index], state.options,
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
			if (!bind_data.SetPartition(output.data[output_column], output_count, global.column_ids[output_column],
			                            state.file_index)) {
				SetRecordValue(output.data[output_column], output_count, global.column_ids[output_column], record);
			}
		}
		output_count++;
	}
	output.SetCardinality(output_count);
}

struct StreamGlobalState : public CaptureGlobalState {
	StreamGlobalState(ClientContext &context, const PcapBindData &bind)
	    : scheduler(bind.selected_indices.size()), file_count(bind.selected_indices.size()) {
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

// SHA-1 and SHA-256 of a certificate's DER, for the parser, which has no hash
// of its own.
static void TlsCertificateDigest(const uint8_t *der, size_t size, packetquapture::X509Certificate &out) {
	const std::string bytes(reinterpret_cast<const char *>(der), size);
	duckdb_mbedtls::MbedTlsWrapper::SHA1State sha1;
	sha1.AddString(bytes);
	char sha1_hex[duckdb_mbedtls::MbedTlsWrapper::SHA1_HASH_LENGTH_TEXT];
	sha1.FinishHex(sha1_hex);
	out.sha1.assign(sha1_hex, sizeof(sha1_hex));
	duckdb_mbedtls::MbedTlsWrapper::SHA256State sha256;
	sha256.AddString(bytes);
	char sha256_hex[duckdb_mbedtls::MbedTlsWrapper::SHA256_HASH_LENGTH_TEXT];
	sha256.FinishHex(sha256_hex);
	out.sha256.assign(sha256_hex, sizeof(sha256_hex));
}

static packetquapture::TlsHandshakeAssembler NewTlsAssembler() {
	packetquapture::TlsHandshakeLimits limits;
	limits.certificate_digest = TlsCertificateDigest;
	return packetquapture::TlsHandshakeAssembler(limits);
}

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

	// read_tls pairs the two directions of a connection, which the transport core
	// finishes independently, so rows can outlive the stream that produced them.
	// The file they belong to is held with them.
	packetquapture::TlsHandshakeAssembler tls_assembler = NewTlsAssembler();
	std::vector<packetquapture::TlsHandshake> tls_pending;
	idx_t tls_pending_index = 0;
	string tls_pending_filename, tls_open_filename;
	idx_t tls_pending_file_index = 0, tls_open_file_index = 0;
	bool tls_drained = false;
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
			idx_t work_index;
			if (!global.scheduler.Claim(work_index)) {
				return false;
			}
			state.file_index = bind.selected_indices[work_index];
			const auto &file = bind.files[state.file_index];
			state.filename = file.path;
			state.reassembler = packetquapture::TcpReassembler();
			state.reader = make_uniq<CaptureReader>(context, file, global.options, &global.progress, work_index);
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
	// Keep the dns_* columns and drop the per-packet ones: this reader reports one
	// row per reassembled message, not per packet.
	vector<LogicalType> dns_types(types.begin() + DNS_COLUMN_BEGIN, types.end());
	vector<string> dns_names(names.begin() + DNS_COLUMN_BEGIN, names.end());
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
	state->progress.Initialize(context, input.bind_data->Cast<PcapBindData>().SelectedFiles(), true);
	state->columns = input.column_ids;
	state->options.reassemble_dns = true;
	state->options.decode_depth = packetquapture::DecodeDepth::TRANSPORT;
	for (const auto column : state->columns) {
		if (column >= MESSAGE_DNS_COLUMN_BEGIN && column < MESSAGE_DNS_COLUMN_END) {
			state->decode_dns = true;
		}
	}
	return std::move(state);
}

static void SetMessageValue(Vector &vector, idx_t row, column_t column, const string &filename,
                            const packetquapture::TcpDnsMessage &message, const PacketRecord &dns_record) {
	const auto &key = message.key;
	if (column >= MESSAGE_DNS_COLUMN_BEGIN && column < MESSAGE_DNS_COLUMN_END) {
		SetRecordValue(vector, row, column - MESSAGE_DNS_COLUMN_BEGIN + DNS_COLUMN_BEGIN, dns_record);
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
				if (!bind.SetPartition(output.data[i], count, global.columns[i], state.file_index)) {
					SetMessageValue(output.data[i], count, global.columns[i], state.filename, message, dns_record);
				}
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

// read_tls reports one row per handshake, pairing the two directions of a
// connection so the offered name and the selected parameters arrive together.
// The key is oriented client to server whichever direction was captured.
// One element of server_certificates.
static LogicalType TlsCertificateType() {
	child_list_t<LogicalType> fields;
	fields.emplace_back("subject", LogicalType::VARCHAR);
	fields.emplace_back("issuer", LogicalType::VARCHAR);
	fields.emplace_back("serial", LogicalType::VARCHAR);
	fields.emplace_back("not_before", LogicalType::TIMESTAMP);
	fields.emplace_back("not_after", LogicalType::TIMESTAMP);
	fields.emplace_back("san_dns", LogicalType::LIST(LogicalType::VARCHAR));
	fields.emplace_back("san_ip", LogicalType::LIST(LogicalType::VARCHAR));
	// JA4X and its raw form. FoxIO License 1.1; see NOTICE.
	fields.emplace_back("ja4x", LogicalType::VARCHAR);
	fields.emplace_back("ja4x_r", LogicalType::VARCHAR);
	fields.emplace_back("sha1", LogicalType::VARCHAR);
	fields.emplace_back("sha256", LogicalType::VARCHAR);
	fields.emplace_back("signature_algorithm", LogicalType::VARCHAR);
	fields.emplace_back("public_key_algorithm", LogicalType::VARCHAR);
	fields.emplace_back("public_key_bits", LogicalType::UINTEGER);
	fields.emplace_back("public_key_curve", LogicalType::VARCHAR);
	fields.emplace_back("is_ca", LogicalType::BOOLEAN);
	fields.emplace_back("path_length", LogicalType::UINTEGER);
	fields.emplace_back("key_usage", LogicalType::LIST(LogicalType::VARCHAR));
	fields.emplace_back("extended_key_usage", LogicalType::LIST(LogicalType::VARCHAR));
	return LogicalType::STRUCT(std::move(fields));
}

// The tunnel that carried a handshake, when TLS did not begin a stream.
static LogicalType TlsTunnelType() {
	child_list_t<LogicalType> fields;
	fields.emplace_back("protocol", LogicalType::VARCHAR);
	fields.emplace_back("destination", LogicalType::VARCHAR);
	fields.emplace_back("client_prefix_bytes", LogicalType::UINTEGER);
	fields.emplace_back("server_prefix_bytes", LogicalType::UINTEGER);
	return LogicalType::STRUCT(std::move(fields));
}

static unique_ptr<FunctionData> TlsBind(ClientContext &context, TableFunctionBindInput &input,
                                        vector<LogicalType> &types, vector<string> &names) {
	auto result = PcapBind(context, input, types, names);
	names = {"filename",
	         "section_number",
	         "interface_id",
	         "ip_version",
	         "client_ip",
	         "server_ip",
	         "client_port",
	         "server_port",
	         "client_stream_id",
	         "server_stream_id",
	         "handshake_number",
	         "first_packet_number",
	         "last_packet_number",
	         "first_timestamp",
	         "last_timestamp",
	         "client_hello",
	         "server_hello",
	         "tls_sni",
	         "client_version",
	         "negotiated_version",
	         "cipher_suite",
	         "session_resumed",
	         "reassembly_status",
	         "reassembly_error",
	         "vlan_ids",
	         "client_cipher_suites",
	         "client_cipher_suites_no_grease",
	         "client_extensions",
	         "client_extensions_no_grease",
	         "client_supported_groups",
	         "client_supported_groups_no_grease",
	         "client_signature_algorithms",
	         "client_signature_algorithms_no_grease",
	         "client_supported_versions",
	         "client_supported_versions_no_grease",
	         "client_ec_point_formats",
	         "client_alpn",
	         "client_alpn_no_grease",
	         "server_extensions",
	         "server_extensions_no_grease",
	         "server_alpn",
	         "warnings",
	         "ja3",
	         "ja3_full",
	         "ja3s",
	         "ja3s_full",
	         "ja4",
	         "ja4_r",
	         "ja4s",
	         "ja4s_r",
	         "server_certificates",
	         "tunnel",
	         "client_certificates"};
	const auto codes = LogicalType::LIST(LogicalType::USMALLINT);
	const auto text = LogicalType::LIST(LogicalType::VARCHAR);
	types = {LogicalType::VARCHAR,
	         LogicalType::UINTEGER,
	         LogicalType::UINTEGER,
	         LogicalType::UTINYINT,
	         LogicalType::VARCHAR,
	         LogicalType::VARCHAR,
	         LogicalType::USMALLINT,
	         LogicalType::USMALLINT,
	         LogicalType::UBIGINT,
	         LogicalType::UBIGINT,
	         LogicalType::UBIGINT,
	         LogicalType::UBIGINT,
	         LogicalType::UBIGINT,
	         LogicalType::TIMESTAMP,
	         LogicalType::TIMESTAMP,
	         LogicalType::BOOLEAN,
	         LogicalType::BOOLEAN,
	         LogicalType::VARCHAR,
	         LogicalType::USMALLINT,
	         LogicalType::USMALLINT,
	         LogicalType::USMALLINT,
	         LogicalType::BOOLEAN,
	         LogicalType::VARCHAR,
	         LogicalType::VARCHAR,
	         codes,
	         codes,
	         codes,
	         codes,
	         codes,
	         codes,
	         codes,
	         codes,
	         codes,
	         codes,
	         codes,
	         LogicalType::LIST(LogicalType::UTINYINT),
	         text,
	         text,
	         codes,
	         codes,
	         LogicalType::VARCHAR,
	         text,
	         LogicalType::VARCHAR,
	         LogicalType::VARCHAR,
	         LogicalType::VARCHAR,
	         LogicalType::VARCHAR,
	         LogicalType::VARCHAR,
	         LogicalType::VARCHAR,
	         LogicalType::VARCHAR,
	         LogicalType::VARCHAR,
	         LogicalType::LIST(TlsCertificateType()),
	         TlsTunnelType(),
	         LogicalType::LIST(TlsCertificateType())};
	auto &bind = result->Cast<PcapBindData>();
	bind.types = types;
	bind.stream_plan =
	    context.registered_state->GetOrCreate<StreamPlanRegistry>("packetquapture_stream_plans")->Register();
	return result;
}

static unique_ptr<GlobalTableFunctionState> TlsInit(ClientContext &context, TableFunctionInitInput &input) {
	auto state = make_uniq<StreamGlobalState>(context, input.bind_data->Cast<PcapBindData>());
	state->progress.Initialize(context, input.bind_data->Cast<PcapBindData>().SelectedFiles(), true);
	state->columns = input.column_ids;
	state->options.reassemble_tcp = true;
	state->options.decode_depth = packetquapture::DecodeDepth::TRANSPORT;
	return std::move(state);
}

// The first 12 hex digits of SHA-256, as JA4 truncates it. An empty list is
// written as zeros rather than the hash of nothing, as the JA4 specification
// and both FoxIO implementations do.
static string Ja4Hash12(const string &text) {
	if (text.empty()) {
		return "000000000000";
	}
	duckdb_mbedtls::MbedTlsWrapper::SHA256State sha;
	sha.AddString(text);
	char hex[duckdb_mbedtls::MbedTlsWrapper::SHA256_HASH_LENGTH_TEXT];
	sha.FinishHex(hex);
	return string(hex, 12);
}

// A hello list as a column value: NULL when the hello did not carry it, was not
// captured, or carried it malformed. With skip_grease, RFC 8701 values are dropped.
static void SetTlsCodes(Vector &vector, idx_t row, const packetquapture::TlsList<uint16_t> &list, bool skip_grease) {
	if (!list.present) {
		FlatVector::SetNull(vector, row, true);
		return;
	}
	duckdb::vector<Value> values;
	for (const auto code : list.values) {
		if (!skip_grease || !packetquapture::IsTlsGrease(code)) {
			values.push_back(Value::USMALLINT(code));
		}
	}
	vector.SetValue(row, Value::LIST(LogicalType::USMALLINT, values));
}

// ALPN identifiers are peer-supplied bytes, escaped as server names are.
static void SetTlsAlpn(Vector &vector, idx_t row, const packetquapture::TlsList<std::string> &list, bool skip_grease) {
	if (!list.present) {
		FlatVector::SetNull(vector, row, true);
		return;
	}
	duckdb::vector<Value> values;
	for (const auto &protocol : list.values) {
		if (!skip_grease || !packetquapture::IsTlsGreaseAlpn(protocol)) {
			values.push_back(Value(packetquapture::EscapeTlsText(protocol)));
		}
	}
	vector.SetValue(row, Value::LIST(LogicalType::VARCHAR, values));
}

static Value TextList(const std::vector<std::string> &items) {
	duckdb::vector<Value> values;
	for (const auto &item : items) {
		values.push_back(Value(item));
	}
	return Value::LIST(LogicalType::VARCHAR, values);
}

// Estimated output bytes for one read_tls row. max_list_entries bounds how many
// entries a list holds, not how many bytes it produces, so the lists are
// counted: each code point lands in its list column, the no-GREASE copy and the
// JA3/JA4 raw strings, and each ALPN name is written twice and may grow
// fourfold when escaped.
static idx_t TlsRowBytes(const string &filename, const packetquapture::TlsHandshake &handshake) {
	const idx_t codes = handshake.client_cipher_suites.values.size() + handshake.client_extensions.values.size() +
	                    handshake.client_supported_groups.values.size() +
	                    handshake.client_signature_algorithms.values.size() +
	                    handshake.client_supported_versions.values.size() +
	                    handshake.client_ec_point_formats.values.size() + handshake.server_extensions.values.size();
	idx_t alpn = 0;
	for (const auto &protocol : handshake.client_alpn.values) {
		alpn += 32 + 8 * protocol.size();
	}
	for (const auto &protocol : handshake.server_alpn.values) {
		alpn += 32 + 4 * protocol.size();
	}
	idx_t certificates = 0;
	for (const auto *chain : {&handshake.server_certificates, &handshake.client_certificates}) {
		for (const auto &certificate : chain->values) {
			const auto &fields = certificate.fields;
			certificates += 512 + fields.TextBytes();
			certificates += 32 * (fields.san_dns.size() + fields.san_ip.size() + fields.key_usage.size() +
			                      fields.extended_key_usage.size());
		}
	}
	return 1024 + filename.size() + handshake.sni.size() + 32 * codes + alpn + certificates +
	       handshake.tunnel_destination.size();
}

static Value OptionalText(const std::string &text) {
	return text.empty() ? Value(LogicalType::VARCHAR) : Value(text);
}

static void SetTlsCertificates(Vector &vector, idx_t row,
                               const packetquapture::TlsList<packetquapture::TlsCertificate> &chain) {
	if (!chain.present) {
		FlatVector::SetNull(vector, row, true);
		return;
	}
	const auto type = TlsCertificateType();
	duckdb::vector<Value> values;
	for (const auto &certificate : chain.values) {
		if (!certificate.parsed) {
			values.push_back(Value(type));
			continue;
		}
		const auto &fields = certificate.fields;
		packetquapture::Ja4xParts ja4x;
		packetquapture::Ja4xStrings(fields, ja4x);
		values.push_back(Value::STRUCT(
		    type, {Value(fields.subject), Value(fields.issuer), Value(fields.serial),
		           Value::TIMESTAMP(timestamp_t(fields.not_before)), Value::TIMESTAMP(timestamp_t(fields.not_after)),
		           TextList(fields.san_dns), TextList(fields.san_ip),
		           Value(Ja4Hash12(ja4x.issuer) + "_" + Ja4Hash12(ja4x.subject) + "_" + Ja4Hash12(ja4x.extensions)),
		           Value(ja4x.issuer + "_" + ja4x.subject + "_" + ja4x.extensions), OptionalText(fields.sha1),
		           OptionalText(fields.sha256), Value(fields.signature_algorithm), Value(fields.public_key_algorithm),
		           fields.public_key_bits != 0 ? Value::UINTEGER(fields.public_key_bits) : Value(LogicalType::UINTEGER),
		           OptionalText(fields.public_key_curve),
		           fields.has_basic_constraints ? Value::BOOLEAN(fields.is_ca) : Value(LogicalType::BOOLEAN),
		           fields.has_path_length ? Value::UINTEGER(fields.path_length) : Value(LogicalType::UINTEGER),
		           fields.has_key_usage ? TextList(fields.key_usage) : Value(LogicalType::LIST(LogicalType::VARCHAR)),
		           fields.has_extended_key_usage ? TextList(fields.extended_key_usage)
		                                         : Value(LogicalType::LIST(LogicalType::VARCHAR))}));
	}
	vector.SetValue(row, Value::LIST(type, values));
}

static void SetHandshakeValue(Vector &vector, idx_t row, column_t column, const string &filename,
                              const packetquapture::TlsHandshake &handshake) {
	const auto &key = handshake.key;
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
	// A stream id is NULL when that direction of the connection was not captured.
	case 8:
		if (handshake.has_client_stream) {
			SetDecodedScalar(vector, row, handshake.client_stream_id);
		} else {
			FlatVector::SetNull(vector, row, true);
		}
		break;
	case 9:
		if (handshake.has_server_stream) {
			SetDecodedScalar(vector, row, handshake.server_stream_id);
		} else {
			FlatVector::SetNull(vector, row, true);
		}
		break;
	case 10:
		SetDecodedScalar(vector, row, handshake.handshake_number);
		break;
	case 11:
		SetDecodedScalar(vector, row, handshake.first.number);
		break;
	case 12:
		SetDecodedScalar(vector, row, handshake.last.number);
		break;
	case 13:
	case 14: {
		const auto &stamp = column == 13 ? handshake.first : handshake.last;
		if (stamp.has_timestamp) {
			vector.SetValue(row, Value::TIMESTAMP(timestamp_t(stamp.timestamp)));
		} else {
			FlatVector::SetNull(vector, row, true);
		}
		break;
	}
	case 15:
		SetDecodedScalar(vector, row, handshake.has_client_hello);
		break;
	case 16:
		SetDecodedScalar(vector, row, handshake.has_server_hello);
		break;
	case 17:
		if (handshake.has_sni) {
			vector.SetValue(row, handshake.sni);
		} else {
			FlatVector::SetNull(vector, row, true);
		}
		break;
	case 18:
		if (handshake.has_client_version) {
			SetDecodedScalar(vector, row, handshake.client_version);
		} else {
			FlatVector::SetNull(vector, row, true);
		}
		break;
	case 19:
		if (handshake.has_negotiated_version) {
			SetDecodedScalar(vector, row, handshake.negotiated_version);
		} else {
			FlatVector::SetNull(vector, row, true);
		}
		break;
	case 20:
		if (handshake.has_cipher_suite) {
			SetDecodedScalar(vector, row, handshake.cipher_suite);
		} else {
			FlatVector::SetNull(vector, row, true);
		}
		break;
	case 21:
		// Undecidable without both directions, and meaningless in TLS 1.3.
		if (handshake.has_resumed) {
			SetDecodedScalar(vector, row, handshake.resumed);
		} else {
			FlatVector::SetNull(vector, row, true);
		}
		break;
	case 22:
		vector.SetValue(row, handshake.status);
		break;
	case 23:
		if (handshake.error.empty()) {
			FlatVector::SetNull(vector, row, true);
		} else {
			vector.SetValue(row, handshake.error);
		}
		break;
	case 24: {
		duckdb::vector<Value> values;
		for (const auto vlan : key.vlans) {
			values.push_back(Value::USMALLINT(vlan));
		}
		vector.SetValue(row, Value::LIST(LogicalType::USMALLINT, values));
		break;
	}
	case 25:
	case 26:
		SetTlsCodes(vector, row, handshake.client_cipher_suites, column == 26);
		break;
	case 27:
	case 28:
		SetTlsCodes(vector, row, handshake.client_extensions, column == 28);
		break;
	case 29:
	case 30:
		SetTlsCodes(vector, row, handshake.client_supported_groups, column == 30);
		break;
	case 31:
	case 32:
		SetTlsCodes(vector, row, handshake.client_signature_algorithms, column == 32);
		break;
	case 33:
	case 34:
		SetTlsCodes(vector, row, handshake.client_supported_versions, column == 34);
		break;
	case 35: {
		// Point formats have no GREASE values, so there is no filtered twin.
		const auto &list = handshake.client_ec_point_formats;
		if (!list.present) {
			FlatVector::SetNull(vector, row, true);
			break;
		}
		duckdb::vector<Value> values;
		for (const auto format : list.values) {
			values.push_back(Value::UTINYINT(format));
		}
		vector.SetValue(row, Value::LIST(LogicalType::UTINYINT, values));
		break;
	}
	case 36:
	case 37:
		SetTlsAlpn(vector, row, handshake.client_alpn, column == 37);
		break;
	case 38:
	case 39:
		SetTlsCodes(vector, row, handshake.server_extensions, column == 39);
		break;
	case 40:
		if (handshake.server_alpn.present && !handshake.server_alpn.values.empty()) {
			vector.SetValue(row, packetquapture::EscapeTlsText(handshake.server_alpn.values.front()));
		} else {
			FlatVector::SetNull(vector, row, true);
		}
		break;
	case 41: {
		duckdb::vector<Value> values;
		for (const auto &warning : handshake.warnings) {
			values.push_back(Value(warning));
		}
		vector.SetValue(row, Value::LIST(LogicalType::VARCHAR, values));
		break;
	}
	// Fingerprints are built only when projected, like every other column, so
	// queries that do not ask for them pay nothing. NULL rather than a hash of
	// partial input; see tls_fingerprint.hpp.
	case 42:
	case 43:
	case 44:
	case 45: {
		std::string text;
		const bool client = column == 42 || column == 43;
		if (!(client ? packetquapture::Ja3String(handshake, text) : packetquapture::Ja3sString(handshake, text))) {
			FlatVector::SetNull(vector, row, true);
		} else if (column == 43 || column == 45) {
			vector.SetValue(row, Value(text));
		} else {
			MD5Context md5;
			md5.Add(text);
			vector.SetValue(row, Value(md5.FinishHex()));
		}
		break;
	}
	// JA4 and JA4S, and their raw forms. JA4S is FoxIO License 1.1; see NOTICE.
	case 46:
	case 47:
	case 48:
	case 49: {
		packetquapture::Ja4Parts parts;
		const bool client = column == 46 || column == 47;
		if (!(client ? packetquapture::Ja4Strings(handshake, parts) : packetquapture::Ja4sStrings(handshake, parts))) {
			FlatVector::SetNull(vector, row, true);
		} else if (column == 47 || column == 49) {
			vector.SetValue(row, Value(parts.prefix + "_" + parts.first + "_" + parts.second));
		} else {
			// JA4S carries its one cipher suite as is; JA4 hashes its cipher list.
			const auto first = client ? Ja4Hash12(parts.first) : parts.first;
			vector.SetValue(row, Value(parts.prefix + "_" + first + "_" + Ja4Hash12(parts.second)));
		}
		break;
	}
	// The chain from each side's Certificate message, leaf first. An entry that
	// did not parse is a NULL element, so positions still match the chain.
	case 50:
		SetTlsCertificates(vector, row, handshake.server_certificates);
		break;
	case 52:
		SetTlsCertificates(vector, row, handshake.client_certificates);
		break;
	// NULL unless a prefix came before TLS in a captured direction. The protocol
	// is the client's reading of its own prefix when it has one, since only the
	// client's request names the destination; otherwise the server's.
	case 51: {
		if (handshake.client_prefix_bytes == 0 && handshake.server_prefix_bytes == 0) {
			FlatVector::SetNull(vector, row, true);
			break;
		}
		const auto &protocol = !handshake.client_tunnel.empty() ? handshake.client_tunnel : handshake.server_tunnel;
		vector.SetValue(row, Value::STRUCT(TlsTunnelType(),
		                                   {protocol.empty() ? Value(LogicalType::VARCHAR) : Value(protocol),
		                                    handshake.tunnel_destination.empty() ? Value(LogicalType::VARCHAR)
		                                                                         : Value(handshake.tunnel_destination),
		                                    handshake.has_client_hello ? Value::UINTEGER(handshake.client_prefix_bytes)
		                                                               : Value(LogicalType::UINTEGER),
		                                    handshake.has_server_hello ? Value::UINTEGER(handshake.server_prefix_bytes)
		                                                               : Value(LogicalType::UINTEGER)}));
		break;
	}
	default:
		throw InternalException("Unexpected read_tls column id %d", column);
	}
}

static void TlsScan(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
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
		if (state.tls_pending_index < state.tls_pending.size()) {
			const auto &handshake = state.tls_pending[state.tls_pending_index++];
			for (idx_t i = 0; i < global.columns.size(); ++i) {
				if (!bind.SetPartition(output.data[i], count, global.columns[i], state.tls_pending_file_index)) {
					SetHandshakeValue(output.data[i], count, global.columns[i], state.tls_pending_filename, handshake);
				}
			}
			output_bytes += TlsRowBytes(state.tls_pending_filename, handshake);
			++count;
			continue;
		}
		state.tls_pending.clear();
		state.tls_pending_index = 0;
		if (state.tls_drained) {
			break;
		}
		StreamEvent event;
		if (!NextStreamEvent(context, bind, global, state, event)) {
			// Directions still waiting for a peer are reported on their own.
			state.tls_drained = true;
			state.tls_pending = state.tls_assembler.Finish();
			state.tls_pending_filename = state.tls_open_filename;
			state.tls_pending_file_index = state.tls_open_file_index;
			continue;
		}
		// TLS runs over TCP. DTLS frames differently and is not parsed.
		if (!event.tcp) {
			continue;
		}
		if (state.tls_open_filename != state.filename || state.tls_open_file_index != state.file_index) {
			// A connection cannot span files, so anything still held belongs to
			// the file just finished and is reported before moving on.
			state.tls_pending = state.tls_assembler.Finish();
			state.tls_pending_filename = state.tls_open_filename;
			state.tls_pending_file_index = state.tls_open_file_index;
			state.tls_open_filename = state.filename;
			state.tls_open_file_index = state.file_index;
		}
		auto handshakes = state.tls_assembler.Add(event.stream);
		if (!handshakes.empty()) {
			// Nothing pairs on the first stream of a file, so these two never
			// collide; append rather than assume it.
			if (state.tls_pending.empty()) {
				state.tls_pending_filename = state.filename;
				state.tls_pending_file_index = state.file_index;
				state.tls_pending = std::move(handshakes);
			} else {
				state.tls_pending.insert(state.tls_pending.end(), std::make_move_iterator(handshakes.begin()),
				                         std::make_move_iterator(handshakes.end()));
			}
		}
	}
	output.SetCardinality(count);
	if (!count) {
		std::vector<packetquapture::TcpStream>().swap(state.streams);
		std::vector<packetquapture::TlsHandshake>().swap(state.tls_pending);
		state.tls_assembler = NewTlsAssembler();
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
	state->progress.Initialize(context, input.bind_data->Cast<PcapBindData>().SelectedFiles(), true);
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
			if (!bind.SetPartition(output.data[i], count, global.columns[i], state.file_index)) {
				SetStreamValue(output.data[i], count, global.columns[i], state.filename, event.stream);
			}
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

struct FlowGlobalState : public CaptureGlobalState {
	FlowGlobalState(ClientContext &context, const PcapBindData &bind)
	    : scheduler(bind.selected_indices.size()), file_count(bind.selected_indices.size()) {
		budget = context.registered_state->GetOrCreate<FlowQueryBudget>("packetquapture_flow_budget", context);
		if (bind.flow_plan) {
			bind.flow_plan->sealed.store(true);
			max_workers = MaxValue<idx_t>(1, budget->Slots() / bind.flow_plan->scans.load());
		}
		max_workers = MinValue<idx_t>(max_workers, MaxValue<idx_t>(1, file_count));
		if (file_count) {
			initial = make_uniq<FlowReservation>(budget);
			if (!initial->Acquired()) {
				throw OutOfMemoryException("PacketQuapture cannot reserve 48 MiB for a flow worker. "
				                           "Increase packetquapture_flow_memory_mb or memory_limit; "
				                           "all flow scans in this query share the budget.");
			}
		}
	}
	idx_t MaxThreads() const override {
		return max_workers;
	}
	unique_ptr<FlowReservation> Admit() {
		lock_guard<mutex> guard(lock);
		if (admitted >= max_workers) {
			return nullptr;
		}
		++admitted;
		if (initial) {
			return std::move(initial);
		}
		auto result = make_uniq<FlowReservation>(budget);
		return result->Acquired() ? std::move(result) : nullptr;
	}
	void Drained() {
		if (drained.fetch_add(1, std::memory_order_relaxed) + 1 == file_count) {
			progress.Finish();
		}
	}
	FileScheduler scheduler;
	const idx_t file_count;
	shared_ptr<FlowQueryBudget> budget;
	unique_ptr<FlowReservation> initial;
	mutex lock;
	std::atomic<idx_t> drained {0};
	idx_t max_workers = 1, admitted = 0;
	vector<column_t> columns;
	ScanOptions options;
	bool decode_dns = false;
};

struct FlowScanState : public LocalTableFunctionState {
	unique_ptr<FlowReservation> reservation;
	idx_t file_index = 0;
	bool initialized = false, finished = false;
	unique_ptr<CaptureReader> reader;
	unique_ptr<packetquapture::FlowAggregator> aggregator;
};
static unique_ptr<LocalTableFunctionState> FlowsInitLocal(ExecutionContext &, TableFunctionInitInput &,
                                                          GlobalTableFunctionState *) {
	return make_uniq<FlowScanState>();
}
static unique_ptr<FunctionData> FlowsBind(ClientContext &context, TableFunctionBindInput &input,
                                          vector<LogicalType> &types, vector<string> &names) {
	auto result = PcapBind(context, input, types, names);
	auto &bind = result->Cast<PcapBindData>();
	bind.flow_scan = true;
	for (auto &entry : input.named_parameters) {
		if (StringUtil::CIEquals(entry.first, "max_active_flows")) {
			if (entry.second.IsNull()) {
				throw BinderException("max_active_flows must not be NULL");
			}
			auto value = entry.second.GetValue<uint64_t>();
			if (!value || value > 16384) {
				throw BinderException("max_active_flows must be between 1 and 16384");
			}
			bind.flow_limits.max_flows = value;
		} else if (StringUtil::CIEquals(entry.first, "tcp_idle_timeout") ||
		           StringUtil::CIEquals(entry.first, "udp_idle_timeout")) {
			if (entry.second.IsNull()) {
				throw BinderException("Flow idle timeout must not be NULL");
			}
			const auto interval = entry.second.GetValue<interval_t>();
			int64_t micros;
			if (interval.months || !Interval::TryGetMicro(interval, micros) || micros < 0) {
				throw BinderException("Flow idle timeout must be a nonnegative fixed interval without months");
			}
			if (StringUtil::CIEquals(entry.first, "tcp_idle_timeout")) {
				bind.flow_limits.tcp_idle_us = micros;
			} else {
				bind.flow_limits.udp_idle_us = micros;
			}
		}
	}
	names = {"filename",
	         "input_index",
	         "flow_id",
	         "section_number",
	         "interface_id",
	         "vlan_ids",
	         "first_packet_number",
	         "last_packet_number",
	         "transport",
	         "ip_version",
	         "orig_ip",
	         "orig_port",
	         "resp_ip",
	         "resp_port",
	         "originator_basis",
	         "orig_packets",
	         "resp_packets",
	         "orig_captured_bytes",
	         "resp_captured_bytes",
	         "orig_reported_bytes",
	         "resp_reported_bytes",
	         "orig_payload_bytes",
	         "resp_payload_bytes",
	         "first_timestamp",
	         "last_timestamp",
	         "duration",
	         "missing_timestamp_packets",
	         "late_packets",
	         "orig_tcp_flags",
	         "resp_tcp_flags",
	         "handshake_complete",
	         "syn_seen",
	         "fin_seen",
	         "reset_seen",
	         "simultaneous_open",
	         "equal_endpoints",
	         "partial_session",
	         "ambiguous",
	         "finalized_by"};
	types = {LogicalType::VARCHAR,   LogicalType::UBIGINT,   LogicalType::UBIGINT,
	         LogicalType::UINTEGER,  LogicalType::UINTEGER,  LogicalType::LIST(LogicalType::USMALLINT),
	         LogicalType::UBIGINT,   LogicalType::UBIGINT,   LogicalType::VARCHAR,
	         LogicalType::UTINYINT,  LogicalType::VARCHAR,   LogicalType::USMALLINT,
	         LogicalType::VARCHAR,   LogicalType::USMALLINT, LogicalType::VARCHAR,
	         LogicalType::UBIGINT,   LogicalType::UBIGINT,   LogicalType::UBIGINT,
	         LogicalType::UBIGINT,   LogicalType::UBIGINT,   LogicalType::UBIGINT,
	         LogicalType::UBIGINT,   LogicalType::UBIGINT,   LogicalType::TIMESTAMP,
	         LogicalType::TIMESTAMP, LogicalType::INTERVAL,  LogicalType::UBIGINT,
	         LogicalType::UBIGINT,   LogicalType::USMALLINT, LogicalType::USMALLINT,
	         LogicalType::BOOLEAN,   LogicalType::BOOLEAN,   LogicalType::BOOLEAN,
	         LogicalType::BOOLEAN,   LogicalType::BOOLEAN,   LogicalType::BOOLEAN,
	         LogicalType::BOOLEAN,   LogicalType::BOOLEAN,   LogicalType::VARCHAR};
	bind.types = types;
	bind.flow_plan = context.registered_state->GetOrCreate<FlowPlanRegistry>("packetquapture_flow_plans")->Register();
	return result;
}
static unique_ptr<GlobalTableFunctionState> FlowsInit(ClientContext &context, TableFunctionInitInput &input) {
	auto state = make_uniq<FlowGlobalState>(context, input.bind_data->Cast<PcapBindData>());
	state->progress.Initialize(context, input.bind_data->Cast<PcapBindData>().SelectedFiles(), true);
	state->columns = input.column_ids;
	state->options.flow_scan = true;
	state->options.decode_depth = packetquapture::DecodeDepth::TRANSPORT;
	return std::move(state);
}
static void SetFlowValue(Vector &v, idx_t row, column_t col, const PcapBindData &bind, idx_t file,
                         const packetquapture::FlowSummary &flow) {
	const auto &orig = flow.orig_is_low ? flow.key.low : flow.key.high;
	const auto &resp = flow.orig_is_low ? flow.key.high : flow.key.low;
	const bool tcp = flow.key.protocol == 6;
	if ((!tcp && col >= 28 && col <= 34) || ((col == 23 || col == 24) && !flow.has_timestamp) ||
	    (col == 25 && (!flow.has_timestamp || flow.missing_timestamps))) {
		FlatVector::SetNull(v, row, true);
		return;
	}
	switch (col) {
	case 0:
		v.SetValue(row, bind.files[file].path);
		break;
	case 1:
		v.SetValue(row, Value::UBIGINT(file + 1));
		break;
	case 2:
		v.SetValue(row, Value::UBIGINT(FlowScanId(flow.first_packet, file, bind.files.size())));
		break;
	case 3:
		v.SetValue(row, Value::UINTEGER(flow.section));
		break;
	case 4:
		v.SetValue(row, Value::UINTEGER(flow.key.interface_id));
		break;
	case 5: {
		vector<Value> tags;
		for (idx_t i = 0; i < flow.key.vlan_count; ++i)
			tags.push_back(Value::USMALLINT(flow.key.vlans[i]));
		v.SetValue(row, Value::LIST(LogicalType::USMALLINT, tags));
		break;
	}
	case 6:
		v.SetValue(row, Value::UBIGINT(flow.first_packet));
		break;
	case 7:
		v.SetValue(row, Value::UBIGINT(flow.last_packet));
		break;
	case 8:
		v.SetValue(row, tcp ? "tcp" : "udp");
		break;
	case 9:
		v.SetValue(row, Value::UTINYINT(flow.key.ip_version));
		break;
	case 10:
		v.SetValue(row, IpString(orig.ip, flow.key.ip_version));
		break;
	case 11:
		v.SetValue(row, Value::USMALLINT(orig.port));
		break;
	case 12:
		v.SetValue(row, IpString(resp.ip, flow.key.ip_version));
		break;
	case 13:
		v.SetValue(row, Value::USMALLINT(resp.port));
		break;
	case 14:
		v.SetValue(row, flow.originator_basis);
		break;
	case 15:
		v.SetValue(row, Value::UBIGINT(flow.orig.packets));
		break;
	case 16:
		v.SetValue(row, Value::UBIGINT(flow.resp.packets));
		break;
	case 17:
		v.SetValue(row, Value::UBIGINT(flow.orig.captured_bytes));
		break;
	case 18:
		v.SetValue(row, Value::UBIGINT(flow.resp.captured_bytes));
		break;
	case 19:
		v.SetValue(row, Value::UBIGINT(flow.orig.reported_bytes));
		break;
	case 20:
		v.SetValue(row, Value::UBIGINT(flow.resp.reported_bytes));
		break;
	case 21:
		v.SetValue(row, Value::UBIGINT(flow.orig.payload_bytes));
		break;
	case 22:
		v.SetValue(row, Value::UBIGINT(flow.resp.payload_bytes));
		break;
	case 23:
		v.SetValue(row, Value::TIMESTAMP(timestamp_t(flow.first_timestamp)));
		break;
	case 24:
		v.SetValue(row, Value::TIMESTAMP(timestamp_t(flow.last_timestamp)));
		break;
	case 25: {
		if (flow.first_timestamp < 0 &&
		    flow.last_timestamp > NumericLimits<int64_t>::Maximum() + flow.first_timestamp) {
			throw OutOfRangeException("Flow duration exceeds INTERVAL microsecond capacity");
		}
		interval_t duration {0, 0, flow.last_timestamp - flow.first_timestamp};
		v.SetValue(row, Value::INTERVAL(duration));
		break;
	}
	case 26:
		v.SetValue(row, Value::UBIGINT(flow.missing_timestamps));
		break;
	case 27:
		v.SetValue(row, Value::UBIGINT(flow.late_packets));
		break;
	case 28:
		v.SetValue(row, Value::USMALLINT(flow.orig.flags));
		break;
	case 29:
		v.SetValue(row, Value::USMALLINT(flow.resp.flags));
		break;
	case 30:
		v.SetValue(row, Value(flow.handshake_complete));
		break;
	case 31:
		v.SetValue(row, Value(flow.syn_seen));
		break;
	case 32:
		v.SetValue(row, Value(flow.fin_seen));
		break;
	case 33:
		v.SetValue(row, Value(flow.reset_seen));
		break;
	case 34:
		v.SetValue(row, Value(flow.simultaneous_open));
		break;
	case 35:
		v.SetValue(row, Value(flow.equal_endpoints));
		break;
	case 36:
		v.SetValue(row, Value(!tcp || !flow.handshake_complete ||
		                      (!flow.reset_seen && !((flow.orig.flags & 1) && (flow.resp.flags & 1)))));
		break;
	case 37:
		v.SetValue(row, Value(flow.equal_endpoints || flow.simultaneous_open || flow.late_packets ||
		                      flow.missing_timestamps || flow.originator_basis == "first_packet"));
		break;
	case 38:
		v.SetValue(row, flow.finalized_by);
		break;
	default:
		throw InternalException("Unexpected read_flows column id %d", col);
	}
}
static void FlowsScan(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
	auto &bind = input.bind_data->Cast<PcapBindData>();
	auto &global = input.global_state->Cast<FlowGlobalState>();
	auto &state = input.local_state->Cast<FlowScanState>();
	if (!state.initialized) {
		state.initialized = true;
		if (global.file_count)
			state.reservation = global.Admit();
	}
	if (!state.reservation)
		return;
	idx_t count = 0, bytes = 0;
	while (count < STANDARD_VECTOR_SIZE && bytes < FLOW_OUTPUT_BATCH_BYTES) {
		if (context.IsInterrupted())
			throw InterruptException();
		if (!state.reader) {
			idx_t work;
			if (!global.scheduler.Claim(work))
				break;
			state.file_index = bind.selected_indices[work];
			state.aggregator = make_uniq<packetquapture::FlowAggregator>(bind.flow_limits);
			state.reader =
			    make_uniq<CaptureReader>(context, bind.files[state.file_index], global.options, &global.progress, work);
			state.finished = false;
		}
		packetquapture::FlowSummary flow;
		bool have_flow = false;
		try {
			have_flow = state.aggregator->Next(flow);
		} catch (const std::exception &exception) {
			ErrorData error(exception);
			error.Throw(StringUtil::Format("Flow scan '%s': ", bind.files[state.file_index].path));
		}
		if (have_flow) {
			for (idx_t i = 0; i < global.columns.size(); ++i) {
				if (!bind.SetPartition(output.data[i], count, global.columns[i], state.file_index)) {
					SetFlowValue(output.data[i], count, global.columns[i], bind, state.file_index, flow);
				}
			}
			bytes += 1024 + bind.files[state.file_index].path.size();
			++count;
			continue;
		}
		if (state.finished) {
			state.aggregator.reset();
			state.reader.reset();
			global.Drained();
			continue;
		}
		PacketRecord record;
		if (!state.reader->Next(record)) {
			state.aggregator->Finish(state.reader->SectionNumber());
			state.finished = true;
			continue;
		}
		packetquapture::FlowInput packet;
		packet.section = record.section_number;
		packet.interface_id = record.interface_id;
		packet.captured_length = record.captured_length;
		packet.original_length = record.original_length;
		packet.stamp = Stamp(record);
		packet.packet = std::move(record.decoded);
		state.aggregator->Push(std::move(packet));
	}
	output.SetCardinality(count);
	if (!count) {
		state.aggregator.reset();
		state.reader.reset();
		state.reservation.reset();
	}
}

// Inventory catalogs are read as native DuckDB tables in the current transaction.
// No SQL text supplied by the caller is executed and no writes occur in SELECT.
enum InventoryColumn : idx_t {
	IC_FILE,
	IC_INPUT,
	IC_ID_TYPE,
	IC_ID,
	IC_STRENGTH,
	IC_SIZE,
	IC_MTIME,
	IC_FORMAT,
	IC_LINKS,
	IC_PACKETS,
	IC_MIN,
	IC_MAX,
	IC_NULLS,
	IC_CAPTURED,
	IC_REPORTED,
	IC_DETAIL,
	IC_IPV4,
	IC_IPV6,
	IC_TCP,
	IC_UDP,
	IC_OTHER,
	IC_MALFORMED,
	IC_UNSUPPORTED,
	IC_FRAGMENTS,
	IC_STATUS,
	IC_ERROR,
	IC_TIME,
	IC_SCAN_TIME,
	IC_SCHEMA,
	IC_SEMANTICS,
	IC_STABLE,
	IC_REUSED,
	IC_VALIDATION,
	IC_REASON,
	IC_COUNT
};
static void InventorySchema(vector<LogicalType> &types, vector<string> &names) {
	names = {"filename",
	         "input_index",
	         "identity_type",
	         "identity_value",
	         "identity_strength",
	         "file_size",
	         "modification_time",
	         "capture_format",
	         "link_types",
	         "packet_count",
	         "min_timestamp",
	         "max_timestamp",
	         "timestamp_null_count",
	         "captured_bytes",
	         "reported_bytes",
	         "detail",
	         "ipv4_packets",
	         "ipv6_packets",
	         "tcp_packets",
	         "udp_packets",
	         "other_protocol_packets",
	         "malformed_packets",
	         "unsupported_packets",
	         "fragment_packets",
	         "scan_status",
	         "scan_error",
	         "inventory_time",
	         "source_scan_time",
	         "schema_version",
	         "semantic_version",
	         "metadata_unchanged",
	         "reused",
	         "catalog_validation",
	         "reuse_reason"};
	types = {LogicalType::VARCHAR,   LogicalType::UBIGINT,   LogicalType::VARCHAR,
	         LogicalType::VARCHAR,   LogicalType::VARCHAR,   LogicalType::UBIGINT,
	         LogicalType::TIMESTAMP, LogicalType::VARCHAR,   LogicalType::LIST(LogicalType::UINTEGER),
	         LogicalType::UBIGINT,   LogicalType::TIMESTAMP, LogicalType::TIMESTAMP,
	         LogicalType::UBIGINT,   LogicalType::UBIGINT,   LogicalType::UBIGINT,
	         LogicalType::VARCHAR,   LogicalType::UBIGINT,   LogicalType::UBIGINT,
	         LogicalType::UBIGINT,   LogicalType::UBIGINT,   LogicalType::UBIGINT,
	         LogicalType::UBIGINT,   LogicalType::UBIGINT,   LogicalType::UBIGINT,
	         LogicalType::VARCHAR,   LogicalType::VARCHAR,   LogicalType::TIMESTAMP,
	         LogicalType::TIMESTAMP, LogicalType::UINTEGER,  LogicalType::UINTEGER,
	         LogicalType::BOOLEAN,   LogicalType::BOOLEAN,   LogicalType::VARCHAR,
	         LogicalType::VARCHAR};
}
struct InventoryBindData : public TableFunctionData {
	vector<string> paths;
	bool protocols = false, report = false, immutable = false;
	string previous;
	shared_ptr<InventoryPlanCount> plan;
	unique_ptr<FunctionData> Copy() const override {
		auto result = make_uniq<InventoryBindData>();
		result->paths = paths;
		result->protocols = protocols;
		result->report = report;
		result->immutable = immutable;
		result->previous = previous;
		result->plan = plan;
		if (plan)
			plan->scans.fetch_add(1);
		return std::move(result);
	}
	bool Equals(const FunctionData &other_p) const override {
		auto &other = other_p.Cast<InventoryBindData>();
		return paths == other.paths && protocols == other.protocols && report == other.report &&
		       immutable == other.immutable && previous == other.previous;
	}
};
static TableCatalogEntry &InventoryCatalog(ClientContext &context, const string &name, vector<StorageIndex> &columns) {
	auto qualified = QualifiedName::Parse(name);
	Binder::BindSchemaOrCatalog(context, qualified.catalog, qualified.schema);
	auto &table = Catalog::GetEntry<TableCatalogEntry>(context, qualified.catalog, qualified.schema, qualified.name);
	if (!table.IsDuckTable())
		throw BinderException("previous_catalog must name a native DuckDB table");
	vector<LogicalType> types;
	vector<string> names;
	InventorySchema(types, names);
	for (idx_t i = 0; i < names.size(); ++i) {
		auto index = table.GetColumnIndex(names[i]);
		auto &column = table.GetColumn(index);
		if (column.Generated() || column.Type() != types[i]) {
			throw BinderException("Incompatible inventory catalog column '%s': expected stored %s", names[i],
			                      types[i].ToString());
		}
		columns.push_back(table.GetStorageIndex(ColumnIndex(index.index)));
	}
	return table;
}
static string BindInventoryCatalog(ClientContext &context, const string &name) {
	vector<StorageIndex> columns;
	auto &table = InventoryCatalog(context, name, columns);
	QualifiedName resolved;
	resolved.catalog = table.catalog.GetName();
	resolved.schema = table.schema.name;
	resolved.name = table.name;
	return resolved.ToString();
}
static void ValidateInventoryLocator(const string &path) {
	if (!FileSystem::IsRemoteFile(path))
		return;
	auto authority = path.find("://");
	auto end = authority == string::npos ? 0 : path.find('/', authority + 3);
	auto at = path.find('@', authority == string::npos ? 0 : authority + 3);
	if (path.find('?') != string::npos || path.find('#') != string::npos ||
	    (at != string::npos && (end == string::npos || at < end))) {
		throw InvalidInputException("Inventory requires stable remote locators without query strings, fragments, or "
		                            "user information; use DuckDB credentials");
	}
}
static unique_ptr<FunctionData> InventoryBind(ClientContext &context, TableFunctionBindInput &input,
                                              vector<LogicalType> &types, vector<string> &names) {
	auto result = make_uniq<InventoryBindData>();
	result->paths = MultiFileReader::Create(input.table_function)->ParsePaths(input.inputs[0]);
	for (const auto &path : result->paths)
		ValidateInventoryLocator(path);
	for (auto &entry : input.named_parameters) {
		if (entry.second.IsNull())
			throw BinderException("Inventory option '%s' must not be NULL", entry.first);
		auto value = entry.second.GetValue<string>();
		if (StringUtil::CIEquals(entry.first, "previous_catalog")) {
			vector<StorageIndex> columns;
			auto &table = InventoryCatalog(context, value, columns);
			QualifiedName resolved;
			resolved.catalog = table.catalog.GetName();
			resolved.schema = table.schema.name;
			resolved.name = table.name;
			result->previous = resolved.ToString();
		} else {
			value = StringUtil::Lower(value);
			if (StringUtil::CIEquals(entry.first, "detail")) {
				if (value != "framing" && value != "protocols")
					throw BinderException("detail must be framing or protocols");
				result->protocols = value == "protocols";
			} else if (StringUtil::CIEquals(entry.first, "on_error")) {
				if (value != "error" && value != "report")
					throw BinderException("on_error must be error or report");
				result->report = value == "report";
			} else if (StringUtil::CIEquals(entry.first, "catalog_validation")) {
				if (value != "strict" && value != "immutable")
					throw BinderException("catalog_validation must be strict or immutable");
				result->immutable = value == "immutable";
			}
		}
	}
	InventorySchema(types, names);
	result->plan =
	    context.registered_state->GetOrCreate<InventoryPlanRegistry>("packetquapture_inventory_plans")->Register();
	return std::move(result);
}
static vector<OpenFileInfo> InventoryFiles(ClientContext &context, const InventoryBindData &bind) {
	vector<OpenFileInfo> files;
	auto reader = MultiFileReader::CreateDefault("capture_inventory");
	for (const auto &path : bind.paths) {
		if (context.IsInterrupted())
			throw InterruptException();
		if (FileSystem::HasGlob(path)) {
			auto expanded = reader->CreateFileList(context, vector<string> {path})->GetAllFiles();
			for (auto &file : expanded) {
				ValidateInventoryLocator(file.path);
				files.push_back(std::move(file));
			}
		} else
			files.emplace_back(path);
	}
	auto &fs = FileSystem::GetFileSystem(context);
	for (auto &file : files) {
		if (!FileSystem::IsRemoteFile(file.path))
			file.path = fs.CanonicalizePath(file.path);
	}
	return files;
}
struct InventoryPrevious {
	vector<Value> row;
	bool conflict = false;
};
// Native Values retained outside DuckDB vectors are conservatively charged, with
// an explicit 64 MiB snapshot cap. This is metadata, not a second capture cache.
class InventorySnapshotMemory {
public:
	explicit InventorySnapshotMemory(ClientContext &context) : manager(BufferManager::GetBufferManager(context)) {
	}
	~InventorySnapshotMemory() {
		if (used)
			manager.FreeReservedMemory(used);
	}
	void Add(idx_t bytes) {
		if (bytes > 64ULL * 1024 * 1024 - used)
			throw OutOfMemoryException("Inventory previous_catalog snapshot exceeds 64 MiB");
		manager.ReserveMemory(bytes);
		used += bytes;
	}

private:
	BufferManager &manager;
	idx_t used = 0;
};
static bool InventoryAgreement(const vector<Value> &a, const vector<Value> &b) {
	for (idx_t i = IC_ID_TYPE; i <= IC_STABLE; ++i) {
		if (i == IC_TIME || i == IC_SCAN_TIME)
			continue;
		if (!Value::NotDistinctFrom(a[i], b[i]))
			return false;
	}
	return true;
}
static void LoadInventorySnapshot(ClientContext &context, const string &catalog, const vector<OpenFileInfo> &files,
                                  InventorySnapshotMemory &snapshot_memory,
                                  unordered_map<string, InventoryPrevious> &previous) {
	unordered_set<string> wanted;
	for (const auto &file : files) {
		if (wanted.insert(file.path).second)
			snapshot_memory.Add(128 + file.path.size() * 2);
	}
	vector<StorageIndex> ids;
	auto &table = InventoryCatalog(context, catalog, ids);
	auto &transaction = DuckTransaction::Get(context, table.catalog);
	auto &storage = table.GetStorage();
	TableScanState scan;
	storage.InitializeScan(context, transaction, scan, ids);
	vector<LogicalType> types;
	vector<string> names;
	InventorySchema(types, names);
	DataChunk chunk;
	chunk.Initialize(context, types);
	while (true) {
		if (context.IsInterrupted())
			throw InterruptException();
		chunk.Reset();
		storage.Scan(transaction, chunk, scan);
		if (!chunk.size())
			break;
		for (idx_t n = 0; n < chunk.size(); ++n) {
			auto file = chunk.GetValue(IC_FILE, n);
			if (file.IsNull() || !wanted.count(file.GetValue<string>()))
				continue;
			vector<Value> values;
			idx_t bytes = 512 + file.GetValue<string>().size() * 2;
			for (idx_t c = 0; c < IC_COUNT; ++c) {
				auto value = chunk.GetValue(c, n);
				bytes += sizeof(Value) * 2;
				if (!value.IsNull() && value.type().id() == LogicalTypeId::VARCHAR)
					bytes += StringValue::Get(value).size() * 2;
				if (!value.IsNull() && c == IC_LINKS)
					bytes += ListValue::GetChildren(value).size() * sizeof(Value) * 2;
				values.push_back(std::move(value));
			}
			auto found = previous.find(file.GetValue<string>());
			if (found == previous.end()) {
				snapshot_memory.Add(bytes);
				InventoryPrevious entry;
				entry.row = std::move(values);
				previous.emplace(file.GetValue<string>(), std::move(entry));
			} else if (!InventoryAgreement(found->second.row, values))
				found->second.conflict = true;
		}
	}
}
struct InventoryGlobalState : public CaptureGlobalState {
	InventoryGlobalState(ClientContext &context, const InventoryBindData &bind)
	    : files(InventoryFiles(context, bind)), scheduler(files.size()), snapshot_memory(context) {
		options.inventory_scan = true;
		options.decode_depth =
		    bind.protocols ? packetquapture::DecodeDepth::TRANSPORT : packetquapture::DecodeDepth::NONE;
		budget =
		    context.registered_state->GetOrCreate<InventoryQueryBudget>("packetquapture_inventory_budget", context);
		bind.plan->sealed.store(true);
		max_workers = MinValue<idx_t>(MaxValue<idx_t>(1, files.size()),
		                              MaxValue<idx_t>(1, budget->Slots() / bind.plan->scans.load()));
		if (!files.empty()) {
			initial = make_uniq<InventoryReservation>(budget);
			if (!initial->Acquired())
				throw OutOfMemoryException("PacketQuapture cannot reserve 32 MiB for an inventory worker; increase "
				                           "packetquapture_inventory_memory_mb or memory_limit");
		}
		if (!bind.previous.empty() && !files.empty())
			LoadInventorySnapshot(context, bind.previous, files, snapshot_memory, previous);
		progress.Initialize(context, files, true);
	}
	idx_t MaxThreads() const override {
		return max_workers;
	}
	unique_ptr<InventoryReservation> Admit() {
		lock_guard<mutex> guard(lock);
		if (admitted >= max_workers)
			return nullptr;
		++admitted;
		if (initial)
			return std::move(initial);
		auto result = make_uniq<InventoryReservation>(budget);
		return result->Acquired() ? std::move(result) : nullptr;
	}
	void Drained() {
		if (drained.fetch_add(1) + 1 == files.size())
			progress.Finish();
	}
	vector<OpenFileInfo> files;
	FileScheduler scheduler;
	InventorySnapshotMemory snapshot_memory;
	unordered_map<string, InventoryPrevious> previous;
	shared_ptr<InventoryQueryBudget> budget;
	unique_ptr<InventoryReservation> initial;
	idx_t max_workers = 1, admitted = 0;
	std::atomic<idx_t> drained {0};
	mutex lock;
	vector<column_t> columns;
	ScanOptions options;
};
struct InventoryLocalState : public LocalTableFunctionState {
	unique_ptr<InventoryReservation> reservation;
	bool initialized = false;
};
static unique_ptr<LocalTableFunctionState> InventoryInitLocal(ExecutionContext &, TableFunctionInitInput &,
                                                              GlobalTableFunctionState *) {
	return make_uniq<InventoryLocalState>();
}
static unique_ptr<GlobalTableFunctionState> InventoryInit(ClientContext &context, TableFunctionInitInput &input) {
	auto result = make_uniq<InventoryGlobalState>(context, input.bind_data->Cast<InventoryBindData>());
	result->columns = input.column_ids;
	return std::move(result);
}
static void InventoryIdentityValues(vector<Value> &row, const CaptureIdentity &identity) {
	row[IC_ID_TYPE] = Value(identity.backend);
	string encoded;
	const char *hex = "0123456789abcdef";
	for (unsigned char byte : identity.tag) {
		encoded.push_back(hex[byte >> 4]);
		encoded.push_back(hex[byte & 15]);
	}
	row[IC_ID] = identity.tag.empty() ? Value(LogicalType::VARCHAR) : Value(encoded);
	row[IC_STRENGTH] = Value(identity.Known() ? "weak" : "unavailable");
	row[IC_SIZE] = identity.size < 0 ? Value(LogicalType::UBIGINT) : Value::UBIGINT(identity.size);
	row[IC_MTIME] =
	    Timestamp::IsFinite(identity.modified) ? Value::TIMESTAMP(identity.modified) : Value(LogicalType::TIMESTAMP);
}
static bool InventoryValidPrevious(const vector<Value> &row, bool protocols) {
	auto equal = [&](idx_t col, Value value) {
		return Value::NotDistinctFrom(row[col], value);
	};
	if (!equal(IC_SCHEMA, Value::UINTEGER(1)) || !equal(IC_SEMANTICS, Value::UINTEGER(1)) ||
	    !equal(IC_STATUS, Value("complete")) || !equal(IC_STABLE, Value(true)) || !row[IC_ERROR].IsNull())
		return false;
	if (!equal(IC_DETAIL, Value("protocols")) && (protocols || !equal(IC_DETAIL, Value("framing"))))
		return false;
	if (!equal(IC_FORMAT, Value("pcap")) && !equal(IC_FORMAT, Value("pcapng")))
		return false;
	for (idx_t col : {IC_PACKETS, IC_NULLS, IC_CAPTURED, IC_REPORTED, IC_LINKS})
		if (row[col].IsNull())
			return false;
	auto packets = row[IC_PACKETS].GetValue<uint64_t>(), nulls = row[IC_NULLS].GetValue<uint64_t>();
	if (nulls > packets || row[IC_MIN].IsNull() != row[IC_MAX].IsNull() || row[IC_MIN].IsNull() != (nulls == packets))
		return false;
	if (row[IC_SCAN_TIME].IsNull() || !Timestamp::IsFinite(row[IC_SCAN_TIME].GetValue<timestamp_t>()))
		return false;
	if (!row[IC_MIN].IsNull() && (!Timestamp::IsFinite(row[IC_MIN].GetValue<timestamp_t>()) ||
	                              !Timestamp::IsFinite(row[IC_MAX].GetValue<timestamp_t>()) ||
	                              row[IC_MIN].GetValue<timestamp_t>() > row[IC_MAX].GetValue<timestamp_t>()))
		return false;
	const auto &links = ListValue::GetChildren(row[IC_LINKS]);
	if ((packets && links.empty()) || links.size() > 65536)
		return false;
	uint32_t last = 0;
	bool first = true;
	for (const auto &link : links) {
		if (link.IsNull())
			return false;
		auto value = link.GetValue<uint32_t>();
		if (!first && value <= last)
			return false;
		first = false;
		last = value;
	}
	if (equal(IC_DETAIL, Value("protocols"))) {
		for (idx_t col = IC_IPV4; col <= IC_FRAGMENTS; ++col)
			if (row[col].IsNull() || row[col].GetValue<uint64_t>() > packets)
				return false;
		auto remaining = packets;
		for (idx_t col : {IC_TCP, IC_UDP, IC_MALFORMED, IC_UNSUPPORTED, IC_FRAGMENTS}) {
			auto count = row[col].GetValue<uint64_t>();
			if (count > remaining)
				return false;
			remaining -= count;
		}
		if (remaining || row[IC_OTHER].GetValue<uint64_t>() > row[IC_UNSUPPORTED].GetValue<uint64_t>())
			return false;
	}
	return true;
}
// Accept only the static scalar timestamp filters whose statistics semantics we
// have tested. Unknown/dynamic/expression filters remain ordinary row filters.
static bool CatalogTimestampFilter(const TableFilter &filter) {
	switch (filter.filter_type) {
	case TableFilterType::IS_NULL:
	case TableFilterType::IS_NOT_NULL:
		return true;
	case TableFilterType::CONSTANT_COMPARISON: {
		auto &constant = filter.Cast<ConstantFilter>();
		return constant.constant.type() == LogicalType::TIMESTAMP;
	}
	case TableFilterType::CONJUNCTION_AND:
	case TableFilterType::CONJUNCTION_OR: {
		auto &conjunction = static_cast<const ConjunctionFilter &>(filter);
		if (conjunction.child_filters.empty())
			return false;
		for (auto &child : conjunction.child_filters)
			if (!CatalogTimestampFilter(*child))
				return false;
		return true;
	}
	default:
		return false;
	}
}
static vector<idx_t> SelectCatalogFiles(ClientContext &context, const PcapBindData &bind, TableFunctionInitInput &input,
                                        map<string, idx_t> &reasons) {
	if (bind.catalog.empty() || bind.selected_indices.empty())
		return bind.selected_indices;
	// Re-resolve the table in the execution's transaction, even in strict mode.
	vector<StorageIndex> ids;
	InventoryCatalog(context, bind.catalog, ids);
	const TableFilter *time_filter = nullptr;
	if (input.filters) {
		for (auto &entry : input.filters->filters)
			if (input.column_ids[entry.first] == 2 && CatalogTimestampFilter(*entry.second))
				time_filter = entry.second.get();
	}
	if (!bind.catalog_immutable || !time_filter) {
		reasons[!bind.catalog_immutable ? "strict requires scan" : "no supported time filter"] =
		    bind.selected_indices.size();
		return bind.selected_indices;
	}
	auto &fs = FileSystem::GetFileSystem(context);
	vector<OpenFileInfo> candidates;
	for (auto index : bind.selected_indices) {
		auto file = bind.files[index];
		if (!FileSystem::IsRemoteFile(file.path))
			file.path = fs.CanonicalizePath(file.path);
		candidates.push_back(std::move(file));
	}
	InventorySnapshotMemory memory(context);
	unordered_map<string, InventoryPrevious> previous;
	LoadInventorySnapshot(context, bind.catalog, candidates, memory, previous);
	vector<idx_t> selected;
	vector<LogicalType> types;
	vector<string> names;
	InventorySchema(types, names);
	for (idx_t n = 0; n < candidates.size(); ++n) {
		if (context.IsInterrupted())
			throw InterruptException();
		auto &file = candidates[n];
		string reason = "no matching summary";
		bool exclude = false;
		auto found = previous.find(file.path);
		if (found != previous.end()) {
			auto &old = found->second;
			reason = old.conflict ? "conflicting summaries" : "incompatible summary";
			if (!old.conflict && InventoryValidPrevious(old.row, false)) {
				reason = "unverified remote backend";
				// Only local and HTTP(S) have measured freshness behavior for this
				// milestone. S3/other backends fall back until provider tests pass.
				bool supported = !FileSystem::IsRemoteFile(file.path) || StringUtil::StartsWith(file.path, "http://") ||
				                 StringUtil::StartsWith(file.path, "https://");
				if (supported && FileSystem::IsRemoteFile(file.path)) {
					Value cached;
					if (context.TryGetCurrentSetting("enable_http_metadata_cache", cached) &&
					    (cached.IsNull() || cached.GetValue<bool>())) {
						supported = false;
						reason = "metadata cache enabled";
					}
					if (file.path.find('?') != string::npos || file.path.find('#') != string::npos ||
					    file.path.find('@') != string::npos) {
						supported = false;
						reason = "unstable remote locator";
					}
				}
				if (supported) {
					if (fs.IsPipe(file.path))
						throw InvalidInputException("Catalog validation requires seekable capture files");
					auto handle = fs.OpenFile(file, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
					if (!handle->CanSeek() || handle->IsPipe())
						throw InvalidInputException("Catalog validation requires seekable capture files");
					auto identity = ReadCaptureIdentity(fs, *handle);
					vector<Value> current;
					for (auto &type : types)
						current.emplace_back(type);
					InventoryIdentityValues(current, identity);
					bool match = identity.Known();
					for (idx_t col = IC_ID_TYPE; col <= IC_MTIME; ++col)
						match &= Value::NotDistinctFrom(current[col], old.row[col]);
					reason = "identity mismatch or unavailable";
					if (match) {
						auto stats = NumericStats::CreateUnknown(LogicalType::TIMESTAMP);
						auto packets = old.row[IC_PACKETS].GetValue<uint64_t>();
						auto nulls = old.row[IC_NULLS].GetValue<uint64_t>();
						stats.Set(nulls ? StatsInfo::CAN_HAVE_NULL_VALUES : StatsInfo::CANNOT_HAVE_NULL_VALUES);
						stats.Set(packets > nulls ? StatsInfo::CAN_HAVE_VALID_VALUES
						                          : StatsInfo::CANNOT_HAVE_VALID_VALUES);
						if (packets > nulls) {
							NumericStats::SetMin(stats, old.row[IC_MIN]);
							NumericStats::SetMax(stats, old.row[IC_MAX]);
						}
						exclude = packets == 0 ||
						          time_filter->CheckStatistics(stats) == FilterPropagateResult::FILTER_ALWAYS_FALSE;
						reason = exclude ? "time excluded" : "time may match";
					}
				}
			}
		}
		++reasons[reason];
		if (!exclude)
			selected.push_back(bind.selected_indices[n]);
	}
	return selected;
}
static InsertionOrderPreservingMap<string> CatalogDynamicToString(TableFunctionDynamicToStringInput &input) {
	InsertionOrderPreservingMap<string> result;
	if (!input.global_state || input.bind_data->Cast<PcapBindData>().catalog.empty())
		return result;
	auto &global = input.global_state->Cast<PcapGlobalState>();
	result["Runtime Selected Files"] = StringUtil::Format("%llu", global.selected_indices.size());
	for (auto &reason : global.catalog_reasons)
		result["Catalog: " + reason.first] = StringUtil::Format("%llu", reason.second);
	return result;
}
static void AddCatalogOptions(TableFunction &function) {
	function.named_parameters["catalog"] = LogicalType::VARCHAR;
	function.named_parameters["catalog_validation"] = LogicalType::VARCHAR;
	function.dynamic_to_string = CatalogDynamicToString;
}

static vector<Value> InventoryOne(ClientContext &context, const InventoryBindData &bind, InventoryGlobalState &global,
                                  idx_t index) {
	vector<LogicalType> types;
	vector<string> names;
	InventorySchema(types, names);
	vector<Value> row;
	for (const auto &type : types)
		row.emplace_back(type);
	const auto &file = global.files[index];
	row[IC_FILE] = Value(file.path);
	row[IC_INPUT] = Value::UBIGINT(index + 1);
	row[IC_DETAIL] = Value(bind.protocols ? "protocols" : "framing");
	row[IC_TIME] = Value::TIMESTAMP(Timestamp::GetCurrentTimestamp());
	row[IC_SCAN_TIME] = row[IC_TIME];
	row[IC_SCHEMA] = Value::UINTEGER(1);
	row[IC_SEMANTICS] = Value::UINTEGER(1);
	row[IC_REUSED] = Value(false);
	row[IC_VALIDATION] = Value(bind.immutable ? "immutable" : "strict");
	row[IC_REASON] = Value(bind.previous.empty() ? "no_previous_catalog" : "no_matching_summary");
	auto &fs = FileSystem::GetFileSystem(context);
	if (FileSystem::IsRemoteFile(file.path)) {
		Value metadata_cache;
		if (context.TryGetCurrentSetting("enable_http_metadata_cache", metadata_cache) &&
		    (metadata_cache.IsNull() || metadata_cache.GetValue<bool>())) {
			throw InvalidInputException(
			    "Remote capture_inventory requires enable_http_metadata_cache=false for fresh metadata validation");
		}
	}
	bool changed = false;
	try {
		if (fs.IsPipe(file.path))
			throw InvalidInputException("Inventory does not support named pipes");
		auto probe = fs.OpenFile(file, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
		if (!probe->CanSeek() || probe->IsPipe())
			throw InvalidInputException("Inventory requires seekable capture files");
		auto identity = ReadCaptureIdentity(fs, *probe);
		InventoryIdentityValues(row, identity);
		auto found = global.previous.find(file.path);
		if (found != global.previous.end()) {
			const auto &old = found->second;
			row[IC_REASON] = Value(!bind.immutable ? "strict_requires_scan"
			                       : old.conflict  ? "conflicting_summaries"
			                                       : "incompatible_summary");
			if (bind.immutable && !old.conflict && InventoryValidPrevious(old.row, bind.protocols)) {
				bool match = identity.Known();
				for (idx_t col = IC_ID_TYPE; col <= IC_MTIME; ++col)
					match &= Value::NotDistinctFrom(row[col], old.row[col]);
				if (match) {
					for (idx_t col = IC_FORMAT; col <= IC_FRAGMENTS; ++col)
						row[col] = old.row[col];
					row[IC_DETAIL] = Value(bind.protocols ? "protocols" : "framing");
					if (!bind.protocols)
						for (idx_t col = IC_IPV4; col <= IC_FRAGMENTS; ++col)
							row[col] = Value(LogicalType::UBIGINT);
					row[IC_STATUS] = Value("complete");
					row[IC_STABLE] = Value(true);
					row[IC_REUSED] = Value(true);
					row[IC_SCAN_TIME] = old.row[IC_SCAN_TIME];
					row[IC_REASON] = Value("immutable_metadata_match");
					global.progress.CheckSize(index, true, identity.size < 0 ? 0 : identity.size);
					if (identity.size >= 0)
						global.progress.Advance(identity.size);
					global.progress.CompleteFile();
					return row;
				}
				row[IC_REASON] = Value("identity_changed_or_unavailable");
			}
		}
		probe.reset();
		CaptureReader reader(context, file, global.options, &global.progress, index);
		auto before = reader.InventoryBefore();
		InventoryIdentityValues(row, before);
		InventoryTotals totals;
		PacketRecord record;
		while (reader.Next(record)) {
			if (context.IsInterrupted())
				throw InterruptException();
			totals.Observe(record.has_timestamp, record.timestamp, record.captured_length, record.original_length,
			               record.decoded, bind.protocols);
		}
		auto after = reader.InventoryAfter();
		auto verify = fs.OpenFile(file, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
		auto current = ReadCaptureIdentity(fs, *verify);
		changed = !identity.Same(before) || !before.Same(after) || !after.Same(current);
		if (changed)
			throw InvalidInputException("Capture identity changed during inventory");
		row[IC_FORMAT] = Value(reader.InventoryFormat());
		vector<Value> links;
		for (auto link : reader.InventoryLinks())
			links.push_back(Value::UINTEGER(link));
		row[IC_LINKS] = Value::LIST(LogicalType::UINTEGER, links);
		row[IC_PACKETS] = Value::UBIGINT(totals.packets);
		row[IC_NULLS] = Value::UBIGINT(totals.null_timestamps);
		row[IC_CAPTURED] = Value::UBIGINT(totals.captured);
		row[IC_REPORTED] = Value::UBIGINT(totals.reported);
		if (totals.timed) {
			row[IC_MIN] = Value::TIMESTAMP(totals.minimum);
			row[IC_MAX] = Value::TIMESTAMP(totals.maximum);
		}
		if (bind.protocols) {
			const uint64_t counts[] = {totals.ipv4,  totals.ipv6,      totals.tcp,         totals.udp,
			                           totals.other, totals.malformed, totals.unsupported, totals.fragments};
			for (idx_t i = 0; i < 8; ++i)
				row[IC_IPV4 + i] = Value::UBIGINT(counts[i]);
		}
		row[IC_STATUS] = Value(reader.SawTruncatedTail() ? "truncated" : "complete");
		row[IC_STABLE] = before.Known() ? Value(true) : Value(LogicalType::BOOLEAN);
	} catch (const std::exception &exception) {
		ErrorData error(exception);
		if (!bind.report || error.Type() == ExceptionType::INTERRUPT || error.Type() == ExceptionType::OUT_OF_MEMORY)
			throw;
		for (idx_t col = IC_FORMAT; col <= IC_FRAGMENTS; ++col)
			if (col != IC_DETAIL)
				row[col] = Value(types[col]);
		row[IC_STATUS] = Value(changed ? "changed" : "error");
		row[IC_ERROR] = Value(FileSystem::IsRemoteFile(file.path)
		                          ? "Remote inventory scan failed; rerun with on_error=error for provider details"
		                          : error.Message());
		row[IC_SCAN_TIME] = Value(LogicalType::TIMESTAMP);
		row[IC_STABLE] = Value(false);
	}
	return row;
}
static void InventoryScan(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
	auto &bind = input.bind_data->Cast<InventoryBindData>();
	auto &global = input.global_state->Cast<InventoryGlobalState>();
	auto &local = input.local_state->Cast<InventoryLocalState>();
	if (!local.initialized) {
		local.initialized = true;
		if (!global.files.empty())
			local.reservation = global.Admit();
	}
	if (!local.reservation)
		return;
	idx_t index;
	if (!global.scheduler.Claim(index)) {
		local.reservation.reset();
		return;
	}
	if (context.IsInterrupted())
		throw InterruptException();
	auto row = InventoryOne(context, bind, global, index);
	for (idx_t c = 0; c < global.columns.size(); ++c)
		output.data[c].SetValue(0, row[global.columns[c]]);
	output.SetCardinality(1);
	global.Drained();
}

static TableFunction ReadPcapFunction() {
	TableFunction function("read_pcap", {LogicalType::VARCHAR}, PcapScan, BindCapture<PcapBind>, PcapInit,
	                       PcapInitLocal);
	function.projection_pushdown = true;
	function.table_scan_progress = CaptureScanProgress;
	function.filter_pushdown = true;
	function.filter_prune = true;
	function.supports_pushdown_type = SupportsPacketFilter;
	function.pushdown_complex_filter = NormalizePacketFilters;
	AddCaptureOptions(function);
	AddCatalogOptions(function);
	return function;
}

static void LoadInternal(ExtensionLoader &loader) {
	RegisterPcapCopy(loader);
	loader.SetDescription("Query PCAP and PCAPNG packet captures directly from DuckDB");
	DBConfig::GetConfig(loader.GetDatabaseInstance())
	    .AddExtensionOption("packetquapture_stream_memory_mb",
	                        "Query-wide stream-worker admission budget in MiB, capped at half memory_limit",
	                        LogicalType::UBIGINT, Value::UBIGINT(512));
	DBConfig::GetConfig(loader.GetDatabaseInstance())
	    .AddExtensionOption("packetquapture_flow_memory_mb",
	                        "Query-wide flow-worker budget in MiB, capped at half memory_limit", LogicalType::UBIGINT,
	                        Value::UBIGINT(192));
	TableFunction flows("read_flows", {LogicalType::VARCHAR}, FlowsScan, BindCapture<FlowsBind>, FlowsInit,
	                    FlowsInitLocal);
	flows.projection_pushdown = true;
	flows.table_scan_progress = CaptureScanProgress;
	flows.pushdown_complex_filter = PruneCaptureFiles;
	AddCaptureOptions(flows);
	flows.named_parameters["tcp_idle_timeout"] = LogicalType::INTERVAL;
	flows.named_parameters["udp_idle_timeout"] = LogicalType::INTERVAL;
	flows.named_parameters["max_active_flows"] = LogicalType::UBIGINT;
	loader.RegisterFunction(MultiFileReader::CreateFunctionSet(flows));
	DBConfig::GetConfig(loader.GetDatabaseInstance())
	    .AddExtensionOption("packetquapture_inventory_memory_mb",
	                        "Query-wide inventory-worker budget in MiB, capped at half memory_limit",
	                        LogicalType::UBIGINT, Value::UBIGINT(128));
	TableFunction inventory("capture_inventory", {LogicalType::VARCHAR}, InventoryScan, InventoryBind, InventoryInit,
	                        InventoryInitLocal);
	inventory.projection_pushdown = true;
	inventory.table_scan_progress = CaptureScanProgress;
	for (const auto *option : {"detail", "on_error", "previous_catalog", "catalog_validation"})
		inventory.named_parameters[option] = LogicalType::VARCHAR;
	loader.RegisterFunction(MultiFileReader::CreateFunctionSet(inventory));
	loader.RegisterFunction(MultiFileReader::CreateFunctionSet(ReadPcapFunction()));
	TableFunction packets("read_packets", {LogicalType::VARCHAR}, PcapScan, BindCapture<PacketsBind>, PcapInit,
	                      PcapInitLocal);
	packets.projection_pushdown = true;
	packets.table_scan_progress = CaptureScanProgress;
	packets.filter_pushdown = true;
	packets.filter_prune = true;
	packets.supports_pushdown_type = SupportsPacketFilter;
	packets.pushdown_complex_filter = NormalizePacketFilters;
	AddCaptureOptions(packets);
	AddCatalogOptions(packets);
	loader.RegisterFunction(MultiFileReader::CreateFunctionSet(packets));
	TableFunction dns("read_dns", {LogicalType::VARCHAR}, PcapScan, BindCapture<DnsBind>, PcapInit, PcapInitLocal);
	dns.projection_pushdown = true;
	dns.table_scan_progress = CaptureScanProgress;
	dns.filter_pushdown = true;
	dns.filter_prune = true;
	dns.supports_pushdown_type = SupportsPacketFilter;
	dns.pushdown_complex_filter = NormalizePacketFilters;
	AddCaptureOptions(dns);
	AddCatalogOptions(dns);
	loader.RegisterFunction(MultiFileReader::CreateFunctionSet(dns));
	TableFunction messages("read_dns_messages", {LogicalType::VARCHAR}, DnsMessagesScan, BindCapture<DnsMessagesBind>,
	                       DnsMessagesInit, StreamInitLocal);
	messages.projection_pushdown = true;
	messages.table_scan_progress = CaptureScanProgress;
	messages.pushdown_complex_filter = PruneCaptureFiles;
	AddCaptureOptions(messages);
	// Segment-level predicates could remove bytes required to reconstruct a matching message.
	loader.RegisterFunction(MultiFileReader::CreateFunctionSet(messages));
	TableFunction tls("read_tls", {LogicalType::VARCHAR}, TlsScan, BindCapture<TlsBind>, TlsInit, StreamInitLocal);
	tls.projection_pushdown = true;
	tls.table_scan_progress = CaptureScanProgress;
	// File-level pruning only: a segment-level predicate could remove bytes needed
	// to reconstruct a handshake that would have matched it.
	tls.pushdown_complex_filter = PruneCaptureFiles;
	AddCaptureOptions(tls);
	loader.RegisterFunction(MultiFileReader::CreateFunctionSet(tls));
	TableFunction streams("read_tcp_streams", {LogicalType::VARCHAR}, TcpStreamsScan, BindCapture<TcpStreamsBind>,
	                      TcpStreamsInit, StreamInitLocal);
	streams.projection_pushdown = true;
	streams.table_scan_progress = CaptureScanProgress;
	streams.pushdown_complex_filter = PruneCaptureFiles;
	AddCaptureOptions(streams);
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
