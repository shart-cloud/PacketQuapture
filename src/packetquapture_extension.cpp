#define DUCKDB_EXTENSION_MAIN

#include "packetquapture_extension.hpp"
#include "pcap_copy.hpp"
#include "capture_progress.hpp"
#include "scan_budget.hpp"
#include "flow_aggregator.hpp"
#include "capture_inventory.hpp"
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
#include "dns_analytics.hpp"
#include "sparse_readahead.hpp"
#include "traffic_analytics.hpp"
#include "pq_assert.hpp"
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
// Skipped gaps up to this size leave headers close enough that reading the whole
// file sequentially beats a disk read per header on a cold cache (measured: a
// 200,000-byte gap halves), so the kernel is asked to read ahead through them.
// Wider gaps are left to seek.
constexpr idx_t LOCAL_READAHEAD_MAX_GAP = 256ULL * 1024ULL;
constexpr idx_t MAX_CAPTURED_PACKET_SIZE = 256ULL * 1024ULL * 1024ULL;
// Packet bytes are read in steps no larger than this, so a header that lies
// about its length costs at most one step before the read hits end of file.
constexpr idx_t PACKET_READ_STEP = 1024ULL * 1024ULL;
// Interfaces per PCAPNG section. Real captures have a handful; each one costs
// memory for the rest of the section, so a file cannot add them without bound.
constexpr idx_t MAX_PCAPNG_INTERFACES = 65536;
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
// Stream and flow scans end an output batch once its estimated size passes a
// limit, so one batch of large rows cannot exhaust memory. The estimates are
// deliberately conservative, not measured: a fixed share per row for its scalar
// columns and vector overhead, plus each variable-size field.
static const idx_t ROW_BASE_BYTES = 1024;
// One list element: its list entry, validity bit and value.
static const idx_t LIST_ENTRY_BYTES = 32;
// Payload bytes are charged several times over: the row's own copy, the copies
// a batch keeps while it is built, and string headers.
static const idx_t PAYLOAD_COPIES = 4;
// A decoded DNS resource record: its name, text form, raw data and struct.
static const idx_t DNS_RECORD_BYTES = 4096;
// A certificate struct's fixed fields, before its text.
static const idx_t CERTIFICATE_BASE_BYTES = 512;
// read_packets column groups, in schema order; PacketsBind checks them against the names.
static const column_t NETWORK_COLUMNS_BEGIN = 15;
static const column_t TRANSPORT_COLUMNS_BEGIN = 23;
static const column_t TCP_FLAG_COLUMNS_BEGIN = 32;
static const column_t TLS_COLUMN_BEGIN = 40;
static const column_t TLS_COLUMN_COUNT = 6;
static const column_t DNS_COLUMN_BEGIN = TLS_COLUMN_BEGIN + TLS_COLUMN_COUNT;
static const column_t DNS_COLUMN_COUNT = 14;
// read_dns_messages keeps the same dns_* columns but puts them after its own
// per-message columns, so it remaps into the block above.
static const column_t MESSAGE_DNS_COLUMN_BEGIN = 20;
static const column_t MESSAGE_DNS_COLUMN_END = MESSAGE_DNS_COLUMN_BEGIN + DNS_COLUMN_COUNT;

class PacketFilter;

struct ScanOptions {
	bool materialize_packet_data = false;
	bool flow_scan = false;
	bool inventory_scan = false;
	bool dns_scan = false, decode_dns = false;
	bool decode_tls = false;
	bool reassemble_dns = false, reassemble_tcp = false;
	packetquapture::DecodeDepth decode_depth = packetquapture::DecodeDepth::NONE;
	std::array<bool, STAGE_COUNT> filter_stages {};
	// The pushed-down filters of the scanning thread, set where filter_stages has
	// any stage; owned by that thread's local state.
	vector<unique_ptr<PacketFilter>> *filters = nullptr;
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
		return executor->SelectExpression(input, selected) == 1;
	}
	column_t column;
	unsigned stage;

private:
	unique_ptr<Expression> expression;
	unique_ptr<ExpressionExecutor> executor;
	DataChunk input;
	SelectionVector selected {1}; // one row per call, allocated once
};

// Whether a record passes every filter that applies at stage.
static bool FiltersMatch(vector<unique_ptr<PacketFilter>> *filters, const PacketRecord &record, unsigned stage) {
	PQ_ASSERT(filters != nullptr); // a filtered stage implies installed filters
	for (auto &filter : *filters) {
		if (filter->stage == stage && !filter->Matches(record)) {
			return false;
		}
	}
	return true;
}

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
		} catch (const packetquapture::AssertionFailure &) {
			// A bug, not a capture error: it keeps its own message and type so no
			// handler further up mistakes it for a bad file.
			throw;
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
		PQ_ASSERT(within_window < window_length);
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
		PQ_ASSERT(within_window < local_length);
		PQ_ASSERT(local_length <= LOCAL_READ_WINDOW_SIZE);
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

		ResetRecord(record);
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

	// Each pass consumes a block of at least 12 bytes (a section header 28) or
	// returns, so the loop is bounded by the file's size over 12.
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
		// Bound interface metadata independently of capture size, for every scan: a
		// file of nothing but interface blocks would otherwise grow this list by one
		// entry per 20 bytes. No real capture comes near the cap.
		if (interfaces.size() >= MAX_PCAPNG_INTERFACES) {
			throw InvalidInputException("Capture exceeds %d PCAPNG interfaces per section in '%s'",
			                            MAX_PCAPNG_INTERFACES, file.path);
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

		ResetRecord(record);
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
		// A simple packet block records no captured length: it is the original
		// length cut to the interface's snap length, where 0 means no limit.
		const auto snap_length = interfaces[0].snap_length == 0 ? original_length : interfaces[0].snap_length;
		const auto captured_length = static_cast<uint32_t>(MinValue<idx_t>(original_length, snap_length));
		ValidatePacketLength(captured_length);
		if (AlignTo32Bits(captured_length) > available) {
			throw InvalidInputException("Truncated PCAPNG simple packet in '%s'", file.path);
		}

		ResetRecord(record);
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

	// Clears a record for the next packet but keeps its buffers' capacity: one
	// record is reused for a whole scan, so a packet costs no allocation once
	// the buffers have grown to the capture's largest packet.
	static void ResetRecord(PacketRecord &record) {
		record.filename.clear();
		record.packet_data.clear();
		record.transport_data.clear();
		record.packet_number = 0;
		record.has_timestamp = false;
		record.timestamp = timestamp_t();
		record.captured_length = record.original_length = record.link_type = record.interface_id = 0;
		record.packet_offset = 0;
		record.format = CaptureFormat::PCAP;
		record.section_number = 0;
		record.decoded = packetquapture::DecodedPacket();
		record.dns = packetquapture::DnsMessage();
		record.tls = packetquapture::TlsRecord();
		record.selected = true;
	}

	// The bytes of one packet record, read only as far as some consumer asks.
	class PacketPrefix : public packetquapture::PacketSource {
	public:
		PacketPrefix(CaptureReader &reader_p, idx_t length_p, vector<uint8_t> &bytes_p)
		    : reader(reader_p), length(length_p), bytes(bytes_p) {
			bytes.clear();
		}
		size_t Size() const override {
			return length;
		}
		// Grows in steps of at most PACKET_READ_STEP, so on a stream whose size
		// is unknown a header claiming a huge packet costs one step of memory
		// past the end of the file, not the whole claimed length.
		const uint8_t *ReadPrefix(size_t requested) override {
			PQ_ASSERT(requested <= length);
			while (bytes.size() < requested) {
				const auto previous = bytes.size();
				const auto step = MinValue<idx_t>(requested - previous, PACKET_READ_STEP);
				bytes.resize(previous + step);
				reader.ReadExact(bytes.data() + previous, step, "packet header");
			}
			return bytes.data();
		}
		// The rest of the record, after whatever the decoders read.
		idx_t Unread() const {
			PQ_ASSERT(bytes.size() <= length);
			return length - bytes.size();
		}
		const vector<uint8_t> &Bytes() const {
			return bytes;
		}

	private:
		CaptureReader &reader;
		idx_t length;
		vector<uint8_t> &bytes;
	};

	// Whether the record passes the filters pushed down to stage; one that fails
	// is deselected, and the caller skips the rest of its bytes.
	bool Accept(PacketRecord &record, unsigned stage) const {
		if (options.filter_stages[stage] && !FiltersMatch(options.filters, record, stage)) {
			record.selected = false;
			return false;
		}
		return true;
	}

	// read_dns parses one message per packet. Over TCP that is the RFC 1035 4.2.2
	// framing with exactly one whole message in the segment; reassembled
	// messages are read_dns_messages' job.
	static void DecodeDnsPayload(PacketRecord &record, const uint8_t *bytes) {
		const auto &packet = record.decoded;
		const auto *message = bytes + packet.payload_offset;
		auto message_length = packet.payload_length;
		if (packet.tcp) {
			if (message_length < 2 || ReadU16(message, ByteOrder::BIG) != message_length - 2) {
				record.dns.error = "TCP DNS requires exactly one complete length-prefixed message per packet";
				return;
			}
			message += 2;
			message_length -= 2;
		} else if (message_length != packet.udp_length - 8U) {
			record.dns.error = "truncated UDP DNS payload";
			return;
		}
		record.dns = packetquapture::DecodeDns(message, message_length);
	}

	// Reads the stages a scan needs, stopping at the first filter that rejects the
	// packet, so a filtered scan reads and decodes no more than the filter needs.
	// Each filtered decode depth decodes again from the link layer: the decoder
	// keeps no state between depths, and the prefix bytes are already in memory.
	void ReadPacketData(PacketRecord &record, idx_t length) {
		// Checked before any read: a header claiming more bytes than the file has
		// left is a truncated record, reported without first allocating for it.
		RequireAvailable(length, "packet data");
		PacketPrefix source(*this, length, packet_prefix);
		if (!Accept(record, STAGE_PACKET)) {
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
			if (!Accept(record, stage)) {
				Skip(source.Unread(), "packet data");
				return;
			}
		}
		const auto &packet = record.decoded;
		if (options.reassemble_dns || options.reassemble_tcp) {
			// TCP reassembly takes every TCP segment; DNS reassembly also takes UDP
			// on port 53, which it passes through as single datagrams.
			if (!packet.transport ||
			    (options.reassemble_tcp ? !packet.tcp : (packet.src_port != 53 && packet.dst_port != 53))) {
				record.selected = false;
			} else if (packet.payload_length > 0) {
				const auto *bytes = source.ReadPrefix(packet.payload_offset + packet.payload_length);
				record.transport_data.assign(bytes + packet.payload_offset,
				                             bytes + packet.payload_offset + packet.payload_length);
			}
			Skip(source.Unread(), "packet data");
			return;
		}
		if (options.dns_scan) {
			if (!packet.transport || (packet.src_port != 53 && packet.dst_port != 53) || packet.payload_length == 0) {
				record.selected = false;
				Skip(source.Unread(), "packet data");
				return;
			}
			if (options.decode_dns) {
				DecodeDnsPayload(record, source.ReadPrefix(packet.payload_offset + packet.payload_length));
			}
			if (!Accept(record, STAGE_DNS)) {
				Skip(source.Unread(), "packet data");
				return;
			}
		}
		if (options.decode_tls) {
			// TLS runs over TCP; DTLS frames differently and is not parsed here.
			if (packet.transport && packet.tcp && packet.payload_length > 0) {
				const auto *bytes = source.ReadPrefix(packet.payload_offset + packet.payload_length);
				record.tls = packetquapture::DecodeTlsRecord(bytes + packet.payload_offset, packet.payload_length);
			}
			if (!Accept(record, STAGE_TLS)) {
				Skip(source.Unread(), "packet data");
				return;
			}
		}
		if (options.materialize_packet_data) {
			source.ReadPrefix(length);
			record.packet_data.assign(source.Bytes().begin(), source.Bytes().end());
			Accept(record, STAGE_PACKET_DATA);
		} else {
			Skip(source.Unread(), "packet data");
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

	// The bound is written as 2^63 rather than converted from INT64_MAX, which
	// rounds up to 2^63 where long double is double and so would let 2^63 through
	// to an undefined cast. INT64_MAX itself is DuckDB's infinity, so the largest
	// finite timestamp is one below it.
	timestamp_t CheckedTimestamp(long double micros) const {
		if (!std::isfinite(micros) || micros >= 9223372036854775808.0L) {
			throw InvalidInputException("Packet timestamp is out of range in '%s'", file.path);
		}
		const auto value = static_cast<int64_t>(micros);
		if (value == NumericLimits<int64_t>::Maximum()) {
			throw InvalidInputException("Packet timestamp is out of range in '%s'", file.path);
		}
		return Timestamp::FromEpochMicroSeconds(value);
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

	// Asks the kernel to read ahead of a sparse local scan. Decided once per
	// file: only a file on disk, and a file system that cannot say so is not
	// treated as one.
	void Readahead(uint64_t next) {
		if (!readahead_checked) {
			readahead_checked = true;
			bool on_disk = false;
			try {
				on_disk = handle->OnDiskFile();
			} catch (const std::exception &) {
				// Readahead is only a hint: a file system that cannot say whether a
				// file is on disk is scanned without it, never failed for it.
				on_disk = false;
			}
			if (on_disk) {
				readahead = make_uniq<packetquapture::SparseReadahead>(handle->GetPath(), seekable_size);
			}
		}
		if (readahead) {
			readahead->Ahead(next);
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

	// On a file whose size is known, a record that claims more bytes than remain
	// is truncated. Ends the scan the way a short read would.
	void RequireAvailable(idx_t length, const char *description) {
		if (can_skip_by_seek && (position > seekable_size || length > seekable_size - position)) {
			EndOfRecord(description);
		}
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
					if (length <= LOCAL_READAHEAD_MAX_GAP) {
						Readahead(position + length);
					}
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

	// Reader state.
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
	unique_ptr<packetquapture::SparseReadahead> readahead;
	bool readahead_checked = false;
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
	// The bytes of the current packet read so far, reused across packets.
	vector<uint8_t> packet_prefix;
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
		PQ_ASSERT(file_index < partition_values.size());
		PQ_ASSERT(column - base_column_count < partition_values[file_index].size());
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
	packetquapture::TcpReassemblyLimits stream_limits;
	bool stream_scan = false;

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
		result->stream_limits = stream_limits;
		result->stream_scan = stream_scan;
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
		    flow_limits.max_flows != other.flow_limits.max_flows || stream_scan != other.stream_scan ||
		    stream_limits.tcp_idle_us != other.stream_limits.tcp_idle_us || files.size() != other.files.size() ||
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
	PacketRecord record; // reused for every packet
};

static idx_t NamedColumn(const vector<string> &names, const char *name) {
	for (idx_t i = 0; i < names.size(); ++i) {
		if (names[i] == name) {
			return i;
		}
	}
	throw InternalException("capture bind has no column named %s", name);
}

constexpr column_t PCAP_TIMESTAMP_COLUMN = 2;

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
	// Every capture reader starts with these columns, and catalog pruning finds
	// the timestamp by position.
	PQ_ASSERT(names[PCAP_TIMESTAMP_COLUMN] == "timestamp");
	result->types = return_types;
	result->AppendStages(STAGE_PACKET, return_types.size());
	result->column_stages[NamedColumn(names, "packet_data")] = STAGE_PACKET_DATA;
	return std::move(result);
}

using ColumnGroup = std::pair<ColumnStage, vector<std::pair<string, LogicalType>>>;

// read_packets' decoded columns, after read_pcap's.
static vector<ColumnGroup> DecodedColumnGroups() {
	// Grouped by the decode stage that produces them, so a column added to a group
	// takes that group's stage and no other column's stage moves.
	return {
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
}

static unique_ptr<FunctionData> PacketsBind(ClientContext &context, TableFunctionBindInput &input,
                                            vector<LogicalType> &return_types, vector<string> &names) {
	auto result = PcapBind(context, input, return_types, names);
	const auto decoded = DecodedColumnGroups();
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
	// The cell writers find column groups by position.
	PQ_ASSERT(names[PACKET_COLUMN_COUNT] == "src_mac");
	PQ_ASSERT(names[NETWORK_COLUMNS_BEGIN] == "ip_version");
	PQ_ASSERT(names[TRANSPORT_COLUMNS_BEGIN] == "src_port");
	PQ_ASSERT(names[TCP_FLAG_COLUMNS_BEGIN] == "tcp_fin");
	for (const auto &column : tls) {
		names.push_back(column.first);
		return_types.push_back(column.second);
	}
	bind.AppendStages(STAGE_TLS, tls.size());
	bind.types = return_types;
	return result;
}

static LogicalType MakeDnsQuestionType() {
	return LogicalType::STRUCT(
	    {{"name", LogicalType::VARCHAR}, {"type", LogicalType::USMALLINT}, {"class", LogicalType::USMALLINT}});
}
// Built once: rows ask for it per cell, and a STRUCT type allocates.
static const LogicalType &DnsQuestionType() {
	static const LogicalType type = MakeDnsQuestionType();
	return type;
}
static LogicalType MakeDnsRecordType() {
	return LogicalType::STRUCT({{"name", LogicalType::VARCHAR},
	                            {"type", LogicalType::USMALLINT},
	                            {"class", LogicalType::USMALLINT},
	                            {"ttl", LogicalType::UINTEGER},
	                            {"value", LogicalType::VARCHAR},
	                            {"data", LogicalType::BLOB}});
}
// Built once: rows ask for it per cell, and a STRUCT type allocates.
static const LogicalType &DnsRecordType() {
	static const LogicalType type = MakeDnsRecordType();
	return type;
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

// Idle timeouts are fixed INTERVALs: a month has no fixed length.
static int64_t IdleTimeoutMicros(const Value &value, const char *what) {
	if (value.IsNull()) {
		throw BinderException("%s idle timeout must not be NULL", what);
	}
	const auto interval = value.GetValue<interval_t>();
	int64_t micros;
	if (interval.months || !Interval::TryGetMicro(interval, micros) || micros < 0) {
		throw BinderException("%s idle timeout must be a nonnegative fixed interval without months", what);
	}
	return micros;
}

// The stream readers share one transport core; tcp_idle_timeout is its only exposed limit.
static void BindStreamOptions(FunctionData &result, const TableFunctionBindInput &input) {
	auto &bind = result.Cast<PcapBindData>();
	bind.stream_scan = true;
	for (auto &entry : input.named_parameters) {
		if (StringUtil::CIEquals(entry.first, "tcp_idle_timeout")) {
			bind.stream_limits.tcp_idle_us = IdleTimeoutMicros(entry.second, "TCP");
		}
	}
}

// Parses the capture options DuckDB passed, other than the ones the bind itself
// owns, into bind and options. Returns whether any Hive type option was given.
static bool BindCaptureOptions(ClientContext &context, TableFunctionBindInput &input, PcapBindData &bind,
                               MultiFileOptions &options) {
	auto reader = MultiFileReader::Create(input.table_function);
	bool has_type_options = false;
	for (auto &entry : input.named_parameters) {
		if (StringUtil::CIEquals(entry.first, "catalog")) {
			if (entry.second.IsNull()) {
				throw BinderException("catalog must not be NULL");
			}
			bind.catalog = BindInventoryCatalog(context, entry.second.GetValue<string>());
			continue;
		}
		if (StringUtil::CIEquals(entry.first, "catalog_validation")) {
			if (entry.second.IsNull()) {
				throw BinderException("catalog_validation must not be NULL");
			}
			auto mode = StringUtil::Lower(entry.second.GetValue<string>());
			if (mode != "strict" && mode != "immutable") {
				throw BinderException("catalog_validation must be strict or immutable");
			}
			bind.catalog_immutable = mode == "immutable";
			continue;
		}
		if (bind.flow_scan && (StringUtil::CIEquals(entry.first, "tcp_idle_timeout") ||
		                       StringUtil::CIEquals(entry.first, "udp_idle_timeout") ||
		                       StringUtil::CIEquals(entry.first, "max_active_flows"))) {
			continue;
		}
		if (bind.stream_scan && StringUtil::CIEquals(entry.first, "tcp_idle_timeout")) {
			continue;
		}
		if (!reader->ParseOption(entry.first, entry.second, options, context)) {
			throw BinderException("Unsupported capture option: %s", entry.first);
		}
		has_type_options |= !StringUtil::CIEquals(entry.first, "hive_partitioning");
	}
	return has_type_options;
}

// Adds a column per Hive partition key, typed and valued per file. Every path
// must carry the same keys.
static void BindHivePartitions(ClientContext &context, PcapBindData &bind, MultiFileOptions &options,
                               vector<LogicalType> &types, vector<string> &names) {
	PQ_ASSERT(!bind.files.empty());
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
	// Each path is parsed once; the typing pass below reuses the result.
	vector<std::map<string, string>> parsed;
	parsed.reserve(bind.files.size());
	for (auto &file : bind.files) {
		if (context.IsInterrupted()) {
			throw InterruptException();
		}
		parsed.push_back(HivePartitioning::Parse(file.path));
		const auto &values = parsed.back();
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
	PQ_ASSERT(parsed.size() == bind.files.size());
	for (const auto &values : parsed) {
		if (context.IsInterrupted()) {
			throw InterruptException();
		}
		vector<Value> typed_values;
		for (auto &key : bind.partition_keys) {
			typed_values.push_back(options.GetHivePartitionValue(values.at(key), key, context));
		}
		bind.partition_values.push_back(std::move(typed_values));
	}
	bind.types = types;
}

template <table_function_bind_t BIND>
static unique_ptr<FunctionData> BindCapture(ClientContext &context, TableFunctionBindInput &input,
                                            vector<LogicalType> &types, vector<string> &names) {
	auto result = BIND(context, input, types, names);
	// Every bind pairs its column names and types by position.
	PQ_ASSERT(names.size() == types.size());
	auto &bind = result->Cast<PcapBindData>();
	bind.base_column_count = types.size();
	for (idx_t i = 0; i < bind.files.size(); ++i) {
		bind.selected_indices.push_back(i);
	}
	MultiFileOptions options;
	options.auto_detect_hive_partitioning = false;
	options.hive_types_autocast = false;
	const bool has_type_options = BindCaptureOptions(context, input, bind, options);
	if (bind.catalog.empty() && input.named_parameters.count("catalog_validation")) {
		throw BinderException("catalog_validation requires catalog");
	}
	if (has_type_options && !options.hive_partitioning) {
		throw BinderException("Capture partition type options require hive_partitioning=true");
	}
	bind.hive_partitioning = options.hive_partitioning;
	if (!options.hive_partitioning || bind.files.empty()) {
		return result;
	}
	BindHivePartitions(context, bind, options, types, names);
	return result;
}

static bool SupportsPacketFilter(const FunctionData &data, idx_t column) {
	const auto &bind = data.Cast<PcapBindData>();
	return column < bind.base_column_count && bind.types[column].id() != LogicalTypeId::LIST;
}

// The decode depth and extra stages a scan needs, from the columns it reads,
// including filter-only columns.
static void PlanDecodeStages(const PcapBindData &bind, const vector<column_t> &column_ids, ScanOptions &options) {
	// Filter-only packet columns still determine the required decode depth.
	for (const auto column : column_ids) {
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
}

// Pushes the packet-column filters a scan can evaluate itself, so packets that
// fail them are skipped as early in decoding as possible.
static void PushPacketFilters(const PcapBindData &bind, TableFunctionInitInput &input, PcapGlobalState &global) {
	auto &options = global.options;
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
			global.filters.push_back({column, filter.Copy()});
			options.filter_stages[bind.StageOf(column)] = true;
		}
	}
}

static unique_ptr<GlobalTableFunctionState> PcapInit(ClientContext &context, TableFunctionInitInput &input) {
	auto &bind = input.bind_data->Cast<PcapBindData>();
	map<string, idx_t> reasons;
	auto result = make_uniq<PcapGlobalState>(SelectCatalogFiles(context, bind, input, reasons));
	result->catalog_reasons = std::move(reasons);
	vector<OpenFileInfo> selected_files;
	for (auto index : result->selected_indices) {
		selected_files.push_back(bind.files[index]);
	}
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
	PlanDecodeStages(bind, input.column_ids, options);
	PushPacketFilters(bind, input, *result);
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
	result->options.filters = &result->filters;
	return std::move(result);
}

// Cells are written straight into the flat output vectors. Building a Value per
// cell boxed every scalar and heap-allocated every string, which profiled at about
// a sixth of a read_packets scan.
template <class T>
static void SetDecodedScalar(Vector &vector, idx_t row, T value) {
	// SetValue cast a mismatched Value silently; a direct write would not.
	PQ_ASSERT(vector.GetType().InternalType() == GetTypeId<T>());
	FlatVector::SetNull(vector, row, false);
	FlatVector::GetData<T>(vector)[row] = value;
}

// A scalar cell that is NULL unless present.
template <class T>
static void SetOptionalScalar(Vector &vector, idx_t row, bool present, T value) {
	if (present) {
		SetDecodedScalar(vector, row, value);
	} else {
		FlatVector::SetNull(vector, row, true);
	}
}

// Text or bytes; the vector owns its copy. Callers pass only valid UTF-8 for
// VARCHAR columns: paths, fixed names and escaped peer text.
static void SetStringCell(Vector &vector, idx_t row, const char *data, idx_t length) {
	PQ_ASSERT(vector.GetType().InternalType() == PhysicalType::VARCHAR);
	if (length == 0) {
		data = ""; // an empty packet_data vector has no buffer
	}
	FlatVector::SetNull(vector, row, false);
	FlatVector::GetData<string_t>(vector)[row] = StringVector::AddStringOrBlob(vector, data, length);
}
static void SetStringCell(Vector &vector, idx_t row, const string &text) {
	SetStringCell(vector, row, text.data(), text.size());
}
// A text cell that is NULL when empty, as error columns are.
static void SetOptionalText(Vector &vector, idx_t row, const string &text) {
	if (text.empty()) {
		FlatVector::SetNull(vector, row, true);
	} else {
		SetStringCell(vector, row, text);
	}
}

static const char HEX_DIGITS[] = "0123456789abcdef";

// Formats into buffer, which holds at least 18 bytes, and returns the length.
// Written digit by digit: four snprintf calls per packet were a visible share of
// a read_packets scan.
static idx_t FormatMac(const std::array<uint8_t, 6> &address, char *buffer) {
	idx_t length = 0;
	for (idx_t i = 0; i < address.size(); ++i) {
		if (i > 0) {
			buffer[length++] = ':';
		}
		buffer[length++] = HEX_DIGITS[address[i] >> 4U];
		buffer[length++] = HEX_DIGITS[address[i] & 0x0FU];
	}
	PQ_ASSERT(length == 17);
	return length;
}

// Formats into buffer, which holds at least 40 bytes, and returns the length:
// dotted IPv4, or IPv6 as eight four-digit groups, uncompressed.
static idx_t FormatIp(const std::array<uint8_t, 16> &address, uint8_t version, char *buffer) {
	idx_t length = 0;
	if (version == 4) {
		for (idx_t i = 0; i < 4; ++i) {
			if (i > 0) {
				buffer[length++] = '.';
			}
			const auto byte = address[i];
			if (byte >= 100) {
				buffer[length++] = static_cast<char>('0' + byte / 100);
			}
			if (byte >= 10) {
				buffer[length++] = static_cast<char>('0' + byte / 10 % 10);
			}
			buffer[length++] = static_cast<char>('0' + byte % 10);
		}
		PQ_ASSERT(length >= 7 && length <= 15);
		return length;
	}
	for (idx_t i = 0; i < 16; ++i) {
		if (i > 0 && i % 2 == 0) {
			buffer[length++] = ':';
		}
		buffer[length++] = HEX_DIGITS[address[i] >> 4U];
		buffer[length++] = HEX_DIGITS[address[i] & 0x0FU];
	}
	PQ_ASSERT(length == 39);
	return length;
}

static void SetMacCell(Vector &vector, idx_t row, const std::array<uint8_t, 6> &address) {
	char buffer[18];
	SetStringCell(vector, row, buffer, FormatMac(address, buffer));
}

static void SetIpCell(Vector &vector, idx_t row, const std::array<uint8_t, 16> &address, uint8_t version) {
	char buffer[40];
	SetStringCell(vector, row, buffer, FormatIp(address, version, buffer));
}

struct KeepAll {
	template <class T>
	bool operator()(const T &) const {
		return true;
	}
};

// A LIST cell of fixed-width values, appended to the list vector's child. Only
// values keep accepts are written, which drops GREASE from the filtered lists.
template <class T, class KEEP = KeepAll>
static void SetScalarListCell(Vector &vector, idx_t row, const T *values, idx_t count, KEEP keep = KEEP()) {
	PQ_ASSERT(vector.GetType().InternalType() == PhysicalType::LIST);
	const auto offset = ListVector::GetListSize(vector);
	ListVector::Reserve(vector, offset + count);
	auto &child = ListVector::GetEntry(vector);
	PQ_ASSERT(child.GetType().InternalType() == GetTypeId<T>());
	auto *data = FlatVector::GetData<T>(child);
	auto &validity = FlatVector::Validity(child);
	idx_t kept = 0;
	for (idx_t i = 0; i < count; ++i) {
		if (keep(values[i])) {
			validity.SetValid(offset + kept);
			data[offset + kept++] = values[i];
		}
	}
	PQ_ASSERT(kept <= count);
	ListVector::SetListSize(vector, offset + kept);
	FlatVector::SetNull(vector, row, false);
	FlatVector::GetData<list_entry_t>(vector)[row] = list_entry_t(offset, kept);
}

// A LIST(VARCHAR) cell; render turns each kept item into its valid UTF-8 text.
template <class ITEM, class KEEP, class RENDER>
static void SetStringListCell(Vector &vector, idx_t row, const std::vector<ITEM> &items, KEEP keep, RENDER render) {
	PQ_ASSERT(vector.GetType().InternalType() == PhysicalType::LIST);
	const auto offset = ListVector::GetListSize(vector);
	ListVector::Reserve(vector, offset + items.size());
	auto &child = ListVector::GetEntry(vector);
	PQ_ASSERT(child.GetType().InternalType() == PhysicalType::VARCHAR);
	auto *data = FlatVector::GetData<string_t>(child);
	auto &validity = FlatVector::Validity(child);
	idx_t kept = 0;
	for (const auto &item : items) {
		if (keep(item)) {
			const string text = render(item);
			validity.SetValid(offset + kept);
			data[offset + kept++] = StringVector::AddString(child, text);
		}
	}
	ListVector::SetListSize(vector, offset + kept);
	FlatVector::SetNull(vector, row, false);
	FlatVector::GetData<list_entry_t>(vector)[row] = list_entry_t(offset, kept);
}

static void SetOutputValue(Vector &vector, idx_t row, column_t column_id, const PacketRecord &record) {
	switch (column_id) {
	case 0:
		SetStringCell(vector, row, record.filename);
		break;
	case 1:
		SetDecodedScalar(vector, row, record.packet_number);
		break;
	case 2:
		if (record.has_timestamp) {
			SetDecodedScalar(vector, row, record.timestamp);
		} else {
			FlatVector::SetNull(vector, row, true);
		}
		break;
	case 3:
		SetDecodedScalar(vector, row, record.captured_length);
		break;
	case 4:
		SetDecodedScalar(vector, row, record.original_length);
		break;
	case 5:
		SetDecodedScalar(vector, row, record.link_type);
		break;
	case 6:
		SetDecodedScalar(vector, row, record.interface_id);
		break;
	case 7:
		SetDecodedScalar(vector, row, record.packet_offset);
		break;
	case 8:
		if (record.format == CaptureFormat::PCAP) {
			SetStringCell(vector, row, "pcap", 4);
		} else {
			SetStringCell(vector, row, "pcapng", 6);
		}
		break;
	case 9:
		SetStringCell(vector, row, reinterpret_cast<const char *>(record.packet_data.data()),
		              record.packet_data.size());
		break;
	case 10:
		SetDecodedScalar(vector, row, record.section_number);
		break;
	default:
		throw InternalException("Unexpected read_pcap column id %d", column_id);
	}
}

// Ethernet and IP header fields.
static void SetLinkNetworkValue(Vector &vector, idx_t row, column_t column,
                                const packetquapture::DecodedPacket &packet) {
	PQ_ASSERT(column >= PACKET_COLUMN_COUNT && column < TRANSPORT_COLUMNS_BEGIN);
	switch (column) {
	case 11:
		SetMacCell(vector, row, packet.src_mac);
		break;
	case 12:
		SetMacCell(vector, row, packet.dst_mac);
		break;
	case 13:
		SetDecodedScalar(vector, row, packet.ether_type);
		break;
	case 14:
		SetScalarListCell(vector, row, packet.vlan_ids.data(), packet.vlan_ids.size());
		break;
	case 15:
		SetDecodedScalar(vector, row, packet.ip_version);
		break;
	case 16:
		SetIpCell(vector, row, packet.src_ip, packet.ip_version);
		break;
	case 17:
		SetIpCell(vector, row, packet.dst_ip, packet.ip_version);
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
	default:
		throw InternalException("Unexpected read_packets column id %d", column);
	}
}

// TCP and UDP header fields and the payload's place in the packet.
static void SetTransportValue(Vector &vector, idx_t row, column_t column, const packetquapture::DecodedPacket &packet) {
	PQ_ASSERT(column >= TRANSPORT_COLUMNS_BEGIN && column < TCP_FLAG_COLUMNS_BEGIN);
	switch (column) {
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

static void SetDecodedValue(Vector &vector, idx_t row, column_t column, const packetquapture::DecodedPacket &packet) {
	// Each column needs the layer it comes from: link columns, including vlan_ids,
	// exist only for Ethernet framing; network and transport ones only once that
	// header decoded.
	bool valid = column < NETWORK_COLUMNS_BEGIN     ? packet.ethernet
	             : column < TRANSPORT_COLUMNS_BEGIN ? packet.network
	                                                : packet.transport;
	if (column >= TCP_FLAG_COLUMNS_BEGIN && column < TLS_COLUMN_BEGIN) {
		if (!packet.tcp) {
			FlatVector::SetNull(vector, row, true);
		} else {
			SetDecodedScalar(vector, row, (packet.tcp_flags & (1U << (column - TCP_FLAG_COLUMNS_BEGIN))) != 0);
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
	if (column < TRANSPORT_COLUMNS_BEGIN) {
		SetLinkNetworkValue(vector, row, column, packet);
	} else {
		SetTransportValue(vector, row, column, packet);
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
			SetStringCell(vector, row, tls.server_name);
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

// The dns_* columns, by position among them.
static void SetDnsValue(Vector &vector, idx_t row, column_t dns_column, const packetquapture::DnsMessage &dns) {
	PQ_ASSERT(dns_column < DNS_COLUMN_COUNT);
	if (dns_column == 0) {
		SetDecodedScalar(vector, row, dns.valid);
		return;
	}
	if (dns_column == 13) {
		SetOptionalText(vector, row, dns.error);
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
		SetStringCell(vector, row, dns.questions[0].name);
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
		throw InternalException("Unexpected read_dns column id %d", dns_column);
	}
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
	SetDnsValue(vector, row, column - DNS_COLUMN_BEGIN, record.dns);
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
	PQ_ASSERT(global.column_ids.size() == output.ColumnCount());
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
		auto &record = state.record;
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
			PQ_ASSERT(bind.stream_plan->scans.load() > 0); // bind registered this scan
			max_workers = MaxValue<idx_t>(1, budget->Slots() / bind.stream_plan->scans.load());
		}
		max_workers = MinValue<idx_t>(max_workers, MaxValue<idx_t>(1, file_count));
		if (file_count) {
			initial = make_uniq<StreamReservation>(budget);
			if (!initial->Acquired()) {
				throw OutOfMemoryException("PacketQuapture cannot reserve %llu MiB for a stream worker. "
				                           "Increase packetquapture_stream_memory_mb or memory_limit; "
				                           "all stream scans in this query share the budget.",
				                           STREAM_WORKER_BYTES / (1024 * 1024));
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
		PQ_ASSERT(admitted <= max_workers);
		if (initial) {
			return std::move(initial);
		}
		auto result = make_uniq<StreamReservation>(budget);
		if (!result->Acquired()) {
			// The slot goes back, so a later worker can still try the budget.
			--admitted;
			return nullptr;
		}
		return result;
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
};

// read_tls column groups, in schema order; TlsBind checks them against the names.
static const column_t TLS_HELLO_COLUMNS_BEGIN = 15;
static const column_t TLS_LIST_COLUMNS_BEGIN = 25;
static const column_t TLS_FINGERPRINT_COLUMNS_BEGIN = 42;
static const column_t TLS_FINGERPRINT_COLUMNS_END = 50;
// Columns that hold certificate structs, with the tunnel between them.
static const column_t TLS_SERVER_CERTIFICATES = 50;
static const column_t TLS_TUNNEL = 51;
static const column_t TLS_CLIENT_CERTIFICATES = 52;
static_assert(TLS_FINGERPRINT_COLUMNS_END == TLS_SERVER_CERTIFICATES, "fingerprints precede the certificates");

// SHA-1 and SHA-256 of a certificate's DER, for the parser, which has no hash
// of its own.
static void TlsCertificateDigest(const uint8_t *der, size_t size, packetquapture::X509Certificate &out) {
	// SHA1State takes only a string; SHA256State reads the bytes in place.
	duckdb_mbedtls::MbedTlsWrapper::SHA1State sha1;
	sha1.AddString(std::string(reinterpret_cast<const char *>(der), size));
	char sha1_hex[duckdb_mbedtls::MbedTlsWrapper::SHA1_HASH_LENGTH_TEXT];
	sha1.FinishHex(sha1_hex);
	out.sha1.assign(sha1_hex, sizeof(sha1_hex));
	duckdb_mbedtls::MbedTlsWrapper::SHA256State sha256;
	sha256.AddBytes(der, size);
	char sha256_hex[duckdb_mbedtls::MbedTlsWrapper::SHA256_HASH_LENGTH_TEXT];
	sha256.FinishHex(sha256_hex);
	out.sha256.assign(sha256_hex, sizeof(sha256_hex));
}

// Hashing every certificate costs a query that asks for none, so the digest is
// supplied only when a certificate column is projected.
static packetquapture::TlsHandshakeAssembler NewTlsAssembler(bool digest) {
	packetquapture::TlsHandshakeLimits limits;
	limits.certificate_digest = digest ? TlsCertificateDigest : nullptr;
	return packetquapture::TlsHandshakeAssembler(limits);
}

struct StreamEvent {
	bool tcp = false;
	packetquapture::TcpStream stream;
	PacketRecord datagram;
};

struct StreamScanState : public LocalTableFunctionState {
	// Destroy all worker buffers before releasing the reservation.
	unique_ptr<StreamReservation> reservation;
	idx_t file_index = 0, stream_index = 0;
	bool file_finished = false, initialized = false;
	string filename;
	unique_ptr<CaptureReader> reader;
	PacketRecord record; // reused for every packet
	StreamEvent event;   // reused for every event, so its buffers are too
	packetquapture::TcpReassembler reassembler;
	std::vector<packetquapture::TcpStream> streams;
	idx_t pending_index = 0;
	std::vector<packetquapture::TcpDnsMessage> pending;

	// read_tls pairs the two directions of a connection, which the transport core
	// finishes independently, so rows can outlive the stream that produced them.
	// The file they belong to is held with them.
	packetquapture::TlsHandshakeAssembler tls_assembler;
	// Whether tls_assembler hashes certificates, decided on the first scan call.
	bool tls_configured = false, tls_digest = false;
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
// Admits this thread as a stream worker on its first call, if the query's
// memory budget has room. Returns whether it holds a reservation and may scan.
static bool AdmitStreamWorker(StreamGlobalState &global, StreamScanState &state) {
	if (!state.initialized) {
		state.initialized = true;
		if (global.file_count) {
			state.reservation = global.Admit();
		}
	}
	return state.reservation != nullptr;
}

// A worker with nothing left frees every buffer it holds, and only then its
// reservation, so memory never outlives the budget that admitted it.
static void ReleaseStreamWorker(const PcapBindData &bind, StreamScanState &state) {
	std::vector<packetquapture::TcpStream>().swap(state.streams);
	std::vector<packetquapture::TcpDnsMessage>().swap(state.pending);
	std::vector<packetquapture::TlsHandshake>().swap(state.tls_pending);
	state.tls_assembler = packetquapture::TlsHandshakeAssembler();
	state.tls_configured = false; // a later call configures it again
	state.reassembler = packetquapture::TcpReassembler(bind.stream_limits);
	state.record = PacketRecord();
	state.event = StreamEvent();
	state.reservation.reset();
}

// Shared capture iteration and transport lifecycle for every stream-level consumer.
// Each pass hands out a stream, reads one record, finishes one flow at end of
// file, or claims the next file, so it is bounded by records plus flows plus files.
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
			state.reassembler = packetquapture::TcpReassembler(bind.stream_limits);
			state.reader = make_uniq<CaptureReader>(context, file, global.options, &global.progress, work_index);
		}
		auto &record = state.record;
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
			// A swap, not a move, so both records keep their buffers.
			std::swap(event.datagram, record);
			return true;
		}
	}
}

// read_dns_messages's own columns, one per line so each name sits beside its type.
// The dns_* columns of read_dns follow them.
static void DnsMessagesSchema(vector<LogicalType> &types, vector<string> &names) {
	types.clear();
	names.clear();
	auto column = [&](const char *name, const LogicalType &type) {
		names.emplace_back(name);
		types.push_back(type);
	};
	column("filename", LogicalType::VARCHAR);
	column("section_number", LogicalType::UINTEGER);
	column("interface_id", LogicalType::UINTEGER);
	column("ip_version", LogicalType::UTINYINT);
	column("src_ip", LogicalType::VARCHAR);
	column("dst_ip", LogicalType::VARCHAR);
	column("src_port", LogicalType::USMALLINT);
	column("dst_port", LogicalType::USMALLINT);
	column("transport", LogicalType::VARCHAR);
	column("stream_id", LogicalType::UBIGINT);
	column("message_number", LogicalType::UBIGINT);
	column("first_packet_number", LogicalType::UBIGINT);
	column("last_packet_number", LogicalType::UBIGINT);
	column("first_timestamp", LogicalType::TIMESTAMP);
	column("last_timestamp", LogicalType::TIMESTAMP);
	column("tcp_sequence", LogicalType::UINTEGER);
	column("reassembly_status", LogicalType::VARCHAR);
	column("reassembly_error", LogicalType::VARCHAR);
	column("message_data", LogicalType::BLOB);
	column("vlan_ids", LogicalType::LIST(LogicalType::USMALLINT));
}

static unique_ptr<FunctionData> DnsMessagesBind(ClientContext &context, TableFunctionBindInput &input,
                                                vector<LogicalType> &types, vector<string> &names) {
	auto result = DnsBind(context, input, types, names);
	BindStreamOptions(*result, input);
	// Keep the dns_* columns and drop the per-packet ones: this reader reports one
	// row per reassembled message, not per packet.
	vector<LogicalType> dns_types(types.begin() + DNS_COLUMN_BEGIN, types.end());
	vector<string> dns_names(names.begin() + DNS_COLUMN_BEGIN, names.end());
	DnsMessagesSchema(types, names);
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
			state->options.decode_dns = true; // dns_* columns are projected, so messages are parsed
		}
	}
	return std::move(state);
}

// The first columns of every stream-level reader: the file, then the connection
// as the transport core keyed it.
static const column_t CONNECTION_COLUMN_COUNT = 8;
static void SetConnectionValue(Vector &vector, idx_t row, column_t column, const string &filename,
                               const packetquapture::TcpFlowKey &key) {
	PQ_ASSERT(column < CONNECTION_COLUMN_COUNT);
	switch (column) {
	case 0:
		SetStringCell(vector, row, filename);
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
		SetIpCell(vector, row, key.src_ip, key.ip_version);
		break;
	case 5:
		SetIpCell(vector, row, key.dst_ip, key.ip_version);
		break;
	case 6:
		SetDecodedScalar(vector, row, key.src_port);
		break;
	default:
		SetDecodedScalar(vector, row, key.dst_port);
		break;
	}
}

static void SetMessageValue(Vector &vector, idx_t row, column_t column, const string &filename,
                            const packetquapture::TcpDnsMessage &message, const PacketRecord &dns_record) {
	const auto &key = message.key;
	if (column >= MESSAGE_DNS_COLUMN_BEGIN && column < MESSAGE_DNS_COLUMN_END) {
		SetRecordValue(vector, row, column - MESSAGE_DNS_COLUMN_BEGIN + DNS_COLUMN_BEGIN, dns_record);
		return;
	}
	if (column < CONNECTION_COLUMN_COUNT) {
		SetConnectionValue(vector, row, column, filename, key);
		return;
	}
	switch (column) {
	case 8:
		if (message.tcp) {
			SetStringCell(vector, row, "tcp", 3);
		} else {
			SetStringCell(vector, row, "udp", 3);
		}
		break;
	case 9:
		SetOptionalScalar(vector, row, message.tcp, message.stream_id);
		break;
	case 10:
		SetOptionalScalar(vector, row, message.message_number != 0, message.message_number);
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
		SetOptionalScalar(vector, row, stamp.has_timestamp, timestamp_t(stamp.timestamp));
		break;
	}
	case 15:
		if (message.tcp && (message.status == packetquapture::DnsFrameStatus::COMPLETE ||
		                    message.status == packetquapture::DnsFrameStatus::INCOMPLETE ||
		                    message.status == packetquapture::DnsFrameStatus::INVALID)) {
			SetDecodedScalar(vector, row, message.sequence);
		} else {
			FlatVector::SetNull(vector, row, true);
		}
		break;
	case 16:
		SetStringCell(vector, row, packetquapture::DnsFrameStatusName(message.status));
		break;
	case 17:
		SetOptionalText(vector, row, message.error);
		break;
	case 18:
		if (message.status != packetquapture::DnsFrameStatus::COMPLETE) {
			FlatVector::SetNull(vector, row, true);
		} else if (message.data.empty()) {
			SetStringCell(vector, row, "", 0);
		} else {
			SetStringCell(vector, row, reinterpret_cast<const char *>(message.data.data()), message.data.size());
		}
		break;
	case 19:
		SetScalarListCell(vector, row, key.vlans.data(), key.vlans.size());
		break;
	default:
		throw InternalException("Unexpected read_dns_messages column id %d", column);
	}
}

static void DnsMessagesScan(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
	auto &bind = input.bind_data->Cast<PcapBindData>();
	auto &global = input.global_state->Cast<StreamGlobalState>();
	auto &state = input.local_state->Cast<StreamScanState>();
	if (!AdmitStreamWorker(global, state)) {
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
			if (global.options.decode_dns) {
				if (message.status == packetquapture::DnsFrameStatus::COMPLETE) {
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
			output_bytes += ROW_BASE_BYTES + state.filename.size() + message.data.size() * PAYLOAD_COPIES;
			output_bytes += (dns_record.dns.questions.size() + dns_record.dns.answers.size() +
			                 dns_record.dns.authorities.size() + dns_record.dns.additionals.size()) *
			                DNS_RECORD_BYTES;
			++count;
			continue;
		}
		state.pending.clear();
		state.pending_index = 0;
		auto &event = state.event;
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
				message.status = packetquapture::DnsFrameStatus::COMPLETE;
				message.data.assign(record.transport_data.begin(), record.transport_data.end());
			} else {
				message.status = packetquapture::DnsFrameStatus::INCOMPLETE;
				message.error = "truncated UDP DNS payload";
				message.message_number = 0;
			}
			state.pending.push_back(std::move(message));
		}
	}
	output.SetCardinality(count);
	if (!count) {
		ReleaseStreamWorker(bind, state);
	}
}

// read_tls reports one row per handshake, pairing the two directions of a
// connection so the offered name and the selected parameters arrive together.
// The key is oriented client to server whichever direction was captured.
// One element of server_certificates and client_certificates.
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
	fields.emplace_back("subject_key_id", LogicalType::VARCHAR);
	fields.emplace_back("authority_key_id", LogicalType::VARCHAR);
	fields.emplace_back("ocsp_urls", LogicalType::LIST(LogicalType::VARCHAR));
	fields.emplace_back("ca_issuers_urls", LogicalType::LIST(LogicalType::VARCHAR));
	fields.emplace_back("crl_urls", LogicalType::LIST(LogicalType::VARCHAR));
	fields.emplace_back("policies", LogicalType::LIST(LogicalType::VARCHAR));
	return LogicalType::STRUCT(std::move(fields));
}

// The tunnel that carried a handshake, when TLS did not begin a stream.
static LogicalType MakeTlsTunnelType() {
	child_list_t<LogicalType> fields;
	fields.emplace_back("protocol", LogicalType::VARCHAR);
	fields.emplace_back("destination", LogicalType::VARCHAR);
	fields.emplace_back("client_prefix_bytes", LogicalType::UINTEGER);
	fields.emplace_back("server_prefix_bytes", LogicalType::UINTEGER);
	return LogicalType::STRUCT(std::move(fields));
}
// Built once: rows ask for it per cell, and a STRUCT type allocates.
static const LogicalType &TlsTunnelType() {
	static const LogicalType type = MakeTlsTunnelType();
	return type;
}

// read_tls's schema, one column per line so each name sits beside its type.
static void TlsSchema(vector<LogicalType> &types, vector<string> &names) {
	const auto codes = LogicalType::LIST(LogicalType::USMALLINT);
	const auto text = LogicalType::LIST(LogicalType::VARCHAR);
	types.clear();
	names.clear();
	auto column = [&](const char *name, const LogicalType &type) {
		names.emplace_back(name);
		types.push_back(type);
	};
	column("filename", LogicalType::VARCHAR);
	column("section_number", LogicalType::UINTEGER);
	column("interface_id", LogicalType::UINTEGER);
	column("ip_version", LogicalType::UTINYINT);
	column("client_ip", LogicalType::VARCHAR);
	column("server_ip", LogicalType::VARCHAR);
	column("client_port", LogicalType::USMALLINT);
	column("server_port", LogicalType::USMALLINT);
	column("client_stream_id", LogicalType::UBIGINT);
	column("server_stream_id", LogicalType::UBIGINT);
	column("handshake_number", LogicalType::UBIGINT);
	column("first_packet_number", LogicalType::UBIGINT);
	column("last_packet_number", LogicalType::UBIGINT);
	column("first_timestamp", LogicalType::TIMESTAMP);
	column("last_timestamp", LogicalType::TIMESTAMP);
	column("client_hello", LogicalType::BOOLEAN);
	column("server_hello", LogicalType::BOOLEAN);
	column("tls_sni", LogicalType::VARCHAR);
	column("client_version", LogicalType::USMALLINT);
	column("negotiated_version", LogicalType::USMALLINT);
	column("cipher_suite", LogicalType::USMALLINT);
	column("session_resumed", LogicalType::BOOLEAN);
	column("reassembly_status", LogicalType::VARCHAR);
	column("reassembly_error", LogicalType::VARCHAR);
	column("vlan_ids", codes);
	column("client_cipher_suites", codes);
	column("client_cipher_suites_no_grease", codes);
	column("client_extensions", codes);
	column("client_extensions_no_grease", codes);
	column("client_supported_groups", codes);
	column("client_supported_groups_no_grease", codes);
	column("client_signature_algorithms", codes);
	column("client_signature_algorithms_no_grease", codes);
	column("client_supported_versions", codes);
	column("client_supported_versions_no_grease", codes);
	column("client_ec_point_formats", LogicalType::LIST(LogicalType::UTINYINT));
	column("client_alpn", text);
	column("client_alpn_no_grease", text);
	column("server_extensions", codes);
	column("server_extensions_no_grease", codes);
	column("server_alpn", LogicalType::VARCHAR);
	column("warnings", text);
	column("ja3", LogicalType::VARCHAR);
	column("ja3_full", LogicalType::VARCHAR);
	column("ja3s", LogicalType::VARCHAR);
	column("ja3s_full", LogicalType::VARCHAR);
	column("ja4", LogicalType::VARCHAR);
	column("ja4_r", LogicalType::VARCHAR);
	column("ja4s", LogicalType::VARCHAR);
	column("ja4s_r", LogicalType::VARCHAR);
	column("server_certificates", LogicalType::LIST(TlsCertificateType()));
	column("tunnel", TlsTunnelType());
	column("client_certificates", LogicalType::LIST(TlsCertificateType()));
}

static unique_ptr<FunctionData> TlsBind(ClientContext &context, TableFunctionBindInput &input,
                                        vector<LogicalType> &types, vector<string> &names) {
	auto result = PcapBind(context, input, types, names);
	BindStreamOptions(*result, input);
	TlsSchema(types, names);
	// The cell writers find column groups by position.
	PQ_ASSERT(names.size() == TLS_CLIENT_CERTIFICATES + 1);
	PQ_ASSERT(names[TLS_HELLO_COLUMNS_BEGIN] == "client_hello");
	PQ_ASSERT(names[TLS_LIST_COLUMNS_BEGIN] == "client_cipher_suites");
	PQ_ASSERT(names[TLS_FINGERPRINT_COLUMNS_BEGIN] == "ja3");
	PQ_ASSERT(names[TLS_SERVER_CERTIFICATES] == "server_certificates");
	PQ_ASSERT(names[TLS_TUNNEL] == "tunnel");
	PQ_ASSERT(names[TLS_CLIENT_CERTIFICATES] == "client_certificates");
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
	SetScalarListCell(vector, row, list.values.data(), list.values.size(),
	                  [skip_grease](uint16_t code) { return !skip_grease || !packetquapture::IsTlsGrease(code); });
}

// ALPN identifiers are peer-supplied bytes, escaped as server names are.
static void SetTlsAlpn(Vector &vector, idx_t row, const packetquapture::TlsList<std::string> &list, bool skip_grease) {
	if (!list.present) {
		FlatVector::SetNull(vector, row, true);
		return;
	}
	SetStringListCell(
	    vector, row, list.values,
	    [skip_grease](const std::string &protocol) {
		    return !skip_grease || !packetquapture::IsTlsGreaseAlpn(protocol);
	    },
	    [](const std::string &protocol) { return packetquapture::EscapeTlsText(protocol); });
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
	const idx_t code_count =
	    handshake.client_cipher_suites.values.size() + handshake.client_extensions.values.size() +
	    handshake.client_supported_groups.values.size() + handshake.client_signature_algorithms.values.size() +
	    handshake.client_supported_versions.values.size() + handshake.client_ec_point_formats.values.size() +
	    handshake.server_extensions.values.size();
	idx_t alpn_bytes = 0;
	for (const auto &protocol : handshake.client_alpn.values) {
		alpn_bytes += LIST_ENTRY_BYTES + 8 * protocol.size(); // the escaped text, in two columns
	}
	for (const auto &protocol : handshake.server_alpn.values) {
		alpn_bytes += LIST_ENTRY_BYTES + 4 * protocol.size(); // the escaped text, in one column
	}
	idx_t certificate_bytes = 0;
	for (const auto *chain : {&handshake.server_certificates, &handshake.client_certificates}) {
		for (const auto &certificate : chain->values) {
			const auto &fields = certificate.fields;
			certificate_bytes += CERTIFICATE_BASE_BYTES + fields.TextBytes();
			certificate_bytes +=
			    LIST_ENTRY_BYTES * (fields.san_dns.size() + fields.san_ip.size() + fields.key_usage.size() +
			                        fields.extended_key_usage.size() + fields.ocsp_urls.size() +
			                        fields.ca_issuers_urls.size() + fields.crl_urls.size() + fields.policies.size());
		}
	}
	return ROW_BASE_BYTES + filename.size() + handshake.sni.size() + LIST_ENTRY_BYTES * code_count + alpn_bytes +
	       certificate_bytes + handshake.tunnel_destination.size();
}

static Value OptionalText(const std::string &text) {
	return text.empty() ? Value(LogicalType::VARCHAR) : Value(text);
}

static Value OptionalList(bool present, const std::vector<std::string> &items) {
	return present ? TextList(items) : Value(LogicalType::LIST(LogicalType::VARCHAR));
}

static void SetTlsCertificates(Vector &vector, idx_t row,
                               const packetquapture::TlsList<packetquapture::TlsCertificate> &chain) {
	if (!chain.present) {
		FlatVector::SetNull(vector, row, true);
		return;
	}
	static const LogicalType type = TlsCertificateType();
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
		    type, {Value(fields.subject),
		           Value(fields.issuer),
		           Value(fields.serial),
		           Value::TIMESTAMP(timestamp_t(fields.not_before)),
		           Value::TIMESTAMP(timestamp_t(fields.not_after)),
		           TextList(fields.san_dns),
		           TextList(fields.san_ip),
		           Value(Ja4Hash12(ja4x.issuer) + "_" + Ja4Hash12(ja4x.subject) + "_" + Ja4Hash12(ja4x.extensions)),
		           Value(ja4x.issuer + "_" + ja4x.subject + "_" + ja4x.extensions),
		           OptionalText(fields.sha1),
		           OptionalText(fields.sha256),
		           OptionalText(fields.signature_algorithm),
		           OptionalText(fields.public_key_algorithm),
		           fields.public_key_bits != 0 ? Value::UINTEGER(fields.public_key_bits) : Value(LogicalType::UINTEGER),
		           OptionalText(fields.public_key_curve),
		           fields.has_basic_constraints ? Value::BOOLEAN(fields.is_ca) : Value(LogicalType::BOOLEAN),
		           fields.has_path_length ? Value::UINTEGER(fields.path_length) : Value(LogicalType::UINTEGER),
		           OptionalList(fields.has_key_usage, fields.key_usage),
		           OptionalList(fields.has_extended_key_usage, fields.extended_key_usage),
		           OptionalText(fields.subject_key_id),
		           OptionalText(fields.authority_key_id),
		           OptionalList(fields.has_authority_info_access, fields.ocsp_urls),
		           OptionalList(fields.has_authority_info_access, fields.ca_issuers_urls),
		           OptionalList(fields.has_crl_distribution_points, fields.crl_urls),
		           OptionalList(fields.has_policies, fields.policies)}));
	}
	vector.SetValue(row, Value::LIST(type, values));
}

// One row's fingerprint inputs, built on first use: the hash and raw columns of
// JA3, JA3S, JA4 and JA4S share them, so projecting both builds each once.
class TlsFingerprintInputs {
public:
	explicit TlsFingerprintInputs(const packetquapture::TlsHandshake &handshake_p) : handshake(handshake_p) {
	}
	// JA3 for the client side, JA3S for the server's; null when not computable.
	const std::string *Ja3(bool client) {
		auto &slot = ja3[client ? 0 : 1];
		if (!slot.built) {
			slot.built = true;
			slot.valid = client ? packetquapture::Ja3String(handshake, slot.text)
			                    : packetquapture::Ja3sString(handshake, slot.text);
		}
		return slot.valid ? &slot.text : nullptr;
	}
	// JA4 for the client side, JA4S for the server's; null when not computable.
	const packetquapture::Ja4Parts *Ja4(bool client) {
		auto &slot = ja4[client ? 0 : 1];
		if (!slot.built) {
			slot.built = true;
			slot.valid = client ? packetquapture::Ja4Strings(handshake, slot.parts)
			                    : packetquapture::Ja4sStrings(handshake, slot.parts);
		}
		return slot.valid ? &slot.parts : nullptr;
	}

private:
	struct Ja3Slot {
		bool built = false, valid = false;
		std::string text;
	};
	struct Ja4Slot {
		bool built = false, valid = false;
		packetquapture::Ja4Parts parts;
	};
	const packetquapture::TlsHandshake &handshake;
	Ja3Slot ja3[2];
	Ja4Slot ja4[2];
};

// The connection and provenance columns.
static void SetHandshakeKeyValue(Vector &vector, idx_t row, column_t column, const string &filename,
                                 const packetquapture::TlsHandshake &handshake) {
	PQ_ASSERT(column < TLS_HELLO_COLUMNS_BEGIN);
	const auto &key = handshake.key;
	if (column < CONNECTION_COLUMN_COUNT) {
		SetConnectionValue(vector, row, column, filename, key);
		return;
	}
	switch (column) {
	// A stream id is NULL when that direction of the connection was not captured.
	case 8:
		SetOptionalScalar(vector, row, handshake.has_client_stream, handshake.client_stream_id);
		break;
	case 9:
		SetOptionalScalar(vector, row, handshake.has_server_stream, handshake.server_stream_id);
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
	default: {
		const auto &stamp = column == 13 ? handshake.first : handshake.last;
		SetOptionalScalar(vector, row, stamp.has_timestamp, timestamp_t(stamp.timestamp));
		break;
	}
	}
}

// What the hellos said, and the row's status.
static void SetHandshakeHelloValue(Vector &vector, idx_t row, column_t column,
                                   const packetquapture::TlsHandshake &handshake) {
	PQ_ASSERT(column >= TLS_HELLO_COLUMNS_BEGIN && column < TLS_LIST_COLUMNS_BEGIN);
	switch (column) {
	case 15:
		SetDecodedScalar(vector, row, handshake.has_client_hello);
		break;
	case 16:
		SetDecodedScalar(vector, row, handshake.has_server_hello);
		break;
	case 17:
		if (handshake.has_sni) {
			SetStringCell(vector, row, handshake.sni);
		} else {
			FlatVector::SetNull(vector, row, true);
		}
		break;
	case 18:
		SetOptionalScalar(vector, row, handshake.has_client_version, handshake.client_version);
		break;
	case 19:
		SetOptionalScalar(vector, row, handshake.has_negotiated_version, handshake.negotiated_version);
		break;
	case 20:
		SetOptionalScalar(vector, row, handshake.has_cipher_suite, handshake.cipher_suite);
		break;
	case 21:
		// Undecidable without both directions, and meaningless in TLS 1.3.
		SetOptionalScalar(vector, row, handshake.has_resumed, handshake.resumed);
		break;
	case 22:
		SetStringCell(vector, row, packetquapture::TlsStatusName(handshake.status));
		break;
	case 23:
		SetOptionalText(vector, row, handshake.error);
		break;
	default:
		SetScalarListCell(vector, row, handshake.key.vlans.data(), handshake.key.vlans.size());
		break;
	}
}

// The hello lists, each with its GREASE-free twin, and the warnings.
static void SetHandshakeListValue(Vector &vector, idx_t row, column_t column,
                                  const packetquapture::TlsHandshake &handshake) {
	PQ_ASSERT(column >= TLS_LIST_COLUMNS_BEGIN && column < TLS_FINGERPRINT_COLUMNS_BEGIN);
	switch (column) {
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
		SetScalarListCell(vector, row, list.values.data(), list.values.size());
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
			SetStringCell(vector, row, packetquapture::EscapeTlsText(handshake.server_alpn.values.front()));
		} else {
			FlatVector::SetNull(vector, row, true);
		}
		break;
	default:
		SetStringListCell(
		    vector, row, handshake.warnings, [](const std::string &) { return true; },
		    [](const std::string &warning) { return warning; });
		break;
	}
}

// JA3 and JA3S, then JA4 and JA4S, each hashed and raw. Fingerprints are built
// only when projected, like every other column, so queries that do not ask for
// them pay nothing. NULL rather than a hash of partial input; see
// tls_fingerprint.hpp. JA4S is FoxIO License 1.1; see NOTICE.
static void SetHandshakeFingerprintValue(Vector &vector, idx_t row, column_t column,
                                         TlsFingerprintInputs &fingerprints) {
	PQ_ASSERT(column >= TLS_FINGERPRINT_COLUMNS_BEGIN && column < TLS_FINGERPRINT_COLUMNS_END);
	if (column < 46) {
		const auto *text = fingerprints.Ja3(column == 42 || column == 43);
		if (text == nullptr) {
			FlatVector::SetNull(vector, row, true);
		} else if (column == 43 || column == 45) {
			SetStringCell(vector, row, *text);
		} else {
			MD5Context md5;
			md5.Add(*text);
			SetStringCell(vector, row, md5.FinishHex());
		}
		return;
	}
	const bool client = column == 46 || column == 47;
	const auto *parts = fingerprints.Ja4(client);
	if (parts == nullptr) {
		FlatVector::SetNull(vector, row, true);
	} else if (column == 47 || column == 49) {
		SetStringCell(vector, row, parts->prefix + "_" + parts->first + "_" + parts->second);
	} else {
		// JA4S carries its one cipher suite as is; JA4 hashes its cipher list.
		const auto first = client ? Ja4Hash12(parts->first) : parts->first;
		SetStringCell(vector, row, parts->prefix + "_" + first + "_" + Ja4Hash12(parts->second));
	}
}

// NULL unless a prefix came before TLS in a captured direction. The protocol
// is the client's reading of its own prefix when it has one, since only the
// client's request names the destination; otherwise the server's.
static void SetHandshakeTunnel(Vector &vector, idx_t row, const packetquapture::TlsHandshake &handshake) {
	if (handshake.client_prefix_bytes == 0 && handshake.server_prefix_bytes == 0) {
		FlatVector::SetNull(vector, row, true);
		return;
	}
	const auto &protocol = !handshake.client_tunnel.empty() ? handshake.client_tunnel : handshake.server_tunnel;
	vector.SetValue(
	    row, Value::STRUCT(TlsTunnelType(), {protocol.empty() ? Value(LogicalType::VARCHAR) : Value(protocol),
	                                         handshake.tunnel_destination.empty() ? Value(LogicalType::VARCHAR)
	                                                                              : Value(handshake.tunnel_destination),
	                                         handshake.has_client_hello ? Value::UINTEGER(handshake.client_prefix_bytes)
	                                                                    : Value(LogicalType::UINTEGER),
	                                         handshake.has_server_hello ? Value::UINTEGER(handshake.server_prefix_bytes)
	                                                                    : Value(LogicalType::UINTEGER)}));
}

static void SetHandshakeValue(Vector &vector, idx_t row, column_t column, const string &filename,
                              const packetquapture::TlsHandshake &handshake, TlsFingerprintInputs &fingerprints) {
	if (column < TLS_HELLO_COLUMNS_BEGIN) {
		SetHandshakeKeyValue(vector, row, column, filename, handshake);
	} else if (column < TLS_LIST_COLUMNS_BEGIN) {
		SetHandshakeHelloValue(vector, row, column, handshake);
	} else if (column < TLS_FINGERPRINT_COLUMNS_BEGIN) {
		SetHandshakeListValue(vector, row, column, handshake);
	} else if (column < TLS_FINGERPRINT_COLUMNS_END) {
		SetHandshakeFingerprintValue(vector, row, column, fingerprints);
	} else if (column == TLS_SERVER_CERTIFICATES) {
		// The chain from each side's Certificate message, leaf first. An entry that
		// did not parse is a NULL element, so positions still match the chain.
		SetTlsCertificates(vector, row, handshake.server_certificates);
	} else if (column == TLS_CLIENT_CERTIFICATES) {
		SetTlsCertificates(vector, row, handshake.client_certificates);
	} else if (column == TLS_TUNNEL) {
		SetHandshakeTunnel(vector, row, handshake);
	} else {
		throw InternalException("Unexpected read_tls column id %d", column);
	}
}

// Hashing certificates costs per certificate, so the assembler does it only when
// a certificate column is projected. Decided on the worker's first call.
static void ConfigureTlsWorker(const StreamGlobalState &global, StreamScanState &state) {
	if (state.tls_configured) {
		return;
	}
	for (const auto column : global.columns) {
		state.tls_digest = state.tls_digest || column == TLS_SERVER_CERTIFICATES || column == TLS_CLIENT_CERTIFICATES;
	}
	state.tls_assembler = NewTlsAssembler(state.tls_digest);
	state.tls_configured = true;
}

// Writes the next held handshake as output row `row`; returns its estimated bytes.
static idx_t EmitTlsRow(const PcapBindData &bind, const StreamGlobalState &global, StreamScanState &state,
                        DataChunk &output, idx_t row) {
	PQ_ASSERT(state.tls_pending_index < state.tls_pending.size());
	const auto &handshake = state.tls_pending[state.tls_pending_index++];
	TlsFingerprintInputs fingerprints(handshake);
	for (idx_t i = 0; i < global.columns.size(); ++i) {
		if (!bind.SetPartition(output.data[i], row, global.columns[i], state.tls_pending_file_index)) {
			SetHandshakeValue(output.data[i], row, global.columns[i], state.tls_pending_filename, handshake,
			                  fingerprints);
		}
	}
	return TlsRowBytes(state.tls_pending_filename, handshake);
}

static void TlsScan(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
	auto &bind = input.bind_data->Cast<PcapBindData>();
	auto &global = input.global_state->Cast<StreamGlobalState>();
	auto &state = input.local_state->Cast<StreamScanState>();
	if (!AdmitStreamWorker(global, state)) {
		return;
	}
	idx_t count = 0, output_bytes = 0;
	ConfigureTlsWorker(global, state);
	while (count < STANDARD_VECTOR_SIZE && output_bytes < STREAM_OUTPUT_BATCH_BYTES) {
		if (context.IsInterrupted()) {
			throw InterruptException();
		}
		if (state.tls_pending_index < state.tls_pending.size()) {
			output_bytes += EmitTlsRow(bind, global, state, output, count);
			++count;
			continue;
		}
		state.tls_pending.clear();
		state.tls_pending_index = 0;
		if (state.tls_drained) {
			break;
		}
		auto &event = state.event;
		if (!NextStreamEvent(context, bind, global, state, event)) {
			// Directions still waiting for a peer are reported on their own.
			state.tls_drained = true;
			state.tls_pending = state.tls_assembler.Finish();
			state.tls_pending_filename = state.tls_open_filename;
			state.tls_pending_file_index = state.tls_open_file_index;
			continue;
		}
		// TLS runs over TCP, and a TLS scan reassembles TCP only (the reader drops
		// every other packet), so a non-TCP event would mean that filter broke.
		PQ_ASSERT(event.tcp);
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
			// Nothing pairs on the first stream of a file, so rows held from the
			// previous file are never pending here; were they, these rows would be
			// filed under that file's name.
			PQ_ASSERT(state.tls_pending.empty());
			state.tls_pending_filename = state.filename;
			state.tls_pending_file_index = state.file_index;
			state.tls_pending = std::move(handshakes);
		}
	}
	output.SetCardinality(count);
	if (!count) {
		ReleaseStreamWorker(bind, state);
	}
}

static LogicalType MakeTcpChunkType() {
	return LogicalType::STRUCT({{"offset", LogicalType::UINTEGER},
	                            {"tcp_sequence", LogicalType::UINTEGER},
	                            {"data", LogicalType::BLOB},
	                            {"first_packet_number", LogicalType::UBIGINT},
	                            {"last_packet_number", LogicalType::UBIGINT}});
}
// Built once: rows ask for it per cell, and a STRUCT type allocates.
static const LogicalType &TcpChunkType() {
	static const LogicalType type = MakeTcpChunkType();
	return type;
}
static LogicalType MakeTcpGapType() {
	return LogicalType::STRUCT({{"offset", LogicalType::UINTEGER}, {"length", LogicalType::UINTEGER}});
}
// Built once: rows ask for it per cell, and a STRUCT type allocates.
static const LogicalType &TcpGapType() {
	static const LogicalType type = MakeTcpGapType();
	return type;
}
// read_tcp_streams's schema, one column per line so each name sits beside its type.
static void TcpStreamsSchema(vector<LogicalType> &types, vector<string> &names) {
	types.clear();
	names.clear();
	auto column = [&](const char *name, const LogicalType &type) {
		names.emplace_back(name);
		types.push_back(type);
	};
	column("filename", LogicalType::VARCHAR);
	column("section_number", LogicalType::UINTEGER);
	column("interface_id", LogicalType::UINTEGER);
	column("ip_version", LogicalType::UTINYINT);
	column("src_ip", LogicalType::VARCHAR);
	column("dst_ip", LogicalType::VARCHAR);
	column("src_port", LogicalType::USMALLINT);
	column("dst_port", LogicalType::USMALLINT);
	column("stream_id", LogicalType::UBIGINT);
	column("tcp_sequence", LogicalType::UINTEGER);
	column("syn_seen", LogicalType::BOOLEAN);
	column("fin_seen", LogicalType::BOOLEAN);
	column("reset_seen", LogicalType::BOOLEAN);
	column("finalized_by", LogicalType::VARCHAR);
	column("reassembly_status", LogicalType::VARCHAR);
	column("reassembly_error", LogicalType::VARCHAR);
	column("first_packet_number", LogicalType::UBIGINT);
	column("last_packet_number", LogicalType::UBIGINT);
	column("first_timestamp", LogicalType::TIMESTAMP);
	column("last_timestamp", LogicalType::TIMESTAMP);
	column("expected_bytes", LogicalType::UINTEGER);
	column("captured_bytes", LogicalType::UINTEGER);
	column("has_gaps", LogicalType::BOOLEAN);
	column("stream_data", LogicalType::BLOB);
	column("chunks", LogicalType::LIST(TcpChunkType()));
	column("gaps", LogicalType::LIST(TcpGapType()));
	column("vlan_ids", LogicalType::LIST(LogicalType::USMALLINT));
}

static unique_ptr<FunctionData> TcpStreamsBind(ClientContext &context, TableFunctionBindInput &input,
                                               vector<LogicalType> &types, vector<string> &names) {
	auto result = PcapBind(context, input, types, names);
	BindStreamOptions(*result, input);
	TcpStreamsSchema(types, names);
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
// The captured runs of a stream, each with the packets that carried it.
static void SetTcpChunks(Vector &vector, idx_t row, const packetquapture::TcpStream &stream) {
	duckdb::vector<Value> values;
	for (const auto &chunk : stream.chunks) {
		const auto stamps = chunk.Provenance(0, chunk.data.size());
		values.push_back(
		    Value::STRUCT(TcpChunkType(), {Value::UINTEGER(chunk.offset), Value::UINTEGER(chunk.sequence),
		                                   Value::BLOB(chunk.data.data(), chunk.data.size()),
		                                   Value::UBIGINT(stamps.first.number), Value::UBIGINT(stamps.second.number)}));
	}
	vector.SetValue(row, Value::LIST(TcpChunkType(), values));
}

static void SetTcpGaps(Vector &vector, idx_t row, const packetquapture::TcpStream &stream) {
	duckdb::vector<Value> values;
	for (const auto &gap : stream.gaps) {
		values.push_back(Value::STRUCT(TcpGapType(), {Value::UINTEGER(gap.offset), Value::UINTEGER(gap.length)}));
	}
	vector.SetValue(row, Value::LIST(TcpGapType(), values));
}

// What was captured of a stream: its packets, bytes, gaps and VLANs.
static void SetStreamCaptureValue(Vector &vector, idx_t row, column_t column, const packetquapture::TcpStream &stream) {
	switch (column) {
	case 16:
		SetDecodedScalar(vector, row, stream.first.number);
		break;
	case 17:
		SetDecodedScalar(vector, row, stream.last.number);
		break;
	case 18:
	case 19: {
		const auto &stamp = column == 18 ? stream.first : stream.last;
		SetOptionalScalar(vector, row, stamp.has_timestamp, timestamp_t(stamp.timestamp));
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
			SetStringCell(vector, row, reinterpret_cast<const char *>(bytes.data()), bytes.size());
		}
		break;
	case 24:
		SetTcpChunks(vector, row, stream);
		break;
	case 25:
		SetTcpGaps(vector, row, stream);
		break;
	case 26:
		SetScalarListCell(vector, row, stream.key.vlans.data(), stream.key.vlans.size());
		break;
	default:
		throw InternalException("Unexpected read_tcp_streams column id %d", column);
	}
}

static void SetStreamValue(Vector &vector, idx_t row, column_t column, const string &filename,
                           const packetquapture::TcpStream &stream) {
	const auto &key = stream.key;
	const bool failed = stream.status == packetquapture::TcpStreamStatus::CONFLICT ||
	                    stream.status == packetquapture::TcpStreamStatus::LIMIT;
	if (failed && (column == 9 || (column >= 20 && column <= 25))) {
		FlatVector::SetNull(vector, row, true);
		return;
	}
	if (column < CONNECTION_COLUMN_COUNT) {
		SetConnectionValue(vector, row, column, filename, key);
		return;
	}
	switch (column) {
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
		SetStringCell(vector, row, stream.finalized_by);
		break;
	case 14:
		SetStringCell(vector, row, packetquapture::TcpStreamStatusName(stream.status));
		break;
	case 15:
		SetOptionalText(vector, row, stream.error);
		break;
	default:
		SetStreamCaptureValue(vector, row, column, stream);
		break;
	}
}
static void TcpStreamsScan(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
	auto &bind = input.bind_data->Cast<PcapBindData>();
	auto &global = input.global_state->Cast<StreamGlobalState>();
	auto &state = input.local_state->Cast<StreamScanState>();
	if (!AdmitStreamWorker(global, state)) {
		return;
	}
	idx_t count = 0, output_bytes = 0;
	while (count < STANDARD_VECTOR_SIZE && output_bytes < STREAM_OUTPUT_BATCH_BYTES) {
		if (context.IsInterrupted()) {
			throw InterruptException();
		}
		auto &event = state.event;
		if (!NextStreamEvent(context, bind, global, state, event)) {
			break;
		}
		for (idx_t i = 0; i < global.columns.size(); ++i) {
			if (!bind.SetPartition(output.data[i], count, global.columns[i], state.file_index)) {
				SetStreamValue(output.data[i], count, global.columns[i], state.filename, event.stream);
			}
		}
		output_bytes += ROW_BASE_BYTES + state.filename.size() + event.stream.captured_bytes * PAYLOAD_COPIES +
		                (event.stream.chunks.size() + event.stream.gaps.size()) * ROW_BASE_BYTES;
		++count;
	}
	output.SetCardinality(count);
	if (!count) {
		ReleaseStreamWorker(bind, state);
	}
}

struct FlowGlobalState : public CaptureGlobalState {
	FlowGlobalState(ClientContext &context, const PcapBindData &bind)
	    : scheduler(bind.selected_indices.size()), file_count(bind.selected_indices.size()) {
		budget = context.registered_state->GetOrCreate<FlowQueryBudget>("packetquapture_flow_budget", context);
		if (bind.flow_plan) {
			bind.flow_plan->sealed.store(true);
			PQ_ASSERT(bind.flow_plan->scans.load() > 0); // bind registered this scan
			max_workers = MaxValue<idx_t>(1, budget->Slots() / bind.flow_plan->scans.load());
		}
		max_workers = MinValue<idx_t>(max_workers, MaxValue<idx_t>(1, file_count));
		if (file_count) {
			initial = make_uniq<FlowReservation>(budget);
			if (!initial->Acquired()) {
				throw OutOfMemoryException("PacketQuapture cannot reserve %llu MiB for a flow worker. "
				                           "Increase packetquapture_flow_memory_mb or memory_limit; "
				                           "all flow scans in this query share the budget.",
				                           FLOW_WORKER_BYTES / (1024 * 1024));
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
		PQ_ASSERT(admitted <= max_workers);
		if (initial) {
			return std::move(initial);
		}
		auto result = make_uniq<FlowReservation>(budget);
		if (!result->Acquired()) {
			// The slot goes back, so a later worker can still try the budget.
			--admitted;
			return nullptr;
		}
		return result;
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
};

struct FlowScanState : public LocalTableFunctionState {
	unique_ptr<FlowReservation> reservation;
	idx_t file_index = 0;
	bool initialized = false, finished = false;
	unique_ptr<CaptureReader> reader;
	unique_ptr<packetquapture::FlowAggregator> aggregator;
	PacketRecord record; // reused for every packet
};
static unique_ptr<LocalTableFunctionState> FlowsInitLocal(ExecutionContext &, TableFunctionInitInput &,
                                                          GlobalTableFunctionState *) {
	return make_uniq<FlowScanState>();
}
// read_flows column groups, in schema order; FlowsBind checks them against the names.
static const column_t FLOW_COUNTER_COLUMNS_BEGIN = 15;
static const column_t FLOW_STATE_COLUMNS_BEGIN = 28;

// read_flows's schema, one column per line so each name sits beside its type.
static void FlowsSchema(vector<LogicalType> &types, vector<string> &names) {
	types.clear();
	names.clear();
	auto column = [&](const char *name, const LogicalType &type) {
		names.emplace_back(name);
		types.push_back(type);
	};
	column("filename", LogicalType::VARCHAR);
	column("input_index", LogicalType::UBIGINT);
	column("flow_id", LogicalType::UBIGINT);
	column("section_number", LogicalType::UINTEGER);
	column("interface_id", LogicalType::UINTEGER);
	column("vlan_ids", LogicalType::LIST(LogicalType::USMALLINT));
	column("first_packet_number", LogicalType::UBIGINT);
	column("last_packet_number", LogicalType::UBIGINT);
	column("transport", LogicalType::VARCHAR);
	column("ip_version", LogicalType::UTINYINT);
	column("orig_ip", LogicalType::VARCHAR);
	column("orig_port", LogicalType::USMALLINT);
	column("resp_ip", LogicalType::VARCHAR);
	column("resp_port", LogicalType::USMALLINT);
	column("originator_basis", LogicalType::VARCHAR);
	column("orig_packets", LogicalType::UBIGINT);
	column("resp_packets", LogicalType::UBIGINT);
	column("orig_captured_bytes", LogicalType::UBIGINT);
	column("resp_captured_bytes", LogicalType::UBIGINT);
	column("orig_reported_bytes", LogicalType::UBIGINT);
	column("resp_reported_bytes", LogicalType::UBIGINT);
	column("orig_payload_bytes", LogicalType::UBIGINT);
	column("resp_payload_bytes", LogicalType::UBIGINT);
	column("first_timestamp", LogicalType::TIMESTAMP);
	column("last_timestamp", LogicalType::TIMESTAMP);
	column("duration", LogicalType::INTERVAL);
	column("missing_timestamp_packets", LogicalType::UBIGINT);
	column("late_packets", LogicalType::UBIGINT);
	column("orig_tcp_flags", LogicalType::USMALLINT);
	column("resp_tcp_flags", LogicalType::USMALLINT);
	column("handshake_complete", LogicalType::BOOLEAN);
	column("syn_seen", LogicalType::BOOLEAN);
	column("fin_seen", LogicalType::BOOLEAN);
	column("reset_seen", LogicalType::BOOLEAN);
	column("simultaneous_open", LogicalType::BOOLEAN);
	column("equal_endpoints", LogicalType::BOOLEAN);
	column("partial_session", LogicalType::BOOLEAN);
	column("ambiguous", LogicalType::BOOLEAN);
	column("finalized_by", LogicalType::VARCHAR);
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
			const auto micros = IdleTimeoutMicros(entry.second, "Flow");
			if (StringUtil::CIEquals(entry.first, "tcp_idle_timeout")) {
				bind.flow_limits.tcp_idle_us = micros;
			} else {
				bind.flow_limits.udp_idle_us = micros;
			}
		}
	}
	FlowsSchema(types, names);
	// The cell writers find column groups by position.
	PQ_ASSERT(names.size() == 39);
	PQ_ASSERT(names[FLOW_COUNTER_COLUMNS_BEGIN] == "orig_packets");
	PQ_ASSERT(names[FLOW_STATE_COLUMNS_BEGIN] == "orig_tcp_flags");
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
// The session's identity: file, ids, endpoints and how its originator was chosen.
static void SetFlowKeyValue(Vector &v, idx_t row, column_t col, const PcapBindData &bind, idx_t file,
                            const packetquapture::FlowSummary &flow) {
	PQ_ASSERT(col < FLOW_COUNTER_COLUMNS_BEGIN);
	const auto &orig = flow.orig_is_low ? flow.key.low : flow.key.high;
	const auto &resp = flow.orig_is_low ? flow.key.high : flow.key.low;
	const bool tcp = flow.key.protocol == 6;
	switch (col) {
	case 0:
		SetStringCell(v, row, bind.files[file].path);
		break;
	case 1:
		SetDecodedScalar<uint64_t>(v, row, file + 1);
		break;
	case 2:
		SetDecodedScalar<uint64_t>(v, row, FlowScanId(flow.first_packet, file, bind.files.size()));
		break;
	case 3:
		SetDecodedScalar<uint32_t>(v, row, flow.section);
		break;
	case 4:
		SetDecodedScalar<uint32_t>(v, row, flow.key.interface_id);
		break;
	case 5:
		PQ_ASSERT(flow.key.vlan_count <= flow.key.vlans.size());
		SetScalarListCell(v, row, flow.key.vlans.data(), flow.key.vlan_count);
		break;
	case 6:
		SetDecodedScalar<uint64_t>(v, row, flow.first_packet);
		break;
	case 7:
		SetDecodedScalar<uint64_t>(v, row, flow.last_packet);
		break;
	case 8:
		if (tcp) {
			SetStringCell(v, row, "tcp", 3);
		} else {
			SetStringCell(v, row, "udp", 3);
		}
		break;
	case 9:
		SetDecodedScalar<uint8_t>(v, row, flow.key.ip_version);
		break;
	case 10:
		SetIpCell(v, row, orig.ip, flow.key.ip_version);
		break;
	case 11:
		SetDecodedScalar<uint16_t>(v, row, orig.port);
		break;
	case 12:
		SetIpCell(v, row, resp.ip, flow.key.ip_version);
		break;
	case 13:
		SetDecodedScalar<uint16_t>(v, row, resp.port);
		break;
	case 14:
		SetStringCell(v, row, flow.originator_basis);
		break;
	default:
		throw InternalException("Unexpected read_flows key column id %d", col);
	}
}

// Per-direction counters and the session's timing.
static void SetFlowCounterValue(Vector &v, idx_t row, column_t col, const packetquapture::FlowSummary &flow) {
	PQ_ASSERT(col >= FLOW_COUNTER_COLUMNS_BEGIN && col < FLOW_STATE_COLUMNS_BEGIN);
	switch (col) {
	case 15:
		SetDecodedScalar<uint64_t>(v, row, flow.orig.packets);
		break;
	case 16:
		SetDecodedScalar<uint64_t>(v, row, flow.resp.packets);
		break;
	case 17:
		SetDecodedScalar<uint64_t>(v, row, flow.orig.captured_bytes);
		break;
	case 18:
		SetDecodedScalar<uint64_t>(v, row, flow.resp.captured_bytes);
		break;
	case 19:
		SetDecodedScalar<uint64_t>(v, row, flow.orig.reported_bytes);
		break;
	case 20:
		SetDecodedScalar<uint64_t>(v, row, flow.resp.reported_bytes);
		break;
	case 21:
		SetDecodedScalar<uint64_t>(v, row, flow.orig.payload_bytes);
		break;
	case 22:
		SetDecodedScalar<uint64_t>(v, row, flow.resp.payload_bytes);
		break;
	case 23:
		SetDecodedScalar<timestamp_t>(v, row, timestamp_t(flow.first_timestamp));
		break;
	case 24:
		SetDecodedScalar<timestamp_t>(v, row, timestamp_t(flow.last_timestamp));
		break;
	case 25: {
		// The aggregator keeps first and last as the minimum and maximum seen, so
		// the duration is never negative and only the overflow needs a check.
		PQ_ASSERT(flow.last_timestamp >= flow.first_timestamp);
		if (flow.first_timestamp < 0 &&
		    flow.last_timestamp > NumericLimits<int64_t>::Maximum() + flow.first_timestamp) {
			throw OutOfRangeException("Flow duration exceeds INTERVAL microsecond capacity");
		}
		interval_t duration {0, 0, flow.last_timestamp - flow.first_timestamp};
		SetDecodedScalar<interval_t>(v, row, duration);
		break;
	}
	case 26:
		SetDecodedScalar<uint64_t>(v, row, flow.missing_timestamps);
		break;
	case 27:
		SetDecodedScalar<uint64_t>(v, row, flow.late_packets);
		break;
	default:
		throw InternalException("Unexpected read_flows counter column id %d", col);
	}
}

// TCP flags and the session-state flags derived from them.
static void SetFlowStateValue(Vector &v, idx_t row, column_t col, const packetquapture::FlowSummary &flow) {
	PQ_ASSERT(col >= FLOW_STATE_COLUMNS_BEGIN);
	const bool tcp = flow.key.protocol == 6;
	switch (col) {
	case 28:
		SetDecodedScalar<uint16_t>(v, row, flow.orig.flags);
		break;
	case 29:
		SetDecodedScalar<uint16_t>(v, row, flow.resp.flags);
		break;
	case 30:
		SetDecodedScalar<bool>(v, row, flow.handshake_complete);
		break;
	case 31:
		SetDecodedScalar<bool>(v, row, flow.syn_seen);
		break;
	case 32:
		SetDecodedScalar<bool>(v, row, flow.fin_seen);
		break;
	case 33:
		SetDecodedScalar<bool>(v, row, flow.reset_seen);
		break;
	case 34:
		SetDecodedScalar<bool>(v, row, flow.simultaneous_open);
		break;
	case 35:
		SetDecodedScalar<bool>(v, row, flow.equal_endpoints);
		break;
	case 36:
		SetDecodedScalar<bool>(v, row,
		                       !tcp || !flow.handshake_complete ||
		                           (!flow.reset_seen && !((flow.orig.flags & packetquapture::TCP_FIN) &&
		                                                  (flow.resp.flags & packetquapture::TCP_FIN))));
		break;
	case 37:
		SetDecodedScalar<bool>(v, row,
		                       flow.equal_endpoints || flow.simultaneous_open || flow.late_packets ||
		                           flow.missing_timestamps || flow.originator_basis == "first_packet");
		break;
	case 38:
		SetStringCell(v, row, flow.finalized_by);
		break;
	default:
		throw InternalException("Unexpected read_flows column id %d", col);
	}
}

static void SetFlowValue(Vector &v, idx_t row, column_t col, const PcapBindData &bind, idx_t file,
                         const packetquapture::FlowSummary &flow) {
	const bool tcp = flow.key.protocol == 6;
	if ((!tcp && col >= 28 && col <= 34) || ((col == 23 || col == 24) && !flow.has_timestamp) ||
	    (col == 25 && (!flow.has_timestamp || flow.missing_timestamps))) {
		FlatVector::SetNull(v, row, true);
		return;
	}
	if (col < FLOW_COUNTER_COLUMNS_BEGIN) {
		SetFlowKeyValue(v, row, col, bind, file, flow);
	} else if (col < FLOW_STATE_COLUMNS_BEGIN) {
		SetFlowCounterValue(v, row, col, flow);
	} else {
		SetFlowStateValue(v, row, col, flow);
	}
}
// What the aggregator needs of a packet; its decoded headers are moved out.
static packetquapture::FlowInput FlowInputOf(PacketRecord &record) {
	packetquapture::FlowInput packet;
	packet.section = record.section_number;
	packet.interface_id = record.interface_id;
	packet.captured_length = record.captured_length;
	packet.original_length = record.original_length;
	packet.stamp = Stamp(record);
	packet.packet = std::move(record.decoded);
	return packet;
}

static void FlowsScan(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
	auto &bind = input.bind_data->Cast<PcapBindData>();
	auto &global = input.global_state->Cast<FlowGlobalState>();
	auto &state = input.local_state->Cast<FlowScanState>();
	if (!state.initialized) {
		state.initialized = true;
		state.reservation = global.file_count ? global.Admit() : nullptr;
	}
	if (!state.reservation) {
		return;
	}
	idx_t count = 0, bytes = 0;
	while (count < STANDARD_VECTOR_SIZE && bytes < FLOW_OUTPUT_BATCH_BYTES) {
		if (context.IsInterrupted()) {
			throw InterruptException();
		}
		if (!state.reader) {
			idx_t work;
			if (!global.scheduler.Claim(work)) {
				break;
			}
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
		} catch (const packetquapture::AssertionFailure &) {
			throw;
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
			bytes += ROW_BASE_BYTES + bind.files[state.file_index].path.size();
			++count;
			continue;
		}
		if (state.finished) {
			state.aggregator.reset();
			state.reader.reset();
			global.Drained();
			continue;
		}
		auto &record = state.record;
		if (!state.reader->Next(record)) {
			state.aggregator->Finish(state.reader->SectionNumber());
			state.finished = true;
			continue;
		}
		state.aggregator->Push(FlowInputOf(record));
	}
	output.SetCardinality(count);
	if (!count) {
		state.aggregator.reset();
		state.reader.reset();
		state.record = PacketRecord();
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
	types.clear();
	names.clear();
	auto column = [&](const char *name, const LogicalType &type) {
		names.emplace_back(name);
		types.push_back(type);
	};
	column("filename", LogicalType::VARCHAR);
	column("input_index", LogicalType::UBIGINT);
	column("identity_type", LogicalType::VARCHAR);
	column("identity_value", LogicalType::VARCHAR);
	column("identity_strength", LogicalType::VARCHAR);
	column("file_size", LogicalType::UBIGINT);
	column("modification_time", LogicalType::TIMESTAMP);
	column("capture_format", LogicalType::VARCHAR);
	column("link_types", LogicalType::LIST(LogicalType::UINTEGER));
	column("packet_count", LogicalType::UBIGINT);
	column("min_timestamp", LogicalType::TIMESTAMP);
	column("max_timestamp", LogicalType::TIMESTAMP);
	column("timestamp_null_count", LogicalType::UBIGINT);
	column("captured_bytes", LogicalType::UBIGINT);
	column("reported_bytes", LogicalType::UBIGINT);
	column("detail", LogicalType::VARCHAR);
	column("ipv4_packets", LogicalType::UBIGINT);
	column("ipv6_packets", LogicalType::UBIGINT);
	column("tcp_packets", LogicalType::UBIGINT);
	column("udp_packets", LogicalType::UBIGINT);
	column("other_protocol_packets", LogicalType::UBIGINT);
	column("malformed_packets", LogicalType::UBIGINT);
	column("unsupported_packets", LogicalType::UBIGINT);
	column("fragment_packets", LogicalType::UBIGINT);
	column("scan_status", LogicalType::VARCHAR);
	column("scan_error", LogicalType::VARCHAR);
	column("inventory_time", LogicalType::TIMESTAMP);
	column("source_scan_time", LogicalType::TIMESTAMP);
	column("schema_version", LogicalType::UINTEGER);
	column("semantic_version", LogicalType::UINTEGER);
	column("metadata_unchanged", LogicalType::BOOLEAN);
	column("reused", LogicalType::BOOLEAN);
	column("catalog_validation", LogicalType::VARCHAR);
	column("reuse_reason", LogicalType::VARCHAR);
	PQ_ASSERT(names.size() == types.size());
	PQ_ASSERT(names.size() == IC_COUNT);
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
		if (plan) {
			plan->scans.fetch_add(1);
		}
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
	if (!table.IsDuckTable()) {
		throw BinderException("previous_catalog must name a native DuckDB table");
	}
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
// A remote locator names the same object on every read only without a query
// string or fragment (signed or versioned URLs) and without user information in
// its authority. One rule serves inventory and catalog pruning, so a locator
// either may be summarised and later trusted, or neither.
static bool StableRemoteLocator(const string &path) {
	PQ_ASSERT(FileSystem::IsRemoteFile(path));
	if (path.find('?') != string::npos || path.find('#') != string::npos) {
		return false;
	}
	auto authority = path.find("://");
	auto end = authority == string::npos ? 0 : path.find('/', authority + 3);
	auto at = path.find('@', authority == string::npos ? 0 : authority + 3);
	return at == string::npos || (end != string::npos && at > end);
}
static void ValidateInventoryLocator(const string &path) {
	if (FileSystem::IsRemoteFile(path) && !StableRemoteLocator(path)) {
		throw InvalidInputException("Inventory requires stable remote locators without query strings, fragments, or "
		                            "user information; use DuckDB credentials");
	}
}
static unique_ptr<FunctionData> InventoryBind(ClientContext &context, TableFunctionBindInput &input,
                                              vector<LogicalType> &types, vector<string> &names) {
	auto result = make_uniq<InventoryBindData>();
	result->paths = MultiFileReader::Create(input.table_function)->ParsePaths(input.inputs[0]);
	for (const auto &path : result->paths) {
		ValidateInventoryLocator(path);
	}
	for (auto &entry : input.named_parameters) {
		if (entry.second.IsNull()) {
			throw BinderException("Inventory option '%s' must not be NULL", entry.first);
		}
		auto value = entry.second.GetValue<string>();
		if (StringUtil::CIEquals(entry.first, "previous_catalog")) {
			result->previous = BindInventoryCatalog(context, value);
		} else {
			value = StringUtil::Lower(value);
			if (StringUtil::CIEquals(entry.first, "detail")) {
				if (value != "framing" && value != "protocols") {
					throw BinderException("detail must be framing or protocols");
				}
				result->protocols = value == "protocols";
			} else if (StringUtil::CIEquals(entry.first, "on_error")) {
				if (value != "error" && value != "report") {
					throw BinderException("on_error must be error or report");
				}
				result->report = value == "report";
			} else if (StringUtil::CIEquals(entry.first, "catalog_validation")) {
				if (value != "strict" && value != "immutable") {
					throw BinderException("catalog_validation must be strict or immutable");
				}
				result->immutable = value == "immutable";
			} else {
				// DuckDB rejects options the function did not register.
				throw InternalException("Unhandled capture_inventory option '%s'", entry.first);
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
		if (context.IsInterrupted()) {
			throw InterruptException();
		}
		if (FileSystem::HasGlob(path)) {
			auto expanded = reader->CreateFileList(context, vector<string> {path})->GetAllFiles();
			for (auto &file : expanded) {
				ValidateInventoryLocator(file.path);
				files.push_back(std::move(file));
			}
		} else {
			files.emplace_back(path);
		}
	}
	auto &fs = FileSystem::GetFileSystem(context);
	for (auto &file : files) {
		if (!FileSystem::IsRemoteFile(file.path)) {
			file.path = fs.CanonicalizePath(file.path);
		}
	}
	return files;
}
struct InventoryPrevious {
	vector<Value> row;
	bool conflict = false;
};
// Native Values retained outside DuckDB vectors are conservatively charged, with
// an explicit snapshot cap. This is metadata, not a second capture cache.
constexpr idx_t INVENTORY_SNAPSHOT_BYTES = 64ULL * 1024 * 1024;
class InventorySnapshotMemory {
public:
	explicit InventorySnapshotMemory(ClientContext &context) : manager(BufferManager::GetBufferManager(context)) {
	}
	~InventorySnapshotMemory() {
		if (used) {
			manager.FreeReservedMemory(used);
		}
	}
	void Add(idx_t bytes) {
		PQ_ASSERT(used <= INVENTORY_SNAPSHOT_BYTES);
		if (bytes > INVENTORY_SNAPSHOT_BYTES - used) {
			throw OutOfMemoryException("Inventory previous_catalog snapshot exceeds %llu MiB",
			                           INVENTORY_SNAPSHOT_BYTES / (1024 * 1024));
		}
		manager.ReserveMemory(bytes);
		used += bytes;
	}

private:
	BufferManager &manager;
	idx_t used = 0;
};
static bool InventoryAgreement(const vector<Value> &a, const vector<Value> &b) {
	for (idx_t i = IC_ID_TYPE; i <= IC_STABLE; ++i) {
		if (i == IC_TIME || i == IC_SCAN_TIME) {
			continue;
		}
		if (!Value::NotDistinctFrom(a[i], b[i])) {
			return false;
		}
	}
	return true;
}
// Reads the catalog rows for the wanted files. The range of wanted filenames goes
// to the storage scan as a filter, so row groups outside it are skipped by their
// zone maps and the rest are filtered vectorised, not a Value per row; the
// wanted check below stays as the exact test. (Raw storage scans support
// constant comparisons, not IN.) The loop ends when the transaction's snapshot
// runs out.
// Copies catalog row n into values; returns the memory the copy holds, charged
// conservatively as Values are larger than their payload.
static idx_t SnapshotRow(DataChunk &chunk, idx_t n, const string &file, vector<Value> &values) {
	idx_t bytes = 512 + file.size() * 2;
	for (idx_t c = 0; c < IC_COUNT; ++c) {
		auto value = chunk.GetValue(c, n);
		bytes += sizeof(Value) * 2;
		if (!value.IsNull() && value.type().id() == LogicalTypeId::VARCHAR) {
			bytes += StringValue::Get(value).size() * 2;
		}
		if (!value.IsNull() && c == IC_LINKS) {
			bytes += ListValue::GetChildren(value).size() * sizeof(Value) * 2;
		}
		values.push_back(std::move(value));
	}
	return bytes;
}

static void LoadInventorySnapshot(ClientContext &context, TableCatalogEntry &table, const vector<StorageIndex> &ids,
                                  const vector<OpenFileInfo> &files, InventorySnapshotMemory &snapshot_memory,
                                  unordered_map<string, InventoryPrevious> &previous) {
	PQ_ASSERT(ids.size() == IC_COUNT);
	PQ_ASSERT(!files.empty());
	unordered_set<string> wanted;
	string lowest = files[0].path, highest = files[0].path;
	for (const auto &file : files) {
		if (wanted.insert(file.path).second) {
			snapshot_memory.Add(128 + file.path.size() * 2);
			lowest = MinValue(lowest, file.path);
			highest = MaxValue(highest, file.path);
		}
	}
	auto &transaction = DuckTransaction::Get(context, table.catalog);
	auto &storage = table.GetStorage();
	TableFilterSet filters;
	auto range = make_uniq<ConjunctionAndFilter>();
	range->child_filters.push_back(
	    make_uniq<ConstantFilter>(ExpressionType::COMPARE_GREATERTHANOREQUALTO, Value(lowest)));
	range->child_filters.push_back(
	    make_uniq<ConstantFilter>(ExpressionType::COMPARE_LESSTHANOREQUALTO, Value(highest)));
	filters.PushFilter(ColumnIndex(IC_FILE), std::move(range));
	TableScanState scan;
	storage.InitializeScan(context, transaction, scan, ids, &filters);
	vector<LogicalType> types;
	vector<string> names;
	InventorySchema(types, names);
	DataChunk chunk;
	chunk.Initialize(context, types);
	while (true) {
		if (context.IsInterrupted()) {
			throw InterruptException();
		}
		chunk.Reset();
		storage.Scan(transaction, chunk, scan);
		if (!chunk.size()) {
			break;
		}
		for (idx_t n = 0; n < chunk.size(); ++n) {
			auto file_value = chunk.GetValue(IC_FILE, n);
			if (file_value.IsNull()) {
				continue;
			}
			// Read once: the name is looked up, charged and stored for each row.
			const auto file = file_value.GetValue<string>();
			if (!wanted.count(file)) {
				continue;
			}
			vector<Value> values;
			const idx_t bytes = SnapshotRow(chunk, n, file, values);
			auto found = previous.find(file);
			if (found == previous.end()) {
				snapshot_memory.Add(bytes);
				InventoryPrevious entry;
				entry.row = std::move(values);
				previous.emplace(file, std::move(entry));
			} else if (!InventoryAgreement(found->second.row, values)) {
				found->second.conflict = true;
			}
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
		PQ_ASSERT(bind.plan->scans.load() > 0); // bind registered this scan
		max_workers = MinValue<idx_t>(MaxValue<idx_t>(1, files.size()),
		                              MaxValue<idx_t>(1, budget->Slots() / bind.plan->scans.load()));
		if (!files.empty()) {
			initial = make_uniq<InventoryReservation>(budget);
			if (!initial->Acquired()) {
				throw OutOfMemoryException("PacketQuapture cannot reserve %llu MiB for an inventory worker; increase "
				                           "packetquapture_inventory_memory_mb or memory_limit",
				                           INVENTORY_WORKER_BYTES / (1024 * 1024));
			}
		}
		if (!bind.previous.empty() && !files.empty()) {
			vector<StorageIndex> ids;
			auto &table = InventoryCatalog(context, bind.previous, ids);
			LoadInventorySnapshot(context, table, ids, files, snapshot_memory, previous);
		}
		progress.Initialize(context, files, true);
	}
	idx_t MaxThreads() const override {
		return max_workers;
	}
	unique_ptr<InventoryReservation> Admit() {
		lock_guard<mutex> guard(lock);
		if (admitted >= max_workers) {
			return nullptr;
		}
		++admitted;
		PQ_ASSERT(admitted <= max_workers);
		if (initial) {
			return std::move(initial);
		}
		auto result = make_uniq<InventoryReservation>(budget);
		if (!result->Acquired()) {
			// The slot goes back, so a later worker can still try the budget.
			--admitted;
			return nullptr;
		}
		return result;
	}
	void Drained() {
		if (drained.fetch_add(1) + 1 == files.size()) {
			progress.Finish();
		}
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
// Whether a file's identity now matches a catalog row's. The one rule for reuse
// in capture_inventory and for pruning in read_pcap(catalog=...), so a summary
// trusted by one is trusted by the other.
static bool InventoryIdentityMatches(const CaptureIdentity &identity, const vector<Value> &current,
                                     const vector<Value> &old) {
	PQ_ASSERT(current.size() == IC_COUNT);
	PQ_ASSERT(old.size() == IC_COUNT);
	if (!identity.Known()) {
		return false;
	}
	for (idx_t col = IC_ID_TYPE; col <= IC_MTIME; ++col) {
		if (!Value::NotDistinctFrom(current[col], old[col])) {
			return false;
		}
	}
	return true;
}
static bool InventoryValidPrevious(const vector<Value> &row, bool protocols) {
	auto equal = [&](idx_t col, Value value) {
		return Value::NotDistinctFrom(row[col], value);
	};
	if (!equal(IC_SCHEMA, Value::UINTEGER(1)) || !equal(IC_SEMANTICS, Value::UINTEGER(1)) ||
	    !equal(IC_STATUS, Value("complete")) || !equal(IC_STABLE, Value(true)) || !row[IC_ERROR].IsNull()) {
		return false;
	}
	if (!equal(IC_DETAIL, Value("protocols")) && (protocols || !equal(IC_DETAIL, Value("framing")))) {
		return false;
	}
	if (!equal(IC_FORMAT, Value("pcap")) && !equal(IC_FORMAT, Value("pcapng"))) {
		return false;
	}
	for (idx_t col : {IC_PACKETS, IC_NULLS, IC_CAPTURED, IC_REPORTED, IC_LINKS}) {
		if (row[col].IsNull()) {
			return false;
		}
	}
	auto packets = row[IC_PACKETS].GetValue<uint64_t>(), nulls = row[IC_NULLS].GetValue<uint64_t>();
	if (nulls > packets || row[IC_MIN].IsNull() != row[IC_MAX].IsNull() || row[IC_MIN].IsNull() != (nulls == packets)) {
		return false;
	}
	if (row[IC_SCAN_TIME].IsNull() || !Timestamp::IsFinite(row[IC_SCAN_TIME].GetValue<timestamp_t>())) {
		return false;
	}
	if (!row[IC_MIN].IsNull() && (!Timestamp::IsFinite(row[IC_MIN].GetValue<timestamp_t>()) ||
	                              !Timestamp::IsFinite(row[IC_MAX].GetValue<timestamp_t>()) ||
	                              row[IC_MIN].GetValue<timestamp_t>() > row[IC_MAX].GetValue<timestamp_t>())) {
		return false;
	}
	const auto &links = ListValue::GetChildren(row[IC_LINKS]);
	// Link types are 16 bits, so a summary can list at most 65536 of them.
	if ((packets && links.empty()) || links.size() > 65536) {
		return false;
	}
	uint32_t last = 0;
	bool first = true;
	for (const auto &link : links) {
		if (link.IsNull()) {
			return false;
		}
		auto value = link.GetValue<uint32_t>();
		if (!first && value <= last) {
			return false;
		}
		first = false;
		last = value;
	}
	if (equal(IC_DETAIL, Value("protocols"))) {
		for (idx_t col = IC_IPV4; col <= IC_FRAGMENTS; ++col) {
			if (row[col].IsNull() || row[col].GetValue<uint64_t>() > packets) {
				return false;
			}
		}
		auto remaining = packets;
		for (idx_t col : {IC_TCP, IC_UDP, IC_MALFORMED, IC_UNSUPPORTED, IC_FRAGMENTS}) {
			auto count = row[col].GetValue<uint64_t>();
			if (count > remaining) {
				return false;
			}
			remaining -= count;
		}
		if (remaining || row[IC_OTHER].GetValue<uint64_t>() > row[IC_UNSUPPORTED].GetValue<uint64_t>()) {
			return false;
		}
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
		if (conjunction.child_filters.empty()) {
			return false;
		}
		for (auto &child : conjunction.child_filters) {
			if (!CatalogTimestampFilter(*child)) {
				return false;
			}
		}
		return true;
	}
	default:
		return false;
	}
}
// Why a catalog summary cannot be trusted for this file's backend, or null when
// it can. Only local and HTTP(S) have measured freshness behavior for this
// milestone. S3/other backends fall back until provider tests pass.
static const char *CatalogBackendRefusal(ClientContext &context, const string &path) {
	if (!FileSystem::IsRemoteFile(path)) {
		return nullptr;
	}
	const char *refusal = nullptr;
	if (!StringUtil::StartsWith(path, "http://") && !StringUtil::StartsWith(path, "https://")) {
		return "unverified remote backend";
	}
	Value cached;
	if (context.TryGetCurrentSetting("enable_http_metadata_cache", cached) &&
	    (cached.IsNull() || cached.GetValue<bool>())) {
		refusal = "metadata cache enabled";
	}
	if (!StableRemoteLocator(path)) {
		refusal = "unstable remote locator";
	}
	return refusal;
}

// Whether a summary proves the file has no rows the time filter could keep.
static bool CatalogTimeExcludes(const vector<Value> &summary, const TableFilter &time_filter) {
	auto stats = NumericStats::CreateUnknown(LogicalType::TIMESTAMP);
	auto packets = summary[IC_PACKETS].GetValue<uint64_t>();
	auto nulls = summary[IC_NULLS].GetValue<uint64_t>();
	PQ_ASSERT(nulls <= packets); // InventoryValidPrevious checked it
	stats.Set(nulls ? StatsInfo::CAN_HAVE_NULL_VALUES : StatsInfo::CANNOT_HAVE_NULL_VALUES);
	stats.Set(packets > nulls ? StatsInfo::CAN_HAVE_VALID_VALUES : StatsInfo::CANNOT_HAVE_VALID_VALUES);
	if (packets > nulls) {
		NumericStats::SetMin(stats, summary[IC_MIN]);
		NumericStats::SetMax(stats, summary[IC_MAX]);
	}
	return packets == 0 || time_filter.CheckStatistics(stats) == FilterPropagateResult::FILTER_ALWAYS_FALSE;
}

// Decides one file of a pruned scan: exclude is set when its summary proves the
// time filter keeps none of its rows. Returns the reason, for EXPLAIN.
static string CatalogDecision(ClientContext &context, const OpenFileInfo &file,
                              const unordered_map<string, InventoryPrevious> &previous, const TableFilter &time_filter,
                              bool &exclude) {
	exclude = false;
	auto found = previous.find(file.path);
	if (found == previous.end()) {
		return "no matching summary";
	}
	const auto &old = found->second;
	if (old.conflict) {
		return "conflicting summaries";
	}
	if (!InventoryValidPrevious(old.row, false)) {
		return "incompatible summary";
	}
	const char *refusal = CatalogBackendRefusal(context, file.path);
	if (refusal != nullptr) {
		return refusal;
	}
	auto &fs = FileSystem::GetFileSystem(context);
	if (fs.IsPipe(file.path)) {
		throw InvalidInputException("Catalog validation requires seekable capture files");
	}
	auto handle = fs.OpenFile(file, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
	if (!handle->CanSeek() || handle->IsPipe()) {
		throw InvalidInputException("Catalog validation requires seekable capture files");
	}
	auto identity = ReadCaptureIdentity(fs, *handle);
	vector<LogicalType> types;
	vector<string> names;
	InventorySchema(types, names);
	vector<Value> current;
	for (auto &type : types) {
		current.emplace_back(type);
	}
	InventoryIdentityValues(current, identity);
	if (!InventoryIdentityMatches(identity, current, old.row)) {
		return "identity mismatch or unavailable";
	}
	exclude = CatalogTimeExcludes(old.row, time_filter);
	return exclude ? "time excluded" : "time may match";
}

static vector<idx_t> SelectCatalogFiles(ClientContext &context, const PcapBindData &bind, TableFunctionInitInput &input,
                                        map<string, idx_t> &reasons) {
	if (bind.catalog.empty() || bind.selected_indices.empty()) {
		return bind.selected_indices;
	}
	// Re-resolve the table in the execution's transaction, even in strict mode.
	vector<StorageIndex> ids;
	auto &table = InventoryCatalog(context, bind.catalog, ids);
	const TableFilter *time_filter = nullptr;
	if (input.filters) {
		for (auto &entry : input.filters->filters) {
			if (input.column_ids[entry.first] == PCAP_TIMESTAMP_COLUMN && CatalogTimestampFilter(*entry.second)) {
				time_filter = entry.second.get();
			}
		}
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
		if (!FileSystem::IsRemoteFile(file.path)) {
			file.path = fs.CanonicalizePath(file.path);
		}
		candidates.push_back(std::move(file));
	}
	InventorySnapshotMemory memory(context);
	unordered_map<string, InventoryPrevious> previous;
	LoadInventorySnapshot(context, table, ids, candidates, memory, previous);
	vector<idx_t> selected;
	for (idx_t n = 0; n < candidates.size(); ++n) {
		if (context.IsInterrupted()) {
			throw InterruptException();
		}
		auto &file = candidates[n];
		bool exclude = false;
		const auto reason = CatalogDecision(context, file, previous, *time_filter, exclude);
		++reasons[reason];
		if (!exclude) {
			selected.push_back(bind.selected_indices[n]);
		}
	}
	return selected;
}
static InsertionOrderPreservingMap<string> CatalogDynamicToString(TableFunctionDynamicToStringInput &input) {
	InsertionOrderPreservingMap<string> result;
	if (!input.global_state || input.bind_data->Cast<PcapBindData>().catalog.empty()) {
		return result;
	}
	auto &global = input.global_state->Cast<PcapGlobalState>();
	result["Runtime Selected Files"] = StringUtil::Format("%llu", global.selected_indices.size());
	for (auto &reason : global.catalog_reasons) {
		result["Catalog: " + reason.first] = StringUtil::Format("%llu", reason.second);
	}
	return result;
}
static void AddCatalogOptions(TableFunction &function) {
	function.named_parameters["catalog"] = LogicalType::VARCHAR;
	function.named_parameters["catalog_validation"] = LogicalType::VARCHAR;
	function.dynamic_to_string = CatalogDynamicToString;
}

// The row's columns that do not depend on reading the file.
static vector<Value> InventoryRow(const InventoryBindData &bind, const OpenFileInfo &file, idx_t index,
                                  const vector<LogicalType> &types) {
	vector<Value> row;
	for (const auto &type : types) {
		row.emplace_back(type);
	}
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
	return row;
}

// Fills the row from the previous catalog's summary when catalog_validation is
// immutable and the file's identity still matches it; otherwise records why not.
static bool ReuseInventorySummary(const InventoryBindData &bind, InventoryGlobalState &global, idx_t index,
                                  const CaptureIdentity &identity, vector<Value> &row) {
	auto found = global.previous.find(global.files[index].path);
	if (found == global.previous.end()) {
		return false;
	}
	const auto &old = found->second;
	row[IC_REASON] = Value(!bind.immutable ? "strict_requires_scan"
	                       : old.conflict  ? "conflicting_summaries"
	                                       : "incompatible_summary");
	if (!bind.immutable || old.conflict || !InventoryValidPrevious(old.row, bind.protocols)) {
		return false;
	}
	if (!InventoryIdentityMatches(identity, row, old.row)) {
		row[IC_REASON] = Value("identity_changed_or_unavailable");
		return false;
	}
	for (idx_t col = IC_FORMAT; col <= IC_FRAGMENTS; ++col) {
		row[col] = old.row[col];
	}
	row[IC_DETAIL] = Value(bind.protocols ? "protocols" : "framing");
	if (!bind.protocols) {
		for (idx_t col = IC_IPV4; col <= IC_FRAGMENTS; ++col) {
			row[col] = Value(LogicalType::UBIGINT);
		}
	}
	row[IC_STATUS] = Value("complete");
	row[IC_STABLE] = Value(true);
	row[IC_REUSED] = Value(true);
	row[IC_SCAN_TIME] = old.row[IC_SCAN_TIME];
	row[IC_REASON] = Value("immutable_metadata_match");
	// As the reader does: progress counts files only while it is enabled, so a
	// reused file is counted on the same terms.
	if (global.progress.Enabled()) {
		global.progress.CheckSize(index, true, identity.size < 0 ? 0 : identity.size);
		if (identity.size >= 0) {
			global.progress.Advance(identity.size);
		}
		global.progress.CompleteFile();
	}
	return true;
}

// The totals a full read of the file produced.
static void SetInventoryTotals(const InventoryBindData &bind, CaptureReader &reader, const InventoryTotals &totals,
                               vector<Value> &row) {
	row[IC_FORMAT] = Value(reader.InventoryFormat());
	vector<Value> links;
	for (auto link : reader.InventoryLinks()) {
		links.push_back(Value::UINTEGER(link));
	}
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
		static_assert(IC_FRAGMENTS - IC_IPV4 + 1 == 8, "counts[] lists one value per protocol column");
		for (idx_t i = 0; i < 8; ++i) {
			row[IC_IPV4 + i] = Value::UBIGINT(counts[i]);
		}
	}
	row[IC_STATUS] = Value(reader.SawTruncatedTail() ? "truncated" : "complete");
}

// Reads the whole file, then checks its identity did not change while it was
// read; changed is set when it did.
static void ScanInventory(ClientContext &context, const InventoryBindData &bind, InventoryGlobalState &global,
                          idx_t index, const CaptureIdentity &identity, vector<Value> &row, bool &changed) {
	auto &fs = FileSystem::GetFileSystem(context);
	const auto &file = global.files[index];
	CaptureReader reader(context, file, global.options, &global.progress, index);
	auto before = reader.InventoryBefore();
	InventoryIdentityValues(row, before);
	InventoryTotals totals;
	PacketRecord record;
	while (reader.Next(record)) {
		if (context.IsInterrupted()) {
			throw InterruptException();
		}
		totals.Observe(record.has_timestamp, record.timestamp, record.captured_length, record.original_length,
		               record.decoded, bind.protocols);
	}
	auto after = reader.InventoryAfter();
	auto verify = fs.OpenFile(file, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
	auto current = ReadCaptureIdentity(fs, *verify);
	changed = !identity.Same(before) || !before.Same(after) || !after.Same(current);
	if (changed) {
		throw InvalidInputException("Capture identity changed during inventory");
	}
	SetInventoryTotals(bind, reader, totals, row);
	row[IC_STABLE] = before.Known() ? Value(true) : Value(LogicalType::BOOLEAN);
}

// With on_error=report, a capture's own failure becomes its row. An interrupt,
// exhausted memory or a broken invariant fails the query instead: report is for
// bad files, not for bugs in this code or the engine.
static void ReportInventoryError(const InventoryBindData &bind, const OpenFileInfo &file,
                                 const vector<LogicalType> &types, const ErrorData &error, bool changed,
                                 vector<Value> &row) {
	for (idx_t col = IC_FORMAT; col <= IC_FRAGMENTS; ++col) {
		if (col != IC_DETAIL) {
			row[col] = Value(types[col]);
		}
	}
	row[IC_STATUS] = Value(changed ? "changed" : "error");
	row[IC_ERROR] = Value(FileSystem::IsRemoteFile(file.path)
	                          ? "Remote inventory scan failed; rerun with on_error=error for provider details"
	                          : error.Message());
	row[IC_SCAN_TIME] = Value(LogicalType::TIMESTAMP);
	row[IC_STABLE] = Value(false);
}

static vector<Value> InventoryOne(ClientContext &context, const InventoryBindData &bind, InventoryGlobalState &global,
                                  idx_t index) {
	vector<LogicalType> types;
	vector<string> names;
	InventorySchema(types, names);
	const auto &file = global.files[index];
	auto row = InventoryRow(bind, file, index, types);
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
		if (fs.IsPipe(file.path)) {
			throw InvalidInputException("Inventory does not support named pipes");
		}
		auto probe = fs.OpenFile(file, FileFlags::FILE_FLAGS_READ | FileFlags::FILE_FLAGS_DIRECT_IO);
		if (!probe->CanSeek() || probe->IsPipe()) {
			throw InvalidInputException("Inventory requires seekable capture files");
		}
		auto identity = ReadCaptureIdentity(fs, *probe);
		InventoryIdentityValues(row, identity);
		if (ReuseInventorySummary(bind, global, index, identity, row)) {
			return row;
		}
		probe.reset();
		ScanInventory(context, bind, global, index, identity, row, changed);
	} catch (const packetquapture::AssertionFailure &) {
		throw;
	} catch (const std::exception &exception) {
		ErrorData error(exception);
		const auto type = error.Type();
		if (!bind.report || type == ExceptionType::INTERRUPT || type == ExceptionType::OUT_OF_MEMORY ||
		    type == ExceptionType::INTERNAL || type == ExceptionType::FATAL) {
			throw;
		}
		ReportInventoryError(bind, file, types, error, changed, row);
	}
	return row;
}
static void InventoryScan(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
	auto &bind = input.bind_data->Cast<InventoryBindData>();
	auto &global = input.global_state->Cast<InventoryGlobalState>();
	auto &local = input.local_state->Cast<InventoryLocalState>();
	if (!local.initialized) {
		local.initialized = true;
		if (!global.files.empty()) {
			local.reservation = global.Admit();
		}
	}
	if (!local.reservation) {
		return;
	}
	idx_t index;
	if (!global.scheduler.Claim(index)) {
		local.reservation.reset();
		return;
	}
	if (context.IsInterrupted()) {
		throw InterruptException();
	}
	auto row = InventoryOne(context, bind, global, index);
	PQ_ASSERT(row.size() == IC_COUNT);
	PQ_ASSERT(global.columns.size() == output.ColumnCount());
	for (idx_t c = 0; c < global.columns.size(); ++c) {
		PQ_ASSERT(global.columns[c] < IC_COUNT);
		output.data[c].SetValue(0, row[global.columns[c]]);
	}
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

// The worker memory settings, read_flows and capture_inventory.
static void RegisterBudgetedScans(ExtensionLoader &loader) {
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
	for (const auto *option : {"detail", "on_error", "previous_catalog", "catalog_validation"}) {
		inventory.named_parameters[option] = LogicalType::VARCHAR;
	}
	loader.RegisterFunction(MultiFileReader::CreateFunctionSet(inventory));
}

// The per-packet readers: read_pcap, read_packets and read_dns.
static void RegisterPacketReaders(ExtensionLoader &loader) {
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
}

// The readers built on TCP reassembly: read_dns_messages, read_tls and
// read_tcp_streams.
static void RegisterStreamReaders(ExtensionLoader &loader) {
	TableFunction messages("read_dns_messages", {LogicalType::VARCHAR}, DnsMessagesScan, BindCapture<DnsMessagesBind>,
	                       DnsMessagesInit, StreamInitLocal);
	messages.projection_pushdown = true;
	messages.table_scan_progress = CaptureScanProgress;
	messages.pushdown_complex_filter = PruneCaptureFiles;
	AddCaptureOptions(messages);
	messages.named_parameters["tcp_idle_timeout"] = LogicalType::INTERVAL;
	// Segment-level predicates could remove bytes required to reconstruct a matching message.
	loader.RegisterFunction(MultiFileReader::CreateFunctionSet(messages));
	TableFunction tls("read_tls", {LogicalType::VARCHAR}, TlsScan, BindCapture<TlsBind>, TlsInit, StreamInitLocal);
	tls.projection_pushdown = true;
	tls.table_scan_progress = CaptureScanProgress;
	// File-level pruning only: a segment-level predicate could remove bytes needed
	// to reconstruct a handshake that would have matched it.
	tls.pushdown_complex_filter = PruneCaptureFiles;
	AddCaptureOptions(tls);
	tls.named_parameters["tcp_idle_timeout"] = LogicalType::INTERVAL;
	loader.RegisterFunction(MultiFileReader::CreateFunctionSet(tls));
	TableFunction streams("read_tcp_streams", {LogicalType::VARCHAR}, TcpStreamsScan, BindCapture<TcpStreamsBind>,
	                      TcpStreamsInit, StreamInitLocal);
	streams.projection_pushdown = true;
	streams.table_scan_progress = CaptureScanProgress;
	streams.pushdown_complex_filter = PruneCaptureFiles;
	AddCaptureOptions(streams);
	streams.named_parameters["tcp_idle_timeout"] = LogicalType::INTERVAL;
	loader.RegisterFunction(MultiFileReader::CreateFunctionSet(streams));
}

static void LoadInternal(ExtensionLoader &loader) {
	RegisterPcapCopy(loader);
	loader.SetDescription("Query PCAP and PCAPNG packet captures directly from DuckDB");
	RegisterBudgetedScans(loader);
	RegisterPacketReaders(loader);
	RegisterStreamReaders(loader);
	RegisterTrafficAnalytics(loader);
	RegisterDnsAnalytics(loader);
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
