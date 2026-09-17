#define DUCKDB_EXTENSION_MAIN

#include "packetquapture_extension.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/multi_file/multi_file_reader.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "duckdb/function/function_set.hpp"
#include "duckdb/function/table_function.hpp"

#include <array>
#include <cmath>
#include <cstring>
#include <limits>

namespace duckdb {
namespace {

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
	uint32_t section_number = 0;
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

class CaptureReader {
public:
	CaptureReader(ClientContext &context, const OpenFileInfo &file_p, bool materialize_packet_data_p)
	    : file(file_p), fs(FileSystem::GetFileSystem(context)), materialize_packet_data(materialize_packet_data_p) {
		handle = fs.OpenFile(file, FileFlags::FILE_FLAGS_READ);
		Initialize();
	}

	bool Next(PacketRecord &record) {
		return format == CaptureFormat::PCAP ? NextPcap(record) : NextPcapNg(record);
	}

private:
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
		vector<uint8_t> remainder(block_length - 12);
		ReadExact(remainder.data(), remainder.size(), "PCAPNG section header");
		ValidateTrailer(remainder.data() + remainder.size() - 4, block_length);
		const auto major_version = ReadU16(remainder.data(), order);
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
		if (!materialize_packet_data) {
			Skip(length, "packet data");
			return;
		}
		record.packet_data.resize(length);
		ReadExact(record.packet_data.data(), length, "packet data");
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
			const auto bytes_read = handle->Read(static_cast<uint8_t *>(buffer) + total, length - total);
			if (bytes_read == 0) {
				if (total == 0) {
					return false;
				}
				throw IOException("Unexpected end of capture file '%s' at byte %d", file.path, position + total);
			}
			total += NumericCast<idx_t>(bytes_read);
		}
		position += length;
		return true;
	}

	void ReadExact(void *buffer, idx_t length, const char *description) {
		if (length > 0 && !ReadMaybe(buffer, length)) {
			throw IOException("Unexpected end of '%s' while reading %s", file.path, description);
		}
	}

	void Skip(idx_t length, const char *description) {
		std::array<uint8_t, 8192> buffer {};
		while (length > 0) {
			const auto chunk_size = MinValue<idx_t>(length, buffer.size());
			ReadExact(buffer.data(), chunk_size, description);
			length -= chunk_size;
		}
	}

private:
	OpenFileInfo file;
	FileSystem &fs;
	unique_ptr<FileHandle> handle;
	bool materialize_packet_data;
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

	unique_ptr<FunctionData> Copy() const override {
		auto result = make_uniq<PcapBindData>();
		result->files = files;
		return std::move(result);
	}

	bool Equals(const FunctionData &other_p) const override {
		auto &other = other_p.Cast<PcapBindData>();
		if (files.size() != other.files.size()) {
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

struct PcapGlobalState : public GlobalTableFunctionState {
	vector<column_t> column_ids;
	idx_t file_index = 0;
	unique_ptr<CaptureReader> reader;
	bool materialize_packet_data = false;
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
	return std::move(result);
}

static unique_ptr<GlobalTableFunctionState> PcapInit(ClientContext &context, TableFunctionInitInput &input) {
	auto result = make_uniq<PcapGlobalState>();
	result->column_ids = input.column_ids;
	for (const auto column_id : result->column_ids) {
		if (column_id == 9) {
			result->materialize_packet_data = true;
			break;
		}
	}
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

static void PcapScan(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
	auto &bind_data = input.bind_data->Cast<PcapBindData>();
	auto &state = input.global_state->Cast<PcapGlobalState>();
	idx_t output_count = 0;
	while (output_count < STANDARD_VECTOR_SIZE) {
		if (!state.reader) {
			if (state.file_index >= bind_data.files.size()) {
				break;
			}
			state.reader =
			    make_uniq<CaptureReader>(context, bind_data.files[state.file_index++], state.materialize_packet_data);
		}
		PacketRecord record;
		if (!state.reader->Next(record)) {
			state.reader.reset();
			continue;
		}
		for (idx_t output_column = 0; output_column < state.column_ids.size(); output_column++) {
			SetOutputValue(output.data[output_column], output_count, state.column_ids[output_column], record);
		}
		output_count++;
	}
	output.SetCardinality(output_count);
}

static TableFunction ReadPcapFunction() {
	TableFunction function("read_pcap", {LogicalType::VARCHAR}, PcapScan, PcapBind, PcapInit);
	function.projection_pushdown = true;
	return function;
}

static void LoadInternal(ExtensionLoader &loader) {
	loader.SetDescription("Query PCAP and PCAPNG packet captures directly from DuckDB");
	loader.RegisterFunction(MultiFileReader::CreateFunctionSet(ReadPcapFunction()));
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
