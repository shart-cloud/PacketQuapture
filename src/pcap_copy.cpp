#include "pcap_copy.hpp"
#include "pcap_writer.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/function/copy_function.hpp"
#include "duckdb/planner/binder.hpp"
#include "duckdb/planner/bound_statement.hpp"
#include "duckdb/planner/operator/logical_copy_to_file.hpp"
#include "duckdb/parser/query_node.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/types/uuid.hpp"
#include "duckdb/common/types/data_chunk.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/execution/execution_context.hpp"
#include <array>
#include <stdexcept>
#include <cerrno>
#include "duckdb/main/config.hpp"
#ifdef _WIN32
#include "duckdb/common/windows_util.hpp"
#include <io.h>
#include <fcntl.h>
#include <share.h>
#include <sys/stat.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace duckdb {
namespace {
struct PcapCopyBind : FunctionData {
	explicit PcapCopyBind(uint32_t link) : options(link) {
	}
	packetquapture::PcapWriterOptions options;
	string destination;
	std::array<idx_t, 5> columns;
	unique_ptr<FunctionData> Copy() const override {
		auto result = make_uniq<PcapCopyBind>(options.link_type);
		result->options = options;
		result->destination = destination;
		result->columns = columns;
		return std::move(result);
	}
	bool Equals(const FunctionData &other_p) const override {
		auto &other = other_p.Cast<PcapCopyBind>();
		return destination == other.destination && columns == other.columns &&
		       options.link_type == other.options.link_type && options.has_snaplen == other.options.has_snaplen &&
		       options.snaplen == other.options.snaplen;
	}
};
static void ValidateDestination(ClientContext &context, const string &path) {
	auto &fs = FileSystem::GetFileSystem(context);
	if (path.empty() || FileSystem::IsRemoteFile(path) || path.find("://") != string::npos || path == "-" ||
	    fs.IsPipe(path) || fs.DirectoryExists(path))
		throw InvalidInputException("PCAP output requires a local regular-file destination");
	if (fs.FileExists(path)) {
		auto file = fs.OpenFile(path, FileFlags::FILE_FLAGS_READ);
		if (file->GetType() != FileType::FILE_TYPE_REGULAR)
			throw InvalidInputException("PCAP output requires a local regular-file destination");
	}
}
struct PcapCopyGlobal : GlobalFunctionData, packetquapture::PcapOutput {
	PcapCopyGlobal(ClientContext &context_p, string stage_p, string destination_p)
	    : context(context_p), fs(FileSystem::GetFileSystem(context_p)), stage(std::move(stage_p)),
	      destination(std::move(destination_p)) {
	}
	~PcapCopyGlobal() override {
		writer.reset();
#ifdef _WIN32
		if (descriptor >= 0)
			_close(descriptor);
#else
		if (descriptor >= 0)
			::close(descriptor);
#endif
		if (owned) {
			try {
				fs.TryRemoveFile(stage);
			} catch (...) {
			}
		}
	}
	void Start(const packetquapture::PcapWriterOptions &options) {
		ValidateDestination(context, destination);
		if (!DBConfig::GetConfig(context).CanAccessFile(stage, FileType::FILE_TYPE_REGULAR))
			throw PermissionException("PCAP staging is disabled by file access configuration");
#ifdef _WIN32
		// DuckDB v1.5.5 ignores EXCLUSIVE_CREATE on Windows. Use the CRT's
		// O_EXCL creation and retain that same descriptor; never reopen by name.
		auto wide = WindowsUtil::UTF8ToUnicode(stage.c_str());
		if (_wsopen_s(&descriptor, wide.c_str(), _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY | _O_NOINHERIT, _SH_DENYNO,
		              _S_IREAD | _S_IWRITE) != 0)
			throw IOException("Cannot exclusively create PCAP staging file");
		owned = true;
#else
		// DuckDB's UnixFileHandle::Close discards close errors. Retain a native
		// descriptor so every publication-critical operation has a checked result.
		descriptor = ::open(stage.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
		if (descriptor < 0)
			throw IOException("Cannot exclusively create PCAP staging file");
		owned = true;
#endif
		writer = make_uniq<packetquapture::PcapWriter>(*this, options);
	}
	size_t Write(const uint8_t *data, size_t size) override {
		if (context.IsInterrupted())
			throw InterruptException();
#ifdef _WIN32
		auto count = _write(descriptor, data, static_cast<unsigned>(size));
#else
		auto count = ::write(descriptor, data, size);
		while (count < 0 && errno == EINTR) {
			if (context.IsInterrupted())
				throw InterruptException();
			count = ::write(descriptor, data, size);
		}
#endif
		if (count < 0)
			throw IOException("PCAP output write failed");
		return static_cast<size_t>(count);
	}
	void Seek(uint64_t offset) override {
		if (offset > static_cast<uint64_t>(NumericLimits<int64_t>::Maximum()))
			throw IOException("PCAP output offset exceeds the filesystem range");
		if (context.IsInterrupted())
			throw InterruptException();
#ifdef _WIN32
		if (_lseeki64(descriptor, static_cast<__int64>(offset), SEEK_SET) < 0)
			throw IOException("PCAP staging seek failed");
#else
		if (::lseek(descriptor, static_cast<off_t>(offset), SEEK_SET) < 0)
			throw IOException("PCAP staging seek failed");
#endif
	}
	void Publish() {
		if (context.IsInterrupted())
			throw InterruptException();
		writer->Finish();
#ifdef _WIN32
		if (_commit(descriptor) != 0)
			throw IOException("PCAP staging sync failed");
		auto closing = descriptor;
		descriptor = -1;
		if (_close(closing) != 0)
			throw IOException("PCAP staging close failed");
#else
		auto sync_result = ::fsync(descriptor);
		while (sync_result != 0 && errno == EINTR) {
			if (context.IsInterrupted())
				throw InterruptException();
			sync_result = ::fsync(descriptor);
		}
		if (sync_result != 0)
			throw IOException("PCAP staging sync failed");
		auto closing = descriptor;
		descriptor = -1;
		// Do not retry close: the descriptor can already be released on error.
		if (::close(closing) != 0)
			throw IOException("PCAP staging close failed");
#endif
		if (context.IsInterrupted())
			throw InterruptException();
		ValidateDestination(context, destination);
		fs.MoveFile(stage, destination);
		owned = false;
	}
	ClientContext &context;
	FileSystem &fs;
	string stage, destination;
	bool owned = false;
	int descriptor = -1;
	unique_ptr<packetquapture::PcapWriter> writer;
};
struct PcapCopyLocal : LocalFunctionData {};
static unique_ptr<GlobalFunctionData> InitializeGlobal(ClientContext &context, FunctionData &data, const string &path) {
	auto &bind = data.Cast<PcapCopyBind>();
	auto result = make_uniq<PcapCopyGlobal>(context, path, bind.destination);
	result->Start(bind.options);
	return std::move(result);
}
static unique_ptr<LocalFunctionData> InitializeLocal(ExecutionContext &, FunctionData &) {
	return make_uniq<PcapCopyLocal>();
}
static void Sink(ExecutionContext &context, FunctionData &data, GlobalFunctionData &global, LocalFunctionData &,
                 DataChunk &input) {
	auto &bind = data.Cast<PcapCopyBind>();
	auto &state = global.Cast<PcapCopyGlobal>();
	std::array<UnifiedVectorFormat, 5> values;
	for (idx_t i = 0; i < 5; ++i)
		input.data[bind.columns[i]].ToUnifiedFormat(input.size(), values[i]);
	for (idx_t row = 0; row < input.size(); ++row) {
		if (context.client.IsInterrupted())
			throw InterruptException();
		std::array<idx_t, 5> index;
		for (idx_t i = 0; i < 5; ++i) {
			index[i] = values[i].sel->get_index(row);
			if (!values[i].validity.RowIsValid(index[i]))
				throw InvalidInputException("PCAP export required columns must not contain NULL");
		}
		auto stamp = UnifiedVectorFormat::GetData<timestamp_t>(values[0])[index[0]];
		auto captured = UnifiedVectorFormat::GetData<uint32_t>(values[1])[index[1]];
		auto original = UnifiedVectorFormat::GetData<uint32_t>(values[2])[index[2]];
		auto link = UnifiedVectorFormat::GetData<uint32_t>(values[3])[index[3]];
		auto payload = UnifiedVectorFormat::GetData<string_t>(values[4])[index[4]];
		try {
			state.writer->WritePacket(stamp.value, captured, original, link,
			                          reinterpret_cast<const uint8_t *>(payload.GetData()), payload.GetSize());
		} catch (const std::invalid_argument &error) {
			throw InvalidInputException("%s", error.what());
		}
	}
}
static void Finalize(ClientContext &, FunctionData &, GlobalFunctionData &global) {
	global.Cast<PcapCopyGlobal>().Publish();
}
static CopyFunctionExecutionMode ExecutionMode(bool, bool) {
	return CopyFunctionExecutionMode::REGULAR_COPY_TO_FILE;
}
static CopyFunction WriterFunction() {
	CopyFunction function("pcap");
	function.extension = "pcap";
	function.copy_to_initialize_global = InitializeGlobal;
	function.copy_to_initialize_local = InitializeLocal;
	function.copy_to_sink = Sink;
	function.copy_to_finalize = Finalize;
	function.execution_mode = ExecutionMode;
	return function;
}
static uint32_t UIntOption(ClientContext &context, const string &name, const vector<Value> &values) {
	if (values.size() != 1 || values[0].IsNull() || !values[0].type().IsIntegral())
		throw BinderException("PCAP %s requires one integer", name);
	auto value = values[0].CastAs(context, LogicalType::UBIGINT).GetValue<uint64_t>();
	if (value > NumericLimits<uint32_t>::Maximum())
		throw BinderException("PCAP %s exceeds 32 bits", name);
	return static_cast<uint32_t>(value);
}
static BoundStatement Plan(Binder &binder, CopyStatement &statement) {
	auto &context = binder.context;
	auto &info = *statement.info;
	uint32_t link = 0, snaplen = 0;
	bool has_link = false, has_snaplen = false;
	for (auto &option : info.options) {
		auto key = StringUtil::Lower(option.first);
		if (key == "linktype") {
			link = UIntOption(context, key, option.second);
			has_link = true;
		} else if (key == "snaplen") {
			snaplen = UIntOption(context, key, option.second);
			has_snaplen = true;
		} else if (key == "use_tmp_file" || key == "preserve_order" || key == "write_empty_file") {
			if (option.second.size() > 1 ||
			    (!option.second.empty() && (option.second[0].IsNull() ||
			                                !option.second[0].CastAs(context, LogicalType::BOOLEAN).GetValue<bool>())))
				throw BinderException("PCAP %s cannot be disabled", key);
		} else
			throw BinderException("Unsupported PCAP COPY option: %s", key);
	}
	if (!has_link || link > 65535)
		throw BinderException("PCAP requires LINKTYPE between 0 and 65535 without FCS metadata");
	if (has_snaplen && !snaplen)
		throw BinderException("PCAP SNAPLEN must be positive");
	auto &fs = FileSystem::GetFileSystem(context);
	auto destination = fs.ExpandPath(info.file_path);
	if (!fs.IsPathAbsolute(destination))
		destination = fs.JoinPath(fs.GetWorkingDirectory(), destination);
	ValidateDestination(context, destination);
	auto query = info.select_statement->Copy();
	auto select = binder.Bind(*query);
	const vector<string> required = {"timestamp", "captured_length", "original_length", "link_type", "packet_data"};
	const vector<LogicalType> expected = {LogicalType::TIMESTAMP, LogicalType::UINTEGER, LogicalType::UINTEGER,
	                                      LogicalType::UINTEGER, LogicalType::BLOB};
	auto bind = make_uniq<PcapCopyBind>(link);
	bind->destination = destination;
	bind->options.has_snaplen = has_snaplen;
	bind->options.snaplen = snaplen;
	for (idx_t col = 0; col < required.size(); ++col) {
		idx_t matches = 0;
		for (idx_t i = 0; i < select.names.size(); ++i) {
			if (!StringUtil::CIEquals(select.names[i], required[col]))
				continue;
			++matches;
			bind->columns[col] = i;
			if (select.types[i] != expected[col])
				throw BinderException("PCAP column %s must have exact type %s (cast explicitly)", required[col],
				                      expected[col].ToString());
		}
		if (matches != 1)
			throw BinderException("PCAP requires exactly one column named %s", required[col]);
	}
	// The engine tracks this owned path for error cleanup. Never put the final
	// destination there: its destructor removes tracked files after sink errors.
	auto stage = fs.JoinPath(StringUtil::GetFilePath(destination),
	                         ".packetquapture-" + UUID::ToString(UUID::GenerateRandomUUID()) + ".pcap.tmp");
	auto copy = make_uniq<LogicalCopyToFile>(WriterFunction(), std::move(bind), std::move(statement.info));
	copy->file_path = stage;
	copy->use_tmp_file = false;
	copy->overwrite_mode = CopyOverwriteMode::COPY_ERROR_ON_CONFLICT;
	copy->file_extension = "pcap";
	copy->per_thread_output = false;
	copy->rotate = false;
	copy->return_type = CopyFunctionReturnType::CHANGED_ROWS;
	copy->partition_output = false;
	copy->write_partition_columns = false;
	copy->preserve_order = PreserveOrderType::PRESERVE_ORDER;
	copy->names = select.names;
	copy->expected_types = select.types;
	copy->AddChild(std::move(select.plan));
	binder.GetStatementProperties().return_type = StatementReturnType::CHANGED_ROWS;
	BoundStatement result;
	result.names = GetCopyFunctionReturnNames(copy->return_type);
	result.types = GetCopyFunctionReturnLogicalTypes(copy->return_type);
	result.plan = std::move(copy);
	return result;
}
} // namespace
void RegisterPcapCopy(ExtensionLoader &loader) {
	auto function = WriterFunction();
	function.plan = Plan;
	loader.RegisterFunction(function);
}
} // namespace duckdb
