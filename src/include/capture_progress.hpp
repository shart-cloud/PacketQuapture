#pragma once

#include "duckdb/common/error_data.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/main/client_config.hpp"
#include "duckdb/main/client_context.hpp"

#include <atomic>
#include <limits>

namespace duckdb {

// Query-local accounting, published in coarse byte increments rather than per packet.
// The progress callback never reads worker-owned parser or reassembly state.
class CaptureProgress {
public:
	void Initialize(ClientContext &context, const vector<OpenFileInfo> &files, bool defer_completion_p = false) {
		enabled = ClientConfig::GetConfig(context).enable_progress_bar;
		defer_completion = defer_completion_p;
		if (!enabled) {
			return;
		}
		auto &fs = FileSystem::GetFileSystem(context);
		for (const auto &file : files) {
			if (context.IsInterrupted()) {
				throw InterruptException();
			}
			try {
				// Do not open a FIFO just to discover its size: opening may block.
				if (fs.IsPipe(file.path)) {
					known.store(false, std::memory_order_relaxed);
					return;
				}
				auto handle = fs.OpenFile(file, FileFlags::FILE_FLAGS_READ);
				const auto size = fs.GetFileSize(*handle);
				if (!handle->CanSeek() || handle->IsPipe() || size < 0 ||
				    uint64_t(size) > std::numeric_limits<uint64_t>::max() - total) {
					known.store(false, std::memory_order_relaxed);
					return;
				}
				sizes.push_back(uint64_t(size));
				total += uint64_t(size);
			} catch (const std::exception &exception) {
				if (ErrorData(exception).Type() == ExceptionType::INTERRUPT) {
					throw;
				}
				// The scan itself still reports errors when the affected input is read.
				known.store(false, std::memory_order_relaxed);
				return;
			}
		}
		if (files.empty()) {
			finished.store(true, std::memory_order_relaxed);
		}
	}

	bool Enabled() const {
		return enabled && known.load(std::memory_order_relaxed);
	}
	void CheckSize(idx_t index, bool seekable, uint64_t size) {
		if (Enabled() && (!seekable || index >= sizes.size() || sizes[index] != size)) {
			known.store(false, std::memory_order_relaxed);
		}
	}
	void Advance(uint64_t bytes) {
		consumed.fetch_add(bytes, std::memory_order_relaxed);
	}
	void CompleteFile() {
		if (completed_files.fetch_add(1, std::memory_order_relaxed) + 1 == sizes.size() && !defer_completion) {
			Finish();
		}
	}
	void Finish() {
		finished.store(true, std::memory_order_relaxed);
	}
	double Percentage() const {
		if (!Enabled()) {
			return -1;
		}
		if (finished.load(std::memory_order_relaxed)) {
			return 100;
		}
		// EOF and stream draining, not read-ahead or a final seek, establish completion.
		return total ? MinValue<double>(99.9, 100.0 * double(consumed.load(std::memory_order_relaxed)) / double(total))
		             : 0;
	}

private:
	bool enabled = false, defer_completion = false;
	vector<uint64_t> sizes;
	uint64_t total = 0;
	std::atomic<uint64_t> consumed {0};
	std::atomic<idx_t> completed_files {0};
	std::atomic<bool> known {true}, finished {false};
};

} // namespace duckdb
