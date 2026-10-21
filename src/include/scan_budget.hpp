#pragma once

#include "duckdb/main/client_context_state.hpp"
#include "duckdb/storage/buffer_manager.hpp"
#include "pq_assert.hpp"
#include <atomic>
#include <limits>

namespace duckdb {

// Per-worker memory envelopes: conservative admission estimates, not RSS
// measurements. See PARALLEL_STREAMS.md, FLOWS.md and CAPTURE_INVENTORY.md.
constexpr idx_t STREAM_WORKER_BYTES = 128ULL * 1024 * 1024;
constexpr idx_t FLOW_WORKER_BYTES = 48ULL * 1024 * 1024;
constexpr idx_t INVENTORY_WORKER_BYTES = 32ULL * 1024 * 1024;
constexpr idx_t STREAM_OUTPUT_BATCH_BYTES = 1024ULL * 1024;
constexpr idx_t FLOW_OUTPUT_BATCH_BYTES = 1024ULL * 1024;

// What distinguishes one kind of scan's budget from another's.
struct StreamBudgetKind {
	static constexpr idx_t WORKER_BYTES = STREAM_WORKER_BYTES;
	static const char *Setting() {
		return "packetquapture_stream_memory_mb";
	}
	static const char *StateKey() {
		return "packetquapture_stream_budget";
	}
};
struct FlowBudgetKind {
	static constexpr idx_t WORKER_BYTES = FLOW_WORKER_BYTES;
	static const char *Setting() {
		return "packetquapture_flow_memory_mb";
	}
	static const char *StateKey() {
		return "packetquapture_flow_budget";
	}
};
struct InventoryBudgetKind {
	static constexpr idx_t WORKER_BYTES = INVENTORY_WORKER_BYTES;
	static const char *Setting() {
		return "packetquapture_inventory_memory_mb";
	}
	static const char *StateKey() {
		return "packetquapture_inventory_budget";
	}
};

// Interleaves per-file row ids into one query-wide id space: local id n of file
// f out of count files becomes (n - 1) * count + f + 1.
inline uint64_t ScanRowId(uint64_t local_id, uint64_t file_index, uint64_t file_count, const char *what) {
	const auto maximum = std::numeric_limits<uint64_t>::max();
	if (!local_id || !file_count || file_index >= file_count ||
	    local_id - 1 > (maximum - (file_index + 1)) / file_count) {
		throw InvalidInputException("PacketQuapture %s ID exceeds UBIGINT capacity", what);
	}
	return (local_id - 1) * file_count + file_index + 1;
}
inline uint64_t StreamScanId(uint64_t local_id, uint64_t file_index, uint64_t file_count) {
	return ScanRowId(local_id, file_index, file_count, "stream");
}
inline uint64_t FlowScanId(uint64_t local_id, uint64_t file_index, uint64_t file_count) {
	return ScanRowId(local_id, file_index, file_count, "flow");
}

// Binding precedes pipeline execution. Count scan bindings and plan copies so
// an early pipeline cannot consume the later pipelines' worker allowances.
// Copies can conservatively overestimate concurrency, which only lowers parallelism.
struct ScanPlanCount {
	std::atomic<idx_t> scans {0};
	std::atomic<bool> sealed {false};
};
class ScanPlanRegistry : public ClientContextState {
public:
	shared_ptr<ScanPlanCount> Register() {
		if (!current || current->sealed.load()) {
			current = make_shared_ptr<ScanPlanCount>();
		}
		current->scans.fetch_add(1);
		PQ_ASSERT(current->scans.load() > 0);
		return current;
	}
	void QueryEnd() override {
		current.reset();
	}

private:
	shared_ptr<ScanPlanCount> current;
};

// Shared by all invocations of one kind of scan in one query. QueryEnd detaches
// this generation; leases may safely outlive it while execution is unwinding.
template <class Kind>
class ScanQueryBudget : public ClientContextState {
public:
	explicit ScanQueryBudget(ClientContext &context) : manager(BufferManager::GetBufferManager(context)) {
		Value setting;
		context.TryGetCurrentSetting(Kind::Setting(), setting);
		if (setting.IsNull()) {
			throw InvalidInputException("%s must not be NULL", Kind::Setting());
		}
		const auto mib = setting.GetValue<uint64_t>();
		if (mib > std::numeric_limits<idx_t>::max() / (1024ULL * 1024)) {
			throw InvalidInputException("%s is too large", Kind::Setting());
		}
		limit = MinValue<idx_t>(mib * 1024 * 1024, manager.GetMaxMemory() / 2);
	}
	void QueryEnd(ClientContext &context) override {
		context.registered_state->Remove(Kind::StateKey());
	}
	idx_t Slots() const {
		return limit / Kind::WORKER_BYTES;
	}
	bool Acquire() {
		lock_guard<mutex> guard(lock);
		PQ_ASSERT(used <= limit);
		if (Kind::WORKER_BYTES > limit - used) {
			return false;
		}
		try {
			manager.ReserveMemory(Kind::WORKER_BYTES);
		} catch (const OutOfMemoryException &) {
			return false;
		}
		used += Kind::WORKER_BYTES;
		PQ_ASSERT(used <= limit);
		return true;
	}
	void Release() {
		lock_guard<mutex> guard(lock);
		PQ_ASSERT(used >= Kind::WORKER_BYTES);
		manager.FreeReservedMemory(Kind::WORKER_BYTES);
		used -= Kind::WORKER_BYTES;
	}

private:
	BufferManager &manager;
	mutex lock;
	idx_t limit = 0, used = 0;
};

template <class Kind>
class ScanReservation {
public:
	explicit ScanReservation(shared_ptr<ScanQueryBudget<Kind>> budget_p) : budget(std::move(budget_p)) {
		acquired = budget->Acquire();
	}
	~ScanReservation() {
		if (acquired) {
			budget->Release();
		}
	}
	ScanReservation(const ScanReservation &) = delete;
	ScanReservation &operator=(const ScanReservation &) = delete;
	bool Acquired() const {
		return acquired;
	}

private:
	shared_ptr<ScanQueryBudget<Kind>> budget;
	bool acquired = false;
};

using StreamPlanCount = ScanPlanCount;
using FlowPlanCount = ScanPlanCount;
using InventoryPlanCount = ScanPlanCount;
using StreamPlanRegistry = ScanPlanRegistry;
using FlowPlanRegistry = ScanPlanRegistry;
using InventoryPlanRegistry = ScanPlanRegistry;
using StreamQueryBudget = ScanQueryBudget<StreamBudgetKind>;
using FlowQueryBudget = ScanQueryBudget<FlowBudgetKind>;
using InventoryQueryBudget = ScanQueryBudget<InventoryBudgetKind>;
using StreamReservation = ScanReservation<StreamBudgetKind>;
using FlowReservation = ScanReservation<FlowBudgetKind>;
using InventoryReservation = ScanReservation<InventoryBudgetKind>;

} // namespace duckdb
