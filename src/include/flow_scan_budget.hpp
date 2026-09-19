#pragma once

#include "duckdb/main/client_context_state.hpp"
#include "duckdb/storage/buffer_manager.hpp"
#include <limits>
#include <atomic>

namespace duckdb {

// Conservative admission envelope, not an RSS measurement. See FLOWS.md.
constexpr idx_t FLOW_WORKER_BYTES = 48ULL * 1024 * 1024;
constexpr idx_t FLOW_OUTPUT_BATCH_BYTES = 1024 * 1024;

inline uint64_t FlowScanId(uint64_t local_id, uint64_t file_index, uint64_t file_count) {
	const auto maximum = std::numeric_limits<uint64_t>::max();
	if (!local_id || !file_count || file_index >= file_count ||
	    local_id - 1 > (maximum - (file_index + 1)) / file_count) {
		throw InvalidInputException("PacketQuapture flow ID exceeds UBIGINT capacity");
	}
	return (local_id - 1) * file_count + file_index + 1;
}

// Binding precedes pipeline execution. Count scan bindings and plan copies so
// an early pipeline cannot consume the later pipelines' worker allowances.
// Copies can conservatively overestimate concurrency, which only lowers parallelism.
struct FlowPlanCount {
	std::atomic<idx_t> scans {0};
	std::atomic<bool> sealed {false};
};
class FlowPlanRegistry : public ClientContextState {
public:
	shared_ptr<FlowPlanCount> Register() {
		if (!current || current->sealed.load()) {
			current = make_shared_ptr<FlowPlanCount>();
		}
		current->scans.fetch_add(1);
		return current;
	}
	void QueryEnd() override {
		current.reset();
	}

private:
	shared_ptr<FlowPlanCount> current;
};

// Shared by all flow table-function invocations in one query. QueryEnd detaches
// this generation; leases may safely outlive it while execution is unwinding.
class FlowQueryBudget : public ClientContextState {
public:
	explicit FlowQueryBudget(ClientContext &context) : manager(BufferManager::GetBufferManager(context)) {
		Value setting;
		context.TryGetCurrentSetting("packetquapture_flow_memory_mb", setting);
		if (setting.IsNull()) {
			throw InvalidInputException("packetquapture_flow_memory_mb must not be NULL");
		}
		const auto mib = setting.GetValue<uint64_t>();
		if (mib > std::numeric_limits<idx_t>::max() / (1024 * 1024)) {
			throw InvalidInputException("packetquapture_flow_memory_mb is too large");
		}
		limit = MinValue<idx_t>(mib * 1024 * 1024, manager.GetMaxMemory() / 2);
	}
	void QueryEnd(ClientContext &context) override {
		context.registered_state->Remove("packetquapture_flow_budget");
	}
	idx_t Slots() const {
		return limit / FLOW_WORKER_BYTES;
	}
	bool Acquire() {
		lock_guard<mutex> guard(lock);
		if (FLOW_WORKER_BYTES > limit - used) {
			return false;
		}
		try {
			manager.ReserveMemory(FLOW_WORKER_BYTES);
		} catch (const OutOfMemoryException &) {
			return false;
		}
		used += FLOW_WORKER_BYTES;
		return true;
	}
	void Release() {
		lock_guard<mutex> guard(lock);
		manager.FreeReservedMemory(FLOW_WORKER_BYTES);
		used -= FLOW_WORKER_BYTES;
	}

private:
	BufferManager &manager;
	mutex lock;
	idx_t limit = 0, used = 0;
};

class FlowReservation {
public:
	explicit FlowReservation(shared_ptr<FlowQueryBudget> budget_p) : budget(std::move(budget_p)) {
		acquired = budget->Acquire();
	}
	~FlowReservation() {
		if (acquired) {
			budget->Release();
		}
	}
	FlowReservation(const FlowReservation &) = delete;
	FlowReservation &operator=(const FlowReservation &) = delete;
	bool Acquired() const {
		return acquired;
	}

private:
	shared_ptr<FlowQueryBudget> budget;
	bool acquired = false;
};
} // namespace duckdb
