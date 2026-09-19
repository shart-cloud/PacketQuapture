#pragma once

#include "duckdb/main/client_context_state.hpp"
#include "duckdb/storage/buffer_manager.hpp"
#include <limits>
#include <atomic>

namespace duckdb {

// Conservative admission envelope, not an RSS measurement. See CAPTURE_INVENTORY.md.
constexpr idx_t INVENTORY_WORKER_BYTES = 32ULL * 1024 * 1024;

// Binding precedes pipeline execution. Count scan bindings and plan copies so
// an early pipeline cannot consume the later pipelines' worker allowances.
// Copies can conservatively overestimate concurrency, which only lowers parallelism.
struct InventoryPlanCount {
	std::atomic<idx_t> scans {0};
	std::atomic<bool> sealed {false};
};
class InventoryPlanRegistry : public ClientContextState {
public:
	shared_ptr<InventoryPlanCount> Register() {
		if (!current || current->sealed.load()) {
			current = make_shared_ptr<InventoryPlanCount>();
		}
		current->scans.fetch_add(1);
		return current;
	}
	void QueryEnd() override {
		current.reset();
	}

private:
	shared_ptr<InventoryPlanCount> current;
};

// Shared by all inventory table-function invocations in one query. QueryEnd detaches
// this generation; leases may safely outlive it while execution is unwinding.
class InventoryQueryBudget : public ClientContextState {
public:
	explicit InventoryQueryBudget(ClientContext &context) : manager(BufferManager::GetBufferManager(context)) {
		Value setting;
		context.TryGetCurrentSetting("packetquapture_inventory_memory_mb", setting);
		if (setting.IsNull()) {
			throw InvalidInputException("packetquapture_inventory_memory_mb must not be NULL");
		}
		const auto mib = setting.GetValue<uint64_t>();
		if (mib > std::numeric_limits<idx_t>::max() / (1024 * 1024)) {
			throw InvalidInputException("packetquapture_inventory_memory_mb is too large");
		}
		limit = MinValue<idx_t>(mib * 1024 * 1024, manager.GetMaxMemory() / 2);
	}
	void QueryEnd(ClientContext &context) override {
		context.registered_state->Remove("packetquapture_inventory_budget");
	}
	idx_t Slots() const {
		return limit / INVENTORY_WORKER_BYTES;
	}
	bool Acquire() {
		lock_guard<mutex> guard(lock);
		if (INVENTORY_WORKER_BYTES > limit - used) {
			return false;
		}
		try {
			manager.ReserveMemory(INVENTORY_WORKER_BYTES);
		} catch (const OutOfMemoryException &) {
			return false;
		}
		used += INVENTORY_WORKER_BYTES;
		return true;
	}
	void Release() {
		lock_guard<mutex> guard(lock);
		manager.FreeReservedMemory(INVENTORY_WORKER_BYTES);
		used -= INVENTORY_WORKER_BYTES;
	}

private:
	BufferManager &manager;
	mutex lock;
	idx_t limit = 0, used = 0;
};

class InventoryReservation {
public:
	explicit InventoryReservation(shared_ptr<InventoryQueryBudget> budget_p) : budget(std::move(budget_p)) {
		acquired = budget->Acquire();
	}
	~InventoryReservation() {
		if (acquired) {
			budget->Release();
		}
	}
	InventoryReservation(const InventoryReservation &) = delete;
	InventoryReservation &operator=(const InventoryReservation &) = delete;
	bool Acquired() const {
		return acquired;
	}

private:
	shared_ptr<InventoryQueryBudget> budget;
	bool acquired = false;
};
} // namespace duckdb
