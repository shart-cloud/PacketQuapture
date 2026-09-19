// Linux integration test against the built DuckDB library (including this extension).
// Observe live capture descriptors, interrupt actual queries, and reuse the connection.
#include "duckdb.hpp"
#include "stream_scan_budget.hpp"
#include "flow_scan_budget.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <thread>
#include <unistd.h>

namespace fs = std::filesystem;
using namespace std::chrono_literals;

static void Require(bool ok, const std::string &message) {
	if (!ok) {
		std::cerr << message << std::endl;
		// A broken cancellation path must not hang while a future joins its worker.
		std::_Exit(1);
	}
}

static void Execute(duckdb::Connection &connection, const std::string &sql) {
	auto result = connection.Query(sql);
	if (result->HasError()) {
		Require(false, result->GetError());
	}
}

static size_t Readers(const fs::path &capture) {
	size_t count = 0;
	for (const auto &entry : fs::directory_iterator("/proc/self/fd")) {
		std::error_code error;
		if (fs::read_symlink(entry.path(), error) == capture) {
			++count;
		}
	}
	return count;
}

static std::string Inputs(const fs::path &path, size_t count) {
	std::string result = "[";
	for (size_t i = 0; i < count; ++i) {
		result += (i ? ", '" : "'") + path.string() + "'";
	}
	return result + "]";
}

int main() {
	std::cout << std::unitbuf;
	const auto directory = fs::absolute("build/parallel-scan-test-" + std::to_string(getpid()));
	fs::create_directories(directory);
	const auto capture = directory / "large.pcap";
	const auto broken = directory / "broken.pcap";
	{
		std::ifstream source("test/data/dns/messages.pcap", std::ios::binary);
		Require(source.good(), "Run from the repository root with generated fixtures");
		std::string bytes((std::istreambuf_iterator<char>(source)), std::istreambuf_iterator<char>());
		Require(bytes.size() > 24, "Missing PCAP records");
		std::ofstream output(capture, std::ios::binary);
		output.write(bytes.data(), 24);
		// Enough no-output work for the observer to see active readers, without a speed threshold.
		for (size_t i = 0; i < 65536; ++i) {
			output.write(bytes.data() + 24, bytes.size() - 24);
		}
		Require(output.good(), "Failed to write concurrency fixture");
		std::ofstream malformed(broken, std::ios::binary);
		malformed << "not a capture";
	}
	duckdb::DuckDB database(nullptr);
	duckdb::Connection connection(database);
	for (const auto *function : {"read_pcap", "read_packets", "read_dns", "read_tcp_streams", "read_dns_messages",
	                             "read_flows", "capture_inventory"}) {
		for (const size_t threads : {1, 2, 4, 8}) {
			Execute(connection, "SET threads=" + std::to_string(threads));
			for (const size_t files : {1, 8}) {
				const auto sql =
				    "SELECT count(*) FROM " + std::string(function) + "(" + Inputs(capture, files) + ") WHERE " +
				    (std::string(function) == "capture_inventory" ? "packet_count=18446744073709551615"
				     : std::string(function) == "read_tcp_streams" || std::string(function) == "read_dns_messages" ||
				             std::string(function) == "read_flows"
				         ? "first_packet_number = 0"
				         : "captured_length = 4294967295");
				auto query = std::async(std::launch::async, [&] {
					auto result = connection.Query(sql);
					return result->HasError() ? result->GetError() : std::string();
				});
				const size_t required = threads > 1 && files > 1 ? 2 : 1;
				size_t peak = 0;
				const auto deadline = std::chrono::steady_clock::now() + 15s;
				while (std::chrono::steady_clock::now() < deadline) {
					peak = std::max(peak, Readers(capture));
					if (peak >= required || query.wait_for(0ms) == std::future_status::ready) {
						break;
					}
					std::this_thread::sleep_for(1ms);
				}
				Require(peak >= required, "Did not observe the required simultaneous capture readers");
				// Sample one-worker cases repeatedly so accidental extra readers can be detected.
				if (required == 1) {
					for (size_t i = 0; i < 20; ++i) {
						peak = std::max(peak, Readers(capture));
						std::this_thread::sleep_for(1ms);
					}
					Require(peak == 1, "One file or threads=1 must use one reader");
				}
				connection.Interrupt();
				Require(query.wait_for(5s) == std::future_status::ready,
				        "Cancellation did not finish within 5 seconds");
				const auto error = query.get();
				Require(error.find("Interrupt") != std::string::npos, "Expected an interrupted query: " + error);
				Require(Readers(capture) == 0, "Cancellation leaked capture handles");
				Execute(connection, "SELECT 42");
				std::cout << function << " threads=" << threads << " files=" << files << " overlap=" << peak
				          << "; cancellation and connection reuse passed\n";
			}
			auto failing = std::async(std::launch::async, [&] {
				return connection.Query("SELECT count(*) FROM " + std::string(function) + "(['" + broken.string() +
				                        "', '" + capture.string() + "', '" + capture.string() + "'])");
			});
			Require(failing.wait_for(5s) == std::future_status::ready, "Worker error did not cancel the scan");
			auto result = failing.get();
			Require(result->HasError() && result->GetError().find(broken.string()) != std::string::npos,
			        "Worker error lost filename context");
			Require(Readers(capture) == 0 && Readers(broken) == 0, "Worker exception leaked handles");
			Execute(connection, "SELECT 42");
			const auto small = fs::absolute("test/data/dns/messages.pcap");
			Execute(connection, "SELECT count(*) FROM " + std::string(function) + "(" + Inputs(small, 8) + ")");
			Require(Readers(small) == 0, "EOF leaked capture handles");
			// A 2,500-message direction leaves pending DNS output when LIMIT stops.
			const auto early = std::string(function) == "read_tcp_streams" ||
			                           std::string(function) == "read_dns_messages" ||
			                           std::string(function) == "read_flows"
			                       ? fs::absolute("test/data/reassembly/chunks.pcap")
			                       : capture;
			Execute(connection, "SELECT * FROM " + std::string(function) + "(" + Inputs(early, 8) + ") LIMIT 1");
			Require(Readers(early) == 0, "Early LIMIT leaked capture handles");
		}
	}
	// Actual descriptor counts verify that the admission budget limits workers,
	// independently of the DuckDB thread setting. Both readers must release slots.
	Execute(connection, "SET threads=8");
	for (const auto *function : {"read_tcp_streams", "read_dns_messages"}) {
		for (const size_t budget : {128, 256, 512}) {
			Execute(connection, "SET packetquapture_stream_memory_mb=" + std::to_string(budget));
			auto query = std::async(std::launch::async, [&] {
				return connection.Query("SELECT count(*) FROM " + std::string(function) + "(" + Inputs(capture, 8) +
				                        ") WHERE first_packet_number = 0");
			});
			size_t peak = 0;
			const auto deadline = std::chrono::steady_clock::now() + 10s;
			while (std::chrono::steady_clock::now() < deadline && peak < budget / 128) {
				peak = std::max(peak, Readers(capture));
				if (query.wait_for(0ms) == std::future_status::ready) {
					break;
				}
				std::this_thread::sleep_for(1ms);
			}
			for (size_t i = 0; i < 20; ++i) {
				peak = std::max(peak, Readers(capture));
				std::this_thread::sleep_for(1ms);
			}
			connection.Interrupt();
			Require(query.wait_for(5s) == std::future_status::ready, "Memory-limited scan did not cancel");
			auto result = query.get();
			Require(result->HasError(), "Expected cancellation");
			Require(peak == budget / 128, "Memory budget did not bound live readers");
			Require(Readers(capture) == 0, "Memory-limited scan leaked descriptors");
			auto usage = connection.Query("SELECT memory_usage_bytes FROM duckdb_memory() WHERE tag='EXTENSION'");
			Require(!usage->HasError() && usage->GetValue(0, 0).GetValue<uint64_t>() == 0,
			        "Cancellation leaked extension reservations");
			std::cout << function << " budget=" << budget << " MiB readers=" << peak << " passed\n";
		}
	}

	for (const size_t slots : {1, 2, 4}) {
		Execute(connection, "SET packetquapture_flow_memory_mb=" + std::to_string(slots * 48));
		auto query = std::async(std::launch::async, [&] {
			return connection.Query("SELECT count(*) FROM read_flows(" + Inputs(capture, 8) +
			                        ") WHERE first_packet_number=0");
		});
		size_t peak = 0;
		auto deadline = std::chrono::steady_clock::now() + 10s;
		while (std::chrono::steady_clock::now() < deadline && peak < slots) {
			peak = std::max(peak, Readers(capture));
			if (query.wait_for(0ms) == std::future_status::ready)
				break;
			std::this_thread::sleep_for(1ms);
		}
		connection.Interrupt();
		Require(query.wait_for(5s) == std::future_status::ready, "Flow scan did not cancel");
		Require(query.get()->HasError() && peak == slots, "Flow admission count mismatch");
		Require(Readers(capture) == 0, "Flow reservation leaked capture handles");
		auto usage = connection.Query("SELECT memory_usage_bytes FROM duckdb_memory() WHERE tag='EXTENSION'");
		Require(!usage->HasError() && usage->GetValue(0, 0).GetValue<uint64_t>() == 0,
		        "Flow reservation leaked memory");
	}
	Execute(connection, "SET packetquapture_flow_memory_mb=96");
	Execute(connection, "SELECT count(*) FROM read_flows('test/data/flows/tcp.pcap') a CROSS JOIN "
	                    "read_flows('test/data/flows/udp.pcap') b");
	Execute(connection, "PREPARE flows AS SELECT count(*) FROM read_flows('test/data/flows/tcp.pcap')");
	for (size_t i = 0; i < 3; ++i)
		Execute(connection, "EXECUTE flows");
	Require(duckdb::FlowScanId(7, 1, 3) == 20, "Flow ID mapping failed");
	bool flow_overflow = false;
	try {
		duckdb::FlowScanId(UINT64_MAX, 1, 2);
	} catch (const duckdb::InvalidInputException &) {
		flow_overflow = true;
	}
	Require(flow_overflow, "Flow ID overflow was not detected");
	Execute(connection, "SET packetquapture_stream_memory_mb=128");
	auto insufficient =
	    connection.Query("SELECT a.stream_id FROM read_tcp_streams('test/data/tcp_streams/protocols.pcap') a "
	                     "CROSS JOIN read_dns_messages('test/data/reassembly/streams.pcap') b");
	// Pipeline dependencies can let the second scan reuse the first slot. If
	// both initialize together, admission must fail explicitly rather than hang.
	Require(!insufficient->HasError() || insufficient->GetError().find("cannot reserve") != std::string::npos,
	        "Unexpected shared-budget failure");
	{
		auto budget = duckdb::make_shared_ptr<duckdb::StreamQueryBudget>(*connection.context);
		auto first = duckdb::make_uniq<duckdb::StreamReservation>(budget);
		auto second = duckdb::make_uniq<duckdb::StreamReservation>(budget);
		Require(first->Acquired() && !second->Acquired(), "Shared budget admitted too many reservations");
		first.reset();
		auto replacement = duckdb::make_uniq<duckdb::StreamReservation>(budget);
		Require(replacement->Acquired(), "Released reservation was not reusable");
	}
	Execute(connection, "SET packetquapture_stream_memory_mb=256");
	Execute(connection, "SELECT count(*) FROM read_tcp_streams('test/data/tcp_streams/protocols.pcap') a "
	                    "CROSS JOIN read_dns_messages('test/data/reassembly/streams.pcap') b");
	Execute(connection,
	        "PREPARE streams AS SELECT count(*) FROM read_tcp_streams('test/data/tcp_streams/protocols.pcap')");
	for (size_t i = 0; i < 3; ++i) {
		Execute(connection, "EXECUTE streams");
	}
	Execute(connection, "SET packetquapture_stream_memory_mb=512");
	Require(duckdb::StreamScanId(1, 0, 3) == 1 && duckdb::StreamScanId(2, 2, 3) == 6,
	        "Stream occurrence mapping failed");
	Require(duckdb::StreamScanId(UINT64_MAX, 0, 1) == UINT64_MAX, "Single-file ID boundary failed");
	bool overflow = false;
	try {
		duckdb::StreamScanId(UINT64_MAX, 1, 2);
	} catch (const duckdb::InvalidInputException &) {
		overflow = true;
	}
	Require(overflow, "ID overflow was not detected");
	fs::remove(capture);
	fs::remove(broken);
	fs::remove(directory);
	std::cout << "Live-reader overlap, worker limits, cancellation, error cleanup, and reuse passed\n";
}
