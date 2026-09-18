// Linux integration test against the built DuckDB library (including this extension).
// Observe live capture descriptors, interrupt actual queries, and reuse the connection.
#include "duckdb.hpp"

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
	for (const auto *function : {"read_pcap", "read_packets", "read_dns"}) {
		for (const size_t threads : {1, 2, 4, 8}) {
			Execute(connection, "SET threads=" + std::to_string(threads));
			for (const size_t files : {1, 8}) {
				const auto sql = "SELECT count(*) FROM " + std::string(function) + "(" + Inputs(capture, files) +
				                 ") WHERE captured_length = 4294967295";
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
			Execute(connection, "SELECT * FROM " + std::string(function) + "(" + Inputs(capture, 8) + ") LIMIT 1");
			Require(Readers(capture) == 0, "Early LIMIT leaked capture handles");
		}
	}
	fs::remove(capture);
	fs::remove(broken);
	fs::remove(directory);
	std::cout << "Live-reader overlap, worker limits, cancellation, error cleanup, and reuse passed\n";
}
