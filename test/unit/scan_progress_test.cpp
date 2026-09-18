// Linux native tests: weighted accounting, concurrency, unknown sizes, and actual query display callbacks.
#include "duckdb.hpp"
#include "capture_progress.hpp"
#include "duckdb/common/progress_bar/progress_bar_display.hpp"

#include <atomic>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <thread>
#include <sys/stat.h>
#include <unistd.h>

using namespace duckdb;
namespace fs = std::filesystem;

static void Require(bool value, const char *message) {
	if (!value) {
		std::cerr << message << std::endl;
		std::exit(1);
	}
}
static void SQL(Connection &connection, const std::string &sql) {
	auto result = connection.Query(sql);
	Require(!result->HasError(), result->HasError() ? result->GetError().c_str() : "query error");
}
static std::mutex display_lock;
static std::vector<double> displayed;
static bool finished = false;
class RecordingDisplay : public ProgressBarDisplay {
public:
	void Update(double value) override {
		std::lock_guard<std::mutex> guard(display_lock);
		displayed.push_back(value);
	}
	void Finish() override {
		std::lock_guard<std::mutex> guard(display_lock);
		finished = true;
	}
};
static void WriteSize(const fs::path &path, size_t bytes) {
	std::ofstream out(path, std::ios::binary);
	out.seekp(bytes - 1);
	out.put(0);
}

int main() {
	auto directory = fs::absolute("build/progress-test-" + std::to_string(getpid()));
	fs::create_directories(directory);
	auto small = directory / "small", large = directory / "large", pipe = directory / "pipe";
	WriteSize(small, 10);
	WriteSize(large, 90);
	Require(mkfifo(pipe.c_str(), 0600) == 0, "mkfifo failed");
	DuckDB database(nullptr);
	Connection connection(database);
	SQL(connection, "SET enable_progress_bar=false");
	CaptureProgress disabled;
	disabled.Initialize(*connection.context, {OpenFileInfo(pipe.string())});
	Require(disabled.Percentage() < 0, "Disabled progress must not open inputs");
	SQL(connection, "SET enable_progress_bar=true");
	SQL(connection, "SET enable_progress_bar_print=false");
	CaptureProgress weighted;
	weighted.Initialize(*connection.context,
	                    {OpenFileInfo(small.string()), OpenFileInfo(large.string()), OpenFileInfo(small.string())});
	weighted.Advance(10);
	weighted.CompleteFile();
	Require(std::abs(weighted.Percentage() - 100.0 / 11.0) < 0.001,
	        "Progress must weight bytes, including duplicate inputs");
	weighted.Advance(100);
	Require(weighted.Percentage() < 100, "Consuming all bytes is not EOF");
	weighted.CompleteFile();
	weighted.CompleteFile();
	Require(weighted.Percentage() == 100, "All input occurrences must complete");
	CaptureProgress stream;
	stream.Initialize(*connection.context, {OpenFileInfo(small.string())}, true);
	stream.Advance(10);
	stream.CompleteFile();
	Require(stream.Percentage() < 100, "Stream draining must not report completion at input EOF");
	stream.Finish();
	Require(stream.Percentage() == 100, "Drained streams must finish");
	CaptureProgress unknown;
	unknown.Initialize(*connection.context, {OpenFileInfo(pipe.string())});
	Require(unknown.Percentage() < 0, "Pipe size must remain unknown without opening it");
	CaptureProgress changed;
	changed.Initialize(*connection.context, {OpenFileInfo(small.string())});
	changed.CheckSize(0, true, 20);
	Require(changed.Percentage() < 0, "Changed input size must invalidate the estimate");
	CaptureProgress empty;
	empty.Initialize(*connection.context, {});
	Require(empty.Percentage() == 100, "Empty file list must be complete");
	WriteSize(large, 1024 * 1024);
	vector<OpenFileInfo> duplicates(8, OpenFileInfo(large.string()));
	CaptureProgress parallel;
	parallel.Initialize(*connection.context, duplicates);
	std::atomic<unsigned> done {0};
	std::vector<std::thread> workers;
	for (unsigned i = 0; i < 8; ++i) {
		workers.emplace_back([&] {
			for (unsigned n = 0; n < 1024; ++n) {
				parallel.Advance(1024);
			}
			parallel.CompleteFile();
			done.fetch_add(1);
		});
	}
	double previous = 0;
	while (done.load() != 8) {
		auto value = parallel.Percentage();
		Require(value >= previous && value <= 100, "Concurrent progress must be monotonic and bounded");
		previous = value;
	}
	for (auto &worker : workers) {
		worker.join();
	}
	Require(parallel.Percentage() == 100, "Parallel progress did not complete");

	const auto capture = directory / "packets.pcap";
	{
		std::ofstream out(capture, std::ios::binary);
		const unsigned char header[24] = {0xd4, 0xc3, 0xb2, 0xa1, 2,    0,    4, 0, 0, 0, 0, 0,
		                                  0,    0,    0,    0,    0xff, 0xff, 0, 0, 1, 0, 0, 0};
		unsigned char record[80] = {};
		record[8] = record[12] = 64;
		out.write(reinterpret_cast<const char *>(header), sizeof(header));
		for (unsigned i = 0; i < 500000; ++i) {
			out.write(reinterpret_cast<const char *>(record), sizeof(record));
		}
	}
	auto &config = ClientConfig::GetConfig(*connection.context);
	config.display_create_func = []() -> unique_ptr<ProgressBarDisplay> {
		return make_uniq<RecordingDisplay>();
	};
	SQL(connection, "SET enable_progress_bar_print=true");
	SQL(connection, "SET progress_bar_time=0");
	for (const auto *function : {"read_pcap", "read_packets", "read_dns"}) {
		for (const auto threads : {1, 4}) {
			SQL(connection, "SET threads=" + std::to_string(threads));
			displayed.clear();
			finished = false;
			SQL(connection, "SELECT count(*) FROM " + std::string(function) + "(['" + capture.string() + "','" +
			                    capture.string() + "'])");
			Require(finished, "Query progress display did not finish");
			bool intermediate = false;
			double last = 0;
			for (auto value : displayed) {
				Require(value >= last && value <= 100, "Real query progress regressed or exceeded 100");
				intermediate |= value > 0 && value < 100;
				last = value;
			}
			Require(intermediate, "Real scan did not publish intermediate byte progress");
		}
	}
	fs::remove(capture);
	fs::remove(pipe);
	fs::remove(small);
	fs::remove(large);
	fs::remove(directory);
	std::cout << "Byte weighting, duplicate inputs, stream draining, unknown sizes, concurrent accounting and query "
	             "progress passed\n";
}
