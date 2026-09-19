#pragma once
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/error_data.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "packet_decoder.hpp"
#include <limits>
#include <set>

namespace duckdb {
struct CaptureIdentity {
	int64_t size = -1;
	timestamp_t modified = timestamp_t::ninfinity();
	string tag, backend;
	bool Known() const {
		return size >= 0 || Timestamp::IsFinite(modified) || !tag.empty();
	}
	bool Same(const CaptureIdentity &other) const {
		return size == other.size && modified == other.modified && tag == other.tag && backend == other.backend;
	}
};
inline CaptureIdentity ReadCaptureIdentity(FileSystem &fs, FileHandle &handle) {
	CaptureIdentity result;
	result.backend = handle.file_system.GetName();
	try {
		auto stats = fs.Stats(handle);
		result.size = stats.file_size;
		result.modified = stats.last_modification_time;
	} catch (const NotImplementedException &) {
		try {
			result.size = fs.GetFileSize(handle);
		} catch (const NotImplementedException &) {
		}
		try {
			result.modified = fs.GetLastModifiedTime(handle);
		} catch (const NotImplementedException &) {
		}
	}
	try {
		result.tag = fs.GetVersionTag(handle);
	} catch (const NotImplementedException &) {
	}
	return result;
}
struct InventoryTotals {
	uint64_t packets = 0, null_timestamps = 0, captured = 0, reported = 0;
	uint64_t ipv4 = 0, ipv6 = 0, tcp = 0, udp = 0, other = 0, malformed = 0, unsupported = 0, fragments = 0;
	bool timed = false;
	timestamp_t minimum, maximum;
	static void Add(uint64_t &counter, uint64_t value) {
		if (value > std::numeric_limits<uint64_t>::max() - counter) {
			throw OutOfRangeException("Capture inventory counter exceeds UBIGINT capacity");
		}
		counter += value;
	}
	void Observe(bool has_time, timestamp_t time, uint32_t cap, uint32_t orig, const packetquapture::DecodedPacket &p,
	             bool protocols) {
		Add(packets, 1);
		Add(captured, cap);
		Add(reported, orig);
		if (!has_time)
			Add(null_timestamps, 1);
		else {
			minimum = timed ? MinValue(minimum, time) : time;
			maximum = timed ? MaxValue(maximum, time) : time;
			timed = true;
		}
		if (!protocols)
			return;
		Add(ipv4, p.network && p.ip_version == 4);
		Add(ipv6, p.network && p.ip_version == 6);
		Add(tcp, p.tcp);
		Add(udp, p.udp);
		Add(other, p.network && p.ip_protocol != 6 && p.ip_protocol != 17 &&
		               p.outcome == packetquapture::DecodeOutcome::UNSUPPORTED);
		Add(malformed, p.outcome == packetquapture::DecodeOutcome::MALFORMED);
		Add(unsupported, p.outcome == packetquapture::DecodeOutcome::UNSUPPORTED);
		Add(fragments, p.outcome == packetquapture::DecodeOutcome::FRAGMENT);
	}
};
} // namespace duckdb
