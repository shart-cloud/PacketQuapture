#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace packetquapture {
struct DnsQuestion {
	std::string name;
	uint16_t type = 0, klass = 0;
};
struct DnsRecord {
	std::string name;
	uint16_t type = 0, klass = 0;
	uint32_t ttl = 0;
	bool has_text = false;
	std::string text;
	std::vector<uint8_t> data;
};
struct DnsMessage {
	bool valid = false;
	std::string error;
	uint16_t id = 0;
	bool response = false, truncated = false;
	uint8_t opcode = 0, rcode = 0;
	std::vector<DnsQuestion> questions;
	std::vector<DnsRecord> answers, authorities, additionals;
};
DnsMessage DecodeDns(const uint8_t *data, size_t size);
} // namespace packetquapture
