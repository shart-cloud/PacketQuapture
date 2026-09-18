#include "dns_decoder.hpp"

#include <cstdio>

namespace packetquapture {
namespace {
uint16_t U16(const uint8_t *p) {
	return (uint16_t(p[0]) << 8U) | p[1];
}
uint32_t U32(const uint8_t *p) {
	return (uint32_t(U16(p)) << 16U) | U16(p + 2);
}

class Parser {
public:
	Parser(const uint8_t *data_p, size_t size_p) : data(data_p), size(size_p) {
	}
	bool Has(size_t offset, size_t length) const {
		return offset <= size && length <= size - offset;
	}
	// Bound total work as well as pointer hops; names may contain arbitrary octets.
	bool Name(size_t &offset, std::string &name) {
		size_t cursor = offset, expanded = 1;
		bool jumped = false;
		for (unsigned hops = 0; hops < 128; ++hops) {
			if (++work > 262144 || !Has(cursor, 1)) {
				return false;
			}
			const auto length = data[cursor++];
			if ((length & 0xc0U) == 0xc0U) {
				if (!Has(cursor, 1)) {
					return false;
				}
				const size_t target = ((length & 0x3fU) << 8U) | data[cursor++];
				// RFC 1035 compression references prior occurrences; rejects cycles/forward pointers.
				if (target < 12 || target >= cursor - 2) {
					return false;
				}
				if (!jumped) {
					offset = cursor;
					jumped = true;
				}
				cursor = target;
				continue;
			}
			if (length > 63 || !Has(cursor, length)) {
				return false;
			}
			if (length == 0) {
				if (!jumped) {
					offset = cursor;
				}
				if (name.empty()) {
					name = ".";
				}
				return true;
			}
			expanded += length + 1;
			if (expanded > 255) {
				return false;
			}
			if (!name.empty()) {
				name += '.';
			}
			for (size_t i = 0; i < length; ++i) {
				const auto ch = data[cursor++];
				if (ch >= 33 && ch <= 126 && ch != '.' && ch != '\\') {
					name += static_cast<char>(ch);
				} else {
					char escaped[5];
					std::snprintf(escaped, sizeof(escaped), "\\%03u", ch);
					name += escaped;
				}
			}
		}
		return false;
	}
	bool Records(size_t &offset, uint16_t count, std::vector<DnsRecord> &records) {
		for (unsigned i = 0; i < count; ++i) {
			DnsRecord record;
			if (!Name(offset, record.name) || !Has(offset, 10)) {
				return false;
			}
			record.type = U16(data + offset);
			record.klass = U16(data + offset + 2);
			record.ttl = U32(data + offset + 4);
			const auto length = U16(data + offset + 8);
			offset += 10;
			if (!Has(offset, length)) {
				return false;
			}
			record.data.assign(data + offset, data + offset + length);
			char address[40];
			if (record.type == 1 && record.klass == 1) {
				if (length != 4) {
					return false;
				}
				std::snprintf(address, sizeof(address), "%u.%u.%u.%u", data[offset], data[offset + 1], data[offset + 2],
				              data[offset + 3]);
				record.text = address;
				record.has_text = true;
			} else if (record.type == 28 && record.klass == 1) {
				if (length != 16) {
					return false;
				}
				std::snprintf(address, sizeof(address), "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", U16(data + offset),
				              U16(data + offset + 2), U16(data + offset + 4), U16(data + offset + 6),
				              U16(data + offset + 8), U16(data + offset + 10), U16(data + offset + 12),
				              U16(data + offset + 14));
				record.text = address;
				record.has_text = true;
			} else if (record.type == 2 || record.type == 5 || record.type == 12) {
				auto cursor = offset;
				if (!Name(cursor, record.text) || cursor != offset + length) {
					return false;
				}
				record.has_text = true;
			}
			offset += length;
			records.push_back(std::move(record));
		}
		return true;
	}

private:
	const uint8_t *data;
	size_t size;
	size_t work = 0;
};
} // namespace

DnsMessage DecodeDns(const uint8_t *data, size_t size) {
	DnsMessage invalid;
	invalid.error = "malformed or truncated DNS message";
	if (size < 12 || size > 65535) {
		return invalid;
	}
	Parser parser(data, size);
	DnsMessage result;
	result.id = U16(data);
	const auto flags = U16(data + 2);
	result.response = (flags & 0x8000U) != 0;
	result.truncated = (flags & 0x0200U) != 0;
	result.opcode = (flags >> 11U) & 15U;
	result.rcode = flags & 15U;
	const auto questions = U16(data + 4), answers = U16(data + 6), authorities = U16(data + 8),
	           additionals = U16(data + 10);
	if (uint32_t(questions) + answers + authorities + additionals > 4096) {
		invalid.error = "DNS record count exceeds safety limit";
		return invalid;
	}
	size_t offset = 12;
	for (unsigned i = 0; i < questions; ++i) {
		DnsQuestion question;
		if (!parser.Name(offset, question.name) || !parser.Has(offset, 4)) {
			return invalid;
		}
		question.type = U16(data + offset);
		question.klass = U16(data + offset + 2);
		offset += 4;
		result.questions.push_back(std::move(question));
	}
	if (!parser.Records(offset, answers, result.answers) || !parser.Records(offset, authorities, result.authorities) ||
	    !parser.Records(offset, additionals, result.additionals) || offset != size) {
		return invalid;
	}
	result.valid = true;
	return result;
}
} // namespace packetquapture
