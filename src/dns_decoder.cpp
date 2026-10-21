#include "dns_decoder.hpp"

#include "byte_order.hpp"
#include "pq_assert.hpp"
#include "text_escape.hpp"

#include <cstdio>

namespace packetquapture {
namespace {

class Parser {
public:
	Parser(const uint8_t *data_p, size_t size_p) : data(data_p), size(size_p) {
	}
	bool Has(size_t offset, size_t length) const {
		return offset <= size && length <= size - offset;
	}
	// A name is at most 255 octets (RFC 1035 3.1), so at most 127 labels. Each
	// compression pointer must target a prior occurrence: before the start of the
	// segment holding it. Segment starts then strictly decrease, which rules out
	// cycles. A legal name needs at most one pointer per label, so more than 127
	// pointers is rejected, and a name takes at most 127 labels, 127 pointers and
	// the terminator: STEPS_MAX steps. Total work across the message is bounded
	// separately, since names repeat.
	bool Name(size_t &offset, std::string &name) {
		static const unsigned STEPS_MAX = 127 + 127 + 1;
		size_t cursor = offset, expanded = 1, segment = offset;
		unsigned labels = 0, pointers = 0;
		bool jumped = false;
		for (unsigned step = 0; step < STEPS_MAX; ++step) {
			if (++work > 262144 || !Has(cursor, 1)) {
				return false;
			}
			const auto length = data[cursor++];
			if ((length & 0xc0U) == 0xc0U) {
				if (!Has(cursor, 1)) {
					return false;
				}
				const size_t target = ((length & 0x3fU) << 8U) | data[cursor++];
				if (target < 12 || target >= segment) {
					return false;
				}
				if (++pointers > 127) {
					return false;
				}
				if (!jumped) {
					offset = cursor;
					jumped = true;
				}
				cursor = segment = target;
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
			++labels;
			PQ_ASSERT(labels <= 127);
			if (!name.empty()) {
				name += '.';
			}
			for (size_t i = 0; i < length; ++i) {
				const auto ch = data[cursor++];
				if (ch >= 33 && ch <= 126 && ch != '.' && ch != '\\') {
					name += static_cast<char>(ch);
				} else {
					AppendDecimalEscape(name, ch);
				}
			}
		}
		// Every label and pointer is counted against a cap that returns first.
		PQ_ASSERT(false);
		return false;
	}
	bool Records(size_t &offset, uint16_t count, std::vector<DnsRecord> &records) {
		for (unsigned i = 0; i < count; ++i) {
			DnsRecord record;
			if (!Name(offset, record.name) || !Has(offset, 10)) {
				return false;
			}
			record.type = ReadBigEndian16(data + offset);
			record.klass = ReadBigEndian16(data + offset + 2);
			record.ttl = ReadBigEndian32(data + offset + 4);
			const auto length = ReadBigEndian16(data + offset + 8);
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
				std::snprintf(address, sizeof(address), "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
				              ReadBigEndian16(data + offset), ReadBigEndian16(data + offset + 2),
				              ReadBigEndian16(data + offset + 4), ReadBigEndian16(data + offset + 6),
				              ReadBigEndian16(data + offset + 8), ReadBigEndian16(data + offset + 10),
				              ReadBigEndian16(data + offset + 12), ReadBigEndian16(data + offset + 14));
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
	result.id = ReadBigEndian16(data);
	const auto flags = ReadBigEndian16(data + 2);
	result.response = (flags & 0x8000U) != 0;
	result.truncated = (flags & 0x0200U) != 0;
	result.opcode = (flags >> 11U) & 15U;
	result.rcode = flags & 15U;
	const auto questions = ReadBigEndian16(data + 4), answers = ReadBigEndian16(data + 6),
	           authorities = ReadBigEndian16(data + 8), additionals = ReadBigEndian16(data + 10);
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
		question.type = ReadBigEndian16(data + offset);
		question.klass = ReadBigEndian16(data + offset + 2);
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
