#pragma once

#include "pq_assert.hpp"
#include "tls_record.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace packetquapture {

static const uint8_t TLS_HANDSHAKE_CLIENT_HELLO = 1;
static const uint8_t TLS_HANDSHAKE_SERVER_HELLO = 2;
static const uint8_t TLS_HANDSHAKE_CERTIFICATE = 11;
static const uint16_t TLS_EXTENSION_SERVER_NAME = 0;
static const uint16_t TLS_EXTENSION_SUPPORTED_VERSIONS = 43;
static const uint16_t TLS_VERSION_1_3 = 0x0304;

// Bounds-checked reader over one buffer of peer-supplied bytes, shared by the
// per-packet record reader and the reassembled handshake reader. After a read
// runs past the end the reader stays overrun and every later read fails, so
// malformed input unwinds without a check at each step.
class TlsReader {
public:
	TlsReader(const uint8_t *data_p, size_t size_p) : data(data_p), size(size_p) {
		if (size != 0) {
			PQ_ASSERT(data != nullptr);
		}
	}
	bool Overrun() const {
		return overrun;
	}
	size_t Remaining() const {
		PQ_ASSERT(offset <= size);
		return overrun ? 0 : size - offset;
	}
	uint8_t U8() {
		if (Remaining() < 1) {
			overrun = true;
			return 0;
		}
		return data[offset++];
	}
	uint16_t U16() {
		const uint16_t high = U8();
		const uint16_t low = U8();
		return static_cast<uint16_t>((high << 8U) | low);
	}
	uint32_t U24() {
		const uint32_t high = U8();
		const uint32_t mid = U8();
		const uint32_t low = U8();
		return (high << 16U) | (mid << 8U) | low;
	}
	bool Skip(size_t count) {
		if (Remaining() < count) {
			overrun = true;
			return false;
		}
		offset += count;
		return true;
	}
	// Consumes a block prefixed by a one- or two-byte length.
	bool SkipVector(size_t length_bytes) {
		PQ_ASSERT(length_bytes == 1 || length_bytes == 2);
		const size_t length = length_bytes == 1 ? U8() : U16();
		return !overrun && Skip(length);
	}
	bool Take(size_t count, std::string &out) {
		if (Remaining() < count) {
			overrun = true;
			return false;
		}
		out.assign(reinterpret_cast<const char *>(data + offset), count);
		offset += count;
		return true;
	}
	// The next count bytes as a reader of their own, without copying them.
	bool Sub(size_t count, TlsReader &out) {
		if (Remaining() < count) {
			overrun = true;
			return false;
		}
		out = TlsReader(data + offset, count);
		offset += count;
		return true;
	}
	// The next count bytes in place, for a parser that takes a pointer and length.
	bool TakeSpan(size_t count, const uint8_t *&out) {
		if (Remaining() < count) {
			overrun = true;
			return false;
		}
		out = data + offset;
		offset += count;
		return true;
	}
	bool TakeBytes(size_t count, std::vector<uint8_t> &out) {
		if (Remaining() < count) {
			overrun = true;
			return false;
		}
		out.assign(data + offset, data + offset + count);
		offset += count;
		return true;
	}

private:
	const uint8_t *data;
	size_t size;
	size_t offset = 0;
	bool overrun = false;
};

// RFC 6066 3: the body of a server_name extension, a ServerNameList holding at
// most one host_name. Other name types are skipped. Returns false when the
// list's framing is broken, so a caller can report the name as malformed rather
// than silently absent; has_name is set only for a complete host_name.
inline bool ParseTlsServerName(TlsReader &reader, bool &has_name, std::string &name) {
	has_name = false;
	name.clear();
	const uint16_t list_length = reader.U16();
	if (reader.Overrun() || reader.Remaining() != list_length) {
		return false;
	}
	size_t consumed = 0;
	while (consumed + 3 <= list_length) {
		const uint8_t name_type = reader.U8();
		const uint16_t name_length = reader.U16();
		consumed += 3;
		if (reader.Overrun() || name_length > list_length - consumed) {
			return false;
		}
		if (name_type == 0) { // host_name
			std::string raw;
			if (!reader.Take(name_length, raw)) {
				return false;
			}
			has_name = true;
			name = EscapeTlsText(raw);
			return true;
		}
		if (!reader.Skip(name_length)) {
			return false;
		}
		consumed += name_length;
	}
	return consumed == list_length;
}

} // namespace packetquapture
