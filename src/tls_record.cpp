#include "tls_record.hpp"

namespace packetquapture {
namespace {

// A cursor over one payload. Every read is bounds-checked; once a read runs past
// the end the cursor stays overrun and all later reads fail, so a malformed
// record unwinds without special-casing each step.
class Cursor {
public:
	Cursor(const uint8_t *data_p, size_t size_p) : data(data_p), size(size_p) {
	}
	bool Overrun() const {
		return overrun;
	}
	size_t Remaining() const {
		return overrun ? 0 : size - offset;
	}
	bool Skip(size_t count) {
		if (Remaining() < count) {
			overrun = true;
			return false;
		}
		offset += count;
		return true;
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
	// Consumes a length-prefixed block and returns whether it fit.
	bool SkipVector(size_t length_bytes) {
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

private:
	const uint8_t *data;
	size_t size;
	size_t offset = 0;
	bool overrun = false;
};

const uint16_t EXTENSION_SERVER_NAME = 0;
const uint8_t SERVER_NAME_TYPE_HOST = 0;
const uint8_t HANDSHAKE_CLIENT_HELLO = 1;

bool KnownRecordType(uint8_t type) {
	return type >= TLS_RECORD_CHANGE_CIPHER_SPEC && type <= TLS_RECORD_HEARTBEAT;
}

// Reads the server_name extension body. Only host_name entries carry a name;
// any other entry type is skipped rather than treated as an error.
void ParseServerNameExtension(Cursor &cursor, TlsRecord &result) {
	const uint16_t list_length = cursor.U16();
	if (cursor.Overrun() || cursor.Remaining() < list_length) {
		return;
	}
	size_t consumed = 0;
	while (consumed + 3 <= list_length) {
		const uint8_t name_type = cursor.U8();
		const uint16_t name_length = cursor.U16();
		consumed += 3;
		if (cursor.Overrun() || name_length > list_length - consumed) {
			return;
		}
		if (name_type == SERVER_NAME_TYPE_HOST) {
			std::string name;
			if (cursor.Take(name_length, name)) {
				result.has_server_name = true;
				result.server_name = EscapeTlsText(name);
			}
			return;
		}
		if (!cursor.Skip(name_length)) {
			return;
		}
		consumed += name_length;
	}
}

// Walks a ClientHello body far enough to reach the extension list. Returns
// false when the message runs past the bytes available.
bool ParseClientHello(Cursor &cursor, TlsRecord &result) {
	cursor.Skip(2);              // legacy_version
	cursor.Skip(32);             // random
	if (!cursor.SkipVector(1)) { // legacy_session_id
		return false;
	}
	if (!cursor.SkipVector(2)) { // cipher_suites
		return false;
	}
	if (!cursor.SkipVector(1)) { // legacy_compression_methods
		return false;
	}
	const uint16_t extensions_length = cursor.U16();
	if (cursor.Overrun()) {
		return false;
	}
	// A ClientHello with no extensions is legal and simply carries no SNI.
	size_t consumed = 0;
	while (consumed + 4 <= extensions_length) {
		const uint16_t extension_type = cursor.U16();
		const uint16_t extension_length = cursor.U16();
		consumed += 4;
		if (cursor.Overrun() || extension_length > extensions_length - consumed) {
			return false;
		}
		if (extension_type == EXTENSION_SERVER_NAME) {
			ParseServerNameExtension(cursor, result);
			return !cursor.Overrun();
		}
		if (!cursor.Skip(extension_length)) {
			return false;
		}
		consumed += extension_length;
	}
	return !cursor.Overrun();
}

} // namespace

TlsRecord DecodeTlsRecord(const uint8_t *data, size_t size) {
	TlsRecord result;
	if (data == nullptr || size < TLS_RECORD_HEADER_LENGTH) {
		return result;
	}
	const uint8_t record_type = data[0];
	const uint16_t record_version = static_cast<uint16_t>((data[1] << 8U) | data[2]);
	const uint32_t record_length = static_cast<uint32_t>((data[3] << 8U) | data[4]);
	// Identify TLS by shape rather than by port. The major version byte is 0x03
	// for every TLS and SSL 3.0 version, and TLS 1.3 still writes a 1.2 value
	// here for middlebox compatibility.
	if (!KnownRecordType(record_type) || data[1] != 0x03 || data[2] > 0x04) {
		return result;
	}
	if (record_length == 0 || record_length > TLS_MAX_RECORD_LENGTH) {
		return result;
	}
	// Require the record to fit the payload. A record continuing into the next
	// segment is left to the reassembled reader, which keeps this layer's false
	// positive rate low on arbitrary binary traffic.
	if (record_length + TLS_RECORD_HEADER_LENGTH > size) {
		return result;
	}
	result.valid = true;
	result.record_type = record_type;
	result.record_version = record_version;
	result.record_length = record_length;
	if (record_type != TLS_RECORD_HANDSHAKE) {
		return result;
	}

	Cursor cursor(data + TLS_RECORD_HEADER_LENGTH, record_length);
	const uint8_t handshake_type = cursor.U8();
	const uint32_t handshake_length = cursor.U24();
	if (cursor.Overrun()) {
		return result;
	}
	result.has_handshake_type = true;
	result.handshake_type = handshake_type;
	if (handshake_type != HANDSHAKE_CLIENT_HELLO) {
		return result;
	}
	result.client_hello = true;
	// A ClientHello larger than its record spans further records, so anything
	// not found here is unknown rather than absent.
	if (handshake_length > cursor.Remaining()) {
		result.truncated = true;
		return result;
	}
	if (!ParseClientHello(cursor, result)) {
		result.truncated = true;
		result.has_server_name = false;
		result.server_name.clear();
	}
	return result;
}

} // namespace packetquapture
