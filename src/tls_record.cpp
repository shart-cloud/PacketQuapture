#include "tls_record.hpp"

#include "tls_reader.hpp"

namespace packetquapture {
namespace {

bool KnownRecordType(uint8_t type) {
	return type >= TLS_RECORD_CHANGE_CIPHER_SPEC && type <= TLS_RECORD_HEARTBEAT;
}

// Walks a ClientHello body far enough to reach the server_name extension. The
// reader spans exactly the message, so a broken extension length cannot run into
// the next message. Returns false when the message runs past its own length.
bool ParseClientHello(TlsReader &reader, TlsRecord &result) {
	if (!reader.Skip(2 + 32)) { // legacy_version, random
		return false;
	}
	if (!reader.SkipVector(1)) { // legacy_session_id
		return false;
	}
	if (!reader.SkipVector(2)) { // cipher_suites
		return false;
	}
	if (!reader.SkipVector(1)) { // legacy_compression_methods
		return false;
	}
	// A ClientHello with no extensions is legal and simply carries no SNI.
	if (reader.Remaining() == 0) {
		return true;
	}
	const uint16_t extensions_length = reader.U16();
	if (reader.Overrun()) {
		return false;
	}
	size_t consumed = 0;
	while (consumed + 4 <= extensions_length) {
		const uint16_t extension_type = reader.U16();
		const uint16_t extension_length = reader.U16();
		consumed += 4;
		if (reader.Overrun() || extension_length > extensions_length - consumed) {
			return false;
		}
		TlsReader extension(nullptr, 0);
		if (!reader.Sub(extension_length, extension)) {
			return false;
		}
		consumed += extension_length;
		if (extension_type == TLS_EXTENSION_SERVER_NAME) {
			// A malformed name list leaves the name absent; the hello itself is
			// still whole, so it is not reported truncated.
			ParseTlsServerName(extension, result.has_server_name, result.server_name);
			return true;
		}
	}
	return !reader.Overrun();
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
	// Identify TLS by shape rather than by port.
	if (!KnownRecordType(record_type) || !TlsRecordHeaderValid(data)) {
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

	TlsReader record(data + TLS_RECORD_HEADER_LENGTH, record_length);
	const uint8_t handshake_type = record.U8();
	const uint32_t handshake_length = record.U24();
	if (record.Overrun()) {
		return result;
	}
	result.has_handshake_type = true;
	result.handshake_type = handshake_type;
	if (handshake_type != TLS_HANDSHAKE_CLIENT_HELLO) {
		return result;
	}
	result.client_hello = true;
	// A ClientHello larger than its record spans further records, so anything
	// not found here is unknown rather than absent.
	TlsReader hello(nullptr, 0);
	if (!record.Sub(handshake_length, hello)) {
		result.truncated = true;
		return result;
	}
	if (!ParseClientHello(hello, result)) {
		result.truncated = true;
		result.has_server_name = false;
		result.server_name.clear();
	}
	return result;
}

} // namespace packetquapture
