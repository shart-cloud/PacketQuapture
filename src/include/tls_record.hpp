#pragma once

#include "text_escape.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

namespace packetquapture {

// Largest record a peer may send: RFC 8446 caps the plaintext fragment at 2^14
// and the ciphertext expansion at 256 bytes, but TLS 1.2 implementations are
// permitted 2^14 + 2048. Take the larger bound so a valid record is never
// rejected for length alone.
static const uint32_t TLS_MAX_RECORD_LENGTH = 16384 + 2048;
static const uint32_t TLS_RECORD_HEADER_LENGTH = 5;

enum TlsRecordType : uint8_t {
	TLS_RECORD_CHANGE_CIPHER_SPEC = 20,
	TLS_RECORD_ALERT = 21,
	TLS_RECORD_HANDSHAKE = 22,
	TLS_RECORD_APPLICATION_DATA = 23,
	TLS_RECORD_HEARTBEAT = 24,
};

// The version and length checks every record header must pass: an SSL 3.0 to
// TLS 1.3 version, and a non-empty body within TLS_MAX_RECORD_LENGTH. The major
// version byte is 0x03 for every TLS and SSL 3.0 version, and TLS 1.3 still
// writes a 1.2 value here for middlebox compatibility.
inline bool TlsRecordHeaderValid(const uint8_t *header) {
	const uint32_t length = static_cast<uint32_t>((header[3] << 8U) | header[4]);
	return header[1] == 0x03 && header[2] <= 0x04 && length != 0 && length <= TLS_MAX_RECORD_LENGTH;
}

// The result of parsing one TCP payload as the start of a TLS record. Nothing
// here spans packets: a field that needs bytes beyond this payload is reported
// absent with truncated set, and the reassembled reader resolves it.
struct TlsRecord {
	// A record header was found at the start of the payload.
	bool valid = false;
	uint8_t record_type = 0;
	// The version in the record header, which for a ClientHello is a
	// compatibility value and not the version that gets negotiated.
	uint16_t record_version = 0;
	uint32_t record_length = 0;

	// Set only for a handshake record whose first message header is present.
	bool has_handshake_type = false;
	uint8_t handshake_type = 0;

	// Set when this payload holds a ClientHello, whether or not it carried SNI.
	bool client_hello = false;
	// A complete host_name from the server_name extension.
	bool has_server_name = false;
	std::string server_name;
	// The ClientHello continues past this payload, so absent fields are unknown
	// rather than known-absent.
	bool truncated = false;
};

// Renders peer-supplied bytes, such as a server name, as text. Printable ASCII
// other than backslash passes through; every other byte becomes a decimal \DDD
// escape, as DNS names do. The result is always valid UTF-8, so a hostile name
// cannot fail the query, and distinct inputs stay distinct.
inline std::string EscapeTlsText(const std::string &raw) {
	std::string text;
	text.reserve(raw.size());
	for (size_t i = 0; i < raw.size(); ++i) {
		const auto ch = static_cast<unsigned char>(raw[i]);
		if (ch >= 33 && ch <= 126 && ch != '\\') {
			text += static_cast<char>(ch);
		} else {
			AppendDecimalEscape(text, ch);
		}
	}
	return text;
}

// Parses the payload as a TLS record. Reads only the bytes given and never
// throws; a payload that is not TLS yields a default-constructed result.
TlsRecord DecodeTlsRecord(const uint8_t *data, size_t size);

} // namespace packetquapture
