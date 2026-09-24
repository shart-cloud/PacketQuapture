#pragma once

#include "tcp_reassembly.hpp"
#include "tls_record.hpp"

namespace packetquapture {

struct TlsHandshakeLimits {
	// Handshakes reported per connection. Renegotiation in the clear is rare;
	// a flow claiming many handshakes is more likely malformed than interesting.
	size_t max_handshakes = 16;
	// One handshake message. A ClientHello or ServerHello far above this is not
	// something we can usefully report on.
	size_t max_message_bytes = 64 * 1024;
	size_t max_extensions = 256;
	// Entries in one parsed list, such as cipher suites or supported groups.
	// Real hellos carry well under a hundred; the cap bounds what a pending
	// direction holds.
	size_t max_list_entries = 1024;
	// Directions held while waiting for their peer. Each holds parsed fields,
	// not payload bytes.
	size_t max_pending = 512;
};

// RFC 8701 reserves the same sixteen values, 0x0A0A through 0xFAFA, for GREASE
// in cipher suites, extensions, named groups, signature algorithms and versions.
inline bool IsTlsGrease(uint16_t value) {
	return (value >> 8U) == (value & 0xFFU) && (value & 0x0FU) == 0x0AU;
}

// ALPN GREASE identifiers are the same values as two raw bytes.
inline bool IsTlsGreaseAlpn(const std::string &protocol) {
	return protocol.size() == 2 && IsTlsGrease(static_cast<uint16_t>((static_cast<unsigned char>(protocol[0]) << 8U) |
	                                                                 static_cast<unsigned char>(protocol[1])));
}

// A list read from a hello. Absent means the hello did not carry it; a list
// that was present but malformed or longer than max_list_entries is reported
// absent with malformed or over_limit set, so an empty list always means the
// peer sent an empty list, and only a list that is neither is really missing.
template <class T>
struct TlsList {
	bool present = false;
	bool malformed = false;
	bool over_limit = false;
	std::vector<T> values;

	// Whether the hello's value for this list is known: present, or not sent.
	bool Known() const {
		return !malformed && !over_limit;
	}
};

// One reported handshake. The key is oriented client to server, whichever
// direction was actually captured.
struct TlsHandshake {
	TcpFlowKey key;
	bool has_client_stream = false, has_server_stream = false;
	uint64_t client_stream_id = 0, server_stream_id = 0;
	uint64_t handshake_number = 0;
	PacketStamp first, last;

	bool has_client_hello = false;
	bool has_sni = false;
	std::string sni;
	// legacy_version from the ClientHello, which is a compatibility value.
	bool has_client_version = false;
	uint16_t client_version = 0;
	// Lists from the ClientHello, in wire order and including GREASE. The
	// cipher suites and extension types are present whenever the hello parsed.
	TlsList<uint16_t> client_cipher_suites, client_extensions, client_supported_groups, client_signature_algorithms,
	    client_supported_versions;
	TlsList<uint8_t> client_ec_point_formats;
	// Raw protocol identifiers; they are peer-supplied bytes, escaped on output.
	TlsList<std::string> client_alpn;

	bool has_server_hello = false;
	// The version actually selected: supported_versions when the server sent it,
	// otherwise legacy_version from the ServerHello.
	bool has_negotiated_version = false;
	uint16_t negotiated_version = 0;
	// legacy_version from the ServerHello, before supported_versions. JA3S
	// fingerprints this, not the version actually selected.
	bool has_server_legacy_version = false;
	uint16_t server_legacy_version = 0;
	bool has_cipher_suite = false;
	uint16_t cipher_suite = 0;
	TlsList<uint16_t> server_extensions;
	// The one protocol a server selects, if it sent ALPN.
	TlsList<std::string> server_alpn;
	// The one version a server selects in supported_versions, if it sent it.
	// Not a column; it feeds negotiated_version and the malformed warning.
	TlsList<uint16_t> server_supported_versions;
	// Only decidable when both sides were captured and neither is TLS 1.3.
	bool has_resumed = false;
	bool resumed = false;

	std::string status, error;
	// Conditions that leave some columns NULL without being a reassembly
	// failure, such as an uncaptured side. Stable codes, in a fixed order.
	std::vector<std::string> warnings;
};

// Pairs the two directions of a connection, which the transport core finishes
// independently. Streams are added in scan order; a direction whose peer never
// arrives is reported on its own when Finish() is called.
//
// Stateless with respect to the transport: owns no flows, reorders nothing, and
// interprets no TCP flags. It holds only parsed handshake fields between the two
// directions of a connection.
class TlsHandshakeAssembler {
public:
	explicit TlsHandshakeAssembler(TlsHandshakeLimits limits_p = TlsHandshakeLimits());
	// Returns the handshakes completed by this stream, if any.
	std::vector<TlsHandshake> Add(const TcpStream &stream);
	// Returns handshakes for every direction still waiting for a peer.
	std::vector<TlsHandshake> Finish();
	bool Empty() const;

private:
	// A single direction's parsed handshakes, held until its peer arrives.
	struct Direction {
		TcpFlowKey oriented_key;
		uint64_t stream_id = 0;
		bool client = false;
		PacketStamp first, last;
		std::string status, error;
		std::vector<TlsHandshake> handshakes;
		// Kept beside each handshake rather than on the reported row: it is only
		// used to decide resumption once both directions are known.
		std::vector<std::vector<uint8_t>> session_ids;
	};
	static Direction Parse(const TcpStream &stream, const TlsHandshakeLimits &limits);
	static std::vector<TlsHandshake> Merge(const Direction &client, const Direction *server);
	TlsHandshakeLimits limits;
	std::map<TcpFlowKey, Direction> pending;
};

} // namespace packetquapture
