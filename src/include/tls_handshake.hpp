#pragma once

#include "tcp_reassembly.hpp"
#include "tls_record.hpp"
#include "x509_certificate.hpp"

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
	// The server's Certificate message: certificates in the chain, and bytes in
	// one certificate. Real chains hold two to four certificates of a few KiB.
	size_t max_certificates = 16;
	size_t max_certificate_bytes = 32 * 1024;
	// Parsed certificate text one direction holds, across all its handshakes.
	// Without it a direction waiting for its peer could hold 16 handshakes of
	// 64 KiB messages, each growing when escaped.
	size_t max_direction_certificate_bytes = 256 * 1024;
	// Directions held while waiting for their peer. Each holds parsed fields,
	// not payload bytes: bounded hello lists and at most
	// max_direction_certificate_bytes of certificate text.
	size_t max_pending = 512;
	// Bytes a tunnel, such as a SOCKS or HTTP CONNECT exchange, may put before
	// the first TLS record of a direction. SOCKS takes tens of bytes; an HTTP
	// proxy login with a 407 page or a Negotiate token can take a few KiB. The
	// cap bounds the search for a hello in a stream that does not begin with one.
	size_t max_tunnel_prefix_bytes = 8 * 1024;
	// Fills a parsed certificate's sha1 and sha256 from its DER. This library has
	// no hash of its own; the extension supplies DuckDB's, and only when a
	// certificate column is projected. Left unset, they stay empty. Not a limit,
	// but it travels with them to every certificate parse.
	void (*certificate_digest)(const uint8_t *der, size_t size, X509Certificate &out) = nullptr;
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

// One certificate from a Certificate message. One that did not parse is kept,
// unparsed, so the chain keeps its length and order.
struct TlsCertificate {
	bool parsed = false;
	X509Certificate fields;
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
	// The Certificate message that followed the ServerHello, in wire order, leaf
	// first. TLS 1.3 encrypts it, so it is only read in TLS 1.2 and earlier.
	TlsList<TlsCertificate> server_certificates;
	// The client's Certificate message, sent when the server asked for one, read
	// the same way and with the same TLS 1.3 limitation. An empty list means the
	// client was asked and had none to send.
	TlsList<TlsCertificate> client_certificates;
	// Only decidable when both sides were captured and neither is TLS 1.3.
	bool has_resumed = false;
	bool resumed = false;
	// Bytes before the first TLS record in each captured direction; zero when
	// TLS began the stream. A tunnel is the usual cause.
	uint32_t client_prefix_bytes = 0, server_prefix_bytes = 0;
	// What each prefix parsed as, exactly: socks4, socks4a, socks5 or
	// http_connect. Empty when there is no prefix or it was not recognised.
	std::string client_tunnel, server_tunnel;
	// The host:port the client asked its tunnel to reach, escaped as tls_sni is.
	// Only a recognised client prefix names one.
	std::string tunnel_destination;

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
		// Bytes before the first TLS record, and what they parsed as.
		uint32_t prefix_bytes = 0;
		// Found by searching a stream whose SYN was not captured, so its first
		// byte is mid-conversation. Reported only once the other direction of
		// the same connection confirms it; see Add.
		bool needs_confirmation = false;
		std::string tunnel, tunnel_destination;
		std::vector<TlsHandshake> handshakes;
		// Kept beside each handshake rather than on the reported row: it is only
		// used to decide resumption once both directions are known.
		std::vector<std::vector<uint8_t>> session_ids;
	};
	static Direction Parse(const TcpStream &stream, const TlsHandshakeLimits &limits);
	static void ParseRecords(const TcpStream &stream, const TcpStreamChunk &chunk, size_t start,
	                         const TlsHandshakeLimits &limits, Direction &direction);
	static std::vector<TlsHandshake> Merge(const Direction &client, const Direction *server);
	static bool Confirms(const Direction &peer, const Direction &found);
	static std::vector<TlsHandshake> ReportAlone(const Direction &direction);
	bool Hold(const Direction &direction);
	void Release(std::map<TcpFlowKey, Direction>::iterator it);
	TlsHandshakeLimits limits;
	std::map<TcpFlowKey, Direction> pending;
	// How many held directions still need confirmation.
	size_t unconfirmed = 0;
};

} // namespace packetquapture
