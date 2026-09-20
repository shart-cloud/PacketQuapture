#pragma once

#include "tcp_reassembly.hpp"

namespace packetquapture {

struct TlsHandshakeLimits {
	// Handshakes reported per connection. Renegotiation in the clear is rare;
	// a flow claiming many handshakes is more likely malformed than interesting.
	size_t max_handshakes = 16;
	// One handshake message. A ClientHello or ServerHello far above this is not
	// something we can usefully report on.
	size_t max_message_bytes = 64 * 1024;
	size_t max_extensions = 256;
	// Directions held while waiting for their peer. Each holds parsed fields,
	// not payload bytes.
	size_t max_pending = 512;
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

	bool has_server_hello = false;
	// The version actually selected: supported_versions when the server sent it,
	// otherwise legacy_version from the ServerHello.
	bool has_negotiated_version = false;
	uint16_t negotiated_version = 0;
	bool has_cipher_suite = false;
	uint16_t cipher_suite = 0;
	// Only decidable when both sides were captured and neither is TLS 1.3.
	bool has_resumed = false;
	bool resumed = false;

	std::string status, error;
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
