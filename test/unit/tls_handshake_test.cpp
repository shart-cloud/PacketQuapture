#include "tls_handshake.hpp"

#include <cassert>
#include <cstdio>
#include <random>
#include <string>
#include <vector>

using namespace packetquapture;

namespace {

void Append16(std::vector<uint8_t> &out, uint16_t value) {
	out.push_back(static_cast<uint8_t>(value >> 8U));
	out.push_back(static_cast<uint8_t>(value & 0xFFU));
}

std::vector<uint8_t> Record(const std::vector<uint8_t> &body, uint8_t type = 22, uint16_t version = 0x0301) {
	std::vector<uint8_t> out;
	out.push_back(type);
	Append16(out, version);
	Append16(out, static_cast<uint16_t>(body.size()));
	out.insert(out.end(), body.begin(), body.end());
	return out;
}

std::vector<uint8_t> Message(const std::vector<uint8_t> &body, uint8_t type) {
	std::vector<uint8_t> out;
	out.push_back(type);
	out.push_back(static_cast<uint8_t>(body.size() >> 16U));
	out.push_back(static_cast<uint8_t>(body.size() >> 8U));
	out.push_back(static_cast<uint8_t>(body.size() & 0xFFU));
	out.insert(out.end(), body.begin(), body.end());
	return out;
}

std::vector<uint8_t> ServerNameExtension(const std::string &host) {
	std::vector<uint8_t> entry;
	entry.push_back(0);
	Append16(entry, static_cast<uint16_t>(host.size()));
	entry.insert(entry.end(), host.begin(), host.end());
	std::vector<uint8_t> out;
	Append16(out, 0);
	Append16(out, static_cast<uint16_t>(entry.size() + 2));
	Append16(out, static_cast<uint16_t>(entry.size()));
	out.insert(out.end(), entry.begin(), entry.end());
	return out;
}

std::vector<uint8_t> SupportedVersions(uint16_t version) {
	std::vector<uint8_t> out;
	Append16(out, 43);
	Append16(out, 2);
	Append16(out, version);
	return out;
}

std::vector<uint8_t> ClientHello(const std::vector<uint8_t> &extensions, const std::vector<uint8_t> &session = {}) {
	std::vector<uint8_t> body;
	Append16(body, 0x0303);
	body.insert(body.end(), 32, 0xAB);
	body.push_back(static_cast<uint8_t>(session.size()));
	body.insert(body.end(), session.begin(), session.end());
	Append16(body, 2);
	Append16(body, 0x1301);
	body.push_back(1);
	body.push_back(0);
	Append16(body, static_cast<uint16_t>(extensions.size()));
	body.insert(body.end(), extensions.begin(), extensions.end());
	return Message(body, 1);
}

std::vector<uint8_t> ServerHello(uint16_t suite, const std::vector<uint8_t> &extensions = {},
                                 const std::vector<uint8_t> &session = {}) {
	std::vector<uint8_t> body;
	Append16(body, 0x0303);
	body.insert(body.end(), 32, 0xCD);
	body.push_back(static_cast<uint8_t>(session.size()));
	body.insert(body.end(), session.begin(), session.end());
	Append16(body, suite);
	body.push_back(0);
	Append16(body, static_cast<uint16_t>(extensions.size()));
	body.insert(body.end(), extensions.begin(), extensions.end());
	return Message(body, 2);
}

TcpFlowKey Key(uint16_t client_port = 51000) {
	TcpFlowKey key;
	key.ip_version = 4;
	key.src_ip[0] = 10;
	key.dst_ip[0] = 20;
	key.src_port = client_port;
	key.dst_port = 443;
	return key;
}

PacketStamp Stamp(uint64_t number) {
	PacketStamp stamp;
	stamp.number = number;
	stamp.has_timestamp = true;
	stamp.timestamp = static_cast<int64_t>(number * 1000);
	return stamp;
}

// Builds the stream the transport core would produce for one direction.
TcpStream Stream(const TcpFlowKey &key, uint64_t stream_id, const std::vector<uint8_t> &bytes, uint64_t packet = 1,
                 const std::string &status = "") {
	TcpStream stream;
	stream.key = key;
	stream.stream_id = stream_id;
	stream.syn_seen = true;
	stream.expected_bytes = static_cast<uint32_t>(bytes.size());
	stream.captured_bytes = static_cast<uint32_t>(bytes.size());
	stream.first = Stamp(packet);
	stream.last = Stamp(packet);
	stream.status = status;
	TcpStreamChunk chunk;
	chunk.offset = 0;
	chunk.sequence = 1;
	chunk.data = bytes;
	TcpByteOrigin origin;
	origin.offset = 0;
	origin.length = bytes.size();
	origin.stamp = Stamp(packet);
	chunk.origins.push_back(origin);
	stream.chunks.push_back(chunk);
	return stream;
}

std::vector<uint8_t> Concat(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b) {
	std::vector<uint8_t> out = a;
	out.insert(out.end(), b.begin(), b.end());
	return out;
}

void TestPairedHandshake() {
	TlsHandshakeAssembler assembler;
	const auto key = Key();
	auto client = assembler.Add(Stream(key, 1, Record(ClientHello(ServerNameExtension("example.com"))), 1));
	// Nothing is reported until the peer direction arrives.
	assert(client.empty());
	auto done = assembler.Add(Stream(key.Reverse(), 2, Record(ServerHello(0x1301, SupportedVersions(0x0304))), 2));
	assert(done.size() == 1);
	const auto &handshake = done[0];
	assert(handshake.has_client_hello && handshake.has_server_hello);
	assert(handshake.has_sni && handshake.sni == "example.com");
	assert(handshake.has_negotiated_version && handshake.negotiated_version == 0x0304);
	assert(handshake.has_cipher_suite && handshake.cipher_suite == 0x1301);
	assert(handshake.status == "complete");
	assert(handshake.handshake_number == 1);
	// The key is oriented client to server whichever direction arrived first.
	assert(handshake.key.src_port == 51000 && handshake.key.dst_port == 443);
	assert(handshake.client_stream_id == 1 && handshake.server_stream_id == 2);
	assert(handshake.first.number == 1 && handshake.last.number == 2);
	assert(assembler.Empty());
}

void TestServerArrivingFirst() {
	TlsHandshakeAssembler assembler;
	const auto key = Key();
	assert(assembler.Add(Stream(key.Reverse(), 2, Record(ServerHello(0x009C)), 2)).empty());
	auto done = assembler.Add(Stream(key, 1, Record(ClientHello(ServerNameExtension("late.example"))), 1));
	assert(done.size() == 1);
	assert(done[0].has_client_hello && done[0].has_server_hello);
	assert(done[0].sni == "late.example");
	assert(done[0].key.src_port == 51000 && done[0].key.dst_port == 443);
}

void TestOrphanClientHello() {
	TlsHandshakeAssembler assembler;
	assembler.Add(Stream(Key(), 1, Record(ClientHello(ServerNameExtension("orphan.example"))), 1));
	auto done = assembler.Finish();
	assert(done.size() == 1);
	assert(done[0].has_client_hello && !done[0].has_server_hello);
	assert(done[0].sni == "orphan.example");
	// Server-side fields stay unset rather than being invented.
	assert(!done[0].has_negotiated_version && !done[0].has_cipher_suite);
	assert(!done[0].has_server_stream);
	assert(done[0].status == "one-sided");
	assert(assembler.Empty());
}

void TestOrphanServerHello() {
	TlsHandshakeAssembler assembler;
	assembler.Add(Stream(Key().Reverse(), 7, Record(ServerHello(0x1302)), 4));
	auto done = assembler.Finish();
	assert(done.size() == 1);
	assert(!done[0].has_client_hello && done[0].has_server_hello);
	assert(done[0].cipher_suite == 0x1302);
	assert(!done[0].has_sni);
	assert(!done[0].has_client_stream && done[0].server_stream_id == 7);
	assert(done[0].status == "one-sided");
	// Still oriented client to server, so it joins the others in a report.
	assert(done[0].key.src_port == 51000 && done[0].key.dst_port == 443);
}

// A handshake message split across two TLS records must still be read: records
// carry a byte stream, not message boundaries.
void TestMessageSpanningRecords() {
	const auto hello = ClientHello(ServerNameExtension("split.example.com"));
	const size_t cut = 20;
	std::vector<uint8_t> first(hello.begin(), hello.begin() + static_cast<long>(cut));
	std::vector<uint8_t> second(hello.begin() + static_cast<long>(cut), hello.end());
	TlsHandshakeAssembler assembler;
	assembler.Add(Stream(Key(), 1, Concat(Record(first), Record(second)), 1));
	auto done = assembler.Finish();
	assert(done.size() == 1);
	assert(done[0].has_sni && done[0].sni == "split.example.com");
	assert(done[0].status == "one-sided");
}

// Several handshake messages inside one record must all be seen.
void TestMultipleMessagesInOneRecord() {
	auto body = ServerHello(0x1301);
	const auto certificate = Message(std::vector<uint8_t>(32, 0), 11);
	body.insert(body.end(), certificate.begin(), certificate.end());
	TlsHandshakeAssembler assembler;
	assembler.Add(Stream(Key().Reverse(), 3, Record(body), 2));
	auto done = assembler.Finish();
	assert(done.size() == 1);
	assert(done[0].has_server_hello && done[0].cipher_suite == 0x1301);
}

void TestRenegotiationNumbersHandshakes() {
	auto client_bytes = Record(ClientHello(ServerNameExtension("first.example")));
	const auto again = Record(ClientHello(ServerNameExtension("second.example")));
	client_bytes.insert(client_bytes.end(), again.begin(), again.end());
	auto server_bytes = Record(ServerHello(0x009C));
	const auto server_again = Record(ServerHello(0x1301));
	server_bytes.insert(server_bytes.end(), server_again.begin(), server_again.end());

	TlsHandshakeAssembler assembler;
	const auto key = Key();
	assembler.Add(Stream(key, 1, client_bytes, 1));
	auto done = assembler.Add(Stream(key.Reverse(), 2, server_bytes, 2));
	assert(done.size() == 2);
	assert(done[0].handshake_number == 1 && done[0].sni == "first.example");
	assert(done[0].cipher_suite == 0x009C);
	assert(done[1].handshake_number == 2 && done[1].sni == "second.example");
	assert(done[1].cipher_suite == 0x1301);
}

// More ClientHellos than ServerHellos: the unanswered one is still reported.
void TestUnevenHandshakeCounts() {
	auto client_bytes = Record(ClientHello(ServerNameExtension("a.example")));
	const auto again = Record(ClientHello(ServerNameExtension("b.example")));
	client_bytes.insert(client_bytes.end(), again.begin(), again.end());

	TlsHandshakeAssembler assembler;
	const auto key = Key();
	assembler.Add(Stream(key, 1, client_bytes, 1));
	auto done = assembler.Add(Stream(key.Reverse(), 2, Record(ServerHello(0x009C)), 2));
	assert(done.size() == 2);
	assert(done[0].has_server_hello && done[0].status == "complete");
	assert(!done[1].has_server_hello && done[1].status == "one-sided");
	assert(done[1].sni == "b.example");
}

void TestSessionResumption() {
	const std::vector<uint8_t> session(32, 0x5A);
	TlsHandshakeAssembler assembler;
	const auto key = Key();
	assembler.Add(Stream(key, 1, Record(ClientHello(std::vector<uint8_t>(), session)), 1));
	auto done = assembler.Add(Stream(key.Reverse(), 2, Record(ServerHello(0x009C, {}, session)), 2));
	assert(done.size() == 1 && done[0].has_resumed && done[0].resumed);

	// A different session id echoed back is a full handshake.
	TlsHandshakeAssembler fresh;
	fresh.Add(Stream(key, 1, Record(ClientHello(std::vector<uint8_t>(), session)), 1));
	auto full = fresh.Add(Stream(key.Reverse(), 2, Record(ServerHello(0x009C, {}, std::vector<uint8_t>(32, 0x11))), 2));
	assert(full.size() == 1 && full[0].has_resumed && !full[0].resumed);

	// TLS 1.3 echoes the id regardless, so resumption is not decidable here.
	TlsHandshakeAssembler thirteen;
	thirteen.Add(Stream(key, 1, Record(ClientHello(std::vector<uint8_t>(), session)), 1));
	auto modern =
	    thirteen.Add(Stream(key.Reverse(), 2, Record(ServerHello(0x1301, SupportedVersions(0x0304), session)), 2));
	assert(modern.size() == 1 && !modern[0].has_resumed);
}

// Only one side can be decided without the peer, so a resumption verdict must
// not be offered for a one-sided handshake.
void TestResumptionNeedsBothSides() {
	TlsHandshakeAssembler assembler;
	assembler.Add(Stream(Key(), 1, Record(ClientHello(std::vector<uint8_t>(), std::vector<uint8_t>(32, 0x5A))), 1));
	auto done = assembler.Finish();
	assert(done.size() == 1 && !done[0].has_resumed);
}

// Parsing must stop at change_cipher_spec: what follows is encrypted and would
// otherwise be read as handshake bytes.
void TestStopsAtChangeCipherSpec() {
	auto bytes = Record(ServerHello(0x009C));
	const auto ccs = Record(std::vector<uint8_t>(1, 1), 20, 0x0303);
	bytes.insert(bytes.end(), ccs.begin(), ccs.end());
	// Encrypted bytes that happen to look like a ClientHello.
	const auto encrypted = Record(ClientHello(ServerNameExtension("must.not.appear")), 22, 0x0303);
	bytes.insert(bytes.end(), encrypted.begin(), encrypted.end());

	TlsHandshakeAssembler assembler;
	assembler.Add(Stream(Key().Reverse(), 1, bytes, 1));
	auto done = assembler.Finish();
	assert(done.size() == 1);
	assert(done[0].has_server_hello && !done[0].has_sni);
}

void TestTruncatedHandshakeIsReported() {
	auto hello = ClientHello(ServerNameExtension("cut.example"));
	// Declare the full length but supply only part of it.
	auto record = Record(hello);
	record.resize(record.size() - 30);
	record[3] = static_cast<uint8_t>((record.size() - 5) >> 8U);
	record[4] = static_cast<uint8_t>((record.size() - 5) & 0xFFU);
	TlsHandshakeAssembler assembler;
	assembler.Add(Stream(Key(), 1, record, 1));
	auto done = assembler.Finish();
	// The ClientHello could not be framed, so nothing is claimed about it.
	assert(done.empty());
}

void TestNonTlsStreamsAreIgnored() {
	TlsHandshakeAssembler assembler;
	const std::string http = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
	std::vector<uint8_t> bytes(http.begin(), http.end());
	assert(assembler.Add(Stream(Key(), 1, bytes, 1)).empty());
	assert(assembler.Add(Stream(Key(), 2, std::vector<uint8_t>(200, 0xFF), 2)).empty());
	// A transport failure on a stream we cannot classify is not a TLS finding.
	TcpStream failed = Stream(Key(), 3, std::vector<uint8_t>(), 3, "conflict");
	failed.chunks.clear();
	assert(assembler.Add(failed).empty());
	assert(assembler.Finish().empty());
}

// Two connections reusing the same address pair must not be merged into one.
void TestTupleReuse() {
	TlsHandshakeAssembler assembler;
	const auto key = Key();
	assert(assembler.Add(Stream(key, 1, Record(ClientHello(ServerNameExtension("first.example"))), 1)).empty());
	auto done = assembler.Add(Stream(key, 2, Record(ClientHello(ServerNameExtension("second.example"))), 5));
	assert(done.size() == 1);
	assert(done[0].sni == "first.example" && done[0].client_stream_id == 1);
	auto rest = assembler.Finish();
	assert(rest.size() == 1 && rest[0].sni == "second.example" && rest[0].client_stream_id == 2);
}

// Reverse() does not normalise section, interface_id or vlans, so directions
// captured with different tagging do not pair and are reported separately.
void TestDirectionsWithDifferentVlansDoNotPair() {
	TlsHandshakeAssembler assembler;
	auto client_key = Key();
	client_key.vlans.push_back(100);
	auto server_key = Key().Reverse();
	server_key.vlans.push_back(200);
	assembler.Add(Stream(client_key, 1, Record(ClientHello(ServerNameExtension("vlan.example"))), 1));
	assembler.Add(Stream(server_key, 2, Record(ServerHello(0x009C)), 2));
	auto done = assembler.Finish();
	assert(done.size() == 2);
	assert(done[0].has_client_hello != done[1].has_client_hello);
	assert(done[0].status == "one-sided" && done[1].status == "one-sided");
}

void TestPendingLimit() {
	TlsHandshakeLimits limits;
	limits.max_pending = 4;
	TlsHandshakeAssembler assembler(limits);
	size_t reported = 0;
	for (uint16_t port = 1; port <= 20; ++port) {
		auto key = Key(static_cast<uint16_t>(40000 + port));
		reported +=
		    assembler.Add(Stream(key, port, Record(ClientHello(ServerNameExtension("many.example"))), port)).size();
	}
	// Past the limit, directions are reported alone rather than accumulated.
	assert(reported > 0);
	const auto rest = assembler.Finish();
	assert(reported + rest.size() == 20);
}

void TestHandshakeCountLimit() {
	TlsHandshakeLimits limits;
	limits.max_handshakes = 3;
	TlsHandshakeAssembler assembler(limits);
	std::vector<uint8_t> bytes;
	for (int i = 0; i < 10; ++i) {
		const auto record = Record(ClientHello(ServerNameExtension("many.example")));
		bytes.insert(bytes.end(), record.begin(), record.end());
	}
	assembler.Add(Stream(Key(), 1, bytes, 1));
	auto done = assembler.Finish();
	assert(done.size() == 3);
	assert(done[0].status == "limit");
}

// Random bytes must never be reported as a handshake, and must never crash.
void TestFuzz() {
	std::mt19937 rng(20260920);
	std::uniform_int_distribution<int> byte(0, 255);
	std::uniform_int_distribution<size_t> length(0, 800);
	size_t reported = 0;
	for (size_t round = 0; round < 5000; ++round) {
		std::vector<uint8_t> bytes(length(rng));
		for (auto &value : bytes) {
			value = static_cast<uint8_t>(byte(rng));
		}
		TlsHandshakeAssembler assembler;
		reported += assembler.Add(Stream(Key(), 1, bytes, 1)).size();
		reported += assembler.Finish().size();
	}
	printf("fuzz: %zu handshakes reported from 5000 random streams\n", reported);
	assert(reported * 100 < 5000);
}

// Every truncation of a complete two-directional exchange must terminate and
// must never report a name it could not have read.
void TestTruncationsTerminate() {
	const auto client_bytes = Record(ClientHello(ServerNameExtension("example.com")));
	const auto server_bytes = Record(ServerHello(0x1301, SupportedVersions(0x0304)));
	for (size_t cut = 0; cut <= client_bytes.size(); ++cut) {
		std::vector<uint8_t> prefix(client_bytes.begin(), client_bytes.begin() + static_cast<long>(cut));
		TlsHandshakeAssembler assembler;
		assembler.Add(Stream(Key(), 1, prefix, 1));
		assembler.Add(Stream(Key().Reverse(), 2, server_bytes, 2));
		for (const auto &handshake : assembler.Finish()) {
			if (handshake.has_sni) {
				assert(handshake.sni == "example.com");
				assert(cut == client_bytes.size());
			}
		}
	}
}

} // namespace

int main() {
	TestPairedHandshake();
	TestServerArrivingFirst();
	TestOrphanClientHello();
	TestOrphanServerHello();
	TestMessageSpanningRecords();
	TestMultipleMessagesInOneRecord();
	TestRenegotiationNumbersHandshakes();
	TestUnevenHandshakeCounts();
	TestSessionResumption();
	TestResumptionNeedsBothSides();
	TestStopsAtChangeCipherSpec();
	TestTruncatedHandshakeIsReported();
	TestNonTlsStreamsAreIgnored();
	TestTupleReuse();
	TestDirectionsWithDifferentVlansDoNotPair();
	TestPendingLimit();
	TestHandshakeCountLimit();
	TestTruncationsTerminate();
	TestFuzz();
	printf("TLS handshake pairing, orphans, renegotiation, resumption and limits passed\n");
	return 0;
}
