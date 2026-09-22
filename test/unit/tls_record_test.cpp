#include "tls_record.hpp"

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

std::vector<uint8_t> Handshake(const std::vector<uint8_t> &body, uint8_t type = 1) {
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
	entry.push_back(0); // host_name
	Append16(entry, static_cast<uint16_t>(host.size()));
	entry.insert(entry.end(), host.begin(), host.end());

	std::vector<uint8_t> out;
	Append16(out, 0); // server_name
	Append16(out, static_cast<uint16_t>(entry.size() + 2));
	Append16(out, static_cast<uint16_t>(entry.size()));
	out.insert(out.end(), entry.begin(), entry.end());
	return out;
}

std::vector<uint8_t> ClientHello(const std::vector<uint8_t> &extensions) {
	std::vector<uint8_t> body;
	Append16(body, 0x0303);
	body.insert(body.end(), 32, 0xAB); // random
	body.push_back(0);                 // legacy_session_id
	Append16(body, 2);                 // cipher_suites
	Append16(body, 0x1301);
	body.push_back(1); // legacy_compression_methods
	body.push_back(0);
	Append16(body, static_cast<uint16_t>(extensions.size()));
	body.insert(body.end(), extensions.begin(), extensions.end());
	return Handshake(body, 1);
}

TlsRecord Decode(const std::vector<uint8_t> &bytes) {
	return DecodeTlsRecord(bytes.data(), bytes.size());
}

void TestClientHelloWithSni() {
	const auto bytes = Record(ClientHello(ServerNameExtension("example.com")));
	const auto result = Decode(bytes);
	assert(result.valid);
	assert(result.record_type == TLS_RECORD_HANDSHAKE);
	assert(result.record_version == 0x0301);
	assert(result.has_handshake_type && result.handshake_type == 1);
	assert(result.client_hello);
	assert(result.has_server_name && result.server_name == "example.com");
	assert(!result.truncated);
}

void TestClientHelloWithoutSni() {
	// An extension list that does not contain server_name: the name is absent,
	// not merely out of reach, so truncated stays false.
	std::vector<uint8_t> other;
	Append16(other, 0x002B);
	Append16(other, 2);
	Append16(other, 0x0304);
	const auto result = Decode(Record(ClientHello(other)));
	assert(result.client_hello && !result.has_server_name && !result.truncated);

	const auto empty = Decode(Record(ClientHello(std::vector<uint8_t>())));
	assert(empty.client_hello && !empty.has_server_name && !empty.truncated);
}

void TestTruncatedClientHello() {
	// A handshake whose declared length runs past the record it sits in.
	auto hello = ClientHello(ServerNameExtension("split.example.com"));
	auto record = Record(hello);
	record.resize(record.size() - 8);
	record[3] = static_cast<uint8_t>((record.size() - 5) >> 8U);
	record[4] = static_cast<uint8_t>((record.size() - 5) & 0xFFU);
	const auto result = Decode(record);
	assert(result.valid && result.client_hello);
	assert(result.truncated && !result.has_server_name);
}

void TestNonHandshakeRecords() {
	const auto data = Decode(Record(std::vector<uint8_t>(32, 0x01), 23, 0x0303));
	assert(data.valid && data.record_type == 23);
	assert(!data.has_handshake_type && !data.client_hello && !data.truncated);

	const auto server = Decode(Record(Handshake(std::vector<uint8_t>(16, 0), 2)));
	assert(server.valid && server.has_handshake_type && server.handshake_type == 2);
	assert(!server.client_hello);
}

void TestRejectsNonTls() {
	assert(!Decode(std::vector<uint8_t>()).valid);
	assert(!DecodeTlsRecord(nullptr, 64).valid);
	// Too short to hold a record header.
	assert(!Decode(std::vector<uint8_t>(4, 0x16)).valid);
	// Unknown content type, and a major version that is not 0x03.
	assert(!Decode(Record(std::vector<uint8_t>(8, 0), 99)).valid);
	assert(!Decode(Record(std::vector<uint8_t>(8, 0), 22, 0x0201)).valid);
	// A declared length that runs past the payload is left to the stream reader.
	auto short_record = Record(std::vector<uint8_t>(8, 0));
	short_record.resize(short_record.size() - 2);
	assert(!Decode(short_record).valid);
	// A zero-length record carries nothing to parse.
	std::vector<uint8_t> empty_record;
	empty_record.push_back(22);
	Append16(empty_record, 0x0301);
	Append16(empty_record, 0);
	assert(!Decode(empty_record).valid);
	// Plain text that happens to arrive on a TLS port.
	const std::string http = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
	assert(!DecodeTlsRecord(reinterpret_cast<const uint8_t *>(http.data()), http.size()).valid);
}

// Every truncation of a valid ClientHello must terminate without reading past
// the buffer, and must never claim a server name it could not have read.
void TestTruncationsTerminate() {
	const auto full = Record(ClientHello(ServerNameExtension("example.com")));
	for (size_t size = 0; size <= full.size(); ++size) {
		std::vector<uint8_t> prefix(full.begin(), full.begin() + static_cast<long>(size));
		const auto result = DecodeTlsRecord(prefix.data(), prefix.size());
		if (result.has_server_name) {
			assert(result.server_name == "example.com");
			assert(size == full.size());
		}
	}
}

// Random bytes must not be mistaken for TLS often, and must never crash.
void TestFuzz() {
	std::mt19937 rng(20260920);
	std::uniform_int_distribution<int> byte(0, 255);
	std::uniform_int_distribution<size_t> length(0, 600);
	size_t accepted = 0;
	const size_t rounds = 20000;
	for (size_t round = 0; round < rounds; ++round) {
		std::vector<uint8_t> bytes(length(rng));
		for (auto &value : bytes) {
			value = static_cast<uint8_t>(byte(rng));
		}
		const auto result = DecodeTlsRecord(bytes.data(), bytes.size());
		if (result.valid) {
			++accepted;
			assert(result.record_length + TLS_RECORD_HEADER_LENGTH <= bytes.size());
			assert(result.record_length <= TLS_MAX_RECORD_LENGTH);
		} else {
			assert(!result.has_server_name && !result.client_hello);
		}
	}
	// Strict header validation should keep random traffic well under 1 in 1000.
	assert(accepted * 1000 < rounds);
	printf("fuzz: %zu of %zu random buffers accepted\n", accepted, rounds);
}

// A ClientHello whose inner lengths lie must not be trusted.
void TestHostileLengths() {
	auto extension = ServerNameExtension("example.com");
	// Claim a host name far longer than the bytes that follow.
	extension[7] = 0xFF;
	extension[8] = 0xFF;
	const auto result = Decode(Record(ClientHello(extension)));
	assert(!result.has_server_name);

	// A session id longer than the record.
	std::vector<uint8_t> body;
	Append16(body, 0x0303);
	body.insert(body.end(), 32, 0);
	body.push_back(0xFF);
	const auto lying = Decode(Record(Handshake(body, 1)));
	assert(lying.client_hello && !lying.has_server_name);
}

void TestEscapesServerName() {
	assert(EscapeTlsText("example.com") == "example.com");
	assert(EscapeTlsText("") == "");
	assert(EscapeTlsText(std::string("a\xff\xfe b\\c", 7)) == "a\\255\\254\\032b\\092c");
	assert(EscapeTlsText(std::string("\0", 1)) == "\\000");
	// Escaping is injective: a literal "\255" in the input cannot collide with byte 255.
	assert(EscapeTlsText("\\255") != EscapeTlsText("\xff"));
}

} // namespace

int main() {
	TestClientHelloWithSni();
	TestClientHelloWithoutSni();
	TestTruncatedClientHello();
	TestNonHandshakeRecords();
	TestRejectsNonTls();
	TestTruncationsTerminate();
	TestHostileLengths();
	TestFuzz();
	TestEscapesServerName();
	printf("TLS record parsing, truncation, hostile lengths, name escaping and non-TLS rejection passed\n");
	return 0;
}
