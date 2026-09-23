#include "tls_fingerprint.hpp"

#include <cassert>
#include <cstdio>
#include <random>
#include <string>
#include <vector>

using namespace packetquapture;

namespace {

template <class T>
TlsList<T> List(const std::vector<T> &values) {
	TlsList<T> list;
	list.present = true;
	list.values = values;
	return list;
}

TlsHandshake Client(uint16_t version, const std::vector<uint16_t> &ciphers, const std::vector<uint16_t> &extensions) {
	TlsHandshake handshake;
	handshake.has_client_hello = true;
	handshake.has_client_version = true;
	handshake.client_version = version;
	handshake.client_cipher_suites = List(ciphers);
	handshake.client_extensions = List(extensions);
	return handshake;
}

TlsHandshake Server(uint16_t version, uint16_t cipher, const std::vector<uint16_t> &extensions) {
	TlsHandshake handshake;
	handshake.has_server_hello = true;
	handshake.has_server_legacy_version = true;
	handshake.server_legacy_version = version;
	handshake.has_cipher_suite = true;
	handshake.cipher_suite = cipher;
	handshake.server_extensions = List(extensions);
	return handshake;
}

std::string Ja3(const TlsHandshake &handshake) {
	std::string out;
	return Ja3String(handshake, out) ? out : "NULL";
}

std::string Ja3s(const TlsHandshake &handshake) {
	std::string out;
	return Ja3sString(handshake, out) ? out : "NULL";
}

// The two worked examples in the salesforce/ja3 README (502cc63).
void TestSpecExamples() {
	auto full = Client(769, {47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4}, {0, 10, 11});
	full.client_supported_groups = List<uint16_t>({23, 24, 25});
	full.client_ec_point_formats = List<uint8_t>({0});
	assert(Ja3(full) == "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0");

	// No extensions at all: every later field is empty.
	const auto bare = Client(769, {4, 5, 10, 9, 100, 98, 3, 6, 19, 18, 99}, {});
	assert(Ja3(bare) == "769,4-5-10-9-100-98-3-6-19-18-99,,,");
}

// GREASE is dropped from every field that can carry it, and wire order is kept.
void TestGreaseAndOrder() {
	auto hello = Client(771, {0x0A0A, 0x1302, 0x1301}, {0x1A1A, 43, 0, 0xFAFA});
	hello.client_supported_groups = List<uint16_t>({0x2A2A, 29, 23});
	hello.client_ec_point_formats = List<uint8_t>({2, 0});
	assert(Ja3(hello) == "771,4866-4865,43-0,29-23,2-0");
	assert(Ja3s(Server(771, 0x1301, {0x3A3A, 43, 51})) == "771,4865,43-51");
}

// A list the hello did not carry is an empty field; one whose value is unknown
// makes the whole fingerprint NULL.
void TestUnknownInputs() {
	const auto base = Client(771, {4865}, {0});
	assert(Ja3(base) == "771,4865,0,,");

	auto empty_groups = base;
	empty_groups.client_supported_groups = List<uint16_t>({});
	assert(Ja3(empty_groups) == "771,4865,0,,");

	auto malformed = base;
	malformed.client_supported_groups.malformed = true;
	assert(Ja3(malformed) == "NULL");

	auto over = base;
	over.client_ec_point_formats.over_limit = true;
	assert(Ja3(over) == "NULL");

	auto no_ciphers = base;
	no_ciphers.client_cipher_suites = TlsList<uint16_t>();
	no_ciphers.client_cipher_suites.over_limit = true;
	assert(Ja3(no_ciphers) == "NULL");

	auto no_extensions = base;
	no_extensions.client_extensions = TlsList<uint16_t>();
	assert(Ja3(no_extensions) == "NULL");

	// Lists JA3 does not hash do not affect it.
	auto other = base;
	other.client_alpn.malformed = true;
	other.client_signature_algorithms.over_limit = true;
	assert(Ja3(other) == "771,4865,0,,");

	auto missing = base;
	missing.has_client_hello = false;
	assert(Ja3(missing) == "NULL");
	assert(Ja3s(base) == "NULL");
}

// JA3S uses legacy_version, not the version supported_versions selected.
void TestServerVersion() {
	auto tls13 = Server(0x0303, 0x1301, {43, 51});
	tls13.has_negotiated_version = true;
	tls13.negotiated_version = 0x0304;
	assert(Ja3s(tls13) == "771,4865,43-51");

	auto no_extensions = Server(0x0301, 0x0035, {});
	assert(Ja3s(no_extensions) == "769,53,");

	auto invalid = no_extensions;
	invalid.server_extensions = TlsList<uint16_t>();
	assert(Ja3s(invalid) == "NULL");
	assert(Ja3(invalid) == "NULL");
}

bool WellFormed(const std::string &text, size_t commas) {
	size_t seen = 0;
	char previous = ',';
	for (const auto c : text) {
		if (c == ',') {
			++seen;
		} else if (c == '-') {
			if (previous == ',' || previous == '-') {
				return false;
			}
		} else if (c < '0' || c > '9') {
			return false;
		}
		previous = c;
	}
	return seen == commas && previous != '-';
}

// Random lists and flags: the strings stay well formed, and a fingerprint is
// produced exactly when all of its inputs are known.
void TestFuzz() {
	std::mt19937 rng(20260923);
	size_t produced = 0;
	for (size_t round = 0; round < 20000; ++round) {
		TlsHandshake handshake;
		handshake.has_client_hello = rng() % 8 != 0;
		handshake.has_client_version = true;
		handshake.client_version = static_cast<uint16_t>(rng());
		handshake.has_server_hello = rng() % 8 != 0;
		handshake.has_server_legacy_version = true;
		handshake.server_legacy_version = static_cast<uint16_t>(rng());
		handshake.has_cipher_suite = true;
		handshake.cipher_suite = static_cast<uint16_t>(rng());
		TlsList<uint16_t> *lists[] = {&handshake.client_cipher_suites, &handshake.client_extensions,
		                              &handshake.client_supported_groups, &handshake.server_extensions};
		for (auto *list : lists) {
			const auto kind = rng() % 10;
			list->present = kind < 7;
			list->malformed = kind == 8;
			list->over_limit = kind == 9;
			if (list->present) {
				for (size_t i = rng() % 6; i > 0; --i) {
					// Mostly GREASE, so fully filtered lists are common.
					list->values.push_back(rng() % 2 ? static_cast<uint16_t>(0x0A0A + 0x1010 * (rng() % 16))
					                                 : static_cast<uint16_t>(rng()));
				}
			}
		}
		const auto kind = rng() % 10;
		handshake.client_ec_point_formats.present = kind < 7;
		handshake.client_ec_point_formats.malformed = kind == 8;
		for (size_t i = handshake.client_ec_point_formats.present ? rng() % 4 : 0; i > 0; --i) {
			handshake.client_ec_point_formats.values.push_back(static_cast<uint8_t>(rng()));
		}

		std::string text;
		const bool ja3 = Ja3String(handshake, text);
		const bool ja3_expected = handshake.has_client_hello && handshake.client_cipher_suites.present &&
		                          handshake.client_extensions.present && handshake.client_supported_groups.Known() &&
		                          handshake.client_ec_point_formats.Known();
		assert(ja3 == ja3_expected);
		assert(ja3 ? WellFormed(text, 4) : text.empty());
		const bool ja3s = Ja3sString(handshake, text);
		assert(ja3s == (handshake.has_server_hello && handshake.server_extensions.present));
		assert(ja3s ? WellFormed(text, 2) : text.empty());
		produced += (ja3 ? 1 : 0) + (ja3s ? 1 : 0);
	}
	printf("fuzz: %zu fingerprints from 20000 random handshakes, all well formed\n", produced);
}

} // namespace

int main() {
	TestSpecExamples();
	TestGreaseAndOrder();
	TestUnknownInputs();
	TestServerVersion();
	TestFuzz();
	printf("TLS JA3/JA3S strings, GREASE, unknown inputs and fuzzing passed\n");
	return 0;
}
