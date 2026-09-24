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

		// JA4 does not use groups or point formats; its prefix has a fixed width.
		Ja4Parts parts;
		if (Ja4Strings(handshake, parts)) {
			assert(ja3 || !handshake.client_supported_groups.Known() || !handshake.client_ec_point_formats.Known());
			assert(parts.prefix.size() == 10 && parts.prefix[0] == 't');
			++produced;
		} else {
			assert(!handshake.has_client_hello || !handshake.client_cipher_suites.present ||
			       !handshake.client_extensions.present);
		}
		if (Ja4sStrings(handshake, parts)) {
			assert(parts.prefix.size() == 7 && parts.first.size() == 4);
			++produced;
		}
	}
	printf("fuzz: %zu fingerprints from 20000 random handshakes, all well formed\n", produced);
}

std::string Raw(const Ja4Parts &parts) {
	return parts.prefix + "_" + parts.first + "_" + parts.second;
}

std::string Ja4Raw(const TlsHandshake &handshake) {
	Ja4Parts parts;
	return Ja4Strings(handshake, parts) ? Raw(parts) : "NULL";
}

std::string Ja4sRaw(const TlsHandshake &handshake) {
	Ja4Parts parts;
	return Ja4sStrings(handshake, parts) ? Raw(parts) : "NULL";
}

// The worked example in FoxIO-LLC/ja4 technical_details/JA4.md at 16b96d9.
TlsHandshake SpecClientHello() {
	auto hello = Client(0x0303,
	                    {0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c,
	                     0x009d, 0x002f, 0x0035},
	                    {0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012, 0x002b,
	                     0xff01, 0x000b, 0x000a, 0x0015});
	hello.client_signature_algorithms =
	    List<uint16_t>({0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601});
	hello.client_supported_versions = List<uint16_t>({0x0304, 0x0303});
	hello.client_alpn = List<std::string>({"h2", "http/1.1"});
	return hello;
}

void TestJa4SpecExample() {
	assert(Ja4Raw(SpecClientHello()) ==
	       "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_"
	       "0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_"
	       "0403,0804,0401,0503,0805,0501,0806,0601");

	// Without signature algorithms the string ends without an underscore.
	auto unsigned_hello = SpecClientHello();
	unsigned_hello.client_signature_algorithms = TlsList<uint16_t>();
	Ja4Parts parts;
	assert(Ja4Strings(unsigned_hello, parts));
	assert(parts.second == "0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01");
}

// The ALPN table in JA4.md, plus the single-character rule.
void TestJa4Alpn() {
	assert(Ja4Alpn("h2") == "h2");
	assert(Ja4Alpn("http/1.1") == "h1");
	assert(Ja4Alpn("x") == "xx");
	assert(Ja4Alpn("") == "00");
	assert(Ja4Alpn("\xAB") == "ab");
	assert(Ja4Alpn("\x20") == "20");
	assert(Ja4Alpn("\xAB\xCD") == "ad");
	assert(Ja4Alpn("\x20\x61") == "21");
	assert(Ja4Alpn("\x30\xAB") == "3b");
	assert(Ja4Alpn("\x61\x20") == "60");
	assert(Ja4Alpn("\x30\x31\xAB\xCD") == "3d");
	assert(Ja4Alpn("\x30\xAB\xCD\x31") == "01");
	// A GREASE identifier as the first value is taken as sent.
	assert(Ja4Alpn("\x0A\x0A") == "0a");
}

void TestJa4Rules() {
	// GREASE is ignored in every list and count; SNI and ALPN are counted but
	// not hashed; ciphers are sorted and signature algorithms are not.
	auto hello = Client(0x0303, {0x0A0A, 0xc02f, 0x1301}, {0x1A1A, 0x0000, 0x0010, 0x000d, 0x000a});
	hello.client_signature_algorithms = List<uint16_t>({0x2A2A, 0x0804, 0x0403});
	hello.client_alpn = List<std::string>({"h2"});
	assert(Ja4Raw(hello) == "t12d0204h2_1301,c02f_000a,000d_0804,0403");

	// The highest non-GREASE supported version wins over legacy_version.
	auto versions = Client(0x0301, {0x1301}, {0x002b});
	versions.client_supported_versions = List<uint16_t>({0x3A3A, 0x0302, 0x0304, 0x0303});
	assert(Ja4Raw(versions) == "t13i010100_1301_002b");
	versions.client_supported_versions = List<uint16_t>({0x3A3A});
	assert(Ja4Raw(versions) == "NULL");
	assert(Ja4Raw(Client(0x0305, {}, {})) == "t00i000000__");

	// Counts are capped at 99.
	std::vector<uint16_t> many;
	for (uint16_t cipher = 1; cipher <= 120; ++cipher) {
		many.push_back(cipher);
	}
	Ja4Parts parts;
	assert(Ja4Strings(Client(0x0303, many, {}), parts) && parts.prefix == "t12i990000");

	// Unknown inputs make it NULL; lists JA4 does not use do not.
	auto malformed = SpecClientHello();
	malformed.client_alpn = TlsList<std::string>();
	malformed.client_alpn.malformed = true;
	assert(Ja4Raw(malformed) == "NULL");
	auto over = SpecClientHello();
	over.client_signature_algorithms = TlsList<uint16_t>();
	over.client_signature_algorithms.over_limit = true;
	assert(Ja4Raw(over) == "NULL");
	auto groups = SpecClientHello();
	groups.client_supported_groups.malformed = true;
	groups.client_ec_point_formats.over_limit = true;
	assert(Ja4Raw(groups) == Ja4Raw(SpecClientHello()));
	auto missing = SpecClientHello();
	missing.has_client_hello = false;
	assert(Ja4Raw(missing) == "NULL");
}

void TestJa4sRules() {
	// Negotiated version, extension count and list including GREASE, in wire
	// order, and the selected cipher in hex.
	auto tls13 = Server(0x0303, 0x1301, {0x002b, 0x0033});
	tls13.has_negotiated_version = true;
	tls13.negotiated_version = 0x0304;
	assert(Ja4sRaw(tls13) == "t130200_1301_002b,0033");

	auto legacy = Server(0x0301, 0xc013, {0x3A3A, 0xff01, 0x000b});
	legacy.has_negotiated_version = true;
	legacy.negotiated_version = 0x0301;
	assert(Ja4sRaw(legacy) == "t100300_c013_3a3a,ff01,000b");

	auto alpn = legacy;
	alpn.server_alpn = List<std::string>({"http/1.1"});
	assert(Ja4sRaw(alpn) == "t1003h1_c013_3a3a,ff01,000b");
	alpn.server_alpn = TlsList<std::string>();
	alpn.server_alpn.malformed = true;
	assert(Ja4sRaw(alpn) == "NULL");

	auto bare = Server(0x0303, 0x002f, {});
	bare.has_negotiated_version = true;
	bare.negotiated_version = 0x0303;
	assert(Ja4sRaw(bare) == "t120000_002f_");
	assert(Ja4sRaw(SpecClientHello()) == "NULL");
}

} // namespace

// JA4X takes each list of comma-joined hex OIDs as is; hashing is the
// extension's job.
// Values from the FoxIO rust reference at 16b96d9 for the fixture chain.
void TestJa4xStrings() {
	X509Certificate leaf;
	leaf.issuer_oids = "550406,55040a,55040b,550403";
	leaf.subject_oids = "550406,550407,55040a";
	leaf.extension_oids = "551d11";
	Ja4xParts parts;
	Ja4xStrings(leaf, parts);
	assert(parts.issuer == "550406,55040a,55040b,550403" && parts.subject == "550406,550407,55040a");
	assert(parts.extensions == "551d11");
	// A version 1 certificate has no extensions; the empty part is empty, not absent.
	X509Certificate v1;
	v1.issuer_oids = "550403";
	Ja4xStrings(v1, parts);
	assert(parts.issuer == "550403" && parts.subject.empty() && parts.extensions.empty());
}

int main() {
	TestSpecExamples();
	TestJa4xStrings();
	TestGreaseAndOrder();
	TestUnknownInputs();
	TestServerVersion();
	TestJa4SpecExample();
	TestJa4Alpn();
	TestJa4Rules();
	TestJa4sRules();
	TestFuzz();
	printf("TLS JA3/JA3S and JA4/JA4S strings, GREASE, unknown inputs and fuzzing passed\n");
	return 0;
}
