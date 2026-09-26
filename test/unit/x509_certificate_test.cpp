#include "x509_certificate.hpp"

#include <cassert>
#include <cstdio>
#include <random>
#include <string>
#include <vector>

using namespace packetquapture;

namespace {

typedef std::vector<uint8_t> Bytes;

Bytes Tlv(uint8_t tag, const Bytes &content) {
	Bytes out = {tag};
	const size_t n = content.size();
	if (n < 0x80) {
		out.push_back(static_cast<uint8_t>(n));
	} else if (n < 0x100) {
		out.insert(out.end(), {0x81, static_cast<uint8_t>(n)});
	} else {
		out.insert(out.end(), {0x82, static_cast<uint8_t>(n >> 8U), static_cast<uint8_t>(n & 0xFFU)});
	}
	out.insert(out.end(), content.begin(), content.end());
	return out;
}

Bytes Cat(const std::vector<Bytes> &parts) {
	Bytes out;
	for (const auto &part : parts) {
		out.insert(out.end(), part.begin(), part.end());
	}
	return out;
}

Bytes Text(uint8_t tag, const std::string &text) {
	return Tlv(tag, Bytes(text.begin(), text.end()));
}

Bytes Oid(const std::vector<uint64_t> &arcs) {
	Bytes content;
	std::vector<uint64_t> values = {arcs[0] * 40 + arcs[1]};
	values.insert(values.end(), arcs.begin() + 2, arcs.end());
	for (const auto value : values) {
		Bytes encoded = {static_cast<uint8_t>(value & 0x7FU)};
		for (uint64_t rest = value >> 7U; rest; rest >>= 7U) {
			encoded.insert(encoded.begin(), static_cast<uint8_t>(0x80U | (rest & 0x7FU)));
		}
		content.insert(content.end(), encoded.begin(), encoded.end());
	}
	return Tlv(0x06, content);
}

Bytes Attribute(const std::vector<uint64_t> &oid, const Bytes &value) {
	return Tlv(0x30, Cat({Oid(oid), value}));
}
const std::vector<uint64_t> CN = {2, 5, 4, 3}, O = {2, 5, 4, 10}, C = {2, 5, 4, 6}, OU = {2, 5, 4, 11};

// One RDN per attribute, in wire order (least specific first).
Bytes Name(const std::vector<Bytes> &attributes) {
	Bytes rdns;
	for (const auto &attribute : attributes) {
		const auto rdn = Tlv(0x31, attribute);
		rdns.insert(rdns.end(), rdn.begin(), rdn.end());
	}
	return Tlv(0x30, rdns);
}

struct Spec {
	Bytes serial = {0x00, 0xAB, 0x01};
	Bytes issuer = Name({Attribute(C, Text(0x13, "US")), Attribute(O, Text(0x13, "Test CA"))});
	Bytes subject = Name({Attribute(C, Text(0x13, "US")), Attribute(O, Text(0x0C, "Example Inc.")),
	                      Attribute(CN, Text(0x0C, "www.example.com"))});
	Bytes not_before = Text(0x17, "250102030405Z");
	Bytes not_after = Text(0x18, "20500101000000Z");
	bool version = true;
	std::vector<Bytes> extensions;
	Bytes trailing;
	Bytes key = Tlv(0x30, Cat({Tlv(0x30, Oid({1, 2, 840, 10045, 2, 1})), Tlv(0x03, {0x00, 0x04, 0x01})}));
	Bytes algorithm = Tlv(0x30, Cat({Oid({1, 2, 840, 10045, 4, 3, 2})}));
};

Bytes San(const std::vector<Bytes> &names) {
	return Tlv(0x30, Cat({Oid({2, 5, 29, 17}), Tlv(0x04, Tlv(0x30, Cat(names)))}));
}

Bytes Certificate(const Spec &spec) {
	const Bytes &algorithm = spec.algorithm;
	const Bytes &key = spec.key;
	Bytes tbs = spec.version ? Tlv(0xA0, Tlv(0x02, {0x02})) : Bytes();
	tbs = Cat({tbs, Tlv(0x02, spec.serial), algorithm, spec.issuer, Tlv(0x30, Cat({spec.not_before, spec.not_after})),
	           spec.subject, key});
	if (!spec.extensions.empty()) {
		tbs = Cat({tbs, Tlv(0xA3, Tlv(0x30, Cat(spec.extensions)))});
	}
	return Cat({Tlv(0x30, Cat({Tlv(0x30, tbs), algorithm, Tlv(0x03, {0x00, 0x30, 0x00}), spec.trailing}))});
}

X509Result Parse(const Bytes &der, X509Certificate &out, size_t max_san = 1024) {
	return ParseX509Certificate(der.data(), der.size(), max_san, out);
}

X509Certificate Ok(const Spec &spec) {
	X509Certificate out;
	const auto result = Parse(Certificate(spec), out);
	assert(result == X509Result::OK);
	(void)result;
	return out;
}

std::string SubjectOf(const Bytes &value) {
	Spec spec;
	spec.subject = Name({Attribute(CN, value)});
	return Ok(spec).subject;
}

bool Malformed(const Spec &spec) {
	X509Certificate out;
	return Parse(Certificate(spec), out) == X509Result::MALFORMED && out.subject.empty();
}

void TestFields() {
	Spec spec;
	spec.extensions = {
	    San({Text(0x82, "www.example.com"), Tlv(0x87, {192, 0, 2, 7}), Tlv(0x81, {'a', '@', 'b'}),
	         Text(0x82, "example.com"), Tlv(0x87, {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})})};
	const auto cert = Ok(spec);
	assert(cert.subject == "CN=www.example.com,O=Example Inc.,C=US");
	assert(cert.issuer == "O=Test CA,C=US");
	assert(cert.serial == "00ab01");
	assert(cert.not_before == 1735787045LL * 1000000); // 2025-01-02 03:04:05 UTC
	assert(cert.not_after == 2524608000LL * 1000000);  // 2050-01-01 00:00:00 UTC
	assert((cert.san_dns == std::vector<std::string> {"www.example.com", "example.com"}));
	assert((cert.san_ip == std::vector<std::string> {"192.0.2.7", "2001:db8::1"}));

	// Version 1: no version field and no extensions.
	Spec v1;
	v1.version = false;
	const auto old = Ok(v1);
	assert(old.subject == "CN=www.example.com,O=Example Inc.,C=US" && old.san_dns.empty());
}

void TestNames() {
	// A multi-valued RDN joins its attributes with +, reversed as OpenSSL does.
	Spec multi;
	multi.subject =
	    Tlv(0x30, Cat({Tlv(0x31, Attribute(C, Text(0x13, "US"))),
	                   Tlv(0x31, Cat({Attribute(OU, Text(0x0C, "Ops")), Attribute(CN, Text(0x0C, "x"))}))}));
	assert(Ok(multi).subject == "CN=x+OU=Ops,C=US");

	// RFC 4514 specials, and leading and trailing positions.
	assert(SubjectOf(Text(0x0C, "a,b+c\"d\\e<f>g;h")) == "CN=a\\,b\\+c\\\"d\\\\e\\<f\\>g\\;h");
	assert(SubjectOf(Text(0x0C, "#lead")) == "CN=\\#lead");
	assert(SubjectOf(Text(0x0C, " both ")) == "CN=\\ both\\ ");
	assert(SubjectOf(Text(0x0C, "mid#dle x")) == "CN=mid#dle x");
	// Control characters and bytes that are not UTF-8 become hex pairs.
	assert(SubjectOf(Tlv(0x0C, {'a', 0x00, 0x0A, 0xFF, 'b'})) == "CN=a\\00\\0A\\FFb");
	assert(SubjectOf(Tlv(0x0C, {0xC3, 0xA9})) == "CN=\xC3\xA9"); // valid UTF-8 passes through
	// Other string types decode to UTF-8.
	assert(SubjectOf(Tlv(0x1E, {0x00, 'h', 0x00, 0xE9})) == "CN=h\xC3\xA9");
	assert(SubjectOf(Tlv(0x14, {'h', 0xE9})) == "CN=h\xC3\xA9"); // Teletex as Latin-1
	assert(SubjectOf(Tlv(0x1C, {0, 0, 0, 'u', 0, 1, 0xF6, 0x00})) == "CN=u\xF0\x9F\x98\x80");
	assert(SubjectOf(Text(0x16, "ia5")) == "CN=ia5" && SubjectOf(Text(0x13, "p")) == "CN=p");
	// A value that is not a string is written as #hex of its encoding.
	assert(SubjectOf(Tlv(0x02, {0x05})) == "CN=#020105");
	// Registered types beyond RFC 4514's table use OpenSSL's spelling; any other
	// type is its dotted OID with a #hex value.
	Spec email;
	email.subject = Name({Attribute({1, 2, 840, 113549, 1, 9, 1}, Text(0x16, "a@b")), Attribute(CN, Text(0x0C, "x"))});
	assert(Ok(email).subject == "CN=x,emailAddress=a@b");
	Spec other;
	other.subject = Name({Attribute({1, 3, 6, 1, 4, 1, 99999, 1}, Text(0x0C, "v")), Attribute(CN, Text(0x0C, "x"))});
	assert(Ok(other).subject == "CN=x,1.3.6.1.4.1.99999.1=#0C0176");
	Spec dc;
	dc.subject = Name({Attribute({0, 9, 2342, 19200300, 100, 1, 25}, Text(0x16, "com")),
	                   Attribute({0, 9, 2342, 19200300, 100, 1, 25}, Text(0x16, "example"))});
	assert(Ok(dc).subject == "DC=example,DC=com");
	// An empty name, as some leaf certificates have.
	Spec empty;
	empty.subject = Tlv(0x30, {});
	assert(Ok(empty).subject.empty());
	// A string that does not decode, such as odd-length BMP, falls back to #hex.
	assert(SubjectOf(Tlv(0x1E, {0x00})) == "CN=#1E0100");
	// An empty RDN set is malformed.
	Spec bad;
	bad.subject = Tlv(0x30, Tlv(0x31, {}));
	assert(Malformed(bad));
}

void TestTimes() {
	Spec spec;
	spec.not_before = Text(0x17, "491231235959Z");
	spec.not_after = Text(0x17, "500101000000Z");
	const auto cert = Ok(spec);
	assert(cert.not_before == 2524607999LL * 1000000); // 2049-12-31 23:59:59
	assert(cert.not_after == -631152000LL * 1000000);  // 1950-01-01 00:00:00
	spec.not_before = Text(0x18, "20240229120000Z");   // leap day
	assert(Ok(spec).not_before == 1709208000LL * 1000000);
	for (const auto &bad : {"20230229120000Z", "20241301000000Z", "20240101240000Z", "2024010100000Z",
	                        "20240101000000+0100", "20240101000000.5Z", "2024010100000aZ"}) {
		Spec invalid;
		invalid.not_before = Text(0x18, bad);
		assert(Malformed(invalid));
	}
	Spec utc_as_generalized;
	utc_as_generalized.not_before = Text(0x18, "250102030405Z");
	assert(Malformed(utc_as_generalized));
}

void TestIpv6() {
	struct Case {
		Bytes address;
		std::string text;
	};
	const std::vector<Case> cases = {
	    {Bytes(16, 0), "::"},
	    {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, "::1"},
	    {{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1}, "2001:db8:0:1:1:1:1:1"},
	    {{0, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3}, "1:0:0:2::3"},
	    {{0, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 3, 0, 0}, "1::2:0:0:3:0"},
	    {{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, "fe80::"},
	};
	for (const auto &item : cases) {
		Spec spec;
		spec.extensions = {San({Tlv(0x87, item.address)})};
		const auto cert = Ok(spec);
		assert(cert.san_ip.size() == 1 && cert.san_ip[0] == item.text);
	}
}

void TestExtensions() {
	// A DNS name is escaped as tls_sni is.
	Spec hostile;
	hostile.extensions = {San({Tlv(0x82, {'a', ' ', 0xFF})})};
	assert(Ok(hostile).san_dns[0] == "a\\032\\255");
	// A critical flag is allowed; other extensions are skipped.
	Spec critical;
	critical.extensions = {Tlv(0x30, Cat({Oid({2, 5, 29, 19}), Tlv(0x01, {0xFF}), Tlv(0x04, Tlv(0x30, {}))})),
	                       San({Text(0x82, "a.example")})};
	assert(Ok(critical).san_dns[0] == "a.example");
	// RFC 5280 forbids a repeated extension.
	Spec twice;
	twice.extensions = {San({Text(0x82, "a")}), San({Text(0x82, "b")})};
	assert(Malformed(twice));
	// An iPAddress must be 4 or 16 octets.
	Spec odd_ip;
	odd_ip.extensions = {San({Tlv(0x87, {1, 2, 3})})};
	assert(Malformed(odd_ip));
	// More names than the limit is over the limit, not malformed.
	Spec many;
	many.extensions = {San({Text(0x82, "a"), Text(0x82, "b"), Tlv(0x87, {1, 2, 3, 4})})};
	X509Certificate out;
	assert(Parse(Certificate(many), out, 2) == X509Result::OVER_LIMIT && out.san_dns.empty());
	assert(Parse(Certificate(many), out, 3) == X509Result::OK && out.san_ip.size() == 1);
}

void TestFraming() {
	Spec trailing;
	trailing.trailing = Tlv(0x05, {});
	assert(Malformed(trailing));
	Spec empty_serial;
	empty_serial.serial = {};
	assert(Malformed(empty_serial));
	const auto good = Certificate(Spec());
	X509Certificate out;
	// Every truncation fails cleanly, and so does extra data after the certificate.
	for (size_t size = 0; size < good.size(); ++size) {
		assert(ParseX509Certificate(good.data(), size, 1024, out) == X509Result::MALFORMED);
	}
	Bytes extra = good;
	extra.push_back(0);
	assert(Parse(extra, out) == X509Result::MALFORMED);
	// Indefinite and oversized lengths.
	assert(Parse({0x30, 0x80, 0x00, 0x00}, out) == X509Result::MALFORMED);
	assert(Parse({0x30, 0x85, 1, 0, 0, 0, 0}, out) == X509Result::MALFORMED);
	assert(Parse({0x1F, 0x01, 0x00}, out) == X509Result::MALFORMED);
}

// What a parsed certificate holds is what the memory budget counts. Thousands
// of one-byte extensions cost a few bytes each, not a string apiece, and
// every list entry is charged its own overhead.
void TestTextBytes() {
	Spec spec;
	const Bytes tiny = Tlv(0x30, Cat({Tlv(0x06, {0x2A}), Tlv(0x04, {})}));
	for (int i = 0; i < 3000; ++i) {
		spec.extensions.push_back(tiny);
	}
	spec.extensions.push_back(San({Text(0x82, "a"), Text(0x82, "b")}));
	const auto cert = Ok(spec);
	assert(cert.extension_oids.size() == 3000 * 3 + 6 && cert.extension_oids.compare(0, 6, "2a,2a,") == 0);
	assert(cert.extension_oids.compare(cert.extension_oids.size() - 9, 9, "2a,551d11") == 0);
	assert(cert.issuer_oids == "550406,55040a" && cert.subject_oids == "550406,55040a,550403");
	assert(cert.TextBytes() >= cert.extension_oids.size() + 2 * sizeof(std::string));
	// Usage names are list entries too.
	Spec purposes;
	std::vector<Bytes> oids;
	for (uint64_t i = 0; i < 100; ++i) {
		oids.push_back(Oid({1, 2, i}));
	}
	purposes.extensions = {Tlv(0x30, Cat({Oid({2, 5, 29, 37}), Tlv(0x04, Tlv(0x30, Cat(oids)))}))};
	const auto many = Ok(purposes);
	assert(many.TextBytes() >= 100 * sizeof(std::string));
}

Bytes Extension(const std::vector<uint64_t> &oid, const Bytes &value) {
	return Tlv(0x30, Cat({Oid(oid), Tlv(0x04, value)}));
}

void TestAlgorithmsAndKeys() {
	Spec spec;
	auto cert = Ok(spec);
	assert(cert.signature_algorithm == "ecdsa-with-SHA256" && cert.public_key_algorithm == "id-ecPublicKey");
	// An EC key with no curve has no size.
	assert(cert.public_key_curve.empty() && cert.public_key_bits == 0);

	spec.key = Tlv(0x30, Cat({Tlv(0x30, Cat({Oid({1, 2, 840, 10045, 2, 1}), Oid({1, 3, 132, 0, 34})})),
	                          Tlv(0x03, {0x00, 0x04, 0x01})}));
	cert = Ok(spec);
	assert(cert.public_key_curve == "secp384r1" && cert.public_key_bits == 384);
	// A curve without a name here is its OID, with no size.
	spec.key = Tlv(
	    0x30, Cat({Tlv(0x30, Cat({Oid({1, 2, 840, 10045, 2, 1}), Oid({1, 2, 3, 4})})), Tlv(0x03, {0x00, 0x04, 0x01})}));
	cert = Ok(spec);
	assert(cert.public_key_curve == "1.2.3.4" && cert.public_key_bits == 0);

	// RSA: the modulus's significant bits, not counting its sign octet.
	Bytes modulus = {0x00, 0x01};
	modulus.insert(modulus.end(), 255, 0xFF);
	spec.key = Tlv(0x30, Cat({Tlv(0x30, Cat({Oid({1, 2, 840, 113549, 1, 1, 1}), Tlv(0x05, {})})),
	                          Tlv(0x03, Cat({{0x00}, Tlv(0x30, Cat({Tlv(0x02, modulus), Tlv(0x02, {1, 0, 1})}))}))}));
	spec.algorithm = Tlv(0x30, Cat({Oid({1, 2, 840, 113549, 1, 1, 11}), Tlv(0x05, {})}));
	cert = Ok(spec);
	assert(cert.public_key_algorithm == "rsaEncryption" && cert.public_key_bits == 2041);
	assert(cert.signature_algorithm == "sha256WithRSAEncryption" && cert.public_key_curve.empty());
	// A key body that does not parse leaves the size unknown, not the certificate broken.
	spec.key = Tlv(0x30, Cat({Tlv(0x30, Oid({1, 2, 840, 113549, 1, 1, 1})), Tlv(0x03, {0x00, 0x05})}));
	cert = Ok(spec);
	assert(cert.public_key_algorithm == "rsaEncryption" && cert.public_key_bits == 0);

	// Unknown algorithms are dotted OIDs.
	spec.algorithm = Tlv(0x30, Oid({1, 2, 3, 5}));
	spec.key = Tlv(0x30, Cat({Tlv(0x30, Oid({1, 3, 101, 112})), Tlv(0x03, Bytes(33, 0))}));
	cert = Ok(spec);
	assert(cert.signature_algorithm == "1.2.3.5" && cert.public_key_algorithm == "ED25519");
	assert(cert.public_key_bits == 0);

	// Describing the key and algorithm only adds fields, so a key info or an
	// algorithm that does not parse leaves them unknown, and the rest stands.
	Spec broken;
	broken.key = Tlv(0x30, Tlv(0x03, {0x00}));
	cert = Ok(broken);
	assert(cert.public_key_algorithm.empty() && cert.subject == "CN=www.example.com,O=Example Inc.,C=US");
	broken = Spec();
	broken.algorithm = Tlv(0x30, Tlv(0x05, {}));
	cert = Ok(broken);
	assert(cert.signature_algorithm.empty() && cert.public_key_algorithm == "id-ecPublicKey");

	// RSASSA-PSS keys have the RSA body, so they are sized the same way.
	spec.key = Tlv(0x30, Cat({Tlv(0x30, Oid({1, 2, 840, 113549, 1, 1, 10})),
	                          Tlv(0x03, Cat({{0x00}, Tlv(0x30, Cat({Tlv(0x02, modulus), Tlv(0x02, {1, 0, 1})}))}))}));
	cert = Ok(spec);
	assert(cert.public_key_algorithm == "rsassaPss" && cert.public_key_bits == 2041);
}

void TestConstraintsAndUsage() {
	const std::vector<uint64_t> basic = {2, 5, 29, 19}, usage = {2, 5, 29, 15}, purposes = {2, 5, 29, 37};
	Spec spec;
	auto cert = Ok(spec);
	assert(!cert.has_basic_constraints && !cert.has_key_usage && !cert.has_extended_key_usage);

	// An empty SEQUENCE is cA FALSE with no path length.
	spec.extensions = {Extension(basic, Tlv(0x30, {}))};
	cert = Ok(spec);
	assert(cert.has_basic_constraints && !cert.is_ca && !cert.has_path_length);
	spec.extensions = {Extension(basic, Tlv(0x30, Cat({Tlv(0x01, {0xFF}), Tlv(0x02, {0x00, 0x80})})))};
	cert = Ok(spec);
	assert(cert.is_ca && cert.has_path_length && cert.path_length == 128);
	// A negative or oversized path length leaves basicConstraints unknown; these
	// extensions only add fields, so the certificate itself still parses.
	spec.extensions = {Extension(basic, Tlv(0x30, Cat({Tlv(0x01, {0xFF}), Tlv(0x02, {0x80})})))};
	cert = Ok(spec);
	assert(!cert.has_basic_constraints && !cert.is_ca && !cert.has_path_length);
	spec.extensions = {Extension(basic, Tlv(0x30, Tlv(0x02, {1, 0, 0, 0, 0})))};
	assert(!Ok(spec).has_basic_constraints);

	// keyUsage bits in bit order, over two octets for decipherOnly.
	spec.extensions = {Extension(usage, Tlv(0x03, {0x07, 0x86, 0x80}))};
	cert = Ok(spec);
	assert((cert.key_usage == std::vector<std::string> {"digitalSignature", "keyCertSign", "cRLSign", "decipherOnly"}));
	// No bits set is a present, empty list; unused bits beyond 7 are malformed.
	spec.extensions = {Extension(usage, Tlv(0x03, {0x00}))};
	cert = Ok(spec);
	assert(cert.has_key_usage && cert.key_usage.empty());
	spec.extensions = {Extension(usage, Tlv(0x03, {0x08, 0xFF}))};
	cert = Ok(spec);
	assert(!cert.has_key_usage && cert.key_usage.empty());

	// Named purposes, then an unnamed one by OID.
	spec.extensions = {Extension(
	    purposes, Tlv(0x30, Cat({Oid({1, 3, 6, 1, 5, 5, 7, 3, 1}), Oid({2, 5, 29, 37, 0}), Oid({1, 2, 3})})))};
	cert = Ok(spec);
	assert((cert.extended_key_usage == std::vector<std::string> {"serverAuth", "anyExtendedKeyUsage", "1.2.3"}));
	// RFC 5280 requires at least one purpose, and each must be an OID.
	spec.extensions = {Extension(purposes, Tlv(0x30, {}))};
	assert(!Ok(spec).has_extended_key_usage);
	spec.extensions = {Extension(purposes, Tlv(0x30, Cat({Oid({1, 2, 3}), Tlv(0x05, {})})))};
	cert = Ok(spec);
	assert(!cert.has_extended_key_usage && cert.extended_key_usage.empty());
	// More purposes than the limit is over the limit, as SAN entries are.
	spec.extensions = {Extension(purposes, Tlv(0x30, Cat({Oid({1, 2, 3}), Oid({1, 2, 4}), Oid({1, 2, 5})})))};
	X509Certificate out;
	assert(Parse(Certificate(spec), out, 2) == X509Result::OVER_LIMIT);
	assert(Parse(Certificate(spec), out, 3) == X509Result::OK && out.extended_key_usage.size() == 3);

	// Each of these twice is unknown: RFC 5280 forbids it, and neither copy is
	// more believable. A third copy does not bring it back.
	for (const auto &oid : {basic, usage, purposes}) {
		const Bytes value = oid == basic ? Tlv(0x30, {}) : oid == usage ? Tlv(0x03, {0x00}) : Tlv(0x30, Oid({1, 2}));
		spec.extensions = {Extension(oid, value), Extension(oid, value), Extension(oid, value)};
		cert = Ok(spec);
		assert(!cert.has_basic_constraints && !cert.has_key_usage && !cert.has_extended_key_usage);
		assert(cert.key_usage.empty() && cert.extended_key_usage.empty());
	}
}

// Random corruption never crashes, and never yields a partly filled result.
void TestFuzz() {
	std::mt19937 random(424242);
	Spec spec;
	spec.extensions = {San({Text(0x82, "www.example.com"), Tlv(0x87, {192, 0, 2, 7})})};
	const auto good = Certificate(spec);
	size_t parsed = 0;
	for (int run = 0; run < 20000; ++run) {
		Bytes mutated = good;
		const int flips = 1 + static_cast<int>(random() % 4);
		for (int i = 0; i < flips; ++i) {
			mutated[random() % mutated.size()] = static_cast<uint8_t>(random());
		}
		X509Certificate out;
		const auto result = Parse(mutated, out, 8);
		if (result == X509Result::OK) {
			++parsed;
		} else {
			assert(out.subject.empty() && out.serial.empty() && out.san_dns.empty() && out.san_ip.empty());
		}
	}
	for (int run = 0; run < 20000; ++run) {
		Bytes noise(random() % 256);
		for (auto &byte : noise) {
			byte = static_cast<uint8_t>(random());
		}
		if (!noise.empty() && run % 2) {
			noise[0] = 0x30;
		}
		X509Certificate out;
		Parse(noise, out, 8);
	}
	std::printf("fuzz: %zu of 20000 mutated certificates still parsed\n", parsed);
}

} // namespace

int main() {
	TestAlgorithmsAndKeys();
	TestConstraintsAndUsage();
	TestFields();
	TestNames();
	TestTimes();
	TestIpv6();
	TestExtensions();
	TestFraming();
	TestTextBytes();
	TestFuzz();
	std::printf("X.509 fields, RFC 4514 names, times, SANs, framing and fuzzing passed\n");
}
