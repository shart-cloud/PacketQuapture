#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace packetquapture {

// Fields read from one DER X.509 certificate, as a TLS server presents it. This
// is parsing only: no signature, chain, name or validity check is made.
struct X509Certificate {
	// RFC 4514 strings, most specific RDN first. Common attribute types use their
	// registered names, spelled as OpenSSL prints them; any other is its dotted
	// OID with a #hex DER value.
	std::string subject, issuer;
	// The serial number's INTEGER content octets as lowercase hex, leading zero
	// octet included, as tshark shows x509af.serialNumber.
	std::string serial;
	// Microseconds since the Unix epoch, UTC.
	int64_t not_before = 0, not_after = 0;
	// subjectAltName dNSName entries, escaped as tls_sni is, and iPAddress
	// entries as text (dotted IPv4, RFC 5952 IPv6), in wire order.
	std::vector<std::string> san_dns, san_ip;
	// The type OID of every issuer and subject attribute, and the OID of every
	// extension, in wire order, each as lowercase hex of its DER content octets
	// and joined with commas, which is the form JA4X fingerprints. One string
	// each, so a certificate with thousands of tiny extensions costs its text
	// and nothing more.
	std::string issuer_oids, subject_oids, extension_oids;
	// SHA-1 and SHA-256 of the whole DER certificate as lowercase hex, which is
	// what certificate blocklists key on. The parser has no hash of its own, so
	// these are filled by whoever supplies one; see TlsHandshakeLimits.
	std::string sha1, sha256;
	// The signature and public key algorithms, and an EC key's named curve, as
	// `openssl x509 -text` prints them. An OID it would print by number is its
	// dotted OID here too.
	std::string signature_algorithm, public_key_algorithm, public_key_curve;
	// An RSA modulus or DSA prime in bits, or an EC curve's size. Zero when the
	// key is another kind or its curve is not known.
	uint32_t public_key_bits = 0;
	// basicConstraints, when present: the cA flag and any pathLenConstraint.
	bool has_basic_constraints = false, is_ca = false, has_path_length = false;
	uint32_t path_length = 0;
	// keyUsage bits and extendedKeyUsage purposes by their RFC 5280 names, in
	// bit and wire order. A purpose without a name here is its dotted OID.
	bool has_key_usage = false, has_extended_key_usage = false;
	std::vector<std::string> key_usage, extended_key_usage;

	// The memory this certificate holds once parsed, for budgets: its text, and
	// each list entry's own string.
	size_t TextBytes() const {
		size_t bytes = subject.size() + issuer.size() + serial.size() + issuer_oids.size() + subject_oids.size() +
		               extension_oids.size() + sizeof(not_before) + sizeof(not_after) + sha1.size() + sha256.size() +
		               signature_algorithm.size() + public_key_algorithm.size() + public_key_curve.size() +
		               sizeof(public_key_bits) + sizeof(path_length);
		for (const auto *list : {&san_dns, &san_ip, &key_usage, &extended_key_usage}) {
			for (const auto &item : *list) {
				bytes += sizeof(std::string) + item.size();
			}
		}
		return bytes;
	}
};

// An IPv4 (size 4) or IPv6 (size 16) address as text: dotted IPv4, RFC 5952 IPv6.
std::string FormatIp(const uint8_t *p, size_t size);

enum class X509Result { OK, MALFORMED, OVER_LIMIT };

// Parses exactly one certificate filling data. OVER_LIMIT means it is well formed
// so far but carries more than max_entries subjectAltName entries, or more than
// max_entries extendedKeyUsage purposes. On anything but OK, out is left
// default-constructed.
X509Result ParseX509Certificate(const uint8_t *data, size_t size, size_t max_entries, X509Certificate &out);

} // namespace packetquapture
