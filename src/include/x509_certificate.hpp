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
};

enum class X509Result { OK, MALFORMED, OVER_LIMIT };

// Parses exactly one certificate filling data. OVER_LIMIT means it is well formed
// so far but carries more than max_san_entries subjectAltName entries. On
// anything but OK, out is left default-constructed.
X509Result ParseX509Certificate(const uint8_t *data, size_t size, size_t max_san_entries, X509Certificate &out);

} // namespace packetquapture
