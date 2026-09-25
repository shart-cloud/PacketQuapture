#pragma once

#include "tls_handshake.hpp"

#include <string>

namespace packetquapture {

// The strings JA3 and JA3S hash, as defined by salesforce/ja3 (README at
// 502cc63) and computed by tshark 4.2.2:
//
//   JA3   legacy_version,ciphers,extensions,groups,point_formats
//   JA3S  legacy_version,cipher,extensions
//
// Values are decimal, joined with '-', with RFC 8701 GREASE values dropped;
// a list the hello did not carry is an empty field. Each returns false, and
// leaves out empty, when its hello was not captured or failed to parse, or
// when one of its inputs was malformed or over the list limit: a fingerprint
// over partial input matches nothing and looks like it should.
bool Ja3String(const TlsHandshake &handshake, std::string &out);
bool Ja3sString(const TlsHandshake &handshake, std::string &out);

// The pieces of a JA4 or JA4S fingerprint, as defined by FoxIO-LLC/ja4 at
// 16b96d9 (technical_details/JA4.md, and the python and rust reference
// implementations for JA4S, whose only specification is a diagram). The
// fingerprint is prefix_hash12(first)_hash12(second) and the raw form
// prefix_first_second, where hash12 is the first 12 hex digits of SHA-256,
// or 000000000000 for an empty string. For JA4S, first is the selected
// cipher, which is not hashed.
//
// JA4S and the rest of JA4+ are licensed under the FoxIO License 1.1, not
// the MIT license of this project; see NOTICE. JA4 itself is BSD 3-Clause.
struct Ja4Parts {
	std::string prefix, first, second;
};

// As with JA3, each returns false when its hello is missing or invalid, or
// when an input it uses is malformed or over the list limit.
//
// JA4: t, version (highest non-GREASE supported_versions, else
// legacy_version), d or i for SNI, cipher and extension counts without
// GREASE capped at 99, and the first ALPN value's first and last characters.
// first: sorted cipher suites. second: sorted extension types without GREASE,
// SNI or ALPN, then _ and the signature algorithms in wire order, if any.
bool Ja4Strings(const TlsHandshake &handshake, Ja4Parts &out);
// JA4S: t, the negotiated version, the extension count including GREASE, and
// the selected ALPN value's characters. first: the selected cipher suite.
// second: extension types in wire order, GREASE included.
bool Ja4sStrings(const TlsHandshake &handshake, Ja4Parts &out);

// JA4X, from the same repository: rust/ja4x/src/lib.rs and python/ja4x.py. The
// fingerprint is hash12(issuer)_hash12(subject)_hash12(extensions) and the raw
// form issuer_subject_extensions, each part the comma-joined hex OIDs in wire
// order: issuer attribute types, subject attribute types, extensions. An
// empty part hashes to 000000000000, as in the rust reference and JA4; the
// python reference writes the hash of an empty string instead. FoxIO License
// 1.1; see NOTICE.
struct Ja4xParts {
	std::string issuer, subject, extensions;
};
void Ja4xStrings(const X509Certificate &certificate, Ja4xParts &out);

// The two ALPN characters of a JA4 prefix, per JA4.md: the first and last
// byte when both are ASCII alphanumeric, otherwise the first and last digit
// of the value's lower-case hex. 00 for no value.
std::string Ja4Alpn(const std::string &protocol);

} // namespace packetquapture
