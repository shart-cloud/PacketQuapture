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

} // namespace packetquapture
