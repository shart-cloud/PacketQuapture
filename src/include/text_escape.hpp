#pragma once

#include <cstdint>
#include <string>

namespace packetquapture {

// Escapes written digit by digit: these run per escaped byte of peer text, where
// an snprintf call cost more than the rest of the escaping together.

// \DDD, the decimal escape DNS names and tls_sni use.
inline void AppendDecimalEscape(std::string &out, uint8_t byte) {
	out += '\\';
	out += static_cast<char>('0' + byte / 100);
	out += static_cast<char>('0' + byte / 10 % 10);
	out += static_cast<char>('0' + byte % 10);
}

// \XX, the upper-case hex escape RFC 4514 uses.
inline void AppendHexEscape(std::string &out, uint8_t byte) {
	static const char DIGITS[] = "0123456789ABCDEF";
	out += '\\';
	out += DIGITS[byte >> 4U];
	out += DIGITS[byte & 0x0FU];
}

} // namespace packetquapture
