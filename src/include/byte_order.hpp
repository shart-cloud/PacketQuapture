#pragma once

#include <cstdint>

namespace packetquapture {

// Network protocols store multi-byte integers big-endian. Callers must have
// already checked that the bytes are in bounds; these readers do no checking.
inline uint16_t ReadBigEndian16(const uint8_t *p) {
	return static_cast<uint16_t>((uint16_t(p[0]) << 8U) | p[1]);
}

inline uint32_t ReadBigEndian32(const uint8_t *p) {
	return (uint32_t(ReadBigEndian16(p)) << 16U) | ReadBigEndian16(p + 2);
}

} // namespace packetquapture
