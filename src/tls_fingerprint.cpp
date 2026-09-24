#include "tls_fingerprint.hpp"

#include <algorithm>

namespace packetquapture {

namespace {

void AppendNumber(std::string &out, unsigned value) {
	char digits[8];
	size_t length = 0;
	do {
		digits[length++] = static_cast<char>('0' + value % 10);
		value /= 10;
	} while (value != 0);
	while (length != 0) {
		out.push_back(digits[--length]);
	}
}

template <class T>
void AppendList(std::string &out, const TlsList<T> &list, bool skip_grease) {
	bool first = true;
	for (size_t i = 0; i < list.values.size(); ++i) {
		const unsigned value = list.values[i];
		if (skip_grease && IsTlsGrease(static_cast<uint16_t>(value))) {
			continue;
		}
		if (!first) {
			out.push_back('-');
		}
		first = false;
		AppendNumber(out, value);
	}
}

} // namespace

bool Ja3String(const TlsHandshake &handshake, std::string &out) {
	out.clear();
	// A parsed ClientHello always has its cipher suites and extension types;
	// without them it was not captured or did not parse.
	if (!handshake.has_client_hello || !handshake.has_client_version || !handshake.client_cipher_suites.present ||
	    !handshake.client_extensions.present || !handshake.client_supported_groups.Known() ||
	    !handshake.client_ec_point_formats.Known()) {
		return false;
	}
	AppendNumber(out, handshake.client_version);
	out.push_back(',');
	AppendList(out, handshake.client_cipher_suites, true);
	out.push_back(',');
	AppendList(out, handshake.client_extensions, true);
	out.push_back(',');
	AppendList(out, handshake.client_supported_groups, true);
	out.push_back(',');
	// Point formats are single bytes and have no GREASE values.
	AppendList(out, handshake.client_ec_point_formats, false);
	return true;
}

bool Ja3sString(const TlsHandshake &handshake, std::string &out) {
	out.clear();
	if (!handshake.has_server_hello || !handshake.has_server_legacy_version || !handshake.has_cipher_suite ||
	    !handshake.server_extensions.present) {
		return false;
	}
	AppendNumber(out, handshake.server_legacy_version);
	out.push_back(',');
	AppendNumber(out, handshake.cipher_suite);
	out.push_back(',');
	AppendList(out, handshake.server_extensions, true);
	return true;
}

namespace {

const uint16_t EXTENSION_SERVER_NAME = 0;
const uint16_t EXTENSION_ALPN = 16;
const uint16_t TLS_1_3 = 0x0304;

std::string Ja4Version(uint16_t version) {
	switch (version) {
	case TLS_1_3:
		return "13";
	case 0x0303:
		return "12";
	case 0x0302:
		return "11";
	case 0x0301:
		return "10";
	case 0x0300:
		return "s3";
	case 0x0002:
		return "s2";
	default:
		return "00";
	}
}

void AppendHex4(std::string &out, uint16_t value) {
	static const char digits[] = "0123456789abcdef";
	out.push_back(digits[(value >> 12U) & 0xFU]);
	out.push_back(digits[(value >> 8U) & 0xFU]);
	out.push_back(digits[(value >> 4U) & 0xFU]);
	out.push_back(digits[value & 0xFU]);
}

void AppendCount(std::string &out, size_t count) {
	count = std::min<size_t>(count, 99);
	out.push_back(static_cast<char>('0' + count / 10));
	out.push_back(static_cast<char>('0' + count % 10));
}

std::string JoinHex(const std::vector<uint16_t> &values) {
	std::string out;
	for (size_t i = 0; i < values.size(); ++i) {
		if (i != 0) {
			out.push_back(',');
		}
		AppendHex4(out, values[i]);
	}
	return out;
}

std::vector<uint16_t> WithoutGrease(const std::vector<uint16_t> &values) {
	std::vector<uint16_t> out;
	for (size_t i = 0; i < values.size(); ++i) {
		if (!IsTlsGrease(values[i])) {
			out.push_back(values[i]);
		}
	}
	return out;
}

bool IsAlphanumeric(unsigned char c) {
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

} // namespace

std::string Ja4Alpn(const std::string &protocol) {
	if (protocol.empty()) {
		return "00";
	}
	const unsigned char first = static_cast<unsigned char>(protocol[0]);
	const unsigned char last = static_cast<unsigned char>(protocol[protocol.size() - 1]);
	if (IsAlphanumeric(first) && IsAlphanumeric(last)) {
		return std::string(1, static_cast<char>(first)) + static_cast<char>(last);
	}
	static const char digits[] = "0123456789abcdef";
	return std::string(1, digits[first >> 4U]) + digits[last & 0xFU];
}

bool Ja4Strings(const TlsHandshake &handshake, Ja4Parts &out) {
	out = Ja4Parts();
	const auto &versions = handshake.client_supported_versions;
	if (!handshake.has_client_hello || !handshake.has_client_version || !handshake.client_cipher_suites.present ||
	    !handshake.client_extensions.present || !versions.Known() || !handshake.client_signature_algorithms.Known() ||
	    !handshake.client_alpn.Known()) {
		return false;
	}
	uint16_t version = handshake.client_version;
	if (versions.present) {
		const auto offered = WithoutGrease(versions.values);
		// Offering supported_versions with no real version leaves nothing to
		// report; the rust reference emits no fingerprint either.
		if (offered.empty()) {
			return false;
		}
		version = *std::max_element(offered.begin(), offered.end());
	}
	auto ciphers = WithoutGrease(handshake.client_cipher_suites.values);
	const auto extensions = WithoutGrease(handshake.client_extensions.values);
	const bool sni = std::find(extensions.begin(), extensions.end(), EXTENSION_SERVER_NAME) != extensions.end();

	out.prefix = "t" + Ja4Version(version) + (sni ? "d" : "i");
	AppendCount(out.prefix, ciphers.size());
	AppendCount(out.prefix, extensions.size());
	// The first value as sent, GREASE or not, as tshark and both FoxIO
	// implementations take it.
	out.prefix += handshake.client_alpn.present && !handshake.client_alpn.values.empty()
	                  ? Ja4Alpn(handshake.client_alpn.values.front())
	                  : "00";

	std::sort(ciphers.begin(), ciphers.end());
	out.first = JoinHex(ciphers);
	std::vector<uint16_t> hashed;
	for (size_t i = 0; i < extensions.size(); ++i) {
		if (extensions[i] != EXTENSION_SERVER_NAME && extensions[i] != EXTENSION_ALPN) {
			hashed.push_back(extensions[i]);
		}
	}
	std::sort(hashed.begin(), hashed.end());
	out.second = JoinHex(hashed);
	const auto signatures = WithoutGrease(handshake.client_signature_algorithms.values);
	if (!signatures.empty()) {
		out.second += "_" + JoinHex(signatures);
	}
	return true;
}

bool Ja4sStrings(const TlsHandshake &handshake, Ja4Parts &out) {
	out = Ja4Parts();
	if (!handshake.has_server_hello || !handshake.has_negotiated_version || !handshake.has_cipher_suite ||
	    !handshake.server_extensions.present || !handshake.server_alpn.Known()) {
		return false;
	}
	const auto &extensions = handshake.server_extensions.values;
	out.prefix = "t" + Ja4Version(handshake.negotiated_version);
	AppendCount(out.prefix, extensions.size());
	out.prefix += handshake.server_alpn.present && !handshake.server_alpn.values.empty()
	                  ? Ja4Alpn(handshake.server_alpn.values.front())
	                  : "00";
	AppendHex4(out.first, handshake.cipher_suite);
	out.second = JoinHex(extensions);
	return true;
}

// JA4X (FoxIO License 1.1): see tls_fingerprint.hpp and NOTICE.
void Ja4xStrings(const X509Certificate &certificate, Ja4xParts &out) {
	out.issuer = certificate.issuer_oids;
	out.subject = certificate.subject_oids;
	out.extensions = certificate.extension_oids;
}

} // namespace packetquapture
