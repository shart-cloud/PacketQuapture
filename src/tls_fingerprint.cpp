#include "tls_fingerprint.hpp"

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

} // namespace packetquapture
