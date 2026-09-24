#include "tls_handshake.hpp"

#include <algorithm>
#include <iterator>

namespace packetquapture {
namespace {

const uint8_t RECORD_CHANGE_CIPHER_SPEC = 20;
const uint8_t RECORD_HANDSHAKE = 22;
const uint8_t HANDSHAKE_CLIENT_HELLO = 1;
const uint8_t HANDSHAKE_SERVER_HELLO = 2;
const uint16_t EXTENSION_SERVER_NAME = 0;
const uint16_t EXTENSION_SUPPORTED_VERSIONS = 43;
const uint16_t TLS_1_3 = 0x0304;
const uint32_t MAX_RECORD_LENGTH = 16384 + 2048;
const size_t RECORD_HEADER_LENGTH = 5;

// Bounds-checked reader over one buffer. After a read runs past the end the
// reader stays overrun and every later read fails, so malformed input unwinds
// without a check at each step.
class Reader {
public:
	Reader(const uint8_t *data_p, size_t size_p) : data(data_p), size(size_p) {
	}
	bool Overrun() const {
		return overrun;
	}
	size_t Remaining() const {
		return overrun ? 0 : size - offset;
	}
	uint8_t U8() {
		if (Remaining() < 1) {
			overrun = true;
			return 0;
		}
		return data[offset++];
	}
	uint16_t U16() {
		const uint16_t high = U8();
		const uint16_t low = U8();
		return static_cast<uint16_t>((high << 8U) | low);
	}
	uint32_t U24() {
		const uint32_t high = U8();
		const uint32_t mid = U8();
		const uint32_t low = U8();
		return (high << 16U) | (mid << 8U) | low;
	}
	bool Skip(size_t count) {
		if (Remaining() < count) {
			overrun = true;
			return false;
		}
		offset += count;
		return true;
	}
	bool SkipVector(size_t length_bytes) {
		const size_t length = length_bytes == 1 ? U8() : U16();
		return !overrun && Skip(length);
	}
	bool Take(size_t count, std::string &out) {
		if (Remaining() < count) {
			overrun = true;
			return false;
		}
		out.assign(reinterpret_cast<const char *>(data + offset), count);
		offset += count;
		return true;
	}
	bool TakeBytes(size_t count, std::vector<uint8_t> &out) {
		if (Remaining() < count) {
			overrun = true;
			return false;
		}
		out.assign(data + offset, data + offset + count);
		offset += count;
		return true;
	}

private:
	const uint8_t *data;
	size_t size;
	size_t offset = 0;
	bool overrun = false;
};

void ParseServerName(Reader &reader, TlsHandshake &handshake) {
	const uint16_t list_length = reader.U16();
	if (reader.Overrun() || reader.Remaining() < list_length) {
		return;
	}
	size_t consumed = 0;
	while (consumed + 3 <= list_length) {
		const uint8_t name_type = reader.U8();
		const uint16_t name_length = reader.U16();
		consumed += 3;
		if (reader.Overrun() || name_length > list_length - consumed) {
			return;
		}
		if (name_type == 0) {
			std::string name;
			if (reader.Take(name_length, name)) {
				handshake.has_sni = true;
				handshake.sni = EscapeTlsText(name);
			}
			return;
		}
		if (!reader.Skip(name_length)) {
			return;
		}
		consumed += name_length;
	}
}

const uint16_t EXTENSION_SUPPORTED_GROUPS = 10;
const uint16_t EXTENSION_EC_POINT_FORMATS = 11;
const uint16_t EXTENSION_SIGNATURE_ALGORITHMS = 13;
const uint16_t EXTENSION_ALPN = 16;

// Set when a parsed list is longer than the per-list limit. The hello is then
// reported with status limit rather than with a list silently cut short.
struct ListBudget {
	explicit ListBudget(size_t cap_p) : cap(cap_p), exceeded(false) {
	}
	size_t cap;
	bool exceeded;
};

// Reads a length-prefixed vector of 16-bit code points. With exact set, the
// vector must fill the rest of the reader, as it does in an extension body.
// Returns false only when the reader itself overran; a vector that is
// well-framed but internally wrong is marked malformed instead.
bool ReadCodes(Reader &reader, size_t length_bytes, bool exact, ListBudget &budget, TlsList<uint16_t> &out) {
	const size_t length = length_bytes == 1 ? reader.U8() : reader.U16();
	std::vector<uint8_t> bytes;
	if (reader.Overrun() || !reader.TakeBytes(length, bytes)) {
		out = TlsList<uint16_t>();
		out.malformed = true;
		return false;
	}
	out = TlsList<uint16_t>();
	if (length % 2 != 0 || (exact && reader.Remaining() != 0)) {
		out.malformed = true;
		return true;
	}
	if (length / 2 > budget.cap) {
		budget.exceeded = true;
		out.over_limit = true;
		return true;
	}
	out.present = true;
	for (size_t i = 0; i < length; i += 2) {
		out.values.push_back(static_cast<uint16_t>((bytes[i] << 8U) | bytes[i + 1]));
	}
	return true;
}

void ReadPointFormats(Reader &reader, ListBudget &budget, TlsList<uint8_t> &out) {
	const size_t length = reader.U8();
	std::vector<uint8_t> bytes;
	out = TlsList<uint8_t>();
	if (reader.Overrun() || !reader.TakeBytes(length, bytes) || reader.Remaining() != 0) {
		out.malformed = true;
		return;
	}
	if (length > budget.cap) {
		budget.exceeded = true;
		out.over_limit = true;
		return;
	}
	out.present = true;
	out.values = bytes;
}

// RFC 7301: a vector of non-empty protocol names, each a one-byte length and
// raw bytes. A server must select exactly one.
void ReadAlpn(Reader &reader, bool client, ListBudget &budget, TlsList<std::string> &out) {
	out = TlsList<std::string>();
	const uint16_t list_length = reader.U16();
	if (reader.Overrun() || reader.Remaining() != list_length) {
		out.malformed = true;
		return;
	}
	std::vector<std::string> protocols;
	while (reader.Remaining() > 0) {
		const size_t length = reader.U8();
		std::string protocol;
		if (reader.Overrun() || length == 0 || !reader.Take(length, protocol)) {
			out.malformed = true;
			return;
		}
		protocols.push_back(protocol);
	}
	if (protocols.empty() || (!client && protocols.size() != 1)) {
		out.malformed = true;
		return;
	}
	if (protocols.size() > budget.cap) {
		budget.exceeded = true;
		out.over_limit = true;
		return;
	}
	out.present = true;
	out.values = protocols;
}

// A second copy of an extension is forbidden (RFC 8446 4.2), so its list is
// reported malformed rather than choosing one copy.
template <class T>
bool Duplicate(TlsList<T> &list) {
	if (list.present || list.malformed || list.over_limit) {
		list = TlsList<T>();
		list.malformed = true;
		return true;
	}
	return false;
}

// A ClientHello offers a list of versions; a ServerHello names the one chosen.
void ParseSupportedVersions(Reader &reader, bool client, ListBudget &budget, TlsHandshake &handshake) {
	if (client) {
		if (!Duplicate(handshake.client_supported_versions)) {
			ReadCodes(reader, 1, true, budget, handshake.client_supported_versions);
		}
		return;
	}
	// Exactly one version, in exactly two bytes. Otherwise the version is
	// unknown: legacy_version is no fallback, since TLS 1.3 fixes it at 0x0303.
	auto &selected = handshake.server_supported_versions;
	const uint16_t version = reader.U16();
	if (Duplicate(selected) || reader.Overrun() || reader.Remaining() != 0) {
		selected = TlsList<uint16_t>();
		selected.malformed = true;
		handshake.has_negotiated_version = false;
		handshake.negotiated_version = 0;
		return;
	}
	selected.present = true;
	selected.values.push_back(version);
	handshake.has_negotiated_version = true;
	handshake.negotiated_version = version;
}

// Walks the extension list, recording every type in order and reading the
// bodies this layer reports.
bool ParseExtensions(Reader &reader, bool client, const TlsHandshakeLimits &limits, ListBudget &budget,
                     TlsHandshake &handshake) {
	const uint16_t extensions_length = reader.U16();
	if (reader.Overrun()) {
		return false;
	}
	auto &types = client ? handshake.client_extensions : handshake.server_extensions;
	size_t consumed = 0, count = 0;
	while (consumed + 4 <= extensions_length) {
		const uint16_t type = reader.U16();
		const uint16_t length = reader.U16();
		consumed += 4;
		if (reader.Overrun() || length > extensions_length - consumed) {
			return false;
		}
		if (++count > limits.max_extensions) {
			return false;
		}
		std::vector<uint8_t> body;
		if (!reader.TakeBytes(length, body)) {
			return false;
		}
		consumed += length;
		types.values.push_back(type);
		Reader inner(body.data(), body.size());
		if (type == EXTENSION_SERVER_NAME && client) {
			ParseServerName(inner, handshake);
		} else if (type == EXTENSION_SUPPORTED_VERSIONS) {
			ParseSupportedVersions(inner, client, budget, handshake);
		} else if (client && type == EXTENSION_SUPPORTED_GROUPS) {
			if (!Duplicate(handshake.client_supported_groups)) {
				ReadCodes(inner, 2, true, budget, handshake.client_supported_groups);
			}
		} else if (client && type == EXTENSION_SIGNATURE_ALGORITHMS) {
			if (!Duplicate(handshake.client_signature_algorithms)) {
				ReadCodes(inner, 2, true, budget, handshake.client_signature_algorithms);
			}
		} else if (client && type == EXTENSION_EC_POINT_FORMATS) {
			if (!Duplicate(handshake.client_ec_point_formats)) {
				ReadPointFormats(inner, budget, handshake.client_ec_point_formats);
			}
		} else if (type == EXTENSION_ALPN) {
			auto &alpn = client ? handshake.client_alpn : handshake.server_alpn;
			if (!Duplicate(alpn)) {
				ReadAlpn(inner, client, budget, alpn);
			}
		}
	}
	return !reader.Overrun();
}

// ClientHello and ServerHello share a prefix up to the extension list, differing
// only in how the session id and cipher suites are encoded.
bool ParseHello(const std::vector<uint8_t> &body, bool client, const TlsHandshakeLimits &limits,
                TlsHandshake &handshake, std::vector<uint8_t> &session_id) {
	Reader reader(body.data(), body.size());
	const uint16_t legacy_version = reader.U16();
	if (reader.Overrun()) {
		return false;
	}
	if (client) {
		handshake.has_client_version = true;
		handshake.client_version = legacy_version;
	} else {
		handshake.has_negotiated_version = true;
		handshake.negotiated_version = legacy_version;
		handshake.has_server_legacy_version = true;
		handshake.server_legacy_version = legacy_version;
	}
	if (!reader.Skip(32)) { // random
		return false;
	}
	const size_t session_length = reader.U8();
	if (reader.Overrun() || !reader.TakeBytes(session_length, session_id)) {
		return false;
	}
	ListBudget budget(limits.max_list_entries);
	if (client) {
		if (!ReadCodes(reader, 2, false, budget, handshake.client_cipher_suites)) {
			return false;
		}
		if (!reader.SkipVector(1)) { // legacy_compression_methods
			return false;
		}
	} else {
		const uint16_t suite = reader.U16();
		if (reader.Overrun()) {
			return false;
		}
		handshake.has_cipher_suite = true;
		handshake.cipher_suite = suite;
		if (!reader.Skip(1)) { // legacy_compression_method
			return false;
		}
	}
	// The hello parsed this far, so its extension list is known: absent means
	// it offered none.
	auto &types = client ? handshake.client_extensions : handshake.server_extensions;
	types.present = true;
	// A hello with no extension list at all is legal and simply offers nothing.
	if (reader.Remaining() != 0 && !ParseExtensions(reader, client, limits, budget, handshake)) {
		return false;
	}
	if (budget.exceeded) {
		handshake.status = "limit";
		handshake.error = "TLS hello list exceeds the per-list limit";
	}
	return true;
}

// A hello that failed to parse reports none of the fields read before the
// failure: a partial list is worse than none, since it looks complete.
void ClearHello(TlsHandshake &handshake) {
	handshake.has_sni = false;
	handshake.sni.clear();
	handshake.client_cipher_suites = TlsList<uint16_t>();
	handshake.client_extensions = TlsList<uint16_t>();
	handshake.client_supported_groups = TlsList<uint16_t>();
	handshake.client_signature_algorithms = TlsList<uint16_t>();
	handshake.client_supported_versions = TlsList<uint16_t>();
	handshake.client_ec_point_formats = TlsList<uint8_t>();
	handshake.client_alpn = TlsList<std::string>();
	handshake.server_extensions = TlsList<uint16_t>();
	handshake.server_alpn = TlsList<std::string>();
	handshake.server_supported_versions = TlsList<uint16_t>();
}

} // namespace

TlsHandshakeAssembler::TlsHandshakeAssembler(TlsHandshakeLimits limits_p) : limits(limits_p) {
}

bool TlsHandshakeAssembler::Empty() const {
	return pending.empty();
}

// Reads the handshake messages of one direction. TLS records carry a byte
// stream, so a handshake message may span several records and a record may hold
// several messages: the record bodies are concatenated before framing messages.
TlsHandshakeAssembler::Direction TlsHandshakeAssembler::Parse(const TcpStream &stream,
                                                              const TlsHandshakeLimits &limits) {
	Direction direction;
	direction.oriented_key = stream.key;
	direction.stream_id = stream.stream_id;
	direction.first = stream.first;
	direction.last = stream.last;

	// A direction the transport could not reconstruct tells us nothing about
	// whether it carried TLS, so it is reported only if a peer identifies it.
	if (stream.status == "conflict" || stream.status == "limit") {
		direction.status = stream.status;
		direction.error = stream.error;
		return direction;
	}
	const auto *chunk = !stream.chunks.empty() && stream.chunks.front().offset == 0 ? &stream.chunks.front() : nullptr;
	if (chunk == nullptr) {
		return direction;
	}

	std::vector<uint8_t> handshake_bytes;
	std::vector<std::pair<size_t, size_t>> record_spans; // offset in chunk, length contributed
	size_t offset = 0;
	bool truncated = false;
	while (chunk->data.size() - offset >= RECORD_HEADER_LENGTH) {
		const uint8_t *header = chunk->data.data() + offset;
		const uint8_t type = header[0];
		const uint32_t length = static_cast<uint32_t>((header[3] << 8U) | header[4]);
		if (header[1] != 0x03 || header[2] > 0x04 || length == 0 || length > MAX_RECORD_LENGTH) {
			break;
		}
		if (type == RECORD_CHANGE_CIPHER_SPEC) {
			// Everything after this is encrypted; stop rather than parse noise.
			break;
		}
		if (length > chunk->data.size() - offset - RECORD_HEADER_LENGTH) {
			truncated = true;
			break;
		}
		if (type != RECORD_HANDSHAKE) {
			offset += RECORD_HEADER_LENGTH + length;
			continue;
		}
		const size_t begin = offset + RECORD_HEADER_LENGTH;
		handshake_bytes.insert(handshake_bytes.end(), chunk->data.begin() + static_cast<long>(begin),
		                       chunk->data.begin() + static_cast<long>(begin + length));
		record_spans.push_back(std::make_pair(begin, static_cast<size_t>(length)));
		offset += RECORD_HEADER_LENGTH + length;
	}
	if (handshake_bytes.empty()) {
		return direction;
	}

	// Map an offset in the concatenated handshake bytes back to the chunk, so
	// provenance comes from the packets that actually carried the message.
	struct Locator {
		const std::vector<std::pair<size_t, size_t>> *spans;
		std::pair<size_t, size_t> Locate(size_t begin, size_t length) const {
			size_t seen = 0, first = 0, last = 0;
			bool found = false;
			for (size_t i = 0; i < spans->size(); ++i) {
				const size_t span_begin = seen;
				const size_t span_end = seen + (*spans)[i].second;
				seen = span_end;
				if (span_end <= begin || span_begin >= begin + length) {
					continue;
				}
				const size_t local = begin > span_begin ? begin - span_begin : 0;
				const size_t chunk_begin = (*spans)[i].first + local;
				if (!found) {
					first = chunk_begin;
					found = true;
				}
				last = (*spans)[i].first + std::min((*spans)[i].second, begin + length - span_begin);
			}
			return found ? std::make_pair(first, last - first) : std::make_pair(size_t(0), size_t(0));
		}
	};
	const Locator locator = {&record_spans};

	size_t message_offset = 0;
	while (handshake_bytes.size() - message_offset >= 4) {
		Reader reader(handshake_bytes.data() + message_offset, handshake_bytes.size() - message_offset);
		const uint8_t type = reader.U8();
		const uint32_t length = reader.U24();
		if (length > limits.max_message_bytes) {
			direction.status = "limit";
			direction.error = "TLS handshake message exceeds the per-message limit";
			break;
		}
		if (length > handshake_bytes.size() - message_offset - 4) {
			truncated = true;
			break;
		}
		if (type == HANDSHAKE_CLIENT_HELLO || type == HANDSHAKE_SERVER_HELLO) {
			const bool client = type == HANDSHAKE_CLIENT_HELLO;
			if (direction.handshakes.size() >= limits.max_handshakes) {
				direction.status = "limit";
				direction.error = "TLS handshake count exceeds the per-direction limit";
				break;
			}
			TlsHandshake handshake;
			handshake.has_client_hello = client;
			handshake.has_server_hello = !client;
			std::vector<uint8_t> body(handshake_bytes.begin() + static_cast<long>(message_offset + 4),
			                          handshake_bytes.begin() + static_cast<long>(message_offset + 4 + length));
			std::vector<uint8_t> session_id;
			if (!ParseHello(body, client, limits, handshake, session_id)) {
				handshake.status = "invalid";
				handshake.error = client ? "ClientHello is malformed" : "ServerHello is malformed";
				ClearHello(handshake);
			}
			const auto span = locator.Locate(message_offset, length + 4);
			if (span.second > 0) {
				const auto provenance = chunk->Provenance(span.first, span.second);
				handshake.first = provenance.first;
				handshake.last = provenance.second;
			}
			direction.client = direction.client || client;
			direction.handshakes.push_back(handshake);
			direction.session_ids.push_back(session_id);
		}
		message_offset += 4 + length;
	}
	if (truncated && direction.status.empty()) {
		direction.status = "incomplete";
		direction.error = !stream.gaps.empty() ? "missing TCP bytes leave a sequence gap"
		                                       : "TLS handshake continues past the captured bytes";
	}
	if (direction.status.empty() && stream.status == "unanchored") {
		direction.status = "unanchored";
		direction.error = stream.error;
	}
	if (!direction.client && !direction.handshakes.empty()) {
		// Only a ServerHello was seen, so this direction runs server to client.
		direction.oriented_key = stream.key.Reverse();
	}
	return direction;
}

// Joins the two directions by position: the nth ClientHello of a connection is
// answered by its nth ServerHello. A direction that arrived without its peer is
// reported alone, with the absent side's columns left unset.
std::vector<TlsHandshake> TlsHandshakeAssembler::Merge(const Direction &client, const Direction *server) {
	std::vector<TlsHandshake> result;
	const size_t count = std::max(client.handshakes.size(), server != nullptr ? server->handshakes.size() : size_t(0));
	for (size_t index = 0; index < count; ++index) {
		const TlsHandshake *from_client = index < client.handshakes.size() ? &client.handshakes[index] : nullptr;
		const TlsHandshake *from_server =
		    server != nullptr && index < server->handshakes.size() ? &server->handshakes[index] : nullptr;
		TlsHandshake handshake;
		handshake.key = client.handshakes.empty() && server != nullptr ? server->oriented_key : client.oriented_key;
		handshake.handshake_number = index + 1;
		if (from_client != nullptr) {
			handshake.has_client_hello = true;
			handshake.has_sni = from_client->has_sni;
			handshake.sni = from_client->sni;
			handshake.has_client_version = from_client->has_client_version;
			handshake.client_version = from_client->client_version;
			handshake.client_cipher_suites = from_client->client_cipher_suites;
			handshake.client_extensions = from_client->client_extensions;
			handshake.client_supported_groups = from_client->client_supported_groups;
			handshake.client_signature_algorithms = from_client->client_signature_algorithms;
			handshake.client_supported_versions = from_client->client_supported_versions;
			handshake.client_ec_point_formats = from_client->client_ec_point_formats;
			handshake.client_alpn = from_client->client_alpn;
			handshake.first = from_client->first;
			handshake.last = from_client->last;
			handshake.status = from_client->status;
			handshake.error = from_client->error;
		}
		if (from_server != nullptr) {
			handshake.has_server_hello = true;
			handshake.has_negotiated_version = from_server->has_negotiated_version;
			handshake.negotiated_version = from_server->negotiated_version;
			handshake.has_server_legacy_version = from_server->has_server_legacy_version;
			handshake.server_legacy_version = from_server->server_legacy_version;
			handshake.has_cipher_suite = from_server->has_cipher_suite;
			handshake.cipher_suite = from_server->cipher_suite;
			handshake.server_extensions = from_server->server_extensions;
			handshake.server_alpn = from_server->server_alpn;
			handshake.server_supported_versions = from_server->server_supported_versions;
			if (from_client == nullptr) {
				handshake.first = from_server->first;
				handshake.last = from_server->last;
			} else if (from_server->last.number > handshake.last.number) {
				handshake.last = from_server->last;
			}
			if (handshake.status.empty()) {
				handshake.status = from_server->status;
				handshake.error = from_server->error;
			}
		}
		if (!client.handshakes.empty()) {
			handshake.has_client_stream = true;
			handshake.client_stream_id = client.stream_id;
		}
		if (server != nullptr && !server->handshakes.empty()) {
			handshake.has_server_stream = true;
			handshake.server_stream_id = server->stream_id;
		}
		// A server echoing a non-empty session id resumed the session. TLS 1.3
		// echoes the id whether or not it resumed, so the question does not apply,
		// and without a known version it cannot be asked.
		if (from_client != nullptr && from_server != nullptr && index < client.session_ids.size() &&
		    index < server->session_ids.size() && handshake.has_negotiated_version &&
		    handshake.negotiated_version != TLS_1_3) {
			const auto &offered = client.session_ids[index];
			const auto &echoed = server->session_ids[index];
			handshake.has_resumed = true;
			handshake.resumed = !offered.empty() && offered == echoed;
		}
		// A status set on the handshake itself, such as a malformed hello, is the
		// most specific. Next comes a status covering the whole direction, such as
		// a limit or a truncated stream. Only then is the row judged on whether
		// both sides were captured.
		if (handshake.status.empty() && from_client != nullptr && !client.status.empty()) {
			handshake.status = client.status;
			handshake.error = client.error;
		}
		if (handshake.status.empty() && from_server != nullptr && server != nullptr && !server->status.empty()) {
			handshake.status = server->status;
			handshake.error = server->error;
		}
		// A direction whose peer never arrived is not an error: one side of a
		// connection is often all that was captured.
		if (handshake.status.empty()) {
			handshake.status = from_client == nullptr || from_server == nullptr ? "one-sided" : "complete";
		}
		// reassembly_status holds one value and a more specific one wins, so an
		// uncaptured side is also stated here, where no other status can hide it.
		if (from_client == nullptr) {
			handshake.warnings.push_back("client_hello_missing");
		}
		if (from_server == nullptr) {
			handshake.warnings.push_back("server_hello_missing");
		}
		if (from_client != nullptr && from_client->status == "invalid") {
			handshake.warnings.push_back("client_hello_invalid");
		}
		if (from_server != nullptr && from_server->status == "invalid") {
			handshake.warnings.push_back("server_hello_invalid");
		}
		if (from_client != nullptr &&
		    (from_client->client_cipher_suites.malformed || from_client->client_supported_groups.malformed ||
		     from_client->client_signature_algorithms.malformed || from_client->client_supported_versions.malformed ||
		     from_client->client_ec_point_formats.malformed || from_client->client_alpn.malformed)) {
			handshake.warnings.push_back("client_list_malformed");
		}
		if (from_server != nullptr &&
		    (from_server->server_alpn.malformed || from_server->server_supported_versions.malformed)) {
			handshake.warnings.push_back("server_list_malformed");
		}
		result.push_back(handshake);
	}
	return result;
}

std::vector<TlsHandshake> TlsHandshakeAssembler::Add(const TcpStream &stream) {
	std::vector<TlsHandshake> result;
	auto direction = Parse(stream, limits);
	if (direction.handshakes.empty()) {
		// Nothing identified this direction as TLS, so it is not reported. A
		// transport failure on a stream we cannot classify is not a TLS finding.
		return result;
	}
	auto existing = pending.find(direction.oriented_key);
	if (existing == pending.end()) {
		if (pending.size() >= limits.max_pending) {
			// Report rather than drop: emit this direction alone instead of
			// holding it past the limit.
			return Merge(direction.client ? direction : Direction(), direction.client ? nullptr : &direction);
		}
		pending.insert(std::make_pair(direction.oriented_key, direction));
		return result;
	}
	if (existing->second.client == direction.client) {
		// The same side twice, so these are separate connections reusing the
		// tuple. Report the one already held and keep the newcomer.
		result = existing->second.client ? Merge(existing->second, nullptr) : Merge(Direction(), &existing->second);
		existing->second = direction;
		return result;
	}
	const Direction &client = direction.client ? direction : existing->second;
	const Direction &server = direction.client ? existing->second : direction;
	result = Merge(client, &server);
	pending.erase(existing);
	return result;
}

std::vector<TlsHandshake> TlsHandshakeAssembler::Finish() {
	std::vector<TlsHandshake> result;
	for (std::map<TcpFlowKey, Direction>::iterator it = pending.begin(); it != pending.end(); ++it) {
		auto handshakes = it->second.client ? Merge(it->second, nullptr) : Merge(Direction(), &it->second);
		result.insert(result.end(), std::make_move_iterator(handshakes.begin()),
		              std::make_move_iterator(handshakes.end()));
	}
	pending.clear();
	return result;
}

} // namespace packetquapture
