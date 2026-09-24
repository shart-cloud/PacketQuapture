#include "x509_certificate.hpp"

#include "tls_record.hpp"

#include <cstdio>

namespace packetquapture {
namespace {

const uint8_t TAG_BOOLEAN = 0x01;
const uint8_t TAG_INTEGER = 0x02;
const uint8_t TAG_OCTET_STRING = 0x04;
const uint8_t TAG_OID = 0x06;
const uint8_t TAG_UTF8_STRING = 0x0C;
const uint8_t TAG_NUMERIC_STRING = 0x12;
const uint8_t TAG_PRINTABLE_STRING = 0x13;
const uint8_t TAG_TELETEX_STRING = 0x14;
const uint8_t TAG_IA5_STRING = 0x16;
const uint8_t TAG_UTC_TIME = 0x17;
const uint8_t TAG_GENERALIZED_TIME = 0x18;
const uint8_t TAG_VISIBLE_STRING = 0x1A;
const uint8_t TAG_UNIVERSAL_STRING = 0x1C;
const uint8_t TAG_BMP_STRING = 0x1E;
const uint8_t TAG_SEQUENCE = 0x30;
const uint8_t TAG_SET = 0x31;
const uint8_t TAG_VERSION = 0xA0;        // [0] EXPLICIT
const uint8_t TAG_ISSUER_UID = 0x81;     // [1] IMPLICIT
const uint8_t TAG_SUBJECT_UID = 0x82;    // [2] IMPLICIT
const uint8_t TAG_EXTENSIONS = 0xA3;     // [3] EXPLICIT
const uint8_t TAG_SAN_DNS_NAME = 0x82;   // GeneralName [2] IMPLICIT IA5String
const uint8_t TAG_SAN_IP_ADDRESS = 0x87; // GeneralName [7] IMPLICIT OCTET STRING

// One DER element: its tag, and its content and whole encoding as spans.
struct Element {
	uint8_t tag = 0;
	const uint8_t *content = nullptr;
	size_t length = 0;
	const uint8_t *encoding = nullptr;
	size_t encoded_length = 0;
};

// Walks the elements of one constructed value. Every read is bounds-checked; a
// failed read leaves the walker failed, so a malformed input unwinds.
class Der {
public:
	Der(const uint8_t *data_p, size_t size_p) : data(data_p), size(size_p) {
	}
	bool AtEnd() const {
		return offset == size;
	}
	bool Failed() const {
		return failed;
	}
	uint8_t PeekTag() const {
		return offset < size ? data[offset] : 0;
	}
	bool Next(Element &out) {
		if (failed || size - offset < 2) {
			return Fail();
		}
		const size_t start = offset;
		const uint8_t tag = data[offset++];
		if ((tag & 0x1FU) == 0x1FU) { // high tag numbers never occur in certificates
			return Fail();
		}
		size_t length = data[offset++];
		if (length & 0x80U) {
			const size_t count = length & 0x7FU;
			// No indefinite lengths in DER; four octets already exceed any certificate.
			if (count == 0 || count > 4 || size - offset < count) {
				return Fail();
			}
			length = 0;
			for (size_t i = 0; i < count; ++i) {
				length = (length << 8U) | data[offset++];
			}
		}
		if (length > size - offset) {
			return Fail();
		}
		out.tag = tag;
		out.content = data + offset;
		out.length = length;
		out.encoding = data + start;
		out.encoded_length = offset + length - start;
		offset += length;
		return true;
	}
	bool Expect(uint8_t tag, Element &out) {
		return Next(out) && (out.tag == tag || Fail());
	}

private:
	bool Fail() {
		failed = true;
		return false;
	}
	const uint8_t *data;
	size_t size;
	size_t offset = 0;
	bool failed = false;
};

std::string Hex(const uint8_t *data, size_t size, bool upper = false) {
	const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
	std::string out;
	out.reserve(size * 2);
	for (size_t i = 0; i < size; ++i) {
		out += digits[data[i] >> 4U];
		out += digits[data[i] & 0x0FU];
	}
	return out;
}

bool DecodeOid(const Element &element, std::string &out) {
	if (element.length == 0 || (element.content[element.length - 1] & 0x80U)) {
		return false;
	}
	out.clear();
	uint64_t value = 0;
	size_t digits = 0;
	bool first = true;
	for (size_t i = 0; i < element.length; ++i) {
		const uint8_t byte = element.content[i];
		if (digits == 0 && byte == 0x80U) { // leading zero in an arc
			return false;
		}
		if (++digits > 9) { // beyond 63 bits
			return false;
		}
		value = (value << 7U) | (byte & 0x7FU);
		if (byte & 0x80U) {
			continue;
		}
		if (first) {
			const uint64_t top = value < 40 ? 0 : value < 80 ? 1 : 2;
			out = std::to_string(top) + "." + std::to_string(value - top * 40);
			first = false;
		} else {
			out += "." + std::to_string(value);
		}
		value = 0;
		digits = 0;
	}
	return true;
}

// RFC 4514 section 3 lists the names every implementation must know. It allows
// other registered names; for those this uses the spelling OpenSSL prints with
// -nameopt RFC2253, so the two can be compared. Anything else is a dotted OID.
const char *ShortName(const std::string &oid) {
	static const char *const names[][2] = {
	    {"2.5.4.3", "CN"},
	    {"2.5.4.7", "L"},
	    {"2.5.4.8", "ST"},
	    {"2.5.4.10", "O"},
	    {"2.5.4.11", "OU"},
	    {"2.5.4.6", "C"},
	    {"2.5.4.9", "STREET"},
	    {"0.9.2342.19200300.100.1.25", "DC"},
	    {"0.9.2342.19200300.100.1.1", "UID"},
	    {"2.5.4.5", "serialNumber"},
	    {"2.5.4.97", "organizationIdentifier"},
	    {"1.2.840.113549.1.9.1", "emailAddress"},
	    {"2.5.4.12", "title"},
	    {"2.5.4.42", "GN"},
	    {"2.5.4.4", "SN"},
	    {"2.5.4.43", "initials"},
	    {"2.5.4.44", "generationQualifier"},
	    {"2.5.4.17", "postalCode"},
	    {"2.5.4.15", "businessCategory"},
	    {"2.5.4.65", "pseudonym"},
	    {"2.5.4.46", "dnQualifier"},
	    {"2.5.4.41", "name"},
	    {"1.3.6.1.4.1.311.60.2.1.1", "jurisdictionL"},
	    {"1.3.6.1.4.1.311.60.2.1.2", "jurisdictionST"},
	    {"1.3.6.1.4.1.311.60.2.1.3", "jurisdictionC"},
	};
	for (const auto &entry : names) {
		if (oid == entry[0]) {
			return entry[1];
		}
	}
	return nullptr;
}

void AppendUtf8(uint32_t code, std::string &out) {
	if (code < 0x80) {
		out += static_cast<char>(code);
	} else if (code < 0x800) {
		out += static_cast<char>(0xC0 | (code >> 6U));
		out += static_cast<char>(0x80 | (code & 0x3FU));
	} else if (code < 0x10000) {
		out += static_cast<char>(0xE0 | (code >> 12U));
		out += static_cast<char>(0x80 | ((code >> 6U) & 0x3FU));
		out += static_cast<char>(0x80 | (code & 0x3FU));
	} else {
		out += static_cast<char>(0xF0 | (code >> 18U));
		out += static_cast<char>(0x80 | ((code >> 12U) & 0x3FU));
		out += static_cast<char>(0x80 | ((code >> 6U) & 0x3FU));
		out += static_cast<char>(0x80 | (code & 0x3FU));
	}
}

// Decodes the next UTF-8 sequence at text[i], returning its length, or 0 when
// the bytes there are not valid UTF-8.
size_t Utf8Length(const std::string &text, size_t i) {
	const auto lead = static_cast<unsigned char>(text[i]);
	size_t length;
	uint32_t code, minimum;
	if (lead < 0x80) {
		return 1;
	} else if ((lead & 0xE0U) == 0xC0U) {
		length = 2, code = lead & 0x1FU, minimum = 0x80;
	} else if ((lead & 0xF0U) == 0xE0U) {
		length = 3, code = lead & 0x0FU, minimum = 0x800;
	} else if ((lead & 0xF8U) == 0xF0U) {
		length = 4, code = lead & 0x07U, minimum = 0x10000;
	} else {
		return 0;
	}
	if (text.size() - i < length) {
		return 0;
	}
	for (size_t j = 1; j < length; ++j) {
		const auto next = static_cast<unsigned char>(text[i + j]);
		if ((next & 0xC0U) != 0x80U) {
			return 0;
		}
		code = (code << 6U) | (next & 0x3FU);
	}
	if (code < minimum || code > 0x10FFFF || (code >= 0xD800 && code <= 0xDFFF)) {
		return 0;
	}
	return length;
}

// RFC 4514 section 2.4. Specials get a backslash; control characters, and bytes
// that are not UTF-8, become \XX hex pairs, so the result is always valid UTF-8.
std::string EscapeRfc4514(const std::string &value) {
	std::string out;
	for (size_t i = 0; i < value.size();) {
		const auto ch = static_cast<unsigned char>(value[i]);
		const size_t length = Utf8Length(value, i);
		if (length == 0 || ch < 0x20 || ch == 0x7F) {
			char escaped[4];
			std::snprintf(escaped, sizeof(escaped), "\\%02X", static_cast<unsigned>(ch));
			out += escaped;
			++i;
			continue;
		}
		const bool special = ch == ',' || ch == '+' || ch == '"' || ch == '\\' || ch == '<' || ch == '>' || ch == ';' ||
		                     (i == 0 && (ch == ' ' || ch == '#')) || (i + 1 == value.size() && ch == ' ');
		if (special) {
			out += '\\';
		}
		out.append(value, i, length);
		i += length;
	}
	return out;
}

// Reads a directory string as UTF-8. Teletex is taken as Latin-1, as OpenSSL
// does. Returns false for a type that is not a string, or a malformed one.
bool DecodeString(const Element &element, std::string &out) {
	out.clear();
	const uint8_t *p = element.content;
	const size_t n = element.length;
	switch (element.tag) {
	case TAG_UTF8_STRING:
	case TAG_PRINTABLE_STRING:
	case TAG_IA5_STRING:
	case TAG_VISIBLE_STRING:
	case TAG_NUMERIC_STRING:
		out.assign(reinterpret_cast<const char *>(p), n);
		return true;
	case TAG_TELETEX_STRING:
		for (size_t i = 0; i < n; ++i) {
			AppendUtf8(p[i], out);
		}
		return true;
	case TAG_BMP_STRING:
		if (n % 2 != 0) {
			return false;
		}
		for (size_t i = 0; i < n; i += 2) {
			const uint32_t code = (uint32_t(p[i]) << 8U) | p[i + 1];
			if (code >= 0xD800 && code <= 0xDFFF) {
				return false;
			}
			AppendUtf8(code, out);
		}
		return true;
	case TAG_UNIVERSAL_STRING:
		if (n % 4 != 0) {
			return false;
		}
		for (size_t i = 0; i < n; i += 4) {
			const uint32_t code =
			    (uint32_t(p[i]) << 24U) | (uint32_t(p[i + 1]) << 16U) | (uint32_t(p[i + 2]) << 8U) | p[i + 3];
			if (code > 0x10FFFF || (code >= 0xD800 && code <= 0xDFFF)) {
				return false;
			}
			AppendUtf8(code, out);
		}
		return true;
	default:
		return false;
	}
}

// Name ::= SEQUENCE OF RelativeDistinguishedName, each a SET OF
// AttributeTypeAndValue. RFC 4514 writes the last RDN first. Order inside a
// multi-valued RDN carries no meaning; it is reversed too, as OpenSSL does, so
// the two print the same string.
bool DecodeName(const Element &name, std::string &out) {
	if (name.tag != TAG_SEQUENCE) {
		return false;
	}
	std::vector<std::vector<std::string>> rdns;
	Der sequence(name.content, name.length);
	while (!sequence.AtEnd()) {
		Element set;
		if (!sequence.Expect(TAG_SET, set) || set.length == 0) {
			return false;
		}
		std::vector<std::string> rdn;
		Der attributes(set.content, set.length);
		while (!attributes.AtEnd()) {
			Element pair, type, value;
			if (!attributes.Expect(TAG_SEQUENCE, pair)) {
				return false;
			}
			Der fields(pair.content, pair.length);
			std::string oid, text;
			if (!fields.Expect(TAG_OID, type) || !fields.Next(value) || !fields.AtEnd() || !DecodeOid(type, oid)) {
				return false;
			}
			const char *short_name = ShortName(oid);
			if (short_name != nullptr && DecodeString(value, text)) {
				rdn.push_back(std::string(short_name) + "=" + EscapeRfc4514(text));
			} else {
				rdn.push_back((short_name != nullptr ? std::string(short_name) : oid) + "=#" +
				              Hex(value.encoding, value.encoded_length, true));
			}
		}
		rdns.push_back(rdn);
	}
	out.clear();
	for (size_t i = rdns.size(); i-- > 0;) {
		for (size_t j = rdns[i].size(); j-- > 0;) {
			out += rdns[i][j];
			if (j > 0) {
				out += '+';
			}
		}
		if (i > 0) {
			out += ',';
		}
	}
	return true;
}

bool Digits(const uint8_t *p, size_t count, int &out) {
	out = 0;
	for (size_t i = 0; i < count; ++i) {
		if (p[i] < '0' || p[i] > '9') {
			return false;
		}
		out = out * 10 + (p[i] - '0');
	}
	return true;
}

// Days from 1970-01-01 to a proleptic Gregorian date.
int64_t DaysFromCivil(int64_t year, int64_t month, int64_t day) {
	year -= month <= 2 ? 1 : 0;
	const int64_t era = (year >= 0 ? year : year - 399) / 400;
	const int64_t yoe = year - era * 400;
	const int64_t doy = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1;
	const int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
	return era * 146097 + doe - 719468;
}

// RFC 5280 4.1.2.5: UTCTime YYMMDDHHMMSSZ, where YY below 50 is 20YY, and
// GeneralizedTime YYYYMMDDHHMMSSZ. Other forms are not valid in a certificate.
bool DecodeTime(const Element &element, int64_t &out) {
	const uint8_t *p = element.content;
	int year, month, day, hour, minute, second;
	if (element.tag == TAG_UTC_TIME && element.length == 13) {
		if (!Digits(p, 2, year)) {
			return false;
		}
		year += year < 50 ? 2000 : 1900;
		p += 2;
	} else if (element.tag == TAG_GENERALIZED_TIME && element.length == 15) {
		if (!Digits(p, 4, year)) {
			return false;
		}
		p += 4;
	} else {
		return false;
	}
	if (!Digits(p, 2, month) || !Digits(p + 2, 2, day) || !Digits(p + 4, 2, hour) || !Digits(p + 6, 2, minute) ||
	    !Digits(p + 8, 2, second) || p[10] != 'Z') {
		return false;
	}
	static const int month_days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
	const bool leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
	if (month < 1 || month > 12 || day < 1 || day > month_days[month - 1] + (month == 2 && leap ? 1 : 0) || hour > 23 ||
	    minute > 59 || second > 59) {
		return false;
	}
	const int64_t seconds = DaysFromCivil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second;
	out = seconds * 1000000;
	return true;
}

std::string FormatIp(const uint8_t *p, size_t size) {
	char text[8];
	std::string out;
	if (size == 4) {
		for (size_t i = 0; i < 4; ++i) {
			std::snprintf(text, sizeof(text), i ? ".%u" : "%u", static_cast<unsigned>(p[i]));
			out += text;
		}
		return out;
	}
	// RFC 5952: the longest run of two or more zero groups, the first if tied, is ::.
	uint16_t groups[8];
	for (size_t i = 0; i < 8; ++i) {
		groups[i] = static_cast<uint16_t>((p[2 * i] << 8U) | p[2 * i + 1]);
	}
	size_t best = 8, best_length = 0;
	for (size_t i = 0; i < 8;) {
		size_t j = i;
		while (j < 8 && groups[j] == 0) {
			++j;
		}
		if (j - i > best_length && j - i >= 2) {
			best = i;
			best_length = j - i;
		}
		i = j == i ? i + 1 : j;
	}
	for (size_t i = 0; i < 8;) {
		if (i == best) {
			out += "::";
			i += best_length;
			continue;
		}
		if (!out.empty() && out.back() != ':') {
			out += ':';
		}
		std::snprintf(text, sizeof(text), "%x", static_cast<unsigned>(groups[i]));
		out += text;
		++i;
	}
	return out;
}

// SubjectAltName ::= GeneralNames, a SEQUENCE OF GeneralName. Only dNSName and
// iPAddress are kept; the other forms are skipped.
X509Result DecodeSubjectAltName(const Element &value, size_t max_entries, X509Certificate &out) {
	Der outer(value.content, value.length);
	Element names;
	if (!outer.Expect(TAG_SEQUENCE, names) || !outer.AtEnd()) {
		return X509Result::MALFORMED;
	}
	Der list(names.content, names.length);
	size_t count = 0;
	while (!list.AtEnd()) {
		Element name;
		if (!list.Next(name)) {
			return X509Result::MALFORMED;
		}
		if (name.tag == TAG_SAN_DNS_NAME) {
			out.san_dns.push_back(
			    EscapeTlsText(std::string(reinterpret_cast<const char *>(name.content), name.length)));
		} else if (name.tag == TAG_SAN_IP_ADDRESS) {
			if (name.length != 4 && name.length != 16) {
				return X509Result::MALFORMED;
			}
			out.san_ip.push_back(FormatIp(name.content, name.length));
		} else {
			continue;
		}
		if (++count > max_entries) {
			return X509Result::OVER_LIMIT;
		}
	}
	return X509Result::OK;
}

X509Result DecodeExtensions(const Element &wrapper, size_t max_san_entries, X509Certificate &out) {
	Der explicit_tag(wrapper.content, wrapper.length);
	Element extensions;
	if (!explicit_tag.Expect(TAG_SEQUENCE, extensions) || !explicit_tag.AtEnd()) {
		return X509Result::MALFORMED;
	}
	bool seen_san = false;
	Der list(extensions.content, extensions.length);
	while (!list.AtEnd()) {
		Element extension, id, value;
		if (!list.Expect(TAG_SEQUENCE, extension)) {
			return X509Result::MALFORMED;
		}
		Der fields(extension.content, extension.length);
		std::string oid;
		if (!fields.Expect(TAG_OID, id) || !DecodeOid(id, oid)) {
			return X509Result::MALFORMED;
		}
		if (fields.PeekTag() == TAG_BOOLEAN) {
			Element critical;
			fields.Next(critical);
		}
		if (!fields.Expect(TAG_OCTET_STRING, value) || !fields.AtEnd()) {
			return X509Result::MALFORMED;
		}
		if (oid == "2.5.29.17") {
			// RFC 5280 4.2: a certificate must not carry an extension twice.
			if (seen_san) {
				return X509Result::MALFORMED;
			}
			seen_san = true;
			const auto result = DecodeSubjectAltName(value, max_san_entries, out);
			if (result != X509Result::OK) {
				return result;
			}
		}
	}
	return X509Result::OK;
}

X509Result Parse(const uint8_t *data, size_t size, size_t max_san_entries, X509Certificate &out) {
	Der top(data, size);
	Element certificate, tbs;
	if (!top.Expect(TAG_SEQUENCE, certificate) || !top.AtEnd()) {
		return X509Result::MALFORMED;
	}
	Der outer(certificate.content, certificate.length);
	if (!outer.Expect(TAG_SEQUENCE, tbs)) {
		return X509Result::MALFORMED;
	}
	// signatureAlgorithm and signatureValue follow; they are framed but not read.
	Element algorithm, signature;
	if (!outer.Expect(TAG_SEQUENCE, algorithm) || !outer.Next(signature) || !outer.AtEnd()) {
		return X509Result::MALFORMED;
	}

	Der fields(tbs.content, tbs.length);
	Element element, serial, validity, issuer, subject;
	if (fields.PeekTag() == TAG_VERSION && !fields.Next(element)) {
		return X509Result::MALFORMED;
	}
	if (!fields.Expect(TAG_INTEGER, serial) || serial.length == 0) {
		return X509Result::MALFORMED;
	}
	out.serial = Hex(serial.content, serial.length);
	if (!fields.Expect(TAG_SEQUENCE, element) || !fields.Next(issuer) || !DecodeName(issuer, out.issuer)) {
		return X509Result::MALFORMED;
	}
	if (!fields.Expect(TAG_SEQUENCE, validity)) {
		return X509Result::MALFORMED;
	}
	Der times(validity.content, validity.length);
	Element not_before, not_after;
	if (!times.Next(not_before) || !times.Next(not_after) || !times.AtEnd() ||
	    !DecodeTime(not_before, out.not_before) || !DecodeTime(not_after, out.not_after)) {
		return X509Result::MALFORMED;
	}
	if (!fields.Next(subject) || !DecodeName(subject, out.subject)) {
		return X509Result::MALFORMED;
	}
	if (!fields.Expect(TAG_SEQUENCE, element)) { // subjectPublicKeyInfo
		return X509Result::MALFORMED;
	}
	for (const uint8_t optional : {TAG_ISSUER_UID, TAG_SUBJECT_UID}) {
		if (fields.PeekTag() == optional && !fields.Next(element)) {
			return X509Result::MALFORMED;
		}
	}
	if (!fields.AtEnd()) {
		if (!fields.Expect(TAG_EXTENSIONS, element) || !fields.AtEnd()) {
			return X509Result::MALFORMED;
		}
		const auto result = DecodeExtensions(element, max_san_entries, out);
		if (result != X509Result::OK) {
			return result;
		}
	}
	return X509Result::OK;
}

} // namespace

X509Result ParseX509Certificate(const uint8_t *data, size_t size, size_t max_san_entries, X509Certificate &out) {
	X509Certificate parsed;
	const auto result = Parse(data, size, max_san_entries, parsed);
	out = result == X509Result::OK ? parsed : X509Certificate();
	return result;
}

} // namespace packetquapture
