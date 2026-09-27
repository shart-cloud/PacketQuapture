#include "x509_certificate.hpp"

#include "tls_record.hpp"

#include <cstdio>

namespace packetquapture {
namespace {

const uint8_t TAG_BOOLEAN = 0x01;
const uint8_t TAG_INTEGER = 0x02;
const uint8_t TAG_BIT_STRING = 0x03;
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
const uint8_t TAG_URI = 0x86;            // GeneralName [6] IMPLICIT IA5String
const uint8_t TAG_CONTEXT_0 = 0x80;      // [0] IMPLICIT, primitive
const uint8_t TAG_CONTEXT_0_SET = 0xA0;  // [0], constructed

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

// An arc wider than 64 bits as decimal, from its base-128 digits. UUID-based
// OIDs (2.25, RFC 4122) carry 128-bit arcs.
std::string WideArc(const uint8_t *digits, size_t count) {
	std::vector<uint8_t> decimal(1, 0); // least significant first
	for (size_t i = 0; i < count; ++i) {
		unsigned carry = digits[i] & 0x7FU;
		for (auto &digit : decimal) {
			const unsigned value = digit * 128U + carry;
			digit = static_cast<uint8_t>(value % 10);
			carry = value / 10;
		}
		for (; carry != 0; carry /= 10) {
			decimal.push_back(static_cast<uint8_t>(carry % 10));
		}
	}
	std::string out;
	for (auto it = decimal.rbegin(); it != decimal.rend(); ++it) {
		out += static_cast<char>('0' + *it);
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
		// Past 63 bits an arc is kept as decimal text, up to 140 bits; the
		// first, which also encodes the top arc, must fit.
		if (++digits > 20 || (first && digits > 9)) {
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
			out += "." + (digits > 9 ? WideArc(element.content + i + 1 - digits, digits) : std::to_string(value));
		}
		value = 0;
		digits = 0;
	}
	return true;
}

// An OID and the name it is given.
struct Named {
	const char *oid, *name;
};

// The entry for oid in a table whose entries begin with their OID, or nullptr.
template <class T, size_t N>
const T *Find(const T (&table)[N], const std::string &oid) {
	for (const auto &entry : table) {
		if (oid == entry.oid) {
			return &entry;
		}
	}
	return nullptr;
}

template <size_t N>
const char *Lookup(const Named (&table)[N], const std::string &oid) {
	const Named *entry = Find(table, oid);
	return entry != nullptr ? entry->name : nullptr;
}

// RFC 4514 section 3 lists the names every implementation must know. It allows
// other registered names; for those this uses the spelling OpenSSL prints with
// -nameopt RFC2253, so the two can be compared. Anything else is a dotted OID.
const char *ShortName(const std::string &oid) {
	static const Named names[] = {
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
	return Lookup(names, oid);
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
void AppendOid(const Element &oid, std::string &list) {
	if (!list.empty()) {
		list += ',';
	}
	list += Hex(oid.content, oid.length);
}

bool DecodeName(const Element &name, std::string &out, std::string &types) {
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
			AppendOid(type, types);
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

} // namespace

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

namespace {

// Algorithm and curve names as `openssl x509 -text` prints them, which is
// OpenSSL's long name for each object, each checked against OpenSSL 3.0.13. An
// algorithm outside this table is its dotted OID, even where OpenSSL has a name.
const char *AlgorithmName(const std::string &oid) {
	static const Named names[] = {
	    {"1.2.840.113549.1.1.1", "rsaEncryption"},
	    {"1.2.840.113549.1.1.2", "md2WithRSAEncryption"},
	    {"1.2.840.113549.1.1.3", "md4WithRSAEncryption"},
	    {"1.2.840.113549.1.1.4", "md5WithRSAEncryption"},
	    {"1.2.840.113549.1.1.5", "sha1WithRSAEncryption"},
	    {"1.2.840.113549.1.1.7", "rsaesOaep"},
	    {"1.2.840.113549.1.1.10", "rsassaPss"},
	    {"1.2.840.113549.1.1.11", "sha256WithRSAEncryption"},
	    {"1.2.840.113549.1.1.12", "sha384WithRSAEncryption"},
	    {"1.2.840.113549.1.1.13", "sha512WithRSAEncryption"},
	    {"1.2.840.113549.1.1.14", "sha224WithRSAEncryption"},
	    {"1.2.840.113549.1.1.15", "sha512-224WithRSAEncryption"},
	    {"1.2.840.113549.1.1.16", "sha512-256WithRSAEncryption"},
	    {"1.3.14.3.2.29", "sha1WithRSA"},
	    {"1.3.36.3.3.1.2", "ripemd160WithRSA"},
	    {"2.16.840.1.101.3.4.3.13", "RSA-SHA3-224"},
	    {"2.16.840.1.101.3.4.3.14", "RSA-SHA3-256"},
	    {"2.16.840.1.101.3.4.3.15", "RSA-SHA3-384"},
	    {"2.16.840.1.101.3.4.3.16", "RSA-SHA3-512"},
	    {"1.2.840.10040.4.1", "dsaEncryption"},
	    {"1.2.840.10040.4.3", "dsaWithSHA1"},
	    {"2.16.840.1.101.3.4.3.1", "dsa_with_SHA224"},
	    {"2.16.840.1.101.3.4.3.2", "dsa_with_SHA256"},
	    {"2.16.840.1.101.3.4.3.3", "dsa_with_SHA384"},
	    {"2.16.840.1.101.3.4.3.4", "dsa_with_SHA512"},
	    {"1.2.840.10045.2.1", "id-ecPublicKey"},
	    {"1.2.840.10045.4.1", "ecdsa-with-SHA1"},
	    {"1.2.840.10045.4.2", "ecdsa-with-Recommended"},
	    {"1.2.840.10045.4.3.1", "ecdsa-with-SHA224"},
	    {"1.2.840.10045.4.3.2", "ecdsa-with-SHA256"},
	    {"1.2.840.10045.4.3.3", "ecdsa-with-SHA384"},
	    {"1.2.840.10045.4.3.4", "ecdsa-with-SHA512"},
	    {"2.16.840.1.101.3.4.3.9", "ecdsa_with_SHA3-224"},
	    {"2.16.840.1.101.3.4.3.10", "ecdsa_with_SHA3-256"},
	    {"2.16.840.1.101.3.4.3.11", "ecdsa_with_SHA3-384"},
	    {"2.16.840.1.101.3.4.3.12", "ecdsa_with_SHA3-512"},
	    {"1.2.156.10197.1.501", "SM2-with-SM3"},
	    {"1.2.643.7.1.1.1.1", "GOST R 34.10-2012 with 256 bit modulus"},
	    {"1.2.643.7.1.1.1.2", "GOST R 34.10-2012 with 512 bit modulus"},
	    {"1.2.643.7.1.1.3.2", "GOST R 34.10-2012 with GOST R 34.11-2012 (256 bit)"},
	    {"1.2.643.7.1.1.3.3", "GOST R 34.10-2012 with GOST R 34.11-2012 (512 bit)"},
	    {"1.3.101.110", "X25519"},
	    {"1.3.101.111", "X448"},
	    {"1.3.101.112", "ED25519"},
	    {"1.3.101.113", "ED448"},
	};
	return Lookup(names, oid);
}

// Named curves as OpenSSL's ASN1 OID line prints them, and their sizes.
struct NamedCurve {
	const char *oid, *name;
	uint32_t bits;
};

const NamedCurve *FindCurve(const std::string &oid) {
	static const NamedCurve curves[] = {
	    {"1.2.840.10045.3.1.1", "prime192v1", 192},
	    {"1.3.132.0.33", "secp224r1", 224},
	    {"1.2.840.10045.3.1.7", "prime256v1", 256},
	    {"1.3.132.0.34", "secp384r1", 384},
	    {"1.3.132.0.35", "secp521r1", 521},
	    {"1.3.132.0.10", "secp256k1", 256},
	    {"1.3.36.3.3.2.8.1.1.7", "brainpoolP256r1", 256},
	    {"1.3.36.3.3.2.8.1.1.11", "brainpoolP384r1", 384},
	    {"1.3.36.3.3.2.8.1.1.13", "brainpoolP512r1", 512},
	    {"1.2.156.10197.1.301", "SM2", 256},
	};
	return Find(curves, oid);
}

// RFC 5280 4.2.1.12 and the purposes CAs commonly assert beside them.
const char *PurposeName(const std::string &oid) {
	static const Named names[] = {
	    {"2.5.29.37.0", "anyExtendedKeyUsage"},   {"1.3.6.1.5.5.7.3.1", "serverAuth"},
	    {"1.3.6.1.5.5.7.3.2", "clientAuth"},      {"1.3.6.1.5.5.7.3.3", "codeSigning"},
	    {"1.3.6.1.5.5.7.3.4", "emailProtection"}, {"1.3.6.1.5.5.7.3.8", "timeStamping"},
	    {"1.3.6.1.5.5.7.3.9", "OCSPSigning"},
	};
	return Lookup(names, oid);
}

// The name OpenSSL prints for an AlgorithmIdentifier's algorithm, or its dotted
// OID. False, with nothing set, when the OID cannot be read.
bool AlgorithmOf(const Element &identifier, std::string &oid, std::string &out) {
	Der fields(identifier.content, identifier.length);
	Element id;
	if (!fields.Expect(TAG_OID, id) || !DecodeOid(id, oid)) {
		return false;
	}
	const char *name = AlgorithmName(oid);
	out = name != nullptr ? name : oid;
	return true;
}

// Significant bits of a DER INTEGER's magnitude, as OpenSSL's BN_num_bits.
uint32_t IntegerBits(const Element &integer) {
	size_t i = 0;
	while (i < integer.length && integer.content[i] == 0) {
		++i;
	}
	if (i == integer.length) {
		return 0;
	}
	uint32_t bits = static_cast<uint32_t>((integer.length - i - 1) * 8);
	for (uint8_t top = integer.content[i]; top != 0; top >>= 1U) {
		++bits;
	}
	return bits;
}

// SubjectPublicKeyInfo: the algorithm, and the key's size where it has one.
// Describing the key is an addition to the certificate, so anything here that
// does not parse leaves these fields unknown and the certificate as it was.
void DecodePublicKey(const Element &info, X509Certificate &out) {
	Der fields(info.content, info.length);
	Element algorithm, key;
	std::string oid;
	if (!fields.Expect(TAG_SEQUENCE, algorithm) || !fields.Expect(TAG_BIT_STRING, key) ||
	    !AlgorithmOf(algorithm, oid, out.public_key_algorithm)) {
		return;
	}
	Der parameters(algorithm.content, algorithm.length);
	Element skipped, parameter;
	parameters.Next(skipped);
	const bool has_parameter = !parameters.AtEnd() && parameters.Next(parameter);
	if (oid == "1.2.840.10045.2.1") {
		std::string curve;
		if (has_parameter && parameter.tag == TAG_OID && DecodeOid(parameter, curve)) {
			const NamedCurve *known = FindCurve(curve);
			out.public_key_curve = known != nullptr ? known->name : curve;
			out.public_key_bits = known != nullptr ? known->bits : 0;
		} else if (has_parameter && parameter.tag == TAG_SEQUENCE) {
			// RFC 3279 ECParameters, spelled out: version, fieldID, curve, base,
			// order. The curve has no name; its size is the order's, as OpenSSL
			// reports it. Legitimate CAs do not issue such keys.
			Der values(parameter.content, parameter.length);
			Element version, field, shape, base, order;
			if (values.Expect(TAG_INTEGER, version) && values.Expect(TAG_SEQUENCE, field) &&
			    values.Expect(TAG_SEQUENCE, shape) && values.Expect(TAG_OCTET_STRING, base) &&
			    values.Expect(TAG_INTEGER, order)) {
				out.public_key_bits = IntegerBits(order);
			}
		}
	} else if (oid == "1.2.840.10040.4.1") {
		Element prime;
		if (has_parameter && parameter.tag == TAG_SEQUENCE) {
			Der values(parameter.content, parameter.length);
			if (values.Expect(TAG_INTEGER, prime)) {
				out.public_key_bits = IntegerBits(prime);
			}
		}
	} else if ((oid == "1.2.840.113549.1.1.1" || oid == "1.2.840.113549.1.1.10") && key.length > 1 &&
	           key.content[0] == 0) {
		// rsaEncryption and RSASSA-PSS keys share the RSAPublicKey body.
		Der body(key.content + 1, key.length - 1);
		Element sequence, modulus;
		if (body.Expect(TAG_SEQUENCE, sequence)) {
			Der values(sequence.content, sequence.length);
			if (values.Expect(TAG_INTEGER, modulus)) {
				out.public_key_bits = IntegerBits(modulus);
			}
		}
	}
}

// basicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE,
//                                 pathLenConstraint INTEGER (0..MAX) OPTIONAL }
bool DecodeBasicConstraints(const Element &value, X509Certificate &out) {
	Der outer(value.content, value.length);
	Element sequence, element;
	if (!outer.Expect(TAG_SEQUENCE, sequence) || !outer.AtEnd()) {
		return false;
	}
	Der fields(sequence.content, sequence.length);
	out.has_basic_constraints = true;
	if (fields.PeekTag() == TAG_BOOLEAN) {
		if (!fields.Next(element) || element.length != 1) {
			return false;
		}
		out.is_ca = element.content[0] != 0;
	}
	if (fields.PeekTag() == TAG_INTEGER) {
		// Non-negative, and small enough for a UINTEGER after any sign octet.
		if (!fields.Next(element) || element.length == 0 || (element.content[0] & 0x80U) ||
		    element.length - (element.content[0] == 0 ? 1 : 0) > 4) {
			return false;
		}
		uint64_t length = 0;
		for (size_t i = 0; i < element.length; ++i) {
			length = (length << 8U) | element.content[i];
		}
		out.has_path_length = true;
		out.path_length = static_cast<uint32_t>(length);
	}
	return fields.AtEnd();
}

// keyUsage ::= BIT STRING, bit 0 first.
bool DecodeKeyUsage(const Element &value, X509Certificate &out) {
	static const char *const bits[] = {"digitalSignature", "nonRepudiation", "keyEncipherment",
	                                   "dataEncipherment", "keyAgreement",   "keyCertSign",
	                                   "cRLSign",          "encipherOnly",   "decipherOnly"};
	Der outer(value.content, value.length);
	Element string;
	if (!outer.Expect(TAG_BIT_STRING, string) || !outer.AtEnd() || string.length == 0 || string.content[0] > 7 ||
	    (string.length == 1 && string.content[0] != 0)) {
		return false;
	}
	const size_t unused = string.content[0];
	const size_t total = (string.length - 1) * 8 - unused;
	out.has_key_usage = true;
	for (size_t bit = 0; bit < total && bit < sizeof(bits) / sizeof(bits[0]); ++bit) {
		if (string.content[1 + bit / 8] & (0x80U >> (bit % 8))) {
			out.key_usage.push_back(bits[bit]);
		}
	}
	return true;
}

// ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
X509Result DecodeExtendedKeyUsage(const Element &value, size_t max_entries, X509Certificate &out) {
	Der outer(value.content, value.length);
	Element sequence;
	if (!outer.Expect(TAG_SEQUENCE, sequence) || !outer.AtEnd()) {
		return X509Result::MALFORMED;
	}
	Der list(sequence.content, sequence.length);
	out.has_extended_key_usage = true;
	while (!list.AtEnd()) {
		Element id;
		std::string oid;
		if (!list.Expect(TAG_OID, id) || !DecodeOid(id, oid)) {
			return X509Result::MALFORMED;
		}
		if (out.extended_key_usage.size() >= max_entries) {
			return X509Result::OVER_LIMIT;
		}
		const char *name = PurposeName(oid);
		out.extended_key_usage.push_back(name != nullptr ? name : oid);
	}
	return out.extended_key_usage.empty() ? X509Result::MALFORMED : X509Result::OK;
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

// subjectKeyIdentifier ::= KeyIdentifier, an OCTET STRING.
bool DecodeSubjectKeyId(const Element &value, X509Certificate &out) {
	Der outer(value.content, value.length);
	Element id;
	if (!outer.Expect(TAG_OCTET_STRING, id) || !outer.AtEnd() || id.length == 0) {
		return false;
	}
	out.subject_key_id = Hex(id.content, id.length);
	return true;
}

// AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] OPTIONAL,
//     authorityCertIssuer [1] OPTIONAL, authorityCertSerialNumber [2] OPTIONAL }
// Only the key identifier is kept; the others must still be in order.
bool DecodeAuthorityKeyId(const Element &value, X509Certificate &out) {
	Der outer(value.content, value.length);
	Element sequence;
	if (!outer.Expect(TAG_SEQUENCE, sequence) || !outer.AtEnd()) {
		return false;
	}
	Der fields(sequence.content, sequence.length);
	int last = -1;
	while (!fields.AtEnd()) {
		Element field;
		// [0] and [2] are primitive, [1] (GeneralNames) constructed.
		static const uint8_t tags[] = {0x80, 0xA1, 0x82};
		if (!fields.Next(field) || (field.tag & 0x1FU) > 2 || field.tag != tags[field.tag & 0x1FU] ||
		    static_cast<int>(field.tag & 0x1FU) <= last) {
			return false;
		}
		last = field.tag & 0x1FU;
		if (field.tag == TAG_CONTEXT_0) {
			if (field.length == 0) {
				return false;
			}
			out.authority_key_id = Hex(field.content, field.length);
		}
	}
	return true;
}

// The URIs among a run of GeneralNames, escaped. Other forms are skipped. For
// these lists, more than max_entries is not a limit on the certificate: the
// extensions only add fields, so the list alone is left unknown.
X509Result GeneralNameUris(Der &names, size_t max_entries, std::vector<std::string> &out) {
	while (!names.AtEnd()) {
		Element name;
		if (!names.Next(name)) {
			return X509Result::MALFORMED;
		}
		if (name.tag != TAG_URI) {
			continue;
		}
		if (out.size() >= max_entries) {
			return X509Result::OVER_LIMIT;
		}
		out.push_back(EscapeTlsText(std::string(reinterpret_cast<const char *>(name.content), name.length)));
	}
	return X509Result::OK;
}

// AuthorityInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription.
// An empty list is read as present and empty, as OpenSSL reads it; so for the
// CRL distribution points and policies below.
// AccessDescription ::= SEQUENCE { accessMethod OID, accessLocation GeneralName }
X509Result DecodeAuthorityInfoAccess(const Element &value, size_t max_entries, X509Certificate &out) {
	Der outer(value.content, value.length);
	Element sequence;
	if (!outer.Expect(TAG_SEQUENCE, sequence) || !outer.AtEnd()) {
		return X509Result::MALFORMED;
	}
	Der list(sequence.content, sequence.length);
	out.has_authority_info_access = true;
	while (!list.AtEnd()) {
		Element description, method;
		std::string oid;
		if (!list.Expect(TAG_SEQUENCE, description)) {
			return X509Result::MALFORMED;
		}
		Der fields(description.content, description.length);
		Element location;
		if (!fields.Expect(TAG_OID, method) || !DecodeOid(method, oid) || !fields.Next(location) || !fields.AtEnd()) {
			return X509Result::MALFORMED;
		}
		auto *target = oid == "1.3.6.1.5.5.7.48.1"   ? &out.ocsp_urls
		               : oid == "1.3.6.1.5.5.7.48.2" ? &out.ca_issuers_urls
		                                             : nullptr;
		if (target == nullptr || location.tag != TAG_URI) {
			continue;
		}
		if (target->size() >= max_entries) {
			return X509Result::OVER_LIMIT;
		}
		target->push_back(
		    EscapeTlsText(std::string(reinterpret_cast<const char *>(location.content), location.length)));
	}
	return X509Result::OK;
}

// CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
// DistributionPoint ::= SEQUENCE { distributionPoint [0] DistributionPointName
//     OPTIONAL, reasons [1] OPTIONAL, cRLIssuer [2] OPTIONAL }
// DistributionPointName ::= CHOICE { fullName [0] GeneralNames,
//     nameRelativeToCRLIssuer [1] }
// Only URIs in a fullName are kept.
X509Result DecodeCrlDistributionPoints(const Element &value, size_t max_entries, X509Certificate &out) {
	Der outer(value.content, value.length);
	Element sequence;
	if (!outer.Expect(TAG_SEQUENCE, sequence) || !outer.AtEnd()) {
		return X509Result::MALFORMED;
	}
	Der list(sequence.content, sequence.length);
	out.has_crl_distribution_points = true;
	while (!list.AtEnd()) {
		Element point, name;
		if (!list.Expect(TAG_SEQUENCE, point)) {
			return X509Result::MALFORMED;
		}
		Der fields(point.content, point.length);
		if (fields.PeekTag() != TAG_CONTEXT_0_SET) {
			continue;
		}
		Element wrapper;
		if (!fields.Next(wrapper)) {
			return X509Result::MALFORMED;
		}
		Der choice(wrapper.content, wrapper.length);
		if (!choice.Next(name) || !choice.AtEnd()) {
			return X509Result::MALFORMED;
		}
		if (name.tag != TAG_CONTEXT_0_SET) {
			continue;
		}
		Der names(name.content, name.length);
		const auto result = GeneralNameUris(names, max_entries, out.crl_urls);
		if (result != X509Result::OK) {
			return result;
		}
	}
	return X509Result::OK;
}

// certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
// PolicyInformation ::= SEQUENCE { policyIdentifier OID, policyQualifiers OPTIONAL }
X509Result DecodePolicies(const Element &value, size_t max_entries, X509Certificate &out) {
	Der outer(value.content, value.length);
	Element sequence;
	if (!outer.Expect(TAG_SEQUENCE, sequence) || !outer.AtEnd()) {
		return X509Result::MALFORMED;
	}
	Der list(sequence.content, sequence.length);
	out.has_policies = true;
	while (!list.AtEnd()) {
		Element information, id;
		std::string oid;
		if (!list.Expect(TAG_SEQUENCE, information)) {
			return X509Result::MALFORMED;
		}
		Der fields(information.content, information.length);
		Element qualifiers;
		if (!fields.Expect(TAG_OID, id) || !DecodeOid(id, oid) ||
		    (!fields.AtEnd() && (!fields.Expect(TAG_SEQUENCE, qualifiers) || !fields.AtEnd()))) {
			return X509Result::MALFORMED;
		}
		if (out.policies.size() >= max_entries) {
			return X509Result::OVER_LIMIT;
		}
		out.policies.push_back(oid);
	}
	return X509Result::OK;
}

X509Result DecodeExtensions(const Element &wrapper, size_t max_entries, X509Certificate &out) {
	Der explicit_tag(wrapper.content, wrapper.length);
	Element extensions;
	if (!explicit_tag.Expect(TAG_SEQUENCE, extensions) || !explicit_tag.AtEnd()) {
		return X509Result::MALFORMED;
	}
	// RFC 5280 4.2: a certificate must not carry an extension twice. A second
	// subjectAltName makes the certificate malformed, as it always has. The
	// other extensions read here only add fields, so a malformed or repeated
	// one leaves its field unknown instead.
	bool seen_san = false;
	size_t basic_copies = 0, usage_copies = 0, purpose_copies = 0, subject_id_copies = 0, authority_id_copies = 0,
	       access_copies = 0, crl_copies = 0, policy_copies = 0;
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
		AppendOid(id, out.extension_oids);
		if (fields.PeekTag() == TAG_BOOLEAN) {
			Element critical;
			fields.Next(critical);
		}
		if (!fields.Expect(TAG_OCTET_STRING, value) || !fields.AtEnd()) {
			return X509Result::MALFORMED;
		}
		if (oid == "2.5.29.17") {
			if (seen_san) {
				return X509Result::MALFORMED;
			}
			seen_san = true;
			const auto result = DecodeSubjectAltName(value, max_entries, out);
			if (result != X509Result::OK) {
				return result;
			}
		} else if (oid == "2.5.29.19") {
			if (++basic_copies > 1 || !DecodeBasicConstraints(value, out)) {
				out.has_basic_constraints = out.is_ca = out.has_path_length = false;
				out.path_length = 0;
			}
		} else if (oid == "2.5.29.15") {
			if (++usage_copies > 1 || !DecodeKeyUsage(value, out)) {
				out.has_key_usage = false;
				out.key_usage.clear();
			}
		} else if (oid == "2.5.29.37") {
			// Too many purposes is a limit, as too many names is: it bounds memory.
			const auto result =
			    ++purpose_copies > 1 ? X509Result::MALFORMED : DecodeExtendedKeyUsage(value, max_entries, out);
			if (result == X509Result::OVER_LIMIT) {
				return result;
			}
			if (result != X509Result::OK) {
				out.has_extended_key_usage = false;
				out.extended_key_usage.clear();
			}
		} else if (oid == "2.5.29.14") {
			if (++subject_id_copies > 1 || !DecodeSubjectKeyId(value, out)) {
				out.subject_key_id.clear();
			}
		} else if (oid == "2.5.29.35") {
			if (++authority_id_copies > 1 || !DecodeAuthorityKeyId(value, out)) {
				out.authority_key_id.clear();
			}
		} else if (oid == "1.3.6.1.5.5.7.1.1") {
			const auto result =
			    ++access_copies > 1 ? X509Result::MALFORMED : DecodeAuthorityInfoAccess(value, max_entries, out);
			if (result != X509Result::OK) {
				out.has_authority_info_access = false;
				out.ocsp_urls.clear();
				out.ca_issuers_urls.clear();
			}
		} else if (oid == "2.5.29.31") {
			const auto result =
			    ++crl_copies > 1 ? X509Result::MALFORMED : DecodeCrlDistributionPoints(value, max_entries, out);
			if (result != X509Result::OK) {
				out.has_crl_distribution_points = false;
				out.crl_urls.clear();
			}
		} else if (oid == "2.5.29.32") {
			const auto result = ++policy_copies > 1 ? X509Result::MALFORMED : DecodePolicies(value, max_entries, out);
			if (result != X509Result::OK) {
				out.has_policies = false;
				out.policies.clear();
			}
		}
	}
	return X509Result::OK;
}

X509Result Parse(const uint8_t *data, size_t size, size_t max_entries, X509Certificate &out) {
	Der top(data, size);
	Element certificate, tbs;
	if (!top.Expect(TAG_SEQUENCE, certificate) || !top.AtEnd()) {
		return X509Result::MALFORMED;
	}
	Der outer(certificate.content, certificate.length);
	if (!outer.Expect(TAG_SEQUENCE, tbs)) {
		return X509Result::MALFORMED;
	}
	// signatureAlgorithm and signatureValue follow. The value is framed but not
	// read, since nothing is verified.
	Element algorithm, signature;
	std::string signature_oid;
	if (!outer.Expect(TAG_SEQUENCE, algorithm) || !outer.Next(signature) || !outer.AtEnd()) {
		return X509Result::MALFORMED;
	}
	// Naming the algorithm adds a field; an OID that cannot be read leaves it unknown.
	AlgorithmOf(algorithm, signature_oid, out.signature_algorithm);

	Der fields(tbs.content, tbs.length);
	Element element, serial, validity, issuer, subject;
	if (fields.PeekTag() == TAG_VERSION && !fields.Next(element)) {
		return X509Result::MALFORMED;
	}
	if (!fields.Expect(TAG_INTEGER, serial) || serial.length == 0) {
		return X509Result::MALFORMED;
	}
	out.serial = Hex(serial.content, serial.length);
	if (!fields.Expect(TAG_SEQUENCE, element) || !fields.Next(issuer) ||
	    !DecodeName(issuer, out.issuer, out.issuer_oids)) {
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
	if (!fields.Next(subject) || !DecodeName(subject, out.subject, out.subject_oids)) {
		return X509Result::MALFORMED;
	}
	if (!fields.Expect(TAG_SEQUENCE, element)) { // subjectPublicKeyInfo
		return X509Result::MALFORMED;
	}
	DecodePublicKey(element, out);
	for (const uint8_t optional : {TAG_ISSUER_UID, TAG_SUBJECT_UID}) {
		if (fields.PeekTag() == optional && !fields.Next(element)) {
			return X509Result::MALFORMED;
		}
	}
	if (!fields.AtEnd()) {
		if (!fields.Expect(TAG_EXTENSIONS, element) || !fields.AtEnd()) {
			return X509Result::MALFORMED;
		}
		const auto result = DecodeExtensions(element, max_entries, out);
		if (result != X509Result::OK) {
			return result;
		}
	}
	return X509Result::OK;
}

} // namespace

X509Result ParseX509Certificate(const uint8_t *data, size_t size, size_t max_entries, X509Certificate &out) {
	X509Certificate parsed;
	const auto result = Parse(data, size, max_entries, parsed);
	out = result == X509Result::OK ? parsed : X509Certificate();
	return result;
}

} // namespace packetquapture
