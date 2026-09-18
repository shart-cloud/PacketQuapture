# DNS packet queries

`read_dns(path_or_list)` uses the same file/list/glob inputs as `read_packets` and returns its raw,
network, transport, and TCP flag columns, plus the DNS columns below. This schema is experimental.

It emits one row per packet with a decoded TCP/UDP header, either port equal to 53, and a nonempty
captured transport payload. Non-DNS ports, empty TCP acknowledgments, fragmented IP packets, and
packets without complete transport headers are excluded. It does not identify DNS by payload signatures.

```sql
-- Questions, including malformed candidates for inspection when requested separately.
SELECT timestamp, src_ip, dns_question_name, dns_question_type
FROM read_dns('captures/**/*.pcap*')
WHERE dns_valid AND NOT dns_response;

-- NXDOMAIN responses.
SELECT dns_question_name, count(*) AS failures
FROM read_dns('captures/**/*.pcap*')
WHERE dns_response AND dns_rcode = 3
GROUP BY ALL;

-- Expand answer records into rows.
SELECT timestamp, dns_question_name, answer.name, answer.type, answer.value, answer.ttl
FROM (
  SELECT timestamp, dns_question_name, unnest(dns_answers) AS answer
  FROM read_dns('captures/**/*.pcap*')
  WHERE dns_valid AND dns_response
);
```

| Column | Type | Meaning |
| --- | --- | --- |
| `dns_valid` | `BOOLEAN` | Complete message successfully parsed within the documented limits |
| `dns_error` | `VARCHAR` | Diagnostic for invalid/unsupported messages; null on success |
| `dns_id` | `USMALLINT` | Transaction ID |
| `dns_response` | `BOOLEAN` | QR bit: response versus query |
| `dns_opcode` | `UTINYINT` | Four-bit opcode |
| `dns_rcode` | `UTINYINT` | Four-bit response code from the base DNS header; excludes EDNS extended codes |
| `dns_truncated` | `BOOLEAN` | TC bit from the DNS header; distinct from capture truncation |
| `dns_question_name` | `VARCHAR` | First question's name; null if there are no questions |
| `dns_question_type`, `dns_question_class` | `USMALLINT` | First question's numeric type and class |
| `dns_questions` | `STRUCT(name VARCHAR, type USMALLINT, class USMALLINT)[]` | All questions |
| `dns_answers`, `dns_authorities`, `dns_additionals` | See below | Resource records in wire order |

Resource-record lists contain `STRUCT(name VARCHAR, type USMALLINT, class USMALLINT, ttl UINTEGER,
value VARCHAR, data BLOB)`. `value` presents IN-class A/AAAA addresses and NS/CNAME/PTR names as text.
Other record types retain their original RDATA in `data` with a null `value`. Compressed RDATA pointers
are relative to the original DNS message; the raw capture columns preserve that context.

Names preserve case and omit the trailing root dot, except the root itself is `.`. Dot, backslash,
non-printable, and non-ASCII label octets use decimal `\DDD` escapes to produce valid, unambiguous text.
Use `lower(dns_question_name)` when case-insensitive matching is desired.

For messages split across TCP packets, use [`read_dns_messages`](DNS_REASSEMBLY.md). That separate
function reconstructs streams and emits message rows, with explicit gap/conflict diagnostics and resource bounds.

## Malformed input and scope

Invalid DNS candidate packets remain visible with `dns_valid = false`, a `dns_error`, and null DNS fields.
Their raw and lower-layer columns remain available. `count(*)` counts candidate packets, including invalid
ones; use `WHERE dns_valid` to count successfully parsed messages. Raw capture-framing errors still raise errors.

UDP requires the whole declared datagram payload to be captured. TCP requires exactly one complete
length-prefixed DNS message in the packet payload. Split messages, multiple messages in one TCP packet,
stream alignment, retransmission deduplication, and TCP/IP reassembly are not implemented. Encrypted DNS,
mDNS, DNS on alternate ports, DNSSEC validation, and EDNS interpretation are outside this first version.
A structurally complete TC response is decoded; physically incomplete records are marked invalid.

Compression pointers are checked for bounds and must reference prior bytes outside the fixed DNS header.
Labels are limited to 63 bytes, expanded names to 255 wire bytes, pointer/label walks to 128 steps per name,
and messages to 65,535 bytes and 4,096 total questions/resource records. A total name-walk work budget
also bounds CPU consumption. Messages over these limits are reported as invalid.

## Projection and filtering

Queries of only packet/transport metadata classify candidates using headers and skip DNS payloads.
Requesting or filtering any DNS field parses the full DNS message, so validation stays consistent across
projections. Earlier metadata/IP/port/TCP filters run before DNS parsing. DNS filters run before any
remaining bytes needed for `packet_data` are read. DNS parsing necessarily reads the DNS payload itself.

The generated fixtures and standalone sanitizer tests use independently constructed messages based on
[RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) and
[RFC 3596](https://www.rfc-editor.org/rfc/rfc3596), with no captured user traffic.

```sh
python3 scripts/generate_dns_captures.py
./build/release/test/unittest 'test/sql/*'
c++ -std=c++17 -Wall -Wextra -Werror -g -O1 \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  -Isrc/include src/dns_decoder.cpp test/unit/dns_decoder_test.cpp \
  -o build/dns_decoder_test
./build/dns_decoder_test
```