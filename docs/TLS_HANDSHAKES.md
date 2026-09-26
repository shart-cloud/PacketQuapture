# Reassembled TLS handshakes

`read_tls(path_or_list)` returns one row per TLS handshake, pairing the two directions of a
connection so the name the client offered and the parameters the server selected arrive
together. It accepts PCAP/PCAPNG files, lists, and globs.

`read_packets` remains the per-packet layer: it marks TLS records and recovers an SNI that
fits in one packet. Use it to narrow a capture cheaply; use `read_tls` when the answer needs
bytes from more than one packet.

```sql
SELECT client_ip, server_ip, tls_sni, negotiated_version, cipher_suite
FROM read_tls('captures/**/*.pcap*')
WHERE reassembly_status = 'complete';

SELECT filename, client_ip, server_ip, reassembly_status
FROM read_tls('captures/**/*.pcap*')
WHERE reassembly_status <> 'complete';
```

The shared [protocol-independent TCP engine](TCP_STREAMS.md) performs sequence ordering,
retransmission handling, overlap checks, and resource accounting. TLS adds a handshake reader
over its output, in the same place [DNS framing](DNS_REASSEMBLY.md) sits.

## One row per handshake

`read_dns_messages` reports one row per message per direction. `read_tls` does not: a
handshake is only meaningful as an exchange, so the client and server sides are joined into
one row. That is a different shape, and it needs rules the DNS reader never had.

- **The key is oriented client to server**, whichever direction was captured. A capture that
  saw only the server's replies still reports `client_ip` as the client. Rows from
  one-directional and two-directional captures therefore line up in the same report.
- **A handshake with only one side captured is still reported**, with the missing side's
  columns NULL and `reassembly_status` of `one-sided`. One direction is often all that was
  recorded, and dropping it would hide the connection entirely.
- **Renegotiation in the clear produces a row per handshake**, numbered by
  `handshake_number` within the connection. The nth ClientHello is answered by the nth
  ServerHello. After TLS 1.3, and after `change_cipher_spec` in earlier versions,
  renegotiation is encrypted and invisible here.
- **Parsing stops at `change_cipher_spec`.** Records after it are encrypted, and reading them
  as handshake bytes would invent handshakes that never happened.
- **A connection never spans files.** Directions still unpaired when a file ends are reported
  against that file.
- **Reusing an address pair starts a new connection.** If the same direction is seen twice
  for one tuple, the earlier one is reported rather than merged into the later.

## Columns

| Column | Meaning |
| --- | --- |
| `client_ip`, `server_ip`, `client_port`, `server_port` | Endpoints, oriented client to server. |
| `client_stream_id`, `server_stream_id` | Scan-local stream ids. NULL when that direction was not captured. |
| `handshake_number` | 1 for the first handshake of a connection, incrementing on renegotiation. |
| `first_packet_number`, `last_packet_number`, `first_timestamp`, `last_timestamp` | Provenance of the packets carrying the handshake. |
| `client_hello`, `server_hello` | Whether each side was seen. |
| `tls_sni` | `host_name` from the ClientHello's `server_name` extension, complete across segments. Escaped as in `read_packets`: bytes outside printable ASCII, and backslash, become decimal `\DDD`. |
| `client_version` | `legacy_version` from the ClientHello, a compatibility value. |
| `negotiated_version` | `supported_versions` from the ServerHello when present, otherwise its `legacy_version`. This is why a TLS 1.3 connection reports 0x0304 rather than the 0x0303 in its record headers. NULL when the ServerHello's `supported_versions` is malformed (not exactly one version, or sent twice), since `legacy_version` would then misreport TLS 1.3 as 1.2; `ja4s` is NULL with it and `server_list_malformed` is set. |
| `cipher_suite` | The suite the server selected. |
| `session_resumed` | See below. |
| `reassembly_status`, `reassembly_error` | See below. |
| `vlan_ids` | VLAN tags of the connection. |
| `client_cipher_suites`, `client_extensions` | Cipher suites and extension types from the ClientHello, in wire order. |
| `client_supported_groups`, `client_signature_algorithms`, `client_supported_versions` | Code points from those ClientHello extensions, in wire order. |
| `client_ec_point_formats` | `ec_point_formats` from the ClientHello, `LIST(UTINYINT)`. |
| `client_alpn` | Protocols the client offered, escaped as `tls_sni` is. |
| `server_extensions` | Extension types from the ServerHello, in wire order. |
| `server_alpn` | The protocol the server selected. Always NULL for TLS 1.3, which sends it encrypted. |
| `*_no_grease` | The same list without RFC 8701 GREASE values. |
| `warnings` | See below. |
| `ja3`, `ja3_full` | JA3 client fingerprint and the string it hashes. See below. |
| `ja3s`, `ja3s_full` | JA3S server fingerprint and the string it hashes. |
| `ja4`, `ja4_r` | JA4 client fingerprint and its raw form. See below. |
| `ja4s`, `ja4s_r` | JA4S server fingerprint and its raw form. **FoxIO License 1.1**, see [NOTICE](../NOTICE). |
| `server_certificates` | The server's certificate chain, a `LIST(STRUCT)` with the fields below, leaf first. NULL when no Certificate message was read, which includes every TLS 1.3 handshake. See below. |
| `client_certificates` | The client's certificates, the same type, when the server asked for them in TLS 1.2 or earlier. `[]` when the client was asked and had none; NULL when it sent no Certificate message. |
| `tunnel` | `STRUCT(protocol, destination, client_prefix_bytes, server_prefix_bytes)` when bytes came before TLS in a captured direction, such as a SOCKS or HTTP CONNECT exchange or a STARTTLS upgrade; NULL when TLS began every captured stream. See below. |

## Hello lists

Every list is published in wire order with GREASE values included, and again with the
suffix `_no_grease` without them. Both forms are kept on purpose. Fingerprint formats
filter GREASE, but whether a client sends GREASE at all is itself evidence. RFC 8701
reserves the values 0x0A0A, 0x1A1A, and so on up to 0xFAFA for cipher suites,
extensions, named groups, signature algorithms, versions and, as two raw bytes, ALPN.
EC point formats have no GREASE values and no twin.

NULL and an empty list mean different things:

- **NULL:** the hello did not carry the list, its side was not captured, or the list
  was malformed.
- **`[]`:** the peer sent an empty list.

A hello that parsed always has `client_cipher_suites` and `client_extensions`, or
`server_extensions` on the server side; they are `[]` when it offered none.

A list is never partial:

- **Malformed:** a vector with an odd length, bytes left over inside the extension, an
  empty ALPN name, a server selecting more than one ALPN protocol, or a repeated
  extension. Only that list is NULL, the rest of the hello is still reported, and
  `warnings` says so.
- **Invalid hello:** a hello that fails to parse reports none of its lists.
- **Over the limit:** a list longer than `max_list_entries` sets `reassembly_status` to
  `limit`.

Expected values in `read_tls.test` come from tshark 4.2.2.
`scripts/compare_tls_tshark.py` repeats the comparison for any capture:

```sh
python3 scripts/compare_tls_tshark.py test/data/tls/*.pcap
```

It reports differences in the lists, any hello tshark decoded that no row accounts
for, and packets holding several hellos, which it cannot split and so skips. tshark
reads the valid prefix of a malformed list where `read_tls` reports NULL; the script
counts those as documented divergences.

## Warnings

`reassembly_status` holds one value, and a more specific status outranks `one-sided`. A
client-only handshake from a capture that began mid-connection is therefore
`unanchored`, not `one-sided`. `warnings` states the conditions that leave columns NULL,
whatever the status. It is `[]` when there are none and is never NULL.

| Code | Meaning |
| --- | --- |
| `client_hello_missing` | No complete ClientHello was captured, so the client columns are NULL. |
| `server_hello_missing` | No complete ServerHello was captured, so the server columns are NULL. |
| `client_hello_invalid`, `server_hello_invalid` | That hello was seen but failed to parse. |
| `client_list_malformed`, `server_list_malformed` | At least one of that side's lists is NULL because it was malformed. On the server side this includes a malformed `supported_versions`, which leaves `negotiated_version` NULL. |
| `server_certificate_malformed`, `client_certificate_malformed` | That side's Certificate message was malformed, so its column is NULL, or at least one certificate in it did not parse and is a NULL element. |
| `client_tunnel_unrecognized`, `server_tunnel_unrecognized` | Bytes came before TLS in that direction but did not parse exactly as a known tunnel. The TLS columns are still sound; see below. |
| `tunnel_mismatch` | Each side's prefix parsed as a different tunnel; `tunnel.protocol` is the client's. |

## JA3 and JA3S

The format is [salesforce/ja3](https://github.com/salesforce/ja3) at `502cc63`, and the
expected values in `read_tls.test` come from tshark 4.2.2's `tls.handshake.ja3*` fields:

```text
ja3_full   legacy_version,cipher_suites,extensions,supported_groups,ec_point_formats
ja3s_full  legacy_version,cipher_suite,extensions
```

Values are decimal and joined with `-`, in wire order. GREASE values are dropped, from
the ServerHello too. A list the hello did not carry is an empty field. `ja3` and `ja3s`
are the MD5 of those strings. The version is `legacy_version` on both sides, so a TLS
1.3 exchange reads 771, not the `negotiated_version` 772.

A fingerprint is NULL when its hello was not captured or failed to parse, or when one
of its inputs was malformed or over `max_list_entries`. tshark hashes the valid prefix
of such a list instead. Those rows carry `client_list_malformed` or status `limit`.
The fingerprint is built only when a query selects it.

`scripts/compare_tls_tshark.py` compares the fingerprints along with the lists.

## JA4 and JA4S

The definition is [FoxIO-LLC/ja4](https://github.com/FoxIO-LLC/ja4) at `16b96d9`.
JA4 follows `technical_details/JA4.md`. JA4S has only a diagram there, so it follows
the FoxIO python and rust implementations, which agree on it.

**Licensing.** JA4 is BSD 3-Clause. JA4S is part of JA4+, which is patent pending and
licensed under the FoxIO License 1.1. That license does not permit monetization
without an OEM license from FoxIO. The rest of this extension is MIT. See
[NOTICE](../NOTICE).

```text
ja4_r   t{version}{d|i}{ciphers:02}{extensions:02}{alpn}_{sorted ciphers}_{sorted extensions}[_{signature algorithms}]
ja4s_r  t{version}{extensions:02}{alpn}_{cipher}_{extensions}
```

`ja4` and `ja4s` replace each list after the prefix with the first 12 hex digits of
its SHA-256, or `000000000000` when the list is empty. JA4S keeps its one cipher as is.

- **Version:** for JA4, the highest non-GREASE `supported_versions` value, else
  `legacy_version`. For JA4S, the negotiated version. Unknown values are `00`.
- **JA4 lists:** GREASE is dropped from lists and counts. SNI (0) and ALPN (16) are
  counted but not hashed. Ciphers and extensions are sorted; signature algorithms keep
  wire order. Counts stop at 99.
- **JA4S lists:** extensions stay in wire order and **include GREASE**, in both the
  count and the hash, as both FoxIO implementations do.
- **ALPN:** the first value as sent. If its first and last bytes are both ASCII
  alphanumeric, those two characters; a one-character value appears twice. Otherwise
  the first and last digit of the value's lower-case hex. `00` when there is none.

A fingerprint is NULL when its hello is missing or invalid, or when an input it uses
was malformed or over `max_list_entries`, as for JA3. JA4 does not use
`supported_groups` or `ec_point_formats`, so a malformed one of those leaves `ja4`
defined.

The references disagree with each other, so these are the choices, in order: the
specification text, then the implementations where the text is silent.

| Case | JA4.md | tshark 4.2.2 | FoxIO python | FoxIO rust | `read_tls` |
| --- | --- | --- | --- | --- | --- |
| Empty list hash | `000000000000` | `e3b0c44298fc` | zeros | zeros | zeros |
| Non-alphanumeric ALPN byte | hex digits | hex digits | `9` or the raw byte | `9` | hex digits |
| One-character ALPN `x` | `xx` | `xx` | `xx` | `x0` | `xx` |
| GREASE as first ALPN value | "ignore GREASE" | first value | first value | first value | first value |

`scripts/compare_tls_tshark.py` compares JA4 with tshark, counting the empty-list
difference as documented. With `--foxio <path to python/ja4.py>` it also compares
JA4S with the FoxIO python reference. At `16b96d9` that reference misses a ServerHello
that shares a packet with other handshake messages, and fails on some streams it saw
start mid-connection; the script reports both separately from disagreements.

## Certificates

In TLS 1.2 and earlier the server sends its Certificate message in the clear, right
after the ServerHello. `server_certificates` lists it in wire order, so
`server_certificates[1]` is the leaf. Nothing is verified: not the signatures, the
chain, the host name or the validity period. These are the certificates the server
presented, not a judgement of them. TLS 1.3 encrypts the message, so the column is NULL
there. A client that the server asks for a certificate sends its own Certificate message
after its ClientHello, and `client_certificates` lists it the same way.

```sql
SELECT server_ip, tls_sni, server_certificates[1].subject AS leaf,
       server_certificates[1].not_after AS expires
FROM read_tls('capture.pcap')
WHERE server_certificates IS NOT NULL;
```

| Field | Content |
| --- | --- |
| `subject`, `issuer` | RFC 4514 strings, most specific first: `CN=www.example.com,O=Example Inc.,C=US`. |
| `serial` | The serial number's content octets as lowercase hex, including a leading `00` octet, as tshark shows it. |
| `not_before`, `not_after` | The validity period, UTC. |
| `san_dns` | subjectAltName DNS names, escaped as `tls_sni` is. |
| `san_ip` | subjectAltName IP addresses: dotted IPv4, RFC 5952 IPv6. |
| `ja4x`, `ja4x_r` | JA4X certificate fingerprint and its raw form. **FoxIO License 1.1**, see [NOTICE](../NOTICE). See below. |
| `sha1`, `sha256` | The whole DER certificate's hashes as lowercase hex, which is what certificate blocklists such as abuse.ch SSLBL key on. |
| `signature_algorithm`, `public_key_algorithm` | As `openssl x509 -text` prints them: `sha256WithRSAEncryption`, `ecdsa-with-SHA256`, `rsaEncryption`, `id-ecPublicKey`, `ED25519`. The names come from a table of about 45 RSA, RSA-PSS, DSA, ECDSA, EdDSA, SHA-3, SM2 and GOST algorithms, each checked against OpenSSL 3.0.13; any other algorithm is its dotted OID, even where OpenSSL has a name. |
| `public_key_bits` | RSA or RSA-PSS modulus size, DSA prime size, or a named EC curve's size, as OpenSSL's `Public-Key: (N bit)`. NULL for other keys, an unknown or explicitly specified curve, or a key body that does not parse. |
| `public_key_curve` | An EC key's named curve as OpenSSL's `ASN1 OID` line prints it, such as `prime256v1` or `secp384r1`; an unknown curve is its OID. |
| `is_ca`, `path_length` | basicConstraints' cA flag and pathLenConstraint. `is_ca` is NULL without the extension; `path_length` is NULL without a constraint. |
| `key_usage` | keyUsage bits by their RFC 5280 names, in bit order: `digitalSignature`, `nonRepudiation`, `keyEncipherment`, `dataEncipherment`, `keyAgreement`, `keyCertSign`, `cRLSign`, `encipherOnly`, `decipherOnly`. NULL without the extension. |
| `extended_key_usage` | extendedKeyUsage purposes by their RFC 5280 names (`serverAuth`, `clientAuth`, `codeSigning`, `emailProtection`, `timeStamping`, `OCSPSigning`, `anyExtendedKeyUsage`), others as dotted OIDs, in wire order. NULL without the extension. |

The algorithms and curve use OpenSSL's names so they can be read beside `openssl x509
-text`; the usage lists use RFC 5280's, which are identifiers rather than prose (OpenSSL
prints `TLS Web Server Authentication` for `serverAuth`). None of this is verified: a key
is described, not checked, and an RSA modulus is sized without being tested.

These fields only add to a certificate, so none of them can make it malformed. An
algorithm or key that does not parse leaves its fields NULL. A basicConstraints, keyUsage
or extendedKeyUsage that is malformed or repeated, which RFC 5280 forbids, leaves that
field NULL too, since neither copy is more believable. Only more than `max_list_entries`
purposes is a limit. The hashes are computed only when a certificate column is projected.

Names follow RFC 4514 and match `openssl x509 -nameopt RFC2253,-esc_msb` character for
character, with one exception. Attribute types in RFC 4514's own table use its short
names (`CN`, `O`, `OU`, `C`, `L`, `ST`, `STREET`, `DC`, `UID`), where OpenSSL prints
`street` in lower case. Other registered types use the names OpenSSL prints, such as
`emailAddress`, `serialNumber`, `organizationIdentifier` and `jurisdictionC`. Any other
type is written as its dotted OID with the value as `#` and uppercase hex of its DER
encoding. Inside a multi-valued RDN the attributes are also reversed, as OpenSSL does;
RFC 4514 gives that order no meaning. Special characters are escaped with a backslash.
Control characters and bytes that are not valid UTF-8 become `\XX` hex pairs, so a
hostile name cannot fail the query. TeletexString is read as Latin-1, as OpenSSL and Go
read it; tshark decodes it as T.61, so the two can differ outside ASCII.

A certificate that does not parse keeps its place in the list as a NULL element, and the
row gets `server_certificate_malformed`. A Certificate message whose framing is broken,
or a second one after the same ServerHello, makes the column NULL with the same warning.
A chain over `max_certificates`, a certificate over `max_certificate_bytes`, one with
more than `max_list_entries` subjectAltName entries or extendedKeyUsage purposes, or a chain that would take its
direction past `max_direction_certificate_bytes` of parsed text makes the column NULL
and sets `reassembly_status` to `limit`. The last bounds what a direction waiting for its
peer can hold.

`scripts/compare_tls_tshark.py` compares chains with tshark field by field, and names,
hashes, algorithms, keys and usage with OpenSSL's reading of the DER that tshark
extracted. Client certificates are compared the same way. On the whole CTU-13 Neris
capture it compared 4,244 certificate values, and on a capture carrying this machine's
121 CA certificates 1,952, with no disagreements.

## JA4X

`ja4x` fingerprints how a certificate was built, not what it says: the attribute types
of its issuer and subject names and the extension types it carries, each in wire order.
Two certificates from the same issuing software tend to share it, whatever their names.
`ja4x_r` is `issuer_subject_extensions`, each part the comma-joined hex of the DER OID
content octets, and `ja4x` replaces each part with the first 12 hex digits of its
SHA-256, or `000000000000` for an empty part.

The definition is FoxIO-LLC/ja4 at `16b96d9`, which has no written specification for
JA4X, only its two reference implementations. `ja4x` equals the rust one (`rust/ja4x`)
on every certificate checked: 135 certificates, including this machine's CA bundle,
the fixtures and the CTU-13 Neris capture. The python one (`python/ja4x.py`) differs in
three ways, all reference bugs: it writes an empty part as the hash of an empty
string, `e3b0c44298fc`; it counts RDNs rather than attributes, so a multi-valued RDN
shifts every later OID and it misses later certificates in the chain; and it stops with
an error on the Neris capture.

`scripts/compare_tls_tshark.py --ja4x <rust ja4x binary>` compares every certificate's
`ja4x` and `ja4x_r` with the rust reference.

## Tunnels

A stream whose first bytes are a TLS handshake record header is read as it stands and
never searched. Neither is a stream without its SYN: it begins mid-conversation, so its
first byte is not where a tunnel would start, and a hello-shaped run inside ordinary data
is not TLS. On CTU-13 Neris that is exactly what an unanchored SMTP direction held, a
complete ClientHello inside a binary mail body. Any other stream is searched for a hello
in its first 8 KiB
(`max_tunnel_prefix_bytes`). Past the start the test is stricter than at it: a whole
ClientHello or ServerHello must sit inside the first record found, within
`max_message_bytes`, and must parse. Bytes that merely look like a record header are not
TLS, and parsing one record per candidate bounds the search.

The bytes before the hello are then read as a tunnel, and must parse exactly, with no
byte left over:

| `protocol` | Client prefix | Server prefix |
| --- | --- | --- |
| `socks5` | RFC 1928 greeting, RFC 1929 username and password if offered, CONNECT request | Method choice, RFC 1929 status if it chose that method, success reply |
| `socks4`, `socks4a` | CONNECT request, and for 4a (address `0.0.0.x`) a name | Granted reply; always `socks4`, since the reply cannot tell 4 from 4a |
| `http_connect` | One or more `CONNECT target HTTP/1.x` heads to one target, as a client sends when a proxy asks it to log in | Refusals such as `407`, each body framed by `Content-Length`, then a `2xx` head, which has no body whatever it declares |
| `smtp` | `EHLO` or `HELO`, then any of `EHLO`, `HELO`, `NOOP`, `RSET`, then `STARTTLS` (RFC 3207) | A `220` greeting, `250` replies (at least one) with `5xx` refusals among them, then `220` |
| `imap` | Tagged `CAPABILITY` or `NOOP` commands, then a tagged `STARTTLS` (RFC 2595) | An untagged `* OK` greeting, untagged `CAPABILITY` or `OK` data and tagged `OK`, `NO` or `BAD` replies, then a tagged `OK` |
| `pop3` | Any number of `CAPA`, then `STLS` (RFC 2595) | A `+OK` greeting, `+OK` or `-ERR` replies (`CAPA`'s multi-line one ending in a lone `.`), then `+OK` |
| `ftp` | Any of `FEAT`, `SYST`, `NOOP` and refused `AUTH` attempts, then `AUTH TLS`, `AUTH SSL`, `AUTH TLS-C` or `AUTH TLS-P` (RFC 4217) | A `220` greeting, `2xx` or `5xx` replies, then `234` |

The four STARTTLS exchanges are read line by line: every line must end in CRLF, and
commands are matched without regard to case. A multi-line SMTP or FTP reply ends at its
code alone or followed by a space; SMTP repeats the code and a hyphen on every line before
that, while FTP allows any text there. A login, `MAIL`, or any command not listed before
the upgrade leaves the prefix unrecognised, as does an IMAP `BYE` or `PREAUTH`. Each side
is read on its own, so an IMAP server's final tag is not matched to the client's. These
protocols name no destination, so `destination` is NULL for them.

- `protocol` is the client's reading when its prefix was recognised, since only the
  client's request names the destination, and otherwise the server's. It is NULL when
  neither side was recognised.
- `destination` is the client's CONNECT target as `host:port`, with IPv6 in brackets and
  names escaped as `tls_sni` is. It is NULL unless the client's prefix was recognised.
- `client_prefix_bytes` and `server_prefix_bytes` count the bytes before TLS in each
  direction: 0 when TLS began it, NULL when that direction was not captured.
- A prefix that is not recognised still leaves the row sound, because its hello parsed
  in full. The row gets `client_tunnel_unrecognized` or `server_tunnel_unrecognized`.
- Sides that recognise different tunnels get `tunnel_mismatch`; a `socks4a` request and
  its `socks4` reply agree.
- Every handshake on a tunnelled connection reports its tunnel, including the second
  ClientHello after a TLS 1.3 HelloRetryRequest and a renegotiation. The prefix lengths
  count the bytes before the connection's first TLS record.
- SOCKS5 with GSSAPI authentication is not recognised: after the login its requests may
  be encapsulated, so they cannot be read.

On the CTU-13 Neris capture this reads all 63 handshakes on connections between the
infected host `147.32.84.165` and `212.117.171.138:65500`, which was the last gap against
tshark there. They are a backconnect proxy: the bot opens the TCP connection, then acts as
the SOCKS5 server for the far end, which sends a ClientHello for `login.live.com` through
it. `read_tls` orients rows by TLS role, so `client_ip` is `212.117.171.138`. The bot's
side is standard SOCKS5. The far end sends one extra byte, `0x7e`, before an otherwise
standard greeting, so its prefix is unrecognised and no destination is claimed.

## `session_resumed` is often NULL

A server resumed a session when it echoed back a non-empty session id the client offered.
That question needs both directions, and in TLS 1.3 the id is echoed whether or not the
session resumed. So `session_resumed` is NULL for a one-sided handshake, for TLS 1.3 and when
`negotiated_version` is NULL, and
false rather than NULL when both sides were captured and the client offered no session id.

## Status values

| Status | Meaning |
| --- | --- |
| `complete` | Both directions captured and the handshake parsed. |
| `one-sided` | Only one direction was captured. The other side's columns are NULL. |
| `incomplete` | The handshake continues past the captured bytes, or a sequence gap interrupts it. |
| `unanchored` | No SYN was captured, so the stream offsets start at the earliest observed sequence. |
| `invalid` | A hello was present but malformed. |
| `limit` | A per-connection or per-message limit was reached. |

A TCP stream that shows no ClientHello or ServerHello produces no row, including one the
transport core could not reconstruct. We cannot tell whether such a stream carried TLS, and
reporting every unreadable stream as a TLS finding would bury the real ones.

## Limits

Bounded by `TlsHandshakeLimits`, alongside the transport-wide
`packetquapture_stream_memory_mb`:

| Limit | Default | Applies to |
| --- | --- | --- |
| `max_handshakes` | 16 | Handshakes reported per direction. |
| `max_message_bytes` | 64 KiB | One handshake message. |
| `max_extensions` | 256 | Extensions walked in one hello. |
| `max_pending` | 512 | Directions held while waiting for a peer. |
| `max_list_entries` | 1024 | Entries in one parsed hello list, and subjectAltName entries or extendedKeyUsage purposes in one certificate. |
| `max_certificates` | 16 | Certificates in one Certificate message. |
| `max_certificate_bytes` | 32 KiB | One certificate. |
| `max_direction_certificate_bytes` | 256 KiB | Parsed certificate text one direction holds across its handshakes. |
| `max_tunnel_prefix_bytes` | 8 KiB | Bytes searched for a hello in a stream that does not begin with a handshake record. |

Reaching a limit sets `reassembly_status` to `limit` rather than failing the query. Directions
waiting for a peer hold parsed fields, not payload bytes, and at most
`max_direction_certificate_bytes` of certificate text each.

## Pairing and VLAN tags

Directions are paired with `TcpFlowKey::Reverse()`, which swaps the addresses and ports but
leaves `section`, `interface_id` and `vlans` alone. Two directions of one connection recorded
with different VLAN tags, or on different interfaces, therefore do not pair: each is reported
as `one-sided`. This is deliberate. Treating differently tagged traffic as one connection
would merge flows that the capture itself distinguishes.

## No filter pushdown

Like `read_dns_messages`, `read_tcp_streams` and `read_flows`, `read_tls` takes file-level
pruning only. A segment-level predicate could remove bytes needed to reconstruct a handshake
that would have matched it.

## Not yet implemented

Certificate extensions beyond subjectAltName, basicConstraints, keyUsage and
extendedKeyUsage, such as the key identifiers, CRL and OCSP locations, and policies, and
the public key's own bytes. DTLS and QUIC hellos, the `d` and `q` JA4
variants, are not read.

Handshakes can still go missing on very busy captures. The transport core tracks
1,024 TCP directions per file and evicts those idle for 300 seconds (see
[TCP streams](TCP_STREAMS.md)). If more than 1,024 are active at once, each new packet
becomes its own one-packet stream with status `limit`. This reader cannot tell whether
such a stream carried TLS, so it reports nothing for it.

Tunnels other than SOCKS, HTTP CONNECT and SMTP, IMAP, POP3 and FTP STARTTLS are read,
but not named: XMPP, LDAP and PostgreSQL upgrades, for example, are found the same way
when their exchange fits in 8 KiB, and are reported with an unrecognised prefix. TLS after
a longer prefix is not found.
