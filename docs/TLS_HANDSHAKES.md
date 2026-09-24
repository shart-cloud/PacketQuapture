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
| `max_list_entries` | 1024 | Entries in one parsed hello list. |

Reaching a limit sets `reassembly_status` to `limit` rather than failing the query. Directions
waiting for a peer hold parsed fields, not payload bytes.

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

The certificate chain and JA4X. The certificate is in a later handshake message that
this reader does not yet parse. JA4X is part of JA4+ and under the same license as
JA4S. DTLS and QUIC hellos, the `d` and `q` JA4 variants, are not read.

Handshakes can still go missing on very busy captures. The transport core tracks
1,024 TCP directions per file and evicts those idle for 300 seconds (see
[TCP streams](TCP_STREAMS.md)). If more than 1,024 are active at once, each new packet
becomes its own one-packet stream with status `limit`. This reader cannot tell whether
such a stream carried TLS, so it reports nothing for it.

TLS carried inside another protocol, such as a SOCKS tunnel, is not read: a stream
must begin with a TLS record. tshark does decode these, so they show up in
`compare_tls_tshark.py` as tshark hellos without a `read_tls` row.
