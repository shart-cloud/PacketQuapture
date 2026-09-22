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
| `negotiated_version` | `supported_versions` from the ServerHello when present, otherwise its `legacy_version`. This is why a TLS 1.3 connection reports 0x0304 rather than the 0x0303 in its record headers. |
| `cipher_suite` | The suite the server selected. |
| `session_resumed` | See below. |
| `reassembly_status`, `reassembly_error` | See below. |

## `session_resumed` is often NULL

A server resumed a session when it echoed back a non-empty session id the client offered.
That question needs both directions, and in TLS 1.3 the id is echoed whether or not the
session resumed. So `session_resumed` is NULL for a one-sided handshake and for TLS 1.3, and
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

JA3/JA4/JA4S fingerprints, ALPN, offered cipher suites, supported groups, signature
algorithms, and the certificate chain. Each needs more of the handshake than this reader
parses, and fingerprints need to match their reference implementations byte for byte.
