# Protocol decoding prototype

`read_packets(path_or_list)` accepts the same PCAP/PCAPNG files, lists, and globs as `read_pcap`.
It returns all eleven raw columns unchanged, followed by the nullable columns below. This decoded
schema is experimental; `read_pcap` remains the stable framing interface.

```sql
SELECT timestamp, src_ip, src_port, dst_ip, dst_port, tcp_flags
FROM read_packets('captures/**/*.pcap*')
WHERE ip_protocol = 6 AND dst_port = 443;
```

| Column | DuckDB type | Meaning |
| --- | --- | --- |
| `src_mac`, `dst_mac` | `VARCHAR` | Lowercase colon-separated Ethernet MAC addresses |
| `ether_type` | `USMALLINT` | Final Ethernet type after VLAN tags |
| `vlan_ids` | `USMALLINT[]` | Outer-to-inner VLAN IDs; empty list for untagged Ethernet |
| `ip_version` | `UTINYINT` | 4 or 6 |
| `src_ip`, `dst_ip` | `VARCHAR` | IPv4 dotted decimal or IPv6 eight lowercase, zero-padded groups |
| `ip_protocol` | `UTINYINT` | IPv4 protocol or IPv6 next-header value after supported extensions |
| `ip_ttl` | `UTINYINT` | IPv4 TTL or IPv6 hop limit |
| `ip_fragment_offset` | `UINTEGER` | Fragment offset in bytes; zero for unfragmented traffic |
| `ip_more_fragments` | `BOOLEAN` | Whether more fragments follow |
| `ip_id` | `UINTEGER` | IPv4 identification or IPv6 fragment identification; otherwise null |
| `src_port`, `dst_port` | `USMALLINT` | TCP/UDP ports |
| `tcp_flags` | `USMALLINT` | Eight TCP control bits (FIN=1 through CWR=128); excludes reserved bits |
| `tcp_fin`, `tcp_syn`, `tcp_rst`, `tcp_psh`, `tcp_ack_flag`, `tcp_urg`, `tcp_ece`, `tcp_cwr` | `BOOLEAN` | Individual TCP flag bits; null whenever `tcp_flags` is null |
| `tcp_seq`, `tcp_ack` | `UINTEGER` | TCP sequence and acknowledgment numbers |
| `tcp_header_length` | `UTINYINT` | TCP header length in bytes, including options |
| `udp_length` | `USMALLINT` | Declared UDP datagram length, including its header |
| `payload_offset` | `UINTEGER` | Zero-based transport payload offset within `packet_data`, not the capture file |
| `payload_length` | `UINTEGER` | Captured transport payload bytes, bounded by IP/UDP lengths and capture length |

## Supported packets and null behavior

- Ethernet II with up to eight stacked 802.1Q/802.1ad VLAN tags.
- Raw IP (`LINKTYPE_RAW=101`), explicit IPv4/IPv6 (228/229), and Linux cooked v1/v2 (113/276).
  Ethernet-specific columns are null on these non-Ethernet links.
- IPv4 with bounded variable-length headers. Options are skipped, not interpreted.
- IPv6 with up to sixteen Hop-by-Hop, Routing, Destination Options, Fragment, and Authentication headers.
  Extension contents are not semantically validated. Unknown next headers and ESP retain IP fields but have
  null transport fields. For later fragments, `ip_protocol` is the fragment header's next-header value;
  the fragment payload is not walked as an extension chain.
- TCP and UDP with complete, bounded headers. Checksums and individual TCP/IP options are not validated.

Unsupported link types still return their raw row. A malformed or incomplete Ethernet/VLAN header makes
Ethernet and higher fields null. A malformed or incomplete IP header chain makes IP and higher fields null.
A malformed or incomplete transport header makes transport fields null, preserving valid IP/Ethernet fields.
Capture framing errors continue to raise the existing reader errors.

Both first and later IP fragments have null transport fields; there is no reassembly. IPv6 atomic fragments
(offset zero and no more-fragments flag) can be decoded normally. IPv6 jumbograms are unsupported.
Truncated payloads with intact headers retain decoded header fields. `payload_length` counts only captured
bytes and excludes Ethernet padding, IP bytes beyond the UDP length, and missing payload bytes.

## Execution and current limits

The decoder uses a non-owning bounded `PacketView` and has no DuckDB or filesystem dependency.
Metadata-only projections do not call it or allocate packet buffers. Link-only projections stop before IP;
network-only projections stop before TCP/UDP. Scalar decoded fields are written directly into DuckDB vectors.
No packet BLOB is constructed unless `packet_data` is projected.

The decoder requests progressively larger header prefixes only as needed, including variable-length VLAN,
IP, IPv6 extension, and TCP headers. For ordinary Ethernet/IPv4/TCP packets this reads 14 bytes for link
fields, 34 bytes for IP fields, and 54 bytes for TCP fields. Full packet bytes are read only when `packet_data`
is requested. Payload lengths still use the captured and protocol-declared lengths, not the prefix size.

Seekable files with a known size skip unused payloads via checked seeks; skipped ranges beyond the file's
opening size raise truncation errors. Non-seekable inputs discard unused bytes through an 8 KiB buffer,
so they save allocation/decoding but must still consume the stream. Files are assumed immutable during a scan.
The maximum supported header prefix is 32,914 bytes, independent of payload size. The existing 256 MiB
captured-packet safety limit remains in effect. Scans remain sequential. Filter pushdown is described below; reassembly is not implemented.

## Reproduce validation

All fixtures are deterministic project-authored data under the project's MIT license; they contain no captured
user traffic. The generator uses the header layouts in [RFC 791](https://www.rfc-editor.org/rfc/rfc791),
[RFC 8200](https://www.rfc-editor.org/rfc/rfc8200), [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293),
and [RFC 768](https://www.rfc-editor.org/rfc/rfc768). Checksums are deliberately zero.

```sh
python3 scripts/generate_protocol_captures.py
make format-check
GEN=ninja make release
./build/release/test/unittest 'test/sql/*'

# Standalone decoder, independent of DuckDB:
c++ -std=c++17 -Wall -Wextra -Werror -g -O1 \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  -Isrc/include src/packet_decoder.cpp test/unit/packet_decoder_test.cpp \
  -o build/packet_decoder_test
./build/packet_decoder_test
```

SQL tests cover valid and malformed protocols, alternate link types, PCAPNG, raw-row parity, lists/globs,
filter null semantics, and null/non-null transitions across multiple DuckDB output chunks. Standalone tests
exercise every fixture prefix, 68,000 deterministic header mutations, and 140,000 random link/input cases.
## Header-read I/O check (Linux)

After a release build, run `python3 scripts/benchmark_header_reads.py` with `strace` installed. This creates
1,000 synthetic Ethernet/IPv4/TCP packets with 60,000 payload bytes each in the ignored build directory.
The script asserts bytes returned by capture-file read syscalls (including capture framing):

| Projection | Bytes read |
| --- | ---: |
| Count only | 16,024 |
| Ethernet address | 30,024 |
| IP address | 50,024 |
| TCP flags and payload length | 70,024 |
| Raw packet bytes and payload length | 60,070,024 |

These measure application reads, not physical disk traffic or a general throughput guarantee; filesystem
read-ahead and storage backends can differ. Both payload-length queries return 60,000,000 payload bytes.
Standalone sanitizer tests also compare lazy-prefix and full-buffer decoding for every tested input and depth.

## Filter pushdown

`read_pcap`, `read_packets`, and `read_dns` accept scalar table filters from DuckDB. Supported pushed
predicates use DuckDB's own expression evaluator, preserving comparisons and three-valued null semantics.
Bare boolean predicates such as `tcp_syn AND NOT tcp_ack_flag` are normalized to boolean comparisons.
DuckDB keeps expressions it cannot push (such as cross-column OR and nested-list predicates) above the scan.
Advisory dynamic, optional, and Bloom filters may be ignored; joins/residual predicates retain correctness.

Filters are applied in increasing cost order: capture metadata, Ethernet, IP, TCP/UDP, DNS, then raw bytes.
A rejected row skips its remaining packet bytes on seekable files, even when the query selects `packet_data`.
On non-seekable streams those bytes must still be consumed using a bounded discard buffer. Capture framing
continues to be validated for rejected packets. This does not yet prune entire files or indexed time ranges.
`EXPLAIN` shows pushed predicates under the scan's `Filters` entry.

```sql
SELECT timestamp, src_ip, dst_ip, packet_data
FROM read_packets('captures/**/*.pcap*')
WHERE tcp_syn AND NOT tcp_ack_flag AND dst_port = 443;
```

The I/O benchmark also checks queries selecting raw bytes whose rows are rejected by capture-length,
IP-version, or port predicates. They read respectively 16,024, 50,024, and 70,024 bytes from the synthetic
60 MB capture, while a matching TCP-flag predicate reads all 60,070,024 bytes. This is a read-volume
measurement, not a throughput claim; per-row filter evaluation also has a CPU cost.

For DNS questions and answers, see [DNS packet queries](DNS.md).
