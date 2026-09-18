# Reassembled DNS messages

`read_dns_messages(path_or_list)` returns DNS message rows from UDP datagrams and reconstructed TCP
streams on port 53. It accepts PCAP/PCAPNG files, lists, and globs. `read_dns` remains the lightweight,
packet-level function; `read_packets` and `read_pcap` retain their existing meanings.

```sql
SELECT src_ip, dst_ip, dns_question_name, first_packet_number, last_packet_number
FROM read_dns_messages('captures/**/*.pcap*')
WHERE dns_valid AND NOT dns_response;

SELECT filename, src_ip, src_port, reassembly_status, reassembly_error
FROM read_dns_messages('captures/**/*.pcap*')
WHERE reassembly_status <> 'complete';
```

The shared [protocol-independent TCP engine](TCP_STREAMS.md) performs sequence ordering, retransmission
handling, overlap checks, and resource accounting. DNS adds a stateless length-prefix framer over its output.
`read_tcp_streams` exposes the same transport bytes directly, on any TCP port.

## TCP behavior

- Reconstructs length-prefixed DNS messages split across segments, including a split two-byte prefix.
- Reorders captured segments using TCP sequence numbers and handles 32-bit sequence wraparound within
  the bounded sequence window. SYN consumes a sequence number, including TCP Fast Open data on SYN.
- Extracts multiple messages from a segment or a persistent stream.
- Deduplicates identical retransmissions and accepts overlapping segments whose shared bytes agree.
- Treats conflicting overlapping bytes as a conflict for the entire buffered direction, rather than
  choosing one interpretation. No messages from that direction are emitted in this case.
- Requires a captured SYN (or SYN-ACK for the reverse direction) to establish framing alignment. A SYN
  captured out of order can still anchor previously buffered segments. Without a SYN, the direction
  produces an `unanchored` diagnostic; bytes are not guessed to start at a DNS message boundary.
- A new SYN sequence starts a new direction. An initiating SYN retires the old reverse direction too.
  Repeated SYNs with the same sequence are treated as retransmissions. RST finalizes both directions.
- FIN establishes the expected end of a direction, including gaps before FIN. Directions remain buffered
  after FIN to allow out-of-order capture records and late retransmissions to be checked.

This is an offline, file-scoped implementation. TCP output is delayed until file end, reset, or a new SYN
that reuses a tuple. It does not promise capture order for result rows. UDP output can precede buffered TCP
output. Use `ORDER BY` when ordering matters.

Each direction is scoped by the file, PCAPNG section/interface, IP version, source/destination addresses,
ports, and VLAN stack. Files are never stitched together, even when they are consecutive capture rotations.
The same tuple on different interfaces or VLANs remains separate. The decoder does not attempt to deduplicate
traffic observed on multiple interfaces. IP fragment reassembly, encrypted DNS, ACK-based inference of lost
bytes, TCP checksum verification, and operating-system-specific overlap policies are not implemented.

## Output and diagnostics

The function includes all fourteen `dns_*` columns documented in [DNS packet queries](DNS.md), plus:

| Column | Type | Meaning |
| --- | --- | --- |
| `filename` | `VARCHAR` | Source capture |
| `section_number`, `interface_id` | `UINTEGER` | Capture scope |
| `ip_version` | `UTINYINT` | 4 or 6 |
| `src_ip`, `dst_ip` | `VARCHAR` | Direction's addresses |
| `src_port`, `dst_port` | `USMALLINT` | Direction's ports |
| `transport` | `VARCHAR` | `tcp` or `udp` |
| `stream_id` | `UBIGINT` | Scan-local directional TCP identifier; null for UDP |
| `message_number` | `UBIGINT` | One-based message number within a TCP direction; one for UDP; null on diagnostics |
| `first_packet_number`, `last_packet_number` | `UBIGINT` | Earliest/latest contributing capture packet numbers |
| `first_timestamp`, `last_timestamp` | `TIMESTAMP` | Timestamps of those packets, nullable when absent |
| `tcp_sequence` | `UINTEGER` | Sequence of the message's length prefix, or start of an incomplete/invalid frame |
| `reassembly_status` | `VARCHAR` | Status described below |
| `reassembly_error` | `VARCHAR` | Diagnostic text, null on complete message rows |
| `message_data` | `BLOB` | DNS message bytes, without TCP length prefix; null on diagnostics |
| `vlan_ids` | `USMALLINT[]` | VLAN stack defining the direction's scope |

For complete messages, provenance includes the first receipt of each byte and its length prefix; identical
retransmissions do not change it. Diagnostic provenance spans the observed direction, including control packets.
Packet-number order determines first/last provenance, not timestamp order. `tcp_sequence` is null for UDP and
for conflicts, unanchored directions, or resource-limit diagnostics.

Statuses:

- `complete`: all bytes of a framed message are available. DNS parsing may still fail, so check `dns_valid`.
- `incomplete`: a sequence gap, a snaplen-truncated payload, a partial prefix/message, or truncated UDP payload.
- `unanchored`: TCP data was captured without a SYN anchoring that direction.
- `conflict`: contradictory overlapping TCP bytes or FIN positions.
- `invalid`: a TCP DNS length prefix declares fewer than twelve DNS header bytes.
- `limit`: bounded reassembly capacity was exceeded.

Complete messages before the first gap or incomplete frame remain available, followed by a diagnostic.
The parser does not search past missing bytes or invalid framing to guess subsequent message boundaries.
A conflicting direction or a resource-limited direction produces a diagnostic instead of potentially
ambiguous message rows. Diagnostic rows have `dns_valid = false`, null DNS fields, and `dns_error` text.

## Bounds and query behavior

Defaults are fixed for this experimental release:

- 1,024 tracked TCP directions per file, including completed directions retained for overlap checking.
- 32 MiB of buffered captured TCP payload per file.
- 1 MiB of captured payload and a 1 MiB sequence span per direction.
- 4,096 retained segments per direction and 65,536 retained segments per file.
- 4,096 DNS messages per finalized direction.

Identical whole-segment retransmissions do not consume additional storage. Partial overlaps count toward
stored-byte limits. Metadata, reconstruction buffers, and output rows use additional bounded memory beyond
that payload budget. Exceeding a stored-byte/segment budget quarantines the affected direction until reset,
tuple reuse, or file end; it emits an explicit diagnostic. New directions beyond the tracked-direction cap
produce limit diagnostics. This first version favors detectable incompleteness over silent eviction.

All DNS-relevant transport payloads must be read for reassembly, even for `count(*)`. Payloads on other ports
are skipped. DNS structure parsing is avoided when no DNS fields are requested. SQL filters run **after**
reconstruction: applying packet/time/flag predicates to segments first could remove bytes required by a
matching message. The packet-level functions retain their staged filter pushdown.

## Validation

The implementation follows TCP sequence accounting and DNS TCP framing described in
[RFC 9293](https://www.rfc-editor.org/rfc/rfc9293) and
[RFC 7766](https://www.rfc-editor.org/rfc/rfc7766). All checked-in fixtures are project-authored, deterministic
MIT data. Coverage includes split prefixes, reordered and duplicate segments, consistent/conflicting overlaps,
sequence wraparound, SYN data, resets, tuple reuse, IPv6, VLAN/interface/file isolation, capture truncation,
and result chunk boundaries.

```sh
python3 scripts/generate_reassembly_captures.py
GEN=ninja make release
./build/release/test/unittest 'test/sql/*'
c++ -std=c++17 -Wall -Wextra -Werror -g -O1 \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  -Isrc/include src/tcp_reassembly.cpp src/dns_tcp_framer.cpp test/unit/dns_tcp_framer_test.cpp \
  -o build/dns_tcp_framer_test
./build/dns_tcp_framer_test
```

## Whole-file parallel execution

See [parallel stream scans](PARALLEL_STREAMS.md) for deterministic scan-local IDs,
query-wide memory admission, worker limits, and bounded output batches. The 32 MiB
stored-payload limit above applies per active input occurrence; aggregate admission
is separately bounded across all stream readers in a query.
