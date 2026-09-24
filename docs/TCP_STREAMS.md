# TCP streams and the shared architecture

`read_tcp_streams(path_or_list)` exposes reconstructed TCP bytes on **any port**, with one row per
observed direction. It handles PCAP/PCAPNG files, lists, and globs. It does not parse application protocols
or decrypt TLS; encrypted payloads remain opaque bytes.

```sql
SELECT src_ip, src_port, dst_ip, dst_port,
       reassembly_status, captured_bytes, stream_data
FROM read_tcp_streams('captures/**/*.pcap*')
WHERE dst_port = 443;

-- Inspect individual ranges without pretending missing bytes are present.
SELECT stream_id, part.offset, part.tcp_sequence, part.data
FROM (
  SELECT stream_id, unnest(chunks) AS part
  FROM read_tcp_streams('captures/**/*.pcap*')
  WHERE has_gaps
);
```

## One transport implementation, separate application layers

The dependency direction is:

```text
CaptureReader -> bounded packet decoder -> TcpReassembler -> TcpStream
                                                        |-> read_tcp_streams
                                                        |-> FrameTcpDns -> DecodeDns -> read_dns_messages
```

- `src/include/tcp_reassembly.hpp` and `src/tcp_reassembly.cpp` own flow identity, sequence arithmetic,
  SYN/FIN/RST lifecycle, ordering, retransmissions, overlap policy, byte provenance, gaps, and memory bounds.
  They have no DuckDB, filesystem, DNS, port-53, or application-message dependency.
- `src/include/dns_tcp_framer.hpp` and `src/dns_tcp_framer.cpp` are stateless consumers of `TcpStream`.
  They recognize DNS's length prefixes and return message views as owned byte buffers. They do not maintain
  flows or implement their own retransmission handling.
- `dns_decoder` interprets complete DNS messages. UDP reaches that same decoder without TCP framing.
- `NextStreamEvent` shares capture iteration and transport lifecycle across the SQL functions. SQL adapters
  select relevant traffic, choose application framing, and populate columns.

The earlier DNS-specific reassembly engine has been replaced, not retained as a second implementation.
Future HTTP, TLS-record, or other protocol analysis should consume `TcpStream` ranges and add its own
framing/parser. Changes to ordering, overlap policy, or resource accounting belong in the TCP core once.

A new application consumer must define its message-boundary rules, behavior when SYN/alignment is missing,
behavior at gaps/end-of-input, and limits on message size/count. It must not join ranges across gaps or
infer bytes that were not captured. Application-specific limits (such as DNS's message count) belong in
the framer, while transport-wide limits belong in `TcpReassemblyLimits`.

## Byte and gap contract

A `TcpStream` has ordered, non-overlapping `chunks` and explicit `gaps` within its observed sequence span.
Every chunk owns its exact bytes and byte-range provenance. The core retains captured ranges **after** gaps;
application framers decide whether they can safely resume there. DNS deliberately stops at the first gap.

When SYN was captured, offset zero is its sequence number plus one. Without SYN, the core uses the earliest
observed payload sequence as offset zero and marks the result `unanchored`. This supports inspecting captures
that begin mid-connection without claiming the application-message boundary is known. Out-of-order records
and 32-bit sequence wraparound are handled within the bounded sequence window.

Identical retransmissions do not duplicate bytes. Overlaps whose bytes agree are merged. Conflicting overlaps
invalidate the entire buffered direction; no preferred operating-system overlap policy is guessed. Opposite
directions have distinct IDs. File, section, interface, IP endpoints, ports, and VLAN stack define scope.
There is no cross-file stitching, IP-fragment reassembly, checksum verification, or deduplication across interfaces.

Output remains offline: directions finalize at EOF, RST, or tuple reuse by a new SYN. FIN marks the expected
end but does not immediately emit the direction, allowing late capture records to be validated. There is no
promise of global capture-time ordering. Control-only directions with no observed or missing payload produce
no row, except resource diagnostics; this function is not a connection inventory.

## SQL columns

| Column | Type | Meaning |
| --- | --- | --- |
| `filename` | `VARCHAR` | Source capture |
| `section_number`, `interface_id` | `UINTEGER` | Capture scope |
| `ip_version` | `UTINYINT` | 4 or 6 |
| `src_ip`, `dst_ip` | `VARCHAR` | Direction's addresses |
| `src_port`, `dst_port` | `USMALLINT` | Direction's ports |
| `stream_id` | `UBIGINT` | Scan-local directional identifier |
| `tcp_sequence` | `UINTEGER` | Absolute TCP sequence corresponding to offset zero |
| `syn_seen`, `fin_seen`, `reset_seen` | `BOOLEAN` | Observed lifecycle markers |
| `finalized_by` | `VARCHAR` | `eof`, `reset`, `tuple_reuse`, `idle_timeout`, or immediate `limit` rejection |
| `reassembly_status` | `VARCHAR` | `contiguous`, `gapped`, `unanchored`, `conflict`, or `limit` |
| `reassembly_error` | `VARCHAR` | Diagnostic text, otherwise null |
| `first_packet_number`, `last_packet_number` | `UBIGINT` | First/last observed packet of the direction, including control packets |
| `first_timestamp`, `last_timestamp` | `TIMESTAMP` | Timestamps of those packets; null if absent |
| `expected_bytes` | `UINTEGER` | Observed sequence span, extended to FIN when available |
| `captured_bytes` | `UINTEGER` | Unique captured bytes after retransmission deduplication |
| `has_gaps` | `BOOLEAN` | Whether the observed span contains known missing ranges |
| `stream_data` | `BLOB` | Captured bytes if gap-free; null when gaps/conflicts/limits prevent a single byte string |
| `chunks` | `STRUCT(offset UINTEGER, tcp_sequence UINTEGER, data BLOB, first_packet_number UBIGINT, last_packet_number UBIGINT)[]` | Contiguous captured ranges |
| `gaps` | `STRUCT(offset UINTEGER, length UINTEGER)[]` | Known missing ranges |
| `vlan_ids` | `USMALLINT[]` | Scope's VLAN stack |

`contiguous` means the observed span has no known gaps. It does **not** mean that the entire connection was
captured; EOF without FIN may simply end observation. `unanchored` can also contain gaps, so inspect `has_gaps`.
An unanchored but gap-free capture still exposes `stream_data`. Conflicts and limits yield null byte counts,
sequence, chunks, gaps, and data rather than fabricated zero-byte results. Chunk provenance uses first receipt
of each byte, so retransmissions do not move its packet range.

## Resource policy and validation

The core retains the existing limits: 1,024 tracked directions per file, 32 MiB stored payload per file,
1 MiB stored payload and sequence span per direction, 4,096 segments per direction, and 65,536 segments
per file. Metadata, reconstruction, and output use additional bounded memory. Quarantined directions emit
explicit diagnostics rather than silent eviction.

A direction with no packet for 300 seconds is finalized with `finalized_by = 'idle_timeout'`, freeing its
slot, as `read_flows` does with its default `tcp_idle_timeout`. Idle is judged per capture interface by the
latest timestamp seen on it; a direction that has any packet without a timestamp is never evicted. Without
this, connections that never close (scans, abandoned sessions) filled the 1,024 slots for good and every
later packet became a one-packet `limit` stream. The status still describes the bytes, so an evicted
direction is usually `contiguous`. Two costs: traffic that resumes after eviction starts a new direction,
reported `unanchored` because its SYN belonged to the old one, and a retransmission that arrives after
eviction can no longer be checked against the bytes already emitted. Only more than 1,024 directions active
within 300 seconds of each other still produce direction-limit rows.
The DNS framer independently limits messages per direction to 4,096.

All transport payloads selected by the stream function are needed for reconstruction, including for count-only
queries. SQL filters execute after reconstruction, so they cannot accidentally remove necessary segments.
Selecting fewer columns avoids constructing unused SQL blobs/lists. Packet-level functions retain their
separate staged filter pushdown and selective header reads.

Transport and application tests are separate: arbitrary binary payloads on non-DNS ports test the core;
DNS framing and SQL regressions test the adapter. Both run with AddressSanitizer and UndefinedBehaviorSanitizer.

```sh
python3 scripts/generate_tcp_stream_captures.py
./build/release/test/unittest 'test/sql/*'
c++ -std=c++17 -Wall -Wextra -Werror -g -O1 \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  -Isrc/include src/tcp_reassembly.cpp test/unit/tcp_reassembly_test.cpp \
  -o build/tcp_reassembly_test
./build/tcp_reassembly_test
```

## Whole-file parallel execution

See [parallel stream scans](PARALLEL_STREAMS.md) for deterministic scan-local IDs,
query-wide memory admission, worker limits, and bounded output batches. The 32 MiB
stored-payload limit above applies per active input occurrence; aggregate admission
is separately bounded across all stream readers in a query.
