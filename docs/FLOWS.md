# Session summaries: read_flows

`read_flows` summarizes observed TCP and UDP sessions in both directions. It reads
bounded headers and never instantiates TCP payload reconstruction. Existing reader
schemas are unchanged. This is phase 1 of `FLOWS_INVENTORY_EXPORT_PLAN.md`; inventory,
catalog-assisted pruning, and PCAP export are not implemented by this change.

```sql
SELECT filename, input_index, flow_id, transport,
       orig_ip, orig_port, resp_ip, resp_port,
       orig_packets, resp_packets, duration, finalized_by
FROM read_flows('captures/**/*.pcap',
                tcp_idle_timeout=INTERVAL '5 minutes',
                udp_idle_timeout=INTERVAL '1 minute');

SELECT host, sum(orig_captured_bytes + resp_captured_bytes)
FROM read_flows('captures/host=*/*.pcap', hive_partitioning=true)
GROUP BY host;
```

## Scope and identity

Filenames, lists, globs, PCAP and PCAPNG use the existing capture reader and DuckDB
filesystem. Independent input occurrences run on separate workers; one occurrence
remains sequential. Repeating a path repeats its observations. Sessions never cross
input occurrences, PCAPNG sections or interfaces, IP families, transports, or VLAN
stacks. Unsupported encapsulations, malformed transport headers and fragmented IP
packets are excluded. A successfully decoded atomic IPv6 fragment is eligible.
There is no DNS/application decoding, fragment reassembly, cross-file stitching, or
claim about packet loss or application success.

`flow_id = (first_packet_number - 1) * original_input_count + original_index + 1`,
with checked UBIGINT arithmetic. `input_index` is one-based. IDs are stable for the
same ordered expanded inputs, contents, and options across thread counts and
filename/Hive filtering. They are scan-local, not persistent, and must not be joined
to TCP stream IDs. Output order is unspecified; use SQL ORDER BY when needed.

The lookup key uses an unordered endpoint pair. First SYN without ACK chooses its
sender as originator; first SYN-ACK chooses its receiver; other first packets use
their sender. `originator_basis` is `syn`, `syn_ack`, or `first_packet`. Directions
never flip after creation. Equal endpoints are explicitly ambiguous and are
accounted consistently in the chosen direction; bidirectionality cannot be recovered.

## Fixture-defined lifecycle

All records are processed in capture order. The following rules are policy for
imperfect observations, not a reconstruction of real-world connection boundaries:

- A first eligible packet creates a session, including control-only TCP traffic.
- An initiating SYN with the same sequence in an active handshake is a retransmission.
  A handshake stops being active after non-SYN ACK/data traffic, observed completion,
  or FIN. The same SYN sequence after that point starts a new session.
- An initiating SYN with a different sequence starts a new session. A first initiating
  SYN in the reverse direction during an active handshake is retained and flagged as
  simultaneous open. A SYN following an observation that began midstream or with a
  SYN-ACK starts a new session. The previous row has `finalized_by='tuple_reuse'`.
- FIN records evidence and retains the session for trailing ACKs and retransmissions.
  RST is included in the row and finalizes it immediately with `reset`.
- A per-interface watermark is the maximum valid timestamp in the current section,
  including ineligible records. Update it, expire old sessions, then account for the
  current record. Expiry uses **strictly greater than** last valid activity plus timeout.
  Exact-threshold activity remains in the session. Expiry emits `idle_timeout`.
- A packet is late when its timestamp is below the watermark preceding that record.
  It may join an active session; already emitted sessions cannot reopen. A late packet
  after expiry/reset/reuse can create a new partial observation.
- One missing timestamp disables idle expiry for that session. Time extrema still
  summarize known timestamps, but duration is NULL. All-missing extrema are NULL.
- Section changes emit `section_boundary`, including a trailing empty section. EOF
  emits `eof`. Every section gets fresh clocks.

Timeout defaults are five minutes for TCP and one minute for UDP. Zero disables idle
expiry. NULL, calendar months, negative total durations, and fixed-duration conversion
overflow are errors. `max_active_flows` defaults to 16,384; callers may lower it to
1..16,384 to impose a stricter per-worker bound. Exhaustion fails the query; no sessions
are evicted or silently split to meet a resource limit.

`handshake_complete` requires observed initiating SYN, opposite SYN-ACK acknowledging
SYN+1, then initiating-side non-SYN ACK with matching sequence and acknowledgement
(including unsigned sequence wrap). TCP Fast Open or missing/out-of-order evidence
can leave it false despite a real handshake. It does not mean application success.
`partial_session` is true for UDP; for TCP it is true unless handshake evidence and
RST or FIN in both directions were observed. False is only this evidence test, not a
promise that the entire connection was captured. `ambiguous` flags equal endpoints,
simultaneous open, late/missing timestamps, or first-packet orientation. These flags
are deliberately conservative and do not prove a real-world boundary.

## Accounting and schema

Per-direction counters are checked UBIGINTs. Captured bytes sum captured frame
lengths; reported bytes sum original frame lengths; payload bytes sum captured TCP/UDP
payload lengths. Retransmissions are included. These are observed volumes, not unique
reassembled bytes. TCP flag unions and evidence columns are NULL for UDP.

`first_packet_number` and `last_packet_number` describe capture order. Time columns
are minimum/maximum known packet timestamps in DuckDB microseconds. Fully timed
`duration` is their nonnegative difference as INTERVAL; arithmetic overflow fails.
Opt-in Hive columns are appended after the following complete base schema:

| Column | Type |
| --- | --- |
| `filename` | VARCHAR |
| `input_index` | UBIGINT |
| `flow_id` | UBIGINT |
| `section_number` | UINTEGER |
| `interface_id` | UINTEGER |
| `vlan_ids` | USMALLINT[] |
| `first_packet_number` | UBIGINT |
| `last_packet_number` | UBIGINT |
| `transport` | VARCHAR |
| `ip_version` | UTINYINT |
| `orig_ip` | VARCHAR |
| `orig_port` | USMALLINT |
| `resp_ip` | VARCHAR |
| `resp_port` | USMALLINT |
| `originator_basis` | VARCHAR |
| `orig_packets` | UBIGINT |
| `resp_packets` | UBIGINT |
| `orig_captured_bytes` | UBIGINT |
| `resp_captured_bytes` | UBIGINT |
| `orig_reported_bytes` | UBIGINT |
| `resp_reported_bytes` | UBIGINT |
| `orig_payload_bytes` | UBIGINT |
| `resp_payload_bytes` | UBIGINT |
| `first_timestamp` | TIMESTAMP |
| `last_timestamp` | TIMESTAMP |
| `duration` | INTERVAL |
| `missing_timestamp_packets` | UBIGINT |
| `late_packets` | UBIGINT |
| `orig_tcp_flags` | USMALLINT |
| `resp_tcp_flags` | USMALLINT |
| `handshake_complete` | BOOLEAN |
| `syn_seen` | BOOLEAN |
| `fin_seen` | BOOLEAN |
| `reset_seen` | BOOLEAN |
| `simultaneous_open` | BOOLEAN |
| `equal_endpoints` | BOOLEAN |
| `partial_session` | BOOLEAN |
| `ambiguous` | BOOLEAN |
| `finalized_by` | VARCHAR |

## Memory and filtering

```sql
SET packetquapture_flow_memory_mb=192; -- default: four 48 MiB workers
SET threads=8;
```

Flow scans in one query share `min(packetquapture_flow_memory_mb MiB, memory_limit/2)`.
Each worker reserves 48 MiB through DuckDB's buffer manager before opening a source.
This is independent of the larger TCP reconstruction reservation. Binding counts scan
instances and plan copies to divide optional worker slots conservatively. At least one
starter slot is required per concurrently initialized scan; no worker waits for memory
while holding session state. Optional admission contention can reduce concurrency;
failed starter admission is an explicit error. Fully pruned scans require no slot.
Normal completion, LIMIT, interruption and errors release reservations and descriptors.

The state map has at most 16,384 entries. Each expirable session has one indexed expiry
entry, replaced on activity rather than accumulating stale per-packet heap entries.
There are at most 65,536 interface clocks and interface definitions per section. The
core emits one completed row at a time. SQL drains at most one vector and approximately
1 MiB of estimated row output per call; DuckDB owns its output vectors.

On this Linux x86-64 build, the standalone heap probe measured 8,388,720 allocated bytes
for 16,384 timed active sessions and 15,732,752 bytes including 65,536 interface clocks.
The state value itself is 296 bytes. The 48 MiB reservation additionally allows capture
interface metadata, the existing maximum 16 MiB interface-description block, bounded
header/output storage, and allocator margin. This is a conservative admission envelope,
not a cross-platform RSS measurement. Remote 4 MiB cache windows remain separately
charged to DuckDB's buffer manager. Re-measure for other allocators/platforms.

Only filename and Hive predicates prune inputs. Session time, port and counter filters
remain after aggregation: dropping packets would change counts and watermark behavior.
Existing path-pruning zero-open behavior is retained, including with progress enabled.

## Reproduction and validation

```sh
python3 scripts/generate_flow_captures.py
cmake --build build/release --target libduckdb.so shell unittest -j 4
./build/release/test/unittest 'test/sql/*'
c++ -std=c++17 -Wall -Wextra -Werror -O1 -g \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  -Isrc/include src/flow_aggregator.cpp test/unit/flow_aggregator_test.cpp \
  -o build/flow_aggregator_test
./build/flow_aggregator_test
clang++ -std=c++17 -O1 -g -fsanitize=fuzzer,address,undefined \
  -Isrc/include src/flow_aggregator.cpp test/unit/flow_aggregator_fuzz.cpp \
  -o build/flow_aggregator_fuzz
./build/flow_aggregator_fuzz -runs=20000 -max_len=4096
c++ -std=c++17 -O2 -Isrc/include src/flow_aggregator.cpp \
  test/unit/flow_memory_probe.cpp -o build/flow_memory_probe
./build/flow_memory_probe # Linux/glibc measurement only
python3 scripts/benchmark_header_reads.py
python3 test/unit/file_pruning_test.py
python3 scripts/benchmark_flows.py
```

The pure test compares 400,000 deterministic randomized UDP observations against an
independent reference sessionizer and checks lifecycle fixtures, scope isolation,
thresholds, missing/regressing times, equal endpoints, capacity, and conservation.
Fuzz coverage checks mixed TCP/UDP lifecycle and conservation. SQL checks full rows
across 1/2/4/8 thread settings, duplicates, Hive/filename pruning and post-aggregation
time predicates. Native concurrency/progress suites include read_flows, worker limits,
interruption, LIMIT, error cleanup, shared budgets, prepared reuse and ID overflow.

The synthetic selective-I/O fixture contains 60,070,024 bytes: read_flows reads exactly
70,024 bytes (framing and transport headers), preserving payload-length counts while
skipping payload reads on local seekable files. Remote cache windows may fetch adjacent
payload bytes; no claim of zero remote payload transfer is made.

The benchmark uses eight duplicate input occurrences, controlled packet counts, a warm-up,
and uncontrolled local OS cache. Its JSON records machine/compiler information and raw
trial times. It is not a cold-storage benchmark or a performance guarantee. Hosted native
platform CI must pass on the proposed change before calling the phase release-ready.
