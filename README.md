# PacketQuapture

PacketQuapture is a native DuckDB extension for querying packet captures where they already live. Point DuckDB at
one PCAP, a list of captures, or a folder glob and get one row per packet—no import or conversion step required.

```sql
SELECT filename, timestamp, captured_length, link_type
FROM read_pcap('captures/**/*.pcap*')
WHERE captured_length > 1000;
```

The current vertical slice reads classic PCAP and PCAPNG through DuckDB's filesystem abstraction. It supports
`VARCHAR`, `LIST<VARCHAR>`, and glob inputs, classic microsecond and nanosecond timestamps, PCAPNG interface timestamp
resolution, Enhanced Packet Blocks, Simple Packet Blocks, and projection pushdown for raw packet bytes.

## Output

`read_pcap(...)` returns:

| Column | Type | Meaning |
| --- | --- | --- |
| `filename` | `VARCHAR` | Capture path selected by the input or glob |
| `packet_number` | `UBIGINT` | One-based packet number within the file |
| `timestamp` | `TIMESTAMP` | Capture time, or `NULL` when the block has none |
| `captured_length` | `UINTEGER` | Bytes present in the capture |
| `original_length` | `UINTEGER` | Original on-wire packet length |
| `link_type` | `UINTEGER` | PCAP/PCAPNG link-layer type |
| `interface_id` | `UINTEGER` | PCAPNG interface index; zero for classic PCAP |
| `packet_offset` | `UBIGINT` | Byte offset of the packet payload in its file |
| `capture_format` | `VARCHAR` | `pcap` or `pcapng` |
| `packet_data` | `BLOB` | Raw captured packet bytes |
| `section_number` | `UINTEGER` | One-based PCAPNG section; one for classic PCAP |

If `packet_data` is not selected, PacketQuapture does not materialize packet blobs. This keeps metadata queries such as
`count(*)` cheap while retaining zero-preprocessing access to packet payloads when needed.

## Protocol decoding

The experimental `read_packets(...)` function adds Ethernet/VLAN, IPv4/IPv6, and TCP/UDP fields to the raw
capture columns. Unsupported or malformed protocols retain their raw rows with nullable decoded fields.

```sql
SELECT src_ip, src_port, dst_ip, dst_port, tcp_flags
FROM read_packets('captures/**/*.pcap*')
WHERE tcp_syn AND NOT tcp_ack_flag AND dst_port = 443;
```

See [the decoded schema and supported protocols](docs/PROTOCOL_DECODING.md) for column types, truncation and
fragmentation behavior, projection-driven decoding, current limitations, and reproducible tests.

`read_dns(...)` adds DNS question names, response codes, and structured answer records, with diagnostics
for malformed messages. See [DNS packet queries](docs/DNS.md) for examples and supported transports.
Scalar filters run inside the reader before later decoding and raw payload reads when DuckDB can push them down.

`read_dns_messages(...)` reconstructs TCP DNS messages split across packets, with retransmission handling
and explicit gap/conflict diagnostics. See [DNS reassembly](docs/DNS_REASSEMBLY.md) for SYN requirements,
file scope, and memory bounds.

`read_tcp_streams(...)` exposes reconstructed bytes for every TCP port, including explicit chunks and gaps.
DNS framing uses this same transport engine. See [TCP streams and the shared architecture](docs/TCP_STREAMS.md).

## Parallel capture collections

`read_pcap`, `read_packets`, and `read_dns` scan independent files on DuckDB workers.
Use `SET threads=8` to allow up to eight workers; one file remains sequential.
Input lists retain repeated paths, and packet numbers and offsets remain file-relative.
Results have no global ordering guarantee; use `ORDER BY` when needed.

`read_tcp_streams` and `read_dns_messages` also scan whole files in parallel, with
stable IDs for the same input list and a shared memory admission budget. See
[parallel stream scans](docs/PARALLEL_STREAMS.md) and the
[multicore benchmark](docs/STREAM_MULTICORE_BENCHMARK.md).

## File filters and partition columns

All five readers skip captures excluded by a filter on `filename`. Stream IDs and
duplicate input occurrences are preserved. `EXPLAIN` shows `Scanning Files: selected/original`.

For directory layouts such as `dt=2026-09-18/host=fw01/capture.pcap`, opt in to
partition columns and filter by them before captures are opened:

```sql
SELECT dt, host, count(*)
FROM read_dns_messages(
    'captures/dt=*/host=*/*.pcap',
    hive_partitioning=true,
    hive_types={'dt': DATE}
)
WHERE dt=DATE '2026-09-18' AND host='fw01'
GROUP BY dt, host;
```

Partition columns are appended to the existing schema and default to VARCHAR.
Use `hive_types` for explicit types or `hive_types_autocast=true` for DuckDB's
inference. Layouts must have consistent keys; names that collide with reader
columns are rejected. Directory dates describe the layout, not packet timestamps.

Excluded literal paths cause no execution-time file opens or HTTP requests, even
with progress enabled. Glob expansion still lists inputs. See the
[file pruning contract and validation](docs/FILE_PRUNING_DESIGN.md).

## Scan progress

Use `SET enable_progress_bar=true` to report bytes processed across capture inputs, including
parallel and cached scans. See [progress reporting](docs/SCAN_PROGRESS.md) for client settings,
metadata-request costs, and behavior for pipes and stream reassembly.

## Remote capture reads

Remote captures use [shared 4 MiB read windows](docs/REMOTE_CACHE.md) through DuckDB's
external file cache. Repeated queries on the same database can reuse packet bytes, while
local files retain selective seeks. HTTP and MinIO benchmarks verify request counts,
transferred bytes, cache controls, and repeated-query reuse. The
[original benchmark](docs/REMOTE_IO_BENCHMARK.md) records the uncached baseline. The
[1 GiB scale check](docs/REMOTE_CACHE_SCALE.md) shows how reuse changes under memory pressure.
The [in-cluster follow-up](docs/REMOTE_CACHE_INCLUSTER.md) compares direct access with the counting proxy.

## Build and test

The repository includes DuckDB and its extension build tooling as submodules.

```sh
GEN=ninja make debug
python3 scripts/generate_test_captures.py
python3 scripts/generate_protocol_captures.py
python3 scripts/generate_dns_captures.py
python3 scripts/generate_reassembly_captures.py
python3 scripts/generate_tcp_stream_captures.py
python3 scripts/generate_partition_captures.py
make test_debug
```

The debug DuckDB shell and loadable extension are written under `build/debug/`.

## Release support

PacketQuapture supports the DuckDB version recorded in `.github/duckdb-version`. Pull requests test a reduced native
platform set, while pushes test Linux, macOS, and Windows on their supported x64 and ARM64 runners.

A weekly compatibility build runs against DuckDB `main` to expose internal C++ API changes before a release. A daily
release watcher notices new stable DuckDB tags and runs the complete native build and SQL test matrix. Only if every job
passes does it create a `duckdb-vX.Y.Z` GitHub Release containing platform-labelled extension binaries, compressed
copies, and checksums. A build or test failure prevents publication.

WebAssembly builds are intentionally excluded from this native release policy until the browser file-access contract is
defined and tested.

## Direction

This is the storage foundation for a PCAP lake rather than a Wireshark replacement on day one. Natural next layers
are deeper protocol-specific table functions, filter pushdown, file-level statistics and indexes,
parallel stream scans, and a WebAssembly-friendly build. Keeping raw framing separate from protocol dissection lets those
features evolve without requiring captures to be rewritten.

The implementation roadmap, architectural boundaries, acceptance criteria, and licensing notes are in
[`docs/HANDOFF.md`](docs/HANDOFF.md).

PacketQuapture is licensed under the MIT License.

## Session summaries

Use `read_flows` for payload-free, bidirectional TCP/UDP session counts and timing.
See [session semantics, schema, and resource limits](docs/FLOWS.md).

## Capture inventory

Use `capture_inventory` to inspect capture metadata and explicitly refresh a stored
catalog. See [identity, refresh, and error semantics](docs/CAPTURE_INVENTORY.md).
Packet readers can use [catalog-assisted time selection](docs/CATALOG_PRUNING.md)
with an explicit immutable-archive guarantee.

Export selected raw packets with `COPY (...) TO 'selected.pcap' (FORMAT PCAP, LINKTYPE 1)`.
See [PCAP export, ordering and publication](docs/PCAP_EXPORT.md) for required columns
and failure behavior.
