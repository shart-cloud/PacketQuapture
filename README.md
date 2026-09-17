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
WHERE dst_port = 443;
```

See [the decoded schema and supported protocols](docs/PROTOCOL_DECODING.md) for column types, truncation and
fragmentation behavior, projection-driven decoding, current limitations, and reproducible tests.

## Build and test

The repository includes DuckDB and its extension build tooling as submodules.

```sh
GEN=ninja make debug
python3 scripts/generate_test_captures.py
python3 scripts/generate_protocol_captures.py
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
parallel file scans, and a WebAssembly-friendly build. Keeping raw framing separate from protocol dissection lets those
features evolve without requiring captures to be rewritten.

The implementation roadmap, architectural boundaries, acceptance criteria, and licensing notes are in
[`docs/HANDOFF.md`](docs/HANDOFF.md).

PacketQuapture is licensed under the MIT License.
