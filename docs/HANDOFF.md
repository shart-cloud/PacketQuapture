# PacketQuapture Handoff

## Active next-work handoff (2026-09-18)

Start with [Current implementation and next steps](CURRENT_HANDOFF.md). It records the
packet parallelism, shared remote cache, scan progress, validation, benchmark
results, and operational cleanup. Packaging and hosted CI status are recorded there. The [original multicore plan](MULTICORE_HANDOFF.md)
remains useful for the pending stream-reader work. The broader roadmap below includes
historical phases; consult the current handoff before selecting unfinished work.

## Mission

PacketQuapture is the storage and query foundation for a PCAP lake. Its job is to let DuckDB scan capture files where
they already live, using normal SQL over individual files, lists, and folder globs. It is not intended to reproduce
Wireshark's user interface or complete protocol coverage in its first releases.

The project should preserve this layering:

```text
capture bytes
    -> PCAP/PCAPNG framing
    -> immutable packet view
    -> optional protocol decoders
    -> DuckDB vectors

capture files
    -> optional file statistics/index catalog
    -> file and range pruning
```

Raw framing is the stable foundation. Protocol dissection, indexing, and presentation should evolve without rewriting
or taking ownership of the source captures.

## Current state

The native C++ extension provides `read_pcap`, `read_packets`, `read_dns`, `read_tcp_streams`, and
`read_dns_messages`, accepting a path or list of paths. DuckDB's `MultiFileReader` expands exact paths, lists,
and globs, and DuckDB's filesystem abstraction opens each file. The three packet readers scan
whole files in parallel; the two stream readers remain sequential. All five support shared
remote caching and optional byte-based scan progress.

Supported capture framing:

- Classic PCAP in little- and big-endian forms.
- Classic PCAP timestamps with microsecond or nanosecond resolution.
- PCAPNG Section Header, Interface Description, Enhanced Packet, and Simple Packet blocks.
- Multiple PCAPNG sections and interfaces.
- PCAPNG `if_tsresol` timestamp resolution.
- Safe skipping of unknown PCAPNG blocks.

The current row contains capture identity, packet number, timestamp, captured/original lengths, link type, interface,
packet byte offset, capture format, raw packet data, and PCAPNG section number. Projection pushdown avoids materializing
`packet_data` unless the query requests it. A 256 MiB captured-packet limit protects against corrupt length fields.

There is deliberately no libpcap dependency. This keeps distribution simple and avoids tying the parser to native-only
I/O APIs.

### Known limitations

- Experimental `read_packets` now decodes Ethernet/VLAN, IPv4/IPv6, TCP, and UDP. See `docs/PROTOCOL_DECODING.md` for the schema and limits.
- Single-file scans and the two stream readers remain sequential; the three packet readers
  distribute input files across workers.
- Projection and scalar filter pushdown are implemented; file-statistics pruning and indexed range scans remain future work.
- There is no persistent file-statistics catalog or packet index.
- PCAPNG support is intentionally focused on packet-bearing and interface metadata blocks.
- Native release builds exclude WebAssembly until the browser file-access contract is defined.
- DuckDB's C++ extension API is version-specific, so every binary must match its DuckDB version and platform.

### Performance baseline

On the initial WSL2 development machine, an optimized DuckDB 1.5.5 build scanned a synthetic 549.3 MiB classic PCAP
containing four million 128-byte packets at approximately:

| Query shape | Packet rate | Effective capture throughput |
| --- | ---: | ---: |
| Metadata-only scans | 1.1-1.3 million packets/s | 152-177 MiB/s |
| Timestamp filtering | 1.24 million packets/s | 170 MiB/s |
| Raw packet materialization | 1.07 million packets/s | 147 MiB/s |

Raw sequential reads of the same cached file exceeded 4 GiB/s. The current scanner is therefore limited primarily by
single-threaded per-packet parsing and vector population, not storage bandwidth. Keep the fixture shape, build type,
hardware, and cache state with every future benchmark result.

## Design rules

1. Source captures are immutable and authoritative.
2. A query must not require an import or conversion step.
3. Indexes and derived metadata are optional accelerators and must be rebuildable.
4. `read_pcap` remains a lossless framing interface; do not silently change its existing columns or meanings.
5. Unknown or unsupported protocols produce nullable decoded fields, not dropped packets.
6. Decode only what the projected columns and filters require.
7. All length and offset arithmetic must be bounds checked before reading or allocating.
8. Keep parsing logic independent from a particular filesystem or browser host.
9. Favor generated captures and provenance-recorded public fixtures over opaque binary test data.
10. Measure before adding caches, indexes, or custom on-disk formats.

## Target architecture

The current implementation can grow into four separable components.

### 1. Byte source and capture framing

This layer reads bytes, handles endianness and block boundaries, and emits an immutable `PacketView` with capture
metadata and a bounded byte span. It must not know about Ethernet or higher-level protocols.

Refactor the current `CaptureReader` behind a small seek/read byte-source interface. Native builds can adapt DuckDB's
`FileHandle`; WASM builds can adapt the filesystem or blob contract exposed by the host application. Tests should be
able to run the framing parser entirely from an in-memory byte array.

### 2. Protocol decoding

Decoders consume `PacketView` and return bounded views into headers and payloads. Start with:

- Ethernet II and common link types.
- 802.1Q and stacked VLAN tags.
- IPv4, including header length and fragmentation metadata.
- IPv6, with a bounded extension-header walk.
- TCP and UDP ports, lengths, flags, and payload offsets.

Every decoder must validate its own minimum length and derived offsets. A malformed layer should null that layer and
anything above it while preserving the raw packet row.

### 3. DuckDB table functions

Keep `read_pcap` as the raw contract. Add a decoded surface, tentatively `read_packets`, rather than continually
expanding the raw function. Settle names and types before declaring that schema stable.

Candidate decoded columns include:

- Source and destination MAC addresses.
- VLAN IDs.
- IP version, source, destination, protocol, TTL/hop limit, and fragmentation fields.
- TCP/UDP source and destination ports.
- TCP flags, sequence/acknowledgment numbers, and header length.
- Transport payload offset and length.

Populate DuckDB vectors directly where practical. Avoid constructing a heap-owning `Value` for every scalar cell.
Decoded byte spans should refer to the current packet buffer and never outlive it.

### 4. Optional catalog and indexes

The first catalog should operate at file granularity:

- Path or object URI.
- Size and modification identity, such as mtime, ETag, or version ID.
- Capture format and link types.
- Packet count.
- Minimum and maximum timestamp.
- Protocol counts and other inexpensive summaries.
- A fingerprint used to invalidate stale metadata.

Start with ordinary DuckDB or Parquet tables so the schema can change easily. Do not introduce a custom binary sidecar
until profiling shows that the catalog itself is a bottleneck. Catalog creation must be incremental and atomic, and a
stale entry must never cause an incorrect query result.

Packet-level indexes should come later. They are most useful for timestamp-range seeking and splitting one large file
between workers. An index must contain enough capture identity to detect replacement or truncation of the source file.

## Protocol-first implementation update

The protocol-decoding prototype was implemented ahead of the broader framing refactor and parallel scans.
`read_packets` preserves every raw column and adds nullable decoded fields. Its bounded `PacketView` decoder is
independent of DuckDB and uses projection-driven layer selection. Generated SQL fixtures and standalone sanitizer
checks cover malformed headers, fragmentation, truncation, alternate link types, and output-chunk boundaries.
On-demand header prefixes and checked payload seeks are implemented. The broader framing byte-source extraction,
and parallel scanning remain future work. Scalar filters now run in stages before raw materialization; TCP flag
booleans and the experimental `read_dns` function are implemented. The separate `read_dns_messages` function
uses a DNS framer over the shared protocol-independent TCP core. `read_tcp_streams` exposes the same core on all TCP ports; see `docs/DNS_REASSEMBLY.md` for scope and limits. See `docs/DNS.md` for DNS coverage and limits.
The decoded schema is experimental; details and validation commands are in `docs/PROTOCOL_DECODING.md`.

## Delivery roadmap

### Phase 0: Harden the framing core

Work:

- Extract framing and byte-source interfaces from DuckDB vector population.
- Add truncated-header, oversized-length, invalid-padding, interface-resolution, and multi-section cases.
- Add fuzz targets for classic PCAP and PCAPNG framing.
- Establish a reusable benchmark command and record machine/build metadata.

Exit criteria:

- Existing `read_pcap` SQL behavior remains unchanged.
- Sanitizer and fuzz smoke tests do not find out-of-bounds reads or unbounded allocations.
- In-memory and DuckDB-file-backed readers pass the same fixture corpus.

### Phase 1: Parallel folder scans

Work:

- Replace the single global reader with a thread-safe file work queue and per-thread local reader state.
- Parallelize across independent files first.
- Preserve packet numbering within each file and avoid promising global row order.
- Add multi-file benchmarks for one, two, four, and eight DuckDB threads.

Exit criteria:

- Folder scans return exactly the same rows at `threads=1` and `threads>1`.
- At least two sufficiently large files execute concurrently.
- A single file remains single-worker until a trustworthy range index exists.
- Errors identify the failing filename without losing errors from other workers.

### Phase 2: Ethernet/IP/TCP/UDP columns

Work:

- Introduce `PacketView` and bounded layer decoders.
- Add the decoded table function and projection-driven decoding.
- Cover Ethernet, VLAN, IPv4, IPv6, TCP, and UDP with generated fixtures.
- Add malformed and truncated variants for every supported layer.

Exit criteria:

- Unsupported link/protocol types still return a raw row with nullable decoded fields.
- Selecting only capture metadata does not invoke protocol decoders.
- Decoder results agree with independently generated fixture expectations.
- Public column names and types are documented before a release marks them stable.

### Phase 3: Filter pushdown

Apply filters in increasing cost order:

1. File identity and catalog statistics.
2. Capture framing fields such as timestamp, packet number, lengths, and link type.
3. Minimal Ethernet/IP/transport header decoding.
4. Raw payload materialization only for surviving rows that request it.

Exit criteria:

- `EXPLAIN` and profiling demonstrate that rejected files and packet payloads are not read unnecessarily.
- Pushdown never changes SQL null semantics or results.
- Benchmarks include selective timestamp, protocol, address, and port predicates.

### Phase 4: File statistics and indexes

Work:

- Add a table function or command that inventories a capture folder into a catalog.
- Implement identity-based invalidation and incremental refresh.
- Use timestamp and link/protocol summaries for file pruning.
- Prototype timestamp-to-offset checkpoints for large-file range scans.

Exit criteria:

- Removing the catalog only affects performance, never query correctness.
- Changed captures are detected before stale metadata is trusted.
- A selective time-range query demonstrates measurable file or range pruning.

### Phase 5: Protocol-specific table functions

Build focused functions on the shared decoded packet model rather than adding every field to one table. Likely early
targets are DNS messages, TCP flow summaries, and UDP conversations. TCP stream reassembly is a separate stateful layer
and should not be hidden inside the basic packet scan.

Each function needs explicit behavior for truncation, fragmentation, retransmission, out-of-order packets, and memory
limits. Full Wireshark protocol parity is not a project milestone.

### Phase 6: WebAssembly-friendly build

The parser is already free of libpcap, but WASM requires more than a successful Emscripten compile.

Work:

- Complete the byte-source/parser separation.
- Define how the website registers an uploaded `File`/`Blob` or mounted virtual path with DuckDB-WASM.
- Stream bounded chunks rather than copying an entire capture into extension memory.
- Build against the matching DuckDB-WASM extension ABI.
- Run the same small PCAP/PCAPNG corpus in native and WASM tests.
- Add browser tests for cancellation, large-file memory limits, malformed inputs, and repeated queries.

Exit criteria:

- Native and WASM readers produce identical rows for the shared corpus.
- A browser can query a user-selected capture without uploading it to a server.
- Peak memory is bounded independently of total capture size.
- The native release workflow remains independent from the WASM preview until the browser contract is stable.

## Recommended next pull requests

1. Review the packaged packet-scan, cache, and progress changes and complete hosted CI.
2. Put both stream functions on the existing whole-file scheduler, preserving per-file reassembly semantics
   and explicitly handling query-unique IDs and aggregate memory bounds.
3. Use profiling to select vector/filter allocation improvements or framing/byte-source extraction; tackle
   indexed single-file parallelism only after defining safe record checkpoints and transport ownership.

Implementation details and acceptance criteria are in [MULTICORE_HANDOFF.md](MULTICORE_HANDOFF.md).

## Testing strategy

- Keep SQLLogicTests for public SQL behavior and error messages.
- Use generated binary fixtures for precise endianness, timestamps, lengths, and offsets.
- Add unit tests for each decoder without requiring DuckDB.
- Maintain a small regression corpus for malformed real-world captures with recorded provenance.
- Use an external tool such as `tshark` only for optional differential testing; do not make it part of the extension.
- Test all projected-column combinations that affect whether packet bytes or protocol layers are materialized.
- Benchmark release builds only and report packet size distribution as well as file size.

Before merging a change:

```sh
make format-check
GEN=ninja make release
./build/release/test/unittest 'test/sql/*'
```

The formatter dependencies are listed in the code-quality workflow. GitHub Actions installs its own formatter and
clang-tidy toolchain.

## CI and release expectations

- `.github/duckdb-version` is the supported development baseline.
- Stable workflows and both submodules move together when that baseline changes.
- A weekly DuckDB `main` build provides early warning for internal C++ API changes.
- A new DuckDB release is publishable only after every configured native platform builds and tests successfully.
- Release artifacts are unsigned until a signing and trusted-distribution design is added.
- WebAssembly is not part of the native artifact matrix yet.

Check the latest GitHub Actions run before beginning feature work. Do not treat a locally successful Linux build as a
substitute for the macOS, Windows, and ARM jobs.

## Licensing and dependency policy

PacketQuapture is distributed under the MIT License. New project-authored source, tests, and documentation should remain
MIT-compatible.

Wireshark is a behavioral reference, not a source-code dependency. Do not copy Wireshark dissector code into this
repository or link GPL components into the MIT extension without an explicit licensing decision and review. Running an
installed `tshark` executable as an optional test oracle is a separate integration and must not make release builds
depend on it.

Before adding any parser library:

- Confirm its license is compatible with MIT distribution.
- Confirm it builds on every supported native platform and, if relevant, Emscripten.
- Record required notices and source-offer obligations.
- Compare its binary size, memory behavior, and bounds-checking model with a small internal decoder.

The root `LICENSE` was inherited from the DuckDB extension template and currently carries a DuckDB Foundation copyright
notice. Before the first public PacketQuapture release, confirm the appropriate PacketQuapture copyright attribution and
preserve all notices required by the DuckDB submodule and other dependencies. Record the origin and redistribution terms
for every checked-in capture fixture.

## Non-goals for the first PCAP-lake release

- A packet inspection GUI.
- Live interface capture.
- Full Wireshark dissector parity.
- Transparent TCP stream reassembly.
- Mandatory conversion of captures into another format.
- Mutation or annotation of the source capture.
- A custom distributed storage service.

## Definition of the first PCAP-lake milestone

The first meaningful lake milestone is complete when PacketQuapture can:

- Query PCAP and PCAPNG folder globs without preprocessing.
- Scan independent files in parallel.
- Project stable Ethernet/IP/TCP/UDP columns.
- Avoid raw packet materialization when it is not requested.
- Prune files using an optional, rebuildable statistics catalog.
- Publish tested binaries for the supported DuckDB native platforms.
- Demonstrate the same framing results in an experimental WASM build.

That milestone is intentionally smaller than Wireshark and larger than a file parser: it is a dependable SQL storage
layer on which deeper protocol analysis can be built.
