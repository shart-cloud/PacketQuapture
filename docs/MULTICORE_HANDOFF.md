# Multicore scan handoff and improvement plan

Date: 2026-09-17. Code baseline: `dd038c6`. DuckDB baseline: v1.5.5.

> Historical baseline plan. Whole-file parallelism for the three packet readers is now
> implemented in the working tree. Start with [the current handoff](CURRENT_HANDOFF.md) for
> completed work and validation; stream-reader parallelism remains pending.

## Goal and recommended delivery

Use multiple CPU cores to query capture collections without changing packet, DNS, or TCP reconstruction semantics. Start with **one complete file per DuckDB worker**. Deliver packet scans first, then put stream consumers on the same scheduler. A single capture remains sequential in this first delivery.

Reuse the existing capture reader, packet decoder, TCP core, and protocol framers. Do not create a custom thread pool, duplicate reassembly engine, or separate file scheduler for every protocol. This document records the original plan and pre-implementation baseline; current status is linked above.

## Verified starting point

All five functions accept paths, lists, and globs:

| Function | Behavior | First parallel work unit |
| --- | --- | --- |
| `read_pcap` | Raw framing and selective payload materialization | Whole file |
| `read_packets` | Link/IP/TCP/UDP fields and TCP flag booleans | Whole file |
| `read_dns` | Packet-level DNS and staged filters | Whole file |
| `read_tcp_streams` | Any TCP port; bytes, ranges, gaps, diagnostics | Whole file including finalization |
| `read_dns_messages` | UDP DNS and DNS framing over the shared TCP core | Whole file including finalization |

`PcapGlobalState` owns the sole reader, file cursor, filters, and scan options. `StreamScanState` also derives from global state and owns the sole reader, TCP engine, and pending streams; `DnsMessagesState` adds pending messages. None overrides `GlobalTableFunctionState::MaxThreads()`, whose pinned DuckDB default is 1. No function registers local initialization. Setting `threads=8` alone does not parallelize these readers.

`MultiFileReader` expands inputs with `GetAllFiles()`; it does not automatically parallelize the custom scanner. Discovery is eager and may eventually become a large-collection bottleneck.

Baseline validation: 899 SQL assertions in six tests; standalone TCP and DNS-framer sanitizer stress tests; all projected columns compared with full rows for both stream functions, including 2,500-row fixtures; deterministic fixture regeneration. These are not concurrency tests. Check branch CI before implementation; this handoff does not certify the native platform matrix.

## Source map

- `src/packetquapture_extension.cpp`: `PcapBindData`, `PcapGlobalState`, `PcapInit`, `PcapScan`, `PacketFilter`, `ScanOptions`, `CaptureReader`, `StreamScanState`, `NextStreamEvent`, stream init/scan callbacks, registrations.
- `src/packet_decoder.cpp`: bounded projection-driven packet decoding.
- `src/tcp_reassembly.cpp` and `src/include/tcp_reassembly.hpp`: protocol-independent TCP state and limits.
- `src/dns_tcp_framer.cpp`: application message boundaries; no transport state.
- `src/dns_decoder.cpp`: complete DNS message decoding.
- `duckdb/src/include/duckdb/function/table_function.hpp`: version-matched `MaxThreads`, global/local state, and `table_function_init_local_t`. Verify callback and ownership conventions against checked-out DuckDB examples.
- `scripts/benchmark_header_reads.py`: selective-read/filter I/O checks, not a multicore throughput benchmark.
- `test/sql/`, `test/unit/`, capture generators, `.github/workflows/ProtocolDecoders.yml`: regression fixtures and sanitizer commands.

## PR 1: Shared file scheduler and parallel packet scans

Keep bind data immutable. Introduce a shared file scheduler and worker-local scan state for `read_pcap`, `read_packets`, and `read_dns`.

Global state should own immutable projection/decode requirements, owned filter definitions, the work cursor, and optional progress counters. The file list can remain bind-owned with a verified lifetime. Each input-list occurrence is a separate work item, including repeated paths.

Local state owns one reader/file handle, packet buffers, mutable filter executors/input chunks, scratch vectors, and scan options. Register `init_local`, override `MaxThreads()` according to eligible file work, and consume `input.local_state` in scan callbacks. Let DuckDB schedule workers and enforce its thread setting. Follow the pinned API's empty-input conventions. Lock only to claim work or update accounting, never around file opening, reads, decoding, or output.

**Filter race to avoid:** `PacketFilter::Matches` resets a mutable `DataChunk` and uses an `ExpressionExecutor`. Today's `ScanOptions::matches` lambda captures global state. Sharing these objects or copying that callback into every worker is unsafe. Own/clone immutable definitions with appropriate lifetime, construct executors per worker, and capture each local state's stable lifetime. Preserve stage order and SQL null semantics.

A worker reads a file sequentially and then claims another. Empty or fully filtered files must not cause a premature empty output batch while work remains. Preserve file-relative packet numbers and offsets. No global row ordering is promised; callers use `ORDER BY` when needed.

Use DuckDB's error/cancellation path. Include filename and available packet/offset context in failures, cancel other work, and release handles. Do not promise to collect every simultaneous error after the query has already failed.

Acceptance:

- Equal row multisets at `threads=1,2,4,8`, covering duplicate paths, empty files, rejected files, mixed PCAP/PCAPNG, null fields, and batches crossing file boundaries.
- A bounded diagnostic/test demonstrates at least two readers overlap on sufficiently large inputs; timing alone is not proof.
- Existing selective reads and staged filters retain their I/O behavior.
- One file remains one worker; cancellation and worker exceptions clean up other readers.

## PR 2: Parallel stream consumers on the same scheduler

Move stream scan state to worker-local ownership and keep `NextStreamEvent` shared. A work item owns the TCP engine, pending streams, and pending DNS messages until completely drained. At EOF, emit all finalization output under the correct filename before claiming another file. Never carry flows across captures with matching endpoints.

Preserve file/section/interface/VLAN isolation, capture-order input within each file, first-receipt provenance, wraparound, tuple reuse, and reverse-direction reset behavior. Generic streams retain unanchored ranges; DNS still requires known framing alignment. Leave stream predicates after reconstruction: timestamp, flag, and message filters can remove segments required for a correct result.

### Stream identifiers

The current single reassembler survives file transitions and increments `next_id` throughout the scan. Separate worker engines would create colliding `stream_id` values if exposed directly. Existing IDs are scan-local and directional, not durable identifiers.

Recommended initial policy: translate core IDs to query-unique IDs at the SQL boundary using a global atomic allocator and per-file mapping. Every DNS message from one direction must reuse the same translated ID. Include diagnostics; preserve existing UDP identifier/null behavior. Retire mappings after all output for a finalized direction drains, rather than retaining all historical streams. Keep allocation out of the packet hot path.

Document that numeric IDs can differ across worker schedules and repeated queries. Do not pack file ordinal and stream number into arbitrary bit widths without overflow checks. Deterministic IDs require a separately reviewed contract; avoid a full pre-scan just to preserve numbering.

Normalize IDs for cross-thread semantic comparisons, then separately verify query-wide uniqueness and message grouping. Raw numeric ID equality is not a valid parallelism requirement.

### Aggregate memory

Each TCP core currently permits 1,024 directions, 32 MiB stored payload, 1 MiB payload/sequence span per direction, 4,096 segments per direction, and 65,536 segments total. DNS adds a 4,096-message limit per direction. Eight workers can retain 256 MiB of payload alone. Maps, provenance, reconstruction, pending output, and DuckDB vectors need additional memory. Standard-library allocations must not be assumed to respect DuckDB's memory limit.

For the first version, preserve per-file limits and cap concurrent stream workers through an explicit query-level reservation policy. Wait before claiming a file, not while holding partial flows whose completion needs more memory. Measure overhead to justify reservation size; call it an estimate unless all allocations are accounted for. Document the worker cap. Changing the thread setting must not silently change per-file acceptance limits.

Avoid a shared byte counter that rejects arbitrary packets depending on scheduling: that can change diagnostic results between runs. Precise accounting/spill can follow, but no silent active-flow eviction or weakened conflict validation. EOF-delayed output is intentional because a late conflicting retransmission may invalidate a direction.

Acceptance:

- Both stream functions use the common scheduler and TCP engine.
- Parity at 1/2/4/8 threads covers gaps, conflicts, retransmissions, wraparound, missing SYN, tuple reuse, FIN/RST, interleaved directions, limits, and multiple output chunks.
- Matching endpoints in different files/sections/interfaces/VLANs never stitch together; repeated paths remain separate occurrences.
- No ID collisions or message/filename mix-ups; reservations and handles release on EOF, exception, and cancellation.

## Benchmark and concurrency validation

Add `scripts/benchmark_parallel_scans.py`. Generate large fixtures under ignored `build/`; do not commit them. Record revision, DuckDB version, release flags, CPU/core count, OS/storage, threads, capture shape, cache state, wall/CPU time, utilization, peak RSS, rows/s, and source MiB/s. Source throughput is not physical bytes read when projection skips payload.

Use the same total bytes as one file and 2/4/8 independent files. Include many tiny files and one dominant file among smaller ones. Repeat trials at 1/2/4/8 threads and report median/spread. Label warm-cache runs and document any cold-cache procedure. Do not make noisy speedup thresholds a CI correctness gate.

Cover metadata counts, transport columns, selective flag/address/port filters, raw blobs, packet DNS, stream counts, stream bytes/chunks, and reconstructed DNS messages. Keep throughput fixtures below reassembly limits; benchmark limit handling separately. Avoid printing all rows; use aggregates that force the intended columns and check the query plan.

Compare row multisets including duplicate multiplicity (`EXCEPT ALL` both ways or canonical comparison). Repeat randomized file mixes to expose races. Retain projection parity tests. Run ASan/UBSan and add ThreadSanitizer where supported by the toolchain/DuckDB build, documenting exclusions. Exercise cancellation and error cleanup with bounded timeouts.

Report scaling and single-thread regressions. Storage, file imbalance, output allocation, or aggregation can limit speedup. Whole-file parallelism is expected to leave single-file performance unchanged.

## One large capture: separate design phase

Never split arbitrary byte ranges or search payload for plausible record headers. Classic PCAP records vary in length; PCAPNG additionally depends on section byte order, interface metadata, and timestamp resolution. A valid checkpoint needs a verified record boundary, prefix packet number, framing state, and source identity.

For stateless packet scans, profile two options:

1. Sequential framing with bounded owned packet batches sent to decode workers. No mandatory index, but framing can remain the bottleneck. Preserve selective reads and safe buffer lifetime.
2. Optional rebuildable checkpoints for independent range readers. Keep sequential fallback, invalidate stale/replaced/truncated sources, restore all PCAPNG state, and assign each boundary record exactly once. Measure index creation and repeated-query break-even cost.

Neither automatically parallelizes TCP. Future flow dispatch must place **both directions** of a connection on one shard: SYN/RST can affect the reverse direction. Use a canonical bidirectional key including file/section/interface/VLAN scope, preserve capture order per shard, and bound queues with backpressure. Range-local reassembly plus concatenation is incorrect; fixed overlap cannot cover arbitrarily long flows. Measure the sequential producer before building this complexity.

## Other improvements, prioritized

| Priority | Improvement | Evidence or completion requirement |
| --- | --- | --- |
| Alongside multicore | Cancellation, progress, resource visibility | Check interruption in long no-output loops; useful counters without packet-level shared contention |
| Next | Profile vector output and filter cost | Current scalar `SetValue` and one-row expression evaluation may be hot; measure before direct-vector writes or predicate batching; preserve nulls and selective reads |
| Next | Extract framing behind a byte-source interface | Same in-memory/filesystem malformed PCAP/PCAPNG corpus, parser fuzz targets, preserved prefix reads and checked seeks |
| Next | Configurable validated transport limits and accounting | Shared core owns limits; explicit diagnostics and boundary tests; no silent eviction or unsafe early output |
| Next | Optional file statistics and pruning | Rebuildable DuckDB/Parquet metadata, identity-based invalidation, unknown/stale entries fall back to scanning; timestamps may be unsorted |
| After profiling | Segment lookup/copy improvements | Current duplicate detection scans stored segments; stress high-segment flows and preserve overlap/provenance semantics |
| After scheduling | Lazy file discovery and work balance | Measure glob startup/memory and size skew; preserve list occurrences and DuckDB filesystem support |
| Later | New protocol adapters | Consume shared TCP ranges, define message alignment/gap/size rules, keep protocol logic outside transport |
| Separate feature | IP fragment reassembly | Shared bounded layer before transport with explicit identity, overlap, lifetime, and resource policy |

Keep native platform/release and licensing checks. WASM remains a separate host/file-access milestone; keep filesystem and threading assumptions out of the standalone protocol core.

## Starting instructions

1. Read this document, `docs/TCP_STREAMS.md`, and `docs/DNS_REASSEMBLY.md`; inspect branch status and CI.
2. Reproduce the existing release/SQL baseline and standalone sanitizer checks.
3. Implement PR 1 with parallel correctness tests and the benchmark harness.
4. Review identifier and aggregate-memory policy, then implement PR 2 on the same scheduler.
5. Use measured results to choose vector work, framing extraction, or indexed single-file scans next.

```sh
make format-check
GEN=ninja make release
./build/release/test/unittest 'test/sql/*'
python3 scripts/benchmark_header_reads.py  # Linux strace dependency
```

Install the formatter/toolchain dependencies first. The sanitizer workflow contains standalone build commands. Keep fixture generators deterministic and run `git diff --check` before handing off implementation.
