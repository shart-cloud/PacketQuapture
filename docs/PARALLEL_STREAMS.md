# Parallel stream scans

`read_tcp_streams` and `read_dns_messages` schedule whole input occurrences on
DuckDB workers. A worker owns its reader, TCP reassembler, and pending DNS output.
No transport state crosses files, duplicate occurrences, sections, or interfaces.
One file remains sequential. SQL filtering still follows reconstruction.

## Identifier contract

`stream_id` remains UBIGINT and identifies a direction within one function call.
For a one-based file-local direction number L, zero-based input occurrence I,
and expanded input count N, its value is `(L - 1) * N + I + 1`.
This includes resource diagnostics and distinguishes repeated paths. All DNS
messages belonging to one direction retain its ID. UDP IDs remain null.

IDs are independent of worker scheduling and thread count for the same ordered
expanded inputs, contents, and reader options. Single-file numbering is unchanged;
multi-file numbering changes from the previous sequential implementation. They
are not persistent identifiers: input-list changes (including glob expansion)
can change them. Do not join the two functions using IDs: their traffic selection
differs. Arithmetic overflow is an explicit error. Output order is unspecified.

## Memory admission

```sql
SET packetquapture_stream_memory_mb = 512; -- MiB; default
SET threads = 8;
```

All stream table-function instances in one query share an admission budget of
`min(packetquapture_stream_memory_mb MiB, memory_limit / 2)`. Each active worker
reserves 128 MiB through DuckDB's buffer manager before opening a file. At most
four workers are admitted with the default setting; a 512 MiB DuckDB memory
limit permits at most two, and 256 MiB permits one. Actual concurrency is also
bounded by input count and DuckDB's available threads.

Binding counts stream scan instances and conservatively counts copied plans. Each
scan's worker ceiling is its equal share of the available slots (at least one),
also capped by input count. Plan copies may lower concurrency conservatively.
This prevents an early pipeline from consuming later scans' worker allowances.
Each nonempty scan reserves one starter slot during initialization. Remaining
workers try to acquire spare slots without blocking; workers without a slot do
not claim inputs. Scans initialized together need one starter slot each; later pipelines can reuse
slots released by finished scans. Failure to admit a starter is a clear out-of-memory error, never a partial successful scan.
Buffer-manager contention can reduce optional concurrency or fail admission.
Workers never wait for memory while holding unfinished transport state.

The per-file reconstruction policy remains 32 MiB stored TCP payload, 65,536
segments, 1,024 directions, and the existing per-direction limits. Neither the
thread count nor another file consuming its allowance changes these diagnostics.
No spilling, premature finalization, or silent eviction is introduced.

Reservations live through EOF reconstruction and pending message draining; they
are released on exhaustion, early LIMIT, cancellation, and errors. Query-end
state detaches the old budget so prepared statements and connection reuse obtain
a fresh budget. Reservations are accounted under DuckDB's EXTENSION memory tag.
They are logical capacity charges, not eagerly allocated buffers or measured RSS.

### Working allowance

The 128 MiB worker envelope is deliberately conservative for the fixed limits:

- 32 MiB captured TCP payload plus segment-vector capacity, flow-map nodes, and keys.
- Up to 1 MiB sequence span reconstructed at once, with a byte buffer and 32-bit
  owner array (5 MiB), bounded offsets, provenance, chunks, and gaps. At most two
  directions retire on one packet; EOF drains one at a time.
- DNS framing retains at most 4,096 messages from one direction (plus a possible
  terminal diagnostic), with at most 1 MiB of framed payload.
- Stream readers reject more than 65,536 PCAPNG interfaces in one section. Interface
  blocks retain the existing 16 MiB bound. Section options are skipped incrementally
  instead of allocating the entire section-header block. Supported IP payloads and
  bounded header decoding do not allocate the capture record's full padding.
- Output batches stop after a conservative 1 MiB logical weight, allowing one final
  row to exceed the threshold. TCP weights include payload and nested elements;
  DNS weights include expanded decoded records. This prevents 2,048 maximal rows
  from accumulating in a worker's output chunk. Transient Value copies and container
  capacity have headroom in the envelope.

This is an admission envelope for bounded worker-owned state, not an exact malloc
tracker or a total-process memory guarantee. Input path lists, file-system/client
internals, DuckDB result storage and downstream operators are outside this budget.
Remote cache pins are already accounted by DuckDB; they must not be double-charged.
Future changes to transport limits or allocation structures must revisit the
allowance. Tiny captures still require a full slot; this favors predictable behavior
over maximum concurrency under very small memory limits.

## Research basis

- [PostgreSQL scanner](https://raw.githubusercontent.com/duckdb/duckdb-postgres/main/src/postgres_scanner.cpp):
  shared work assignment, worker-local readers, optional admission when connections run out.
- [Parquet](https://duckdb.org/docs/stable/data/parquet/overview): file-relative identity
  via file_row_number and filename, independent of output arrival order.
- [Pinned DuckDB buffer manager](https://github.com/duckdb/duckdb/blob/d8cdaa33fda8df955cc76ef58a280f68f4cd43fa/src/storage/standard_buffer_manager.cpp):
  ReserveMemory/FreeReservedMemory account for extension-owned capacity. Temporary
  operator reservations alone are not a physical-memory grant or an automatic spill path.

These informed the design; none provides TCP reconstruction directly.

## Local validation — September 18, 2026

- Release and fully thread-sanitized SQL suites: 1,196 assertions across eight cases passed.
- Native release and ThreadSanitizer checks: simultaneous file readers, one-file and
  one-thread bounds, cancellation, worker errors, early LIMIT with pending DNS output,
  descriptor cleanup, reservation release/reuse, prepared execution, and ID overflow passed.
- Live descriptor counts matched one, two, and four workers at 128, 256, and 512 MiB
  admission budgets. Queries with both reader types exercised shared-query accounting.
- Memory-pressure comparisons across 256 MiB, 512 MiB, and 1 GiB DuckDB limits
  preserved bytes, provenance, IDs, gaps, and diagnostics for full 32 MiB reassemblers
  and heavily fragmented directions. Large section-option skipping and interface
  bounds passed. These checks do not establish a general RSS ceiling.
- Native progress tests passed against release and thread-sanitized libraries.
- Transport and DNS-framing tests passed with AddressSanitizer/UndefinedBehaviorSanitizer.
- 200 randomized multiset comparisons passed (10 mixes, all five readers, four thread counts).
- Nine request-instrumentation and nine remote-cache integration tests passed, as did
  selective-read byte counts, truncation, and named-pipe regressions.
- Repository formatting and whitespace checks passed.

Coverage is in `test/sql/parallel_streams.test`, `test/unit/parallel_scan_test.cpp`,
`test/unit/stream_memory_test.py`, and the existing progress/cache suites. CI wiring
includes the new tests; hosted CI was not run during local implementation validation.
Local multicore timing and memory measurements are reported separately in
[the stream benchmark](STREAM_MULTICORE_BENCHMARK.md).
