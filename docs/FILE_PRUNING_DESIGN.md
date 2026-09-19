# File pruning and partition columns

Status: implemented and locally validated, September 18, 2026. This document
records the design and supported contract. Baseline: PacketQuapture `60d6bd1`, DuckDB v1.5.5
(`d8cdaa33fda8df955cc76ef58a280f68f4cd43fa`). Stream parallelism was merged in
[PR #2](https://github.com/shart-cloud/PacketQuapture/pull/2).

## Decision

Add file selection before opening captures, in two small implementation changes:

1. Prune by the existing `filename` column in all five readers. Preserve original
   input occurrences and stream IDs. Add explicit file-count information to EXPLAIN.
2. Add opt-in Hive partition columns, then use those constants for the same pruning.

Reuse DuckDB's exported path parsing, value conversion, and file-filter evaluation
helpers. Keep PacketQuapture's whole-file scheduler and worker-local reconstruction.
A wholesale conversion to `MultiFileFunction` is unnecessary for these two changes
and would entangle reader lifecycle, memory admission, and pending stream output.

Do not add a persistent catalog, packet-range pruning, dynamic join pruning,
compression, or a guessed bytes-per-row estimator in these changes. Those require
separate evidence and contracts. This design does not promise reduced object-listing
cost or any particular throughput improvement.

## Observed baseline

Small probes against the release build established the following:

- All five readers still open an existing malformed file excluded by
  `WHERE filename = '<other valid file>'`; each query failed on that file before this change.
- With two literal loopback HTTP URLs pointing at the same 252,594-byte fixture,
  all five readers fetched the excluded URL: one HEAD, one GET, and 252,594 body
  bytes. Results were unchanged with progress reporting enabled or disabled.
- Plain EXPLAIN showed approximately one row for each reader. The pinned
  `LogicalGet::EstimateCardinality` falls back to one when no estimate is provided.

Probe outputs are local, ignored build artifacts:
`build/pruning-design-baseline.json` and
`build/pruning-design-remote-baseline.json`. These are request-count and behavior
checks, not the deferred parallel-throughput benchmark.

## SQL contract

Filename pruning is automatic and does not change schemas:

```sql
SELECT count(*)
FROM read_packets(['captures/a.pcap', 'captures/b.pcap'])
WHERE filename = 'captures/b.pcap';
```

Partition columns require an explicit opt-in:

```sql
SELECT dt, host, count(*)
FROM read_dns_messages(
    's3://bucket/captures/dt=*/host=*/*.pcap',
    hive_partitioning = true,
    hive_types = {'dt': DATE, 'host': VARCHAR}
)
WHERE dt = DATE '2026-09-18' AND host = 'fw01'
GROUP BY dt, host;
```

Apply the same options to `read_pcap`, `read_packets`, `read_dns`,
`read_tcp_streams`, and `read_dns_messages`.

Supported options and schema behavior:

- `hive_partitioning` defaults to false, preserving existing `SELECT *` schemas.
- Partition keys default to VARCHAR. Support explicit `hive_types` and optional
  `hive_types_autocast = true` using DuckDB's type inference. Default autocasting
  to false so identifiers such as `host=001` retain their spelling.
- Require `hive_partitioning = true` when supplying partition type options; reject
  contradictory options instead of silently enabling a different schema.
- Append keys in deterministic sorted order after the reader's complete existing
  schema. Require consistent key sets across expanded inputs; report bind errors
  for inconsistent layouts or failed declared-type conversions.
- Reject partition names that collide, case-insensitively, with existing columns
  or with another distinct partition key. Never replace `filename`, `timestamp`, `src_ip`,
  `stream_id`, or any packet-derived value with a directory value.
- Use pinned DuckDB parsing and conversion semantics for directory separators,
  escaped values, null markers, and typed values. Preserve the original filename
  string; do not decode or canonicalize it for filename comparisons.
- Do not expose unrelated `filename` or `union_by_name` options merely by calling
  `MultiFileReader::AddParameters`; register only the supported options.

`dt` and `host` describe directory values. A capture in `dt=2026-09-18` can contain
packets from other dates, and `host` is not either endpoint's IP address. Packet-time
predicates alone therefore cannot prune by `dt`. Users combine a partition predicate
with packet predicates when their ingest layout provides that relationship.

The existing no-match glob and invalid-input binding behavior remains unchanged.
A nonempty expanded input list reduced to zero by a filter is a successful empty scan.
Schema validation still examines all input path strings before pruning.

## Preserve occurrence identity

Keep separate immutable input identity and executable work:

- `input_files`: the original ordered expanded `OpenFileInfo` occurrences, including
  duplicates and any filesystem metadata attached to each occurrence.
- `selected_indices`: an ordered subsequence of original indexes, initially all indexes.
- Partition definitions and typed values, when enabled, derived only from path strings.

The scheduler claims a dense selected-work index. Use that index for progress and
completion accounting; translate it through `selected_indices` for the original file
and stream identity. Keep both indexes explicit in local state.

Continue computing stream IDs as `(local_id - 1) * original_input_count + original_index + 1`.
Never use the selected count or renumber surviving occurrences. For `[A, B, A]`, an
A-only filter retains original indexes 0 and 2, and the multiplier remains 3.

Pruning must preserve the full result multiset, including IDs, of filtering a
materialized unpruned scan with the same original input list. Passing a smaller input
list directly remains a different call and can produce different IDs, as documented
in [parallel stream scans](PARALLEL_STREAMS.md).

Bind-data `Copy` and `Equals` must include selection, partition schema/options, and
original identity. Immutable path/value storage may be shared; mutable selections must
not leak between optimizer copies, prepared executions, or separate function calls.
Retain the existing stream-plan counting behavior when bind data is copied.

## Integrate with DuckDB without filtering TCP packets

Refactor binding into input expansion, complete reader-schema construction, then
partition finalization. Appending partition columns inside the current base `PcapBind`
would shift the decoded packet and DNS indexes and is unsafe.

Register a shared `pushdown_complex_filter` callback on all five functions. For packet
readers, compose it with the current boolean normalization. For stream readers, add
only this file-level hook; do not enable packet filter pushdown into reconstruction.

Use `MultiFilePushdownInfo(get)` and
`HivePartitioning::ApplyFiltersToFileList` with an explicit map from known filename/
partition names to projected binding indexes. The helper copies expressions,
substitutes known constants, and prunes only when a scalar, foldable expression
successfully evaluates to false or NULL. Expressions that cannot be evaluated remain
as residual SQL filters. Preserve AND/OR structure, collations, casts, NULL semantics,
and references to other tables by using DuckDB expressions rather than a custom SQL
predicate evaluator. Do not evaluate volatile expressions at bind time.

Run the helper on the currently selected file vector. Recover surviving original
indexes with a stable subsequence walk, retaining original `OpenFileInfo` objects.
The pinned helper preserves order and duplicates. Assert that mapping succeeds;
never deduplicate by filename or reconstruct the file vector from unique paths.
Selection can only narrow across repeated optimizer callbacks.

For the initial change, conservatively retain residual filters by giving the helper
copies of the filters. Packet filters keep their existing enforcement path; stream
filters remain above reconstructed output. This avoids removing a predicate before
all supported expression and partition cases are covered. Redundant filename checks
on surviving rows are acceptable initially.

Track the complete base-column count separately from appended partition columns.
Update projection and filter classification so a partition column cannot accidentally
trigger transport/DNS decoding or reach packet `ColumnStage`/`SetRecordValue` switches.
Materialize partition constants from the owning file for every emitted row, including
resource diagnostics and delayed EOF/DNS output. Residual partition expressions
remain in DuckDB's filter operator. Packet readers
honor `projection_ids` with `filter_prune=true`: the pinned physical planner rebuilds
projections for unsupported table filters. Decode depth still accounts for filter-only
packet columns, even when those columns are absent from output. Late advisory join
filters on partition/list columns are ignored by the packet decoder; their parent
join enforces the predicate.

Initialize progress with selected files only, before readers are created. Its size
probes currently open each supplied file. Bound worker count, stream starter
reservations, and drained-file completion by selected count. An entirely pruned scan
opens no files and reserves no stream worker, even with a zero stream budget.

Expose `File Filters` and `Scanning Files: selected/original` via DuckDB's operator
information. Reset total/selected counts deliberately after multiple pruning passes;
do not let a later pass silently redefine the original denominator. EXPLAIN needs no
capture opens. Preserve cancellation checks during large path/filter loops.

## I/O and error boundary

For a literal input list, excluded files must incur no execution-time opens, stat/
size probes, cache validation, HEADs, or GETs. Test this with progress both on and off.
Glob expansion can still issue filesystem/object-listing requests before filtering;
provider-specific existence checks during expansion are not covered by this guarantee.

Selected files retain existing framing errors and reconstruction diagnostics. An
excluded malformed capture is no longer parsed. Excluded FIFOs must not be opened or
block progress. Unresolved parameters or dynamic filters may fall back to scanning;
correctness is required even when a pruning opportunity cannot be used. Test prepared
executions with alternating parameter values to catch a permanently narrowed plan.

Full glob expansion remains necessary for the current ID contract: all original
occurrences and their count must be known before assigning IDs. Prefix pruning or
lazy discovery that omits inputs before identity assignment needs a separate identity
contract or a manifest with stable occurrence indexes. Do not silently combine it with
this change.

## Row-count estimates: finding and recommendation

The current one-row fallback can mislead join planning, but directory values and file
sizes do not establish packet, stream, or DNS-message counts. Classic PCAP has no
stored total packet count; PCAPNG block sizes/options and packet lengths vary. One TCP
direction can produce many DNS messages, and diagnostics are output rows too.

For the first pruning change, a cardinality callback may report `NodeStatistics(0, 0)`
for an empty selection. Do not mark a heuristic estimate as a maximum, use a packet
count for stream/message readers, or open excluded files to obtain statistics.

A useful subsequent estimate should prefer identity-validated per-file, per-reader
counts gathered by a complete scan or an explicit inventory. Key them by file identity,
reader/version, and reconstruction options; sum over surviving occurrences including
duplicates. Unknown or stale statistics must not become pruning evidence. Without
such counts, evaluate a sampled/file-size estimate separately against packet-size and
traffic mixes and join plans. A running count discovered during execution is too late
to fix that query's already-selected join order.

Parquet's stored row counts and DuckLake's catalog statistics explain why their
estimates are stronger than anything available from a bare capture path. Do not copy
their estimates without their metadata assumptions. The first implementation should
solve file selection; calibrated nonempty row estimates remain a follow-up.

## Implementation and acceptance checks

First change: occurrence-preserving selection, filename filters on all five readers,
selected-only scheduling/progress/budgeting, and EXPLAIN counts. Second change: explicit
Hive options, schema validation, appended constant columns, and partition pruning.

Acceptance checks must include:

- Compare against a materialized unpruned baseline using EXCEPT ALL in both directions,
  including nested bytes, diagnostics, stream IDs, and duplicate occurrences.
- Threads 1/2/4/8; `[A, B, A]`; reordered projections; filename unprojected; zero/one/all
  files selected; repeated optimizer callbacks; CTEs, joins, and prepared reuse.
- Equality, IN, deterministic string predicates, AND/OR mixed with packet predicates,
  NULL tests, casts, and volatile expressions. Unsupported cases retain residual checks.
- TCP gaps, overlaps, retransmissions, tuple reuse, resource limits, late EOF output,
  and multiple DNS messages per direction remain identical for selected captures.
- Local open instrumentation and cold HTTP request logs show zero accesses to excluded
  files with progress on/off. Include malformed inputs, excluded FIFOs, cache validation,
  cancellation, and shared memory reservations; keep existing remote regressions.
- Partition key collisions, inconsistent key sets, mixed-case names, escaped and NULL
  values, date casts, leading-zero identifiers, and Windows/POSIX path separators.
- EXPLAIN reports selected/original counts without opens. Empty selection works below
  the 128 MiB admission minimum; partial selection keeps original stream numbering.

Do not call pruning complete solely because result rows match: zero excluded-file I/O
is the purpose of the feature and must be measured directly.

## Implementation validation — September 18, 2026

- Release SQL suite: 1,506 assertions across nine cases passed, including the new
  `test/sql/file_pruning.test`. Tests compare full rows with EXCEPT ALL across
  1/2/4/8 threads, duplicates, typed partitions, collations, glob inputs, joins,
  prepared executions, volatile expressions, and empty scans below the admission limit.
- The new pruning SQL suite also passed under ThreadSanitizer: 310 assertions,
  with `halt_on_error=1` and no race reports.
- Six integration tests in `test/unit/file_pruning_test.py` passed. Local syscall
  traces show zero opens for excluded malformed captures and FIFOs, with no extra
  stat/size probes beyond input binding. Loopback HTTP logs show zero requests to
  excluded captures on cold and cached scans, including changed cached identities.
  Both filename and partition predicates were tested on all five readers with
  progress enabled and disabled. EXPLAIN made no capture opens or HTTP requests.
- Partition tests cover default schema compatibility, declared and inferred types,
  leading zeros, NULL markers, escaping, key collisions, invalid casts, filtered
  projections, 521 duplicate input occurrences across pruning batches, and partition
  ownership through multi-chunk stream and DNS output.
- 200 randomized full-row comparisons passed. Native reader overlap, cancellation,
  error/limit cleanup, memory admission/reuse, and progress checks passed. Stream
  memory-pressure comparisons passed at one, two, and four worker slots.
- Nine remote-read and nine remote-cache tests passed. Selective-read byte counts,
  truncated inputs, and named-pipe fallback checks passed.
- Release shell, library, SQL runner, and loadable extension built successfully.
  Repository formatting and whitespace checks passed.

The SQL tests participate in the existing cross-platform extension workflow. The
Linux scan workflow also runs the new syscall/HTTP integration suite after installing
httpfs. Hosted CI has not been run for this change; local checks used Linux in WSL.

## Sources and compatibility

- [DuckDB Hive partitioning documentation](https://duckdb.org/docs/stable/data/partitioning/hive_partitioning):
  path-derived columns and partition-filter pruning. PacketQuapture's explicit opt-in,
  VARCHAR default, and collision rejection are deliberate compatibility choices.
- [Pinned file-filter helper](https://github.com/duckdb/duckdb/blob/d8cdaa33fda8df955cc76ef58a280f68f4cd43fa/src/common/hive_partitioning.cpp):
  parsing, conversion, conservative expression evaluation, and order-preserving selection.
- [Pinned multi-file integration](https://github.com/duckdb/duckdb/blob/d8cdaa33fda8df955cc76ef58a280f68f4cd43fa/src/common/multi_file/multi_file_reader.cpp):
  option parsing and binding; standard BindOptions can override colliding columns.
- [Pinned Parquet estimates](https://github.com/duckdb/duckdb/blob/d8cdaa33fda8df955cc76ef58a280f68f4cd43fa/extension/parquet/parquet_multi_file_info.cpp):
  estimates use file row metadata, cached metadata, and size-based extrapolation.
- [DuckLake file-list implementation](https://github.com/duckdb/ducklake/blob/620150b1471c7f449a4e00bc46d55320ff29ca36/src/storage/ducklake_multi_file_list.cpp):
  metadata-backed filtering and table-statistics cardinality. Its current callback APIs
  differ from our pinned DuckDB; use it as an architectural reference, not copied code.

The pinned DuckDB sources were inspected locally. Any later DuckDB upgrade must
revalidate helper semantics, ABI availability, projection mapping, and filter behavior.
