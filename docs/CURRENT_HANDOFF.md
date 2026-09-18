# PacketQuapture current handoff

Updated: 2026-09-18. Repository: `/home/jg/git/packetquapture` (WSL Ubuntu).
Base commit: `dd038c6` on `main`; DuckDB v1.5.5, measured httpfs build `827222f`.

## Start here

Whole-file packet parallelism, shared remote caching, and scan progress are implemented
and locally validated. The user requested review, cohesive commits, and hosted CI on
September 18. The work is packaged on review/parallel-cache-progress; see the packaging status
below for current validation and CI results. Preserve unrelated working-tree changes.

| Reader | Whole-file parallelism | Shared remote cache | Scan progress |
| --- | --- | --- | --- |
| `read_pcap` | Yes | Yes | Yes |
| `read_packets` | Yes | Yes | Yes |
| `read_dns` | Yes | Yes | Yes |
| `read_tcp_streams` | Still sequential | Yes | Yes |
| `read_dns_messages` | Still sequential | Yes | Yes |

Single-file scanning remains sequential. The bounded in-cluster MinIO follow-up is now
complete: 16 smoke and 96 scale queries passed. Direct first-scan medians were 2.57–5.07
seconds for 1 GiB; in-cluster proxy medians were 2.81–5.03 seconds. These replace the earlier
tunneled timings as evidence for this measured path, not general storage throughput.
See [in-cluster report](REMOTE_CACHE_INCLUSTER.md). There is no implementation task in progress.

## Completed changes

### Whole-file packet scans

`src/packetquapture_extension.cpp` now has an atomic file scheduler and worker-local readers,
filters, and expression executors for the three packet functions. Every input occurrence is
scheduled, including duplicate paths. Thread count is bounded by file count. Packet numbers
and byte offsets remain relative to each file; global output order is not guaranteed.
Cancellation checks and contextual reader errors are included.

Tests and tooling: `test/sql/parallel_scans.test`, `test/unit/parallel_scan_test.cpp`,
`test/data/parallel/`, `scripts/generate_test_captures.py`,
`scripts/benchmark_parallel_scans.py`, and `.github/workflows/ParallelScans.yml`.
The protocol-decoder workflow also regenerates basic fixtures.
See [parallel scans](PARALLEL_SCANS.md) for semantics, commands, and measurements.

### Shared remote cache

Recognized remote paths use DuckDB's `CachingFileSystem` and aligned 4 MiB windows.
Direct I/O avoids stacking httpfs read-ahead over these windows. Each reader holds at most
one window pin and releases it before acquiring the next; unpinned windows are evictable
through DuckDB's memory manager. Parser skips advance the logical cursor. Local selective
reads and the sequential fallback for nonseekable/unknown-size inputs are retained.

The cache is shared between connections in the same database instance, not persisted across
processes. Existing DuckDB cache and validation settings apply. This adds no table-function
options and makes no snapshot guarantee for captures changing during a scan.
See [remote cache](REMOTE_CACHE.md) and `test/unit/remote_cache_test.py`.

### Scan progress

All five readers register a progress callback backed by `src/include/capture_progress.hpp`.
When enabled, execution probes input sizes one handle at a time and workers publish atomic
logical-byte counters. Unequal files are weighted by bytes; duplicates count repeatedly.
Skipped payloads count as scanned, while prefetched bytes count only when consumed.
Stream readers defer completion until buffered output drains. Unknown sizes report progress
as unavailable; errors, cancellation, and early LIMIT do not falsely complete unread inputs.

```sql
SET enable_progress_bar = true;
SET progress_bar_time = 500;
-- For clients polling query progress without terminal output:
SET enable_progress_bar_print = false;
```

Progress is not an ETA or download meter. Enabling it can add a metadata request per input
occurrence. DuckDB refreshes its visible snapshot between execution tasks, so blocking reads,
long filters producing no rows, and reassembly can pause visible updates. Disabled progress
adds no progress-specific probes or counter updates. Optimizer cardinality estimates are
still missing. See [scan progress](SCAN_PROGRESS.md) and `test/unit/scan_progress_test.cpp`.

## What the measurements establish

The original assumption of one remote GET per packet was disproved. Before shared caching,
an 8 MiB MinIO capture containing 8,065 packets required 4–8 GETs depending on projection;
repeats downloaded it again. HTTP metadata caching removed repeated HEADs, not payload reads.
[The baseline report](REMOTE_IO_BENCHMARK.md) deliberately describes pre-change behavior.

After caching, the small HTTP matrix passed 432 queries and MinIO passed 108. All 180 repeats
with caching enabled transferred zero payload bytes. A first 8 MiB scan required two GETs.
Cold timings were not consistently faster. Evidence is in
[the cache report](REMOTE_CACHE.md) and [compact results](benchmarks/remote-cache-2026-09-17.json).

The subsequent 1 GiB MinIO check passed all 16 metadata queries, each returning 1,032,444
packets, across one/eight files, cache on/off, and 128/2,048 MiB memory limits:

- With 2 GiB available, cached repeats transferred zero payload bytes and took 0.34 seconds
  for one file or 0.09 seconds for eight files.
- At 128 MiB, repeats reread about 94–100% of the capture. Resident cache snapshots were
  around 120–124 MiB; process RSS is a different measurement.
- First scans took roughly 98–114 seconds through the proxy/tunnel. These are single trials,
  not established speedups or direct MinIO throughput measurements.

Keep the 4 MiB window policy for now: no alternative window sizes have been compared.
See [scale report](REMOTE_CACHE_SCALE.md) and
[compact scale results](benchmarks/minio-1gib-2026-09-17.json).
No AWS S3 or R2 benchmark has been run. Response-byte counters exclude protocol/tunnel
overhead; cache residency is not a cache-hit-rate counter. Synthetic captures do not establish
performance on every real capture workload.

Earlier packet-parallelism measurements at eight files/eight threads showed 4.21x metadata,
6.52x transport, 4.74x raw, and 5.04x DNS throughput versus one thread. These are stage-one
measurements, not fresh performance results after every later change.

## Validation completed

Latest checks after scan progress:

- Release SQL suite: 1,140 assertions across seven cases passed.
- Full ThreadSanitizer SQL suite: the same 1,140 assertions passed.
- Native progress tests passed against both release and fully thread-sanitized builds,
  with no reported data race.
- Nine remote cache/integration tests passed, including first/cached progress,
  cancellation and connection reuse, invalidation, memory pressure, and reader parity.
- Local selective-byte, truncation, and named-pipe regressions passed.
- Formatting and whitespace checks passed.

Earlier stages also passed the nine request-instrumentation tests and native parallel-reader
concurrency/cancellation checks. Hosted CI has not been observed. Existing progress logs are
under `/tmp/packetquapture-progress-*.log`; raw benchmark traces are ignored local artifacts
under `build/remote-reads/`. Compact evidence under `docs/benchmarks/` should be retained.

## Build and verification

Run these commands in Linux from `/home/jg/git/packetquapture`:

```sh
cmake --build build/release --target libduckdb.so shell unittest -j 4
./build/release/duckdb -c "INSTALL httpfs; LOAD httpfs;"
./build/release/test/unittest 'test/sql/*'
python3 test/unit/remote_reads_test.py
python3 test/unit/remote_cache_test.py
python3 scripts/benchmark_header_reads.py

c++ -std=c++17 -Wall -Wextra -Werror -O1 -g -pthread \
  -Isrc/include -isystem duckdb/src/include test/unit/scan_progress_test.cpp \
  -Lbuild/release/src -Wl,-rpath,/home/jg/git/packetquapture/build/release/src \
  -lduckdb -o build/scan_progress_test
./build/scan_progress_test
```

Explicitly build `libduckdb.so`: rebuilding only the CLI can leave the ctypes benchmark
using an old shared library. An incorrect runtime library path can instead load
`/usr/local/lib/libduckdb.so` and fail with ABI symbol errors. Absolute paths avoid Windows
to WSL shell expansion surprises. The existing sanitizer build has no `shell` target:

```sh
cmake --build build/tsan --target libduckdb.so unittest -j 3
c++ -std=c++17 -Wall -Wextra -Werror -O1 -g -pthread -fsanitize=thread \
  -Isrc/include -isystem duckdb/src/include test/unit/scan_progress_test.cpp \
  -Lbuild/tsan/src -Wl,-rpath,/home/jg/git/packetquapture/build/tsan/src \
  -lduckdb -o build/scan_progress_test_tsan
TSAN_OPTIONS=halt_on_error=1 setarch x86_64 -R ./build/scan_progress_test_tsan
TSAN_OPTIONS=halt_on_error=1 setarch x86_64 -R ./build/tsan/test/unittest 'test/sql/*'
source build/format-env/bin/activate
make format-check
git diff --check
```

The process-local ASLR setting is needed for GCC ThreadSanitizer mappings on this WSL setup;
no race suppressions were used. The sanitized SQL run takes several minutes. Do not load the
sanitized shared library into ordinary Python for the HTTP tests. For a fresh test build,
set `UNITTEST_ROOT_DIRECTORY` to this repository so the intended extension tests are selected.

## Operational state and credential scope

All temporary benchmark buckets and their objects were removed, port-forwards stopped, and
the nine generated large capture files (about 2 GiB locally) removed. Reports remain.
No benchmark job or tunnel is intentionally left running.

The existing service is `trawl-system/minio`, S3 port 9000, on Kubernetes context
`admin@talos-cluster`. Prior runs used a localhost port-forward and the non-caching counting
proxy in `scripts/benchmark_minio_reads.py`. The user approved reading and using
`trawl-system/minio-root` **only for uniquely named temporary benchmark buckets and their
synthetic data**. This is not general authorization for MinIO administration. Credentials
were handled in memory/environment and excluded from reports and output; preserve that rule.
The harness tracks owned objects and reports cleanup failures. See the baseline and scale
reports for reproduction options. Do not expose the service publicly just to benchmark it.

## Recommended continuation

1. Inspect the diff and this handoff before changing code. The original
   [multicore plan](MULTICORE_HANDOFF.md) and [gap analysis](GAP_ANALYSIS.md) contain historical
   assumptions and future work; use the measured reports for current performance claims.
2. The bounded in-cluster benchmark is complete; see [report](REMOTE_CACHE_INCLUSTER.md)
   and docs/benchmarks/minio-incluster-1gib-2026-09-17.json. Keep the 4 MiB policy.
   Cross-node, real-workload, and alternative-window measurements remain separate optional
   investigations. Do not infer a storage bottleneck from the old tunneled timings.
3. For the next implementation, settle stream-ID scope and aggregate memory limits before
   parallelizing `read_tcp_streams` and `read_dns_messages` on the shared file scheduler.
   Their TCP state must remain worker-local and preserve per-file finalization semantics.
4. Cardinality estimates, single-file parallelism, and file/range pruning remain separate
   follow-ups. Scan progress does not implement any of them.
5. Local review and packaging are complete. Explicit approval to push the source, benchmark
   evidence, and documentation to the public origin is pending after automatic approval review
   blocked the first attempt. Run hosted CI on the review branch before calling CI verified.

## In-cluster follow-up completed — September 17, 2026

The private service and pod addresses were unreachable from WSL; no MinIO ingress or
HTTPRoute was found. After explicit user approval to transfer the benchmark artifacts,
the prepared runner was executed in a disposable pod on the MinIO node.

- All 16 smoke queries and 96 scale queries passed, including local packet-count parity.
- Scale queries returned 1,032,444 packets. Direct first-scan medians were 2.57–5.07 seconds;
  in-cluster proxy medians were 2.81–5.03 seconds, across three trials per configuration.
- At 2,048 MiB, all cached repeats fetched zero payload bytes. At 128 MiB, repeats reread
  approximately 94–100%. The proxy's independent GET/byte counts matched HTTP logs exactly.
- HTTP logs remained in memory; only allowlisted fields were exported. Response-length sums
  are not independent wire-byte measurements. No credential values or signed headers were saved.
- The pod had 4 CPU, 4 GiB memory, 6 GiB ephemeral storage, and a 2,400-second deadline.
  Eight DuckDB threads ran on the same node as MinIO. Client placement, CPU allocation,
  runtime, and storage-cache state differ from the earlier WSL measurements.
- Namespace default-deny required two temporary policies allowing benchmark DNS and
  benchmark-to-MinIO port 9000. Packages were installed offline; no public endpoint was created.
- Both unique buckets and nine objects per bucket were deleted. Pod and temporary policies
  were verified absent; generated captures disappeared with the pod. No tunnel was used.
- The shared library was up to date. Runner formatting, Python syntax, local logging parity,
  report invariants, and whitespace checks passed. No production reader code was changed;
  no new full SQL suite or hosted CI run was needed or performed for this benchmark-only work.

Files added by the benchmark follow-up: scripts/benchmark_minio_incluster.py, docs/REMOTE_CACHE_INCLUSTER.md,
and the two docs/benchmarks/minio-incluster-*.json evidence files. These are now included in the packaging commits.
Raw reports, image digest, package versions, artifact hashes, manifests, and cleanup evidence
are retained in ignored build/remote-reads/incluster-* artifacts. The compact scale report
also contains versions, hashes, timing ranges, per-query RSS/cache snapshots, and cleanup.

## Review and packaging — September 18, 2026

The full implementation diff was reviewed for worker-local ownership, duplicate scheduling,
cancellation, cache-window lifetime, and progress completion. Existing regression coverage
checks these behaviors. Stale next-work text was corrected; no new production-code change
was necessary during this review.

Packaging keeps the intertwined reader changes and their regression tests together,
followed by benchmark tooling/evidence, then documentation and hosted CI configuration.
The base includes two existing local commits not yet on origin/main: c622fca (protocol
decoding/selective reads) and dd038c6 (DNS/TCP reassembly). Their history is preserved.

Fresh release verification passed: 1,140 SQL assertions; nine HTTP instrumentation tests;
nine remote cache/integration tests; selective-byte, truncation, and named-pipe regressions;
native overlap/cancellation/cleanup and progress tests; repository formatting checks.
All 120 randomized multiset comparisons passed. Deterministic fixture regeneration matched
the checked-in captures. The fresh fully instrumented ThreadSanitizer SQL run passed all
1,140 assertions, and the native progress test passed, with no reported data race.

Three cohesive commits are on review/parallel-cache-progress: reader implementation and
regressions; benchmark tooling/evidence; documentation and CI. The working tree is clean.
The first two are 941a491 and bd61870; use git log for the documentation commit.

The first push attempt was rejected by automatic approval review because explicit approval
to export the source, benchmark data, and documentation to the public
shart-cloud/PacketQuapture repository was not established. Nothing was pushed and hosted CI
has not run for this branch. Ask for that exact publication approval, then push the review
branch and monitor the hosted workflows. Do not merge or publish a release as part of this task.
