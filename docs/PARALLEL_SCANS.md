# Parallel capture scans

The first delivery of the multicore plan parallelizes `read_pcap`, `read_packets`, and
`read_dns` over complete files. DuckDB owns scheduling and caps workers with its `threads`
setting. Each occurrence in an input list is a separate work item, including duplicate paths.
A single file still has one reader. Empty captures and captures rejected by filters do not
end a worker while unclaimed files remain. Discovery still eagerly expands lists and globs.

Global state owns the atomic file cursor, projection requirements, and copies of filter
definitions. Each local state owns its reader, scan options, expression executors, and filter
input chunks. The filter callback captures the stable local state. No shared lock surrounds
opening, reading, decoding, or output. The bind-owned file list outlives all scan states.

Packet numbers, offsets, PCAPNG scope, nulls, and staged selective reads retain their meanings.
No global row order is promised; callers use `ORDER BY` for ordered results. Query interruption
is checked even during no-output scans and between reads of framing blocks or skipped payloads.
These checks do not interrupt an operating-system read already blocked on a pipe or remote
filesystem; cancellation still depends on that filesystem returning. DuckDB propagates worker
errors and cancels other tasks. Read errors carry a filename and current packet/byte cursor;
opening and initial-header errors retain their existing filename diagnostics. Handles are owned
by local states and released on completion, exception, interruption, or an early query limit.

`read_tcp_streams` and `read_dns_messages` remain sequential. Their shared TCP core, limits,
IDs, and post-reconstruction filters are unchanged. The shared scheduler is ready for the
second delivery after identifier translation and aggregate-memory reservations are reviewed.

## Correctness checks

```sh
GEN=ninja make release
./build/release/test/unittest 'test/sql/*'
python3 scripts/benchmark_parallel_scans.py --verify-only --verify-mixes 10
python3 scripts/benchmark_header_reads.py

# Linux integration: observes /proc/self/fd, not a timing speedup threshold.
c++ -std=c++17 -Wall -Wextra -Werror -O1 -pthread \
  -isystem duckdb/src/include test/unit/parallel_scan_test.cpp \
  -Lbuild/release/src -Wl,-rpath,"$PWD/build/release/src" \
  -lduckdb -o build/parallel_scan_test
timeout 120s ./build/parallel_scan_test
```

The SQL suite compares row multisets using `EXCEPT ALL` in both directions, including duplicate
multiplicity, nullable fields, all projected fields, small projections, mixed PCAP/PCAPNG,
empty captures, and staged filters at 1/2/4/8 threads. Existing large fixtures cross output chunk
boundaries. Randomized mixes use a fixed seed and sample input paths with replacement.

The integration test observes multiple capture descriptors alive at once for all three packet
functions, verifies one reader for one file or `threads=1`, interrupts a fully filtered scan,
checks errors and early `LIMIT`, and reuses the same connection after cleanup. Its captures stay
under ignored `build/`. The observer has bounded deadlines and the executable has an outer timeout.

`.github/workflows/ParallelScans.yml` runs these checks on Linux. Its manual `sanitizer` input can
request a full DuckDB-plus-extension ThreadSanitizer or ASan/UBSan build. Sanitizer instrumentation
must cover DuckDB as well as the extension; linking only a sanitized test executable against an
unsanitized library is not a concurrency certification. For GCC ThreadSanitizer on hosts that report `unexpected memory mapping` before main, the
workflow uses `setarch "$(uname -m)" -R` for the test process and its children. This changes no
system-wide ASLR setting and suppresses no race reports. The live descriptor test is Linux-specific;
the SQL suite remains in the existing native platform workflow. Throughput is never a CI gate.

## Benchmarks

```sh
python3 scripts/benchmark_parallel_scans.py --storage-note 'describe the capture storage'
# Short all-workload check:
python3 scripts/benchmark_parallel_scans.py --units 2048 --trials 1 --tiny-files 32
```

The default generates 262,144 units, each containing SYN, one DNS TCP payload, RST, and one UDP
DNS packet. Each TCP direction finalizes before the next unit, staying below transport and DNS
limits. Limit handling remains covered by correctness fixtures, not these throughput measurements.
The same packet records appear in one, two, four, eight, many-small-file, and 80%-dominant-file
layouts. Per-file PCAP headers add 24 bytes; the report records actual total source size for each
layout. No record or stream unit is split across files.

Workloads cover metadata counts, transport fields, flags, address/port predicates, raw blobs,
packet DNS, stream counts, stream bytes/chunks, and reconstructed DNS messages. They use aggregates
that consume the intended fields. The harness saves `EXPLAIN` plans, checks predicate pushdown,
and asserts aggregate results agree across every layout and thread setting. Stream timings are
sequential controls until the second delivery.

Each trial pre-reads every source to warm the cache. No cold-cache measurements or physical disk
throughput are claimed. Reported query latency comes from DuckDB's profile and excludes CLI startup;
GNU time CPU usage, peak RSS, and utilization cover the whole CLI process. Source MiB/s is based on
file size, which differs from physical bytes read when projection skips payloads. `rows/s` counts
scan output rows (after predicates), not aggregate result rows.

JSON reports contain revision, dirty-tree status, executable label/path, DuckDB version, release
flags, CPU/core count, OS and mount details, source shape, cache policy, individual trials,
median/min/max, and speedup against `threads=1`. Use `--cli`, `--label`, and `--output` to compare an
original-release executable with the current build. Run benchmarks without competing builds or
other substantial workloads. Report single-thread changes as well as scaling; storage, file-size
imbalance, output allocation, and aggregation may limit gains.

## Local validation (2026-09-17)

- Release SQL suite: 1,140 assertions in seven cases (original baseline: 899 in six).
- Ten randomized mixes across three functions and four thread settings: 120 comparisons passed.
- Native integration: overlapping readers, worker limits, interruption, EOF/error/early-limit
  cleanup, and connection reuse passed for all packet functions at 1/2/4/8 threads.
- Selective I/O counts, named-pipe fallback, and truncation errors passed unchanged.
- All four standalone ASan/UBSan suites passed: packet decoder, DNS decoder, TCP core, DNS framer.
- Deterministic fixture regeneration, `make format-check`, and `git diff --check` passed.

The fully instrumented ThreadSanitizer SQL suite (all 1,140 assertions) and native overlap/cleanup
test also passed with `halt_on_error=1` and no race reports, using the process-local startup
workaround described above. The local build omits the unused Parquet
extension and unrelated DuckDB C++ tests; DuckDB core and this extension are instrumented.

See [the current handoff](CURRENT_HANDOFF.md) for packaging and hosted CI status.
These local results alone do not certify the macOS/Windows release matrix.

## Local measurement (2026-09-17)

Release `-O3 -DNDEBUG`, DuckDB v1.5.5, WSL2 Linux on an i9-12900HK with eight visible CPUs,
ext4 capture storage, warm cache, three trials per setting. Each layout contains 524,288
packets (~41 MiB). The isolated sanitizer build was paused during these measurements.
Results characterize this machine and synthetic capture, not a storage-independent promise.

Eight equal files:

| Workload | 1 thread (s) | 2 threads (s) | 4 threads (s) | 8 threads (s) | 8-thread speedup |
| --- | ---: | ---: | ---: | ---: | ---: |
| metadata | 0.417 | 0.230 | 0.122 | 0.099 | 4.21x |
| transport | 1.020 | 0.476 | 0.256 | 0.156 | 6.52x |
| raw | 0.560 | 0.324 | 0.162 | 0.118 | 4.74x |
| dns | 1.109 | 0.600 | 0.318 | 0.220 | 5.04x |

Against an isolated executable built from the original `dd038c6` scanner with the same release
objects/toolchain, one-thread median changes ranged from -2.3% to +4.0% across the one-file and
eight-file workloads above. Most trial ranges overlap; this does not establish a systematic
regression. Full trial spreads, CPU/RSS measurements, and the small-file/skewed layouts are in
`build/parallel-scans/scaling-clean.json` and `build/parallel-scans/baseline.json`. Generated reports
are local ignored artifacts. The `smoke.json` run also checked every stream/filter benchmark case.
The earlier `scaling.json` run overlapped a build and should not be used for performance claims.

## Progress reporting

All packet workers contribute logical bytes to a shared atomic counter when DuckDB progress
is enabled. File occurrences are weighted by size, including duplicate paths; early LIMIT and
cancellation do not mark remaining inputs complete. The two sequential stream functions defer
completion until buffered output is drained. See [scan progress](SCAN_PROGRESS.md) for the
metadata prepass cost and display refresh limitations.
