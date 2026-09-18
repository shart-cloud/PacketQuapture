# Remote cache scale check: 1 GiB

## Results — September 17, 2026

**All 16 queries returned the expected 1,032,444 packets.** With a 2 GiB memory limit,
both layouts retained their working sets and repeated scans transferred zero packet bytes.
With a 128 MiB limit, most or all of the data was fetched again. Cache capacity, rather than
a new window-size change, is the main finding of this test.

These are individual observations, not medians or statistically established speedups.
HTTP metadata caching was disabled: every query still performed one HEAD per input file.

| Files | Limit (MiB) | Cache | First seconds | Repeat seconds | First GETs | Repeat GETs | Repeat body MiB | Resident cache after repeat (MiB) |
| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 128 | on | 113.95 | 95.79 | 256 | 241 | 964.00 | 120.00 |
| 1 | 128 | off | 100.28 | 99.95 | 256 | 256 | 1024.00 | 0.00 |
| 1 | 2048 | on | 104.29 | 0.34 | 256 | 0 | 0.00 | 1024.00 |
| 1 | 2048 | off | 110.14 | 103.93 | 256 | 256 | 1024.00 | 0.00 |
| 8 | 128 | on | 97.67 | 97.96 | 256 | 256 | 1024.00 | 120.00 |
| 8 | 128 | off | 106.21 | 97.67 | 256 | 256 | 1024.00 | 0.00 |
| 8 | 2048 | on | 98.87 | 0.09 | 256 | 0 | 0.00 | 1024.00 |
| 8 | 2048 | off | 99.03 | 97.53 | 256 | 256 | 1024.00 | 0.00 |

The one-file low-memory repeat reused about 60 MiB and reread about 94% of the capture.
The eight-file low-memory repeat reused no payload bytes in this trial. Both completed
without exceeding the configured limit in the observed resident-cache snapshots. Snapshot
accounting is not a continuous measurement of all DuckDB-managed memory.

The one-file source is 1,073,741,784 bytes; the eight-file source totals 1,073,741,952 bytes.
Initial reads transfer all bytes in the single-file layout and 1,073,739,808 bytes in the
eight-file layout. The 2,144-byte difference in the latter is skipped tail payload crossing
a window boundary: counting packets does not need those bytes. This is why transfer bytes
need not exactly equal total file size for this metadata-only query.

Cold scans through this proxy/tunnel took roughly 98–114 seconds. The eight-file layout did
not produce a large cold-scan improvement. When the capture fit in cache, the one-file repeat
took 0.34 seconds and the eight-file repeat 0.09 seconds. Their different warm timings are
consistent with useful parallel scan work, but one trial does not establish a general speedup.

The client process's highest sampled RSS was **1126.6 MiB**, across 777 samples.
This is not the 128 MiB profile's peak: it includes the runs that retained the entire capture.
Per-query sampled RSS is recorded where samples were available; fast repeat queries may have
no sample and are represented as unavailable, not zero. Low-memory cache residency remained
at about 120–124 MiB; total process RSS also includes the runtime and proxy.

A preliminary 8 MiB-limit smoke run hit a clean out-of-memory error and cleaned up its bucket.
The corrected 16/32 MiB smoke matrix passed all eight queries. This confirms that a 4 MiB
window is not a guarantee that an entire query can run with a 4 or 8 MiB memory limit.

The full run's temporary bucket and nine objects were deleted, the port-forward was stopped,
and the nine local generated capture files (about 2 GiB total) were removed. Both smoke
buckets were also deleted. Reports remain under ignored `build/remote-reads/`; no credentials
or authorization headers were recorded.

Compact evidence: [`benchmarks/minio-1gib-2026-09-17.json`](benchmarks/minio-1gib-2026-09-17.json).
Raw query traces: `build/remote-reads/minio-1gib.json`.
Raw RSS samples: `build/remote-reads/minio-1gib-memory.json`.

## Decision

Keep the current 4 MiB window policy for now. This test demonstrates useful reuse when the
working set fits and graceful eviction when it does not; it does not compare alternative
window sizes or establish an optimum. Cache-disabled runs behave as expected and there were
no correctness failures in the 1 GiB matrix.

For larger lakes, selective working sets and pruning matter: a cache much smaller than a full
sequential scan cannot be assumed to save significant traffic. A direct-endpoint benchmark
would separate tunnel effects before further throughput tuning. Scan progress reporting was subsequently implemented; see [scan progress](SCAN_PROGRESS.md). No production
reader change was made as part of this scale check.

## Method

This follow-up tests the shared 4 MiB remote windows against the existing Kubernetes MinIO
service. It uses synthetic classic PCAP with 1,024-byte Ethernet/IPv4/TCP frames, alternating
destination ports 443 and 53. Each layout contains 1,032,444 packets: one approximately 1 GiB
object, or the same records divided among eight approximately 128 MiB objects. Extra file
headers make the byte totals slightly different. This is 1 GiB (1,024 MiB), not decimal 1 GB.

The measured query is `SELECT count(*) FROM read_pcap([...])`. It targets the original
metadata-scan concern and checks every result against both the generated packet count and
local-file queries. Payload decoding/materialization and large PCAPNG files are not part of
this scale check; their smaller-scale regression coverage is described in
[REMOTE_CACHE.md](REMOTE_CACHE.md).

There is one trial per combination: 2 layouts × 2 DuckDB memory limits (128 and 2,048 MiB) ×
2 cache profiles (enabled and disabled) × first/repeat = 16 queries. A fresh database is used
for each combination; the repeated query uses the same database/connection and object URLs.
HTTP metadata caching stays disabled and default cache validation stays enabled. The engine
uses eight worker threads. A first query does not imply a cold MinIO or OS cache.

Requests pass through the same non-caching counting proxy and Kubernetes port-forward as the
small benchmark. The measured timings include both; they do not measure direct-endpoint
throughput or predict AWS S3/R2 behavior. Creation, upload, and cleanup are excluded from
query counters. Network bytes mean response body bytes, excluding HTTP and tunnel overhead.
The query timeout is 300 seconds, and the per-object upload timeout is 600 seconds. The
existing per-query request cap and four-times-source response-byte cap remain in place.

`duckdb_external_file_cache()` snapshots provide cache entries, logical cached bytes, and
resident cached bytes. Resident cache bytes are not process RSS or a cache hit-rate counter.
A separate Linux `/proc` sampler records benchmark-process RSS every two seconds; it includes
DuckDB and the Python proxy, excludes AWS CLI/kubectl/MinIO, and can miss short peaks.
The sampler's maximum is therefore a sampled peak, not a strict allocation bound. The memory
limit controls DuckDB-managed memory, not the entire process.

## Reproduce

With an authorized credential environment and a localhost MinIO port-forward already active:

```sh
python3 scripts/benchmark_minio_reads.py \
  --endpoint http://127.0.0.1:19000 \
  --size-mib 1024 --frame-sizes 1024 --files 1 8 \
  --memory-limits-mib 128 2048 --cache-profiles default external_off \
  --cases metadata --threads 8 --trials 1 \
  --query-timeout 300 --upload-timeout 600 \
  --output build/remote-reads/minio-1gib.json
```

The harness creates a unique temporary bucket and deletes its own objects and bucket in a
cleanup block. It records cleanup status and fails on incomplete cleanup. Credentials are
read from the environment and are never included in reports. See the
[baseline benchmark](REMOTE_IO_BENCHMARK.md) for prerequisites and credential handling.
`--memory-limits-mib 0` retains DuckDB's default memory limit; query and upload timeout
defaults remain 30 and 60 seconds for the smaller benchmark.

## Subsequent in-cluster follow-up

The direct/proxy in-cluster comparison is now complete; see [the follow-up report](REMOTE_CACHE_INCLUSTER.md). All 112 smoke/scale queries passed. Direct 1 GiB first-scan medians were 2.57–5.07 seconds across three trials per configuration. The original tunneled measurements above remain historical evidence for that path only.
