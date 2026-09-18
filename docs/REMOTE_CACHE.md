# Shared caching for remote captures

Remote seekable captures now use DuckDB's shared external file cache. The reader fetches
aligned **4 MiB windows**, copies the requested bytes while holding a `BufferHandle`, and
releases that pin before fetching another window. The underlying remote handle uses
`FILE_FLAGS_DIRECT_IO`, as Parquet does when it supplies its own prefetch buffer, to avoid
stacking the old HTTP read-ahead over these windows.

This applies to remote schemes recognized by DuckDB's `FileSystem::IsRemoteFile`, including
HTTP and S3 URLs. All five capture table functions use the same reader. Local files keep the
existing direct reads and selective seeks; pipes retain sequential reads. Remote handles
without seeking or a known nonnegative size fall back to sequential reads.

## Behavior and controls

The cache belongs to a DuckDB database instance and can serve successive queries on the same
or different connections to that instance. It is not a persistent disk cache and does not
survive restarting DuckDB. Each active reader holds at most one 4 MiB window; other windows
are evictable under DuckDB's buffer-manager memory limit. Memory pressure can therefore
cause later queries to fetch bytes again. Very low limits can still produce out-of-memory
errors when there is insufficient room for active readers and other query work.

Existing DuckDB settings control reuse and validation; no new table-function parameters are
needed:

```sql
LOAD httpfs;
SET enable_external_file_cache = true; -- default
SET enable_http_metadata_cache = false; -- retain fresh metadata checks
SET validate_external_file_cache = 'VALIDATE_ALL'; -- default

SELECT count(*) FROM read_pcap('s3://captures/example.pcap');
SELECT count(*) FROM read_pcap('s3://captures/example.pcap');
```

With these defaults, later queries still check remote metadata but can avoid downloading
unchanged cached windows. DuckDB uses available version tags and modification times for
validation; the extension does not implement a separate invalidation policy. Core DuckDB
avoids reusable caching when required validation metadata is absent. HTTP metadata caching
or disabling cache validation can trade freshness for fewer checks; the extension honors
those settings. Replacement detection was tested with fresh HTTP metadata, including a
same-size object with changed bytes. These tests do not promise a snapshot if an object
changes during a scan, or cover every provider's metadata behavior.

`SET enable_external_file_cache=false` disables reuse, while retaining the bounded remote
window reads. Local reads do not populate this cache through PacketQuapture.

Fetching windows is a deliberate tradeoff: metadata/filter queries may fetch unwanted packet
bytes, and early `LIMIT` can fetch a window plus whatever input is needed to produce a DuckDB
output chunk. The window size bounds a pin, not total query memory or total LIMIT transfer.
Large parser skips can jump directly to a later aligned window without reading the skipped
windows. Four MiB is a starting policy supported by the small benchmarks, not a universal
optimum for all object sizes and latencies.

## Before and after on MinIO

Same 8,065 packets, approximately 8 MiB total, 1,024-byte frames, three trials per case,
DuckDB v1.5.5/httpfs `827222f`, eight workers, default cache settings. Timings below are
medians for **repeat queries**. The earlier baseline and new implementation each validated
108 MinIO queries across both layouts, three cases, three cache profiles, and first/repeat
phases. All results matched local-file queries.

| Files | Query | GET before → after | Bytes before → after | Seconds before → after |
| --- | --- | ---: | ---: | ---: |
| 1 | metadata | 8 → 0 | 8,382,112 → 0 | 0.814 → 0.017 |
| 1 | selective | 4 → 0 | 8,387,312 → 0 | 0.798 → 0.022 |
| 1 | raw | 4 → 0 | 8,387,624 → 0 | 0.799 → 0.019 |
| 8 | metadata | 8 → 0 | 8,386,984 → 0 | 0.768 → 0.031 |
| 8 | selective | 9 → 0 | 8,387,792 → 0 | 0.766 → 0.027 |
| 8 | raw | 9 → 0 | 8,387,792 → 0 | 0.767 → 0.031 |

Default-profile repeat queries still used one HEAD per object. With HTTP metadata caching
enabled, the unchanged-object repeats used zero HEADs as well. With external caching disabled,
repeat queries fetched the windows again, as intended.

For the one-file layout, first-query GETs fell from 8 to 2 for metadata and from 4 to 2 for
raw/selective scans. All first queries now fetched the entire 8,387,624-byte object, compared
with slightly less for metadata/selective baseline queries. The cold-query timings were
roughly unchanged for one file; the eight-file metadata median was slower in this run
(about 1.00 s versus 0.77 s). Reuse is the demonstrated benefit, not a general claim of
faster cold scans. The measurements include the counting proxy and Kubernetes port-forward,
and HTTP and MinIO runs overlapped on the client; treat timing differences cautiously.

The loopback HTTP matrix also passed **432 queries** across 1/8-file layouts, 1,024/60,000-byte
frames, 0/10 ms added request latency, and three cache profiles. Every cached repeat in both
backends transferred **zero response body bytes**: 144 HTTP and 36 MinIO repeated queries.
First HTTP metadata queries for one 16 MiB file used 4 GETs instead of 16. Cache-off repeats
still transfer bytes. The temporary MinIO bucket and its nine objects were deleted, and the
port-forward was stopped. Credentials were kept out of reports.

Raw reports: `build/remote-reads/cached-http.json` and `cached-minio.json` (ignored).
Compact evidence: [`benchmarks/remote-cache-2026-09-17.json`](benchmarks/remote-cache-2026-09-17.json).
The original [remote I/O benchmark](REMOTE_IO_BENCHMARK.md) remains the before-change baseline.
No AWS S3/R2, large-lake, or billing claim follows from these small synthetic measurements.

## Larger-scale follow-up

The [1 GiB MinIO scale check](REMOTE_CACHE_SCALE.md) passed all 16 metadata queries across
one/eight-file layouts and 128/2,048 MiB limits. Repeated queries transferred zero packet
bytes when the working set fit; the smaller cache saved little or nothing on full scans.

## Regression coverage

Eight integration tests in `test/unit/remote_cache_test.py` cover:

- exact packet bytes across window boundaries, cache reuse between query types, cache-off behavior;
- independent connections sharing one database;
- same-size object replacement and deletion with default validation;
- PCAPNG and all five table functions, comparing complete rows against local reads;
- early LIMIT followed by complete scans, including parallel duplicate paths;
- interrupted remote reads followed by connection reuse;
- successful scans larger than a 16 MB memory limit, forcing eviction and refetching;
- malformed remote framing and recovery.

The nine instrumentation tests, all 1,140 SQL assertions, local selective-byte/pipe/truncation
regressions, and native parallel reader/cancellation/cleanup checks also passed. CI builds the
shared library explicitly and runs the remote cache tests in its non-sanitizer job; hosted
CI execution has not been observed for this uncommitted change.

```sh
cmake --build build/release --target libduckdb.so shell unittest -j 4
./build/release/duckdb -c "INSTALL httpfs; LOAD httpfs;"
python3 test/unit/remote_reads_test.py
python3 test/unit/remote_cache_test.py
python3 scripts/benchmark_header_reads.py
./build/release/test/unittest 'test/sql/*'
```

Use the benchmark commands in the baseline document with new output filenames to compare
other window policies or environments. Larger objects, direct endpoint throughput, cold
scan tradeoffs, and provider-specific invalidation remain useful follow-up measurements.
