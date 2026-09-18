# Remote I/O benchmark

**Before-change baseline.** Shared remote caching has since been implemented and measured;
see [the implementation and before/after results](REMOTE_CACHE.md). The measurements below
describe the original reader.

Measured September 17, 2026, on DuckDB v1.5.5 with httpfs `827222f`, PacketQuapture
`dd038c6` plus the working-tree whole-file parallel scan changes. The release library uses
`-O3 -DNDEBUG`; the client is WSL2 Linux on an Intel i9-12900HK with 8 visible logical CPUs
and `threads=8`. These are small synthetic PCAP measurements, not the 200 GB–1 TB scale test.

## What the measurements establish

Both loopback HTTP and real MinIO already batch the reader's small reads into large HTTP
range requests. The earlier gap-analysis hypothesis of one GET per packet is contradicted
by these traces. A metadata-only query can still issue more GETs than a full-payload query,
while transferring almost the same bytes.

The remaining cache gap is measurable: repeated identical queries fetched the packet bytes
again. `duckdb_external_file_cache()` reported zero entries, bytes, and resident bytes before
and after every measured query, including with `enable_external_file_cache=true`. Turning
that setting off did not change the request counts or transferred bytes. Turning on
`enable_http_metadata_cache` removed repeat-query HEADs, but left payload GETs unchanged.
Cache hit rate is **unavailable**, represented as `null` in the reports; cache residency is
not a hit-rate counter.

A 50%-selective transport predicate saved almost no network bytes for these layouts. Local
selective-I/O behavior remains independently covered by `benchmark_header_reads.py`.

## Real MinIO results

The backend was the existing Kubernetes MinIO service, image
`quay.io/minio/minio:RELEASE.2025-04-22T22-12-26Z`. Each query used signed S3 requests through
a localhost counting proxy and Kubernetes port-forward. The proxy preserves the signed
Host and authorization headers, forwards responses without caching, and records only request
method/path/range, status, payload bytes, and duration. Credentials and authorization headers
are not recorded. Bucket creation, upload, and deletion are outside the query counters.

The full run validated **108 queries**: 3 trials × 2 file layouts × 3 cases × 3 cache profiles
× first/repeat. Each layout contains the same 8,065 synthetic Ethernet/IPv4/TCP packets with
1,024-byte frames, alternating destination ports 443 and 53. The one-file layout is 8,387,624
bytes; the eight-file layout is 8,387,792 bytes, including the additional PCAP file headers.
All results matched local-file queries. A separate 8-query smoke run also passed.

Default cache profile, first query; elapsed time is the median of three trials. Request and
byte counts were identical across those trials.

| Files | Query | HEAD | GET | Response body bytes | Median seconds |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | metadata | 1 | 8 | 8,382,112 | 0.820 |
| 1 | selective | 1 | 4 | 8,387,312 | 0.790 |
| 1 | raw | 1 | 4 | 8,387,624 | 0.801 |
| 8 | metadata | 8 | 8 | 8,386,984 | 0.766 |
| 8 | selective | 8 | 9 | 8,387,792 | 0.774 |
| 8 | raw | 8 | 9 | 8,387,792 | 0.767 |

With the default profile, repeat queries had the same request and byte counts as the table.
With metadata caching enabled, repeat HEAD count was zero; GET and byte counts were unchanged.
The timings include the proxy and Kubernetes tunnel and must not be interpreted as direct
MinIO throughput or as evidence of AWS S3/R2 latency. Eight files do not necessarily improve
throughput through this tunnel.

Both uniquely named temporary buckets were deleted after their runs (one smoke object and
nine measured objects), and both port-forwards were stopped. Only generated test objects were
read or written. The benchmark itself accepts credentials from the environment; it does not
read Kubernetes secrets or inspect existing buckets.

## Controlled HTTP results

The loopback server allows controlled delay before each response without cloud credentials.
The full run validated **432 queries**: 3 trials × 2 frame sizes (1,024 and 60,000 bytes) ×
2 file layouts × 2 delays (0 and 10 ms/request) × 3 cases × 3 cache profiles × first/repeat.
A separate smoke run validated all five query cases, including header decoding and a framing
predicate that rejects every packet.

The following slice uses 1,024-byte frames, 16,131 packets, about 16 MiB per layout,
10 ms added delay per HTTP request, default caching, and first queries. Timings are medians.

| Files | Query | HEAD | GET | Response body bytes | Median seconds |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | metadata | 1 | 16 | 16,764,480 | 0.241 |
| 1 | selective | 1 | 5 | 16,775,952 | 0.106 |
| 1 | raw | 1 | 5 | 16,776,264 | 0.118 |
| 8 | metadata | 8 | 16 | 16,769,968 | 0.059 |
| 8 | selective | 8 | 16 | 16,771,584 | 0.075 |
| 8 | raw | 8 | 16 | 16,776,432 | 0.066 |

The one-file metadata scan transferred 99.93% of the source bytes in 16 GETs; raw scans used
5 GETs. This is evidence of existing buffering and different read-request shapes, not proof
of the underlying httpfs buffer growth algorithm. The eight-file metadata query overlapped
request latency across workers. The server's connection queue is 128 to avoid the default
small listener backlog becoming an artificial parallelism bottleneck.

## Queries and cache profiles

| Case | Work checked |
| --- | --- |
| `metadata` | `read_pcap`: packet count, no packet materialization |
| `headers` | `read_packets`: count, destination-port sum, payload-length sum |
| `selective` | `read_packets`: count and total `octet_length(packet_data)` where `dst_port=443` |
| `reject` | Same aggregate where `captured_length<54`, rejecting all generated packets |
| `raw` | `read_packets`: count and total packet bytes without a predicate |

| Profile | External file cache | HTTP metadata cache |
| --- | --- | --- |
| `default` | enabled | disabled |
| `external_off` | disabled | disabled |
| `metadata_on` | enabled | enabled |

Each case/profile/trial gets a fresh in-memory DuckDB database. Its `repeat` phase executes
identical SQL and URLs on the same connection immediately afterward. This does **not** claim
cold OS, MinIO, or provider caches. The HTTP client uses the default implementation,
keep-alive enabled, `http_retries=0`, `http_timeout=10`, and the default external-cache
validation mode `VALIDATE_ALL`. Each query has a 30-second interrupt timer. Request and
response-byte budgets bound unexpectedly amplified reads.

Reports contain raw request traces, results, cache snapshots, process CPU, medians and
min/max elapsed times, source sizes, versions, and script hashes. Measured body bytes exclude
HTTP headers, TLS, and tunnel overhead. Process CPU includes the Python server/proxy and
DuckDB, but excludes the MinIO server and port-forward subprocess. Peak RSS and remote cache
hit rate are not measured.

## Reproduce

Use a release build containing PacketQuapture and the matching installed httpfs extension.
The harness uses the library's C API via Python's standard-library `ctypes`, so no Python
DuckDB package is required. Do not load a sanitizer-instrumented library into ordinary Python;
the CI harness runs only in the non-sanitizer build.

```sh
./build/release/duckdb -c "INSTALL httpfs; LOAD httpfs;"
python3 test/unit/remote_reads_test.py
python3 scripts/benchmark_remote_reads.py \
  --size-mib 16 --trials 3 --cases metadata selective raw \
  --output build/remote-reads/measured-final.json
```

For MinIO, establish a localhost port-forward and supply already-authorized credentials via
`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, optionally `AWS_SESSION_TOKEN`, and
`AWS_DEFAULT_REGION` (defaults to `us-east-1`). The AWS CLI must be installed. The credentials
need permission to create/delete the temporary bucket and put/get/delete its objects. The
script ignores saved AWS profiles and always creates its own unique bucket; it never accepts
an existing target bucket. Do not put credentials in command-line arguments or reports.

```sh
# In a separate terminal; substitute your MinIO namespace/service as appropriate.
kubectl -n trawl-system port-forward svc/minio 19000:9000 --address 127.0.0.1

# In the terminal with the authorized credential environment:
python3 scripts/benchmark_minio_reads.py \
  --endpoint http://127.0.0.1:19000 --size-mib 8 --trials 3 \
  --output build/remote-reads/minio-measured.json
```

The MinIO script attempts cleanup in `finally`, records the owned bucket and explicit key
count, and fails if cleanup fails. A forced process termination cannot guarantee cleanup;
use the report's owned bucket identifier to recover. Stop the port-forward when finished.
The counting proxy is deliberately restricted to localhost MinIO and explicit object paths;
it is not an AWS/R2 proxy or general S3 client.

The current raw reports are under ignored `build/remote-reads/`. A compact copy of the measured
summaries, versions, parameters, validation counts, and cleanup result is kept in the repository at
[`benchmarks/remote-io-2026-09-17.json`](benchmarks/remote-io-2026-09-17.json).
CI runs the nine instrumentation tests plus a small loopback smoke matrix and uploads its
request traces. CI does not need or use MinIO credentials. The workflow was edited locally;
its hosted execution is not part of these measurements.

## Decision at the baseline

No additional production-reader change was made for this benchmark. The next useful experiment
is bounded, large-window reads through DuckDB's shared external file cache, evaluated against
these baselines for repeated-query byte reuse, request count, memory use, and local selective-I/O
regressions. It should earn its complexity through measured improvement. Simply replacing
every tiny read with an independently cached range is not justified by these results.

Still open: large objects and captures, PCAPNG remote behavior, mixed packet distributions,
glob/listing overhead, cache invalidation under object replacement, memory pressure, direct
MinIO endpoint tests, and actual AWS S3/R2 measurements. These small synthetic runs do not
predict cloud bills or complete the progressive scale ladder in the gap analysis.
