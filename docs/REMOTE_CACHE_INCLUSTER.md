# MinIO in-cluster benchmark: 1 GiB

## Results — September 17, 2026

All **96 scale queries** returned the expected **1,032,444 packets**, and all **16 smoke queries** passed. The in-cluster counting proxy agreed exactly with DuckDB HTTP logs on GET counts and response bytes for every proxied query.

Timings below are medians of three trials. Each first scan uses a fresh DuckDB database; MinIO and operating-system caches were not cleared.

| Path | Files | Limit MiB | Cache | First seconds | Repeat seconds | Repeat GETs (range) | Repeat body MiB (range) |
| --- | ---: | ---: | --- | ---: | ---: | ---: | ---: |
| direct | 1 | 128 | on | 3.623 | 3.456 | 241–256 | 964.0–1024.0 |
| direct | 1 | 128 | off | 3.719 | 3.749 | 256–256 | 1024.0–1024.0 |
| direct | 1 | 2048 | on | 5.066 | 0.612 | 0–0 | 0.0–0.0 |
| direct | 1 | 2048 | off | 4.058 | 4.273 | 256–256 | 1024.0–1024.0 |
| direct | 8 | 128 | on | 2.670 | 2.698 | 256–256 | 1024.0–1024.0 |
| direct | 8 | 128 | off | 2.753 | 2.767 | 256–256 | 1024.0–1024.0 |
| direct | 8 | 2048 | on | 2.568 | 0.200 | 0–0 | 0.0–0.0 |
| direct | 8 | 2048 | off | 2.778 | 2.703 | 256–256 | 1024.0–1024.0 |
| proxy | 1 | 128 | on | 4.432 | 4.303 | 241–256 | 964.0–1024.0 |
| proxy | 1 | 128 | off | 4.292 | 4.182 | 256–256 | 1024.0–1024.0 |
| proxy | 1 | 2048 | on | 5.033 | 0.656 | 0–0 | 0.0–0.0 |
| proxy | 1 | 2048 | off | 4.248 | 4.209 | 256–256 | 1024.0–1024.0 |
| proxy | 8 | 128 | on | 2.861 | 2.840 | 256–256 | 1024.0–1024.0 |
| proxy | 8 | 128 | off | 2.908 | 2.901 | 256–256 | 1024.0–1024.0 |
| proxy | 8 | 2048 | on | 2.813 | 0.225 | 0–0 | 0.0–0.0 |
| proxy | 8 | 2048 | off | 2.871 | 2.844 | 256–256 | 1024.0–1024.0 |

## Interpretation

Direct first-scan medians ranged from 2.57 to 5.07 seconds; in-cluster proxied medians ranged from 2.81 to 5.03 seconds. The earlier WSL proxy/port-forward run took roughly 98–114 seconds per first scan. This large path-dependent difference shows why those earlier timings cannot establish a MinIO storage bottleneck. It is not an isolated measurement of tunnel overhead: client placement, CPU allocation, runtime, and storage-cache state also differ.

Every cached repeat with a 2,048 MiB limit fetched zero payload bytes. At 128 MiB the working set did not fit and repeats reread most or all of it. Cache-disabled scans fetched 256 windows on every query. Keep the 4 MiB window policy: this experiment does not compare window sizes.

Three ordered trials provide repeatability evidence, not a randomized performance study. Direct trials precede proxy trials for each layout. All work ran on the same node as MinIO, so these are neither cross-node network-throughput measurements nor AWS S3/R2 predictions. Eight DuckDB threads ran inside a four-CPU pod; do not compare warm CPU timings directly with the earlier WSL run.

## Method and limits

The existing classic-PCAP generator produced 1,024-byte Ethernet/IPv4/TCP frames. Each layout had 1,032,444 records: one approximately 1 GiB object or eight approximately 128 MiB objects. The query was SELECT count(*) FROM read_pcap([...]); every result matched a local-file baseline. The one-file size was 1,073,741,784 bytes; eight files totaled 1,073,741,952 bytes. Metadata scanning can skip a small tail, so response bytes need not equal source bytes.

The matrix was 2 access modes × 2 layouts × 2 memory limits × 2 cache settings × 3 trials × first/repeat = 96 queries. HTTP metadata caching was off and default cache validation stayed on. The smoke run used 8 MiB and a 32 MiB memory limit, for 16 queries.

DuckDB HTTP logging used memory storage and only method, status, and Content-Length were extracted. URLs, signed headers, and credentials were not exported. Reported body bytes sum successful GET response lengths; they exclude protocol overhead and are not an independent packet-level byte measurement. For proxy mode, the non-caching proxy independently counted forwarded bytes and agreed with the logs. Logging and a 20 ms process-RSS sampler were enabled for timed queries. The sampler can miss peaks, and RSS includes runtime/proxy overhead; it is not DuckDB cache residency or a hard allocation bound.

The pod was limited to 4 CPU, 4 GiB memory, 6 GiB ephemeral storage, and 2,400 seconds. Queries had 120-second interruption timers and HTTP retries were disabled. Direct request/byte budgets were checked after each query, not enforced during network reads; proxy mode also enforced its request/byte caps. Only unique benchmark buckets and synthetic objects were used.

The namespace default-deny policy required two temporary policies, scoped to benchmark DNS and benchmark-to-MinIO port 9000. Dependencies were copied and installed offline. No service was exposed publicly. Both temporary buckets and their nine objects each were deleted by the harness. The pod and both temporary network policies were deleted after copying results. Generated captures existed only in the disposable pod.

The highest observed resident-cache snapshot was about 124 MiB for the 128 MiB profile and
1,024 MiB for the 2,048 MiB profile. Highest sampled process RSS was about 531 MiB and
1,311 MiB respectively. The profiles ran sequentially in one Python process, so allocator
retention and shared runtime/proxy overhead can carry across queries; RSS is not a
profile-isolated memory limit measurement.

## Evidence and reproduction

- [Scale results, trial ranges, versions, hashes, and cleanup](benchmarks/minio-incluster-1gib-2026-09-17.json)
- [Smoke results and bucket cleanup](benchmarks/minio-incluster-smoke-2026-09-17.json)
- Runner: scripts/benchmark_minio_incluster.py; shared helpers: scripts/benchmark_remote_reads.py and scripts/benchmark_minio_reads.py.
- Raw local artifacts: build/remote-reads/incluster-*.json and incluster-scale.log.

In an equivalently bounded, authorized disposable pod with the current library at /work/build/release/src/libduckdb.so, the three scripts at /work/scripts, matching httpfs installed, boto3 available, and scoped credentials in the environment:

```sh
python /work/scripts/benchmark_minio_incluster.py --size-mib 8 --trials 1 --memory-limits-mib 32 --modes direct proxy --output /work/smoke.json
python /work/scripts/benchmark_minio_incluster.py --size-mib 1024 --trials 3 --memory-limits-mib 128 2048 --modes direct proxy --output /work/scale.json
```

The runner targets the private minio.trawl-system.svc.cluster.local:9000 service. Pod and network manifests used for this run are retained under ignored build/remote-reads/incluster-pod.json and incluster-network.json. Create only the temporary resources, retrieve reports, confirm bucket cleanup, then delete those exact resources. No production reader changes, commits, pushes, or hosted CI runs were performed in this follow-up.
