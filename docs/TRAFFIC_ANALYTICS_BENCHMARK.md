# Traffic analytics validation

Date: 2026-09-28

This record covers the connection-analytics slice on generated distributions and the
public RAT04 SpyMAX capture. It is validation evidence, not a stable performance
guarantee across machines or PacketQuapture versions.

## Environment

- DuckDB v1.5.5, PacketQuapture development build, eight DuckDB threads.
- Linux 6.6.114.1 under WSL2, x86-64; 12th Gen Intel Core i9-12900HK VM allocation
  with four cores/eight threads.
- DuckDB memory limit: 15.6 GiB; temporary directory: `.tmp`.
- Measurements used a warm filesystem page cache because the archive was downloaded
  and extracted immediately before the runs.

## Generated distributions

`scripts/generate_flow_captures.py` creates independent eight-connection groups with
fixed, jittered, deterministic irregular and bursty intervals, plus alternating small
and large payloads. The checked golden metrics are:

| Case | Median interval | Interval MAD | Median payload | Payload MAD | Timing | Size | Score |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| jittered | 300,000 ms | 60,000 ms | 3 B | 0 B | 20 | 100 | 55 |
| irregular | 419,000 ms | 222,000 ms | 3 B | 0 B | 0 | 100 | 45 |
| burst then pause | 1,000 ms | 0 ms | 3 B | 0 B | 100 | 100 | 95 |
| periodic, variable size | 300,000 ms | 0 ms | 153 B | 150 B | 100 | 0 | 75 |

The burst case deliberately records the behavior of the robust MAD metric: one large
gap does not outweigh six identical intervals. This is visible in the raw intervals
and is not described as proof of malicious activity.

Additional regression cases cover missing and late timestamps, partial and
boundary-finalized sessions, IPv4/IPv6 CIDR boundaries, internal/external orientation,
duration threshold edges, repeated source occurrences, duplicate timestamps, bounded
evidence and exact one-thread/eight-thread equality.

An `EXPLAIN` check of each public analysis entry point shows one `READ_FLOWS`
operator. The materialized connection-facts CTE therefore shares a single capture
scan across each query's downstream aggregates.

The connection-slice validation passed 2,652 release assertions across all 17 SQL test
files. The focused traffic-analytics suite passed 171 assertions under both ASan/UBSan
and ThreadSanitizer; its determinism case compares complete beacon results at one and
eight DuckDB threads.

## Generated DNS tunneling cases

The phase-4 fixture contains 24 distinct 32-character base32-like subdomains with
NXDOMAIN responses and 20 ordinary queries over four short service names with answers.
Under a one-second minimum span, `pq-dns-tunnel-v1` scores them 82.667 and 17.066,
respectively. The result exposes every raw component; entropy contributes at most 20
points and cannot independently produce a high score.

- `tunnel_analytics.pcap` SHA-256:
  `d48ecd95ecb76d54e859be3ccbd36dc3d40690a969d9da4fce7db2dd14b5247b`.
- `encrypted_dns_opaque.pcap` SHA-256:
  `664846ab2c45da9ff819cc5e7612e120a1981fcecf53129aa26da91d551087e3`.

The DNS suite also checks the pinned PSL's wildcard, exception, private and unknown
rules, TCP diagnostics, CNAME/multiple-answer messages, malformed and truncated DNS,
and opaque DNS-shaped bytes on ports 443 and 853. With this slice included, the full
release suite passes 2,768 assertions across 18 SQL files, and the focused DNS suite
passes 116 assertions under ASan/UBSan and ThreadSanitizer.

## RAT04 SpyMAX corpus

Provenance: Stratosphere Laboratory's
[Android Mischief Dataset](https://www.stratosphereips.org/blog/2020/11/10/android-mischief-rats-dataset),
RAT04 SpyMAX v2.0. The archive was downloaded from the dataset's CTU server and kept
outside the repository.

- Archive: `SpyMax.zip`, 87,188,712 bytes,
  SHA-256 `af8cf33430d13b2270bef2594dc21635635342de8aab526383d5d704588c3763`.
- Capture: `RAT04.pcap`, 162,451,456 bytes,
  SHA-256 `aab4a4df2022af3750b929791f0990d46aedb3969a421b895c06caaecb35b8bf`.
- Local-network policy: `['10.8.0.0/24']`.

Each command ran in a separate DuckDB process under `/usr/bin/time -v`:

| Analysis | Wall | User CPU | System CPU | Peak RSS | Observed temp output |
| --- | ---: | ---: | ---: | ---: | ---: |
| talkers, top 10 | 0.23 s | 0.35 s | 0.08 s | 40.2 MiB | 0 B |
| long connections, 1-hour threshold | 0.16 s | 0.27 s | 0.03 s | 31.4 MiB | 0 B |
| beacons, top 10 | 0.23 s | 0.42 s | 0.06 s | 58.4 MiB | 0 B |

These local scans make no remote requests. No spill was observed; “0 B” is the process
file-output counter, not a promise that every larger corpus will avoid DuckDB temporary
storage.

### Result checks

- `10.8.0.93` ranked first by payload with 149,725,783 observed payload bytes,
  194,722 packets and 522 connection facts.
- `147.32.83.181` ranked second by payload; the service had 16 connection facts on
  TCP port 8000.
- The one-hour long-connection query returned `10.8.0.93` to
  `147.32.83.181:8000` at 5,854.636 seconds and 2,035,211 payload bytes.
- The same service's beacon score was 30.0: interval and payload dispersion each
  contributed zero, while support and span each contributed 100. This keeps the raw
  evidence visible without forcing a high beacon finding.
- The highest beacon scores belonged to regular background service traffic, reinforcing
  that these scores identify periodic evidence for analyst review rather than malware.
