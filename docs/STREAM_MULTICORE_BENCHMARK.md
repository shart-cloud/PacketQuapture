# Stream multicore benchmark

Measured September 18, 2026. PacketQuapture `60d6bd1` (the same source tree merged
in PR #2), DuckDB v1.5.5, release build `-O3 -DNDEBUG`. WSL2 Linux on an Intel
i9-12900HK with eight visible logical CPUs; local ext4 files and a warm OS cache.
The DuckDB memory limit was explicitly set to 4 GiB in every timed run.

## Findings

- Across eight balanced files, the default 512 MiB stream budget produced about
  3.8x speedup with four threads for stream summaries, stream bytes/chunks, and DNS messages.
- With a 1 GiB stream budget, eight threads produced 5.4-5.6x speedup against one
  thread under the same budget. Moving from four to eight workers increased throughput
  by approximately 43-47% on this machine.
- One file remained sequential. Two balanced files saturated at two workers.
  A layout with 80% of packets in one file gained only about 1.2x with four workers.
- 256 small files retained approximately 3.7-3.8x speedup with four workers.
- Live file-descriptor observations confirmed one, two, four, and eight simultaneous
  readers with 128, 256, 512, and 1024 MiB stream budgets for both stream functions.
- All 450 primary timed queries returned matching aggregate results. A separate
  correctness pass completed 200 full-row, duplicate-preserving multiset comparisons.

## Workload and measurement

Each layout contains 262,144 identical workload units: 1,048,576 packets and 82 MiB
of packet records, plus 24 bytes of PCAP header per file. Each unit contains a TCP
SYN, one DNS-bearing data segment, a reset that finalizes the direction, and a UDP
DNS datagram. Results contain 262,144 TCP directions or 524,288 DNS messages.
Units never cross file boundaries, and directions do not accumulate toward reassembly
limits. This makes the same result aggregates comparable across layouts.

The layouts are 1, 2, 4, and 8 equal files; 256 equal small files (about 328 KiB
each); and 8 uneven files, with 80% of the workload in the first file.

Every configuration has five trials. Thread/trial pairs are shuffled within each
layout/query using seed 20260918. Each source is read fully before each trial to warm
its cache. Trials and budget experiments run sequentially, without competing benchmark
queries. Budget phases were not interleaved with one another.

DuckDB JSON profiling supplies query latency, excluding CLI startup. GNU time supplies
whole-process CPU and peak RSS; CPU percentages include CLI startup and use Python
elapsed process time as the denominator. Peak RSS is actual process residency, not
the logical memory reservation. Source MiB/s is file bytes divided by query latency;
it is not disk or network bandwidth. Timing tables report medians unless marked as ranges.

The three measured aggregates are:

```sql
-- TCP stream summary
SELECT count(*), sum(captured_bytes) FROM read_tcp_streams(inputs);
-- TCP bytes and nested chunks
SELECT count(*), sum(octet_length(stream_data)), sum(len(chunks))
FROM read_tcp_streams(inputs);
-- DNS messages, including decoded names
SELECT count(*), sum(octet_length(message_data)), count(dns_question_name)
FROM read_dns_messages(inputs);
```

## Default 512 MiB budget: eight balanced files

| Query | 1 thread (s) | 2 threads (s) | 4 threads (s) | 8 threads (s) | 4-thread speedup |
| --- | ---: | ---: | ---: | ---: | ---: |
| TCP stream summary | 2.256 | 1.161 | 0.588 | 0.611 | 3.84x |
| TCP bytes and chunks | 2.906 | 1.495 | 0.755 | 0.772 | 3.85x |
| Decoded DNS messages | 2.689 | 1.397 | 0.712 | 0.715 | 3.78x |

Eight requested threads still admit at most four stream workers under this budget.

## 1 GiB budget: eight balanced files

| Query | 1 thread (s) | 2 threads (s) | 4 threads (s) | 8 threads (s) | 8-thread speedup |
| --- | ---: | ---: | ---: | ---: | ---: |
| TCP stream summary | 2.197 | 1.144 | 0.582 | 0.408 | 5.38x |
| TCP bytes and chunks | 2.867 | 1.478 | 0.749 | 0.508 | 5.65x |
| Decoded DNS messages | 2.709 | 1.393 | 0.704 | 0.484 | 5.59x |

## Effect of file layout

Default budget; speedup versus one thread for the same layout and query:

| Layout | Threads | TCP summary | TCP bytes/chunks | DNS messages |
| --- | ---: | ---: | ---: | ---: |
| One file | 4 | 0.97x | 1.00x | 0.96x |
| Two balanced files | 2 | 1.93x | 1.95x | 1.97x |
| Four balanced files | 4 | 3.75x | 4.03x | 3.90x |
| Eight balanced files | 4 | 3.84x | 3.85x | 3.78x |
| 256 small files | 4 | 3.71x | 3.78x | 3.82x |
| 80% in one of eight files | 4 | 1.23x | 1.17x | 1.18x |

## CPU use, memory, and timing ranges

Eight balanced files. CPU and peak RSS are medians of five process measurements;
100% CPU is approximately one fully utilized logical CPU.

| Query | Budget MiB | Threads | CPU % | Peak RSS MiB | Query min-max (s) |
| --- | ---: | ---: | ---: | ---: | ---: |
| TCP stream summary | 512 | 1 | 99 | 22.5 | 2.216-2.285 |
| TCP stream summary | 512 | 4 | 389 | 22.5 | 0.566-0.598 |
| TCP stream summary | 1024 | 8 | 703 | 23.1 | 0.389-0.441 |
| TCP bytes and chunks | 512 | 1 | 100 | 22.6 | 2.784-2.992 |
| TCP bytes and chunks | 512 | 4 | 386 | 23.0 | 0.754-0.828 |
| TCP bytes and chunks | 1024 | 8 | 721 | 24.0 | 0.497-0.519 |
| Decoded DNS messages | 512 | 1 | 100 | 22.4 | 2.664-2.814 |
| Decoded DNS messages | 512 | 4 | 382 | 22.5 | 0.690-0.718 |
| Decoded DNS messages | 1024 | 8 | 715 | 23.0 | 0.460-0.513 |

The short, immediately finalized directions keep live reconstruction state small.
These RSS observations cannot justify lowering the 128 MiB allowance or establish
a general process-memory ceiling. Worst-case retained state is covered separately
by the existing memory-pressure correctness tests.

## Admission-budget controls

All rows use eight files and request eight threads. Live-reader counts were measured
in separate untimed probes for both stream functions, so descriptor sampling does not
perturb the reported timings. The probe tolerates process-exit races in `/proc` and
requires a successful query, matching counts, and the expected peak reader count.

| Stream budget MiB | Observed readers | TCP summary (s) | TCP bytes/chunks (s) | DNS messages (s) |
| ---: | ---: | ---: | ---: | ---: |
| 128 | 1 | 2.299 | 3.036 | 2.774 |
| 256 | 2 | 1.161 | 1.489 | 1.379 |
| 512 | 4 | 0.611 | 0.772 | 0.715 |
| 1024 | 8 | 0.408 | 0.508 | 0.484 |

## Validation and limits

- 360 default-budget trials, 60 trials with a 1 GiB budget, and 30 lower-budget
  control trials completed. Every timed aggregate matched across thread counts,
  layouts, and budgets. The 12 calibration trials are excluded from the tables.
- Before timing, 10 randomized fixture mixes across all five readers and four thread
  counts passed full-row EXCEPT ALL comparisons. Those checks include duplicates,
  payloads, nested output, diagnostics, and stable IDs for identical input lists.
- Eight separate admission probes passed: both stream functions at four budgets.
- These are synthetic, warm-cache, local measurements on one virtualized laptop.
  They do not establish cold-cache, remote-storage, long-lived-flow, large-payload,
  multi-query contention, or 200 GB-1 TB lake performance.
- Layouts contain independently finalized units. Real captures split through an
  unfinished TCP direction are not equivalent to the same capture in one file.
- Per-file stream IDs depend on the original ordered input list. Their stability
  across threads is checked separately; IDs are not expected to match after changing
  how records are distributed across files.

## Recommendation

Keep the default 512 MiB admission budget and 128 MiB worker reservation. The benchmark
demonstrates useful four-worker scaling without evidence that the worst-case allowance
can be reduced. A 1 GiB budget is a useful opt-in when eight workers, sufficient DuckDB
memory, and enough balanced files are available.

Proceed with the filename/partition-pruning design. Whole-file parallelism is working;
one dominant file remains a separate scheduling/reconstruction problem.

## Reproduction and local artifacts

Run from the repository root. The main benchmark command is:

```sh
python3 scripts/benchmark_parallel_scans.py \
  --units 262144 --trials 5 --threads 1 2 4 8 \
  --layouts 1 2 4 8 tiny skew \
  --cases streams stream_bytes dns_messages --verify-mixes 10 \
  --memory-limit 4GiB --stream-memory-mb 512 \
  --work-dir build/multicore-streams-20260918/default-data \
  --output build/multicore-streams-20260918/default-512mib.json
```

The recorded run performed the 10 verification mixes in a separate calibration run
and used `--verify-mixes 0` for subsequent timing phases. For the raised-budget phase,
use `--layouts 8 --stream-memory-mb 1024` with distinct output/work directories.
For the two lower-budget controls, use `--layouts 8 --threads 8` and budgets 128/256.
The harness now records effective memory settings and interleaves thread/trial pairs.
No extension runtime code was changed for these measurements.

Local generated artifacts are ignored by git:

- [pilot.json](../build/multicore-streams-20260918/pilot.json)
- [default-512mib.json](../build/multicore-streams-20260918/default-512mib.json)
- [budget-1024mib.json](../build/multicore-streams-20260918/budget-1024mib.json)
- [budget-128mib.json](../build/multicore-streams-20260918/budget-128mib.json)
- [budget-256mib.json](../build/multicore-streams-20260918/budget-256mib.json)
- [observed-workers.json](../build/multicore-streams-20260918/observed-workers.json)
- [worker_probe.py](../build/multicore-streams-20260918/worker_probe.py)
- [summary.json](../build/multicore-streams-20260918/summary.json)
