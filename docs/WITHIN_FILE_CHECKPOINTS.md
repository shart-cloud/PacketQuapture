# Within-file packet-time checkpoints — feasibility study

This is a measurement record and a recommendation. No checkpoint implementation
exists, no reader behaviour changed, and no speedup is promised. It answers one
question: once [catalog pruning](CATALOG_PRUNING.md) has retained a file, what does a
selective timestamp query still cost inside that file, and how much of that cost could
region metadata remove?

## Where whole-file selection stops

Catalog pruning decides whether to open a capture. Inside a retained capture the
reader walks every record: it reads each 16-byte record header and, when the
projection does not need payload, seeks past the payload. Timestamp predicates are
applied to rows after decoding. Nothing in the current design lets a predicate skip
a region of a file it has already decided to open.

The measurements confirm that directly. In every recorded case a selective query and
an unrestricted scan read **identical capture bytes and issue identical syscalls**.

## Method

Captures are synthetic classic PCAP with ascending timestamps, plus one shuffled
control. Each query window is one hundredth of the capture's time span, taken from
the middle. Three shapes hold the byte volume roughly constant near 300 MB while
varying packet count, because packet count turns out to be the variable that matters.

Timing and syscall accounting are separate passes: `strace` inflates elapsed time by
more than two orders of magnitude here and is never used for a reported time. Capture
data reads are counted separately from listing and identity syscalls on the same path.

Warm rows repeat an already-read file. Cold rows call `POSIX_FADV_DONTNEED` on the
capture first. That drops the page cache **for that file only**; dentry and inode
caches, the DuckDB process start, and any WSL or host storage caching are not
controlled. Each query is a fresh CLI process, so reported times include the measured
process start of 0.014 s, which is not subtracted. These are single-machine synthetic
observations, not certified cold-disk or cloud-service measurements.

## Measured baseline

Median of three trials, commit `e5ad694`, release build.
[Evidence](benchmarks/within-file-checkpoints-2026-09-20.json) carries every trial.

| Case | Packets | File | Selective warm | Selective cold | Full scan warm | Inventory warm |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `large_payloads` (15,000 B) | 20,000 | 300 MB | 0.044 s | 3.508 s | 0.046 s | 0.034 s |
| `mixed_payloads` (1,500 B) | 200,000 | 303 MB | 0.308 s | 0.553 s | 0.238 s | 0.189 s |
| `small_payloads` (150 B) | 2,000,000 | 332 MB | 2.597 s | 2.665 s | 1.877 s | 1.487 s |
| `unsorted_control` (shuffled) | 200,000 | 303 MB | 0.374 s | 0.654 s | 0.273 s | 0.202 s |

Capture-data reads for the selective query, with listing/identity syscalls counted
separately. The final column compares the selective query against the full scan.

| Case | Capture bytes read | Read calls | Seek calls | Identity calls | Share of file | Same as full scan |
| --- | ---: | ---: | ---: | ---: | ---: | :---: |
| `large_payloads` | 320,024 | 20,003 | 20,000 | 5 | 0.1% | yes |
| `mixed_payloads` | 3,200,024 | 200,003 | 200,000 | 5 | 1.1% | yes |
| `small_payloads` | 32,000,024 | 2,000,003 | 2,000,000 | 5 | 9.6% | yes |
| `unsorted_control` | 3,200,024 | 200,003 | 200,000 | 5 | 1.1% | yes |

Bulk-read reference floors on the same files, with no decoding, give the I/O cost of
reading everything versus reading one contiguous window of the same width as the query.

| Case | Whole file warm | One window warm | Whole file cold | One window cold |
| --- | ---: | ---: | ---: | ---: |
| `large_payloads` | 0.0587 s | 0.0007 s | 0.1963 s | 0.0031 s |
| `mixed_payloads` | 0.0564 s | 0.0006 s | 0.1994 s | 0.0065 s |
| `small_payloads` | 0.0683 s | 0.0008 s | 0.4519 s | 0.0059 s |
| `unsorted_control` | 0.0772 s | 0.0009 s | 0.3169 s | 0.0043 s |

## Cost model

Elapsed time tracks packet count, not file size. Across the three ascending shapes,
which differ in byte volume by under 11%, the selective query costs 1.29–1.51 µs per
packet warm, and total time varies by a factor of 59 (0.044 s against 2.597 s).
Selectivity does not enter the model at all: the predicate changes the answer, never
the work.

Two separable components make up that per-packet cost. An isolated C program
reproducing only the reader's `read(16)` plus `lseek` pair, on the same files and
kernel, takes 0.018 s, 0.145 s and 1.283 s warm for the three shapes, which is 60%, 49%
and 50% of each corresponding scan once process start is removed. The remainder is
decode, vector construction, filter evaluation and progress accounting. So roughly
half of the warm cost is syscall traversal and roughly half is per-packet pipeline work.

The cold `large_payloads` row deserves separate attention. Answering a query that
matches 200 packets takes 3.508 s, while bulk-reading the entire 300 MB file cold
takes 0.196 s. Seeking past 15,000-byte payloads defeats readahead and turns each
record header into an independent cold page fault. On cold cache with large payloads,
the existing payload-skipping seek is roughly an order of magnitude **slower** than
reading the whole file would be. That is a present-day defect, not a checkpoint
question, and it is the single largest number in this study.

## What checkpoints could remove, and what they could not

For a query matching one hundredth of an ascending capture, correct region metadata
could in principle skip roughly 99% of both components, leaving the one-window I/O
floor of 0.0006–0.0065 s plus decode of the matching packets. Against the measured
baselines that is an upper bound, not a projection: it assumes ascending timestamps,
perfectly aligned regions, and validation that costs nothing.

The bound does not apply uniformly:

- `unsorted_control` costs the same 0.374 s as its ascending twin. Per-region minima
  and maxima would each span most of the capture and exclude nothing, while still
  paying full build and storage cost. Real captures merged from multiple interfaces or
  reordered in transit can behave this way, and nothing in a capture declares that it is
  ordered.
- `large_payloads` warm already costs 0.044 s, of which 0.014 s is process start. The
  absolute saving available warm is under 0.03 s.
- The cold `large_payloads` case is where the largest saving sits — but, as above, most
  of that gap is recoverable by fixing the seek behaviour rather than by indexing.

## A cheaper change that captures part of the same cost

Reading record headers in bulk instead of one `read` per packet needs no stored
metadata, no identity validation, no versioning and no fallback path. It addresses
the roughly half of warm cost that is syscall traversal, and it directly addresses the
cold large-payload pathology: in the isolated program, cold, the per-record pattern
took 5.613 s against 0.600 s to bulk-read the same file, about 9× on a like-for-like
comparison that decodes nothing in either case. It cannot touch the per-packet decode
half, because it still visits every packet.

Checkpoints and buffering are complementary, not alternatives. Buffering lowers the
cost of the regions that are visited; checkpoints reduce how many regions are visited.
Buffering is far smaller, carries no correctness surface, and its benefit is measurable
before any index exists — which also means it changes the baseline that a checkpoint
proposal would have to beat.

## What checkpoints would cost

Building region metadata requires one full traversal, which is what
`capture_inventory` already does: 0.034 s, 0.189 s and 1.487 s warm for the three
shapes, and up to 3.544 s cold. That is roughly the cost of one selective query, so a
capture queried once selectively gains nothing; the investment repays only across
repeated selective queries against an unchanged file.

The correctness surface is the substantial cost. Every requirement below comes from
the existing identity contract, and none of it is optional:

- Versioned, rebuildable metadata, with unknown or stale versions falling back to
  scanning rather than to a wrong answer.
- True per-region minimum, maximum and NULL-count statistics, including packets the
  decoder does not support.
- Verified record boundaries, original packet numbers and byte offsets, so that
  `packet_number` and progress accounting stay identical to a full scan.
- Source identity validated at execution time. All current identities are weak or
  unavailable, so strict mode would scan and only the explicit immutable promise could
  enable skipping — exactly the limitation catalog pruning already carries.
- Full-row `EXCEPT ALL` parity against unindexed scans for unsorted captures, all-NULL
  and empty timestamps, region boundaries, duplicate inputs, changed sources and
  prepared-query reuse, across thread counts.
- Demonstrated avoided capture-data reads, counted separately from identity traffic.

PCAPNG additionally needs section byte order, interface definitions and timestamp
resolution restored at any entry point that is not the start of the file, so it cannot
be enabled in a first change.

## Recommendation

The premise of the milestone is confirmed: within-file time selection currently does
nothing, and for repeated selective queries over large, ordered, many-packet captures
the available headroom is real and large.

Even so, checkpoints should not be the next change. Two measurements argue against
starting there. Half the warm cost and nearly all of the worst cold case come from the
per-record read-and-seek pattern, which a bounded buffering change removes without any
new correctness surface. And the build cost equals about one selective query, so the
feature only pays back on repeated queries against files that are both ordered and
stable — a workload this study has not observed in real captures, only constructed.

Proposed order:

1. **Done.** Fix the per-record traversal: bulk header reads, and stop seeking past
   payloads when the gap is small enough that reading it is cheaper. See
   [local record traversal](RECORD_TRAVERSAL.md) for the behaviour and its measured
   effect, recorded by re-running this benchmark unchanged.
2. Re-measure the remaining headroom against the new baseline, and gather real capture
   shapes — packet-size distribution, timestamp ordering, query selectivity and repeat
   rate. The decision to index depends on whether real captures resemble
   `mixed_payloads` or `unsorted_control`, and this study cannot answer that.
3. Only if step 2 still shows worthwhile headroom, prototype checkpoints for classic
   PCAP under the correctness requirements above, with PCAPNG deferred.

Step 1 moved the baseline that step 3 must now beat. Selective queries warm are 1.7×
to 2.1× faster on the packet-dense shapes, and an inventory refresh of `small_payloads`
is 5.0× faster, so the absolute saving still available to checkpoints on those shapes
has shrunk by about half. The per-packet pipeline work that only region skipping can
remove is now the larger share of what remains. `large_payloads` is unchanged. The cold
sparse pathology this study identified was not addressed by step 1 and is not a
checkpoint question; a readahead hint for sparse local captures now addresses it, see
[record traversal](RECORD_TRAVERSAL.md#readahead-hint-for-sparse-local-captures).

Do not turn region statistics into optimizer bounds or cached `EMPTY_RESULT` plans;
the same weak-identity argument that keeps catalog counts out of the optimizer applies
unchanged here.

## Reproduction

```sh
cmake --build build/release --target libduckdb.so shell -j 4
python3 scripts/benchmark_within_file_checkpoints.py \
    --output docs/benchmarks/within-file-checkpoints-2026-09-20.json
```

Needs Linux and `strace`. The run generates about 1.2 GB of captures under
`build/checkpoint-captures` and removes them on exit unless `--keep` is given; pass
`--quick` for a fast check with smaller captures. Recorded on WSL Ubuntu against
commit `e5ad694`; the evidence file carries the CPU, compiler, build flags, DuckDB
version and the full per-trial timings behind every median quoted here.
