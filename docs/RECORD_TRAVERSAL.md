# Local record traversal

Local seekable captures are read through a bounded window instead of one read and one
seek per packet. Reader schemas, packet numbering, progress accounting and every
remote or non-seekable path are unchanged. This is the first step recommended by the
[checkpoint feasibility study](WITHIN_FILE_CHECKPOINTS.md).

## Two modes, chosen by the observed payload gap

A scan starts in **cursor mode**, which is the previous behaviour exactly: sequential
reads through the file handle, seeking past any payload the projection does not need.
Nothing is read on speculation, so a metadata-only scan of a capture with large payloads
still touches only the file header and one record header per packet.

After a skipped payload of 4 KiB or less, the scan switches to **window mode**: a 256 KiB
positioned read serves the following record headers, and payload gaps that fall inside
the window cost no syscall at all. A later gap wider than 4 KiB returns the scan to
cursor mode and reseeks, so a capture whose packet size changes adapts in both
directions within one file.

The threshold reflects that a gap of a few kilobytes shares pages with the record
headers around it: reading through costs less than the syscall that skipping saves.
Reads already larger than a window are served directly rather than buffered.

Window mode is enabled only for local seekable files. Remote captures keep their
existing 4 MiB cached window, and pipes and other non-seekable sources keep the
sequential fallback, so no request count or byte total over HTTP or S3 changes.

## The trade this makes

Window mode reads payload bytes that cursor mode skipped. For a capture of 1,500-byte
packets, a `count(*)` that previously read 1.1% of the file now reads essentially all
of it, in about 1,160 syscalls rather than 400,003. That is the intended exchange:
the measurements behind it show elapsed time tracking syscalls rather than bytes on
local storage. It does not apply to remote sources, where bytes are the cost that
matters, and it does not apply to captures whose payloads exceed the threshold.

`scripts/benchmark_header_reads.py` continues to assert exact byte totals for the
large-payload fixture at every projection depth, including rejected filters, truncated
payloads and named pipes. Those totals are unchanged.

## Measured effect

Median of three trials against commit `e5ad694`, same machine and build,
[evidence](benchmarks/record-traversal-2026-09-20.json). Warm trials varied by at most
1.20× across all cases and are the reliable figures here.

| Case | Selective warm | Inventory warm | Syscalls | Capture bytes read |
| --- | --- | --- | --- | --- |
| `large_payloads` (15,000 B) | 0.044 → 0.049 s | 0.034 → 0.039 s | 40,003 → 40,002 | 320,024 → 320,024 |
| `mixed_payloads` (1,500 B) | 0.308 → 0.181 s (1.7×) | 0.189 → 0.081 s (2.3×) | 400,003 → 1,160 | 3,200,024 → 303,055,180 |
| `small_payloads` (150 B) | 2.597 → 1.236 s (2.1×) | 1.487 → 0.299 s (5.0×) | 4,000,003 → 1,269 | 32,000,024 → 331,827,834 |
| `unsorted_control` | 0.374 → 0.192 s (2.0×) | 0.202 → 0.083 s (2.4×) | 400,003 → 1,160 | 3,200,024 → 303,055,180 |

`large_payloads` stays in cursor mode throughout, so its syscalls and bytes are
unchanged by construction and the small warm difference is within run-to-run spread.

Cold-cache figures are not reported as gains. Evicting one file with
`POSIX_FADV_DONTNEED` leaves the surrounding caches uncontrolled, and the cold
`large_payloads` trials spanned 73× within a single run. The evidence file records every
trial; the cold pathology that study identified for sparse large-payload captures is
**not** addressed by this change and remains open.

An earlier revision of this change served cursor-mode reads with positioned reads as
well, which measured about 3.4× slower on `large_payloads`: reading at a header-sized
stride through `pread` appears to defeat the kernel's sequential readahead detection.
Cursor mode therefore keeps the handle cursor, and positioned reads are used only for
window refills and oversized reads.

## Validation

```sh
cmake --build build/release --target libduckdb.so shell unittest -j 4
./build/release/test/unittest 'test/sql/*'
python3 test/unit/local_window_test.py
python3 scripts/benchmark_header_reads.py
python3 scripts/benchmark_parallel_scans.py --verify-only --verify-mixes 10
python3 scripts/benchmark_within_file_checkpoints.py --output build/record-traversal.json
```

`local_window_test.py` asserts that a dense capture drops below one read per ten packets
with no seeks, that a sparse capture still reads exactly the file header plus one record
header per packet, that a capture changing packet size mid-file adapts in both
directions, and that five projections over a named pipe match the same query on disk.
It needs Linux and `strace`.

The full release SQL suite (1,933 assertions in 13 cases), capture inventory, catalog
pruning, file pruning, PCAP COPY, remote reads, remote cache, stream memory, native
parallel-scan and scan-progress checks, randomized multiset parity across 10 mixes ×
5 functions × 4 thread settings, and formatting and whitespace checks all passed.
Hosted native platform checks remain required.
