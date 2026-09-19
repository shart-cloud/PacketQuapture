# SQL-selected PCAP export

PCAP export writes raw SQL-selected packets to one local classic-PCAP file.

```sql
COPY (
    SELECT timestamp, captured_length, original_length, link_type, packet_data
    FROM read_packets('capture.pcap')
    WHERE dst_port=443
    ORDER BY packet_number
) TO 'selected.pcap' (FORMAT PCAP, LINKTYPE 1, USE_TMP_FILE true);
```

The output can be read with PacketQuapture, libpcap, tcpdump, or Wireshark, subject
to their format/packet-size limits and the timestamp compatibility note below.
This exports packet bytes rather than TCP reconstruction output. PCAPNG interface
metadata, comments, options and other blocks are not round-tripped.

## Required columns and options

Names are case-insensitive, may be reordered, and must each appear exactly once.
Extra columns are ignored by the writer. Required types are exact; cast explicitly
when constructing rows or adapting another source. NULL in any required column fails.

| Column | Type | Meaning |
| --- | --- | --- |
| timestamp | TIMESTAMP | Unix timestamp represented at microsecond precision |
| captured_length | UINTEGER | Must equal the BLOB size |
| original_length | UINTEGER | Must be at least captured_length |
| link_type | UINTEGER | Must equal the required LINKTYPE option for every row |
| packet_data | BLOB | Raw frame bytes, including valid zero-length BLOBs |

`LINKTYPE` is mandatory even for an empty result and must be an integer from 0 to
65535. FCS/additional metadata bits are unsupported. Mixed link types fail; explicitly
filter or separate them in SQL. The optional positive integer `SNAPLEN` rejects larger
packets without truncating them. If omitted, it is inferred from the maximum captured
length, at least one for an empty/zero-length capture.

Output is PCAP 2.4, little endian, with microsecond timestamps. Values before the Unix
epoch or beyond `4294967295999999` microseconds are rejected. TIMESTAMP_NS is rejected
as an input type; an explicit cast to TIMESTAMP makes precision reduction visible.
The existing readers already expose microsecond timestamps, so discarded source
nanoseconds cannot be restored. Installed libpcap 1.10.4 interprets dates after the
signed-seconds boundary in January 2038 differently; see the measured
[writer compatibility note](PCAP_WRITER.md#independent-decoder-compatibility).
PacketQuapture preserves the unsigned PCAP seconds range through 2106.

Staging, order preservation, and empty-file creation are always enabled. Options
`USE_TMP_FILE true`, `PRESERVE_ORDER true`, and `WRITE_EMPTY_FILE true` are accepted;
false is rejected. Other options are rejected, including append, overwrite flags,
partition/per-thread output, rotation/file-size limits, compression and RETURN_FILES /
RETURN_STATS. COPY returns the ordinary Count of rows written. Ordinary single-file
replacement is the default; it does not need an OVERWRITE option. COPY FROM PCAP is
not registered; use the packet readers.

## Ordering and bounded writing

An explicit query ORDER BY determines the record order across DuckDB thread counts,
even when the session has `preserve_insertion_order=false`. For multiple captures,
use appropriate tie breakers, for example `ORDER BY filename, packet_number`.
Duplicate paths can contain identical tie keys; SQL must provide any additional
ordering distinction the application requires. Without ORDER BY, order is unspecified.

The extension uses DuckDB's regular ordered COPY sink, not parallel writers protected
by a mutex. Packet blobs are accessed through vector views and are not retained or
copied into a growing writer buffer. The [independent writer](PCAP_WRITER.md) makes
writes of at most 64 KiB, checking interruption between calls. A SQL sort can use
DuckDB's own memory and spill facilities; sorting cost is separate from writer state.

## Publication and ownership

The destination must be a local regular-file path with an existing parent directory.
Directories, pipes, devices and remote output are rejected. Inputs may come from any
supported reader/filesystem. DuckDB external-access restrictions continue to apply;
allowlists must permit the adjacent staging file as well as the destination.

Each bound COPY plan names a UUID staging file in the destination directory. Each
execution creates it exclusively, so prepared re-execution cannot truncate a colliding
file. It retains that handle/descriptor until it has finished all records, patched
snaplen, synced and closed successfully. Only then does DuckDB's local MoveFile operation
replace the destination. Multiple successful writers targeting the same name use the
underlying replacement semantics: the last successful publication wins, with no record
interleaving. This is not compare-and-swap or append.

The pinned DuckDB engine tracks the staging path for failure cleanup, never the final
destination. The extension also closes and removes its own staging file on failure.
Unrelated temporary files are not removed. Invalid rows, source errors, interruption,
write errors, failed sync/close and failed rename preserve an existing destination. Failed
new exports are not published. Cleanup is best-effort if the filesystem itself refuses
removal; crashes can leave staging files. Parent path bindings must remain stable during
export, and no crash-consistency or cross-filesystem atomicity guarantee is implied.
An existing symbolic link to a regular file follows the filesystem's named-path
replacement semantics; exporting replaces the link entry rather than rewriting its target.

The Windows backend in pinned DuckDB v1.5.5 ignores its exclusive-create flag, so the
Windows adapter uses `_wsopen_s` with `_O_EXCL` and retains the same descriptor. It
checks DuckDB file-access configuration before creating it. POSIX uses exclusive
`open` and checked `write`/`fsync`/`close`, because the pinned DuckDB handle discards
close errors. Both retain the original descriptor throughout. This is a deliberate compatibility adaptation,
not a change to the vendored DuckDB source.

**COPY publication is not a DuckDB transaction rollback operation.** A successful
export remains after SQL ROLLBACK. Interruption after successful publication also
cannot undo it. Sync covers the staging file; the extension does not claim directory
fsync/crash durability or stronger rename guarantees than the underlying platform.

## Validation and reproduction

```sh
cmake --build build/release --target libduckdb.so shell unittest -j 4
./build/release/test/unittest 'test/sql/*'
python3 test/unit/pcap_copy_test.py
python3 test/unit/pcap_writer_roundtrip_test.py
python3 scripts/benchmark_pcap_copy.py
```

Portable SQL tests run through the existing native distribution matrix. Linux lifecycle
tests include exact header/payload/length/timestamp readback, column reordering, empty and
zero-length output, strict types/NULLs, order across 1/2/4/8 threads, malformed sources,
prepared reuse, same-source/destination replacement, multiple and remote inputs,
concurrent publishers, real RLIMIT_FSIZE write failures, SIGINT cleanup, injected fsync / close /
rename failures, access restrictions and preservation of unrelated staging files.
The core also has independent libpcap/tcpdump and ASan/UBSan coverage. ThreadSanitizer
runs the ordered COPY SQL tests. New hosted Windows/macOS checks remain a release gate.

The benchmark verifies output size and complete ordering while measuring SQL-generated
exports with 64/1500-byte frames, 1,000/10,000 packets and one/four query threads.
Elapsed time includes sorting, writing, sync, close and publication. OS cache state is
uncontrolled; no cold-disk or cloud-performance claim is made.
