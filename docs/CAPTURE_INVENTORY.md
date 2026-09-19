# Capture inventory and explicit refresh

`capture_inventory` returns file-level metadata for PCAP and PCAPNG sources. This
implements the inventory milestone of the flows/inventory/export plan. The original inventory milestone did not include reader
catalog arguments, optimizer pruning, within-file indexes or PCAP export; those were not
part of this change. Existing reader schemas and filtering behavior remain unchanged.

```sql
SELECT filename, packet_count, min_timestamp, max_timestamp, scan_status
FROM capture_inventory('captures/**/*.pcap', detail='protocols', on_error='report');
```

## Input and scan semantics

One row is returned for every expanded input occurrence, including duplicate paths.
`input_index` is one-based within the current ordered expansion. Local filenames are
canonical absolute paths; remote locators remain unchanged. Different input aliases
of the same local source still produce separate rows. Lists and globs are supported.
Unlike existing packet readers, inventory expands its original glob patterns again
on each execution, including prepared executions. Output order is unspecified.
An unmatched glob or discovery failure fails the statement, even in report mode;
an explicitly named missing file can produce an error row. Named pipes and
nonseekable sources are rejected. No source files are modified.

`detail='framing'` (default) reads capture framing without decoding packets.
`detail='protocols'` uses bounded link/network/transport headers. Neither buffers
packet payload BLOBs or reconstructs streams. Packet count and byte totals include
all records. Captured/reported bytes sum captured/original frame lengths. Timestamp
bounds are true minima/maxima, including packets unsupported by the decoder; missing
timestamps are counted separately. Empty valid captures have zero totals and NULL
time bounds. A zero-byte file is an invalid capture, not an empty valid capture.
Link types include declared PCAPNG interfaces with no packets and declarations in
empty sections, and are sorted/distinct. Classic PCAP link metadata is retained as
its existing raw unsigned field; this is not a promise that every encoding is decoded.

Protocol counts use the existing decoder's validation boundaries:

- `ipv4_packets` and `ipv6_packets` count successfully decoded network headers.
- `tcp_packets` and `udp_packets` count successfully decoded transport headers.
- `malformed_packets` includes invalid or truncated headers the decoder attempted.
- `unsupported_packets` includes unknown link/network/transport protocols and bounded
  parser limits (over eight VLAN tags or sixteen IPv6 extension headers).
- `fragment_packets` counts non-atomic IP fragments whose transport is not decoded.
- `other_protocol_packets` is the subset of unsupported packets with a decoded IP
  header advertising a protocol other than TCP/UDP.

TCP + UDP + malformed + unsupported + fragment counts sum to packet count. Network
counts overlap these categories. These are decoder dispositions, not deep protocol
validation: payload-only truncation with intact headers is not counted as a malformed
header, checksums are not verified, and valid non-IP traffic can be unsupported.
All protocol counters are NULL in framing mode, not zero.

`on_error='error'` (default) fails on a source error. `on_error='report'` returns
`scan_status='error'` or `'changed'`, NULL statistics and an error description.
It never exposes partial counts as complete. Cancellation, memory exhaustion,
invalid configuration, catalog schema errors and discovery failures always fail the
statement. Remote provider error bodies are not persisted; rerun with error mode for
provider details. Successful rows have `scan_status='complete'` and NULL `scan_error`.

## Identity and freshness contract

Metadata is checked before reading, after reading the same open source, and by
reopening its locator after the scan. An observed identity change invalidates the
statistics. Files must remain immutable during a scan: metadata checks do not turn
external files into transactionally consistent snapshots and cannot detect changes
that leave all available validators unchanged.

`identity_type` names the backend. `identity_value` is a hex encoding of its opaque
version-tag bytes, or NULL; it is not advertised as a content hash. Size and modification
time are independently nullable. `identity_strength` is **weak** or **unavailable**
in this release. No backend currently qualifies for strong validation. A complete scan
with matching available metadata has `metadata_unchanged=true`; that means no change
was observed, not that the content was cryptographically verified. It is NULL when
no identity metadata is available, and false on error/change rows.

| Backend | Pinned API / validation result | Strict reuse |
| --- | --- | --- |
| Local POSIX | Version tag contains device/inode/size/second-resolution mtime; same-size edits with restored mtime evade it | Disabled |
| Local Windows | Version-tag hook returns empty; available Stats size/mtime are weak metadata | Disabled |
| HTTP via httpfs | Loopback probe exercises HEAD metadata and opaque validator; conditional/object snapshot semantics are not certified | Disabled |
| S3 via httpfs | S3 client path exercised against a synthetic loopback range endpoint; this is not an actual AWS/MinIO service test | Disabled |
| Actual S3/MinIO and other providers | Strong freshness/version-pinning guarantees remain unverified | Disabled |

Remote inventories require `SET enable_http_metadata_cache=false` (the normal default).
The function fails clearly if it is enabled; it never changes the caller's setting.
Inventory capture reads bypass the shared external-file cache and use the existing
filesystem's direct-I/O path. Fresh identity checks can issue HEAD requests; avoided
capture-body reads are reported separately from metadata requests. Stable remote
locators must not contain query strings, URL fragments or user information; use
DuckDB's credential mechanisms. Authentication headers and transient signed URLs
are not catalog fields. Inventory refresh itself does not prune reader queries; see [catalog-assisted selection](CATALOG_PRUNING.md) for that separate opt-in API.

## Incremental refresh

```sql
SELECT * FROM capture_inventory(
    'captures/**/*.pcap', previous_catalog='main.capture_catalog',
    detail='protocols', catalog_validation='immutable', on_error='report');
```

`previous_catalog` is a qualified native DuckDB table name, never an SQL expression.
The table must contain every base column below with matching stored types; additional
columns are ignored. Views, generated base columns and foreign tables are not supported.
The name is resolved at bind time; its current transaction-visible contents and schema
are re-read at execution, including prepared reuse. SELECT does not write to the table.

`catalog_validation='strict'` is the default. It scans every source because no currently
supported identity is certified strong. `immutable` explicitly trusts the caller's
guarantee that content and locator bindings are unchanged when available metadata
matches. It still checks available metadata and rejects detected changes. Same-size,
same-mtime edits on POSIX demonstrate why this option is a promise, not verification.
Do not use it for mutable archives. Unavailable identity always falls back to scanning.

Reuse requires a complete, valid, version-compatible summary with matching source
metadata and adequate detail. Protocol summaries can satisfy framing requests, with
protocol columns cleared to NULL. Framing summaries cannot satisfy protocol requests.
Duplicate catalog rows do not multiply input occurrences: matching summaries must
agree, otherwise the source is scanned. Incompatible/error rows and corrupt or missing
statistics force a scan. `reused` and `reuse_reason` expose the decision.
`inventory_time` is this occurrence's inventory attempt time; `source_scan_time` is
retained on reuse and is NULL for a failed scan. Both are DuckDB microsecond timestamps.

Use ordinary SQL for persistence. The following recipe scopes deletion to one complete
collection, retains error rows to invalidate prior summaries, and deduplicates persisted
metadata without deduplicating inventory output or later reader inputs:

```sql
-- First publication. The collection column is application metadata.
CREATE TABLE capture_catalog AS
SELECT 'archive_a' AS collection, *
FROM capture_inventory('captures/archive_a/**/*.pcap',
                       detail='protocols', on_error='report')
QUALIFY row_number() OVER (PARTITION BY filename ORDER BY input_index)=1;

-- Explicit refresh of a collection guaranteed immutable by ingestion.
BEGIN;
CREATE TEMP TABLE previous_inventory AS
SELECT * FROM capture_catalog WHERE collection='archive_a';

CREATE TEMP TABLE staged_inventory AS
SELECT 'archive_a' AS collection, *
FROM capture_inventory('captures/archive_a/**/*.pcap',
                       previous_catalog='temp.previous_inventory',
                       detail='protocols', catalog_validation='immutable',
                       on_error='report')
QUALIFY row_number() OVER (PARTITION BY filename ORDER BY input_index)=1;

-- Execute these only after the entire staging statement succeeds.
DELETE FROM capture_catalog WHERE collection='archive_a';
INSERT INTO capture_catalog BY NAME SELECT * FROM staged_inventory;
DROP TABLE staged_inventory;
DROP TABLE previous_inventory;
COMMIT;
```

On a failed/interrupted staging statement, ROLLBACK; do not run the publication steps.
Do not delete unseen files based on a LIMIT, partial discovery, or a failed scan job.
The implementation completes discovery before producing any rows and raises discovery
errors, but cannot certify a provider that silently returns an incomplete listing.
An entirely absent collection produces an unmatched-glob error; deletion of the whole
collection requires an explicit application decision. DuckDB transactions protect the
catalog publication, not the external files. A failed refresh must never be treated as
proof that an old source identity remains valid; future pruning must revalidate it.

## Base schema

Schema and semantic versions currently equal 1. Consumers must check both. Missing
or uncomputed statistics are NULL. Counter types are checked UBIGINTs.

| Column | Type |
| --- | --- |
| `filename` | VARCHAR |
| `input_index` | UBIGINT |
| `identity_type` | VARCHAR |
| `identity_value` | VARCHAR |
| `identity_strength` | VARCHAR |
| `file_size` | UBIGINT |
| `modification_time` | TIMESTAMP |
| `capture_format` | VARCHAR |
| `link_types` | UINTEGER[] |
| `packet_count` | UBIGINT |
| `min_timestamp` | TIMESTAMP |
| `max_timestamp` | TIMESTAMP |
| `timestamp_null_count` | UBIGINT |
| `captured_bytes` | UBIGINT |
| `reported_bytes` | UBIGINT |
| `detail` | VARCHAR |
| `ipv4_packets` | UBIGINT |
| `ipv6_packets` | UBIGINT |
| `tcp_packets` | UBIGINT |
| `udp_packets` | UBIGINT |
| `other_protocol_packets` | UBIGINT |
| `malformed_packets` | UBIGINT |
| `unsupported_packets` | UBIGINT |
| `fragment_packets` | UBIGINT |
| `scan_status` | VARCHAR |
| `scan_error` | VARCHAR |
| `inventory_time` | TIMESTAMP |
| `source_scan_time` | TIMESTAMP |
| `schema_version` | UINTEGER |
| `semantic_version` | UINTEGER |
| `metadata_unchanged` | BOOLEAN |
| `reused` | BOOLEAN |
| `catalog_validation` | VARCHAR |
| `reuse_reason` | VARCHAR |

## Resources and validation

Independent occurrences use worker-local capture readers. Each admitted worker
reserves 32 MiB through DuckDB's buffer manager; all inventory scans in a query share
`min(packetquapture_inventory_memory_mb MiB, memory_limit/2)`, with a default of 128 MiB.
Actual concurrency also respects input count, thread count, and conservative plan-copy
accounting. The envelope covers the existing maximum 16 MiB interface block, at most
65,536 interface definitions per section, bounded header reads and one output row.
There is no per-packet retained state. LIMIT, errors and interruption release handles
and reservations; report mode does not swallow cancellation or out-of-memory errors.

Previous-catalog entries for candidate sources are snapshotted into a read-only map.
Retained strings, values and lookup keys are conservatively charged to the buffer
manager with a 64 MiB per-invocation cap. Larger snapshots fail explicitly; split an
archive into bounded collections rather than accepting partial reuse. Duplicate rows
are checked for agreement. No stale map persists between executions or connections.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/generate_inventory_captures.py
cmake --build build/release --target libduckdb.so shell unittest -j 4
./build/release/test/unittest 'test/sql/*'
python3 test/unit/capture_inventory_test.py
python3 scripts/benchmark_header_reads.py
PYTHONDONTWRITEBYTECODE=1 python3 scripts/benchmark_inventory.py
```

Inventory tests cover true timestamp extrema, NULL/empty captures, unused link types,
duplicate occurrences, protocol disposition conservation, prior-catalog conflicts,
transaction-local snapshots, prepared changes/discovery, replaced/truncated/deleted
files, same-metadata mutation, mid-scan remote mutation, safe names/locators, bounded
admission and file-level errors. Existing native tests include inventory overlap,
cancellation, LIMIT, connection reuse and descriptor cleanup. Existing SQL and decoder
sanitizer suites verify that other reader output remains unchanged.

The local byte-read fixture contains 60,070,024 bytes. Framing inventory reads exactly
16,024 bytes; protocol inventory reads exactly 70,024 bytes. These are local seekable
file measurements; remote filesystem buffering and request counts have separate
instrumentation. The benchmark reports first inventory, strict refresh, unchanged
immutable refresh and one-file update on increasing synthetic collections, along with
machine/build/cache information. No cold-cache, cloud-service or speedup guarantee is
implied. Hosted native platform checks remain a release gate.


### Recorded local results (September 19, 2026)

- Final release SQL suite: 1,760 assertions across 11 cases; refresh integration: nine tests.
- ThreadSanitizer: full suite passed 1,750 assertions before the final locator/cache guard changes; final inventory suite passed all 92 assertions, and final native concurrency/cancellation checks passed.
- Native query-progress checks passed, including inventory with one and four threads.
- Decoder ASan/UBSan passed 68,000 mutations and 140,000 random link cases.
- Existing file-pruning (six), remote-read (nine), and remote-cache (nine) integration tests passed. Repository formatting passed.
- The documented transactional refresh recipe was executed successfully against the flow fixtures.

[Benchmark evidence](benchmarks/inventory-2026-09-19.json) records implementation
commit `c93e68b`, hardware, build flags, cache caveats and request counts. For 512
synthetic files (1,000 packets each), first inventory took 0.430 s, strict refresh
0.449 s, unchanged immutable refresh 0.058 s and one-file update 0.062 s. These are
single local measurements, not statistical performance claims. Both loopback HTTP
and S3-client immutable refreshes used one HEAD request and zero GET/body bytes.
Actual AWS/MinIO and hosted platform checks remain unverified for this milestone.


Inventory was merged in [PR #5](https://github.com/shart-cloud/PacketQuapture/pull/5)
as `e2896d9cbbdf4893551ba7fcf67283b46105143b`; hosted native platform, quality,
concurrency and decoder checks passed. The following milestone adds
[catalog-assisted packet-time selection](CATALOG_PRUNING.md).
