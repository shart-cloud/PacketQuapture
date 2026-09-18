# Capture scan progress

All five capture table functions now register DuckDB's scan-progress callback:
`read_pcap`, `read_packets`, `read_dns`, `read_dns_messages`, and `read_tcp_streams`.
Enable it through DuckDB's existing controls:

```sql
SET enable_progress_bar = true;
SET progress_bar_time = 500; -- wait 500 ms before showing a terminal bar
SELECT count(*) FROM read_pcap('captures/**/*.pcap*');
```

For a programmatic client, enable progress but disable terminal printing:

```sql
SET enable_progress_bar = true;
SET enable_progress_bar_print = false;
```

Use DuckDB's normal query-progress API (for example, `duckdb_query_progress` in the C API).
Its row counters are DuckDB's normalized query-progress units, not PacketQuapture packet
counts. The extension reports a scan percentage; DuckDB combines that with other query work.
This change does not add optimizer cardinality estimates.

## What the percentage measures

Progress is the logical parser position across all input occurrences, divided by their total
file size. Unequal files are weighted by bytes. Repeated paths in an input list count repeatedly,
just as they do in query results. File-size discovery is performed for each execution, rather
than storing a denominator in prepared-statement bind data.

Payload bytes skipped by seeking still count as consumed input. Remote windows count only as
the parser consumes them, not when read-ahead fetches them. Cached reads therefore advance the
same byte accounting even when they transfer no network bytes. This is a scan-work measure,
not a download meter or a time-remaining estimate.

Workers publish counters at 64 KiB logical-byte intervals and at EOF. Shared counters are
atomic; the callback does not inspect mutable reader or reassembler state. Packet scans reach
100% only when every input occurrence reaches EOF. Stream scans stay below 100% while buffered
stream/message output is draining. Early LIMIT, errors, and cancellation do not falsely mark
unread input complete; DuckDB itself controls the final query display.

## Metadata cost and unknown sizes

When `enable_progress_bar` is false, the reader does not perform progress-specific size
checks and does not update progress counters. This preserves the default C API benchmark's
remote request behavior.

When enabled, initialization opens each input briefly to obtain its size, then closes that
handle. Only one metadata handle is open at a time. Remote storage can therefore see an
additional metadata request per input occurrence (usually a HEAD); large file collections
can incur extra startup time. Metadata-cache settings may reduce those requests. These checks
do not read packet contents or populate the packet-byte cache.

Named pipes are recognized before opening them for metadata, avoiding a blocking FIFO open.
Pipes, non-seekable/unknown-size inputs, or failed metadata probes make the scan callback
return unavailable rather than inventing a percentage. The actual scan retains responsibility
for reporting input errors. If a file's size differs when the reader opens it, the estimate is
invalidated. This is not a snapshot guarantee against a file changing during the scan.

## Refresh limits

DuckDB refreshes its displayed/query-progress snapshot between execution tasks. A long
no-output filtering step, blocking remote request, or reassembly step can pause the visible
percentage even though the extension's byte counters are advancing. Stream output processing
may keep the display near completion after all bytes have been consumed. This implementation
does not change DuckDB's scheduler, inject output rows, or claim to measure reassembly CPU work.

## Validation

`test/unit/scan_progress_test.cpp` exercises unequal file sizes, duplicate inputs, unknown
pipe sizes without blocking, size changes, empty input, deferred stream completion, and
concurrent updates. Its integration portion records DuckDB's actual progress-display callbacks
for all three packet functions with one and four configured threads, checking intermediate,
monotonic, bounded progress and final display completion.

`test/unit/remote_cache_test.py` also polls the C query-progress API during HTTP metadata scans
with payload skips, verifies both first and cached scans show intermediate progress, confirms
cached repeats still use zero GETs, and checks interrupted queries leave the connection usable.
The nine remote cache/integration tests passed, along with all 1,140 SQL assertions and the
local selective-byte, truncation, and named-pipe regressions. The native progress test also
passed against the fully thread-sanitized DuckDB/extension build with no reported data race.
The complete 1,140-assertion SQL suite also passed under ThreadSanitizer.

The Linux parallel-scan workflow now runs the native progress test with its selected sanitizer,
and runs the HTTP integration test in the non-sanitizer job. See [the current handoff](CURRENT_HANDOFF.md)
for hosted CI status.
