# TigerStyle hardening plan

Drafted 2026-10-21 against `main` at `975d1a5`, from a TigerStyle audit of `src/`. It
covers every finding of that audit. File references are from that commit; `EXT` is
`src/packetquapture_extension.cpp`.

TigerStyle orders its goals as safety, performance, then developer experience, and this
plan follows that order. The phases are:

0. **Assertion support:** one macro that stays on in release builds.
1. **Safety bugs:** wrong output, or work and memory that grow without a bound.
2. **Invariants:** assertions where a broken invariant would hang, crash or corrupt.
3. **Performance:** per-packet and per-row costs, gated on a benchmark.
4. **Developer experience:** long functions, duplicated code, stringly-typed state,
   magic numbers and missing "why" comments.

Each phase is one commit or more on `tigerstyle-hardening`, and each leaves every suite
green: the release SQL suite, the native sanitizer tests, the Python integrations,
`make format-check` and `git diff --check`.

## Repo conventions kept

TigerStyle defers to a repo's own conventions, and these stay:

- **DuckDB C++ style:** tabs, a 120-column limit (no line exceeds it today), CamelCase
  functions, lower_case members, `.clang-format` and `.clang-tidy` as they stand.
- **Unit-first limit names.** Names like `max_stream_bytes` stay, because they are
  consistent across the code, the SQL options and the docs. New names follow the same
  pattern. Renaming them is not in this plan.
- **Errors are exceptions** at the DuckDB boundary, and status values in the parsers.
- **C++11** for production extension code.

## Phase 0: assertion support

Today `src/` has one `static_assert` and no runtime assertions. DuckDB's `D_ASSERT`
cannot fill that gap, for two reasons:

- It compiles to nothing in release builds.
- The parsers (`tcp_reassembly`, `tls_*`, `x509_*`, `dns_*`, `packet_decoder`,
  `flow_aggregator`, `pcap_writer`) do not include DuckDB, so that their native
  sanitizer tests build without it.

Add `src/include/pq_assert.hpp`:

- `PQ_ASSERT(condition)` is always on, in every build type.
- On failure it throws `packetquapture::AssertionFailure`, which derives from
  `std::logic_error`. The message is `packetquapture assertion failed: <condition>
  (<file>:<line>)`.

**Why throw instead of abort.** TigerStyle says a failed assertion should crash. Here
the code runs inside the user's database process, and aborting would take their session
and any uncommitted work with it. Throwing still stops the query immediately, gives the
location, and cannot be mistaken for bad input. Every `catch` that turns errors into
data rows must rethrow `AssertionFailure` (see S10), so a broken invariant is never
swallowed.

Rules for using it:

- Split compound conditions: two `PQ_ASSERT`s, not one with `&&`.
- Write implications on one line: `if (a) PQ_ASSERT(b);`.
- `static_assert` relationships between constants wherever the compiler can check them.
- Assertions check the code's own logic. They never replace validating input: hostile
  bytes are still rejected with a status or an `InvalidInputException`.

Tests: a unit test showing a failed `PQ_ASSERT` throws with the condition and location.

## Phase 1: safety bugs

Every item below gets a regression test that fails before the fix.

### S1. Quadratic provenance lookup in TLS handshakes

`tls_handshake.cpp:1047-1068`, called at `:1103` and `:1121`.

- **Problem:** for each handshake message, `Locator::Locate` scans every record span
  and `chunk.Provenance` scans every packet origin. Certificate messages are not capped
  the way hellos are. A 1 MiB stream of 1-byte records full of empty Certificate
  messages comes to about 10^10 iterations.
- **Fix:**
  - Messages are framed in increasing offset order, so `Locator` carries its span index
    forward. The whole stream then costs O(spans + messages).
  - Give `TcpStreamChunk::Provenance` the same cursor form, through a stateful
    `ProvenanceCursor`. The DNS framer (`dns_tcp_framer.cpp:255`) has the same pattern
    and uses the same cursor.
  - Once a direction's chain is a duplicate, stop handling that direction's Certificate
    messages.
- **Test:** a generated stream of 1-byte records with thousands of empty Certificate
  messages, given a step budget: it must finish and report the right first and last
  packets.

### S2. PCAPNG interface cap missing on plain scans

`EXT:556`.

- **Problem:** the 65,536 interface cap only applies to stream, flow and inventory
  scans. `read_pcap`, `read_packets`, `read_dns` and `read_tls` grow `interfaces`
  without a limit.
- **Fix:** apply the cap to every scan. An enhanced packet block's interface id refers
  to this list, so the cap cannot reject a valid capture that has fewer than 65,536
  interfaces.
- **Test:** a SQL test on a capture with 65,537 interface blocks.

### S3. Allocating a record before its length is checked against the file

`EXT:644`, through `NextPcap`, `ReadEnhancedPacket` and `ReadSimplePacket`.

- **Problem:** a header that claims a 256 MiB packet makes `bytes.resize()` allocate
  256 MiB before `ReadExact` reaches end of file.
- **Fix:** on seekable files, reject `captured_length > seekable_size - position` before
  any read. Use the existing truncated-record error so output does not change for
  truncated captures. Non-seekable remote reads keep the 256 MiB per-packet cap, and
  `ReadPrefix` grows its buffer in steps of at most 1 MiB, so a lying header costs at
  most one step past end of file.
- **Test:** a 100-byte capture whose record header claims 200 MiB fails fast with the
  truncated-record error. The native test checks that memory stays under a bound.

### S4. Too many TLS extensions reported as malformed

`tls_handshake.cpp:284`.

- **Problem:** going over `max_extensions` returns `false`, so the hello is marked
  `invalid` and wiped. A peer can hide every field of its hello by sending 257 empty
  extensions.
- **Fix:** handle it the way list overflow is handled: set `budget.exceeded`, stop
  walking the extensions, and keep the fields parsed so far, with status `limit`.
- **Test:** a ClientHello with 300 extensions reports status `limit` and keeps its SNI.

### S5. Duplicate SNI not detected

`tls_handshake.cpp:293`.

- **Problem:** `server_name` is the only extension parsed without a `Duplicate` guard,
  so the last SNI silently wins. That breaks the RFC 8446 4.2 rule cited at `:230`.
- **Fix:** track that SNI has been seen. A repeat marks the hello malformed, as every
  other repeated extension does.
- **Test:** a hello with two different SNI values.

### S6. DNS name hop cap off by one, and a misleading comment

`dns_decoder.cpp:25` and `:35`.

- **Problem:** `hops < 128` counts labels, pointers and the terminator together. A
  legal 255-octet name that also uses one pointer needs 129 steps, so the message is
  rejected. That is a way to evade the DNS analytics.
- **Fix:**
  - Count labels and pointers separately. Labels are already bounded by
    `expanded <= 255`. Pointers get their own cap of 127, the most a 255-octet name can
    need.
  - Make pointers strictly decreasing: each target must be below the previous one.
    That rules out cycles by construction, so the comment becomes true.
- **Test:** a 255-octet name ending in a pointer decodes. A two-pointer cycle is
  rejected.

### S7. Flow table overflow aborts the query

`flow_aggregator.cpp:202-204`.

- **Problem:** more than `max_flows` (16,384) active flows throws, which fails all of
  `read_flows`. A port scan inside the 5-minute idle timeout does this, and such
  captures are common in forensics. TCP reassembly handles the same situation with a
  per-row `limit` diagnostic.
- **Fix (decided 2026-10-21):** evict the session that is closest to expiring, and emit
  it with `end_reason = 'limit'`. The query completes and the evicted session is
  labelled. Update `FLOWS.md:73` to match.
- **Test:** a generated SYN scan of 20,000 ports.

### S8. Latent stack overflow in `AppendNumber`

`tls_fingerprint.cpp:9-19`.

- **Problem:** `char digits[8]` holds an `unsigned`, which can need 10 digits. Every
  caller passes 16 bits today.
- **Fix:** take `uint16_t` and size the buffer at 5, with a `static_assert` tying the
  two together.

### S9. ClientHello bounded by the record instead of the message

`tls_record.cpp:177-195`.

- **Problem:** after checking `handshake_length`, the parse cursor spans the whole
  record, so the extension walk can run into the next handshake message.
- **Fix:** `Cursor(data + 9, handshake_length)`.
- **Test:** a record holding a ClientHello followed by a second message, where the
  first message's extension length overruns into the second.

### S10. Errors swallowed or mislabelled

- **`InventoryOne` (`EXT:4303`):** rethrow `INTERNAL`, `FATAL` and `AssertionFailure`,
  not just `INTERRUPT` and `OUT_OF_MEMORY`.
- **`EXT:849`:** catch by `const &`, and add a comment on why the file-system error is
  safe to ignore.
- **`TlsScan` (`EXT:2989`):** the "append rather than assume" branch would file rows
  under the previous file's name if `Hold()` ever failed. Replace it with
  `PQ_ASSERT(state.tls_pending.empty())`. The dead `!event.tcp` branch (`EXT:2976`)
  becomes `PQ_ASSERT(event.tcp)`.
- **Ignored returns:** `tls_record.cpp:108-109` (`Skip`), `x509_certificate.cpp:648`
  and `:1000` (`Next`). Test the result, or cast to `(void)` with a comment saying the
  reader stays failed.
- **Missing `else`:** `InventoryBind`'s option chain (`EXT:3796-3808`) ends with
  `else throw InternalException`.
- **`InventoryScan` (`EXT:4338`):** `PQ_ASSERT(global.columns[c] < IC_COUNT)`.

### S11. Wasted work and early allocation

- **Catalog loads (`EXT:3891`):** they scan the whole catalog table even when a few
  files are wanted. Push an `IN` filter on `filename` into the scan. Also stop calling
  `InventoryCatalog` twice (`EXT:4085`, `:3881`).
- **ALPN and `ReadCodes` (`tls_handshake.cpp:158`, `:208-224`):** they allocate every
  entry before checking the cap. Check the cap inside the loop, and decode in place
  through `Sub()` instead of copying with `TakeBytes`.
- **`ParseRecords` (`tls_handshake.cpp:1036`):** stop copying handshake bytes once
  `max_handshakes` is reached.
- **`DecodeName` (`x509_certificate.cpp:374`):** honour `max_entries`, as every other
  list does.
- **`held` budget (`tls_handshake.cpp:385`):** return a dropped duplicate chain's bytes
  to `held`.

### S12. Inconsistencies that can drift into bugs

- **Remote locators:** `ValidateInventoryLocator` (`EXT:3764`) and `SelectCatalogFiles`
  (`EXT:4135`) disagree on `@` in a remote locator. Use one `StableRemoteLocator()`.
- **Catalog reuse:** the rules are written twice (`EXT:4152`, `:4240`), and the reason
  strings already differ (`"strict requires scan"` vs `"strict_requires_scan"`). Use
  one `CatalogReuseDecision`. Check the docs and tests for which reason string is the
  documented one first.
- **`Admit()` (`EXT:1952`, `:3285`, `:3952`):** `admitted` is incremented even when
  `Acquire()` fails. Decrement it on failure.
- **Timestamp range check (`EXT:769`):** compare with `>= 9223372036854775808.0L` so a
  platform where `long double` is `double` cannot pass 2^63, and cap one below
  DuckDB's infinity timestamp.
- **Hard-coded column numbers (`EXT:1557-1571`):** named offsets built from the column
  table, with `static_assert`s on each group boundary.

## Phase 2: invariants

Add an assertion wherever a broken invariant would hang, read out of bounds or wrap.
They are listed by the harm they prevent.

| Where | Assertion | Prevents |
|---|---|---|
| `tcp_reassembly.cpp:131` `Expire` | the expired key is in `flows`; `Remove` also unschedules a missing key | infinite loop |
| `flow_aggregator.cpp:168`, `tcp_reassembly.cpp:80` | `find() != end()` before dereferencing | undefined behaviour |
| `tcp_reassembly.cpp:212` | `buffered_bytes <= max_total_bytes`; `flow.bytes <= max_stream_bytes` | wrapped subtraction |
| `tcp_reassembly.cpp:51`, `:70` | `buffered_bytes >= flow.bytes` before subtracting | wrapped counter |
| `tcp_reassembly.hpp` limits | `static_assert` that the defaults fit `uint32_t`; check configured limits in the constructor | truncated offsets (`:301-323`) |
| `HeaderSource::ReadPrefix` (`EXT:644`) and each `Skip(length - Consumed())` | `requested <= length`; `Consumed() <= length` | reading into the next record |
| `ReadLocalWindow` and `ReadRemoteWindow` | `within_window < window_length` before `memcpy`; cursor branch: `SeekPosition() == offset` | out-of-bounds copy |
| `Reader`, `Cursor` and `Der` advances | `offset <= size` | out-of-bounds read |
| `ParseRecords` | `offset <= data.size()` at the loop top; message end within `handshake_bytes`; span total equals `handshake_bytes.size()` | out-of-bounds read |
| `ParseCertificates:410` | `held <= max_direction_certificate_bytes` | wrapped subtraction |
| `Hold` and `Release` (`tls_handshake.cpp:1346`, `:1416`) | `pending.size() < max_pending`; `unconfirmed <= pending.size()` | wrapped counter |
| `tls_handshake.cpp:997`, `x509_certificate.cpp:628` | value fits before the `uint32_t` cast | truncation |
| `ReadCodes`, `ReadAlpn`, `ReadPointFormats` | `values.size() <= cap` on exit | unbounded list |
| `FlowAggregator::Push` | `vlan_ids.size() <= 8` before copying into `std::array` | overflow |
| `SetFlowValue` (`EXT:3504`) | `last_timestamp >= first_timestamp` | negative duration |
| Budget `Release()` (three headers, merged in Phase 4) | `used >= worker_bytes`; `Admit`: `admitted <= max_workers` | wrapped counter |
| `StreamGlobalState` constructor | `scans > 0` | division by zero |
| `dns_tcp_framer.cpp:236` | `offset <= available` | out-of-bounds read |
| `CaptureProgress::CompleteFile` | `completed <= sizes.size()` | progress over 100% |
| `InventorySnapshotMemory::Add` | `used <= cap` | broken cap |
| Every bind | names and types have the same length; inventory has `IC_COUNT` | misaligned columns |
| `InventoryOne:4296` | `static_assert(IC_FRAGMENTS - IC_IPV4 + 1 == 8)` | misaligned counters |
| `SelectCatalogFiles:4089` | `names[2] == "timestamp"` | wrong pruning column |
| `PcapScan` | `column_ids.size() == output.ColumnCount()` | misaligned output |
| `SetPartition` | `file_index < partition_values.size()` | out-of-bounds read |

**Loops.** The five `while (true)` loops all terminate. Rewrite each so the bound shows
in the loop condition, and put the bound in a comment:

- `tls_handshake.cpp:523` becomes `while (reader.Remaining() > 0)`.
- `tls_handshake.cpp:697` becomes `for (++i; i < lines.size(); ++i)`.
- `EXT:489`, `EXT:2069` and `EXT:3891` are bounded by file bytes, records plus flows, and
  catalog rows. They stay event-style loops, but each gets a comment with its bound.
  - `EXT:489` also gets an iteration assertion: at most `file_bytes / 8` passes.
- The empty-bodied loop at `tls_handshake.cpp:814` gets a body.

**Removed:** the dead `captured > declared` condition at `tcp_reassembly.cpp:198`.

## Phase 3: performance

**Measure first.** Record `scripts/benchmark_header_reads.py`, plus a
`read_packets`/`read_flows`/`read_tls` timing on the benchmark captures, before Phase 3,
and keep each change only if it does not regress. Results go in
`docs/benchmarks/tigerstyle-2026-10.json`.

| # | Change | Where |
|---|---|---|
| P1 | Find duplicate TCP segments through a hash of `(sequence, declared)` instead of a linear `memcmp` scan | `tcp_reassembly.cpp:202` |
| P2 | Reuse one `PacketRecord` per thread. Read the filename from bind data instead of copying it per packet | `EXT:473`, `:586`, `:622`, `:1912`, `:2307`, `:3602` |
| P3 | Store VLANs as `std::array<uint16_t, 8>` plus a count in `TcpFlowKey` and `DecodedPacket` | `tcp_reassembly.hpp`, `packet_decoder` |
| P4 | Keep the filter `SelectionVector` and chunk as members. Call the filter directly instead of through `std::function` | `EXT:191-208`, `:666` |
| P5 | Write cells through `FlatVector::GetData<T>` and `StringVector::AddString`, as `SetDecodedScalar` does, instead of `SetValue(Value)` | `SetRecordValue`, `SetFlowValue`, MAC and IP cells |
| P6 | Build struct types once (`static const`). Compare status once per row, as an enum (Phase 4) | `EXT:2909`, `:3192-3202`, `:2249`, `:3096` |
| P7 | Lazy expiry: keep the deadline on the state, and re-queue a stale entry when it is popped, instead of an erase plus insert per packet | `FlowAggregator::Next`, `TcpReassembler::Schedule` |
| P8 | Move instead of copying handshakes, chains and parsed certificates. Parse DER in place | `tls_handshake.cpp:1110`, `:1297`, `:398`, `Merge`; `x509:1140` |
| P9 | Parse a constant CIDR list once, and break on the first match | `traffic_analytics.cpp:222-248` |
| P10 | Resolve public suffixes through `string_view`s instead of a string per candidate | `dns_analytics.cpp:126-159` |
| P11 | Hex and decimal escapes through a lookup table instead of `snprintf`. Reserve output strings | `EscapeTlsText`, `EscapeRfc4514`, `JoinHex`, `AppendList` |
| P12 | Build JA3 and JA4 once when both the hash and raw columns are projected | `EXT:2863`, `:2881` |
| P13 | Parse the Hive partition once per file at bind time | `EXT:1342`, `:1365` |
| P14 | Read the catalog filename once per row | `EXT:3899-3918` |

**Deferred.** Cutting the TCP payload copies (segment, then stream, then chunk, then DNS
message) means moving framing onto spans, which reworks the `TcpStreamChunk` contract.
It needs its own plan, and it starts only if P1-P14 leave reassembly as the hot spot.

## Phase 4: developer experience

### D1. Functions over 70 lines

Split each one, keeping branching in the parent and the work in leaf functions:

| Function | Lines | Split into |
|---|---|---|
| `SetHandshakeValue` | 248 | client, server, certificate and fingerprint column groups |
| `DecodePacket` | 186 | `DecodeLink`, `DecodeIPv4`, `DecodeIPv6`, `DecodeTransport` |
| `Merge` | 152 | `MergeClient`, `MergeServer`, `MergeWarnings` |
| `SetFlowValue` | 144 | key, counters, timing and diagnostic column groups |
| `ParseRecords` | 135 | `CollectRecords`, `FrameMessages`; `Locator` moves to namespace scope |
| `SetStreamValue` | 126 | stream and chunk column groups |
| `InventoryOne` | 123 | reuse decision, scan, row fill |
| `ReadPacketData` | 118 | per-stage readers |
| `TlsBind` | 118 | one column table |
| `BindCapture` | 111 | option parsing, file expansion |
| `Finish` | 110 | extent, overlay, emission |
| `SelectCatalogFiles` | 101 | catalog query, reuse decision |
| `Add` | 99 | `Admit`, `BufferSegment` |
| `FlowAggregator::Next` | 98 | key build, update, emit |
| `DecodeExtensions` | 95 | `{oid, decoder}` table, which also drops eight `*_copies` counters |
| `SetDecodedValue` | 94 | column groups |
| `DnsMessagesScan`, `TlsScan` | 75, 87 | the shared admit and release helpers from D2 |
| `SetMessageValue`, `LoadInternal`, `FlowsBind`, `SetRecordValue`, `Plan`, `PcapInit`, `FlowsScan` | 71-104 | as natural seams allow |

Check: a small script, `scripts/function_lengths.py`, lists functions in `src/` over 70
lines and exits non-zero if any exist. It runs alongside `make format-check`.

### D2. Duplicated code

- **Budget headers:** `flow_scan_budget.hpp`, `stream_scan_budget.hpp` and
  `inventory_scan_budget.hpp` become one `scan_budget.hpp` template, parameterised on
  worker bytes, setting name and state key.
- **Worker admission:** the admit and teardown prologue in `DnsMessagesScan`, `TlsScan`,
  `TcpStreamsScan` and `InventoryScan` becomes `AdmitStreamWorker` and
  `ReleaseStreamWorker`.
- **TLS readers:** `Reader` (`tls_handshake.cpp:34`) and `Cursor` (`tls_record.cpp:9`)
  become one `byte_reader.hpp`. `ParseServerName` and `ParseServerNameExtension` become
  one function.
- **TLS constants:** the duplicates in `tls_handshake.cpp:13-22`, plus
  `EXTENSION_SERVER_NAME` and `TLS_1_3`, use the ones in `tls_record.hpp`.
  `RecordHeaderValid` and `DecodeTlsRecord` share one header check.
- **Hex helpers:** x509 `Hex`, `AppendHex4` and `JoinHex` become one set.
- **`RegisterMacros`** (`dns_analytics`, `traffic_analytics`) and **`U16`/`U32`**
  (`packet_decoder`, `dns_decoder`) each become one shared copy.
- **`InventoryBind`:** calls `BindInventoryCatalog` instead of repeating it
  (`EXT:3787-3793`), and `PcapInit` calls `SelectedFiles()` instead of repeating it
  (`EXT:1386-1388`).
- **Bind columns:** the parallel name and type vectors in each bind become one
  `{name, type}` table, and column ids become enums everywhere, as inventory already
  does.

### D3. Duplicated state

- `ScanOptions::decode_dns` vs `dns_scan`, and `StreamGlobalState::decode_dns`.
- `PcapLocalState::options`, which copies the global options only to add `matches`.

### D4. Status strings become enums

`"invalid"`, `"limit"`, `"conflict"`, `"ok"` and the other statuses become enums inside
the parsers. They are converted to strings only when a cell is written, so the SQL
output does not change.

### D5. Named constants and "why" comments

- **Named constants:**
  - TCP flags (`TCP_FIN`, `TCP_SYN`, `TCP_RST`, `TCP_ACK`) in `tcp_reassembly`,
    `flow_aggregator` and `EXT:3539`.
  - The row-cost constants.
  - The 64 MiB snapshot cap and the 65,536 link cap.
  - Error text that hard-codes "48 MiB" and "32 MiB" is built from the constants instead.
- **"Why" comments:**
  - `entropy / 6.0`
  - `maximum_capture = 1`
  - snap length 0 meaning unlimited (`EXT:615`)
  - TCP DNS framing (`EXT:691`, `:714`)
  - `vlan_ids` depending on Ethernet (`EXT:1557`)
  - re-running the decoder per filter stage (`EXT:681`)
  - the POP3 skip loop
  - `0x1F` tag handling in `DecodeAuthorityKeyId`
- **Naming:** in `TlsRowBytes`, `codes` becomes `code_count`, `alpn` becomes
  `alpn_bytes` and `certificates` becomes `certificate_bytes`. `ListBudget::cap`
  becomes `cap_entries`. Pick one width for `TcpByteOrigin` and `TcpStreamChunk`
  offsets.

### D6. Small fixes

- Brace the unbraced `if`s at `EXT:1280-1290`, `:1307` and `:1387`.
- Move the misplaced `EndOfRecord` comment (`EXT:836`).
- Drop the repeated `private:` (`EXT:906`).

## Not in this plan

- **Renaming limits to put units last.** The repo convention wins; see above.
- **Aborting on a failed assertion.** This plan throws instead; see Phase 0.
- **Zero-copy TCP payload framing.** Deferred; see Phase 3.
- **Changing the rest of `FLOWS.md`'s contract.** Only S7 touches it.

## Verification

After each phase:

```sh
cmake --build build/release --target libduckdb.so shell unittest -j 8
./build/release/test/unittest 'test/sql/*'
F="-Wall -Wextra -Werror -O1 -fsanitize=address,undefined -Isrc/include"
# each native test, at -std=c++11, as in CURRENT_HANDOFF.md
python3 test/unit/*_test.py   # the ones that need no network
make format-check && git diff --check
```

The TSan suite runs once, at the end of Phases 2 and 4, because those phases touch the
shared scan state.

## Outcome

Implemented on `tigerstyle-hardening` on 2026-10-21. Every check below passed at the end:

- the native sanitizer tests;
- the release SQL suite, 2,769 assertions, and the same suite under TSan with no race
  reports;
- the DuckDB-linked parallel-scan and progress tests;
- the Python integrations, including the new `hostile_capture_test.py`;
- `make format-check`;
- `scripts/function_lengths.py --check`, which finds no function over 70 lines.

### Where the implementation differs from the plan

- **S3:** the up-front length check covers seekable files. Remote reads also grow the
  prefix buffer in 1 MiB steps.
- **S11, catalog filter:** DuckDB's raw storage scan rejects `IN` filters (`Unsupported
  filter type for TableFilterState::Initialize`). The snapshot scan therefore pushes the
  range `min(wanted) <= filename <= max(wanted)`, and keeps the exact `wanted` check per
  row.
- **S11, name bound:** `DecodeName` is bounded by a fixed 256 attributes rather than
  `max_list_entries`, whose documented reach is the SAN and EKU lists.
- **S11, not done:** `ParseRecords` still copies a direction's handshake bytes after
  `max_handshakes`. The copy is bounded by `max_stream_bytes`, and stopping early would
  have meant interleaving record collection with message framing.
- **S12, column numbers:** these are now named group boundaries (`TLS_*_COLUMNS_BEGIN`,
  `FLOW_*_COLUMNS_BEGIN`, `NETWORK_COLUMNS_BEGIN` and the rest). Each bind asserts them
  against its column names, and each bind's schema is one `column(name, type)` line per
  column.
- **Phase 2, not asserted:** `SeekPosition() == offset` in `ReadLocalWindow`'s cursor
  branch. Asserting it costs an `lseek` per header read, which `local_window_test`
  counts as a regression.
- **Phase 2, input check instead:** the X.509 `uint32_t` bit-count narrowing is an
  input check (the key size is reported unknown), not an assertion, because the input
  size is not this code's invariant.
- **D2, not merged:** `RegisterMacros`. The traffic analytics copy wraps registration
  errors and the DNS copy does not, so one function would change behaviour.
- **D2, dropped:** "`PcapInit` should call `SelectedFiles()`" was a false positive.
  `PcapInit` lists the files left after catalog pruning, not the bind's selection.

### Assertions that found bugs

- **Inventory progress overcount.** `CaptureProgress::CompleteFile`'s new bound
  (`completed <= sizes.size()`) caught `InventoryOne` counting a reused file even with
  the progress bar disabled. The reader always guarded that call with `Enabled()`.
- **Two wrong assertions removed.** A drafted `pointers <= labels + 1` in the DNS name
  decoder, and `max_stream_bytes <= max_total_bytes` in the reassembler, could both be
  broken by valid input or configuration. Both were removed rather than weakened into
  input checks.

### Performance

From `scripts/benchmark_hot_paths.py`: 340,000 packets, 20,000 TLS connections, single
thread, best of 7 trials alternating between a build of `main` and this branch. Every
query returned identical answers on both builds. Full results are in
`docs/benchmarks/tigerstyle-2026-10.json`.

| Query | `main` | this branch | Speedup |
| --- | --- | --- | --- |
| `read_pcap` count | 0.114 s | 0.070 s | 1.6x |
| `read_packets`, all columns | 1.929 s | 1.103 s | 1.7x |
| `read_packets`, filtered | 0.251 s | 0.172 s | 1.5x |
| `read_flows`, all columns | 0.520 s | 0.404 s | 1.3x |
| `read_tcp_streams` | 0.443 s | 0.356 s | 1.2x |
| `read_tls`, all columns | 1.004 s | 0.579 s | 1.7x |
| `read_dns`, all columns | 0.473 s | 0.275 s | 1.7x |

Machine noise on this host is about ±20% between sequential runs. That is why the
comparison alternates the two binaries on every trial.
