# Gap analysis and product roadmap review

Date: 2026-09-17. Code baseline: `dd038c6` plus the uncommitted parallel-scan work in the tree.
DuckDB baseline: v1.5.5.

This document is a review of what PacketQuapture has, what it is missing, and what order the missing
work should be done in. It is opinionated on purpose. It complements rather than replaces
[`HANDOFF.md`](HANDOFF.md) (architecture and phases) and [`MULTICORE_HANDOFF.md`](MULTICORE_HANDOFF.md)
(the concrete next implementation).

## Product goals this review is measured against

The roadmap in `HANDOFF.md` describes a "PCAP lake storage foundation." The stated product goals are
broader, and the priorities below are ranked against these rather than against the original phases:

1. **Protocol coverage approaching what Wireshark shows for common traffic**, not full dissector parity.
2. **TLS fingerprinting** (SNI, JA3/JA4) as a first-class decoded surface.
3. **Flow/conversation records** as a primitive, not something users assemble with `GROUP BY`.
4. **200 GB-1 TB of captures on S3 and/or R2**, tested progressively, with performance treated as a
   feature rather than an afterthought.
5. **BPF filter expressions** as a familiar, pushdown-capable predicate language.

Goal 4 is the one that most changes the ordering below. Several items that look like polish on a local
filesystem become correctness- or cost-shaped problems against object storage.

## Context

The project is a few days old. The gaps below are not defects; they are the difference between a strong
foundation and a tool people adopt. The motivating opportunity is real: the obvious alternatives are
either commercially absorbed or unmaintained, and there is currently no good DuckDB-native answer for
querying packet captures at rest.

## What is already right

These are load-bearing decisions that are expensive to retrofit and are already made correctly:

- **No libpcap dependency.** Distribution stays simple and the parser is not tied to native-only I/O.
- **Bounds-checked framing** for classic PCAP (both endiannesses, microsecond and nanosecond) and
  PCAPNG (multi-section, multi-interface, `if_tsresol`, safe unknown-block skipping).
- **Projection-driven decoding.** `DecodeDepth` and the `ScanOptions` stage flags mean a `count(*)`
  never decodes a header and never materializes a payload blob.
- **Staged filter pushdown** that runs framing predicates before header decode before payload reads.
- **A protocol-independent TCP core** (`tcp_reassembly.cpp`) with explicit gap, conflict, retransmission,
  wraparound, tuple-reuse, and limit diagnostics, kept separate from application framing
  (`dns_tcp_framer.cpp`). Output is delayed to EOF so a late conflicting retransmission can still
  invalidate a direction. This is the correct and uncommon choice.
- **Decoders that are testable without DuckDB**, with ASan/UBSan runs in CI over mutation and
  random-input corpora.
- **Deterministic, regenerated fixtures** with `git diff --exit-code` enforcement.

The parallel work currently in the tree (`FileScheduler`, `PcapLocalState`, per-worker `PacketFilter`
construction, `MaxThreads()`, interrupt checks, filename/cursor error context) implements PR 1 of the
multicore plan and appears to correctly avoid the shared-`ExpressionExecutor` race that plan called out.

## Priority 0: object storage readiness

This section is ranked first because it is a precondition for the 200 GB-1 TB goal. None of it matters
on a local SSD; all of it matters on S3 or R2.

### How PacketQuapture reaches object storage today

`httpfs` is an out-of-tree extension and is not part of the pinned DuckDB submodule. PacketQuapture never
links against it and should not. `CaptureReader` opens files through `FileSystem::GetFileSystem(context)`
(`src/packetquapture_extension.cpp:151`), so once a user runs `INSTALL httpfs; LOAD httpfs;` and sets
credentials or a secret, `read_pcap('s3://bucket/**/*.pcap')` resolves to `S3FileSystem` with no change
to this extension. Remote reads therefore already *work*.

The problem is not capability, it is request shape and cost.

### Measured remote read behavior

**Implementation update:** [shared remote caching](REMOTE_CACHE.md) now uses aligned 4 MiB
windows through `CachingFileHandle`, preserves local selective seeks, and has measured
zero payload GETs on every cached repeat in the HTTP/MinIO matrices. Tests cover HTTP
replacement invalidation and memory-pressure eviction. The baseline observations and
candidate discussion below explain the motivation; larger-scale/provider tests remain open.

The September 17 [remote I/O benchmark](REMOTE_IO_BENCHMARK.md) supersedes the earlier
one-range-request-per-packet hypothesis in this section. `CaptureReader::ReadMaybe` still
calls the underlying handle for each record/header, but those calls are not equivalent to
network requests. With DuckDB v1.5.5 and httpfs `827222f`, both loopback HTTP and real MinIO
batch them into large reads. Small payload seeks did not produce one GET per packet.

For one 8 MiB MinIO object containing 8,065 packets, metadata scans used 8 GETs, and raw or
50%-selective payload scans used 4 GETs. All three fetched almost the entire object.
Repeated queries fetched the bytes again; external file cache snapshots remained empty.
Enabling HTTP metadata caching removed repeated HEADs without reducing payload GETs.

This changes the motivation for further work: measure **cross-query byte reuse, window
sizing, and selective transfer amplification**, rather than fixing an assumed per-packet
request explosion. Local selective seeks still have their separately verified benefit.
These small captures do not establish large-lake performance or AWS S3/R2 billing.

### Candidate: use DuckDB's CachingFileSystem for shared byte reuse

An earlier draft of this document recommended writing a custom buffering layer between the framing parser
and the `FileHandle`. That was the wrong conclusion. Core DuckDB provides a candidate abstraction,
and the Parquet reader is a useful reference implementation. Adopting it remains a proposed
change to benchmark against the measured baseline, not a demonstrated performance fix.

`duckdb/storage/caching_file_system.hpp` defines `CachingFileSystem` and `CachingFileHandle`, a read-only
layer over any `FileSystem` that caches byte ranges in the `ExternalFileCache`. Its `Read(buffer, nr_bytes,
location)` returns a `BufferHandle` and sets a pointer *into* the cached buffer, rather than copying into
a caller-supplied destination.

This is materially better than a hand-rolled buffer for five reasons:

1. **Cached ranges live in the BufferManager**, so they respect `memory_limit` and can spill. A private
   buffer allocated with the standard allocator would not, which is the same concern
   `MULTICORE_HANDOFF.md` already raises about the TCP core's allocations.
2. **The cache is shared across queries.** Repeatedly querying the same slice of a lake, which is the
   normal investigation pattern, stops re-fetching from S3 after the first pass. A per-scan buffer cannot
   do this. `enable_external_file_cache` and `validate_external_file_cache` are the user-facing knobs.
3. **`GetVersionTag()` exposes the ETag or version ID**, with `CacheValidationMode` controlling whether
   entries are revalidated. This is precisely the identity-based invalidation primitive the Phase 4
   catalog design in `HANDOFF.md` says it needs; adopting `CachingFileHandle` supplies it for free.
4. **Reads are zero-copy.** Because `Read` hands back a pointer into the cache, packet payloads could be
   handed to the decoder, and potentially written into output blob vectors, without the intermediate copy
   the current reader performs, provided the `BufferHandle` is held for the lifetime of that use.
5. **`IsRemoteFile()` and `OnDiskFile()` are available on the handle**, which gives the cost-aware policy
   a principled input instead of a guess.

Important caveat: `CachingFileHandle` caches exactly the range requested. Routing the current per-header
and per-packet reads through it unchanged would create millions of tiny cache entries and tiny range
requests, which is worse than today. **`CachingFileSystem` replaces where the buffer lives and who manages
it; it does not remove the need to read in large windows.** The framing parser still has to be restructured
to pull large aligned windows and serve headers and payloads out of them.

### Adopt Parquet's prefetch heuristic

`ShouldAndCanPrefetch` in `extension/parquet/parquet_reader.cpp:48` encodes the exact policy this document
was reaching for, and it is worth copying rather than reinventing:

```cpp
bool should_prefetch = !file_handle.OnDiskFile() || prefetch_all_files;
bool can_prefetch = file_handle.CanSeek() && !disable_prefetch;
```

Remote implies prefetch; local implies do not. That inverts the current `can_skip_by_seek` logic in the
right direction, and it establishes the DuckDB-idiomatic pair of escape hatches, a `disable_prefetch`
style option and a `prefetch_all_files` style override, which PacketQuapture should mirror as named
parameters.

`ReadAheadBuffer` in `extension/parquet/include/thrift_tools.hpp:57` is the other half of the pattern: a
two-step *register all ranges, merging consecutive ones, then prefetch* interface. PCAP framing is
sequential rather than random-access, so the merging machinery is less relevant, but the window sizing is.
`ThriftFileTransport::PREFETCH_FALLBACK_BUFFERSIZE` is 1,000,000 bytes, which is a reasonable starting
point for the capture read window, to be tuned by measurement rather than assumed.

### Candidate implementation to benchmark

- Restructure `CaptureReader` to read through a `CachingFileHandle` in large windows, serving record
  headers and packet bodies from the window and only issuing a real fetch when the window is exhausted.
- Replace `can_skip_by_seek` with a policy that additionally consults `OnDiskFile()`, so that on remote
  files a short payload skip is satisfied from the already-fetched window instead of a seek.
- Keep the seek path for large skips on local files, where it demonstrably helps.
- Expect the selective-I/O regression to change meaning. `scripts/benchmark_header_reads.py` currently
  asserts that payload bytes are not read. Under windowed reads, small payload skips will be fetched as a
  side effect of bulk reading. That is the correct trade against object storage, but the test must become
  backend-aware and assert different properties for local and remote handles, rather than being weakened.

### Remaining measurement gaps

The benchmark now records individual requests, response bytes, elapsed time, and observable
external-cache residency. It establishes batching and repeat-query refetching for literal
HTTP/S3 object lists on the tested versions. Cache residency is not a hit-rate counter;
the reports leave hit rate unavailable rather than inventing a value.

Still unverified: large-object behavior, glob/listing costs, memory pressure, changed-object
invalidation, direct-endpoint throughput, and AWS S3 versus R2 latency and cost. MinIO timings
include a local counting proxy and Kubernetes port-forward. The proposed caching/window
work must retain these counters and local selective-I/O checks when evaluated.

### Parallelism should not be bounded by file count against object storage

`FileScheduler::MaxThreads()` returns the file count. This is right for whole-file parallelism, but against
S3 or R2 the bottleneck is request latency rather than CPU, and the useful concurrency for a *single* large
object is well above one. Once windowed reads exist, asynchronously prefetching the next window while
decoding the current one is likely a larger win for remote reads than adding cores.

This does not require the checkpoint or index design that `MULTICORE_HANDOFF.md` defers. Sequential framing
with an outstanding read-ahead of one or two windows is a much smaller change and is the right first step.

### Compression is unsupported

Nothing in `src/` opens a compressed handle. Archived captures are very often `.pcap.gz`, and increasingly
`.pcap.zst`. For a lake where storage and egress cost are real, this is not optional.

`FileSystem::OpenFile` with `FileCompressionType::AUTO_DETECT` is close to a one-line change, and the
`CanSeek()` guard at `src/packetquapture_extension.cpp:152` already causes the reader to fall back to
buffered skipping when the handle cannot seek. Two complications: compressed files cannot use range-based
parallelism later, and per-file decompression becomes the CPU bottleneck, which makes whole-file
parallelism *more* valuable rather than less. Note also that `CachingFileHandle` operates on the underlying
byte ranges, so the interaction between the external file cache and a decompressing handle needs to be
checked rather than assumed.

### Progressive scale testing

**First rung measured:** the [1 GiB MinIO metadata scan matrix](REMOTE_CACHE_SCALE.md)
passed with one/eight-file layouts, cache enabled/disabled, and 128 MiB/2 GiB limits. It
confirms repeat-query reuse when the working set fits and little or no transfer reduction
under memory pressure. This does not complete the local/S3/R2 or decoded-payload scale ladder.

The goal of testing progressively toward 1 TB needs a defined ladder so results are comparable. Suggested
rungs, each run against local disk, S3, and R2:

| Rung | Shape | What it is meant to expose |
| --- | --- | --- |
| 1 GB | one file | Per-packet CPU cost; vector write overhead |
| 10 GB | 10 x 1 GB | Whole-file parallel scaling; scheduler fairness |
| 50 GB | 5,000 x 10 MB | Glob and discovery cost; per-file open latency; request amplification |
| 200 GB | mixed, skewed sizes | Work imbalance; one dominant file among many small ones |
| 1 TB | partitioned by date/host | Partition pruning; catalog value; cold-cache behavior |

Record for every run what `MULTICORE_HANDOFF.md` already specifies (revision, DuckDB version, flags, CPU,
OS and storage, threads, capture shape, cache state, wall and CPU time, RSS, rows/s, MiB/s) plus, for
object storage, **request count, bytes transferred, and external file cache hit rate**. Wall time alone
will hide both the cost problem and the effect of the cache.

## Priority 1: make the existing surface fast

### Row-at-a-time `Value` construction is the largest single-thread cost

`SetRecordValue`, `SetPacketValue`, `SetDnsValue`, and `SetStreamValue` populate output almost entirely
through `vector.SetValue(row, Value::UINTEGER(...))` (`src/packetquapture_extension.cpp:868-906` and
following). Every cell constructs a heap-backed `Value` and goes through generic dispatch. With ~30
columns at the measured 1.1-1.3 M packets/s, this is tens of millions of `Value` constructions per
second and is very likely the dominant cost in the scan loop.

The correct pattern already exists in the file at `src/packetquapture_extension.cpp:915-916`
(`FlatVector::GetData<T>(vector)[row] = value`); it is simply not used for most columns. Strings and
blobs should use `StringVector::AddStringOrBlob`. List and struct columns (`vlan_ids`, the DNS record
lists) need child-vector appends rather than `Value::LIST`, which is more work but is also where the
per-row allocation is worst.

`MULTICORE_HANDOFF.md` correctly says "measure before direct-vector writes." Measure, but this is the
item I would expect to pay off most, and it helps the single-large-capture case that whole-file
parallelism does nothing for.

### Estimated cardinality remains missing; scan progress is implemented

All five functions now register `table_scan_progress`, using execution-local, byte-weighted
accounting across input occurrences. See [scan progress](SCAN_PROGRESS.md) for configuration,
unknown-size behavior, metadata costs, and DuckDB refresh limitations. Size probes and counter
updates are skipped when progress reporting is disabled.

`cardinality` is still unset. The optimizer lacks a capture-row estimate, which can affect
join planning. A file-size/running-mean estimate remains a separate candidate to validate;
progress percentages do not provide optimizer cardinality automatically.

## Priority 2: schema decisions that are cheap now and expensive later

### IP and MAC columns should not be `VARCHAR`

`src_ip`, `dst_ip`, `src_mac`, and `dst_mac` are `VARCHAR`, formatted per row by `IpString`/`MacString`
(`src/packetquapture_extension.cpp:962-985`). Three consequences:

1. **No CIDR containment.** `WHERE src_ip <<= '10.0.0.0/8'` is among the most common packet queries
   there is, and it currently requires string manipulation.
2. **Per-row formatting cost** on every decoded packet, on the hot path identified above.
3. **Lexical rather than numeric ordering**, and no consistent ordering between IPv4 and IPv6.

DuckDB's `inet` extension provides a native `INET` type with containment, `host()`, `netmask()`, and
family predicates. Emitting `INET` (with `UHUGEINT`/`UINTEGER` as a fallback if taking a dependency on
`inet` is unattractive) makes a class of queries expressible that currently is not.

This is a breaking schema change, which is exactly why it should happen now while `read_packets` is
documented as experimental. Design rule 4 in `HANDOFF.md` protects `read_pcap`'s columns; it does not
protect the decoded surface, and the decoded surface should be stabilized deliberately rather than by
drift.

### `MultiFileReader` is used only for globbing

`PcapBind` calls `MultiFileReader::Create(...)->CreateFileList(...)->GetAllFiles()`
(`src/packetquapture_extension.cpp:703`) and then ignores the rest of the machinery. The functions are
registered through `MultiFileReader::CreateFunctionSet`, but the binding, column, and filter integration
is not wired up. As a result there is no hive partitioning, no `filename=` option, and no
`union_by_name`.

Hive partitioning is the highest value-to-effort item in this entire document for the lake goal.
A layout like `s3://bucket/captures/dt=2026-09-17/host=fw01/*.pcap.gz` gives partition columns and
**partition pruning before any file is opened**, without writing a single line of catalog code. At 1 TB,
pruning by date is the difference between a two-second query and a two-hour one.

Full file-statistics catalog work (Phase 4) remains worth doing afterward, for time-range pruning within
a partition. But hive partitioning should come first because it is a fraction of the work and captures
most of the benefit for a well-organized lake.

## Priority 3: the features that make people choose this

### Flow records

All five current functions are packet-grain or byte-grain. The question actually asked of a capture is
almost never "show me packets"; it is "show me conversations." A `read_flows()` returning one row per
5-tuple with packet and byte counts per direction, first/last timestamps, duration, TCP flag union, and
connection state is the Zeek `conn.log` primitive, and it is the natural entry point for every
investigation.

The project is close to this already: `TcpFlowKey` and its `Reverse()` in `tcp_reassembly.hpp` do the
keying and bidirectional pairing, and the flow map in `TcpReassembler` does the lifetime tracking. The
important design difference from `read_tcp_streams` is that flows must **not** buffer payload; they are
counters keyed by tuple, so per-file memory is bounded by flow count rather than by bytes. That makes
`read_flows()` dramatically cheaper than the existing stream functions and safe to run over the whole
lake.

Worth noting: because it aggregates, `read_flows()` is also the function that benefits most from being
implemented as a proper aggregating table function rather than as `GROUP BY` over `read_packets`, since
it never materializes packet rows at all.

### TLS fingerprinting

By traffic volume this is the highest-value decoder available today, because most traffic is encrypted
and SNI plus a fingerprint is most of what remains observable. Concretely:

- **SNI** from the ClientHello `server_name` extension.
- **JA3/JA3S** (MD5 over the version, cipher list, extension list, curves, and point formats). Widely
  deployed, widely understood, and increasingly evadable.
- **JA4/JA4S** and ideally **JA4X** for certificates. Newer, more robust to randomization, designed with
  the GREASE and extension-shuffling problems in mind. If only one is implemented, implement JA4.
- **Certificate subject/issuer/validity** from the ServerHello chain when not encrypted (TLS 1.2).
- **ALPN**, which cheaply distinguishes HTTP/1.1, HTTP/2, and gRPC traffic.

The handshake may span TCP segments, so this must consume the existing TCP core rather than parsing a
single packet's payload; that is exactly the "protocol adapter on shared TCP ranges" pattern
`MULTICORE_HANDOFF.md` anticipates. Encrypted ClientHello (ECH) will erode SNI availability over time,
which is an argument for JA4 over SNI-only, not an argument against doing this.

This is the feature most likely to get the project noticed.

### Protocol coverage

Current coverage is Ethernet/VLAN, IPv4/IPv6, TCP/UDP, and DNS. Ranked by value for common traffic:

| Protocol | Priority | Note |
| --- | --- | --- |
| TLS (SNI, JA3/JA4, ALPN, certs) | Highest | See above; needs TCP core |
| Tunnels: VXLAN, GRE, GTP-U, IP-in-IP, MPLS, ERSPAN | Highest | See below; correctness-shaped |
| ICMP / ICMPv6 | High | Cheap, and its absence is conspicuous |
| ARP | High | Cheap; essential for L2 investigations |
| IP fragment reassembly | High | Currently a silent decode gap, see below |
| HTTP/1.1 (request line, host, status, headers) | Medium | Needs TCP core; declining share of traffic |
| QUIC (initial packet, SNI, JA4) | Medium | Growing fast; initial packets are decryptable |
| DHCP, NTP, SNMP, mDNS/LLMNR | Medium | Cheap UDP parses, high signal for asset discovery |
| SMB, Kerberos, LDAP | Lower | High forensic value, substantial implementation cost |
| TCP options (MSS, window scale, SACK, timestamps) | Lower | Needed for OS fingerprinting later |

Two of these deserve elaboration because they are not just "more coverage":

**Tunnel decapsulation is closer to a correctness issue than a coverage issue.** Decoding currently
stops at the outer header. In any cloud VPC traffic mirror, ERSPAN feed, or mobile core capture, that
means every packet decodes to the tunnel endpoints and the actual conversation is invisible. Since VPC
mirroring is one of the main reasons an organization has a PCAP lake in the first place, this belongs
near the top. It needs an explicit schema decision: either outer/inner column pairs, or an encapsulation
depth column plus innermost-wins semantics. Recommend innermost-wins for the primary columns with the
outer tunnel exposed as separate columns, because the inner conversation is what users mean.

**IP fragment reassembly is a silent gap.** `MULTICORE_HANDOFF.md` lists it as a separate feature. Today
a fragmented UDP datagram yields a first fragment with a truncated payload and subsequent fragments with
no transport layer at all. Large DNS responses, NFS, and some VPN traffic hit this routinely. It needs
the same bounded-resource treatment as the TCP core: explicit identity (source, destination, protocol,
IP ID), overlap policy, timeout, and limits with diagnostics rather than silent drops.

### BPF filter support

BPF expression syntax (`tcp port 443 and host 10.0.0.1`) is the lingua franca of packet filtering and
supporting it would meaningfully lower the barrier for anyone arriving from `tcpdump` or Wireshark.
There are three viable implementations with quite different trade-offs:

1. **Link libpcap's compiler only.** `pcap_open_dead()` plus `pcap_compile()` produces a BPF program
   without any capture capability, and libpcap is BSD-licensed and therefore MIT-compatible. But this
   contradicts the deliberate "no libpcap dependency" decision in `HANDOFF.md`, adds a native dependency
   to every platform in the release matrix, and is a problem for the eventual WASM target.
2. **Implement a BPF subset natively.** A recursive-descent parser over the common grammar
   (`host`, `net`, `port`, `portrange`, `proto`, `vlan`, `tcp[13] & 2 != 0`, and boolean composition)
   compiled directly into the existing staged-filter representation rather than into BPF bytecode.
   More work up front, no new dependency, works in WASM, and integrates with pushdown.
3. **Translate BPF text into DuckDB filter expressions.** Simplest, but produces confusing semantics at
   the edges and cannot express byte-offset predicates.

Option 2 is recommended. The decisive argument is that BPF's value here is as a *pushdown* predicate: a
`bpf => 'tcp port 443'` named parameter that runs inside the reader, before header decode and before
payload materialization, is far more valuable than one evaluated after rows are produced. That requires
compiling into the internal staged-filter model, which options 1 and 3 do not naturally give.

Scope should be stated honestly in docs: a documented, tested subset of the BPF grammar, with a clear
error for unsupported constructs, is much better than a claim of compatibility that fails on unusual
expressions.

### A PCAP writer

`COPY (SELECT ... FROM read_pcap(...) WHERE ...) TO 'carved.pcap'` is the single best demonstration of
what this project is for: filter a terabyte of capture with SQL, get back a small PCAP that opens in
Wireshark. Everything needed is already available (raw bytes, link type, timestamps, per-interface
metadata). It also closes the loop with existing tooling instead of competing with it, which is the
right posture for adoption.

Classic PCAP output is straightforward. PCAPNG output is harder because interface description blocks
must be reconstructed for the surviving packets and link types may be heterogeneous across a multi-file
input; classic PCAP with a single link type is the right first version, erroring clearly on mixed input.

## Priority 4: operational robustness at lake scale

- **No `ignore_errors` option.** One corrupt file in a 10,000-file glob fails the entire query with no
  partial results. At lake scale there is always a capture truncated by a full disk. Needed: skip-and-
  continue behavior, and ideally a way to surface which files failed and why rather than discarding that
  information. This interacts with the parallel error path, which currently cancels sibling workers.
- **No named parameters at all.** None of the five functions accept any. Candidates, roughly in order:
  `bpf`, `ignore_errors`, `decode_depth`, `max_packet_bytes` (the 256 MiB limit is hardcoded),
  `link_type` override for headerless captures, and the `TcpReassemblyLimits` fields, which the core
  already cleanly parameterizes but which nothing can currently set.
- **Eager file discovery.** `GetAllFiles()` materializes the entire list at bind time. At 100,000 objects
  this becomes a startup latency and memory cost before a single packet is read, and it is worse against
  object storage where listing is paginated.

## Priority 5: distribution and correctness assurance

### Distribution

- **Not submitted to `duckdb/community-extensions`**, so there is no `INSTALL packetquapture FROM
  community`. This is the difference between a project people can try in ten seconds and one they must
  build. Worth doing early, while the surface is small, rather than after it stabilizes.
- **Artifacts are unsigned**, as `HANDOFF.md` notes.
- **`LICENSE` still carries the DuckDB Foundation copyright** inherited from the extension template.
  `HANDOFF.md` flags this; it should be resolved before any public release.
- **No WASM build.** Real work, and lower priority than everything above for the stated goals. Worth
  keeping the parser free of filesystem and threading assumptions so the option stays open, which the
  current layering already does.

### Testing gaps against the project's own stated criteria

- **No fuzz targets.** Phase 0's exit criteria in `HANDOFF.md` require them and they do not exist. For a
  parser consuming hostile bytes, a libFuzzer harness over `CaptureReader` and `DecodePacket` is the
  highest-value missing test. `PacketSource` is already an abstract interface, so a memory-backed
  implementation for fuzzing is straightforward.
- **ThreadSanitizer is `workflow_dispatch`-only.** `ParallelScans.yml` runs TSan only on manual trigger.
  With a shared scheduler and atomics landing, TSan should run at least on a schedule.
- **No differential testing against `tshark`**, which the testing strategy contemplates as an optional
  oracle. Once protocol coverage broadens, a differential harness is the most economical way to find
  decoder disagreements. It must remain a test-only dependency, never a build or release dependency.
- **No malformed real-world corpus with recorded provenance**, also contemplated by the testing strategy.

## Suggested sequencing

The ordering below front-loads the work that is cheap, unblocks the lake goal, or becomes more expensive
the longer it waits.

**Now: finish and land the parallel scan work.** PR 1 and PR 2 of `MULTICORE_HANDOFF.md` as written.

**Next: object storage readiness and single-thread speed.** Move `CaptureReader` onto
`CachingFileSystem` with windowed reads and a Parquet-style remote/local prefetch policy, add compression
support, convert to direct vector writes, and set cardinality and progress. Stand up the scale ladder at
1 GB and 10 GB against R2 and record request counts and cache hit rates. This block is what makes the
numbers trustworthy before optimizing anything else.

**Then: lake shape.** Hive partitioning through proper `MultiFileReader` integration, `ignore_errors`,
named parameters, lazy discovery. Extend the ladder to 50 GB and 200 GB. Add the file statistics catalog
only if partition pruning proves insufficient at that scale.

**Then: schema stabilization.** `INET` types for addresses, tunnel encapsulation columns, and a
documented decision that the decoded schema is now stable. Doing this after the lake work means the
partitioning and catalog designs are informed by the final column types, and doing it before broad
protocol work means new decoders are built against the right types.

**Then: the differentiating features.** `read_flows()`, TLS with JA4, ICMP and ARP, tunnel decap, IP
fragment reassembly, the BPF subset, and the PCAP writer. These can proceed in parallel with each other
since they touch mostly independent code.

**Throughout:** fuzz targets, scheduled TSan, and a community-extensions submission early enough that
iteration happens in public.

## Two things worth reconsidering in the existing plan

**Indexed single-file parallelism may never be necessary.** `MULTICORE_HANDOFF.md` correctly defers it
behind a careful checkpoint design. It is worth noting that once per-cell `Value` construction is
eliminated and buffered read-ahead exists, the sequential framing path may simply stop being the
bottleneck, and the substantial complexity of verified record checkpoints could be avoided entirely.
Re-measure before committing to that design.

**WASM is a large investment for a demonstration.** Phase 6 is a real amount of work whose main payoff
is a browser demo. Against the stated goals, that effort is better spent on the PCAP writer and TLS
fingerprinting. Keep the layering that makes WASM possible; do not schedule it yet.

## Open questions

These need decisions before the relevant work starts:

1. **Tunnel schema.** Innermost-wins primary columns with separate outer columns, or explicit
   outer/inner pairs? Affects every downstream consumer.
2. **`INET` dependency.** Take a dependency on DuckDB's `inet` extension, or emit integer types and
   leave conversion to the user? The former is much better ergonomically and adds a load-time dependency.
3. **Flow identity across files.** `MULTICORE_HANDOFF.md` establishes that stream IDs are scan-local.
   Should `read_flows()` offer a stable, content-derived flow key (hash of the canonical bidirectional
   tuple plus scope) so flows can be joined across queries and across files? This is more useful than a
   scan-local counter and avoids the ID translation problem entirely.
4. **BPF scope.** Which subset of the grammar is in the first version, and what is the error behavior for
   unsupported constructs?
5. **Buffer sizing policy.** Fixed, or adaptive based on observed handle behavior? Needs measurement
   against R2 and S3 before being fixed in code.
