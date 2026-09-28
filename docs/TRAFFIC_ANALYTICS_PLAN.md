# Traffic analytics implementation plan

Status: the connection slice through phase 3, its local scale/manual corpus
validation, and phase 4 DNS tunneling are implemented; phases 5-7 remain. The analyst contract is in
[TRAFFIC_ANALYTICS.md](TRAFFIC_ANALYTICS.md). This plan begins with direct PCAP-backed
analysis and retains the normalized-fact boundary needed for future Zeek adapters.

## Outcome

An analyst can point PacketQuapture at a local capture, list, glob or remote capture
set and get explainable connection findings without first importing or converting it.
The first stable slice provides:

```sql
SELECT * FROM summarize_talkers(...);
SELECT * FROM analyze_long_connections(...);
SELECT * FROM analyze_beacons(...);
```

Each result exposes source evidence and raw metrics. Scores are versioned and nullable
when evidence is insufficient. The implementation uses the existing readers rather
than adding another capture parser or sessionizer.

The implemented slice uses system-catalog table macros generated from the reviewed
`src/traffic_analytics.sql` resource. `summarize_talkers` has a thin bind-replacement
facade solely because DuckDB 1.5.5 cannot retain the keyword parameter `by` on a
system-catalog macro. Portable native CIDR membership is the only scalar helper.

## Delivery constraints

- Preserve every existing reader schema and behavior.
- Preserve the six intentional local documentation changes listed in
  [CURRENT_HANDOFF.md](CURRENT_HANDOFF.md).
- Base implementation branches on current `origin/main` and keep PRs independently
  reviewable.
- Run code review before each PR and open ready-for-review PRs, following the current
  repository workflow.
- Production extension code remains C++11 compatible if native code is added.
- Do not add a RITA runtime, build or source dependency.
- Do not call a detector stable until its formula, defaults and golden cases are
  documented.

## Phase 0: freeze the fact and scoring decisions

### Work

1. Turn the connection-fact table in the specification into a column-by-column mapping
   from `read_flows`.
2. Validate the pinned DuckDB version's supported mechanisms for registering and
   distributing table macros from an extension. If installed macros cannot provide the
   documented call shape, choose a thin table-function facade before implementation.
3. Decide how CIDR membership is implemented. Prefer a DuckDB-provided type/function if
   it is available in the supported build without a new required extension; otherwise
   add a small bounded scalar helper with IPv4 and IPv6 tests.
4. Freeze `balanced-v1` candidate formulas for beacon timing, size, support and span.
   Record every normalization, clamp, NULL rule and weight.
5. Freeze the long-connection score or decide that v1 is threshold-and-rank only. The
   observed duration and completeness fields remain authoritative either way.
6. Decide which source-quality signals can be derived from `read_flows` today. File-level
   truncation may require joining `capture_inventory`; avoid a second full source scan
   merely to decorate a finding.
7. Decide whether the first functions take only path inputs or whether an internal
   normalized view is also exposed for tests and composition.

### Evidence and calibration corpus

- Generated perfectly periodic, jittered, bursty, random and duplicate-timestamp
  connection series.
- Generated constant, clustered and highly variable payload-size series.
- Missing timestamps, late timestamps, partial sessions, reset sessions, EOF-finalized
  sessions and idle-timeout splits.
- IPv4 and IPv6 local-network orientation including local/local and external/external.
- Repeated path occurrences and overlapping synthetic captures.
- The local RAT04 SpyMax capture as a manual/public-corpus check, never as a committed
  155 MiB fixture. Record its public provenance and checksum before using it as evidence.

### Exit criteria

- The normalized mapping and score formulas are reviewable documents.
- Expected results for synthetic distributions are written before implementation.
- The macro/facade mechanism works in a minimal extension test on every supported
  platform, or a documented fallback is selected.
- No detector uses `orig_ip` as a synonym for internal host.

## Phase 1: normalized PCAP connection relation

### Work

Create one internal SQL relation over `read_flows` that:

- maps original and responder fields into endpoint A/B facts;
- applies explicit CIDR membership and local/remote orientation;
- maps directional counters after orientation;
- derives stable per-query source record references;
- converts missing/late/partial/ambiguous/finalization evidence into quality flags;
- carries TCP and UDP idle-timeout options without changing their defaults;
- preserves filename/Hive pruning behavior;
- materializes `read_flows` once within an analysis query.

Keep this adapter in a versioned SQL resource rather than duplicating its expressions in
every detector. If the project cannot bundle SQL resources portably, generate a C++
string from the reviewed SQL during the build rather than hand-maintaining two copies.

### Tests

- Directional packet and byte conservation before and after orientation.
- CIDR boundary cases for IPv4 and IPv6.
- Initiator local, responder local, local/local and neither-local cases.
- NULL timestamps and NULL TCP-only fields.
- Duplicate input occurrences remain duplicated.
- One analysis query produces one `read_flows` scan in `EXPLAIN`.

### Exit criteria

- Connection detectors can consume only normalized columns.
- The adapter adds no payload reconstruction and keeps `read_flows`' selective-I/O
  properties.
- Existing SQL, Python and header-read regression suites remain green.

## Phase 2: talker and long-connection functions

Deliver the simplest useful analyst functions before scoring beacon distributions.

### `summarize_talkers`

- Aggregate by host first; retain service grouping as a tested option.
- Report both directional and total packet/captured/reported/payload counters.
- Count distinct peers and connection facts.
- Rank by a caller-selected documented metric.
- Return no suspicion score or severity.

### `analyze_long_connections`

- Filter on exact observed duration.
- Preserve connection provenance and all completeness indicators.
- Distinguish EOF/capture-boundary evidence from FIN/RST evidence.
- Do not combine connection durations across source files.
- Expose raw duration and byte counts even if a score is NULL.

### Validation

- Generated threshold-edge durations at one microsecond below, equal to and above the
  configured threshold.
- RAT04 should put `10.8.0.93` and `147.32.83.181:8000` near the top by payload and
  expose the roughly 5,855-second observed connection without claiming it crossed
  capture boundaries.
- Compare talker totals with independent `read_packets` aggregates on supported,
  unfragmented fixtures.
- Verify deterministic ranking tie breakers.

### Suggested PR boundary

One PR for the normalized adapter and these two functions, documentation, generated
fixtures and SQL tests. Split the adapter into its own PR only if the portability spike
requires native support.

## Phase 3: beacon metrics and findings

### Work

1. Group normalized facts by local host, remote host, transport and remote port.
2. Partition by an explicit window when supplied; otherwise analyze the selected time
   range as one window.
3. Sort starts inside each group independent of source expansion order.
4. Compute distinct non-NULL inter-start intervals.
5. Compute the frozen raw timing and payload metrics.
6. Apply sample sufficiency, span and quality rules before scoring.
7. Emit component scores, reasons, quality flags and a bounded deterministic evidence
   sample.
8. Apply `min_score` and `max_results` only after exact admitted-group metrics exist.

### SQL-first prototype

Build the first version from CTEs and DuckDB aggregates/window functions. Inspect the
plan for:

- repeated `read_flows` scans;
- unbounded `list()` aggregate state;
- avoidable payload columns;
- sorts that can spill through DuckDB;
- loss of file/Hive pruning;
- cancellation and progress behavior.

Do not move scoring into C++ merely to hide the formula. Native helpers are justified
only for missing statistical primitives, portable CIDR handling, or measured resource
problems.

### Validation

- Golden generated interval and size distributions with independently calculated
  quartiles, MAD, skew and component scores.
- Same results across thread counts and input-list permutations.
- Missing timestamps yield NULL timing components and explicit quality flags.
- Duplicate timestamps cannot inflate regularity through zero intervals.
- One extra unrelated file does not change a group's result except dataset-relative
  fields documented to depend on it.
- RAT04 is expected to rank strongly as a long connection/top talker; it must not be
  forced into a high beacon score if its interval dispersion does not support one.

### Scale checks

- One local 155 MiB real capture.
- A multi-file generated corpus with many analytical groups.
- A bounded R2 sample selected from explicit locators.
- Record source bytes, remote requests, wall/CPU time, peak memory, temporary-storage
  bytes, group count and result count.

### Exit criteria

- Formula and output equal the documented `pq-beacon-v1` contract.
- Results remain explainable without reading implementation code.
- Resource behavior is bounded by DuckDB memory/temp policies or fails explicitly.
- No claim of RITA numerical compatibility appears in code or docs.

## Phase 4: DNS tunneling analysis

Status: implemented as a separate slice because its input and policy differ from
connection analytics.

### Work

- Define the normalized DNS adapter across UDP and TCP message readers.
- Pin and record a Public Suffix List snapshot and its license.
- Specify fallback grouping for private/internal names.
- Freeze length, entropy, uniqueness, query-type, response-code, no-answer and rate
  metrics.
- Emit raw metrics and bounded name samples with an explicit sensitive-data policy.
- Report unsupported encrypted DNS coverage rather than estimating it.

### Tests

- Generated high-entropy tunnel-like labels and ordinary CDN/service labels.
- CNAME chains, multiple answers, NXDOMAIN, truncation and malformed messages.
- TCP DNS split/retransmission cases already covered by the message reader.
- PSL wildcard, exception, private and unknown suffix cases.
- DoH/DoT traffic produces no false claim of DNS inspection.

### Exit criteria

- High score is supported by multiple visible components, not entropy alone.
- PSL and algorithm versions appear in output/provenance.
- Raw names are never sent to a network service by the extension.

## Phase 5: overview relation and TLS enrichment

Add `analyze_traffic` only after specialist outputs are stable.

- Share one normalized flow materialization across flow-based detectors.
- Share one normalized DNS materialization across DNS analyses.
- Return a stable common envelope while keeping specialist functions available.
- Join TLS SNI, JA4 families, certificate hashes and tunnel metadata as evidence where
  endpoint/time matching is unambiguous.
- A missing TLS match is NULL evidence, not evidence that traffic was plaintext.
- Do not reread stream payloads for an overview that needs only connection/DNS/TLS
  metadata.

Validate with `EXPLAIN`, request counters and exact result comparison against separately
run specialist functions.

## Phase 6: corpus rarity and persistent investigations

Rarity requires a meaningful baseline, so it follows one-shot detectors.

### One-shot rarity

- Define prevalence relative to explicit selected sources and window.
- Require more than one active local host for a scored result.
- Label short or incomplete baselines.

### Persistence design checkpoint

Before implementing custom persistence, measure repeated R2 analyst workflows. If source
rescans dominate, specify:

- named datasets and explicit local-network policy;
- immutable source manifests built from inventory;
- materialized connection/DNS/TLS facts;
- detector runs tied to fact and algorithm versions;
- normalized finding features and evidence references;
- atomic refresh and publication;
- rolling lateness, source replacement and retention rules;
- preflight `max_files` and `max_source_bytes` limits.

Prefer ordinary DuckDB tables first. Consider partitioned Parquet only after measuring
database size and sharing needs.

## Phase 7: Zeek source adapters

Zeek support begins after the normalized contracts have real detector consumers.

1. Inventory the exact Zeek encodings and versions to support; do not use "binary" as
   one undifferentiated format.
2. Implement connection input first and map it to normalized connection facts.
3. Preserve Zeek UID, connection state, service and loss fields as provenance.
4. Run the same talker, long-connection and beacon golden cases through PCAP and Zeek
   adapters where equivalent observations can be generated.
5. Add DNS and TLS adapters without changing detector schemas.
6. Document unavoidable source differences instead of coercing them into false parity.

The public analytics names remain unchanged. The final source-selection interface is
chosen only after a prototype proves that overloads, explicit formats or relation-valued
macros work cleanly in the supported DuckDB version.

## Cross-cutting test matrix

Every implementation PR runs, as applicable:

- release SQL suite;
- full ThreadSanitizer SQL suite for native state changes;
- generated fixture regeneration and byte comparison;
- flow core ASan/UBSan and reference tests if flow behavior changes;
- file pruning, catalog pruning, scan progress and header-read checks;
- one/eight-thread deterministic result comparison;
- interruption, early LIMIT and error cleanup;
- `git diff --check` and format checks.

New analytics-specific checks include:

- independent reference calculations for statistical metrics;
- score bounds, NULL propagation and component-sum invariants;
- deterministic evidence sampling;
- source permutation and duplicate behavior;
- memory pressure and temporary-storage failure;
- local and remote request/byte accounting;
- documented quality flags for every incomplete-evidence fixture.

Do not run fixture generators concurrently with SQL suites because generators rewrite
files the suites glob over.

## Documentation deliverables

- Function reference and examples for each specialist relation.
- A hunting tutorial using generated data and the public RAT04/SpyMax corpus.
- Score-card documentation with formulas, profiles and limitations.
- Source coverage matrix for PCAP and future Zeek adapters.
- Performance report with corpus shape and resource measurements.
- Licensing/provenance record for algorithms, PSL data and comparison tools.

## Proposed PR sequence

1. **Analytics contract and connection adapter:** reviewed SQL/facade mechanism,
   normalized PCAP connection facts and CIDR orientation tests.
2. **Talkers and long connections:** typed functions, docs and RAT04 validation notes.
3. **Beacon analysis:** frozen `pq-beacon-v1`, golden distributions and scale evidence.
4. **DNS tunneling:** normalized DNS facts, pinned PSL and explainable detector.
5. **Analysis overview:** shared scans, common envelope and optional TLS enrichment.
6. **Rarity/baselines:** corpus-relative prevalence with completeness rules.
7. **Persistence, only if measured:** manifests, facts, immutable reports and rolling
   refresh.
8. **Zeek connection adapter:** same analytics over a second source family.

Each PR should leave a useful stable behavior and avoid depending on an unmerged later
phase.

## Decisions

The implemented connection slice resolves the first design checkpoint: formulas are
documented as `pq-beacon-v1` and `pq-long-v1`, no severity labels are assigned,
`window=NULL` means the selected dataset span, beacon scope defaults to outbound, CIDR
membership uses the bounded portable scalar helper, and installed table macros provide
the public relations (with the documented talker facade for DuckDB's `by` keyword).

The first persistent source identity strong enough for incremental fact reuse and the
exact future Zeek formats and versions remain to be frozen in their later phases.
