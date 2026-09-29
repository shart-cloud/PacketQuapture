# Traffic analytics

Status: connection and DNS-tunneling analytics implemented. This document specifies the analyst-facing
contract for behavioral traffic analysis. [TRAFFIC_ANALYTICS_PLAN.md](TRAFFIC_ANALYTICS_PLAN.md)
tracks the remaining overview, persistence and Zeek deliveries.
Generated and public-corpus evidence is recorded in
[TRAFFIC_ANALYTICS_BENCHMARK.md](TRAFFIC_ANALYTICS_BENCHMARK.md).

## Purpose

PacketQuapture exposes packet, connection, DNS, TLS and TCP-stream facts directly
from captures. Traffic analytics turns those facts into explainable findings such as:

- repeated connections with beacon-like timing or sizes;
- unusually long observed connections;
- the largest hosts, peers and services in a capture;
- DNS names with tunneling-like structure or response behavior;
- destinations that are rare relative to the selected dataset.

The first implementation reads PCAP and PCAPNG through the existing table functions.
The analytics contract is source-neutral so future Zeek and other telemetry readers
can supply the same normalized facts without changing detector output.

This is behavioral triage. A high score identifies evidence worth examining; it does
not identify malware, attribute an operator, establish intent, or prove compromise.

## Design principles

1. **Direct capture queries remain the first workflow.** A single local capture, list,
   glob or remote locator must be analyzable without an import step.
2. **Inputs and analytics are separate layers.** Capture and future Zeek adapters emit
   normalized facts. Detectors depend on those facts rather than parser internals.
3. **Evidence comes before scores.** Every scored result includes raw measurements,
   component scores, the scoring version and data-quality warnings.
4. **Analyst policy is explicit.** Internal networks, time windows and grouping rules
   are arguments, not hidden assumptions.
5. **Incomplete evidence stays visible.** Missing timestamps, partial sessions,
   truncation, reassembly limits and capture boundaries reduce confidence or make a
   metric unavailable. They do not silently become zero.
6. **Queries are composable DuckDB relations.** Results support normal `WHERE`, `JOIN`,
   `UNNEST`, `COPY` and materialization.
7. **Resources are bounded.** Reader budgets remain in force. Analysis aggregation
   obeys DuckDB's memory limit and temporary-storage policy, or fails clearly.
8. **Algorithms are versioned.** A result can be reproduced from its source set,
   reader options, detector version and profile.

## Layering

```text
PCAP/PCAPNG                     future Zeek sources
     |                                  |
read_flows/read_dns/read_tls     Zeek source adapters
     |                                  |
     +------ normalized network facts --+
                         |
          behavioral metrics and detectors
                         |
       findings, evidence and analyst reports
```

The initial SQL implementation may read `read_flows` directly. Its column mapping
must nevertheless be isolated as the PCAP connection adapter so detector logic does
not depend on `flow_id`, capture framing, or the C++ `FlowAggregator`.

## Terminology

- **Source occurrence:** one input selected by an exact path, list entry or glob
  expansion. Repeated paths are repeated occurrences.
- **Connection fact:** one bounded TCP or UDP session observation. Initially this is
  one `read_flows` row.
- **Local network:** a caller-supplied CIDR whose addresses are under investigation.
- **Local endpoint:** the endpoint belonging to a supplied local network.
- **Remote endpoint:** the other endpoint in a local/remote connection.
- **Finding:** one detector result for an analytical subject and window.
- **Metric:** a raw measured value such as median interval or observed duration.
- **Component:** a normalized metric contribution to a score.
- **Profile:** a named, versioned set of thresholds and score weights.
- **Quality flag:** an explicit limit on the evidence or interpretation.

`orig_ip` and `resp_ip` remain transport-orientation terms from `read_flows`. They do
not mean internal and external. Analytics derives local/remote orientation separately.

## Normalized facts

### Connection facts

The minimum connection-fact contract is:

| Field | Type | Meaning |
| --- | --- | --- |
| `source_locator` | `VARCHAR` | Capture or log source. |
| `source_record_id` | `VARCHAR` | Source-local evidence identifier. For PCAP this is derived from input occurrence and `flow_id`; it is not persistent across changed inputs. |
| `transport` | `VARCHAR` | `tcp` or `udp`. |
| `endpoint_a_ip`, `endpoint_b_ip` | `VARCHAR` | Observed endpoints before local-network orientation. |
| `endpoint_a_port`, `endpoint_b_port` | `USMALLINT` | Observed ports. |
| `initiator` | `VARCHAR` | `a`, `b` or `unknown`, with a separate basis. |
| `first_timestamp`, `last_timestamp` | `TIMESTAMP` | Observed time bounds. |
| `duration` | `INTERVAL` | Nonnegative observed duration when timestamps permit it. |
| `a_packets`, `b_packets` | `UBIGINT` | Observed directional packet counts. |
| `a_captured_bytes`, `b_captured_bytes` | `UBIGINT` | Observed directional captured bytes. |
| `a_payload_bytes`, `b_payload_bytes` | `UBIGINT` | Observed directional transport payload bytes. |
| `handshake_complete` | `BOOLEAN` | TCP handshake evidence, otherwise NULL. |
| `partial_session`, `ambiguous` | `BOOLEAN` | Conservative quality indicators. |
| `finalized_by` | `VARCHAR` | Source adapter's connection-boundary reason. |
| `quality_flags` | `VARCHAR[]` | Missing time, late records, capture boundary and other limitations. |

The PCAP adapter maps the `orig_*` fields to endpoint A and `resp_*` to endpoint B.
Future Zeek mapping retains Zeek-specific identifiers and state as provenance, but
must not change the shared meanings above.

Connection facts do not stitch sessions across capture files. Rotated captures may
split a real connection into several observations. Detectors may aggregate repeated
connections across files, but a long-connection detector must not add adjacent
durations and claim continuous observation.

### Implemented PCAP mapping

The bundled `packetquapture_connection_facts` table macro is the shared adapter used
by all three connection analytics functions. It maps `filename` to `source_locator`,
`input_index || ':' || flow_id` to the query-local `source_record_id`, `orig_*` to
endpoint A and `resp_*` to endpoint B. `originator_basis` is retained separately from
`initiator`; simultaneous-open and equal-endpoint observations have an unknown
initiator. Captured, reported and payload counters are preserved before and after
local/remote orientation.

The adapter derives `missing_timestamps`, `late_packets`, `partial_session`,
`ambiguous_orientation`, `capture_boundary` and `invalid_address` flags from the
current `read_flows` columns. EOF and section-boundary finalization are capture-boundary
evidence. Source truncation is not inferred because doing so would require another
capture scan.

### DNS facts

`packetquapture_dns_facts(path_or_list, tcp_idle_timeout := INTERVAL '5 minutes')`
implements the DNS-fact contract with source provenance, client and resolver,
timestamp, transport, question name/type/class, response code, decoded answers,
validity, truncation and error fields. It uses `read_dns_messages` so UDP datagrams
and reassembled TCP messages share one schema and diagnostic model.

Registrable domains use the bundled `psl-2023-09-30-02074b85` Public Suffix List
snapshot, including its ICANN, private, wildcard and exception rules. Unknown suffixes
use the implicit `*` PSL rule; single-label names fall back to the normalized raw name.
Raw FQDNs remain in the normalized fact relation and bounded evidence. Clear DNS on
port 53 only is analyzed. Results carry `cleartext_dns_only`; DoH, DoT and encrypted
application payloads are not inspected or estimated.

### TLS facts

TLS facts include client/server orientation, SNI, negotiated parameters, JA3/JA4
families, certificate hashes and names, tunnel information, timestamps, source
provenance and warnings. They enrich findings but are not required for the first
connection detectors.

## Local-network orientation

Every detector that uses direction takes `local_networks VARCHAR[]`. The argument is
required in the first stable interface. An explicit convenience preset may be added
later, but RFC 1918 inference is never silent.

For each connection:

- exactly one endpoint local: orient it as local and the other as remote;
- both endpoints local: classify it as `internal`;
- neither endpoint local: classify it as `external`;
- an invalid or unparseable address: retain a quality flag and omit it from analyses
  that require orientation.

For an exactly-one-local observation, direction is `outbound` or `inbound` only when
initiation is known. It is `unknown` when simultaneous-open evidence prevents that
decision; local and remote endpoint orientation is still retained. Default outbound
analysis excludes the row, while `scope='local_remote'` includes it with the unknown
direction visible.

The default analytical scope is `outbound`, meaning a local endpoint initiated the
connection when initiation evidence is available. Functions may accept
`scope='local_remote'` to include inbound local/remote observations and surface the
direction explicitly. Internal and external-only observations require an explicit
scope.

## Initial public functions

Names are source-neutral even though the first implementation accepts capture inputs.
All path arguments retain the normal `VARCHAR`, `LIST<VARCHAR>` and glob behavior.

### `analyze_beacons`

```sql
analyze_beacons(
    path_or_list,
    local_networks,
    scope := 'outbound',
    group_by := 'service',
    window := NULL,
    min_connections := 6,
    min_span := INTERVAL '5 minutes',
    min_score := 0,
    max_results := 1000,
    evidence_rows := 8,
    profile := 'balanced-v1',
    tcp_idle_timeout := INTERVAL '5 minutes',
    udp_idle_timeout := INTERVAL '1 minute'
)
```

`group_by='service'` groups by local address, remote address, transport and remote
port. Future groupings may use remote host, SNI or a TLS fingerprint, but they must not
silently merge services in the first release.

One row describes one group in one window:

| Field | Type |
| --- | --- |
| `finding_id` | `VARCHAR` |
| `detector` | `VARCHAR` |
| `detector_version` | `VARCHAR` |
| `profile` | `VARCHAR` |
| `local_ip`, `remote_ip` | `VARCHAR` |
| `remote_port` | `USMALLINT` |
| `transport`, `direction` | `VARCHAR` |
| `window_start`, `window_end` | `TIMESTAMP` |
| `first_seen`, `last_seen` | `TIMESTAMP` |
| `connection_count`, `timed_connection_count` | `UBIGINT` |
| `observation_span` | `INTERVAL` |
| `median_interval_ms`, `interval_mad_ms` | `DOUBLE` |
| `interval_q1_ms`, `interval_q3_ms`, `interval_bowley_skew` | `DOUBLE` |
| `median_payload_bytes`, `payload_mad_bytes` | `DOUBLE` |
| `timing_score`, `size_score`, `support_score`, `span_score` | `DOUBLE` |
| `score` | `DOUBLE` |
| `reasons`, `quality_flags` | `VARCHAR[]` |
| `evidence` | `STRUCT(source_locator VARCHAR, source_record_id VARCHAR, started_at TIMESTAMP, payload_bytes UBIGINT, duration INTERVAL)[]` |
| `evidence_truncated` | `BOOLEAN` |

Intervals are computed between sorted, distinct non-NULL connection start timestamps
within the analytical group and window. Duplicate timestamps do not create zero-length
intervals. Groups without enough timed observations retain their counts and quality
flags but cannot receive a timing score.

Payload size is the sum of both observed directional payload counters for a connection.
It includes retransmitted bytes because the source connection facts do. This limitation
is reported in documentation and is not relabeled as unique application data.

The implemented `pq-beacon-v1` `balanced-v1` profile freezes the scoring rules below.
All clamps are to the inclusive range 0-1 before multiplying by 100.

- `timing_score = 100 * clamp(1 - 4 * interval_mad / median_interval)`. It is NULL
  unless at least three positive intervals exist.
- `size_score = 100 * clamp(1 - 2 * payload_mad / max(1, median_payload))`.
- `support_score = min(100, 50 + 50 * (count - min_connections) / min_connections)`.
- `span_score = min(100, 50 * observation_span / min_span)`, or 100 when `min_span`
  is zero.
- `score = .50 * timing_score + .20 * size_score + .15 * support_score +
  .15 * span_score`. If `timing_score` is NULL, the final score is NULL.

Quartiles use DuckDB's continuous quantile aggregate. MAD is median absolute
deviation. A group must meet `min_connections`; a short span remains visible with
`insufficient_span` and a reduced component instead of being discarded. `min_score`
is applied only after all admitted-group metrics are computed. Evidence is ordered by
timestamp and source reference before being bounded by `evidence_rows`.

Example:

```sql
SELECT local_ip, remote_ip, remote_port, score,
       connection_count, median_interval_ms, interval_mad_ms,
       reasons, quality_flags
FROM analyze_beacons(
    'captures/**/*.pcap*',
    ['10.0.0.0/8']
)
WHERE score >= 70
ORDER BY score DESC;
```

### `analyze_long_connections`

```sql
analyze_long_connections(
    path_or_list,
    local_networks,
    scope := 'local_remote',
    min_duration := INTERVAL '1 hour',
    include_partial := true,
    min_score := 0,
    max_results := 1000,
    profile := 'balanced-v1',
    tcp_idle_timeout := INTERVAL '5 minutes',
    udp_idle_timeout := INTERVAL '1 minute'
)
```

This returns one row per qualifying connection fact. Its typed output preserves source
locator and record ID, local/remote and original endpoint orientation, timestamps,
duration, directional packet and byte counters, handshake/partial/ambiguous flags,
finalization reason, score components, reasons and quality flags.

Duration is observed evidence, not proof that the application communicated for the
whole interval. A connection finalized at EOF or a capture boundary is not extended
into another file. `include_partial=false` removes partial rows rather than treating
them as complete.

The implemented `pq-long-v1` `balanced-v1` score uses a duration component of
`min(100, 50 + 25 * log2(max(1, duration / min_duration)))`. The completeness
component is 100 for a complete observation, 25 for a partial observation finalized
at EOF or a section boundary, and 40 for another partial observation. The final score
is `0.8 * duration_score + 0.2 * completeness_score`. With a zero duration threshold,
the denominator is clamped to one microsecond. Duration and completeness fields remain
authoritative; the score only provides deterministic ranking.

### `summarize_talkers`

```sql
summarize_talkers(
    path_or_list,
    local_networks,
    by := 'host',
    metric := 'payload_bytes',
    scope := 'all',
    max_results := 100,
    tcp_idle_timeout := INTERVAL '5 minutes',
    udp_idle_timeout := INTERVAL '1 minute'
)
```

This is inventory, not threat scoring. Output includes rank, endpoint or service key,
sent/received/total packets, captured/reported/payload bytes, connection count, peer
count and first/last timestamps. The selected metric controls rank. Results do not
contain a suspicion score or severity.

`scope='all'` emits both endpoints of every admitted connection. Directional scopes
emit the local endpoint, while explicit internal and external scopes emit both
endpoints. DuckDB treats `BY` as a parser keyword, so callers setting the non-default
argument quote it: `summarize_talkers(..., "by"='service')`. Similarly, an explicit
beacon window is written as `"window" := INTERVAL '1 hour'`.

### `analyze_dns_tunnels`

```sql
analyze_dns_tunnels(
    path_or_list,
    window := NULL,
    min_queries := 20,
    min_span := INTERVAL '1 minute',
    min_score := 0,
    max_results := 1000,
    evidence_rows := 8,
    profile := 'balanced-v1',
    tcp_idle_timeout := INTERVAL '5 minutes'
)
```

This groups visible, valid DNS messages by client, resolver, grouping domain and
optional window. Query direction establishes client/resolver orientation; response
direction reverses it. The implemented `pq-dns-tunnel-v1` result exposes:

- query and response counts;
- distinct names and distinct left labels;
- question-type distribution;
- median and maximum name/label length;
- normalized label entropy and encoded-character ratio;
- NXDOMAIN and no-answer ratios;
- query rate and active span;
- raw components, score version, reasons, quality flags and bounded samples.

The left payload concatenates labels before the registrable domain. Entropy is Shannon
entropy over its escaped UTF-8 bytes divided by six and clamped to `[0,1]`. The encoded
ratio is the larger proportion matching hexadecimal or RFC 4648 base32 characters;
its component is gated from zero at 12 characters to full weight at 32 characters.
Rate divides query count by at least one minute, avoiding infinite one-timestamp rates.
Malformed and incomplete messages remain visible in `packetquapture_dns_facts` but are
not scored as tunnel queries.

The balanced profile clamps every component to `[0,100]` and computes:

- `length_score = 100 * clamp((median_left_payload_length - 12) / 40)`;
- `entropy_score = 100 * mean_normalized_entropy`;
- `encoded_score = 100 * mean_encoded_ratio * clamp((median_left_payload_length - 12) / 20)`;
- `uniqueness_score = 100 * distinct_name_count / query_count`;
- `failure_score = 100 * max(nxdomain_ratio, no_answer_ratio)`;
- `rate_score = 100 * clamp(queries_per_minute / 30)`;
- support starts at 50 at `min_queries` and reaches 100 at twice that count;
- span reaches 100 at `min_span`, or is 100 when the configured span is zero;
- `score = .20*length + .20*entropy + .10*encoded + .20*uniqueness +
  .10*failure + .10*rate + .05*support + .05*span`.

Entropy alone therefore contributes at most 20 points. Raw names never leave the
process; only the deterministically ordered, caller-bounded evidence list returns
them. A high-entropy CDN or service-discovery name remains evidence for review, not
proof of tunneling.

## Planned functions

### `analyze_rare_destinations`

Rarity is relative to a selected corpus or explicit baseline. Output states the number
of local sources reaching a destination, total active local sources, prevalence, days
seen, first/last seen and connection counts. A single-host capture cannot establish
network prevalence and must report insufficient baseline coverage.

### `analyze_traffic`

After specialist schemas stabilize, this convenience relation runs selected detectors
and returns a common finding envelope:

```sql
SELECT *
FROM analyze_traffic(
    'captures/**/*.pcap*',
    local_networks=['10.0.0.0/8'],
    analyses=['beacon', 'long_connection', 'dns_tunnel']
)
ORDER BY score DESC;
```

Its common columns include detector/version, subject endpoints/domain, window, score,
summary, quality flags and an explainable component list. Specialist functions remain
the authoritative typed interfaces.

## Score and explanation contract

Every scored row contains:

- a score from 0 through 100;
- a detector algorithm version;
- a named profile;
- raw metrics used by that version;
- normalized component scores;
- human-readable reasons derived from those components;
- quality flags and sample sufficiency;
- bounded evidence references back to source records.

Severity, if added, is a versioned mapping from score to labels. It is not stored in
place of the numeric score. Threshold changes create a new profile or version.

An unavailable metric is NULL. A score that cannot be computed is NULL, not zero.
Filtering `score >= 70` therefore does not confuse insufficient evidence with benign
evidence.

`finding_id` is deterministic only for identical normalized subject, window, detector
version, profile and exact ordered source occurrences. It is an analysis-run identifier,
not a persistent global identity.

## Quality and completeness

Relevant quality flags include:

- `missing_timestamps`;
- `late_packets`;
- `partial_session`;
- `ambiguous_orientation`;
- `capture_boundary`;
- `truncated_capture`;
- `insufficient_intervals`;
- `insufficient_span`;
- `flow_limit` or `reassembly_limit`;
- `unsupported_protocol`;
- `incomplete_baseline`;
- `evidence_truncated`.

Functions must distinguish analytical evidence truncation, where only a bounded sample
is returned, from source-data truncation. Limiting evidence rows does not change the
metrics computed over all admitted facts.

## Input, duplicate and ordering semantics

Input expansion follows the existing readers. Repeating a path repeats its facts.
Overlapping captures may therefore double-count traffic; the analytics layer does not
silently deduplicate packets or connections. A future manifest can make overlap policy
explicit.

Input order does not define event order. Detectors sort by analytical key and timestamp
before computing intervals. Equal timestamps use stable source provenance as a tie
breaker, although duplicate timestamps do not create timing intervals.

Output order is unspecified. Analysts use `ORDER BY`.

## Resource and execution contract

The initial macro implementation materializes a normalized connection relation once
per detector query. It must not invoke `read_flows` separately for each score component.
An overview query should share one flow materialization across flow-based detectors and
one DNS materialization across DNS-based detectors.

Reader memory settings and timeouts retain their documented meanings. Downstream sorts
and hash aggregates use DuckDB's memory manager and temporary directory. `max_results`
bounds returned groups and retained evidence; it does not avoid scanning or grouping
the admitted input and is not advertised as a source-byte limit.

If profiling justifies a native implementation, it must preserve these SQL semantics,
use bounded group/evidence state, spill through DuckDB-managed temporary storage, report
progress and respond to interruption. It must not create an unaccounted second memory
budget.

For large remote corpora, callers should first use `capture_inventory` and an explicit
source list or catalog-assisted selection. Persistent investigations may later preflight
file count and source bytes before capture-body reads.

## Persistence and rolling analysis

Persistence is not required by the first release. Analysts can use ordinary DuckDB:

```sql
CREATE TABLE case_beacons AS
SELECT * FROM analyze_beacons(...);
```

A later investigation layer may add named datasets, immutable source manifests,
materialized normalized facts, detector runs and evidence tables. Completed reports
must reference exact source versions and algorithm configuration; rolling refresh must
never silently replace a completed report.

## Future Zeek adapters

Future readers may expose separate functions such as `read_zeek_connections`,
`read_zeek_dns` and `read_zeek_tls`. Text, JSON and any supported binary encodings are
source-adapter concerns. They map into the normalized facts above and retain original
Zeek fields as additional provenance.

The analytics function overload or input selector is not frozen yet. Possible forms are
an explicit `input_format`, a source descriptor, or relation-valued macros if the pinned
DuckDB version provides a satisfactory interface. Format detection must not guess from
ambiguous content or silently reinterpret malformed captures.

Analytical results must state source coverage differences. For example, a Zeek adapter
may have application metadata that a capture decoder does not yet expose, while a raw
capture may retain packet evidence absent from imported logs.

## Licensing boundary

RITA is a useful product and behavior reference, but its repository is GPL-3.0 while
PacketQuapture is MIT except for the separately identified JA4+ implementation. The
core analytics must be independently specified and implemented from public statistical
concepts and PacketQuapture's own fixtures. Do not copy RITA source, SQL, constants,
tests, scoring tables or documentation text.

An installed RITA executable may be used later as an optional black-box comparison
oracle, as tshark is used for protocol validation. It must not become a build or runtime
dependency. Exact RITA compatibility, if desired, belongs in a separately reviewed GPL
package that consumes PacketQuapture's public facts.

## Non-goals for the first release

- claiming parity with RITA or another NDR product;
- threat attribution or automatic malware verdicts;
- live packet capture or alert streaming;
- cross-file TCP reconstruction or connection stitching;
- encrypted DNS or TLS payload decryption;
- automatic network calls for reputation, GeoIP or threat intelligence;
- a custom dashboard, TUI or query language;
- a persistent investigation database;
- hidden deduplication of overlapping captures.
