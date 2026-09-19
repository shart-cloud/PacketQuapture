# Catalog-assisted packet-time selection

`read_pcap`, `read_packets`, and `read_dns` accept `catalog` and
`catalog_validation` options. Reader columns and packet numbering stay unchanged.

```sql
CREATE TABLE capture_catalog AS
SELECT * FROM capture_inventory('captures/*.pcap');

-- Explicit promise: neither contents nor path bindings change without refresh.
SELECT filename, packet_number, timestamp
FROM read_packets('captures/*.pcap',
                  catalog='main.capture_catalog',
                  catalog_validation='immutable')
WHERE timestamp >= TIMESTAMP '2026-09-18 10:00:00'
  AND timestamp < TIMESTAMP '2026-09-18 10:05:00';
```

Refresh with the [transactional inventory recipe](CAPTURE_INVENTORY.md). SELECT
never writes the catalog. Required catalog columns must have the inventory schema;
additional columns are ignored. The name is bound as a native DuckDB table, not
executed as SQL. Catalog schema errors fail clearly. Invalid/incomplete summary rows,
incompatible versions, conflicting duplicates, missing summaries and observed identity
mismatches fall back to ordinary capture reads. Matching metadata duplicates do not
multiply query rows; duplicate input occurrences remain separate work.

## Trust and supported backends

`catalog_validation='strict'` is the default and currently scans every path-selected
candidate. No backend in this release has a certified strong content identity. A stored
`identity_strength='strong'` label cannot enable strict pruning. Supplying validation
without a catalog is an error.

`immutable` explicitly trusts the caller to maintain correct summaries and keep source
contents **and path bindings** unchanged between refresh and use, including during the
query. Available size, modification time, backend and opaque tag must still match a
complete, stable, compatible inventory row. Files without usable identity metadata scan.
Size/mtime equality is not content verification: same-size edits with restored mtime
can evade these checks. The integration tests demonstrate why strict is the default.

| Source | Immutable time pruning | Validation traffic |
| --- | --- | --- |
| Local regular file | Enabled when available metadata matches | Metadata open/stat; excluded files have zero capture-data reads |
| HTTP/HTTPS | Enabled for stable locators with fresh metadata | HEAD/provider metadata checks; excluded files have zero GET/body bytes in the loopback probe |
| S3 and other remote backends | Disabled pending provider verification | Ordinary reader behavior |

HTTP time pruning requires `enable_http_metadata_cache=false`; if enabled, it falls
back to scanning without changing that setting. Locators containing user information,
query strings or fragments are not used as pruning evidence. Use DuckDB credentials.
The tests exercise HTTP on a loopback server, not arbitrary production providers.
S3 tests use the S3 client against a synthetic server and verify fallback; they do not
certify AWS or MinIO pruning. Local Windows identities can lack a tag and still rely
on the explicit immutable promise plus available size/mtime checks.

Failures opening or inspecting a candidate are errors, never evidence that the file
contains no matches. This includes deleted captures and credential/permission failures.
The implementation does not claim snapshot isolation for external sources or detection
of every mutation after metadata validation. The immutability promise is essential.

## Predicate and execution semantics

Only complete packet timestamp statistics are used. Constant timestamp comparisons,
ranges, IS NULL / IS NOT NULL, and supported same-column AND/OR combinations use
DuckDB's statistics checks. Unknown or unsupported expressions scan. Cross-column OR
is not reduced to a timestamp-only condition. SQL predicates are still evaluated on
scanned packets; statistics never remove the residual row filter. Unsorted captures use
actual minima/maxima, and all-NULL or empty captures have explicit validity statistics.

Filename/Hive selection runs first and retains its existing zero-capture-I/O contract.
Only remaining occurrences are catalog candidates. Catalog selection is held in each
execution's global state, leaving original bind occurrences intact. Every execution
resolves and snapshots the catalog in its current transaction, then rechecks source
metadata; a prepared query does not retain earlier time exclusions. As with existing
readers, input globs are bound to their occurrence list: prepare a new query to discover
new files. Inventory refresh itself rediscovers files on each execution.

The shared inventory snapshot implementation reserves retained metadata through DuckDB's
buffer manager, capped at 64 MiB per invocation. Exceeding that cap fails explicitly.
No snapshot survives initialization, and workers share only the immutable selected
occurrence vector. Whole-file parallelism, selected-file byte progress, LIMIT and
cancellation retain their existing behavior.

Catalog counts do not change optimizer estimates in this milestone. Current identities
cannot be validated strongly at planning time; execution-time statistics are never
installed as optimizer bounds or used to produce a cached EMPTY_RESULT plan.
`read_flows`, `read_tcp_streams`, and `read_dns_messages` do not accept catalog options:
packet-time filtering before stateful aggregation would change their results.

## Explain and validation

Plain EXPLAIN displays path selection, validation mode, and `pending execution` for
catalog selection. EXPLAIN ANALYZE/profiling adds `Runtime Selected Files` and counts
for `Catalog: time excluded`, `time may match`, and fallback reasons. Static path
selection is not a claim that runtime identity validation has occurred.

```sh
./build/release/test/unittest 'test/sql/*'
python3 test/unit/catalog_pruning_test.py
python3 test/unit/capture_inventory_test.py
python3 test/unit/file_pruning_test.py
python3 scripts/benchmark_catalog_pruning.py
```

The catalog SQL suite compares complete rows with EXCEPT ALL across three packet
readers and 1/2/4/8 threads, including duplicates, empty/all-NULL timestamps, unsorted
bounds, boundary comparisons and unsupported predicates. Integration checks cover
prepared reuse, replaced/truncated/deleted sources, strict same-metadata edits,
conflicting/invalid catalogs, transaction-local snapshots, bounded memory, local read
traces, HTTP requests, S3 fallback and explain output. Native tests exercise concurrent
selected readers, cancellation, LIMIT, handle/reservation cleanup and query progress.

The benchmark records first measured and repeated selective queries on increasing
collections, compiler/build/machine details and actual HTTP request/body counts.
Local OS cache state is uncontrolled: these are not certified cold-disk measurements
or cloud-service performance claims. PCAP export and within-file seeking remain later
milestones. Hosted native platform checks remain required for this change.
