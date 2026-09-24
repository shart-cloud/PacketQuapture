#!/usr/bin/env python3
"""File pruning integration: real opens/HTTP requests and path-only Hive metadata.

Run after building the shell/library and installing the matching httpfs extension.
Uses only synthetic fixtures, temporary files, and a loopback HTTP server.
"""

from collections import Counter
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from benchmark_remote_reads import Connection, RangeServer, configure, quote

LIBRARY = ROOT / "build/release/src/libduckdb.so"
CLI = ROOT / "build/release/duckdb"
READERS = [
    "read_pcap",
    "read_packets",
    "read_dns",
    "read_tcp_streams",
    "read_dns_messages",
    "read_flows",
]
FIXTURE = ROOT / "test/data/reassembly/streams.pcap"


def inputs(paths):
    return "[" + ",".join(map(quote, paths)) + "]"


class FilePruningTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="file-pruning-", dir=ROOT / "build")
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name)

    def capture(self, layout, source=FIXTURE):
        target = self.path / layout / "capture.pcap"
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        return target

    def test_local_excluded_opens_and_progress(self):
        a = self.capture("dt=2026-09-18/host=001")
        bad = self.capture("dt=2026-09-17/host=002", ROOT / "test/data/not-a-capture.bin")
        fifo = self.path / "dt=2026-09-16/host=003/pipe.pcap"
        fifo.parent.mkdir(parents=True)
        os.mkfifo(fifo)
        trace = self.path / "opens.log"

        def run(sql):
            result = subprocess.run(
                [
                    "strace",
                    "-f",
                    "-qq",
                    "-yy",
                    "-e",
                    "trace=%file,read,pread64",
                    "-o",
                    str(trace),
                    str(CLI),
                    "-json",
                    "-c",
                    sql,
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            accesses = Counter()
            for line in trace.read_text().splitlines():
                call = re.search(r"\b([a-z][a-z0-9_]*)\(", line)
                if call and call[1] != "execve":
                    for path in [a, bad, fifo]:
                        if str(path) in line:
                            accesses[(path, call[1])] += 1
            return accesses

        for reader in READERS:
            for progress in [False, True]:
                settings = f"SET threads=4; SET enable_progress_bar={str(progress).lower()}; "
                settings += "SET enable_progress_bar_print=false; "
                for options, predicate in [
                    ("", f"filename={quote(a)}"),
                    (", hive_partitioning=true", "host='001'"),
                ]:
                    with self.subTest(reader=reader, progress=progress, options=options):
                        sql = f"SELECT count(*) FROM {reader}({inputs([a, bad, fifo, a])}{options}) WHERE {predicate}"
                        binding = run(settings + "EXPLAIN " + sql)
                        self.assertEqual(binding[(a, "openat")], 0)
                        scanning = run(settings + sql)
                        self.assertGreater(scanning[(a, "openat")], 0)
                        for excluded in [bad, fifo]:
                            self.assertEqual(scanning[(excluded, "openat")], 0)
                            # Literal input expansion may stat; execution/progress must add no probes.
                            self.assertEqual(
                                {op: n for (p, op), n in scanning.items() if p == excluded},
                                {op: n for (p, op), n in binding.items() if p == excluded},
                            )

    def test_remote_cold_cached_and_empty_with_progress(self):
        a = "/dt=2026-09-18/host=001/capture.pcap"
        b = "/dt=2026-09-17/host=002/capture.pcap"
        selected = self.capture("source_a")
        excluded = self.capture("source_b")
        with RangeServer({a: selected, b: excluded}) as server:
            for reader in READERS:
                for progress in [False, True]:
                    for partitioned in [False, True]:
                        with self.subTest(reader=reader, progress=progress, partitioned=partitioned), Connection(
                            LIBRARY
                        ) as c:
                            configure(c, "default", 4)
                            c.query(f"SET enable_progress_bar={str(progress).lower()}")
                            c.query("SET enable_progress_bar_print=false")
                            urls = inputs([server.url + a, server.url + b, server.url + a])
                            options = ", hive_partitioning=true" if partitioned else ""
                            predicate = "host='001'" if partitioned else f"filename={quote(server.url + a)}"
                            sql = f"SELECT count(*) AS n FROM {reader}({urls}{options}) WHERE {predicate}"
                            server.begin()
                            plan = c.query("EXPLAIN " + sql)[0]["explain_value"]
                            self.assertIn("Scanning Files: 2/3", plan)
                            self.assertIn("File Filters:", plan)
                            self.assertEqual(server.finish(), [])
                            expected = c.query(f"SELECT count(*) AS n FROM {reader}({inputs([selected, selected])})")
                            server.begin()
                            self.assertEqual(c.query(sql), expected)
                            events = server.finish()
                            self.assertTrue(any(e["method"] == "GET" for e in events), events)
                            self.assertTrue(
                                all(e["path"] == a and e["completed"] for e in events),
                                events,
                            )
                            # Populate the excluded cache entry, then change its identity.
                            c.query(f"SELECT count(*) FROM {reader}({quote(server.url + b)})")
                            timestamp = excluded.stat().st_mtime_ns + 2000000000
                            os.utime(excluded, ns=(timestamp, timestamp))
                            server.begin()
                            self.assertEqual(c.query(sql), expected)
                            self.assertTrue(all(e["path"] == a for e in server.finish()))
                            c.query("SET packetquapture_stream_memory_mb=0")
                            c.query("SET packetquapture_flow_memory_mb=0")
                            empty = "host='missing'" if partitioned else "filename='missing'"
                            server.begin()
                            self.assertEqual(
                                c.query(f"SELECT count(*) AS n FROM {reader}({urls}{options}) WHERE {empty}"),
                                [{"n": "0"}],
                            )
                            self.assertEqual(server.finish(), [])

    def test_schema_types_nulls_escapes_and_projection(self):
        a = self.capture("dt=2026-09-18/host=001")
        b = self.capture("dt=2026-09-17/host=002")
        for reader in READERS:
            with self.subTest(reader=reader), Connection(LIBRARY) as c:
                plain = f"{reader}({quote(a)})"
                hive = f"{reader}({inputs([a,b,a])}, hive_partitioning=true)"
                # Partition columns follow the reader's own schema, whatever its width.
                schema = c.query("DESCRIBE SELECT * FROM " + plain)
                count = len(schema)
                self.assertNotIn("dt", [row["column_name"] for row in schema])
                extended = c.query("DESCRIBE SELECT * FROM " + hive)
                self.assertEqual(extended[:count], schema)
                self.assertEqual(
                    [(row["column_name"], row["column_type"]) for row in extended[count:]],
                    [("dt", "VARCHAR"), ("host", "VARCHAR")],
                )
                typed = f"{reader}({quote(a)}, hive_partitioning=true, hive_types={{'DT':DATE}})"
                self.assertEqual(
                    c.query(f"SELECT DISTINCT typeof(dt) AS t, host FROM {typed}"),
                    [{"t": "DATE", "host": "001"}],
                )
                auto = f"{reader}({quote(a)}, hive_partitioning=true, hive_types_autocast=true)"
                self.assertEqual(
                    c.query(f"SELECT DISTINCT typeof(dt) AS t, typeof(host) AS h, host FROM {auto}"),
                    [{"t": "DATE", "h": "VARCHAR", "host": "001"}],
                )
                # Filter-only partitions and reversed projected columns use different binding indexes.
                self.assertEqual(
                    c.query(f"SELECT DISTINCT host, dt FROM {hive} WHERE host='001'"),
                    [{"host": "001", "dt": "2026-09-18"}],
                )
                self.assertEqual(
                    c.query(f"SELECT DISTINCT dt FROM {hive} WHERE host='001'"),
                    [{"dt": "2026-09-18"}],
                )
                for value, expected in [
                    ("fw%20one", "fw one"),
                    ("NULL", None),
                    ("__HIVE_DEFAULT_PARTITION__", None),
                    ("", ""),
                ]:
                    path = self.capture("encoded/host=" + value)
                    scan = f"{reader}({quote(path)}, hive_partitioning=true)"
                    self.assertEqual(
                        c.query(f"SELECT DISTINCT host FROM {scan}"),
                        [{"host": expected}],
                    )
                    pred = "host IS NULL" if expected is None else f"host={quote(expected)}"
                    self.assertEqual(
                        c.query(f"SELECT count(*)>0 AS ok FROM {scan} WHERE {pred}"),
                        [{"ok": "true"}],
                    )
                upper = self.capture("upper/HOST=fw01")
                self.assertEqual(
                    c.query(
                        f"SELECT DISTINCT host FROM {reader}({quote(upper)}, HIVE_PARTITIONING=true) WHERE host='fw01'"
                    ),
                    [{"HOST": "fw01"}],
                )

    def test_invalid_metadata_fails_before_selection(self):
        for reader in READERS:
            with self.subTest(reader=reader), Connection(LIBRARY) as c:
                for key in [
                    "filename",
                    "TiMeStAmP" if reader in READERS[:3] else ("FLOW_ID" if reader == "read_flows" else "STREAM_ID"),
                ]:
                    path = self.capture("collision/" + key + "=x")
                    with self.assertRaisesRegex(RuntimeError, "collides"):
                        c.query(
                            f"SELECT * FROM {reader}({quote(path)}, hive_partitioning=true) WHERE filename='missing'"
                        )
                duplicate = self.capture("HOST=a/host=b")
                with self.assertRaisesRegex(RuntimeError, "collides"):
                    c.query(f"SELECT * FROM {reader}({quote(duplicate)}, hive_partitioning=true)")
                invalid = self.capture("dt=invalid/host=001")
                with self.assertRaisesRegex(RuntimeError, "Unable to cast"):
                    c.query(
                        f"SELECT * FROM {reader}({quote(invalid)}, hive_partitioning=true, hive_types={{'dt':DATE}}) WHERE host='missing'"
                    )

    def test_chunk_boundaries_diagnostics_and_partition_ownership(self):
        for reader, fixture in [
            ("read_tcp_streams", "tcp_streams/chunks.pcap"),
            ("read_dns_messages", "reassembly/chunks.pcap"),
        ]:
            a = self.capture(reader + "/host=001", ROOT / "test/data" / fixture)
            b = self.capture(reader + "/host=002")
            scan = f"{reader}({inputs([a,b,a])}, hive_partitioning=true)"
            with self.subTest(reader=reader), Connection(LIBRARY) as c:
                c.query("SET threads=1")
                c.query(f"CREATE TABLE baseline AS SELECT * FROM {scan}")
                self.assertEqual(
                    c.query("SELECT count(*)>2048 AS ok FROM baseline"),
                    [{"ok": "true"}],
                )
                for threads in [1, 2, 4, 8]:
                    c.query(f"SET threads={threads}")
                    c.query(f"CREATE OR REPLACE TABLE actual AS SELECT * FROM {scan} WHERE host='001'")
                    self.assertEqual(
                        c.query(
                            "SELECT count(*) AS n FROM ((SELECT * FROM actual EXCEPT ALL SELECT * FROM baseline WHERE host='001') UNION ALL (SELECT * FROM baseline WHERE host='001' EXCEPT ALL SELECT * FROM actual))"
                        ),
                        [{"n": "0"}],
                    )
                    self.assertEqual(
                        c.query(
                            "SELECT count(*) AS n FROM actual WHERE host!='001' OR NOT contains(filename, 'host=001')"
                        ),
                        [{"n": "0"}],
                    )

    def test_batched_duplicate_occurrences_and_explain(self):
        a = self.capture("host=001")
        b = self.capture("host=002")
        # Cross the cancellation batch boundary with repeated occurrences.
        paths = [a, b] * 260 + [a]
        with Connection(LIBRARY) as c:
            c.query("SET threads=4")
            for reader in ["read_pcap", "read_tcp_streams", "read_dns_messages"]:
                with self.subTest(reader=reader):
                    scan = f"{reader}({inputs(paths)}, hive_partitioning=true)"
                    c.query(f"CREATE OR REPLACE TABLE baseline AS SELECT * FROM {scan}")
                    c.query(f"CREATE OR REPLACE TABLE actual AS SELECT * FROM {scan} WHERE host='001'")
                    self.assertEqual(
                        c.query(
                            "SELECT count(*) AS n FROM ((SELECT * FROM actual EXCEPT ALL SELECT * FROM baseline WHERE host='001') UNION ALL (SELECT * FROM baseline WHERE host='001' EXCEPT ALL SELECT * FROM actual))"
                        ),
                        [{"n": "0"}],
                    )
                    plan = c.query(f"EXPLAIN SELECT * FROM {scan} WHERE host='001'")[0]["explain_value"]
                    self.assertIn("ScanningFiles:261/521", "".join(plan.replace("│", "").split()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
