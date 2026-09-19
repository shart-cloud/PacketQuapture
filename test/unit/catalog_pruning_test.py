#!/usr/bin/env python3
"""Execution-time catalog validation, prepared reuse and actual avoided reads."""

import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from benchmark_remote_reads import Connection, RangeServer, configure, quote
from generate_protocol_captures import eth, ip4, udp

LIB = ROOT / "build/release/src/libduckdb.so"
CLI = ROOT / "build/release/duckdb"


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="catalog-", dir=ROOT / "build")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "a.pcap"
        self.capture(self.path, [1, 2, 3])

    def capture(self, path, times):
        packet = eth(ip4(udp(), 17))
        path.write_bytes(
            struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
            + b"".join(struct.pack("<IIII", t, 0, len(packet), len(packet)) + packet for t in times)
        )

    def create(self, c, path=None):
        c.query(f"CREATE OR REPLACE TABLE cat AS SELECT * FROM capture_inventory({quote(path or self.path)})")

    def query(self, path=None, mode="immutable", reader="read_packets"):
        options = "" if mode is None else f",catalog='cat',catalog_validation='{mode}'"
        return f"SELECT count(*) n FROM {reader}({quote(path or self.path)}{options}) WHERE timestamp >= TIMESTAMP '1970-01-01 00:00:10'"

    def count(self, c, **kwargs):
        return int(c.query(self.query(**kwargs))[0]["n"])

    def test_prepared_revalidates_sources_and_catalog(self):
        with Connection(LIB) as c:
            self.create(c)
            c.query("PREPARE q AS " + self.query())
            self.assertEqual(c.query("EXECUTE q"), [{"n": "0"}])
            self.capture(self.path, [20, 21, 22, 23])
            self.assertEqual(c.query("EXECUTE q"), [{"n": "4"}])
            self.create(c)
            self.assertEqual(c.query("EXECUTE q"), [{"n": "4"}])
            c.query("DELETE FROM cat")
            self.assertEqual(c.query("EXECUTE q"), [{"n": "4"}])
            self.path.write_bytes(b"bad")
            with self.assertRaises(RuntimeError):
                c.query("EXECUTE q")
            self.path.unlink()
            with self.assertRaises(RuntimeError):
                c.query("EXECUTE q")
            self.capture(self.path, [30])
            self.assertEqual(c.query("EXECUTE q"), [{"n": "1"}])

    def test_strict_same_metadata_and_invalid_summaries(self):
        with Connection(LIB) as c:
            self.create(c)
            before = self.path.stat()
            self.capture(self.path, [20, 21, 22])
            os.utime(self.path, ns=(before.st_atime_ns, before.st_mtime_ns))
            self.assertEqual(self.count(c, mode="strict"), 3)
            # This deliberately violates the immutable contract, proving why it is opt-in.
            self.assertEqual(self.count(c), 0)
            for change in [
                "semantic_version=99",
                "metadata_unchanged=false",
                "scan_status='error'",
                "packet_count=NULL",
                "timestamp_null_count=999",
            ]:
                self.create(c)
                c.query("UPDATE cat SET " + change)
                self.assertEqual(self.count(c), 3)
            self.create(c)
            c.query("INSERT INTO cat SELECT * REPLACE(TIMESTAMP '1970-01-01' AS min_timestamp) FROM cat")
            self.assertEqual(self.count(c), 3)
            c.query("UPDATE cat SET identity_value=repeat('x',34000000)")
            with self.assertRaisesRegex(RuntimeError, "snapshot exceeds 64 MiB"):
                self.count(c)
            self.assertEqual(
                c.query("SELECT coalesce(sum(memory_usage_bytes),0) n FROM duckdb_memory() WHERE tag='EXTENSION'"),
                [{"n": "0"}],
            )
            self.assertEqual(self.count(c, mode=None), 3)

    def test_transaction_snapshot_and_connections(self):
        for _ in range(2):
            with Connection(LIB) as c:
                c.query("BEGIN")
                self.create(c)
                self.assertEqual(self.count(c), 0)
                c.query("UPDATE cat SET semantic_version=99")
                self.assertEqual(self.count(c), 0)
                c.query("ROLLBACK")
                with self.assertRaises(RuntimeError):
                    self.count(c)

    def test_http_avoided_reads_fallback_and_path_selection(self):
        with RangeServer({"/a.pcap": self.path}) as server, Connection(LIB) as c:
            configure(c, "external_off", 4)
            url = server.url + "/a.pcap"
            self.create(c, url)
            for reader in ["read_pcap", "read_packets", "read_dns"]:
                for progress in [False, True]:
                    c.query(f"SET enable_progress_bar={str(progress).lower()}; SET enable_progress_bar_print=false")
                    server.begin()
                    self.assertEqual(self.count(c, path=url, reader=reader), 0)
                    requests = server.finish()
                    self.assertTrue(any(x["method"] == "HEAD" for x in requests))
                    self.assertEqual(sum(x["body_bytes"] for x in requests), 0)
            server.begin()
            self.assertEqual(self.count(c, path=url, mode="strict"), 0)
            self.assertGreater(sum(x["body_bytes"] for x in server.finish()), 0)
            server.begin()
            c.query(self.query(path=url) + f" AND filename <> {quote(url)}")
            self.assertEqual(server.finish(), [])
            c.query("PREPARE remote_q AS " + self.query(path=url))
            self.capture(self.path, [20, 21, 22, 23])
            self.assertEqual(c.query("EXECUTE remote_q"), [{"n": "4"}])
            c.query("SET enable_http_metadata_cache=true")
            server.begin()
            self.assertEqual(self.count(c, path=url), 4)
            self.assertGreater(sum(x["body_bytes"] for x in server.finish()), 0)

    def test_s3_remains_fallback(self):
        with RangeServer({"/bucket/a.pcap": self.path}) as server, Connection(LIB) as c:
            configure(c, "external_off", 4)
            c.query(f"SET s3_endpoint='127.0.0.1:{server.server_port}'")
            c.query(
                "SET s3_use_ssl=false; SET s3_url_style='path'; SET s3_region='us-east-1'; SET s3_access_key_id='synthetic'; SET s3_secret_access_key='synthetic'"
            )
            path = "s3://bucket/a.pcap"
            self.create(c, path)
            server.begin()
            self.assertEqual(self.count(c, path=path), 0)
            self.assertGreater(sum(x["body_bytes"] for x in server.finish()), 0)
            plan = str(c.query("EXPLAIN ANALYZE " + self.query(path=path)))
            self.assertIn("unverified remote", plan)

    def test_local_data_reads_and_explain(self):
        db = self.root / "catalog.db"
        subprocess.run(
            [str(CLI), str(db), "-c", f"CREATE TABLE cat AS SELECT * FROM capture_inventory({quote(self.path)})"],
            check=True,
            capture_output=True,
        )
        for mode in ["immutable", "strict"]:
            trace = self.root / "trace.log"
            result = subprocess.run(
                [
                    "strace",
                    "-f",
                    "-qq",
                    "-yy",
                    "-e",
                    "trace=read,pread64,openat",
                    "-o",
                    str(trace),
                    str(CLI),
                    str(db),
                    "-c",
                    self.query(mode=mode),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            reads = [
                line
                for line in trace.read_text().splitlines()
                if str(self.path) in line and re.search(r"\b(?:read|pread64)\(", line)
            ]
            self.assertEqual(bool(reads), mode == "strict")
        with Connection(LIB) as c:
            self.create(c)
            plain = str(c.query("EXPLAIN " + self.query()))
            self.assertIn("pending execution", plain)
            self.assertNotIn("Runtime Selected Files", plain)
            actual = str(c.query("EXPLAIN ANALYZE " + self.query()))
            self.assertIn("Runtime Selected Files", actual)
            self.assertIn("time excluded", actual)


if __name__ == "__main__":
    unittest.main(verbosity=2)
