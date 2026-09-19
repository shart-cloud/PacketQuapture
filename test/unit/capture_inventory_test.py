#!/usr/bin/env python3
"""Inventory identity, incremental refresh, preparation and instrumented remote I/O."""

from pathlib import Path
import os
import shutil
import struct
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from benchmark_remote_reads import (
    Connection,
    RangeServer,
    RangeHandler,
    configure,
    quote,
)

LIBRARY = ROOT / "build/release/src/libduckdb.so"
FIXTURE = ROOT / "test/data/flows/tcp.pcap"


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="inventory-", dir=ROOT / "build")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.path = self.directory / "a.pcap"
        shutil.copyfile(FIXTURE, self.path)

    def scan(self, source=None, options=""):
        return f"capture_inventory({quote(source or self.path)}{options})"

    def test_refresh_transaction_duplicates_and_fallback(self):
        with Connection(LIBRARY) as c:
            c.query("BEGIN")
            c.query("CREATE TEMP TABLE previous AS SELECT * FROM " + self.scan(options=",detail='protocols'"))
            options = ",previous_catalog='previous',detail='protocols',catalog_validation='immutable'"
            self.assertEqual(
                c.query("SELECT reused FROM " + self.scan(options=options)),
                [{"reused": "true"}],
            )
            c.query("INSERT INTO previous SELECT * FROM previous")
            rows = c.query(
                f"SELECT input_index,packet_count,reused FROM capture_inventory([{quote(self.path)},{quote(self.path)}]{options}) ORDER BY input_index"
            )
            self.assertEqual(
                rows,
                [
                    {"input_index": "1", "packet_count": "9", "reused": "true"},
                    {"input_index": "2", "packet_count": "9", "reused": "true"},
                ],
            )
            c.query("INSERT INTO previous SELECT * REPLACE(packet_count+1 AS packet_count) FROM previous LIMIT 1")
            self.assertEqual(
                c.query("SELECT reused,reuse_reason FROM " + self.scan(options=options)),
                [{"reused": "false", "reuse_reason": "conflicting_summaries"}],
            )
            c.query("ROLLBACK")
            c.query("CREATE TABLE previous AS SELECT * FROM " + self.scan())
            self.assertEqual(
                c.query("SELECT reused FROM " + self.scan(options=options)),
                [{"reused": "false"}],
            )  # detail upgrade
            c.query("UPDATE previous SET semantic_version=99")
            self.assertEqual(
                c.query("SELECT reused FROM " + self.scan(options=options.replace(",detail='protocols'", ""))),
                [{"reused": "false"}],
            )

    def test_prepared_rechecks_catalog_and_discovers_files(self):
        with Connection(LIBRARY) as c:
            c.query("CREATE TABLE previous AS SELECT * FROM " + self.scan())
            c.query(
                "PREPARE inv AS SELECT filename,reused FROM "
                + self.scan(
                    str(self.directory / "*.pcap"),
                    ",previous_catalog='previous',catalog_validation='immutable'",
                )
                + " ORDER BY filename"
            )
            self.assertEqual(c.query("EXECUTE inv"), [{"filename": str(self.path), "reused": "true"}])
            other = self.directory / "b.pcap"
            shutil.copyfile(self.path, other)
            self.assertEqual(len(c.query("EXECUTE inv")), 2)
            c.query("UPDATE previous SET scan_status='error'")
            self.assertTrue(all(r["reused"] == "false" for r in c.query("EXECUTE inv")))
            other.unlink()
            self.assertEqual(len(c.query("EXECUTE inv")), 1)
            self.path.unlink()
            with self.assertRaises(RuntimeError):
                c.query("EXECUTE inv")  # incomplete/empty discovery must fail

    def test_changed_and_same_metadata_replacements(self):
        with Connection(LIBRARY) as c:
            c.query("CREATE TABLE previous AS SELECT * FROM " + self.scan())
            options = ",previous_catalog='previous',catalog_validation='immutable'"
            stat = self.path.stat()
            contents = bytearray(self.path.read_bytes())
            # Same length and restored mtime: weak metadata cannot certify content.
            contents[24:28] = struct.pack("<I", 100)
            self.path.write_bytes(contents)
            os.utime(self.path, ns=(stat.st_atime_ns, stat.st_mtime_ns))
            strict = c.query(
                "SELECT reused,epoch(max_timestamp) AS maximum FROM "
                + self.scan(options=",previous_catalog='previous'")
            )[0]
            self.assertEqual(strict, {"reused": "false", "maximum": "100.0"})
            trusted = c.query("SELECT reused FROM " + self.scan(options=options))[0]
            self.assertEqual(trusted["reused"], "true")  # only permitted by explicit immutable promise
            replacement = self.directory / "replacement"
            replacement.write_bytes(contents[:-1])
            replacement.replace(self.path)
            row = c.query(
                "SELECT reused,scan_status,packet_count FROM " + self.scan(options=options + ",on_error='report'")
            )[0]
            self.assertEqual(row, {"reused": "false", "scan_status": "error", "packet_count": None})
            self.path.unlink()
            row = c.query("SELECT scan_status,packet_count FROM " + self.scan(options=options + ",on_error='report'"))[
                0
            ]
            self.assertEqual(row, {"scan_status": "error", "packet_count": None})

    def test_http_and_s3_identity_reuse_requests(self):
        for backend in ("http", "s3"):
            with self.subTest(backend=backend), RangeServer({"/bucket/a.pcap": self.path}) as server, Connection(
                LIBRARY
            ) as c:
                configure(c, "external_off", 4)
                if backend == "s3":
                    c.query(f"SET s3_endpoint='127.0.0.1:{server.server_port}'")
                    c.query(
                        "SET s3_use_ssl=false; SET s3_url_style='path'; SET s3_region='us-east-1'; SET s3_access_key_id='synthetic'; SET s3_secret_access_key='synthetic'"
                    )
                    source = "s3://bucket/a.pcap"
                else:
                    source = server.url + "/bucket/a.pcap"
                server.begin()
                c.query("CREATE TABLE previous AS SELECT * FROM " + self.scan(source, ",detail='protocols'"))
                first = server.finish()
                self.assertTrue(any(e["body_bytes"] for e in first))
                server.begin()
                result = c.query(
                    "SELECT reused,identity_strength FROM "
                    + self.scan(
                        source,
                        ",detail='protocols',previous_catalog='previous',catalog_validation='immutable'",
                    )
                )
                reused = server.finish()
                self.assertEqual(result, [{"reused": "true", "identity_strength": "weak"}])
                self.assertTrue(reused)
                self.assertEqual(sum(e["body_bytes"] for e in reused), 0)
                self.assertTrue(all(e["method"] == "HEAD" for e in reused))
                server.begin()
                result = c.query("SELECT reused FROM " + self.scan(source, ",previous_catalog='previous'"))
                strict = server.finish()
                self.assertEqual(result, [{"reused": "false"}])
                self.assertTrue(any(e["body_bytes"] for e in strict))

    def test_remote_metadata_cache_requires_explicit_disable(self):
        with RangeServer({"/a.pcap": self.path}) as server, Connection(LIBRARY) as c:
            configure(c, "metadata_on", 1)
            with self.assertRaisesRegex(RuntimeError, "enable_http_metadata_cache=false"):
                c.query("SELECT count(*) FROM " + self.scan(server.url + "/a.pcap", ",on_error='report'"))
            c.query("SET enable_http_metadata_cache=false")
            self.assertEqual(
                c.query("SELECT packet_count FROM " + self.scan(server.url + "/a.pcap")),
                [{"packet_count": "9"}],
            )

    def test_mutation_during_remote_scan_invalidates_summary(self):
        path = self.path

        class Mutate(RangeHandler):
            def do_GET(self):
                super().do_GET()
                with self.server.condition:
                    if not getattr(self.server, "mutated", False):
                        self.server.mutated = True
                        st = path.stat()
                        os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 2000000000))

        with RangeServer({"/a.pcap": self.path}) as server, Connection(LIBRARY) as c:
            server.RequestHandlerClass = Mutate
            configure(c, "external_off", 1)
            row = c.query(
                "SELECT scan_status,packet_count FROM " + self.scan(server.url + "/a.pcap", ",on_error='report'")
            )[0]
            self.assertIn(row["scan_status"], ("changed", "error"))
            self.assertIsNone(row["packet_count"])

    def test_named_pipe_reports_without_opening(self):
        pipe = self.directory / "pipe.pcap"
        os.mkfifo(pipe)
        with Connection(LIBRARY) as c:
            self.assertEqual(
                c.query("SELECT scan_status,packet_count FROM " + self.scan(pipe, ",on_error='report'")),
                [{"scan_status": "error", "packet_count": None}],
            )

    def test_catalog_snapshot_cap_releases_reservations(self):
        with Connection(LIBRARY) as c:
            c.query("CREATE TABLE previous AS SELECT * FROM " + self.scan())
            c.query("UPDATE previous SET identity_value=repeat('x',34000000)")
            with self.assertRaisesRegex(RuntimeError, "snapshot exceeds 64 MiB"):
                c.query(
                    "SELECT packet_count FROM "
                    + self.scan(options=",previous_catalog='previous',catalog_validation='immutable',on_error='report'")
                )
            self.assertEqual(
                c.query("SELECT coalesce(sum(memory_usage_bytes),0) bytes FROM duckdb_memory() WHERE tag='EXTENSION'"),
                [{"bytes": "0"}],
            )
            self.assertEqual(
                c.query("SELECT packet_count FROM " + self.scan()),
                [{"packet_count": "9"}],
            )

    def test_safe_table_binding_and_stable_locators(self):
        with Connection(LIBRARY) as c:
            c.query("CREATE TABLE sentinel(x INTEGER)")
            with self.assertRaises(RuntimeError):
                c.query("SELECT * FROM " + self.scan(options=",previous_catalog='sentinel; DROP TABLE sentinel'"))
            self.assertEqual(c.query("SELECT count(*) n FROM sentinel"), [{"n": "0"}])
            with self.assertRaises(RuntimeError):
                c.query("SELECT * FROM " + self.scan("https://example.invalid/a.pcap?token=private"))
            with self.assertRaises(RuntimeError):
                c.query("SELECT * FROM " + self.scan("https://user:secret@example.invalid/a.pcap"))
            c.query("CREATE TEMP TABLE previous AS SELECT * FROM " + self.scan())
            c.query("SET packetquapture_inventory_memory_mb=31")
            with self.assertRaisesRegex(RuntimeError, "cannot reserve 32 MiB"):
                c.query("SELECT * FROM " + self.scan())
            c.query("SET packetquapture_inventory_memory_mb=128")
            c.query("SELECT count(*) FROM " + self.scan())


if __name__ == "__main__":
    unittest.main(verbosity=2)
