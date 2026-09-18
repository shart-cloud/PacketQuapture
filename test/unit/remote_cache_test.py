#!/usr/bin/env python3
"""Integration regressions for remote cache reuse, framing, invalidation, and eviction."""

import ctypes as c
from concurrent.futures import ThreadPoolExecutor
import time
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from benchmark_remote_reads import Connection, RangeServer, cache_snapshot, configure, generate, query, quote

WINDOW = 4 * 1024 * 1024
LIBRARY = ROOT / "build/release/src/libduckdb.so"


class RemoteCacheTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="remote-cache-", dir=ROOT / "build")
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)

    def measure(self, connection, server, sql):
        server.begin()
        result = connection.query(sql)
        events = server.finish()
        self.assertTrue(all(e["completed"] and e["status"] in (200, 206, 304) for e in events))
        return result, [e for e in events if e["method"] == "GET"]

    def test_windows_reuse_and_disable_with_cross_boundary_payloads(self):
        files = generate(self.path, 60000, 150, 1)
        with RangeServer(files) as server:
            urls = [server.url + path for path in files]
            for profile in ["default", "external_off", "metadata_on"]:
                with self.subTest(profile=profile), Connection(LIBRARY) as connection:
                    configure(connection, profile, 8)
                    for case in ["metadata", "headers", "selective", "raw", "reject"]:
                        expected = connection.query(query(case, files.values()))
                        first, events = self.measure(connection, server, query(case, urls))
                        self.assertEqual(first, expected)
                        if case == "metadata" or profile == "external_off":
                            self.assertEqual(
                                sum(e["body_bytes"] for e in events), sum(p.stat().st_size for p in files.values())
                            )
                            self.assertEqual(len(events), 3)
                            self.assertTrue(all(e["body_bytes"] <= WINDOW for e in events))
                        else:
                            self.assertEqual(events, [])
                        repeated, events = self.measure(connection, server, query(case, urls))
                        self.assertEqual(repeated, expected)
                        self.assertEqual(len(events), 3 if profile == "external_off" else 0)
                    # Verify bytes themselves across window boundaries, not just lengths.
                    select = "SELECT sum(hash(packet_data)) AS digest FROM read_packets({})"
                    local = connection.query(select.format(quote(next(iter(files.values())))))
                    remote, _ = self.measure(connection, server, select.format(quote(urls[0])))
                    self.assertEqual(remote, local)
                    self.assertEqual(int(cache_snapshot(connection)["entries"]) > 0, profile != "external_off")

    def test_remote_progress_with_skips_cache_and_cancellation(self):
        class QueryProgress(c.Structure):
            _fields_ = [("percentage", c.c_double), ("rows_processed", c.c_uint64), ("total_rows", c.c_uint64)]

        files = generate(self.path, 64, 500000, 1)
        with RangeServer(files, latency_ms=20) as server, Connection(LIBRARY) as connection:
            configure(connection, "default", 4)
            connection.query("SET enable_progress_bar=true")
            connection.query("SET enable_progress_bar_print=false")
            connection.query("SET progress_bar_time=0")
            connection.api.duckdb_query_progress.argtypes = [c.c_void_p]
            connection.api.duckdb_query_progress.restype = QueryProgress
            sql = query("metadata", [server.url + next(iter(files))])
            for phase in ["first", "repeat"]:
                server.begin()
                values = []
                with ThreadPoolExecutor(max_workers=1) as executor:
                    result = executor.submit(connection.query, sql)
                    while not result.done():
                        percentage = connection.api.duckdb_query_progress(connection.connection).percentage
                        if percentage >= 0:
                            values.append(percentage)
                        time.sleep(0.001)
                    self.assertEqual(result.result(), [{"packets": "500000"}])
                events = server.finish()
                self.assertTrue(any(0 < value < 100 for value in values), (phase, values))
                self.assertTrue(all(0 <= value <= 100 for value in values))
                self.assertEqual(values, sorted(values))
                if phase == "repeat":
                    self.assertEqual([e for e in events if e["method"] == "GET"], [])
            connection.query("SET enable_external_file_cache=false")
            with self.assertRaisesRegex(RuntimeError, "Interrupt"):
                connection.query(sql, timeout=0.05)
            server.finish()
            self.assertEqual(connection.query("SELECT 1 AS ok"), [{"ok": "1"}])

    def test_reuse_across_connections_in_one_database(self):
        files = generate(self.path, 1024, 100, 1)
        with RangeServer(files) as server, Connection(LIBRARY) as connection:
            configure(connection, "default", 1)
            sql = query("raw", [server.url + next(iter(files))])
            expected, _ = self.measure(connection, server, sql)
            # Open a second native connection without opening another database.
            original, second = connection.connection, c.c_void_p()
            self.assertEqual(connection.api.duckdb_connect(connection.database, c.byref(second)), 0)
            try:
                connection.connection = second
                configure(connection, "default", 1)
                actual, events = self.measure(connection, server, sql)
                self.assertEqual((actual, events), (expected, []))
            finally:
                connection.connection = original
                connection.api.duckdb_disconnect(c.byref(second))

    def test_interrupted_remote_read_releases_reader_and_connection_recovers(self):
        files = generate(self.path, 60000, 150, 1)
        with RangeServer(files, latency_ms=100) as server, Connection(LIBRARY) as connection:
            configure(connection, "default", 1)
            sql = query("raw", [server.url + next(iter(files))])
            with self.assertRaisesRegex(RuntimeError, "Interrupt"):
                connection.query(sql, timeout=0.05)
            server.finish()
            server.latency_ms = 0
            expected = connection.query(query("raw", files.values()))
            actual, _ = self.measure(connection, server, sql)
            self.assertEqual(actual, expected)
            actual, events = self.measure(connection, server, sql)
            self.assertEqual((actual, events), (expected, []))

    def test_same_size_replacement_invalidates_cached_bytes(self):
        files = generate(self.path, 1024, 100, 1)
        path = next(iter(files.values()))
        with RangeServer(files) as server, Connection(LIBRARY) as connection:
            configure(connection, "default", 1)
            sql = "SELECT sum(hash(packet_data)) AS digest FROM read_packets({})"
            remote_sql = sql.format(quote(server.url + next(iter(files))))
            original, _ = self.measure(connection, server, remote_sql)
            repeated, events = self.measure(connection, server, remote_sql)
            self.assertEqual((repeated, events), (original, []))
            previous = path.stat().st_mtime_ns
            data = bytearray(path.read_bytes())
            data[-1] = 1
            path.write_bytes(data)
            os.utime(path, ns=(previous + 2000000000, previous + 2000000000))
            changed, events = self.measure(connection, server, remote_sql)
            self.assertNotEqual(changed, original)
            self.assertEqual(changed, connection.query(sql.format(quote(path))))
            self.assertGreater(len(events), 0)
            path.unlink()
            with self.assertRaises(RuntimeError):
                connection.query(remote_sql)

    def test_pcapng_and_stream_readers_share_cache(self):
        paths = [
            ROOT / "test/data/sample.pcapng",
            ROOT / "test/data/dns/response.pcapng",
            ROOT / "test/data/reassembly/streams.pcap",
            ROOT / "test/data/tcp_streams/chunks.pcap",
        ]
        files = {f"/{index}.pcap": path for index, path in enumerate(paths)}
        with RangeServer(files) as server, Connection(LIBRARY) as connection:
            configure(connection, "default", 8)
            for url, path in files.items():
                for function in ["read_pcap", "read_packets", "read_dns", "read_dns_messages", "read_tcp_streams"]:
                    with self.subTest(file=path.name, function=function):
                        sql = (
                            "SELECT CAST(t AS VARCHAR) AS row FROM (SELECT * EXCLUDE(filename) FROM "
                            + function
                            + "({})) t"
                        )
                        local = connection.query(sql.format(quote(path)))
                        remote, _ = self.measure(connection, server, sql.format(quote(server.url + url)))
                        self.assertEqual(remote, local)
                        repeated, events = self.measure(connection, server, sql.format(quote(server.url + url)))
                        self.assertEqual((repeated, events), (local, []))

    def test_limit_then_full_scan_and_parallel_duplicates(self):
        files = generate(self.path, 1024, 10000, 1)
        with RangeServer(files) as server, Connection(LIBRARY) as connection:
            configure(connection, "default", 8)
            url = server.url + next(iter(files))
            result, events = self.measure(
                connection, server, "SELECT packet_number FROM read_pcap(" + quote(url) + ") LIMIT 1"
            )
            self.assertEqual(result, [{"packet_number": "1"}])
            self.assertLessEqual(sum(e["body_bytes"] for e in events), WINDOW)
            expected = connection.query(query("raw", list(files.values()) * 8))
            actual, _ = self.measure(connection, server, query("raw", [url] * 8))
            self.assertEqual(actual, expected)
            actual, events = self.measure(connection, server, query("raw", [url] * 8))
            self.assertEqual((actual, events), (expected, []))

    def test_eviction_under_memory_limit(self):
        files = generate(self.path, 60000, 560, 1)
        with RangeServer(files) as server, Connection(LIBRARY) as connection:
            configure(connection, "default", 1)
            connection.query("SET memory_limit='16MB'")
            urls = [server.url + path for path in files]
            expected = connection.query(query("metadata", files.values()))
            for _ in range(2):
                actual, events = self.measure(connection, server, query("metadata", urls))
                self.assertEqual(actual, expected)
                self.assertGreater(len(events), 0)
                self.assertLessEqual(int(cache_snapshot(connection)["resident_bytes"]), 16000000)

    def test_malformed_remote_framing_and_recovery(self):
        files = {
            "/bad.pcap": ROOT / "test/data/malformed/payload.pcap",
            "/bad.pcapng": ROOT / "test/data/malformed/trailer.pcapng",
        }
        with RangeServer(files) as server, Connection(LIBRARY) as connection:
            configure(connection, "default", 1)
            for url in files:
                for _ in range(2):
                    with self.assertRaises(RuntimeError):
                        connection.query(query("raw", [server.url + url]))
            self.assertEqual(connection.query("SELECT 1 AS ok"), [{"ok": "1"}])


if __name__ == "__main__":
    unittest.main()
