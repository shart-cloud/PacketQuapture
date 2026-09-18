#!/usr/bin/env python3
"""Validate benchmark HTTP accounting, ranges, limits, fixtures, and C API ownership."""

import http.client
import json
from pathlib import Path
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
    generate,
    request_summary,
)
from benchmark_minio_reads import MinioProxy


class RemoteReadBenchmarkTests(unittest.TestCase):
    def setUp(self):
        (ROOT / "build").mkdir(exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(prefix="remote-test-", dir=ROOT / "build")
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "capture.pcap"
        self.path.write_bytes(b"0123456789")

    def request(self, server, method="GET", path="/capture.pcap", headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        try:
            connection.request(method, path, headers=headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_head_ranges_and_accounting(self):
        with RangeServer({"/capture.pcap": self.path}) as server:
            server.begin()
            status, headers, body = self.request(server, "HEAD")
            self.assertEqual((status, headers["Content-Length"], body), (200, "10", b""))
            status, headers, body = self.request(server, headers={"Range": "bytes=2-5"})
            self.assertEqual((status, headers["Content-Range"], body), (206, "bytes 2-5/10", b"2345"))
            self.assertEqual(self.request(server, headers={"Range": "bytes=-3"})[2], b"789")
            self.assertEqual(self.request(server, headers={"Range": "bytes=8-"})[2], b"89")
            self.assertEqual(self.request(server)[2], b"0123456789")
            events = server.finish()
            summary = request_summary(events, 10)
            self.assertEqual(summary["requests"], 5)
            self.assertEqual(summary["head_requests"], 1)
            self.assertEqual(summary["range_requests"], 3)
            self.assertEqual(summary["response_body_bytes"], 19)
            self.assertEqual(summary["incomplete_responses"], 0)

    def test_invalid_ranges_and_url_allowlist(self):
        with RangeServer({"/capture.pcap": self.path}) as server:
            for value in [
                "bytes=100-",
                "bytes=9-2",
                "bytes=-0",
                "bytes=",
                "bytes=1-2,4-5",
            ]:
                status, headers, body = self.request(server, headers={"Range": value})
                self.assertEqual((status, headers["Content-Range"], body), (416, "bytes */10", b""))
            self.assertEqual(self.request(server, path="/../capture.pcap")[0], 404)
            self.assertEqual(server.finish()[-1]["status"], 404)

    def test_request_budget_and_reset(self):
        with RangeServer({"/capture.pcap": self.path}, max_requests=2) as server:
            self.assertEqual(self.request(server, "HEAD")[0], 200)
            self.assertEqual(self.request(server, "HEAD")[0], 200)
            self.assertEqual(self.request(server, "HEAD")[0], 503)
            self.assertEqual(len(server.finish()), 3)
            server.begin()
            self.assertEqual(self.request(server)[0], 200)
            self.assertEqual(request_summary(server.finish(), 10)["response_body_bytes"], 10)

    def test_byte_budget(self):
        with RangeServer({"/capture.pcap": self.path}, max_bytes=5) as server:
            self.assertEqual(self.request(server, "HEAD")[0], 200)
            self.assertEqual(self.request(server, headers={"Range": "bytes=0-3"})[0], 206)
            self.assertEqual(self.request(server, headers={"Range": "bytes=4-7"})[0], 503)
            self.assertEqual(request_summary(server.finish(), 10)["response_body_bytes"], 4)

    def test_stable_version_conditions(self):
        with RangeServer({"/capture.pcap": self.path}) as server:
            etag = self.request(server, "HEAD")[1]["ETag"]
            self.assertEqual(self.request(server, headers={"If-None-Match": etag})[0], 304)
            self.assertEqual(self.request(server, headers={"If-Match": '"wrong"'})[0], 412)
            self.assertEqual(
                self.request(server, headers={"Range": "bytes=0-1", "If-Range": etag})[2],
                b"01",
            )
            self.assertEqual(
                self.request(server, headers={"Range": "bytes=0-1", "If-Range": '"wrong"'})[2],
                b"0123456789",
            )

    def test_minio_proxy_preserves_signature_and_counts_only_payload(self):
        observed = []

        class RecordingHandler(RangeHandler):
            def do_GET(self):
                observed.append((self.headers.get("Host"), self.headers.get("Authorization")))
                super().do_GET()

        with RangeServer({"/capture.pcap": self.path}) as upstream:
            upstream.RequestHandlerClass = RecordingHandler
            with MinioProxy({"/capture.pcap": self.path}, ("127.0.0.1", upstream.server_port)) as proxy:
                self.assertEqual(self.request(proxy, "HEAD")[0], 200)
                status, headers, body = self.request(
                    proxy,
                    headers={
                        "Range": "bytes=2-5",
                        "Host": "signed-host",
                        "Authorization": "fake-signature",
                    },
                )
                self.assertEqual(
                    (status, headers["Content-Range"], body),
                    (206, "bytes 2-5/10", b"2345"),
                )
                self.assertEqual(observed, [("signed-host", "fake-signature")])
                self.assertEqual(self.request(proxy, path="/other-bucket/object")[0], 403)
                events = proxy.finish()
                self.assertEqual(request_summary(events, 10)["response_body_bytes"], 4)
                self.assertNotIn("fake-signature", json.dumps(events))
                self.assertEqual(len(upstream.finish()), 2)

    def test_minio_proxy_byte_and_request_limits(self):
        with RangeServer({"/capture.pcap": self.path}) as upstream:
            with MinioProxy(
                {"/capture.pcap": self.path},
                ("127.0.0.1", upstream.server_port),
                max_bytes=5,
                max_requests=3,
            ) as proxy:
                self.assertEqual(self.request(proxy, "HEAD")[0], 200)
                self.assertEqual(self.request(proxy, headers={"Range": "bytes=0-3"})[2], b"0123")
                self.assertEqual(self.request(proxy, headers={"Range": "bytes=4-7"})[0], 503)
                self.assertEqual(self.request(proxy, "HEAD")[0], 503)
                self.assertEqual(request_summary(proxy.finish(), 10)["response_body_bytes"], 4)
                proxy.begin()
                self.assertEqual(self.request(proxy, "HEAD")[0], 200)

    def test_fixture_split_preserves_records_and_predicate_selectivity(self):
        files = generate(Path(self.directory.name), 100, 7, 3)
        ports = []
        for path in files.values():
            data = path.read_bytes()
            self.assertEqual(data[:4], bytes.fromhex("d4c3b2a1"))
            cursor = 24
            while cursor < len(data):
                _, _, captured, original = struct.unpack_from("<IIII", data, cursor)
                self.assertEqual((captured, original), (100, 100))
                ports.append(struct.unpack_from("!H", data, cursor + 16 + 36)[0])
                cursor += 16 + captured
            self.assertEqual(cursor, len(data))
        self.assertEqual(ports, [443, 53, 443, 53, 443, 53, 443])

    @unittest.skipUnless((ROOT / "build/release/src/libduckdb.so").exists(), "release library not built")
    def test_native_result_ownership_and_error_recovery(self):
        with Connection(ROOT / "build/release/src/libduckdb.so") as connection:
            self.assertEqual(
                connection.query("SELECT 42 AS n, NULL::VARCHAR AS missing, 'x' AS label"),
                [{"n": "42", "missing": None, "label": "x"}],
            )
            with self.assertRaises(RuntimeError):
                connection.query("SELECT * FROM definitely_missing_benchmark_table")
            self.assertEqual(connection.query("SELECT 1 AS ok"), [{"ok": "1"}])


if __name__ == "__main__":
    unittest.main()
