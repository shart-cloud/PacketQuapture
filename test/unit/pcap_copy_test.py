#!/usr/bin/env python3
"""PCAP COPY publication, exact readback, ordering and failure cleanup."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os
import signal
import struct
import subprocess
import sys
import tempfile
import time
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from benchmark_remote_reads import Connection, RangeServer, configure, quote

LIB = ROOT / "build/release/src/libduckdb.so"
CLI = ROOT / "build/release/duckdb"
FIELDS = "timestamp,captured_length,original_length,link_type,packet_data"
ROW = "SELECT make_timestamp(1000001) AS timestamp,3::UINTEGER AS captured_length,5::UINTEGER AS original_length,1::UINTEGER AS link_type,from_hex('0080FF') AS packet_data"


class CopyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pcap-copy-", dir=ROOT / "build")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "out.pcap"

    def copy(self, c, query=ROW, options="LINKTYPE 1", path=None):
        return c.query(f"COPY ({query}) TO {quote(path or self.path)} (FORMAT PCAP, {options})")

    def clean(self):
        self.assertEqual(list(self.root.glob(".packetquapture-*")), [])

    def test_roundtrip_header_empty_and_reordered_columns(self):
        with Connection(LIB) as c:
            self.assertEqual(self.copy(c), [{"Count": "1"}])
            self.assertEqual(struct.unpack('<IHHIIII', self.path.read_bytes()[:24]), (0xA1B2C3D4, 2, 4, 0, 0, 3, 1))
            self.assertEqual(
                c.query(
                    f"SELECT epoch_us(timestamp) t,captured_length,original_length,hex(packet_data) payload FROM read_pcap({quote(self.path)})"
                ),
                [{"t": "1000001", "captured_length": "3", "original_length": "5", "payload": "0080FF"}],
            )
            self.copy(
                c,
                "SELECT packet_data,link_type,original_length,captured_length,timestamp,42 extra FROM (" + ROW + ")",
                "LINKTYPE 1,SNAPLEN 10,USE_TMP_FILE true",
            )
            self.assertEqual(struct.unpack_from('<I', self.path.read_bytes(), 16)[0], 10)
            self.copy(c, ROW + " WHERE false", "LINKTYPE 101")
            self.assertEqual(len(self.path.read_bytes()), 24)
            self.assertEqual(struct.unpack_from('<II', self.path.read_bytes(), 16), (1, 101))
            self.copy(c, ROW.replace("3::UINTEGER", "0::UINTEGER").replace("from_hex('0080FF')", "from_hex('')"))
            self.assertEqual(len(self.path.read_bytes()), 40)
        self.clean()

    def test_independent_tcpdump_and_timestamp_boundaries(self):
        source = ROOT / "test/data/flows/tcp.pcap"
        with Connection(LIB) as c:
            self.copy(c, f"SELECT {FIELDS} FROM read_packets({quote(source)}) ORDER BY packet_number")
            baseline = subprocess.run(
                ["tcpdump", "-nn", "-tt", "-r", str(source)], capture_output=True, text=True, check=True
            )
            exported = subprocess.run(
                ["tcpdump", "-nn", "-tt", "-r", str(self.path)], capture_output=True, text=True, check=True
            )
            self.assertEqual(exported.stdout, baseline.stdout)
            self.assertTrue(exported.stdout.strip())
            for timestamp in [0, 999999, 1000000, 4294967295999999]:
                self.copy(c, ROW.replace("1000001", str(timestamp)))
                self.assertEqual(
                    c.query(f"SELECT epoch_us(timestamp) t FROM read_pcap({quote(self.path)})"), [{"t": str(timestamp)}]
                )
        self.clean()

    def test_order_across_threads_and_global_setting(self):
        for threads in [1, 2, 4, 8]:
            for preserve in [True, False]:
                with Connection(LIB) as c:
                    c.query(f"SET threads={threads};SET preserve_insertion_order={str(preserve).lower()}")
                    query = "SELECT make_timestamp(i) AS timestamp,4::UINTEGER captured_length,4::UINTEGER original_length,1::UINTEGER link_type,from_hex(lpad(hex(i),8,'0')) packet_data FROM range(5000) t(i) ORDER BY i DESC"
                    self.copy(c, query)
                    rows = c.query(
                        f"SELECT epoch_us(timestamp) t,hex(packet_data) payload FROM read_pcap({quote(self.path)}) ORDER BY packet_number"
                    )
                    self.assertEqual(rows, [{"t": str(i), "payload": f"{i:08X}"} for i in reversed(range(5000))])
        self.clean()

    def test_bad_rows_preserve_new_and_existing_outputs(self):
        bad = [
            ROW.replace("1000001", "-1"),
            ROW.replace("1000001", "4294967296000000"),
            ROW.replace("3::UINTEGER", "2::UINTEGER"),
            ROW.replace("5::UINTEGER", "2::UINTEGER"),
            ROW.replace("1::UINTEGER", "101::UINTEGER"),
        ]
        types = ["TIMESTAMP", "UINTEGER", "UINTEGER", "UINTEGER", "BLOB"]
        for col, typ in zip(FIELDS.split(','), types):
            bad.append(f"SELECT * REPLACE(NULL::{typ} AS {col}) FROM ({ROW})")
        with Connection(LIB) as c:
            for exists in [False, True]:
                for query in bad:
                    if self.path.exists():
                        self.path.unlink()
                    if exists:
                        self.path.write_bytes(b"existing destination")
                    with self.assertRaises(RuntimeError):
                        self.copy(c, query)
                    self.assertEqual(
                        self.path.read_bytes() if self.path.exists() else None,
                        b"existing destination" if exists else None,
                    )
                    self.clean()
                with self.assertRaises(RuntimeError):
                    self.copy(c, options="LINKTYPE 1,SNAPLEN 2")
            self.copy(c)
        self.clean()

    def test_options_and_binding_rejected_before_output(self):
        with Connection(LIB) as c:
            for option in [
                "LINKTYPE 65536",
                "LINKTYPE -1",
                "LINKTYPE NULL",
                "LINKTYPE 1.5",
                "LINKTYPE 1,SNAPLEN 0",
                "LINKTYPE 1,USE_TMP_FILE false",
                "LINKTYPE 1,PRESERVE_ORDER false",
                "LINKTYPE 1,WRITE_EMPTY_FILE false",
                "LINKTYPE 1,APPEND true",
                "LINKTYPE 1,OVERWRITE true",
                "LINKTYPE 1,PER_THREAD_OUTPUT true",
                "LINKTYPE 1,PARTITION_BY(link_type)",
                "LINKTYPE 1,FILE_SIZE_BYTES '1MB'",
                "LINKTYPE 1,RETURN_FILES true",
                "LINKTYPE 1,COMPRESSION gzip",
            ]:
                with self.assertRaises(RuntimeError, msg=option):
                    self.copy(c, options=option)
            for query in [
                ROW.replace("3::UINTEGER", "3::BIGINT"),
                ROW.replace("make_timestamp(1000001)", "make_timestamp(1000001)::TIMESTAMP_NS"),
                "SELECT 1 x",
                f"SELECT *,timestamp AS timestamp FROM ({ROW})",
            ]:
                with self.assertRaises(RuntimeError, msg=query):
                    self.copy(c, query)
            with self.assertRaises(RuntimeError):
                c.query(f"COPY ({ROW}) TO {quote(self.path)} (FORMAT PCAP)")
            for path in ["https://example.invalid/out.pcap", "s3://bucket/out.pcap", "/dev/null", str(self.root)]:
                with self.assertRaises(RuntimeError):
                    self.copy(c, path=path)
            fifo = self.root / 'pipe'
            os.mkfifo(fifo)
            with self.assertRaises(RuntimeError):
                self.copy(c, path=fifo)
            fifo.unlink()
        self.assertFalse(self.path.exists())
        self.clean()

    def test_source_error_prepared_and_existing_source_destination(self):
        with Connection(LIB) as c:
            self.copy(c)
            original = self.path.read_bytes()
            broken = self.root / 'broken.pcap'
            broken.write_bytes(b'broken')
            with self.assertRaises(RuntimeError):
                self.copy(c, f"SELECT {FIELDS} FROM read_pcap([{quote(self.path)},{quote(broken)}])")
            self.assertEqual(self.path.read_bytes(), original)
            self.clean()
            c.query(f"PREPARE export AS COPY ({ROW}) TO {quote(self.path)} (FORMAT PCAP,LINKTYPE 1)")
            for _ in range(3):
                c.query("EXECUTE export")
                self.clean()
            self.copy(c, f"SELECT {FIELDS} FROM read_pcap({quote(self.path)})")
            self.assertEqual(self.path.read_bytes(), original)
            c.query("BEGIN")
            self.copy(c, ROW.replace("1000001", "1000002"))
            c.query("ROLLBACK")
            self.assertNotEqual(self.path.read_bytes(), original)  # COPY files are not transactionally rolled back.
        self.clean()

    def test_concurrent_publishers_never_mix_records(self):
        def publish(tag):
            with Connection(LIB) as c:
                query = ROW.replace("from_hex('0080FF')", f"from_hex('{tag:06x}')") + " FROM range(2000)"
                self.copy(c, query)

        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(publish, range(4)))
        with Connection(LIB) as c:
            self.assertEqual(
                c.query(f"SELECT count(*) n,count(DISTINCT packet_data) d FROM read_pcap({quote(self.path)})"),
                [{"n": "2000", "d": "1"}],
            )
        self.clean()

    def test_disk_full_and_cancellation_preserve_destination(self):
        self.path.write_bytes(b"preserve")
        huge = ROW + " FROM range(10000000)"

        # RLIMIT_FSIZE produces a real short write/error, with SIGXFSZ ignored so
        # DuckDB can unwind and clean its owned staging file.
        def limits():
            import resource

            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            resource.setrlimit(resource.RLIMIT_FSIZE, (1024, 1024))

        sql = f"COPY ({huge}) TO {quote(self.path)} (FORMAT PCAP,LINKTYPE 1)"
        result = subprocess.run(
            [str(CLI), '-c', sql], cwd=ROOT, capture_output=True, text=True, preexec_fn=limits, timeout=20
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.path.read_bytes(), b"preserve")
        self.clean()
        process = subprocess.Popen(
            [str(CLI), '-c', sql], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and not list(self.root.glob('.packetquapture-*')):
                if process.poll() is not None:
                    break
                time.sleep(0.01)
            self.assertTrue(list(self.root.glob('.packetquapture-*')))
            process.send_signal(signal.SIGINT)
            process.communicate(timeout=10)
            self.assertNotEqual(process.returncode, 0)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()
        self.assertEqual(self.path.read_bytes(), b"preserve")
        self.clean()

    def test_sync_and_rename_failures_preserve_destination(self):
        self.path.write_bytes(b"preserve")
        sql = f"COPY ({ROW}) TO {quote(self.path)} (FORMAT PCAP,LINKTYPE 1)"
        for operation in ["fsync", "rename"]:
            trace = self.root / "fault.log"
            result = subprocess.run(
                [
                    "strace",
                    "-f",
                    "-qq",
                    "-o",
                    str(trace),
                    "-e",
                    f"inject={operation}:error=EIO:when=1",
                    str(CLI),
                    "-c",
                    sql,
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertNotEqual(result.returncode, 0, operation)
            self.assertIn("INJECTED", trace.read_text())
            self.assertEqual(self.path.read_bytes(), b"preserve")
            self.clean()

    def test_close_failure_is_not_published(self):
        self.path.write_bytes(b"preserve")
        sql = f"SET threads=1; COPY ({ROW}) TO {quote(self.path)} (FORMAT PCAP,LINKTYPE 1)"
        trace = self.root / "closes.log"
        subprocess.run(
            ["strace", "-qq", "-yy", "-e", "trace=close", "-o", str(trace), str(CLI), "-c", sql],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        closes = [line for line in trace.read_text().splitlines() if line.startswith("close(")]
        target = next(i + 1 for i, line in enumerate(closes) if ".packetquapture-" in line)
        self.path.write_bytes(b"preserve")
        result = subprocess.run(
            [
                "strace",
                "-qq",
                "-yy",
                "-e",
                "trace=close",
                "-e",
                f"inject=close:error=EIO:when={target}",
                "-o",
                str(trace),
                str(CLI),
                "-c",
                sql,
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PCAP staging close failed", result.stderr)
        injected = [line for line in trace.read_text().splitlines() if "INJECTED" in line]
        self.assertTrue(any(".packetquapture-" in line for line in injected))
        self.assertEqual(self.path.read_bytes(), b"preserve")
        self.clean()

    def test_cleanup_preserves_unowned_staging_files(self):
        sentinel = self.root / ".packetquapture-unowned.pcap.tmp"
        sentinel.write_bytes(b"not ours")
        with Connection(LIB) as c:
            with self.assertRaises(RuntimeError):
                self.copy(c, ROW.replace("1000001", "-1"))
            self.copy(c)
        self.assertEqual(sentinel.read_bytes(), b"not ours")
        sentinel.unlink()
        self.clean()

    def test_external_access_restriction(self):
        with Connection(LIB) as c:
            c.query("SET enable_external_access=false")
            with self.assertRaises(RuntimeError):
                self.copy(c)
        self.assertFalse(self.path.exists())
        self.clean()

    def test_remote_input_and_multiple_files(self):
        with Connection(LIB) as c:
            self.copy(c)
        with RangeServer({'/a.pcap': self.path}) as server, Connection(LIB) as c:
            configure(c, 'external_off', 4)
            out = self.root / 'remote.pcap'
            self.copy(
                c,
                f"SELECT {FIELDS} FROM read_pcap([{quote(server.url+'/a.pcap')},{quote(server.url+'/a.pcap')}]) ORDER BY filename,packet_number",
                path=out,
            )
            self.assertEqual(c.query(f"SELECT count(*) n FROM read_pcap({quote(out)})"), [{"n": "2"}])
        self.clean()


if __name__ == '__main__':
    unittest.main(verbosity=2)
