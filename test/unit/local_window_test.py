#!/usr/bin/env python3
"""Local record traversal: windowed reads for dense captures, exact skipping for sparse ones.

Dense captures must stop issuing one read and one seek per packet. Sparse captures must
keep reading only record headers, so a metadata-only scan never touches large payloads.
Linux only: the assertions are made against strace syscall records.
"""

import os
import re
import struct
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "build/release/duckdb"
HEADER = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
RECORD = struct.Struct("<IIII")
# Must track LOCAL_SKIP_THRESHOLD and LOCAL_READAHEAD_MAX_GAP in the extension.
THRESHOLD = 4 * 1024
READAHEAD_MAX_GAP = 256 * 1024


def write_capture(path, sizes):
    frame = bytes.fromhex("aabbccddeeff0011223344550800")
    with path.open("wb") as handle:
        handle.write(HEADER)
        for index, size in enumerate(sizes):
            payload = frame + bytes(size - len(frame))
            handle.write(RECORD.pack(index, 0, size, size))
            handle.write(payload)
    return path


class LocalWindowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="local-window-", dir=ROOT / "build")
        cls.root = Path(cls.directory.name)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def trace(self, path, sql, hints=None):
        """Return capture-file read bytes and read/seek counts for one query, and
        append the count of readahead hints to `hints` when given."""
        log = self.root / "trace.log"
        result = subprocess.run(
            [
                "strace",
                "-f",
                "-qq",
                "-yy",
                "-e",
                "trace=read,pread64,lseek,fadvise64",
                "-o",
                str(log),
                str(CLI),
                "-noheader",
                "-list",
                "-c",
                sql,
            ],
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = [line for line in log.read_text().splitlines() if str(path) in line]
        reads = [line for line in lines if re.search(r"\b(?:read|pread64)\(", line)]
        seeks = [line for line in lines if re.search(r"\blseek\(", line)]
        total = sum(int(match[1]) for line in reads if (match := re.search(r"= (\d+)$", line)) is not None)
        if hints is not None:
            hints.append(sum(1 for line in lines if re.search(r"\bfadvise64\(.*POSIX_FADV_WILLNEED", line)))
        log.unlink()
        return total, len(reads), len(seeks), result.stdout.strip()

    def test_dense_capture_is_windowed(self):
        """Payload gaps under the threshold are read through, not skipped one at a time."""
        packets = 20_000
        path = write_capture(self.root / "dense.pcap", [200] * packets)
        size = path.stat().st_size
        total, reads, seeks, answer = self.trace(path, f"SELECT count(*) FROM read_packets('{path}')")
        self.assertEqual(answer, str(packets))
        # One positioned read per window replaces a read and a seek per packet.
        self.assertLess(reads, packets // 10)
        self.assertEqual(seeks, 0)
        # Reading through the small gaps means the scan now covers the whole file.
        self.assertGreater(total, size * 0.9)

    def test_sparse_capture_still_skips_payloads(self):
        """Payload gaps over the threshold keep the scan off the payload bytes."""
        packets = 2_000
        payload = THRESHOLD * 4
        path = write_capture(self.root / "sparse.pcap", [payload] * packets)
        total, reads, _, answer = self.trace(path, f"SELECT count(*) FROM read_packets('{path}')")
        self.assertEqual(answer, str(packets))
        # The file header plus one record header per packet, and nothing else.
        self.assertEqual(total, len(HEADER) + RECORD.size * packets)
        self.assertLessEqual(reads, packets + 2)

    def test_sparse_capture_hints_readahead(self):
        """Moderate gaps are hinted to the kernel, which reads no bytes into the process;
        dense captures and wide gaps get no hint."""
        for name, payload, packets, hinted in [
            ("hinted", THRESHOLD * 4, 1_000, True),
            ("wide", READAHEAD_MAX_GAP * 2, 8, False),
            ("dense", 200, 1_000, False),
        ]:
            path = write_capture(self.root / f"{name}.pcap", [payload] * packets)
            hints = []
            total, _, _, answer = self.trace(path, f"SELECT count(*) FROM read_packets('{path}')", hints)
            self.assertEqual(answer, str(packets))
            if hinted:
                # A cold file is hinted once per 128 KiB piece, each piece once;
                # reads are still the headers alone. A warm file may skip hints.
                pieces = -(-path.stat().st_size // (128 * 1024))
                self.assertLessEqual(hints[0], pieces + 1)
                self.assertEqual(total, len(HEADER) + RECORD.size * packets)
            else:
                self.assertEqual(hints[0], 0, name)
        # Evicted first, the hinted capture gets hints covering it. Pages just
        # written are dirty and cannot be dropped until they are flushed.
        path = self.root / "hinted.pcap"
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
            os.posix_fadvise(descriptor, 0, 0, os.POSIX_FADV_DONTNEED)
        finally:
            os.close(descriptor)
        hints = []
        self.trace(path, f"SELECT count(*) FROM read_packets('{path}')", hints)
        self.assertGreater(hints[0], path.stat().st_size // (256 * 1024))

    def test_adapts_in_both_directions_within_one_file(self):
        """A capture that changes packet size switches strategy and still reads correctly."""
        sizes = [200] * 5_000 + [THRESHOLD * 4] * 500 + [200] * 5_000
        path = write_capture(self.root / "mixed.pcap", sizes)
        total, _, _, answer = self.trace(path, f"SELECT count(*) FROM read_packets('{path}')")
        self.assertEqual(answer, str(len(sizes)))
        # Well above headers alone, because the dense runs are windowed, and well below
        # the whole file, because the large payloads in the middle are still skipped.
        self.assertGreater(total, len(HEADER) + RECORD.size * len(sizes))
        self.assertLess(total, path.stat().st_size * 0.8)

    def test_results_match_a_non_seekable_source(self):
        """A pipe cannot seek or window; every projection must still agree with the file."""
        sizes = [200] * 500 + [THRESHOLD * 4] * 50
        path = write_capture(self.root / "parity.pcap", sizes)
        content = path.read_bytes()
        fifo = self.root / "parity.fifo"
        os.mkfifo(fifo)
        try:
            for projection in [
                "count(*)",
                "sum(captured_length)",
                "count(src_ip)",
                "sum(octet_length(packet_data))",
                "max(timestamp)",
            ]:

                def feed():
                    try:
                        with fifo.open("wb") as stream:
                            stream.write(content)
                    except BrokenPipeError:
                        pass

                feeder = threading.Thread(target=feed, daemon=True)
                feeder.start()
                piped = subprocess.run(
                    [
                        str(CLI),
                        "-noheader",
                        "-list",
                        "-c",
                        f"SELECT {projection} FROM read_packets('{fifo}')",
                    ],
                    text=True,
                    capture_output=True,
                    timeout=60,
                )
                feeder.join(timeout=10)
                self.assertFalse(feeder.is_alive(), "FIFO reader did not consume input")
                self.assertEqual(piped.returncode, 0, piped.stderr)
                expected = subprocess.run(
                    [
                        str(CLI),
                        "-noheader",
                        "-list",
                        "-c",
                        f"SELECT {projection} FROM read_packets('{path}')",
                    ],
                    text=True,
                    capture_output=True,
                    check=True,
                ).stdout.strip()
                self.assertEqual(piped.stdout.strip(), expected, projection)
        finally:
            fifo.unlink()


if __name__ == "__main__":
    unittest.main(verbosity=2)
