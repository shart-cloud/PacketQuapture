#!/usr/bin/env python3
"""Captures built to exhaust memory or abort a scan must stay bounded.

Each capture here is generated, not committed: they are large or only interesting for
the shape of their headers. Every query runs in its own CLI process, so its peak
memory can be read from that process alone.
"""

import os
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "build/release/duckdb"
PCAP_HEADER = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
PCAP_RECORD = struct.Struct("<IIII")
ETHERNET_IPV4 = bytes.fromhex("aabbccddeeff0011223344550800")


def run(sql):
    """Runs sql in a fresh CLI and returns (stdout, stderr, peak RSS in MiB)."""
    wrapper = (
        "import resource, subprocess, sys\n"
        "r = subprocess.run(sys.argv[1:], capture_output=True, text=True)\n"
        "sys.stdout.write(r.stdout)\n"
        "sys.stderr.write(r.stderr)\n"
        "print(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss // 1024, file=sys.stderr)\n"
    )
    result = subprocess.run(
        ["python3", "-I", "-c", wrapper, str(CLI), "-csv", "-noheader", "-c", sql],
        capture_output=True,
        text=True,
        timeout=300,
    )
    lines = result.stderr.strip().splitlines()
    return result.stdout.strip(), "\n".join(lines[:-1]), int(lines[-1])


def checksum(data):
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def tcp_syn(source_port, target_port):
    """An Ethernet/IPv4/TCP SYN from 10.0.0.1 to 10.0.0.2."""
    tcp = struct.pack("!HHIIBBHHH", source_port, target_port, 1000, 0, 5 << 4, 0x02, 1024, 0, 0)
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0, bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])
    )
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return ETHERNET_IPV4 + ip + tcp


class HostileCaptureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (ROOT / "build").mkdir(exist_ok=True)
        cls.directory = tempfile.TemporaryDirectory(prefix="hostile-capture-", dir=ROOT / "build")
        cls.root = Path(cls.directory.name)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def test_lying_record_length_is_not_allocated(self):
        # Two good records, then one whose header claims 200 MiB inside a file
        # with 20 bytes left. It is a truncated tail, and must cost no memory.
        path = self.root / "lying.pcap"
        frame = ETHERNET_IPV4 + bytes(46)
        with path.open("wb") as handle:
            handle.write(PCAP_HEADER)
            for index in range(2):
                handle.write(PCAP_RECORD.pack(index, 0, len(frame), len(frame)))
                handle.write(frame)
            claimed = 200 * 1024 * 1024
            handle.write(PCAP_RECORD.pack(9, 0, claimed, claimed))
            handle.write(b"x" * 20)
        out, err, peak = run(f"SELECT count(*), sum(octet_length(packet_data)) FROM read_packets('{path}')")
        self.assertEqual(out, "2,120", err)
        self.assertLess(peak, 128, "a claimed length must not be allocated before it is read")

    def test_interface_flood_is_capped_for_every_scan(self):
        # One section with 65,537 interface blocks. Plain packet scans were not
        # capped, so a file of nothing but these grew the list without bound.
        path = self.root / "interfaces.pcapng"
        section = struct.pack("<IIIHHqI", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28)
        interface = struct.pack("<IIHHII", 1, 20, 1, 0, 0, 20)
        with path.open("wb") as handle:
            handle.write(section)
            handle.write(interface * 65537)
        for function in ("read_pcap", "read_packets", "read_dns", "read_tls"):
            out, err, _ = run(f"SELECT count(*) FROM {function}('{path}')")
            self.assertIn("exceeds 65536 PCAPNG interfaces", err, function)
        # The cap is inclusive of a capture that only reaches it.
        with path.open("wb") as handle:
            handle.write(section)
            handle.write(interface * 65536)
        out, err, _ = run(f"SELECT count(*) FROM read_pcap('{path}')")
        self.assertEqual(out, "0", err)

    def test_port_scan_completes_flows(self):
        # A SYN scan opens more sessions than read_flows tracks. The query must
        # finish, with the sessions it had to give up labelled as such.
        path = self.root / "scan.pcap"
        with path.open("wb") as handle:
            handle.write(PCAP_HEADER)
            for port in range(1, 20001):
                frame = tcp_syn(40000, port)
                handle.write(PCAP_RECORD.pack(1700000000, port, len(frame), len(frame)))
                handle.write(frame)
        out, err, _ = run(f"SELECT count(*), count(*) FILTER (WHERE finalized_by = 'limit') FROM read_flows('{path}')")
        self.assertTrue(out, err)
        total, limited = (int(value) for value in out.split(","))
        self.assertEqual(total, 20000)
        self.assertGreater(limited, 0)


if __name__ == "__main__":
    if not CLI.exists():
        raise SystemExit(f"{CLI} is missing; build the release CLI first")
    os.chdir(ROOT)
    unittest.main()
