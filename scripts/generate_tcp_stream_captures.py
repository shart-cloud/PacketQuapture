#!/usr/bin/env python3
"""Deterministic MIT non-DNS TCP fixtures for the shared transport engine."""

from pathlib import Path
from generate_reassembly_captures import segment
from generate_protocol_captures import pcap

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "test/data/tcp_streams"


def main():
    DATA.mkdir(parents=True, exist_ok=True)
    packets = []

    def add(port, seq, data=b"", flags=0x18, **kwargs):
        packets.append(segment(port, seq, data, flags, **kwargs))

    add(50000, 100, flags=2, server_port=80)
    add(50000, 111, b"/1.1\r\nHost: example.com\r\n\r\n", server_port=80)
    add(50000, 101, b"GET / HTTP", server_port=80)
    add(50000, 111, b"/1.1\r\nHost: example.com\r\n\r\n", server_port=80)
    add(50001, 200, flags=2, server_port=443)
    add(50001, 201, bytes.fromhex("1603030005ff00018042"), server_port=443)
    add(50002, 105, b"EF", server_port=8080)
    add(50002, 101, b"ABCD", server_port=8080)
    add(50003, 100, flags=2, server_port=22)
    add(50003, 101, b"AB", server_port=22)
    add(50003, 105, b"EF", server_port=22)
    add(50004, 100, flags=2, server_port=12345)
    add(50004, 101, b"XYZ", server_port=12345)
    add(50004, 102, b"!", server_port=12345)
    add(50005, 100, flags=2, server_port=80)
    add(50005, 101, b"abc", server_port=80)
    add(50005, 104, flags=1, server_port=80)
    add(50006, 100, flags=2, server_port=80)
    add(50006, 101, b"xyz", server_port=80)
    add(50006, 104, flags=4, server_port=80)
    pcap(DATA / "protocols.pcap", packets)
    # Each direction finalizes with RST, exceeding one DuckDB output chunk without exhausting active-flow limits.
    many = []
    for i in range(2500):
        many += [
            segment(51000, i * 100, flags=2, server_port=80),
            segment(51000, i * 100 + 1, b"abc", server_port=80),
            segment(51000, i * 100 + 4, flags=4, server_port=80),
        ]
    pcap(DATA / "chunks.pcap", many)


if __name__ == "__main__":
    main()
