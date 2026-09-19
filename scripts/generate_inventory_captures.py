#!/usr/bin/env python3
"""Deterministic inventory framing fixtures; synthetic MIT packet data."""

import struct
from pathlib import Path
from generate_protocol_captures import eth, ip4, udp, pcap
from generate_test_captures import block

ROOT = Path(__file__).resolve().parents[1]


def main():
    out = ROOT / "test/data/inventory"
    out.mkdir(parents=True, exist_ok=True)
    pcap(out / "empty.pcap", [], link=101)
    shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))

    def idb(link):
        return block(1, struct.pack("<HHI", link, 0, 65535))

    packet = eth(ip4(udp(), 17))
    spb = block(3, struct.pack("<I", len(packet)) + packet + bytes((-len(packet)) % 4))
    (out / "all-null.pcapng").write_bytes(
        shb + idb(1) + spb + spb + idb(101) + shb + idb(276)
    )
    (out / "empty.pcapng").write_bytes(shb + idb(1) + idb(101) + shb + idb(276))


if __name__ == "__main__":
    main()
