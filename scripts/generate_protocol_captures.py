#!/usr/bin/env python3
"""Deterministic, project-authored MIT fixtures; no captured user traffic.

Headers are built directly from RFC 791/8200/9293/768 layouts. Checksums are
zero intentionally: the decoder extracts headers without verifying checksums.
"""

from pathlib import Path
import struct

from generate_test_captures import block

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "test/data/protocols"


def tcp(offset=5):
    return struct.pack(
        "!HHIIBBHHH", 12345, 443, 0x01020304, 0x05060708, offset << 4, 0x12, 4096, 0, 0
    )


def udp(length=11):
    return struct.pack("!HHHH", 5353, 53, length, 0) + b"abc"


def ip4(payload, protocol=6, fragment=0, ihl=5, total=None):
    options = b"\x01" * max(0, (ihl - 5) * 4)
    return (
        struct.pack(
            "!BBHHHBBH4s4s",
            0x40 | ihl,
            0,
            total if total is not None else 20 + len(options) + len(payload),
            42,
            fragment,
            64,
            protocol,
            0,
            bytes([192, 0, 2, 1]),
            bytes([198, 51, 100, 2]),
        )
        + options
        + payload
    )


def ip6(payload, protocol=17):
    return (
        struct.pack(
            "!IHBB16s16s",
            6 << 28,
            len(payload),
            protocol,
            32,
            bytes.fromhex("20010db8000000000000000000000001"),
            bytes.fromhex("20010db8000000000000000000000002"),
        )
        + payload
    )


def eth(payload, kind=0x0800, tags=()):
    prefix = bytes.fromhex("aabbccddeeff001122334455")
    for index, tag in enumerate(tags):
        prefix += struct.pack("!HH", 0x88A8 if index == 0 else 0x8100, tag)
    return prefix + struct.pack("!H", kind) + payload


def pcap(path, packets, link=1):
    content = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, link)
    for packet in packets:
        content += (
            struct.pack("<IIII", 1700000000, 0, len(packet), len(packet)) + packet
        )
    path.write_bytes(content)


def main():
    DATA.mkdir(parents=True, exist_ok=True)
    tcp_packet = eth(ip4(tcp() + b"hello"))
    udp_packet = eth(ip4(udp(), 17), tags=(100, 200))
    v6_packet = eth(ip6(udp()), 0x86DD)
    extension = bytes([17, 0]) + bytes(6)
    fragment = lambda offset: struct.pack("!BBHI", 17, 0, offset, 99)
    packets = [
        tcp_packet,
        udp_packet,
        v6_packet,
        eth(ip6(extension + udp(), 0), 0x86DD),
        eth(ip4(tcp(), fragment=0x2000)),
        eth(ip4(tcp(), fragment=1)),
        eth(ip6(fragment(1) + udp(), 44), 0x86DD),
        eth(ip6(fragment(8) + udp(), 44), 0x86DD),
        eth(ip6(fragment(0) + udp(), 44), 0x86DD),
        eth(ip4(tcp(), ihl=6)),
        eth(ip4(tcp(offset=6) + bytes(4))),
        tcp_packet[:-3],  # Intact headers and two captured payload bytes.
        eth(ip4(udp(length=8), 17)) + bytes(20),  # UDP/IP/Ethernet padding is excluded.
        eth(b"arp", 0x0806),
        b"\x00" * 13,
        bytes.fromhex("aabbccddeeff001122334455810000"),
        eth(ip4(tcp())[:19]),
        eth(ip4(tcp(), ihl=4)),
        eth(ip4(tcp(), total=19)),
        eth(ip4(tcp(offset=4))),
        eth(ip4(tcp()[:19])),
        eth(ip4(udp(length=7), 17)),
        eth(ip4(udp(length=100), 17)),
        eth(ip4(udp()[:7], 17)),
        eth(ip6(udp())[:39], 0x86DD),
        eth(ip6(bytes([17, 3]) + bytes(6), 0), 0x86DD),
        eth(ip6(bytes([0, 0]) + bytes(6), 0), 0x86DD),
        eth(ip6(bytes([0, 0]) + bytes(6), 50), 0x86DD),
        eth(ip6(b"", 59), 0x86DD),
        eth(ip6(bytes([0, 0]) * 68, 0), 0x86DD),  # Exceeds extension walk limit.
        eth(ip4(udp(), 17), tags=tuple(range(9))),
        eth(ip4(bytes(8), 1)),
        eth(ip6(bytes([17, 1]) + bytes(10) + udp(), 51), 0x86DD),
        eth(ip6(bytes([17, 0]) + bytes(6) + udp(), 51), 0x86DD),
    ]
    pcap(DATA / "ethernet.pcap", packets)
    pcap(DATA / "raw.pcap", [ip4(udp(), 17)], 101)
    pcap(DATA / "ipv4.pcap", [ip4(udp(), 17)], 228)
    pcap(DATA / "ipv6.pcap", [ip6(udp())], 229)
    pcap(DATA / "sll.pcap", [bytes(14) + b"\x08\x00" + ip4(udp(), 17)], 113)
    pcap(DATA / "sll2.pcap", [b"\x86\xdd" + bytes(18) + ip6(udp())], 276)
    pcap(DATA / "unknown.pcap", [tcp_packet], 999)
    section = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    interface = block(1, struct.pack("<HHI", 1, 0, 65535))
    body = struct.pack("<IIIII", 0, 0, 0, len(tcp_packet), len(tcp_packet))
    (DATA / "ethernet.pcapng").write_bytes(
        section + interface + block(6, body + tcp_packet + bytes(-len(tcp_packet) % 4))
    )
    malformed = ROOT / "test/data/malformed"
    malformed.mkdir(parents=True, exist_ok=True)
    pcap(malformed / "payload.pcap", [tcp_packet])
    bad = malformed / "payload.pcap"
    bad.write_bytes(bad.read_bytes()[:-1])
    complete = (DATA / "ethernet.pcapng").read_bytes()
    (malformed / "payload.pcapng").write_bytes(complete[:-8])
    (malformed / "trailer.pcapng").write_bytes(complete[:-1])
    flags = ROOT / "test/data/flags"
    flags.mkdir(parents=True, exist_ok=True)
    flag_packets = []
    for bits in range(256):
        segment = bytearray(tcp())
        segment[13] = bits
        flag_packets.append(eth(ip4(bytes(segment))))
    pcap(flags / "all_flags.pcap", flag_packets)
    # More than two DuckDB vectors, alternating valid and invalid values.
    pcap(DATA / "chunks.pcap", [tcp_packet, b"\x00", v6_packet] * 1500)


if __name__ == "__main__":
    main()
