#!/usr/bin/env python3
"""MIT synthetic TCP DNS streams; no captured traffic or external fixtures."""

from pathlib import Path
import struct
from generate_protocol_captures import eth, ip4, ip6, pcap
from generate_test_captures import block
from generate_dns_captures import name, header

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "test/data/reassembly"


def segment(
    port, seq, data=b"", flags=0x18, reverse=False, version=4, tags=(), server_port=53
):
    src, dst = (server_port, port) if reverse else (port, server_port)
    tcp = (
        struct.pack(
            "!HHIIBBHHH", src, dst, seq & 0xFFFFFFFF, 0, 0x50, flags, 4096, 0, 0
        )
        + data
    )
    network = bytearray(ip4(tcp) if version == 4 else ip6(tcp, 6))
    if reverse:
        first, second, length = (12, 16, 4) if version == 4 else (8, 24, 16)
        left, right = bytes(network[first : first + length]), bytes(
            network[second : second + length]
        )
        network[first : first + length], network[second : second + length] = right, left
    return eth(bytes(network), 0x0800 if version == 4 else 0x86DD, tags=tags)


def main():
    DATA.mkdir(parents=True, exist_ok=True)
    query = header() + name("example.com") + struct.pack("!HH", 1, 1)
    response = header(0x8180) + name("example.com") + struct.pack("!HH", 1, 1)
    frame = struct.pack("!H", len(query)) + query
    reply = struct.pack("!H", len(response)) + response
    packets = []

    def add(port, seq, data=b"", flags=0x18, **kwargs):
        packets.append(segment(port, seq, data, flags, **kwargs))

    def syn(port, seq, **kwargs):
        add(port, seq, flags=2, **kwargs)

    syn(40000, 100)
    add(40000, 101, frame[:1])
    add(40000, 102, frame[1:11])
    add(40000, 112, frame[11:])
    syn(40001, 200)
    add(40001, 211, frame[10:])
    add(40001, 201, frame[:10])
    add(40001, 211, frame[10:])
    syn(40002, 300)
    add(40002, 301, frame + reply + frame)
    syn(40003, 400)
    add(40003, 401, frame[:20])
    add(40003, 411, frame[10:])
    add(40003, 401, frame[:20])
    syn(40004, 500)
    add(40004, 501, frame)
    add(40004, 511, bytes([frame[10] ^ 1]) + frame[11:])
    syn(40005, 600)
    add(40005, 601, frame[:10])
    add(40005, 613, frame[12:])
    syn(40006, 700)
    packets.append(segment(40006, 701, frame)[:-4])
    add(40007, 801, frame)
    syn(40008, 0xFFFFFFF8)
    add(40008, 0xFFFFFFF9, frame[:10])
    add(40008, 3, frame[10:])
    add(40009, 900, frame, flags=2)
    add(40009, 901 + len(frame), flags=1)
    syn(40010, 10)
    add(40010, 11, frame)
    syn(40010, 200)
    add(40010, 201, frame)
    syn(40011, 100)
    add(40011, 101, frame[:9])
    add(40011, 110, flags=4)
    syn(40012, 100)
    add(40012, 200, flags=0x12, reverse=True)
    add(40012, 101, frame)
    add(40012, 201, reply[:7], reverse=True)
    add(40012, 208, reply[7:], reverse=True)
    syn(40013, 100)
    add(40013, 101, frame)
    add(40013, 101 + len(frame) + 5, flags=1)
    syn(40014, 100)
    add(40014, 101, frame[:1])
    syn(40015, 100)
    add(40015, 101, b"\0\0")
    syn(40016, 100)
    add(40016, 101 + 1024 * 1024, frame)
    add(40017, 109, frame[8:])
    syn(40017, 100)
    add(40017, 101, frame[:8])
    syn(40018, 100, version=6)
    add(40018, 110, frame[9:], version=6)
    add(40018, 101, frame[:9], version=6)
    syn(40019, 100, tags=(100,))
    add(40019, 101, frame, tags=(100,))
    syn(40019, 100, tags=(200,))
    add(40019, 101, reply, tags=(200,))
    pcap(DATA / "streams.pcap", packets)
    pcap(
        DATA / "part_a.pcap",
        [segment(41000, 100, flags=2), segment(41000, 101, frame[:10])],
    )
    pcap(DATA / "part_b.pcap", [segment(41000, 111, frame[10:])])
    # Same addresses/ports on two PCAPNG interfaces must not complete each other's gaps.
    section = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    interface = block(1, struct.pack("<HHI", 1, 0, 65535))
    content = section + interface + interface
    for iface, packet in [
        (0, segment(42000, 100, flags=2)),
        (1, segment(42000, 100, flags=2)),
        (0, segment(42000, 101, frame[:10])),
        (1, segment(42000, 111, frame[10:])),
    ]:
        body = (
            struct.pack("<IIIII", iface, 0, 0, len(packet), len(packet))
            + packet
            + bytes(-len(packet) % 4)
        )
        content += block(6, body)
    (DATA / "interfaces.pcapng").write_bytes(content)
    malformed = header(q=4097)
    malformed_frame = struct.pack("!H", len(malformed)) + malformed
    pcap(
        DATA / "malformed_dns.pcap",
        [segment(44000, 100, flags=2), segment(44000, 101, malformed_frame)],
    )
    # A query that pauses for two seconds mid-message: whole under the default idle
    # timeout, split in two by a one-second tcp_idle_timeout.
    pcap(
        DATA / "paused.pcap",
        [
            (1700000000, segment(45000, 100, flags=2)),
            (1700000000, segment(45000, 101, frame[:10])),
            (1700000002, segment(45000, 111, frame[10:])),
        ],
    )
    # More than one output vector from one persistent stream, without fragmenting the fixture.
    pcap(
        DATA / "chunks.pcap",
        [segment(43000, 100, flags=2)]
        + [segment(43000, 101 + i * len(frame), frame) for i in range(2500)],
    )


if __name__ == "__main__":
    main()
