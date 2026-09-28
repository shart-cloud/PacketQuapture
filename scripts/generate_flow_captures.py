#!/usr/bin/env python3
"""Deterministic session fixtures, synthetic MIT packet headers."""

import struct
from pathlib import Path
from generate_protocol_captures import eth, ip4, udp
from generate_reassembly_captures import segment
from generate_test_captures import block

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "test/data/flows"


def tcp(seq, flags, reverse=False, ack=0):
    frame = bytearray(
        segment(50000, seq, flags=flags, reverse=reverse, server_port=443)
    )
    frame[42:46] = struct.pack("!I", ack)
    return bytes(frame)


def write(path, records):
    data = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for micros, frame in records:
        sec, sub = divmod(micros, 1000000)
        data += struct.pack("<IIII", sec, sub, len(frame), len(frame)) + frame
    path.write_bytes(data)


def analytics_datagram(source_port, service_port, payload_size=3):
    payload = bytes([service_port & 0xFF]) * payload_size
    header = struct.pack("!HHHH", source_port, service_port, 8 + payload_size, 0)
    return eth(ip4(header + payload, 17))


def series(start, service_port, intervals, payload_sizes=None):
    timestamps = [start]
    for interval in intervals:
        timestamps.append(timestamps[-1] + interval * 1_000_000)
    sizes = payload_sizes or [3] * len(timestamps)
    return [
        (
            timestamp,
            analytics_datagram(40000 + index, service_port, sizes[index]),
        )
        for index, timestamp in enumerate(timestamps)
    ]


def main():
    DATA.mkdir(parents=True, exist_ok=True)
    handshake = [
        (0, tcp(100, 2)),
        (1, tcp(100, 2)),
        (2, tcp(200, 0x12, True, 101)),
        (3, tcp(101, 0x10, ack=201)),
        (4, tcp(101, 1)),
        (5, tcp(201, 0x10, True, 102)),
        (6, tcp(100, 2)),
        (7, tcp(200, 4, True)),
        (8, tcp(101, 0x10)),
    ]
    write(DATA / "tcp.pcap", handshake)
    datagram = eth(ip4(udp(), 17))
    write(
        DATA / "udp.pcap",
        [
            (0, datagram),
            (10, datagram),
            (21, datagram),
            (19, datagram),
            (40, eth(b"arp", 0x0806)),
            (20, datagram),
        ],
    )
    # Eight equal-size UDP observations at a fixed five-minute cadence. The
    # one-minute idle timeout makes each packet a separate connection fact.
    beacon_start = 1_700_000_000 * 1_000_000
    write(
        DATA / "analytics.pcap",
        [(beacon_start + index * 300_000_000, datagram) for index in range(8)],
    )
    distributions = []
    distributions += series(
        beacon_start, 54, [240, 360, 270, 330, 240, 360, 300]
    )
    distributions += series(
        beacon_start, 55, [73, 509, 181, 887, 293, 641, 419]
    )
    distributions += series(beacon_start, 56, [1, 1, 1, 897, 1, 1, 1])
    distributions += series(
        beacon_start,
        57,
        [300] * 7,
        [3, 303, 3, 303, 3, 303, 3, 303],
    )
    write(DATA / "analytics_distributions.pcap", distributions)
    write(
        DATA / "simultaneous_open.pcap",
        [(beacon_start, tcp(100, 2)), (beacon_start + 1, tcp(200, 2, True))],
    )
    shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = block(1, struct.pack("<HHI", 1, 0, 65535))

    def epb(t, interface=0):
        return block(
            6,
            struct.pack("<IIIII", interface, 0, t, len(datagram), len(datagram))
            + datagram
            + bytes((-len(datagram)) % 4),
        )

    spb = block(
        3, struct.pack("<I", len(datagram)) + datagram + bytes((-len(datagram)) % 4)
    )
    (DATA / "scopes.pcapng").write_bytes(
        shb
        + idb
        + idb
        + epb(0)
        + spb
        + epb(1000, 1)
        + epb(1)
        + shb
        + idb
        + epb(0)
        + shb
        + idb
    )


if __name__ == "__main__":
    main()
