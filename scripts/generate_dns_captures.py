#!/usr/bin/env python3
"""Project-authored MIT DNS fixtures, generated from RFC 1035 header layouts."""

from pathlib import Path
import ipaddress
import struct
from generate_protocol_captures import eth, ip4, ip6, pcap
from generate_test_captures import block

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "test/data/dns"


def name(value):
    return (
        b"".join(bytes([len(label)]) + label.encode() for label in value.split("."))
        + b"\0"
    )


def header(flags=0x100, q=1, a=0, ns=0, ar=0):
    return struct.pack("!6H", 1234, flags, q, a, ns, ar)


def identified_header(identifier, flags=0x100, q=1, a=0, ns=0, ar=0):
    return struct.pack("!6H", identifier, flags, q, a, ns, ar)


def rr(kind, data, owner=b"\xc0\x0c", ttl=300):
    return owner + struct.pack("!HHIH", kind, 1, ttl, len(data)) + data


def udp(message, src=53000, dst=53):
    return struct.pack("!HHHH", src, dst, 8 + len(message), 0) + message


def tcp(message):
    prefix = struct.pack("!HHIIBBHHH", 53000, 53, 1, 1, 0x50, 0x18, 4096, 0, 0)
    return prefix + struct.pack("!H", len(message)) + message


def addressed_ip4(payload, src, dst):
    return struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        42,
        0,
        64,
        17,
        0,
        ipaddress.ip_address(src).packed,
        ipaddress.ip_address(dst).packed,
    ) + payload


def opaque_tcp(payload, src_port, dst_port):
    return struct.pack(
        "!HHIIBBHHH", src_port, dst_port, 1, 1, 0x50, 0x18, 4096, 0, 0
    ) + payload


def analytics_exchange(timestamp, identifier, qname, client, resolver, port, rcode):
    question = name(qname) + struct.pack("!HH", 1, 1)
    query = identified_header(identifier) + question
    answers = 0 if rcode else 1
    response = identified_header(identifier, 0x8180 | rcode, a=answers) + question
    if answers:
        response += rr(1, bytes([203, 0, 113, 9]))
    return [
        (timestamp, eth(addressed_ip4(udp(query, port, 53), client, resolver))),
        (timestamp + 1, eth(addressed_ip4(udp(response, 53, port), resolver, client))),
    ]


def main():
    DATA.mkdir(parents=True, exist_ok=True)
    question = name("example.com") + struct.pack("!HH", 1, 1)
    query = header() + question
    response = header(0x8180, a=1) + question + rr(1, bytes([192, 0, 2, 5]))
    v6 = (
        header(0x8180, a=1)
        + name("example.com")
        + struct.pack("!HH", 28, 1)
        + rr(28, bytes.fromhex("20010db8000000000000000000000005"))
    )
    cname = (
        header(0x8180, a=2)
        + question
        + rr(5, b"\x03www\xc0\x0c")
        + rr(1, bytes([192, 0, 2, 9]), owner=b"\x03www\xc0\x0c")
    )
    negative = header(0x8183) + question
    sections = (
        header(0x8180, a=1, ns=1, ar=1)
        + question
        + rr(65000, b"opaque")
        + rr(2, b"\x02ns\xc0\x0c")
        + rr(1, bytes([192, 0, 2, 53]), owner=b"\x02ns\xc0\x0c")
    )
    messages = [
        query,
        response,
        v6,
        cname,
        negative,
        sections,
        header(q=0),
        header(q=2) + question + b"\xc0\x0c\x00\x1c\x00\x01",
        header(0x8380) + question,
        header() + b"\xc0\x0c\x00\x01\x00\x01",  # Pointer cycle.
        header() + b"\xc0\xff\x00\x01\x00\x01",  # Out-of-bounds pointer.
        query[:-1],
        response[:-1],
        header(q=4097),
        header() + b"\x40" + b"x" * 64 + b"\0\0\1\0\1",
        header() + b"".join(b"\x3f" + b"a" * 63 for _ in range(4)) + b"\0\0\1\0\1",
        header() + b"\x03a\0b\0\0\1\0\1",
        query + b"trailing",
        header(0x8180, a=1) + question + rr(1, b"\x01\x02\x03"),
    ]
    packets = [
        eth(
            ip4(
                udp(
                    message,
                    53 if i in (1, 2, 3, 4, 5) else 53000,
                    53000 if i in (1, 2, 3, 4, 5) else 53,
                ),
                17,
            )
        )
        for i, message in enumerate(messages)
    ]
    packets += [
        eth(ip4(tcp(query))),
        eth(ip4(tcp(query)[:-1])),
        eth(ip4(tcp(query) + struct.pack("!H", len(query)) + query)),
        eth(ip6(udp(query)), 0x86DD),
        eth(ip4(udp(query), 17))[:-1],
        eth(ip4(udp(query, dst=9999), 17)),
        eth(ip4(udp(query), 17, fragment=0x2000)),
    ]
    pcap(DATA / "messages.pcap", packets)
    pcap(DATA / "chunks.pcap", [packets[0], packets[9], packets[1]] * 1500)
    for i, message in enumerate(messages):
        (DATA / f"message_{i:02d}.bin").write_bytes(message)
    section = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    interface = block(1, struct.pack("<HHI", 1, 0, 65535))
    packet = packets[1]
    body = (
        struct.pack("<IIIII", 0, 0, 0, len(packet), len(packet))
        + packet
        + bytes(-len(packet) % 4)
    )
    (DATA / "response.pcapng").write_bytes(section + interface + block(6, body))

    analytics = []
    tunnel_alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    for i in range(24):
        label = "".join(tunnel_alphabet[(i * 11 + j * 7) % len(tunnel_alphabet)] for j in range(32))
        analytics += analytics_exchange(
            1_700_100_000 + i * 2,
            2000 + i,
            f"{label}.example.com",
            "192.0.2.10",
            "198.51.100.53",
            40000 + i,
            3,
        )
    ordinary_names = ["www.example.org", "api.example.org", "static.example.org", "mail.example.org"]
    for i in range(20):
        analytics += analytics_exchange(
            1_700_100_000 + i * 30,
            3000 + i,
            ordinary_names[i % len(ordinary_names)],
            "192.0.2.20",
            "198.51.100.53",
            41000 + i,
            0,
        )
    pcap(DATA / "tunnel_analytics.pcap", analytics)
    opaque_query = identified_header(4000) + name("opaque.example") + struct.pack("!HH", 1, 1)
    pcap(
        DATA / "encrypted_dns_opaque.pcap",
        [
            eth(addressed_ip4(opaque_tcp(opaque_query, 42000, 443), "192.0.2.30", "198.51.100.10")),
            eth(
                addressed_ip4(
                    opaque_tcp(struct.pack("!H", len(opaque_query)) + opaque_query, 42001, 853),
                    "192.0.2.30",
                    "198.51.100.11",
                )
            ),
        ],
    )


if __name__ == "__main__":
    main()
