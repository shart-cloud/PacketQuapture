#!/usr/bin/env python3
"""Project-authored MIT TLS fixtures, generated from RFC 8446 record layouts."""

from pathlib import Path
import struct
from generate_protocol_captures import eth, ip4, pcap

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "test/data/tls"


def record(body, kind=22, version=0x0301):
    return struct.pack("!BHH", kind, version, len(body)) + body


def handshake(body, kind=1):
    return struct.pack("!B", kind) + struct.pack("!I", len(body))[1:] + body


def extension(kind, body):
    return struct.pack("!HH", kind, len(body)) + body


def server_name(host):
    entry = struct.pack("!BH", 0, len(host)) + host.encode()
    return extension(0, struct.pack("!H", len(entry)) + entry)


def client_hello(extensions=b"", session_id=b"", version=0x0303):
    body = struct.pack("!H", version) + bytes(range(32))
    body += struct.pack("!B", len(session_id)) + session_id
    body += struct.pack("!H", 2) + struct.pack("!H", 0x1301)  # cipher_suites
    body += struct.pack("!B", 1) + b"\0"  # legacy_compression_methods
    body += struct.pack("!H", len(extensions)) + extensions
    return handshake(body, 1)


def server_hello(version=0x0303):
    body = struct.pack("!H", version) + bytes(range(32))
    body += struct.pack("!B", 0)  # legacy_session_id_echo
    body += struct.pack("!H", 0x1301) + struct.pack("!B", 0)
    body += struct.pack("!H", 0)
    return handshake(body, 2)


def tcp(payload, src=51000, dst=443, seq=1):
    return struct.pack("!HHIIBBHHH", src, dst, seq, 1, 0x50, 0x18, 4096, 0, 0) + payload


def packet(payload, src=51000, dst=443, seq=1):
    return eth(ip4(tcp(payload, src, dst, seq)))


def main():
    DATA.mkdir(parents=True, exist_ok=True)

    # A ClientHello carrying SNI, its ServerHello, and an application-data record.
    hello = record(client_hello(server_name("example.com")))
    packets = [
        packet(hello),
        packet(record(server_hello()), src=443, dst=51000),
        packet(record(b"\x01" * 48, kind=23, version=0x0303)),
    ]
    pcap(DATA / "handshake.pcap", packets)

    # A ClientHello with extensions but no server_name: SNI is absent, not truncated.
    no_sni = record(client_hello(extension(0x002B, b"\x02\x03\x04")))
    pcap(DATA / "no_sni.pcap", [packet(no_sni)])

    # A ClientHello with no extensions at all.
    pcap(DATA / "no_extensions.pcap", [packet(record(client_hello()))])

    # A ClientHello padded past one record, so the SNI does not fit this packet.
    big = client_hello(server_name("split.example.com") + extension(0x0015, b"\0" * 900))
    first = big[:400]
    pcap(
        DATA / "truncated.pcap",
        [packet(struct.pack("!BHH", 22, 0x0301, len(first)) + first)],
    )

    # Traffic that is not TLS at all, on the TLS port and on another port.
    pcap(
        DATA / "not_tls.pcap",
        [packet(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", dst=80), packet(b"\xff" * 64)],
    )

    # A handshake on a non-standard port: detection is by record shape, not port.
    pcap(DATA / "alt_port.pcap", [packet(hello, dst=8443)])


if __name__ == "__main__":
    main()
