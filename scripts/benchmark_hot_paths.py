#!/usr/bin/env python3
"""Per-packet and per-row CPU cost of the readers, for before/after comparisons.

Builds one synthetic capture in the ignored build directory: TCP connections that
open, exchange a TLS ClientHello and ServerHello, carry data and close, half of them
VLAN-tagged, interleaved with UDP DNS queries and responses. Each query runs on one
thread, warm, and reports the best of --trials runs, so the numbers measure CPU per
packet rather than I/O or scheduling.

    python3 scripts/benchmark_hot_paths.py [--connections N] [--trials N] [--json PATH] [--cli PATH ...]

With several --cli binaries, trials alternate between them, so machine noise
falls on each binary alike and their times can be compared.
"""

import argparse
import json
import struct
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "build/release/duckdb"
CAPTURE = ROOT / "build/hot_paths.pcap"

QUERIES = {
    "read_pcap_count": "SELECT count(*) FROM read_pcap('{path}')",
    "read_packets_all": "SELECT count(*), sum(hash(COLUMNS(*))) FROM read_packets('{path}')",
    "read_packets_filtered": "SELECT count(*) FROM read_packets('{path}') WHERE dst_port = 443",
    "read_flows_all": "SELECT count(*), sum(hash(COLUMNS(*))) FROM read_flows('{path}')",
    "read_tcp_streams": "SELECT count(*), sum(captured_bytes) FROM read_tcp_streams('{path}')",
    "read_tls_all": "SELECT count(*), sum(hash(COLUMNS(*))) FROM read_tls('{path}')",
    "read_dns_all": "SELECT count(*), sum(hash(COLUMNS(*))) FROM read_dns('{path}')",
}


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ethernet(vlan, ethertype):
    header = bytes.fromhex("aabbccddeeff001122334455")
    if vlan:
        return header + struct.pack("!HHH", 0x8100, vlan, ethertype)
    return header + struct.pack("!H", ethertype)


def ipv4(source, target, protocol, payload):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64, protocol, 0, source, target)
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:] + payload


def tcp(source_port, target_port, sequence, acknowledgement, flags, payload=b""):
    return struct.pack("!HHIIBBHHH", source_port, target_port, sequence, acknowledgement, 5 << 4, flags, 65535, 0,
                       0) + payload


def record(body):
    return struct.pack("!BHH", 22, 0x0301, len(body)) + body


def hello(kind, suites, extensions):
    body = struct.pack("!H", 0x0303) + bytes(32) + b"\0"
    if kind == 1:
        body += struct.pack("!H", 2 * len(suites)) + b"".join(struct.pack("!H", s) for s in suites) + b"\x01\x00"
    else:
        body += struct.pack("!H", suites[0]) + b"\x00"
    body += struct.pack("!H", len(extensions)) + extensions
    return bytes([kind]) + len(body).to_bytes(3, "big") + body


def extension(kind, body):
    return struct.pack("!HH", kind, len(body)) + body


def client_hello(index):
    name = f"host{index}.example.com".encode()
    sni = extension(0, struct.pack("!HBH", len(name) + 3, 0, len(name)) + name)
    groups = extension(10, struct.pack("!H", 6) + struct.pack("!HHH", 0x001D, 0x0017, 0x0018))
    signatures = extension(13, struct.pack("!H", 8) + struct.pack("!HHHH", 0x0403, 0x0804, 0x0401, 0x0503))
    alpn = extension(16, struct.pack("!H", 12) + b"\x02h2\x08http/1.1")
    versions = extension(43, b"\x04\x03\x04\x03\x03")
    suites = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0x009C]
    return record(hello(1, suites, sni + groups + signatures + alpn + versions))


def server_hello():
    return record(hello(2, [0x1301], extension(43, b"\x03\x04")))


def dns(identifier, response):
    flags = 0x8180 if response else 0x0100
    header = struct.pack("!HHHHHH", identifier, flags, 1, 1 if response else 0, 0, 0)
    question = b"\x03www\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + bytes([192, 0, 2, identifier % 250])
    return header + question + (answer if response else b"")


def build(connections):
    packets = []
    timestamp = 1700000000_000000
    for index in range(connections):
        # One connection a second keeps ~600 directions live inside the 5-minute
        # idle timeout, under the reassembler's 1,024, as in an ordinary capture.
        timestamp = 1700000000_000000 + index * 1000000
        vlan = 100 + index % 4 if index % 2 else 0
        client = bytes([10, (index >> 16) & 255, (index >> 8) & 255, index & 255])
        server = bytes([192, 0, 2, 1 + index % 200])
        client_port = 1024 + index % 60000
        c, s = 1000, 5000

        def send(reverse=False, flags=0x18, payload=b""):
            nonlocal timestamp
            source, target = (server, client) if reverse else (client, server)
            ports = (443, client_port) if reverse else (client_port, 443)
            sequence, acknowledgement = (s, c) if reverse else (c, s)
            segment = tcp(ports[0], ports[1], sequence, acknowledgement, flags, payload)
            packets.append((timestamp, ethernet(vlan, 0x0800) + ipv4(source, target, 6, segment)))
            timestamp += 50

        send(flags=0x02)
        c += 1
        send(reverse=True, flags=0x12)
        s += 1
        send(flags=0x10)
        hello_bytes = client_hello(index)
        send(payload=hello_bytes)
        c += len(hello_bytes)
        reply = server_hello()
        send(reverse=True, payload=reply)
        s += len(reply)
        for _ in range(4):
            data = bytes(200)
            send(payload=data)
            c += len(data)
            send(reverse=True, payload=data)
            s += len(data)
        send(flags=0x11)
        send(reverse=True, flags=0x11)
        query = struct.pack("!HHHH", 40000 + index % 20000, 53, 0, 0)
        name = dns(index & 0xFFFF, False)
        packets.append((timestamp, ethernet(0, 0x0800) +
                        ipv4(client, bytes([192, 0, 2, 53]), 17, query[:4] + struct.pack("!HH", 8 + len(name), 0) +
                             name)))
        answer = dns(index & 0xFFFF, True)
        packets.append((timestamp + 20, ethernet(0, 0x0800) +
                        ipv4(bytes([192, 0, 2, 53]), client, 17, struct.pack("!HHHH", 53, query[0] << 8 | query[1],
                                                                            8 + len(answer), 0) + answer)))
    with CAPTURE.open("wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for stamp, frame in packets:
            handle.write(struct.pack("<IIII", stamp // 1000000, stamp % 1000000, len(frame), len(frame)))
            handle.write(frame)
    return len(packets)


def timed(clis, sql, trials):
    """Best time and answer per binary, alternating binaries on every trial."""
    best = [None] * len(clis)
    answers = [None] * len(clis)
    for _ in range(trials):
        for index, cli in enumerate(clis):
            start = time.perf_counter()
            result = subprocess.run([str(cli), "-csv", "-noheader", "-c", "SET threads=1; " + sql],
                                    capture_output=True, text=True, check=False)
            elapsed = time.perf_counter() - start
            if result.returncode != 0 or result.stderr.strip():
                raise SystemExit(f"{cli}: {sql}\n{result.stderr}")
            best[index] = elapsed if best[index] is None else min(best[index], elapsed)
            answers[index] = result.stdout.strip()
    return best, answers


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--connections", type=int, default=20000)
    parser.add_argument("--trials", type=int, default=5)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--cli", type=Path, action="append", help="DuckDB CLI to time; repeat to compare")
    arguments = parser.parse_args()
    clis = arguments.cli or [CLI]
    packets = build(arguments.connections)
    results = {"connections": arguments.connections, "packets": packets, "clis": [str(c) for c in clis],
               "seconds": {}, "answers": {}}
    timed(clis, "SELECT 1", 1)
    for name, sql in QUERIES.items():
        seconds, answers = timed(clis, sql.format(path=CAPTURE), arguments.trials)
        results["seconds"][name] = [round(value, 4) for value in seconds]
        results["answers"][name] = answers
        times = "  ".join(f"{value:7.3f} s" for value in seconds)
        same = "" if len(set(answers)) == 1 else "  ANSWERS DIFFER"
        print(f"{name:24} {times}{same}")
    if arguments.json:
        arguments.json.write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    main()
