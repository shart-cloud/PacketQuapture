#!/usr/bin/env python3
"""Bounded synthetic reassembly/admission regressions against the release CLI."""

import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "scripts"))
from generate_reassembly_captures import segment
from generate_test_captures import block

CLI = ROOT / "build/release/duckdb"


def run(sql, error=None):
    p = subprocess.run([str(CLI), "-json", "-c", sql], cwd=ROOT, capture_output=True, text=True, timeout=90)
    if error:
        assert p.returncode and error in p.stderr, p.stderr
        return
    assert not p.returncode, p.stderr
    decoder = json.JSONDecoder()
    result = []
    output = p.stdout.strip()
    while output:
        value, end = decoder.raw_decode(output)
        result.append(value)
        output = output[end:].strip()
    return result


def quote(path):
    return "'" + str(path).replace("'", "''") + "'"


def record(out, packet):
    out.write(struct.pack("<IIII", 1700000000, 0, len(packet), len(packet)))
    out.write(packet)


def main():
    with tempfile.TemporaryDirectory(prefix="stream-memory-", dir=ROOT / "build") as temp:
        directory = Path(temp)
        capture = directory / "pressure.pcap"
        # 33 directions: 32 reach the retained-payload limit, and the last must
        # produce the same explicit limit diagnostic regardless of worker count.
        frame = struct.pack("!H", 32766) + bytes(32766)
        payload = frame * 32
        with capture.open("wb") as out:
            out.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for i in range(33):
                record(out, segment(40000 + i, 100, flags=2))
                for offset in range(0, len(payload), 32768):
                    record(out, segment(40000 + i, 101 + offset, payload[offset : offset + 32768]))
        fragmented = directory / "fragmented.pcap"
        with fragmented.open("wb") as out:
            out.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            record(out, segment(45000, 100, flags=2))
            for i in range(4096):
                record(out, segment(45000, 101 + i * 256, b"x"))
        inputs = "[" + ",".join([quote(capture), quote(fragmented)] * 4) + "]"
        for fn in ["read_tcp_streams", "read_dns_messages"]:
            data = "stream_data" if fn == "read_tcp_streams" else "message_data"
            projection = f"stream_id, first_packet_number, last_packet_number, reassembly_status, md5({data}) AS digest"
            if fn == "read_tcp_streams":
                projection += ", CAST(chunks AS VARCHAR) AS chunks, CAST(gaps AS VARCHAR) AS gaps"
            else:
                projection += ", message_number, dns_valid"
            # Hash the full reconstructed bytes; sort by stable identity. Keep only
            # digests in the subprocess result, not 128 MiB of reconstructed output.
            projection = projection.replace("CAST(chunks AS VARCHAR)", "md5(CAST(chunks AS VARCHAR))")
            baseline = None
            for budget, memory in [(128, "256MiB"), (256, "512MiB"), (512, "1GiB")]:
                rows = run(
                    f"SET threads=8; SET memory_limit='{memory}'; SET packetquapture_stream_memory_mb={budget}; "
                    f"SELECT {projection} FROM {fn}({inputs}) ORDER BY ALL;"
                )[0]
                assert any(x["reassembly_status"] == "limit" for x in rows), "Missing resource diagnostics"
                if baseline is None:
                    baseline = rows
                else:
                    assert rows == baseline, (fn, budget, "Memory admission changed reconstruction")
            print(fn, "byte/provenance/ID/diagnostic parity at 1, 2 and 4 worker slots", flush=True)
        # Oversized section options must be skipped without allocating the block.
        section = directory / "large-section.pcapng"
        with section.open("wb") as out:
            length = 256 * 1024 * 1024
            out.write(struct.pack("<IIIHHq", 0x0A0D0D0A, length, 0x1A2B3C4D, 1, 0, -1))
            out.seek(length - 4)
            out.write(struct.pack("<I", length))
        for fn in ["read_tcp_streams", "read_dns_messages"]:
            assert run(f"SET memory_limit='256MiB'; SELECT count(*) AS n FROM {fn}({quote(section)});")[0] == [{"n": 0}]
        interfaces = directory / "interfaces.pcapng"
        with interfaces.open("wb") as out:
            out.write(block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
            out.write(block(1, struct.pack("<HHI", 1, 0, 65535)) * 65537)
        for fn in ["read_tcp_streams", "read_dns_messages"]:
            run(f"SELECT count(*) FROM {fn}({quote(interfaces)});", "65536 PCAPNG interfaces")
        print("Large section skipping and bounded interface metadata passed", flush=True)


if __name__ == "__main__":
    main()
