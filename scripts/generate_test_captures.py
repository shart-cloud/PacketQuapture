#!/usr/bin/env python3
"""Generate the tiny deterministic capture files used by the SQL tests."""

from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "test" / "data"


def block(block_type: int, body: bytes) -> bytes:
    total_length = 12 + len(body)
    assert total_length % 4 == 0
    return (
        struct.pack("<II", block_type, total_length)
        + body
        + struct.pack("<I", total_length)
    )


def write_pcap() -> None:
    ethernet = bytes.fromhex("ffffffffffff0011223344550800")
    truncated = bytes.fromhex("01020304")
    content = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    content += (
        struct.pack("<IIII", 1_700_000_000, 123_456, len(ethernet), len(ethernet))
        + ethernet
    )
    content += (
        struct.pack("<IIII", 1_700_000_001, 500_000, len(truncated), 10) + truncated
    )
    (DATA / "sample.pcap").write_bytes(content)


def write_pcapng() -> None:
    section = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    ts_resolution = struct.pack("<HHB3x", 9, 1, 6)
    end_options = struct.pack("<HH", 0, 0)
    interface = block(1, struct.pack("<HHI", 1, 0, 65535) + ts_resolution + end_options)

    packet = bytes.fromhex("deadbeef0102")
    timestamp = 1_700_000_002_250_000
    enhanced_body = struct.pack(
        "<IIIII", 0, timestamp >> 32, timestamp & 0xFFFFFFFF, len(packet), len(packet)
    )
    enhanced_body += packet + b"\x00\x00" + end_options
    enhanced = block(6, enhanced_body)

    simple_data = b"quak"
    simple = block(3, struct.pack("<I", len(simple_data)) + simple_data)
    (DATA / "sample.pcapng").write_bytes(section + interface + enhanced + simple)


def main() -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    write_pcap()
    write_pcapng()
    parallel = DATA / "parallel"
    parallel.mkdir(exist_ok=True)
    (parallel / "empty.pcap").write_bytes((DATA / "sample.pcap").read_bytes()[:24])
    section = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    (parallel / "empty.pcapng").write_bytes(section)
    (DATA / "not-a-capture.bin").write_bytes(b"not a capture")


if __name__ == "__main__":
    main()
