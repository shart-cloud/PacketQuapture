#!/usr/bin/env python3
"""Generate captures that stop partway through a record.

A writer killed mid-write leaves the final record incomplete. That is the
normal shape of a real-world capture, not corruption, so the reader stops at
the last complete packet and capture_inventory reports scan_status='truncated'.

Each fixture cuts at a different boundary because each one lands on a different
read in the reader: the record header, the payload, a PCAPNG block body, and a
PCAPNG block trailer. The two header fixtures must still fail: a file that
stops inside its own magic number or global header has never proven itself a
capture at all.
"""

from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "test" / "data" / "truncated"

ETHERNET = bytes.fromhex("ffffffffffff0011223344550800")
PCAP_MAGIC = 0xA1B2C3D4


def pcap_global_header() -> bytes:
    return struct.pack("<IHHIIII", PCAP_MAGIC, 2, 4, 0, 0, 65535, 1)


def pcap_record(seconds: int, payload: bytes) -> bytes:
    return struct.pack("<IIII", seconds, 0, len(payload), len(payload)) + payload


def complete_pcap(count: int = 2) -> bytes:
    out = pcap_global_header()
    for i in range(count):
        out += pcap_record(1_700_000_000 + i, ETHERNET)
    return out


def block(block_type: int, body: bytes) -> bytes:
    total_length = 12 + len(body)
    assert total_length % 4 == 0
    return struct.pack("<II", block_type, total_length) + body + struct.pack("<I", total_length)


def pcapng_prefix() -> bytes:
    shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = block(0x00000001, struct.pack("<HHI", 1, 0, 65535))
    return shb + idb


def enhanced_packet(payload: bytes) -> bytes:
    padded = payload + b"\x00" * (-len(payload) % 4)
    return block(0x00000006, struct.pack("<IIIII", 0, 0, 0, len(payload), len(payload)) + padded)


def write(name: str, content: bytes) -> None:
    path = DATA / name
    path.write_bytes(content)
    print(f"{path.relative_to(ROOT)}: {len(content)} bytes")


def main() -> None:
    DATA.mkdir(parents=True, exist_ok=True)

    # --- tolerated: two complete packets, then a cut-short tail -------------
    # Record header cut mid-way: 6 of the 16 header bytes present.
    write("record_header.pcap", complete_pcap() + struct.pack("<IH", 1_700_000_002, 0))

    # Header complete, payload short: declares a full frame, supplies 4 bytes.
    write(
        "payload.pcap",
        complete_pcap() + struct.pack("<IIII", 1_700_000_002, 0, len(ETHERNET), len(ETHERNET)) + ETHERNET[:4],
    )

    # Header complete, payload absent entirely -- the file ends exactly on the
    # record boundary, which is a different path from a short read.
    write(
        "payload_absent.pcap",
        complete_pcap() + struct.pack("<IIII", 1_700_000_002, 0, len(ETHERNET), len(ETHERNET)),
    )

    # The real corpus minimum: two bytes missing from the end.
    full = complete_pcap(3)
    write("two_bytes.pcap", full[:-2])

    # PCAPNG block body cut mid-way.
    write("block.pcapng", pcapng_prefix() + enhanced_packet(ETHERNET) + enhanced_packet(ETHERNET)[:20])

    # PCAPNG block whose 4-byte trailing length is missing.
    write("trailer.pcapng", pcapng_prefix() + enhanced_packet(ETHERNET) + enhanced_packet(ETHERNET)[:-4])

    # --- still fatal: the file never establishes itself as a capture --------
    # Kept in a subdirectory so the tolerated fixtures can be globbed together.
    (DATA / "fatal").mkdir(exist_ok=True)
    write("fatal/magic.pcap", struct.pack("<I", PCAP_MAGIC)[:2])
    write("fatal/global_header.pcap", pcap_global_header()[:12])

    # Valid headers, but the one and only record is partial, so the file never
    # yields a packet. Tolerating this would return silently empty results for
    # a file that may not be a capture at all.
    write(
        "fatal/only_partial.pcap",
        pcap_global_header() + struct.pack("<IIII", 1_700_000_000, 0, len(ETHERNET), len(ETHERNET)) + ETHERNET[:4],
    )

    # --- control: nothing truncated ----------------------------------------
    write("complete.pcap", complete_pcap(3))


if __name__ == "__main__":
    main()
