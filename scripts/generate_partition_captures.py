#!/usr/bin/env python3
"""Reuse deterministic captures under a small Hive layout for portable SQL tests."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "test/data"
for directory, source in [
    ("dt=2026-09-18/host=001", "reassembly/streams.pcap"),
    ("dt=2026-09-17/host=002", "tcp_streams/protocols.pcap"),
]:
    target = ROOT / "partitioned" / directory / "capture.pcap"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes((ROOT / source).read_bytes())
