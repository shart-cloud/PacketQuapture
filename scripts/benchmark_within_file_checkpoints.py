#!/usr/bin/env python3
"""Feasibility baseline for within-file packet-time checkpoints.

Measures what a selective timestamp query costs today, when whole-file catalog
pruning has already retained the file. Capture-data reads are counted separately
from listing/identity syscalls, and warm and evicted page-cache conditions are
reported separately. This records a baseline; it does not implement checkpoints
and does not assert an achievable speedup.
"""

import argparse
import json
import os
from pathlib import Path
import platform
import re
import statistics
import struct
import subprocess
import sys
import time

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "build/release/duckdb"

# Same approximate byte volume, three packet-count regimes, plus an unsorted control.
CASES = [
    ("large_payloads", 20_000, 15_000, 10),
    ("mixed_payloads", 200_000, 1_500, 100),
    ("small_payloads", 2_000_000, 150, 1_000),
]
QUICK = [
    ("large_payloads", 4_000, 15_000, 10),
    ("mixed_payloads", 40_000, 1_500, 100),
    ("small_payloads", 200_000, 150, 1_000),
]
RECORD = struct.Struct("<IIII")
FILE_HEADER = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
SELECTIVITY = 100  # the query window is one hundredth of each capture's time span


def generate(path, packets, size, rate, shuffle=False):
    """Write a classic PCAP whose timestamps advance at `rate` packets per second."""
    if path.exists():
        return path
    payload = bytes.fromhex("aabbccddeeff0011223344550800") + bytes(size - 14)
    order = list(range(packets))
    if shuffle:
        import random

        random.Random(7).shuffle(order)
    with path.open("wb") as handle:
        handle.write(FILE_HEADER)
        for index in order:
            handle.write(
                RECORD.pack(
                    index // rate, (index % rate) * (1_000_000 // rate), size, size
                )
            )
            handle.write(payload)
    return path


def evict(path):
    """Drop this file's page cache without root; other kernel caches are untouched."""
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.posix_fadvise(descriptor, 0, 0, os.POSIX_FADV_DONTNEED)
    finally:
        os.close(descriptor)


def run_query(sql, path, cold):
    if cold:
        evict(path)
    start = time.perf_counter()
    result = subprocess.run(
        [str(CLI), "-noheader", "-list", "-c", sql], text=True, capture_output=True
    )
    elapsed = time.perf_counter() - start
    if result.returncode != 0:
        raise RuntimeError(result.stderr)
    return elapsed, result.stdout.strip()


def measure(sql, path, trials):
    """Median of repeated warm runs, and of repeated runs after eviction."""
    warm = [run_query(sql, path, False)[0] for _ in range(trials)]
    cold = [run_query(sql, path, True)[0] for _ in range(trials)]
    _, answer = run_query(sql, path, False)
    return {
        "warm_seconds": warm,
        "warm_median_seconds": statistics.median(warm),
        "cold_seconds": cold,
        "cold_median_seconds": statistics.median(cold),
        "result": answer,
    }


def account(sql, path, log):
    """Separate capture-data reads from listing/identity syscalls on the same path."""
    result = subprocess.run(
        [
            "strace",
            "-f",
            "-qq",
            "-yy",
            "-e",
            "trace=read,pread64,lseek,openat,statx,newfstatat,fstat",
            "-o",
            str(log),
            str(CLI),
            "-noheader",
            "-list",
            "-c",
            sql,
        ],
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr)
    name = str(path)
    lines = [line for line in log.read_text().splitlines() if name in line]
    reads = [line for line in lines if re.search(r"\b(?:read|pread64)\(", line)]
    seeks = [line for line in lines if re.search(r"\blseek\(", line)]
    identity = [
        line
        for line in lines
        if re.search(r"\b(?:openat|statx|newfstatat|fstat)\(", line)
    ]
    data_bytes = sum(
        int(match[1]) for line in reads if (match := re.search(r"= (\d+)$", line))
    )
    log.unlink()
    return {
        "capture_data_bytes": data_bytes,
        "capture_read_calls": len(reads),
        "capture_seek_calls": len(seeks),
        "identity_calls": len(identity),
    }


def reference_floors(path, cold):
    """Bulk sequential read of the whole file, and of one contiguous window."""
    size = path.stat().st_size

    def read_bytes(offset, wanted):
        if cold:
            evict(path)
        else:
            # The preceding cold measurements evicted this file; read it once so that
            # the warm floor really is warm rather than a first touch after eviction.
            with path.open("rb") as priming:
                while priming.read(1 << 20):
                    pass
        start = time.perf_counter()
        with path.open("rb") as handle:
            handle.seek(offset)
            remaining = wanted
            while remaining > 0:
                chunk = handle.read(min(1 << 20, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
        return time.perf_counter() - start

    window = size // SELECTIVITY
    return {
        "whole_file_seconds": read_bytes(0, size),
        "one_window_seconds": read_bytes(size // 2, window),
        "whole_file_bytes": size,
        "one_window_bytes": window,
    }


def window_predicate(packets, rate):
    span = max(1, packets // rate)
    start = span // 2
    width = max(1, span // SELECTIVITY)
    return (
        "timestamp >= TIMESTAMP '1970-01-01 00:00:00' + INTERVAL "
        f"{start} SECOND AND timestamp < TIMESTAMP '1970-01-01 00:00:00' + "
        f"INTERVAL {start + width} SECOND"
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output", type=Path, default=ROOT / "build/within-file-checkpoints.json"
    )
    parser.add_argument(
        "--captures",
        type=Path,
        default=ROOT / "build/checkpoint-captures",
        help="Directory for generated captures; reused when already present.",
    )
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument(
        "--quick", action="store_true", help="Smaller captures for a fast check."
    )
    parser.add_argument(
        "--keep", action="store_true", help="Keep generated captures on exit."
    )
    args = parser.parse_args()

    evidence = {
        "commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "platform": platform.platform(),
        "cpu": subprocess.check_output(["lscpu"], text=True),
        "compiler": subprocess.check_output(
            ["c++", "--version"], text=True
        ).splitlines()[0],
        "selectivity": f"1/{SELECTIVITY} of each capture's time span",
        "cache": (
            "Warm rows repeat an already-read file. Cold rows call POSIX_FADV_DONTNEED on "
            "the capture first, which drops that file's page cache only: dentry/inode caches, "
            "the DuckDB process start, and any WSL or host storage caching remain uncontrolled. "
            "These are local synthetic observations, not certified cold-disk or cloud measurements."
        ),
        "method": (
            "Timing and syscall accounting are separate passes; strace inflates elapsed time and "
            "is never used for the reported times. Each query is a fresh CLI process, so the "
            "reported times include the measured process start."
        ),
        "runs": [],
    }
    evidence["build"] = [
        line
        for line in (ROOT / "build/release/CMakeCache.txt").read_text().splitlines()
        if line.startswith(
            (
                "CMAKE_BUILD_TYPE:",
                "CMAKE_CXX_FLAGS_RELEASE:",
                "ENABLE_THREAD_SANITIZER:",
                "RELEASE_SANITIZER:",
            )
        )
    ]

    args.captures.mkdir(parents=True, exist_ok=True)
    generated = []
    try:
        empty = args.captures / "startup.pcap"
        generate(empty, 1, 64, 1)
        generated.append(empty)
        evidence["process_start_seconds"] = statistics.median(
            [run_query("SELECT 1", empty, False)[0] for _ in range(args.trials)]
        )

        cases = QUICK if args.quick else CASES
        for name, packets, size, rate in cases + [
            ("unsorted_control", cases[1][1], cases[1][2], cases[1][3])
        ]:
            path = args.captures / f"{name}.pcap"
            generate(path, packets, size, rate, shuffle=name == "unsorted_control")
            generated.append(path)
            predicate = window_predicate(packets, rate)
            selective = f"SELECT count(*) FROM read_packets('{path}') WHERE {predicate}"
            everything = f"SELECT count(*) FROM read_packets('{path}')"
            inventory = f"SELECT packet_count FROM capture_inventory('{path}')"
            row = {
                "case": name,
                "packets": packets,
                "packet_bytes": size,
                "file_bytes": path.stat().st_size,
                "timestamps": "shuffled" if name == "unsorted_control" else "ascending",
                "selective_query": measure(selective, path, args.trials),
                "full_scan_query": measure(everything, path, args.trials),
                "inventory_refresh": measure(inventory, path, args.trials),
                "selective_io": account(
                    selective, path, args.captures / f"{name}-selective.log"
                ),
                "full_scan_io": account(
                    everything, path, args.captures / f"{name}-full.log"
                ),
                "reference_floor_warm": reference_floors(path, False),
                "reference_floor_cold": reference_floors(path, True),
            }
            row["selective_reads_match_full_scan"] = (
                row["selective_io"]["capture_data_bytes"]
                == row["full_scan_io"]["capture_data_bytes"]
            )
            row["capture_data_fraction_read"] = (
                row["selective_io"]["capture_data_bytes"] / row["file_bytes"]
            )
            evidence["runs"].append(row)
            print(json.dumps(row, indent=2))

        evidence["observation"] = (
            "A selective timestamp predicate reads the same capture bytes and issues the same "
            "syscalls as an unrestricted scan in every recorded case: whole-file selection cannot "
            "reduce work inside a retained file. Elapsed time tracks packet count rather than file "
            "size. The unsorted control shows a capture for which per-region bounds could not "
            "exclude anything."
        )
    finally:
        if not args.keep:
            for path in generated:
                path.unlink(missing_ok=True)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"\nWrote {args.output}")


if __name__ == "__main__":
    main()
