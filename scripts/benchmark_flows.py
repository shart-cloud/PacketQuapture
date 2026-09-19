#!/usr/bin/env python3
"""Small reproducible local flow benchmark; synthetic data, no cold-cache claims."""

import argparse
import json
import platform
import statistics
import struct
import subprocess
import tempfile
import time
from pathlib import Path
from generate_protocol_captures import eth, ip4

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--packets", type=int, default=100000)
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument(
        "--output", type=Path, default=ROOT / "build/flows-benchmark.json"
    )
    args = parser.parse_args()
    cli = ROOT / "build/release/duckdb"
    result = {
        "platform": platform.platform(),
        "cpu": subprocess.check_output(["lscpu"], text=True),
        "compiler": subprocess.check_output(
            ["c++", "--version"], text=True
        ).splitlines()[0],
        "packets_per_occurrence": args.packets,
        "input_occurrences": 8,
        "cache": "Local OS cache uncontrolled; warm-up query; eight duplicate occurrences of one immutable synthetic file",
        "commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "duckdb_version": subprocess.check_output(
            [str(cli), "-csv", "-noheader", "-c", "SELECT version()"], text=True
        ).strip(),
        "build": [
            line
            for line in (ROOT / "build/release/CMakeCache.txt").read_text().splitlines()
            if line.startswith(
                (
                    "CMAKE_BUILD_TYPE:",
                    "CMAKE_CXX_FLAGS:",
                    "CMAKE_CXX_FLAGS_RELEASE:",
                    "ENABLE_SANITIZER:",
                    "ENABLE_UBSAN:",
                    "ENABLE_THREAD_SANITIZER:",
                )
            )
        ],
        "flow_memory_mb": 384,
        "trials": [],
    }
    with tempfile.TemporaryDirectory(
        prefix="flows-benchmark-", dir=ROOT / "build"
    ) as d:
        path = Path(d) / "input.pcap"
        with path.open("wb") as f:
            f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for n in range(args.packets):
                packet = eth(
                    ip4(
                        struct.pack("!HHHH", 1000 + n % 1024, 443, 108, 0) + bytes(100),
                        17,
                    )
                )
                f.write(
                    struct.pack(
                        "<IIII", 1700000000, n % 1000000, len(packet), len(packet)
                    )
                )
                f.write(packet)
        inputs = "[" + ",".join(["'" + str(path) + "'"] * 8) + "]"
        sql = f"SELECT sum(orig_packets+resp_packets)::BIGINT AS packets FROM read_flows({inputs})"
        subprocess.run([str(cli), "-c", sql], check=True, capture_output=True)
        for threads in (1, 2, 4, 8):
            times = []
            for _ in range(args.trials):
                start = time.perf_counter()
                output = subprocess.check_output(
                    [
                        str(cli),
                        "-json",
                        "-c",
                        f"SET threads={threads}; SET packetquapture_flow_memory_mb=384; "
                        + sql,
                    ],
                    text=True,
                )
                times.append(time.perf_counter() - start)
                assert int(json.loads(output)[0]["packets"]) == args.packets * 8
            result["trials"].append(
                {
                    "threads": threads,
                    "seconds": times,
                    "median_seconds": statistics.median(times),
                }
            )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["trials"], indent=2))


if __name__ == "__main__":
    main()
