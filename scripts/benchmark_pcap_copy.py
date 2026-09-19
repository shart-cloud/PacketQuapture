#!/usr/bin/env python3
"""Synthetic PCAP COPY measurement, including close/sync/publication and checked readback."""

import argparse
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
from benchmark_remote_reads import Connection, quote

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output", type=Path, default=ROOT / "build/pcap-copy-benchmark.json"
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
        "cache": "Synthetic SQL-generated payloads; OS cache uncontrolled; elapsed time includes sorting, writing, sync, close and rename. No cold-disk or durability claim.",
        "runs": [],
    }
    evidence["build"] = [
        x
        for x in (ROOT / "build/release/CMakeCache.txt").read_text().splitlines()
        if x.startswith(
            (
                "CMAKE_BUILD_TYPE:",
                "CMAKE_CXX_FLAGS_RELEASE:",
                "ENABLE_THREAD_SANITIZER:",
                "RELEASE_SANITIZER:",
            )
        )
    ]
    with tempfile.TemporaryDirectory(
        prefix="pcap-copy-benchmark-", dir=ROOT / "build"
    ) as temporary, Connection(ROOT / "build/release/src/libduckdb.so") as c:
        path = Path(temporary) / "export.pcap"
        evidence["duckdb_version"] = c.query("SELECT version() v")[0]["v"]
        for threads in [1, 4]:
            c.query(f"SET threads={threads}")
            for rows in [1000, 10000]:
                for size in [64, 1500]:
                    sql = f"COPY (SELECT make_timestamp(i) AS timestamp,{size}::UINTEGER captured_length,{size}::UINTEGER original_length,1::UINTEGER link_type,repeat('x',{size})::BLOB packet_data FROM range({rows}) t(i) ORDER BY i DESC) TO {quote(path)} (FORMAT PCAP,LINKTYPE 1)"
                    start = time.perf_counter()
                    assert c.query(sql) == [{"Count": str(rows)}]
                    elapsed = time.perf_counter() - start
                    assert path.stat().st_size == 24 + rows * (16 + size)
                    assert c.query(
                        f"SELECT count(*) n,sum(octet_length(packet_data)) bytes,count(*) FILTER(WHERE epoch_us(timestamp)<>{rows}-packet_number) misordered FROM read_pcap({quote(path)})"
                    ) == [
                        {"n": str(rows), "bytes": str(rows * size), "misordered": "0"}
                    ]
                    evidence["runs"].append(
                        {
                            "threads": threads,
                            "packets": rows,
                            "frame_bytes": size,
                            "file_bytes": path.stat().st_size,
                            "seconds": elapsed,
                        }
                    )
        assert not list(Path(temporary).glob(".packetquapture-*"))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps(evidence["runs"], indent=2))


if __name__ == "__main__":
    main()
