#!/usr/bin/env python3
"""Synthetic selective queries with explicit cache caveats and HTTP read counts."""

import argparse
import json
import platform
from pathlib import Path
import statistics
import struct
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
from benchmark_remote_reads import Connection, RangeServer, configure, quote
from generate_protocol_captures import eth, ip4, udp

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output", type=Path, default=ROOT / "build/catalog-benchmark.json"
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
        "threads": 4,
        "cache": "Files freshly written; local OS cache uncontrolled. First measured and repeated queries are not certified cold/warm disk measurements. HTTP external cache disabled.",
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
        prefix="catalog-benchmark-", dir=ROOT / "build"
    ) as temporary:
        root = Path(temporary)
        packet = eth(ip4(udp(), 17))
        header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

        def data(seconds, count=1000):
            return (
                header
                + (struct.pack("<IIII", seconds, 0, len(packet), len(packet)) + packet)
                * count
            )

        for files in [16, 128, 512]:
            folder = root / str(files)
            folder.mkdir()
            for index in range(files):
                (folder / f"{index}.pcap").write_bytes(data(20 if index == 0 else 1))
            with Connection(ROOT / "build/release/src/libduckdb.so") as c:
                c.query("SET threads=4")
                evidence["duckdb_version"] = c.query("SELECT version() v")[0]["v"]
                source = quote(folder / "*.pcap")
                c.query(
                    f"CREATE TABLE cat AS SELECT * FROM capture_inventory({source})"
                )
                row = {
                    "files": files,
                    "packets_per_file": 1000,
                    "time_selected_files": 1,
                }
                for mode in ["baseline", "strict", "immutable"]:
                    options = (
                        ""
                        if mode == "baseline"
                        else f",catalog='cat',catalog_validation='{mode}'"
                    )
                    sql = f"SELECT count(*) n FROM read_packets({source}{options}) WHERE timestamp>=TIMESTAMP '1970-01-01 00:00:10'"
                    times = []
                    for _ in range(4):
                        start = time.perf_counter()
                        assert c.query(sql) == [{"n": "1000"}]
                        times.append(time.perf_counter() - start)
                    row[mode] = {
                        "first_seconds": times[0],
                        "repeat_seconds": times[1:],
                        "repeat_median_seconds": statistics.median(times[1:]),
                    }
                evidence["runs"].append(row)
        source = root / "remote.pcap"
        source.write_bytes(data(1, 3))
        with RangeServer({"/source.pcap": source}) as server, Connection(
            ROOT / "build/release/src/libduckdb.so"
        ) as c:
            configure(c, "external_off", 4)
            url = quote(server.url + "/source.pcap")
            c.query(f"CREATE TABLE cat AS SELECT * FROM capture_inventory({url})")
            evidence["http"] = {}
            for mode in ["strict", "immutable"]:
                server.begin()
                assert c.query(
                    f"SELECT count(*) n FROM read_packets({url},catalog='cat',catalog_validation='{mode}') WHERE timestamp>=TIMESTAMP '1970-01-01 00:00:10'"
                ) == [{"n": "0"}]
                requests = server.finish()
                evidence["http"][mode] = {
                    "head": sum(x["method"] == "HEAD" for x in requests),
                    "get": sum(x["method"] == "GET" for x in requests),
                    "body_bytes": sum(x["body_bytes"] for x in requests),
                }
            assert evidence["http"]["immutable"]["body_bytes"] == 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps(evidence["runs"], indent=2))


if __name__ == "__main__":
    main()
