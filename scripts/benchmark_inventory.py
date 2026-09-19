#!/usr/bin/env python3
"""Synthetic inventory/refresh benchmark and loopback identity capability probe."""

import argparse
import json
import platform
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.dont_write_bytecode = True
from benchmark_remote_reads import Connection, RangeServer, configure, quote
from generate_protocol_captures import eth, ip4, udp

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--counts", type=int, nargs="+", default=[16, 128, 512])
    parser.add_argument("--packets", type=int, default=1000)
    parser.add_argument(
        "--output", type=Path, default=ROOT / "build/inventory-benchmark.json"
    )
    args = parser.parse_args()
    evidence = {
        "platform": platform.platform(),
        "cpu": subprocess.check_output(["lscpu"], text=True),
        "compiler": subprocess.check_output(
            ["c++", "--version"], text=True
        ).splitlines()[0],
        "commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "cache": "Local OS cache uncontrolled; synthetic files just written; no cold-cache or speedup claim",
        "threads": 4,
        "packets_per_file": args.packets,
        "runs": [],
        "identity_probes": [],
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
        prefix="inventory-benchmark-", dir=ROOT / "build"
    ) as temp:
        root = Path(temp)
        packet = eth(ip4(udp(), 17))
        record = struct.pack("<IIII", 1700000000, 0, len(packet), len(packet)) + packet
        source = root / "source.pcap"
        source.write_bytes(
            struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
            + record * args.packets
        )
        with Connection(ROOT / "build/release/src/libduckdb.so") as c:
            c.query("SET threads=4")
            evidence["duckdb_version"] = c.query("SELECT version() v")[0]["v"]
            for count in args.counts:
                folder = root / str(count)
                folder.mkdir()
                for i in range(count):
                    shutil.copyfile(source, folder / f"{i:05}.pcap")
                glob = quote(folder / "*.pcap")
                timings = {}
                for phase, options in [
                    ("first", ""),
                    (
                        "unchanged",
                        ",previous_catalog='previous',catalog_validation='immutable'",
                    ),
                    ("strict", ",previous_catalog='previous'"),
                ]:
                    start = time.perf_counter()
                    c.query(
                        f"CREATE OR REPLACE TABLE stage AS SELECT * FROM capture_inventory({glob}{options})"
                    )
                    timings[phase + "_seconds"] = time.perf_counter() - start
                    values = c.query(
                        "SELECT count(*) files,sum(packet_count) packets,count(*) FILTER(WHERE reused) reused FROM stage"
                    )[0]
                    assert (
                        int(values["files"]) == count
                        and int(values["packets"]) == count * args.packets
                    )
                    assert int(values["reused"]) == (
                        count if phase == "unchanged" else 0
                    )
                    if phase == "first":
                        c.query(
                            "CREATE OR REPLACE TABLE previous AS SELECT * FROM stage"
                        )
                with (folder / "00000.pcap").open("ab") as f:
                    f.write(record)
                start = time.perf_counter()
                c.query(
                    f"CREATE OR REPLACE TABLE stage AS SELECT * FROM capture_inventory({glob},previous_catalog='previous',catalog_validation='immutable')"
                )
                timings["one_file_update_seconds"] = time.perf_counter() - start
                values = c.query(
                    "SELECT sum(packet_count) packets,count(*) FILTER(WHERE reused) reused FROM stage"
                )[0]
                assert (
                    int(values["packets"]) == count * args.packets + 1
                    and int(values["reused"]) == count - 1
                )
                evidence["runs"].append(
                    {
                        "files": count,
                        "bytes_before_update": source.stat().st_size * count,
                        **timings,
                    }
                )
            c.query("DROP TABLE stage")
            c.query("DROP TABLE previous")
        # Tiny inputs keep direct per-record remote requests intentionally bounded.
        source.write_bytes(
            struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + record * 3
        )
        for kind in ("http", "s3"):
            with RangeServer({"/bucket/source.pcap": source}) as server, Connection(
                ROOT / "build/release/src/libduckdb.so"
            ) as c:
                configure(c, "external_off", 1)
                locator = server.url + "/bucket/source.pcap"
                if kind == "s3":
                    c.query(f"SET s3_endpoint='127.0.0.1:{server.server_port}'")
                    c.query(
                        "SET s3_use_ssl=false; SET s3_url_style='path'; SET s3_region='us-east-1'; SET s3_access_key_id='synthetic'; SET s3_secret_access_key='synthetic'"
                    )
                    locator = "s3://bucket/source.pcap"
                server.begin()
                c.query(
                    f"CREATE TABLE previous AS SELECT * FROM capture_inventory({quote(locator)})"
                )
                first = server.finish()
                identity = c.query(
                    "SELECT identity_type,identity_strength,identity_value IS NOT NULL has_tag,file_size IS NOT NULL has_size,modification_time IS NOT NULL has_mtime FROM previous"
                )[0]
                server.begin()
                c.query(
                    f"SELECT reused FROM capture_inventory({quote(locator)},previous_catalog='previous',catalog_validation='immutable')"
                )
                reused = server.finish()
                evidence["identity_probes"].append(
                    {
                        "backend": kind,
                        "endpoint": "loopback synthetic range server (not an actual S3 or MinIO service)",
                        **identity,
                        "first_head": sum(e["method"] == "HEAD" for e in first),
                        "first_get": sum(e["method"] == "GET" for e in first),
                        "first_body_bytes": sum(e["body_bytes"] for e in first),
                        "reuse_head": sum(e["method"] == "HEAD" for e in reused),
                        "reuse_get": sum(e["method"] == "GET" for e in reused),
                        "reuse_body_bytes": sum(e["body_bytes"] for e in reused),
                    }
                )
                assert sum(e["body_bytes"] for e in reused) == 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps(evidence["runs"], indent=2))


if __name__ == "__main__":
    main()
