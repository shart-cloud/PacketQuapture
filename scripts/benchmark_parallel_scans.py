#!/usr/bin/env python3
"""Warm-cache multicore benchmark; generated captures and JSON reports stay in build/.

Requires the release CLI and Linux /usr/bin/time. No privileged cache eviction.
Timing includes a separate process measurement and DuckDB's query-only latency.
The same packet bytes are split over each layout; per-file headers add 24 bytes.
"""

import argparse
import json
import os
from pathlib import Path
import platform
import random
import statistics
import struct
import subprocess
import sys
import time

sys.dont_write_bytecode = True
from generate_reassembly_captures import segment
from generate_dns_captures import header, name, udp
from generate_protocol_captures import eth, ip4

ROOT = Path(__file__).resolve().parents[1]
CASES = {
    "metadata": ("read_pcap", "count(*) AS rows", ""),
    "transport": (
        "read_packets",
        "count(*) AS rows, sum(src_port), sum(payload_length)",
        "",
    ),
    "flags": (
        "read_packets",
        "count(*) AS rows, sum(payload_length)",
        "tcp_syn AND NOT tcp_ack_flag",
    ),
    "address_port": (
        "read_packets",
        "count(*) AS rows, sum(payload_length)",
        "src_ip = '192.0.2.1' AND dst_port = 53",
    ),
    "raw": ("read_packets", "count(*) AS rows, sum(octet_length(packet_data))", ""),
    "dns": ("read_dns", "count(*) AS rows, count(dns_question_name), sum(dns_id)", ""),
    "streams": ("read_tcp_streams", "count(*) AS rows, sum(captured_bytes)", ""),
    "stream_bytes": (
        "read_tcp_streams",
        "count(*) AS rows, sum(octet_length(stream_data)), sum(len(chunks))",
        "",
    ),
    "dns_messages": (
        "read_dns_messages",
        "count(*) AS rows, sum(octet_length(message_data)), count(dns_question_name)",
        "",
    ),
}


def quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def inputs(paths):
    return "[" + ",".join(quote(path) for path in paths) + "]"


def command(args):
    return subprocess.run(
        args, cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()


def make_layout(directory, sizes, unit):
    directory.mkdir(parents=True, exist_ok=True)
    paths = []
    for i, size in enumerate(sizes):
        path = directory / f"capture-{i:04}.pcap"
        with path.open("wb") as output:
            output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for start in range(0, size, 1024):
                output.write(unit * min(1024, size - start))
        paths.append(path)
    return paths


def distribute(total, count):
    return [total // count + (i < total % count) for i in range(count)]


def generate(directory, units, tiny_files, layouts):
    message = header() + name("example.com") + struct.pack("!HH", 1, 1)
    framed = struct.pack("!H", len(message)) + message
    # Each unit closes its TCP direction with RST. No growing flows, limits, or
    # file-boundary splits contaminate throughput or stream-result comparisons.
    packets = [
        segment(53000, 100, flags=2),
        segment(53000, 101, framed),
        segment(53000, 101 + len(framed), flags=4),
        eth(ip4(udp(message), protocol=17)),
    ]
    unit = b"".join(
        struct.pack("<IIII", 1700000000, 0, len(p), len(p)) + p for p in packets
    )
    shapes = {str(count): distribute(units, count) for count in (1, 2, 4, 8)}
    shapes["tiny"] = distribute(units, tiny_files)
    shapes["skew"] = [units * 4 // 5] + distribute(units - units * 4 // 5, 7)
    return {
        layout: make_layout(directory / layout, shapes[layout], unit)
        for layout in layouts
    }, len(unit)


def warm(paths):
    for path in paths:
        with path.open("rb") as source:
            while source.read(8 * 1024 * 1024):
                pass


def verify(cli, trials):
    rng = random.Random(20260917)
    pool = sorted((ROOT / "test/data/protocols").glob("*.pcap*"))
    pool += sorted((ROOT / "test/data/dns").glob("*.pcap*"))
    pool += sorted((ROOT / "test/data/parallel").glob("*.pcap*"))
    pool += sorted((ROOT / "test/data/reassembly").glob("*.pcap*"))
    pool += sorted((ROOT / "test/data/tcp_streams").glob("*.pcap*"))
    for trial in range(trials):
        paths = rng.choices(pool, k=12)
        paths += paths[
            :2
        ]  # Exercise multiplicity even if random choices happen to be unique.
        for function in (
            "read_pcap",
            "read_packets",
            "read_dns",
            "read_tcp_streams",
            "read_dns_messages",
        ):
            source = f"{function}({inputs(paths)})"
            predicate = "packet_number > 1 AND captured_length > 30"
            if function != "read_pcap":
                predicate += (
                    " AND (tcp_syn OR dst_port IN (53, 443) OR src_port IS NULL)"
                )
            if function == "read_dns":
                predicate += " AND (dns_valid OR dns_id IS NULL)"
            if function in ("read_tcp_streams", "read_dns_messages"):
                predicate = (
                    "first_packet_number > 1 AND (src_port > 0 OR dst_port = 53)"
                )
            sql = (
                f"SET threads=1; CREATE TEMP TABLE expected AS SELECT * FROM {source};"
            )
            for threads in (1, 2, 4, 8):
                a = f"SELECT * FROM {source} WHERE {predicate}"
                b = f"SELECT * FROM expected WHERE {predicate}"
                sql += f"SET threads={threads}; SELECT count(*) AS differences FROM (({a} EXCEPT ALL {b}) UNION ALL ({b} EXCEPT ALL {a}));"
            output = command([str(cli), "-json", "-c", sql])
            # The CLI emits one JSON array per statement that returns rows.
            decoder = json.JSONDecoder()
            results = []
            while output.strip():
                value, end = decoder.raw_decode(output.lstrip())
                results.extend(value)
                output = output.lstrip()[end:]
            assert len(results) == 4 and all(
                row["differences"] == 0 for row in results
            ), (trial, function, results)
    print(
        f"Randomized multiset parity passed: {trials} mixes x 5 functions x 4 thread settings",
        flush=True,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, default=ROOT / "build/release/duckdb")
    parser.add_argument(
        "--units",
        type=int,
        default=262144,
        help="four packets and one short finalized TCP direction per unit",
    )
    parser.add_argument("--tiny-files", type=int, default=256)
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--threads", nargs="+", type=int, default=[1, 2, 4, 8])
    parser.add_argument(
        "--layouts",
        nargs="+",
        choices=["1", "2", "4", "8", "tiny", "skew"],
        default=["1", "2", "4", "8", "tiny", "skew"],
    )
    parser.add_argument("--cases", nargs="+", choices=list(CASES), default=list(CASES))
    parser.add_argument("--verify-mixes", type=int, default=5)
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--storage-note", default="unspecified; see mount record")
    parser.add_argument("--label", default="working tree")
    parser.add_argument("--work-dir", type=Path, default=ROOT / "build/parallel-scans")
    parser.add_argument("--stream-memory-mb", type=int)
    parser.add_argument("--memory-limit", help="DuckDB memory_limit, for example 4GiB")
    parser.add_argument(
        "--output", type=Path, default=ROOT / "build/parallel-scans/report.json"
    )
    args = parser.parse_args()
    if (
        min(args.units, args.tiny_files, args.trials, *args.threads) < 1
        or args.verify_mixes < 0
        or (args.stream_memory_mb is not None and args.stream_memory_mb < 1)
    ):
        parser.error(
            "sizes, trials, and thread counts must be positive; mixes must be nonnegative"
        )
    args.cli = args.cli.resolve()
    verify(args.cli, args.verify_mixes)
    if args.verify_only:
        return
    args.output = args.output.resolve()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    directory = args.work_dir.resolve()
    settings = ""
    if args.memory_limit is not None:
        settings += f"SET memory_limit={quote(args.memory_limit)};"
    if args.stream_memory_mb is not None:
        settings += f"SET packetquapture_stream_memory_mb={args.stream_memory_mb};"
    effective_settings = json.loads(
        command(
            [
                str(args.cli),
                "-json",
                "-c",
                settings
                + "SELECT current_setting('memory_limit') AS memory_limit, "
                + "current_setting('packetquapture_stream_memory_mb') AS stream_memory_mb",
            ]
        )
    )[0]
    captures, unit_bytes = generate(
        directory, args.units, args.tiny_files, args.layouts
    )
    cache = ROOT / "build/release/CMakeCache.txt"
    report = {
        "label": args.label,
        "settings": effective_settings,
        "work_dir": str(directory),
        "verification_mixes": args.verify_mixes,
        "trial_order": "thread/trial pairs shuffled within each layout/case using seed 20260918",
        "cli": str(args.cli),
        "revision": command(["git", "rev-parse", "HEAD"]),
        "working_tree": command(["git", "status", "--short"]),
        "duckdb": command([str(args.cli), "--version"]),
        "build_flags": (
            [
                line
                for line in cache.read_text().splitlines()
                if line.startswith(
                    ("CMAKE_CXX_FLAGS", "CMAKE_BUILD_TYPE", "CMAKE_CXX_COMPILER:")
                )
            ]
            if cache.exists()
            else []
        ),
        "os": platform.platform(),
        "cpu": command(["lscpu"]),
        "logical_cpus": os.cpu_count(),
        "storage_note": args.storage_note,
        "mount": command(["findmnt", "-T", str(directory)]),
        "cache": "warm: every source read once before each trial; no cache eviction or cold-cache claim",
        "shape": {
            "units": args.units,
            "packets": args.units * 4,
            "packet_bytes": args.units * unit_bytes,
            "tiny_files": args.tiny_files,
            "stream_limits": "one short direction per unit, finalized by RST",
        },
        "measurement": "DuckDB profile latency excludes CLI startup; GNU time CPU/RSS/utilization include the entire CLI process. Source MiB/s measures input file size, not physical I/O. Rows/s is output scan rows per query latency.",
        "runs": [],
        "summaries": [],
    }
    expected = {}
    for layout, paths in captures.items():
        source_bytes = sum(path.stat().st_size for path in paths)
        for case in args.cases:
            function, projection, predicate = CASES[case]
            sql = f"SELECT {projection} FROM {function}({inputs(paths)})"
            if predicate:
                sql += " WHERE " + predicate
            plan_path = directory / f"plan-{layout}-{case}.txt"
            plan_path.write_text(
                command([str(args.cli), "-c", settings + "EXPLAIN " + sql])
            )
            if predicate:
                assert "Filters:" in plan_path.read_text(), (
                    case,
                    "filter pushdown missing",
                )
            runs_by_threads = {threads: [] for threads in args.threads}
            trial_order = [
                (threads, trial)
                for trial in range(args.trials)
                for threads in args.threads
            ]
            random.Random(20260918).shuffle(trial_order)
            for threads, trial in trial_order:
                warm(paths)
                profile = directory / "profile.json"
                metrics = directory / "process-time.txt"
                query = (
                    settings
                    + f"SET threads={threads}; SET enable_profiling='json'; SET profiling_output={quote(profile)}; {sql};"
                )
                start = time.monotonic()
                output = command(
                    [
                        "/usr/bin/time",
                        "-f",
                        "%e %U %S %M",
                        "-o",
                        str(metrics),
                        str(args.cli),
                        "-json",
                        "-c",
                        query,
                    ]
                )
                elapsed = time.monotonic() - start
                result = json.loads(output)
                if case not in expected:
                    expected[case] = result
                assert result == expected[case], (
                    layout,
                    case,
                    threads,
                    result,
                    expected[case],
                )
                measured = json.loads(profile.read_text())
                wall, user, system, rss = map(float, metrics.read_text().split())
                latency = measured["latency"]
                rows = result[0]["rows"]
                run = {
                    "layout": layout,
                    "files": len(paths),
                    "case": case,
                    "threads": threads,
                    "trial": trial,
                    "source_bytes": source_bytes,
                    "rows": rows,
                    "query_wall_s": latency,
                    "process_wall_s": elapsed,
                    "process_cpu_s": user + system,
                    "process_cpu_percent": 100 * (user + system) / elapsed,
                    "peak_rss_kib": rss,
                    "rows_per_s": rows / latency,
                    "source_mib_per_s": source_bytes / (1024**2) / latency,
                    "result": result,
                    "plan": str(plan_path),
                }
                runs_by_threads[threads].append(run)
                report["runs"].append(run)
            for threads, runs in runs_by_threads.items():
                times = [run["query_wall_s"] for run in runs]
                summary = {
                    "layout": layout,
                    "case": case,
                    "threads": threads,
                    "median_s": statistics.median(times),
                    "min_s": min(times),
                    "max_s": max(times),
                    "median_source_mib_per_s": statistics.median(
                        run["source_mib_per_s"] for run in runs
                    ),
                }
                report["summaries"].append(summary)
                args.output.write_text(json.dumps(report, indent=2) + "\n")
                print(json.dumps(summary), flush=True)
    for summary in report["summaries"]:
        baseline = next(
            (
                s
                for s in report["summaries"]
                if s["layout"] == summary["layout"]
                and s["case"] == summary["case"]
                and s["threads"] == 1
            ),
            None,
        )
        if baseline:
            summary["speedup_vs_threads_1"] = baseline["median_s"] / summary["median_s"]
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Report: {args.output}")


if __name__ == "__main__":
    main()
