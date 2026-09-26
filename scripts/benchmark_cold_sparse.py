#!/usr/bin/env python3
"""Cold and warm count(*) over local captures of four packet sizes, alternating two
DuckDB CLIs so that drift in the host's own caching hits both alike.

Each cold trial first drops the capture's pages with POSIX_FADV_DONTNEED, which needs no
root. Under WSL2 the Windows host may still cache the virtual disk, so cold figures are
comparable within one run, not across machines.

usage: benchmark_cold_sparse.py <baseline cli> <candidate cli> [trials] [--output FILE]
"""
import argparse, json, os, statistics, subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from benchmark_within_file_checkpoints import generate, evict  # noqa: E402

# name, packets, captured bytes per packet: about 300 MB each.
CAPTURES = [
    ("large_15000", 20_000, 15_000),
    ("medium_6000", 50_000, 6_000),
    ("huge_200000", 1_500, 200_000),
    ("dense_1500", 200_000, 1_500),
]


def run(cli, path, cold):
    if cold:
        # Pages just written stay dirty, and dirty pages cannot be dropped.
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        evict(path)
    env = dict(os.environ, LD_LIBRARY_PATH=str(Path(cli).resolve().parent))
    start = time.perf_counter()
    out = subprocess.run([cli, "-csv", "-noheader", "-c", f"SELECT count(*) FROM read_pcap('{path}')"],
                         capture_output=True, text=True, env=env, check=True).stdout.strip()
    return time.perf_counter() - start, out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("baseline")
    parser.add_argument("candidate")
    parser.add_argument("trials", nargs="?", type=int, default=7)
    parser.add_argument("--output")
    parser.add_argument("--keep", action="store_true", help="keep the generated captures")
    args = parser.parse_args()
    results = {}
    paths = []
    try:
        for name, packets, size in CAPTURES:
            path = generate(ROOT / f"build/cold-{name}.pcap", packets, size, 10)
            paths.append(path)
            for mode in ("cold", "warm"):
                times = {"baseline": [], "candidate": []}
                for trial in range(args.trials):
                    order = (("baseline", args.baseline), ("candidate", args.candidate))
                    for label, cli in order[:: 1 if trial % 2 else -1]:
                        if mode == "warm":
                            run(cli, path, False)
                        seconds, count = run(cli, path, mode == "cold")
                        assert count == str(packets), (label, count)
                        times[label].append(seconds)
                summary = {k: {"median": statistics.median(v), "min": min(v), "max": max(v)} for k, v in times.items()}
                results[f"{name}/{mode}"] = summary
                b, c = summary["baseline"], summary["candidate"]
                print(f"{name:12} {mode}: baseline {b['median']:.3f}s [{b['min']:.3f}-{b['max']:.3f}]  "
                      f"candidate {c['median']:.3f}s [{c['min']:.3f}-{c['max']:.3f}]", flush=True)
    finally:
        if not args.keep:
            for path in paths:
                path.unlink(missing_ok=True)
    if args.output:
        Path(args.output).write_text(json.dumps({"trials": args.trials, "results": results}, indent=2) + "\n")


if __name__ == "__main__":
    main()
