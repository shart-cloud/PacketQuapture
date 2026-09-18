#!/usr/bin/env python3
"""Measure actual DuckDB httpfs requests against a loopback HTTP range server.

Uses the C API of the built library so repeated queries share a database/connection.
No third-party Python dependencies, credentials, cloud writes, or production captures.
Install the matching httpfs extension before running; downloads are not benchmarked.
"""

import argparse
from collections import Counter
import ctypes as c
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import hashlib
import math
import os
from pathlib import Path
import platform
import re
import socket
import statistics
import struct
import subprocess
import threading
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
CASES = {
    "metadata": ("read_pcap", "count(*) AS packets", ""),
    "headers": (
        "read_packets",
        "count(*) AS packets, sum(dst_port) AS ports, sum(payload_length) AS payload_bytes",
        "",
    ),
    "selective": (
        "read_packets",
        "count(*) AS packets, sum(octet_length(packet_data)) AS packet_bytes",
        "dst_port = 443",
    ),
    "reject": (
        "read_packets",
        "count(*) AS packets, sum(octet_length(packet_data)) AS packet_bytes",
        "captured_length < 54",
    ),
    "raw": (
        "read_packets",
        "count(*) AS packets, sum(octet_length(packet_data)) AS packet_bytes",
        "",
    ),
}
PROFILES = {
    "default": (True, False),
    "external_off": (False, False),
    "metadata_on": (True, True),
}


def quote(value):
    return "'" + str(value).replace("'", "''") + "'"


class Result(c.Structure):
    # duckdb_result from the pinned duckdb.h; no private C++ ABI is used.
    _fields_ = [
        ("columns", c.c_uint64),
        ("rows", c.c_uint64),
        ("changed", c.c_uint64),
        ("data", c.c_void_p),
        ("error", c.c_void_p),
        ("internal", c.c_void_p),
    ]


class Connection:
    def __init__(self, library):
        self.api = c.CDLL(str(library))
        self.database, self.connection = c.c_void_p(), c.c_void_p()
        signatures = {
            "duckdb_open": ([c.c_char_p, c.POINTER(c.c_void_p)], c.c_int),
            "duckdb_connect": ([c.c_void_p, c.POINTER(c.c_void_p)], c.c_int),
            "duckdb_query": ([c.c_void_p, c.c_char_p, c.POINTER(Result)], c.c_int),
            "duckdb_result_error": ([c.POINTER(Result)], c.c_char_p),
            "duckdb_row_count": ([c.POINTER(Result)], c.c_uint64),
            "duckdb_column_count": ([c.POINTER(Result)], c.c_uint64),
            "duckdb_column_name": ([c.POINTER(Result), c.c_uint64], c.c_char_p),
            "duckdb_value_varchar": (
                [c.POINTER(Result), c.c_uint64, c.c_uint64],
                c.c_void_p,
            ),
            "duckdb_value_is_null": (
                [c.POINTER(Result), c.c_uint64, c.c_uint64],
                c.c_bool,
            ),
            "duckdb_destroy_result": ([c.POINTER(Result)], None),
            "duckdb_free": ([c.c_void_p], None),
            "duckdb_interrupt": ([c.c_void_p], None),
            "duckdb_disconnect": ([c.POINTER(c.c_void_p)], None),
            "duckdb_close": ([c.POINTER(c.c_void_p)], None),
        }
        for name, (args, result) in signatures.items():
            function = getattr(self.api, name)
            function.argtypes, function.restype = args, result
        if self.api.duckdb_open(None, c.byref(self.database)):
            raise RuntimeError("Could not open in-memory DuckDB")
        if self.api.duckdb_connect(self.database, c.byref(self.connection)):
            self.close()
            raise RuntimeError("Could not connect to DuckDB")

    def query(self, sql, timeout=30):
        result = Result()
        timer = threading.Timer(
            timeout, self.api.duckdb_interrupt, args=(self.connection,)
        )
        timer.daemon = True
        timer.start()
        try:
            if self.api.duckdb_query(self.connection, sql.encode(), c.byref(result)):
                message = self.api.duckdb_result_error(c.byref(result))
                raise RuntimeError(
                    message.decode() if message else "DuckDB query failed"
                )
            names = [
                self.api.duckdb_column_name(c.byref(result), col).decode()
                for col in range(self.api.duckdb_column_count(c.byref(result)))
            ]
            rows = []
            for row in range(self.api.duckdb_row_count(c.byref(result))):
                values = {}
                for col, name in enumerate(names):
                    if self.api.duckdb_value_is_null(c.byref(result), col, row):
                        values[name] = None
                    else:
                        value = self.api.duckdb_value_varchar(c.byref(result), col, row)
                        if not value:
                            raise RuntimeError(
                                "C API could not convert column "
                                + name
                                + " to VARCHAR; cast it explicitly"
                            )
                        try:
                            values[name] = c.string_at(value).decode()
                        finally:
                            self.api.duckdb_free(value)
                rows.append(values)
            return rows
        finally:
            timer.cancel()
            timer.join()
            self.api.duckdb_destroy_result(c.byref(result))

    def close(self):
        if self.connection:
            self.api.duckdb_disconnect(c.byref(self.connection))
        if self.database:
            self.api.duckdb_close(c.byref(self.database))

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class RangeServer(ThreadingHTTPServer):
    daemon_threads = True
    # The stdlib default queue of five can cause SYN retries with eight workers.
    request_queue_size = 128

    def __init__(self, files, latency_ms=0, max_requests=2048, max_bytes=256 * 1024**2):
        self.files = (
            files  # Exact URL allowlist, never resolve arbitrary request paths.
        )
        self.latency_ms, self.max_requests, self.max_bytes = (
            latency_ms,
            max_requests,
            max_bytes,
        )
        self.condition = threading.Condition()
        self.active, self.reserved, self.events = 0, 0, []
        super().__init__(("127.0.0.1", 0), RangeHandler)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_port}"

    def begin(self):
        with self.condition:
            if self.active:
                raise RuntimeError("Previous request still active at query boundary")
            self.events, self.reserved = [], 0

    def finish(self):
        with self.condition:
            if not self.condition.wait_for(lambda: self.active == 0, timeout=10):
                raise RuntimeError("HTTP requests did not drain after the query")
            return [dict(event) for event in self.events]

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=5)


class RangeHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.connection.settimeout(10)

    def log_message(self, *args):
        pass

    def do_HEAD(self):
        self.respond(True)

    def do_GET(self):
        self.respond(False)

    def respond(self, head):
        server = self.server
        event = {
            "method": self.command,
            "path": urlsplit(self.path).path,
            "range": self.headers.get("Range"),
            "status": None,
            "body_bytes": 0,
            "start": None,
            "end": None,
            "completed": False,
        }
        started = time.perf_counter()
        with server.condition:
            server.events.append(event)
            server.active += 1
            request_limit = len(server.events) > server.max_requests
        try:
            if request_limit:
                self.empty(event, 503)
                return
            if server.latency_ms:
                time.sleep(server.latency_ms / 1000)
            path = server.files.get(event["path"])
            if path is None:
                self.empty(event, 404)
                return
            try:
                size = path.stat().st_size
            except FileNotFoundError:
                self.empty(event, 404)
                return
            etag = f'"synthetic-{size}-{path.stat().st_mtime_ns}"'
            if self.headers.get("If-Match") not in (None, "*", etag):
                self.empty(event, 412)
                return
            if self.headers.get("If-None-Match") in ("*", etag):
                self.empty(event, 304)
                return
            start, end, status = 0, size - 1, 200
            range_header = self.headers.get("Range")
            if (
                range_header
                and not head
                and self.headers.get("If-Range") in (None, etag)
            ):
                match = re.fullmatch(r"bytes=(\d*)-(\d*)", range_header)
                if not match or not any(match.groups()):
                    self.empty(event, 416, size)
                    return
                first, last = match.groups()
                if first:
                    start = int(first)
                    end = min(int(last), size - 1) if last else size - 1
                else:
                    start = max(0, size - int(last))
                if start >= size or start > end:
                    self.empty(event, 416, size)
                    return
                status = 206
            amount = max(0, end - start + 1)
            with server.condition:
                budget = server.reserved + (0 if head else amount)
                over_budget = budget > server.max_bytes
                if not over_budget:
                    server.reserved = budget
            if over_budget:
                self.empty(event, 503)
                return
            event.update(status=status, start=start, end=end, response_length=amount)
            self.send_response(status)
            self.send_header("Content-Length", str(amount))
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("ETag", etag)
            self.send_header(
                "Last-Modified", self.date_time_string(path.stat().st_mtime)
            )
            if status == 206:
                self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
            self.end_headers()
            if not head:
                with path.open("rb") as source:
                    source.seek(start)
                    remaining = amount
                    while remaining:
                        chunk = source.read(min(256 * 1024, remaining))
                        if not chunk:
                            raise RuntimeError(
                                "Synthetic capture changed during request"
                            )
                        self.wfile.write(chunk)
                        event["body_bytes"] += len(chunk)
                        remaining -= len(chunk)
            event["completed"] = True
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            event["disconnected"] = True
        finally:
            event["duration_s"] = time.perf_counter() - started
            with server.condition:
                server.active -= 1
                server.condition.notify_all()

    def empty(self, event, status, size=None):
        event["status"] = status
        self.send_response(status)
        if status != 304:
            self.send_header("Content-Length", "0")
        if size is not None:
            self.send_header("Content-Range", f"bytes */{size}")
        self.end_headers()
        event["completed"] = True


def packet(frame_size, port):
    payload = bytes(frame_size - 54)
    ethernet = bytes.fromhex("aabbccddeeff0011223344550800")
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        69,
        0,
        frame_size - 14,
        42,
        0,
        64,
        6,
        0,
        bytes([192, 0, 2, 1]),
        bytes([198, 51, 100, 2]),
    )
    tcp = struct.pack(
        "!HHIIBBHHH", 12345, port, 1, 0, 80, 2 if port == 443 else 24, 4096, 0, 0
    )
    return (
        struct.pack("<IIII", 1700000000, 0, frame_size, frame_size)
        + ethernet
        + ip
        + tcp
        + payload
    )


def generate(directory, frame_size, records, files):
    directory.mkdir(parents=True, exist_ok=True)
    pair = [packet(frame_size, 443), packet(frame_size, 53)]
    result, offset = {}, 0
    for index in range(files):
        count = records // files + (index < records % files)
        name = f"frame-{frame_size}-files-{files}-{index}.pcap"
        path = directory / name
        first, second = pair[offset % 2], pair[(offset + 1) % 2]
        with path.open("wb") as output:
            output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            pairs = count // 2
            for begin in range(0, pairs, 512):
                output.write((first + second) * min(512, pairs - begin))
            if count % 2:
                output.write(first)
        offset += count
        result["/" + name] = path
    return result


def query(case, paths):
    function, projection, predicate = CASES[case]
    expression = "[" + ",".join(quote(path) for path in paths) + "]"
    return f"SELECT {projection} FROM {function}({expression})" + (
        " WHERE " + predicate if predicate else ""
    )


def cache_snapshot(connection):
    return connection.query(
        "SELECT count(*) AS entries, coalesce(sum(nr_bytes),0) AS bytes, "
        "coalesce(sum(CASE WHEN loaded THEN nr_bytes ELSE 0 END),0) AS resident_bytes "
        "FROM duckdb_external_file_cache()"
    )[0]


def request_summary(events, source_bytes):
    counts = Counter(event["method"] for event in events)
    body_bytes = sum(event["body_bytes"] for event in events)
    return {
        "requests": len(events),
        "head_requests": counts["HEAD"],
        "get_requests": counts["GET"],
        "range_requests": sum(
            event["method"] == "GET" and event["range"] is not None for event in events
        ),
        "response_body_bytes": body_bytes,
        "body_to_source_ratio": body_bytes / source_bytes,
        "statuses": dict(Counter(str(event["status"]) for event in events)),
        "get_body_size_counts": dict(
            Counter(
                str(event["body_bytes"]) for event in events if event["method"] == "GET"
            )
        ),
        "incomplete_responses": sum(not event["completed"] for event in events),
    }


def configure(connection, profile, threads):
    connection.query("LOAD httpfs")
    external, metadata = PROFILES[profile]
    for statement in [
        f"SET threads={threads}",
        f"SET enable_external_file_cache={str(external).lower()}",
        f"SET enable_http_metadata_cache={str(metadata).lower()}",
        "SET http_retries=0",
        "SET http_timeout=10",
    ]:
        connection.query(statement)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--library", type=Path, default=ROOT / "build/release/src/libduckdb.so"
    )
    parser.add_argument(
        "--size-mib", type=int, default=8, help="approximate record bytes per layout"
    )
    parser.add_argument("--frame-sizes", nargs="+", type=int, default=[1024, 60000])
    parser.add_argument("--files", nargs="+", type=int, default=[1, 8])
    parser.add_argument("--latency-ms", nargs="+", type=float, default=[0, 10])
    parser.add_argument("--threads", type=int, default=8)
    parser.add_argument("--trials", type=int, default=2)
    parser.add_argument("--cases", nargs="+", choices=list(CASES), default=list(CASES))
    parser.add_argument(
        "--cache-profiles", nargs="+", choices=list(PROFILES), default=list(PROFILES)
    )
    parser.add_argument(
        "--max-requests", type=int, default=2048, help="per-query request safety cap"
    )
    parser.add_argument(
        "--output", type=Path, default=ROOT / "build/remote-reads/report.json"
    )
    args = parser.parse_args()
    if (
        min(args.size_mib, args.threads, args.trials, args.max_requests, *args.files)
        < 1
    ):
        parser.error("sizes, counts, and limits must be positive")
    if any(size < 54 or size > 65549 for size in args.frame_sizes) or any(
        not math.isfinite(value) or value < 0 for value in args.latency_ms
    ):
        parser.error("frame sizes must be 54..65549 and latency nonnegative")
    args.library, args.output = args.library.resolve(), args.output.resolve()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    directory = ROOT / "build/remote-reads"
    with Connection(args.library) as connection:
        configure(connection, "default", args.threads)
        metadata = {
            "duckdb": connection.query("SELECT version() AS version"),
            "extensions": connection.query(
                "SELECT extension_name, extension_version FROM duckdb_extensions() WHERE loaded"
            ),
            "settings": connection.query(
                "SELECT name,value FROM duckdb_settings() WHERE name IN "
                "('httpfs_client_implementation','http_keep_alive','http_retries','http_timeout',"
                "'enable_external_file_cache','enable_http_metadata_cache','validate_external_file_cache')"
            ),
        }
    report = {
        "status": "running",
        "benchmark_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "metadata": metadata,
        "library": str(args.library),
        "os": platform.platform(),
        "logical_cpus": os.cpu_count(),
        "revision": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "working_tree": subprocess.check_output(
            ["git", "status", "--short"], cwd=ROOT, text=True
        ),
        "parameters": {
            key: str(value) if isinstance(value, Path) else value
            for key, value in vars(args).items()
        },
        "method": {
            "backend": "loopback HTTP/1.1 byte-range server, real installed httpfs",
            "latency": "fixed delay per HTTP request before response headers, not bandwidth shaping",
            "first": "new in-memory DuckDB instance; filesystem/OS cache state is uncontrolled",
            "repeat": "identical SQL/URLs on the same connection immediately after first query",
            "bytes": "response body bytes written by the server; excludes HTTP headers and TCP/TLS overhead",
            "cpu": "query interval process CPU includes DuckDB and the Python HTTP server",
            "cache": "external cache snapshots are observable residency, not hit-rate counters; unavailable hit rate remains null",
            "scope": "no S3/R2 authentication, listing, provider cache, billing, or WAN behavior is measured",
        },
        "baselines": [],
        "runs": [],
        "summaries": [],
    }
    for frame_size in args.frame_sizes:
        records = max(max(args.files), args.size_mib * 1024**2 // (frame_size + 16))
        for files in args.files:
            fixtures = generate(directory / "captures", frame_size, records, files)
            source_bytes = sum(path.stat().st_size for path in fixtures.values())
            baselines = {}
            with Connection(args.library) as local:
                for case in args.cases:
                    sql = query(case, fixtures.values())
                    start = time.perf_counter()
                    expected = local.query(sql)
                    elapsed = time.perf_counter() - start
                    plan = local.query("EXPLAIN " + sql)
                    if CASES[case][2]:
                        assert any(
                            "Filters:" in str(row) for row in plan
                        ), "Expected staged filter pushdown"
                    selected = (
                        (records + 1) // 2
                        if case == "selective"
                        else (0 if case == "reject" else records)
                    )
                    assert int(expected[0]["packets"]) == selected, (
                        case,
                        expected,
                        selected,
                    )
                    if "packet_bytes" in expected[0]:
                        assert expected[0]["packet_bytes"] == (
                            str(selected * frame_size) if selected else None
                        )
                    if case == "headers":
                        assert expected[0]["ports"] == str(
                            ((records + 1) // 2) * 443 + (records // 2) * 53
                        )
                        assert expected[0]["payload_bytes"] == str(
                            records * (frame_size - 54)
                        )
                    baselines[case] = expected
                    report["baselines"].append(
                        {
                            "frame_size": frame_size,
                            "files": files,
                            "case": case,
                            "wall_s": elapsed,
                            "result": expected,
                            "plan": plan,
                        }
                    )
            with RangeServer(
                fixtures, max_requests=args.max_requests, max_bytes=source_bytes * 4
            ) as server:
                paths = [server.url + path for path in fixtures]
                for latency in args.latency_ms:
                    server.latency_ms = latency
                    for profile in args.cache_profiles:
                        for case in args.cases:
                            for trial in range(args.trials):
                                with Connection(args.library) as connection:
                                    configure(connection, profile, args.threads)
                                    for phase in ["first", "repeat"]:
                                        before = cache_snapshot(connection)
                                        server.begin()
                                        started, cpu = (
                                            time.perf_counter(),
                                            time.process_time(),
                                        )
                                        error = None
                                        try:
                                            result = connection.query(
                                                query(case, paths)
                                            )
                                        except RuntimeError as exception:
                                            result, error = None, str(exception)
                                        elapsed, used_cpu = (
                                            time.perf_counter() - started,
                                            time.process_time() - cpu,
                                        )
                                        events = server.finish()
                                        row = {
                                            "frame_size": frame_size,
                                            "files": files,
                                            "records": records,
                                            "source_bytes": source_bytes,
                                            "latency_ms": latency,
                                            "cache_profile": profile,
                                            "case": case,
                                            "trial": trial,
                                            "phase": phase,
                                            "wall_s": elapsed,
                                            "process_cpu_s": used_cpu,
                                            "result": result,
                                            "error": error,
                                            "cache_before": before,
                                            "cache_after": cache_snapshot(connection),
                                            "external_cache_hit_rate": None,
                                            "events": events,
                                            **request_summary(events, source_bytes),
                                        }
                                        row["validation_passed"] = (
                                            error is None
                                            and result == baselines[case]
                                            and not row["incomplete_responses"]
                                            and all(
                                                e["status"] in (200, 206, 304)
                                                for e in events
                                            )
                                        )
                                        report["runs"].append(row)
                                        if not row["validation_passed"]:
                                            report["status"] = "failed"
                                        args.output.write_text(
                                            json.dumps(report, indent=2) + "\n"
                                        )
                                        if not row["validation_passed"]:
                                            raise RuntimeError(
                                                f"Remote query failed validation; trace saved to {args.output}: {error or result}"
                                            )
                            for phase in ["first", "repeat"]:
                                rows = [
                                    row
                                    for row in report["runs"]
                                    if all(
                                        row[key] == value
                                        for key, value in {
                                            "frame_size": frame_size,
                                            "files": files,
                                            "latency_ms": latency,
                                            "cache_profile": profile,
                                            "case": case,
                                            "phase": phase,
                                        }.items()
                                    )
                                ]
                                summary = {
                                    key: rows[0][key]
                                    for key in [
                                        "frame_size",
                                        "files",
                                        "latency_ms",
                                        "cache_profile",
                                        "case",
                                        "phase",
                                    ]
                                }
                                for metric in [
                                    "wall_s",
                                    "requests",
                                    "head_requests",
                                    "get_requests",
                                    "response_body_bytes",
                                ]:
                                    values = [row[metric] for row in rows]
                                    summary[metric] = {
                                        "median": statistics.median(values),
                                        "min": min(values),
                                        "max": max(values),
                                    }
                                report["summaries"].append(summary)
                                print(json.dumps(summary), flush=True)
                            args.output.write_text(json.dumps(report, indent=2) + "\n")
    report["status"] = "passed"
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Report: {args.output}")


if __name__ == "__main__":
    main()
