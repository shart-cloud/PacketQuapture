#!/usr/bin/env python3
"""Benchmark real MinIO S3 reads through a counting proxy and clean up owned objects.

Requires AWS CLI, the built DuckDB library, installed httpfs, and an already established
localhost port-forward. Credentials are read only from environment variables, never
written to a report. Creates a uniquely named bucket, then deletes only its own objects.
This proxy preserves the signed Host header; it targets MinIO, not arbitrary AWS endpoints.
"""

import argparse
import hashlib
from http.server import BaseHTTPRequestHandler
import http.client
import json
import os
from pathlib import Path
import platform
import re
import socket
import statistics
import subprocess
import sys
import time
from urllib.parse import urlsplit
import uuid

sys.dont_write_bytecode = True
from benchmark_remote_reads import (
    CASES,
    PROFILES,
    ROOT,
    Connection,
    RangeServer,
    cache_snapshot,
    configure,
    generate,
    query,
    quote,
    request_summary,
)


class MinioProxy(RangeServer):
    def __init__(self, files, upstream, **kwargs):
        super().__init__(files, **kwargs)
        self.upstream = upstream
        self.RequestHandlerClass = ProxyHandler


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.connection.settimeout(15)
        self.backend = http.client.HTTPConnection(*self.server.upstream, timeout=10)

    def finish(self):
        self.backend.close()
        super().finish()

    def log_message(self, *args):
        pass

    def do_HEAD(self):
        self.forward(True)

    def do_GET(self):
        self.forward(False)

    def empty(self, event, code):
        event["status"] = code
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.end_headers()
        event["completed"] = True

    def forward(self, head):
        server = self.server
        event = {
            "method": self.command,
            "path": urlsplit(self.path).path,
            "range": self.headers.get("Range"),
            "status": None,
            "body_bytes": 0,
            "completed": False,
            "start": None,
            "end": None,
        }
        started = time.perf_counter()
        with server.condition:
            server.events.append(event)
            server.active += 1
            over_requests = len(server.events) > server.max_requests
        try:
            if event["path"] not in server.files:
                self.empty(event, 403)
                return
            if over_requests:
                self.empty(event, 503)
                return
            # Preserve Host and Authorization exactly as signed. Never log headers.
            self.backend.request(self.command, self.path, headers=dict(self.headers))
            response = self.backend.getresponse()
            amount = int(response.getheader("Content-Length", "0"))
            with server.condition:
                budget = server.reserved + (0 if head else amount)
                over_bytes = budget > server.max_bytes
                if not over_bytes:
                    server.reserved = budget
            if over_bytes:
                self.backend.close()
                self.empty(event, 503)
                return
            event.update(status=response.status, response_length=amount)
            content_range = response.getheader("Content-Range", "")
            match = re.fullmatch(r"bytes (\d+)-(\d+)/(\d+)", content_range)
            if match:
                event.update(start=int(match[1]), end=int(match[2]))
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() not in [
                    "connection",
                    "transfer-encoding",
                    "server",
                    "date",
                ]:
                    self.send_header(key, value)
            if response.getheader("Content-Length") is None and response.status != 304:
                # Error responses without a length are bounded and connection-delimited.
                self.send_header("Connection", "close")
                self.close_connection = True
            self.end_headers()
            if not head:
                while True:
                    chunk = response.read(256 * 1024)
                    if not chunk:
                        break
                    if event["body_bytes"] + len(chunk) > server.max_bytes:
                        self.close_connection = True
                        self.backend.close()
                        return
                    self.wfile.write(chunk)
                    event["body_bytes"] += len(chunk)
            else:
                response.read()
            event["completed"] = True
        except (OSError, http.client.HTTPException):
            event["upstream_or_client_error"] = True
            self.backend.close()
            self.close_connection = True
        finally:
            event["duration_s"] = time.perf_counter() - started
            with server.condition:
                server.active -= 1
                server.condition.notify_all()


class Credentials:
    def __init__(self):
        self.access = os.environ.get("AWS_ACCESS_KEY_ID", "")
        self.secret = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
        self.token = os.environ.get("AWS_SESSION_TOKEN", "")
        self.region = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
        if not self.access or not self.secret:
            raise RuntimeError(
                "Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in the process environment"
            )

    def redact(self, value):
        for secret in [self.access, self.secret, self.token]:
            if secret:
                value = value.replace(secret, "[redacted]")
        return value

    def configure_connection(self, connection, endpoint, bucket):
        options = [
            "TYPE s3",
            "KEY_ID " + quote(self.access),
            "SECRET " + quote(self.secret),
            "REGION " + quote(self.region),
            "ENDPOINT " + quote(endpoint),
            "URL_STYLE 'path'",
            "USE_SSL false",
            "SCOPE " + quote(f"s3://{bucket}/"),
        ]
        if self.token:
            options.append("SESSION_TOKEN " + quote(self.token))
        try:
            connection.query(
                "CREATE SECRET packetquapture_benchmark (" + ",".join(options) + ")"
            )
        except RuntimeError:
            # The SQL text contains credentials, so never forward its exception text.
            raise RuntimeError(
                "Could not configure the ephemeral benchmark S3 secret"
            ) from None

    def aws(self, endpoint, operation, *args, timeout=60):
        env = {
            **os.environ,
            "AWS_CONFIG_FILE": os.devnull,
            "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
            "AWS_EC2_METADATA_DISABLED": "true",
            "AWS_DEFAULT_REGION": self.region,
        }
        for key in ["AWS_PROFILE", "AWS_DEFAULT_PROFILE"]:
            env.pop(key, None)
        result = subprocess.run(
            [
                "aws",
                "--endpoint-url",
                endpoint,
                "--no-cli-pager",
                "--output",
                "json",
                "s3api",
                operation,
                *args,
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode:
            raise RuntimeError(
                f"{operation} failed: {self.redact(result.stderr)[:1200]}"
            )
        return json.loads(result.stdout) if result.stdout.strip() else {}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--endpoint",
        required=True,
        help="http://127.0.0.1:PORT from an existing MinIO port-forward",
    )
    parser.add_argument(
        "--library", type=Path, default=ROOT / "build/release/src/libduckdb.so"
    )
    parser.add_argument("--size-mib", type=int, default=8)
    parser.add_argument("--frame-sizes", nargs="+", type=int, default=[1024])
    parser.add_argument("--files", nargs="+", type=int, default=[1, 8])
    parser.add_argument("--trials", type=int, default=2)
    parser.add_argument("--threads", type=int, default=8)
    parser.add_argument(
        "--memory-limits-mib",
        nargs="+",
        type=int,
        default=[0],
        help="DuckDB memory limits per profile; 0 keeps the database default",
    )
    parser.add_argument(
        "--query-timeout",
        type=int,
        default=30,
        help="Seconds before interrupting a measured or local baseline query",
    )
    parser.add_argument(
        "--upload-timeout",
        type=int,
        default=60,
        help="Seconds allowed for each synthetic-object upload",
    )
    parser.add_argument(
        "--cases",
        nargs="+",
        choices=list(CASES),
        default=["metadata", "selective", "raw"],
    )
    parser.add_argument(
        "--cache-profiles", nargs="+", choices=list(PROFILES), default=list(PROFILES)
    )
    parser.add_argument(
        "--output", type=Path, default=ROOT / "build/remote-reads/minio.json"
    )
    args = parser.parse_args()
    endpoint = urlsplit(args.endpoint)
    if (
        endpoint.scheme != "http"
        or endpoint.hostname != "127.0.0.1"
        or not endpoint.port
        or endpoint.username
        or endpoint.path not in ("", "/")
        or endpoint.query
        or endpoint.fragment
    ):
        parser.error("Use a plain HTTP localhost MinIO port-forward endpoint")
    if (
        min(
            args.size_mib,
            args.trials,
            args.threads,
            args.query_timeout,
            args.upload_timeout,
            *args.files,
        )
        < 1
        or any(limit < 0 for limit in args.memory_limits_mib)
        or any(size < 54 or size > 65549 for size in args.frame_sizes)
    ):
        parser.error("positive counts and 54..65549 byte frames are required")
    args.library, args.output = args.library.resolve(), args.output.resolve()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    credentials = Credentials()
    bucket = "packetquapture-bench-" + uuid.uuid4().hex[:16]
    attempted_keys, created = [], False
    report = {
        "status": "running",
        "bucket": bucket,
        "cleanup": {"bucket_deleted": False},
        "benchmark_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "shared_harness_sha256": hashlib.sha256(
            (ROOT / "scripts/benchmark_remote_reads.py").read_bytes()
        ).hexdigest(),
        "revision": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "os": platform.platform(),
        "logical_cpus": os.cpu_count(),
        "parameters": {
            key: str(value) if isinstance(value, Path) else value
            for key, value in vars(args).items()
            if key != "endpoint"
        },
        "method": {
            "backend": "real MinIO via a Kubernetes port-forward and non-caching counting proxy",
            "scope": "literal S3 object lists, signed requests; no listing, production data, AWS S3, R2, or cost claims",
            "bytes": "MinIO response payload bytes forwarded to DuckDB, excludes headers/tunnel overhead",
            "timing": "includes local proxy and port-forward overhead; not direct-endpoint throughput",
            "cache": "first=new database; repeat=identical SQL on same connection; hit rate unavailable",
            "credentials": "environment and ephemeral database secret only; never included in reports",
            "control_requests": "bucket creation, upload, and cleanup are excluded from query counters",
        },
        "baselines": [],
        "runs": [],
        "summaries": [],
    }

    def save():
        args.output.write_text(credentials.redact(json.dumps(report, indent=2)) + "\n")

    try:
        credentials.aws(args.endpoint, "create-bucket", "--bucket", bucket)
        created = True
        save()
        with Connection(args.library) as connection:
            configure(connection, "default", args.threads)
            report["metadata"] = {
                "duckdb": connection.query("SELECT version() AS version"),
                "extensions": connection.query(
                    "SELECT extension_name,extension_version FROM duckdb_extensions() WHERE loaded"
                ),
            }
        for frame in args.frame_sizes:
            records = max(max(args.files), args.size_mib * 1024**2 // (frame + 16))
            for files in args.files:
                fixtures = generate(
                    ROOT / "build/remote-reads/minio-captures", frame, records, files
                )
                source_bytes = sum(path.stat().st_size for path in fixtures.values())
                print(
                    f"Uploading {files} objects, {source_bytes} bytes total", flush=True
                )
                for path in fixtures.values():
                    attempted_keys.append(path.name)
                    credentials.aws(
                        args.endpoint,
                        "put-object",
                        "--bucket",
                        bucket,
                        "--key",
                        path.name,
                        "--body",
                        str(path),
                        timeout=args.upload_timeout,
                    )
                allowed = {f"/{bucket}/{path.name}": path for path in fixtures.values()}
                baselines = {}
                with Connection(args.library) as local:
                    for case in args.cases:
                        result = local.query(
                            query(case, fixtures.values()), timeout=args.query_timeout
                        )
                        selected = (
                            (records + 1) // 2
                            if case == "selective"
                            else (0 if case == "reject" else records)
                        )
                        assert int(result[0]["packets"]) == selected
                        baselines[case] = result
                        report["baselines"].append(
                            {
                                "frame_size": frame,
                                "files": files,
                                "case": case,
                                "result": result,
                            }
                        )
                with MinioProxy(
                    allowed,
                    (endpoint.hostname, endpoint.port),
                    max_bytes=source_bytes * 4,
                ) as proxy:
                    uris = [f"s3://{bucket}/{path.name}" for path in fixtures.values()]
                    for memory_limit in args.memory_limits_mib:
                        for profile in args.cache_profiles:
                            for case in args.cases:
                                for trial in range(args.trials):
                                    with Connection(args.library) as connection:
                                        configure(connection, profile, args.threads)
                                        if memory_limit:
                                            connection.query(
                                                "SET memory_limit="
                                                + quote(f"{memory_limit}MiB")
                                            )
                                        effective_limit = connection.query(
                                            "SELECT current_setting('memory_limit') AS value"
                                        )[0]["value"]
                                        credentials.configure_connection(
                                            connection,
                                            f"127.0.0.1:{proxy.server_port}",
                                            bucket,
                                        )
                                        for phase in ["first", "repeat"]:
                                            print(
                                                f"Starting {files} files, {memory_limit or 'default'} MiB, {profile}, {case}, trial {trial}, {phase}",
                                                flush=True,
                                            )
                                            before = cache_snapshot(connection)
                                            proxy.begin()
                                            started, cpu = (
                                                time.perf_counter(),
                                                time.process_time(),
                                            )
                                            error, result = None, None
                                            try:
                                                result = connection.query(
                                                    query(case, uris),
                                                    timeout=args.query_timeout,
                                                )
                                            except RuntimeError as exception:
                                                error = credentials.redact(
                                                    str(exception)
                                                )
                                            elapsed, used_cpu = (
                                                time.perf_counter() - started,
                                                time.process_time() - cpu,
                                            )
                                            events = proxy.finish()
                                            row = {
                                                "frame_size": frame,
                                                "files": files,
                                                "records": records,
                                                "source_bytes": source_bytes,
                                                "cache_profile": profile,
                                                "memory_limit_mib": memory_limit,
                                                "effective_memory_limit": effective_limit,
                                                "case": case,
                                                "trial": trial,
                                                "phase": phase,
                                                "wall_s": elapsed,
                                                "process_cpu_s": used_cpu,
                                                "result": result,
                                                "error": error,
                                                "cache_before": before,
                                                "cache_after": cache_snapshot(
                                                    connection
                                                ),
                                                "external_cache_hit_rate": None,
                                                "events": events,
                                                **request_summary(events, source_bytes),
                                            }
                                            row["validation_passed"] = (
                                                error is None
                                                and result == baselines[case]
                                                and not row["incomplete_responses"]
                                                and all(
                                                    event["status"] in (200, 206, 304)
                                                    for event in events
                                                )
                                            )
                                            report["runs"].append(row)
                                            save()
                                            if not row["validation_passed"]:
                                                raise RuntimeError(
                                                    "MinIO query failed validation: "
                                                    + str(error or result)
                                                )
                                for phase in ["first", "repeat"]:
                                    selected = [
                                        row
                                        for row in report["runs"]
                                        if all(
                                            row[key] == value
                                            for key, value in {
                                                "frame_size": frame,
                                                "files": files,
                                                "case": case,
                                                "cache_profile": profile,
                                                "memory_limit_mib": memory_limit,
                                                "phase": phase,
                                            }.items()
                                        )
                                    ]
                                    summary = {
                                        key: selected[0][key]
                                        for key in [
                                            "frame_size",
                                            "files",
                                            "case",
                                            "cache_profile",
                                            "memory_limit_mib",
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
                                        values = [row[metric] for row in selected]
                                        summary[metric] = {
                                            "median": statistics.median(values),
                                            "min": min(values),
                                            "max": max(values),
                                        }
                                    report["summaries"].append(summary)
                                    print(json.dumps(summary), flush=True)
                                save()
        report["status"] = "passed"
    except Exception as exception:
        report["status"] = "failed"
        report["error"] = credentials.redact(str(exception))
        raise RuntimeError(report["error"]) from None
    finally:
        if created:
            try:
                # This invocation's unique bucket and explicit synthetic key manifest only.
                if attempted_keys:
                    deletion = json.dumps(
                        {
                            "Objects": [{"Key": key} for key in attempted_keys],
                            "Quiet": True,
                        }
                    )
                    response = credentials.aws(
                        args.endpoint,
                        "delete-objects",
                        "--bucket",
                        bucket,
                        "--delete",
                        deletion,
                    )
                    if response.get("Errors"):
                        raise RuntimeError(
                            "Some benchmark objects could not be deleted"
                        )
                credentials.aws(args.endpoint, "delete-bucket", "--bucket", bucket)
                report["cleanup"] = {
                    "bucket_deleted": True,
                    "object_count": len(attempted_keys),
                }
            except Exception as exception:
                report["cleanup"]["error"] = credentials.redact(str(exception))
                report["status"] = "cleanup_failed"
        save()
    if not report["cleanup"]["bucket_deleted"]:
        raise RuntimeError(
            "Benchmark cleanup failed; see the owned bucket name in the report"
        )
    print(f"Report: {args.output}; temporary bucket deleted", flush=True)


if __name__ == "__main__":
    main()
