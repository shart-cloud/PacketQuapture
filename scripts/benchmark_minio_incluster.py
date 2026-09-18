#!/usr/bin/env python3
"""Bounded private in-cluster MinIO benchmark; only synthetic owned objects are modified.
Run in a disposable pod with boto3, the current libduckdb and matching httpfs installed.
Credentials stay in environment/ephemeral DuckDB secrets; only allowlisted HTTP fields leave memory.
"""

import argparse, json, os, time, uuid, hashlib, threading
from pathlib import Path
import boto3
from botocore.config import Config
from benchmark_remote_reads import (
    Connection,
    configure,
    generate,
    query,
    quote,
    cache_snapshot,
)
from benchmark_minio_reads import Credentials, MinioProxy


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--size-mib", type=int, default=8)
    p.add_argument("--trials", type=int, default=1)
    p.add_argument("--memory-limits-mib", type=int, nargs="+", default=[32])
    p.add_argument(
        "--modes", nargs="+", choices=["direct", "proxy"], default=["direct"]
    )
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    if (
        not 1 <= a.size_mib <= 1024
        or not 1 <= a.trials <= 3
        or any(x < 32 or x > 2048 for x in a.memory_limits_mib)
    ):
        p.error("bounded to 1..1024 MiB, 1..3 trials, and 32..2048 MiB memory")
    endpoint = "http://minio.trawl-system.svc.cluster.local:9000"
    cred = Credentials()
    s3 = boto3.client(
        "s3",
        endpoint_url=endpoint,
        config=Config(
            signature_version="s3v4",
            connect_timeout=5,
            read_timeout=120,
            retries={"max_attempts": 0},
        ),
    )
    bucket = "packetquapture-bench-" + uuid.uuid4().hex[:16]
    owned = []
    created = False
    lib = Path("/work/build/release/src/libduckdb.so")
    report = {
        "status": "running",
        "bucket": bucket,
        "parameters": vars(a) | {"output": str(a.output)},
        "runs": [],
        "method": {
            "path": "private ClusterIP within same Kubernetes node as MinIO",
            "requests": "DuckDB in-memory HTTP logs, only method/status/response Content-Length exported",
            "bytes": "sum successful GET response Content-Length; excludes HTTP overhead, not independent wire measurement",
            "timing": "HTTP logging enabled; direct has no proxy or Kubernetes tunnel; proxy mode adds local counting proxy",
            "threads": 8,
            "pod_cpu_limit": 4,
            "pod_memory_limit": "4Gi",
            "first": "fresh DuckDB database, not cold storage or OS cache",
        },
        "library_sha256": hashlib.sha256(lib.read_bytes()).hexdigest(),
        "cleanup": {},
    }

    def save():
        a.output.write_text(cred.redact(json.dumps(report, indent=2)) + "\n")

    try:
        s3.create_bucket(Bucket=bucket)
        created = True
        save()
        records = a.size_mib * 1024**2 // 1040
        with Connection(lib) as c:
            configure(c, "default", 8)
            report["version"] = c.query("select version() as version")
            report["extensions"] = c.query(
                "select extension_name,extension_version from duckdb_extensions() where loaded"
            )
        for files in [1, 8]:
            fixtures = generate(Path("/work/captures"), 1024, records, files)
            source = sum(x.stat().st_size for x in fixtures.values())
            for path in fixtures.values():
                owned.append(path.name)
                with path.open("rb") as f:
                    s3.put_object(Bucket=bucket, Key=path.name, Body=f)
            with Connection(lib) as c:
                baseline = c.query(query("metadata", fixtures.values()), timeout=120)
                assert int(baseline[0]["packets"]) == records
            uris = [f"s3://{bucket}/{x.name}" for x in fixtures.values()]
            for mode in a.modes:
                proxy = None
                if mode == "proxy":
                    proxy = MinioProxy(
                        {f"/{bucket}/{x.name}": x for x in fixtures.values()},
                        ("minio.trawl-system.svc.cluster.local", 9000),
                        max_bytes=source * 4,
                    )
                    proxy.__enter__()
                try:
                    for limit in a.memory_limits_mib:
                        for profile in ["default", "external_off"]:
                            for trial in range(a.trials):
                                with Connection(lib) as c:
                                    configure(c, profile, 8)
                                    c.query(
                                        "SET memory_limit=" + quote(str(limit) + "MiB")
                                    )
                                    cred.configure_connection(
                                        c,
                                        (
                                            f"127.0.0.1:{proxy.server_port}"
                                            if proxy
                                            else endpoint.removeprefix("http://")
                                        ),
                                        bucket,
                                    )
                                    c.query(
                                        "CALL enable_logging('HTTP', storage='memory')"
                                    )
                                    for phase in ["first", "repeat"]:
                                        c.query("CALL truncate_duckdb_logs()")
                                        before = cache_snapshot(c)
                                        samples = []
                                        stop = threading.Event()

                                        def sample():
                                            while not stop.is_set():
                                                for line in (
                                                    Path("/proc/self/status")
                                                    .read_text()
                                                    .splitlines()
                                                ):
                                                    if line.startswith("VmRSS:"):
                                                        samples.append(
                                                            int(line.split()[1]) * 1024
                                                        )
                                                stop.wait(0.02)

                                        t = threading.Thread(target=sample)
                                        t.start()
                                        if proxy:
                                            proxy.begin()
                                        start = time.perf_counter()
                                        try:
                                            result = c.query(
                                                query("metadata", uris), timeout=120
                                            )
                                        finally:
                                            elapsed = time.perf_counter() - start
                                            stop.set()
                                            t.join()
                                        events = proxy.finish() if proxy else None
                                        after = cache_snapshot(c)
                                        # Do not serialize request URLs or headers: they can contain signed credentials.
                                        logs = c.query(
                                            """SELECT request.type AS method, response.status AS status,
                                            coalesce(element_at(response.headers,'Content-Length')[1],
                                                     element_at(response.headers,'content-length')[1]) AS length
                                            FROM duckdb_logs_parsed('HTTP')"""
                                        )
                                        gets = [x for x in logs if x["method"] == "GET"]
                                        heads = [
                                            x for x in logs if x["method"] == "HEAD"
                                        ]
                                        row = {
                                            "mode": mode,
                                            "files": files,
                                            "memory_limit_mib": limit,
                                            "cache_profile": profile,
                                            "trial": trial,
                                            "phase": phase,
                                            "wall_s": elapsed,
                                            "source_bytes": source,
                                            "result": result,
                                            "get_requests": len(gets),
                                            "head_requests": len(heads),
                                            "response_body_bytes": sum(
                                                int(x["length"] or 0) for x in gets
                                            ),
                                            "statuses": sorted(
                                                set(x["status"] for x in logs)
                                            ),
                                            "cache_before": before,
                                            "cache_after": after,
                                            "sampled_peak_rss_bytes": (
                                                max(samples) if samples else None
                                            ),
                                        }
                                        assert (
                                            result == baseline
                                        ), "packet count mismatch"
                                        assert (
                                            len(heads) == files
                                        ), "HTTP logging did not capture expected HEADs"
                                        assert all(
                                            x["length"] is not None for x in gets
                                        ), "missing response lengths"
                                        assert all(
                                            x["status"]
                                            in [
                                                "OK_200",
                                                "PartialContent_206",
                                                "NotModified_304",
                                                "200",
                                                "206",
                                                "304",
                                            ]
                                            for x in logs
                                        ), "unexpected HTTP status: " + str(
                                            row["statuses"]
                                        )
                                        assert (
                                            len(logs) <= 2048
                                            and row["response_body_bytes"] <= source * 4
                                        ), "request/byte budget exceeded"
                                        if events is not None:
                                            row["proxy_get_requests"] = sum(
                                                e["method"] == "GET" for e in events
                                            )
                                            row["proxy_body_bytes"] = sum(
                                                e["body_bytes"] for e in events
                                            )
                                            assert (
                                                row["proxy_get_requests"] == len(gets)
                                                and row["proxy_body_bytes"]
                                                == row["response_body_bytes"]
                                            ), "HTTP log/proxy disagreement"
                                        row["validation_passed"] = True
                                        report["runs"].append(row)
                                        save()
                                        print(
                                            json.dumps(
                                                {
                                                    k: row[k]
                                                    for k in [
                                                        "mode",
                                                        "files",
                                                        "memory_limit_mib",
                                                        "cache_profile",
                                                        "trial",
                                                        "phase",
                                                        "wall_s",
                                                        "get_requests",
                                                        "response_body_bytes",
                                                    ]
                                                }
                                            ),
                                            flush=True,
                                        )
                finally:
                    if proxy:
                        proxy.__exit__(None, None, None)
            for path in fixtures.values():
                path.unlink()
        report["status"] = "passed"
    except Exception as e:
        report["status"] = "failed"
        report["error"] = cred.redact(str(e))
        raise RuntimeError(report["error"]) from None
    finally:
        if created:
            try:
                if owned:
                    response = s3.delete_objects(
                        Bucket=bucket,
                        Delete={"Objects": [{"Key": k} for k in owned], "Quiet": True},
                    )
                    if response.get("Errors"):
                        raise RuntimeError("owned-object deletion failed")
                s3.delete_bucket(Bucket=bucket)
                report["cleanup"] = {"bucket_deleted": True, "object_count": len(owned)}
            except Exception as e:
                report["status"] = "cleanup_failed"
                report["cleanup"] = {"error": cred.redact(str(e))}
        save()
    if report["status"] != "passed":
        raise RuntimeError("benchmark did not pass")


if __name__ == "__main__":
    main()
