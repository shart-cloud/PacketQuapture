#!/usr/bin/env python3
"""Linux strace I/O check; builds synthetic captures in the ignored build directory."""

from pathlib import Path
import struct, subprocess, re, json

r = Path(__file__).resolve().parents[1]
cli = r / "build/release/duckdb"
p = r / "build/header_reads.pcap"
header = (
    bytes.fromhex("aabbccddeeff0011223344550800")
    + struct.pack(
        "!BBHHHBBH4s4s",
        69,
        0,
        60040,
        42,
        0,
        64,
        6,
        0,
        bytes([192, 0, 2, 1]),
        bytes([198, 51, 100, 2]),
    )
    + struct.pack("!HHIIBBHHH", 12345, 443, 1, 0, 80, 2, 4096, 0, 0)
)
packet = header + bytes(60000)
with p.open("wb") as f:
    f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for _ in range(1000):
        f.write(struct.pack("<IIII", 0, 0, len(packet), len(packet)))
        f.write(packet)
for name, columns in [
    ("metadata", "count(*)"),
    ("ethernet", "count(src_mac)"),
    ("ip", "count(src_ip)"),
    ("tcp", "sum(tcp_flags), sum(payload_length)"),
    ("raw", "sum(octet_length(packet_data)), sum(payload_length)"),
    ("reject_metadata", "sum(octet_length(packet_data))"),
    ("reject_ip", "sum(octet_length(packet_data))"),
    ("reject_tcp", "sum(octet_length(packet_data))"),
    ("accept_tcp", "sum(octet_length(packet_data))"),
]:
    log = r / f"build/header_reads_{name}.log"
    sql = f"select {columns} from read_packets('{p}')"
    predicates = {
        "reject_metadata": "captured_length < 100",
        "reject_ip": "ip_version = 6",
        "reject_tcp": "dst_port = 53",
        "accept_tcp": "tcp_syn AND NOT tcp_ack_flag",
    }
    if name in predicates:
        sql += " WHERE " + predicates[name]
        plan = subprocess.run(
            [str(cli), "-c", "EXPLAIN " + sql],
            text=True,
            capture_output=True,
            check=True,
        ).stdout
        assert "Filters:" in plan, plan
    result = subprocess.run(
        [
            "strace",
            "-f",
            "-yy",
            "-e",
            "trace=read,pread64,lseek",
            "-o",
            str(log),
            str(cli),
            "-json",
            "-c",
            sql,
        ],
        text=True,
        capture_output=True,
        check=True,
    )
    lines = [line for line in log.read_text().splitlines() if f"<{p}>" in line]
    reads = [line for line in lines if re.search(r"\b(read|pread64)\(", line)]
    count = sum(
        int(re.search(r"= (\d+)", line)[1])
        for line in reads
        if re.search(r"= (\d+)", line)
    )
    print(name, count, "bytes read;", result.stdout.strip())
    expected = {
        "metadata": 16024,
        "ethernet": 30024,
        "ip": 50024,
        "tcp": 70024,
        "raw": 60070024,
        "reject_metadata": 16024,
        "reject_ip": 50024,
        "reject_tcp": 70024,
        "accept_tcp": 60070024,
    }[name]
    assert count == expected, (name, count, expected)
# A declared packet longer than its actual file must fail even on a metadata-only scan.
broken = r / "build/truncated_payload.pcap"
broken.write_bytes(p.read_bytes()[: 24 + 16 + 54])
for expression in [
    "count(*)",
    "count(src_ip)",
    "count(tcp_flags)",
    "sum(octet_length(packet_data))",
]:
    proc = subprocess.run(
        [str(cli), "-c", f"select {expression} from read_packets('{broken}')"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode != 0 and "Unexpected end" in proc.stderr, proc
print("Truncated payload errors preserved for every projection depth")

# Named pipes exercise the non-seekable fallback using the same valid and corrupt captures.
import os
import tempfile
import threading

with tempfile.TemporaryDirectory(prefix="header-stream-", dir=r / "build") as directory:
    fifo = Path(directory) / "capture.pcap"
    os.mkfifo(fifo)
    for source in [r / "test/data/protocols/ethernet.pcap", broken]:
        for expression in [
            "count(*)",
            "count(src_mac)",
            "count(src_ip)",
            "sum(tcp_flags)",
            "sum(octet_length(packet_data))",
        ]:
            content = source.read_bytes()

            def feed():
                try:
                    with fifo.open("wb") as stream:
                        stream.write(content)
                except BrokenPipeError:
                    pass

            feeder = threading.Thread(target=feed, daemon=True)
            feeder.start()
            query = f"select {expression} from read_packets('{fifo}')"
            streamed = subprocess.run(
                [str(cli), "-json", "-c", query],
                text=True,
                capture_output=True,
                timeout=20,
            )
            feeder.join(timeout=5)
            assert not feeder.is_alive(), "FIFO reader did not consume its input"
            if source == broken:
                assert streamed.returncode != 0 and "Unexpected end" in streamed.stderr
            else:
                disk = subprocess.run(
                    [str(cli), "-json", "-c", query.replace(str(fifo), str(source))],
                    text=True,
                    capture_output=True,
                    check=True,
                )
                assert streamed.returncode == 0, streamed.stderr
                assert json.loads(streamed.stdout) == json.loads(disk.stdout)
print(
    "Named-pipe results and truncation errors match file reads at all projection depths"
)
