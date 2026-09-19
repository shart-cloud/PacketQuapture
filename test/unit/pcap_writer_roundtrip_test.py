#!/usr/bin/env python3
"""Read standalone writer artifacts through all packet readers; COPY is not registered yet."""

from pathlib import Path
import os
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from benchmark_remote_reads import Connection, quote


def main():
    with tempfile.TemporaryDirectory(prefix="writer-roundtrip-", dir=ROOT / "build") as temp:
        folder = Path(temp)
        executable = folder / "writer_test"
        subprocess.run(
            [
                os.environ.get("CXX", "c++"),
                "-std=c++11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-O1",
                "-Isrc/include",
                "src/pcap_writer.cpp",
                "test/unit/pcap_writer_test.cpp",
                "-o",
                str(executable),
            ],
            cwd=ROOT,
            check=True,
        )
        subprocess.run([str(executable), str(folder)], cwd=ROOT, check=True)
        times = [0, 999999, 1000000, 2147483647999999, 2147483648000000, 4294967295999999]
        expected = [
            {
                "packet_number": str(i + 1),
                "timestamp_us": str(t),
                "captured_length": "3",
                "original_length": "5",
                "link_type": "1",
                "payload_hex": "0080FF",
            }
            for i, t in enumerate(times)
        ]
        with Connection(ROOT / "build/release/src/libduckdb.so") as connection:
            for reader in ["read_pcap", "read_packets", "read_dns"]:
                if reader == "read_dns":
                    assert connection.query(f"SELECT count(*) n FROM {reader}({quote(folder / 'oracle.pcap')})") == [
                        {"n": "0"}
                    ]
                else:
                    actual = connection.query(
                        f"SELECT packet_number,epoch_us(timestamp) timestamp_us,captured_length,original_length,link_type,hex(packet_data) AS payload_hex FROM {reader}({quote(folder / 'oracle.pcap')}) ORDER BY packet_number"
                    )
                    assert actual == expected, (reader, actual)
                assert connection.query(f"SELECT count(*) n FROM {reader}({quote(folder / 'empty.pcap')})") == [
                    {"n": "0"}
                ]
            assert connection.query(
                f"SELECT captured_length,original_length,hex(packet_data) AS payload_hex FROM read_pcap({quote(folder / 'zero.pcap')})"
            ) == [{"captured_length": "0", "original_length": "4294967295", "payload_hex": ""}]
            assert connection.query(
                f"SELECT src_ip,dst_ip,src_port,dst_port FROM read_packets({quote(folder / 'udp.pcap')})"
            ) == [{"src_ip": "192.0.2.1", "dst_ip": "192.0.2.2", "src_port": "12345", "dst_port": "9999"}]
        print(
            "Writer payload, lengths, link type, empty/zero records and unsigned timestamp boundaries round-trip through PacketQuapture"
        )


if __name__ == "__main__":
    main()
