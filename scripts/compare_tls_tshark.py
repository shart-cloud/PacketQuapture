#!/usr/bin/env python3
"""Compare read_tls hello lists and fingerprints with tshark, handshake by handshake.

tshark is the reference implementation for the parsed lists and the JA3/JA3S
fingerprints computed from them, and for JA4 apart from one documented
difference: tshark 4.2.2 hashes an empty list, where the JA4 specification and
both FoxIO implementations write 000000000000. tshark has no JA4S; with
--foxio, JA4S is compared with the FoxIO python reference (FoxIO-LLC/ja4,
python/ja4.py, pinned at 16b96d9), which is not part of this repository. Expected values in the SQL tests are literals
taken from tshark; this script is how they were checked, and how a corpus
sample is compared before a fingerprint PR.

    python3 scripts/compare_tls_tshark.py test/data/tls/*.pcap
    python3 scripts/compare_tls_tshark.py --duckdb build/release/duckdb capture.pcap
    python3 scripts/compare_tls_tshark.py --foxio ~/src/ja4/python/ja4.py capture.pcap

Rows are matched on the oriented connection and the nth hello of each type.
Exits non-zero on any disagreement that is not a documented divergence.
"""

import argparse
import collections
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# (our column, tshark field, hello type, tshark renders it as hex)
LISTS = [
    ("client_cipher_suites", "tls.handshake.ciphersuite", 1, True),
    ("client_extensions", "tls.handshake.extension.type", 1, False),
    ("client_supported_groups", "tls.handshake.extensions_supported_group", 1, True),
    ("client_signature_algorithms", "tls.handshake.sig_hash_alg", 1, True),
    ("client_supported_versions", "tls.handshake.extensions.supported_version", 1, True),
    ("client_ec_point_formats", "tls.handshake.extensions_ec_point_format", 1, False),
    ("client_alpn", "tls.handshake.extensions_alpn_str", 1, None),
    ("server_extensions", "tls.handshake.extension.type", 2, False),
    ("server_alpn", "tls.handshake.extensions_alpn_str", 2, None),
    ("ja3", "tls.handshake.ja3", 1, None),
    ("ja3_full", "tls.handshake.ja3_full", 1, None),
    ("ja3s", "tls.handshake.ja3s", 2, None),
    ("ja3s_full", "tls.handshake.ja3s_full", 2, None),
    ("ja4", "tls.handshake.ja4", 1, None),
    ("ja4_r", "tls.handshake.ja4_r", 1, None),
]
# Columns holding one value rather than a list.
SCALARS = {"server_alpn", "ja3", "ja3_full", "ja3s", "ja3s_full", "ja4", "ja4_r"}
EMPTY_SHA256_12 = "e3b0c44298fc"
# Lists every parsed hello has: tshark shows no field for an empty one.
ALWAYS_PRESENT = {"client_cipher_suites", "client_extensions", "server_extensions"}
AMBIGUOUS = object()
KEY_FIELDS = ["ip.src", "tcp.srcport", "ip.dst", "tcp.dstport", "tls.handshake.type"]


def tshark_hellos(path):
    # JSON rather than delimited fields: a GREASE ALPN identifier is two newline
    # bytes and would split a line-oriented record.
    fields = KEY_FIELDS + sorted({field for _, field, _, _ in LISTS})
    command = ["tshark", "-r", str(path), "-Y", "tls.handshake.type == 1 || tls.handshake.type == 2",
               "-T", "json"]
    for field in fields:
        command += ["-e", field]
    output = subprocess.run(command, check=True, capture_output=True).stdout.decode("utf-8", "replace")
    hellos = collections.defaultdict(list)
    for packet in json.loads(output or "[]"):
        values = packet["_source"]["layers"]
        kinds = [int(kind) for kind in values["tls.handshake.type"] if kind in ("1", "2")]
        src = (values["ip.src"][0], int(values["tcp.srcport"][0]))
        dst = (values["ip.dst"][0], int(values["tcp.dstport"][0]))
        for kind in kinds:
            key = src + dst if kind == 1 else dst + src
            # tshark concatenates the lists of every hello in a packet, so a
            # packet holding several cannot be split back into hellos.
            hellos[(key, kind)].append(values if len(kinds) == 1 else AMBIGUOUS)
    return hellos


def ours(path, duckdb):
    # The CLI's JSON mode renders lists unquoted and this build has no json
    # extension, so each list travels as a unit-separated string.
    def encode(column):
        if column in SCALARS:
            return column
        return f"array_to_string(list_transform({column}, lambda x: x::VARCHAR), chr(31)) AS {column}"

    columns = ", ".join(encode(column) for column, _, _, _ in LISTS)
    query = (f"SELECT client_ip, client_port, server_ip, server_port, client_hello, server_hello, "
             f"array_to_string(warnings, ',') AS warnings, reassembly_status, {columns} "
             f"FROM read_tls('{path}') ORDER BY client_ip, client_port, handshake_number")
    output = subprocess.run([duckdb, "-json", "-c", query], check=True, capture_output=True, cwd=ROOT).stdout
    rows = json.loads(output.strip() or b"[]")
    for row in rows:
        for column, _, _, hex_values in LISTS:
            value = row[column]
            if value is None or column in SCALARS:
                continue
            parts = value.split("\x1f") if value else []
            row[column] = parts if hex_values is None else [int(part) for part in parts]
    return rows


def reference_value(parts, hex_values):
    if not parts:
        return None
    if hex_values is None:
        return parts
    return [int(part, 16) if hex_values else int(part) for part in parts]


def compare(path, duckdb):
    reference = tshark_hellos(path)
    seen = collections.Counter()
    failures = divergences = checked = skipped = 0
    for row in ours(path, duckdb):
        key = (row["client_ip"], row["client_port"], row["server_ip"], row["server_port"])
        for column, field, kind, hex_values in LISTS:
            if not row["client_hello" if kind == 1 else "server_hello"]:
                continue
            index = seen[(key, kind, column)]
            seen[(key, kind, column)] += 1
            candidates = reference.get((key, kind), [])
            if index >= len(candidates):
                print(f"{path}: {key} hello {kind}: tshark has no matching hello")
                failures += 1
                continue
            if candidates[index] is AMBIGUOUS:
                skipped += 1
                continue
            expected = reference_value(candidates[index].get(field), hex_values)
            if expected is None and column in ALWAYS_PRESENT:
                expected = []
            actual = row[column]
            if column in SCALARS and expected is not None:
                expected = expected[0] if len(expected) == 1 else expected
            if hex_values is None and expected is not None:
                # tshark cannot render arbitrary bytes faithfully; compare only
                # identifiers that are printable ASCII on both sides.
                values = expected if isinstance(expected, list) else [expected]
                if any(not v.isascii() or not v.isprintable() for v in values):
                    continue
            checked += 1
            if expected == actual:
                continue
            if actual is None and "list_malformed" in row["warnings"]:
                divergences += 1
                continue
            if actual is None and row["reassembly_status"] == "limit":
                divergences += 1
                continue
            if column == "ja4" and actual and expected and \
                    expected.replace(EMPTY_SHA256_12, "000000000000") == actual:
                divergences += 1
                continue
            print(f"{path}: {key} {column}: tshark {expected!r}, read_tls {actual!r}")
            failures += 1
    # Hellos tshark decoded that no read_tls row accounts for. Not a list
    # disagreement, but coverage the comparison would otherwise hide.
    used = collections.Counter()
    for (key, kind, _), count in seen.items():
        used[(key, kind)] = max(used[(key, kind)], count)
    missed = 0
    for (key, kind), candidates in reference.items():
        extra = len(candidates) - used[(key, kind)]
        if extra > 0:
            missed += extra
            print(f"{path}: {key} hello {kind}: {extra} decoded by tshark, not reported by read_tls")
    return checked, failures, divergences, skipped, missed


def foxio_ja4s(path, script):
    """JA4S per connection from the FoxIO python reference, which prints one
    pretty-printed JSON object per stream and keeps a stream's first JA4S."""
    run = subprocess.run([sys.executable, Path(script).name, "-J", "-r", str(Path(path).resolve())],
                         cwd=Path(script).parent, capture_output=True, text=True)
    if run.returncode != 0:
        # At 16b96d9 the reference raises KeyError on some streams it saw
        # start mid-connection; that says nothing about read_tls.
        return None
    output = run.stdout
    decoder, index, result = json.JSONDecoder(), 0, {}
    while True:
        index = output.find("{", index)
        if index < 0:
            return result
        stream, index = decoder.raw_decode(output, index)
        if "JA4S" in stream:
            # The reference reports the stream as its first packet saw it.
            key = (stream["src"], int(stream["srcport"]), stream["dst"], int(stream["dstport"]))
            result[key] = (stream["JA4S"], stream.get("JA4S_r"))


def compare_foxio(path, duckdb, script):
    expected = foxio_ja4s(path, script)
    if expected is None:
        print(f"{path}: the FoxIO reference failed on this capture; JA4S not compared")
        return 0, 0, 1, 0
    query = (f"SELECT client_ip, client_port, server_ip, server_port, ja4s, ja4s_r "
             f"FROM read_tls('{path}') WHERE handshake_number = 1 AND ja4s IS NOT NULL")
    output = subprocess.run([duckdb, "-json", "-c", query], check=True, capture_output=True, cwd=ROOT).stdout
    checked = failures = uncovered = 0
    for row in json.loads(output.strip() or b"[]"):
        key = (row["client_ip"], row["client_port"], row["server_ip"], row["server_port"])
        reference = expected.get(key) or expected.get((key[2], key[3], key[0], key[1]))
        if reference is None:
            # At 16b96d9 the reference only recognises a packet whose sole
            # handshake message is the ServerHello, so it misses the common
            # ServerHello+Certificate+ServerHelloDone packet. This row's inputs
            # are still compared with tshark above.
            uncovered += 1
            continue
        for actual, wanted, column in ((row["ja4s"], reference[0], "ja4s"), (row["ja4s_r"], reference[1], "ja4s_r")):
            checked += 1
            if actual != wanted:
                print(f"{path}: {key} {column}: FoxIO {wanted!r}, read_tls {actual!r}")
                failures += 1
    return checked, failures, 0, uncovered


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("captures", nargs="+")
    parser.add_argument("--duckdb", default=str(ROOT / "build/release/duckdb"))
    parser.add_argument("--foxio", help="path to FoxIO-LLC/ja4 python/ja4.py, to compare JA4S")
    args = parser.parse_args()
    totals = [0, 0, 0, 0, 0]
    foxio_checked = foxio_failures = foxio_skipped = foxio_uncovered = 0
    for capture in args.captures:
        for i, value in enumerate(compare(capture, args.duckdb)):
            totals[i] += value
        if args.foxio:
            checked, failures, skipped, uncovered = compare_foxio(capture, args.duckdb, args.foxio)
            foxio_uncovered += uncovered
            foxio_checked += checked
            foxio_failures += failures
            foxio_skipped += skipped
    checked, failures, divergences, skipped, missed = totals
    if args.foxio:
        print(f"FoxIO reference: {foxio_checked} JA4S values compared, {foxio_failures} disagreements, "
              f"{foxio_skipped} captures the reference could not process, "
              f"{foxio_uncovered} rows it did not fingerprint (ServerHello sharing a packet)")
        failures += foxio_failures
    print(f"{checked} values compared, {failures} disagreements, "
          f"{divergences} documented divergences (malformed or over-limit lists and fingerprints over them "
          f"reported NULL, or an empty JA4 list written as zeros), "
          f"{skipped} skipped (several hellos in one packet), {missed} tshark hellos without a read_tls row")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
