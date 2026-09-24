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
Server certificate chains are matched on the connection and the nth Certificate
message. tshark has no whole-name field, so subject and issuer are compared with
OpenSSL's RFC 4514 rendering (-nameopt RFC2253,-esc_msb) of the DER tshark
extracted; serials, validity and subjectAltName entries are compared with tshark.
With --ja4x, each certificate's ja4x and ja4x_r are compared with the FoxIO rust
reference (FoxIO-LLC/ja4 at 16b96d9, rust/ja4x, built with cargo); the python
reference misaligns multi-valued RDNs and hashes empty parts differently.
Exits non-zero on any disagreement that is not a documented divergence.
"""

import argparse
import collections
import datetime
import ipaddress
import json
import os
import subprocess
import sys
import tempfile
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


def find(tree, key, found=None):
    """Every value stored under key anywhere in a tshark JSON tree, in order."""
    found = [] if found is None else found
    if isinstance(tree, dict):
        for name, value in tree.items():
            if name == key:
                found.extend(value if isinstance(value, list) else [value])
            else:
                find(value, key, found)
    elif isinstance(tree, list):
        for item in tree:
            find(item, key, found)
    return found


def as_list(value):
    return value if isinstance(value, list) else [value]


def tshark_time(text):
    # utcTime is "2025-03-01 12:00:00 (UTC)"; generalizedTime is local time,
    # which TZ=UTC makes "Dec 31, 2050 23:59:59.000000000 UTC".
    if text.endswith("(UTC)"):
        moment = datetime.datetime.strptime(text[:-6], "%Y-%m-%d %H:%M:%S")
    else:
        moment = datetime.datetime.strptime(text.split(".")[0], "%b %d, %Y %H:%M:%S")
    return int(moment.replace(tzinfo=datetime.timezone.utc).timestamp())


def tshark_certificates(path):
    command = ["tshark", "-r", str(path), "-Y", "tls.handshake.type == 11", "-T", "json", "--no-duplicate-keys"]
    output = subprocess.run(command, check=True, capture_output=True, env=dict(os.environ, TZ="UTC")).stdout
    messages = collections.defaultdict(list)
    for packet in json.loads(output.decode("utf-8", "replace") or "[]"):
        layers = packet["_source"]["layers"]
        ip = layers.get("ip") or layers.get("ipv6")
        prefix = "ip" if "ip" in layers else "ipv6"
        src = (as_list(ip[f"{prefix}.src"])[0], int(as_list(layers["tcp"]["tcp.srcport"])[0]))
        dst = (as_list(ip[f"{prefix}.dst"])[0], int(as_list(layers["tcp"]["tcp.dstport"])[0]))
        for message in find(layers.get("tls"), "tls.handshake.certificates"):
            chain = []
            ders = as_list(message.get("tls.handshake.certificate", []))
            trees = as_list(message.get("tls.handshake.certificate_tree", []))
            for der, tree in zip(ders, trees):
                signed = tree.get("x509af.signedCertificate_element", {})
                validity = signed.get("x509af.validity_element", {})
                # Each bound may be either encoding, so read them in order, not by type.
                times = [tshark_time(t) for bound in ("x509af.notBefore_tree", "x509af.notAfter_tree")
                         for t in find(validity.get(bound, {}), "x509af.utcTime") +
                         find(validity.get(bound, {}), "x509af.generalizedTime")]
                san = [e for e in find(signed, "x509af.Extension_element")
                       if isinstance(e, dict) and e.get("x509af.extension.id") == "2.5.29.17"]
                chain.append({
                    "der": bytes.fromhex(der.replace(":", "")),
                    "serial": "".join(find(signed, "x509af.serialNumber")[:1]).replace(":", ""),
                    "times": times,
                    "san_dns": find(san, "x509ce.dNSName"),
                    "san_ip": find(san, "x509ce.IPAddress.ipv4") + find(san, "x509ce.IPAddress.ipv6"),
                })
            # tshark lists every entry's length but dissects only the certificates
            # it can parse; the rest are counted, so read_tls must have NULLs there.
            unparsed = len(as_list(message.get("tls.handshake.certificate_length", []))) - len(chain)
            # The certificate follows the server's hello, so the server is the source.
            messages[dst + src].append((chain, unparsed))
    return messages


def openssl_names(der):
    names = []
    for option in ("-subject", "-issuer"):
        result = subprocess.run(["openssl", "x509", "-inform", "DER", "-noout", option, "-nameopt", "RFC2253,-esc_msb"],
                                input=der, capture_output=True)
        text = result.stdout.decode("utf-8", "replace").strip()
        names.append(text.split("=", 1)[1] if result.returncode == 0 and "=" in text else None)
    return names


def our_certificates(path, duckdb):
    # Nested values travel as control-character-separated strings, as the lists do.
    field = ("CASE WHEN c IS NULL THEN chr(1) ELSE concat_ws(chr(30), c.subject, c.issuer, c.serial, "
             "epoch(c.not_before)::BIGINT, epoch(c.not_after)::BIGINT, array_to_string(c.san_dns, chr(29)), "
             "array_to_string(c.san_ip, chr(29)), c.ja4x, c.ja4x_r) END")
    query = (f"SELECT client_ip, client_port, server_ip, server_port, reassembly_status, "
             f"array_to_string(warnings, ',') AS warnings, "
             f"array_to_string(list_transform(server_certificates, lambda c: {field}), chr(31)) AS chain, "
             f"server_certificates IS NULL AS absent "
             f"FROM read_tls('{path}') WHERE server_hello ORDER BY client_ip, client_port, handshake_number")
    output = subprocess.run([duckdb, "-json", "-c", query], check=True, capture_output=True, cwd=ROOT).stdout
    chains = collections.defaultdict(list)
    for row in json.loads(output.strip() or b"[]"):
        key = (row["client_ip"], row["client_port"], row["server_ip"], row["server_port"])
        chain = None
        if not row["absent"]:
            chain = []
            for item in row["chain"].split("\x1f") if row["chain"] else []:
                if item == "\x01":
                    chain.append(None)
                    continue
                subject, issuer, serial, before, after, dns, ips, ja4x, ja4x_r = item.split("\x1e")
                chain.append({"subject": subject, "issuer": issuer, "serial": serial, "ja4x": ja4x, "ja4x_r": ja4x_r,
                              "times": [int(before), int(after)],
                              "san_dns": dns.split("\x1d") if dns else [],
                              "san_ip": ips.split("\x1d") if ips else []})
        chains[key].append((chain, row))
    return chains


def rust_ja4x(binary, der):
    with tempfile.NamedTemporaryFile(suffix=".der") as handle:
        handle.write(der)
        handle.flush()
        output = subprocess.run([binary, "-j", "-r", handle.name], capture_output=True, text=True).stdout
    try:
        record = json.loads(output)
    except ValueError:
        return None, None
    return record.get("ja4x"), record.get("ja4x_r")


def compare_certificates(path, duckdb, ja4x=None):
    reference = tshark_certificates(path)
    ours_by_key = our_certificates(path, duckdb)
    checked = failures = divergences = missed = 0
    for key, messages in reference.items():
        rows = [(chain, row) for chain, row in ours_by_key.get(key, []) if chain is not None or
                "certificate" in row["warnings"] or row["reassembly_status"] == "limit"]
        for index, (expected_chain, unparsed) in enumerate(messages):
            if index >= len(rows):
                # Coverage, like a missing hello: no read_tls row, not a wrong value.
                print(f"{path}: {key} certificate message {index + 1}: decoded by tshark, not reported by read_tls")
                missed += 1
                continue
            chain, row = rows[index]
            if chain is None:
                # A malformed or over-limit chain is NULL by design.
                divergences += 1
                continue
            parsed = [certificate for certificate in chain if certificate is not None]
            if len(chain) != len(expected_chain) + unparsed or len(parsed) != len(expected_chain):
                print(f"{path}: {key} chain: tshark {len(expected_chain)} parsed of {len(expected_chain) + unparsed}, "
                      f"read_tls {len(parsed)} of {len(chain)}")
                failures += 1
                continue
            checked += 1
            for position, (expected, actual) in enumerate(zip(expected_chain, parsed), 1):
                subject, issuer = openssl_names(expected["der"])
                pairs = [("subject", subject, actual["subject"]), ("issuer", issuer, actual["issuer"]),
                         ("serial", expected["serial"], actual["serial"]),
                         ("validity", expected["times"], actual["times"]),
                         ("san_dns", expected["san_dns"], actual["san_dns"]),
                         ("san_ip", [ipaddress.ip_address(a) for a in expected["san_ip"]],
                          [ipaddress.ip_address(a) for a in actual["san_ip"]])]
                if ja4x:
                    hashed, raw = rust_ja4x(ja4x, expected["der"])
                    pairs += [("ja4x", hashed, actual["ja4x"]), ("ja4x_r", raw, actual["ja4x_r"])]
                for field, want, got in pairs:
                    checked += 1
                    # RFC 4514's table spells 2.5.4.9 STREET; OpenSSL prints street.
                    if field in ("subject", "issuer") and want is not None and want != got and \
                            want.replace("street=", "STREET=") == got:
                        divergences += 1
                        continue
                    if want != got:
                        print(f"{path}: {key} certificate {position} {field}: reference {want!r}, read_tls {got!r}")
                        failures += 1
    return checked, failures, divergences, missed


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
    parser.add_argument("--ja4x", help="path to the FoxIO-LLC/ja4 rust ja4x binary, to compare JA4X")
    args = parser.parse_args()
    totals = [0, 0, 0, 0, 0]
    certificate_totals = [0, 0, 0, 0]
    foxio_checked = foxio_failures = foxio_skipped = foxio_uncovered = 0
    for capture in args.captures:
        for i, value in enumerate(compare(capture, args.duckdb)):
            totals[i] += value
        for i, value in enumerate(compare_certificates(capture, args.duckdb, args.ja4x)):
            certificate_totals[i] += value
        if args.foxio:
            checked, failures, skipped, uncovered = compare_foxio(capture, args.duckdb, args.foxio)
            foxio_uncovered += uncovered
            foxio_checked += checked
            foxio_failures += failures
            foxio_skipped += skipped
    checked, failures, divergences, skipped, missed = totals
    certificate_checked, certificate_failures, certificate_divergences, certificate_missed = certificate_totals
    print(f"Certificates: {certificate_checked} values compared, {certificate_failures} disagreements, "
          f"{certificate_divergences} documented divergences (malformed or over-limit chains reported NULL, "
          f"or OpenSSL's lowercase street), {certificate_missed} tshark Certificate messages without a read_tls row")
    failures += certificate_failures
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
