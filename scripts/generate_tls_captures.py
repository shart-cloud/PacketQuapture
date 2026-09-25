#!/usr/bin/env python3
"""Project-authored MIT TLS fixtures, generated from RFC 8446 record layouts."""

from pathlib import Path
import struct
from generate_protocol_captures import eth, ip4, pcap

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "test/data/tls"


def record(body, kind=22, version=0x0301):
    return struct.pack("!BHH", kind, version, len(body)) + body


def handshake(body, kind=1):
    return struct.pack("!B", kind) + struct.pack("!I", len(body))[1:] + body


def extension(kind, body):
    return struct.pack("!HH", kind, len(body)) + body


def server_name(host):
    raw = host if isinstance(host, bytes) else host.encode()
    entry = struct.pack("!BH", 0, len(raw)) + raw
    return extension(0, struct.pack("!H", len(entry)) + entry)


def client_hello(extensions=b"", session_id=b"", version=0x0303):
    body = struct.pack("!H", version) + bytes(range(32))
    body += struct.pack("!B", len(session_id)) + session_id
    body += struct.pack("!H", 2) + struct.pack("!H", 0x1301)  # cipher_suites
    body += struct.pack("!B", 1) + b"\0"  # legacy_compression_methods
    body += struct.pack("!H", len(extensions)) + extensions
    return handshake(body, 1)


def u16s(values):
    return b"".join(struct.pack("!H", v) for v in values)


def vector16(body):
    return struct.pack("!H", len(body)) + body


def vector8(body):
    return struct.pack("!B", len(body)) + body


def alpn(protocols):
    return extension(16, vector16(b"".join(vector8(p) for p in protocols)))


def full_client_hello(ciphers, extensions, session_id=b"", version=0x0303):
    """A ClientHello with explicit cipher suites, for fingerprint fixtures."""
    body = struct.pack("!H", version) + bytes(range(32))
    body += vector8(session_id)
    body += vector16(u16s(ciphers))
    body += vector8(b"\0")
    body += vector16(b"".join(extensions))
    return handshake(body, 1)


def full_server_hello(cipher, extensions, version=0x0303, session_id=b""):
    body = struct.pack("!H", version) + bytes(range(32))
    body += vector8(session_id)
    body += struct.pack("!HB", cipher, 0)
    body += vector16(b"".join(extensions))
    return handshake(body, 2)


# RFC 8701 GREASE values used below.
GREASE = [0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A]


def browser_like(host, alpn_protocols=(b"h2", b"http/1.1")):
    """A TLS 1.3 ClientHello shaped like a current browser: GREASE in every
    list that permits it, ciphers and extensions deliberately unsorted."""
    ciphers = [GREASE[0], 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030,
               0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035]
    extensions = [
        extension(GREASE[1], b""),
        extension(23, b""),  # extended_master_secret
        extension(65281, b"\0"),  # renegotiation_info
        extension(10, vector16(u16s([GREASE[2], 0x001D, 0x0017, 0x0018]))),
        extension(11, vector8(b"\0")),  # ec_point_formats: uncompressed
        extension(35, b""),  # session_ticket
        alpn(list(alpn_protocols)),
        extension(5, b"\x01\0\0\0\0"),  # status_request
        extension(13, vector16(u16s([0x0403, 0x0804, 0x0401, 0x0503, 0x0805,
                                     0x0501, 0x0806, 0x0601]))),
        extension(18, b""),  # signed_certificate_timestamp
        extension(51, vector16(struct.pack("!HH", GREASE[2], 1) + b"\0"
                               + struct.pack("!HH", 0x001D, 32) + bytes(32))),
        extension(45, vector8(b"\x01")),  # psk_key_exchange_modes
        extension(43, vector8(u16s([GREASE[3], 0x0304, 0x0303]))),
        extension(27, vector8(b"\0\x02")),  # compress_certificate: brotli
        extension(GREASE[4], b"\0"),
    ]
    if host is not None:
        extensions.insert(1, server_name(host))
    return full_client_hello(ciphers, extensions)


def server_hello(version=0x0303):
    body = struct.pack("!H", version) + bytes(range(32))
    body += struct.pack("!B", 0)  # legacy_session_id_echo
    body += struct.pack("!H", 0x1301) + struct.pack("!B", 0)
    body += struct.pack("!H", 0)
    return handshake(body, 2)


def tcp(payload, src=51000, dst=443, seq=1):
    return struct.pack("!HHIIBBHHH", src, dst, seq, 1, 0x50, 0x18, 4096, 0, 0) + payload


def packet(payload, src=51000, dst=443, seq=1):
    return eth(ip4(tcp(payload, src, dst, seq)))


def main():
    DATA.mkdir(parents=True, exist_ok=True)

    # A ClientHello carrying SNI, its ServerHello, and an application-data record.
    hello = record(client_hello(server_name("example.com")))
    packets = [
        packet(hello),
        packet(record(server_hello()), src=443, dst=51000),
        packet(record(b"\x01" * 48, kind=23, version=0x0303)),
    ]
    pcap(DATA / "handshake.pcap", packets)

    # A ClientHello with extensions but no server_name: SNI is absent, not truncated.
    no_sni = record(client_hello(extension(0x002B, b"\x02\x03\x04")))
    pcap(DATA / "no_sni.pcap", [packet(no_sni)])

    # A ClientHello with no extensions at all.
    pcap(DATA / "no_extensions.pcap", [packet(record(client_hello()))])

    # A ClientHello padded past one record, so the SNI does not fit this packet.
    big = client_hello(server_name("split.example.com") + extension(0x0015, b"\0" * 900))
    first = big[:400]
    pcap(
        DATA / "truncated.pcap",
        [packet(struct.pack("!BHH", 22, 0x0301, len(first)) + first)],
    )

    # Traffic that is not TLS at all, on the TLS port and on another port.
    pcap(
        DATA / "not_tls.pcap",
        [packet(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", dst=80), packet(b"\xff" * 64)],
    )

    # A handshake on a non-standard port: detection is by record shape, not port.
    pcap(DATA / "alt_port.pcap", [packet(hello, dst=8443)])

    reassembly_fixtures()


CLIENT_IP = bytes([192, 0, 2, 1])
SERVER_IP = bytes([198, 51, 100, 2])


def ip4_between(payload, src, dst):
    """IPv4 with explicit endpoints, so both directions of a flow can be built."""
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 42, 0, 64, 6, 0, src, dst
    )
    return header + payload


def segment(payload, src_port, dst_port, seq, ack=1, flags=0x18):
    return struct.pack(
        "!HHIIBBHHH", src_port, dst_port, seq, ack, 0x50, flags, 4096, 0, 0
    ) + payload


def to_client(payload, seq, port=51000, flags=0x18):
    return eth(ip4_between(segment(payload, 443, port, seq, flags=flags), SERVER_IP, CLIENT_IP))


def to_server(payload, seq, port=51000, flags=0x18):
    return eth(ip4_between(segment(payload, port, 443, seq, flags=flags), CLIENT_IP, SERVER_IP))


def connection(client_payloads, server_payloads, port=51000):
    """A SYN-anchored connection carrying the given payloads in each direction."""
    packets = [
        to_server(b"", 0, port, flags=0x02),
        to_client(b"", 0, port, flags=0x12),
    ]
    seq = 1
    for payload in client_payloads:
        packets.append(to_server(payload, seq, port))
        seq += len(payload)
    seq = 1
    for payload in server_payloads:
        packets.append(to_client(payload, seq, port))
        seq += len(payload)
    return packets


def reassembly_fixtures():
    hello = record(client_hello(server_name("example.com")))
    reply = record(server_hello())

    # A complete handshake with both directions captured.
    pcap(DATA / "session.pcap", connection([hello], [reply]))

    # Only the client direction was captured.
    pcap(DATA / "client_only.pcap", connection([hello], []))

    # Only the server direction was captured.
    pcap(DATA / "server_only.pcap", connection([], [reply]))

    # A ClientHello split across two TLS records, which in turn span two
    # segments: the name is only recoverable after reassembly.
    body = client_hello(server_name("split.example.com"))
    first, second = body[:40], body[40:]
    split = record(first) + record(second)
    pcap(
        DATA / "split.pcap",
        connection([split[:30], split[30:]], [reply]),
    )

    # Two handshakes on one connection, renegotiated in the clear.
    again = record(client_hello(server_name("second.example.com")))
    pcap(
        DATA / "renegotiated.pcap",
        connection([hello + again], [reply + record(server_hello())]),
    )

    # Handshake bytes followed by change_cipher_spec and encrypted records that
    # would otherwise parse as another ClientHello.
    encrypted = record(b"\x01", kind=20, version=0x0303) + record(
        client_hello(server_name("must.not.appear")), version=0x0303
    )
    pcap(DATA / "encrypted_after_ccs.pcap", connection([hello + encrypted], [reply]))

    # A server name that is not valid UTF-8, with a space and a backslash: it must
    # be escaped rather than fail the query.
    hostile = record(client_hello(server_name(b"a\xff\xfe b\\c.example")))
    pcap(DATA / "hostile_sni.pcap", connection([hostile], [reply]))

    fingerprint_fixtures()
    idle_fixtures()
    certificate_fixtures()
    tunnel_fixtures()

    # TCP that is not TLS at all.
    pcap(
        DATA / "plain_tcp.pcap",
        connection([b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"], [b"HTTP/1.1 200 OK\r\n\r\n"]),
    )


def fingerprint_fixtures():
    """Hellos rich enough to exercise the parsed lists and, later, JA3/JA4:
    unsorted lists, GREASE, ALPN, TLS 1.3 and the edge cases the formats name."""

    # A browser-like TLS 1.3 exchange. ALPN is encrypted in TLS 1.3, so the
    # ServerHello carries only supported_versions and key_share.
    tls13_reply = record(full_server_hello(0x1301, [
        extension(43, struct.pack("!H", 0x0304)),
        extension(51, struct.pack("!HH", 0x001D, 32) + bytes(32)),
    ]))
    pcap(DATA / "browser_tls13.pcap",
         connection([record(browser_like("www.example.com"))], [tls13_reply]))

    # TLS 1.2 with the selected protocol in the ServerHello.
    tls12_hello = full_client_hello(
        [0xC02F, 0xC02B, 0x009C, 0x002F],
        [server_name("api.example.com"),
         extension(10, vector16(u16s([0x0017, 0x001D]))),
         extension(11, vector8(b"\0\x01\x02")),
         extension(13, vector16(u16s([0x0401, 0x0403]))),
         alpn([b"h2", b"http/1.1"]),
         extension(23, b"")],
    )
    tls12_reply = record(full_server_hello(0xC02F, [
        extension(65281, b"\0"),
        extension(11, vector8(b"\0")),
        alpn([b"http/1.1"]),
        extension(23, b""),
    ]))
    pcap(DATA / "tls12_alpn.pcap", connection([record(tls12_hello)], [tls12_reply]))

    # No SNI and more than 99 cipher suites, which JA4 caps in its count field.
    many = full_client_hello(list(range(0x0001, 0x0079)), [
        extension(10, vector16(u16s([0x001D]))),
        extension(43, vector8(u16s([0x0304]))),
    ])
    pcap(DATA / "many_ciphers.pcap", connection([record(many)], []))

    # ALPN edge cases on three connections: GREASE first, a single character,
    # and a non-alphanumeric identifier.
    edges = []
    for port, protocols in ((51001, [b"\x0a\x0a", b"h2"]), (51002, [b"x"]),
                            (51003, [b"\xab\x01", b"h2"])):
        hello = full_client_hello([0x1301], [alpn(protocols)])
        edges += connection([record(hello)], [], port=port)
    pcap(DATA / "alpn_edges.pcap", edges)

    # supported_groups with an odd length: that list is malformed and reported
    # NULL with a warning, while the rest of the hello still parses.
    odd = full_client_hello([0x1301], [
        server_name("odd.example.com"),
        extension(10, struct.pack("!H", 3) + b"\0\x1d\0"),
    ])
    pcap(DATA / "malformed_groups.pcap", connection([record(odd)], []))

    # More cipher suites than max_list_entries: the hello reports status limit.
    huge = full_client_hello(list(range(0x0100, 0x0100 + 1100)), [])
    pcap(DATA / "list_limit.pcap", connection([record(huge)], []))

    # JA3 takes the version from legacy_version on both sides, never from
    # supported_versions, and drops GREASE; here it is in the ServerHello too.
    old_hello = full_client_hello([GREASE[0], 0xC013, 0x0035], [
        extension(GREASE[1], b""),
        server_name("legacy.example.com"),
        extension(10, vector16(u16s([GREASE[2], 0x0017]))),
        extension(11, vector8(b"\0")),
    ], version=0x0301)
    old_reply = full_server_hello(0xC013, [
        extension(GREASE[3], b""),
        extension(65281, b"\0"),
        extension(11, vector8(b"\0")),
    ], version=0x0301)
    pcap(DATA / "ja3_legacy.pcap", connection([record(old_hello)], [record(old_reply)]))


# X.509 DER, built field by field. Signatures are placeholders: read_tls parses
# certificates and never verifies them, and fixed bytes keep the fixtures stable.
def der(tag, content):
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    elif n < 0x100:
        length = bytes([0x81, n])
    else:
        length = bytes([0x82]) + struct.pack("!H", n)
    return bytes([tag]) + length + content


def oid(dotted):
    arcs = [int(a) for a in dotted.split(".")]
    out = b""
    for value in [arcs[0] * 40 + arcs[1]] + arcs[2:]:
        chunk = [value & 0x7F]
        value >>= 7
        while value:
            chunk.insert(0, 0x80 | (value & 0x7F))
            value >>= 7
        out += bytes(chunk)
    return der(0x06, out)


def name(*rdns):
    """Each RDN is a list of (oid, tag, value bytes), least specific first."""
    # DER sorts the members of a SET by their encodings.
    return der(0x30, b"".join(
        der(0x31, b"".join(sorted(der(0x30, oid(o) + der(t, v)) for o, t, v in rdn))) for rdn in rdns))


def certificate(serial, issuer, subject, not_before, not_after, dns=(), ips=()):
    algorithm = der(0x30, oid("1.2.840.10045.4.3.2"))
    key = der(0x30, der(0x30, oid("1.2.840.10045.2.1") + oid("1.2.840.10045.3.1.7"))
              + der(0x03, b"\0\x04" + bytes(range(64))))
    tbs = der(0xA0, der(0x02, b"\x02")) + der(0x02, serial) + algorithm + issuer
    tbs += der(0x30, not_before + not_after) + subject + key
    names = b"".join(der(0x82, d) for d in dns) + b"".join(der(0x87, ip) for ip in ips)
    if names:
        san = der(0x30, oid("2.5.29.17") + der(0x04, der(0x30, names)))
        tbs += der(0xA3, der(0x30, san))
    return der(0x30, der(0x30, tbs) + algorithm + der(0x03, b"\0" + der(0x30, bytes(8))))


def certificate_message(chain):
    entries = b"".join(struct.pack("!I", len(c))[1:] + c for c in chain)
    return handshake(struct.pack("!I", len(entries))[1:] + entries, 11)


CN, O, OU, C, L = "2.5.4.3", "2.5.4.10", "2.5.4.11", "2.5.4.6", "2.5.4.7"
UTF8, PRINTABLE, TELETEX, IA5, BMP = 0x0C, 0x13, 0x14, 0x16, 0x1E


def certificate_fixtures():
    ca = name([(C, PRINTABLE, b"US")], [(O, PRINTABLE, b"Fixture Trust")], [(CN, UTF8, b"Fixture Root CA")])
    intermediate_name = name(
        [(C, PRINTABLE, b"US")], [(O, PRINTABLE, b"Fixture Trust")],
        [(OU, UTF8, b"Issuing"), (CN, UTF8, b"Fixture Issuing CA 1")])
    intermediate = certificate(
        b"\x01", ca, intermediate_name, der(0x17, b"200101000000Z"), der(0x18, b"20501231235959Z"))
    leaf_name = name(
        [(C, PRINTABLE, b"DE")], [(L, TELETEX, b"M\xfcnchen")],
        [(O, UTF8, "Beispiel, \"Gr\u00fcn\" + Co <AG>;".encode())],
        [(O, BMP, "\u00e9t\u00e9".encode("utf-16-be"))],
        [("1.2.840.113549.1.9.1", IA5, b"ops@example.test")],
        [("1.3.6.1.4.1.55555.1", UTF8, b"private")],
        [(CN, UTF8, b" #www.example.test ")])
    leaf = certificate(
        b"\x00\x8f\x3a\x10\x42", intermediate_name, leaf_name,
        der(0x17, b"250301120000Z"), der(0x17, b"260301120000Z"),
        dns=[b"www.example.test", b"example.test", b"*.cdn.example.test"],
        ips=[bytes([192, 0, 2, 44]), bytes.fromhex("20010db8000000000000000000000044")])

    client = record(client_hello(server_name("www.example.test")))
    reply = record(server_hello() + certificate_message([leaf, intermediate]))
    pcap(DATA / "certificates.pcap", connection([client], [reply]))

    # One certificate that does not parse keeps its place in the chain.
    broken = record(server_hello() + certificate_message([leaf, b"\x30\x03\x02\x01"]))
    pcap(DATA / "certificate_malformed.pcap", connection([client], [broken]))


def exchange(steps, port):
    """A SYN-anchored connection whose payloads alternate as given: each step is
    (True, payload) client to server or (False, payload) back, in wire order."""
    packets = [to_server(b"", 0, port, flags=0x02), to_client(b"", 0, port, flags=0x12)]
    seq = {True: 1, False: 1}
    for client, payload in steps:
        packets.append((to_server if client else to_client)(payload, seq[client], port))
        seq[client] += len(payload)
    return packets


def tunnel_fixtures():
    """TLS behind SOCKS and HTTP CONNECT, one connection per client port, each
    message in its own segment and in the order a proxy exchanges them."""
    reply = record(server_hello())

    def hello(host):
        return record(client_hello(server_name(host)))

    def socks5_address(ip, port=443):
        return b"\x01" + bytes(ip) + struct.pack("!H", port)

    packets = []
    # SOCKS5 with RFC 1929 username and password, to a name.
    host = b"login.live.com"
    packets += exchange([
        (True, b"\x05\x02\x00\x02"), (False, b"\x05\x02"),
        (True, b"\x01\x04user\x02pw"), (False, b"\x01\x00"),
        (True, b"\x05\x01\x00\x03" + bytes([len(host)]) + host + struct.pack("!H", 443)),
        (False, b"\x05\x00\x00" + socks5_address([65, 55, 196, 251])),
        (True, hello("login.live.com")), (False, reply)], port=51001)
    # SOCKS4a, to a name.
    packets += exchange([
        (True, b"\x04\x01\x01\xbb\x00\x00\x00\x01bot\x00c2.example\x00"),
        (False, b"\x00\x5a\x00\x00\x00\x00\x00\x00"),
        (True, hello("c2.example")), (False, reply)], port=51002)
    # HTTP CONNECT with headers on both sides.
    packets += exchange([
        (True, b"CONNECT proxy.example:8443 HTTP/1.1\r\nHost: proxy.example:8443\r\n\r\n"),
        (False, b"HTTP/1.1 200 Connection established\r\nProxy-Agent: fixture\r\n\r\n"),
        (True, hello("proxy.example")), (False, reply)], port=51003)
    # The CTU-13 Neris botnet's shape: one stray byte before a SOCKS5 greeting.
    # The server side is standard SOCKS5.
    packets += exchange([
        (True, b"\x7e"), (True, b"\x05\x01\x00"), (False, b"\x05\x00"),
        (True, b"\x05\x01\x00" + socks5_address([65, 55, 16, 187])),
        (False, b"\x05\x00\x00" + socks5_address([65, 55, 16, 187])),
        (True, hello("neris.example")), (False, reply)], port=51004)
    # Not TLS: a record header whose hello runs past its record.
    decoy = bytearray(hello("decoy.example"))
    decoy[5 + 4 + 2 + 32] = 0xFF
    packets += exchange([(True, b"junk"), (False, b"ok"), (True, bytes(decoy))], port=51005)
    # Only the client side of a SOCKS5 tunnel was captured.
    packets += exchange([
        (True, b"\x05\x01\x00\x05\x01\x00" + socks5_address([192, 0, 2, 9])),
        (True, hello("one-sided.example"))], port=51006)
    pcap(DATA / "tunnels.pcap", packets)


def idle_fixtures():
    # 1,024 connections fill every tracked TCP direction and then go quiet, as
    # scans and abandoned sessions do. The first carries data, so its eviction is
    # visible as a stream. A handshake after the 300 s idle timeout must still be
    # reported rather than rejected as over the direction limit.
    start = 1700000000
    quiet = connection([b"quiet"], [], port=20000)[::2]
    for port in range(20001, 20000 + 1024):  # one direction each, 1,024 in all
        quiet.append(to_server(b"", 0, port, flags=0x02))
    hello = record(client_hello(server_name("after-idle.example")))
    late = connection([hello], [record(server_hello())])
    packets = [(start, p) for p in quiet] + [(start + 301, p) for p in late]
    pcap(DATA / "idle_eviction.pcap", packets)


if __name__ == "__main__":
    main()
