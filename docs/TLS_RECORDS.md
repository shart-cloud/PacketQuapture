# Single-packet TLS records

`read_packets` decodes the TLS record at the start of each TCP payload and exposes six columns.
Nothing here reassembles: every field comes from the bytes of one packet. The reassembled
layer is [`read_tls()`](TLS_HANDSHAKES.md), a separate function.

```sql
SELECT src_ip, dst_ip, dst_port, tls_sni
FROM read_packets('captures/**/*.pcap*')
WHERE tls_handshake_type = 1 AND tls_sni IS NOT NULL;

SELECT filename, packet_number, src_ip, dst_ip
FROM read_packets('captures/**/*.pcap*')
WHERE tls_handshake_type = 1 AND tls_truncated;
```

## Columns

| Column | Meaning |
| --- | --- |
| `is_tls` | A TLS record header begins this payload. Never NULL. |
| `tls_record_type` | Content type: 20 change_cipher_spec, 21 alert, 22 handshake, 23 application_data, 24 heartbeat. |
| `tls_record_version` | The version in the record header. For a ClientHello this is a compatibility value, not the negotiated version. |
| `tls_handshake_type` | First handshake message type in a handshake record, for example 1 ClientHello, 2 ServerHello. |
| `tls_sni` | `host_name` from the `server_name` extension of a ClientHello that fits this packet. |
| `tls_truncated` | For a ClientHello, whether it continues past this packet. |

## What the columns mean when they are NULL

`tls_truncated` exists so a NULL `tls_sni` is not ambiguous. A NULL name with `tls_truncated`
false means the ClientHello was complete and carried no `server_name` extension: the
reassembled reader would find nothing more. A NULL name with `tls_truncated` true means the
message continues into segments this packet does not contain.

| Case | `is_tls` | `tls_sni` | `tls_truncated` |
| --- | --- | --- | --- |
| ClientHello with SNI, fits this packet | true | the name | false |
| ClientHello complete, no `server_name` extension | true | NULL | false |
| ClientHello continues past this packet | true | NULL | true |
| Any other TLS record | true | NULL | NULL |
| Not TLS | false | NULL | NULL |

## Detection

Packets are classified by record shape, not by port, so TLS on 8443 or any other port is
found. A payload is TLS when the content type is 20-24, the version's major byte is `0x03`,
the minor byte is at most `0x04`, and the declared record length is non-zero, within
`16384 + 2048`, and fits within the remaining payload.

Requiring the record to fit the payload is what keeps false positives low on arbitrary binary
traffic: 20,000 random buffers produced no matches in
[the parser test](../test/unit/tls_record_test.cpp). The cost is that a record spanning
segments is not reported by this layer, and neither is a record that begins partway through a
segment. Both are the reassembled reader's job.

TLS runs over TCP here. DTLS frames differently and is not parsed, so UDP payloads are never
marked `is_tls`.

## Relationship to the other readers

Unlike `read_dns`, which returns only packets on port 53, `read_packets` returns every packet.
A non-TLS packet is a row with `is_tls` false rather than an absent row, so these columns
narrow a capture without changing which packets it contains.

The payload is read only when one of these columns is projected or filtered. A query that does
not mention them reads exactly the bytes it read before, at every projection depth; see
`scripts/benchmark_header_reads.py`.

`read_dns` builds on `read_packets` and therefore carries the TLS columns as well.

## Limits

- Only the first record of a payload is parsed. Later records in the same packet are ignored.
- Only the first handshake message of a record is identified.
- The negotiated version, cipher suite, ALPN, certificate chain and JA3/JA4 fingerprints need
  both directions and full reassembly. They belong to
  [`read_tls()`](TLS_HANDSHAKES.md).
