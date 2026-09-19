# Independent classic-PCAP byte writer

This is the standalone byte-writer milestone from the flows/inventory/export plan.
It does **not** register `COPY ... FORMAT PCAP` yet. The next change must integrate
DuckDB's ordered COPY lifecycle, type/NULL checks, and owned temporary-file publication.
The implementation has no DuckDB or filesystem dependency and adds no shipped libpcap
dependency. `pcap_writer.cpp` is compiled into the extension for the next integration.

## Encoding and validation

`packetquapture::PcapWriter` emits classic PCAP 2.4 with explicit little-endian
encoding, microsecond timestamps, zero reserved header fields, and one required link
type. It follows the [PCAP format draft, revision 08](https://www.ietf.org/archive/id/draft-ietf-opsawg-pcap-08.html),
a work in progress. The native byte and independent decoder tests pin the encoding.

The constructor takes a caller-owned `PcapOutput` and `PcapWriterOptions(link_type)`.
Link type must fit 16 bits. FCS/additional metadata bits are rejected. Set
`has_snaplen=true` and a positive `snaplen` for a fixed limit; otherwise Finish patches
the largest captured length, with a minimum of one for empty/zero-length captures.
Packets exceeding an explicit limit are rejected rather than truncated.

WritePacket takes a non-null signed microsecond timestamp, captured/original lengths,
link type, payload pointer and payload size. Accepted timestamps range from zero
through `4294967295999999` microseconds since the Unix epoch. Negative values and
larger timestamps are rejected before a record is written. Captured and original
lengths must fit 32 bits; captured length must equal payload size and cannot exceed
original length. Every row's link type must match the header. A null pointer is valid
only for a present zero-length payload. The future SQL adapter must distinguish that
from SQL NULL and reject NULL values and direct TIMESTAMP_NS inputs at binding/runtime.

These are format limits, not a promise that every external decoder accepts extreme
packet sizes. Payload bytes are copied verbatim without packet repair or protocol
validation. The writer preserves call order, including equal and regressing timestamps;
it performs no sort or reconstruction and does not preserve PCAPNG metadata.

## Output and failure contract

PcapOutput::Write reports the number of bytes written. The writer retries positive
short writes; zero/excessive counts and exceptions are errors. Each call is at most
65,536 bytes, so an adapter can check cancellation between bounded writes. PcapOutput::Seek
uses absolute positions and must throw on failure. Output starts empty at position zero.

The writer retains no payload buffer, record list or file handle. Header buffers are
24 and 16 bytes on the stack; Finish uses four bytes for the snaplen patch. The caller
keeps the payload valid until WritePacket returns and serializes calls. PacketCount and
BytesWritten describe successfully completed records, excluding any partially written
failed record. Output-size arithmetic is checked before writing a record.

Any row-validation or I/O failure permanently poisons the writer. Finish and subsequent
writes then fail. Finish restores EOF after an inferred-snaplen patch and marks success
only after all operations complete. An explicit-snaplen output needs no patch. Repeated
Finish and writes after Finish are errors. The destructor does not write or finalize.

**Finish is not publication.** The caller must close/flush/check its owned output and
publish only after every required operation succeeds. Constructor or write failures can
leave partial staging bytes, which the caller must discard. This core does not open,
replace, remove, or publish files and makes no filesystem atomicity/rollback guarantee.
The test adapter writes its own temporary fixtures; it is not a production publisher.

## Independent decoder compatibility

Installed libpcap 1.10.4 interprets the seconds field as signed on native-endian reads.
Consequently, dates at/after `2038-01-19 03:14:08 UTC` can appear negative in that decoder,
even though the format's unsigned seconds field supports values through 2106. Its
[source](https://github.com/the-tcpdump-group/libpcap/blob/libpcap-1.10.4/sf-pcap.c)
contains the signed conversion and a corresponding 2038 caveat.

Tests explicitly recognize this decoder limitation rather than claiming exact libpcap
calendar-time round trips beyond 2038. Raw encoded fields and PacketQuapture readback
retain the unsigned values exactly, including both sides of 2038 and the maximum
seconds/microseconds pair. Ordinary timestamps, payloads, lengths, header fields and EOF
are independently checked through libpcap. A valid UDP frame is also decoded by tcpdump.

## Validation and reproduction

```sh
mkdir -p build/pcap-writer
c++ -std=c++11 -Wall -Wextra -Werror -g -O1 \
  -fsanitize=address,undefined -fno-omit-frame-pointer -DPCAP_ORACLE \
  -Isrc/include src/pcap_writer.cpp test/unit/pcap_writer_test.cpp \
  -lpcap -o build/pcap_writer_test
./build/pcap_writer_test build/pcap-writer
tcpdump -nn -r build/pcap-writer/udp.pcap
python3 test/unit/pcap_writer_roundtrip_test.py
./build/release/test/unittest 'test/sql/*'
```

The standalone oracle requires libpcap development files only for testing; omit
`-DPCAP_ORACLE -lpcap` for the dependency-free unit test. The Python round-trip test
builds that version itself and uses the existing release library. CI runs sanitizer
and libpcap tests in the decoder workflow and reader round trips in the native scan
workflow. Existing distribution jobs compile the writer on supported native platforms.

Recorded local results, September 19, 2026: release build and all 1,899 SQL assertions
passed. Writer ASan/UBSan passed byte-exact headers/records, timestamp/length/link bounds,
zero/empty records, explicit and inferred snaplen, every byte-failure position in a
header/record/final patch, failed seeks, invalid progress, failure after a good record,
short writes with a payload larger than 1 MiB, and 10,000 seeded randomized records.
Independent libpcap/tcpdump and PacketQuapture round trips passed with the documented
signed-seconds compatibility observation. Repository formatting passed. Local logs are
`/tmp/packetquapture-writer-*.log`; test captures remain under the ignored build directory.
No throughput claim is made by these core correctness tests.

## Remaining COPY gate

Before exposing SQL export, verify the pinned DuckDB staging/finalization hooks and
explicit ORDER BY preservation. Reject incompatible output modes, bind the five named
columns with exact types, provide local exclusive staging, close before publication,
and clean only owned artifacts on errors/interruption. Test new/existing destinations,
competing writers, source failures and native platform behavior. Neither a mutex around
parallel writes nor this byte writer alone establishes ordered or safely published COPY.
