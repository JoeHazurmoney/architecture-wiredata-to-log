"""The wire format against the two frames captured in docs/interface-description.md §13.

The other wire tests round-trip frames through the same code, so a change made on both sides at
once (byte order, field order, what the CRC covers) would pass them, and still break every
deployed receiver. These frames are fixed bytes from a real capture: decoding them must give the
ICD's field tables, and encoding the same content must give the same bytes."""

import hashlib
import json
import os
import re
import zlib

from wd2l import wire

ICD = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "docs",
                   "interface-description.md")
ETH_IP_UDP = 14 + 20 + 8        # the WD2L frame starts at offset 0x2A
STREAM = 0xfc9cb69060036d8f


def captured(heading: str) -> bytes:
    """The bytes of the hex dump that follows `heading` (tcpdump -xx style lines)."""
    with open(ICD, encoding="utf-8") as f:
        text = f.read()
    block = text.split(heading, 1)[1].split("```", 2)[1]
    out = b""
    for line in block.strip().splitlines():
        offset, hexpart = re.split(r"\s{2,}", line.strip())[:2]
        assert int(offset.rstrip(":"), 16) == len(out), line
        out += bytes.fromhex(hexpart.replace(" ", ""))
    return out


def test_the_header_is_what_the_icd_describes():
    assert wire.MAGIC == b"WD2L" and wire.VERSION == 1      # the wire version stays 1
    assert wire.HEADER.format == "!4sBBHQQHHI32s"           # network byte order
    assert wire.OVERHEAD == 68


def test_the_captured_data_frame():
    frame = captured("### DATA frame: event 1, in one piece (354 bytes)")
    assert len(frame) == 354
    dg = frame[ETH_IP_UDP:]
    f = wire.decode(dg)
    assert (dg[:4], dg[4], dg[5]) == (b"WD2L", 1, wire.TYPE_DATA)
    assert (f.type, f.flags, f.stream_id, f.seq) == (wire.TYPE_DATA, 0, STREAM, 1)
    assert (f.chunk_idx, f.chunk_count, f.event_len) == (0, 1, 244)
    assert f.payload == dg[0x6A - ETH_IP_UDP:-4] and len(f.payload) == 244
    assert f.digest == hashlib.sha256(f.payload).digest()
    # The CRC-32 covers frame offsets 0x2A-0x15D: the whole datagram but the CRC itself.
    assert zlib.crc32(dg[:-4]) == int.from_bytes(dg[-4:], "big")
    assert json.loads(f.payload)["host"] == "fw01"
    assert wire.encode_event(STREAM, 1, f.payload) == [dg]


def test_the_captured_heartbeat_frame():
    frame = captured("### HEARTBEAT frame (308 bytes)")
    assert len(frame) == 308
    dg = frame[ETH_IP_UDP:]
    f = wire.decode(dg)
    assert (dg[:4], dg[4], dg[5]) == (b"WD2L", 1, wire.TYPE_HEARTBEAT)
    assert (f.type, f.flags, f.stream_id, f.seq) == (wire.TYPE_HEARTBEAT, 0, STREAM, 2025)
    assert (f.chunk_idx, f.chunk_count, f.event_len) == (0, 1, 198)
    assert f.digest == hashlib.sha256(f.payload).digest()
    assert zlib.crc32(dg[:-4]) == int.from_bytes(dg[-4:], "big")
    info = json.loads(f.payload)
    assert (info["boot"], info["events_sent"], info["uptime"]) == (1, 2025, 3.0)
    assert wire.encode_heartbeat(STREAM, 2025, info) == dg
