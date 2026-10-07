"""WD2L datagram format, shared by sender and receiver.

Every UDP payload is one frame:

    offset size field
    0      4    magic        b"WD2L"
    4      1    version      1
    5      1    type         1 = DATA, 2 = HEARTBEAT
    6      2    flags        bit 0: records stream (the sender's own records); others 0
    8      8    stream_id    random per sender start
    16     8    seq          DATA: event number (starts at 1). HEARTBEAT: last seq sent
    24     2    chunk_idx    0-based
    26     2    chunk_count  >= 1
    28     4    event_len    length of the whole event (all chunks joined)
    32     32   digest       SHA-256 of the whole event
    64     n    payload      this chunk's bytes
    64+n   4    crc32        CRC-32 of bytes 0 .. 64+n

All integers are big-endian. See docs/wire-format.md.
"""

from __future__ import annotations

import hashlib
import json
import struct
import zlib
from typing import Any, Dict, List, NamedTuple, Optional

MAGIC = b"WD2L"
VERSION = 1
TYPE_DATA = 1
TYPE_HEARTBEAT = 2

# flags bit 0: the frame belongs to the sender's records stream, which carries its own audit and
# health records (docs/audit-and-health-plan.md section 7). The other bits are reserved (0).
FLAG_RECORDS = 0x0001

HEADER = struct.Struct("!4sBBHQQHHI32s")
CRC = struct.Struct("!I")
OVERHEAD = HEADER.size + CRC.size  # 68

DEFAULT_MAX_DATAGRAM = 1472  # 1500 MTU - 20 IPv4 - 8 UDP
DEFAULT_MAX_EVENT = 256 * 1024
MAX_CHUNKS = 0xFFFF

# Fields carried end to end. Everything else the log aggregator attaches is dropped by the sender
# unless listed with --extra-field (those ride in "fields").
EVENT_KEYS = ("_time", "host", "source", "sourcetype", "index", "_raw")


class FrameError(ValueError):
    """Datagram is not a valid WD2L frame."""


class Frame(NamedTuple):
    type: int
    flags: int
    stream_id: int
    seq: int
    chunk_idx: int
    chunk_count: int
    event_len: int
    digest: bytes
    payload: bytes


def _pack(ftype: int, stream_id: int, seq: int, idx: int, count: int,
          event_len: int, digest: bytes, payload: bytes, flags: int = 0) -> bytes:
    head = HEADER.pack(MAGIC, VERSION, ftype, flags, stream_id, seq, idx, count, event_len, digest)
    body = head + payload
    return body + CRC.pack(zlib.crc32(body) & 0xFFFFFFFF)


def event_digest(event: bytes) -> bytes:
    """SHA-256 of a serialized event: the frame's digest, and the sender's reconciliation term."""
    return hashlib.sha256(event).digest()


def encode_event(stream_id: int, seq: int, event: bytes,
                 max_datagram: int = DEFAULT_MAX_DATAGRAM, flags: int = 0,
                 digest: Optional[bytes] = None) -> List[bytes]:
    """Split one serialized event into DATA frames that each fit in max_datagram bytes."""
    chunk_size = max_datagram - OVERHEAD
    if chunk_size < 1:
        raise ValueError("max_datagram too small")
    count = max(1, -(-len(event) // chunk_size))
    if count > MAX_CHUNKS:
        raise ValueError("event needs more than %d chunks" % MAX_CHUNKS)
    if digest is None:
        digest = event_digest(event)
    return [
        _pack(TYPE_DATA, stream_id, seq, i, count, len(event), digest,
              event[i * chunk_size:(i + 1) * chunk_size], flags)
        for i in range(count)
    ]


def encode_heartbeat(stream_id: int, last_seq: int, info: Dict[str, Any], flags: int = 0) -> bytes:
    payload = json.dumps(info, separators=(",", ":"), sort_keys=True).encode()
    return _pack(TYPE_HEARTBEAT, stream_id, last_seq, 0, 1, len(payload),
                 hashlib.sha256(payload).digest(), payload, flags)


def decode(datagram: bytes) -> Frame:
    """Parse and validate one datagram. Raises FrameError on anything unexpected."""
    if len(datagram) < OVERHEAD:
        raise FrameError("short datagram")
    body, (crc,) = datagram[:-CRC.size], CRC.unpack(datagram[-CRC.size:])
    if zlib.crc32(body) & 0xFFFFFFFF != crc:
        raise FrameError("bad crc")
    magic, version, ftype, flags, stream_id, seq, idx, count, event_len, digest = \
        HEADER.unpack_from(body)
    if magic != MAGIC:
        raise FrameError("bad magic")
    if version != VERSION:
        raise FrameError("unsupported version %d" % version)
    if ftype not in (TYPE_DATA, TYPE_HEARTBEAT):
        raise FrameError("unknown type %d" % ftype)
    if count < 1 or idx >= count:
        raise FrameError("bad chunk index")
    payload = body[HEADER.size:]
    if len(payload) > event_len:
        raise FrameError("chunk longer than event")
    if ftype == TYPE_HEARTBEAT:
        if count != 1 or len(payload) != event_len or hashlib.sha256(payload).digest() != digest:
            raise FrameError("bad heartbeat")
    return Frame(ftype, flags, stream_id, seq, idx, count, event_len, digest, payload)


def serialize_event(event: Dict[str, Any], extra_fields: tuple = ()) -> bytes:
    """Reduce a log aggregator event to the fields the SIEM needs and encode it as compact JSON."""
    out: Dict[str, Any] = {k: event[k] for k in EVENT_KEYS if event.get(k) is not None}
    if "_raw" not in out:
        # Structured event with no _raw: keep the whole thing as the raw text.
        out["_raw"] = json.dumps(event, separators=(",", ":"), sort_keys=True)
    fields = {k: event[k] for k in extra_fields if event.get(k) is not None}
    if fields:
        out["fields"] = fields
    return json.dumps(out, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def parse_event(data: bytes) -> Dict[str, Any]:
    """Decode a reassembled event. Only accepts the shape serialize_event produces."""
    try:
        obj = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as e:  # Recursion: too deeply nested
        raise FrameError("event is not JSON: %s" % e)
    if not isinstance(obj, dict) or not isinstance(obj.get("_raw"), str):
        raise FrameError("event has no _raw string")
    out: Dict[str, Any] = {"_raw": obj["_raw"]}
    t = obj.get("_time")
    if isinstance(t, (int, float)) and not isinstance(t, bool):
        out["_time"] = t
    for k in ("host", "source", "sourcetype", "index"):
        v = obj.get(k)
        if isinstance(v, str) and len(v) <= 1024:
            out[k] = v
    fields = obj.get("fields")
    if isinstance(fields, dict):
        clean = {k: v for k, v in fields.items()
                 if isinstance(k, str) and isinstance(v, (str, int, float)) and not isinstance(v, bool)}
        if clean:
            out["fields"] = clean
    return out
