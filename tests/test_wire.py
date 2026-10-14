import hashlib
import json
import random

import pytest

from wd2l import wire


def test_single_chunk_roundtrip():
    data = b'{"_raw":"hello"}'
    [dg] = wire.encode_event(7, 1, data)
    f = wire.decode(dg)
    assert (f.type, f.stream_id, f.seq, f.chunk_idx, f.chunk_count) == (wire.TYPE_DATA, 7, 1, 0, 1)
    assert f.payload == data and f.event_len == len(data)


@pytest.mark.parametrize("max_dg", [100, 1472, 8972])
def test_chunks_fit_and_join(max_dg):
    data = bytes(random.Random(1).getrandbits(8) for _ in range(20000))
    dgs = wire.encode_event(1, 5, data, max_dg)
    assert all(len(d) <= max_dg for d in dgs)
    frames = [wire.decode(d) for d in dgs]
    assert [f.chunk_idx for f in frames] == list(range(len(dgs)))
    assert b"".join(f.payload for f in frames) == data


def test_empty_event_is_one_chunk():
    [dg] = wire.encode_event(1, 1, b"")
    assert wire.decode(dg).event_len == 0


def test_corruption_detected():
    [dg] = wire.encode_event(1, 1, b"payload")
    bad = bytearray(dg)
    bad[40] ^= 1
    with pytest.raises(wire.FrameError, match="crc"):
        wire.decode(bytes(bad))


@pytest.mark.parametrize("lit", [b"NaN", b"Infinity", b"-Infinity"])
def test_parse_event_refuses_nan_and_infinity(lit):
    with pytest.raises(wire.FrameError, match="not JSON"):
        wire.parse_event(b'{"_raw":"x","_time":' + lit + b"}")


def test_parse_event_drops_numbers_too_big_for_a_float():
    e = wire.parse_event(b'{"_raw":"x","_time":1e999,"fields":{"a":1e999,"b":2}}')
    assert e == {"_raw": "x", "fields": {"b": 2}}


def test_a_heartbeat_never_carries_a_non_finite_number():
    f = wire.decode(wire.encode_heartbeat(1, 1, {"a": float("nan"), "b": float("inf"), "c": 1.5}))
    assert json.loads(f.payload) == {"c": 1.5}


def test_bad_magic_with_valid_crc():
    body = b"XXXX" + wire.encode_event(1, 1, b"x")[0][4:-4]
    import zlib
    dg = body + wire.CRC.pack(zlib.crc32(body))
    with pytest.raises(wire.FrameError, match="magic"):
        wire.decode(dg)


def test_heartbeat_roundtrip():
    dg = wire.encode_heartbeat(9, 42, {"events_sent": 42, "final": True})
    f = wire.decode(dg)
    assert f.type == wire.TYPE_HEARTBEAT and f.seq == 42
    assert json.loads(f.payload) == {"events_sent": 42, "final": True}


def test_fuzz_decode_only_raises_frame_error():
    rnd = random.Random(2)
    good = wire.encode_event(1, 1, b"x" * 3000, 1000)
    for _ in range(5000):
        base = bytearray(rnd.choice(good))
        for _ in range(rnd.randint(1, 5)):
            base[rnd.randrange(len(base))] = rnd.getrandbits(8)
        cut = rnd.randint(0, len(base))
        for dg in (bytes(base), bytes(base[:cut]), bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 100)))):
            try:
                wire.decode(dg)
            except wire.FrameError:
                pass


def test_serialize_keeps_splunk_fields_only():
    evt = {"_time": 1.5, "host": "h", "source": "s", "sourcetype": "st", "index": "i",
           "_raw": "r", "cribl_pipe": "p", "site": "a"}
    assert json.loads(wire.serialize_event(evt)) == {
        "_time": 1.5, "host": "h", "source": "s", "sourcetype": "st", "index": "i", "_raw": "r"}
    assert json.loads(wire.serialize_event(evt, ("site",)))["fields"] == {"site": "a"}


def test_serialize_structured_event_without_raw():
    out = json.loads(wire.serialize_event({"host": "h", "msg": "x"}))
    assert out["host"] == "h" and json.loads(out["_raw"]) == {"host": "h", "msg": "x"}


def test_parse_event_validates():
    with pytest.raises(wire.FrameError):
        wire.parse_event(b"not json")
    with pytest.raises(wire.FrameError):
        wire.parse_event(b'{"host":"h"}')
    with pytest.raises(wire.FrameError):
        wire.parse_event(b'["_raw"]')
    evt = wire.parse_event(b'{"_raw":"r","_time":"bad","host":5,"fields":{"a":1,"b":[1]},"x":1}')
    assert evt == {"_raw": "r", "fields": {"a": 1}}


def test_flags_round_trip_and_default_to_zero():
    body = b'{"_raw":"x"}'
    assert wire.decode(wire.encode_event(5, 1, body)[0]).flags == 0
    assert wire.decode(wire.encode_event(5, 1, body, flags=wire.FLAG_RECORDS)[0]).flags == 1
    assert wire.decode(wire.encode_heartbeat(5, 1, {"a": 1}, flags=wire.FLAG_RECORDS)).flags == 1


def test_a_precomputed_digest_is_used():
    body = b'{"_raw":"x"}'
    d = wire.event_digest(body)
    assert d == hashlib.sha256(body).digest()
    assert wire.decode(wire.encode_event(5, 1, body, digest=d)[0]).digest == d
