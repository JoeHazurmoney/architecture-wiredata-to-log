# Phase 2: built-in chrony query (`--chrony-addr`)

Part of the [release packaging plan](README.md). Read its **Global constraints** first. Spec:
[spec.md](spec.md) "Phase 2".

**Delivers:**

* `--chrony-addr HOST[:PORT]` on the sender and the receiver. It asks chronyd for `tracking`
  over UDP, with the request `chronyc` sends, and fills `time_quality` with **the same keys**.
  The images have no `chronyc` ([ADR-0004](../../../decisions/0004-container-base-image.md)).
* Without the option, nothing changes.
* A lab stand-in for chronyd, and a lab run (`--chrony-udp`) that proves the UDP path end to end,
  including the clock fault.

**Protocol facts** (chrony's `candm.h`, `util.c`, `cmdmon.c`):

* **Versions and codes:** protocol version 6; request type 1, reply type 2; `REQ_TRACKING` = 33,
  `RPY_TRACKING` = 5; status 0 is success.
* **The request:** a 20-byte header, `!BBBBHHIII` (version, type, res1, res2, command, attempt,
  sequence, pad, pad). chronyd drops a request shorter than its reply, so the request is
  **zero-padded to 108 bytes**.
* **The reply:**
  * a 28-byte header, `!BBBBHHHHHHIII` (version, type, res1, res2, command, reply, status,
    pad ×3, sequence, pad ×2);
  * then 80 bytes of tracking data, `!I16sHHHHIII9Ii`: ref_id, address (16 bytes), family, pad,
    stratum, leap status, ref_time (3 × u32), 9 Floats (the first is `current_correction`),
    EOR.
* **Address family:** 0 = none (a reference clock), 1 = IPv4, 2 = IPv6. Leap status 3 = not
  synchronised.
* **Float:** u32, a 7-bit signed exponent and a 25-bit signed coefficient,
  `value = coef × 2^(exp − 25)`.
* **Access:** chronyd always answers monitoring requests such as `tracking` from 127.0.0.1 and
  ::1, unless it was started with `cmdport 0`.

Run tests with `T` from the plan README.

---

### Task 2.1: The chrony client in `hostinfo`, and the stand-in chronyd

**Files:**
- Modify: `wd2l/hostinfo.py`, `tests/helpers.py`, `tests/test_hostinfo.py`
- Create: `lab/fake_chronyd.py`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  * `hostinfo.CHRONY_PORT = 323`, `hostinfo.CHRONY_REPLY_SIZE = 108`;
  * `hostinfo.chrony_float(x: int) -> float`;
  * `hostinfo.chrony_request(sequence: int) -> bytes`;
  * `hostinfo.chrony_reply_sequence(data: bytes) -> Optional[int]`;
  * `hostinfo.parse_chrony_tracking(data: bytes, sequence: int) -> Dict` with the keys
    `stratum`, `offset_ms`, `synced` and `source` (raises `ValueError`);
  * `hostinfo.chrony_tracking(addr: Tuple[str, int], timeout: float = 2.0) -> Dict` (raises
    `OSError` or `ValueError`);
  * `hostinfo.chrony_hostport(s: str) -> Tuple[str, int]`, and `hostinfo.chrony_address(s: str)
    -> str`, the argparse type;
  * `lab/fake_chronyd.py`: `float_to_chrony(x) -> int`, `tracking_reply(seq, **fields) ->
    bytes`, `answer(data, unsynced=False) -> Optional[bytes]`, `respond(data, flag) ->
    Optional[bytes]`, and a `--listen`/`--flag` CLI;
  * `helpers.chronyd_server(replies)`, a context manager yielding `(host, port)`. `replies` is
    `request -> [datagram, ...]`.

- [ ] **Step 1: Write the failing tests**

`tests/helpers.py`, add at the end:

```python
import contextlib


@contextlib.contextmanager
def chronyd_server(replies):
    """A chronyd stand-in on a free UDP port of 127.0.0.1. replies(request) returns the
    datagrams to send back, in order (none, one, or a stale one first)."""
    import socket
    import threading
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    s.settimeout(0.05)
    stop = threading.Event()

    def run():
        while not stop.is_set():
            try:
                data, peer = s.recvfrom(4096)
            except socket.timeout:
                continue
            for out in replies(data):
                s.sendto(out, peer)

    t = threading.Thread(target=run, daemon=True)
    t.start()
    try:
        yield s.getsockname()
    finally:
        stop.set()
        t.join()
        s.close()
```

`tests/test_hostinfo.py`, add after the `chronyc` tests:

```python
import socket

from lab import fake_chronyd

from helpers import chronyd_server

FLOATS = [(0x00000000, 0.0), (0x04800000, 1.0), (0x03000000, -1.0), (0x02800000, 0.5),
          (0xF0800000, 2.0 ** -10)]


def seq_of(request):
    return int.from_bytes(request[8:12], "big")


def test_chrony_float_known_values():
    for raw, value in FLOATS:
        assert hostinfo.chrony_float(raw) == value
        assert fake_chronyd.float_to_chrony(value) == raw


@pytest.mark.parametrize("v", [0.000012345, -0.000001, 0.0137, -12.345, 1024.5, 3.0e-9])
def test_chrony_float_round_trips(v):
    assert hostinfo.chrony_float(fake_chronyd.float_to_chrony(v)) == pytest.approx(v, rel=1e-7)


def test_request_is_padded_to_the_reply_size():
    r = hostinfo.chrony_request(0x01020304)
    assert len(r) == hostinfo.CHRONY_REPLY_SIZE == 108
    assert r[:4] == bytes([6, 1, 0, 0]) and r[4:6] == (33).to_bytes(2, "big")
    assert r[8:12] == bytes([1, 2, 3, 4]) and r[20:] == bytes(88)


def test_query_synced_reference_clock():
    with chronyd_server(lambda req: [fake_chronyd.answer(req)]) as addr:
        assert hostinfo.chrony_tracking(addr) == {
            "stratum": 3, "offset_ms": 0.004, "synced": True, "source": "GPS"}


def test_query_unsynced():
    with chronyd_server(lambda req: [fake_chronyd.answer(req, unsynced=True)]) as addr:
        q = hostinfo.chrony_tracking(addr)
    assert q == {"stratum": 0, "offset_ms": 0.0, "synced": False, "source": "00000000"}


def test_query_ntp_source_over_ipv4():
    ip = socket.inet_aton("162.159.200.123")
    with chronyd_server(lambda req: [fake_chronyd.tracking_reply(
            seq_of(req), ref_id=0xA29FC87B, family=1, addr=ip, correction=0.000012345)]) as addr:
        assert hostinfo.chrony_tracking(addr) == {
            "stratum": 3, "offset_ms": 0.012, "synced": True, "source": "162.159.200.123"}


def test_stale_reply_is_skipped():
    def replies(req):
        return [fake_chronyd.tracking_reply(seq_of(req) ^ 1, stratum=9), fake_chronyd.answer(req)]
    with chronyd_server(replies) as addr:
        assert hostinfo.chrony_tracking(addr)["stratum"] == 3


def test_refused_request_is_unavailable_with_the_status():
    with chronyd_server(lambda req: [fake_chronyd.tracking_reply(seq_of(req), status=2)]) as addr:
        q = hostinfo.TimeQuality(query=lambda: hostinfo.chrony_tracking(addr, 1.0)).read()
    assert q["synced"] is None and q["source"] == "unavailable" and "status 2" in q["error"]


def test_garbage_reply_is_unavailable():
    with chronyd_server(lambda req: [b"hello"]) as addr:
        q = hostinfo.TimeQuality(query=lambda: hostinfo.chrony_tracking(addr, 1.0)).read()
    assert q["source"] == "unavailable" and "not a chrony reply" in q["error"]


def test_short_tracking_reply_is_unavailable():
    with chronyd_server(lambda req: [fake_chronyd.answer(req)[:60]]) as addr:
        q = hostinfo.TimeQuality(query=lambda: hostinfo.chrony_tracking(addr, 1.0)).read()
    assert q["source"] == "unavailable" and "short" in q["error"]


def test_no_answer_times_out():
    with chronyd_server(lambda req: []) as addr:
        t0 = time.monotonic()
        q = hostinfo.TimeQuality(query=lambda: hostinfo.chrony_tracking(addr, 0.3)).read()
    assert q["source"] == "unavailable" and time.monotonic() - t0 < 2


def test_nothing_listening_is_unavailable_quickly():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    addr = s.getsockname()
    s.close()
    t0 = time.monotonic()
    q = hostinfo.TimeQuality(query=lambda: hostinfo.chrony_tracking(addr, 2.0)).read()
    assert q["source"] == "unavailable" and time.monotonic() - t0 < 1.0


@pytest.mark.parametrize("s, want", [
    ("127.0.0.1", ("127.0.0.1", 323)), ("127.0.0.1:1323", ("127.0.0.1", 1323)),
    ("localhost:323", ("localhost", 323)), ("[::1]:323", ("::1", 323)), ("[::1]", ("::1", 323)),
    ("::1", ("::1", 323))])
def test_chrony_hostport(s, want):
    assert hostinfo.chrony_hostport(s) == want
    assert hostinfo.chrony_address(s) == s


@pytest.mark.parametrize("s", ["", ":323", "host:", "host:0", "host:70000", "host:abc", "[::1",
                               "[::1]x"])
def test_chrony_hostport_rejects(s):
    with pytest.raises(ValueError):
        hostinfo.chrony_hostport(s)


def test_fake_chronyd_ignores_short_requests_like_chronyd(tmp_path):
    assert fake_chronyd.answer(hostinfo.chrony_request(1)[:20]) is None
    assert fake_chronyd.answer(b"junk") is None
    flag = tmp_path / "clock-bad"
    req = hostinfo.chrony_request(7)
    assert hostinfo.parse_chrony_tracking(fake_chronyd.respond(req, str(flag)), 7)["synced"]
    flag.write_text("")
    assert not hostinfo.parse_chrony_tracking(fake_chronyd.respond(req, str(flag)), 7)["synced"]
```

- [ ] **Step 2: Run them to verify they fail**

Run: `T tests/test_hostinfo.py -v`
Expected: FAIL. Collection error `ModuleNotFoundError: No module named 'lab.fake_chronyd'`.

- [ ] **Step 3: Write `lab/fake_chronyd.py`**

```python
#!/usr/bin/env python3
"""Stand-in for chronyd's command port in the lab, for --chrony-addr (the containers have no
chronyc). Answers `tracking` like the hosts: synchronised at stratum 3 to a GPS reference
clock, 4 µs off; or "not synchronised" while the flag file exists (lab --fault clock).
Like chronyd, it ignores requests shorter than its reply.

    python3 lab/fake_chronyd.py [--listen 127.0.0.1:323] [--flag FILE]

float_to_chrony() is chrony's UTI_FloatHostToNetwork. The tests use it to build replies."""

import argparse
import math
import os
import socket
import struct
from typing import Optional

REQ = struct.Struct("!BBBBHHIII")
RPY = struct.Struct("!BBBBHHHHHHIII")
TRACKING = struct.Struct("!I16sHHHHIII9Ii")
GPS = 0x47505300          # "GPS\0"
COEF_MAX = (1 << 24) - 1


def float_to_chrony(x: float) -> int:
    neg = x < 0
    x = abs(x) if x == x else 0.0        # NaN is sent as zero
    if x < 1.0e-100:
        exp = coef = 0
    elif x > 1.0e100:
        exp, coef = 63, COEF_MAX + neg
    else:
        exp = int(math.log(x) / math.log(2) + 1)
        coef = int(x * 2.0 ** (-exp + 25) + 0.5)
        while coef > COEF_MAX + neg:
            coef >>= 1
            exp += 1
        if exp > 63:
            exp, coef = 63, COEF_MAX + neg
        elif exp < -64:
            if exp + 25 >= -64:
                coef >>= -64 - exp
                exp = -64
            else:
                exp = coef = 0
    if neg:
        coef = (-coef) & ((1 << 25) - 1)
    return ((exp & 0x7F) << 25) | coef


def tracking_reply(seq: int, ref_id: int = GPS, family: int = 0, addr: bytes = b"",
                   stratum: int = 3, leap: int = 0, correction: float = 0.000004,
                   status: int = 0) -> bytes:
    head = RPY.pack(6, 2, 0, 0, 33, 5, status, 0, 0, 0, seq, 0, 0)
    if status:
        return head                       # chronyd sends only the header with an error status
    floats = [float_to_chrony(v) for v in
              (correction, 0.000001, 0.000003, -1.0, 0.0, 0.01, 0.0001, 0.00005, 16.0)]
    return head + TRACKING.pack(ref_id, addr.ljust(16, b"\0"), family, 0, stratum, leap,
                                0, 1791209000, 0, *floats, 0)


def answer(data: bytes, unsynced: bool = False) -> Optional[bytes]:
    if len(data) < RPY.size + TRACKING.size:
        return None
    version, ptype, _r1, _r2, command, _attempt, seq, _p1, _p2 = REQ.unpack_from(data)
    if (version, ptype, command) != (6, 1, 33):
        return None
    if unsynced:
        return tracking_reply(seq, ref_id=0, stratum=0, leap=3, correction=0.0)
    return tracking_reply(seq)


def respond(data: bytes, flag: Optional[str]) -> Optional[bytes]:
    return answer(data, unsynced=bool(flag) and os.path.exists(flag))


def main() -> None:
    p = argparse.ArgumentParser(description="chronyd stand-in for the lab (--chrony-addr)")
    p.add_argument("--listen", default="127.0.0.1:323")
    p.add_argument("--flag", help="answer 'not synchronised' while this file exists")
    a = p.parse_args()
    host, port = a.listen.rsplit(":", 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((host, int(port)))
    while True:
        data, peer = s.recvfrom(4096)
        out = respond(data, a.flag)
        if out:
            s.sendto(out, peer)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Write the client in `wd2l/hostinfo.py`**

Add `import shlex` and `import struct` to the imports, and `Tuple` to the `typing` import.
Then add this section just **before** `class TimeQuality`:

```python
# ---------------------------------------------------------------- chrony over UDP (cmdmon)
#
# The container images have no chronyc (docs/decisions/0004-container-base-image.md), so they
# ask chronyd the same question on its command port: UDP 323, which chronyd always answers from
# 127.0.0.1 and ::1 for monitoring requests. Protocol version 6, from chrony's candm.h.

CHRONY_PORT = 323
CHRONY_PROTO = 6
CHRONY_REQ_TRACKING = 33
CHRONY_RPY_TRACKING = 5
CHRONY_LEAP_UNSYNCED = 3
# version, type, res1, res2, command, attempt, sequence, pad, pad
_CHRONY_REQ = struct.Struct("!BBBBHHIII")
# version, type, res1, res2, command, reply, status, pad, pad, pad, sequence, pad, pad
_CHRONY_RPY = struct.Struct("!BBBBHHHHHHIII")
# ref_id, address, family, pad, stratum, leap, ref_time (3), nine Floats, EOR
_CHRONY_TRACKING = struct.Struct("!I16sHHHHIII9Ii")
CHRONY_REPLY_SIZE = _CHRONY_RPY.size + _CHRONY_TRACKING.size    # 108


def chrony_float(x: int) -> float:
    """chrony's 32-bit network float: a 7-bit signed exponent and a 25-bit signed coefficient
    (UTI_FloatNetworkToHost)."""
    exp = x >> 25
    if exp >= 64:
        exp -= 128
    coef = x % (1 << 25)
    if coef >= 1 << 24:
        coef -= 1 << 25
    return coef * 2.0 ** (exp - 25)


def chrony_request(sequence: int) -> bytes:
    """A tracking request, zero-padded to the reply's size: chronyd ignores shorter requests,
    so it never sends more than it was sent."""
    head = _CHRONY_REQ.pack(CHRONY_PROTO, 1, 0, 0, CHRONY_REQ_TRACKING, 0, sequence, 0, 0)
    return head + bytes(CHRONY_REPLY_SIZE - len(head))


def chrony_reply_sequence(data: bytes) -> Optional[int]:
    """The sequence number of a chrony reply, or None if `data` isn't one."""
    if len(data) < _CHRONY_RPY.size:
        return None
    f = _CHRONY_RPY.unpack_from(data)
    return f[10] if (f[0], f[1]) == (CHRONY_PROTO, 2) else None


def _chrony_source(ref_id: int, addr: bytes, family: int) -> str:
    if family == 1:
        return socket.inet_ntop(socket.AF_INET, addr[:4])
    if family == 2:
        return socket.inet_ntop(socket.AF_INET6, addr)
    # A reference clock (GPS, PPS ...) has no address: chronyc shows its ref ID as text.
    name = "".join(chr(b) for b in ref_id.to_bytes(4, "big") if 32 < b < 127)
    return name or "%08X" % ref_id


def parse_chrony_tracking(data: bytes, sequence: int) -> Dict[str, Any]:
    """A tracking reply -> the keys parse_chronyc_tracking gives. ValueError for anything else."""
    if chrony_reply_sequence(data) != sequence:
        raise ValueError("not a chrony reply to this request (%d bytes)" % len(data))
    command, reply, status = _CHRONY_RPY.unpack_from(data)[4:7]
    if status != 0:
        raise ValueError("chronyd refused the tracking request (status %d)" % status)
    if command != CHRONY_REQ_TRACKING or reply != CHRONY_RPY_TRACKING:
        raise ValueError("unexpected chrony reply (command %d, reply %d)" % (command, reply))
    if len(data) < CHRONY_REPLY_SIZE:
        raise ValueError("short chrony tracking reply (%d bytes)" % len(data))
    f = _CHRONY_TRACKING.unpack_from(data, _CHRONY_RPY.size)
    ref_id, addr, family, _pad, stratum, leap = f[:6]
    correction = chrony_float(f[9])        # chronyc's "System time": the offset from NTP time
    synced = leap != CHRONY_LEAP_UNSYNCED and 0 < stratum < 16 and ref_id != 0
    return {"stratum": stratum, "offset_ms": round(correction * 1000.0, 3), "synced": synced,
            "source": _chrony_source(ref_id, addr, family)}


def chrony_tracking(addr: Tuple[str, int], timeout: float = 2.0) -> Dict[str, Any]:
    """Ask chronyd for `tracking` over UDP, as `chronyc -c tracking` does. Late replies to
    earlier requests are skipped. Raises OSError (refused, no answer in time) or ValueError
    (an error status, a malformed reply); TimeQuality reports either as "unavailable"."""
    seq = int.from_bytes(os.urandom(4), "big")
    family, kind, proto, _name, sockaddr = socket.getaddrinfo(addr[0], addr[1], 0,
                                                              socket.SOCK_DGRAM)[0]
    deadline = time.monotonic() + timeout
    with socket.socket(family, kind, proto) as s:
        s.connect(sockaddr)
        s.send(chrony_request(seq))
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise socket.timeout("no reply from chronyd at %s:%d" % (addr[0], addr[1]))
            s.settimeout(left)
            data = s.recv(4096)
            if chrony_reply_sequence(data) not in (None, seq):
                continue                     # a late reply to an earlier request
            return parse_chrony_tracking(data, seq)


def chrony_hostport(s: str) -> Tuple[str, int]:
    """"HOST", "HOST:PORT", "[IPV6]:PORT" or a bare IPv6 address; the port defaults to 323."""
    s = s.strip()
    if s.startswith("["):
        host, sep, rest = s[1:].partition("]")
        if not sep or (rest and not rest.startswith(":")):
            raise ValueError("bad chrony address %r" % s)
        port = rest[1:] or str(CHRONY_PORT)
    elif s.count(":") == 1:
        host, port = s.split(":")
    else:
        host, port = s, str(CHRONY_PORT)
    if not host or not port.isdigit() or not 0 < int(port) < 65536:
        raise ValueError("bad chrony address %r" % s)
    return host, int(port)


def chrony_address(s: str) -> str:
    """argparse type for --chrony-addr: checks the value and keeps the text, which goes into
    the config audit record as given."""
    chrony_hostport(s)
    return s
```

Then change `TimeQuality` so the read is pluggable:

```python
class TimeQuality:
    """chrony's view of this host's clock, read at most every `every` seconds: by running
    chronyc (`cmd`), or by `query` (chrony_tracking, for --chrony-addr)."""

    def __init__(self, cmd: Sequence[str] = ("chronyc", "-c", "tracking"), every: float = 60.0,
                 timeout: float = 2.0, max_stratum: int = 3, max_offset_ms: float = 100.0,
                 clock: Callable[[], float] = time.monotonic,
                 query: Optional[Callable[[], Dict[str, Any]]] = None):
        self.cmd = list(cmd)
        self.every = every
        self.timeout = timeout
        self.max_stratum = max_stratum
        self.max_offset_ms = max_offset_ms
        self.clock = clock
        self.query = query or self._chronyc
        self._at: Optional[float] = None
        self._last: Dict[str, Any] = {}

    def _chronyc(self) -> Dict[str, Any]:
        out = subprocess.run(self.cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             timeout=self.timeout, check=True).stdout
        return parse_chronyc_tracking(out.decode("utf-8", "replace"))

    def read(self) -> Dict[str, Any]:
        now = self.clock()
        if self._at is None or now - self._at >= self.every:
            self._at = now
            try:
                self._last = self.query()
            except (OSError, subprocess.SubprocessError, ValueError) as e:
                self._last = {"synced": None, "source": "unavailable", "error": str(e)[:200]}
        return dict(self._last)
```

(`alarm()` is unchanged.) Update the module docstring's first sentence to say "chrony's view
of the clock (chronyc, or chronyd over UDP)".

- [ ] **Step 5: Run the tests to verify they pass**

Run: `T tests/test_hostinfo.py -v && T312 tests/test_hostinfo.py -q`
Expected: PASS on both Pythons. The existing `chronyc` tests pass unchanged.

- [ ] **Step 6: Commit**

```bash
git add wd2l/hostinfo.py lab/fake_chronyd.py tests/helpers.py tests/test_hostinfo.py
git commit -m "hostinfo: ask chronyd for tracking over UDP (stdlib cmdmon client)"
```

---

### Task 2.2: `--chrony-addr` on both sides

**Files:**
- Modify: `wd2l/hostinfo.py`, `wd2l/sender.py`, `wd2l/receiver.py`,
  `tests/test_hostinfo.py`, `tests/test_receiver_audit.py`,
  `docs/deployment/log-server.md`, `docs/deployment/receiver.md`, `docs/operations.md`,
  `docs/audit-and-health-plan.md`

**Interfaces:**
- Consumes: Task 2.1.
- Produces:
  * `hostinfo.time_quality(chronyc: str = "chronyc", chrony_addr: Optional[str] = None,
    every: float = 60.0) -> TimeQuality`;
  * `--chrony-addr HOST[:PORT]` on `sender.build_parser()` and `receiver.build_parser()`
    (`a.chrony_addr`, default `None`).

- [ ] **Step 1: Write the failing tests**

`tests/test_hostinfo.py`, add:

```python
def test_time_quality_uses_udp_when_given_an_address():
    with chronyd_server(lambda req: [fake_chronyd.answer(req)]) as (host, port):
        tq = hostinfo.time_quality("/nonexistent/chronyc", "%s:%d" % (host, port))
        assert tq.read()["source"] == "GPS"


def test_time_quality_runs_chronyc_without_an_address(tmp_path):
    script = tmp_path / "chronyc.py"
    script.write_text("print(%r)\n" % SYNCED)
    tq = hostinfo.time_quality("%s %s" % (sys.executable, script), None, every=5.0)
    assert tq.cmd[-2:] == ["-c", "tracking"] and tq.every == 5.0
    assert tq.read()["source"] == "162.159.200.123"


def test_both_parsers_take_chrony_addr():
    from wd2l import receiver, sender
    assert sender.build_parser().parse_args(["--chrony-addr", "127.0.0.1:323"]).chrony_addr \
        == "127.0.0.1:323"
    assert receiver.build_parser().parse_args(["--pcap", "x", "--chrony-addr", "[::1]"]) \
        .chrony_addr == "[::1]"
    assert sender.build_parser().parse_args([]).chrony_addr is None
    for p, base in ((sender.build_parser(), []), (receiver.build_parser(), ["--pcap", "x"])):
        with pytest.raises(SystemExit):
            p.parse_args(base + ["--chrony-addr", "host:notaport"])
```

`tests/test_receiver_audit.py`, add (next to `test_replay_run_records_the_files_and_their_hashes`):

```python
def test_replay_reads_time_quality_from_chronyd_over_udp(tmp_path):
    from lab import fake_chronyd
    from helpers import chronyd_server
    p = replay_pcap(tmp_path)
    adir, out = str(tmp_path / "audit"), str(tmp_path / "out")
    with chronyd_server(lambda req: [fake_chronyd.answer(req)]) as (host, port):
        receiver.main(["--pcap", p, "--out-dir", out, "--audit-dir", adir,
                       "--chrony-addr", "%s:%d" % (host, port)])
    recs = read_audit(adir)
    assert recs[0]["event"] == "start"
    assert recs[0]["time_quality"] == {"stratum": 3, "offset_ms": 0.004, "synced": True,
                                       "source": "GPS"}
    assert auditlog.verify_dir(adir).ok
```

- [ ] **Step 2: Run them to verify they fail**

Run: `T tests/test_hostinfo.py tests/test_receiver_audit.py -k "time_quality or chrony" -v`
Expected: FAIL (`AttributeError: module 'wd2l.hostinfo' has no attribute 'time_quality'`, and
`unrecognized arguments: --chrony-addr`).

- [ ] **Step 3: Write the implementation**

`wd2l/hostinfo.py`, add after `class TimeQuality`:

```python
def time_quality(chronyc: str = "chronyc", chrony_addr: Optional[str] = None,
                 every: float = 60.0) -> TimeQuality:
    """The TimeQuality for --chronyc / --chrony-addr: chronyd over UDP when an address is
    given (the containers have no chronyc), else the chronyc command."""
    tq = TimeQuality(shlex.split(chronyc) + ["-c", "tracking"], every=every)
    if chrony_addr:
        hostport = chrony_hostport(chrony_addr)
        tq.query = lambda: chrony_tracking(hostport, tq.timeout)
    return tq
```

`wd2l/sender.py` `build_parser()`, right after the `--chronyc` argument:

```python
    p.add_argument("--chrony-addr", type=hostinfo.chrony_address, metavar="HOST[:PORT]",
                   help="ask chronyd over UDP (its command port, 323) for time quality instead "
                        "of running --chronyc; the container units use 127.0.0.1:323")
```

`wd2l/sender.py` `main()`: replace
`tq = hostinfo.TimeQuality(shlex.split(a.chronyc) + ["-c", "tracking"])` with
`tq = hostinfo.time_quality(a.chronyc, a.chrony_addr)`.

`wd2l/receiver.py`: add the same argument after its `--chronyc`. In `main()`, replace the
`hostinfo.TimeQuality(...)` call with
`tq = hostinfo.time_quality(a.chronyc, a.chrony_addr, every=a.time_check_interval)`.

In both files, run `grep -n "shlex" wd2l/sender.py wd2l/receiver.py`, and remove
`import shlex` from any file where nothing else uses it.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `T -q && T312 -q`
Expected: the whole suite PASSes on both Pythons.

- [ ] **Step 5: Docs**

* **`docs/deployment/log-server.md`** options table, after the `--chronyc` row:

  ```markdown
  | `--chrony-addr` | none | Ask chronyd over UDP (`HOST[:PORT]`, port 323) instead of running `chronyc`. The container unit uses `127.0.0.1:323`. chronyd's default configuration answers it; `cmdport 0` turns it off |
  ```

* **`docs/deployment/receiver.md`:** the same row after its `--chronyc` row.
* **`docs/operations.md`**, "Alert: time quality". Add after step 1:

  ```markdown
     In a container (`--chrony-addr`), "unavailable" can also mean chronyd doesn't answer on
     127.0.0.1:323. As a normal user (not root) on the host, `chronyc -h 127.0.0.1 tracking`
     asks the same way and shows whether it does.
  ```

* **`docs/audit-and-health-plan.md`** §11, as-built block. Add a last bullet:

  ```markdown
  > * `--chrony-addr HOST[:PORT]` (added with the release packaging) asks chronyd over UDP
  >   with the request `chronyc` sends, for the container images, which have no `chronyc`
  >   ([ADR-0004](decisions/0004-container-base-image.md)). The `time_quality` keys are the
  >   same.
  ```

- [ ] **Step 6: Commit**

```bash
git add wd2l/hostinfo.py wd2l/sender.py wd2l/receiver.py tests/test_hostinfo.py \
  tests/test_receiver_audit.py docs/deployment/log-server.md docs/deployment/receiver.md \
  docs/operations.md docs/audit-and-health-plan.md
git commit -m "--chrony-addr: time quality from chronyd over UDP on both sides"
```

---

### Task 2.3: The lab proves the UDP path (`--chrony-udp`)

**Files:**
- Modify: `lab/run-lab.sh`, `.github/workflows/tests.yml`, `docs/running-the-lab.md`

**Interfaces:**
- Consumes: `lab/fake_chronyd.py` (Task 2.1) and `--chrony-addr` (Task 2.2).
- Produces:
  * `lab/run-lab.sh --chrony-udp`, which runs `fake_chronyd.py` in both namespaces on
    127.0.0.1:323 and gives both sides `--chrony-addr 127.0.0.1:323`;
  * the shell array `TIME_ARGS` in `run-lab.sh`, which Task 3.3's `--image` mode reuses.

- [ ] **Step 1: Change `lab/run-lab.sh`**

* **Usage block:** add `[--chrony-udp]` and the explanation:
  `--chrony-udp   both sides ask a stand-in chronyd over UDP (--chrony-addr), as the containers do`.
* **Defaults:** add `CHRONY_UDP=0`.
* **Option parsing:** add `--chrony-udp) CHRONY_UDP=1; shift ;;`.
* **After `CHRONYC="$CHRONYC $OUT/clock-bad"`, add:**

```bash
TIME_ARGS=(--chronyc "$CHRONYC")
```

* **After the namespaces are built** (right after the Enclave 2 `notx` nft block), add:

```bash
if [ "$CHRONY_UDP" = 1 ]; then
  # A chronyd stand-in on each side's 127.0.0.1:323, as the containers ask it (--chrony-addr).
  for ns in wd2l-enc1 wd2l-enc2; do
    ip netns exec "$ns" python3 "$HERE/fake_chronyd.py" --listen 127.0.0.1:323 \
      --flag "$OUT/clock-bad" 2>>"$OUT/fake_chronyd.log" &
    PIDS+=($!)
  done
  TIME_ARGS=(--chrony-addr 127.0.0.1:323)
fi
```

* **Use the array:** in `RX_ARGS`, in `start_sender`, and in the archive-replay command, replace
  `--chronyc "$CHRONYC"` with `"${TIME_ARGS[@]}"`. The archive replay runs outside the
  namespaces, so for it keep `--chronyc "$CHRONYC"`: it has no chronyd stand-in. Its
  `time_quality` is read from the fake `chronyc`, as today.

- [ ] **Step 2: CI.** In `.github/workflows/tests.yml`'s `lab` job, add after the `--fault clock`
  run:

```yaml
      - run: sudo lab/run-lab.sh --chrony-udp
      - run: sudo lab/run-lab.sh --fault clock --chrony-udp
```

- [ ] **Step 3: Docs.** In `docs/running-the-lab.md` §9 (faults), after the `clock` row's table,
  add one sentence: "`--chrony-udp` runs the same lab with both sides asking a chronyd stand-in
  over UDP, as the container images do (`--chrony-addr`); `--fault clock --chrony-udp` checks
  the clock alarm that way."

- [ ] **Step 4: Check it.** Locally, the privileged-container lab from the plan README may work:

```bash
MSYS_NO_PATHCONV=1 docker run --rm --privileged -v "$(pwd -W)":/src -w /src ubuntu:24.04 bash -c \
  "apt-get update -qq && apt-get install -y -qq iproute2 nftables tcpdump python3 >/dev/null && lab/run-lab.sh --fault clock --chrony-udp"
```

Expected: the run ends in `PASS`, and `check_fault.py` prints a `time_status` alarm and then
`ok`. If Docker Desktop's kernel lacks `act_mirred`, the CI `lab` job is the check, on the next
push (with your partner's OK).

- [ ] **Step 5: Commit**

```bash
git add lab/run-lab.sh .github/workflows/tests.yml docs/running-the-lab.md
git commit -m "Lab: --chrony-udp proves the UDP time-quality path, clock fault included"
```
