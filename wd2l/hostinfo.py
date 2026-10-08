"""Facts about this host and process for audit and health records: who runs us or signals us,
which build, chrony's view of the clock (chronyc, or chronyd over UDP), and CPU and memory.
Anything that can't be read comes back as None or "unavailable"; nothing here raises, except
the chrony parsers and chrony_tracking, which raise for TimeQuality to catch."""

from __future__ import annotations

import glob
import hashlib
import os
import pwd
import resource
import shlex
import socket
import struct
import subprocess
import time
from typing import Any, Callable, Dict, Optional, Sequence, Tuple

UNSET_AUID = 4294967295
PKG_DIR = os.path.dirname(os.path.abspath(__file__))
LEAP_UNSYNCED = "Not synchronised"


def hostname() -> str:
    return socket.gethostname()


def _read(path: str) -> Optional[str]:
    try:
        with open(path) as f:
            return f.read().strip()
    except (OSError, UnicodeDecodeError):
        return None


def _user(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return "?"


def loginuid(proc: str = "/proc/self") -> Optional[int]:
    """The audit login uid (auid): who logged in, kept across sudo. None when unset (services)."""
    v = _read(os.path.join(proc, "loginuid"))
    if v is None or not v.isdigit() or int(v) == UNSET_AUID:
        return None
    return int(v)


def systemd_unit(proc: str = "/proc/self") -> Optional[str]:
    for line in (_read(os.path.join(proc, "cgroup")) or "").splitlines():
        last = line.rsplit("/", 1)[-1]
        if last.endswith(".service"):
            return last
    return None


def actor(proc: str = "/proc/self", uid: Optional[int] = None,
          environ: Optional[Dict[str, str]] = None) -> str:
    """Who runs this process: "uid=987(wd2l) unit=wd2l-sender.service", or
    "uid=987(wd2l) auid=1001(jdoe) via sudo" when a person started it."""
    uid = os.getuid() if uid is None else uid
    env = os.environ if environ is None else environ
    parts = ["uid=%d(%s)" % (uid, _user(uid))]
    auid = loginuid(proc)
    if auid is not None:
        parts.append("auid=%d(%s)" % (auid, _user(auid)))
    unit = systemd_unit(proc)
    if unit:
        parts.append("unit=" + unit)
    if env.get("SUDO_USER"):
        parts.append("via sudo")
    return " ".join(parts)


def signal_actor(pid: int, uid: int, proc_root: str = "/proc") -> str:
    """Who sent a signal (from sigwaitinfo): "uid=0(root) pid=4242 comm=kill auid=1001(jdoe)".
    The sending process is often gone already; then only uid and pid are known."""
    parts = ["uid=%d(%s)" % (uid, _user(uid)), "pid=%d" % pid]
    base = os.path.join(proc_root, str(pid))
    comm = _read(os.path.join(base, "comm"))
    if comm:
        parts.append("comm=" + comm)
    auid = loginuid(base)
    if auid is not None:
        parts.append("auid=%d(%s)" % (auid, _user(auid)))
    return " ".join(parts)


def build_id(environ: Optional[Dict[str, str]] = None, pkg_dir: str = PKG_DIR) -> str:
    """The build (git commit): $WD2L_BUILD, else the BUILD file the install step writes next to
    the code, else "unknown"."""
    env = os.environ if environ is None else environ
    return env.get("WD2L_BUILD") or _read(os.path.join(pkg_dir, "BUILD")) or "unknown"


def code_sha256(pkg_dir: str = PKG_DIR) -> str:
    """One SHA-256 over the package's .py files (names and contents): which code is running."""
    try:
        h = hashlib.sha256()
        for name in sorted(os.listdir(pkg_dir)):
            if name.endswith(".py"):
                with open(os.path.join(pkg_dir, name), "rb") as f:
                    h.update(name.encode() + b"\0" + hashlib.sha256(f.read()).digest())
        return h.hexdigest()
    except OSError:
        return "unavailable"


# ---------------------------------------------------------------- time quality (chrony)

def parse_chronyc_tracking(text: str) -> Dict[str, Any]:
    """`chronyc -c tracking`, one CSV line: reference id, reference name, stratum, reference
    time, system time offset (s), last offset, RMS offset, frequency, residual frequency, skew,
    root delay, root dispersion, update interval, leap status."""
    f = text.strip().split(",")
    if len(f) < 14:
        raise ValueError("unexpected chronyc output: %r" % text[:200])
    stratum = int(f[2])
    synced = f[13] != LEAP_UNSYNCED and 0 < stratum < 16 and f[0].strip("0") != ""
    return {"stratum": stratum, "offset_ms": round(float(f[4]) * 1000.0, 3), "synced": synced,
            "source": f[1] or f[0]}


def time_alarm(q: Dict[str, Any], max_stratum: int = 3,
               max_offset_ms: float = 100.0) -> Optional[str]:
    """Why time quality is out of bounds (§11), or None when it is fine."""
    if q.get("synced") is None:
        return "unavailable"
    if not q["synced"]:
        return "unsynced"
    if q["stratum"] > max_stratum:
        return "stratum %d > %d" % (q["stratum"], max_stratum)
    if abs(q["offset_ms"]) > max_offset_ms:
        return "offset %.1f ms > %g ms" % (q["offset_ms"], max_offset_ms)
    return None


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
# ref_id, address, family, pad, stratum, leap, ref_time (3), nine Floats. chronyd sends the
# reply up to its EOR marker, not including it (PKL_ReplyLength).
_CHRONY_TRACKING = struct.Struct("!I16sHHHHIII9I")
CHRONY_REPLY_SIZE = _CHRONY_RPY.size + _CHRONY_TRACKING.size    # 104


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

    def alarm(self, q: Optional[Dict[str, Any]] = None) -> Optional[str]:
        return time_alarm(self.read() if q is None else q, self.max_stratum, self.max_offset_ms)


def time_quality(chronyc: str = "chronyc", chrony_addr: Optional[str] = None,
                 every: float = 60.0) -> TimeQuality:
    """The TimeQuality for --chronyc / --chrony-addr: chronyd over UDP when an address is
    given (the containers have no chronyc), else the chronyc command."""
    tq = TimeQuality(shlex.split(chronyc) + ["-c", "tracking"], every=every)
    if chrony_addr:
        hostport = chrony_hostport(chrony_addr)
        tq.query = lambda: chrony_tracking(hostport, tq.timeout)
    return tq


# ---------------------------------------------------------------- this process

class ProcStats:
    """This process's CPU % since the previous read() (all threads) and its resident memory."""

    def __init__(self, clock: Callable[[], float] = time.monotonic,
                 statm: str = "/proc/self/statm"):
        self.clock = clock
        self.statm = statm
        self._t = clock()
        self._cpu = self._cpu_s()

    @staticmethod
    def _cpu_s() -> float:
        r = resource.getrusage(resource.RUSAGE_SELF)
        return r.ru_utime + r.ru_stime

    def read(self) -> Dict[str, Any]:
        now, cpu = self.clock(), self._cpu_s()
        dt = now - self._t
        pct = round(100.0 * (cpu - self._cpu) / dt, 1) if dt > 0 else 0.0
        self._t, self._cpu = now, cpu
        rss = None
        v = _read(self.statm)
        if v:
            try:
                rss = round(int(v.split()[1]) * os.sysconf("SC_PAGE_SIZE") / 1048576.0, 1)
            except (IndexError, ValueError):
                rss = None
        return {"cpu_pct": pct, "rss_mb": rss}


# ---------------------------------------------------------------- NICs and the capture archive

NIC_COUNTERS = ("rx_packets", "rx_bytes", "rx_errors", "rx_dropped", "rx_crc_errors",
                "rx_frame_errors", "rx_missed_errors", "tx_packets", "tx_errors", "tx_dropped")


def _int(v: Optional[str]) -> Optional[int]:
    try:
        return int(v) if v is not None else None
    except ValueError:
        return None


def nic_stats(iface: str, sysfs: str = "/sys/class/net") -> Dict[str, Any]:
    """Carrier and counters from sysfs. Reading `carrier` fails while the interface is down,
    which counts as no carrier. Driver-specific counters need `ethtool -S` by hand."""
    base = os.path.join(sysfs, iface)
    carrier = _read(os.path.join(base, "carrier"))
    out: Dict[str, Any] = {
        "carrier": (carrier == "1") if carrier in ("0", "1") else (False if os.path.isdir(base) else None),
        "carrier_changes": _int(_read(os.path.join(base, "carrier_changes")))}
    for c in NIC_COUNTERS:
        out[c] = _int(_read(os.path.join(base, "statistics", c)))
    return out


def archive_status(pcap_dir: str, now: Optional[float] = None,
                   pattern: str = "cap-*.pcap") -> Dict[str, Any]:
    """The newest capture file: name, seconds since it was last written, size. tcpdump -U
    writes every packet as it arrives, so with packets arriving the age stays near 0.
    Files may be deleted by pruning while this function runs; survivors are returned."""
    files = glob.glob(os.path.join(pcap_dir, pattern))
    if not files:
        return {"archive_file": None, "archive_age_s": None, "archive_bytes": None}
    candidates = []
    for f in files:
        try:
            st = os.stat(f)
            candidates.append((st.st_mtime, f, st.st_size))
        except OSError:
            continue
    if not candidates:
        return {"archive_file": None, "archive_age_s": None, "archive_bytes": None}
    mtime, newest, size = max(candidates)
    now = time.time() if now is None else now
    return {"archive_file": os.path.basename(newest), "archive_age_s": round(now - mtime, 1),
            "archive_bytes": size}
