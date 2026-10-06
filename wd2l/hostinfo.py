"""Facts about this host and process for audit and health records: who runs us or signals us,
which build, chrony's view of the clock, and CPU and memory. Anything that can't be read comes
back as None or "unavailable"; nothing here raises, except parse_chronyc_tracking, which raises
ValueError for TimeQuality to catch."""

from __future__ import annotations

import hashlib
import os
import pwd
import resource
import socket
import subprocess
import time
from typing import Any, Callable, Dict, Optional, Sequence

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


class TimeQuality:
    """chrony's view of this host's clock, read at most every `every` seconds."""

    def __init__(self, cmd: Sequence[str] = ("chronyc", "-c", "tracking"), every: float = 60.0,
                 timeout: float = 2.0, max_stratum: int = 3, max_offset_ms: float = 100.0,
                 clock: Callable[[], float] = time.monotonic):
        self.cmd = list(cmd)
        self.every = every
        self.timeout = timeout
        self.max_stratum = max_stratum
        self.max_offset_ms = max_offset_ms
        self.clock = clock
        self._at: Optional[float] = None
        self._last: Dict[str, Any] = {}

    def read(self) -> Dict[str, Any]:
        now = self.clock()
        if self._at is None or now - self._at >= self.every:
            self._at = now
            try:
                out = subprocess.run(self.cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     timeout=self.timeout, check=True).stdout
                self._last = parse_chronyc_tracking(out.decode("utf-8", "replace"))
            except (OSError, subprocess.SubprocessError, ValueError) as e:
                self._last = {"synced": None, "source": "unavailable", "error": str(e)[:200]}
        return dict(self._last)

    def alarm(self, q: Optional[Dict[str, Any]] = None) -> Optional[str]:
        return time_alarm(self.read() if q is None else q, self.max_stratum, self.max_offset_ms)


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
