"""Operational logs and signals.

Operational logs go to stderr (journald) as text, or with --log-format json as one JSON object
per line, tagged with the segment it is about (docs/audit-and-health.md §2, §6). The message
texts are the same either way, so runbook checks such as `final: last_seq=` still match.

SIGUSR1 switches between INFO and DEBUG without a restart. It is an audit event
(debug_toggled) that names who sent the signal, which only sigwaitinfo() can tell."""

from __future__ import annotations

import json
import logging
import signal
import threading
from typing import Any, Callable, Dict, Optional

from . import hostinfo
from .audit import utc_ts

log = logging.getLogger("wd2l")

SEGMENT_BY_LOGGER = (("wd2l.sender.input", "e1-input"), ("wd2l.sender", "e1-sender"),
                     ("wd2l.receiver", "e2-receiver"), ("wd2l.outputs", "e2-siem"))
TEXT_FORMAT = "%(asctime)s %(name)s %(levelname)s %(message)s"


def segment_for(logger_name: str) -> Optional[str]:
    for prefix, seg in SEGMENT_BY_LOGGER:
        if logger_name == prefix or logger_name.startswith(prefix + "."):
            return seg
    return None


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out: Dict[str, Any] = {"ts": utc_ts(record.created), "level": record.levelname,
                               "logger": record.name, "msg": record.getMessage()}
        seg = getattr(record, "segment", None) or segment_for(record.name)
        if seg:
            out["segment"] = seg
        for k in ("stream", "seq"):
            v = getattr(record, k, None)
            if v is not None:
                out[k] = v
        if record.exc_info:
            out["exc"] = self.formatException(record.exc_info)
        return json.dumps(out, ensure_ascii=False, sort_keys=True)


def setup(fmt: str = "text", verbose: bool = False) -> None:
    """Like logging.basicConfig (a no-op if logging is already set up, e.g. under pytest)."""
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter() if fmt == "json" else logging.Formatter(TEXT_FORMAT))
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, handlers=[handler])


def toggle_debug() -> str:
    root = logging.getLogger()
    new = logging.INFO if root.level <= logging.DEBUG else logging.DEBUG
    root.setLevel(new)
    return logging.getLevelName(new)


class SignalWatcher:
    """Handles signals in a thread of its own with sigwaitinfo(), which says who sent each one
    (si_pid, si_uid). Call start() before any other thread starts: threads inherit the blocked
    signal mask, so only this thread receives these signals."""

    def __init__(self, handlers: Dict[int, Callable[[int, int, int], None]]):
        self.handlers = dict(handlers)

    def start(self) -> None:
        sigs = set(self.handlers)
        signal.pthread_sigmask(signal.SIG_BLOCK, sigs)
        threading.Thread(target=self._run, args=(sigs,), name="signals", daemon=True).start()

    def _run(self, sigs: set) -> None:
        while True:
            info = signal.sigwaitinfo(sigs)
            try:
                self.handlers[info.si_signo](info.si_signo, info.si_pid, info.si_uid)
            except Exception:
                log.exception("handling signal %d failed", info.si_signo)


def debug_toggle_handler(audit: Any = None) -> Callable[[int, int, int], None]:
    """SIGUSR1: switch INFO <-> DEBUG and record who asked (debug_toggled)."""
    def handle(_sig: int, pid: int, uid: int) -> None:
        level = toggle_debug()
        who = hostinfo.signal_actor(pid, uid)
        log.warning("SIGUSR1 from %s: log level now %s", who, level)
        if audit is not None:
            audit.write("debug_toggled", "info", actor=who, level=level)
    return handle
