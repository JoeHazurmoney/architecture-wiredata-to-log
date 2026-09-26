"""Enclave 1 sidecar: take events from the log aggregator (JSON lines over TCP), send them one way as WD2L UDP frames.

    log aggregator --JSON lines (127.0.0.1:10070)--> wd2l-sender --UDP--> black-hole IP

Every event gets the next sequence number. A heartbeat goes out every second with the last
sequence number and counters, so the receiver can tell "quiet" from "broken".
"""

from __future__ import annotations

import argparse
import errno
import json
import logging
import os
import signal
import socket
import socketserver
import threading
import time
from typing import Any, Dict, Optional, Sequence, Tuple

from . import wire

log = logging.getLogger("wd2l.sender")

IP_MTU_DISCOVER = getattr(socket, "IP_MTU_DISCOVER", 10)
IP_PMTUDISC_DO = getattr(socket, "IP_PMTUDISC_DO", 2)
MAX_LINE = 16 * 1024 * 1024


class Sender:
    def __init__(self, dst: Tuple[str, int], bind_ip: Optional[str] = None,
                 max_datagram: int = wire.DEFAULT_MAX_DATAGRAM,
                 max_event: int = wire.DEFAULT_MAX_EVENT,
                 rate_pps: float = 20000.0, extra_fields: Sequence[str] = (),
                 sock: Optional[socket.socket] = None):
        if max_event < 1024:
            raise ValueError("max_event must be at least 1024")
        self.dst = dst
        self.max_datagram = max_datagram
        self.max_event = max_event
        self.extra_fields = tuple(extra_fields)
        self.stream_id = int.from_bytes(os.urandom(8), "big") or 1
        self.seq = 0
        self.started = time.time()
        self.counters = {"events_sent": 0, "datagrams_sent": 0, "sender_drops": 0,
                         "truncated": 0, "bad_input": 0}
        self.lock = threading.Lock()
        self.rate = float(rate_pps)
        self.tokens = max(1.0, self.rate / 10)
        self.last_refill = time.monotonic()
        if sock is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
            if bind_ip:
                sock.bind((bind_ip, 0))
        self.sock = sock

    # -- sending

    def _pace(self) -> None:
        if self.rate <= 0:
            return
        now = time.monotonic()
        self.tokens = min(max(1.0, self.rate / 10), self.tokens + (now - self.last_refill) * self.rate)
        self.last_refill = now
        if self.tokens < 1:
            time.sleep((1 - self.tokens) / self.rate)
            self.tokens = 1.0
            self.last_refill = time.monotonic()
        self.tokens -= 1

    def _transmit(self, datagram: bytes) -> bool:
        self._pace()
        for _ in range(100):
            try:
                self.sock.sendto(datagram, self.dst)
                self.counters["datagrams_sent"] += 1
                return True
            except OSError as e:
                if e.errno not in (errno.ENOBUFS, errno.EAGAIN, errno.EWOULDBLOCK):
                    log.error("send failed: %s", e)
                    break
                time.sleep(0.001)
        self.counters["sender_drops"] += 1
        return False

    def _fit(self, event: Dict[str, Any]) -> bytes:
        """Serialize; if too big, cut _raw down to fit and flag it (like a SIEM's line-length limit)."""
        data = wire.serialize_event(event, self.extra_fields)
        if len(data) <= self.max_event:
            return data
        raw = event.get("_raw")
        if not isinstance(raw, str):
            raw = json.loads(data)["_raw"]
        raw_bytes = raw.encode("utf-8")
        trimmed = dict(event, _raw=raw)
        fields = self.extra_fields + ("wd2l_truncated",)
        trimmed["wd2l_truncated"] = len(raw_bytes)
        keep = len(raw_bytes)
        while len(data) > self.max_event:
            if keep <= 0:
                # Metadata alone is too big: keep only time and the truncation marker.
                trimmed = {"_raw": "", "_time": event.get("_time"),
                           "wd2l_truncated": len(raw_bytes)}
                data = wire.serialize_event(trimmed, ("wd2l_truncated",))
                break
            keep -= max(1, len(data) - self.max_event)
            trimmed["_raw"] = raw_bytes[:max(0, keep)].decode("utf-8", "ignore")
            data = wire.serialize_event(trimmed, fields)
        self.counters["truncated"] += 1
        log.warning("truncated event host=%s source=%s from %d bytes",
                    event.get("host"), event.get("source"), len(raw_bytes))
        return data

    def send_event(self, event: Dict[str, Any]) -> int:
        """Send one event. Returns its sequence number."""
        data = self._fit(event)
        with self.lock:
            self.seq += 1
            for dg in wire.encode_event(self.stream_id, self.seq, data, self.max_datagram):
                self._transmit(dg)
            self.counters["events_sent"] += 1
            return self.seq

    def heartbeat_info(self, final: bool = False) -> Dict[str, Any]:
        info = dict(self.counters, sender_time=round(time.time(), 3),
                    uptime=round(time.time() - self.started, 1))
        if final:
            info["final"] = True
        return info

    def send_heartbeat(self, final: bool = False) -> None:
        with self.lock:
            self._transmit(wire.encode_heartbeat(self.stream_id, self.seq, self.heartbeat_info(final)))

    def count_bad_input(self) -> None:
        with self.lock:
            self.counters["bad_input"] += 1


# ---------------------------------------------------------------- log aggregator input (JSON lines over TCP)

def _is_header(obj: Dict[str, Any]) -> bool:
    if "authToken" in obj:
        return True
    return "fields" in obj and "_raw" not in obj and "_time" not in obj


class CriblHandler(socketserver.StreamRequestHandler):
    """One log aggregator connection (e.g. Cribl Stream's TCP JSON destination): optional
    header line, then one JSON event per line."""

    def handle(self) -> None:
        srv: "InputServer" = self.server  # type: ignore[assignment]
        first = self.rfile.peek(2)[:2] if hasattr(self.rfile, "peek") else b""
        if first == b"\x1f\x8b":
            log.error("gzip data from %s: turn off compression on the log aggregator's "
                      "output", self.client_address)
            return
        defaults: Dict[str, Any] = {}
        first_line = True
        while True:
            line = self.rfile.readline(MAX_LINE)
            if not line:
                return
            if not line.endswith(b"\n") and len(line) >= MAX_LINE:
                while True:  # discard the rest of an absurdly long line
                    more = self.rfile.readline(MAX_LINE)
                    if not more or more.endswith(b"\n"):
                        break
                srv.sender.count_bad_input()
                log.warning("dropped input line over %d bytes", MAX_LINE)
                first_line = False
                continue
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                srv.sender.count_bad_input()
                first_line = False
                continue
            if not isinstance(obj, dict):
                srv.sender.count_bad_input()
                first_line = False
                continue
            if first_line and _is_header(obj):
                first_line = False
                if srv.auth_token is not None and obj.get("authToken") != srv.auth_token:
                    log.error("bad auth token from %s", self.client_address)
                    return
                if isinstance(obj.get("fields"), dict):
                    defaults = obj["fields"]
                continue
            if first_line and srv.auth_token is not None:
                log.error("no auth header from %s", self.client_address)
                return
            first_line = False
            for k, v in defaults.items():
                obj.setdefault(k, v)
            srv.sender.send_event(obj)


class InputServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr: Tuple[str, int], sender: Sender, auth_token: Optional[str] = None):
        self.sender = sender
        self.auth_token = auth_token
        super().__init__(addr, CriblHandler)


def _heartbeat_loop(sender: Sender, interval: float, stop: threading.Event,
                    stats_every: float) -> None:
    next_stats = time.monotonic() + stats_every
    while not stop.wait(interval):
        sender.send_heartbeat()
        if time.monotonic() >= next_stats:
            next_stats += stats_every
            log.info("stream=%016x last_seq=%d %s", sender.stream_id, sender.seq,
                     json.dumps(sender.counters, sort_keys=True))


def _hostport(s: str) -> Tuple[str, int]:
    host, _, port = s.rpartition(":")
    return host, int(port)


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="wd2l-sender", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--listen", default="127.0.0.1:10070", help="TCP JSON listen address")
    p.add_argument("--dst", default="10.255.255.2:5514", help="black-hole IP:port")
    p.add_argument("--bind", help="source IP (the egress NIC's address)")
    p.add_argument("--max-datagram", type=int, default=wire.DEFAULT_MAX_DATAGRAM,
                   help="UDP payload bytes per packet (1472 for 1500 MTU, 8972 for 9000)")
    p.add_argument("--max-event", type=int, default=wire.DEFAULT_MAX_EVENT,
                   help="events bigger than this are truncated and flagged")
    p.add_argument("--rate-pps", type=float, default=20000, help="packet rate cap, 0 = none")
    p.add_argument("--heartbeat", type=float, default=1.0, help="seconds between heartbeats")
    p.add_argument("--stats-interval", type=float, default=60, help="seconds between stats logs")
    p.add_argument("--auth-token-file", help="file holding the token the log aggregator sends in its header")
    p.add_argument("--extra-field", action="append", default=[],
                   help="extra event field to carry as an indexed field in the SIEM (repeatable)")
    p.add_argument("-v", "--verbose", action="store_true")
    a = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")

    token = None
    if a.auth_token_file:
        with open(a.auth_token_file) as f:
            token = f.read().strip()
    sender = Sender(_hostport(a.dst), a.bind, a.max_datagram, a.max_event, a.rate_pps,
                    a.extra_field)
    server = InputServer(_hostport(a.listen), sender, token)
    stop = threading.Event()
    hb = threading.Thread(target=_heartbeat_loop,
                          args=(sender, a.heartbeat, stop, a.stats_interval), daemon=True)
    hb.start()

    def _shutdown(signum, _frame):
        log.info("signal %d, shutting down", signum)
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)
    log.info("stream %016x: listening on %s, sending to %s", sender.stream_id, a.listen, a.dst)
    server.serve_forever()
    stop.set()
    hb.join()
    sender.send_heartbeat(final=True)
    log.info("final: last_seq=%d %s", sender.seq, json.dumps(sender.counters, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
