"""Enclave 1 sidecar: take events from the log aggregator (JSON lines over TCP), send them one way as WD2L UDP frames.

    log aggregator --JSON lines (127.0.0.1:10070)--> wd2l-sender --UDP--> black-hole IP

Every event gets the next sequence number. A heartbeat goes out every second with the last
sequence number and counters, so the receiver can tell "quiet" from "broken".

With --state, the sender also counts its own restarts and tells the receiver which stream came
before this one and how far it got, so the receiver can spot a lost tail or a whole missed run.
"""

from __future__ import annotations

import argparse
import errno
import fcntl
import json
import logging
import os
import select
import signal
import socket
import socketserver
import struct
import termios
import threading
import time
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from . import wire

log = logging.getLogger("wd2l.sender")

IP_MTU_DISCOVER = getattr(socket, "IP_MTU_DISCOVER", 10)
IP_PMTUDISC_DO = getattr(socket, "IP_PMTUDISC_DO", 2)
SRC_SEQ_FIELD = "wd2l_src_seq"
MAX_LINE = 16 * 1024 * 1024
ERROR_LOG_EVERY = 10.0


class Sender:
    def __init__(self, dst: Tuple[str, int], bind_ip: Optional[str] = None,
                 max_datagram: int = wire.DEFAULT_MAX_DATAGRAM,
                 max_event: int = wire.DEFAULT_MAX_EVENT,
                 rate_pps: float = 20000.0, extra_fields: Sequence[str] = (),
                 sock: Optional[socket.socket] = None, state_path: Optional[str] = None,
                 source_seq: bool = False):
        if max_event < 1024:
            raise ValueError("max_event must be at least 1024")
        self.dst = dst
        self.max_datagram = max_datagram
        self.max_event = max_event
        self.extra_fields = tuple(extra_fields)
        # Optional per-file line counter (indexed field wd2l_src_seq): numbers events 1, 2, 3...
        # separately for each (host, source), so Enclave 2 can rebuild several interleaved files
        # and name the exact lines a gap took from each one.
        self.source_seq = source_seq
        self.src_counters: Dict[Tuple[Any, Any], int] = {}
        if source_seq and SRC_SEQ_FIELD not in self.extra_fields:
            self.extra_fields += (SRC_SEQ_FIELD,)
        self.stream_id = int.from_bytes(os.urandom(8), "big") or 1
        self.seq = 0
        self.started = time.time()
        self.counters = {"events_sent": 0, "datagrams_sent": 0, "sender_drops": 0,
                         "truncated": 0, "bad_input": 0, "send_errors": 0,
                         "shutdown_unread_bytes": 0}
        self.lock = threading.Lock()
        self.closed = False
        self.rate = float(rate_pps)
        self.tokens = max(1.0, self.rate / 10)
        self.last_refill = time.monotonic()
        self._err_log: Dict[int, List[float]] = {}  # errno -> [last logged, suppressed since]
        self.state_path = state_path
        self.link: Dict[str, int] = {}
        if state_path:
            self._start_state()
        if sock is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
            if bind_ip:
                sock.bind((bind_ip, 0))
        self.sock = sock

    # -- restart chain

    def _start_state(self) -> None:
        """Read the previous run's record, then claim the next boot number for this run."""
        prev: Dict[str, Any] = {}
        try:
            with open(self.state_path) as f:  # type: ignore[arg-type]
                prev = json.load(f)
        except FileNotFoundError:
            pass
        except (OSError, ValueError) as e:
            # Starting over at boot 1 is visible on the receiver as sender_boot_reset.
            log.error("sender state %s unreadable (%s): restart count starts over", self.state_path, e)
        boot = prev.get("boot")
        self.link = {"boot": boot + 1 if isinstance(boot, int) and boot >= 1 else 1}
        stream = prev.get("stream")
        last_seq = prev.get("last_seq")
        if isinstance(stream, str) and isinstance(last_seq, int):
            try:
                self.link.update(prev_stream=int(stream, 16), prev_last_seq=last_seq)
            except ValueError:
                pass
        self._save_state()
        log.info("boot %d%s", self.link["boot"],
                 " after stream %016x (last seq %d)" % (self.link["prev_stream"], self.link["prev_last_seq"])
                 if "prev_stream" in self.link else "")

    def _save_state(self) -> None:
        """Record this run's stream and progress. Called with the lock held (or at start)."""
        if not self.state_path:
            return
        body = json.dumps({"boot": self.link["boot"], "stream": "%016x" % self.stream_id,
                           "last_seq": self.seq})
        tmp = self.state_path + ".tmp"
        try:
            with open(tmp, "w") as f:
                f.write(body)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.state_path)
        except OSError as e:
            self._log_error(e.errno or -1, "sender state write failed: %s" % e)

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

    def _log_error(self, code: int, msg: str) -> None:
        """Log an error at most once per ERROR_LOG_EVERY seconds per errno (sends can fail
        thousands of times a second when the egress link is down)."""
        now = time.monotonic()
        last, suppressed = self._err_log.get(code, [-1e9, 0])
        if now - last >= ERROR_LOG_EVERY:
            log.error("%s%s", msg, " (%d more like this since the last message)" % suppressed
                      if suppressed else "")
            self._err_log[code] = [now, 0]
        else:
            self._err_log[code] = [last, suppressed + 1]

    def _transmit(self, datagram: bytes) -> bool:
        self._pace()
        for _ in range(100):
            try:
                self.sock.sendto(datagram, self.dst)
                self.counters["datagrams_sent"] += 1
                return True
            except OSError as e:
                if e.errno not in (errno.ENOBUFS, errno.EAGAIN, errno.EWOULDBLOCK):
                    self.counters["send_errors"] += 1
                    self._log_error(e.errno or -1, "send failed: %s" % e)
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
        """Send one event. Returns its sequence number (0 if the sender has already closed)."""
        if not self.source_seq:
            data = self._fit(event)
        with self.lock:
            if self.closed:
                return 0
            if self.source_seq:
                # Numbered under the lock, together with seq, so both orders agree.
                key = (event.get("host"), event.get("source"))
                n = self.src_counters.get(key, 0) + 1
                self.src_counters[key] = n
                data = self._fit(dict(event, **{SRC_SEQ_FIELD: n}))
            self.seq += 1
            for dg in wire.encode_event(self.stream_id, self.seq, data, self.max_datagram):
                self._transmit(dg)
            self.counters["events_sent"] += 1
            return self.seq

    def heartbeat_info(self, final: bool = False) -> Dict[str, Any]:
        info = dict(self.counters, sender_time=round(time.time(), 3),
                    uptime=round(time.time() - self.started, 1), **self.link)
        if final:
            info["final"] = True
        return info

    def send_heartbeat(self, final: bool = False) -> None:
        with self.lock:
            if self.closed:
                return
            self._transmit(wire.encode_heartbeat(self.stream_id, self.seq, self.heartbeat_info(final)))
            self._save_state()
            if final:
                self.closed = True

    def count_bad_input(self) -> None:
        with self.lock:
            self.counters["bad_input"] += 1

    def count_unread(self, nbytes: int) -> None:
        with self.lock:
            self.counters["shutdown_unread_bytes"] += nbytes


# ---------------------------------------------------------------- log aggregator input (JSON lines over TCP)

def _is_header(obj: Dict[str, Any]) -> bool:
    """The optional first line: {"authToken": ..., "fields": {...}}. A line without authToken
    only counts as a header if "fields" is its only key, so a real event is never swallowed."""
    return "authToken" in obj or set(obj) == {"fields"}


def _unread_bytes(sock: socket.socket) -> int:
    """Bytes the kernel has received (and acknowledged) that nobody has read yet."""
    try:
        buf = fcntl.ioctl(sock.fileno(), termios.FIONREAD, b"\0\0\0\0")
        return struct.unpack("i", buf)[0]
    except OSError:
        return 0


class CriblHandler(socketserver.BaseRequestHandler):
    """One log aggregator connection (e.g. Cribl Stream's TCP JSON destination): optional
    header line, then one JSON event per line.

    Reads with select() rather than a blocking readline so it can react to shutdown: once the
    server is stopping it keeps reading whatever is already arriving (the aggregator thinks
    those bytes are delivered), and stops when the connection goes quiet or the drain time runs
    out. Whatever is left unread then is counted in shutdown_unread_bytes."""

    def handle(self) -> None:
        srv: "InputServer" = self.server  # type: ignore[assignment]
        try:
            self._run(srv, self.request)
        finally:
            with srv.handlers_lock:
                srv.handlers.discard(threading.current_thread())

    def _run(self, srv: "InputServer", sock: socket.socket) -> None:
        self.defaults: Dict[str, Any] = {}
        self.first_line = True
        buf = b""
        skipping = False
        started = False
        deadline: Optional[float] = None
        while True:
            if srv.stopping.is_set() and deadline is None:
                deadline = time.monotonic() + srv.drain_timeout
            if deadline is not None and time.monotonic() > deadline:
                break
            ready, _, _ = select.select([sock], [], [], 0.2)
            if not ready:
                if deadline is not None:
                    break  # quiet while stopping: everything sent to us has been read
                continue
            try:
                chunk = sock.recv(65536)
            except OSError:
                return
            if not chunk:
                if buf and not skipping:
                    self._line(srv, buf)
                return
            if not started:
                started = True
                if chunk[:2] == b"\x1f\x8b":
                    log.error("gzip data from %s: turn off compression on the log aggregator's "
                              "output", self.client_address)
                    return
            parts = (buf + chunk).split(b"\n")
            buf = parts.pop()
            if skipping and parts:
                parts.pop(0)  # the end of a line that was too long
                skipping = False
            for line in parts:
                if not self._line(srv, line):
                    return
            if len(buf) > MAX_LINE:
                srv.sender.count_bad_input()
                log.warning("dropped input line over %d bytes", MAX_LINE)
                buf = b""
                skipping = True
                self.first_line = False
        # Stopping: what is left was acknowledged to the aggregator but will not be sent.
        unread = len(buf) + _unread_bytes(sock)
        if unread:
            srv.sender.count_unread(unread)
            log.warning("shutdown: %d bytes from %s left unread", unread, self.client_address)

    def _line(self, srv: "InputServer", line: bytes) -> bool:
        """Handle one input line. Returns False to close the connection."""
        line = line.strip()
        if not line:
            return True
        try:
            obj = json.loads(line)
        except ValueError:
            srv.sender.count_bad_input()
            self.first_line = False
            return True
        if not isinstance(obj, dict):
            srv.sender.count_bad_input()
            self.first_line = False
            return True
        if self.first_line and _is_header(obj):
            self.first_line = False
            if srv.auth_token is not None and obj.get("authToken") != srv.auth_token:
                log.error("bad auth token from %s", self.client_address)
                return False
            if isinstance(obj.get("fields"), dict):
                self.defaults = obj["fields"]
            return True
        if self.first_line and srv.auth_token is not None:
            log.error("no auth header from %s", self.client_address)
            return False
        self.first_line = False
        for k, v in self.defaults.items():
            obj.setdefault(k, v)
        srv.sender.send_event(obj)
        return True


class InputServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr: Tuple[str, int], sender: Sender, auth_token: Optional[str] = None,
                 rcvbuf: int = 256 * 1024, drain_timeout: float = 2.0):
        self.sender = sender
        self.auth_token = auth_token
        self.rcvbuf = rcvbuf
        self.drain_timeout = drain_timeout
        self.stopping = threading.Event()
        self.handlers: Set[threading.Thread] = set()
        self.handlers_lock = threading.Lock()
        super().__init__(addr, CriblHandler)

    def server_bind(self) -> None:
        # A small receive buffer (inherited by accepted connections) bounds how much data the
        # kernel acknowledges to the aggregator ahead of the sender actually reading it.
        if self.rcvbuf:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.rcvbuf)
        super().server_bind()

    def process_request(self, request, client_address) -> None:
        t = threading.Thread(target=self.process_request_thread,
                             args=(request, client_address), daemon=True)
        with self.handlers_lock:
            self.handlers.add(t)
        t.start()

    def drain(self) -> None:
        """Call after serve_forever() returns. Stops input without dropping data the kernel has
        already acknowledged: connections still waiting in the accept queue are taken on too,
        the listener is closed, and every connection gets to finish what is already arriving."""
        self.stopping.set()
        self.socket.setblocking(False)
        while True:
            try:
                request, addr = self.socket.accept()
            except OSError:
                break
            request.setblocking(True)
            self.process_request(request, addr)
        self.server_close()
        with self.handlers_lock:
            threads = list(self.handlers)
        for t in threads:
            t.join(self.drain_timeout + 1.0)


def _heartbeat_loop(sender: Sender, interval: float, stop: threading.Event,
                    stats_every: float) -> None:
    next_stats = time.monotonic() + stats_every
    while not stop.wait(interval):
        sender.send_heartbeat()
        if time.monotonic() >= next_stats:
            next_stats += stats_every
            with sender.lock:
                counters = json.dumps(sender.counters, sort_keys=True)
            log.info("stream=%016x last_seq=%d %s", sender.stream_id, sender.seq, counters)


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
    p.add_argument("--source-seq", action="store_true",
                   help="number events per (host, source) in indexed field wd2l_src_seq, so "
                        "Enclave 2 can rebuild interleaved files and locate lost lines")
    p.add_argument("--state", help="state file for the restart count and previous stream "
                                   "(lets the receiver link runs together)")
    p.add_argument("--drain-timeout", type=float, default=2.0,
                   help="seconds to keep reading already-arriving input on shutdown")
    p.add_argument("--input-rcvbuf", type=int, default=256 * 1024,
                   help="TCP receive buffer for aggregator connections (0 = system default)")
    p.add_argument("-v", "--verbose", action="store_true")
    a = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")

    token = None
    if a.auth_token_file:
        with open(a.auth_token_file) as f:
            token = f.read().strip()
    sender = Sender(_hostport(a.dst), a.bind, a.max_datagram, a.max_event, a.rate_pps,
                    a.extra_field, state_path=a.state, source_seq=a.source_seq)
    server = InputServer(_hostport(a.listen), sender, token, a.input_rcvbuf, a.drain_timeout)
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
    # Order matters: stop accepting, finish reading what is in flight, and only then send the
    # final heartbeat, so its sequence number really is the last one.
    server.drain()
    stop.set()
    hb.join()
    sender.send_heartbeat(final=True)
    log.info("final: last_seq=%d %s", sender.seq, json.dumps(sender.counters, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
