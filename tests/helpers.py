import random
import re
import socket
import struct

from wd2l import packets
from wd2l.outputs import Output

SRC_MAC = "02:00:00:00:00:01"
DST_MAC = "02:00:00:00:00:02"
SRC_IP = "10.255.255.1"
DST_IP = "10.255.255.2"
PORT = 5514


def ip_checksum(header: bytes) -> int:
    s = sum(struct.unpack("!%dH" % (len(header) // 2), header))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def mac_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))


def build_udp_frame(src_mac: str, dst_mac: str, src_ip: str, dst_ip: str,
                    sport: int, dport: int, payload: bytes, ident: int = 0) -> bytes:
    """An Ethernet/IPv4/UDP frame (UDP checksum 0), as the tap would deliver one."""
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), ident & 0xFFFF, 0x4000, 64,
                     packets.IPPROTO_UDP, 0, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip = ip[:10] + struct.pack("!H", ip_checksum(ip)) + ip[12:]
    return mac_bytes(dst_mac) + mac_bytes(src_mac) + struct.pack("!H", packets.ETH_P_IP) + ip + udp


class PcapWriter:
    """A classic libpcap file, as tcpdump -w writes one, for packets.read_pcap to read."""

    def __init__(self, f, snaplen: int = 65535):
        self.f = f
        f.write(struct.pack("<IHHiIII", packets.PCAP_MAGIC_US, 2, 4, 0, 0, snaplen,
                            packets.LINKTYPE_ETHERNET))

    def write(self, ts: float, frame: bytes) -> None:
        sec = int(ts)
        usec = int(round((ts - sec) * 1e6))
        if usec >= 1000000:
            sec, usec = sec + 1, usec - 1000000
        self.f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame)


def eth(datagram: bytes, ident: int = 0) -> bytes:
    return build_udp_frame(SRC_MAC, DST_MAC, SRC_IP, DST_IP, 40000, PORT, datagram, ident)


TIME_FIELDS = ("wd2l_tx_time", "wd2l_rx_time")


def strip_times(evt):
    """Copy of an event without the send/receive time stamps, for exact-content comparisons."""
    out = dict(evt)
    fields = {k: v for k, v in out.pop("fields", {}).items() if k not in TIME_FIELDS}
    if fields:
        out["fields"] = fields
    return out


class FakeSock:
    def __init__(self):
        self.sent = []

    def sendto(self, data, addr):
        self.sent.append(bytes(data))


class MemOutput(Output):
    def __init__(self):
        self.events = []
        self.records = []
        self.audits = []
        self.forwarded_records = []

    def event(self, evt, stream_id, seq):
        self.events.append((stream_id, seq, evt))

    def health(self, rec):
        self.records.append(rec)

    def audit(self, rec):
        self.audits.append(rec)

    def forwarded(self, evt, stream_id, seq, kind):
        self.forwarded_records.append((kind, stream_id, seq, evt))

    def kinds(self, kind):
        return [r for r in self.records if r["type"] == kind]

    def seqs(self):
        return [s for _, s, _ in self.events]


def make_events(n: int, seed: int = 1):
    """Mixed bag: short syslog, multi-KB Windows XML, unicode, embedded newlines."""
    rnd = random.Random(seed)
    out = []
    for i in range(n):
        kind = i % 4
        if kind == 0:
            raw = "<134>Sep 25 12:00:%02d fw01 %%ASA-6-302013: Built connection %d" % (i % 60, i)
            st, host = "cisco:asa", "fw01"
        elif kind == 1:
            body = "".join(rnd.choice("abcdefghij<>/ =\"") for _ in range(rnd.randint(2000, 9000)))
            raw = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>%s</Event>" % body
            st, host = "XmlWinEventLog:Security", "ws%02d" % (i % 3)
        elif kind == 2:
            raw = "vmkernel: cpu%d: héllo wörld ✓ 日本 %d" % (i % 8, i)
            st, host = "vmw-syslog", "esx%02d" % (i % 3 + 1)
        else:
            raw = "Traceback (most recent call last):\n  File \"x.py\", line %d\n\tValueError: bad" % i
            st, host = "linux:app", "srv01"
        out.append({"_time": 1727265600 + i * 0.001, "host": host, "source": "src%d" % kind,
                    "sourcetype": st, "index": "main", "_raw": raw})
    return out


class SlowOutput(MemOutput):
    """Like a SIEM output: events wait in memory until commit(), and can be dropped with fail()."""

    def __init__(self):
        super().__init__()
        self.waiting = []
        self.failed = []

    def event(self, evt, stream_id, seq):
        super().event(evt, stream_id, seq)
        self.waiting.append((stream_id, seq))

    def commit(self):
        self.waiting = []

    def fail(self, stream_id, seq):
        self.waiting.remove((stream_id, seq))
        self.failed.append((stream_id, seq))

    def pending(self):
        out = {}
        for sid, seq in self.waiting:
            out.setdefault(sid, set()).add(seq)
        return out

    def take_failed(self):
        f, self.failed = self.failed, []
        return f


def read_audit(directory):
    """Every audit record on disk in this directory, oldest first (torn lines skipped)."""
    import json as _json
    from wd2l import audit as _audit
    out = []
    for path in _audit.audit_files(str(directory)):
        with open(path, "rb") as f:
            for line in _audit.split_lines(f.read()):
                if line.endswith(b"\n"):
                    out.append(_json.loads(line))
    return out


def write_pcap(path, datagrams, t0=1000.0):
    with open(path, "wb") as f:
        w = PcapWriter(f)
        for i, d in enumerate(datagrams):
            w.write(t0 + i * 0.0005, eth(d, i))


def load_script(relpath):
    """Load a script under packaging/ by its path. packaging/ has no __init__.py on purpose:
    a regular package called `packaging` would shadow the library pytest and pip import."""
    import importlib.util
    import os
    import sys
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    path = os.path.join(root, relpath)
    name = "wd2l_script_" + relpath.replace("/", "_").replace(".", "_").replace("-", "_")
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


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


def audit_watch(kind, path, key):
    """A watch as auditd syscall rules, for 64- and 32-bit syscalls (what `-w path -p wa` covered)."""
    return ["-a always,exit -F arch=%s -F %s=%s -F perm=wa -k %s" % (a, kind, path, key)
            for a in ("b64", "b32")]


def assert_rules_load_silently(rules):
    # augenrules warns "Old style watch rules are slower" for each -w, and "perm used without an
    # arch is slower" for each perm= rule with no arch=: 28 lines at every install (#110).
    assert rules
    for r in rules:
        assert re.match(r"-a always,exit -F arch=b(64|32) ", r) and " -F perm=wa" in r, r
        assert re.search(r" -k wd2l-[a-z-]+$", r), r
    b64 = [r for r in rules if "arch=b64" in r]
    assert sorted(r.replace("arch=b64", "arch=b32") for r in b64) == sorted(set(rules) - set(b64))
