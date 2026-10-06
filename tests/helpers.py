import random

from wd2l import packets
from wd2l.outputs import Output

SRC_MAC = "02:00:00:00:00:01"
DST_MAC = "02:00:00:00:00:02"
SRC_IP = "10.255.255.1"
DST_IP = "10.255.255.2"
PORT = 5514


def eth(datagram: bytes, ident: int = 0) -> bytes:
    return packets.build_udp_frame(SRC_MAC, DST_MAC, SRC_IP, DST_IP, 40000, PORT, datagram, ident)


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
        w = packets.PcapWriter(f)
        for i, d in enumerate(datagrams):
            w.write(t0 + i * 0.0005, eth(d, i))
