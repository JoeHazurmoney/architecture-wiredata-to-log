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


class FakeSock:
    def __init__(self):
        self.sent = []

    def sendto(self, data, addr):
        self.sent.append(bytes(data))


class MemOutput(Output):
    def __init__(self):
        self.events = []
        self.records = []

    def event(self, evt, stream_id, seq):
        self.events.append((stream_id, seq, evt))

    def health(self, rec):
        self.records.append(rec)

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
