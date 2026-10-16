"""Every field the SIEM's saved searches and dashboard read from wd2l's health records is one
the code emits (#143). Renaming or dropping a key (invariant 7 only ever adds them) would
otherwise leave a panel or an alert empty with CI green.

The records are built as a deployment builds them: the receiver with its NIC, archive, audit
and time probes, faults on, and a SIEM output next to the file one; the sender with its input
server, egress NIC and audit trail. The fields are read from each search by its commands
(table, aggregates, functions, comparisons, by), less what the search names itself."""
import json
import os
import re

import pytest

from wd2l import audit as auditlog
from wd2l import hostinfo, receiver, wire
from wd2l.outputs import HecOutput, MultiOutput
from wd2l.receiver import Receiver
from wd2l.sender import InputServer, Sender

from helpers import FakeSock, MemOutput, eth

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SPLUNK = os.path.join(REPO, "deploy", "receiver", "splunk")
SID, OTHER = 0x1111, 0x2222

# Fields Splunk sets or a search takes from its own arguments, never from a record.
SPLUNK_FIELDS = {"_time", "_indextime", "index", "sourcetype", "source", "earliest", "latest",
                 "span", "current", "column_name"}
FUNCTIONS = {"latest", "last", "range", "sum", "min", "max", "values", "median", "count",
             "coalesce", "upper", "round", "if", "eval", "strftime", "now", "null", "dc"}


# ---------------------------------------------------------------- what the SIEM reads

def saved_searches():
    with open(os.path.join(SPLUNK, "savedsearches.conf")) as f:
        text = re.sub(r"\\\n", " ", f.read())
    return {m.group(1): m.group(2) for m in
            re.finditer(r"^\[(.+?)\]\n(?:(?!\[).*\n)*?search = (.+)$", text, re.M)}


def dashboard_searches():
    """name -> the full query, a chained source's base first."""
    with open(os.path.join(SPLUNK, "wd2l-health-dashboard.json")) as f:
        sources = json.load(f)["dataSources"]

    def full(name):
        o = sources[name]["options"]
        return (full(o["extend"]) + " " if "extend" in o else "") + o["query"]
    return {name: full(name) for name in sources}


def kinds(spl):
    """(sourcetypes, record types) a search reads, from its first command; ([], []) for other
    indexes. No record type means any record of the sourcetype."""
    first = spl.split("|")[0]
    sts = re.findall(r"sourcetype=(wd2l:[\w:]+)", first)
    types = re.findall(r"\btype=(\w+)", first)
    for group in re.findall(r"\btype IN \(([^)]*)\)", first):
        types += [t.strip() for t in group.split(",")]
    return sts, types


def fields_read(spl):
    """The record fields one search uses: what each command reads, in pipeline order, less what
    an earlier command named itself (`as`, `eval x=`)."""
    spl = re.sub(r'"[^"]*"', '""', spl)                       # string values
    spl = re.sub(r"foreach \S+ \[[^\]]*\]", "", spl)            # field templates
    made, used = set(), set()

    def take(names):
        used.update(n for n in names if n not in made)
    for cmd in (c.strip() for c in spl.split("|")):
        word, _, rest = cmd.partition(" ")
        if word in ("", "tstats", "head", "sort", "transpose", "rename", "fields"):
            continue
        if word == "table":
            take(f for f in rest.split() if re.fullmatch(r"\w+", f))
        elif word in ("stats", "streamstats", "timechart"):
            # Function arguments are fields even when named like a function: sum(count).
            take(re.findall(r"\b(?:%s)\(\s*(?:eval\()?(\w+)" % "|".join(FUNCTIONS), rest))
            by = re.search(r"\bby\s+(.+)$", rest)
            if by:
                take(f.strip() for f in by.group(1).split(","))
            made.update(re.findall(r"\bas\s+(\w+)", rest))
        elif word == "eval":
            for assign in re.split(r",\s*(?=\w+=)", rest):
                lhs, _, rhs = assign.partition("=")
                take(n for n in re.findall(r"\b([a-z_]\w*)\b(?!\()", rhs) if n not in FUNCTIONS)
                made.add(lhs.strip())
        else:                                           # the first command, or where
            text = rest if word == "where" else cmd
            take(n for n in re.findall(r"\b([a-z_]\w*)\s*(?:!=|>=|<=|=|>|<)", text)
                 if n not in FUNCTIONS)
    return used - SPLUNK_FIELDS - {"type"}


def wanted():
    """search name -> (sourcetypes, record types, the fields it reads), wd2l's own indexes."""
    out = {}
    for name, spl in list(saved_searches().items()) + list(dashboard_searches().items()):
        sts, types = kinds(spl)
        if sts:
            out[name] = (sts, types, fields_read(spl))
    return out


# ---------------------------------------------------------------- what the code emits

class BadTime:
    def read(self):
        return {"stratum": 0, "offset_ms": 0.0, "synced": False, "source": ""}

    def alarm(self, q=None):
        return "unsynced"


def deployed_receiver(tmp_path, name, siem=False, **kw):
    """A receiver as receiver.env runs one: NIC, archive, audit and time probes, faults on, and
    with siem a SIEM output beside the file one (it never confirms delivery here, so a run's
    reconcile cut never settles: only for the health record). Records land in the MemOutput."""
    pcap = tmp_path / name / "pcap"
    pcap.mkdir(parents=True)
    (pcap / "cap-1.pcap").write_bytes(b"x")
    mem = MemOutput()
    out = MultiOutput([mem, HecOutput("http://127.0.0.1:9", "t", str(tmp_path / name / "spool"))]) \
        if siem else mem
    audit = auditlog.AuditLog(str(tmp_path / name / "audit"), "receiver", 2, host="rx",
                              actor="me", build="b")
    for k, v in dict(health_interval=1e9, gap_window=1, hb_timeout=2, stream_lost_after=5,
                     fault_interval=1, fault_window=10).items():
        kw.setdefault(k, v)
    r = Receiver(out, dst_ip="10.255.255.2", dst_port=5514, audit=audit,
                 time_quality=BadTime(), nic_probe=lambda: hostinfo.nic_stats("lo"),
                 archive_probe=lambda: hostinfo.archive_status(str(pcap)), **kw)
    return r, mem


def feed(r, dgs, now):
    for d in dgs:
        r.handle_frame(eth(d), now)


def link_hb(sid, boot, **link):
    return wire.encode_heartbeat(sid, 0, dict({"events_sent": 0, "boot": boot}, **link))


def receiver_records(tmp_path, monkeypatch):
    """The keys of every record type a receiver writes, by type, from four short lives."""
    recs = []
    # 1. A run with a loss that ends cleanly: gap, fault, time_status, reconcile, health; then
    #    the same with the SIEM output, for its counters in the health record.
    for siem in (False, True):
        r, mem = deployed_receiver(tmp_path, "loss-%s" % siem, siem=siem)
        s = Sender(("10.255.255.2", 5514), sock=FakeSock(), rate_pps=0)
        for i in range(5):
            s.send_event({"_raw": "e%d" % i, "host": "h"})
        s.send_heartbeat(final=True)
        feed(r, s.sock.sent[:2] + s.sock.sent[3:], 0)      # seq 3 lost
        for t in range(1, 5):
            r.tick(t)
        recs += mem.records + [r.emit_health(5)]
    # 2. A run that goes quiet without a clean stop: heartbeat_stale, stream_lost.
    r, mem = deployed_receiver(tmp_path, "quiet")
    feed(r, [link_hb(SID, 1)], 0)
    for t in (1, 3, 10):
        r.tick(t)
    recs += mem.records
    # 3. Runs that never arrived, and a boot counter that went back: stream_missing (one run,
    #    and a span of runs), sender_boot_reset.
    r, mem = deployed_receiver(tmp_path, "chain")
    feed(r, [link_hb(0x3333, 2)], 0)
    feed(r, [link_hb(0x4444, 4, prev_stream=0x5555, prev_last_seq=7)], 1)
    feed(r, [link_hb(0x6666, 9, prev_stream=0x7777, prev_last_seq=3)], 2)
    feed(r, [link_hb(0x8888, 1)], 3)
    r.tick(4)
    recs += mem.records
    # 4. Too many streams, the dropped one with gaps open: stream_evicted.
    monkeypatch.setattr(receiver, "MAX_STREAMS", 1)
    r, mem = deployed_receiver(tmp_path, "evict")
    feed(r, wire.encode_event(SID, 2, b'{"_raw":"x"}'), 0)
    r.tick(5)                                              # seq 1 declared a gap
    feed(r, wire.encode_event(OTHER, 1, b'{"_raw":"y"}'), 6)
    recs += mem.records
    # 5. A loss on the sender's records stream: its gap says records=true.
    r, mem = deployed_receiver(tmp_path, "records")
    rec = json.dumps({"_raw": json.dumps({"event": "start", "enclave": 1, "component": "sender"}),
                      "sourcetype": "wd2l:sender:audit"}).encode()
    feed(r, wire.encode_event(OTHER, 2, rec, flags=wire.FLAG_RECORDS), 0)
    r.tick(5)
    recs += mem.records
    by_type = {}
    for rec in recs:
        by_type.setdefault(rec["type"], set()).update(rec)
    return by_type


def sender_health(tmp_path):
    audit = auditlog.AuditLog(str(tmp_path / "audit-e1"), "sender", 1, host="logsrv01",
                              actor="me", build="b")
    s = Sender(("10.255.255.2", 5514), sock=FakeSock(), audit=audit, rate_pps=0,
               egress_iface="lo")
    s.input_server = InputServer(("127.0.0.1", 0), s)
    try:
        s.send_heartbeat()
        return set(s.health_record())
    finally:
        s.input_server.server_close()


def test_the_searches_read_what_this_test_thinks():
    """The extraction is a heuristic: pin a few searches, so it can't quietly find nothing."""
    w = {name: fields for name, (_, _, fields) in wanted().items()}
    assert w["WD2L - Fault segment"] == {"host", "fault_status", "fault_segment", "fault_rule",
                                         "fault_detail", "previous_status"}
    assert w["ds_d_receiver"] == {"heartbeat_age_s", "open_gap_events", "reasm_expired",
                                  "cpu_pct", "rss_mb"}
    assert {"seg_e1_input", "seg_e2_siem"} <= w["ds_segments"]
    assert "sender_unread_bytes" in w["WD2L - Unexpected traffic or damage on the tap"]
    assert {"stall_s", "sender_drops", "nic_tx_errors"} <= w["ds_d_sender"]
    assert w["WD2L - Events lost in transfer"] == {"host", "stream", "reason", "count",
                                                   "first_seq", "last_seq"}
    assert {"balanced", "cut", "gaps_open", "gaps_forgotten"} <= w["WD2L - Reconciliation not balanced"]
    assert "balanced_checks" not in w["WD2L - Reconciliation not balanced"]    # the search's own
    assert "WD2L - Receiver silent" not in w and "ds_delay" not in w           # no record fields


def test_every_field_the_siem_reads_is_emitted(tmp_path, monkeypatch):
    emitted = {("wd2l:health", t): keys for t, keys in receiver_records(tmp_path, monkeypatch).items()}
    emitted[("wd2l:sender:health", "health")] = sender_health(tmp_path)
    missing = {}
    for name, (sts, types, fields) in sorted(wanted().items()):
        for st in sts:
            have = set()
            for (s, t), keys in emitted.items():
                if s == st and (not types or t in types):
                    have |= keys
            for t in types:
                if st == "wd2l:health" or t == "health":
                    assert (st, t) in emitted, "no %s %s record was built for %r" % (st, t, name)
            if fields - have:
                missing[(name, st)] = sorted(fields - have)
    assert not missing, missing
