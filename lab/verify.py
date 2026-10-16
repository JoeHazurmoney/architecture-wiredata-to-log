#!/usr/bin/env python3
"""Compare what the lab sent with what Enclave 2 rebuilt.

Sequence number N is the Nth line of the events file (fake_cribl.py, the stand-in log
aggregator, sends in order over one connection). Every sent event must be either received
exactly once, byte-for-byte equal to what the sender put on the wire, or listed in a reported
gap. Nothing else may show up.

Each received event must also carry its send time (wd2l_tx_time, part of what the sender put on
the wire) and its arrival time (wd2l_rx_time, added in Enclave 2). The difference is reported as
the link delay.

With --sender-runs N the sender was stopped and started again in between (planned downtime).
Each run numbers its events from 1 again, so run k's events continue the file where run k-1
ended (the last_seq of its stream_end record). Every run but the last must have ended cleanly
with no input left unread, and nothing may be reported lost, missing or reset.
"""

import argparse
import json
import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from wd2l import audit as auditlog  # noqa: E402
from wd2l import wire  # noqa: E402
from wd2l.sender import Sender  # noqa: E402
from lab.gen_events import OPAQUE_AT  # noqa: E402

logging.getLogger("wd2l.sender").setLevel(logging.ERROR)


class _NoSock:
    def sendto(self, *_):
        pass


def load(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("sent")
    p.add_argument("received_dir")
    p.add_argument("--state", help="receiver state file: open gaps are read from here")
    p.add_argument("--max-event", type=int, default=wire.DEFAULT_MAX_EVENT)
    p.add_argument("--allow-other-packets", action="store_true",
                   help="foreign packets crossed the cable on purpose")
    p.add_argument("--expect-gaps", action="store_true", help="loss was injected on purpose")
    p.add_argument("--generated", type=int, metavar="N",
                   help="one sender run of gen_events.py's N events and its oversize one: those "
                        "must be exactly the events truncated and flagged opaque")
    p.add_argument("--allow-duplicates", action="store_true",
                   help="identical copies of an event are fine (after a receiver crash)")
    p.add_argument("--source-seq", action="store_true",
                   help="the sender ran with --source-seq (per-file line numbers)")
    p.add_argument("--extra-field", action="append", default=[],
                   help="extra field the sender was told to carry (same as wd2l-sender)")
    p.add_argument("--sender-runs", type=int, default=1,
                   help="the sender was stopped and started again: expect this many runs, "
                        "linked, with nothing lost in between")
    p.add_argument("--audit-dir", action="append", default=[],
                   help="an audit directory whose hash chain must verify (repeatable)")
    p.add_argument("--e1-audit-dir", help="Enclave 1's audit directory: the in-band copy in "
                   "<received>/audit.jsonl must match it")
    p.add_argument("--reconcile-dir", help="Enclave 2's audit directory: each data stream's last reconcile record must be balanced (with --expect-gaps: at least one must not be)")
    a = p.parse_args()
    if a.sender_runs > 1 and a.source_seq:
        p.error("--sender-runs can't be combined with --source-seq (line numbers restart "
                "with each sender run)")

    extra = list(a.extra_field) + (["wd2l_src_seq"] if a.source_seq else [])
    fitter = Sender(("127.0.0.1", 9), sock=_NoSock(), max_event=a.max_event, rate_pps=0,
                    extra_fields=extra)
    sent = load(a.sent)
    if a.source_seq:
        # The sender numbers events 1, 2, 3... per (host, source), in the order it gets them.
        counters = {}
        for e in sent:
            key = (e.get("host"), e.get("source"))
            counters[key] = counters.get(key, 0) + 1
            e["wd2l_src_seq"] = counters[key]
    sent_by_seq = {i + 1: e for i, e in enumerate(sent)}

    def expected(seq, tx):
        """What the sender put on the wire for this event, given the send time it stamped
        (the stamp counts toward the size limit, so it changes where big events are cut),
        including any opaque-content flag."""
        e = sent_by_seq[seq]
        return wire.parse_event(fitter._fit(dict(e, wd2l_tx_time=tx, **fitter.opaque_fields(e))))

    got = load(os.path.join(a.received_dir, "events.jsonl"))
    health = load(os.path.join(a.received_dir, "health.jsonl"))
    streams = {g["wd2l_stream"] for g in got}

    problems = []
    # Sender runs in the order Enclave 2 first saw them, and where each run's numbers start in
    # the sent file.
    runs = list(dict.fromkeys(h["stream"] for h in health
                              if h["type"] == "stream_start" and not h.get("records")))
    ends = {h["stream"]: h for h in health
            if h["type"] == "stream_end" and not h.get("records")}
    offset = {}
    if a.sender_runs == 1:
        if len(streams) > 1:
            problems.append("expected one sender stream, saw %d" % len(streams))
        offset = dict.fromkeys(streams | set(runs), 0)
    else:
        seen_runs = set(runs) | streams
        if len(runs) != a.sender_runs or len(seen_runs) != a.sender_runs:
            problems.append("expected %d sender runs, saw %d" % (a.sender_runs, len(seen_runs)))
        received_max = {}
        for g in got:
            s = g["wd2l_stream"]
            received_max[s] = max(received_max.get(s, 0), g["wd2l_seq"])
        base = 0
        for s in runs:
            offset[s] = base
            if s in ends:
                base += ends[s]["last_seq"]
            else:
                if s != runs[-1]:
                    problems.append("sender run %s did not end cleanly (no stream_end)" % s)
                base += received_max.get(s, 0)  # best guess, so later runs still line up
        for s, h in ends.items():
            unread = h.get("sender", {}).get("shutdown_unread_bytes")
            if unread:
                problems.append("sender run %s stopped with %s bytes of input unread" % (s, unread))
        for kind in ("stream_lost", "stream_missing", "sender_boot_reset"):
            n = sum(h["type"] == kind for h in health if not h.get("records"))
            if n:
                problems.append("%d %s record(s)" % (n, kind))
    seen = {}
    dups = 0
    delays = []
    for g in got:
        seq = offset.get(g.pop("wd2l_stream"), 0) + g.pop("wd2l_seq")
        # The arrival time is added in Enclave 2, so it is checked apart from the wire content.
        fields = g.get("fields", {})
        rx, tx = fields.pop("wd2l_rx_time", None), fields.get("wd2l_tx_time")
        if not fields:
            g.pop("fields", None)
        if tx is None or rx is None:
            problems.append("seq %d has no send or arrival time" % seq)
        else:
            delays.append(rx - tx)
        if seq in seen:
            dups += 1
            if not a.allow_duplicates or seen[seq] != g:
                problems.append("duplicate seq %d" % seq)
        seen[seq] = g
        if seq not in sent_by_seq:
            problems.append("unexpected seq %d" % seq)
        elif g != expected(seq, tx):
            problems.append("seq %d content differs" % seq)

    if a.state:
        with open(a.state) as f:
            st = json.load(f)
        open_gaps = set()
        for sid, s in st["streams"].items():
            if s.get("records"):
                continue
            base = offset.get(sid, 0)
            for lo, hi in s["gaps"]:
                open_gaps |= set(range(base + lo, base + hi + 1))
    else:
        open_gaps = set()
        for h in health:
            if h["type"] == "gap" and not h.get("records"):
                base = offset.get(h["stream"], 0)
                open_gaps |= set(range(base + h["first_seq"], base + h["last_seq"] + 1))

    missing = set(sent_by_seq) - set(seen)
    if missing - open_gaps:
        problems.append("%d events missing and NOT reported as gaps: %s"
                        % (len(missing - open_gaps), sorted(missing - open_gaps)[:20]))
    if open_gaps - missing:
        problems.append("%d gaps reported for events that did arrive" % len(open_gaps - missing))
    if open_gaps and not a.expect_gaps:
        problems.append("%d events lost but no loss was injected" % len(open_gaps))
    if a.expect_gaps and not open_gaps:
        problems.append("loss was injected but no gaps were reported")

    last = [h for h in health if h["type"] == "health"]
    last = last[-1] if last else {}
    for k in ("other_packets", "bad_frames", "bad_events", "digest_mismatch"):
        if k == "other_packets" and a.allow_other_packets:
            continue
        if last.get(k):
            problems.append("%s = %s" % (k, last[k]))
    truncated = sorted(s for s, e in seen.items() if "wd2l_truncated" in e.get("fields", {}))
    flagged = sorted(s for s, e in seen.items() if "wd2l_opaque" in e.get("fields", {}))
    if a.generated is not None:
        # An oracle of their own (#151): the generator's positions, not the sender's code, which
        # the content check above shares with what it checks. Lost events can't be flagged.
        want = [a.generated + 1] if a.generated + 1 in seen else []
        if truncated != want:
            problems.append("truncated: seq %s, expected %s" % (truncated, want))
        want = [p + 1 for p in OPAQUE_AT if p < a.generated and p + 1 in seen]
        if flagged != want:
            problems.append("opaque content: seq %s, expected %s" % (flagged, want))

    for d in a.audit_dir:
        res = auditlog.verify_dir(d)
        names = []
        for path in auditlog.audit_files(d):
            with open(path, "rb") as f:
                names += [json.loads(x)["event"] for x in auditlog.split_lines(f.read())
                          if x.endswith(b"\n")]
        if not res.ok:
            problems.append("audit chain in %s: %s" % (d, res.problems[:3]))
        if "start" not in names:
            problems.append("audit trail in %s has no start record" % d)
        print("audit %-28s %d records, chain %s%s" % (
            os.path.basename(d.rstrip("/")) + ":", res.records, "ok" if res.ok else "BROKEN",
            ", %d torn line(s)" % len(res.torn) if res.torn else ""))

    if a.e1_audit_dir:
        official = {}
        for path in auditlog.audit_files(a.e1_audit_dir):
            with open(path, "rb") as f:
                for line in auditlog.split_lines(f.read()):
                    if line.endswith(b"\n"):
                        r = json.loads(line)
                        official[r["n"]] = r["hash"]
        inband = [r for r in load(os.path.join(a.received_dir, "audit.jsonl"))
                  if r.get("component") == "sender" and r.get("n") is not None]
        wrong = [r["n"] for r in inband if official.get(r["n"]) != r["hash"]]
        missing = set(official) - {r["n"] for r in inband}
        if wrong:
            problems.append("%d in-band sender audit records differ from Enclave 1's files: %s"
                            % (len(wrong), wrong[:10]))
        if missing and not a.expect_gaps:
            problems.append("%d sender audit records never reached Enclave 2: %s"
                            % (len(missing), sorted(missing)[:10]))
        print("sender audit:    %d of %d records arrived in-band" % (len(official) - len(missing),
                                                                     len(official)))

    if a.reconcile_dir:
        last_rc = {}
        for path in auditlog.audit_files(a.reconcile_dir):
            with open(path, "rb") as f:
                for line in auditlog.split_lines(f.read()):
                    if line.endswith(b"\n"):
                        r = json.loads(line)
                        if r["event"] == "reconcile" and r["component"] in ("receiver", "replay"):
                            last_rc[r["stream"]] = r
        for s in sorted(set(runs) | streams):
            r = last_rc.get(s)
            if r is None:
                problems.append("no reconcile record for stream %s" % s)
            elif not r["balanced"] and not a.expect_gaps:
                problems.append("stream %s not balanced at cut %s (%s open gap events)"
                                % (s, r["cut"], r["gaps_open"]))
        if a.expect_gaps and last_rc and all(r["balanced"] for r in last_rc.values()):
            problems.append("events were lost but every reconcile record says balanced")
        print("reconcile:       %s" % "; ".join(
            "%s cut %s %s" % (s, r["cut"], "balanced" if r["balanced"] else "NOT balanced")
            for s, r in sorted(last_rc.items())))

    print("sent:            %d" % len(sent_by_seq))
    if a.sender_runs > 1:
        print("sender runs:     %s" % ", ".join(
            "%s (%s events, input unread at stop: %s)"
            % (s, ends[s]["last_seq"] if s in ends else "?",
               ends[s].get("sender", {}).get("shutdown_unread_bytes") if s in ends else "?")
            for s in runs))
    print("received:        %d" % len(seen))
    print("duplicates:      %d" % dups)
    print("gaps (reported): %d" % len(open_gaps))
    print("truncated:       %d (seq %s)" % (len(truncated), truncated))
    print("opaque content:  %d (seq %s)" % (len(flagged), flagged))
    print("other packets on the tapped cable: %s" % last.get("other_packets"))
    print("kernel drops:    %s" % last.get("kernel_drops"))
    if delays:
        delays.sort()

        def ms(q):
            return "%.1f" % (delays[int(q * (len(delays) - 1))] * 1000)
        print("link delay (wd2l_rx_time - wd2l_tx_time): median %s ms, p99 %s ms, max %s ms"
              % (ms(0.5), ms(0.99), ms(1.0)))
    print("clock offset (last heartbeat): %s s" % last.get("clock_offset_s"))
    if problems:
        print("\nFAIL")
        for pr in problems[:50]:
            print("  - " + pr)
        return 1
    print("\nPASS: every event arrived intact or is accounted for in a reported gap")
    return 0


if __name__ == "__main__":
    sys.exit(main())
