#!/usr/bin/env python3
"""Compare what the lab sent with what Enclave 2 rebuilt.

Sequence number N is the Nth line of the events file (fake_cribl.py, the stand-in log
aggregator, sends in order over one connection). Every sent event must be either received
exactly once, byte-for-byte equal to what the sender put on the wire, or listed in a reported
gap. Nothing else may show up.

Each received event must also carry its send time (wd2l_tx_time, part of what the sender put on
the wire) and its arrival time (wd2l_rx_time, added in Enclave 2). The difference is reported as
the link delay.
"""

import argparse
import json
import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from wd2l import wire  # noqa: E402
from wd2l.sender import Sender  # noqa: E402

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
    p.add_argument("--expect-gaps", action="store_true", help="loss was injected on purpose")
    p.add_argument("--allow-duplicates", action="store_true",
                   help="identical copies of an event are fine (after a receiver crash)")
    p.add_argument("--source-seq", action="store_true",
                   help="the sender ran with --source-seq (per-file line numbers)")
    p.add_argument("--extra-field", action="append", default=[],
                   help="extra field the sender was told to carry (same as wd2l-sender)")
    a = p.parse_args()

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
    if len(streams) > 1:
        problems.append("expected one sender stream, saw %d" % len(streams))
    seen = {}
    dups = 0
    delays = []
    for g in got:
        seq = g.pop("wd2l_seq")
        g.pop("wd2l_stream")
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
        for s in st["streams"].values():
            for lo, hi in s["gaps"]:
                open_gaps |= set(range(lo, hi + 1))
    else:
        open_gaps = set()
        for h in health:
            if h["type"] == "gap":
                open_gaps |= set(range(h["first_seq"], h["last_seq"] + 1))

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
        if last.get(k):
            problems.append("%s = %s" % (k, last[k]))
    truncated = [s for s, e in seen.items() if "wd2l_truncated" in e.get("fields", {})]
    flagged = sorted(s for s, e in seen.items() if "wd2l_opaque" in e.get("fields", {}))

    print("sent:            %d" % len(sent_by_seq))
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
