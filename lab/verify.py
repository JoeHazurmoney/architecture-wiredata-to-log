#!/usr/bin/env python3
"""Compare what the lab sent with what Enclave 2 rebuilt.

Sequence number N is the Nth line of the events file (fake_cribl.py, the stand-in log
aggregator, sends in order over one connection). Every sent event must be either received
exactly once, byte-for-byte equal to what the sender put on the wire, or listed in a reported
gap. Nothing else may show up.
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
    p.add_argument("--extra-field", action="append", default=[],
                   help="extra field the sender was told to carry (same as wd2l-sender)")
    a = p.parse_args()

    fitter = Sender(("127.0.0.1", 9), sock=_NoSock(), max_event=a.max_event, rate_pps=0,
                    extra_fields=a.extra_field)
    sent = load(a.sent)
    expected = {i + 1: wire.parse_event(fitter._fit(e)) for i, e in enumerate(sent)}

    got = load(os.path.join(a.received_dir, "events.jsonl"))
    health = load(os.path.join(a.received_dir, "health.jsonl"))
    streams = {g["wd2l_stream"] for g in got}

    problems = []
    if len(streams) > 1:
        problems.append("expected one sender stream, saw %d" % len(streams))
    seen = {}
    dups = 0
    for g in got:
        seq = g.pop("wd2l_seq")
        g.pop("wd2l_stream")
        if seq in seen:
            dups += 1
            if not a.allow_duplicates or seen[seq] != g:
                problems.append("duplicate seq %d" % seq)
        seen[seq] = g
        if seq not in expected:
            problems.append("unexpected seq %d" % seq)
        elif g != expected[seq]:
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

    missing = set(expected) - set(seen)
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

    print("sent:            %d" % len(expected))
    print("received:        %d" % len(seen))
    print("duplicates:      %d" % dups)
    print("gaps (reported): %d" % len(open_gaps))
    print("truncated:       %d (seq %s)" % (len(truncated), truncated))
    print("other packets on the tapped cable: %s" % last.get("other_packets"))
    print("kernel drops:    %s" % last.get("kernel_drops"))
    if problems:
        print("\nFAIL")
        for pr in problems[:50]:
            print("  - " + pr)
        return 1
    print("\nPASS: every event arrived intact or is accounted for in a reported gap")
    return 0


if __name__ == "__main__":
    sys.exit(main())
