#!/usr/bin/env python3
"""Check that the receiver placed an injected fault where expected (lab --fault runs): a
type=fault record (or, with --time-alarm, a type=time_status alarm) matching the expectation,
and a later record saying things are ok again."""

import argparse
import json
import sys


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("health", help="health.jsonl from the receiver's --out-dir")
    p.add_argument("--segment")
    p.add_argument("--status")
    p.add_argument("--rule", type=int)
    p.add_argument("--time-alarm", action="store_true")
    a = p.parse_args()
    with open(a.health) as f:
        recs = [json.loads(x) for x in f if x.strip()]
    if a.time_alarm:
        seq = [(r["time_status"], r.get("time_reason")) for r in recs if r["type"] == "time_status"]
        hit = next((i for i, (s, _) in enumerate(seq) if s == "alarm"), None)
        cleared = hit is not None and any(s == "ok" for s, _ in seq[hit + 1:])
        print("time_status records: %s" % seq)
    else:
        seq = [(r["fault_status"], r["fault_segment"], r["fault_rule"])
               for r in recs if r["type"] == "fault"]
        want = (a.status, a.segment, a.rule)
        hit = next((i for i, x in enumerate(seq) if x == want), None)
        cleared = hit is not None and any(s == "ok" for s, _, _ in seq[hit + 1:])
        print("fault records: %s" % seq)
        print("expected:      %s" % (want,))
    if hit is None:
        print("FAIL: the expected fault was never reported")
        return 1
    if not cleared:
        print("FAIL: the fault was reported but never cleared")
        return 1
    print("PASS: fault reported where expected, then cleared")
    return 0


if __name__ == "__main__":
    sys.exit(main())
