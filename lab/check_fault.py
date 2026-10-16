#!/usr/bin/env python3
"""Check a lab run's fault and time records (the receiver's health.jsonl).

With an expectation (--segment/--status/--rule, or --time-alarm; lab --fault runs): a matching
type=fault record (or a type=time_status alarm), then a later record saying things are ok again.
With --first, the first one the receiver reports must be it: what an operator sees first after
a fault must name the right segment (#149).

With --none (every other lab run): no time alarm, and no fault but the --allow-rule ones, for
example rule 9 after loss or an outage. A false alarm otherwise reaches main unseen."""

import argparse
import json
import sys


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("health", help="health.jsonl from the receiver's --out-dir")
    p.add_argument("--segment")
    p.add_argument("--status")
    p.add_argument("--rule", type=int)
    p.add_argument("--time-alarm", action="store_true")
    p.add_argument("--first", action="store_true",
                   help="the expected fault must be the first one reported")
    p.add_argument("--none", action="store_true", help="no fault and no time alarm at all")
    p.add_argument("--allow-rule", type=int, action="append", default=[],
                   help="with --none: a fault rule this run may raise (repeatable)")
    a = p.parse_args()
    with open(a.health) as f:
        recs = [json.loads(x) for x in f if x.strip()]
    times = [(r["time_status"], r.get("time_reason")) for r in recs if r["type"] == "time_status"]
    faults = [(r["fault_status"], r["fault_segment"], r["fault_rule"])
              for r in recs if r["type"] == "fault"]
    if a.none:
        print("fault records:       %s" % faults)
        print("time_status records: %s" % times)
        false = [x for x in faults if x[0] != "ok" and x[2] not in a.allow_rule]
        alarms = [x for x in times if x[0] == "alarm"]
        if false or alarms:
            print("FAIL: a false alarm: %s" % (false + alarms))
            return 1
        print("PASS: no fault%s and no time alarm" % (
            " but rule %s" % ", ".join(map(str, a.allow_rule)) if a.allow_rule else ""))
        return 0
    if a.time_alarm:
        seq, want = times, "alarm"
        print("time_status records: %s" % seq)
        matches = [i for i, (s, _) in enumerate(seq) if s == want]
        shown = [i for i, (s, _) in enumerate(seq) if s != "ok"]
    else:
        seq, want = faults, (a.status, a.segment, a.rule)
        print("fault records: %s" % seq)
        print("expected:      %s" % (want,))
        matches = [i for i, x in enumerate(seq) if x == want]
        shown = [i for i, x in enumerate(seq) if x[0] != "ok"]
    hit = matches[0] if matches else None
    if hit is None:
        print("FAIL: the expected fault was never reported")
        return 1
    if a.first and shown[0] != hit:
        print("FAIL: the receiver reported %s first" % (seq[shown[0]],))
        return 1
    if not any(x[0] == "ok" for x in seq[hit + 1:]):
        print("FAIL: the fault was reported but never cleared")
        return 1
    print("PASS: fault reported where expected, then cleared")
    return 0


if __name__ == "__main__":
    sys.exit(main())
