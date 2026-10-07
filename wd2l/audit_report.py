"""wd2l-audit-report: reports from wd2l audit records, for assessors and audit reviews
(docs/audit-and-health-plan.md §9).

    wd2l-audit-report verify    --dir DIR | --export FILE...    check the hash chain
    wd2l-audit-report reconcile --dir DIR... | --export FILE...  reconciliation per day and stream
    wd2l-audit-report events    --dir DIR... | --export FILE...  the records, filtered

--dir reads audit files (the official copy). --export reads a SIEM export: JSON lines that are
records, or objects holding the record as text in "_raw" (also inside "result", as Splunk's
export API writes them). Times are UTC, ISO 8601, compared as text: --since is inclusive,
--until exclusive. Output is JSON (default) or CSV."""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import sys
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .audit import GENESIS, audit_files, record_hash, split_lines, verify_dir

RECONCILE_COLUMNS = ("day", "stream", "sender_cut", "events_in", "events_sent", "sender_hash",
                     "receiver_cut", "events_delivered", "gaps_open", "gaps_filled",
                     "receiver_hash", "balanced")
EVENT_COLUMNS = ("ts", "host", "enclave", "component", "segment", "event", "outcome", "actor",
                 "stream", "seq_first", "seq_last", "n")


def unwrap(obj: Any) -> Optional[Dict[str, Any]]:
    if isinstance(obj, dict) and isinstance(obj.get("result"), dict):
        obj = obj["result"]
    if isinstance(obj, dict) and isinstance(obj.get("_raw"), str):
        try:
            obj = json.loads(obj["_raw"])
        except (ValueError, RecursionError):
            return None
    return obj if isinstance(obj, dict) and "event" in obj else None


def load(dirs: Sequence[str], exports: Sequence[str]) -> tuple[List[Dict[str, Any]], List[str]]:
    out: List[Dict[str, Any]] = []
    skipped: List[str] = []
    for d in dirs:
        try:
            paths = list(audit_files(d))
        except (OSError, IOError):
            skipped.append(f"{d}: cannot read directory")
            continue
        for path in paths:
            try:
                with open(path, "rb") as f:
                    for line_num, line in enumerate(split_lines(f.read()), 1):
                        if line.endswith(b"\n"):
                            try:
                                obj = json.loads(line)
                                if not isinstance(obj, dict):
                                    skipped.append(f"{path}:{line_num}: not a JSON object")
                                else:
                                    out.append(obj)
                            except (ValueError, RecursionError):
                                skipped.append(f"{path}:{line_num}: not JSON")
            except (OSError, IOError) as e:
                skipped.append(f"{path}: {e}")
    for path in exports:
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for line_num, line in enumerate(f, 1):
                    if line.strip():
                        try:
                            obj = json.loads(line)
                        except (ValueError, RecursionError):
                            skipped.append(f"{path}:{line_num}: not JSON")
                            continue
                        rec = unwrap(obj)
                        if rec is None:
                            skipped.append(f"{path}:{line_num}: not an audit record")
                        else:
                            out.append(rec)
        except (OSError, IOError) as e:
            skipped.append(f"{path}: {e}")
    return out, skipped


def verify_export(records: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """A SIEM copy can come in any order, with duplicates (re-sent) and holes (records-stream
    loss, or a search window): sort by n, accept identical copies, list the holes. Links are
    checked between neighbouring numbers only. Chains are split by host/enclave, so a record
    whose host was altered lands in another chain (design limit)."""
    chains: Dict[str, List[Dict[str, Any]]] = {}
    for r in records:
        chains.setdefault("%s/enclave%s" % (r.get("host"), r.get("enclave")), []).append(r)
    out: Dict[str, Dict[str, Any]] = {}
    for name, recs in sorted(chains.items()):
        problems: List[str] = []
        by_n: Dict[int, Dict[str, Any]] = {}
        unchained = 0
        for r in recs:
            n = r.get("n")
            if n is None:
                unchained += 1
                continue
            # Check if n is a valid integer (not bool, which is a subclass of int)
            if isinstance(n, bool) or not isinstance(n, int):
                problems.append("record with non-integer n (%r)" % (n,))
                continue
            # Keep the first record for each n; later different copies are a problem
            if n in by_n:
                if by_n[n] != r:
                    problems.append("n=%d: two different records" % n)
            else:
                by_n[n] = r
        missing: List[List[int]] = []
        prev = None
        for n in sorted(by_n):
            r = by_n[n]
            try:
                h = record_hash(r)
            except (ValueError, TypeError, RecursionError):
                problems.append("n=%d can't be hashed (not canonical JSON)" % n)
                continue
            if h != r.get("hash"):
                problems.append("n=%d content does not match its hash (edited)" % n)
            if prev is None:
                if n == 1 and r.get("prev_hash") != GENESIS:
                    problems.append("n=1 does not start from the genesis hash")
            elif n == prev[0] + 1:
                if r.get("prev_hash") != prev[1]:
                    problems.append("n=%d does not link to n=%d" % (n, prev[0]))
            else:
                missing.append([prev[0] + 1, n - 1])
            prev = (n, r.get("hash"))
        ns = sorted(by_n)
        out[name] = {"result": "failed" if problems else "ok", "records": len(by_n),
                     "first_n": ns[0] if ns else None, "last_n": ns[-1] if ns else None,
                     "last_hash": by_n[ns[-1]].get("hash") if ns else None, "missing": missing,
                     "unchained": unchained, "problems": problems[:100]}
    return out


def reconcile_rows(records: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The day's last reconcile record from each side, per UTC day and stream."""
    rows: Dict[tuple, Dict[str, Any]] = {}
    for r in records:
        if r.get("event") != "reconcile":
            continue
        ts = str(r.get("ts", ""))
        key = (ts[:10], r.get("stream"))
        row = rows.setdefault(key, {"day": key[0], "stream": key[1]})
        side = "sender" if r.get("component") == "sender" else "receiver"
        if ts < row.get("_" + side, ""):
            continue
        row["_" + side] = ts
        if side == "sender":
            row.update(sender_cut=r.get("cut"), events_in=r.get("events_in"),
                       events_sent=r.get("events_sent"), sender_hash=r.get("sender_hash"))
        else:
            row.update(receiver_cut=r.get("cut"), events_delivered=r.get("events_delivered"),
                       gaps_open=r.get("gaps_open"), gaps_filled=r.get("gaps_filled"),
                       receiver_hash=r.get("receiver_hash"), balanced=r.get("balanced"))
            row.setdefault("sender_hash", r.get("sender_hash"))
    return [{c: rows[k].get(c) for c in RECONCILE_COLUMNS} for k in sorted(rows, key=str)]


def filter_events(records: Iterable[Dict[str, Any]], since: Optional[str] = None,
                  until: Optional[str] = None, streams: Sequence[str] = (),
                  events: Sequence[str] = (), segments: Sequence[str] = (),
                  components: Sequence[str] = (), hosts: Sequence[str] = ()
                  ) -> List[Dict[str, Any]]:
    out = []
    for r in records:
        ts = str(r.get("ts", ""))
        if (since and ts < since) or (until and ts >= until):
            continue
        for want, field in ((streams, "stream"), (events, "event"), (segments, "segment"),
                            (components, "component"), (hosts, "host")):
            if want and r.get(field) not in want:
                break
        else:
            out.append(r)
    def sort_key(r: Dict[str, Any]) -> tuple:
        n = r.get("n")
        n_val = n if isinstance(n, int) and not isinstance(n, bool) else 0
        return (str(r.get("ts", "")), str(r.get("host")), n_val)
    return sorted(out, key=sort_key)


def _csv(rows: List[Dict[str, Any]], columns: Sequence[str]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=list(columns), extrasaction="ignore", lineterminator="\n")
    w.writeheader()
    for r in rows:
        w.writerow(r)
    return buf.getvalue()


def _event_row(r: Dict[str, Any]) -> Dict[str, Any]:
    row = {c: r.get(c) for c in EVENT_COLUMNS}
    row["details"] = json.dumps({k: v for k, v in r.items()
                                 if k not in EVENT_COLUMNS and k not in ("prev_hash", "hash")},
                                sort_keys=True)
    return row


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="wd2l-audit-report", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd")
    cmds = {name: sub.add_parser(name) for name in ("verify", "reconcile", "events")}
    for sp in cmds.values():
        sp.add_argument("--dir", action="append", default=[], help="audit directory (repeatable)")
        sp.add_argument("--export", nargs="+", default=[], help="SIEM export files (JSON lines)")
        sp.add_argument("--format", choices=("json", "csv"), default="json")
    cmds["verify"].add_argument("--upto", type=int, help="with --dir: the chain must reach this n")
    cmds["verify"].add_argument("--upto-hash", help="... and record --upto must have this hash")
    cmds["verify"].add_argument("--complete", action="store_true",
                                help="with --export: records missing from the export fail")
    for name in ("reconcile", "events"):
        cmds[name].add_argument("--since", help="UTC, e.g. 2026-10-05 or 2026-10-05T14:00")
        cmds[name].add_argument("--until")
    ev = cmds["events"]
    for flag in ("--stream", "--event", "--segment", "--component", "--host"):
        ev.add_argument(flag, action="append", default=[])
    try:
        a = p.parse_args(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 2
    if not a.cmd or not (a.dir or a.export):
        p.print_usage(sys.stderr)
        print("need a subcommand and --dir or --export", file=sys.stderr)
        return 2

    if a.cmd == "verify":
        if a.dir:
            if len(a.dir) != 1 or a.export:
                print("verify takes one --dir (one chain) or --export", file=sys.stderr)
                return 2
            if not os.path.isdir(a.dir[0]):
                print("no such directory: %s" % a.dir[0], file=sys.stderr)
                return 2
            try:
                verify_result = verify_dir(a.dir[0], a.upto, a.upto_hash)
            except (OSError, IOError) as e:
                print("no such directory: %s" % a.dir[0], file=sys.stderr)
                return 2
            if verify_result.records == 0:
                verify_result.problems.append("no audit records found")
            res = verify_result.to_json()
            print(json.dumps(res, sort_keys=True) if a.format == "json" else
                  _csv([dict(res, problems="; ".join(res["problems"]))], sorted(res)), end="\n")
            return 0 if res["result"] == "ok" else 1
        for path in a.export:
            if not os.path.exists(path):
                print("no such file: %s" % path, file=sys.stderr)
                return 2
        recs, skipped = load([], a.export)
        chains = verify_export(recs)
        bad = bool(skipped) or not chains or any(c["problems"] or (a.complete and c["missing"])
                                                   for c in chains.values())
        if a.format == "json":
            if skipped:
                chains["unreadable"] = skipped
            print(json.dumps(chains, sort_keys=True))
        else:
            rows = [dict(c, chain=k, missing=json.dumps(c["missing"]), problems="; ".join(c["problems"]))
                    for k, c in chains.items()]
            if skipped:
                rows.append({"chain": "(unreadable)", "result": "failed", "problems": "; ".join(skipped)})
            print(_csv(rows, ["chain", "result", "records", "first_n", "last_n", "missing",
                              "unchained", "problems"]), end="")
        if not chains:
            print("nothing to verify", file=sys.stderr)
        return 1 if bad else 0

    # Check directories exist for reconcile/events
    for d in a.dir:
        if not os.path.isdir(d):
            print("no such directory: %s" % d, file=sys.stderr)
            return 2
    for path in a.export:
        if not os.path.exists(path):
            print("no such file: %s" % path, file=sys.stderr)
            return 2
    recs, skipped = load(a.dir, a.export)
    if a.cmd == "reconcile":
        rows = reconcile_rows(filter_events(recs, a.since, a.until, events=["reconcile"]))
        print(json.dumps(rows) if a.format == "json" else _csv(rows, RECONCILE_COLUMNS), end="\n")
        if skipped:
            print("skipped %d unreadable lines" % len(skipped), file=sys.stderr)
        return 0
    rows = filter_events(recs, a.since, a.until, a.stream, a.event, a.segment, a.component, a.host)
    if a.format == "json":
        print(json.dumps(rows))
    else:
        print(_csv([_event_row(r) for r in rows], EVENT_COLUMNS + ("details",)), end="")
    if skipped:
        print("skipped %d unreadable lines" % len(skipped), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
