#!/usr/bin/env python3
"""Rebuild whole log files from the events Enclave 2 received, then compare SHA-256 hashes
with the originals (from the manifest files_to_events.py wrote).

Several files sent interleaved on one stream (like a forwarder tailing logs that are being
written at the same time) are separated by (host, source) and put in order by the sender's
per-source line counter, wd2l_src_seq (sender option --source-seq). Missing lines are named by
file and line number.

A file is only rebuilt if every one of its lines arrived. Missing lines (reported gaps) or
truncated lines make it INCOMPLETE, never a false match. Duplicate copies of an event (allowed
after a receiver crash) are ignored.

Exit status 0 only if every file was rebuilt and its hash matches.
"""

import argparse
import base64
import hashlib
import json
import os
import sys

B64_FIELD = "wd2l_b64"


def load_events(path):
    """{seq: event} from the receiver's events.jsonl (first copy of each seq wins)."""
    out = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                e = json.loads(line)
                out.setdefault(e["wd2l_seq"], e)
    return out


def raw_bytes(evt):
    fields = evt.get("fields", {})
    if fields.get(B64_FIELD):
        return base64.b64decode(evt["_raw"])
    return evt["_raw"].encode("utf-8")


SRC_SEQ_FIELD = "wd2l_src_seq"


def ranges(nums):
    """[1, 2, 3, 7, 9, 10] -> "1-3, 7, 9-10" (line numbers, for reports)."""
    out, nums = [], sorted(nums)
    i = 0
    while i < len(nums):
        j = i
        while j + 1 < len(nums) and nums[j + 1] == nums[j] + 1:
            j += 1
        out.append(str(nums[i]) if i == j else "%d-%d" % (nums[i], nums[j]))
        i = j + 1
    return ", ".join(out)


def _finish(row, m, data, out_dir):
    with open(os.path.join(out_dir, m["name"]), "wb") as f:
        f.write(data)
    row["rebuilt"] = hashlib.sha256(data).hexdigest()
    row["status"] = "MATCH" if row["rebuilt"] == m["sha256"] else "DIFFERENT"


def _by_seq_range(m, events, row, out_dir):
    """Files sent one after another: the file is the contiguous seq range in the manifest."""
    seqs = range(m["first_seq"], m["last_seq"] + 1)
    missing = [s - m["first_seq"] + 1 for s in seqs if s not in events]
    wrong_source = [s for s in seqs if s in events and events[s].get("source") != m["path"]]
    truncated = [s for s in seqs if s in events and "wd2l_truncated" in events[s].get("fields", {})]
    row.update(missing=missing, truncated=len(truncated))
    if wrong_source:
        row["status"] = "WRONG-SOURCE"
    elif missing or truncated:
        row["status"] = "INCOMPLETE"
    else:
        _finish(row, m, b"".join(raw_bytes(events[s]) for s in seqs), out_dir)


def _by_source(m, events, row, out_dir):
    """Interleaved files: pick this file's events by (host, source), order them by the sender's
    per-source counter wd2l_src_seq. Line N of the file is the event with wd2l_src_seq N."""
    mine = [e for e in events.values() if e.get("source") == m["path"]
            and (m.get("host") is None or e.get("host") == m["host"])]
    streams = {e.get("wd2l_stream") for e in mine}
    lines = {}
    for e in sorted(mine, key=lambda e: e["wd2l_seq"]):
        n = e.get("fields", {}).get(SRC_SEQ_FIELD)
        if n is None:
            row["status"] = "NO-LINE-NUMBERS"
            return
        lines.setdefault(n, e)
    missing = [n for n in range(1, m["lines"] + 1) if n not in lines]
    truncated = [n for n, e in lines.items() if "wd2l_truncated" in e.get("fields", {})]
    row.update(missing=missing, truncated=len(truncated),
               extra=len([n for n in lines if n > m["lines"]]))
    if len(streams) > 1:
        # wd2l_src_seq restarts with each sender run; joining runs needs the stream chain.
        row["status"] = "MULTIPLE-RUNS"
    elif missing or truncated:
        row["status"] = "INCOMPLETE"
    else:
        _finish(row, m, b"".join(raw_bytes(lines[n]) for n in range(1, m["lines"] + 1)), out_dir)


def rebuild(manifest, events, out_dir):
    """Write rebuilt files; return one result row per manifest entry.

    Uses the per-source line numbers (wd2l_src_seq) when the events carry them, so files can be
    rebuilt from one interleaved stream. Otherwise falls back to the seq range in the manifest,
    which only works for files sent one after another."""
    os.makedirs(out_dir, exist_ok=True)
    have_src_seq = any(SRC_SEQ_FIELD in e.get("fields", {}) for e in events.values())
    rows = []
    for m in manifest:
        row = {"name": m["name"], "original": m["sha256"], "rebuilt": None,
               "missing": [], "truncated": 0, "lines": m.get("lines")}
        if have_src_seq or "first_seq" not in m:
            _by_source(m, events, row, out_dir)
        else:
            _by_seq_range(m, events, row, out_dir)
        rows.append(row)
    return rows


def report(rows):
    lines = ["%-12s %-10s %-64s %s" % ("file", "result", "sha256 original", "sha256 rebuilt")]
    for r in rows:
        extra = ""
        if r["status"] == "INCOMPLETE":
            extra = "  (%d line(s) missing: %s; %d truncated)" % (
                len(r["missing"]), ranges(r["missing"][:200]) or "-", r["truncated"])
        elif r["status"] == "NO-LINE-NUMBERS":
            extra = "  (interleaved files need the sender's --source-seq)"
        lines.append("%-12s %-10s %s %s%s" % (r["name"], r["status"], r["original"],
                                               r["rebuilt"] or "-", extra))
    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("manifest", help="manifest from files_to_events.py")
    p.add_argument("events", help="receiver output: events.jsonl")
    p.add_argument("out_dir", help="where to write the rebuilt files")
    p.add_argument("--hashes", help="also write the comparison table to this file")
    a = p.parse_args()
    with open(a.manifest) as f:
        manifest = json.load(f)
    rows = rebuild(manifest, load_events(a.events), a.out_dir)
    text = report(rows)
    print(text)
    if a.hashes:
        with open(a.hashes, "w") as f:
            f.write(text + "\n")
    sys.exit(0 if all(r["status"] == "MATCH" for r in rows) else 1)


if __name__ == "__main__":
    main()
