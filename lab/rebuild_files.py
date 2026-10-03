#!/usr/bin/env python3
"""Rebuild whole log files from the events Enclave 2 received, then compare SHA-256 hashes
with the originals (from the manifest files_to_events.py wrote).

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


def rebuild(manifest, events, out_dir):
    """Write rebuilt files; return one result row per manifest entry."""
    os.makedirs(out_dir, exist_ok=True)
    rows = []
    for m in manifest:
        seqs = range(m["first_seq"], m["last_seq"] + 1)
        missing = [s for s in seqs if s not in events]
        wrong_source = [s for s in seqs if s in events and events[s].get("source") != m["path"]]
        truncated = [s for s in seqs if s in events
                     and "wd2l_truncated" in events[s].get("fields", {})]
        row = {"name": m["name"], "original": m["sha256"], "rebuilt": None,
               "missing": len(missing), "truncated": len(truncated)}
        if missing or wrong_source or truncated:
            row["status"] = "INCOMPLETE"
            if wrong_source:
                row["status"] = "WRONG-SOURCE"
        else:
            data = b"".join(raw_bytes(events[s]) for s in seqs)
            with open(os.path.join(out_dir, m["name"]), "wb") as f:
                f.write(data)
            row["rebuilt"] = hashlib.sha256(data).hexdigest()
            row["status"] = "MATCH" if row["rebuilt"] == m["sha256"] else "DIFFERENT"
        rows.append(row)
    return rows


def report(rows):
    lines = ["%-12s %-10s %-64s %s" % ("file", "result", "sha256 original", "sha256 rebuilt")]
    for r in rows:
        extra = ""
        if r["status"] == "INCOMPLETE":
            extra = "  (%d line(s) missing, %d truncated)" % (r["missing"], r["truncated"])
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
