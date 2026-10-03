#!/usr/bin/env python3
"""Turn log files into lab events, one event per line, so whole files can cross the one-way
path and be rebuilt byte for byte (see rebuild_files.py).

Each event's _raw is the line *including* its line ending, so joining the _raw values of a file
in order gives back the exact file. Lines that are not valid UTF-8 travel base64-encoded with the
indexed field wd2l_b64=1 (start the sender with --extra-field wd2l_b64).

Two orders:
  default        file after file, like copying finished files
  --interleave   merged by each line's own timestamp, like a forwarder tailing several logs that
                 are being written at the same time. Each file's own line order is always kept.

Writes the events file (JSONL) and a manifest with, per file, its line count, size and SHA-256
(and, in file-after-file order, the sequence numbers its lines get: the lab's stand-in aggregator
sends in order over one connection, so line N of the events file is sequence number N).
"""

import argparse
import base64
import calendar
import hashlib
import heapq
import json
import os
import re
import socket
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from wd2l import wire  # noqa: E402

B64_FIELD = "wd2l_b64"

SOURCETYPES = (("audit", "linux_audit"), ("secure", "linux_secure"), ("auth", "linux_secure"),
               ("messages", "syslog"), ("syslog", "syslog"))

MONTHS = {m: i for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}
SYSLOG_TIME = re.compile(rb"^([A-Z][a-z]{2}) {1,2}(\d{1,2}) (\d\d):(\d\d):(\d\d)")
AUDIT_TIME = re.compile(rb"msg=audit\((\d+)\.(\d+):")


def sourcetype_for(path):
    name = os.path.basename(path).lower()
    for key, st in SOURCETYPES:
        if key in name:
            return st
    return "log_file"


def split_lines(data):
    """Split bytes after every b"\\n", keeping the endings. Joining the parts gives data back."""
    parts, start = [], 0
    while True:
        i = data.find(b"\n", start)
        if i < 0:
            break
        parts.append(data[start:i + 1])
        start = i + 1
    if start < len(data):
        parts.append(data[start:])
    return parts


def line_time(line, year):
    """Epoch seconds from an auditd record or a traditional syslog line (UTC), else None."""
    m = AUDIT_TIME.search(line)
    if m:
        return int(m.group(1)) + int(m.group(2)) / 10 ** len(m.group(2))
    m = SYSLOG_TIME.match(line)
    if m and m.group(1).decode() in MONTHS:
        try:
            return float(calendar.timegm((year, MONTHS[m.group(1).decode()], int(m.group(2)),
                                          int(m.group(3)), int(m.group(4)), int(m.group(5)))))
        except ValueError:
            return None
    return None


def timed_lines(lines, fallback):
    """[(time, line)]: lines without a timestamp inherit the previous line's time."""
    out, t = [], None
    for line in lines:
        lt = line_time(line, time.gmtime(fallback).tm_year)
        if lt is not None:
            t = lt
        out.append((t, line))
    first = next((x for x, _ in out if x is not None), fallback)
    return [(x if x is not None else first, line) for x, line in out]


def line_event(line, path, host, index, t=None):
    evt = {"host": host, "source": path, "sourcetype": sourcetype_for(path), "index": index}
    if t is not None:
        evt["_time"] = round(t, 6)
    try:
        evt["_raw"] = line.decode("utf-8")
    except UnicodeDecodeError:
        evt["_raw"] = base64.b64encode(line).decode("ascii")
        evt[B64_FIELD] = 1
    return evt


def convert(paths, host=None, index="enclave1", max_event=wire.DEFAULT_MAX_EVENT, first_seq=1,
            interleave=False):
    """Return (events, manifest). Raises ValueError if a line would not fit in one event."""
    host = host or socket.gethostname()
    names = [os.path.basename(p) for p in paths]
    if len(set(names)) != len(names):
        raise ValueError("two input files share a name; rename one: %s" % names)
    per_file, manifest, too_big = [], [], []
    for path in paths:
        with open(path, "rb") as f:
            data = f.read()
        lines = split_lines(data)
        timed = timed_lines(lines, os.path.getmtime(path))
        per_file.append([(t, i, path, line) for i, (t, line) in enumerate(timed)])
        for n, line in enumerate(lines, 1):
            if len(wire.serialize_event(line_event(line, path, host, index), (B64_FIELD,))) > max_event:
                too_big.append("%s line %d (%d bytes)" % (path, n, len(line)))
        manifest.append({"path": path, "name": os.path.basename(path), "host": host,
                         "lines": len(lines), "bytes": len(data),
                         "sha256": hashlib.sha256(data).hexdigest()})
    if too_big:
        raise ValueError("lines too big for one event (max %d bytes serialized); they would "
                         "arrive truncated: %s" % (max_event, "; ".join(too_big[:10])))

    if interleave:
        # heapq.merge only compares the heads of the inputs, so each file keeps its own order
        # even where its timestamps go backwards.
        ordered = list(heapq.merge(*per_file, key=lambda x: x[0]))
    else:
        ordered = [x for f in per_file for x in f]
        seq = first_seq
        for m in manifest:
            m["first_seq"], m["last_seq"] = seq, seq + m["lines"] - 1
            seq += m["lines"]
    events = [line_event(line, path, host, index, t) for t, _, path, line in ordered]
    return events, manifest


def switches(events):
    """How many times consecutive events come from different files."""
    return sum(1 for a, b in zip(events, events[1:]) if a["source"] != b["source"])


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("files", nargs="+")
    p.add_argument("--out", required=True, help="events file to write (JSONL)")
    p.add_argument("--manifest", required=True, help="manifest file to write (JSON)")
    p.add_argument("--host", help="host field for every event (default: this machine)")
    p.add_argument("--max-event", type=int, default=wire.DEFAULT_MAX_EVENT)
    p.add_argument("--interleave", action="store_true",
                   help="merge the files by each line's timestamp instead of file after file")
    a = p.parse_args()
    try:
        events, manifest = convert(a.files, a.host, max_event=a.max_event, interleave=a.interleave)
    except (OSError, ValueError) as e:
        sys.exit("files_to_events: %s" % e)
    with open(a.out, "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    with open(a.manifest, "w") as f:
        json.dump(manifest, f, indent=2)
    for m in manifest:
        print("  %-12s %7d lines %10d bytes  sha256 %s" % (m["name"], m["lines"], m["bytes"],
                                                          m["sha256"]))
    if a.interleave:
        print("  interleaved by time: %d events, the source file changes %d times between "
              "consecutive events" % (len(events), switches(events)))


if __name__ == "__main__":
    main()
