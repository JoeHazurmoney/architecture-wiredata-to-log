#!/usr/bin/env python3
"""Turn log files into lab events, one event per line, so whole files can cross the one-way
path and be rebuilt byte for byte (see rebuild_files.py).

Each event's _raw is the line *including* its line ending, so joining the _raw values of a file
in sequence order gives back the exact file. Lines that are not valid UTF-8 travel base64-encoded
with the indexed field wd2l_b64=1 (start the sender with --extra-field wd2l_b64).

Writes the events file (JSONL) and a manifest with, per file, the sequence numbers its lines get
(the lab's stand-in aggregator sends in order over one connection, so line N of the events file
is sequence number N), its size and its SHA-256.
"""

import argparse
import base64
import hashlib
import json
import os
import socket
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from wd2l import wire  # noqa: E402

B64_FIELD = "wd2l_b64"

SOURCETYPES = (("audit", "linux_audit"), ("secure", "linux_secure"), ("auth", "linux_secure"),
               ("messages", "syslog"), ("syslog", "syslog"))


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


def line_event(line, path, host, index):
    evt = {"host": host, "source": path, "sourcetype": sourcetype_for(path), "index": index}
    try:
        evt["_raw"] = line.decode("utf-8")
    except UnicodeDecodeError:
        evt["_raw"] = base64.b64encode(line).decode("ascii")
        evt[B64_FIELD] = 1
    return evt


def convert(paths, host=None, index="enclave1", max_event=wire.DEFAULT_MAX_EVENT, first_seq=1):
    """Return (events, manifest). Raises ValueError if a line would not fit in one event."""
    host = host or socket.gethostname()
    events, manifest, seq = [], [], first_seq
    too_big = []
    for path in paths:
        with open(path, "rb") as f:
            data = f.read()
        lines = split_lines(data)
        start = seq
        for n, line in enumerate(lines, 1):
            evt = line_event(line, path, host, index)
            if len(wire.serialize_event(evt, (B64_FIELD,))) > max_event:
                too_big.append("%s line %d (%d bytes)" % (path, n, len(line)))
            events.append(evt)
            seq += 1
        manifest.append({"path": path, "name": os.path.basename(path), "first_seq": start,
                         "last_seq": seq - 1, "lines": len(lines), "bytes": len(data),
                         "sha256": hashlib.sha256(data).hexdigest()})
    if too_big:
        raise ValueError("lines too big for one event (max %d bytes serialized); they would "
                         "arrive truncated: %s" % (max_event, "; ".join(too_big[:10])))
    names = [m["name"] for m in manifest]
    if len(set(names)) != len(names):
        raise ValueError("two input files share a name; rename one: %s" % names)
    return events, manifest


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("files", nargs="+")
    p.add_argument("--out", required=True, help="events file to write (JSONL)")
    p.add_argument("--manifest", required=True, help="manifest file to write (JSON)")
    p.add_argument("--host", help="host field for every event (default: this machine)")
    p.add_argument("--max-event", type=int, default=wire.DEFAULT_MAX_EVENT)
    a = p.parse_args()
    try:
        events, manifest = convert(a.files, a.host, max_event=a.max_event)
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


if __name__ == "__main__":
    main()
