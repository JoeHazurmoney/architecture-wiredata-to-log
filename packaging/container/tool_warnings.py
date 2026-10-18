#!/usr/bin/env python3
"""Raises every warning a scanner or Syft logged as a warning on the run, never a failure
(docs/decisions/0011-vulnerability-scanners.md). A tool that can't do its job usually says so only
in its log: upstream Trivy logs "Unsupported os" on the Hardened image, and CI ran it with --quiet,
so nobody saw it (#191).

Each WARN, ERROR or FATAL line, in Trivy's format or in Grype's and Syft's, is counted once. A line
that a reviewed, unexpired entry in tool-warnings.json expects is listed as expected; any other, or
one whose entry expired, becomes a GitHub warning annotation. GitHub keeps 10 annotations per step:
past 9, one more line counts the rest. Every warning is in the --summary table.

    tool_warnings.py --known tool-warnings.json --log NAME=FILE [--log ...] [--summary OUT.md]
                     [--today YYYY-MM-DD]
Exit 0, whatever the logs hold (2 for a usage error)."""

import argparse
import json
import os
import re
import sys
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vuln_gate import MAX_DAYS  # noqa: E402  (the same 90-day limit as a vulnerability exception)

FIELDS = ("tool", "text", "reason", "expires", "approved_by")
CAP = 10                                    # annotations GitHub keeps for one step
LINE = (re.compile(r"^\S+\t(WARN|ERROR|FATAL)\t(.*)$"),            # Trivy: <time>\tLEVEL\tmessage
        re.compile(r"^\[\d+\]\s+(WARN|ERROR|FATAL)\s+(.*)$"))      # Grype, Syft: [0000]  LEVEL message
Warning = Tuple[str, str, str]              # (tool, level, message)


def warnings_in(tool: str, text: str) -> List[Warning]:
    out: List[Warning] = []
    for raw in text.splitlines():
        line = raw.rstrip("\r")
        for pat in LINE:
            m = pat.match(line)
            if m:
                w = (tool, m.group(1), " ".join(m.group(2).split()))
                if w not in out:
                    out.append(w)
                break
    return out


def load_known(doc: Dict[str, Any], today: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """(the entries in force, the problems with the rest). An expired entry is returned too, marked,
    so that its warning says to review it."""
    valid, probs = [], []
    t = date.fromisoformat(today)
    for e in doc.get("warnings") or []:
        name = "the entry for %s (%s)" % (e.get("tool"), e.get("text"))
        missing = [k for k in FIELDS if not e.get(k)]
        if missing:
            probs.append("%s is missing %s" % (name, ", ".join(missing)))
            continue
        try:
            expires = date.fromisoformat(e["expires"])
        except ValueError:
            probs.append("%s: expires %r is not YYYY-MM-DD" % (name, e["expires"]))
            continue
        if expires > t + timedelta(days=MAX_DAYS):
            probs.append("%s expires on %s, more than %d days from today: review it for %d days at most"
                         % (name, e["expires"], MAX_DAYS, MAX_DAYS))
            continue
        valid.append(dict(e, expired=expires < t))
    return valid, probs


def annotation(title: str, message: str) -> str:
    def data(s: str) -> str:
        return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return "::warning title=%s::%s" % (data(title).replace(":", "%3A").replace(",", "%2C"), data(message))


def cell(s: str) -> str:
    return s.replace("|", "\\|")


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Raise the tools' logged warnings on the run.")
    p.add_argument("--known", required=True, help="tool-warnings.json")
    p.add_argument("--log", action="append", default=[], metavar="NAME=FILE")
    p.add_argument("--summary", help="write every warning, as a Markdown table, here")
    p.add_argument("--today", default=datetime.now(timezone.utc).date().isoformat())
    a = p.parse_args(argv)
    with open(a.known, encoding="utf-8") as f:
        known, probs = load_known(json.load(f), a.today)
    raised = [annotation("tool-warnings.json", x) for x in probs]
    rows = []
    for spec in a.log:
        tool, sep, path = spec.partition("=")
        if not (sep and tool and path):
            p.error("--log %s: give NAME=FILE" % spec)
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                found = warnings_in(tool, f.read())
        except OSError:
            raised.append(annotation(tool, "no log at %s: did %s run?" % (path, tool)))
            continue
        for tool_, level, msg in found:
            e = next((k for k in known if k["tool"] == tool_ and k["text"] in msg), None)
            if e and not e["expired"]:
                rows.append((tool_, level, msg, "expected, reviewed until %s: %s" % (e["expires"], e["reason"])))
                continue
            if e:
                rows.append((tool_, level, msg, "expired on %s: review it" % e["expires"]))
                raised.append(annotation(tool_, "%s %s (its review in tool-warnings.json expired on %s: "
                                                "review it, then renew or remove it)" % (level, msg, e["expires"])))
            else:
                rows.append((tool_, level, msg, "new"))
                raised.append(annotation(tool_, "%s %s" % (level, msg)))
    if len(raised) > CAP:
        raised = raised[:CAP - 1] + [annotation("Tool warnings", "%d more, in this step's summary and the "
                                                                 "tools' logs" % (len(raised) - CAP + 1))]
    for line in raised:
        print(line)
    if a.summary:
        text = ["### Tool warnings", ""]
        if rows or probs:
            text += ["| Tool | Level | Warning | Status |", "|---|---|---|---|"]
            text += ["| %s | %s | %s | %s |" % tuple(cell(x) for x in r) for r in rows]
            text += ["", "**tool-warnings.json**", ""] + ["- " + x for x in probs] if probs else []
        else:
            text.append("None.")
        with open(a.summary, "w", encoding="utf-8") as f:
            f.write("\n".join(text) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
