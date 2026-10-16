#!/usr/bin/env python3
"""One review gate over Grype and Trivy results (docs/decisions/0004-container-base-image.md).

Scanning measures known risk at the time of the scan, so findings never fail the build (#175).
This records them, and says whether a security review is needed: for any fixable High or
Critical vulnerability, and any secret Trivy finds, unless an unexpired exception in
vuln-exceptions.json names that ID in that package; and for any exception that is expired,
incomplete or runs more than 90 days from the scan, used or not, so that each one gets looked
at again. image.yml then pauses at the security-review environment until a reviewer approves.

    vuln_gate.py --grype G.json --trivy T.json --exceptions E.json [--today YYYY-MM-DD]
                 [--summary OUT.md] [--predicate OUT.json] [--exit-code N]

Exit 0, or N with --exit-code when a review is needed (the weekly rescan opens an issue)."""

import argparse
import json
import sys
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

GATED = ("HIGH", "CRITICAL")
FIELDS = ("id", "package", "reason", "expires", "approved_by")
MAX_DAYS = 90                      # an exception's life, at most (docs/releasing.md)


def grype_findings(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for m in doc.get("matches") or []:
        v, a = m.get("vulnerability") or {}, m.get("artifact") or {}
        fix = v.get("fix") or {}
        out.append({"scanner": "grype", "id": v.get("id"), "package": a.get("name"),
                    "version": a.get("version"), "severity": str(v.get("severity", "")).upper(),
                    "fixed_in": ",".join(fix.get("versions") or []),
                    "fixable": fix.get("state") == "fixed", "secret": False})
    return out


def trivy_findings(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for r in doc.get("Results") or []:
        for v in r.get("Vulnerabilities") or []:
            out.append({"scanner": "trivy", "id": v.get("VulnerabilityID"),
                        "package": v.get("PkgName"), "version": v.get("InstalledVersion"),
                        "severity": str(v.get("Severity", "")).upper(),
                        "fixed_in": v.get("FixedVersion") or "",
                        "fixable": bool(v.get("FixedVersion")), "secret": False})
        for s in r.get("Secrets") or []:
            out.append({"scanner": "trivy", "id": s.get("RuleID"), "package": r.get("Target"),
                        "version": "", "severity": "SECRET", "fixed_in": "", "fixable": True,
                        "secret": True})
    return out


def load_exceptions(doc: Dict[str, Any], today: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    valid, probs = [], []
    t = date.fromisoformat(today)
    for e in doc.get("exceptions") or []:
        missing = [k for k in FIELDS if not e.get(k)]
        if missing:
            probs.append("exception %s is missing %s" % (e.get("id"), ", ".join(missing)))
            continue
        try:
            expires = date.fromisoformat(e["expires"])
        except ValueError:
            probs.append("exception %s: expires %r is not YYYY-MM-DD" % (e["id"], e["expires"]))
            continue
        if expires < t:
            probs.append("exception for %s in %s expired on %s: review it, then renew or remove it"
                         % (e["id"], e["package"], e["expires"]))
            continue
        if expires > t + timedelta(days=MAX_DAYS):         # #177: 2099 passed
            probs.append("exception for %s in %s expires on %s, more than %d days from today: "
                         "approve it for %d days at most" % (e["id"], e["package"], e["expires"],
                                                             MAX_DAYS, MAX_DAYS))
            continue
        valid.append(e)
    return valid, probs


def gate(findings: List[Dict[str, Any]],
         exceptions: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    covered = {(e["id"], e["package"]) for e in exceptions}
    gated, excepted = [], []
    for f in findings:
        if not (f["secret"] or (f["severity"] in GATED and f["fixable"])):
            continue
        (excepted if (f["id"], f["package"]) in covered else gated).append(f)
    return gated, excepted


SEVERITY_ORDER = ("SECRET", "CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "UNKNOWN")


def _gate_reason(f: Dict[str, Any], gated: List[Dict[str, Any]],
                 excepted: List[Dict[str, Any]]) -> str:
    if any(f is g for g in gated):
        return "review"
    if any(f is e for e in excepted):
        return "exception"
    return "passed: no fix yet" if f["severity"] in GATED else "passed: below High"


def summary(gated: List[Dict[str, Any]], excepted: List[Dict[str, Any]], probs: List[str],
            counts: Dict[str, int], findings: Sequence[Dict[str, Any]] = ()) -> str:
    lines = ["### Vulnerability scan: %s" % ("security review needed" if gated or probs
                                             else "no review needed"), "",
             "Findings: %s." % ", ".join("%s %d" % kv for kv in sorted(counts.items())), ""]
    for title, rows in (("Needs review (fixable High/Critical, or a secret)", gated),
                        ("Covered by an exception", excepted)):
        if rows:
            lines += ["**%s**" % title, "", "| Scanner | ID | Package | Version | Severity | Fixed in |",
                      "|---|---|---|---|---|---|"]
            lines += ["| %(scanner)s | %(id)s | %(package)s | %(version)s | %(severity)s | %(fixed_in)s |" % f
                      for f in rows]
            lines.append("")
    if findings:
        rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
        lines += ["**Every finding, worst first**", "",
                  "| Scanner | ID | Package | Version | Severity | Fixed in | Gate |",
                  "|---|---|---|---|---|---|---|"]
        for f in sorted(findings, key=lambda f: (rank.get(f["severity"], len(rank)),
                                                 f["scanner"], str(f["id"]))):
            lines.append("| %s | %s | %s | %s | %s | %s | %s |" % (
                f["scanner"], f["id"], f["package"], f["version"], f["severity"], f["fixed_in"],
                _gate_reason(f, gated, excepted)))
        lines.append("")
    if probs:
        lines += ["**Exceptions to review**", ""] + ["- " + p for p in probs]
    return "\n".join(lines) + "\n"


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Gate Grype and Trivy results.")
    p.add_argument("--grype", required=True)
    p.add_argument("--trivy", required=True)
    p.add_argument("--exceptions", required=True)
    p.add_argument("--today", default=datetime.now(timezone.utc).date().isoformat())
    p.add_argument("--summary")
    p.add_argument("--predicate")
    p.add_argument("--exit-code", type=int, default=0, metavar="N",
                   help="exit N when a review is needed (default 0: findings never fail)")
    a = p.parse_args(argv)
    docs = {}
    for name in ("grype", "trivy", "exceptions"):
        with open(getattr(a, name)) as f:
            docs[name] = json.load(f)
    g, t = grype_findings(docs["grype"]), trivy_findings(docs["trivy"])
    valid, probs = load_exceptions(docs["exceptions"], a.today)
    gated, excepted = gate(g + t, valid)
    text = summary(gated, excepted, probs, {"grype": len(g), "trivy": len(t)}, g + t)
    print(text)
    if a.summary:
        with open(a.summary, "w") as f:
            f.write(text)
    if a.predicate:
        with open(a.predicate, "w") as f:
            json.dump({"scanned_on": a.today,
                       "scanners": {"grype": docs["grype"].get("descriptor", {}),
                                    "trivy": {"SchemaVersion": docs["trivy"].get("SchemaVersion")}},
                       "gate": {"passed": not (gated or probs), "review_needed": bool(gated or probs),
                                "rule": "fixable High/Critical, or a secret: a security review",
                                "gated": gated, "excepted": excepted, "problems": probs},
                       "findings": {"grype": len(g), "trivy": len(t)}}, f, indent=1)
    return a.exit_code if gated or probs else 0


if __name__ == "__main__":
    sys.exit(main())
