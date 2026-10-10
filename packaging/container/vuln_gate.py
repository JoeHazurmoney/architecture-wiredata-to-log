#!/usr/bin/env python3
"""One gate over Grype and Trivy results (docs/decisions/0004-container-base-image.md).

Fails on any fixable High or Critical vulnerability, and on any secret Trivy finds, unless an
unexpired exception in vuln-exceptions.json names that ID in that package. Also fails on any
expired or incomplete exception, used or not, so that each one gets looked at again.

    vuln_gate.py --grype G.json --trivy T.json --exceptions E.json [--today YYYY-MM-DD]
                 [--summary OUT.md] [--predicate OUT.json]"""

import argparse
import json
import sys
from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

GATED = ("HIGH", "CRITICAL")
FIELDS = ("id", "package", "reason", "expires", "approved_by")


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


def summary(gated: List[Dict[str, Any]], excepted: List[Dict[str, Any]], probs: List[str],
            counts: Dict[str, int]) -> str:
    lines = ["### Vulnerability gate: %s" % ("FAILED" if gated or probs else "passed"), "",
             "Findings: %s." % ", ".join("%s %d" % kv for kv in sorted(counts.items())), ""]
    for title, rows in (("Gated (fixable High/Critical, or a secret)", gated),
                        ("Covered by an exception", excepted)):
        if rows:
            lines += ["**%s**" % title, "", "| Scanner | ID | Package | Version | Severity | Fixed in |",
                      "|---|---|---|---|---|---|"]
            lines += ["| %(scanner)s | %(id)s | %(package)s | %(version)s | %(severity)s | %(fixed_in)s |" % f
                      for f in rows]
            lines.append("")
    lines += ["- " + p for p in probs]
    return "\n".join(lines) + "\n"


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Gate Grype and Trivy results.")
    p.add_argument("--grype", required=True)
    p.add_argument("--trivy", required=True)
    p.add_argument("--exceptions", required=True)
    p.add_argument("--today", default=datetime.now(timezone.utc).date().isoformat())
    p.add_argument("--summary")
    p.add_argument("--predicate")
    a = p.parse_args(argv)
    docs = {}
    for name in ("grype", "trivy", "exceptions"):
        with open(getattr(a, name)) as f:
            docs[name] = json.load(f)
    g, t = grype_findings(docs["grype"]), trivy_findings(docs["trivy"])
    valid, probs = load_exceptions(docs["exceptions"], a.today)
    gated, excepted = gate(g + t, valid)
    text = summary(gated, excepted, probs, {"grype": len(g), "trivy": len(t)})
    print(text)
    if a.summary:
        with open(a.summary, "w") as f:
            f.write(text)
    if a.predicate:
        with open(a.predicate, "w") as f:
            json.dump({"scanned_on": a.today,
                       "scanners": {"grype": docs["grype"].get("descriptor", {}),
                                    "trivy": {"SchemaVersion": docs["trivy"].get("SchemaVersion")}},
                       "gate": {"passed": not (gated or probs), "rule": "fixable High/Critical, or a secret",
                                "gated": gated, "excepted": excepted, "problems": probs},
                       "findings": {"grype": len(g), "trivy": len(t)}}, f, indent=1)
    return 1 if gated or probs else 0


if __name__ == "__main__":
    sys.exit(main())
