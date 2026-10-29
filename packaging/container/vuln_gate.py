#!/usr/bin/env python3
"""One review gate over Grype and Trivy results (docs/decisions/0011-vulnerability-scanners.md).

Scanning measures known risk at the time of the scan, so findings never fail the build (#175).
This records them, and says whether a security review is needed:

* for any fixable High or Critical vulnerability, and any secret Trivy finds, unless an unexpired
  exception in vuln-exceptions.json names that ID in that package;
* for any exception that is expired, incomplete or runs more than 90 days from the scan, used or
  not, so that each one gets looked at again;
* when no scanner covered the operating system's packages. A scanner with no advisory data for the
  image's OS checks only its language packages (and secrets), and reports nothing else (#191).

A rescan of an older release also takes the latest release's results (--latest-grype,
--latest-trivy, --latest): a gated finding whose ID and package the latest release doesn't have is
fixed there, so it's listed as "fixed in <latest>: upgrade" and needs no review (#239).

image.yml then pauses at the security-review environment until a reviewer approves. The same
finding from both scanners is shown once, with both named. The summary also shows what each
scanner covered, and each finding one scanner reported that another, covering that kind of
package, didn't: the scanners differ in their data and in how they find packages, so a person
should look at those.

    vuln_gate.py --grype G.json --trivy T.json --exceptions E.json [--today YYYY-MM-DD]
                 [--summary OUT.md] [--predicate OUT.json] [--warnings OUT.log] [--exit-code N]
                 [--latest-grype G.json --latest-trivy T.json --latest VERSION]

--warnings writes a warning for each scanner without data for the image's OS, in a log that
tool_warnings.py reads, so the same reviewed list decides which are expected. Without --summary,
the summary goes to stdout. Exit 0, or N with --exit-code when a review is needed (the
monthly rescan opens an issue)."""

import argparse
import json
import re
import sys
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

GATED = ("HIGH", "CRITICAL")
FIELDS = ("id", "package", "reason", "expires", "approved_by")
MAX_DAYS = 90                      # an exception's life, at most (docs/releasing.md)
# The operating systems each scanner's data is known to cover, by the name the scanner reports for
# the OS (Grype's distro, Trivy's OS family). Recognizing an OS isn't covering it: Red Hat's build
# of Trivy recognizes Hummingbird, then checks it against a database with no advisories for it
# (#191). Add an OS only with evidence, a scan of it that found a known advisory (ADR-0011).
OS_DATA = {"grype": ("hummingbird",       # 1.1.0: 7 findings in hummingbird:distro:hummingbird:rolling
                     "redhat"),           # UBI 9.8 (#192): 527 findings in redhat:distro:redhat:9
           "trivy": ("redhat",)}          # UBI 9.8 (#192): 534 findings in its os-pkgs result
OS_TYPES = ("rpm", "deb", "apk")           # Grype's package types for an operating system's packages


def grype_findings(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for m in doc.get("matches") or []:
        v, a = m.get("vulnerability") or {}, m.get("artifact") or {}
        fix = v.get("fix") or {}
        kind = "os" if a.get("type") in OS_TYPES else ("language" if a.get("type") else "other")
        out.append({"scanner": "grype", "id": v.get("id"), "package": a.get("name"),
                    "version": a.get("version"), "severity": str(v.get("severity", "")).upper(),
                    "fixed_in": ",".join(fix.get("versions") or []),
                    "fixable": fix.get("state") == "fixed", "secret": False, "kind": kind})
    return out


def trivy_findings(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for r in doc.get("Results") or []:
        kind = {"os-pkgs": "os", "lang-pkgs": "language"}.get(r.get("Class"), "other")
        for v in r.get("Vulnerabilities") or []:
            out.append({"scanner": "trivy", "id": v.get("VulnerabilityID"),
                        "package": v.get("PkgName"), "version": v.get("InstalledVersion"),
                        "severity": str(v.get("Severity", "")).upper(),
                        "fixed_in": v.get("FixedVersion") or "",
                        "fixable": bool(v.get("FixedVersion")), "secret": False, "kind": kind})
        for s in r.get("Secrets") or []:
            out.append({"scanner": "trivy", "id": s.get("RuleID"), "package": r.get("Target"),
                        "version": "", "severity": "SECRET", "fixed_in": "", "fixable": True,
                        "secret": True, "kind": "secret"})
    return out


def scanner_of(doc: Dict[str, Any]) -> Optional[str]:
    """Which scanner wrote a result, by its shape."""
    if "matches" in doc:
        return "grype"
    if "SchemaVersion" in doc and "ArtifactName" in doc:
        return "trivy"
    return None


def coverage(name: str, doc: Dict[str, Any]) -> Dict[str, Any]:
    """What a scanner's run covered: the OS it recognized, and whether its data covers that OS's
    packages. Both scanners check language packages; Trivy also looks for secrets."""
    if name == "grype":
        d = doc.get("distro") or {}
        os_id, version = d.get("name") or "", d.get("version") or ""
    else:
        o = (doc.get("Metadata") or {}).get("OS") or {}
        os_id = "" if o.get("Family") in (None, "", "none") else o["Family"]
        version = o.get("Name") or ""
    return {"scanner": name, "os": ("%s %s" % (os_id, version)).strip() if os_id else "",
            "os_packages": bool(os_id) and os_id in OS_DATA.get(name, ()),
            "language_packages": True, "secrets": name == "trivy"}


def bare_version(v: str) -> str:
    """Without an RPM epoch ("1:3.5.9-0.3" → "3.5.9-0.3"): Grype names it and Trivy doesn't."""
    return re.sub(r"^\d+:", "", v or "")


def merge(findings: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """One finding per ID, package and version, naming every scanner that found it, with the more
    severe rating and any fix either one knows of."""
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    out: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for f in findings:
        key = (f["id"] or "", f["package"] or "", bare_version(f["version"]))
        m = out.get(key)
        if m is None:
            out[key] = dict(f, scanners=[f["scanner"]])
            continue
        if f["scanner"] not in m["scanners"]:
            m["scanners"].append(f["scanner"])
        if rank.get(f["severity"], len(rank)) < rank.get(m["severity"], len(rank)):
            m["severity"] = f["severity"]
        m["fixable"] = m["fixable"] or f["fixable"]
        m["fixed_in"] = m["fixed_in"] or f["fixed_in"]
    for m in out.values():
        m["scanner"] = ", ".join(m["scanners"])
    return list(out.values())


def disagreements(findings: Sequence[Dict[str, Any]],
                  covers: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Each merged finding that a scanner covering its kind of package didn't report."""
    out = []
    for f in findings:
        key = {"os": "os_packages", "language": "language_packages"}.get(f.get("kind"))
        if not key:
            continue
        missed = [c["scanner"] for c in covers if c[key] and c["scanner"] not in f["scanners"]]
        if missed:
            out.append({"id": f["id"], "package": f["package"], "version": f["version"],
                        "severity": f["severity"], "found_by": list(f["scanners"]), "missed_by": missed})
    return out


def annotation(title: str, message: str) -> str:
    """A GitHub Actions warning annotation, escaped."""
    def data(s: str) -> str:
        return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return "::warning title=%s::%s" % (data(title).replace(":", "%3A").replace(",", "%2C"), data(message))


def coverage_warnings(covers: Sequence[Dict[str, Any]]) -> List[str]:
    """One warning for each scanner without data for the image's OS, and one more when none had
    any. tool_warnings.py raises them, unless tool-warnings.json expects one."""
    out = ["%s has no advisory data for this image's operating system (%s), so it checked only language "
           "packages%s." % (c["scanner"], c["os"] or "not recognized", " and secrets" if c["secrets"] else "")
           for c in covers if not c["os_packages"]]
    if not any(c["os_packages"] for c in covers):
        out.append("No scanner covered the operating system's packages: a security review is needed.")
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


def fixed_in_latest(gated: List[Dict[str, Any]], latest: Sequence[Dict[str, Any]]
                    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Split an older release's gated findings: those the latest release still has (by ID and
    package, whatever its version), and those it fixed (#239)."""
    there = {(f["id"], f["package"]) for f in latest}
    still = [f for f in gated if (f["id"], f["package"]) in there]
    return still, [f for f in gated if (f["id"], f["package"]) not in there]


SEVERITY_ORDER = ("SECRET", "CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "UNKNOWN")


def _gate_reason(f: Dict[str, Any], gated: List[Dict[str, Any]],
                 excepted: List[Dict[str, Any]], fixed: Sequence[Dict[str, Any]] = (),
                 latest: str = "") -> str:
    if any(f is g for g in gated):
        return "review"
    if any(f is x for x in fixed):
        return "fixed in %s" % latest
    if any(f is e for e in excepted):
        return "exception"
    return "passed: no fix yet" if f["severity"] in GATED else "passed: below High"


def summary(gated: List[Dict[str, Any]], excepted: List[Dict[str, Any]], probs: List[str],
            counts: Dict[str, int], findings: Sequence[Dict[str, Any]] = (),
            coverage: Sequence[Dict[str, Any]] = (), disagreements: Sequence[Dict[str, Any]] = (),
            fixed: Sequence[Dict[str, Any]] = (), latest: str = "") -> str:
    uncovered = bool(coverage) and not any(c["os_packages"] for c in coverage)
    lines = ["### Vulnerability scan: %s" % ("security review needed" if gated or probs or uncovered
                                             else "no review needed"), "",
             "Findings: %s." % ", ".join("%s %d" % kv for kv in sorted(counts.items())), ""]
    if coverage:
        yes = {True: "yes", False: "**no**"}
        lines += ["**What each scanner covered**", "",
                  "| Scanner | Operating system | OS packages | Language packages | Secrets |",
                  "|---|---|---|---|---|"]
        lines += ["| %s | %s | %s | %s | %s |" % (c["scanner"], c["os"] or "not recognized", yes[c["os_packages"]],
                                                  yes[c["language_packages"]], "yes" if c["secrets"] else "no")
                  for c in coverage]
        lines.append("")
        if uncovered:
            lines += ["**No scanner covered the operating system's packages.** None of them has advisory data "
                      "for this image's operating system, so its packages weren't checked: a person must check "
                      "them, and a security review is needed.", ""]
    for title, rows in (("Needs review (fixable High/Critical, or a secret)", gated),
                        ("Fixed in %s: upgrade" % latest, fixed),
                        ("Covered by an exception", excepted)):
        if rows:
            lines += ["**%s**" % title, "", "| Found by | ID | Package | Version | Severity | Fixed in |",
                      "|---|---|---|---|---|---|"]
            lines += ["| %(scanner)s | %(id)s | %(package)s | %(version)s | %(severity)s | %(fixed_in)s |" % f
                      for f in rows]
            lines.append("")
    if findings:
        rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
        lines += ["**Every finding, worst first**", "",
                  "| Found by | ID | Package | Version | Severity | Fixed in | Gate |",
                  "|---|---|---|---|---|---|---|"]
        for f in sorted(findings, key=lambda f: (rank.get(f["severity"], len(rank)),
                                                 f["scanner"], str(f["id"]))):
            lines.append("| %s | %s | %s | %s | %s | %s | %s |" % (
                f["scanner"], f["id"], f["package"], f["version"], f["severity"], f["fixed_in"],
                _gate_reason(f, gated, excepted, fixed, latest)))
        lines.append("")
    if disagreements:
        lines += ["**Found by one scanner, missed by another that covers it**", "",
                  "The scanners use different data and find packages differently, so look at each: is the "
                  "package really there, at that version?", "",
                  "| ID | Package | Version | Found by | Missed by |", "|---|---|---|---|---|"]
        lines += ["| %s | %s | %s | %s | %s |" % (d["id"], d["package"], d["version"], ", ".join(d["found_by"]),
                                                  ", ".join(d["missed_by"])) for d in disagreements]
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
    p.add_argument("--warnings", metavar="OUT.log",
                   help="write a warning for each scanner without data for the image's OS, for tool_warnings.py")
    p.add_argument("--exit-code", type=int, default=0, metavar="N",
                   help="exit N when a review is needed (default 0: findings never fail)")
    p.add_argument("--latest-grype", metavar="G.json", help="the latest release's Grype results (a rescan)")
    p.add_argument("--latest-trivy", metavar="T.json", help="the latest release's Trivy results")
    p.add_argument("--latest", metavar="VERSION", help="the latest release's version, for the summary")
    a = p.parse_args(argv)
    given = [x is not None for x in (a.latest_grype, a.latest_trivy, a.latest)]
    if any(given) and not all(given):
        p.error("--latest-grype, --latest-trivy and --latest go together")
    docs = {}
    for name in ("grype", "trivy", "exceptions", "latest_grype", "latest_trivy"):
        if getattr(a, name) is None:
            continue
        with open(getattr(a, name)) as f:
            docs[name] = json.load(f)
    g, t = grype_findings(docs["grype"]), trivy_findings(docs["trivy"])
    covers = [coverage("grype", docs["grype"]), coverage("trivy", docs["trivy"])]
    found = merge(g + t)
    dis = disagreements(found, covers)
    uncovered = not any(c["os_packages"] for c in covers)
    valid, probs = load_exceptions(docs["exceptions"], a.today)
    gated, excepted = gate(found, valid)
    fixed: List[Dict[str, Any]] = []
    if a.latest:
        latest = merge(grype_findings(docs["latest_grype"]) + trivy_findings(docs["latest_trivy"]))
        gated, fixed = fixed_in_latest(gated, latest)
    review = bool(gated or probs or uncovered)
    text = summary(gated, excepted, probs, {"grype": len(g), "trivy": len(t)}, found,
                   coverage=covers, disagreements=dis, fixed=fixed, latest=a.latest or "")
    if a.warnings:
        with open(a.warnings, "w") as f:
            f.writelines("[0000]  WARN %s\n" % w for w in coverage_warnings(covers))     # Grype's log format
    if a.summary:
        with open(a.summary, "w") as f:
            f.write(text)
    else:
        print(text)
    if a.predicate:
        with open(a.predicate, "w") as f:
            json.dump({"scanned_on": a.today,
                       "scanners": {"grype": docs["grype"].get("descriptor", {}),
                                    "trivy": {"SchemaVersion": docs["trivy"].get("SchemaVersion")}},
                       "coverage": covers,
                       "gate": {"passed": not review, "review_needed": review,
                                "rule": "fixable High/Critical, a secret, or no scanner covering the "
                                        "operating system's packages: a security review",
                                "uncovered_os": uncovered,
                                "gated": gated, "excepted": excepted, "problems": probs,
                                "fixed_in_latest": fixed, "latest": a.latest},
                       "findings": {"grype": len(g), "trivy": len(t), "merged": len(found)},
                       "disagreements": dis}, f, indent=1)
    return a.exit_code if review else 0


if __name__ == "__main__":
    sys.exit(main())
