#!/usr/bin/env python3
"""The release's SBOMs as one page a person can read: wd2l-<version>-sbom.html
(docs/decisions/0009-sbom-content.md). It is made from each view's SPDX and CycloneDX SBOMs
(completed by packaging/container/sbom_enrich.py) and its vulnerability scans.

A view is one image (or system): wd2l's are one per platform. Each scan is a Grype or Trivy JSON
result, read by its shape and shown by the name given, so two builds of one scanner stay apart.
The page works offline and loads nothing: no external stylesheet, script, font or image, and a
Content-Security-Policy that forbids them. Without JavaScript it shows every view in turn, each
component expanding to its files; JavaScript adds tabs, a search box and a switch between the
components and every entry. The JSON SBOMs stay the authoritative record.

    sbom_report.py --version V --commit C --repo-url URL --out wd2l-V-sbom.html \\
        --view ID LABEL SPDX.json CDX.json [--view ...] [--scan ID NAME=SCAN.json ...]

With --commit and --repo-url, the page states the release's facts (the commit, the signed
SHA256SUMS, ADR-0009). Without them, --title (and --intro) describe some other system: the
briefing's comparison pages use this."""

import argparse
import html
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "container"))
import vuln_gate  # noqa: E402  (the findings, normalized as the review gate saw them)

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "UNKNOWN")
NONE = ("", "NOASSERTION", "NONE")


def esc(x: Any) -> str:
    return html.escape("" if x is None else str(x), quote=True)


bare_version = vuln_gate.bare_version        # scanners and Syft disagree on an RPM's epoch


def purl_of(pkg: Dict[str, Any]) -> str:
    return next((r["referenceLocator"] for r in pkg.get("externalRefs") or []
                 if r.get("referenceType") == "purl"), "")


def short_purl(purl: str) -> str:
    return purl.split("?")[0]


def org(s: str) -> str:
    return re.sub(r"^(Organization|Person|Tool): ", "", s or "")


def read_scan(name: str, doc: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """A scan's findings and what it covered, as the review gate sees them, credited to NAME."""
    kind = vuln_gate.scanner_of(doc)
    if kind is None:
        raise ValueError("%s: not a Grype or Trivy JSON result" % name)
    found = vuln_gate.grype_findings(doc) if kind == "grype" else vuln_gate.trivy_findings(doc)
    return [dict(f, scanner=name) for f in found], dict(vuln_gate.coverage(kind, doc), scanner=name)


def load_view(vid: str, label: str, spdx: Dict[str, Any], cdx: Dict[str, Any],
              scans: Sequence[Tuple[str, Dict[str, Any]]], names: Dict[str, str]) -> Dict[str, Any]:
    """One view: its SBOMs (names: the names they are released under) and its scans."""
    roots = {r["relatedSpdxElement"] for r in spdx.get("relationships") or []
             if r.get("spdxElementId") == "SPDXRef-DOCUMENT" and r.get("relationshipType") == "DESCRIBES"}
    files = {f["SPDXID"]: f for f in spdx.get("files") or []}
    every = {p["SPDXID"]: p for p in spdx.get("packages") or []}
    described = [p for p in every.values() if p["SPDXID"] in roots]
    # An image's SBOM describes the image, whose packages are its components. A package SBOM
    # (package_sbom.py, #190) describes the packages themselves; what they need from the host, or
    # were built with, are packages too, shown under each rather than counted as components.
    image = any(p.get("primaryPackagePurpose") == "CONTAINER" for p in described)
    pkgs = [p for p in every.values() if p["SPDXID"] not in roots] if image else described
    root = described[0] if image and described else {}
    owner: Dict[str, List[Dict[str, Any]]] = {p["SPDXID"]: [] for p in pkgs}
    links: Dict[str, Dict[str, List[str]]] = {p["SPDXID"]: {"needs": [], "depends": [], "built_with": []} for p in pkgs}

    def called(p: Dict[str, Any]) -> str:
        v = p.get("versionInfo")
        return "%s %s" % (p.get("name"), v) if v and v not in NONE else str(p.get("name"))

    owned = set()
    deps = 0
    for r in spdx.get("relationships") or []:
        t, a, b = r.get("relationshipType"), r.get("spdxElementId"), r.get("relatedSpdxElement")
        if t == "CONTAINS" and a in owner and b in files:
            owner[a].append(files[b])
            owned.add(b)
        elif t in ("DEPENDS_ON", "DEPENDENCY_OF"):
            deps += 1
            if t == "DEPENDS_ON" and a in links and b in every:
                links[a]["depends" if b in owner else "needs"].append(called(every[b]))
        elif t == "BUILD_DEPENDENCY_OF" and b in links and a in every:
            links[b]["built_with"].append(called(every[a]))

    read = [read_scan(name, doc) for name, doc in scans]
    by_pkg: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for m in vuln_gate.merge([f for found, _ in read for f in found]):
        by_pkg.setdefault((m["package"] or "", bare_version(m["version"])), []).append(m)

    comps = []
    for p in sorted(pkgs, key=lambda p: (p.get("name") or "").lower()):
        key = (p.get("name") or "", bare_version(p.get("versionInfo") or ""))
        lic = p.get("licenseDeclared") if p.get("licenseDeclared") not in NONE else p.get("licenseConcluded")
        comps.append({"name": p.get("name"), "version": p.get("versionInfo"), "supplier": org(p.get("supplier")),
                      "license": lic if lic not in NONE else "", "purl": purl_of(p),
                      "verification": (p.get("packageVerificationCode") or {}).get("packageVerificationCodeValue"),
                      "sha256": next((c["checksumValue"] for c in p.get("checksums") or []
                                      if c.get("algorithm") == "SHA256"), ""),
                      "files": sorted(owner[p["SPDXID"]], key=lambda f: f["fileName"]),
                      "file_name": p.get("packageFileName") or "",
                      **{k: sorted(v) for k, v in links[p["SPDXID"]].items()},
                      "findings": sorted(by_pkg.pop(key, []), key=lambda f: SEVERITIES.index(f["severity"])
                                         if f["severity"] in SEVERITIES else 9)})
    unmatched = [f for fs in by_pkg.values() for f in fs]
    os_comp = next((c for c in cdx.get("components") or [] if c.get("type") == "operating-system"), None)
    info = spdx.get("creationInfo") or {}
    sha = next((c["checksumValue"] for c in root.get("checksums") or [] if c.get("algorithm") == "SHA256"), "")
    return {
        "id": vid, "label": label, "assets": names, "scanners": [name for name, _ in scans], "is_image": image,
        "coverage": [c for _, c in read],
        "image": root.get("name"), "version": root.get("versionInfo"), "digest": sha,
        "created": info.get("created"), "creators": info.get("creators") or [], "comment": info.get("comment"),
        "lifecycles": [x.get("phase") for x in (cdx.get("metadata") or {}).get("lifecycles") or []],
        "os": os_comp, "components": comps, "unowned": sorted((f for i, f in files.items() if i not in owned),
                                                             key=lambda f: f["fileName"]),
        "file_count": len(files), "deps": deps, "unmatched": unmatched,
        "hashed_files": sum(1 for f in files.values() if any(c.get("algorithm") == "SHA256" for c in f.get("checksums") or [])),
        "shared_files": sum(len(c) for c in owner.values()) - len(owned),
        "findings": sorted((f for c in comps for f in c["findings"]), key=lambda f: (
            SEVERITIES.index(f["severity"]) if f["severity"] in SEVERITIES else 9, f["id"] or "")) + unmatched,
        "spdx_version": spdx.get("spdxVersion"), "cdx_version": cdx.get("specVersion"),
    }


def minimum_fields(p: Dict[str, Any]) -> List[Tuple[str, str, str]]:
    """(field, Yes/Partly/No, detail): the fields an SBOM is widely expected to carry."""
    comps, n = p["components"], len(p["components"])

    def rate(k: int, total: int) -> str:
        return "Yes" if k == total and total else ("Partly" if k else "No")

    sup = sum(1 for c in comps if c["supplier"] and c["supplier"] not in NONE)
    ver = sum(1 for c in comps if c["version"])
    ids = sum(1 for c in comps if c["purl"])
    lic = sum(1 for c in comps if c["license"])
    hashed, files_total = p["hashed_files"], p["file_count"]
    verified = sum(1 for c in comps if c["verification"])
    orgs = [org(c) for c in p["creators"] if c.startswith(("Organization: ", "Person: "))]
    tools = [org(c) for c in p["creators"] if c.startswith("Tool: ")]
    return [
        ("Supplier", rate(sup, n), "%d of %d components" % (sup, n)),
        ("Component name", rate(n, n), "every component"),
        ("Version", rate(ver, n), "%d of %d components" % (ver, n)),
        ("Unique identifier", rate(ids, n), "a package ID (purl) on %d of %d components" % (ids, n)),
        ("Dependency relationships", "Yes" if p["deps"] else "No",
         "%d between components, and each component's files" % p["deps"]),
        ("Author of the SBOM", "Yes" if orgs else "No", ", ".join(orgs) or "not stated"),
        ("Timestamp", "Yes" if p["created"] else "No", p["created"] or "not stated"),
        # A component's own hash: its SHA-256 (an RPM's header digest, a wheel's), or SPDX's
        # verification code over its files. Files' hashes alone are the files', not the component's.
        ("Component hash", rate(sum(1 for c in comps if c["sha256"] or c["verification"]), n),
         "a SHA-256 on %d of %d components, a verification code over their files on %d; a SHA-256 on %s of %s files"
         % (sum(1 for c in comps if c["sha256"]), n, verified, "{:,}".format(hashed), "{:,}".format(files_total))),
        ("License", rate(lic, n), "%d of %d components" % (lic, n)),
        ("Tool", "Yes" if tools else "No", ", ".join(tools) or "not stated"),
        ("Generation context", "Yes" if p["comment"] or p["lifecycles"] else "No",
         p["comment"] or ", ".join(p["lifecycles"]) or "not stated"),
    ]


def cve_link(i: str) -> str:
    if re.fullmatch(r"CVE-\d{4}-\d+", i or ""):
        return '<a href="https://www.cve.org/CVERecord?id=%s">%s</a>' % (esc(i), esc(i))
    return esc(i)


def badge(sev: str) -> str:
    return '<span class="sev sev-%s">%s</span>' % (esc(sev.lower()), esc(sev.title()))


def files_table(files: Sequence[Dict[str, Any]]) -> str:
    rows = "".join('<tr><td class="path">/%s</td><td class="hash">%s</td></tr>' % (
        esc(f["fileName"].lstrip("/")),
        esc(next((c["checksumValue"] for c in f.get("checksums") or [] if c.get("algorithm") == "SHA256"), "")))
        for f in files)
    return ('<table class="files"><thead><tr><th>File</th><th>SHA-256</th></tr></thead><tbody>%s</tbody></table>'
            % rows) if files else '<p class="muted">No files of its own.</p>'


def coverage_table(covers: Sequence[Dict[str, Any]]) -> str:
    """What each scan covered: a scanner without data for the image's operating system checked only
    its language packages (docs/decisions/0011-vulnerability-scanners.md)."""
    def yes(b: bool) -> str:
        return '<td class="ok-yes">Yes</td>' if b else '<td class="ok-no">No</td>'
    rows = "".join('<tr><td>%s</td><td>%s</td>%s%s<td>%s</td></tr>' % (
        esc(c["scanner"]), esc(c["os"] or "not recognized"), yes(c["os_packages"]), yes(c["language_packages"]),
        "Yes" if c["secrets"] else "No") for c in covers)
    return ('<table class="coverage"><thead><tr><th>Scanner</th><th>Operating system it recognized</th>'
            '<th>Has data for its packages</th><th>Language packages</th><th>Secrets</th></tr></thead>'
            '<tbody>%s</tbody></table>' % rows)


def view_html(p: Dict[str, Any], release: bool) -> str:
    comps, assets = p["components"], p["assets"]
    by_sup: Dict[str, int] = {}
    for c in comps:
        by_sup[c["supplier"] or "not stated"] = by_sup.get(c["supplier"] or "not stated", 0) + 1
    by_sev: Dict[str, int] = {}
    for f in p["findings"]:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    out = ['<section class="view" id="view-%s" data-view="%s" data-label="%s">' % (
               esc(p["id"]), esc(p["id"]), esc(p["label"])),
           '<h2>%s</h2>' % esc(p["label"]),
           '<dl class="facts">']
    if p["is_image"]:
        out += ['<dt>Image</dt><dd><code>%s:%s</code></dd>' % (esc(p["image"]), esc(p["version"])),
                '<dt>Digest</dt><dd><code class="wrap">sha256:%s</code></dd>' % esc(p["digest"]),
                '<dt>Operating system</dt><dd>%s</dd>' % (
                    esc("%s %s" % (p["os"].get("name"), p["os"].get("version")))
                    + (" (supplier: %s)" % esc((p["os"].get("supplier") or {}).get("name"))
                       if (p["os"].get("supplier") or {}).get("name") else "") if p["os"] else "not stated")]
    else:
        out.append('<dt>Packages</dt><dd>%s</dd>' % ", ".join(
            esc(c["file_name"] or c["name"]) for c in comps))
    out += ['<dt>SBOM made</dt><dd>%s, by %s</dd>' % (esc(p["created"]), esc(", ".join(org(c) for c in p["creators"]))),
           '<dt>The SBOM files</dt><dd><code>%s</code> (SPDX %s) and <code>%s</code> (CycloneDX %s)</dd>' % (
               esc(assets["spdx"]), esc((p["spdx_version"] or "").replace("SPDX-", "")), esc(assets["cdx"]), esc(p["cdx_version"])),
           '</dl>',
           '<div class="tiles">',
           '<div class="tile"><b>%d</b><span>components</span></div>' % len(comps),
           '<div class="tile"><b>%s</b><span>files, each with a SHA-256</span></div>' % "{:,}".format(p["file_count"]),
           '<div class="tile"><b>%d</b><span>files in no component</span></div>' % len(p["unowned"]),
           '<div class="tile"><b>%d</b><span>known vulnerabilities</span></div>' % len(p["findings"])
           if p["scanners"] else '<div class="tile"><b>&#8212;</b><span>not scanned for vulnerabilities</span></div>',
           '</div>',
           '<p class="suppliers">Suppliers: %s.%s</p>' % (
               ", ".join("%s (%d)" % (esc(k), n) for k, n in sorted(by_sup.items(), key=lambda kv: -kv[1])),
               " %d files belong to two components, and are listed under both." % p["shared_files"]
               if p["shared_files"] else ""),
           '<h3>The fields an SBOM is expected to carry</h3>',
           '<table class="check"><thead><tr><th>Field</th><th>Present</th><th>In this SBOM</th></tr></thead><tbody>']
    for field, ok, detail in minimum_fields(p):
        out.append('<tr><td>%s</td><td class="ok-%s">%s</td><td>%s</td></tr>' % (esc(field), esc(ok.lower()), esc(ok), esc(detail)))
    out += ['</tbody></table>', '<h3>Known vulnerabilities</h3>']
    if not p["scanners"]:
        out.append('<p>No scan results were given for this view.</p>')
    else:
        out.append('<p>From the scans with %s. A finding with no fix yet stays listed until its supplier '
                   'ships one%s.</p>' % (esc(", ".join(p["scanners"])),
                                         "; the rescan after release checks again every month" if release else ""))
        out.append(coverage_table(p["coverage"]))
        if not any(c["os_packages"] for c in p["coverage"]):
            out.append('<p><b>No scan covered the operating system\'s packages, so they weren\'t checked for known '
                       'vulnerabilities.</b></p>')
    if p["findings"]:
        out.append('<p class="suppliers">%s.</p>' % ", ".join("%d %s" % (by_sev[s], s.title()) for s in SEVERITIES if s in by_sev))
        out.append('<table class="vulns"><thead><tr><th>ID</th><th>Severity</th><th>Component</th><th>Version</th>'
                   '<th>Fixed in</th><th>Found by</th></tr></thead><tbody>')
        for f in p["findings"]:
            out.append('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' % (
                cve_link(f["id"]), badge(f["severity"]), esc(f["package"]), esc(f["version"]),
                esc(f["fixed_in"]) or '<span class="muted">no fix yet</span>', esc(", ".join(f["scanners"]))))
        out.append('</tbody></table>')
        if p["unmatched"]:
            out.append('<p class="muted">%d of them name a component this SBOM doesn\'t list by that name and version.</p>'
                       % len(p["unmatched"]))
    elif p["scanners"]:
        out.append('<p>None.</p>')
    out += ['<h3>Components</h3>',
            '<p>Each component expands to the files it installed, each with its SHA-256.</p>',
            '<div class="comps" role="list">',
            '<div class="row head" aria-hidden="true"><span>Component</span><span>Version</span><span>Supplier</span>'
            '<span>License</span><span>Package ID</span><span class="num">Files</span><span>Known vulnerabilities</span></div>']
    for c in comps:
        vulns = " ".join(badge(f["severity"]) for f in c["findings"]) or '<span class="muted">none</span>'
        search = " ".join(str(x) for x in (c["name"], c["version"], c["supplier"], c["license"], c["purl"]))
        out.append('<details class="comp" role="listitem" data-search="%s"><summary class="row">'
                   '<span class="name">%s</span><span>%s</span><span>%s</span><span>%s</span>'
                   '<span class="purl" title="%s">%s</span><span class="num">%d</span><span>%s</span></summary>%s</details>' % (
                       esc(search.lower()), esc(c["name"]), esc(c["version"]), esc(c["supplier"]), esc(c["license"]),
                       esc(c["purl"]), esc(short_purl(c["purl"])), len(c["files"]), vulns,
                       relations_html(c) + files_table(c["files"])))
    out.append('</div>')
    if p["unowned"]:
        out.append('<details class="comp unowned" data-search="in no component"><summary class="row">'
                   '<span class="name">In no component</span><span></span><span></span><span></span>'
                   '<span>Operating-system and package-manager state, such as the package database</span>'
                   '<span class="num">%d</span><span></span></summary>%s</details>' % (
                       len(p["unowned"]), files_table(p["unowned"])))
    out.append('</section>')
    return "\n".join(out)


def relations_html(c: Dict[str, Any]) -> str:
    """What a package needs from the host, depends on in this release, and was built with."""
    return "".join('<p class="rel"><b>%s:</b> %s</p>' % (title, esc(", ".join(c[k])))
                   for k, title in (("needs", "Needs from the host"), ("depends", "Depends on, in this release"),
                                    ("built_with", "Built with")) if c.get(k))


CSS = """
:root{--bg:#fff;--fg:#1b262c;--muted:#5e7378;--line:#d9e2e1;--card:#f2f6f5;--accent:#2a7f7a;--link:#1f6e69;
--crit:#9b1c1c;--high:#b4441f;--med:#8a6110;--low:#3d6b4f;--ok:#2a7f7a;--no:#b4441f}
@media (prefers-color-scheme:dark){:root{--bg:#141b1e;--fg:#e6eceb;--muted:#9fb1b4;--line:#2c393d;--card:#1c2629;
--accent:#7cc3bb;--link:#8fd3cb;--crit:#ff8a8a;--high:#ffab85;--med:#f2c879;--low:#9fd6b4;--ok:#7cc3bb;--no:#ffab85}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Calibri,Arial,sans-serif}
main{max-width:1200px;margin:0 auto;padding:24px 16px 64px}h1{font-size:28px;margin:0 0 4px}h2{font-size:22px;margin:32px 0 8px}
h3{font-size:17px;margin:28px 0 8px}a{color:var(--link)}code{font:13px/1.4 ui-monospace,Consolas,"Courier New",monospace}
.wrap{word-break:break-all}.muted{color:var(--muted)}.lede{font-size:16px;max-width:820px}
.intro{background:var(--card);border-radius:8px;padding:12px 16px;max-width:820px}.intro p{margin:6px 0}
.facts{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:8px 0 16px}.facts dt{color:var(--muted)}.facts dd{margin:0}
.tiles{display:flex;flex-wrap:wrap;gap:12px;margin:8px 0}.tile{background:var(--card);border-radius:8px;padding:10px 14px;min-width:150px}
.tile b{display:block;font-size:26px;color:var(--accent)}.tile span{color:var(--muted);font-size:13px}.suppliers{color:var(--muted)}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:13px;color:var(--muted);font-weight:600}.check td:first-child{font-weight:600}
.ok-yes{color:var(--ok);font-weight:600}.ok-partly{color:var(--med);font-weight:600}.ok-no{color:var(--no);font-weight:600}
.sev{display:inline-block;font-size:12px;font-weight:700;padding:0 6px;border-radius:4px;border:1px solid currentColor;margin:1px 2px 1px 0}
.sev-critical{color:var(--crit)}.sev-high{color:var(--high)}.sev-medium{color:var(--med)}.sev-low,.sev-negligible,.sev-unknown{color:var(--low)}
.row{display:grid;grid-template-columns:1.4fr 1.1fr 1fr 1fr 2fr 56px 1.2fr;gap:8px;padding:6px 8px;align-items:start}
.row.head{font-size:13px;color:var(--muted);font-weight:600;border-bottom:1px solid var(--line)}
.comp{border-bottom:1px solid var(--line)}.comp>summary{cursor:pointer;list-style:none}.comp>summary::-webkit-details-marker{display:none}
.comp>summary .name::before{content:"\\25B8  ";color:var(--muted)}.comp[open]>summary .name::before{content:"\\25BE  "}
.comp>summary:hover{background:var(--card)}.comp[open]>summary{background:var(--card)}.name{font-weight:600;word-break:break-word}
.purl{font:12px/1.4 ui-monospace,Consolas,"Courier New",monospace;word-break:break-all;color:var(--muted)}.num{text-align:right}
.rel{margin:6px 0 2px 24px}.files{margin:4px 0 12px 24px;width:calc(100% - 24px)}.files td{font:12px/1.4 ui-monospace,Consolas,"Courier New",monospace;padding:3px 8px}
.files .path{word-break:break-all}.files .hash{word-break:break-all;color:var(--muted);width:46%}
.controls{display:none;flex-wrap:wrap;gap:12px;align-items:center;position:sticky;top:0;background:var(--bg);padding:10px 0;
border-bottom:1px solid var(--line);z-index:1}.js .controls{display:flex}
.controls input[type=search]{font:inherit;padding:6px 10px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg);min-width:260px}
.controls button{font:inherit;padding:6px 12px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--fg);cursor:pointer}
.controls button[aria-pressed=true]{background:var(--accent);color:var(--bg);border-color:var(--accent)}
.js .view{display:none}.js .view.shown{display:block}.hidden{display:none!important}footer{margin-top:40px;color:var(--muted);font-size:13px}
@media (max-width:820px){.row{grid-template-columns:1fr 1fr}.row.head{display:none}.row>span:nth-child(n+3){font-size:13px}}
@media print{.controls{display:none!important}.js .view{display:block}.comp>summary .name::before{content:""}body{font-size:11px}
.view{break-before:page}}
"""

JS = """
document.documentElement.classList.add('js');
(function(){
  var views=[].slice.call(document.querySelectorAll('.view'));
  var tabs=document.getElementById('tabs'), q=document.getElementById('q'), all=document.getElementById('all'), count=document.getElementById('count');
  function show(v){views.forEach(function(p){p.classList.toggle('shown',p.dataset.view===v)});
    [].forEach.call(tabs.querySelectorAll('button'),function(b){b.setAttribute('aria-pressed',b.dataset.view===v)});filter()}
  views.forEach(function(p){var b=document.createElement('button');b.type='button';b.textContent=p.dataset.label;
    b.dataset.view=p.dataset.view;b.onclick=function(){show(p.dataset.view)};tabs.appendChild(b)});
  function filter(){var t=q.value.trim().toLowerCase(),n=0,shown=document.querySelector('.view.shown');if(!shown)return;
    [].forEach.call(shown.querySelectorAll('details.comp'),function(d){var hit=!t||d.dataset.search.indexOf(t)>=0,fileHit=false;
      [].forEach.call(d.querySelectorAll('.files tbody tr'),function(r){var m=!t||hit||r.firstChild.textContent.toLowerCase().indexOf(t)>=0;
        r.classList.toggle('hidden',!m);if(t&&m&&!hit)fileHit=true});
      var vis=hit||fileHit;d.classList.toggle('hidden',!vis);if(fileHit)d.open=true;if(vis&&!d.classList.contains('unowned'))n++});
    count.textContent=t?n+' matching':''}
  q.addEventListener('input',filter);
  all.onclick=function(){var open=all.getAttribute('aria-pressed')!=='true';all.setAttribute('aria-pressed',open);
    all.textContent=open?'Show components only':'Show every entry';
    [].forEach.call(document.querySelectorAll('details.comp'),function(d){d.open=open})};
  if(views.length)show(views[0].dataset.view);
})();
"""


def compare_html(views: Sequence[Dict[str, Any]]) -> str:
    """The views side by side: what each base brings (#192: the Hardened image beside UBI 9)."""
    rows = []
    for v in views:
        f = v["findings"]
        sev = [sum(1 for x in f if x["severity"] in s)
               for s in (("CRITICAL",), ("HIGH",), ("MEDIUM",), ("LOW", "NEGLIGIBLE", "UNKNOWN"))]
        vulns = ([len(f)] + sev + [sum(1 for x in f if x["fixed_in"])]) if v["scanners"] else ["&#8212;"] * 6
        rows.append("<tr><td>%s</td><td>%d</td><td>%s</td>%s</tr>" % (
            esc(v["label"]), len(v["components"]), "{:,}".format(v["file_count"]),
            "".join("<td>%s</td>" % x for x in vulns)))
    return ('<h2>Side by side</h2><table class="compare"><thead><tr><th>View</th><th>Components</th><th>Files</th>'
            '<th>Known vulnerabilities</th><th>Critical</th><th>High</th><th>Medium</th><th>Low and other</th>'
            '<th>With a fix</th></tr></thead><tbody>%s</tbody></table>' % "".join(rows))


def and_join(items: Sequence[str]) -> str:
    return items[0] if len(items) == 1 else "%s and %s" % (", ".join(items[:-1]), items[-1])


def page(views: Sequence[Dict[str, Any]], title: str, lede: str,
         release: Optional[Dict[str, str]] = None) -> str:
    """release: the version, commit and repo_url of the wd2l release the page is part of."""
    head = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; '
            'script-src \'unsafe-inline\'; img-src data:; base-uri \'none\'; form-action \'none\'">'
            '<title>%s</title><style>%s</style></head><body><main>' % (esc(title), CSS))
    intro = ['<h1>%s</h1>' % esc(title), '<p class="lede">%s</p>' % esc(lede),
             '<div class="intro">',
             '<p><b>What an SBOM is.</b> A software bill of materials lists every component inside one version of a '
             'product, and every file those components install. Scanners match its package IDs against vulnerability '
             'databases, and each file\'s SHA-256 proves exactly which bytes shipped.</p>']
    if release:
        repo_url = release["repo_url"]
        doc = "%s/blob/v%s/docs" % (repo_url.rstrip("/"), release["version"])
        intro += ['<p><b>Where this page comes from.</b> The release pipeline generates it from the SPDX and CycloneDX '
                  'SBOMs released alongside it, which stay the authoritative record. Like every release file, it is '
                  'listed in the release manifest and its checksum is in the signed <code>SHA256SUMS</code>.</p>',
                  '<p><b>Built from</b> commit <code>%s</code> of <a href="%s">%s</a>. How the SBOM is made: '
                  '<a href="%s/decisions/0009-sbom-content.md">ADR-0009</a>.</p>' % (
                      esc(release["commit"]), esc(repo_url), esc(repo_url.split("//")[-1]), esc(doc))]
    else:
        intro.append('<p><b>Where this page comes from.</b> It is generated from the SPDX and CycloneDX SBOMs named '
                     'in each view, which stay the authoritative record.</p>')
    intro.append('</div>')
    if len(views) > 1:
        intro.append(compare_html(views))
    intro += ['<div class="controls" role="toolbar" aria-label="View"><span id="tabs" role="group" aria-label="View"></span>'
              '<input id="q" type="search" placeholder="Search components and files" aria-label="Search components and files">'
              '<button id="all" type="button" aria-pressed="false">Show every entry</button>'
              '<span id="count" class="muted" aria-live="polite"></span></div>']
    body = [view_html(p, bool(release)) for p in views]
    scanners = list(dict.fromkeys(s for p in views for s in p["scanners"]))      # each once, in order
    foot = ('<footer>Generated by <code>packaging/release/sbom_report.py</code> from %s%s.</footer></main>'
            '<script>%s</script></body></html>\n' % (
                esc(", ".join(p["assets"]["spdx"] for p in views)),
                " and the scan results of %s" % esc(", ".join(scanners)) if scanners else "", JS))
    return head + "\n".join(intro + body) + foot


def load(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="SBOMs and their vulnerability scans as one readable page.")
    p.add_argument("--out", required=True)
    p.add_argument("--view", nargs=4, action="append", required=True, metavar=("ID", "LABEL", "SPDX", "CDX"))
    p.add_argument("--scan", nargs=2, action="append", default=[], metavar=("ID", "NAME=FILE"),
                   help="a Grype or Trivy JSON result for view ID, shown as found by NAME")
    p.add_argument("--title", help="default: wd2l VERSION: software bill of materials")
    p.add_argument("--intro", help="the sentence under the title")
    p.add_argument("--version")
    p.add_argument("--commit")
    p.add_argument("--repo-url")
    a = p.parse_args(argv)
    if not (a.title or a.version):
        p.error("--title is needed without --version")
    if bool(a.commit) != bool(a.repo_url) or (a.commit and not a.version):
        p.error("--commit and --repo-url go together, with --version")
    ids = [v[0] for v in a.view]
    if len(set(ids)) != len(ids):
        p.error("each --view needs its own ID")
    scans: Dict[str, List[Tuple[str, Dict[str, Any]]]] = {i: [] for i in ids}
    for vid, spec in a.scan:
        name, sep, path = spec.partition("=")
        if vid not in scans:
            p.error("--scan %s: no --view has that ID" % vid)
        if not (sep and name and path):
            p.error("--scan %s %s: give NAME=FILE" % (vid, spec))
        scans[vid].append((name, load(path)))
    views = []
    for vid, label, spdx, cdx in a.view:
        try:
            views.append(load_view(vid, label, load(spdx), load(cdx), scans[vid],
                                   {"spdx": os.path.basename(spdx), "cdx": os.path.basename(cdx)}))
        except ValueError as e:                 # a scan file that is neither Grype's nor Trivy's
            p.error(str(e))
    labels = and_join([v["label"] for v in views])
    title = a.title or "wd2l %s: software bill of materials" % a.version
    lede = a.intro or (
        "What is inside the wd2l %s container image, for %s: every component, who supplies it, its license and "
        "version, the files it installed, and what the release's vulnerability scans found." % (a.version, labels)
        if a.version else "Every component inside %s: who supplies it, its license and version, the files it "
                          "installed, and what the vulnerability scans found." % labels)
    release = {"version": a.version, "commit": a.commit, "repo_url": a.repo_url} if a.commit else None
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(page(views, title, lede, release))
    for v in views:
        print("sbom-report %s: %d components, %d files, %s" % (
            v["id"], len(v["components"]), v["file_count"],
            "%d known vulnerabilities" % len(v["findings"]) if v["scanners"] else "not scanned"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
