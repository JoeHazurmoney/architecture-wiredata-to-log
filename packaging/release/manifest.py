#!/usr/bin/env python3
"""The release manifest (docs/decisions/0008-release-manifest.md): what one release is, as JSON
validated against release-manifest.schema.json, and a markdown view of it, the customer's
version description. release.yml's assets job makes it, before SHA256SUMS, so the key's
signature, the SLSA provenance and the release attestation all cover it.

    manifest.py generate --assets DIR --base-record FILE [--image-digest sha256:...]
                         [--platform-digest ARCH=sha256:...] [--dry-run] > manifest.json
    manifest.py validate manifest.json
    manifest.py render manifest.json > manifest.md

generate reads git (full history and tags) and the forge's API (GitHub: GH_TOKEN, and the
GITHUB_* variables a workflow run has)."""

import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(REPO, "packaging", "ci"))
import versions  # noqa: E402  (sibling scripts, not packages)
import check_title  # noqa: E402

SCHEMA = os.path.join(HERE, "release-manifest.schema.json")
IMAGE = "ghcr.io/joehazurmoney/wd2l"
ATT = "https://github.com/JoeHazurmoney/architecture-wiredata-to-log/attestations"
# The workflows a release runs, for the build environment (tests/test_workflow_policy.py).
RELEASE_PATH = ("tests.yml", "image.yml", "rpm.yml", "publish.yml", "release.yml", "attest.yml")
# One category per issue, from its labels: the first match in this order.
CATEGORIES = ("security", "bug", "enhancement", "documentation", "dependencies", "release")
SECTIONS = (("enhancement", "Enhancements"), ("bug", "Fixes"), ("security", "Security"),
            ("documentation", "Documentation"), ("dependencies", "Dependencies"),
            ("release", "Release engineering"), ("other", "Other"))
CLOSES = re.compile(r"\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?):?\s+#(\d+)\b", re.I)
PR_SUFFIX = re.compile(r"\(#(\d+)\)\s*$")
PRE_RANK = {"a": 0, "b": 1, "rc": 2, None: 3}


# ---- versions and git ---------------------------------------------------------------------

def tag_key(tag: str) -> Optional[Tuple[int, int, int, int, int]]:
    """Sort key for a version tag (v0.3.0rc6 < v1.0.0rc1 < v1.0.0), None if it isn't one."""
    m = versions.SCHEME.match(tag[1:]) if tag.startswith("v") else None
    if not m:
        return None
    major, minor, patch, pre, n = m.groups()
    return int(major), int(minor), int(patch), PRE_RANK[pre], int(n or 0)


def is_final(tag: str) -> bool:
    k = tag_key(tag)
    return k is not None and k[3] == PRE_RANK[None]


def earliest(tags: Iterable[str]) -> Optional[str]:
    keyed = [(tag_key(t), t) for t in tags if tag_key(t)]
    return min(keyed)[1] if keyed else None


def git(*args: str, cwd: str = REPO) -> str:
    return subprocess.run(("git",) + args, cwd=cwd, check=True, capture_output=True,
                          text=True).stdout


def git_facts(current_tag: str, cwd: str = REPO) -> Dict[str, Any]:
    """HEAD, the previous release and tag, and each main-line commit since the previous final
    release (oldest first), with the earliest version tag that contains it."""
    head = git("rev-parse", "HEAD", cwd=cwd).strip()
    merged = [t for t in git("tag", "--merged", "HEAD", "--list", "v*", cwd=cwd).split()
              if tag_key(t) and t != current_tag]
    def ref(tag: Optional[str]) -> Optional[Dict[str, str]]:
        if not tag:
            return None
        return {"tag": tag, "commit": git("rev-list", "-n1", tag, cwd=cwd).strip()}
    prev_release = max((t for t in merged if is_final(t)), key=tag_key, default=None)
    prev_tag = max(merged, key=tag_key, default=None)
    rng = ["%s..HEAD" % prev_release] if prev_release else ["HEAD"]
    log = git("log", "--first-parent", "--reverse", "--format=%H%x1f%s%x1f%b%x1e", *rng, cwd=cwd)
    commits = []
    for rec in log.split("\x1e"):
        if not rec.strip():
            continue
        sha, subject, body = rec.strip("\n").split("\x1f", 2)
        containing = git("tag", "--contains", sha, "--list", "v*", cwd=cwd).split()
        commits.append({"sha": sha, "subject": subject, "body": body, "first_tag": earliest(containing)})
    return {"head": head, "head_date": iso(git("show", "-s", "--format=%cI", "HEAD", cwd=cwd).strip()),
            "previous_release": ref(prev_release), "previous_tag": ref(prev_tag), "commits": commits}


def iso(t: str) -> str:
    """Any ISO 8601 time as UTC, ending in Z."""
    d = datetime.datetime.fromisoformat(t.replace("Z", "+00:00"))
    return d.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def closes_in(text: str) -> List[int]:
    """Issue numbers a commit message closes (GitHub's keywords)."""
    return sorted({int(n) for n in CLOSES.findall(text or "")})


# ---- the forge ----------------------------------------------------------------------------

class GitHub:
    """The few GitHub API reads the manifest needs. Titles and labels come back as data: they
    are only ever JSON strings here, never shell, and render() escapes them."""

    def __init__(self, repo: str, token: str, api: str = "https://api.github.com",
                 graphql: str = "https://api.github.com/graphql"):
        self.owner, self.name = repo.split("/", 1)
        self.token, self.api, self.graphql_url = token, api.rstrip("/"), graphql

    def _call(self, url: str, body: Optional[bytes] = None) -> Any:
        req = urllib.request.Request(url, data=body, headers={
            "Authorization": "Bearer " + self.token, "Accept": "application/vnd.github+json",
            "User-Agent": "wd2l-release-manifest", "Content-Type": "application/json"})
        for attempt in range(4):
            try:
                with urllib.request.urlopen(req, timeout=60) as r:
                    return json.load(r)
            except urllib.error.HTTPError as e:
                if e.code < 500 or attempt == 3:
                    raise
            except urllib.error.URLError:
                if attempt == 3:
                    raise
            time.sleep(5 * (attempt + 1))
        raise RuntimeError("unreachable")

    def _graphql(self, fields: str, not_found_ok: bool = False) -> Dict[str, Any]:
        q = 'query { repository(owner: %s, name: %s) { %s } }' % (
            json.dumps(self.owner), json.dumps(self.name), fields)
        out = self._call(self.graphql_url, json.dumps({"query": q}).encode())
        errors = out.get("errors") or []
        if not_found_ok:      # a number that is neither an issue nor a pull request
            errors = [e for e in errors if e.get("type") != "NOT_FOUND"]
        if errors or not (out.get("data") or {}).get("repository"):
            raise RuntimeError("GitHub GraphQL: %s" % json.dumps(errors or out)[:500])
        return out["data"]["repository"]

    def pull_requests(self, commits: Sequence[Dict[str, Any]]) -> Dict[str, Optional[Dict[str, Any]]]:
        """For each commit, the merged pull request whose merge commit it is (or None)."""
        pr = ("number title url mergedAt mergeCommit { oid } "
              "closingIssuesReferences(first: 50) { nodes { number } }")
        out: Dict[str, Optional[Dict[str, Any]]] = {}
        for i in range(0, len(commits), 40):
            chunk = commits[i:i + 40]
            fields = " ".join('c%d: object(oid: "%s") { ... on Commit { associatedPullRequests'
                              '(first: 5) { nodes { %s } } } }' % (j, c["sha"], pr)
                              for j, c in enumerate(chunk))
            data = self._graphql(fields)
            for j, c in enumerate(chunk):
                nodes = ((data.get("c%d" % j) or {}).get("associatedPullRequests") or {}).get("nodes", [])
                match = [n for n in nodes if (n.get("mergeCommit") or {}).get("oid") == c["sha"]]
                out[c["sha"]] = _pr(match[0]) if match else None
        return out

    def issues(self, numbers: Iterable[int]) -> Dict[int, Dict[str, Any]]:
        """Issue details by number; pull request numbers and unknown numbers are left out."""
        nums = sorted(set(numbers))
        out: Dict[int, Dict[str, Any]] = {}
        for i in range(0, len(nums), 50):
            fields = " ".join("i%d: issueOrPullRequest(number: %d) { __typename ... on Issue { "
                              "number title url state stateReason labels(first: 20) { nodes "
                              "{ name } } } }" % (n, n) for n in nums[i:i + 50])
            data = self._graphql(fields, not_found_ok=True)
            for n in nums[i:i + 50]:
                node = data.get("i%d" % n)
                if node and node.get("__typename") == "Issue":
                    out[n] = _issue(node)
        return out

    def known_issues(self) -> List[Dict[str, Any]]:
        data = self._graphql('issues(states: OPEN, labels: ["bug"], first: 100, orderBy: '
                             '{field: CREATED_AT, direction: ASC}) { nodes { number title url '
                             'labels(first: 20) { nodes { name } } } }')
        return [{"number": n["number"], "title": n["title"], "url": n["url"],
                 "labels": [x["name"] for x in n["labels"]["nodes"]]} for n in data["issues"]["nodes"]]

    def approvals(self, run_id: str) -> List[Dict[str, str]]:
        rows = self._call("%s/repos/%s/%s/actions/runs/%s/approvals" % (self.api, self.owner, self.name, run_id))
        return [{"environment": e["name"], "user": a["user"]["login"], "state": a["state"],
                 "comment": a.get("comment") or ""} for a in rows for e in a.get("environments", [])]


def _pr(n: Dict[str, Any]) -> Dict[str, Any]:
    return {"number": n["number"], "title": n["title"], "url": n["url"], "merged_at": iso(n["mergedAt"]),
            "closes": [x["number"] for x in n["closingIssuesReferences"]["nodes"]]}


def _issue(n: Dict[str, Any]) -> Dict[str, Any]:
    return {"number": n["number"], "title": n["title"], "url": n["url"], "state": n["state"],
            "state_reason": n.get("stateReason"), "labels": [x["name"] for x in n["labels"]["nodes"]]}


# ---- building the manifest ----------------------------------------------------------------

def category(labels: Sequence[str]) -> str:
    return next((c for c in CATEGORIES if c in labels), "other")


def commit_type(title: str) -> Optional[str]:
    return title.split(":", 1)[0].split("(", 1)[0].rstrip("!") if check_title.check(title) is None else None


def changes(commits: Sequence[Dict[str, Any]], forge: Any) -> Dict[str, Any]:
    """Pull requests, direct commits, and the issues they resolve: the union of `Closes #N` in
    the commit message (git) and the links the forge records (which also covers links added to
    a pull request's description after it merged)."""
    prs_by_sha = forge.pull_requests(commits)
    prs, direct = [], []
    for c in commits:
        p = prs_by_sha.get(c["sha"])
        if p is None:
            direct.append({"commit": c["sha"], "subject": c["subject"], "first_tag": c["first_tag"]})
            continue
        prs.append({"number": p["number"], "title": p["title"], "url": p["url"],
                    "merged_at": p["merged_at"], "commit": c["sha"], "type": commit_type(p["title"]),
                    "first_tag": c["first_tag"],
                    "closes": sorted(set(p["closes"]) | set(closes_in(c["body"])))})
    found = forge.issues(n for p in prs for n in p["closes"])
    for p in prs:
        p["closes"] = [n for n in p["closes"] if n in found]      # drop numbers that aren't issues
    resolved = []
    for n, i in sorted(found.items()):
        if i["state"] != "CLOSED" or i["state_reason"] != "COMPLETED":
            continue
        by = [p for p in prs if n in p["closes"]]
        resolved.append({"number": n, "title": i["title"], "url": i["url"],
                         "category": category(i["labels"]), "labels": i["labels"],
                         "retroactive": "retroactive" in i["labels"],
                         "resolved_by": [p["number"] for p in by],
                         "resolved_at": min(p["merged_at"] for p in by),
                         "first_tag": earliest(p["first_tag"] for p in by if p["first_tag"])})
    return {"pull_requests": prs, "direct_commits": direct, "issues_resolved": resolved,
            "pull_requests_without_issue": [p["number"] for p in prs if not p["closes"]]}


KINDS = ((r"\.rpm$", "rpm"), (r"\.whl$", "wheel"), (r"\.tar\.gz$", "sdist"), (r"-oci\.tar$", "oci-image"),
         (r"\.(spdx|cdx)\.json$", "sbom"), (r"vuln-summary", "vulnerability-summary"),
         (r"provenance\.json$", "provenance"), (r"^base-image-record\.json$", "base-image-record"),
         (r"^cosign\.pub$", "public-key"), (r"\.bundle$", "source-bundle"),
         (r"changelog\.md$", "changelog"), (r"verify-release\.py$", "verification-script"))


def kind(name: str) -> str:
    return next((k for pat, k in KINDS if re.search(pat, name)), "other")


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def deliverables(directory: str) -> List[Dict[str, Any]]:
    out = []
    for name in sorted(os.listdir(directory)):
        path = os.path.join(directory, name)
        if os.path.isfile(path):
            out.append({"name": name, "kind": kind(name), "size": os.path.getsize(path),
                        "sha256": sha256_file(path)})
    return out


def build_environment(repo: str = REPO) -> Dict[str, Any]:
    """The pins a release ran with, read from the commit: actions by SHA, tool images by
    digest, and the runner labels."""
    actions, runners = {}, set()
    for name in RELEASE_PATH:
        with open(os.path.join(repo, ".github", "workflows", name), encoding="utf-8") as f:
            text = f.read()
        for a, sha, v in re.findall(r"uses:\s*([\w.-]+/[\w./-]+)@([0-9a-f]{40})\s*#\s*(\S+)", text):
            actions[(a, sha)] = v
        runners.update(r for r in re.findall(r"runs-on:\s*([\w.-]+)\s*$", text, re.M))
        runners.update(re.findall(r"runner:\s*([\w.-]+)", text))
    with open(os.path.join(repo, "packaging", "ci", "tools.Containerfile"), encoding="utf-8") as f:
        tools = re.findall(r"^FROM\s+(\S+)\s+AS\s+(\S+)\s*$", f.read(), re.M | re.I)
    return {"actions": [{"action": a, "commit": sha, "version": v} for (a, sha), v in sorted(actions.items())],
            "tool_images": [{"name": n, "ref": r} for r, n in tools],
            "runners": sorted(runners)}


def base_images(record: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [{"stage": b.get("stage"), "ref": b["ref"], "index_digest": b["index_digest"],
             "platforms": b.get("platforms", {}), "release": b.get("release"),
             "source_image": b.get("source_image")} for b in record.get("images", [])]


def summary(version: str, repo: str = REPO) -> Optional[Dict[str, str]]:
    rel = "docs/releases/%s.md" % version
    path = os.path.join(repo, rel)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        text = f.read()
    return {"file": rel, "sha256": hashlib.sha256(text.encode()).hexdigest(), "text": text}


def generate(a: argparse.Namespace, env: Dict[str, str], forge: Any, repo: str = REPO,
             now: Optional[datetime.datetime] = None) -> Dict[str, Any]:
    names = versions.names(versions.read_version(os.path.join(repo, "wd2l", "__init__.py")))
    v, tag = names["pep440"], names["tag"]
    facts = git_facts(tag, cwd=repo)
    summ = summary(v, repo)
    if summ is None and not a.dry_run:
        raise SystemExit("docs/releases/%s.md is missing: a release needs its summary" % v)
    server = env.get("GITHUB_SERVER_URL", "https://github.com")
    slug = env.get("GITHUB_REPOSITORY", "JoeHazurmoney/architecture-wiredata-to-log")
    run = None
    if env.get("GITHUB_RUN_ID"):
        run = {"id": env["GITHUB_RUN_ID"], "attempt": int(env.get("GITHUB_RUN_ATTEMPT", "1")),
               "url": "%s/%s/actions/runs/%s" % (server, slug, env["GITHUB_RUN_ID"]),
               "workflow_ref": env.get("GITHUB_WORKFLOW_REF", "")}
    platforms = dict(x.split("=", 1) for x in a.platform_digest if x.split("=", 1)[1])
    with open(a.base_record) as f:
        record = json.load(f)
    with open(os.path.join(repo, "cosign.pub"), "rb") as f:
        key_sha = hashlib.sha256(f.read()).hexdigest()
    now = now or datetime.datetime.now(datetime.timezone.utc)
    return {
        "schema_version": 1,
        "release": {"product": "wd2l", "version": v, "tag": tag, "prerelease": names["prerelease"],
                    "dry_run": bool(a.dry_run)},
        "source": {"repository": "%s/%s" % (server, slug), "commit": facts["head"],
                   "commit_date": facts["head_date"], "previous_release": facts["previous_release"],
                   "previous_tag": facts["previous_tag"]},
        "generated": {"at": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "by": "packaging/release/manifest.py",
                      "run": run},
        "summary": summ,
        "changes": dict(since=(facts["previous_release"] or {}).get("tag"),
                        **changes(facts["commits"], forge)),
        "known_issues": forge.known_issues(),
        "deliverables": deliverables(a.assets),
        "image": ({"name": IMAGE, "tags": names["image_tags"], "index_digest": a.image_digest,
                   "platforms": platforms} if a.image_digest else None),
        "base_images": base_images(record),
        "build_environment": build_environment(repo),
        "changelog": None,
        "approvals": forge.approvals(run["id"]) if run and not a.dry_run else [],
        "verification": {
            "public_key_sha256": key_sha,
            "signer_workflow": "%s/.github/workflows/attest.yml" % slug,
            "sealed_by": ["SHA256SUMS", "SHA256SUMS.sigstore.json", "wd2l-%s-attestations.jsonl" % v],
            "attestations": [
                {"predicate_type": "https://slsa.dev/provenance/v1", "signed_by": "attest.yml (GitHub, keyless)",
                 "covers": "every file in SHA256SUMS, the image index and each platform image"},
                {"predicate_type": "https://slsa.dev/provenance/v1", "signed_by": "the release key",
                 "covers": "the image index and each platform image (wd2l-%s-provenance.json)" % v},
                {"predicate_type": "%s/base-image-record/v2" % ATT, "signed_by": "the release key",
                 "covers": "the image index and each platform image"},
                {"predicate_type": "https://spdx.dev/Document", "signed_by": "the release key",
                 "covers": "each platform image (its SBOM)"},
                {"predicate_type": "%s/vuln-scan/v1" % ATT, "signed_by": "the release key",
                 "covers": "each platform image (its scan results)"},
            ]},
    }


# ---- validating and rendering -------------------------------------------------------------

def validate(doc: Dict[str, Any], schema_path: str = SCHEMA) -> Optional[str]:
    """None if the manifest matches the schema, else the first error."""
    import fastjsonschema    # packaging/release/requirements.txt
    with open(schema_path) as f:
        check = fastjsonschema.compile(json.load(f))
    try:
        check(doc)
    except fastjsonschema.JsonSchemaException as e:
        return str(e.message)
    return None


def esc(text: Any) -> str:
    """Forge text (titles, labels) for a markdown table cell: no HTML, no cell breaks."""
    return (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace("|", "\\|").replace("\r", " ").replace("\n", " "))


def _size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return ("%d %s" % (n, unit)) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024.0
    return str(n)


def render(m: Dict[str, Any]) -> str:
    r, s, ch = m["release"], m["source"], m["changes"]
    repo = s["repository"]
    out = ["# wd2l %s: release manifest" % r["version"], ""]
    if r["dry_run"]:
        out += ["> **Dry run.** Built without a version tag: nothing was published or signed.", ""]
    elif r["prerelease"]:
        out += ["> **Pre-release**, for testing.", ""]
    run = m["generated"]["run"]
    out += ["The version description of **wd2l %s** (tag `%s`), built from commit [`%s`](%s/commit/%s) "
            "of %s. Generated %s by `%s`%s." % (
                r["version"], r["tag"], s["commit"], repo, s["commit"], s["commit_date"][:10],
                m["generated"]["at"], m["generated"]["by"],
                " in [run %s](%s)" % (run["id"], run["url"]) if run else ""),
            "",
            "`wd2l-%s-release-manifest.json` is the authoritative record; this page is generated "
            "from it (schema version %d)." % (r["version"], m["schema_version"]), ""]
    if m["summary"]:
        out += ["## Summary", "", m["summary"]["text"].strip(), ""]

    since = ch["since"]
    issues = ch["issues_resolved"]
    out += ["## Issues resolved (%d)" % len(issues), "",
            ("Since %s." % since) if since else "Since the first commit: there is no earlier final release.", ""]
    for cat, heading in SECTIONS:
        rows = [i for i in issues if i["category"] == cat]
        if not rows:
            continue
        out += ["### %s" % heading, "", "| Issue | Title | Resolved by | Merged | First released in |",
                "|---|---|---|---|---|"]
        for i in rows:
            by = ", ".join("[#%d](%s/pull/%d)" % (n, repo, n) for n in i["resolved_by"])
            out.append("| [#%d](%s)%s | %s | %s | %s | %s |" % (
                i["number"], i["url"], " \u2020" if i["retroactive"] else "", esc(i["title"]), by,
                i["resolved_at"][:10], "`%s`" % i["first_tag"] if i["first_tag"] else "this release"))
        out.append("")
    if any(i["retroactive"] for i in issues):
        out += ["\u2020 Recorded after its work had merged, to complete the record; dated by its "
                "pull request's merge.", ""]
    if ch["pull_requests_without_issue"]:
        by_num = {p["number"]: p for p in ch["pull_requests"]}
        out += ["## Pull requests without an issue (%d)" % len(ch["pull_requests_without_issue"]), "",
                "| Pull request | Title | Merged |", "|---|---|---|"]
        for n in ch["pull_requests_without_issue"]:
            p = by_num[n]
            out.append("| [#%d](%s) | %s | %s |" % (n, p["url"], esc(p["title"]), p["merged_at"][:10]))
        out.append("")
    out += ["## Known issues", ""]
    if m["known_issues"]:
        out += ["| Issue | Title |", "|---|---|"]
        out += ["| [#%d](%s) | %s |" % (k["number"], k["url"], esc(k["title"])) for k in m["known_issues"]]
    else:
        out.append("No open bugs when this manifest was made.")
    out.append("")

    out += ["## Deliverables", "", "| File | Kind | Size | SHA-256 |", "|---|---|---|---|"]
    out += ["| `%s` | %s | %s | `%s` |" % (d["name"], d["kind"], _size(d["size"]), d["sha256"])
            for d in m["deliverables"]]
    out += ["", "Made after this manifest, and covering it: %s." % ", ".join(
        "`%s`" % x for x in m["verification"]["sealed_by"]), ""]

    img = m["image"]
    out += ["## Container image", ""]
    if img:
        out += ["`%s@%s`, tagged %s." % (img["name"], img["index_digest"],
                                         ", ".join("`%s`" % t for t in img["tags"])), "",
                "| Platform | Digest |", "|---|---|"]
        out += ["| linux/%s | `%s` |" % (p, d) for p, d in sorted(img["platforms"].items())]
    else:
        out.append("Not published (dry run).")
    out += ["", "| Stage | Base image | Source (SRPMs) |", "|---|---|---|"]
    out += ["| %s | `%s` | `%s` |" % (b["stage"], b["ref"], b["source_image"]) for b in m["base_images"]]
    out.append("")

    out += ["## Changes (%d pull requests)" % len(ch["pull_requests"]), "",
            "| Pull request | Title | Merged | Closes | First released in |", "|---|---|---|---|---|"]
    for p in ch["pull_requests"]:
        closes = ", ".join("#%d" % n for n in p["closes"]) or "\u2014"
        out.append("| [#%d](%s) | %s | %s | %s | %s |" % (
            p["number"], p["url"], esc(p["title"]), p["merged_at"][:10], closes,
            "`%s`" % p["first_tag"] if p["first_tag"] else "this release"))
    for d in ch["direct_commits"]:
        out.append("| `%s` | %s | | \u2014 | %s |" % (d["commit"][:7], esc(d["subject"]),
                                                      "`%s`" % d["first_tag"] if d["first_tag"] else "this release"))
    out.append("")
    if m["changelog"]:
        out += ["The changelog, grouped by commit type, is `%s`." % m["changelog"]["file"], ""]

    env = m["build_environment"]
    out += ["## Build environment", "",
            "Pinned at the commit. Runners: %s." % ", ".join("`%s`" % x for x in env["runners"]), "",
            "| Action | Commit | Version |", "|---|---|---|"]
    out += ["| `%s` | `%s` | %s |" % (x["action"], x["commit"], x["version"]) for x in env["actions"]]
    out += ["", "| Tool | Image |", "|---|---|"]
    out += ["| %s | `%s` |" % (x["name"], x["ref"]) for x in env["tool_images"]]
    out.append("")

    out += ["## Approvals", ""]
    if m["approvals"]:
        out += ["| Environment | Approved by | State | Comment |", "|---|---|---|---|"]
        out += ["| %s | %s | %s | %s |" % (esc(x["environment"]), esc(x["user"]), esc(x["state"]),
                                           esc(x["comment"])) for x in m["approvals"]]
        out += ["", "The `release` gate, approved after this manifest was made, approves signing it."]
    else:
        out.append("None recorded (a dry run has no approval gates).")
    out.append("")

    ver = m["verification"]
    v = r["version"]
    out += ["## Verifying this release", "",
            "Offline, with a `cosign.pub` obtained from a trusted channel (SHA-256 `%s`):" % ver["public_key_sha256"],
            "", "```bash",
            "cosign verify-blob --key cosign.pub --insecure-ignore-tlog --bundle SHA256SUMS.sigstore.json SHA256SUMS",
            "sha256sum -c SHA256SUMS      # this manifest is one of the files it lists",
            "```", "",
            "With the GitHub CLI (`--bundle wd2l-%s-attestations.jsonl` works offline):" % v, "",
            "```bash",
            "gh attestation verify wd2l-%s-release-manifest.json --repo %s --signer-workflow %s"
            % (v, repo.split("github.com/", 1)[-1], ver["signer_workflow"]),
            "gh release verify %s" % r["tag"],
            "```", "",
            "| Attestation | Signed by | Covers |", "|---|---|---|"]
    out += ["| `%s` | %s | %s |" % (x["predicate_type"], x["signed_by"], x["covers"]) for x in ver["attestations"]]
    return "\n".join(out) + "\n"


# ---- command line -------------------------------------------------------------------------

def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="The release manifest: generate, validate, render.")
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate", help="make the manifest (JSON on stdout)")
    g.add_argument("--assets", required=True, help="the directory of release files it lists")
    g.add_argument("--base-record", required=True)
    g.add_argument("--image-digest", default="")
    g.add_argument("--platform-digest", action="append", default=[], metavar="ARCH=DIGEST")
    g.add_argument("--dry-run", action="store_true", help="no version tag: nothing published")
    val = sub.add_parser("validate", help="check a manifest against the schema")
    val.add_argument("manifest")
    ren = sub.add_parser("render", help="the markdown view (on stdout)")
    ren.add_argument("manifest")
    a = p.parse_args(argv)
    if a.cmd == "generate":
        env = dict(os.environ)
        forge = GitHub(env.get("GITHUB_REPOSITORY", "JoeHazurmoney/architecture-wiredata-to-log"),
                       env.get("GH_TOKEN") or env.get("GITHUB_TOKEN") or "",
                       env.get("GITHUB_API_URL", "https://api.github.com"),
                       env.get("GITHUB_GRAPHQL_URL", "https://api.github.com/graphql"))
        json.dump(generate(a, env, forge), sys.stdout, indent=1, sort_keys=False)
        sys.stdout.write("\n")
        return 0
    with open(a.manifest) as f:
        doc = json.load(f)
    if a.cmd == "validate":
        err = validate(doc)
        if err:
            print("manifest %s is invalid: %s" % (a.manifest, err), file=sys.stderr)
            return 1
        print("manifest %s: valid" % a.manifest)
        return 0
    sys.stdout.write(render(doc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
