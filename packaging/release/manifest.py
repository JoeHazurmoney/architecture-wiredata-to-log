#!/usr/bin/env python3
"""The release manifest (docs/decisions/0008-release-manifest.md): what one release is, as JSON
validated against release-manifest.schema.json, and its readable view, the customer's
version description, as markdown and as an offline HTML page (#202). release.yml's assets job
makes it, before SHA256SUMS, so the key's signature, the SLSA provenance and the release
attestation all cover it.

    manifest.py generate --assets DIR --base-record FILE [--image-digest sha256:...]
                         [--platform-digest ARCH=sha256:...] [--comparison-digest sha256:...
                          --comparison-base-record FILE] [--dry-run] > manifest.json
    manifest.py validate manifest.json
    manifest.py render manifest.json > manifest.md
    manifest.py render --format html manifest.json > manifest.html

generate reads git (full history and tags, and the diff from the previous final release for the
lines changed) and the forge's API (GitHub: GH_TOKEN, and the GITHUB_* variables a workflow run
has)."""

import argparse
import datetime
import hashlib
import html
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
UBI9_IMAGE = "ghcr.io/joehazurmoney/wd2l-ubi9"        # the comparison image, amd64 only (#192)
COMPARISON_PURPOSE = ("For comparison only: the same wd2l on UBI 9, to show what the base changes. It is "
                      "not hardened, not FIPS. Deploy %s (docs/decisions/0004-container-base-image.md)." % IMAGE)
ATT ="https://github.com/JoeHazurmoney/architecture-wiredata-to-log/attestations"
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


def earlier_tags(current_tag: str, cwd: str = REPO) -> List[str]:
    """The version tags reachable from HEAD, other than this release's own."""
    return [t for t in git("tag", "--merged", "HEAD", "--list", "v*", cwd=cwd).split()
            if tag_key(t) and t != current_tag]


def previous_release(current_tag: str, cwd: str = REPO) -> Optional[str]:
    """The previous final (not pre-) release: where the changes start."""
    return max((t for t in earlier_tags(current_tag, cwd) if is_final(t)), key=tag_key, default=None)


def git_facts(current_tag: str, cwd: str = REPO) -> Dict[str, Any]:
    """HEAD, the previous release and tag, and each main-line commit since the previous final
    release (oldest first), with the earliest version tag that contains it."""
    head = git("rev-parse", "HEAD", cwd=cwd).strip()
    merged = earlier_tags(current_tag, cwd)
    def ref(tag: Optional[str]) -> Optional[Dict[str, str]]:
        if not tag:
            return None
        return {"tag": tag, "commit": git("rev-list", "-n1", tag, cwd=cwd).strip()}
    prev_release = previous_release(current_tag, cwd)
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


DIFF_METHOD = "git diff -M -U0; per hunk, modified = min(lines added, lines removed)"
# Every option that changes the output is given, so no git config can change the count (#224).
DIFF_ARGS = ("-c", "core.quotePath=false", "diff", "-M", "--no-color", "--no-ext-diff",
             "--no-textconv", "--src-prefix=a/", "--dst-prefix=b/")


BUILD_FILES = ("Containerfile", "Dockerfile")


def file_type(path: str) -> str:
    """The lower-case extension, or the file's name when it has none (LICENSE, .gitignore). A
    container build file is one type whatever its variant: Containerfile.ubi9 and
    tools.Containerfile are both Containerfile (#226)."""
    name = path.rsplit("/", 1)[-1]
    parts = name.lower().split(".")
    for b in BUILD_FILES:
        if b.lower() in parts:
            return b
    ext = os.path.splitext(name)[1].lower()
    return ext or name


def diff_stats(base: Dict[str, str], head: str, repository: str, cwd: str = REPO) -> Dict[str, Any]:
    """Lines added, modified and deleted from the previous release to this commit: a plain count
    of lines, not SLOC (#224). In each hunk, the lines both removed and added are modified; the
    rest are added or deleted. So added + modified is git's insertions, and modified + deleted
    its deletions. Binary files count as files, with no lines."""
    def run(*args: str) -> str:          # bytes, decoded leniently: git() would fail on non-UTF-8 text
        return subprocess.run(("git",) + DIFF_ARGS + args + (base["commit"], head), cwd=cwd, check=True,
                              capture_output=True).stdout.decode("utf-8", "replace")
    # The paths from --numstat -z (any name, unquoted); the hunks from the patch, file by file in
    # the same order.
    fields, files = run("--numstat", "-z").split("\0"), []
    while len(fields) > 1:
        plus, minus, path = fields.pop(0).split("\t", 2)
        if not path:                      # a rename: the old path, then the new one
            path = fields[1]
            del fields[:2]
        files.append((path, plus, minus))
    patch = run("-U0")                   # -U0 implies --patch, so it can't share the --numstat call
    blocks = re.split(r"^diff --git ", patch, flags=re.M)[1:]
    if len(blocks) != len(files):
        raise RuntimeError("git diff: %d files in the patch, %d in --numstat" % (len(blocks), len(files)))
    types: Dict[str, Dict[str, int]] = {}
    binary = 0
    for (path, plus, minus), block in zip(files, blocks):
        t = types.setdefault(file_type(path), {"files": 0, "added": 0, "modified": 0, "deleted": 0})
        t["files"] += 1
        if plus == "-":
            binary += 1
            continue
        hunks: List[List[int]] = []        # [lines added, lines removed] per hunk
        for line in block.split("\n")[1:]:
            if line.startswith("@@"):
                hunks.append([0, 0])
            elif hunks and line.startswith("+"):
                hunks[-1][0] += 1
            elif hunks and line.startswith("-"):
                hunks[-1][1] += 1
        for p, mi in hunks:
            mod = min(p, mi)
            t["added"] += p - mod
            t["modified"] += mod
            t["deleted"] += mi - mod
        if (sum(h[0] for h in hunks), sum(h[1] for h in hunks)) != (int(plus), int(minus)):
            raise RuntimeError("git diff: %s's hunks don't match --numstat" % path)
    by_type = sorted(({"type": k, **v} for k, v in types.items()),
                     key=lambda x: (-(x["added"] + x["modified"] + x["deleted"]), x["type"]))
    return {"base": base, "head": head,
            "compare_url": "%s/compare/%s...%s" % (repository, base["commit"], head),
            "method": DIFF_METHOD, "files_changed": len(files), "binary_files": binary,
            "lines": {k: sum(x[k] for x in by_type) for k in ("added", "modified", "deleted")},
            "by_type": by_type}


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


KINDS = ((r"-sbom\.html$", "sbom-report"), (r"\.rpm$", "rpm"), (r"\.whl$", "wheel"), (r"\.tar\.gz$", "sdist"), (r"-oci\.tar$", "oci-image"),
         (r"\.(spdx|cdx)\.json$", "sbom"), (r"vuln-summary", "vulnerability-summary"),
         (r"provenance(-ubi9)?\.json$", "provenance"), (r"^base-image-record(-ubi9)?\.json$", "base-image-record"),
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


def changelog_record(path: str, repo: str = REPO) -> Dict[str, Any]:
    """The changelog file, and what made it: git-cliff's pinned image and cliff.toml."""
    with open(os.path.join(repo, "packaging", "ci", "tools.Containerfile"), encoding="utf-8") as f:
        refs = {n: r for r, n in re.findall(r"^FROM\s+(\S+)\s+AS\s+(\S+)\s*$", f.read(), re.M | re.I)}
    ref = refs["git-cliff"]
    return {"file": os.path.basename(path), "sha256": sha256_file(path),
            "tool": {"name": "git-cliff", "version": ref.split("@", 1)[0].rsplit(":", 1)[1], "image": ref},
            "config_sha256": sha256_file(os.path.join(repo, "cliff.toml"))}


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
    changelog = getattr(a, "changelog", None)
    approvals = forge.approvals(run["id"]) if run and not a.dry_run else []
    if not a.dry_run:
        # A tag: publish ran and the release gate was approved. Anything missing from them here
        # would make a valid manifest saying the image wasn't published (#161).
        missing = ([] if a.image_digest else ["the image index digest"]) + [
            "the %s image digest" % arch for arch in ("amd64", "arm64") if arch not in platforms] + (
            [] if getattr(a, "comparison_digest", "") else ["the comparison image digest"]) + (
            [] if changelog else ["the changelog"]) + (
            [] if any(x["environment"] == "release" and x["state"] == "approved" for x in approvals)
            else ["an approval of the release gate"])
        if missing:
            raise SystemExit("a release's manifest needs %s" % ", ".join(missing))
    with open(a.base_record) as f:
        record = json.load(f)
    comparison = None
    if getattr(a, "comparison_digest", ""):
        with open(a.comparison_base_record) as f:
            comparison = {"name": UBI9_IMAGE, "tags": names["image_tags"], "digest": a.comparison_digest,
                          "platform": "linux/amd64", "base_images": base_images(json.load(f)),
                          "purpose": COMPARISON_PURPOSE}
    with open(os.path.join(repo, "cosign.pub"), "rb") as f:
        key_sha = hashlib.sha256(f.read()).hexdigest()
    now = now or datetime.datetime.now(datetime.timezone.utc)
    repository = "%s/%s" % (server, slug)
    prev = facts["previous_release"]
    return {
        "schema_version": 1,
        "release": {"product": "wd2l", "version": v, "tag": tag, "prerelease": names["prerelease"],
                    "dry_run": bool(a.dry_run)},
        "source": {"repository": repository, "commit": facts["head"],
                   "commit_date": facts["head_date"], "previous_release": facts["previous_release"],
                   "previous_tag": facts["previous_tag"]},
        "generated": {"at": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "by": "packaging/release/manifest.py",
                      "run": run},
        "summary": summ,
        "changes": dict(since=(prev or {}).get("tag"), **changes(facts["commits"], forge),
                        diff=diff_stats(prev, facts["head"], repository, cwd=repo) if prev else None),
        "known_issues": forge.known_issues(),
        "deliverables": deliverables(a.assets),
        "image": ({"name": IMAGE, "tags": names["image_tags"], "index_digest": a.image_digest,
                   "platforms": platforms} if a.image_digest else None),
        "base_images": base_images(record),
        "comparison_image": comparison,
        "build_environment": build_environment(repo),
        "changelog": changelog_record(changelog, repo) if changelog else None,
        "approvals": approvals,
        "verification": {
            "public_key_sha256": key_sha,
            "signer_workflow": "%s/.github/workflows/attest.yml" % slug,
            "sealed_by": ["SHA256SUMS", "SHA256SUMS.sigstore.json", "wd2l-%s-attestations.jsonl" % v],
            "attestations": [
                {"predicate_type": "https://slsa.dev/provenance/v1", "signed_by": "attest.yml (GitHub, keyless)",
                 "covers": "every file in SHA256SUMS, the image index, each platform image and the comparison image"},
                {"predicate_type": "https://slsa.dev/provenance/v1", "signed_by": "the release key",
                 "covers": "the image index and each platform image (wd2l-%s-provenance.json), "
                           "and the comparison image (wd2l-%s-provenance-ubi9.json)" % (v, v)},
                {"predicate_type": "%s/base-image-record/v2" % ATT, "signed_by": "the release key",
                 "covers": "the image index, each platform image and the comparison image"},
                {"predicate_type": "https://spdx.dev/Document", "signed_by": "the release key",
                 "covers": "each platform image and the comparison image (its SBOM)"},
                {"predicate_type": "%s/vuln-scan/v1" % ATT, "signed_by": "the release key",
                 "covers": "each platform image and the comparison image (its scan results)"},
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


# ---- the readable views (#202) ------------------------------------------------------------
# One list of blocks, written as markdown (the .md, and the run's summary) or as one HTML page,
# so the two can't drift. A block is ("h", level, inline), ("p", inline), ("note", inline),
# ("md", text) (the release's summary, markdown from the repository), ("table", head, rows) or
# ("code", lines). Inline content is a str (our own text), or a list of strs and parts:
# forge(s), text from the forge, escaped in both formats; code(s); bold(x); link(x, url). A table
# cell of None is empty.

def code(s: Any, esc_md: bool = False) -> Tuple[str, str, bool]:
    return ("code", str(s), esc_md)


def forge(s: Any) -> Tuple[str, str]:
    return ("forge", str(s))


def bold(x: Any) -> Tuple[str, Any]:
    return ("b", x)


def link(x: Any, url: str) -> Tuple[str, Any, str]:
    return ("link", x, url)


def _parts(x: Any) -> List[Any]:
    return x if isinstance(x, list) else [x]


def md_inline(x: Any) -> str:
    out = []
    for p in _parts(x):
        if isinstance(p, str):
            out.append(p)
        elif p[0] == "forge":
            out.append(esc(p[1]))
        elif p[0] == "code":
            out.append("`%s`" % (esc(p[1]) if p[2] else p[1]))
        elif p[0] == "b":
            out.append("**%s**" % md_inline(p[1]))
        else:
            out.append("[%s](%s)" % (md_inline(p[1]), p[2]))
    return "".join(out)


def diff_section(d: Optional[Dict[str, Any]]) -> List[Tuple[Any, ...]]:
    if d is None:
        return [("h", 2, "Lines changed"), ("p", "No earlier final release to compare with.")]
    b, L = d["base"], d["lines"]
    n = "{:,}".format
    return [("h", 2, "Lines changed since %s" % b["tag"]),
            ("p", ["From ", code(b["commit"]), " (%s) to " % b["tag"], code(d["head"]), " (this release): ",
                   link("compare on the forge", d["compare_url"]), ". Offline, in a clone of the source bundle: ",
                   code("git diff %s %s" % (b["commit"], d["head"])), "."]),
            ("p", "A plain count of lines, not SLOC: %s. %d binary file%s changed." % (
                d["method"], d["binary_files"], "" if d["binary_files"] == 1 else "s")),
            ("table", ["Type", "Files", "Added", "Modified", "Deleted"],
             [[code(t["type"], esc_md=True), n(t["files"]), n(t["added"]), n(t["modified"]), n(t["deleted"])]
              for t in d["by_type"]]
             + [[bold("Total"), bold(n(d["files_changed"])), bold(n(L["added"])), bold(n(L["modified"])),
                 bold(n(L["deleted"]))]])]


def blocks(m: Dict[str, Any]) -> List[Tuple[Any, ...]]:
    """The manifest's readable view, as blocks."""
    r, s, ch = m["release"], m["source"], m["changes"]
    repo = s["repository"]
    out: List[Tuple[Any, ...]] = [("h", 1, "wd2l %s: release manifest" % r["version"])]
    if r["dry_run"]:
        out.append(("note", [bold("Dry run."), " Built without a version tag: nothing was published or signed."]))
    elif r["prerelease"]:
        out.append(("note", [bold("Pre-release"), ", for testing."]))
    run = m["generated"]["run"]
    out += [("p", ["The version description of ", bold("wd2l %s" % r["version"]), " (tag ", code(r["tag"]),
                   "), built from commit ", link(code(s["commit"]), "%s/commit/%s" % (repo, s["commit"])),
                   " of %s. Generated %s by " % (s["commit_date"][:10], m["generated"]["at"]),
                   code(m["generated"]["by"])]
                  + ([" in ", link("run %s" % run["id"], run["url"])] if run else []) + ["."]),
            ("p", [code("wd2l-%s-release-manifest.json" % r["version"]), " is the authoritative record; this page "
                   "is generated from it (schema version %d)." % m["schema_version"]])]
    if m["summary"]:
        out += [("h", 2, "Summary"), ("md", m["summary"]["text"].strip())]

    since = ch["since"]
    issues = ch["issues_resolved"]
    out += [("h", 2, "Issues resolved (%d)" % len(issues)),
            ("p", ("Since %s." % since) if since else "Since the first commit: there is no earlier final release.")]
    for cat, heading in SECTIONS:
        rows = [i for i in issues if i["category"] == cat]
        if not rows:
            continue
        table = []
        for i in rows:
            by: List[Any] = []
            for k, n in enumerate(i["resolved_by"]):
                by += ([", "] if k else []) + [link("#%d" % n, "%s/pull/%d" % (repo, n))]
            table.append([[link("#%d" % i["number"], i["url"])] + ([" †"] if i["retroactive"] else []),
                          forge(i["title"]), by, i["resolved_at"][:10],
                          code(i["first_tag"]) if i["first_tag"] else "this release"])
        out += [("h", 3, heading),
                ("table", ["Issue", "Title", "Resolved by", "Merged", "First released in"], table)]
    if any(i["retroactive"] for i in issues):
        out.append(("p", "† Recorded after its work had merged, to complete the record; dated by its "
                         "pull request's merge."))
    if ch["pull_requests_without_issue"]:
        by_num = {p["number"]: p for p in ch["pull_requests"]}
        out += [("h", 2, "Pull requests without an issue (%d)" % len(ch["pull_requests_without_issue"])),
                ("table", ["Pull request", "Title", "Merged"],
                 [[link("#%d" % n, by_num[n]["url"]), forge(by_num[n]["title"]), by_num[n]["merged_at"][:10]]
                  for n in ch["pull_requests_without_issue"]])]
    out.append(("h", 2, "Known issues"))
    if m["known_issues"]:
        out.append(("table", ["Issue", "Title"],
                    [[link("#%d" % k["number"], k["url"]), forge(k["title"])] for k in m["known_issues"]]))
    else:
        out.append(("p", "No open bugs when this manifest was made."))

    sealed: List[Any] = ["Made after this manifest, and covering it: "]
    for k, x in enumerate(m["verification"]["sealed_by"]):
        sealed += ([", "] if k else []) + [code(x)]
    out += [("h", 2, "Deliverables"),
            ("table", ["File", "Kind", "Size", "SHA-256"],
             [[code(d["name"]), d["kind"], _size(d["size"]), code(d["sha256"])] for d in m["deliverables"]]),
            ("p", sealed + ["."])]

    img = m["image"]
    out.append(("h", 2, "Container image"))
    if img:
        tags: List[Any] = []
        for k, t in enumerate(img["tags"]):
            tags += ([", "] if k else []) + [code(t)]
        out += [("p", [code("%s@%s" % (img["name"], img["index_digest"])), ", tagged "] + tags + ["."]),
                ("table", ["Platform", "Digest"],
                 [["linux/%s" % p, code(d)] for p, d in sorted(img["platforms"].items())])]
    else:
        out.append(("p", "Not published (dry run)."))
    out.append(("table", ["Stage", "Base image", "Source (SRPMs)"],
                [[b["stage"], code(b["ref"]), code(b["source_image"])] for b in m["base_images"]]))

    ci = m.get("comparison_image")
    out.append(("h", 2, "Comparison image (UBI 9: not hardened, not FIPS)"))
    if ci:
        tags = []
        for k, t in enumerate(ci["tags"]):
            tags += ([", "] if k else []) + [code(t)]
        out += [("p", [code("%s@%s" % (ci["name"], ci["digest"])), ", %s, tagged " % ci["platform"]] + tags + ["."]),
                ("p", ["%s Deploy " % ci["purpose"].split(" Deploy ")[0], code(IMAGE), "."]),
                ("table", ["Stage", "Base image"], [[b["stage"], code(b["ref"])] for b in ci["base_images"]])]
    else:
        out.append(("p", "Not published (dry run)."))

    if "diff" in ch:                     # manifests before #224 have no line counts
        out += diff_section(ch["diff"])
    rows = [[link("#%d" % p["number"], p["url"]), forge(p["title"]), p["merged_at"][:10],
             ", ".join("#%d" % n for n in p["closes"]) or "—",
             code(p["first_tag"]) if p["first_tag"] else "this release"] for p in ch["pull_requests"]]
    rows += [[code(d["commit"][:7]), forge(d["subject"]), None, "—",
              code(d["first_tag"]) if d["first_tag"] else "this release"] for d in ch["direct_commits"]]
    out += [("h", 2, "Changes (%d pull requests)" % len(ch["pull_requests"])),
            ("table", ["Pull request", "Title", "Merged", "Closes", "First released in"], rows)]
    if m["changelog"]:
        out.append(("p", ["The changelog, grouped by commit type, is ", code(m["changelog"]["file"]), "."]))

    env = m["build_environment"]
    runners: List[Any] = []
    for k, x in enumerate(env["runners"]):
        runners += ([", "] if k else []) + [code(x)]
    out += [("h", 2, "Build environment"),
            ("p", ["Pinned at the commit. Runners: "] + runners + ["."]),
            ("table", ["Action", "Commit", "Version"],
             [[code(x["action"]), code(x["commit"]), x["version"]] for x in env["actions"]]),
            ("table", ["Tool", "Image"], [[x["name"], code(x["ref"])] for x in env["tool_images"]])]

    out.append(("h", 2, "Approvals"))
    if m["approvals"]:
        out += [("table", ["Environment", "Approved by", "State", "Comment"],
                 [[forge(x["environment"]), forge(x["user"]), forge(x["state"]), forge(x["comment"])]
                  for x in m["approvals"]]),
                ("p", ["The ", code("release"), " gate, approved after this manifest was made, approves signing it."])]
    else:
        out.append(("p", "None recorded (a dry run has no approval gates)."))

    ver = m["verification"]
    v = r["version"]
    out += [("h", 2, "Verifying this release"),
            ("p", ["Offline, with a ", code("cosign.pub"), " obtained from a trusted channel (SHA-256 ",
                   code(ver["public_key_sha256"]), "):"]),
            ("code", ["cosign verify-blob --key cosign.pub --insecure-ignore-tlog --bundle SHA256SUMS.sigstore.json SHA256SUMS",
                      "sha256sum -c SHA256SUMS      # this manifest is one of the files it lists"]),
            ("p", ["With the GitHub CLI (", code("--bundle wd2l-%s-attestations.jsonl" % v), " works offline):"]),
            ("code", ["gh attestation verify wd2l-%s-release-manifest.json --repo %s --signer-workflow %s"
                      % (v, repo.split("github.com/", 1)[-1], ver["signer_workflow"]),
                      "gh release verify %s" % r["tag"]]),
            ("table", ["Attestation", "Signed by", "Covers"],
             [[code(x["predicate_type"]), x["signed_by"], x["covers"]] for x in ver["attestations"]])]
    return out


def to_markdown(bl: Sequence[Tuple[Any, ...]]) -> str:
    out: List[str] = []
    for b in bl:
        if b[0] == "h":
            out += ["#" * b[1] + " " + md_inline(b[2]), ""]
        elif b[0] == "p":
            out += [md_inline(b[1]), ""]
        elif b[0] == "note":
            out += ["> " + md_inline(b[1]), ""]
        elif b[0] == "md":
            out += [b[1], ""]
        elif b[0] == "code":
            out += ["```bash"] + list(b[1]) + ["```", ""]
        else:
            out += ["| " + " | ".join(b[1]) + " |", "|" + "---|" * len(b[1])]
            out += ["|" + "".join(" |" if c is None else " %s |" % md_inline(c) for c in row) for row in b[2]]
            out.append("")
    if out and out[-1] == "":
        out.pop()
    return "\n".join(out) + "\n"


def render(m: Dict[str, Any]) -> str:
    """The markdown view: wd2l-<version>-release-manifest.md, and the run's summary."""
    return to_markdown(blocks(m))


# The HTML view: wd2l-<version>-release-manifest.html, for a reviewer with nothing that renders
# markdown. It looks like the SBOM page (the same stylesheet), loads nothing and runs nothing.
HTML_CSS = ("nav{background:var(--card);border-radius:8px;padding:8px 16px;margin:16px 0;max-width:820px}"
            "nav ul{margin:4px 0;padding-left:20px;columns:2}main code{overflow-wrap:anywhere}"
            "blockquote{border-left:4px solid var(--accent);margin:12px 0;padding:4px 12px;background:var(--card)}"
            "pre{background:var(--card);padding:10px 12px;border-radius:6px;overflow-x:auto}pre code{white-space:pre}"
            "table{margin:8px 0 16px}"
            "@media print{thead{display:table-header-group}tr{break-inside:avoid}h2,h3{break-after:avoid}nav{display:none}}")


def _h(text: Any, quote: bool = True) -> str:
    return html.escape(str(text), quote=quote)


def html_inline(x: Any) -> str:
    out = []
    for p in _parts(x):
        if isinstance(p, str) or p[0] == "forge":
            out.append(_h(p if isinstance(p, str) else p[1]))
        elif p[0] == "code":
            out.append("<code>%s</code>" % _h(p[1]))
        elif p[0] == "b":
            out.append("<b>%s</b>" % html_inline(p[1]))
        elif p[2].startswith("https://"):
            out.append('<a href="%s">%s</a>' % (_h(p[2]), html_inline(p[1])))
        else:                            # a link only to an https URL; anything else stays text
            out.append(html_inline(p[1]))
    return "".join(out)


def summary_inline_html(text: str) -> str:
    """The summary's own markdown inline: `code`, **bold** and [text](https://...)."""
    out = []
    for k, part in enumerate(text.split("`")):
        if k % 2:
            out.append("<code>%s</code>" % _h(part))
            continue
        t = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", _h(part))
        out.append(re.sub(r"\[([^\]]+)\]\((https://[^)\s]+)\)", r'<a href="\2">\1</a>', t))
    return "".join(out)


ITEM = re.compile(r"(\s*)([*-]|\d+\.) (.*)")


def summary_html(text: str, heading: Any) -> List[str]:
    """The release's summary (docs/releases/<version>.md): headings, paragraphs, nested lists and
    code blocks, the markdown those files use. heading(level, html) writes a heading."""
    out: List[str] = []
    para: List[str] = []
    stack: List[List[Any]] = []          # the open lists: [indent, tag]
    lines = text.splitlines()

    def flush() -> None:
        if para:
            out.append("<p>%s</p>" % summary_inline_html(" ".join(para)))
            del para[:]

    def close(deeper_than: int = -1) -> None:
        while stack and stack[-1][0] > deeper_than:
            out.append("</li></%s>" % stack.pop()[1])

    i = 0
    while i < len(lines):
        line, i = lines[i], i + 1
        bare = line.strip()
        if bare.startswith("```"):
            flush()
            close()
            body = []
            while i < len(lines) and not lines[i].strip().startswith("```"):
                body.append(lines[i])
                i += 1
            i += 1
            out.append("<pre><code>%s</code></pre>" % _h("\n".join(body), quote=False))
            continue
        hm = re.match(r"(#{1,6}) (.*)", line)
        if hm:
            flush()
            close()
            out.append(heading(len(hm.group(1)), summary_inline_html(hm.group(2))))
            continue
        im = ITEM.match(line)
        if im:
            flush()
            indent, tag = len(im.group(1)), "ol" if im.group(2)[0].isdigit() else "ul"
            words = [im.group(3)]
            while (i < len(lines) and lines[i].strip() and not ITEM.match(lines[i])
                   and not lines[i].strip().startswith("```")
                   and len(lines[i]) - len(lines[i].lstrip()) > indent):
                words.append(lines[i].strip())
                i += 1
            close(indent)
            if stack and stack[-1][0] == indent:
                out.append("</li>")
            else:
                out.append("<%s>" % tag)
                stack.append([indent, tag])
            out.append("<li>%s" % summary_inline_html(" ".join(words)))
            continue
        if not bare:
            flush()
            nxt = next((l for l in lines[i:] if l.strip()), "")
            if not ITEM.match(nxt):
                close()
            continue
        close()
        para.append(bare)
    flush()
    close()
    return out


def render_html(m: Dict[str, Any]) -> str:
    """The HTML view, from the same blocks as the markdown."""
    import sbom_report                   # the SBOM page's stylesheet, so the two read as one set
    v = m["release"]["version"]
    body: List[str] = []
    nav: List[Tuple[str, str]] = []
    ids: Dict[str, int] = {}

    def heading(level: int, inner: str) -> str:
        if level != 2:
            return "<h%d>%s</h%d>" % (level, inner, level)
        text = re.sub(r"<[^>]+>", "", inner)
        slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "section"
        ids[slug] = ids.get(slug, 0) + 1
        if ids[slug] > 1:
            slug += "-%d" % ids[slug]
        nav.append((slug, inner))
        return '<h2 id="%s">%s</h2>' % (slug, inner)

    for b in blocks(m):
        if b[0] == "h":
            body.append(heading(b[1], html_inline(b[2])))
        elif b[0] == "p":
            body.append("<p>%s</p>" % html_inline(b[1]))
        elif b[0] == "note":
            body.append("<blockquote>%s</blockquote>" % html_inline(b[1]))
        elif b[0] == "md":
            body += summary_html(b[1], heading)
        elif b[0] == "code":
            body.append("<pre><code>%s</code></pre>" % _h("\n".join(b[1]), quote=False))
        else:
            body.append("<table><thead><tr>%s</tr></thead><tbody>%s</tbody></table>" % (
                "".join("<th>%s</th>" % _h(c) for c in b[1]),
                "".join("<tr>%s</tr>" % "".join("<td>%s</td>" % ("" if c is None else html_inline(c)) for c in row)
                        for row in b[2])))
    first = next((k for k, x in enumerate(body) if x.startswith("<h2")), len(body))
    sbom = "wd2l-%s-sbom.html" % v
    intro = ['<p>Its SBOMs and scan results, as one readable page: <a href="%s">%s</a>.</p>' % (_h(sbom), _h(sbom)),
             '<nav aria-label="Sections"><b>Sections</b><ul>%s</ul></nav>' % "".join(
                 '<li><a href="#%s">%s</a></li>' % (slug, inner) for slug, inner in nav)]
    title = "wd2l %s: release manifest" % v
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; '
            'img-src data:; base-uri \'none\'; form-action \'none\'">'
            '<title>%s</title><style>%s%s</style></head><body><main>\n%s\n'
            '<footer>Generated by <code>packaging/release/manifest.py render --format html</code> from '
            '<code>wd2l-%s-release-manifest.json</code>.</footer></main></body></html>\n' % (
                _h(title), sbom_report.CSS, HTML_CSS, "\n".join(body[:first] + intro + body[first:]), _h(v)))


# ---- command line -------------------------------------------------------------------------

def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="The release manifest: generate, validate, render.")
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate", help="make the manifest (JSON on stdout)")
    g.add_argument("--assets", required=True, help="the directory of release files it lists")
    g.add_argument("--base-record", required=True)
    g.add_argument("--image-digest", default="")
    g.add_argument("--platform-digest", action="append", default=[], metavar="ARCH=DIGEST")
    g.add_argument("--comparison-digest", default="", help="the UBI 9 comparison image's digest (#192)")
    g.add_argument("--comparison-base-record", help="base-image-record-ubi9.json")
    g.add_argument("--dry-run", action="store_true", help="no version tag: nothing published")
    g.add_argument("--changelog", help="the changelog git-cliff made (one of the --assets files)")
    sub.add_parser("previous-release", help="print the previous final release's tag, if any")
    val = sub.add_parser("validate", help="check a manifest against the schema")
    val.add_argument("manifest")
    ren = sub.add_parser("render", help="the readable view (on stdout): markdown, or HTML (#202)")
    ren.add_argument("--format", choices=("md", "html"), default="md")
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
    if a.cmd == "previous-release":
        prev = previous_release(versions.names(versions.read_version())["tag"])
        if prev:
            print(prev)
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
    sys.stdout.write(render_html(doc) if a.format == "html" else render(doc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
