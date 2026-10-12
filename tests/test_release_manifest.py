"""The release manifest (docs/decisions/0008-release-manifest.md): JSON validated against a
committed schema, a markdown view of it, and how it's made from git and the forge's API."""

import argparse
import copy
import json
import os
import shutil
import subprocess

import pytest

from helpers import load_script

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
m = load_script("packaging/release/manifest.py")
EXAMPLE = os.path.join(REPO, "packaging", "release", "release-manifest.example.json")
needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


def example():
    with open(EXAMPLE) as f:
        return json.load(f)


# ---- the schema ---------------------------------------------------------------------------

def test_the_hand_written_example_matches_the_schema():
    pytest.importorskip("fastjsonschema")
    assert m.validate(example()) is None


def _drop(key):
    def f(d):
        del d[key]
    return f


@pytest.mark.parametrize("change", [
    lambda d: d["source"].update(commit="3e7b91c"),                          # a short SHA
    lambda d: d["image"].update(index_digest="1.1.0"),                       # a tag, not a digest
    lambda d: d["release"].update(tag="1.1.0"),                              # no v
    lambda d: d.update(extra=1),                                             # an unknown key
    _drop("deliverables"),
    lambda d: d["deliverables"][0].update(name="../wd2l.rpm"),               # a path, not a name
    lambda d: d["changes"]["issues_resolved"][0].update(resolved_by=[]),     # resolved by nothing
    lambda d: d["changes"]["issues_resolved"][0].update(category="feature"),
    lambda d: d["release"].pop("dry_run"),
    lambda d: d.update(schema_version=2),
])
def test_the_schema_refuses_a_malformed_manifest(change):
    pytest.importorskip("fastjsonschema")
    d = copy.deepcopy(example())
    change(d)
    assert m.validate(d) is not None


def test_cli_validate_fails_an_invalid_file(tmp_path, capsys):
    pytest.importorskip("fastjsonschema")
    good, bad = tmp_path / "good.json", tmp_path / "bad.json"
    good.write_text(json.dumps(example()))
    d = example()
    d["source"]["commit"] = "nope"
    bad.write_text(json.dumps(d))
    assert m.main(["validate", str(good)]) == 0
    assert m.main(["validate", str(bad)]) == 1
    assert "invalid" in capsys.readouterr().err


# ---- versions, commits and links ----------------------------------------------------------

def test_tags_sort_by_version_not_by_name():
    tags = ["v1.0.0", "v0.3.0rc6", "v1.0.0rc1", "v0.10.0", "v1.0.0b2", "latest"]
    assert sorted((t for t in tags if m.tag_key(t)), key=m.tag_key) == \
        ["v0.3.0rc6", "v0.10.0", "v1.0.0b2", "v1.0.0rc1", "v1.0.0"]
    assert m.earliest(["v1.0.0", "v1.0.0rc1"]) == "v1.0.0rc1" and m.earliest([]) is None
    assert m.is_final("v1.0.0") and not m.is_final("v1.0.0rc1")


@pytest.mark.parametrize("body, nums", [
    ("Closes #29", [29]), ("fixes #3, resolves #4", [3, 4]), ("Closed: #7", [7]),
    ("See #12 and PR #13", []), ("closes#5", []), ("", []),
])
def test_closing_keywords_in_a_commit_message(body, nums):
    assert m.closes_in(body) == nums


def test_category_is_one_label_in_a_fixed_order():
    assert m.category(["enhancement", "security"]) == "security"
    assert m.category(["retroactive", "documentation"]) == "documentation"
    assert m.category(["question"]) == "other"


def test_commit_type_only_for_conventional_titles():
    assert m.commit_type("feat(release)!: manifest") == "feat"
    assert m.commit_type("build(deps): bump x") == "build"
    assert m.commit_type("0.3.0rc5: arm64 image") is None


class FakeForge:
    """Pull requests by the (#N) GitHub appends to a squash subject; issues by number."""

    def __init__(self, prs, issues, known=(), approvals=()):
        self.prs, self._issues = prs, issues
        self.known, self.appr = list(known), list(approvals)
        self.asked_issues = set()

    def pull_requests(self, commits):
        out = {}
        for c in commits:
            num = m.PR_SUFFIX.search(c["subject"])
            out[c["sha"]] = self.prs.get(int(num.group(1))) if num else None
        return out

    def issues(self, numbers):
        numbers = set(numbers)
        self.asked_issues |= numbers
        return {n: i for n, i in self._issues.items() if n in numbers}

    def known_issues(self):
        return self.known

    def approvals(self, run_id):
        return self.appr


def pr(n, title, merged, closes=()):
    return {"number": n, "title": title, "url": "https://github.com/o/r/pull/%d" % n,
            "merged_at": merged, "closes": list(closes)}


def issue(n, title, labels, state="CLOSED", reason="COMPLETED"):
    return {"number": n, "title": title, "url": "https://github.com/o/r/issues/%d" % n,
            "state": state, "state_reason": reason, "labels": labels}


def commit(sha, subject, body="", first_tag=None):
    return {"sha": sha * 40, "subject": subject, "body": body, "first_tag": first_tag}


def test_changes_join_git_and_forge_links_and_keep_only_completed_issues():
    commits = [
        commit("a", "Initial commit", first_tag="v0.3.0rc1"),
        commit("b", "One-way architecture (#1)", first_tag="v0.3.0rc1"),
        commit("c", "feat: release manifest (#64)", "Closes #33\nCloses #64", first_tag="v1.0.0rc1"),
        commit("d", "build(deps): bump x (#70)", first_tag=None),
        commit("e", "fix: two fixes (#71)", "Fixes #75, fixes #76", first_tag=None),
    ]
    forge = FakeForge(
        prs={1: pr(1, "One-way architecture", "2026-09-26T10:00:00Z", closes=[39]),   # retro link
             64: pr(64, "feat: release manifest", "2026-10-13T10:00:00Z"),
             70: pr(70, "build(deps): bump x", "2026-10-14T10:00:00Z"),
             71: pr(71, "fix: two fixes", "2026-10-15T10:00:00Z")},
        issues={39: issue(39, "Architecture", ["enhancement", "retroactive"]),
                33: issue(33, "Manifest", ["enhancement"]),
                75: issue(75, "Done", ["bug"]),
                76: issue(76, "Won't do", ["bug"], reason="NOT_PLANNED")})
    ch = m.changes(commits, forge)
    assert [d["subject"] for d in ch["direct_commits"]] == ["Initial commit"]
    byn = {p["number"]: p for p in ch["pull_requests"]}
    assert byn[1]["closes"] == [39] and byn[1]["type"] is None
    assert byn[64]["closes"] == [33] and byn[64]["type"] == "feat"    # #64 is a PR: dropped
    assert byn[71]["closes"] == [75, 76]
    assert ch["pull_requests_without_issue"] == [70]
    res = {i["number"]: i for i in ch["issues_resolved"]}
    assert sorted(res) == [33, 39, 75]                                 # 76 wasn't completed
    assert res[39]["retroactive"] and res[39]["category"] == "enhancement"
    assert res[39]["resolved_by"] == [1] and res[39]["resolved_at"] == "2026-09-26T10:00:00Z"
    assert res[39]["first_tag"] == "v0.3.0rc1" and res[75]["first_tag"] is None
    assert not res[33]["retroactive"]


def test_an_issue_closed_by_two_prs_is_dated_by_the_first_and_released_with_the_earliest():
    commits = [commit("a", "fix: part one (#5)", "Closes #9", "v1.0.0rc1"),
               commit("b", "fix: part two (#6)", "Closes #9", "v1.0.0")]
    forge = FakeForge(prs={5: pr(5, "fix: part one", "2026-10-01T00:00:00Z"),
                           6: pr(6, "fix: part two", "2026-10-05T00:00:00Z")},
                      issues={9: issue(9, "Bug", ["bug"])})
    (i,) = m.changes(commits, forge)["issues_resolved"]
    assert i["resolved_by"] == [5, 6] and i["resolved_at"] == "2026-10-01T00:00:00Z"
    assert i["first_tag"] == "v1.0.0rc1"


@pytest.mark.parametrize("name, kind", [
    ("wd2l-1.0.0-1.el9.noarch.rpm", "rpm"), ("wd2l-1.0.0-py3-none-any.whl", "wheel"),
    ("wd2l-1.0.0.tar.gz", "sdist"), ("wd2l-1.0.0-image-arm64-oci.tar", "oci-image"),
    ("wd2l-1.0.0-image-amd64.cdx.json", "sbom"), ("wd2l-1.0.0-vuln-summary-amd64.md", "vulnerability-summary"),
    ("wd2l-1.0.0-provenance.json", "provenance"), ("base-image-record.json", "base-image-record"),
    ("cosign.pub", "public-key"), ("wd2l-1.0.0-source.bundle", "source-bundle"),
    ("wd2l-1.0.0-changelog.md", "changelog"), ("wd2l-1.0.0-verify-release.py", "verification-script"),
    ("notes.txt", "other"),
])
def test_each_release_file_gets_a_kind(name, kind):
    assert m.kind(name) == kind


def test_build_environment_lists_the_pins_at_the_commit():
    env = m.build_environment(REPO)
    acts = {a["action"] for a in env["actions"]}
    assert {"actions/checkout", "actions/attest", "actions/upload-artifact"} <= acts
    assert all(len(a["commit"]) == 40 for a in env["actions"])
    assert "cosign" in {t["name"] for t in env["tool_images"]}
    assert all("@sha256:" in t["ref"] for t in env["tool_images"])
    assert {"ubuntu-24.04", "ubuntu-24.04-arm"} <= set(env["runners"])


# ---- the whole thing, from a small git repository -----------------------------------------

def run_git(cwd, *args, date="2026-10-12T12:00:00Z"):
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.com",
               GIT_AUTHOR_DATE=date, GIT_COMMITTER_DATE=date)
    subprocess.run(("git", "-c", "init.defaultBranch=main", "-c", "tag.gpgSign=false",
                    "-c", "commit.gpgSign=false") + args, cwd=cwd, check=True, env=env,
                   capture_output=True)


def make_repo(tmp_path, version="1.0.0rc1", final_tag=True, summary=True):
    r = tmp_path / "repo"
    for rel in [os.path.join(".github", "workflows", w) for w in m.RELEASE_PATH] + \
               [os.path.join("packaging", "ci", "tools.Containerfile"), "cosign.pub"]:
        (r / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(os.path.join(REPO, rel), r / rel)
    (r / "wd2l").mkdir()
    (r / "wd2l" / "__init__.py").write_text('__version__ = "%s"\n' % version)
    if summary:
        (r / "docs" / "releases").mkdir(parents=True)
        (r / "docs" / "releases" / ("%s.md" % version)).write_text("## What changed\n\n* All of it.\n")
    run_git(r, "init", "-q")
    run_git(r, "add", "-A")
    run_git(r, "commit", "-q", "-m", "Initial commit")
    run_git(r, "commit", "-q", "--allow-empty", "-m", "One-way architecture (#1)")
    run_git(r, "tag", "-a", "v0.3.0rc1", "-m", "rc1")
    run_git(r, "commit", "-q", "--allow-empty", "-m", "Fix review findings (#2)")
    if final_tag:
        run_git(r, "tag", "v0.3.0")
    run_git(r, "commit", "-q", "--allow-empty", "-m", "feat: release manifest (#64)", "-m", "Closes #33")
    run_git(r, "commit", "-q", "--allow-empty", "-m", "chore(release): %s (#66)" % version, "-m", "Closes #36")
    run_git(r, "tag", "-a", "v" + version, "-m", version)
    return r


@needs_git
def test_git_facts_cover_the_changes_since_the_previous_final_release(tmp_path):
    r = make_repo(tmp_path)
    f = m.git_facts("v1.0.0rc1", cwd=str(r))
    assert f["previous_release"]["tag"] == "v0.3.0" and f["previous_tag"]["tag"] == "v0.3.0"
    assert len(f["head"]) == 40 and f["head_date"] == "2026-10-12T12:00:00Z"
    assert [c["subject"] for c in f["commits"]] == ["feat: release manifest (#64)", "chore(release): 1.0.0rc1 (#66)"]
    assert {c["first_tag"] for c in f["commits"]} == {"v1.0.0rc1"}
    assert f["commits"][1]["body"].strip() == "Closes #36"


@needs_git
def test_without_a_final_release_the_changes_go_back_to_the_first_commit(tmp_path):
    r = make_repo(tmp_path, final_tag=False)
    f = m.git_facts("v1.0.0rc1", cwd=str(r))
    assert f["previous_release"] is None and f["previous_tag"]["tag"] == "v0.3.0rc1"
    assert [c["first_tag"] for c in f["commits"]] == ["v0.3.0rc1", "v0.3.0rc1", "v1.0.0rc1", "v1.0.0rc1", "v1.0.0rc1"]


def forge_for_repo():
    return FakeForge(
        prs={64: pr(64, "feat: release manifest", "2026-10-13T10:00:00Z"),
             66: pr(66, "chore(release): 1.0.0rc1", "2026-10-14T10:00:00Z")},
        issues={33: issue(33, "Release manifest <generate> | validate", ["enhancement"]),
                36: issue(36, "Rehearse 1.0.0rc1", ["release"])},
        known=[{"number": 88, "title": "Lab flake", "url": "https://github.com/o/r/issues/88", "labels": ["bug"]}],
        approvals=[{"environment": "release", "user": "owner", "state": "approved", "comment": ""}])


def gen_args(tmp_path, dry_run=False, digests=True):
    assets = tmp_path / "assets"
    assets.mkdir(exist_ok=True)
    (assets / "wd2l-1.0.0rc1-py3-none-any.whl").write_bytes(b"wheel")
    (assets / "cosign.pub").write_bytes(b"key")
    rec = tmp_path / "base-image-record.json"
    rec.write_text(json.dumps({"images": [{"stage": "runtime", "ref": "registry.example/python@sha256:" + "1" * 64,
                                           "index_digest": "sha256:" + "1" * 64,
                                           "platforms": {"amd64": "sha256:" + "2" * 64},
                                           "release": "1", "source_image": "registry.example/python:1-source"}]}))
    d = "sha256:" + "3" * 64
    return argparse.Namespace(assets=str(assets), base_record=str(rec), dry_run=dry_run,
                              image_digest=d if digests else "",
                              platform_digest=(["amd64=sha256:" + "4" * 64, "arm64=sha256:" + "5" * 64]
                                               if digests else ["amd64=", "arm64="]))


RUN_ENV = {"GITHUB_SERVER_URL": "https://github.com", "GITHUB_REPOSITORY": "o/r", "GITHUB_RUN_ID": "123",
           "GITHUB_RUN_ATTEMPT": "2", "GITHUB_WORKFLOW_REF": "o/r/.github/workflows/release.yml@refs/tags/v1.0.0rc1"}


@needs_git
def test_a_tag_run_makes_a_valid_manifest_with_image_approvals_and_summary(tmp_path):
    pytest.importorskip("fastjsonschema")
    r = make_repo(tmp_path)
    doc = m.generate(gen_args(tmp_path), RUN_ENV, forge_for_repo(), repo=str(r))
    assert m.validate(doc) is None
    assert doc["release"] == {"product": "wd2l", "version": "1.0.0rc1", "tag": "v1.0.0rc1",
                              "prerelease": True, "dry_run": False}
    assert doc["changes"]["since"] == "v0.3.0"
    assert [i["number"] for i in doc["changes"]["issues_resolved"]] == [33, 36]
    assert doc["image"]["tags"] == ["1.0.0rc1"] and set(doc["image"]["platforms"]) == {"amd64", "arm64"}
    assert doc["approvals"][0]["user"] == "owner"
    assert doc["generated"]["run"]["attempt"] == 2
    assert doc["summary"]["file"] == "docs/releases/1.0.0rc1.md"
    assert [d["name"] for d in doc["deliverables"]] == ["cosign.pub", "wd2l-1.0.0rc1-py3-none-any.whl"]
    assert doc["verification"]["sealed_by"][-1] == "wd2l-1.0.0rc1-attestations.jsonl"


@needs_git
def test_a_dry_run_has_no_image_and_asks_for_no_approvals(tmp_path):
    pytest.importorskip("fastjsonschema")
    r = make_repo(tmp_path, summary=False)
    doc = m.generate(gen_args(tmp_path, dry_run=True, digests=False), {}, forge_for_repo(), repo=str(r))
    assert m.validate(doc) is None
    assert doc["image"] is None and doc["approvals"] == [] and doc["summary"] is None
    assert doc["release"]["dry_run"] and doc["generated"]["run"] is None


@needs_git
def test_a_tag_without_its_summary_is_refused_before_anything_else(tmp_path):
    r = make_repo(tmp_path, summary=False)
    with pytest.raises(SystemExit, match="docs/releases/1.0.0rc1.md"):
        m.generate(gen_args(tmp_path), RUN_ENV, forge_for_repo(), repo=str(r))


# ---- the markdown view --------------------------------------------------------------------

@needs_git
def test_the_view_escapes_forge_text(tmp_path):
    r = make_repo(tmp_path)
    md = m.render(m.generate(gen_args(tmp_path), RUN_ENV, forge_for_repo(), repo=str(r)))
    assert "Release manifest &lt;generate&gt; \\| validate" in md
    assert "<generate>" not in md
    assert "## Issues resolved (2)" in md and "Since v0.3.0." in md
    assert "### Enhancements" in md and "### Release engineering" in md
    assert "| [#88](https://github.com/o/r/issues/88) | Lab flake |" in md


def test_the_view_marks_dry_runs_and_retroactive_issues():
    d = example()
    d["release"]["dry_run"], d["image"], d["approvals"] = True, None, []
    d["changes"]["issues_resolved"][0]["retroactive"] = True
    md = m.render(d)
    assert md.startswith("# wd2l 1.1.0: release manifest\n\n> **Dry run.**")
    assert "Not published (dry run)." in md
    assert "#79](https://github.com/JoeHazurmoney/architecture-wiredata-to-log/issues/79) † |" in md
    assert "† Recorded after its work had merged" in md
    assert "## Pull requests without an issue (1)" in md
    assert "gh attestation verify wd2l-1.1.0-release-manifest.json" in md


def test_every_version_has_its_release_summary():
    # A tag can't be released without docs/releases/<version>.md: the assets job refuses, after
    # publish has run. So the version bump's PR fails here first.
    v = load_script("packaging/release/versions.py").read_version()
    assert os.path.exists(os.path.join(REPO, "docs", "releases", "%s.md" % v)), v
