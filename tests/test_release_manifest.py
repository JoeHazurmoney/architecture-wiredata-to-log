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
    lambda d: d["changes"]["diff"].update(head="00206cd"),                   # a short SHA (#224)
    lambda d: d["changes"]["diff"]["lines"].update(added=-1),
    lambda d: d["changes"]["diff"]["by_type"][0].update(sloc=1),
    lambda d: d["changes"]["diff"].update(compare_url="http://example.com"),
])
def test_the_schema_refuses_a_malformed_manifest(change):
    pytest.importorskip("fastjsonschema")
    d = copy.deepcopy(example())
    change(d)
    assert m.validate(d) is not None


def _no_platform(arch):
    def f(d):
        del d["image"]["platforms"][arch]
    return f


@pytest.mark.parametrize("change", [
    lambda d: d.update(image=None),
    lambda d: d.update(comparison_image=None),
    _no_platform("amd64"),
    _no_platform("arm64"),
    lambda d: d.update(changelog=None),
    lambda d: d.update(summary=None),
    lambda d: d.update(approvals=[]),
    lambda d: d["approvals"][0].update(state="rejected"),
    lambda d: d["approvals"][0].update(environment="staging"),
])
def test_a_real_release_must_name_its_image_changelog_summary_and_approval(change):
    # These were each allowed whatever the run, so a publish output that came through empty on
    # a tag made a valid manifest saying the image wasn't published (#161).
    pytest.importorskip("fastjsonschema")
    d = copy.deepcopy(example())
    assert d["release"]["dry_run"] is False and m.validate(d) is None
    change(d)
    assert m.validate(d) is not None


def test_a_base_image_may_ship_more_platforms_than_ours():
    # #121's re-pinned bases list linux/s390x too, and the manifest refused the base record
    # (#171). Ours stay exactly amd64 and arm64.
    pytest.importorskip("fastjsonschema")
    d = copy.deepcopy(example())
    d["base_images"][0]["platforms"]["s390x"] = "sha256:" + "9" * 64
    assert m.validate(d) is None
    del d["base_images"][0]["platforms"]["arm64"]
    assert m.validate(d) is not None
    d = copy.deepcopy(example())
    d["base_images"][0]["platforms"]["s390x"] = "not a digest"
    assert m.validate(d) is not None
    d = copy.deepcopy(example())
    d["image"]["platforms"]["s390x"] = "sha256:" + "9" * 64
    assert m.validate(d) is not None


def test_manifests_from_before_the_line_counts_still_validate():
    # 1.0.0 to 1.2.0 were published without changes.diff (#224); the schema still takes them.
    pytest.importorskip("fastjsonschema")
    d = copy.deepcopy(example())
    del d["changes"]["diff"]
    assert m.validate(d) is None
    d["changes"]["diff"] = None
    assert m.validate(d) is None


def test_a_dry_run_may_have_no_image_changelog_summary_or_approval():
    pytest.importorskip("fastjsonschema")
    d = copy.deepcopy(example())
    d["release"]["dry_run"] = True
    d.update(image=None, changelog=None, summary=None, approvals=[])
    assert m.validate(d) is None


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
    ("wd2l-1.0.0-provenance.json", "provenance"), ("wd2l-1.0.0-provenance-ubi9.json", "provenance"),
    ("base-image-record.json", "base-image-record"),
    ("cosign.pub", "public-key"), ("wd2l-1.0.0-source.bundle", "source-bundle"),
    ("wd2l-1.0.0-changelog.md", "changelog"), ("wd2l-1.0.0-verify-release.py", "verification-script"),
    ("wd2l-1.0.0-sbom.html", "sbom-report"), ("base-image-record-ubi9.json", "base-image-record"),
    ("wd2l-1.0.0-image-ubi9-amd64-oci.tar", "oci-image"), ("wd2l-1.0.0-image-ubi9-amd64.spdx.json", "sbom"),
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
               [os.path.join("packaging", "ci", "tools.Containerfile"), "cosign.pub", "cliff.toml"]:
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


def sha(cwd, ref):
    return subprocess.run(("git", "rev-parse", ref), cwd=cwd, check=True, capture_output=True,
                          text=True).stdout.strip()


@needs_git
def test_lines_added_modified_and_deleted_since_the_previous_release(tmp_path):
    # A plain count of lines, not SLOC (#224): per hunk, the lines both added and removed are
    # modified, and the rest are added or deleted.
    r = tmp_path / "r"
    (r / "docs").mkdir(parents=True)
    (r / "app.py").write_text("a\nb\nc\n")
    (r / "site.yml").write_text("- hosts: all\n  roles: [wd2l]\n  become: true\n")
    (r / "docs" / "old name.txt").write_text("".join("line %d\n" % i for i in range(10)))
    (r / "logo.png").write_bytes(b"\x89PNG\0\0\0")
    run_git(r, "init", "-q")
    run_git(r, "add", "-A")
    run_git(r, "commit", "-q", "-m", "one")
    run_git(r, "tag", "v1.0.0")
    (r / "app.py").write_text("A\nB\nc\nd\n")                     # 2 modified, then 1 added
    (r / "site.yml").unlink()                                      # 3 deleted
    (r / "Containerfile").write_text("FROM x\nRUN y\n")            # 2 added, no extension
    os.rename(r / "docs" / "old name.txt", r / "docs" / "new name.txt")
    (r / "docs" / "new name.txt").write_text(
        "".join(("line %d\n" % i) if i != 5 else "five\n" for i in range(10)))   # 1 modified
    (r / "logo.png").write_bytes(b"\x89PNG\0\0\1")                 # binary: a file, no lines
    run_git(r, "add", "-A")
    run_git(r, "commit", "-q", "-m", "two")
    base, head = sha(r, "v1.0.0"), sha(r, "HEAD")
    d = m.diff_stats({"tag": "v1.0.0", "commit": base}, head, "https://github.com/o/r", cwd=str(r))
    assert d["base"] == {"tag": "v1.0.0", "commit": base} and d["head"] == head
    assert d["compare_url"] == "https://github.com/o/r/compare/%s...%s" % (base, head)
    assert d["files_changed"] == 5 and d["binary_files"] == 1
    assert d["lines"] == {"added": 3, "modified": 3, "deleted": 3}
    assert {t["type"]: (t["files"], t["added"], t["modified"], t["deleted"]) for t in d["by_type"]} == {
        ".py": (1, 1, 2, 0), ".yml": (1, 0, 0, 3), "Containerfile": (1, 2, 0, 0),
        ".txt": (1, 0, 1, 0), ".png": (1, 0, 0, 0)}
    # Most lines first, then by name: the same order every time.
    assert [t["type"] for t in d["by_type"]] == [".py", ".yml", "Containerfile", ".txt", ".png"]
    # It agrees with git's own totals: insertions = added + modified, deletions = modified + deleted.
    short = subprocess.run(("git", "diff", "--shortstat", "-M", base, head), cwd=str(r), check=True,
                           capture_output=True, text=True).stdout
    L = d["lines"]
    assert "5 files changed, %d insertions(+), %d deletions(-)" % (
        L["added"] + L["modified"], L["modified"] + L["deleted"]) in short


@pytest.mark.parametrize("path, kind", [
    ("wd2l/receiver.py", ".py"), ("site.YML", ".yml"), ("LICENSE", "LICENSE"), (".gitignore", ".gitignore"),
    ("docs/old name.txt", ".txt"),
    # Container build files are one type, whatever their variant (#226).
    ("packaging/container/Containerfile", "Containerfile"),
    ("packaging/container/Containerfile.ubi9", "Containerfile"),
    ("packaging/ci/tools.Containerfile", "Containerfile"),
    ("Dockerfile.dev", "Dockerfile"), ("build/dockerfile", "Dockerfile"),
    ("packaging/quadlet/wd2l-receiver.container", ".container"),
])
def test_each_file_has_one_type(path, kind):
    assert m.file_type(path) == kind


@needs_git
def test_no_changes_since_the_previous_release_count_nothing(tmp_path):
    r = make_repo(tmp_path)          # only empty commits after v0.3.0
    base = sha(r, "v0.3.0")
    d = m.diff_stats({"tag": "v0.3.0", "commit": base}, sha(r, "HEAD"), "https://github.com/o/r", cwd=str(r))
    assert d["files_changed"] == 0 and d["by_type"] == []
    assert d["lines"] == {"added": 0, "modified": 0, "deleted": 0}


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
                                           "platforms": {"amd64": "sha256:" + "2" * 64,
                                                         "arm64": "sha256:" + "6" * 64},
                                           "release": "1", "source_image": "registry.example/python:1-source"}]}))
    rec9 = tmp_path / "base-image-record-ubi9.json"
    rec9.write_text(json.dumps({"images": [{"stage": "runtime", "ref": "registry.example/ubi9/ubi:latest@sha256:" + "7" * 64,
                                            "index_digest": "sha256:" + "7" * 64,
                                            "platforms": {"amd64": "sha256:" + "8" * 64, "arm64": "sha256:" + "9" * 64},
                                            "release": "1791888712", "source_image": None, "provenance": None}]}))
    d = "sha256:" + "3" * 64
    changelog = None
    if not dry_run:
        changelog = assets / "wd2l-1.0.0rc1-changelog.md"
        changelog.write_text("# Changelog\n")
    return argparse.Namespace(assets=str(assets), base_record=str(rec), dry_run=dry_run,
                              image_digest=d if digests else "",
                              platform_digest=(["amd64=sha256:" + "4" * 64, "arm64=sha256:" + "5" * 64]
                                               if digests else ["amd64=", "arm64="]),
                              comparison_digest="sha256:" + "a" * 64 if digests else "",
                              comparison_base_record=str(rec9),
                              changelog=changelog and str(changelog))


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
    assert [d["name"] for d in doc["deliverables"]] == ["cosign.pub", "wd2l-1.0.0rc1-changelog.md",
                                                      "wd2l-1.0.0rc1-py3-none-any.whl"]
    assert doc["verification"]["sealed_by"][-1] == "wd2l-1.0.0rc1-attestations.jsonl"
    # The comparison image (#192): its own name and digest, one platform, its base, its purpose.
    ci = doc["comparison_image"]
    assert ci["name"] == "ghcr.io/joehazurmoney/wd2l-ubi9" and ci["digest"] == "sha256:" + "a" * 64
    assert ci["tags"] == ["1.0.0rc1"] and ci["platform"] == "linux/amd64"
    assert ci["base_images"][0]["release"] == "1791888712" and ci["base_images"][0]["source_image"] is None
    assert "not hardened" in ci["purpose"] and "not FIPS" in ci["purpose"]
    # The line counts (#224) start where the changes do: the previous final release.
    diff = doc["changes"]["diff"]
    assert diff["base"] == doc["source"]["previous_release"] and diff["head"] == doc["source"]["commit"]
    assert diff["compare_url"] == "https://github.com/o/r/compare/%s...%s" % (
        doc["source"]["previous_release"]["commit"], doc["source"]["commit"])


@needs_git
def test_a_dry_run_has_no_image_and_asks_for_no_approvals(tmp_path):
    pytest.importorskip("fastjsonschema")
    r = make_repo(tmp_path, summary=False)
    doc = m.generate(gen_args(tmp_path, dry_run=True, digests=False), {}, forge_for_repo(), repo=str(r))
    assert m.validate(doc) is None
    assert doc["image"] is None and doc["approvals"] == [] and doc["summary"] is None
    assert doc["comparison_image"] is None
    assert doc["release"]["dry_run"] and doc["generated"]["run"] is None


@needs_git
def test_without_a_final_release_there_is_nothing_to_count_from(tmp_path):
    pytest.importorskip("fastjsonschema")
    r = make_repo(tmp_path, final_tag=False)
    doc = m.generate(gen_args(tmp_path), RUN_ENV, forge_for_repo(), repo=str(r))
    assert m.validate(doc) is None and doc["changes"]["diff"] is None
    assert "## Lines changed\n\nNo earlier final release to compare with." in m.render(doc)


@needs_git
def test_a_tag_without_its_summary_is_refused_before_anything_else(tmp_path):
    r = make_repo(tmp_path, summary=False)
    with pytest.raises(SystemExit, match="docs/releases/1.0.0rc1.md"):
        m.generate(gen_args(tmp_path), RUN_ENV, forge_for_repo(), repo=str(r))


def _empty_platform(arch):
    def f(a, forge):
        a.platform_digest = [x for x in a.platform_digest if not x.startswith(arch)] + [arch + "="]
    return f


@needs_git
@pytest.mark.parametrize("change, missing", [
    (lambda a, forge: setattr(a, "image_digest", ""), "the image index digest"),
    (_empty_platform("amd64"), "the amd64 image digest"),
    (_empty_platform("arm64"), "the arm64 image digest"),
    (lambda a, forge: setattr(a, "comparison_digest", ""), "the comparison image digest"),
    (lambda a, forge: setattr(a, "changelog", None), "the changelog"),
    (lambda a, forge: setattr(forge, "appr", []), "an approval of the release gate"),
    (lambda a, forge: setattr(forge, "appr", [{"environment": "release", "user": "owner",
                                               "state": "rejected", "comment": ""}]),
     "an approval of the release gate"),
])
def test_a_tag_run_missing_what_publish_and_the_gate_give_is_refused(tmp_path, change, missing):
    # publish's outputs were passed through unchecked: an empty one on a tag made a manifest
    # that said the image wasn't published (#161).
    r = make_repo(tmp_path)
    a, forge = gen_args(tmp_path), forge_for_repo()
    change(a, forge)
    with pytest.raises(SystemExit, match="a release's manifest needs " + missing):
        m.generate(a, RUN_ENV, forge, repo=str(r))


# ---- the markdown view --------------------------------------------------------------------

@needs_git
def test_the_view_shows_the_comparison_image_as_not_for_deployment(tmp_path):
    r = make_repo(tmp_path)
    md = m.render(m.generate(gen_args(tmp_path), RUN_ENV, forge_for_repo(), repo=str(r)))
    section = md.split("## Comparison image", 1)[1].split("\n## ", 1)[0]
    assert "`ghcr.io/joehazurmoney/wd2l-ubi9@sha256:%s`" % ("a" * 64) in section
    assert "not hardened, not FIPS" in section and "Deploy `ghcr.io/joehazurmoney/wd2l`" in section
    assert "registry.example/ubi9/ubi:latest@sha256:" + "7" * 64 in section


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


def test_the_view_counts_the_lines_and_links_the_full_diff():
    d = example()
    diff = d["changes"]["diff"]
    md = m.render(d)
    section = md.split("## Lines changed since v1.0.0", 1)[1].split("\n## ", 1)[0]
    assert "[compare on the forge](%s)" % diff["compare_url"] in section
    assert "`git diff %s %s`" % (diff["base"]["commit"], diff["head"]) in section
    assert "not SLOC" in section
    assert "| `.py` | 3 | 1,207 | 18 | 2 |" in section
    assert "| **Total** | **9** | **1,602** | **41** | **7** |" in section
    assert md.index("## Lines changed since") < md.index("## Changes (")
    del d["changes"]["diff"]                       # a manifest from before #224
    assert "## Lines changed" not in m.render(d)


def test_every_version_has_its_release_summary():
    # A tag can't be released without docs/releases/<version>.md: the assets job refuses, after
    # publish has run. So the version bump's PR fails here first.
    v = load_script("packaging/release/versions.py").read_version()
    assert os.path.exists(os.path.join(REPO, "docs", "releases", "%s.md" % v)), v


def test_the_changelog_record_names_git_cliffs_pinned_image_and_the_config(tmp_path):
    f = tmp_path / "wd2l-1.0.0-changelog.md"
    f.write_text("# Changelog\n")
    rec = m.changelog_record(str(f), REPO)
    assert rec["file"] == "wd2l-1.0.0-changelog.md" and rec["tool"]["name"] == "git-cliff"
    assert rec["tool"]["image"].startswith("docker.io/orhunp/git-cliff:" + rec["tool"]["version"] + "@sha256:")
    assert len(rec["config_sha256"]) == 64


@needs_git
def test_a_manifest_with_a_changelog_is_valid_and_lists_it(tmp_path):
    pytest.importorskip("fastjsonschema")
    r = make_repo(tmp_path)
    a = gen_args(tmp_path)
    (tmp_path / "assets" / "wd2l-1.0.0rc1-changelog.md").write_text("# Changelog\n")
    a.changelog = str(tmp_path / "assets" / "wd2l-1.0.0rc1-changelog.md")
    doc = m.generate(a, RUN_ENV, forge_for_repo(), repo=str(r))
    assert m.validate(doc) is None
    assert doc["changelog"]["file"] == "wd2l-1.0.0rc1-changelog.md"
    assert {"changelog"} <= {d["kind"] for d in doc["deliverables"]}
    assert "The changelog, grouped by commit type, is `wd2l-1.0.0rc1-changelog.md`." in m.render(doc)


@needs_git
def test_previous_release_is_the_last_final_tag_before_this_one(tmp_path):
    r = make_repo(tmp_path)
    assert m.previous_release("v1.0.0rc1", cwd=str(r)) == "v0.3.0"
    assert m.previous_release("v1.0.0rc1", cwd=str(make_repo(tmp_path / "b", final_tag=False))) is None


# ---- the HTML view (#202) -----------------------------------------------------------------
# The same sections as the markdown, from the same blocks, as one page that loads nothing.

import html as _html  # noqa: E402
import re as _re  # noqa: E402


def _md_headings_and_rows(md):
    lines, fenced = [], False
    for l in md.splitlines():                  # a "# comment" in a code block is no heading
        if l.startswith("```"):
            fenced = not fenced
        elif not fenced:
            lines.append(l)
    heads = [l.lstrip("#").strip() for l in lines if _re.match(r"#{1,3} ", l)]
    rows = [l for l in lines if l.startswith("|") and not _re.match(r"\|(-+\|)+$", l)]
    return heads, len(rows)


def _html_headings_and_rows(page):
    heads = [_html.unescape(_re.sub(r"<[^>]+>", "", h)).strip()
             for h in _re.findall(r"<h[123][^>]*>(.*?)</h[123]>", page)]
    return heads, len(_re.findall(r"<tr>", page))


@pytest.mark.parametrize("dry", [False, True])
def test_the_html_and_the_markdown_have_the_same_sections_and_table_rows(dry):
    d = example()
    if dry:
        d["release"]["dry_run"], d["image"], d["approvals"] = True, None, []
    md_heads, md_rows = _md_headings_and_rows(m.render(d))
    html_heads, html_rows = _html_headings_and_rows(m.render_html(d))
    # The markdown's headings and backticks are plain text in the page.
    assert [h.replace("`", "") for h in md_heads] == html_heads and md_rows == html_rows


def test_the_html_page_links_each_section_and_names_the_record():
    page = m.render_html(example())
    v = example()["release"]["version"]
    assert page.startswith("<!doctype html>") and "<title>wd2l %s: release manifest</title>" % v in page
    nav = page.split('<nav', 1)[1].split("</nav>", 1)[0]
    for h in ("Issues resolved", "Known issues", "Deliverables", "Container image", "Build environment",
              "Approvals", "Verifying this release"):
        assert h in nav, h
    assert "<code>wd2l-%s-release-manifest.json</code> is the authoritative record" % v in page
    assert '<a href="wd2l-%s-sbom.html">' % v in page            # the pair read as one set


def test_forge_text_is_escaped_in_the_html():
    d = example()
    evil = '<script>alert("x")</script> & [a](javascript:x) `y` **z**'
    d["changes"]["issues_resolved"][0]["title"] = evil
    d["changes"]["pull_requests"][0]["title"] = evil
    page = m.render_html(d)
    assert "<script" not in page                              # shown as text, never run
    assert page.count(_html.escape(evil, quote=True)) == 2
    assert 'href="javascript' not in page and "<b>z</b>" not in page and "<code>y</code>" not in page


def test_the_html_page_loads_nothing_and_links_only_plainly():
    page = m.render_html(example())
    assert "<script" not in page and " src=" not in page
    assert "default-src 'none'" in page                       # a Content-Security-Policy, like the SBOM page
    for href in _re.findall(r'href="([^"]*)"', page):
        assert href.startswith("https://") or href.startswith("#") or _re.match(r"wd2l-[^/]+-sbom\.html$", href), href


def test_the_html_page_keeps_table_headers_with_their_rows_in_print():
    page = m.render_html(example())
    assert "thead{display:table-header-group}" in page and "tr{break-inside:avoid}" in page


def test_render_writes_either_format(tmp_path, capsys):
    path = tmp_path / "m.json"
    path.write_text(json.dumps(example()))
    assert m.main(["render", str(path)]) == 0
    assert capsys.readouterr().out == m.render(example())
    assert m.main(["render", "--format", "html", str(path)]) == 0
    assert capsys.readouterr().out == m.render_html(example())
