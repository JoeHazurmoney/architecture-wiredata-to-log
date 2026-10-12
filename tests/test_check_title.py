"""The commit convention (docs/releasing.md, "Conventions"): a squash merge's commit subject is
the PR title, so the title must be a Conventional Commit. pr-title.yml blocks a PR whose title
isn't one; tests.yml warns if one lands on main anyway (a title edited after the check)."""

import io
import os
import re

import pytest

from helpers import load_script

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
WORKFLOWS = os.path.join(REPO, ".github", "workflows")
title = load_script("packaging/ci/check_title.py")


def read(*parts):
    with open(os.path.join(REPO, *parts), encoding="utf-8") as f:
        return f.read()


@pytest.mark.parametrize("ok", [
    "feat: release manifest",
    "fix(receiver): keep the spool on a full disk",
    "feat(release)!: drop the 0.2 manifest format",
    "build(deps): bump hi/grype from 0.119 to 0.120 in /packaging/ci",
    "security: pin the base image by digest",
    "docs: ADR-0008 release manifest (#64)",     # GitHub appends (#N) to what lands
    "chore(release): 1.0.0",
    "revert: feat: release manifest",
])
def test_conventional_titles_pass(ok):
    assert title.check(ok) is None


@pytest.mark.parametrize("bad, why", [
    ("Release manifest", "type"),
    ("Feat: release manifest", "type"),
    ("feature: release manifest", "feature"),
    ("feat:release manifest", "type"),
    ("feat: ", "type"),
    ("feat(): empty scope", "type"),
    ("feat(Release): capital scope", "type"),
    ("WIP", "type"),
    ("", "empty"),
])
def test_other_titles_fail_and_say_why(bad, why):
    msg = title.check(bad)
    assert msg and why in msg
    if bad:
        assert "feat, fix, security" in msg   # the error names the allowed types


def test_the_types_are_the_ones_the_convention_lists():
    assert title.TYPES == ("feat", "fix", "security", "docs", "build", "ci", "test",
                           "refactor", "perf", "chore", "revert")


def test_cli_fails_a_bad_title_and_passes_a_good_one(capsys):
    assert title.main(["feat: x"]) == 0
    assert title.main(["not a commit"]) == 1
    assert "not a commit" in capsys.readouterr().err


def test_cli_warn_mode_never_fails_and_writes_a_github_warning(capsys):
    assert title.main(["--warn", "not a commit"]) == 0
    assert capsys.readouterr().out.startswith("::warning")


def test_cli_reads_the_subject_from_stdin(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("fix: one\n\nbody line\n"))
    assert title.main([]) == 0


def test_pr_title_workflow_passes_the_title_as_data_never_as_shell():
    wf = read(".github", "workflows", "pr-title.yml")
    assert "types: [opened, edited, synchronize, reopened]" in wf
    assert "TITLE: ${{ github.event.pull_request.title }}" in wf
    assert 'python3 packaging/ci/check_title.py "$TITLE"' in wf
    for run in re.findall(r"run: (.+)", wf):
        assert "${{" not in run, run     # an expression in run: is pasted into the shell
    assert "permissions:\n  contents: read" in wf and "secrets." not in wf


def test_main_warns_about_what_landed_without_failing_the_run():
    tests = read(".github", "workflows", "tests.yml")
    job = tests.split("\n  landed-title:\n", 1)[1].split("\n  ci-ok:\n", 1)[0]
    assert "github.event_name == 'push' && github.ref == 'refs/heads/main'" in job
    assert "git log -1 --format=%s | python3 packaging/ci/check_title.py --warn" in job
    assert "landed-title" not in tests.split("\n  ci-ok:\n", 1)[1]   # never blocks


def test_dependabot_titles_follow_the_convention():
    cfg = read(".github", "dependabot.yml")
    updates = cfg.count("package-ecosystem:")
    assert updates and cfg.count('prefix: "build"') == updates
    assert cfg.count('include: "scope"') == updates


def test_the_pr_template_asks_for_the_issue_it_closes():
    assert read(".github", "pull_request_template.md").startswith("Closes #")
