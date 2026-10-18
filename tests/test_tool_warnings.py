"""Every warning a scanner or Syft logs is raised on the run, never failing it, unless a reviewed,
unexpired entry in tool-warnings.json expects it (#191, docs/decisions/0011-vulnerability-scanners.md)."""

import json
import os

from helpers import load_script

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
tw = load_script("packaging/container/tool_warnings.py")
TODAY = "2026-10-17"

# As the tools write them (Trivy 0.75; Grype 0.119 and Syft 1.54 share a format).
TRIVY_LOG = ("2026-10-18T03:12:52Z\tINFO\t[vulndb] Need to update DB\n"
             "2026-10-18T03:12:54Z\tWARN\tThird-party SBOM may lead to inaccurate vulnerability detection\n"
             "2026-10-18T03:12:54Z\tWARN\tUnsupported os\tfamily=\"none\"\n"
             "2026-10-18T03:12:54Z\tWARN\tUnsupported os\tfamily=\"none\"\n"
             "2026-10-18T03:12:55Z\tERROR\tfailed to analyze layer\tlayer=\"sha256:ab\"\n"
             "\n📣 Notices:\n  - Version 0.76.0 of Trivy is now available, current version is 0.75.0\n")
GRYPE_LOG = ("[0000]  INFO grype version: 0.119.0\n"
             "[0003]  WARN unable to determine the distro, skipping OS package matching\n"
             "[0004] ERROR failed to fetch latest version: context deadline exceeded\n")


def entry(tool, text, expires="2026-12-31", **kw):
    e = {"tool": tool, "text": text, "reason": "known", "expires": expires, "approved_by": "system owner"}
    e.update(kw)
    return e


def logs(tmp_path, **texts):
    out = []
    for name, text in texts.items():
        p = tmp_path / (name + ".log")
        p.write_text(text, encoding="utf-8")
        out.append((name, str(p)))
    return out


def run(tmp_path, known, **texts):
    k = tmp_path / "known.json"
    k.write_text(json.dumps({"warnings": known}))
    args = ["--known", str(k), "--today", TODAY, "--summary", str(tmp_path / "w.md")]
    for name, path in logs(tmp_path, **texts):
        args += ["--log", "%s=%s" % (name, path)]
    return args


def test_warning_and_error_lines_are_read_in_both_formats_once_each():
    found = tw.warnings_in("trivy", TRIVY_LOG) + tw.warnings_in("grype", GRYPE_LOG)
    assert found == [
        ("trivy", "WARN", "Third-party SBOM may lead to inaccurate vulnerability detection"),
        ("trivy", "WARN", 'Unsupported os family="none"'),
        ("trivy", "ERROR", 'failed to analyze layer layer="sha256:ab"'),
        ("grype", "WARN", "unable to determine the distro, skipping OS package matching"),
        ("grype", "ERROR", "failed to fetch latest version: context deadline exceeded"),
    ]


def test_a_new_warning_is_annotated_and_never_fails_the_run(tmp_path, capsys):
    assert tw.main(run(tmp_path, [], grype=GRYPE_LOG)) == 0
    out = capsys.readouterr().out.splitlines()
    assert out == ["::warning title=grype::WARN unable to determine the distro, skipping OS package matching",
                   "::warning title=grype::ERROR failed to fetch latest version: context deadline exceeded"]
    table = (tmp_path / "w.md").read_text()
    assert "| grype | WARN | unable to determine the distro, skipping OS package matching | new |" in table


def test_an_expected_warning_is_listed_but_not_annotated(tmp_path, capsys):
    known = [entry("trivy", 'Unsupported os family="none"', reason="Trivy has no Hummingbird data")]
    tw.main(run(tmp_path, known, trivy=TRIVY_LOG))
    out = capsys.readouterr().out
    assert "Unsupported os" not in out
    assert "::warning title=trivy::WARN Third-party SBOM may lead to inaccurate vulnerability detection" in out
    table = (tmp_path / "w.md").read_text()
    assert ('| trivy | WARN | Unsupported os family="none" | expected, reviewed until 2026-12-31: '
            'Trivy has no Hummingbird data |') in table


def test_an_entry_matches_only_its_own_tool(tmp_path, capsys):
    known = [entry("grype", 'Unsupported os family="none"')]
    tw.main(run(tmp_path, known, trivy=TRIVY_LOG))
    assert '::warning title=trivy::WARN Unsupported os family="none"' in capsys.readouterr().out


def test_an_expired_entry_raises_its_warning_again_and_asks_for_a_review(tmp_path, capsys):
    known = [entry("trivy", 'Unsupported os family="none"', expires="2026-10-16")]
    tw.main(run(tmp_path, known, trivy=TRIVY_LOG))
    out = capsys.readouterr().out
    assert ('::warning title=trivy::WARN Unsupported os family="none" (its review in tool-warnings.json '
            'expired on 2026-10-16: review it, then renew or remove it)') in out
    assert "| expired on 2026-10-16: review it |" in (tmp_path / "w.md").read_text()


def test_an_entry_for_more_than_90_days_is_not_accepted(tmp_path, capsys):
    known = [entry("trivy", 'Unsupported os family="none"', expires="2027-01-16")]     # TODAY + 91
    tw.main(run(tmp_path, known, trivy=TRIVY_LOG))
    out = capsys.readouterr().out
    assert '::warning title=trivy::WARN Unsupported os family="none"' in out
    assert "::warning title=tool-warnings.json::the entry for trivy" in out and "more than 90 days" in out
    known = [entry("trivy", 'Unsupported os family="none"', expires="2027-01-15")]     # TODAY + 90
    tw.main(run(tmp_path, known, trivy=TRIVY_LOG))
    assert "Unsupported os" not in capsys.readouterr().out


def test_an_incomplete_entry_is_raised_and_matches_nothing(tmp_path, capsys):
    known = [{"tool": "trivy", "text": "Unsupported os"}]
    tw.main(run(tmp_path, known, trivy=TRIVY_LOG))
    out = capsys.readouterr().out
    assert "::warning title=tool-warnings.json::the entry for trivy (Unsupported os) is missing reason, expires, approved_by" in out
    assert '::warning title=trivy::WARN Unsupported os family="none"' in out


def test_at_most_ten_annotations_the_rest_counted(tmp_path, capsys):
    many = "".join("[0001]  WARN warning number %d\n" % i for i in range(14))
    tw.main(run(tmp_path, [], syft=many))
    out = capsys.readouterr().out.splitlines()
    assert len(out) == 10
    assert out[:9] == ["::warning title=syft::WARN warning number %d" % i for i in range(9)]
    assert out[9] == "::warning title=Tool warnings::5 more, in this step's summary and the tools' logs"
    assert (tmp_path / "w.md").read_text().count("| new |") == 14


def test_text_is_escaped_for_annotations_and_the_table(tmp_path, capsys):
    tw.main(run(tmp_path, [], syft="[0001]  WARN 100% of a|b, done\r\n"))
    assert capsys.readouterr().out.strip() == "::warning title=syft::WARN 100%25 of a|b, done"
    assert "| syft | WARN | 100% of a\\|b, done | new |" in (tmp_path / "w.md").read_text()


def test_a_missing_log_is_raised_not_fatal(tmp_path, capsys):
    k = tmp_path / "known.json"
    k.write_text(json.dumps({"warnings": []}))
    rc = tw.main(["--known", str(k), "--today", TODAY, "--log", "grype=" + str(tmp_path / "none.log")])
    assert rc == 0
    assert capsys.readouterr().out.startswith("::warning title=grype::no log at ")


def test_no_warnings_says_so(tmp_path, capsys):
    tw.main(run(tmp_path, [], grype="[0000]  INFO grype version: 0.119.0\n"))
    assert capsys.readouterr().out == ""
    assert (tmp_path / "w.md").read_text() == "### Tool warnings\n\nNone.\n"


def test_the_committed_list_expects_trivy_s_warnings_on_both_images(tmp_path, capsys):
    # The Hardened image's three, and UBI 9's one (the comparison image, #192), as Trivy logs them.
    ubi9 = ("2026-10-18T04:02:11Z\tWARN\tUsing severities from other vendors for some vulnerabilities. "
            "Read https://trivy.dev/docs/v0.75/guide/scanner/vulnerability#severity-selection for details.\n")
    p = tmp_path / "trivy.log"
    p.write_text(TRIVY_LOG.replace("2026-10-18T03:12:55Z\tERROR\tfailed to analyze layer\tlayer=\"sha256:ab\"\n", "")
                 + ubi9, encoding="utf-8")
    tw.main(["--known", os.path.join(REPO, "packaging", "container", "tool-warnings.json"), "--today", TODAY,
             "--log", "trivy=" + str(p)])
    assert capsys.readouterr().out == ""


def test_the_committed_list_is_valid_and_each_entry_names_its_reason():
    with open(os.path.join(REPO, "packaging", "container", "tool-warnings.json"), encoding="utf-8") as f:
        doc = json.load(f)
    valid, problems = tw.load_known(doc, TODAY)
    assert problems == [] and len(valid) == len(doc["warnings"])
    assert all(len(e["reason"]) > 20 for e in valid)
