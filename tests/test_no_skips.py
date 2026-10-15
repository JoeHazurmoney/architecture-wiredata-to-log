"""WD2L_NO_SKIPS=1 (CI) fails a run in which any test skipped (tests/conftest.py, #122)."""
import os
import shutil
import subprocess
import sys

CONFTEST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conftest.py")


def run(tmp_path, body, no_skips):
    shutil.copy(CONFTEST, tmp_path / "conftest.py")
    (tmp_path / "test_x.py").write_text("import pytest\n\n" + body)
    env = {k: v for k, v in os.environ.items() if k != "WD2L_NO_SKIPS"}
    if no_skips:
        env["WD2L_NO_SKIPS"] = "1"
    return subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(tmp_path)],
                          cwd=str(tmp_path), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          universal_newlines=True)


SKIPS = ("def test_ok():\n    pass\n\n"
         "def test_needs_a_tool():\n    pytest.skip('needs git')\n\n"
         "def test_needs_a_package():\n    pytest.importorskip('no_such_module_wd2l')\n")


def test_a_skip_fails_the_run_and_is_named(tmp_path):
    r = run(tmp_path, SKIPS, no_skips=True)
    assert r.returncode == 1, r.stdout
    assert "WD2L_NO_SKIPS: test_x.py::test_needs_a_tool skipped (Skipped: needs git)" in r.stdout
    assert "test_x.py::test_needs_a_package skipped" in r.stdout and "no_such_module_wd2l" in r.stdout


def test_a_module_skipped_at_collection_fails_the_run(tmp_path):
    (tmp_path / "test_y.py").write_text("def test_ok():\n    pass\n")     # the rest of the suite
    r = run(tmp_path, "pytest.importorskip('no_such_module_wd2l')\n\ndef test_ok():\n    pass\n",
            no_skips=True)
    assert r.returncode == 1, r.stdout
    assert "WD2L_NO_SKIPS: test_x.py skipped" in r.stdout


def test_without_the_variable_a_skip_passes(tmp_path):
    r = run(tmp_path, SKIPS, no_skips=False)
    assert r.returncode == 0, r.stdout
    assert "WD2L_NO_SKIPS" not in r.stdout


def test_a_clean_run_passes_and_a_failure_still_fails(tmp_path):
    assert run(tmp_path, "def test_ok():\n    pass\n", no_skips=True).returncode == 0
    r = run(tmp_path, "def test_bad():\n    assert False\n\n"
                      "def test_skip():\n    pytest.skip('x')\n", no_skips=True)
    assert r.returncode == 1, r.stdout


def test_an_expected_failure_is_not_a_skip(tmp_path):
    r = run(tmp_path, "@pytest.mark.xfail(strict=True)\ndef test_known():\n    assert False\n",
            no_skips=True)
    assert r.returncode == 0, r.stdout
