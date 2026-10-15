"""Checks over the whole run. With WD2L_NO_SKIPS=1, as CI sets it, a run in which any test
skipped fails: a missing tool or package (git, fastjsonschema) would otherwise turn tests off
with CI green (#122). Developers' runs are unchanged."""
import os
import sys

_skipped = []


def pytest_collectreport(report):
    if report.skipped:                     # a whole module, e.g. importorskip at the top
        _skipped.append(report)


def pytest_runtest_logreport(report):
    if report.skipped and not hasattr(report, "wasxfail"):    # an expected failure isn't a skip
        _skipped.append(report)


def pytest_sessionfinish(session, exitstatus):
    if os.environ.get("WD2L_NO_SKIPS") != "1" or exitstatus != 0 or not _skipped:
        return
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    for rep in _skipped:
        why = rep.longrepr[2] if isinstance(rep.longrepr, tuple) else rep.longrepr
        line = "WD2L_NO_SKIPS: %s skipped (%s)" % (rep.nodeid, why)
        if reporter:
            reporter.write_line(line, red=True)
        else:
            print(line, file=sys.stderr)
    session.exitstatus = 1
