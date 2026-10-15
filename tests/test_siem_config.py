import configparser
import glob
import os
import re

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SPLUNK = os.path.join(REPO, "deploy", "receiver", "splunk")


def conf(name):
    with open(os.path.join(SPLUNK, name)) as f:
        text = re.sub(r"\\\n", " ", f.read())
    cp = configparser.ConfigParser(interpolation=None, strict=False, delimiters=("=",))
    cp.optionxform = str
    cp.read_string(text)
    return cp


def test_every_alert_the_docs_name_exists():
    names = set(conf("savedsearches.conf").sections())
    named = set()
    for path in glob.glob(os.path.join(REPO, "docs", "**", "*.md"), recursive=True):
        with open(path, encoding="utf-8") as f:
            named |= set(re.findall(r'"(WD2L - [^"]+)"', f.read()))
    assert named and not named - names, sorted(named - names)


def test_new_alerts_and_review_report():
    s = conf("savedsearches.conf")
    for name in ("WD2L - Fault segment", "WD2L - Reconciliation not balanced",
                 "WD2L - Audit trail", "WD2L - Time quality"):
        assert "index=wd2l " in s[name]["search"] and "wd2l_audit" not in s[name]["search"]
    assert "index=wd2l_audit" in s["WD2L - Audit review (daily)"]["search"]


def test_reconciliation_alert_fires_only_without_open_gaps():
    """Final review I3: a stream with a permanent gap never balances again; open gaps are the
    "Events lost" alert's job, so this one fires only for the unexplained case."""
    search = conf("savedsearches.conf")["WD2L - Reconciliation not balanced"]["search"]
    assert "latest(gaps_open) as gaps_open" in search
    assert re.search(r"\| where balanced_checks=0 AND gaps_open=0\s*$", search), search


def test_tap_alert_watches_every_boundary_counter():
    """Final review follow-up: the alert covers what the receiver audits as boundary_anomaly."""
    from wd2l.receiver import BOUNDARY_COUNTERS
    search = conf("savedsearches.conf")["WD2L - Unexpected traffic or damage on the tap"]["search"]
    for name in ("other_packets", "bad_frames", "bad_events", "digest_mismatch", "records_bad"):
        assert name in BOUNDARY_COUNTERS
        assert "range(%s)" % name in search and "%s>0" % name in search, name


def test_daily_review_shows_the_sourcetype():
    """Final review I6: the reviewer can see which records came in-band from Enclave 1."""
    search = conf("savedsearches.conf")["WD2L - Audit review (daily)"]["search"]
    assert "sourcetype" in search.split("| table", 1)[1].split()


def test_audit_index_token_and_role():
    idx = conf("indexes.conf")
    assert idx["wd2l_audit"]["frozenTimePeriodInSecs"] == "31622400"
    inp = conf("inputs.conf")
    assert "wd2l_audit" not in inp["http://wd2l"]["indexes"]
    assert inp["http://wd2l_audit"]["indexes"] == "wd2l_audit"
    auth = conf("authorize.conf")
    assert "wd2l_audit" in auth["role_wd2l_auditor"]["srchIndexesAllowed"]
    for role in ("role_user", "role_power"):
        allowed = auth[role]["srchIndexesAllowed"]
        assert "wd2l_audit" not in allowed and "*" not in allowed


def test_json_parsing_for_every_wd2l_sourcetype():
    props = conf("props.conf")
    for st in ("wd2l:health", "wd2l:audit", "wd2l:sender:audit", "wd2l:sender:health"):
        assert props[st]["KV_MODE"] == "json"
