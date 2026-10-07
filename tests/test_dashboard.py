import json
import os
import re

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
DASH = os.path.join(REPO, "deploy", "receiver", "splunk", "wd2l-health-dashboard.json")
DOC = os.path.join(REPO, "docs", "state-of-health.md")


def load():
    with open(DASH, encoding="utf-8") as f:
        return json.load(f)


def test_references_resolve_and_everything_is_placed():
    d = load()
    ds, viz = d["dataSources"], d["visualizations"]
    for vid, v in viz.items():
        for ref in v.get("dataSources", {}).values():
            assert ref in ds, (vid, ref)
    for k, s in ds.items():
        if s["type"] == "ds.chain":
            assert s["options"]["extend"] in ds, k
        else:
            q = s["options"]["query"]
            assert "index=wd2l" in q or "index=enclave1" in q or "tstats" in q, k
    width = d["layout"]["options"]["width"]
    placed = {b["item"] for b in d["layout"]["structure"]}
    assert set(viz) <= placed
    for b in d["layout"]["structure"]:
        p = b["position"]
        assert 0 <= p["x"] and p["x"] + p["w"] <= width, b["item"]


def test_dashboard_panels_match_the_state_of_health_page():
    with open(DOC, encoding="utf-8") as f:
        doc_titles = set(re.findall(r"^\| *\d+[a-z]? *\| \*\*(.+?)\*\* \|", f.read(), re.M))
    titles = {v["title"] for v in load()["visualizations"].values() if v.get("title")}
    assert doc_titles and titles == doc_titles, (sorted(doc_titles - titles), sorted(titles - doc_titles))


def test_only_the_review_panel_reads_the_audit_index():
    d = load()
    readers = [k for k, s in d["dataSources"].items()
               if "wd2l_audit" in s["options"].get("query", "")]
    assert readers == ["ds_audit_review"]


def test_single_values_colour_every_state_their_source_can_emit():
    viz = load()["visualizations"]
    expected = {
        "viz_status": {"OK", "AMBER", "RED", "UNKNOWN"},
        "viz_time": {"OK", "ALARM", "UNKNOWN"},
        "viz_reconcile": {"OK", "RED"},
        "viz_audit": {"OK", "RED"},
    }
    for vid, states in expected.items():
        matches = {m["match"] for m in viz[vid]["context"]["statusColors"]}
        assert states <= matches, (vid, sorted(states - matches))
