"""The options tables in the deployment guides match the parsers (#152): every option is in its
guide's table, every option the table names exists, and a plain default (a value, a number with
its unit, none, off, "… on") is the parser's. Descriptive defaults ("the --live NIC") are left."""
import os
import re

import pytest

from wd2l import receiver, sender

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
GUIDES = [(sender, "log-server.md"), (receiver, "receiver.md")]
UNITS = {"s": 1, "KB": 1024, "MB": 1024 * 1024, "days": 86400}


def parser_options(mod):
    """--option -> its default, for every option but --help."""
    return {s: a.default for a in mod.build_parser()._actions for s in a.option_strings
            if s.startswith("--") and s != "--help"}


def table(guide):
    """The guide's options table as [(options, default cell)]."""
    with open(os.path.join(REPO, "docs", "deployment", guide), encoding="utf-8") as f:
        text = f.read()
    body = text.split("| Option | Default | Notes |", 1)[1].split("\n\n", 1)[0]
    rows = []
    for row in body.splitlines()[2:]:
        name, default, notes = (c.strip() for c in row.strip().strip("|").split("|", 2))
        # Options named in the first cell; a notes cell may name a lab-only one (--hec-insecure).
        opts = re.findall(r"`(--[a-z0-9-]+)", name)
        rows.append((opts, default, re.findall(r"`(--[a-z0-9-]+)` is for", notes)))
    return rows


def documented(guide):
    return {o for opts, _, extra in table(guide) for o in opts + extra}


def value(part):
    """A default cell's part as the parser would hold it, or None when it only describes it."""
    part = part.strip()
    if part in ("none",):
        return ("none",)
    if part == "off":
        return False
    if part.endswith(" on"):
        return True
    m = re.fullmatch(r"`?(\d+(?:\.\d+)?)`?(?: (s|KB|MB|days))?", part)
    if m:
        return float(m.group(1)) * UNITS.get(m.group(2), 1)
    m = re.fullmatch(r"`([^`]+)`", part)
    if m and not m.group(1).startswith("--"):   # another option's name describes, isn't a value
        return m.group(1)
    if re.fullmatch(r"[a-z]+", part) and part != "any":     # a bare word (text), not "any"
        return part
    return None


@pytest.mark.parametrize("mod, guide", GUIDES)
def test_every_option_is_in_its_guides_table(mod, guide):
    assert sorted(set(parser_options(mod)) - documented(guide)) == []


@pytest.mark.parametrize("mod, guide", GUIDES)
def test_every_option_the_table_names_exists(mod, guide):
    assert sorted(documented(guide) - set(parser_options(mod))) == []


@pytest.mark.parametrize("mod, guide", GUIDES)
def test_plain_defaults_are_the_parsers(mod, guide):
    defaults = parser_options(mod)
    checked = 0
    for opts, cell, _ in table(guide):
        if not cell:
            continue
        for opt, part in zip(opts, cell.split(", ")):
            want = value(part)
            if want is None:
                continue
            got = defaults[opt]
            if want == ("none",):
                assert got in (None, [], ""), (opt, cell, got)
            elif isinstance(want, float):
                assert float(got) == want, (opt, cell, got)
            else:
                assert got == want, (opt, cell, got)
            checked += 1
    assert checked >= 20, checked                 # the parsing still reads most rows
