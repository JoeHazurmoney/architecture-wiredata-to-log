"""Every relative link in the user docs points at a file that exists, and every #anchor at a
heading in it (GitHub's slugs). docs/superpowers (working plans) is left out."""
import os
import re

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
LINK = re.compile(r"\]\(([^)\s]+)\)")
HEADING = re.compile(r"^#{1,6} +(.+?) *#*$", re.M)
FENCE = re.compile(r"^```.*?^```", re.M | re.S)
SKIP_DIRS = {".git", "superpowers", ".superpowers", "node_modules", "dist", "build", "out"}


def docs():
    for dirpath, dirs, files in os.walk(REPO):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            if f.endswith(".md"):
                yield os.path.join(dirpath, f)


def slug(heading):
    s = re.sub(r"[^\w\- ]", "", heading.strip().lower())
    return s.replace(" ", "-")


def anchors(path):
    with open(path, encoding="utf-8") as f:
        text = FENCE.sub("", f.read())
    seen, out = {}, set()
    for h in HEADING.findall(text):
        base = slug(h)
        n = seen.get(base, 0)
        out.add(base if n == 0 else "%s-%d" % (base, n))
        seen[base] = n + 1
    return out


def test_every_relative_link_and_anchor_resolves():
    bad = []
    for path in docs():
        with open(path, encoding="utf-8") as f:
            text = FENCE.sub("", f.read())
        for target in LINK.findall(text):
            if re.match(r"^[a-z]+:", target):
                continue
            file_part, _, anchor = target.partition("#")
            dest = path if not file_part else os.path.normpath(os.path.join(os.path.dirname(path), file_part))
            rel = os.path.relpath(path, REPO)
            if not os.path.exists(dest):
                bad.append("%s: %s (no such file)" % (rel, target))
            elif anchor and dest.endswith(".md") and anchor not in anchors(dest):
                bad.append("%s: %s (no such heading)" % (rel, target))
    assert not bad, "\n".join(bad)
