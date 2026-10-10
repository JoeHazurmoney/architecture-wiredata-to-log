#!/usr/bin/env python3
"""Rewrites the deploy/ tree for the RPM's paths (packaging/rpm/wd2l.spec runs it in %build):

* units: scripts move from /opt/wd2l/deploy/<side>/x.sh to LIBEXEC/x.sh, and the
  PYTHONPATH=/opt/wd2l line goes (the code is in Python's site-packages);
* auditd rules: /opt/wd2l/ becomes SITELIB/wd2l/ and LIBEXEC/; each watched unit is also
  watched where the RPM puts it (UNITDIR) and in its drop-in directory;
* everything else is copied unchanged. Nothing written may still name /opt/wd2l.

    rpmify.py --sitelib DIR --libexec DIR --unitdir DIR SRC_DEPLOY OUT
    rpmify.py --drop-in-dirs RULES...      print the drop-in dirs the rules watch"""

import argparse
import os
import re
import shutil
import sys
from typing import List, Optional, Sequence

SCRIPT = re.compile(r"/opt/wd2l/deploy/[A-Za-z0-9_-]+/([A-Za-z0-9_.-]+\.sh)")
PYTHONPATH = re.compile(r"^Environment=PYTHONPATH=/opt/wd2l[ \t]*\n", re.M)
UNIT_WATCH = re.compile(r"^-w /etc/systemd/system/(\S+) -p wa -k (\S+)$")
DROP_IN = re.compile(r"^-w (/etc/systemd/system/\S+\.d)/ ")
CODE_WATCH = "-w /opt/wd2l/ -p wa -k wd2l-code"


def rewrite_unit(text: str, libexec: str) -> str:
    return SCRIPT.sub(lambda m: "%s/%s" % (libexec, m.group(1)), PYTHONPATH.sub("", text))


def rewrite_rules(text: str, sitelib: str, libexec: str, unitdir: str) -> str:
    out = []
    for line in text.splitlines():
        if line == CODE_WATCH:
            out += ["-w %s/wd2l/ -p wa -k wd2l-code" % sitelib, "-w %s/ -p wa -k wd2l-code" % libexec]
            continue
        m = UNIT_WATCH.match(line)
        if m:
            unit, key = m.groups()
            out += [line, "-w %s/%s -p wa -k %s" % (unitdir, unit, key),
                    "-w /etc/systemd/system/%s.d/ -p wa -k %s" % (unit, key)]
            continue
        out.append(line)
    return "\n".join(out) + "\n"


def drop_in_dirs(rules_text: str) -> List[str]:
    return [m.group(1) for m in map(DROP_IN.match, rules_text.splitlines()) if m]


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


def rpmify(src: str, out: str, sitelib: str, libexec: str, unitdir: str) -> List[str]:
    written = []
    for dirpath, _dirs, files in os.walk(src):
        for name in sorted(files):
            s = os.path.join(dirpath, name)
            rel = os.path.relpath(s, src).replace(os.sep, "/")
            d = os.path.join(out, rel)
            os.makedirs(os.path.dirname(d), exist_ok=True)
            if name.endswith((".service", ".timer")):
                text: Optional[str] = rewrite_unit(_read(s), libexec)
            elif name == "wd2l.rules":
                text = rewrite_rules(_read(s), sitelib, libexec, unitdir)
            else:
                text = None
            if text is None:
                shutil.copy2(s, d)
            else:
                with open(d, "w", encoding="utf-8") as f:
                    f.write(text)
                shutil.copymode(s, d)
            written.append(rel)
    left = [r for r in written if "/opt/wd2l" in _read(os.path.join(out, r))]
    if left:
        raise SystemExit("rpmify: these still name /opt/wd2l: %s" % ", ".join(left))
    return sorted(written)


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Rewrite deploy/ for the RPM's paths.")
    p.add_argument("--sitelib")
    p.add_argument("--libexec")
    p.add_argument("--unitdir")
    p.add_argument("--drop-in-dirs", nargs="+", metavar="RULES")
    p.add_argument("src", nargs="?")
    p.add_argument("out", nargs="?")
    a = p.parse_args(argv)
    if a.drop_in_dirs:
        for r in a.drop_in_dirs:
            print("\n".join(drop_in_dirs(_read(r))))
        return 0
    if not (a.sitelib and a.libexec and a.unitdir and a.src and a.out):
        p.error("needs --sitelib, --libexec, --unitdir, SRC and OUT")
    for rel in rpmify(a.src, a.out, a.sitelib, a.libexec, a.unitdir):
        print("rpmify: " + rel)
    return 0


if __name__ == "__main__":
    sys.exit(main())
