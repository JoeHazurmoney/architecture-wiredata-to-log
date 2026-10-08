#!/usr/bin/env bash
# Builds the wd2l RPMs inside a UBI container (.github/workflows/rpm.yml), from the repo root
# with dist/ holding the sdist and wheel:
#   build-rpms.sh PYVERSION RPMVERSION
# Writes rpms/rel1 (what a release ships) and rpms/rel2 (the same sources as Release 2, for the
# upgrade test). rpmlint (where the UBI has it) is advisory.
set -euo pipefail
PY="$1"; RPMV="$2"
dnf install -y -q rpm-build python3-devel python3-pip systemd-rpm-macros
dnf install -y -q rpmlint >/dev/null 2>&1 || true
for rel in 1 2; do
  top="$(mktemp -d)"; mkdir -p "$top/SOURCES"
  cp "dist/wd2l-$PY.tar.gz" "dist/wd2l-$PY-py3-none-any.whl" "$top/SOURCES/"
  rpmbuild -ba --define "_topdir $top" --define "wd2l_pyversion $PY" --define "wd2l_rpmversion $RPMV" \
    --define "rel $rel" packaging/rpm/wd2l.spec
  mkdir -p "rpms/rel$rel"
  cp "$top"/RPMS/noarch/*.rpm "$top"/SRPMS/*.rpm "rpms/rel$rel/"
done
if command -v rpmlint >/dev/null 2>&1; then rpmlint rpms/rel1/*.rpm || true; fi
ls -l rpms/rel1
