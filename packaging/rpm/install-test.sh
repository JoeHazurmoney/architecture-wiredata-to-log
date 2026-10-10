#!/usr/bin/env bash
# The RPMs' install test, run as root in a fresh UBI container (.github/workflows/rpm.yml):
#   install-test.sh fresh|over-manual|upgrade REL1_DIR [REL2_DIR]
#   fresh        install the three packages on a clean system
#   over-manual  first make what the manual install made (the wd2l user and group, an edited
#                /etc/wd2l/sender.env), then install: nothing fails and the edit stays
#   upgrade      install Release 1, edit sender.env, upgrade to Release 2: the edit stays
# Runs from the repo root, so python3 runs with -I: the checkout's wd2l/ must not be imported.
set -euo pipefail
leg="$1"; rel1="$2"; rel2="${3:-}"
fail() { echo "FAIL ($leg): $*" >&2; exit 1; }
EDIT='WD2L_SENDER_ARGS="--listen 127.0.0.1:9999"'
case "$leg" in
  fresh)
    dnf install -y -q "$rel1"/*.noarch.rpm ;;
  over-manual)
    dnf install -y -q shadow-utils
    groupadd -r wd2l && useradd -r -g wd2l -s /sbin/nologin wd2l && groupadd -r wd2l-audit
    install -d /etc/wd2l && echo "$EDIT" > /etc/wd2l/sender.env
    dnf install -y -q "$rel1"/*.noarch.rpm
    grep -qxF "$EDIT" /etc/wd2l/sender.env || fail "the edited sender.env was replaced"
    [ -f /etc/wd2l/sender.env.rpmnew ] || fail "no sender.env.rpmnew beside the edited file" ;;
  upgrade)
    dnf install -y -q "$rel1"/*.noarch.rpm
    echo "$EDIT" > /etc/wd2l/sender.env
    dnf upgrade -y -q "$rel2"/*.noarch.rpm
    rpm -q --qf '%{RELEASE}\n' wd2l | grep -q '^2\.' || fail "not upgraded: $(rpm -q wd2l)"
    grep -qxF "$EDIT" /etc/wd2l/sender.env || fail "the upgrade replaced the edited sender.env" ;;
  *) fail "unknown leg" ;;
esac
for c in wd2l-sender wd2l-receiver wd2l-audit-report; do "$c" --help >/dev/null || fail "$c --help"; done
python3 -I -c 'import sys, wd2l; sys.exit(0 if wd2l.__file__.startswith("/usr/lib/python3") else 1)' \
  || fail "wd2l isn't in the system site-packages"
python3 -I -c 'import sys; from wd2l import hostinfo; sys.exit(0 if hostinfo.build_id() != "unknown" else 1)' \
  || fail "wd2l/BUILD is missing"
getent passwd wd2l >/dev/null || fail "no wd2l user"
getent group wd2l-audit >/dev/null || fail "no wd2l-audit group"
mode() { stat -c '%a %U %G' "$1"; }
[ "$(mode /var/log/wd2l)" = "2750 wd2l wd2l-audit" ] || fail "/var/log/wd2l is $(mode /var/log/wd2l)"
[ "$(mode /etc/wd2l)" = "750 root wd2l" ] || fail "/etc/wd2l is $(mode /etc/wd2l)"
for d in /var/lib/wd2l /var/lib/wd2l/spool /var/lib/wd2l/pcap; do
  [ "$(mode "$d")" = "750 wd2l wd2l" ] || fail "$d is $(mode "$d")"
done
d=$(mktemp -d)
if python3 -I -m wd2l.audit verify "$d" >/dev/null 2>&1; then fail "an empty audit directory verified"; fi
out=$(rpm -V wd2l wd2l-sender wd2l-receiver | grep -v ' c /etc/wd2l/' || true)
[ -z "$out" ] || fail "rpm -V: $out"
if grep -rl /opt/wd2l /usr/lib/systemd/system/wd2l-* /usr/share/wd2l/audit /usr/share/wd2l/quadlet; then
  fail "/opt/wd2l is still named"
fi
[ -f /usr/lib/sysctl.d/90-wd2l.conf ] || fail "no sysctl file"
systemd-analyze verify /usr/lib/systemd/system/wd2l-*.service /usr/lib/systemd/system/wd2l-*.timer \
  || fail "systemd-analyze verify"
echo "install test ($leg): ok"
