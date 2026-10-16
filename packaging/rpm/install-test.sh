#!/usr/bin/env bash
# The RPMs' install test, run as root in a fresh UBI container (.github/workflows/rpm.yml):
#   install-test.sh fresh|over-manual|upgrade REL1_DIR [REL2_DIR]
#   fresh        install the three packages on a clean system
#   over-manual  first make what the manual install made (the wd2l user and group, an edited
#                /etc/wd2l/sender.env), then install: nothing fails and the edit stays
#   upgrade      install Release 1, edit sender.env, upgrade to Release 2: the edit stays
#   remove       install, add what a site and a running wd2l make, then dnf remove: the code,
#                the units and the SELinux modules go; the audit trail, the state, the tokens,
#                the edited sender.env (as .rpmsave) and the wd2l user stay
# Runs from the repo root, so python3 runs with -I: the checkout's wd2l/ must not be imported.
set -euo pipefail
leg="$1"; rel1="$2"; rel2="${3:-}"
fail() { echo "FAIL ($leg): $*" >&2; exit 1; }
EDIT='WD2L_SENDER_ARGS="--listen 127.0.0.1:9999"'
case "$leg" in
  fresh)
    dnf install -y -q selinux-policy-targeted     # a policy store, so %post can load the label
    dnf install -y -q "$rel1"/*.noarch.rpm
    matchpathcon /var/lib/wd2l/pcap/cap-1.pcap | grep -q ':netutils_tmp_t:' \
      || fail "the capture archive isn't labelled for tcpdump: $(matchpathcon /var/lib/wd2l/pcap)"
    # Container mode's label (the targeted policy has container_file_t even without
    # container-selinux), and the archive keeps tcpdump's label once container-selinux is in.
    semodule -l | grep -qx wd2l_container || fail "the container-mode module isn't loaded"
    matchpathcon /var/lib/wd2l/state.json | grep -q ':container_file_t:' \
      || fail "/var/lib/wd2l isn't labelled for containers: $(matchpathcon /var/lib/wd2l/state.json)"
    dnf install -y -q container-selinux
    matchpathcon /var/lib/wd2l/state.json | grep -q ':container_file_t:' \
      || fail "with container-selinux /var/lib/wd2l isn't container_file_t: $(matchpathcon /var/lib/wd2l/state.json)"
    matchpathcon /var/lib/wd2l/pcap/cap-1.pcap | grep -q ':netutils_tmp_t:' \
      || fail "container-selinux took the capture archive's label" ;;
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
  remove)
    dnf install -y -q selinux-policy-targeted     # a policy store, so the modules load, then go
    dnf install -y -q "$rel1"/*.noarch.rpm
    echo "$EDIT" > /etc/wd2l/sender.env
    echo token > /etc/wd2l/hec.token
    echo '{"record": "audit"}' > /var/log/wd2l/audit-1.jsonl
    echo '{}' > /var/lib/wd2l/state.json
    dnf remove -y -q wd2l wd2l-sender wd2l-receiver
    for p in wd2l wd2l-sender wd2l-receiver; do ! rpm -q "$p" >/dev/null || fail "$p is still installed"; done
    for c in wd2l-sender wd2l-receiver wd2l-audit-report; do ! command -v "$c" >/dev/null || fail "$c is still there"; done
    if ls -d /usr/lib/python3*/site-packages/wd2l 2>/dev/null; then fail "site-packages/wd2l is still there"; fi
    if ls /usr/lib/systemd/system/wd2l-* 2>/dev/null; then fail "units are still there"; fi
    mods=$(semodule -l)                           # not piped: grep -q could end it early
    if grep -qx 'wd2l_container\|wd2l_pcap' <<< "$mods"; then fail "an SELinux module is still loaded"; fi
    grep -qxF "$EDIT" /etc/wd2l/sender.env.rpmsave || fail "the edited sender.env wasn't kept as .rpmsave"
    for f in /etc/wd2l/hec.token /var/log/wd2l/audit-1.jsonl /var/lib/wd2l/state.json; do
      [ -f "$f" ] || fail "$f was removed"
    done
    getent passwd wd2l >/dev/null || fail "the wd2l user was removed: its files would be left unowned"
    getent group wd2l-audit >/dev/null || fail "the wd2l-audit group was removed"
    echo "install test ($leg): ok"
    exit 0 ;;
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
