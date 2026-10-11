#!/usr/bin/env bash
# The deploy NIC scripts, run for real (as root) in a network namespace on a veth pair: a NIC with
# no ring settings, and real nft, ip and ethtool. The stub tests (tests/test_nic_scripts.py) can't
# catch a ruleset nft refuses or a command a NIC doesn't support; this does. CI's lab job runs it.
#   sudo lab/check-nic-scripts.sh
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
REPO="${WD2L_REPO:-$(cd "$(dirname "$0")/.." && pwd)}"   # WD2L_REPO: check another tree's scripts
NS=wd2l-nictest
TMP="$(mktemp -d)"
cleanup() {
  ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
  ip netns del "$NS" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT
ip netns del "$NS" 2>/dev/null || true                    # left over from an interrupted run
ip netns add "$NS"
ip -n "$NS" link add tx0 type veth peer name cap0
id wd2l >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin wd2l
printf 'IFACE=tx0\nSRC_CIDR=10.255.255.1/30\nBH_IP=10.255.255.2\nBH_MAC=02:00:00:00:00:02\nMTU=1500\nPORT=5514\n' > "$TMP/egress.env"
printf 'IFACE=cap0\n' > "$TMP/capture.env"
run() { ip netns exec "$NS" env WD2L_EGRESS_ENV="$TMP/egress.env" WD2L_CAPTURE_ENV="$TMP/capture.env" "$@"; }
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; exit 1; fi; }

run bash "$REPO/deploy/log-server/egress-nic.sh" > /dev/null
run bash "$REPO/deploy/log-server/egress-nic.sh" > /dev/null          # a restart replaces, never duplicates
check "egress tables loaded" '[ "$(run nft list tables | sort | tr "\n" " ")" = "table arp wd2l_arp table inet wd2l table netdev wd2l_egress " ]'
check "one copy of the egress rules" '[ "$(run nft list table inet wd2l | grep -c "meta skuid")" = 1 ]'
check "static ARP entry" 'run ip neigh show 10.255.255.2 dev tx0 | grep -q PERMANENT'

run bash "$REPO/deploy/receiver/capture-nic.sh" > /dev/null             # veth: no ring settings
check "capture NIC egress drop" 'run nft list table netdev wd2l_notx > /dev/null'
check "capture NIC: NOARP, PROMISC, no address" 'run ip -br link show cap0 | grep -q "NOARP,PROMISC" && [ -z "$(run ip -br -4 addr show cap0 | awk "{print \$3}")" ]'

run bash "$REPO/deploy/log-server/egress-arp-watch.sh" > "$TMP/watch.log" 2>&1 &
sleep 1
run ip link set tx0 down && run ip link set tx0 up
for _ in $(seq 25); do run ip neigh show 10.255.255.2 dev tx0 | grep -q PERMANENT && break; sleep 0.2; done
check "ARP entry back after a NIC down/up" 'run ip neigh show 10.255.255.2 dev tx0 | grep -q PERMANENT'
check "the watcher logged it" 'grep -q "egress-arp: restored 10.255.255.2" "$TMP/watch.log"'
echo "PASS: the NIC scripts work on a real kernel"
