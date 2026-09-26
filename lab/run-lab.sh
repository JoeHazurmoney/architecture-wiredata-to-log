#!/usr/bin/env bash
# Full one-way path on one Linux box, using network namespaces.
#
#   wd2l-enc1                       wd2l-bh                          wd2l-enc2
#   fake agg.  -> wd2l-sender      "black-hole switch port"
#   enc1nic 10.255.255.1 ==cable==>   bh0 (no IP, nft drops all)
#   static ARP .2 -> 02:..:02       | tc mirred = the network tap
#                                   '-> tap0 ======TX only======>   cap0 (no IP, arp off, egress dropped)
#                                                                   tcpdump archive + wd2l-receiver
#
# Needs: root, iproute2, nftables (kernel >= 5.16 for the netdev egress hook), tcpdump, python3.
#
# Usage: sudo lab/run-lab.sh [--events N] [--eps N] [--loss PCT] [--receiver-outage]
#                            [--receiver-crash] [--keep]
#   --loss PCT          drop PCT% of packets on the cable (before the tap): gaps must be reported
#   --receiver-outage   stop the receiver mid-run, restart it, then replay the pcap archive:
#                       everything must end up delivered with no duplicates
#   --receiver-crash    same, but the receiver is killed (SIGKILL) instead of stopped: nothing
#                       may be lost; a few duplicates are allowed (dedup on wd2l_stream/wd2l_seq)
#   --keep              leave namespaces up afterwards (lab/teardown.sh removes them)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(dirname "$HERE")"
OUT="${OUT:-$HERE/out}"
EVENTS=5000
EPS=1000
LOSS=""
OUTAGE=0
KILLSIG=TERM
KEEP=0
MAX_EVENT=262144

while [ $# -gt 0 ]; do
  case "$1" in
    --events) EVENTS="$2"; shift 2 ;;
    --eps) EPS="$2"; shift 2 ;;
    --loss) LOSS="$2"; shift 2 ;;
    --receiver-outage) OUTAGE=1; shift ;;
    --receiver-crash) OUTAGE=1; KILLSIG=KILL; shift ;;
    --keep) KEEP=1; shift ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" = 0 ] || { echo "run as root (needs network namespaces)" >&2; exit 1; }
for c in ip tc nft tcpdump python3; do
  command -v "$c" >/dev/null || { echo "missing $c (apt install iproute2 nftables tcpdump)" >&2; exit 1; }
done

export PYTHONPATH="$REPO"
ENC1="ip netns exec wd2l-enc1"
BH="ip netns exec wd2l-bh"
ENC2="ip netns exec wd2l-enc2"
PIDS=()

# Turn IPv6 off on the given interfaces inside a namespace (so the NIC never sends router
# solicitations or neighbor discovery onto the cable). Skipped if the kernel has no IPv6.
v6off() {
  local ns="$1"; shift
  for d in "$@"; do
    ip netns exec "$ns" sh -c "f=/proc/sys/net/ipv6/conf/$d/disable_ipv6; [ ! -e \$f ] || echo 1 > \$f"
  done
}

cleanup() {
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  [ "$KEEP" = 1 ] || "$HERE/teardown.sh" >/dev/null 2>&1 || true
}
trap cleanup EXIT

"$HERE/teardown.sh" >/dev/null 2>&1 || true
rm -rf "$OUT"
mkdir -p "$OUT/pcap" "$OUT/received"

echo "== building namespaces"
for ns in wd2l-enc1 wd2l-bh wd2l-enc2; do
  ip netns add "$ns"
  v6off "$ns" all default
  ip netns exec "$ns" ip link set lo up
done

# The cable between the log server and the black-hole switch port.
ip link add enc1nic netns wd2l-enc1 address 02:00:00:00:00:01 type veth peer name bh0 netns wd2l-bh
# The tap's monitor port -> Enclave 2 capture NIC.
ip link add tap0 netns wd2l-bh type veth peer name cap0 netns wd2l-enc2

# Enclave 1: the log server's dedicated egress NIC.
v6off wd2l-enc1 enc1nic
$ENC1 ip addr add 10.255.255.1/30 dev enc1nic
$ENC1 ip link set enc1nic up
$ENC1 ip neigh replace 10.255.255.2 lladdr 02:00:00:00:00:02 nud permanent dev enc1nic
if [ -n "$LOSS" ]; then
  # Random loss after the IP stack (sendto still succeeds), before the tap: wire loss.
  PERMYRIAD=$(python3 -c "print(int(round(float('$LOSS') * 100)))")
  $ENC1 nft -f - <<EOF
table netdev wireloss {
  chain out {
    type filter hook egress device "enc1nic" priority 0; policy accept;
    numgen random mod 10000 < $PERMYRIAD drop
  }
}
EOF
fi

# Black hole: no IP, drop everything that arrives. tc ingress runs before the nft
# ingress hook, so the mirror (the tap) still sees every frame on the cable.
v6off wd2l-bh bh0 tap0
$BH ip link set bh0 up
$BH ip link set tap0 up
$BH nft -f - <<'EOF'
table netdev blackhole {
  chain in { type filter hook ingress device "bh0" priority 0; policy drop; }
}
EOF
$BH tc qdisc add dev bh0 ingress
$BH tc filter add dev bh0 parent ffff: protocol all u32 match u32 0 0 action mirred egress mirror dev tap0

# Enclave 2: receive only. No IP, no ARP, and anything it tries to send is dropped
# (stands in for the missing TX strand).
v6off wd2l-enc2 cap0
$ENC2 ip link set cap0 arp off promisc on up
$ENC2 nft -f - <<'EOF'
table netdev notx {
  chain out { type filter hook egress device "cap0" priority 0; policy drop; }
}
EOF

echo "== generating $EVENTS events (+1 oversize)"
python3 "$HERE/gen_events.py" -n "$EVENTS" "$OUT/sent.jsonl"

echo "== starting Enclave 2: capture archive + receiver"
$ENC2 tcpdump -i cap0 -U -Z root -G 3600 -w "$OUT/pcap/cap-%Y%m%d%H%M%S.pcap" \
  2>"$OUT/tcpdump.log" &
PIDS+=($!)

RX_ARGS=(--live cap0 --dst-ip 10.255.255.2 --dst-port 5514 --src-ip 10.255.255.1
         --out-dir "$OUT/received" --state "$OUT/state.json"
         --gap-window 2 --health-interval 5 --max-event "$MAX_EVENT")
start_receiver() {
  $ENC2 python3 -m wd2l.receiver "${RX_ARGS[@]}" >>"$OUT/receiver.log" 2>&1 &
  RX_PID=$!
  PIDS+=($RX_PID)
}
start_receiver
sleep 1

echo "== starting Enclave 1: wd2l-sender + stand-in log aggregator"
$ENC1 python3 -m wd2l.sender --listen 127.0.0.1:10070 --dst 10.255.255.2:5514 \
  --bind 10.255.255.1 --max-event "$MAX_EVENT" --stats-interval 5 --state "$OUT/sender.json" \
  >"$OUT/sender.log" 2>&1 &
TX_PID=$!
PIDS+=($TX_PID)
sleep 1

$ENC1 python3 "$HERE/fake_cribl.py" --eps "$EPS" "$OUT/sent.jsonl" &
AGG_PID=$!

if [ "$OUTAGE" = 1 ]; then
  sleep 1.5
  echo "== simulating receiver outage with SIG$KILLSIG (capture keeps running)"
  kill -"$KILLSIG" "$RX_PID"; wait "$RX_PID" 2>/dev/null || true
  sleep 2
  start_receiver
  echo "== receiver restarted"
fi

wait "$AGG_PID"
sleep 3   # heartbeats + gap window
kill -TERM "$TX_PID"; wait "$TX_PID" 2>/dev/null || true   # final heartbeat
sleep 3
kill -TERM "$RX_PID"; wait "$RX_PID" 2>/dev/null || true
sleep 0.5

if [ "$OUTAGE" = 1 ]; then
  echo "== replaying the capture archive to fill the outage"
  python3 -m wd2l.receiver --pcap "$OUT"/pcap/*.pcap --dst-ip 10.255.255.2 --dst-port 5514 \
    --out-dir "$OUT/received" --state "$OUT/state.json" --max-event "$MAX_EVENT" \
    >"$OUT/replay.log" 2>&1
fi

# Proof Enclave 2 never transmitted: nothing came back into the tap port.
BACK=$($BH cat /sys/class/net/tap0/statistics/rx_packets)
echo "== frames sent back toward Enclave 1 from Enclave 2: $BACK"

echo "== verifying"
VERIFY_ARGS=("$OUT/sent.jsonl" "$OUT/received" --max-event "$MAX_EVENT")
if [ -n "$LOSS" ]; then VERIFY_ARGS+=(--expect-gaps); fi
if [ "$OUTAGE" = 1 ]; then VERIFY_ARGS+=(--state "$OUT/state.json"); fi
if [ "$KILLSIG" = KILL ]; then VERIFY_ARGS+=(--allow-duplicates); fi
set +e
python3 "$HERE/verify.py" "${VERIFY_ARGS[@]}"
RC=$?
set -e
if [ "$OUTAGE" = 1 ]; then
  echo "(during the outage the live receiver reported $(grep -c '"type": "gap"' "$OUT/received/health.jsonl" || true) gap record(s); the archive replay filled them)"
fi
[ "$BACK" = 0 ] || { echo "FAIL: Enclave 2 transmitted $BACK frames"; RC=1; }
echo "logs and captures: $OUT"
exit $RC
