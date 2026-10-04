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
#                            [--receiver-crash] [--maintenance] [--keep] [--interleave]
#                            [--files FILE...]
#   --loss PCT          drop PCT% of packets on the cable (before the tap): gaps must be reported
#   --receiver-outage   stop the receiver mid-run, restart it, then replay the pcap archive:
#                       everything must end up delivered with no duplicates
#   --receiver-crash    same, but the receiver is killed (SIGKILL) instead of stopped: nothing
#                       may be lost; a few duplicates are allowed (dedup on wd2l_stream/wd2l_seq)
#   --maintenance       planned downtime, in the order docs/planned-downtime.md gives: half the
#                       events, then hold the aggregator, stop the sender, stop the receiver and
#                       the capture (receiver host down), start the capture and receiver, start
#                       the sender, send the rest. Two linked sender runs, nothing lost, no replay
#   --keep              leave namespaces up afterwards (lab/teardown.sh removes them)
#   --interleave        with --files: merge the files by each line's timestamp, as if they were
#                       being written at the same time and tailed by a forwarder. The sender
#                       numbers lines per file (--source-seq) so Enclave 2 can separate them.
#   --files FILE...     send these log files (one event per line) instead of generated events,
#                       then rebuild them in Enclave 2 and compare SHA-256 hashes. Must be the
#                       last option: everything after it is a file.
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
FILES=()
INTERLEAVE=0
MAINT=0

while [ $# -gt 0 ]; do
  case "$1" in
    --events) EVENTS="$2"; shift 2 ;;
    --eps) EPS="$2"; shift 2 ;;
    --loss) LOSS="$2"; shift 2 ;;
    --receiver-outage) OUTAGE=1; shift ;;
    --receiver-crash) OUTAGE=1; KILLSIG=KILL; shift ;;
    --maintenance) MAINT=1; shift ;;
    --keep) KEEP=1; shift ;;
    --interleave) INTERLEAVE=1; shift ;;
    --files) shift; FILES=("$@"); [ ${#FILES[@]} -gt 0 ] || { echo "--files needs files" >&2; exit 2; }; break ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done

if [ "$MAINT" = 1 ] && { [ "$OUTAGE" = 1 ] || [ -n "$LOSS" ] || [ ${#FILES[@]} -gt 0 ]; }; then
  echo "--maintenance runs on its own (with --events / --eps)" >&2; exit 2
fi
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

SENDER_EXTRA=()
if [ ${#FILES[@]} -gt 0 ]; then
  echo "== turning ${#FILES[@]} file(s) into events, one per line"
  F2E_ARGS=(--out "$OUT/sent.jsonl" --manifest "$OUT/manifest.json" --max-event "$MAX_EVENT")
  SENDER_EXTRA=(--extra-field wd2l_b64)
  if [ "$INTERLEAVE" = 1 ]; then
    F2E_ARGS+=(--interleave)
    SENDER_EXTRA+=(--source-seq)
  fi
  python3 "$HERE/files_to_events.py" "${F2E_ARGS[@]}" "${FILES[@]}"
else
  echo "== generating $EVENTS events (+1 oversize)"
  python3 "$HERE/gen_events.py" -n "$EVENTS" "$OUT/sent.jsonl"
fi

start_capture() {
  $ENC2 tcpdump -i cap0 -U -Z root -G 3600 -w "$OUT/pcap/cap-%Y%m%d%H%M%S.pcap" \
    2>>"$OUT/tcpdump.log" &
  CAP_PID=$!
  PIDS+=($CAP_PID)
}
RX_ARGS=(--live cap0 --dst-ip 10.255.255.2 --dst-port 5514 --src-ip 10.255.255.1 --src-port 5514
         --out-dir "$OUT/received" --state "$OUT/state.json"
         --gap-window 2 --health-interval 5 --max-event "$MAX_EVENT")
start_receiver() {
  $ENC2 python3 -m wd2l.receiver "${RX_ARGS[@]}" >>"$OUT/receiver.log" 2>&1 &
  RX_PID=$!
  PIDS+=($RX_PID)
}
start_sender() {
  $ENC1 python3 -m wd2l.sender --listen 127.0.0.1:10070 --dst 10.255.255.2:5514 \
    --bind 10.255.255.1:5514 --max-event "$MAX_EVENT" --stats-interval 5 \
    --state "$OUT/sender.json" "${SENDER_EXTRA[@]}" >>"$OUT/sender.log" 2>&1 &
  TX_PID=$!
  PIDS+=($TX_PID)
}

echo "== starting Enclave 2: capture archive + receiver"
start_capture
start_receiver
sleep 1

echo "== starting Enclave 1: wd2l-sender + stand-in log aggregator"
start_sender
sleep 1

if [ "$MAINT" = 1 ]; then
  HALF=$(( $(wc -l < "$OUT/sent.jsonl") / 2 ))
  head -n "$HALF" "$OUT/sent.jsonl" > "$OUT/sent-part1.jsonl"
  tail -n +"$((HALF + 1))" "$OUT/sent.jsonl" > "$OUT/sent-part2.jsonl"
  $ENC1 python3 "$HERE/fake_cribl.py" --eps "$EPS" "$OUT/sent-part1.jsonl"
  # The steps of docs/planned-downtime.md. The stand-in aggregator has sent its part and
  # disconnected: that is "hold the aggregator's output", so the sender's input is quiet.
  echo "== planned downtime: aggregator held, stopping wd2l-sender"
  sleep 1
  kill -TERM "$TX_PID"; wait "$TX_PID" 2>/dev/null || true
  echo "== waiting for Enclave 2 to record the clean end (stream_end)"
  for _ in $(seq 50); do
    grep -q '"type": "stream_end"' "$OUT/received/health.jsonl" 2>/dev/null && break
    sleep 0.2
  done
  echo "== stopping wd2l-receiver and the capture (receiver host down)"
  kill -TERM "$RX_PID"; wait "$RX_PID" 2>/dev/null || true
  kill -TERM "$CAP_PID"; wait "$CAP_PID" 2>/dev/null || true
  sleep 3
  echo "== starting Enclave 2 first: capture, then wd2l-receiver"
  start_capture
  start_receiver
  sleep 1
  echo "== starting wd2l-sender, then releasing the aggregator"
  start_sender
  sleep 1
  $ENC1 python3 "$HERE/fake_cribl.py" --eps "$EPS" "$OUT/sent-part2.jsonl" &
  AGG_PID=$!
else
  $ENC1 python3 "$HERE/fake_cribl.py" --eps "$EPS" "$OUT/sent.jsonl" &
  AGG_PID=$!
fi

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
    --src-ip 10.255.255.1 --src-port 5514 \
    --out-dir "$OUT/received" --state "$OUT/state.json" --max-event "$MAX_EVENT" \
    >"$OUT/replay.log" 2>&1
fi

# Proof Enclave 2 never transmitted: nothing came back into the tap port.
BACK=$($BH cat /sys/class/net/tap0/statistics/rx_packets)
echo "== frames sent back toward Enclave 1 from Enclave 2: $BACK"

echo "== verifying"
VERIFY_ARGS=("$OUT/sent.jsonl" "$OUT/received" --max-event "$MAX_EVENT" "${SENDER_EXTRA[@]}")
if [ -n "$LOSS" ]; then VERIFY_ARGS+=(--expect-gaps); fi
if [ "$OUTAGE" = 1 ]; then VERIFY_ARGS+=(--state "$OUT/state.json"); fi
if [ "$KILLSIG" = KILL ]; then VERIFY_ARGS+=(--allow-duplicates); fi
if [ "$MAINT" = 1 ]; then VERIFY_ARGS+=(--sender-runs 2); fi
set +e
python3 "$HERE/verify.py" "${VERIFY_ARGS[@]}"
RC=$?
set -e
if [ "$OUTAGE" = 1 ]; then
  echo "(during the outage the live receiver reported $(grep -c '"type": "gap"' "$OUT/received/health.jsonl" || true) gap record(s); the archive replay filled them)"
fi
[ "$BACK" = 0 ] || { echo "FAIL: Enclave 2 transmitted $BACK frames"; RC=1; }
if [ ${#FILES[@]} -gt 0 ]; then
  echo
  echo "== rebuilding the files in Enclave 2 and comparing SHA-256 hashes"
  set +e
  python3 "$HERE/rebuild_files.py" "$OUT/manifest.json" "$OUT/received/events.jsonl" \
    "$OUT/rebuilt" --hashes "$OUT/hashes.txt"
  HRC=$?
  set -e
  if [ "$HRC" = 0 ]; then
    echo "PASS: every file rebuilt byte for byte (rebuilt copies in $OUT/rebuilt)"
  elif [ -n "$LOSS" ]; then
    echo "(expected with --loss: files with lost lines are INCOMPLETE, never a false MATCH)"
  else
    echo "FAIL: not every file was rebuilt identically"; RC=1
  fi
fi
echo "logs and captures: $OUT"
exit $RC
