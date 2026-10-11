#!/usr/bin/env bash
# Enclave 2 capture NIC: receive only. Run at boot by wd2l-capture-nic.service.
#
# The one-way guarantee is physical (only the network tap monitor port's TX strand is connected to
# this NIC's RX). Everything here is defense in depth and keeps the host from trying:
#   - no IP address, ARP off, IPv6 off  -> the stack has nothing to say on this port
#   - promiscuous                      -> frames are addressed to the black-hole MAC, not us
#   - GRO/LRO off                      -> the capture sees packets exactly as they were on the wire
#   - bigger RX ring                   -> absorbs bursts
#   - nft egress drop (kernel 5.16+)   -> belt and braces: nothing leaves even if something tries;
#                                         nft's reason is printed if it can't load
set -euo pipefail
ENV_FILE="${WD2L_CAPTURE_ENV:-/etc/wd2l/capture.env}"   # override: tests and lab/check-nic-scripts.sh
[ -f "$ENV_FILE" ] && . "$ENV_FILE"
IFACE="${IFACE:-ens256}"
MTU="${MTU:-1500}"   # match Enclave 1 (9000 if you use jumbo frames end to end)

if command -v nmcli >/dev/null 2>&1; then
  nmcli device set "$IFACE" managed no || true
fi
f="/proc/sys/net/ipv6/conf/$IFACE/disable_ipv6"
[ ! -e "$f" ] || echo 1 > "$f"

ip link set "$IFACE" down
ip addr flush dev "$IFACE"
ip link set "$IFACE" mtu "$MTU" arp off promisc on
if command -v ethtool >/dev/null 2>&1; then
  ethtool -K "$IFACE" gro off lro off 2>/dev/null || true
  # Not every NIC reports ring sizes (veth, many USB NICs): then keep the driver's default.
  max=$(ethtool -g "$IFACE" 2>/dev/null | awk '/^RX:/{print $2; exit}') || true
  [ -n "${max:-}" ] && ethtool -G "$IFACE" rx "$max" 2>/dev/null || true
fi
ip link set "$IFACE" up

# The egress drop (kernel 5.16+). Checked with the same text it loads, so a failure names nft's
# reason. "table" then "delete table" makes a reload replace the table on every nft version.
NOTX="table netdev wd2l_notx
delete table netdev wd2l_notx
table netdev wd2l_notx {
  chain out { type filter hook egress device \"$IFACE\" priority 0; policy drop; }
}"
if err=$(nft -c -f - <<<"$NOTX" 2>&1); then
  nft -f - <<<"$NOTX"
else
  echo "note: no egress drop on $IFACE (nft: ${err//$'\n'/ }); relying on no-IP/no-ARP + the missing TX strand" >&2
fi

ip -d link show dev "$IFACE"
