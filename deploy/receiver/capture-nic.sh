#!/usr/bin/env bash
# Enclave 2 capture NIC: receive only. Run at boot by wd2l-capture-nic.service.
#
# The one-way guarantee is physical (only the network tap monitor port's TX strand is connected to
# this NIC's RX). Everything here is defense in depth and keeps the host from trying:
#   - no IP address, ARP off, IPv6 off  -> the stack has nothing to say on this port
#   - promiscuous                      -> frames are addressed to the black-hole MAC, not us
#   - GRO/LRO off                      -> the capture sees packets exactly as they were on the wire
#   - bigger RX ring                   -> absorbs bursts
#   - nft egress drop (kernel 5.16+)   -> belt and braces: nothing leaves even if something tries
set -euo pipefail
[ -f /etc/wd2l/capture.env ] && . /etc/wd2l/capture.env
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
  max=$(ethtool -g "$IFACE" 2>/dev/null | awk '/^RX:/{print $2; exit}')
  [ -n "${max:-}" ] && ethtool -G "$IFACE" rx "$max" 2>/dev/null || true
fi
ip link set "$IFACE" up

if nft -c -f - >/dev/null 2>&1 <<EOF
table netdev wd2l_notx { chain out { type filter hook egress device "$IFACE" priority 0; policy drop; } }
EOF
then
  nft -f - <<EOF
table netdev wd2l_notx {
  chain out { type filter hook egress device "$IFACE" priority 0; policy drop; }
}
EOF
else
  echo "note: kernel has no netdev egress hook; relying on no-IP/no-ARP + the missing TX strand" >&2
fi

ip -d link show dev "$IFACE"
