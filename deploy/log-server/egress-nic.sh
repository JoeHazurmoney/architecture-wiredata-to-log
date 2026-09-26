#!/usr/bin/env bash
# Configure the central log server's dedicated egress NIC (the one cabled through the
# network tap to the black-hole switch port). Run at boot by wd2l-egress-nic.service.
#
# What it does:
#   - one /30 address, no gateway, no DHCP
#   - static (permanent) ARP entry for the black-hole IP, because nothing will ever answer ARP
#   - IPv6 off on this NIC (no router solicitations / neighbor discovery on the tapped cable)
#   - no LLDP from this host on this NIC
#
# Settings come from /etc/wd2l/egress.env if present.
set -euo pipefail
[ -f /etc/wd2l/egress.env ] && . /etc/wd2l/egress.env

IFACE="${IFACE:-ens224}"
SRC_CIDR="${SRC_CIDR:-10.255.255.1/30}"
BH_IP="${BH_IP:-10.255.255.2}"
BH_MAC="${BH_MAC:-02:00:00:00:00:02}"   # made-up, locally administered; must not exist anywhere
MTU="${MTU:-1500}"

# Keep NetworkManager away from this NIC so it does not add DHCP, IPv6 or LLDP later.
if command -v nmcli >/dev/null 2>&1; then
  nmcli device set "$IFACE" managed no || true
fi

f="/proc/sys/net/ipv6/conf/$IFACE/disable_ipv6"
[ ! -e "$f" ] || echo 1 > "$f"

ip link set "$IFACE" down
ip addr flush dev "$IFACE"
ip link set "$IFACE" mtu "$MTU"
ip addr add "$SRC_CIDR" dev "$IFACE"
ip link set "$IFACE" up
ip neigh replace "$BH_IP" lladdr "$BH_MAC" nud permanent dev "$IFACE"

# lldpd, if installed, must not talk on this port.
if command -v lldpcli >/dev/null 2>&1; then
  lldpcli configure ports "$IFACE" lldp status disabled || true
fi

ip -br addr show dev "$IFACE"
ip neigh show dev "$IFACE"
