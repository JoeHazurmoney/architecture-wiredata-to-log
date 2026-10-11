#!/usr/bin/env bash
# Configure the central log server's dedicated egress NIC (the one cabled through the
# network tap to the black-hole switch port). Run at boot by wd2l-egress-nic.service.
#
# What it does:
#   - one /30 address, no gateway, no DHCP
#   - static (permanent) ARP entry for the black-hole IP, because nothing will ever answer ARP
#   - IPv6 off on this NIC (no router solicitations / neighbor discovery on the tapped cable)
#   - no LLDP from this host on this NIC
#   - the egress firewall: only wd2l-sender's one flow leaves, nothing is accepted, no ARP.
#     Loaded here, not by nftables.service, whose stop and reload flush every table (firewalld's
#     too). Loading again replaces wd2l's tables and touches no other.
#
# Settings come from /etc/wd2l/egress.env (WD2L_EGRESS_ENV overrides the path, for tests).
set -euo pipefail
ENV_FILE="${WD2L_EGRESS_ENV:-/etc/wd2l/egress.env}"
[ -f "$ENV_FILE" ] && . "$ENV_FILE"

IFACE="${IFACE:-ens224}"
SRC_CIDR="${SRC_CIDR:-10.255.255.1/30}"
BH_IP="${BH_IP:-10.255.255.2}"
BH_MAC="${BH_MAC:-02:00:00:00:00:02}"   # made-up, locally administered; must not exist anywhere
MTU="${MTU:-1500}"
PORT="${PORT:-5514}"                    # UDP source and destination port (sender.env --bind, --dst)
SRC_IP="${SRC_CIDR%/*}"

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

# The egress firewall. "table" then "delete table" makes a reload replace wd2l's tables on every
# nft version ("destroy" needs kernel 6.3).
nft -f - <<EOF
table inet wd2l
delete table inet wd2l
table inet wd2l {
    chain input {
        type filter hook input priority filter; policy accept;
        iifname "$IFACE" counter drop comment "nothing is ever accepted from the tapped cable"
    }
    chain output {
        type filter hook output priority filter; policy accept;
        oifname "$IFACE" meta skuid "wd2l" ip saddr $SRC_IP ip daddr $BH_IP udp sport $PORT udp dport $PORT accept
        oifname "$IFACE" counter drop comment "only wd2l-sender may use this NIC"
    }
}
table arp wd2l_arp
delete table arp wd2l_arp
table arp wd2l_arp {
    chain output {
        type filter hook output priority filter; policy accept;
        oifname "$IFACE" counter drop
    }
    chain input {
        type filter hook input priority filter; policy accept;
        iifname "$IFACE" counter drop
    }
}
EOF

# Kernel 5.16+: also drop any other frame a daemon might put on the wire (LLDP, IPv6 RS, ...).
# Checked with the same text it loads, so a failure names nft's reason.
EGRESS="table netdev wd2l_egress
delete table netdev wd2l_egress
table netdev wd2l_egress {
    chain out {
        type filter hook egress device \"$IFACE\" priority filter; policy drop;
        ip saddr $SRC_IP ip daddr $BH_IP udp sport $PORT udp dport $PORT accept
    }
}"
if err=$(nft -c -f - <<<"$EGRESS" 2>&1); then
  nft -f - <<<"$EGRESS"
else
  echo "note: no netdev egress table on $IFACE (nft: ${err//$'\n'/ }); relying on the inet and arp tables" >&2
fi

ip -br addr show dev "$IFACE"
ip neigh show dev "$IFACE"
