#!/bin/sh
set -e

CONF="/etc/socks5tun/config_prod.json"

# Требуется jq: apt-get install -y jq (или поставь заранее)
if ! command -v jq >/dev/null 2>&1; then
  echo "[nat6_setup] 'jq' is required. Install: apt-get install -y jq" >&2
  exit 0  # не валим сервис, просто предупреждаем
fi

# 1) Параметры из конфига
TUN6_CIDR=$(jq -r '.tun.prefix6 // empty' "$CONF")
WAN_IF=$(jq -r '.nat.out_iface // empty' "$CONF")

# Фолбэки
[ -z "$TUN6_CIDR" ] && TUN6_CIDR="fd00:0:0:8::/64"
if [ -z "$WAN_IF" ]; then
  WAN_IF=$(ip -o -6 route show default 2>/dev/null | awk '{print $5}' | head -1)
  [ -z "$WAN_IF" ] && WAN_IF=$(ip -o route show default 2>/dev/null | awk '{print $5}' | head -1)
  [ -z "$WAN_IF" ] && WAN_IF="eth0"
fi

echo "[nat6_setup] prefix6=$TUN6_CIDR wan_if=$WAN_IF"

# 2) IPv6 forwarding: сейчас и персистентно
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null || true
if [ -d /etc/sysctl.d ]; then
  echo 'net.ipv6.conf.all.forwarding=1' >/etc/sysctl.d/99-socks5tun-ipv6.conf || true
fi

# 3) Если nftables — используем его, иначе ip6tables
if command -v nft >/dev/null 2>&1 && nft list tables 2>/dev/null | grep -q ' ip6 nat'; then
  # nftables
  nft --quiet add rule ip6 nat POSTROUTING ip6 saddr $TUN6_CIDR oif $WAN_IF masquerade 2>/dev/null || true
  echo "[nat6_setup] nftables rule ensured"
else
  # ip6tables
  ip6tables -t nat -C POSTROUTING -s "$TUN6_CIDR" -o "$WAN_IF" -j MASQUERADE 2>/dev/null \
    || ip6tables -t nat -A POSTROUTING -s "$TUN6_CIDR" -o "$WAN_IF" -j MASQUERADE
  # (опц.) сохранить, если iptables-persistent установлен
  if command -v ip6tables-save >/dev/null 2>&1 && [ -d /etc/iptables ]; then
    ip6tables-save > /etc/iptables/rules.v6 || true
  fi
  echo "[nat6_setup] ip6tables rule ensured"
fi

exit 0
