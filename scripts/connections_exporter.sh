#!/bin/bash

OUTFILE="/var/lib/node_exporter/connections.prom"

# Подсчёт активных TCP соединений к порту 443 (stunnel)
STUNNEL_CONN=$(ss -tan state established '( sport = :443 )' | tail -n +2 | wc -l)

# Подсчёт активных TCP соединений к порту 5000 (socks5tun)
SOCKS5_CONN=$(ss -tan state established '( sport = :5000 )' | tail -n +2 | wc -l)

# Сохраняем в Prometheus формат
cat <<EOF > "$OUTFILE"
vpn_connections{service="stunnel"} $STUNNEL_CONN
vpn_connections{service="socks5tun"} $SOCKS5_CONN
EOF
