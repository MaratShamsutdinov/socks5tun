#!/bin/bash

OUTFILE="/var/lib/node_exporter/services_status.prom"

# Соединения по портам
STUNNEL_CONN=$(ss -tan state established '( sport = :443 )' | tail -n +2 | wc -l)
SOCKS5_CONN=$(ss -tan state established '( sport = :5000 )' | tail -n +2 | wc -l)

# Статусы сервисов (1 = активен, 0 = нет)
is_active() {
  systemctl is-active "$1" >/dev/null 2>&1 && echo 1 || echo 0
}

STUNNEL_STATUS=$(is_active stunnel4)
SOCKS5_STATUS=$(is_active socks5tun)

# Выводим в формате Prometheus
cat <<EOF > "$OUTFILE"
vpn_connections{service="stunnel"} $STUNNEL_CONN
vpn_connections{service="socks5tun"} $SOCKS5_CONN
service_status{service="stunnel"} $STUNNEL_STATUS
service_status{service="socks5tun"} $SOCKS5_STATUS
EOF
