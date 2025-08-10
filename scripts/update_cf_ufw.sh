#!/usr/bin/env bash
set -euo pipefail

PORTS=(80 443)
UFW() { ufw --force "$@"; }

# Удаляем все старые правила с комментом CF-<PORT> (v4 и v6)
delete_cf_rules() {
  local port="$1"
  # вытаскиваем номера правил по комменту, удаляем сверху вниз
  mapfile -t nums < <(ufw status numbered | sed -n "s/^\[\s*\([0-9]\+\)\]\s\+.*# CF-${port}.*$/\1/p" | sort -rn)
  for n in "${nums[@]:-}"; do UFW delete "$n"; done
}

add_cf_rules_for_port() {
  local port="$1"
  # v4 сначала
  curl -fsS https://www.cloudflare.com/ips-v4 | while read -r net; do
    [[ -n "$net" ]] && UFW prepend allow from "$net" to any port "$port" proto tcp comment "CF-${port}"
  done
  # затем v6
  curl -fsS https://www.cloudflare.com/ips-v6 | while read -r net; do
    [[ -n "$net" ]] && UFW prepend allow from "$net" to any port "$port" proto tcp comment "CF-${port}"
  done
  # и убедимся, что есть deny (оба стека)
  ufw status | grep -qE "(^| )${port}/tcp.*DENY" || UFW deny "${port}/tcp"
}

for p in "${PORTS[@]}"; do
  delete_cf_rules "$p"
  add_cf_rules_for_port "$p"
done

echo "UFW updated for Cloudflare IPs on ports: ${PORTS[*]}"
