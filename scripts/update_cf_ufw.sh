#!/usr/bin/env bash
set -euo pipefail

PORTS=("80" "443")
CF_V4_URL="https://www.cloudflare.com/ips-v4"
CF_V6_URL="https://www.cloudflare.com/ips-v6"

fetch_list() { curl -fsS "$1"; }

# Удаляем старые CF-правила по комменту "# CF-<PORT>"
delete_old_cf_rules() {
  local port="$1"
  local nums
  nums=$(ufw status numbered | sed -n "s/^\[\s*\([0-9]\+\)\]\s\+.*# CF-${port}\s*$/\1/p" | sort -rn)
  for n in $nums; do ufw --force delete "$n"; done
}

# Безопасная вставка в начало, с откатом на append
ufw_add_top() {
  if ufw --force insert 1 "$@" 2>/dev/null; then
    true
  else
    ufw --force "$@"
  fi
}

for PORT in "${PORTS[@]}"; do
  delete_old_cf_rules "$PORT"

  # v4
  while read -r cidr; do
    [ -n "$cidr" ] && ufw_add_top allow proto tcp from "$cidr" to any port "$PORT" comment "CF-${PORT}"
  done < <(fetch_list "$CF_V4_URL")

  # v6
  while read -r cidr; do
    [ -n "$cidr" ] && ufw_add_top allow proto tcp from "$cidr" to any port "$PORT" comment "CF-${PORT}"
  done < <(fetch_list "$CF_V6_URL")
done

# Явные DENY ниже ALLOW (не критично, но удобно для читаемости)
ufw --force deny in 80/tcp || true
ufw --force deny in 443/tcp || true

echo "CF UFW rules updated."
