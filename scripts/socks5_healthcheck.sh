#!/usr/bin/env bash

TOKEN="8285785110:AAGaDAsisuGlbMYDCKkAWuYl_wmgzmEsdLQ"
CHAT_ID="271161868"

STATUS_FILE="/var/lib/node_exporter/socks5tun.prom"
STATE_FILE="/var/lib/socks5health/last_status"

# Создаём папку для STATE_FILE, если не существует
mkdir -p "$(dirname "$STATE_FILE")"

# Проверка доступности через SOCKS5
if curl -sS -4 --max-time 8 --socks5-hostname 127.0.0.1:5000 https://ifconfig.co > /dev/null; then
    CURRENT="up"
    systemd-notify --status="SOCKS5 OK" --ready
    echo "socks5tun_status 1" > "$STATUS_FILE"
else
    CURRENT="down"
    systemd-notify --status="SOCKS5 ERROR"
    echo "socks5tun_status 0" > "$STATUS_FILE"
fi

# Читаем предыдущее состояние
PREV=$(cat "$STATE_FILE" 2>/dev/null || echo "unknown")

# Отправка Telegram только если статус изменился
if [[ "$CURRENT" == "up" && "$PREV" != "up" ]]; then
    curl -s -X POST https://api.telegram.org/bot${TOKEN}/sendMessage \
         -d chat_id=${CHAT_ID} \
         -d text="✅ SOCKS5TUN восстановлен на $(hostname) в $(date)" > /dev/null
elif [[ "$CURRENT" == "down" && "$PREV" != "down" ]]; then
    curl -s -X POST https://api.telegram.org/bot${TOKEN}/sendMessage \
         -d chat_id=${CHAT_ID} \
         -d text="🚨 SOCKS5TUN НЕ РАБОТАЕТ на $(hostname) в $(date)" > /dev/null
fi

# Обновляем текущее состояние
echo "$CURRENT" > "$STATE_FILE"

# Код завершения
[[ "$CURRENT" == "up" ]] && exit 0 || exit 1
