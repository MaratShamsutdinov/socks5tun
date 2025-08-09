#!/usr/bin/env bash

TOKEN="8285785110:AAGaDAsisuGlbMYDCKkAWuYl_wmgzmEsdLQ"
CHAT_ID="271161868"

MSG="🚨 *SOCKS5TUN ALERT*: \`$1\` failed on \`$(hostname)\` at \`$(date)\`"
curl -s -X POST https://api.telegram.org/bot${TOKEN}/sendMessage \
     -d chat_id=${CHAT_ID} \
     -d text="$MSG" \
     -d parse_mode=Markdown > /dev/null
