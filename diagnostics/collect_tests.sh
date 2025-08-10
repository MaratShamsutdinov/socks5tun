#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# Проект: socks5tun – сбор диагностических данных в единый TXT‑дамп
# Версия: рефакторинг «всё по функциям»
# ------------------------------------------------------------------------------
#   • ENV‑переменные  OUT_DIR, TEST_DIR, OUT_FILE, AUTHOR, MOD_DIR, …
#   • CLI‑флаги       -o|--out-file  -d|--out-dir  -t|--test-dir  -a|--author
# ------------------------------------------------------------------------------
set -Eeuo pipefail
trap 'log_err "Fail @ $LINENO: $BASH_COMMAND"' ERR

# ---------------------------- Цветной лог -------------------------------------
if [[ -t 1 ]]; then
  COLOR_OK=$(tput setaf 2)
  COLOR_WARN=$(tput setaf 3)
  COLOR_ERR=$(tput setaf 1)
  COLOR_RESET=$(tput sgr0)
else
  COLOR_OK=""; COLOR_WARN=""; COLOR_ERR=""; COLOR_RESET=""
fi
log_info() { echo -e "${COLOR_OK}[INFO] $*${COLOR_RESET}"; }
log_warn() { echo -e "${COLOR_WARN}[WARN] $*${COLOR_RESET}"; }
log_err()  { echo -e "${COLOR_ERR}[ERR]  $*${COLOR_RESET}" >&2; }

# ------------------------- Значения по умолчанию ------------------------------
OUT_DIR="${OUT_DIR:-diagnostics}"
TEST_DIR="${TEST_DIR:-tests}"
OUT_FILE="${OUT_FILE:-${OUT_DIR}/socks5_diagnostics.txt}"
AUTHOR="${AUTHOR:-${USER:-unknown}}"
MOD_DIR="${MOD_DIR:-socks5tun}"
MISC_FILE="${MISC_FILE:-${OUT_DIR}/misc_files.txt}"
MOD_FILE="${MOD_FILE:-${OUT_DIR}/socks5tun_modules.txt}"
TREE_FILE="${TREE_FILE:-${OUT_DIR}/project_tree.txt}"
STRUCTURE_FILE="${STRUCTURE_FILE:-${OUT_DIR}/structure_index.txt}"
CONFIG_FILE="${CONFIG_FILE:-${OUT_DIR}/server_configs.txt}"
IGNORE_PATTERNS='(^|/)(__pycache__|\.pytest_cache|\.mypy_cache|\.git|\.venv|venv|diagnostics|\.vscode)(/|$)'

# ----------------------------------------------------------------------------
# 1. parse_cli – обработка аргументов командной строки
# ----------------------------------------------------------------------------
parse_cli() {
  # GNU getopt: длинные опции und = «--out-file=<path>» или «--out-file <path>»
  local opts
  opts=$(getopt -o "" \
        -l out-file:,out-dir:,test-dir:,author:,help \
        -- "$@") || { usage; exit 1; }

  eval set -- "$opts"
  while true; do
    case "$1" in
      --out-file) OUT_FILE=$2; shift 2 ;;
      --out-dir)  OUT_DIR=$2;  shift 2 ;;
      --test-dir) TEST_DIR=$2; shift 2 ;;
      --author)   AUTHOR=$2;   shift 2 ;;
      --help)     usage; exit 0 ;;
      --) shift; break ;;      # конец списка
      *) log_err "getopt internal error: $1"; exit 1 ;;
    esac
  done
}

# ----------------------------------------------------------------------------
# 2. init_output_files – подготовка директорий и шапок
# ----------------------------------------------------------------------------
init_output_files() {
  mkdir -p "$OUT_DIR"
  for f in "$OUT_FILE" "$STRUCTURE_FILE" "$CONFIG_FILE" "$TREE_FILE"; do
    : >"$f"
    printf 'Generated on %(%Y-%m-%d %H:%M:%S)T by %s\n\n' -1 "$AUTHOR" >"$f"
  done
}

# ----------------------------------------------------------------------------
# 3. collect_tests – дамп всех test_*.py + test.yml
# ----------------------------------------------------------------------------
collect_tests() {
  log_info "=== ТЕСТОВЫЕ ФАЙЛЫ ===" >>"$OUT_FILE"
  if [[ -d "$TEST_DIR" ]]; then
    find "$TEST_DIR" -type f -name "*.py" -print0 | sort -z | \
      while IFS= read -r -d '' file; do
        printf '\n# --- %s ---\n' "$file" >>"$OUT_FILE"
        cat "$file" >>"$OUT_FILE"
      done
  else
    log_warn "Каталог $TEST_DIR не найден" >>"$OUT_FILE"
  fi
}

# ----------------------------------------------------------------------------
# 4. collect_project_tree – дерево проекта без мусора
# ----------------------------------------------------------------------------
collect_project_tree() {
  printf '=== ДЕРЕВО ПРОЕКТА ===\n' >>"$TREE_FILE"
  if command -v tree &>/dev/null; then
    tree -a --dirsfirst -I "$IGNORE_PATTERNS" >>"$TREE_FILE"
  else
    printf '[tree не установлен ⇒ вывод через find]\n' >>"$TREE_FILE"
    find . -path "./$OUT_DIR" -prune -o -type f | grep -Ev "$IGNORE_PATTERNS" | sort >>"$TREE_FILE"
  fi
}

# ----------------------------------------------------------------------------
# 5. collect_modules – дамп python‑модулей socks5tun/
# ----------------------------------------------------------------------------
collect_modules() {
  log_info "=== SOCKS5 MODULES ($MOD_DIR) ===" >>"$MOD_FILE"
  if [[ -d "$MOD_DIR" ]]; then
    find "$MOD_DIR" -type f -name "*.py" \
         ! -name "run.py" ! -name "server.py" ! -name "udp_handler.py" -print0 | sort -z | \
      while IFS= read -r -d '' file; do
        relpath="${file#./}"
        printf '%s\n' "$relpath" >>"$STRUCTURE_FILE"
        printf '\n# --- %s ---\n' "$file" >>"$MOD_FILE"
        cat "$file" >>"$MOD_FILE"
      done
  else
    log_warn "Каталог $MOD_DIR не найден" >>"$MOD_FILE"
  fi
}

# ----------------------------------------------------------------------------
# 6. collect_misc – прочие .py / .json / .sh / … (кроме tests и socks5tun)
# ----------------------------------------------------------------------------
collect_misc() {
  log_info "=== MISC FILES ===" >>"$MISC_FILE"
  mapfile -d '' misc < <(
    find . -type f \( -name "*.py" -o -name "*.json" -o -name "*.sh" -o -name "*.md" -o -name "*.txt" -o -name "*.yml" \) \
      -not -path "./$TEST_DIR/*" -not -path "./$MOD_DIR/*" -not -path "*/__pycache__/*" \
      -not -path "*/.pytest_cache/*" -not -path "*/.mypy_cache/*" -not -path "*/.venv/*" \
      -not -path "*/venv/*" -not -path "*/.git/*" -not -path "*/.vscode/*" -not -name "*.pyc" \
      -not -path "./$OUT_DIR/*" -not -path "*/socks5tun.egg-info/*" -size -100k -print0 )
  if ((${#misc[@]} == 0)); then
    log_info "Нет подходящих файлов" >>"$MISC_FILE"
  else
    for f in "${misc[@]}"; do
      printf '\n# --- %s ---\n' "$f" >>"$MISC_FILE"
      cat "$f" >>"$MISC_FILE"
    done
  fi
}

# ----------------------------------------------------------------------------
# 7. dump_configs – сетевые/системные конфиги и вывод команд
# ----------------------------------------------------------------------------
append_cfg() {
  local path="$1"; local title="${2:-$1}"; local cmd="${3:-$USE_SUDO cat \"$path\"}"
  [[ -f "$path" ]] || return 0
  echo -e "\n# --- $title ---" >>"$CONFIG_FILE"
  eval "$cmd" >>"$CONFIG_FILE" 2>/dev/null || true
}

append_cmd() {
  local title="$1"; local cmd="$2"
  echo -e "\n# --- $title ---" >>"$CONFIG_FILE"
  eval "$cmd" >>"$CONFIG_FILE" 2>/dev/null || echo "[$title недоступно]" >>"$CONFIG_FILE"
}

dump_configs() {
  log_info "=== SERVER CONFIGS ===" >>"$CONFIG_FILE"
  USE_SUDO=""; [[ $EUID -ne 0 ]] && USE_SUDO="sudo"

  # команды
  declare -A CMDS=(
    ["ufw status"]="$USE_SUDO ufw status verbose | sed -r 's/\\x1B\\[[0-9;]*[mK]//g'"
    ["iptables-save"]="$USE_SUDO iptables-save"
    ["sysctl ip_forward/tcp"]="$USE_SUDO sysctl -a | grep -E 'net\\.ipv4\\.ip_forward|^tcp_'"
    ["ip a"]="ip a"
    ["ip r"]="ip r"
    ["ss -tunlp"]="(command -v ss &>/dev/null && (ss -tunlp || $USE_SUDO ss -tunlp))"
    ["systemctl running"]="$USE_SUDO systemctl list-units --type=service --state=running"
    ["crontab root"]="$USE_SUDO crontab -l -u root"
    ["dpkg (net)"]="dpkg -l | grep -Ei 'openvpn|stunnel|iptables|wireguard|net-tools|nginx'"
    ["journal socks5tun"]="$USE_SUDO journalctl -u socks5tun.service --no-pager -n 100 | sed -r 's/\\x1B\\[[0-9;]*[mK]//g'"
    ["nft list ruleset"]="$USE_SUDO nft list ruleset"
    ["pip freeze"]="pip freeze"

    # --- добавлено для WS-моста/NGINX ---
    ["systemctl ws-bridge"]="$USE_SUDO systemctl status ws-bridge --no-pager"
    ["journal ws-bridge"]="$USE_SUDO journalctl -u ws-bridge --no-pager -n 200 | sed -r 's/\\x1B\\[[0-9;]*[mK]//g'"
    ["nginx -T"]="$USE_SUDO nginx -T"
    ["websocat --version"]="/usr/local/bin/websocat --version || websocat --version"
    ["listen 80/5001/5000"]="ss -ltnp | egrep ':80\\b|:5001\\b|:5000\\b' || true"
  )
  for k in "${!CMDS[@]}"; do append_cmd "$k" "${CMDS[$k]}"; done

  # файлы через ассоциативный массив
  declare -A FILE_DUMPS=(
    ["/etc/stunnel/stunnel.conf"]="stunnel.conf"
    ["/etc/systemd/system/socks5tun.service"]="socks5tun.service"
    ["/etc/ssh/sshd_config"]="sshd_config"
    ["/etc/systemd/system/socks5tun-update.service"]="socks5tun-update.service"
    ["/usr/local/bin/update_socks5tun.sh"]="update_socks5tun.sh"
    ["/etc/systemd/system/socks5_healthcheck.service"]="socks5_healthcheck.service"
    ["/etc/systemd/system/socks5-healthcheck.timer"]="socks5_healthcheck.timer"
    ["/etc/systemd/system/restart-socks5tun@.service"]="restart-socks5tun@.service"
    ["/usr/local/bin/socks5_healthcheck.sh"]="socks5_healthcheck.sh"
    ["/usr/local/bin/socks5_telegram_alert.sh"]="socks5_telegram_alert.sh"
    ["/etc/systemd/system/stunnel.service"]="stunnel.service (alt)"
    ["/etc/tmpfiles.d/stunnel.conf"]="tmpfiles-stunnel.conf"
    ["/etc/init.d/stunnel4"]="init.d stunnel4"
    ["/etc/resolv.conf"]="resolv.conf"
    ["/var/lib/socks5health/last_status"]="last_status"

    # --- добавлено: WS-мост и nginx WS-конфиг ---
    ["/etc/systemd/system/ws-bridge.service"]="ws-bridge.service"
    ["/etc/nginx/sites-available/ws.conf"]="nginx ws.conf (available)"
    # симлинк покажем отдельно ниже
    ["/etc/nginx/nginx.conf"]="nginx.conf"

    # твои проектные скрипты
    ["/opt/socks5tun/scripts/nat6_setup.sh"]="nat6_setup.sh"
    ["/opt/socks5tun/scripts/update_cf_ufw.sh"]="update_cf_ufw.sh (Cloudflare UFW) - optional"
  )
  for path in "${!FILE_DUMPS[@]}"; do
    append_cfg "$path" "${FILE_DUMPS[$path]}"
  done

  # симлинк sites-enabled → покажем сам линк и целевой путь
  if [[ -L /etc/nginx/sites-enabled/ws.conf ]]; then
    echo -e "\n# --- nginx ws.conf symlink ---" >>"$CONFIG_FILE"
    ls -l /etc/nginx/sites-enabled/ws.conf >>"$CONFIG_FILE" 2>/dev/null || true
    REAL_TARGET="$(readlink -f /etc/nginx/sites-enabled/ws.conf 2>/dev/null || true)"
    if [[ -n "$REAL_TARGET" && -f "$REAL_TARGET" ]]; then
      echo -e "\n# --- nginx ws.conf (resolved target) ---" >>"$CONFIG_FILE"
      $USE_SUDO cat "$REAL_TARGET" >>"$CONFIG_FILE" 2>/dev/null || true
    fi
  fi

  # логи nginx по WS — только хвост, чтобы не раздуть файл
  if [[ -f /var/log/nginx/ws_access.log ]]; then
    echo -e "\n# --- /var/log/nginx/ws_access.log (tail -n 20) ---" >>"$CONFIG_FILE"
    $USE_SUDO tail -n 20 /var/log/nginx/ws_access.log >>"$CONFIG_FILE" 2>/dev/null || true
  fi

  # stunnel.pem публичная часть
  if command -v openssl &>/dev/null; then
    append_cfg /etc/stunnel/stunnel.pem \
      "/etc/stunnel/stunnel.pem (x509-dump)" \
      "openssl x509 -in /etc/stunnel/stunnel.pem -noout -text"
  fi
}


# ----------------------------------------------------------------------------
# 8. summarize – финальная сводка размеров файлов
# ----------------------------------------------------------------------------
summarize() {
  {
    echo
    log_info "📦 Файлы успешно собраны:"
    for f in "$OUT_FILE" "$MOD_FILE" "$MISC_FILE" "$TREE_FILE" "$STRUCTURE_FILE" "$CONFIG_FILE"; do
      [[ -f "$f" ]] && log_info "  • $f ($(du -h "$f" | cut -f1))"
    done
    log_info "✅ Диагностика завершена"
  } >>/dev/null # лог уже экранный; не пишем в файлы
}

# ----------------------------------------------------------------------------
# safe_run – последовательный запуск функций + остановка при ошибке
# ----------------------------------------------------------------------------
safe_run() {
  for func in "$@"; do
    log_info "→ $func()"
    "$func"
  done
}

# ----------------------------------------------------------------------------
# main – точка входа
# ----------------------------------------------------------------------------
main() {
  parse_cli "$@"
  init_output_files
  safe_run collect_tests collect_project_tree collect_modules collect_misc dump_configs
  summarize
}

main "$@"
