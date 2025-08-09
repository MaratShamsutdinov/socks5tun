#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

BRANCH="main"
USER_MSG="${1:-auto}"

AUTO_FREEZE=${AUTO_FREEZE:-1}   # 1 = обновлять requirements.txt из .venv, 0 = не трогать

# ---- выбрать python ----
pick_python() {
  if [[ -x ".venv/bin/python" ]]; then echo ".venv/bin/python"; return; fi
  command -v python3 >/dev/null 2>&1 && { echo python3; return; }
  command -v python  >/dev/null 2>&1 && { echo python;  return; }
  echo python3
}
PY="$(pick_python)"

# ---- upstream + fetch/pull --rebase ----
git fetch origin || true
git rev-parse --abbrev-ref --symbolic-full-name "@{u}" >/dev/null 2>&1 || git branch -u "origin/${BRANCH}" "${BRANCH}" || true
if git rev-list --left-right --count "HEAD...origin/${BRANCH}" >/dev/null 2>&1; then
  behind=$(git rev-list --left-right --count "HEAD...origin/${BRANCH}" | awk '{print $2}')
  [[ "${behind:-0}" -gt 0 ]] && git pull --rebase origin "${BRANCH}"
fi

# ---- выясняем, менялся ли requirements.txt относительно origin/BRANCH ----
req_changed=0
if [[ -f requirements.txt ]]; then
  base="$(git merge-base HEAD "origin/${BRANCH}" 2>/dev/null || true)"
  if [[ -z "$base" ]]; then
    req_changed=1
  elif git diff --name-only "$base" HEAD | grep -qx "requirements.txt"; then
    req_changed=1
  fi
fi

# ---- AUTO_FREEZE: при необходимости перегенерим requirements.txt из .venv ----
req_updated_by_freeze=0
if [[ "$AUTO_FREEZE" = "1" ]]; then
  # Определяем pip
  if [[ -n "${VIRTUAL_ENV:-}" && -x "$VIRTUAL_ENV/bin/pip" ]]; then
    PIP="$VIRTUAL_ENV/bin/pip"
  elif [[ -x ".venv/bin/pip" ]]; then
    PIP=".venv/bin/pip"
  elif [[ -x "/opt/venv-pyroute/bin/pip" ]]; then
    PIP="/opt/venv-pyroute/bin/pip"
  else
    PIP="$PY -m pip"
  fi

  tmp_req="$(mktemp)"
  # shellcheck disable=SC2086
  $PIP freeze | sed '/^pkg-resources==/d' > "$tmp_req"

  if [[ ! -f requirements.txt ]] || ! diff -q "$tmp_req" requirements.txt >/dev/null 2>&1; then
    echo "📄 Updating requirements.txt from env via: $PIP"
    mv "$tmp_req" requirements.txt
    req_updated_by_freeze=1
  else
    rm -f "$tmp_req"
  fi
fi

# ---- если requirements изменился (локально или после freeze) — ставим deps ----
if [[ -f requirements.txt && ( "$req_changed" -eq 1 || "$req_updated_by_freeze" -eq 1 ) ]]; then
  echo "📦 Installing deps with $($PY -c 'import sys; print(sys.executable)')"
  $PY -m pip install --upgrade pip
  $PY -m pip install -r requirements.txt
else
  echo "requirements.txt unchanged — skip deps install."
fi

# ---- индексируем изменения ----
git add -A

# нет staged-изменений — выходим
if git diff --cached --quiet; then
  echo "Nothing to commit."
  # но всё равно попробуем запушить, если появились локальные коммиты
else
  # умное сообщение
  stat_line="$(git diff --cached --name-status | awk '{c[$1]++} END{for (k in c) printf "%s:%d ", k, c[k]}' | sed 's/ $//')"
  [[ -z "$stat_line" ]] && stat_line="A:0 M:0 D:0"
  ins_del="$(git diff --cached --numstat | awk '{ins+=$1; del+=$2} END{printf "+%d/-%d", ins?ins:0, del?del:0}')"
  mapfile -t files < <(git diff --cached --name-only)
  total=${#files[@]}; show=$(( total<10 ? total : 10 ))
  files_list="$(printf '%s, ' "${files[@]:0:show}")"; files_list="${files_list%, }"
  more=$(( total - show )); [[ $more -gt 0 ]] && files_list="$files_list …(+${more} more)"
  ts="$(date -u +'%Y-%m-%d %H:%M:%S UTC')"
  MSG="${USER_MSG}: ${ts} | ${total} file(s) | ${stat_line} | ${ins_del} | ${files_list}"
  git commit -m "$MSG"
fi

# ---- пушим только если есть локальные коммиты впереди origin ----
ahead=0
if git rev-list --left-right --count "HEAD...origin/${BRANCH}" >/dev/null 2>&1; then
  ahead=$(git rev-list --left-right --count "HEAD...origin/${BRANCH}" | awk '{print $1}')
fi
if [[ "${ahead:-0}" -gt 0 ]]; then
  git push origin "${BRANCH}"
  echo "Pushed to origin/${BRANCH}."
else
  echo "Nothing to push — local == remote."
fi
