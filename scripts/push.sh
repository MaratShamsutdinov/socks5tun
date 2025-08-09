#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

BRANCH="main"
MSG="${1:-auto: sync $(date -u +'%Y-%m-%d %H:%M:%S UTC')}"

# ---- helper: выбрать python (предпочтительно из .venv) ----
pick_python() {
  if [[ -x ".venv/bin/python" ]]; then echo ".venv/bin/python"; return; fi
  if command -v python3 >/dev/null 2>&1; then echo "python3"; return; fi
  if command -v python >/dev/null 2>&1;  then echo "python";  return; fi
  echo "python3"  # на случай экзотики
}
PY="$(pick_python)"

# ---- гарантируем upstream ----
if ! git rev-parse --abbrev-ref --symbolic-full-name "@{u}" >/dev/null 2>&1; then
  git branch -u "origin/${BRANCH}" "${BRANCH}" || true
fi

# ---- fetch и при необходимости подтянуть удалённые изменения ----
git fetch origin || true
if git rev-list --left-right --count "HEAD...origin/${BRANCH}" >/dev/null 2>&1; then
  behind=$(git rev-list --left-right --count "HEAD...origin/${BRANCH}" | awk '{print $2}')
  if [[ "${behind:-0}" -gt 0 ]]; then
    git pull --rebase origin "${BRANCH}"
  fi
fi

# ---- если менялся requirements.txt в локальных коммитах — установить зависимости ----
req_changed=0
if [[ -f requirements.txt ]]; then
  # base: общая точка с origin/BRANCH (или пусто, если первый пуш)
  base="$(git merge-base HEAD "origin/${BRANCH}" 2>/dev/null || true)"
  if [[ -z "$base" ]]; then
    # первый пуш: если файл существует — считаем, что изменился
    req_changed=1
  else
    if git diff --name-only "$base" HEAD | grep -qx "requirements.txt"; then
      req_changed=1
    fi
  fi
fi

if [[ "$req_changed" -eq 1 ]]; then
  echo "📦 requirements.txt changed — installing dependencies with $($PY -c 'import sys; print(sys.executable)')"
  "$PY" -m pip install --upgrade pip
  "$PY" -m pip install -r requirements.txt
else
  echo "requirements.txt unchanged — skip deps install."
fi

# ---- добавить/закоммитить локальные правки ----
git add -A
if ! git diff --cached --quiet; then
  git commit -m "$MSG"
fi

# ---- пушить ТОЛЬКО если есть локальные коммиты, которых нет в origin ----
ahead=0
if git rev-list --left-right --count "HEAD...origin/${BRANCH}" >/dev/null 2>&1; then
  ahead=$(git rev-list --left-right --count "HEAD...origin/${BRANCH}" | awk '{print $1}')
fi
if [[ "${ahead:-0}" -gt 0 ]]; then
  git push origin "${BRANCH}"
else
  echo "Nothing to push — local == remote."
fi
