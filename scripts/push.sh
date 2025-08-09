#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

BRANCH="main"
MSG="${1:-auto: sync $(date -u +'%Y-%m-%d %H:%M:%S UTC')}"

# Гарантируем, что есть upstream
if ! git rev-parse --abbrev-ref --symbolic-full-name "@{u}" >/dev/null 2>&1; then
  git branch -u "origin/${BRANCH}" "${BRANCH}" || true
fi

# 1) Узнаем апстрим и подтягиваем удалённые ссылки
git fetch origin || true

# 2) Если удалённый впереди — подтянем изменения (rebase)
if git rev-list --left-right --count "HEAD...origin/${BRANCH}" >/dev/null 2>&1; then
  behind=$(git rev-list --left-right --count "HEAD...origin/${BRANCH}" | awk '{print $2}')
  if [ "${behind:-0}" -gt 0 ]; then
    git pull --rebase origin "${BRANCH}"
  fi
fi

# 3) Если есть локальные изменения в рабочем дереве — закоммитим
git add -A
if ! git diff --cached --quiet; then
  git commit -m "$MSG"
fi

# 4) Пушим ТОЛЬКО если есть локальные коммиты, которых нет в origin
ahead=0
if git rev-list --left-right --count "HEAD...origin/${BRANCH}" >/dev/null 2>&1; then
  ahead=$(git rev-list --left-right --count "HEAD...origin/${BRANCH}" | awk '{print $1}')
fi

if [ "${ahead:-0}" -gt 0 ]; then
  git push origin "${BRANCH}"
fi
