# scripts/coverage.sh
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

THRESHOLD="${1:-0}"  # по умолчанию не валим

pytest --cov=socks5tun --cov-branch \
       --cov-report=term-missing:skip-covered \
       --cov-report=html --cov-report=xml \
       --cov-fail-under="$THRESHOLD"

echo
echo "HTML report → $(realpath htmlcov/index.html)"
