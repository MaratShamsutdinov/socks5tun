#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# Запуск тестов с покрытием: терминал + html + xml
pytest --cov=socks5tun --cov-branch \
       --cov-report=term-missing:skip-covered \
       --cov-report=html --cov-report=xml

echo
echo "HTML report → $(realpath htmlcov/index.html)"
