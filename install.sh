#!/usr/bin/env sh
set -eu
umask 077
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
if command -v pkg >/dev/null 2>&1 && [ -n "${TERMUX_VERSION:-}" ]; then
  pkg install -y python python-pip python-cryptography
  if [ ! -d .venv ]; then python -m venv --system-site-packages .venv; fi
else
  echo "Non-Termux host: using the installed Python 3 (3.10+ required)."
  if [ ! -d .venv ]; then python3 -m venv .venv; fi
fi
.venv/bin/python -m pip install .
if [ ! -f .env ]; then cp .env.example .env; fi
chmod 600 .env
mkdir -p data reports
chmod 700 data reports
.venv/bin/pocketsoc check --config config.yaml
printf '\nInstalled. Start safely: .venv/bin/pocketsoc run --config config.yaml\n'
printf 'Telegram stays disabled until you configure .env and enable it in config.yaml.\n'
