#!/usr/bin/env sh
set -eu
umask 077
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
if [ ! -x .venv/bin/python ]; then echo "Run sh install.sh first." >&2; exit 1; fi
mkdir -p data
chmod 700 data
nohup .venv/bin/python -m pocketsoc run --config "${POCKETSOC_CONFIG:-config.yaml}" "$@" \
  >> data/background.log 2>&1 < /dev/null &
pid=$!
sleep 1
if ! kill -0 "$pid" 2>/dev/null; then
  echo "PocketSOC did not stay running. Read data/background.log (kept private)." >&2
  exit 1
fi
printf 'PocketSOC PID: %s\nStop gracefully: kill -TERM %s\n' "$pid" "$pid"
printf 'Android may still terminate background apps; this is not an uptime guarantee.\n'
