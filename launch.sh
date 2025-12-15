#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if [ ! -d ".venv" ]; then
  echo "Virtualenv .venv not found. Run ./setup.sh first." >&2
  exit 1
fi

source .venv/bin/activate

trap 'kill 0' INT TERM EXIT

python server/server.py &
SERVER_PID=$!

# Give server a moment to bind before client connects.
sleep 1

python client/client.py &
CLIENT_PID=$!

wait "$CLIENT_PID" "$SERVER_PID" 2>/dev/null || true

