#!/bin/sh
set -e

PORT="8443"
if [ -n "$VEILINK_BIND_ADDR" ]; then
  PORT="${VEILINK_BIND_ADDR##*:}"
fi

if curl -k -fsS "https://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1; then
  exit 0
fi

if pgrep veilink >/dev/null 2>&1; then
  exit 0
fi

exit 1
