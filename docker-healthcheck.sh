#!/bin/sh
set -eu

# Master resolves defaults, persisted settings, then explicitly visited CLI flags.
# Read PID 1's flags rather than our own; the last occurrence wins as with Go flags.
args=$(tr '\000' '\n' < /proc/1/cmdline)
flag() {
  printf '%s\n' "$args" | awk -v name="-$1" '
    $0 == name { if (getline > 0) value = $0; next }
    index($0, name "=") == 1 { value = substr($0, length(name) + 2) }
    END { print value }
  '
}
listen=$(flag listen-addr)
scheme=$(flag scheme)
database=$(flag database)
database=${database:-/data/veilink.db}

if [ -z "$listen" ] || [ -z "$scheme" ]; then
  if [ -e "$database" ]; then
    # -readonly must never create a DB during a health probe. Query errors fail
    # closed rather than checking an unrelated listener on the default port.
    stored=$(sqlite3 -readonly -separator '|' "$database" \
      "SELECT json_extract(data, '$.ListenAddr'), json_extract(data, '$.Scheme') FROM master_config WHERE id=1") || exit 1
    if [ -n "$stored" ]; then
      persisted_listen=${stored%%|*}
      persisted_scheme=${stored#*|}
      listen=${listen:-$persisted_listen}
      scheme=${scheme:-$persisted_scheme}
    fi
  fi
fi
listen=${listen:-127.0.0.1:8443}
scheme=${scheme:-http}
port=${listen##*:}
host=${listen%:*}
case "$host" in
  ''|'0.0.0.0') host=127.0.0.1 ;;
  '::'|'[::]') host='[::1]' ;;
  *:*) case "$host" in \[*\]) ;; *) host="[$host]" ;; esac ;;
esac

case "$scheme" in
  https) curl --noproxy '*' --insecure --fail --silent --max-time 4 "https://${host}:${port}/healthz" >/dev/null ;;
  http)  curl --noproxy '*' --fail --silent --max-time 4 "http://${host}:${port}/healthz" >/dev/null ;;
  *) exit 1 ;;
esac
