#!/bin/bash
set -euo pipefail
unset ALL_PROXY HTTP_PROXY HTTPS_PROXY all_proxy http_proxy https_proxy
D=${1:?scratch directory required}
variant=${2:-standard}
label=${3:-$variant}
python3 tests/perf/mihomo-configs.py "$D" "$variant"
"$D/mihomo" -t -d "$D/server" -f "$D/mihomo-server.json" > "$D/check-$label-server.log" 2>&1
"$D/mihomo" -t -d "$D/client" -f "$D/mihomo-client.json" > "$D/check-$label-client.log" 2>&1
"$D/mihomo" -d "$D/server" -f "$D/mihomo-server.json" > "$D/run-$label-server.log" 2>&1 & S=$!
"$D/mihomo" -d "$D/client" -f "$D/mihomo-client.json" > "$D/run-$label-client.log" 2>&1 & C=$!
cleanup() { kill "$S" "$C" 2>/dev/null || true; wait "$S" "$C" 2>/dev/null || true; }
trap cleanup EXIT
sleep 2
kill -0 "$S" "$C"
for network in tcp udp; do
 "$D/hy2bench" -cert-dir "$D" -network "$network" > "$D/result-$label-$network.log" 2>&1
 cat "$D/result-$label-$network.log"
done
