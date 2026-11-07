#!/usr/bin/env bash
# P4: CAPI client against a local mock CAPI (login, startup snapshot, delta).
# Uses the daemon's own store, so this also exercises server+capi thread sharing.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck disable=SC1091
. scripts/env.sh

T=x86_64-unknown-linux-musl
BIN="target/$T/release"
DIR="$(mktemp -d /tmp/cslite-p4.XXXXXX)"
PORT=18300
SEED="${SEED:-/tmp/decisions.json}"
[ -f "$SEED" ] || python3 scripts/gen_decisions.py "$SEED"

python3 scripts/p4_mock.py "$PORT" "$SEED" >"$DIR/mock.log" 2>&1 &
MOCK=$!

cat >"$DIR/creds.yaml" <<EOF
url: http://127.0.0.1:$PORT
login: testlogin
password: testpass
EOF

cat >"$DIR/cslite.yaml" <<EOF
mode: lapi
listen: 127.0.0.1:18082
api_key: "testkey"
log_level: debug
update_frequency: 1s

persistence:
  enabled: true
  path: $DIR/decisions.bin

capi:
  enabled: true
  credentials_path: $DIR/creds.yaml
  update_frequency: 2h

backend:
  mode: iptables
  blacklists_ipv4: cslitetest-blacklists
  blacklists_ipv6: cslitetest6-blacklists
  ipset_type: hash:net
  maxelem: 4096
  deny_action: DROP
  iptables_chains: [INPUT]
  add_rule_comments: false
  teardown_on_exit: false

limits:
  max_decisions: 100000
  max_bans_per_second: 50
EOF

[ -x "$BIN/cslited" ] || { echo "build first: cargo build --release --target $T"; exit 1; }
"$BIN/cslited" --config "$DIR/cslite.yaml" >"$DIR/srv.log" 2>&1 &
SRV=$!
cleanup() { kill "$SRV" "$MOCK" 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$DIR"; }
trap cleanup EXIT

for _ in $(seq 1 100); do
    if curl -s -o /dev/null http://127.0.0.1:18082/health 2>/dev/null; then break; fi
    sleep 0.05
done

count=0
for _ in $(seq 1 200); do
    body=$(curl -s -H "X-Api-Key: testkey" "http://127.0.0.1:18082/v1/decisions" 2>/dev/null || true)
    count=$(printf '%s' "$body" | grep -o '"id":' | wc -l || true)
    if [ "$count" -ge 15345 ]; then break; fi
    sleep 0.1
done

echo "decisions after CAPI sync: $count (expect >= 15345)"
body=$(curl -s -H "X-Api-Key: testkey" "http://127.0.0.1:18082/v1/decisions" 2>/dev/null || true)
delta=$(printf '%s' "$body" | grep -c 203.0.113.99 || true)
echo "delta decision 203.0.113.99 present: $delta"
echo "== daemon log (capi lines) =="
grep -E "capi|serving" "$DIR/srv.log" | tail -8

if [ "$count" -lt 15345 ] || [ "$delta" -lt 1 ]; then
    echo "P4 FAIL"
    exit 1
fi
echo
echo "P4 passed."
