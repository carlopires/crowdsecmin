#!/usr/bin/env bash
# P5: direct mode (CAPI -> ipset) with no store and no HTTP server.
# Runs the daemon + mock CAPI in one private netns (needs ipset/root inside).
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/env.sh

T=x86_64-unknown-linux-musl
BIN="$(pwd)/target/$T/release"
DIR="$(mktemp -d /tmp/cslite-p5.XXXXXX)"
PORT=18301
SEED="${SEED:-/tmp/decisions.json}"
[ -f "$SEED" ] || python3 scripts/gen_decisions.py "$SEED"
[ -x "$BIN/cslited" ] || { echo "build first: cargo build --release --target $T"; exit 1; }

cat >"$DIR/creds.yaml" <<EOF
url: http://127.0.0.1:$PORT
login: testlogin
password: testpass
EOF

cat >"$DIR/cslite.yaml" <<EOF
mode: direct
log_level: debug
update_frequency: 1s

persistence:
  enabled: false
  path: $DIR/state/decisions.bin

capi:
  enabled: true
  credentials_path: $DIR/creds.yaml
  update_frequency: 1s

backend:
  mode: iptables
  blacklists_ipv4: cslitetest-blacklists
  blacklists_ipv6: cslitetest6-blacklists
  ipset_type: hash:net
  maxelem: 131072
  deny_action: DROP
  iptables_chains: [INPUT]
  add_rule_comments: false
  teardown_on_exit: false

limits:
  max_decisions: 100000
  max_bans_per_second: 50
EOF
mkdir -p "$DIR/state"
trap 'rm -rf "$DIR"' EXIT

sudo -n env BIN="$BIN" DIR="$DIR" PORT="$PORT" SEED="$SEED" \
    MOCK="$(pwd)/scripts/p5_mock.py" unshare --net bash -c '
set -u
ip link set lo up
python3 "$MOCK" "$PORT" "$SEED" >"$DIR/mock.log" 2>&1 & MOCKPID=$!
"$BIN/cslited" --config "$DIR/cslite.yaml" >"$DIR/srv.log" 2>&1 & SRV=$!

total() { t=0; for s in $(ipset list -n | grep cslitetest || true); do n=$(ipset list -t "$s" | awk "/Number of entries/{print \$4}"); t=$((t + ${n:-0})); done; echo $t; }
present() { for s in $(ipset list -n | grep cslitetest || true); do if ipset test "$s" 192.0.2.123 2>/dev/null; then return 0; fi; done; return 1; }

ADD=0
for i in $(seq 1 300); do if present; then ADD=1; break; fi; sleep 0.1; done
echo "entries after startup+delta: $(total)"
if [ "$ADD" = 1 ]; then echo "ok: delta add enforced"; else echo "FAIL: delta add not enforced"; fi

GONE=0
for i in $(seq 1 300); do if ! present; then GONE=1; break; fi; sleep 0.1; done
if [ "$GONE" = 1 ]; then echo "ok: delta delete removed"; else echo "FAIL: delete not applied"; fi

echo "sets:"; ipset list -n | grep cslitetest || true
echo "rss: $(grep -E "^(VmRSS|RssAnon|RssFile|Threads)" /proc/$SRV/status | tr "\n" " ")"
echo "== log =="; grep -E "direct|error" "$DIR/srv.log" | tail -6

kill "$SRV" "$MOCKPID" 2>/dev/null; wait 2>/dev/null
if [ "$ADD" = 1 ] && [ "$GONE" = 1 ]; then echo; echo "P5 passed."; else exit 1; fi
'
