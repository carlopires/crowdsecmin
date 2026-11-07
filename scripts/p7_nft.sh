#!/usr/bin/env bash
# P7: nftables backend via direct mode, in an isolated netns.
# Also verifies unrelated tables are left untouched (spec §7.5).
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/env.sh

T=x86_64-unknown-linux-musl
BIN="$(pwd)/target/$T/release"
DIR="$(mktemp -d /tmp/cslite-p7.XXXXXX)"
PORT=18302
SEED="${SEED:-/tmp/decisions.json}"
[ -f "$SEED" ] || python3 scripts/gen_decisions.py "$SEED"
[ -x "$BIN/cslited" ] || { echo "build first"; exit 1; }

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
  mode: nftables
  blacklists_ipv4: cslitetest-blacklists
  blacklists_ipv6: cslitetest6-blacklists
  ipset_type: hash:net
  maxelem: 131072
  deny_action: DROP
  iptables_chains: [INPUT]
  add_rule_comments: false
  teardown_on_exit: false
  nft_table: cslitenft
  nft_chain: cslite-chain
  nft_priority: -10

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
nft add table inet keepme
python3 "$MOCK" "$PORT" "$SEED" >"$DIR/mock.log" 2>&1 & MOCKPID=$!
"$BIN/cslited" --config "$DIR/cslite.yaml" >"$DIR/srv.log" 2>&1 & SRV=$!

present() { nft list table inet cslitenft 2>/dev/null | grep -q 192.0.2.123; }

ADD=0
for i in $(seq 1 300); do if present; then ADD=1; break; fi; sleep 0.1; done
echo "== sets =="; nft list table inet cslitenft 2>/dev/null | grep -E "^[[:space:]]*set " | head
echo "== rules =="; nft list chain inet cslitenft "cslite-chain" 2>/dev/null | grep -E "saddr|drop" | head -4
if [ "$ADD" = 1 ]; then echo "ok: delta add present in nft set"; else echo "FAIL: delta add missing"; fi

GONE=0
for i in $(seq 1 300); do if ! present; then GONE=1; break; fi; sleep 0.1; done
if [ "$GONE" = 1 ]; then echo "ok: delta delete removed"; else echo "FAIL: delete not applied"; fi

if nft list table inet keepme >/dev/null 2>&1; then echo "ok: unrelated table untouched"; else echo "FAIL: foreign table removed"; fi
echo "rss: $(grep -E "^(VmRSS|RssAnon|Threads)" /proc/$SRV/status | tr "\n" " ")"
echo "== log =="; grep -E "direct|error" "$DIR/srv.log" | tail -6

kill "$SRV" "$MOCKPID" 2>/dev/null; wait 2>/dev/null
if [ "$ADD" = 1 ] && [ "$GONE" = 1 ]; then echo; echo "P7 nftables passed."; else exit 1; fi
'
