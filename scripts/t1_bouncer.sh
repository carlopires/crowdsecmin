#!/usr/bin/env bash
# T1: wire compatibility with the UNMODIFIED crowdsec-firewall-bouncer v0.0.36.
#
# Runs the cslite LAPI and the real Go bouncer in the SAME private network
# namespace (so 127.0.0.1:18080 is shared and ipset/iptables are isolated from
# the host). Requires passwordless sudo + unshare.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck disable=SC1091
. scripts/env.sh

TARGET=x86_64-unknown-linux-musl
ROOT="$(pwd)"
SERVER="$ROOT/target/$TARGET/release/cslited"
CFG="$ROOT/deploy/cslite.lapi-test.yaml"
SEED="${SEED:-/tmp/decisions.json}"
BOUNCER="${BOUNCER:-$HOME/opt/cs-bouncer-0.0.36/crowdsec-firewall-bouncer-v0.0.36/crowdsec-firewall-bouncer}"
BCFG="$ROOT/deploy/bouncer.t1.yaml"

[ -x "$SERVER" ] || cargo build --release --target "$TARGET" --quiet
[ -f "$SEED" ] || python3 scripts/gen_decisions.py "$SEED"
[ -x "$BOUNCER" ] || { echo "bouncer binary not found: $BOUNCER"; exit 2; }

sudo -n env SERVER="$SERVER" CFG="$CFG" SEED="$SEED" BOUNCER="$BOUNCER" BCFG="$BCFG" \
    unshare --net bash -c '
set -euo pipefail
# A fresh netns starts with loopback DOWN; bring it up so 127.0.0.1 works.
ip link set lo up
"$SERVER" --config "$CFG" --seed "$SEED" >/tmp/t1-server.log 2>&1 & SPID=$!
for _ in $(seq 1 100); do
    curl -s -o /dev/null http://127.0.0.1:18080/health && break
    sleep 0.1
done
curl -s -o /dev/null -H "X-Api-Key: testkey" "http://127.0.0.1:18080/v1/decisions/stream?startup=true" \
    || { echo "server not serving"; kill $SPID; exit 1; }

"$BOUNCER" -c "$BCFG" >/tmp/t1-bouncer.log 2>&1 & BPID=$!
sleep 15   # startup sync + one 10s delta poll

echo "== ipsets created by the bouncer =="
total=0
for s in $(ipset list -n | grep cslitetest || true); do
    n=$(ipset list -t "$s" | awk "/Number of entries/{print \$4}")
    echo "  $s: ${n:-?} entries"
    total=$((total + ${n:-0}))
done
echo "  TOTAL applied: $total (expected 15344)"

RC=0
echo "== cslited memory (T2) =="
grep -E "^(VmRSS|RssAnon|RssFile|Threads)" /proc/$SPID/status | sed "s/^/  /"
rss=$(awk "/^VmRSS/{print \$2}" /proc/$SPID/status)
if [ "${rss:-999999}" -gt 3072 ]; then
    echo "T2 FAIL: cslited VmRSS ${rss}kB > 3072kB"; RC=1
fi

echo "== iptables CROWDSEC_CHAIN =="
iptables -L CROWDSEC_CHAIN -n 2>/dev/null | head -8 || echo "  (no chain)"

echo "== bouncer errors (excluding known teardown noise) =="
# The Go bouncer logs chain-teardown noise on every start (spec §7.6). Treat
# those as benign; fail on anything else.
if grep -iE "level=error|level=fatal|panic" /tmp/t1-bouncer.log \
   | grep -viE "does not exist|No chain/target|error while (removing|flushing|deleting)" \
   | grep -q .; then
    echo "T1 FAIL: bouncer logged non-benign errors"; RC=1
else
    echo "  no non-benign errors (teardown noise ignored)"
fi
echo "== bouncer log (tail) =="
tail -6 /tmp/t1-bouncer.log

kill $BPID 2>/dev/null; wait $BPID 2>/dev/null || true
kill $SPID 2>/dev/null; wait $SPID 2>/dev/null || true

if [ "$total" -ne 15344 ]; then
    echo "T1 FAIL: applied $total decisions, expected 15344"; RC=1
fi
if [ "$RC" -eq 0 ]; then echo; echo "T1 passed."; fi
exit $RC
'
