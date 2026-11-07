#!/usr/bin/env bash
# Build a .deb with the static binaries, systemd unit, example config, docs.
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/env.sh

T=x86_64-unknown-linux-musl
VERSION="$(grep -m1 '^version' Cargo.toml | sed 's/.*"\(.*\)"/\1/')"
BIN="target/$T/release"
OUT="$(pwd)/dist"
ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

cargo build --release --target "$T" --quiet
rm -rf "$OUT" && mkdir -p "$OUT"

mkdir -p "$ROOT/DEBIAN" "$ROOT/usr/local/sbin" "$ROOT/lib/systemd/system" \
         "$ROOT/etc/cslite" "$ROOT/usr/share/doc/cslite/docs"
install -m 0755 "$BIN/cslited" "$ROOT/usr/local/sbin/cslited"
install -m 0755 "$BIN/cslite" "$ROOT/usr/local/sbin/cslite"
install -m 0644 deploy/cslite.service "$ROOT/lib/systemd/system/cslite.service"
install -m 0644 deploy/cslite.yaml.example "$ROOT/etc/cslite/cslite.yaml.example"
install -m 0644 README.md "$ROOT/usr/share/doc/cslite/README.md"
install -m 0644 RUNBOOK.md "$ROOT/usr/share/doc/cslite/RUNBOOK.md"
install -m 0644 LICENSE NOTICE "$ROOT/usr/share/doc/cslite/"
install -m 0644 docs/*.md "$ROOT/usr/share/doc/cslite/docs/"

cat >"$ROOT/DEBIAN/control" <<EOF
Package: cslite
Version: $VERSION
Section: net
Priority: optional
Architecture: amd64
Maintainer: ops <ops@example.invalid>
Depends: ipset | nftables
Description: lightweight CrowdSec-compatible LAPI / firewall bouncer
 cslite is a small, static, memory-safe replacement for the CrowdSec
 engine and firewall bouncer. It runs as a wire-compatible LAPI (mode
 lapi) or as a direct CAPI-to-firewall bouncer (mode direct).
EOF

cat >"$ROOT/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
systemctl daemon-reload >/dev/null 2>&1 || true
if [ ! -f /etc/cslite/cslite.yaml ]; then
    cp /etc/cslite/cslite.yaml.example /etc/cslite/cslite.yaml
    echo "cslite: wrote /etc/cslite/cslite.yaml from example; edit mode/api_key."
fi
exit 0
EOF
chmod 0755 "$ROOT/DEBIAN/postinst"

dpkg-deb --build --root-owner-group "$ROOT" "$OUT/cslite_${VERSION}_amd64.deb" >/dev/null
echo "built $OUT/cslite_${VERSION}_amd64.deb"
dpkg-deb --info "$OUT/cslite_${VERSION}_amd64.deb" | sed -n '1,12p'
echo "--- contents ---"
dpkg-deb --contents "$OUT/cslite_${VERSION}_amd64.deb"
