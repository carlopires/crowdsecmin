# Operations

## Prerequisites

- root (enforcement needs `CAP_NET_ADMIN`).
- `ipset` and/or `nftables`.
- For Mode B/A with CAPI: `/etc/crowdsec/online_api_credentials.yaml`
  (`url`, `login`, `password`; root-owned `0600`).
- No compiler or toolchain on the target host (binaries are static).

## Install

```bash
sudo dpkg -i cslite_0.1.0_amd64.deb
sudoedit /etc/cslite/cslite.yaml
sudo cslite check-config
```

If you use `api_key_file: /etc/cslite/api.key`, make it readable by the admins
who run the CLI (the daemon runs as root):

```bash
sudo chgrp sudo /etc/cslite/api.key && sudo chmod 640 /etc/cslite/api.key
```

Without that, `cslite decisions list` as a non-root user exits 4 with a clear
hint. The CLI also accepts `--api-key` or `CSLITE_API_KEY`.

## Mode B — wire-compatible LAPI (keep the Go bouncer)

```yaml
mode: lapi
listen: 127.0.0.1:8080
api_key_file: /etc/cslite/api.key     # must match the bouncer's api_key
capi: { enabled: true }
persistence: { enabled: true, path: /var/lib/cslite/decisions.bin }
```

Cutover (replace the Go **engine**, keep the Go **bouncer**):

1. `sudo systemctl stop crowdsec`            # engine only
2. `sudo systemctl enable --now cslite`
3. Verify:
   - `cslite status` → `up: {"status":"up"}`
   - `journalctl -u cslite -n 20` shows `serving LAPI` and CAPI polls
   - bouncer log shows decisions being added
   - `cslite decisions list | head`
4. **Reconcile once** — removes entries the old engine left in ipset and adds
   any the store has but ipset lacks (two-way, needs root):
   ```bash
   sudo cslite reconcile --dry-run   # review
   sudo cslite reconcile             # apply
   sudo cslite reconcile --dry-run   # expect 0 stale / 0 missing
   ```
5. Rollback: `sudo systemctl stop cslite && sudo systemctl start crowdsec`
   (re-enable with `systemctl enable crowdsec` if it was disabled).

## Mode A — direct (no engine, no bouncer)

```yaml
mode: direct
capi: { enabled: true, credentials_path: /etc/crowdsec/online_api_credentials.yaml }
backend: { mode: iptables, blacklists_ipv4: crowdsec-blacklists, maxelem: 131072 }
```

1. `sudo systemctl stop crowdsec-firewall-bouncer crowdsec`
2. `sudo systemctl enable --now cslite`
3. Verify: `ipset list -n`, `ipset test`, `journalctl -u cslite` shows
   `direct: full_refresh=true applied N changes`.
4. Rollback: `sudo systemctl stop cslite && sudo systemctl enable --now crowdsec
   crowdsec-firewall-bouncer`.

For nftables set `backend.mode: nftables` (and optionally `nft_table`,
`nft_chain`, `nft_priority`). Only the configured table is managed; unrelated
tables are never touched.

## Local detection

```yaml
local_detection:
  enabled: true
  log_path: /var/log/auth.log
  ban_threshold: 5
  window: 60s
  ban_duration: 4h
```

Bans land in the store as origin `crowdsec` / scenario `ssh:bruteforce` and are
enforced in `crowdsec-blacklists-1`. The unit needs `CAP_DAC_READ_SEARCH` to read
`auth.log` (`0640 syslog:adm`). Enabling detection adds a third thread.

## Verification and measurement

```bash
curl -s http://127.0.0.1:8080/health
cslite decisions list | head
ipset test crowdsec-blacklists-0 203.0.113.7
nft list set inet crowdsec crowdsec-blacklists-0

# RSS: RssAnon/RssFile live in /proc/<pid>/status
grep -E 'RssAnon|RssFile|RssShmem|VmRSS|Threads' /proc/$(pidof cslited)/status
# (smaps_rollup only exposes Rss/Pss/Anonymous)
```

Baselines: Mode B ~2.2 MB (2–3 threads), Mode A ~1.0 MB ipset / ~1.2 MB nftables.

## Removing the CrowdSec engine (keeping the bouncer)

Mode B only needs the bouncer package and CAPI credentials. The engine package
can be removed, but its **purge** script deletes `/etc/crowdsec/*` (except
`bouncers/`) and deletes `/var/lib/crowdsec`. Relocate the credentials first:

```bash
# 1. decouple cslite from /etc/crowdsec
sudo install -m600 /etc/crowdsec/online_api_credentials.yaml /etc/cslite/capi_credentials.yaml
sudo sed -i 's#/etc/crowdsec/online_api_credentials.yaml#/etc/cslite/capi_credentials.yaml#' /etc/cslite/cslite.yaml
sudo cslite check-config
sudo systemctl restart cslite
# verify: cslite decisions list | wc -l  (~15k) and journal shows CAPI polls

# 2. back up and purge the engine
sudo tar czf /var/backups/crowdsec-config-$(date +%Y%m%d-%H%M).tgz -C /etc crowdsec
sudo apt-get purge -y crowdsec
```

The bouncer package (`crowdsec-firewall-bouncer-iptables`) depends only on
`gettext-base`, `iptables`, and `ipset`; it keeps running. `/etc/crowdsec/bouncers`
is preserved by the engine's purge script.

**Rollback** after removal requires reinstalling `crowdsec` from the configured
packagecloud repo and restoring the backup (no `.deb` is cached by default).

## Gotchas

- **`maxelem`** must exceed the largest per-origin set; otherwise `ipset restore`
  aborts with "hash is full".
- ipset sets must be **`hash:net`** (decisions include CIDRs).
- The **origin→index map** is persisted in the state dir; don't reorder it or the
  `-0`/`-1` assignment changes.
- **nftables** interval sets reject overlaps; contained CIDRs are dropped (still
  covered) and are not re-added until restart. `auto-merge` cannot be combined
  with per-entry timeouts.
- **CAPI is v3** (`/v3/...`); `/v1/...` is the local LAPI. Do not send
  `community_pull=false` to CAPI — it returns an empty blocklist.
- CAPI may close TLS without `close_notify`; the client treats that as EOF.
- The 24 h soak is available: `SOAK_SECONDS=86400 SOAK_INTERVAL=3600 ./scripts/soak.sh`.
