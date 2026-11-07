# Configuration

`cslited` reads `/etc/cslite/cslite.yaml` (override with `--config`). The parser
accepts a **strict YAML subset**: comments, top-level `key: value`, one level of
nesting, booleans, integers, quoted strings, inline lists (`[A, B]`) and
durations (`10s`, `4h`, `2h`, bare seconds). Unknown keys are a hard error with
a line number.

Validate with:

```bash
cslite check-config
```

## Keys

### Top level

| key | default | notes |
|---|---|---|
| `mode` | `lapi` | `lapi` (Mode B) or `direct` (Mode A) |
| `listen` | `127.0.0.1:8080` | Mode B only |
| `api_key` | — | inline key (or use `api_key_file`) |
| `api_key_file` | — | file containing the key (mode 0600/0640 recommended) |
| `log_level` | `info` | `error\|warn\|info\|debug`; rate-limited stderr |
| `update_frequency` | `10s` | bouncer LAPI poll hint; `cslite` does **not** poll CAPI at this rate |
| `startup_pull` | `true` | accepted for compatibility (startup is always pulled) |

Mode B requires `api_key` or `api_key_file`. The key must match the bouncer's
`api_key`.

### `persistence`

| key | default |
|---|---|
| `enabled` | `true` |
| `path` | `/var/lib/cslite/decisions.bin` |

Only used in Mode B; the origin→index map lives in the same directory.

### `capi`

| key | default |
|---|---|
| `enabled` | `true` |
| `credentials_path` | `/etc/crowdsec/online_api_credentials.yaml` |
| `update_frequency` | `2h` |

`update_frequency` is the **CAPI snapshot poll interval** (default 2 h). CAPI v3
returns the full blocklist on every request; the client diffs it and prunes
CAPI-origin decisions that disappeared. Local origins are exempt. Credentials file:

```yaml
url: https://api.crowdsec.net/
login: <machine_id>
password: <password>
```

### `backend`

| key | default | notes |
|---|---|---|
| `mode` | `iptables` | `iptables` (ipset) or `nftables` |
| `blacklists_ipv4` | `crowdsec-blacklists` | set name prefix |
| `blacklists_ipv6` | `crowdsec6-blacklists` | set name prefix |
| `ipset_type` | `hash:net` | must be `hash:net` (CIDRs) |
| `maxelem` | `131072` | must exceed the largest per-origin set |
| `deny_action` | `DROP` | documentation/CLI only |
| `iptables_chains` | `[INPUT]` | used by the Go bouncer config |
| `add_rule_comments` | `true` | Go bouncer config |
| `teardown_on_exit` | `false` | keep sets on exit: no protection gap |
| `nft_table` | `crowdsec` | nftables only |
| `nft_chain` | `crowdsec-chain` | nftables only |
| `nft_priority` | `-10` | nftables only |

### `local_detection`

| key | default |
|---|---|
| `enabled` | `false` |
| `log_path` | `/var/log/auth.log` |
| `ban_threshold` | `5` |
| `window` | `60s` |
| `ban_duration` | `4h` |

The systemd unit includes `CAP_DAC_READ_SEARCH` so the daemon can read
`auth.log` (`0640 syslog:adm`).

### `limits`

| key | default |
|---|---|
| `max_decisions` | `100000` |
| `max_bans_per_second` | `50` |

## Examples

Mode B (keep the Go bouncer):

```yaml
mode: lapi
listen: 127.0.0.1:8080
api_key_file: /etc/cslite/api.key
update_frequency: 10s

persistence:
  enabled: true
  path: /var/lib/cslite/decisions.bin

capi:
  enabled: true
  credentials_path: /etc/crowdsec/online_api_credentials.yaml
  update_frequency: 2h

backend:
  mode: iptables
  blacklists_ipv4: crowdsec-blacklists
  blacklists_ipv6: crowdsec6-blacklists
  ipset_type: hash:net
  maxelem: 131072
  teardown_on_exit: false

local_detection:
  enabled: true
  log_path: /var/log/auth.log
  ban_threshold: 5
  window: 60s
  ban_duration: 4h
```

Mode A (no engine, no bouncer), nftables variant:

```yaml
mode: direct
capi:
  enabled: true
  credentials_path: /etc/crowdsec/online_api_credentials.yaml
backend:
  mode: nftables
  blacklists_ipv4: crowdsec-blacklists
  blacklists_ipv6: crowdsec6-blacklists
  nft_table: crowdsec
  nft_chain: crowdsec-chain
  nft_priority: -10
```

## CLI key resolution

`cslite` (the CLI) resolves the daemon key from, in order:
`--api-key`, `CSLITE_API_KEY`, `api_key`, `api_key_file`. If the key file is
unreadable it exits 4 with a hint rather than sending an empty key (which would
yield a bare `403`).

`cslite decisions add` defaults to origin **`crowdsec`** (local set `-1`), which
the CAPI snapshot prune never removes. Use `--origin CAPI` only for the community
set, which is reconciled from the snapshot.
