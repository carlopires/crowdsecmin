# crowdsecmin (`cslite`)

An independent, memory-safe **Rust** implementation of a CrowdSec-compatible
Local API and firewall bouncer. It is small (~2 MB RSS), static, and speaks
enough of the CrowdSec wire protocol that the **unmodified
`crowdsec-firewall-bouncer` v0.0.36** works against it.

> **Not affiliated with CrowdSec SAS.** "CrowdSec" is a trademark of CrowdSec
> SAS and is used only to describe interoperability. See [NOTICE](NOTICE).

## Why

A stock CrowdSec engine + Go bouncer needs ~156 MB RSS on a small VPS (the Go
runtime dominates; the data is only a few MB). `cslite` was built to keep the
same protection with a fraction of the footprint.

Measured on a 2 vCPU / 953 MB Ubuntu 24.04 host with ~15k community decisions:

| | RSS | threads | notes |
|---|---|---|---|
| CrowdSec engine + Go bouncer | ~156 MB | — | baseline |
| **cslite, Mode B (LAPI)** | **~2.2 MB** | 2–3 | keeps the Go bouncer |
| **cslite, Mode A (direct)** | **~1.0 MB** | 1 | no bouncer, no HTTP server |

## Features

- **Mode B — wire-compatible LAPI**: serves `/v1/decisions/stream`,
  `/v1/decisions`, `/v1/bouncers`, `/health`, `/v1/heartbeat` with `X-Api-Key`
  auth and chunked responses. The existing Go bouncer keeps enforcing.
- **Mode A — direct**: one process polls CAPI and writes ipset/nftables
  directly; no store, no HTTP server.
- **CAPI v3 client** over rustls: login, startup snapshot, 10 s deltas, 2 h full
  refresh, backoff.
- **Enforcement**: ipset (`hash:net`, per-entry timeouts) and nftables
  (interval sets, containment-safe).
- **Local SSH detection**: tails `auth.log`, bans at a threshold, origin
  `crowdsec`.
- **Operations**: persistence across restarts, expiry pruning, two-way
  `reconcile`, rate-limited logs, static musl binaries.

## Build

`ring` needs a musl C compiler for the static target:

```bash
sudo apt-get install musl-tools
. scripts/env.sh
cargo build --release --target x86_64-unknown-linux-musl
# target/x86_64-unknown-linux-musl/release/{cslited,cslite}
```

The resulting binaries are static; the target host needs no toolchain.

## Quick start

```bash
sudo dpkg -i dist/cslite_0.1.0_amd64.deb
sudoedit /etc/cslite/cslite.yaml     # mode + api_key/api_key_file
cslite check-config
sudo systemctl enable --now cslite
cslite status
```

Mode B (keep the Go bouncer, replace the engine):

```yaml
mode: lapi
listen: 127.0.0.1:8080
api_key_file: /etc/cslite/api.key    # the bouncer's api_key
capi: { enabled: true }
persistence: { enabled: true, path: /var/lib/cslite/decisions.bin }
```

Mode A (no engine, no bouncer):

```yaml
mode: direct
capi: { enabled: true, credentials_path: /etc/crowdsec/online_api_credentials.yaml }
backend: { mode: iptables, blacklists_ipv4: crowdsec-blacklists, maxelem: 131072 }
```

See [docs/configuration.md](docs/configuration.md) and
[docs/operations.md](docs/operations.md).

## CLI

```bash
cslite status
cslite decisions list [--json]
cslite decisions add 203.0.113.7 --duration 4h
cslite decisions delete 203.0.113.7
cslite decisions test 203.0.113.7          # exit 0 present / 1 absent
cslite bouncers list | add <name>
cslite reconcile [--dry-run]               # ipset <-> store, two-way (root)
cslite ipset add|del|test|flush <v>        # direct backend path
```

The daemon key is read from `--api-key`, `CSLITE_API_KEY`, `api_key`, or
`api_key_file`. If the key file is unreadable the CLI exits 4 with a clear hint
instead of a bare 403.

## Documentation

- [Architecture](docs/architecture.md)
- [Configuration](docs/configuration.md)
- [Operations / runbook](docs/operations.md)
- [Wire protocol (LAPI v1 + CAPI v3)](docs/protocol.md)
- [Testing](docs/testing.md)

## Project layout

```
src/            daemon + CLI (config, store, HTTP, CAPI, ipset, nft, detect)
deploy/         systemd unit + example/test configs
packaging/      .deb builder
scripts/        env + test gates + fixture generator
docs/           architecture, configuration, operations, protocol, testing
```

## Status & limitations

- Tested against the unmodified `crowdsec-firewall-bouncer` v0.0.36 and a live
  CAPI v3 account; T1/T2/T3/T4/T11/T12 pass, plus a two-way reconcile ending at
  0 stale / 0 missing.
- Local detection adds a third thread (server + CAPI + detect). Merging it into
  the CAPI poller is future work if two threads are required.
- The 24 h soak harness is provided but not yet run for a full day.
- nftables interval sets reject overlaps; contained CIDRs are dropped (still
  covered by their container). `auto-merge` cannot be combined with timeouts.
- Binary size (~1.5 MB static with rustls) is larger than a hand-written C
  target; TLS is the floor.

## License

MIT — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
