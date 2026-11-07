# Architecture

`cslite` is a single static Rust binary (`cslited`) plus a CLI (`cslite`). It has
two deployment modes that share the same CAPI client and enforcement backends.

## Components

| module | role |
|---|---|
| `config` | strict YAML-subset parser + typed `Config` |
| `store` | 40-byte `Decision`, open-addressing index, delta log, persistence, expiry pruning |
| `json` | stream parsing (LAPI v1 + CAPI v3 grouped), serialization, Go duration format |
| `server` | HTTP/1.1 LAPI + admin API, chunked responses |
| `capi` | CAPI v3 client over rustls (login, startup, deltas, full refresh, backoff) |
| `ipset` | ipset backend (`hash:net`, per-entry timeout, origin→index map, batched `restore`) |
| `nft` | nftables backend (interval sets, base chains, containment filter) |
| `direct` | Mode A loop: CAPI → firewall, no store/server |
| `detect` | `auth.log` tailer + sliding-window bans |
| `client` | CLI HTTP client |
| `sysd` / `log` | dependency-free `sd_notify`, rate-limited stderr logging |

## Mode B — wire-compatible LAPI

```
[CAPI api.crowdsec.net] --TLS(rustls)--> cslite (capi thread) --> store
                                                                    |
[bouncer] --HTTP/1.1 :8080, X-Api-Key, chunked--> cslite (server) --+
                                                                    |
                                                        ipset / nftables (bouncer)
```

- The daemon serves decisions; the **existing Go bouncer** enforces them.
- Auth: one configured key plus optional keys created via `POST /v1/bouncers`.
- The store is shared with the CAPI poller via `Arc<Mutex<Store>>`.
- Threads: server + CAPI poller (+ detection when enabled) = 2–3.

## Mode A — direct

```
[CAPI] --TLS--> cslite --batched ipset restore / nft -f--> kernel
```

- No HTTP listener, no decision store: each poll's payload is parsed and applied,
  then dropped. Memory is O(1) in blocklist size.
- Startup snapshot and every delta use one batched `ipset restore -!` (or one
  `nft -f -`); sets are created first.
- The kernel owns entry expiry via per-entry timeouts.

## Decision store (Mode B)

```rust
#[repr(C)] struct Decision {        // exactly 40 bytes
    addr: [u8;16], id: u32, expires_at: u32,
    origin_id: u16, scenario_id: u16,
    prefixlen: u8, family: u8, scope: u8, kind: u8, _pad: [u8;8],
}
```

- Open-addressing index (`i32` slots, index+1, 0 = empty), ~2× load factor.
- Strings (origins/scenarios) interned into small tables.
- Mutations append to a revisioned event log so `startup=false` can return both
  adds and deletes; indices stay stable (a `present` flag marks removals).
- Expired decisions are **pruned** at startup and on every poll; pruning emits
  deletes so bouncers converge.
- Persistence is a compact binary file (`CSL1`, 40 bytes + flag per decision)
  so a restart has no protection gap.

## CAPI client (v3)

- `POST /v3/watchers/login` with `machine_id`/`password` (from
  `online_api_credentials.yaml`), then
  `GET /v3/decisions/stream?startup=true|false&scopes=Ip,Range` with a Bearer
  token.
- v3 returns **grouped** decisions (`scope`/`scenario`/`decisions[]`), not the
  flat v1 shape; the parser handles both `new` and `deleted` groups.
- Deltas poll every `update_frequency` (10 s, like the Go engine).
  `capi.update_frequency` (2 h) triggers a **full refresh** (`startup=true`) so
  deletions missed in deltas are reconciled.
- Backoff 1 s→60 s with jitter; re-login on 401/403.
- Certificates verified against the system CA bundle; servers that close without
  TLS `close_notify` are treated as EOF.

## Enforcement

- **ipset**: `<prefix>-<N>` / `<prefix6>-<N>`, `N` is the per-origin first-seen
  index persisted in the state dir. `hash:net`, revision 7, per-entry timeout.
- **nftables**: one `inet <table>`, one set per origin/family, base chains for
  `input` and `forward`. Interval sets reject overlaps, so CIDRs contained in
  another are dropped (still fully covered); foreign tables are never touched.

## Local detection

Tails `auth.log` incrementally (inode + offset, rotation/truncation aware),
counts `Failed password` / `Invalid user` per source in a bounded sliding window,
and bans at the threshold (origin `crowdsec`, scenario `ssh:bruteforce`). Bans
go into the store (Mode B) or straight to the firewall (Mode A); they are
rate-limited by `limits.max_bans_per_second`.
