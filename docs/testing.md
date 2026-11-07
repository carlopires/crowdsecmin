# Testing

## Unit tests

```bash
cargo test --lib
```

16 tests cover: config parsing/validation, Go duration parse/format, IPv4/IPv6
and CIDR handling, LAPI v1 parsing, **CAPI v3 grouped parsing**, store
insert/dedup/remove/deltas, persistence round-trip, origin-map stability,
`auth.log` line parsing, threshold-once behavior, and the incremental tailer.

## Integration gates

All scripts live in `scripts/` and are run from the repo root:

```bash
. scripts/env.sh
./scripts/p0_check.sh
./scripts/p3_admin.sh
./scripts/t3_ipset.sh
./scripts/t1_bouncer.sh
./scripts/p4_capi.sh
./scripts/p5_direct.sh
./scripts/p6_detect.sh
./scripts/p7_nft.sh
SOAK_SECONDS=60 ./scripts/soak.sh
```

| gate | asserts |
|---|---|
| `p0_check.sh` | unit tests, static musl build, binaries ≤ 3 MiB, no dynamic `NEEDED`, example config accepted, unknown key rejected |
| `p3_admin.sh` | admin API + CLI: add/list/test/delete, delta carries changes, persistence across restart, bouncer key authorizes |
| `t3_ipset.sh` | ipset add, kernel-side expiry (no daemon action), IPv6 set, bad prefix rejected — in a private netns |
| `t1_bouncer.sh` | **unmodified** `crowdsec-firewall-bouncer` v0.0.36 against `cslited`: exact decision count applied, RSS ≤ 3 MB, no non-benign errors |
| `p4_capi.sh` | CAPI v3 login + startup snapshot + delta against a local v3 mock |
| `p5_direct.sh` | Mode A: startup + delta add/delete enforced with no HTTP server |
| `p6_detect.sh` | `auth.log` threshold bans, below-threshold source ignored |
| `p7_nft.sh` | nftables backend add/delete and foreign-table safety |
| `soak.sh` | decision churn; `RssAnon` drift < 512 kB |

`t3_ipset.sh`, `p5_direct.sh`, and `p7_nft.sh` run inside
`sudo unshare --net` so they never touch the host's real sets.

## Reference results

Measured on Ubuntu 24.04, 2 vCPU / 953 MB, ~15k decisions:

- T1: unmodified bouncer applies **15,344** decisions; Mode B RSS **~2.2 MB**,
  1 thread with CAPI off / 2 with CAPI on.
- T2: startup snapshot served in ~2.1 MB / 15k decisions; server RSS ~1.6 MB.
- T3/T4: CLI add enforced (`ipset test`), entry gone by the kernel after its
  timeout without daemon action.
- T11/T12: rustls active with CAPI polling; static binaries, no `libcurl`/`libssl`.
- Two-way `cslite reconcile`: **0 stale / 0 missing**, ipset == store.
- Mode A: **~1.0 MB**, add and delete applied.
- Detection: 3 failures in 60 s ban the source as `crowdsec/ssh:bruteforce`.

## Long soak

```bash
SOAK_SECONDS=86400 SOAK_INTERVAL=3600 ./scripts/soak.sh
```

The 24 h run has not been completed yet; the short run passes with ~20 kB drift
against a 512 kB threshold.

## Adding tests

- Pure logic → `#[cfg(test)]` in the module.
- Anything touching ipset/nftables → add a script under `scripts/` that runs in
  `sudo unshare --net` and exits non-zero on failure.
