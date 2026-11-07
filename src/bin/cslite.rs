//! cslite — CLI.
//!
//! P3: `decisions`/`bouncers`/`status` talk to the daemon over HTTP.
//! `ipset` keeps the direct-path harness (used by the T3/T4 netns test).
#![forbid(unsafe_code)]
use cslite::client::Client;
use cslite::config::{self, parse_duration_secs, Config};
use cslite::ipset::{self, Backend, Family, OriginMap};
use cslite::json;
use cslite::{COMPAT_BOUNCER, COMPAT_CROWDSEC, VERSION};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::exit;

const DEFAULT_CONFIG: &str = "/etc/cslite/cslite.yaml";

/// Print a line, ignoring EPIPE (e.g. `cslite ... | head`). `outln!` panics
/// on a closed stdout, which is a poor CLI experience.
macro_rules! outln {
    ($($t:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stdout(), $($t)*);
    }};
}

fn die(msg: impl AsRef<str>, code: i32) -> ! {
    eprintln!("cslite: {}", msg.as_ref());
    exit(code)
}

fn take(it: &mut impl Iterator<Item = String>, opt: &str) -> String {
    match it.next() {
        Some(v) => v,
        None => die(format!("{opt} requires a value"), 2),
    }
}

fn state_dir(cfg: &Config, override_dir: Option<String>) -> PathBuf {
    if let Some(d) = override_dir {
        return PathBuf::from(d);
    }
    if let Some(parent) = Path::new(&cfg.persistence.path).parent() {
        if !parent.as_os_str().is_empty() {
            return parent.to_path_buf();
        }
    }
    PathBuf::from("/var/lib/cslite")
}

fn load_cfg(path: &str) -> Config {
    match config::load(path) {
        Ok(c) => c,
        Err(e) => die(format!("config error: {e}"), 3),
    }
}

/// Resolve the daemon API key from (in order): --api-key, CSLITE_API_KEY,
/// api_key, api_key_file. Returns an actionable error instead of sending an
/// empty key (which would yield a bare HTTP 403).
fn resolve_key(cfg: &Config, override_key: Option<&str>) -> Result<String, String> {
    if let Some(k) = override_key {
        if !k.trim().is_empty() {
            return Ok(k.trim().to_string());
        }
    }
    if let Ok(k) = std::env::var("CSLITE_API_KEY") {
        if !k.trim().is_empty() {
            return Ok(k.trim().to_string());
        }
    }
    if let Some(k) = &cfg.api_key {
        if !k.trim().is_empty() {
            return Ok(k.trim().to_string());
        }
    }
    if let Some(p) = &cfg.api_key_file {
        return match std::fs::read_to_string(p) {
            Ok(s) if !s.trim().is_empty() => Ok(s.trim().to_string()),
            Ok(_) => Err(format!("api_key_file {p} is empty")),
            Err(e) => Err(format!(
                "cannot read api_key_file {p}: {e}\n  hint: run with sudo, or pass --api-key / set CSLITE_API_KEY"
            )),
        };
    }
    Err("no API key configured (api_key or api_key_file) and CSLITE_API_KEY is unset".to_string())
}

fn client_or_die(cfg: &Config, key: Option<&str>) -> Client {
    match resolve_key(cfg, key) {
        Ok(k) => Client::new(&cfg.listen, &k),
        Err(e) => die(e, 4),
    }
}

/// For unauthenticated endpoints (`/health`): tolerate a missing key.
fn client_optional(cfg: &Config, key: Option<&str>) -> Client {
    let k = resolve_key(cfg, key).unwrap_or_default();
    Client::new(&cfg.listen, &k)
}

fn main() {
    let mut config_path = DEFAULT_CONFIG.to_string();
    let mut command: Option<String> = None;
    let mut pos: Vec<String> = Vec::new();
    let mut duration = "4h".to_string();
    let mut origin = "CAPI".to_string();
    let mut scenario = "cslite/manual".to_string();
    let mut state_override: Option<String> = None;
    let mut api_override: Option<String> = None;
    let mut as_json = false;
    let mut dry_run = false;

    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "-c" | "--config" => config_path = take(&mut it, "--config"),
            "--duration" => duration = take(&mut it, "--duration"),
            "--origin" => origin = take(&mut it, "--origin"),
            "--scenario" => scenario = take(&mut it, "--scenario"),
            "--state-dir" => state_override = Some(take(&mut it, "--state-dir")),
            "--api-key" => api_override = Some(take(&mut it, "--api-key")),
            "--json" => as_json = true,
            "--dry-run" => dry_run = true,
            "-h" | "--help" => {
                print_help();
                return;
            }
            "-V" | "--version" => {
                outln!("cslite {VERSION}");
                return;
            }
            s if s.starts_with('-') => die(format!("unknown option {s:?}"), 2),
            s => {
                if command.is_none() {
                    command = Some(s.to_string());
                } else {
                    pos.push(s.to_string());
                }
            }
        }
    }

    if command.is_none() {
        print_help();
        exit(2);
    }
    if let Some("version") = command.as_deref() {
        outln!("cslite {VERSION}");
        outln!("compat crowdsec: {COMPAT_CROWDSEC}");
        outln!("compat bouncer: {COMPAT_BOUNCER}");
        return;
    }
    if let Some("tls-check") = command.as_deref() {
        let url = pos
            .first()
            .map(String::as_str)
            .unwrap_or_else(|| die("tls-check requires <url>", 2));
        match cslite::capi::probe(url) {
            Ok(s) => {
                outln!("{url} -> HTTP {s}");
                if s == 0 {
                    exit(1);
                }
            }
            Err(e) => die(e, 4),
        }
        return;
    }
    let cfg = load_cfg(&config_path);
    match command.as_deref() {
        None => {
            print_help();
            exit(2);
        }
        Some("version") => {
            outln!("cslite {VERSION}");
            outln!("compat crowdsec: {COMPAT_CROWDSEC}");
            outln!("compat bouncer: {COMPAT_BOUNCER}");
        }
        Some("check-config") => {
            outln!("ok: {config_path} (mode={:?}, listen={})", cfg.mode, cfg.listen)
        }
        Some("status") => {
            let c = client_optional(&cfg, api_override.as_deref());
            match c.health() {
                Ok(b) => outln!("up: {b}"),
                Err(e) => die(e, 4),
            }
        }
        Some("tls-check") => {
            let url = pos
                .first()
                .map(String::as_str)
                .unwrap_or_else(|| die("tls-check requires <url>", 2));
            match cslite::capi::probe(url) {
                Ok(s) => {
                    outln!("{url} -> HTTP {s}");
                    if s == 0 {
                        exit(1);
                    }
                }
                Err(e) => die(e, 4),
            }
        }
        Some("decisions") => run_decisions(
            &cfg,
            &pos,
            &origin,
            &scenario,
            &duration,
            api_override.as_deref(),
            as_json,
        ),
        Some("bouncers") => run_bouncers(&cfg, &pos, api_override.as_deref()),
        Some("ipset") => run_ipset(&cfg, &pos, &origin, &duration, state_override),
        Some("reconcile") => run_reconcile(&cfg, api_override.as_deref(), state_override, dry_run),
        Some("flush") => run_flush(&cfg, &origin, state_override),
        Some(other) => die(format!("unknown command {other:?}"), 2),
    }
}

fn run_decisions(
    cfg: &Config,
    pos: &[String],
    origin: &str,
    scenario: &str,
    duration: &str,
    api_override: Option<&str>,
    as_json: bool,
) {
    let sub = match pos.first().map(String::as_str) {
        Some(s) => s,
        None => die("decisions requires a subcommand: list|add|delete|test", 2),
    };
    let c = client_or_die(cfg, api_override);
    match sub {
        "list" => match c.list() {
            Ok(body) => {
                if as_json {
                    outln!("{body}");
                } else {
                    let raws = json::parse_stream(body.as_bytes());
                    outln!("{:<10} {:<6} {:<6} {:<10} {}", "ORIGIN", "SCOPE", "TYPE", "DURATION", "VALUE");
                    for r in raws {
                        outln!(
                            "{:<10} {:<6} {:<6} {:<10} {}",
                            r.origin, r.scope_str(), r.typ, r.duration, r.value
                        );
                    }
                }
            }
            Err(e) => die(e, 4),
        },
        "add" => {
            let value = pos.get(1).unwrap_or_else(|| die("decisions add requires <ip|cidr>", 2));
            let secs = match parse_duration_secs(duration) {
                Ok(s) if s > 0 => s,
                Ok(_) => die("--duration must be > 0", 2),
                Err(e) => die(e, 2),
            };
            match c.add(value, secs, origin, scenario) {
                Ok(b) => outln!("{b}"),
                Err(e) => die(e, 4),
            }
        }
        "delete" => {
            let value = pos
                .get(1)
                .unwrap_or_else(|| die("decisions delete requires <ip|cidr>", 2));
            match c.delete(value) {
                Ok(b) => outln!("{b}"),
                Err(e) => die(e, 4),
            }
        }
        "test" => {
            let value = pos
                .get(1)
                .unwrap_or_else(|| die("decisions test requires <ip|cidr>", 2));
            let target = json::parse_value(value)
                .unwrap_or_else(|| die(format!("invalid value {value:?}"), 2));
            let body = match c.list() {
                Ok(b) => b,
                Err(e) => die(e, 4),
            };
            let present = json::parse_stream(body.as_bytes())
                .iter()
                .any(|r| json::parse_value(&r.value) == Some(target));
            if present {
                outln!("present: {value}");
            } else {
                outln!("absent: {value}");
                exit(1);
            }
        }
        other => die(format!("unknown decisions subcommand {other:?}"), 2),
    }
}

fn run_bouncers(cfg: &Config, pos: &[String], api_override: Option<&str>) {
    let c = client_or_die(cfg, api_override);
    match pos.first().map(String::as_str) {
        Some("list") => match c.bouncers() {
            Ok(b) => outln!("{b}"),
            Err(e) => die(e, 4),
        },
        Some("add") => {
            let name = pos.get(1).unwrap_or_else(|| die("bouncers add requires <name>", 2));
            match c.add_bouncer(name) {
                Ok(b) => outln!("{b}"),
                Err(e) => die(e, 4),
            }
        }
        _ => die("bouncers requires list|add", 2),
    }
}

fn run_reconcile(
    cfg: &Config,
    api_override: Option<&str>,
    state_override: Option<String>,
    dry_run: bool,
) {
    let client = client_or_die(cfg, api_override);
    let body = match client.list() {
        Ok(b) => b,
        Err(e) => die(e, 4),
    };
    let raws = json::parse_stream(body.as_bytes());
    let (backend, origins) = open_backend(cfg, state_override);

    // Expected values per (family, set), with remaining timeout (seconds).
    let mut expected: HashMap<(Family, String), HashMap<String, u32>> = HashMap::new();
    for (_o, idx) in origins.entries() {
        for fam in [Family::V4, Family::V6] {
            let name = backend.set_name(fam, idx);
            expected.entry((fam, name)).or_default();
        }
    }
    for r in raws {
        let (_addr, _plen, fam4) = match json::parse_value(&r.value) {
            Some(v) => v,
            None => continue,
        };
        let family = if fam4 == 4 { Family::V4 } else { Family::V6 };
        let idx = match origins.get(&r.origin) {
            Some(i) => i,
            None => continue,
        };
        let name = backend.set_name(family, idx);
        expected
            .entry((family, name))
            .or_default()
            .entry(r.value)
            .or_insert(r.duration.max(1));
    }

    let mut stale_total = 0usize;
    let mut missing_total = 0usize;
    let mut added_total = 0usize;
    for ((family, name), exp) in &expected {
        if exp.is_empty() && !backend.exists(name) {
            continue;
        }
        if !backend.exists(name) {
            if let Err(e) = backend.ensure(*family, name) {
                eprintln!("ensure {name}: {e}");
                continue;
            }
        }
        let members = match backend.members(name) {
            Ok(m) => m,
            Err(e) => die(e.to_string(), 1),
        };
        let member_set: HashSet<String> = members.iter().cloned().collect();

        // Delete entries the store no longer has (over-block from old engine).
        let mut stale: Vec<&String> = members.iter().filter(|m| !exp.contains_key(*m)).collect();
        stale.sort();
        for v in &stale {
            if dry_run {
                outln!("would delete {name} {v}");
            } else if let Err(e) = backend.del(*family, name, v.as_str()) {
                eprintln!("delete {name} {v}: {e}");
            }
        }

        // Add entries the store has but ipset lacks (under-block), with the
        // decision's remaining timeout.
        let missing: Vec<(&String, &u32)> =
            exp.iter().filter(|(v, _)| !member_set.contains(*v)).collect();
        for (v, timeout) in &missing {
            if dry_run {
                outln!("would add {name} {v} timeout {timeout}");
            } else if let Err(e) = backend.add(*family, name, v.as_str(), **timeout as u64) {
                eprintln!("add {name} {v}: {e}");
            } else {
                added_total += 1;
            }
        }

        stale_total += stale.len();
        missing_total += missing.len();
        outln!(
            "{name}: {} members, {} stale{}, {} missing{}",
            members.len(),
            stale.len(),
            if dry_run { " (dry-run)" } else { "" },
            missing.len(),
            if dry_run { " (would be added)" } else { " (added)" }
        );
    }
    outln!(
        "reconcile: {stale_total} stale{}, {missing_total} missing, {added_total} added",
        if dry_run { " (dry-run)" } else { "" }
    );
}

fn open_backend(cfg: &Config, state_override: Option<String>) -> (Backend, OriginMap) {
    let backend = Backend::from_config(&cfg.backend);
    let sd = state_dir(cfg, state_override);
    let origins = match OriginMap::load(&sd) {
        Ok(o) => o,
        Err(e) => die(format!("origin map: {e}"), 1),
    };
    (backend, origins)
}

fn run_ipset(
    cfg: &Config,
    pos: &[String],
    origin: &str,
    duration: &str,
    state_override: Option<String>,
) {
    let sub = match pos.first().map(String::as_str) {
        Some(s) => s,
        None => die("ipset requires add|del|test|flush", 2),
    };
    let value = match pos.get(1) {
        Some(v) => v,
        None => die(format!("ipset {sub} requires <ip|cidr>"), 2),
    };
    let (family, norm) = match ipset::parse_value(value) {
        Ok(v) => v,
        Err(e) => die(e.to_string(), 2),
    };
    let (backend, mut origins) = open_backend(cfg, state_override);
    match sub {
        "add" => {
            let secs = match parse_duration_secs(duration) {
                Ok(s) if s > 0 => s,
                Ok(_) => die("--duration must be > 0", 2),
                Err(e) => die(e, 2),
            };
            let idx = match origins.index(origin) {
                Ok(i) => i,
                Err(e) => die(format!("origin map: {e}"), 1),
            };
            let name = backend.set_name(family, idx);
            if let Err(e) = backend.add(family, &name, &norm, secs) {
                die(e.to_string(), 1);
            }
            outln!("added {norm} -> {name} (origin={origin}, timeout={secs}s)");
        }
        "del" | "delete" => {
            let idx = match origins.get(origin) {
                Some(i) => i,
                None => {
                    outln!("no set for origin {origin}; nothing to delete");
                    return;
                }
            };
            let name = backend.set_name(family, idx);
            if let Err(e) = backend.del(family, &name, &norm) {
                die(e.to_string(), 1);
            }
            outln!("deleted {norm} from {name}");
        }
        "test" => {
            let idx = match origins.get(origin) {
                Some(i) => i,
                None => {
                    outln!("absent ({norm}): no set for origin {origin}");
                    exit(1);
                }
            };
            let name = backend.set_name(family, idx);
            match backend.test(&name, &norm) {
                Ok(true) => outln!("present: {norm} in {name}"),
                Ok(false) => {
                    outln!("absent: {norm} not in {name}");
                    exit(1);
                }
                Err(e) => die(e.to_string(), 1),
            }
        }
        other => die(format!("unknown ipset subcommand {other:?}"), 2),
    }
}

fn run_flush(cfg: &Config, origin: &str, state_override: Option<String>) {
    let (backend, origins) = open_backend(cfg, state_override);
    let idx = match origins.get(origin) {
        Some(i) => i,
        None => {
            outln!("no sets for origin {origin}; nothing to flush");
            return;
        }
    };
    for fam in [Family::V4, Family::V6] {
        let name = backend.set_name(fam, idx);
        if let Err(e) = backend.flush(&name) {
            die(e.to_string(), 1);
        }
        outln!("flushed {name}");
    }
}

fn print_help() {
    outln!(
        "cslite {VERSION} — CLI\n\n\
         USAGE:\n    cslite [-c|--config PATH] <command> [options]\n\n\
         COMMANDS:\n    \
         version                          version + compat strings\n    \
         check-config                     validate config\n    \
         status                           daemon health (via HTTP)\n    \
         tls-check <url>                  TLS handshake test (rustls)\n    \
         decisions list                   list decisions (via daemon)\n    \
         decisions add <ip|cidr>          add a decision (via daemon)\n    \
         decisions delete <ip|cidr>       delete a decision (via daemon)\n    \
         decisions test <ip|cidr>         exit 0 if present, 1 if absent\n    \
         bouncers list | add <name>       bouncer keys (via daemon)\n    \
         ipset add|del|test|flush <v>     direct ipset path (no daemon)\n    \
         reconcile [--dry-run]            delete ipset entries absent from the store\n    \
         flush                            flush this origin's sets directly\n\n\
         OPTIONS:\n    \
         -c, --config PATH   config (default {DEFAULT_CONFIG})\n    \
         --origin NAME       origin/set index (default CAPI)\n    \
         --scenario NAME     scenario for add (default cslite/manual)\n    \
         --duration DUR      duration for add (default 4h)\n    \
         --state-dir DIR     origin->index dir for direct ipset\n    \
         --api-key KEY       override daemon api key (or set CSLITE_API_KEY)\n    \
         --json              raw JSON output for list\n    \
         --dry-run           with reconcile: show deletions only"
    );
}
