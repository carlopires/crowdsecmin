//! cslited — the cslite daemon.
//!
//! P0: config/logging/systemd. P2: Mode-B LAPI server. P5 (direct mode) not yet.
//! `--seed FILE` preloads a decisions/stream payload (used by the T1/T2 tests
//! and as a stop-gap until the P4 CAPI client lands).
#![forbid(unsafe_code)]
use cslite::config::{self, Mode};
use cslite::server::{self, Ctx};
use cslite::store::{now_secs, Store};
use cslite::{json, log, loge, logi, logw, sysd, VERSION};
use std::process::exit;
use std::time::Duration;

const DEFAULT_CONFIG: &str = "/etc/cslite/cslite.yaml";

fn die(msg: impl AsRef<str>, code: i32) -> ! {
    eprintln!("cslited: {}", msg.as_ref());
    exit(code)
}

fn main() {
    let mut config_path = DEFAULT_CONFIG.to_string();
    let mut seed: Option<String> = None;
    let mut api_override: Option<String> = None;

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-c" | "--config" => match args.next() {
                Some(p) => config_path = p,
                None => die("--config requires a path", 2),
            },
            "--seed" => match args.next() {
                Some(p) => seed = Some(p),
                None => die("--seed requires a path", 2),
            },
            "--api-key" => match args.next() {
                Some(k) => api_override = Some(k),
                None => die("--api-key requires a value", 2),
            },
            "-h" | "--help" => {
                print_help();
                return;
            }
            "-V" | "--version" => {
                println!("cslited {VERSION}");
                return;
            }
            other => die(format!("unknown argument {other:?}"), 2),
        }
    }

    let cfg = match config::load(&config_path) {
        Ok(c) => c,
        Err(e) => die(format!("config error: {e}"), 3),
    };
    log::set_max(cfg.log_level);
    logi!(
        "cslited {} starting (mode={:?}, listen={})",
        VERSION,
        cfg.mode,
        cfg.listen
    );

    let api_key = api_override
        .or_else(|| cfg.api_key.clone())
        .or_else(|| {
            cfg.api_key_file
                .as_ref()
                .and_then(|p| std::fs::read_to_string(p).ok())
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_default();

    match cfg.mode {
        Mode::Direct => {
            if !cfg.capi.enabled {
                loge!("direct mode requires capi.enabled=true; idling");
                idle();
            }
            let state_dir = std::path::Path::new(&cfg.persistence.path)
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| std::path::PathBuf::from("/var/lib/cslite"));
            logi!(
                "direct mode: CAPI -> {} (state_dir={}, prefixes {} / {})",
                cfg.backend.mode,
                state_dir.display(),
                cfg.backend.blacklists_ipv4,
                cfg.backend.blacklists_ipv6
            );
            if cfg.local_detection.enabled {
                let backend_detect = cfg.backend.clone();
                let sd_detect = state_dir.clone();
                let lc = cfg.local_detection.clone();
                let max_bps = cfg.limits.max_bans_per_second as u32;
                let dur = lc.ban_duration_secs as u32;
                std::thread::spawn(move || {
                    let dcfg = cslite::detect::DetectConfig {
                        log_path: lc.log_path.clone(),
                        threshold: lc.ban_threshold as u32,
                        window_secs: lc.window_secs,
                        ban_duration_secs: dur,
                        max_bans_per_sec: max_bps,
                    };
                    cslite::detect::run(dcfg, move |ip| {
                        cslite::direct::ban_once(
                            &backend_detect,
                            &sd_detect,
                            &ip.to_string(),
                            dur as u64,
                        );
                    });
                });
                logi!("local detection enabled on {}", cfg.local_detection.log_path);
            }
            cslite::direct::run(
                &cfg.backend,
                &cfg.capi.credentials_path,
                cfg.update_frequency_secs,
                cfg.capi.update_frequency_secs,
                &state_dir,
                notify_ready,
            );
        }
        Mode::Lapi => {
            if api_key.is_empty() {
                die("mode=lapi but no api_key/api_key_file configured", 3);
            }
            let mut store = Store::new();
            let persist = if cfg.persistence.enabled {
                Some(std::path::PathBuf::from(&cfg.persistence.path))
            } else {
                None
            };
            if let Some(p) = &persist {
                if p.exists() {
                    match Store::load_from(p) {
                        Ok(s) => {
                            logi!("loaded {} decisions from {}", s.len(), p.display());
                            store = s;
                        }
                        Err(e) => logw!("persist load failed ({e}); starting empty"),
                    }
                }
            }
            if let Some(path) = seed.as_deref() {
                match std::fs::read(path) {
                    Ok(bytes) => {
                        let n = json::load_into(&mut store, &bytes, now_secs());
                        logi!("seeded {n} decisions from {path}");
                        if let Some(p) = &persist {
                            if let Err(e) = store.save_to(p) {
                                logw!("persist failed: {e}");
                            }
                        }
                    }
                    Err(e) => die(format!("cannot read seed {path}: {e}"), 1),
                }
            }
            let pruned = store.prune_expired(now_secs());
            if pruned > 0 {
                logi!("pruned {pruned} expired decisions from persistence");
            }
            logi!("serving LAPI on {} ({} decisions)", cfg.listen, store.len());
            let ctx = Ctx::new(api_key, store, persist);
            if cfg.capi.enabled {
                let handle = ctx.store_handle();
                let creds = cfg.capi.credentials_path.clone();
                let interval = cfg.update_frequency_secs;
                let full = cfg.capi.update_frequency_secs;
                let persist_capi = ctx.persist.clone();
                let creds_thread = creds.clone();
                std::thread::spawn(move || {
                    cslite::capi::run(handle, &creds_thread, interval, full, persist_capi)
                });
                logi!("capi poller started (credentials={creds}, delta={interval}s, full_refresh={full}s)");
            } else {
                logi!("capi disabled");
            }
            if cfg.local_detection.enabled {
                let handle = ctx.store_handle();
                let persist_detect = ctx.persist.clone();
                let lc = cfg.local_detection.clone();
                let max_bps = cfg.limits.max_bans_per_second as u32;
                let dur = lc.ban_duration_secs as u32;
                std::thread::spawn(move || {
                    let dcfg = cslite::detect::DetectConfig {
                        log_path: lc.log_path.clone(),
                        threshold: lc.ban_threshold as u32,
                        window_secs: lc.window_secs,
                        ban_duration_secs: dur,
                        max_bans_per_sec: max_bps,
                    };
                    cslite::detect::run(dcfg, move |ip| {
                        let now = cslite::store::now_secs();
                        let mut st = handle.lock().unwrap_or_else(|p| p.into_inner());
                        if let Some(d) = cslite::json::build_decision_for(
                            &mut st,
                            "crowdsec",
                            "ssh:bruteforce",
                            &ip.to_string(),
                            dur,
                            now,
                        ) {
                            if st.insert(d) {
                                if let Some(p) = &persist_detect {
                                    let _ = st.save_to(p);
                                }
                                logi!("detect: banned {ip}");
                            }
                        }
                    });
                });
                logi!("local detection enabled on {}", cfg.local_detection.log_path);
            }
            if let Err(e) = server::run(&cfg.listen, ctx, notify_ready) {
                loge!("server error: {e}");
                exit(1);
            }
        }
    }
}

fn notify_ready() {
    match sysd::notify("READY=1") {
        Ok(true) => logi!("notified systemd READY=1"),
        Ok(false) => logi!("NOTIFY_SOCKET not set (not running under systemd)"),
        Err(e) => logw!("sd_notify failed: {e}"),
    }
}

fn idle() -> ! {
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

fn print_help() {
    println!(
        "cslited {VERSION} — cslite daemon\n\n\
         USAGE:\n    cslited [-c|--config PATH] [--seed FILE] [--api-key KEY]\n\n\
         OPTIONS:\n    \
         -c, --config PATH   config file (default {DEFAULT_CONFIG})\n    \
         --seed FILE         preload decisions/stream JSON (test/bootstrap)\n    \
         --api-key KEY       override the config api_key\n    \
         -h, --help          show help\n    -V, --version       show version"
    );
}
