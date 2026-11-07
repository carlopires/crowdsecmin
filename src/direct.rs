//! Direct mode (P5 / spec Mode A): CAPI -> firewall, no store, no HTTP server.
//!
//! The enforcement backend is selected by `backend.mode`:
//!   iptables  -> ipset (batched `ipset restore -!`)
//!   nftables  -> nft   (one batched `nft -f -` for adds)
use crate::capi::{CapiClient, Credentials};
use crate::config;
use crate::ipset::{Backend, Family, OriginMap};
use crate::json;
use crate::nft::Nft;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

enum Enforce {
    Ip(Backend),
    Nft(Nft),
}

impl Enforce {
    fn from_config(b: &config::Backend) -> Self {
        if b.mode == "nftables" {
            Enforce::Nft(Nft::from_config(b))
        } else {
            Enforce::Ip(Backend::from_config(b))
        }
    }

    fn set_name(&self, family: Family, idx: u8) -> String {
        match self {
            Enforce::Ip(b) => b.set_name(family, idx),
            Enforce::Nft(n) => n.set_name(family, idx),
        }
    }

    /// One-time backend init (creates table/chains for nftables).
    fn base(&self) -> Result<(), String> {
        match self {
            Enforce::Ip(_) => Ok(()),
            Enforce::Nft(n) => n.ensure_base(),
        }
    }

    fn ensure(&self, family: Family, name: &str) -> Result<(), String> {
        match self {
            Enforce::Ip(b) => b.ensure(family, name).map_err(|e| e.to_string()),
            Enforce::Nft(n) => n.ensure_set(family, name),
        }
    }

    fn adds(&self, adds: &[(String, String, u32)]) -> Result<(), String> {
        match self {
            Enforce::Ip(b) => {
                let mut script = String::new();
                for (set, value, timeout) in adds {
                    script.push_str(&format!("add {} {} timeout {}\n", set, value, timeout));
                }
                if script.is_empty() {
                    Ok(())
                } else {
                    b.restore(&script).map_err(|e| e.to_string())
                }
            }
            Enforce::Nft(n) => n.apply_adds(adds),
        }
    }

    fn del(&self, family: Family, set: &str, value: &str) -> Result<(), String> {
        match self {
            Enforce::Ip(b) => b.del(family, set, value).map_err(|e| e.to_string()),
            Enforce::Nft(n) => n.apply_del(set, value),
        }
    }

    /// List a set's members.
    fn members(&self, _family: Family, set: &str) -> Result<Vec<String>, String> {
        match self {
            Enforce::Ip(b) => b.members(set).map_err(|e| e.to_string()),
            Enforce::Nft(n) => n.members(set),
        }
    }
}

pub fn run<F: FnOnce()>(
    backend_cfg: &config::Backend,
    creds_path: &str,
    poll_interval_secs: u64,
    state_dir: &Path,
    on_ready: F,
) {
    let enforcer = Enforce::from_config(backend_cfg);
    if let Err(e) = enforcer.base() {
        crate::loge!("direct: backend init failed: {e}");
        return;
    }
    let mut origins = match OriginMap::load(state_dir) {
        Ok(o) => o,
        Err(e) => {
            crate::loge!("direct: origin map: {e}");
            return;
        }
    };
    let creds = match Credentials::load(creds_path) {
        Ok(c) => c,
        Err(e) => {
            crate::loge!("direct: {e}");
            return;
        }
    };
    let mut client = match CapiClient::new(creds) {
        Ok(c) => c,
        Err(e) => {
            crate::loge!("direct: {e}");
            return;
        }
    };

    let mut ready = Some(on_ready);
    let mut backoff = 1u64;
    loop {
        // Re-read the origin map so a concurrent detection thread's assignments
        // are visible to the poller (and vice versa).
        if let Ok(o) = OriginMap::load(state_dir) {
            origins = o;
        }
        match client.fetch(true) {
            Ok(body) => match apply(&enforcer, &mut origins, &body) {
                Ok((applied, pruned)) => {
                    if let Some(cb) = ready.take() {
                        cb();
                    }
                    crate::logi!("direct: snapshot applied {applied}, pruned {pruned}");
                    backoff = 1;
                    std::thread::sleep(Duration::from_secs(poll_interval_secs.max(1)));
                }
                Err(e) => {
                    crate::logw!("direct: apply failed: {e}; retry in {backoff}s");
                    std::thread::sleep(Duration::from_secs(backoff));
                    backoff = (backoff * 2).min(60);
                }
            },
            Err(e) => {
                crate::logw!("direct: fetch failed: {e}; retry in {backoff}s");
                std::thread::sleep(Duration::from_secs(backoff));
                backoff = (backoff * 2).min(60);
            }
        }
    }
}

fn family_of(fam4: u8) -> Family {
    if fam4 == 4 {
        Family::V4
    } else {
        Family::V6
    }
}

fn apply(enforcer: &Enforce, origins: &mut OriginMap, body: &[u8]) -> Result<(usize, usize), String> {
    let (newv, delv) = json::parse_capi_v3(body);
    let capi = origins.index("CAPI").map_err(|e| e.to_string())?;
    let mut seen: Vec<String> = Vec::new();

    // Seed both families so an empty snapshot clears the set.
    let mut expected: HashMap<(Family, String), HashSet<String>> = HashMap::new();
    for fam in [Family::V4, Family::V6] {
        expected
            .entry((fam, enforcer.set_name(fam, capi)))
            .or_default();
    }

    let mut adds: Vec<(String, String, u32)> = Vec::new();
    for r in newv {
        let (_addr, _plen, fam4) = match json::parse_value(&r.value) {
            Some(v) => v,
            None => continue,
        };
        let family = family_of(fam4);
        let name = enforcer.set_name(family, capi);
        ensure(enforcer, family, &name, &mut seen)?;
        expected
            .entry((family, name.clone()))
            .or_default()
            .insert(r.value.clone());
        adds.push((name, r.value, r.duration));
    }

    let mut deleted = 0usize;
    for r in delv {
        let (_addr, _plen, fam4) = match json::parse_value(&r.value) {
            Some(v) => v,
            None => continue,
        };
        let family = family_of(fam4);
        let name = enforcer.set_name(family, capi);
        enforcer.del(family, &name, &r.value)?;
        deleted += 1;
    }

    if !adds.is_empty() {
        enforcer.adds(&adds)?;
    }

    // The v3 response is a full snapshot: drop entries absent from it.
    let mut pruned = 0usize;
    for ((family, name), exp) in &expected {
        for m in enforcer.members(*family, name)? {
            if !exp.contains(&m) {
                enforcer.del(*family, name, &m)?;
                pruned += 1;
            }
        }
    }

    Ok((adds.len() + deleted, pruned))
}

fn ensure(
    enforcer: &Enforce,
    family: Family,
    name: &str,
    seen: &mut Vec<String>,
) -> Result<(), String> {
    if seen.iter().any(|s| s == name) {
        return Ok(());
    }
    enforcer.ensure(family, name)?;
    seen.push(name.to_string());
    Ok(())
}

/// Ban a single source IP (used by local detection in direct mode).
pub fn ban_once(backend_cfg: &config::Backend, state_dir: &Path, ip: &str, duration_secs: u64) {
    let enforcer = Enforce::from_config(backend_cfg);
    let mut origins = match OriginMap::load(state_dir) {
        Ok(o) => o,
        Err(e) => {
            crate::logw!("detect: origin map: {e}");
            return;
        }
    };
    let (_addr, _plen, fam4) = match json::parse_value(ip) {
        Some(v) => v,
        None => return,
    };
    let family = family_of(fam4);
    let idx = match origins.index("crowdsec") {
        Ok(i) => i,
        Err(e) => {
            crate::logw!("detect: {e}");
            return;
        }
    };
    let name = enforcer.set_name(family, idx);
    if let Err(e) = enforcer.ensure(family, &name) {
        crate::logw!("detect: ensure set failed: {e}");
        return;
    }
    let add = (name.clone(), ip.to_string(), duration_secs as u32);
    match enforcer.adds(&[add]) {
        Ok(()) => crate::logi!("detect: banned {ip} in {name}"),
        Err(e) => crate::logw!("detect: add failed: {e}"),
    }
}
