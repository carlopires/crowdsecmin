//! nftables enforcement backend (P7, `backend.mode: nftables`).
//!
//! Drives the `nft` binary. One table (default `inet crowdsec`), one set per
//! origin/family, and base chains for `input` + `forward`. Elements carry
//! per-entry timeouts, so the kernel owns expiry. Never touches tables it did
//! not create.
use crate::config;
use crate::ipset::Family;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

pub struct Nft {
    pub bin: String,
    pub table: String,
    pub chain: String,
    pub priority: i32,
    pub v4_prefix: String,
    pub v6_prefix: String,
}

impl Nft {
    pub fn from_config(b: &config::Backend) -> Self {
        Nft {
            bin: nft_bin(),
            table: b.nft_table.clone(),
            chain: b.nft_chain.clone(),
            priority: b.nft_priority,
            v4_prefix: b.blacklists_ipv4.clone(),
            v6_prefix: b.blacklists_ipv6.clone(),
        }
    }

    pub fn set_name(&self, family: Family, index: u8) -> String {
        match family {
            Family::V4 => format!("{}-{}", self.v4_prefix, index),
            Family::V6 => format!("{}-{}", self.v6_prefix, index),
        }
    }

    fn fwd_chain(&self) -> String {
        format!("{}-fwd", self.chain)
    }

    fn run(&self, args: &[&str]) -> Result<Output, String> {
        Command::new(&self.bin)
            .args(args)
            .output()
            .map_err(|e| e.to_string())
    }

    fn script(&self, body: &str) -> Result<(), String> {
        let mut child = Command::new(&self.bin)
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| e.to_string())?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(body.as_bytes()).map_err(|e| e.to_string())?;
        }
        let out = child.wait_with_output().map_err(|e| e.to_string())?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "nft: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }

    fn exists(&self, kind: &str, name: &str) -> bool {
        matches!(self.run(&["list", kind, "inet", &self.table, name]), Ok(o) if o.status.success())
    }

    /// Create the table and base chains if absent (idempotent).
    pub fn ensure_base(&self) -> Result<(), String> {
        self.script(&format!("add table inet {}\n", self.table))?;
        for (chain, hook) in [(&self.chain, "input"), (&self.fwd_chain(), "forward")] {
            if !self.exists("chain", chain) {
                self.script(&format!(
                    "add chain inet {} {} {{ type filter hook {} priority {}; policy accept; }}\n",
                    self.table, chain, hook, self.priority
                ))?;
            }
        }
        Ok(())
    }

    /// Create a per-origin set and its drop rules if absent (idempotent).
    pub fn ensure_set(&self, family: Family, name: &str) -> Result<(), String> {
        if self.exists("set", name) {
            return Ok(());
        }
        let (ty, ipver) = match family {
            Family::V4 => ("ipv4_addr", "ip"),
            Family::V6 => ("ipv6_addr", "ip6"),
        };
        let mut s = String::new();
        s.push_str(&format!(
            "add set inet {} {} {{ type {}; flags interval; timeout 300s; }}\n",
            self.table, name, ty
        ));
        s.push_str(&format!(
            "add rule inet {} {} {} saddr @{} drop\n",
            self.table, self.chain, ipver, name
        ));
        s.push_str(&format!(
            "add rule inet {} {} {} saddr @{} drop\n",
            self.table,
            self.fwd_chain(),
            ipver,
            name
        ));
        self.script(&s)
    }

    /// Add `(set, value, timeout_secs)` elements in one batch.
    ///
    /// nft interval sets reject overlaps (ipset `hash:net` allows them), so for
    /// each set we drop decisions already contained in another CIDR. CIDR ranges
    /// are always disjoint or nested, so this leaves a valid non-overlapping set
    /// that still covers every decision. Timeouts of contained entries are not
    /// merged into their container (documented limitation).
    pub fn apply_adds(&self, adds: &[(String, String, u32)]) -> Result<(), String> {
        if adds.is_empty() {
            return Ok(());
        }
        let mut groups: std::collections::BTreeMap<&str, Vec<(&str, u32)>> =
            std::collections::BTreeMap::new();
        for (set, value, timeout) in adds {
            groups
                .entry(set.as_str())
                .or_default()
                .push((value.as_str(), *timeout));
        }
        let mut s = String::new();
        for (set, items) in groups {
            for (value, timeout) in filter_contained(items) {
                s.push_str(&format!(
                    "add element inet {} {} {{ {} timeout {}s }}\n",
                    self.table, set, value, timeout
                ));
            }
        }
        if s.is_empty() {
            return Ok(());
        }
        self.script(&s)
    }

    /// Delete one element; a missing/expired element is not an error.
    pub fn apply_del(&self, set: &str, value: &str) -> Result<(), String> {
        let _ = self.script(&format!(
            "delete element inet {} {} {{ {} }}\n",
            self.table, set, value
        ));
        Ok(())
    }

    /// List a set's members (values only, timeout stripped).
    pub fn members(&self, name: &str) -> Result<Vec<String>, String> {
        let out = self.run(&["list", "set", "inet", &self.table, name])?;
        if !out.status.success() {
            return Ok(Vec::new());
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let mut members = Vec::new();
        if let Some(start) = text.find("elements = {") {
            let rest = &text[start + "elements = {".len()..];
            if let Some(end) = rest.find('}') {
                for item in rest[..end].split(',') {
                    if let Some(tok) = item.split_whitespace().next() {
                        let t = tok.trim().trim_matches('"');
                        if !t.is_empty() {
                            members.push(t.to_string());
                        }
                    }
                }
            }
        }
        Ok(members)
    }
}

fn range_of(value: &str) -> Option<(u128, u128)> {
    let (addr, plen, fam4) = crate::json::parse_value(value)?;
    if fam4 == 4 {
        let mut v: u32 = 0;
        for b in &addr[..4] {
            v = (v << 8) | *b as u32;
        }
        let bits = plen as u32;
        let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
        let start = v & mask;
        let end = start | !mask;
        Some((start as u128, end as u128))
    } else {
        let mut v: u128 = 0;
        for b in &addr {
            v = (v << 8) | *b as u128;
        }
        let bits = plen as u32;
        let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
        let start = v & mask;
        let end = start | !mask;
        Some((start, end))
    }
}

/// Drop CIDRs wholly contained in another (nft interval sets reject overlaps).
fn filter_contained(items: Vec<(&str, u32)>) -> Vec<(&str, u32)> {
    let mut ranges: Vec<(u128, u128, &str, u32)> = items
        .into_iter()
        .filter_map(|(v, t)| range_of(v).map(|(s, e)| (s, e, v, t)))
        .collect();
    ranges.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
    let mut out: Vec<(&str, u32)> = Vec::new();
    let mut cur_end: Option<u128> = None;
    for (start, end, value, timeout) in ranges {
        match cur_end {
            Some(ce) if start <= ce && end <= ce => {} // contained: covered by an existing range
            Some(ce) if start <= ce => {
                cur_end = Some(end);
                out.push((value, timeout));
            }
            _ => {
                cur_end = Some(end);
                out.push((value, timeout));
            }
        }
    }
    out
}

fn nft_bin() -> String {
    for p in ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"] {
        if Path::new(p).exists() {
            return p.to_string();
        }
    }
    "nft".to_string()
}
