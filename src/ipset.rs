//! ipset enforcement backend (P1).
//!
//! Drives the `ipset` binary. Set creation is idempotent (`-exist`), and every
//! entry carries a per-entry `timeout` so the **kernel** owns expiry — the
//! daemon keeps no expiry state (original spec §7.3).
//!
//! Set naming is per-origin, zero-based, first-seen order:
//! `<blacklists_ipv4>-<N>` / `<blacklists_ipv6>-<N>`, with `N` shared between
//! the v4 and v6 sets of the same origin. `OriginMap` persists that mapping so
//! a restart/cutover never reshuffles which set an origin owns.
//!
//! P1b will add a raw nfnetlink path; the `Backend` API stays the same.
use crate::config;
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::str::FromStr;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Family {
    V4,
    V6,
}

#[derive(Debug)]
pub enum IpSetError {
    Io(io::Error),
    Command {
        verb: String,
        args: String,
        status: Option<i32>,
        stderr: String,
    },
    InvalidValue(String),
}

impl fmt::Display for IpSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpSetError::Io(e) => write!(f, "i/o: {e}"),
            IpSetError::Command {
                verb,
                args,
                status,
                stderr,
            } => write!(
                f,
                "ipset {verb} failed (status {:?}): {stderr} [{args}]",
                status
            ),
            IpSetError::InvalidValue(m) => write!(f, "invalid value: {m}"),
        }
    }
}

impl std::error::Error for IpSetError {}

impl From<io::Error> for IpSetError {
    fn from(e: io::Error) -> Self {
        IpSetError::Io(e)
    }
}

fn ipset_bin() -> String {
    for p in ["/usr/sbin/ipset", "/sbin/ipset", "/usr/bin/ipset"] {
        if Path::new(p).exists() {
            return p.to_string();
        }
    }
    "ipset".to_string()
}

/// Backend configuration plus the `ipset` binary path.
pub struct Backend {
    pub ipv4_prefix: String,
    pub ipv6_prefix: String,
    pub maxelem: u64,
    pub bin: String,
}

impl Backend {
    pub fn from_config(b: &config::Backend) -> Self {
        Backend {
            ipv4_prefix: b.blacklists_ipv4.clone(),
            ipv6_prefix: b.blacklists_ipv6.clone(),
            maxelem: b.maxelem,
            bin: ipset_bin(),
        }
    }

    pub fn set_name(&self, family: Family, index: u8) -> String {
        match family {
            Family::V4 => format!("{}-{}", self.ipv4_prefix, index),
            Family::V6 => format!("{}-{}", self.ipv6_prefix, index),
        }
    }

    fn run(&self, args: &[&str]) -> Result<Output, IpSetError> {
        Command::new(&self.bin)
            .args(args)
            .output()
            .map_err(IpSetError::Io)
    }

    fn fail(&self, verb: &str, args: &[&str], out: &Output) -> IpSetError {
        IpSetError::Command {
            verb: verb.to_string(),
            args: args.join(" "),
            status: out.status.code(),
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        }
    }

    pub fn exists(&self, name: &str) -> bool {
        matches!(self.run(&["list", "-n", name]), Ok(o) if o.status.success())
    }

    /// Create the set if absent. Idempotent: `-exist` makes a concurrent/again
    /// create a no-op.
    pub fn ensure(&self, family: Family, name: &str) -> Result<(), IpSetError> {
        if self.exists(name) {
            return Ok(());
        }
        let fam = match family {
            Family::V4 => "inet",
            Family::V6 => "inet6",
        };
        let maxelem = self.maxelem.to_string();
        let args = [
            "create", name, "hash:net", "family", fam, "hashsize", "1024", "maxelem", &maxelem,
            "timeout", "300", "bucketsize", "12", "-exist",
        ];
        let out = self.run(&args)?;
        if out.status.success() {
            Ok(())
        } else {
            Err(self.fail("create", &args, &out))
        }
    }

    /// Add an entry with a per-entry timeout (seconds). Idempotent.
    pub fn add(
        &self,
        family: Family,
        name: &str,
        value: &str,
        timeout_secs: u64,
    ) -> Result<(), IpSetError> {
        self.ensure(family, name)?;
        let t = timeout_secs.to_string();
        let args = ["add", name, value, "timeout", &t, "-exist"];
        let out = self.run(&args)?;
        if out.status.success() {
            Ok(())
        } else {
            Err(self.fail("add", &args, &out))
        }
    }

    /// Delete an entry. Missing set or entry is not an error (idempotent teardown).
    pub fn del(&self, family: Family, name: &str, value: &str) -> Result<(), IpSetError> {
        if !self.exists(name) {
            return Ok(());
        }
        let _ = self.ensure(family, name);
        let args = ["del", name, value, "-exist"];
        let out = self.run(&args)?;
        if out.status.success() {
            Ok(())
        } else {
            let msg = String::from_utf8_lossy(&out.stderr);
            // ipset: "it's not added" when the entry is already absent.
            if msg.contains("not added") || msg.contains("not in set") {
                Ok(())
            } else {
                Err(self.fail("del", &args, &out))
            }
        }
    }

    pub fn test(&self, name: &str, value: &str) -> Result<bool, IpSetError> {
        let out = self.run(&["test", name, value])?;
        Ok(out.status.success())
    }

    /// List the members of a set (values only, timeout stripped).
    pub fn members(&self, name: &str) -> Result<Vec<String>, IpSetError> {
        let out = self.run(&["list", name])?;
        if !out.status.success() {
            return Ok(Vec::new());
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let mut in_members = false;
        let mut members = Vec::new();
        for line in text.lines() {
            if line.trim_start().starts_with("Members:") {
                in_members = true;
                continue;
            }
            if in_members {
                if let Some(tok) = line.split_whitespace().next() {
                    members.push(tok.to_string());
                }
            }
        }
        Ok(members)
    }

    pub fn flush(&self, name: &str) -> Result<(), IpSetError> {
        if !self.exists(name) {
            return Ok(());
        }
        let out = self.run(&["flush", name])?;
        if out.status.success() {
            Ok(())
        } else {
            Err(self.fail("flush", &["flush", name], &out))
        }
    }

    pub fn destroy(&self, name: &str) -> Result<(), IpSetError> {
        if !self.exists(name) {
            return Ok(());
        }
        let out = self.run(&["destroy", name])?;
        if out.status.success() {
            Ok(())
        } else {
            Err(self.fail("destroy", &["destroy", name], &out))
        }
    }

    /// Apply a batch of `add`/`del` lines through one `ipset restore -!`.
    /// `create` must NOT be included (an existing set aborts the batch);
    /// call `ensure()` first.
    pub fn restore(&self, script: &str) -> Result<(), IpSetError> {
        use std::io::Write as _;
        use std::process::{Command, Stdio};
        let mut child = Command::new(&self.bin)
            .args(["restore", "-!"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(IpSetError::Io)?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(script.as_bytes()).map_err(IpSetError::Io)?;
        }
        let out = child.wait_with_output().map_err(IpSetError::Io)?;
        if out.status.success() {
            Ok(())
        } else {
            Err(self.fail("restore", &["restore", "-!"], &out))
        }
    }
}

/// Parse an IP or CIDR into (family, normalized text). Rejects bad prefixes.
pub fn parse_value(s: &str) -> Result<(Family, String), IpSetError> {
    let t = s.trim();
    if t.is_empty() {
        return Err(IpSetError::InvalidValue("empty value".to_string()));
    }
    let (ip_part, plen) = match t.split_once('/') {
        Some((a, b)) => (a, Some(b)),
        None => (t, None),
    };
    let ip = IpAddr::from_str(ip_part)
        .map_err(|_| IpSetError::InvalidValue(format!("not an IP/CIDR: {t:?}")))?;
    let family = match ip {
        IpAddr::V4(_) => Family::V4,
        IpAddr::V6(_) => Family::V6,
    };
    if let Some(p) = plen {
        let max = if family == Family::V4 { 32 } else { 128 };
        let n: u32 = p
            .parse()
            .map_err(|_| IpSetError::InvalidValue(format!("bad prefix length: {p:?}")))?;
        if n > max {
            return Err(IpSetError::InvalidValue(format!(
                "prefix {n} exceeds /{max} for this family"
            )));
        }
    }
    Ok((family, t.to_string()))
}

/// Persisted origin -> set-index map (`first-seen order`).
pub struct OriginMap {
    path: PathBuf,
    map: BTreeMap<String, u8>,
    next: u8,
}

impl OriginMap {
    pub fn load(dir: &Path) -> Result<Self, IpSetError> {
        let path = dir.join("origins");
        let mut map = BTreeMap::new();
        let mut next: u8 = 0;
        if let Ok(txt) = fs::read_to_string(&path) {
            for line in txt.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let mut it = line.split_whitespace();
                if let (Some(origin), Some(n)) = (it.next(), it.next()) {
                    if let Ok(v) = n.parse::<u8>() {
                        map.insert(origin.to_string(), v);
                        if v >= next {
                            next = v.saturating_add(1);
                        }
                    }
                }
            }
        }
        Ok(OriginMap { path, map, next })
    }

    /// Assign (or return) the stable index for `origin`, persisting on change.
    pub fn index(&mut self, origin: &str) -> Result<u8, IpSetError> {
        if let Some(v) = self.map.get(origin) {
            return Ok(*v);
        }
        let v = self.next;
        self.next = self.next.saturating_add(1);
        self.map.insert(origin.to_string(), v);
        self.save()?;
        Ok(v)
    }

    pub fn get(&self, origin: &str) -> Option<u8> {
        self.map.get(origin).copied()
    }

    pub fn entries(&self) -> impl Iterator<Item = (&str, u8)> {
        self.map.iter().map(|(k, v)| (k.as_str(), *v))
    }

    pub fn save(&self) -> Result<(), IpSetError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(IpSetError::Io)?;
        }
        let mut s = String::from("# origin index (cslite; do not reorder)\n");
        for (origin, idx) in &self.map {
            s.push_str(&format!("{origin} {idx}\n"));
        }
        fs::write(&self.path, s).map_err(IpSetError::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_names_per_origin_index() {
        let b = Backend {
            ipv4_prefix: "crowdsec-blacklists".into(),
            ipv6_prefix: "crowdsec6-blacklists".into(),
            maxelem: 131072,
            bin: "ipset".into(),
        };
        assert_eq!(b.set_name(Family::V4, 0), "crowdsec-blacklists-0");
        assert_eq!(b.set_name(Family::V6, 1), "crowdsec6-blacklists-1");
    }

    #[test]
    fn value_family_and_validation() {
        assert_eq!(parse_value("1.2.3.4").unwrap().0, Family::V4);
        assert_eq!(parse_value("2001:db8::1").unwrap().0, Family::V6);
        assert_eq!(parse_value("1.2.3.0/24").unwrap().0, Family::V4);
        assert_eq!(parse_value("2001:db8::/32").unwrap().0, Family::V6);
        assert!(parse_value("1.2.3.4/33").is_err());
        assert!(parse_value("not-an-ip").is_err());
        assert!(parse_value("").is_err());
    }

    #[test]
    fn origin_map_persists_first_seen_order() {
        let dir = std::env::temp_dir().join(format!("cslite-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        {
            let mut m = OriginMap::load(&dir).unwrap();
            assert_eq!(m.index("CAPI").unwrap(), 0);
            assert_eq!(m.index("crowdsec").unwrap(), 1);
            assert_eq!(m.index("CAPI").unwrap(), 0); // stable
        }
        // reload: same assignment, no reshuffle
        let m = OriginMap::load(&dir).unwrap();
        assert_eq!(m.get("CAPI"), Some(0));
        assert_eq!(m.get("crowdsec"), Some(1));
        let mut m2 = m;
        assert_eq!(m2.index("third").unwrap(), 2);
        let _ = fs::remove_dir_all(&dir);
    }
}
