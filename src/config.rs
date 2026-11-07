//! Strict subset of YAML for `/etc/cslite/cslite.yaml`.
//!
//! Supported: comments (`#` outside quotes), top-level `key: value`, one level
//! of nesting (`section:` then indented `key: value`), `true|false`, integers,
//! plain or quoted strings, and inline lists (`[a, b]`). Anything else is an
//! error with a line number — we fail loudly rather than guess.
use crate::log::Level;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Lapi,
    Direct,
}

#[derive(Debug, Clone)]
pub struct Persistence {
    pub enabled: bool,
    pub path: String,
}

#[derive(Debug, Clone)]
pub struct Capi {
    pub enabled: bool,
    pub credentials_path: String,
    pub update_frequency_secs: u64,
}

#[derive(Debug, Clone)]
pub struct Backend {
    pub mode: String,
    pub blacklists_ipv4: String,
    pub blacklists_ipv6: String,
    pub ipset_type: String,
    pub maxelem: u64,
    pub deny_action: String,
    pub iptables_chains: Vec<String>,
    pub add_rule_comments: bool,
    pub teardown_on_exit: bool,
    pub nft_table: String,
    pub nft_table_ipv6: String,
    pub nft_chain: String,
    pub nft_priority: i32,
}

#[derive(Debug, Clone)]
pub struct LocalDetection {
    pub enabled: bool,
    pub log_path: String,
    pub ban_threshold: u64,
    pub window_secs: u64,
    pub ban_duration_secs: u64,
}

#[derive(Debug, Clone)]
pub struct Limits {
    pub max_decisions: u64,
    pub max_bans_per_second: u64,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub mode: Mode,
    pub listen: String,
    pub api_key: Option<String>,
    pub api_key_file: Option<String>,
    pub log_level: Level,
    pub update_frequency_secs: u64,
    pub startup_pull: bool,
    pub persistence: Persistence,
    pub capi: Capi,
    pub backend: Backend,
    pub local_detection: LocalDetection,
    pub limits: Limits,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            mode: Mode::Lapi,
            listen: "127.0.0.1:8080".to_string(),
            api_key: None,
            api_key_file: None,
            log_level: Level::Info,
            update_frequency_secs: 10,
            startup_pull: true,
            persistence: Persistence {
                enabled: true,
                path: "/var/lib/cslite/decisions.bin".to_string(),
            },
            capi: Capi {
                enabled: true,
                credentials_path: "/etc/crowdsec/online_api_credentials.yaml".to_string(),
                update_frequency_secs: 7200,
            },
            backend: Backend {
                mode: "iptables".to_string(),
                blacklists_ipv4: "crowdsec-blacklists".to_string(),
                blacklists_ipv6: "crowdsec6-blacklists".to_string(),
                ipset_type: "hash:net".to_string(),
                maxelem: 131072,
                deny_action: "DROP".to_string(),
                iptables_chains: vec!["INPUT".to_string()],
                add_rule_comments: true,
                teardown_on_exit: false,
                nft_table: "crowdsec".to_string(),
                nft_table_ipv6: "crowdsec6".to_string(),
                nft_chain: "crowdsec-chain".to_string(),
                nft_priority: -10,
            },
            local_detection: LocalDetection {
                enabled: false,
                log_path: "/var/log/auth.log".to_string(),
                ban_threshold: 5,
                window_secs: 60,
                ban_duration_secs: 4 * 3600,
            },
            limits: Limits {
                max_decisions: 100_000,
                max_bans_per_second: 50,
            },
        }
    }
}

#[derive(Debug)]
pub struct ConfigError {
    pub line: usize,
    pub msg: String,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.line == 0 {
            write!(f, "{}", self.msg)
        } else {
            write!(f, "line {}: {}", self.line, self.msg)
        }
    }
}

impl std::error::Error for ConfigError {}

impl ConfigError {
    fn at(line: usize, msg: impl Into<String>) -> Self {
        ConfigError { line, msg: msg.into() }
    }
}

/// Load and validate a config file.
pub fn load(path: &str) -> Result<Config, ConfigError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| ConfigError::at(0, format!("cannot read {path}: {e}")))?;
    parse_str(&text)
}

fn strip_comment(line: &str) -> &str {
    let mut in_quote = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => in_quote = !in_quote,
            '#' if !in_quote => return &line[..i],
            _ => {}
        }
    }
    line
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    if s.len() >= 2 {
        let b = s.as_bytes();
        if (b[0] == b'"' && b[b.len() - 1] == b'"')
            || (b[0] == b'\'' && b[b.len() - 1] == b'\'')
        {
            return s[1..s.len() - 1].to_string();
        }
    }
    s.to_string()
}

fn as_bool(line: usize, key: &str, v: &str) -> Result<bool, ConfigError> {
    match v.to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Ok(true),
        "false" | "no" | "off" | "0" => Ok(false),
        _ => Err(ConfigError::at(line, format!("{key}: expected boolean, got {v:?}"))),
    }
}

fn as_u64(line: usize, key: &str, v: &str) -> Result<u64, ConfigError> {
    v.trim()
        .replace('_', "")
        .parse::<u64>()
        .map_err(|_| ConfigError::at(line, format!("{key}: expected integer, got {v:?}")))
}

fn as_i32(line: usize, key: &str, v: &str) -> Result<i32, ConfigError> {
    v.trim()
        .parse::<i32>()
        .map_err(|_| ConfigError::at(line, format!("{key}: expected integer, got {v:?}")))
}

/// Parse a duration like `10s`, `4h`, `2h`, `90m`, or a bare number of seconds.
pub fn parse_duration_secs(v: &str) -> Result<u64, String> {
    let v = v.trim();
    let (num, mult) = match v.as_bytes().last() {
        Some(&b's') => (&v[..v.len() - 1], 1u64),
        Some(&b'm') => (&v[..v.len() - 1], 60),
        Some(&b'h') => (&v[..v.len() - 1], 3600),
        Some(&b'd') => (&v[..v.len() - 1], 86_400),
        _ => (v, 1),
    };
    let n = num
        .trim()
        .parse::<u64>()
        .map_err(|_| format!("expected duration like 10s/4h, got {v:?}"))?;
    Ok(n * mult)
}

fn as_secs(line: usize, key: &str, v: &str) -> Result<u64, ConfigError> {
    parse_duration_secs(v).map_err(|m| ConfigError::at(line, format!("{key}: {m}")))
}

fn as_list(line: usize, key: &str, v: &str) -> Result<Vec<String>, ConfigError> {
    let t = v.trim();
    let inner = t
        .strip_prefix('[')
        .and_then(|x| x.strip_suffix(']'))
        .ok_or_else(|| ConfigError::at(line, format!("{key}: expected list like [INPUT, FORWARD]")))?;
    if inner.trim().is_empty() {
        return Ok(Vec::new());
    }
    Ok(inner.split(',').map(|s| unquote(s.trim())).collect())
}

/// Parse config text (exposed for tests).
pub fn parse_str(text: &str) -> Result<Config, ConfigError> {
    let mut cfg = Config::default();
    let mut section = String::new();

    for (idx, raw) in text.lines().enumerate() {
        let lineno = idx + 1;
        let line = strip_comment(raw);
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let indent = line.len() - line.trim_start().len();

        // A bare `section:` header.
        if indent == 0 {
            if let Some(name) = trimmed.strip_suffix(':') {
                let name = name.trim();
                if name.is_empty() {
                    return Err(ConfigError::at(lineno, "empty section header"));
                }
                section = name.to_string();
                continue;
            }
            section.clear(); // top-level key resets any active section
        }

        let (k, v) = trimmed
            .split_once(':')
            .ok_or_else(|| ConfigError::at(lineno, format!("expected 'key: value', got {trimmed:?}")))?;
        let key = k.trim();
        let val = v.trim();
        let full = if indent == 0 { key.to_string() } else { format!("{section}.{key}") };

        match full.as_str() {
            "mode" => {
                cfg.mode = match unquote(val).to_ascii_lowercase().as_str() {
                    "lapi" => Mode::Lapi,
                    "direct" => Mode::Direct,
                    other => return Err(ConfigError::at(lineno, format!("mode: expected lapi|direct, got {other:?}"))),
                }
            }
            "listen" => cfg.listen = unquote(val),
            "api_key" => cfg.api_key = Some(unquote(val)),
            "api_key_file" => cfg.api_key_file = Some(unquote(val)),
            "log_level" => {
                cfg.log_level = Level::parse(val)
                    .ok_or_else(|| ConfigError::at(lineno, format!("log_level: expected error|warn|info|debug, got {val:?}")))?;
            }
            "update_frequency" => cfg.update_frequency_secs = as_secs(lineno, "update_frequency", val)?,
            "startup_pull" => cfg.startup_pull = as_bool(lineno, "startup_pull", val)?,

            "persistence.enabled" => cfg.persistence.enabled = as_bool(lineno, "persistence.enabled", val)?,
            "persistence.path" => cfg.persistence.path = unquote(val),

            "capi.enabled" => cfg.capi.enabled = as_bool(lineno, "capi.enabled", val)?,
            "capi.credentials_path" => cfg.capi.credentials_path = unquote(val),
            "capi.update_frequency" => cfg.capi.update_frequency_secs = as_secs(lineno, "capi.update_frequency", val)?,

            "backend.mode" => cfg.backend.mode = unquote(val),
            "backend.blacklists_ipv4" => cfg.backend.blacklists_ipv4 = unquote(val),
            "backend.blacklists_ipv6" => cfg.backend.blacklists_ipv6 = unquote(val),
            "backend.ipset_type" => cfg.backend.ipset_type = unquote(val),
            "backend.maxelem" => cfg.backend.maxelem = as_u64(lineno, "backend.maxelem", val)?,
            "backend.deny_action" => cfg.backend.deny_action = unquote(val),
            "backend.iptables_chains" => cfg.backend.iptables_chains = as_list(lineno, "backend.iptables_chains", val)?,
            "backend.add_rule_comments" => cfg.backend.add_rule_comments = as_bool(lineno, "backend.add_rule_comments", val)?,
            "backend.teardown_on_exit" => cfg.backend.teardown_on_exit = as_bool(lineno, "backend.teardown_on_exit", val)?,
            "backend.nft_table" => cfg.backend.nft_table = unquote(val),
            "backend.nft_table_ipv6" => cfg.backend.nft_table_ipv6 = unquote(val),
            "backend.nft_chain" => cfg.backend.nft_chain = unquote(val),
            "backend.nft_priority" => cfg.backend.nft_priority = as_i32(lineno, "backend.nft_priority", val)?,

            "local_detection.enabled" => cfg.local_detection.enabled = as_bool(lineno, "local_detection.enabled", val)?,
            "local_detection.log_path" => cfg.local_detection.log_path = unquote(val),
            "local_detection.ban_threshold" => cfg.local_detection.ban_threshold = as_u64(lineno, "local_detection.ban_threshold", val)?,
            "local_detection.window" => cfg.local_detection.window_secs = as_secs(lineno, "local_detection.window", val)?,
            "local_detection.ban_duration" => cfg.local_detection.ban_duration_secs = as_secs(lineno, "local_detection.ban_duration", val)?,

            "limits.max_decisions" => cfg.limits.max_decisions = as_u64(lineno, "limits.max_decisions", val)?,
            "limits.max_bans_per_second" => cfg.limits.max_bans_per_second = as_u64(lineno, "limits.max_bans_per_second", val)?,

            other => return Err(ConfigError::at(lineno, format!("unknown key {other:?}"))),
        }
    }

    validate(&cfg)?;
    Ok(cfg)
}

fn validate(cfg: &Config) -> Result<(), ConfigError> {
    if cfg.mode == Mode::Lapi {
        if cfg.listen.parse::<std::net::SocketAddr>().is_err() {
            return Err(ConfigError::at(0, format!("listen: not a valid address: {:?}", cfg.listen)));
        }
        let has_key = cfg.api_key.is_some() || cfg.api_key_file.is_some();
        if !has_key {
            return Err(ConfigError::at(0, "mode=lapi requires api_key or api_key_file".to_string()));
        }
    }
    if cfg.backend.mode != "iptables" && cfg.backend.mode != "nftables" {
        return Err(ConfigError::at(0, format!("backend.mode: expected iptables|nftables, got {:?}", cfg.backend.mode)));
    }
    if cfg.backend.ipset_type != "hash:net" {
        return Err(ConfigError::at(0, format!("backend.ipset_type: must be hash:net (CIDRs), got {:?}", cfg.backend.ipset_type)));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_config() {
        let text = r#"
mode: lapi                 # comment
listen: 127.0.0.1:8080
api_key: "abc"
log_level: debug
update_frequency: 10s
startup_pull: true

persistence:
  enabled: false
  path: /tmp/x.bin

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
  deny_action: DROP
  iptables_chains: [INPUT, FORWARD]
  add_rule_comments: true
  teardown_on_exit: false

local_detection:
  enabled: false
  log_path: /var/log/auth.log
  ban_threshold: 5
  window: 60s
  ban_duration: 4h

limits:
  max_decisions: 100000
  max_bans_per_second: 50
"#;
        let c = parse_str(text).expect("parse");
        assert_eq!(c.mode, Mode::Lapi);
        assert_eq!(c.log_level, Level::Debug);
        assert_eq!(c.update_frequency_secs, 10);
        assert!(!c.persistence.enabled);
        assert_eq!(c.capi.update_frequency_secs, 7200);
        assert_eq!(c.backend.iptables_chains, vec!["INPUT", "FORWARD"]);
        assert_eq!(c.local_detection.ban_duration_secs, 4 * 3600);
    }

    #[test]
    fn rejects_unknown_key() {
        let e = parse_str("mode: lapi\nbogus: 1\n").unwrap_err();
        assert!(e.to_string().contains("unknown key"));
    }

    #[test]
    fn rejects_hash_ip() {
        let e = parse_str("mode: direct\nbackend:\n  ipset_type: hash:ip\n").unwrap_err();
        assert!(e.to_string().contains("hash:net"));
    }

    #[test]
    fn rejects_bad_duration() {
        let e = parse_str("update_frequency: ten\n").unwrap_err();
        assert!(e.to_string().contains("duration"));
    }
}
