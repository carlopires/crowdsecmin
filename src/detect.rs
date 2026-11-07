//! Local SSH brute-force detection from `/var/log/auth.log` (P6).
//!
//! Incremental tail (inode + offset, rotation/truncation aware), a bounded
//! per-source sliding window, and a per-second ban rate limit. Bans are handed
//! to a callback (Mode B inserts into the store; Mode A writes to ipset).
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::net::IpAddr;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub struct DetectConfig {
    pub log_path: String,
    pub threshold: u32,
    pub window_secs: u64,
    pub ban_duration_secs: u32,
    pub max_bans_per_sec: u32,
}

/// Incremental line tailer.
struct Tailer {
    path: PathBuf,
    file: Option<File>,
    ino: u64,
    offset: u64,
    partial: Vec<u8>,
    started: bool,
}

impl Tailer {
    fn new(path: PathBuf) -> Self {
        Tailer {
            path,
            file: None,
            ino: 0,
            offset: 0,
            partial: Vec::new(),
            started: false,
        }
    }

    fn open(&mut self, from_end: bool) -> std::io::Result<()> {
        let mut f = OpenOptions::new().read(true).open(&self.path)?;
        let md = f.metadata()?;
        self.ino = md.ino();
        self.offset = if from_end { md.len() } else { 0 };
        f.seek(SeekFrom::Start(self.offset))?;
        self.file = Some(f);
        self.partial.clear();
        Ok(())
    }

    fn poll(&mut self) -> std::io::Result<Vec<String>> {
        if !self.path.exists() {
            self.file = None;
            return Ok(Vec::new());
        }
        if !self.started {
            self.open(true)?;
            self.started = true;
            return Ok(Vec::new());
        }
        let md = std::fs::metadata(&self.path)?;
        if md.ino() != self.ino || md.len() < self.offset {
            // rotated or truncated: read the new file from the start
            self.open(false)?;
            return Ok(Vec::new());
        }
        let f = match self.file.as_mut() {
            Some(f) => f,
            None => {
                self.open(true)?;
                return Ok(Vec::new());
            }
        };
        f.seek(SeekFrom::Start(self.offset))?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        self.offset += buf.len() as u64;
        let mut data = std::mem::take(&mut self.partial);
        data.extend_from_slice(&buf);
        let mut lines = Vec::new();
        let mut start = 0;
        for (i, b) in data.iter().enumerate() {
            if *b == b'\n' {
                lines.push(String::from_utf8_lossy(&data[start..i]).to_string());
                start = i + 1;
            }
        }
        self.partial = data[start..].to_vec();
        Ok(lines)
    }
}

/// Extract the source IP from a failed-auth syslog line.
pub fn parse_failed(line: &str) -> Option<IpAddr> {
    if !(line.contains("Failed password") || line.contains("Invalid user")) {
        return None;
    }
    let idx = line.find(" from ")?;
    let tok = line[idx + 6..].split_whitespace().next()?;
    tok.parse().ok()
}

struct Tracker {
    threshold: u32,
    window: Duration,
    cap: usize,
    map: HashMap<IpAddr, (u32, Instant)>,
}

impl Tracker {
    fn new(threshold: u32, window: Duration, cap: usize) -> Self {
        Tracker {
            threshold,
            window,
            cap,
            map: HashMap::new(),
        }
    }

    /// Record one failure; true exactly when the threshold is first reached.
    fn record(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        if self.map.len() >= self.cap && !self.map.contains_key(&ip) {
            if let Some(k) = self.map.keys().next().copied() {
                self.map.remove(&k);
            }
        }
        let e = self.map.entry(ip).or_insert((0, now));
        if now.duration_since(e.1) > self.window {
            *e = (0, now);
        }
        e.0 += 1;
        e.0 == self.threshold
    }
}

/// Run forever: poll the log, count failures, and call `on_ban` at threshold.
pub fn run<F: FnMut(IpAddr)>(cfg: DetectConfig, mut on_ban: F) {
    let mut tailer = Tailer::new(PathBuf::from(&cfg.log_path));
    let mut tracker = Tracker::new(cfg.threshold.max(1), Duration::from_secs(cfg.window_secs.max(1)), 4096);
    let mut window = (Instant::now(), 0u32);
    crate::logi!(
        "detect: tailing {} (threshold {} in {}s, ban {}s)",
        cfg.log_path,
        cfg.threshold,
        cfg.window_secs,
        cfg.ban_duration_secs
    );
    loop {
        match tailer.poll() {
            Ok(lines) => {
                for line in lines {
                    if let Some(ip) = parse_failed(&line) {
                        if tracker.record(ip) {
                            let now = Instant::now();
                            if now.duration_since(window.0).as_secs() >= 1 {
                                window = (now, 0);
                            }
                            if window.1 >= cfg.max_bans_per_sec {
                                crate::logw!("detect: ban rate limit reached, dropping {ip}");
                                continue;
                            }
                            window.1 += 1;
                            crate::logi!("detect: banning {ip}");
                            on_ban(ip);
                        }
                    }
                }
            }
            Err(e) => crate::logw!("detect: tail error: {e}"),
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_failed_lines() {
        assert_eq!(
            parse_failed("sshd[1]: Failed password for root from 203.0.113.9 port 2222 ssh2"),
            Some("203.0.113.9".parse().unwrap())
        );
        assert_eq!(
            parse_failed("sshd[1]: Invalid user admin from 2001:db8::5 port 22"),
            Some("2001:db8::5".parse().unwrap())
        );
        assert_eq!(parse_failed("Accepted publickey for root from 1.2.3.4"), None);
    }

    #[test]
    fn threshold_triggers_once() {
        let mut t = Tracker::new(3, Duration::from_secs(60), 16);
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        assert!(!t.record(ip));
        assert!(!t.record(ip));
        assert!(t.record(ip)); // exactly at threshold
        assert!(!t.record(ip)); // no repeat
    }

    #[test]
    fn tailer_reads_appended_lines() {
        let path = std::env::temp_dir().join(format!("cslite-auth-{}.log", std::process::id()));
        std::fs::write(&path, b"").unwrap();
        let mut t = Tailer::new(path.clone());
        assert!(t.poll().unwrap().is_empty()); // start at end
        use std::io::Write;
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        writeln!(f, "line1").unwrap();
        writeln!(f, "line2").unwrap();
        drop(f);
        let lines = t.poll().unwrap();
        assert_eq!(lines, vec!["line1".to_string(), "line2".to_string()]);
        let _ = std::fs::remove_file(&path);
    }
}
