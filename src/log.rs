//! Rate-limited stderr logger (C-10): stderr -> journald, never a self-rotated
//! file, and never unbounded. At most `MAX_PER_SEC` lines per second; excess is
//! dropped and reported as a single suppression notice.
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Level {
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
}

impl Level {
    pub fn parse(s: &str) -> Option<Level> {
        match s.trim().to_ascii_lowercase().as_str() {
            "error" => Some(Level::Error),
            "warn" | "warning" => Some(Level::Warn),
            "info" => Some(Level::Info),
            "debug" => Some(Level::Debug),
            _ => None,
        }
    }
    fn tag(self) -> &'static str {
        match self {
            Level::Error => "ERROR",
            Level::Warn => "WARN ",
            Level::Info => "INFO ",
            Level::Debug => "DEBUG",
        }
    }
}

const MAX_PER_SEC: u32 = 50;
static LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);

struct Limiter {
    window: Option<Instant>,
    count: u32,
    suppressed: u32,
}
static LIMITER: Mutex<Limiter> = Mutex::new(Limiter {
    window: None,
    count: 0,
    suppressed: 0,
});

/// Set the maximum level that will be emitted.
pub fn set_max(level: Level) {
    LEVEL.store(level as u8, Ordering::Relaxed);
}

pub fn max() -> u8 {
    LEVEL.load(Ordering::Relaxed)
}

fn hhmmss() -> (u64, u64, u64) {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // UTC; journald adds its own timestamps anyway.
    ((secs / 3600) % 24, (secs / 60) % 60, secs % 60)
}

/// Emit one log line, subject to level and rate limiting.
pub fn log(level: Level, args: std::fmt::Arguments) {
    if (level as u8) > max() {
        return;
    }
    let mut lim = match LIMITER.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let now = Instant::now();
    let reset = match lim.window {
        None => true,
        Some(w) => now.duration_since(w).as_secs() >= 1,
    };
    if reset {
        lim.window = Some(now);
        lim.count = 0;
    }
    if lim.count >= MAX_PER_SEC {
        lim.suppressed += 1;
        return;
    }
    lim.count += 1;
    if lim.suppressed > 0 {
        let n = lim.suppressed;
        lim.suppressed = 0;
        eprintln!("[cslite] suppressed {n} log line(s): rate limit");
    }
    let (h, m, s) = hhmmss();
    eprintln!("[{h:02}:{m:02}:{s:02}Z {}] {}", level.tag(), args);
}

#[macro_export]
macro_rules! loge {
    ($($t:tt)*) => { $crate::log::log($crate::log::Level::Error, format_args!($($t)*)) };
}
#[macro_export]
macro_rules! logw {
    ($($t:tt)*) => { $crate::log::log($crate::log::Level::Warn, format_args!($($t)*)) };
}
#[macro_export]
macro_rules! logi {
    ($($t:tt)*) => { $crate::log::log($crate::log::Level::Info, format_args!($($t)*)) };
}
#[macro_export]
macro_rules! logd {
    ($($t:tt)*) => { $crate::log::log($crate::log::Level::Debug, format_args!($($t)*)) };
}
