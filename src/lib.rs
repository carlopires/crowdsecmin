//! cslite — lightweight CrowdSec-compatible LAPI (Rust).
//!
//! P0 scope: config parsing, logging, version, systemd notify, CLI.
//! No `unsafe` anywhere in the crate outside the future `netlink` module.
#![forbid(unsafe_code)]

pub mod capi;
pub mod client;
pub mod config;
pub mod detect;
pub mod direct;
pub mod ipset;
pub mod json;
pub mod log;
pub mod nft;
pub mod server;
pub mod store;
pub mod sysd;

/// cslite's own version (from Cargo.toml).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Version strings advertised for compatibility with the live stack.
pub const COMPAT_CROWDSEC: &str = "v1.8.1-debian-pragmatic-amd64";
pub const COMPAT_BOUNCER: &str = "v0.0.36";
