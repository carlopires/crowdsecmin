//! Minimal HTTP/1.1 client for the cslite CLI (std only).
//!
//! Handles `Content-Length` and `Transfer-Encoding: chunked`, which is what the
//! daemon emits for `/v1/decisions` and `/v1/decisions/stream`.
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub struct Client {
    addr: String,
    key: String,
}

impl Client {
    pub fn new(addr: &str, key: &str) -> Self {
        Client {
            addr: addr.to_string(),
            key: key.to_string(),
        }
    }

    fn request(&self, method: &str, path: &str, body: Option<&str>) -> Result<String, String> {
        let mut s = TcpStream::connect(&self.addr)
            .map_err(|e| format!("daemon unreachable at {}: {e}", self.addr))?;
        let _ = s.set_read_timeout(Some(Duration::from_secs(15)));
        let _ = s.set_write_timeout(Some(Duration::from_secs(15)));
        let body = body.unwrap_or("");
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nX-Api-Key: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.addr,
            self.key,
            body.len()
        );
        s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&buf).to_string();
        let (head, raw) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
        let status: u16 = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let chunked = head
            .to_ascii_lowercase()
            .contains("transfer-encoding: chunked");
        let decoded = if chunked {
            decode_chunked(raw.as_bytes())
        } else {
            raw.as_bytes().to_vec()
        };
        if !(200..300).contains(&status) {
            return Err(format!(
                "HTTP {status}: {}",
                String::from_utf8_lossy(&decoded)
            ));
        }
        Ok(String::from_utf8_lossy(&decoded).to_string())
    }

    pub fn list(&self) -> Result<String, String> {
        self.request("GET", "/v1/decisions", None)
    }

    pub fn add(
        &self,
        value: &str,
        duration_secs: u64,
        origin: &str,
        scenario: &str,
    ) -> Result<String, String> {
        let scope = if value.contains('/') { "Range" } else { "Ip" };
        let body = format!(
            "{{\"duration\":\"{duration_secs}s\",\"origin\":\"{origin}\",\"scenario\":\"{scenario}\",\"scope\":\"{scope}\",\"type\":\"ban\",\"value\":\"{value}\"}}"
        );
        self.request("POST", "/v1/decisions", Some(&body))
    }

    pub fn delete(&self, value: &str) -> Result<String, String> {
        self.request("DELETE", &format!("/v1/decisions?value={value}"), None)
    }

    pub fn bouncers(&self) -> Result<String, String> {
        self.request("GET", "/v1/bouncers", None)
    }

    pub fn add_bouncer(&self, name: &str) -> Result<String, String> {
        let body = format!("{{\"name\":\"{name}\"}}");
        self.request("POST", "/v1/bouncers", Some(&body))
    }

    pub fn health(&self) -> Result<String, String> {
        self.request("GET", "/health", None)
    }
}

fn decode_chunked(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let rel = match b[i..].windows(2).position(|w| w == b"\r\n") {
            Some(r) => r,
            None => break,
        };
        let line = String::from_utf8_lossy(&b[i..i + rel]);
        let size = usize::from_str_radix(line.trim().split(';').next().unwrap_or("0"), 16)
            .unwrap_or(0);
        i += rel + 2;
        if size == 0 {
            break;
        }
        if i + size > b.len() {
            out.extend_from_slice(&b[i..]);
            break;
        }
        out.extend_from_slice(&b[i..i + size]);
        i += size;
        if b.get(i..i + 2) == Some(b"\r\n") {
            i += 2;
        }
    }
    out
}
