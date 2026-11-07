//! CAPI client (P4): TLS via rustls, HTTP/1.1 written by hand, login + stream
//! polling with exponential backoff. Applies decisions to a shared `Store`.
use crate::json;
use crate::store::{now_secs, Store};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct Credentials {
    pub url: String,
    pub login: String,
    pub password: String,
}

impl Credentials {
    pub fn load(path: &str) -> Result<Credentials, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
        let (mut url, mut login, mut password) = (None, None, None);
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if let Some((k, v)) = line.split_once(':') {
                let v = v.trim().trim_matches('"').trim_matches('\'').to_string();
                match k.trim() {
                    "url" => url = Some(v),
                    "login" | "machine_id" => login = Some(v),
                    "password" => password = Some(v),
                    _ => {}
                }
            }
        }
        Ok(Credentials {
            url: url.ok_or("credentials: missing url")?,
            login: login.ok_or("credentials: missing login/machine_id")?,
            password: password.ok_or("credentials: missing password")?,
        })
    }
}

struct Endpoint {
    tls: bool,
    host: String,
    port: u16,
    base: String,
}

fn parse_url(url: &str) -> Result<Endpoint, String> {
    let (scheme, rest) = url.split_once("://").ok_or("url: missing scheme")?;
    let tls = match scheme {
        "https" => true,
        "http" => false,
        _ => return Err(format!("url: unsupported scheme {scheme:?}")),
    };
    let (hostport, base) = match rest.split_once('/') {
        Some((h, b)) => (h, format!("/{b}")),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => (
            h.to_string(),
            p.parse().unwrap_or(if tls { 443 } else { 80 }),
        ),
        _ => (hostport.to_string(), if tls { 443 } else { 80 }),
    };
    if host.is_empty() {
        return Err("url: empty host".to_string());
    }
    Ok(Endpoint {
        tls,
        host,
        port,
        base: base.trim_end_matches('/').to_string(),
    })
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

fn tls_stream(
    ep: &Endpoint,
    tcp: TcpStream,
) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>, String> {
    let result = rustls_native_certs::load_native_certs();
    let mut roots = rustls::RootCertStore::empty();
    for cert in result.certs {
        let _ = roots.add(cert);
    }
    if roots.is_empty() {
        return Err("no system CA certificates found".to_string());
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls config: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = rustls::pki_types::ServerName::try_from(ep.host.clone())
        .map_err(|e| format!("bad server name: {e}"))?;
    let conn = rustls::ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| format!("tls init: {e}"))?;
    Ok(rustls::StreamOwned::new(conn, tcp))
}

fn decode_chunked(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let rel = match b[i..].windows(2).position(|w| w == b"\r\n") {
            Some(r) => r,
            None => break,
        };
        let size = usize::from_str_radix(
            String::from_utf8_lossy(&b[i..i + rel])
                .trim()
                .split(';')
                .next()
                .unwrap_or("0"),
            16,
        )
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

fn parse_response(buf: &[u8]) -> Result<(u16, Vec<u8>), String> {
    let idx = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("malformed HTTP response")?;
    let head = String::from_utf8_lossy(&buf[..idx]);
    let mut raw = buf[idx + 4..].to_vec();
    let status: u16 = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let lower = head.to_ascii_lowercase();
    if lower.contains("transfer-encoding: chunked") {
        raw = decode_chunked(&raw);
    } else if let Some(cl) = head.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        if k.trim().eq_ignore_ascii_case("content-length") {
            v.trim().parse::<usize>().ok()
        } else {
            None
        }
    }) {
        raw.truncate(cl);
    }
    Ok((status, raw))
}

fn http_request(
    ep: &Endpoint,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<(u16, Vec<u8>), String> {
    let tcp = TcpStream::connect((ep.host.as_str(), ep.port))
        .map_err(|e| format!("connect {}:{}: {e}", ep.host, ep.port))?;
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(20)));
    let _ = tcp.set_write_timeout(Some(Duration::from_secs(20)));
    let mut stream: Box<dyn ReadWrite> = if ep.tls {
        Box::new(tls_stream(ep, tcp)?)
    } else {
        Box::new(tcp)
    };
    let host_header = if (ep.tls && ep.port == 443) || (!ep.tls && ep.port == 80) {
        ep.host.clone()
    } else {
        format!("{}:{}", ep.host, ep.port)
    };
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: cslite/{}\r\n",
        crate::VERSION
    );
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if !body.is_empty() {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("Connection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    if !body.is_empty() {
        stream.write_all(body).map_err(|e| format!("write body: {e}"))?;
    }
    stream.flush().ok();
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            // Many servers close without a TLS close_notify; treat it as EOF and
            // use whatever has been received (the HTTP response is complete).
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e)
                if e.kind() == std::io::ErrorKind::ConnectionReset && !buf.is_empty() =>
            {
                break
            }
            Err(e) => return Err(format!("read: {e}")),
        }
    }
    parse_response(&buf)
}

/// Diagnostic: GET `url` and return the HTTP status (proves the TLS path).
pub fn probe(url: &str) -> Result<u16, String> {
    let ep = parse_url(url)?;
    let path = format!("{}/", ep.base);
    let (status, _) = http_request(&ep, "GET", &path, &[], b"")?;
    Ok(status)
}

pub struct CapiClient {
    ep: Endpoint,
    creds: Credentials,
    token: Option<String>,
    expire: u64,
}

impl CapiClient {
    pub fn new(creds: Credentials) -> Result<CapiClient, String> {
        let ep = parse_url(&creds.url)?;
        Ok(CapiClient {
            ep,
            creds,
            token: None,
            expire: 0,
        })
    }

    fn login(&mut self) -> Result<(), String> {
        let body = format!(
            "{{\"machine_id\":\"{}\",\"password\":\"{}\"}}",
            self.creds.login.replace('"', ""),
            self.creds.password.replace('"', "")
        );
        let (status, resp) = http_request(
            &self.ep,
            "POST",
            "/v3/watchers/login",
            &[("Content-Type", "application/json")],
            body.as_bytes(),
        )?;
        if status != 200 {
            return Err(format!("login HTTP {status}: {}", snippet(&resp)));
        }
        let token = json::extract_str(&resp, "token").ok_or("login: no token in response")?;
        self.token = Some(token);
        // Token lifetime: use the advertised expiry if parseable, else 1h.
        self.expire = json::extract_str(&resp, "expire")
            .and_then(|e| parse_rfc3339(&e))
            .unwrap_or_else(|| now_secs() as u64 + 3600);
        Ok(())
    }

    fn token(&mut self) -> Result<String, String> {
        let need = self.token.is_none() || (now_secs() as u64) + 60 >= self.expire;
        if need {
            self.login()?;
        }
        Ok(self.token.clone().unwrap_or_default())
    }

    /// Perform one authenticated stream fetch and return the raw body.
    pub fn fetch(&mut self, startup: bool) -> Result<Vec<u8>, String> {
        let token = self.token()?;
        let path = format!(
            "{}/v3/decisions/stream?startup={}&scopes=Ip,Range",
            self.ep.base, startup
        );
        let auth = format!("Bearer {token}");
        let (status, body) =
            http_request(&self.ep, "GET", &path, &[("Authorization", &auth)], b"")?;
        if status == 401 || status == 403 {
            self.token = None;
            return Err(format!("stream HTTP {status}: {}", snippet(&body)));
        }
        if status != 200 {
            return Err(format!("stream HTTP {status}: {}", snippet(&body)));
        }
        Ok(body)
    }

    /// One poll; returns the number of decisions added.
    pub fn poll(&mut self, store: &mut Store, startup: bool) -> Result<usize, String> {
        let body = self.fetch(startup)?;
        let (newv, delv) = json::parse_capi_v3(&body);
        let now = now_secs();
        let mut added = 0;
        for r in newv {
            if let Some(d) = json::build_decision(store, &r, now) {
                if store.insert(d) {
                    added += 1;
                }
            }
        }
        for r in delv {
            if let Some(mut d) = json::build_decision(store, &r, now) {
                d.scope = r.scope;
                store.remove(&d);
            }
        }
        store.prune_expired(now);
        Ok(added)
    }
}

fn snippet(b: &[u8]) -> String {
    let s = String::from_utf8_lossy(b);
    s.chars().take(120).collect()
}

/// Parse an RFC3339 timestamp (`YYYY-MM-DDTHH:MM:SSZ`) to epoch seconds.
fn parse_rfc3339(s: &str) -> Option<u64> {
    let s = s.trim().trim_end_matches('Z');
    let (date, time) = s.split_once('T')?;
    let mut d = date.split('-');
    let y: i64 = d.next()?.parse().ok()?;
    let mo: i64 = d.next()?.parse().ok()?;
    let da: i64 = d.next()?.parse().ok()?;
    let mut t = time.split(':');
    let h: i64 = t.next()?.parse().ok()?;
    let mi: i64 = t.next()?.parse().ok()?;
    let se: i64 = t.next()?.split('.').next()?.parse().ok()?;
    // days since epoch (civil-from-days)
    let yy = if mo <= 2 { y - 1 } else { y };
    let era = if yy >= 0 { yy } else { yy - 399 } / 400;
    let yoe = yy - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + da - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let secs = days * 86400 + h * 3600 + mi * 60 + se;
    if secs < 0 {
        None
    } else {
        Some(secs as u64)
    }
}

/// Background poller: startup snapshot, then deltas every `interval_secs`,
/// with exponential backoff (1s..60s) and jitter on error.
pub fn run(
    store: Arc<Mutex<Store>>,
    creds_path: &str,
    interval_secs: u64,
    full_refresh_secs: u64,
    persist: Option<PathBuf>,
) {
    let creds = match Credentials::load(creds_path) {
        Ok(c) => c,
        Err(e) => {
            crate::loge!("capi: {e}");
            return;
        }
    };
    let mut client = match CapiClient::new(creds) {
        Ok(c) => c,
        Err(e) => {
            crate::loge!("capi: {e}");
            return;
        }
    };
    let mut startup = true;
    let mut last_full: Option<Instant> = None;
    let mut backoff = 1u64;
    loop {
        // `startup=true` (full snapshot) once at boot, and again every
        // capi.update_frequency so deletions missed in deltas get reconciled.
        let full = startup
            || (full_refresh_secs > 0
                && last_full
                    .map(|t| t.elapsed().as_secs() >= full_refresh_secs)
                    .unwrap_or(true));
        let result = {
            let mut st = store.lock().unwrap_or_else(|p| p.into_inner());
            let r = client.poll(&mut st, full);
            if r.is_ok() {
                if let Some(p) = &persist {
                    let _ = st.save_to(p);
                }
            }
            r
        };
        match result {
            Ok(n) => {
                if full {
                    last_full = Some(Instant::now());
                }
                crate::logi!("capi: full_refresh={full} added {n} decisions");
                startup = false;
                backoff = 1;
                std::thread::sleep(Duration::from_secs(interval_secs.max(1)));
            }
            Err(e) => {
                let jitter = (now_secs() as u64 % 1000) / 1000;
                crate::logw!("capi poll failed: {e}; retry in {backoff}s");
                std::thread::sleep(Duration::from_secs(backoff + jitter));
                backoff = (backoff * 2).min(60);
            }
        }
    }
}
