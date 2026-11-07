//! HTTP/1.1 LAPI server (Mode B). Blocking, single-threaded accept loop with
//! per-connection timeouts. The store is shared with the CAPI poller thread
//! via `Arc<Mutex<Store>>`.
//!
//! Endpoints: /v1/decisions/stream, /v1/decisions (GET/POST/DELETE),
//! /v1/bouncers (GET/POST), /health, /v1/heartbeat.
use crate::json::{self, push_decision_json};
use crate::store::{now_secs, Decision, Store};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct Ctx {
    pub api_key: String,
    pub extra_keys: Vec<String>,
    pub bouncers: Vec<(String, String)>,
    pub store: Arc<Mutex<Store>>,
    pub cursors: HashMap<String, u64>,
    pub persist: Option<PathBuf>,
}

impl Ctx {
    pub fn new(api_key: String, store: Store, persist: Option<PathBuf>) -> Self {
        Ctx {
            api_key,
            extra_keys: Vec::new(),
            bouncers: Vec::new(),
            store: Arc::new(Mutex::new(store)),
            cursors: HashMap::new(),
            persist,
        }
    }

    pub fn store_handle(&self) -> Arc<Mutex<Store>> {
        Arc::clone(&self.store)
    }

    fn authorized(&self, key: &str) -> bool {
        key == self.api_key || self.extra_keys.iter().any(|k| k == key)
    }
}

pub fn run<F: FnOnce()>(listen: &str, mut ctx: Ctx, ready: F) -> io::Result<()> {
    let listener = TcpListener::bind(listen)?;
    ready();
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                if let Err(e) = handle(stream, &mut ctx) {
                    crate::logd!("connection error: {e}");
                }
            }
            Err(e) => crate::logw!("accept failed: {e}"),
        }
    }
    Ok(())
}

fn find_headers_end(b: &[u8]) -> Option<usize> {
    b.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn read_request(s: &mut TcpStream) -> io::Result<(String, Vec<u8>)> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 2048];
    let mut hend = None;
    loop {
        let n = s.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(i) = find_headers_end(&buf) {
            hend = Some(i);
            break;
        }
        if buf.len() > 16384 {
            break;
        }
    }
    let hend = hend.unwrap_or(buf.len());
    let head = String::from_utf8_lossy(&buf[..hend.saturating_sub(4)]).to_string();
    let cl = content_length(&head).unwrap_or(0);
    let mut body = if hend <= buf.len() {
        buf[hend..].to_vec()
    } else {
        Vec::new()
    };
    while body.len() < cl {
        let n = s.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(cl);
    Ok((head, body))
}

fn content_length(head: &str) -> Option<usize> {
    for l in head.split("\r\n") {
        if let Some((k, v)) = l.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                return v.trim().parse().ok();
            }
        }
    }
    None
}

fn handle(mut s: TcpStream, ctx: &mut Ctx) -> io::Result<()> {
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    s.set_write_timeout(Some(Duration::from_secs(30)))?;

    let (head, body) = read_request(&mut s)?;
    let mut lines = head.split("\r\n");
    let reqline = lines.next().unwrap_or("");
    let mut parts = reqline.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("/");

    let mut api_key: Option<String> = None;
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            if k.trim().eq_ignore_ascii_case("x-api-key") {
                api_key = Some(v.trim().to_string());
            }
        }
    }
    let key = api_key.unwrap_or_default();
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p, q),
        None => (target, ""),
    };

    match (method, path) {
        ("GET", "/health") => respond(&mut s, 200, "application/json", "{\"status\":\"up\"}"),
        ("GET", "/v1/heartbeat") => {
            if ctx.authorized(&key) {
                respond_empty(&mut s, 200)
            } else {
                forbidden(&mut s)
            }
        }
        ("GET", "/v1/decisions/stream") => {
            if !ctx.authorized(&key) {
                return forbidden(&mut s);
            }
            let startup = query.split('&').any(|kv| kv == "startup=true");
            if startup {
                write_snapshot(&mut s, ctx)
            } else {
                delta_response(&mut s, ctx, &key)
            }
        }
        ("GET", "/v1/decisions") => {
            if !ctx.authorized(&key) {
                return forbidden(&mut s);
            }
            write_snapshot(&mut s, ctx)
        }
        ("POST", "/v1/decisions") => {
            if !ctx.authorized(&key) {
                return forbidden(&mut s);
            }
            add_decisions(&mut s, ctx, &body)
        }
        ("DELETE", "/v1/decisions") => {
            if !ctx.authorized(&key) {
                return forbidden(&mut s);
            }
            let value = query
                .split('&')
                .find_map(|kv| kv.strip_prefix("value="))
                .map(|v| v.to_string())
                .or_else(|| json::extract_str(&body, "value"))
                .unwrap_or_default();
            delete_decision(&mut s, ctx, &value)
        }
        ("GET", "/v1/bouncers") => {
            if !ctx.authorized(&key) {
                return forbidden(&mut s);
            }
            let mut out = String::from("[");
            for (i, (name, _)) in ctx.bouncers.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str("{\"name\":\"");
                json::json_escape(name, &mut out);
                out.push_str("\"}");
            }
            out.push(']');
            respond(&mut s, 200, "application/json", &out)
        }
        ("POST", "/v1/bouncers") => {
            if !ctx.authorized(&key) {
                return forbidden(&mut s);
            }
            let name = json::extract_str(&body, "name").unwrap_or_else(|| "cslite".to_string());
            let new_key = gen_key();
            ctx.extra_keys.push(new_key.clone());
            ctx.bouncers.push((name.clone(), new_key.clone()));
            let mut out = String::from("{\"name\":\"");
            json::json_escape(&name, &mut out);
            out.push_str("\",\"api_key\":\"");
            out.push_str(&new_key);
            out.push_str("\"}");
            respond(&mut s, 201, "application/json", &out)
        }
        ("POST", "/v1/usage-metrics") => {
            // Optional metrics from bouncers/agents: accept and drop, so clients
            // don't log "not implemented" warnings.
            if ctx.authorized(&key) {
                respond_empty(&mut s, 200)
            } else {
                forbidden(&mut s)
            }
        }
        (_, "/v1/decisions/stream") | (_, "/v1/decisions") | (_, "/v1/bouncers") => {
            respond(
                &mut s,
                405,
                "application/json",
                "{\"message\":\"method not allowed\"}",
            )
        }
        _ => respond(
            &mut s,
            501,
            "application/json",
            "{\"code\":501,\"message\":\"not implemented\"}",
        ),
    }
}

fn forbidden(s: &mut TcpStream) -> io::Result<()> {
    respond(
        s,
        403,
        "application/json",
        "{\"message\":\"access forbidden\"}",
    )
}

fn write_chunk_headers(s: &mut TcpStream) -> io::Result<()> {
    write!(
        s,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
    )
}

fn write_snapshot(s: &mut TcpStream, ctx: &Ctx) -> io::Result<()> {
    let mut st = ctx.store.lock().unwrap_or_else(|p| p.into_inner());
    let now = now_secs();
    st.prune_expired(now);
    write_chunk_headers(s)?;
    let mut cw = ChunkWriter::new(s);
    cw.push(b"{\"new\":[")?;
    let mut first = true;
    for d in st.iter() {
        push_item(&mut cw, &st, d, now, &mut first)?;
    }
    cw.push(b"],\"deleted\":[]}")?;
    cw.finish()
}

fn delta_response(s: &mut TcpStream, ctx: &mut Ctx, key: &str) -> io::Result<()> {
    let cursor = *ctx.cursors.get(key).unwrap_or(&0);
    let now = now_secs();
    let rev;
    {
        let mut st = ctx.store.lock().unwrap_or_else(|p| p.into_inner());
        st.prune_expired(now);
        let (adds, dels) = st.delta_since(cursor);
        write_chunk_headers(s)?;
        let mut cw = ChunkWriter::new(s);
        cw.push(b"{\"new\":[")?;
        let mut first = true;
        for idx in adds {
            if let Some(d) = st.get(idx) {
                push_item(&mut cw, &st, d, now, &mut first)?;
            }
        }
        cw.push(b"],\"deleted\":[")?;
        first = true;
        for idx in dels {
            if let Some(d) = st.get(idx) {
                push_item(&mut cw, &st, d, now, &mut first)?;
            }
        }
        cw.push(b"]}")?;
        cw.finish()?;
        rev = st.current_rev();
    }
    ctx.cursors.insert(key.to_string(), rev);
    Ok(())
}

fn push_item(
    cw: &mut ChunkWriter<'_>,
    st: &Store,
    d: &Decision,
    now: u32,
    first: &mut bool,
) -> io::Result<()> {
    let mut item = String::new();
    if !*first {
        item.push(',');
    }
    *first = false;
    push_decision_json(
        &mut item,
        d,
        st.origin(d.origin_id),
        st.scenario(d.scenario_id),
        now,
    );
    cw.push(item.as_bytes())
}

fn add_decisions(s: &mut TcpStream, ctx: &mut Ctx, body: &[u8]) -> io::Result<()> {
    let now = now_secs();
    let mut added = 0;
    {
        let mut st = ctx.store.lock().unwrap_or_else(|p| p.into_inner());
        // Accept an envelope ({"new":[...]}) or a bare decision object.
        let mut raws = json::parse_stream(body);
        if raws.is_empty() {
            raws = json::parse_objects(body);
        }
        for r in raws {
            if let Some(d) = json::build_decision(&mut st, &r, now) {
                if st.insert(d) {
                    added += 1;
                }
            }
        }
        if added > 0 {
            if let Some(p) = &ctx.persist {
                let _ = st.save_to(p);
            }
        }
    }
    let out = format!("{{\"ok\":true,\"added\":{added}}}");
    respond(s, 200, "application/json", &out)
}

fn delete_decision(s: &mut TcpStream, ctx: &mut Ctx, value: &str) -> io::Result<()> {
    let (addr, prefixlen, family) = match json::parse_value(value) {
        Some(v) => v,
        None => {
            return respond(
                s,
                400,
                "application/json",
                "{\"message\":\"invalid value\"}",
            )
        }
    };
    let scope = if value.contains('/') { 1 } else { 0 };
    let probe = Decision {
        addr,
        id: 0,
        expires_at: 0,
        origin_id: 0,
        scenario_id: 0,
        prefixlen,
        family,
        scope,
        kind: 0,
        _pad: [0; 8],
    };
    let removed = {
        let mut st = ctx.store.lock().unwrap_or_else(|p| p.into_inner());
        let r = st.remove(&probe).is_some();
        if r {
            if let Some(p) = &ctx.persist {
                let _ = st.save_to(p);
            }
        }
        r
    };
    let out = format!("{{\"deleted\":{removed}}}");
    respond(s, 200, "application/json", &out)
}

fn gen_key() -> String {
    use std::fs::File;
    let mut raw = [0u8; 32];
    if let Ok(mut f) = File::open("/dev/urandom") {
        if f.read_exact(&mut raw).is_ok() {
            return b64url(&raw);
        }
    }
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    b64url(&t.to_le_bytes())
}

fn b64url(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | data[i + 2] as u32;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(T[((n >> 6) & 63) as usize] as char);
        out.push(T[(n & 63) as usize] as char);
        i += 3;
    }
    match data.len() - i {
        1 => {
            let n = (data[i] as u32) << 16;
            out.push(T[((n >> 18) & 63) as usize] as char);
            out.push(T[((n >> 12) & 63) as usize] as char);
        }
        2 => {
            let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
            out.push(T[((n >> 18) & 63) as usize] as char);
            out.push(T[((n >> 12) & 63) as usize] as char);
            out.push(T[((n >> 6) & 63) as usize] as char);
        }
        _ => {}
    }
    out
}

fn respond(s: &mut TcpStream, code: u16, ct: &str, body: &str) -> io::Result<()> {
    let reason = match code {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        405 => "Method Not Allowed",
        501 => "Not Implemented",
        _ => "OK",
    };
    write!(
        s,
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    if !body.is_empty() {
        s.write_all(body.as_bytes())?;
    }
    s.flush()
}

fn respond_empty(s: &mut TcpStream, code: u16) -> io::Result<()> {
    let reason = if code == 200 { "OK" } else { "Unauthorized" };
    write!(
        s,
        "HTTP/1.1 {code} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )?;
    s.flush()
}

struct ChunkWriter<'a> {
    s: &'a mut TcpStream,
    buf: Vec<u8>,
}

impl<'a> ChunkWriter<'a> {
    fn new(s: &'a mut TcpStream) -> Self {
        ChunkWriter {
            s,
            buf: Vec::with_capacity(32768),
        }
    }

    fn push(&mut self, data: &[u8]) -> io::Result<()> {
        self.buf.extend_from_slice(data);
        if self.buf.len() >= 32768 {
            self.flush_chunk()?;
        }
        Ok(())
    }

    fn flush_chunk(&mut self) -> io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        write!(self.s, "{:x}\r\n", self.buf.len())?;
        self.s.write_all(&self.buf)?;
        self.s.write_all(b"\r\n")?;
        self.buf.clear();
        Ok(())
    }

    fn finish(&mut self) -> io::Result<()> {
        self.flush_chunk()?;
        self.s.write_all(b"0\r\n\r\n")?;
        self.s.flush()
    }
}
