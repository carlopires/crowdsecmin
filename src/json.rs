//! Wire JSON: parse `/v1/decisions/stream` payloads and serialize decisions.
//!
//! No JSON library: the input shapes are fixed (the spec's "3 known shapes"),
//! so a small scanner extracts the decision objects directly. Output is
//! byte-compatible with the fields/order the Go bouncer expects (spec §6.3).
use crate::store::{Decision, Store};
use std::net::IpAddr;

fn find_sub(h: &[u8], n: &[u8], from: usize) -> Option<usize> {
    if n.is_empty() || h.len() < n.len() || from > h.len() - n.len() {
        return None;
    }
    let last = h.len() - n.len();
    let mut i = from;
    while i <= last {
        if &h[i..i + n.len()] == n {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn obj_str<'a>(o: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let p = find_sub(o, key, 0)?;
    let mut i = p + key.len();
    while i < o.len() && o[i] != b':' {
        i += 1;
    }
    i += 1;
    while i < o.len() && (o[i] == b' ' || o[i] == b'\t') {
        i += 1;
    }
    if i >= o.len() || o[i] != b'"' {
        return None;
    }
    i += 1;
    let s = i;
    while i < o.len() && o[i] != b'"' {
        i += 1;
    }
    Some(&o[s..i])
}

fn obj_int(o: &[u8], key: &[u8]) -> Option<u64> {
    let p = find_sub(o, key, 0)?;
    let mut i = p + key.len();
    while i < o.len() && o[i] != b':' {
        i += 1;
    }
    i += 1;
    while i < o.len() && (o[i] == b' ' || o[i] == b'\t') {
        i += 1;
    }
    let mut v: u64 = 0;
    while i < o.len() && o[i].is_ascii_digit() {
        v = v.wrapping_mul(10).wrapping_add((o[i] - b'0') as u64);
        i += 1;
    }
    Some(v)
}

/// Go duration subset `[Nh][Nm][Ns]` -> seconds (round up to >= 1s).
pub fn parse_duration(s: &[u8]) -> u32 {
    let mut v: u64 = 0;
    let mut cur: u64 = 0;
    for &c in s {
        if c.is_ascii_digit() {
            cur = cur * 10 + (c - b'0') as u64;
        } else if c == b'h' {
            v += cur * 3600;
            cur = 0;
        } else if c == b'm' {
            v += cur * 60;
            cur = 0;
        } else if c == b's' {
            v += cur;
            cur = 0;
        }
    }
    (v as u32).max(1)
}

/// Format seconds as a Go duration string (`HhMmSs`, zero parts omitted).
pub fn format_duration(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    let mut out = String::new();
    if h > 0 {
        out.push_str(&format!("{h}h"));
    }
    if m > 0 {
        out.push_str(&format!("{m}m"));
    }
    if s > 0 || out.is_empty() {
        out.push_str(&format!("{s}s"));
    }
    out
}

/// Escape a string for a JSON value.
pub fn json_escape(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
}

/// Parse an IP or CIDR into (addr, prefixlen, family 4|6).
pub fn parse_value(val: &str) -> Option<([u8; 16], u8, u8)> {
    let (ip_s, plen_s) = match val.split_once('/') {
        Some((a, b)) => (a, Some(b)),
        None => (val, None),
    };
    let ip: IpAddr = ip_s.parse().ok()?;
    let mut addr = [0u8; 16];
    match ip {
        IpAddr::V4(v) => {
            addr[..4].copy_from_slice(&v.octets());
            let plen = match plen_s {
                Some(p) => p.parse::<u8>().ok()?,
                None => 32,
            };
            if plen > 32 {
                return None;
            }
            Some((addr, plen, 4))
        }
        IpAddr::V6(v) => {
            addr.copy_from_slice(&v.octets());
            let plen = match plen_s {
                Some(p) => p.parse::<u8>().ok()?,
                None => 128,
            };
            if plen > 128 {
                return None;
            }
            Some((addr, plen, 6))
        }
    }
}

/// Reconstruct the wire `value` string from an address + prefix.
pub fn value_string(d: &Decision) -> String {
    if d.family == 4 {
        let mut s = format!("{}.{}.{}.{}", d.addr[0], d.addr[1], d.addr[2], d.addr[3]);
        if d.prefixlen < 32 {
            s.push_str(&format!("/{}", d.prefixlen));
        }
        s
    } else {
        let mut s = std::net::Ipv6Addr::from(d.addr).to_string();
        if d.prefixlen < 128 {
            s.push_str(&format!("/{}", d.prefixlen));
        }
        s
    }
}

/// Serialize one decision object (exact field set/order from spec §6.3).
pub fn push_decision_json(
    out: &mut String,
    d: &Decision,
    origin: &str,
    scenario: &str,
    now: u32,
) {
    let remaining = d.expires_at.saturating_sub(now).max(1) as u64;
    out.push_str("{\"duration\":\"");
    out.push_str(&format_duration(remaining));
    out.push_str("\",\"id\":");
    out.push_str(&d.id.to_string());
    out.push_str(",\"origin\":\"");
    json_escape(origin, out);
    out.push_str("\",\"scenario\":\"");
    json_escape(scenario, out);
    out.push_str("\",\"scope\":\"");
    out.push_str(if d.scope == 1 { "Range" } else { "Ip" });
    out.push_str("\",\"type\":\"ban\",\"value\":\"");
    out.push_str(&value_string(d));
    out.push_str("\"}");
}

pub struct RawDecision {
    pub duration: u32,
    pub id: u32,
    pub origin: String,
    pub scenario: String,
    pub scope: u8,
    pub typ: String,
    pub value: String,
}

impl RawDecision {
    pub fn scope_str(&self) -> &'static str {
        if self.scope == 1 { "Range" } else { "Ip" }
    }
}

/// Scan a byte slice for decision objects.
fn scan_objects(slice: &[u8]) -> Vec<RawDecision> {
    let mut out = Vec::new();
    let mut p = 0;
    while p < slice.len() {
        let ob = match find_sub(slice, b"{", p) {
            Some(i) => i,
            None => break,
        };
        let oe = match find_sub(slice, b"}", ob) {
            Some(i) => i,
            None => break,
        };
        let obj = &slice[ob..oe];
        if let Some(value) = obj_str(obj, b"\"value\"") {
            let bstr = |k: &[u8]| {
                obj_str(obj, k)
                    .map(|s| String::from_utf8_lossy(s).to_string())
                    .unwrap_or_default()
            };
            out.push(RawDecision {
                duration: parse_duration(obj_str(obj, b"\"duration\"").unwrap_or(b"")),
                id: obj_int(obj, b"\"id\"").unwrap_or(0) as u32,
                origin: bstr(b"\"origin\""),
                scenario: bstr(b"\"scenario\""),
                scope: if bstr(b"\"scope\"") == "Range" { 1 } else { 0 },
                typ: bstr(b"\"type\""),
                value: String::from_utf8_lossy(value).to_string(),
            });
        }
        p = oe + 1;
    }
    out
}

/// Parse decision objects inside the array that follows `marker` (e.g. "new").
fn parse_array(bytes: &[u8], marker: &[u8]) -> Vec<RawDecision> {
    let start = match find_sub(bytes, marker, 0) {
        Some(i) => i,
        None => return Vec::new(),
    };
    let lb = match find_sub(bytes, b"[", start) {
        Some(i) => i,
        None => return Vec::new(),
    };
    let rb = find_sub(bytes, b"]", lb).unwrap_or(bytes.len());
    scan_objects(&bytes[lb..rb])
}

/// Parse decision objects from an arbitrary body (bare object, array, or envelope).
pub fn parse_objects(bytes: &[u8]) -> Vec<RawDecision> {
    scan_objects(bytes)
}

/// Extract `"new"` decisions from a stream payload.
pub fn parse_stream(bytes: &[u8]) -> Vec<RawDecision> {
    parse_array(bytes, b"\"new\"")
}

/// Extract `"deleted"` decisions from a stream payload.
pub fn parse_deleted(bytes: &[u8]) -> Vec<RawDecision> {
    parse_array(bytes, b"\"deleted\"")
}

// ---- CAPI v3 grouped format ------------------------------------------------
// {"new":[{"scope":"ip","scenario":"...","decisions":[{"value":..,"duration":..}]}],
//  "deleted":[{"scope":"ip","decisions":["1.2.3.4", ...]}]}

fn matching(b: &[u8], start: usize, open: u8, close: u8) -> Option<usize> {
    let mut depth: i32 = 0;
    let mut in_str = false;
    let mut esc = false;
    for (i, &c) in b.iter().enumerate().skip(start) {
        if in_str {
            if esc {
                esc = false;
            } else if c == b'\\' {
                esc = true;
            } else if c == b'"' {
                in_str = false;
            }
            continue;
        }
        match c {
            b'"' => in_str = true,
            x if x == open => depth += 1,
            x if x == close => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

fn key_array<'a>(b: &'a [u8], key: &str) -> Option<&'a [u8]> {
    let k = format!("\"{key}\"");
    let p = find_sub(b, k.as_bytes(), 0)?;
    let lb = find_sub(b, b"[", p)?;
    let rb = matching(b, lb, b'[', b']')?;
    Some(&b[lb + 1..rb])
}

fn trim_bytes(mut s: &[u8]) -> &[u8] {
    while let Some((&c, rest)) = s.split_first() {
        if c.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    while let Some((&c, rest)) = s.split_last() {
        if c.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    s
}

fn split_top(slice: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut depth: i32 = 0;
    let mut in_str = false;
    let mut esc = false;
    for (i, &c) in slice.iter().enumerate() {
        if in_str {
            if esc {
                esc = false;
            } else if c == b'\\' {
                esc = true;
            } else if c == b'"' {
                in_str = false;
            }
            continue;
        }
        match c {
            b'"' => in_str = true,
            b'{' | b'[' => depth += 1,
            b'}' | b']' => depth -= 1,
            b',' if depth == 0 => {
                out.push(trim_bytes(&slice[start..i]));
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(trim_bytes(&slice[start..]));
    out.into_iter().filter(|s| !s.is_empty()).collect()
}

fn unquote_bytes(s: &[u8]) -> String {
    let t = trim_bytes(s);
    if t.len() >= 2 && t[0] == b'"' && t[t.len() - 1] == b'"' {
        String::from_utf8_lossy(&t[1..t.len() - 1]).to_string()
    } else {
        String::from_utf8_lossy(t).to_string()
    }
}

/// Parse the CAPI v3 grouped stream into (new, deleted) decisions.
pub fn parse_capi_v3(bytes: &[u8]) -> (Vec<RawDecision>, Vec<RawDecision>) {
    let mut newv = Vec::new();
    let mut delv = Vec::new();
    let mut id: u32 = 1;

    if let Some(arr) = key_array(bytes, "new") {
        for group in split_top(arr) {
            if group.first() != Some(&b'{') {
                continue;
            }
            let scope = obj_str(group, b"\"scope\"")
                .map(|s| String::from_utf8_lossy(s).to_ascii_lowercase())
                .unwrap_or_else(|| "ip".to_string());
            let sc = if scope == "range" { 1 } else { 0 };
            let scenario = obj_str(group, b"\"scenario\"")
                .map(|s| String::from_utf8_lossy(s).to_string())
                .unwrap_or_default();
            if let Some(ds) = key_array(group, "decisions") {
                for d in split_top(ds) {
                    if d.first() != Some(&b'{') {
                        continue;
                    }
                    if let Some(value) = obj_str(d, b"\"value\"") {
                        newv.push(RawDecision {
                            duration: parse_duration(
                                obj_str(d, b"\"duration\"").unwrap_or(b""),
                            ),
                            id,
                            origin: "CAPI".to_string(),
                            scenario: scenario.clone(),
                            scope: sc,
                            typ: "ban".to_string(),
                            value: String::from_utf8_lossy(value).to_string(),
                        });
                        id += 1;
                    }
                }
            }
        }
    }

    if let Some(arr) = key_array(bytes, "deleted") {
        for group in split_top(arr) {
            if group.first() != Some(&b'{') {
                continue;
            }
            let scope = obj_str(group, b"\"scope\"")
                .map(|s| String::from_utf8_lossy(s).to_ascii_lowercase())
                .unwrap_or_else(|| "ip".to_string());
            let sc = if scope == "range" { 1 } else { 0 };
            if let Some(ds) = key_array(group, "decisions") {
                for d in split_top(ds) {
                    if d.first() == Some(&b'"') {
                        delv.push(RawDecision {
                            duration: 0,
                            id: 0,
                            origin: "CAPI".to_string(),
                            scenario: String::new(),
                            scope: sc,
                            typ: "ban".to_string(),
                            value: unquote_bytes(d),
                        });
                    }
                }
            }
        }
    }
    (newv, delv)
}

/// Build a store `Decision` from a parsed wire decision.
pub fn build_decision(store: &mut Store, r: &RawDecision, now: u32) -> Option<Decision> {
    if r.typ != "ban" {
        return None;
    }
    let (addr, prefixlen, family) = parse_value(&r.value)?;
    Some(Decision {
        addr,
        id: r.id,
        expires_at: now.saturating_add(r.duration),
        origin_id: store.intern_origin(&r.origin),
        scenario_id: store.intern_scenario(&r.scenario),
        prefixlen,
        family,
        scope: r.scope,
        kind: 0,
        _pad: [0; 8],
    })
}

/// Extract a string field from a JSON-ish body (used by admin endpoints).
pub fn extract_str(bytes: &[u8], key: &str) -> Option<String> {
    let k = format!("\"{key}\"");
    obj_str(bytes, k.as_bytes()).map(|s| String::from_utf8_lossy(s).to_string())
}

/// Build a decision from an explicit origin/scenario/value/duration.
pub fn build_decision_for(
    store: &mut Store,
    origin: &str,
    scenario: &str,
    value: &str,
    duration_secs: u32,
    now: u32,
) -> Option<Decision> {
    let (addr, prefixlen, family) = parse_value(value)?;
    let scope = if value.contains('/') { 1 } else { 0 };
    Some(Decision {
        addr,
        id: now,
        expires_at: now.saturating_add(duration_secs),
        origin_id: store.intern_origin(origin),
        scenario_id: store.intern_scenario(scenario),
        prefixlen,
        family,
        scope,
        kind: 0,
        _pad: [0; 8],
    })
}

/// Parse a stream payload into the store; returns the number inserted.
pub fn load_into(store: &mut Store, bytes: &[u8], now: u32) -> usize {
    let mut added = 0;
    for r in parse_stream(bytes) {
        if let Some(d) = build_decision(store, &r, now) {
            if store.insert(d) {
                added += 1;
            }
        }
    }
    added
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_roundtrip() {
        assert_eq!(format_duration(144843), "40h14m3s");
        assert_eq!(format_duration(875), "14m35s");
        assert_eq!(format_duration(45), "45s");
        assert_eq!(format_duration(7037), "1h57m17s");
        assert_eq!(parse_duration(b"40h14m3s"), 144843);
        assert_eq!(parse_duration(b"45s"), 45);
    }

    #[test]
    fn parses_and_reloads() {
        let payload = br#"{"new":[{"duration":"40h14m3s","id":7,"origin":"CAPI","scenario":"ssh:bruteforce","scope":"Range","type":"ban","value":"1.2.3.0/24"},{"duration":"5m","id":8,"origin":"crowdsec","scenario":"ssh:bf","scope":"Ip","type":"ban","value":"2001:db8::1"}],"deleted":[]}"#;
        let mut s = Store::new();
        assert_eq!(load_into(&mut s, payload, 1000), 2);
        let mut out = String::new();
        let d0 = s.get(0).unwrap();
        push_decision_json(&mut out, d0, s.origin(d0.origin_id), s.scenario(d0.scenario_id), 1000);
        assert!(out.contains("\"duration\":\"40h14m3s\""));
        assert!(out.contains("\"scope\":\"Range\""));
        assert!(out.contains("\"value\":\"1.2.3.0/24\""));
        let d1 = s.get(1).unwrap();
        assert_eq!(value_string(d1), "2001:db8::1");
    }

    #[test]
    fn rejects_bad_values() {
        assert!(parse_value("1.2.3.4/33").is_none());
        assert!(parse_value("nope").is_none());
        assert_eq!(parse_value("1.2.3.4").unwrap().2, 4);
        assert_eq!(parse_value("2001:db8::/32").unwrap().2, 6);
    }

    #[test]
    fn parses_capi_v3_grouped() {
        let payload = br#"{"new":[{"scope":"ip","scenario":"ssh:bruteforce","decisions":[{"value":"1.2.3.4","duration":"164h"},{"value":"5.6.7.8","duration":"1h"}]},{"scope":"range","scenario":"x","decisions":[{"value":"10.0.0.0/24","duration":"2h"}]}],"deleted":[{"scope":"ip","decisions":["9.9.9.9"]}]}"#;
        let (n, d) = parse_capi_v3(payload);
        assert_eq!(n.len(), 3);
        assert_eq!(n[0].origin, "CAPI");
        assert_eq!(n[0].scope, 0);
        assert_eq!(n[2].scope, 1);
        assert_eq!(parse_duration(b"164h"), 590400);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].value, "9.9.9.9");
        assert_eq!(d[0].scope, 0);
    }
}
