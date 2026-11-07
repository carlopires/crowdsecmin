//! Decision store (Mode B): 40-byte records + open-addressing index.
//!
//! Mirrors the spec's C struct so the memory model is identical. Deletion keeps
//! record indices stable (a `present` flag), so the revisioned event log can
//! describe both adds and deletes for `startup=false` deltas.
//!
//! Persistence is a compact binary file (`CSL1`) so a restart has no gap.
use std::fs;
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Decision {
    pub addr: [u8; 16],
    pub id: u32,
    pub expires_at: u32,
    pub origin_id: u16,
    pub scenario_id: u16,
    pub prefixlen: u8,
    pub family: u8, // 4 or 6
    pub scope: u8,  // 0 = Ip, 1 = Range
    pub kind: u8,   // 0 = ban
    pub _pad: [u8; 8],
}
const _: () = assert!(std::mem::size_of::<Decision>() == 40);

pub fn now_secs() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

fn hashkey(family: u8, addr: &[u8; 16], prefixlen: u8, scope: u8) -> u32 {
    let mut h: u32 = 2166136261;
    let n = if family == 4 { 4 } else { 16 };
    for &b in &addr[..n] {
        h ^= b as u32;
        h = h.wrapping_mul(16777619);
    }
    h ^= prefixlen as u32;
    h = h.wrapping_mul(16777619);
    h ^= scope as u32;
    h = h.wrapping_mul(16777619);
    h ^= family as u32;
    h
}

#[derive(Clone, Copy)]
enum Event {
    Add(usize),
    Del(usize),
}

pub struct Store {
    decisions: Vec<Decision>,
    present: Vec<bool>,
    slots: Vec<i32>,
    cap: usize,
    alive: usize,
    origins: Vec<String>,
    scenarios: Vec<String>,
    rev: u64,
    events: Vec<(u64, Event)>,
}

impl Default for Store {
    fn default() -> Self {
        Store::new()
    }
}

impl Store {
    pub fn new() -> Self {
        let cap = 32768usize;
        Store {
            decisions: Vec::with_capacity(16384),
            present: Vec::with_capacity(16384),
            slots: vec![0i32; cap],
            cap,
            alive: 0,
            origins: Vec::new(),
            scenarios: Vec::new(),
            rev: 0,
            events: Vec::new(),
        }
    }

    pub fn intern_origin(&mut self, s: &str) -> u16 {
        if let Some(i) = self.origins.iter().position(|e| e == s) {
            return i as u16;
        }
        self.origins.push(s.to_string());
        (self.origins.len() - 1) as u16
    }

    pub fn intern_scenario(&mut self, s: &str) -> u16 {
        if let Some(i) = self.scenarios.iter().position(|e| e == s) {
            return i as u16;
        }
        self.scenarios.push(s.to_string());
        (self.scenarios.len() - 1) as u16
    }

    pub fn origin(&self, id: u16) -> &str {
        self.origins.get(id as usize).map(String::as_str).unwrap_or("")
    }

    pub fn scenario(&self, id: u16) -> &str {
        self.scenarios.get(id as usize).map(String::as_str).unwrap_or("")
    }

    fn slot_of(&self, d: &Decision) -> usize {
        (hashkey(d.family, &d.addr, d.prefixlen, d.scope) as usize) & (self.cap - 1)
    }

    fn find_slot(&self, d: &Decision) -> Option<usize> {
        let mut h = self.slot_of(d);
        loop {
            let s = self.slots[h];
            if s == 0 {
                return None;
            }
            let idx = (s - 1) as usize;
            if self.present[idx] {
                let e = &self.decisions[idx];
                if e.family == d.family
                    && e.prefixlen == d.prefixlen
                    && e.scope == d.scope
                    && e.addr == d.addr
                {
                    return Some(idx);
                }
            }
            h = (h + 1) & (self.cap - 1);
        }
    }

    fn place_slot(&mut self, idx: usize) {
        let d = self.decisions[idx];
        let mut h = self.slot_of(&d);
        while self.slots[h] != 0 {
            h = (h + 1) & (self.cap - 1);
        }
        self.slots[h] = idx as i32 + 1;
    }

    /// Insert; returns false if an equal (present) key already exists.
    pub fn insert(&mut self, d: Decision) -> bool {
        if self.find_slot(&d).is_some() {
            return false;
        }
        let idx = self.decisions.len();
        self.decisions.push(d);
        self.present.push(true);
        self.alive += 1;
        self.place_slot(idx);
        self.rev += 1;
        self.events.push((self.rev, Event::Add(idx)));
        true
    }

    /// Remove by key; returns the removed index if it was present.
    pub fn remove(&mut self, d: &Decision) -> Option<usize> {
        let idx = self.find_slot(d)?;
        self.present[idx] = false;
        self.alive = self.alive.saturating_sub(1);
        self.rev += 1;
        self.events.push((self.rev, Event::Del(idx)));
        Some(idx)
    }

    /// Remove decisions whose expiry has passed; emits delete events so
    /// clients/bouncers converge. Returns how many were pruned.
    pub fn prune_expired(&mut self, now: u32) -> usize {
        let mut n = 0usize;
        for idx in 0..self.decisions.len() {
            if self.present[idx] && self.decisions[idx].expires_at <= now {
                self.present[idx] = false;
                self.alive = self.alive.saturating_sub(1);
                self.rev += 1;
                self.events.push((self.rev, Event::Del(idx)));
                n += 1;
            }
        }
        n
    }

    pub fn len(&self) -> usize {
        self.alive
    }

    pub fn is_empty(&self) -> bool {
        self.alive == 0
    }

    pub fn current_rev(&self) -> u64 {
        self.rev
    }

    pub fn iter(&self) -> impl Iterator<Item = &Decision> {
        self.decisions
            .iter()
            .enumerate()
            .filter(move |(i, _)| self.present[*i])
            .map(|(_, d)| d)
    }

    pub fn get(&self, idx: usize) -> Option<&Decision> {
        self.decisions.get(idx)
    }

    /// (added indices, deleted indices) with revision > cursor.
    pub fn delta_since(&self, cursor: u64) -> (Vec<usize>, Vec<usize>) {
        let mut adds = Vec::new();
        let mut dels = Vec::new();
        for (rev, ev) in &self.events {
            if *rev > cursor {
                match ev {
                    Event::Add(i) => adds.push(*i),
                    Event::Del(i) => dels.push(*i),
                }
            }
        }
        (adds, dels)
    }

    // ---- persistence -----------------------------------------------------

    pub fn save_to(&self, path: &Path) -> io::Result<()> {
        let mut out = Vec::with_capacity(64 + self.decisions.len() * 41);
        out.extend_from_slice(b"CSL1");
        out.extend_from_slice(&(self.origins.len() as u32).to_le_bytes());
        for s in &self.origins {
            out.extend_from_slice(&(s.len() as u16).to_le_bytes());
            out.extend_from_slice(s.as_bytes());
        }
        out.extend_from_slice(&(self.scenarios.len() as u32).to_le_bytes());
        for s in &self.scenarios {
            out.extend_from_slice(&(s.len() as u16).to_le_bytes());
            out.extend_from_slice(s.as_bytes());
        }
        out.extend_from_slice(&self.rev.to_le_bytes());
        out.extend_from_slice(&(self.decisions.len() as u32).to_le_bytes());
        for (i, d) in self.decisions.iter().enumerate() {
            let b = unsafe_free_bytes(d);
            out.extend_from_slice(&b);
            out.push(self.present[i] as u8);
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, out)
    }

    pub fn load_from(path: &Path) -> io::Result<Store> {
        let data = fs::read(path)?;
        if data.len() < 4 || &data[..4] != b"CSL1" {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad magic"));
        }
        let mut p = 4usize;
        let rd_u16 = |p: &mut usize| -> io::Result<u16> {
            if *p + 2 > data.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated"));
            }
            let v = u16::from_le_bytes([data[*p], data[*p + 1]]);
            *p += 2;
            Ok(v)
        };
        let rd_u32 = |p: &mut usize| -> io::Result<u32> {
            if *p + 4 > data.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated"));
            }
            let v = u32::from_le_bytes([data[*p], data[*p + 1], data[*p + 2], data[*p + 3]]);
            *p += 4;
            Ok(v)
        };
        let rd_u64 = |p: &mut usize| -> io::Result<u64> {
            if *p + 8 > data.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated"));
            }
            let mut b = [0u8; 8];
            b.copy_from_slice(&data[*p..*p + 8]);
            *p += 8;
            Ok(u64::from_le_bytes(b))
        };
        let mut origins = Vec::new();
        let no = rd_u32(&mut p)?;
        for _ in 0..no {
            let l = rd_u16(&mut p)? as usize;
            if p + l > data.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated"));
            }
            origins.push(String::from_utf8_lossy(&data[p..p + l]).to_string());
            p += l;
        }
        let mut scenarios = Vec::new();
        let ns = rd_u32(&mut p)?;
        for _ in 0..ns {
            let l = rd_u16(&mut p)? as usize;
            if p + l > data.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated"));
            }
            scenarios.push(String::from_utf8_lossy(&data[p..p + l]).to_string());
            p += l;
        }
        let rev = rd_u64(&mut p)?;
        let nd = rd_u32(&mut p)? as usize;
        let mut s = Store::new();
        s.origins = origins;
        s.scenarios = scenarios;
        for _ in 0..nd {
            if p + 41 > data.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated"));
            }
            let d = bytes_to_decision(&data[p..p + 40]);
            let present = data[p + 40] != 0;
            p += 41;
            let idx = s.decisions.len();
            s.decisions.push(d);
            s.present.push(present);
            if present {
                s.alive += 1;
                s.place_slot(idx);
            }
        }
        s.rev = rev;
        Ok(s)
    }
}

// Bind a `Decision` to bytes without `unsafe`: field-by-field LE encoding.
fn unsafe_free_bytes(d: &Decision) -> [u8; 40] {
    let mut b = [0u8; 40];
    b[0..16].copy_from_slice(&d.addr);
    b[16..20].copy_from_slice(&d.id.to_le_bytes());
    b[20..24].copy_from_slice(&d.expires_at.to_le_bytes());
    b[24..26].copy_from_slice(&d.origin_id.to_le_bytes());
    b[26..28].copy_from_slice(&d.scenario_id.to_le_bytes());
    b[28] = d.prefixlen;
    b[29] = d.family;
    b[30] = d.scope;
    b[31] = d.kind;
    b
}

fn bytes_to_decision(b: &[u8]) -> Decision {
    let mut addr = [0u8; 16];
    addr.copy_from_slice(&b[0..16]);
    Decision {
        addr,
        id: u32::from_le_bytes([b[16], b[17], b[18], b[19]]),
        expires_at: u32::from_le_bytes([b[20], b[21], b[22], b[23]]),
        origin_id: u16::from_le_bytes([b[24], b[25]]),
        scenario_id: u16::from_le_bytes([b[26], b[27]]),
        prefixlen: b[28],
        family: b[29],
        scope: b[30],
        kind: b[31],
        _pad: [0; 8],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dec(a: [u8; 4], plen: u8) -> Decision {
        let mut addr = [0u8; 16];
        addr[..4].copy_from_slice(&a);
        Decision {
            addr,
            id: 1,
            expires_at: 0,
            origin_id: 0,
            scenario_id: 0,
            prefixlen: plen,
            family: 4,
            scope: 0,
            kind: 0,
            _pad: [0; 8],
        }
    }

    #[test]
    fn insert_dedup_delta_remove() {
        let mut s = Store::new();
        assert!(s.insert(dec([1, 2, 3, 4], 32)));
        assert!(!s.insert(dec([1, 2, 3, 4], 32)));
        assert_eq!(s.len(), 1);
        let (a, d) = s.delta_since(0);
        assert_eq!((a.len(), d.len()), (1, 0));
        let cur = s.current_rev();
        assert_eq!(s.remove(&dec([1, 2, 3, 4], 32)).is_some(), true);
        assert_eq!(s.len(), 0);
        let (a, d) = s.delta_since(cur);
        assert_eq!((a.len(), d.len()), (0, 1));
    }

    #[test]
    fn persistence_roundtrip() {
        let mut s = Store::new();
        let o = s.intern_origin("CAPI");
        let sc = s.intern_scenario("ssh:bf");
        let mut d = dec([9, 9, 9, 9], 24);
        d.origin_id = o;
        d.scenario_id = sc;
        s.insert(d);
        let path = std::env::temp_dir().join(format!("cslite-store-{}.bin", std::process::id()));
        s.save_to(&path).unwrap();
        let t = Store::load_from(&path).unwrap();
        assert_eq!(t.len(), 1);
        assert_eq!(t.origin(0), "CAPI");
        assert_eq!(t.get(0).unwrap().prefixlen, 24);
        let _ = fs::remove_file(&path);
    }
}
