// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

//! Encrypted UDP telemetry.
//!
//! Packet = `Magic "PL"(2) ++ KeyHint(4) ++ Nonce(12)` (the 18-byte cleartext
//! header, also used as AEAD associated data) followed by
//! `ChaCha20-Poly1305( SeqNum(4) ++ Level(1) ++ PayloadLen(2) ++ Payload )`.
//! Key = `SHA-256(UUID)`, KeyHint = `SHA-256(UUID)[0:4]`, Nonce =
//! `sessionID(8) ++ seq(4 BE)`.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use domain::base::iana::Rtype;
use domain::base::rdata::ComposeRecordData;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use crate::dns::OwnedRecord;

const MAGIC0: u8 = 0x50; // 'P'
const MAGIC1: u8 = 0x4C; // 'L'
const HEADER_SIZE: usize = 18;
const AEAD_OVERHEAD: usize = 16;
const INNER_HEADER_SIZE: usize = 7;
const MAX_PACKET_SIZE: usize = 1400;
const MAX_INNER_PAYLOAD: usize = MAX_PACKET_SIZE - HEADER_SIZE - AEAD_OVERHEAD - INNER_HEADER_SIZE;
const FLAG_IPV6: u8 = 1;
const CHANNEL_SIZE: usize = 4096;
const WRITE_TIMEOUT: Duration = Duration::from_millis(100);
pub const SEVERITY_INFO: u8 = 1;
pub const SEVERITY_WARN: u8 = 2;

// Route bytes.
pub const ROUTE_CACHE: u8 = 0;
pub const ROUTE_LOCAL: u8 = 1;
pub const ROUTE_FALL: u8 = 2;
pub const ROUTE_HOSTS: u8 = 3;
pub const ROUTE_FORCE_FALL: u8 = 4;
pub const ROUTE_HOOK_FALL: u8 = 5;
// Custom rcode bytes (outside the standard 0-23 range).
pub const RCODE_TIMEOUT: u8 = 0xFE;
pub const RCODE_NODATA: u8 = 0xFF;

/// Parse a UUID string (hyphens optional) into 16 bytes.
pub fn parse_uuid(s: &str) -> Option<[u8; 16]> {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    // len() counts bytes and the loop below slices by byte index, so non-ASCII
    // input of the right byte length would slice mid-character and panic.
    if hex.len() != 32 || !hex.is_ascii() {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// A query telemetry entry (levels 1-4).
pub struct QueryEntry<'a> {
    pub client: IpAddr,
    pub qtype: u16,
    pub rcode: u8,
    pub route: u8,
    pub duration_ms: u16,
    pub query_name: &'a str,
    pub upstream: &'a str,
    pub answers: &'a [OwnedRecord],
    pub additional: &'a [OwnedRecord],
}

/// Clamp a duration to the `u16` millisecond field.
pub fn dur_to_ms(d: Duration) -> u16 {
    d.as_millis().min(0xFFFF) as u16
}

/// Mutable session state guarded by the lock: just the nonce inputs. Kept tiny
/// so the lock is held only long enough to reserve a unique (session_id, seq)
/// nonce — AEAD sealing happens outside the lock.
struct Session {
    session_id: [u8; 8],
    seq: u32,
}

pub struct Config {
    pub uuid: String,
    pub server: String,
    pub level: i64,
    pub heartbeat: i64,
}

/// Best-effort encrypted UDP reporter.
pub struct Reporter {
    level: u8,
    // Immutable after construction → shared without locking. `ChaCha20Poly1305`
    // is `Sync` and `encrypt` is a pure function of (key, nonce, plaintext), so
    // sealing runs concurrently outside the session lock.
    cipher: ChaCha20Poly1305,
    key_hint: [u8; 4],
    session: Mutex<Session>,
    tx: mpsc::Sender<Vec<u8>>,
    // Unix time (seconds) of the last report; u32 for 32-bit MIPS (no 64-bit
    // atomics). Second granularity is fine for the heartbeat's liveness check.
    last_report: AtomicU32,
    heartbeat_secs: i64,
}

impl Reporter {
    /// Build a reporter and start its sender (and heartbeat) tasks. Returns None
    /// if the config is incomplete/invalid or the socket can't be set up.
    pub async fn new(cfg: Config) -> Option<Arc<Reporter>> {
        if cfg.server.is_empty() || cfg.uuid.is_empty() {
            return None;
        }
        if !(1..=5).contains(&cfg.level) {
            eprintln!("pplog: level must be 1-5, got {}", cfg.level);
            return None;
        }
        let uuid = parse_uuid(&cfg.uuid).or_else(|| {
            eprintln!("pplog: invalid UUID");
            None
        })?;
        let hash = Sha256::digest(uuid);
        let cipher = ChaCha20Poly1305::new_from_slice(&hash).ok()?;
        let mut key_hint = [0u8; 4];
        key_hint.copy_from_slice(&hash[..4]);

        // Match the socket family to the server (v6 literal → bind [::]).
        let bind = match cfg.server.parse::<SocketAddr>() {
            Ok(SocketAddr::V6(_)) => "[::]:0",
            _ => "0.0.0.0:0",
        };
        let sock = tokio::net::UdpSocket::bind(bind).await.ok()?;
        sock.connect(&cfg.server).await.ok()?;

        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(CHANNEL_SIZE);
        tokio::spawn(async move {
            while let Some(pkt) = rx.recv().await {
                let _ = tokio::time::timeout(WRITE_TIMEOUT, sock.send(&pkt)).await;
            }
        });

        let reporter = Arc::new(Reporter {
            level: cfg.level as u8,
            cipher,
            key_hint,
            session: Mutex::new(Session {
                session_id: random8(),
                seq: 0,
            }),
            tx,
            last_report: AtomicU32::new(0),
            heartbeat_secs: cfg.heartbeat.max(0),
        });

        if reporter.heartbeat_secs > 0 && reporter.level >= 2 {
            let r = reporter.clone();
            tokio::spawn(async move { r.heartbeat_loop().await });
        }
        Some(reporter)
    }

    pub fn level(&self) -> u8 {
        self.level
    }

    /// Report a query entry (non-blocking; dropped if the channel is full).
    pub fn report(&self, entry: &QueryEntry) {
        let ts = now_secs();
        self.last_report.store(ts, Ordering::Relaxed);
        // Query entries max out at level 4 even when configured level is 5.
        let level = self.level.min(4);
        let payload = if level >= 3 {
            encode::fit_payload(entry, level, ts)
        } else {
            encode::encode_query(entry, level, ts)
        };
        self.seal_and_send(level, &payload);
    }

    /// Report a level-5 event (heartbeat, hook transitions, …). Sent only when
    /// the configured level is >= 2.
    pub fn report_event(&self, severity: u8, msg: &str) {
        if self.level < 2 {
            return;
        }
        let payload = encode::encode_event(severity, msg, now_secs());
        self.seal_and_send(5, &payload);
    }

    fn seal_and_send(&self, level: u8, payload: &[u8]) {
        // Hold the lock only to reserve a unique nonce (session_id, seq); the
        // AEAD sealing below runs lock-free. seq is monotonic under the lock and
        // the session id rotates atomically with the wrap, so the nonce never
        // repeats.
        let (session_id, seq) = {
            let mut s = self.session.lock().unwrap();
            s.seq = s.seq.wrapping_add(1);
            if s.seq == 0 {
                // seq wrapped: new session id so the nonce never repeats.
                s.session_id = random8();
                s.seq = 1;
            }
            (s.session_id, s.seq)
        };

        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&session_id);
        nonce[8..].copy_from_slice(&seq.to_be_bytes());

        let mut header = [0u8; HEADER_SIZE];
        header[0] = MAGIC0;
        header[1] = MAGIC1;
        header[2..6].copy_from_slice(&self.key_hint);
        header[6..18].copy_from_slice(&nonce);

        let mut inner = Vec::with_capacity(INNER_HEADER_SIZE + payload.len());
        inner.extend_from_slice(&seq.to_be_bytes());
        inner.push(level);
        inner.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        inner.extend_from_slice(payload);

        let ct = match self.cipher.encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &inner,
                aad: &header,
            },
        ) {
            Ok(c) => c,
            Err(_) => return,
        };

        let mut pkt = Vec::with_capacity(HEADER_SIZE + ct.len());
        pkt.extend_from_slice(&header);
        pkt.extend_from_slice(&ct);
        let _ = self.tx.try_send(pkt);
    }

    async fn heartbeat_loop(self: Arc<Self>) {
        let interval = Duration::from_secs(self.heartbeat_secs as u64);
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let msg = format!("[pplog] heart_beat={}", self.heartbeat_secs);
        loop {
            tick.tick().await;
            // Skip if a real report already proved liveness this interval.
            let last = self.last_report.load(Ordering::Relaxed);
            let now = now_secs();
            if last > 0 && now >= last && (now - last) < self.heartbeat_secs as u32 {
                continue;
            }
            self.report_event(SEVERITY_INFO, &msg);
        }
    }
}

fn random8() -> [u8; 8] {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).expect("getrandom");
    b
}

fn now_secs() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

mod encode {
    use super::*;

    /// Encode a query entry at the given level.
    pub fn encode_query(e: &QueryEntry, level: u8, ts: u32) -> Vec<u8> {
        let ans: Vec<&OwnedRecord> = e.answers.iter().collect();
        let add: Vec<&OwnedRecord> = e.additional.iter().collect();
        encode_query_with(e, &ans, &add, level, ts)
    }

    fn encode_query_with(
        e: &QueryEntry,
        answers: &[&OwnedRecord],
        additional: &[&OwnedRecord],
        level: u8,
        ts: u32,
    ) -> Vec<u8> {
        let mut b = Vec::with_capacity(64);
        b.extend_from_slice(&ts.to_be_bytes());

        // flags + client IP (4 or 16 bytes)
        let (is_v6, ip_bytes): (bool, Vec<u8>) = match e.client {
            IpAddr::V4(v4) => (false, v4.octets().to_vec()),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => (false, v4.octets().to_vec()),
                None => (true, v6.octets().to_vec()),
            },
        };
        b.push(if is_v6 { FLAG_IPV6 } else { 0 });
        b.extend_from_slice(&ip_bytes);

        b.extend_from_slice(&e.qtype.to_be_bytes());
        b.push(e.rcode);
        b.push(e.route);
        b.extend_from_slice(&e.duration_ms.to_be_bytes());

        // name (trailing dot stripped, capped 255)
        let name = e.query_name.strip_suffix('.').unwrap_or(e.query_name);
        let nb = name.as_bytes();
        let n = nb.len().min(255);
        b.push(n as u8);
        b.extend_from_slice(&nb[..n]);

        if level < 2 {
            return b;
        }
        let ub = e.upstream.as_bytes();
        let un = ub.len().min(255);
        b.push(un as u8);
        b.extend_from_slice(&ub[..un]);

        if level < 3 {
            return b;
        }
        encode_rr_section(&mut b, answers);
        if level < 4 {
            return b;
        }
        encode_rr_section(&mut b, additional);
        b
    }

    /// count(1) + per-RR: type(2) + ttl(4) + rdlen(2) + rdata. OPT is skipped.
    fn encode_rr_section(b: &mut Vec<u8>, records: &[&OwnedRecord]) {
        let count_idx = b.len();
        b.push(0);
        let mut written: u8 = 0;
        for r in records.iter() {
            if written == 255 {
                break;
            }
            if r.rtype() == Rtype::OPT {
                continue;
            }
            let mut rdata = Vec::new();
            if r.data().compose_rdata(&mut rdata).is_err() || rdata.len() > 0xFFFF {
                continue;
            }
            b.extend_from_slice(&r.rtype().to_int().to_be_bytes());
            b.extend_from_slice(&r.ttl().as_secs().to_be_bytes());
            b.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            b.extend_from_slice(&rdata);
            written += 1;
        }
        b[count_idx] = written;
    }

    /// Re-encode with RR trimming so the payload fits `MAX_INNER_PAYLOAD`,
    /// using a priority order.
    pub fn fit_payload(e: &QueryEntry, level: u8, ts: u32) -> Vec<u8> {
        let full = encode_query(e, level, ts);
        if full.len() <= MAX_INNER_PAYLOAD || level < 3 {
            return full;
        }
        let qtype = Rtype::from_int(e.qtype);
        let same: Vec<&OwnedRecord> = e
            .answers
            .iter()
            .filter(|r| r.rtype() != Rtype::OPT && r.rtype() == qtype)
            .collect();
        let diff: Vec<&OwnedRecord> = e
            .answers
            .iter()
            .filter(|r| r.rtype() != Rtype::OPT && r.rtype() != qtype)
            .collect();
        let extras: Vec<&OwnedRecord> = e
            .additional
            .iter()
            .filter(|r| r.rtype() != Rtype::OPT)
            .collect();

        // 1) trim same-type answers to 20/10/5/1.
        for &limit in &[20usize, 10, 5, 1] {
            if same.len() > limit {
                let mut a = same[..limit].to_vec();
                a.extend_from_slice(&diff);
                let n = encode_query_with(e, &a, &extras, level, ts);
                if n.len() <= MAX_INNER_PAYLOAD {
                    return n;
                }
            }
        }
        // 2) drop the additional section (level 3).
        if level >= 4 {
            let mut a = same.clone();
            a.extend_from_slice(&diff);
            let n = encode_query_with(e, &a, &[], 3, ts);
            if n.len() <= MAX_INNER_PAYLOAD {
                return n;
            }
        }
        // 3) same-type answers only.
        let n = encode_query_with(e, &same, &[], 3, ts);
        if n.len() <= MAX_INNER_PAYLOAD {
            return n;
        }
        // 4) a single same-type answer.
        if same.len() > 1 {
            let n = encode_query_with(e, &same[..1], &[], 3, ts);
            if n.len() <= MAX_INNER_PAYLOAD {
                return n;
            }
        }
        // Fallback: level 2 (no RR sections at all).
        encode_query(e, 2, ts)
    }

    /// Level-5 event: ts(4) + severity(1) + message (capped).
    pub fn encode_event(severity: u8, msg: &str, ts: u32) -> Vec<u8> {
        let mut b = Vec::with_capacity(8 + msg.len());
        b.extend_from_slice(&ts.to_be_bytes());
        b.push(severity);
        let mb = msg.as_bytes();
        let max = MAX_INNER_PAYLOAD - 5;
        let n = mb.len().min(max);
        b.extend_from_slice(&mb[..n]);
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_parsing() {
        assert_eq!(
            parse_uuid("00112233-4455-6677-8899-aabbccddeeff"),
            Some([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ])
        );
        assert!(parse_uuid("too-short").is_none());
        // 32 *bytes* of non-ASCII must be rejected, not sliced (would panic).
        assert!(parse_uuid("€€€€€€€€€€aa").is_none());
    }

    #[test]
    fn encode_query_level1_layout() {
        let e = QueryEntry {
            client: "1.2.3.4".parse().unwrap(),
            qtype: 1,
            rcode: 0,
            route: ROUTE_LOCAL,
            duration_ms: 5,
            query_name: "example.com.",
            upstream: "",
            answers: &[],
            additional: &[],
        };
        let out = encode::encode_query(&e, 1, 0x1122_3344);
        assert_eq!(&out[0..4], &[0x11, 0x22, 0x33, 0x44]); // ts
        assert_eq!(out[4], 0); // flags: IPv4
        assert_eq!(&out[5..9], &[1, 2, 3, 4]); // client
        assert_eq!(&out[9..11], &[0, 1]); // qtype
        assert_eq!(out[11], 0); // rcode
        assert_eq!(out[12], ROUTE_LOCAL); // route
        assert_eq!(&out[13..15], &[0, 5]); // duration
        assert_eq!(out[15], 11); // name len ("example.com", dot stripped)
        assert_eq!(&out[16..27], b"example.com");
        assert_eq!(out.len(), 27); // level 1 stops after the name
    }

    #[test]
    fn encode_query_ipv6_flag_and_upstream() {
        let e = QueryEntry {
            client: "2001:db8::1".parse().unwrap(),
            qtype: 28,
            rcode: RCODE_NODATA,
            route: ROUTE_FALL,
            duration_ms: 0,
            query_name: "x.",
            upstream: "1.1.1.1:53",
            answers: &[],
            additional: &[],
        };
        let out = encode::encode_query(&e, 2, 0);
        assert_eq!(out[4], FLAG_IPV6);
        // ts(4)+flags(1)+ip(16)+qtype(2)+rcode(1)+route(1)+dur(2)+namelen(1)+"x"(1)
        let up_len_idx = 4 + 1 + 16 + 2 + 1 + 1 + 2 + 1 + 1;
        assert_eq!(out[up_len_idx] as usize, "1.1.1.1:53".len());
    }

    #[test]
    fn seal_roundtrip() {
        // Build a session, seal a payload, and decrypt it back with the same
        // key/nonce to prove the header+inner framing.
        let uuid = parse_uuid("00112233445566778899aabbccddeeff").unwrap();
        let hash = Sha256::digest(uuid);
        let cipher = ChaCha20Poly1305::new_from_slice(&hash).unwrap();
        let session_id = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let seq: u32 = 1;

        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&session_id);
        nonce[8..].copy_from_slice(&seq.to_be_bytes());
        let mut header = [0u8; 18];
        header[0] = MAGIC0;
        header[1] = MAGIC1;
        header[2..6].copy_from_slice(&hash[..4]);
        header[6..18].copy_from_slice(&nonce);

        let payload = b"hello-telemetry";
        let mut inner = Vec::new();
        inner.extend_from_slice(&seq.to_be_bytes());
        inner.push(1);
        inner.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        inner.extend_from_slice(payload);

        let ct = cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: &inner,
                    aad: &header,
                },
            )
            .unwrap();
        // Decrypt using the header as AAD (what the collector does).
        let pt = cipher
            .decrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: &ct,
                    aad: &header,
                },
            )
            .unwrap();
        assert_eq!(pt, inner);
        assert_eq!(&pt[0..4], &seq.to_be_bytes());
        assert_eq!(pt[4], 1); // level
        assert_eq!(&pt[7..], payload);
    }
}
