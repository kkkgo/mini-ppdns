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
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::AeadInOut;
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
/// Queued packets before telemetry starts dropping. Each is up to
/// `MAX_PACKET_SIZE`, so this also bounds what a stalled collector can pin.
const CHANNEL_SIZE: usize = 512;
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
    /// The question name in wire form; the payload carries it in
    /// presentation form (see `encode::write_name`).
    pub qname_wire: &'a [u8],
    pub upstream: &'a str,
    pub answers: &'a [OwnedRecord],
    pub additional: &'a [OwnedRecord],
}

/// Clamp a duration to the `u16` millisecond field.
pub fn dur_to_ms(d: Duration) -> u16 {
    d.as_millis().min(0xFFFF) as u16
}

/// A payload queued for the sender task: what to seal, and at which level.
struct Outgoing {
    level: u8,
    payload: Vec<u8>,
}
/// Packet framing and AEAD sealing.
///
/// Owned by the sender task alone, which is what lets the nonce counter live
/// without a lock and the per-packet buffers be reused: sealing a 40-byte
/// payload costs microseconds, far more than everything else a report does,
/// and the query path must not pay it.
struct Sealer {
    cipher: ChaCha20Poly1305,
    key_hint: [u8; 4],
    session_id: [u8; 8],
    seq: u32,
    /// Plaintext buffer, sealed in place, so a packet allocates nothing.
    inner: Vec<u8>,
    packet: Vec<u8>,
}
impl Sealer {
    fn new(cipher: ChaCha20Poly1305, key_hint: [u8; 4]) -> Self {
        Sealer {
            cipher,
            key_hint,
            session_id: random8(),
            seq: 0,
            inner: Vec::with_capacity(MAX_PACKET_SIZE),
            packet: Vec::with_capacity(MAX_PACKET_SIZE),
        }
    }
    /// Frame `payload` into a packet and seal it. Returns the packet bytes,
    /// valid until the next call.
    fn seal(&mut self, level: u8, payload: &[u8]) -> Option<&[u8]> {
        self.seq = self.seq.wrapping_add(1);
        if self.seq == 0 {
            // seq wrapped: a fresh session id keeps the nonce unique.
            self.session_id = random8();
            self.seq = 1;
        }
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&self.session_id);
        nonce[8..].copy_from_slice(&self.seq.to_be_bytes());
        let mut header = [0u8; HEADER_SIZE];
        header[0] = MAGIC0;
        header[1] = MAGIC1;
        header[2..6].copy_from_slice(&self.key_hint);
        header[6..18].copy_from_slice(&nonce);
        let Sealer {
            cipher,
            inner,
            packet,
            ..
        } = self;
        inner.clear();
        inner.extend_from_slice(&self.seq.to_be_bytes());
        inner.push(level);
        inner.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        inner.extend_from_slice(payload);
        // The header is the associated data, as the collector expects.
        cipher
            .encrypt_in_place(&Nonce::from(nonce), &header, inner)
            .ok()?;
        packet.clear();
        packet.extend_from_slice(&header);
        packet.extend_from_slice(inner);
        Some(packet)
    }
}

pub struct Config {
    pub uuid: String,
    pub server: String,
    pub level: i64,
    pub heartbeat: i64,
}

/// Best-effort encrypted UDP reporter.
///
/// The query path only encodes a payload and queues it: framing, nonce
/// assignment and AEAD sealing all run in the sender task (see [`Sealer`]),
/// off the receive loop that answers clients.
pub struct Reporter {
    level: u8,
    tx: mpsc::Sender<Outgoing>,
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

        let (tx, mut rx) = mpsc::channel::<Outgoing>(CHANNEL_SIZE);
        tokio::spawn(async move {
            let mut sealer = Sealer::new(cipher, key_hint);
            while let Some(msg) = rx.recv().await {
                if let Some(pkt) = sealer.seal(msg.level, &msg.payload) {
                    let _ = tokio::time::timeout(WRITE_TIMEOUT, sock.send(pkt)).await;
                }
            }
        });

        let reporter = Arc::new(Reporter {
            level: cfg.level as u8,
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
        // Only written when the second actually turns over: every query on every
        // core touches this, and a store takes the cache line exclusively where
        // a load can share it.
        if self.last_report.load(Ordering::Relaxed) != ts {
            self.last_report.store(ts, Ordering::Relaxed);
        }
        // Query entries max out at level 4 even when configured level is 5.
        let level = self.level.min(4);
        let payload = if level >= 3 {
            encode::fit_payload(entry, level, ts)
        } else {
            encode::encode_query(entry, level, ts)
        };
        self.queue(level, payload);
    }

    /// Report a level-5 event (heartbeat, hook transitions, …). Sent only when
    /// the configured level is >= 2.
    pub fn report_event(&self, severity: u8, msg: &str) {
        if self.level < 2 {
            return;
        }
        let payload = encode::encode_event(severity, msg, now_secs());
        self.queue(5, payload);
    }

    /// Hand a payload to the sender task, which frames and seals it. Dropped
    /// when the queue is full: telemetry never stalls a query.
    fn queue(&self, level: u8, payload: Vec<u8>) {
        let _ = self.tx.try_send(Outgoing { level, payload });
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
        let v6 = match e.client {
            IpAddr::V4(_) => None,
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(_) => None,
                None => Some(v6),
            },
        };
        b.push(if v6.is_some() { FLAG_IPV6 } else { 0 });
        match (e.client, v6) {
            (_, Some(v6)) => b.extend_from_slice(&v6.octets()),
            (IpAddr::V4(v4), _) => b.extend_from_slice(&v4.octets()),
            (IpAddr::V6(mapped), _) => {
                b.extend_from_slice(&mapped.to_ipv4_mapped().expect("mapped").octets())
            }
        }

        b.extend_from_slice(&e.qtype.to_be_bytes());
        b.push(e.rcode);
        b.push(e.route);
        b.extend_from_slice(&e.duration_ms.to_be_bytes());

        // name in presentation form (no root dot), capped at 255 bytes
        let at = b.len();
        b.push(0);
        write_name(&mut b, e.qname_wire);
        let n = (b.len() - at - 1).min(255);
        b.truncate(at + 1 + n);
        b[at] = n as u8;

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

    /// Append a wire-form name in presentation form, without the root dot.
    /// Escaping matches the `domain` crate's `Display`: space, dot and
    /// backslash take a backslash, and anything outside printable ASCII
    /// becomes a three-digit `\\DDD` escape. The root name renders empty.
    pub fn write_name(b: &mut Vec<u8>, wire: &[u8]) {
        let mut i = 0;
        let mut first = true;
        while let Some(&len) = wire.get(i) {
            let len = usize::from(len);
            if len == 0 {
                break;
            }
            let Some(label) = wire.get(i + 1..i + 1 + len) else {
                break;
            };
            if !first {
                b.push(b'.');
            }
            first = false;
            for &c in label {
                match c {
                    b' ' | b'.' | b'\\' => b.extend_from_slice(&[b'\\', c]),
                    0x20..=0x7E => b.push(c),
                    _ => b.extend_from_slice(&[
                        b'\\',
                        b'0' + c / 100,
                        b'0' + (c / 10) % 10,
                        b'0' + c % 10,
                    ]),
                }
            }
            i += 1 + len;
        }
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
    use chacha20poly1305::aead::{Aead, Payload};

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
            qname_wire: b"\x07example\x03com\x00",
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
            qname_wire: b"\x01x\x00",
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
    fn the_sealer_frames_what_a_collector_decrypts() {
        // Seal through the production sealer and take it apart the way the
        // collector does: header as associated data, then the inner framing.
        let uuid = parse_uuid("00112233445566778899aabbccddeeff").unwrap();
        let hash = Sha256::digest(uuid);
        let cipher = ChaCha20Poly1305::new_from_slice(&hash).unwrap();
        let mut key_hint = [0u8; 4];
        key_hint.copy_from_slice(&hash[..4]);
        let mut sealer = Sealer::new(cipher.clone(), key_hint);
        let mut seen_nonces = std::collections::HashSet::new();
        for (i, payload) in [
            b"hello-telemetry".to_vec(),
            Vec::new(),
            vec![0xA5; MAX_INNER_PAYLOAD],
            b"third".to_vec(),
        ]
        .into_iter()
        .enumerate()
        {
            let level = (i as u8 % 5) + 1;
            let pkt = sealer.seal(level, &payload).expect("sealed").to_vec();
            assert!(
                pkt.len() <= MAX_PACKET_SIZE,
                "packet {i} overruns the datagram"
            );
            assert_eq!(&pkt[..2], &[MAGIC0, MAGIC1]);
            assert_eq!(&pkt[2..6], &hash[..4], "key hint");
            let header = &pkt[..HEADER_SIZE];
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&pkt[6..18]);
            assert!(seen_nonces.insert(nonce), "a nonce repeated");
            let pt = cipher
                .decrypt(
                    &Nonce::from(nonce),
                    Payload {
                        msg: &pkt[HEADER_SIZE..],
                        aad: header,
                    },
                )
                .expect("collector decrypts with the header as AAD");
            let seq = u32::from_be_bytes([pt[0], pt[1], pt[2], pt[3]]);
            assert_eq!(seq, i as u32 + 1, "sequence numbers run in order");
            // The nonce carries the same sequence number as the sealed body.
            assert_eq!(&nonce[8..], &seq.to_be_bytes());
            assert_eq!(pt[4], level);
            assert_eq!(
                u16::from_be_bytes([pt[5], pt[6]]) as usize,
                payload.len(),
                "declared payload length"
            );
            assert_eq!(&pt[INNER_HEADER_SIZE..], &payload[..]);
        }
    }
    #[test]
    fn an_over_long_name_is_capped_to_the_length_byte() {
        // Every byte escapes to four, so this renders far past 255 and the
        // payload's one-byte length must still describe what follows.
        let mut wire = Vec::new();
        for _ in 0..4 {
            wire.push(60u8);
            wire.extend(std::iter::repeat_n(0u8, 60));
        }
        wire.push(0);
        let e = QueryEntry {
            client: "1.2.3.4".parse().unwrap(),
            qtype: 1,
            rcode: 0,
            route: ROUTE_LOCAL,
            duration_ms: 0,
            qname_wire: &wire,
            upstream: "",
            answers: &[],
            additional: &[],
        };
        let out = encode::encode_query(&e, 1, 0);
        assert_eq!(out[15], 255, "length byte");
        assert_eq!(out.len(), 16 + 255, "name truncated to the declared length");
    }

    #[test]
    fn rendered_names_match_the_display_they_replaced() {
        use domain::base::Name;
        // Names built from the bytes that make rendering interesting: the
        // escaped characters, the printable range, and everything outside it.
        let mut state = 0x1234_5678_9abc_def0u64;
        let mut rng = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut compared = 0;
        let mut escaped = 0;
        for round in 0..20_000u32 {
            let mut wire: Vec<u8> = Vec::new();
            if round > 0 {
                for _ in 0..1 + rng() % 4 {
                    let len = 1 + (rng() % 9) as usize;
                    if wire.len() + len + 2 > 255 {
                        break;
                    }
                    wire.push(len as u8);
                    for _ in 0..len {
                        wire.push(match rng() % 8 {
                            0 => b'.',
                            1 => b'\\',
                            2 => b' ',
                            3 => (rng() % 256) as u8,
                            4 => 0x7F,
                            _ => b"abzAZ09-_*"[(rng() % 10) as usize],
                        });
                    }
                }
            }
            wire.push(0); // root, and for round 0 the root name itself
            let Ok(name) = Name::from_octets(wire.clone()) else {
                continue;
            };
            // `Display` already omits the root dot, except for the root
            // name itself, which the payload carries as an empty name.
            let shown = name.to_string();
            let want = if name.is_root() { "" } else { shown.as_str() };
            let mut got = Vec::new();
            encode::write_name(&mut got, &wire);
            assert_eq!(String::from_utf8_lossy(&got), want, "wire={wire:?}");
            compared += 1;
            escaped += usize::from(got.contains(&b'\\'));
        }
        assert!(compared > 10_000, "only {compared} names compared");
        assert!(escaped > 1_000, "only {escaped} names exercised an escape");
    }

    #[test]
    fn a_wrapped_sequence_starts_a_new_session() {
        let hash = Sha256::digest(parse_uuid("00112233445566778899aabbccddeeff").unwrap());
        let cipher = ChaCha20Poly1305::new_from_slice(&hash).unwrap();
        let mut sealer = Sealer::new(cipher, [0; 4]);
        sealer.seq = u32::MAX - 1;
        let before = sealer.session_id;
        let last = sealer.seal(1, b"x").expect("sealed")[6..18].to_vec();
        assert_eq!(&last[8..], &u32::MAX.to_be_bytes());
        let wrapped = sealer.seal(1, b"x").expect("sealed")[6..18].to_vec();
        // Reusing (session id, seq) would reuse a nonce, which breaks the AEAD.
        assert_eq!(&wrapped[8..], &1u32.to_be_bytes(), "seq restarts at 1");
        assert_ne!(&wrapped[..8], &before[..], "with a fresh session id");
    }
}
