// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

//! Local record resolution helpers — the name-conversion and classification
//! subset. File loading, hot-reload, and the resolver struct itself land in a
//! later phase (see plan.md §6 P3); the pure functions here are shared by the
//! static-rewrite path and are fully unit-tested.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use domain::base::Name;

use crate::dns::OwnedName;
use crate::util::v6_is_private_special;

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Convert an IP string to its reverse PTR name. IPv4 → `d.c.b.a.in-addr.arpa.`;
/// IPv6 → nibble-reversed `ip6.arpa.`. IPv4-mapped IPv6 is unmapped first.
/// Returns "" if the string does not parse.
pub fn ip_to_ptr_name_str(ip: &str) -> String {
    match ip.parse::<IpAddr>() {
        Ok(addr) => ip_to_ptr_name(addr),
        Err(_) => String::new(),
    }
}

/// Convert an IP address to its reverse PTR name.
pub fn ip_to_ptr_name(addr: IpAddr) -> String {
    let addr = unmap(addr);
    match addr {
        IpAddr::V4(a) => {
            let b = a.octets();
            format!("{}.{}.{}.{}.in-addr.arpa.", b[3], b[2], b[1], b[0])
        }
        IpAddr::V6(a) => {
            let b = a.octets();
            // 32 nibbles: low nibble of byte 15 first, then its high nibble,
            // ..., ending with the high nibble of byte 0.
            let mut s = String::with_capacity(73);
            for i in (0..16).rev() {
                s.push(HEX[(b[i] & 0x0f) as usize] as char);
                s.push('.');
                s.push(HEX[(b[i] >> 4) as usize] as char);
                s.push('.');
            }
            s.push_str("ip6.arpa.");
            s
        }
    }
}

fn unmap(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Reports whether a PTR query name corresponds to a private/loopback/
/// link-local address.
pub fn is_private_ptr(qname: &str) -> bool {
    let mut qname = qname.to_ascii_lowercase();
    // Tolerate a missing root dot (some name renderings omit it) so the
    // `.in-addr.arpa.` / `.ip6.arpa.` suffix checks still match.
    if !qname.ends_with('.') {
        qname.push('.');
    }

    if let Some(trimmed) = qname.strip_suffix(".in-addr.arpa.") {
        return match parse_ipv4_arpa_labels(trimmed) {
            Some(octets) => {
                let a = Ipv4Addr::from(octets);
                a.is_private() || a.is_link_local() || a.is_loopback()
            }
            None => false,
        };
    }

    if let Some(trimmed) = qname.strip_suffix(".ip6.arpa.") {
        return match parse_ipv6_arpa_labels(trimmed) {
            Some(bytes) => v6_is_private_special(Ipv6Addr::from(bytes)),
            None => false,
        };
    }

    false
}

/// Parse the reversed dotted-octet portion of an in-addr.arpa query (e.g.
/// `132.10.10.10`) into a big-endian `[u8; 4]`. Rejects wrong label counts,
/// empty/over-long labels, and octets > 255.
pub fn parse_ipv4_arpa_labels(s: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut count = 0;
    for (i, label) in s.split('.').enumerate() {
        if i >= 4
            || label.is_empty()
            || label.len() > 3
            || !label.bytes().all(|c| c.is_ascii_digit())
        {
            return None;
        }
        let v: u16 = label.parse().ok()?;
        if v > 255 {
            return None;
        }
        // Labels appear low-order first; index 3 receives the first label so
        // the result ends up in big-endian (wire) order.
        out[3 - i] = v as u8;
        count += 1;
    }
    if count != 4 {
        return None;
    }
    Some(out)
}

/// Parse the 32 nibble labels of an ip6.arpa query into a `[u8; 16]`.
fn parse_ipv6_arpa_labels(s: &str) -> Option<[u8; 16]> {
    let mut bytes = [0u8; 16];
    let mut count = 0;
    for (i, label) in s.split('.').enumerate() {
        if i >= 32 || label.len() != 1 {
            return None;
        }
        let v = hex_nibble(label.as_bytes()[0])?;
        // label[0] is the lowest nibble; reverse into bytes16.
        let byte_idx = 15 - i / 2;
        if i % 2 == 0 {
            bytes[byte_idx] |= v;
        } else {
            bytes[byte_idx] |= v << 4;
        }
        count += 1;
    }
    if count != 32 {
        return None;
    }
    Some(bytes)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

// ---- File-backed resolver (lease/hosts) with lazy hot-reload ----

const DEFAULT_LEASE_FILES: &[&str] = &["/tmp/dhcp.leases", "/tmp/dnsmasq.leases"];
const DEFAULT_HOSTS_FILES: &[&str] = &["/etc/hosts"];
const RELOAD_INTERVAL_SECS: u32 = 5;

/// Encode a presentation name into lower-cased uncompressed wire bytes, the
/// form used as map keys (so a query's `qname_lower` matches directly). Lenient
/// about label charset (allows `_` etc.).
fn name_to_wire(s: &str, lower: bool) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('.');
    let mut out = Vec::with_capacity(s.len() + 2);
    if !s.is_empty() {
        for label in s.split('.') {
            let b = label.as_bytes();
            if b.is_empty() || b.len() > 63 {
                return None;
            }
            out.push(b.len() as u8);
            if lower {
                out.extend(b.iter().map(|c| c.to_ascii_lowercase()));
            } else {
                out.extend_from_slice(b);
            }
        }
    }
    out.push(0);
    if out.len() > 255 {
        return None;
    }
    Some(out)
}

/// Build an owned DNS name from a hostname string (case preserved), for use as
/// a PTR record's target.
pub fn hostname_to_name(s: &str) -> Option<OwnedName> {
    Name::from_octets(name_to_wire(s, false)?).ok()
}

fn now_secs() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

#[derive(Default)]
struct Maps {
    ptr: HashMap<Vec<u8>, String>,          // wire-lower(arpa) -> hostname
    fwd: HashMap<Vec<u8>, Vec<IpAddr>>,     // wire-lower(name) -> ips
    mod_times: HashMap<String, SystemTime>, // watched path -> mtime
}

/// In-memory resolver over DHCP lease + hosts files, plus `[hosts]` statics.
/// Supports reverse (PTR) and forward (A/AAAA) lookups with a lazy 5s reload.
pub struct PtrResolver {
    lease_files: Vec<String>,
    hosts_files: Vec<String>,      // explicit, watched for hot-reload
    auto_hosts_files: Vec<String>, // auto-detected, loaded once (not watched)
    static_ptr: HashMap<Vec<u8>, String>,
    static_fwd: HashMap<Vec<u8>, Vec<IpAddr>>,
    maps: RwLock<Maps>,
    // Unix time (seconds) of the last file-change check. u32 (not i64) so the
    // type exists on 32-bit MIPS, which has no 64-bit atomics; seconds fit
    // until 2106 and this is only a reload throttle.
    last_check: AtomicU32,
}

impl PtrResolver {
    /// Build a resolver, auto-detecting default lease/hosts paths when neither
    /// lease nor hosts files were explicitly configured. Returns None when
    /// there is nothing to resolve.
    pub fn new(
        mut lease_files: Vec<String>,
        hosts_files: Vec<String>,
        auto_detect: bool,
        static_hosts: &HashMap<String, Vec<IpAddr>>,
    ) -> Option<PtrResolver> {
        let mut auto_hosts_files = Vec::new();
        if auto_detect {
            for f in DEFAULT_LEASE_FILES {
                if std::path::Path::new(f).exists() {
                    lease_files.push((*f).to_string());
                }
            }
            if static_hosts.is_empty() {
                for f in DEFAULT_HOSTS_FILES {
                    if std::path::Path::new(f).exists() {
                        auto_hosts_files.push((*f).to_string());
                    }
                }
            }
            if lease_files.is_empty() && auto_hosts_files.is_empty() && static_hosts.is_empty() {
                return None;
            }
        }

        let mut static_fwd = HashMap::new();
        let mut static_ptr = HashMap::new();
        for (domain, ips) in static_hosts {
            if let Some(k) = name_to_wire(domain, true) {
                static_fwd.insert(k, ips.clone());
            }
            for ip in ips {
                if let Some(k) = name_to_wire(&ip_to_ptr_name(*ip), true) {
                    static_ptr.insert(k, domain.trim_end_matches('.').to_string());
                }
            }
        }

        let r = PtrResolver {
            lease_files,
            hosts_files,
            auto_hosts_files,
            static_ptr,
            static_fwd,
            maps: RwLock::new(Maps::default()),
            last_check: AtomicU32::new(now_secs()),
        };
        r.reload();
        Some(r)
    }

    /// Effective lease files (explicit + auto-detected), for the startup log.
    pub fn lease_files_desc(&self) -> String {
        if self.lease_files.is_empty() {
            "-".to_string()
        } else {
            self.lease_files.join(",")
        }
    }

    /// Effective hosts files (explicit + auto-detected), for the startup log.
    pub fn hosts_files_desc(&self) -> String {
        let mut all: Vec<&str> = self.hosts_files.iter().map(String::as_str).collect();
        all.extend(self.auto_hosts_files.iter().map(String::as_str));
        if all.is_empty() {
            "-".to_string()
        } else {
            all.join(",")
        }
    }

    /// Reverse lookup: PTR query wire name (lower-cased) → hostname.
    pub fn lookup(&self, qname_lower: &[u8]) -> Option<String> {
        self.maybe_reload();
        self.maps.read().unwrap().ptr.get(qname_lower).cloned()
    }

    /// Forward lookup: A/AAAA query wire name (lower-cased) → IPs.
    pub fn lookup_ip(&self, qname_lower: &[u8]) -> Vec<IpAddr> {
        self.maybe_reload();
        self.maps
            .read()
            .unwrap()
            .fwd
            .get(qname_lower)
            .cloned()
            .unwrap_or_default()
    }

    fn maybe_reload(&self) {
        let now = now_secs();
        let last = self.last_check.load(Ordering::Relaxed);
        // now < last guards a wall-clock step-back: fall through and resync.
        if now >= last && now - last < RELOAD_INTERVAL_SECS {
            return;
        }
        if self
            .last_check
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        if self.files_changed() {
            self.reload();
        }
    }

    fn files_changed(&self) -> bool {
        let watched: Vec<&String> = self
            .lease_files
            .iter()
            .chain(self.hosts_files.iter())
            .collect();
        // Stat outside the lock so disk I/O never blocks readers.
        let cur: Vec<(&String, Option<SystemTime>)> = watched
            .iter()
            .map(|f| (*f, std::fs::metadata(f).and_then(|m| m.modified()).ok()))
            .collect();
        let maps = self.maps.read().unwrap();
        for (f, cur_mt) in cur {
            let prev = maps.mod_times.get(f).copied();
            match (cur_mt, prev) {
                (None, Some(_)) => return true,              // disappeared
                (Some(_), None) => return true,              // appeared
                (Some(c), Some(p)) if c != p => return true, // changed
                _ => {}
            }
        }
        false
    }

    fn reload(&self) {
        let mut ptr = HashMap::new();
        let mut fwd = HashMap::new();
        let mut mod_times = HashMap::new();
        for f in &self.lease_files {
            load_lease(f, &mut ptr, &mut mod_times);
        }
        for f in &self.hosts_files {
            load_hosts(f, &mut ptr, &mut fwd, Some(&mut mod_times));
        }
        for f in &self.auto_hosts_files {
            load_hosts(f, &mut ptr, &mut fwd, None);
        }
        // Static [hosts] entries always overlay file entries.
        for (k, v) in &self.static_ptr {
            ptr.insert(k.clone(), v.clone());
        }
        for (k, v) in &self.static_fwd {
            fwd.insert(k.clone(), v.clone());
        }
        let mut m = self.maps.write().unwrap();
        m.ptr = ptr;
        m.fwd = fwd;
        m.mod_times = mod_times;
    }
}

fn load_lease(
    path: &str,
    ptr: &mut HashMap<Vec<u8>, String>,
    mod_times: &mut HashMap<String, SystemTime>,
) {
    let Ok(meta) = std::fs::metadata(path) else {
        return;
    };
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    for line in text.lines() {
        // dnsmasq lease: timestamp mac ip hostname client-id
        let line = strip_comment(line);
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let (ip, hostname) = (fields[2], fields[3]);
        if hostname == "*" || hostname.is_empty() {
            continue;
        }
        let ptr_text = ip_to_ptr_name_str(ip);
        if ptr_text.is_empty() {
            continue;
        }
        if let Some(k) = name_to_wire(&ptr_text, true) {
            ptr.insert(k, hostname.to_string());
        }
    }
    if let Ok(mt) = meta.modified() {
        mod_times.insert(path.to_string(), mt);
    }
}

fn load_hosts(
    path: &str,
    ptr: &mut HashMap<Vec<u8>, String>,
    fwd: &mut HashMap<Vec<u8>, Vec<IpAddr>>,
    mod_times: Option<&mut HashMap<String, SystemTime>>,
) {
    let Ok(meta) = std::fs::metadata(path) else {
        return;
    };
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    for line in text.lines() {
        let line = strip_comment(line.trim());
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 2 {
            continue;
        }
        let Ok(ip) = fields[0].parse::<IpAddr>() else {
            continue;
        };
        // Reverse: first hostname is canonical.
        let ptr_text = ip_to_ptr_name_str(fields[0]);
        if !ptr_text.is_empty() {
            if let Some(k) = name_to_wire(&ptr_text, true) {
                ptr.insert(k, fields[1].to_string());
            }
        }
        // Forward: every alias maps to this IP.
        for hostname in &fields[1..] {
            if *hostname == "*" || hostname.is_empty() {
                continue;
            }
            if let Some(k) = name_to_wire(hostname, true) {
                fwd.entry(k).or_default().push(ip);
            }
        }
    }
    if let Some(mt) = mod_times {
        if let Ok(t) = meta.modified() {
            mt.insert(path.to_string(), t);
        }
    }
}

/// Strip an inline `#` comment.
fn strip_comment(line: &str) -> &str {
    match line.split_once('#') {
        Some((head, _)) => head,
        None => line,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ptr_name_vectors() {
        // Test vectors for IP-to-PTR-name conversion.
        let cases = [
            ("10.10.10.132", "132.10.10.10.in-addr.arpa."),
            ("192.168.1.1", "1.1.168.192.in-addr.arpa."),
            ("255.255.255.255", "255.255.255.255.in-addr.arpa."),
            ("0.0.0.0", "0.0.0.0.in-addr.arpa."),
            (
                "::1",
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
            ),
            (
                "2001:db8::1",
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
            ),
            ("::ffff:1.2.3.4", "4.3.2.1.in-addr.arpa."),
        ];
        for (ip, want) in cases {
            assert_eq!(ip_to_ptr_name_str(ip), want, "ip={ip}");
        }
        assert_eq!(ip_to_ptr_name_str("not-an-ip"), "");
    }

    #[test]
    fn private_ptr_vectors() {
        // Test vectors for private-PTR classification.
        let cases = [
            ("132.10.10.10.in-addr.arpa.", true),
            ("1.0.0.10.in-addr.arpa.", true),
            ("1.0.16.172.in-addr.arpa.", true),
            ("1.0.31.172.in-addr.arpa.", true),
            ("1.0.32.172.in-addr.arpa.", false), // 172.32.x is not private
            ("1.1.168.192.in-addr.arpa.", true),
            ("1.1.254.169.in-addr.arpa.", true),
            ("1.0.0.127.in-addr.arpa.", true),
            ("4.4.8.8.in-addr.arpa.", false),
            ("1.1.1.1.in-addr.arpa.", false),
            (
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
                true,
            ), // ::1
            (
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.c.f.ip6.arpa.",
                true,
            ), // fc..
            (
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.",
                true,
            ), // fe80..
            (
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
                false,
            ), // 2001:db8..
            ("1.2.3.in-addr.arpa.", false),
            ("abc.2.3.4.in-addr.arpa.", false),
        ];
        for (qname, want) in cases {
            assert_eq!(is_private_ptr(qname), want, "qname={qname}");
        }
    }

    #[test]
    fn arpa_labels_edges() {
        assert_eq!(
            parse_ipv4_arpa_labels("132.10.10.10"),
            Some([10, 10, 10, 132])
        );
        assert_eq!(parse_ipv4_arpa_labels("1.2.3"), None); // too few
        assert_eq!(parse_ipv4_arpa_labels("1.2.3.4.5"), None); // too many
        assert_eq!(parse_ipv4_arpa_labels("256.1.1.1"), None); // out of range
        assert_eq!(parse_ipv4_arpa_labels("0010.1.1.1"), None); // over-long label
        assert_eq!(parse_ipv4_arpa_labels("a.1.1.1"), None); // non-digit
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn file_backed_forward_reverse_static_and_reload() {
        let dir = std::env::temp_dir();
        let uniq = format!("mppdns-{}-{:p}", std::process::id(), &dir as *const _);
        let lease = dir.join(format!("{uniq}.leases"));
        let hosts = dir.join(format!("{uniq}.hosts"));
        std::fs::write(
            &lease,
            "1700000000 aa:bb:cc:dd:ee:ff 192.168.1.50 leasehost *\n",
        )
        .unwrap();
        std::fs::write(&hosts, "10.0.0.5 myhost.lan alias.lan\n").unwrap();

        let mut statics: HashMap<String, Vec<IpAddr>> = HashMap::new();
        statics.insert("static.lan.".to_string(), vec![ip("172.16.0.9")]);

        let r = PtrResolver::new(
            vec![lease.to_string_lossy().into_owned()],
            vec![hosts.to_string_lossy().into_owned()],
            false,
            &statics,
        )
        .expect("resolver present");

        let fwd = |name: &str| r.lookup_ip(&name_to_wire(name, true).unwrap());
        let rev = |ipstr: &str| r.lookup(&name_to_wire(&ip_to_ptr_name_str(ipstr), true).unwrap());

        // lease reverse; hosts forward (all aliases) + reverse (first name); static.
        assert_eq!(rev("192.168.1.50").as_deref(), Some("leasehost"));
        assert_eq!(fwd("myhost.lan"), vec![ip("10.0.0.5")]);
        assert_eq!(fwd("alias.lan"), vec![ip("10.0.0.5")]);
        assert_eq!(rev("10.0.0.5").as_deref(), Some("myhost.lan"));
        assert_eq!(fwd("static.lan"), vec![ip("172.16.0.9")]);

        // Hot reload: rewrite hosts, force a reload, old entry gone / new present,
        // and the [hosts] static overlay survives.
        std::fs::write(&hosts, "10.0.0.6 newhost.lan\n").unwrap();
        r.reload();
        assert_eq!(fwd("newhost.lan"), vec![ip("10.0.0.6")]);
        assert!(fwd("myhost.lan").is_empty());
        assert_eq!(fwd("static.lan"), vec![ip("172.16.0.9")]);

        let _ = std::fs::remove_file(&lease);
        let _ = std::fs::remove_file(&hosts);
    }
}
