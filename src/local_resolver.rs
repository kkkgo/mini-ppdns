// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

//! Local record resolution helpers — the name-conversion and classification
//! subset. The pure functions here are shared by the static-rewrite path and
//! are fully unit-tested.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::RwLock;
use std::time::SystemTime;

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

// ---- File-backed resolver (lease/hosts) with background hot-reload ----

const DEFAULT_LEASE_FILES: &[&str] = &["/tmp/dhcp.leases", "/tmp/dnsmasq.leases"];
const DEFAULT_HOSTS_FILES: &[&str] = &["/etc/hosts"];
/// Interval of the background file-watch task (see `app`).
pub const RELOAD_INTERVAL_SECS: u64 = 5;

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

#[derive(Default)]
struct Maps {
    ptr: HashMap<Vec<u8>, String>,          // wire-lower(arpa) -> hostname
    fwd: HashMap<Vec<u8>, Vec<IpAddr>>,     // wire-lower(name) -> ips
    mod_times: HashMap<String, SystemTime>, // watched path -> mtime
}

/// Bits in [`NameFilter`] (8 KiB). Sized so typical lease/hosts tables
/// (dozens to a few thousand names) test negative essentially always, while
/// a huge adblock-style table merely saturates the filter toward "always
/// maybe" — degrading to the pre-filter cost, never below it.
const FILTER_BITS: usize = 1 << 16;

/// Word width of the filter bitmap. `AtomicUsize` (never `AtomicU64`): the
/// 32-bit MIPS release targets have no 64-bit atomics — `AtomicU64` does not
/// even exist there — while pointer-width atomics exist on every target we
/// ship. The word size only changes the bitmap's internal layout, not the
/// filter's semantics.
const WORD_BITS: usize = usize::BITS as usize;

/// Add-only Bloom filter (k=2) over lower-cased wire names, guarding the
/// forward lookup that runs on *every* A/AAAA query: profiling showed the
/// RwLock + HashMap probe costing ~6% of cache-hit-path CPU even when the
/// table only held /etc/hosts boilerplate. Bits are set before the new maps
/// are published and never cleared, so steady-state lookups get no false
/// negatives; names a reload removed leave stale bits behind, costing one
/// wasted map probe. Relaxed atomics: a lookup racing a reload may miss that
/// reload's *new* names for an instant — it just gets the pre-reload answer
/// once.
struct NameFilter {
    words: Box<[AtomicUsize]>,
}

impl NameFilter {
    fn new() -> Self {
        NameFilter {
            words: (0..FILTER_BITS / WORD_BITS)
                .map(|_| AtomicUsize::new(0))
                .collect(),
        }
    }

    /// The two bit positions for a name hash (`util::hash` of the wire
    /// name): low and high halves of the one hash.
    fn bits_of(h: u64) -> [usize; 2] {
        [
            h as usize & (FILTER_BITS - 1),
            (h >> 32) as usize & (FILTER_BITS - 1),
        ]
    }

    fn insert(&self, name: &[u8]) {
        for i in Self::bits_of(crate::util::hash(name)) {
            self.words[i / WORD_BITS].fetch_or(1 << (i % WORD_BITS), Ordering::Relaxed);
        }
    }

    fn may_contain_hash(&self, h: u64) -> bool {
        Self::bits_of(h).into_iter().all(|i| {
            self.words[i / WORD_BITS].load(Ordering::Relaxed) & (1 << (i % WORD_BITS)) != 0
        })
    }
}

/// In-memory resolver over DHCP lease + hosts files, plus `[hosts]` statics.
/// Supports reverse (PTR) and forward (A/AAAA) lookups. Reload is driven by a
/// periodic background task (see `app`), never by lookups: the lookup path
/// runs inline in the UDP receive loops, where synchronous file IO would
/// stall intake.
pub struct PtrResolver {
    lease_files: Vec<String>,
    hosts_files: Vec<String>,      // explicit
    auto_hosts_files: Vec<String>, // auto-detected (e.g. /etc/hosts)

    static_ptr: HashMap<Vec<u8>, String>,
    static_fwd: HashMap<Vec<u8>, Vec<IpAddr>>,
    maps: RwLock<Maps>,
    /// Lock-free negative filter over `maps.fwd` keys (see [`NameFilter`]).
    fwd_filter: NameFilter,
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
            fwd_filter: NameFilter::new(),
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
        self.maps.read().unwrap().ptr.get(qname_lower).cloned()
    }

    /// Forward lookup: A/AAAA query wire name (lower-cased) → IPs. Runs on
    /// every A/AAAA query, so the (overwhelmingly common) absent name is
    /// rejected by the lock-free filter before paying for the RwLock +
    /// HashMap probe. `name_hash` is the caller's per-query `util::hash` of
    /// `qname_lower` (`QueryInfo::name_hash`), so the name isn't re-hashed.
    pub fn lookup_ip(&self, qname_lower: &[u8], name_hash: u64) -> Vec<IpAddr> {
        if !self.fwd_filter.may_contain_hash(name_hash) {
            return Vec::new();
        }
        self.maps
            .read()
            .unwrap()
            .fwd
            .get(qname_lower)
            .cloned()
            .unwrap_or_default()
    }

    /// Reload if any watched file changed. Runs blocking file IO — call it
    /// from the background watcher task, never from the query path.
    pub fn check_reload(&self) {
        if self.files_changed() {
            self.reload();
        }
    }

    /// Every file the resolver reads is watched, auto-detected ones included —
    /// `/etc/hosts` is documented as hot-reloading, and a file that is read but
    /// not watched only refreshes when some *other* watched file changes.
    fn watched_files(&self) -> impl Iterator<Item = &String> {
        self.lease_files
            .iter()
            .chain(self.hosts_files.iter())
            .chain(self.auto_hosts_files.iter())
    }

    fn files_changed(&self) -> bool {
        let watched: Vec<&String> = self.watched_files().collect();
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
            load_hosts(f, &mut ptr, &mut fwd, Some(&mut mod_times));
        }
        // Static [hosts] entries always overlay file entries.
        for (k, v) in &self.static_ptr {
            ptr.insert(k.clone(), v.clone());
        }
        for (k, v) in &self.static_fwd {
            fwd.insert(k.clone(), v.clone());
        }
        // Publish filter bits for every (possibly new) name BEFORE swapping
        // the maps in, so a lookup that sees the new maps also sees the bits.
        for k in fwd.keys() {
            self.fwd_filter.insert(k);
        }
        // Swap under the lock, drop the replaced maps *outside* it: dropping
        // them frees every key and value, and lookups take this same lock from
        // inside the UDP receive loops, where a large table's deallocation
        // would stall intake.
        let old = {
            let mut m = self.maps.write().unwrap();
            std::mem::replace(
                &mut *m,
                Maps {
                    ptr,
                    fwd,
                    mod_times,
                },
            )
        };
        drop(old);
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
    // The mtime is recorded the moment the path is statable, *before* the read
    // is attempted. Every statable path must get an entry in `mod_times`, or
    // `files_changed` scores it as newly appeared on every poll and reloads
    // every watched file on every tick — which is what a path that stats but
    // cannot be read (a directory, a permission or I/O error) would do. The
    // trade is that a transient read failure is retried when the file's mtime
    // next changes, not on the next tick.
    record_mtime(&meta, path, Some(mod_times));
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
    // See `load_lease`: the mtime is recorded on stat, not on a successful read.
    record_mtime(&meta, path, mod_times);
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
}

/// Note `path`'s modification time in the watch table, if it has one and the
/// caller is tracking this file (auto-detected files are not watched).
fn record_mtime(
    meta: &std::fs::Metadata,
    path: &str,
    mod_times: Option<&mut HashMap<String, SystemTime>>,
) {
    if let (Some(table), Ok(mt)) = (mod_times, meta.modified()) {
        table.insert(path.to_string(), mt);
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
    fn name_filter_rejects_absent_accepts_inserted() {
        let f = NameFilter::new();
        let h = |name: &str| crate::util::hash(&name_to_wire(name, true).unwrap());
        assert!(
            !f.may_contain_hash(h("myhost.lan")),
            "empty filter rejects everything"
        );
        f.insert(&name_to_wire("myhost.lan", true).unwrap());
        assert!(f.may_contain_hash(h("myhost.lan")), "no false negatives");
        // A distinct name stays (deterministically, for this input) negative.
        assert!(!f.may_contain_hash(h("www.example.com")));
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

        let fwd = |name: &str| {
            let wire = name_to_wire(name, true).unwrap();
            r.lookup_ip(&wire, crate::util::hash(&wire))
        };
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

    /// A watched path that can be stat'ed but never read (a directory here, in
    /// practice also a permission or I/O error) must not be scored as "changed"
    /// on every poll — that would re-parse every watched file on every tick,
    /// forever. Change detection for the readable files must still work.
    #[test]
    fn unreadable_watched_file_does_not_force_endless_reloads() {
        let dir = std::env::temp_dir();
        let uniq = format!(
            "mppdns-unread-{}-{:p}",
            std::process::id(),
            &dir as *const _
        );
        let good = dir.join(format!("{uniq}.hosts"));
        let bad = dir.join(format!("{uniq}.baddir")); // statable, never readable
        std::fs::write(&good, "10.0.0.5 myhost.lan\n").unwrap();
        std::fs::create_dir_all(&bad).unwrap();

        let r = PtrResolver::new(
            vec![],
            vec![
                good.to_string_lossy().into_owned(),
                bad.to_string_lossy().into_owned(),
            ],
            false,
            &HashMap::new(),
        )
        .expect("resolver present");
        let fwd = |name: &str| {
            let wire = name_to_wire(name, true).unwrap();
            r.lookup_ip(&wire, crate::util::hash(&wire))
        };
        assert_eq!(
            fwd("myhost.lan"),
            vec![ip("10.0.0.5")],
            "the readable sibling is still loaded"
        );

        for i in 0..5 {
            assert!(
                !r.files_changed(),
                "quiet poll {i} reported a spurious change"
            );
        }

        // A genuine change to the readable file is still detected. The mtime is
        // set explicitly so the test does not depend on filesystem timestamp
        // granularity.
        std::fs::write(&good, "10.0.0.6 newhost.lan\n").unwrap();
        let f = std::fs::File::options().write(true).open(&good).unwrap();
        f.set_times(
            std::fs::FileTimes::new()
                .set_modified(SystemTime::now() + std::time::Duration::from_secs(120)),
        )
        .unwrap();
        drop(f);

        assert!(r.files_changed(), "a real mtime change must still be seen");
        r.check_reload();
        assert_eq!(fwd("newhost.lan"), vec![ip("10.0.0.6")]);
        assert!(fwd("myhost.lan").is_empty(), "old entry dropped");
        assert!(!r.files_changed(), "settles again after the reload");

        let _ = std::fs::remove_file(&good);
        let _ = std::fs::remove_dir(&bad);
    }

    /// The auto-detected hosts file must be watched like an explicit one. A
    /// file that is read on every reload but never *triggers* one only refreshes
    /// when some other watched file changes — and never at all when it is the
    /// only file, which is the default setup.
    #[test]
    fn auto_detected_hosts_file_is_watched() {
        if !std::path::Path::new("/etc/hosts").exists() {
            return; // nothing auto-detectable here
        }
        let r = PtrResolver::new(vec![], vec![], true, &HashMap::new())
            .expect("auto-detection finds /etc/hosts");
        assert!(
            r.watched_files().any(|f| f == "/etc/hosts"),
            "auto-detected hosts file must be in the watch set"
        );
        assert!(
            r.maps.read().unwrap().mod_times.contains_key("/etc/hosts"),
            "and must have an mtime recorded, or every poll reports a change"
        );
        assert!(!r.files_changed(), "so a quiet poll settles");
    }
}
