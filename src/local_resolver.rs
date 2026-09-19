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

/// Labels in the longest reverse name: 32 nibbles, then `ip6` and `arpa`.
const MAX_REVERSE_LABELS: usize = 34;

/// Reports whether a PTR query name, given in lower-cased wire form, is the
/// reverse name of a private, loopback, or link-local address.
pub fn is_private_ptr_name(name: &[u8]) -> bool {
    let mut labels: [&[u8]; MAX_REVERSE_LABELS] = [&[]; MAX_REVERSE_LABELS];
    let mut count = 0;
    let mut i = 0;
    loop {
        let Some(&len) = name.get(i) else {
            return false;
        };
        let len = usize::from(len);
        if len == 0 {
            break;
        }
        if count == MAX_REVERSE_LABELS {
            return false;
        }
        let Some(label) = name.get(i + 1..i + 1 + len) else {
            return false;
        };
        labels[count] = label;
        count += 1;
        i += 1 + len;
    }
    let Some((&b"arpa", rest)) = labels[..count].split_last() else {
        return false;
    };
    match rest.split_last() {
        Some((&b"in-addr", addr)) => ipv4_from_arpa_labels(addr)
            .is_some_and(|a| a.is_private() || a.is_link_local() || a.is_loopback()),
        Some((&b"ip6", addr)) => ipv6_from_arpa_labels(addr).is_some_and(v6_is_private_special),
        _ => false,
    }
}

/// The address named by the labels in front of `in-addr.arpa` (e.g. `132`,
/// `10`, `10`, `10`). Rejects a label count other than four, empty or
/// over-long labels, and octets over 255.
fn ipv4_from_arpa_labels(labels: &[&[u8]]) -> Option<Ipv4Addr> {
    if labels.len() != 4 {
        return None;
    }
    let mut out = [0u8; 4];
    for (i, label) in labels.iter().enumerate() {
        if label.is_empty() || label.len() > 3 || !label.iter().all(u8::is_ascii_digit) {
            return None;
        }
        let v = label
            .iter()
            .fold(0u16, |acc, d| acc * 10 + u16::from(d - b'0'));
        if v > 255 {
            return None;
        }
        // Labels appear low-order first; index 3 receives the first label so
        // the result ends up in big-endian (wire) order.
        out[3 - i] = v as u8;
    }
    Some(Ipv4Addr::from(out))
}

/// The address named by the 32 nibble labels in front of `ip6.arpa`.
fn ipv6_from_arpa_labels(labels: &[&[u8]]) -> Option<Ipv6Addr> {
    if labels.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (i, label) in labels.iter().enumerate() {
        let &[c] = *label else {
            return None;
        };
        let v = hex_nibble(c)?;
        // The first label is the lowest nibble; reverse into bytes16.
        let byte_idx = 15 - i / 2;
        if i % 2 == 0 {
            bytes[byte_idx] |= v;
        } else {
            bytes[byte_idx] |= v << 4;
        }
    }
    Some(Ipv6Addr::from(bytes))
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
    /// What `lookup` probes: lease entries, then hosts entries, then statics.
    ptr: HashMap<Vec<u8>, String>, // wire-lower(arpa) -> hostname
    /// What `lookup_ip` probes. Only hosts files and `[hosts]` feed it, and it
    /// is the table that can get large, so it is never rebuilt for a lease
    /// change.
    fwd: HashMap<Vec<u8>, Vec<IpAddr>>, // wire-lower(name) -> ips
    /// Each source's own contribution to `ptr`, so either can be rebuilt
    /// without re-reading the other. Both are keyed by address rather than by
    /// name, so they stay small even when a hosts file holds a million names.
    lease_ptr: HashMap<Vec<u8>, String>,
    hosts_ptr: HashMap<Vec<u8>, String>,
    lease_times: HashMap<String, SystemTime>, // watched path -> mtime
    hosts_times: HashMap<String, SystemTime>,
}

/// Which group of files a poll found changed.
#[derive(Clone, Copy)]
struct Changed {
    lease: bool,
    hosts: bool,
}

impl Changed {
    fn all() -> Self {
        Changed {
            lease: true,
            hosts: true,
        }
    }

    fn any(&self) -> bool {
        self.lease || self.hosts
    }
}

/// Whether any watched path's modification time differs from what was recorded
/// when it was last read.
fn group_changed(files: &[&String], recorded: &HashMap<String, SystemTime>) -> bool {
    files.iter().any(|f| {
        // Stat outside the lock so disk I/O never blocks readers.
        let cur = std::fs::metadata(f).and_then(|m| m.modified()).ok();
        match (cur, recorded.get(*f).copied()) {
            (None, Some(_)) => true,      // disappeared
            (Some(_), None) => true,      // appeared
            (Some(c), Some(p)) => c != p, // changed
            (None, None) => false,
        }
    })
}

/// Bits a filter reserves per name. With k = 2 a freshly filled filter then
/// sits about an eighth full, i.e. ~1.4% false positives — each costing one
/// wasted map probe, never a wrong answer.
const FILTER_BITS_PER_NAME: usize = 16;

/// Bitmap bounds. The floor (8 KiB) covers the dozens-to-thousands of names a
/// lease/hosts table normally holds; the ceiling (1 MiB) covers the ~500k
/// names of an adblock-scale table, past which the table itself dwarfs the
/// filter.
const MIN_FILTER_BITS: usize = 1 << 16;
const MAX_FILTER_BITS: usize = 1 << 23;

/// How many filters [`FilterSet`] keeps live at once. Sizes at least double
/// from slot to slot, so the retained total stays under twice the newest
/// filter. Once the slots are spent the newest filter keeps absorbing names
/// and saturates, which only costs map probes.
const FILTER_SLOTS: usize = 4;

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
    /// One below the (power-of-two) bit count, masking a hash into range.
    mask: usize,
}

impl NameFilter {
    /// Bitmap size for a table of `names` names: the per-name reservation,
    /// rounded up to a power of two and held inside the bounds above.
    fn bits_for(names: usize) -> usize {
        names
            .saturating_mul(FILTER_BITS_PER_NAME)
            .checked_next_power_of_two()
            .unwrap_or(MAX_FILTER_BITS)
            .clamp(MIN_FILTER_BITS, MAX_FILTER_BITS)
    }

    fn with_bits(bits: usize) -> Self {
        debug_assert!(bits.is_power_of_two() && bits >= WORD_BITS);
        NameFilter {
            words: (0..bits / WORD_BITS).map(|_| AtomicUsize::new(0)).collect(),
            mask: bits - 1,
        }
    }

    fn bits(&self) -> usize {
        self.mask + 1
    }

    /// The two bit positions for a name hash (`util::hash` of the wire
    /// name): low and high halves of the one hash.
    fn bits_of(&self, h: u64) -> [usize; 2] {
        [h as usize & self.mask, (h >> 32) as usize & self.mask]
    }

    fn insert_hash(&self, h: u64) {
        for i in self.bits_of(h) {
            self.words[i / WORD_BITS].fetch_or(1 << (i % WORD_BITS), Ordering::Relaxed);
        }
    }

    fn may_contain_hash(&self, h: u64) -> bool {
        self.bits_of(h).into_iter().all(|i| {
            self.words[i / WORD_BITS].load(Ordering::Relaxed) & (1 << (i % WORD_BITS)) != 0
        })
    }
}

/// The filter lookups test against, plus the ones earlier reloads published.
/// A filter cannot be resized in place and a lookup reads it without a lock,
/// so a table that outgrows its filter gets a bigger one in a fresh slot and
/// the outgrown ones stay live — a lookup that read the old index keeps a
/// valid filter, and every live filter is fed every name, so growing can
/// never turn a present name negative.
struct FilterSet {
    slots: [std::sync::OnceLock<NameFilter>; FILTER_SLOTS],
    /// Index of the published filter; `usize::MAX` until the first load.
    active: AtomicUsize,
}

impl FilterSet {
    fn new() -> Self {
        FilterSet {
            slots: [const { std::sync::OnceLock::new() }; FILTER_SLOTS],
            active: AtomicUsize::new(usize::MAX),
        }
    }

    /// The filter to test against, absent only before the first load.
    fn active(&self) -> Option<&NameFilter> {
        self.slots.get(self.active.load(Ordering::Acquire))?.get()
    }

    /// Feed every name of the table about to be published into every live
    /// filter, first growing into a fresh slot when the active filter is too
    /// small for the table. Call this *before* publishing the table, so a
    /// lookup that sees a name in the table also sees its bits.
    fn refill<'a>(&self, names: impl Iterator<Item = &'a [u8]>, count: usize) {
        let cur = self.active.load(Ordering::Relaxed);
        let want = NameFilter::bits_for(count);
        // `usize::MAX` wraps to 0, so the first load publishes slot 0.
        let next = cur.wrapping_add(1);
        let grow = next < FILTER_SLOTS
            && self
                .slots
                .get(cur)
                .and_then(std::sync::OnceLock::get)
                .is_none_or(|f| f.bits() < want);
        if grow {
            self.slots[next].get_or_init(|| NameFilter::with_bits(want));
        }
        for name in names {
            let h = crate::util::hash(name);
            for f in self.slots.iter().filter_map(std::sync::OnceLock::get) {
                f.insert_hash(h);
            }
        }
        if grow {
            // Published only now that it holds every name of the table.
            self.active.store(next, Ordering::Release);
        }
    }
}

/// Addresses a name resolves to, copied out of the table. A hosts or lease
/// entry names a handful of addresses, so the copy stays on the caller's
/// stack; a longer entry spills to the heap rather than losing addresses.
const INLINE_IPS: usize = 8;

pub enum Ips {
    Inline {
        buf: [IpAddr; INLINE_IPS],
        len: usize,
    },
    Spilled(Vec<IpAddr>),
}

impl Ips {
    fn empty() -> Self {
        Ips::Inline {
            buf: [IpAddr::V4(Ipv4Addr::UNSPECIFIED); INLINE_IPS],
            len: 0,
        }
    }

    fn copied(ips: &[IpAddr]) -> Self {
        if ips.len() > INLINE_IPS {
            return Ips::Spilled(ips.to_vec());
        }
        let mut buf = [IpAddr::V4(Ipv4Addr::UNSPECIFIED); INLINE_IPS];
        buf[..ips.len()].copy_from_slice(ips);
        Ips::Inline {
            buf,
            len: ips.len(),
        }
    }

    pub fn as_slice(&self) -> &[IpAddr] {
        match self {
            Ips::Inline { buf, len } => &buf[..*len],
            Ips::Spilled(v) => v,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }

    /// Drop the addresses `keep` rejects, preserving the order of the rest.
    pub fn retain(&mut self, keep: impl Fn(IpAddr) -> bool) {
        match self {
            Ips::Inline { buf, len } => {
                let mut kept = 0;
                for i in 0..*len {
                    if keep(buf[i]) {
                        buf[kept] = buf[i];
                        kept += 1;
                    }
                }
                *len = kept;
            }
            Ips::Spilled(v) => v.retain(|ip| keep(*ip)),
        }
    }
}

/// Which group's default paths to probe, for the groups the config named no
/// file of its own. The two are independent — naming a lease file does not
/// silence the hosts default, and `[hosts]` entries overlay the hosts files
/// rather than replacing them — which is what the ReadMe documents.
pub struct AutoDetect {
    pub lease: bool,
    pub hosts: bool,
}
impl AutoDetect {
    /// Probe neither group.
    #[cfg(test)]
    pub fn none() -> Self {
        AutoDetect {
            lease: false,
            hosts: false,
        }
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
    fwd_filter: FilterSet,
}

impl PtrResolver {
    /// Build a resolver, auto-detecting default lease/hosts paths when neither
    /// lease nor hosts files were explicitly configured. Returns None when
    /// there is nothing to resolve.
    pub fn new(
        mut lease_files: Vec<String>,
        hosts_files: Vec<String>,
        auto: AutoDetect,
        static_hosts: &HashMap<String, Vec<IpAddr>>,
    ) -> Option<PtrResolver> {
        let mut auto_hosts_files = Vec::new();
        if auto.lease {
            for f in DEFAULT_LEASE_FILES {
                if std::path::Path::new(f).exists() {
                    lease_files.push((*f).to_string());
                }
            }
        }
        if auto.hosts {
            for f in DEFAULT_HOSTS_FILES {
                if std::path::Path::new(f).exists() {
                    auto_hosts_files.push((*f).to_string());
                }
            }
        }
        if lease_files.is_empty()
            && hosts_files.is_empty()
            && auto_hosts_files.is_empty()
            && static_hosts.is_empty()
        {
            return None;
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
            fwd_filter: FilterSet::new(),
        };
        r.reload(Changed::all());
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
    ///
    /// The addresses are copied out rather than borrowed: the answer is built
    /// after the lock is released, and a reload may replace the table in
    /// between.
    pub fn lookup_ip(&self, qname_lower: &[u8], name_hash: u64) -> Ips {
        if self
            .fwd_filter
            .active()
            .is_some_and(|f| !f.may_contain_hash(name_hash))
        {
            return Ips::empty();
        }
        match self.maps.read().unwrap().fwd.get(qname_lower) {
            Some(ips) => Ips::copied(ips),
            None => Ips::empty(),
        }
    }

    /// Reload if any watched file changed. Runs blocking file IO — call it
    /// from the background watcher task, never from the query path.
    pub fn check_reload(&self) {
        let what = self.changed();
        if what.any() {
            self.reload(what);
        }
    }

    /// The hosts files this resolver reads: the configured ones plus anything
    /// auto-detection turned up. Auto-detected files are watched like the rest —
    /// `/etc/hosts` is documented as hot-reloading, and a file that is read but
    /// not watched only refreshes when some *other* watched file changes.
    fn hosts_group(&self) -> Vec<&String> {
        self.hosts_files
            .iter()
            .chain(self.auto_hosts_files.iter())
            .collect()
    }

    /// Which group of watched files changed since it was last read.
    fn changed(&self) -> Changed {
        let lease: Vec<&String> = self.lease_files.iter().collect();
        let hosts = self.hosts_group();
        let m = self.maps.read().unwrap();
        Changed {
            lease: group_changed(&lease, &m.lease_times),
            hosts: group_changed(&hosts, &m.hosts_times),
        }
    }

    #[cfg(test)]
    fn files_changed(&self) -> bool {
        self.changed().any()
    }

    /// Rebuild the tables fed by the groups named in `what`, leaving the other
    /// group's as they are. A DHCP server rewrites its lease file constantly,
    /// and re-parsing a large hosts table on every one of those is the cost this
    /// split avoids.
    fn reload(&self, what: Changed) {
        let mut lease_times = None;
        let lease_ptr = if what.lease {
            let (mut p, mut t) = (HashMap::new(), HashMap::new());
            for f in &self.lease_files {
                load_lease(f, &mut p, &mut t);
            }
            lease_times = Some(t);
            p
        } else {
            self.maps.read().unwrap().lease_ptr.clone()
        };

        let mut hosts_times = None;
        let mut new_fwd = None;
        let hosts_ptr = if what.hosts {
            let (mut p, mut fwd, mut t) = (HashMap::new(), HashMap::new(), HashMap::new());
            for f in self.hosts_files.iter().chain(self.auto_hosts_files.iter()) {
                load_hosts(f, &mut p, &mut fwd, Some(&mut t));
            }
            // Static [hosts] entries always overlay file entries.
            for (k, v) in &self.static_fwd {
                fwd.insert(k.clone(), v.clone());
            }
            // Publish filter bits for every (possibly new) name BEFORE swapping
            // the table in, so a lookup that sees the table also sees the bits.
            self.fwd_filter
                .refill(fwd.keys().map(Vec::as_slice), fwd.len());
            hosts_times = Some(t);
            new_fwd = Some(fwd);
            p
        } else {
            self.maps.read().unwrap().hosts_ptr.clone()
        };

        // Merge the reverse view in priority order, off the lock.
        let mut ptr =
            HashMap::with_capacity(lease_ptr.len() + hosts_ptr.len() + self.static_ptr.len());
        for src in [&lease_ptr, &hosts_ptr, &self.static_ptr] {
            ptr.extend(src.iter().map(|(k, v)| (k.clone(), v.clone())));
        }

        // Swap under the lock, drop the replaced tables *outside* it: dropping
        // them frees every key and value, and lookups take this same lock from
        // inside the UDP receive loops, where a large table's deallocation
        // would stall intake.
        let old = {
            let mut m = self.maps.write().unwrap();
            m.lease_ptr = lease_ptr;
            m.hosts_ptr = hosts_ptr;
            if let Some(t) = lease_times {
                m.lease_times = t;
            }
            if let Some(t) = hosts_times {
                m.hosts_times = t;
            }
            let old_fwd = new_fwd.map(|f| std::mem::replace(&mut m.fwd, f));
            (std::mem::replace(&mut m.ptr, ptr), old_fwd)
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
                // The same address can be named twice (a repeated line, or one
                // name listed in several hosts files); a duplicate RR in the
                // answer is noise the client has to filter.
                let ips = fwd.entry(k).or_default();
                if !ips.contains(&ip) {
                    ips.push(ip);
                }
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
            let wire = name_to_wire(qname, true).unwrap();
            assert_eq!(is_private_ptr_name(&wire), want, "qname={qname}");
            assert_eq!(
                reference::is_private_ptr(qname),
                want,
                "reference, qname={qname}"
            );
        }
    }

    #[test]
    fn arpa_labels_edges() {
        let v4 = |s: &str| {
            let labels: Vec<&[u8]> = s.split('.').map(str::as_bytes).collect();
            ipv4_from_arpa_labels(&labels)
        };
        assert_eq!(v4("132.10.10.10"), Some(Ipv4Addr::new(10, 10, 10, 132)));
        assert_eq!(v4("1.2.3"), None); // too few
        assert_eq!(v4("1.2.3.4.5"), None); // too many
        assert_eq!(v4("256.1.1.1"), None); // out of range
        assert_eq!(v4("0010.1.1.1"), None); // over-long label
        assert_eq!(v4("a.1.1.1"), None); // non-digit
        assert_eq!(v4("01.0.0.10"), Some(Ipv4Addr::new(10, 0, 0, 1))); // leading zero
    }

    /// The string-based classification the wire form must agree with.
    mod reference {
        use super::super::hex_nibble;
        use crate::util::v6_is_private_special;
        use std::net::{Ipv4Addr, Ipv6Addr};

        pub fn is_private_ptr(qname: &str) -> bool {
            let mut qname = qname.to_ascii_lowercase();
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

        fn parse_ipv4_arpa_labels(s: &str) -> Option<[u8; 4]> {
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
                out[3 - i] = v as u8;
                count += 1;
            }
            if count != 4 {
                return None;
            }
            Some(out)
        }

        fn parse_ipv6_arpa_labels(s: &str) -> Option<[u8; 16]> {
            let mut bytes = [0u8; 16];
            let mut count = 0;
            for (i, label) in s.split('.').enumerate() {
                if i >= 32 || label.len() != 1 {
                    return None;
                }
                let v = hex_nibble(label.as_bytes()[0])?;
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
    }

    /// The wire-form classification runs on the query path; the string form it
    /// must agree with rendered the name first. Compared over reverse names of
    /// private and public addresses of both families, the same names with one
    /// byte replaced (by digits, hex letters in both cases, or characters a
    /// rendering escapes), and runs of random labels in front of the real
    /// suffixes and near misses.
    #[test]
    fn wire_form_private_ptr_agrees_with_the_rendered_form() {
        let mut state: u64 = 0x5eed_cafe_f00d_d00d;
        let mut rnd = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let alphabet: &[u8] = b"0123456789abcdefABCDEFgx.-\\ \x80";
        let suffixes: [&[&[u8]]; 7] = [
            &[b"in-addr", b"arpa"],
            &[b"ip6", b"arpa"],
            &[b"IN-ADDR", b"ARPA"],
            &[b"Ip6", b"Arpa"],
            &[b"arpa"],
            &[b"xin-addr", b"arpa"],
            &[b"in-addr", b"arpa", b"x"],
        ];
        let (mut private, mut public, mut total) = (0usize, 0usize, 0usize);
        for round in 0..200_000u32 {
            let mut wire = if round % 3 == 2 {
                // Random labels in front of a suffix.
                let suffix = suffixes[(rnd() % suffixes.len() as u64) as usize];
                let n_labels = match round % 4 {
                    0 => 4,
                    1 => 32,
                    _ => (rnd() % 36) as usize,
                };
                let mut wire = Vec::new();
                for _ in 0..n_labels {
                    let len = 1 + (rnd() % 4) as usize;
                    wire.push(len as u8);
                    for _ in 0..len {
                        wire.push(alphabet[(rnd() % alphabet.len() as u64) as usize]);
                    }
                }
                for label in suffix {
                    wire.push(label.len() as u8);
                    wire.extend_from_slice(label);
                }
                wire.push(0);
                wire
            } else {
                // The reverse name of an address that is private about half
                // the time.
                let r = rnd();
                let addr = if round % 3 == 0 {
                    let [a, b, c, d] = (r as u32).to_be_bytes();
                    IpAddr::V4(match r >> 32 & 7 {
                        0 => Ipv4Addr::new(10, b, c, d),
                        1 => Ipv4Addr::new(172, 16 | (b & 0x1f), c, d),
                        2 => Ipv4Addr::new(192, 168, c, d),
                        3 => Ipv4Addr::new(169, 254, c, d),
                        _ => Ipv4Addr::new(a, b, c, d),
                    })
                } else {
                    let mut o = [0u8; 16];
                    for (i, byte) in o.iter_mut().enumerate() {
                        *byte = (rnd() >> (i % 8)) as u8;
                    }
                    match r >> 32 & 7 {
                        0 => o[0] = 0xfc | (o[0] & 1),
                        1 => {
                            o[0] = 0xfe;
                            o[1] = 0x80 | (o[1] & 0x3f);
                        }
                        2 => o = Ipv6Addr::LOCALHOST.octets(),
                        _ => {}
                    }
                    IpAddr::V6(Ipv6Addr::from(o))
                };
                let mut text = ip_to_ptr_name(addr);
                if r >> 42 & 1 == 1 {
                    // Leading zeros on the octet labels: up to three digits
                    // still name the octet, a fourth makes the label invalid.
                    let mut bits = r >> 43;
                    text = text
                        .split('.')
                        .map(|l| {
                            let pad = (bits & 3) as usize;
                            bits >>= 2;
                            if l.bytes().all(|b| b.is_ascii_digit()) && l.len() <= 3 {
                                format!("{}{l}", "0".repeat(pad))
                            } else {
                                l.to_string()
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(".");
                }
                let mut wire = name_to_wire(&text, false).unwrap();
                if r >> 40 & 1 == 1 {
                    wire.make_ascii_uppercase();
                }
                if r >> 41 & 1 == 1 {
                    // One byte replaced; label length bytes are fair game too.
                    let at = (rnd() % (wire.len() as u64 - 1)) as usize;
                    wire[at] = alphabet[(rnd() % alphabet.len() as u64) as usize];
                }
                wire
            };
            wire.truncate(wire.len().min(255));
            let Ok(name) = Name::from_octets(wire.clone()) else {
                continue;
            };
            let mut lower = wire.clone();
            lower.make_ascii_lowercase();
            let want = reference::is_private_ptr(&name.to_string());
            assert_eq!(
                is_private_ptr_name(&lower),
                want,
                "disagreement on {:?} ({name})",
                wire
            );
            total += 1;
            if want {
                private += 1;
            } else {
                public += 1;
            }
        }
        assert!(total > 100_000, "only {total} names compared");
        assert!(private > 10_000, "only {private} private names compared");
        assert!(public > 20_000, "only {public} non-private names compared");
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn name_filter_rejects_absent_accepts_inserted() {
        let f = NameFilter::with_bits(MIN_FILTER_BITS);
        let h = |name: &str| crate::util::hash(&name_to_wire(name, true).unwrap());
        assert!(
            !f.may_contain_hash(h("myhost.lan")),
            "empty filter rejects everything"
        );
        f.insert_hash(h("myhost.lan"));
        assert!(f.may_contain_hash(h("myhost.lan")), "no false negatives");
        // A distinct name stays (deterministically, for this input) negative.
        assert!(!f.may_contain_hash(h("www.example.com")));
    }

    #[test]
    fn an_address_list_spills_only_past_the_inline_capacity() {
        let v4 = |i: usize| IpAddr::V4(Ipv4Addr::new(10, 0, (i / 256) as u8, i as u8));
        for n in [0usize, 1, INLINE_IPS - 1, INLINE_IPS, INLINE_IPS + 1, 300] {
            let ips: Vec<IpAddr> = (0..n).map(v4).collect();
            let copied = Ips::copied(&ips);
            assert_eq!(copied.as_slice(), ips.as_slice(), "n={n}");
            assert_eq!(copied.is_empty(), n == 0, "n={n}");
            assert_eq!(
                matches!(copied, Ips::Spilled(_)),
                n > INLINE_IPS,
                "n={n}: spilled when it need not, or lost addresses"
            );
        }
    }

    #[test]
    fn retaining_addresses_keeps_the_rest_in_order() {
        let v4 = |i: usize| IpAddr::V4(Ipv4Addr::new(10, 0, 0, i as u8));
        let v6 = |i: usize| IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i as u16));
        // Both storage forms: interleaved so a wrong compaction reorders.
        for n in [4usize, INLINE_IPS * 3] {
            let mixed: Vec<IpAddr> = (0..n)
                .map(|i| if i % 2 == 0 { v4(i) } else { v6(i) })
                .collect();
            let mut ips = Ips::copied(&mixed);
            ips.retain(|ip| ip.is_ipv4());
            let want: Vec<IpAddr> = mixed.iter().copied().filter(IpAddr::is_ipv4).collect();
            assert_eq!(ips.as_slice(), want.as_slice(), "n={n}");
            ips.retain(|ip| !ip.is_ipv4());
            assert!(ips.is_empty(), "n={n}");
        }
    }

    #[test]
    fn filter_size_follows_the_table_within_its_bounds() {
        assert_eq!(NameFilter::bits_for(0), MIN_FILTER_BITS);
        assert_eq!(NameFilter::bits_for(1), MIN_FILTER_BITS);
        // Tables the floor already covers keep the floor.
        assert_eq!(
            NameFilter::bits_for(MIN_FILTER_BITS / FILTER_BITS_PER_NAME),
            MIN_FILTER_BITS
        );
        assert_eq!(NameFilter::bits_for(usize::MAX), MAX_FILTER_BITS);
        let mut prev = 0;
        for names in [0, 1_000, 10_000, 100_000, 1_000_000, 10_000_000] {
            let bits = NameFilter::bits_for(names);
            assert!(bits.is_power_of_two(), "{names} names -> {bits} bits");
            assert!(bits >= prev, "must not shrink as the table grows");
            assert!(
                bits >= (names * FILTER_BITS_PER_NAME).min(MAX_FILTER_BITS),
                "{names} names get too few bits"
            );
            prev = bits;
        }
    }

    /// Wire names for a generated table, distinct across `tag`.
    fn table_names(tag: &str, count: usize) -> Vec<Vec<u8>> {
        (0..count)
            .map(|i| name_to_wire(&format!("n{i}.{tag}.lan"), true).unwrap())
            .collect()
    }

    #[test]
    fn a_big_table_gets_a_filter_that_still_rejects() {
        let names = table_names("big", 100_000);
        let set = FilterSet::new();
        set.refill(names.iter().map(Vec::as_slice), names.len());
        let f = set.active().expect("a load published a filter");
        assert_eq!(f.bits(), NameFilter::bits_for(names.len()));
        for n in &names {
            assert!(
                f.may_contain_hash(crate::util::hash(n)),
                "no false negatives"
            );
        }
        let absent = table_names("absent", 100_000);
        let fp = absent
            .iter()
            .filter(|n| f.may_contain_hash(crate::util::hash(n)))
            .count();
        // ~1.4% by construction. The bound sits below what this table would
        // give from a single hash bit, so a filter that is undersized or
        // weakened fails here instead of quietly costing a probe per query.
        assert!(
            fp * 50 < absent.len(),
            "{fp} false positives in 100k probes"
        );
    }

    #[test]
    fn a_growing_table_keeps_every_filter_answering_for_it() {
        let set = FilterSet::new();
        let mut live: Vec<usize> = Vec::new();
        let mut all: Vec<Vec<u8>> = Vec::new();
        // Each round's table is the previous one plus enough names to outgrow
        // its filter, which is what makes the set grow into a fresh slot.
        for round in 0..FILTER_SLOTS + 2 {
            all.extend(table_names(&format!("r{round}"), 2_000 << round));
            set.refill(all.iter().map(Vec::as_slice), all.len());
            let bits = set.active().expect("published").bits();
            assert!(
                live.last().is_none_or(|&b| bits >= b),
                "round {round} shrank the filter"
            );
            live.push(bits);
            // Every filter a lookup could still be holding answers for the
            // whole current table, so growth cannot make a name look absent.
            for slot in set.slots.iter().filter_map(std::sync::OnceLock::get) {
                for n in &all {
                    assert!(
                        slot.may_contain_hash(crate::util::hash(n)),
                        "round {round}: a live filter lost a name"
                    );
                }
            }
        }
        assert_eq!(
            set.slots.iter().filter(|s| s.get().is_some()).count(),
            FILTER_SLOTS,
            "growth stops once the slots are spent"
        );
        // Reloads of a table its filter already fits must not spend a slot:
        // the slots exist for growth, and there are only so many.
        let spent = FilterSet::new();
        let small = table_names("small", 100);
        for _ in 0..5 {
            spent.refill(small.iter().map(Vec::as_slice), small.len());
        }
        assert_eq!(spent.active.load(Ordering::Relaxed), 0);
        assert_eq!(spent.slots.iter().filter(|s| s.get().is_some()).count(), 1);
        assert_eq!(
            set.active.load(Ordering::Relaxed),
            FILTER_SLOTS - 1,
            "the newest slot stays published"
        );
    }

    #[test]
    fn a_lookup_before_the_first_load_is_not_filtered_out() {
        // `active()` is None only in that window; a None filter must mean
        // "ask the table", never "absent".
        let set = FilterSet::new();
        assert!(set.active().is_none());
        let wire = name_to_wire("myhost.lan", true).unwrap();
        set.refill(std::iter::once(wire.as_slice()), 1);
        assert!(set
            .active()
            .expect("published")
            .may_contain_hash(crate::util::hash(&wire)));
    }

    #[test]
    fn a_name_listed_twice_answers_with_one_record_per_address() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("mppdns-dup-{}.hosts", std::process::id()));
        // The same pair twice (a repeated line), then a second address for the
        // same name, which is a real second record.
        std::fs::write(
            &path,
            "10.0.0.5 dup.lan\n10.0.0.5 dup.lan alias.lan\n10.0.0.6 dup.lan\n",
        )
        .unwrap();
        let r = PtrResolver::new(
            vec![],
            vec![path.to_string_lossy().into_owned()],
            AutoDetect::none(),
            &HashMap::new(),
        )
        .expect("resolver present");
        let wire = name_to_wire("dup.lan", true).unwrap();
        let ips = r.lookup_ip(&wire, crate::util::hash(&wire));
        assert_eq!(
            ips.as_slice(),
            [ip("10.0.0.5"), ip("10.0.0.6")],
            "a repeated line must not become a repeated record"
        );
        let alias = name_to_wire("alias.lan", true).unwrap();
        assert_eq!(
            r.lookup_ip(&alias, crate::util::hash(&alias)).as_slice(),
            [ip("10.0.0.5")]
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn config_entries_do_not_switch_off_the_hosts_file_default() {
        if !std::path::Path::new("/etc/hosts").exists() {
            return; // nothing auto-detectable here
        }
        // The ReadMe promises `/etc/hosts` whenever `hosts_file` is unset, and
        // `[hosts]` entries that overlay it rather than replace it.
        let mut statics: HashMap<String, Vec<IpAddr>> = HashMap::new();
        statics.insert("static.lan.".to_string(), vec![ip("172.16.0.9")]);
        let r = PtrResolver::new(
            vec![],
            vec![],
            AutoDetect {
                lease: false,
                hosts: true,
            },
            &statics,
        )
        .expect("resolver present");
        assert!(
            r.hosts_group().iter().any(|f| *f == "/etc/hosts"),
            "[hosts] entries must not switch off the /etc/hosts default"
        );
        let wire = name_to_wire("static.lan", true).unwrap();
        assert_eq!(
            r.lookup_ip(&wire, crate::util::hash(&wire)).as_slice(),
            [ip("172.16.0.9")],
            "and the config entries still resolve"
        );
    }

    #[test]
    fn naming_one_group_leaves_the_other_groups_default_alone() {
        if !std::path::Path::new("/etc/hosts").exists() {
            return;
        }
        // Naming a lease file says nothing about hosts files.
        let lease = std::env::temp_dir().join(format!("mppdns-b12-{}.leases", std::process::id()));
        std::fs::write(
            &lease,
            "1700000000 aa:bb:cc:dd:ee:ff 192.168.1.50 leasehost *\n",
        )
        .unwrap();
        let r = PtrResolver::new(
            vec![lease.to_string_lossy().into_owned()],
            vec![],
            AutoDetect {
                lease: false,
                hosts: true,
            },
            &HashMap::new(),
        )
        .expect("resolver present");
        assert!(r.hosts_group().iter().any(|f| *f == "/etc/hosts"));
        assert_eq!(
            r.lookup(&name_to_wire(&ip_to_ptr_name_str("192.168.1.50"), true).unwrap())
                .as_deref(),
            Some("leasehost"),
            "the named lease file is still read"
        );
        let _ = std::fs::remove_file(&lease);
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
            AutoDetect::none(),
            &statics,
        )
        .expect("resolver present");

        let fwd = |name: &str| {
            let wire = name_to_wire(name, true).unwrap();
            r.lookup_ip(&wire, crate::util::hash(&wire))
                .as_slice()
                .to_vec()
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
        r.reload(Changed::all());
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
            AutoDetect::none(),
            &HashMap::new(),
        )
        .expect("resolver present");
        let fwd = |name: &str| {
            let wire = name_to_wire(name, true).unwrap();
            r.lookup_ip(&wire, crate::util::hash(&wire))
                .as_slice()
                .to_vec()
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
        let r = PtrResolver::new(
            vec![],
            vec![],
            AutoDetect {
                lease: true,
                hosts: true,
            },
            &HashMap::new(),
        )
        .expect("auto-detection finds /etc/hosts");
        assert!(
            r.hosts_group().iter().any(|f| *f == "/etc/hosts"),
            "auto-detected hosts file must be in the watch set"
        );
        assert!(
            r.maps
                .read()
                .unwrap()
                .hosts_times
                .contains_key("/etc/hosts"),
            "and must have an mtime recorded, or every poll reports a change"
        );
        assert!(!r.files_changed(), "so a quiet poll settles");
    }

    /// Set `path`'s modification time explicitly, so a test never depends on
    /// filesystem timestamp granularity.
    fn set_mtime(path: &std::path::Path, t: SystemTime) {
        let f = std::fs::File::options().write(true).open(path).unwrap();
        f.set_times(std::fs::FileTimes::new().set_modified(t))
            .unwrap();
    }

    /// A DHCP server rewrites its lease file constantly. Those reloads must not
    /// re-read the hosts files, which is where a large table would be.
    ///
    /// Proven by editing the hosts file's *content* while restoring its mtime,
    /// so it still looks untouched: if a lease-only reload re-read it, the new
    /// content would show up.
    #[test]
    fn a_lease_change_does_not_re_read_the_hosts_files() {
        let dir = std::env::temp_dir();
        let uniq = format!("mppdns-split-{}-{:p}", std::process::id(), &dir as *const _);
        let lease = dir.join(format!("{uniq}.leases"));
        let hosts = dir.join(format!("{uniq}.hosts"));
        std::fs::write(
            &lease,
            "1700000000 aa:bb:cc:dd:ee:ff 192.168.1.50 leasehost *\n",
        )
        .unwrap();
        std::fs::write(&hosts, "10.0.0.5 myhost.lan\n").unwrap();

        let r = PtrResolver::new(
            vec![lease.to_string_lossy().into_owned()],
            vec![hosts.to_string_lossy().into_owned()],
            AutoDetect::none(),
            &HashMap::new(),
        )
        .expect("resolver present");
        let fwd = |name: &str| {
            let wire = name_to_wire(name, true).unwrap();
            r.lookup_ip(&wire, crate::util::hash(&wire))
                .as_slice()
                .to_vec()
        };
        let rev = |ipstr: &str| r.lookup(&name_to_wire(&ip_to_ptr_name_str(ipstr), true).unwrap());
        assert_eq!(fwd("myhost.lan"), vec![ip("10.0.0.5")]);
        assert_eq!(rev("192.168.1.50").as_deref(), Some("leasehost"));

        // Rewrite the hosts file but put its mtime back: to the watcher it is
        // unchanged.
        let hosts_mtime = std::fs::metadata(&hosts).unwrap().modified().unwrap();
        std::fs::write(&hosts, "10.0.0.9 newhost.lan\n").unwrap();
        set_mtime(&hosts, hosts_mtime);

        // Now make the lease file genuinely change.
        std::fs::write(
            &lease,
            "1700000000 aa:bb:cc:dd:ee:ff 192.168.1.51 movedhost *\n",
        )
        .unwrap();
        set_mtime(
            &lease,
            SystemTime::now() + std::time::Duration::from_secs(120),
        );
        r.check_reload();

        // The lease side is up to date...
        assert_eq!(rev("192.168.1.51").as_deref(), Some("movedhost"));
        assert!(rev("192.168.1.50").is_none(), "old lease entry dropped");
        // ...and the hosts side was not re-read.
        assert_eq!(
            fwd("myhost.lan"),
            vec![ip("10.0.0.5")],
            "a lease-only reload must not re-parse the hosts files"
        );
        assert!(fwd("newhost.lan").is_empty());

        // A real hosts change is still picked up, and the lease side survives it.
        set_mtime(
            &hosts,
            SystemTime::now() + std::time::Duration::from_secs(240),
        );
        r.check_reload();
        assert_eq!(fwd("newhost.lan"), vec![ip("10.0.0.9")]);
        assert!(fwd("myhost.lan").is_empty());
        assert_eq!(rev("192.168.1.51").as_deref(), Some("movedhost"));

        // And the watch settles afterwards.
        assert!(!r.files_changed());

        let _ = std::fs::remove_file(&lease);
        let _ = std::fs::remove_file(&hosts);
    }

    /// Reverse lookups resolve one address to one name, so the three sources
    /// have to have a defined precedence: `[hosts]` config beats a hosts file,
    /// which beats a DHCP lease.
    #[test]
    fn reverse_lookup_precedence_is_config_then_hosts_then_lease() {
        let dir = std::env::temp_dir();
        let uniq = format!("mppdns-prio-{}-{:p}", std::process::id(), &dir as *const _);
        let lease = dir.join(format!("{uniq}.leases"));
        let hosts = dir.join(format!("{uniq}.hosts"));
        // All three name 10.0.0.7; only one can answer its PTR.
        std::fs::write(
            &lease,
            "1700000000 aa:bb:cc:dd:ee:ff 10.0.0.7 leasename *\n",
        )
        .unwrap();
        std::fs::write(&hosts, "10.0.0.7 hostsname.lan\n10.0.0.8 leaseless.lan\n").unwrap();
        let mut statics: HashMap<String, Vec<IpAddr>> = HashMap::new();
        statics.insert("configname.lan.".to_string(), vec![ip("10.0.0.7")]);

        let r = PtrResolver::new(
            vec![lease.to_string_lossy().into_owned()],
            vec![hosts.to_string_lossy().into_owned()],
            AutoDetect::none(),
            &statics,
        )
        .expect("resolver present");
        let rev = |ipstr: &str| r.lookup(&name_to_wire(&ip_to_ptr_name_str(ipstr), true).unwrap());

        assert_eq!(
            rev("10.0.0.7").as_deref(),
            Some("configname.lan"),
            "a [hosts] entry outranks both files"
        );
        // With the config entry out of the way, the hosts file outranks the lease.
        let r2 = PtrResolver::new(
            vec![lease.to_string_lossy().into_owned()],
            vec![hosts.to_string_lossy().into_owned()],
            AutoDetect::none(),
            &HashMap::new(),
        )
        .expect("resolver present");
        let rev2 =
            |ipstr: &str| r2.lookup(&name_to_wire(&ip_to_ptr_name_str(ipstr), true).unwrap());
        assert_eq!(rev2("10.0.0.7").as_deref(), Some("hostsname.lan"));
        assert_eq!(rev2("10.0.0.8").as_deref(), Some("leaseless.lan"));

        let _ = std::fs::remove_file(&lease);
        let _ = std::fs::remove_file(&hosts);
    }
}
