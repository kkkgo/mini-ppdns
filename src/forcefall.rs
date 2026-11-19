// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

//! force_fall client matching.
//!
//! Include rules (no `^`) use OR logic: any match triggers force_fall.
//! Negate rules (`^` prefix) use AND logic: the client IP must NOT be in ANY
//! negated prefix for force_fall to trigger. When both kinds are present,
//! include rules are checked first and take precedence.

use std::net::{IpAddr, Ipv4Addr};

/// A CIDR prefix. The base address is stored as parsed (not masked); the
/// host bits are dropped when the matcher turns it into a range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpPrefix {
    addr: IpAddr,
    bits: u8,
}

/// Network mask of an IPv4 prefix length (lengths past 32 mean the whole
/// address).
fn mask4(bits: u8) -> u32 {
    u32::MAX
        .checked_shl(32 - u32::from(bits.min(32)))
        .unwrap_or(0)
}

/// Network mask of an IPv6 prefix length (lengths past 128 mean the whole
/// address).
fn mask6(bits: u8) -> u128 {
    u128::MAX
        .checked_shl(128 - u32::from(bits.min(128)))
        .unwrap_or(0)
}

impl IpPrefix {
    pub fn new(addr: IpAddr, bits: u8) -> Self {
        IpPrefix { addr, bits }
    }

    /// Reports whether `ip` falls inside this prefix; false when the address
    /// families differ. The matcher answers the same question from its
    /// compiled ranges; this direct form is the reference they are checked
    /// against.
    #[cfg(test)]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = mask4(self.bits);
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = mask6(self.bits);
                (u128::from(net) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.bits)
    }
}

/// Inclusive address ranges sorted by start, with overlapping ones merged.
/// The ranges are then disjoint and their ends ascend too, so the only range
/// that can hold an address is the last one starting at or below it.
#[derive(Debug, Clone)]
struct Ranges<T>(Box<[(T, T)]>);

impl<T> Default for Ranges<T> {
    fn default() -> Self {
        Ranges(Box::new([]))
    }
}

impl<T: Copy + Ord> Ranges<T> {
    fn new(mut ranges: Vec<(T, T)>) -> Self {
        // Rule lists are short and compiled once at startup, so a plain
        // insertion sort does; a library sort adds kilobytes of code per
        // element type to a binary that ships to small flash.
        for i in 1..ranges.len() {
            let mut j = i;
            while j > 0 && ranges[j - 1] > ranges[j] {
                ranges.swap(j - 1, j);
                j -= 1;
            }
        }
        let mut merged: Vec<(T, T)> = Vec::with_capacity(ranges.len());
        for (start, end) in ranges {
            match merged.last_mut() {
                Some(last) if start <= last.1 => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        Ranges(merged.into_boxed_slice())
    }

    fn contains(&self, x: T) -> bool {
        let after = self.0.partition_point(|&(start, _)| start <= x);
        after.checked_sub(1).is_some_and(|i| x <= self.0[i].1)
    }
}

/// The IPv4 and IPv6 ranges a prefix list covers.
fn ranges_of(prefixes: &[IpPrefix]) -> (Ranges<u32>, Ranges<u128>) {
    let (mut v4, mut v6) = (Vec::new(), Vec::new());
    for p in prefixes {
        match p.addr {
            IpAddr::V4(a) => {
                let mask = mask4(p.bits);
                let start = u32::from(a) & mask;
                v4.push((start, start | !mask));
            }
            IpAddr::V6(a) => {
                let mask = mask6(p.bits);
                let start = u128::from(a) & mask;
                v6.push((start, start | !mask));
            }
        }
    }
    (Ranges::new(v4), Ranges::new(v6))
}

/// force_fall matcher: include prefixes (OR) and negate prefixes (AND).
///
/// It runs for every query that reaches the cache, so the prefixes are
/// compiled into merged ranges per family up front and a client costs one
/// binary search per list, however many prefixes the rules expand to (an
/// address range alone can expand to dozens).
#[derive(Default, Debug, Clone)]
pub struct ForceFallMatcher {
    include4: Ranges<u32>,
    include6: Ranges<u128>,
    negate4: Ranges<u32>,
    negate6: Ranges<u128>,
    /// Whether any negate rule exists, of either family. Once one does, a
    /// client no rule names is forced — a client of the other family too,
    /// since no negate prefix can contain it.
    negates: bool,
    /// Whether there is any rule at all. Most configurations have none, and
    /// then no client is forced, without looking at its address.
    rules: bool,
}

impl ForceFallMatcher {
    pub fn new(include: &[IpPrefix], negate: &[IpPrefix]) -> Self {
        let (include4, include6) = ranges_of(include);
        let (negate4, negate6) = ranges_of(negate);
        ForceFallMatcher {
            include4,
            include6,
            negate4,
            negate6,
            negates: !negate.is_empty(),
            rules: !include.is_empty() || !negate.is_empty(),
        }
    }

    /// Reports whether `addr` should be forced onto the fallback DNS.
    pub fn matches(&self, addr: IpAddr) -> bool {
        if !self.rules {
            return false;
        }
        match addr {
            IpAddr::V4(ip) => {
                let x = u32::from(ip);
                self.include4.contains(x) || (self.negates && !self.negate4.contains(x))
            }
            IpAddr::V6(ip) => {
                let x = u128::from(ip);
                self.include6.contains(x) || (self.negates && !self.negate6.contains(x))
            }
        }
    }
}

/// Parse a `a.b.c.d/nn` (or IPv6) CIDR string. Rejects out-of-range prefix
/// lengths and non-numeric lengths, matching `netip.ParsePrefix`.
pub fn parse_prefix(s: &str) -> Result<IpPrefix, String> {
    let (addr_str, bits_str) = s
        .split_once('/')
        .ok_or_else(|| format!("invalid CIDR {s}: missing '/'"))?;
    let addr: IpAddr = addr_str
        .parse()
        .map_err(|_| format!("invalid CIDR {s}: bad address"))?;
    let bits: u16 = bits_str
        .parse()
        .map_err(|_| format!("invalid CIDR {s}: bad prefix length"))?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    if bits > max {
        return Err(format!("invalid CIDR {s}: prefix length out of range"));
    }
    Ok(IpPrefix::new(addr, bits as u8))
}

/// Parsed result of a single force_fall entry.
pub struct ForceFallEntry {
    pub prefixes: Vec<IpPrefix>,
    pub negated: bool,
}

/// Parse a single force_fall entry: single IP, CIDR, or `start-end` range,
/// with an optional leading `^` for negation. An empty entry yields no
/// prefixes and is not an error.
pub fn parse_force_fall_entry(s: &str) -> Result<ForceFallEntry, String> {
    let mut s = s.trim();
    let mut negated = false;
    if let Some(rest) = s.strip_prefix('^') {
        negated = true;
        s = rest;
    }
    if s.is_empty() {
        return Ok(ForceFallEntry {
            prefixes: Vec::new(),
            negated,
        });
    }

    if let Some((start_s, end_s)) = s.split_once('-') {
        // IP range: start-end
        let start: IpAddr = start_s
            .trim()
            .parse()
            .map_err(|_| format!("invalid range start IP {start_s}"))?;
        let end: IpAddr = end_s
            .trim()
            .parse()
            .map_err(|_| format!("invalid range end IP {end_s}"))?;
        let (start, end) = match (start, end) {
            (IpAddr::V4(a), IpAddr::V4(b)) => (a, b),
            _ => {
                return Err(format!(
                    "IPv6 range {start_s}-{end_s} is not supported; use CIDR or single addresses"
                ))
            }
        };
        let prefixes = range_to_prefix(start, end);
        if prefixes.is_empty() {
            return Err(format!("invalid IP range {start_s}-{end_s}"));
        }
        return Ok(ForceFallEntry { prefixes, negated });
    }

    if s.contains('/') {
        let p = parse_prefix(s)?;
        return Ok(ForceFallEntry {
            prefixes: vec![p],
            negated,
        });
    }

    // Single IP.
    let addr: IpAddr = s.parse().map_err(|_| format!("invalid IP {s}"))?;
    let bits = if addr.is_ipv4() { 32 } else { 128 };
    Ok(ForceFallEntry {
        prefixes: vec![IpPrefix::new(addr, bits)],
        negated,
    })
}

/// Convert an inclusive IPv4 range `[start, end]` to the minimal set of CIDR
/// prefixes.
pub fn range_to_prefix(start: Ipv4Addr, end: Ipv4Addr) -> Vec<IpPrefix> {
    let mut s = u32::from(start);
    let e = u32::from(end);
    if s > e {
        return Vec::new();
    }
    let mut out = Vec::new();
    loop {
        // Largest aligned block starting at s: 2^trailing_zeros(s).
        // trailing_zeros(0) == 32 in Rust.
        let align_exp = s.trailing_zeros();
        // Largest block fitting the remaining span: 2^floor(log2(span)).
        let span = (e as u64) - (s as u64) + 1;
        let size_exp = 63 - span.leading_zeros(); // bits.Len64(span) - 1
        let exp = align_exp.min(size_exp);
        out.push(IpPrefix::new(
            IpAddr::V4(Ipv4Addr::from(s)),
            (32 - exp) as u8,
        ));
        let next = (s as u64) + (1u64 << exp);
        if next > e as u64 {
            break;
        }
        s = next as u32;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn v4(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn matcher(include: &[&str], negate: &[&str]) -> ForceFallMatcher {
        let parse =
            |v: &[&str]| -> Vec<IpPrefix> { v.iter().map(|s| parse_prefix(s).unwrap()).collect() };
        ForceFallMatcher::new(&parse(include), &parse(negate))
    }

    /// The rule semantics stated directly over the prefix lists: any include
    /// prefix holding the client forces it; otherwise, when negate rules
    /// exist, the client is forced unless one of them holds it.
    fn reference(include: &[IpPrefix], negate: &[IpPrefix], ip: IpAddr) -> bool {
        include.iter().any(|p| p.contains(ip))
            || (!negate.is_empty() && !negate.iter().any(|p| p.contains(ip)))
    }

    /// Small deterministic generator (xorshift64*), so a failure replays.
    struct Gen(u64);

    impl Gen {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }

        /// Addresses drawn from a narrow window, so prefixes overlap, nest and
        /// touch instead of landing far apart.
        fn v4(&mut self) -> u32 {
            0xC0A8_0000 | self.below(1 << 10) as u32
        }

        fn v6(&mut self) -> u128 {
            (0xfd00_u128 << 112) | u128::from(self.below(1 << 10))
        }

        fn prefix(&mut self) -> IpPrefix {
            if self.below(4) == 0 {
                let bits = [0, 64, 112, 118, 120, 124, 127, 128][self.below(8) as usize];
                IpPrefix::new(IpAddr::V6(self.v6().into()), bits)
            } else {
                let bits = [0, 16, 22, 24, 26, 28, 30, 31, 32][self.below(9) as usize];
                IpPrefix::new(IpAddr::V4(self.v4().into()), bits)
            }
        }
    }

    /// The compiled ranges must classify every client exactly as the prefix
    /// lists they came from do: overlapping, nested, adjacent and
    /// mixed-family rules, probed at and around every range edge.
    #[test]
    fn the_compiled_matcher_agrees_with_the_prefix_rules() {
        let mut g = Gen(0x9E37_79B9_7F4A_7C15);
        for round in 0..2000 {
            let n_inc = g.below(6) as usize;
            let n_neg = g.below(6) as usize;
            let include: Vec<IpPrefix> = (0..n_inc).map(|_| g.prefix()).collect();
            let negate: Vec<IpPrefix> = (0..n_neg).map(|_| g.prefix()).collect();
            let m = ForceFallMatcher::new(&include, &negate);

            let mut probes: Vec<IpAddr> = Vec::new();
            for p in include.iter().chain(&negate) {
                match p.addr {
                    IpAddr::V4(a) => {
                        let mask = mask4(p.bits);
                        let (lo, hi) = (u32::from(a) & mask, u32::from(a) | !mask);
                        for x in [
                            lo.wrapping_sub(1),
                            lo,
                            lo + (hi - lo) / 2,
                            hi,
                            hi.wrapping_add(1),
                        ] {
                            probes.push(IpAddr::V4(x.into()));
                        }
                    }
                    IpAddr::V6(a) => {
                        let mask = mask6(p.bits);
                        let (lo, hi) = (u128::from(a) & mask, u128::from(a) | !mask);
                        for x in [
                            lo.wrapping_sub(1),
                            lo,
                            lo + (hi - lo) / 2,
                            hi,
                            hi.wrapping_add(1),
                        ] {
                            probes.push(IpAddr::V6(x.into()));
                        }
                    }
                }
            }
            for _ in 0..16 {
                probes.push(IpAddr::V4(g.v4().into()));
                probes.push(IpAddr::V6(g.v6().into()));
            }
            probes.push(ip("0.0.0.0"));
            probes.push(ip("255.255.255.255"));
            probes.push(ip("::"));
            probes.push(ip("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"));

            for probe in probes {
                assert_eq!(
                    m.matches(probe),
                    reference(&include, &negate, probe),
                    "round {round}: include={include:?} negate={negate:?} client={probe}"
                );
            }
        }
    }

    /// Best-of-rounds nanoseconds per `matches` call over `clients`.
    fn ns_per_match(m: &ForceFallMatcher, clients: &[IpAddr]) -> f64 {
        let mut best = f64::MAX;
        for _ in 0..7 {
            let started = std::time::Instant::now();
            let mut forced = 0usize;
            for _ in 0..40 {
                for c in clients {
                    forced += usize::from(std::hint::black_box(m).matches(*c));
                }
            }
            std::hint::black_box(forced);
            best = best.min(started.elapsed().as_nanos() as f64 / (40 * clients.len()) as f64);
        }
        best
    }

    /// Every query that reaches the cache is classified, so the cost must
    /// not grow with the number of prefixes the rules expand to.
    #[test]
    fn matching_cost_does_not_grow_with_the_rule_count() {
        let one = [parse_prefix("10.0.0.1/32").unwrap()];
        let many: Vec<IpPrefix> = (0..1000u32)
            .map(|i| IpPrefix::new(IpAddr::V4((0x0A00_0000 | (i * 7)).into()), 32))
            .collect();
        let clients: Vec<IpAddr> = (0..512u32)
            .map(|i| IpAddr::V4((0x0A00_0000 | (i * 13)).into()))
            .collect();
        let small = ns_per_match(&ForceFallMatcher::new(&[], &one), &clients);
        let large = ns_per_match(&ForceFallMatcher::new(&[], &many), &clients);
        // A scan of 1000 prefixes costs hundreds of times one; ten binary
        // search steps cost a few times one.
        assert!(
            large < small * 25.0,
            "1000 rules cost {large:.1} ns per client, one rule {small:.1} ns"
        );
    }

    /// A range rule expands to many prefixes; the matcher must still treat
    /// the whole span, and only it, as covered.
    #[test]
    fn a_range_rule_covers_exactly_its_span() {
        let entry = parse_force_fall_entry("^192.168.1.3-192.168.1.250").unwrap();
        assert!(
            entry.prefixes.len() > 8,
            "the range expands to many prefixes"
        );
        let m = ForceFallMatcher::new(&[], &entry.prefixes);
        for last in 0..=255u8 {
            let client = IpAddr::V4(Ipv4Addr::new(192, 168, 1, last));
            assert_eq!(
                m.matches(client),
                !(3..=250).contains(&last),
                "client {client}"
            );
        }
        // Negate rules of one family force every client of the other.
        assert!(m.matches(ip("fd00::1")));
    }

    #[test]
    fn force_fall_matcher() {
        // (include, negate, client, want).
        let cases: &[(&[&str], &[&str], &str, bool)] = &[
            (&[], &[], "192.168.1.1", false),
            (&["192.168.1.10/32"], &[], "192.168.1.10", true),
            (&["192.168.1.10/32"], &[], "192.168.1.11", false),
            (&["192.168.2.0/24"], &[], "192.168.2.100", true),
            (&["192.168.2.0/24"], &[], "192.168.3.1", false),
            (&["10.0.0.1/32", "192.168.1.0/24"], &[], "10.0.0.1", true),
            (
                &["10.0.0.1/32", "192.168.1.0/24"],
                &[],
                "192.168.1.50",
                true,
            ),
            (&["10.0.0.1/32", "192.168.1.0/24"], &[], "172.16.0.1", false),
            (&[], &["192.168.1.10/32"], "192.168.1.11", true),
            (&[], &["192.168.1.10/32"], "192.168.1.10", false),
            (&[], &["192.168.1.10/32", "10.0.0.0/8"], "172.16.0.1", true),
            (&[], &["192.168.1.10/32", "10.0.0.0/8"], "10.0.0.5", false),
            (&["10.0.0.1/32"], &["192.168.1.0/24"], "10.0.0.1", true),
            (&["10.0.0.1/32"], &["192.168.1.0/24"], "172.16.0.1", true),
            (&["10.0.0.1/32"], &["192.168.1.0/24"], "192.168.1.50", false),
            (&["10.0.0.0/8"], &["10.0.0.1/32"], "10.0.0.1", true),
            (
                &["192.168.0.0/16"],
                &["192.168.1.0/24"],
                "192.168.1.50",
                true,
            ),
        ];
        for (inc, neg, client, want) in cases {
            let m = matcher(inc, neg);
            assert_eq!(
                m.matches(ip(client)),
                *want,
                "include={inc:?} negate={neg:?} client={client}"
            );
        }
    }

    #[test]
    fn range_to_prefix_vectors() {
        // Test vectors for IPv4 range to CIDR conversion.
        let cases: &[(&str, &str, &[&str])] = &[
            ("192.168.1.10", "192.168.1.10", &["192.168.1.10/32"]),
            ("192.168.1.10", "192.168.1.11", &["192.168.1.10/31"]),
            (
                "192.168.1.123",
                "192.168.1.125",
                &["192.168.1.123/32", "192.168.1.124/31"],
            ),
            ("192.168.1.0", "192.168.1.255", &["192.168.1.0/24"]),
            (
                "10.0.0.1",
                "10.0.0.6",
                &["10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/31", "10.0.0.6/32"],
            ),
            ("0.0.0.0", "255.255.255.255", &["0.0.0.0/0"]),
            (
                "255.255.255.254",
                "255.255.255.255",
                &["255.255.255.254/31"],
            ),
        ];
        for (start, end, want) in cases {
            let got: Vec<String> = range_to_prefix(v4(start), v4(end))
                .iter()
                .map(|p| p.to_string())
                .collect();
            assert_eq!(got, *want, "range {start}-{end}");
        }
    }

    #[test]
    fn parse_force_fall_entry_vectors() {
        // (input, want_neg, want_count, want_first, want_err)
        let cases: &[(&str, bool, usize, &str, bool)] = &[
            ("", false, 0, "", false),
            ("192.168.1.10", false, 1, "192.168.1.10/32", false),
            ("192.168.2.0/24", false, 1, "192.168.2.0/24", false),
            (
                "192.168.1.10-192.168.1.11",
                false,
                1,
                "192.168.1.10/31",
                false,
            ),
            ("^192.168.1.126", true, 1, "192.168.1.126/32", false),
            ("^192.168.10.0/24", true, 1, "192.168.10.0/24", false),
            (
                "^192.168.1.123-192.168.1.125",
                true,
                2,
                "192.168.1.123/32",
                false,
            ),
            ("not.an.ip", false, 0, "", true),
            ("192.168.1.10-bad", false, 0, "", true),
            ("192.168.1.0/99", false, 0, "", true),
        ];
        for (input, want_neg, want_count, want_first, want_err) in cases {
            let res = parse_force_fall_entry(input);
            if *want_err {
                assert!(res.is_err(), "expected error for {input:?}");
                continue;
            }
            let e = res.unwrap_or_else(|err| panic!("{input:?} unexpected err: {err}"));
            assert_eq!(e.negated, *want_neg, "negated for {input:?}");
            assert_eq!(e.prefixes.len(), *want_count, "count for {input:?}");
            if *want_count > 0 {
                assert_eq!(
                    e.prefixes[0].to_string(),
                    *want_first,
                    "first for {input:?}"
                );
            }
        }
    }
}
