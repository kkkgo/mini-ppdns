// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

//! force_fall client matching.
//!
//! Include rules (no `^`) use OR logic: any match triggers force_fall.
//! Negate rules (`^` prefix) use AND logic: the client IP must NOT be in ANY
//! negated prefix for force_fall to trigger. When both kinds are present,
//! include rules are checked first and take precedence.

use std::net::{IpAddr, Ipv4Addr};

/// A CIDR prefix. The base address is stored as parsed (not masked); masking
/// happens only in [`IpPrefix::contains`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpPrefix {
    addr: IpAddr,
    bits: u8,
}

impl IpPrefix {
    pub fn new(addr: IpAddr, bits: u8) -> Self {
        IpPrefix { addr, bits }
    }

    /// Reports whether `ip` falls inside this prefix. Returns false when the
    /// address families differ (mirrors `netip.Prefix.Contains`).
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask: u32 = if self.bits == 0 {
                    0
                } else if self.bits >= 32 {
                    u32::MAX
                } else {
                    u32::MAX << (32 - self.bits)
                };
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask: u128 = if self.bits == 0 {
                    0
                } else if self.bits >= 128 {
                    u128::MAX
                } else {
                    u128::MAX << (128 - self.bits)
                };
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

/// force_fall matcher: include prefixes (OR) and negate prefixes (AND).
#[derive(Default, Debug, Clone)]
pub struct ForceFallMatcher {
    pub include: Vec<IpPrefix>,
    pub negate: Vec<IpPrefix>,
}

impl ForceFallMatcher {
    pub fn is_empty(&self) -> bool {
        self.include.is_empty() && self.negate.is_empty()
    }

    /// Reports whether `addr` should be forced onto the fallback DNS.
    pub fn matches(&self, addr: IpAddr) -> bool {
        if self.is_empty() {
            return false;
        }
        for p in &self.include {
            if p.contains(addr) {
                return true;
            }
        }
        if !self.negate.is_empty() {
            for p in &self.negate {
                if p.contains(addr) {
                    return false;
                }
            }
            return true;
        }
        false
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
        ForceFallMatcher {
            include: include.iter().map(|s| parse_prefix(s).unwrap()).collect(),
            negate: negate.iter().map(|s| parse_prefix(s).unwrap()).collect(),
        }
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
