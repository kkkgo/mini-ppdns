// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

//! Small networking and hashing helpers shared across modules.

use std::net::{IpAddr, Ipv6Addr};

/// FNV-1a 64-bit — the crate's shared cheap non-cryptographic hash. A query
/// name is hashed once (`dns::extract_query`) and the value reused by the
/// resolver's negative filter and, via [`fnv1a_continue`], the cache's shard
/// selection. Not DoS-resistant by design; every consumer bounds the damage
/// elsewhere (per-shard caps, SipHash inside the shard maps, filter
/// false-positive fallthrough).
pub fn fnv1a(bytes: &[u8]) -> u64 {
    fnv1a_continue(0xcbf29ce484222325, bytes)
}

/// Continue an FNV-1a hash over more bytes (exactly as if the two byte runs
/// had been hashed as one).
pub fn fnv1a_continue(mut h: u64, bytes: &[u8]) -> u64 {
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Join a host and port: any host containing a colon (IPv6 literal, possibly
/// with a `%zone`) is bracketed.
pub fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Unmap an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) to plain IPv4 so client
/// matching and logging see the address family the operator configured rules
/// for. Other addresses pass through unchanged.
pub fn unmap_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// IPv6 Unique Local Address (fc00::/7).
pub fn v6_is_ula(a: Ipv6Addr) -> bool {
    (a.octets()[0] & 0xfe) == 0xfc
}

/// IPv6 link-local unicast (fe80::/10).
pub fn v6_is_link_local(a: Ipv6Addr) -> bool {
    let o = a.octets();
    o[0] == 0xfe && (o[1] & 0xc0) == 0x80
}

/// The bindable/local IPv6 classes: loopback (::1), ULA, or link-local.
pub fn v6_is_private_special(a: Ipv6Addr) -> bool {
    a.is_loopback() || v6_is_ula(a) || v6_is_link_local(a)
}

/// Normalize an upstream DNS string into a `scheme://host:port` URL that the
/// upstream layer accepts: add `udp://` when no scheme is present and fill in
/// the default port 53 when missing. The URL parsing is hand-rolled to avoid a
/// `url` dependency.
pub fn format_upstream_addr(addr: &str) -> String {
    let addr = addr.trim();

    // Fast path: bare IP literal (no scheme, no bracket). Handles unbracketed
    // IPv6 like "::1" which a naive URL parse cannot round-trip.
    if !addr.contains("://") && !addr.contains('[') {
        if let Ok(ip) = addr.parse::<IpAddr>() {
            return format!("udp://{}", join_host_port(&ip.to_string(), "53"));
        }
    }

    let (scheme, rest) = match addr.split_once("://") {
        Some((s, r)) => (s, r),
        None => ("udp", addr),
    };
    format!("{scheme}://{}", normalize_host_port(rest))
}

/// Ensure a host authority carries an explicit port, bracketing bare IPv6.
fn normalize_host_port(rest: &str) -> String {
    // Already bracketed IPv6: "[host]" or "[host]:port".
    if let Some(after) = rest.strip_prefix('[') {
        if let Some(idx) = after.find(']') {
            let host = &after[..idx];
            let tail = &after[idx + 1..];
            if tail.len() > 1 && tail.starts_with(':') {
                return format!("[{host}]{tail}");
            }
            return format!("[{host}]:53");
        }
    }
    // Bare IPv6 literal → bracket and add :53.
    if rest.parse::<Ipv6Addr>().is_ok() {
        return format!("[{rest}]:53");
    }
    // IPv4 or hostname: keep if it already has a port, else add :53.
    if rest.contains(':') {
        return rest.to_string();
    }
    format!("{rest}:53")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_upstream() {
        let cases = [
            ("10.10.10.8", "udp://10.10.10.8:53"),
            (" 10.10.10.8 ", "udp://10.10.10.8:53"),
            ("10.10.10.8:53", "udp://10.10.10.8:53"),
            ("10.10.10.8:5353", "udp://10.10.10.8:5353"),
            ("::1", "udp://[::1]:53"),
            ("udp://10.10.10.8", "udp://10.10.10.8:53"),
            ("udp://::1", "udp://[::1]:53"),
            ("udp://[::1]:53", "udp://[::1]:53"),
            ("tcp://1.1.1.1:53", "tcp://1.1.1.1:53"),
            ("tcp://1.1.1.1", "tcp://1.1.1.1:53"),
            ("tcp+pipeline://9.9.9.9", "tcp+pipeline://9.9.9.9:53"),
        ];
        for (input, want) in cases {
            assert_eq!(format_upstream_addr(input), want, "input={input}");
        }
    }

    #[test]
    fn join() {
        assert_eq!(join_host_port("1.2.3.4", "53"), "1.2.3.4:53");
        assert_eq!(join_host_port("::1", "53"), "[::1]:53");
        assert_eq!(join_host_port("fe80::1%eth0", "53"), "[fe80::1%eth0]:53");
    }

    #[test]
    fn v6_classes() {
        assert!(v6_is_ula("fc00::1".parse().unwrap()));
        assert!(v6_is_ula("fd12::1".parse().unwrap()));
        assert!(!v6_is_ula("2001:db8::1".parse().unwrap()));
        assert!(v6_is_link_local("fe80::1".parse().unwrap()));
        assert!(!v6_is_link_local("fec0::1".parse().unwrap()));
        assert!(v6_is_private_special("::1".parse().unwrap()));
    }
}
