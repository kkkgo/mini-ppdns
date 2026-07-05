// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

//! System/interface inspection — sizing and listen-address helpers.

use std::net::{IpAddr, SocketAddr};

use crate::util::{join_host_port, v6_is_link_local, v6_is_private_special};

const ESTIMATED_ENTRY_SIZE: u64 = 2048; // bytes per cache entry (rough)
const MAX_CACHE_SIZE: usize = 102400; // absolute upper limit
const MIN_CACHE_SIZE: usize = 1024; // minimum entries

/// Read `/proc/meminfo` and return available memory in bytes. Returns 0 when
/// the file cannot be read (non-Linux) — callers treat 0 as "unknown".
pub fn get_available_memory() -> u64 {
    let contents = match std::fs::read_to_string("/proc/meminfo") {
        Ok(c) => c,
        Err(_) => return 0,
    };
    let (mut mem_available, mut mem_free, mut buffers, mut cached) = (0u64, 0u64, 0u64, 0u64);
    for line in contents.lines() {
        let mut it = line.split_whitespace();
        let (Some(key), Some(val)) = (it.next(), it.next()) else {
            continue;
        };
        let Ok(v) = val.parse::<u64>() else { continue };
        let bytes = v.saturating_mul(1024); // /proc/meminfo values are in kB
        match key {
            "MemAvailable:" => mem_available = bytes,
            "MemFree:" => mem_free = bytes,
            "Buffers:" => buffers = bytes,
            "Cached:" => cached = bytes,
            _ => {}
        }
    }
    if mem_available > 0 {
        return mem_available;
    }
    mem_free + buffers + cached
}

/// Compute the cache capacity (entries) from available memory: 20% of
/// available / entry size, clamped to `[MIN, MAX]`. When `available_bytes`
/// is 0 (unknown), returns the max.
pub fn calculate_cache_size(available_bytes: u64) -> usize {
    if available_bytes == 0 {
        return MAX_CACHE_SIZE;
    }
    let mem_based = (available_bytes / 5 / ESTIMATED_ENTRY_SIZE) as usize;
    mem_based.clamp(MIN_CACHE_SIZE, MAX_CACHE_SIZE)
}

/// Auto-detected private/loopback/link-local listen addresses on :53.
pub fn get_private_ips() -> Vec<String> {
    collect_private_listen_addrs("53", true, true)
}

/// Walk interface addresses and return private + loopback (+ link-local)
/// IPs formatted as `host:port`. `v4`/`v6` select which families to include.
pub fn collect_private_listen_addrs(port: &str, v4: bool, v6: bool) -> Vec<String> {
    let mut ips = Vec::new();

    match if_addrs::get_if_addrs() {
        Ok(ifaces) => {
            for iface in ifaces {
                match iface.ip() {
                    IpAddr::V4(ip) => {
                        if !v4 {
                            continue;
                        }
                        if ip.is_private() || ip.is_loopback() || ip.is_link_local() {
                            ips.push(join_host_port(&ip.to_string(), port));
                        }
                    }
                    IpAddr::V6(ip) => {
                        if !v6 {
                            continue;
                        }
                        if v6_is_private_special(ip) {
                            let host = if v6_is_link_local(ip) {
                                format!("{}%{}", ip, iface.name)
                            } else {
                                ip.to_string()
                            };
                            ips.push(join_host_port(&host, port));
                        }
                    }
                }
            }
        }
        Err(_) => return fallback_addrs(port, v4, v6),
    }

    if ips.is_empty() {
        return fallback_addrs(port, v4, v6);
    }
    ips
}

fn fallback_addrs(port: &str, v4: bool, v6: bool) -> Vec<String> {
    let mut fb = Vec::new();
    if v4 {
        fb.push(join_host_port("127.0.0.1", port));
    }
    if v6 {
        fb.push(join_host_port("::1", port));
    }
    fb
}

/// Append the default DNS port (:53) to a bare IP literal that has no port.
/// Inputs already of the form `host:port` (or shapes we can't classify) pass
/// through unchanged.
pub fn ensure_listen_port(addr: &str) -> String {
    let addr = addr.trim();
    if addr.is_empty() {
        return String::new();
    }
    if addr.parse::<SocketAddr>().is_ok() {
        return addr.to_string();
    }
    if let Ok(ip) = addr.parse::<IpAddr>() {
        return join_host_port(&ip.to_string(), "53");
    }
    addr.to_string()
}

/// Rewrite a `0.0.0.0:port` / `[::]:port` wildcard listen into the set of
/// private/loopback addresses on that port. Non-wildcard entries pass through.
pub fn expand_wildcard_listen(addr: &str) -> Vec<String> {
    let sock: SocketAddr = match addr.parse() {
        Ok(s) => s,
        Err(_) => return vec![addr.to_string()],
    };
    if !sock.ip().is_unspecified() {
        return vec![addr.to_string()];
    }
    let port = sock.port().to_string();
    match sock.ip() {
        // 0.0.0.0 → IPv4 private only.
        IpAddr::V4(_) => collect_private_listen_addrs(&port, true, false),
        // :: → IPv4 + IPv6 private.
        IpAddr::V6(_) => collect_private_listen_addrs(&port, true, true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_size_clamp() {
        assert_eq!(calculate_cache_size(0), MAX_CACHE_SIZE);
        // Tiny memory → floored at MIN.
        assert_eq!(calculate_cache_size(1024), MIN_CACHE_SIZE);
        // Huge memory → capped at MAX.
        assert_eq!(calculate_cache_size(1 << 40), MAX_CACHE_SIZE);
        // Mid-range: 100 MiB → 100Mi/5/2048.
        let hundred_mib = 100u64 * 1024 * 1024;
        let want = (hundred_mib / 5 / ESTIMATED_ENTRY_SIZE) as usize;
        assert_eq!(
            calculate_cache_size(hundred_mib),
            want.clamp(MIN_CACHE_SIZE, MAX_CACHE_SIZE)
        );
    }

    #[test]
    fn ensure_port() {
        assert_eq!(ensure_listen_port("127.0.0.1"), "127.0.0.1:53");
        assert_eq!(ensure_listen_port("127.0.0.1:5353"), "127.0.0.1:5353");
        assert_eq!(ensure_listen_port("::1"), "[::1]:53");
        assert_eq!(ensure_listen_port("[::1]:53"), "[::1]:53");
        assert_eq!(ensure_listen_port("  10.0.0.1 "), "10.0.0.1:53");
        assert_eq!(ensure_listen_port(""), "");
    }

    #[test]
    fn wildcard_non_wildcard_passthrough() {
        // A concrete address is returned unchanged.
        assert_eq!(
            expand_wildcard_listen("192.168.1.1:53"),
            vec!["192.168.1.1:53".to_string()]
        );
        // A non-parseable entry is returned unchanged.
        assert_eq!(
            expand_wildcard_listen("garbage"),
            vec!["garbage".to_string()]
        );
    }

    #[test]
    fn wildcard_expands_to_nonempty() {
        // 0.0.0.0 must expand to at least the loopback fallback, and every
        // result must carry the requested port.
        let got = expand_wildcard_listen("0.0.0.0:5353");
        assert!(!got.is_empty());
        assert!(got.iter().all(|a| a.ends_with(":5353")));
    }
}
