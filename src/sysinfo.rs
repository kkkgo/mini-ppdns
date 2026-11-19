// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

//! System/interface inspection — sizing and listen-address helpers.

use std::net::{IpAddr, SocketAddr};

use crate::util::{join_host_port, v6_is_link_local, v6_is_private_special};

/// Bytes per cache entry the capacity is computed from; the cache's byte
/// budget is derived from the same figure, so the two agree.
const ESTIMATED_ENTRY_SIZE: u64 = crate::cache::ENTRY_BYTES as u64;
const MAX_CACHE_SIZE: usize = 102400; // absolute upper limit
const MIN_CACHE_SIZE: usize = 1024; // minimum entries
const MIN_FALLBACK_CACHE_SIZE: usize = 256; // minimum entries, fallback cache

/// Memory this process can still use, in bytes: what `/proc/meminfo` reports
/// available, lowered to the headroom of any memory-limited cgroup the process
/// runs in. A container sees the host's whole meminfo, so without the cgroup
/// a cache sized from it can be killed for exceeding its own limit. Returns 0
/// when neither can be read (non-Linux) — callers treat 0 as "unknown".
pub fn get_available_memory() -> u64 {
    let host = std::fs::read_to_string("/proc/meminfo")
        .map(|c| meminfo_available(&c))
        .unwrap_or(0);
    let cgroup = std::fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|own| cgroup_headroom(std::path::Path::new("/sys/fs/cgroup"), &own));
    match (host, cgroup) {
        (0, Some(c)) => c,
        (h, Some(c)) => h.min(c),
        (h, None) => h,
    }
}

/// What a cgroup's memory limit leaves free: limit minus usage, or `None`
/// for no limit — `max` under cgroup v2, a near-`i64::MAX` value under v1.
fn limit_headroom(limit: &str, usage: &str) -> Option<u64> {
    let limit: u64 = limit.trim().parse().ok()?;
    if limit >= 1 << 62 {
        return None;
    }
    let usage: u64 = usage.trim().parse().unwrap_or(0);
    Some(limit.saturating_sub(usage))
}

/// The tightest headroom any memory-limited cgroup on the path from the
/// process's own group (`own`, the text of `/proc/self/cgroup`) up to the
/// hierarchy root leaves. Both cgroup v2 (`0::/path`) and the v1 `memory`
/// controller are read; `None` when no group on the way sets a limit.
fn cgroup_headroom(root: &std::path::Path, own: &str) -> Option<u64> {
    let mut tightest: Option<u64> = None;
    for line in own.lines() {
        let mut fields = line.splitn(3, ':');
        let (Some(_), Some(controllers), Some(path)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let (base, limit_file, usage_file) = if controllers.is_empty() {
            (root.to_path_buf(), "memory.max", "memory.current")
        } else if controllers.split(',').any(|c| c == "memory") {
            (
                root.join("memory"),
                "memory.limit_in_bytes",
                "memory.usage_in_bytes",
            )
        } else {
            continue;
        };
        // A parent's limit binds the children as much as their own does.
        let mut dir = base.join(path.trim_start_matches('/'));
        loop {
            let read = |f: &str| std::fs::read_to_string(dir.join(f));
            if let (Ok(limit), Ok(usage)) = (read(limit_file), read(usage_file)) {
                if let Some(h) = limit_headroom(&limit, &usage) {
                    tightest = Some(tightest.map_or(h, |t| t.min(h)));
                }
            }
            if dir == base || !dir.pop() {
                break;
            }
        }
    }
    tightest
}

/// `MemAvailable` from `/proc/meminfo` text, or its classic estimate on
/// kernels too old to report it; 0 when neither is there.
fn meminfo_available(contents: &str) -> u64 {
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

/// Capacity for the fallback-answer cache, derived from the main one.
///
/// It only holds answers produced by the fallback upstream: hot for force_fall
/// clients and while the main DNS is down, near-empty in a healthy default
/// deployment. A quarter of the main budget caps the worst-case cache footprint
/// at a quarter more, which matters on the 64/128 MB routers this targets.
pub fn calculate_fallback_cache_size(main_cap: usize) -> usize {
    (main_cap / 4).max(MIN_FALLBACK_CACHE_SIZE)
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
    fn fallback_cache_size_is_a_quarter_with_a_floor() {
        assert_eq!(calculate_fallback_cache_size(102400), 25600);
        // Never below the floor, even off the smallest main cache.
        assert_eq!(
            calculate_fallback_cache_size(MIN_CACHE_SIZE),
            MIN_FALLBACK_CACHE_SIZE
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

    #[test]
    fn meminfo_prefers_mem_available() {
        let with = "MemTotal: 1000 kB\nMemFree: 100 kB\nMemAvailable: 600 kB\nBuffers: 50 kB\nCached: 200 kB\n";
        assert_eq!(meminfo_available(with), 600 * 1024);
        let without = "MemTotal: 1000 kB\nMemFree: 100 kB\nBuffers: 50 kB\nCached: 200 kB\n";
        assert_eq!(meminfo_available(without), 350 * 1024);
        assert_eq!(meminfo_available(""), 0);
    }

    #[test]
    fn a_cgroup_limit_leaves_its_headroom_and_no_limit_leaves_none() {
        assert_eq!(
            limit_headroom("104857600\n", "4857600\n"),
            Some(100_000_000)
        );
        assert_eq!(
            limit_headroom("100", "250"),
            Some(0),
            "usage past the limit"
        );
        assert_eq!(limit_headroom("max\n", "123"), None, "cgroup v2: no limit");
        assert_eq!(
            limit_headroom("9223372036854771712\n", "123"),
            None,
            "cgroup v1: no limit"
        );
        assert_eq!(limit_headroom("", ""), None);
    }

    /// A scratch cgroup hierarchy under the system temp directory.
    struct FakeCgroups(std::path::PathBuf);

    impl FakeCgroups {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "mini-ppdns-cgroup-{tag}-{}-{}",
                std::process::id(),
                crate::rng::next_u64()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            FakeCgroups(dir)
        }

        fn group(&self, path: &str, limit: &str, usage: &str, names: (&str, &str)) {
            let dir = self.0.join(path);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(names.0), limit).unwrap();
            std::fs::write(dir.join(names.1), usage).unwrap();
        }
    }

    impl Drop for FakeCgroups {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// In a container the host's meminfo says nothing about what the process
    /// may use: the cache has to be sized from the tightest cgroup limit on
    /// the way up from the process's own group.
    #[test]
    fn the_tightest_cgroup_on_the_way_to_the_root_bounds_available_memory() {
        const V2: (&str, &str) = ("memory.max", "memory.current");
        const V1: (&str, &str) = ("memory.limit_in_bytes", "memory.usage_in_bytes");
        let fs = FakeCgroups::new("v2");
        fs.group("system.slice", "300000000", "100000000", V2);
        fs.group("system.slice/dns.service", "max", "5000000", V2);
        // The slice's limit binds the service inside it.
        assert_eq!(
            cgroup_headroom(&fs.0, "0::/system.slice/dns.service\n"),
            Some(200_000_000)
        );
        // A namespaced container sees its own group as the root.
        fs.group("", "64000000", "14000000", V2);
        assert_eq!(cgroup_headroom(&fs.0, "0::/\n"), Some(50_000_000));

        let fs = FakeCgroups::new("v1");
        fs.group("memory/docker/abc", "268435456", "68435456", V1);
        fs.group("memory/docker", "9223372036854771712", "0", V1);
        let own = "12:cpu,cpuacct:/docker/abc\n4:memory:/docker/abc\n";
        assert_eq!(cgroup_headroom(&fs.0, own), Some(200_000_000));

        // No limited group anywhere: nothing to say.
        let fs = FakeCgroups::new("none");
        fs.group("user.slice", "max", "1", V2);
        assert_eq!(cgroup_headroom(&fs.0, "0::/user.slice\n"), None);
        assert_eq!(cgroup_headroom(&fs.0, ""), None);
    }
}
