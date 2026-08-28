// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

//! Small networking and hashing helpers shared across modules.

use std::net::{IpAddr, Ipv6Addr};

// ---- keyed hash ----
//
// rapidhashNano, ported from the reference C implementation
// (https://github.com/Nicoshev/rapidhash, MIT, © 2025 Nicolas De Carli). The
// Nano variant is the one that fits: it is tuned for inputs up to 48 bytes, and
// a DNS wire name is 255 bytes at most, typically under 40.
//
// Two properties the rest of the crate leans on:
//
// 1. The output is well distributed enough to index a hash table directly, so
//    the cache's shard maps take it as their bucket hash (`cache::PreHashed`)
//    instead of hashing the key a second time.
// 2. It is seeded per process from `getrandom`, so which shard a name lands in
//    is not attacker-predictable.

const SECRET: [u64; 8] = [
    0x2d358dccaa6c78a5,
    0x8bb84b93962eacc9,
    0x4b33a62ed433d4a3,
    0x4d5a2da51de1aa47,
    0xa0761d6478bd642f,
    0xe7037ed1a0b428db,
    0x90ed1765281c388c,
    0xaaaaaaaaaaaaaaaa,
];

/// Per-process hash seed, drawn once and stored with the algorithm's seed-mixing
/// prologue already applied — that step is a 128-bit multiply whose result is
/// constant for a fixed seed, so it is pointless to redo it on every hash.
///
/// A `OnceLock` rather than an atomic: the 32-bit MIPS release targets have no
/// 64-bit atomics.
fn mixed_seed() -> u64 {
    static SEED: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *SEED.get_or_init(|| {
        let mut b = [0u8; 8];
        // Only DoS resistance rides on this, never correctness, so a failure
        // degrades to a fixed seed rather than taking the process down.
        let _ = getrandom::fill(&mut b);
        let seed = u64::from_ne_bytes(b);
        seed ^ mix(seed ^ SECRET[2], SECRET[1])
    })
}

/// 64x64 → 128 multiply, returning (low, high).
#[inline(always)]
fn mum(a: u64, b: u64) -> (u64, u64) {
    let r = (a as u128).wrapping_mul(b as u128);
    (r as u64, (r >> 64) as u64)
}

/// Multiply-and-xor-fold mix.
#[inline(always)]
fn mix(a: u64, b: u64) -> u64 {
    let (lo, hi) = mum(a, b);
    lo ^ hi
}

/// Little-endian reads, matching the reference on both endiannesses (it
/// byte-swaps on big-endian so the output stays platform-independent).
#[inline(always)]
fn read64(p: &[u8]) -> u64 {
    u64::from_le_bytes([p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]])
}

#[inline(always)]
fn read32(p: &[u8]) -> u64 {
    u32::from_le_bytes([p[0], p[1], p[2], p[3]]) as u64
}

/// Hash `bytes` with this process's seed.
pub fn hash(bytes: &[u8]) -> u64 {
    hash_mixed(bytes, mixed_seed())
}

/// Fold an extra 64-bit value into an existing hash, so a name's hash can be
/// extended over the query's type and class without re-reading the name.
#[inline]
pub fn hash_extend(h: u64, extra: u64) -> u64 {
    mix(h ^ SECRET[3], extra ^ SECRET[4])
}

/// rapidhashNano with an explicit seed — the seed-mixing prologue included.
/// Only the tests call this (with the reference vectors' fixed seeds);
/// production goes through [`hash`], which keeps the prologue precomputed.
#[cfg(test)]
fn hash_seeded(key: &[u8], seed: u64) -> u64 {
    hash_mixed(key, seed ^ mix(seed ^ SECRET[2], SECRET[1]))
}

/// rapidhashNano's body, taking the seed with the prologue already applied.
fn hash_mixed(key: &[u8], mut seed: u64) -> u64 {
    let len = key.len();
    let (mut a, mut b) = (0u64, 0u64);
    let mut i = len;
    if len <= 16 {
        if len >= 4 {
            seed ^= len as u64;
            if len >= 8 {
                a = read64(&key[..8]);
                b = read64(&key[len - 8..]);
            } else {
                a = read32(&key[..4]);
                b = read32(&key[len - 4..]);
            }
        } else if len > 0 {
            a = ((key[0] as u64) << 45) | key[len - 1] as u64;
            b = key[len >> 1] as u64;
        }
    } else {
        let mut p = 0usize;
        if i > 48 {
            let (mut see1, mut see2) = (seed, seed);
            while i > 48 {
                seed = mix(read64(&key[p..]) ^ SECRET[0], read64(&key[p + 8..]) ^ seed);
                see1 = mix(
                    read64(&key[p + 16..]) ^ SECRET[1],
                    read64(&key[p + 24..]) ^ see1,
                );
                see2 = mix(
                    read64(&key[p + 32..]) ^ SECRET[2],
                    read64(&key[p + 40..]) ^ see2,
                );
                p += 48;
                i -= 48;
            }
            seed ^= see1;
            seed ^= see2;
        }
        if i > 16 {
            seed = mix(read64(&key[p..]) ^ SECRET[2], read64(&key[p + 8..]) ^ seed);
            if i > 32 {
                seed = mix(
                    read64(&key[p + 16..]) ^ SECRET[2],
                    read64(&key[p + 24..]) ^ seed,
                );
            }
        }
        // `p + i` is invariant at `len`, so these are the last 16 bytes.
        a = read64(&key[len - 16..]) ^ (i as u64);
        b = read64(&key[len - 8..]);
    }
    a ^= SECRET[1];
    b ^= seed;
    let (lo, hi) = mum(a, b);
    mix(lo ^ SECRET[7], hi ^ SECRET[1] ^ (i as u64))
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

    /// The rapidhashNano port must agree with the reference C implementation
    /// bit for bit. Vectors were generated by compiling the upstream
    /// `rapidhash.h` and calling `rapidhashNano_withSeed` over a fixed byte
    /// pattern: every length from 0 to 96 (covering all four size branches and
    /// their boundaries) at four seeds, plus longer inputs that go around the
    /// 48-byte block loop several times.
    // (len, seed, expected) from the reference C rapidhashNano.
    const VECTORS: &[(usize, u64, u64)] = &[
        (0, 0x0000000000000000, 0x0338dc4be2cecdae),
        (1, 0x0000000000000000, 0xc6939e8fb00709ff),
        (2, 0x0000000000000000, 0xad801a47df89b990),
        (3, 0x0000000000000000, 0x5655e9f764e8fb47),
        (4, 0x0000000000000000, 0x49227fb2f401a8fc),
        (5, 0x0000000000000000, 0x01b87dc529f9affe),
        (6, 0x0000000000000000, 0x7266a22a28a37a3e),
        (7, 0x0000000000000000, 0xf8d2bdfe7f388df8),
        (8, 0x0000000000000000, 0xf5980b646f822e89),
        (9, 0x0000000000000000, 0xfd9787420766dd08),
        (10, 0x0000000000000000, 0x1ebf95799fb7e8f2),
        (11, 0x0000000000000000, 0x1e428b29acf0f830),
        (12, 0x0000000000000000, 0x2401514f706bc577),
        (13, 0x0000000000000000, 0x984cf88f2980a413),
        (14, 0x0000000000000000, 0x45b8ad52d75aa5e0),
        (15, 0x0000000000000000, 0x71bb053c322ab7cb),
        (16, 0x0000000000000000, 0xd0e68844cb24a480),
        (17, 0x0000000000000000, 0x7998c836066e171b),
        (18, 0x0000000000000000, 0x9f11a624c0bb383c),
        (19, 0x0000000000000000, 0x739d6d14f0b024a5),
        (20, 0x0000000000000000, 0x3130522906aeaa1e),
        (21, 0x0000000000000000, 0xcca11ff5ed600992),
        (22, 0x0000000000000000, 0x2a32a435a933ba64),
        (23, 0x0000000000000000, 0x0f9b7b8b4eaa331f),
        (24, 0x0000000000000000, 0x961432085ca20b01),
        (25, 0x0000000000000000, 0xd817de2348dce7f1),
        (26, 0x0000000000000000, 0x4c5151669cd3e893),
        (27, 0x0000000000000000, 0x4dbaf5c0f207b05b),
        (28, 0x0000000000000000, 0x72af298b42c75561),
        (29, 0x0000000000000000, 0x1039300f700e0228),
        (30, 0x0000000000000000, 0x07ef2a27cb18b2b2),
        (31, 0x0000000000000000, 0xed3eee46cfa04e29),
        (32, 0x0000000000000000, 0x4f6a424c80f09818),
        (33, 0x0000000000000000, 0x50f708a727e0a6f9),
        (34, 0x0000000000000000, 0xd6f51ba0395a3c15),
        (35, 0x0000000000000000, 0x62be0159983c1e3c),
        (36, 0x0000000000000000, 0xf474f185db2709a3),
        (37, 0x0000000000000000, 0x0d56b709cb1d5b00),
        (38, 0x0000000000000000, 0x53efdb7d671341fd),
        (39, 0x0000000000000000, 0x18f794fed11dbfad),
        (40, 0x0000000000000000, 0xe9301afd873db9e9),
        (41, 0x0000000000000000, 0x2047fcb9144df77f),
        (42, 0x0000000000000000, 0x5bd059d25535bcb0),
        (43, 0x0000000000000000, 0xaf9fcc62e3186dce),
        (44, 0x0000000000000000, 0x0599ffbf67a513a6),
        (45, 0x0000000000000000, 0x033bae1e1e08cfa9),
        (46, 0x0000000000000000, 0x87722805c2456b12),
        (47, 0x0000000000000000, 0x5fa1ee593a9d44e5),
        (48, 0x0000000000000000, 0x78e892266d502576),
        (49, 0x0000000000000000, 0x3b64ec2b4166561c),
        (50, 0x0000000000000000, 0x185d5f7fba89c308),
        (51, 0x0000000000000000, 0xc554865b82b90fe4),
        (52, 0x0000000000000000, 0xf00e8fc645420b44),
        (53, 0x0000000000000000, 0x72b07fde1ecaab5f),
        (54, 0x0000000000000000, 0x48dc61239211baf6),
        (55, 0x0000000000000000, 0xab443c7ba6b3563e),
        (56, 0x0000000000000000, 0x6f95ac36950875d4),
        (57, 0x0000000000000000, 0x393d652a59804964),
        (58, 0x0000000000000000, 0x6750eb64b9895f37),
        (59, 0x0000000000000000, 0xaa049d51ebb426af),
        (60, 0x0000000000000000, 0xbdd91ffb4f15df90),
        (61, 0x0000000000000000, 0x32f86592570ed129),
        (62, 0x0000000000000000, 0xed0e808329815141),
        (63, 0x0000000000000000, 0xa9e044140b88fd56),
        (64, 0x0000000000000000, 0x11b563e267e1cafd),
        (65, 0x0000000000000000, 0x9b0938534aca8803),
        (66, 0x0000000000000000, 0x35a78d0d2bcd3f68),
        (67, 0x0000000000000000, 0xc8df5a664c0178c8),
        (68, 0x0000000000000000, 0x50289a54fbd27066),
        (69, 0x0000000000000000, 0x1be19a4e14678cbf),
        (70, 0x0000000000000000, 0xa5c791fed29acd92),
        (71, 0x0000000000000000, 0xffc717f231b267d9),
        (72, 0x0000000000000000, 0x4f85d743c9a5a67c),
        (73, 0x0000000000000000, 0xfd5d10f0ab4d37f9),
        (74, 0x0000000000000000, 0xd3d5683f7d40e6be),
        (75, 0x0000000000000000, 0x526bc23dd367b4fb),
        (76, 0x0000000000000000, 0xa75cf1dd770a4629),
        (77, 0x0000000000000000, 0x0291cec849694e0a),
        (78, 0x0000000000000000, 0xefbc760d9c816f70),
        (79, 0x0000000000000000, 0xbcec4ea2f5c6ae4a),
        (80, 0x0000000000000000, 0xdd71b6a306e735fa),
        (81, 0x0000000000000000, 0x0f6fbb708b8c09f3),
        (82, 0x0000000000000000, 0x7c72db8f1aa94ec1),
        (83, 0x0000000000000000, 0x914cf396e4704ef4),
        (84, 0x0000000000000000, 0x38615c7a92a5274b),
        (85, 0x0000000000000000, 0xacfd4c4b9275a816),
        (86, 0x0000000000000000, 0xb9a6451e912b672b),
        (87, 0x0000000000000000, 0x1be2e1b5b3589c95),
        (88, 0x0000000000000000, 0x10698231214b4bdb),
        (89, 0x0000000000000000, 0xf33b22c88f410e95),
        (90, 0x0000000000000000, 0x7c77138cd8fdff5a),
        (91, 0x0000000000000000, 0x5708ca2985638b95),
        (92, 0x0000000000000000, 0x3622c9012f29fe63),
        (93, 0x0000000000000000, 0xeebc0e7bf2b30181),
        (94, 0x0000000000000000, 0x01064349a0286146),
        (95, 0x0000000000000000, 0x4a66ebb963f9ad24),
        (96, 0x0000000000000000, 0x3d8753f5dc138eda),
        (0, 0x0000000000000001, 0xad700ecdf353d5ca),
        (1, 0x0000000000000001, 0x400f1d91d6906460),
        (2, 0x0000000000000001, 0xd57bf61751c70e48),
        (3, 0x0000000000000001, 0xb1c2c64c475b22d9),
        (4, 0x0000000000000001, 0xcf9ef38152e20a2d),
        (5, 0x0000000000000001, 0x3803788605ea2878),
        (6, 0x0000000000000001, 0xd46c1f8854d7ee19),
        (7, 0x0000000000000001, 0x39651d3af2df4a14),
        (8, 0x0000000000000001, 0xf4caa67f2df56a02),
        (9, 0x0000000000000001, 0x37dc258419582a4d),
        (10, 0x0000000000000001, 0x639350cb3eb3ddd3),
        (11, 0x0000000000000001, 0x789277ee6a3e356b),
        (12, 0x0000000000000001, 0x068a8175ed1ede8c),
        (13, 0x0000000000000001, 0xb013c62952c54be5),
        (14, 0x0000000000000001, 0x5610af3626ac72be),
        (15, 0x0000000000000001, 0xd2d0fd97ec5aff23),
        (16, 0x0000000000000001, 0xa66fdf6effad597d),
        (17, 0x0000000000000001, 0x7040da179181c69c),
        (18, 0x0000000000000001, 0x6053467d46dcb31a),
        (19, 0x0000000000000001, 0x514f42e01d17f46f),
        (20, 0x0000000000000001, 0x338f4901b5f277ec),
        (21, 0x0000000000000001, 0x7dbc2f207b259c53),
        (22, 0x0000000000000001, 0x4f83ea339b55fb6f),
        (23, 0x0000000000000001, 0x92a6aa452b4a8fb5),
        (24, 0x0000000000000001, 0x0b4283c1f50c853a),
        (25, 0x0000000000000001, 0xb78e6ea2bdc3fa56),
        (26, 0x0000000000000001, 0x296fbeaa95574d32),
        (27, 0x0000000000000001, 0x025fa33a36376a3f),
        (28, 0x0000000000000001, 0xd697e7a2e5484ce6),
        (29, 0x0000000000000001, 0x501d00e27bb21c0c),
        (30, 0x0000000000000001, 0x506f1c14e2275203),
        (31, 0x0000000000000001, 0xaac78e91c905ffdc),
        (32, 0x0000000000000001, 0xb1b39019a38490fa),
        (33, 0x0000000000000001, 0xc4fbee73e1325d03),
        (34, 0x0000000000000001, 0xd880b8c440d14943),
        (35, 0x0000000000000001, 0x83d931e3b7263c9e),
        (36, 0x0000000000000001, 0x0049aceb42855bee),
        (37, 0x0000000000000001, 0x7ffd576b605b609a),
        (38, 0x0000000000000001, 0xa5eb0e21bbabe56f),
        (39, 0x0000000000000001, 0x3aa37f7b7395a8d4),
        (40, 0x0000000000000001, 0x9f3bc8fbabe5bfc7),
        (41, 0x0000000000000001, 0x4e95110101838eda),
        (42, 0x0000000000000001, 0x1090a6d4d33c3d3b),
        (43, 0x0000000000000001, 0xf2b5e356bfeee131),
        (44, 0x0000000000000001, 0x0ab9eebaba56a478),
        (45, 0x0000000000000001, 0x9a47b9fd08299fc5),
        (46, 0x0000000000000001, 0x6f91f8d7e88dfb09),
        (47, 0x0000000000000001, 0x3587a5994ef321f3),
        (48, 0x0000000000000001, 0x10881bbfbe1f2829),
        (49, 0x0000000000000001, 0x6ec9468c365d4f3e),
        (50, 0x0000000000000001, 0xbfc449b96ba70998),
        (51, 0x0000000000000001, 0x203dee12339d7ffb),
        (52, 0x0000000000000001, 0x3eba3016e9129ed9),
        (53, 0x0000000000000001, 0x7f21112f0414bc45),
        (54, 0x0000000000000001, 0x3103e38850b5b890),
        (55, 0x0000000000000001, 0xe7e84a23f0efaf0f),
        (56, 0x0000000000000001, 0x33b2dfa72bc5805d),
        (57, 0x0000000000000001, 0xfbe80d3bceb498fb),
        (58, 0x0000000000000001, 0x316d1600a4d1740d),
        (59, 0x0000000000000001, 0x133013889e602f0c),
        (60, 0x0000000000000001, 0x00c706e3107c80a3),
        (61, 0x0000000000000001, 0x42d4086516789ee2),
        (62, 0x0000000000000001, 0x12978a3272e02161),
        (63, 0x0000000000000001, 0x96ced31193074c7b),
        (64, 0x0000000000000001, 0xa6f55554ff1e5a18),
        (65, 0x0000000000000001, 0xf7f37bd8dec7968e),
        (66, 0x0000000000000001, 0x622e8274bd6874b3),
        (67, 0x0000000000000001, 0xb10c54c716e71efa),
        (68, 0x0000000000000001, 0x3e5e77bedab7b876),
        (69, 0x0000000000000001, 0x7d6a14dfbacd076a),
        (70, 0x0000000000000001, 0xdd747e7b26922567),
        (71, 0x0000000000000001, 0x6de3b2c444cf229b),
        (72, 0x0000000000000001, 0x9605d4e3da19e5d1),
        (73, 0x0000000000000001, 0x6bdfb9f6396d1daf),
        (74, 0x0000000000000001, 0x83e7f3ff8d459b50),
        (75, 0x0000000000000001, 0xe55b4798c145316f),
        (76, 0x0000000000000001, 0xf6ea54497e8cfc15),
        (77, 0x0000000000000001, 0xaa8b781f022aa1c8),
        (78, 0x0000000000000001, 0xfe5af70478c05fdb),
        (79, 0x0000000000000001, 0x4bd460507d97c9d7),
        (80, 0x0000000000000001, 0xcc8eb039e0397e73),
        (81, 0x0000000000000001, 0x5d322c61d6e348e0),
        (82, 0x0000000000000001, 0x7eed3ac9c04c68b4),
        (83, 0x0000000000000001, 0xb3ff6fcb6c33de48),
        (84, 0x0000000000000001, 0x24b350450f6a6c0b),
        (85, 0x0000000000000001, 0xf2f938773d9aae51),
        (86, 0x0000000000000001, 0xcb8e475f9fdc721a),
        (87, 0x0000000000000001, 0x8520f6f69c820205),
        (88, 0x0000000000000001, 0x7e6d5bab9a9fc614),
        (89, 0x0000000000000001, 0xbb6da6f7a0f83bbd),
        (90, 0x0000000000000001, 0xc00ad0fa3fcf9cfa),
        (91, 0x0000000000000001, 0xdacd1499ed6f6841),
        (92, 0x0000000000000001, 0xe0a64fafb2388947),
        (93, 0x0000000000000001, 0xb23a970a773d7ab8),
        (94, 0x0000000000000001, 0x6f15711b2a7c80ff),
        (95, 0x0000000000000001, 0x5de8ad9fd5a73cd8),
        (96, 0x0000000000000001, 0x8e3738f2dcac2642),
        (0, 0x0123456789abcdef, 0x565ef32cd8efb3dd),
        (1, 0x0123456789abcdef, 0x5ed83e2608fc233e),
        (2, 0x0123456789abcdef, 0x4051a9439961052b),
        (3, 0x0123456789abcdef, 0xc82eb9221b53d004),
        (4, 0x0123456789abcdef, 0xd8148f849747ec09),
        (5, 0x0123456789abcdef, 0xf9dea057a2d174fe),
        (6, 0x0123456789abcdef, 0xa9acf822e28258d8),
        (7, 0x0123456789abcdef, 0x15ed25ef16203477),
        (8, 0x0123456789abcdef, 0x18266e9028777fa7),
        (9, 0x0123456789abcdef, 0x27dcc8fa30fda633),
        (10, 0x0123456789abcdef, 0x81c002b64cb4199b),
        (11, 0x0123456789abcdef, 0xfea498ad49958f06),
        (12, 0x0123456789abcdef, 0x31c1027d3b5b9071),
        (13, 0x0123456789abcdef, 0xf7c03860e90bcf2c),
        (14, 0x0123456789abcdef, 0xe04d18da3fbfd9b6),
        (15, 0x0123456789abcdef, 0xde8ee23860e293e6),
        (16, 0x0123456789abcdef, 0x020311d9259b9e9e),
        (17, 0x0123456789abcdef, 0x0f6db5ecf711d100),
        (18, 0x0123456789abcdef, 0xef985dac88ca856e),
        (19, 0x0123456789abcdef, 0x15b130d981832ed9),
        (20, 0x0123456789abcdef, 0x5cabbb3c8488bc71),
        (21, 0x0123456789abcdef, 0x970e3045050f3e99),
        (22, 0x0123456789abcdef, 0xfa3d9f8fc718c992),
        (23, 0x0123456789abcdef, 0x9f6ff07fb8021be5),
        (24, 0x0123456789abcdef, 0xca1b7a7125d21f09),
        (25, 0x0123456789abcdef, 0x7cc5f073ee5bd4ff),
        (26, 0x0123456789abcdef, 0x519e85d9853126d4),
        (27, 0x0123456789abcdef, 0x9dc0f8547fc48758),
        (28, 0x0123456789abcdef, 0x62ef5e8b2fa4d917),
        (29, 0x0123456789abcdef, 0x63b686e3dfe17aa5),
        (30, 0x0123456789abcdef, 0x342b0360f1650ffa),
        (31, 0x0123456789abcdef, 0x0c4187b2dabc1b54),
        (32, 0x0123456789abcdef, 0x4458222399725cc3),
        (33, 0x0123456789abcdef, 0x95723ea9a41bf3d7),
        (34, 0x0123456789abcdef, 0x3f9fd7b2e5cd7625),
        (35, 0x0123456789abcdef, 0x571dcba87f58b6b1),
        (36, 0x0123456789abcdef, 0xdb3115cc611e4e16),
        (37, 0x0123456789abcdef, 0xfb7e1b242e350b37),
        (38, 0x0123456789abcdef, 0xfe60e72c25c3d7cd),
        (39, 0x0123456789abcdef, 0xaebc2c27495ff644),
        (40, 0x0123456789abcdef, 0xcbf0e27ed23f532e),
        (41, 0x0123456789abcdef, 0x6542db98e1a76a50),
        (42, 0x0123456789abcdef, 0xa423889dfcba70ca),
        (43, 0x0123456789abcdef, 0x872cbb39533c6007),
        (44, 0x0123456789abcdef, 0x1c752a7cc48bf662),
        (45, 0x0123456789abcdef, 0x946301179e30439d),
        (46, 0x0123456789abcdef, 0x462c5bb37d24a749),
        (47, 0x0123456789abcdef, 0x836712ff3b012d08),
        (48, 0x0123456789abcdef, 0x4d155e31fbf3ddbc),
        (49, 0x0123456789abcdef, 0x843f6c16feaa421e),
        (50, 0x0123456789abcdef, 0x00e583767a5796af),
        (51, 0x0123456789abcdef, 0x2848685801cd692b),
        (52, 0x0123456789abcdef, 0x93796667bc4c74ac),
        (53, 0x0123456789abcdef, 0x60fb9a55cf8a3626),
        (54, 0x0123456789abcdef, 0xe6c667959fb961d6),
        (55, 0x0123456789abcdef, 0x22fb51e4317aaf18),
        (56, 0x0123456789abcdef, 0x58201be7c8f6779f),
        (57, 0x0123456789abcdef, 0x15ef60d4146a9ef6),
        (58, 0x0123456789abcdef, 0xa1b6f9d7fe6f823d),
        (59, 0x0123456789abcdef, 0x4ede91387c275ae8),
        (60, 0x0123456789abcdef, 0xb42c5f93b1a826b7),
        (61, 0x0123456789abcdef, 0x16b5683f5e00c9d6),
        (62, 0x0123456789abcdef, 0x36b4d7f6182423c0),
        (63, 0x0123456789abcdef, 0x1f1813b658f750ec),
        (64, 0x0123456789abcdef, 0x7f2c05ce34903c7b),
        (65, 0x0123456789abcdef, 0x51f8d325878818c1),
        (66, 0x0123456789abcdef, 0x05991d3a2b0b4424),
        (67, 0x0123456789abcdef, 0x55d6e80eb9f79e69),
        (68, 0x0123456789abcdef, 0x8c6f584702ace249),
        (69, 0x0123456789abcdef, 0xe496c1b70c45661e),
        (70, 0x0123456789abcdef, 0x7dde56833537d621),
        (71, 0x0123456789abcdef, 0x96a4ca1b3cd33958),
        (72, 0x0123456789abcdef, 0xdccd05841c52708f),
        (73, 0x0123456789abcdef, 0x6e6f8351fc602d10),
        (74, 0x0123456789abcdef, 0x6da000cc06fde918),
        (75, 0x0123456789abcdef, 0x1cf667b73ec2efaf),
        (76, 0x0123456789abcdef, 0xb236cfc0d167208f),
        (77, 0x0123456789abcdef, 0x28e321a73b00d758),
        (78, 0x0123456789abcdef, 0x049aedb24b431390),
        (79, 0x0123456789abcdef, 0xd3acc6660a8c4e25),
        (80, 0x0123456789abcdef, 0xc95d53f7ee8a7d88),
        (81, 0x0123456789abcdef, 0xa4a9fdb6f59909d8),
        (82, 0x0123456789abcdef, 0xf95c2a7b53bb3ed5),
        (83, 0x0123456789abcdef, 0x4fb571a8e767f1a1),
        (84, 0x0123456789abcdef, 0x5d4b683539e333db),
        (85, 0x0123456789abcdef, 0xaba22c88a8808e7c),
        (86, 0x0123456789abcdef, 0xee34f51c0c2e3dbc),
        (87, 0x0123456789abcdef, 0x0dfa75a512fe4795),
        (88, 0x0123456789abcdef, 0x0affdc06ae13144e),
        (89, 0x0123456789abcdef, 0x46cdab143c21a128),
        (90, 0x0123456789abcdef, 0x598a4df087a6aec4),
        (91, 0x0123456789abcdef, 0xb26adc48fcb21c94),
        (92, 0x0123456789abcdef, 0x2f7a10e301e216aa),
        (93, 0x0123456789abcdef, 0xb7a04433f798f663),
        (94, 0x0123456789abcdef, 0x2f7de96d0638a55c),
        (95, 0x0123456789abcdef, 0x41a6ce7e11efcc4e),
        (96, 0x0123456789abcdef, 0xd8c7d687ede0bd2b),
        (0, 0xffffffffffffffff, 0x9a9c59147a213be8),
        (1, 0xffffffffffffffff, 0xc6f59f210c3f6013),
        (2, 0xffffffffffffffff, 0xfaa25e856a706fb6),
        (3, 0xffffffffffffffff, 0xc189f216cf24b75d),
        (4, 0xffffffffffffffff, 0x0a2020858f6bef41),
        (5, 0xffffffffffffffff, 0xea214f4e453f074b),
        (6, 0xffffffffffffffff, 0x3aacdcb5bf391457),
        (7, 0xffffffffffffffff, 0xb09cee6c33d85326),
        (8, 0xffffffffffffffff, 0x66b8cc341b6082f2),
        (9, 0xffffffffffffffff, 0x3450fb356f668496),
        (10, 0xffffffffffffffff, 0xe0b11c6d1bc5d428),
        (11, 0xffffffffffffffff, 0xf795680ae93d20bb),
        (12, 0xffffffffffffffff, 0x14dc5fa863860855),
        (13, 0xffffffffffffffff, 0x34a13b99f17d9808),
        (14, 0xffffffffffffffff, 0x9e8f46b28176176e),
        (15, 0xffffffffffffffff, 0x08e08e403e8a525b),
        (16, 0xffffffffffffffff, 0xc825aadf16a74c53),
        (17, 0xffffffffffffffff, 0xe1fc33d6fd7e114e),
        (18, 0xffffffffffffffff, 0x3ad5119ddd7259f2),
        (19, 0xffffffffffffffff, 0x8ca7ffbdb1474c44),
        (20, 0xffffffffffffffff, 0xe97b66908c100ce1),
        (21, 0xffffffffffffffff, 0xcbc773ffa4ee7614),
        (22, 0xffffffffffffffff, 0x2b1179e2bbbe8d1d),
        (23, 0xffffffffffffffff, 0xf71f89a37211ba66),
        (24, 0xffffffffffffffff, 0xc7d98ef17ce89db2),
        (25, 0xffffffffffffffff, 0x05c8784a20f1a1c0),
        (26, 0xffffffffffffffff, 0xfe4284242252ce8d),
        (27, 0xffffffffffffffff, 0xc86bab998a34433c),
        (28, 0xffffffffffffffff, 0x91ee3b0985573910),
        (29, 0xffffffffffffffff, 0xc581dd56439bf4d4),
        (30, 0xffffffffffffffff, 0x618b65947401a758),
        (31, 0xffffffffffffffff, 0xfc736e872f1d0e97),
        (32, 0xffffffffffffffff, 0x37bd9efc6e2ed6d1),
        (33, 0xffffffffffffffff, 0xf03d46d90bbed71c),
        (34, 0xffffffffffffffff, 0xf13aab3a7dba978c),
        (35, 0xffffffffffffffff, 0xe16f9188e1d8c4c1),
        (36, 0xffffffffffffffff, 0x65520b9451236c60),
        (37, 0xffffffffffffffff, 0x91e28e3ac8c1b3df),
        (38, 0xffffffffffffffff, 0x71348d6fc1af2223),
        (39, 0xffffffffffffffff, 0x6c309c45885bb1d9),
        (40, 0xffffffffffffffff, 0xd63418dd4dbe2209),
        (41, 0xffffffffffffffff, 0xb0811fb268cbed0d),
        (42, 0xffffffffffffffff, 0x015a961febd008cb),
        (43, 0xffffffffffffffff, 0xe882dcca911dc92f),
        (44, 0xffffffffffffffff, 0x97500c6270b6fb70),
        (45, 0xffffffffffffffff, 0x0b9212a6a6f80133),
        (46, 0xffffffffffffffff, 0x5f3373b07d79d773),
        (47, 0xffffffffffffffff, 0xe9cf5473a1c0804d),
        (48, 0xffffffffffffffff, 0xce8773ad027db12f),
        (49, 0xffffffffffffffff, 0xd1fb6e364c8d37e2),
        (50, 0xffffffffffffffff, 0xb1d5a9c2c0b5c877),
        (51, 0xffffffffffffffff, 0x5fa9826b73439d44),
        (52, 0xffffffffffffffff, 0x3a8f209babb5299f),
        (53, 0xffffffffffffffff, 0xfc18e8eebdb43621),
        (54, 0xffffffffffffffff, 0x1cb702d49ea8a529),
        (55, 0xffffffffffffffff, 0x775db4745003e2a7),
        (56, 0xffffffffffffffff, 0x2da3f48f067aaca4),
        (57, 0xffffffffffffffff, 0xc6df4da0d809d34e),
        (58, 0xffffffffffffffff, 0x6bdacad3b9c5422b),
        (59, 0xffffffffffffffff, 0x4127f89e3869de6a),
        (60, 0xffffffffffffffff, 0xbd0f475cab233ab7),
        (61, 0xffffffffffffffff, 0x12b39edaa3f0b936),
        (62, 0xffffffffffffffff, 0x41aead92a4168466),
        (63, 0xffffffffffffffff, 0x8cb335c1848f3ece),
        (64, 0xffffffffffffffff, 0x5a54b55f03f5ffa1),
        (65, 0xffffffffffffffff, 0x66286d0b99c13194),
        (66, 0xffffffffffffffff, 0x1fb4ae4f317a0ec5),
        (67, 0xffffffffffffffff, 0x11915d2cb95709ae),
        (68, 0xffffffffffffffff, 0xa7df1f554a335058),
        (69, 0xffffffffffffffff, 0x3e880631ce78b8ec),
        (70, 0xffffffffffffffff, 0xefec063a4cb273d9),
        (71, 0xffffffffffffffff, 0x430cdbad06a13ff7),
        (72, 0xffffffffffffffff, 0xb5f58e4be86a602d),
        (73, 0xffffffffffffffff, 0xf89b4d177661d0a2),
        (74, 0xffffffffffffffff, 0x0268783ec70a4dd7),
        (75, 0xffffffffffffffff, 0x0b227b469e27186d),
        (76, 0xffffffffffffffff, 0xcef169ee0767a9b3),
        (77, 0xffffffffffffffff, 0xb8698389ee04f507),
        (78, 0xffffffffffffffff, 0x648a7432ac5317a9),
        (79, 0xffffffffffffffff, 0x766191a4432b4659),
        (80, 0xffffffffffffffff, 0x78da7b48c005946d),
        (81, 0xffffffffffffffff, 0x51c3fa71812ba4de),
        (82, 0xffffffffffffffff, 0xf4f2df728273b600),
        (83, 0xffffffffffffffff, 0xa30942ea2664942e),
        (84, 0xffffffffffffffff, 0x55f6d4ac53025048),
        (85, 0xffffffffffffffff, 0x6b37a23f308f5453),
        (86, 0xffffffffffffffff, 0xdad00027556b7b9a),
        (87, 0xffffffffffffffff, 0xb964e02303ecead4),
        (88, 0xffffffffffffffff, 0x878f8d9e6683fbcd),
        (89, 0xffffffffffffffff, 0xa1ffb2947f9f4bdd),
        (90, 0xffffffffffffffff, 0xdc0e6263c7518d70),
        (91, 0xffffffffffffffff, 0x3b27efa671f2a680),
        (92, 0xffffffffffffffff, 0x618aa0a982ac4ccc),
        (93, 0xffffffffffffffff, 0x5a76972f24a4fb9e),
        (94, 0xffffffffffffffff, 0xf3e7537cadcc9fcd),
        (95, 0xffffffffffffffff, 0x4de993417d3ffd5e),
        (96, 0xffffffffffffffff, 0x6ef02a90c8b6d57c),
        (100, 0x0000000000000000, 0xde3884105eba67a1),
        (120, 0x0000000000000000, 0xf2c7e73ba2bea384),
        (140, 0x0000000000000000, 0x76e9a5eeeac9ccab),
        (160, 0x0000000000000000, 0xde2097b4223c1d23),
        (180, 0x0000000000000000, 0xd6bc3297a4baca6f),
        (200, 0x0000000000000000, 0xf4bca4fba5e6401a),
        (220, 0x0000000000000000, 0x75aa23ae4ad5d0cb),
        (240, 0x0000000000000000, 0x606ae9bec2f3a05f),
        (260, 0x0000000000000000, 0x63ab37c043050b14),
    ];

    #[test]
    fn hash_matches_the_c_reference() {
        let buf: Vec<u8> = (0..300u32).map(|i| (i * 7 + 3) as u8).collect();
        for &(len, seed, want) in VECTORS {
            assert_eq!(
                hash_seeded(&buf[..len], seed),
                want,
                "len={len} seed={seed:#018x}"
            );
        }
    }

    #[test]
    fn hash_is_seeded_per_process_and_stable_within_it() {
        // Same input, same answer, every time — the cache depends on it.
        let name = b"\x03www\x07example\x03com\x00";
        assert_eq!(hash(name), hash(name));
        // Different seeds must give different results, or seeding buys nothing.
        assert_ne!(hash_seeded(name, 1), hash_seeded(name, 2));
    }

    #[test]
    fn hash_extend_separates_qtype_and_qclass() {
        let name = hash(b"\x07example\x03com\x00");
        let a = hash_extend(name, (1u64 << 16) | 1); // A / IN
        let b = hash_extend(name, (28u64 << 16) | 1); // AAAA / IN
        let c = hash_extend(name, (1u64 << 16) | 3); // A / CH
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }
}
