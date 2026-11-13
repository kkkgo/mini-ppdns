// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

//! `dns://` upstreams: the DNS servers the host's own network configuration
//! hands out, looked up per interface.
//!
//! Every source here is best effort. Each OS family keeps this information in
//! a different place and some keep it nowhere readable, so a lookup that finds
//! nothing is normal and the caller substitutes [`DEFAULT_SERVERS`].
//!
//! Reading the system ([`Snapshot::gather`]) is kept apart from choosing from
//! what was read ([`Snapshot::select`]) so the choice can be tested against
//! fixtures.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::util::v6_is_link_local;

/// Used for a `dns://` upstream when nothing usable was found.
pub const DEFAULT_SERVERS: [IpAddr; 2] = [
    IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)),
    IpAddr::V4(Ipv4Addr::new(119, 29, 29, 29)),
];

/// netifd's per-interface resolver file; the second path is where releases
/// before the `resolv.conf.d` directory keep it (newer ones symlink it).
const NETIFD_RESOLV: [&str; 2] = [
    "/tmp/resolv.conf.d/resolv.conf.auto",
    "/tmp/resolv.conf.auto",
];

/// Whole-system resolver files, consulted in order by `dns://%` when no
/// interface-specific answer exists. systemd-resolved's stub file is absent on
/// purpose: it only ever names the local stub.
const GLOBAL_RESOLV: [&str; 6] = [
    NETIFD_RESOLV[0],
    NETIFD_RESOLV[1],
    "/tmp/resolv.conf.ppp",
    "/run/systemd/resolve/resolv.conf",
    "/etc/resolv.conf",
    "/etc/ppp/resolv.conf",
];

/// `ubus` answers in milliseconds; this only bounds a wedged ubusd.
const UBUS_TIMEOUT: Duration = Duration::from_secs(2);

const RTF_UP: u32 = 0x0001;
const RTF_REJECT: u32 = 0x0200;

/// Which interface's DNS a `dns://` entry asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Selector {
    /// `dns://%`: the interface traffic leaves through.
    Auto,
    /// `dns://<name>`: a kernel device name, or an OpenWrt logical interface.
    Iface(String),
}

impl Selector {
    /// `None` when `entry` is not a `dns://` entry at all; `Some(Err)` when it
    /// is one but names no interface.
    pub fn parse(entry: &str) -> Option<Result<Selector, String>> {
        let name = entry.trim().strip_prefix("dns://")?;
        Some(match name {
            "%" => Ok(Selector::Auto),
            "" => Err(format!(
                "{entry:?} names no interface (use dns://% for automatic)"
            )),
            n if n.chars().any(|c| c.is_whitespace() || c == '/') => {
                Err(format!("{entry:?} is not a valid interface name"))
            }
            n => Ok(Selector::Iface(n.to_string())),
        })
    }
}

impl fmt::Display for Selector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Selector::Auto => f.write_str("dns://%"),
            Selector::Iface(n) => write!(f, "dns://{n}"),
        }
    }
}

/// Whether `name` can be a kernel interface name, as `SO_BINDTODEVICE` needs:
/// 1 to `IFNAMSIZ - 1` bytes, not `.` or `..`, and no `/`, `:` or whitespace
/// (the kernel's own `dev_valid_name` rules).
pub fn valid_ifname(name: &str) -> bool {
    !name.is_empty()
        && name.len() < libc::IF_NAMESIZE
        && name != "."
        && name != ".."
        && !name
            .chars()
            .any(|c| c == '/' || c == ':' || c.is_whitespace())
}

/// One lookup to perform: a selector, and for `dns://%` the egress interface
/// that decides what it means. A named selector does not depend on the
/// egress, so [`Lookup::new`] leaves it out and equal names share a lookup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lookup {
    pub selector: Selector,
    pub egress: Option<Arc<str>>,
}

impl Lookup {
    pub fn new(selector: Selector, egress: Option<Arc<str>>) -> Lookup {
        let egress = egress.filter(|_| selector == Selector::Auto);
        Lookup { selector, egress }
    }
}

impl fmt::Display for Lookup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.egress {
            Some(dev) => write!(f, "{dev}@{}", self.selector),
            None => self.selector.fmt(f),
        }
    }
}

/// The servers chosen for one selector and where they were read from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Found {
    pub servers: Vec<IpAddr>,
    pub source: String,
}

/// Perform every lookup against one reading of the system.
pub async fn detect(lookups: &[Lookup]) -> Vec<Option<Found>> {
    let snap = Snapshot::gather().await;
    lookups
        .iter()
        .map(|l| snap.select(&l.selector, l.egress.as_deref()))
        .collect()
}

/// What one source knows about one interface.
#[derive(Debug, Default)]
struct Link {
    /// Every name the interface answers to: OpenWrt logical name, layer-3
    /// device, underlying device.
    names: Vec<String>,
    /// A PPP uplink. On a router that is the WAN, whichever way the default
    /// route points.
    ppp: bool,
    servers: Vec<IpAddr>,
    source: String,
}

impl Link {
    fn is(&self, name: &str) -> bool {
        self.names.iter().any(|n| n == name)
    }
}

#[derive(Debug, Default)]
pub struct Snapshot {
    links: Vec<Link>,
    /// Devices carrying a default route, preferred first.
    egress: Vec<String>,
    /// Whole-system resolver files that exist, in [`GLOBAL_RESOLV`] order.
    global: Vec<(&'static str, Vec<IpAddr>)>,
    /// This host's own addresses: a server among them is this process or a
    /// local stub, and forwarding to it would loop.
    local: Vec<IpAddr>,
}

impl Snapshot {
    pub async fn gather() -> Snapshot {
        let mut links = Vec::new();
        if is_openwrt() {
            match netifd_dump().await.and_then(|j| netifd_links(&j)) {
                Some(l) => links.extend(l),
                None => links.extend(netifd_file_links(
                    &read_first(&NETIFD_RESOLV),
                    &read("/var/state/network"),
                )),
            }
        }
        links.extend(indexed_links(
            "/run/NetworkManager/devices",
            "NetworkManager",
            networkmanager_servers,
        ));
        links.extend(indexed_links(
            "/run/systemd/netif/links",
            "systemd-networkd",
            networkd_servers,
        ));
        let global = GLOBAL_RESOLV
            .iter()
            .filter_map(|p| Some((*p, nameservers(&std::fs::read_to_string(p).ok()?))))
            .collect();
        let local = if_addrs::get_if_addrs()
            .map(|v| v.into_iter().map(|i| i.ip()).collect())
            .unwrap_or_default();
        Snapshot {
            links,
            egress: default_route_devs(&read("/proc/net/route"), &read("/proc/net/ipv6_route")),
            global,
            local,
        }
    }

    pub fn select(&self, sel: &Selector, out: Option<&str>) -> Option<Found> {
        match (sel, out) {
            (Selector::Iface(name), _) => self.links_answer(|l| l.is(name)),
            (Selector::Auto, Some(dev)) => self
                .links_answer(|l| l.is(dev))
                .or_else(|| self.global_answer()),
            (Selector::Auto, None) => self
                .links_answer(|l| l.ppp && self.egress.iter().any(|e| l.is(e)))
                .or_else(|| self.links_answer(|l| l.ppp))
                .or_else(|| {
                    self.egress
                        .iter()
                        .find_map(|e| self.links_answer(|l| l.is(e)))
                })
                .or_else(|| self.global_answer()),
        }
    }

    fn links_answer(&self, wanted: impl Fn(&Link) -> bool) -> Option<Found> {
        let mut servers = Vec::new();
        for link in self.links.iter().filter(|l| wanted(l)) {
            servers.extend(link.servers.iter().map(|ip| (*ip, link.source.as_str())));
        }
        self.answer(servers)
    }

    fn global_answer(&self) -> Option<Found> {
        self.global
            .iter()
            .find_map(|(path, list)| self.answer(list.iter().map(|ip| (*ip, *path)).collect()))
    }

    /// The usable servers among `candidates`, each once, and the sources that
    /// supplied the ones kept. IPv4 servers win when there are any: an
    /// interface that has both usually hands out the same resolvers twice, and
    /// every extra upstream widens each query's fan-out.
    fn answer(&self, mut candidates: Vec<(IpAddr, &str)>) -> Option<Found> {
        candidates.retain(|(ip, _)| self.usable(ip));
        if candidates.iter().any(|(ip, _)| ip.is_ipv4()) {
            candidates.retain(|(ip, _)| ip.is_ipv4());
        }
        let mut servers: Vec<IpAddr> = Vec::new();
        let mut sources: Vec<&str> = Vec::new();
        for (ip, source) in candidates {
            if !servers.contains(&ip) {
                servers.push(ip);
            }
            if !sources.contains(&source) {
                sources.push(source);
            }
        }
        (!servers.is_empty()).then(|| Found {
            servers,
            source: sources.join(", "),
        })
    }

    fn usable(&self, ip: &IpAddr) -> bool {
        if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() || self.local.contains(ip) {
            return false;
        }
        match ip {
            IpAddr::V4(v4) => !v4.is_broadcast(),
            // A link-local server needs a scope the file did not record.
            IpAddr::V6(v6) => !v6_is_link_local(*v6),
        }
    }
}

fn read(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

fn read_first(paths: &[&str]) -> String {
    paths
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
        .unwrap_or_default()
}

fn is_openwrt() -> bool {
    std::path::Path::new("/etc/openwrt_release").exists()
        || NETIFD_RESOLV
            .iter()
            .any(|p| std::path::Path::new(p).exists())
}

/// Every `nameserver` address in resolv.conf syntax.
fn nameservers(text: &str) -> Vec<IpAddr> {
    resolv_groups(text)
        .into_iter()
        .flat_map(|(_, v)| v)
        .collect()
}

/// `nameserver` addresses grouped under netifd's `# Interface <name>` headers;
/// addresses before any header land in a group named by `None`.
fn resolv_groups(text: &str) -> Vec<(Option<&str>, Vec<IpAddr>)> {
    let mut groups: Vec<(Option<&str>, Vec<IpAddr>)> = vec![(None, Vec::new())];
    for line in text.lines() {
        let line = line.trim();
        if let Some(name) = line.strip_prefix("# Interface ") {
            groups.push((Some(name.trim()), Vec::new()));
            continue;
        }
        let mut fields = line.split_whitespace();
        if fields.next() != Some("nameserver") {
            continue;
        }
        if let Some(ip) = fields.next().and_then(|a| a.parse().ok()) {
            if let Some(g) = groups.last_mut() {
                g.1.push(ip);
            }
        }
    }
    groups.retain(|(_, v)| !v.is_empty());
    groups
}

/// The layer-3 device of each OpenWrt logical interface, from the
/// `network.<iface>.ifname='<dev>'` lines netifd's hotplug writes to
/// `/var/state/network`.
fn netifd_state_devs(state: &str) -> Vec<(&str, &str)> {
    state
        .lines()
        .filter_map(|line| {
            let rest = line.trim().strip_prefix("network.")?;
            let (iface, value) = rest.split_once(".ifname=")?;
            Some((iface, value.trim_matches(|c| c == '\'' || c == '"')))
        })
        .collect()
}

/// netifd's interfaces from its resolver file, for when `ubus` cannot be asked.
/// Each group is matched by its logical name and, where hotplug recorded one,
/// its layer-3 device. A dynamic `<iface>_6` (the DHCPv6 child netifd creates
/// for `ipv6 auto`) is never recorded and shares its parent's device.
fn netifd_file_links(resolv: &str, state: &str) -> Vec<Link> {
    let devs = netifd_state_devs(state);
    let dev_of = |iface: &str| devs.iter().find(|(i, _)| *i == iface).map(|(_, d)| *d);
    resolv_groups(resolv)
        .into_iter()
        .filter_map(|(iface, servers)| {
            let iface = iface?;
            let dev = dev_of(iface).or_else(|| iface.strip_suffix("_6").and_then(dev_of));
            let mut names = vec![iface.to_string()];
            if let Some(d) = dev {
                names.push(d.to_string());
            }
            Some(Link {
                names,
                ppp: dev.is_some_and(|d| d.starts_with("pppoe-")),
                servers,
                source: format!("netifd {iface}"),
            })
        })
        .collect()
}

async fn netifd_dump() -> Option<Vec<u8>> {
    let child = tokio::process::Command::new("ubus")
        .args(["call", "network.interface", "dump"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .ok()?;
    let out = tokio::time::timeout(UBUS_TIMEOUT, child.wait_with_output())
        .await
        .ok()?
        .ok()?;
    out.status.success().then_some(out.stdout)
}

/// Interfaces from `ubus call network.interface dump`, which is netifd's own
/// view: logical name, layer-3 and underlying device, protocol and DNS
/// servers. Interfaces that are down are left out. `None` when the output is
/// not that document.
fn netifd_links(dump: &[u8]) -> Option<Vec<Link>> {
    let root = json::parse(dump)?;
    let mut links = Vec::new();
    for itf in root.get("interface")?.items() {
        if !matches!(itf.get("up"), Some(json::Value::Bool(true))) {
            continue;
        }
        let field = |k| str_field(itf, k);
        let l3 = field("l3_device");
        let mut names: Vec<String> = Vec::new();
        for n in [field("interface"), l3, field("device")]
            .into_iter()
            .flatten()
        {
            if !names.iter().any(|x| x == n) {
                names.push(n.to_string());
            }
        }
        let servers = itf
            .get("dns-server")
            .map(|v| v.items().filter_map(|s| s.as_str()?.parse().ok()).collect())
            .unwrap_or_default();
        links.push(Link {
            ppp: field("proto") == Some("pppoe") || l3.is_some_and(|d| d.starts_with("pppoe-")),
            source: format!("netifd {}", field("interface").unwrap_or("?")),
            names,
            servers,
        });
    }
    Some(links)
}

fn str_field<'a>(v: &'a json::Value, key: &str) -> Option<&'a str> {
    v.get(key)
        .and_then(json::Value::as_str)
        .filter(|s| !s.is_empty())
}

/// One link per file in a directory of per-interface state files named by
/// interface index, as NetworkManager and systemd-networkd keep them.
fn indexed_links(dir: &str, source: &str, parse: fn(&str) -> Vec<IpAddr>) -> Vec<Link> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| {
            let index: u32 = e.file_name().to_str()?.parse().ok()?;
            let name = if_name(index)?;
            let servers = parse(&std::fs::read_to_string(e.path()).ok()?);
            (!servers.is_empty()).then(|| Link {
                names: vec![name],
                ppp: false,
                servers,
                source: source.to_string(),
            })
        })
        .collect()
}

fn if_name(index: u32) -> Option<String> {
    let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: `buf` is IF_NAMESIZE bytes, which is what if_indextoname writes
    // at most, NUL included.
    let p = unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) };
    if p.is_null() {
        return None;
    }
    // SAFETY: on success `buf` holds a NUL-terminated name.
    let name = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
    name.to_str().ok().map(str::to_string)
}

/// Servers NetworkManager learned over DHCP, from its
/// `/run/NetworkManager/devices/<index>` file.
fn networkmanager_servers(text: &str) -> Vec<IpAddr> {
    text.lines()
        .filter_map(|l| {
            l.strip_prefix("dhcp4.domain_name_servers=")
                .or_else(|| l.strip_prefix("dhcp6.dhcp6_name_servers="))
        })
        .flat_map(str::split_whitespace)
        .filter_map(|a| a.parse().ok())
        .collect()
}

/// Servers from systemd-networkd's `DNS=` line. Entries may carry a port, an
/// interface scope and a server name: `[2001:db8::1]:53%2#dns.example`.
fn networkd_servers(text: &str) -> Vec<IpAddr> {
    text.lines()
        .filter_map(|l| l.strip_prefix("DNS="))
        .flat_map(str::split_whitespace)
        .filter_map(|a| {
            let a = a.split(['#', '%']).next()?;
            a.parse::<IpAddr>()
                .or_else(|_| a.parse::<SocketAddr>().map(|s| s.ip()))
                .ok()
        })
        .collect()
}

/// Devices with a default route, IPv4 before IPv6 and lowest metric first
/// within each.
fn default_route_devs(v4: &str, v6: &str) -> Vec<String> {
    let mut routes: Vec<(u8, u32, &str)> = Vec::new();
    // Iface Destination Gateway Flags RefCnt Use Metric Mask ...; addresses and
    // flags in hex, metric in decimal.
    for f in v4
        .lines()
        .skip(1)
        .map(|l| l.split_whitespace().collect::<Vec<_>>())
    {
        if f.len() < 8 || f[1] != "00000000" || f[7] != "00000000" {
            continue;
        }
        let flags = u32::from_str_radix(f[3], 16).unwrap_or(0);
        if flags & RTF_UP != 0 && flags & RTF_REJECT == 0 && f[0] != "*" {
            routes.push((0, f[6].parse().unwrap_or(u32::MAX), f[0]));
        }
    }
    // dest plen src splen nexthop metric refcnt use flags dev; all hex.
    for f in v6.lines().map(|l| l.split_whitespace().collect::<Vec<_>>()) {
        if f.len() < 10 || f[1] != "00" || f[0].bytes().any(|b| b != b'0') {
            continue;
        }
        let flags = u32::from_str_radix(f[8], 16).unwrap_or(0);
        if flags & RTF_UP != 0 && flags & RTF_REJECT == 0 && f[9] != "lo" {
            routes.push((1, u32::from_str_radix(f[5], 16).unwrap_or(u32::MAX), f[9]));
        }
    }
    // Insertion sort, stable: there are only a handful of routes, and the
    // general-purpose sort would cost far more code than it saves time.
    for i in 1..routes.len() {
        let mut j = i;
        while j > 0 && (routes[j - 1].0, routes[j - 1].1) > (routes[j].0, routes[j].1) {
            routes.swap(j - 1, j);
            j -= 1;
        }
    }
    let mut devs: Vec<String> = Vec::new();
    for (_, _, dev) in routes {
        if !devs.iter().any(|d| d == dev) {
            devs.push(dev.to_string());
        }
    }
    devs
}

/// Just enough JSON to read `ubus` output.
mod json {
    /// Nesting beyond this is refused rather than recursed into.
    const MAX_DEPTH: u32 = 32;

    #[derive(Debug, PartialEq)]
    pub enum Value {
        Null,
        Bool(bool),
        /// Numbers are recognised and skipped; nothing here reads one.
        Num,
        Str(String),
        Arr(Vec<Value>),
        Obj(Vec<(String, Value)>),
    }

    impl Value {
        pub fn get(&self, key: &str) -> Option<&Value> {
            match self {
                Value::Obj(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
                _ => None,
            }
        }

        /// Array elements; nothing for any other value.
        pub fn items(&self) -> std::slice::Iter<'_, Value> {
            match self {
                Value::Arr(items) => items.iter(),
                _ => [].iter(),
            }
        }

        pub fn as_str(&self) -> Option<&str> {
            match self {
                Value::Str(s) => Some(s),
                _ => None,
            }
        }
    }

    pub fn parse(text: &[u8]) -> Option<Value> {
        let mut p = Parser { b: text, i: 0 };
        let v = p.value(0)?;
        p.ws();
        (p.i == text.len()).then_some(v)
    }

    struct Parser<'a> {
        b: &'a [u8],
        i: usize,
    }

    impl Parser<'_> {
        fn ws(&mut self) {
            while matches!(self.b.get(self.i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
                self.i += 1;
            }
        }

        fn eat(&mut self, c: u8) -> bool {
            self.ws();
            let hit = self.b.get(self.i) == Some(&c);
            if hit {
                self.i += 1;
            }
            hit
        }

        fn value(&mut self, depth: u32) -> Option<Value> {
            self.ws();
            match *self.b.get(self.i)? {
                b'{' | b'[' if depth >= MAX_DEPTH => None,
                b'{' => {
                    self.i += 1;
                    let mut members = Vec::new();
                    if self.eat(b'}') {
                        return Some(Value::Obj(members));
                    }
                    loop {
                        self.ws();
                        let k = self.string()?;
                        if !self.eat(b':') {
                            return None;
                        }
                        members.push((k, self.value(depth + 1)?));
                        if self.eat(b'}') {
                            return Some(Value::Obj(members));
                        }
                        if !self.eat(b',') {
                            return None;
                        }
                    }
                }
                b'[' => {
                    self.i += 1;
                    let mut items = Vec::new();
                    if self.eat(b']') {
                        return Some(Value::Arr(items));
                    }
                    loop {
                        items.push(self.value(depth + 1)?);
                        if self.eat(b']') {
                            return Some(Value::Arr(items));
                        }
                        if !self.eat(b',') {
                            return None;
                        }
                    }
                }
                b'"' => self.string().map(Value::Str),
                b't' => self.word("true", Value::Bool(true)),
                b'f' => self.word("false", Value::Bool(false)),
                b'n' => self.word("null", Value::Null),
                b'-' | b'0'..=b'9' => {
                    let start = self.i;
                    while matches!(
                        self.b.get(self.i),
                        Some(b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E')
                    ) {
                        self.i += 1;
                    }
                    (self.i > start).then_some(Value::Num)
                }
                _ => None,
            }
        }

        fn word(&mut self, w: &str, v: Value) -> Option<Value> {
            let end = self.i + w.len();
            if self.b.get(self.i..end)? != w.as_bytes() {
                return None;
            }
            self.i = end;
            Some(v)
        }

        fn hex4(&mut self) -> Option<u32> {
            let s = std::str::from_utf8(self.b.get(self.i..self.i + 4)?).ok()?;
            let v = u32::from_str_radix(s, 16).ok()?;
            self.i += 4;
            Some(v)
        }

        fn string(&mut self) -> Option<String> {
            if self.b.get(self.i) != Some(&b'"') {
                return None;
            }
            self.i += 1;
            let mut out = Vec::new();
            loop {
                let c = *self.b.get(self.i)?;
                self.i += 1;
                match c {
                    b'"' => return String::from_utf8(out).ok(),
                    b'\\' => {
                        let e = *self.b.get(self.i)?;
                        self.i += 1;
                        let ch = match e {
                            b'"' | b'\\' | b'/' => e as char,
                            b'b' => '\u{8}',
                            b'f' => '\u{c}',
                            b'n' => '\n',
                            b'r' => '\r',
                            b't' => '\t',
                            b'u' => {
                                let hi = self.hex4()?;
                                let code = if (0xD800..0xDC00).contains(&hi)
                                    && self.b.get(self.i..self.i + 2) == Some(b"\\u")
                                {
                                    self.i += 2;
                                    let lo = self.hex4()?;
                                    if !(0xDC00..0xE000).contains(&lo) {
                                        return None;
                                    }
                                    0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                                } else {
                                    hi
                                };
                                char::from_u32(code).unwrap_or('\u{FFFD}')
                            }
                            _ => return None,
                        };
                        let mut tmp = [0u8; 4];
                        out.extend_from_slice(ch.encode_utf8(&mut tmp).as_bytes());
                    }
                    c if c < 0x20 => return None,
                    c => out.push(c),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn ips(list: &[&str]) -> Vec<IpAddr> {
        list.iter().map(|s| ip(s)).collect()
    }

    fn link(names: &[&str], ppp: bool, servers: &[&str], source: &str) -> Link {
        Link {
            names: names.iter().map(|s| s.to_string()).collect(),
            ppp,
            servers: ips(servers),
            source: source.to_string(),
        }
    }

    /// The shape of a PPPoE OpenWrt router's `ubus call network.interface
    /// dump`, documentation addresses substituted: a PPPoE `wan` over `eth1`,
    /// its DHCPv6 child `wan_6` on the same layer-3 device, a static interface
    /// sharing `eth1`, the LAN bridge, and a down interface with servers.
    const UBUS_DUMP: &str = r#"{
        "interface": [
            { "interface": "ONT", "up": true, "l3_device": "eth1", "proto": "static",
              "device": "eth1", "metric": 0, "dns-server": [ ],
              "inactive": { "dns-server": [ "203.0.113.99" ] } },
            { "interface": "lan", "up": true, "l3_device": "br-lan", "proto": "static",
              "device": "br-lan", "dns-server": [ ], "data": { } },
            { "interface": "wan", "up": true, "pending": false, "l3_device": "pppoe-wan",
              "proto": "pppoe", "device": "eth1", "uptime": 8302943,
              "ipv4-address": [ { "address": "198.51.100.75", "mask": 32 } ],
              "dns-server": [ "192.0.2.86", "192.0.2.33" ] },
            { "interface": "wan_6", "up": true, "l3_device": "pppoe-wan", "proto": "dhcpv6",
              "device": "pppoe-wan", "dns-server": [ "2001:db8:1::1", "2001:db8:1::33" ] },
            { "interface": "wwan", "up": false, "l3_device": "wlan1", "proto": "dhcp",
              "device": "wlan1", "dns-server": [ "203.0.113.7" ] }
        ]
    }"#;

    fn router() -> Snapshot {
        Snapshot {
            links: netifd_links(UBUS_DUMP.as_bytes()).unwrap(),
            egress: vec!["pppoe-wan".into()],
            global: vec![("/etc/resolv.conf", ips(&["127.0.0.1", "::1"]))],
            local: vec![ip("10.10.10.1"), ip("127.0.0.1")],
        }
    }

    #[test]
    fn entries_parse_into_selectors() {
        assert_eq!(Selector::parse("dns://%"), Some(Ok(Selector::Auto)));
        assert_eq!(
            Selector::parse(" dns://eth0 "),
            Some(Ok(Selector::Iface("eth0".into())))
        );
        assert!(matches!(Selector::parse("dns://"), Some(Err(_))));
        assert!(matches!(Selector::parse("dns://a b"), Some(Err(_))));
        assert_eq!(Selector::parse("10.0.0.1"), None, "not a dns:// entry");
        assert_eq!(Selector::parse("udp://10.0.0.1"), None);
        assert_eq!(Selector::Auto.to_string(), "dns://%");
        assert_eq!(Selector::Iface("wan".into()).to_string(), "dns://wan");
    }

    #[test]
    fn interface_names_follow_the_kernels_rules() {
        for ok in ["eth0", "pppoe-wan", "br-lan", "eth0.6", "abcdefghijklmno"] {
            assert!(valid_ifname(ok), "{ok}");
        }
        for bad in ["", ".", "..", "a/b", "eth0:1", "a b", "abcdefghijklmnop"] {
            assert!(!valid_ifname(bad), "{bad:?}");
        }
    }

    #[test]
    fn only_automatic_lookups_depend_on_the_egress() {
        let dev: Option<Arc<str>> = Some(Arc::from("eth0"));
        let auto = Lookup::new(Selector::Auto, dev.clone());
        assert_eq!(auto.egress.as_deref(), Some("eth0"));
        assert_eq!(auto.to_string(), "eth0@dns://%");
        assert_ne!(auto, Lookup::new(Selector::Auto, None));
        let wan = Lookup::new(Selector::Iface("wan".into()), dev);
        assert_eq!(
            wan,
            Lookup::new(Selector::Iface("wan".into()), None),
            "a named interface means the same whatever the binding"
        );
        assert_eq!(wan.to_string(), "dns://wan");
    }

    #[test]
    fn netifd_interfaces_answer_to_every_name() {
        let snap = router();
        let wan = Found {
            servers: ips(&["192.0.2.86", "192.0.2.33"]),
            source: "netifd wan".into(),
        };
        // The PPP device, the logical name, and the Ethernet port under it.
        for name in ["pppoe-wan", "wan", "eth1"] {
            let got = snap.select(&Selector::Iface(name.into()), None);
            assert_eq!(
                got.as_ref().map(|f| &f.servers),
                Some(&wan.servers),
                "{name}"
            );
        }
        assert_eq!(
            snap.select(&Selector::Iface("wan_6".into()), None)
                .unwrap()
                .servers,
            ips(&["2001:db8:1::1", "2001:db8:1::33"]),
            "an interface with only IPv6 servers keeps them"
        );
        assert_eq!(snap.select(&Selector::Iface("br-lan".into()), None), None);
        assert_eq!(
            snap.select(&Selector::Iface("wlan1".into()), None),
            None,
            "an interface that is down offers nothing"
        );
        assert_eq!(snap.select(&Selector::Iface("eth9".into()), None), None);
    }

    #[test]
    fn auto_prefers_the_ppp_uplink_over_the_default_route() {
        let mut snap = router();
        // The default route leaves through a side gateway on the LAN.
        snap.egress = vec!["br-lan".into()];
        snap.links
            .push(link(&["br-lan"], false, &["10.10.10.3"], "test"));
        let got = snap.select(&Selector::Auto, None).unwrap();
        assert_eq!(got.servers, ips(&["192.0.2.86", "192.0.2.33"]));
        assert_eq!(got.source, "netifd wan");
    }

    #[test]
    fn auto_takes_the_ppp_link_the_default_route_uses_first() {
        let snap = Snapshot {
            links: vec![
                link(&["wanb", "pppoe-wanb"], true, &["192.0.2.2"], "netifd wanb"),
                link(&["wana", "pppoe-wana"], true, &["192.0.2.1"], "netifd wana"),
            ],
            egress: vec!["pppoe-wana".into()],
            ..Snapshot::default()
        };
        assert_eq!(
            snap.select(&Selector::Auto, None).unwrap().servers,
            ips(&["192.0.2.1"])
        );
    }

    #[test]
    fn auto_follows_the_default_route_without_ppp() {
        let snap = Snapshot {
            links: vec![
                link(&["enx1"], false, &["192.168.88.1"], "NetworkManager"),
                link(&["br0"], false, &["10.10.10.1"], "NetworkManager"),
            ],
            egress: vec!["br0".into(), "enx1".into()],
            ..Snapshot::default()
        };
        let got = snap.select(&Selector::Auto, None).unwrap();
        assert_eq!(got.servers, ips(&["10.10.10.1"]));
        assert_eq!(got.source, "NetworkManager");
    }

    #[test]
    fn out_decides_what_auto_means() {
        let mut snap = router();
        snap.links
            .push(link(&["eth0.6"], false, &["10.6.6.53"], "test"));
        assert_eq!(
            snap.select(&Selector::Auto, Some("eth0.6"))
                .unwrap()
                .servers,
            ips(&["10.6.6.53"]),
            "the egress interface was named, so the PPP preference does not apply"
        );
        // Named interfaces are unaffected by `out`.
        assert_eq!(
            snap.select(&Selector::Iface("wan".into()), Some("eth0.6"))
                .unwrap()
                .servers,
            ips(&["192.0.2.86", "192.0.2.33"])
        );
    }

    #[test]
    fn auto_falls_back_to_the_first_global_file_with_a_usable_server() {
        let snap = Snapshot {
            egress: vec!["eth0".into()],
            global: vec![
                // systemd-resolved stub and the router's own address: both loop.
                (
                    "/run/systemd/resolve/resolv.conf",
                    ips(&["127.0.0.53", "10.0.0.2"]),
                ),
                (
                    "/etc/resolv.conf",
                    ips(&["192.0.2.53", "192.0.2.53", "2001:db8::53"]),
                ),
            ],
            local: vec![ip("10.0.0.2")],
            ..Snapshot::default()
        };
        let got = snap.select(&Selector::Auto, None).unwrap();
        assert_eq!(got.servers, ips(&["192.0.2.53"]), "deduplicated, IPv4 kept");
        assert_eq!(got.source, "/etc/resolv.conf");
        // Out named but unknown: the global files still answer.
        assert!(snap.select(&Selector::Auto, Some("eth5")).is_some());
        // A named interface never borrows the global answer.
        assert_eq!(snap.select(&Selector::Iface("eth0".into()), None), None);
    }

    #[test]
    fn nothing_found_is_none() {
        assert_eq!(router().select(&Selector::Iface("lo".into()), None), None);
        let empty = Snapshot::default();
        assert_eq!(empty.select(&Selector::Auto, None), None);
        // Only unusable servers anywhere.
        let snap = Snapshot {
            links: vec![link(
                &["eth0"],
                false,
                &[
                    "127.0.0.1",
                    "fe80::1",
                    "0.0.0.0",
                    "224.0.0.1",
                    "255.255.255.255",
                ],
                "x",
            )],
            egress: vec!["eth0".into()],
            ..Snapshot::default()
        };
        assert_eq!(snap.select(&Selector::Auto, None), None);
    }

    #[test]
    fn servers_merge_across_links_and_sources_without_repeats() {
        let snap = Snapshot {
            links: vec![
                link(
                    &["eth0"],
                    false,
                    &["192.0.2.1", "192.0.2.2"],
                    "NetworkManager",
                ),
                link(
                    &["eth0"],
                    false,
                    &["192.0.2.2", "192.0.2.3"],
                    "systemd-networkd",
                ),
            ],
            ..Snapshot::default()
        };
        let got = snap.select(&Selector::Iface("eth0".into()), None).unwrap();
        assert_eq!(got.servers, ips(&["192.0.2.1", "192.0.2.2", "192.0.2.3"]));
        assert_eq!(got.source, "NetworkManager, systemd-networkd");
    }

    #[test]
    fn resolv_files_group_by_netifd_interface() {
        let text = "search lan\nnameserver 192.0.2.9\n# Interface wan\nnameserver 192.0.2.86\n\
                    nameserver  192.0.2.33 \n# Interface wan_6\nnameserver 2001:db8:1::1\n\
                    nameserver fe80::1%eth0\n# Interface empty\n";
        let groups = resolv_groups(text);
        assert_eq!(
            groups,
            vec![
                (None, ips(&["192.0.2.9"])),
                (Some("wan"), ips(&["192.0.2.86", "192.0.2.33"])),
                (Some("wan_6"), ips(&["2001:db8:1::1"])),
            ]
        );
        assert_eq!(nameservers(text).len(), 4);
    }

    #[test]
    fn netifd_files_stand_in_for_ubus() {
        let resolv = "# Interface wan\nnameserver 192.0.2.86\n# Interface wan_6\n\
                      nameserver 2001:db8:1::1\n# Interface lan2\nnameserver 192.0.2.7\n";
        let state = "network.lan.up='1'\nnetwork.lan.ifname='br-lan'\n\
                     network.wan.up='1'\nnetwork.wan.ifname='pppoe-wan'\n";
        let snap = Snapshot {
            links: netifd_file_links(resolv, state),
            egress: vec!["pppoe-wan".into()],
            ..Snapshot::default()
        };
        assert_eq!(
            snap.select(&Selector::Iface("pppoe-wan".into()), None)
                .unwrap()
                .servers,
            ips(&["192.0.2.86"]),
            "the device found through /var/state; IPv4 preferred over wan_6"
        );
        assert_eq!(
            snap.select(&Selector::Iface("wan_6".into()), None)
                .unwrap()
                .servers,
            ips(&["2001:db8:1::1"])
        );
        assert_eq!(
            snap.select(&Selector::Iface("lan2".into()), None)
                .unwrap()
                .servers,
            ips(&["192.0.2.7"]),
            "a group with no recorded device still answers to its logical name"
        );
        let auto = snap.select(&Selector::Auto, None).unwrap();
        assert_eq!(auto.servers, ips(&["192.0.2.86"]));
        assert_eq!(auto.source, "netifd wan");
    }

    #[test]
    fn networkmanager_and_networkd_files() {
        let nm = "[device]\nmanaged=true\n\n[dhcp4]\ndhcp4.domain_name=lan\n\
                  dhcp4.domain_name_servers=192.168.88.1 192.168.88.2\n\
                  dhcp6.dhcp6_name_servers=2001:db8::1\n";
        assert_eq!(
            networkmanager_servers(nm),
            ips(&["192.168.88.1", "192.168.88.2", "2001:db8::1"])
        );
        let nd = "# This is private data.\nADMIN_STATE=configured\n\
                  DNS=192.0.2.1 192.0.2.2:5353 [2001:db8::1]:53%2#dns.example 2001:db8::2 junk\n\
                  NTP=192.0.2.123\n";
        assert_eq!(
            networkd_servers(nd),
            ips(&["192.0.2.1", "192.0.2.2", "2001:db8::1", "2001:db8::2"])
        );
    }

    #[test]
    fn default_routes_come_out_by_family_then_metric() {
        let v4 =
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                  enx1\t00000000\t0158A8C0\t0003\t0\t0\t20101\t00000000\t0\t0\t0\n\
                  br0\t00000000\t010A0A0A\t0003\t0\t0\t425\t00000000\t0\t0\t0\n\
                  eth2\t00000000\t0102A8C0\t0003\t0\t0\t425\t00000000\t0\t0\t0\n\
                  br0\t000A0A0A\t00000000\t0001\t0\t0\t425\t00FEFFFF\t0\t0\t0\n\
                  *\t00000000\t00000000\t0201\t0\t0\t0\t00000000\t0\t0\t0\n\
                  eth9\t00000000\t01010101\t0002\t0\t0\t1\t00000000\t0\t0\t0\n";
        let v6 = "00000000000000000000000000000000 00 20010db8000000000000000000000000 40 fe800000000000000000000000000001 00000200 00000005 00000000 00000003 pppoe-wan\n\
                  00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000002 00000000 00200200       lo\n\
                  20010db8000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 br0\n";
        assert_eq!(
            default_route_devs(v4, v6),
            vec!["br0", "eth2", "enx1", "pppoe-wan"],
            "metric order, file order among equals; reject, down and non-default routes left out"
        );
        assert!(default_route_devs("", "").is_empty());
    }

    #[test]
    fn json_reads_what_ubus_writes() {
        use json::Value;
        let text = [
            &br#" {"a": [1, -2.5e3, true, false, null, "x\"\\\/\n"#[..],
            b"\\",
            b"u00e9",
            b"\\",
            b"ud83d",
            b"\\",
            b"ude00",
            br#""], "b": {}} "#,
        ]
        .concat();
        let v = json::parse(&text).unwrap();
        let items: Vec<&Value> = v.get("a").unwrap().items().collect();
        assert_eq!(items.len(), 6);
        assert_eq!(items[0], &Value::Num);
        assert_eq!(items[2], &Value::Bool(true));
        assert_eq!(items[4], &Value::Null);
        assert_eq!(items[5].as_str(), Some("x\"\\/\n\u{e9}\u{1F600}"));
        assert_eq!(v.get("b"), Some(&Value::Obj(vec![])));
        assert_eq!(v.get("missing"), None);
        assert_eq!(json::parse(b"[]"), Some(Value::Arr(vec![])));
    }

    #[test]
    fn json_refuses_malformed_input() {
        for bad in [
            &b""[..],
            b"{",
            b"[1,]",
            b"{\"a\" 1}",
            b"{\"a\":1,}",
            b"\"unterminated",
            b"\"bad \\q escape\"",
            b"\"\\ud800\\u0041\"",
            b"tru",
            b"[1] trailing",
            b"\"raw\ncontrol\"",
        ] {
            assert_eq!(json::parse(bad), None, "{:?}", String::from_utf8_lossy(bad));
        }
        let deep = "[".repeat(1000) + &"]".repeat(1000);
        assert_eq!(json::parse(deep.as_bytes()), None, "nesting is bounded");
        let ok = "[".repeat(10) + &"]".repeat(10);
        assert!(json::parse(ok.as_bytes()).is_some());
    }

    #[test]
    fn a_dump_that_is_not_netifds_is_refused() {
        assert!(netifd_links(b"{\"interfaces\": []}").is_none());
        assert!(netifd_links(b"not json").is_none());
        assert_eq!(
            netifd_links(b"{\"interface\": []}").map(|v| v.len()),
            Some(0)
        );
    }
}
