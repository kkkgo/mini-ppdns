// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

//! Runtime assembly and lifecycle: build the forwarders/cache/handler, bind
//! every listen address, run until a signal, then drain.

use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{watch, Notify, Semaphore};

use crate::cache::Cache;
use crate::config::Config;
use crate::forcefall::ForceFallMatcher;
use crate::handler::{AaaaMode, Handler, MAX_LINGERING_MAIN};
use crate::hook::HookMonitor;
use crate::ifdns::{self, Found, Lookup, Selector, DEFAULT_SERVERS};
use crate::local_resolver::{AutoDetect, PtrResolver};
use crate::log;
use crate::server::{serve_tcp, serve_udp};
use crate::sysinfo::{calculate_cache_size, calculate_fallback_cache_size, get_available_memory};
use crate::upstream::{merge_upstreams, Forwarder, LiveUpstreams, Upstream};

// Concurrency caps are per-protocol so a TCP connection flood cannot starve
// UDP query handling (and vice versa): the two share no permits. Each is a
// hard ceiling on in-flight handlers — UDP sheds excess by dropping the
// datagram (see `serve_udp`), TCP by back-pressuring only the offending
// connection.
const MAX_CONCURRENT_UDP: usize = 4096;
const MAX_CONCURRENT_TCP: usize = 1024;
// Hard cap on concurrent TCP *connections*, independent of the per-query TCP
// permit pool above. Bounds task/memory growth under a connection flood;
// excess connections are dropped at accept (see `serve_tcp`).
const MAX_TCP_CONNS: usize = 2048;
// Floors, so a tiny file-descriptor limit still leaves the forwarder usable.
const MIN_CONCURRENT_UDP: usize = 64;
const MIN_CONCURRENT_TCP: usize = 16;
const MIN_TCP_CONNS: usize = 32;
// Descriptors set aside for the listen sockets, the upstream idle pools
// (`MAX_IDLE_CONNS` per upstream) and whatever else the process holds open.
const FD_RESERVE: usize = 320;
// The soft descriptor limit is raised toward the hard one at startup, up to
// this: enough for every ceiling above at the widest fan-out, without handing
// child processes (the hook) a limit in the millions.
const FD_WANT: u64 = 65_536;
const SHUTDOWN_DRAIN: Duration = Duration::from_secs(5);
/// How often the servers behind `dns://` entries are looked up again.
const REDISCOVER_EVERY: Duration = Duration::from_secs(60);
/// Least spacing between lookups set off by queries no upstream answered, so
/// an outage that fails every query does not re-read the system for each one.
const REDISCOVER_GAP: Duration = Duration::from_secs(10);

/// One `[dns]` / `[fall]` entry: `[<interface>@]<target>`.
#[derive(Clone, Debug)]
pub struct UpstreamSpec {
    /// Interface this entry's sockets are bound to; in its place the global
    /// `out` applies.
    pub device: Option<Arc<str>>,
    pub target: Target,
}

#[derive(Clone, Debug)]
pub enum Target {
    /// A normalized `scheme://ip:port` address.
    Addr(String),
    /// A `dns://` entry: whatever servers the host's configuration names.
    Iface(Selector),
}

impl UpstreamSpec {
    pub fn new(device: Option<Arc<str>>, target: Target) -> Self {
        UpstreamSpec { device, target }
    }
}

impl fmt::Display for UpstreamSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(dev) = &self.device {
            write!(f, "{dev}@")?;
        }
        match &self.target {
            Target::Addr(a) => f.write_str(a),
            Target::Iface(s) => s.fmt(f),
        }
    }
}

fn show_specs(specs: &[UpstreamSpec]) -> String {
    let names: Vec<String> = specs.iter().map(|s| s.to_string()).collect();
    format!("[{}]", names.join(", "))
}

fn show_ips(ips: &[IpAddr]) -> String {
    let names: Vec<String> = ips.iter().map(|i| i.to_string()).collect();
    names.join(", ")
}

/// The `dns://` lookups in use, the servers each currently stands for, and
/// the forwarders built from them.
struct Discovery {
    lookups: Vec<Lookup>,
    servers: Vec<Vec<IpAddr>>,
    /// Whether the latest lookup for each entry found anything. When it did
    /// not, `servers` keeps the previous answer, or the defaults at startup.
    found: Vec<bool>,
    out: Option<Arc<str>>,
    live: Vec<(Vec<UpstreamSpec>, Arc<LiveUpstreams>)>,
}

impl Discovery {
    fn new(specs: &[&[UpstreamSpec]], out: Option<Arc<str>>) -> Self {
        let mut disc = Discovery {
            lookups: Vec::new(),
            servers: Vec::new(),
            found: Vec::new(),
            out,
            live: Vec::new(),
        };
        for spec in specs.iter().flat_map(|s| s.iter()) {
            if let Some(l) = disc.lookup_of(spec) {
                if !disc.lookups.contains(&l) {
                    disc.lookups.push(l);
                }
            }
        }
        disc.servers = vec![DEFAULT_SERVERS.to_vec(); disc.lookups.len()];
        disc.found = vec![false; disc.lookups.len()];
        disc
    }

    /// The interface `spec`'s sockets are bound to: its own, else `out`.
    fn device_of<'a>(&'a self, spec: &'a UpstreamSpec) -> Option<&'a Arc<str>> {
        spec.device.as_ref().or(self.out.as_ref())
    }

    fn lookup_of(&self, spec: &UpstreamSpec) -> Option<Lookup> {
        match &spec.target {
            Target::Iface(sel) => Some(Lookup::new(sel.clone(), self.device_of(spec).cloned())),
            Target::Addr(_) => None,
        }
    }

    /// The first lookup, logged in full: what each `dns://` entry stands for
    /// is the first thing to check when forwarding goes wrong.
    async fn start(&mut self) {
        if self.lookups.is_empty() {
            return;
        }
        let found = ifdns::detect(&self.lookups).await;
        for (i, f) in found.into_iter().enumerate() {
            let lookup = &self.lookups[i];
            match f {
                Some(Found { servers, source }) => {
                    log::info(&format!(
                        "{lookup} -> {} (from {source})",
                        log::hl_value(show_ips(&servers))
                    ));
                    self.servers[i] = servers;
                    self.found[i] = true;
                }
                None => log::warn(&format!(
                    "{lookup}: no DNS server found on this system, using {}",
                    show_ips(&self.servers[i])
                )),
            }
        }
    }

    /// Take in a later lookup. An entry that finds nothing keeps what it had:
    /// losing the uplink's servers for a moment (a PPP redial) is no reason to
    /// drop servers that may still answer.
    fn update(&mut self, found: Vec<Option<Found>>) {
        let mut changed = false;
        for (i, f) in found.into_iter().enumerate() {
            let lookup = &self.lookups[i];
            match f {
                Some(Found { servers, source }) => {
                    if servers != self.servers[i] {
                        log::info(&format!(
                            "{lookup} -> {} (from {source}), was {}",
                            log::hl_value(show_ips(&servers)),
                            show_ips(&self.servers[i])
                        ));
                        self.servers[i] = servers;
                        changed = true;
                    }
                    self.found[i] = true;
                }
                None if self.found[i] => {
                    log::warn(&format!(
                        "{lookup}: no DNS server found any more, keeping {}",
                        show_ips(&self.servers[i])
                    ));
                    self.found[i] = false;
                }
                None => {}
            }
        }
        if changed {
            for (specs, live) in &self.live {
                live.replace(self.upstreams(specs, false));
            }
        }
    }

    /// The upstreams `specs` currently stand for, in order and without
    /// repeats. `warn` reports entries that do not parse (once, at startup).
    fn upstreams(&self, specs: &[UpstreamSpec], warn: bool) -> Vec<Upstream> {
        let mut list = Vec::new();
        for spec in specs {
            let device = self.device_of(spec);
            match &spec.target {
                Target::Addr(url) => match Upstream::parse(url) {
                    Ok(u) => merge_upstreams(&mut list, [u.bound_to(device)]),
                    Err(e) if warn => log::warn(&format!("skipping invalid upstream {url}: {e}")),
                    Err(_) => {}
                },
                Target::Iface(_) => {
                    let Some(i) = self
                        .lookup_of(spec)
                        .and_then(|l| self.lookups.iter().position(|x| *x == l))
                    else {
                        continue;
                    };
                    let found = self.servers[i].iter();
                    merge_upstreams(
                        &mut list,
                        found.map(|ip| Upstream::udp53(*ip).bound_to(device)),
                    );
                }
            }
        }
        list
    }

    /// The forwarder for `specs`: a live one, kept current by [`rediscover`],
    /// when any entry is `dns://`.
    fn forwarder(
        &mut self,
        specs: &[UpstreamSpec],
        list: Vec<Upstream>,
        timeout: Duration,
        breaker: bool,
        stale: &Arc<Notify>,
    ) -> Forwarder {
        let list: Vec<Arc<Upstream>> = list.into_iter().map(Arc::new).collect();
        if !specs.iter().any(|s| matches!(s.target, Target::Iface(_))) {
            return if breaker {
                Forwarder::with_breaker(list, timeout)
            } else {
                Forwarder::new(list, timeout)
            };
        }
        let live = Arc::new(LiveUpstreams::new(list, stale.clone()));
        self.live.push((specs.to_vec(), live.clone()));
        Forwarder::live(live, timeout, breaker)
    }
}

/// Look the `dns://` servers up again every [`REDISCOVER_EVERY`], and sooner
/// when a query found every upstream of a live forwarder silent.
async fn rediscover(mut disc: Discovery, stale: Arc<Notify>, mut shutdown: watch::Receiver<bool>) {
    let mut tick = tokio::time::interval_at(
        tokio::time::Instant::now() + REDISCOVER_EVERY,
        REDISCOVER_EVERY,
    );
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last = Instant::now();
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
                continue;
            }
            _ = tick.tick() => {}
            _ = stale.notified() => {
                if last.elapsed() < REDISCOVER_GAP { continue; }
            }
        }
        last = Instant::now();
        let found = ifdns::detect(&disc.lookups).await;
        disc.update(found);
    }
}

/// Every interface upstream sockets get bound to: `out` and each entry's own.
fn bound_devices(out: Option<&Arc<str>>, specs: &[&[UpstreamSpec]]) -> Vec<Arc<str>> {
    let mut devs: Vec<Arc<str>> = out.into_iter().cloned().collect();
    for dev in specs
        .iter()
        .flat_map(|s| s.iter())
        .filter_map(|s| s.device.as_ref())
    {
        if !devs.contains(dev) {
            devs.push(dev.clone());
        }
    }
    devs
}

/// Make sure sockets can be bound to `dev` before serving: without that right
/// every query to an upstream bound there would fail. An interface that does
/// not exist yet (a PPP link still dialing) is only warned about.
async fn check_bind_device(dev: &str) -> Result<(), String> {
    let sock = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("Error: interface {dev}: {e}"))?;
    match sock.bind_device(Some(dev.as_bytes())) {
        Ok(()) => {
            log::info(&format!(
                "upstream sockets can bind to {}",
                log::hl_value(dev)
            ));
            Ok(())
        }
        Err(e) if e.raw_os_error() == Some(libc::ENODEV) => {
            log::warn(&format!(
                "interface {dev} does not exist yet; upstreams bound to it fail until it appears"
            ));
            Ok(())
        }
        Err(e) => Err(format!(
            "Error: interface {dev}: cannot bind sockets to it: {e}"
        )),
    }
}

/// The three concurrency ceilings, after the file-descriptor limit is taken
/// into account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Caps {
    udp: usize,
    tcp: usize,
    tcp_conns: usize,
}

/// Derive the ceilings from `fd_limit` (`None` when it cannot be read, which
/// means "assume plenty").
///
/// A forwarded query holds one socket per upstream its fan-out asks, and once
/// the hedge starts the fallback alongside a slow main, both fan-outs are open
/// at once: `main_sockets + fall_sockets`. A main query the fallback beat
/// keeps its sockets after the query's permit is gone, up to
/// [`MAX_LINGERING_MAIN`] of them, so those are reserved off the top. Every
/// accepted TCP connection is a descriptor of its own. Ceilings above what the
/// process may open turn overload into `EMFILE` — a SERVFAIL for the client —
/// rather than the intended shed, which drops a datagram the client will
/// retry. The connection ceiling is not divided: a connection costs one
/// descriptor whether or not the query on it is being forwarded.
fn caps_for(fd_limit: Option<usize>, main_sockets: usize, fall_sockets: usize) -> Caps {
    let Some(limit) = fd_limit else {
        return Caps {
            udp: MAX_CONCURRENT_UDP,
            tcp: MAX_CONCURRENT_TCP,
            tcp_conns: MAX_TCP_CONNS,
        };
    };
    let main_sockets = main_sockets.max(1);
    let reserve = FD_RESERVE + MAX_LINGERING_MAIN * main_sockets;
    let budget = limit.saturating_sub(reserve);
    let per_query = main_sockets + fall_sockets.max(1);
    Caps {
        udp: (budget / 2 / per_query).clamp(MIN_CONCURRENT_UDP, MAX_CONCURRENT_UDP),
        tcp_conns: (budget * 3 / 10).clamp(MIN_TCP_CONNS, MAX_TCP_CONNS),
        tcp: (budget / 5 / per_query).clamp(MIN_CONCURRENT_TCP, MAX_CONCURRENT_TCP),
    }
}

/// The deadlines the two upstream stages run on, all derived from `qtime`.
struct Timings {
    /// How long the main DNS gets alone before the fallback joins in.
    hedge_after: Duration,
    /// The main's whole deadline. It is the full window the client waits, not
    /// `qtime`: once the fallback has joined in, a main answer that still
    /// arrives first is the answer this client asked for — and only a main
    /// that misses this deadline is the failure the breaker counts.
    main: Duration,
    /// The fallback's deadline, and so the longest the client waits.
    fall: Duration,
}
impl Timings {
    fn from_qtime(qtime: Duration) -> Self {
        let fall = qtime * 10;
        Timings {
            hedge_after: qtime,
            main: qtime + fall,
            fall,
        }
    }
}
/// Which group of default paths to probe. Each group answers only for itself:
/// naming a lease file says nothing about hosts files, and `[hosts]` entries
/// overlay the hosts files instead of standing in for them — which is what the
/// ReadMe promises.
fn auto_detect_for(cfg: &Config) -> AutoDetect {
    AutoDetect {
        lease: cfg.lease_file.is_empty(),
        hosts: cfg.hosts_file.is_empty(),
    }
}

/// Raise the soft descriptor limit toward the hard one, to at most
/// [`FD_WANT`]. The hard limit is the administrator's ceiling; the soft one
/// is commonly left at 1024, too few for a forwarder whose every query holds
/// several upstream sockets. Returns the limit before and after when it
/// changed. The original is kept for child processes (see
/// [`restore_child_fd_limit`]).
fn raise_fd_limit() -> Option<(u64, u64)> {
    // SAFETY: `getrlimit`/`setrlimit` only read and write the `rlimit` we hand
    // them.
    unsafe {
        let mut rl: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) != 0 {
            return None;
        }
        // `rlim_t` is 32 bits wide on some of the targets released for.
        #[allow(clippy::unnecessary_cast)]
        let wide = |v: libc::rlim_t| {
            if v == libc::RLIM_INFINITY {
                u64::MAX
            } else {
                v as u64
            }
        };
        let before = wide(rl.rlim_cur);
        let want = raised_soft_limit(before, wide(rl.rlim_max))?;
        let _ = ORIGINAL_FD_LIMIT.set(rl);
        rl.rlim_cur = want as libc::rlim_t;
        if libc::setrlimit(libc::RLIMIT_NOFILE, &rl) != 0 {
            return None;
        }
        Some((before, want))
    }
}

/// The soft limit to raise `cur` to under hard limit `max` (`u64::MAX` for
/// unlimited), or `None` to leave it alone.
fn raised_soft_limit(cur: u64, max: u64) -> Option<u64> {
    let want = max.min(FD_WANT);
    (want > cur).then_some(want)
}

/// The descriptor limit the process started with, when [`raise_fd_limit`]
/// changed it.
static ORIGINAL_FD_LIMIT: std::sync::OnceLock<libc::rlimit> = std::sync::OnceLock::new();

/// Put the starting descriptor limit back, for a child about to exec. Some
/// programs walk every descriptor up to the soft limit closing each; the
/// raised limit is this process's need, not theirs.
///
/// Only calls `setrlimit`, which is async-signal-safe, so this may run between
/// fork and exec.
pub fn restore_child_fd_limit() {
    if let Some(rl) = ORIGINAL_FD_LIMIT.get() {
        // SAFETY: `setrlimit` reads the `rlimit` it is given and nothing else.
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, rl) };
    }
}

/// The process's soft descriptor limit, or `None` if it is unlimited or
/// unreadable.
fn fd_limit() -> Option<usize> {
    // SAFETY: `getrlimit` only writes into the `rlimit` we hand it.
    let rl = unsafe {
        let mut rl: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) != 0 {
            return None;
        }
        rl
    };
    if rl.rlim_cur == libc::RLIM_INFINITY {
        return None;
    }
    usize::try_from(rl.rlim_cur).ok()
}

/// UDP receive-loop shards per listen address. The fast path (cache hit /
/// static rewrite) runs inline in the receive loop, so one loop caps
/// throughput at one core; SO_REUSEPORT shards let the kernel spread flows
/// across several loops. Capped at 4 — beyond that, upstream IO, not intake,
/// is the limit.
fn udp_shards() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(4)
}

/// Bind a nonblocking UDP socket, optionally with SO_REUSEPORT (needed to
/// bind several shards to one address).
fn bind_udp_shard(addr: std::net::SocketAddr, reuseport: bool) -> std::io::Result<UdpSocket> {
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    if reuseport {
        sock.set_reuse_port(true)?;
    }
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    UdpSocket::from_std(sock.into())
}

/// Build everything and serve until SIGINT/SIGTERM. Blocks on a fresh Tokio
/// runtime. Returns an error string on fatal setup failure.
pub fn run(
    cfg: &Config,
    listen: Vec<String>,
    matcher: ForceFallMatcher,
    dns_upstreams: Vec<UpstreamSpec>,
    fall_upstreams: Vec<UpstreamSpec>,
) -> Result<(), String> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("failed to build runtime: {e}"))?;
    #[cfg(feature = "profiling")]
    let guard = pprof::ProfilerGuardBuilder::default()
        .frequency(1997)
        .blocklist(&["libc", "libgcc", "pthread", "vdso"])
        .build()
        .ok();

    let result = rt.block_on(serve(cfg, listen, matcher, dns_upstreams, fall_upstreams));

    #[cfg(feature = "profiling")]
    if let Some(g) = guard {
        if let Ok(report) = g.report().build() {
            if let Ok(f) = std::fs::File::create("flamegraph.svg") {
                let _ = report.flamegraph(f);
                eprintln!("wrote flamegraph.svg");
            }
            // Folded stacks (leaf-first per frame) for exact self-time analysis.
            let mut folded = String::new();
            for (frames, count) in report.data.iter() {
                let mut names: Vec<String> = Vec::new();
                for f in frames.frames.iter().rev() {
                    for sym in f.iter().rev() {
                        names.push(sym.name());
                    }
                }
                folded.push_str(&names.join(";"));
                folded.push_str(&format!(" {count}\n"));
            }
            let _ = std::fs::write("folded.txt", folded);
            eprintln!("wrote folded.txt");
        }
    }

    result
}

async fn serve(
    cfg: &Config,
    listen: Vec<String>,
    matcher: ForceFallMatcher,
    dns_upstreams: Vec<UpstreamSpec>,
    fall_upstreams: Vec<UpstreamSpec>,
) -> Result<(), String> {
    let avail = get_available_memory();
    log::info(&format!("mini-ppdns {}", crate::VERSION));
    log::info(&format!(
        "available memory {} {}",
        log::hl_value(avail / 1024 / 1024),
        log::hl_unit("MB")
    ));
    if let Some((before, after)) = raise_fd_limit() {
        log::info(&format!(
            "fd limit raised from {before} to {}",
            log::hl_value(after)
        ));
    }

    let out: Option<Arc<str>> = (!cfg.out.is_empty()).then(|| Arc::from(cfg.out.as_str()));
    for dev in bound_devices(out.as_ref(), &[&dns_upstreams, &fall_upstreams]) {
        check_bind_device(&dev).await?;
    }
    let mut disc = Discovery::new(&[&dns_upstreams, &fall_upstreams], out);
    disc.start().await;
    let main = disc.upstreams(&dns_upstreams, true);
    let fall = disc.upstreams(&fall_upstreams, true);
    if main.is_empty() {
        return Err("Error: No valid DNS upstream (-dns)".into());
    }
    if fall.is_empty() {
        return Err("Error: No valid fallback DNS (-fall)".into());
    }
    // Upstreams past MAX_UPSTREAMS are never queried (the per-query candidate
    // set is capped). Warn rather than silently ignore them.
    let cap = crate::upstream::MAX_UPSTREAMS;
    if main.len() > cap {
        log::warn(&format!(
            "{} dns upstreams configured; only the first {cap} are used per query",
            main.len()
        ));
    }
    if fall.len() > cap {
        log::warn(&format!(
            "{} fallback upstreams configured; only the first {cap} are used per query",
            fall.len()
        ));
    }

    let timings = Timings::from_qtime(Duration::from_millis(cfg.qtime as u64));
    let stale = Arc::new(Notify::new());
    // Only the main forwarder gets the fail-fast breaker (see `Breaker`).
    // An NXDOMAIN waits up to `qtime` for a peer's NOERROR: the threshold
    // already chosen for how long a slow upstream is waited on.
    let main_fwd = disc
        .forwarder(&dns_upstreams, main, timings.main, true, &stale)
        .settle_after(timings.hedge_after);
    let fall_fwd = disc
        .forwarder(&fall_upstreams, fall, timings.fall, false, &stale)
        .settle_after(timings.hedge_after);

    let cache_cap = calculate_cache_size(avail);
    let cache = Arc::new(Cache::new(cache_cap));
    // Answers from the fallback upstream live in their own cache (see the
    // `Handler` fields): partitioning by source upstream is what lets
    // force_fall clients and a hook-down outage share entries safely.
    let fall_cache_cap = calculate_fallback_cache_size(cache_cap);
    let fall_cache = Arc::new(Cache::new(fall_cache_cap));

    log::info(&format!(
        "upstreams dns={} fall={}",
        show_specs(&dns_upstreams),
        show_specs(&fall_upstreams)
    ));
    log::info(&format!(
        "cache capacity {} entries / {} {} (fallback {} entries / {} {})",
        log::hl_value(cache_cap),
        log::hl_value(cache.byte_budget() / 1024 / 1024),
        log::hl_unit("MB"),
        log::hl_value(fall_cache_cap),
        log::hl_value(fall_cache.byte_budget() / 1024 / 1024),
        log::hl_unit("MB")
    ));

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    if !disc.live.is_empty() {
        tokio::spawn(rediscover(disc, stale, shutdown_rx.clone()));
    }

    // Local resolver (lease/hosts files + [hosts] statics) — None if nothing
    // to resolve.
    let resolver = PtrResolver::with_static_ptr(
        cfg.lease_file.clone(),
        cfg.hosts_file.clone(),
        auto_detect_for(cfg),
        &cfg.hosts,
        &cfg.hosts_ptr,
    )
    .map(Arc::new);
    if let Some(r) = &resolver {
        log::info(&format!(
            "local resolver enabled lease_files {} hosts_files {} static_hosts {} boguspriv {}",
            log::hl_value(r.lease_files_desc()),
            log::hl_value(r.hosts_files_desc()),
            log::hl_value(cfg.hosts.len()),
            log::hl_value(cfg.boguspriv),
        ));
        // Watch lease/hosts files from a background task. Lookups themselves
        // never reload: they run inline in the UDP receive loops, where a
        // synchronous re-read of a large hosts file would stall intake.
        let watcher = r.clone();
        let mut rx = shutdown_rx.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(
                crate::local_resolver::RELOAD_INTERVAL_SECS,
            ));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = rx.changed() => {
                        if *rx.borrow() { break; }
                    }
                    _ = tick.tick() => {
                        let w = watcher.clone();
                        // Blocking pool: stat + potential full re-read.
                        let _ = tokio::task::spawn_blocking(move || w.check_reload()).await;
                    }
                }
            }
        });
    }

    // pplog encrypted telemetry reporter (built before the hook so the hook can
    // emit level-5 transition events).
    let pplog = if cfg.pplog_level > 0 && !cfg.pplog_server.is_empty() && !cfg.pplog_uuid.is_empty()
    {
        let rep = crate::pplog::Reporter::new(crate::pplog::Config {
            uuid: cfg.pplog_uuid.clone(),
            server: cfg.pplog_server.clone(),
            level: cfg.pplog_level,
            heartbeat: cfg.pplog_heart_beat,
        })
        .await;
        match &rep {
            Some(_) => log::info(&format!(
                "pplog enabled server {} level {}",
                log::hl_addr(&cfg.pplog_server),
                log::hl_value(cfg.pplog_level)
            )),
            None => log::error("pplog init failed (reporting disabled)"),
        }
        rep
    } else {
        None
    };

    // Hook health monitor.
    let hook_failed = match &cfg.hook {
        Some(h) if !h.exec.is_empty() => {
            let failed = Arc::new(AtomicBool::new(false));
            let mon = HookMonitor {
                cfg: h.clone(),
                failed: failed.clone(),
                cache: cache.clone(),
                pplog: pplog.clone(),
            };
            tokio::spawn(mon.run(shutdown_rx.clone()));
            log::info(&format!(
                "hook enabled exec={:?} sleep={} retry={} count={}",
                h.exec, h.sleep_time, h.retry_time, h.count
            ));
            Some(failed)
        }
        _ => None,
    };

    let handler = Arc::new(Handler {
        main: Arc::new(main_fwd),
        hedge_after: timings.hedge_after,
        fallback: fall_fwd,
        cache: cache.clone(),
        fall_cache,
        force_fall: matcher,
        aaaa_mode: AaaaMode::parse(&cfg.aaaa),
        lite: cfg.lite == "yes",
        boguspriv: cfg.boguspriv,
        block_svcb: cfg.block_svcb,
        trust_rcodes: cfg
            .trust_rcode
            .iter()
            .filter_map(|&r| u8::try_from(r).ok())
            .collect(),
        resolver,
        hook_failed,
        pplog,
    });

    let caps = caps_for(
        fd_limit(),
        handler.main.sockets_per_query(),
        handler.fallback.sockets_per_query(),
    );
    log::info(&format!(
        "concurrency udp {} tcp {} tcp-conns {} (fd limit {})",
        log::hl_value(caps.udp),
        log::hl_value(caps.tcp),
        log::hl_value(caps.tcp_conns),
        log::hl_value(match fd_limit() {
            Some(n) => n.to_string(),
            None => "unlimited".to_string(),
        })
    ));
    let udp_sem = Arc::new(Semaphore::new(caps.udp));
    let tcp_sem = Arc::new(Semaphore::new(caps.tcp));
    let tcp_conn_sem = Arc::new(Semaphore::new(caps.tcp_conns));

    // An address the user asked for by name must work; an auto-detected one
    // may have gone away since detection (an interface came down), so it is
    // only logged and skipped.
    let listen_is_configured = !cfg.listen.is_empty();
    let mut servers = Vec::new();
    for addr in &listen {
        // TCP first, and without SO_REUSEPORT: this bind is what makes the
        // whole address exclusive. The UDP shards below *do* set SO_REUSEPORT
        // and would otherwise happily share the port with a second instance,
        // leaving the kernel to split clients between two configurations.
        let tcp = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                let msg = format!("listen tcp://{addr} err: {e}");
                if listen_is_configured {
                    return Err(msg);
                }
                log::error(&msg);
                continue;
            }
        };

        // Resolve once; SO_REUSEPORT-sharded receive loops (see `udp_shards`).
        // If the sharded bind fails (e.g. SO_REUSEPORT unsupported), fall back
        // to a single plain socket, preserving old behavior.
        let parsed: Option<std::net::SocketAddr> = addr.parse().ok();
        let shards = if parsed.is_some() { udp_shards() } else { 1 };
        let mut bound = 0usize;
        if let Some(sa) = parsed {
            for _ in 0..shards {
                match bind_udp_shard(sa, shards > 1) {
                    Ok(sock) => {
                        servers.push(tokio::spawn(serve_udp(
                            sock,
                            handler.clone(),
                            udp_sem.clone(),
                            shutdown_rx.clone(),
                        )));
                        bound += 1;
                    }
                    Err(_) if bound == 0 => break, // fall through to plain bind
                    Err(e) => {
                        // Partial shard failure: keep what we have.
                        log::warn(&format!("udp shard bind {addr} err: {e}"));
                        break;
                    }
                }
            }
        }
        if bound == 0 {
            match UdpSocket::bind(addr).await {
                Ok(sock) => {
                    servers.push(tokio::spawn(serve_udp(
                        sock,
                        handler.clone(),
                        udp_sem.clone(),
                        shutdown_rx.clone(),
                    )));
                }
                Err(e) => {
                    let msg = format!("listen udp://{addr} err: {e}");
                    if listen_is_configured {
                        return Err(msg);
                    }
                    log::error(&msg);
                }
            }
        }
        servers.push(tokio::spawn(serve_tcp(
            tcp,
            handler.clone(),
            tcp_sem.clone(),
            tcp_conn_sem.clone(),
            shutdown_rx.clone(),
        )));
        log::info(&format!("listen: {}", log::hl_addr(addr)));
    }
    if servers.is_empty() {
        return Err("failed to listen on any address".into());
    }

    // Cache janitor.
    let jan = tokio::spawn(janitor(handler.caches(), shutdown_rx.clone()));
    // Everything is bound and serving; a `-d` parent is waiting to hear it.
    crate::ready::serving();

    wait_for_signal().await;
    log::info(&format!(
        "signal received, shutting down (drain up to {}s)",
        SHUTDOWN_DRAIN.as_secs()
    ));
    let _ = shutdown_tx.send(true);

    // Drain in-flight handlers: the accept/receive loops have stopped, so
    // acquiring every permit of each pool means no handler is still running.
    // Both pools drain concurrently in the background; the sequential awaits
    // just observe them, all bounded by the one outer timeout.
    let drain = async {
        let _ = udp_sem.acquire_many(caps.udp as u32).await;
        let _ = tcp_sem.acquire_many(caps.tcp as u32).await;
    };
    let _ = tokio::time::timeout(SHUTDOWN_DRAIN, drain).await;

    jan.abort();
    for s in servers {
        s.abort();
    }
    log::info("shutdown complete");
    Ok(())
}

fn sweep_all(caches: &[Arc<Cache>]) {
    for c in caches {
        c.sweep();
    }
}

/// Drop expired entries from every cache the handler fills. Expired entries
/// are never served, so this only returns their memory — a cache left out of
/// the sweep holds dead entries until its own capacity evicts them.
async fn janitor(caches: [Arc<Cache>; 2], mut shutdown: watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(Duration::from_secs(10));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
            _ = tick.tick() => sweep_all(&caches),
        }
    }
}

async fn wait_for_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    match (
        signal(SignalKind::interrupt()),
        signal(SignalKind::terminate()),
    ) {
        (Ok(mut sigint), Ok(mut sigterm)) => {
            tokio::select! {
                _ = sigint.recv() => {}
                _ = sigterm.recv() => {}
            }
        }
        _ => {
            // Fallback: Ctrl-C only.
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_stay_at_the_ceilings_when_descriptors_are_plentiful() {
        let plenty = caps_for(Some(1_048_576), 1, 1);
        assert_eq!(
            plenty,
            Caps {
                udp: MAX_CONCURRENT_UDP,
                tcp: MAX_CONCURRENT_TCP,
                tcp_conns: MAX_TCP_CONNS,
            }
        );
        // An unreadable or unlimited rlimit means "assume plenty", not "assume
        // nothing" — the floors would otherwise cripple a healthy machine.
        assert_eq!(caps_for(None, 3, 3), plenty);
    }

    /// The most descriptors a forwarder running at its ceilings holds: every
    /// in-flight query with both fan-outs open (the hedge runs the fallback
    /// beside a slow main), every lingering main query the fallback beat,
    /// every accepted connection, and the fixed reserve.
    fn peak_descriptors(c: Caps, main: usize, fall: usize) -> usize {
        (c.udp + c.tcp) * (main + fall) + MAX_LINGERING_MAIN * main + c.tcp_conns + FD_RESERVE
    }

    #[test]
    fn caps_fit_inside_a_small_descriptor_limit() {
        // A common default soft limit, with one main and one fallback.
        let limit = 1024;
        let c = caps_for(Some(limit), 1, 1);
        assert!(peak_descriptors(c, 1, 1) <= limit, "{c:?} overruns {limit}");
        assert!(c.udp < MAX_CONCURRENT_UDP, "must actually scale down");
        assert!(c.udp >= MIN_CONCURRENT_UDP);
    }

    #[test]
    fn caps_leave_room_for_both_fan_outs_of_a_hedged_query() {
        for limit in [4096usize, 16_384, 65_536] {
            let single = caps_for(Some(limit), 1, 1);
            for main in 1..=3 {
                for fall in 1..=3 {
                    let c = caps_for(Some(limit), main, fall);
                    assert!(
                        peak_descriptors(c, main, fall) <= limit,
                        "{c:?} with fan-outs {main}+{fall} overruns {limit}"
                    );
                    assert!(
                        c.udp <= single.udp
                            && c.tcp <= single.tcp
                            && c.tcp_conns <= single.tcp_conns,
                        "fanning out cannot raise a ceiling"
                    );
                }
            }
        }
    }

    #[test]
    fn the_soft_descriptor_limit_is_raised_within_the_hard_one() {
        let inf = u64::MAX;
        assert_eq!(raised_soft_limit(1024, 4096), Some(4096));
        assert_eq!(raised_soft_limit(1024, 1 << 20), Some(FD_WANT));
        assert_eq!(raised_soft_limit(1024, inf), Some(FD_WANT));
        // Never lowered, and left alone when there is no room to raise it.
        assert_eq!(raised_soft_limit(FD_WANT * 2, 1 << 20), None);
        assert_eq!(raised_soft_limit(4096, 4096), None);
        assert_eq!(raised_soft_limit(inf, inf), None);
    }

    #[test]
    fn the_main_stage_may_answer_for_as_long_as_the_client_waits() {
        for ms in [50u64, 250, 1_000] {
            let t = Timings::from_qtime(Duration::from_millis(ms));
            assert_eq!(t.hedge_after, Duration::from_millis(ms), "{ms}ms");
            // The fallback joins in at the threshold; the main keeps going to
            // the end of the window, so a late main answer can still win —
            // and a main cut off at the threshold would look like a failure
            // to the breaker when it is only slow.
            assert!(
                t.hedge_after < t.main,
                "{ms}ms: the main must outlast the threshold"
            );
            assert!(
                t.main >= t.hedge_after + t.fall,
                "{ms}ms: the main must last as long as the client is willing to wait"
            );
        }
    }

    #[test]
    fn each_file_group_probes_its_own_default() {
        let with = |lease: &[&str], hosts: &[&str]| {
            auto_detect_for(&Config {
                lease_file: lease.iter().map(|s| (*s).to_string()).collect(),
                hosts_file: hosts.iter().map(|s| (*s).to_string()).collect(),
                hosts: [("static.lan.".to_string(), Vec::new())]
                    .into_iter()
                    .collect(),
                ..Config::default()
            })
        };
        let a = with(&[], &[]);
        assert!(a.lease && a.hosts, "nothing named: both defaults apply");
        let b = with(&["/tmp/x.leases"], &[]);
        assert!(!b.lease && b.hosts, "a named lease file leaves hosts alone");
        let c = with(&[], &["/tmp/x.hosts"]);
        assert!(
            c.lease && !c.hosts,
            "a named hosts file leaves leases alone"
        );
        let d = with(&["/tmp/x.leases"], &["/tmp/x.hosts"]);
        assert!(!d.lease && !d.hosts);
    }

    #[test]
    fn the_sweep_reaches_every_cache_it_is_given() {
        use crate::cache::{CacheKey, CachedMsg};
        let caches = [Arc::new(Cache::new(64)), Arc::new(Cache::new(64))];
        for (i, c) in caches.iter().enumerate() {
            c.store(
                CacheKey::new(vec![i as u8, 0], 1, 1),
                Arc::new(CachedMsg {
                    stored: std::time::Instant::now(),
                    rcode: domain::base::iana::Rcode::NOERROR,
                    answers: vec![],
                    authority: vec![],
                    additional: vec![],
                }),
                1,
            );
        }
        // A stored TTL is at least a second, so wait one out rather than
        // reaching into the entry.
        std::thread::sleep(Duration::from_millis(1100));
        sweep_all(&caches);
        for (i, c) in caches.iter().enumerate() {
            assert_eq!(c.len(), 0, "cache {i} kept an expired entry");
        }
    }

    #[test]
    fn caps_never_fall_below_the_floors() {
        for limit in [0usize, 1, 64, FD_RESERVE, FD_RESERVE + 1] {
            let c = caps_for(Some(limit), 3, 3);
            assert_eq!(c.udp, MIN_CONCURRENT_UDP, "limit={limit}");
            assert_eq!(c.tcp, MIN_CONCURRENT_TCP, "limit={limit}");
            assert_eq!(c.tcp_conns, MIN_TCP_CONNS, "limit={limit}");
        }
    }

    #[test]
    fn caps_grow_monotonically_with_the_limit() {
        let mut prev = caps_for(Some(0), 2, 2);
        for limit in (0..20_000).step_by(97) {
            let c = caps_for(Some(limit), 2, 2);
            assert!(c.udp >= prev.udp && c.tcp >= prev.tcp && c.tcp_conns >= prev.tcp_conns);
            prev = c;
        }
    }

    fn ips(list: &[&str]) -> Vec<IpAddr> {
        list.iter().map(|s| s.parse().unwrap()).collect()
    }

    fn labels(list: &[Upstream]) -> Vec<String> {
        list.iter().map(|u| u.label.to_string()).collect()
    }

    fn found(servers: &[&str]) -> Option<Found> {
        Some(Found {
            servers: ips(servers),
            source: "test".into(),
        })
    }

    fn addr(url: &str) -> UpstreamSpec {
        UpstreamSpec::new(None, Target::Addr(url.into()))
    }

    fn auto() -> UpstreamSpec {
        UpstreamSpec::new(None, Target::Iface(Selector::Auto))
    }

    fn iface(name: &str) -> UpstreamSpec {
        UpstreamSpec::new(None, Target::Iface(Selector::Iface(name.into())))
    }

    fn on(dev: &str, spec: UpstreamSpec) -> UpstreamSpec {
        UpstreamSpec::new(Some(Arc::from(dev)), spec.target)
    }

    fn devices(list: &[Upstream]) -> Vec<Option<&str>> {
        list.iter().map(Upstream::device).collect()
    }

    #[test]
    fn dns_entries_expand_in_place_without_repeats() {
        let main = vec![addr("udp://10.0.0.8:53"), auto(), iface("eth0")];
        let fall = vec![auto(), addr("udp://223.5.5.5:53")];
        let mut disc = Discovery::new(&[&main, &fall], None);
        assert_eq!(
            disc.lookups,
            [
                Lookup::new(Selector::Auto, None),
                Lookup::new(Selector::Iface("eth0".into()), None)
            ],
            "each lookup is done once however often it appears"
        );
        assert_eq!(
            labels(&disc.upstreams(&fall, false)),
            ["udp://223.5.5.5:53", "udp://119.29.29.29:53"],
            "before anything is found the defaults stand in, and are not repeated"
        );
        disc.servers = vec![
            ips(&["192.0.2.1", "192.0.2.2"]),
            ips(&["192.0.2.2", "192.0.2.3"]),
        ];
        assert_eq!(
            labels(&disc.upstreams(&main, false)),
            [
                "udp://10.0.0.8:53",
                "udp://192.0.2.1:53",
                "udp://192.0.2.2:53",
                "udp://192.0.2.3:53"
            ]
        );
        assert_eq!(
            show_specs(&main),
            "[udp://10.0.0.8:53, dns://%, dns://eth0]"
        );
    }

    #[test]
    fn a_lookup_that_finds_nothing_keeps_the_servers_in_force() {
        let specs = vec![auto()];
        let mut disc = Discovery::new(&[&specs], None);
        let stale = Arc::new(Notify::new());
        let initial = disc.upstreams(&specs, false);
        let fwd = disc.forwarder(&specs, initial, Duration::from_secs(1), false, &stale);
        let (_, live) = disc.live[0].clone();
        let now = |live: &LiveUpstreams| -> Vec<String> {
            live.current().iter().map(|u| u.label.to_string()).collect()
        };
        assert_eq!(fwd.sockets_per_query(), 2);

        disc.update(vec![found(&["192.0.2.1"])]);
        assert_eq!(now(&live), ["udp://192.0.2.1:53"]);
        assert!(disc.found[0]);

        disc.update(vec![None]);
        assert_eq!(
            now(&live),
            ["udp://192.0.2.1:53"],
            "a lost answer (a PPP redial in progress) does not drop the servers"
        );
        assert!(!disc.found[0]);

        disc.update(vec![found(&["192.0.2.9", "192.0.2.1"])]);
        assert_eq!(now(&live), ["udp://192.0.2.9:53", "udp://192.0.2.1:53"]);
    }

    #[test]
    fn plain_addresses_build_a_fixed_forwarder() {
        let specs = vec![on("br-lan", addr("udp://10.0.0.8:53"))];
        let mut disc = Discovery::new(&[&specs], None);
        assert!(disc.lookups.is_empty());
        let list = disc.upstreams(&specs, false);
        let stale = Arc::new(Notify::new());
        disc.forwarder(&specs, list, Duration::from_secs(1), true, &stale);
        assert!(disc.live.is_empty(), "nothing to keep current");
    }

    #[test]
    fn out_binds_every_upstream_it_can() {
        let specs = vec![
            addr("udp://127.0.0.1:5353"),
            addr("tcp://10.0.0.8:53"),
            addr("not-an-address"),
            auto(),
        ];
        let disc = Discovery::new(&[&specs], Some(Arc::from("pppoe-wan")));
        let list = disc.upstreams(&specs, false);
        assert_eq!(list.len(), 4, "the unparsable entry is skipped");
        assert_eq!(
            devices(&list),
            [
                None,
                Some("pppoe-wan"),
                Some("pppoe-wan"),
                Some("pppoe-wan")
            ],
            "loopback stays unbound"
        );
    }

    #[test]
    fn an_entrys_own_interface_wins_over_out() {
        let main = vec![on("br-lan", addr("udp://10.10.10.8:53"))];
        let fall = vec![auto(), addr("udp://223.5.5.5:53")];
        let disc = Discovery::new(&[&main, &fall], Some(Arc::from("pppoe-wan")));
        assert_eq!(
            devices(&disc.upstreams(&main, false)),
            [Some("br-lan")],
            "the LAN main DNS stays on the LAN while out sends the rest to the WAN"
        );
        // The defaults already include 223.5.5.5, so it is listed once.
        assert_eq!(
            devices(&disc.upstreams(&fall, false)),
            [Some("pppoe-wan"), Some("pppoe-wan")]
        );
        let none = Discovery::new(&[&main], None);
        assert_eq!(devices(&none.upstreams(&main, false)), [Some("br-lan")]);
    }

    #[test]
    fn a_bound_automatic_entry_means_that_interfaces_dns() {
        let main = vec![on("eth1", auto())];
        let fall = vec![auto(), iface("wan"), on("eth1", iface("wan"))];
        let mut disc = Discovery::new(&[&main, &fall], Some(Arc::from("pppoe-wan")));
        assert_eq!(
            disc.lookups,
            [
                Lookup::new(Selector::Auto, Some(Arc::from("eth1"))),
                Lookup::new(Selector::Auto, Some(Arc::from("pppoe-wan"))),
                Lookup::new(Selector::Iface("wan".into()), None),
            ],
            "dns://% is looked up per egress; a named interface once"
        );
        disc.servers = vec![
            ips(&["192.0.2.1"]),
            ips(&["192.0.2.2"]),
            ips(&["192.0.2.3"]),
        ];
        let main_list = disc.upstreams(&main, false);
        assert_eq!(labels(&main_list), ["udp://192.0.2.1:53"]);
        assert_eq!(devices(&main_list), [Some("eth1")]);
        let fall_list = disc.upstreams(&fall, false);
        assert_eq!(
            labels(&fall_list),
            [
                "udp://192.0.2.2:53",
                "udp://192.0.2.3:53",
                "udp://192.0.2.3:53"
            ]
        );
        assert_eq!(
            devices(&fall_list),
            [Some("pppoe-wan"), Some("pppoe-wan"), Some("eth1")],
            "the same server bound to two interfaces is two upstreams"
        );
    }

    #[test]
    fn every_bound_interface_is_checked_once() {
        let main = vec![
            on("br-lan", addr("udp://10.10.10.8:53")),
            on("eth1", auto()),
        ];
        let fall = vec![on("br-lan", auto()), addr("udp://223.5.5.5:53")];
        let out: Arc<str> = Arc::from("pppoe-wan");
        let devs = bound_devices(Some(&out), &[&main, &fall]);
        let names: Vec<&str> = devs.iter().map(|d| &**d).collect();
        assert_eq!(names, ["pppoe-wan", "br-lan", "eth1"]);
        assert!(bound_devices(None, &[&fall[1..]]).is_empty());
    }
}
