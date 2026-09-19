// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

//! Runtime assembly and lifecycle: build the forwarders/cache/handler, bind
//! every listen address, run until a signal, then drain.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{watch, Semaphore};

use crate::cache::Cache;
use crate::config::Config;
use crate::forcefall::ForceFallMatcher;
use crate::handler::{AaaaMode, Handler};
use crate::hook::HookMonitor;
use crate::local_resolver::{AutoDetect, PtrResolver};
use crate::log;
use crate::server::{serve_tcp, serve_udp};
use crate::sysinfo::{calculate_cache_size, calculate_fallback_cache_size, get_available_memory};
use crate::upstream::{Forwarder, Upstream};

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
const SHUTDOWN_DRAIN: Duration = Duration::from_secs(5);

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
/// Every in-flight forwarded query holds `sockets_per_query` upstream sockets —
/// the fan-out queries several upstreams at once — and every accepted TCP
/// connection is a descriptor of its own. Ceilings above what the process may
/// open turn overload into `EMFILE` — a SERVFAIL for the client — rather than
/// the intended shed, which drops a datagram the client will retry. The
/// connection ceiling is not divided: a connection costs one descriptor
/// whether or not the query on it is being forwarded.
fn caps_for(fd_limit: Option<usize>, sockets_per_query: usize) -> Caps {
    let Some(limit) = fd_limit else {
        return Caps {
            udp: MAX_CONCURRENT_UDP,
            tcp: MAX_CONCURRENT_TCP,
            tcp_conns: MAX_TCP_CONNS,
        };
    };
    let budget = limit.saturating_sub(FD_RESERVE);
    let per_query = sockets_per_query.max(1);
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
    dns_upstreams: Vec<String>,
    fall_upstreams: Vec<String>,
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

fn build_upstreams(list: &[String]) -> Vec<Arc<Upstream>> {
    let mut out = Vec::new();
    for url in list {
        match Upstream::parse(url) {
            Ok(u) => out.push(Arc::new(u)),
            Err(e) => log::warn(&format!("skipping invalid upstream {url}: {e}")),
        }
    }
    out
}

async fn serve(
    cfg: &Config,
    listen: Vec<String>,
    matcher: ForceFallMatcher,
    dns_upstreams: Vec<String>,
    fall_upstreams: Vec<String>,
) -> Result<(), String> {
    let main = build_upstreams(&dns_upstreams);
    let fall = build_upstreams(&fall_upstreams);
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
    // Only the main forwarder gets the fail-fast breaker (see `Breaker`).
    let main_fwd = Forwarder::with_breaker(main, timings.main);
    let fall_fwd = Forwarder::new(fall, timings.fall);

    let avail = get_available_memory();
    let cache_cap = calculate_cache_size(avail);
    let cache = Arc::new(Cache::new(cache_cap));
    // Answers from the fallback upstream live in their own cache (see the
    // `Handler` fields): partitioning by source upstream is what lets
    // force_fall clients and a hook-down outage share entries safely.
    let fall_cache_cap = calculate_fallback_cache_size(cache_cap);
    let fall_cache = Arc::new(Cache::new(fall_cache_cap));

    // Startup banner (timestamped, highlighted).
    log::info(&format!("mini-ppdns {}", crate::VERSION));
    log::info(&format!(
        "available memory {} {}",
        log::hl_value(avail / 1024 / 1024),
        log::hl_unit("MB")
    ));
    log::info(&format!(
        "upstreams dns={dns_upstreams:?} fall={fall_upstreams:?}"
    ));
    log::info(&format!(
        "cache capacity {} entries (fallback {} entries)",
        log::hl_value(cache_cap),
        log::hl_value(fall_cache_cap)
    ));

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Local resolver (lease/hosts files + [hosts] statics) — None if nothing
    // to resolve.
    let resolver = PtrResolver::new(
        cfg.lease_file.clone(),
        cfg.hosts_file.clone(),
        auto_detect_for(cfg),
        &cfg.hosts,
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

    // Main and fallback are queried in sequence, so a query's peak descriptor
    // use is the wider of the two fan-outs, not their sum.
    let caps = caps_for(
        fd_limit(),
        handler
            .main
            .sockets_per_query()
            .max(handler.fallback.sockets_per_query()),
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
        let plenty = caps_for(Some(1_048_576), 1);
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
        assert_eq!(caps_for(None, 3), plenty);
    }

    #[test]
    fn caps_fit_inside_a_small_descriptor_limit() {
        // The default on the routers this targets.
        let limit = 1024;
        let c = caps_for(Some(limit), 1);
        // Each in-flight query holds an upstream socket and each accepted
        // connection is a descriptor, so the three together plus the reserve
        // must stay inside the limit.
        assert!(
            c.udp + c.tcp + c.tcp_conns + FD_RESERVE <= limit,
            "{c:?} + reserve overruns {limit}"
        );
        assert!(c.udp < MAX_CONCURRENT_UDP, "must actually scale down");
        assert!(c.udp >= MIN_CONCURRENT_UDP);
    }
    #[test]
    fn caps_leave_room_for_every_socket_a_query_fans_out_to() {
        for limit in [1024usize, 4096, 16_384] {
            let single = caps_for(Some(limit), 1);
            for per_query in 1..=3 {
                let c = caps_for(Some(limit), per_query);
                // The descriptors a saturated forwarder holds: one per socket
                // of every in-flight query, plus one per accepted connection.
                assert!(
                    (c.udp + c.tcp) * per_query + c.tcp_conns + FD_RESERVE <= limit,
                    "{c:?} x{per_query} + reserve overruns {limit}"
                );
                assert!(
                    c.udp <= single.udp && c.tcp <= single.tcp,
                    "fanning out cannot raise a ceiling"
                );
                assert_eq!(
                    c.tcp_conns, single.tcp_conns,
                    "a connection costs one descriptor whatever the fan-out"
                );
            }
            // A single upstream is the common config: its budget is unchanged.
            assert_eq!(caps_for(Some(limit), 1), single);
        }
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
            let c = caps_for(Some(limit), 3);
            assert_eq!(c.udp, MIN_CONCURRENT_UDP, "limit={limit}");
            assert_eq!(c.tcp, MIN_CONCURRENT_TCP, "limit={limit}");
            assert_eq!(c.tcp_conns, MIN_TCP_CONNS, "limit={limit}");
        }
    }

    #[test]
    fn caps_grow_monotonically_with_the_limit() {
        let mut prev = caps_for(Some(0), 2);
        for limit in (0..20_000).step_by(97) {
            let c = caps_for(Some(limit), 2);
            assert!(c.udp >= prev.udp && c.tcp >= prev.tcp && c.tcp_conns >= prev.tcp_conns);
            prev = c;
        }
    }
}
