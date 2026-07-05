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
use crate::local_resolver::PtrResolver;
use crate::log;
use crate::server::{serve_tcp, serve_udp};
use crate::sysinfo::{calculate_cache_size, get_available_memory};
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
const SHUTDOWN_DRAIN: Duration = Duration::from_secs(5);

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
    rt.block_on(serve(cfg, listen, matcher, dns_upstreams, fall_upstreams))
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

    let qtime = Duration::from_millis(cfg.qtime as u64);
    let main_fwd = Forwarder::new(main, qtime);
    let fall_fwd = Forwarder::new(fall, qtime * 10);

    let avail = get_available_memory();
    let cache_cap = calculate_cache_size(avail);
    let cache = Arc::new(Cache::new(cache_cap));

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
        "cache capacity {} entries",
        log::hl_value(cache_cap)
    ));

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Local resolver (lease/hosts files + [hosts] statics) — None if nothing
    // to resolve.
    let auto_detect = cfg.lease_file.is_empty() && cfg.hosts_file.is_empty();
    let resolver = PtrResolver::new(
        cfg.lease_file.clone(),
        cfg.hosts_file.clone(),
        auto_detect,
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
        main: main_fwd,
        fallback: fall_fwd,
        cache: cache.clone(),
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

    let udp_sem = Arc::new(Semaphore::new(MAX_CONCURRENT_UDP));
    let tcp_sem = Arc::new(Semaphore::new(MAX_CONCURRENT_TCP));
    let tcp_conn_sem = Arc::new(Semaphore::new(MAX_TCP_CONNS));

    let mut servers = Vec::new();
    for addr in &listen {
        match UdpSocket::bind(addr).await {
            Ok(sock) => {
                servers.push(tokio::spawn(serve_udp(
                    sock,
                    handler.clone(),
                    udp_sem.clone(),
                    shutdown_rx.clone(),
                )));
            }
            Err(e) => log::error(&format!("listen udp://{addr} err: {e}")),
        }
        match TcpListener::bind(addr).await {
            Ok(l) => {
                servers.push(tokio::spawn(serve_tcp(
                    l,
                    handler.clone(),
                    tcp_sem.clone(),
                    tcp_conn_sem.clone(),
                    shutdown_rx.clone(),
                )));
                log::info(&format!("listen: {}", log::hl_addr(addr)));
            }
            Err(e) => log::error(&format!("listen tcp://{addr} err: {e}")),
        }
    }
    if servers.is_empty() {
        return Err("failed to listen on any address".into());
    }

    // Cache janitor.
    let jan = tokio::spawn(janitor(cache.clone(), shutdown_rx.clone()));

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
        let _ = udp_sem.acquire_many(MAX_CONCURRENT_UDP as u32).await;
        let _ = tcp_sem.acquire_many(MAX_CONCURRENT_TCP as u32).await;
    };
    let _ = tokio::time::timeout(SHUTDOWN_DRAIN, drain).await;

    jan.abort();
    for s in servers {
        s.abort();
    }
    log::info("shutdown complete");
    Ok(())
}

async fn janitor(cache: Arc<Cache>, mut shutdown: watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(Duration::from_secs(10));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
            _ = tick.tick() => cache.sweep(),
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
