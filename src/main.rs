// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

mod app;
mod cache;
mod cli;
mod config;
mod dns;
mod forcefall;
mod handler;
mod hook;
mod local_resolver;
mod log;
mod pplog;
mod rng;
mod server;
mod sysinfo;
mod upstream;
mod util;

use std::process::ExitCode;

use config::Config;
use forcefall::ForceFallMatcher;

/// Version string, overridable at build time via the `MINI_PPDNS_VERSION` env
/// var (the release workflow sets it to `kkkgo/ppdns:mini-ppdns <date> <hash>`).
const VERSION: &str = match option_env!("MINI_PPDNS_VERSION") {
    Some(v) => v,
    None => "kkkgo/ppdns:mini-ppdns rust-dev",
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(Fatal::Usage(msg)) => {
            eprintln!("{msg}");
            ExitCode::from(2)
        }
        Err(Fatal::Config(msg)) => {
            eprintln!("{msg}");
            ExitCode::from(1)
        }
    }
}

enum Fatal {
    Usage(String),
    Config(String),
}

fn run() -> Result<(), Fatal> {
    let raw = cli::parse(std::env::args().skip(1)).map_err(Fatal::Usage)?;

    if raw.get_bool("version").unwrap_or(false) {
        println!("{VERSION}");
        return Ok(());
    }

    let mut warnings: Vec<String> = Vec::new();
    let cfg = build_config(&raw, &mut warnings)?;
    // Initialize logging (timestamp + color) before emitting any log lines.
    log::init(cfg.debug);
    for w in &warnings {
        log::warn(w);
    }

    // Resolve upstreams (normalize addresses; full validation lands with the
    // upstream layer in P2).
    let dns_upstreams: Vec<String> = cfg
        .dns
        .iter()
        .map(|a| util::format_upstream_addr(a))
        .collect();
    let fall_upstreams: Vec<String> = cfg
        .fall
        .iter()
        .map(|a| util::format_upstream_addr(a))
        .collect();
    if dns_upstreams.is_empty() {
        return Err(Fatal::Config(
            "Error: No DNS upstream provided (-dns)".into(),
        ));
    }
    if fall_upstreams.is_empty() {
        return Err(Fatal::Config(
            "Error: No fallback DNS provided (-fall)".into(),
        ));
    }
    if cfg.qtime <= 0 {
        return Err(Fatal::Config(format!(
            "Error: qtime must be positive (got {})",
            cfg.qtime
        )));
    }

    // Resolve listen addresses.
    let listen = resolve_listen(&cfg);

    // Build force_fall matcher (invalid entries are fatal).
    let matcher = build_force_fall(&cfg)?;

    if cfg.daemon {
        // Fork a detached child (re-exec without -d) and exit the parent.
        daemonize();
    }

    // Serve until a signal.
    app::run(&cfg, listen, matcher, dns_upstreams, fall_upstreams).map_err(Fatal::Config)
}

/// Re-exec this binary in a new session (setsid) without the `-d` flag, print
/// the child PID, and exit the parent. Never returns.
fn daemonize() -> ! {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to get executable path: {e}");
            std::process::exit(1);
        }
    };
    let args: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| !is_daemon_flag_arg(a))
        .collect();
    let mut cmd = Command::new(exe);
    cmd.args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: setsid is async-signal-safe and the only work done in the child
    // between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    match cmd.spawn() {
        Ok(child) => {
            println!("Started in background with PID {}", child.id());
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("Failed to start daemon: {e}");
            std::process::exit(1);
        }
    }
}

/// Any form of the `-d` boolean flag, so the forked child never inherits it.
fn is_daemon_flag_arg(arg: &str) -> bool {
    arg == "-d" || arg == "--d" || arg.starts_with("-d=") || arg.starts_with("--d=")
}

/// Merge an optional config file with CLI flags. Precedence is uniform:
/// CLI (when explicitly given) > config file > default. Collection flags
/// (dns/fall/listen/…) append CLI entries after the file's.
fn build_config(raw: &cli::RawArgs, warnings: &mut Vec<String>) -> Result<Config, Fatal> {
    // daemon/debug are CLI-only (the file has no such keys).
    let mut cfg = Config {
        daemon: raw.get_bool("d").unwrap_or(false),
        debug: raw.get_bool("debug").unwrap_or(false),
        ..Config::default()
    };

    if let Some(path) = nonempty(raw.get_str("config")) {
        config::parse_ini(path, &mut cfg, warnings)
            .map_err(|e| Fatal::Config(format!("Error reading config: {e}")))?;
    }

    // Scalars: an explicitly-given CLI flag overrides the file.
    if raw.was_set("qtime") {
        if let Some(n) = raw.get_int("qtime") {
            cfg.qtime = n;
        }
    }
    if let Some(v) = nonempty(raw.get_str("aaaa")) {
        cfg.aaaa = v.to_string();
    }
    if let Some(v) = nonempty(raw.get_str("lite")) {
        cfg.lite = v.to_string();
    }

    // Collection flags: config entries first, then CLI entries appended.
    if let Some(v) = nonempty(raw.get_str("dns")) {
        cfg.dns.extend(split_csv_raw(v));
    }
    if let Some(v) = nonempty(raw.get_str("fall")) {
        cfg.fall.extend(split_csv_raw(v));
    }
    if let Some(v) = nonempty(raw.get_str("listen")) {
        cfg.listen.extend(split_csv_raw(v));
    }
    if let Some(v) = nonempty(raw.get_str("force_fall")) {
        cfg.force_fall.extend(split_csv_raw(v));
    }
    if let Some(v) = nonempty(raw.get_str("lease_file")) {
        cfg.lease_file.extend(split_csv_trim(v));
    }
    if let Some(v) = nonempty(raw.get_str("hosts_file")) {
        cfg.hosts_file.extend(split_csv_trim(v));
    }

    // pplog: CLI overrides config when provided.
    if let Some(v) = nonempty(raw.get_str("pplog_server")) {
        cfg.pplog_server = v.to_string();
    }
    if let Some(v) = nonempty(raw.get_str("pplog_uuid")) {
        cfg.pplog_uuid = v.to_string();
    }
    if let Some(n) = raw.get_int("pplog_level") {
        if n > 0 {
            cfg.pplog_level = n;
        }
    }

    // trust_rcode: CLI (when non-empty) clears and replaces the config value.
    if let Some(v) = nonempty(raw.get_str("trust_rcode")) {
        cfg.trust_rcode.clear();
        for s in v.split(',') {
            let s = s.trim();
            if s.is_empty() {
                continue;
            }
            match s.parse::<i32>() {
                Ok(n) => cfg.trust_rcode.push(n),
                Err(_) => warnings.push(format!("invalid trust_rcode value, skipping: {s}")),
            }
        }
    }

    // Tri-state booleans: CLI (explicit) > config (if set) > default true.
    if raw.was_set("boguspriv") {
        cfg.boguspriv = raw.get_bool("boguspriv").unwrap_or(true);
    } else if !cfg.boguspriv_set {
        cfg.boguspriv = true;
    }
    if raw.was_set("block_svcb") {
        cfg.block_svcb = raw.get_bool("block_svcb").unwrap_or(true);
    } else if !cfg.block_svcb_set {
        cfg.block_svcb = true;
    }

    // Normalize enum-like values (case-insensitive) with fallback.
    cfg.aaaa = cfg.aaaa.trim().to_ascii_lowercase();
    if !matches!(cfg.aaaa.as_str(), "no" | "yes" | "noerror") {
        println!("invalid aaaa value {:?}, falling back to \"no\"", cfg.aaaa);
        cfg.aaaa = "no".to_string();
    }
    cfg.lite = cfg.lite.trim().to_ascii_lowercase();
    if !matches!(cfg.lite.as_str(), "no" | "yes") {
        println!("invalid lite value {:?}, falling back to \"yes\"", cfg.lite);
        cfg.lite = "yes".to_string();
    }

    Ok(cfg)
}

fn resolve_listen(cfg: &Config) -> Vec<String> {
    if cfg.listen.is_empty() {
        return sysinfo::get_private_ips();
    }
    let mut expanded = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for a in &cfg.listen {
        let a = sysinfo::ensure_listen_port(a);
        for e in sysinfo::expand_wildcard_listen(&a) {
            if seen.insert(e.clone()) {
                expanded.push(e);
            }
        }
    }
    expanded
}

fn build_force_fall(cfg: &Config) -> Result<ForceFallMatcher, Fatal> {
    let mut matcher = ForceFallMatcher::default();
    for s in &cfg.force_fall {
        let entry = forcefall::parse_force_fall_entry(s)
            .map_err(|e| Fatal::Config(format!("invalid force_fall entry {s:?}: {e}")))?;
        if entry.prefixes.is_empty() {
            continue;
        }
        if entry.negated {
            matcher.negate.extend(entry.prefixes);
        } else {
            matcher.include.extend(entry.prefixes);
        }
    }
    Ok(matcher)
}

fn nonempty(o: Option<&str>) -> Option<&str> {
    o.filter(|s| !s.is_empty())
}

/// Split on commas without trimming (for dns/fall/listen/force_fall CLI flags).
fn split_csv_raw(v: &str) -> Vec<String> {
    v.split(',').map(|s| s.to_string()).collect()
}

/// Split on commas, trimming and dropping empties (lease_file/hosts_file).
fn split_csv_trim(v: &str) -> Vec<String> {
    v.split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_overrides_config_file() {
        let mut path = std::env::temp_dir();
        path.push(format!("mini-ppdns-prec-{}.ini", std::process::id()));
        std::fs::write(&path, "[adv]\nqtime=300\naaaa=noerror\nlite=no\n").unwrap();
        let raw = cli::parse(
            [
                "-config",
                path.to_str().unwrap(),
                "-qtime",
                "100",
                "-aaaa",
                "yes",
            ]
            .iter()
            .map(|s| s.to_string()),
        )
        .unwrap();
        let mut warnings = Vec::new();
        let Ok(cfg) = build_config(&raw, &mut warnings) else {
            panic!("build_config failed");
        };
        let _ = std::fs::remove_file(&path);
        assert_eq!(cfg.qtime, 100, "CLI qtime wins over file");
        assert_eq!(cfg.aaaa, "yes", "CLI aaaa wins over file");
        assert_eq!(cfg.lite, "no", "file value kept when CLI absent");
    }
}
