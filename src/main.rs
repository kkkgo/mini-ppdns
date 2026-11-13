// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

mod app;
mod cache;
mod cli;
mod config;
mod dns;
mod forcefall;
mod handler;
mod hook;
mod ifdns;
mod local_resolver;
mod log;
mod pplog;
mod ready;
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
    // A `-d` child inherits a pipe its parent is waiting on; everything below
    // that can fail fatally has to be able to say so through it.
    ready::adopt_from_env();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(Fatal::Usage(msg)) => {
            ready::failed(&msg);
            eprintln!("{msg}");
            ExitCode::from(2)
        }
        Err(Fatal::Config(msg)) => {
            ready::failed(&msg);
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

    let dns_upstreams = upstream_specs(&cfg.dns);
    let fall_upstreams = upstream_specs(&cfg.fall);
    check_out(&cfg.out)?;
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

/// How long the parent waits for the child's startup report before assuming
/// it is simply slow. Binding is the last step before the report and takes
/// milliseconds; a child still silent after this is reported as started, since
/// there is nothing better to say about it.
const READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Re-exec this binary in a new session (setsid) without the `-d` flag, wait
/// for it to report that it is serving, and exit with that verdict. Never
/// returns.
///
/// The child binds its listen addresses only after this fork, with its stdio
/// already pointed at /dev/null, so without the report the parent would print
/// "started" and exit 0 even when the child dies on `EADDRINUSE` — which is
/// what watchdog scripts then retry forever, silently.
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

    let mut fds = [0i32; 2];
    // SAFETY: `pipe2` writes exactly two descriptors into the array.
    let piped = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } == 0;
    let (read_fd, write_fd) = (fds[0], fds[1]);

    let mut cmd = Command::new(exe);
    cmd.args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if piped {
        cmd.env(ready::READY_FD_VAR, write_fd.to_string());
    }
    // SAFETY: setsid and fcntl are async-signal-safe and the only work done in
    // the child between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            libc::setsid();
            if piped {
                // The pipe was created close-on-exec so no other child can
                // inherit it; this one must, so clear the flag.
                libc::fcntl(write_fd, libc::F_SETFD, 0);
            }
            Ok(())
        });
    }
    let child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            eprintln!("Failed to start daemon: {e}");
            std::process::exit(1);
        }
    };
    if !piped {
        println!("Started in background with PID {}", child.id());
        std::process::exit(0);
    }
    // The parent's copy of the write end has to go, or the read below never
    // reaches EOF when the child exits without reporting.
    // SAFETY: this descriptor is the parent's own and is not used again.
    unsafe { libc::close(write_fd) };
    match child_report(read_fd) {
        Ok(()) => {
            println!("Started in background with PID {}", child.id());
            std::process::exit(0);
        }
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(1);
        }
    }
}

/// Wait for the child's startup report on `read_fd`. `Ok` means it is serving
/// (or stayed silent long enough that we stop waiting); `Err` carries what to
/// print.
fn child_report(read_fd: i32) -> Result<(), String> {
    use std::io::Read;

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // SAFETY: the read end belongs to this process and is used only here;
        // the `File` closes it on drop.
        let mut pipe = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(read_fd) };
        let mut buf = Vec::new();
        let _ = pipe.read_to_end(&mut buf);
        let _ = tx.send(buf);
    });
    match rx.recv_timeout(READY_TIMEOUT) {
        Ok(buf) if buf == ready::OK => Ok(()),
        // Still starting after the timeout: report it as started, which is the
        // best that can be said.
        Err(_) => Ok(()),
        Ok(buf) if buf.is_empty() => {
            Err("Failed to start in background: it exited during startup".to_string())
        }
        Ok(buf) => Err(String::from_utf8_lossy(&buf).into_owned()),
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
    if let Some(v) = nonempty(raw.get_str("out")) {
        cfg.out = v.to_string();
    }
    cfg.out = cfg.out.trim().to_string();

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

/// Turn `[dns]`/`[fall]` entries into upstream specs. An empty list means the
/// host's own DNS (`dns://%`). Malformed entries are skipped with a warning,
/// like any other invalid upstream.
fn upstream_specs(entries: &[String]) -> Vec<app::UpstreamSpec> {
    if entries.is_empty() {
        let auto = app::Target::Iface(ifdns::Selector::Auto);
        return vec![app::UpstreamSpec::new(None, auto)];
    }
    entries
        .iter()
        .filter_map(|e| match parse_spec(e) {
            Ok(spec) => Some(spec),
            Err(msg) => {
                log::warn(&format!("skipping invalid upstream: {msg}"));
                None
            }
        })
        .collect()
}

/// One entry: `[<interface>@]<target>`, where the target is an address in any
/// accepted form or a `dns://` entry. No target form contains `@`, so the
/// first one always ends the interface name.
fn parse_spec(entry: &str) -> Result<app::UpstreamSpec, String> {
    let entry = entry.trim();
    let (device, target) = match entry.split_once('@') {
        None => (None, entry),
        Some((dev, target)) => {
            let dev = dev.trim();
            if !ifdns::valid_ifname(dev) {
                return Err(format!("{entry:?}: {dev:?} is not a valid interface name"));
            }
            let target = target.trim();
            if target.is_empty() {
                return Err(format!("{entry:?} names no upstream after the @"));
            }
            (Some(std::sync::Arc::from(dev)), target)
        }
    };
    let target = match ifdns::Selector::parse(target) {
        Some(sel) => app::Target::Iface(sel?),
        None => app::Target::Addr(util::format_upstream_addr(target)),
    };
    Ok(app::UpstreamSpec::new(device, target))
}

/// `out` has to be a name `SO_BINDTODEVICE` can take (or empty, for unset).
fn check_out(out: &str) -> Result<(), Fatal> {
    if !out.is_empty() && !ifdns::valid_ifname(out) {
        return Err(Fatal::Config(format!(
            "Error: out={out:?} is not a valid interface name"
        )));
    }
    Ok(())
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

    #[test]
    fn unconfigured_upstreams_mean_the_hosts_own_dns() {
        let shown = |entries: &[&str]| -> Vec<String> {
            let given: Vec<String> = entries.iter().map(|s| s.to_string()).collect();
            upstream_specs(&given)
                .iter()
                .map(|s| s.to_string())
                .collect()
        };
        assert_eq!(shown(&[]), ["dns://%"]);
        assert!(upstream_specs(&[])[0].device.is_none());
        assert_eq!(
            shown(&["10.0.0.8", "dns://eth0", "dns://", "dns://%"]),
            ["udp://10.0.0.8:53", "dns://eth0", "dns://%"],
            "a malformed dns:// entry is dropped, not defaulted"
        );
    }

    #[test]
    fn an_entry_may_name_the_interface_it_goes_out_of() {
        let spec = parse_spec(" eth0@10.10.10.8:53 ").unwrap();
        assert_eq!(spec.device.as_deref(), Some("eth0"));
        assert!(matches!(&spec.target, app::Target::Addr(a) if a == "udp://10.10.10.8:53"));
        for (entry, shown) in [
            ("eth0@10.10.10.8", "eth0@udp://10.10.10.8:53"),
            ("br-lan @ 10.10.10.8:5353", "br-lan@udp://10.10.10.8:5353"),
            ("eth0@tcp://1.1.1.1", "eth0@tcp://1.1.1.1:53"),
            ("eth0@::1", "eth0@udp://[::1]:53"),
            (
                "pppoe-wan@[2001:db8::1]:53",
                "pppoe-wan@udp://[2001:db8::1]:53",
            ),
            ("pppoe-wan@dns://%", "pppoe-wan@dns://%"),
            ("eth1@dns://wan", "eth1@dns://wan"),
            ("10.10.10.8", "udp://10.10.10.8:53"),
        ] {
            assert_eq!(parse_spec(entry).unwrap().to_string(), shown, "{entry}");
        }
        for bad in [
            "@10.10.10.8",
            "eth0@",
            "eth 0@10.10.10.8",
            "eth0:1@10.10.10.8",
            "udp://eth0@10.10.10.8",
            "abcdefghijklmnop@10.10.10.8",
            "eth0@dns://",
        ] {
            assert!(parse_spec(bad).is_err(), "{bad:?}");
        }
        let given: Vec<String> = ["@1.2.3.4", "eth0@1.2.3.4"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(upstream_specs(&given).len(), 1, "the bad entry is skipped");
    }

    #[test]
    fn out_must_be_a_kernel_interface_name() {
        assert!(check_out("").is_ok(), "unset");
        assert!(check_out("pppoe-wan").is_ok());
        assert!(check_out("abcdefghijklmno").is_ok(), "15 bytes fit");
        assert!(check_out("abcdefghijklmnop").is_err(), "16 do not");
        assert!(check_out("eth0 eth1").is_err());
        assert!(check_out("../x").is_err());
    }

    #[test]
    fn out_comes_from_the_cli_over_the_file() {
        let mut path = std::env::temp_dir();
        path.push(format!("mini-ppdns-out-{}.ini", std::process::id()));
        std::fs::write(&path, "[adv]\nout=eth0\n").unwrap();
        let parse = |extra: &[&str]| {
            let mut args = vec!["-config".to_string(), path.to_str().unwrap().to_string()];
            args.extend(extra.iter().map(|s| s.to_string()));
            let raw = cli::parse(args).unwrap();
            let Ok(cfg) = build_config(&raw, &mut Vec::new()) else {
                panic!("build_config failed");
            };
            cfg.out
        };
        assert_eq!(parse(&[]), "eth0");
        assert_eq!(parse(&["-out", "pppoe-wan"]), "pppoe-wan");
        let _ = std::fs::remove_file(&path);
    }
}
