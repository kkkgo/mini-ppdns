// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

//! Minimal leveled logger.
//!
//! Every line is `YYYY/MM/DD HH:MM:SS ` (second precision, in the **system-local
//! timezone**; UTC+8 only as the tzdata-missing fallback — see
//! [`append_timestamp`]) followed by an optional level tag (`[WARN]`/`[ERROR]`,
//! colored; info/debug have none) and the message body. Output goes to stderr;
//! colors are emitted only when stderr is a TTY. Query-line field order:
//! `<client> <route> [-> <upstream>] <qtype> <domain> <rcode> [<ms>ms] [extra]`.

use std::fmt::{Display, Write as _};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use domain::base::iana::Rtype;

static DEBUG: AtomicBool = AtomicBool::new(false);
static COLOR: AtomicBool = AtomicBool::new(false);
// Whether timestamps use the system-local zone (tz database present) or the
// fixed UTC+8 fallback — resolved once at startup.
static SYSTEM_TZ: AtomicBool = AtomicBool::new(true);

/// Configure logging once at startup.
pub fn init(debug: bool) {
    DEBUG.store(debug, Ordering::Relaxed);
    COLOR.store(stderr_is_tty(), Ordering::Relaxed);
    SYSTEM_TZ.store(tzdata_available(), Ordering::Relaxed);
}

pub fn debug_enabled() -> bool {
    DEBUG.load(Ordering::Relaxed)
}

fn color_on() -> bool {
    COLOR.load(Ordering::Relaxed)
}

fn stderr_is_tty() -> bool {
    // SAFETY: isatty just inspects a file descriptor.
    unsafe { libc::isatty(libc::STDERR_FILENO) == 1 }
}

// ---- timestamp ----
//
// Probe the tz database (`Asia/Shanghai`); on success use the system-local zone
// and log timestamps use it, else pin a fixed UTC+8. When the tz database is
// present, format in the system-local zone (libc `localtime_r`, DST-aware,
// honoring `TZ` / `/etc/localtime`); otherwise fall back to fixed UTC+8.

/// Reports whether the system tz database can resolve named zones — the
/// practical equivalent of probing for the `Asia/Shanghai` zone. Absent on
/// stripped embedded images, defaulting to UTC+8.
fn tzdata_available() -> bool {
    let dir = std::env::var_os("TZDIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/usr/share/zoneinfo"));
    dir.join("Asia/Shanghai").exists()
}

/// Append `YYYY/MM/DD HH:MM:SS ` in the system-local zone (or UTC+8 fallback).
fn append_timestamp(s: &mut String) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (y, m, d, hh, mm, ss) = if SYSTEM_TZ.load(Ordering::Relaxed) {
        local_time(now).unwrap_or_else(|| utc_plus8(now))
    } else {
        utc_plus8(now)
    };
    let _ = write!(s, "{y:04}/{m:02}/{d:02} {hh:02}:{mm:02}:{ss:02} ");
}

/// Broken-down system-local time via libc `localtime_r` (DST-aware, respects
/// `TZ` / `/etc/localtime`). None only if the C library rejects the timestamp.
fn local_time(secs: i64) -> Option<(i64, u32, u32, u32, u32, u32)> {
    // SAFETY: `localtime_r` writes into our stack `tm`; it is the thread-safe
    // variant and reads only global tz state (guarded by libc's own lock).
    unsafe {
        let t = secs as libc::time_t;
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&t, &mut tm).is_null() {
            return None;
        }
        Some((
            tm.tm_year as i64 + 1900,
            tm.tm_mon as u32 + 1,
            tm.tm_mday as u32,
            tm.tm_hour as u32,
            tm.tm_min as u32,
            tm.tm_sec as u32,
        ))
    }
}

/// Fixed UTC+8 broken-down time — tzdata-missing fallback.
fn utc_plus8(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let secs = secs + 8 * 3600;
    let days = secs.div_euclid(86400);
    let tod = secs.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    (
        y,
        m,
        d,
        (tod / 3600) as u32,
        ((tod % 3600) / 60) as u32,
        (tod % 60) as u32,
    )
}

/// Convert days-since-1970-01-01 to (year, month, day). Howard Hinnant's
/// `civil_from_days` algorithm — correct for the full proleptic Gregorian range.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

// ---- leveled lines ----

fn emit(prefix: &str, body: &str) {
    let mut line = String::with_capacity(body.len() + 48);
    append_timestamp(&mut line);
    line.push_str(prefix);
    line.push_str(body);
    eprintln!("{line}");
}

/// Info line (no level tag).
pub fn info(msg: &str) {
    emit("", msg);
}

pub fn warn(msg: &str) {
    let p = if color_on() {
        "\x1b[93m[WARN]\x1b[0m "
    } else {
        "[WARN] "
    };
    emit(p, msg);
}

pub fn error(msg: &str) {
    let p = if color_on() {
        "\x1b[91m[ERROR]\x1b[0m "
    } else {
        "[ERROR] "
    };
    emit(p, msg);
}

// ---- highlight helpers for composing colored info bodies (startup lines) ----

const RESET: &str = "\x1b[0m";
const C_VALUE: &str = "\x1b[1;37m"; // bold white — highlighted values
const C_UNIT: &str = "\x1b[32m"; // green — units
const C_ADDR: &str = "\x1b[1;35m"; // bold magenta — addresses

fn wrap(color: &str, x: impl Display) -> String {
    if color_on() {
        format!("{color}{x}{RESET}")
    } else {
        x.to_string()
    }
}

/// Highlight a value (bold white).
pub fn hl_value(x: impl Display) -> String {
    wrap(C_VALUE, x)
}

/// Highlight an address (bold magenta).
pub fn hl_addr(x: impl Display) -> String {
    wrap(C_ADDR, x)
}

/// Highlight a unit like "MB" (green).
pub fn hl_unit(x: impl Display) -> String {
    wrap(C_UNIT, x)
}

// ---- query log ----

const C_CLIENT: &str = "\x1b[33m"; // yellow
const C_ROUTE: &str = "\x1b[36m"; // cyan
const C_ARROW: &str = "\x1b[90m"; // gray
const C_UPSTREAM: &str = "\x1b[35m"; // magenta
const C_QTYPE: &str = "\x1b[34m"; // blue
const C_DOMAIN: &str = "\x1b[1;37m"; // bold white
const C_DUR: &str = "\x1b[90m"; // gray
const C_EXTRA: &str = "\x1b[96m"; // bright cyan

fn rcode_color(rcode: &str) -> &'static str {
    if rcode.starts_with("NOERROR") {
        "\x1b[32m" // green
    } else if rcode.starts_with("NODATA") {
        "\x1b[33m" // yellow
    } else if rcode.starts_with("NXDOMAIN") {
        "\x1b[31m" // red
    } else if rcode.starts_with("SERVFAIL") || rcode.starts_with("timeout") {
        "\x1b[91m" // bright red
    } else if rcode.starts_with("REFUSED") {
        "\x1b[95m" // bright magenta
    } else if rcode.starts_with("BLOCKED") {
        "\x1b[90m" // gray
    } else {
        "\x1b[37m" // white
    }
}

/// A single query log record.
pub struct Query<'a> {
    pub route: &'a str,
    pub client: IpAddr,
    pub upstream: Option<&'a str>,
    pub qtype: Rtype,
    pub domain: &'a str,
    pub rcode: &'a str,
    pub dur: Option<Duration>,
    pub extra: Option<&'a str>,
}

/// Emit a query log line (no-op unless debug is enabled).
pub fn query(q: &Query) {
    if !debug_enabled() {
        return;
    }
    let color = color_on();
    let mut s = String::with_capacity(112);
    append_timestamp(&mut s);

    let seg = |s: &mut String, c: &str, text: &str| {
        if color {
            s.push_str(c);
            s.push_str(text);
            s.push_str(RESET);
        } else {
            s.push_str(text);
        }
    };

    seg(&mut s, C_CLIENT, &q.client.to_string());
    s.push(' ');
    seg(&mut s, C_ROUTE, q.route);
    if let Some(up) = q.upstream {
        s.push(' ');
        seg(&mut s, C_ARROW, "->");
        s.push(' ');
        seg(&mut s, C_UPSTREAM, up);
    }
    s.push(' ');
    seg(&mut s, C_QTYPE, &q.qtype.to_string());
    s.push(' ');
    seg(&mut s, C_DOMAIN, q.domain);
    s.push(' ');
    seg(&mut s, rcode_color(q.rcode), q.rcode);
    if let Some(d) = q.dur {
        s.push(' ');
        seg(&mut s, C_DUR, &format!("{}ms", d.as_millis()));
    }
    if let Some(extra) = q.extra {
        s.push(' ');
        seg(&mut s, C_EXTRA, extra);
    }
    eprintln!("{s}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_date_epoch_and_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // 2000-01-01 is 10957 days after the epoch.
        assert_eq!(civil_from_days(10957), (2000, 1, 1));
        // 2026-07-01 → 20635 days after epoch.
        assert_eq!(civil_from_days(20635), (2026, 7, 1));
    }

    #[test]
    fn utc_plus8_fallback() {
        // Epoch is 1970-01-01 00:00:00 UTC → 08:00:00 at UTC+8.
        assert_eq!(utc_plus8(0), (1970, 1, 1, 8, 0, 0));
        // 2026-07-01 00:00:00 UTC → 08:00:00 UTC+8.
        assert_eq!(utc_plus8(20635 * 86400), (2026, 7, 1, 8, 0, 0));
    }

    #[test]
    fn local_time_returns_sane_value() {
        // Exercise the libc localtime_r integration without touching the
        // process-global TZ (which would race the parallel test harness):
        // just assert it resolves "now" to a plausible broken-down time.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let (y, m, d, hh, mm, ss) = local_time(now).expect("localtime_r resolves");
        assert!(y >= 2024, "year {y} implausible");
        assert!((1..=12).contains(&m) && (1..=31).contains(&d));
        assert!(hh < 24 && mm < 60 && ss < 60);
    }
}
