// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

//! Startup readiness channel between a `-d` parent and its forked child.
//!
//! The child does its real work — parsing the config, binding every listen
//! address — only after the fork, with stdio already sent to /dev/null, so the
//! parent has nothing to report and exits 0 whatever happens. The parent keeps
//! the read end of a pipe and waits on it: the child writes [`OK`] once it is
//! serving, or the fatal error text, and the parent turns that into its own
//! exit code and message.

use std::fs::File;
use std::io::Write;
use std::os::fd::FromRawFd;
use std::sync::{Mutex, OnceLock};

/// Environment variable carrying the write end's descriptor number to the
/// child. Removed as soon as it is read, so nothing the child spawns later
/// (hook commands) inherits it.
pub const READY_FD_VAR: &str = "MINI_PPDNS_READY_FD";
/// What a child that reached "serving" writes.
pub const OK: &[u8] = b"ok";

static PIPE: OnceLock<Mutex<Option<File>>> = OnceLock::new();

/// Adopt the readiness pipe this process was forked with, if any. Call once,
/// before anything that could fail fatally.
pub fn adopt_from_env() {
    let Ok(raw) = std::env::var(READY_FD_VAR) else {
        return;
    };
    std::env::remove_var(READY_FD_VAR);
    let Ok(fd) = raw.parse::<i32>() else {
        return;
    };
    if fd < 0 {
        return;
    }
    // SAFETY: the parent passed this descriptor number for exactly this
    // purpose and does not use it again in the child; the `File` owns it from
    // here on and closes it on drop.
    let file = unsafe { File::from_raw_fd(fd) };
    let _ = PIPE.set(Mutex::new(Some(file)));
}

/// Report that the process is serving.
pub fn serving() {
    report(OK);
}

/// Report a fatal startup error, which the parent prints as its own.
pub fn failed(msg: &str) {
    report(msg.as_bytes());
}

/// Write once and close: the parent reads to EOF, and a second report would
/// only confuse it. Later calls are no-ops.
fn report(bytes: &[u8]) {
    let Some(slot) = PIPE.get() else {
        return;
    };
    let Ok(mut slot) = slot.lock() else {
        return;
    };
    if let Some(mut file) = slot.take() {
        let _ = file.write_all(bytes);
        let _ = file.flush();
    }
}
