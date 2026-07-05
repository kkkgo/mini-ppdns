// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

//! Hook health monitor.
//!
//! Periodically runs a shell probe of the primary DNS's health. After `count`
//! consecutive failures it marks the primary down (flipping the shared flag the
//! handler reads to force fallback), flushes the cache, and runs the optional
//! `switch_fall_exec`. On recovery it flips back and runs `switch_main_exec`.

use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::sync::watch;

use crate::cache::Cache;
use crate::config::HookConfig;
use crate::pplog::{Reporter, SEVERITY_INFO, SEVERITY_WARN};

const HOOK_CHECK_TIMEOUT: Duration = Duration::from_secs(30);
const HOOK_CMD_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_HOOK_OUTPUT: usize = 64 * 1024;

pub struct HookMonitor {
    pub cfg: HookConfig,
    pub failed: Arc<AtomicBool>,
    pub cache: Arc<Cache>,
    pub pplog: Option<Arc<Reporter>>,
}

impl HookMonitor {
    /// Run the monitor loop until shutdown.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        let sleep_time = Duration::from_secs(self.cfg.sleep_time.max(1) as u64);
        let retry_time = Duration::from_secs(self.cfg.retry_time.max(1) as u64);
        let mut fail_count: i64 = 0;
        let mut was_down = false;

        loop {
            let ok = self.check().await;
            let wait = if ok {
                fail_count = 0;
                if was_down {
                    self.failed.store(false, Ordering::Relaxed);
                    was_down = false;
                    eprintln!("[hook] main DNS recovered, switching back to main DNS");
                    if let Some(rep) = &self.pplog {
                        rep.report_event(SEVERITY_INFO, "[hook] main DNS recovered");
                    }
                    spawn_exec(self.cfg.switch_main_exec.clone());
                }
                sleep_time
            } else {
                fail_count += 1;
                if fail_count >= self.cfg.count && !was_down {
                    self.failed.store(true, Ordering::Relaxed);
                    was_down = true;
                    self.cache.flush();
                    eprintln!(
                        "[hook] main DNS marked DOWN ({fail_count} failures), switching to fallback; cache flushed"
                    );
                    if let Some(rep) = &self.pplog {
                        rep.report_event(
                            SEVERITY_WARN,
                            "[hook] main DNS DOWN, switching to fallback",
                        );
                    }
                    // switch_fall_exec runs after retry_time/2 so the fallback is
                    // already active — and only if still down at that point.
                    if !self.cfg.switch_fall_exec.is_empty() {
                        let cmd = self.cfg.switch_fall_exec.clone();
                        let delay = retry_time / 2;
                        let failed = self.failed.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(delay).await;
                            if failed.load(Ordering::Relaxed) {
                                run_exec_cmd(&cmd).await;
                            }
                        });
                    }
                }
                retry_time
            };

            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() { break; }
                }
                _ = tokio::time::sleep(wait) => {}
            }
        }
    }

    /// Probe the primary DNS. With neither `exit_code` nor `keyword` configured,
    /// success is exit 0; otherwise both configured checks must pass.
    async fn check(&self) -> bool {
        let Some((exit_code, output)) = run_shell(&self.cfg.exec, HOOK_CHECK_TIMEOUT).await else {
            return false; // spawn error or timeout
        };
        if !self.cfg.exit_code_set && self.cfg.keyword.is_empty() {
            return exit_code == 0;
        }
        if self.cfg.exit_code_set && exit_code != self.cfg.exit_code {
            return false;
        }
        if !self.cfg.keyword.is_empty() && !contains_sub(&output, self.cfg.keyword.as_bytes()) {
            return false;
        }
        true
    }
}

fn shell() -> String {
    std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string())
}

/// Run `cmd_str` via the shell. Returns `(exit_code, combined stdout+stderr)`,
/// or None on spawn error / timeout. Output is bounded to `MAX_HOOK_OUTPUT`
/// *during* reading (excess is drained and discarded) so a runaway command
/// cannot grow the buffer without limit.
async fn run_shell(cmd_str: &str, timeout: Duration) -> Option<(i32, Vec<u8>)> {
    let mut cmd = Command::new(shell());
    cmd.arg("-c")
        .arg(cmd_str)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = cmd.spawn().ok()?;
    let stdout = child.stdout.take()?;
    let stderr = child.stderr.take()?;

    let run = async {
        // Read both pipes concurrently (bounded), then reap the child.
        let (o, e) = tokio::join!(read_capped(stdout), read_capped(stderr));
        let status = child.wait().await.ok()?;
        let mut combined = o;
        combined.extend_from_slice(&e);
        combined.truncate(MAX_HOOK_OUTPUT);
        Some((status.code().unwrap_or(-1), combined))
    };
    tokio::time::timeout(timeout, run).await.ok()?
}

/// Read an async stream into a buffer, retaining at most `MAX_HOOK_OUTPUT`
/// bytes but continuing to drain the rest so the child never blocks on a full
/// pipe.
async fn read_capped<R: AsyncReadExt + Unpin>(mut r: R) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match r.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if buf.len() < MAX_HOOK_OUTPUT {
                    let take = (MAX_HOOK_OUTPUT - buf.len()).min(n);
                    buf.extend_from_slice(&chunk[..take]);
                }
                // Bytes beyond the cap are read but discarded.
            }
        }
    }
    buf
}

/// Run a side-effect command (switch_*_exec), logging failures.
async fn run_exec_cmd(cmd_str: &str) {
    if cmd_str.is_empty() {
        return;
    }
    match run_shell(cmd_str, HOOK_CMD_TIMEOUT).await {
        Some((0, _)) => {}
        Some((code, out)) => eprintln!(
            "[hook] switch exec failed (exit {code}): {}",
            String::from_utf8_lossy(&out)
        ),
        None => eprintln!("[hook] switch exec failed to run or timed out: {cmd_str}"),
    }
}

fn spawn_exec(cmd_str: String) {
    if cmd_str.is_empty() {
        return;
    }
    tokio::spawn(async move { run_exec_cmd(&cmd_str).await });
}

fn contains_sub(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn monitor(cfg: HookConfig) -> HookMonitor {
        HookMonitor {
            cfg,
            failed: Arc::new(AtomicBool::new(false)),
            cache: Arc::new(Cache::new(16)),
            pplog: None,
        }
    }

    fn cfg(exec: &str) -> HookConfig {
        HookConfig {
            exec: exec.to_string(),
            ..HookConfig::default()
        }
    }

    #[tokio::test]
    async fn exit_zero_is_success_by_default() {
        assert!(monitor(cfg("true")).check().await);
        assert!(!monitor(cfg("false")).check().await);
    }

    #[tokio::test]
    async fn keyword_must_be_present() {
        let mut ok = cfg("printf hello-world");
        ok.keyword = "hello".to_string();
        assert!(monitor(ok).check().await);

        let mut no = cfg("printf hello-world");
        no.keyword = "absent".to_string();
        assert!(!monitor(no).check().await);
    }

    #[tokio::test]
    async fn exit_code_checked_only_when_set() {
        let mut ok = cfg("exit 3");
        ok.exit_code = 3;
        ok.exit_code_set = true;
        assert!(monitor(ok).check().await);

        let mut no = cfg("exit 3");
        no.exit_code = 0;
        no.exit_code_set = true;
        assert!(!monitor(no).check().await);
    }

    #[tokio::test]
    async fn spawn_failure_is_treated_as_down() {
        // A command that cannot run (empty → sh error / nonzero) is not success.
        assert!(
            !monitor(cfg("this-command-does-not-exist-xyz"))
                .check()
                .await
        );
    }
}
