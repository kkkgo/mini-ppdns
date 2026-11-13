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
use tokio::process::{Child, Command};
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
            let ok = tokio::select! {
                biased;
                _ = shutdown.wait_for(|stop| *stop) => break,
                ok = self.check() => ok,
            };
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
                    // Only the main cache: its entries came from the DNS we
                    // just declared dead, and everyone is about to read the
                    // fallback cache instead. The fallback cache is deliberately
                    // kept — its entries are faithful fallback-upstream answers,
                    // which is exactly what the outage needs, and dropping them
                    // would also punish force_fall clients that are unaffected.
                    // Nothing needs clearing on recovery either: clients go back
                    // to reading this (now empty) cache and re-query the main DNS.
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
                _ = shutdown.wait_for(|stop| *stop) => break,
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

/// Keeps the group leader unreaped until output has drained. Its PID therefore
/// cannot be reused while it identifies the process group we may need to kill.
/// Commands that deliberately leave this group (e.g. with setsid) are outside
/// this cleanup boundary.
struct ShellProcess {
    child: Option<Child>,
    group: Option<libc::pid_t>,
}

impl ShellProcess {
    fn terminate(&mut self) {
        if let Some(group) = self.group.take() {
            // SAFETY: process_group(0) created this group for our unreaped child.
            // The negative PID targets that group, never the monitor's group.
            unsafe { libc::kill(-group, libc::SIGKILL) };
        }
        if let Some(child) = &mut self.child {
            // Also cover a leader that has changed its own group.
            let _ = child.start_kill();
        }
    }

    async fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        let status = self.child.as_mut().unwrap().wait().await?;
        // Reaping releases the PID. Never signal the old group after this point,
        // and preserve background tasks left by normally completed commands.
        self.group = None;
        Ok(status)
    }
}

impl Drop for ShellProcess {
    fn drop(&mut self) {
        self.terminate();
        if let Some(mut child) = self.child.take() {
            if child.id().is_some() {
                // Cancellation cannot await. Signal synchronously, then let the
                // running runtime reap the direct child. kill_on_drop remains a
                // fallback when the runtime itself is already shutting down.
                if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                    runtime.spawn(async move {
                        let _ = child.wait().await;
                    });
                }
            }
        }
    }
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
        .process_group(0)
        .kill_on_drop(true);
    let child = cmd.spawn().ok()?;
    let mut process = ShellProcess {
        group: child.id().map(|pid| pid as libc::pid_t),
        child: Some(child),
    };
    let stdout = process.child.as_mut()?.stdout.take()?;
    let stderr = process.child.as_mut()?.stderr.take()?;

    let run = async {
        // Read both pipes concurrently (bounded), then reap the child.
        let (o, e) = tokio::join!(read_capped(stdout), read_capped(stderr));
        let status = process.wait().await.ok()?;
        let mut combined = o;
        combined.extend_from_slice(&e);
        combined.truncate(MAX_HOOK_OUTPUT);
        Some((status.code().unwrap_or(-1), combined))
    };
    match tokio::time::timeout(timeout, run).await {
        Ok(result) => result,
        Err(_) => {
            process.terminate();
            let _ = process.wait().await;
            None
        }
    }
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

    #[tokio::test]
    async fn shell_preserves_exit_code_and_both_output_streams() {
        assert_eq!(
            run_shell(
                "printf stdout; printf stderr >&2; exit 7",
                Duration::from_secs(5)
            )
            .await,
            Some((7, b"stdoutstderr".to_vec()))
        );
    }

    #[tokio::test]
    async fn shell_drains_output_beyond_the_cap() {
        let (code, output) = run_shell(
            "head -c 131072 /dev/zero; head -c 131072 /dev/zero >&2; exit 7",
            Duration::from_secs(5),
        )
        .await
        .expect("both pipes should drain without blocking");
        assert_eq!(code, 7);
        assert_eq!(output, vec![0; MAX_HOOK_OUTPUT]);
    }

    #[cfg(target_os = "linux")]
    mod process_cleanup {
        use super::*;
        use std::path::PathBuf;
        use std::sync::atomic::AtomicUsize;
        use tokio::task::JoinHandle;

        // A PID alone is insufficient for cleanup: the original process may
        // already have exited and its numeric PID may have been reused.
        #[derive(Clone, Copy)]
        struct Process {
            pid: libc::pid_t,
            start_time: u64,
        }

        fn process_stat(pid: libc::pid_t) -> Option<(u64, char)> {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
            let fields: Vec<_> = stat[stat.rfind(')')? + 1..].split_whitespace().collect();
            Some((
                fields.get(19)?.parse().ok()?,
                fields.first()?.chars().next()?,
            ))
        }

        impl Process {
            fn running(self) -> bool {
                process_stat(self.pid).is_some_and(|(start_time, state)| {
                    start_time == self.start_time && !matches!(state, 'Z' | 'X')
                })
            }

            fn exists(self) -> bool {
                process_stat(self.pid).is_some_and(|(start_time, _)| start_time == self.start_time)
            }

            fn kill(self) {
                if self.running() {
                    // SAFETY: this PID was recorded by our isolated fixture;
                    // its start time was checked immediately before signaling.
                    unsafe { libc::kill(self.pid, libc::SIGKILL) };
                }
            }
        }

        struct Fixture {
            dir: PathBuf,
            processes: Vec<Process>,
        }

        impl Fixture {
            fn new() -> Self {
                static NEXT: AtomicUsize = AtomicUsize::new(0);
                let dir = std::env::temp_dir().join(format!(
                    "mini-ppdns-hook-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
                std::fs::create_dir(&dir).unwrap();
                Self {
                    dir,
                    processes: Vec::new(),
                }
            }

            fn command(&self, exit_shell: bool, redirect_child: bool) -> String {
                let pidfile = self
                    .dir
                    .join("pids")
                    .to_string_lossy()
                    .replace('\'', "'\\''");
                let release = self
                    .dir
                    .join("release")
                    .to_string_lossy()
                    .replace('\'', "'\\''");
                let redirect = if redirect_child {
                    ">/dev/null 2>&1"
                } else {
                    ""
                };
                let finish = if exit_shell { "exit 0" } else { "wait" };
                format!(
                    "sleep 60 {redirect} & descendant=$!; printf '%s %s\\n' \"$$\" \"$descendant\" > '{pidfile}'; while [ ! -f '{release}' ]; do sleep 0.01; done; {finish}"
                )
            }

            async fn handshake(&mut self) {
                tokio::time::timeout(Duration::from_secs(5), async {
                    loop {
                        if let Ok(pids) = std::fs::read_to_string(self.dir.join("pids")) {
                            let pids: Vec<libc::pid_t> = pids
                                .split_whitespace()
                                .map(|pid| pid.parse().unwrap())
                                .collect();
                            if pids.len() == 2 {
                                self.processes = pids
                                    .into_iter()
                                    .filter_map(|pid| {
                                        process_stat(pid)
                                            .map(|(start_time, _)| Process { pid, start_time })
                                    })
                                    .collect();
                                assert_eq!(
                                    self.processes.len(),
                                    2,
                                    "shell and descendant must be observed"
                                );
                                std::fs::write(self.dir.join("release"), b"").unwrap();
                                return;
                            }
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .expect("shell startup handshake");
            }

            async fn assert_stopped(&self) {
                tokio::time::timeout(Duration::from_secs(5), async {
                    while self.processes.iter().any(|process| process.running())
                        || self.processes[0].exists()
                    {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .expect("shell must be reaped and its descendant must stop");
            }
        }

        impl Drop for Fixture {
            fn drop(&mut self) {
                // A failed assertion must not leave the fixture's sleep running.
                for process in self.processes.iter().rev() {
                    process.kill();
                }
                let _ = std::fs::remove_dir_all(&self.dir);
            }
        }

        struct AbortOnDrop<T>(JoinHandle<T>);

        impl<T> Drop for AbortOnDrop<T> {
            fn drop(&mut self) {
                self.0.abort();
            }
        }

        async fn run_cleanup_case(cancel: bool, exit_shell: bool) {
            let mut fixture = Fixture::new();
            let command = fixture.command(exit_shell, false);
            let timeout = if cancel {
                Duration::from_secs(60)
            } else {
                Duration::from_secs(2)
            };
            let mut task = AbortOnDrop(tokio::spawn(
                async move { run_shell(&command, timeout).await },
            ));
            fixture.handshake().await;
            assert!(fixture.processes[1].running(), "descendant has started");
            if exit_shell {
                tokio::time::timeout(Duration::from_secs(5), async {
                    while fixture.processes[0].running() {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .expect("shell has exited while descendant retains its pipes");
            }
            if cancel {
                task.0.abort();
                assert!((&mut task.0).await.unwrap_err().is_cancelled());
            } else {
                assert_eq!((&mut task.0).await.unwrap(), None);
            }
            fixture.assert_stopped().await;
        }

        #[tokio::test]
        async fn timeout_stops_shell_and_descendant() {
            run_cleanup_case(false, false).await;
        }

        #[tokio::test]
        async fn cancellation_stops_shell_and_descendant() {
            run_cleanup_case(true, false).await;
        }

        #[tokio::test]
        async fn timeout_stops_pipe_holder_after_shell_exits() {
            run_cleanup_case(false, true).await;
        }

        #[tokio::test]
        async fn cancellation_stops_pipe_holder_after_shell_exits() {
            run_cleanup_case(true, true).await;
        }

        #[tokio::test]
        async fn successful_shell_preserves_redirected_background_task() {
            let mut fixture = Fixture::new();
            let command = fixture.command(true, true);
            let mut task = AbortOnDrop(tokio::spawn(async move {
                run_shell(&command, Duration::from_secs(5)).await
            }));
            fixture.handshake().await;
            assert_eq!((&mut task.0).await.unwrap(), Some((0, Vec::new())));
            assert!(fixture.processes[1].running());
            assert!(
                !fixture.processes[0].exists(),
                "successful shell was reaped"
            );
        }

        #[tokio::test]
        async fn shutdown_cancels_probe_without_marking_primary_down() {
            let mut fixture = Fixture::new();
            let mut config = cfg(&fixture.command(false, false));
            config.count = 1;
            let monitor = monitor(config);
            let failed = monitor.failed.clone();
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let mut task = AbortOnDrop(tokio::spawn(monitor.run(shutdown_rx)));
            fixture.handshake().await;
            shutdown_tx.send(true).unwrap();
            tokio::time::timeout(Duration::from_secs(2), &mut task.0)
                .await
                .expect("shutdown must cancel an in-flight probe")
                .unwrap();
            assert!(!failed.load(Ordering::Relaxed));
            fixture.assert_stopped().await;
        }
    }
}
