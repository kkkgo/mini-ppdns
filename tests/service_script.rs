//! Exercise the shipped start function with an isolated fake daemon. No host
//! services, /usr/sbin binaries or real PID files are touched.
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Fixture(PathBuf);

impl Fixture {
    fn new(program: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "mini-ppdns-script-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        let prog = path.join("daemon");
        std::fs::write(&prog, format!("#!/bin/sh\n{program}\n")).unwrap();
        std::fs::set_permissions(&prog, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn start(&self) -> Output {
        let (functions, _) = include_str!("../mini-ppdns.sh")
            .split_once("\ncase \"$1\" in\n")
            .expect("script dispatch follows its function definitions");
        let harness = r#"
export SCRIPT_TEST_DIR="$1"
PROG="$1/daemon"
CONF="$1/config.ini"
PIDFILE="$1/pid"
sleep() { :; }
is_running() { [ -f "$SCRIPT_TEST_DIR/running" ]; }
get_cur_pid() { if is_running; then echo 4242; fi; }
start
"#;
        let mut child = Command::new("sh")
            .args(["-s", "--"])
            .arg(&self.0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(functions.as_bytes()).unwrap();
        stdin.write_all(harness.as_bytes()).unwrap();
        drop(stdin);
        child.wait_with_output().unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn daemon_start_failure_is_returned_without_a_success_message_or_pid_file() {
    let fixture = Fixture::new("exit 7");
    let output = fixture.start();
    assert_eq!(output.status.code(), Some(7));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("mini-ppdns started."));
    assert!(!fixture.0.join("pid").exists());
}

#[test]
fn daemon_exiting_after_startup_is_not_reported_as_running() {
    let fixture = Fixture::new("exit 0");
    let output = fixture.start();
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("mini-ppdns started."));
    assert!(!fixture.0.join("pid").exists());
}

#[test]
fn a_live_daemon_is_recorded_and_reported_as_started() {
    let fixture = Fixture::new(
        "[ \"$1\" = -config ] && [ \"$2\" = \"$SCRIPT_TEST_DIR/config.ini\" ] && [ \"$3\" = -d ] || exit 9\n: > \"$SCRIPT_TEST_DIR/running\"",
    );
    let output = fixture.start();
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("mini-ppdns started."));
    let pid = std::fs::read_to_string(fixture.0.join("pid")).unwrap();
    assert_eq!(pid.lines().next(), Some("4242"));
    assert!(pid.lines().nth(1).is_some_and(|time| !time.is_empty()));
}

#[test]
fn an_existing_daemon_is_not_started_again() {
    let fixture = Fixture::new(": > \"$SCRIPT_TEST_DIR/called\"\nexit 7");
    std::fs::write(fixture.0.join("running"), "").unwrap();
    let output = fixture.start();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("mini-ppdns running OK."));
    assert!(!fixture.0.join("called").exists());
}
