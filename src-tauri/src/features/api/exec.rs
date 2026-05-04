//! Small wrapper around `tokio::process::Command` matching the semantics of
//! the Express server's `runCmd` helper: never throw, always return a struct
//! with `code`, `stdout`, `stderr`, captured to completion.
//!
//! Used by feature modules that shell out (clamdscan, freshclam, brew,
//! launchctl, systemctl, netsh, ufw, networksetup, …). Phase 1 only ports
//! pure read endpoints, so the type is currently unused; suppress the
//! dead-code warning until Phase 2 starts wiring shell-outs.
#![allow(dead_code)]

use std::ffi::OsStr;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::process::Command;

#[derive(Debug, Clone, Default)]
pub struct ExecOutput {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl ExecOutput {
    pub fn ok(&self) -> bool {
        self.code == 0
    }
    pub fn combined(&self) -> String {
        let mut s = String::with_capacity(self.stdout.len() + self.stderr.len());
        s.push_str(&self.stdout);
        s.push_str(&self.stderr);
        s
    }
}

/// Run a binary capturing stdout + stderr. Never panics; on spawn failure or
/// timeout returns `code = -1` with the error in `stderr`.
pub async fn run<I, S>(bin: &Path, args: I, timeout: Option<Duration>) -> ExecOutput
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return ExecOutput {
                code: -1,
                stdout: String::new(),
                stderr: format!("spawn {}: {e}", bin.display()),
            };
        }
    };

    let mut stdout_pipe = child.stdout.take().expect("piped stdout");
    let mut stderr_pipe = child.stderr.take().expect("piped stderr");

    let mut stdout = String::new();
    let mut stderr = String::new();

    let drain = async {
        let _ = tokio::join!(
            stdout_pipe.read_to_string(&mut stdout),
            stderr_pipe.read_to_string(&mut stderr),
        );
    };

    let wait = async {
        drain.await;
        child.wait().await
    };

    let status = match timeout {
        Some(t) => match tokio::time::timeout(t, wait).await {
            Ok(r) => r,
            Err(_) => {
                let _ = child.kill().await;
                return ExecOutput {
                    code: -1,
                    stdout,
                    stderr: format!("timeout after {}ms", t.as_millis()),
                };
            }
        },
        None => wait.await,
    };

    let code = match status {
        Ok(s) => s.code().unwrap_or(-1),
        Err(e) => {
            return ExecOutput {
                code: -1,
                stdout,
                stderr: format!("wait error: {e}"),
            }
        }
    };

    ExecOutput {
        code,
        stdout,
        stderr,
    }
}
