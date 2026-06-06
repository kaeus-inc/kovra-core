//! The process runner — the seam that actually launches the child (or mocks it).
//!
//! The runner is a trait so the Wrapper's orchestration (resolve → policy →
//! confirm → allowlist → inject) is tested deterministically with [`MockRunner`],
//! while production uses [`SystemRunner`]. The injected values are
//! [`SecretValue`]s exposed **only** at the moment of spawning and placed into
//! the child's environment — never written to disk (I7).

use std::path::PathBuf;
use std::sync::Mutex;

use kovra_core::SecretValue;

use crate::error::WrapperError;

/// A fully-resolved command ready to launch: the program, its arguments, and the
/// environment to inject into the child.
pub struct Command {
    /// The program to execute (the resolved `argv[0]`).
    pub program: PathBuf,
    /// The arguments after the program.
    pub args: Vec<String>,
    /// Variables to inject into the child's environment. Values stay protected
    /// until the runner exposes them at spawn time (I7 — never to disk).
    pub env: Vec<(String, SecretValue)>,
}

/// The captured result of a finished child process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    /// The exit status code, or `None` if the process was terminated by a signal.
    pub status: Option<i32>,
    /// Captured standard output (possibly sanitized by the Wrapper, §5.1).
    pub stdout: Vec<u8>,
    /// Captured standard error (possibly sanitized by the Wrapper, §5.1).
    pub stderr: Vec<u8>,
}

/// Launches a [`Command`]. The Wrapper depends on this trait, not on
/// `std::process`, so its logic is testable with [`MockRunner`].
pub trait ProcessRunner {
    /// Run the command to completion and capture its output.
    fn run(&self, command: &Command) -> Result<Output, WrapperError>;
}

/// The real runner: launches via `std::process::Command`, injecting the resolved
/// environment into the child. Inherits the parent environment and overrides it
/// with the injected variables. Nothing is written to disk (I7).
pub struct SystemRunner;

impl ProcessRunner for SystemRunner {
    fn run(&self, command: &Command) -> Result<Output, WrapperError> {
        let mut cmd = std::process::Command::new(&command.program);
        cmd.args(&command.args);
        for (name, value) in &command.env {
            // Expose the value only here, straight into the child's env. A value
            // that is not valid UTF-8 cannot be placed in the process
            // environment portably; reject it without echoing the value (I12).
            let s = std::str::from_utf8(value.expose()).map_err(|_| {
                WrapperError::Spawn(format!(
                    "value for `{name}` is not valid UTF-8 and cannot be injected"
                ))
            })?;
            cmd.env(name, s);
        }
        let out = cmd.output().map_err(|e| {
            WrapperError::Spawn(format!("launch {}: {e}", command.program.display()))
        })?;
        Ok(Output {
            status: out.status.code(),
            stdout: out.stdout,
            stderr: out.stderr,
        })
    }
}

/// A single recorded invocation, for test assertions. The exposed env values are
/// captured **only** because this is a test double; production never copies a
/// value out like this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedRun {
    /// The program that would have launched.
    pub program: PathBuf,
    /// Its arguments.
    pub args: Vec<String>,
    /// The injected environment, exposed for assertions (name → value).
    pub env: Vec<(String, String)>,
}

impl RecordedRun {
    /// The injected value for `name`, if present.
    pub fn env_value(&self, name: &str) -> Option<&str> {
        self.env
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// A test runner that records each invocation and returns a configured
/// [`Output`] without launching anything.
pub struct MockRunner {
    output: Output,
    invocations: Mutex<Vec<RecordedRun>>,
}

impl MockRunner {
    /// A runner returning `output` for every call.
    pub fn new(output: Output) -> Self {
        Self {
            output,
            invocations: Mutex::new(Vec::new()),
        }
    }

    /// A runner returning a successful empty output (exit code 0).
    pub fn ok() -> Self {
        Self::new(Output {
            status: Some(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
        })
    }

    /// A snapshot of the recorded invocations.
    pub fn invocations(&self) -> Vec<RecordedRun> {
        self.invocations
            .lock()
            .expect("runner mutex poisoned")
            .clone()
    }

    /// Whether the runner was ever invoked (i.e. a child would have launched).
    pub fn was_invoked(&self) -> bool {
        !self
            .invocations
            .lock()
            .expect("runner mutex poisoned")
            .is_empty()
    }
}

impl ProcessRunner for MockRunner {
    fn run(&self, command: &Command) -> Result<Output, WrapperError> {
        let env = command
            .env
            .iter()
            .map(|(k, v)| (k.clone(), String::from_utf8_lossy(v.expose()).into_owned()))
            .collect();
        self.invocations
            .lock()
            .expect("runner mutex poisoned")
            .push(RecordedRun {
                program: command.program.clone(),
                args: command.args.clone(),
                env,
            });
        Ok(self.output.clone())
    }
}
