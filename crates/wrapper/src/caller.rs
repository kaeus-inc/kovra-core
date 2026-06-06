//! Observe the **requesting process** — the parent that launched this kovra
//! process — to populate [`kovra_core::ConfirmRequest::requesting_process`] (I16,
//! §8.3).
//!
//! This is a **trusted, observed fact**: the parent pid comes from the kernel
//! (`getppid`), and the executable name is read from the OS by pid. It is never
//! sourced from untrusted requester input, so it cannot be spoofed by the agent
//! whose request triggered the prompt. The human approving at the Touch ID /
//! file-broker prompt therefore sees *who* is really asking (e.g.
//! `node (pid 1234)`) rather than always "kovra".
//!
//! Why this lives in the wrapper (not core): observing a process is OS work, and
//! `core` must stay free of process-observation logic (CLAUDE.md rule 4). Both
//! the CLI (`kovra show`, private-key ops) and the wrapper (`kovra run`) call
//! [`observe_parent`]; the CLI depends on `kovra-wrapper`, so it reuses this
//! helper rather than duplicating it.
//!
//! Degradation: if the name cannot be read, we fall back to `pid <N>`. We never
//! include anything but a process identity (executable name/path + pid) — no
//! arguments, no environment — so this can never leak a secret value (I7/I12).

/// A human-readable identity for the **parent** process of the current process.
///
/// Returns e.g. `node (pid 1234)` or `/opt/homebrew/bin/node (pid 1234)`, or
/// just `pid 1234` when the executable name cannot be resolved. Returns `None`
/// only if even the parent pid cannot be observed (not expected on supported
/// hosts, but it fails soft rather than fabricating an identity).
#[must_use]
pub fn observe_parent() -> Option<String> {
    let ppid = parent_pid()?;
    match process_name(ppid) {
        Some(name) if !name.is_empty() => Some(format!("{name} (pid {ppid})")),
        _ => Some(format!("pid {ppid}")),
    }
}

/// The parent process id, from the kernel. `None` only if unobservable.
#[cfg(unix)]
fn parent_pid() -> Option<i32> {
    // SAFETY: `getppid` takes no arguments, has no preconditions, and cannot fail.
    let ppid = unsafe { libc::getppid() };
    if ppid > 0 { Some(ppid) } else { None }
}

#[cfg(not(unix))]
fn parent_pid() -> Option<i32> {
    None
}

/// Best-effort executable name/path for `pid`. Platform-specific; degrades to
/// `None` when it cannot be read (caller then shows just the pid).
#[cfg(target_os = "macos")]
fn process_name(pid: i32) -> Option<String> {
    // `proc_pidpath` fills an absolute executable path. We bind it directly
    // (libc does not expose the libproc shim) and keep the call minimal.
    const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;
    unsafe extern "C" {
        fn proc_pidpath(
            pid: libc::c_int,
            buffer: *mut libc::c_void,
            buffersize: u32,
        ) -> libc::c_int;
    }
    let mut buf = vec![0u8; PROC_PIDPATHINFO_MAXSIZE];
    // SAFETY: `buf` is a valid, writable allocation of `buf.len()` bytes; the
    // call writes at most `buffersize` bytes and returns the count written.
    let n = unsafe {
        proc_pidpath(
            pid as libc::c_int,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len() as u32,
        )
    };
    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    String::from_utf8(buf).ok().filter(|s| !s.is_empty())
}

/// Linux: read the executable name from `/proc/<pid>/comm` (the short name),
/// falling back to `/proc/<pid>/exe` (the resolved path) when available.
#[cfg(all(unix, not(target_os = "macos")))]
fn process_name(pid: i32) -> Option<String> {
    if let Ok(exe) = std::fs::read_link(format!("/proc/{pid}/exe")) {
        if let Some(s) = exe.to_str() {
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim_end().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(not(unix))]
fn process_name(_pid: i32) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // The helper degrades gracefully: on the test host it observes a real parent
    // (the test harness / cargo), so it returns Some(_) and includes a pid. We do
    // not assert a specific name (that varies by host), only the shape.
    #[test]
    fn observe_parent_returns_non_empty_identity_with_pid() {
        let id = observe_parent().expect("a parent process should be observable on the test host");
        assert!(!id.is_empty());
        assert!(
            id.contains("pid "),
            "identity should always carry the observed pid, got {id:?}"
        );
    }

    // It must never leak more than a process identity (no secret value): the
    // returned string is just a name/path and a pid — assert it has no embedded
    // NUL and is a single line.
    #[test]
    fn observed_identity_is_a_clean_single_line() {
        let id = observe_parent().unwrap();
        assert!(!id.contains('\0'));
        assert!(!id.contains('\n'));
    }
}
