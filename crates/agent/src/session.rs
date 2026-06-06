//! Session logic: map a parsed ssh-agent [`Request`] to a response, applying
//! kovra's policy (KOV-13). This is the heart of the governed agent and is
//! **pure / OS-free** so it is driven entirely by mocks in tests — the real
//! socket and a real `ssh` client are `[host]`, not unit-tested (CLAUDE.md
//! rule 4, like the biometric path).
//!
//! For each request the session:
//! - **REQUEST_IDENTITIES** → enumerate the custodied keypairs that are
//!   *addressable* under the agent's [`AgentScope`] (I13: an out-of-scope key is
//!   not even listed — unaddressable, not listed-then-refused) and that hold a
//!   private half, and answer with their public blobs.
//! - **SIGN_REQUEST** → match the requested public blob to a custodied keypair
//!   (exact bytes); re-check scope (I13, defense in depth); run the per-signature
//!   policy funnel exactly like KOV-12's `gate_private_key_op`
//!   (`Operation::Inject` → `policy::decide`): `high`/`prod` confirm via the
//!   injected [`Confirmer`] on **every** signature (I3/I15), `low`/`medium` sign
//!   silently; sign **in memory** (I7) with `keypair::sign_ssh_agent`; and audit
//!   the act (I12 — coordinate + truncated fingerprint, never key bytes, never
//!   the challenge). Any denial/timeout/mismatch yields `SSH_AGENT_FAILURE`.

use std::time::Duration;

use kovra_core::{
    AccessRequest, AgentScope, AuditAction, AuditEvent, AuditSink, Clock, ConfirmOutcome,
    ConfirmRequest, Confirmer, Coordinate, Decision, Operation, Origin, Sensitivity, Surface,
    decide, fingerprint, public_key_blob, sign_ssh_agent,
};
use zeroize::Zeroizing;

use crate::error::AgentError;
use crate::protocol::{
    Identity, Request, encode_failure, encode_identities_answer, encode_sign_response,
};

/// A custodied keypair the agent can offer/sign with. Built by the face from a
/// `SecretRecord::Keypair { private: Some(_), .. }`; the private half is held in
/// a zeroizing buffer that is wiped when the entry drops. Public-only entries
/// are never turned into a `KeypairEntry` (nothing to sign with).
pub struct KeypairEntry {
    /// The canonical coordinate (`<env>/<component>/<key>`), for prompts/audit.
    pub coordinate: Coordinate,
    /// The owning project (`None` = global vault), for scope addressing.
    pub project: Option<String>,
    /// The environment segment, for the audit/confirm record.
    pub environment: String,
    /// The secret's sensitivity (drives per-signature confirmation).
    pub sensitivity: Sensitivity,
    /// OpenSSH public key (`ssh-ed25519 …` / `ssh-rsa …`).
    pub public_openssh: String,
    /// OpenSSH private key, sealed in memory only — never written to disk (I7).
    pub private_openssh: Zeroizing<String>,
}

impl KeypairEntry {
    /// The canonical coordinate string for prompts and audit.
    fn canonical(&self) -> String {
        self.coordinate.canonical_path().unwrap_or_else(|_| {
            format!(
                "{}/{}/{}",
                self.environment, self.coordinate.component, self.coordinate.key
            )
        })
    }

    /// Whether this key is addressable under `scope` (I13). A key not addressable
    /// is neither listed nor signable — it does not exist for this channel.
    fn addressable(&self, scope: &AgentScope) -> bool {
        scope.addresses(&self.coordinate, self.project.as_deref())
    }

    /// The advertised comment (the canonical coordinate, public metadata).
    fn comment(&self) -> String {
        format!("kovra:{}", self.canonical())
    }
}

/// Everything the session needs from the face: the custodied keys, the agent's
/// scope, the confirmation broker, the audit sink, the clock, and the
/// confirmation timeout. All behind traits so tests inject mocks.
pub struct Session<'a> {
    /// The keys this agent may offer/sign with (already filtered to those with a
    /// private half).
    pub keys: &'a [KeypairEntry],
    /// The agent's capability scope (I13).
    pub scope: &'a AgentScope,
    /// The per-signature confirmation broker (biometric / file fallback).
    pub confirmer: &'a dyn Confirmer,
    /// The append-only audit sink (I12).
    pub audit: &'a dyn AuditSink,
    /// The clock for audit timestamps.
    pub clock: &'a dyn Clock,
    /// How long a `high`/`prod` confirmation may block before failing safe.
    pub confirm_timeout: Duration,
    /// The observed requesting process, for the I16 prompt line (set by the
    /// face from `kovra_wrapper::observe_parent()`); `None` when unobserved.
    pub requesting_process: Option<String>,
}

impl Session<'_> {
    /// Handle one parsed request, returning the **response body** (ready to be
    /// framed by the daemon). All policy faults map to `SSH_AGENT_FAILURE`; this
    /// function never returns an `Err` for a protocol-level refusal (the wire
    /// answer carries it). It returns `Err` only on an audit/IO fault the daemon
    /// should log.
    pub fn handle(&self, request: &Request) -> Result<Vec<u8>, AgentError> {
        match request {
            Request::RequestIdentities => Ok(self.identities_answer()),
            Request::SignRequest {
                key_blob,
                data,
                flags,
            } => self.sign(key_blob, data, *flags),
        }
    }

    /// `SSH_AGENT_IDENTITIES_ANSWER` over the in-scope custodied keys (I13).
    fn identities_answer(&self) -> Vec<u8> {
        let mut identities = Vec::new();
        for k in self.keys {
            if !k.addressable(self.scope) {
                continue; // out of scope: unaddressable, not listed (I13)
            }
            // The public blob is public material (I12); a key whose public half
            // cannot be encoded is silently skipped rather than aborting the list.
            if let Ok(blob) = public_key_blob(&k.public_openssh) {
                identities.push(Identity {
                    key_blob: blob,
                    comment: k.comment(),
                });
            }
        }
        encode_identities_answer(&identities)
    }

    /// `SSH_AGENT_SIGN_RESPONSE`, or `SSH_AGENT_FAILURE` on any refusal.
    fn sign(&self, key_blob: &[u8], data: &[u8], flags: u32) -> Result<Vec<u8>, AgentError> {
        // (a) Match the requested public blob to a custodied key by exact bytes.
        //     A key the agent does not hold → FAILURE (no information leak).
        let key = match self.match_key(key_blob) {
            Some(k) => k,
            None => return Ok(encode_failure()),
        };
        let canonical = key.canonical();

        // (b) Re-check scope (I13, defense in depth). An out-of-scope key was
        //     never listed; even a client that crafted its blob cannot sign.
        if !key.addressable(self.scope) {
            self.record(
                AuditAction::OutOfScopeAttempt,
                "unaddressable",
                &canonical,
                &key.environment,
                None,
            );
            return Ok(encode_failure());
        }

        // (c) Per-signature policy funnel — identical to KOV-12's
        //     gate_private_key_op: a private-key op routed as Inject.
        let request = AccessRequest {
            coordinate: &key.coordinate,
            project: key.project.as_deref(),
            sensitivity: key.sensitivity,
            revealable: false,
            operation: Operation::Inject,
            surface: Surface::Cli,
            origin: Origin::Human,
        };
        match decide(&request, self.scope) {
            Decision::Allow => {
                // low/medium: sign silently, but still audited (I12).
                let sig = self.sign_in_memory(key, data, flags)?;
                self.record(
                    AuditAction::Inject,
                    "sign",
                    &canonical,
                    &key.environment,
                    Some(key),
                );
                Ok(encode_sign_response(&sig))
            }
            Decision::RequireConfirmation => {
                // high/prod: confirm on EVERY signature (I3/I15).
                let mut req = ConfirmRequest::new(
                    &canonical,
                    key.sensitivity,
                    &key.environment,
                    Origin::Human,
                )
                .with_command(format!("ssh-agent sign {canonical}"));
                if let Some(proc) = &self.requesting_process {
                    req = req.with_requesting_process(proc.clone());
                }
                match self.confirmer.confirm(&req, self.confirm_timeout) {
                    ConfirmOutcome::Approved => {
                        let sig = self.sign_in_memory(key, data, flags)?;
                        self.record(
                            AuditAction::Approve,
                            "approved",
                            &canonical,
                            &key.environment,
                            Some(key),
                        );
                        Ok(encode_sign_response(&sig))
                    }
                    ConfirmOutcome::Denied => {
                        self.record(
                            AuditAction::Deny,
                            "denied",
                            &canonical,
                            &key.environment,
                            None,
                        );
                        Ok(encode_failure())
                    }
                    ConfirmOutcome::TimedOut => {
                        self.record(
                            AuditAction::Timeout,
                            "timeout",
                            &canonical,
                            &key.environment,
                            None,
                        );
                        Ok(encode_failure())
                    }
                }
            }
            // Unaddressable was handled above; any other non-allow decision
            // (e.g. a future Deny) fails safe to FAILURE, audited.
            Decision::Deny(_) | Decision::Unaddressable => {
                self.record(
                    AuditAction::Deny,
                    "denied",
                    &canonical,
                    &key.environment,
                    None,
                );
                Ok(encode_failure())
            }
        }
    }

    /// Sign the challenge **in memory** with the custodied private key (I7). The
    /// key bytes live only inside this call; the raw ssh-agent signature blob
    /// carries no key material.
    fn sign_in_memory(
        &self,
        key: &KeypairEntry,
        data: &[u8],
        flags: u32,
    ) -> Result<Vec<u8>, AgentError> {
        Ok(sign_ssh_agent(&key.private_openssh, data, flags)?)
    }

    /// Find the custodied key whose public blob equals `key_blob` (exact bytes).
    fn match_key(&self, key_blob: &[u8]) -> Option<&KeypairEntry> {
        self.keys.iter().find(|k| {
            public_key_blob(&k.public_openssh)
                .map(|b| b == key_blob)
                .unwrap_or(false)
        })
    }

    /// Record an audit event (I12). The optional `key` adds the **public** key's
    /// truncated fingerprint — never the private half, never the challenge.
    fn record(
        &self,
        action: AuditAction,
        result: &str,
        canonical: &str,
        environment: &str,
        key: Option<&KeypairEntry>,
    ) {
        let mut ev = AuditEvent::new(self.clock, action, result)
            .at(canonical, environment)
            .by(Origin::Human);
        if let Some(k) = key {
            ev = ev.with_fingerprint(fingerprint(k.public_openssh.as_bytes()));
        }
        // An audit write failure must not crash the daemon mid-connection; the
        // file sink fsyncs, and a transient error is dropped like the CLI's
        // `audit()` helper does.
        let _ = self.audit.record(&ev);
    }
}
