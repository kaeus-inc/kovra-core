//! `kovra-core` — vault, crypto, policy, model, resolver, `AgentScope`, and the
//! OS/cloud traits (`Provider`/`Confirmer`/`Keyring`/`Biometric`).
//!
//! All policy and invariants (spec §2, §3) live here; the other faces (CLI,
//! wrapper, Web UI, MCP) are thin adapters over this crate.
//!
//! L1 provides the secret model, the coordinate URI parser, secret-bearing
//! value types, and AEAD encryption at rest. L2 adds storage on disk: the
//! partitioned per-secret vault store with atomic writes and a tolerant loader,
//! the `~/.vaults` registry with project→global override, the truncated
//! fingerprint, the master key behind a `Keyring` trait, and the rebuildable
//! redb metadata index (ADR-0001).

//! L3 adds the invariant-enforcement core (OS-independent half of I1–I16):
//! `AgentScope` (I13), the sensitivity decision (`policy::decide`), the
//! confirmation broker (`Confirmer`/`Biometric` + `CliApproveConfirmer`, I16),
//! `prod`-born-`high` (I5), and the append-only audit log (§11, I12) — plus the
//! `Clock` trait. Every face consumes these decisions; none re-derives them.

pub mod audit;
pub mod clock;
pub mod confirm;
pub mod coordinate;
pub mod crypto;
pub mod doctor;
pub mod env_source;
pub mod envrefs;
pub mod error;
pub mod exchange;
pub mod file_confirm;
pub mod fingerprint;
pub mod formatter;
pub mod hooks;
pub mod index;
pub mod keybackup;
pub mod keypair;
pub mod keyring;
pub mod package;
pub mod policy;
pub mod provider;
pub mod record;
pub mod registry;
pub mod resolver;
pub mod scaffold;
pub mod scope;
pub mod secret;
pub mod sensitivity;
pub mod store;
pub mod totp;

pub use audit::{
    AUDIT_LOG, AuditAction, AuditEvent, AuditQuery, AuditSink, FileAuditSink, MockAuditSink,
    outcome_result, query_log, read_log, render_log,
};
pub use clock::{Clock, MockClock, SystemClock};
pub use confirm::{
    Biometric, CliApproveConfirmer, ConfirmOutcome, ConfirmRequest, Confirmer, MockConfirmer,
    Untrusted,
};
pub use coordinate::{Coordinate, EnvSegment, KeyHalf, Scope};
pub use crypto::{KEY_LEN, NONCE_LEN, SealedRecord, open, open_bytes, seal, seal_bytes};
pub use doctor::{Finding, Report, Severity, check as doctor_check};
pub use env_source::{EnvSource, MockEnvSource, SystemEnvSource};
pub use envrefs::{EnvRefs, Source};
pub use error::CoreError;
pub use exchange::{
    BINARY_NAME, INSTALL_SCRIPT, PACKAGE_FILE, RECIPIENT_COORDINATE, RECIPIENT_PUB, UNPACK_SCRIPT,
    VOLUME_LABEL, mount_point, render_install_script, render_unpack_script, write_bootstrap,
};
pub use file_confirm::{FileConfirmer, PENDING_DIR, PendingRequest};
pub use fingerprint::{FINGERPRINT_BYTES, fingerprint};
pub use formatter::{
    DeviceInfo, Formatter, MockFormatter, assert_eraseable_target, eligible_targets,
    format_removable, wipe_headline,
};
pub use hooks::{HOOK_MARKER, Scanner, gitleaks_config, hook_script};
pub use index::{INDEX_FILE, Index, IndexEntry, RecordMode};
pub use keybackup::{BackupKind, export_backup, import_backup};
pub use keypair::{
    EnvSshAgent, GeneratedKeypair, KeyAlgorithm, MockSshAgent, RSA_BITS, SSH_AGENT_RSA_SHA2_256,
    SSH_AGENT_RSA_SHA2_512, SSH_SIG_NAMESPACE, SshAgent, decrypt, encrypt_to, generate,
    public_algorithm, public_from_private, public_key_blob, sign, sign_ssh_agent, verify,
    write_string,
};
pub use keyring::{Argon2Keyring, Keyring, MasterKey, MockKeyring, OsKeyring};
pub use package::{
    AccessToken, PACKAGE_MAGIC, PACKAGE_SCHEMA_VERSION, Package, PackagePayload, TokenConfirmer,
    enforce_no_prod_unattended, open_attended, open_unattended, seal as seal_package, verify_token,
};
pub use policy::{
    AccessRequest, Decision, DenyReason, PROD, birth_sensitivity, decide,
    delete_requires_confirmation, downgrade_requires_confirmation, inject_requires_allowlist,
    inject_requires_confirmation, is_downgrade, prod_blocks_unattended, prod_forbids_fallback,
    prod_not_packageable,
};
pub use provider::{
    MockProvider, SchemeRouter, SecretProvider, UnsupportedProvider, reference_scheme,
};
pub use record::{SCHEMA_VERSION, SecretRecord, Vault};
pub use registry::{Registry, Resolution, VaultOrigin};
pub use resolver::{Resolved, ResolvedVar, resolve};
pub use scaffold::{Lang, Proposal, coordinate_for, detect_in_source, render_env_refs, scan_repo};
pub use scope::{AgentScope, Filter, Operation, Origin, Surface};
pub use secret::SecretValue;
pub use sensitivity::Sensitivity;
pub use store::{LoadOutcome, Quarantined};
pub use totp::{
    DEFAULT_DIGITS, DEFAULT_PERIOD, ParsedEnrollment, TotpAlgorithm, TotpParams, code_at,
    decode_base32, parse_otpauth, parse_seed_input, returns_current, seconds_remaining,
};
