//! `kovra doctor` / `lint` — validate a project's secret configuration (L12).
//!
//! Diagnoses the most common dev friction — a misconfigured secret contract —
//! using **coordinates and resolution status only**. It never materializes or
//! reveals a value (I11/I12): findings carry coordinates and a status, never
//! secret bytes. Four check classes (spec §13):
//!
//! 1. **resolution** — every `.env.refs` `secret:` URI resolves in the vault
//!    (via the §1.1 override table); an unresolved coordinate with no fallback
//!    is an error.
//! 2. **orphans** — vault entries (for the checked environment) that no
//!    `.env.refs` line references — a warning (dead custody or a missing line).
//! 3. **prod fallback** — a `prod` coordinate carrying a `| fallback` is a hard
//!    error (I4c / [`crate::prod_forbids_fallback`]): prod must never silently
//!    fall back to a non-custodied value.
//! 4. **references** — a coordinate that resolves to an external reference
//!    (`azure-kv://…`) is reported as a reference with its scheme; offline, its
//!    remote accessibility is not probed (it degrades gracefully without a
//!    provider — status only, never the value).

use std::collections::BTreeSet;
use std::str::FromStr;

use crate::coordinate::Coordinate;
use crate::crypto::KEY_LEN;
use crate::envrefs::{EnvRefs, Source};
use crate::error::CoreError;
use crate::policy::prod_forbids_fallback;
use crate::registry::{Registry, Resolution};
use crate::store;

/// How serious a [`Finding`] is. Only [`Severity::Error`] fails the command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// A hard problem — `doctor` exits non-zero.
    Error,
    /// Worth attention but not fatal (e.g. an orphan, a used fallback).
    Warning,
    /// Informational (e.g. a reference whose remote access wasn't probed).
    Info,
}

impl Severity {
    /// A short uppercase tag for rendering (`ERROR` / `WARN` / `INFO`).
    pub fn tag(&self) -> &'static str {
        match self {
            Severity::Error => "ERROR",
            Severity::Warning => "WARN",
            Severity::Info => "INFO",
        }
    }
}

/// A single diagnostic. Carries a coordinate (an address, never a value) and a
/// human message — never any secret bytes (I11/I12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Severity — only [`Severity::Error`] is fatal.
    pub severity: Severity,
    /// The coordinate or `.env.refs` variable the finding is about, if any.
    pub coordinate: Option<String>,
    /// The diagnostic message (value-free).
    pub message: String,
}

/// The outcome of a `doctor` run: an ordered list of findings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Findings in check order.
    pub findings: Vec<Finding>,
}

impl Report {
    fn push(&mut self, severity: Severity, coordinate: Option<String>, message: impl Into<String>) {
        self.findings.push(Finding {
            severity,
            coordinate,
            message: message.into(),
        });
    }

    /// Whether any finding is an [`Severity::Error`] — the command's exit gate.
    pub fn has_errors(&self) -> bool {
        self.findings.iter().any(|f| f.severity == Severity::Error)
    }

    /// Count of findings at a given severity.
    pub fn count(&self, severity: Severity) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == severity)
            .count()
    }
}

/// Run all checks against `refs` resolved for `env`, over `registry` with an
/// already-materialized master `key`. `project` is the resolved project vault
/// (the `--project` override or the `.env.refs` `project =` line), if any.
///
/// Pure of value materialization: it resolves coordinates to **records** (to
/// read modality + existence) but never unseals or returns a value.
pub fn check(
    refs: &EnvRefs,
    env: &str,
    registry: &Registry,
    key: &[u8; KEY_LEN],
    project: Option<&str>,
) -> Result<Report, CoreError> {
    let mut report = Report::default();
    let mut referenced: BTreeSet<String> = BTreeSet::new();

    for (name, source) in &refs.vars {
        let Source::Uri { uri, fallback } = source else {
            continue; // literals / env-passthroughs are not vault coordinates
        };

        let coord = match Coordinate::from_str(uri) {
            Ok(c) => c.with_env(env),
            Err(e) => {
                report.push(
                    Severity::Error,
                    Some(uri.clone()),
                    format!("`{name}`: malformed coordinate — {e}"),
                );
                continue;
            }
        };
        // `with_env` made the environment a literal, so `canonical_path` cannot
        // hit its placeholder error; the env is the first canonical segment.
        let canonical = coord
            .canonical_path()
            .expect("with_env replaced the ${ENV} placeholder");
        let effective_env = canonical.split('/').next().unwrap_or(env);

        // Check 3 — prod must never carry a fallback (hard error, I4c).
        if prod_forbids_fallback(effective_env) && fallback.is_some() {
            report.push(
                Severity::Error,
                Some(canonical.clone()),
                format!("`{name}`: a `prod` coordinate must not have a `| fallback` (I4c)"),
            );
        }

        // Check 1 — resolution status (never the value).
        match registry.resolve_with_key(&coord, project, key)? {
            Resolution::Found { record, .. } => {
                referenced.insert(canonical.clone());
                // Check 4 — a reference resolves but is not probed offline.
                if let Some(reference) = record.reference() {
                    let scheme = crate::reference_scheme(reference).unwrap_or("?");
                    report.push(
                        Severity::Info,
                        Some(canonical.clone()),
                        format!(
                            "`{name}`: resolves to a `{scheme}` reference; \
                             remote accessibility not probed offline"
                        ),
                    );
                }
            }
            Resolution::NotFound => {
                if fallback.is_some() {
                    report.push(
                        Severity::Warning,
                        Some(canonical.clone()),
                        format!("`{name}`: coordinate does not resolve, but a fallback is set"),
                    );
                } else {
                    report.push(
                        Severity::Error,
                        Some(canonical.clone()),
                        format!("`{name}`: coordinate does not resolve and has no fallback"),
                    );
                }
            }
        }
    }

    // Check 2 — orphans: vault entries (for this env) that nothing references.
    for record in vault_records(registry, key, project)? {
        if record.environment() != env {
            continue; // only compare within the environment being checked
        }
        let path = record.canonical_path();
        if !referenced.contains(&path) {
            report.push(
                Severity::Warning,
                Some(path),
                "orphan secret: in the vault for this env but not referenced by `.env.refs`",
            );
        }
    }

    Ok(report)
}

/// Load every record from the global vault plus the resolved project vault (if
/// any). Reads records (modality/coordinate), never returns a value.
fn vault_records(
    registry: &Registry,
    key: &[u8; KEY_LEN],
    project: Option<&str>,
) -> Result<Vec<crate::record::SecretRecord>, CoreError> {
    let mut out = Vec::new();
    out.extend(
        store::load_all(&registry.global_dir(), key)?
            .records
            .into_iter()
            .map(|(_, r)| r),
    );
    if let Some(name) = project {
        let dir = registry.project_dir(name);
        if dir.exists() {
            out.extend(
                store::load_all(&dir, key)?
                    .records
                    .into_iter()
                    .map(|(_, r)| r),
            );
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::SecretRecord;
    use crate::sensitivity::Sensitivity;
    use crate::{Coordinate, SecretValue, crypto::KEY_LEN, seal};

    const KEY: [u8; KEY_LEN] = [7u8; KEY_LEN];

    fn registry_with(records: &[SecretRecord]) -> (tempfile::TempDir, Registry) {
        let tmp = tempfile::tempdir().unwrap();
        let registry = Registry::open(tmp.path()).unwrap();
        for rec in records {
            let coord = Coordinate::from_str(&format!("secret:{}", rec.canonical_path())).unwrap();
            store::write_record(&registry.global_dir(), &coord, &seal(rec, &KEY).unwrap()).unwrap();
        }
        (tmp, registry)
    }

    fn literal(env: &str, component: &str, key: &str, sens: Sensitivity) -> SecretRecord {
        SecretRecord::Literal {
            value: SecretValue::new(b"x".to_vec()),
            sensitivity: sens,
            revealable: false,
            environment: env.to_string(),
            component: component.to_string(),
            key: key.to_string(),
            description: None,
            created: "t".to_string(),
            updated: "t".to_string(),
        }
    }

    fn reference(env: &str, component: &str, key: &str) -> SecretRecord {
        SecretRecord::Reference {
            reference: "azure-kv://corp-kv/db-url".to_string(),
            sensitivity: Sensitivity::High,
            revealable: false,
            environment: env.to_string(),
            component: component.to_string(),
            key: key.to_string(),
            description: None,
            created: "t".to_string(),
            updated: "t".to_string(),
        }
    }

    #[test]
    fn clean_config_has_no_errors() {
        let (_tmp, reg) = registry_with(&[literal("dev", "db", "password", Sensitivity::Medium)]);
        let refs = EnvRefs::parse("DB=secret:${ENV}/db/password").unwrap();
        let report = check(&refs, "dev", &reg, &KEY, None).unwrap();
        assert!(!report.has_errors(), "clean config: {:?}", report.findings);
    }

    #[test]
    fn unresolved_coordinate_without_fallback_is_error() {
        let (_tmp, reg) = registry_with(&[]);
        let refs = EnvRefs::parse("DB=secret:${ENV}/db/password").unwrap();
        let report = check(&refs, "dev", &reg, &KEY, None).unwrap();
        assert!(report.has_errors());
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("does not resolve"))
        );
    }

    #[test]
    fn unresolved_with_fallback_is_only_a_warning() {
        let (_tmp, reg) = registry_with(&[]);
        let refs = EnvRefs::parse("DB=secret:${ENV}/db/password | localhost").unwrap();
        let report = check(&refs, "dev", &reg, &KEY, None).unwrap();
        assert!(!report.has_errors());
        assert_eq!(report.count(Severity::Warning), 1);
    }

    #[test]
    fn prod_with_fallback_is_a_hard_error() {
        let (_tmp, reg) = registry_with(&[literal("prod", "db", "password", Sensitivity::High)]);
        let refs = EnvRefs::parse("DB=secret:prod/db/password | localhost").unwrap();
        let report = check(&refs, "prod", &reg, &KEY, None).unwrap();
        assert!(report.has_errors());
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("must not have a `| fallback`"))
        );
    }

    #[test]
    fn orphan_vault_entry_is_flagged() {
        let (_tmp, reg) = registry_with(&[
            literal("dev", "db", "password", Sensitivity::Medium),
            literal("dev", "app", "unused", Sensitivity::Medium),
        ]);
        let refs = EnvRefs::parse("DB=secret:${ENV}/db/password").unwrap();
        let report = check(&refs, "dev", &reg, &KEY, None).unwrap();
        assert!(!report.has_errors(), "orphan is a warning, not an error");
        assert!(
            report.findings.iter().any(|f| {
                f.severity == Severity::Warning && f.coordinate.as_deref() == Some("dev/app/unused")
            }),
            "the unused vault entry must be flagged as an orphan: {:?}",
            report.findings
        );
    }

    #[test]
    fn reference_is_reported_as_info_not_value() {
        let (_tmp, reg) = registry_with(&[reference("dev", "db", "url")]);
        let refs = EnvRefs::parse("DB=secret:${ENV}/db/url").unwrap();
        let report = check(&refs, "dev", &reg, &KEY, None).unwrap();
        assert!(!report.has_errors());
        let info = report
            .findings
            .iter()
            .find(|f| f.severity == Severity::Info)
            .expect("a reference yields an INFO finding");
        assert!(info.message.contains("azure-kv"));
        // No finding ever contains the reference's would-be value.
        let blob = format!("{:?}", report.findings);
        assert!(!blob.contains("db-url-value"));
    }

    #[test]
    fn malformed_coordinate_is_an_error() {
        let (_tmp, reg) = registry_with(&[]);
        let refs = EnvRefs::parse("DB=secret:${ENV}/db/password").unwrap();
        // Hand-craft a refs with a bad URI by bypassing parse (two segments).
        let mut bad = refs.clone();
        bad.vars = vec![(
            "DB".to_string(),
            Source::Uri {
                uri: "secret:dev/onlytwo".to_string(),
                fallback: None,
            },
        )];
        let report = check(&bad, "dev", &reg, &KEY, None).unwrap();
        assert!(report.has_errors());
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("malformed coordinate"))
        );
    }
}
