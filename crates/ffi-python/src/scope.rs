//! Translate a Python session-scope description into an [`AgentScope`].
//!
//! The session's scope is fixed at construction and never widened by the model
//! (I13). [`build_scope`] is the pure core (unit-tested without an interpreter);
//! [`scope_from_dict`] is the thin pyo3 adapter the `KovraSession` constructor
//! calls.

use kovra_core::{AgentScope, Filter, Operation};
use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::errors::FfiError;

/// Build an [`AgentScope`] from string operation names and optional
/// project/environment allowlists. `None` for a filter means "any" (`*`).
///
/// Operation names: `metadata`, `inject`, `reveal` (case-insensitive). An
/// unknown name is a configuration error — the scope is never silently widened.
pub fn build_scope(
    operations: &[String],
    projects: Option<Vec<String>>,
    environments: Option<Vec<String>>,
) -> Result<AgentScope, FfiError> {
    let mut ops = std::collections::BTreeSet::new();
    for name in operations {
        let op = match name.to_ascii_lowercase().as_str() {
            "metadata" => Operation::Metadata,
            "inject" => Operation::Inject,
            "reveal" => Operation::Reveal,
            other => {
                return Err(FfiError::Config(format!(
                    "unknown scope operation `{other}` (expected metadata|inject|reveal)"
                )));
            }
        };
        ops.insert(op);
    }
    Ok(AgentScope {
        operations: ops,
        projects: to_filter(projects),
        environments: to_filter(environments),
    })
}

/// `None` (or the wildcard sentinel) → [`Filter::Any`]; a list → [`Filter::only`].
fn to_filter(values: Option<Vec<String>>) -> Filter {
    match values {
        None => Filter::Any,
        Some(list) if list.iter().any(|v| v == "*") => Filter::Any,
        Some(list) => Filter::only(list),
    }
}

/// Parse the `scope` dict passed to `KovraSession(...)`. Shape:
/// `{"operations": ["metadata", ...], "projects": None|"*"|[...], "environments": None|"*"|[...]}`.
pub fn scope_from_dict(dict: &Bound<'_, PyDict>) -> PyResult<AgentScope> {
    let operations: Vec<String> = match dict.get_item("operations")? {
        Some(v) => v.extract()?,
        None => {
            return Err(
                FfiError::Config("scope must include an `operations` list".to_string()).into(),
            );
        }
    };
    let projects = extract_filter(dict, "projects")?;
    let environments = extract_filter(dict, "environments")?;
    Ok(build_scope(&operations, projects, environments)?)
}

/// Extract an optional axis filter: missing/`None` → `None` (any); a string `"*"`
/// → `None` (any); a list → `Some(list)`.
fn extract_filter(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<Vec<String>>> {
    match dict.get_item(key)? {
        None => Ok(None),
        Some(v) if v.is_none() => Ok(None),
        Some(v) => {
            if let Ok(s) = v.extract::<String>() {
                if s == "*" {
                    Ok(None)
                } else {
                    Ok(Some(vec![s]))
                }
            } else {
                Ok(Some(v.extract::<Vec<String>>()?))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_operation_set_case_insensitively() {
        let s = build_scope(
            &["Metadata".into(), "REVEAL".into()],
            None,
            Some(vec!["dev".into(), "test".into()]),
        )
        .unwrap();
        assert!(s.permits(Operation::Metadata));
        assert!(s.permits(Operation::Reveal));
        assert!(!s.permits(Operation::Inject));
        assert_eq!(s.projects, Filter::Any);
        assert_eq!(s.environments, Filter::only(["dev", "test"]));
    }

    #[test]
    fn unknown_operation_is_rejected_not_ignored() {
        let err = build_scope(&["sudo".into()], None, None).unwrap_err();
        assert!(matches!(err, FfiError::Config(_)));
    }

    #[test]
    fn wildcard_and_none_both_mean_any() {
        let a = build_scope(&["metadata".into()], Some(vec!["*".into()]), None).unwrap();
        assert_eq!(a.projects, Filter::Any);
        let b = build_scope(&["metadata".into()], None, None).unwrap();
        assert_eq!(b.environments, Filter::Any);
    }
}
