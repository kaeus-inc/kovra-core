//! The `.env.refs` project contract (spec §4.1/§4.2).
//!
//! Maps a local variable name to a **source** — a vault URI, an environment
//! passthrough, or a literal — plus an optional `project =` link. It holds
//! **no secret values**, only addresses, which is why it is committed to the
//! repo (the vault is not).
//!
//! This parser is **filename-agnostic**: it parses content, never a path. The
//! CLI/scaffold (L12) decides which file to read; the same grammar can back a
//! language-native "dotenv that resolves vault references" via the L9 binding.
//!
//! The only legal interpolation is `${ENV}` inside a URI path (substituted at
//! resolution, §4.3) and the `${env:NAME}` passthrough form. Any other `${…}`
//! — i.e. cross-variable interpolation — is rejected (§4.2): composing one
//! secret inside another string is the app's job, not the contract's, because
//! the composed string would get logged and nullify policy.

use crate::error::CoreError;

/// The source a variable resolves from (§4.1 line types 1–5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// A direct literal passthrough (`PORT=8080`).
    Literal(String),
    /// Read from the execution environment (`${env:NAME}`), with optional fallback.
    EnvPassthrough {
        /// The environment variable to read.
        var: String,
        /// Fallback applied when the variable is absent.
        fallback: Option<String>,
    },
    /// A vault coordinate URI (`secret:…`), with optional fallback.
    Uri {
        /// The `secret:` URI (may contain the `${ENV}` placeholder).
        uri: String,
        /// Fallback applied when the coordinate does not resolve.
        fallback: Option<String>,
    },
}

/// A parsed `.env.refs`: ordered variable bindings plus the optional project link.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EnvRefs {
    /// Variable bindings, in file order (resolution is a single ordered pass).
    pub vars: Vec<(String, Source)>,
    /// The `project = <name>` link (§4.1 line type 6), consumed by the Wrapper.
    pub project: Option<String>,
}

impl EnvRefs {
    /// Parse `.env.refs` content. Skips blank lines and `#` comments; errors on a
    /// malformed line, a bad identifier, a duplicate name, or any illegal
    /// (cross-variable) interpolation.
    pub fn parse(content: &str) -> Result<EnvRefs, CoreError> {
        let mut refs = EnvRefs::default();
        for (i, raw) in content.lines().enumerate() {
            let line = strip_comment(raw).trim();
            if line.is_empty() {
                continue;
            }
            let lineno = i + 1;
            let (key, rhs) = line
                .split_once('=')
                .ok_or_else(|| err(lineno, "expected `NAME=<source>` or `project = <name>`"))?;
            let key = key.trim();
            let rhs = rhs.trim();

            // The `project = <name>` metadata line (lowercase sentinel).
            if key == "project" {
                if refs.project.is_some() {
                    return Err(err(lineno, "duplicate `project =` line"));
                }
                if rhs.is_empty() {
                    return Err(err(lineno, "`project =` requires a name"));
                }
                refs.project = Some(rhs.to_string());
                continue;
            }

            if !is_identifier(key) {
                return Err(err(lineno, "variable name is not a valid identifier"));
            }
            if refs.vars.iter().any(|(n, _)| n == key) {
                return Err(err(lineno, "duplicate variable name"));
            }
            refs.vars.push((key.to_string(), classify(rhs, lineno)?));
        }
        Ok(refs)
    }
}

/// Classify a right-hand side into a [`Source`].
fn classify(rhs: &str, lineno: usize) -> Result<Source, CoreError> {
    if let Some(rest) = rhs.strip_prefix("secret:") {
        // URI (+ optional fallback). The URI keeps its `secret:` scheme; the
        // `${ENV}` placeholder is validated later by the coordinate parser.
        let (uri_tail, fallback) = split_fallback(rest);
        if let Some(fb) = &fallback {
            reject_interpolation(fb, lineno)?;
        }
        Ok(Source::Uri {
            uri: format!("secret:{uri_tail}"),
            fallback,
        })
    } else if let Some(inner) = strip_env_passthrough(rhs) {
        // ${env:VAR} or ${env:VAR | fallback}
        let (var, fallback) = split_fallback(inner);
        if !is_identifier(var) {
            return Err(err(lineno, "`${env:…}` requires a valid variable name"));
        }
        if let Some(fb) = &fallback {
            reject_interpolation(fb, lineno)?;
        }
        Ok(Source::EnvPassthrough {
            var: var.to_string(),
            fallback,
        })
    } else {
        // Literal — must not contain any interpolation (cross-variable footgun).
        reject_interpolation(rhs, lineno)?;
        Ok(Source::Literal(rhs.to_string()))
    }
}

/// Strip a trailing `# comment`. A `#` only starts a comment at the line start
/// or after whitespace, so `secret:dev/a#b` keeps the `#`.
fn strip_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'#' && (i == 0 || bytes[i - 1].is_ascii_whitespace()) {
            return &line[..i];
        }
    }
    line
}

/// Split `body [| fallback]` on the first ` | `-style pipe; trims both sides.
fn split_fallback(body: &str) -> (&str, Option<String>) {
    match body.split_once('|') {
        Some((left, right)) => (left.trim(), Some(right.trim().to_string())),
        None => (body.trim(), None),
    }
}

/// If `s` is exactly a `${env:…}` form, return its inner text.
fn strip_env_passthrough(s: &str) -> Option<&str> {
    s.strip_prefix("${env:")?.strip_suffix('}')
}

/// Reject any `${…}` interpolation in text that must be taken verbatim (§4.2).
fn reject_interpolation(text: &str, lineno: usize) -> Result<(), CoreError> {
    if text.contains("${") {
        return Err(err(
            lineno,
            "cross-variable interpolation is not allowed (only `${ENV}` in a URI path and `${env:NAME}` are valid)",
        ));
    }
    Ok(())
}

/// A valid env-var identifier: `[A-Za-z_][A-Za-z0-9_]*`.
fn is_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn err(lineno: usize, msg: &str) -> CoreError {
    CoreError::EnvRefs(format!("line {lineno}: {msg}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_line_types() {
        let src = "\
# a comment
DB_PASSWORD=secret:${ENV}/db/password
DB_HOST=secret:${ENV}/db/host | localhost
CI_TOKEN=${env:CI_TOKEN}
LOG_LEVEL=${env:LOG_LEVEL | info}
PORT=8080

project = billing
";
        let refs = EnvRefs::parse(src).unwrap();
        assert_eq!(refs.project.as_deref(), Some("billing"));
        assert_eq!(refs.vars.len(), 5);
        assert_eq!(
            refs.vars[0],
            (
                "DB_PASSWORD".to_string(),
                Source::Uri {
                    uri: "secret:${ENV}/db/password".to_string(),
                    fallback: None
                }
            )
        );
        assert_eq!(
            refs.vars[1],
            (
                "DB_HOST".to_string(),
                Source::Uri {
                    uri: "secret:${ENV}/db/host".to_string(),
                    fallback: Some("localhost".to_string())
                }
            )
        );
        assert_eq!(
            refs.vars[2],
            (
                "CI_TOKEN".to_string(),
                Source::EnvPassthrough {
                    var: "CI_TOKEN".to_string(),
                    fallback: None
                }
            )
        );
        assert_eq!(
            refs.vars[3],
            (
                "LOG_LEVEL".to_string(),
                Source::EnvPassthrough {
                    var: "LOG_LEVEL".to_string(),
                    fallback: Some("info".to_string())
                }
            )
        );
        assert_eq!(
            refs.vars[4],
            ("PORT".to_string(), Source::Literal("8080".to_string()))
        );
    }

    #[test]
    fn rejects_cross_variable_interpolation() {
        // a literal composing another variable
        assert!(matches!(
            EnvRefs::parse("DSN=postgres://user:${DB_PASSWORD}@h/db"),
            Err(CoreError::EnvRefs(_))
        ));
        // a fallback that interpolates
        assert!(matches!(
            EnvRefs::parse("X=secret:${ENV}/a/b | ${OTHER}"),
            Err(CoreError::EnvRefs(_))
        ));
    }

    #[test]
    fn rejects_bad_identifier_and_duplicates() {
        assert!(matches!(
            EnvRefs::parse("1BAD=8080"),
            Err(CoreError::EnvRefs(_))
        ));
        assert!(matches!(
            EnvRefs::parse("A=8080\nA=9090"),
            Err(CoreError::EnvRefs(_))
        ));
    }

    #[test]
    fn rejects_line_without_equals() {
        assert!(matches!(
            EnvRefs::parse("just-a-word"),
            Err(CoreError::EnvRefs(_))
        ));
    }

    #[test]
    fn comment_and_blank_lines_are_skipped() {
        let refs = EnvRefs::parse("\n  # hi\n\nPORT=8080  # trailing\n").unwrap();
        assert_eq!(
            refs.vars,
            vec![("PORT".to_string(), Source::Literal("8080".to_string()))]
        );
    }

    #[test]
    fn hash_inside_value_is_kept() {
        // `#` only starts a comment at line start or after whitespace.
        let refs = EnvRefs::parse("U=secret:dev/a/b#frag").unwrap();
        assert_eq!(
            refs.vars[0].1,
            Source::Uri {
                uri: "secret:dev/a/b#frag".to_string(),
                fallback: None
            }
        );
    }

    #[test]
    fn project_only_once() {
        assert!(matches!(
            EnvRefs::parse("project = a\nproject = b"),
            Err(CoreError::EnvRefs(_))
        ));
    }

    // ---- KOV-28 hardening: `.env.refs` parser fuzzing ----
    //
    // The `.env.refs` grammar previously had only example-based unit tests. These
    // proptest harnesses pin the structural guarantees against arbitrary input:
    // the parser never panics, and no cross-variable interpolation (§4.2) ever
    // survives into a parsed `Source`.
    mod fuzz {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            // Arbitrary single-line content never panics — a malformed line is a
            // `CoreError::EnvRefs`, never an unwind.
            #[test]
            fn parse_never_panics(content in ".*") {
                let _ = EnvRefs::parse(&content);
            }

            // Arbitrary multi-line content (the real input shape) never panics.
            #[test]
            fn parse_multiline_never_panics(
                lines in proptest::collection::vec(".*", 0..16)
            ) {
                let _ = EnvRefs::parse(&lines.join("\n"));
            }

            // §4.2: no cross-variable interpolation ever survives parsing. The
            // only legal `${…}` is the `${ENV}` placeholder inside a URI path; a
            // literal value or any fallback must be free of `${`.
            #[test]
            fn no_interpolation_survives_in_literal_or_fallback(
                name in "[A-Za-z_][A-Za-z0-9_]{0,12}",
                body in ".*",
            ) {
                // A `${` literal inside `prop_assert!` confuses its internal
                // format string; keeping the sigil in a variable avoids that.
                let sigil = "${";
                if let Ok(refs) = EnvRefs::parse(&format!("{name}={body}")) {
                    for (_, src) in &refs.vars {
                        match src {
                            Source::Literal(v) => prop_assert!(!v.contains(sigil)),
                            Source::EnvPassthrough { fallback, .. }
                            | Source::Uri { fallback, .. } => {
                                if let Some(fb) = fallback {
                                    prop_assert!(!fb.contains(sigil));
                                }
                            }
                        }
                    }
                }
            }

            // A plain `NAME=value` literal (no scheme prefix, no interpolation,
            // no comment/fallback metacharacters) always parses and preserves the
            // value verbatim.
            #[test]
            fn well_formed_literal_round_trips(
                name in "[A-Za-z_][A-Za-z0-9_]{0,12}",
                value in "[A-Za-z0-9_./:-]{1,20}",
            ) {
                // exclude the `secret:` prefix, which would (correctly) classify
                // as a URI rather than a literal.
                prop_assume!(!value.starts_with("secret:"));
                let refs = EnvRefs::parse(&format!("{name}={value}")).unwrap();
                prop_assert_eq!(&refs.vars, &vec![(name, Source::Literal(value))]);
            }

            // A duplicate variable name is always rejected, whatever the values.
            #[test]
            fn duplicate_names_always_error(name in "[A-Za-z_][A-Za-z0-9_]{0,8}") {
                let content = format!("{name}=1\n{name}=2");
                prop_assert!(EnvRefs::parse(&content).is_err());
            }

            // A leading-digit identifier is never a valid variable name.
            #[test]
            fn bad_identifier_always_errors(
                bad in "[0-9][A-Za-z0-9_]{0,8}",
                value in "[a-z]{1,8}",
            ) {
                let line = format!("{bad}={value}");
                prop_assert!(EnvRefs::parse(&line).is_err());
            }
        }
    }
}
