//! The secret coordinate URI: a three-segment address (spec §1.2, §4.2).
//!
//! Grammar (this layer parses only the `secret:` coordinate, **not** the
//! `.env.refs` grammar — that is L4):
//!
//! ```text
//! secret:<env>/<component>/<key>
//! secret://global/<env>/<component>/<key>   # scope selector: ignore project override
//! secret:<env>/<component>/<key>#public     # keypair half selector (KOV-12)
//! secret:<env>/<component>/<key>#private     #   "
//! ```
//!
//! - Always exactly three path segments; no short form (removes env-vs-component
//!   ambiguity).
//! - The only interpolation allowed is `${ENV}` in the **environment** segment,
//!   substituted with the `--env` value at run time (L4). `${COMPONENT}` and any
//!   other `${...}` are rejected here, never silently passed through.
//! - An optional trailing `#public` / `#private` **fragment** (KOV-12) selects
//!   which half of a keypair to act on. It is meaningful only for the `Keypair`
//!   modality (injecting/using a key); a literal/reference ignores it. The
//!   fragment is part of the *resolution* request, not the stored address, so it
//!   does not change the storage id (a coordinate and its `#half` forms file
//!   under the same record).

use core::fmt;
use core::str::FromStr;

use crate::error::CoreError;

/// Scope selector: whether the project vault may override the global vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Project vault overrides global at the exact coordinate (spec §1.1).
    Default,
    /// `secret://global/...` — resolve only against the global vault.
    Global,
}

/// Which half of a keypair a coordinate refers to (KOV-12). Only meaningful for
/// the `Keypair` modality; for a literal/reference it is always [`KeyHalf::Unspecified`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyHalf {
    /// No `#public`/`#private` fragment given. For a keypair, resolution
    /// defaults to the **public** half (the safe, non-secret default); a face
    /// that needs the private half must ask for it explicitly.
    #[default]
    Unspecified,
    /// `#public` — the public key (free, non-secret; a `Metadata`-class op).
    Public,
    /// `#private` — the private key (a private-key op: routed as `Inject`,
    /// broker-gated for high/prod, never returned to the caller's context).
    Private,
}

/// The environment segment: a fixed literal or the `${ENV}` placeholder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvSegment {
    /// A fixed environment, e.g. `prod`.
    Literal(String),
    /// `${ENV}` — resolved from `--env` at run time (L4).
    Placeholder,
}

impl fmt::Display for EnvSegment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnvSegment::Literal(s) => f.write_str(s),
            EnvSegment::Placeholder => f.write_str("${ENV}"),
        }
    }
}

/// A parsed, canonical secret coordinate. Carries only the address — never a
/// value (I6: the command line carries the coordinate, the value enters
/// separately as a [`crate::SecretValue`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coordinate {
    /// Override scope.
    pub scope: Scope,
    /// Environment segment (literal or `${ENV}`).
    pub environment: EnvSegment,
    /// Component segment.
    pub component: String,
    /// Key segment.
    pub key: String,
    /// Keypair half selector (`#public`/`#private`). [`KeyHalf::Unspecified`]
    /// for a plain coordinate; meaningful only for the `Keypair` modality.
    pub half: KeyHalf,
}

impl Coordinate {
    /// The canonical storage path `<env>/<component>/<key>` — the address a
    /// secret is filed under on disk. The scope selector is a *resolution*
    /// concern (which vault to read), never stored, so it is excluded here:
    /// `secret:prod/db/pw` and `secret://global/prod/db/pw` map to the same
    /// path in whichever vault is chosen.
    ///
    /// Fails for an unresolved `${ENV}` placeholder — placeholders are
    /// substituted at resolution time (L4); only concrete coordinates are
    /// storable.
    pub fn canonical_path(&self) -> Result<String, CoreError> {
        match &self.environment {
            EnvSegment::Literal(env) => Ok(format!("{}/{}/{}", env, self.component, self.key)),
            EnvSegment::Placeholder => Err(CoreError::NotStorable(
                "coordinate has an unresolved `${ENV}` placeholder".to_string(),
            )),
        }
    }

    /// Substitute the `${ENV}` placeholder with a concrete environment, for
    /// resolution at launch (spec §4.2/§4.3). A coordinate whose environment is
    /// already literal is returned unchanged; only the `Placeholder` is replaced.
    pub fn with_env(&self, env: &str) -> Coordinate {
        match &self.environment {
            EnvSegment::Placeholder => Coordinate {
                scope: self.scope,
                environment: EnvSegment::Literal(env.to_string()),
                component: self.component.clone(),
                key: self.key.clone(),
                half: self.half,
            },
            EnvSegment::Literal(_) => self.clone(),
        }
    }

    /// The opaque on-disk record id: lowercase-hex `BLAKE3(canonical_path)`
    /// (ADR-0001 §A.1). Hashing the coordinate keeps the address off disk as a
    /// filename while giving an O(1) point lookup. Inherits the placeholder
    /// rejection from [`Coordinate::canonical_path`].
    pub fn storage_id(&self) -> Result<String, CoreError> {
        Ok(blake3::hash(self.canonical_path()?.as_bytes())
            .to_hex()
            .to_string())
    }
}

impl FromStr for Coordinate {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let invalid = |msg: &str| CoreError::InvalidCoordinate(msg.to_string());

        let rest = s
            .strip_prefix("secret:")
            .ok_or_else(|| invalid("must start with `secret:`"))?;

        // Split off an optional `#public`/`#private` keypair half selector
        // (KOV-12) before parsing the path. Only those two fragments are valid.
        let (rest, half) = match rest.split_once('#') {
            Some((before, "public")) => (before, KeyHalf::Public),
            Some((before, "private")) => (before, KeyHalf::Private),
            Some((_, other)) => {
                return Err(invalid(&format!(
                    "unknown coordinate fragment `#{other}` (only `#public`/`#private` are valid)"
                )));
            }
            None => (rest, KeyHalf::Unspecified),
        };

        let (scope, path) = match rest.strip_prefix("//") {
            Some(authority_and_path) => {
                let (authority, path) = authority_and_path
                    .split_once('/')
                    .ok_or_else(|| invalid("scope form requires `//<authority>/<path>`"))?;
                if authority != "global" {
                    return Err(invalid("only `//global/` scope selector is supported"));
                }
                (Scope::Global, path)
            }
            None => (Scope::Default, rest),
        };

        let segments: Vec<&str> = path.split('/').collect();
        if segments.len() != 3 {
            return Err(invalid("coordinate must have exactly three segments"));
        }
        if segments.iter().any(|seg| seg.is_empty()) {
            return Err(invalid("segments must be non-empty"));
        }

        let environment = parse_env_segment(segments[0])?;
        let component = parse_plain_segment(segments[1], "component")?;
        let key = parse_plain_segment(segments[2], "key")?;

        Ok(Coordinate {
            scope,
            environment,
            component,
            key,
            half,
        })
    }
}

/// The environment segment is either exactly `${ENV}` or a literal with no
/// interpolation. Any other `${...}` is rejected.
fn parse_env_segment(seg: &str) -> Result<EnvSegment, CoreError> {
    if seg == "${ENV}" {
        return Ok(EnvSegment::Placeholder);
    }
    if seg.contains("${") {
        return Err(CoreError::InvalidCoordinate(
            "only `${ENV}` interpolation is allowed in the environment segment".to_string(),
        ));
    }
    Ok(EnvSegment::Literal(seg.to_string()))
}

/// Component and key segments admit no interpolation at all (only `${ENV}`
/// interpolates, and only in the environment segment).
fn parse_plain_segment(seg: &str, what: &str) -> Result<String, CoreError> {
    if seg.contains("${") {
        return Err(CoreError::InvalidCoordinate(format!(
            "interpolation is not allowed in the {what} segment"
        )));
    }
    Ok(seg.to_string())
}

impl fmt::Display for Coordinate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.scope {
            Scope::Default => write!(
                f,
                "secret:{}/{}/{}",
                self.environment, self.component, self.key
            )?,
            Scope::Global => write!(
                f,
                "secret://global/{}/{}/{}",
                self.environment, self.component, self.key
            )?,
        }
        match self.half {
            KeyHalf::Unspecified => Ok(()),
            KeyHalf::Public => f.write_str("#public"),
            KeyHalf::Private => f.write_str("#private"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn parses_literal_three_segments() {
        let c: Coordinate = "secret:prod/db/password".parse().unwrap();
        assert_eq!(c.scope, Scope::Default);
        assert_eq!(c.environment, EnvSegment::Literal("prod".to_string()));
        assert_eq!(c.component, "db");
        assert_eq!(c.key, "password");
    }

    #[test]
    fn parses_env_placeholder() {
        let c: Coordinate = "secret:${ENV}/db/password".parse().unwrap();
        assert_eq!(c.environment, EnvSegment::Placeholder);
    }

    #[test]
    fn parses_global_scope_selector() {
        let c: Coordinate = "secret://global/prod/db/password".parse().unwrap();
        assert_eq!(c.scope, Scope::Global);
        assert_eq!(c.environment, EnvSegment::Literal("prod".to_string()));
        assert_eq!(c.key, "password");
    }

    #[test]
    fn rejects_two_segments() {
        assert!("secret:prod/db".parse::<Coordinate>().is_err());
    }

    #[test]
    fn rejects_four_segments() {
        assert!(
            "secret:prod/db/password/extra"
                .parse::<Coordinate>()
                .is_err()
        );
    }

    #[test]
    fn rejects_missing_scheme() {
        assert!("prod/db/password".parse::<Coordinate>().is_err());
    }

    #[test]
    fn rejects_empty_segment() {
        assert!("secret:prod//password".parse::<Coordinate>().is_err());
    }

    #[test]
    fn rejects_non_env_interpolation() {
        assert!("secret:${FOO}/db/password".parse::<Coordinate>().is_err());
        assert!(
            "secret:prod/${COMPONENT}/password"
                .parse::<Coordinate>()
                .is_err()
        );
        assert!("secret:prod/db/${KEY}".parse::<Coordinate>().is_err());
    }

    #[test]
    fn storage_id_ignores_scope() {
        // Default and global scope of the same address file under the same id;
        // scope only chooses which vault to read.
        let default: Coordinate = "secret:prod/db/password".parse().unwrap();
        let global: Coordinate = "secret://global/prod/db/password".parse().unwrap();
        assert_eq!(default.canonical_path().unwrap(), "prod/db/password");
        assert_eq!(default.storage_id().unwrap(), global.storage_id().unwrap());
    }

    #[test]
    fn storage_id_is_blake3_hex_of_path() {
        let c: Coordinate = "secret:prod/db/password".parse().unwrap();
        let expected = blake3::hash(b"prod/db/password").to_hex().to_string();
        assert_eq!(c.storage_id().unwrap(), expected);
    }

    #[test]
    fn with_env_substitutes_placeholder_only() {
        let ph: Coordinate = "secret:${ENV}/db/password".parse().unwrap();
        let resolved = ph.with_env("prod");
        assert_eq!(
            resolved.environment,
            EnvSegment::Literal("prod".to_string())
        );
        assert_eq!(resolved.canonical_path().unwrap(), "prod/db/password");

        // A literal env is unchanged by with_env.
        let lit: Coordinate = "secret:dev/db/password".parse().unwrap();
        assert_eq!(lit.with_env("prod"), lit);
    }

    #[test]
    fn placeholder_is_not_storable() {
        let c: Coordinate = "secret:${ENV}/db/password".parse().unwrap();
        assert!(matches!(c.canonical_path(), Err(CoreError::NotStorable(_))));
        assert!(matches!(c.storage_id(), Err(CoreError::NotStorable(_))));
    }

    #[test]
    fn parses_keypair_half_selector() {
        let pubc: Coordinate = "secret:dev/ssh/deploy#public".parse().unwrap();
        assert_eq!(pubc.half, KeyHalf::Public);
        assert_eq!(pubc.key, "deploy");
        let privc: Coordinate = "secret:dev/ssh/deploy#private".parse().unwrap();
        assert_eq!(privc.half, KeyHalf::Private);
        // a plain coordinate has no half selector
        let plain: Coordinate = "secret:dev/ssh/deploy".parse().unwrap();
        assert_eq!(plain.half, KeyHalf::Unspecified);
    }

    #[test]
    fn half_selector_does_not_change_storage_id() {
        // A coordinate and its #public/#private forms file under the same record:
        // the half is a resolution concern, not part of the stored address.
        let plain: Coordinate = "secret:dev/ssh/deploy".parse().unwrap();
        let pubc: Coordinate = "secret:dev/ssh/deploy#public".parse().unwrap();
        let privc: Coordinate = "secret:dev/ssh/deploy#private".parse().unwrap();
        assert_eq!(plain.storage_id().unwrap(), pubc.storage_id().unwrap());
        assert_eq!(plain.storage_id().unwrap(), privc.storage_id().unwrap());
    }

    #[test]
    fn half_selector_round_trips_through_display() {
        for uri in [
            "secret:dev/ssh/deploy#public",
            "secret:dev/ssh/deploy#private",
            "secret://global/dev/ssh/deploy#private",
        ] {
            let c: Coordinate = uri.parse().unwrap();
            assert_eq!(c.to_string(), uri);
            assert_eq!(c.to_string().parse::<Coordinate>().unwrap(), c);
        }
    }

    #[test]
    fn rejects_unknown_fragment() {
        assert!("secret:dev/ssh/deploy#frag".parse::<Coordinate>().is_err());
        assert!("secret:dev/a/b#".parse::<Coordinate>().is_err());
    }

    #[test]
    fn rejects_unknown_scope_authority() {
        assert!(
            "secret://local/prod/db/password"
                .parse::<Coordinate>()
                .is_err()
        );
    }

    #[test]
    fn display_round_trips() {
        for uri in [
            "secret:prod/db/password",
            "secret:${ENV}/db/password",
            "secret://global/prod/db/password",
        ] {
            let c: Coordinate = uri.parse().unwrap();
            assert_eq!(c.to_string(), uri);
            // and re-parsing the rendered form yields the same coordinate
            assert_eq!(c.to_string().parse::<Coordinate>().unwrap(), c);
        }
    }

    proptest! {
        // A parse never panics, and any accepted coordinate round-trips through
        // Display -> parse. Malformed input must error, never silently resolve.
        #[test]
        fn parse_never_panics_and_round_trips(s in ".*") {
            if let Ok(c) = s.parse::<Coordinate>() {
                prop_assert_eq!(c.to_string().parse::<Coordinate>().unwrap(), c);
            }
        }

        // Well-formed literal coordinates (no slashes / `${` in segments) always parse.
        #[test]
        fn well_formed_literals_parse(
            env in "[a-z][a-z0-9_-]{0,12}",
            comp in "[a-z][a-z0-9_-]{0,12}",
            key in "[a-z][a-z0-9_-]{0,12}",
        ) {
            let uri = format!("secret:{env}/{comp}/{key}");
            let c = uri.parse::<Coordinate>().unwrap();
            prop_assert_eq!(c.environment, EnvSegment::Literal(env));
            prop_assert_eq!(c.component, comp);
            prop_assert_eq!(c.key, key);
        }
    }

    // ---- KOV-28 hardening: structured near-miss fuzzing ----
    //
    // `parse_never_panics_and_round_trips` above uses `.*`, which rarely lands on
    // the `secret:`/`//`/`#`/`${ENV}` boundaries where parser bugs hide. These
    // generators concatenate "interesting" tokens so coverage concentrates right
    // on those boundaries (scheme, scope authority, keypair fragment, segment
    // separators, the interpolation sigil, and embedded control/unicode bytes).

    /// Tokens that have historically tripped URI-like grammars.
    fn near_miss_token() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("secret:".to_string()),
            Just("//".to_string()),
            Just("global".to_string()),
            Just("/".to_string()),
            Just("#".to_string()),
            Just("#public".to_string()),
            Just("#private".to_string()),
            Just("${ENV}".to_string()),
            Just("${FOO}".to_string()),
            Just("${".to_string()),
            Just("\0".to_string()),
            Just("\n".to_string()),
            Just("é".to_string()),
            "[a-z0-9_-]{0,6}",
        ]
    }

    proptest! {
        // Assembled near-miss inputs never panic the parser; any accepted
        // coordinate still round-trips through Display -> parse. Malformed input
        // errors, never silently resolves to a (wrong) coordinate.
        #[test]
        fn near_miss_never_panics_and_round_trips(
            toks in proptest::collection::vec(near_miss_token(), 0..8)
        ) {
            let s = toks.concat();
            if let Ok(c) = s.parse::<Coordinate>() {
                prop_assert_eq!(c.to_string().parse::<Coordinate>().unwrap(), c);
            }
        }

        // `${...}` interpolation is legal ONLY as exactly `${ENV}` in the
        // environment segment. The same sigil in the component or key segment —
        // even `${ENV}` itself — is always rejected, never passed through to
        // storage (the §4.2 cross-interpolation footgun).
        #[test]
        fn interpolation_outside_env_segment_is_rejected(
            env in "[a-z][a-z0-9_-]{0,8}",
            comp in "[a-z][a-z0-9_-]{0,8}",
            key in "[a-z][a-z0-9_-]{0,8}",
            inject in prop_oneof![Just("${X}"), Just("${ENV}"), Just("${COMPONENT}")],
        ) {
            // poison the component segment
            let poisoned_comp = format!("secret:{env}/{comp}{inject}/{key}");
            prop_assert!(poisoned_comp.parse::<Coordinate>().is_err());
            // poison the key segment
            let poisoned_key = format!("secret:{env}/{comp}/{key}{inject}");
            prop_assert!(poisoned_key.parse::<Coordinate>().is_err());
        }

        // A `${ENV}` placeholder coordinate is never storable: both
        // `canonical_path` and `storage_id` error, so an on-disk id can never be
        // derived from an unresolved placeholder (it must be resolved first, L4).
        #[test]
        fn placeholder_never_yields_storage_id(
            comp in "[a-z][a-z0-9_-]{0,8}",
            key in "[a-z][a-z0-9_-]{0,8}",
        ) {
            let c: Coordinate = format!("secret:${{ENV}}/{comp}/{key}").parse().unwrap();
            prop_assert!(matches!(c.canonical_path(), Err(CoreError::NotStorable(_))));
            prop_assert!(matches!(c.storage_id(), Err(CoreError::NotStorable(_))));
        }
    }
}
