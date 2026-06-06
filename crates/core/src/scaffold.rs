//! `kovra scaffold` — repo scan → proposed `.env.refs` (spec §13, L12).
//!
//! Reads a repository's **source** for environment-variable *references*
//! (`os.getenv("X")`, `process.env.X`, `std::env::var("X")`, …) and proposes a
//! `.env.refs` mapping each one to a kovra coordinate. It is a code-reading
//! accelerator: the safe path (a secret contract) becomes the fast path.
//!
//! **It never reads, materializes, or writes a secret value.** It works purely
//! from source *references* — variable names, never values — so no value can
//! enter the agent's context. It deliberately skips `.env*` files (which hold
//! values) and reads only known source extensions.
//!
//! The generated coordinates use the `${ENV}` placeholder (one contract serves
//! all environments, substituted by `kovra run --env`) and follow the
//! three-segment grammar `<env>/<component>/<key>` (spec §1.2/§4.2). The output
//! is a **proposal** for a human to review — callers must not silently overwrite
//! an existing `.env.refs`.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::LazyLock;

use ignore::WalkBuilder;
use regex::Regex;

use crate::error::CoreError;

/// A source language whose env-var reference patterns scaffold understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Python,
    JavaScript,
    Rust,
}

impl Lang {
    /// The language for a file extension, or `None` if scaffold does not scan it.
    pub fn for_extension(ext: &str) -> Option<Lang> {
        match ext {
            "py" | "pyi" => Some(Lang::Python),
            "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" => Some(Lang::JavaScript),
            "rs" => Some(Lang::Rust),
            _ => None,
        }
    }
}

// One capture group (group 1) per pattern: the env-var name. Names are the
// conventional SHOUTING_SNAKE_CASE — lowercase/mixed names are not treated as
// env vars (too noisy), matching how teams actually name them.
static PY_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r#"os\.getenv\(\s*["']([A-Z][A-Z0-9_]*)["']"#).unwrap(),
        Regex::new(r#"os\.environ\.get\(\s*["']([A-Z][A-Z0-9_]*)["']"#).unwrap(),
        Regex::new(r#"os\.environ\[\s*["']([A-Z][A-Z0-9_]*)["']\s*\]"#).unwrap(),
    ]
});
static JS_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r#"process\.env\.([A-Z][A-Z0-9_]*)"#).unwrap(),
        Regex::new(r#"process\.env\[\s*["']([A-Z][A-Z0-9_]*)["']\s*\]"#).unwrap(),
    ]
});
static RS_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![Regex::new(r#"env::var(?:_os)?\(\s*["']([A-Z][A-Z0-9_]*)["']"#).unwrap()]
});

/// OS/process env vars that are never application secrets — proposing them is
/// pure noise, so scaffold drops them. Conservative on purpose: anything that
/// *might* be a secret is kept for the human to prune.
const NEVER_SECRET: &[&str] = &[
    "PATH", "HOME", "PWD", "USER", "SHELL", "TERM", "LANG", "LC_ALL", "TMPDIR", "HOSTNAME",
];

fn patterns(lang: Lang) -> &'static [Regex] {
    match lang {
        Lang::Python => &PY_PATTERNS,
        Lang::JavaScript => &JS_PATTERNS,
        Lang::Rust => &RS_PATTERNS,
    }
}

/// Env-var names referenced in `source` for `lang`, in **source order**
/// (by first byte offset), deduped. Pure (no I/O) so it is exhaustively
/// unit-tested per language. Matches across patterns are merged by position so
/// the order reflects the code, not the pattern list.
pub fn detect_in_source(source: &str, lang: Lang) -> Vec<String> {
    let mut hits: Vec<(usize, String)> = Vec::new();
    for re in patterns(lang) {
        for caps in re.captures_iter(source) {
            let m = caps.get(1).expect("pattern has capture group 1");
            let name = m.as_str().to_string();
            if !NEVER_SECRET.contains(&name.as_str()) {
                hits.push((m.start(), name));
            }
        }
    }
    hits.sort_by_key(|(pos, _)| *pos);
    let mut seen: Vec<String> = Vec::new();
    for (_, name) in hits {
        if !seen.contains(&name) {
            seen.push(name);
        }
    }
    seen
}

/// A single proposed mapping: an env var → a kovra coordinate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    /// The environment variable name as written in source (e.g. `DATABASE_URL`).
    pub var: String,
    /// The proposed coordinate, `secret:${ENV}/<component>/<key>`.
    pub coordinate: String,
}

/// Lowercase, replace any run of non-alphanumerics with a single `-`, and trim
/// leading/trailing `-`. Yields a valid single coordinate segment (no `/`, no
/// `${...}`). Empty input (or all-punctuation) falls back to `fallback`.
fn slug(raw: &str, fallback: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut prev_dash = false;
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.to_string()
    }
}

/// Infer the `component` segment from a file's path relative to the repo root:
/// the top-level directory name (e.g. `backend/db.py` → `backend`). A file at
/// the repo root has no directory, so it falls back to `app`.
fn component_for(rel_path: &Path) -> String {
    let top = rel_path.components().next().and_then(|c| {
        // Only treat it as a component if there is a further path segment (i.e.
        // it is a directory, not the file itself).
        if rel_path.components().count() > 1 {
            c.as_os_str().to_str()
        } else {
            None
        }
    });
    match top {
        Some(dir) => slug(dir, "app"),
        None => "app".to_string(),
    }
}

/// Build the coordinate for a var detected in `component`:
/// `secret:${ENV}/<component>/<key>` with `key` the kebab-cased var name.
pub fn coordinate_for(var: &str, component: &str) -> String {
    format!("secret:${{ENV}}/{}/{}", component, slug(var, "value"))
}

/// Scan `root` and return the proposals, sorted by variable name and unique per
/// variable (the lexicographically-first file path wins the component). Walks
/// with `.gitignore` honored and `.env*` files skipped — only source files are
/// read, and only for variable *names*.
pub fn scan_repo(root: &Path) -> Result<Vec<Proposal>, CoreError> {
    // var -> component, keyed so the first path (sorted) wins deterministically.
    let mut found: BTreeMap<String, String> = BTreeMap::new();

    let walker = WalkBuilder::new(root)
        // Skip hidden trees (`.git`, `.venv`, …) and honor `.gitignore`/`.ignore`,
        // so vendored/generated dirs (`node_modules`, `target`) aren't scanned as
        // project source. `.env*` is hidden anyway, and also skipped by name below
        // (belt-and-suspenders for the no-value rule).
        .hidden(true)
        .git_ignore(true)
        .ignore(true)
        // Honor `.gitignore` even when the scan root is not itself a git repo
        // (a worktree, an exported tree); otherwise vendored dirs slip through.
        .require_git(false)
        .git_global(false)
        .build();

    // Collect (rel_path, lang) for deterministic ordering, then process sorted.
    let mut files: Vec<(std::path::PathBuf, Lang)> = Vec::new();
    for entry in walker.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        // Never read value-bearing env files — only source references.
        if name == ".env" || name.starts_with(".env.") {
            continue;
        }
        let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
            continue;
        };
        let Some(lang) = Lang::for_extension(ext) else {
            continue;
        };
        let rel = path.strip_prefix(root).unwrap_or(path).to_path_buf();
        files.push((rel, lang));
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));

    for (rel, lang) in files {
        let abs = root.join(&rel);
        // Read as bytes → lossy UTF-8: a binary or non-UTF8 file just yields no
        // matches; it never errors out the whole scan.
        let Ok(bytes) = std::fs::read(&abs) else {
            continue;
        };
        let source = String::from_utf8_lossy(&bytes);
        let component = component_for(&rel);
        for var in detect_in_source(&source, lang) {
            found.entry(var).or_insert_with(|| component.clone());
        }
    }

    Ok(found
        .into_iter()
        .map(|(var, component)| Proposal {
            coordinate: coordinate_for(&var, &component),
            var,
        })
        .collect())
}

/// Render proposals as a committable `.env.refs` body (addresses only, never
/// values). An empty proposal set still yields the header so the output is a
/// valid, self-explanatory file.
pub fn render_env_refs(proposals: &[Proposal]) -> String {
    let mut out = String::new();
    out.push_str("# Proposed by `kovra scaffold` — REVIEW before use.\n");
    out.push_str(
        "# Holds only ADDRESSES, never values; safe to commit (replaces a plaintext .env).\n",
    );
    out.push_str("# `${ENV}` is substituted by `kovra run --env <e>`. Prune non-secret vars\n");
    out.push_str("# (e.g. PORT, LOG_LEVEL) and adjust components/keys as needed.\n");
    if proposals.is_empty() {
        out.push_str("# (no environment-variable references detected)\n");
        return out;
    }
    out.push('\n');
    for p in proposals {
        out.push_str(&p.var);
        out.push('=');
        out.push_str(&p.coordinate);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_python_patterns() {
        let src = r#"
            db = os.getenv("DATABASE_URL")
            key = os.environ.get("STRIPE_KEY")
            tok = os.environ["API_TOKEN"]
            lower = os.getenv("not_a_secret")   # mixed-case: ignored
        "#;
        let found = detect_in_source(src, Lang::Python);
        assert_eq!(found, vec!["DATABASE_URL", "STRIPE_KEY", "API_TOKEN"]);
    }

    #[test]
    fn detects_js_ts_patterns() {
        let src = r#"
            const url = process.env.DATABASE_URL;
            const k = process.env["STRIPE_KEY"];
            const p = process.env.PORT;
        "#;
        let found = detect_in_source(src, Lang::JavaScript);
        assert_eq!(found, vec!["DATABASE_URL", "STRIPE_KEY", "PORT"]);
    }

    #[test]
    fn detects_rust_patterns() {
        let src = r#"
            let u = std::env::var("DATABASE_URL").unwrap();
            let o = env::var_os("HOME");          // NEVER_SECRET: dropped
            let s = env::var("SECRET_KEY")?;
        "#;
        let found = detect_in_source(src, Lang::Rust);
        assert_eq!(found, vec!["DATABASE_URL", "SECRET_KEY"]);
    }

    #[test]
    fn dedups_within_a_source() {
        let src = r#"os.getenv("X"); os.getenv("X"); os.environ["X"]"#;
        assert_eq!(detect_in_source(src, Lang::Python), vec!["X"]);
    }

    #[test]
    fn coordinate_uses_three_segment_grammar_with_placeholder() {
        assert_eq!(
            coordinate_for("DATABASE_URL", "backend"),
            "secret:${ENV}/backend/database-url"
        );
        // The generated coordinate parses under the L4 grammar.
        let parsed = crate::EnvRefs::parse("X=secret:${ENV}/backend/database-url").unwrap();
        assert_eq!(parsed.vars.len(), 1);
    }

    #[test]
    fn slug_kebab_cases_and_falls_back() {
        assert_eq!(slug("DATABASE_URL", "x"), "database-url");
        assert_eq!(slug("___", "fallback"), "fallback");
        assert_eq!(slug("Mixed.Name", "x"), "mixed-name");
    }

    #[test]
    fn component_is_top_dir_or_app() {
        assert_eq!(component_for(Path::new("backend/db.py")), "backend");
        assert_eq!(component_for(Path::new("main.py")), "app");
        assert_eq!(component_for(Path::new("api/v1/handler.ts")), "api");
    }

    #[test]
    fn render_is_valid_env_refs_and_round_trips() {
        let proposals = vec![
            Proposal {
                var: "DATABASE_URL".into(),
                coordinate: "secret:${ENV}/backend/database-url".into(),
            },
            Proposal {
                var: "STRIPE_KEY".into(),
                coordinate: "secret:${ENV}/backend/stripe-key".into(),
            },
        ];
        let body = render_env_refs(&proposals);
        // Every non-comment line parses under the shipped grammar.
        let parsed = crate::EnvRefs::parse(&body).unwrap();
        assert_eq!(parsed.vars.len(), 2);
        assert!(body.contains("DATABASE_URL=secret:${ENV}/backend/database-url"));
    }

    #[test]
    fn scan_repo_walks_sources_and_skips_env_files() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("backend")).unwrap();
        std::fs::write(
            root.join("backend/app.py"),
            r#"db = os.getenv("DATABASE_URL")"#,
        )
        .unwrap();
        std::fs::write(root.join("web.ts"), r#"const k = process.env.STRIPE_KEY;"#).unwrap();
        // A value-bearing .env must NEVER be read (no value enters context).
        std::fs::write(root.join(".env"), "DATABASE_URL=super-secret-value\n").unwrap();

        let proposals = scan_repo(root).unwrap();
        let vars: Vec<&str> = proposals.iter().map(|p| p.var.as_str()).collect();
        assert_eq!(vars, vec!["DATABASE_URL", "STRIPE_KEY"]);
        // component inference: backend/ → backend, root file → app
        let by_var: std::collections::HashMap<_, _> = proposals
            .iter()
            .map(|p| (p.var.as_str(), p.coordinate.as_str()))
            .collect();
        assert_eq!(by_var["DATABASE_URL"], "secret:${ENV}/backend/database-url");
        assert_eq!(by_var["STRIPE_KEY"], "secret:${ENV}/app/stripe-key");
        // The rendered body never contains the planted .env value.
        let body = render_env_refs(&proposals);
        assert!(!body.contains("super-secret-value"));
    }

    #[test]
    fn scan_repo_skips_hidden_and_vendored_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        // A hidden virtualenv with third-party source must be skipped.
        std::fs::create_dir_all(root.join(".venv/lib")).unwrap();
        std::fs::write(root.join(".venv/lib/dep.py"), r#"os.getenv("VENDOR_KEY")"#).unwrap();
        // A gitignored vendored dir must be skipped too.
        std::fs::write(root.join(".gitignore"), "node_modules/\n").unwrap();
        std::fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
        std::fs::write(
            root.join("node_modules/pkg/i.ts"),
            r#"process.env.DEP_TOKEN"#,
        )
        .unwrap();
        // The project's own source IS scanned.
        std::fs::write(root.join("app.py"), r#"os.getenv("APP_KEY")"#).unwrap();

        let vars: Vec<String> = scan_repo(root)
            .unwrap()
            .into_iter()
            .map(|p| p.var)
            .collect();
        assert_eq!(
            vars,
            vec!["APP_KEY"],
            "hidden (.venv) and gitignored (node_modules) trees must be skipped"
        );
    }
}
