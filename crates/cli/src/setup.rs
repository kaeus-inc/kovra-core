//! `kovra setup` — per-repo onboarding (spec §13, KOV-9).
//!
//! Bootstraps a consumer repository so an agent follows the secure path by
//! default. Idempotent; safe to re-run. Three steps:
//!   1. ensure the vault + master key exist (reusing `init`'s logic), and the
//!      project vault dir,
//!   2. merge a `kovra` server entry into the repo's `./.mcp.json` (without
//!      clobbering other servers),
//!   3. insert/update the kovra conventions block in the repo's `./CLAUDE.md`
//!      between `<!-- kovra:begin -->` and `<!-- kovra:end -->` (never touching
//!      anything outside those markers).
//!
//! This is the only piece that can register the MCP server, because it runs
//! *before* the MCP server exists — the MCP `setup_kovra_conventions` prompt
//! complements it for re-applying the block once the agent is connected.

use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};

use crate::commands;
use crate::context::Ctx;

/// The canonical conventions block — single source of truth, compiled in so the
/// CLI and the shipped template never drift.
pub const CONVENTIONS: &str = include_str!("../../../templates/kovra-conventions.md");

const BEGIN: &str = "<!-- kovra:begin -->";
const END: &str = "<!-- kovra:end -->";
const MCP_FILE: &str = ".mcp.json";
const CLAUDE_FILE: &str = "CLAUDE.md";

/// Run onboarding in the current directory.
pub fn setup(ctx: &Ctx, project: Option<&str>, mcp_command: &str, dry_run: bool) -> Result<()> {
    let project = match project {
        Some(p) => p.to_string(),
        None => default_project()?,
    };

    // 1. Vault — ensure the registry + master key exist, then the project vault.
    if dry_run {
        println!("[dry-run] would ensure vault is initialized and project `{project}` exists");
    } else {
        ensure_vault(ctx)?;
        // The project vault dir is also created lazily on first write; we
        // pre-create it here so the user sees it exists after setup.
        let dir = ctx.registry.project_dir(&project);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating project vault `{project}`"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).ok();
        }
        println!("Vault ready; project `{project}`.");
    }

    // 2. .mcp.json — merge the kovra server entry.
    let mcp_path = Path::new(MCP_FILE);
    let existing_mcp = read_if_exists(mcp_path)?;
    let merged_mcp = merge_mcp_json(existing_mcp.as_deref(), &project, mcp_command)?;
    write_or_preview(
        mcp_path,
        &merged_mcp,
        dry_run,
        "register the kovra MCP server",
    )?;

    // 3. CLAUDE.md — insert/update the conventions block.
    let claude_path = Path::new(CLAUDE_FILE);
    let existing_claude = read_if_exists(claude_path)?;
    let merged_claude = merge_conventions(existing_claude.as_deref(), CONVENTIONS);
    write_or_preview(
        claude_path,
        &merged_claude,
        dry_run,
        "insert/update the kovra conventions block",
    )?;

    if !dry_run {
        println!(
            "Setup complete. Review {CLAUDE_FILE} and {MCP_FILE}, then reload your agent to pick up the MCP server."
        );
    }
    Ok(())
}

/// Ensure the vault is initialized; if not, initialize it (reusing `init`).
fn ensure_vault(ctx: &Ctx) -> Result<()> {
    if ctx.master_key().is_ok() {
        return Ok(());
    }
    commands::init(ctx, false)
}

/// The default project name: the current directory's file name.
fn default_project() -> Result<String> {
    let cwd = std::env::current_dir().context("reading the current directory")?;
    cwd.file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "cannot derive a project name from the current directory; pass --project"
            )
        })
}

/// Read a file's contents, or `None` if it does not exist.
fn read_if_exists(path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Write `content`, or print a dry-run preview line.
fn write_or_preview(path: &Path, content: &str, dry_run: bool, what: &str) -> Result<()> {
    if dry_run {
        println!("[dry-run] would {what} in {}", path.display());
        return Ok(());
    }
    std::fs::write(path, content).with_context(|| format!("writing {}", path.display()))?;
    println!("Updated {} ({what}).", path.display());
    Ok(())
}

/// Merge a `kovra` server entry into an existing `.mcp.json` (or create one).
/// Other servers are preserved; the `kovra` entry is replaced if present.
///
/// `mcp_command` is split on whitespace: the first token is `command`, the rest
/// are `args` (so both `kovra-mcp` and `uv run --directory … kovra-mcp` work).
pub fn merge_mcp_json(existing: Option<&str>, project: &str, mcp_command: &str) -> Result<String> {
    let mut root: Value = match existing {
        Some(s) if !s.trim().is_empty() => {
            serde_json::from_str(s).context("parsing existing .mcp.json")?
        }
        _ => json!({}),
    };
    if !root.is_object() {
        bail!(".mcp.json is not a JSON object");
    }
    let obj = root.as_object_mut().unwrap();
    let servers = obj
        .entry("mcpServers")
        .or_insert_with(|| Value::Object(Map::new()));
    if !servers.is_object() {
        bail!(".mcp.json `mcpServers` is not a JSON object");
    }
    let servers = servers.as_object_mut().unwrap();

    let mut tokens = mcp_command.split_whitespace();
    let command = tokens
        .next()
        .ok_or_else(|| anyhow::anyhow!("--mcp-command is empty"))?;
    let args: Vec<Value> = tokens.map(|t| Value::String(t.to_string())).collect();

    let mut entry = Map::new();
    entry.insert("command".into(), Value::String(command.into()));
    if !args.is_empty() {
        entry.insert("args".into(), Value::Array(args));
    }
    entry.insert(
        "env".into(),
        json!({
            "KOVRA_MCP_PROJECTS": project,
            "KOVRA_MCP_ENVIRONMENTS": "dev,test",
        }),
    );
    servers.insert("kovra".into(), Value::Object(entry));

    let mut out = serde_json::to_string_pretty(&root).context("serializing .mcp.json")?;
    out.push('\n');
    Ok(out)
}

/// Insert or update the conventions block in a `CLAUDE.md`.
///
/// - No existing file → the block becomes the file (with a trailing newline).
/// - File without the markers → the block is appended (one blank line before).
/// - File with the markers → only the span between `BEGIN`/`END` is replaced;
///   everything outside is preserved byte-for-byte.
pub fn merge_conventions(existing: Option<&str>, block: &str) -> String {
    let block = block.trim_end_matches('\n');
    let Some(text) = existing else {
        return format!("{block}\n");
    };
    if let (Some(start), Some(end_open)) = (text.find(BEGIN), text.find(END)) {
        let end = end_open + END.len();
        let mut out = String::with_capacity(text.len());
        out.push_str(&text[..start]);
        out.push_str(block);
        out.push_str(&text[end..]);
        return out;
    }
    // No markers — append, separated by a blank line.
    let sep = if text.ends_with('\n') { "\n" } else { "\n\n" };
    format!("{text}{sep}{block}\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conventions_block_has_markers_and_key_rules() {
        assert!(CONVENTIONS.contains(BEGIN));
        assert!(CONVENTIONS.contains(END));
        assert!(CONVENTIONS.contains("kovra run"));
        assert!(CONVENTIONS.contains(".env.refs"));
    }

    #[test]
    fn mcp_merge_creates_file_with_kovra_entry() {
        let out = merge_mcp_json(None, "myproj", "kovra-mcp").unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let k = &v["mcpServers"]["kovra"];
        assert_eq!(k["command"], "kovra-mcp");
        assert!(k.get("args").is_none(), "single-token command has no args");
        assert_eq!(k["env"]["KOVRA_MCP_PROJECTS"], "myproj");
        assert_eq!(k["env"]["KOVRA_MCP_ENVIRONMENTS"], "dev,test");
    }

    #[test]
    fn mcp_merge_splits_multi_token_command() {
        let out = merge_mcp_json(None, "p", "uv run --directory ./mcp kovra-mcp").unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let k = &v["mcpServers"]["kovra"];
        assert_eq!(k["command"], "uv");
        assert_eq!(k["args"][0], "run");
        assert_eq!(k["args"][3], "kovra-mcp");
    }

    #[test]
    fn mcp_merge_preserves_other_servers_and_replaces_kovra() {
        let existing = r#"{"mcpServers":{"other":{"command":"x"},"kovra":{"command":"old"}}}"#;
        let out = merge_mcp_json(Some(existing), "p", "kovra-mcp").unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            v["mcpServers"]["other"]["command"], "x",
            "other server kept"
        );
        assert_eq!(
            v["mcpServers"]["kovra"]["command"], "kovra-mcp",
            "kovra replaced"
        );
    }

    #[test]
    fn mcp_merge_is_idempotent() {
        let first = merge_mcp_json(None, "p", "kovra-mcp").unwrap();
        let second = merge_mcp_json(Some(&first), "p", "kovra-mcp").unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn conventions_into_empty_is_just_the_block() {
        let out = merge_conventions(None, CONVENTIONS);
        assert!(out.starts_with(BEGIN));
        assert!(out.trim_end().ends_with(END));
    }

    #[test]
    fn conventions_appended_preserves_existing_content() {
        let existing = "# My Project\n\nSome rules.\n";
        let out = merge_conventions(Some(existing), CONVENTIONS);
        assert!(
            out.starts_with("# My Project"),
            "existing content preserved"
        );
        assert!(out.contains(BEGIN) && out.contains(END));
    }

    #[test]
    fn conventions_update_replaces_only_the_block() {
        let existing = format!("# Top\n\n{BEGIN}\nOLD CONTENT\n{END}\n\n## Tail kept\n");
        let out = merge_conventions(Some(&existing), CONVENTIONS);
        assert!(out.starts_with("# Top"), "preamble kept");
        assert!(out.contains("## Tail kept"), "tail kept");
        assert!(!out.contains("OLD CONTENT"), "old block replaced");
        assert!(out.contains("kovra run"), "new block present");
        assert_eq!(out.matches(BEGIN).count(), 1);
        assert_eq!(out.matches(END).count(), 1);
    }

    #[test]
    fn conventions_merge_is_idempotent() {
        let once = merge_conventions(Some("# P\n"), CONVENTIONS);
        let twice = merge_conventions(Some(&once), CONVENTIONS);
        assert_eq!(once, twice);
    }
}
