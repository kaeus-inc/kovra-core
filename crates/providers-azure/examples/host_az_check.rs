//! `[host]` validation tool for the real [`SystemAzRunner`] — NOT a unit test.
//!
//! Exercises the production `az` path (real subprocess spawn + the `wait-timeout`
//! deadline + kill-on-timeout) that, by design (§6 / CLAUDE.md rule 4), has no
//! unit coverage and must be validated by a human against a live Key Vault.
//!
//! It prints only the **outcome** — a byte length on success, or the error — and
//! NEVER the materialized value (I11/I12). Use it to confirm both the success
//! path (real secret) and the timeout path (a slow stand-in `az` on PATH):
//!
//!   # success (needs `az login` + access to the vault):
//!   cargo run -p kovra-providers-azure --example host_az_check -- \
//!     15 azure-kv://<vault>/<secret>
//!
//!   # timeout/kill (shadow `az` with a sleeping script on PATH, tiny deadline):
//!   PATH="/tmp/slow-az:$PATH" cargo run -p kovra-providers-azure \
//!     --example host_az_check -- 1 azure-kv://anything/here
use std::time::Duration;

use kovra_core::SecretProvider;
use kovra_providers_azure::{AzureProvider, SystemAzRunner};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: host_az_check <timeout_secs> <azure-kv://vault/secret>");
        std::process::exit(2);
    }
    let secs: u64 = args[1].parse().expect("timeout_secs must be an integer");
    let reference = &args[2];

    let provider = AzureProvider::new(SystemAzRunner).with_timeout(Duration::from_secs(secs));
    match provider.materialize(reference) {
        // The value is NEVER printed — only its length, as proof of materialization.
        Ok(v) => println!(
            "OK: materialized {} bytes (value NOT printed)",
            v.expose().len()
        ),
        Err(e) => println!("ERR: {e}"),
    }
}
