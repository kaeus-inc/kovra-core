//! `[host]` validation tool for the real [`SystemAwsRunner`] — NOT a unit test.
//!
//! Exercises the production `aws` path (real subprocess spawn + the `wait-timeout`
//! deadline + kill-on-timeout) that, by design (§6 / CLAUDE.md rule 4), has no
//! unit coverage and must be validated by a human against a live Secrets Manager
//! secret.
//!
//! It prints only the **outcome** — a byte length on success, or the error — and
//! NEVER the materialized value (I11/I12). Use it to confirm both the success
//! path (real secret) and the timeout path (a slow stand-in `aws` on PATH):
//!
//!   # success (needs valid `aws` credentials + access to the secret):
//!   cargo run -p kovra-providers-aws --example host_aws_check -- \
//!     15 aws-sm://<region>/<secret>
//!
//!   # timeout/kill (shadow `aws` with a sleeping script on PATH, tiny deadline):
//!   PATH="/tmp/slow-aws:$PATH" cargo run -p kovra-providers-aws \
//!     --example host_aws_check -- 1 aws-sm://us-east-1/anything
use std::time::Duration;

use kovra_core::SecretProvider;
use kovra_providers_aws::{AwsProvider, SystemAwsRunner};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: host_aws_check <timeout_secs> <aws-sm://region/secret>");
        std::process::exit(2);
    }
    let secs: u64 = args[1].parse().expect("timeout_secs must be an integer");
    let reference = &args[2];

    let provider = AwsProvider::new(SystemAwsRunner).with_timeout(Duration::from_secs(secs));
    match provider.materialize(reference) {
        // The value is NEVER printed — only its length, as proof of materialization.
        Ok(v) => println!(
            "OK: materialized {} bytes (value NOT printed)",
            v.expose().len()
        ),
        Err(e) => println!("ERR: {e}"),
    }
}
