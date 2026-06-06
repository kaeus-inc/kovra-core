//! `kovra` — the command-line surface over `kovra-core` + `kovra-wrapper`
//! (spec §9.2, KOV-7). The CLI is the trusted channel for revealing critical
//! values; all policy lives in the core, this binary is a thin adapter.

mod cli;
mod commands;
mod context;
mod onepassword;
mod provider;
mod setup;
mod value_input;

use anyhow::Result;
use clap::Parser;

use crate::cli::{Cli, Command, ExchangeAction, HooksAction, KeyAction};
use crate::context::Ctx;

fn main() -> Result<()> {
    let parsed = Cli::parse();
    let ctx = Ctx::load()?;
    match parsed.command {
        Command::Init { force } => commands::init(&ctx, force),
        Command::Setup {
            project,
            mcp_command,
            dry_run,
        } => setup::setup(&ctx, project.as_deref(), &mcp_command, dry_run),
        Command::Add {
            coordinate,
            stdin,
            sensitivity,
            description,
            reference,
            public_key,
            totp,
            revealable,
            project,
        } => commands::add(
            &ctx,
            &coordinate,
            stdin,
            sensitivity,
            description,
            reference,
            public_key,
            totp,
            revealable,
            project.as_deref(),
        ),
        Command::Set {
            coordinate,
            stdin,
            project,
        } => commands::set(&ctx, &coordinate, stdin, project.as_deref()),
        Command::Edit {
            coordinate,
            sensitivity,
            description,
            reference,
            revealable,
            project,
        } => commands::edit(
            &ctx,
            &coordinate,
            sensitivity,
            description,
            reference,
            revealable,
            project.as_deref(),
        ),
        Command::Rm {
            coordinate,
            project,
        } => commands::rm(&ctx, &coordinate, project.as_deref()),
        Command::List {
            env,
            component,
            project,
        } => commands::list(
            &ctx,
            env.as_deref(),
            component.as_deref(),
            project.as_deref(),
        ),
        Command::Show {
            coordinate,
            project,
        } => commands::show(&ctx, &coordinate, project.as_deref()),
        Command::Code {
            coordinate,
            project,
            min_validity,
        } => commands::code(&ctx, &coordinate, project.as_deref(), min_validity),
        Command::Generate {
            coordinate,
            length,
            sensitivity,
            description,
            project,
        } => commands::generate(
            &ctx,
            &coordinate,
            length,
            sensitivity,
            description,
            project.as_deref(),
        ),
        Command::Run {
            env,
            refs,
            project,
            allow,
            command,
        } => commands::run(&ctx, &env, refs, project.as_deref(), &allow, &command),
        Command::Approve { list, deny, id } => commands::approve(&ctx, list, deny, id),
        Command::Confirm { description, ttl } => commands::confirm(&ctx, &description, ttl),
        Command::Keygen {
            coordinate,
            algorithm,
            sensitivity,
            description,
            project,
        } => commands::keygen(
            &ctx,
            &coordinate,
            algorithm,
            sensitivity,
            description,
            project.as_deref(),
        ),
        Command::Pubkey {
            coordinate,
            project,
        } => commands::pubkey(&ctx, &coordinate, project.as_deref()),
        Command::SshAdd {
            coordinate,
            project,
        } => commands::ssh_add(&ctx, &coordinate, project.as_deref()),
        Command::SshAgent { socket } => commands::ssh_agent(&ctx, socket),
        Command::Sign {
            coordinate,
            input,
            project,
        } => commands::sign(&ctx, &coordinate, &input, project.as_deref()),
        Command::Verify {
            coordinate,
            signature,
            input,
            project,
        } => commands::verify(&ctx, &coordinate, &signature, &input, project.as_deref()),
        Command::Encrypt {
            coordinate,
            input,
            project,
        } => commands::encrypt(&ctx, &coordinate, &input, project.as_deref()),
        Command::Decrypt {
            coordinate,
            input,
            project,
        } => commands::decrypt(&ctx, &coordinate, &input, project.as_deref()),
        Command::Scaffold { path, out, force } => commands::scaffold(&ctx, &path, out, force),
        Command::Doctor { env, refs, project } => {
            commands::doctor(&ctx, &env, refs, project.as_deref())
        }
        Command::Hooks { action } => match action {
            HooksAction::Install {
                path,
                scanner,
                force,
            } => commands::hooks_install(&ctx, &path, scanner.into(), force),
        },
        Command::Key { action } => match action {
            KeyAction::Export {
                out,
                clipboard,
                op,
                op_vault,
                op_title,
            } => commands::key_export(
                &ctx,
                commands::ExportTargets {
                    out: out.as_deref(),
                    clipboard,
                    op,
                    op_vault: op_vault.as_deref(),
                    op_title: op_title.as_deref(),
                },
            ),
            KeyAction::Import {
                file,
                force,
                op,
                op_vault,
            } => commands::key_import(
                &ctx,
                file.as_deref(),
                force,
                op.as_deref(),
                op_vault.as_deref(),
            ),
        },
        Command::Import {
            coordinate,
            from,
            sensitivity,
            description,
            revealable,
            project,
        } => commands::import(
            &ctx,
            &coordinate,
            &from,
            sensitivity,
            description,
            revealable,
            project.as_deref(),
        ),
        Command::Ui {
            port,
            idle,
            no_open,
            docker,
            no_confirm,
        } => commands::ui(&ctx, port, idle, no_open, docker, no_confirm),
        Command::Package {
            env,
            component,
            recipient,
            ttl,
            out,
            token_out,
            project,
        } => commands::package(
            &ctx,
            &env,
            &component,
            &recipient,
            ttl,
            &out,
            &token_out,
            project.as_deref(),
        ),
        Command::Unpack {
            r#in,
            identity_file,
            identity,
            token,
            project,
            force,
        } => commands::unpack(
            &ctx,
            &r#in,
            identity_file.as_deref(),
            identity.as_deref(),
            token.as_deref(),
            project.as_deref(),
            force,
        ),
        Command::Exchange { action } => match action {
            ExchangeAction::Init { device } => commands::exchange_init(&ctx, device.as_deref()),
            ExchangeAction::Seal {
                env,
                component,
                ttl,
                usb,
                project,
            } => commands::exchange_seal(&ctx, &env, &component, ttl, &usb, project.as_deref()),
            ExchangeAction::RegisterToken { from } => {
                commands::exchange_register_token(&ctx, from.as_deref())
            }
            ExchangeAction::Open {
                usb,
                token,
                project,
                force,
            } => commands::exchange_open(&ctx, &usb, token.as_deref(), project.as_deref(), force),
        },
        Command::Audit {
            coordinate,
            env,
            component,
            since,
            until,
            action,
        } => commands::audit_view(&ctx, coordinate, env, component, since, until, action),
    }
}
