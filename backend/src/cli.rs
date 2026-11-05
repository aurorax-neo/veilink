use std::io::{Read, Write};

use tokio_util::sync::CancellationToken;

use crate::auth::{KeyStore, ROLE_ADMIN};
use crate::buildinfo;
use crate::config::{self, ParseFlagsError};
use crate::master;
use crate::node;
use crate::store::Store;
use crate::tunnel;

const KEYS_USAGE: &str = "Usage: veilink keys list|create|revoke [flags]\n\nSubcommands:\n  list              List API keys (prefix only, never plaintext)\n  create [name]     Create a new API key (plaintext shown once)\n  revoke <id>       Revoke an API key by ID\n\nFlags:\n  -database         Database path (default /data/veilink.db)\n  -deployment-key   Deployment key path (default /data/veilink.key)";

pub async fn run<W: Write>(
    cancel: CancellationToken,
    args: &[String],
    out: &mut W,
) -> Result<(), String> {
    let mut empty = std::io::empty();
    run_with_input(cancel, args, &mut empty, out).await
}

pub async fn run_with_input<R: Read, W: Write>(
    cancel: CancellationToken,
    raw_args: &[String],
    _input: &mut R,
    out: &mut W,
) -> Result<(), String> {
    if raw_args.is_empty() {
        return Err(
            "usage: veilink master|server|client|keys|x25519|mldsa65|vlessenc|version [flags]"
                .to_string(),
        );
    }

    let mut args: Vec<String> = raw_args.to_vec();
    if args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
        if args.len() == 1 {
            writeln!(
                out,
                "Usage: veilink master|server|client|keys|x25519|mldsa65|vlessenc|version [flags]\nUse veilink help <command> for command help."
            )
            .map_err(|e| e.to_string())?;
            return Ok(());
        }
        if args[0] != "help" || args.len() != 2 {
            return Err("unexpected help arguments".to_string());
        }
        args = vec![args[1].clone(), "--help".to_string()];
    } else if args.len() == 2 && args[1] == "help" {
        args = vec![args[0].clone(), "--help".to_string()];
    }

    let cmd = args[0].as_str();
    if matches!(cmd, "version" | "x25519" | "mldsa65" | "vlessenc")
        && args.len() == 2
        && (args[1] == "--help" || args[1] == "-h")
    {
        writeln!(
            out,
            "Usage: veilink {}\nThis command accepts no flags.",
            cmd
        )
        .map_err(|e| e.to_string())?;
        return Ok(());
    }

    if cmd == "keys" && args.len() == 2 && (args[1] == "--help" || args[1] == "-h") {
        writeln!(out, "{}", KEYS_USAGE).map_err(|e| e.to_string())?;
        return Ok(());
    }

    if matches!(cmd, "version" | "x25519" | "mldsa65" | "vlessenc") && args.len() != 1 {
        return Err("unexpected arguments".to_string());
    }

    match cmd {
        "version" => {
            writeln!(
                out,
                "veilink {} ({})",
                buildinfo::version(),
                buildinfo::commit()
            )
            .map_err(|e| e.to_string())?;
            return Ok(());
        }
        "x25519" => {
            let (priv_key, pub_key) = tunnel::generate_x25519()?;
            writeln!(out, "Private key: {}\nPublic key: {}", priv_key, pub_key)
                .map_err(|e| e.to_string())?;
            return Ok(());
        }
        "mldsa65" => {
            let (priv_key, pub_key) = tunnel::generate_mldsa65()?;
            writeln!(out, "Private key: {}\nPublic key: {}", priv_key, pub_key)
                .map_err(|e| e.to_string())?;
            return Ok(());
        }
        "vlessenc" => {
            let (x_dec, x_enc, pq_dec, pq_enc) = tunnel::generate_vless_enc()?;
            writeln!(
                out,
                "Authentication: X25519, not Post-Quantum\ndecryption: {}\nencryption: {}\n\nAuthentication: ML-KEM-768, Post-Quantum\ndecryption: {}\nencryption: {}",
                x_dec, x_enc, pq_dec, pq_enc
            )
            .map_err(|e| e.to_string())?;
            return Ok(());
        }
        "keys" => return run_keys(&args[1..], out),
        _ => {}
    }

    if cmd.starts_with('-') {
        return Err(
            "missing role: put master, server or client before role flags (example: veilink master -database /data/veilink.db)"
                .to_string(),
        );
    }
    if cmd != "master" && cmd != "server" && cmd != "client" {
        return Err("unknown command".to_string());
    }

    let cfg = match config::parse_flags_output(cmd, &args[1..], out) {
        Ok(c) => c,
        Err(ParseFlagsError::Help) => return Ok(()),
        Err(ParseFlagsError::Error(m)) => return Err(m),
    };

    match cmd {
        "master" => master::run(cancel, cfg).await,
        "server" => node::run(cancel, cfg, "server")
            .await
            .map_err(|e| e.to_string()),
        "client" => node::run(cancel, cfg, "client")
            .await
            .map_err(|e| e.to_string()),
        _ => Err("unknown command".to_string()),
    }
}

pub fn run_keys<W: Write>(args: &[String], out: &mut W) -> Result<(), String> {
    for a in args {
        if a == "--help" || a == "-h" {
            writeln!(out, "{}", KEYS_USAGE).map_err(|e| e.to_string())?;
            return Ok(());
        }
    }
    if args.is_empty() {
        return Err("usage: veilink keys list|create|revoke [flags]".to_string());
    }

    let mut subcmd = String::new();
    let mut sub_arg = String::new();
    let mut flag_args: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if subcmd.is_empty() && (a == "list" || a == "create" || a == "revoke") {
            subcmd = a.clone();
            if (subcmd == "create" || subcmd == "revoke")
                && i + 1 < args.len()
                && !args[i + 1].starts_with('-')
            {
                sub_arg = args[i + 1].clone();
                i += 1;
            }
            i += 1;
            continue;
        }
        flag_args.push(a.clone());
        i += 1;
    }

    if subcmd.is_empty() {
        return Err("usage: veilink keys list|create|revoke [flags]".to_string());
    }

    let mut db = "/data/veilink.db".to_string();
    let mut key = "/data/veilink.key".to_string();

    let mut idx = 0;
    while idx < flag_args.len() {
        let raw = &flag_args[idx];
        if !raw.starts_with('-') || raw == "-" {
            return Err(format!(
                "unexpected arguments: {}",
                flag_args[idx..].join(" ")
            ));
        }
        let trimmed = raw
            .strip_prefix("--")
            .or_else(|| raw.strip_prefix('-'))
            .unwrap_or("");
        let (name, inline_val) = match trimmed.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (trimmed, None),
        };
        match name {
            "database" => {
                let v = match inline_val {
                    Some(v) => v,
                    None => {
                        idx += 1;
                        if idx >= flag_args.len() {
                            return Err("flag needs an argument: -database".to_string());
                        }
                        flag_args[idx].clone()
                    }
                };
                db = v;
            }
            "deployment-key" => {
                let v = match inline_val {
                    Some(v) => v,
                    None => {
                        idx += 1;
                        if idx >= flag_args.len() {
                            return Err("flag needs an argument: -deployment-key".to_string());
                        }
                        flag_args[idx].clone()
                    }
                };
                key = v;
            }
            _ => return Err(format!("flag provided but not defined: -{}", name)),
        }
        idx += 1;
    }

    let s = Store::open_existing(&db, &key).map_err(|e| format!("open database: {}", e))?;
    let ks = KeyStore::new(s.db());
    ks.migrate().map_err(|e| e.to_string())?;
    ks.commit_legacy_migration(&mut *out).map_err(|e| e.to_string())?;

    match subcmd.as_str() {
        "list" => {
            let keys = ks.list().map_err(|e| e.to_string())?;
            if keys.is_empty() {
                writeln!(out, "no API keys").map_err(|e| e.to_string())?;
                return Ok(());
            }
            writeln!(
                out,
                "{:<5} {:<20} {:<10} {:<10} {}",
                "ID", "NAME", "PREFIX", "ROLE", "CREATED"
            )
            .map_err(|e| e.to_string())?;
            for k in keys {
                writeln!(
                    out,
                    "{:<5} {:<20} {:<10} {:<10} {}",
                    k.id,
                    k.name,
                    k.key_prefix,
                    k.role,
                    k.created_at.format("%Y-%m-%d %H:%M")
                )
                .map_err(|e| e.to_string())?;
            }
            Ok(())
        }
        "create" => {
            let (plaintext, _) = ks
                .create_named(&sub_arg, ROLE_ADMIN)
                .map_err(|e| e.to_string())?;
            writeln!(out, "API Key created (shown only once):\n{}", plaintext)
                .map_err(|e| e.to_string())?;
            Ok(())
        }
        "revoke" => {
            if sub_arg.is_empty() {
                return Err("usage: veilink keys revoke <id>".to_string());
            }
            let id: i64 = sub_arg
                .parse()
                .map_err(|_| "invalid key id".to_string())?;
            ks.revoke(id).map_err(|e| e.to_string())?;
            writeln!(out, "API Key revoked").map_err(|e| e.to_string())?;
            Ok(())
        }
        _ => Err("usage: veilink keys list|create|revoke [flags]".to_string()),
    }
}
