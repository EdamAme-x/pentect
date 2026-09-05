//! Fail-closed classification for client modes whose model traffic is not
//! owned by the local Pentect gateway launched for this process.
//!
//! OpenCode server exposure is classified from this invocation's CLI. Its
//! generated server config is also forced to loopback by the launcher.

use crate::client_descriptor::{ClientDescriptor, CLAUDE, CODEX, OPENCODE, PI};
use std::net::IpAddr;

pub(crate) fn validate(tool: &ClientDescriptor, args: &[String]) -> Result<(), String> {
    if *tool == CODEX {
        return validate_codex(args);
    }
    if *tool == CLAUDE {
        return validate_claude(args);
    }
    if *tool == OPENCODE {
        return validate_opencode(args);
    }
    if *tool == PI {
        // The installed Pi CLI has no remote/cloud/attach execution mode.
        return Ok(());
    }
    Ok(())
}

fn validate_codex(args: &[String]) -> Result<(), String> {
    if has_option(args, "--remote", codex_option_arity) {
        return Err(
            "Codex remote app-server sessions are not protected by this local gateway".to_string(),
        );
    }
    if matches!(first_command(args, codex_option_arity), Some((_, "cloud"))) {
        return Err("Codex Cloud tasks are not protected by this local gateway".to_string());
    }
    if matches!(
        first_command(args, codex_option_arity),
        Some((_, "remote-control"))
    ) {
        return Err("Codex Remote Control is outside this local gateway boundary".to_string());
    }
    Ok(())
}

fn validate_claude(args: &[String]) -> Result<(), String> {
    for option in ["--cloud", "--environment", "--remote-control", "--teleport"] {
        if has_option(args, option, claude_option_arity) {
            return Err(
                "Claude remote or cloud execution is not protected by this local gateway"
                    .to_string(),
            );
        }
    }
    if matches!(
        first_command(args, claude_option_arity),
        Some((_, "ultrareview"))
    ) {
        return Err(
            "Claude ultrareview is cloud-hosted and outside this local gateway boundary"
                .to_string(),
        );
    }
    Ok(())
}

fn validate_opencode(args: &[String]) -> Result<(), String> {
    let command = first_command(args, opencode_option_arity);
    if matches!(command, Some((_, "attach")))
        || matches!(command, Some((index, "run")) if has_option(&args[index + 1..], "--attach", opencode_option_arity))
    {
        return Err(
            "OpenCode attach uses another server and bypasses this local gateway".to_string(),
        );
    }

    if matches!(command, Some((_, "serve" | "web"))) {
        if enabled_boolean_option(args, "--mdns", opencode_option_arity) {
            return Err(
                "network-exposed OpenCode servers are not supported by this launcher".to_string(),
            );
        }
        if option_values(args, "--hostname", opencode_option_arity)
            .any(|hostname| !is_loopback_host(hostname))
        {
            return Err(
                "network-exposed OpenCode servers are not supported by this launcher".to_string(),
            );
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Arity {
    None,
    One,
    Many,
}

fn first_command(args: &[String], arity: fn(&str) -> Arity) -> Option<(usize, &str)> {
    let mut index = 0;
    while index < args.len() {
        let argument = args[index].as_str();
        if argument == "--" {
            return None;
        }
        if argument.starts_with('-') {
            if argument.contains('=') {
                index += 1;
                continue;
            }
            match arity(argument) {
                Arity::None => index += 1,
                Arity::One => index = index.saturating_add(2),
                Arity::Many => {
                    index += 1;
                    while index < args.len() && !args[index].starts_with('-') {
                        index += 1;
                    }
                }
            }
            continue;
        }
        return Some((index, argument));
    }
    None
}

fn codex_option_arity(option: &str) -> Arity {
    match option {
        "-c"
        | "--config"
        | "--enable"
        | "--disable"
        | "--remote"
        | "--remote-auth-token-env"
        | "-m"
        | "--model"
        | "--local-provider"
        | "-p"
        | "--profile"
        | "-s"
        | "--sandbox"
        | "-C"
        | "--cd"
        | "--add-dir"
        | "-a"
        | "--ask-for-approval" => Arity::One,
        "-i" | "--image" => Arity::Many,
        _ => Arity::None,
    }
}

fn claude_option_arity(option: &str) -> Arity {
    match option {
        "--add-dir" | "--allowedTools" | "--allowed-tools" | "--betas" | "--disallowedTools"
        | "--disallowed-tools" | "--file" | "--mcp-config" => Arity::Many,
        "--agent"
        | "--agents"
        | "--append-system-prompt"
        | "--autocompact"
        | "--debug-file"
        | "--effort"
        | "--environment"
        | "--fallback-model"
        | "--input-format"
        | "--json-schema"
        | "--max-budget-usd"
        | "--model"
        | "-n"
        | "--name"
        | "--output-format"
        | "--permission-mode"
        | "--permission-prompts"
        | "--plugin-dir"
        | "--plugin-url"
        | "--remote-control-session-name-prefix"
        | "--settings"
        | "--system-prompt"
        | "--system-prompt-file" => Arity::One,
        _ => Arity::None,
    }
}

fn opencode_option_arity(option: &str) -> Arity {
    match option {
        "--cors" => Arity::Many,
        "--log-level" | "--port" | "--hostname" | "--mdns-domain" | "-m" | "--model" | "-s"
        | "--session" | "--prompt" | "--agent" | "--replay-limit" => Arity::One,
        _ => Arity::None,
    }
}

fn has_option(args: &[String], option: &str, arity: fn(&str) -> Arity) -> bool {
    option_values(args, option, arity).next().is_some()
}

fn enabled_boolean_option(args: &[String], option: &str, arity: fn(&str) -> Arity) -> bool {
    let mut index = 0;
    while index < args.len() && args[index] != "--" {
        let argument = args[index].as_str();
        if argument == option {
            return true;
        }
        if let Some(value) = argument
            .strip_prefix(option)
            .and_then(|rest| rest.strip_prefix('='))
        {
            // A disabled occurrence does not make a later duplicate safe.
            // Reject if any occurrence enables the option or has an
            // unrecognized value, independent of argument order.
            if value != "false" {
                return true;
            }
        }
        if argument.starts_with('-') && !argument.contains('=') {
            match arity(argument) {
                Arity::None => {}
                Arity::One => index = index.saturating_add(1),
                Arity::Many => {
                    index += 1;
                    while index < args.len() && !args[index].starts_with('-') {
                        index += 1;
                    }
                    continue;
                }
            }
        }
        index += 1;
    }
    false
}

fn option_values<'a>(
    args: &'a [String],
    option: &'a str,
    arity: fn(&str) -> Arity,
) -> impl Iterator<Item = &'a str> {
    let mut values = Vec::new();
    let mut index = 0;
    while index < args.len() && args[index] != "--" {
        let argument = args[index].as_str();
        if argument == option {
            values.push(args.get(index + 1).map(String::as_str).unwrap_or(""));
            index += 1;
        } else if let Some(value) = argument
            .strip_prefix(option)
            .and_then(|rest| rest.strip_prefix('='))
        {
            values.push(value);
        } else if argument.starts_with('-') && !argument.contains('=') {
            match arity(argument) {
                Arity::None => {}
                Arity::One => index = index.saturating_add(1),
                Arity::Many => {
                    index += 1;
                    while index < args.len() && !args[index].starts_with('-') {
                        index += 1;
                    }
                    continue;
                }
            }
        }
        index += 1;
    }
    values.into_iter()
}

pub(crate) fn opencode_server_command(args: &[String]) -> bool {
    matches!(
        first_command(args, opencode_option_arity),
        Some((_, "serve" | "web"))
    )
}

fn is_loopback_host(hostname: &str) -> bool {
    hostname.eq_ignore_ascii_case("localhost")
        || hostname.eq_ignore_ascii_case("localhost.")
        || hostname.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(args: &[&str]) -> Vec<String> {
        args.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn codex_rejects_remote_and_cloud_routes_without_matching_literals() {
        for args in [
            values(&["--remote", "wss://example.invalid"]),
            values(&["--remote=wss://example.invalid"]),
            values(&["-c", "model=fixture", "cloud", "list"]),
            values(&["-i", "image.png", "--enable", "fixture", "cloud", "list"]),
            values(&["remote-control", "start"]),
        ] {
            assert!(validate(&CODEX, &args).is_err(), "{args:?}");
        }
        for args in [
            values(&["exec", "cloud"]),
            values(&["exec", "--", "--remote", "fixture"]),
            values(&["--", "cloud"]),
            values(&["--remote-auth-token-env", "TOKEN", "exec", "hello"]),
            values(&["-i", "one.png", "cloud", "list"]),
        ] {
            assert!(validate(&CODEX, &args).is_ok(), "{args:?}");
        }
    }

    #[test]
    fn claude_rejects_only_exact_remote_or_cloud_modes() {
        for args in [
            values(&["--cloud"]),
            values(&["--cloud=session_1"]),
            values(&["--environment", "ccpool_1"]),
            values(&["--remote-control=fixture"]),
            values(&["--teleport", "session_1"]),
            values(&["--model", "sonnet", "ultrareview"]),
        ] {
            assert!(validate(&CLAUDE, &args).is_err(), "{args:?}");
        }
        for args in [
            values(&["--bg", "hello"]),
            values(&["attach", "local-id"]),
            values(&["--remote-control-session-name-prefix", "fixture", "hello"]),
            values(&["--system-prompt", "--cloud", "hello"]),
            values(&["--", "--cloud", "ultrareview"]),
        ] {
            assert!(validate(&CLAUDE, &args).is_ok(), "{args:?}");
        }
    }

    #[test]
    fn opencode_separates_remote_attach_from_server_exposure() {
        for args in [
            values(&["attach", "http://localhost:4096"]),
            values(&["run", "--attach", "http://localhost:4096", "hello"]),
            values(&["run", "--attach=http://localhost:4096", "hello"]),
        ] {
            assert!(validate(&OPENCODE, &args).is_err(), "{args:?}");
        }
        for args in [
            values(&["serve", "--hostname", "0.0.0.0"]),
            values(&["web", "--hostname=example.test"]),
            values(&["serve", "--mdns"]),
            values(&["serve", "--mdns=true"]),
            values(&["serve", "--mdns=unexpected"]),
            values(&["serve", "--mdns=0"]),
            values(&["serve", "--mdns", "false"]),
            values(&["serve", "--mdns=false", "--mdns=true"]),
            values(&["serve", "--mdns=false", "--mdns"]),
            values(&["serve", "--mdns=true", "--mdns=false"]),
            values(&["serve", "--hostname", "127.0.0.1", "--hostname=0.0.0.0"]),
        ] {
            let error = validate(&OPENCODE, &args).unwrap_err();
            assert!(error.contains("network-exposed"));
        }
        for args in [
            values(&["run", "--", "--attach", "literal"]),
            values(&["serve"]),
            values(&["serve", "--hostname", "127.0.0.1"]),
            values(&["web", "--hostname=::1"]),
            values(&["serve", "--mdns=false"]),
            values(&["serve", "--mdns=false", "--mdns=false"]),
            values(&["serve", "--prompt", "--mdns", "--hostname=localhost"]),
        ] {
            assert!(validate(&OPENCODE, &args).is_ok(), "{args:?}");
        }
    }

    #[test]
    fn pi_has_no_remote_execution_classification() {
        assert!(validate(&PI, &values(&["--", "--attach", "cloud"])).is_ok());
    }
}
