#[derive(Debug, Clone, PartialEq, Eq)]
struct SshInvocation {
    program: String,
    connection_args: Vec<String>,
    destination: String,
    destination_after_separator: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SshProbeSpec {
    program: String,
    args: Vec<String>,
    current_dir: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoteAgentProbe {
    Detected(crate::detect::Agent),
    NoAgent,
    Unavailable,
}

fn parse_ssh_invocation(process: &crate::platform::ForegroundProcess) -> Option<SshInvocation> {
    let argv = process.argv.as_ref()?;
    let program = argv.first()?.clone();
    let basename = std::path::Path::new(&program).file_name()?.to_str()?;
    if !basename.eq_ignore_ascii_case("ssh") && !basename.eq_ignore_ascii_case("ssh.exe") {
        return None;
    }

    let mut connection_args = Vec::new();
    let mut destination_after_separator = false;
    let mut index = 1;
    while let Some(argument) = argv.get(index) {
        if argument == "--" {
            destination_after_separator = true;
            index += 1;
            break;
        }
        if !argument.starts_with('-') || argument == "-" {
            break;
        }

        let option = argument.as_bytes().get(1).copied()? as char;
        let takes_value = matches!(
            option,
            'B' | 'b'
                | 'c'
                | 'D'
                | 'E'
                | 'e'
                | 'F'
                | 'I'
                | 'i'
                | 'J'
                | 'L'
                | 'l'
                | 'm'
                | 'O'
                | 'o'
                | 'P'
                | 'p'
                | 'Q'
                | 'R'
                | 'S'
                | 'W'
                | 'w'
        );
        if takes_value {
            if matches!(option, 'F' | 'J' | 'O' | 'Q' | 'S' | 'W') {
                return None;
            }
            let preserve = !matches!(option, 'D' | 'E' | 'e' | 'L' | 'R' | 'w');
            if preserve {
                connection_args.push(argument.clone());
            }
            let requires_separate_value = argument.len() == 2;
            index += 1;
            if requires_separate_value {
                let value = argv.get(index)?.clone();
                if preserve {
                    connection_args.push(value);
                }
                index += 1;
            }
            continue;
        }

        let mut preserved_flags = String::from("-");
        for flag in argument[1..].chars() {
            match flag {
                '4' | '6' | 'C' => preserved_flags.push(flag),
                'A' | 'a' | 'g' | 'K' | 'k' | 'n' | 'q' | 'T' | 't' | 'v' | 'X' | 'x' | 'Y'
                | 'y' => {}
                'f' | 'G' | 'M' | 'N' | 's' | 'V' => return None,
                _ => return None,
            }
        }
        if preserved_flags.len() > 1 {
            connection_args.push(preserved_flags);
        }
        index += 1;
    }

    Some(SshInvocation {
        program,
        connection_args,
        destination: argv.get(index)?.clone(),
        destination_after_separator,
    })
}

fn parse_remote_probe_output(output: &str) -> RemoteAgentProbe {
    let mut matched = None;
    let mut completed = false;
    let mut remote_sessions = std::collections::HashSet::new();
    for line in output.lines() {
        let mut fields = line.split_whitespace();
        match fields.next() {
            Some("HERDR_REMOTE_SESSION_V1") => {
                let Some(session) = fields.next() else {
                    return RemoteAgentProbe::Unavailable;
                };
                let Ok(session) = session.parse::<u32>() else {
                    return RemoteAgentProbe::Unavailable;
                };
                if fields.next().is_some() {
                    return RemoteAgentProbe::Unavailable;
                }
                remote_sessions.insert(session);
            }
            Some("HERDR_REMOTE_AGENT_V1") => {
                let Some(agent) = fields.next().and_then(crate::detect::parse_agent_label) else {
                    return RemoteAgentProbe::Unavailable;
                };
                if !matches!(
                    agent,
                    crate::detect::Agent::Claude | crate::detect::Agent::Codex
                ) {
                    return RemoteAgentProbe::Unavailable;
                }
                let Some(pid) = fields.next() else {
                    return RemoteAgentProbe::Unavailable;
                };
                if pid.parse::<u32>().is_err() || fields.next().is_some() {
                    return RemoteAgentProbe::Unavailable;
                }
                if matched.is_some_and(|previous| previous != agent) {
                    return RemoteAgentProbe::Unavailable;
                }
                matched = Some(agent);
            }
            Some("HERDR_REMOTE_PROBE_V1") => {
                if completed || fields.next() != Some("OK") || fields.next().is_some() {
                    return RemoteAgentProbe::Unavailable;
                }
                completed = true;
            }
            _ => continue,
        }
    }
    // One TCP transport can carry multiple ControlMaster sessions. Refuse to
    // attribute an agent unless the tuple identifies exactly one remote TTY.
    if !completed || remote_sessions.len() != 1 {
        RemoteAgentProbe::Unavailable
    } else if let Some(agent) = matched {
        RemoteAgentProbe::Detected(agent)
    } else {
        RemoteAgentProbe::NoAgent
    }
}

fn build_ssh_probe_spec(
    process: &crate::platform::ForegroundProcess,
    connections: &[crate::platform::ProcessTcpConnection],
) -> Option<SshProbeSpec> {
    let invocation = parse_ssh_invocation(process)?;
    let [connection] = connections else {
        return None;
    };
    let mut args = vec![
        "-o".to_string(),
        "BatchMode=yes".to_string(),
        "-o".to_string(),
        "ConnectTimeout=3".to_string(),
        "-o".to_string(),
        "ConnectionAttempts=1".to_string(),
        "-o".to_string(),
        "ClearAllForwardings=yes".to_string(),
        "-o".to_string(),
        "ForwardAgent=no".to_string(),
        "-o".to_string(),
        "ForwardX11=no".to_string(),
        "-o".to_string(),
        "PermitLocalCommand=no".to_string(),
        "-o".to_string(),
        "RemoteCommand=none".to_string(),
        "-o".to_string(),
        "SessionType=default".to_string(),
        "-o".to_string(),
        "Tunnel=no".to_string(),
        "-o".to_string(),
        "ControlMaster=no".to_string(),
        "-o".to_string(),
        "ControlPath=none".to_string(),
        "-o".to_string(),
        "ControlPersist=no".to_string(),
        "-o".to_string(),
        "ForkAfterAuthentication=no".to_string(),
        "-o".to_string(),
        "ProxyCommand=none".to_string(),
        "-o".to_string(),
        "ProxyJump=none".to_string(),
        "-o".to_string(),
        "KnownHostsCommand=none".to_string(),
        "-o".to_string(),
        "LocalCommand=none".to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=yes".to_string(),
        "-o".to_string(),
        "UpdateHostKeys=no".to_string(),
        "-F".to_string(),
        "/dev/null".to_string(),
    ];
    args.extend(invocation.connection_args);
    args.push("-T".to_string());
    if invocation.destination_after_separator {
        args.push("--".to_string());
    }
    args.push(invocation.destination);
    args.push(remote_probe_command(connection));
    Some(SshProbeSpec {
        program: invocation.program,
        args,
        current_dir: crate::platform::process_cwd(process.pid)
            .filter(|path| path.is_absolute() && path.is_dir()),
    })
}

fn remote_probe_command(connection: &crate::platform::ProcessTcpConnection) -> String {
    let expected_connection = format!(
        "{} {} {} {}",
        connection.local_address,
        connection.local_port,
        connection.remote_address,
        connection.remote_port
    );
    let expected_connection = shell_quote(&expected_connection);
    let script = REMOTE_PROBE_SCRIPT.replace("@EXPECTED_CONNECTION@", &expected_connection);
    format!("/bin/sh -c {}", shell_quote(&script))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

const REMOTE_PROBE_SCRIPT: &str = r#"expected_connection=@EXPECTED_CONNECTION@
[ -d /proc ] || exit 0
remote_uid=$(id -u 2>/dev/null) || exit 0
herdr_process_fields() {
    herdr_stat=$(cat "$1/stat" 2>/dev/null) || return 1
    herdr_rest=${herdr_stat##*) }
    set -- $herdr_rest
    [ "$#" -ge 6 ] || return 1
    herdr_pgrp=$3
    herdr_session=$4
    herdr_tpgid=$6
    [ -n "$herdr_pgrp" ] && [ -n "$herdr_session" ] && [ -n "$herdr_tpgid" ]
}
herdr_env_value() {
    herdr_environment=$({ tr '\000' '\n' < "$1/environ"; } 2>/dev/null) || return 1
    printf '%s\n' "$herdr_environment" | sed -n "s/^$2=//p" | head -n 1
}
herdr_same_user() {
    herdr_process_uid=
    while read -r herdr_status_key herdr_status_value herdr_status_rest; do
        if [ "$herdr_status_key" = "Uid:" ]; then
            herdr_process_uid=$herdr_status_value
            break
        fi
    done < "$1/status" 2>/dev/null
    [ "$herdr_process_uid" = "$remote_uid" ]
}
herdr_shpool_sessions=
herdr_connection_found=
for proc_dir in /proc/[0-9]*; do
    IFS= read -r comm < "$proc_dir/comm" || continue
    case "$comm" in
        bash|claude|codex|dash|fish|ksh|nu|sh|shpool|tcsh|xonsh|zsh) ;;
        *) continue ;;
    esac
    herdr_same_user "$proc_dir" || continue
    ssh_connection=$(herdr_env_value "$proc_dir" SSH_CONNECTION) || continue
    [ "$ssh_connection" = "$expected_connection" ] || continue
    herdr_process_fields "$proc_dir" || continue
    [ "$herdr_tpgid" != "-1" ] || continue
    herdr_connection_found=1
    printf 'HERDR_REMOTE_SESSION_V1 %s\n' "$herdr_session"
    [ "$herdr_pgrp" = "$herdr_tpgid" ] || continue
    case "$comm" in
        claude|codex)
            pid=${proc_dir##*/}
            printf 'HERDR_REMOTE_AGENT_V1 %s %s\n' "$comm" "$pid"
            ;;
        shpool)
            shpool_session=$(herdr_env_value "$proc_dir" SHPOOL_SESSION_NAME) || continue
            [ -n "$shpool_session" ] || continue
            herdr_shpool_sessions="${herdr_shpool_sessions}
${shpool_session}"
            ;;
    esac
done
if [ -n "$herdr_shpool_sessions" ]; then
    for proc_dir in /proc/[0-9]*; do
        IFS= read -r comm < "$proc_dir/comm" || continue
        case "$comm" in
            claude|codex) ;;
            *) continue ;;
        esac
        herdr_same_user "$proc_dir" || continue
        shpool_session=$(herdr_env_value "$proc_dir" SHPOOL_SESSION_NAME) || continue
        [ -n "$shpool_session" ] || continue
        printf '%s\n' "$herdr_shpool_sessions" | grep -F -x -- "$shpool_session" >/dev/null 2>&1 || continue
        herdr_process_fields "$proc_dir" || continue
        [ "$herdr_tpgid" != "-1" ] || continue
        [ "$herdr_pgrp" = "$herdr_tpgid" ] || continue
        pid=${proc_dir##*/}
        printf 'HERDR_REMOTE_AGENT_V1 %s %s\n' "$comm" "$pid"
    done
fi
[ "$herdr_connection_found" = "1" ] || exit 0
printf 'HERDR_REMOTE_PROBE_V1 OK\n'
"#;

fn probe_remote_agent_with(
    process: &crate::platform::ForegroundProcess,
    connections: &[crate::platform::ProcessTcpConnection],
    run: impl FnOnce(&SshProbeSpec) -> Option<String>,
) -> RemoteAgentProbe {
    let Some(spec) = build_ssh_probe_spec(process, connections) else {
        return RemoteAgentProbe::Unavailable;
    };
    let Some(output) = run(&spec) else {
        return RemoteAgentProbe::Unavailable;
    };
    parse_remote_probe_output(&output)
}

pub(crate) async fn probe_remote_agent(
    process: crate::platform::ForegroundProcess,
) -> RemoteAgentProbe {
    tokio::task::spawn_blocking(move || {
        let connections = crate::platform::process_tcp_connections(process.pid);
        probe_remote_agent_with(&process, &connections, run_ssh_probe)
    })
    .await
    .unwrap_or(RemoteAgentProbe::Unavailable)
}

fn run_ssh_probe(spec: &SshProbeSpec) -> Option<String> {
    let mut command = std::process::Command::new(&spec.program);
    command
        .args(&spec.args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    if let Some(current_dir) = &spec.current_dir {
        command.current_dir(current_dir);
    }
    let mut child = command.spawn().ok()?;
    let started = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let output = child.wait_with_output().ok()?;
                if !status.success() || output.stdout.len() > 64 * 1024 {
                    return None;
                }
                return String::from_utf8(output.stdout).ok();
            }
            Ok(None) if started.elapsed() < std::time::Duration::from_secs(4) => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Ok(None) | Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_invocation_parser_preserves_connection_options_and_target() {
        let process = crate::platform::ForegroundProcess {
            pid: 42,
            name: "ssh".to_string(),
            argv0: None,
            argv: Some(vec![
                "/usr/bin/ssh".to_string(),
                "-p".to_string(),
                "2222".to_string(),
                "-i".to_string(),
                "/tmp/test key".to_string(),
                "joel@example.test".to_string(),
            ]),
            cmdline: None,
        };

        let invocation = parse_ssh_invocation(&process).expect("valid SSH invocation");

        assert_eq!(invocation.program, "/usr/bin/ssh");
        assert_eq!(
            invocation.connection_args,
            ["-p", "2222", "-i", "/tmp/test key"]
        );
        assert_eq!(invocation.destination, "joel@example.test");
    }

    #[test]
    fn remote_probe_output_accepts_one_foreground_agent_kind() {
        let output = "shell startup noise\nHERDR_REMOTE_SESSION_V1 2465011\nHERDR_REMOTE_AGENT_V1 claude 1611184\nHERDR_REMOTE_AGENT_V1 claude 1611185\nHERDR_REMOTE_PROBE_V1 OK\n";

        assert_eq!(
            parse_remote_probe_output(output),
            RemoteAgentProbe::Detected(crate::detect::Agent::Claude)
        );
    }

    #[test]
    fn remote_probe_confirms_absence_only_with_completion_marker() {
        assert_eq!(parse_remote_probe_output(""), RemoteAgentProbe::Unavailable);
        assert_eq!(
            parse_remote_probe_output("HERDR_REMOTE_PROBE_V1 OK\n"),
            RemoteAgentProbe::Unavailable
        );
        assert_eq!(
            parse_remote_probe_output(
                "HERDR_REMOTE_SESSION_V1 2465011\nHERDR_REMOTE_PROBE_V1 OK\n"
            ),
            RemoteAgentProbe::NoAgent
        );
    }

    #[test]
    fn remote_probe_rejects_multiple_sessions_on_one_transport() {
        let output = "HERDR_REMOTE_SESSION_V1 2465011\nHERDR_REMOTE_SESSION_V1 2465999\nHERDR_REMOTE_AGENT_V1 claude 1611184\nHERDR_REMOTE_PROBE_V1 OK\n";

        assert_eq!(
            parse_remote_probe_output(output),
            RemoteAgentProbe::Unavailable
        );
    }

    #[test]
    fn ssh_probe_spec_targets_the_exact_local_connection_noninteractively() {
        let process = crate::platform::ForegroundProcess {
            pid: 42,
            name: "ssh".to_string(),
            argv0: None,
            argv: Some(vec![
                "/usr/bin/ssh".to_string(),
                "-p".to_string(),
                "2222".to_string(),
                "joel@example.test".to_string(),
            ]),
            cmdline: None,
        };
        let connection = crate::platform::ProcessTcpConnection {
            local_address: "192.168.0.242".parse().unwrap(),
            local_port: 38_848,
            remote_address: "192.168.0.213".parse().unwrap(),
            remote_port: 2222,
        };

        let spec = build_ssh_probe_spec(&process, &[connection]).expect("probeable SSH process");

        assert_eq!(spec.program, "/usr/bin/ssh");
        assert!(spec
            .args
            .windows(4)
            .any(|arguments| { arguments == ["-p", "2222", "-T", "joel@example.test"] }));
        assert!(spec.args.last().is_some_and(|command| {
            command.starts_with("/bin/sh -c '")
                && command.contains("192.168.0.242 38848 192.168.0.213 2222")
        }));
    }

    #[cfg(unix)]
    #[test]
    fn remote_probe_command_is_valid_posix_shell() {
        let connection = crate::platform::ProcessTcpConnection {
            local_address: "203.0.113.10".parse().unwrap(),
            local_port: 61_001,
            remote_address: "203.0.113.11".parse().unwrap(),
            remote_port: 61_002,
        };
        let command = remote_probe_command(&connection);

        let output = std::process::Command::new("/bin/sh")
            .args(["-c", &command])
            .output()
            .expect("POSIX shell should execute the wrapped probe");

        assert!(output.status.success());
        assert!(output.stdout.is_empty());
    }

    #[test]
    fn remote_agent_probe_returns_the_process_reported_by_the_exact_connection() {
        let process = crate::platform::ForegroundProcess {
            pid: 42,
            name: "ssh".to_string(),
            argv0: None,
            argv: Some(vec!["ssh".to_string(), "joel@example.test".to_string()]),
            cmdline: None,
        };
        let connection = crate::platform::ProcessTcpConnection {
            local_address: "192.168.0.242".parse().unwrap(),
            local_port: 38_848,
            remote_address: "192.168.0.213".parse().unwrap(),
            remote_port: 22,
        };

        let agent = probe_remote_agent_with(&process, &[connection], |_| {
            Some(
                "HERDR_REMOTE_SESSION_V1 2465011\nHERDR_REMOTE_AGENT_V1 codex 77\nHERDR_REMOTE_PROBE_V1 OK\n"
                    .to_string(),
            )
        });

        assert_eq!(
            agent,
            RemoteAgentProbe::Detected(crate::detect::Agent::Codex)
        );
    }

    #[test]
    fn ssh_probe_forces_noninteractive_safety_before_user_options() {
        let process = crate::platform::ForegroundProcess {
            pid: 42,
            name: "ssh".to_string(),
            argv0: None,
            argv: Some(vec![
                "ssh".to_string(),
                "-o".to_string(),
                "BatchMode=no".to_string(),
                "joel@example.test".to_string(),
            ]),
            cmdline: None,
        };
        let connection = crate::platform::ProcessTcpConnection {
            local_address: "192.168.0.242".parse().unwrap(),
            local_port: 38_848,
            remote_address: "192.168.0.213".parse().unwrap(),
            remote_port: 22,
        };

        let spec = build_ssh_probe_spec(&process, &[connection]).expect("probeable SSH process");

        assert_eq!(&spec.args[..2], ["-o", "BatchMode=yes"]);
        let user_batch_mode = spec
            .args
            .windows(2)
            .position(|pair| pair == ["-o", "BatchMode=no"])
            .expect("original SSH options stay available");
        assert!(user_batch_mode > 0);
    }

    #[test]
    fn ssh_invocation_end_of_options_does_not_displace_probe_target() {
        let process = crate::platform::ForegroundProcess {
            pid: 42,
            name: "ssh".to_string(),
            argv0: None,
            argv: Some(vec![
                "ssh".to_string(),
                "--".to_string(),
                "-host.example.test".to_string(),
            ]),
            cmdline: None,
        };
        let connection = crate::platform::ProcessTcpConnection {
            local_address: "192.168.0.242".parse().unwrap(),
            local_port: 38_848,
            remote_address: "192.168.0.213".parse().unwrap(),
            remote_port: 22,
        };

        let spec = build_ssh_probe_spec(&process, &[connection]).expect("probeable SSH process");

        assert_eq!(
            &spec.args[spec.args.len() - 3..spec.args.len() - 1],
            ["--", "-host.example.test"]
        );
    }

    #[test]
    fn ssh_probe_rejects_control_and_forward_only_invocations() {
        for unsafe_args in [
            vec!["-O", "exit", "joel@example.test"],
            vec!["-W", "internal.example.test:22", "jump.example.test"],
            vec!["-N", "joel@example.test"],
            vec!["-F", "/tmp/ssh-config", "joel@example.test"],
            vec!["-J", "jump.example.test", "joel@example.test"],
            vec!["-S", "/tmp/control", "joel@example.test"],
        ] {
            let process = crate::platform::ForegroundProcess {
                pid: 42,
                name: "ssh".to_string(),
                argv0: None,
                argv: Some(
                    std::iter::once("ssh".to_string())
                        .chain(unsafe_args.into_iter().map(str::to_string))
                        .collect(),
                ),
                cmdline: None,
            };
            let connection = crate::platform::ProcessTcpConnection {
                local_address: "192.168.0.242".parse().unwrap(),
                local_port: 38_848,
                remote_address: "192.168.0.213".parse().unwrap(),
                remote_port: 22,
            };

            assert!(build_ssh_probe_spec(&process, &[connection]).is_none());
        }
    }

    #[test]
    fn ssh_probe_drops_forwarding_flags_and_disables_configured_side_effects() {
        let process = crate::platform::ForegroundProcess {
            pid: 42,
            name: "ssh".to_string(),
            argv0: None,
            argv: Some(vec![
                "ssh".to_string(),
                "-A".to_string(),
                "-L".to_string(),
                "1234:internal.example.test:22".to_string(),
                "joel@example.test".to_string(),
            ]),
            cmdline: None,
        };
        let connection = crate::platform::ProcessTcpConnection {
            local_address: "192.168.0.242".parse().unwrap(),
            local_port: 38_848,
            remote_address: "192.168.0.213".parse().unwrap(),
            remote_port: 22,
        };

        let spec = build_ssh_probe_spec(&process, &[connection]).expect("probeable SSH process");

        assert!(!spec.args.iter().any(|argument| argument == "-A"));
        assert!(!spec.args.iter().any(|argument| argument == "-L"));
        for safety_option in [
            "ClearAllForwardings=yes",
            "ControlMaster=no",
            "ControlPath=none",
            "ControlPersist=no",
            "ForkAfterAuthentication=no",
            "ForwardAgent=no",
            "ForwardX11=no",
            "PermitLocalCommand=no",
            "ProxyCommand=none",
            "ProxyJump=none",
            "RemoteCommand=none",
            "SessionType=default",
            "Tunnel=no",
        ] {
            assert!(spec.args.iter().any(|argument| argument == safety_option));
        }
    }

    #[test]
    fn remote_probe_rejects_ambiguous_agent_kinds() {
        let output = "HERDR_REMOTE_SESSION_V1 2465011\nHERDR_REMOTE_AGENT_V1 claude 1611184\nHERDR_REMOTE_AGENT_V1 codex 1611199\nHERDR_REMOTE_PROBE_V1 OK\n";

        assert_eq!(
            parse_remote_probe_output(output),
            RemoteAgentProbe::Unavailable
        );
    }
}
