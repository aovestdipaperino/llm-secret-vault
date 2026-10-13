//! Guard hook rule table.

use llm_secret_vault::hook::{Decision, check_command, check_run, evaluate};

const DENY: &[&str] = &[
    "security find-generic-password -s foo -w",
    "security find-internet-password -gs github.com",
    "secret-tool lookup service nas",
    "powershell -c Get-StoredCredential -Target nas",
    "cmdkey /list:nas /pass",
    "cat /proc/1234/environ",
    "lsv run PW=nas-root -- sh -c 'echo $PW'",
    "lsv run PW=nas-root -- sh -c 'printf %s \"$PW\" | base64'",
    "lsv run T=tok -- sh -c 'echo ${T} | rev'",
    "lsv run T=tok -- sh -c 'printf %s $T | xxd'",
    "lsv run -- echo {{nas-root}}",
    "lsv run PW=nas-root -- printenv",
    "lsv run PW=nas-root -- printenv PW",
    "lsv run PW=nas-root -- env",
    "lsv run PW=nas-root -- sh -c 'set'",
    "lsv run PW=nas-root -- sh -c 'export -p'",
    "cd /tmp && lsv run PW=nas-root -- sh -c 'ls; echo $PW'",
    "lsv run A=a -- ls && lsv run PW=b -- printenv",
    "./target/release/lsv run PW=b -- printenv",
    "/usr/local/bin/lsv run PW=b -- sh -c 'echo $PW'",
    "lsv run PW=b -- /bin/sh -c 'echo $PW'",
    "lsv run PW=b -- bash -lc 'echo $PW'",
    "bash -c \"lsv run T=x -- printenv\"",
    "sh -c 'lsv run T=x -- printenv'",
    "lsv run PW=b -- /usr/bin/env -0",
    "lsv run PW=b -- env -i",
    "lsv run PW=b -- /usr/bin/printenv",
    "lsv run PW=b -- sh -c 'export'",
    "security -q find-generic-password -s foo -w",
    "lsv run T=x -- sh -c 'echo $T > /dev/stdout'",
    "lsv run T=x -- sh -c 'echo $T >&2'",
    "lsv run T=x -- sh -c 'printf %s $T >/dev/tty'",
    "lsv run T=x -- sh -c 'echo $T >> /dev/stderr'",
    "lsv run T=x -- sh -c 'echo $T 1>&2'",
    "lsv run T=x -- sh -c 'echo $T > /dev/fd/1'",
    "lsv run T=x -- sh -c 'echo $T 2>&1'",
    // --no-touch is for the human at a terminal only.
    "lsv run --no-touch T=resend -- curl https://x",
    "lsv run T=resend --no-touch -- curl https://x",
    "cd /tmp && /usr/local/bin/lsv run \"--no-touch\" T=x -- true",
    "bash -c 'lsv run --no-touch T=x -- true'",
    // Touch ID settings cannot be changed from the agent.
    "LSV_TOUCH_ID=off lsv run T=x -- curl https://x",
    "export LSV_TOUCH_ID=off",
    "unset LSV_TOUCH_ID",
    "env -u LSV_TOUCH_ID lsv run T=x -- true",
    "LSV_TOUCH_ID_TTL=3600 lsv mcp",
    // Encoders and echo/printf by path.
    "lsv run T=x -- sh -c '/bin/echo $T'",
    "lsv run T=x -- sh -c 'printf %s $T | /usr/bin/base64'",
    "lsv run T=x -- sh -c '/usr/bin/printf %s $T'",
    // Redirects that still reach the agent.
    "lsv run T=x -- sh -c 'echo $T > /dev/pts/0'",
    "lsv run T=x -- sh -c 'echo $T > /proc/self/fd/1'",
    "lsv run T=x -- bash -c 'echo $T > >(cat)'",
    "lsv run T=x -- sh -c 'echo $T > $OUT'",
];

const ALLOW: &[&str] = &[
    "ls -la",
    "echo hello",
    "cargo test 2>&1 | tail",
    "security find-generic-password -s foo",
    "lsv run HF_TOKEN=hf-token -- huggingface-cli upload repo file",
    "lsv run T=tok -- sh -c 'printf %s \"$T\" | docker login --password-stdin'",
    "lsv run T=tok -- sh -c 'curl -H \"Authorization: Bearer $T\" https://x > out.json'",
    "lsv run PW=nas-root -- sshpass -e ssh root@nas",
    "lsv run -- curl -H 'Bearer {{resend}}' https://api.resend.com",
    "lsv run PW=nas-root -- env FOO=1 ./deploy.sh",
    "lsv list",
    "lsv run T=x -- sh -c 'echo $T > f'",
    "lsv run T=x -- sh -c 'printf %s \"$T\" >> f'",
    "lsv run T=x -- sh -c 'echo $T >f 2>&1'",
    "lsv run T=tok -- sh -c 'echo $TERM'",
    "cmdkey /add:nas /user:u /pass:x",
    "echo $HOME",
    "lsv run T=x -- curl -H \"Authorization: Bearer $T\" https://x",
    "lsv run T=x -- sh -c 'echo $T > /dev/null'",
    "lsv run T=x -- sh -c '/bin/echo $T > out.txt'",
    "lsv info resend",
];

#[test]
fn denies_leaky_commands() {
    for command in DENY {
        assert!(
            matches!(check_command(command), Decision::Deny(_)),
            "should deny: {command}"
        );
    }
}

#[test]
fn allows_normal_commands() {
    for command in ALLOW {
        assert_eq!(
            check_command(command),
            Decision::Allow,
            "should allow: {command}"
        );
    }
}

#[test]
fn evaluates_hook_json() {
    let deny = r#"{"tool_name":"Bash","tool_input":{"command":"lsv run X=a -- printenv"}}"#;
    assert!(matches!(evaluate(deny).unwrap(), Decision::Deny(_)));
    let plank = r#"{"tool_name":"bash","tool_input":{"command":"lsv run X=a -- printenv"}}"#;
    assert!(matches!(evaluate(plank).unwrap(), Decision::Deny(_)));
    let other_tool = r#"{"tool_name":"Read","tool_input":{"file_path":"/etc/hosts"}}"#;
    assert_eq!(evaluate(other_tool).unwrap(), Decision::Allow);
    assert!(evaluate("not json").is_err());
    assert!(evaluate(r#"{"tool_name":"Bash","tool_input":{}}"#).is_err());
}

#[test]
fn deny_reasons_name_the_rule() {
    let reason = |c: &str| match check_command(c) {
        Decision::Deny(r) => r,
        Decision::Allow => panic!("should deny: {c}"),
    };
    assert_eq!(
        reason("lsv run --no-touch T=x -- true"),
        "--no-touch skips Touch ID and is for your own terminal only"
    );
    assert_eq!(
        reason("export LSV_TOUCH_ID=off"),
        "changing LSV_TOUCH_ID would bypass Touch ID approval"
    );
    let run = argv(&[
        "lsv",
        "run",
        "T=resend",
        "--",
        "sh",
        "-c",
        "printf %s $T | base64",
    ]);
    assert_eq!(
        check_run(&run, &[]),
        Decision::Deny("secret_run must not start lsv itself".to_owned())
    );
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|p| (*p).to_owned()).collect()
}

#[test]
fn check_run_denies_leaky_argv() {
    let cases: &[(&[&str], &[&str])] = &[
        (&["sh", "-c", "printf %s $T | base64"], &["T"]),
        (&["sh", "-c", "echo $T"], &["T"]),
        (&["printenv"], &["T"]),
        (&["env"], &["T"]),
        (&["echo", "{{tok}}"], &[]),
        (&["security", "find-generic-password", "-s", "x", "-w"], &[]),
        (&["sh", "-c", "echo ${T} | xxd"], &["T"]),
        (&["sh", "-c", "echo $T >/dev/stderr"], &["T"]),
        (&["sh", "-c", "echo $T 1>&2"], &["T"]),
        (&["sh", "-c", "printf %s $T > /dev/stdout"], &["T"]),
        (
            &[
                "lsv",
                "run",
                "T=resend",
                "--",
                "sh",
                "-c",
                "printf %s $T | base64",
            ],
            &[],
        ),
        (&["/usr/local/bin/lsv", "list"], &[]),
        (
            &["sh", "-c", "lsv run --no-touch T=x -- curl https://x"],
            &[],
        ),
        (&["sh", "-c", "./target/release/lsv run T=x -- true"], &[]),
        (&["env", "LSV_TOUCH_ID=off", "true"], &[]),
        (&["true"], &["LSV_TOUCH_ID"]),
        (&["sh", "-c", "/bin/echo $T"], &["T"]),
        (&["sh", "-c", "echo $T > /dev/pts/0"], &["T"]),
        (&["sh", "-c", "echo $T >/proc/self/fd/1"], &["T"]),
        (&["bash", "-c", "echo $T > >(cat)"], &["T"]),
    ];
    for (parts, vars) in cases {
        assert!(
            matches!(check_run(&argv(parts), vars), Decision::Deny(_)),
            "should deny: {parts:?}"
        );
    }
}

#[test]
fn check_run_allows_normal_argv() {
    let cases: &[(&[&str], &[&str])] = &[
        (
            &["curl", "-H", "Authorization: Bearer {{tok}}", "https://x"],
            &[],
        ),
        (
            &[
                "sh",
                "-c",
                "printf %s \"$T\" | docker login --password-stdin",
            ],
            &["T"],
        ),
        (&["sshpass", "-e", "ssh", "root@nas"], &["PW"]),
        (&["sh", "-c", "echo $T > f"], &["T"]),
        (&["ls"], &[]),
        (&["sh", "-c", "echo $T > /dev/null"], &["T"]),
        (&["curl", "https://lsv.example.com"], &[]),
    ];
    for (parts, vars) in cases {
        assert_eq!(
            check_run(&argv(parts), vars),
            Decision::Allow,
            "should allow: {parts:?}"
        );
    }
}
