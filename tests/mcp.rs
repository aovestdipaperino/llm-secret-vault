//! MCP server tests: protocol handling and tools, with a no-leak check on every response.

use std::collections::BTreeSet;
use std::io::Cursor;
use std::sync::{Arc, Mutex};

use llm_secret_vault::approve::Approver;
use llm_secret_vault::capture::Clipboard;
use llm_secret_vault::mcp::{PROTOCOL_VERSION, Server};
use llm_secret_vault::{Error, ErrorKind, Result, SecretName, Vault};
use serde_json::{Value, json};

const SECRET: &str = "re_live_0123456789abcdef";

#[derive(Debug)]
struct FixedClipboard(Option<String>);

impl Clipboard for FixedClipboard {
    fn text(&mut self) -> Result<Option<String>> {
        Ok(self.0.clone())
    }
    fn clear(&mut self) -> Result<()> {
        self.0 = None;
        Ok(())
    }
}

fn server() -> Server {
    Server::new(
        Vault::in_memory(),
        Box::new(|| Ok(Box::new(FixedClipboard(Some(SECRET.to_owned()))) as Box<dyn Clipboard>)),
    )
}

fn call(server: &Server, id: u64, method: &str, params: &Value) -> Value {
    let response = server
        .handle(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
        .expect("requests get responses");
    assert!(!response.to_string().contains(SECRET), "leak in {response}");
    response
}

fn tool(server: &Server, name: &str, arguments: &Value) -> (String, bool) {
    let response = call(
        server,
        1,
        "tools/call",
        &json!({"name": name, "arguments": arguments}),
    );
    let result = &response["result"];
    (
        result["content"][0]["text"].as_str().unwrap().to_owned(),
        result["isError"].as_bool().unwrap(),
    )
}

#[test]
fn initialize_echoes_supported_protocol_version() {
    let response = call(
        &server(),
        1,
        "initialize",
        &json!({"protocolVersion": "2025-03-26", "capabilities": {}}),
    );
    assert_eq!(response["result"]["protocolVersion"], "2025-03-26");
    assert_eq!(response["result"]["serverInfo"]["name"], "llm-secret-vault");
    assert!(response["result"]["capabilities"]["tools"].is_object());
}

#[test]
fn initialize_falls_back_for_unknown_protocol_version() {
    let response = call(
        &server(),
        1,
        "initialize",
        &json!({"protocolVersion": "1999-01-01"}),
    );
    assert_eq!(response["result"]["protocolVersion"], PROTOCOL_VERSION);
}

#[test]
fn ping_and_id_echo() {
    let response = call(&server(), 42, "ping", &json!({}));
    assert_eq!(response["id"], 42);
    assert_eq!(response["result"], json!({}));
    let response = server()
        .handle(&json!({"jsonrpc": "2.0", "id": "abc", "method": "ping"}))
        .unwrap();
    assert_eq!(response["id"], "abc");
}

#[test]
fn invalid_requests_get_32600() {
    let server = server();
    for (message, id) in [
        (json!(42), Value::Null),
        (
            json!([{"jsonrpc": "2.0", "id": 1, "method": "ping"}]),
            Value::Null,
        ),
        (
            json!({"jsonrpc": "2.0", "id": [1], "method": "ping"}),
            Value::Null,
        ),
        (
            json!({"jsonrpc": "2.0", "id": null, "method": "ping"}),
            Value::Null,
        ),
        (json!({"id": 5, "method": "ping"}), json!(5)),
        (
            json!({"jsonrpc": "1.0", "id": 6, "method": "ping"}),
            json!(6),
        ),
        (json!({"jsonrpc": "2.0", "id": 8}), json!(8)),
    ] {
        let response = server.handle(&message).expect("error response");
        assert_eq!(response["error"]["code"], -32600, "{message}");
        assert_eq!(response["id"], id, "{message}");
    }
    assert!(server.handle(&json!({"method": "ping"})).is_none());
}

#[test]
fn tools_call_needs_params_and_name() {
    let server = server();
    for params in [None, Some(json!({"arguments": {}}))] {
        let mut message = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call"});
        if let Some(params) = params {
            message["params"] = params;
        }
        assert_eq!(server.handle(&message).unwrap()["error"]["code"], -32602);
    }
}

#[test]
fn generate_refuses_existing_name_without_overwrite() {
    let server = server();
    let (_, is_error) = tool(&server, "secret_generate", &json!({"name": "db"}));
    assert!(!is_error);
    let (_, is_error) = tool(&server, "secret_generate", &json!({"name": "db"}));
    assert!(is_error);
    let (_, is_error) = tool(
        &server,
        "secret_generate",
        &json!({"name": "db", "overwrite": true}),
    );
    assert!(!is_error);
}

#[cfg(unix)]
#[test]
fn run_rejects_unknown_secret_and_bad_env_var_without_spawning() {
    let server = server();
    let marker = std::env::temp_dir().join(format!("lsv-mcp-marker-{}", std::process::id()));
    let _ = std::fs::remove_file(&marker);
    let touch = format!("touch {}", marker.display());
    let (text, is_error) = tool(
        &server,
        "secret_run",
        &json!({"argv": ["sh", "-c", touch], "env": {"T": "missing"}}),
    );
    assert!(is_error);
    assert_eq!(text, "no secret named `missing`");
    tool(&server, "secret_capture", &json!({"name": "resend"}));
    let (_, is_error) = tool(
        &server,
        "secret_run",
        &json!({"argv": ["sh", "-c", touch], "env": {"1BAD": "resend"}}),
    );
    assert!(is_error);
    assert!(!marker.exists());
}

#[test]
fn run_rejects_out_of_range_limits() {
    let server = server();
    for (field, value) in [
        ("timeout_s", json!(0)),
        ("timeout_s", json!(3601)),
        ("timeout_s", json!(u64::MAX)),
        ("max_output_kb", json!(0)),
        ("max_output_kb", json!(1025)),
        ("max_output_kb", json!(u64::MAX)),
    ] {
        let mut args = json!({"argv": ["true"]});
        args[field] = value;
        let (text, is_error) = tool(&server, "secret_run", &args);
        assert!(is_error, "{field}");
        assert!(
            text.starts_with(&format!("{field} must be between")),
            "{text}"
        );
    }
}

#[test]
fn notifications_get_no_response() {
    assert!(
        server()
            .handle(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .is_none()
    );
}

#[test]
fn lists_exactly_the_five_tools() {
    let response = call(&server(), 1, "tools/list", &json!({}));
    let mut names: Vec<&str> = response["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "secret_capture",
            "secret_generate",
            "secret_info",
            "secret_list",
            "secret_run"
        ]
    );
}

#[test]
fn capture_then_list_and_info() {
    let server = server();
    let (text, is_error) = tool(
        &server,
        "secret_capture",
        &json!({"name": "resend", "expect_prefix": "re_"}),
    );
    assert!(!is_error, "{text}");
    assert!(text.starts_with("stored resend: 24 chars, fp "), "{text}");
    assert!(text.ends_with("clipboard cleared"), "{text}");

    let (list, _) = tool(&server, "secret_list", &json!({}));
    assert!(list.contains("\"resend\""));
    let (info, _) = tool(&server, "secret_info", &json!({"name": "resend"}));
    assert!(info.contains("\"source\": \"clipboard\""), "{info}");
}

#[test]
fn generate_reports_metadata_only() {
    let (text, is_error) = tool(
        &server(),
        "secret_generate",
        &json!({"name": "db", "length": 40, "alphabet": "hex"}),
    );
    assert!(!is_error);
    assert!(text.starts_with("stored db: 40 chars, fp "), "{text}");
}

#[cfg(unix)]
#[test]
fn run_redacts_output() {
    let server = server();
    tool(&server, "secret_capture", &json!({"name": "resend"}));
    // The guard cannot see inside a script, so this exercises redaction itself.
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("print.sh");
    std::fs::write(&script, "echo token=$T\n").unwrap();
    let (text, is_error) = tool(
        &server,
        "secret_run",
        &json!({"argv": ["sh", script.to_str().unwrap()], "env": {"T": "resend"}}),
    );
    assert!(!is_error, "{text}");
    let out: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(out["stdout"], "token=«redacted:resend»\n");
    assert_eq!(out["exit_code"], 0);
}

#[cfg(unix)]
#[test]
fn run_refuses_leaky_commands() {
    let server = server();
    tool(&server, "secret_capture", &json!({"name": "resend"}));
    let (text, is_error) = tool(
        &server,
        "secret_run",
        &json!({"argv": ["sh", "-c", "printf %s $T | base64"], "env": {"T": "resend"}}),
    );
    assert!(is_error, "{text}");
    assert!(text.starts_with("refused by llm-secret-vault: "), "{text}");
    assert!(!text.contains(SECRET), "{text}");
}

#[test]
fn errors_are_tool_errors_without_values() {
    let server = server();
    let (text, is_error) = tool(&server, "secret_info", &json!({"name": "missing"}));
    assert!(is_error);
    assert_eq!(text, "no secret named `missing`");
    let (_, is_error) = tool(
        &server,
        "secret_capture",
        &json!({"name": "x", "expect_prefix": "hf_"}),
    );
    assert!(is_error);
    for cli_only in ["secret_delete", "secret_import"] {
        let (text, is_error) = tool(&server, cli_only, &json!({"name": "x"}));
        assert!(is_error);
        assert!(text.contains("unknown tool"));
    }
    let (_, is_error) = tool(&server, "secret_list", &json!({"bogus": 1}));
    assert!(is_error);
}

#[test]
fn unknown_method_is_a_protocol_error() {
    let response = call(&server(), 7, "resources/list", &json!({}));
    assert_eq!(response["error"]["code"], -32601);
    assert_eq!(response["id"], 7);
}

#[test]
fn serve_survives_bad_lines_and_leaks_nothing() {
    let mut input = Vec::new();
    input.extend_from_slice(br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#);
    input.extend_from_slice(b"\n");
    input.extend_from_slice(br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
    input.extend_from_slice(b"\n\nnot json\n\xff\xfe bad utf8\n");
    input.extend_from_slice(
        br#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"secret_capture","arguments":{"name":"resend"}}}"#,
    );
    input.extend_from_slice(b"\n");
    input.extend_from_slice(br#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#);
    input.extend_from_slice(b"\n");
    let mut output = Vec::new();
    server().serve(Cursor::new(input), &mut output).unwrap();
    let text = String::from_utf8(output).unwrap();
    assert!(!text.contains(SECRET), "leak in {text}");
    let lines: Vec<Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 5);
    assert_eq!(lines[0]["id"], 1);
    assert_eq!(lines[1]["error"]["code"], -32700);
    assert_eq!(lines[2]["error"]["code"], -32700);
    assert_eq!(lines[3]["id"], 3);
    assert_eq!(lines[4]["id"], 2);
}

#[derive(Debug, Clone)]
struct Recording {
    reasons: Arc<Mutex<Vec<String>>>,
    allow: bool,
}

impl Approver for Recording {
    fn approve(&self, reason: &str, _secrets: &BTreeSet<SecretName>) -> Result<()> {
        self.reasons.lock().unwrap().push(reason.to_owned());
        if self.allow {
            Ok(())
        } else {
            Err(Error::from_kind(ErrorKind::Denied(
                "Touch ID approval was denied or cancelled".to_owned(),
            )))
        }
    }
}

fn approving_server(allow: bool) -> (Server, Arc<Mutex<Vec<String>>>) {
    let reasons = Arc::new(Mutex::new(Vec::new()));
    let approver = Recording {
        reasons: Arc::clone(&reasons),
        allow,
    };
    (server().with_approver(Box::new(approver)), reasons)
}

#[cfg(unix)]
#[test]
fn run_asks_approval_with_command_and_names_only() {
    let (server, reasons) = approving_server(true);
    tool(&server, "secret_capture", &json!({"name": "resend"}));
    let (text, is_error) = tool(
        &server,
        "secret_run",
        &json!({"argv": ["true"], "env": {"T": "resend"}}),
    );
    assert!(!is_error, "{text}");
    let reasons = reasons.lock().unwrap();
    assert_eq!(*reasons, ["run \"true\" with secrets resend"]);
    assert!(!reasons[0].contains(SECRET));
}

#[cfg(unix)]
#[test]
fn run_denied_approval_does_not_spawn() {
    let (server, reasons) = approving_server(false);
    tool(&server, "secret_capture", &json!({"name": "resend"}));
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("marker");
    let (text, is_error) = tool(
        &server,
        "secret_run",
        &json!({"argv": ["touch", marker.to_str().unwrap()], "env": {"T": "resend"}}),
    );
    assert!(is_error);
    assert_eq!(text, "Touch ID approval was denied or cancelled");
    assert!(!marker.exists());
    assert_eq!(reasons.lock().unwrap().len(), 1);
}

#[cfg(unix)]
#[test]
fn run_without_secrets_skips_approval() {
    let (server, reasons) = approving_server(false);
    let (text, is_error) = tool(&server, "secret_run", &json!({"argv": ["true"]}));
    assert!(!is_error, "{text}");
    assert!(reasons.lock().unwrap().is_empty());
}

#[test]
fn run_with_unknown_secret_fails_before_asking() {
    let (server, reasons) = approving_server(true);
    let (text, is_error) = tool(
        &server,
        "secret_run",
        &json!({"argv": ["true", "{{missing}}"]}),
    );
    assert!(is_error);
    assert!(text.contains("missing"), "{text}");
    assert!(reasons.lock().unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn run_asks_approval_for_placeholder_only_secrets() {
    let (server, reasons) = approving_server(true);
    tool(&server, "secret_capture", &json!({"name": "resend"}));
    let (text, is_error) = tool(
        &server,
        "secret_run",
        &json!({"argv": ["true", "{{resend}}"]}),
    );
    assert!(!is_error, "{text}");
    let reasons = reasons.lock().unwrap();
    assert_eq!(reasons.len(), 1);
    assert!(reasons[0].contains("resend"), "{}", reasons[0]);
    assert!(!reasons[0].contains(SECRET));
}

#[test]
fn run_rejects_bad_env_var_before_asking() {
    let (server, reasons) = approving_server(true);
    tool(&server, "secret_capture", &json!({"name": "resend"}));
    let (text, is_error) = tool(
        &server,
        "secret_run",
        &json!({"argv": ["true"], "env": {"1BAD": "resend"}}),
    );
    assert!(is_error);
    assert!(
        text.contains("not a valid environment variable name"),
        "{text}"
    );
    assert!(reasons.lock().unwrap().is_empty());
}

#[test]
fn run_refuses_nested_lsv() {
    let (server, reasons) = approving_server(true);
    tool(&server, "secret_capture", &json!({"name": "resend"}));
    let (text, is_error) = tool(
        &server,
        "secret_run",
        &json!({"argv": ["lsv", "run", "T=resend", "--", "sh", "-c", "printf %s $T | base64"]}),
    );
    assert!(is_error);
    assert!(text.contains("must not start lsv itself"), "{text}");
    assert!(reasons.lock().unwrap().is_empty());
}
