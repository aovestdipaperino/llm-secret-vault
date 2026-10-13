//! MCP server tests: protocol handling and tools, with a no-leak check on every response.

use std::io::Cursor;

use llm_secret_vault::capture::Clipboard;
use llm_secret_vault::mcp::Server;
use llm_secret_vault::{Result, Vault};
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
fn initialize_echoes_protocol_version() {
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
    let (text, is_error) = tool(
        &server,
        "secret_run",
        &json!({"argv": ["sh", "-c", "echo token=$T"], "env": {"T": "resend"}}),
    );
    assert!(!is_error, "{text}");
    let out: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(out["stdout"], "token=«redacted:resend»\n");
    assert_eq!(out["exit_code"], 0);
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
fn serve_handles_newline_delimited_stream() {
    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        "\n",
        "\n",
        "not json\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#,
        "\n",
    );
    let mut output = Vec::new();
    server().serve(Cursor::new(input), &mut output).unwrap();
    let lines: Vec<Value> = String::from_utf8(output)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0]["id"], 1);
    assert_eq!(lines[1]["error"]["code"], -32700);
    assert_eq!(lines[2]["id"], 2);
}
