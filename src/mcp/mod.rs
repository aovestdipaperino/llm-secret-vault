//! Minimal MCP server over stdio exposing the vault as tools.

mod tools;

use std::fmt;
use std::io::{BufRead, Write};

use serde_json::{Value, json};

use crate::capture::{Clipboard, SystemClipboard};
use crate::error::Result;
use crate::vault::Vault;

/// Protocol version announced when the client does not request one.
pub const PROTOCOL_VERSION: &str = "2025-06-18";

const INSTRUCTIONS: &str = "Secrets are referenced by name and never returned. \
When the user says a key or password is in the clipboard, call secret_capture. \
Use secret_run to pass secrets to commands through env vars or {{name}} placeholders. \
Never ask the user to paste a secret into the chat.";

/// Creates a clipboard handle on demand (so headless machines fail per call, not at startup).
pub type ClipboardFactory = Box<dyn Fn() -> Result<Box<dyn Clipboard>> + Send + Sync>;

/// MCP server that answers JSON-RPC messages using a [`Vault`].
pub struct Server {
    vault: Vault,
    clipboard: ClipboardFactory,
}

impl fmt::Debug for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Server")
            .field("vault", &self.vault)
            .finish_non_exhaustive()
    }
}

fn tool_result(text: &str, is_error: bool) -> Value {
    json!({"content": [{"type": "text", "text": text}], "isError": is_error})
}

impl Server {
    /// Creates a server using `clipboard` to reach the clipboard.
    #[must_use]
    pub fn new(vault: Vault, clipboard: ClipboardFactory) -> Self {
        Self { vault, clipboard }
    }

    /// Creates a server that uses the system clipboard.
    #[must_use]
    pub fn with_system_clipboard(vault: Vault) -> Self {
        Self::new(
            vault,
            Box::new(|| Ok(Box::new(SystemClipboard::new()?) as Box<dyn Clipboard>)),
        )
    }

    /// Handles one JSON-RPC message; returns `None` for notifications.
    #[must_use]
    pub fn handle(&self, message: &Value) -> Option<Value> {
        let id = message.get("id")?.clone();
        let params = message.get("params");
        let result = match message.get("method").and_then(Value::as_str) {
            Some("initialize") => Ok(Self::initialize(params)),
            Some("ping") => Ok(json!({})),
            Some("tools/list") => Ok(json!({"tools": tools::definitions()})),
            Some("tools/call") => self.call(params),
            Some(other) => Err((-32601, format!("method not found: {other}"))),
            None => Err((-32600, "invalid request: missing method".to_owned())),
        };
        Some(match result {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err((code, message)) => {
                json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
            }
        })
    }

    fn initialize(params: Option<&Value>) -> Value {
        let version = params
            .and_then(|p| p.get("protocolVersion"))
            .and_then(Value::as_str)
            .unwrap_or(PROTOCOL_VERSION);
        json!({
            "protocolVersion": version,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "llm-secret-vault", "version": env!("CARGO_PKG_VERSION")},
            "instructions": INSTRUCTIONS,
        })
    }

    fn call(&self, params: Option<&Value>) -> std::result::Result<Value, (i64, String)> {
        let params = params.ok_or((-32602, "missing params".to_owned()))?;
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or((-32602, "missing tool name".to_owned()))?;
        let args = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        Ok(
            match tools::call(&self.vault, &self.clipboard, name, &args) {
                Ok(text) => tool_result(&text, false),
                Err(err) => tool_result(&err.to_string(), true),
            },
        )
    }

    /// Serves newline-delimited JSON-RPC from `input` to `output` until EOF.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if reading `input` or writing `output` fails.
    pub fn serve(&self, input: impl BufRead, mut output: impl Write) -> std::io::Result<()> {
        for line in input.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let response = match serde_json::from_str::<Value>(&line) {
                Ok(message) => self.handle(&message),
                Err(e) => Some(json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": {"code": -32700, "message": format!("parse error: {e}")}
                })),
            };
            if let Some(response) = response {
                serde_json::to_writer(&mut output, &response)?;
                output.write_all(b"\n")?;
                output.flush()?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::error::{Error, ErrorKind};

    #[derive(Debug)]
    struct StuckClipboard;

    impl Clipboard for StuckClipboard {
        fn text(&mut self) -> Result<Option<String>> {
            Ok(Some("re_live_0123456789abcdef".to_owned()))
        }
        fn clear(&mut self) -> Result<()> {
            Err(Error::new(ErrorKind::Clipboard("denied".to_owned())))
        }
    }

    #[test]
    fn capture_says_when_clipboard_was_not_cleared() {
        let server = Server::new(
            Vault::in_memory(),
            Box::new(|| Ok(Box::new(StuckClipboard) as Box<dyn Clipboard>)),
        );
        let response = server
            .handle(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "secret_capture", "arguments": {"name": "resend"}}}))
            .unwrap();
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert_eq!(response["result"]["isError"], false);
        assert!(text.starts_with("stored resend: 24 chars, fp "), "{text}");
        assert!(text.ends_with("clipboard NOT cleared"), "{text}");
    }
}
