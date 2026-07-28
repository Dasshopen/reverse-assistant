// A provider-agnostic chat-completion abstraction for the AI naming
// agents (arbitration first, then the fuller analysis/critique/synthesis
// pipeline). The trait is deliberately shaped around the "chat
// completions" request/response format, since that same shape is already
// spoken natively by several real, independent backends without any
// vendor-specific code: a local Ollama server, OpenAI, Mistral's La
// Plateforme, and many self-hosted servers. A second, differently-shaped
// adapter (e.g. Anthropic's native Messages API) can implement the same
// trait later without touching any agent logic built on top of it.
//
// Request/response construction and parsing are kept as pure functions
// so they can be tested directly against real-shaped JSON, without
// requiring a live server in the automated test suite -- the same
// convention already used for Ghidra headless invocations in this
// project (argument construction is tested; the actual external process
// is not launched from committed tests).

use std::io;
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

// ureq's default agent has no request timeout at all -- a single stalled
// call (a local model wedged, a dead connection) would hang forever and,
// since the background arbitration queue awaits one call at a time, would
// silently freeze every function still behind it in the queue too. A real
// case: 6 functions arbitrated, then no further progress for as long as
// the app stayed open, because call #7 never returned.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
const OLLAMA_START_TIMEOUT: Duration = Duration::from_secs(8);
const OLLAMA_PORT: u16 = 11_434;
static OLLAMA_START_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn is_local_ollama_url(base_url: &str) -> bool {
    let normalized = base_url.trim().trim_end_matches('/').to_ascii_lowercase();
    normalized == "http://localhost:11434/v1"
        || normalized == "http://127.0.0.1:11434/v1"
        || normalized == "http://[::1]:11434/v1"
}

fn ollama_is_listening() -> bool {
    TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], OLLAMA_PORT)),
        Duration::from_millis(150),
    )
    .is_ok()
}

fn ollama_executable() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
        let installed = PathBuf::from(local_app_data)
            .join("Programs")
            .join("Ollama")
            .join("ollama.exe");
        if installed.is_file() {
            return Some(installed);
        }
    }
    Some(PathBuf::from(if cfg!(target_os = "windows") {
        "ollama.exe"
    } else {
        "ollama"
    }))
}

fn spawn_ollama_server(executable: &PathBuf) -> io::Result<()> {
    let mut command = Command::new(executable);
    command
        .arg("serve")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    command.spawn().map(|_| ())
}

fn ensure_local_ollama_running(base_url: &str) -> Result<(), String> {
    if !is_local_ollama_url(base_url) || ollama_is_listening() {
        return Ok(());
    }
    let lock = OLLAMA_START_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock
        .lock()
        .map_err(|_| "the Ollama startup lock was poisoned".to_owned())?;
    if ollama_is_listening() {
        return Ok(());
    }
    let executable = ollama_executable().ok_or_else(|| {
        "Ollama local is configured but its executable could not be found".to_owned()
    })?;
    spawn_ollama_server(&executable).map_err(|error| {
        format!(
            "Ollama local is configured but could not be started from '{}': {error}",
            executable.display()
        )
    })?;
    let started = std::time::Instant::now();
    while started.elapsed() < OLLAMA_START_TIMEOUT {
        if ollama_is_listening() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(200));
    }
    Err(format!(
        "Ollama was launched but did not listen on port {OLLAMA_PORT} within {} seconds",
        OLLAMA_START_TIMEOUT.as_secs()
    ))
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ChatCompletionRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    pub temperature: Option<f64>,
    /// Ask compatible providers (including Ollama) to constrain decoding to
    /// one JSON object instead of relying on prompt wording alone.
    pub require_json_object: bool,
    /// Optional strict schema. When present it takes precedence over generic
    /// JSON mode and is supported by Ollama's OpenAI-compatible endpoint.
    pub response_schema: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChatCompletionResponse {
    pub content: String,
}

/// Code-specialized models (confirmed: qwen2.5-coder, unlike llama3.1)
/// wrap a JSON answer in a markdown code fence even when told to respond
/// with nothing else -- real output observed: "```json\n{...}\n```".
/// `serde_json::from_str` rejects that outright (fails on the leading
/// backtick), so every caller expecting a raw JSON object in `content`
/// strips an optional fence first rather than trusting the model's
/// formatting instincts over its actual behavior.
pub fn strip_markdown_json_fence(content: &str) -> &str {
    let trimmed = content.trim();
    let without_open = trimmed
        .strip_prefix("```json")
        .or_else(|| trimmed.strip_prefix("```JSON"))
        .or_else(|| trimmed.strip_prefix("```"))
        .map(str::trim_start)
        .unwrap_or(trimmed);
    without_open
        .strip_suffix("```")
        .map(str::trim_end)
        .unwrap_or(without_open)
}

pub trait ChatCompletionProvider {
    fn complete(&self, request: &ChatCompletionRequest) -> Result<ChatCompletionResponse, String>;
}

/// Speaks the OpenAI-compatible "chat completions" HTTP format. Works
/// against a local Ollama server, OpenAI itself, Mistral, and any other
/// server exposing the same endpoint shape -- `base_url` and `api_key`
/// are the only things that differ between them.
pub struct OpenAiCompatibleProvider {
    pub base_url: String,
    pub api_key: Option<String>,
}

impl OpenAiCompatibleProvider {
    fn endpoint_url(&self) -> String {
        format!("{}/chat/completions", self.base_url.trim_end_matches('/'))
    }
}

pub(crate) fn build_request_body_json(request: &ChatCompletionRequest) -> Value {
    let mut body = json!({
        "model": request.model,
        "messages": request
            .messages
            .iter()
            .map(|message| json!({ "role": message.role, "content": message.content }))
            .collect::<Vec<_>>(),
    });
    if let Some(temperature) = request.temperature {
        body["temperature"] = json!(temperature);
    }
    if let Some(schema) = &request.response_schema {
        body["response_format"] = json!({
            "type": "json_schema",
            "json_schema": {
                "name": "reverse_assistant_response",
                "strict": true,
                "schema": schema
            }
        });
    } else if request.require_json_object {
        body["response_format"] = json!({ "type": "json_object" });
    }
    body
}

#[derive(Deserialize)]
struct ChatCompletionResponseJson {
    choices: Vec<ChatCompletionChoiceJson>,
}

#[derive(Deserialize)]
struct ChatCompletionChoiceJson {
    message: ChatCompletionResponseMessageJson,
}

#[derive(Deserialize)]
struct ChatCompletionResponseMessageJson {
    content: String,
}

pub(crate) fn parse_response_body_json(body: &str) -> Result<ChatCompletionResponse, String> {
    let parsed: ChatCompletionResponseJson = serde_json::from_str(body)
        .map_err(|error| format!("invalid chat completion response JSON: {error}"))?;
    let first_choice = parsed
        .choices
        .into_iter()
        .next()
        .ok_or_else(|| "chat completion response contained no choices".to_owned())?;
    Ok(ChatCompletionResponse {
        content: first_choice.message.content,
    })
}

impl ChatCompletionProvider for OpenAiCompatibleProvider {
    fn complete(&self, request: &ChatCompletionRequest) -> Result<ChatCompletionResponse, String> {
        ensure_local_ollama_running(&self.base_url)?;
        let url = self.endpoint_url();
        let body = build_request_body_json(request);

        let agent = ureq::AgentBuilder::new().timeout(REQUEST_TIMEOUT).build();
        let mut call = agent.post(&url).set("Content-Type", "application/json");
        if let Some(api_key) = &self.api_key {
            call = call.set("Authorization", &format!("Bearer {api_key}"));
        }

        let response = call
            .send_string(&body.to_string())
            .map_err(|error| match error {
                ureq::Error::Status(status, response) => {
                    let details = response
                        .into_string()
                        .unwrap_or_else(|_| "response body unavailable".to_owned());
                    format!(
                        "chat completion request to '{url}' failed with HTTP {status}: {details}"
                    )
                }
                other => format!("chat completion request to '{url}' failed: {other}"),
            })?;
        let body_text = response.into_string().map_err(|error| {
            format!("failed to read the chat completion response body from '{url}': {error}")
        })?;

        parse_response_body_json(&body_text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_url_appends_the_chat_completions_path() {
        let provider = OpenAiCompatibleProvider {
            base_url: "http://localhost:11434/v1".to_owned(),
            api_key: None,
        };

        assert_eq!(
            provider.endpoint_url(),
            "http://localhost:11434/v1/chat/completions"
        );
    }

    #[test]
    fn endpoint_url_tolerates_a_trailing_slash() {
        let provider = OpenAiCompatibleProvider {
            base_url: "https://api.openai.com/v1/".to_owned(),
            api_key: Some("test-key".to_owned()),
        };

        assert_eq!(
            provider.endpoint_url(),
            "https://api.openai.com/v1/chat/completions"
        );
    }

    #[test]
    fn only_the_standard_loopback_ollama_endpoint_is_auto_managed() {
        assert!(is_local_ollama_url("http://localhost:11434/v1/"));
        assert!(is_local_ollama_url("http://127.0.0.1:11434/v1"));
        assert!(!is_local_ollama_url("https://api.openai.com/v1"));
        assert!(!is_local_ollama_url("http://localhost:8080/v1"));
    }

    #[test]
    fn request_body_includes_model_and_messages() {
        let request = ChatCompletionRequest {
            model: "llama3.1".to_owned(),
            messages: vec![
                ChatMessage {
                    role: "system".to_owned(),
                    content: "You are an arbitration agent.".to_owned(),
                },
                ChatMessage {
                    role: "user".to_owned(),
                    content: "Pick the best candidate.".to_owned(),
                },
            ],
            temperature: None,
            require_json_object: false,
            response_schema: None,
        };

        let body = build_request_body_json(&request);

        assert_eq!(body["model"], "llama3.1");
        assert_eq!(body["messages"][0]["role"], "system");
        assert_eq!(
            body["messages"][0]["content"],
            "You are an arbitration agent."
        );
        assert_eq!(body["messages"][1]["role"], "user");
        assert!(body.get("temperature").is_none());
    }

    #[test]
    fn request_body_includes_temperature_when_set() {
        let request = ChatCompletionRequest {
            model: "gpt-4o-mini".to_owned(),
            messages: vec![],
            temperature: Some(0.2),
            require_json_object: true,
            response_schema: None,
        };

        let body = build_request_body_json(&request);

        assert_eq!(body["temperature"], 0.2);
        assert_eq!(body["response_format"]["type"], "json_object");
    }

    #[test]
    fn a_strict_schema_takes_precedence_over_generic_json_mode() {
        let request = ChatCompletionRequest {
            model: "qwen2.5-coder:7b".to_owned(),
            messages: vec![],
            temperature: Some(0.0),
            require_json_object: true,
            response_schema: Some(json!({
                "type": "object",
                "properties": { "name": { "type": "string" } },
                "required": ["name"]
            })),
        };
        let body = build_request_body_json(&request);
        assert_eq!(body["response_format"]["type"], "json_schema");
        assert_eq!(
            body["response_format"]["json_schema"]["schema"]["required"][0],
            "name"
        );
    }

    #[test]
    fn parses_a_real_shaped_openai_compatible_response() {
        // Real shape returned by both OpenAI and Ollama's compatible
        // endpoint for a non-streaming chat completion.
        let body = r#"{
            "id": "chatcmpl-123",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": { "role": "assistant", "content": "sqlite3OsOpen" },
                    "finish_reason": "stop"
                }
            ]
        }"#;

        let response = parse_response_body_json(body).expect("a valid response should parse");

        assert_eq!(response.content, "sqlite3OsOpen");
    }

    #[test]
    fn rejects_a_response_with_no_choices() {
        let body = r#"{ "id": "chatcmpl-123", "choices": [] }"#;

        let error = parse_response_body_json(body).expect_err("no choices should be rejected");

        assert!(error.contains("no choices"));
    }

    #[test]
    fn rejects_malformed_json() {
        let error =
            parse_response_body_json("not json").expect_err("invalid JSON should be rejected");

        assert!(error.contains("invalid chat completion response JSON"));
    }

    #[test]
    fn a_json_fenced_response_has_its_fence_stripped() {
        // Real content observed from qwen2.5-coder:7b for a prompt that
        // explicitly asked for a bare JSON object and nothing else.
        let content = "```json\n{\n  \"suggested_name\": null,\n  \"reasoning\": \"...\"\n}\n```";

        assert_eq!(
            strip_markdown_json_fence(content),
            "{\n  \"suggested_name\": null,\n  \"reasoning\": \"...\"\n}"
        );
    }

    #[test]
    fn a_response_with_no_fence_is_returned_unchanged() {
        let content = r#"{"chosen_name": "memcpy", "reasoning": "..."}"#;

        assert_eq!(strip_markdown_json_fence(content), content);
    }

    #[test]
    fn a_fence_without_the_json_language_tag_is_also_stripped() {
        let content = "```\n{\"chosen_name\": null, \"reasoning\": \"...\"}\n```";

        assert_eq!(
            strip_markdown_json_fence(content),
            "{\"chosen_name\": null, \"reasoning\": \"...\"}"
        );
    }
}
