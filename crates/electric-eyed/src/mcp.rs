//! Read-only MCP (Model Context Protocol) server.
//!
//! The daemon exposes this over a Unix socket so agent clients can query the
//! same live state as the CLI. `electric-eye mcp` bridges MCP's stdio transport
//! to that socket. The protocol is intentionally small: JSON-RPC 2.0 requests
//! are newline-delimited, and every tool maps to an existing read-only API
//! request.

use std::collections::HashSet;
use std::io::{self, BufRead, BufReader, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};

use crate::api::{self, SharedState};

pub const DEFAULT_SOCKET: &str = "/run/electric-eye/mcp.sock";
pub const SERVER_NAME: &str = "electric-eye";
const LATEST_PROTOCOL: &str = "2025-11-25";
const SUPPORTED_PROTOCOLS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
const MAX_CLIENTS: usize = 8;
const CLIENT_POLL: Duration = Duration::from_millis(500);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
pub const ALL_TOOLS: [&str; 15] = [
    "status",
    "activity",
    "apps",
    "app",
    "process",
    "tree",
    "file",
    "network",
    "flows",
    "summaries",
    "why",
    "incidents",
    "focus",
    "investigate",
    "noise",
];
const DEFAULT_TOOLS: [&str; 7] = [
    "status",
    "incidents",
    "investigate",
    "activity",
    "apps",
    "flows",
    "focus",
];

#[derive(Clone, Debug)]
pub struct ToolProfile {
    allowed: Option<HashSet<&'static str>>,
}

impl Default for ToolProfile {
    fn default() -> Self {
        Self::from_names(&DEFAULT_TOOLS)
    }
}

impl ToolProfile {
    pub fn all() -> Self {
        Self { allowed: None }
    }
    fn from_names(names: &[&'static str]) -> Self {
        Self {
            allowed: Some(names.iter().copied().collect()),
        }
    }
    pub fn from_config(values: &[String]) -> Result<Self, String> {
        if values.is_empty() {
            return Ok(Self::default());
        }
        Self::parse(&values.join(","))
    }
    pub fn parse(value: &str) -> Result<Self, String> {
        let value = value.trim();
        if value.is_empty()
            || value.eq_ignore_ascii_case("default")
            || value.eq_ignore_ascii_case("core")
        {
            return Ok(Self::default());
        }
        if value.eq_ignore_ascii_case("all") || value.eq_ignore_ascii_case("full") {
            return Ok(Self::all());
        }
        let mut names = Vec::new();
        for name in value
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            let Some(name) = ALL_TOOLS.iter().find(|allowed| **allowed == name) else {
                return Err(format!("unknown MCP tool {name}"));
            };
            names.push(*name);
        }
        if names.is_empty() {
            return Err("MCP tool profile is empty".into());
        }
        Ok(Self::from_names(&names))
    }
    pub fn allows(&self, name: &str) -> bool {
        self.allowed
            .as_ref()
            .is_none_or(|allowed| allowed.contains(name))
    }
}

const INSTRUCTIONS: &str = "Electric Eye is a read-only Linux activity monitor. \
Call status first to check capture health, then incidents and activity for recent \
observations. The default profile exposes status, activity, apps, flows, incidents, \
focus and investigate; when the full profile is enabled, process, tree, file, app, \
network, why, summaries and noise are also available. Flow records include \
network_context (host, vopono, container or namespace), role, direction and \
exposure; roles are heuristics and payloads are not inspected. Paths and process \
identities can have uncertainty labels; prefer --json-equivalent structured \
results and do not claim events that were not observed.";

pub fn bind_socket(path: &Path) -> io::Result<api::SocketGuard> {
    api::bind_socket(path)
}

pub struct Server {
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl Server {
    pub fn start(
        socket: api::SocketGuard,
        state: Arc<Mutex<SharedState>>,
        profile: ToolProfile,
    ) -> io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let join = thread::Builder::new()
            .name("electric-eye-mcp".into())
            .spawn(move || {
                let active = Arc::new(AtomicUsize::new(0));
                let mut clients: Vec<JoinHandle<()>> = Vec::new();
                while !stopping.load(Ordering::Relaxed) {
                    clients.retain(|client| !client.is_finished());
                    match socket.listener.accept() {
                        Ok((stream, _)) => {
                            if active.load(Ordering::Relaxed) >= MAX_CLIENTS {
                                let _ = stream.shutdown(Shutdown::Both);
                                continue;
                            }
                            active.fetch_add(1, Ordering::Relaxed);
                            let state = Arc::clone(&state);
                            let stop = Arc::clone(&stopping);
                            let active = Arc::clone(&active);
                            let profile = profile.clone();
                            clients.push(thread::spawn(move || {
                                if let Err(err) = handle_client(stream, &state, &stop, &profile) {
                                    log::debug!("MCP connection closed: {err}");
                                }
                                active.fetch_sub(1, Ordering::Relaxed);
                            }));
                        }
                        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(50));
                        }
                        Err(err) => {
                            log::warn!("MCP accept: {err}");
                            thread::sleep(Duration::from_millis(100));
                        }
                    }
                }
                // Connections poll the stop flag while reading.
                let deadline = Instant::now() + Duration::from_secs(2);
                while active.load(Ordering::Relaxed) > 0 && Instant::now() < deadline {
                    thread::sleep(Duration::from_millis(25));
                }
                for client in clients {
                    let _ = client.join();
                }
                drop(socket);
            })?;
        Ok(Self {
            stop,
            join: Some(join),
        })
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn handle_client(
    mut stream: UnixStream,
    state: &Arc<Mutex<SharedState>>,
    stop: &AtomicBool,
    profile: &ToolProfile,
) -> io::Result<()> {
    stream.set_read_timeout(Some(CLIENT_POLL))?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let config = state.lock().unwrap().config_snapshot();
    let max_bytes = config.limits.api_request_bytes;
    let frame_timeout = Duration::from_millis(config.limits.api_timeout_ms);
    let mut line = Vec::new();
    let mut deadline: Option<Instant> = None;
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let timeout = match deadline {
            Some(end) => {
                let Some(remaining) = end.checked_duration_since(Instant::now()) else {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "MCP request deadline exceeded",
                    ));
                };
                CLIENT_POLL.min(remaining)
            }
            None => CLIENT_POLL,
        };
        stream.set_read_timeout(Some(timeout))?;
        match reader.fill_buf() {
            Ok([]) => break,
            Ok(bytes) => {
                let newline = bytes.iter().position(|byte| *byte == b'\n');
                let count = newline.unwrap_or(bytes.len());
                if count > max_bytes.saturating_sub(line.len()) {
                    let response = error_response(Value::Null, -32600, "request too large");
                    write_message(&mut stream, &response)?;
                    return Ok(());
                }
                deadline.get_or_insert_with(|| Instant::now() + frame_timeout);
                line.extend_from_slice(&bytes[..count]);
                reader.consume(count + usize::from(newline.is_some()));
                if newline.is_some() {
                    let text = String::from_utf8_lossy(&line).trim().to_string();
                    line.clear();
                    deadline = None;
                    if text.is_empty() {
                        continue;
                    }
                    if let Some(response) = handle_message(&text, state, profile) {
                        write_message(&mut stream, &response)?;
                    }
                }
            }
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

fn write_message(stream: &mut UnixStream, value: &Value) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    bytes.push(b'\n');
    stream.write_all(&bytes)?;
    stream.flush()
}

fn handle_message(
    text: &str,
    state: &Arc<Mutex<SharedState>>,
    profile: &ToolProfile,
) -> Option<Value> {
    let request: Value = match serde_json::from_str(text) {
        Ok(request) => request,
        Err(err) => {
            return Some(error_response(
                Value::Null,
                -32700,
                format!("parse error: {err}"),
            ));
        }
    };
    if let Some(batch) = request.as_array() {
        if batch.is_empty() {
            return Some(error_response(Value::Null, -32600, "empty batch"));
        }
        let responses: Vec<Value> = batch
            .iter()
            .filter_map(|request| handle_request(request, state, profile))
            .collect();
        return (!responses.is_empty()).then_some(Value::Array(responses));
    }
    handle_request(&request, state, profile)
}

fn handle_request(
    request: &Value,
    state: &Arc<Mutex<SharedState>>,
    profile: &ToolProfile,
) -> Option<Value> {
    let has_id = request.get("id").is_some();
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        return has_id.then(|| error_response(id, -32600, "missing method"));
    };

    // Notifications never receive a response.
    if !has_id {
        return None;
    }

    match method {
        "initialize" => Some(response(id, initialize_result(request))),
        "ping" => Some(response(id, json!({}))),
        "tools/list" => Some(response(id, json!({ "tools": tools(profile) }))),
        "tools/call" => Some(handle_tool_call(id, request, state, profile)),
        "resources/list" => Some(response(id, json!({ "resources": resources() }))),
        "resources/read" => Some(handle_resource_read(id, request, state)),
        other => Some(error_response(
            id,
            -32601,
            format!("method not found: {other}"),
        )),
    }
}

fn initialize_result(request: &Value) -> Value {
    let requested = request
        .pointer("/params/protocolVersion")
        .and_then(Value::as_str)
        .unwrap_or(LATEST_PROTOCOL);
    let protocol = if SUPPORTED_PROTOCOLS.contains(&requested) {
        requested
    } else {
        LATEST_PROTOCOL
    };
    json!({
        "protocolVersion": protocol,
        "capabilities": {
            "tools": { "listChanged": false },
            "resources": { "subscribe": false, "listChanged": false }
        },
        "serverInfo": {
            "name": SERVER_NAME,
            "title": "Electric Eye",
            "version": env!("CARGO_PKG_VERSION")
        },
        "instructions": INSTRUCTIONS
    })
}

fn handle_tool_call(
    id: Value,
    request: &Value,
    state: &Arc<Mutex<SharedState>>,
    profile: &ToolProfile,
) -> Value {
    let Some(params) = request.get("params").and_then(Value::as_object) else {
        return error_response(id, -32602, "tools/call requires params");
    };
    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return error_response(id, -32602, "tools/call requires a tool name");
    };
    if !profile.allows(name) {
        return error_response(
            id,
            -32602,
            format!("tool {name} is not enabled in this MCP profile"),
        );
    }
    let arguments = match params.get("arguments") {
        Some(Value::Object(arguments)) => arguments,
        Some(Value::Null) | None => &Map::new(),
        Some(_) => return error_response(id, -32602, "tool arguments must be an object"),
    };
    let api_request = match build_request(name, arguments) {
        Ok(request) => request,
        Err(message) => return error_response(id, -32602, message),
    };
    let value = api::response_for(&api_request, state);
    let is_error = value.get("error").is_some();
    let text = serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string());
    let mut result = json!({
        "content": [{ "type": "text", "text": text }],
        "isError": is_error
    });
    if !is_error {
        result["structuredContent"] = value;
    }
    response(id, result)
}

fn build_request(name: &str, args: &Map<String, Value>) -> Result<Value, String> {
    let mut request = json!({
        "op": match name {
            "status" => "status",
            "activity" => "activity",
            "apps" => "apps",
            "app" => "app",
            "process" => "process",
            "tree" => "tree",
            "file" => "file",
            "network" => "network",
            "flows" => "flows",
            "summaries" => "summaries",
            "why" => "why",
            "incidents" => "incidents",
            "focus" => "focus",
            "investigate" => "investigate",
            "noise" => "noise",
            other => return Err(format!("unknown tool: {other}")),
        }
    });

    match name {
        "process" => request["process"] = required_string(args, "process")?.into(),
        "tree" => {
            if let Some(process) = optional_string(args, "process")? {
                request["process"] = process.into();
            }
        }
        "app" => request["app"] = required_string(args, "app")?.into(),
        "investigate" => request["id"] = required_string(args, "id")?.into(),
        "file" | "why" => request["path"] = required_string(args, "path")?.into(),
        _ => {}
    }

    if let Some(limit) = args.get("limit") {
        let Some(limit) = limit.as_u64() else {
            return Err("limit must be an integer".into());
        };
        if !(1..=1000).contains(&limit) {
            return Err("limit must be 1..1000".into());
        }
        request["limit"] = limit.into();
    }
    Ok(request)
}

fn required_string(args: &Map<String, Value>, key: &str) -> Result<String, String> {
    optional_string(args, key)?.ok_or_else(|| format!("{key} is required"))
}

fn optional_string(args: &Map<String, Value>, key: &str) -> Result<Option<String>, String> {
    match args.get(key) {
        Some(Value::String(value)) if !value.is_empty() => Ok(Some(value.clone())),
        Some(Value::String(_)) => Err(format!("{key} must not be empty")),
        Some(Value::Number(value)) => Ok(Some(value.to_string())),
        Some(_) => Err(format!("{key} must be a string")),
        None => Ok(None),
    }
}

fn handle_resource_read(id: Value, request: &Value, state: &Arc<Mutex<SharedState>>) -> Value {
    let Some(uri) = request.pointer("/params/uri").and_then(Value::as_str) else {
        return error_response(id, -32602, "resources/read requires a uri");
    };
    let op = match uri {
        "electric-eye://status" => "status",
        "electric-eye://activity" => "activity",
        "electric-eye://incidents" => "incidents",
        _ => return error_response(id, -32602, format!("unknown resource: {uri}")),
    };
    let value = api::response_for(&json!({ "op": op, "limit": 100 }), state);
    if value.get("error").is_some() {
        return response(id, json!({ "contents": [] }));
    }
    let text = serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string());
    response(
        id,
        json!({
            "contents": [{
                "uri": uri,
                "mimeType": "application/json",
                "text": text
            }]
        }),
    )
}

fn response(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error_response(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message.into() }
    })
}

fn resources() -> Value {
    json!([
        {
            "uri": "electric-eye://status",
            "name": "status",
            "title": "Daemon status",
            "description": "Capture health, attached probes, event totals, loss counters, storage state, and effective configuration.",
            "mimeType": "application/json"
        },
        {
            "uri": "electric-eye://activity",
            "name": "activity",
            "title": "Recent activity",
            "description": "The most recent observed events, newest first.",
            "mimeType": "application/json"
        },
        {
            "uri": "electric-eye://incidents",
            "name": "incidents",
            "title": "Recent incidents",
            "description": "Deterministic-rule incidents with process, path, severity, and evidence.",
            "mimeType": "application/json"
        }
    ])
}

fn tools(profile: &ToolProfile) -> Value {
    let tools = vec![
        tool(
            "status",
            "Daemon status",
            "Check daemon health, kernel version, attached probes, event totals, capture-loss counters, storage drops, and the effective configuration. Start here.",
            no_args(),
        ),
        tool(
            "activity",
            "Recent activity",
            "List the most recent observed events, newest first. Use before drilling into a process, file, or network flow.",
            limit_args(&[]),
        ),
        tool(
            "apps",
            "Applications and tasks",
            "List application/task attribution with event counts, aggregate sent/received bytes and observed network contexts.",
            no_args(),
        ),
        tool(
            "app",
            "Application activity",
            "Show activity for an application name, stable application ID, or task ID.",
            limit_args(&[(
                "app",
                json!({
                    "type": "string",
                    "description": "Application name, stable application ID, or task ID."
                }),
                true,
            )]),
        ),
        tool(
            "process",
            "Process metadata",
            "Show metadata and exec history for a PID or stable process identity (boot_id:pid:start_ns). Numeric PIDs can match multiple historical generations.",
            limit_args(&[(
                "process",
                json!({
                    "type": "string",
                    "description": "PID or stable process identity."
                }),
                true,
            )]),
        ),
        tool(
            "tree",
            "Process tree",
            "Show retained descendants of a process. Omit process to show all retained roots.",
            limit_args(&[(
                "process",
                json!({
                    "type": "string",
                    "description": "Optional PID or stable process identity."
                }),
                false,
            )]),
        ),
        tool(
            "file",
            "File activity",
            "Show persisted and recent activity for an exact file path, including opens, writes, renames, and unlinks.",
            limit_args(&[(
                "path",
                json!({ "type": "string", "description": "Absolute file path." }),
                true,
            )]),
        ),
        tool(
            "network",
            "Network activity",
            "Show recent connect, accept, listen, and traffic observations with endpoints and hostnames.",
            limit_args(&[]),
        ),
        tool(
            "flows",
            "Network flows",
            "Show TCP/UDP flow lifecycles with state, duration, sent/received byte totals, errors, contributing processes, network context (host/vopono/container), role and exposure.",
            limit_args(&[]),
        ),
        tool(
            "summaries",
            "Activity summaries",
            "Show evidence-backed build, save, startup, and download-like summaries with confidence labels and evidence references.",
            limit_args(&[]),
        ),
        tool(
            "why",
            "Who touched a path",
            "Explain which processes accessed or mutated a path, with evidence, syscall outcomes, and uncertainty labels.",
            limit_args(&[(
                "path",
                json!({ "type": "string", "description": "Absolute file path." }),
                true,
            )]),
        ),
        tool(
            "incidents",
            "Incidents",
            "List deterministic-rule incidents such as sensitive-path access, credential sweeps, bulk mutation, suspicious execution, sensitive egress, and novel destinations.",
            limit_args(&[]),
        ),
        tool(
            "focus",
            "Focused sessions",
            "Summarise configured focus rules: matching recent activity, flows, incidents, applications and auto-detected harness log paths.",
            limit_args(&[]),
        ),
        tool(
            "investigate",
            "Investigate an incident",
            "Build a bounded read-only evidence bundle and a complete investigation prompt for an incident. The caller's own agent/model can evaluate it; electric-eye does not call a model.",
            limit_args(&[(
                "id",
                json!({ "type": "string", "description": "Incident id." }),
                true,
            )]),
        ),
        tool(
            "noise",
            "Noise candidates",
            "Suggest likely capture filters and rule allowlists from recent activity, incidents, and summaries. Read-only: review the suggested configuration before applying it.",
            limit_args(&[]),
        ),
    ];
    Value::Array(
        tools
            .into_iter()
            .filter(|tool| {
                tool["name"]
                    .as_str()
                    .is_some_and(|name| profile.allows(name))
            })
            .collect(),
    )
}

fn tool(name: &str, title: &str, description: &str, input_schema: Value) -> Value {
    json!({
        "name": name,
        "title": title,
        "description": description,
        "inputSchema": input_schema,
        "annotations": {
            "title": title,
            "readOnlyHint": true,
            "destructiveHint": false,
            "idempotentHint": true,
            "openWorldHint": false
        }
    })
}

fn no_args() -> Value {
    json!({
        "type": "object",
        "properties": {},
        "additionalProperties": false
    })
}

fn limit_args(extra: &[(&str, Value, bool)]) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();
    for (name, schema, is_required) in extra {
        properties.insert((*name).into(), schema.clone());
        if *is_required {
            required.push((*name).to_string());
        }
    }
    let mut schema = json!({
        "type": "object",
        "properties": {
            "limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": 1000,
                "description": "Maximum rows to return (default 100)."
            }
        },
        "additionalProperties": false
    });
    for (name, value) in properties {
        schema["properties"][name] = value;
    }
    if !required.is_empty() {
        schema["required"] = json!(required);
    }
    schema
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn state() -> Arc<Mutex<SharedState>> {
        Arc::new(Mutex::new(SharedState::new()))
    }

    fn call(request: Value) -> Value {
        call_with_profile(request, ToolProfile::default())
    }
    fn call_with_profile(request: Value, profile: ToolProfile) -> Value {
        handle_message(&request.to_string(), &state(), &profile).expect("request has a response")
    }

    #[test]
    fn initializes_with_a_supported_protocol_and_server_identity() {
        let response = call(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": { "protocolVersion": "2025-06-18", "capabilities": {} }
        }));
        assert_eq!(response["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(response["result"]["serverInfo"]["name"], SERVER_NAME);
        assert!(response["result"]["capabilities"]["tools"].is_object());
        assert!(
            response["result"]["instructions"]
                .as_str()
                .unwrap()
                .contains("default profile")
        );
    }

    #[test]
    fn negotiates_the_latest_protocol_for_unknown_versions() {
        let response = call(json!({
            "jsonrpc": "2.0",
            "id": "x",
            "method": "initialize",
            "params": { "protocolVersion": "2099-01-01" }
        }));
        assert_eq!(response["result"]["protocolVersion"], LATEST_PROTOCOL);
        assert_eq!(response["id"], "x");
    }

    #[test]
    fn notifications_do_not_receive_responses() {
        let state = state();
        assert!(
            handle_message(
                r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
                &state,
                &ToolProfile::default()
            )
            .is_none()
        );
        assert!(
            handle_message(
                r#"{"jsonrpc":"2.0","method":"unknown/notification"}"#,
                &state,
                &ToolProfile::default()
            )
            .is_none()
        );
    }

    #[test]
    fn lists_read_only_tools() {
        let response = call(json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}));
        let tools = response["result"]["tools"].as_array().unwrap();
        let names: Vec<_> = tools
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect();
        assert_eq!(
            names,
            vec![
                "status",
                "activity",
                "apps",
                "flows",
                "incidents",
                "focus",
                "investigate"
            ]
        );
        assert!(
            tools
                .iter()
                .all(|tool| tool["annotations"]["readOnlyHint"] == true)
        );

        let full = call_with_profile(
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
            ToolProfile::all(),
        );
        let full = full["result"]["tools"].as_array().unwrap();
        let full_names: Vec<_> = full
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect();
        for expected in ALL_TOOLS {
            assert!(
                full_names.contains(&expected),
                "missing full tool {expected}"
            );
        }
    }

    #[test]
    fn tool_profiles_filter_listing_and_calls() {
        let custom = ToolProfile::parse("status,investigate").unwrap();
        let response = call_with_profile(
            json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
            custom.clone(),
        );
        let names: Vec<_> = response["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect();
        assert_eq!(names, vec!["status", "investigate"]);
        let disabled = call_with_profile(
            json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"flows","arguments":{}}}),
            custom,
        );
        assert_eq!(disabled["error"]["code"], -32602);
        assert!(ToolProfile::parse("not-a-tool").is_err());
        assert!(
            ToolProfile::from_config(&["all".into()])
                .unwrap()
                .allows("noise")
        );
    }

    #[test]
    fn tool_calls_return_structured_results_and_errors() {
        let response = call(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "status", "arguments": {} }
        }));
        assert_eq!(response["result"]["isError"], false);
        assert_eq!(
            response["result"]["structuredContent"]["daemon"],
            "electric-eyed"
        );
        assert!(
            response["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("electric-eyed")
        );

        let missing = call(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": { "name": "process", "arguments": {} }
        }));
        assert_eq!(missing["error"]["code"], -32602);
    }

    #[test]
    fn rejects_unknown_tools_and_bad_limits() {
        let unknown = call(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "not-a-tool", "arguments": {} }
        }));
        assert_eq!(unknown["error"]["code"], -32602);
        let bad_limit = call(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "activity", "arguments": { "limit": 5000 } }
        }));
        assert_eq!(bad_limit["error"]["code"], -32602);
    }

    #[test]
    fn serves_resources() {
        let list = call(json!({"jsonrpc":"2.0","id":1,"method":"resources/list"}));
        assert_eq!(list["result"]["resources"].as_array().unwrap().len(), 3);
        let read = call(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/read",
            "params": { "uri": "electric-eye://status" }
        }));
        assert!(
            read["result"]["contents"][0]["text"]
                .as_str()
                .unwrap()
                .contains("electric-eyed")
        );
    }

    #[test]
    fn rejects_invalid_json_and_unknown_methods() {
        let invalid = handle_message("{", &state(), &ToolProfile::default()).unwrap();
        assert_eq!(invalid["error"]["code"], -32700);
        let unknown = call(json!({"jsonrpc":"2.0","id":1,"method":"frobnicate"}));
        assert_eq!(unknown["error"]["code"], -32601);
    }

    #[test]
    fn socket_server_round_trips_requests() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("mcp.sock");
        let socket = bind_socket(&path).unwrap();
        let state = state();
        let server = Server::start(socket, Arc::clone(&state), ToolProfile::default()).unwrap();

        let mut client = UnixStream::connect(&path).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .write_all(
                b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n\
                  {\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n",
            )
            .unwrap();

        let mut reader = BufReader::new(client);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let initialize: Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(initialize["result"]["serverInfo"]["name"], SERVER_NAME);
        line.clear();
        reader.read_line(&mut line).unwrap();
        let tools: Value = serde_json::from_str(line.trim()).unwrap();
        assert!(!tools["result"]["tools"].as_array().unwrap().is_empty());

        drop(server);
        assert!(!path.exists());
    }
}

#[cfg(test)]
mod framing_regressions {
    use super::*;
    use std::io::Read;

    #[test]
    fn oversized_unterminated_frames_are_rejected_before_a_newline() {
        let state = Arc::new(Mutex::new(SharedState::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let (mut client, server) = UnixStream::pair().unwrap();
        let join = thread::spawn(move || {
            handle_client(server, &state, &stopping, &ToolProfile::default())
        });
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client.write_all(&vec![b'x'; 32 * 1024]).unwrap();
        let mut line = String::new();
        let result = BufReader::new(client.try_clone().unwrap()).read_line(&mut line);
        stop.store(true, Ordering::Relaxed);
        drop(client);
        join.join().unwrap().unwrap();
        result.unwrap();
        assert!(line.contains("request too large"), "{line}");
    }

    #[test]
    fn incomplete_frames_have_an_absolute_deadline_but_idle_sessions_can_resume() {
        let mut config = crate::config::Config::default();
        config.limits.api_timeout_ms = 60;
        let state = Arc::new(Mutex::new(SharedState::with_config(config)));
        let (mut client, server) = UnixStream::pair().unwrap();
        let join = thread::spawn(move || {
            handle_client(
                server,
                &state,
                &AtomicBool::new(false),
                &ToolProfile::default(),
            )
        });
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        // An idle MCP session is persistent; only an incomplete frame expires.
        thread::sleep(Duration::from_millis(90));
        client
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n")
            .unwrap();
        let mut reader = BufReader::new(client.try_clone().unwrap());
        let mut response = String::new();
        reader.read_line(&mut response).unwrap();
        assert_eq!(serde_json::from_str::<Value>(&response).unwrap()["id"], 1);
        let start = Instant::now();
        let mut writer = client.try_clone().unwrap();
        let drip = thread::spawn(move || {
            for _ in 0..100 {
                if writer.write_all(b" ").is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
        });
        let mut byte = [0];
        match reader.read(&mut byte) {
            Ok(0) => {}
            // A deadline close can surface as RST when the drip writer still
            // has unread bytes in flight; either way the session ended.
            Err(err) if err.kind() == io::ErrorKind::ConnectionReset => {}
            other => panic!("expected closed MCP session, got {other:?}"),
        }
        let error = join.join().unwrap().unwrap_err();
        drip.join().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_millis(800));
    }

    #[test]
    fn coalesced_and_fragmented_frames_remain_separate_requests() {
        let state = Arc::new(Mutex::new(SharedState::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let (mut client, server) = UnixStream::pair().unwrap();
        let join = thread::spawn(move || {
            handle_client(server, &state, &stopping, &ToolProfile::default())
        });
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .write_all(b"{\"id\":1,\"method\":\"ping\"}\n{\"id\":")
            .unwrap();
        let mut reader = BufReader::new(client.try_clone().unwrap());
        let mut response = String::new();
        reader.read_line(&mut response).unwrap();
        assert_eq!(serde_json::from_str::<Value>(&response).unwrap()["id"], 1);
        client.write_all(b"2,\"method\":\"ping\"}\n").unwrap();
        response.clear();
        reader.read_line(&mut response).unwrap();
        assert_eq!(serde_json::from_str::<Value>(&response).unwrap()["id"], 2);
        stop.store(true, Ordering::Relaxed);
        drop(reader);
        drop(client);
        join.join().unwrap().unwrap();
    }
}
