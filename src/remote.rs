//! Minimal synchronous HTTP client for the V1 relay backend.
//!
//! OMK talks to the relay server (see attest-poc: server/server.py) with a
//! tiny task protocol:
//!   POST /relay/submit  {token, op, params}          -> {taskId}
//!   GET  /relay/result?task=<id>&token=<token>       -> {done, result}
//!
//! The stock-side worker executes the task on a genuine, unrooted device's
//! TEE and posts the result back. This module deliberately uses only
//! std::net so no new dependencies are needed; plain HTTP is supported for
//! the validation phase (TLS is a later hardening item).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};

/// CRLF line terminator used on the wire.
const CRLF: &str = "\r\n";

/// Header/body separator.
const CRLF_LF: &str = "\r\n\r\n";

/// Task operations understood by the stock worker.
pub const OP_GENERATE_KEY: &str = "generate_key";
pub const OP_GET_CHAIN: &str = "get_chain";
pub const OP_GENERATE_KEY_AND_CHAIN: &str = "generate_key_and_chain";
pub const OP_SIGN: &str = "sign";
pub const OP_VERIFY: &str = "verify";
pub const OP_DELETE: &str = "delete";
pub const OP_EXISTS: &str = "exists";

/// Failure classes mapped onto OMK routing invariants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteErrorKind {
    /// Relay unreachable or no worker took the task in time. Treated as
    /// OMK-unavailable: callers may preserve the original system reply.
    Unavailable,
    /// The worker answered with a business error (keystore_exception etc).
    WorkerError(String),
    /// Protocol-level failure (bad JSON, unexpected shape).
    Protocol(String),
}

impl std::fmt::Display for RemoteErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RemoteErrorKind::Unavailable => write!(f, "remote unavailable"),
            RemoteErrorKind::WorkerError(message) => write!(f, "worker error: {message}"),
            RemoteErrorKind::Protocol(message) => write!(f, "protocol error: {message}"),
        }
    }
}

fn parse_base_url(server: &str) -> Result<(&str, u16, &str)> {
    // Accept "http://host[:port][/path]" (http only for now).
    let rest = server
        .strip_prefix("http://")
        .or_else(|| server.strip_prefix("https://"))
        .ok_or_else(|| anyhow!("relay server must start with http:// or https://"))?;
    let (host_port, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, ""),
    };
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().context("invalid relay port")?),
        None => (host_port, 8080u16),
    };
    if host.is_empty() {
        bail!("relay server host is empty");
    }
    Ok((host, port, path.trim_end_matches('/')))
}

pub(crate) fn http_request_raw(
    server: &str,
    method: &str,
    path_and_query: &str,
    body: Option<&Value>,
    timeout: Duration,
) -> Result<(u16, Value)> {
    let (host, port, base_path) = parse_base_url(server)?;
    let mut stream = TcpStream::connect((host, port))
        .with_context(|| format!("relay connect {host}:{port} failed (OMK-unavailable)"))?;
    stream
        .set_read_timeout(Some(timeout))
        .context("set read timeout")?;
    stream
        .set_write_timeout(Some(timeout))
        .context("set write timeout")?;
    stream.set_nodelay(true).context("set nodelay")?;

    let full_path = format!("{base_path}{path_and_query}");
    // The relay server (python http.server based) needs strict CRLF line
    // endings and is only reliable with HTTP/1.0 + Connection: close.
    let mut request = format!(
        "{method} {full_path} HTTP/1.0\r\nHost: {host}:{port}\r\nConnection: close\r\n"
    );
    if let Some(body) = body {
        let bytes = body.to_string();
        request.push_str("Content-Type: application/json");
        request.push_str(CRLF);
        request.push_str(&format!("Content-Length: {}", bytes.len()));
        request.push_str(CRLF);
        request.push_str(CRLF);
        request.push_str(&bytes);
    } else {
        request.push_str(CRLF);
    }
    stream
        .write_all(request.as_bytes())
        .context("relay write failed")?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .context("relay read failed")?;
    if response.is_empty() {
        bail!("relay returned an empty response from {host}:{port}");
    }
    let text = String::from_utf8(response).context("relay response not utf-8")?;
    let (head, body) = text
        .split_once(CRLF_LF)
        .ok_or_else(|| anyhow!("relay response has no body separator"))?;
    let status_line = head
        .lines()
        .next()
        .ok_or_else(|| anyhow!("relay response has no status line"))?;
    let code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| anyhow!("relay response has no status code"))?;
    let parsed: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    Ok((code, parsed))
}

/// Convert a relay get_chain response into concatenated DER bytes
/// (the keystore certificateChain wire format).
pub fn chain_from_response(data: &Value) -> Option<Vec<u8>> {
    let parts = chain_parts_from_response(data)?;
    Some(parts.concat())
}

/// Certificate chain from a relay get_chain response, as individual DER
/// certificates (leaf first).
pub fn chain_parts_from_response(data: &Value) -> Option<Vec<Vec<u8>>> {
    let arr = data.get("chain")?.as_array()?;
    let mut out = Vec::new();
    for value in arr {
        let b64 = value.as_str()?;
        out.push(B64.decode(b64).ok()?);
    }
    if out.is_empty() {
        return None;
    }
    Some(out)
}

/// Route one relay call: through the root proxy mailbox when it exists
/// (required on platforms that put keystore sockets on the empty
/// local-network table), otherwise straight from this process.
fn relay_request(
    server: &str,
    method: &str,
    path_and_query: &str,
    body: Option<&Value>,
    timeout: Duration,
) -> Result<(u16, Value)> {
    if crate::netproxy::mailbox_available() {
        return crate::netproxy::request(server, method, path_and_query, body, timeout);
    }
    http_request_raw(server, method, path_and_query, body, timeout)
}

/// Extract the worker's payload from a relay result envelope.
fn unwrap_result(result: &Value) -> Result<Value, RemoteErrorKind> {
    if result.get("ok").and_then(Value::as_bool).unwrap_or(false) {
        return Ok(result.get("data").cloned().unwrap_or(Value::Null));
    }
    let message = result
        .get("error")
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
        .unwrap_or("unknown worker error")
        .to_string();
    Err(RemoteErrorKind::WorkerError(message))
}

/// Submit one task and wait for the worker's result.
///
/// Fast path: a single `/relay/execute` call that submits the task and
/// long-polls server side, so no client-side result polling is needed.
/// Falls back to the submit + poll protocol when the server is older.
pub fn execute(
    server: &str,
    token: &str,
    op: &str,
    params: Value,
    timeout_ms: u64,
    poll_interval_ms: u64,
) -> Result<Value, RemoteErrorKind> {
    let body = json!({
        "token": token,
        "op": op,
        "params": params.clone(),
        "waitMs": timeout_ms,
    });
    let (code, reply) = relay_request(
        server,
        "POST",
        "/relay/execute",
        Some(&body),
        Duration::from_millis(timeout_ms.saturating_add(20_000)),
    )
    .map_err(|error| {
        log::warn!("event=route remote execute transport failed: {error:#}");
        RemoteErrorKind::Unavailable
    })?;
    match code {
        200 => {
            let result = reply.get("result").cloned().unwrap_or(Value::Null);
            unwrap_result(&result)
        }
        404 => {
            log::info!("event=route relay lacks /relay/execute; using submit+poll");
            execute_legacy(server, token, op, params, timeout_ms, poll_interval_ms)
        }
        504 => {
            log::warn!("event=route remote execute timed out waiting for a worker");
            Err(RemoteErrorKind::Unavailable)
        }
        other => {
            log::warn!("event=route remote execute rejected with HTTP {other}");
            Err(RemoteErrorKind::Unavailable)
        }
    }
}

/// Legacy two-step protocol (submit, then poll for the result).
fn execute_legacy(
    server: &str,
    token: &str,
    op: &str,
    params: Value,
    timeout_ms: u64,
    poll_interval_ms: u64,
) -> Result<Value, RemoteErrorKind> {
    let submit_body = json!({"token": token, "op": op, "params": params});
    let (code, submit_reply) = relay_request(
        server,
        "POST",
        "/relay/submit",
        Some(&submit_body),
        Duration::from_secs(10),
    )
    .map_err(|error| {
        log::warn!("event=route remote submit transport failed: {error:#}");
        RemoteErrorKind::Unavailable
    })?;
    if code != 200 {
        log::warn!("event=route remote submit rejected with HTTP {code}");
        return Err(RemoteErrorKind::Unavailable);
    }
    let task_id = submit_reply
        .get("taskId")
        .and_then(Value::as_str)
        .ok_or_else(|| RemoteErrorKind::Protocol("submit response lacks taskId".to_string()))?;

    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let query = format!("/relay/result?task={task_id}&token={token}");
    while Instant::now() < deadline {
        let (code, reply) = relay_request(
            server,
            "GET",
            &query,
            None,
            Duration::from_millis(poll_interval_ms.max(500) + 2000),
        )
        .map_err(|error| {
            log::warn!("event=route remote poll transport failed: {error:#}");
            RemoteErrorKind::Unavailable
        })?;
        if code == 404 {
            return Err(RemoteErrorKind::Protocol("task not found on server".to_string()));
        }
        if code != 200 {
            return Err(RemoteErrorKind::Unavailable);
        }
        if reply.get("done").and_then(Value::as_bool).unwrap_or(false) {
            let result = reply.get("result").cloned().unwrap_or(Value::Null);
            return unwrap_result(&result);
        }
        std::thread::sleep(Duration::from_millis(poll_interval_ms.max(100)));
    }
    Err(RemoteErrorKind::Unavailable) // timed out waiting for a worker
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_http_url() {
        let (host, port, path) = parse_base_url("http://203.0.113.10:8080").unwrap();
        assert_eq!(host, "203.0.113.10");
        assert_eq!(port, 8080);
        assert_eq!(path, "");
        let (host2, port2, path2) = parse_base_url("http://host:9000/relay").unwrap();
        assert_eq!(host2, "host");
        assert_eq!(port2, 9000);
        assert_eq!(path2, "/relay");
    }

    #[test]
    fn rejects_bad_urls() {
        assert!(parse_base_url("ftp://x").is_err());
        assert!(parse_base_url("http://").is_err());
    }

    #[test]
    fn unknown_op_is_a_worker_business_error() {
        let e = RemoteErrorKind::WorkerError("keystore_exception".to_string());
        assert!(e.to_string().contains("worker error"));
        assert!(RemoteErrorKind::Unavailable.to_string().contains("unavailable"));
    }
}
