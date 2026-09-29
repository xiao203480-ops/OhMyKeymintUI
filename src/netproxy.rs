//! Root-side network proxy for the V1 relay client.
//!
//! On this platform the netd socket mark applied to keystore-uid sockets
//! selects the (empty) local-network routing table, so the daemon's own
//! connect() fails with ENETUNREACH. The module wrapper therefore starts a
//! root helper (this same binary with --netproxy) that performs the relay
//! HTTP work on the daemon's behalf through a file mailbox inside the OMK
//! data directory, which both security domains can access.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

/// Directory used as the request/response mailbox.
pub const MAILBOX_DIR: &str = "/data/misc/keystore/omk/netmail";

/// Upper bound accepted from clients for a proxied call.
const MAX_PROXY_TIMEOUT_MS: u64 = 120_000;

/// Keystore uid/gid owning the mailbox files.
const KEYSTORE_UID: libc::uid_t = 1017;
const KEYSTORE_GID: libc::gid_t = 1017;

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn mailbox_dir() -> PathBuf {
    PathBuf::from(MAILBOX_DIR)
}

/// True when the root proxy mailbox is available.
pub fn mailbox_available() -> bool {
    mailbox_dir().is_dir()
}

pub(crate) fn fix_owner(path: &Path, mode: libc::mode_t) {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return;
    };
    unsafe {
        libc::chmod(c_path.as_ptr(), mode);
        libc::chown(c_path.as_ptr(), KEYSTORE_UID, KEYSTORE_GID);
    }
}

/// Root-side proxy loop, started by the module wrapper with --netproxy.
pub fn run_proxy() -> ! {
    let dir = mailbox_dir();
    if let Err(error) = fs::create_dir_all(&dir) {
        eprintln!("netproxy: cannot create {}: {error:#}", dir.display());
        std::process::exit(1);
    }
    fix_owner(&dir, 0o770);
    println!("netproxy: serving {}", dir.display());
    loop {
        match serve_once(&dir) {
            Ok(()) => thread::sleep(Duration::from_millis(25)),
            Err(error) => {
                eprintln!("netproxy: {error:#}");
                thread::sleep(Duration::from_millis(500));
            }
        }
    }
}

fn serve_once(dir: &Path) -> Result<()> {
    let entries = fs::read_dir(dir).context("read mailbox")?;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(id) = name
            .strip_prefix("req-")
            .and_then(|rest| rest.strip_suffix(".json"))
        else {
            continue;
        };
        let request_path = entry.path();
        let Ok(raw) = fs::read_to_string(&request_path) else {
            continue;
        };
        let _ = fs::remove_file(&request_path);
        let parsed: Value = match serde_json::from_str(&raw) {
            Ok(value) => value,
            Err(error) => {
                write_response(dir, id, json!({"error": format!("bad request: {error}")}));
                continue;
            }
        };
        let server = parsed
            .get("server")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let method = parsed.get("method").and_then(Value::as_str).unwrap_or("GET");
        let path = parsed.get("path").and_then(Value::as_str).unwrap_or("/");
        let body = parsed.get("body").cloned();
        let timeout_ms = parsed
            .get("timeoutMs")
            .and_then(Value::as_u64)
            .unwrap_or(15_000)
            .min(MAX_PROXY_TIMEOUT_MS);
        let result = crate::remote::http_request_raw(
            server,
            method,
            path,
            body.as_ref(),
            Duration::from_millis(timeout_ms),
        );
        match result {
            Ok((status, value)) => {
                write_response(dir, id, json!({"status": status, "body": value}));
            }
            Err(error) => {
                write_response(dir, id, json!({"error": format!("{error:#}")}));
            }
        }
    }
    Ok(())
}

fn write_response(dir: &Path, id: &str, value: Value) {
    let path = dir.join(format!("resp-{id}.json"));
    if let Err(error) = fs::write(&path, value.to_string()) {
        eprintln!("netproxy: cannot write {}: {error}", path.display());
        return;
    }
    fix_owner(&path, 0o660);
}

/// Client side: perform one relay request through the mailbox.
pub fn request(
    server: &str,
    method: &str,
    path_and_query: &str,
    body: Option<&Value>,
    timeout: Duration,
) -> Result<(u16, Value)> {
    let dir = mailbox_dir();
    let id = format!(
        "{}-{}-{}",
        std::process::id(),
        micros_since_epoch(),
        REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let request_path = dir.join(format!("req-{id}.json"));
    let response_path = dir.join(format!("resp-{id}.json"));
    let payload = json!({
        "server": server,
        "method": method,
        "path": path_and_query,
        "body": body,
        "timeoutMs": timeout.as_millis() as u64,
    });
    fs::write(&request_path, payload.to_string())
        .with_context(|| format!("write proxy request {}", request_path.display()))?;

    let deadline = Instant::now() + timeout + Duration::from_secs(10);
    loop {
        if response_path.exists() {
            let text = fs::read_to_string(&response_path)
                .with_context(|| format!("read proxy response {}", response_path.display()))?;
            let _ = fs::remove_file(&response_path);
            let value: Value = serde_json::from_str(&text).context("proxy response not json")?;
            if let Some(error) = value.get("error").and_then(Value::as_str) {
                bail!("proxy transport failed: {error}");
            }
            let status = value.get("status").and_then(Value::as_u64).unwrap_or(0) as u16;
            return Ok((status, value.get("body").cloned().unwrap_or(Value::Null)));
        }
        if Instant::now() >= deadline {
            let _ = fs::remove_file(&request_path);
            bail!("proxy request timed out");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn micros_since_epoch() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_micros())
        .unwrap_or(0)
}
