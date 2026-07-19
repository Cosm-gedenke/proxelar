//! Portable capture sessions and interoperable export formats.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::path::Path;

use base64::Engine as _;
use bytes::Bytes;
use chrono::{TimeZone as _, Utc};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, Version};
use proxyapi_models::{
    BodyMetadata, CapturedDnsExchange, CapturedFlow, CapturedTcpStream, CapturedWebSocket,
    ProxiedRequest, ProxiedResponse, TrafficSession, SESSION_FORMAT_VERSION,
};
use serde_json::{json, Value};
use thiserror::Error;

use crate::ProxyEvent;

/// Errors produced while reading, writing, importing, or exporting sessions.
#[derive(Debug, Error)]
pub enum SessionError {
    #[error("session I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid session JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported session format version {found}; this build supports {supported}")]
    UnsupportedVersion { found: u32, supported: u32 },
    #[error("invalid HAR: {0}")]
    InvalidHar(String),
    #[error("invalid native session: {0}")]
    InvalidSession(String),
    #[error("invalid HTTP value in imported capture: {0}")]
    InvalidHttp(String),
}

/// Secret-removal policy applied to exports.
#[derive(Clone, Debug)]
pub struct RedactionPolicy {
    header_names: HashSet<HeaderName>,
    query_names: HashSet<String>,
    replacement: String,
}

impl Default for RedactionPolicy {
    fn default() -> Self {
        Self::new(
            [
                "authorization",
                "proxy-authorization",
                "cookie",
                "set-cookie",
            ],
            [
                "access_token",
                "api_key",
                "apikey",
                "password",
                "secret",
                "token",
            ],
        )
    }
}

impl RedactionPolicy {
    pub fn new<H, Q, HS, QS>(headers: H, query: Q) -> Self
    where
        H: IntoIterator<Item = HS>,
        Q: IntoIterator<Item = QS>,
        HS: AsRef<str>,
        QS: AsRef<str>,
    {
        Self {
            header_names: headers
                .into_iter()
                .filter_map(|name| HeaderName::from_bytes(name.as_ref().as_bytes()).ok())
                .collect(),
            query_names: query
                .into_iter()
                .map(|name| name.as_ref().to_ascii_lowercase())
                .collect(),
            replacement: "[REDACTED]".to_owned(),
        }
    }

    pub fn with_replacement(mut self, replacement: impl Into<String>) -> Self {
        self.replacement = replacement.into();
        self
    }

    fn redact_headers(&self, headers: &HeaderMap) -> HeaderMap {
        let mut redacted = HeaderMap::new();
        for (name, value) in headers {
            let value = if self.header_names.contains(name) {
                HeaderValue::from_str(&self.replacement)
                    .unwrap_or_else(|_| HeaderValue::from_static("[REDACTED]"))
            } else {
                value.clone()
            };
            redacted.append(name.clone(), value);
        }
        redacted
    }

    fn redact_uri(&self, uri: &Uri) -> Uri {
        let Some(query) = uri.query() else {
            return uri.clone();
        };
        let mut changed = false;
        let query = query
            .split('&')
            .map(|pair| {
                let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
                if self.query_names.contains(&name.to_ascii_lowercase()) {
                    changed = true;
                    format!("{name}={}", self.replacement)
                } else if value.is_empty() && !pair.contains('=') {
                    name.to_owned()
                } else {
                    format!("{name}={value}")
                }
            })
            .collect::<Vec<_>>()
            .join("&");
        if !changed {
            return uri.clone();
        }

        let mut parts = uri.clone().into_parts();
        let path = uri.path();
        parts.path_and_query = format!("{path}?{query}").parse().ok();
        Uri::from_parts(parts).unwrap_or_else(|_| uri.clone())
    }

    fn redact_request(&self, request: &ProxiedRequest) -> ProxiedRequest {
        ProxiedRequest::new_with_body_metadata(
            request.method().clone(),
            self.redact_uri(request.uri()),
            request.version(),
            self.redact_headers(request.headers()),
            request.body().clone(),
            request.body_metadata(),
            request.time(),
        )
    }

    fn redact_response(&self, response: &ProxiedResponse) -> ProxiedResponse {
        ProxiedResponse::new_with_body_metadata(
            response.status(),
            response.version(),
            self.redact_headers(response.headers()),
            response.body().clone(),
            response.body_metadata(),
            response.time(),
        )
    }
}

/// In-memory collector used by interfaces, persistence, and the REST API.
#[derive(Debug)]
pub struct SessionRecorder {
    session: TrafficSession,
}

impl Default for SessionRecorder {
    fn default() -> Self {
        Self::new(Utc::now().timestamp_millis())
    }
}

impl SessionRecorder {
    pub const fn new(created_at: i64) -> Self {
        Self {
            session: TrafficSession::new(created_at),
        }
    }

    pub fn from_session(session: TrafficSession) -> Result<Self, SessionError> {
        validate_version(&session)?;
        let largest_id = session
            .flows
            .iter()
            .map(|flow| flow.id)
            .chain(session.websockets.iter().map(|flow| flow.id))
            .chain(session.tcp_streams.iter().map(|stream| stream.id))
            .chain(session.dns_exchanges.iter().map(|exchange| exchange.id))
            .chain(session.udp_exchanges.iter().map(|exchange| exchange.id))
            .max()
            .unwrap_or(0);
        if largest_id == u64::MAX {
            return Err(SessionError::InvalidSession(
                "flow identifiers must be smaller than u64::MAX".to_owned(),
            ));
        }
        crate::event::reserve_ids_through(largest_id);
        Ok(Self { session })
    }

    pub const fn session(&self) -> &TrafficSession {
        &self.session
    }

    pub fn snapshot(&self) -> TrafficSession {
        self.session.clone()
    }

    pub fn clear(&mut self) {
        self.session.flows.clear();
        self.session.websockets.clear();
        self.session.tcp_streams.clear();
        self.session.dns_exchanges.clear();
        self.session.udp_exchanges.clear();
    }

    /// Apply a proxy event to the session. Pending and error events are not
    /// persisted because they do not represent replayable wire exchanges.
    pub fn record(&mut self, event: &ProxyEvent) {
        match event {
            ProxyEvent::RequestComplete {
                id,
                request,
                response,
            } => {
                let flow = CapturedFlow {
                    id: *id,
                    request: request.as_ref().clone(),
                    response: response.as_ref().clone(),
                };
                if let Some(existing) = self.session.flows.iter_mut().find(|flow| flow.id == *id) {
                    *existing = flow;
                } else {
                    self.session.flows.push(flow);
                }
            }
            ProxyEvent::WebSocketConnected {
                id,
                request,
                response,
            } => {
                let connection = CapturedWebSocket {
                    id: *id,
                    request: request.as_ref().clone(),
                    response: response.as_ref().clone(),
                    frames: Vec::new(),
                    closed: false,
                };
                if let Some(existing) = self
                    .session
                    .websockets
                    .iter_mut()
                    .find(|connection| connection.id == *id)
                {
                    *existing = connection;
                } else {
                    self.session.websockets.push(connection);
                }
            }
            ProxyEvent::WebSocketFrame { conn_id, frame } => {
                if let Some(connection) = self
                    .session
                    .websockets
                    .iter_mut()
                    .find(|connection| connection.id == *conn_id)
                {
                    connection.frames.push(frame.as_ref().clone());
                }
            }
            ProxyEvent::WebSocketClosed { conn_id } => {
                if let Some(connection) = self
                    .session
                    .websockets
                    .iter_mut()
                    .find(|connection| connection.id == *conn_id)
                {
                    connection.closed = true;
                }
            }
            ProxyEvent::TcpConnected {
                id,
                target,
                opened_at,
            } => {
                self.session.tcp_streams.push(CapturedTcpStream {
                    id: *id,
                    target: target.clone(),
                    opened_at: *opened_at,
                    chunks: Vec::new(),
                    closed: false,
                });
            }
            ProxyEvent::TcpData { stream_id, chunk } => {
                if let Some(stream) = self
                    .session
                    .tcp_streams
                    .iter_mut()
                    .find(|stream| stream.id == *stream_id)
                {
                    const MAX_CHUNKS_PER_STREAM: usize = 10_000;
                    if stream.chunks.len() < MAX_CHUNKS_PER_STREAM {
                        stream.chunks.push(chunk.as_ref().clone());
                    }
                }
            }
            ProxyEvent::TcpClosed { stream_id } => {
                if let Some(stream) = self
                    .session
                    .tcp_streams
                    .iter_mut()
                    .find(|stream| stream.id == *stream_id)
                {
                    stream.closed = true;
                }
            }
            ProxyEvent::DnsQuery {
                id,
                name,
                query_type,
                time,
            } => {
                self.session.dns_exchanges.push(CapturedDnsExchange {
                    id: *id,
                    name: name.clone(),
                    query_type: *query_type,
                    time: *time,
                    answers: Vec::new(),
                    overridden: false,
                    completed: false,
                });
            }
            ProxyEvent::DnsResponse {
                id,
                answers,
                overridden,
            } => {
                if let Some(exchange) = self
                    .session
                    .dns_exchanges
                    .iter_mut()
                    .find(|exchange| exchange.id == *id)
                {
                    exchange.answers.clone_from(answers);
                    exchange.overridden = *overridden;
                    exchange.completed = true;
                }
            }
            ProxyEvent::RequestIntercepted { .. } | ProxyEvent::Error { .. } => {}
            ProxyEvent::UdpExchange { exchange } => {
                if let Some(existing) = self
                    .session
                    .udp_exchanges
                    .iter_mut()
                    .find(|existing| existing.id == exchange.id)
                {
                    existing.clone_from(exchange);
                } else {
                    self.session.udp_exchanges.push(exchange.as_ref().clone());
                }
            }
        }
    }
}

pub fn save_session(path: impl AsRef<Path>, session: &TrafficSession) -> Result<(), SessionError> {
    validate_version(session)?;
    let bytes = serde_json::to_vec_pretty(session)?;
    write_private(path.as_ref(), &bytes)?;
    Ok(())
}

pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        options.mode(0o600);
        let mut file = options.open(path)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let mut file = options.open(path)?;
        file.write_all(bytes)?;
        file.sync_all()
    }
}

pub fn load_session(path: impl AsRef<Path>) -> Result<TrafficSession, SessionError> {
    let bytes = fs::read(path)?;
    let session = serde_json::from_slice(&bytes)?;
    validate_version(&session)?;
    Ok(session)
}

/// Recreate the public event stream represented by a stored session.
///
/// Interfaces use this to display imported history through the same code path
/// as live traffic.
pub fn session_events(session: &TrafficSession) -> Vec<ProxyEvent> {
    let http_events = session
        .flows
        .iter()
        .map(|flow| ProxyEvent::RequestComplete {
            id: flow.id,
            request: Box::new(flow.request.clone()),
            response: Box::new(flow.response.clone()),
        });
    let websocket_events = session.websockets.iter().flat_map(|connection| {
        let connected = std::iter::once(ProxyEvent::WebSocketConnected {
            id: connection.id,
            request: Box::new(connection.request.clone()),
            response: Box::new(connection.response.clone()),
        });
        let frames = connection
            .frames
            .iter()
            .cloned()
            .map(|frame| ProxyEvent::WebSocketFrame {
                conn_id: connection.id,
                frame: Box::new(frame),
            });
        let closed = connection
            .closed
            .then_some(ProxyEvent::WebSocketClosed {
                conn_id: connection.id,
            })
            .into_iter();
        connected.chain(frames).chain(closed)
    });
    let tcp_events = session.tcp_streams.iter().flat_map(|stream| {
        let connected = std::iter::once(ProxyEvent::TcpConnected {
            id: stream.id,
            target: stream.target.clone(),
            opened_at: stream.opened_at,
        });
        let chunks = stream
            .chunks
            .iter()
            .cloned()
            .map(|chunk| ProxyEvent::TcpData {
                stream_id: stream.id,
                chunk: Box::new(chunk),
            });
        let closed = stream
            .closed
            .then_some(ProxyEvent::TcpClosed {
                stream_id: stream.id,
            })
            .into_iter();
        connected.chain(chunks).chain(closed)
    });
    let dns_events = session.dns_exchanges.iter().flat_map(|exchange| {
        let query = std::iter::once(ProxyEvent::DnsQuery {
            id: exchange.id,
            name: exchange.name.clone(),
            query_type: exchange.query_type,
            time: exchange.time,
        });
        let response = exchange
            .completed
            .then(|| ProxyEvent::DnsResponse {
                id: exchange.id,
                answers: exchange.answers.clone(),
                overridden: exchange.overridden,
            })
            .into_iter();
        query.chain(response)
    });
    let udp_events =
        session
            .udp_exchanges
            .iter()
            .cloned()
            .map(|exchange| ProxyEvent::UdpExchange {
                exchange: Box::new(exchange),
            });
    http_events
        .chain(websocket_events)
        .chain(tcp_events)
        .chain(dns_events)
        .chain(udp_events)
        .collect()
}

fn validate_version(session: &TrafficSession) -> Result<(), SessionError> {
    if session.version != SESSION_FORMAT_VERSION {
        return Err(SessionError::UnsupportedVersion {
            found: session.version,
            supported: SESSION_FORMAT_VERSION,
        });
    }
    Ok(())
}

pub fn export_har(
    path: impl AsRef<Path>,
    session: &TrafficSession,
    redaction: Option<&RedactionPolicy>,
) -> Result<(), SessionError> {
    let entries: Vec<Value> = session
        .flows
        .iter()
        .map(|flow| har_entry(flow, redaction))
        .collect();
    let har = json!({
        "log": {
            "version": "1.2",
            "creator": { "name": "Proxelar", "version": env!("CARGO_PKG_VERSION") },
            "entries": entries
        }
    });
    fs::write(path, serde_json::to_vec_pretty(&har)?)?;
    Ok(())
}

fn har_entry(flow: &CapturedFlow, redaction: Option<&RedactionPolicy>) -> Value {
    let request = redaction
        .map(|policy| policy.redact_request(&flow.request))
        .unwrap_or_else(|| flow.request.clone());
    let response = redaction
        .map(|policy| policy.redact_response(&flow.response))
        .unwrap_or_else(|| flow.response.clone());
    let duration = response.time().saturating_sub(request.time()).max(0);
    let started = Utc
        .timestamp_millis_opt(request.time())
        .single()
        .unwrap_or_else(Utc::now)
        .to_rfc3339();
    let request_body = har_content(request.body(), request.headers(), request.body_metadata());
    let response_body = har_content(
        response.body(),
        response.headers(),
        response.body_metadata(),
    );
    let query = request
        .uri()
        .query()
        .map(|query| {
            query
                .split('&')
                .map(|pair| {
                    let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
                    json!({"name": name, "value": value})
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    json!({
        "startedDateTime": started,
        "time": duration,
        "request": {
            "method": request.method().as_str(),
            "url": request.uri().to_string(),
            "httpVersion": version_string(request.version()),
            "headers": har_headers(request.headers()),
            "queryString": query,
            "cookies": [],
            "headersSize": -1,
            "bodySize": request.body_metadata().total_seen,
            "postData": request_body,
            "comment": truncation_comment(request.body_metadata())
        },
        "response": {
            "status": response.status().as_u16(),
            "statusText": response.status().canonical_reason().unwrap_or(""),
            "httpVersion": version_string(response.version()),
            "headers": har_headers(response.headers()),
            "cookies": [],
            "content": response_body,
            "redirectURL": response.headers().get(http::header::LOCATION)
                .and_then(|value| value.to_str().ok()).unwrap_or(""),
            "headersSize": -1,
            "bodySize": response.body_metadata().total_seen,
            "comment": truncation_comment(response.body_metadata())
        },
        "cache": {},
        "timings": { "send": 0, "wait": duration, "receive": 0 }
    })
}

fn har_headers(headers: &HeaderMap) -> Vec<Value> {
    headers
        .iter()
        .map(|(name, value)| {
            json!({
                "name": name.as_str(),
                "value": String::from_utf8_lossy(value.as_bytes())
            })
        })
        .collect()
}

fn har_content(body: &Bytes, headers: &HeaderMap, metadata: BodyMetadata) -> Value {
    let mime = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("application/octet-stream");
    if let Ok(text) = std::str::from_utf8(body) {
        json!({
            "size": metadata.total_seen,
            "mimeType": mime,
            "text": text,
            "comment": truncation_comment(metadata)
        })
    } else {
        json!({
            "size": metadata.total_seen,
            "mimeType": mime,
            "text": base64::engine::general_purpose::STANDARD.encode(body),
            "encoding": "base64",
            "comment": truncation_comment(metadata)
        })
    }
}

fn truncation_comment(metadata: BodyMetadata) -> Option<String> {
    metadata.truncated.then(|| {
        format!(
            "Body truncated by Proxelar; captured prefix, observed {} wire bytes",
            metadata.total_seen
        )
    })
}

pub fn export_curl(
    path: impl AsRef<Path>,
    session: &TrafficSession,
    redaction: Option<&RedactionPolicy>,
) -> Result<(), SessionError> {
    let mut output = String::new();
    for flow in &session.flows {
        let request = redaction
            .map(|policy| policy.redact_request(&flow.request))
            .unwrap_or_else(|| flow.request.clone());
        writeln!(output, "# flow {}", flow.id).expect("writing to String cannot fail");
        write!(
            output,
            "curl --request {} {}",
            shell_quote(request.method().as_str()),
            shell_quote(&request.uri().to_string())
        )
        .expect("writing to String cannot fail");
        for (name, value) in request.headers() {
            let header = format!(
                "{}: {}",
                name.as_str(),
                String::from_utf8_lossy(value.as_bytes())
            );
            output.push_str(" \\");
            output.push('\n');
            write!(output, "  --header {}", shell_quote(&header))
                .expect("writing to String cannot fail");
        }
        if !request.body().is_empty() {
            let encoded = base64::engine::general_purpose::STANDARD.encode(request.body());
            output.push_str(" \\");
            output.push('\n');
            write!(
                output,
                "  --data-binary \"$(printf %s {} | base64 --decode)\"",
                shell_quote(&encoded)
            )
            .expect("writing to String cannot fail");
        }
        output.push_str("\n\n");
    }
    fs::write(path, output)?;
    Ok(())
}

pub fn export_raw(
    directory: impl AsRef<Path>,
    session: &TrafficSession,
    redaction: Option<&RedactionPolicy>,
) -> Result<(), SessionError> {
    let directory = directory.as_ref();
    fs::create_dir_all(directory)?;
    for flow in &session.flows {
        let request = redaction
            .map(|policy| policy.redact_request(&flow.request))
            .unwrap_or_else(|| flow.request.clone());
        let response = redaction
            .map(|policy| policy.redact_response(&flow.response))
            .unwrap_or_else(|| flow.response.clone());
        fs::write(
            directory.join(format!("{:08}-request.http", flow.id)),
            raw_request(&request),
        )?;
        fs::write(
            directory.join(format!("{:08}-response.http", flow.id)),
            raw_response(&response),
        )?;
    }
    Ok(())
}

fn raw_request(request: &ProxiedRequest) -> Vec<u8> {
    let target = request
        .uri()
        .path_and_query()
        .map_or("/", |value| value.as_str());
    let mut output = format!(
        "{} {} {}\r\n",
        request.method(),
        target,
        version_string(request.version())
    )
    .into_bytes();
    append_headers_and_body(&mut output, request.headers(), request.body());
    output
}

fn raw_response(response: &ProxiedResponse) -> Vec<u8> {
    let mut output = format!(
        "{} {} {}\r\n",
        version_string(response.version()),
        response.status().as_u16(),
        response.status().canonical_reason().unwrap_or("")
    )
    .into_bytes();
    append_headers_and_body(&mut output, response.headers(), response.body());
    output
}

fn append_headers_and_body(output: &mut Vec<u8>, headers: &HeaderMap, body: &Bytes) {
    for (name, value) in headers {
        output.extend_from_slice(name.as_str().as_bytes());
        output.extend_from_slice(b": ");
        output.extend_from_slice(value.as_bytes());
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(body);
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn version_string(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2",
        Version::HTTP_3 => "HTTP/3",
        _ => "HTTP/1.1",
    }
}

/// Import the HTTP entries in a HAR 1.2 file into a Proxelar session.
pub fn import_har(path: impl AsRef<Path>) -> Result<TrafficSession, SessionError> {
    let data: Value = serde_json::from_slice(&fs::read(path)?)?;
    let entries = data
        .pointer("/log/entries")
        .and_then(Value::as_array)
        .ok_or_else(|| SessionError::InvalidHar("missing log.entries array".to_owned()))?;
    let mut session = TrafficSession::new(Utc::now().timestamp_millis());
    for (index, entry) in entries.iter().enumerate() {
        session.flows.push(import_har_entry(index, entry)?);
    }
    Ok(session)
}

fn import_har_entry(index: usize, entry: &Value) -> Result<CapturedFlow, SessionError> {
    let request = entry
        .get("request")
        .ok_or_else(|| SessionError::InvalidHar(format!("entry {index} missing request")))?;
    let response = entry
        .get("response")
        .ok_or_else(|| SessionError::InvalidHar(format!("entry {index} missing response")))?;
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("GET")
        .parse::<Method>()
        .map_err(|error| SessionError::InvalidHttp(error.to_string()))?;
    let uri = request
        .get("url")
        .and_then(Value::as_str)
        .ok_or_else(|| SessionError::InvalidHar(format!("entry {index} missing request.url")))?
        .parse::<Uri>()
        .map_err(|error| SessionError::InvalidHttp(error.to_string()))?;
    let status = StatusCode::from_u16(
        response
            .get("status")
            .and_then(Value::as_u64)
            .and_then(|value| u16::try_from(value).ok())
            .unwrap_or(200),
    )
    .map_err(|error| SessionError::InvalidHttp(error.to_string()))?;
    let started = entry
        .get("startedDateTime")
        .and_then(Value::as_str)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map_or_else(
            || Utc::now().timestamp_millis(),
            |value| value.timestamp_millis(),
        );
    let duration = entry.get("time").and_then(Value::as_f64).unwrap_or(0.0) as i64;
    let request_headers = import_har_headers(request.get("headers"))?;
    let response_headers = import_har_headers(response.get("headers"))?;
    let request_body = import_har_body(request.get("postData"))?;
    let response_body = import_har_body(response.get("content"))?;

    Ok(CapturedFlow {
        id: u64::try_from(index + 1).unwrap_or(u64::MAX),
        request: ProxiedRequest::new(
            method,
            uri,
            parse_version(request.get("httpVersion")),
            request_headers,
            request_body,
            started,
        ),
        response: ProxiedResponse::new(
            status,
            parse_version(response.get("httpVersion")),
            response_headers,
            response_body,
            started.saturating_add(duration),
        ),
    })
}

fn import_har_headers(value: Option<&Value>) -> Result<HeaderMap, SessionError> {
    let mut headers = HeaderMap::new();
    for header in value.and_then(Value::as_array).into_iter().flatten() {
        let Some(name) = header.get("name").and_then(Value::as_str) else {
            continue;
        };
        let Some(value) = header.get("value").and_then(Value::as_str) else {
            continue;
        };
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|error| SessionError::InvalidHttp(error.to_string()))?;
        let value = HeaderValue::from_str(value)
            .map_err(|error| SessionError::InvalidHttp(error.to_string()))?;
        headers.append(name, value);
    }
    Ok(headers)
}

fn import_har_body(value: Option<&Value>) -> Result<Bytes, SessionError> {
    let Some(value) = value else {
        return Ok(Bytes::new());
    };
    let Some(text) = value.get("text").and_then(Value::as_str) else {
        return Ok(Bytes::new());
    };
    if value.get("encoding").and_then(Value::as_str) == Some("base64") {
        return base64::engine::general_purpose::STANDARD
            .decode(text)
            .map(Bytes::from)
            .map_err(|error| SessionError::InvalidHar(error.to_string()));
    }
    Ok(Bytes::copy_from_slice(text.as_bytes()))
}

fn parse_version(value: Option<&Value>) -> Version {
    match value.and_then(Value::as_str).unwrap_or("HTTP/1.1") {
        "HTTP/0.9" => Version::HTTP_09,
        "HTTP/1.0" => Version::HTTP_10,
        "HTTP/2" | "HTTP/2.0" => Version::HTTP_2,
        "HTTP/3" | "HTTP/3.0" => Version::HTTP_3,
        _ => Version::HTTP_11,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn flow(id: u64) -> CapturedFlow {
        let mut request_headers = HeaderMap::new();
        request_headers.append("cookie", "secret=one".parse().unwrap());
        request_headers.append("x-repeat", "one".parse().unwrap());
        request_headers.append("x-repeat", "two".parse().unwrap());
        let mut response_headers = HeaderMap::new();
        response_headers.insert("content-type", "application/json".parse().unwrap());
        CapturedFlow {
            id,
            request: ProxiedRequest::new(
                Method::POST,
                "https://example.test/path?token=secret".parse().unwrap(),
                Version::HTTP_11,
                request_headers,
                Bytes::from_static(b"request"),
                1_000,
            ),
            response: ProxiedResponse::new(
                StatusCode::OK,
                Version::HTTP_11,
                response_headers,
                Bytes::from_static(br#"{"ok":true}"#),
                1_025,
            ),
        }
    }

    #[test]
    fn recorder_tracks_http_websocket_and_dns_lifecycle() {
        let captured = flow(7);
        let mut recorder = SessionRecorder::new(1);
        recorder.record(&ProxyEvent::RequestComplete {
            id: captured.id,
            request: Box::new(captured.request.clone()),
            response: Box::new(captured.response.clone()),
        });
        recorder.record(&ProxyEvent::WebSocketConnected {
            id: 8,
            request: Box::new(captured.request.clone()),
            response: Box::new(captured.response.clone()),
        });
        recorder.record(&ProxyEvent::WebSocketClosed { conn_id: 8 });
        recorder.record(&ProxyEvent::DnsQuery {
            id: 9,
            name: "api.example.test".to_owned(),
            query_type: 1,
            time: 1_000,
        });
        recorder.record(&ProxyEvent::DnsResponse {
            id: 9,
            answers: vec!["127.0.0.1".to_owned()],
            overridden: true,
        });
        recorder.record(&ProxyEvent::UdpExchange {
            exchange: Box::new(proxyapi_models::CapturedUdpExchange {
                id: 10,
                target: "127.0.0.1:9000".to_owned(),
                client: "127.0.0.1:50000".to_owned(),
                time: 1_001,
                request: Bytes::from_static(b"request"),
                response: Bytes::new(),
                response_received: true,
                request_truncated: false,
                response_truncated: false,
            }),
        });

        assert_eq!(recorder.session().flows.len(), 1);
        assert_eq!(recorder.session().websockets.len(), 1);
        assert!(recorder.session().websockets[0].closed);
        assert_eq!(recorder.session().dns_exchanges.len(), 1);
        assert_eq!(recorder.session().dns_exchanges[0].answers, ["127.0.0.1"]);
        assert!(recorder.session().dns_exchanges[0].overridden);
        assert!(recorder.session().dns_exchanges[0].completed);
        assert_eq!(recorder.session().udp_exchanges.len(), 1);
        assert!(recorder.session().udp_exchanges[0].response_received);
    }

    #[test]
    fn native_session_roundtrip_preserves_duplicate_headers() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("capture.pxsession");
        let mut session = TrafficSession::new(1);
        session.flows.push(flow(1));

        save_session(&path, &session).unwrap();
        let loaded = load_session(&path).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        let repeated = loaded.flows[0]
            .request
            .headers()
            .get_all("x-repeat")
            .iter()
            .count();
        assert_eq!(repeated, 2);
    }

    #[test]
    fn loading_history_reserves_new_ids_after_existing_flows() {
        let mut session = TrafficSession::new(1);
        session.flows.push(flow(2_000_000));

        SessionRecorder::from_session(session).unwrap();

        assert!(crate::event::next_id() > 2_000_000);
    }

    #[test]
    fn exports_har_curl_and_raw_with_redaction() {
        let dir = tempdir().unwrap();
        let mut session = TrafficSession::new(1);
        session.flows.push(flow(3));
        let policy = RedactionPolicy::default();

        let har = dir.path().join("capture.har");
        let curl = dir.path().join("capture.sh");
        let raw = dir.path().join("raw");
        export_har(&har, &session, Some(&policy)).unwrap();
        export_curl(&curl, &session, Some(&policy)).unwrap();
        export_raw(&raw, &session, Some(&policy)).unwrap();

        let har_text = fs::read_to_string(har).unwrap();
        assert!(har_text.contains("[REDACTED]"));
        assert!(!har_text.contains("secret=one"));
        assert_eq!(
            import_har(dir.path().join("capture.har"))
                .unwrap()
                .flows
                .len(),
            1
        );
        assert!(fs::read_to_string(curl).unwrap().contains("curl --request"));
        assert!(raw.join("00000003-request.http").exists());
        assert!(raw.join("00000003-response.http").exists());
    }

    #[test]
    fn shell_quote_handles_single_quotes() {
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }
}
