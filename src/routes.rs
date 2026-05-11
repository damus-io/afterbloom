use std::net::SocketAddr;
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use axum::body::Body;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use bytes::Bytes;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::io::ReaderStream;

use crate::auth::{self, Action};
use crate::ratelimit::RateDecision;
use crate::state::AppState;
use crate::storage::{self, BlobMeta};

#[derive(Serialize)]
pub struct BlobDescriptor {
    pub url: String,
    pub sha256: String,
    pub size: u64,
    #[serde(rename = "type", skip_serializing_if = "String::is_empty")]
    pub mime: String,
    pub uploaded: u64,
}

impl BlobDescriptor {
    fn from_meta(public_url: &str, meta: BlobMeta) -> Self {
        let url = format!("{}/{}", public_url.trim_end_matches('/'), meta.sha256);
        Self {
            url,
            sha256: meta.sha256,
            size: meta.size,
            mime: meta.mime,
            uploaded: meta.uploaded_at,
        }
    }
}

#[derive(Serialize)]
struct ErrorBody {
    message: String,
}

fn error(status: StatusCode, msg: impl Into<String>) -> Response {
    let msg = msg.into();
    let body = ErrorBody { message: msg.clone() };
    let mut resp = (status, Json(body)).into_response();
    if let Ok(v) = HeaderValue::from_str(&msg) {
        resp.headers_mut().insert("x-reason", v);
    }
    resp
}

fn auth_error(msg: impl Into<String>) -> Response {
    let msg = msg.into();
    let body = ErrorBody { message: msg.clone() };
    let mut resp = (StatusCode::UNAUTHORIZED, Json(body)).into_response();
    if let Ok(v) = HeaderValue::from_str(&msg) {
        resp.headers_mut().insert("x-reason", v);
    }
    resp
}

fn extract_auth(headers: &HeaderMap, action: Action, max_lifetime: u64) -> Result<auth::VerifiedAuth, Response> {
    let raw = headers
        .get(header::AUTHORIZATION)
        .ok_or_else(|| auth_error("missing Authorization header"))?
        .to_str()
        .map_err(|_| auth_error("invalid Authorization header"))?;
    let event = auth::parse_header(raw).map_err(|e| auth_error(e.to_string()))?;
    auth::verify(&event, action, max_lifetime).map_err(|e| auth_error(e.to_string()))
}

pub async fn upload(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let verified = match extract_auth(&headers, Action::Upload, state.cfg.max_auth_lifetime_seconds) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if (body.len() as u64) > state.cfg.max_upload_bytes {
        return error(StatusCode::PAYLOAD_TOO_LARGE, "upload exceeds max size");
    }

    match state.ratelimit.check_upload(addr.ip(), body.len() as u64) {
        RateDecision::Ok => {}
        RateDecision::TooManyRequests => {
            return error(StatusCode::TOO_MANY_REQUESTS, "upload rate exceeded");
        }
        RateDecision::QuotaExceeded => {
            return error(StatusCode::TOO_MANY_REQUESTS, "byte quota exceeded");
        }
    }

    // If the auth event lists hashes (`x` tags), the body MUST hash to one of them.
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(&body);
    let computed = hex::encode(h.finalize());
    if !verified.hashes.is_empty() && !verified.hashes.contains(&computed) {
        return error(
            StatusCode::BAD_REQUEST,
            "uploaded blob hash does not match any 'x' tag in auth event",
        );
    }

    let mime = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            infer::get(&body)
                .map(|t| t.mime_type().to_string())
                .unwrap_or_else(|| "application/octet-stream".to_string())
        });

    match state.storage.put(&verified.pubkey, &body, &mime).await {
        Ok(meta) => Json(BlobDescriptor::from_meta(&state.cfg.public_url, meta)).into_response(),
        Err(e) => {
            tracing::error!("storage put failed: {e:#}");
            error(StatusCode::INTERNAL_SERVER_ERROR, "storage error")
        }
    }
}

pub async fn upload_head(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    // BUD-06: clients HEAD /upload to learn upload requirements. We return 200 if
    // the request looks acceptable, with X-Reason on failure.
    if let Some(len) = headers.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|s| s.parse::<u64>().ok()) {
        if len > state.cfg.max_upload_bytes {
            let mut resp = StatusCode::PAYLOAD_TOO_LARGE.into_response();
            resp.headers_mut().insert("x-reason", HeaderValue::from_static("upload exceeds max size"));
            return resp;
        }
    }
    if headers.get(header::AUTHORIZATION).is_none() {
        let mut resp = StatusCode::UNAUTHORIZED.into_response();
        resp.headers_mut().insert("x-reason", HeaderValue::from_static("missing Authorization header"));
        return resp;
    }
    StatusCode::OK.into_response()
}

pub async fn get_blob(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    headers: HeaderMap,
) -> Response {
    let sha = match storage::parse_sha_from_path(&path) {
        Some(s) => s,
        None => return error(StatusCode::NOT_FOUND, "not a sha256"),
    };
    let file_path = match state.storage.get_path(&sha).await {
        Some(p) => p,
        None => return error(StatusCode::NOT_FOUND, "blob not found"),
    };

    let mut file = match tokio::fs::File::open(&file_path).await {
        Ok(f) => f,
        Err(_) => return error(StatusCode::NOT_FOUND, "blob not found"),
    };
    let meta = match file.metadata().await {
        Ok(m) => m,
        Err(_) => return error(StatusCode::INTERNAL_SERVER_ERROR, "stat failed"),
    };
    let total = meta.len();

    let mime = sniff_mime(&file_path).await.unwrap_or_else(|| "application/octet-stream".to_string());

    let range_header = headers.get(header::RANGE).and_then(|v| v.to_str().ok());
    let range = match range_header {
        Some(raw) => match parse_range(raw, total) {
            ParsedRange::Valid(s, e) => Some((s, e)),
            ParsedRange::Unsupported => None,
            ParsedRange::Invalid => {
                let mut resp = StatusCode::RANGE_NOT_SATISFIABLE.into_response();
                let cr = format!("bytes */{}", total);
                if let Ok(v) = HeaderValue::from_str(&cr) {
                    resp.headers_mut().insert(header::CONTENT_RANGE, v);
                }
                return resp;
            }
        },
        None => None,
    };

    let (status, body, content_length, content_range) = match range {
        Some((start, end)) => {
            if file.seek(std::io::SeekFrom::Start(start)).await.is_err() {
                return error(StatusCode::INTERNAL_SERVER_ERROR, "seek failed");
            }
            let len = end - start + 1;
            let stream = ReaderStream::new(file.take(len));
            let body = Body::from_stream(stream);
            let cr = format!("bytes {}-{}/{}", start, end, total);
            (StatusCode::PARTIAL_CONTENT, body, len, Some(cr))
        }
        None => {
            let stream = ReaderStream::new(file);
            (StatusCode::OK, Body::from_stream(stream), total, None)
        }
    };

    let mut resp = (status, body).into_response();
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_str(&mime).unwrap());
    resp.headers_mut().insert(header::CONTENT_LENGTH, HeaderValue::from(content_length));
    resp.headers_mut().insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    if let Some(cr) = content_range {
        if let Ok(v) = HeaderValue::from_str(&cr) {
            resp.headers_mut().insert(header::CONTENT_RANGE, v);
        }
    }
    if let Ok(expires_at) = expires_at_header(&meta, state.cfg.ttl_seconds) {
        resp.headers_mut().insert("x-expires-at", expires_at);
    }
    resp
}

pub async fn head_blob(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    headers: HeaderMap,
) -> Response {
    let sha = match storage::parse_sha_from_path(&path) {
        Some(s) => s,
        None => return StatusCode::NOT_FOUND.into_response(),
    };
    let meta = match state.storage.stat(&sha).await {
        Ok(Some(m)) => m,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };

    let range_header = headers.get(header::RANGE).and_then(|v| v.to_str().ok());
    let (status, content_length, content_range) = match range_header {
        Some(raw) => match parse_range(raw, meta.size) {
            ParsedRange::Valid(s, e) => (
                StatusCode::PARTIAL_CONTENT,
                e - s + 1,
                Some(format!("bytes {}-{}/{}", s, e, meta.size)),
            ),
            ParsedRange::Unsupported => (StatusCode::OK, meta.size, None),
            ParsedRange::Invalid => {
                let mut resp = StatusCode::RANGE_NOT_SATISFIABLE.into_response();
                let cr = format!("bytes */{}", meta.size);
                if let Ok(v) = HeaderValue::from_str(&cr) {
                    resp.headers_mut().insert(header::CONTENT_RANGE, v);
                }
                return resp;
            }
        },
        None => (StatusCode::OK, meta.size, None),
    };

    let mut resp = status.into_response();
    resp.headers_mut().insert(header::CONTENT_LENGTH, HeaderValue::from(content_length));
    resp.headers_mut().insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    if let Some(cr) = content_range {
        if let Ok(v) = HeaderValue::from_str(&cr) {
            resp.headers_mut().insert(header::CONTENT_RANGE, v);
        }
    }
    resp
}

pub async fn delete_blob(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    headers: HeaderMap,
) -> Response {
    let sha = match storage::parse_sha_from_path(&path) {
        Some(s) => s,
        None => return error(StatusCode::NOT_FOUND, "not a sha256"),
    };
    let verified = match extract_auth(&headers, Action::Delete, state.cfg.max_auth_lifetime_seconds) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if !verified.hashes.iter().any(|h| h == &sha) {
        return error(StatusCode::FORBIDDEN, "auth event does not authorize this hash");
    }
    match state.storage.remove_owner(&verified.pubkey, &sha).await {
        Ok(true) => StatusCode::OK.into_response(),
        Ok(false) => error(StatusCode::NOT_FOUND, "you do not own this blob"),
        Err(e) => {
            tracing::error!("delete failed: {e:#}");
            error(StatusCode::INTERNAL_SERVER_ERROR, "storage error")
        }
    }
}

pub async fn list_owner(
    State(state): State<Arc<AppState>>,
    Path(pubkey): Path<String>,
    headers: HeaderMap,
) -> Response {
    if pubkey.len() != 64 || !pubkey.bytes().all(|b| b.is_ascii_hexdigit()) {
        return error(StatusCode::BAD_REQUEST, "invalid pubkey");
    }
    // BUD-02 list events are authenticated.
    let verified = match extract_auth(&headers, Action::List, state.cfg.max_auth_lifetime_seconds) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if verified.pubkey != pubkey.to_lowercase() {
        return error(StatusCode::FORBIDDEN, "auth pubkey does not match listed pubkey");
    }
    match state.storage.list_for_owner(&pubkey.to_lowercase()).await {
        Ok(metas) => {
            let descriptors: Vec<_> = metas
                .into_iter()
                .map(|m| BlobDescriptor::from_meta(&state.cfg.public_url, m))
                .collect();
            Json(descriptors).into_response()
        }
        Err(e) => {
            tracing::error!("list failed: {e:#}");
            error(StatusCode::INTERNAL_SERVER_ERROR, "storage error")
        }
    }
}

async fn sniff_mime(path: &std::path::Path) -> Option<String> {
    let mut buf = vec![0u8; 512];
    use tokio::io::AsyncReadExt;
    let mut f = tokio::fs::File::open(path).await.ok()?;
    let n = f.read(&mut buf).await.ok()?;
    buf.truncate(n);
    infer::get(&buf).map(|t| t.mime_type().to_string())
}

fn expires_at_header(meta: &std::fs::Metadata, ttl_seconds: u64) -> Result<HeaderValue, ()> {
    let mtime = meta.modified().map_err(|_| ())?;
    let secs = mtime.duration_since(UNIX_EPOCH).map_err(|_| ())?.as_secs();
    HeaderValue::from_str(&(secs + ttl_seconds).to_string()).map_err(|_| ())
}

#[derive(Debug, PartialEq, Eq)]
enum ParsedRange {
    Valid(u64, u64),
    Unsupported,
    Invalid,
}

fn parse_range(raw: &str, total: u64) -> ParsedRange {
    let Some(spec) = raw.strip_prefix("bytes=") else {
        return ParsedRange::Invalid;
    };
    if spec.contains(',') {
        return ParsedRange::Unsupported;
    }
    let Some((start_s, end_s)) = spec.split_once('-') else {
        return ParsedRange::Invalid;
    };
    let start_s = start_s.trim();
    let end_s = end_s.trim();

    if start_s.is_empty() {
        let Ok(n) = end_s.parse::<u64>() else {
            return ParsedRange::Invalid;
        };
        if n == 0 || total == 0 {
            return ParsedRange::Invalid;
        }
        let n = n.min(total);
        ParsedRange::Valid(total - n, total - 1)
    } else {
        let Ok(start) = start_s.parse::<u64>() else {
            return ParsedRange::Invalid;
        };
        if total == 0 || start >= total {
            return ParsedRange::Invalid;
        }
        let end = if end_s.is_empty() {
            total - 1
        } else {
            let Ok(e) = end_s.parse::<u64>() else {
                return ParsedRange::Invalid;
            };
            e.min(total - 1)
        };
        if start > end {
            return ParsedRange::Invalid;
        }
        ParsedRange::Valid(start, end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_simple() {
        assert_eq!(parse_range("bytes=0-99", 1000), ParsedRange::Valid(0, 99));
        assert_eq!(parse_range("bytes=100-199", 1000), ParsedRange::Valid(100, 199));
    }

    #[test]
    fn range_open_ended() {
        assert_eq!(parse_range("bytes=500-", 1000), ParsedRange::Valid(500, 999));
    }

    #[test]
    fn range_suffix() {
        assert_eq!(parse_range("bytes=-200", 1000), ParsedRange::Valid(800, 999));
        // suffix larger than file clamps to the whole file.
        assert_eq!(parse_range("bytes=-5000", 1000), ParsedRange::Valid(0, 999));
    }

    #[test]
    fn range_end_clamps_to_file_size() {
        assert_eq!(parse_range("bytes=0-9999", 1000), ParsedRange::Valid(0, 999));
    }

    #[test]
    fn range_invalid_start_past_end_of_file() {
        assert_eq!(parse_range("bytes=1000-", 1000), ParsedRange::Invalid);
        assert_eq!(parse_range("bytes=2000-3000", 1000), ParsedRange::Invalid);
    }

    #[test]
    fn range_invalid_start_greater_than_end() {
        assert_eq!(parse_range("bytes=500-100", 1000), ParsedRange::Invalid);
    }

    #[test]
    fn range_invalid_suffix_zero_or_empty_file() {
        assert_eq!(parse_range("bytes=-0", 1000), ParsedRange::Invalid);
        assert_eq!(parse_range("bytes=-100", 0), ParsedRange::Invalid);
        assert_eq!(parse_range("bytes=0-", 0), ParsedRange::Invalid);
    }

    #[test]
    fn range_invalid_syntax() {
        assert_eq!(parse_range("items=0-99", 1000), ParsedRange::Invalid);
        assert_eq!(parse_range("bytes=abc-def", 1000), ParsedRange::Invalid);
        assert_eq!(parse_range("bytes=0", 1000), ParsedRange::Invalid);
    }

    #[test]
    fn range_multi_unsupported() {
        // Multi-range gets treated as "ignore the header and return full body".
        assert_eq!(parse_range("bytes=0-99,200-299", 1000), ParsedRange::Unsupported);
    }
}

