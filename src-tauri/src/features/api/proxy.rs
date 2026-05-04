//! Strangler proxy: forward any request that did not match a native handler
//! to the legacy Node helper running on `state.proxy_port`.
//!
//! Removed in the final phase of the migration once every endpoint is native.

use axum::body::{Body, Bytes};
use axum::extract::{OriginalUri, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use futures_util::TryStreamExt;
use http_body_util::BodyExt;

use super::state::AppState;

/// Hop-by-hop headers we never forward in either direction (RFC 7230 §6.1).
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
];

fn is_hop_by_hop(name: &HeaderName) -> bool {
    let n = name.as_str().to_ascii_lowercase();
    HOP_BY_HOP.contains(&n.as_str())
}

fn copy_request_headers(src: &HeaderMap) -> reqwest::header::HeaderMap {
    let mut out = reqwest::header::HeaderMap::with_capacity(src.len());
    for (k, v) in src.iter() {
        if is_hop_by_hop(k) {
            continue;
        }
        if let (Ok(name), Ok(val)) = (
            reqwest::header::HeaderName::from_bytes(k.as_str().as_bytes()),
            reqwest::header::HeaderValue::from_bytes(v.as_bytes()),
        ) {
            out.append(name, val);
        }
    }
    out
}

fn copy_response_headers(src: &reqwest::header::HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::with_capacity(src.len());
    for (k, v) in src.iter() {
        let lower = k.as_str().to_ascii_lowercase();
        if HOP_BY_HOP.contains(&lower.as_str()) {
            continue;
        }
        if let (Ok(name), Ok(val)) = (
            HeaderName::from_bytes(k.as_str().as_bytes()),
            HeaderValue::from_bytes(v.as_bytes()),
        ) {
            out.append(name, val);
        }
    }
    out
}

/// Return 502 with a JSON body explaining the upstream is unreachable.
fn bad_gateway(detail: String) -> Response {
    let body = serde_json::json!({
        "error": "ClamAV Control proxy: upstream Node helper unreachable",
        "detail": detail,
    })
    .to_string();
    let mut res = Response::new(Body::from(body));
    *res.status_mut() = StatusCode::BAD_GATEWAY;
    res.headers_mut()
        .insert("content-type", HeaderValue::from_static("application/json"));
    res
}

pub async fn forward(
    State(state): State<AppState>,
    // `OriginalUri` is the URI as it was *before* `Router::nest("/api", ...)`
    // stripped the prefix, so the proxy forwards `/api/health` to Node and
    // not just `/health` (which would fall through to Express's SPA catchall
    // and return index.html).
    OriginalUri(original_uri): OriginalUri,
    req: Request,
) -> Response {
    let Some(port) = state.proxy_port else {
        return bad_gateway("no upstream configured".into());
    };

    let (parts, body) = req.into_parts();

    // Slurp the body. ClamAV Control's payloads are tiny (config edits, cron
    // entries), so this keeps the proxy simple. Streaming bodies are not used
    // in any current endpoint.
    let bytes: Bytes = match body.collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => return bad_gateway(format!("read request body: {e}")),
    };

    let path_and_query = original_uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or_else(|| original_uri.path());
    let upstream = format!("http://127.0.0.1:{port}{path_and_query}");

    let method = match reqwest::Method::from_bytes(parts.method.as_str().as_bytes()) {
        Ok(m) => m,
        Err(e) => return bad_gateway(format!("invalid method: {e}")),
    };

    let res = state
        .http
        .request(method, &upstream)
        .headers(copy_request_headers(&parts.headers))
        .body(bytes)
        .send()
        .await;

    let upstream_res = match res {
        Ok(r) => r,
        Err(e) => return bad_gateway(format!("connect {upstream}: {e}")),
    };

    let status_code = StatusCode::from_u16(upstream_res.status().as_u16())
        .unwrap_or(StatusCode::BAD_GATEWAY);
    let headers = copy_response_headers(upstream_res.headers());
    let stream = upstream_res
        .bytes_stream()
        .map_err(std::io::Error::other);
    let body = Body::from_stream(stream);

    let mut out = Response::new(body);
    *out.status_mut() = status_code;
    *out.headers_mut() = headers;
    out
}
