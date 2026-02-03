use axum::{
    body::Body,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::{delete, get, post},
    Json, Router,
};
use bytes::Bytes;
use dos_core::{AttribReq, ListResp, MkdirReq, OkResp, RenameReq, StatResp, StatFsResp};
use std::collections::HashMap;

use crate::{state::AppState, storage};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/fs/list", get(list))
        .route("/fs/stat", get(stat))
        .route("/fs/read", get(read))
        .route("/fs/mkdir", post(mkdir))
        .route("/fs/rename", post(rename))
        .route("/fs/attrib", post(attrib))
        .route("/fs/statfs", get(statfs))
        .route("/fs/delete", delete(del))
        .with_state(state)
}

fn require_auth(state: &AppState, headers: &HeaderMap) -> Result<(), (StatusCode, String)> {
    let Some(auth) = headers.get(axum::http::header::AUTHORIZATION) else {
        return Err((StatusCode::UNAUTHORIZED, "missing auth".into()));
    };
    let auth = auth.to_str().unwrap_or("");
    let token = auth.strip_prefix("Bearer ").unwrap_or("");
    if token.is_empty() {
        return Err((StatusCode::UNAUTHORIZED, "bad auth".into()));
    }
    let ok = state.tokens.read().unwrap().contains_key(token);
    if !ok {
        return Err((StatusCode::UNAUTHORIZED, "unknown token".into()));
    }
    Ok(())
}

async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Json<ListResp>, (StatusCode, String)> {
    require_auth(&state, &headers)?;
    let path = q.get("path").map(|s| s.as_str()).unwrap_or("/");
    let entries = storage::list_dir(&state.root, path)
        .await
        .map_err(map_err)?;
    Ok(Json(ListResp {
        path: dos_core::normalize_path(path).map_err(map_err)?,
        entries,
    }))
}

async fn stat(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Json<StatResp>, (StatusCode, String)> {
    require_auth(&state, &headers)?;
    let path = q.get("path").ok_or((StatusCode::BAD_REQUEST, "missing path".into()))?;
    let st = storage::stat_path(&state.root, path).await.map_err(map_err)?;
    Ok(Json(st))
}

async fn mkdir(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<MkdirReq>,
) -> Result<Json<OkResp>, (StatusCode, String)> {
    require_auth(&state, &headers)?;
    storage::mkdir(&state.root, &req.path).await.map_err(map_err)?;
    Ok(Json(OkResp { ok: true }))
}

async fn rename(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RenameReq>,
) -> Result<Json<OkResp>, (StatusCode, String)> {
    require_auth(&state, &headers)?;
    storage::rename(&state.root, &req.from, &req.to, req.replace).await.map_err(map_err)?;
    Ok(Json(OkResp { ok: true }))
}

async fn del(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Json<OkResp>, (StatusCode, String)> {
    require_auth(&state, &headers)?;
    let path = q.get("path").ok_or((StatusCode::BAD_REQUEST, "missing path".into()))?;
    let recursive = q.get("recursive").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false);
    storage::delete(&state.root, path, recursive).await.map_err(map_err)?;
    Ok(Json(OkResp { ok: true }))
}

async fn attrib(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(_req): Json<AttribReq>,
) -> Result<Json<OkResp>, (StatusCode, String)> {
    require_auth(&state, &headers)?;
    // MVP: accept but do nothing (you'll store metadata later)
    // Still useful for CLI demos.
    // In a later step: store in sqlite or sidecar xattr.
    // (Keeping this endpoint to lock API shape early.)
    // require_auth already implied.
    // We do it anyway:
    // NOTE: needs state; just validate auth in a follow-up.
    Ok(Json(OkResp { ok: true }))
}

async fn statfs(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<StatFsResp>, (StatusCode, String)> {
    require_auth(&state, &headers)?;
    let cap = std::env::var("DOS_CAPACITY_BYTES")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(1_073_741_824); // 1GB default
    let s = storage::statfs(&state.root, cap).await.map_err(map_err)?;
    Ok(Json(s))
}

async fn read(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Response, (StatusCode, String)> {
    require_auth(&state, &headers)?;
    let path = q.get("path").ok_or((StatusCode::BAD_REQUEST, "missing path".into()))?;
    let fs_path = dos_core::path_to_fs(&state.root, path).map_err(map_err)?;

    let meta = tokio::fs::metadata(&fs_path).await.map_err(|e| map_err(dos_core::DosError::Io(e)))?;
    if !meta.is_file() {
        return Err((StatusCode::BAD_REQUEST, "not a file".into()));
    }
    let size = meta.len();
    if size == 0 {
        let mut resp = Response::new(Body::empty());
        let h = resp.headers_mut();
        h.insert(axum::http::header::ACCEPT_RANGES, "bytes".parse().unwrap());
        return Ok(resp);
    }

    // Parse Range header: bytes=start-end
    let mut start: u64 = 0;
    let mut end: u64 = size.saturating_sub(1);

    if let Some(range) = headers.get(axum::http::header::RANGE) {
        if let Ok(r) = range.to_str() {
            if let Some(spec) = r.strip_prefix("bytes=") {
                let parts: Vec<&str> = spec.split('-').collect();
                if parts.len() == 2 {
                    if !parts[0].is_empty() {
                        start = parts[0].parse().unwrap_or(0);
                    }
                    if !parts[1].is_empty() {
                        end = parts[1].parse().unwrap_or(end);
                    }
                }
            }
        }
    }

    if start >= size {
        return Err((StatusCode::RANGE_NOT_SATISFIABLE, "range start beyond EOF".into()));
    }
    end = end.min(size.saturating_sub(1));
    let len = (end - start) + 1;

    let mut file = tokio::fs::File::open(&fs_path).await.map_err(|e| map_err(dos_core::DosError::Io(e)))?;
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    file.seek(std::io::SeekFrom::Start(start)).await.map_err(|e| map_err(dos_core::DosError::Io(e)))?;

    let mut buf = vec![0u8; len as usize];
    file.read_exact(&mut buf).await.map_err(|e| map_err(dos_core::DosError::Io(e)))?;

    let mut resp = Response::new(Body::from(Bytes::from(buf)));
    *resp.status_mut() = if headers.contains_key(axum::http::header::RANGE) { StatusCode::PARTIAL_CONTENT } else { StatusCode::OK };

    let is_partial = resp.status() == StatusCode::PARTIAL_CONTENT;
    let h = resp.headers_mut();
    h.insert(axum::http::header::ACCEPT_RANGES, "bytes".parse().unwrap());
    if is_partial {
        h.insert(
            axum::http::header::CONTENT_RANGE,
            format!("bytes {}-{}/{}", start, end, size).parse().unwrap(),
        );
    }
    Ok(resp)
}

fn map_err(e: dos_core::DosError) -> (StatusCode, String) {
    use dos_core::DosError::*;
    match e {
        NotFound => (StatusCode::NOT_FOUND, "not found".into()),
        BadPath(s) => (StatusCode::BAD_REQUEST, format!("bad path: {s}")),
        AlreadyExists => (StatusCode::CONFLICT, "already exists".into()),
        PermissionDenied => (StatusCode::FORBIDDEN, "permission denied".into()),
        Invalid(s) => (StatusCode::BAD_REQUEST, s),
        Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".into()),
        Io(err) => (StatusCode::INTERNAL_SERVER_ERROR, format!("io: {err}")),
        Internal(s) => (StatusCode::INTERNAL_SERVER_ERROR, s),
    }
}
