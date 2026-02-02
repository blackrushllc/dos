use axum::{
    body::Bytes,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    routing::{post, put},
    Json, Router,
};
use dos_core::{OkResp, UploadAbortReq, UploadCommitReq, UploadStartReq, UploadStartResp};
use std::collections::HashMap;
use uuid::Uuid;

use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/fs/upload/start", post(start))
        .route("/fs/upload/chunk", put(chunk))
        .route("/fs/upload/commit", post(commit))
        .route("/fs/upload/abort", post(abort))
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

async fn start(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<UploadStartReq>,
) -> Result<Json<UploadStartResp>, (StatusCode, String)> {
    require_auth(&state, &headers)?;

    let upload_id = format!("up_{}", Uuid::new_v4());
    let path = dos_core::normalize_path(&req.path).map_err(map_err)?;

    let dir = state.upload_root.join(&upload_id);
    tokio::fs::create_dir_all(&dir).await.map_err(|e| map_err(dos_core::DosError::Io(e)))?;

    // store intended destination path in a small file
    tokio::fs::write(dir.join("dest.txt"), path.as_bytes())
        .await
        .map_err(|e| map_err(dos_core::DosError::Io(e)))?;

    // create empty temp data file
    tokio::fs::write(dir.join("data.bin"), &[])
        .await
        .map_err(|e| map_err(dos_core::DosError::Io(e)))?;

    Ok(Json(UploadStartResp {
        upload_id,
        chunk_size: 4 * 1024 * 1024,
        current_size: 0,
    }))
}

async fn chunk(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    body: Bytes,
) -> Result<Json<OkResp>, (StatusCode, String)> {
    require_auth(&state, &headers)?;

    let upload_id = q.get("upload_id").ok_or((StatusCode::BAD_REQUEST, "missing upload_id".into()))?;
    let offset = q.get("offset").and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);

    let dir = state.upload_root.join(upload_id);
    let data_path = dir.join("data.bin");

    // MVP: support random write by seeking into a temp file
    use tokio::io::{AsyncSeekExt, AsyncWriteExt};
    let mut f = tokio::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&data_path)
        .await
        .map_err(|e| map_err(dos_core::DosError::Io(e)))?;

    f.seek(std::io::SeekFrom::Start(offset))
        .await
        .map_err(|e| map_err(dos_core::DosError::Io(e)))?;
    f.write_all(&body)
        .await
        .map_err(|e| map_err(dos_core::DosError::Io(e)))?;

    Ok(Json(OkResp { ok: true }))
}

async fn commit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<UploadCommitReq>,
) -> Result<Json<OkResp>, (StatusCode, String)> {
    require_auth(&state, &headers)?;

    let dir = state.upload_root.join(&req.upload_id);
    let dest = tokio::fs::read_to_string(dir.join("dest.txt"))
        .await
        .map_err(|e| map_err(dos_core::DosError::Io(e)))?;
    let dest = dest.trim().to_string();

    let data_path = dir.join("data.bin");
    let fs_dest = dos_core::path_to_fs(&state.root, &dest).map_err(map_err)?;

    // Ensure parent exists
    if let Some(parent) = fs_dest.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|e| map_err(dos_core::DosError::Io(e)))?;
    }

    // Atomic-ish replace: write to .tmp then rename
    let tmp = fs_dest.with_extension("dos_tmp");
    tokio::fs::copy(&data_path, &tmp).await.map_err(|e| map_err(dos_core::DosError::Io(e)))?;
    // remove existing then rename
    if let Ok(meta) = tokio::fs::metadata(&fs_dest).await {
        if meta.is_file() {
            let _ = tokio::fs::remove_file(&fs_dest).await;
        }
    }
    tokio::fs::rename(&tmp, &fs_dest).await.map_err(|e| map_err(dos_core::DosError::Io(e)))?;

    // Cleanup
    let _ = tokio::fs::remove_dir_all(&dir).await;

    Ok(Json(OkResp { ok: true }))
}

async fn abort(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<UploadAbortReq>,
) -> Result<Json<OkResp>, (StatusCode, String)> {
    require_auth(&state, &headers)?;
    let dir = state.upload_root.join(&req.upload_id);
    let _ = tokio::fs::remove_dir_all(dir).await;
    Ok(Json(OkResp { ok: true }))
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
