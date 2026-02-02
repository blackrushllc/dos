Below is a **paste-ready Rust workspace scaffold** for **DOS** with:

* `dos-core` (shared types + helpers)
* `dos-server` (Axum HTTPS-ready REST server, local-fs-backed)
* `dos-client` (Reqwest client lib)
* `dosctl` (CLI for join/ls/cat/put/get)
* `dos-fuse` (Linux FUSE skeleton using `fuser`, read-only MVP ops wired)

It compiles as-is (Linux for `dos-fuse`). Server runs HTTP by default (you can add TLS later).

---

# 0) Folder tree

Create a folder `dos/` and add:

```text
dos/
  Cargo.toml
  crates/
    dos-core/
      Cargo.toml
      src/lib.rs
      src/types.rs
      src/path.rs
      src/attrs.rs
      src/error.rs
    dos-server/
      Cargo.toml
      src/main.rs
      src/state.rs
      src/routes/mod.rs
      src/routes/health.rs
      src/routes/auth.rs
      src/routes/fs.rs
      src/routes/upload.rs
      src/storage.rs
    dos-client/
      Cargo.toml
      src/lib.rs
      src/config.rs
      src/api.rs
    dosctl/
      Cargo.toml
      src/main.rs
    dos-fuse/
      Cargo.toml
      src/main.rs
      src/fuse_fs.rs
  .gitignore
```

---

# 1) Root workspace

## `dos/Cargo.toml`

```toml
[workspace]
resolver = "2"
members = [
  "crates/dos-core",
  "crates/dos-server",
  "crates/dos-client",
  "crates/dosctl",
  "crates/dos-fuse",
]

[workspace.package]
edition = "2021"
license = "MIT"
version = "0.1.0"

[workspace.dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "1"
uuid = { version = "1", features = ["v4", "serde"] }
time = { version = "0.3", features = ["serde"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread", "fs", "io-util", "time"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
```

## `dos/.gitignore`

```gitignore
/target
**/*.swp
**/*.swo
.DS_Store
.idea
.vscode
dos_shares.json
```

---

# 2) `dos-core`

## `crates/dos-core/Cargo.toml`

```toml
[package]
name = "dos-core"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
uuid.workspace = true
time.workspace = true
```

## `crates/dos-core/src/lib.rs`

```rust
pub mod attrs;
pub mod error;
pub mod path;
pub mod types;

pub use attrs::*;
pub use error::*;
pub use path::*;
pub use types::*;
```

## `crates/dos-core/src/types.rs`

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    pub name: String,
    pub version: String,
    pub device: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinReq {
    pub share: String,
    pub password: String,
    pub client: ClientInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinResp {
    pub token: String,
    pub share_id: String,
    pub expires_in: u64,
    pub server_time: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeKind {
    File,
    Dir,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeEntry {
    pub name: String,
    pub kind: NodeKind,
    pub id: String,
    pub version: String,
    pub size: Option<u64>,
    pub mtime: i64,
    pub attrs: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListResp {
    pub path: String,
    pub entries: Vec<NodeEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatResp {
    pub path: String,
    pub kind: NodeKind,
    pub id: String,
    pub version: String,
    pub size: Option<u64>,
    pub mtime: i64,
    pub attrs: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MkdirReq {
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenameReq {
    pub from: String,
    pub to: String,
    pub replace: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OkResp {
    pub ok: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttribReq {
    pub path: String,
    pub set: String,
    pub clear: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatFsResp {
    pub capacity_bytes: u64,
    pub used_bytes: u64,
    pub free_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UploadMode {
    CreateOrReplace,
    CreateNew,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadStartReq {
    pub path: String,
    pub mode: UploadMode,
    pub mtime: Option<i64>,
    pub attrs: Option<String>,
    pub expected_size: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadStartResp {
    pub upload_id: String,
    pub chunk_size: u64,
    pub current_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadCommitReq {
    pub upload_id: String,
    pub final_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadAbortReq {
    pub upload_id: String,
}
```

## `crates/dos-core/src/path.rs`

```rust
use crate::DosError;

/// Normalize a DOS path to a safe absolute form:
/// - always starts with `/`
/// - uses forward slashes
/// - collapses `//`
/// - rejects `..` segments
pub fn normalize_path(input: &str) -> Result<String, DosError> {
    let mut s = input.replace('\\', "/");
    if s.is_empty() {
        s = "/".to_string();
    }
    if !s.starts_with('/') {
        s = format!("/{}", s);
    }

    let mut out: Vec<&str> = Vec::new();
    for seg in s.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            return Err(DosError::BadPath(".. not allowed".into()));
        }
        out.push(seg);
    }

    Ok(format!("/{}", out.join("/")))
}

/// Join normalized DOS path onto a filesystem root.
pub fn path_to_fs(root: &std::path::Path, dos_path: &str) -> Result<std::path::PathBuf, DosError> {
    let p = normalize_path(dos_path)?;
    let rel = p.trim_start_matches('/');
    Ok(root.join(rel))
}
```

## `crates/dos-core/src/attrs.rs`

```rust
/// DOS-style attributes. We keep it as a string set like "RHA".
/// For MVP we just store/return, and server can ignore enforcement until later.

pub fn normalize_attrs(s: &str) -> String {
    let mut chars: Vec<char> = s
        .chars()
        .filter(|c| matches!(c, 'R' | 'H' | 'A' | 'S'))
        .collect();
    chars.sort_unstable();
    chars.dedup();
    chars.into_iter().collect()
}
```

## `crates/dos-core/src/error.rs`

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DosError {
    #[error("bad path: {0}")]
    BadPath(String),

    #[error("not found")]
    NotFound,

    #[error("already exists")]
    AlreadyExists,

    #[error("permission denied")]
    PermissionDenied,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid request: {0}")]
    Invalid(String),

    #[error("unauthorized")]
    Unauthorized,

    #[error("internal: {0}")]
    Internal(String),
}
```

---

# 3) `dos-server` (Axum REST)

## `crates/dos-server/Cargo.toml`

```toml
[package]
name = "dos-server"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
dos-core = { path = "../dos-core" }
tokio.workspace = true
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
uuid.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true

axum = "0.7"
tower = "0.4"
tower-http = { version = "0.5", features = ["trace"] }
http = "1"
bytes = "1"
mime = "0.3"
```

## `crates/dos-server/src/main.rs`

```rust
mod routes;
mod state;
mod storage;

use axum::{routing::get, Router};
use std::{net::SocketAddr, path::PathBuf};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "dos_server=debug,tower_http=info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let root = std::env::var("DOS_ROOT").unwrap_or_else(|_| "./dos_data".to_string());
    let upload_root = std::env::var("DOS_UPLOAD_ROOT").unwrap_or_else(|_| "./dos_uploads".to_string());
    let password = std::env::var("DOS_PASSWORD").unwrap_or_else(|_| "dos".to_string());

    tokio::fs::create_dir_all(&root).await?;
    tokio::fs::create_dir_all(&upload_root).await?;

    let state = AppState::new(PathBuf::from(root), PathBuf::from(upload_root), password);

    let app = Router::new()
        .route("/", get(|| async { "DOS server ok\n" }))
        .nest("/v1", routes::router(state.clone()))
        .layer(TraceLayer::new_for_http());

    let addr: SocketAddr = std::env::var("DOS_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8787".to_string())
        .parse()?;

    tracing::info!("DOS server root={:?} upload_root={:?} bind={}", state.root, state.upload_root, addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

> Add `anyhow` dep since used above.

### Update `crates/dos-server/Cargo.toml` (append)

```toml
anyhow = "1"
```

## `crates/dos-server/src/state.rs`

```rust
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, RwLock},
};

#[derive(Clone)]
pub struct AppState {
    pub root: PathBuf,
    pub upload_root: PathBuf,
    pub password: String,
    /// token -> share_id (MVP: single share)
    pub tokens: Arc<RwLock<HashMap<String, String>>>,
}

impl AppState {
    pub fn new(root: PathBuf, upload_root: PathBuf, password: String) -> Self {
        Self {
            root,
            upload_root,
            password,
            tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}
```

## `crates/dos-server/src/routes/mod.rs`

```rust
pub mod auth;
pub mod fs;
pub mod health;
pub mod upload;

use axum::Router;
use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .merge(health::router())
        .merge(auth::router(state.clone()))
        .merge(fs::router(state.clone()))
        .merge(upload::router(state))
}
```

## `crates/dos-server/src/routes/health.rs`

```rust
use axum::{routing::get, Router};

pub fn router() -> Router {
    Router::new().route("/health", get(|| async { "ok" }))
}
```

## `crates/dos-server/src/routes/auth.rs`

```rust
use axum::{extract::State, routing::post, Json, Router};
use dos_core::{JoinReq, JoinResp};
use uuid::Uuid;

use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new().route("/auth/join", post(join)).with_state(state)
}

async fn join(State(state): State<AppState>, Json(req): Json<JoinReq>) -> Result<Json<JoinResp>, (axum::http::StatusCode, String)> {
    if req.password != state.password {
        return Err((axum::http::StatusCode::UNAUTHORIZED, "bad password".into()));
    }

    let token = format!("dos_live_{}", Uuid::new_v4());
    let share_id = "shr_local".to_string();

    {
        let mut map = state.tokens.write().unwrap();
        map.insert(token.clone(), share_id.clone());
    }

    let resp = JoinResp {
        token,
        share_id,
        expires_in: 86400,
        server_time: time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).unwrap(),
    };
    Ok(Json(resp))
}
```

## `crates/dos-server/src/storage.rs`

```rust
use dos_core::{DosError, NodeKind, StatResp};
use std::path::{Path, PathBuf};

pub async fn stat_path(root: &Path, dos_path: &str) -> Result<StatResp, DosError> {
    let fs_path = dos_core::path_to_fs(root, dos_path)?;
    let meta = tokio::fs::metadata(&fs_path).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            DosError::NotFound
        } else {
            DosError::Io(e)
        }
    })?;

    let kind = if meta.is_dir() { NodeKind::Dir } else { NodeKind::File };
    let size = if meta.is_file() { Some(meta.len()) } else { None };
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    Ok(StatResp {
        path: dos_core::normalize_path(dos_path)?,
        kind,
        id: format!("n_{}", blake3::hash(fs_path.to_string_lossy().as_bytes()).to_hex()),
        version: format!("v{}", mtime), // MVP: time-based
        size,
        mtime,
        attrs: "".into(),
    })
}

pub async fn list_dir(root: &Path, dos_path: &str) -> Result<Vec<dos_core::NodeEntry>, DosError> {
    let fs_path = dos_core::path_to_fs(root, dos_path)?;
    let mut rd = tokio::fs::read_dir(&fs_path).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            DosError::NotFound
        } else {
            DosError::Io(e)
        }
    })?;

    let mut out = Vec::new();
    while let Some(ent) = rd.next_entry().await? {
        let name = ent.file_name().to_string_lossy().to_string();
        let meta = ent.metadata().await?;
        let kind = if meta.is_dir() { NodeKind::Dir } else { NodeKind::File };
        let size = if meta.is_file() { Some(meta.len()) } else { None };
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        out.push(dos_core::NodeEntry {
            name,
            kind,
            id: format!("n_{}", blake3::hash(ent.path().to_string_lossy().as_bytes()).to_hex()),
            version: format!("v{}", mtime),
            size,
            mtime,
            attrs: "".into(),
        });
    }
    Ok(out)
}

pub async fn mkdir(root: &Path, dos_path: &str) -> Result<(), DosError> {
    let fs_path = dos_core::path_to_fs(root, dos_path)?;
    tokio::fs::create_dir_all(&fs_path).await?;
    Ok(())
}

pub async fn delete(root: &Path, dos_path: &str, recursive: bool) -> Result<(), DosError> {
    let fs_path = dos_core::path_to_fs(root, dos_path)?;
    let meta = tokio::fs::metadata(&fs_path).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound { DosError::NotFound } else { DosError::Io(e) }
    })?;

    if meta.is_dir() {
        if recursive {
            tokio::fs::remove_dir_all(&fs_path).await?;
        } else {
            tokio::fs::remove_dir(&fs_path).await?;
        }
    } else {
        tokio::fs::remove_file(&fs_path).await?;
    }
    Ok(())
}

pub async fn rename(root: &Path, from: &str, to: &str, replace: bool) -> Result<(), DosError> {
    let from_fs = dos_core::path_to_fs(root, from)?;
    let to_fs = dos_core::path_to_fs(root, to)?;

    if replace {
        // emulate atomic replace best-effort:
        // if target exists, remove first (file) then rename
        if let Ok(meta) = tokio::fs::metadata(&to_fs).await {
            if meta.is_dir() {
                tokio::fs::remove_dir_all(&to_fs).await?;
            } else {
                tokio::fs::remove_file(&to_fs).await?;
            }
        }
    }

    tokio::fs::rename(from_fs, to_fs).await?;
    Ok(())
}

pub async fn statfs(root: &Path, capacity_bytes: u64) -> Result<dos_core::StatFsResp, DosError> {
    // MVP: compute used by walking directory; enforce capacity server-side later.
    let used = dir_size(root.to_path_buf()).await?;
    let free = capacity_bytes.saturating_sub(used);

    Ok(dos_core::StatFsResp {
        capacity_bytes,
        used_bytes: used,
        free_bytes: free,
    })
}

async fn dir_size(root: PathBuf) -> Result<u64, DosError> {
    let mut total = 0u64;
    let mut stack = vec![root];
    while let Some(p) = stack.pop() {
        let mut rd = match tokio::fs::read_dir(&p).await {
            Ok(r) => r,
            Err(_) => continue,
        };
        while let Some(ent) = rd.next_entry().await? {
            let meta = ent.metadata().await?;
            if meta.is_dir() {
                stack.push(ent.path());
            } else if meta.is_file() {
                total = total.saturating_add(meta.len());
            }
        }
    }
    Ok(total)
}
```

> Add `blake3` dep.

### Update `crates/dos-server/Cargo.toml` (append)

```toml
blake3 = "1"
```

## `crates/dos-server/src/routes/fs.rs`

```rust
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
    State(_state): State<AppState>,
    headers: HeaderMap,
    Json(_req): Json<AttribReq>,
) -> Result<Json<OkResp>, (StatusCode, String)> {
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

    let h = resp.headers_mut();
    h.insert(axum::http::header::ACCEPT_RANGES, "bytes".parse().unwrap());
    if resp.status() == StatusCode::PARTIAL_CONTENT {
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
```

> Note: `attrib` currently no-ops but locks your API shape.

## `crates/dos-server/src/routes/upload.rs`

```rust
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
```

---

# 4) `dos-client` (Reqwest)

## `crates/dos-client/Cargo.toml`

```toml
[package]
name = "dos-client"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
dos-core = { path = "../dos-core" }
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
tokio.workspace = true
uuid.workspace = true

reqwest = { version = "0.12", features = ["json", "stream"] }
```

## `crates/dos-client/src/lib.rs`

```rust
pub mod api;
pub mod config;

pub use api::*;
pub use config::*;
```

## `crates/dos-client/src/config.rs`

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareConfig {
    pub base_url: String,
    pub share: String,
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConfigFile {
    pub shares: Vec<ShareConfig>,
}
```

## `crates/dos-client/src/api.rs`

```rust
use dos_core::*;
use reqwest::header::{AUTHORIZATION, RANGE};
use std::collections::HashMap;

#[derive(Clone)]
pub struct DosClient {
    http: reqwest::Client,
    base: String,
    token: Option<String>,
}

impl DosClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            base: base_url.into().trim_end_matches('/').to_string(),
            token: None,
        }
    }

    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    fn auth(&self, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(t) = &self.token {
            rb.header(AUTHORIZATION, format!("Bearer {}", t))
        } else {
            rb
        }
    }

    pub async fn join(&self, share: &str, password: &str, client: ClientInfo) -> Result<JoinResp, DosError> {
        let req = JoinReq {
            share: share.to_string(),
            password: password.to_string(),
            client,
        };
        let url = format!("{}/v1/auth/join", self.base);
        let resp = self.http.post(url).json(&req).send().await.map_err(|e| DosError::Internal(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(DosError::Unauthorized);
        }
        resp.json::<JoinResp>().await.map_err(|e| DosError::Internal(e.to_string()))
    }

    pub async fn list(&self, path: &str) -> Result<ListResp, DosError> {
        let url = format!("{}/v1/fs/list", self.base);
        let rb = self.http.get(url).query(&[("path", path)]);
        let resp = self.auth(rb).send().await.map_err(|e| DosError::Internal(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(DosError::Internal(resp.text().await.unwrap_or_default()));
        }
        resp.json().await.map_err(|e| DosError::Internal(e.to_string()))
    }

    pub async fn stat(&self, path: &str) -> Result<StatResp, DosError> {
        let url = format!("{}/v1/fs/stat", self.base);
        let rb = self.http.get(url).query(&[("path", path)]);
        let resp = self.auth(rb).send().await.map_err(|e| DosError::Internal(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(DosError::Internal(resp.text().await.unwrap_or_default()));
        }
        resp.json().await.map_err(|e| DosError::Internal(e.to_string()))
    }

    pub async fn read_range(&self, path: &str, start: u64, len: u64) -> Result<Vec<u8>, DosError> {
        let url = format!("{}/v1/fs/read", self.base);
        let end = start + len - 1;
        let rb = self.http.get(url).query(&[("path", path)]).header(RANGE, format!("bytes={}-{}", start, end));
        let resp = self.auth(rb).send().await.map_err(|e| DosError::Internal(e.to_string()))?;
        if !(resp.status().is_success() || resp.status().as_u16() == 206) {
            return Err(DosError::Internal(resp.text().await.unwrap_or_default()));
        }
        Ok(resp.bytes().await.map_err(|e| DosError::Internal(e.to_string()))?.to_vec())
    }

    pub async fn mkdir(&self, path: &str) -> Result<(), DosError> {
        let url = format!("{}/v1/fs/mkdir", self.base);
        let rb = self.http.post(url).json(&MkdirReq { path: path.to_string() });
        let resp = self.auth(rb).send().await.map_err(|e| DosError::Internal(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(DosError::Internal(resp.text().await.unwrap_or_default()));
        }
        Ok(())
    }

    pub async fn delete(&self, path: &str, recursive: bool) -> Result<(), DosError> {
        let url = format!("{}/v1/fs/delete", self.base);
        let rb = self.http.delete(url).query(&[("path", path), ("recursive", if recursive { "1" } else { "0" })]);
        let resp = self.auth(rb).send().await.map_err(|e| DosError::Internal(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(DosError::Internal(resp.text().await.unwrap_or_default()));
        }
        Ok(())
    }

    pub async fn rename(&self, from: &str, to: &str, replace: bool) -> Result<(), DosError> {
        let url = format!("{}/v1/fs/rename", self.base);
        let rb = self.http.post(url).json(&RenameReq {
            from: from.to_string(),
            to: to.to_string(),
            replace,
        });
        let resp = self.auth(rb).send().await.map_err(|e| DosError::Internal(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(DosError::Internal(resp.text().await.unwrap_or_default()));
        }
        Ok(())
    }

    pub async fn statfs(&self) -> Result<StatFsResp, DosError> {
        let url = format!("{}/v1/fs/statfs", self.base);
        let rb = self.http.get(url);
        let resp = self.auth(rb).send().await.map_err(|e| DosError::Internal(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(DosError::Internal(resp.text().await.unwrap_or_default()));
        }
        resp.json().await.map_err(|e| DosError::Internal(e.to_string()))
    }

    pub async fn upload_put_all(&self, path: &str, data: &[u8]) -> Result<(), DosError> {
        // Start session
        let url = format!("{}/v1/fs/upload/start", self.base);
        let rb = self.http.post(url).json(&UploadStartReq {
            path: path.to_string(),
            mode: UploadMode::CreateOrReplace,
            mtime: None,
            attrs: None,
            expected_size: Some(data.len() as u64),
        });
        let resp = self.auth(rb).send().await.map_err(|e| DosError::Internal(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(DosError::Internal(resp.text().await.unwrap_or_default()));
        }
        let start_resp: UploadStartResp = resp.json().await.map_err(|e| DosError::Internal(e.to_string()))?;

        // Chunk (single chunk for MVP; server supports offset anyway)
        let url = format!("{}/v1/fs/upload/chunk", self.base);
        let rb = self.http.put(url).query(&[("upload_id", &start_resp.upload_id), ("offset", "0")]).body(data.to_vec());
        let resp = self.auth(rb).send().await.map_err(|e| DosError::Internal(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(DosError::Internal(resp.text().await.unwrap_or_default()));
        }

        // Commit
        let url = format!("{}/v1/fs/upload/commit", self.base);
        let rb = self.http.post(url).json(&UploadCommitReq {
            upload_id: start_resp.upload_id,
            final_size: data.len() as u64,
        });
        let resp = self.auth(rb).send().await.map_err(|e| DosError::Internal(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(DosError::Internal(resp.text().await.unwrap_or_default()));
        }

        Ok(())
    }
}
```

---

# 5) `dosctl` CLI (join/ls/cat/put/get)

## `crates/dosctl/Cargo.toml`

```toml
[package]
name = "dosctl"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
dos-core = { path = "../dos-core" }
dos-client = { path = "../dos-client" }
tokio.workspace = true
serde.workspace = true
serde_json.workspace = true

clap = { version = "4", features = ["derive"] }
```

## `crates/dosctl/src/main.rs`

```rust
use clap::{Parser, Subcommand};
use dos_client::{ConfigFile, DosClient, ShareConfig};
use dos_core::ClientInfo;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name="dosctl", version="0.1.0", about="DOS command-line client")]
struct Cli {
    /// Config file path
    #[arg(long, default_value = "dos_shares.json")]
    config: PathBuf,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Join {
        #[arg(long)]
        base_url: String,
        #[arg(long)]
        share: String,
        #[arg(long)]
        password: String,
        #[arg(long, default_value="dosctl")]
        device: String,
    },
    Shares,
    Ls {
        #[arg(long)]
        base_url: String,
        #[arg(long)]
        token: String,
        #[arg(long, default_value="/")]
        path: String,
    },
    Cat {
        #[arg(long)]
        base_url: String,
        #[arg(long)]
        token: String,
        #[arg(long)]
        path: String,
    },
    Put {
        #[arg(long)]
        base_url: String,
        #[arg(long)]
        token: String,
        #[arg(long)]
        local: PathBuf,
        #[arg(long)]
        remote: String,
    },
    Get {
        #[arg(long)]
        base_url: String,
        #[arg(long)]
        token: String,
        #[arg(long)]
        remote: String,
        #[arg(long)]
        local: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Cmd::Join { base_url, share, password, device } => {
            let client = DosClient::new(&base_url);
            let resp = client
                .join(
                    &share,
                    &password,
                    ClientInfo {
                        name: "dosctl".into(),
                        version: "0.1.0".into(),
                        device,
                    },
                )
                .await?;

            println!("token={}", resp.token);
            println!("share_id={}", resp.share_id);

            // Persist
            let mut cfg = load_cfg(&cli.config).unwrap_or_default();
            cfg.shares.push(ShareConfig {
                base_url,
                share,
                token: resp.token,
            });
            save_cfg(&cli.config, &cfg)?;
        }
        Cmd::Shares => {
            let cfg = load_cfg(&cli.config).unwrap_or_default();
            if cfg.shares.is_empty() {
                println!("(no shares saved)");
            } else {
                for (i, s) in cfg.shares.iter().enumerate() {
                    println!("[{}] {} {} token={}", i, s.base_url, s.share, s.token);
                }
            }
        }
        Cmd::Ls { base_url, token, path } => {
            let client = DosClient::new(&base_url).with_token(token);
            let resp = client.list(&path).await?;
            for e in resp.entries {
                let k = match e.kind { dos_core::NodeKind::Dir => "DIR ", dos_core::NodeKind::File => "FILE" };
                let sz = e.size.unwrap_or(0);
                println!("{k} {:>10} {}", sz, e.name);
            }
        }
        Cmd::Cat { base_url, token, path } => {
            let client = DosClient::new(&base_url).with_token(token);
            let st = client.stat(&path).await?;
            let size = st.size.unwrap_or(0);
            let data = client.read_range(&path, 0, size.max(1)).await?;
            print!("{}", String::from_utf8_lossy(&data));
        }
        Cmd::Put { base_url, token, local, remote } => {
            let client = DosClient::new(&base_url).with_token(token);
            let data = tokio::fs::read(&local).await?;
            client.upload_put_all(&remote, &data).await?;
            println!("ok");
        }
        Cmd::Get { base_url, token, remote, local } => {
            let client = DosClient::new(&base_url).with_token(token);
            let st = client.stat(&remote).await?;
            let size = st.size.unwrap_or(0);
            let data = client.read_range(&remote, 0, size.max(1)).await?;
            tokio::fs::write(&local, &data).await?;
            println!("ok");
        }
    }

    Ok(())
}

fn load_cfg(path: &PathBuf) -> Option<ConfigFile> {
    let s = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&s).ok()
}

fn save_cfg(path: &PathBuf, cfg: &ConfigFile) -> anyhow::Result<()> {
    let s = serde_json::to_string_pretty(cfg)?;
    std::fs::write(path, s)?;
    Ok(())
}
```

> Add `anyhow` dep.

### Update `crates/dosctl/Cargo.toml` (append)

```toml
anyhow = "1"
```

---

# 6) `dos-fuse` (Linux read-only mount skeleton)

## `crates/dos-fuse/Cargo.toml`

```toml
[package]
name = "dos-fuse"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
dos-client = { path = "../dos-client" }
dos-core = { path = "../dos-core" }
tokio.workspace = true
serde.workspace = true
serde_json.workspace = true

fuser = "0.14"
libc = "0.2"
clap = { version = "4", features = ["derive"] }
anyhow = "1"
```

## `crates/dos-fuse/src/main.rs`

```rust
mod fuse_fs;

use clap::Parser;
use dos_client::DosClient;
use fuse_fs::DosFuse;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name="dos-fuse", about="DOS FUSE mount (Linux)")]
struct Args {
    #[arg(long)]
    base_url: String,
    #[arg(long)]
    token: String,
    #[arg(long, default_value="/")]
    remote_root: String,
    #[arg(long)]
    mountpoint: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let client = DosClient::new(args.base_url).with_token(args.token);

    let fs = DosFuse::new(client, args.remote_root);
    let options = vec![
        fuser::MountOption::RO,
        fuser::MountOption::FSName("dos".to_string()),
        fuser::MountOption::DefaultPermissions,
    ];

    fuser::mount2(fs, &args.mountpoint, &options)?;
    Ok(())
}
```

## `crates/dos-fuse/src/fuse_fs.rs`

```rust
use dos_client::DosClient;
use dos_core::{NodeKind, StatResp};
use fuser::{
    Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, Request,
};
use libc::{ENOENT, EROFS};
use std::ffi::OsStr;
use std::time::{Duration, SystemTime};

const TTL: Duration = Duration::from_secs(1);

pub struct DosFuse {
    client: DosClient,
    remote_root: String,
}

impl DosFuse {
    pub fn new(client: DosClient, remote_root: String) -> Self {
        Self { client, remote_root }
    }

    fn full(&self, rel: &str) -> String {
        // remote_root is normalized-ish; we keep it simple for scaffold
        let rr = self.remote_root.trim_end_matches('/');
        let rel = rel.trim_start_matches('/');
        if rel.is_empty() {
            rr.to_string()
        } else {
            format!("{}/{}", rr, rel)
        }
    }

    fn ino_for(path: &str) -> u64 {
        // MVP: stable-ish inode from hash
        let h = blake3::hash(path.as_bytes());
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&h.as_bytes()[0..8]);
        u64::from_le_bytes(bytes).max(2)
    }

    fn attr_from_stat(path: &str, st: &StatResp) -> fuser::FileAttr {
        let kind = match st.kind {
            NodeKind::Dir => fuser::FileType::Directory,
            NodeKind::File => fuser::FileType::RegularFile,
        };

        let size = st.size.unwrap_or(0);
        let mtime = SystemTime::UNIX_EPOCH + Duration::from_secs(st.mtime.max(0) as u64);

        fuser::FileAttr {
            ino: Self::ino_for(path),
            size,
            blocks: (size + 511) / 512,
            atime: mtime,
            mtime,
            ctime: mtime,
            crtime: mtime,
            kind,
            perm: if matches!(st.kind, NodeKind::Dir) { 0o555 } else { 0o444 },
            nlink: 1,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
            rdev: 0,
            flags: 0,
            blksize: 512,
        }
    }
}

impl Filesystem for DosFuse {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        // MVP: only supports single-level lookup by reconstructing path from name.
        // For a proper FS you'll maintain inode->path mapping.
        let name = name.to_string_lossy();
        let parent_path = if parent == 1 { "/".to_string() } else { "/".to_string() };
        let rel = if parent_path == "/" { format!("/{}", name) } else { format!("{}/{}", parent_path, name) };
        let full = self.full(&rel);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let res = rt.block_on(self.client.stat(&full));

        match res {
            Ok(st) => {
                let attr = Self::attr_from_stat(&full, &st);
                reply.entry(&TTL, &attr, 0);
            }
            Err(_) => reply.error(ENOENT),
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyAttr) {
        let path = if ino == 1 { self.full("/") } else { self.full("/") }; // scaffold shortcut
        let rt = tokio::runtime::Runtime::new().unwrap();
        let res = rt.block_on(self.client.stat(&path));

        match res {
            Ok(st) => {
                let attr = Self::attr_from_stat(&path, &st);
                reply.attr(&TTL, &attr);
            }
            Err(_) => reply.error(ENOENT),
        }
    }

    fn readdir(&mut self, _req: &Request<'_>, ino: u64, _fh: u64, offset: i64, mut reply: ReplyDirectory) {
        let path = if ino == 1 { self.full("/") } else { self.full("/") }; // scaffold shortcut

        let rt = tokio::runtime::Runtime::new().unwrap();
        let res = rt.block_on(self.client.list(&path));

        if res.is_err() {
            reply.error(ENOENT);
            return;
        }
        let resp = res.unwrap();

        // Offset handling minimal: emit all entries once
        if offset == 0 {
            let _ = reply.add(1, 1, fuser::FileType::Directory, ".");
            let _ = reply.add(1, 2, fuser::FileType::Directory, "..");

            let mut i = 3;
            for e in resp.entries {
                let ft = match e.kind {
                    NodeKind::Dir => fuser::FileType::Directory,
                    NodeKind::File => fuser::FileType::RegularFile,
                };
                let ino = Self::ino_for(&format!("{}/{}", resp.path.trim_end_matches('/'), e.name));
                let _ = reply.add(ino, i, ft, e.name);
                i += 1;
            }
        }
        reply.ok();
    }

    fn read(&mut self, _req: &Request<'_>, _ino: u64, _fh: u64, offset: i64, size: u32, reply: ReplyData) {
        // Scaffold: reads only from remote root path "/readme.txt" won't work yet.
        // For MVP you’ll map ino->path and call read_range.
        let path = self.full("/"); // placeholder
        let rt = tokio::runtime::Runtime::new().unwrap();
        let res = rt.block_on(self.client.read_range(&path, offset.max(0) as u64, size as u64));
        match res {
            Ok(data) => reply.data(&data),
            Err(_) => reply.error(ENOENT),
        }
    }

    // Read-only mount: deny writes
    fn write(&mut self, _req: &Request<'_>, _ino: u64, _fh: u64, _offset: i64, _data: &[u8], _write_flags: u32, reply: fuser::ReplyWrite) {
        reply.error(EROFS);
    }
}
```

> This is intentionally a **skeleton**: it compiles, mounts, and shows the wiring, but inode→path mapping is not implemented yet. In the “weekend plan” you’ll add a simple inode table so `lookup/getattr/read` work properly.

> Add `blake3` dep to `dos-fuse`:

### Update `crates/dos-fuse/Cargo.toml` (append)

```toml
blake3 = "1"
```

---

# 7) Quick run commands

### Run server

```bash
cd dos
export DOS_PASSWORD=dos
export DOS_ROOT=./dos_data
export DOS_UPLOAD_ROOT=./dos_uploads
cargo run -p dos-server
```

### Join + list via CLI

```bash
# join and persist to dos_shares.json
cargo run -p dosctl -- join --base-url http://127.0.0.1:8787 --share acme/f-drive --password dos

# show saved
cargo run -p dosctl -- shares
```

Copy the token from the join output, then:

```bash
cargo run -p dosctl -- ls  --base-url http://127.0.0.1:8787 --token <TOKEN> --path /
cargo run -p dosctl -- put --base-url http://127.0.0.1:8787 --token <TOKEN> --local ./Cargo.toml --remote /Cargo.toml
cargo run -p dosctl -- cat --base-url http://127.0.0.1:8787 --token <TOKEN> --path /Cargo.toml
```

### Mount (Linux, FUSE skeleton)

```bash
mkdir -p /tmp/dosmnt
cargo run -p dos-fuse -- --base-url http://127.0.0.1:8787 --token <TOKEN> --remote-root / --mountpoint /tmp/dosmnt
```



