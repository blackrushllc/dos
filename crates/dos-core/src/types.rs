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
