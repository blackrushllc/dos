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
