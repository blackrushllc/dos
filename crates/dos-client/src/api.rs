use dos_core::*;
use reqwest::header::{AUTHORIZATION, RANGE};

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
        let rb = self.http.put(url).query(&[("upload_id", start_resp.upload_id.as_str()), ("offset", "0")]).body(data.to_vec());
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
