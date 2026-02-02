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
