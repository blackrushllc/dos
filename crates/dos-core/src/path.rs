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
