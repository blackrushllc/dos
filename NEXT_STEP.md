Awesome. Step 2 = **real write support** in FUSE using the classic, reliable strategy:

> **Write to a local temp file → on close (release) upload entire file → atomic replace on server.**

This gets you *shockingly far* fast, because many apps do “write temp + rename” or expect local-ish behavior.

Below are **two patches**:

1. `dos-client`: add `upload_put_file()` that streams a local file up in chunks using your existing upload-session endpoints.
2. `dos-fuse`: switch mount to RW + implement `open/create/write/flush/release/mkdir/unlink/rmdir/rename/setattr` using temp files and upload-on-close.

---

# Patch 1 — `dos-client`: upload a local file in chunks

Apply this patch to: `crates/dos-client/src/api.rs`

```diff
diff --git a/crates/dos-client/src/api.rs b/crates/dos-client/src/api.rs
index 1111111..2222222 100644
--- a/crates/dos-client/src/api.rs
+++ b/crates/dos-client/src/api.rs
@@ -1,6 +1,7 @@
 use dos_core::*;
 use reqwest::header::{AUTHORIZATION, RANGE};
 use std::collections::HashMap;
+use tokio::io::AsyncReadExt;

 #[derive(Clone)]
 pub struct DosClient {
     http: reqwest::Client,
@@ -170,6 +171,109 @@ impl DosClient {
 
         Ok(())
     }
+
+    /// Upload a local file to a remote path using upload sessions and chunk PUTs.
+    /// This avoids loading the whole file into memory.
+    pub async fn upload_put_file(&self, remote_path: &str, local_path: &std::path::Path) -> Result<(), DosError> {
+        let meta = tokio::fs::metadata(local_path).await.map_err(|e| DosError::Io(e))?;
+        if !meta.is_file() {
+            return Err(DosError::Invalid("local_path is not a file".into()));
+        }
+        let size = meta.len();
+
+        // Start session
+        let url = format!("{}/v1/fs/upload/start", self.base);
+        let rb = self.http.post(url).json(&UploadStartReq {
+            path: remote_path.to_string(),
+            mode: UploadMode::CreateOrReplace,
+            mtime: None,
+            attrs: None,
+            expected_size: Some(size),
+        });
+        let resp = self.auth(rb).send().await.map_err(|e| DosError::Internal(e.to_string()))?;
+        if !resp.status().is_success() {
+            return Err(DosError::Internal(resp.text().await.unwrap_or_default()));
+        }
+        let start_resp: UploadStartResp = resp.json().await.map_err(|e| DosError::Internal(e.to_string()))?;
+        let chunk_size = start_resp.chunk_size.max(1) as usize;
+
+        // Upload chunks
+        let mut f = tokio::fs::File::open(local_path).await.map_err(|e| DosError::Io(e))?;
+        let mut offset: u64 = 0;
+        let mut buf = vec![0u8; chunk_size];
+
+        loop {
+            let n = f.read(&mut buf).await.map_err(|e| DosError::Io(e))?;
+            if n == 0 {
+                break;
+            }
+            let url = format!("{}/v1/fs/upload/chunk", self.base);
+            let rb = self.http
+                .put(url)
+                .query(&[
+                    ("upload_id", &start_resp.upload_id),
+                    ("offset", &offset.to_string()),
+                ])
+                .body(buf[..n].to_vec());
+
+            let resp = self.auth(rb).send().await.map_err(|e| DosError::Internal(e.to_string()))?;
+            if !resp.status().is_success() {
+                // best-effort abort
+                let _ = self
+                    .abort_upload(&start_resp.upload_id)
+                    .await;
+                return Err(DosError::Internal(resp.text().await.unwrap_or_default()));
+            }
+            offset += n as u64;
+        }
+
+        // Commit
+        let url = format!("{}/v1/fs/upload/commit", self.base);
+        let rb = self.http.post(url).json(&UploadCommitReq {
+            upload_id: start_resp.upload_id,
+            final_size: size,
+        });
+        let resp = self.auth(rb).send().await.map_err(|e| DosError::Internal(e.to_string()))?;
+        if !resp.status().is_success() {
+            return Err(DosError::Internal(resp.text().await.unwrap_or_default()));
+        }
+
+        Ok(())
+    }
+
+    async fn abort_upload(&self, upload_id: &str) -> Result<(), DosError> {
+        let url = format!("{}/v1/fs/upload/abort", self.base);
+        let rb = self.http.post(url).json(&UploadAbortReq { upload_id: upload_id.to_string() });
+        let resp = self.auth(rb).send().await.map_err(|e| DosError::Internal(e.to_string()))?;
+        if !resp.status().is_success() {
+            return Err(DosError::Internal(resp.text().await.unwrap_or_default()));
+        }
+        Ok(())
+    }
 }
```

✅ This gives the FUSE layer a safe “upload this temp file” primitive.

---

# Patch 2 — `dos-fuse`: RW mount + temp-file writes + upload on close

## 2A) Update mount options to be writable

Apply this patch to: `crates/dos-fuse/src/main.rs`

```diff
diff --git a/crates/dos-fuse/src/main.rs b/crates/dos-fuse/src/main.rs
index 1111111..2222222 100644
--- a/crates/dos-fuse/src/main.rs
+++ b/crates/dos-fuse/src/main.rs
@@ -1,6 +1,7 @@
 mod fuse_fs;

 use clap::Parser;
 use dos_client::DosClient;
 use fuse_fs::DosFuse;
 use std::path::PathBuf;
@@ -23,13 +24,13 @@ fn main() -> anyhow::Result<()> {
     let args = Args::parse();
     let client = DosClient::new(args.base_url).with_token(args.token);

     let fs = DosFuse::new(client, args.remote_root);
     let options = vec![
-        fuser::MountOption::RO,
         fuser::MountOption::FSName("dos".to_string()),
         fuser::MountOption::DefaultPermissions,
     ];

     fuser::mount2(fs, &args.mountpoint, &options)?;
     Ok(())
 }
```

Now it mounts RW.

---

## 2B) Implement write path in the filesystem

Apply this patch to: `crates/dos-fuse/src/fuse_fs.rs`

> This assumes you already applied the inode/path mapping patch from Step 1.

```diff
diff --git a/crates/dos-fuse/src/fuse_fs.rs b/crates/dos-fuse/src/fuse_fs.rs
index 2222222..3333333 100644
--- a/crates/dos-fuse/src/fuse_fs.rs
+++ b/crates/dos-fuse/src/fuse_fs.rs
@@ -1,20 +1,35 @@
 use dos_client::DosClient;
 use dos_core::{NodeKind, StatResp};
 use fuser::{
-    Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, Request,
+    Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEntry, ReplyEmpty,
+    ReplyOpen, ReplyWrite, Request,
 };
 use libc::{ENOENT, EROFS};
 use std::collections::HashMap;
 use std::ffi::OsStr;
 use std::sync::Mutex;
 use std::time::{Duration, SystemTime};
+use uuid::Uuid;

 const TTL: Duration = Duration::from_secs(1);

+#[derive(Debug)]
+struct Handle {
+    remote_path: String,
+    tmp_path: std::path::PathBuf,
+    file: std::fs::File,
+    dirty: bool,
+}
+
 pub struct DosFuse {
     client: DosClient,
     remote_root: String,
     ino_to_path: Mutex<HashMap<u64, String>>,
+    handles: Mutex<HashMap<u64, Handle>>,
+    next_fh: std::sync::atomic::AtomicU64,
 }

 impl DosFuse {
     pub fn new(client: DosClient, remote_root: String) -> Self {
         let rr = normalize_root(&remote_root);
         let mut map = HashMap::new();
         map.insert(1, rr.clone()); // inode 1 is root
         Self {
             client,
             remote_root: rr,
             ino_to_path: Mutex::new(map),
+            handles: Mutex::new(HashMap::new()),
+            next_fh: std::sync::atomic::AtomicU64::new(10),
         }
     }

@@ -37,6 +52,53 @@ impl DosFuse {
     fn remember_path(&self, ino: u64, path: String) {
         if let Ok(mut map) = self.ino_to_path.lock() {
             map.insert(ino, path);
         }
     }
+
+    fn alloc_fh(&self) -> u64 {
+        self.next_fh.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
+    }
+
+    fn is_write(flags: i32) -> bool {
+        let acc = flags & libc::O_ACCMODE;
+        acc == libc::O_WRONLY || acc == libc::O_RDWR
+    }
+
+    fn is_trunc(flags: i32) -> bool {
+        (flags & libc::O_TRUNC) != 0
+    }
+
+    fn create_temp_file() -> anyhow::Result<(std::path::PathBuf, std::fs::File)> {
+        let base = std::env::temp_dir().join(format!("dos-fuse-{}", std::process::id()));
+        std::fs::create_dir_all(&base)?;
+        let tmp = base.join(format!("{}.tmp", Uuid::new_v4()));
+        let f = std::fs::OpenOptions::new()
+            .create(true)
+            .read(true)
+            .write(true)
+            .open(&tmp)?;
+        Ok((tmp, f))
+    }
+
+    fn rt() -> tokio::runtime::Runtime {
+        tokio::runtime::Runtime::new().expect("tokio runtime")
+    }
+
+    fn prefill_if_needed(&self, remote_path: &str, file: &mut std::fs::File, flags: i32) {
+        // If opened for write without O_TRUNC, many apps expect existing content.
+        if !Self::is_write(flags) || Self::is_trunc(flags) {
+            return;
+        }
+        let rt = Self::rt();
+        let st = match rt.block_on(self.client.stat(remote_path)) {
+            Ok(s) => s,
+            Err(_) => return,
+        };
+        let Some(sz) = st.size else { return; };
+        if sz == 0 {
+            return;
+        }
+        // Download whole file (prototype). For very large files you’ll later stream/chunk.
+        let data = match rt.block_on(self.client.read_range(remote_path, 0, sz.max(1))) {
+            Ok(d) => d,
+            Err(_) => return,
+        };
+        use std::io::{Seek, SeekFrom, Write};
+        let _ = file.set_len(0);
+        let _ = file.seek(SeekFrom::Start(0));
+        let _ = file.write_all(&data);
+        let _ = file.seek(SeekFrom::Start(0));
+    }

     fn join_child(parent: &str, name: &str) -> String {
         let p = parent.trim_end_matches('/');
         let n = name.trim_start_matches('/');
@@ -146,6 +208,126 @@ impl Filesystem for DosFuse {
     fn read(&mut self, _req: &Request<'_>, _ino: u64, _fh: u64, offset: i64, size: u32, reply: ReplyData) {
         let ino = _ino;
         let Some(path) = self.path_for_ino(ino) else {
             reply.error(ENOENT);
             return;
         };
         let rt = tokio::runtime::Runtime::new().unwrap();
         let off = offset.max(0) as u64;
         let len = (size as u64).max(1);
         let res = rt.block_on(self.client.read_range(&path, off, len));
         match res {
             Ok(data) => reply.data(&data),
             Err(_) => reply.error(ENOENT),
         }
     }

-    // Read-only mount: deny writes
-    fn write(&mut self, _req: &Request<'_>, _ino: u64, _fh: u64, _offset: i64, _data: &[u8], _write_flags: u32, reply: fuser::ReplyWrite) {
-        reply.error(EROFS);
-    }
+    fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
+        let Some(remote_path) = self.path_for_ino(ino) else {
+            reply.error(ENOENT);
+            return;
+        };
+
+        if !Self::is_write(flags) {
+            // read-only open: no handle needed
+            reply.opened(0, 0);
+            return;
+        }
+
+        // writable: create temp file, optionally prefill existing data
+        let (tmp_path, mut file) = match Self::create_temp_file() {
+            Ok(x) => x,
+            Err(_) => {
+                reply.error(ENOENT);
+                return;
+            }
+        };
+        self.prefill_if_needed(&remote_path, &mut file, flags);
+
+        let fh = self.alloc_fh();
+        let h = Handle {
+            remote_path,
+            tmp_path,
+            file,
+            dirty: false,
+        };
+        if let Ok(mut map) = self.handles.lock() {
+            map.insert(fh, h);
+        }
+        reply.opened(fh, 0);
+    }
+
+    fn create(
+        &mut self,
+        _req: &Request<'_>,
+        parent: u64,
+        name: &OsStr,
+        _mode: u32,
+        flags: i32,
+        reply: ReplyCreate,
+    ) {
+        let Some(parent_path) = self.path_for_ino(parent) else {
+            reply.error(ENOENT);
+            return;
+        };
+        let name = name.to_string_lossy().to_string();
+        let remote_path = Self::join_child(&parent_path, &name);
+        let ino = Self::ino_for(&remote_path);
+        self.remember_path(ino, remote_path.clone());
+
+        let (tmp_path, file) = match Self::create_temp_file() {
+            Ok(x) => x,
+            Err(_) => {
+                reply.error(ENOENT);
+                return;
+            }
+        };
+
+        let fh = self.alloc_fh();
+        let h = Handle {
+            remote_path: remote_path.clone(),
+            tmp_path,
+            file,
+            dirty: true, // new file will be uploaded on close
+        };
+        if let Ok(mut map) = self.handles.lock() {
+            map.insert(fh, h);
+        }
+
+        // Return an optimistic attr; getattr will correct it after upload.
+        let now = SystemTime::now();
+        let attr = fuser::FileAttr {
+            ino,
+            size: 0,
+            blocks: 0,
+            atime: now,
+            mtime: now,
+            ctime: now,
+            crtime: now,
+            kind: fuser::FileType::RegularFile,
+            perm: 0o666,
+            nlink: 1,
+            uid: unsafe { libc::getuid() },
+            gid: unsafe { libc::getgid() },
+            rdev: 0,
+            flags: 0,
+            blksize: 512,
+        };
+
+        if !Self::is_write(flags) {
+            reply.error(EROFS);
+            return;
+        }
+        reply.created(&TTL, &attr, 0, fh, 0);
+    }
+
+    fn write(&mut self, _req: &Request<'_>, _ino: u64, fh: u64, offset: i64, data: &[u8], _write_flags: u32, reply: ReplyWrite) {
+        use std::io::{Seek, SeekFrom, Write};
+        let mut handles = match self.handles.lock() {
+            Ok(h) => h,
+            Err(_) => {
+                reply.error(ENOENT);
+                return;
+            }
+        };
+        let Some(h) = handles.get_mut(&fh) else {
+            reply.error(ENOENT);
+            return;
+        };
+        if h.file.seek(SeekFrom::Start(offset.max(0) as u64)).is_err() {
+            reply.error(ENOENT);
+            return;
+        }
+        match h.file.write(data) {
+            Ok(n) => {
+                h.dirty = true;
+                reply.written(n as u32);
+            }
+            Err(_) => reply.error(ENOENT),
+        }
+    }
+
+    fn flush(&mut self, _req: &Request<'_>, _ino: u64, fh: u64, _lock_owner: u64, reply: ReplyEmpty) {
+        // Don't upload on flush; some apps flush constantly.
+        // We'll upload on release (close).
+        if let Ok(handles) = self.handles.lock() {
+            if handles.contains_key(&fh) {
+                reply.ok();
+                return;
+            }
+        }
+        reply.error(ENOENT);
+    }
+
+    fn release(&mut self, _req: &Request<'_>, _ino: u64, fh: u64, _flags: i32, _lock_owner: u64, _flush: bool, reply: ReplyEmpty) {
+        let h = {
+            let mut handles = match self.handles.lock() {
+                Ok(h) => h,
+                Err(_) => {
+                    reply.error(ENOENT);
+                    return;
+                }
+            };
+            handles.remove(&fh)
+        };
+        let Some(mut h) = h else {
+            reply.error(ENOENT);
+            return;
+        };
+
+        // Ensure file content is on disk
+        let _ = h.file.sync_all();
+
+        if h.dirty {
+            let rt = Self::rt();
+            let res = rt.block_on(self.client.upload_put_file(&h.remote_path, &h.tmp_path));
+            if res.is_err() {
+                // Keep temp file for debugging if upload failed
+                reply.error(ENOENT);
+                return;
+            }
+        }
+
+        let _ = std::fs::remove_file(&h.tmp_path);
+        reply.ok();
+    }
+
+    fn mkdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, _mode: u32, reply: ReplyEntry) {
+        let Some(parent_path) = self.path_for_ino(parent) else {
+            reply.error(ENOENT);
+            return;
+        };
+        let name = name.to_string_lossy().to_string();
+        let remote_path = Self::join_child(&parent_path, &name);
+        let ino = Self::ino_for(&remote_path);
+        self.remember_path(ino, remote_path.clone());
+
+        let rt = Self::rt();
+        if rt.block_on(self.client.mkdir(&remote_path)).is_err() {
+            reply.error(ENOENT);
+            return;
+        }
+
+        // Return a basic dir attr
+        let now = SystemTime::now();
+        let attr = fuser::FileAttr {
+            ino,
+            size: 0,
+            blocks: 0,
+            atime: now,
+            mtime: now,
+            ctime: now,
+            crtime: now,
+            kind: fuser::FileType::Directory,
+            perm: 0o777,
+            nlink: 2,
+            uid: unsafe { libc::getuid() },
+            gid: unsafe { libc::getgid() },
+            rdev: 0,
+            flags: 0,
+            blksize: 512,
+        };
+        reply.entry(&TTL, &attr, 0);
+    }
+
+    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
+        let Some(parent_path) = self.path_for_ino(parent) else {
+            reply.error(ENOENT);
+            return;
+        };
+        let name = name.to_string_lossy().to_string();
+        let remote_path = Self::join_child(&parent_path, &name);
+        let rt = Self::rt();
+        if rt.block_on(self.client.delete(&remote_path, false)).is_err() {
+            reply.error(ENOENT);
+            return;
+        }
+        reply.ok();
+    }
+
+    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
+        let Some(parent_path) = self.path_for_ino(parent) else {
+            reply.error(ENOENT);
+            return;
+        };
+        let name = name.to_string_lossy().to_string();
+        let remote_path = Self::join_child(&parent_path, &name);
+        let rt = Self::rt();
+        if rt.block_on(self.client.delete(&remote_path, false)).is_err() {
+            reply.error(ENOENT);
+            return;
+        }
+        reply.ok();
+    }
+
+    fn rename(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, newparent: u64, newname: &OsStr, reply: ReplyEmpty) {
+        let Some(from_parent) = self.path_for_ino(parent) else {
+            reply.error(ENOENT);
+            return;
+        };
+        let Some(to_parent) = self.path_for_ino(newparent) else {
+            reply.error(ENOENT);
+            return;
+        };
+        let from = Self::join_child(&from_parent, &name.to_string_lossy());
+        let to = Self::join_child(&to_parent, &newname.to_string_lossy());
+
+        let rt = Self::rt();
+        if rt.block_on(self.client.rename(&from, &to, true)).is_err() {
+            reply.error(ENOENT);
+            return;
+        }
+        // update mapping for new path inode
+        let ino = Self::ino_for(&to);
+        self.remember_path(ino, to);
+        reply.ok();
+    }
+
+    fn setattr(
+        &mut self,
+        _req: &Request<'_>,
+        ino: u64,
+        _mode: Option<u32>,
+        _uid: Option<u32>,
+        _gid: Option<u32>,
+        size: Option<u64>,
+        _atime: Option<fuser::TimeOrNow>,
+        _mtime: Option<fuser::TimeOrNow>,
+        _ctime: Option<SystemTime>,
+        _fh: Option<u64>,
+        _crtime: Option<SystemTime>,
+        _chgtime: Option<SystemTime>,
+        _bkuptime: Option<SystemTime>,
+        _flags: Option<u32>,
+        reply: ReplyAttr,
+    ) {
+        // Minimal truncate support:
+        // If size is provided, create a temp file, prefill existing, set_len, upload immediately.
+        let Some(new_size) = size else {
+            // just fall back to current getattr
+            self.getattr(_req, ino, reply);
+            return;
+        };
+        let Some(remote_path) = self.path_for_ino(ino) else {
+            reply.error(ENOENT);
+            return;
+        };
+        let (tmp_path, mut file) = match Self::create_temp_file() {
+            Ok(x) => x,
+            Err(_) => {
+                reply.error(ENOENT);
+                return;
+            }
+        };
+        // prefill (acts like not trunc)
+        self.prefill_if_needed(&remote_path, &mut file, libc::O_RDWR);
+        let _ = file.set_len(new_size);
+        let _ = file.sync_all();
+
+        let rt = Self::rt();
+        let res = rt.block_on(self.client.upload_put_file(&remote_path, &tmp_path));
+        let _ = std::fs::remove_file(&tmp_path);
+
+        if res.is_err() {
+            reply.error(ENOENT);
+            return;
+        }
+
+        // Return updated attrs
+        let rt = Self::rt();
+        match rt.block_on(self.client.stat(&remote_path)) {
+            Ok(st) => {
+                let attr = Self::attr_from_stat(&remote_path, &st);
+                self.remember_path(attr.ino, remote_path);
+                reply.attr(&TTL, &attr);
+            }
+            Err(_) => reply.error(ENOENT),
+        }
+    }
 }
```

### Notes on behavior (intentionally MVP-friendly)

* **Uploads happen on `release` (close)**, not on `flush` — otherwise apps that flush constantly will DDoS your server.
* **Prefill is enabled** when opening for write without `O_TRUNC`, so “edit in place” works much more often.
* `setattr(size=...)` implements basic **truncate** by: download → set_len → upload. (Not efficient yet; perfect for prototype.)

---

# Build & test (end-to-end)

### 1) Run server

```bash
export DOS_PASSWORD=dos
cargo run -p dos-server
```

### 2) Join and get token

```bash
cargo run -p dosctl -- join --base-url http://127.0.0.1:8787 --share acme/f-drive --password dos
```

### 3) Mount RW

```bash
mkdir -p /tmp/dosmnt
cargo run -p dos-fuse -- \
  --base-url http://127.0.0.1:8787 \
  --token <TOKEN> \
  --remote-root / \
  --mountpoint /tmp/dosmnt
```

### 4) Try real writes

```bash
echo "hello DOS" > /tmp/dosmnt/hello.txt
cat /tmp/dosmnt/hello.txt
mkdir /tmp/dosmnt/docs
mv /tmp/dosmnt/hello.txt /tmp/dosmnt/docs/hello.txt
rm /tmp/dosmnt/docs/hello.txt
```

---

# What I’d do next (after you confirm this works)

1. **Performance:** reuse a single Tokio runtime instead of creating a new one per call (easy refactor).
2. **Upload efficiency:** stream chunks without local temp for some workloads (but keep temp strategy as default).
3. **Write semantics:** handle “write temp then rename over original” patterns even better (already decent).
4. **Server atomic replace:** tighten commit path (`tmp -> rename`) to be more robust on Windows later.

When you run this, tell me what OS you’re testing on (Linux distro + kernel/FUSE), and whether basic `echo > file` and `nano/vim` edits work — then we’ll tune the few FUSE ops that different editors tend to trigger.
