Here’s the **patch** that turns the `dos-fuse` skeleton into a **working read-only FUSE filesystem** by adding a simple **inode ↔ path** map and wiring `lookup/getattr/readdir/read` to real remote paths.

This keeps things intentionally small and “weekend-friendly,” but it will let you do:

* `ls /tmp/dosmnt`
* `cat /tmp/dosmnt/somefile`
* `find`, `head`, etc. (read-only)

> **Apply this patch to** `crates/dos-fuse/src/fuse_fs.rs`

---

## Patch: inode/path map + real lookup/getattr/readdir/read

```diff
diff --git a/crates/dos-fuse/src/fuse_fs.rs b/crates/dos-fuse/src/fuse_fs.rs
index 1111111..2222222 100644
--- a/crates/dos-fuse/src/fuse_fs.rs
+++ b/crates/dos-fuse/src/fuse_fs.rs
@@ -1,66 +1,149 @@
 use dos_client::DosClient;
 use dos_core::{NodeKind, StatResp};
 use fuser::{
     Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, Request,
 };
 use libc::{ENOENT, EROFS};
+use std::collections::HashMap;
 use std::ffi::OsStr;
+use std::sync::Mutex;
 use std::time::{Duration, SystemTime};
 
 const TTL: Duration = Duration::from_secs(1);
 
 pub struct DosFuse {
     client: DosClient,
-    remote_root: String,
+    remote_root: String,
+    ino_to_path: Mutex<HashMap<u64, String>>,
 }
 
 impl DosFuse {
     pub fn new(client: DosClient, remote_root: String) -> Self {
-        Self { client, remote_root }
+        let rr = normalize_root(&remote_root);
+        let mut map = HashMap::new();
+        map.insert(1, rr.clone()); // inode 1 is root
+        Self {
+            client,
+            remote_root: rr,
+            ino_to_path: Mutex::new(map),
+        }
     }
 
-    fn full(&self, rel: &str) -> String {
-        // remote_root is normalized-ish; we keep it simple for scaffold
-        let rr = self.remote_root.trim_end_matches('/');
-        let rel = rel.trim_start_matches('/');
-        if rel.is_empty() {
-            rr.to_string()
-        } else {
-            format!("{}/{}", rr, rel)
-        }
+    fn path_for_ino(&self, ino: u64) -> Option<String> {
+        self.ino_to_path.lock().ok()?.get(&ino).cloned()
+    }
+
+    fn remember_path(&self, ino: u64, path: String) {
+        if let Ok(mut map) = self.ino_to_path.lock() {
+            map.insert(ino, path);
+        }
+    }
+
+    fn join_child(parent: &str, name: &str) -> String {
+        let p = parent.trim_end_matches('/');
+        let n = name.trim_start_matches('/');
+        if p.is_empty() || p == "/" {
+            format!("/{}", n)
+        } else {
+            format!("{}/{}", p, n)
+        }
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
-        // MVP: only supports single-level lookup by reconstructing path from name.
-        // For a proper FS you'll maintain inode->path mapping.
-        let name = name.to_string_lossy();
-        let parent_path = if parent == 1 { "/".to_string() } else { "/".to_string() };
-        let rel = if parent_path == "/" { format!("/{}", name) } else { format!("{}/{}", parent_path, name) };
-        let full = self.full(&rel);
+        let name = name.to_string_lossy().to_string();
+        let Some(parent_path) = self.path_for_ino(parent) else {
+            reply.error(ENOENT);
+            return;
+        };
+        let full = Self::join_child(&parent_path, &name);
 
         let rt = tokio::runtime::Runtime::new().unwrap();
         let res = rt.block_on(self.client.stat(&full));
 
         match res {
             Ok(st) => {
                 let attr = Self::attr_from_stat(&full, &st);
+                self.remember_path(attr.ino, full);
                 reply.entry(&TTL, &attr, 0);
             }
             Err(_) => reply.error(ENOENT),
         }
     }
 
     fn getattr(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyAttr) {
-        let path = if ino == 1 { self.full("/") } else { self.full("/") }; // scaffold shortcut
+        let Some(path) = self.path_for_ino(ino) else {
+            reply.error(ENOENT);
+            return;
+        };
         let rt = tokio::runtime::Runtime::new().unwrap();
         let res = rt.block_on(self.client.stat(&path));
 
         match res {
             Ok(st) => {
                 let attr = Self::attr_from_stat(&path, &st);
+                // refresh mapping in case server canonicalizes; harmless
+                self.remember_path(attr.ino, path);
                 reply.attr(&TTL, &attr);
             }
             Err(_) => reply.error(ENOENT),
         }
     }
 
     fn readdir(&mut self, _req: &Request<'_>, ino: u64, _fh: u64, offset: i64, mut reply: ReplyDirectory) {
-        let path = if ino == 1 { self.full("/") } else { self.full("/") }; // scaffold shortcut
+        let Some(path) = self.path_for_ino(ino) else {
+            reply.error(ENOENT);
+            return;
+        };
 
         let rt = tokio::runtime::Runtime::new().unwrap();
         let res = rt.block_on(self.client.list(&path));
 
         if res.is_err() {
             reply.error(ENOENT);
             return;
         }
         let resp = res.unwrap();
 
-        // Offset handling minimal: emit all entries once
-        if offset == 0 {
-            let _ = reply.add(1, 1, fuser::FileType::Directory, ".");
-            let _ = reply.add(1, 2, fuser::FileType::Directory, "..");
-
-            let mut i = 3;
-            for e in resp.entries {
-                let ft = match e.kind {
-                    NodeKind::Dir => fuser::FileType::Directory,
-                    NodeKind::File => fuser::FileType::RegularFile,
-                };
-                let ino = Self::ino_for(&format!("{}/{}", resp.path.trim_end_matches('/'), e.name));
-                let _ = reply.add(ino, i, ft, e.name);
-                i += 1;
-            }
-        }
+        // Proper-ish offset: FUSE expects us to resume listing from `offset`.
+        // We'll build a virtual list: [".", "..", entries...]
+        let mut items: Vec<(u64, fuser::FileType, String)> = Vec::new();
+        items.push((ino, fuser::FileType::Directory, ".".to_string()));
+        items.push((1, fuser::FileType::Directory, "..".to_string()));
+
+        for e in resp.entries {
+            let ft = match e.kind {
+                NodeKind::Dir => fuser::FileType::Directory,
+                NodeKind::File => fuser::FileType::RegularFile,
+            };
+            let child_path = Self::join_child(&path, &e.name);
+            let child_ino = Self::ino_for(&child_path);
+            self.remember_path(child_ino, child_path);
+            items.push((child_ino, ft, e.name));
+        }
+
+        let start = offset.max(0) as usize;
+        for (i, (child_ino, ft, name)) in items.into_iter().enumerate().skip(start) {
+            let next_offset = (i + 1) as i64;
+            if reply.add(child_ino, next_offset, ft, name) {
+                break;
+            }
+        }
         reply.ok();
     }
 
     fn read(&mut self, _req: &Request<'_>, _ino: u64, _fh: u64, offset: i64, size: u32, reply: ReplyData) {
-        // Scaffold: reads only from remote root path "/readme.txt" won't work yet.
-        // For MVP you’ll map ino->path and call read_range.
-        let path = self.full("/"); // placeholder
+        let ino = _ino;
+        let Some(path) = self.path_for_ino(ino) else {
+            reply.error(ENOENT);
+            return;
+        };
         let rt = tokio::runtime::Runtime::new().unwrap();
-        let res = rt.block_on(self.client.read_range(&path, offset.max(0) as u64, size as u64));
+        let off = offset.max(0) as u64;
+        let len = (size as u64).max(1);
+        let res = rt.block_on(self.client.read_range(&path, off, len));
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
+
+fn normalize_root(input: &str) -> String {
+    // ensure absolute, no trailing slash unless root
+    let mut s = input.replace('\\', "/");
+    if s.is_empty() {
+        s = "/".to_string();
+    }
+    if !s.starts_with('/') {
+        s = format!("/{}", s);
+    }
+    while s.contains("//") {
+        s = s.replace("//", "/");
+    }
+    if s.len() > 1 {
+        s = s.trim_end_matches('/').to_string();
+    }
+    s
+}
```

### What this patch changes

* Adds `ino_to_path` map (root inode `1` → remote root path).
* `readdir` now:

    * fetches remote listing
    * **assigns inodes** based on full remote paths
    * stores mappings for each child
    * supports the `offset` parameter enough to keep FUSE happy
* `lookup/getattr/read` now resolve the inode to a real remote path

### Build & test

```bash
cargo build -p dos-fuse

# run server (in another terminal)
cargo run -p dos-server

# join / get token
cargo run -p dosctl -- join --base-url http://127.0.0.1:8787 --share acme/f-drive --password dos

# mount
mkdir -p /tmp/dosmnt
cargo run -p dos-fuse -- \
  --base-url http://127.0.0.1:8787 \
  --token <TOKEN> \
  --remote-root / \
  --mountpoint /tmp/dosmnt

# test reads
ls -la /tmp/dosmnt
cat /tmp/dosmnt/Cargo.toml
```

> If you don’t see files: remember the server’s `DOS_ROOT` directory is the “share disk.” Put something in there (or use `dosctl put`).

---

## Next: Step 2 (write support via temp-file then upload-on-close)

When you’re ready, we’ll implement a “classic” strategy:

* On `create/open(O_WRONLY|O_RDWR)`: create a local temp file and a handle
* `write` writes to temp file
* On `flush/release`: upload temp file via:

    * `upload/start`
    * `upload/chunk` (stream in 4MB chunks)
    * `upload/commit` (atomic replace)
* On `unlink`/`rename`: call server endpoints directly
* This makes a surprising number of apps work immediately because they expect local-like semantics.

The next step is NEXT_STEP.md
