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
