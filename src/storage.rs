use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use tokio::fs;
use tokio::io::AsyncWriteExt;

#[derive(Clone)]
pub struct Storage {
    root: PathBuf,
}

#[derive(Debug, Clone)]
pub struct BlobMeta {
    pub sha256: String,
    pub size: u64,
    pub uploaded_at: u64,
    pub mime: String,
}

impl Storage {
    pub async fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("blobs")).await?;
        fs::create_dir_all(root.join("owners")).await?;
        // Used for atomic writes.
        fs::create_dir_all(root.join("tmp")).await?;
        Ok(Self { root })
    }

    fn blob_path(&self, sha256: &str) -> PathBuf {
        self.root.join("blobs").join(sha256)
    }

    fn owner_dir(&self, pubkey: &str) -> PathBuf {
        self.root.join("owners").join(pubkey)
    }

    fn owner_link(&self, pubkey: &str, sha256: &str) -> PathBuf {
        self.owner_dir(pubkey).join(sha256)
    }

    /// Stream `data` to a temp file, hashing as we go. On match-or-empty,
    /// rename into `blobs/<hash>` (atomic) and create the owner symlink.
    /// Returns the resulting `BlobMeta`.
    pub async fn put(&self, pubkey: &str, data: &[u8], mime: &str) -> Result<BlobMeta> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let sha256 = hex::encode(hasher.finalize());

        let final_path = self.blob_path(&sha256);

        // Skip the write if the blob already exists; just refresh mtime so it gets
        // a fresh TTL.
        if fs::metadata(&final_path).await.is_ok() {
            touch(&final_path).await?;
        } else {
            let tmp = self.root.join("tmp").join(format!("{sha256}.partial"));
            let mut f = fs::File::create(&tmp).await?;
            f.write_all(data).await?;
            f.sync_all().await?;
            drop(f);
            fs::rename(&tmp, &final_path).await?;
        }

        // Create owner symlink (relative target so the data dir stays portable).
        let owner_dir = self.owner_dir(pubkey);
        fs::create_dir_all(&owner_dir).await?;
        let link = self.owner_link(pubkey, &sha256);
        let _ = fs::remove_file(&link).await;
        // Symlink target relative to owners/<pubkey>/: ../../blobs/<sha256>
        symlink(Path::new("../../blobs").join(&sha256), &link).await?;
        // Touch the symlink itself so list-by-pubkey can show recent uploads.
        touch_symlink(&link)?;

        let meta = fs::metadata(&final_path).await?;
        Ok(BlobMeta {
            sha256,
            size: meta.len(),
            uploaded_at: mtime_secs(&meta),
            mime: mime.to_string(),
        })
    }

    pub async fn get_path(&self, sha256: &str) -> Option<PathBuf> {
        let p = self.blob_path(sha256);
        if fs::metadata(&p).await.is_ok() {
            Some(p)
        } else {
            None
        }
    }

    pub async fn stat(&self, sha256: &str) -> Result<Option<BlobMeta>> {
        let p = self.blob_path(sha256);
        match fs::metadata(&p).await {
            Ok(meta) => Ok(Some(BlobMeta {
                sha256: sha256.to_string(),
                size: meta.len(),
                uploaded_at: mtime_secs(&meta),
                mime: String::new(),
            })),
            Err(_) => Ok(None),
        }
    }

    /// Remove a single owner's claim on a blob. The blob itself is left in place;
    /// the sweeper removes it when it expires (or when the last owner is gone and
    /// it's stale).
    pub async fn remove_owner(&self, pubkey: &str, sha256: &str) -> Result<bool> {
        let link = self.owner_link(pubkey, sha256);
        match fs::remove_file(&link).await {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    pub async fn list_for_owner(&self, pubkey: &str) -> Result<Vec<BlobMeta>> {
        let dir = self.owner_dir(pubkey);
        let mut out = Vec::new();
        let mut rd = match fs::read_dir(&dir).await {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        while let Some(entry) = rd.next_entry().await? {
            let name = entry.file_name();
            let sha = match name.to_str() {
                Some(s) if is_hex_sha256(s) => s.to_string(),
                _ => continue,
            };
            // Resolve the symlink target's real metadata.
            match fs::metadata(entry.path()).await {
                Ok(meta) => {
                    out.push(BlobMeta {
                        sha256: sha,
                        size: meta.len(),
                        uploaded_at: mtime_secs(&meta),
                        mime: String::new(),
                    });
                }
                Err(_) => {
                    // Dangling symlink — clean up opportunistically.
                    let _ = fs::remove_file(entry.path()).await;
                }
            }
        }
        Ok(out)
    }

    /// Sweep blobs older than `ttl`. Then sweep dangling owner symlinks.
    pub async fn sweep(&self, ttl: Duration) -> Result<SweepStats> {
        let mut stats = SweepStats::default();
        let cutoff = SystemTime::now() - ttl;

        let blobs_dir = self.root.join("blobs");
        let mut rd = fs::read_dir(&blobs_dir).await?;
        while let Some(entry) = rd.next_entry().await? {
            let path = entry.path();
            let meta = match fs::metadata(&path).await {
                Ok(m) => m,
                Err(_) => continue,
            };
            let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            if mtime < cutoff {
                if fs::remove_file(&path).await.is_ok() {
                    stats.blobs_deleted += 1;
                    stats.bytes_freed += meta.len();
                }
            }
        }

        let owners_dir = self.root.join("owners");
        let mut rd = match fs::read_dir(&owners_dir).await {
            Ok(rd) => rd,
            Err(_) => return Ok(stats),
        };
        while let Some(user_entry) = rd.next_entry().await? {
            let user_dir = user_entry.path();
            let mut user_rd = match fs::read_dir(&user_dir).await {
                Ok(r) => r,
                Err(_) => continue,
            };
            let mut remaining = 0u32;
            while let Some(link_entry) = user_rd.next_entry().await? {
                // metadata() (not symlink_metadata) follows the link; if the target
                // is gone, this errors and we drop the dangling link.
                if fs::metadata(link_entry.path()).await.is_err() {
                    let _ = fs::remove_file(link_entry.path()).await;
                    stats.symlinks_pruned += 1;
                } else {
                    remaining += 1;
                }
            }
            if remaining == 0 {
                let _ = fs::remove_dir(&user_dir).await;
            }
        }

        Ok(stats)
    }
}

#[derive(Debug, Default)]
pub struct SweepStats {
    pub blobs_deleted: u64,
    pub bytes_freed: u64,
    pub symlinks_pruned: u64,
}

pub fn is_hex_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Strip an optional `.ext` suffix from the URL path so `/<sha>.png` works.
pub fn parse_sha_from_path(s: &str) -> Option<String> {
    let stem = s.split('.').next()?;
    let lower = stem.to_lowercase();
    if is_hex_sha256(&lower) {
        Some(lower)
    } else {
        None
    }
}

fn mtime_secs(meta: &std::fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn touch(path: &Path) -> Result<()> {
    let now = SystemTime::now();
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let f = std::fs::OpenOptions::new().write(true).open(&path)?;
        f.set_modified(now)?;
        Ok(())
    })
    .await
    .map_err(|e| anyhow!("join: {e}"))??;
    Ok(())
}

fn touch_symlink(_path: &Path) -> Result<()> {
    // Symlink mtime is set at creation time on Linux; nothing extra needed.
    Ok(())
}

#[cfg(unix)]
async fn symlink(target: PathBuf, link: &Path) -> Result<()> {
    let link = link.to_path_buf();
    tokio::task::spawn_blocking(move || std::os::unix::fs::symlink(target, link))
        .await
        .map_err(|e| anyhow!("join: {e}"))?
        .context("creating symlink")
}

#[cfg(not(unix))]
async fn symlink(_target: PathBuf, _link: &Path) -> Result<()> {
    bail!("symlinks not supported on this platform")
}
