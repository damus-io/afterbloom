use anyhow::{anyhow, Result};
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

/// Outcome of an upload attempt.
#[derive(Debug)]
pub enum PutOutcome {
    /// First upload of this blob — caller is the owner.
    Created(BlobMeta),
    /// Blob existed, caller is the existing owner — mtime was refreshed.
    Refreshed(BlobMeta),
    /// Blob existed and is owned by someone else. No claim, no mtime refresh.
    /// The returned meta describes the existing blob.
    Existing(BlobMeta),
}

impl PutOutcome {
    pub fn into_meta(self) -> BlobMeta {
        match self {
            PutOutcome::Created(m) | PutOutcome::Refreshed(m) | PutOutcome::Existing(m) => m,
        }
    }
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

    fn owner_path(&self, sha256: &str) -> PathBuf {
        self.root.join("owners").join(sha256)
    }

    /// Upload semantics (first-uploader-wins):
    /// - If the blob doesn't exist: write it, record caller as owner.
    /// - If the blob exists and the caller is its owner: refresh mtime (TTL extended).
    /// - If the blob exists and the caller is NOT the owner: no-op. The blob's
    ///   mtime is not touched and no claim is recorded. This prevents a third
    ///   party from extending someone else's TTL or being able to delete it.
    pub async fn put(&self, pubkey: &str, data: &[u8], mime: &str) -> Result<PutOutcome> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let sha256 = hex::encode(hasher.finalize());

        let final_path = self.blob_path(&sha256);
        let blob_exists = fs::metadata(&final_path).await.is_ok();

        if blob_exists {
            let owner = self.read_owner(&sha256).await?;
            // If the owner sidecar is missing (e.g. crash between blob write and
            // sidecar write) treat the existing blob as owned by the current
            // caller: backfill the sidecar and refresh mtime.
            if owner.as_deref().map_or(true, |o| o == pubkey) {
                if owner.is_none() {
                    self.write_owner(&sha256, pubkey).await?;
                }
                touch(&final_path).await?;
                let meta = self.meta_for(&sha256, mime).await?;
                return Ok(PutOutcome::Refreshed(meta));
            }
            let meta = self.meta_for(&sha256, mime).await?;
            return Ok(PutOutcome::Existing(meta));
        }

        let tmp = self.root.join("tmp").join(format!("{sha256}.partial"));
        let mut f = fs::File::create(&tmp).await?;
        f.write_all(data).await?;
        f.sync_all().await?;
        drop(f);
        fs::rename(&tmp, &final_path).await?;

        self.write_owner(&sha256, pubkey).await?;

        let meta = self.meta_for(&sha256, mime).await?;
        Ok(PutOutcome::Created(meta))
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

    /// Result of a delete attempt.
    pub async fn remove(&self, pubkey: &str, sha256: &str) -> Result<RemoveOutcome> {
        let owner = self.read_owner(sha256).await?;
        match owner {
            None => {
                // No owner sidecar. If the blob doesn't exist either, treat as
                // not-found. If the blob exists but has no owner record, refuse
                // to delete — we can't authorize.
                if fs::metadata(self.blob_path(sha256)).await.is_ok() {
                    Ok(RemoveOutcome::Forbidden)
                } else {
                    Ok(RemoveOutcome::NotFound)
                }
            }
            Some(o) if o == pubkey => {
                let _ = fs::remove_file(self.blob_path(sha256)).await;
                let _ = fs::remove_file(self.owner_path(sha256)).await;
                Ok(RemoveOutcome::Removed)
            }
            Some(_) => Ok(RemoveOutcome::Forbidden),
        }
    }

    /// Sweep blobs older than `ttl`, removing the owner sidecar alongside.
    /// Also cleans up any orphan sidecars whose blobs are already gone.
    pub async fn sweep(&self, ttl: Duration) -> Result<SweepStats> {
        let mut stats = SweepStats::default();
        let cutoff = SystemTime::now() - ttl;

        let blobs_dir = self.root.join("blobs");
        let mut rd = fs::read_dir(&blobs_dir).await?;
        while let Some(entry) = rd.next_entry().await? {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !is_hex_sha256(name) {
                continue;
            }
            let meta = match fs::metadata(&path).await {
                Ok(m) => m,
                Err(_) => continue,
            };
            let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            if mtime < cutoff && fs::remove_file(&path).await.is_ok() {
                stats.blobs_deleted += 1;
                stats.bytes_freed += meta.len();
                let _ = fs::remove_file(self.owner_path(name)).await;
            }
        }

        // Orphan sidecars (blob gone but sidecar lingered — e.g. crash between
        // the two unlinks above).
        let owners_dir = self.root.join("owners");
        if let Ok(mut rd) = fs::read_dir(&owners_dir).await {
            while let Some(entry) = rd.next_entry().await? {
                let path = entry.path();
                let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                if !is_hex_sha256(name) {
                    continue;
                }
                if fs::metadata(self.blob_path(name)).await.is_err() {
                    let _ = fs::remove_file(&path).await;
                    stats.orphans_pruned += 1;
                }
            }
        }

        Ok(stats)
    }

    async fn read_owner(&self, sha256: &str) -> Result<Option<String>> {
        match fs::read_to_string(self.owner_path(sha256)).await {
            Ok(s) => {
                let trimmed = s.trim();
                if is_hex_pubkey(trimmed) {
                    Ok(Some(trimmed.to_string()))
                } else {
                    Ok(None)
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn write_owner(&self, sha256: &str, pubkey: &str) -> Result<()> {
        let path = self.owner_path(sha256);
        // Atomic-ish: write to tmp then rename. Owners dir is created at open().
        let tmp = self
            .root
            .join("tmp")
            .join(format!("{sha256}.owner.partial"));
        let mut f = fs::File::create(&tmp).await?;
        f.write_all(pubkey.as_bytes()).await?;
        f.write_all(b"\n").await?;
        f.sync_all().await?;
        drop(f);
        fs::rename(&tmp, &path).await?;
        Ok(())
    }

    async fn meta_for(&self, sha256: &str, mime: &str) -> Result<BlobMeta> {
        let meta = fs::metadata(self.blob_path(sha256)).await?;
        Ok(BlobMeta {
            sha256: sha256.to_string(),
            size: meta.len(),
            uploaded_at: mtime_secs(&meta),
            mime: mime.to_string(),
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum RemoveOutcome {
    Removed,
    Forbidden,
    NotFound,
}

#[derive(Debug, Default)]
pub struct SweepStats {
    pub blobs_deleted: u64,
    pub bytes_freed: u64,
    pub orphans_pruned: u64,
}

pub fn is_hex_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_hex_pubkey(s: &str) -> bool {
    is_hex_sha256(s)
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
