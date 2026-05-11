use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

use crate::ratelimit::RateLimiter;
use crate::storage::Storage;

pub fn spawn(storage: Storage, ratelimit: Arc<RateLimiter>, ttl: Duration, interval: Duration) {
    tokio::spawn(async move {
        loop {
            match storage.sweep(ttl).await {
                Ok(stats) => {
                    if stats.blobs_deleted > 0 || stats.orphans_pruned > 0 {
                        info!(
                            blobs_deleted = stats.blobs_deleted,
                            bytes_freed = stats.bytes_freed,
                            orphans_pruned = stats.orphans_pruned,
                            "sweep complete"
                        );
                    }
                }
                Err(e) => warn!("sweep failed: {e:#}"),
            }
            ratelimit.gc();
            tokio::time::sleep(interval).await;
        }
    });
}
