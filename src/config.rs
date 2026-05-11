use anyhow::{Context, Result};
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub listen: SocketAddr,
    pub storage_dir: PathBuf,
    pub public_url: String,

    #[serde(default = "default_ttl")]
    pub ttl_seconds: u64,

    #[serde(default = "default_sweep_interval")]
    pub sweep_interval_seconds: u64,

    #[serde(default = "default_max_upload")]
    pub max_upload_bytes: u64,

    #[serde(default = "default_max_auth_lifetime")]
    pub max_auth_lifetime_seconds: u64,

    #[serde(default)]
    pub ratelimit: RateLimitConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    #[serde(default = "default_uploads_burst")]
    pub uploads_burst: u32,

    #[serde(default = "default_uploads_refill")]
    pub uploads_refill_per_minute: u32,

    #[serde(default = "default_bytes_per_hour")]
    pub bytes_per_hour: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            uploads_burst: default_uploads_burst(),
            uploads_refill_per_minute: default_uploads_refill(),
            bytes_per_hour: default_bytes_per_hour(),
        }
    }
}

fn default_ttl() -> u64 { 86400 }
fn default_sweep_interval() -> u64 { 300 }
fn default_max_upload() -> u64 { 100 * 1024 * 1024 }
fn default_max_auth_lifetime() -> u64 { 3600 }
fn default_uploads_burst() -> u32 { 10 }
fn default_uploads_refill() -> u32 { 10 }
fn default_bytes_per_hour() -> u64 { 1024 * 1024 * 1024 }

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        toml::from_str(&raw).context("parsing config")
    }
}
