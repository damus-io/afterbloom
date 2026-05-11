mod auth;
mod config;
mod ratelimit;
mod routes;
mod state;
mod storage;
mod sweep;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, put};
use axum::Router;
use clap::Parser;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::ratelimit::RateLimiter;
use crate::state::AppState;
use crate::storage::Storage;

#[derive(Parser)]
#[command(version, about = "Minimal Blossom server for transient blobs")]
struct Args {
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let cfg = Config::load(&args.config)?;
    tracing::info!(?cfg.listen, ttl_seconds = cfg.ttl_seconds, "starting afterbloom");

    let storage = Storage::open(&cfg.storage_dir).await?;
    let ratelimit = Arc::new(RateLimiter::new(cfg.ratelimit.clone()));

    sweep::spawn(
        storage.clone(),
        ratelimit.clone(),
        Duration::from_secs(cfg.ttl_seconds),
        Duration::from_secs(cfg.sweep_interval_seconds),
    );

    let max_upload = cfg.max_upload_bytes as usize;
    let listen = cfg.listen;

    let state = Arc::new(AppState { cfg, storage, ratelimit });

    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_origin(Any)
        .expose_headers(Any);

    let app = Router::new()
        .route("/upload", put(routes::upload).head(routes::upload_head))
        .route("/list/:pubkey", get(routes::list_owner))
        .route("/:hash", get(routes::get_blob).head(routes::head_blob).delete(routes::delete_blob))
        .layer(DefaultBodyLimit::max(max_upload))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!("listening on http://{listen}");
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;

    Ok(())
}
