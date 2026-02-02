mod routes;
mod state;
mod storage;

use axum::{routing::get, Router};
use std::{net::SocketAddr, path::PathBuf};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "dos_server=debug,tower_http=info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let root = std::env::var("DOS_ROOT").unwrap_or_else(|_| "./dos_data".to_string());
    let upload_root = std::env::var("DOS_UPLOAD_ROOT").unwrap_or_else(|_| "./dos_uploads".to_string());
    let password = std::env::var("DOS_PASSWORD").unwrap_or_else(|_| "dos".to_string());

    tokio::fs::create_dir_all(&root).await?;
    tokio::fs::create_dir_all(&upload_root).await?;

    let state = AppState::new(PathBuf::from(root), PathBuf::from(upload_root), password);

    let app = Router::new()
        .route("/", get(|| async { "DOS server ok\n" }))
        .nest("/v1", routes::router(state.clone()))
        .layer(TraceLayer::new_for_http());

    let addr: SocketAddr = std::env::var("DOS_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8787".to_string())
        .parse()?;

    tracing::info!("DOS server root={:?} upload_root={:?} bind={}", state.root, state.upload_root, addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
