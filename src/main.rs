mod auth;
mod config;
mod error;

use std::sync::Arc;

use anyhow::Result;
use axum::{Router, routing::get};
use config::Config;
use tower_http::trace::TraceLayer;

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    states: Arc<auth::StateStore>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ponpilot_api=info,tower_http=info".into()),
        )
        .init();

    let config = Config::from_env()?;
    let bind = config.bind.clone();
    let state = AppState {
        config: Arc::new(config),
        states: Arc::new(auth::StateStore::default()),
    };

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/v2/auth/{provider}/", get(auth::start))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!("listening on {bind}");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}

async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}
