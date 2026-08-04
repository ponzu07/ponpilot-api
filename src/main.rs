mod auth;
mod config;
mod db;
mod error;
mod token;

use std::sync::Arc;

use anyhow::Result;
use axum::{
    Router,
    http::{HeaderValue, Method, header},
    routing::{get, post},
};
use config::Config;
use sqlx::SqlitePool;
use tower_http::{cors::CorsLayer, trace::TraceLayer};

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    db: SqlitePool,
    http: reqwest::Client,
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
    let cors = CorsLayer::new()
        .allow_origin(config.frontend_url.parse::<HeaderValue>()?)
        .allow_methods([Method::GET, Method::POST, Method::PATCH, Method::DELETE])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]);
    let state = AppState {
        db: db::connect(&config.database).await?,
        http: reqwest::Client::builder()
            .user_agent(concat!("ponpilot-api/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(10))
            .build()?,
        config: Arc::new(config),
    };

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/v2/auth/", post(auth::exchange))
        .route("/v2/auth/{provider}/", get(auth::start))
        .route("/v2/auth/{provider}/redirect/", get(auth::callback))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!("listening on {bind}");
    axum::serve(listener, app).await?;
    Ok(())
}
