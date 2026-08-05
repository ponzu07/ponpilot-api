mod athena;
mod auth;
mod config;
mod db;
mod device;
mod error;
mod qlog;
mod route;
mod rpc;
mod sigv4;
mod token;
mod user;

use std::sync::Arc;

use anyhow::Result;
use axum::{
    Router,
    http::{HeaderValue, Method, header},
    routing::{get, patch, post},
};
use config::Config;
use sqlx::SqlitePool;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing_subscriber::{filter::Targets, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    db: SqlitePool,
    http: reqwest::Client,
    peers: rpc::Peers,
    tofu: athena::Tofu,
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter = std::env::var("RUST_LOG")
        .ok()
        .and_then(|s| s.parse::<Targets>().ok())
        .unwrap_or_else(|| "ponpilot_api=info,tower_http=info".parse().unwrap());
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(filter)
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
        peers: Default::default(),
        tofu: Arc::new(tokio::sync::Semaphore::new(athena::MAX_TOFU)),
    };

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/v1/me/", get(user::me))
        .route("/v1/me/devices/", get(device::list))
        .route(
            "/v1.1/devices/{dongle_id}",
            get(device::get).delete(device::remove),
        )
        .route("/v1.1/devices/{dongle_id}/", get(device::get))
        .route("/v1.1/devices/{dongle_id}/stats", get(route::stats))
        .route("/v1/devices/{dongle_id}/", patch(device::set_alias))
        .route("/v1/devices/{dongle_id}/unpair", post(device::unpair))
        .route("/v2/pilotpair/", post(device::pilotpair))
        .route("/v1.4/{dongle_id}/upload_url/", get(route::upload_url))
        .route(
            "/v1/devices/{dongle_id}/routes_segments",
            get(route::routes_segments),
        )
        .route("/v1/route/{route_name}/", patch(route::set_public))
        .route("/v1/route/{route_name}/files", get(route::files))
        .route(
            "/v1/route/{route_name}/qcamera.m3u8",
            get(route::qcamera_m3u8),
        )
        .route(
            "/v1/segments/{tok}/{d}/{route}/{seg}/{file}",
            get(route::segment_file),
        )
        .route("/ws/v2/{dongle_id}", get(athena::ws))
        .route("/v2/auth/", post(auth::exchange))
        .route("/v2/auth/{provider}/", get(auth::start))
        .route("/v2/auth/{provider}/redirect/", get(auth::callback))
        .route("/{dongle_id}", post(rpc::relay))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!("listening on {bind}");
    axum::serve(listener, app).await?;
    Ok(())
}
