use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unknown provider: {0}")]
    UnknownProvider(String),
    #[error("{0} auth is not configured")]
    ProviderDisabled(&'static str),
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status = match self {
            Error::UnknownProvider(_) => StatusCode::NOT_FOUND,
            Error::ProviderDisabled(_) => StatusCode::BAD_REQUEST,
        };
        (status, Json(json!({ "error": self.to_string() }))).into_response()
    }
}

pub type Result<T> = std::result::Result<T, Error>;
