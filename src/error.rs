use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error("too many requests")]
    TooManyRequests,
    #[error("unknown provider")]
    UnknownProvider,
    #[error("provider is not configured")]
    ProviderDisabled,
    #[error("invalid or expired state")]
    InvalidState,
    #[error("could not exchange authorization code")]
    ExchangeFailed,
    #[error("internal error")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status = match self {
            Error::Unauthorized => StatusCode::UNAUTHORIZED,
            Error::Forbidden => StatusCode::FORBIDDEN,
            Error::NotFound | Error::UnknownProvider => StatusCode::NOT_FOUND,
            Error::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            Error::ProviderDisabled | Error::InvalidState | Error::ExchangeFailed => {
                StatusCode::BAD_REQUEST
            }
            Error::Internal(ref e) => {
                tracing::error!("{e:#}");
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        (status, Json(json!({ "error": self.to_string() }))).into_response()
    }
}

pub type Result<T> = std::result::Result<T, Error>;
