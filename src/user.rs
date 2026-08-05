use axum::{
    Json,
    extract::{FromRequestParts, OptionalFromRequestParts, State},
    http::{header, request::Parts},
};
use serde_json::{Value, json};

use crate::{
    AppState, db,
    error::{Error, Result},
    token,
};

pub struct CurrentUser {
    pub id: i64,
    pub identity: String,
    pub username: String,
}

impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, app: &AppState) -> Result<Self> {
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("JWT "))
            .ok_or(Error::Unauthorized)?;
        let identity = token::verify(&app.config.jwt_secret, token)
            .map_err(|_| Error::Unauthorized)?
            .identity;
        let (id, username) = db::find_user(&app.db, &identity)
            .await?
            .ok_or(Error::Unauthorized)?;
        Ok(Self {
            id,
            identity,
            username,
        })
    }
}

impl OptionalFromRequestParts<AppState> for CurrentUser {
    type Rejection = Error;

    /// トークンが無いときだけ匿名。壊れたトークンは 401 のまま。
    async fn from_request_parts(parts: &mut Parts, app: &AppState) -> Result<Option<Self>> {
        if !parts.headers.contains_key(header::AUTHORIZATION) {
            return Ok(None);
        }
        <Self as FromRequestParts<AppState>>::from_request_parts(parts, app)
            .await
            .map(Some)
    }
}

pub async fn me(State(app): State<AppState>, user: CurrentUser) -> Json<Value> {
    Json(json!({
        "id": user.id,
        "user_id": user.identity,
        "email": user.username,
        "superuser": app.config.is_superuser(&user.identity),
        "prime": true,
    }))
}
