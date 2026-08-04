use axum::{
    Form, Json,
    extract::{Path, Query, State},
    http::{HeaderMap, header},
    response::{IntoResponse, Redirect},
};
use rand::distr::{Alphanumeric, SampleString};
use serde::Deserialize;
use serde_json::{Value, json};
use url::{Url, form_urlencoded};

use crate::{
    AppState, db,
    error::{Error, Result},
    token,
};

const STATE_COOKIE: &str = "__Host-oauth_state";

fn set_state(value: &str, max_age: u32) -> [(header::HeaderName, String); 1] {
    [(
        header::SET_COOKIE,
        format!(
            "{STATE_COOKIE}={value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={max_age}"
        ),
    )]
}

fn issued_state(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|c| {
            c.trim()
                .strip_prefix(STATE_COOKIE)
                .and_then(|v| v.strip_prefix('='))
        })
}

pub async fn start(
    State(app): State<AppState>,
    Path(provider): Path<String>,
) -> Result<impl IntoResponse> {
    if provider != "h" {
        return Err(Error::UnknownProvider);
    }
    let github = app.config.github.as_ref().ok_or(Error::ProviderDisabled)?;

    let state = Alphanumeric.sample_string(&mut rand::rng(), 32);
    let mut url = Url::parse("https://github.com/login/oauth/authorize").unwrap();
    url.query_pairs_mut()
        .append_pair("client_id", &github.client_id)
        .append_pair(
            "redirect_uri",
            &format!("{}/v2/auth/h/redirect/", app.config.public_url),
        )
        .append_pair("scope", "read:user")
        .append_pair("state", &state);

    Ok((set_state(&state, 600), Redirect::to(url.as_str())))
}

#[derive(Deserialize)]
pub struct Callback {
    code: Option<String>,
    state: String,
}

pub async fn callback(
    State(app): State<AppState>,
    Path(provider): Path<String>,
    headers: HeaderMap,
    Query(params): Query<Callback>,
) -> Result<impl IntoResponse> {
    if provider != "h" {
        return Err(Error::UnknownProvider);
    }
    if issued_state(&headers) != Some(params.state.as_str()) {
        return Err(Error::InvalidState);
    }

    let target = match params.code {
        Some(code) => {
            let query = form_urlencoded::Serializer::new(String::new())
                .append_pair("code", &code)
                .append_pair("provider", &provider)
                .finish();
            format!("{}/auth/?{query}", app.config.frontend_url)
        }
        None => app.config.frontend_url.clone(),
    };
    Ok((set_state("", 0), Redirect::to(&target)))
}

#[derive(Deserialize)]
pub struct Exchange {
    code: String,
    provider: String,
}

pub async fn exchange(
    State(app): State<AppState>,
    Form(params): Form<Exchange>,
) -> Result<Json<Value>> {
    if params.provider != "h" {
        return Err(Error::UnknownProvider);
    }
    let github = app.config.github.as_ref().ok_or(Error::ProviderDisabled)?;

    let body = app
        .http
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .form(&[
            ("client_id", github.client_id.as_str()),
            ("client_secret", github.client_secret.as_str()),
            ("code", params.code.as_str()),
        ])
        .send()
        .await
        .map_err(anyhow::Error::from)?
        .text()
        .await
        .map_err(anyhow::Error::from)?;
    let token: GithubToken = serde_json::from_str(&body).map_err(|_| {
        tracing::warn!("github token exchange failed: {body}");
        Error::ExchangeFailed
    })?;

    let user: GithubUser = app
        .http
        .get("https://api.github.com/user")
        .header("Authorization", format!("Bearer {}", token.access_token))
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(anyhow::Error::from)?
        .json()
        .await
        .map_err(|_| Error::ExchangeFailed)?;

    let identity = format!("github_{}", user.id);
    db::upsert_user(&app.db, &identity, &user.login).await?;

    let access_token =
        token::issue(&app.config.jwt_secret, &identity).map_err(anyhow::Error::from)?;
    Ok(Json(json!({ "access_token": access_token })))
}

#[derive(Deserialize)]
struct GithubToken {
    access_token: String,
}

#[derive(Deserialize)]
struct GithubUser {
    id: u64,
    login: String,
}
