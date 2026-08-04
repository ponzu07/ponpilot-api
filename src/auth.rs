use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use axum::{
    extract::{Path, State},
    response::Redirect,
};
use rand::distr::{Alphanumeric, SampleString};
use url::Url;

use crate::{
    AppState,
    error::{Error, Result},
};

const STATE_TTL: Duration = Duration::from_secs(600);

#[derive(Default)]
pub struct StateStore(Mutex<HashMap<String, Instant>>);

impl StateStore {
    pub fn issue(&self) -> String {
        let token = Alphanumeric.sample_string(&mut rand::rng(), 32);
        let mut map = self.0.lock().unwrap();
        map.retain(|_, issued| issued.elapsed() < STATE_TTL);
        map.insert(token.clone(), Instant::now());
        token
    }

    #[allow(dead_code)]
    pub fn consume(&self, token: &str) -> bool {
        let issued = self.0.lock().unwrap().remove(token);
        issued.is_some_and(|at| at.elapsed() < STATE_TTL)
    }
}

pub async fn start(State(state): State<AppState>, Path(provider): Path<String>) -> Result<Redirect> {
    let url = match provider.as_str() {
        "h" => {
            let github = state
                .config
                .github
                .as_ref()
                .ok_or(Error::ProviderDisabled("GitHub"))?;
            let mut url = Url::parse("https://github.com/login/oauth/authorize").unwrap();
            url.query_pairs_mut()
                .append_pair("client_id", &github.client_id)
                .append_pair(
                    "redirect_uri",
                    &format!("{}/v2/auth/h/redirect/", state.config.public_url),
                )
                .append_pair("scope", "read:user")
                .append_pair("state", &state.states.issue());
            url
        }
        other => return Err(Error::UnknownProvider(other.to_string())),
    };

    Ok(Redirect::to(url.as_str()))
}
