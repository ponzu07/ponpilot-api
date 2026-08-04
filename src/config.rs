use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: String,
    pub public_url: String,
    pub frontend_url: String,
    pub github: Option<OAuthProvider>,
}

#[derive(Debug, Clone)]
pub struct OAuthProvider {
    pub client_id: String,
    pub client_secret: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            bind: optional("BIND").unwrap_or_else(|| "0.0.0.0:8080".into()),
            public_url: required("PUBLIC_URL")?.trim_end_matches('/').to_string(),
            frontend_url: required("FRONTEND_URL")?.trim_end_matches('/').to_string(),
            github: OAuthProvider::from_env("GITHUB"),
        })
    }
}

impl OAuthProvider {
    fn from_env(prefix: &str) -> Option<Self> {
        Some(Self {
            client_id: optional(&format!("{prefix}_CLIENT_ID"))?,
            client_secret: optional(&format!("{prefix}_CLIENT_SECRET"))?,
        })
    }
}

fn optional(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

fn required(key: &str) -> Result<String> {
    optional(key).with_context(|| format!("{key} is required"))
}
