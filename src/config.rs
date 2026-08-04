use anyhow::{Context, Result};

pub struct Config {
    pub bind: String,
    pub public_url: String,
    pub frontend_url: String,
    pub database: String,
    pub jwt_secret: String,
    pub github: Option<OAuthProvider>,
}

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
            database: optional("DATABASE").unwrap_or_else(|| "/data/ponpilot.sqlite3".into()),
            jwt_secret: {
                let s = required("JWT_SECRET")?;
                anyhow::ensure!(s.len() >= 32, "JWT_SECRET must be at least 32 bytes");
                s
            },
            github: match (optional("GITHUB_CLIENT_ID"), optional("GITHUB_CLIENT_SECRET")) {
                (Some(client_id), Some(client_secret)) => Some(OAuthProvider {
                    client_id,
                    client_secret,
                }),
                _ => None,
            },
        })
    }
}

fn optional(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

fn required(key: &str) -> Result<String> {
    optional(key).with_context(|| format!("{key} is required"))
}
