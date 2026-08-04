use std::collections::HashSet;

use anyhow::{Context, Result};

pub struct Config {
    pub bind: String,
    pub public_url: String,
    pub frontend_url: String,
    pub database: String,
    pub jwt_secret: String,
    superusers: HashSet<String>,
    pub github: Option<OAuthProvider>,
    pub storage: Option<Storage>,
}

pub struct OAuthProvider {
    pub client_id: String,
    pub client_secret: String,
}

pub struct Storage {
    pub endpoint: String,
    pub bucket: String,
    pub access_key: String,
    pub secret_key: String,
    pub region: String,
}

impl Storage {
    fn from_env() -> Option<Self> {
        Some(Self {
            endpoint: optional("STORAGE_ENDPOINT")?
                .trim_end_matches('/')
                .to_string(),
            bucket: optional("STORAGE_BUCKET")?,
            access_key: optional("STORAGE_ACCESS_KEY")?,
            secret_key: optional("STORAGE_SECRET_KEY")?,
            region: optional("STORAGE_REGION").unwrap_or_else(|| "us-east-1".into()),
        })
    }
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
            superusers: optional("SUPERUSERS")
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
            github: match (
                optional("GITHUB_CLIENT_ID"),
                optional("GITHUB_CLIENT_SECRET"),
            ) {
                (Some(client_id), Some(client_secret)) => Some(OAuthProvider {
                    client_id,
                    client_secret,
                }),
                _ => None,
            },
            storage: Storage::from_env(),
        })
    }
}

impl Config {
    pub fn is_superuser(&self, identity: &str) -> bool {
        self.superusers.contains(identity)
    }
}

fn optional(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

fn required(key: &str) -> Result<String> {
    optional(key).with_context(|| format!("{key} is required"))
}
