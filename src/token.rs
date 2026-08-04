use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

const TTL_SECS: u64 = 60 * 60 * 24 * 365;

#[derive(Serialize, Deserialize)]
pub struct UserClaims {
    pub identity: String,
    pub exp: u64,
}

pub fn issue(secret: &str, identity: &str) -> jsonwebtoken::errors::Result<String> {
    let claims = UserClaims {
        identity: identity.to_string(),
        exp: std::time::UNIX_EPOCH.elapsed().unwrap().as_secs() + TTL_SECS,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
}

#[allow(dead_code)]
pub fn verify(secret: &str, token: &str) -> jsonwebtoken::errors::Result<UserClaims> {
    decode::<UserClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map(|d| d.claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_reject_wrong_secret() {
        let t = issue("s3cret", "github_42").unwrap();
        assert_eq!(verify("s3cret", &t).unwrap().identity, "github_42");
        assert!(verify("other", &t).is_err(), "別の鍵では検証が通らない");
    }
}
