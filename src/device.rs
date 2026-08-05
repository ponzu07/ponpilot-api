use axum::{
    Form, Json,
    extract::{Path, State},
    http::{HeaderMap, header},
};
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, dangerous::insecure_decode, decode, get_current_timestamp,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::SqlitePool;

use crate::{
    AppState,
    error::{Error, Result},
    token,
    user::CurrentUser,
};

/// デバイスが自分の鍵で好きな寿命を書けるので、サーバー側で上限を切る。
const MAX_TTL: u64 = 24 * 60 * 60;

#[derive(Deserialize)]
pub struct DeviceClaims {
    pub identity: String,
    pub exp: u64,
    #[serde(default)]
    pub pair: bool,
}

pub fn peek(jwt: &str) -> Result<DeviceClaims> {
    insecure_decode::<DeviceClaims>(jwt)
        .map(|d| d.claims)
        .map_err(|_| Error::Unauthorized)
}

/// alg は JWT ヘッダではなく保存済み PEM の鍵種から導く。
pub fn verify(pem: &str, jwt: &str) -> Result<DeviceClaims> {
    let (key, alg) = match DecodingKey::from_rsa_pem(pem.as_bytes()) {
        Ok(k) => (k, Algorithm::RS256),
        Err(_) => (
            DecodingKey::from_ec_pem(pem.as_bytes()).map_err(|_| Error::Unauthorized)?,
            Algorithm::ES256,
        ),
    };
    let claims = decode::<DeviceClaims>(jwt, &key, &Validation::new(alg))
        .map_err(|_| Error::Unauthorized)?
        .claims;
    if claims.exp > get_current_timestamp() + MAX_TTL {
        return Err(Error::Unauthorized);
    }
    Ok(claims)
}

pub fn valid_dongle_id(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[derive(sqlx::FromRow)]
pub struct Device {
    dongle_id: String,
    pub public_key: String,
    pub owner_id: Option<i64>,
    last_athena_ping: Option<i64>,
    openpilot_version: Option<String>,
}

pub async fn find(db: &SqlitePool, dongle_id: &str) -> Result<Option<Device>> {
    Ok(sqlx::query_as(
        "SELECT dongle_id, public_key, owner_id, last_athena_ping, openpilot_version
         FROM devices WHERE dongle_id = ?1",
    )
    .bind(dongle_id)
    .fetch_optional(db)
    .await
    .map_err(anyhow::Error::from)?)
}

pub async fn owned(db: &SqlitePool, dongle_id: &str, user_id: i64) -> Result<bool> {
    Ok(find(db, dongle_id).await?.and_then(|d| d.owner_id) == Some(user_id))
}

impl Device {
    fn json(&self, viewer: Option<i64>) -> Value {
        json!({
            "dongle_id": self.dongle_id,
            "alias": null,
            // 欠けると connect が "comma undefined" と表示する（`utils/index.js:53-59`）。
            "device_type": "unknown",
            "is_owner": viewer.is_some() && viewer == self.owner_id,
            "shared": false,
            "prime": true,
            "prime_type": 0,
            "is_paired": self.owner_id.is_some(),
            "last_athena_ping": self.last_athena_ping,
            "openpilot_version": self.openpilot_version,
        })
    }
}

pub async fn list(State(app): State<AppState>, user: CurrentUser) -> Result<Json<Value>> {
    let rows: Vec<Device> = sqlx::query_as(
        "SELECT dongle_id, public_key, owner_id, last_athena_ping, openpilot_version
         FROM devices WHERE owner_id = ?1",
    )
    .bind(user.id)
    .fetch_all(&app.db)
    .await
    .map_err(anyhow::Error::from)?;
    Ok(Json(Value::Array(
        rows.iter().map(|d| d.json(Some(user.id))).collect(),
    )))
}

pub async fn get(
    State(app): State<AppState>,
    Path(dongle_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>> {
    let jwt = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("JWT "))
        .ok_or(Error::Unauthorized)?;
    let device = find(&app.db, &dongle_id).await?.ok_or(Error::NotFound)?;

    match token::verify(&app.config.jwt_secret, jwt) {
        Ok(user) => {
            let (id, _) = crate::db::find_user(&app.db, &user.identity)
                .await?
                .ok_or(Error::Unauthorized)?;
            // 他人のデバイスに 401 を返すとフロントが強制ログアウトする
            if device.owner_id != Some(id) {
                return Err(Error::NotFound);
            }
            Ok(Json(device.json(Some(id))))
        }
        Err(_) => {
            let claims = verify(&device.public_key, jwt)?;
            if claims.identity != dongle_id {
                return Err(Error::Unauthorized);
            }
            Ok(Json(device.json(None)))
        }
    }
}

#[derive(Deserialize)]
pub struct PairForm {
    pair_token: String,
}

pub async fn pilotpair(
    State(app): State<AppState>,
    user: CurrentUser,
    Form(form): Form<PairForm>,
) -> Result<Json<Value>> {
    let dongle_id = peek(&form.pair_token)
        .map_err(|_| Error::Forbidden)?
        .identity;
    let device = find(&app.db, &dongle_id).await?.ok_or(Error::NotFound)?;
    let claims = verify(&device.public_key, &form.pair_token).map_err(|_| Error::Forbidden)?;
    if !claims.pair {
        return Err(Error::Forbidden);
    }
    let updated = sqlx::query(
        "UPDATE devices SET owner_id = ?2
         WHERE dongle_id = ?1 AND (owner_id IS NULL OR owner_id = ?2)",
    )
    .bind(&dongle_id)
    .bind(user.id)
    .execute(&app.db)
    .await
    .map_err(anyhow::Error::from)?
    .rows_affected();
    if updated == 0 {
        return Err(Error::Forbidden);
    }
    Ok(Json(json!({ "dongle_id": dongle_id })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, encode};

    const EC_A: &str = include_str!("../tests/keys/ec_a.pem");
    const EC_A_PUB: &str = include_str!("../tests/keys/ec_a.pub.pem");
    const EC_B: &str = include_str!("../tests/keys/ec_b.pem");
    const RSA: &str = include_str!("../tests/keys/rsa.pem");
    const RSA_PUB: &str = include_str!("../tests/keys/rsa.pub.pem");

    fn sign(alg: Algorithm, pem: &str, claims: Value) -> String {
        let key = match alg {
            Algorithm::RS256 => EncodingKey::from_rsa_pem(pem.as_bytes()),
            _ => EncodingKey::from_ec_pem(pem.as_bytes()),
        }
        .unwrap();
        encode(&Header::new(alg), &claims, &key).unwrap()
    }

    fn claims() -> Value {
        let now = get_current_timestamp();
        json!({ "identity": "1d3dc3e03047b0c7", "nbf": now, "iat": now, "exp": now + 3600 })
    }

    #[test]
    fn rejects_token_signed_by_another_key() {
        let good = sign(Algorithm::ES256, EC_A, claims());
        assert_eq!(
            verify(EC_A_PUB, &good).unwrap().identity,
            "1d3dc3e03047b0c7"
        );

        let evil = sign(Algorithm::ES256, EC_B, claims());
        assert!(verify(EC_A_PUB, &evil).is_err(), "別の鍵の署名は通らない");
    }

    #[test]
    fn rejects_algorithm_confusion() {
        let hs = encode(
            &Header::new(Algorithm::HS256),
            &claims(),
            &EncodingKey::from_secret(RSA_PUB.as_bytes()),
        )
        .unwrap();
        assert!(verify(RSA_PUB, &hs).is_err(), "HS* は受理しない");

        assert!(verify(RSA_PUB, &sign(Algorithm::ES256, EC_A, claims())).is_err());
        assert!(verify(EC_A_PUB, &sign(Algorithm::RS256, RSA, claims())).is_err());
    }

    #[test]
    fn rejects_absurd_lifetime() {
        let mut c = claims();
        c["exp"] = json!(get_current_timestamp() + 10 * 365 * 24 * 3600);
        assert!(verify(EC_A_PUB, &sign(Algorithm::ES256, EC_A, c)).is_err());
    }

    #[test]
    fn user_token_is_not_a_device_token() {
        let secret = "x".repeat(32);
        assert!(verify(EC_A_PUB, &token::issue(&secret, "github_42").unwrap()).is_err());
        assert!(token::verify(&secret, &sign(Algorithm::ES256, EC_A, claims())).is_err());
    }
}
