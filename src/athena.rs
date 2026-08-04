use std::time::Duration;

use axum::{
    extract::{
        Path, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, header},
    response::Response,
};
use serde_json::{Value, json};

use crate::{
    AppState, device,
    error::{Error, Result},
};

/// デバイスは 70 秒 ping が来ないと切断する（`athenad.py:49`）。
const PING_INTERVAL: Duration = Duration::from_secs(30);
const TOFU_TIMEOUT: Duration = Duration::from_secs(20);
/// 未認証のまま TOFU 中のクライアントに 64MiB（tungstenite 既定）を確保させない。
const MAX_MESSAGE: usize = 1 << 20;

pub async fn ws(
    State(app): State<AppState>,
    Path(dongle_id): Path<String>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Result<Response> {
    if !device::valid_dongle_id(&dongle_id) {
        return Err(Error::Unauthorized);
    }
    let jwt = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').find_map(|c| c.trim().strip_prefix("jwt=")))
        .ok_or(Error::Unauthorized)?
        .to_string();
    if device::peek(&jwt)?.identity != dongle_id {
        return Err(Error::Unauthorized);
    }

    // 101 を返してから閉じるとデバイスの backoff が 0 になる（`athenad.py:785`）。
    let tofu = match device::find(&app.db, &dongle_id).await? {
        Some(d) => {
            device::verify(&d.public_key, &jwt)?;
            None
        }
        None => Some(jwt),
    };
    Ok(upgrade
        .max_message_size(MAX_MESSAGE)
        .on_upgrade(move |s| pump(s, app, dongle_id, tofu)))
}

async fn pump(mut socket: WebSocket, app: AppState, dongle_id: String, tofu: Option<String>) {
    if let Some(jwt) = tofu {
        // 衝突 = 他の接続が先に登録した。その鍵で検証していないので ping ループに入れない。
        let registered = match trust_on_first_use(&mut socket, &dongle_id, &jwt).await {
            Some(pem) => sqlx::query("INSERT INTO devices (dongle_id, public_key) VALUES (?1, ?2)")
                .bind(&dongle_id)
                .bind(&pem)
                .execute(&app.db)
                .await
                .is_ok(),
            None => false,
        };
        if !registered {
            // 即閉じると上記のホットループになる。
            tokio::time::sleep(TOFU_TIMEOUT).await;
            return;
        }
        tracing::info!("registered device {dongle_id}");
    }

    let mut ping = tokio::time::interval(PING_INTERVAL);
    let mut alive = true;
    loop {
        tokio::select! {
            msg = socket.recv() => match msg {
                Some(Ok(_)) => alive = true,
                _ => break,
            },
            _ = ping.tick() => {
                // デバイスは PING に必ず pong を返す（`_core.py:466`）。
                if !std::mem::take(&mut alive) {
                    break;
                }
                if socket.send(Message::Ping(Default::default())).await.is_err() {
                    break;
                }
                let _ = sqlx::query("UPDATE devices SET last_athena_ping = unixepoch() WHERE dongle_id = ?1")
                    .bind(&dongle_id)
                    .execute(&app.db)
                    .await;
            }
        }
    }
}

async fn trust_on_first_use(socket: &mut WebSocket, dongle_id: &str, jwt: &str) -> Option<String> {
    let call = json!({ "jsonrpc": "2.0", "id": "tofu", "method": "getPublicKey" });
    socket
        .send(Message::Text(call.to_string().into()))
        .await
        .ok()?;

    let deadline = tokio::time::Instant::now() + TOFU_TIMEOUT;
    loop {
        let msg = tokio::time::timeout_at(deadline, socket.recv())
            .await
            .ok()??
            .ok()?;
        let Message::Text(text) = msg else { continue };
        let Ok(resp) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        if resp["id"] != "tofu" {
            continue;
        }
        let pem = resp["result"].as_str()?.trim();
        let claims = device::verify(pem, jwt).ok()?;
        return (claims.identity == dongle_id).then(|| pem.to_string());
    }
}
