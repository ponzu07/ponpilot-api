use std::{collections::HashMap, sync::Arc, time::Duration};

use axum::{
    extract::{
        Path, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, header},
    response::Response,
};
use serde_json::{Value, json};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};

use crate::{
    AppState, device,
    error::{Error, Result},
};

/// デバイスは 70 秒 ping が来ないと切断する（`athenad.py:49`）。
const PING_INTERVAL: Duration = Duration::from_secs(30);
const TOFU_TIMEOUT: Duration = Duration::from_secs(20);
/// 未認証のまま TOFU 中のクライアントに 64MiB（tungstenite 既定）を確保させない。
const MAX_MESSAGE: usize = 1 << 20;
const MAX_RESPONSE: usize = 16 << 20;
pub const MAX_TOFU: usize = 64;
pub const MAX_DEVICES: i64 = 1000;

pub type Tofu = Arc<Semaphore>;

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
        None => Some((
            jwt,
            app.tofu
                .clone()
                .try_acquire_owned()
                .map_err(|_| Error::TooManyRequests)?,
        )),
    };
    Ok(upgrade
        .max_message_size(if tofu.is_some() {
            MAX_MESSAGE
        } else {
            MAX_RESPONSE
        })
        .on_upgrade(move |s| pump(s, app, dongle_id, tofu)))
}

async fn pump(
    mut socket: WebSocket,
    app: AppState,
    dongle_id: String,
    tofu: Option<(String, OwnedSemaphorePermit)>,
) {
    if let Some((jwt, slot)) = tofu {
        // 衝突 = 他の接続が先に登録した。その鍵で検証していないので ping ループに入れない。
        let registered = match trust_on_first_use(&mut socket, &dongle_id, &jwt).await {
            Some(pem) => sqlx::query(
                "INSERT INTO devices (dongle_id, public_key)
                 SELECT ?1, ?2 WHERE (SELECT count(*) FROM devices) < ?3",
            )
            .bind(&dongle_id)
            .bind(&pem)
            .bind(MAX_DEVICES)
            .execute(&app.db)
            .await
            .map(|r| r.rows_affected() == 1)
            .unwrap_or(false),
            None => false,
        };
        if !registered {
            // 即閉じると上記のホットループになる。ペナルティ中は枠を返す。
            drop(slot);
            tokio::time::sleep(TOFU_TIMEOUT).await;
            return;
        }
        tracing::info!("registered device {dongle_id}");
    }

    let (tx, mut rx) = mpsc::channel(8);
    app.peers.lock().unwrap().insert(dongle_id.clone(), tx);
    let mut pending: HashMap<u64, oneshot::Sender<Value>> = HashMap::new();

    let probe = json!({ "jsonrpc": "2.0", "id": "version", "method": "getVersion" });
    let _ = socket.send(Message::Text(probe.to_string().into())).await;

    let mut ping = tokio::time::interval(PING_INTERVAL);
    let mut alive = true;
    let mut probed = false;
    loop {
        tokio::select! {
            msg = socket.recv() => match msg {
                Some(Ok(msg)) => {
                    alive = true;
                    if let Message::Text(t) = msg
                        && let Ok(resp) = serde_json::from_str::<Value>(&t)
                    {
                        match resp["id"].as_u64() {
                            Some(id) => {
                                if let Some(reply) = pending.remove(&id) {
                                    let _ = reply.send(resp);
                                }
                            }
                            // 応答しないと1ファイルにつき100秒ブロックし、同じログを再送し続ける。
                            None if resp["method"] == "forwardLogs" => {
                                let ack = json!({ "jsonrpc": "2.0", "id": resp["id"], "result": { "success": 1 } });
                                if socket.send(Message::Text(ack.to_string().into())).await.is_err() {
                                    break;
                                }
                            }
                            None => if !probed
                                && resp["id"] == "version"
                                && let Some(v) = resp["result"]["version"].as_str()
                            {
                                probed = true;
                                let _ = sqlx::query("UPDATE devices SET openpilot_version = ?2 WHERE dongle_id = ?1")
                                    .bind(&dongle_id)
                                    .bind(v)
                                    .execute(&app.db)
                                    .await;
                            },
                        }
                    }
                }
                _ => break,
            },
            call = rx.recv() => match call {
                Some((id, text, reply)) => {
                    pending.retain(|_, r| !r.is_closed());
                    if socket.send(Message::Text(text.into())).await.is_err() {
                        break;
                    }
                    pending.insert(id, reply);
                },
                None => break,
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
    drop(rx);
    app.peers
        .lock()
        .unwrap()
        .retain(|k, v| k != &dongle_id || !v.is_closed());
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
