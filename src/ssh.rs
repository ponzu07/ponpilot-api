use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    extract::{
        Path, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::HeaderMap,
    response::Response,
};
use futures_util::{SinkExt, StreamExt};
use rand::distr::{Alphanumeric, SampleString};
use serde_json::json;
use tokio::sync::oneshot;

use crate::{
    AppState, athena, device,
    error::{Error, Result},
    rpc,
    user::CurrentUser,
};

const PING_INTERVAL: Duration = Duration::from_secs(30);

pub type Pending = Arc<Mutex<HashMap<String, oneshot::Sender<WebSocket>>>>;

struct Slot(Pending, String);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.lock().unwrap().remove(&self.1);
    }
}

pub async fn open(
    State(app): State<AppState>,
    Path(dongle_id): Path<String>,
    user: CurrentUser,
    upgrade: WebSocketUpgrade,
) -> Result<Response> {
    if !app.config.is_superuser(&user.identity)
        && !device::owned(&app.db, &dongle_id, user.id).await?
    {
        return Err(Error::NotFound);
    }

    let token = Alphanumeric.sample_string(&mut rand::rng(), 32);
    let (tx, rx) = oneshot::channel();
    let slot = Slot(app.proxies.clone(), format!("{dongle_id}/{token}"));
    app.proxies.lock().unwrap().insert(slot.1.clone(), tx);

    let req = json!({
        "method": "startLocalProxy",
        "params": {
            "remote_ws_uri": format!(
                "{}/ws/v2/{dongle_id}/proxy/{token}",
                app.config.public_url.replacen("http", "ws", 1)
            ),
            "local_port": 22,
        },
    });
    let wait = rpc::dispatch(&app, &dongle_id, &req).ok_or(Error::Offline)?;
    let Ok(Ok(resp)) = tokio::time::timeout(rpc::RPC_TIMEOUT, wait).await else {
        return Err(Error::Offline);
    };
    if resp["result"]["success"] != 1 {
        tracing::warn!("startLocalProxy {dongle_id}: {}", resp["error"]);
        return Err(Error::Offline);
    }
    tracing::info!("ssh tunnel {dongle_id} for {}", user.identity);
    Ok(upgrade
        .max_message_size(athena::MAX_MESSAGE)
        .on_upgrade(move |client| bridge(slot, client, rx)))
}

pub async fn attach(
    State(app): State<AppState>,
    Path((dongle_id, token)): Path<(String, String)>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Result<Response> {
    if !device::valid_dongle_id(&dongle_id) {
        return Err(Error::Unauthorized);
    }
    let jwt = device::cookie_jwt(&headers)?;
    if device::peek(jwt)?.identity != dongle_id {
        return Err(Error::Unauthorized);
    }
    let stored = device::find(&app.db, &dongle_id)
        .await?
        .ok_or(Error::Unauthorized)?;
    device::verify(&stored.public_key, jwt)?;

    let tx = app
        .proxies
        .lock()
        .unwrap()
        .remove(&format!("{dongle_id}/{token}"))
        .ok_or(Error::NotFound)?;
    Ok(upgrade
        .max_message_size(athena::MAX_MESSAGE)
        .on_upgrade(move |device_ws| async move {
            let _ = tx.send(device_ws);
        }))
}

async fn bridge(_slot: Slot, client: WebSocket, rx: oneshot::Receiver<WebSocket>) {
    let Ok(Ok(device_ws)) = tokio::time::timeout(rpc::RPC_TIMEOUT, rx).await else {
        return;
    };
    let (mut to_client, mut from_client) = client.split();
    let (mut to_device, mut from_device) = device_ws.split();
    let mut ping = tokio::time::interval(PING_INTERVAL);
    let mut alive = true;
    loop {
        let ok = tokio::select! {
            msg = from_client.next() => {
                alive = true;
                match msg {
                    Some(Ok(Message::Binary(b))) => to_device.send(Message::Binary(b)).await.is_ok(),
                    Some(Ok(_)) => true,
                    _ => false,
                }
            },
            msg = from_device.next() => match msg {
                Some(Ok(Message::Binary(b))) => to_client.send(Message::Binary(b)).await.is_ok(),
                Some(Ok(_)) => true,
                _ => false,
            },
            _ = ping.tick() => {
                std::mem::take(&mut alive)
                    && to_client.send(Message::Ping(Default::default())).await.is_ok()
                    && to_device.send(Message::Binary(Default::default())).await.is_ok()
            },
        };
        if !ok {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_frees_the_token_on_drop() {
        let pending: Pending = Default::default();
        let (tx, _rx) = oneshot::channel();
        pending.lock().unwrap().insert("dead/beef".into(), tx);
        assert!(pending.lock().unwrap().contains_key("dead/beef"));
        drop(Slot(pending.clone(), "dead/beef".into()));
        assert!(pending.lock().unwrap().is_empty(), "drop で解放される");
    }
}
