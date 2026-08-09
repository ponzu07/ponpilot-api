use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use axum::{
    Json,
    extract::{Path, State},
};
use serde_json::{Value, json};
use tokio::sync::{mpsc, oneshot};

use crate::{
    AppState, device,
    error::{Error, Result},
};

pub type Call = (u64, String, oneshot::Sender<Value>);
pub type Peers = Arc<Mutex<HashMap<String, mpsc::Sender<Call>>>>;

const RPC_TIMEOUT: Duration = Duration::from_secs(20);

const ALLOWED: [&str; 8] = [
    "setRouteViewed",
    "listUploadQueue",
    "cancelUpload",
    "getNetworkMetered",
    "getNetworkType",
    "getNotCar",
    "uploadFileToUrl",
    "uploadFilesToUrls",
];

static NEXT: AtomicU64 = AtomicU64::new(1);

fn offline(id: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id,
            "error": { "code": -32001, "message": "device offline" } })
}

fn not_found(id: Value, method: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id,
            "error": { "code": -32601, "message": format!("method not found: {method}") } })
}

fn call(id: u64, req: &Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": req["method"],
        "params": req["params"],
    })
}

pub async fn relay(
    State(app): State<AppState>,
    Path(dongle_id): Path<String>,
    user: crate::user::CurrentUser,
    Json(req): Json<Value>,
) -> Result<Json<Value>> {
    if !app.config.is_superuser(&user.identity)
        && !device::owned(&app.db, &dongle_id, user.id).await?
    {
        return Err(Error::NotFound);
    }

    let cid = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req["method"].as_str().unwrap_or_default();
    if !ALLOWED.contains(&method) {
        return Ok(Json(not_found(cid, method)));
    }

    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let body = call(id, &req).to_string();
    let (reply, wait) = oneshot::channel();
    let peer = app.peers.lock().unwrap().get(&dongle_id).cloned();
    if !peer.is_some_and(|p| p.try_send((id, body, reply)).is_ok()) {
        return Ok(Json(offline(cid)));
    }
    match tokio::time::timeout(RPC_TIMEOUT, wait).await {
        Ok(Ok(mut resp)) => {
            resp["id"] = cid;
            Ok(Json(resp))
        }
        _ => Ok(Json(offline(cid))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denied_methods_never_use_32000() {
        for m in ["startLocalProxy", "getMessage", "getVersion", "reboot", ""] {
            assert!(!ALLOWED.contains(&m));
            let e = not_found(json!(0), m);
            assert_eq!(e["error"]["code"], -32601, "-32000 は TypeError を起こす");
            assert_eq!(e["error"]["message"], format!("method not found: {m}"));
        }
    }

    #[test]
    fn relayed_call_drops_unknown_keys() {
        let req = json!({
            "jsonrpc": "2.0", "id": 0, "method": "setRouteViewed",
            "params": { "route": "a|b" }, "expiry": 1234
        });
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let out = call(id, &req);
        let keys: Vec<_> = out.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["id", "jsonrpc", "method", "params"], "4キーだけ");
        assert!(out["id"].is_number(), "id はサーバー採番の数値");
        assert_eq!(out["params"], req["params"]);

        let bare = json!({ "jsonrpc": "2.0", "id": 0, "method": "listUploadQueue" });
        let next = NEXT.fetch_add(1, Ordering::Relaxed);
        assert_ne!(id, next, "採番は毎回異なる");
        assert!(call(next, &bare)["params"].is_null(), "params 無しは null");
    }
}
