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
const MAX_EXPIRY: i64 = 7 * 24 * 60 * 60;
const MAX_QUEUED: i64 = 256;

const QUEUED: [&str; 2] = ["uploadFileToUrl", "uploadFilesToUrls"];

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

fn bad_params(id: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id,
            "error": { "code": -32602, "message": "url is not in this instance's bucket" } })
}

fn collect_urls(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) if s.starts_with("http") => out.push(s.clone()),
        Value::Array(a) => a.iter().for_each(|x| collect_urls(x, out)),
        Value::Object(o) => o.values().for_each(|x| collect_urls(x, out)),
        _ => {}
    }
}

fn own_bucket(app: &AppState, dongle_id: &str, params: &Value) -> bool {
    let Some(s) = app.config.storage.as_ref() else {
        return false;
    };
    let prefix = format!("{}/{}/{dongle_id}/", s.endpoint, s.bucket);
    let mut urls = Vec::new();
    collect_urls(params, &mut urls);
    !urls.is_empty() && urls.iter().all(|u| u.starts_with(&prefix))
}

async fn enqueue(app: &AppState, dongle_id: &str, req: &Value) -> Result<()> {
    sqlx::query(
        "INSERT INTO athena_queue (dongle_id, method, params, expiry)
         SELECT ?1, ?2, ?3, min(coalesce(?4, unixepoch() + ?5), unixepoch() + ?5)
          WHERE (SELECT count(*) FROM athena_queue WHERE dongle_id = ?1) < ?6",
    )
    .bind(dongle_id)
    .bind(req["method"].as_str().unwrap_or_default())
    .bind(req["params"].to_string())
    .bind(req["expiry"].as_i64())
    .bind(MAX_EXPIRY)
    .bind(MAX_QUEUED)
    .execute(&app.db)
    .await
    .map_err(anyhow::Error::from)?;
    Ok(())
}

pub async fn queued(
    State(app): State<AppState>,
    Path(dongle_id): Path<String>,
    user: crate::user::CurrentUser,
) -> Result<Json<Value>> {
    if !device::owned(&app.db, &dongle_id, user.id).await? {
        return Err(Error::NotFound);
    }
    let rows: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT method, params, expiry FROM athena_queue
          WHERE dongle_id = ?1 AND expiry > unixepoch() ORDER BY id",
    )
    .bind(&dongle_id)
    .fetch_all(&app.db)
    .await
    .map_err(anyhow::Error::from)?;
    Ok(Json(Value::Array(
        rows.iter()
            .map(|(method, params, expiry)| {
                json!({
                    "method": method,
                    "params": serde_json::from_str::<Value>(params).unwrap_or(Value::Null),
                    "expiry": expiry,
                })
            })
            .collect(),
    )))
}

pub async fn drain(app: &AppState, dongle_id: &str) -> Vec<String> {
    let rows: Vec<(String, String, i64)> = sqlx::query_as(
        "DELETE FROM athena_queue WHERE dongle_id = ?1
         RETURNING method, params, expiry > unixepoch()",
    )
    .bind(dongle_id)
    .fetch_all(&app.db)
    .await
    .unwrap_or_default();
    rows.iter()
        .filter(|(_, _, alive)| *alive != 0)
        .map(|(method, params, _)| {
            json!({
                "jsonrpc": "2.0",
                "id": NEXT.fetch_add(1, Ordering::Relaxed),
                "method": method,
                "params": serde_json::from_str::<Value>(params).unwrap_or(Value::Null),
            })
            .to_string()
        })
        .collect()
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

    let queueable = QUEUED.contains(&method);
    if queueable && !own_bucket(&app, &dongle_id, &req["params"]) {
        return Ok(Json(bad_params(cid)));
    }

    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let body = call(id, &req).to_string();
    let (reply, wait) = oneshot::channel();
    let peer = app.peers.lock().unwrap().get(&dongle_id).cloned();
    if !peer.is_some_and(|p| p.try_send((id, body, reply)).is_ok()) {
        if !queueable {
            return Ok(Json(offline(cid)));
        }
        enqueue(&app, &dongle_id, &req).await?;
        return Ok(Json(
            json!({ "jsonrpc": "2.0", "id": cid, "result": "Device offline, message queued" }),
        ));
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
