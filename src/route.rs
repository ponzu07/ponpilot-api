use std::collections::HashMap;

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, header},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    AppState,
    config::Storage,
    device,
    error::{Error, Result},
    sigv4,
    user::CurrentUser,
};

const SEGMENT_MILLIS: i64 = 60 * 1000;
const URL_TTL: u32 = 24 * 60 * 60;

fn storage(app: &AppState) -> Result<&Storage> {
    app.config
        .storage
        .as_ref()
        .ok_or_else(|| Error::Internal(anyhow::anyhow!("storage is not configured")))
}

fn safe_path(path: &str) -> Option<&str> {
    let ok = !path.is_empty()
        && !path.starts_with('/')
        && !path.contains("..")
        && !path.contains(['\\', '\0']);
    ok.then_some(path)
}

fn segment_of(path: &str) -> Option<(&str, u32, &str)> {
    let (dir, file) = path.split_once('/')?;
    let (route, seg) = dir.rsplit_once("--")?;
    // route 名は URL に素で埋まる（`actions/cached.js:307`）ので `?` `#` を弾く。
    let named = route
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-');
    named.then_some((route, seg.parse().ok()?, file))
}

fn kind_of(file: &str) -> Option<&'static str> {
    match file {
        "qcamera.ts" => Some("qcameras"),
        "qlog.bz2" | "qlog.zst" => Some("qlogs"),
        _ => None,
    }
}

#[derive(Deserialize)]
pub struct UploadQuery {
    path: String,
}

pub async fn upload_url(
    State(app): State<AppState>,
    Path(dongle_id): Path<String>,
    headers: HeaderMap,
    Query(q): Query<UploadQuery>,
) -> Result<Json<Value>> {
    let jwt = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("JWT "))
        .ok_or(Error::Unauthorized)?;
    let device = device::find(&app.db, &dongle_id)
        .await?
        .ok_or(Error::NotFound)?;
    if device::verify(&device.public_key, jwt)?.identity != dongle_id {
        return Err(Error::Unauthorized);
    }
    if device.owner_id.is_none() {
        return Err(Error::Forbidden);
    }

    let s = storage(&app)?;
    let path = safe_path(&q.path).ok_or(Error::Forbidden)?;
    let key = match segment_of(path) {
        Some((route, seg, file)) => {
            sqlx::query(
                "INSERT OR IGNORE INTO uploads (dongle_id, route_name, segment, filename, created_at)
                 VALUES (?1, ?2, ?3, ?4, unixepoch())",
            )
            .bind(&dongle_id)
            .bind(route)
            .bind(seg)
            .bind(file)
            .execute(&app.db)
            .await
            .map_err(anyhow::Error::from)?;
            format!("{dongle_id}/{route}/{seg}/{file}")
        }
        None => format!("{dongle_id}/{path}"),
    };

    let url = sigv4::presign_url(s, "PUT", &key, URL_TTL);
    Ok(Json(json!({ "url": url, "headers": {} })))
}

#[derive(Deserialize)]
pub struct RoutesQuery {
    start: Option<i64>,
    end: Option<i64>,
    limit: Option<i64>,
    route_str: Option<String>,
}

pub async fn routes_segments(
    State(app): State<AppState>,
    Path(dongle_id): Path<String>,
    user: CurrentUser,
    Query(q): Query<RoutesQuery>,
) -> Result<Json<Value>> {
    if !device::owned(&app.db, &dongle_id, user.id).await? {
        return Ok(Json(json!([])));
    }
    let rows: Vec<(String, i64, String)> = sqlx::query_as(
        "SELECT route_name, MIN(created_at) * 1000 AS started, GROUP_CONCAT(DISTINCT segment)
         FROM uploads WHERE dongle_id = ?1 GROUP BY route_name
         HAVING (?2 IS NULL OR MIN(created_at) * 1000 >= ?2)
            AND (?3 IS NULL OR MIN(created_at) * 1000 <= ?3)
            AND (?4 IS NULL OR route_name = ?4)
         ORDER BY started DESC LIMIT ?5",
    )
    .bind(&dongle_id)
    .bind(q.start)
    .bind(q.end)
    .bind(
        q.route_str
            .as_deref()
            .and_then(|s| s.split_once('|'))
            .map(|(_, log)| log),
    )
    .bind(q.limit.filter(|n| *n > 0).unwrap_or(100))
    .fetch_all(&app.db)
    .await
    .map_err(anyhow::Error::from)?;

    let routes = rows
        .iter()
        .map(|(name, started, segments)| {
            let mut segments: Vec<i64> =
                segments.split(',').filter_map(|s| s.parse().ok()).collect();
            segments.sort_unstable();
            let starts: Vec<i64> = segments
                .iter()
                .map(|n| started + n * SEGMENT_MILLIS)
                .collect();
            let ends: Vec<i64> = starts.iter().map(|t| t + SEGMENT_MILLIS).collect();
            json!({
                "fullname": format!("{dongle_id}|{name}"),
                "dongle_id": dongle_id,
                "url": format!("{}/v1/segments/{dongle_id}/{name}", app.config.public_url),
                "distance": 0,
                "create_time": started / 1000,
                "maxqlog": segments.last(),
                "start_time_utc_millis": starts.first(),
                "end_time_utc_millis": ends.last(),
                "segment_numbers": segments,
                "segment_start_times": starts,
                "segment_end_times": ends,
            })
        })
        .collect();
    Ok(Json(Value::Array(routes)))
}

pub async fn files(
    State(app): State<AppState>,
    Path(route_name): Path<String>,
    user: CurrentUser,
) -> Result<Json<Value>> {
    let (dongle_id, name) = route_name.split_once('|').ok_or(Error::NotFound)?;
    if !device::owned(&app.db, dongle_id, user.id).await? {
        return Ok(Json(json!({})));
    }
    let rows: Vec<(i64, String)> = sqlx::query_as(
        "SELECT segment, filename FROM uploads
         WHERE dongle_id = ?1 AND route_name = ?2 ORDER BY segment",
    )
    .bind(dongle_id)
    .bind(name)
    .fetch_all(&app.db)
    .await
    .map_err(anyhow::Error::from)?;

    let s = storage(&app)?;
    let mut out: HashMap<&str, Vec<String>> = HashMap::new();
    for (seg, file) in &rows {
        if let Some(kind) = kind_of(file) {
            let key = format!("{dongle_id}/{name}/{seg}/{file}");
            out.entry(kind)
                .or_default()
                .push(sigv4::presign_url(s, "GET", &key, URL_TTL));
        }
    }
    Ok(Json(json!(out)))
}

pub async fn empty() -> Json<Value> {
    Json(json!([]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_dangerous_paths() {
        for bad in [
            "",
            "/etc/passwd",
            "../../etc/passwd",
            "a/../../b",
            "..",
            "a\\b",
            "a\0b",
        ] {
            assert!(safe_path(bad).is_none(), "{bad:?} は拒否されるべき");
        }
        for ok in [
            "00000004--0ac3964c96--0/qlog.zst",
            "boot/000000a1--3f2e8c91d0.zst",
            "crash/2026-08-04--12-34-56_a1b2c3d4_x",
        ] {
            assert_eq!(safe_path(ok), Some(ok));
        }
    }

    #[test]
    fn splits_segment_paths() {
        assert_eq!(
            segment_of("00000004--0ac3964c96--12/qcamera.ts"),
            Some(("00000004--0ac3964c96", 12, "qcamera.ts"))
        );
        assert!(segment_of("2026-08-04--12-34-56--3/qlog.zst").is_some());
        assert_eq!(segment_of("a?b--0/qlog.zst"), None);
        assert_eq!(segment_of("boot/000000a1--3f2e8c91d0.zst"), None);
        assert_eq!(segment_of("crash/2026-08-04--12-34-56_x"), None);
    }
}
