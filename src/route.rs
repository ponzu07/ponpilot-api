use std::collections::HashMap;

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    AppState,
    config::Storage,
    device,
    error::{Error, Result},
    qlog, sigv4,
    user::CurrentUser,
};

const SEGMENT_MILLIS: i64 = 60 * 1000;
const URL_TTL: u32 = 24 * 60 * 60;
const METERS_PER_MILE: f64 = 1609.344;
const HARVEST_LIMIT: i64 = 64;
const CLAIM_TTL: i64 = 300;
const MAX_QLOG: usize = 8 << 20;
const HARVEST_BUDGET: std::time::Duration = std::time::Duration::from_secs(20);

fn now() -> i64 {
    std::time::UNIX_EPOCH.elapsed().unwrap().as_secs() as i64
}

fn storage(app: &AppState) -> Result<&Storage> {
    app.config
        .storage
        .as_ref()
        .ok_or_else(|| Error::Internal(anyhow::anyhow!("storage is not configured")))
}

fn safe_path(path: &str) -> Option<&str> {
    (!path.is_empty()
        && !path.starts_with('/')
        && !path.contains("..")
        && !path.contains(['\\', '\0']))
    .then_some(path)
}

fn segment_of(path: &str) -> Option<(&str, u32, &str)> {
    let (dir, file) = path.split_once('/')?;
    let (route, seg) = dir.rsplit_once("--")?;
    // route 名は URL に素で埋まる（`actions/cached.js:307`）ので `?` `#` を弾く。
    route
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        .then_some((route, seg.parse().ok()?, file))
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
                "INSERT OR IGNORE INTO uploads (dongle_id, route_name, segment, filename, created_at, owner_id)
                 VALUES (?1, ?2, ?3, ?4, unixepoch(), ?5)",
            )
            .bind(&dongle_id)
            .bind(route)
            .bind(seg)
            .bind(file)
            .bind(device.owner_id)
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

/// connect は `route.url` にパスを連結する（`cached.js:307`）のでクエリ署名は使えない。
fn segment_token(secret: &str, dongle_id: &str, route_name: &str, exp: i64) -> String {
    let sig = sigv4::hex(&sigv4::hmac(
        secret.as_bytes(),
        &format!("segurl:{dongle_id}/{route_name}/{exp}"),
    ));
    format!("{exp}-{}", &sig[..16])
}

fn verify_segment_token(secret: &str, token: &str, dongle: &str, route: &str) -> Result<()> {
    let exp: i64 = token
        .split_once('-')
        .map_or(0, |(e, _)| e.parse().unwrap_or(0));
    (exp >= now() && segment_token(secret, dongle, route, exp) == token)
        .then_some(())
        .ok_or(Error::Forbidden)
}

#[derive(sqlx::FromRow, Default)]
struct Parsed {
    route_name: String,
    segment: i64,
    start_millis: i64,
    start_offset: i64,
    end_offset: i64,
    distance_m: f64,
    first_lat: Option<f64>,
    first_lng: Option<f64>,
    last_lat: Option<f64>,
    last_lng: Option<f64>,
}

fn timeline(segments: &[i64], parsed: &[&Parsed], started: i64) -> (Vec<i64>, Vec<i64>) {
    let at = |n: i64| parsed.iter().find(|p| p.segment == n);
    let origin = parsed
        .first()
        .map_or(started, |p| p.start_millis - p.segment * SEGMENT_MILLIS);
    let starts: Vec<i64> = segments
        .iter()
        .map(|n| {
            at(*n).map_or(origin + n * SEGMENT_MILLIS, |p| {
                p.start_millis + p.start_offset
            })
        })
        .collect();
    let ends: Vec<i64> = segments
        .iter()
        .zip(&starts)
        .map(|(n, t)| {
            at(*n)
                .filter(|p| p.end_offset > 0)
                .map_or(t + SEGMENT_MILLIS, |p| p.start_millis + p.end_offset)
        })
        .collect();
    (starts, ends)
}

async fn harvest(app: &AppState, dongle_id: &str) {
    // 同時実行を絞らないと 1 リクエストにつき最大 64 本のダウンロードが並列に増える。
    static SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);
    let Ok(_slot) = SLOTS.try_acquire() else {
        return;
    };

    let pending: Vec<(String, i64)> = sqlx::query_as(
        "SELECT u.route_name, u.segment FROM uploads u
          WHERE u.dongle_id = ?1 AND u.filename = 'qlog.zst'
            AND NOT EXISTS (
                SELECT 1 FROM segments s
                 WHERE s.dongle_id = u.dongle_id AND s.route_name = u.route_name
                   AND s.segment = u.segment
                   AND (s.parsed_at IS NOT NULL OR s.claimed_at > unixepoch() - ?2))
          ORDER BY u.route_name DESC, u.segment LIMIT ?3",
    )
    .bind(dongle_id)
    .bind(CLAIM_TTL)
    .bind(HARVEST_LIMIT)
    .fetch_all(&app.db)
    .await
    .unwrap_or_default();

    for (route_name, segment) in pending {
        if let Err(e) = ingest(app, dongle_id, &route_name, segment).await {
            tracing::warn!("qlog {dongle_id}/{route_name}/{segment}: {e:#}");
        }
    }
}

async fn ingest(
    app: &AppState,
    dongle_id: &str,
    route_name: &str,
    segment: i64,
) -> anyhow::Result<()> {
    let key = format!("{dongle_id}/{route_name}/{segment}/qlog.zst");
    let url = sigv4::presign_url(storage(app)?, "GET", &key, 300);

    // 同時に来た別リクエストと二重にパースしないための唯一の同期点。
    let claimed = sqlx::query(
        "INSERT INTO segments (dongle_id, route_name, segment, claimed_at)
              VALUES (?1, ?2, ?3, unixepoch())
         ON CONFLICT DO UPDATE SET claimed_at = unixepoch()
              WHERE parsed_at IS NULL AND claimed_at < unixepoch() - ?4",
    )
    .bind(dongle_id)
    .bind(route_name)
    .bind(segment)
    .bind(CLAIM_TTL)
    .execute(&app.db)
    .await?
    .rows_affected();
    if claimed == 0 {
        return Ok(());
    }

    // reqwest のエラーは Display に URL を含む。presign 済みなのでログに出せない。
    let mut resp = app
        .http
        .get(url)
        .send()
        .await
        .map_err(reqwest::Error::without_url)?;
    // 実体がまだ無いだけ。claim を残せば CLAIM_TTL 秒のバックオフが効く。
    if !resp.status().is_success() {
        return Ok(());
    }

    let mut body = Vec::new();
    while let Some(c) = resp.chunk().await.map_err(reqwest::Error::without_url)? {
        body.extend_from_slice(&c);
        anyhow::ensure!(body.len() <= MAX_QLOG, "qlog too large");
    }

    // 読めなかった qlog は parsed_at だけ立てて確定させる（二度読まない）。
    let p = qlog::parse(&body);
    sqlx::query(
        "UPDATE segments SET parsed_at = unixepoch(), start_millis = ?4, start_offset = ?5,
                end_offset = ?6, distance_m = ?7, first_lat = ?8, first_lng = ?9,
                last_lat = ?10, last_lng = ?11, coords = ?12, events = ?13
          WHERE dongle_id = ?1 AND route_name = ?2 AND segment = ?3",
    )
    .bind(dongle_id)
    .bind(route_name)
    .bind(segment)
    .bind(p.as_ref().map(|q| q.start_millis))
    .bind(p.as_ref().map(|q| q.start_offset))
    .bind(p.as_ref().map(|q| q.end_offset))
    .bind(p.as_ref().map(|q| q.distance_m))
    .bind(p.as_ref().and_then(|q| q.coords.first()).map(|c| c.1))
    .bind(p.as_ref().and_then(|q| q.coords.first()).map(|c| c.2))
    .bind(p.as_ref().and_then(|q| q.coords.last()).map(|c| c.1))
    .bind(p.as_ref().and_then(|q| q.coords.last()).map(|c| c.2))
    .bind(p.as_ref().map_or_else(|| "[]".into(), coords_json))
    .bind(p.as_ref().map_or_else(|| "[]".into(), events_json))
    .execute(&app.db)
    .await?;
    Ok(())
}

/// `t` は整数秒。connect が `driveCoords[Math.floor(offset/1e3)]` で直接引く。
fn coords_json(s: &qlog::Segment) -> String {
    Value::Array(
        s.coords
            .iter()
            .map(|(t, lat, lng)| json!({ "t": t, "lat": lat, "lng": lng }))
            .collect(),
    )
    .to_string()
}

fn events_json(s: &qlog::Segment) -> String {
    Value::Array(
        s.states
            .iter()
            .map(|(ms, state, enabled, alert)| {
                json!({
                    "type": "state",
                    "route_offset_millis": ms,
                    "data": {
                        "state": state,
                        "enabled": enabled,
                        // connect は文字列比較と数値添字を両方する（`cached.js:179`）。
                        "alertStatus": if *alert == 0 { json!("normal") } else { json!(alert) },
                    },
                })
            })
            .collect(),
    )
    .to_string()
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
    // connect は `[]` を 14 日キャッシュする（`cached.js:337`）ので先にパースする。
    let _ = tokio::time::timeout(HARVEST_BUDGET, harvest(&app, &dongle_id)).await;

    let rows: Vec<(String, i64, String)> = sqlx::query_as(
        "SELECT route_name, MIN(created_at) * 1000 AS started, GROUP_CONCAT(DISTINCT segment)
         FROM uploads WHERE dongle_id = ?1 AND owner_id = ?6 GROUP BY route_name
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
    .bind(q.limit.filter(|n| *n > 0).unwrap_or(100).min(1000))
    .bind(user.id)
    .fetch_all(&app.db)
    .await
    .map_err(anyhow::Error::from)?;

    let names: Vec<&str> = rows.iter().map(|(name, _, _)| name.as_str()).collect();
    let parsed: Vec<Parsed> = sqlx::query_as(
        "SELECT route_name, segment, start_millis, start_offset, end_offset, distance_m,
                first_lat, first_lng, last_lat, last_lng
           FROM segments
          WHERE dongle_id = ?1 AND start_millis IS NOT NULL
            AND route_name IN (SELECT value FROM json_each(?2))
          ORDER BY segment",
    )
    .bind(&dongle_id)
    .bind(serde_json::to_string(&names).unwrap_or_default())
    .fetch_all(&app.db)
    .await
    .map_err(anyhow::Error::from)?;

    let mut by_route: HashMap<&str, Vec<&Parsed>> = HashMap::new();
    for p in &parsed {
        by_route.entry(&p.route_name).or_default().push(p);
    }
    let exp = now() + i64::from(URL_TTL);

    let routes = rows
        .iter()
        .map(|(name, started, segments)| {
            let mut segments: Vec<i64> =
                segments.split(',').filter_map(|s| s.parse().ok()).collect();
            segments.sort_unstable();

            let parsed = by_route.get(name.as_str()).map_or(&[][..], Vec::as_slice);
            let (starts, ends) = timeline(&segments, parsed, *started);
            let tok = segment_token(&app.config.jwt_secret, &dongle_id, name, exp);

            json!({
                "fullname": format!("{dongle_id}|{name}"),
                "dongle_id": dongle_id,
                "url": format!("{}/v1/segments/{tok}/{dongle_id}/{name}", app.config.public_url),
                "share_exp": exp,
                "share_sig": &tok[tok.len() - 16..],
                // 単位はマイル。未パースでも数値でないと `toFixed` が落ちる。
                "distance": parsed.iter().fold(0.0, |m, p| m + p.distance_m) / METERS_PER_MILE,
                "create_time": starts.first().copied().unwrap_or(*started) / 1000,
                "maxqlog": segments.last(),
                "start_time_utc_millis": starts.first(),
                "end_time_utc_millis": ends.last(),
                "segment_numbers": segments,
                "segment_start_times": starts,
                "segment_end_times": ends,
                "start_lat": parsed.iter().find_map(|p| p.first_lat),
                "start_lng": parsed.iter().find_map(|p| p.first_lng),
                "end_lat": parsed.iter().rev().find_map(|p| p.last_lat),
                "end_lng": parsed.iter().rev().find_map(|p| p.last_lng),
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
         WHERE dongle_id = ?1 AND route_name = ?2 AND owner_id = ?3 ORDER BY segment",
    )
    .bind(dongle_id)
    .bind(name)
    .bind(user.id)
    .fetch_all(&app.db)
    .await
    .map_err(anyhow::Error::from)?;

    let s = storage(&app)?;
    let mut out: HashMap<&str, Vec<String>> = HashMap::new();
    for (seg, file) in &rows {
        let kind = match file.as_str() {
            "qcamera.ts" => "qcameras",
            "qlog.zst" => "qlogs",
            _ => continue,
        };
        let key = format!("{dongle_id}/{name}/{seg}/{file}");
        out.entry(kind)
            .or_default()
            .push(sigv4::presign_url(s, "GET", &key, URL_TTL));
    }
    Ok(Json(json!(out)))
}

#[derive(Deserialize)]
pub struct StreamQuery {
    exp: String,
    sig: String,
}

/// `#EXT-X-ENDLIST` が無いと hls.js が LIVE 扱いして `video.duration` が `Infinity` になる。
fn playlist(items: &[(f64, bool, String)]) -> String {
    let target = items.iter().fold(0.0f64, |m, (d, _, _)| m.max(*d)).ceil() as i64;
    let mut out = format!(
        "#EXTM3U\n#EXT-X-VERSION:8\n#EXT-X-PLAYLIST-TYPE:VOD\n\
         #EXT-X-TARGETDURATION:{target}\n#EXT-X-MEDIA-SEQUENCE:0\n"
    );
    for (d, present, url) in items {
        if !present {
            out.push_str("#EXT-X-GAP\n");
        }
        out.push_str(&format!("#EXTINF:{d:.3},\n{url}\n"));
    }
    out.push_str("#EXT-X-ENDLIST\n");
    out
}

pub async fn qcamera_m3u8(
    State(app): State<AppState>,
    Path(route_name): Path<String>,
    Query(q): Query<StreamQuery>,
) -> Result<Response> {
    let (dongle_id, name) = route_name.split_once('|').ok_or(Error::NotFound)?;
    verify_segment_token(
        &app.config.jwt_secret,
        &format!("{}-{}", q.exp, q.sig),
        dongle_id,
        name,
    )?;

    let rows: Vec<(i64, Option<i64>, Option<i64>, bool)> = sqlx::query_as(
        "SELECT u.segment, s.start_offset, s.end_offset, MAX(u.filename = 'qcamera.ts')
           FROM uploads u LEFT JOIN segments s
             ON s.dongle_id = u.dongle_id AND s.route_name = u.route_name
            AND s.segment = u.segment
          WHERE u.dongle_id = ?1 AND u.route_name = ?2
          GROUP BY u.segment ORDER BY u.segment",
    )
    .bind(dongle_id)
    .bind(name)
    .fetch_all(&app.db)
    .await
    .map_err(anyhow::Error::from)?;
    if !rows.iter().any(|(_, _, _, qcam)| *qcam) {
        return Err(Error::NotFound);
    }

    let s = storage(&app)?;
    // 欠落セグメントを飛ばすとプレイリスト時刻が connect のルートオフセットと恒久的にずれる。
    let items: Vec<(f64, bool, String)> = (rows[0].0..=rows[rows.len() - 1].0)
        .map(|n| {
            let row = rows.iter().find(|r| r.0 == n);
            // qcamera.ts は encoderd が 1200 フレームで切るので必ず 60 秒以下。
            let d = match row.map(|r| (r.1, r.2)) {
                Some((Some(a), Some(b))) if b > a => ((b - a) as f64 / 1000.0).min(60.0),
                _ => 60.0,
            };
            let key = format!("{dongle_id}/{name}/{n}/qcamera.ts");
            (
                d,
                row.is_some_and(|r| r.3),
                sigv4::presign_url(s, "GET", &key, URL_TTL),
            )
        })
        .collect();

    Ok((
        [
            (header::CONTENT_TYPE, "application/vnd.apple.mpegurl"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        playlist(&items),
    )
        .into_response())
}

pub async fn segment_file(
    State(app): State<AppState>,
    Path((token, dongle_id, route_name, segment, file)): Path<(
        String,
        String,
        String,
        i64,
        String,
    )>,
) -> Result<Response> {
    verify_segment_token(&app.config.jwt_secret, &token, &dongle_id, &route_name)?;
    let want_coords = match file.as_str() {
        "coords.json" => true,
        "events.json" => false,
        _ => return Err(Error::NotFound),
    };
    let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT coords, events FROM segments
          WHERE dongle_id = ?1 AND route_name = ?2 AND segment = ?3",
    )
    .bind(&dongle_id)
    .bind(&route_name)
    .bind(segment)
    .fetch_optional(&app.db)
    .await
    .map_err(anyhow::Error::from)?;

    // `[]` は 14 日キャッシュされる。空ボディなら `resp.json()` が投げて再取得される。
    let body = row.and_then(|(c, e)| if want_coords { c } else { e });
    Ok((
        [(header::CONTENT_TYPE, "application/json")],
        body.unwrap_or_default(),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_token_binds_route_and_expiry() {
        let (secret, dongle, route) = ("s".repeat(32), "ded1dce02bf7e410", "00000004--0ac3964c96");
        let exp = now() + 3600;
        let tok = segment_token(&secret, dongle, route, exp);
        assert!(verify_segment_token(&secret, &tok, dongle, route).is_ok());

        let url = format!("https://h/v1/segments/{tok}/{dongle}/{route}/1/events.json");
        assert!(!url.contains(['?', '#', '&']), "{url}");

        let (e, s) = (exp, &tok[tok.len() - 16..]);
        assert_eq!(format!("{e}-{s}"), tok, "share_exp と share_sig の再連結");

        for (t, d, r) in [
            (tok.as_str(), "other_dongle_id", route),
            (tok.as_str(), dongle, "00000005--0ac3964c96"),
            ("deadbeef", dongle, route),
            (
                segment_token(&secret, dongle, route, now() - 1).as_str(),
                dongle,
                route,
            ),
        ] {
            assert!(
                verify_segment_token(&secret, t, d, r).is_err(),
                "{t} {d} {r}"
            );
        }
        let other = segment_token(&"x".repeat(32), dongle, route, exp);
        assert!(verify_segment_token(&secret, &other, dongle, route).is_err());
    }

    #[test]
    fn playlist_is_a_finite_vod() {
        let url0 = "https://s3/a/0/qcamera.ts?X-Amz-Date=x&X-Amz-Signature=y".to_string();
        let items = [
            (60.0, true, url0.clone()),
            (32.4, true, "https://s3/1".into()),
        ];
        let m = playlist(&items);

        assert!(m.starts_with("#EXTM3U\n"), "{m}");
        assert!(m.ends_with("#EXT-X-ENDLIST\n"), "{m}");
        assert!(m.contains("#EXT-X-TARGETDURATION:60\n"), "{m}");
        assert_eq!(m.matches("#EXTINF:").count(), 2);
        assert!(m.contains("#EXTINF:32.400,\n"), "{m}");
        assert!(
            m.contains(&format!("\n{url0}\n")),
            "URI 行が verbatim でない"
        );
        assert!(!m.contains("#EXT-X-GAP"), "全部そろっているので不要: {m}");

        let gap = playlist(&[(60.0, true, "a".into()), (60.0, false, "b".into())]);
        assert_eq!(
            gap.matches("#EXT-X-GAP\n#EXTINF:60.000,\nb\n").count(),
            1,
            "{gap}"
        );
    }

    #[test]
    fn timeline_uses_per_segment_wall_clock() {
        let seg = |segment, start_millis, end_offset| Parsed {
            segment,
            start_millis,
            end_offset,
            ..Default::default()
        };

        let (a, b) = (seg(0, 1_000_000, 61_428), seg(1, 1_061_500, 60_000));
        let (starts, ends) = timeline(&[0, 1], &[&a, &b], 0);
        assert_eq!(
            starts,
            [1_000_000, 1_061_500],
            "61428 刻みになってはいけない"
        );
        assert_eq!(ends, [1_061_428, 1_121_500]);

        let (starts, _) = timeline(&[0, 1, 2], &[&a], 0);
        assert_eq!(starts[2], 1_120_000, "未パースは origin + n*60000");

        let c = seg(3, 1_180_000, 0);
        let (starts, ends) = timeline(&[0, 3], &[&c], 0);
        assert_eq!(starts, [1_000_000, 1_180_000], "origin が 3 分前に戻る");
        assert_eq!(ends[1], 1_240_000, "end_offset 0 は 60 秒に落ちる");

        assert_eq!(timeline(&[0], &[], 42_000).0, [42_000], "started に落ちる");
    }

    #[test]
    fn encodes_alert_status_for_both_readers() {
        let s = qlog::Segment {
            states: vec![(0, "disabled", false, 0), (10, "enabled", true, 2)],
            ..Default::default()
        };
        let v: Value = serde_json::from_str(&events_json(&s)).unwrap();
        assert_eq!(v[0]["data"]["alertStatus"], json!("normal"));
        assert_eq!(v[1]["data"]["alertStatus"], json!(2));
        assert_eq!(v[1]["route_offset_millis"], json!(10));
        assert_eq!(v[1]["data"]["enabled"], json!(true));
        assert_eq!(v[1]["type"], json!("state"));
    }

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
