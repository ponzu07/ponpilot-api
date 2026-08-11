use crate::{AppState, sigv4};

const BATCH: i64 = 500;
const URL_TTL: u32 = 300;

async fn drop_key(app: &AppState, key: &str) -> bool {
    let Some(s) = app.config.storage.as_ref() else {
        return false;
    };
    if app.config.retention_dry_run {
        tracing::info!("retention dry-run: would delete {key}");
        return false;
    }
    let url = sigv4::presign_url(s, "DELETE", key, URL_TTL);
    match app.http.delete(url).send().await {
        Ok(r) => r.status().is_success() || r.status() == 404,
        Err(e) => {
            tracing::warn!("retention: {}", e.without_url());
            false
        }
    }
}

pub async fn sweep(app: &AppState) -> anyhow::Result<()> {
    let cutoff = app.config.retention_days * 86_400;

    let stale: Vec<(String, String, i64, String)> = sqlx::query_as(
        "SELECT u.dongle_id, u.route_name, u.segment, u.filename FROM uploads u
          WHERE u.created_at < unixepoch() - ?1
            AND NOT EXISTS (SELECT 1 FROM routes r WHERE r.dongle_id = u.dongle_id
                             AND r.route_name = u.route_name AND r.preserved)
          ORDER BY u.created_at LIMIT ?2",
    )
    .bind(cutoff)
    .bind(BATCH)
    .fetch_all(&app.db)
    .await?;

    let mut gone = 0;
    for (dongle_id, route_name, segment, filename) in &stale {
        if !drop_key(
            app,
            &format!("{dongle_id}/{route_name}/{segment}/{filename}"),
        )
        .await
        {
            continue;
        }
        sqlx::query(
            "DELETE FROM uploads WHERE dongle_id = ?1 AND route_name = ?2
              AND segment = ?3 AND filename = ?4",
        )
        .bind(dongle_id)
        .bind(route_name)
        .bind(segment)
        .bind(filename)
        .execute(&app.db)
        .await?;
        gone += 1;
    }

    let boots: Vec<(String, String)> = sqlx::query_as(
        "SELECT dongle_id, filename FROM bootlogs WHERE created_at < unixepoch() - ?1
          ORDER BY created_at LIMIT ?2",
    )
    .bind(cutoff)
    .bind(BATCH)
    .fetch_all(&app.db)
    .await?;

    for (dongle_id, filename) in &boots {
        if !drop_key(app, &format!("{dongle_id}/{filename}")).await {
            continue;
        }
        sqlx::query("DELETE FROM bootlogs WHERE dongle_id = ?1 AND filename = ?2")
            .bind(dongle_id)
            .bind(filename)
            .execute(&app.db)
            .await?;
        gone += 1;
    }

    let mut orphans = 0;
    if !app.config.retention_dry_run {
        orphans = sqlx::query(
            "DELETE FROM segments WHERE NOT EXISTS (SELECT 1 FROM uploads u
               WHERE u.dongle_id = segments.dongle_id AND u.route_name = segments.route_name
                 AND u.segment = segments.segment)",
        )
        .execute(&app.db)
        .await?
        .rows_affected();
        sqlx::query("DELETE FROM athena_queue WHERE expiry < unixepoch()")
            .execute(&app.db)
            .await?;
    }

    if !stale.is_empty() || !boots.is_empty() {
        tracing::info!(
            "retention: {} 候補 / {gone} 削除 / segments {orphans} 行{}",
            stale.len() + boots.len(),
            if app.config.retention_dry_run {
                "（dry-run）"
            } else {
                ""
            }
        );
    }
    Ok(())
}
