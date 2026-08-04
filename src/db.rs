use anyhow::Result;
use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};

pub async fn connect(path: &str) -> Result<SqlitePool> {
    let opts = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);
    let pool = SqlitePoolOptions::new().connect_with(opts).await?;
    sqlx::migrate!().run(&pool).await?;
    Ok(pool)
}

pub async fn upsert_user(pool: &SqlitePool, identity: &str, username: &str) -> Result<i64> {
    Ok(sqlx::query_scalar(
        "INSERT INTO users (identity, username, created_at)
         VALUES (?1, ?2, unixepoch())
         ON CONFLICT(identity) DO UPDATE SET username = ?2
         RETURNING id",
    )
    .bind(identity)
    .bind(username)
    .fetch_one(pool)
    .await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db() -> String {
        let p = std::env::temp_dir().join(format!("ponpilot-test-{}.sqlite3", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p.to_string_lossy().into_owned()
    }

    #[tokio::test]
    async fn upsert_is_idempotent_and_refreshes_username() {
        let pool = connect(&temp_db()).await.unwrap();

        let a = upsert_user(&pool, "github_42", "old").await.unwrap();
        let b = upsert_user(&pool, "github_42", "new").await.unwrap();
        assert_eq!(a, b, "同じ identity は同じ行");

        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 1);

        let name: String = sqlx::query_scalar("SELECT username FROM users WHERE identity = ?1")
            .bind("github_42")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(name, "new", "username は毎回更新される");
    }
}
