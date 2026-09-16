pub mod delivery;
pub mod grants;
pub mod replay;
pub mod sessions;

use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod, Runtime};
use tokio_postgres::NoTls;

use crate::error::{ProblemCode, RelayError};

pub type PgPool = Pool;
pub type Client = deadpool_postgres::Client;

pub async fn connect(database_url: &str) -> Result<PgPool, RelayError> {
    let cfg = database_url
        .parse::<tokio_postgres::Config>()
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    let mgr = Manager::from_config(
        cfg,
        NoTls,
        ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        },
    );
    let pool = Pool::builder(mgr)
        .max_size(16)
        .runtime(Runtime::Tokio1)
        .build()
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    run_migrations(&pool).await?;
    Ok(pool)
}

pub async fn run_migrations(pool: &PgPool) -> Result<(), RelayError> {
    let client = pool
        .get()
        .await
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    client
        .batch_execute(
            r#"
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version TEXT PRIMARY KEY,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            "#,
        )
        .await
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    let exists = client
        .query_opt("SELECT 1 FROM schema_migrations WHERE version = $1", &[&"0001_init"])
        .await
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    if exists.is_none() {
        client
            .batch_execute(include_str!("../../migrations/0001_init.sql"))
            .await
            .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
        client
            .execute("INSERT INTO schema_migrations (version) VALUES ($1)", &[&"0001_init"])
            .await
            .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    }
    Ok(())
}

pub async fn try_advisory_lock(pool: &PgPool, key: i64) -> Result<bool, RelayError> {
    let client = pool
        .get()
        .await
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    let row = client
        .query_one("SELECT pg_try_advisory_lock($1)", &[&key])
        .await
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    Ok(row.get(0))
}

pub async fn ping(pool: &PgPool) -> Result<(), RelayError> {
    let client = pool
        .get()
        .await
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    client
        .simple_query("SELECT 1")
        .await
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    Ok(())
}

pub fn is_unique_violation(err: &tokio_postgres::Error) -> bool {
    err.code().is_some_and(|code| code.code() == "23505")
}

pub async fn begin(client: &mut Client) -> Result<tokio_postgres::Transaction<'_>, RelayError> {
    tokio_postgres::Client::transaction(&mut *client)
        .await
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))
}
