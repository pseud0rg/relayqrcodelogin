use tokio_postgres::Row;

use crate::db::PgPool;
use crate::error::{ProblemCode, RelayError};

#[derive(Debug, Clone)]
pub struct DeliveryJob {
    pub id: i64,
    pub kind: String,
    pub domain: String,
    pub jti: String,
    pub payload_ciphertext: Vec<u8>,
    pub idempotency_key: String,
    pub session_id: String,
    pub nonce_hash: Vec<u8>,
    pub attempts: i32,
    pub status: String,
}

fn from_row(row: &Row) -> DeliveryJob {
    DeliveryJob {
        id: row.get("id"),
        kind: row.get("kind"),
        domain: row.get("domain"),
        jti: row.get("jti"),
        payload_ciphertext: row.get("payload_ciphertext"),
        idempotency_key: row.get("idempotency_key"),
        session_id: row.get("session_id"),
        nonce_hash: row.get("nonce_hash"),
        attempts: row.get("attempts"),
        status: row.get("status"),
    }
}

pub async fn enqueue(
    client: &impl tokio_postgres::GenericClient,
    kind: &str,
    domain: &str,
    jti: &str,
    payload_ciphertext: &[u8],
    session_id: &str,
    nonce_hash: &[u8],
) -> Result<(), RelayError> {
    client
        .execute(
            r#"
            INSERT INTO delivery_jobs (
                kind, domain, jti, payload_ciphertext, idempotency_key,
                session_id, nonce_hash, status, next_retry_at
            ) VALUES ($1,$2,$3,$4,$3,$5,$6,'pending', NOW())
            ON CONFLICT (jti) DO NOTHING
            "#,
            &[&kind, &domain, &jti, &payload_ciphertext, &session_id, &nonce_hash],
        )
        .await
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    Ok(())
}

pub async fn claim_due(pool: &PgPool, limit: i64) -> Result<Vec<DeliveryJob>, RelayError> {
    let client = pool
        .get()
        .await
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    let rows = client
        .query(
            r#"
            UPDATE delivery_jobs
            SET attempts = attempts + 1, next_retry_at = NOW() + INTERVAL '5 seconds'
            WHERE id IN (
                SELECT id FROM delivery_jobs
                WHERE status = 'pending' AND (next_retry_at IS NULL OR next_retry_at <= NOW())
                ORDER BY id
                LIMIT $1
                FOR UPDATE SKIP LOCKED
            )
            RETURNING id, kind, domain, jti, payload_ciphertext, idempotency_key, session_id, nonce_hash, attempts, status
            "#,
            &[&limit],
        )
        .await
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    Ok(rows.iter().map(from_row).collect())
}

pub async fn mark_delivered(pool: &PgPool, id: i64) -> Result<(), RelayError> {
    let client = pool
        .get()
        .await
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    client
        .execute("UPDATE delivery_jobs SET status = 'delivered' WHERE id = $1", &[&id])
        .await
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    Ok(())
}

pub async fn mark_failed(pool: &PgPool, id: i64) -> Result<(), RelayError> {
    let client = pool
        .get()
        .await
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    client
        .execute("UPDATE delivery_jobs SET status = 'failed' WHERE id = $1", &[&id])
        .await
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    Ok(())
}
