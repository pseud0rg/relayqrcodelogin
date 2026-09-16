use tokio_postgres::Row;

use tokio_postgres::GenericClient;
use crate::error::{ProblemCode, RelayError};

#[derive(Debug, Clone)]
pub struct GrantRow {
    pub id: i64,
    pub domain: String,
    pub subject_hash: Vec<u8>,
    pub subject_ciphertext: Vec<u8>,
    pub matrix_user_ciphertext: Vec<u8>,
    pub session_id: String,
    pub nonce_hash: Vec<u8>,
    pub subject_key_version: i32,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

fn from_row(row: &Row) -> GrantRow {
    GrantRow {
        id: row.get("id"),
        domain: row.get("domain"),
        subject_hash: row.get("subject_hash"),
        subject_ciphertext: row.get("subject_ciphertext"),
        matrix_user_ciphertext: row.get("matrix_user_ciphertext"),
        session_id: row.get("session_id"),
        nonce_hash: row.get("nonce_hash"),
        subject_key_version: row.get("subject_key_version"),
        revoked_at: row.get("revoked_at"),
    }
}

pub async fn upsert_grant(
    client: &impl GenericClient,
    domain: &str,
    subject_hash: &[u8],
    subject_ciphertext: &[u8],
    matrix_user_ciphertext: &[u8],
    session_id: &str,
    nonce_hash: &[u8],
    subject_key_version: i32,
) -> Result<GrantRow, RelayError> {
    let row = client
        .query_one(
            r#"
            INSERT INTO grants (
                domain, subject_hash, subject_ciphertext, matrix_user_ciphertext,
                session_id, nonce_hash, subject_key_version
            ) VALUES ($1,$2,$3,$4,$5,$6,$7)
            ON CONFLICT (domain, subject_hash) DO UPDATE SET
                session_id = EXCLUDED.session_id,
                nonce_hash = EXCLUDED.nonce_hash,
                revoked_at = NULL
            RETURNING *
            "#,
            &[
                &domain,
                &subject_hash,
                &subject_ciphertext,
                &matrix_user_ciphertext,
                &session_id,
                &nonce_hash,
                &subject_key_version,
            ],
        )
        .await
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    Ok(from_row(&row))
}

pub async fn find_active_grant(
    client: &impl GenericClient,
    domain: &str,
    subject_hash: &[u8],
) -> Result<Option<GrantRow>, RelayError> {
    let row = client
        .query_opt(
            "SELECT * FROM grants WHERE domain = $1 AND subject_hash = $2 FOR UPDATE",
            &[&domain, &subject_hash],
        )
        .await
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    Ok(row.as_ref().map(from_row))
}

pub async fn mark_revoked(client: &impl GenericClient, id: i64) -> Result<(), RelayError> {
    client
        .execute(
            "UPDATE grants SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL",
            &[&id],
        )
        .await
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    Ok(())
}
