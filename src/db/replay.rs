use chrono::{DateTime, Utc};

use tokio_postgres::GenericClient;

use crate::db::is_unique_violation;
use crate::error::{ProblemCode, RelayError};

pub async fn reserve_request_event(
    client: &impl GenericClient,
    event_id: &str,
    expires_at: DateTime<Utc>,
) -> Result<(), RelayError> {
    insert_text(client, "replay_request_event_ids", "event_id", event_id, expires_at, ProblemCode::ChallengeReplayed).await
}

pub async fn reserve_challenge_hash(
    client: &impl GenericClient,
    hash: &[u8],
    expires_at: DateTime<Utc>,
) -> Result<(), RelayError> {
    let result = client
        .execute(
            "INSERT INTO replay_challenge_hashes (challenge_hash, expires_at) VALUES ($1, $2)",
            &[&hash, &expires_at],
        )
        .await;
    map_unique(result, ProblemCode::ChallengeReplayed)
}

pub async fn reserve_consent_event(
    client: &impl GenericClient,
    event_id: &str,
    expires_at: DateTime<Utc>,
) -> Result<(), RelayError> {
    insert_text(client, "replay_consent_event_ids", "event_id", event_id, expires_at, ProblemCode::ConsentReplayed).await
}

pub async fn reserve_assertion_jti(
    client: &impl GenericClient,
    jti: &str,
    expires_at: DateTime<Utc>,
) -> Result<(), RelayError> {
    insert_text(client, "replay_assertion_jtis", "jti", jti, expires_at, ProblemCode::AssertionReplayed).await
}

pub async fn reserve_revocation_jti(
    client: &impl GenericClient,
    jti: &str,
    expires_at: DateTime<Utc>,
) -> Result<(), RelayError> {
    insert_text(client, "replay_revocation_jtis", "jti", jti, expires_at, ProblemCode::AssertionReplayed).await
}

async fn insert_text(
    client: &impl GenericClient,
    table: &str,
    column: &str,
    value: &str,
    expires_at: DateTime<Utc>,
    conflict: ProblemCode,
) -> Result<(), RelayError> {
    let sql = format!("INSERT INTO {table} ({column}, expires_at) VALUES ($1, $2)");
    map_unique(client.execute(&sql, &[&value, &expires_at]).await, conflict)
}

fn map_unique(result: Result<u64, tokio_postgres::Error>, conflict: ProblemCode) -> Result<(), RelayError> {
    match result {
        Ok(_) => Ok(()),
        Err(err) if is_unique_violation(&err) => Err(RelayError::problem(conflict)),
        Err(_) => Err(RelayError::problem(ProblemCode::InternalError)),
    }
}
