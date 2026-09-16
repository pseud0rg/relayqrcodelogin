use chrono::{TimeZone, Utc};
use tokio_postgres::Row;

use crate::constants::REPLAY_GRACE_MS;
use tokio_postgres::GenericClient;

use crate::db::is_unique_violation;
use crate::error::{ProblemCode, RelayError};

#[derive(Debug, Clone)]
pub struct SessionRow {
    pub id: i64,
    pub domain: String,
    pub session_id: String,
    pub nonce_hash: Vec<u8>,
    pub nonce_ciphertext: Vec<u8>,
    pub iat: i64,
    pub exp: i64,
    pub requested_display_name: String,
    pub site_display_name: String,
    pub site_public_key: String,
    pub qr_signature: String,
    pub registration_signature: String,
    pub registration_hash: Vec<u8>,
    pub state: String,
    pub version: i32,
    pub request_event_id: Option<String>,
    pub request_room_ciphertext: Option<Vec<u8>>,
    pub request_sender_ciphertext: Option<Vec<u8>>,
    pub challenge_hash: Option<Vec<u8>>,
    pub challenge_expires_at: Option<i64>,
    pub consent_event_id: Option<String>,
    pub display_name_ciphertext: Option<Vec<u8>>,
    pub assertion_jti: Option<String>,
    pub assertion_ciphertext: Option<Vec<u8>>,
}

impl SessionRow {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.state.as_str(),
            "REFUSED" | "ASSERTION_DELIVERED" | "EXPIRED" | "CANCELLED" | "REVOKED"
        )
    }
}

pub struct NewSession<'a> {
    pub domain: &'a str,
    pub session_id: &'a str,
    pub nonce_hash: &'a [u8],
    pub nonce_ciphertext: &'a [u8],
    pub iat: i64,
    pub exp: i64,
    pub requested_display_name: &'a str,
    pub site_display_name: &'a str,
    pub site_public_key: &'a str,
    pub qr_signature: &'a str,
    pub registration_signature: &'a str,
    pub registration_hash: &'a [u8],
}

fn from_row(row: &Row) -> SessionRow {
    SessionRow {
        id: row.get("id"),
        domain: row.get("domain"),
        session_id: row.get("session_id"),
        nonce_hash: row.get("nonce_hash"),
        nonce_ciphertext: row.get("nonce_ciphertext"),
        iat: row.get("iat"),
        exp: row.get("exp"),
        requested_display_name: row.get("requested_display_name"),
        site_display_name: row.get("site_display_name"),
        site_public_key: row.get("site_public_key"),
        qr_signature: row.get("qr_signature"),
        registration_signature: row.get("registration_signature"),
        registration_hash: row.get("registration_hash"),
        state: row.get("state"),
        version: row.get("version"),
        request_event_id: row.get("request_event_id"),
        request_room_ciphertext: row.get("request_room_ciphertext"),
        request_sender_ciphertext: row.get("request_sender_ciphertext"),
        challenge_hash: row.get("challenge_hash"),
        challenge_expires_at: row.get("challenge_expires_at"),
        consent_event_id: row.get("consent_event_id"),
        display_name_ciphertext: row.get("display_name_ciphertext"),
        assertion_jti: row.get("assertion_jti"),
        assertion_ciphertext: row.get("assertion_ciphertext"),
    }
}

pub async fn insert_registered(client: &impl GenericClient, session: NewSession<'_>) -> Result<InsertOutcome, RelayError> {
    let expires_at = millis_to_utc(session.exp + REPLAY_GRACE_MS)?;
    let result = client
        .execute(
            r#"
            INSERT INTO sessions (
                domain, session_id, nonce_hash, nonce_ciphertext, iat, exp,
                requested_display_name, site_display_name, site_public_key,
                qr_signature, registration_signature, registration_hash,
                state, expires_at
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'SITE_REGISTERED',$13)
            ON CONFLICT DO NOTHING
            "#,
            &[
                &session.domain,
                &session.session_id,
                &session.nonce_hash,
                &session.nonce_ciphertext,
                &session.iat,
                &session.exp,
                &session.requested_display_name,
                &session.site_display_name,
                &session.site_public_key,
                &session.qr_signature,
                &session.registration_signature,
                &session.registration_hash,
                &expires_at,
            ],
        )
        .await
        .map_err(conflict_or_internal)?;

    if result == 1 {
        return Ok(InsertOutcome::Created);
    }
    if let Some(existing) = get_by_session(client, session.domain, session.session_id).await? {
        if existing.registration_hash == session.registration_hash
            && existing.nonce_hash == session.nonce_hash
            && existing.qr_signature == session.qr_signature
            && existing.registration_signature == session.registration_signature
        {
            return Ok(InsertOutcome::Identical);
        }
        return Err(RelayError::problem(ProblemCode::SessionConflict));
    }
    Err(RelayError::problem(ProblemCode::SessionConflict))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertOutcome {
    Created,
    Identical,
}

pub async fn get_by_session(
    client: &impl GenericClient,
    domain: &str,
    session_id: &str,
) -> Result<Option<SessionRow>, RelayError> {
    let row = client
        .query_opt(
            "SELECT * FROM sessions WHERE domain = $1 AND session_id = $2 FOR UPDATE",
            &[&domain, &session_id],
        )
        .await
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    Ok(row.as_ref().map(from_row))
}

pub async fn get_by_session_and_nonce(
    client: &impl GenericClient,
    session_id: &str,
    nonce_hash: &[u8],
) -> Result<Option<SessionRow>, RelayError> {
    let row = client
        .query_opt(
            "SELECT * FROM sessions WHERE session_id = $1 AND nonce_hash = $2 FOR UPDATE",
            &[&session_id, &nonce_hash],
        )
        .await
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    Ok(row.as_ref().map(from_row))
}

pub async fn get_matching(
    client: &impl GenericClient,
    domain: &str,
    session_id: &str,
    nonce_hash: &[u8],
) -> Result<Option<SessionRow>, RelayError> {
    let row = client
        .query_opt(
            "SELECT * FROM sessions WHERE domain = $1 AND session_id = $2 AND nonce_hash = $3 FOR UPDATE",
            &[&domain, &session_id, &nonce_hash],
        )
        .await
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    Ok(row.as_ref().map(from_row))
}

pub async fn cas_update(
    client: &impl GenericClient,
    id: i64,
    expected_version: i32,
    state: &str,
    request_event_id: Option<&str>,
    request_room_ciphertext: Option<&[u8]>,
    request_sender_ciphertext: Option<&[u8]>,
    challenge_hash: Option<&[u8]>,
    challenge_expires_at: Option<i64>,
    consent_event_id: Option<&str>,
    display_name_ciphertext: Option<&[u8]>,
    assertion_jti: Option<&str>,
    assertion_ciphertext: Option<&[u8]>,
) -> Result<bool, RelayError> {
    let updated = client
        .execute(
            r#"
            UPDATE sessions SET
                state = $3,
                version = version + 1,
                request_event_id = COALESCE($4, request_event_id),
                request_room_ciphertext = COALESCE($5, request_room_ciphertext),
                request_sender_ciphertext = COALESCE($6, request_sender_ciphertext),
                challenge_hash = COALESCE($7, challenge_hash),
                challenge_expires_at = COALESCE($8, challenge_expires_at),
                consent_event_id = COALESCE($9, consent_event_id),
                display_name_ciphertext = COALESCE($10, display_name_ciphertext),
                assertion_jti = COALESCE($11, assertion_jti),
                assertion_ciphertext = COALESCE($12, assertion_ciphertext)
            WHERE id = $1 AND version = $2
            "#,
            &[
                &id,
                &expected_version,
                &state,
                &request_event_id,
                &request_room_ciphertext,
                &request_sender_ciphertext,
                &challenge_hash,
                &challenge_expires_at,
                &consent_event_id,
                &display_name_ciphertext,
                &assertion_jti,
                &assertion_ciphertext,
            ],
        )
        .await
        .map_err(conflict_or_internal)?;
    Ok(updated == 1)
}

pub fn millis_to_utc(ms: i64) -> Result<chrono::DateTime<Utc>, RelayError> {
    Utc.timestamp_millis_opt(ms)
        .single()
        .ok_or(RelayError::problem(ProblemCode::InvalidRequest))
}

fn conflict_or_internal(err: tokio_postgres::Error) -> RelayError {
    if is_unique_violation(&err) {
        RelayError::problem(ProblemCode::SessionConflict)
    } else {
        RelayError::problem(ProblemCode::InternalError)
    }
}
