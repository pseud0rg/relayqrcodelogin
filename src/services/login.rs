use rand::RngCore;

use crate::constants::{ASSERTION_PATH, CHALLENGE_BYTES, JTI_BYTES, REPLAY_GRACE_MS};
use crate::crypto::at_rest::keyed_hash;
use crate::crypto::base64url;
use crate::crypto::p256_consent;
use crate::crypto::subject;
use crate::db::{delivery, grants, replay, sessions};
use crate::error::{ProblemCode, RelayError};
use crate::protocol::assertion::RelayAssertion;
use crate::protocol::matrix::{self, MatrixMessage};
use crate::protocol::time::{challenge_expires_at, sent_at_in_qr_window};
use crate::room_policy::{check_room, RoomSnapshot};
use crate::state::{AppState, Metrics};

#[derive(Debug, Clone)]
pub struct InboundEvent {
    pub event_id: String,
    pub room_id: String,
    pub sender: String,
    pub decrypted: bool,
    pub redacted: bool,
    pub body: String,
    pub room: RoomSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandleResult {
    Ignored,
    Sent,
}

pub async fn handle_inbound(state: &AppState, event: InboundEvent) -> Result<HandleResult, RelayError> {
    if event.redacted || !event.decrypted {
        Metrics::inc(&state.metrics.room_violations);
        return Ok(HandleResult::Ignored);
    }
    if event.sender == state.relay_user_id {
        return Ok(HandleResult::Ignored);
    }
    if check_room(&event.room).is_err() {
        Metrics::inc(&state.metrics.room_violations);
        return Ok(HandleResult::Ignored);
    }
    let Ok(message) = matrix::decode(&event.body) else {
        return Ok(HandleResult::Ignored);
    };
    match message {
        MatrixMessage::Request { .. } => process_request(state, &event, message).await,
        MatrixMessage::Consent { .. } => process_consent(state, &event, message).await,
        MatrixMessage::Revocation { .. } => process_revocation(state, &event, message).await,
        _ => Ok(HandleResult::Ignored),
    }
}

async fn process_request(
    state: &AppState,
    event: &InboundEvent,
    message: MatrixMessage,
) -> Result<HandleResult, RelayError> {
    let MatrixMessage::Request {
        session_id,
        nonce,
        sent_at,
        domain,
    } = message
    else {
        return Ok(HandleResult::Ignored);
    };
    let now = state.clock.now_ms();
    let nonce_hash = keyed_hash(&state.lookup_pepper, nonce.as_bytes())?;
    let mut client = state
        .pool
        .get()
        .await
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    let tx = crate::db::begin(&mut client).await?;
    let Some(session) = sessions::get_matching(&tx, &domain, &session_id, &nonce_hash).await? else {
        return Ok(HandleResult::Ignored);
    };
    if session.exp < now || !sent_at_in_qr_window(sent_at, session.iat, session.exp) {
        return Ok(HandleResult::Ignored);
    }
    if session.challenge_hash.is_some() {
        tx.commit()
            .await
            .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
        return Ok(HandleResult::Ignored);
    }
    replay::reserve_request_event(
        &tx,
        &event.event_id,
        sessions::millis_to_utc(session.exp + REPLAY_GRACE_MS)?,
    )
    .await
    .map_err(|err| {
        Metrics::inc(&state.metrics.replay_conflicts);
        err
    })?;

    let mut challenge_bytes = vec![0u8; CHALLENGE_BYTES];
    rand::thread_rng().fill_bytes(&mut challenge_bytes);
    let challenge = base64url::encode(&challenge_bytes);
    let challenge_hash = keyed_hash(&state.lookup_pepper, challenge.as_bytes())?;
    replay::reserve_challenge_hash(
        &tx,
        &challenge_hash,
        sessions::millis_to_utc(session.exp + REPLAY_GRACE_MS)?,
    )
    .await?;

    let sent = now;
    let expires_at = challenge_expires_at(sent, session.exp);
    let room_ct = state.at_rest.encrypt(event.room_id.as_bytes())?;
    let sender_ct = state.at_rest.encrypt(event.sender.as_bytes())?;
    if !sessions::cas_update(
        &tx,
        session.id,
        session.version,
        "CHALLENGE_SENT",
        Some(&event.event_id),
        Some(&room_ct),
        Some(&sender_ct),
        Some(&challenge_hash),
        Some(expires_at),
        None,
        None,
        None,
        None,
    )
    .await?
    {
        return Err(RelayError::problem(ProblemCode::SessionConflict));
    }
    tx.commit()
        .await
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;

    let outbound = MatrixMessage::Challenge {
        session_id,
        nonce,
        sent_at: sent,
        site_name: session.site_display_name,
        domain,
        requested_display_name: session.requested_display_name,
        challenge,
        expires_at,
    };
    state
        .outbox
        .send_notice(&event.room_id, &matrix::encode(&outbound)?)
        .await?;
    Metrics::inc(&state.metrics.challenges);
    Ok(HandleResult::Sent)
}

async fn process_consent(
    state: &AppState,
    event: &InboundEvent,
    message: MatrixMessage,
) -> Result<HandleResult, RelayError> {
    let MatrixMessage::Consent {
        session_id,
        nonce,
        sent_at,
        approved,
        display_name,
        challenge,
        key_id,
        signature,
    } = message
    else {
        return Ok(HandleResult::Ignored);
    };
    let now = state.clock.now_ms();
    let nonce_hash = keyed_hash(&state.lookup_pepper, nonce.as_bytes())?;
    let challenge_hash = keyed_hash(&state.lookup_pepper, challenge.as_bytes())?;
    let signed = matrix::consent_signed_bytes(
        approved,
        &challenge,
        display_name.as_deref(),
        &nonce,
        &session_id,
        sent_at,
    )?;
    p256_consent::verify_consent_signature(&key_id, &signed, &signature)?;

    let mut client = state
        .pool
        .get()
        .await
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    let tx = crate::db::begin(&mut client).await?;
    let session = sessions::get_by_session_and_nonce(&tx, &session_id, &nonce_hash)
        .await?
        .ok_or(RelayError::problem(ProblemCode::SessionNotFound))?;

    if session.exp < now
        || !sent_at_in_qr_window(sent_at, session.iat, session.exp)
        || session
            .challenge_expires_at
            .is_some_and(|exp| sent_at > exp || now > exp)
    {
        tx.rollback()
            .await
            .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
        return send_failure(state, &event.room_id, &session_id, &nonce, "request_expired").await;
    }
    if session.challenge_hash.as_deref() != Some(challenge_hash.as_slice()) {
        return Ok(HandleResult::Ignored);
    }
    let stored_sender = session
        .request_sender_ciphertext
        .as_ref()
        .and_then(|c| state.at_rest.decrypt(c).ok())
        .and_then(|b| String::from_utf8(b).ok());
    let stored_room = session
        .request_room_ciphertext
        .as_ref()
        .and_then(|c| state.at_rest.decrypt(c).ok())
        .and_then(|b| String::from_utf8(b).ok());
    if stored_sender.as_deref() != Some(event.sender.as_str())
        || stored_room.as_deref() != Some(event.room_id.as_str())
    {
        Metrics::inc(&state.metrics.room_violations);
        return Ok(HandleResult::Ignored);
    }
    replay::reserve_consent_event(
        &tx,
        &event.event_id,
        sessions::millis_to_utc(session.exp + REPLAY_GRACE_MS)?,
    )
    .await
    .map_err(|err| {
        Metrics::inc(&state.metrics.replay_conflicts);
        err
    })?;

    if !approved {
        sessions::cas_update(
            &tx,
            session.id,
            session.version,
            "REFUSED",
            None,
            None,
            None,
            None,
            None,
            Some(&event.event_id),
            None,
            None,
            None,
        )
        .await?;
        tx.commit()
            .await
            .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
        return send_failure(state, &event.room_id, &session_id, &nonce, "request_cancelled").await;
    }

    let display = display_name.ok_or(RelayError::problem(ProblemCode::InvalidRequest))?;
    let sub = subject::derive_pairwise_sub(&state.subject_secret, &session.domain, &event.sender)?;
    let subject_hash = keyed_hash(&state.lookup_pepper, sub.as_bytes())?;
    let subject_ct = state.at_rest.encrypt(sub.as_bytes())?;
    let user_ct = state.at_rest.encrypt(event.sender.as_bytes())?;
    grants::upsert_grant(
        &tx,
        &session.domain,
        &subject_hash,
        &subject_ct,
        &user_ct,
        &session_id,
        &nonce_hash,
        state.subject_key_version,
    )
    .await?;

    let mut jti_bytes = vec![0u8; JTI_BYTES];
    rand::thread_rng().fill_bytes(&mut jti_bytes);
    let jti = base64url::encode(&jti_bytes);
    let exp = session.exp.min(now + crate::constants::MAX_TTL_MS);
    let assertion = RelayAssertion::sign(
        &state.signing_key,
        &state.signing_kid,
        session.domain.clone(),
        sub,
        session_id.clone(),
        nonce,
        jti.clone(),
        now,
        exp,
        display.clone(),
        state.subject_key_version,
    )?;
    replay::reserve_assertion_jti(
        &tx,
        &jti,
        sessions::millis_to_utc(session.exp + REPLAY_GRACE_MS)?,
    )
    .await?;
    let assertion_bytes = assertion.to_bytes()?;
    let assertion_ct = state.at_rest.encrypt(&assertion_bytes)?;
    let display_ct = state.at_rest.encrypt(display.as_bytes())?;
    sessions::cas_update(
        &tx,
        session.id,
        session.version,
        "CONSENT_RECEIVED",
        None,
        None,
        None,
        None,
        None,
        Some(&event.event_id),
        Some(&display_ct),
        Some(&jti),
        Some(&assertion_ct),
    )
    .await?;
    delivery::enqueue(
        &tx,
        "assertion",
        &session.domain,
        &jti,
        &assertion_ct,
        &session_id,
        &nonce_hash,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    Metrics::inc(&state.metrics.consents);
    let _ = ASSERTION_PATH;
    Ok(HandleResult::Sent)
}

async fn process_revocation(
    state: &AppState,
    event: &InboundEvent,
    message: MatrixMessage,
) -> Result<HandleResult, RelayError> {
    let MatrixMessage::Revocation {
        session_id,
        nonce,
        site_account_id,
        reason,
        ..
    } = message
    else {
        return Ok(HandleResult::Ignored);
    };
    let reason = reason.unwrap_or_else(|| "user_requested".into());
    let nonce_hash = keyed_hash(&state.lookup_pepper, nonce.as_bytes())?;
    let subject_hash = keyed_hash(&state.lookup_pepper, site_account_id.as_bytes())?;
    let mut client = state
        .pool
        .get()
        .await
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    let tx = crate::db::begin(&mut client).await?;
    let Some(session) = sessions::get_by_session_and_nonce(&tx, &session_id, &nonce_hash).await? else {
        return Ok(HandleResult::Ignored);
    };
    let Some(grant) = grants::find_active_grant(&tx, &session.domain, &subject_hash).await? else {
        return Ok(HandleResult::Ignored);
    };
    let stored_user = String::from_utf8(state.at_rest.decrypt(&grant.matrix_user_ciphertext)?)
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    if stored_user != event.sender {
        return Ok(HandleResult::Ignored);
    }
    if grant.revoked_at.is_some() {
        tx.commit()
            .await
            .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
        return Ok(HandleResult::Ignored);
    }
    grants::mark_revoked(&tx, grant.id).await?;
    let mut jti_bytes = vec![0u8; JTI_BYTES];
    rand::thread_rng().fill_bytes(&mut jti_bytes);
    let jti = base64url::encode(&jti_bytes);
    replay::reserve_revocation_jti(
        &tx,
        &jti,
        sessions::millis_to_utc(state.clock.now_ms() + REPLAY_GRACE_MS)?,
    )
    .await?;
    let revocation = crate::protocol::revocation::RelayRevocation::sign(
        &state.signing_key,
        &state.signing_kid,
        session.domain.clone(),
        site_account_id,
        jti.clone(),
        state.clock.now_ms(),
        reason,
    )?;
    let payload_ct = state.at_rest.encrypt(&revocation.to_bytes()?)?;
    delivery::enqueue(
        &tx,
        "revocation",
        &session.domain,
        &jti,
        &payload_ct,
        &session_id,
        &nonce_hash,
    )
    .await?;
    sessions::cas_update(
        &tx,
        session.id,
        session.version,
        "REVOKED",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    Ok(HandleResult::Sent)
}

async fn send_failure(
    state: &AppState,
    room_id: &str,
    session_id: &str,
    nonce: &str,
    reason: &str,
) -> Result<HandleResult, RelayError> {
    let message = MatrixMessage::Result {
        session_id: session_id.to_string(),
        nonce: nonce.to_string(),
        sent_at: state.clock.now_ms(),
        success: false,
        site_account_id: None,
        reason: Some(reason.to_string()),
    };
    state
        .outbox
        .send_notice(room_id, &matrix::encode(&message)?)
        .await?;
    Ok(HandleResult::Sent)
}

pub async fn send_success_result(
    state: &AppState,
    room_id: &str,
    session_id: &str,
    nonce: &str,
    sub: &str,
) -> Result<(), RelayError> {
    let message = MatrixMessage::Result {
        session_id: session_id.to_string(),
        nonce: nonce.to_string(),
        sent_at: state.clock.now_ms(),
        success: true,
        site_account_id: Some(sub.to_string()),
        reason: None,
    };
    state
        .outbox
        .send_notice(room_id, &matrix::encode(&message)?)
        .await
}
