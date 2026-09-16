use std::time::Duration;

use crate::constants::{ASSERTION_PATH, REVOCATION_PATH};
use crate::crypto::at_rest::keyed_hash;
use crate::db::{delivery, sessions};
use crate::error::{ProblemCode, RelayError};
use crate::protocol::assertion::RelayAssertion;
use crate::services::login::send_success_result;
use crate::state::{AppState, Metrics};

pub async fn run_loop(state: AppState, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow() {
            break;
        }
        if let Err(error) = tick(&state).await {
            tracing::warn!(code = error.code().as_str(), "delivery tick failed");
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
        }
    }
}

pub async fn process_once(state: &AppState) -> Result<(), RelayError> {
    tick(state).await
}

async fn tick(state: &AppState) -> Result<(), RelayError> {
    let jobs = delivery::claim_due(&state.pool, 10).await?;
    for job in jobs {
        match deliver(state, &job).await {
            Ok(()) => {
                delivery::mark_delivered(&state.pool, job.id).await?;
                Metrics::inc(&state.metrics.deliveries);
            }
            Err(error) if job.attempts >= 8 => {
                tracing::warn!(code = error.code().as_str(), "delivery exhausted");
                delivery::mark_failed(&state.pool, job.id).await?;
            }
            Err(error) => {
                tracing::warn!(code = error.code().as_str(), "delivery retry scheduled");
            }
        }
    }
    Ok(())
}

async fn deliver(state: &AppState, job: &delivery::DeliveryJob) -> Result<(), RelayError> {
    let payload = state.at_rest.decrypt(&job.payload_ciphertext)?;
    let path = match job.kind.as_str() {
        "assertion" => ASSERTION_PATH,
        "revocation" => REVOCATION_PATH,
        _ => return Err(RelayError::problem(ProblemCode::InternalError)),
    };
    let idempotency = if job.kind == "assertion" {
        Some(job.jti.as_str())
    } else {
        None
    };
    let response = state
        .site
        .post_json(&job.domain, path, &payload, idempotency)
        .await?;
    if response.status != 202 && response.status != 200 {
        return Err(RelayError::problem(ProblemCode::RelayUnavailable));
    }
    if job.kind == "assertion" {
        after_assertion_accepted(state, job, &payload).await?;
    }
    Ok(())
}

async fn after_assertion_accepted(
    state: &AppState,
    job: &delivery::DeliveryJob,
    payload: &[u8],
) -> Result<(), RelayError> {
    let assertion: RelayAssertion = crate::json::strict::from_slice(payload)?;
    let mut client = state
        .pool
        .get()
        .await
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    let tx = crate::db::begin(&mut client).await?;
    let Some(session) = sessions::get_matching(&tx, &job.domain, &job.session_id, &job.nonce_hash).await?
    else {
        return Ok(());
    };
    let room = session
        .request_room_ciphertext
        .as_ref()
        .ok_or(RelayError::problem(ProblemCode::InternalError))?;
    let room_id = String::from_utf8(state.at_rest.decrypt(room)?)
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    let nonce = String::from_utf8(state.at_rest.decrypt(&session.nonce_ciphertext)?)
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    sessions::cas_update(
        &tx,
        session.id,
        session.version,
        "ASSERTION_DELIVERED",
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
    let _ = keyed_hash;
    send_success_result(state, &room_id, &job.session_id, &nonce, &assertion.sub).await
}
