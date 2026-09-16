use crate::crypto::at_rest::keyed_hash;
use crate::crypto::ed25519;
use crate::db::sessions::{self, InsertOutcome, NewSession};
use crate::error::{ProblemCode, RelayError};
use crate::protocol::registration::{RegistrationRequest, RegistrationResponse};
use crate::state::AppState;

pub async fn register_session(
    state: &AppState,
    request: RegistrationRequest,
) -> Result<(RegistrationResponse, bool), RelayError> {
    request.validate()?;
    if request.exp <= state.clock.now_ms() {
        return Err(RelayError::problem(ProblemCode::RequestExpired));
    }
    let metadata = state
        .site
        .fetch_metadata(&request.domain)
        .await
        .map_err(|_| {
            crate::state::Metrics::inc(&state.metrics.ssrf_rejections);
            RelayError::problem(ProblemCode::DomainVerificationFailed)
        })?;
    ed25519::verify(
        &metadata.public_key,
        &request.qr_canonical()?,
        &request.qr_signature,
    )
    .map_err(|_| RelayError::problem(ProblemCode::InvalidSignature))?;
    ed25519::verify(
        &metadata.public_key,
        &request.registration_canonical()?,
        &request.registration_signature,
    )
    .map_err(|_| RelayError::problem(ProblemCode::InvalidSignature))?;

    let nonce_hash = keyed_hash(&state.lookup_pepper, request.nonce.as_bytes())?;
    let nonce_ciphertext = state.at_rest.encrypt(request.nonce.as_bytes())?;
    let registration_hash = keyed_hash(
        &state.lookup_pepper,
        &serde_json::to_vec(&request).map_err(|_| RelayError::problem(ProblemCode::InternalError))?,
    )?;

    let mut client = state
        .pool
        .get()
        .await
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    let tx = crate::db::begin(&mut client).await?;
    let outcome = sessions::insert_registered(
        &tx,
        NewSession {
            domain: &request.domain,
            session_id: &request.session_id,
            nonce_hash: &nonce_hash,
            nonce_ciphertext: &nonce_ciphertext,
            iat: request.iat,
            exp: request.exp,
            requested_display_name: &request.requested_display_name,
            site_display_name: &metadata.display_name,
            site_public_key: &metadata.public_key,
            qr_signature: &request.qr_signature,
            registration_signature: &request.registration_signature,
            registration_hash: &registration_hash,
        },
    )
    .await?;
    tx.commit()
        .await
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;

    match outcome {
        InsertOutcome::Created => crate::state::Metrics::inc(&state.metrics.registrations),
        InsertOutcome::Identical => {}
    }

    Ok((
        RegistrationResponse {
            version: 1,
            session_id: request.session_id,
            status: "registered",
            expires_at: request.exp,
        },
        matches!(outcome, InsertOutcome::Created),
    ))
}
