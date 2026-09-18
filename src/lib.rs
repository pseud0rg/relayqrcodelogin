pub mod clock;
pub mod config;
pub mod constants;
pub mod crypto;
pub mod db;
pub mod delivery;
pub mod error;
pub mod http;
pub mod json;
pub mod matrix;
pub mod outbound;
pub mod protocol;
pub mod room_policy;
pub mod services;
pub mod state;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64};

use crate::clock::SystemClock;
use crate::config::AppConfig;
use crate::constants::ADVISORY_LOCK_KEY;
use crate::error::{ProblemCode, RelayError};
use crate::outbound::site_client::SsrfSiteClient;
use crate::state::{AppState, Metrics, NoopSink};

pub async fn run() -> Result<(), RelayError> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .init();
    let _ = rustls::crypto::ring::default_provider().install_default();

    let config = AppConfig::from_env()?;
    let pool = db::connect(&config.database_url)
        .await
        .map_err(|_| RelayError::problem(ProblemCode::RelayUnavailable))?;

    if config.matrix_enabled
        && !db::try_advisory_lock(&pool, ADVISORY_LOCK_KEY)
            .await
            .map_err(|_| RelayError::problem(ProblemCode::RelayUnavailable))?
    {
        return Err(RelayError::problem(ProblemCode::RelayUnavailable));
    }

    let sync_ready = Arc::new(AtomicBool::new(!config.matrix_enabled));
    let last_matrix_sync_ms = Arc::new(AtomicI64::new(if config.matrix_enabled {
        0
    } else {
        crate::clock::Clock::now_ms(&SystemClock)
    }));
    #[allow(unused_mut)]
    let mut state = AppState {
        pool: pool.clone(),
        clock: Arc::new(SystemClock),
        site: Arc::new(SsrfSiteClient::production()),
        outbox: Arc::new(NoopSink),
        at_rest: config.at_rest.clone(),
        lookup_pepper: config.lookup_pepper.clone(),
        subject_secret: config.subject_secret.clone(),
        subject_key_version: config.subject_key_version,
        signing_key: config.signing_key.clone(),
        signing_kid: config.signing_kid.clone(),
        relay_user_id: config.matrix_user_id.clone(),
        sync_ready: sync_ready.clone(),
        last_matrix_sync_ms,
        metrics: Arc::new(Metrics::default()),
    };

    #[cfg(feature = "matrix")]
    let matrix_runtime = if config.matrix_enabled {
        let runtime = crate::matrix::client::MatrixRuntime::start(&config).await?;
        state.outbox = runtime.sink();
        Some(runtime)
    } else {
        let _ = crate::matrix::client::lock_crypto_store(&config.crypto_store_path);
        None
    };

    #[cfg(not(feature = "matrix"))]
    if config.matrix_enabled {
        return Err(RelayError::problem(ProblemCode::InternalError));
    }

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let delivery_state = state.clone();
    let delivery_rx = shutdown_rx.clone();
    tokio::spawn(async move {
        crate::delivery::queue::run_loop(delivery_state, delivery_rx).await;
    });

    #[cfg(feature = "matrix")]
    if let Some(runtime) = matrix_runtime {
        let sync_state = state.clone();
        // matrix-sdk 0.14's sync future is too deep for rustc to prove Send
        // (overflow on Windows GNU). A dedicated current-thread runtime avoids
        // tokio::spawn's Send bound while keeping a single leader sync.
        std::thread::Builder::new()
            .name("matrix-sync".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("matrix sync runtime");
                rt.block_on(crate::matrix::client::sync_forever(sync_state, runtime));
            })
            .map_err(|_| RelayError::problem(ProblemCode::RelayUnavailable))?;
    }

    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .map_err(|_| RelayError::problem(ProblemCode::RelayUnavailable))?;
    tracing::info!("relay listening");
    axum::serve(listener, crate::http::routes::router(state))
        .with_graceful_shutdown(async move {
            let _ = tokio::signal::ctrl_c().await;
            let _ = shutdown_tx.send(true);
        })
        .await
        .map_err(|_| RelayError::problem(ProblemCode::RelayUnavailable))?;
    Ok(())
}

pub mod test_support {
    use super::*;
    use crate::clock::FrozenClock;
    use crate::crypto::at_rest::AtRestKey;
    use crate::crypto::ed25519;
    use crate::crypto::jcs;
    use crate::outbound::site_client::RecordingSite;
    use crate::protocol::metadata::SiteMetadata;
    use crate::protocol::registration::RegistrationRequest;
    use crate::state::RecordingSink;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use std::sync::Arc;

    pub fn test_keys() -> (SigningKey, AtRestKey, Vec<u8>, Vec<u8>) {
        let signing = SigningKey::generate(&mut OsRng);
        let at_rest = AtRestKey::from_bytes(&[11u8; 32]).unwrap();
        (signing, at_rest, vec![13u8; 32], vec![17u8; 32])
    }

    pub const TEST_IAT: i64 = 1_800_000_000_000;
    pub const TEST_EXP: i64 = 1_800_000_300_000;
    pub const TEST_DOMAIN: &str = "login.example.org";
    pub const TEST_SESSION: &str = "session_123456789";
    pub const TEST_NONCE: &str = "nonce_12345678901";

    pub fn signed_metadata(
        domain: &str,
        display_name: &str,
        site_key: &SigningKey,
    ) -> SiteMetadata {
        use crate::crypto::base64url;
        use crate::crypto::jcs;
        let public = base64url::encode(&ed25519::public_key_raw(site_key));
        let canonical = jcs::canonicalize_object(&[
            ("displayName", serde_json::json!(display_name)),
            ("domain", serde_json::json!(domain)),
            ("publicKey", serde_json::json!(public)),
            ("version", serde_json::json!(1)),
        ])
        .unwrap();
        SiteMetadata {
            version: 1,
            domain: domain.into(),
            display_name: display_name.into(),
            public_key: public,
            signature: ed25519::sign(site_key, canonical.as_bytes()),
        }
    }

    pub async fn state_with_pool(
        pool: crate::db::PgPool,
        site: Arc<RecordingSite>,
        clock_ms: i64,
    ) -> (AppState, Arc<RecordingSink>, SigningKey) {
        reset_tables(&pool).await;
        let (signing, at_rest, subject, pepper) = test_keys();
        let sink = Arc::new(RecordingSink::default());
        let state = AppState {
            pool,
            clock: Arc::new(FrozenClock::new(clock_ms)),
            site: site,
            outbox: sink.clone(),
            at_rest,
            lookup_pepper: pepper,
            subject_secret: subject,
            subject_key_version: 1,
            signing_key: signing.clone(),
            signing_kid: crate::constants::DEFAULT_KID.into(),
            relay_user_id: crate::constants::MATRIX_USER_ID.into(),
            sync_ready: Arc::new(AtomicBool::new(true)),
            last_matrix_sync_ms: Arc::new(AtomicI64::new(clock_ms)),
            metrics: Arc::new(Metrics::default()),
        };
        (state, sink, signing)
    }

    pub fn signed_registration(
        site_key: &SigningKey,
        domain: &str,
        session: &str,
        nonce: &str,
        iat: i64,
        exp: i64,
    ) -> RegistrationRequest {
        let qr = jcs::canonicalize_object(&[
            ("domain", serde_json::json!(domain)),
            ("exp", serde_json::json!(exp)),
            ("iat", serde_json::json!(iat)),
            ("nonce", serde_json::json!(nonce)),
            ("session", serde_json::json!(session)),
            ("v", serde_json::json!(1)),
        ])
        .unwrap();
        let qr_signature = ed25519::sign(site_key, qr.as_bytes());
        let registration = jcs::canonicalize_object(&[
            ("domain", serde_json::json!(domain)),
            ("exp", serde_json::json!(exp)),
            ("iat", serde_json::json!(iat)),
            ("nonce", serde_json::json!(nonce)),
            ("qrSignature", serde_json::json!(qr_signature)),
            ("requestedDisplayName", serde_json::json!("")),
            ("sessionId", serde_json::json!(session)),
            ("version", serde_json::json!(1)),
        ])
        .unwrap();
        RegistrationRequest {
            version: 1,
            domain: domain.into(),
            session_id: session.into(),
            nonce: nonce.into(),
            iat,
            exp,
            requested_display_name: String::new(),
            qr_signature,
            registration_signature: ed25519::sign(site_key, registration.as_bytes()),
        }
    }

    pub async fn test_pool() -> Option<crate::db::PgPool> {
        let url = std::env::var("TEST_DATABASE_URL").ok()?;
        crate::db::connect(&url).await.ok()
    }

    pub async fn reset_tables(pool: &crate::db::PgPool) {
        if let Ok(client) = pool.get().await {
            let _ = client
                .batch_execute(
                    r#"
                    TRUNCATE
                        delivery_jobs,
                        grants,
                        sessions,
                        replay_request_event_ids,
                        replay_challenge_hashes,
                        replay_consent_event_ids,
                        replay_assertion_jtis,
                        replay_revocation_jtis
                    RESTART IDENTITY CASCADE
                    "#,
                )
                .await;
        }
    }
}
