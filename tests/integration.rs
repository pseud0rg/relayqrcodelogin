use pseud0_web_login_relay::constants::MATRIX_USER_ID;
use pseud0_web_login_relay::crypto::did_key;
use pseud0_web_login_relay::crypto::base64url;
use pseud0_web_login_relay::delivery::queue::process_once;
use pseud0_web_login_relay::outbound::site_client::RecordingSite;
use pseud0_web_login_relay::protocol::matrix::{self, MatrixMessage};
use pseud0_web_login_relay::room_policy::RoomSnapshot;
use pseud0_web_login_relay::services::login::{handle_inbound, InboundEvent};
use pseud0_web_login_relay::services::registration::register_session;
use pseud0_web_login_relay::state::MessageSink;
use pseud0_web_login_relay::test_support::{
    signed_metadata, signed_registration, state_with_pool, test_pool, TEST_DOMAIN, TEST_EXP, TEST_IAT,
    TEST_NONCE, TEST_SESSION,
};
use ed25519_dalek::SigningKey;
use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey as P256Key};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

fn dm(sender: &str) -> RoomSnapshot {
    RoomSnapshot {
        encrypted: true,
        is_direct: true,
        members: vec![sender.into(), MATRIX_USER_ID.into()],
        sender: sender.into(),
        relay_user_id: MATRIX_USER_ID.into(),
    }
}

fn inbound(event_id: &str, sender: &str, message: &MatrixMessage) -> InboundEvent {
    InboundEvent {
        event_id: event_id.into(),
        room_id: "!dm:pseud0.org".into(),
        sender: sender.into(),
        decrypted: true,
        redacted: false,
        body: matrix::encode(message).unwrap(),
        room: dm(sender),
    }
}

fn sign_consent(key: &P256Key, approved: bool, display: Option<&str>, sent_at: i64, challenge: &str) -> (String, String) {
    let canonical = matrix::consent_signed_bytes(
        approved,
        challenge,
        display,
        TEST_NONCE,
        TEST_SESSION,
        sent_at,
    )
    .unwrap();
    let digest = Sha256::digest(&canonical);
    let (sig, _): (Signature, _) = key.sign_prehash(&digest).unwrap();
    (
        did_key::encode_p256_did_key(&p256::PublicKey::from(key.verifying_key())),
        base64url::encode(&sig.to_bytes()),
    )
}

#[tokio::test]
async fn registration_created_identical_and_conflict() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let site_key = SigningKey::generate(&mut OsRng);
    let site = std::sync::Arc::new(RecordingSite::with_metadata(signed_metadata(TEST_DOMAIN, "Example", &site_key)));
    let (state, _, _) = state_with_pool(pool, site, TEST_IAT + 1_000).await;
    let request = signed_registration(&site_key, TEST_DOMAIN, TEST_SESSION, TEST_NONCE, TEST_IAT, TEST_EXP);
    let (_, created) = register_session(&state, request.clone()).await.unwrap();
    assert!(created);
    let (_, created_again) = register_session(&state, request).await.unwrap();
    assert!(!created_again);
    let conflict = signed_registration(
        &site_key,
        TEST_DOMAIN,
        TEST_SESSION,
        "nonce_other_value_01",
        TEST_IAT,
        TEST_EXP,
    );
    assert!(register_session(&state, conflict).await.is_err());
}

#[tokio::test]
async fn request_challenge_consent_assertion_and_result() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let site_key = SigningKey::generate(&mut OsRng);
    let site = std::sync::Arc::new(RecordingSite::with_metadata(signed_metadata(TEST_DOMAIN, "Example", &site_key)));
    let (state, sink, _) = state_with_pool(pool, site.clone(), TEST_IAT + 2_000).await;
    let request = signed_registration(&site_key, TEST_DOMAIN, TEST_SESSION, TEST_NONCE, TEST_IAT, TEST_EXP);
    register_session(&state, request).await.unwrap();

    let sender = "@alice:pseud0.org";
    handle_inbound(
        &state,
        inbound(
            "$req1",
            sender,
            &MatrixMessage::Request {
                session_id: TEST_SESSION.into(),
                nonce: TEST_NONCE.into(),
                sent_at: TEST_IAT + 1_000,
                domain: TEST_DOMAIN.into(),
            },
        ),
    )
    .await
    .unwrap();

    let recorded = sink.recorded();
    assert_eq!(recorded.len(), 1);
    let challenge = match matrix::decode(&recorded[0].body).unwrap() {
        MatrixMessage::Challenge { challenge, site_name, .. } => {
            assert_eq!(site_name, "Example");
            challenge
        }
        other => panic!("expected challenge, got {other:?}"),
    };

    let p256 = P256Key::random(&mut OsRng);
    let (key_id, signature) = sign_consent(&p256, true, Some("Alice"), TEST_IAT + 3_000, &challenge);
    handle_inbound(
        &state,
        inbound(
            "$consent1",
            sender,
            &MatrixMessage::Consent {
                session_id: TEST_SESSION.into(),
                nonce: TEST_NONCE.into(),
                sent_at: TEST_IAT + 3_000,
                approved: true,
                display_name: Some("Alice".into()),
                challenge,
                key_id,
                signature,
            },
        ),
    )
    .await
    .unwrap();

    process_once(&state).await.unwrap();
    assert!(sink.recorded().iter().any(|m| matrix::decode(&m.body).is_ok_and(|msg| {
        matches!(msg, MatrixMessage::Result { success: true, site_account_id: Some(_), reason: None, .. })
    })));
    let posts = site.posts.lock().unwrap();
    assert_eq!(posts.len(), 1);
    let assertion = String::from_utf8(posts[0].2.clone()).unwrap();
    assert!(!assertion.contains(sender));
    assert!(!assertion.contains('@'));
    assert!(!assertion.contains("!dm"));
}

#[tokio::test]
async fn delivery_retry_posts_identical_bytes_once() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let site_key = SigningKey::generate(&mut OsRng);
    let site = std::sync::Arc::new(RecordingSite::with_metadata(signed_metadata(TEST_DOMAIN, "Example", &site_key)));
    let (state, _, _) = state_with_pool(pool, site.clone(), TEST_IAT + 2_000).await;
    register_session(
        &state,
        signed_registration(&site_key, TEST_DOMAIN, TEST_SESSION, TEST_NONCE, TEST_IAT, TEST_EXP),
    )
    .await
    .unwrap();
    let sender = "@alice:pseud0.org";
    handle_inbound(
        &state,
        inbound(
            "$req-retry",
            sender,
            &MatrixMessage::Request {
                session_id: TEST_SESSION.into(),
                nonce: TEST_NONCE.into(),
                sent_at: TEST_IAT + 1_000,
                domain: TEST_DOMAIN.into(),
            },
        ),
    )
    .await
    .unwrap();
    let challenge = match matrix::decode(&state.outbox.recorded()[0].body).unwrap() {
        MatrixMessage::Challenge { challenge, .. } => challenge,
        other => panic!("expected challenge, got {other:?}"),
    };
    let p256 = P256Key::random(&mut OsRng);
    let (key_id, signature) = sign_consent(&p256, true, Some("Alice"), TEST_IAT + 3_000, &challenge);
    handle_inbound(
        &state,
        inbound(
            "$consent-retry",
            sender,
            &MatrixMessage::Consent {
                session_id: TEST_SESSION.into(),
                nonce: TEST_NONCE.into(),
                sent_at: TEST_IAT + 3_000,
                approved: true,
                display_name: Some("Alice".into()),
                challenge,
                key_id,
                signature,
            },
        ),
    )
    .await
    .unwrap();
    process_once(&state).await.unwrap();
    process_once(&state).await.unwrap();
    assert_eq!(site.posts.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn http_registration_created_identical_and_conflict() {
    let Some(pool) = test_pool().await else {
        return;
    };
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let site_key = SigningKey::generate(&mut OsRng);
    let site = std::sync::Arc::new(RecordingSite::with_metadata(signed_metadata(TEST_DOMAIN, "Example", &site_key)));
    let (state, _, _) = state_with_pool(pool, site, TEST_IAT + 1_000).await;
    let request = signed_registration(&site_key, TEST_DOMAIN, TEST_SESSION, TEST_NONCE, TEST_IAT, TEST_EXP);
    let body = serde_json::to_vec(&request).unwrap();
    let app = pseud0_web_login_relay::http::routes::router(state.clone());
    let created = app
        .oneshot(
            Request::post("/v1/site-sessions")
                .header("content-type", "application/json")
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.status(), axum::http::StatusCode::CREATED);

    let app = pseud0_web_login_relay::http::routes::router(state.clone());
    let again = app
        .oneshot(
            Request::post("/v1/site-sessions")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(again.status(), axum::http::StatusCode::OK);

    let conflict = signed_registration(
        &site_key,
        TEST_DOMAIN,
        TEST_SESSION,
        "nonce_other_value_01",
        TEST_IAT,
        TEST_EXP,
    );
    let app = pseud0_web_login_relay::http::routes::router(state);
    let response = app
        .oneshot(
            Request::post("/v1/site-sessions")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&conflict).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::CONFLICT);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&bytes);
    assert!(!text.contains('@'));
    assert!(!text.contains("alice"));
}
