use pseud0_web_login_relay::constants::MATRIX_USER_ID;
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
use rand::rngs::OsRng;

fn inbound(event_id: &str, sender: &str, message: &MatrixMessage) -> InboundEvent {
    InboundEvent {
        event_id: event_id.into(),
        room_id: "!dm:pseud0.org".into(),
        sender: sender.into(),
        decrypted: true,
        redacted: false,
        body: matrix::encode(message).unwrap(),
        room: RoomSnapshot {
            encrypted: true,
            is_direct: true,
            members: vec![sender.into(), MATRIX_USER_ID.into()],
            sender: sender.into(),
            relay_user_id: MATRIX_USER_ID.into(),
        },
    }
}

#[tokio::test]
async fn duplicate_request_does_not_mint_second_challenge() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let site_key = SigningKey::generate(&mut OsRng);
    let site = std::sync::Arc::new(RecordingSite::with_metadata(signed_metadata(TEST_DOMAIN, "Example", &site_key)));
    let (state, sink, _) = state_with_pool(pool, site, TEST_IAT + 2_000).await;
    register_session(
        &state,
        signed_registration(&site_key, TEST_DOMAIN, TEST_SESSION, TEST_NONCE, TEST_IAT, TEST_EXP),
    )
    .await
    .unwrap();
    let request = MatrixMessage::Request {
        session_id: TEST_SESSION.into(),
        nonce: TEST_NONCE.into(),
        sent_at: TEST_IAT + 1_000,
        domain: TEST_DOMAIN.into(),
    };
    handle_inbound(&state, inbound("$req1", "@alice:pseud0.org", &request))
        .await
        .unwrap();
    handle_inbound(&state, inbound("$req2", "@alice:pseud0.org", &request))
        .await
        .unwrap();
    assert_eq!(sink.recorded().len(), 1);
}

#[tokio::test]
async fn same_request_event_id_is_atomic_replay() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let site_key = SigningKey::generate(&mut OsRng);
    let site = std::sync::Arc::new(RecordingSite::with_metadata(signed_metadata(TEST_DOMAIN, "Example", &site_key)));
    let (state, sink, _) = state_with_pool(pool, site, TEST_IAT + 2_000).await;
    register_session(
        &state,
        signed_registration(
            &site_key,
            TEST_DOMAIN,
            "session_replay_00001",
            "nonce_replay_0000001",
            TEST_IAT,
            TEST_EXP,
        ),
    )
    .await
    .unwrap();
    let request = MatrixMessage::Request {
        session_id: "session_replay_00001".into(),
        nonce: "nonce_replay_0000001".into(),
        sent_at: TEST_IAT + 1_000,
        domain: TEST_DOMAIN.into(),
    };
    let first = handle_inbound(&state, inbound("$same", "@alice:pseud0.org", &request)).await;
    let second = handle_inbound(&state, inbound("$same", "@alice:pseud0.org", &request)).await;
    assert!(first.is_ok());
    assert!(second.is_err() || sink.recorded().len() == 1);
}

#[tokio::test]
async fn assertion_jti_conflict_is_atomic() {
    let Some(pool) = test_pool().await else {
        return;
    };
    use chrono::Utc;
    use pseud0_web_login_relay::db::replay;
    let site_key = SigningKey::generate(&mut OsRng);
    let site = std::sync::Arc::new(RecordingSite::with_metadata(signed_metadata(TEST_DOMAIN, "Example", &site_key)));
    let (state, _, _) = state_with_pool(pool, site, TEST_IAT + 2_000).await;
    let mut client = state.pool.get().await.unwrap();
    let exp = Utc::now() + chrono::Duration::seconds(60);
    {
        let tx = pseud0_web_login_relay::db::begin(&mut client).await.unwrap();
        replay::reserve_assertion_jti(&tx, "jti_conflict_vector_01", exp)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    let tx = pseud0_web_login_relay::db::begin(&mut client).await.unwrap();
    let replayed = replay::reserve_assertion_jti(&tx, "jti_conflict_vector_01", exp).await;
    assert!(replayed.is_err());
}

#[tokio::test]
async fn revocation_enqueues_one_site_callback() {
    let Some(pool) = test_pool().await else {
        return;
    };
    use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey as P256Key};
    use pseud0_web_login_relay::crypto::base64url;
    use pseud0_web_login_relay::crypto::did_key;
    use pseud0_web_login_relay::delivery::queue::process_once;
    use sha2::{Digest, Sha256};

    let site_key = SigningKey::generate(&mut OsRng);
    let site = std::sync::Arc::new(RecordingSite::with_metadata(signed_metadata(TEST_DOMAIN, "Example", &site_key)));
    let (state, sink, _) = state_with_pool(pool, site.clone(), TEST_IAT + 2_000).await;
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
            "$req-rev",
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
    let challenge = match matrix::decode(&sink.recorded()[0].body).unwrap() {
        MatrixMessage::Challenge { challenge, .. } => challenge,
        other => panic!("expected challenge, got {other:?}"),
    };
    let p256 = P256Key::random(&mut OsRng);
    let canonical = matrix::consent_signed_bytes(
        true,
        &challenge,
        Some("Alice"),
        TEST_NONCE,
        TEST_SESSION,
        TEST_IAT + 3_000,
    )
    .unwrap();
    let digest = Sha256::digest(&canonical);
    let (sig, _): (Signature, _) = p256.sign_prehash(&digest).unwrap();
    handle_inbound(
        &state,
        inbound(
            "$consent-rev",
            sender,
            &MatrixMessage::Consent {
                session_id: TEST_SESSION.into(),
                nonce: TEST_NONCE.into(),
                sent_at: TEST_IAT + 3_000,
                approved: true,
                display_name: Some("Alice".into()),
                challenge,
                key_id: did_key::encode_p256_did_key(&p256::PublicKey::from(p256.verifying_key())),
                signature: base64url::encode(&sig.to_bytes()),
            },
        ),
    )
    .await
    .unwrap();
    process_once(&state).await.unwrap();
    let site_account_id = sink.recorded().iter().find_map(|m| match matrix::decode(&m.body) {
        Ok(MatrixMessage::Result {
            site_account_id: Some(id),
            ..
        }) => Some(id),
        _ => None,
    });
    let Some(site_account_id) = site_account_id else {
        panic!("missing pairwise subject in Result");
    };
    handle_inbound(
        &state,
        inbound(
            "$rev1",
            sender,
            &MatrixMessage::Revocation {
                session_id: TEST_SESSION.into(),
                nonce: TEST_NONCE.into(),
                sent_at: TEST_IAT + 4_000,
                site_account_id,
                reason: Some("user_requested".into()),
            },
        ),
    )
    .await
    .unwrap();
    process_once(&state).await.unwrap();
    let posts = site.posts.lock().unwrap();
    assert_eq!(posts.len(), 2);
    assert!(posts.iter().any(|(_, path, _)| path.ends_with("/revocations")));
    assert!(posts.iter().all(|(_, _, body)| !String::from_utf8_lossy(body).contains(sender)));
}
