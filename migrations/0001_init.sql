CREATE TABLE sessions (
    id                          BIGSERIAL PRIMARY KEY,
    domain                      TEXT NOT NULL,
    session_id                  TEXT NOT NULL,
    nonce_hash                  BYTEA NOT NULL,
    nonce_ciphertext            BYTEA NOT NULL,
    iat                         BIGINT NOT NULL,
    exp                         BIGINT NOT NULL,
    requested_display_name      TEXT NOT NULL,
    site_display_name           TEXT NOT NULL,
    site_public_key             TEXT NOT NULL,
    qr_signature                TEXT NOT NULL,
    registration_signature      TEXT NOT NULL,
    registration_hash           BYTEA NOT NULL,
    state                       TEXT NOT NULL,
    version                     INTEGER NOT NULL DEFAULT 0,
    request_event_id            TEXT,
    request_room_ciphertext     BYTEA,
    request_sender_ciphertext   BYTEA,
    challenge_hash              BYTEA,
    challenge_expires_at        BIGINT,
    consent_event_id            TEXT,
    display_name_ciphertext     BYTEA,
    assertion_jti               TEXT,
    assertion_ciphertext        BYTEA,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at                  TIMESTAMPTZ NOT NULL,
    UNIQUE (domain, session_id),
    UNIQUE (domain, nonce_hash)
);

CREATE TABLE replay_request_event_ids (
    event_id    TEXT PRIMARY KEY,
    expires_at  TIMESTAMPTZ NOT NULL
);

CREATE TABLE replay_challenge_hashes (
    challenge_hash BYTEA PRIMARY KEY,
    expires_at     TIMESTAMPTZ NOT NULL
);

CREATE TABLE replay_consent_event_ids (
    event_id    TEXT PRIMARY KEY,
    expires_at  TIMESTAMPTZ NOT NULL
);

CREATE TABLE replay_assertion_jtis (
    jti         TEXT PRIMARY KEY,
    expires_at  TIMESTAMPTZ NOT NULL
);

CREATE TABLE replay_revocation_jtis (
    jti         TEXT PRIMARY KEY,
    expires_at  TIMESTAMPTZ NOT NULL
);

CREATE TABLE grants (
    id                      BIGSERIAL PRIMARY KEY,
    domain                  TEXT NOT NULL,
    subject_hash            BYTEA NOT NULL,
    subject_ciphertext      BYTEA NOT NULL,
    matrix_user_ciphertext  BYTEA NOT NULL,
    session_id              TEXT NOT NULL,
    nonce_hash              BYTEA NOT NULL,
    subject_key_version     INTEGER NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at              TIMESTAMPTZ,
    UNIQUE (domain, subject_hash)
);

CREATE TABLE delivery_jobs (
    id                  BIGSERIAL PRIMARY KEY,
    kind                TEXT NOT NULL,
    domain              TEXT NOT NULL,
    jti                 TEXT NOT NULL UNIQUE,
    payload_ciphertext  BYTEA NOT NULL,
    idempotency_key     TEXT NOT NULL,
    session_id          TEXT NOT NULL,
    nonce_hash          BYTEA NOT NULL,
    attempts            INTEGER NOT NULL DEFAULT 0,
    next_retry_at       TIMESTAMPTZ,
    status              TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);
CREATE INDEX delivery_jobs_status_idx ON delivery_jobs (status, next_retry_at);
