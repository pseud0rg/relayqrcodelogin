# pseud0 web-login relay

Rust relay for Android QR web login. Synapse only transports encrypted Matrix events; this application is the security boundary that registers site sessions, issues challenges, verifies P-256 consent, derives pairwise subjects, and posts signed assertions.

Normative documents:

- [docs/web-login-relay-spec.md](docs/web-login-relay-spec.md)
- [docs/web-login-protocol-v1.md](docs/web-login-protocol-v1.md)
- [docs/matrix-server-web-login-guide.md](docs/matrix-server-web-login-guide.md)

## Fixed identity

| Item | Value |
| --- | --- |
| HTTPS origin | `https://relay.pseud0.org` |
| Matrix API | `https://matrix.pseud0.org` |
| Matrix account | `@web-login:pseud0.org` |
| Body prefix | `pseud0-web-login-v1:` |
| Session TTL | at most 300,000 ms |

## Build

Requires Rust 1.88 and a PostgreSQL database for the full service.

```bash
cargo test --offline --lib
cargo test --features matrix
cargo build --release --features matrix
```

Database-backed tests (`tests/integration.rs`, `tests/replay.rs`) skip unless `TEST_DATABASE_URL` points at an empty PostgreSQL database.

HTTP-only integration tests do not need Synapse. A mocked homeserver is not a substitute for a real encrypted staging run with Android.

## Configuration

Copy [`.env.example`](.env.example) to `.env` and create the files listed in [`secrets/README.md`](secrets/README.md). No secret belongs in Git or in the container image.

```bash
docker compose up --build
```

The Compose file starts PostgreSQL and this relay only. Point `MATRIX_HOMESERVER` at an existing Synapse. Restore the access token, device ID, and encrypted crypto store together; never run two containers on one store.

## HTTP surface

- `POST /v1/site-sessions`
- `GET /.well-known/jwks.json`
- `GET /health/live`
- `GET /health/ready`

## Privacy

Logs and site callbacks never include a Matrix user ID, room ID, access token, subject, display name, QR, consent payload, or signature bytes. Correlation IDs are random.
