# pseud0 web login relay specification

This document specifies the relay application interoperable with the Android implementation in `features/business/**`. It does not provide that application.

> [!IMPORTANT]
> Synapse only transports encrypted Matrix events. A distinct relay application must implement session registration, challenge issuance, consent verification, pairwise subject derivation, assertion delivery, replay prevention, and revocation.

## Fixed identity

- HTTPS origin: `https://relay.pseud0.org`
- Matrix API: `https://matrix.pseud0.org`
- Matrix account: `@web-login:pseud0.org`
- Matrix body prefix: `pseud0-web-login-v1:`
- Session TTL: at most 300,000 milliseconds

The relay account is a non-admin Matrix user with one persistent, verified E2EE device.

## End-to-end sequence

1. The website backend generates `sessionId`, `nonce`, `browser_secret`, `iat`, and `exp`.
2. It signs the QR fields with its Ed25519 key.
3. It registers the session with `https://relay.pseud0.org/v1/site-sessions`.
4. The relay fetches `https://{domain}/.well-known/pseud0-web-login`, verifies the exact v1 metadata object and registration signature, and stores the pending session.
5. Only after registration succeeds does the website display the QR.
6. Android verifies the same metadata and QR signature, opens an encrypted DM with `@web-login:pseud0.org`, and sends `Request`.
7. The relay matches `(domain, sessionId, nonce)`, consumes no credential yet, and sends `Challenge`.
8. Android obtains explicit approval or refusal and sends `Consent` signed with its P-256 DID key.
9. The relay verifies the one-time challenge, raw ES256 signature, encrypted Matrix sender, and expiry.
10. On approval, the relay derives the pairwise `sub`, signs an audience-bound assertion, and posts it to the site's fixed assertion endpoint.
11. The relay sends `Result` to Android.
12. The browser proves `browser_secret` to its backend, which issues its own `HttpOnly` cookie.

## Website metadata verification

The relay applies the same format as Android:

```json
{
  "version": 1,
  "domain": "login.example.org",
  "displayName": "Example",
  "publicKey": "<base64url-raw-32-byte-ed25519-key>",
  "signature": "<base64url-ed25519-signature>"
}
```

The signature covers JCS of exactly `displayName`, `domain`, `publicKey`, and `version`. The relay rejects unknown fields, redirects, domain mismatch, non-HTTPS responses, responses over 16 KiB, and keys other than the v1 raw Ed25519 key. There is no site JWKS in version 1.

## Site session registration

The fixed endpoint is:

```http
POST https://relay.pseud0.org/v1/site-sessions
Content-Type: application/json
```

Request:

```json
{
  "version": 1,
  "domain": "login.example.org",
  "sessionId": "session_123456789",
  "nonce": "nonce_12345678901",
  "iat": 1800000000000,
  "exp": 1800000300000,
  "requestedDisplayName": "Alice",
  "qrSignature": "<base64url-ed25519-signature>",
  "registrationSignature": "<base64url-ed25519-signature>"
}
```

`qrSignature` is the signature placed in QR parameter `sig`. It covers:

```json
{"domain":"login.example.org","exp":1800000300000,"iat":1800000000000,"nonce":"nonce_12345678901","session":"session_123456789","v":1}
```

`registrationSignature` proves that the site authorized the complete registration. It covers JCS of:

```json
{
  "domain": "login.example.org",
  "exp": 1800000300000,
  "iat": 1800000000000,
  "nonce": "nonce_12345678901",
  "qrSignature": "<base64url-ed25519-signature>",
  "requestedDisplayName": "Alice",
  "sessionId": "session_123456789",
  "version": 1
}
```

The relay validates both signatures with the raw key from the verified metadata. `requestedDisplayName` is retained for wire compatibility, must be at most 100 characters, and should be empty. Android ignores it and initializes the editable value from the user's current Matrix profile. The assertion delivery path is fixed to:

```text
https://{domain}/pseud0/web-login/assertions
```

It is not accepted from request input.

### Registration JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://pseud0.org/schema/web-login-v1/relay-registration.json",
  "type": "object",
  "additionalProperties": false,
  "required": ["version", "domain", "sessionId", "nonce", "iat", "exp", "requestedDisplayName", "qrSignature", "registrationSignature"],
  "properties": {
    "version": {"const": 1},
    "domain": {
      "type": "string",
      "maxLength": 253,
      "pattern": "^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}$"
    },
    "sessionId": {"type": "string", "pattern": "^[A-Za-z0-9_-]{16,128}$"},
    "nonce": {"type": "string", "pattern": "^[A-Za-z0-9_-]{16,128}$"},
    "iat": {"type": "integer"},
    "exp": {"type": "integer"},
    "requestedDisplayName": {"type": "string", "maxLength": 100},
    "qrSignature": {"type": "string", "pattern": "^[A-Za-z0-9_-]{86}$"},
    "registrationSignature": {"type": "string", "pattern": "^[A-Za-z0-9_-]{86}$"}
  }
}
```

Response after the transaction commits:

```http
HTTP/1.1 201 Created
Cache-Control: no-store
```

```json
{
  "version": 1,
  "sessionId": "session_123456789",
  "status": "registered",
  "expiresAt": 1800000300000
}
```

Duplicate byte-identical registration may return `200` with the same body. Conflicting reuse of session or nonce returns `409`.

## Matrix wire behavior

The relay encodes and decodes exactly the five `kind` objects in [the protocol](web-login-protocol-v1.md). It must reproduce Kotlin serialization behavior:

- UTF-8 JSON;
- discriminator property `kind`;
- camel-case names such as `sessionId`, `sentAt`, and `siteAccountId`;
- explicit nullable fields for `Consent.displayName`, `Result.siteAccountId`, `Result.reason`, and `Revocation.reason`;
- unpadded base64url JSON after `pseud0-web-login-v1:`;
- decoded body at most 32,768 bytes;
- no unknown fields.

The message directions are:

- `request`: Android to relay;
- `challenge`: relay to Android;
- `consent`: Android to relay;
- `result`: relay to Android;
- `revocation`: either direction.

The relay ignores its own inbound echo and any sender other than the current room peer. It processes only decrypted events in a direct encrypted room containing exactly the peer and `@web-login:pseud0.org`.

## Request and challenge processing

For `Request`, the relay:

1. reads the Matrix user ID only from the authenticated event sender;
2. validates milliseconds and requires `sentAt` in `[iat - 30000, exp]`;
3. matches the pending registration by exact `domain`, `sessionId`, and `nonce`;
4. atomically records the Matrix event ID to stop replay;
5. generates at least 128 random bits as unpadded base64url `challenge`;
6. stores only a keyed hash of the challenge where possible;
7. sends one `Challenge`.

The `Challenge` uses metadata `displayName` as `siteName`, the registered `domain`, the compatibility `requestedDisplayName` value, a current millisecond `sentAt`, and `expiresAt <= min(registration exp, sentAt + 300000)`. A duplicate `Request` must not create a new challenge.

## Consent signature verification

The transport `Consent` always contains `displayName`, including JSON null. Reconstruct the signed object exactly as Android does:

```json
{
  "approved": true,
  "challenge": "challenge_123456",
  "displayName": "Alice",
  "nonce": "nonce_12345678901",
  "sessionId": "session_123456789",
  "sentAt": 1800000003000
}
```

If `displayName == null`, omit the property from the signed object. Canonicalize with RFC 8785 and verify the 64 decoded signature bytes as P-256 `r || s` over SHA-256.

`keyId` must be the exact Android P-256 form: `did:key:z` followed by base58btc of 35 bytes consisting of multicodec varint `0x80 0x24` and a 33-byte SEC1 compressed P-256 point (`0x02` or `0x03` plus the 32-byte x-coordinate). Decode it locally, validate the point is on P-256, and reject all other DID methods, codecs, lengths, and network-based DID resolution.

The relay also requires:

- exact session, nonce, and one-time challenge match;
- `sentAt` within the QR and challenge intervals;
- one consent per challenge;
- non-empty display name of at most 100 characters when approved;
- null display name when refused;
- same Matrix sender and room as the original request.

The P-256 signature proves the Android-held key approved these exact values; Matrix E2EE sender identity binds that approval to the Matrix account.

## Pairwise subject

On approved consent, derive:

```text
sub = base64url(HMAC-SHA-256(
    subject_secret,
    "pseud0-sub-v1\0" ||
    uint32be(length(domain)) || UTF8(domain) ||
    uint32be(length(matrix_user_id)) || UTF8(matrix_user_id)
))
```

Lengths are UTF-8 byte lengths. The secret contains at least 256 random bits, is versioned, and is separate from assertion signing keys. The same Matrix account receives a stable `sub` for one domain and unrelated values for other domains.

The Matrix ID must not leave the relay in an HTTP request, assertion, log, trace, metric, queue payload, or correlation identifier.

## Relay assertion

The relay publishes an RFC 7517 JWKS at:

```text
https://relay.pseud0.org/.well-known/jwks.json
```

Only public Ed25519 keys appear:

```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "<base64url-raw-32-byte-public-key>",
      "use": "sig",
      "alg": "EdDSA",
      "kid": "relay-2026-01"
    }
  ]
}
```

The relay posts this JSON to `https://{domain}/pseud0/web-login/assertions`:

```json
{
  "version": 1,
  "iss": "https://relay.pseud0.org",
  "aud": "login.example.org",
  "sub": "<43-character-pairwise-subject>",
  "sessionId": "session_123456789",
  "nonce": "nonce_12345678901",
  "jti": "<at-least-128-bit-base64url>",
  "iat": 1800000003500,
  "nbf": 1800000003500,
  "exp": 1800000300000,
  "displayName": "Alice",
  "subjectKeyVersion": 1,
  "kid": "relay-2026-01",
  "signature": "<base64url-ed25519-signature>"
}
```

This assertion is a flat JCS-signed JSON object, not a site-style envelope or JWT. The relay signs JCS of every field above except `signature`. `displayName` is required for approved Android v1 consent. `aud` is the exact bare domain, and `exp` is no later than the original QR expiry or `iat + 300000`.

### Assertion JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://pseud0.org/schema/web-login-v1/relay-assertion.json",
  "type": "object",
  "additionalProperties": false,
  "required": ["version", "iss", "aud", "sub", "sessionId", "nonce", "jti", "iat", "nbf", "exp", "displayName", "subjectKeyVersion", "kid", "signature"],
  "properties": {
    "version": {"const": 1},
    "iss": {"const": "https://relay.pseud0.org"},
    "aud": {"type": "string", "maxLength": 253},
    "sub": {"type": "string", "pattern": "^[A-Za-z0-9_-]{43}$"},
    "sessionId": {"type": "string", "pattern": "^[A-Za-z0-9_-]{16,128}$"},
    "nonce": {"type": "string", "pattern": "^[A-Za-z0-9_-]{16,128}$"},
    "jti": {"type": "string", "pattern": "^[A-Za-z0-9_-]{22,128}$"},
    "iat": {"type": "integer"},
    "nbf": {"type": "integer"},
    "exp": {"type": "integer"},
    "displayName": {"type": "string", "minLength": 1, "maxLength": 100},
    "subjectKeyVersion": {"type": "integer", "minimum": 1},
    "kid": {"type": "string", "pattern": "^[A-Za-z0-9._-]{1,64}$"},
    "signature": {"type": "string", "pattern": "^[A-Za-z0-9_-]{86}$"}
  }
}
```

Delivery uses:

```http
POST /pseud0/web-login/assertions
Content-Type: application/json
Idempotency-Key: <jti>
```

The site returns `202 accepted`, or `200 already_accepted` for an exact retry. The relay signs once and retries the identical bytes and `jti`; it never mints a replacement after an ambiguous timeout.

After accepted delivery, send Android a successful `Result` with `siteAccountId = sub` and `reason = null`. Refusal or terminal failure sends `success = false`, `siteAccountId = null`, and a coarse reason.

## Revocation

Android sends `Revocation(sessionId, nonce, sentAt, siteAccountId, "user_requested")`. The relay verifies that the encrypted Matrix sender originally obtained that `siteAccountId` for the domain. It atomically marks the grant revoked and calls:

```http
POST https://{domain}/pseud0/web-login/revocations
Content-Type: application/json
```

```json
{
  "version": 1,
  "iss": "https://relay.pseud0.org",
  "aud": "login.example.org",
  "sub": "<pairwise-subject>",
  "jti": "<one-time-id>",
  "iat": 1800001000000,
  "reason": "user_requested",
  "kid": "relay-2026-01",
  "signature": "<ed25519-signature>"
}
```

As with assertions, `signature` covers JCS of every other field. The relay may send the Matrix `Revocation` format to Android for server-initiated revocation.

## Replay and storage

Use database uniqueness constraints for:

- `(domain, sessionId)`;
- `(domain, nonce_hash)`;
- Matrix request event ID;
- challenge hash;
- consent event ID;
- assertion `jti`;
- revocation `jti`.

State transitions are compare-and-set transactions. Retain replay entries at least until their expiry plus 30 seconds. Encrypt pending assertions and identity mappings at rest. Do not persist a Matrix ID in website delivery jobs; derive `sub` inside a narrow transaction and discard the source identifier.

## SSRF requirements

For metadata, assertion, and revocation requests:

- construct URLs from the validated bare domain and fixed paths only;
- permit HTTPS and default port 443 only;
- reject IP literals, user information, fragments, trailing-dot hosts, invalid IDNA, and redirects;
- resolve DNS, normalize IPv4-mapped IPv6, and reject loopback, private, link-local, multicast, carrier-grade NAT, documentation, reserved, and cloud metadata ranges;
- pin a validated resolved address to the actual connection while preserving host TLS SNI and certificate verification;
- validate again for every new connection to stop DNS rebinding;
- ignore process proxy environment variables;
- limit metadata to 16 KiB and site responses to 16 KiB;
- set strict connect, TLS, first-byte, and total timeouts;
- enforce equivalent outbound firewall rules.

## E2EE device persistence

Persist the relay access token, stable device ID, encrypted crypto store, Olm identity, Megolm sessions, cross-signing state, and sync token. Use one active sync leader per device. Never run concurrent containers over one crypto store.

The device should be cross-signed and verified. Back up the relay database and crypto store crash-consistently and test joint restore. Reject unencrypted rooms, non-DM rooms, third members, bridges, guests, redacted requests, and unexpected senders.

## Errors

HTTP errors use `application/problem+json` with codes:

```text
invalid_request
unsupported_version
invalid_signature
domain_verification_failed
session_not_found
session_conflict
request_expired
request_cancelled
challenge_replayed
consent_replayed
assertion_replayed
audience_mismatch
revoked
rate_limited
relay_unavailable
internal_error
```

Responses contain a random correlation ID and no Matrix ID, account existence, subject, signature bytes, or validation internals.

## Keys, backups, and monitoring

Keep relay Ed25519 assertion keys, HMAC subject key versions, Matrix access token, E2EE store key, database credentials, and backup keys in a secret manager or root-readable mounted secrets. Signing-key rotation does not rotate subjects. Subject-key rotation requires an account migration plan.

Monitor Matrix sync age, decryption failures, room-policy violations, registration failures, challenge age, consent verification, delivery queue depth, assertion expiry, SSRF rejections, key expiry, replay conflicts, database health, and backup restore age. Metrics use aggregate reason labels only.

## Relay acceptance tests

1. A registered session followed by Android `Request`, relay `Challenge`, and valid Android `Consent` yields one assertion and one `Result`.
2. Captured Matrix bodies decode to the exact `kind` JSON defined by Android.
3. Consent verification omits `displayName` from signed JCS when transport contains null.
4. Raw 64-byte `r || s` succeeds; DER and wrong DID keys fail.
5. Timestamps are interpreted as milliseconds and TTL over 300,000 fails.
6. Duplicate request, challenge, consent, assertion, and revocation processing is atomic.
7. Same user/domain produces a stable subject; another domain produces a different one.
8. No relay-to-site traffic or observability output contains a Matrix ID.
9. Site metadata is the exact five-field object and no site JWKS is requested.
10. Redirect, DNS rebinding, private IP, metadata IP, and alternate-port SSRF cases fail.
11. Unencrypted rooms and rooms with a third member cannot produce assertions.
12. Restored E2EE state decrypts new events without replaying completed sessions.
