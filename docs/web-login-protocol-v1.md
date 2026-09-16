# pseud0 web login protocol v1

This document defines the wire format implemented by pseud0 Android under `features/business/**`. Normative terms **MUST**, **SHOULD**, and **MAY** follow RFC 2119.

## Architecture and fixed endpoints

The actors are the browser, the website backend, pseud0 Android, the central relay application, and Synapse.

- Matrix API: `https://matrix.pseud0.org`
- Relay HTTPS origin: `https://relay.pseud0.org`
- Relay Matrix account: `@web-login:pseud0.org`
- Website metadata: `https://{domain}/.well-known/pseud0-web-login`
- Session lifetime: at most 300,000 milliseconds
- Allowed clock skew when scanning: 30,000 milliseconds

The website backend **MUST** register a session with the relay before showing its QR code. Android verifies the website, sends a `Request` in an encrypted Matrix DM, receives a `Challenge`, sends a signed `Consent`, and receives a `Result`. The relay then sends a signed assertion to the website backend. The browser completes the login with a short-lived `browser_secret` and receives a site-owned `Secure`, `HttpOnly` cookie.

The site has no Matrix bot and never receives a Matrix ID. Synapse is only the encrypted transport: a separate relay application must be developed and deployed. MAS and OIDC are not required.

## Common encoding rules

- All timestamps are Unix epoch **milliseconds** encoded as JSON integers.
- JSON signatures use RFC 8785 JSON Canonicalization Scheme (JCS).
- Binary values use unpadded base64url.
- Website metadata and QR signatures use Ed25519.
- Android consent signatures use ECDSA P-256/SHA-256 (`ES256`) encoded as the fixed 64-byte `r || s` value, not ASN.1 DER.
- The Android consent `keyId` is the DID returned by its signing identity.
- Protocol producers must not emit duplicate object keys. Android rejects unknown fields, invalid UTF-8, padded base64url, floating-point timestamps, and non-finite numbers; relay and website parsers must additionally reject duplicate JSON keys.

The signed bytes are exactly the UTF-8 bytes of the JCS object described for each signature. There is no generic signed envelope, protected header, site JWKS, or JWT around website v1 signatures.

## QR code

The QR text has this exact shape:

```text
pseud0://web-login?v=1&domain=login.example.org&session=session_123456789&nonce=nonce_12345678901&iat=1800000000000&exp=1800000300000&sig=<base64url-ed25519-signature>
```

The website should emit parameters in the order shown. Android requires exactly the seven names `v`, `domain`, `session`, `nonce`, `iat`, `exp`, and `sig`, once each, with non-empty unescaped values. Percent encoding, `+`, whitespace, user information, fragments, ports, and paths other than empty or `/` are rejected.

Constraints implemented by Android:

- total URI length: 1 to 2,048 characters;
- `v`: integer `1`;
- `domain`: lower-case ASCII DNS name, at most 253 characters, at least two labels, no IP literal, port, leading/trailing hyphen, or IDN Unicode form;
- `session` and `nonce`: `[A-Za-z0-9_-]{16,128}`;
- `iat` and `exp`: signed 64-bit integer milliseconds;
- `exp > iat`;
- `exp - iat <= 300000`;
- scan time is in `[iat - 30000, exp]`;
- `sig`: unpadded base64url; sites emit an Ed25519 signature of exactly 64 bytes.

### QR signature

The site signs exactly:

```json
{
  "domain": "login.example.org",
  "exp": 1800000300000,
  "iat": 1800000000000,
  "nonce": "nonce_12345678901",
  "session": "session_123456789",
  "v": 1
}
```

The property order above is the resulting JCS lexicographic order. The signature is over `UTF8(JCS(object))`. The QR carries the result as `sig`. Do not sign the URI string, include `sig` in the signed object, or rename fields to Android model names such as `sessionId`.

## Website domain metadata

After parsing, Android fetches exactly:

```http
GET https://login.example.org/.well-known/pseud0-web-login
Accept: application/json
```

The response must be direct HTTPS with no redirect, `application/json`, and no more than 16,384 bytes. It contains exactly five fields:

```json
{
  "version": 1,
  "domain": "login.example.org",
  "displayName": "Example",
  "publicKey": "<unpadded-base64url-raw-ed25519-public-key>",
  "signature": "<unpadded-base64url-ed25519-signature>"
}
```

`version` and `domain` must equal the QR values. `displayName` must be non-blank and at most 100 characters. For interoperable v1 sites, `publicKey` is the raw 32-byte Ed25519 public key encoded as 43 unpadded base64url characters. Android also accepts an encoded X.509 Ed25519 public key for compatibility, but sites should emit the raw form.

The metadata signature is made and verified with `publicKey` over exactly:

```json
{
  "displayName": "Example",
  "domain": "login.example.org",
  "publicKey": "<unpadded-base64url-raw-ed25519-public-key>",
  "version": 1
}
```

The `signature` field is excluded. The self-signature, HTTPS origin control, and equality with the QR domain establish domain ownership and bind the QR key. Version 1 has no site JWKS, key ID, endpoint URL, relay URL, or expiry in this document.

### Metadata JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://pseud0.org/schema/web-login-v1/site-metadata.json",
  "type": "object",
  "additionalProperties": false,
  "required": ["version", "domain", "displayName", "publicKey", "signature"],
  "properties": {
    "version": {"const": 1},
    "domain": {
      "type": "string",
      "maxLength": 253,
      "pattern": "^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}$"
    },
    "displayName": {"type": "string", "minLength": 1, "maxLength": 100},
    "publicKey": {"type": "string", "pattern": "^[A-Za-z0-9_-]{43}$"},
    "signature": {"type": "string", "pattern": "^[A-Za-z0-9_-]{86}$"}
  }
}
```

## Matrix transport

Android uses an encrypted Matrix DM with `@web-login:pseud0.org`. It sends `m.notice` plain-text bodies through the Matrix SDK; Matrix room encryption protects the event on the wire.

Every body is:

```text
pseud0-web-login-v1:<base64url(JSON)>
```

The JSON is UTF-8, Kotlin serialization includes defaults, and base64url has no padding. Decoded JSON must be at most 32,768 bytes. The discriminator property is `kind`. Unknown fields and unknown kinds are rejected.

All message timestamps are milliseconds. For an active login, Android ignores messages whose `sessionId` or `nonce` differs, or whose `sentAt` is outside the QR interval. Android only accepts observed messages whose Matrix sender is `@web-login:pseud0.org`.

### Request: Android to relay

```json
{
  "kind": "request",
  "sessionId": "session_123456789",
  "nonce": "nonce_12345678901",
  "sentAt": 1800000001000,
  "domain": "login.example.org"
}
```

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://pseud0.org/schema/web-login-v1/matrix-request.json",
  "type": "object",
  "additionalProperties": false,
  "required": ["kind", "sessionId", "nonce", "sentAt", "domain"],
  "properties": {
    "kind": {"const": "request"},
    "sessionId": {"type": "string", "pattern": "^[A-Za-z0-9_-]{16,128}$"},
    "nonce": {"type": "string", "pattern": "^[A-Za-z0-9_-]{16,128}$"},
    "sentAt": {"type": "integer"},
    "domain": {"type": "string", "maxLength": 253}
  }
}
```

The relay matches this message to the session previously registered by that website backend. The Matrix sender identity is read from the authenticated encrypted event, never from JSON.

### Challenge: relay to Android

```json
{
  "kind": "challenge",
  "sessionId": "session_123456789",
  "nonce": "nonce_12345678901",
  "sentAt": 1800000002000,
  "siteName": "Example",
  "domain": "login.example.org",
  "requestedDisplayName": "Alice",
  "challenge": "challenge_123456",
  "expiresAt": 1800000030000
}
```

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://pseud0.org/schema/web-login-v1/matrix-challenge.json",
  "type": "object",
  "additionalProperties": false,
  "required": ["kind", "sessionId", "nonce", "sentAt", "siteName", "domain", "requestedDisplayName", "challenge", "expiresAt"],
  "properties": {
    "kind": {"const": "challenge"},
    "sessionId": {"type": "string"},
    "nonce": {"type": "string"},
    "sentAt": {"type": "integer"},
    "siteName": {"type": "string", "minLength": 1, "maxLength": 100},
    "domain": {"type": "string", "maxLength": 253},
    "requestedDisplayName": {"type": "string", "maxLength": 100},
    "challenge": {"type": "string", "minLength": 16, "maxLength": 512},
    "expiresAt": {"type": "integer"}
  }
}
```

Android requires `domain` and `siteName` to match verified metadata, accepts only one challenge, and requires `expiresAt` to be between `sentAt` and the QR expiry. `requestedDisplayName` is retained for wire compatibility but ignored: the editable value is initialized from the current Matrix profile and only the user-approved value is sent.

### Consent: Android to relay

Approved:

```json
{
  "kind": "consent",
  "sessionId": "session_123456789",
  "nonce": "nonce_12345678901",
  "sentAt": 1800000003000,
  "approved": true,
  "displayName": "Alice",
  "challenge": "challenge_123456",
  "keyId": "did:key:<android-signing-key>",
  "signature": "<base64url-64-byte-r-plus-s>"
}
```

Refused:

```json
{
  "kind": "consent",
  "sessionId": "session_123456789",
  "nonce": "nonce_12345678901",
  "sentAt": 1800000003000,
  "approved": false,
  "displayName": null,
  "challenge": "challenge_123456",
  "keyId": "did:key:<android-signing-key>",
  "signature": "<base64url-64-byte-r-plus-s>"
}
```

The ES256 signature covers exactly this JCS object:

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

When `displayName` is null, Android omits that property from the signed JCS object even though the serialized transport message contains `"displayName":null`. `keyId`, `signature`, and `kind` are not signed.

The Android `keyId` is exactly the P-256 `did:key` produced by `AndroidSigningKeyStore`: `did:key:z` followed by base58btc of the P-256 multicodec varint bytes `0x80 0x24` and the 33-byte SEC1 compressed public point. The relay decodes this DID without network resolution, reconstructs the P-256 public key, verifies the raw 64-byte `r || s` signature, and binds the consent to the Matrix sender, session, nonce, and one-time challenge.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://pseud0.org/schema/web-login-v1/matrix-consent.json",
  "type": "object",
  "additionalProperties": false,
  "required": ["kind", "sessionId", "nonce", "sentAt", "approved", "displayName", "challenge", "keyId", "signature"],
  "properties": {
    "kind": {"const": "consent"},
    "sessionId": {"type": "string"},
    "nonce": {"type": "string"},
    "sentAt": {"type": "integer"},
    "approved": {"type": "boolean"},
    "displayName": {"type": ["string", "null"], "maxLength": 100},
    "challenge": {"type": "string", "minLength": 16, "maxLength": 512},
    "keyId": {"type": "string", "minLength": 1, "maxLength": 512, "pattern": "^did:"},
    "signature": {"type": "string", "pattern": "^[A-Za-z0-9_-]{86}$"}
  },
  "allOf": [
    {
      "if": {"properties": {"approved": {"const": true}}},
      "then": {"properties": {"displayName": {"type": "string", "minLength": 1}}},
      "else": {"properties": {"displayName": {"type": "null"}}
    }
  ]
}
```

### Result: relay to Android

Success:

```json
{
  "kind": "result",
  "sessionId": "session_123456789",
  "nonce": "nonce_12345678901",
  "sentAt": 1800000004000,
  "success": true,
  "siteAccountId": "<pairwise-opaque-subject>",
  "reason": null
}
```

Failure:

```json
{
  "kind": "result",
  "sessionId": "session_123456789",
  "nonce": "nonce_12345678901",
  "sentAt": 1800000004000,
  "success": false,
  "siteAccountId": null,
  "reason": "request_expired"
}
```

Because transport serialization uses `encodeDefaults = true`, `siteAccountId` and `reason` are present even when null.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://pseud0.org/schema/web-login-v1/matrix-result.json",
  "type": "object",
  "additionalProperties": false,
  "required": ["kind", "sessionId", "nonce", "sentAt", "success", "siteAccountId", "reason"],
  "properties": {
    "kind": {"const": "result"},
    "sessionId": {"type": "string"},
    "nonce": {"type": "string"},
    "sentAt": {"type": "integer"},
    "success": {"type": "boolean"},
    "siteAccountId": {
      "type": ["string", "null"],
      "pattern": "^[A-Za-z0-9_-]{22,128}$"
    },
    "reason": {"type": ["string", "null"], "maxLength": 100}
  }
}
```

On success, `siteAccountId` is the same domain-pairwise opaque identifier delivered to the website as assertion `sub`. Android stores it only for the linked-site and revocation workflow.

### Revocation: Android or relay

```json
{
  "kind": "revocation",
  "sessionId": "session_123456789",
  "nonce": "nonce_12345678901",
  "sentAt": 1800001000000,
  "siteAccountId": "<pairwise-opaque-subject>",
  "reason": "user_requested"
}
```

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://pseud0.org/schema/web-login-v1/matrix-revocation.json",
  "type": "object",
  "additionalProperties": false,
  "required": ["kind", "sessionId", "nonce", "sentAt", "siteAccountId", "reason"],
  "properties": {
    "kind": {"const": "revocation"},
    "sessionId": {"type": "string"},
    "nonce": {"type": "string"},
    "sentAt": {"type": "integer"},
    "siteAccountId": {"type": "string", "pattern": "^[A-Za-z0-9_-]{22,128}$"},
    "reason": {"type": ["string", "null"], "maxLength": 100}
  }
}
```

Android sends `reason = "user_requested"` when unlinking. The relay may send a revocation to Android. Revocation delivery to the website is a relay HTTPS concern.

## State machine

```text
SITE_REGISTERED
      |
      v
QR_DISPLAYED -> REQUEST_RECEIVED -> CHALLENGE_SENT
      |                                  |
      |                                  v
      +---------------------------- CONSENT_RECEIVED
                                         |
                      +------------------+------------------+
                      |                                     |
                   REFUSED                         ASSERTION_DELIVERED
                                                            |
                                                            v
                                                    BROWSER_CONSUMED

Any non-terminal state -> EXPIRED or CANCELLED
Linked account -> REVOKED
```

Each `(domain, sessionId)`, nonce, challenge, assertion `jti`, and browser completion is single-use. State changes and replay reservations must be atomic.

## Pairwise identity and privacy

The relay derives the subject without sending the Matrix ID to the site:

```text
sub = base64url(HMAC-SHA-256(
    subject_secret,
    "pseud0-sub-v1\0" ||
    uint32be(length(domain)) || UTF8(domain) ||
    uint32be(length(matrix_user_id)) || UTF8(matrix_user_id)
))
```

The relay's subject secret contains at least 256 random bits and is versioned. The result is stable for the same Matrix account and domain and unlinkable across domains. Display name is sent only after an approved consent and is never an identifier.

## Baseline security

- QR, session, nonce, challenge, consent, assertion, and browser completion all expire no later than the original five-minute QR expiry.
- The website stores only a hash of `browser_secret`; the secret is never placed in the QR or a URL.
- Relay assertions are Ed25519-signed, audience-bound to the domain, and carry a unique single-use `jti`.
- Android and the relay reject redirects and invalid domain metadata.
- Relay outbound HTTP applies DNS/IP SSRF defenses.
- The encrypted DM contains only the Android user and `@web-login:pseud0.org`; unencrypted events and unexpected members are rejected.
- Logs never contain Matrix IDs, display names, subjects, QR content, consent payloads, assertions, cookies, or secrets.
- Synapse alone is insufficient; the relay application is a separate required security boundary.
