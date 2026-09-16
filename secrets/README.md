# Secrets

Create these files locally (mode `0600` on Unix). Never commit their contents.

| File | Contents |
| --- | --- |
| `relay_matrix_access_token` | Matrix access token for `@web-login:pseud0.org` |
| `relay_matrix_device_id` | Stable device ID for the single E2EE device |
| `relay_crypto_passphrase` | Passphrase that encrypts the matrix-sdk SQLite store |
| `relay_signing_key` | 32-byte Ed25519 seed as 64 hex chars or 43-char unpadded base64url |
| `relay_subject_key_v1` | ≥32 random bytes as 64 hex chars (HMAC subject secret) |
| `relay_at_rest_key` | 32-byte AES-256-GCM key as 64 hex chars |
| `relay_lookup_pepper` | 32-byte HMAC pepper as 64 hex chars |
| `postgres_password` | PostgreSQL password used by Compose |

Generate keys:

```bash
openssl rand -hex 32
```
