# Matrix server and web login deployment

This guide describes an Ubuntu VPS deployment for the pseud0 Matrix API at `https://matrix.pseud0.org` and the separate web-login relay at `https://relay.pseud0.org`.

> [!WARNING]
> Synapse does not implement pseud0 web login. It only transports Matrix events. A separate relay application implementing `web-login-relay-spec.md` must be developed, deployed, monitored, and backed up.

MAS and OIDC are not required. Neither replaces the relay.

## Identity and delegation

The fixed relay Matrix ID is:

```text
@web-login:pseud0.org
```

Therefore the immutable Synapse `server_name` is `pseud0.org`, while its public client and federation API is `https://matrix.pseud0.org`. Do not configure `server_name: matrix.pseud0.org`, because that would create incompatible `@user:matrix.pseud0.org` IDs.

Publish on `https://pseud0.org`:

```http
GET /.well-known/matrix/client
Content-Type: application/json
Access-Control-Allow-Origin: *
```

```json
{
  "m.homeserver": {
    "base_url": "https://matrix.pseud0.org"
  }
}
```

```http
GET /.well-known/matrix/server
Content-Type: application/json
```

```json
{
  "m.server": "matrix.pseud0.org:443"
}
```

These files may be served by the pseud0.org website or by Nginx on the VPS. They must remain available before creating accounts.

## Target topology

```text
https://pseud0.org
    /.well-known/matrix/* -> delegation

https://matrix.pseud0.org
    Nginx -> Synapse :8008 -> PostgreSQL

https://relay.pseud0.org
    Nginx -> separate relay application :8080
                         |
                         +-> Matrix E2EE as @web-login:pseud0.org
                         +-> persistent crypto store
                         +-> relay database and delivery queue
```

The relay database and credentials are separate from Synapse. The relay account is not a Synapse administrator.

## Host preparation

Use a supported Ubuntu LTS release, SSH keys, automatic security updates, time synchronization, and monitored SSD storage. Install Docker Engine and the Compose plugin from Docker's supported Ubuntu repository. Pin tested image versions or digests; never use `latest`.

Allow inbound TCP 80/443 and restrict SSH to administrative networks. Do not expose Synapse port 8008, PostgreSQL, relay metrics, or administration ports publicly.

Suggested host layout:

```text
/opt/pseud0/
  compose.yaml
  synapse/
    homeserver.yaml
    log.config
    signing.key
    media/
  postgres/
  relay/
    config.yaml
    crypto-store/
    data/
  nginx/
  letsencrypt/
  secrets/
    postgres_password
    relay_matrix_access_token
    relay_crypto_passphrase
    relay_signing_key
    relay_subject_key_v1
```

Secret files and E2EE state must never enter this repository or a container image. Use root ownership and mode `0600`.

## Generate and configure Synapse

```shell
export SYNAPSE_IMAGE="matrixdotorg/synapse:<tested-version>"
docker run --rm \
  -e SYNAPSE_SERVER_NAME=pseud0.org \
  -e SYNAPSE_REPORT_STATS=no \
  -v /opt/pseud0/synapse:/data \
  "$SYNAPSE_IMAGE" generate
```

Review the generated configuration. The relevant settings are:

```yaml
server_name: "pseud0.org"
public_baseurl: "https://matrix.pseud0.org/"
signing_key_path: /data/signing.key
media_store_path: /data/media

listeners:
  - port: 8008
    type: http
    tls: false
    x_forwarded: true
    bind_addresses: ["0.0.0.0"]
    resources:
      - names: [client, federation]
        compress: false

database:
  name: psycopg2
  args:
    user: synapse
    password: "<render from a secret>"
    database: synapse
    host: postgres
    port: 5432
    cp_min: 5
    cp_max: 10

enable_registration: false
enable_registration_without_verification: false
allow_guest_access: false
report_stats: false
```

No `oidc_providers` or MAS configuration is needed for QR web login. Normal Matrix account provisioning remains separate.

## Docker Compose

Replace every placeholder with a tested immutable version:

```yaml
name: pseud0-infrastructure

services:
  postgres:
    image: postgres:<tested-major-version>
    restart: unless-stopped
    environment:
      POSTGRES_DB: synapse
      POSTGRES_USER: synapse
      POSTGRES_PASSWORD_FILE: /run/secrets/postgres_password
      POSTGRES_INITDB_ARGS: "--encoding=UTF8 --locale=C"
    secrets: [postgres_password]
    volumes:
      - ./postgres:/var/lib/postgresql/data
    networks: [backend]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U synapse -d synapse"]
      interval: 10s
      timeout: 5s
      retries: 5

  synapse:
    image: matrixdotorg/synapse:<tested-version>
    restart: unless-stopped
    depends_on:
      postgres:
        condition: service_healthy
    volumes:
      - ./synapse:/data
    networks: [backend, edge]
    healthcheck:
      test: ["CMD", "curl", "--fail", "http://localhost:8008/health"]
      interval: 30s
      timeout: 5s
      retries: 5

  nginx:
    image: nginx:<tested-version>
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx:/etc/nginx/conf.d:ro
      - ./letsencrypt:/etc/letsencrypt:ro
      - ./certbot/www:/var/www/certbot:ro
    networks: [edge]

  # Enable only after implementing and testing the relay specification.
  # web-login-relay:
  #   image: registry.example/pseud0-web-login-relay:<tested-version>
  #   restart: unless-stopped
  #   volumes:
  #     - ./relay/config.yaml:/app/config.yaml:ro
  #     - ./relay/crypto-store:/var/lib/pseud0-relay/crypto
  #     - ./relay/data:/var/lib/pseud0-relay/data
  #   secrets:
  #     - relay_matrix_access_token
  #     - relay_crypto_passphrase
  #     - relay_signing_key
  #     - relay_subject_key_v1
  #   networks: [backend, relay_egress, edge]

networks:
  edge:
  backend:
    internal: true
  relay_egress:

secrets:
  postgres_password:
    file: ./secrets/postgres_password
  # relay_matrix_access_token:
  #   file: ./secrets/relay_matrix_access_token
  # relay_crypto_passphrase:
  #   file: ./secrets/relay_crypto_passphrase
  # relay_signing_key:
  #   file: ./secrets/relay_signing_key
  # relay_subject_key_v1:
  #   file: ./secrets/relay_subject_key_v1
```

Provision a separate relay database and least-privilege credential when enabling the application. The relay must not access Synapse tables.

## Nginx for Matrix

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name matrix.pseud0.org;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name matrix.pseud0.org;

    ssl_certificate /etc/letsencrypt/live/matrix.pseud0.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/matrix.pseud0.org/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_tickets off;
    client_max_body_size 50m;

    location ~ ^(/_matrix|/_synapse/client) {
        proxy_pass http://synapse:8008;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_http_version 1.1;
        proxy_read_timeout 180s;
    }

    location = /health {
        proxy_pass http://synapse:8008/health;
        access_log off;
    }

    location / {
        return 404;
    }
}
```

Federation reaches `matrix.pseud0.org:443` through the parent-domain delegation. Port 8448 need not be public.

## Nginx for the relay

Enable only when a conforming relay image exists:

```nginx
limit_req_zone $binary_remote_addr zone=relay_public:10m rate=10r/s;

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name relay.pseud0.org;

    ssl_certificate /etc/letsencrypt/live/relay.pseud0.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/relay.pseud0.org/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_tickets off;
    client_max_body_size 64k;

    location = /v1/site-sessions {
        limit_req zone=relay_public burst=20 nodelay;
        proxy_pass http://web-login-relay:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }

    location = /.well-known/jwks.json {
        proxy_pass http://web-login-relay:8080;
        proxy_set_header Host $host;
    }

    location /health/ {
        proxy_pass http://web-login-relay:8080;
        access_log off;
    }

    location / {
        return 404;
    }
}
```

Keep metrics and admin endpoints private. The relay's website callbacks use outbound HTTPS and still require application-level DNS/IP SSRF validation. Do not use host networking as an egress workaround.

## Create the relay account

Use Synapse's supported administrative provisioning process:

```shell
docker compose exec synapse register_new_matrix_user \
  -u web-login \
  -p '<generated-password>' \
  --no-admin \
  http://localhost:8008
```

Confirm the resulting ID is exactly `@web-login:pseud0.org`. Sign in the relay once, place its access token in the secret store, and retain one stable device ID.

Persist:

- Matrix access token and device ID;
- encrypted Matrix SDK crypto database;
- Olm account and one-time-key state;
- inbound and outbound Megolm sessions;
- cross-signing and verification state;
- sync token.

Use durable encrypted storage and one active sync leader per device. Never run multiple processes over the same crypto store. Verify the relay device from an operator-controlled device and store recovery material offline.

The relay application, not Synapse configuration, enforces that protocol rooms are encrypted DMs containing exactly the user and `@web-login:pseud0.org`.

## Network security

Example baseline:

```shell
ufw default deny incoming
ufw default allow outgoing
ufw allow from <admin-cidr> to any port 22 proto tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable
```

Add relay-container egress rules denying loopback, RFC 1918, link-local, carrier-grade NAT, cloud metadata, Docker management, and other internal ranges. Permit DNS only to approved resolvers. Keep the system clock synchronized because protocol timestamps are milliseconds with a five-minute lifetime.

## Secrets and rotation

Protect independently:

- Synapse server signing key;
- PostgreSQL credentials and backups;
- relay Matrix token and E2EE store passphrase;
- relay Ed25519 assertion keys;
- relay HMAC subject keys;
- TLS and backup-encryption keys.

Relay signing-key rotation publishes old and new keys together in relay JWKS before switching `kid`. Keep the old public key through all assertion lifetimes and cache overlap. Rotating a subject HMAC key changes pairwise subjects and requires an account-migration plan.

## Backups

Back up off-host and encrypted:

- PostgreSQL plus required WAL;
- Synapse configuration, signing key, and media;
- relay database and delivery queue;
- relay E2EE crypto store;
- relay configuration and key-version references.

Test restoration quarterly. A valid relay restore must decrypt new messages, preserve request/replay state, and retain assertion and subject key versions. Back up database and crypto state crash-consistently.

## Monitoring

Alert on:

- Synapse health, federation errors, database saturation, and disk growth;
- relay Matrix sync age, E2EE decryption failures, and room-policy violations;
- registered-session, challenge, and consent expiry;
- assertion queue age, retries, and SSRF rejections;
- relay JWKS/signing-key expiry;
- backup failure and restore-drill age;
- host clock, CPU, memory, disk, and certificate expiry.

Never log Matrix tokens, encrypted-event bodies, decoded protocol JSON, QR values, browser secrets, assertions, display names, pairwise subjects, cookies, or private keys.

## Deployment checklist

1. `https://pseud0.org/.well-known/matrix/client` resolves to `https://matrix.pseud0.org`.
2. `https://pseud0.org/.well-known/matrix/server` delegates federation to `matrix.pseud0.org:443`.
3. Synapse `server_name` is permanently `pseud0.org`.
4. The relay user is exactly `@web-login:pseud0.org` and is non-admin.
5. Android reaches the Matrix API at `https://matrix.pseud0.org`.
6. Ports 8008, PostgreSQL, metrics, and admin endpoints are private.
7. Relay E2EE survives restart and joint backup restoration.
8. The separately deployed relay passes `web-login-relay-spec.md`.
9. No MAS or OIDC dependency is assumed.
10. Operators understand that healthy Synapse without the application relay means web login is unavailable.
