# syntax=docker/dockerfile:1.7
FROM rust:1.88.0-bookworm AS builder
WORKDIR /src
# Hostinger-sized VPS: rustc SIGKILL during release link is the OOM killer.
# Serialize codegen and skip LTO inside Docker; add 2G host swap if it still dies.
ENV CARGO_INCREMENTAL=0 \
    CARGO_BUILD_JOBS=1 \
    CARGO_PROFILE_RELEASE_LTO=false \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
COPY migrations ./migrations
RUN --mount=type=cache,id=pseud0-relay-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=pseud0-relay-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=pseud0-relay-target,target=/src/target,sharing=locked \
    cargo build --release --features matrix --locked --bin pseud0-web-login-relay \
    && cp /src/target/release/pseud0-web-login-relay /tmp/pseud0-web-login-relay

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /var/lib/pseud0-relay --create-home relay
COPY --from=builder /tmp/pseud0-web-login-relay /usr/local/bin/pseud0-web-login-relay
USER relay
WORKDIR /var/lib/pseud0-relay
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/pseud0-web-login-relay"]
