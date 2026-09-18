use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;

use crate::constants::MAX_HTTP_BODY;
use crate::error::{ProblemCode, RelayError};
use crate::http::jwks::jwks;
use crate::http::problems::problem;
use crate::json::strict;
use crate::protocol::registration::RegistrationRequest;
use crate::services::registration::register_session;
use crate::state::AppState;

static REG_WINDOW: AtomicU64 = AtomicU64::new(0);
static REG_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/site-sessions", post(site_sessions))
        .route("/.well-known/jwks.json", get(jwks))
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .layer(RequestBodyLimitLayer::new(MAX_HTTP_BODY))
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            std::time::Duration::from_secs(15),
        ))
        .with_state(state)
}

async fn live() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn ready(State(state): State<AppState>) -> Response {
    if crate::db::ping(&state.pool).await.is_err() {
        return problem(ProblemCode::RelayUnavailable);
    }
    let sync_running = state.sync_ready.load(std::sync::atomic::Ordering::Relaxed);
    let last_sync = state
        .last_matrix_sync_ms
        .load(std::sync::atomic::Ordering::Relaxed);
    if !matrix_sync_is_fresh(state.clock.now_ms(), last_sync, sync_running) {
        return problem(ProblemCode::RelayUnavailable);
    }
    (StatusCode::OK, "ready").into_response()
}

fn matrix_sync_is_fresh(now_ms: i64, last_sync_ms: i64, sync_running: bool) -> bool {
    sync_running
        && last_sync_ms > 0
        && now_ms.saturating_sub(last_sync_ms) <= crate::constants::MATRIX_SYNC_STALE_MS
}

async fn site_sessions(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    if !rate_limit_ok() {
        return crate::http::problems::rate_limited();
    }
    if body.len() > MAX_HTTP_BODY {
        return problem(ProblemCode::InvalidRequest);
    }
    let request = match strict::from_slice::<RegistrationRequest>(&body) {
        Ok(request) => request,
        Err(_) => return problem(ProblemCode::InvalidRequest),
    };
    match register_session(&state, request).await {
        Ok((response, created)) => {
            let status = if created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            };
            let mut res = (status, Json(response)).into_response();
            res.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            let _ = headers;
            res
        }
        Err(error) => {
            crate::state::Metrics::inc(&state.metrics.registration_failures);
            RelayError::from(error.code()).into_response()
        }
    }
}

fn rate_limit_ok() -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let window = REG_WINDOW.load(Ordering::Relaxed);
    if window != now {
        REG_WINDOW.store(now, Ordering::Relaxed);
        REG_COUNT.store(1, Ordering::Relaxed);
        return true;
    }
    REG_COUNT.fetch_add(1, Ordering::Relaxed) < 30
}

#[cfg(test)]
mod tests {
    use super::matrix_sync_is_fresh;
    use crate::constants::MATRIX_SYNC_STALE_MS;

    #[test]
    fn matrix_sync_readiness_requires_a_recent_success() {
        let now = 1_800_000_000_000;
        assert!(matrix_sync_is_fresh(now, now, true));
        assert!(matrix_sync_is_fresh(now, now - MATRIX_SYNC_STALE_MS, true));
        assert!(!matrix_sync_is_fresh(
            now,
            now - MATRIX_SYNC_STALE_MS - 1,
            true
        ));
        assert!(!matrix_sync_is_fresh(now, now, false));
        assert!(!matrix_sync_is_fresh(now, 0, true));
    }
}
