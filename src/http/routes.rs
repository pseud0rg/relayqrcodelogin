use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
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
    if !state.sync_ready.load(std::sync::atomic::Ordering::Relaxed) {
        return problem(ProblemCode::RelayUnavailable);
    }
    (StatusCode::OK, "ready").into_response()
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
