use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use rand::RngCore;
use serde::Serialize;

use crate::crypto::base64url;
use crate::error::{ProblemCode, RelayError};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProblemBody {
    #[serde(rename = "type")]
    pub type_url: String,
    pub title: String,
    pub status: u16,
    pub code: String,
    pub correlation_id: String,
}

impl IntoResponse for RelayError {
    fn into_response(self) -> Response {
        if let RelayError::Internal(error) = &self {
            tracing::error!(error = %error, "internal error");
        }
        problem(self.code()).into_response()
    }
}

pub fn problem(code: ProblemCode) -> Response {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    let body = ProblemBody {
        type_url: format!("https://relay.pseud0.org/problems/{}", code.as_str()),
        title: code.title().to_string(),
        status: code.status().as_u16(),
        code: code.as_str().to_string(),
        correlation_id: base64url::encode(&bytes),
    };
    let mut response = (code.status(), Json(body)).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    response
}

pub fn rate_limited() -> Response {
    let mut response = problem(ProblemCode::RateLimited);
    *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
    response
}
