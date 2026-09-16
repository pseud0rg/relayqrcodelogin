use axum::http::StatusCode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProblemCode {
    InvalidRequest,
    UnsupportedVersion,
    InvalidSignature,
    DomainVerificationFailed,
    SessionNotFound,
    SessionConflict,
    RequestExpired,
    RequestCancelled,
    ChallengeReplayed,
    ConsentReplayed,
    AssertionReplayed,
    AudienceMismatch,
    Revoked,
    RateLimited,
    RelayUnavailable,
    InternalError,
}

impl ProblemCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::UnsupportedVersion => "unsupported_version",
            Self::InvalidSignature => "invalid_signature",
            Self::DomainVerificationFailed => "domain_verification_failed",
            Self::SessionNotFound => "session_not_found",
            Self::SessionConflict => "session_conflict",
            Self::RequestExpired => "request_expired",
            Self::RequestCancelled => "request_cancelled",
            Self::ChallengeReplayed => "challenge_replayed",
            Self::ConsentReplayed => "consent_replayed",
            Self::AssertionReplayed => "assertion_replayed",
            Self::AudienceMismatch => "audience_mismatch",
            Self::Revoked => "revoked",
            Self::RateLimited => "rate_limited",
            Self::RelayUnavailable => "relay_unavailable",
            Self::InternalError => "internal_error",
        }
    }

    pub fn status(self) -> StatusCode {
        match self {
            Self::InvalidRequest | Self::UnsupportedVersion | Self::InvalidSignature => {
                StatusCode::BAD_REQUEST
            }
            Self::DomainVerificationFailed | Self::AudienceMismatch => StatusCode::UNPROCESSABLE_ENTITY,
            Self::SessionNotFound => StatusCode::NOT_FOUND,
            Self::SessionConflict
            | Self::ChallengeReplayed
            | Self::ConsentReplayed
            | Self::AssertionReplayed => StatusCode::CONFLICT,
            Self::RequestExpired | Self::RequestCancelled | Self::Revoked => StatusCode::GONE,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::RelayUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::InvalidRequest => "Invalid request",
            Self::UnsupportedVersion => "Unsupported version",
            Self::InvalidSignature => "Invalid signature",
            Self::DomainVerificationFailed => "Domain verification failed",
            Self::SessionNotFound => "Session not found",
            Self::SessionConflict => "Session conflict",
            Self::RequestExpired => "Request expired",
            Self::RequestCancelled => "Request cancelled",
            Self::ChallengeReplayed => "Challenge replayed",
            Self::ConsentReplayed => "Consent replayed",
            Self::AssertionReplayed => "Assertion replayed",
            Self::AudienceMismatch => "Audience mismatch",
            Self::Revoked => "Revoked",
            Self::RateLimited => "Rate limited",
            Self::RelayUnavailable => "Relay unavailable",
            Self::InternalError => "Internal error",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("protocol problem")]
    Problem(ProblemCode),
    #[error("internal")]
    Internal(#[from] anyhow::Error),
}

impl RelayError {
    pub fn problem(code: ProblemCode) -> Self {
        Self::Problem(code)
    }

    pub fn code(&self) -> ProblemCode {
        match self {
            Self::Problem(code) => *code,
            Self::Internal(_) => ProblemCode::InternalError,
        }
    }
}

impl From<ProblemCode> for RelayError {
    fn from(value: ProblemCode) -> Self {
        Self::Problem(value)
    }
}
