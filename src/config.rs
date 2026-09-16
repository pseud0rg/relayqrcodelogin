use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;

use crate::constants::{DEFAULT_KID, MATRIX_API, MATRIX_USER_ID, RELAY_ORIGIN};
use crate::crypto::at_rest::AtRestKey;
use crate::crypto::ed25519;
use crate::error::{ProblemCode, RelayError};

#[derive(Clone)]
pub struct AppConfig {
    pub listen: SocketAddr,
    pub relay_origin: String,
    pub matrix_homeserver: String,
    pub matrix_user_id: String,
    pub matrix_enabled: bool,
    pub database_url: String,
    pub crypto_store_path: PathBuf,
    pub data_path: PathBuf,
    pub signing_kid: String,
    pub subject_key_version: i32,
    pub signing_key: SigningKey,
    pub subject_secret: Vec<u8>,
    pub at_rest: AtRestKey,
    pub lookup_pepper: Vec<u8>,
    pub matrix_access_token: Option<String>,
    pub matrix_device_id: Option<String>,
    pub crypto_passphrase: Option<String>,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, RelayError> {
        let database_url = database_url()?;
        let signing_key = ed25519::parse_signing_key(&read_required_secret(
            "RELAY_SIGNING_KEY_FILE",
            "RELAY_SIGNING_KEY",
        )?)?;
        let subject_secret = normalize_secret_bytes(&read_required_secret(
            "RELAY_SUBJECT_KEY_FILE",
            "RELAY_SUBJECT_KEY",
        )?)?;
        let at_rest = AtRestKey::from_bytes(&read_required_secret(
            "RELAY_AT_REST_KEY_FILE",
            "RELAY_AT_REST_KEY",
        )?)?;
        let lookup_pepper = normalize_secret_bytes(&read_required_secret(
            "RELAY_LOOKUP_PEPPER_FILE",
            "RELAY_LOOKUP_PEPPER",
        )?)?;
        if subject_secret.len() < 32 || lookup_pepper.len() < 32 {
            return Err(RelayError::problem(ProblemCode::InternalError));
        }
        Ok(Self {
            listen: std::env::var("LISTEN_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:8080".into())
                .parse()
                .map_err(|_| RelayError::problem(ProblemCode::InternalError))?,
            relay_origin: std::env::var("RELAY_ORIGIN").unwrap_or_else(|_| RELAY_ORIGIN.into()),
            matrix_homeserver: std::env::var("MATRIX_HOMESERVER").unwrap_or_else(|_| MATRIX_API.into()),
            matrix_user_id: std::env::var("MATRIX_USER_ID").unwrap_or_else(|_| MATRIX_USER_ID.into()),
            matrix_enabled: env_bool("MATRIX_ENABLED", true),
            database_url,
            crypto_store_path: PathBuf::from(
                std::env::var("CRYPTO_STORE_PATH").unwrap_or_else(|_| "./relay/crypto-store".into()),
            ),
            data_path: PathBuf::from(std::env::var("DATA_PATH").unwrap_or_else(|_| "./relay/data".into())),
            signing_kid: std::env::var("RELAY_SIGNING_KID").unwrap_or_else(|_| DEFAULT_KID.into()),
            subject_key_version: std::env::var("SUBJECT_KEY_VERSION")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1),
            signing_key,
            subject_secret,
            at_rest,
            lookup_pepper,
            matrix_access_token: read_optional_secret(
                "RELAY_MATRIX_ACCESS_TOKEN_FILE",
                "RELAY_MATRIX_ACCESS_TOKEN",
            )?,
            matrix_device_id: read_optional_secret(
                "RELAY_MATRIX_DEVICE_ID_FILE",
                "RELAY_MATRIX_DEVICE_ID",
            )?,
            crypto_passphrase: read_optional_secret(
                "RELAY_CRYPTO_PASSPHRASE_FILE",
                "RELAY_CRYPTO_PASSPHRASE",
            )?,
        })
    }
}

fn env_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes"))
        .unwrap_or(default)
}

fn read_required_secret(file_var: &str, env_var: &str) -> Result<Vec<u8>, RelayError> {
    if let Ok(path) = std::env::var(file_var) {
        return read_file_bytes(Path::new(&path));
    }
    if let Ok(value) = std::env::var(env_var) {
        return Ok(value.into_bytes());
    }
    Err(RelayError::problem(ProblemCode::InternalError))
}

fn read_optional_secret(file_var: &str, env_var: &str) -> Result<Option<String>, RelayError> {
    if let Ok(path) = std::env::var(file_var) {
        if Path::new(&path).exists() {
            return Ok(Some(
                String::from_utf8(read_file_bytes(Path::new(&path))?)
                    .map_err(|_| RelayError::problem(ProblemCode::InternalError))?
                    .trim()
                    .to_string(),
            ));
        }
    }
    Ok(std::env::var(env_var).ok().map(|v| v.trim().to_string()))
}

fn database_url() -> Result<String, RelayError> {
    if let Ok(url) = std::env::var("DATABASE_URL") {
        if !url.is_empty() {
            return Ok(url);
        }
    }
    if let Ok(path) = std::env::var("DATABASE_URL_FILE") {
        if Path::new(&path).exists() {
            return Ok(String::from_utf8(read_file_bytes(Path::new(&path))?)
                .map_err(|_| RelayError::problem(ProblemCode::InternalError))?
                .trim()
                .to_string());
        }
    }
    if let (Ok(host), Ok(name), Ok(user), Ok(password_file)) = (
        std::env::var("RELAY_DB_HOST"),
        std::env::var("RELAY_DB_NAME"),
        std::env::var("RELAY_DB_USER"),
        std::env::var("RELAY_DB_PASSWORD_FILE"),
    ) {
        let password = String::from_utf8(read_file_bytes(Path::new(&password_file))?)
            .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
        return Ok(format!(
            "postgres://{user}:{}@{host}:5432/{name}",
            urlencoding(&password.trim())
        ));
    }
    Err(RelayError::problem(ProblemCode::InternalError))
}

fn urlencoding(value: &str) -> String {
    let mut out = String::new();
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn read_file_bytes(path: &Path) -> Result<Vec<u8>, RelayError> {
    fs::read(path).map_err(|_| RelayError::problem(ProblemCode::InternalError))
}

fn normalize_secret_bytes(raw: &[u8]) -> Result<Vec<u8>, RelayError> {
    if raw.len() == 32 {
        return Ok(raw.to_vec());
    }
    let text = std::str::from_utf8(raw)
        .map_err(|_| RelayError::problem(ProblemCode::InvalidRequest))?
        .trim();
    if let Ok(bytes) = hex::decode(text) {
        if bytes.len() >= 32 {
            return Ok(bytes);
        }
    }
    Ok(raw.to_vec())
}
