use std::fs::{self, File};
use std::path::Path;
use fs4::fs_std::FileExt;
#[cfg(feature = "matrix")]
use std::sync::Arc;

use crate::error::{ProblemCode, RelayError};
#[cfg(feature = "matrix")]
use crate::config::AppConfig;
#[cfg(feature = "matrix")]
use crate::state::{AppState, MessageSink};

pub struct StoreLock(#[allow(dead_code)] File);

pub fn lock_crypto_store(path: &Path) -> Result<StoreLock, RelayError> {
    fs::create_dir_all(path).map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    let file = File::create(path.join(".sync.lock"))
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    file.try_lock_exclusive()
        .map_err(|_| RelayError::problem(ProblemCode::RelayUnavailable))?;
    Ok(StoreLock(file))
}

#[cfg(feature = "matrix")]
pub struct MatrixRuntime {
    pub client: matrix_sdk::Client,
    _lock: StoreLock,
}

#[cfg(feature = "matrix")]
impl MatrixRuntime {
    pub async fn start(config: &AppConfig) -> Result<Self, RelayError> {
        let lock = lock_crypto_store(&config.crypto_store_path)?;
        let passphrase = config
            .crypto_passphrase
            .as_deref()
            .ok_or(RelayError::problem(ProblemCode::InternalError))?;
        let access_token = config
            .matrix_access_token
            .clone()
            .ok_or(RelayError::problem(ProblemCode::InternalError))?;
        let device_id = config
            .matrix_device_id
            .clone()
            .ok_or(RelayError::problem(ProblemCode::InternalError))?;

        let client = matrix_sdk::Client::builder()
            .homeserver_url(&config.matrix_homeserver)
            .sqlite_store(&config.crypto_store_path, Some(passphrase))
            .build()
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;

        let user_id: matrix_sdk::ruma::OwnedUserId = config
            .matrix_user_id
            .as_str()
            .try_into()
            .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
        let session = matrix_sdk::authentication::matrix::MatrixSession {
            meta: matrix_sdk::SessionMeta {
                user_id,
                device_id: device_id.into(),
            },
            tokens: matrix_sdk::SessionTokens {
                access_token,
                refresh_token: None,
            },
        };
        client
            .restore_session(session)
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        Ok(Self { client, _lock: lock })
    }

    pub fn sink(&self) -> Arc<dyn MessageSink> {
        Arc::new(MatrixSink {
            client: self.client.clone(),
        })
    }
}

#[cfg(feature = "matrix")]
struct MatrixSink {
    client: matrix_sdk::Client,
}

#[cfg(feature = "matrix")]
#[async_trait::async_trait]
impl MessageSink for MatrixSink {
    async fn send_notice(&self, room_id: &str, body: &str) -> Result<(), RelayError> {
        use matrix_sdk::ruma::events::room::message::RoomMessageEventContent;
        let room_id: matrix_sdk::ruma::OwnedRoomId = room_id
            .try_into()
            .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
        let room = self
            .client
            .get_room(&room_id)
            .ok_or(RelayError::problem(ProblemCode::InternalError))?;
        if !room.encryption_state().is_encrypted() {
            return Err(RelayError::problem(ProblemCode::InternalError));
        }
        room.send(RoomMessageEventContent::notice_plain(body))
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        Ok(())
    }
}

#[cfg(feature = "matrix")]
pub async fn sync_forever(state: AppState, runtime: MatrixRuntime) {
    use matrix_sdk::config::SyncSettings;
    use matrix_sdk::ruma::events::room::message::{MessageType, OriginalSyncRoomMessageEvent};

    let client = runtime.client.clone();
    let app = state.clone();
    client.add_event_handler(
        move |event: OriginalSyncRoomMessageEvent, room: matrix_sdk::Room| {
            let app = app.clone();
            async move {
                let clear = match &event.content.msgtype {
                    MessageType::Notice(content) => content.body.clone(),
                    MessageType::Text(content) => content.body.clone(),
                    _ => return,
                };
                let decrypted = true;
                let Ok(snapshot) = crate::matrix::rooms::snapshot(&room, event.sender.as_str(), &app.relay_user_id).await
                else {
                    return;
                };
                crate::matrix::handler::dispatch_text(
                    &app,
                    event.event_id.as_str(),
                    room.room_id().as_str(),
                    event.sender.as_str(),
                    decrypted && room.encryption_state().is_encrypted(),
                    false,
                    &clear,
                    snapshot,
                )
                .await;
            }
        },
    );
    state.sync_ready.store(true, std::sync::atomic::Ordering::Relaxed);
    if let Err(error) = client.sync(SyncSettings::default()).await {
        tracing::error!(error = %error, "matrix sync ended");
        state.sync_ready.store(false, std::sync::atomic::Ordering::Relaxed);
    }
    let _ = runtime;
}
