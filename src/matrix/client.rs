use fs4::fs_std::FileExt;
use std::fs::{self, File};
use std::path::Path;
#[cfg(feature = "matrix")]
use std::sync::Arc;

#[cfg(feature = "matrix")]
use crate::config::AppConfig;
use crate::error::{ProblemCode, RelayError};
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
        Ok(Self {
            client,
            _lock: lock,
        })
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
    use matrix_sdk::LoopCtrl;
    use matrix_sdk::config::SyncSettings;
    use matrix_sdk::ruma::events::room::message::{MessageType, OriginalSyncRoomMessageEvent};
    use std::sync::atomic::Ordering;

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
                let Ok(snapshot) = crate::matrix::rooms::snapshot(
                    &room,
                    event.sender.as_str(),
                    &app.relay_user_id,
                )
                .await
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
    let callback_client = client.clone();
    let callback_state = state.clone();
    if let Err(error) = client
        .sync_with_result_callback(SyncSettings::default(), move |result| {
            let client = callback_client.clone();
            let state = callback_state.clone();
            async move {
                match result {
                    Ok(_) => {
                        if let Err(error) = auto_join_invites(&client, &state.relay_user_id).await {
                            state.sync_ready.store(false, Ordering::Relaxed);
                            tracing::warn!(
                                code = error.code().as_str(),
                                "matrix invitation processing failed"
                            );
                        } else {
                            state
                                .last_matrix_sync_ms
                                .store(state.clock.now_ms(), Ordering::Relaxed);
                            state.sync_ready.store(true, Ordering::Relaxed);
                        }
                    }
                    Err(error) => {
                        state.sync_ready.store(false, Ordering::Relaxed);
                        tracing::warn!(error = %error, "matrix sync request failed");
                    }
                }
                Ok(LoopCtrl::Continue)
            }
        })
        .await
    {
        tracing::error!(error = %error, "matrix sync ended");
        state.sync_ready.store(false, Ordering::Relaxed);
    }
    let _ = runtime;
}

#[cfg(feature = "matrix")]
async fn auto_join_invites(
    client: &matrix_sdk::Client,
    relay_user_id: &str,
) -> Result<(), RelayError> {
    for room in client.invited_rooms() {
        if !crate::matrix::rooms::invite_is_safe(&room, relay_user_id).await? {
            tracing::warn!("rejecting unsafe matrix invitation");
            room.leave()
                .await
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            continue;
        }

        room.join()
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let joined = client
            .get_room(room.room_id())
            .ok_or(RelayError::problem(ProblemCode::InternalError))?;
        if crate::matrix::rooms::joined_room_is_safe(&joined, relay_user_id).await? {
            tracing::info!("joined encrypted direct matrix room");
        } else {
            tracing::warn!("leaving matrix room that failed post-join policy");
            joined
                .leave()
                .await
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        }
    }
    Ok(())
}
