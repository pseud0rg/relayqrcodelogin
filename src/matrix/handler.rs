use crate::room_policy::RoomSnapshot;
use crate::services::login::{handle_inbound, InboundEvent};
use crate::state::AppState;

pub async fn dispatch_text(
    state: &AppState,
    event_id: &str,
    room_id: &str,
    sender: &str,
    decrypted: bool,
    redacted: bool,
    body: &str,
    room: RoomSnapshot,
) {
    let event = InboundEvent {
        event_id: event_id.to_string(),
        room_id: room_id.to_string(),
        sender: sender.to_string(),
        decrypted,
        redacted,
        body: body.to_string(),
        room,
    };
    if let Err(error) = handle_inbound(state, event).await {
        tracing::warn!(code = error.code().as_str(), "inbound protocol rejected");
    }
}
