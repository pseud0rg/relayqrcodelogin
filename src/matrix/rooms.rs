#[cfg(feature = "matrix")]
use crate::room_policy::RoomSnapshot;

#[cfg(feature = "matrix")]
pub async fn snapshot(
    room: &matrix_sdk::Room,
    sender: &str,
    relay_user_id: &str,
) -> Result<RoomSnapshot, crate::error::RelayError> {
    use matrix_sdk::ruma::events::room::member::MembershipState;
    use crate::error::{ProblemCode, RelayError};

    let encrypted = room.encryption_state().is_encrypted();
    let is_direct = room.is_direct().await.unwrap_or(false);
    let members = room
        .members(matrix_sdk::RoomMemberships::ACTIVE)
        .await
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    let ids = members
        .into_iter()
        .filter(|member| member.membership() == &MembershipState::Join)
        .map(|member| member.user_id().to_string())
        .collect();
    Ok(RoomSnapshot {
        encrypted,
        is_direct,
        members: ids,
        sender: sender.to_string(),
        relay_user_id: relay_user_id.to_string(),
    })
}
