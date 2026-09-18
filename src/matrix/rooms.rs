#[cfg(feature = "matrix")]
use crate::room_policy::{InviteSnapshot, RoomSnapshot};

#[cfg(feature = "matrix")]
pub async fn snapshot(
    room: &matrix_sdk::Room,
    sender: &str,
    relay_user_id: &str,
) -> Result<RoomSnapshot, crate::error::RelayError> {
    use crate::error::{ProblemCode, RelayError};
    use matrix_sdk::ruma::events::room::member::MembershipState;

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

#[cfg(feature = "matrix")]
pub async fn invite_is_safe(
    room: &matrix_sdk::Room,
    relay_user_id: &str,
) -> Result<bool, crate::error::RelayError> {
    use crate::error::{ProblemCode, RelayError};

    if room.state() != matrix_sdk::RoomState::Invited {
        return Ok(false);
    }
    let members = room
        .members(matrix_sdk::RoomMemberships::ACTIVE)
        .await
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    let encryption_state = room.encryption_state();
    let invite = InviteSnapshot {
        encrypted: encryption_state.is_encrypted(),
        encryption_unknown: encryption_state.is_unknown(),
        is_direct: room.is_direct().await.unwrap_or(false),
        joined_member_count: room.joined_members_count(),
        invited_member_count: room.invited_members_count(),
        members: members
            .into_iter()
            .map(|member| member.user_id().to_string())
            .collect(),
        relay_user_id: relay_user_id.to_string(),
    };
    let decision = crate::room_policy::check_invite(&invite);
    if let Err(reason) = decision {
        tracing::warn!(
            ?reason,
            encrypted = invite.encrypted,
            encryption_unknown = invite.encryption_unknown,
            is_direct = invite.is_direct,
            joined_member_count = invite.joined_member_count,
            invited_member_count = invite.invited_member_count,
            visible_member_count = invite.members.len(),
            "matrix invitation failed pre-join policy"
        );
    }
    Ok(decision.is_ok())
}

#[cfg(feature = "matrix")]
pub async fn joined_room_is_safe(
    room: &matrix_sdk::Room,
    relay_user_id: &str,
) -> Result<bool, crate::error::RelayError> {
    use crate::error::{ProblemCode, RelayError};
    use matrix_sdk::ruma::events::room::member::MembershipState;

    if room.state() != matrix_sdk::RoomState::Joined {
        return Ok(false);
    }
    room.request_encryption_state()
        .await
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    room.sync_members()
        .await
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    let members = room
        .members_no_sync(matrix_sdk::RoomMemberships::JOIN)
        .await
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    let ids = members
        .into_iter()
        .filter(|member| member.membership() == &MembershipState::Join)
        .map(|member| member.user_id().to_string())
        .collect::<Vec<_>>();
    let Some(peer) = ids
        .iter()
        .find(|member| member.as_str() != relay_user_id)
        .cloned()
    else {
        return Ok(false);
    };
    let snapshot = RoomSnapshot {
        encrypted: room.encryption_state().is_encrypted(),
        is_direct: room.is_direct().await.unwrap_or(false),
        members: ids,
        sender: peer,
        relay_user_id: relay_user_id.to_string(),
    };
    Ok(crate::room_policy::check_room(&snapshot).is_ok())
}
