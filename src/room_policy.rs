use crate::constants::MATRIX_USER_ID;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomSnapshot {
    pub encrypted: bool,
    pub is_direct: bool,
    pub members: Vec<String>,
    pub sender: String,
    pub relay_user_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteSnapshot {
    pub encrypted: bool,
    pub is_direct: bool,
    pub joined_member_count: u64,
    pub invited_member_count: u64,
    pub members: Vec<String>,
    pub relay_user_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomPolicyViolation {
    Unencrypted,
    NotDirect,
    UnexpectedMember,
    UnexpectedSender,
    Guest,
}

pub fn check_room(snapshot: &RoomSnapshot) -> Result<(), RoomPolicyViolation> {
    if !snapshot.encrypted {
        return Err(RoomPolicyViolation::Unencrypted);
    }
    if !snapshot.is_direct {
        return Err(RoomPolicyViolation::NotDirect);
    }
    if snapshot.members.len() != 2 {
        return Err(RoomPolicyViolation::UnexpectedMember);
    }
    let relay = if snapshot.relay_user_id.is_empty() {
        MATRIX_USER_ID
    } else {
        snapshot.relay_user_id.as_str()
    };
    if !snapshot.members.iter().any(|m| m == relay) {
        return Err(RoomPolicyViolation::UnexpectedMember);
    }
    if snapshot
        .members
        .iter()
        .any(|m| m.ends_with(":guest") || m.contains("guest"))
    {
        return Err(RoomPolicyViolation::Guest);
    }
    if snapshot.sender == relay || !snapshot.members.iter().any(|m| m == &snapshot.sender) {
        return Err(RoomPolicyViolation::UnexpectedSender);
    }
    Ok(())
}

pub fn check_invite(snapshot: &InviteSnapshot) -> Result<(), RoomPolicyViolation> {
    if !snapshot.encrypted {
        return Err(RoomPolicyViolation::Unencrypted);
    }
    if !snapshot.is_direct {
        return Err(RoomPolicyViolation::NotDirect);
    }
    if snapshot.joined_member_count != 1
        || snapshot.invited_member_count != 1
        || snapshot.members.len() != 2
    {
        return Err(RoomPolicyViolation::UnexpectedMember);
    }
    if !snapshot
        .members
        .iter()
        .any(|member| member == &snapshot.relay_user_id)
    {
        return Err(RoomPolicyViolation::UnexpectedMember);
    }
    let peers = snapshot
        .members
        .iter()
        .filter(|member| *member != &snapshot.relay_user_id)
        .collect::<Vec<_>>();
    if peers.len() != 1 {
        return Err(RoomPolicyViolation::UnexpectedMember);
    }
    if peers[0].ends_with(":guest") || peers[0].contains("guest") {
        return Err(RoomPolicyViolation::Guest);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_room() -> RoomSnapshot {
        RoomSnapshot {
            encrypted: true,
            is_direct: true,
            members: vec!["@alice:pseud0.org".into(), MATRIX_USER_ID.into()],
            sender: "@alice:pseud0.org".into(),
            relay_user_id: MATRIX_USER_ID.into(),
        }
    }

    #[test]
    fn accepts_encrypted_dm() {
        check_room(&ok_room()).unwrap();
    }

    #[test]
    fn rejects_unencrypted_and_third_member() {
        let mut room = ok_room();
        room.encrypted = false;
        assert_eq!(check_room(&room), Err(RoomPolicyViolation::Unencrypted));
        let mut room = ok_room();
        room.members.push("@mallory:pseud0.org".into());
        assert_eq!(
            check_room(&room),
            Err(RoomPolicyViolation::UnexpectedMember)
        );
    }

    #[test]
    fn accepts_encrypted_direct_two_party_invite() {
        let invite = InviteSnapshot {
            encrypted: true,
            is_direct: true,
            joined_member_count: 1,
            invited_member_count: 1,
            members: vec!["@alice:pseud0.org".into(), MATRIX_USER_ID.into()],
            relay_user_id: MATRIX_USER_ID.into(),
        };
        check_invite(&invite).unwrap();
    }

    #[test]
    fn rejects_unsafe_invites() {
        let base = InviteSnapshot {
            encrypted: true,
            is_direct: true,
            joined_member_count: 1,
            invited_member_count: 1,
            members: vec!["@alice:pseud0.org".into(), MATRIX_USER_ID.into()],
            relay_user_id: MATRIX_USER_ID.into(),
        };
        let mut unencrypted = base.clone();
        unencrypted.encrypted = false;
        assert_eq!(
            check_invite(&unencrypted),
            Err(RoomPolicyViolation::Unencrypted)
        );

        let mut third_member = base;
        third_member.joined_member_count = 2;
        third_member.members.push("@mallory:pseud0.org".into());
        assert_eq!(
            check_invite(&third_member),
            Err(RoomPolicyViolation::UnexpectedMember)
        );
    }
}
