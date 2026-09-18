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
    pub encryption_unknown: bool,
    pub is_direct: bool,
    pub joined_member_count: u64,
    pub invited_member_count: u64,
    pub members: Vec<String>,
    pub relay_user_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomPolicyViolation {
    Unencrypted,
    UnexpectedMember,
    UnexpectedSender,
    Guest,
}

pub fn check_room(snapshot: &RoomSnapshot) -> Result<(), RoomPolicyViolation> {
    if !snapshot.encrypted {
        return Err(RoomPolicyViolation::Unencrypted);
    }
    // `m.direct` is advisory per-account data, not authoritative room state.
    // The relay defines a protocol DM by encryption and exact membership.
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
    if !snapshot.encrypted && !snapshot.encryption_unknown {
        return Err(RoomPolicyViolation::Unencrypted);
    }
    // The inviter's `m.direct` hint is often absent from stripped invite state.
    // Encryption and exact membership are verified authoritatively after join.
    let summary_unknown = snapshot.joined_member_count == 0 && snapshot.invited_member_count == 0;
    if !summary_unknown && (snapshot.joined_member_count != 1 || snapshot.invited_member_count != 1)
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
    // Invite rooms expose stripped state: the inviter's member event may be
    // absent even though the authoritative summary says 1 joined + 1 invited.
    // Full membership is fetched and enforced immediately after joining.
    if peers.len() > 1 {
        return Err(RoomPolicyViolation::UnexpectedMember);
    }
    if summary_unknown && peers.len() != 1 {
        return Err(RoomPolicyViolation::UnexpectedMember);
    }
    if peers
        .first()
        .is_some_and(|peer| peer.ends_with(":guest") || peer.contains("guest"))
    {
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
        let mut without_direct_hint = ok_room();
        without_direct_hint.is_direct = false;
        check_room(&without_direct_hint).unwrap();
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
            encryption_unknown: false,
            is_direct: true,
            joined_member_count: 1,
            invited_member_count: 1,
            members: vec!["@alice:pseud0.org".into(), MATRIX_USER_ID.into()],
            relay_user_id: MATRIX_USER_ID.into(),
        };
        check_invite(&invite).unwrap();

        let stripped_invite = InviteSnapshot {
            members: vec![MATRIX_USER_ID.into()],
            ..invite
        };
        check_invite(&stripped_invite).unwrap();

        let invite_without_direct_hint = InviteSnapshot {
            is_direct: false,
            ..stripped_invite
        };
        check_invite(&invite_without_direct_hint).unwrap();
    }

    #[test]
    fn rejects_unsafe_invites() {
        let base = InviteSnapshot {
            encrypted: true,
            encryption_unknown: false,
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

        let mut third_member = base.clone();
        third_member.joined_member_count = 2;
        third_member.members.push("@mallory:pseud0.org".into());
        assert_eq!(
            check_invite(&third_member),
            Err(RoomPolicyViolation::UnexpectedMember)
        );

        let unknown_summary_and_encryption = InviteSnapshot {
            encrypted: false,
            encryption_unknown: true,
            joined_member_count: 0,
            invited_member_count: 0,
            members: vec!["@alice:pseud0.org".into(), MATRIX_USER_ID.into()],
            ..base
        };
        check_invite(&unknown_summary_and_encryption).unwrap();
    }
}
