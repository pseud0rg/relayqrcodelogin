use pseud0_web_login_relay::constants::MATRIX_USER_ID;
use pseud0_web_login_relay::room_policy::{check_room, RoomPolicyViolation, RoomSnapshot};

fn base() -> RoomSnapshot {
    RoomSnapshot {
        encrypted: true,
        is_direct: true,
        members: vec!["@alice:pseud0.org".into(), MATRIX_USER_ID.into()],
        sender: "@alice:pseud0.org".into(),
        relay_user_id: MATRIX_USER_ID.into(),
    }
}

#[test]
fn unencrypted_rooms_cannot_produce_assertions() {
    let mut room = base();
    room.encrypted = false;
    assert_eq!(check_room(&room), Err(RoomPolicyViolation::Unencrypted));
}

#[test]
fn third_member_cannot_produce_assertions() {
    let mut room = base();
    room.members.push("@mallory:pseud0.org".into());
    assert_eq!(check_room(&room), Err(RoomPolicyViolation::UnexpectedMember));
}
