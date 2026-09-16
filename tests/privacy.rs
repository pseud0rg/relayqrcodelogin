use pseud0_web_login_relay::crypto::subject;

#[test]
fn pairwise_subject_never_embeds_matrix_id() {
    let secret = [9u8; 32];
    let mxid = "@alice:pseud0.org";
    let sub = subject::derive_pairwise_sub(&secret, "login.example.org", mxid).unwrap();
    assert!(!sub.contains('@'));
    assert!(!sub.contains(mxid));
    assert!(!sub.contains("alice"));
    assert!(!sub.contains("pseud0.org"));
}
