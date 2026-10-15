use super::*;

#[test]
fn rejected_inbound_items_return_ownership_and_refund_only_their_own_quota() {
    let control = Arc::new(SessionControl::new());
    let (inbox, receiver) = SessionInbox::new(control);
    for _ in 0..SESSION_INBOUND_CAPACITY {
        inbox
            .try_send(
                srt_proto::Bytes::from_static(b"x").into(),
                Timestamp::default(),
            )
            .unwrap();
    }
    let rejected = inbox
        .try_send(
            srt_proto::Bytes::from_static(b"rejected").into(),
            Timestamp::default(),
        )
        .expect_err("the message-count limit rejects without destroying the payload");
    assert!(rejected.eq(&b"rejected"[..]));
    assert_eq!(
        inbox.bytes.load(Ordering::Acquire),
        SESSION_INBOUND_CAPACITY
    );
    drop(receiver);
    assert_eq!(inbox.bytes.load(Ordering::Acquire), 0);
    let closed = inbox
        .try_send(rejected, Timestamp::default())
        .expect_err("a closed channel must also return ownership");
    assert_eq!(inbox.bytes.load(Ordering::Acquire), 0);
    let mut retired = closed.retire();
    assert_eq!(retired.reclaim(0), 0);
    assert!(!retired.is_complete());
    assert_eq!(retired.reclaim(1), 1);
    assert!(retired.is_complete());
}
