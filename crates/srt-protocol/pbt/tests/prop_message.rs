use proptest::prelude::*;
use shiguredo_srt::{
    ConnectionEvent, ConnectionOptions, ConnectionOutput, ConnectionState, SrtConnection, Timestamp,
};

fn ts(micros: u64) -> Timestamp {
    Timestamp::from_micros(micros)
}

fn drain_sent(conn: &mut SrtConnection) -> Vec<Vec<u8>> {
    let mut sent = Vec::new();
    while let Some(out) = conn.poll_output() {
        if let ConnectionOutput::SendPacket(data) = out {
            sent.push(data);
        }
    }
    sent
}

fn setup_pair() -> (SrtConnection, SrtConnection) {
    let opts = ConnectionOptions {
        tsbpd_delay: 0,
        ..Default::default()
    };
    let mut caller = SrtConnection::new_caller(opts.clone());
    let mut listener = SrtConnection::new_listener(opts);
    caller.connect(ts(0)).unwrap();
    for i in 0..10u64 {
        let now = ts(i * 10_000);
        for data in drain_sent(&mut caller) {
            let _ = listener.feed_recv_buf(&data, now);
        }
        for data in drain_sent(&mut listener) {
            let _ = caller.feed_recv_buf(&data, now);
        }
        if caller.state() == ConnectionState::Connected
            && listener.state() == ConnectionState::Connected
        {
            while caller.poll_event().is_some() {}
            while listener.poll_event().is_some() {}
            return (caller, listener);
        }
    }
    panic!("connection not established");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn fragmentation_reassembly_roundtrip(payload_size in 1usize..8000usize) {
        let (mut caller, mut listener) = setup_pair();
        let payload: Vec<u8> = (0..payload_size).map(|i| (i % 256) as u8).collect();
        let now = ts(100_000);

        caller.send_message(&payload, now).unwrap();
        for data in drain_sent(&mut caller) {
            listener.feed_recv_buf(&data, now).unwrap();
        }

        let mut received = Vec::new();
        while let Some(event) = listener.poll_event() {
            if let ConnectionEvent::DataReceived { payload, .. } = event {
                received.push(payload);
            }
        }

        prop_assert_eq!(received.len(), 1);
        prop_assert_eq!(&received[0], &payload);
    }

    #[test]
    fn message_number_preserved(payload_size in 1usize..4000usize) {
        let (mut caller, mut listener) = setup_pair();
        let payload = vec![0xABu8; payload_size];
        let now = ts(100_000);

        caller.send_message(&payload, now).unwrap();
        for data in drain_sent(&mut caller) {
            listener.feed_recv_buf(&data, now).unwrap();
        }

        let mut msg_nums = Vec::new();
        while let Some(event) = listener.poll_event() {
            if let ConnectionEvent::DataReceived { message_number, .. } = event {
                msg_nums.push(message_number);
            }
        }
        prop_assert_eq!(msg_nums.len(), 1);
    }
}
