//! Wire equivalence and transactional buffer semantics tests for srt-protocol.

use bytes::Bytes;
use srt_proto::crypto::{CipherMode, KeyLength};
use srt_proto::wire::SrtPacket;
use srt_proto::{
    ConnectionEvent, ConnectionOptions, ConnectionOutput, ConnectionState, ErrorKind, OutputInto,
    OutputMeta, SrtConnection, Timestamp,
};

fn ts(micros: u64) -> Timestamp {
    Timestamp::from_micros(micros)
}

fn test_km_salt() -> [u8; 16] {
    [0x42; 16]
}

fn establish_pair(
    passphrase: Option<&str>,
    key_length: KeyLength,
    cipher_mode: CipherMode,
) -> (SrtConnection, SrtConnection) {
    let mut caller_opts = ConnectionOptions {
        socket_id: 0x1000,
        tsbpd_delay: 0,
        ..Default::default()
    };
    let mut listener_opts = ConnectionOptions {
        socket_id: 0x2000,
        tsbpd_delay: 0,
        ..Default::default()
    };
    if let Some(pass) = passphrase {
        caller_opts.passphrase = Some(pass.to_string());
        caller_opts.key_length = key_length;
        caller_opts.cipher_mode = cipher_mode;
        caller_opts.crypto_salt = Some(test_km_salt());
        caller_opts.crypto_sek = Some(vec![0x77; key_length.len()]);
        listener_opts.passphrase = Some(pass.to_string());
        listener_opts.key_length = key_length;
        listener_opts.cipher_mode = cipher_mode;
    }

    let mut caller = SrtConnection::new_caller(caller_opts);
    let mut listener = SrtConnection::new_listener(listener_opts);

    let mut now = ts(1_000);
    caller.connect(now).expect("caller connect");

    for round in 0..10 {
        now = ts(2_000 + round * 1_000);
        let mut progress = false;
        while let Some(out) = caller.poll_output().unwrap() {
            progress = true;
            if let ConnectionOutput::SendPacket(packet) = out {
                let _ = listener.feed_recv_buf(&packet, now);
            }
        }
        while let Some(out) = listener.poll_output().unwrap() {
            progress = true;
            if let ConnectionOutput::SendPacket(packet) = out {
                let _ = caller.feed_recv_buf(&packet, now);
            }
        }
        if caller.state() == ConnectionState::Connected
            && listener.state() == ConnectionState::Connected
        {
            break;
        }
        if !progress {
            break;
        }
    }

    assert_eq!(caller.state(), ConnectionState::Connected);
    assert_eq!(listener.state(), ConnectionState::Connected);

    // Drain any remaining initial connection timer events
    // Drain any remaining initial connection timer events and events
    while caller.poll_output().unwrap().is_some() {}
    while listener.poll_output().unwrap().is_some() {}
    while caller.poll_event().is_some() {}
    while listener.poll_event().is_some() {}
    (caller, listener)
}

#[test]
fn buffer_too_small_is_transactional_and_does_not_corrupt_queue() {
    let (mut caller, _listener) = establish_pair(None, KeyLength::Aes128, CipherMode::Ctr);
    let now = ts(10_000);

    // Queue one data packet
    caller
        .send(b"transactional-test-payload", now)
        .expect("send succeeds");

    let meta = caller.peek_output().expect("output is queued");
    let wire_len = match meta {
        OutputMeta::Datagram { wire_len, .. } => wire_len,
        other => panic!("expected datagram, got {other:?}"),
    };

    // 1. Buffer strictly smaller than wire_len: must fail
    let mut tiny_buf = vec![0u8; wire_len - 1];
    let err = caller
        .poll_output_into(&mut tiny_buf)
        .expect_err("small buffer must be rejected");
    assert_eq!(err.kind, ErrorKind::InsufficientBuffer);

    // 2. Queue state and peek must be completely untouched
    let meta_after = caller.peek_output().expect("output must still be queued");
    assert_eq!(meta, meta_after);

    // 3. Repeating with a 0-length buffer also fails cleanly
    let mut zero_buf = [];
    let err0 = caller
        .poll_output_into(&mut zero_buf)
        .expect_err("zero buffer must be rejected");
    assert_eq!(err0.kind, ErrorKind::InsufficientBuffer);
    assert_eq!(caller.peek_output(), Some(meta));

    // 4. Now provide sufficient buffer: succeeds and consumes the output
    let mut full_buf = vec![0u8; wire_len + 16];
    let result = caller
        .poll_output_into(&mut full_buf)
        .expect("sufficient buffer succeeds");
    assert!(
        matches!(result, Some(OutputInto::Datagram { len, .. }) if len == wire_len),
        "the materialized length must be the datagram's wire length: {result:?}"
    );

    // 5. The datagram is consumed exactly once. Materializing it arms the
    // sender timeout, so a timer action is legitimately queued behind it -- what
    // must not remain is another datagram.
    loop {
        match caller
            .poll_output_into(&mut full_buf)
            .expect("output materializes")
        {
            None => break,
            Some(OutputInto::SetTimer { .. } | OutputInto::ClearTimer { .. }) => {}
            Some(OutputInto::Datagram { .. }) => panic!("the datagram was queued twice"),
        }
    }
}

#[test]
fn wire_equivalence_plaintext() {
    let (mut caller_a, mut listener_a) = establish_pair(None, KeyLength::Aes128, CipherMode::Ctr);
    let (mut caller_b, mut listener_b) = establish_pair(None, KeyLength::Aes128, CipherMode::Ctr);

    let now = ts(50_000);
    let payload = b"Hello SRT Plaintext Streaming Wire Test!";

    caller_a.send(payload, now).expect("send a");
    caller_b.send(payload, now).expect("send b");

    // Path A: legacy poll_output()
    let mut packet_a = None;
    while let Some(out) = caller_a.poll_output().unwrap() {
        if let ConnectionOutput::SendPacket(bytes) = out {
            packet_a = Some(bytes);
            break;
        }
    }
    let packet_a = packet_a.expect("packet_a produced");

    // Path B: direct poll_output_into()
    let meta = caller_b.peek_output().expect("meta exists");
    let wire_len = match meta {
        OutputMeta::Datagram { wire_len, .. } => wire_len,
        other => panic!("expected datagram, got {other:?}"),
    };
    assert_eq!(wire_len, packet_a.len());

    let mut direct_buf = vec![0u8; wire_len];
    let res = caller_b
        .poll_output_into(&mut direct_buf)
        .expect("poll_output_into succeeds");
    assert!(
        matches!(res, Some(OutputInto::Datagram { len, .. }) if len == wire_len),
        "the materialized length must be the datagram's wire length: {res:?}"
    );

    // Wire bytes must be byte-for-byte identical
    assert_eq!(packet_a, direct_buf);

    // Both must decode and deliver cleanly to listeners
    listener_a
        .feed_recv_buf(&packet_a, now)
        .expect("feed listener a");
    listener_b
        .feed_recv_buf(&direct_buf, now)
        .expect("feed listener b");

    let event_a = listener_a.poll_event().expect("event a");
    let event_b = listener_b.poll_event().expect("event b");

    match (event_a, event_b) {
        (
            ConnectionEvent::DataReceived {
                payload: p_a,
                sequence_number: seq_a,
                ..
            },
            ConnectionEvent::DataReceived {
                payload: p_b,
                sequence_number: seq_b,
                ..
            },
        ) => {
            assert_eq!(p_a.as_ref(), payload);
            assert_eq!(p_b.as_ref(), payload);
            assert_eq!(seq_a, seq_b);
        }
        other => panic!("unexpected events: {other:?}"),
    }
}

#[test]
fn wire_equivalence_ctr_modes() {
    for key_len in [KeyLength::Aes128, KeyLength::Aes192, KeyLength::Aes256] {
        let (mut caller_a, _listener_a) =
            establish_pair(Some("shared_passphrase"), key_len, CipherMode::Ctr);
        let (mut caller_b, mut listener_b) =
            establish_pair(Some("shared_passphrase"), key_len, CipherMode::Ctr);

        let now = ts(100_000);
        let payload = Bytes::from_static(b"Encrypted CTR Payload Testing Byte-Exact Match");

        caller_a
            .send_shared(payload.clone(), now)
            .expect("send shared a");
        caller_b
            .send_shared(payload.clone(), now)
            .expect("send shared b");

        // Path A: legacy poll_output
        let mut packet_a = None;
        while let Some(out) = caller_a.poll_output().unwrap() {
            if let ConnectionOutput::SendPacket(bytes) = out {
                packet_a = Some(bytes);
                break;
            }
        }
        let packet_a = packet_a.expect("packet a");

        // Path B: direct poll_output_into
        let meta = caller_b.peek_output().expect("meta b");
        let wire_len = match meta {
            OutputMeta::Datagram { wire_len, .. } => wire_len,
            other => panic!("expected datagram, got {other:?}"),
        };
        assert_eq!(wire_len, packet_a.len());

        let mut direct_buf = vec![0u8; wire_len];
        let out = caller_b
            .poll_output_into(&mut direct_buf)
            .expect("poll_output_into b");
        assert!(
            matches!(out, Some(OutputInto::Datagram { len, .. }) if len == wire_len),
            "the materialized length must be the datagram's wire length: {out:?}"
        );

        assert_eq!(
            packet_a, direct_buf,
            "CTR {key_len:?} wire bytes must be byte-for-byte identical"
        );

        // Feed to receiver
        listener_b
            .feed_recv_buf(&direct_buf, now)
            .expect("feed listener b");
        let event = listener_b.poll_event().expect("event b");
        if let ConnectionEvent::DataReceived {
            payload: recv_payload,
            ..
        } = event
        {
            assert_eq!(recv_payload, payload);
        } else {
            panic!("unexpected event: {event:?}");
        }
    }
}

#[test]
fn wire_equivalence_gcm_modes() {
    for key_len in [KeyLength::Aes128, KeyLength::Aes256] {
        let (mut caller_a, _listener_a) =
            establish_pair(Some("gcm_passphrase"), key_len, CipherMode::Gcm);
        let (mut caller_b, mut listener_b) =
            establish_pair(Some("gcm_passphrase"), key_len, CipherMode::Gcm);

        let now = ts(200_000);
        let payload = Bytes::from_static(b"Authenticated GCM Payload Testing Byte-Exact Match");

        caller_a
            .send_shared(payload.clone(), now)
            .expect("send shared a");
        caller_b
            .send_shared(payload.clone(), now)
            .expect("send shared b");

        let mut packet_a = None;
        while let Some(out) = caller_a.poll_output().unwrap() {
            if let ConnectionOutput::SendPacket(bytes) = out {
                packet_a = Some(bytes);
                break;
            }
        }
        let packet_a = packet_a.expect("packet a");

        let meta = caller_b.peek_output().expect("meta b");
        let wire_len = match meta {
            OutputMeta::Datagram { wire_len, .. } => wire_len,
            other => panic!("expected datagram, got {other:?}"),
        };
        assert_eq!(wire_len, packet_a.len());

        let mut direct_buf = vec![0u8; wire_len];
        let out = caller_b
            .poll_output_into(&mut direct_buf)
            .expect("poll_output_into b");
        assert!(
            matches!(out, Some(OutputInto::Datagram { len, .. }) if len == wire_len),
            "the materialized length must be the datagram's wire length: {out:?}"
        );

        assert_eq!(
            packet_a, direct_buf,
            "GCM {key_len:?} wire bytes must be byte-for-byte identical"
        );

        listener_b
            .feed_recv_buf(&direct_buf, now)
            .expect("feed listener b");
        let event = listener_b.poll_event().expect("event b");
        if let ConnectionEvent::DataReceived {
            payload: recv_payload,
            ..
        } = event
        {
            assert_eq!(recv_payload, payload);
        } else {
            panic!("unexpected event: {event:?}");
        }
    }
}

#[test]
fn wire_equivalence_retransmits() {
    let (mut caller_a, _listener_a) =
        establish_pair(Some("retransmit_pass"), KeyLength::Aes128, CipherMode::Ctr);
    let (mut caller_b, _listener_b) =
        establish_pair(Some("retransmit_pass"), KeyLength::Aes128, CipherMode::Ctr);

    let now = ts(300_000);
    // Send 3 packets
    for i in 0..3 {
        let p = vec![i as u8; 50];
        caller_a.send(&p, now).expect("send a");
        caller_b.send(&p, now).expect("send b");
    }

    // Deliver packet 0 and packet 2, dropping packet 1 to cause a NAK.
    //
    // A `SetTimer(SenderRto)` output interleaves with the datagrams here
    // (queued ahead of any still-unpolled DATA the moment the first one arms
    // the sender's own retransmission timeout, so it is not stuck behind the
    // rest of the flight), so `drain_send_packets` drains until the queue is
    // truly empty rather than stopping at the first non-`SendPacket` output.
    let pkts_a = drain_send_packets(&mut caller_a);
    let pkts_b = drain_send_packets(&mut caller_b);
    assert_eq!(pkts_a.len(), 3);
    assert_eq!(pkts_b.len(), 3);

    let SrtPacket::Data(first_pkt) = SrtPacket::decode(&pkts_a[0]).expect("decode data") else {
        panic!("expected data packet");
    };
    let lost_seq = first_pkt.sequence_number.wrapping_add(1) & 0x7FFF_FFFF;

    let nak_ctrl = srt_proto::wire::ControlPacket {
        control_type: srt_proto::wire::ControlType::Nak,
        subtype: 0,
        type_specific_info: 0,
        timestamp: 0,
        dest_socket_id: 0x1000,
        control_info: lost_seq.to_be_bytes().to_vec(),
    };
    let mut nak_bytes = Vec::new();
    nak_ctrl.encode(&mut nak_bytes).expect("encode nak");

    caller_a.feed_recv_buf(&nak_bytes, now).expect("feed nak a");
    caller_b.feed_recv_buf(&nak_bytes, now).expect("feed nak b");
    // Path A: legacy poll_output()
    let mut retx_a = None;
    while let Some(out) = caller_a.poll_output().unwrap() {
        if let ConnectionOutput::SendPacket(bytes) = out {
            retx_a = Some(bytes);
            break;
        }
    }
    let retx_a = retx_a.expect("retransmit a");

    // Path B: direct poll_output_into()
    let meta = caller_b.peek_output().expect("meta b");
    let wire_len = match meta {
        OutputMeta::Datagram { wire_len, .. } => wire_len,
        other => panic!("expected datagram, got {other:?}"),
    };
    let mut direct_buf = vec![0u8; wire_len];
    let out = caller_b
        .poll_output_into(&mut direct_buf)
        .expect("poll_output_into b");
    assert!(
        matches!(out, Some(OutputInto::Datagram { len, .. }) if len == wire_len),
        "the materialized length must be the datagram's wire length: {out:?}"
    );

    // Retransmit wire bytes must match exactly
    assert_eq!(retx_a, direct_buf);

    // Verify it is a DATA packet with R-bit set
    let parsed = SrtPacket::decode(&direct_buf).expect("valid srt packet");
    match parsed {
        SrtPacket::Data(pkt) => {
            assert!(pkt.retransmitted, "R-bit must be set on retransmit");
        }
        SrtPacket::Control(_) => panic!("expected DATA packet"),
    }
}

#[test]
fn wire_equivalence_key_rotation() {
    let (mut caller, mut listener) =
        establish_pair(Some("rotation_pass"), KeyLength::Aes128, CipherMode::Ctr);

    let mut now = ts(500_000);

    // Seed packet count to just before the switch threshold
    caller
        .seed_encrypted_packet_count_for_test(
            srt_proto::crypto::CryptoContext::KM_REFRESH_PERIOD - 5,
        )
        .expect("seed packet count");

    // Provide new SEK for rotation
    caller
        .provide_new_sek(&[0x5A; 16], now)
        .expect("provide new sek");

    // Transfer KMREQ to listener
    while let Some(out) = caller.poll_output().unwrap() {
        if let ConnectionOutput::SendPacket(bytes) = out {
            listener.feed_recv_buf(&bytes, now).expect("feed listener");
        }
    }
    // Transfer KMRSP back to caller
    while let Some(out) = listener.poll_output().unwrap() {
        if let ConnectionOutput::SendPacket(bytes) = out {
            caller.feed_recv_buf(&bytes, now).expect("feed caller");
        }
    }

    // Now send 10 packets and drain with poll_output_into
    let mut direct_wires = Vec::new();
    for i in 0..10 {
        now = ts(510_000 + i * 1_000);
        let payload = format!("key-rotation-data-{i}").into_bytes();
        caller.send(&payload, now).expect("send packet");

        // Materializing a DATA datagram arms the sender timeout, so a timer
        // action can sit in front of the next datagram; this test is about wire
        // bytes, so consume those here exactly as a runtime would.
        let wire_len = loop {
            match caller.peek_output().expect("datagram is queued") {
                OutputMeta::Datagram { wire_len, .. } => break wire_len,
                OutputMeta::SetTimer { .. } | OutputMeta::ClearTimer { .. } => {
                    assert!(
                        caller
                            .poll_output_into(&mut [])
                            .expect("timer action materializes")
                            .is_some(),
                        "a peeked timer action must materialize"
                    );
                }
            }
        };

        let mut buf = vec![0u8; wire_len];
        let out = caller
            .poll_output_into(&mut buf)
            .expect("poll_output_into succeeds");
        assert!(
            matches!(out, Some(OutputInto::Datagram { len, .. }) if len == wire_len),
            "the materialized length must be the datagram's wire length: {out:?}"
        );
        direct_wires.push(buf);
    }

    // Feed all 10 packets to listener and verify they all decrypt successfully
    for (i, wire) in direct_wires.iter().enumerate() {
        now = ts(520_000 + (i as u64) * 1_000);
        listener
            .feed_recv_buf(wire, now)
            .expect("listener decrypts packet");
        let event = listener.poll_event().expect("event available");
        match event {
            ConnectionEvent::DataReceived { payload, .. } => {
                let expected = format!("key-rotation-data-{i}");
                assert_eq!(payload.as_ref(), expected.as_bytes());
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }
}

/// Every `SendPacket` output until the queue is truly empty, skipping any
/// interleaved timer action rather than stopping at the first one.
fn drain_send_packets(caller: &mut SrtConnection) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    while let Some(output) = caller.poll_output().unwrap() {
        if let ConnectionOutput::SendPacket(p) = output {
            packets.push(p);
        }
    }
    packets
}

fn drain_timers_only(caller: &mut SrtConnection) {
    for _ in 0..16 {
        match caller.peek_output() {
            Some(OutputMeta::SetTimer { .. }) | Some(OutputMeta::ClearTimer { .. }) => {
                let mut dummy = [];
                caller
                    .poll_output_into(&mut dummy)
                    .expect("timer drains without materialization");
            }
            _ => break,
        }
    }
}

fn drain_filler_until_held(
    caller: &mut SrtConnection,
    listener: &mut SrtConnection,
    held_wire_len: usize,
    now: Timestamp,
) {
    while let Some(meta) = caller.peek_output() {
        match meta {
            OutputMeta::Datagram { wire_len, .. } if wire_len == held_wire_len => break,
            OutputMeta::Datagram { wire_len, .. } => {
                let mut buf = vec![0u8; wire_len];
                caller
                    .poll_output_into(&mut buf)
                    .expect("filler materializes");
                listener
                    .feed_recv_buf(&buf, now)
                    .expect("listener accepts filler");
                while listener.poll_event().is_some() {}
            }
            OutputMeta::SetTimer { .. } | OutputMeta::ClearTimer { .. } => {
                let mut dummy = [];
                caller.poll_output_into(&mut dummy).expect("timer drains");
            }
        }
    }
}

#[test]
fn old_key_datagram_materializes_across_switch_and_mass_new_key_admissions() {
    let (mut caller, mut listener) =
        establish_pair(Some("rotation_pass"), KeyLength::Aes128, CipherMode::Ctr);
    let mut now = ts(600_000);

    // Seed to just before the switch threshold so the next admission trips the switch.
    caller
        .seed_encrypted_packet_count_for_test(
            srt_proto::crypto::CryptoContext::KM_REFRESH_PERIOD - 1,
        )
        .expect("seed packet count");
    caller
        .provide_new_sek(&[0x5B; 16], now)
        .expect("provide new sek");
    while let Some(out) = caller.poll_output().unwrap() {
        if let ConnectionOutput::SendPacket(bytes) = out {
            listener.feed_recv_buf(&bytes, now).expect("feed listener");
        }
    }
    while let Some(out) = listener.poll_output().unwrap() {
        if let ConnectionOutput::SendPacket(bytes) = out {
            caller.feed_recv_buf(&bytes, now).expect("feed caller");
        }
    }

    // Queue one old-key (EVEN) datagram and deliberately leave it unmaterialized.
    caller
        .send(b"old-key-held-packet", now)
        .expect("old key admission");
    let held_meta = caller.peek_output().expect("held datagram queued");
    let held_wire_len = match held_meta {
        OutputMeta::Datagram { wire_len, .. } => wire_len,
        other => panic!("expected datagram, got {other:?}"),
    };

    // Drain ONLY the timer actions queued behind/around it, never the datagram.
    // Timers consume no materialization, so the stamp stays outstanding.
    drain_timers_only(&mut caller);
    assert!(
        matches!(
            caller.peek_output(),
            Some(OutputMeta::Datagram { wire_len, .. }) if wire_len == held_wire_len
        ),
        "held old-key datagram must still be queued"
    );

    // Admit 4,000 new-key packets, draining each immediately so only the held
    // packet remains outstanding on the old key.
    for i in 0..4_000u32 {
        now = ts(610_000 + u64::from(i));
        caller
            .send(format!("new-key-filler-{i}").as_bytes(), now)
            .expect("new key admission");
        // Drain filler until the queue front is the held packet again. FIFO
        // order keeps the held packet first; materialize it LAST below.
        drain_filler_until_held(&mut caller, &mut listener, held_wire_len, now);
    }

    // The held old-key packet must still materialize correctly: its cipher
    // schedule must have survived the switch plus 4,000 new-key admissions.
    let mut held_buf = vec![0u8; held_wire_len];
    let out = caller
        .poll_output_into(&mut held_buf)
        .expect("held old-key datagram still materializes");
    assert!(
        matches!(out, Some(OutputInto::Datagram { len, .. }) if len == held_wire_len),
        "held old-key datagram must materialize at its wire length: {out:?}"
    );
    listener
        .feed_recv_buf(&held_buf, now)
        .expect("listener decrypts held old-key packet");
    let event = listener.poll_event().expect("held packet delivers");
    match event {
        ConnectionEvent::DataReceived { payload, .. } => {
            assert_eq!(payload.as_ref(), b"old-key-held-packet");
        }
        other => panic!("unexpected event: {other:?}"),
    }
}
