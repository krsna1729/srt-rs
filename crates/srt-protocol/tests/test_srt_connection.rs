//! SRT 接続の e2e テスト
//!
//! sansio パターンを活用して、実ソケットなしで Caller/Listener の相互接続をテストする。

use std::time::Duration;

use shiguredo_srt::{
    ConnectionEvent, ConnectionOptions, ConnectionOutput, ConnectionState, ConnectionStats,
    DataPacket, ErrorKind, GroupExtensionData, GroupType, KeyLength, PacketPosition, SrtConnection,
    SrtPacket, TimerId, Timestamp,
};

/// テスト用のデフォルトオプション (TSBPD 遅延を 0 にして即時配信)
fn test_options() -> ConnectionOptions {
    ConnectionOptions {
        tsbpd_delay: 0,
        ..Default::default()
    }
}

/// テスト用のタイムスタンプを生成
fn ts(micros: u64) -> Timestamp {
    Timestamp::from_micros(micros)
}

/// Caller の出力パケットを Listener に転送
fn transfer_caller_to_listener(
    caller: &mut SrtConnection,
    listener: &mut SrtConnection,
    now: Timestamp,
) {
    while let Some(output) = caller.poll_output() {
        if let ConnectionOutput::SendPacket(data) = output {
            let _ = listener.feed_recv_buf(&data, now);
        }
    }
}

/// Listener の出力パケットを Caller に転送
fn transfer_listener_to_caller(
    listener: &mut SrtConnection,
    caller: &mut SrtConnection,
    now: Timestamp,
) {
    while let Some(output) = listener.poll_output() {
        if let ConnectionOutput::SendPacket(data) = output {
            let _ = caller.feed_recv_buf(&data, now);
        }
    }
}

/// 双方向でパケットを交換 (1ラウンド)
fn exchange_packets(caller: &mut SrtConnection, listener: &mut SrtConnection, now: Timestamp) {
    transfer_caller_to_listener(caller, listener, now);
    transfer_listener_to_caller(listener, caller, now);
}

/// 接続が確立するまでパケットを交換
fn establish_connection(
    caller: &mut SrtConnection,
    listener: &mut SrtConnection,
) -> Result<(), String> {
    let now = ts(0);
    caller.connect(now).map_err(|e| e.to_string())?;

    // 最大 10 ラウンドで接続確立を試みる
    for i in 0..10 {
        let now = ts(i * 10_000);
        exchange_packets(caller, listener, now);

        if caller.state() == ConnectionState::Connected
            && listener.state() == ConnectionState::Connected
        {
            return Ok(());
        }
    }

    Err(format!(
        "connection not established: caller={:?}, listener={:?}",
        caller.state(),
        listener.state()
    ))
}

/// イベントから Connected を探す
fn find_connected_event(conn: &mut SrtConnection) -> bool {
    while let Some(event) = conn.poll_event() {
        if matches!(event, ConnectionEvent::Connected) {
            return true;
        }
    }
    false
}

#[test]
fn public_connection_and_telemetry_are_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<SrtConnection>();
    assert_send_sync::<ConnectionStats>();
}

#[test]
fn connection_options_debug_redacts_secret_material() {
    let options = ConnectionOptions {
        passphrase: Some("do-not-log-this-passphrase".to_string()),
        crypto_sek: Some(vec![0xA7; 16]),
        ..Default::default()
    };
    let debug = format!("{options:?}");
    assert!(!debug.contains("do-not-log-this-passphrase"));
    assert!(!debug.contains("167, 167"));
    assert_eq!(debug.matches("[REDACTED]").count(), 2);
}

/// イベントから受信データを収集
fn collect_received_data(conn: &mut SrtConnection) -> Vec<Vec<u8>> {
    let mut data = Vec::new();
    while let Some(event) = conn.poll_event() {
        if let ConnectionEvent::DataReceived { payload, .. } = event {
            data.push(payload);
        }
    }
    data
}

// ============================================================================
// ハンドシェイクテスト
// ============================================================================

#[test]
fn test_handshake_without_encryption() {
    let mut caller = SrtConnection::new_caller(test_options());
    let mut listener = SrtConnection::new_listener(test_options());

    establish_connection(&mut caller, &mut listener).expect("connection should be established");

    assert_eq!(caller.state(), ConnectionState::Connected);
    assert_eq!(listener.state(), ConnectionState::Connected);

    // Connected イベントが発火していることを確認
    assert!(find_connected_event(&mut caller));
    assert!(find_connected_event(&mut listener));
}

#[test]
fn connected_connection_rejects_packets_for_another_socket_id() {
    let mut caller = SrtConnection::new_caller(ConnectionOptions {
        socket_id: 0x1111,
        tsbpd_delay: 0,
        ..Default::default()
    });
    let mut listener = SrtConnection::new_listener(ConnectionOptions {
        socket_id: 0x2222,
        tsbpd_delay: 0,
        ..Default::default()
    });
    establish_connection(&mut caller, &mut listener).expect("connected pair");
    while caller.poll_output().is_some() {}
    while listener.poll_output().is_some() {}

    caller.send(b"wrong destination", ts(20_000)).expect("send");
    let packet = loop {
        let output = caller.poll_output().expect("data packet");
        if let ConnectionOutput::SendPacket(bytes) = output {
            break bytes;
        }
    };
    let SrtPacket::Data(mut data) = SrtPacket::decode(&packet).expect("decode data") else {
        panic!("expected data packet");
    };
    data.dest_socket_id = 0x3333;
    let mut misrouted = Vec::new();
    data.encode(&mut misrouted);

    let error = listener
        .feed_recv_buf(&misrouted, ts(20_001))
        .expect_err("wrong destination must be rejected");
    assert_eq!(error.kind, ErrorKind::InvalidData);
    assert!(collect_received_data(&mut listener).is_empty());
}

#[test]
fn connected_connection_rejects_zero_destination_handshake() {
    let mut caller = SrtConnection::new_caller(ConnectionOptions {
        socket_id: 0x1111,
        tsbpd_delay: 0,
        ..Default::default()
    });
    let mut listener = SrtConnection::new_listener(ConnectionOptions {
        socket_id: 0x2222,
        tsbpd_delay: 0,
        ..Default::default()
    });
    establish_connection(&mut caller, &mut listener).expect("connected pair");

    let mut attacker = SrtConnection::new_caller(ConnectionOptions {
        socket_id: 0x3333,
        ..Default::default()
    });
    attacker.connect(ts(20_000)).expect("attacker starts");
    let induction = loop {
        let output = attacker.poll_output().expect("induction output");
        if let ConnectionOutput::SendPacket(bytes) = output {
            break bytes;
        }
    };

    let error = listener
        .feed_recv_buf(&induction, ts(20_001))
        .expect_err("zero-destination handshake must not reach connected state");
    assert_eq!(error.kind, ErrorKind::InvalidData);
    assert_eq!(listener.state(), ConnectionState::Connected);
}

#[test]
fn test_handshake_retransmits_after_packet_loss() {
    let mut caller = SrtConnection::new_caller(test_options());
    let mut listener = SrtConnection::new_listener(test_options());

    caller.connect(ts(0)).expect("caller connection starts");
    while caller.poll_output().is_some() {}

    caller
        .handle_timer(TimerId::Handshake, ts(1_000_000))
        .expect("caller handshake retry");
    transfer_caller_to_listener(&mut caller, &mut listener, ts(1_000_000));
    while listener.poll_output().is_some() {}

    listener
        .handle_timer(TimerId::Handshake, ts(2_000_000))
        .expect("listener handshake retry");
    transfer_listener_to_caller(&mut listener, &mut caller, ts(2_000_000));
    while caller.poll_output().is_some() {}

    caller
        .handle_timer(TimerId::Handshake, ts(2_750_000))
        .expect("caller conclusion retry");
    transfer_caller_to_listener(&mut caller, &mut listener, ts(2_750_000));
    transfer_listener_to_caller(&mut listener, &mut caller, ts(2_750_000));

    assert_eq!(caller.state(), ConnectionState::Connected);
    assert_eq!(listener.state(), ConnectionState::Connected);
}

#[test]
fn test_handshake_with_encryption() {
    let passphrase = "test-passphrase".to_string();

    let caller_opts = ConnectionOptions {
        passphrase: Some(passphrase.clone()),
        // local patch (crates/srt-protocol/VENDOR.md, upstream
        // issue 0052): crypto_salt is now required when passphrase is set,
        // no implicit zero default.
        crypto_salt: Some([0x42; 16]),
        key_length: KeyLength::Aes128,
        tsbpd_delay: 0,
        ..Default::default()
    };
    let listener_opts = ConnectionOptions {
        passphrase: Some(passphrase),
        key_length: KeyLength::Aes128,
        tsbpd_delay: 0,
        ..Default::default()
    };

    let mut caller = SrtConnection::new_caller(caller_opts);
    let mut listener = SrtConnection::new_listener(listener_opts);

    establish_connection(&mut caller, &mut listener).expect("connection should be established");

    assert_eq!(caller.state(), ConnectionState::Connected);
    assert_eq!(listener.state(), ConnectionState::Connected);
}

#[test]
fn encrypted_connections_generate_fresh_default_key_material() {
    fn conclusion_packet() -> Vec<u8> {
        let mut caller = SrtConnection::new_caller(ConnectionOptions {
            socket_id: 0x1111,
            passphrase: Some("random-key-material".to_string()),
            key_length: KeyLength::Aes128,
            ..Default::default()
        });
        let mut listener = SrtConnection::new_listener(ConnectionOptions {
            socket_id: 0x2222,
            ..Default::default()
        });
        caller.connect(ts(0)).expect("start caller");
        transfer_caller_to_listener(&mut caller, &mut listener, ts(0));
        transfer_listener_to_caller(&mut listener, &mut caller, ts(1));
        while let Some(output) = caller.poll_output() {
            if let ConnectionOutput::SendPacket(bytes) = output {
                return bytes;
            }
        }
        panic!("caller did not emit conclusion");
    }

    assert_ne!(conclusion_packet(), conclusion_packet());
}

#[test]
fn encrypted_connection_rejects_an_explicit_all_zero_sek() {
    let mut caller = SrtConnection::new_caller(ConnectionOptions {
        socket_id: 0x1111,
        passphrase: Some("zero-key-must-fail".to_string()),
        crypto_salt: Some([0x42; 16]),
        crypto_sek: Some(vec![0; 16]),
        ..Default::default()
    });
    let mut listener = SrtConnection::new_listener(ConnectionOptions {
        socket_id: 0x2222,
        ..Default::default()
    });
    caller.connect(ts(0)).expect("start caller");
    transfer_caller_to_listener(&mut caller, &mut listener, ts(0));

    let mut error = None;
    while let Some(output) = listener.poll_output() {
        if let ConnectionOutput::SendPacket(bytes) = output {
            error = caller.feed_recv_buf(&bytes, ts(1)).err();
        }
    }
    let error = error.expect("zero SEK must fail during induction response handling");
    assert_eq!(error.kind, shiguredo_srt::ErrorKind::CryptoError);
    assert!(error.reason.contains("all zero"));
}

#[test]
fn listener_can_apply_stream_policy_before_encrypted_conclusion() {
    let passphrase = "stream-policy-passphrase".to_string();
    let caller_opts = ConnectionOptions {
        passphrase: Some(passphrase.clone()),
        crypto_salt: Some([0x24; 16]),
        key_length: KeyLength::Aes256,
        stream_id: Some("publish:encrypted-stream".to_string()),
        tsbpd_delay: 0,
        ..Default::default()
    };
    let mut caller = SrtConnection::new_caller(caller_opts);
    let mut listener = SrtConnection::new_listener(test_options());

    caller.connect(ts(0)).expect("caller connection starts");
    transfer_caller_to_listener(&mut caller, &mut listener, ts(0));
    transfer_listener_to_caller(&mut listener, &mut caller, ts(0));
    listener
        .set_listener_policy(Some(passphrase), KeyLength::Aes256, 2_000, 32_768, 8_548)
        .expect("listener policy is still mutable before conclusion");

    for round in 1..10 {
        exchange_packets(&mut caller, &mut listener, ts(round * 10_000));
        if caller.state() == ConnectionState::Connected
            && listener.state() == ConnectionState::Connected
        {
            return;
        }
    }

    panic!(
        "stream policy was not applied before encrypted conclusion: caller={:?}, listener={:?}",
        caller.state(),
        listener.state()
    );
}

#[test]
fn listener_encryption_mismatches_fail_closed_with_km_errors() {
    let cases = [
        (
            Some("caller-only-secret".to_owned()),
            None,
            ErrorKind::HandshakeRejected,
            "peer is unsecured",
        ),
        (
            None,
            Some("listener-only-secret".to_owned()),
            ErrorKind::HandshakeRejected,
            "peer has no secret",
        ),
        (
            Some("caller-wrong-secret".to_owned()),
            Some("listener-right-secret".to_owned()),
            ErrorKind::HandshakeRejected,
            "peer has wrong secret",
        ),
    ];

    for (caller_secret, listener_secret, listener_error_kind, caller_reason) in cases {
        let mut caller = SrtConnection::new_caller(ConnectionOptions {
            passphrase: caller_secret,
            tsbpd_delay: 0,
            ..ConnectionOptions::default()
        });
        let mut listener = SrtConnection::new_listener(ConnectionOptions {
            passphrase: listener_secret,
            tsbpd_delay: 0,
            ..ConnectionOptions::default()
        });
        caller.connect(ts(0)).expect("start caller");
        transfer_caller_to_listener(&mut caller, &mut listener, ts(0));
        transfer_listener_to_caller(&mut listener, &mut caller, ts(1));

        let conclusion = loop {
            if let Some(ConnectionOutput::SendPacket(packet)) = caller.poll_output() {
                break packet;
            }
        };
        let listener_error = listener
            .feed_recv_buf(&conclusion, ts(2))
            .expect_err("encryption mismatch must fail");
        assert_eq!(listener_error.kind, listener_error_kind);
        assert_eq!(listener.state(), ConnectionState::Disconnected);

        let caller_error = loop {
            let output = listener.poll_output().expect("KM error response");
            if let ConnectionOutput::SendPacket(packet) = output
                && let Err(error) = caller.feed_recv_buf(&packet, ts(3))
            {
                break error;
            }
        };
        assert_eq!(caller_error.kind, ErrorKind::HandshakeRejected);
        assert!(caller_error.reason.contains(caller_reason));
        assert_eq!(caller.state(), ConnectionState::Disconnected);
    }
}

#[test]
fn test_handshake_with_aes256() {
    let passphrase = "test-passphrase-256".to_string();

    let caller_opts = ConnectionOptions {
        passphrase: Some(passphrase.clone()),
        // local patch (crates/srt-protocol/VENDOR.md, upstream
        // issue 0052): crypto_salt is now required when passphrase is set,
        // no implicit zero default.
        crypto_salt: Some([0x42; 16]),
        key_length: KeyLength::Aes256,
        tsbpd_delay: 0,
        ..Default::default()
    };
    let listener_opts = ConnectionOptions {
        passphrase: Some(passphrase),
        key_length: KeyLength::Aes256,
        tsbpd_delay: 0,
        ..Default::default()
    };

    let mut caller = SrtConnection::new_caller(caller_opts);
    let mut listener = SrtConnection::new_listener(listener_opts);

    establish_connection(&mut caller, &mut listener).expect("connection should be established");

    assert_eq!(caller.state(), ConnectionState::Connected);
    assert_eq!(listener.state(), ConnectionState::Connected);
}

#[test]
fn test_handshake_with_stream_id() {
    let stream_id = "#!::r=live/stream1".to_string();

    let caller_opts = ConnectionOptions {
        stream_id: Some(stream_id.clone()),
        tsbpd_delay: 0,
        ..Default::default()
    };
    let listener_opts = test_options();

    let mut caller = SrtConnection::new_caller(caller_opts);
    let mut listener = SrtConnection::new_listener(listener_opts);

    establish_connection(&mut caller, &mut listener).expect("connection should be established");

    // Listener 側で Stream ID を受信できていることを確認
    assert_eq!(listener.peer_stream_id(), Some(stream_id.as_str()));
}

#[test]
fn test_handshake_with_group_metadata_on_both_legs() {
    let caller_group = GroupExtensionData {
        group_id: 0x4000_1001,
        group_type: GroupType::Broadcast,
        flags: 0,
        weight: 100,
    };
    let listener_group = GroupExtensionData {
        group_id: 0x4000_2002,
        group_type: GroupType::Broadcast,
        flags: 0,
        weight: 100,
    };

    let caller_opts = ConnectionOptions {
        group_extension: Some(caller_group),
        tsbpd_delay: 0,
        ..Default::default()
    };
    let listener_opts = ConnectionOptions {
        group_extension: Some(listener_group),
        tsbpd_delay: 0,
        ..Default::default()
    };

    let mut caller = SrtConnection::new_caller(caller_opts);
    let mut listener = SrtConnection::new_listener(listener_opts);

    establish_connection(&mut caller, &mut listener).expect("group handshake should establish");

    assert_eq!(listener.peer_group_extension(), Some(caller_group));
    assert_eq!(caller.peer_group_extension(), Some(listener_group));
}

// ============================================================================
// データ送受信テスト
// ============================================================================

#[test]
fn test_data_transfer_caller_to_listener() {
    let mut caller = SrtConnection::new_caller(test_options());
    let mut listener = SrtConnection::new_listener(test_options());

    establish_connection(&mut caller, &mut listener).expect("connection should be established");

    // イベントをクリア
    while caller.poll_event().is_some() {}
    while listener.poll_event().is_some() {}

    // Caller からデータ送信
    let test_data = b"Hello, SRT!";
    let now = ts(100_000);
    caller.send(test_data, now).expect("send should succeed");

    // パケット転送
    transfer_caller_to_listener(&mut caller, &mut listener, now);

    // ACK タイマー発火をシミュレート (データ配信のため)
    listener
        .handle_timer(TimerId::Ack, now)
        .expect("timer should succeed");

    // Listener 側でデータ受信を確認
    let received = collect_received_data(&mut listener);
    assert_eq!(received.len(), 1);
    assert_eq!(received[0], test_data);
}

#[test]
fn test_data_transfer_with_encryption() {
    let passphrase = "encryption-test".to_string();

    let caller_opts = ConnectionOptions {
        passphrase: Some(passphrase.clone()),
        // local patch (crates/srt-protocol/VENDOR.md, upstream
        // issue 0052): crypto_salt is now required when passphrase is set,
        // no implicit zero default.
        crypto_salt: Some([0x42; 16]),
        key_length: KeyLength::Aes128,
        tsbpd_delay: 0,
        ..Default::default()
    };
    let listener_opts = ConnectionOptions {
        passphrase: Some(passphrase),
        key_length: KeyLength::Aes128,
        tsbpd_delay: 0,
        ..Default::default()
    };

    let mut caller = SrtConnection::new_caller(caller_opts);
    let mut listener = SrtConnection::new_listener(listener_opts);

    establish_connection(&mut caller, &mut listener).expect("connection should be established");

    // イベントをクリア
    while caller.poll_event().is_some() {}
    while listener.poll_event().is_some() {}

    // 暗号化されたデータ送信
    let test_data = b"Encrypted message!";
    let now = ts(100_000);
    caller.send(test_data, now).expect("send should succeed");

    // パケット転送
    transfer_caller_to_listener(&mut caller, &mut listener, now);

    // ACK タイマー発火
    listener
        .handle_timer(TimerId::Ack, now)
        .expect("timer should succeed");

    // 復号化されたデータを確認
    let received = collect_received_data(&mut listener);
    assert_eq!(received.len(), 1);
    assert_eq!(received[0], test_data);
}

#[test]
fn test_multiple_data_packets() {
    let mut caller = SrtConnection::new_caller(test_options());
    let mut listener = SrtConnection::new_listener(test_options());

    establish_connection(&mut caller, &mut listener).expect("connection should be established");

    // イベントをクリア
    while caller.poll_event().is_some() {}
    while listener.poll_event().is_some() {}

    // 複数パケット送信
    let packets: Vec<&[u8]> = vec![b"Packet 1", b"Packet 2", b"Packet 3"];

    for (i, data) in packets.iter().enumerate() {
        let now = ts(100_000 + (i as u64) * 1000);
        caller.send(data, now).expect("send should succeed");
        transfer_caller_to_listener(&mut caller, &mut listener, now);
    }

    // ACK タイマー発火
    let now = ts(200_000);
    listener
        .handle_timer(TimerId::Ack, now)
        .expect("timer should succeed");

    // 全パケット受信を確認
    let received = collect_received_data(&mut listener);
    assert_eq!(received.len(), 3);
    assert_eq!(received[0], b"Packet 1");
    assert_eq!(received[1], b"Packet 2");
    assert_eq!(received[2], b"Packet 3");
}

// ============================================================================
// 双方向通信テスト
// ============================================================================

#[test]
fn test_bidirectional_communication() {
    let mut caller = SrtConnection::new_caller(test_options());
    let mut listener = SrtConnection::new_listener(test_options());

    establish_connection(&mut caller, &mut listener).expect("connection should be established");

    // イベントをクリア
    while caller.poll_event().is_some() {}
    while listener.poll_event().is_some() {}

    let now = ts(100_000);

    // Caller → Listener
    caller
        .send(b"From Caller", now)
        .expect("send should succeed");
    transfer_caller_to_listener(&mut caller, &mut listener, now);

    // Listener → Caller
    listener
        .send(b"From Listener", now)
        .expect("send should succeed");
    transfer_listener_to_caller(&mut listener, &mut caller, now);

    // ACK タイマー発火
    caller
        .handle_timer(TimerId::Ack, now)
        .expect("timer should succeed");
    listener
        .handle_timer(TimerId::Ack, now)
        .expect("timer should succeed");

    // 受信確認
    let caller_received = collect_received_data(&mut caller);
    let listener_received = collect_received_data(&mut listener);

    assert_eq!(caller_received.len(), 1);
    assert_eq!(caller_received[0], b"From Listener");

    assert_eq!(listener_received.len(), 1);
    assert_eq!(listener_received[0], b"From Caller");
}

// ============================================================================
// 切断テスト
// ============================================================================

#[test]
fn test_disconnect() {
    let mut caller = SrtConnection::new_caller(test_options());
    let mut listener = SrtConnection::new_listener(test_options());

    establish_connection(&mut caller, &mut listener).expect("connection should be established");

    // イベントをクリア
    while caller.poll_event().is_some() {}
    while listener.poll_event().is_some() {}

    // Caller から切断
    let now = ts(100_000);
    caller.disconnect(now);

    // Shutdown パケット転送
    transfer_caller_to_listener(&mut caller, &mut listener, now);

    // Listener が Disconnected イベントを受信
    let mut disconnected = false;
    while let Some(event) = listener.poll_event() {
        if matches!(event, ConnectionEvent::Disconnected { .. }) {
            disconnected = true;
        }
    }
    assert!(disconnected, "listener should receive disconnected event");

    assert_eq!(listener.state(), ConnectionState::Disconnected);
}

// ============================================================================
// エラーケーステスト
// ============================================================================

#[test]
fn test_send_before_connected() {
    let mut caller = SrtConnection::new_caller(test_options());

    // 接続前に送信を試みる
    let result = caller.send(b"test", ts(0));
    assert!(result.is_err());
}

#[test]
fn test_caller_connect_twice() {
    let mut caller = SrtConnection::new_caller(test_options());

    caller.connect(ts(0)).expect("first connect should succeed");

    // 2回目の connect はエラーにならない (状態がすでに変わっているため)
    // ただし Caller 以外で connect を呼ぶとエラー
    let mut listener = SrtConnection::new_listener(test_options());
    let result = listener.connect(ts(0));
    assert!(result.is_err());
}

// ============================================================================
// タイマーテスト
// ============================================================================

#[test]
fn test_keepalive_timer() {
    let mut caller = SrtConnection::new_caller(test_options());
    let mut listener = SrtConnection::new_listener(test_options());

    establish_connection(&mut caller, &mut listener).expect("connection should be established");

    // Keepalive タイマー発火
    let now = ts(1_000_000);
    caller
        .handle_timer(TimerId::Keepalive, now)
        .expect("timer should succeed");

    // Keepalive パケットが送信される
    let mut has_packet = false;
    while let Some(output) = caller.poll_output() {
        if matches!(output, ConnectionOutput::SendPacket(_)) {
            has_packet = true;
        }
    }
    assert!(has_packet);
}

#[test]
fn test_nak_timer() {
    let mut caller = SrtConnection::new_caller(test_options());
    let mut listener = SrtConnection::new_listener(test_options());

    establish_connection(&mut caller, &mut listener).expect("connection should be established");

    // NAK タイマー発火
    let now = ts(1_000_000);
    listener
        .handle_timer(TimerId::Nak, now)
        .expect("timer should succeed");

    // 接続は維持される
    assert_eq!(listener.state(), ConnectionState::Connected);
}

#[test]
fn test_retransmit_timer() {
    let mut caller = SrtConnection::new_caller(test_options());
    let mut listener = SrtConnection::new_listener(test_options());

    establish_connection(&mut caller, &mut listener).expect("connection should be established");

    // Retransmit タイマー発火
    let now = ts(1_000_000);
    caller
        .handle_timer(TimerId::Retransmit, now)
        .expect("timer should succeed");

    // 接続は維持される
    assert_eq!(caller.state(), ConnectionState::Connected);
}

#[test]
fn test_inactivity_timeout() {
    let mut caller = SrtConnection::new_caller(test_options());
    let mut listener = SrtConnection::new_listener(test_options());

    establish_connection(&mut caller, &mut listener).expect("connection should be established");

    // イベントをクリア
    while caller.poll_event().is_some() {}

    // 非活性タイムアウト発火
    let now = ts(10_000_000);
    caller
        .handle_timer(TimerId::Inactivity, now)
        .expect("timer should succeed");

    // 切断される
    assert_eq!(caller.state(), ConnectionState::Disconnected);

    // Disconnected イベントが発生
    let mut disconnected = false;
    while let Some(event) = caller.poll_event() {
        if matches!(event, ConnectionEvent::Disconnected { .. }) {
            disconnected = true;
        }
    }
    assert!(disconnected);
}

// ============================================================================
// 統計テスト
// ============================================================================

#[test]
fn test_sender_stats() {
    let mut caller = SrtConnection::new_caller(test_options());
    let mut listener = SrtConnection::new_listener(test_options());

    establish_connection(&mut caller, &mut listener).expect("connection should be established");

    // 初期状態の統計
    let stats = caller.sender_stats().expect("stats should be available");
    assert_eq!(stats.packets_in_buffer, 0);
    assert_eq!(stats.total_sent, 0);

    // データ送信
    let now = ts(100_000);
    caller.send(b"test data", now).expect("send should succeed");

    // 送信後の統計
    let stats = caller.sender_stats().expect("stats should be available");
    assert_eq!(stats.packets_in_buffer, 1);
    assert_eq!(stats.total_sent, 1);
}

#[test]
fn test_receiver_stats() {
    let mut caller = SrtConnection::new_caller(test_options());
    let mut listener = SrtConnection::new_listener(test_options());

    establish_connection(&mut caller, &mut listener).expect("connection should be established");

    // 初期状態の統計
    let stats = listener
        .receiver_stats()
        .expect("stats should be available");
    assert_eq!(stats.total_received, 0);

    // データ受信
    let now = ts(100_000);
    caller.send(b"test data", now).expect("send should succeed");
    transfer_caller_to_listener(&mut caller, &mut listener, now);

    // 受信後の統計
    let stats = listener
        .receiver_stats()
        .expect("stats should be available");
    assert_eq!(stats.total_received, 1);
}

#[test]
fn connection_stats_cover_restream_quality_inputs() {
    let mut caller = SrtConnection::new_caller(test_options());
    let mut listener = SrtConnection::new_listener(test_options());

    assert!(caller.stats().sender.is_none());
    assert!(caller.stats().receiver.is_none());
    establish_connection(&mut caller, &mut listener).expect("connection should be established");

    let baseline = caller.stats();
    caller.send(b"one", ts(100_000)).expect("first send");
    transfer_caller_to_listener(&mut caller, &mut listener, ts(100_000));
    caller.send(b"three", ts(110_000)).expect("second send");
    transfer_caller_to_listener(&mut caller, &mut listener, ts(110_000));

    let queued = caller.stats().sender.expect("sender snapshot");
    assert_eq!(queued.packets_in_flight, 2);
    assert_eq!(queued.payload_bytes_in_buffer, 8);
    assert_eq!(queued.buffer_span_micros, 10_000);
    assert_eq!(queued.available_buffer_bytes, None);

    listener
        .handle_timer(TimerId::Ack, ts(120_000))
        .expect("full ACK");
    transfer_listener_to_caller(&mut listener, &mut caller, ts(120_000));

    let current = caller.stats();
    let sender = current.sender.expect("sender snapshot");
    assert_eq!(sender.total_sent, 2);
    assert_eq!(sender.total_bytes_sent, 8);
    assert_eq!(sender.total_srt_bytes_sent, 40);
    assert_eq!(sender.total_data_packets_sent, 2);
    // Each receive crossed the 10 ms ACK cadence, then the explicit timer
    // emitted a third full ACK.
    assert_eq!(sender.total_acks_received, 3);
    assert_eq!(sender.packets_in_flight, 0);
    assert!(sender.peer_rtt_micros.is_some());
    assert!(sender.peer_receiving_rate_bytes_per_second.is_some());
    assert!(sender.peer_link_capacity_bytes_per_second.is_some());
    assert_eq!(sender.flow_window_packets, sender.congestion_window_packets);

    let receiving = listener.stats().receiver.expect("receiver snapshot");
    assert_eq!(receiving.total_received, 2);
    assert_eq!(receiving.total_bytes_received, 40);
    assert_eq!(receiving.total_acks_sent, 3);
    assert!(receiving.receiving_rate_packets_per_second > 0);
    assert!(receiving.receiving_rate_bytes_per_second > 0);
    assert!(receiving.link_capacity_bytes_per_second.is_some());
    assert_eq!(receiving.tsbpd_delay_micros, 0);
    assert_eq!(receiving.available_buffer_bytes, None);

    // This is the one-second sampling contract used by Restream: cumulative
    // snapshots stay intact and the adapter derives interval rates itself.
    let interval = current.interval_since(&baseline, Duration::from_secs(1));
    let sending = interval.sender.expect("sending interval");
    assert_eq!(sending.packets_sent.count, Some(2));
    assert_eq!(sending.srt_bytes_sent.per_second, Some(40.0));

    // Undecryptable input is counted at the rejection transition even when
    // the connection has no crypto context and returns an error to its owner.
    let undecryptable = DataPacket {
        sequence_number: 2,
        position: PacketPosition::Single,
        order_flag: false,
        encryption_flag: 0b01,
        retransmitted: false,
        message_number: 3,
        timestamp: 130_000,
        dest_socket_id: listener.socket_id(),
        payload: vec![1, 2, 3],
    };
    let mut encoded = Vec::new();
    undecryptable.encode(&mut encoded);
    assert!(listener.feed_recv_buf(&encoded, ts(130_000)).is_err());
    assert_eq!(
        listener
            .stats()
            .receiver
            .expect("receiver snapshot")
            .total_undecryptable,
        1
    );
}

#[test]
fn encrypted_connection_counts_and_rejects_plaintext_data() {
    let mut caller = SrtConnection::new_caller(ConnectionOptions {
        passphrase: Some("telemetry-passphrase".to_string()),
        crypto_salt: Some([0x24; 16]),
        tsbpd_delay: 0,
        ..Default::default()
    });
    let mut listener = SrtConnection::new_listener(ConnectionOptions {
        passphrase: Some("telemetry-passphrase".to_string()),
        tsbpd_delay: 0,
        ..Default::default()
    });
    establish_connection(&mut caller, &mut listener).expect("encrypted connection");

    let plaintext = DataPacket {
        sequence_number: 0,
        position: PacketPosition::Single,
        order_flag: false,
        encryption_flag: 0,
        retransmitted: false,
        message_number: 1,
        timestamp: 100_000,
        dest_socket_id: listener.socket_id(),
        payload: b"must be encrypted".to_vec(),
    };
    let mut encoded = Vec::new();
    plaintext.encode(&mut encoded);

    assert!(listener.feed_recv_buf(&encoded, ts(100_000)).is_err());
    let receiver = listener.stats().receiver.expect("receiver telemetry");
    assert_eq!(receiver.total_undecryptable, 1);
    assert_eq!(receiver.total_data_packets_received, 0);
}

// ============================================================================
// パケットペーシングテスト
// ============================================================================

#[test]
fn test_packet_pacing() {
    let mut caller = SrtConnection::new_caller(test_options());
    let mut listener = SrtConnection::new_listener(test_options());

    establish_connection(&mut caller, &mut listener).expect("connection should be established");

    // パケット送信間隔を設定 (1000μs = 1ms)
    caller.set_packet_send_period(1000);

    // 最初の送信
    let now = ts(100_000);
    caller.send(b"first", now).expect("send should succeed");

    // 直後は送信不可
    assert!(!caller.can_send_with_pacing(ts(100_500)));
    assert!(caller.time_until_send(ts(100_500)) > 0);

    // 1ms 後は送信可能
    assert!(caller.can_send_with_pacing(ts(101_000)));
    assert_eq!(caller.time_until_send(ts(101_000)), 0);
}

// ============================================================================
// ACK/NAK/ACKACK テスト
// ============================================================================

#[test]
fn test_ack_ackack_flow() {
    let mut caller = SrtConnection::new_caller(test_options());
    let mut listener = SrtConnection::new_listener(test_options());

    establish_connection(&mut caller, &mut listener).expect("connection should be established");

    // データ送信
    let now = ts(100_000);
    caller.send(b"test data", now).expect("send should succeed");
    transfer_caller_to_listener(&mut caller, &mut listener, now);

    // ACK 生成 (Listener)
    let now = ts(110_000);
    listener
        .handle_timer(TimerId::Ack, now)
        .expect("timer should succeed");

    // ACK を Caller に転送
    transfer_listener_to_caller(&mut listener, &mut caller, now);

    // Caller が ACKACK を送信
    // (送信バッファがクリアされる)
    let stats = caller.sender_stats().expect("stats should be available");
    assert_eq!(stats.packets_in_buffer, 0);
}

#[test]
fn test_has_retransmit() {
    let mut caller = SrtConnection::new_caller(test_options());
    let mut listener = SrtConnection::new_listener(test_options());

    establish_connection(&mut caller, &mut listener).expect("connection should be established");

    // 初期状態では再送なし
    assert!(!caller.has_retransmit());

    // データ送信
    let now = ts(100_000);
    caller.send(b"test", now).expect("send should succeed");

    // まだ再送リストは空
    assert!(!caller.has_retransmit());
}

#[test]
fn test_process_retransmit() {
    let mut caller = SrtConnection::new_caller(test_options());
    let mut listener = SrtConnection::new_listener(test_options());

    establish_connection(&mut caller, &mut listener).expect("connection should be established");

    // データ送信
    let now = ts(100_000);
    caller.send(b"test", now).expect("send should succeed");

    // 再送処理 (NAK がなければ何もしない)
    caller.process_retransmit(now);

    // パケットはまだバッファにある
    let stats = caller.sender_stats().expect("stats should be available");
    assert_eq!(stats.packets_in_buffer, 1);
}

// ============================================================================
// 追加テスト: より多くのコードパスをカバー
// ============================================================================

#[test]
fn test_can_send() {
    let mut caller = SrtConnection::new_caller(test_options());
    let mut listener = SrtConnection::new_listener(test_options());

    // 未接続時は送信不可
    assert!(!caller.can_send());

    establish_connection(&mut caller, &mut listener).expect("connection should be established");

    // 接続後は送信可能
    assert!(caller.can_send());
}

#[test]
fn test_large_data_transfer() {
    let mut caller = SrtConnection::new_caller(test_options());
    let mut listener = SrtConnection::new_listener(test_options());

    establish_connection(&mut caller, &mut listener).expect("connection should be established");

    // イベントをクリア
    while caller.poll_event().is_some() {}
    while listener.poll_event().is_some() {}

    // 2KB のデータを送信 (複数パケットに分割される可能性)
    let test_data = vec![0xAB; 2000];
    let now = ts(100_000);
    caller.send(&test_data, now).expect("send should succeed");

    // パケット転送
    transfer_caller_to_listener(&mut caller, &mut listener, now);

    // ACK タイマー発火
    listener
        .handle_timer(TimerId::Ack, now)
        .expect("timer should succeed");

    // データ受信を確認
    let received = collect_received_data(&mut listener);
    assert!(!received.is_empty());

    // 受信データの合計が送信データと一致
    let total_received: Vec<u8> = received.into_iter().flatten().collect();
    assert_eq!(total_received, test_data);
}

#[test]
fn test_receive_encrypted_data_with_aes256() {
    let passphrase = "aes256-encrypt-test".to_string();

    let caller_opts = ConnectionOptions {
        passphrase: Some(passphrase.clone()),
        // local patch (crates/srt-protocol/VENDOR.md, upstream
        // issue 0052): crypto_salt is now required when passphrase is set,
        // no implicit zero default.
        crypto_salt: Some([0x42; 16]),
        key_length: KeyLength::Aes256,
        tsbpd_delay: 0,
        ..Default::default()
    };
    let listener_opts = ConnectionOptions {
        passphrase: Some(passphrase),
        key_length: KeyLength::Aes256,
        tsbpd_delay: 0,
        ..Default::default()
    };

    let mut caller = SrtConnection::new_caller(caller_opts);
    let mut listener = SrtConnection::new_listener(listener_opts);

    establish_connection(&mut caller, &mut listener).expect("connection should be established");

    // イベントをクリア
    while caller.poll_event().is_some() {}
    while listener.poll_event().is_some() {}

    // 暗号化されたデータ送信
    let test_data = b"AES-256 encrypted message!";
    let now = ts(100_000);
    caller.send(test_data, now).expect("send should succeed");

    // パケット転送
    transfer_caller_to_listener(&mut caller, &mut listener, now);

    // ACK タイマー発火
    listener
        .handle_timer(TimerId::Ack, now)
        .expect("timer should succeed");

    // 復号化されたデータを確認
    let received = collect_received_data(&mut listener);
    assert_eq!(received.len(), 1);
    assert_eq!(received[0], test_data);
}

#[test]
fn test_listener_receive_shutdown() {
    let mut caller = SrtConnection::new_caller(test_options());
    let mut listener = SrtConnection::new_listener(test_options());

    establish_connection(&mut caller, &mut listener).expect("connection should be established");

    // イベントをクリア
    while listener.poll_event().is_some() {}

    // Listener から切断
    let now = ts(100_000);
    listener.disconnect(now);

    // Shutdown パケット転送
    transfer_listener_to_caller(&mut listener, &mut caller, now);

    // Caller が Disconnected イベントを受信
    let mut disconnected = false;
    while let Some(event) = caller.poll_event() {
        if matches!(event, ConnectionEvent::Disconnected { .. }) {
            disconnected = true;
        }
    }
    assert!(disconnected, "caller should receive disconnected event");
}

#[test]
fn test_multiple_sends_before_transfer() {
    let mut caller = SrtConnection::new_caller(test_options());
    let mut listener = SrtConnection::new_listener(test_options());

    establish_connection(&mut caller, &mut listener).expect("connection should be established");

    // イベントをクリア
    while caller.poll_event().is_some() {}
    while listener.poll_event().is_some() {}

    let now = ts(100_000);

    // 複数のデータを続けて送信
    for i in 0..5 {
        let data = format!("Message {}", i);
        caller
            .send(data.as_bytes(), now)
            .expect("send should succeed");
    }

    // まとめてパケット転送
    transfer_caller_to_listener(&mut caller, &mut listener, now);

    // ACK タイマー発火
    listener
        .handle_timer(TimerId::Ack, now)
        .expect("timer should succeed");

    // 全データ受信を確認
    let received = collect_received_data(&mut listener);
    assert_eq!(received.len(), 5);
}

/// End-to-end loss recovery: a dropped DATA packet must produce a NAK from
/// the listener and a retransmit from the caller. No prior test in this
/// file exercised the full loss -> NAK -> retransmit round trip (the
/// existing `test_nak_timer`/`test_process_retransmit` tests fire the
/// relevant timers but never simulate an actual gap), so this was an
/// unverified path until this test -- added after a live netem differential
/// run needed to confirm the mechanism itself works before trusting its
/// recovery-rate numbers.
#[test]
fn test_dropped_packet_triggers_nak_then_retransmit() {
    let mut caller = SrtConnection::new_caller(test_options());
    let mut listener = SrtConnection::new_listener(test_options());

    establish_connection(&mut caller, &mut listener).expect("connection should be established");
    while caller.poll_event().is_some() {}
    while listener.poll_event().is_some() {}

    let now = ts(100_000);
    for i in 0..10 {
        let data = format!("Message {}", i);
        caller
            .send(data.as_bytes(), now)
            .expect("send should succeed");
    }

    // Deliver every DATA packet except the 6th (index 5), simulating one
    // lost packet.
    let mut idx = 0;
    while let Some(output) = caller.poll_output() {
        if let ConnectionOutput::SendPacket(data) = output {
            if idx != 5 {
                let _ = listener.feed_recv_buf(&data, now);
            }
            idx += 1;
        }
    }

    // Advance time and fire the listener's NAK timer.
    let now2 = ts(150_000);
    listener
        .handle_timer(TimerId::Nak, now2)
        .expect("nak timer");

    // Transfer the listener's output (should include a NAK) to the caller.
    let mut nak_sent = false;
    while let Some(output) = listener.poll_output() {
        if let ConnectionOutput::SendPacket(data) = output {
            nak_sent = true;
            let _ = caller.feed_recv_buf(&data, now2);
        }
    }
    assert!(
        nak_sent,
        "listener should have emitted a NAK for the dropped packet"
    );

    let stats = caller.sender_stats().expect("stats");
    assert!(
        stats.total_retransmits > 0,
        "caller should have retransmitted the lost packet after receiving the NAK"
    );
    // Gap detection emits an immediate NAK and the timer emits a periodic
    // retry. The first retransmission was already dequeued when the second
    // report arrived, so both loss occurrences are observable.
    assert_eq!(stats.total_naks_received, 2);
    assert_eq!(stats.total_lost, 2);
    assert!(stats.total_retransmitted_srt_bytes > 0);

    let receiver = listener.receiver_stats().expect("receiver stats");
    assert_eq!(receiver.total_naks_sent, 2);
    assert_eq!(receiver.total_lost, 1);
}
