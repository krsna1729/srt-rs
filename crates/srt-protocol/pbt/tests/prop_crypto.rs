//! Property-based tests for SRT crypto

use proptest::prelude::*;
use shiguredo_srt::{CipherMode, CryptoContext, KeyFlag, KeyLength, KmRefreshState};

fn generate_sek(key_length: KeyLength) -> Vec<u8> {
    vec![0x42u8; key_length.len()]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn test_encrypt_decrypt_roundtrip(
        passphrase in "[a-zA-Z0-9]{10,32}",
        key_length in prop::sample::select(vec![KeyLength::Aes128, KeyLength::Aes192, KeyLength::Aes256]),
        salt in prop::collection::vec(any::<u8>(), 16..=16),
        payload_data in prop::collection::vec(any::<u8>(), 16..1400),
        packet_index in 0u32..1000000,
    ) {
        let salt_arr: [u8; 16] = salt.try_into().expect("salt is 16 bytes");
        let sek = generate_sek(key_length);
        let mut sender = CryptoContext::new_sender(&passphrase, key_length, salt_arr, &sek, CipherMode::Ctr).expect("sender creation should succeed");

        let mut encrypted = payload_data.clone();
        let key_flag = sender.encrypt(packet_index, &mut encrypted).expect("encrypt should succeed");

        let wrapped_sek = sender.wrap_sek(key_flag).expect("wrap should succeed");
        let receiver = CryptoContext::new_receiver(
            &passphrase,
            *sender.salt(),
            &wrapped_sek,
            key_flag,
            key_length,
            CipherMode::Ctr,
        ).expect("receiver creation should succeed");

        let mut decrypted = encrypted.clone();
        receiver.decrypt(packet_index, key_flag, &mut decrypted).expect("decrypt should succeed");

        prop_assert_eq!(payload_data, decrypted);
    }

    #[test]
    fn test_encrypt_changes_data(
        passphrase in "[a-zA-Z0-9]{10,32}",
        key_length in prop::sample::select(vec![KeyLength::Aes128, KeyLength::Aes192, KeyLength::Aes256]),
        salt in prop::collection::vec(any::<u8>(), 16..=16),
        payload_data in prop::collection::vec(1u8..=255, 16..1400),
        packet_index in 0u32..1000000,
    ) {
        let salt_arr: [u8; 16] = salt.try_into().expect("salt is 16 bytes");
        let sek = generate_sek(key_length);
        let mut ctx = CryptoContext::new_sender(&passphrase, key_length, salt_arr, &sek, CipherMode::Ctr).expect("creation should succeed");

        let mut encrypted = payload_data.clone();
        ctx.encrypt(packet_index, &mut encrypted).expect("encrypt should succeed");

        prop_assert_ne!(payload_data, encrypted);
    }

    #[test]
    fn test_different_packet_index_produces_different_ciphertext(
        passphrase in "[a-zA-Z0-9]{10,32}",
        key_length in prop::sample::select(vec![KeyLength::Aes128, KeyLength::Aes192, KeyLength::Aes256]),
        salt in prop::collection::vec(any::<u8>(), 16..=16),
        payload_data in prop::collection::vec(any::<u8>(), 16..1400),
        packet_index1 in 0u32..500000,
        packet_index2 in 500001u32..1000000,
    ) {
        let salt_arr: [u8; 16] = salt.try_into().expect("salt is 16 bytes");
        let sek = generate_sek(key_length);
        let mut ctx = CryptoContext::new_sender(&passphrase, key_length, salt_arr, &sek, CipherMode::Ctr).expect("creation should succeed");

        let mut encrypted1 = payload_data.clone();
        ctx.encrypt(packet_index1, &mut encrypted1).expect("encrypt should succeed");

        let mut encrypted2 = payload_data.clone();
        ctx.encrypt(packet_index2, &mut encrypted2).expect("encrypt should succeed");

        prop_assert_ne!(encrypted1, encrypted2);
    }

    #[test]
    fn test_salt_low_bytes_do_not_affect_ctr_ciphertext(
        passphrase in "[a-zA-Z0-9]{10,32}",
        key_length in prop::sample::select(vec![KeyLength::Aes128, KeyLength::Aes192, KeyLength::Aes256]),
        salt_high in prop::collection::vec(any::<u8>(), 14..=14),
        low1 in any::<u8>(),
        low2 in any::<u8>(),
        low3 in any::<u8>(),
        low4 in any::<u8>(),
        payload_data in prop::collection::vec(any::<u8>(), 16..1400),
        packet_index in 0u32..1000000,
    ) {
        let mut salt1 = [0u8; 16];
        salt1[..14].copy_from_slice(&salt_high);
        salt1[14] = low1;
        salt1[15] = low2;
        let mut salt2 = salt1;
        salt2[14] = low3;
        salt2[15] = low4;

        let sek = generate_sek(key_length);
        let mut ctx1 = CryptoContext::new_sender(&passphrase, key_length, salt1, &sek, CipherMode::Ctr).expect("creation should succeed");
        let mut ctx2 = CryptoContext::new_sender(&passphrase, key_length, salt2, &sek, CipherMode::Ctr).expect("creation should succeed");

        let mut encrypted1 = payload_data.clone();
        ctx1.encrypt(packet_index, &mut encrypted1).expect("encrypt should succeed");
        let mut encrypted2 = payload_data.clone();
        ctx2.encrypt(packet_index, &mut encrypted2).expect("encrypt should succeed");

        prop_assert_eq!(encrypted1, encrypted2);
    }

    #[test]
    fn test_sek_wrap_unwrap_roundtrip(
        passphrase in "[a-zA-Z0-9]{10,32}",
        key_length in prop::sample::select(vec![KeyLength::Aes128, KeyLength::Aes192, KeyLength::Aes256]),
        salt in prop::collection::vec(any::<u8>(), 16..=16),
    ) {
        let salt_arr: [u8; 16] = salt.try_into().expect("salt is 16 bytes");
        let sek = generate_sek(key_length);
        let sender = CryptoContext::new_sender(&passphrase, key_length, salt_arr, &sek, CipherMode::Ctr).expect("sender creation should succeed");

        let key_flag = sender.current_key();
        let wrapped = sender.wrap_sek(key_flag).expect("wrap should succeed");

        let receiver = CryptoContext::new_receiver(
            &passphrase,
            *sender.salt(),
            &wrapped,
            key_flag,
            key_length,
            CipherMode::Ctr,
        );

        prop_assert!(receiver.is_ok());
    }

    #[test]
    fn test_key_length_roundtrip(
        key_len in prop::sample::select(vec![16usize, 24, 32]),
    ) {
        let key_length = KeyLength::from_len(key_len).expect("valid key length");
        prop_assert_eq!(key_length.len(), key_len);
    }

    #[test]
    fn test_key_flag_from_kk_field_valid(
        value in prop::sample::select(vec![0b01u8, 0b10u8]),
    ) {
        let key_flag = KeyFlag::from_kk_field(value);
        prop_assert!(key_flag.is_some());
        let flag = key_flag.expect("key flag should be Some");
        prop_assert_eq!(flag.to_kk_field(), value);
    }

    #[test]
    fn test_key_flag_from_kk_field_invalid(
        value in prop::sample::select(vec![0b00u8, 0b11u8]),
    ) {
        let key_flag = KeyFlag::from_kk_field(value);
        prop_assert!(key_flag.is_none());
    }

    #[test]
    fn test_key_flag_from_kk_field_with_upper_bits(
        upper_nibble in 0u8..=15u8,
        lower_bits in prop::sample::select(vec![0b01u8, 0b10u8]),
    ) {
        let value = (upper_nibble << 2) | lower_bits;
        let key_flag = KeyFlag::from_kk_field(value);
        prop_assert!(key_flag.is_some());
        let flag = key_flag.expect("key flag should be Some");
        prop_assert_eq!(flag.to_kk_field(), lower_bits);
    }

    #[test]
    fn test_key_flag_other_is_inverse(
        _dummy in Just(()),
    ) {
        prop_assert_eq!(KeyFlag::Even.other(), KeyFlag::Odd);
        prop_assert_eq!(KeyFlag::Odd.other(), KeyFlag::Even);
        prop_assert_eq!(KeyFlag::Even.other().other(), KeyFlag::Even);
        prop_assert_eq!(KeyFlag::Odd.other().other(), KeyFlag::Odd);
    }

    #[test]
    fn test_key_length_from_encryption_field_valid(
        value in prop::sample::select(vec![2u16, 3, 4]),
    ) {
        let key_length = KeyLength::from_encryption_field(value);
        prop_assert!(key_length.is_some());
        let kl = key_length.expect("key length should be Some");
        prop_assert_eq!(kl.to_encryption_field(), value);
    }

    #[test]
    fn test_key_length_from_encryption_field_invalid(
        value in (0u16..2u16).prop_union(5u16..100u16),
    ) {
        let key_length = KeyLength::from_encryption_field(value);
        prop_assert!(key_length.is_none());
    }

    #[test]
    fn test_key_length_from_len_invalid(
        len in prop::sample::select(vec![
            0usize, 1, 8, 15, 17, 18, 23, 25, 26, 31, 33, 48, 64, 100
        ]),
    ) {
        let key_length = KeyLength::from_len(len);
        prop_assert!(key_length.is_none());
    }

    #[test]
    fn test_wrong_passphrase_fails_unwrap(
        passphrase1 in "[a-zA-Z0-9]{10,32}",
        passphrase2 in "[a-zA-Z0-9]{10,32}",
        key_length in prop::sample::select(vec![KeyLength::Aes128, KeyLength::Aes192, KeyLength::Aes256]),
        salt in prop::collection::vec(any::<u8>(), 16..=16),
    ) {
        prop_assume!(passphrase1 != passphrase2);

        let salt_arr: [u8; 16] = salt.try_into().expect("salt is 16 bytes");
        let sek = generate_sek(key_length);
        let sender = CryptoContext::new_sender(&passphrase1, key_length, salt_arr, &sek, CipherMode::Ctr).expect("sender creation should succeed");
        let key_flag = sender.current_key();
        let wrapped_sek = sender.wrap_sek(key_flag).expect("wrap should succeed");

        let receiver_result = CryptoContext::new_receiver(
            &passphrase2,
            *sender.salt(),
            &wrapped_sek,
            key_flag,
            key_length,
            CipherMode::Ctr,
        );

        prop_assert!(receiver_result.is_err());
    }

    #[test]
    fn test_km_refresh_full_lifecycle(
        passphrase in "[a-zA-Z0-9]{10,32}",
        key_length in prop::sample::select(vec![KeyLength::Aes128, KeyLength::Aes192, KeyLength::Aes256]),
        salt in prop::collection::vec(any::<u8>(), 16..=16),
    ) {
        let salt_arr: [u8; 16] = salt.try_into().expect("salt is 16 bytes");
        let sek = generate_sek(key_length);
        let mut crypto = CryptoContext::new_sender(&passphrase, key_length, salt_arr, &sek, CipherMode::Ctr).expect("creation should succeed");

        prop_assert_eq!(crypto.km_refresh_state(), KmRefreshState::Idle);
        prop_assert_eq!(crypto.current_key(), KeyFlag::Even);
        prop_assert!(!crypto.should_pre_announce());
        prop_assert!(!crypto.should_switch_key());
        prop_assert!(!crypto.should_decommission_old_key());

        let new_sek = generate_sek(key_length);
        let (new_key, wrapped) = crypto.start_pre_announce(&new_sek).expect("start_pre_announce should succeed");
        prop_assert_eq!(new_key, KeyFlag::Odd);
        prop_assert!(!wrapped.is_empty());
        prop_assert_eq!(crypto.km_refresh_state(), KmRefreshState::PreAnnounce);
        prop_assert_eq!(crypto.current_key(), KeyFlag::Even);

        crypto.switch_key();
        prop_assert_eq!(crypto.current_key(), KeyFlag::Odd);
        prop_assert_eq!(crypto.km_refresh_state(), KmRefreshState::PostAnnounce);

        crypto.decommission_old_key();
        prop_assert_eq!(crypto.km_refresh_state(), KmRefreshState::Idle);

        let new_sek2 = generate_sek(key_length);
        let (new_key2, _) = crypto.start_pre_announce(&new_sek2).expect("start_pre_announce should succeed");
        prop_assert_eq!(new_key2, KeyFlag::Even);
        crypto.switch_key();
        prop_assert_eq!(crypto.current_key(), KeyFlag::Even);
    }

    #[test]
    fn test_update_sek_changes_decryption(
        passphrase in "[a-zA-Z0-9]{10,32}",
        key_length in prop::sample::select(vec![KeyLength::Aes128, KeyLength::Aes192, KeyLength::Aes256]),
        salt in prop::collection::vec(any::<u8>(), 16..=16),
        payload_data in prop::collection::vec(any::<u8>(), 16..256),
        packet_index in 0u32..1000000,
    ) {
        let salt_arr: [u8; 16] = salt.try_into().expect("salt is 16 bytes");
        let sek = generate_sek(key_length);
        let mut sender = CryptoContext::new_sender(&passphrase, key_length, salt_arr, &sek, CipherMode::Ctr).expect("sender creation should succeed");

        let mut encrypted = payload_data.clone();
        let key_flag = sender.encrypt(packet_index, &mut encrypted).expect("encrypt should succeed");

        let wrapped_sek = sender.wrap_sek(key_flag).expect("wrap should succeed");
        let mut receiver = CryptoContext::new_receiver(
            &passphrase,
            *sender.salt(),
            &wrapped_sek,
            key_flag,
            key_length,
            CipherMode::Ctr,
        ).expect("receiver creation should succeed");

        let new_sek = generate_sek(key_length);
        let (new_key_flag, new_wrapped_sek) = sender.start_pre_announce(&new_sek).expect("start_pre_announce should succeed");

        receiver.update_sek(&new_wrapped_sek, new_key_flag).expect("update_sek should succeed");
        prop_assert_eq!(receiver.current_key(), new_key_flag);

        sender.switch_key();
        let mut encrypted2 = payload_data.clone();
        let key_flag2 = sender.encrypt(packet_index + 1, &mut encrypted2).expect("encrypt should succeed");
        prop_assert_eq!(key_flag2, new_key_flag);

        let mut decrypted2 = encrypted2.clone();
        receiver.decrypt(packet_index + 1, key_flag2, &mut decrypted2).expect("decrypt should succeed");
        prop_assert_eq!(payload_data, decrypted2);
    }

    #[test]
    fn test_encrypt_empty_payload(
        passphrase in "[a-zA-Z0-9]{10,32}",
        key_length in prop::sample::select(vec![KeyLength::Aes128, KeyLength::Aes192, KeyLength::Aes256]),
        salt in prop::collection::vec(any::<u8>(), 16..=16),
        packet_index in 0u32..1000000,
    ) {
        let salt_arr: [u8; 16] = salt.try_into().expect("salt is 16 bytes");
        let sek = generate_sek(key_length);
        let mut ctx = CryptoContext::new_sender(&passphrase, key_length, salt_arr, &sek, CipherMode::Ctr).expect("creation should succeed");

        let mut empty_payload: Vec<u8> = vec![];
        let result = ctx.encrypt(packet_index, &mut empty_payload);
        prop_assert!(result.is_ok());
        prop_assert!(empty_payload.is_empty());
    }

    #[test]
    fn test_switch_key_without_pre_announce(
        passphrase in "[a-zA-Z0-9]{10,32}",
        key_length in prop::sample::select(vec![KeyLength::Aes128, KeyLength::Aes192, KeyLength::Aes256]),
        salt in prop::collection::vec(any::<u8>(), 16..=16),
    ) {
        let salt_arr: [u8; 16] = salt.try_into().expect("salt is 16 bytes");
        let sek = generate_sek(key_length);
        let mut crypto = CryptoContext::new_sender(&passphrase, key_length, salt_arr, &sek, CipherMode::Ctr).expect("creation should succeed");

        let original_key = crypto.current_key();
        crypto.switch_key();

        prop_assert_eq!(crypto.current_key(), original_key);
        prop_assert_eq!(crypto.km_refresh_state(), KmRefreshState::Idle);
    }

    #[test]
    fn test_ctr_mode_different_iv_per_packet(
        passphrase in "[a-zA-Z0-9]{10,32}",
        key_length in prop::sample::select(vec![KeyLength::Aes128, KeyLength::Aes192, KeyLength::Aes256]),
        salt in prop::collection::vec(any::<u8>(), 16..=16),
        payload_data in prop::collection::vec(any::<u8>(), 32..256),
    ) {
        let salt_arr: [u8; 16] = salt.try_into().expect("salt is 16 bytes");
        let sek = generate_sek(key_length);
        let mut ctx = CryptoContext::new_sender(&passphrase, key_length, salt_arr, &sek, CipherMode::Ctr).expect("creation should succeed");

        let mut encrypted0 = payload_data.clone();
        ctx.encrypt(0, &mut encrypted0).expect("encrypt should succeed");

        let mut encrypted1 = payload_data.clone();
        ctx.encrypt(1, &mut encrypted1).expect("encrypt should succeed");

        prop_assert_ne!(encrypted0, encrypted1);
    }

    #[test]
    fn test_packet_index_wraparound(
        passphrase in "[a-zA-Z0-9]{10,32}",
        key_length in prop::sample::select(vec![KeyLength::Aes128, KeyLength::Aes192, KeyLength::Aes256]),
        salt in prop::collection::vec(any::<u8>(), 16..=16),
        payload_data in prop::collection::vec(any::<u8>(), 16..256),
    ) {
        let salt_arr: [u8; 16] = salt.try_into().expect("salt is 16 bytes");
        let sek = generate_sek(key_length);
        let mut sender = CryptoContext::new_sender(&passphrase, key_length, salt_arr, &sek, CipherMode::Ctr).expect("sender creation should succeed");
        let key_flag = sender.current_key();
        let wrapped_sek = sender.wrap_sek(key_flag).expect("wrap should succeed");
        let receiver = CryptoContext::new_receiver(
            &passphrase,
            *sender.salt(),
            &wrapped_sek,
            key_flag,
            key_length,
            CipherMode::Ctr,
        ).expect("receiver creation should succeed");

        let indices = [u32::MAX - 1, u32::MAX, 0, 1];
        for &idx in &indices {
            let mut encrypted = payload_data.clone();
            sender.encrypt(idx, &mut encrypted).expect("encrypt should succeed");

            let mut decrypted = encrypted.clone();
            receiver.decrypt(idx, key_flag, &mut decrypted).expect("decrypt should succeed");
            prop_assert_eq!(payload_data.clone(), decrypted);
        }
    }

    // ── AES-GCM property tests ──

    #[test]
    fn test_gcm_encrypt_decrypt_roundtrip(
        passphrase in "[a-zA-Z0-9]{10,32}",
        key_length in prop::sample::select(vec![KeyLength::Aes128, KeyLength::Aes256]),
        salt in prop::collection::vec(any::<u8>(), 16..=16),
        payload_data in prop::collection::vec(any::<u8>(), 1..1400),
        header in prop::collection::vec(any::<u8>(), 16..=16),
        packet_index in 0u32..1000000,
    ) {
        let salt_arr: [u8; 16] = salt.try_into().expect("salt is 16 bytes");
        let header_arr: [u8; 16] = header.try_into().expect("header is 16 bytes");
        let sek = generate_sek(key_length);
        let mut sender = CryptoContext::new_sender(&passphrase, key_length, salt_arr, &sek, CipherMode::Gcm).expect("sender creation should succeed");

        let payload_len = payload_data.len();
        let (key_flag, encrypted) = sender.encrypt_gcm(packet_index, &header_arr, payload_data.clone()).expect("encrypt_gcm should succeed");

        // ciphertext + 16-byte tag
        prop_assert_eq!(encrypted.len(), payload_len + 16);

        let wrapped_sek = sender.wrap_sek(key_flag).expect("wrap should succeed");
        let receiver = CryptoContext::new_receiver(
            &passphrase,
            *sender.salt(),
            &wrapped_sek,
            key_flag,
            key_length,
            CipherMode::Gcm,
        ).expect("receiver creation should succeed");

        let decrypted = receiver.decrypt_gcm(packet_index, key_flag, &header_arr, encrypted).expect("decrypt_gcm should succeed");
        prop_assert_eq!(payload_data, decrypted);
    }

    #[test]
    fn test_gcm_tampered_ciphertext_rejected(
        passphrase in "[a-zA-Z0-9]{10,32}",
        key_length in prop::sample::select(vec![KeyLength::Aes128, KeyLength::Aes256]),
        salt in prop::collection::vec(any::<u8>(), 16..=16),
        payload_data in prop::collection::vec(any::<u8>(), 16..256),
        header in prop::collection::vec(any::<u8>(), 16..=16),
        packet_index in 0u32..1000000,
        flip_pos in 0usize..16,
    ) {
        let salt_arr: [u8; 16] = salt.try_into().expect("salt is 16 bytes");
        let header_arr: [u8; 16] = header.try_into().expect("header is 16 bytes");
        let sek = generate_sek(key_length);
        let mut sender = CryptoContext::new_sender(&passphrase, key_length, salt_arr, &sek, CipherMode::Gcm).expect("sender creation should succeed");

        let (key_flag, mut encrypted) = sender.encrypt_gcm(packet_index, &header_arr, payload_data).expect("encrypt_gcm should succeed");

        let actual_flip = flip_pos % encrypted.len();
        encrypted[actual_flip] ^= 0xFF;

        let wrapped_sek = sender.wrap_sek(key_flag).expect("wrap should succeed");
        let receiver = CryptoContext::new_receiver(
            &passphrase,
            *sender.salt(),
            &wrapped_sek,
            key_flag,
            key_length,
            CipherMode::Gcm,
        ).expect("receiver creation should succeed");

        let result = receiver.decrypt_gcm(packet_index, key_flag, &header_arr, encrypted);
        prop_assert!(result.is_err());
    }

    #[test]
    fn test_gcm_tampered_aad_rejected(
        passphrase in "[a-zA-Z0-9]{10,32}",
        key_length in prop::sample::select(vec![KeyLength::Aes128, KeyLength::Aes256]),
        salt in prop::collection::vec(any::<u8>(), 16..=16),
        payload_data in prop::collection::vec(any::<u8>(), 16..256),
        header in prop::collection::vec(any::<u8>(), 16..=16),
        packet_index in 0u32..1000000,
        flip_pos in 0usize..16,
    ) {
        let salt_arr: [u8; 16] = salt.try_into().expect("salt is 16 bytes");
        let header_arr: [u8; 16] = header.try_into().expect("header is 16 bytes");
        let sek = generate_sek(key_length);
        let mut sender = CryptoContext::new_sender(&passphrase, key_length, salt_arr, &sek, CipherMode::Gcm).expect("sender creation should succeed");

        let (key_flag, encrypted) = sender.encrypt_gcm(packet_index, &header_arr, payload_data).expect("encrypt_gcm should succeed");

        let mut bad_header = header_arr;
        bad_header[flip_pos] ^= 0xFF;

        let wrapped_sek = sender.wrap_sek(key_flag).expect("wrap should succeed");
        let receiver = CryptoContext::new_receiver(
            &passphrase,
            *sender.salt(),
            &wrapped_sek,
            key_flag,
            key_length,
            CipherMode::Gcm,
        ).expect("receiver creation should succeed");

        let result = receiver.decrypt_gcm(packet_index, key_flag, &bad_header, encrypted);
        prop_assert!(result.is_err());
    }

    #[test]
    fn test_gcm_different_packet_index_produces_different_ciphertext(
        passphrase in "[a-zA-Z0-9]{10,32}",
        key_length in prop::sample::select(vec![KeyLength::Aes128, KeyLength::Aes256]),
        salt in prop::collection::vec(any::<u8>(), 16..=16),
        payload_data in prop::collection::vec(any::<u8>(), 16..256),
        header in prop::collection::vec(any::<u8>(), 16..=16),
        packet_index1 in 0u32..500000,
        packet_index2 in 500001u32..1000000,
    ) {
        let salt_arr: [u8; 16] = salt.try_into().expect("salt is 16 bytes");
        let header_arr: [u8; 16] = header.try_into().expect("header is 16 bytes");
        let sek = generate_sek(key_length);
        let mut ctx = CryptoContext::new_sender(&passphrase, key_length, salt_arr, &sek, CipherMode::Gcm).expect("creation should succeed");

        let (_, encrypted1) = ctx.encrypt_gcm(packet_index1, &header_arr, payload_data.clone()).expect("encrypt should succeed");
        let (_, encrypted2) = ctx.encrypt_gcm(packet_index2, &header_arr, payload_data).expect("encrypt should succeed");

        prop_assert_ne!(encrypted1, encrypted2);
    }

    #[test]
    fn test_gcm_wrong_passphrase_fails(
        passphrase1 in "[a-zA-Z0-9]{10,32}",
        passphrase2 in "[a-zA-Z0-9]{10,32}",
        key_length in prop::sample::select(vec![KeyLength::Aes128, KeyLength::Aes256]),
        salt in prop::collection::vec(any::<u8>(), 16..=16),
        payload_data in prop::collection::vec(any::<u8>(), 16..256),
        header in prop::collection::vec(any::<u8>(), 16..=16),
        packet_index in 0u32..1000000,
    ) {
        prop_assume!(passphrase1 != passphrase2);

        let salt_arr: [u8; 16] = salt.try_into().expect("salt is 16 bytes");
        let header_arr: [u8; 16] = header.try_into().expect("header is 16 bytes");
        let sek = generate_sek(key_length);
        let mut sender = CryptoContext::new_sender(&passphrase1, key_length, salt_arr, &sek, CipherMode::Gcm).expect("sender creation should succeed");

        let (key_flag, _encrypted) = sender.encrypt_gcm(packet_index, &header_arr, payload_data).expect("encrypt_gcm should succeed");

        let wrapped_sek = sender.wrap_sek(key_flag).expect("wrap should succeed");
        let receiver_result = CryptoContext::new_receiver(
            &passphrase2,
            *sender.salt(),
            &wrapped_sek,
            key_flag,
            key_length,
            CipherMode::Gcm,
        );

        // Wrong passphrase fails at key unwrap
        prop_assert!(receiver_result.is_err());
    }

    #[test]
    fn test_gcm_packet_index_wraparound(
        passphrase in "[a-zA-Z0-9]{10,32}",
        key_length in prop::sample::select(vec![KeyLength::Aes128, KeyLength::Aes256]),
        salt in prop::collection::vec(any::<u8>(), 16..=16),
        payload_data in prop::collection::vec(any::<u8>(), 16..256),
        header in prop::collection::vec(any::<u8>(), 16..=16),
    ) {
        let salt_arr: [u8; 16] = salt.try_into().expect("salt is 16 bytes");
        let header_arr: [u8; 16] = header.try_into().expect("header is 16 bytes");
        let sek = generate_sek(key_length);
        let mut sender = CryptoContext::new_sender(&passphrase, key_length, salt_arr, &sek, CipherMode::Gcm).expect("sender creation should succeed");
        let key_flag = sender.current_key();
        let wrapped_sek = sender.wrap_sek(key_flag).expect("wrap should succeed");
        let receiver = CryptoContext::new_receiver(
            &passphrase,
            *sender.salt(),
            &wrapped_sek,
            key_flag,
            key_length,
            CipherMode::Gcm,
        ).expect("receiver creation should succeed");

        let indices = [u32::MAX - 1, u32::MAX, 0, 1];
        for &idx in &indices {
            let (kf, encrypted) = sender.encrypt_gcm(idx, &header_arr, payload_data.clone()).expect("encrypt_gcm should succeed");
            let decrypted = receiver.decrypt_gcm(idx, kf, &header_arr, encrypted).expect("decrypt_gcm should succeed");
            prop_assert_eq!(payload_data.clone(), decrypted);
        }
    }

    #[test]
    fn test_gcm_rejects_aes192(
        passphrase in "[a-zA-Z0-9]{10,32}",
        salt in prop::collection::vec(any::<u8>(), 16..=16),
    ) {
        let salt_arr: [u8; 16] = salt.try_into().expect("salt is 16 bytes");
        let sek = generate_sek(KeyLength::Aes192);
        let result = CryptoContext::new_sender(&passphrase, KeyLength::Aes192, salt_arr, &sek, CipherMode::Gcm);
        prop_assert!(result.is_err());
    }
}
