#![no_main]

use libfuzzer_sys::fuzz_target;
use shiguredo_srt::{CipherMode, CryptoContext, KeyLength};

fuzz_target!(|data: &[u8]| {
    // Fuzz the GCM decrypt path with arbitrary ciphertext+tag payloads.
    // A well-formed GCM payload is at least 16 bytes (tag only, empty plaintext).
    if data.len() < 16 {
        return;
    }

    let sek = [0x42u8; 16];
    let salt = [0xABu8; 16];
    let header = [0u8; 16];

    let sender = CryptoContext::new_sender("fuzz-passphrase", KeyLength::Aes128, salt, &sek, CipherMode::Gcm)
        .expect("context creation with valid params");
    let wrapped = sender.wrap_sek(sender.current_key()).expect("wrap");
    let receiver = CryptoContext::new_receiver(
        "fuzz-passphrase",
        salt,
        &wrapped,
        sender.current_key(),
        KeyLength::Aes128,
        CipherMode::Gcm,
    )
    .expect("receiver");

    // Should never panic — only Ok or Err
    let _ = receiver.decrypt_gcm(0, sender.current_key(), &header, data);
});
