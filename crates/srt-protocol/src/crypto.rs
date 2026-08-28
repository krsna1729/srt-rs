//! SRT encryption module.
//!
//! SRT encrypts payloads with AES-CTR or AES-GCM (authenticated encryption).
//! - KEK (Key Encrypting Key): derived from the passphrase via PBKDF2
//! - SEK (Stream Encrypting Key): generated randomly, wrapped with the KEK via AES Key Wrap
//! - Payload data is encrypted with AES-CTR or AES-GCM
//!
//! AES-GCM (added in libsrt 1.6.0) provides authenticated encryption: each
//! encrypted data packet carries a 16-byte authentication tag appended after
//! the ciphertext, and the 16-byte SRT packet header is used as additional
//! authenticated data (AAD). The retransmit flag (R) is zeroed in the AAD
//! because it can change between original and retransmitted copies.
//!
//! local patch (crates/srt-protocol/VENDOR.md): originally
//! `aws-lc-rs`, which pulls in `aws-lc-sys` -- a cmake+C-compiler native
//! build step, exactly the kind of native toolchain dependency this whole
//! migration exists to move away from. Replaced with a pure-Rust
//! RustCrypto stack, all audited crates, no hand-rolled crypto:
//! - PBKDF2-HMAC-SHA1 (KEK derivation): `pbkdf2` + `sha1`
//! - AES Key Wrap / RFC 3394 (SEK wrap/unwrap): `aes-kw`
//! - AES-CTR (payload encryption): `ctr` + `aes`, `cipher` traits
//! - AES-GCM (authenticated payload encryption): `aes-gcm`
//!
//! `ctr`/`aes-kw`/`aes-gcm` and `hmac`/`sha1`/`pbkdf2` must be pinned to
//! versions that agree on the same `cipher`/`aes` generation (currently
//! `cipher 0.5`/`aes 0.9`). Verified clean (single generation, no
//! duplicate `aes`/`cipher` versions) at the versions pinned in
//! `Cargo.toml`.

use std::fmt;

use aes::{Aes128, Aes192, Aes256};
use aes_gcm::aead::AeadInOut;
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit as GcmKeyInit, Nonce};
use aes_kw::{KwAes128, KwAes192, KwAes256};
use cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use zeroize::Zeroize;

use crate::error::Error;

/// Number of PBKDF2 iterations (per the SRT specification).
const PBKDF2_ITERATIONS: u32 = 2048;

/// AES-GCM authentication tag length (bytes).
pub const GCM_TAG_LEN: usize = 16;

/// AES-GCM IV/nonce length (bytes).
const GCM_IV_LEN: usize = 12;

/// Cipher mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CipherMode {
    /// AES-CTR (counter mode, no authentication).
    #[default]
    Ctr,
    /// AES-GCM (Galois/Counter Mode, authenticated encryption).
    Gcm,
}

impl CipherMode {
    /// Determine cipher mode from a decoded KM message.
    ///
    /// Returns `None` if the cipher/auth fields are inconsistent (e.g.
    /// cipher=AES_GCM but auth!=AES_GCM).
    pub fn from_km(km: &crate::srt_handshake::KmMessage) -> Option<Self> {
        use crate::srt_handshake::{auth_type, cipher_type};
        match (km.cipher, km.auth) {
            (cipher_type::AES_CTR, auth_type::NONE) => Some(Self::Ctr),
            (cipher_type::AES_GCM, auth_type::AES_GCM) => Some(Self::Gcm),
            _ => None,
        }
    }
}

/// Key length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyLength {
    /// AES-128 (16 bytes)
    #[default]
    Aes128 = 16,
    /// AES-192 (24 bytes)
    Aes192 = 24,
    /// AES-256 (32 bytes)
    Aes256 = 32,
}

impl KeyLength {
    /// Get the length in bytes.
    #[expect(clippy::len_without_is_empty)]
    pub fn len(self) -> usize {
        self as usize
    }

    /// Get the `KeyLength` for a length in bytes.
    pub fn from_len(len: usize) -> Option<Self> {
        match len {
            16 => Some(Self::Aes128),
            24 => Some(Self::Aes192),
            32 => Some(Self::Aes256),
            _ => None,
        }
    }

    /// Get the `KeyLength` from a handshake Encryption Field value.
    pub fn from_encryption_field(value: u16) -> Option<Self> {
        match value {
            2 => Some(Self::Aes128),
            3 => Some(Self::Aes192),
            4 => Some(Self::Aes256),
            _ => None,
        }
    }

    /// Convert to a handshake Encryption Field value.
    pub fn to_encryption_field(self) -> u16 {
        match self {
            Self::Aes128 => 2,
            Self::Aes192 => 3,
            Self::Aes256 => 4,
        }
    }
}

/// Key flag (odd/even).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyFlag {
    /// Even key.
    #[default]
    Even = 0b01,
    /// Odd key.
    Odd = 0b10,
}

impl KeyFlag {
    /// Get the flag from a KK field value.
    pub fn from_kk_field(value: u8) -> Option<Self> {
        match value & 0b11 {
            0b01 => Some(Self::Even),
            0b10 => Some(Self::Odd),
            _ => None,
        }
    }

    /// Convert to a KK field value.
    pub fn to_kk_field(self) -> u8 {
        self as u8
    }

    /// Get the opposite key flag.
    pub fn other(self) -> Self {
        match self {
            Self::Even => Self::Odd,
            Self::Odd => Self::Even,
        }
    }
}

/// KM refresh state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KmRefreshState {
    /// Idle; no refresh needed.
    #[default]
    Idle,
    /// Pre-announcing: a new key has been generated and sent, awaiting switchover.
    PreAnnounce,
    /// Key switch complete, awaiting disposal of the old key.
    PostAnnounce,
}

/// Encryption context.
pub struct CryptoContext {
    /// Key Encrypting Key (derived via PBKDF2).
    kek: Vec<u8>,
    /// Stream Encrypting Key (even).
    sek_even: Vec<u8>,
    /// Stream Encrypting Key (odd).
    sek_odd: Vec<u8>,
    /// Salt (16 bytes).
    salt: [u8; 16],
    /// The key currently in use.
    current_key: KeyFlag,
    /// Key length.
    key_length: KeyLength,
    /// Cipher mode (CTR or GCM).
    cipher_mode: CipherMode,
    /// Number of packets encrypted so far.
    encrypted_packet_count: u64,
    /// KM refresh state.
    km_refresh_state: KmRefreshState,
    /// The next key (generated while pre-announcing).
    next_key: Option<KeyFlag>,
}

// local patch (crates/srt-protocol/VENDOR.md, upstream issues
// 0049/0050, open/unfixed at vendor commit 6779cdd): #[derive(Debug)] would
// print raw key bytes and salt via {:?}/dbg!(). Redact all keying material.
impl fmt::Debug for CryptoContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CryptoContext")
            .field("kek", &"[REDACTED]")
            .field("sek_even", &"[REDACTED]")
            .field("sek_odd", &"[REDACTED]")
            .field("salt", &"[REDACTED]")
            .field("current_key", &self.current_key)
            .field("key_length", &self.key_length)
            .field("cipher_mode", &self.cipher_mode)
            .field("encrypted_packet_count", &self.encrypted_packet_count)
            .field("km_refresh_state", &self.km_refresh_state)
            .field("next_key", &self.next_key)
            .finish()
    }
}

// local patch (crates/srt-protocol/VENDOR.md, upstream issue
// 0050, open/unfixed at vendor commit 6779cdd): Vec<u8>'s default Drop only
// frees memory, it does not zero it, so key material could linger in freed
// heap memory. `decommission_old_key` already zeros explicitly on its own
// path; this covers the remaining case (the whole context dropped, e.g. on
// abnormal connection teardown).
impl Drop for CryptoContext {
    fn drop(&mut self) {
        self.kek.zeroize();
        self.sek_even.zeroize();
        self.sek_odd.zeroize();
        self.salt.zeroize();
    }
}

impl CryptoContext {
    /// KM refresh period (2^25 packets).
    pub const KM_REFRESH_PERIOD: u64 = 1 << 25;

    /// KM pre-announce period (4000 packets).
    pub const KM_PRE_ANNOUNCE_PERIOD: u64 = 4000;

    /// Build an encryption context from a passphrase (sender side).
    ///
    /// `salt` and `sek` must be generated externally from a random source.
    pub fn new_sender(
        passphrase: &str,
        key_length: KeyLength,
        salt: [u8; 16],
        sek: &[u8],
        cipher_mode: CipherMode,
    ) -> Result<Self, Error> {
        if sek.len() != key_length.len() {
            return Err(Error::crypto_error("invalid SEK length"));
        }
        if sek.iter().all(|byte| *byte == 0) {
            return Err(Error::crypto_error("SEK must not be all zero"));
        }
        if cipher_mode == CipherMode::Gcm && key_length == KeyLength::Aes192 {
            return Err(Error::crypto_error(
                "AES-192 is not supported with GCM mode",
            ));
        }

        let kek = derive_kek(passphrase, &salt, key_length);

        let sek_even = sek.to_vec();
        let sek_odd = vec![0u8; key_length.len()];

        Ok(Self {
            kek,
            sek_even,
            sek_odd,
            salt,
            current_key: KeyFlag::Even,
            key_length,
            cipher_mode,
            encrypted_packet_count: 0,
            km_refresh_state: KmRefreshState::Idle,
            next_key: None,
        })
    }

    /// Build an encryption context from a passphrase and key material (receiver side).
    ///
    /// Unwraps the SEK with the KEK.
    pub fn new_receiver(
        passphrase: &str,
        salt: [u8; 16],
        wrapped_sek: &[u8],
        key_flag: KeyFlag,
        key_length: KeyLength,
        cipher_mode: CipherMode,
    ) -> Result<Self, Error> {
        if cipher_mode == CipherMode::Gcm && key_length == KeyLength::Aes192 {
            return Err(Error::crypto_error(
                "AES-192 is not supported with GCM mode",
            ));
        }

        let kek = derive_kek(passphrase, &salt, key_length);

        let sek = unwrap_sek(&kek, wrapped_sek, key_length)?;
        if sek.iter().all(|byte| *byte == 0) {
            return Err(Error::crypto_error("unwrapped SEK must not be all zero"));
        }

        let (sek_even, sek_odd) = match key_flag {
            KeyFlag::Even => (sek, vec![0u8; key_length.len()]),
            KeyFlag::Odd => (vec![0u8; key_length.len()], sek),
        };

        Ok(Self {
            kek,
            sek_even,
            sek_odd,
            salt,
            current_key: key_flag,
            key_length,
            cipher_mode,
            encrypted_packet_count: 0,
            km_refresh_state: KmRefreshState::Idle,
            next_key: None,
        })
    }

    /// Get the salt.
    pub fn salt(&self) -> &[u8; 16] {
        &self.salt
    }

    /// Get the current key flag.
    pub fn current_key(&self) -> KeyFlag {
        self.current_key
    }

    /// Get the key length.
    pub fn key_length(&self) -> KeyLength {
        self.key_length
    }

    /// Get the cipher mode.
    pub fn cipher_mode(&self) -> CipherMode {
        self.cipher_mode
    }

    /// Get the SEK, wrapped for a KM message.
    pub fn wrap_sek(&self, key_flag: KeyFlag) -> Result<Vec<u8>, Error> {
        let sek = match key_flag {
            KeyFlag::Even => &self.sek_even,
            KeyFlag::Odd => &self.sek_odd,
        };
        wrap_sek(&self.kek, sek, self.key_length)
    }

    /// Encrypt data in place (CTR mode).
    pub fn encrypt(&mut self, packet_index: u32, payload: &mut [u8]) -> Result<KeyFlag, Error> {
        let sek = match self.current_key {
            KeyFlag::Even => &self.sek_even,
            KeyFlag::Odd => &self.sek_odd,
        };

        encrypt_payload_ctr(sek, &self.salt, packet_index, payload, self.key_length)?;
        self.encrypted_packet_count += 1;

        Ok(self.current_key)
    }

    /// Encrypt data with GCM, returning ciphertext + 16-byte auth tag.
    ///
    /// `header` is the 16-byte SRT data packet header used as AAD; the
    /// retransmit flag must already be zeroed by the caller.
    pub fn encrypt_gcm(
        &mut self,
        packet_index: u32,
        header: &[u8; 16],
        payload: &[u8],
    ) -> Result<(KeyFlag, Vec<u8>), Error> {
        let sek = match self.current_key {
            KeyFlag::Even => &self.sek_even,
            KeyFlag::Odd => &self.sek_odd,
        };

        let out = encrypt_payload_gcm(
            sek,
            &self.salt,
            packet_index,
            header,
            payload,
            self.key_length,
        )?;
        self.encrypted_packet_count += 1;

        Ok((self.current_key, out))
    }

    /// Decrypt data in place (CTR mode).
    pub fn decrypt(
        &self,
        packet_index: u32,
        key_flag: KeyFlag,
        payload: &mut [u8],
    ) -> Result<(), Error> {
        let sek = match key_flag {
            KeyFlag::Even => &self.sek_even,
            KeyFlag::Odd => &self.sek_odd,
        };

        encrypt_payload_ctr(sek, &self.salt, packet_index, payload, self.key_length)
    }

    /// Decrypt data with GCM, verifying the auth tag.
    ///
    /// `payload` contains ciphertext + 16-byte tag (appended by sender).
    /// Returns the plaintext (tag stripped).
    pub fn decrypt_gcm(
        &self,
        packet_index: u32,
        key_flag: KeyFlag,
        header: &[u8; 16],
        payload: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let sek = match key_flag {
            KeyFlag::Even => &self.sek_even,
            KeyFlag::Odd => &self.sek_odd,
        };

        decrypt_payload_gcm(
            sek,
            &self.salt,
            packet_index,
            header,
            payload,
            self.key_length,
        )
    }

    /// Get the KM refresh state.
    pub fn km_refresh_state(&self) -> KmRefreshState {
        self.km_refresh_state
    }

    /// Whether pre-announcing is needed (2^25 - 4000 packets).
    pub fn should_pre_announce(&self) -> bool {
        self.km_refresh_state == KmRefreshState::Idle
            && self.encrypted_packet_count >= Self::KM_REFRESH_PERIOD - Self::KM_PRE_ANNOUNCE_PERIOD
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn set_encrypted_packet_count_for_test(&mut self, count: u64) {
        self.encrypted_packet_count = count;
    }

    /// Whether a key switch is needed (2^25 packets).
    pub fn should_switch_key(&self) -> bool {
        self.km_refresh_state == KmRefreshState::PreAnnounce
            && self.encrypted_packet_count >= Self::KM_REFRESH_PERIOD
    }

    /// Whether the old key needs to be disposed of (2^25 + 4000 packets).
    pub fn should_decommission_old_key(&self) -> bool {
        self.km_refresh_state == KmRefreshState::PostAnnounce
            && self.encrypted_packet_count >= Self::KM_PRE_ANNOUNCE_PERIOD
    }

    /// Begin pre-announcing a new SEK.
    ///
    /// `new_sek` must be generated externally from a random source.
    /// Returns the wrapped SEK; the caller must send a KMREQ.
    pub fn start_pre_announce(&mut self, new_sek: &[u8]) -> Result<(KeyFlag, Vec<u8>), Error> {
        if new_sek.len() != self.key_length.len() {
            return Err(Error::crypto_error("invalid SEK length"));
        }
        if new_sek.iter().all(|byte| *byte == 0) {
            return Err(Error::crypto_error("SEK must not be all zero"));
        }

        let new_key_flag = self.current_key.other();

        let target = match new_key_flag {
            KeyFlag::Even => &mut self.sek_even,
            KeyFlag::Odd => &mut self.sek_odd,
        };
        target.zeroize();
        target.clear();
        target.extend_from_slice(new_sek);

        self.next_key = Some(new_key_flag);
        self.km_refresh_state = KmRefreshState::PreAnnounce;

        let wrapped_sek = self.wrap_sek(new_key_flag)?;
        Ok((new_key_flag, wrapped_sek))
    }

    /// Switch keys (once 2^25 packets is reached).
    pub fn switch_key(&mut self) {
        if let Some(next_key) = self.next_key.take() {
            self.current_key = next_key;
            self.encrypted_packet_count = 0;
            self.km_refresh_state = KmRefreshState::PostAnnounce;
        }
    }

    /// Dispose of the old key (once 2^25 + 4000 packets is reached).
    pub fn decommission_old_key(&mut self) {
        // Zero the old key.
        let old_key = self.current_key.other();
        match old_key {
            KeyFlag::Even => self.sek_even.fill(0),
            KeyFlag::Odd => self.sek_odd.fill(0),
        }
        self.km_refresh_state = KmRefreshState::Idle;
    }

    /// Update the SEK from a received KM message.
    pub fn update_sek(&mut self, wrapped_sek: &[u8], key_flag: KeyFlag) -> Result<(), Error> {
        let sek = unwrap_sek(&self.kek, wrapped_sek, self.key_length)?;
        if sek.iter().all(|byte| *byte == 0) {
            return Err(Error::crypto_error("unwrapped SEK must not be all zero"));
        }

        let target = match key_flag {
            KeyFlag::Even => &mut self.sek_even,
            KeyFlag::Odd => &mut self.sek_odd,
        };
        target.zeroize();
        *target = sek;

        self.current_key = key_flag;
        Ok(())
    }
}

/// Derive the KEK via PBKDF2.
fn derive_kek(passphrase: &str, salt: &[u8; 16], key_length: KeyLength) -> Vec<u8> {
    let mut kek = vec![0u8; key_length.len()];
    // Use the salt's low 64 bits (8 bytes).
    let salt_lsb = &salt[8..16];
    pbkdf2_hmac::<Sha1>(passphrase.as_bytes(), salt_lsb, PBKDF2_ITERATIONS, &mut kek);
    kek
}

/// Wrap the SEK with AES Key Wrap (RFC 3394).
fn wrap_sek(kek: &[u8], sek: &[u8], key_length: KeyLength) -> Result<Vec<u8>, Error> {
    let mut wrapped = vec![0u8; sek.len() + 8];
    match key_length {
        KeyLength::Aes128 => {
            let kw = KwAes128::new_from_slice(kek)
                .map_err(|e| Error::crypto_error(format!("invalid KEK: {e}")))?;
            kw.wrap_key(sek, &mut wrapped)
                .map_err(|e| Error::crypto_error(format!("AES key wrap failed: {e}")))?;
        }
        KeyLength::Aes192 => {
            let kw = KwAes192::new_from_slice(kek)
                .map_err(|e| Error::crypto_error(format!("invalid KEK: {e}")))?;
            kw.wrap_key(sek, &mut wrapped)
                .map_err(|e| Error::crypto_error(format!("AES key wrap failed: {e}")))?;
        }
        KeyLength::Aes256 => {
            let kw = KwAes256::new_from_slice(kek)
                .map_err(|e| Error::crypto_error(format!("invalid KEK: {e}")))?;
            kw.wrap_key(sek, &mut wrapped)
                .map_err(|e| Error::crypto_error(format!("AES key wrap failed: {e}")))?;
        }
    }
    Ok(wrapped)
}

/// Unwrap the SEK with AES Key Wrap (RFC 3394).
fn unwrap_sek(kek: &[u8], wrapped: &[u8], key_length: KeyLength) -> Result<Vec<u8>, Error> {
    if wrapped.len() < 8 {
        return Err(Error::crypto_error("wrapped key too short"));
    }

    let mut unwrapped = vec![0u8; wrapped.len() - 8];
    match key_length {
        KeyLength::Aes128 => {
            let kw = KwAes128::new_from_slice(kek)
                .map_err(|e| Error::crypto_error(format!("invalid KEK: {e}")))?;
            kw.unwrap_key(wrapped, &mut unwrapped)
                .map_err(|e| Error::crypto_error(format!("AES key unwrap failed: {e}")))?;
        }
        KeyLength::Aes192 => {
            let kw = KwAes192::new_from_slice(kek)
                .map_err(|e| Error::crypto_error(format!("invalid KEK: {e}")))?;
            kw.unwrap_key(wrapped, &mut unwrapped)
                .map_err(|e| Error::crypto_error(format!("AES key unwrap failed: {e}")))?;
        }
        KeyLength::Aes256 => {
            let kw = KwAes256::new_from_slice(kek)
                .map_err(|e| Error::crypto_error(format!("invalid KEK: {e}")))?;
            kw.unwrap_key(wrapped, &mut unwrapped)
                .map_err(|e| Error::crypto_error(format!("AES key unwrap failed: {e}")))?;
        }
    }
    Ok(unwrapped)
}

/// Encrypt/decrypt a payload in place with AES-CTR.
fn encrypt_payload_ctr(
    sek: &[u8],
    salt: &[u8; 16],
    packet_index: u32,
    payload: &mut [u8],
    key_length: KeyLength,
) -> Result<(), Error> {
    // Build the counter block (the initial IV for AES-CTR).
    // Reference: draft-sharabayko-srt.md, "Encryption" section, "AES Counter" subsection.
    // Treating the 128-bit counter block as a big-endian 16-byte array:
    //   - bits 0-15 (bytes 14-15): block counter. 0 for each packet's first block; not XORed with the salt.
    //   - bits 16-47 (bytes 10-13): packet index
    //   - bits 48-127 (bytes 0-9): zero
    //   - the upper 112 bits (bytes 0-13) are XORed with IV = MSB(112, Salt) (= salt[0..14])
    // This matches the counter block construction in libsrt's haicrypt implementation.
    // The spec's section layout, line numbers, and notation may change in the future.
    let mut iv = [0u8; 16];
    // Place IV = MSB(112, Salt) in the upper 112 bits (bytes 0-13); bytes 14-15 stay 0.
    iv[..14].copy_from_slice(&salt[..14]);

    // XOR the packet index into bytes 10-13 (to_be_bytes gives [MSB, .., LSB]).
    let pi_bytes = packet_index.to_be_bytes();
    iv[10] ^= pi_bytes[0];
    iv[11] ^= pi_bytes[1];
    iv[12] ^= pi_bytes[2];
    iv[13] ^= pi_bytes[3];

    // In CTR mode, encryption and decryption are the same operation (XOR with the keystream).
    // Ctr128BE treats the whole 128-bit counter block as a big-endian counter, matching
    // libsrt's haicrypt implementation (see the comment above).
    match key_length {
        KeyLength::Aes128 => {
            let mut cipher = Ctr128BE::<Aes128>::new_from_slices(sek, &iv)
                .map_err(|e| Error::crypto_error(format!("invalid SEK: {e}")))?;
            cipher.apply_keystream(payload);
        }
        KeyLength::Aes192 => {
            let mut cipher = Ctr128BE::<Aes192>::new_from_slices(sek, &iv)
                .map_err(|e| Error::crypto_error(format!("invalid SEK: {e}")))?;
            cipher.apply_keystream(payload);
        }
        KeyLength::Aes256 => {
            let mut cipher = Ctr128BE::<Aes256>::new_from_slices(sek, &iv)
                .map_err(|e| Error::crypto_error(format!("invalid SEK: {e}")))?;
            cipher.apply_keystream(payload);
        }
    }

    Ok(())
}

/// Build the 12-byte GCM IV from salt and packet index.
///
/// Layout (96 bits): zero 12 bytes, place PKI at bytes 8-11 (big-endian),
/// XOR with MSB(96, salt). This matches libsrt's `hcrypt_SetGcmIV`.
fn build_gcm_iv(salt: &[u8; 16], packet_index: u32) -> [u8; GCM_IV_LEN] {
    let mut iv = [0u8; GCM_IV_LEN];
    let pi_bytes = packet_index.to_be_bytes();
    iv[8] = pi_bytes[0];
    iv[9] = pi_bytes[1];
    iv[10] = pi_bytes[2];
    iv[11] = pi_bytes[3];
    for i in 0..GCM_IV_LEN {
        iv[i] ^= salt[i];
    }
    iv
}

/// Encrypt a payload with AES-GCM, returning ciphertext + 16-byte tag.
fn encrypt_payload_gcm(
    sek: &[u8],
    salt: &[u8; 16],
    packet_index: u32,
    header: &[u8; 16],
    plaintext: &[u8],
    key_length: KeyLength,
) -> Result<Vec<u8>, Error> {
    let iv = build_gcm_iv(salt, packet_index);
    let nonce = Nonce::try_from(iv.as_slice())
        .map_err(|e| Error::crypto_error(format!("invalid GCM nonce: {e}")))?;
    let mut buffer = plaintext.to_vec();

    match key_length {
        KeyLength::Aes128 => {
            let cipher = Aes128Gcm::new_from_slice(sek)
                .map_err(|e| Error::crypto_error(format!("invalid SEK: {e}")))?;
            cipher
                .encrypt_in_place(&nonce, header, &mut buffer)
                .map_err(|e| Error::crypto_error(format!("AES-GCM encrypt failed: {e}")))?;
        }
        KeyLength::Aes192 => {
            return Err(Error::crypto_error(
                "AES-192 is not supported with GCM mode",
            ));
        }
        KeyLength::Aes256 => {
            let cipher = Aes256Gcm::new_from_slice(sek)
                .map_err(|e| Error::crypto_error(format!("invalid SEK: {e}")))?;
            cipher
                .encrypt_in_place(&nonce, header, &mut buffer)
                .map_err(|e| Error::crypto_error(format!("AES-GCM encrypt failed: {e}")))?;
        }
    }

    Ok(buffer)
}

/// Decrypt a payload with AES-GCM, verifying the auth tag.
///
/// `ciphertext_and_tag` contains the ciphertext followed by a 16-byte tag.
fn decrypt_payload_gcm(
    sek: &[u8],
    salt: &[u8; 16],
    packet_index: u32,
    header: &[u8; 16],
    ciphertext_and_tag: &[u8],
    key_length: KeyLength,
) -> Result<Vec<u8>, Error> {
    if ciphertext_and_tag.len() < GCM_TAG_LEN {
        return Err(Error::crypto_error("GCM payload too short for auth tag"));
    }

    let iv = build_gcm_iv(salt, packet_index);
    let nonce = Nonce::try_from(iv.as_slice())
        .map_err(|e| Error::crypto_error(format!("invalid GCM nonce: {e}")))?;
    let mut buffer = ciphertext_and_tag.to_vec();

    match key_length {
        KeyLength::Aes128 => {
            let cipher = Aes128Gcm::new_from_slice(sek)
                .map_err(|e| Error::crypto_error(format!("invalid SEK: {e}")))?;
            cipher
                .decrypt_in_place(&nonce, header, &mut buffer)
                .map_err(|_| Error::crypto_error("AES-GCM authentication failed"))?;
        }
        KeyLength::Aes192 => {
            return Err(Error::crypto_error(
                "AES-192 is not supported with GCM mode",
            ));
        }
        KeyLength::Aes256 => {
            let cipher = Aes256Gcm::new_from_slice(sek)
                .map_err(|e| Error::crypto_error(format!("invalid SEK: {e}")))?;
            cipher
                .decrypt_in_place(&nonce, header, &mut buffer)
                .map_err(|_| Error::crypto_error("AES-GCM authentication failed"))?;
        }
    }

    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_length() {
        assert_eq!(KeyLength::Aes128.len(), 16);
        assert_eq!(KeyLength::Aes192.len(), 24);
        assert_eq!(KeyLength::Aes256.len(), 32);
        assert_eq!(KeyLength::from_len(24), Some(KeyLength::Aes192));
        assert_eq!(KeyLength::from_encryption_field(3), Some(KeyLength::Aes192));
        assert_eq!(KeyLength::Aes192.to_encryption_field(), 3);
    }

    #[test]
    fn test_derive_kek() {
        let passphrase = "test_passphrase";
        let salt = [0u8; 16];
        let kek = derive_kek(passphrase, &salt, KeyLength::Aes128);
        assert_eq!(kek.len(), 16);
    }

    #[test]
    fn test_wrap_unwrap_sek() {
        let kek = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let sek = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];

        let wrapped = wrap_sek(&kek, &sek, KeyLength::Aes128)
            .expect("SEK のラップは有効な入力では成功する想定");
        let unwrapped = unwrap_sek(&kek, &wrapped, KeyLength::Aes128)
            .expect("ラップ済み SEK のアンラップは成功する想定");

        assert_eq!(sek, unwrapped);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let sek = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let salt = [0u8; 16];
        let packet_index = 12345u32;
        let original = b"Hello, SRT!".to_vec();

        let mut encrypted = original.clone();
        encrypt_payload_ctr(&sek, &salt, packet_index, &mut encrypted, KeyLength::Aes128)
            .expect("暗号化は有効な入力では成功する想定");

        // 暗号化されていることを確認
        assert_ne!(original, encrypted);

        // 復号化
        encrypt_payload_ctr(&sek, &salt, packet_index, &mut encrypted, KeyLength::Aes128)
            .expect("復号化は有効な入力では成功する想定");

        // 元に戻っていることを確認
        assert_eq!(original, encrypted);
    }

    #[test]
    fn test_km_refresh_state_transitions() {
        let salt = [0u8; 16];
        let sek = vec![0x42u8; 16];
        let mut crypto =
            CryptoContext::new_sender("passphrase", KeyLength::Aes128, salt, &sek, CipherMode::Ctr)
                .expect("Sender コンテキストの生成は成功する想定");

        // 初期状態
        assert_eq!(crypto.km_refresh_state(), KmRefreshState::Idle);
        assert_eq!(crypto.current_key(), KeyFlag::Even);

        // 事前通知開始
        let new_sek = vec![0x43u8; 16];
        let (new_key, wrapped) = crypto
            .start_pre_announce(&new_sek)
            .expect("事前通知は正常な鍵で成功する想定");
        assert_eq!(new_key, KeyFlag::Odd);
        assert!(!wrapped.is_empty());
        assert_eq!(crypto.km_refresh_state(), KmRefreshState::PreAnnounce);

        // 鍵切り替え
        crypto.switch_key();
        assert_eq!(crypto.current_key(), KeyFlag::Odd);
        assert_eq!(crypto.km_refresh_state(), KmRefreshState::PostAnnounce);

        // 古い鍵の廃棄
        crypto.decommission_old_key();
        assert_eq!(crypto.km_refresh_state(), KmRefreshState::Idle);
    }

    #[test]
    fn test_km_refresh_should_pre_announce() {
        let salt = [0u8; 16];
        let sek = vec![0x42u8; 16];
        let mut crypto =
            CryptoContext::new_sender("passphrase", KeyLength::Aes128, salt, &sek, CipherMode::Ctr)
                .expect("Sender コンテキストの生成は成功する想定");

        // 初期状態では事前通知不要
        assert!(!crypto.should_pre_announce());

        // 2^25 - 4000 パケット未満では事前通知不要
        crypto.encrypted_packet_count =
            CryptoContext::KM_REFRESH_PERIOD - CryptoContext::KM_PRE_ANNOUNCE_PERIOD - 1;
        assert!(!crypto.should_pre_announce());

        // 2^25 - 4000 パケット以上で事前通知が必要
        crypto.encrypted_packet_count =
            CryptoContext::KM_REFRESH_PERIOD - CryptoContext::KM_PRE_ANNOUNCE_PERIOD;
        assert!(crypto.should_pre_announce());
    }

    #[test]
    fn test_key_flag_kk_field_mapping() {
        assert_eq!(KeyFlag::Even.to_kk_field(), 0b01);
        assert_eq!(KeyFlag::Odd.to_kk_field(), 0b10);
        assert_eq!(KeyFlag::from_kk_field(0b01), Some(KeyFlag::Even));
        assert_eq!(KeyFlag::from_kk_field(0b10), Some(KeyFlag::Odd));
        assert_eq!(KeyFlag::from_kk_field(0b00), None);
        assert_eq!(KeyFlag::from_kk_field(0b11), None);
    }

    #[test]
    fn test_km_refresh_encrypt_with_key_switch() {
        let salt = [0u8; 16];
        let sek = vec![0x42u8; 16];
        let mut crypto =
            CryptoContext::new_sender("passphrase", KeyLength::Aes128, salt, &sek, CipherMode::Ctr)
                .expect("Sender コンテキストの生成は成功する想定");
        let mut payload1 = b"test data 1".to_vec();
        let mut payload2 = b"test data 2".to_vec();

        // 偶数キーで暗号化
        let key1 = crypto
            .encrypt(1, &mut payload1)
            .expect("暗号化は成功する想定");
        assert_eq!(key1, KeyFlag::Even);

        // 事前通知開始
        let new_sek = vec![0x43u8; 16];
        let _ = crypto
            .start_pre_announce(&new_sek)
            .expect("事前通知は正常な鍵で成功する想定");

        // まだ偶数キーで暗号化
        let key2 = crypto
            .encrypt(2, &mut payload2)
            .expect("暗号化は成功する想定");
        assert_eq!(key2, KeyFlag::Even);

        // 鍵切り替え
        crypto.switch_key();

        // 奇数キーで暗号化
        let mut payload3 = b"test data 3".to_vec();
        let key3 = crypto
            .encrypt(3, &mut payload3)
            .expect("暗号化は成功する想定");
        assert_eq!(key3, KeyFlag::Odd);
    }

    #[test]
    fn test_unwrap_sek_short_input() {
        let kek = vec![0x42u8; 16];

        assert!(unwrap_sek(&kek, &[], KeyLength::Aes128).is_err());
        assert!(unwrap_sek(&kek, &[0; 7], KeyLength::Aes128).is_err());
    }

    #[test]
    fn all_zero_stream_keys_are_rejected() {
        let error = CryptoContext::new_sender(
            "passphrase",
            KeyLength::Aes128,
            [0x42; 16],
            &[0; 16],
            CipherMode::Ctr,
        )
        .expect_err("known zero SEK must not be accepted");
        assert!(error.reason.contains("all zero"));

        let mut crypto = CryptoContext::new_sender(
            "passphrase",
            KeyLength::Aes128,
            [0x42; 16],
            &[0x24; 16],
            CipherMode::Ctr,
        )
        .expect("valid SEK");
        assert!(crypto.start_pre_announce(&[0; 16]).is_err());
    }

    #[test]
    fn gcm_encrypt_decrypt_roundtrip() {
        let sek = vec![0x42u8; 16];
        let salt = [0xABu8; 16];
        let header = [0u8; 16];
        let packet_index = 42u32;
        let original = b"Hello, AES-GCM SRT!";

        let encrypted = encrypt_payload_gcm(
            &sek,
            &salt,
            packet_index,
            &header,
            original,
            KeyLength::Aes128,
        )
        .unwrap();

        assert_eq!(encrypted.len(), original.len() + GCM_TAG_LEN);
        assert_ne!(&encrypted[..original.len()], original.as_slice());

        let decrypted = decrypt_payload_gcm(
            &sek,
            &salt,
            packet_index,
            &header,
            &encrypted,
            KeyLength::Aes128,
        )
        .unwrap();

        assert_eq!(decrypted, original);
    }

    #[test]
    fn gcm_rejects_tampered_ciphertext() {
        let sek = vec![0x42u8; 16];
        let salt = [0xABu8; 16];
        let header = [0u8; 16];
        let packet_index = 1u32;
        let original = b"authenticated data";

        let mut encrypted = encrypt_payload_gcm(
            &sek,
            &salt,
            packet_index,
            &header,
            original,
            KeyLength::Aes128,
        )
        .unwrap();

        encrypted[0] ^= 0xFF;

        let result = decrypt_payload_gcm(
            &sek,
            &salt,
            packet_index,
            &header,
            &encrypted,
            KeyLength::Aes128,
        );
        assert!(result.is_err());
    }

    #[test]
    fn gcm_rejects_tampered_header() {
        let sek = vec![0x42u8; 16];
        let salt = [0xABu8; 16];
        let header = [0u8; 16];
        let packet_index = 1u32;

        let encrypted = encrypt_payload_gcm(
            &sek,
            &salt,
            packet_index,
            &header,
            b"integrity check",
            KeyLength::Aes128,
        )
        .unwrap();

        let mut bad_header = header;
        bad_header[0] = 0xFF;

        let result = decrypt_payload_gcm(
            &sek,
            &salt,
            packet_index,
            &bad_header,
            &encrypted,
            KeyLength::Aes128,
        );
        assert!(result.is_err());
    }

    #[test]
    fn gcm_256_roundtrip() {
        let sek = vec![0x42u8; 32];
        let salt = [0xABu8; 16];
        let header = [1u8; 16];
        let packet_index = 999u32;
        let original = b"AES-256-GCM test";

        let encrypted = encrypt_payload_gcm(
            &sek,
            &salt,
            packet_index,
            &header,
            original,
            KeyLength::Aes256,
        )
        .unwrap();

        let decrypted = decrypt_payload_gcm(
            &sek,
            &salt,
            packet_index,
            &header,
            &encrypted,
            KeyLength::Aes256,
        )
        .unwrap();

        assert_eq!(decrypted, original);
    }

    #[test]
    fn gcm_rejects_aes192() {
        let result = CryptoContext::new_sender(
            "passphrase",
            KeyLength::Aes192,
            [0x42; 16],
            &[0x24; 24],
            CipherMode::Gcm,
        );
        assert!(result.is_err());
    }

    #[test]
    fn gcm_context_encrypt_decrypt() {
        let salt = [0xABu8; 16];
        let sek = vec![0x42u8; 16];
        let header = [0u8; 16];

        let mut sender =
            CryptoContext::new_sender("passphrase", KeyLength::Aes128, salt, &sek, CipherMode::Gcm)
                .unwrap();

        let wrapped = sender.wrap_sek(KeyFlag::Even).unwrap();
        let receiver = CryptoContext::new_receiver(
            "passphrase",
            salt,
            &wrapped,
            KeyFlag::Even,
            KeyLength::Aes128,
            CipherMode::Gcm,
        )
        .unwrap();

        let original = b"round-trip via context";
        let (key_flag, encrypted) = sender.encrypt_gcm(1, &header, original).unwrap();

        let decrypted = receiver
            .decrypt_gcm(1, key_flag, &header, &encrypted)
            .unwrap();

        assert_eq!(decrypted, original);
    }

    #[test]
    fn gcm_iv_differs_from_ctr_iv() {
        let salt = [0xABu8; 16];
        let pki = 42u32;

        let gcm_iv = build_gcm_iv(&salt, pki);
        assert_eq!(gcm_iv.len(), 12);

        let mut ctr_iv = [0u8; 16];
        ctr_iv[..14].copy_from_slice(&salt[..14]);
        let pi_bytes = pki.to_be_bytes();
        ctr_iv[10] ^= pi_bytes[0];
        ctr_iv[11] ^= pi_bytes[1];
        ctr_iv[12] ^= pi_bytes[2];
        ctr_iv[13] ^= pi_bytes[3];

        assert_ne!(gcm_iv[..], ctr_iv[..12]);
    }

    #[test]
    fn gcm_short_payload_rejected() {
        let sek = vec![0x42u8; 16];
        let salt = [0xABu8; 16];
        let header = [0u8; 16];

        let result = decrypt_payload_gcm(&sek, &salt, 1, &header, &[0u8; 15], KeyLength::Aes128);
        assert!(result.is_err());
    }
}
