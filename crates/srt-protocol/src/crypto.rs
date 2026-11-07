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

use bytes::BytesMut;
use std::fmt;

use aes::{Aes128, Aes192, Aes256};
use aes_gcm::aead::AeadInOut;
use aes_gcm::aead::consts::U12;
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit as GcmKeyInit, Nonce};
use aes_kw::{KwAes128, KwAes192, KwAes256};
#[cfg(test)]
use cipher::KeyIvInit;
use cipher::{InnerIvInit, StreamCipher};
use ctr::{Ctr128BE, CtrCore};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// Compile-time pin: cached expanded schedules must securely erase on drop.
// Requires `aes/zeroize` + `aes-gcm/zeroize` (which enables AES+GHASH wipe).
// If these bounds fail, the `CryptoContext::Drop` below regresses VENDOR 0050.
fn assert_key_caches_zeroize_on_drop<T: ZeroizeOnDrop>() {}
const _: fn() = || {
    assert_key_caches_zeroize_on_drop::<Aes128>();
    assert_key_caches_zeroize_on_drop::<Aes192>();
    assert_key_caches_zeroize_on_drop::<Aes256>();
    assert_key_caches_zeroize_on_drop::<Aes128Gcm>();
    assert_key_caches_zeroize_on_drop::<Aes256Gcm>();
};

use crate::error::Error;

type GcmNonce = Nonce<U12>;

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

/// The stream keys a key-material (KM) message carries.
///
/// DATA selects exactly one key ([`KeyFlag`]). A KM message may also carry
/// both (KK = 3): libsrt's refresh announces the current and the next SEK
/// together, wrapped as one blob with the even SEK first
/// (`haicrypt/hcrypt_ctx_tx.c`, `hcryptCtx_Tx_AsmKM`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KmKeySelection {
    /// The even key alone.
    Even = 0b01,
    /// The odd key alone.
    Odd = 0b10,
    /// Both keys, even first.
    Both = 0b11,
}

impl KmKeySelection {
    /// Get the selection from a KM message's KK field (its two low bits).
    pub fn from_kk_field(value: u8) -> Option<Self> {
        match value & 0b11 {
            0b01 => Some(Self::Even),
            0b10 => Some(Self::Odd),
            0b11 => Some(Self::Both),
            _ => None,
        }
    }

    /// Convert to a KK field value.
    pub fn to_kk_field(self) -> u8 {
        self as u8
    }

    /// The selected keys in wire order (even first).
    pub fn flags(self) -> &'static [KeyFlag] {
        match self {
            Self::Even => &[KeyFlag::Even],
            Self::Odd => &[KeyFlag::Odd],
            Self::Both => &[KeyFlag::Even, KeyFlag::Odd],
        }
    }

    /// How many SEKs the message wraps.
    pub fn key_count(self) -> usize {
        self.flags().len()
    }

    /// The single selected key, or `None` for [`Self::Both`].
    pub fn single(self) -> Option<KeyFlag> {
        match self {
            Self::Even => Some(KeyFlag::Even),
            Self::Odd => Some(KeyFlag::Odd),
            Self::Both => None,
        }
    }
}

impl From<KeyFlag> for KmKeySelection {
    fn from(flag: KeyFlag) -> Self {
        match flag {
            KeyFlag::Even => Self::Even,
            KeyFlag::Odd => Self::Odd,
        }
    }
}

/// What a peer's receive-key announcement did to the receive direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RxKeyUpdate {
    /// At least one selected slot now holds the announced key.
    Installed,
    /// Every selected slot already held the announced key under the same
    /// salt: a retransmission, answered without reinstalling anything.
    Unchanged,
}

/// Immutable per-datagram cryptographic reservation.
///
/// Reserved at packet admission so that delayed materialization into a
/// caller-supplied buffer cannot alter which key or counter boundary
/// the packet belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxCryptoStamp {
    pub key_flag: KeyFlag,
    pub cipher_mode: CipherMode,
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

/// Expanded AES schedule for CTR (IV still per-packet).
#[allow(clippy::large_enum_variant)] // round-key tables; boxing would defeat the cache
enum CachedCtr {
    Aes128(Aes128),
    Aes192(Aes192),
    Aes256(Aes256),
}

impl CachedCtr {
    fn from_sek(sek: &[u8], key_length: KeyLength) -> Result<Self, Error> {
        match key_length {
            KeyLength::Aes128 => {
                Ok(Self::Aes128(Aes128::new_from_slice(sek).map_err(|e| {
                    Error::crypto_error(format!("invalid SEK: {e}"))
                })?))
            }
            KeyLength::Aes192 => {
                Ok(Self::Aes192(Aes192::new_from_slice(sek).map_err(|e| {
                    Error::crypto_error(format!("invalid SEK: {e}"))
                })?))
            }
            KeyLength::Aes256 => {
                Ok(Self::Aes256(Aes256::new_from_slice(sek).map_err(|e| {
                    Error::crypto_error(format!("invalid SEK: {e}"))
                })?))
            }
        }
    }

    fn apply_keystream(&self, iv: &[u8; 16], payload: &mut [u8]) {
        match self {
            Self::Aes128(aes) => {
                let mut c = Ctr128BE::from_core(CtrCore::inner_iv_init(aes.clone(), iv.into()));
                c.apply_keystream(payload);
            }
            Self::Aes192(aes) => {
                let mut c = Ctr128BE::from_core(CtrCore::inner_iv_init(aes.clone(), iv.into()));
                c.apply_keystream(payload);
            }
            Self::Aes256(aes) => {
                let mut c = Ctr128BE::from_core(CtrCore::inner_iv_init(aes.clone(), iv.into()));
                c.apply_keystream(payload);
            }
        }
    }
}

/// Keyed GCM object (nonce still per-packet).
#[allow(clippy::large_enum_variant)] // AES-GCM state; boxing would defeat the cache
enum CachedGcm {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
}

impl CachedGcm {
    fn from_sek(sek: &[u8], key_length: KeyLength) -> Result<Self, Error> {
        match key_length {
            KeyLength::Aes128 => Ok(Self::Aes128(
                Aes128Gcm::new_from_slice(sek)
                    .map_err(|e| Error::crypto_error(format!("invalid SEK: {e}")))?,
            )),
            KeyLength::Aes192 => Err(Error::crypto_error(
                "AES-192 is not supported with GCM mode",
            )),
            KeyLength::Aes256 => Ok(Self::Aes256(
                Aes256Gcm::new_from_slice(sek)
                    .map_err(|e| Error::crypto_error(format!("invalid SEK: {e}")))?,
            )),
        }
    }

    fn encrypt_in_place(
        &self,
        nonce: &GcmNonce,
        aad: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<(), Error> {
        match self {
            Self::Aes128(c) => c
                .encrypt_in_place(nonce, aad, buffer)
                .map_err(|e| Error::crypto_error(format!("AES-GCM encrypt failed: {e}"))),
            Self::Aes256(c) => c
                .encrypt_in_place(nonce, aad, buffer)
                .map_err(|e| Error::crypto_error(format!("AES-GCM encrypt failed: {e}"))),
        }
    }

    fn encrypt_inout_detached(
        &self,
        nonce: &GcmNonce,
        aad: &[u8],
        payload: &mut [u8],
    ) -> Result<[u8; GCM_TAG_LEN], Error> {
        let tag = match self {
            Self::Aes128(c) => c
                .encrypt_inout_detached(nonce, aad, payload.into())
                .map_err(|e| Error::crypto_error(format!("AES-GCM encrypt failed: {e}")))?,
            Self::Aes256(c) => c
                .encrypt_inout_detached(nonce, aad, payload.into())
                .map_err(|e| Error::crypto_error(format!("AES-GCM encrypt failed: {e}")))?,
        };
        let mut out = [0u8; GCM_TAG_LEN];
        out.copy_from_slice(tag.as_slice());
        Ok(out)
    }

    fn decrypt_in_place(
        &self,
        nonce: &GcmNonce,
        aad: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<(), Error> {
        match self {
            Self::Aes128(c) => c
                .decrypt_in_place(nonce, aad, buffer)
                .map_err(|_| Error::crypto_error("AES-GCM authentication failed")),
            Self::Aes256(c) => c
                .decrypt_in_place(nonce, aad, buffer)
                .map_err(|_| Error::crypto_error("AES-GCM authentication failed")),
        }
    }

    fn decrypt_inout_detached(
        &self,
        nonce: &GcmNonce,
        aad: &[u8],
        payload: &mut [u8],
        tag: &[u8; GCM_TAG_LEN],
    ) -> Result<(), Error> {
        match self {
            Self::Aes128(c) => c
                .decrypt_inout_detached(nonce, aad, payload.into(), tag.into())
                .map_err(|_| Error::crypto_error("AES-GCM authentication failed")),
            Self::Aes256(c) => c
                .decrypt_inout_detached(nonce, aad, payload.into(), tag.into())
                .map_err(|_| Error::crypto_error("AES-GCM authentication failed")),
        }
    }
}

fn cache_ctr(sek: &[u8], key_length: KeyLength) -> Result<Option<CachedCtr>, Error> {
    if sek.iter().all(|b| *b == 0) {
        return Ok(None);
    }
    Ok(Some(CachedCtr::from_sek(sek, key_length)?))
}

fn cache_gcm(sek: &[u8], key_length: KeyLength) -> Result<Option<CachedGcm>, Error> {
    if sek.iter().all(|b| *b == 0) {
        return Ok(None);
    }
    Ok(Some(CachedGcm::from_sek(sek, key_length)?))
}

/// How many replaced receive keys are remembered to refuse their
/// reinstallation.
const RX_RETIRED_CAPACITY: usize = 4;

/// One receive-direction stream key: the SEK, the salt it was announced
/// under (the IV/nonce input for DATA under this selector), and its cached
/// schedule for the session's cipher mode.
struct RxKey {
    sek: Zeroizing<Vec<u8>>,
    salt: [u8; 16],
    ctr: Option<Box<CachedCtr>>,
    gcm: Option<Box<CachedGcm>>,
}

impl RxKey {
    fn new(
        sek: &[u8],
        salt: [u8; 16],
        key_length: KeyLength,
        cipher_mode: CipherMode,
    ) -> Result<Self, Error> {
        if sek.len() != key_length.len() {
            return Err(Error::crypto_error("invalid SEK length"));
        }
        if sek.iter().all(|byte| *byte == 0) {
            return Err(Error::crypto_error("unwrapped SEK must not be all zero"));
        }
        let (ctr, gcm) = match cipher_mode {
            CipherMode::Ctr => (cache_ctr(sek, key_length)?.map(Box::new), None),
            CipherMode::Gcm => (None, cache_gcm(sek, key_length)?.map(Box::new)),
        };
        Ok(Self {
            sek: Zeroizing::new(sek.to_vec()),
            salt,
            ctr,
            gcm,
        })
    }

    fn ctr(&self) -> Result<&CachedCtr, Error> {
        self.ctr
            .as_deref()
            .ok_or_else(|| Error::crypto_error("CTR key schedule missing for key flag"))
    }

    fn gcm(&self) -> Result<&CachedGcm, Error> {
        self.gcm
            .as_deref()
            .ok_or_else(|| Error::crypto_error("GCM key schedule missing for key flag"))
    }

    fn is(&self, sek: &[u8], salt: &[u8; 16]) -> bool {
        self.sek.as_slice() == sek && self.salt == *salt
    }
}

/// The KEK for a receive salt that differs from the transmit salt.
struct RxKek {
    salt: [u8; 16],
    kek: Zeroizing<Vec<u8>>,
}

/// Receive-direction key state, owned separately from the transmit keys.
///
/// A peer's KMREQ changes only this state; the local transmit selector,
/// keys and counters change only through local rotation. libsrt keeps the
/// same split (separate RX/TX HaiCrypt contexts, `srtcore/crypto.cpp`).
#[derive(Default)]
struct RxKeys {
    even: Option<RxKey>,
    odd: Option<RxKey>,
    /// The KEK derived for the latest announced salt other than the
    /// transmit salt, so a retransmission or a later refresh under the
    /// same salt costs no further PBKDF2 derivation.
    kek: Option<RxKek>,
    /// SEKs replaced in a receive slot, newest last in ring order.
    retired: [Option<Zeroizing<Vec<u8>>>; RX_RETIRED_CAPACITY],
    retired_next: usize,
}

impl RxKeys {
    fn slot(&self, flag: KeyFlag) -> Option<&RxKey> {
        match flag {
            KeyFlag::Even => self.even.as_ref(),
            KeyFlag::Odd => self.odd.as_ref(),
        }
    }

    fn slot_mut(&mut self, flag: KeyFlag) -> &mut Option<RxKey> {
        match flag {
            KeyFlag::Even => &mut self.even,
            KeyFlag::Odd => &mut self.odd,
        }
    }

    /// Whether `flag`'s slot already holds exactly this key and salt.
    fn holds(&self, flag: KeyFlag, sek: &[u8], salt: &[u8; 16]) -> bool {
        self.slot(flag).is_some_and(|key| key.is(sek, salt))
    }

    /// Whether a current slot holds `sek`. Called for a key that is not
    /// already in its announced slot under its announced salt, so a match
    /// means the announcement moves a known key to another selector or
    /// salt. The wrapped key authenticates neither.
    fn holds_elsewhere(&self, sek: &[u8]) -> bool {
        [&self.even, &self.odd]
            .into_iter()
            .flatten()
            .any(|key| key.sek.as_slice() == sek)
    }

    /// Whether `sek` was recently replaced in a receive slot.
    fn retired(&self, sek: &[u8]) -> bool {
        self.retired
            .iter()
            .flatten()
            .any(|retired| retired.as_slice() == sek)
    }

    /// Replace `flag`'s slot, remembering the key it held.
    fn replace(&mut self, flag: KeyFlag, key: RxKey) {
        if let Some(old) = self.slot_mut(flag).replace(key) {
            self.retired[self.retired_next] = Some(old.sek.clone());
            self.retired_next = (self.retired_next + 1) % RX_RETIRED_CAPACITY;
        }
    }
}

/// A comparable copy of every key-state field (test builds only).
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeyStateForTest {
    pub tx_even: Vec<u8>,
    pub tx_odd: Vec<u8>,
    pub tx_salt: [u8; 16],
    pub tx_current: KeyFlag,
    pub tx_next: Option<KeyFlag>,
    pub tx_refresh: KmRefreshState,
    pub tx_count: u64,
    pub rx_even: Option<(Vec<u8>, [u8; 16])>,
    pub rx_odd: Option<(Vec<u8>, [u8; 16])>,
    pub rx_kek_salt: Option<[u8; 16]>,
    pub rx_retired: Vec<Option<Vec<u8>>>,
}

/// Encryption context: the transmit keys (`kek` .. `gcm_odd`), which only
/// local rotation changes, and the receive keys (`rx`), which only the
/// peer's key material changes. The handshake's initial key seeds both
/// directions as independent copies.
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
    /// Expanded key schedules, boxed: ~4KB inline would blow the
    /// per-connection footprint budget (`delivery_packet_accounting_*`).
    /// Boxing costs one alloc per SEK install (handshake / KM refresh) and
    /// one deref per packet on already-hot data; the cache win is skipping
    /// key expansion, not avoiding the deref.
    ctr_even: Option<Box<CachedCtr>>,
    ctr_odd: Option<Box<CachedCtr>>,
    gcm_even: Option<Box<CachedGcm>>,
    gcm_odd: Option<Box<CachedGcm>>,
    /// The passphrase, kept to derive the KEK for a salt the peer announces
    /// after the handshake (libsrt keeps its secret for the same purpose).
    passphrase: Zeroizing<Vec<u8>>,
    /// Receive-direction keys.
    rx: RxKeys,
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
            .field("passphrase", &"[REDACTED]")
            .field("rx_even", &self.rx.even.as_ref().map(|_| "[REDACTED]"))
            .field("rx_odd", &self.rx.odd.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

// local patch (crates/srt-protocol/VENDOR.md, upstream issue
// 0050, open/unfixed at vendor commit 6779cdd): Vec<u8>'s default Drop only
// frees memory, it does not zero it, so key material could linger in freed
// heap memory. `decommission_old_key` already zeros explicitly on its own
// path; this covers the remaining case (the whole context dropped, e.g. on
// abnormal connection teardown).
// The boxed caches rely on `ZeroizeOnDrop` from `aes/zeroize` +
// `aes-gcm/zeroize` (pinned above): assigning `None` drops the expanded
// AES schedule / keyed GCM object, whose `Drop` wipes round keys + GHASH
// state. Per-packet CTR clones (`CachedCtr::apply_keystream`) are short-lived
// stack values holding a cloned schedule; dropping them runs the same
// zeroizing drop, so only the IV (public salt + packet index) remains.
impl Drop for CryptoContext {
    fn drop(&mut self) {
        self.kek.zeroize();
        self.sek_even.zeroize();
        self.sek_odd.zeroize();
        self.salt.zeroize();
        self.ctr_even = None;
        self.ctr_odd = None;
        self.gcm_even = None;
        self.gcm_odd = None;
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
    /// The key is installed as the even transmit key and, as an independent
    /// copy, as the even receive key: HSv5's initial key material is
    /// bidirectional.
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
        reject_unsupported_suite(key_length, cipher_mode)?;
        let kek = derive_kek(passphrase.as_bytes(), &salt, key_length);
        Self::seeded(
            passphrase,
            kek,
            salt,
            sek,
            KeyFlag::Even,
            key_length,
            cipher_mode,
        )
    }

    /// Build an encryption context from a passphrase and key material (receiver side).
    ///
    /// Unwraps the SEK with the KEK and installs it under `key_flag` as the
    /// receive key and, as an independent copy, as the transmit key (libsrt
    /// clones the responder's TX context from its RX context in HSv5).
    pub fn new_receiver(
        passphrase: &str,
        salt: [u8; 16],
        wrapped_sek: &[u8],
        key_flag: KeyFlag,
        key_length: KeyLength,
        cipher_mode: CipherMode,
    ) -> Result<Self, Error> {
        reject_unsupported_suite(key_length, cipher_mode)?;
        let kek = derive_kek(passphrase.as_bytes(), &salt, key_length);
        let sek = Zeroizing::new(unwrap_sek(&kek, wrapped_sek, key_length)?);
        if sek.iter().all(|byte| *byte == 0) {
            return Err(Error::crypto_error("unwrapped SEK must not be all zero"));
        }
        Self::seeded(
            passphrase,
            kek,
            salt,
            &sek,
            key_flag,
            key_length,
            cipher_mode,
        )
    }

    /// The initial context: `sek` under `key_flag` in both directions.
    fn seeded(
        passphrase: &str,
        kek: Vec<u8>,
        salt: [u8; 16],
        sek: &[u8],
        key_flag: KeyFlag,
        key_length: KeyLength,
        cipher_mode: CipherMode,
    ) -> Result<Self, Error> {
        let rx_key = RxKey::new(sek, salt, key_length, cipher_mode)?;
        // The other transmit slot is reserved for the next key (KM refresh
        // provides it). All-zero by construction: rejected as a key by
        // validation and skipped by cache_ctr/cache_gcm, so it can never
        // schedule.
        let (sek_even, sek_odd) = match key_flag {
            KeyFlag::Even => (sek.to_vec(), vec![u8::MIN; key_length.len()]),
            KeyFlag::Odd => (vec![u8::MIN; key_length.len()], sek.to_vec()),
        };
        let mut ctx = Self {
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
            ctr_even: None,
            ctr_odd: None,
            gcm_even: None,
            gcm_odd: None,
            passphrase: Zeroizing::new(passphrase.as_bytes().to_vec()),
            rx: RxKeys::default(),
        };
        *ctx.rx.slot_mut(key_flag) = Some(rx_key);
        ctx.rebuild_cipher_cache()?;
        Ok(ctx)
    }

    fn rebuild_cipher_cache(&mut self) -> Result<(), Error> {
        match self.cipher_mode {
            CipherMode::Ctr => {
                self.ctr_even = cache_ctr(&self.sek_even, self.key_length)?.map(Box::new);
                self.ctr_odd = cache_ctr(&self.sek_odd, self.key_length)?.map(Box::new);
                self.gcm_even = None;
                self.gcm_odd = None;
            }
            CipherMode::Gcm => {
                self.gcm_even = cache_gcm(&self.sek_even, self.key_length)?.map(Box::new);
                self.gcm_odd = cache_gcm(&self.sek_odd, self.key_length)?.map(Box::new);
                self.ctr_even = None;
                self.ctr_odd = None;
            }
        }
        Ok(())
    }

    fn cached_ctr(&self, key_flag: KeyFlag) -> Result<&CachedCtr, Error> {
        let slot = match key_flag {
            KeyFlag::Even => &self.ctr_even,
            KeyFlag::Odd => &self.ctr_odd,
        };
        slot.as_deref()
            .ok_or_else(|| Error::crypto_error("CTR key schedule missing for key flag"))
    }

    fn cached_gcm(&self, key_flag: KeyFlag) -> Result<&CachedGcm, Error> {
        let slot = match key_flag {
            KeyFlag::Even => &self.gcm_even,
            KeyFlag::Odd => &self.gcm_odd,
        };
        slot.as_deref()
            .ok_or_else(|| Error::crypto_error("GCM key schedule missing for key flag"))
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

    /// Whether `encrypt`/`encrypt_gcm_detached` would succeed for
    /// `current_key()` right now. The only realistic way either can fail is
    /// a not-yet-cached schedule for the current key flag (e.g. mid
    /// rotation, before the new key's cipher is installed) — the IV/nonce
    /// construction is infallible and a live packet payload never
    /// approaches AES-GCM's length limit. Checking this before committing
    /// any sender state turns that failure into an ordinary pre-admission
    /// rejection instead of a partially-admitted send.
    pub fn can_encrypt_current_key(&self) -> bool {
        match self.cipher_mode {
            CipherMode::Ctr => self.cached_ctr(self.current_key).is_ok(),
            CipherMode::Gcm => self.cached_gcm(self.current_key).is_ok(),
        }
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
        let key = self.current_key;
        let iv = build_ctr_iv(&self.salt, packet_index);
        self.cached_ctr(key)?.apply_keystream(&iv, payload);
        self.encrypted_packet_count += 1;
        Ok(key)
    }

    /// Encrypt data with GCM, returning ciphertext + 16-byte auth tag.
    ///
    /// `header` is the 16-byte SRT data packet header used as AAD; the
    /// retransmit flag must already be zeroed by the caller.
    pub fn encrypt_gcm(
        &mut self,
        packet_index: u32,
        header: &[u8; 16],
        mut payload: Vec<u8>,
    ) -> Result<(KeyFlag, Vec<u8>), Error> {
        let key = self.current_key;
        let iv = build_gcm_iv(&self.salt, packet_index);
        let nonce = Nonce::try_from(iv.as_slice())
            .map_err(|e| Error::crypto_error(format!("invalid GCM nonce: {e}")))?;
        self.cached_gcm(key)?
            .encrypt_in_place(&nonce, header, &mut payload)?;
        self.encrypted_packet_count += 1;
        Ok((key, payload))
    }

    /// Encrypt a payload slice with GCM in place, returning the 16-byte tag
    /// separately so the caller can append it to the wire buffer.
    pub fn encrypt_gcm_detached(
        &mut self,
        packet_index: u32,
        header: &[u8; 16],
        payload: &mut [u8],
    ) -> Result<(KeyFlag, [u8; GCM_TAG_LEN]), Error> {
        let key = self.current_key;
        let iv = build_gcm_iv(&self.salt, packet_index);
        let nonce = Nonce::try_from(iv.as_slice())
            .map_err(|e| Error::crypto_error(format!("invalid GCM nonce: {e}")))?;
        let tag = self
            .cached_gcm(key)?
            .encrypt_inout_detached(&nonce, header, payload)?;
        self.encrypted_packet_count += 1;
        Ok((key, tag))
    }

    /// Verify that the current key schedule is present and capable of encryption.
    pub fn verify_can_encrypt(&self) -> Result<(), Error> {
        match self.cipher_mode {
            CipherMode::Ctr => {
                let _ = self.cached_ctr(self.current_key)?;
            }
            CipherMode::Gcm => {
                let _ = self.cached_gcm(self.current_key)?;
            }
        }
        Ok(())
    }

    /// Reserve an immutable cryptographic stamp at packet admission.
    ///
    /// Validates that the active key schedule is present, increments the
    /// encrypted packet count exactly once, and captures the key flag and cipher mode.
    pub fn reserve_tx_stamp(&mut self) -> Result<TxCryptoStamp, Error> {
        self.verify_can_encrypt()?;
        let key_flag = self.current_key;
        let cipher_mode = self.cipher_mode;
        self.encrypted_packet_count += 1;
        Ok(TxCryptoStamp {
            key_flag,
            cipher_mode,
        })
    }

    /// Encrypt payload in place (CTR mode) using a pre-reserved stamp.
    /// Does not advance key counters again.
    pub fn encrypt_with_stamp(
        &self,
        stamp: TxCryptoStamp,
        packet_index: u32,
        payload: &mut [u8],
    ) -> Result<(), Error> {
        if stamp.cipher_mode != CipherMode::Ctr {
            return Err(Error::crypto_error(
                "encrypt_with_stamp called on non-CTR stamp; use encrypt_gcm_with_stamp for GCM",
            ));
        }
        let iv = build_ctr_iv(&self.salt, packet_index);
        self.cached_ctr(stamp.key_flag)?
            .apply_keystream(&iv, payload);
        Ok(())
    }

    /// Encrypt payload in place (GCM mode) using a pre-reserved stamp, returning
    /// the detached authentication tag. Does not advance key counters again.
    pub fn encrypt_gcm_with_stamp(
        &self,
        stamp: TxCryptoStamp,
        packet_index: u32,
        header: &[u8; 16],
        payload: &mut [u8],
    ) -> Result<[u8; GCM_TAG_LEN], Error> {
        if stamp.cipher_mode != CipherMode::Gcm {
            return Err(Error::crypto_error(
                "encrypt_gcm_with_stamp called on non-GCM stamp; use encrypt_with_stamp for CTR",
            ));
        }
        let iv = build_gcm_iv(&self.salt, packet_index);
        let nonce = Nonce::try_from(iv.as_slice())
            .map_err(|e| Error::crypto_error(format!("invalid GCM nonce: {e}")))?;
        let tag = self
            .cached_gcm(stamp.key_flag)?
            .encrypt_inout_detached(&nonce, header, payload)?;
        Ok(tag)
    }

    /// The receive key DATA under `key_flag` decrypts with.
    fn rx_key(&self, key_flag: KeyFlag) -> Result<&RxKey, Error> {
        self.rx
            .slot(key_flag)
            .ok_or_else(|| Error::crypto_error("no receive key for key flag"))
    }

    /// Decrypt data in place (CTR mode) with the receive key `key_flag`.
    pub fn decrypt(
        &self,
        packet_index: u32,
        key_flag: KeyFlag,
        payload: &mut [u8],
    ) -> Result<(), Error> {
        let key = self.rx_key(key_flag)?;
        let iv = build_ctr_iv(&key.salt, packet_index);
        key.ctr()?.apply_keystream(&iv, payload);
        Ok(())
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
        mut payload: Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        if payload.len() < GCM_TAG_LEN {
            return Err(Error::crypto_error("GCM payload too short for auth tag"));
        }
        let key = self.rx_key(key_flag)?;
        let iv = build_gcm_iv(&key.salt, packet_index);
        let nonce = Nonce::try_from(iv.as_slice())
            .map_err(|e| Error::crypto_error(format!("invalid GCM nonce: {e}")))?;
        key.gcm()?.decrypt_in_place(&nonce, header, &mut payload)?;
        Ok(payload)
    }

    /// Decrypt a GCM payload in place, stripping its authentication tag.
    ///
    /// The mutable `BytesMut` preserves the decoded packet allocation for
    /// delivery after authentication succeeds.
    pub fn decrypt_gcm_detached(
        &self,
        packet_index: u32,
        key_flag: KeyFlag,
        header: &[u8; 16],
        payload: &mut BytesMut,
    ) -> Result<(), Error> {
        if payload.len() < GCM_TAG_LEN {
            return Err(Error::crypto_error("GCM payload too short for auth tag"));
        }
        let key = self.rx_key(key_flag)?;
        let gcm = key.gcm()?;
        let tag_bytes = payload.split_off(payload.len() - GCM_TAG_LEN);
        let tag: [u8; GCM_TAG_LEN] = tag_bytes
            .as_ref()
            .try_into()
            .expect("GCM tag length was checked");
        let iv = build_gcm_iv(&key.salt, packet_index);
        let nonce = Nonce::try_from(iv.as_slice())
            .map_err(|error| Error::crypto_error(format!("invalid GCM nonce: {error}")))?;
        gcm.decrypt_inout_detached(&nonce, header, payload.as_mut(), &tag)?;
        Ok(())
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

    /// Force `current_key`'s cipher schedule out. No production path
    /// reaches this state -- transmit schedules are built only from
    /// validated local keys, and a peer's KM touches only the receive keys.
    /// Exists to let `srt_connection`'s own tests exercise
    /// `can_encrypt_current_key()` returning false deterministically.
    #[cfg(test)]
    pub(crate) fn drop_current_key_schedule_for_test(&mut self) {
        match self.current_key {
            KeyFlag::Even => {
                self.ctr_even = None;
                self.gcm_even = None;
            }
            KeyFlag::Odd => {
                self.ctr_odd = None;
                self.gcm_odd = None;
            }
        }
    }

    /// Every key-state field, for tests that require a rejected KM message
    /// to change nothing.
    #[cfg(test)]
    pub(crate) fn key_state_for_test(&self) -> KeyStateForTest {
        let rx = |key: &Option<RxKey>| key.as_ref().map(|key| (key.sek.to_vec(), key.salt));
        KeyStateForTest {
            tx_even: self.sek_even.clone(),
            tx_odd: self.sek_odd.clone(),
            tx_salt: self.salt,
            tx_current: self.current_key,
            tx_next: self.next_key,
            tx_refresh: self.km_refresh_state,
            tx_count: self.encrypted_packet_count,
            rx_even: rx(&self.rx.even),
            rx_odd: rx(&self.rx.odd),
            rx_kek_salt: self.rx.kek.as_ref().map(|rx_kek| rx_kek.salt),
            rx_retired: self
                .rx
                .retired
                .iter()
                .map(|key| key.as_ref().map(|key| key.to_vec()))
                .collect(),
        }
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

        // Commit the rotation-in-progress flags only after both fallible
        // steps succeed (S02): `next_key`/`km_refresh_state` reaching
        // `PreAnnounce` is itself what later lets `switch_key` (called
        // unconditionally once the packet count threshold is reached,
        // validating nothing) advance `current_key` onto this flag. Both
        // calls read only already-written state, so this reordering changes
        // nothing on the success path.
        self.rebuild_cipher_cache()?;
        let wrapped_sek = self.wrap_sek(new_key_flag)?;
        self.next_key = Some(new_key_flag);
        self.km_refresh_state = KmRefreshState::PreAnnounce;
        Ok((new_key_flag, wrapped_sek))
    }

    /// Discard an unacknowledged rotation after the connection has closed.
    ///
    /// A missing response does not establish that the peer lacks this key.
    /// Therefore callers must stop using the connection before discarding it.
    /// This zeroes the announced slot and drops its schedules; the current
    /// key remains untouched until the context is dropped.
    ///
    /// `key_flag` identifies the pending rotation. A flag that is no longer
    /// announced is ignored so a late call cannot discard a newer rotation.
    pub fn abandon_pre_announce(&mut self, key_flag: KeyFlag) {
        if self.next_key != Some(key_flag) {
            return;
        }
        self.next_key = None;
        self.km_refresh_state = KmRefreshState::Idle;
        match key_flag {
            KeyFlag::Even => {
                self.sek_even.zeroize();
                self.ctr_even = None;
                self.gcm_even = None;
            }
            KeyFlag::Odd => {
                self.sek_odd.zeroize();
                self.ctr_odd = None;
                self.gcm_odd = None;
            }
        }
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
            KeyFlag::Even => {
                self.sek_even.fill(0);
                self.ctr_even = None;
                self.gcm_even = None;
            }
            KeyFlag::Odd => {
                self.sek_odd.fill(0);
                self.ctr_odd = None;
                self.gcm_odd = None;
            }
        }
        self.km_refresh_state = KmRefreshState::Idle;
    }

    /// Whether installing keys announced under `salt` needs a fresh KEK
    /// derivation (one 2048-iteration PBKDF2-HMAC-SHA1 run): `salt` is
    /// neither the transmit salt nor the latest receive salt already
    /// derived. Callers bound how often a peer may cause one.
    pub fn needs_kek_derivation(&self, salt: &[u8; 16]) -> bool {
        self.cached_kek(salt).is_none()
    }

    fn cached_kek(&self, salt: &[u8; 16]) -> Option<&[u8]> {
        if *salt == self.salt {
            return Some(&self.kek);
        }
        self.rx
            .kek
            .as_ref()
            .filter(|rx_kek| rx_kek.salt == *salt)
            .map(|rx_kek| rx_kek.kek.as_slice())
    }

    /// Install the receive keys a peer's KMREQ announces under `salt`.
    ///
    /// As in libsrt (`haicrypt/hcrypt_ctx_rx.c`), a key may replace the one
    /// already held under its selector, with a new SEK and/or a new salt;
    /// a both-key message is one AES-KW blob of `2 * key_length` bytes, even
    /// SEK first. Only the receive slots change: the transmit selector,
    /// keys and counters belong to local rotation.
    ///
    /// Transactional: the KEK is derived and the whole blob unwrapped and
    /// validated before any slot changes, so a failure leaves every key and
    /// the cached KEK as they were. A slot that already holds the announced
    /// key under the same salt is left untouched; if that is every selected
    /// slot the result is [`RxKeyUpdate::Unchanged`] (a retransmission).
    ///
    /// Hardening beyond libsrt, which installs any well-wrapped key (the
    /// wrap authenticates neither selector nor salt): an announced key not
    /// already in its slot is refused if it is one of this side's transmit
    /// keys (reflected), is held under another selector or salt, or was
    /// one of the last four keys replaced in a receive slot.
    pub fn install_rx_keys(
        &mut self,
        keys: KmKeySelection,
        salt: [u8; 16],
        wrapped: &[u8],
    ) -> Result<RxKeyUpdate, Error> {
        let derived = self
            .needs_kek_derivation(&salt)
            .then(|| Zeroizing::new(derive_kek(&self.passphrase, &salt, self.key_length)));
        let kek = match &derived {
            Some(kek) => kek.as_slice(),
            None => self
                .cached_kek(&salt)
                .ok_or_else(|| Error::crypto_error("no KEK for the announced salt"))?,
        };
        // AES-KW accepts any multiple of eight bytes, so the unwrapped
        // length is the wire's claim until checked here.
        let plain = Zeroizing::new(unwrap_sek(kek, wrapped, self.key_length)?);
        let len = self.key_length.len();
        if plain.len() != keys.key_count() * len {
            return Err(Error::crypto_error("invalid SEK length"));
        }
        if keys == KmKeySelection::Both && plain[..len] == plain[len..] {
            return Err(Error::crypto_error(
                "KMREQ announces one SEK under both selectors",
            ));
        }
        let mut fresh: [Option<(KeyFlag, RxKey)>; 2] = [None, None];
        for (slot, (&flag, sek)) in fresh
            .iter_mut()
            .zip(keys.flags().iter().zip(plain.chunks_exact(len)))
        {
            if self.rx.holds(flag, sek, &salt) {
                continue;
            }
            self.check_announced_rx_key(sek)?;
            *slot = Some((
                flag,
                RxKey::new(sek, salt, self.key_length, self.cipher_mode)?,
            ));
        }
        if fresh.iter().all(Option::is_none) {
            return Ok(RxKeyUpdate::Unchanged);
        }
        for (flag, key) in fresh.into_iter().flatten() {
            self.rx.replace(flag, key);
        }
        if let Some(kek) = derived {
            self.rx.kek = Some(RxKek { salt, kek });
        }
        Ok(RxKeyUpdate::Installed)
    }

    /// The hardening checks for an announced key that is not already in
    /// its slot under its salt (see [`Self::install_rx_keys`]).
    fn check_announced_rx_key(&self, sek: &[u8]) -> Result<(), Error> {
        if self.is_transmit_key(sek) {
            return Err(Error::crypto_error("KMREQ reflects a local transmit key"));
        }
        if self.rx.holds_elsewhere(sek) {
            return Err(Error::crypto_error(
                "KMREQ moves a known key to another selector or salt",
            ));
        }
        if self.rx.retired(sek) {
            return Err(Error::crypto_error(
                "KMREQ reinstalls a retired receive key",
            ));
        }
        Ok(())
    }

    /// Whether `sek` is in a transmit slot: the active key or the one being
    /// announced. A decommissioned transmit key is zeroed, not remembered.
    fn is_transmit_key(&self, sek: &[u8]) -> bool {
        [&self.sek_even, &self.sek_odd]
            .into_iter()
            .any(|key| key.as_slice() == sek)
    }
}

fn reject_unsupported_suite(key_length: KeyLength, cipher_mode: CipherMode) -> Result<(), Error> {
    if cipher_mode == CipherMode::Gcm && key_length == KeyLength::Aes192 {
        return Err(Error::crypto_error(
            "AES-192 is not supported with GCM mode",
        ));
    }
    Ok(())
}

/// Derive the KEK via PBKDF2.
fn derive_kek(passphrase: &[u8], salt: &[u8; 16], key_length: KeyLength) -> Vec<u8> {
    let mut kek = vec![0u8; key_length.len()];
    // Use the salt's low 64 bits (8 bytes).
    let salt_lsb = &salt[8..16];
    pbkdf2_hmac::<Sha1>(passphrase, salt_lsb, PBKDF2_ITERATIONS, &mut kek);
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

/// Build the AES-CTR counter block from salt and packet index.
fn build_ctr_iv(salt: &[u8; 16], packet_index: u32) -> [u8; 16] {
    // Reference: draft-sharabayko-srt.md, "Encryption" section, "AES Counter" subsection.
    // Treating the 128-bit counter block as a big-endian 16-byte array:
    //   - bits 0-15 (bytes 14-15): block counter. 0 for each packet's first block; not XORed with the salt.
    //   - bits 16-47 (bytes 10-13): packet index
    //   - bits 48-127 (bytes 0-9): zero
    //   - the upper 112 bits (bytes 0-13) are XORed with IV = MSB(112, Salt) (= salt[0..14])
    // This matches the counter block construction in libsrt's haicrypt implementation.
    let mut iv: [u8; 16] = Default::default();
    iv[..14].copy_from_slice(&salt[..14]);
    let pi_bytes = packet_index.to_be_bytes();
    iv[10] ^= pi_bytes[0];
    iv[11] ^= pi_bytes[1];
    iv[12] ^= pi_bytes[2];
    iv[13] ^= pi_bytes[3];
    iv
}

/// Encrypt/decrypt a payload in place with AES-CTR.
#[cfg(test)]
fn encrypt_payload_ctr(
    sek: &[u8],
    salt: &[u8; 16],
    packet_index: u32,
    payload: &mut [u8],
    key_length: KeyLength,
) -> Result<(), Error> {
    let iv = build_ctr_iv(salt, packet_index);

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
#[cfg(test)]
fn encrypt_payload_gcm(
    sek: &[u8],
    salt: &[u8; 16],
    packet_index: u32,
    header: &[u8; 16],
    mut buffer: Vec<u8>,
    key_length: KeyLength,
) -> Result<Vec<u8>, Error> {
    let iv = build_gcm_iv(salt, packet_index);
    let nonce = Nonce::try_from(iv.as_slice())
        .map_err(|e| Error::crypto_error(format!("invalid GCM nonce: {e}")))?;

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
#[cfg(test)]
fn decrypt_payload_gcm(
    sek: &[u8],
    salt: &[u8; 16],
    packet_index: u32,
    header: &[u8; 16],
    mut buffer: Vec<u8>,
    key_length: KeyLength,
) -> Result<Vec<u8>, Error> {
    if buffer.len() < GCM_TAG_LEN {
        return Err(Error::crypto_error("GCM payload too short for auth tag"));
    }

    let iv = build_gcm_iv(salt, packet_index);
    let nonce = Nonce::try_from(iv.as_slice())
        .map_err(|e| Error::crypto_error(format!("invalid GCM nonce: {e}")))?;

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
        let kek = derive_kek(passphrase.as_bytes(), &salt, KeyLength::Aes128);
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
            original.to_vec(),
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
            encrypted,
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
            original.to_vec(),
            KeyLength::Aes128,
        )
        .unwrap();

        encrypted[0] ^= 0xFF;

        let result = decrypt_payload_gcm(
            &sek,
            &salt,
            packet_index,
            &header,
            encrypted,
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
            b"integrity check".to_vec(),
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
            encrypted,
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
            original.to_vec(),
            KeyLength::Aes256,
        )
        .unwrap();

        let decrypted = decrypt_payload_gcm(
            &sek,
            &salt,
            packet_index,
            &header,
            encrypted,
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

    /// S02: a peer's KM refresh carrying a wrapped key of the wrong length
    /// unwraps fine (AES-KW only requires a multiple of 8 bytes) but is
    /// the wrong size for the selected keys. `install_rx_keys` rejects it
    /// before touching any slot: every key, transmit and receive, stays as
    /// it was.
    #[test]
    fn install_rx_keys_rejects_wrong_length_key_without_touching_keys() {
        let passphrase = "passphrase";
        let salt = [0x42; 16];
        let mut crypto = CryptoContext::new_sender(
            passphrase,
            KeyLength::Aes128,
            salt,
            &[0x24; 16],
            CipherMode::Ctr,
        )
        .expect("valid sender context");
        let before = crypto.key_state_for_test();

        let kek = derive_kek(passphrase.as_bytes(), &salt, KeyLength::Aes128);
        // A 24-byte plaintext wraps to a 32-byte blob -- valid AES-KW, but
        // the wrong length for one AES-128 key (and for two).
        let wrong_length_wrapped =
            wrap_sek(&kek, &[0x11; 24], KeyLength::Aes128).expect("valid AES-KW wrap");
        for keys in [KmKeySelection::Odd, KmKeySelection::Both] {
            let error = crypto
                .install_rx_keys(keys, salt, &wrong_length_wrapped)
                .expect_err("wrong-length key must be rejected");
            assert!(error.reason.contains("invalid SEK"), "{}", error.reason);
            assert_eq!(crypto.key_state_for_test(), before);
        }
        assert!(crypto.can_encrypt_current_key());
    }

    /// A both-key KM is one AES-KW blob of the even then the odd SEK; it
    /// installs both receive slots and leaves the transmit keys alone.
    #[test]
    fn install_rx_keys_installs_both_receive_slots_only() {
        let passphrase = "passphrase";
        let salt = [0x42; 16];
        let mut crypto = CryptoContext::new_sender(
            passphrase,
            KeyLength::Aes128,
            salt,
            &[0x24; 16],
            CipherMode::Ctr,
        )
        .expect("valid sender context");
        let before = crypto.key_state_for_test();
        let kek = derive_kek(passphrase.as_bytes(), &salt, KeyLength::Aes128);
        let both = [[0x31; 16], [0x32; 16]].concat();
        let wrapped = wrap_sek(&kek, &both, KeyLength::Aes128).expect("valid AES-KW wrap");

        let update = crypto
            .install_rx_keys(KmKeySelection::Both, salt, &wrapped)
            .expect("valid both-key announcement");
        assert_eq!(update, RxKeyUpdate::Installed);
        let after = crypto.key_state_for_test();
        assert_eq!(after.rx_even, Some((vec![0x31; 16], salt)));
        assert_eq!(after.rx_odd, Some((vec![0x32; 16], salt)));
        assert_eq!(
            (
                &after.tx_even,
                &after.tx_odd,
                after.tx_current,
                after.tx_count
            ),
            (
                &before.tx_even,
                &before.tx_odd,
                before.tx_current,
                before.tx_count
            ),
            "a receive announcement never touches the transmit keys"
        );
        let repeat = crypto
            .install_rx_keys(KmKeySelection::Both, salt, &wrapped)
            .expect("a retransmission is accepted");
        assert_eq!(repeat, RxKeyUpdate::Unchanged);
        assert_eq!(crypto.key_state_for_test(), after);
    }

    /// S02: `start_pre_announce` must not commit the rotation as
    /// in-progress (`next_key`/`km_refresh_state`) before its own fallible
    /// steps succeed. The new key here is itself valid (start_pre_announce
    /// already validates its length/non-zero up front); the failure comes
    /// from `rebuild_cipher_cache` rebuilding *both* flags unconditionally,
    /// so a corrupted currently-active SEK (simulated directly -- no
    /// production path leaves this state: a peer's KM installs only receive
    /// keys) still fails the call, and that failure must
    /// not leave rotation looking like it started.
    #[test]
    fn start_pre_announce_does_not_commit_rotation_state_on_cache_rebuild_failure() {
        let mut crypto = CryptoContext::new_sender(
            "passphrase",
            KeyLength::Aes128,
            [0x11; 16],
            &[0x22; 16],
            CipherMode::Ctr,
        )
        .expect("valid sender context");
        assert!(crypto.next_key.is_none());
        assert_eq!(crypto.km_refresh_state, KmRefreshState::Idle);

        crypto.sek_even = vec![0x11; 4]; // wrong length for Aes128 (16 bytes)

        let error = crypto
            .start_pre_announce(&[0x33; 16])
            .expect_err("rebuild fails on the corrupted active key");
        assert!(error.reason.contains("invalid SEK"), "{}", error.reason);
        assert!(
            crypto.next_key.is_none(),
            "rotation must not appear in-progress after a failed pre-announce"
        );
        assert_eq!(crypto.km_refresh_state, KmRefreshState::Idle);
    }

    /// S06 (revalidation, not a fix): `#[derive(Debug)]` would print raw
    /// key/salt bytes; the manual `Debug` impl must redact them instead.
    /// Checks the actual formatted output, not just that the impl exists.
    #[test]
    fn debug_output_redacts_key_material() {
        let salt = [0x11u8; 16];
        let sek = [0x22u8; 16];
        let crypto =
            CryptoContext::new_sender("passphrase", KeyLength::Aes128, salt, &sek, CipherMode::Ctr)
                .expect("valid sender context");
        let debug = format!("{crypto:?}");
        assert!(debug.contains("[REDACTED]"));
        // The bytes above never appear as decimal in an unrelated field
        // (encrypted_packet_count is 0, current_key/key_length/cipher_mode
        // are short enums) -- so their presence would only come from a key
        // field slipping through unredacted.
        assert!(
            !debug.contains("17, 17, 17"),
            "salt byte 0x11 leaked: {debug}"
        );
        assert!(
            !debug.contains("34, 34, 34"),
            "sek byte 0x22 leaked: {debug}"
        );
    }

    /// S06 (revalidation, not a fix): once the old key is decommissioned,
    /// its SEK bytes are actually zeroed in place (`fill(0)`, not merely
    /// dropped) -- checked directly since the field is still allocated, not
    /// freed, so this isn't the freed-memory read the card rules out.
    #[test]
    fn decommission_old_key_zeroizes_the_retired_sek() {
        let salt = [0xAAu8; 16];
        let mut crypto = CryptoContext::new_sender(
            "passphrase",
            KeyLength::Aes128,
            salt,
            &[0x33; 16],
            CipherMode::Ctr,
        )
        .expect("valid sender context");
        assert_eq!(crypto.current_key(), KeyFlag::Even);
        assert!(
            crypto.sek_odd.iter().all(|b| *b == 0),
            "unused odd slot starts zero"
        );

        crypto
            .start_pre_announce(&[0x44; 16])
            .expect("valid new key");
        assert!(
            crypto.sek_odd.iter().any(|b| *b != 0),
            "the new odd key is now live"
        );
        crypto.switch_key();
        assert_eq!(crypto.current_key(), KeyFlag::Odd);

        crypto.decommission_old_key();
        assert!(
            crypto.sek_even.iter().all(|b| *b == 0),
            "the retired even key must be zeroed, not merely superseded"
        );
        assert!(crypto.ctr_even.is_none(), "retired schedule is dropped too");
        assert!(
            crypto.can_encrypt_current_key(),
            "the new key remains usable"
        );
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
        let (key_flag, encrypted) = sender.encrypt_gcm(1, &header, original.to_vec()).unwrap();

        let decrypted = receiver
            .decrypt_gcm(1, key_flag, &header, encrypted)
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

        let result = decrypt_payload_gcm(&sek, &salt, 1, &header, vec![0u8; 15], KeyLength::Aes128);
        assert!(result.is_err());
    }

    /// Cached CTR schedule matches fresh key setup, byte for byte, across key
    /// lengths, payload sizes and sequence values including wrap-adjacent
    /// indices. This deterministic equivalence is the correctness gate for the
    /// schedule cache. Per-packet cost of the cached production path is tracked
    /// by `benches/core_packet_loop.rs` (`bench_encrypted*`); no production
    /// path performs per-packet fresh key expansion (schedules are built once
    /// per SEK install), so no timing assertion lives in unit tests.
    #[test]
    fn ctr_key_cache_matches_uncached() {
        let salt: [u8; 16] = std::array::from_fn(|i| (i as u8).wrapping_add(0xA0));
        for key_length in [KeyLength::Aes128, KeyLength::Aes192, KeyLength::Aes256] {
            let sek: Vec<u8> = (1..=key_length.len() as u8)
                .map(|b| b.wrapping_mul(7))
                .collect();
            let mut ctx =
                CryptoContext::new_sender("passphrase", key_length, salt, &sek, CipherMode::Ctr)
                    .unwrap();
            for size in [0usize, 1, 1316] {
                let payload = vec![0x5Au8; size];
                for packet_seq in [0u32, 1, 7, 1023, u32::MAX - 1, u32::MAX] {
                    let mut uncached = payload.clone();
                    encrypt_payload_ctr(&sek, &salt, packet_seq, &mut uncached, key_length)
                        .unwrap();
                    let mut cached = payload.clone();
                    ctx.encrypt(packet_seq, &mut cached).unwrap();
                    assert_eq!(
                        cached, uncached,
                        "{key_length:?}/size {size}/packet {packet_seq} diverged"
                    );
                }
            }
        }
    }
}
