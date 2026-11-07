//! Model-based property test of SRT key-material (KM) handling.
//!
//! A connected srt-rs listener (the system under test) faces a scripted
//! peer that follows libsrt's KM rules, plus a real srt-rs caller that
//! receives the listener's own DATA and key rotations. Each case runs a
//! generated sequence of steps:
//!
//! * the handshake KM exchange (initial key, KMRSP echo);
//! * peer KMREQs, single-key and both-key (KK = 3, even SEK first): fresh
//!   keys under the session salt or a new salt, identical repeats, replays
//!   of earlier requests (stale and retired keys), malformed requests
//!   (corrupt wrap, other key length or cipher, key-count mismatch, one SEK
//!   twice), reflections of the listener's own transmit keys, and known
//!   keys moved to another selector or salt;
//! * peer DATA under either selector;
//! * the listener's own rotations, acknowledged through the real caller,
//!   answered by mismatched, stale or error KMRSPs, retried by the timer,
//!   and switched at the refresh boundary.
//!
//! After every step the observable outcome -- KMRSP echoed or not, which
//! key decrypts DATA under each selector, which selector the listener's
//! own DATA uses, which KMREQ a retry resends, whether the session closes
//! -- is compared with [`Model`]: libsrt 1.5.7's receive rules
//! (`haicrypt/hcrypt_ctx_rx.c`: a valid KMREQ installs its keys into the
//! receive context only, may replace the key under its selector with a new
//! SEK and/or salt, and is echoed; another key length or cipher is
//! refused) with the srt-rs overrides named in [`srt_rs`].
//!
//! Audit properties covered: (1) initial KM installs the caller's key and
//! is echoed, wrong or missing secrets fail the handshake; (2) an identical
//! current KMREQ is echoed without reinstalling; (3) a fresh same-selector
//! replacement, including a new salt, is installed in the receive
//! direction only; (4) a both-key KMREQ installs both slots atomically,
//! even first; (5) corrupt wraps, size mismatches, cipher or key-length
//! changes change nothing; (6) peer KMREQs and peer key switches never
//! change the local transmit key; (7) only the exact pending request's
//! KMRSP acknowledges a rotation, and duplicate, mismatched or error
//! responses neither acknowledge nor regenerate it; (8) an unanswered
//! KMREQ is retried byte-identically; (9) reflected, retired and moved
//! keys are refused; (10) a failed new-salt derivation keeps every key,
//! and derivations are bounded; (11) replacing one receive slot keeps the
//! other slot and the transmit direction working; (12) failure states use
//! the little-endian KM-state word and GCM DATA uses the 1.5.4 AAD layout.
//!
//! Deterministic: fixed RNG seed, no failure persistence.

use std::collections::{HashMap, VecDeque};

use aes_gcm::aead::AeadInOut;
use aes_gcm::aead::consts::U12;
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use aes_kw::{KwAes128, KwAes192, KwAes256};
use cipher::{KeyInit, KeyIvInit, StreamCipher};
use pbkdf2::pbkdf2_hmac;
use proptest::prelude::*;
use proptest::sample::Index;
use proptest::test_runner::{RngAlgorithm, RngSeed, TestCaseResult};
use sha1::Sha1;
use srt_proto::crypto::{CipherMode, KeyFlag, KeyLength, KmKeySelection};
use srt_proto::handshake::{HandshakePacket, KmError};
use srt_proto::wire::{ControlPacket, ControlType, DataPacket, SrtPacket};
use srt_proto::{
    Bytes, ConnectionEvent, ConnectionOptions, ConnectionOutput, ConnectionState, SrtConnection,
    TimerId, Timestamp,
};

const PASSPHRASE: &str = "km-model-passphrase";
const SESSION_SALT: [u8; 16] = [0x24; 16];
const INITIAL_SEK: u8 = 0x5A;
const SRT_CMD_KMREQ: u16 = 3;
const SRT_CMD_KMRSP: u16 = 4;
/// Time between ordinary steps.
const STEP_MICROS: u64 = 1_000;
/// How far behind the listener's clock peer DATA is stamped, so that with
/// a zero TSBPD delay it is due on arrival.
const PEER_CLOCK_LEAD_MICROS: u64 = 50_000;
/// libsrt's and srt-rs's packet count at which the sender switches keys.
const KM_REFRESH_PERIOD: u64 = 1 << 25;

/// srt-rs policies that override libsrt, named so every expectation that
/// depends on one says so.
mod srt_rs {
    /// HARDENING: an announced key not already in its slot is refused if it
    /// is a local transmit key, is held under another selector or salt, or
    /// is one of this many keys most recently replaced in a receive slot.
    /// One SEK under both selectors is refused. (libsrt installs any key
    /// that unwraps.)
    pub const RETIRED_RECEIVE_KEYS: usize = 4;
    /// HARDENING: fresh-salt KEK derivations available at once per
    /// connection, and the interval that restores one.
    pub const DERIVATION_BURST: u64 = 2;
    pub const DERIVATION_REFILL_MICROS: u64 = 1_000_000;
    /// RETRY: an unanswered KMREQ is resent every second, this many times,
    /// then the connection closes. (libsrt: 1.5 x SRTT, ten times.)
    pub const RETRY_INTERVAL_MICROS: u64 = 1_000_000;
    pub const RETRIES: u8 = 4;
    // ACK_GATED_SWITCH: the sender switches to its announced key only after
    // the matching KMRSP (libsrt switches on its packet schedule); see
    // `Model::after_local_send`.
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Suite {
    mode: CipherMode,
    key_length: KeyLength,
}

/// One KMREQ as the scripted peer builds it.
#[derive(Clone, Debug)]
struct Announcement {
    keys: KmKeySelection,
    salt: [u8; 16],
    /// The SEKs in wrap order (even first).
    seks: Vec<Vec<u8>>,
    suite: Suite,
    corrupt: bool,
}

#[derive(Clone, Copy, Debug)]
enum Defect {
    CorruptWrap,
    OtherKeyLength,
    OtherCipher,
    KeyCountMismatch,
    SameKeyTwice,
}

#[derive(Clone, Debug)]
enum Request {
    Fresh {
        keys: KmKeySelection,
        salt: u8,
        seeds: [u8; 2],
    },
    /// The last request the listener echoed, again.
    Duplicate,
    /// Any earlier peer request, again.
    Replay(Index),
    /// One of the listener's own transmit keys (current or announced).
    Reflect {
        next: bool,
        flag: KeyFlag,
        salt: u8,
    },
    /// A key the listener receives under, announced elsewhere.
    MoveKnown {
        from: KeyFlag,
        to: KeyFlag,
        salt: u8,
    },
    Malformed {
        defect: Defect,
        salt: u8,
        seed: u8,
    },
}

#[derive(Clone, Copy, Debug)]
enum Response {
    Mismatched,
    ErrorLittleEndian,
    ErrorBigEndian,
    Stale,
}

#[derive(Clone, Debug)]
enum Step {
    Kmreq(Request),
    PeerData(KeyFlag),
    LocalRotate,
    AckRotation,
    Kmrsp(Response),
    /// This many times: past the retry interval, then the ACK timer.
    Ticks(u8),
    /// Past the derivation refill interval.
    Wait,
    SwitchThreshold,
    LocalData,
}

fn ts(micros: u64) -> Timestamp {
    Timestamp::from_micros(micros)
}

fn slot(flag: KeyFlag) -> usize {
    match flag {
        KeyFlag::Even => 0,
        KeyFlag::Odd => 1,
    }
}

fn salt_for(choice: u8) -> [u8; 16] {
    match choice {
        0 => SESSION_SALT,
        n => [0xC0 + n; 16],
    }
}

fn peer_key(seed: u8, len: usize) -> Vec<u8> {
    vec![0x10 + seed % 24; len]
}

// ============================================================================
// Model
// ============================================================================

#[derive(Clone, Debug)]
struct Pending {
    body: Vec<u8>,
    retries_left: u8,
}

enum Retry {
    Nothing,
    Resend(Vec<u8>),
    Close,
}

#[derive(Debug)]
struct Model {
    suite: Suite,
    rx: [Option<(Vec<u8>, [u8; 16])>; 2],
    retired: VecDeque<Vec<u8>>,
    rx_kek_salt: Option<[u8; 16]>,
    tokens: u64,
    tokens_at: Option<u64>,
    tx: [Vec<u8>; 2],
    tx_current: KeyFlag,
    tx_next: Option<KeyFlag>,
    pending: Option<Pending>,
    at_threshold: bool,
    closed: bool,
}

impl Model {
    /// After the handshake: the caller's initial even key, in both
    /// directions (libsrt clones the responder's transmit context from
    /// the received KM).
    fn new(suite: Suite) -> Self {
        let len = suite.key_length.len();
        let initial = vec![INITIAL_SEK; len];
        Self {
            suite,
            rx: [Some((initial.clone(), SESSION_SALT)), None],
            retired: VecDeque::new(),
            rx_kek_salt: None,
            tokens: srt_rs::DERIVATION_BURST,
            tokens_at: None,
            tx: [initial, vec![0; len]],
            tx_current: KeyFlag::Even,
            tx_next: None,
            pending: None,
            at_threshold: false,
            closed: false,
        }
    }

    fn needs_derivation(&self, salt: &[u8; 16]) -> bool {
        *salt != SESSION_SALT && self.rx_kek_salt != Some(*salt)
    }

    /// HARDENING: the derivation token bucket.
    fn take_token(&mut self, now: u64) -> bool {
        let at = *self.tokens_at.get_or_insert(now);
        let restored = (now - at) / srt_rs::DERIVATION_REFILL_MICROS;
        if restored > 0 {
            self.tokens = (self.tokens + restored).min(srt_rs::DERIVATION_BURST);
            self.tokens_at = Some(at + restored * srt_rs::DERIVATION_REFILL_MICROS);
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }

    /// Checks before any key is looked at: shape, suite (libsrt), the
    /// derivation budget (srt-rs), unwrap and one-SEK-twice.
    fn admits(&mut self, a: &Announcement, now: u64) -> bool {
        let len = a.suite.key_length.len();
        if a.seks.len() != a.keys.key_count() || a.seks.iter().any(|sek| sek.len() != len) {
            return false;
        }
        if a.suite != self.suite {
            return false;
        }
        if self.needs_derivation(&a.salt) && !self.take_token(now) {
            return false;
        }
        !(a.corrupt || (a.keys == KmKeySelection::Both && a.seks[0] == a.seks[1]))
    }

    /// HARDENING: reflected, moved or retired key.
    fn refuses(&self, sek: &[u8]) -> bool {
        self.tx.iter().any(|key| key == sek)
            || self.rx.iter().flatten().any(|(key, _)| key == sek)
            || self.retired.iter().any(|key| key == sek)
    }

    /// The keys to install, or `None` when one is refused.
    fn fresh_keys(&self, a: &Announcement) -> Option<Vec<(KeyFlag, Vec<u8>)>> {
        let mut fresh = Vec::new();
        for (&flag, sek) in a.keys.flags().iter().zip(&a.seks) {
            if self.rx[slot(flag)].as_ref() == Some(&(sek.clone(), a.salt)) {
                continue;
            }
            if self.refuses(sek) {
                return None;
            }
            fresh.push((flag, sek.clone()));
        }
        Some(fresh)
    }

    /// Apply a peer KMREQ; whether the listener must echo it.
    fn announce(&mut self, a: &Announcement, now: u64) -> bool {
        let derived = self.needs_derivation(&a.salt);
        if !self.admits(a, now) {
            return false;
        }
        let Some(fresh) = self.fresh_keys(a) else {
            return false;
        };
        if !fresh.is_empty() && derived {
            self.rx_kek_salt = Some(a.salt);
        }
        for (flag, sek) in fresh {
            if let Some((old, _)) = self.rx[slot(flag)].replace((sek, a.salt)) {
                self.retired.push_back(old);
                if self.retired.len() > srt_rs::RETIRED_RECEIVE_KEYS {
                    self.retired.pop_front();
                }
            }
        }
        true
    }

    fn rotate(&mut self, flag: KeyFlag, sek: Vec<u8>, body: Vec<u8>) {
        self.tx[slot(flag)] = sek;
        self.tx_next = Some(flag);
        self.pending = Some(Pending {
            body,
            retries_left: srt_rs::RETRIES,
        });
    }

    fn retry(&mut self) -> Retry {
        let Some(pending) = self.pending.as_mut() else {
            return Retry::Nothing;
        };
        if pending.retries_left > 0 {
            pending.retries_left -= 1;
            return Retry::Resend(pending.body.clone());
        }
        self.closed = true;
        Retry::Close
    }

    /// ACK_GATED_SWITCH: after a local send at the refresh boundary, the
    /// sender switches only if the announced key was acknowledged.
    fn after_local_send(&mut self) {
        if !self.at_threshold || self.pending.is_some() {
            return;
        }
        if let Some(next) = self.tx_next.take() {
            self.tx_current = next;
            self.at_threshold = false;
        }
    }
}

// ============================================================================
// Independent libsrt-shaped fixtures
// ============================================================================

fn derive_kek(salt: &[u8; 16], len: usize) -> Vec<u8> {
    let mut kek = vec![0; len];
    pbkdf2_hmac::<Sha1>(PASSPHRASE.as_bytes(), &salt[8..], 2048, &mut kek);
    kek
}

fn wrap(kek: &[u8], plain: &[u8]) -> Vec<u8> {
    let mut wrapped = vec![0; plain.len() + 8];
    let wrapped_ok = match kek.len() {
        16 => KwAes128::new_from_slice(kek)
            .expect("AES-128 KEK")
            .wrap_key(plain, &mut wrapped)
            .is_ok(),
        24 => KwAes192::new_from_slice(kek)
            .expect("AES-192 KEK")
            .wrap_key(plain, &mut wrapped)
            .is_ok(),
        _ => KwAes256::new_from_slice(kek)
            .expect("AES-256 KEK")
            .wrap_key(plain, &mut wrapped)
            .is_ok(),
    };
    assert!(wrapped_ok, "the fixture wraps its SEKs");
    wrapped
}

/// libsrt's KM message (`haicrypt/hcrypt_km.h`): version/type, KK, KEKI,
/// cipher, auth, SE, salt and key lengths in words, salt, wrapped keys.
fn km_body(a: &Announcement, kek: &[u8]) -> Vec<u8> {
    let mut wrapped = wrap(kek, &a.seks.concat());
    if a.corrupt {
        let last = wrapped.len() - 1;
        wrapped[last] ^= 0x01;
    }
    let (cipher, auth) = match a.suite.mode {
        CipherMode::Ctr => (2, 0),
        CipherMode::Gcm => (4, 1),
    };
    let key_words = u8::try_from(a.suite.key_length.len() / 4).expect("key words");
    let mut body = vec![
        0x12,
        0x20,
        0x29,
        a.keys.to_kk_field(),
        0,
        0,
        0,
        0,
        cipher,
        auth,
        2,
        0,
        0,
        0,
        4,
        key_words,
    ];
    body.extend_from_slice(&a.salt);
    body.extend_from_slice(&wrapped);
    body
}

/// `hcrypt_SetCtrIV`: packet index at bytes 10..14, XOR the salt's first
/// 112 bits.
fn ctr_iv(salt: &[u8; 16], index: u32) -> [u8; 16] {
    let mut iv = [0; 16];
    iv[..14].copy_from_slice(&salt[..14]);
    for (byte, pki) in iv[10..14].iter_mut().zip(index.to_be_bytes()) {
        *byte ^= pki;
    }
    iv
}

/// `hcrypt_SetGcmIV` (SRT 1.5.4): packet index at bytes 8..12, XOR the
/// salt's first 96 bits.
fn gcm_iv(salt: &[u8; 16], index: u32) -> [u8; 12] {
    let mut iv = [0; 12];
    iv.copy_from_slice(&salt[..12]);
    for (byte, pki) in iv[8..12].iter_mut().zip(index.to_be_bytes()) {
        *byte ^= pki;
    }
    iv
}

fn ctr_apply(sek: &[u8], iv: &[u8; 16], buffer: &mut [u8]) {
    match sek.len() {
        16 => ctr::Ctr128BE::<aes::Aes128>::new_from_slices(sek, iv)
            .expect("AES-128 CTR")
            .apply_keystream(buffer),
        24 => ctr::Ctr128BE::<aes::Aes192>::new_from_slices(sek, iv)
            .expect("AES-192 CTR")
            .apply_keystream(buffer),
        _ => ctr::Ctr128BE::<aes::Aes256>::new_from_slices(sek, iv)
            .expect("AES-256 CTR")
            .apply_keystream(buffer),
    }
}

fn gcm_seal(sek: &[u8], iv: [u8; 12], aad: &[u8], buffer: &mut Vec<u8>) {
    let nonce = Nonce::<U12>::from(iv);
    let sealed = match sek.len() {
        16 => Aes128Gcm::new_from_slice(sek)
            .expect("AES-128 GCM")
            .encrypt_in_place(&nonce, aad, buffer),
        _ => Aes256Gcm::new_from_slice(sek)
            .expect("AES-256 GCM")
            .encrypt_in_place(&nonce, aad, buffer),
    };
    sealed.expect("the fixture seals");
}

fn control_datagram(dest: u32, subtype: u16, body: &[u8], now: u64) -> Vec<u8> {
    let mut packet = ControlPacket::new(ControlType::UserDefined, now as u32, dest);
    packet.subtype = subtype;
    packet.control_info = body.to_vec();
    let mut datagram = Vec::new();
    packet
        .encode(&mut datagram)
        .expect("control packet encodes");
    datagram
}

// ============================================================================
// Observation
// ============================================================================

#[derive(Default)]
struct Outputs {
    kmreq: Vec<Vec<u8>>,
    kmrsp: Vec<Vec<u8>>,
    data: Vec<Vec<u8>>,
    handshakes: Vec<HandshakePacket>,
}

impl Outputs {
    fn record(&mut self, datagram: Vec<u8>) {
        match SrtPacket::decode(&datagram) {
            Ok(SrtPacket::Data(_)) => self.data.push(datagram),
            Ok(SrtPacket::Control(packet)) => self.record_control(packet),
            Err(error) => panic!("the connection emitted an undecodable datagram: {error}"),
        }
    }

    fn record_control(&mut self, packet: ControlPacket) {
        match (packet.control_type, packet.subtype) {
            (ControlType::UserDefined, SRT_CMD_KMREQ) => self.kmreq.push(packet.control_info),
            (ControlType::UserDefined, SRT_CMD_KMRSP) => self.kmrsp.push(packet.control_info),
            (ControlType::Handshake, _) => {
                self.handshakes
                    .push(HandshakePacket::decode(&packet).expect("handshake decodes"));
            }
            _ => {}
        }
    }
}

fn take_outputs(connection: &mut SrtConnection) -> Outputs {
    let mut outputs = Outputs::default();
    while let Some(output) = connection.poll_output().expect("poll_output") {
        if let ConnectionOutput::SendPacket(datagram) = output {
            outputs.record(datagram);
        }
    }
    outputs
}

fn take_delivered(connection: &mut SrtConnection) -> Vec<u8> {
    let mut delivered = Vec::new();
    while let Some(event) = connection.poll_event() {
        if let ConnectionEvent::DataReceived { payload, .. } = event {
            for chunk in payload.chunks() {
                delivered.extend_from_slice(&chunk[..]);
            }
        }
    }
    delivered
}

fn options(socket_id: u32, suite: Suite, passphrase: Option<&str>) -> ConnectionOptions {
    ConnectionOptions {
        socket_id,
        passphrase: passphrase.map(str::to_owned),
        crypto_salt: Some(SESSION_SALT),
        crypto_sek: Some(vec![INITIAL_SEK; suite.key_length.len()]),
        key_length: suite.key_length,
        cipher_mode: suite.mode,
        tsbpd_delay: 0,
        ..ConnectionOptions::default()
    }
}

/// Forward everything `from` sends to `to`; the handshakes among it.
fn forward(
    from: &mut SrtConnection,
    to: &mut SrtConnection,
    now: Timestamp,
) -> Vec<HandshakePacket> {
    let mut outputs = Outputs::default();
    while let Some(output) = from.poll_output().expect("poll_output") {
        if let ConnectionOutput::SendPacket(datagram) = output {
            let _ = to.feed_recv_buf(&datagram, now);
            outputs.record(datagram);
        }
    }
    outputs.handshakes
}

/// Run a handshake; every handshake packet either side sent.
fn handshake(caller: &mut SrtConnection, listener: &mut SrtConnection) -> Vec<HandshakePacket> {
    let mut seen = Vec::new();
    caller.connect(ts(0)).expect("caller connects");
    for round in 0..6 {
        let now = ts(round * 10_000);
        seen.extend(forward(caller, listener, now));
        seen.extend(forward(listener, caller, now));
    }
    seen
}

// ============================================================================
// Harness
// ============================================================================

struct Harness {
    model: Model,
    /// The listener under test.
    sut: SrtConnection,
    /// A real srt-rs caller: receives the listener's DATA and rotations.
    peer: SrtConnection,
    now: u64,
    step: usize,
    peer_seq: u32,
    peer_msg: u32,
    rotations: u8,
    keks: HashMap<([u8; 16], usize), Vec<u8>>,
    sent: Vec<Announcement>,
    last_echoed: Option<Announcement>,
    acked: Vec<Vec<u8>>,
}

impl Harness {
    /// Property 1: the handshake installs the caller's key and the
    /// listener's KMRSP echoes the caller's KMREQ.
    fn connect(suite: Suite) -> Result<Self, TestCaseError> {
        let mut peer = SrtConnection::new_caller(options(1, suite, Some(PASSPHRASE)));
        let mut sut = SrtConnection::new_listener(options(2, suite, Some(PASSPHRASE)));
        let seen = handshake(&mut peer, &mut sut);
        prop_assert_eq!(sut.state(), ConnectionState::Connected);
        prop_assert_eq!(peer.state(), ConnectionState::Connected);
        let request = seen.iter().find_map(|hs| hs.get_km_request()?.ok());
        let response = seen.iter().find_map(|hs| hs.get_km_response().ok()?);
        prop_assert!(request.is_some(), "no handshake KMREQ");
        prop_assert_eq!(request, response, "the handshake KMRSP echoes the KMREQ");
        let _ = (take_delivered(&mut peer), take_delivered(&mut sut));
        let _ = (take_outputs(&mut peer), take_outputs(&mut sut));
        let peer_seq = peer.next_sequence_number().expect("caller sequence");
        Ok(Self {
            model: Model::new(suite),
            sut,
            peer,
            now: 100_000,
            step: 0,
            peer_seq,
            peer_msg: 1,
            rotations: 0,
            keks: HashMap::new(),
            sent: Vec::new(),
            last_echoed: None,
            acked: Vec::new(),
        })
    }

    fn apply(&mut self, step: &Step) -> TestCaseResult {
        self.step += 1;
        self.now += STEP_MICROS;
        match step {
            Step::Kmreq(request) => self.kmreq(request),
            Step::PeerData(flag) => self.peer_data(*flag),
            Step::LocalRotate => self.local_rotate(),
            Step::AckRotation => self.ack_rotation(),
            Step::Kmrsp(response) => self.kmrsp(*response),
            Step::Ticks(count) => (0..*count).try_for_each(|_| self.tick()),
            Step::Wait => {
                self.now += srt_rs::DERIVATION_REFILL_MICROS;
                Ok(())
            }
            Step::SwitchThreshold => self.switch_threshold(),
            Step::LocalData => self.local_data(),
        }
    }

    /// Every receive slot and the transmit direction, once more.
    fn final_check(&mut self) -> TestCaseResult {
        if self.model.closed {
            return Ok(());
        }
        self.peer_data(KeyFlag::Even)?;
        self.peer_data(KeyFlag::Odd)?;
        self.local_data()
    }

    fn kek(&mut self, salt: [u8; 16], len: usize) -> Vec<u8> {
        self.keks
            .entry((salt, len))
            .or_insert_with(|| derive_kek(&salt, len))
            .clone()
    }

    fn announcement(&self, keys: KmKeySelection, salt: u8, seks: Vec<Vec<u8>>) -> Announcement {
        Announcement {
            keys,
            salt: salt_for(salt),
            seks,
            suite: self.model.suite,
            corrupt: false,
        }
    }

    fn resolve(&self, request: &Request) -> Option<Announcement> {
        let len = self.model.suite.key_length.len();
        match request {
            Request::Fresh { keys, salt, seeds } => {
                let seks = (0..keys.key_count())
                    .map(|i| peer_key(seeds[i], len))
                    .collect();
                Some(self.announcement(*keys, *salt, seks))
            }
            Request::Duplicate => self.last_echoed.clone(),
            Request::Replay(index) => {
                (!self.sent.is_empty()).then(|| self.sent[index.index(self.sent.len())].clone())
            }
            Request::Reflect { next, flag, salt } => {
                let source = if *next {
                    self.model.tx_next?
                } else {
                    self.model.tx_current
                };
                let sek = self.model.tx[slot(source)].clone();
                Some(self.announcement((*flag).into(), *salt, vec![sek]))
            }
            Request::MoveKnown { from, to, salt } => {
                let (sek, _) = self.model.rx[slot(*from)].clone()?;
                Some(self.announcement((*to).into(), *salt, vec![sek]))
            }
            Request::Malformed { defect, salt, seed } => {
                Some(self.malformed(*defect, *salt, *seed))
            }
        }
    }

    fn malformed(&self, defect: Defect, salt: u8, seed: u8) -> Announcement {
        let suite = self.model.suite;
        let key = peer_key(seed, suite.key_length.len());
        let mut a = self.announcement(KmKeySelection::Even, salt, vec![key.clone()]);
        match defect {
            Defect::CorruptWrap => a.corrupt = true,
            Defect::OtherKeyLength => {
                let other = match suite.key_length {
                    KeyLength::Aes128 => KeyLength::Aes256,
                    _ => KeyLength::Aes128,
                };
                a.suite.key_length = other;
                a.seks = vec![peer_key(seed, other.len())];
            }
            Defect::OtherCipher => {
                a.suite.mode = match suite.mode {
                    CipherMode::Ctr => CipherMode::Gcm,
                    CipherMode::Gcm => CipherMode::Ctr,
                };
            }
            Defect::KeyCountMismatch => a.keys = KmKeySelection::Both,
            Defect::SameKeyTwice => {
                a.keys = KmKeySelection::Both;
                a.seks = vec![key.clone(), key];
            }
        }
        a
    }

    /// Properties 2-5, 9, 10: echoed exactly, or refused without a KMRSP.
    fn kmreq(&mut self, request: &Request) -> TestCaseResult {
        let Some(a) = self.resolve(request) else {
            return Ok(());
        };
        let kek = self.kek(a.salt, a.suite.key_length.len());
        let body = km_body(&a, &kek);
        let echo = self.model.announce(&a, self.now);
        let datagram = control_datagram(self.sut.socket_id(), SRT_CMD_KMREQ, &body, self.now);
        let result = self.sut.feed_recv_buf(&datagram, ts(self.now));
        let outputs = take_outputs(&mut self.sut);
        if echo {
            prop_assert!(result.is_ok(), "{a:?} refused: {result:?}");
            prop_assert_eq!(outputs.kmrsp, vec![body], "KMRSP echoes {:?}", a);
            self.last_echoed = Some(a.clone());
        } else {
            prop_assert!(result.is_err(), "{:?} accepted; model {:?}", a, self.model);
            prop_assert!(outputs.kmrsp.is_empty(), "refused {:?} answered", a);
        }
        if !matches!(request, Request::Reflect { .. }) {
            self.sent.push(a);
        }
        Ok(())
    }

    fn peer_datagram(&self, flag: KeyFlag, plaintext: &[u8], legacy_aad: bool) -> Vec<u8> {
        let len = self.model.suite.key_length.len();
        let (sek, salt) = self.model.rx[slot(flag)]
            .clone()
            .unwrap_or((vec![0x01; len], SESSION_SALT));
        let mut packet = DataPacket::new(
            self.peer_seq,
            self.peer_msg,
            // Already due: the session clocks start within the handshake.
            (self.now - PEER_CLOCK_LEAD_MICROS) as u32,
            self.sut.socket_id(),
            Bytes::new(),
        );
        packet.encryption_flag = flag.to_kk_field();
        let mut buffer = plaintext.to_vec();
        match self.model.suite.mode {
            CipherMode::Ctr => ctr_apply(&sek, &ctr_iv(&salt, packet.sequence_number), &mut buffer),
            CipherMode::Gcm => {
                let mut aad = packet.gcm_aad();
                if legacy_aad {
                    // SRT 1.5.2-1.5.3: header words in host (little-endian) order.
                    aad.chunks_exact_mut(4).for_each(<[u8]>::reverse);
                }
                gcm_seal(
                    &sek,
                    gcm_iv(&salt, packet.sequence_number),
                    &aad,
                    &mut buffer,
                );
            }
        }
        packet.payload = Bytes::from(buffer);
        let mut datagram = Vec::new();
        packet.encode(&mut datagram).expect("DATA encodes");
        datagram
    }

    /// Properties 3, 4, 11, 12: DATA under a selector decrypts exactly with
    /// the model's key and salt for it, and only in the 1.5.4 GCM layout.
    fn peer_data(&mut self, flag: KeyFlag) -> TestCaseResult {
        let installed = self.model.rx[slot(flag)].is_some();
        let plaintext = format!("peer data {}", self.step).into_bytes();
        if installed && self.model.suite.mode == CipherMode::Gcm {
            let legacy = self.peer_datagram(flag, &plaintext, true);
            let result = self.sut.feed_recv_buf(&legacy, ts(self.now));
            prop_assert!(result.is_err(), "1.5.3 GCM AAD layout accepted");
            prop_assert!(take_delivered(&mut self.sut).is_empty());
        }
        let datagram = self.peer_datagram(flag, &plaintext, false);
        let result = self.sut.feed_recv_buf(&datagram, ts(self.now));
        let delivered = take_delivered(&mut self.sut);
        let _ = take_outputs(&mut self.sut);
        if installed {
            prop_assert!(result.is_ok(), "{flag:?} DATA refused: {result:?}");
            prop_assert_eq!(delivered, plaintext, "{:?} DATA decrypts", flag);
            self.peer_seq += 1;
            self.peer_msg += 1;
        } else {
            prop_assert!(result.is_err(), "{flag:?} DATA without a key accepted");
            prop_assert!(delivered.is_empty());
        }
        Ok(())
    }

    fn local_rotate(&mut self) -> TestCaseResult {
        let sek = vec![0x80 + self.rotations; self.model.suite.key_length.len()];
        self.rotations += 1;
        let result = self.sut.provide_new_sek(&sek, ts(self.now));
        let outputs = take_outputs(&mut self.sut);
        if self.model.pending.is_some() {
            prop_assert!(
                result.is_err(),
                "a second rotation started while one is pending"
            );
            prop_assert!(outputs.kmreq.is_empty());
            return Ok(());
        }
        prop_assert!(result.is_ok(), "rotation refused: {result:?}");
        prop_assert_eq!(outputs.kmreq.len(), 1);
        let body = outputs.kmreq[0].clone();
        let flag = self.model.tx_current.other();
        prop_assert_eq!(body[3], flag.to_kk_field(), "one key, the other selector");
        prop_assert_eq!(&body[16..32], &SESSION_SALT[..]);
        self.model.rotate(flag, sek, body);
        Ok(())
    }

    /// Property 7: the real peer installs the rotation and its KMRSP
    /// acknowledges it.
    fn ack_rotation(&mut self) -> TestCaseResult {
        let Some(pending) = self.model.pending.clone() else {
            return Ok(());
        };
        let request = control_datagram(
            self.peer.socket_id(),
            SRT_CMD_KMREQ,
            &pending.body,
            self.now,
        );
        let result = self.peer.feed_recv_buf(&request, ts(self.now));
        prop_assert!(result.is_ok(), "peer refused the rotation: {result:?}");
        let reply = take_outputs(&mut self.peer);
        prop_assert_eq!(&reply.kmrsp, &vec![pending.body.clone()]);
        let response =
            control_datagram(self.sut.socket_id(), SRT_CMD_KMRSP, &pending.body, self.now);
        let result = self.sut.feed_recv_buf(&response, ts(self.now));
        prop_assert!(result.is_ok(), "matching KMRSP refused: {result:?}");
        prop_assert!(take_outputs(&mut self.sut).kmreq.is_empty());
        self.model.pending = None;
        self.acked.push(pending.body);
        Ok(())
    }

    /// Properties 7, 12: other responses neither acknowledge nor
    /// regenerate a rotation; error states are little-endian words.
    fn kmrsp(&mut self, response: Response) -> TestCaseResult {
        let (body, accepted) = match response {
            // BADSECRET (4).
            Response::ErrorLittleEndian => (vec![4, 0, 0, 0], true),
            Response::ErrorBigEndian => (vec![0, 0, 0, 4], false),
            Response::Stale => match self.acked.last() {
                Some(body) => (body.clone(), false),
                None => return Ok(()),
            },
            Response::Mismatched => {
                let Some(mut body) = self.model.pending.as_ref().map(|p| p.body.clone()) else {
                    return Ok(());
                };
                let last = body.len() - 1;
                body[last] ^= 0x01;
                (body, false)
            }
        };
        let datagram = control_datagram(self.sut.socket_id(), SRT_CMD_KMRSP, &body, self.now);
        let result = self.sut.feed_recv_buf(&datagram, ts(self.now));
        prop_assert_eq!(result.is_ok(), accepted, "{:?}: {:?}", response, result);
        prop_assert!(take_outputs(&mut self.sut).kmreq.is_empty());
        Ok(())
    }

    /// Property 8 and RETRY: a byte-identical resend, then a close.
    fn tick(&mut self) -> TestCaseResult {
        if self.model.closed {
            return Ok(());
        }
        self.now += srt_rs::RETRY_INTERVAL_MICROS;
        let result = self.sut.handle_timer(TimerId::Ack, ts(self.now));
        prop_assert!(result.is_ok(), "ACK timer: {result:?}");
        let outputs = take_outputs(&mut self.sut);
        match self.model.retry() {
            Retry::Nothing => prop_assert!(outputs.kmreq.is_empty(), "unexpected KMREQ"),
            Retry::Resend(body) => prop_assert_eq!(outputs.kmreq, vec![body]),
            Retry::Close => prop_assert_ne!(self.sut.state(), ConnectionState::Connected),
        }
        Ok(())
    }

    fn switch_threshold(&mut self) -> TestCaseResult {
        let result = self
            .sut
            .seed_encrypted_packet_count_for_test(KM_REFRESH_PERIOD);
        prop_assert!(result.is_ok());
        self.model.at_threshold = true;
        Ok(())
    }

    /// Properties 6, 11 and ACK_GATED_SWITCH: the listener's DATA uses the
    /// model's transmit key, which the real peer decrypts.
    fn local_data(&mut self) -> TestCaseResult {
        let plaintext = format!("local data {}", self.step).into_bytes();
        let result = self.sut.send(&plaintext, ts(self.now));
        prop_assert!(result.is_ok(), "send: {result:?}");
        let outputs = take_outputs(&mut self.sut);
        prop_assert_eq!(outputs.data.len(), 1);
        let Ok(SrtPacket::Data(packet)) = SrtPacket::decode(&outputs.data[0]) else {
            return Err(TestCaseError::fail("not a DATA packet"));
        };
        prop_assert_eq!(packet.encryption_flag, self.model.tx_current.to_kk_field());
        let result = self.peer.feed_recv_buf(&outputs.data[0], ts(self.now));
        prop_assert!(result.is_ok(), "peer refused local DATA: {result:?}");
        prop_assert_eq!(take_delivered(&mut self.peer), plaintext);
        let _ = take_outputs(&mut self.peer);
        self.model.after_local_send();
        Ok(())
    }
}

// ============================================================================
// Strategies
// ============================================================================

fn suite() -> impl Strategy<Value = Suite> {
    prop_oneof![
        Just((CipherMode::Ctr, KeyLength::Aes128)),
        Just((CipherMode::Ctr, KeyLength::Aes192)),
        Just((CipherMode::Ctr, KeyLength::Aes256)),
        Just((CipherMode::Gcm, KeyLength::Aes128)),
        Just((CipherMode::Gcm, KeyLength::Aes256)),
    ]
    .prop_map(|(mode, key_length)| Suite { mode, key_length })
}

fn flag() -> impl Strategy<Value = KeyFlag> {
    prop_oneof![Just(KeyFlag::Even), Just(KeyFlag::Odd)]
}

fn selection() -> impl Strategy<Value = KmKeySelection> {
    prop_oneof![
        Just(KmKeySelection::Even),
        Just(KmKeySelection::Odd),
        Just(KmKeySelection::Both),
    ]
}

fn defect() -> impl Strategy<Value = Defect> {
    prop_oneof![
        Just(Defect::CorruptWrap),
        Just(Defect::OtherKeyLength),
        Just(Defect::OtherCipher),
        Just(Defect::KeyCountMismatch),
        Just(Defect::SameKeyTwice),
    ]
}

fn request() -> impl Strategy<Value = Request> {
    prop_oneof![
        4 => (selection(), 0u8..4, any::<[u8; 2]>())
            .prop_map(|(keys, salt, seeds)| Request::Fresh { keys, salt, seeds }),
        2 => Just(Request::Duplicate),
        2 => any::<Index>().prop_map(Request::Replay),
        1 => (any::<bool>(), flag(), 0u8..4)
            .prop_map(|(next, flag, salt)| Request::Reflect { next, flag, salt }),
        1 => (flag(), flag(), 0u8..4)
            .prop_map(|(from, to, salt)| Request::MoveKnown { from, to, salt }),
        2 => (defect(), 0u8..4, any::<u8>())
            .prop_map(|(defect, salt, seed)| Request::Malformed { defect, salt, seed }),
    ]
}

fn response() -> impl Strategy<Value = Response> {
    prop_oneof![
        Just(Response::Mismatched),
        Just(Response::ErrorLittleEndian),
        Just(Response::ErrorBigEndian),
        Just(Response::Stale),
    ]
}

fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        8 => request().prop_map(Step::Kmreq),
        4 => flag().prop_map(Step::PeerData),
        2 => Just(Step::LocalRotate),
        2 => Just(Step::AckRotation),
        2 => response().prop_map(Step::Kmrsp),
        2 => (1u8..=6).prop_map(Step::Ticks),
        1 => Just(Step::Wait),
        1 => Just(Step::SwitchThreshold),
        2 => Just(Step::LocalData),
    ]
}

fn config(cases: u32) -> ProptestConfig {
    ProptestConfig {
        cases,
        failure_persistence: None,
        rng_algorithm: RngAlgorithm::ChaCha,
        rng_seed: RngSeed::Fixed(0x4b4d_5f4d_4f44_454c),
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config(64))]

    /// Properties 1-12 against the model, step by step.
    #[test]
    fn km_exchange_follows_the_libsrt_model_with_srt_rs_overrides(
        suite in suite(),
        steps in prop::collection::vec(step(), 1..40),
    ) {
        let mut harness = Harness::connect(suite)?;
        for step in &steps {
            if harness.model.closed {
                break;
            }
            harness.apply(step)?;
        }
        harness.final_check()?;
    }
}

proptest! {
    #![proptest_config(config(8))]

    /// Property 1: a wrong or missing listener secret fails the handshake;
    /// a wrong one is reported as BADSECRET.
    #[test]
    fn handshake_secret_failures_do_not_connect(
        suite in suite(),
        listener_secret in prop_oneof![Just(None), Just(Some("another-passphrase"))],
    ) {
        let mut caller = SrtConnection::new_caller(options(1, suite, Some(PASSPHRASE)));
        let mut listener = SrtConnection::new_listener(options(2, suite, listener_secret));
        let seen = handshake(&mut caller, &mut listener);
        prop_assert_ne!(caller.state(), ConnectionState::Connected);
        let failures: Vec<KmError> = seen.iter().filter_map(|hs| hs.get_km_response().err()).collect();
        if listener_secret.is_some() {
            prop_assert_eq!(failures, vec![KmError::BadSecret]);
        }
    }

    /// Property 12: a runtime KMREQ on an unencrypted session is answered
    /// with NOSECRET as the little-endian word `03 00 00 00`.
    #[test]
    fn runtime_nosecret_is_a_little_endian_word(suite in suite(), seed in any::<u8>()) {
        let plain = Suite { mode: CipherMode::Ctr, key_length: KeyLength::Aes128 };
        let mut caller = SrtConnection::new_caller(options(1, plain, None));
        let mut listener = SrtConnection::new_listener(options(2, plain, None));
        handshake(&mut caller, &mut listener);
        prop_assert_eq!(listener.state(), ConnectionState::Connected);
        let _ = take_outputs(&mut listener);
        let len = suite.key_length.len();
        let a = Announcement {
            keys: KmKeySelection::Even,
            salt: SESSION_SALT,
            seks: vec![peer_key(seed, len)],
            suite,
            corrupt: false,
        };
        let body = km_body(&a, &derive_kek(&SESSION_SALT, len));
        let datagram = control_datagram(listener.socket_id(), SRT_CMD_KMREQ, &body, 200_000);
        prop_assert!(listener.feed_recv_buf(&datagram, ts(200_000)).is_ok());
        prop_assert_eq!(take_outputs(&mut listener).kmrsp, vec![vec![3, 0, 0, 0]]);
    }
}
