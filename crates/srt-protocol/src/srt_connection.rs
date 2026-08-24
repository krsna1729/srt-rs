//! SRT Connection (sansio パターン)
//!
//! SRT 接続を管理する状態機械。
//! I/O は外部で行い、この構造体はバッファ駆動型で動作する。

use std::collections::VecDeque;
use std::fmt;

use zeroize::{Zeroize, Zeroizing};

use crate::buf::write_u32;
use crate::crypto::{CryptoContext, KeyFlag, KeyLength};
use crate::error::Error;
use crate::srt_handshake::{
    DEFAULT_FLOW_WINDOW, GroupExtensionData, HandshakePacket, HandshakeState, HandshakeType,
    KmError, KmMessage, srt_flags,
};
use crate::srt_packet::{ControlPacket, ControlType, DataPacket, SRT_HEADER_SIZE, SrtPacket};
use crate::srt_receiver::ReceiverBuffer;
use crate::srt_sender::SenderBuffer;
use crate::stats::ConnectionStats;
use crate::time::Timestamp;

/// 接続の役割
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionRole {
    /// Caller (接続を開始する側)
    Caller,
    /// Listener (接続を待ち受ける側)
    Listener,
}

/// 接続状態
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnectionState {
    /// 切断状態
    #[default]
    Disconnected,
    /// INDUCTION フェーズ (Caller)
    Induction,
    /// CONCLUSION フェーズ
    Conclusion,
    /// 待ち受け中 (Listener)
    Listening,
    /// 接続確立
    Connected,
    /// 切断中
    Closing,
}

/// タイマー ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimerId {
    /// ACK 送信タイマー (10ms)
    Ack,
    /// NAK 送信タイマー
    Nak,
    /// キープアライブタイマー
    Keepalive,
    /// 再送タイムアウト
    Retransmit,
    /// ハンドシェイクタイムアウト
    Handshake,
    /// 非活性タイムアウト (Keep-alive 未受信検出)
    Inactivity,
}

/// 非活性タイムアウト時間 (マイクロ秒)
/// SRT 仕様では通常 5 秒
const INACTIVITY_TIMEOUT_MICROS: u64 = 5_000_000;
// local patch (crates/srt-protocol/VENDOR.md, not upstream-tracked): use
// libsrt's request cadence with one whole-attempt deadline rather than a
// retry-count approximation that resets between handshake phases.
/// Default minimum spacing between handshake requests. libsrt sends at most
/// one request per 250 ms while a connection attempt is in progress.
pub const DEFAULT_HANDSHAKE_RETRY_INTERVAL_MICROS: u64 = 250_000;
/// Default deadline for the complete induction + conclusion exchange.
pub const DEFAULT_HANDSHAKE_TIMEOUT_MICROS: u64 = 3_000_000;
const MIN_FLOW_WINDOW_PACKETS: u32 = 32;

/// libsrt 互換ゼロパディング (4 バイト)
///
/// # 背景
///
/// SRT 仕様 (draft-sharabayko-srt) では、Keepalive、ACKACK、Shutdown などの制御パケットは
/// データ部を持たない (0 バイト) と定義されている。
///
/// # libsrt の実装上の問題
///
/// libsrt は全パケットを「ヘッダ部 + データ部」の 2 つの iovec で writev 送信する設計だが、
/// データ部が 0 バイトの場合 writev が正しく動作しない環境がある。
/// そのため、データ部が 0 バイトのパケットに 4 バイトのゼロパディングを追加している。
///
/// ```c
/// // libsrt/srtcore/packet.cpp より
/// case UMSG_KEEPALIVE:
///     // control info field should be none
///     // but "writev" does not allow this
///     m_PacketVector[PV_DATA].set((void*)&m_extra_pad, 4);
///     break;
/// ```
///
/// # Wireshark との互換性
///
/// Wireshark の SRT dissector も libsrt に合わせて実装されているため、
/// 仕様通りの 16 バイトパケットを送ると "Malformed Packet" と表示される。
///
/// # このライブラリでの対応
///
/// libsrt および Wireshark との相互運用性のため、同様の 4 バイトゼロパディングを追加する。
///
/// 対象パケット:
/// - Keepalive (0x0001)
/// - ACKACK (0x0006)
/// - Shutdown (0x0005)
const LIBSRT_COMPAT_PADDING: [u8; 4] = [0, 0, 0, 0];

/// 接続イベント
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionEvent {
    /// 接続完了
    Connected,
    /// データ受信
    DataReceived {
        payload: Vec<u8>,
        sequence_number: u32,
        message_number: u32,
        timestamp: u32,
    },
    /// 状態変化
    StateChanged(ConnectionState),
    /// エラー発生
    Error(String),
    /// 切断
    Disconnected { reason: String },
    /// キーリフレッシュが必要
    KeyRefreshNeeded { key_length: usize },
}

/// 接続出力アクション
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionOutput {
    /// パケット送信
    SendPacket(Vec<u8>),
    /// タイマー設定
    SetTimer { id: TimerId, duration_micros: u64 },
    /// タイマークリア
    ClearTimer { id: TimerId },
}

/// 接続オプション
#[derive(Clone)]
pub struct ConnectionOptions {
    /// ローカルソケット ID
    pub socket_id: u32,
    /// 初期シーケンス番号
    pub initial_seq: Option<u32>,
    /// SYN Cookie (Listener 用)
    pub syn_cookie: Option<u32>,
    /// パスフレーズ (暗号化する場合)
    pub passphrase: Option<String>,
    /// 暗号化用の Salt
    pub crypto_salt: Option<[u8; 16]>,
    /// 暗号化用の SEK
    pub crypto_sek: Option<Vec<u8>>,
    /// 鍵長
    pub key_length: KeyLength,
    /// TSBPD 遅延 (ms)
    pub tsbpd_delay: u16,
    /// SRT バージョン
    pub srt_version: u32,
    /// Stream ID (Caller が Listener に送信する識別子、最大 512 バイト)
    pub stream_id: Option<String>,
    /// Optional libsrt-compatible bonding group metadata.
    pub group_extension: Option<GroupExtensionData>,
    /// 最大帯域幅 (`SRTO_MAXBW` 相当、バイト/秒)。`None` の場合は libsrt の
    /// `BW_INFINITE` (1 Gbps) 相当のデフォルトを使う
    /// (`srt_sender` のペーシング計算を参照)。
    pub max_bandwidth_bytes_per_sec: Option<u64>,
    /// Flow-control window advertised in the handshake, in packets.
    pub flow_window_packets: u32,
    /// Local receive-buffer capacity, in packets.
    pub receive_buffer_packets: u32,
    /// Maximum number of delivered DATA events retained for the application.
    ///
    /// Delivered-but-unread packets consume receive-window capacity just like
    /// packets still held by the protocol receiver. This prevents an
    /// application that stops polling events from creating an unbounded queue.
    pub delivery_queue_packets: u32,
}

impl fmt::Debug for ConnectionOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionOptions")
            .field("socket_id", &self.socket_id)
            .field("initial_seq", &self.initial_seq)
            .field("syn_cookie", &self.syn_cookie)
            .field(
                "passphrase",
                &self.passphrase.as_ref().map(|_| "[REDACTED]"),
            )
            .field("crypto_salt", &self.crypto_salt)
            .field(
                "crypto_sek",
                &self.crypto_sek.as_ref().map(|_| "[REDACTED]"),
            )
            .field("key_length", &self.key_length)
            .field("tsbpd_delay", &self.tsbpd_delay)
            .field("srt_version", &self.srt_version)
            .field("stream_id", &self.stream_id)
            .field("group_extension", &self.group_extension)
            .field(
                "max_bandwidth_bytes_per_sec",
                &self.max_bandwidth_bytes_per_sec,
            )
            .field("flow_window_packets", &self.flow_window_packets)
            .field("receive_buffer_packets", &self.receive_buffer_packets)
            .field("delivery_queue_packets", &self.delivery_queue_packets)
            .finish()
    }
}

impl Default for ConnectionOptions {
    fn default() -> Self {
        Self {
            socket_id: 0,
            initial_seq: None,
            syn_cookie: None,
            passphrase: None,
            crypto_salt: None,
            crypto_sek: None,
            key_length: KeyLength::Aes128,
            tsbpd_delay: 120,
            srt_version: 0x010500, // 1.5.0
            stream_id: None,
            group_extension: None,
            max_bandwidth_bytes_per_sec: None,
            flow_window_packets: DEFAULT_FLOW_WINDOW,
            receive_buffer_packets: DEFAULT_FLOW_WINDOW,
            delivery_queue_packets: DEFAULT_FLOW_WINDOW,
        }
    }
}

/// SRT 接続
pub struct SrtConnection {
    /// 役割
    role: ConnectionRole,
    /// 状態
    state: ConnectionState,
    /// ハンドシェイク状態
    handshake_state: HandshakeState,
    /// オプション
    options: ConnectionOptions,

    /// ピアソケット ID
    peer_socket_id: u32,
    /// SYN Cookie
    syn_cookie: u32,

    /// 初期シーケンス番号
    initial_seq: u32,

    /// 暗号化コンテキスト
    crypto: Option<CryptoContext>,

    /// 送信バッファ
    sender: Option<SenderBuffer>,
    /// 受信バッファ
    receiver: Option<ReceiverBuffer>,

    /// イベントキュー
    event_queue: VecDeque<ConnectionEvent>,
    /// DATA events waiting for application consumption. Control/state events
    /// are state-machine bounded; DATA is the unbounded-rate class.
    pending_data_events: u32,
    /// 出力キュー
    output_queue: VecDeque<ConnectionOutput>,

    /// 接続開始時刻
    start_time: Option<Timestamp>,

    /// 最後の ACK 送信時刻
    last_ack_time: Option<Timestamp>,
    /// 最後の NAK 送信時刻
    last_nak_time: Option<Timestamp>,
    /// 最後のパケット受信時刻 (非活性タイムアウト検出用)
    last_recv_time: Option<Timestamp>,
    /// 受信した KM メッセージ (Listener 用)
    received_km: Option<KmMessage>,
    /// ピアから受信した Stream ID (Listener 用)
    peer_stream_id: Option<String>,
    /// Peer bonding group metadata.
    peer_group_extension: Option<GroupExtensionData>,
    last_handshake_packet: Option<Vec<u8>>,
    handshake_retry_sequence: u32,
    handshake_started_at: Option<Timestamp>,
    handshake_retry_interval_micros: u64,
    handshake_timeout_micros: u64,
}

impl Drop for SrtConnection {
    fn drop(&mut self) {
        self.clear_config_secrets();
    }
}

fn normalize_buffer_options(mut options: ConnectionOptions) -> ConnectionOptions {
    options.flow_window_packets = options.flow_window_packets.max(MIN_FLOW_WINDOW_PACKETS);
    options.receive_buffer_packets = options
        .receive_buffer_packets
        .max(MIN_FLOW_WINDOW_PACKETS)
        .min(options.flow_window_packets);
    options.delivery_queue_packets = options
        .delivery_queue_packets
        .max(1)
        .min(options.receive_buffer_packets);
    options
}

impl SrtConnection {
    fn random_bytes(bytes: &mut [u8], label: &str) -> Result<(), Error> {
        getrandom::fill(bytes)
            .map_err(|error| Error::crypto_error(format!("failed to generate {label}: {error}")))
    }

    /// Put the handshake into its terminal failed state.
    ///
    /// Every path that abandons a handshake -- rejection, KM failure,
    /// caller-side failure, timeout -- has to do the same four things, and
    /// they were written out four times. The copies had already diverged:
    /// the timeout path did not clear the configured secrets, so a
    /// handshake that timed out left its passphrase, salt, and SEK in
    /// memory while a rejected one did not.
    fn terminate_handshake(&mut self) {
        self.handshake_started_at = None;
        self.handshake_state = HandshakeState::Failed;
        self.set_state(ConnectionState::Disconnected);
        self.output_queue.push_back(ConnectionOutput::ClearTimer {
            id: TimerId::Handshake,
        });
        self.clear_config_secrets();
    }

    fn clear_config_secrets(&mut self) {
        if let Some(passphrase) = self.options.passphrase.as_mut() {
            passphrase.zeroize();
        }
        self.options.passphrase = None;
        if let Some(salt) = self.options.crypto_salt.as_mut() {
            salt.zeroize();
        }
        self.options.crypto_salt = None;
        if let Some(sek) = self.options.crypto_sek.as_mut() {
            sek.zeroize();
        }
        self.options.crypto_sek = None;
    }

    /// Caller として新しい接続を作成
    pub fn new_caller(options: ConnectionOptions) -> Self {
        let options = normalize_buffer_options(options);
        let initial_seq = options.initial_seq.unwrap_or(0);
        Self {
            role: ConnectionRole::Caller,
            state: ConnectionState::Disconnected,
            handshake_state: HandshakeState::Initial,
            options,
            peer_socket_id: 0,
            syn_cookie: 0,
            initial_seq,
            crypto: None,
            sender: None,
            receiver: None,
            event_queue: VecDeque::new(),
            pending_data_events: 0,
            output_queue: VecDeque::new(),
            start_time: None,
            last_ack_time: None,
            last_nak_time: None,
            last_recv_time: None,
            received_km: None,
            peer_stream_id: None,
            peer_group_extension: None,
            last_handshake_packet: None,
            handshake_retry_sequence: 0,
            handshake_started_at: None,
            handshake_retry_interval_micros: DEFAULT_HANDSHAKE_RETRY_INTERVAL_MICROS,
            handshake_timeout_micros: DEFAULT_HANDSHAKE_TIMEOUT_MICROS,
        }
    }

    /// Listener として新しい接続を作成
    pub fn new_listener(options: ConnectionOptions) -> Self {
        let options = normalize_buffer_options(options);
        let initial_seq = options.initial_seq.unwrap_or(0);
        Self {
            role: ConnectionRole::Listener,
            state: ConnectionState::Listening,
            handshake_state: HandshakeState::Initial,
            options,
            peer_socket_id: 0,
            syn_cookie: 0,
            initial_seq,
            crypto: None,
            sender: None,
            receiver: None,
            event_queue: VecDeque::new(),
            pending_data_events: 0,
            output_queue: VecDeque::new(),
            start_time: None,
            last_ack_time: None,
            last_nak_time: None,
            last_recv_time: None,
            received_km: None,
            peer_stream_id: None,
            peer_group_extension: None,
            last_handshake_packet: None,
            handshake_retry_sequence: 0,
            handshake_started_at: None,
            handshake_retry_interval_micros: DEFAULT_HANDSHAKE_RETRY_INTERVAL_MICROS,
            handshake_timeout_micros: DEFAULT_HANDSHAKE_TIMEOUT_MICROS,
        }
    }

    /// 現在の状態を取得
    pub fn state(&self) -> ConnectionState {
        self.state
    }

    /// Return this connection's local SRT socket ID.
    ///
    /// The ID is stable for the lifetime of one SRT leg and is carried in the
    /// destination field of peer feedback packets. Callers multiplexing
    /// multiple legs over one UDP tuple can use it to preserve leg identity.
    pub fn socket_id(&self) -> u32 {
        self.options.socket_id
    }

    /// Listener-issued SYN cookie currently expected from the peer.
    #[must_use]
    pub fn syn_cookie(&self) -> u32 {
        self.syn_cookie
    }

    /// ピアから受信した Stream ID を取得 (Listener 用)
    pub fn peer_stream_id(&self) -> Option<&str> {
        self.peer_stream_id.as_deref()
    }

    /// Return the bonding group metadata advertised by the peer.
    pub fn peer_group_extension(&self) -> Option<GroupExtensionData> {
        self.peer_group_extension
    }

    /// Return the SRT socket ID advertised by the peer during handshake.
    ///
    /// The peer socket ID is stable for the lifetime of one SRT leg and is
    /// useful as a member identity after GROUP admission. It is not a
    /// replacement for the UDP tuple when routing packets because the first
    /// induction packet must be assigned before this value is known.
    pub fn peer_socket_id(&self) -> u32 {
        self.peer_socket_id
    }

    /// Apply the listener-side policy selected from the incoming StreamID.
    ///
    /// A listener may only change these handshake options while it is still
    /// waiting for the conclusion packet. This mirrors libsrt's accept hook:
    /// the caller's StreamID is known, but KMREQ and the accepted connection
    /// have not been processed yet.
    pub fn set_listener_policy(
        &mut self,
        mut passphrase: Option<String>,
        key_length: KeyLength,
        tsbpd_delay: u16,
        flow_window_packets: u32,
        receive_buffer_packets: u32,
    ) -> Result<(), Error> {
        if let Err(error) = self.ensure_listener_policy_window() {
            if let Some(secret) = passphrase.as_mut() {
                secret.zeroize();
            }
            return Err(error);
        }
        self.replace_listener_encryption(passphrase, key_length);
        self.options.tsbpd_delay = tsbpd_delay;
        self.set_listener_flow_control_unchecked(flow_window_packets, receive_buffer_packets);
        Ok(())
    }

    /// Select listener encryption after reading the caller's StreamID and
    /// before processing its KM request. Replacing a policy zeroizes the old
    /// secret and clears any caller-side deterministic key material.
    pub fn set_listener_encryption(
        &mut self,
        mut passphrase: Option<String>,
        key_length: KeyLength,
    ) -> Result<(), Error> {
        if let Err(error) = self.ensure_listener_policy_window() {
            if let Some(secret) = passphrase.as_mut() {
                secret.zeroize();
            }
            return Err(error);
        }
        self.replace_listener_encryption(passphrase, key_length);
        Ok(())
    }

    /// Override listener latency during the pre-CONCLUSION policy window.
    pub fn set_listener_latency(&mut self, tsbpd_delay: u16) -> Result<(), Error> {
        self.ensure_listener_policy_window()?;
        self.options.tsbpd_delay = tsbpd_delay;
        Ok(())
    }

    /// Override listener flow-control and receive windows before CONCLUSION.
    pub fn set_listener_flow_control(
        &mut self,
        flow_window_packets: u32,
        receive_buffer_packets: u32,
    ) -> Result<(), Error> {
        self.ensure_listener_policy_window()?;
        self.set_listener_flow_control_unchecked(flow_window_packets, receive_buffer_packets);
        Ok(())
    }

    /// Override listener pacing bandwidth before CONCLUSION.
    pub fn set_listener_bandwidth(
        &mut self,
        max_bandwidth_bytes_per_sec: Option<u64>,
    ) -> Result<(), Error> {
        self.ensure_listener_policy_window()?;
        self.options.max_bandwidth_bytes_per_sec = max_bandwidth_bytes_per_sec;
        Ok(())
    }

    /// Set or clear listener-side GROUP metadata before CONCLUSION.
    pub fn set_listener_group_extension(
        &mut self,
        group: Option<GroupExtensionData>,
    ) -> Result<(), Error> {
        self.ensure_listener_policy_window()?;
        self.options.group_extension = group;
        Ok(())
    }

    fn ensure_listener_policy_window(&self) -> Result<(), Error> {
        if self.role != ConnectionRole::Listener || self.state != ConnectionState::Listening {
            return Err(Error::invalid_state(
                "listener policy can only change before conclusion",
            ));
        }
        Ok(())
    }

    fn replace_listener_encryption(&mut self, passphrase: Option<String>, key_length: KeyLength) {
        if let Some(old) = self.options.passphrase.as_mut() {
            old.zeroize();
        }
        if let Some(salt) = self.options.crypto_salt.as_mut() {
            salt.zeroize();
        }
        if let Some(sek) = self.options.crypto_sek.as_mut() {
            sek.zeroize();
        }
        self.options.passphrase = passphrase;
        self.options.crypto_salt = None;
        self.options.crypto_sek = None;
        self.options.key_length = key_length;
    }

    fn set_listener_flow_control_unchecked(
        &mut self,
        flow_window_packets: u32,
        receive_buffer_packets: u32,
    ) {
        self.options.flow_window_packets = flow_window_packets.max(MIN_FLOW_WINDOW_PACKETS);
        self.options.receive_buffer_packets = receive_buffer_packets
            .max(MIN_FLOW_WINDOW_PACKETS)
            .min(self.options.flow_window_packets);
        self.options.delivery_queue_packets = self
            .options
            .delivery_queue_packets
            .max(1)
            .min(self.options.receive_buffer_packets);
    }

    /// Set listener-side GROUP metadata before processing the conclusion.
    pub fn set_group_extension(&mut self, group: GroupExtensionData) {
        self.options.group_extension = Some(group);
    }

    /// Configure retry spacing and the deadline for the whole handshake.
    ///
    /// Jitter is added only after `retry_interval_micros`, so a retry is
    /// never scheduled earlier than the requested cadence. Both values are
    /// clamped to at least one microsecond and the whole-attempt timeout is
    /// clamped to at least the retry interval.
    pub fn set_handshake_timing(&mut self, retry_interval_micros: u64, timeout_micros: u64) {
        self.handshake_retry_interval_micros = retry_interval_micros.max(1);
        self.handshake_timeout_micros = timeout_micros
            .max(1)
            .max(self.handshake_retry_interval_micros);
    }

    /// 接続を開始 (Caller のみ)
    pub fn connect(&mut self, now: Timestamp) -> Result<(), Error> {
        if self.role != ConnectionRole::Caller {
            return Err(Error::invalid_state("only caller can initiate connection"));
        }

        self.start_time = Some(now);
        self.handshake_started_at = Some(now);
        self.handshake_retry_sequence = 0;
        self.send_induction_request(now);
        self.set_state(ConnectionState::Induction);
        self.handshake_state = HandshakeState::InductionSent;
        self.arm_handshake_timer(now);

        Ok(())
    }

    /// Reject the pending listener handshake with an SRT rejection response.
    pub fn reject(&mut self, reason: i32, now: Timestamp) -> Result<(), Error> {
        if self.role != ConnectionRole::Listener
            || self.handshake_state != HandshakeState::InductionReceived
        {
            return Err(Error::invalid_state(
                "only a listener awaiting conclusion can reject a handshake",
            ));
        }
        let handshake =
            HandshakePacket::new_rejection(self.options.socket_id, self.syn_cookie, reason);
        let packet = handshake.encode(self.relative_timestamp(now), self.peer_socket_id);
        let mut bytes = Vec::new();
        packet.encode(&mut bytes);
        self.queue_handshake_packet(bytes);
        self.terminate_handshake();
        Ok(())
    }

    /// 送信/受信バッファを初期化
    fn init_buffers(&mut self, now: Timestamp, peer_initial_seq: u32, tsbpd_time_base: u64) {
        let mut sender = SenderBuffer::new(
            self.initial_seq,
            self.options.flow_window_packets,
            self.options.tsbpd_delay,
        );
        if let Some(max_bw) = self.options.max_bandwidth_bytes_per_sec {
            sender.set_max_bandwidth(max_bw);
        }
        self.sender = Some(sender);
        self.receiver = Some(ReceiverBuffer::with_buffer_size(
            peer_initial_seq,
            self.options.tsbpd_delay,
            now,
            tsbpd_time_base,
            self.options
                .receive_buffer_packets
                .min(self.options.flow_window_packets),
        ));
        self.last_ack_time = Some(now);
        self.last_nak_time = Some(now);
    }

    fn flight_capacity_packets(&self) -> u32 {
        self.options
            .flow_window_packets
            .min(self.options.receive_buffer_packets)
    }

    /// 受信データを処理
    pub fn feed_recv_buf(&mut self, buf: &[u8], now: Timestamp) -> Result<(), Error> {
        if buf.len() < SRT_HEADER_SIZE {
            return Err(Error::insufficient_buffer());
        }

        let packet = SrtPacket::decode(buf)?;
        let (dest_socket_id, is_handshake) = match &packet {
            SrtPacket::Data(packet) => (packet.dest_socket_id, false),
            SrtPacket::Control(packet) => (
                packet.dest_socket_id,
                packet.control_type == ControlType::Handshake,
            ),
        };
        if self.options.socket_id != 0
            && dest_socket_id != self.options.socket_id
            && !(is_handshake
                && dest_socket_id == 0
                && !matches!(
                    self.state,
                    ConnectionState::Connected | ConnectionState::Closing
                ))
        {
            return Err(Error::invalid_data(format!(
                "destination socket ID mismatch: expected {:#x}, got {:#x}",
                self.options.socket_id, dest_socket_id
            )));
        }

        // Only a valid packet for this connection proves peer activity.
        if self.state == ConnectionState::Connected {
            self.last_recv_time = Some(now);
            self.output_queue.push_back(ConnectionOutput::SetTimer {
                id: TimerId::Inactivity,
                duration_micros: INACTIVITY_TIMEOUT_MICROS,
            });
        }

        match packet {
            SrtPacket::Data(data_pkt) => {
                tracing::debug!("received DATA packet, seq={}", data_pkt.sequence_number);
                self.handle_data_packet(data_pkt, now)
            }
            SrtPacket::Control(ctrl_pkt) => self.handle_control_packet(ctrl_pkt, now),
        }
    }

    /// 再送が必要なパケットがあるか
    pub fn has_retransmit(&self) -> bool {
        self.sender.as_ref().is_some_and(|s| s.has_retransmit())
    }

    /// 再送パケットを取得して送信キューに追加
    ///
    /// `now` はこの Core の他のメソッドとのシグネチャ一貫性のために残して
    /// いる (このメソッド自体はもう使わない -- 再送パケットの
    /// `sent_time` を更新しなくなった理由は
    /// `SenderBuffer::pop_retransmit` のドキュメント参照)。
    pub fn process_retransmit(&mut self, _now: Timestamp) {
        if let Some(ref mut sender) = self.sender {
            while let Some(mut packet) = sender.pop_retransmit() {
                // 暗号化
                if let Some(ref mut crypto) = self.crypto
                    && let Ok(key_flag) =
                        crypto.encrypt(packet.sequence_number, &mut packet.payload)
                {
                    packet.encryption_flag = key_flag.to_kk_field();
                }

                let mut buf = Vec::new();
                packet.encode(&mut buf);
                self.output_queue
                    .push_back(ConnectionOutput::SendPacket(buf));
            }
        }
    }

    /// タイマーイベントを処理
    pub fn handle_timer(&mut self, timer_id: TimerId, now: Timestamp) -> Result<(), Error> {
        match timer_id {
            TimerId::Handshake => {
                if self.state != ConnectionState::Connected {
                    if self.handshake_timed_out(now) {
                        self.fail_handshake_timeout();
                    } else {
                        self.handshake_retry_sequence =
                            self.handshake_retry_sequence.saturating_add(1);
                        self.retransmit_handshake();
                        self.arm_handshake_timer(now);
                    }
                }
            }
            TimerId::Keepalive => {
                if self.state == ConnectionState::Connected {
                    self.send_keepalive(now);
                    // 次のキープアライブタイマー設定
                    self.output_queue.push_back(ConnectionOutput::SetTimer {
                        id: TimerId::Keepalive,
                        duration_micros: 1_000_000, // 1秒
                    });
                }
            }
            TimerId::Ack => {
                // 定期 ACK 送信
                if self.state == ConnectionState::Connected {
                    // TLPKTDROP: 期限切れパケットを削除
                    if let Some(receiver) = self.receiver.as_mut() {
                        for seq in receiver.drop_too_late(now) {
                            if let Some(sender) = self.sender.as_mut() {
                                sender.discard_acked(seq);
                            }
                        }
                    }
                    self.enqueue_ready_data(now);
                    self.send_ack(now);

                    if let Some(sender) = self.sender.as_mut() {
                        let _ = sender.drop_expired(now);
                    }

                    // 次の ACK タイマー設定 (10ms)
                    self.output_queue.push_back(ConnectionOutput::SetTimer {
                        id: TimerId::Ack,
                        duration_micros: 10_000,
                    });
                }
            }
            TimerId::Nak => {
                // Periodic NAK 送信
                if self.state == ConnectionState::Connected {
                    self.send_periodic_nak(now);
                    // 次の NAK タイマー設定
                    let interval = self
                        .receiver
                        .as_ref()
                        .map(|r| r.nak_interval())
                        .unwrap_or(20_000);
                    self.output_queue.push_back(ConnectionOutput::SetTimer {
                        id: TimerId::Nak,
                        duration_micros: interval,
                    });
                }
            }
            TimerId::Retransmit => {
                // 再送処理
                if self.state == ConnectionState::Connected {
                    self.process_retransmit(now);
                }
            }
            TimerId::Inactivity => {
                // 非活性タイムアウト: ピアからのパケット受信がない場合に切断
                if self.state == ConnectionState::Connected {
                    self.event_queue.push_back(ConnectionEvent::Disconnected {
                        reason: "inactivity timeout".to_string(),
                    });
                    self.set_state(ConnectionState::Disconnected);
                }
            }
        }
        Ok(())
    }

    /// データを送信
    pub fn send(&mut self, payload: &[u8], now: Timestamp) -> Result<(), Error> {
        self.send_internal(payload, None, now)
    }

    /// Send one message with a caller-supplied SRT sequence number.
    pub fn send_with_sequence(
        &mut self,
        payload: &[u8],
        sequence_number: u32,
        now: Timestamp,
    ) -> Result<(), Error> {
        self.send_internal(payload, Some(sequence_number), now)
    }

    fn send_internal(
        &mut self,
        payload: &[u8],
        sequence_number: Option<u32>,
        now: Timestamp,
    ) -> Result<(), Error> {
        if self.state != ConnectionState::Connected {
            return Err(Error::invalid_state("not connected"));
        }

        if !self.can_send() {
            return Err(Error::invalid_state("send buffer full"));
        }

        if let Some(sequence_number) = sequence_number
            && self.next_sequence_number() != Some(sequence_number)
        {
            return Err(Error::invalid_state("sequence number is out of order"));
        }

        let timestamp = self.relative_timestamp(now);
        let peer_socket_id = self.peer_socket_id;

        let packet = {
            let sender = self
                .sender
                .as_mut()
                .ok_or_else(|| Error::invalid_state("sender buffer not initialized"))?;
            match sequence_number {
                Some(sequence_number) => sender.push_with_sequence(
                    payload.to_vec(),
                    timestamp,
                    peer_socket_id,
                    now,
                    sequence_number,
                ),
                None => sender.push(payload.to_vec(), timestamp, peer_socket_id, now),
            }
        };

        if let Some(mut packet) = packet {
            tracing::debug!(
                "sending DATA packet, seq={}, msg={}, ts={}, dest_socket_id={:#x}, payload_len={}",
                packet.sequence_number,
                packet.message_number,
                packet.timestamp,
                packet.dest_socket_id,
                packet.payload.len()
            );

            // 暗号化
            if let Some(ref mut crypto) = self.crypto {
                let key_flag = crypto.encrypt(packet.sequence_number, &mut packet.payload)?;
                packet.encryption_flag = key_flag.to_kk_field();
            }

            let mut buf = Vec::new();
            packet.encode(&mut buf);
            self.output_queue
                .push_back(ConnectionOutput::SendPacket(buf));

            // 送信時刻を記録 (パケットペーシング用)
            if let Some(ref mut sender) = self.sender {
                sender.record_send_time(now);
            }
        }

        // KM Refresh チェック
        self.check_km_refresh(now);

        Ok(())
    }

    /// Return the next sequence number assigned by the connection.
    pub fn next_sequence_number(&self) -> Option<u32> {
        self.sender.as_ref().map(SenderBuffer::next_sequence_number)
    }

    pub fn advance_receive_sequence(&mut self, sequence_number: u32, now: Timestamp) {
        let Some(receiver) = self.receiver.as_mut() else {
            return;
        };
        receiver.advance_expected_sequence(sequence_number);
        self.enqueue_ready_data(now);
    }

    pub fn synchronize_send_sequence(&mut self, sequence_number: u32) -> Result<(), Error> {
        let Some(sender) = self.sender.as_mut() else {
            return Err(Error::invalid_state("sender buffer not initialized"));
        };
        if sender.synchronize_next_sequence_number(sequence_number) {
            Ok(())
        } else {
            Err(Error::invalid_state("sender buffer has in-flight packets"))
        }
    }

    /// 送信可能かどうか (ウィンドウサイズのみ)
    pub fn can_send(&self) -> bool {
        self.sender.as_ref().is_some_and(|s| s.can_send())
    }

    /// 送信可能かどうか (パケットペーシングを含む)
    pub fn can_send_with_pacing(&self, now: Timestamp) -> bool {
        self.sender
            .as_ref()
            .is_some_and(|s| s.can_send_with_pacing(now))
    }

    /// 次の送信可能時刻までの待機時間 (マイクロ秒)
    pub fn time_until_send(&self, now: Timestamp) -> u64 {
        self.sender
            .as_ref()
            .map(|s| s.time_until_send(now))
            .unwrap_or(100_000)
    }

    /// パケット送信間隔を設定 (マイクロ秒)
    pub fn set_packet_send_period(&mut self, period: u64) {
        if let Some(ref mut sender) = self.sender {
            sender.set_packet_send_period(period);
        }
    }

    /// イベントを取得
    pub fn poll_event(&mut self) -> Option<ConnectionEvent> {
        let event = self.event_queue.pop_front()?;
        if matches!(event, ConnectionEvent::DataReceived { .. }) {
            self.pending_data_events = self.pending_data_events.saturating_sub(1);
            self.sync_application_backlog();
        }
        Some(event)
    }

    /// 出力を取得
    pub fn poll_output(&mut self) -> Option<ConnectionOutput> {
        self.output_queue.pop_front()
    }

    /// 切断
    pub fn disconnect(&mut self, now: Timestamp) {
        if self.state == ConnectionState::Connected {
            self.send_shutdown(now);
            self.set_state(ConnectionState::Closing);
        }
    }

    /// 送信側の統計情報を取得
    pub fn sender_stats(&self) -> Option<crate::srt_sender::SenderStats> {
        self.sender.as_ref().map(|s| s.stats())
    }

    /// 受信側の統計情報を取得
    pub fn receiver_stats(&self) -> Option<crate::srt_receiver::ReceiverStats> {
        self.receiver.as_ref().map(|r| r.stats())
    }

    /// Return a non-clearing snapshot of cumulative and instantaneous
    /// connection telemetry.
    ///
    /// Interval counts and rates can be derived without giving this sans-I/O
    /// core a clock via [`ConnectionStats::interval_since`].
    pub fn stats(&self) -> ConnectionStats {
        ConnectionStats {
            sender: self.sender_stats(),
            receiver: self.receiver_stats(),
        }
    }

    /// 新しい SEK を提供してキーリフレッシュを開始
    ///
    /// `KeyRefreshNeeded` イベントを受信した後に呼び出す。
    pub fn provide_new_sek(&mut self, new_sek: &[u8], now: Timestamp) -> Result<(), Error> {
        let Some(ref mut crypto) = self.crypto else {
            return Err(Error::with_reason(
                crate::error::ErrorKind::CryptoError,
                "encryption not enabled",
            ));
        };

        let (key_flag, wrapped_key) = crypto.start_pre_announce(new_sek)?;
        let km_message = KmMessage::new(key_flag, crypto.key_length(), *crypto.salt(), wrapped_key);
        self.send_km_request(&km_message, now);

        Ok(())
    }

    // ========================================================================
    // プライベートメソッド
    // ========================================================================

    fn set_state(&mut self, new_state: ConnectionState) {
        if self.state != new_state {
            self.state = new_state;
            self.event_queue
                .push_back(ConnectionEvent::StateChanged(new_state));
        }
    }

    fn relative_timestamp(&self, now: Timestamp) -> u32 {
        // start_time が未設定の場合は明示的に 0 を返す。
        // ハンドシェイク中の Listener 側では start_time が未設定のまま呼ばれる。
        // ハンドシェイクパケットのタイムスタンプは INDUCTION リクエストの
        // hsreq_timestamp から TSBPD 時刻基準を計算するため、レスポンス側の
        // タイムスタンプが 0 でも TSBPD の動作に影響しない。
        self.start_time
            .map_or(0, |s| now.as_micros().saturating_sub(s.as_micros())) as u32
    }

    /// Move at most the configured amount of protocol-ready DATA into the
    /// application queue. Packets that do not fit deliberately remain in the
    /// receiver, where they continue to consume SRT receive-window capacity.
    fn enqueue_ready_data(&mut self, now: Timestamp) {
        let available = self
            .options
            .delivery_queue_packets
            .saturating_sub(self.pending_data_events) as usize;
        if available == 0 {
            return;
        }

        let ready_packets = {
            let Some(receiver) = self.receiver.as_mut() else {
                return;
            };
            let mut ready_packets = Vec::with_capacity(available);
            for _ in 0..available {
                let Some(packet) = receiver.pop_ready(now) else {
                    break;
                };
                ready_packets.push(packet);
            }
            ready_packets
        };

        for packet in ready_packets {
            self.event_queue.push_back(ConnectionEvent::DataReceived {
                payload: packet.payload,
                sequence_number: packet.sequence_number,
                message_number: packet.message_number,
                timestamp: packet.timestamp,
            });
            self.pending_data_events = self.pending_data_events.saturating_add(1);
        }
        self.sync_application_backlog();
    }

    fn sync_application_backlog(&mut self) {
        if let Some(receiver) = self.receiver.as_mut() {
            receiver.set_application_backlog_packets(self.pending_data_events);
        }
    }

    fn handle_data_packet(&mut self, pkt: DataPacket, now: Timestamp) -> Result<(), Error> {
        if self.state != ConnectionState::Connected {
            return Ok(()); // 接続前のデータは無視
        }

        // Checked before the payload clone below: this is the path a
        // misconfigured or hostile peer drives hardest, and the guard reads
        // only the header, so there is no reason to copy ~1.3 KB first.
        //
        // A secured SRT connection must reject plaintext DATA just as it
        // rejects packets whose advertised key cannot be used. This is both a
        // security boundary and the source transition for undecrypt telemetry.
        if pkt.encryption_flag == 0 && self.crypto.is_some() {
            if let Some(receiver) = self.receiver.as_mut() {
                receiver.record_undecryptable();
            }
            return Err(Error::crypto_error(
                "unencrypted DATA packet on encrypted connection",
            ));
        }

        let mut payload = pkt.payload.clone();

        // 復号化
        if pkt.encryption_flag != 0 {
            let decrypt_result = if let Some(ref crypto) = self.crypto {
                KeyFlag::from_kk_field(pkt.encryption_flag)
                    .ok_or_else(|| Error::crypto_error("invalid KK flag"))
                    .and_then(|key_flag| {
                        crypto.decrypt(pkt.sequence_number, key_flag, &mut payload)
                    })
            } else {
                Err(Error::crypto_error(
                    "encrypted packet but no crypto context",
                ))
            };
            if let Err(error) = decrypt_result {
                if let Some(receiver) = self.receiver.as_mut() {
                    receiver.record_undecryptable();
                }
                return Err(error);
            }
        }

        // Receive before delivery. Ready packets are moved into the bounded
        // application queue below, so unread application data remains part of
        // the advertised receive window instead of accumulating without bound.
        let (losses, should_ack) = {
            let receiver = match self.receiver.as_mut() {
                Some(r) => r,
                None => return Ok(()),
            };

            let mut decrypted_pkt = pkt;
            decrypted_pkt.payload = payload;

            let losses = receiver.receive(decrypted_pkt, now);
            let should_ack = receiver.should_send_ack(now);

            (losses, should_ack)
        };

        // 損失が検出された場合、NAK を送信
        if let Some(loss_list) = losses
            && !loss_list.is_empty()
        {
            self.send_nak(&loss_list, now);
        }

        self.enqueue_ready_data(now);

        // Light ACK チェック. This runs after delivery admission so the ACK's
        // available-buffer field includes application backlog.
        if should_ack {
            self.send_ack(now);
        }

        Ok(())
    }

    fn handle_control_packet(&mut self, pkt: ControlPacket, now: Timestamp) -> Result<(), Error> {
        tracing::debug!(
            "received control packet, type={:?}, info_len={}",
            pkt.control_type,
            pkt.control_info.len()
        );
        match pkt.control_type {
            ControlType::Handshake => self.handle_handshake(pkt, now),
            ControlType::Keepalive => Ok(()), // キープアライブは特に処理不要
            ControlType::Ack => self.handle_ack(pkt, now),
            ControlType::Nak => self.handle_nak(pkt, now),
            ControlType::Shutdown => self.handle_shutdown(now),
            ControlType::AckAck => self.handle_ackack(pkt, now),
            ControlType::UserDefined => self.handle_user_defined(pkt, now),
            _ => Ok(()), // その他は無視
        }
    }

    fn handle_handshake(&mut self, pkt: ControlPacket, now: Timestamp) -> Result<(), Error> {
        if self.handshake_timed_out(now) {
            self.fail_handshake_timeout();
            return Ok(());
        }
        let hs = HandshakePacket::decode(&pkt)?;

        match self.role {
            ConnectionRole::Caller => self.handle_handshake_caller(hs, pkt.timestamp, now),
            ConnectionRole::Listener => self.handle_handshake_listener(hs, pkt.timestamp, now),
        }
    }

    fn handle_handshake_caller(
        &mut self,
        hs: HandshakePacket,
        hsreq_timestamp: u32,
        now: Timestamp,
    ) -> Result<(), Error> {
        match hs.handshake_type {
            HandshakeType::Induction => {
                // INDUCTION レスポンス受信
                if !matches!(
                    self.handshake_state,
                    HandshakeState::InductionSent | HandshakeState::ConclusionSent
                ) {
                    return Ok(());
                }

                self.syn_cookie = hs.syn_cookie;
                self.peer_socket_id = hs.socket_id;
                tracing::debug!(
                    "received INDUCTION response, peer_socket_id={:#x}, syn_cookie={:#x}",
                    self.peer_socket_id,
                    self.syn_cookie
                );

                // 暗号化コンテキスト生成
                if self.handshake_state == HandshakeState::InductionSent
                    && let Some(ref passphrase) = self.options.passphrase
                {
                    let key_length = hs.key_length().unwrap_or(self.options.key_length);
                    let salt = match self.options.crypto_salt {
                        Some(salt) => salt,
                        None => {
                            let mut salt = [0u8; 16];
                            Self::random_bytes(&mut salt, "crypto salt")?;
                            salt
                        }
                    };
                    let generated_sek;
                    let sek = match self.options.crypto_sek.as_deref() {
                        Some(sek) => sek,
                        None => {
                            generated_sek = Zeroizing::new({
                                let mut sek = vec![0u8; key_length.len()];
                                Self::random_bytes(&mut sek, "stream encryption key")?;
                                sek
                            });
                            generated_sek.as_slice()
                        }
                    };
                    self.crypto = Some(CryptoContext::new_sender(
                        passphrase, key_length, salt, sek,
                    )?);
                }

                // CONCLUSION を送信
                self.send_conclusion_request(now);
                self.handshake_state = HandshakeState::ConclusionSent;
                self.arm_handshake_timer(now);
            }
            HandshakeType::Conclusion => {
                // CONCLUSION レスポンス受信 → 接続完了
                if self.handshake_state == HandshakeState::Completed {
                    self.retransmit_handshake();
                    return Ok(());
                }
                if self.handshake_state != HandshakeState::ConclusionSent {
                    return Ok(());
                }

                // CONCLUSION レスポンスの socket_id で更新
                // (INDUCTION とは異なる値の場合がある)
                self.peer_socket_id = hs.socket_id;
                self.peer_group_extension = hs.get_group_extension();

                tracing::debug!(
                    "received CONCLUSION response, peer_initial_seq={}, peer_socket_id={:#x}",
                    hs.initial_packet_seq,
                    hs.socket_id
                );

                // KMRSP errors are authoritative even for an unsecured caller:
                // otherwise a listener requiring encryption can fail while the
                // caller incorrectly transitions to Connected.
                match (self.crypto.is_some(), hs.get_km_response()) {
                    (true, Ok(Some(_))) => {}
                    (true, Ok(None)) => {
                        return Err(self.fail_caller_handshake("encryption enabled but no KMRSP"));
                    }
                    (false, Ok(Some(_))) => {
                        return Err(self.fail_caller_handshake(
                            "peer requires encryption but caller is unsecured",
                        ));
                    }
                    (_, Err(km_error)) => {
                        let reason = match km_error {
                            KmError::Unsecured => "peer is unsecured",
                            KmError::NoSecret => "peer has no secret",
                            KmError::BadSecret => "peer has wrong secret",
                            KmError::BadCryptoMode => "incompatible crypto mode",
                        };
                        return Err(self.fail_caller_handshake(reason));
                    }
                    (false, Ok(None)) => {}
                }

                self.handshake_state = HandshakeState::Completed;
                self.handshake_started_at = None;
                self.set_state(ConnectionState::Connected);
                self.start_time = Some(now);

                // TSBPD 時刻基準を計算
                let tsbpd_time_base = now.as_micros().saturating_sub(hsreq_timestamp as u64);

                // バッファ初期化
                self.init_buffers(now, hs.initial_packet_seq, tsbpd_time_base);

                // ハンドシェイクタイマークリア
                self.output_queue.push_back(ConnectionOutput::ClearTimer {
                    id: TimerId::Handshake,
                });

                // タイマー設定
                self.setup_connection_timers();

                self.clear_config_secrets();

                self.event_queue.push_back(ConnectionEvent::Connected);
            }
            // local patch (crates/srt-protocol/VENDOR.md): the
            // wire-format layer now correctly decodes a real libsrt
            // rejection response (handshake_type >= 1000) instead of
            // erroring on it, but nothing consumed `hs.reject_reason` --
            // this arm was the previous silent `_ => {}` catch-all, so a
            // rejected connection attempt would just hang until the
            // caller's own handshake timeout fired, with no reason ever
            // surfaced to the application. Live-verified against a real
            // libsrt listener configured to require a passphrase while
            // this caller connects without one (SRT_REJ_UNSECURE).
            HandshakeType::Rejected => {
                return Err(self.fail_caller_handshake(&format!(
                    "connection rejected by peer, reason={}",
                    hs.reject_reason.unwrap_or(-1)
                )));
            }
            _ => {}
        }

        Ok(())
    }

    fn handle_handshake_listener(
        &mut self,
        hs: HandshakePacket,
        hsreq_timestamp: u32,
        now: Timestamp,
    ) -> Result<(), Error> {
        // Rejection and timeout are terminal for this connection object.
        // A new attempt must get fresh listener state rather than reviving
        // policy-rejected or expired handshake material.
        if self.handshake_state == HandshakeState::Failed {
            return Ok(());
        }
        match hs.handshake_type {
            HandshakeType::Induction => {
                // INDUCTION リクエスト受信
                if self.handshake_state == HandshakeState::Completed {
                    self.retransmit_handshake();
                    return Ok(());
                }
                self.peer_socket_id = hs.socket_id;
                self.syn_cookie = self.options.syn_cookie.unwrap_or(0);
                if self.handshake_started_at.is_none() {
                    self.handshake_started_at = Some(now);
                    self.handshake_retry_sequence = 0;
                }

                // INDUCTION レスポンス送信
                self.send_induction_response(now);
                self.handshake_state = HandshakeState::InductionReceived;
                self.arm_handshake_timer(now);
            }
            HandshakeType::Conclusion => {
                // CONCLUSION リクエスト受信
                if self.handshake_state == HandshakeState::Completed {
                    self.retransmit_handshake();
                    return Ok(());
                }
                if self.handshake_state != HandshakeState::InductionReceived {
                    return Ok(());
                }

                // Cookie 検証
                if hs.syn_cookie != self.syn_cookie {
                    return Err(Error::handshake_rejected("invalid SYN cookie"));
                }

                // SRT 仕様 (Conclusion Response): Listener が Caller に優先権を持つのは
                // Cipher Family と Block Size のみ。ISN は Caller の値を採用する。
                self.initial_seq = hs.initial_packet_seq;

                // Stream ID を取得・保存
                if let Some(stream_id) = hs.get_sid_extension() {
                    self.peer_stream_id = Some(stream_id);
                }
                self.peer_group_extension = hs.get_group_extension();

                // KMREQ を処理して CryptoContext を作成
                if let Some(ref passphrase) = self.options.passphrase {
                    let Some(km_result) = hs.get_km_request() else {
                        return Err(self.fail_listener_km(
                            now,
                            KmError::NoSecret,
                            "encryption required but no KMREQ",
                        ));
                    };
                    let km = km_result?;
                    let crypto = match CryptoContext::new_receiver(
                        passphrase,
                        km.salt,
                        &km.wrapped_key,
                        km.key_flag,
                        km.key_length,
                    ) {
                        Ok(crypto) => crypto,
                        Err(error) => {
                            self.fail_listener_km(now, KmError::BadSecret, &error.reason);
                            return Err(error);
                        }
                    };
                    self.crypto = Some(crypto);
                    self.received_km = Some(km);
                } else if hs.get_km_request().is_some() {
                    return Err(self.fail_listener_km(
                        now,
                        KmError::Unsecured,
                        "caller requested encryption but listener is unsecured",
                    ));
                }

                // CONCLUSION レスポンス送信
                self.send_conclusion_response(now);
                self.handshake_state = HandshakeState::Completed;
                self.handshake_started_at = None;
                self.set_state(ConnectionState::Connected);
                self.start_time = Some(now);

                // TSBPD 時刻基準を計算
                let tsbpd_time_base = now.as_micros().saturating_sub(hsreq_timestamp as u64);

                // バッファ初期化
                self.init_buffers(now, hs.initial_packet_seq, tsbpd_time_base);

                self.output_queue.push_back(ConnectionOutput::ClearTimer {
                    id: TimerId::Handshake,
                });

                // タイマー設定
                self.setup_connection_timers();

                self.clear_config_secrets();

                self.event_queue.push_back(ConnectionEvent::Connected);
            }
            _ => {}
        }

        Ok(())
    }

    fn handle_ack(&mut self, pkt: ControlPacket, now: Timestamp) -> Result<(), Error> {
        if pkt.control_info.len() < 4 {
            return Ok(()); // 不正な ACK
        }

        let mut buf = pkt.control_info.as_slice();
        let ack_seq = crate::buf::read_u32(&mut buf)?;

        tracing::debug!(
            "received ACK, ack_seq={}, type_specific_info={}, control_info_len={}",
            ack_seq,
            pkt.type_specific_info,
            pkt.control_info.len()
        );

        // 送信バッファから ACK されたパケットを削除
        if let Some(ref mut sender) = self.sender {
            let before = sender.packets_in_buffer();
            sender.handle_ack(ack_seq);
            let after = sender.packets_in_buffer();
            tracing::debug!("sender buffer: {} -> {} packets", before, after);
        }

        // A full ACK carries receiver-side instantaneous measurements. Keep
        // the latest complete set so sender-only applications do not need to
        // parse control packets themselves.
        if pkt.control_info.len() >= 28 {
            let mut feedback = &pkt.control_info[4..];
            let rtt_micros = crate::buf::read_u32(&mut feedback)?;
            let rtt_variance_micros = crate::buf::read_u32(&mut feedback)?;
            let available_buffer_packets = crate::buf::read_u32(&mut feedback)?;
            let receiving_rate_packets_per_second = crate::buf::read_u32(&mut feedback)?;
            let link_capacity_packets_per_second = crate::buf::read_u32(&mut feedback)?;
            let receiving_rate_bytes_per_second = crate::buf::read_u32(&mut feedback)?;
            if let Some(sender) = self.sender.as_mut() {
                sender.record_peer_feedback(
                    rtt_micros,
                    rtt_variance_micros,
                    available_buffer_packets,
                    receiving_rate_packets_per_second,
                    link_capacity_packets_per_second,
                    receiving_rate_bytes_per_second,
                );
            }
        }

        // Full ACK の場合、ACKACK を送信
        if pkt.control_info.len() >= 16 {
            // Full ACK (RTT, RTTVar, Buffer Size, Rate を含む)
            self.send_ackack(pkt.type_specific_info, now);
        }

        Ok(())
    }

    fn handle_nak(&mut self, pkt: ControlPacket, now: Timestamp) -> Result<(), Error> {
        // NAK パケットから損失リストをパース
        let loss_list = parse_loss_list(
            &pkt.control_info,
            usize::try_from(self.flight_capacity_packets()).unwrap_or(usize::MAX),
        )?;

        // 送信バッファに損失を通知
        if let Some(ref mut sender) = self.sender {
            sender.handle_nak(&loss_list);
        }

        // 即座に再送処理
        self.process_retransmit(now);

        Ok(())
    }

    fn handle_ackack(&mut self, pkt: ControlPacket, now: Timestamp) -> Result<(), Error> {
        let ack_number = pkt.type_specific_info;

        // RTT を更新 (ACK 送信時刻はReceiverBuffer内で管理)
        if let Some(ref mut receiver) = self.receiver {
            receiver.handle_ackack(ack_number, now);
        }

        Ok(())
    }

    fn handle_shutdown(&mut self, now: Timestamp) -> Result<(), Error> {
        // 切断前に受信バッファをフラッシュ (TSBPD を無視して即時配信)
        if let Some(receiver) = self.receiver.as_mut() {
            receiver.set_tsbpd_enabled(false);
        }
        self.enqueue_ready_data(now);

        self.set_state(ConnectionState::Disconnected);
        self.event_queue.push_back(ConnectionEvent::Disconnected {
            reason: "peer shutdown".to_string(),
        });
        Ok(())
    }

    /// UserDefined パケットを処理 (KM Refresh)
    fn handle_user_defined(&mut self, pkt: ControlPacket, now: Timestamp) -> Result<(), Error> {
        // Subtype で KMREQ/KMRSP を判別
        // SRT_CMD_KMREQ = 3, SRT_CMD_KMRSP = 4
        const SRT_CMD_KMREQ: u16 = 3;
        const SRT_CMD_KMRSP: u16 = 4;

        match pkt.subtype {
            SRT_CMD_KMREQ => {
                // KM Refresh リクエストを受信 (受信側)
                let km = KmMessage::decode(&pkt.control_info)?;

                if let Some(ref mut crypto) = self.crypto {
                    // 新しい SEK を更新
                    crypto.update_sek(&km.wrapped_key, km.key_flag)?;

                    // KMRSP を送信
                    self.send_km_response(&km, now);
                }
            }
            SRT_CMD_KMRSP => {
                // KM Refresh レスポンスを受信 (送信側)
                // 正常に受信できれば、相手が新しい鍵を受け入れた
                // 特に処理は不要 (鍵切り替えは送信側のタイミングで行う)
            }
            _ => {
                // 未知の UserDefined パケットは無視
            }
        }

        Ok(())
    }

    /// KM Refresh をチェックして必要な処理を行う
    fn check_km_refresh(&mut self, _now: Timestamp) {
        // 事前通知が必要かチェック
        let Some(ref crypto) = self.crypto else {
            return;
        };

        if crypto.should_pre_announce() {
            // 外部に新しい SEK が必要なことを通知
            self.event_queue
                .push_back(ConnectionEvent::KeyRefreshNeeded {
                    key_length: crypto.key_length().len(),
                });
        }

        // 鍵切り替えが必要かチェック
        if let Some(ref mut crypto) = self.crypto {
            if crypto.should_switch_key() {
                crypto.switch_key();
            }

            // 古い鍵の廃棄が必要かチェック
            if crypto.should_decommission_old_key() {
                crypto.decommission_old_key();
            }
        }
    }

    /// KMREQ パケットを送信 (KM Refresh)
    fn send_km_request(&mut self, km_message: &KmMessage, now: Timestamp) {
        const SRT_CMD_KMREQ: u16 = 3;

        let pkt = ControlPacket {
            control_type: ControlType::UserDefined,
            subtype: SRT_CMD_KMREQ,
            type_specific_info: 0,
            timestamp: self.relative_timestamp(now),
            dest_socket_id: self.peer_socket_id,
            control_info: km_message.encode(),
        };

        let mut buf = Vec::new();
        pkt.encode(&mut buf);
        self.output_queue
            .push_back(ConnectionOutput::SendPacket(buf));
    }

    /// KMRSP パケットを送信 (KM Refresh)
    fn send_km_response(&mut self, km_message: &KmMessage, now: Timestamp) {
        const SRT_CMD_KMRSP: u16 = 4;

        let pkt = ControlPacket {
            control_type: ControlType::UserDefined,
            subtype: SRT_CMD_KMRSP,
            type_specific_info: 0,
            timestamp: self.relative_timestamp(now),
            dest_socket_id: self.peer_socket_id,
            control_info: km_message.encode(),
        };

        let mut buf = Vec::new();
        pkt.encode(&mut buf);
        self.output_queue
            .push_back(ConnectionOutput::SendPacket(buf));
    }

    /// 接続確立後のタイマーを設定
    fn setup_connection_timers(&mut self) {
        // キープアライブタイマー (1秒)
        self.output_queue.push_back(ConnectionOutput::SetTimer {
            id: TimerId::Keepalive,
            duration_micros: 1_000_000,
        });

        // ACK タイマー (10ms)
        self.output_queue.push_back(ConnectionOutput::SetTimer {
            id: TimerId::Ack,
            duration_micros: 10_000,
        });

        // NAK タイマー (初期値 20ms)
        self.output_queue.push_back(ConnectionOutput::SetTimer {
            id: TimerId::Nak,
            duration_micros: 20_000,
        });

        // 非活性タイマー (5秒)
        self.output_queue.push_back(ConnectionOutput::SetTimer {
            id: TimerId::Inactivity,
            duration_micros: INACTIVITY_TIMEOUT_MICROS,
        });
    }

    /// ACK パケットを送信
    fn send_ack(&mut self, now: Timestamp) {
        let receiver = match self.receiver.as_mut() {
            Some(r) => r,
            None => return,
        };

        let ack_info = receiver.generate_ack(now);
        let ack_number = receiver.ack_number();
        receiver.record_ack_sent();
        self.last_ack_time = Some(now);

        let mut control_info = Vec::new();
        write_u32(&mut control_info, ack_info.ack_seq);

        if !ack_info.is_light {
            // Full ACK (SRT 仕様に準拠)
            write_u32(&mut control_info, ack_info.rtt);
            write_u32(&mut control_info, ack_info.rtt_var);
            write_u32(&mut control_info, ack_info.available_buffer);
            write_u32(&mut control_info, ack_info.receiving_rate); // packets/sec
            write_u32(&mut control_info, ack_info.link_capacity); // packets/sec
            write_u32(&mut control_info, ack_info.recv_rate); // bytes/sec
        }

        let pkt = ControlPacket {
            control_type: ControlType::Ack,
            subtype: 0,
            type_specific_info: if ack_info.is_light { 0 } else { ack_number },
            timestamp: self.relative_timestamp(now),
            dest_socket_id: self.peer_socket_id,
            control_info,
        };

        let mut buf = Vec::new();
        pkt.encode(&mut buf);
        self.output_queue
            .push_back(ConnectionOutput::SendPacket(buf));
    }

    /// NAK パケットを送信
    fn send_nak(&mut self, loss_list: &[u32], now: Timestamp) {
        if loss_list.is_empty() {
            return;
        }

        if let Some(receiver) = self.receiver.as_mut() {
            receiver.record_nak_sent();
        }

        let control_info = encode_loss_list(loss_list);

        let pkt = ControlPacket {
            control_type: ControlType::Nak,
            subtype: 0,
            type_specific_info: 0,
            timestamp: self.relative_timestamp(now),
            dest_socket_id: self.peer_socket_id,
            control_info,
        };

        let mut buf = Vec::new();
        pkt.encode(&mut buf);
        self.output_queue
            .push_back(ConnectionOutput::SendPacket(buf));
    }

    /// Periodic NAK を送信
    fn send_periodic_nak(&mut self, now: Timestamp) {
        let receiver = match self.receiver.as_mut() {
            Some(r) => r,
            None => return,
        };

        if let Some(nak) = receiver.generate_periodic_nak() {
            self.send_nak(&nak.loss_list, now);
        }
        self.last_nak_time = Some(now);
    }

    /// ACKACK パケットを送信
    ///
    /// ACKACK は ACK に対する確認応答で、RTT 計算に使用される。
    /// SRT 仕様ではデータ部 0 バイトの 16 バイトパケットだが、
    /// libsrt 互換のため 4 バイトゼロパディングを追加して 20 バイトで送信する。
    /// 詳細は [`LIBSRT_COMPAT_PADDING`] を参照。
    fn send_ackack(&mut self, ack_number: u32, now: Timestamp) {
        let pkt = ControlPacket {
            control_type: ControlType::AckAck,
            subtype: 0,
            type_specific_info: ack_number,
            timestamp: self.relative_timestamp(now),
            dest_socket_id: self.peer_socket_id,
            // libsrt 互換: データ部 0 バイト → 4 バイトゼロパディング
            control_info: LIBSRT_COMPAT_PADDING.to_vec(),
        };

        let mut buf = Vec::new();
        pkt.encode(&mut buf);
        self.output_queue
            .push_back(ConnectionOutput::SendPacket(buf));
    }

    fn send_induction_request(&mut self, now: Timestamp) {
        let mut hs = HandshakePacket::new_induction_request(self.options.socket_id);
        hs.flow_window = self.flight_capacity_packets();
        if let Some(group) = self.options.group_extension {
            hs.add_group_extension(group);
        }
        let pkt = hs.encode(self.relative_timestamp(now), 0);
        let mut buf = Vec::new();
        pkt.encode(&mut buf);
        self.queue_handshake_packet(buf);
    }

    fn send_induction_response(&mut self, now: Timestamp) {
        let encryption_field = if self.options.passphrase.is_some() {
            self.options.key_length.to_encryption_field()
        } else {
            0
        };

        let mut hs = HandshakePacket::new_induction_response(
            self.options.socket_id,
            self.syn_cookie,
            encryption_field,
        );
        hs.flow_window = self.flight_capacity_packets();
        if let Some(group) = self.options.group_extension {
            hs.add_group_extension(group);
        }
        let pkt = hs.encode(self.relative_timestamp(now), self.peer_socket_id);
        let mut buf = Vec::new();
        pkt.encode(&mut buf);
        self.queue_handshake_packet(buf);
    }

    fn send_conclusion_request(&mut self, now: Timestamp) {
        let encryption_field = if self.options.passphrase.is_some() {
            self.options.key_length.to_encryption_field()
        } else {
            0
        };

        let has_encryption = self.options.passphrase.is_some();
        tracing::debug!(
            "sending CONCLUSION request, our_initial_seq={}, socket_id={:#x}, syn_cookie={:#x}",
            self.initial_seq,
            self.options.socket_id,
            self.syn_cookie
        );
        let mut hs = HandshakePacket::new_conclusion_request(
            self.options.socket_id,
            self.syn_cookie,
            self.initial_seq,
            encryption_field,
            has_encryption,
        );
        hs.flow_window = self.flight_capacity_packets();

        // SRT フラグ
        // CRYPT と REXMITFLG は常に設定 (レガシー互換性フラグ)
        // STREAM フラグは設定しない (Message モードを使用)
        let flags = srt_flags::TSBPDSND
            | srt_flags::TSBPDRCV
            | srt_flags::CRYPT
            | srt_flags::TLPKTDROP
            | srt_flags::PERIODICNAK
            | srt_flags::REXMITFLG;

        hs.add_hs_extension(self.options.srt_version, flags, self.options.tsbpd_delay);

        // 暗号化が有効な場合、KMREQ を追加
        if let Some(ref crypto) = self.crypto
            && let Ok(wrapped_key) = crypto.wrap_sek(crypto.current_key())
        {
            let km_message = KmMessage::new(
                crypto.current_key(),
                crypto.key_length(),
                *crypto.salt(),
                wrapped_key,
            );
            hs.add_km_request(&km_message);
        }

        // Stream ID が設定されている場合、SID 拡張を追加
        if let Some(ref stream_id) = self.options.stream_id {
            hs.add_sid_extension(stream_id);
        }

        if let Some(group) = self.options.group_extension {
            hs.add_group_extension(group);
        }

        // CONCLUSION リクエストは dest_socket_id = 0 で送信 (libsrt 互換)
        let pkt = hs.encode(self.relative_timestamp(now), 0);
        let mut buf = Vec::new();
        pkt.encode(&mut buf);
        self.queue_handshake_packet(buf);
    }

    fn send_conclusion_response(&mut self, now: Timestamp) {
        let encryption_field = if self.options.passphrase.is_some() {
            self.options.key_length.to_encryption_field()
        } else {
            0
        };

        let has_encryption = self.options.passphrase.is_some();
        let mut hs = HandshakePacket::new_conclusion_response(
            self.options.socket_id,
            self.syn_cookie,
            self.initial_seq,
            encryption_field,
            has_encryption,
        );
        hs.flow_window = self.flight_capacity_packets();

        // SRT フラグ
        // CRYPT と REXMITFLG は常に設定 (レガシー互換性フラグ)
        // STREAM フラグは設定しない (Message モードを使用)
        let flags = srt_flags::TSBPDSND
            | srt_flags::TSBPDRCV
            | srt_flags::CRYPT
            | srt_flags::TLPKTDROP
            | srt_flags::PERIODICNAK
            | srt_flags::REXMITFLG;

        hs.add_hs_response(self.options.srt_version, flags, self.options.tsbpd_delay);

        // 受信した KMREQ をそのまま KMRSP として返す
        if let Some(ref km) = self.received_km {
            hs.add_km_response(km);
        }

        if let Some(group) = self.options.group_extension {
            hs.add_group_extension(group);
        }

        let pkt = hs.encode(self.relative_timestamp(now), self.peer_socket_id);
        let mut buf = Vec::new();
        pkt.encode(&mut buf);
        self.queue_handshake_packet(buf);
    }

    /// Queue a protocol-level KM failure and make the listener attempt
    /// terminal. The caller receives the precise encryption mismatch instead
    /// of timing out or observing an unencrypted downgrade.
    fn fail_listener_km(&mut self, now: Timestamp, error: KmError, reason: &str) -> Error {
        let mut hs = HandshakePacket::new_conclusion_response(
            self.options.socket_id,
            self.syn_cookie,
            self.initial_seq,
            0,
            true,
        );
        hs.flow_window = self.flight_capacity_packets();
        let flags = srt_flags::TSBPDSND
            | srt_flags::TSBPDRCV
            | srt_flags::CRYPT
            | srt_flags::TLPKTDROP
            | srt_flags::PERIODICNAK
            | srt_flags::REXMITFLG;
        hs.add_hs_response(self.options.srt_version, flags, self.options.tsbpd_delay);
        hs.add_km_error(error);
        if let Some(group) = self.options.group_extension {
            hs.add_group_extension(group);
        }
        let packet = hs.encode(self.relative_timestamp(now), self.peer_socket_id);
        let mut bytes = Vec::new();
        packet.encode(&mut bytes);
        self.queue_handshake_packet(bytes);
        self.terminate_handshake();
        Error::handshake_rejected(reason)
    }

    fn fail_caller_handshake(&mut self, reason: &str) -> Error {
        self.terminate_handshake();
        Error::handshake_rejected(reason)
    }

    fn queue_handshake_packet(&mut self, packet: Vec<u8>) {
        self.last_handshake_packet = Some(packet.clone());
        self.output_queue
            .push_back(ConnectionOutput::SendPacket(packet));
    }

    fn retransmit_handshake(&mut self) {
        if let Some(packet) = self.last_handshake_packet.as_ref() {
            self.output_queue
                .push_back(ConnectionOutput::SendPacket(packet.clone()));
        }
    }

    fn handshake_timed_out(&self, now: Timestamp) -> bool {
        self.handshake_started_at
            .is_some_and(|started| now.saturating_sub(started) >= self.handshake_timeout_micros)
    }

    fn fail_handshake_timeout(&mut self) {
        if self.handshake_state == HandshakeState::Failed {
            return;
        }
        self.event_queue
            .push_back(ConnectionEvent::Error("handshake timeout".to_string()));
        self.terminate_handshake();
    }

    fn arm_handshake_timer(&mut self, now: Timestamp) {
        // Spread retries later by up to 20% to desynchronize fan-in without
        // violating libsrt's "at most one request per interval" cadence.
        let jitter = {
            use std::hash::{BuildHasher, Hasher};
            // Not cryptographic: per-connection nondeterministic PRNG via
            // RandomState (&mut self cannot hold state).
            let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
            hasher.write_u32(self.options.socket_id);
            hasher.write_u32(self.handshake_retry_sequence);
            hasher.write_u64(self.initial_seq.into());
            hasher.finish()
        };
        let spread = self.handshake_retry_interval_micros / 5;
        let interval = self
            .handshake_retry_interval_micros
            .saturating_add(jitter % spread.saturating_add(1));
        // The final timer is a deadline wake-up, not another early retry.
        let remaining = self
            .handshake_started_at
            .map(|started| {
                started
                    .add_micros(self.handshake_timeout_micros)
                    .saturating_sub(now)
            })
            .unwrap_or(self.handshake_timeout_micros);
        self.output_queue.push_back(ConnectionOutput::SetTimer {
            id: TimerId::Handshake,
            duration_micros: interval.min(remaining),
        });
    }

    /// Keepalive パケットを送信
    ///
    /// Keepalive は接続の生存確認に使用される。一定時間データの送受信がない場合に送信され、
    /// 相手側は Keepalive を受信することで接続がまだ有効であることを確認できる。
    /// SRT 仕様ではデータ部 0 バイトの 16 バイトパケットだが、
    /// libsrt 互換のため 4 バイトゼロパディングを追加して 20 バイトで送信する。
    /// 詳細は [`LIBSRT_COMPAT_PADDING`] を参照。
    fn send_keepalive(&mut self, now: Timestamp) {
        let pkt = ControlPacket {
            control_type: ControlType::Keepalive,
            subtype: 0,
            type_specific_info: 0,
            timestamp: self.relative_timestamp(now),
            dest_socket_id: self.peer_socket_id,
            // libsrt 互換: データ部 0 バイト → 4 バイトゼロパディング
            control_info: LIBSRT_COMPAT_PADDING.to_vec(),
        };
        let mut buf = Vec::new();
        pkt.encode(&mut buf);
        self.output_queue
            .push_back(ConnectionOutput::SendPacket(buf));
    }

    /// Shutdown パケットを送信
    ///
    /// Shutdown は接続の正常終了を通知する。このパケットを送信後、接続は切断状態に遷移する。
    /// SRT 仕様ではデータ部 0 バイトの 16 バイトパケットだが、
    /// libsrt 互換のため 4 バイトゼロパディングを追加して 20 バイトで送信する。
    /// 詳細は [`LIBSRT_COMPAT_PADDING`] を参照。
    fn send_shutdown(&mut self, now: Timestamp) {
        let pkt = ControlPacket {
            control_type: ControlType::Shutdown,
            subtype: 0,
            type_specific_info: 0,
            timestamp: self.relative_timestamp(now),
            dest_socket_id: self.peer_socket_id,
            // libsrt 互換: データ部 0 バイト → 4 バイトゼロパディング
            control_info: LIBSRT_COMPAT_PADDING.to_vec(),
        };
        let mut buf = Vec::new();
        pkt.encode(&mut buf);
        self.output_queue
            .push_back(ConnectionOutput::SendPacket(buf));
    }
}

/// 損失リストをパース (NAK パケットの control_info から)
fn parse_loss_list(data: &[u8], max_entries: usize) -> Result<Vec<u32>, Error> {
    if !data.len().is_multiple_of(4) {
        return Err(Error::invalid_data(
            "NAK loss list length is not a multiple of four",
        ));
    }
    let mut result = Vec::with_capacity((data.len() / 4).min(max_entries));
    let mut slice = data;

    let push = |result: &mut Vec<u32>, sequence: u32| -> Result<(), Error> {
        if result.len() >= max_entries {
            return Err(Error::invalid_data(format!(
                "NAK loss list exceeds negotiated limit of {max_entries} entries"
            )));
        }
        result.push(sequence);
        Ok(())
    };

    while !slice.is_empty() {
        let word = crate::buf::read_u32(&mut slice)?;

        if word & 0x8000_0000 != 0 {
            // Range: [word & 0x7FFF_FFFF, next_word]
            if slice.len() < 4 {
                return Err(Error::invalid_data("NAK range is missing its end"));
            }
            let start = word & 0x7FFF_FFFF;
            let end = crate::buf::read_u32(&mut slice)? & 0x7FFF_FFFF;
            let mut seq = start;
            loop {
                push(&mut result, seq)?;
                if seq == end {
                    break;
                }
                seq = seq.wrapping_add(1) & 0x7FFF_FFFF;
            }
        } else {
            // Single sequence number
            push(&mut result, word)?;
        }
    }

    Ok(result)
}

/// 損失リストをエンコード (NAK パケットの control_info 用)
/// 連続するシーケンス番号は範囲としてエンコードして圧縮する
fn encode_loss_list(loss_list: &[u32]) -> Vec<u8> {
    let mut result = Vec::new();

    if loss_list.is_empty() {
        return result;
    }

    // 連続するシーケンス番号を範囲として検出
    let mut i = 0;
    while i < loss_list.len() {
        let start = loss_list[i];
        let mut end = start;

        // 連続するシーケンス番号を探す
        while i + 1 < loss_list.len() {
            let next = loss_list[i + 1];
            // シーケンス番号のラップアラウンドを考慮した連続判定
            let expected_next = end.wrapping_add(1) & 0x7FFF_FFFF;
            if next == expected_next {
                end = next;
                i += 1;
            } else {
                break;
            }
        }

        if start == end {
            // 単一のシーケンス番号
            write_u32(&mut result, start & 0x7FFF_FFFF);
        } else {
            // 範囲: 2つ以上連続する場合は範囲エンコード
            // 最初の word は MSB を 1 に設定
            write_u32(&mut result, (start & 0x7FFF_FFFF) | 0x8000_0000);
            write_u32(&mut result, end & 0x7FFF_FFFF);
        }

        i += 1;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GroupType, SRTGROUP_MASK};

    #[test]
    fn test_connection_options_default() {
        let opts = ConnectionOptions::default();
        // Sans I/O 化により socket_id は外部から設定する必要がある
        assert_eq!(opts.socket_id, 0);
        assert!(opts.passphrase.is_none());
        assert!(opts.crypto_salt.is_none());
        assert!(opts.crypto_sek.is_none());
        assert_eq!(opts.key_length, KeyLength::Aes128);
    }

    #[test]
    fn test_caller_initial_state() {
        let conn = SrtConnection::new_caller(ConnectionOptions::default());
        assert_eq!(conn.state(), ConnectionState::Disconnected);
        assert_eq!(conn.role, ConnectionRole::Caller);
    }

    #[test]
    fn handshake_retry_is_not_armed_early() {
        let mut conn = SrtConnection::new_caller(ConnectionOptions::default());
        conn.connect(Timestamp::from_micros(0))
            .expect("caller connection starts");

        assert!(matches!(
            conn.poll_output(),
            Some(ConnectionOutput::SendPacket(_))
        ));
        let Some(ConnectionOutput::SetTimer {
            id: TimerId::Handshake,
            duration_micros,
        }) = conn.poll_output()
        else {
            panic!("caller arms its handshake retry");
        };
        assert!(duration_micros >= DEFAULT_HANDSHAKE_RETRY_INTERVAL_MICROS);
        assert!(duration_micros <= DEFAULT_HANDSHAKE_RETRY_INTERVAL_MICROS * 6 / 5);
    }

    #[test]
    fn handshake_deadline_covers_all_phases() {
        let mut conn = SrtConnection::new_caller(ConnectionOptions::default());
        conn.connect(Timestamp::from_micros(0))
            .expect("caller connection starts");
        while conn.poll_output().is_some() {}

        conn.handle_timer(
            TimerId::Handshake,
            Timestamp::from_micros(DEFAULT_HANDSHAKE_TIMEOUT_MICROS),
        )
        .expect("deadline processing succeeds");

        assert_eq!(conn.state(), ConnectionState::Disconnected);
        assert!(matches!(
            conn.poll_event(),
            Some(ConnectionEvent::StateChanged(ConnectionState::Induction))
        ));
        assert!(
            matches!(conn.poll_event(), Some(ConnectionEvent::Error(message)) if message == "handshake timeout")
        );
    }

    #[test]
    fn custom_handshake_timing_is_honored() {
        let mut conn = SrtConnection::new_caller(ConnectionOptions::default());
        conn.set_handshake_timing(400_000, 900_000);
        conn.connect(Timestamp::from_micros(100_000))
            .expect("caller connection starts");
        let _ = conn.poll_output();
        let Some(ConnectionOutput::SetTimer {
            duration_micros, ..
        }) = conn.poll_output()
        else {
            panic!("caller arms its handshake retry");
        };
        assert!((400_000..=480_000).contains(&duration_micros));

        conn.handle_timer(TimerId::Handshake, Timestamp::from_micros(1_000_000))
            .expect("deadline processing succeeds");
        assert_eq!(conn.state(), ConnectionState::Disconnected);
    }

    #[test]
    fn test_listener_initial_state() {
        let conn = SrtConnection::new_listener(ConnectionOptions::default());
        assert_eq!(conn.state(), ConnectionState::Listening);
        assert_eq!(conn.role, ConnectionRole::Listener);
    }

    #[test]
    fn listener_policy_configures_receive_window_before_conclusion() {
        let mut listener = SrtConnection::new_listener(ConnectionOptions::default());
        listener
            .set_listener_policy(None, KeyLength::Aes128, 2_000, 32_768, 8_548)
            .expect("listener policy is still mutable before conclusion");

        listener.init_buffers(Timestamp::from_micros(0), 100, 0);
        let ack = listener
            .receiver
            .as_mut()
            .expect("listener receiver exists")
            .generate_ack(Timestamp::from_micros(0));
        assert_eq!(ack.available_buffer, 8_548);

        listener.send_conclusion_response(Timestamp::from_micros(0));
        let ConnectionOutput::SendPacket(packet) = listener
            .poll_output()
            .expect("listener emits conclusion response")
        else {
            panic!("listener conclusion response is a packet");
        };
        let SrtPacket::Control(control) = SrtPacket::decode(&packet).expect("valid SRT packet")
        else {
            panic!("listener conclusion response is control");
        };
        let handshake = HandshakePacket::decode(&control).expect("valid handshake");
        assert_eq!(handshake.flow_window, 8_548);
    }

    #[test]
    fn unread_data_events_are_bounded_and_consume_receive_window() {
        let mut conn = SrtConnection::new_listener(ConnectionOptions {
            tsbpd_delay: 0,
            flow_window_packets: 3,
            receive_buffer_packets: 3,
            delivery_queue_packets: 2,
            ..ConnectionOptions::default()
        });
        conn.set_state(ConnectionState::Connected);
        let _ = conn.poll_event();
        let now = Timestamp::from_micros(0);
        conn.init_buffers(now, 0, 0);
        conn.receiver
            .as_mut()
            .expect("connected listener has a receiver")
            .set_tsbpd_enabled(false);

        // The protocol enforces a minimum 32-packet SRT flow window; fill it
        // while keeping only two payloads in the application queue.
        for sequence_number in 0..32 {
            conn.handle_data_packet(
                DataPacket::new(sequence_number, sequence_number, 0, 0, vec![1]),
                now,
            )
            .expect("data is accepted");
        }

        assert_eq!(conn.pending_data_events, 2);
        let stats = conn.receiver_stats().expect("receiver stats");
        assert_eq!(stats.packets_in_buffer, 30);
        assert_eq!(stats.available_buffer_packets, 0);

        assert!(matches!(
            conn.poll_event(),
            Some(ConnectionEvent::DataReceived { .. })
        ));
        assert_eq!(conn.pending_data_events, 1);
        conn.handle_timer(TimerId::Ack, Timestamp::from_micros(10_000))
            .expect("ACK timer drains newly admitted delivery");
        assert_eq!(conn.pending_data_events, 2);
        assert_eq!(
            conn.receiver_stats()
                .expect("receiver stats")
                .available_buffer_packets,
            1
        );
    }

    #[test]
    fn listener_encryption_replacement_clears_inapplicable_key_material() {
        let mut listener = SrtConnection::new_listener(ConnectionOptions {
            passphrase: Some("old-secret-123".to_owned()),
            crypto_salt: Some([7; 16]),
            crypto_sek: Some(vec![9; 16]),
            ..ConnectionOptions::default()
        });
        listener
            .set_listener_encryption(Some("tenant-secret-123".to_owned()), KeyLength::Aes256)
            .expect("listener policy window");

        assert_eq!(
            listener.options.passphrase.as_deref(),
            Some("tenant-secret-123")
        );
        assert_eq!(listener.options.key_length, KeyLength::Aes256);
        assert!(listener.options.crypto_salt.is_none());
        assert!(listener.options.crypto_sek.is_none());

        listener.set_state(ConnectionState::Connected);
        let error = listener
            .set_listener_bandwidth(Some(1_000_000))
            .expect_err("live policy mutation must be rejected");
        assert_eq!(error.kind, crate::ErrorKind::InvalidState);
    }

    #[test]
    fn caller_advertises_group_on_induction() {
        let group = GroupExtensionData {
            group_id: SRTGROUP_MASK | 0x1234,
            group_type: GroupType::Backup,
            flags: 0,
            weight: 1,
        };
        let mut conn = SrtConnection::new_caller(ConnectionOptions {
            socket_id: 17,
            group_extension: Some(group),
            ..ConnectionOptions::default()
        });
        conn.connect(Timestamp::from_micros(0))
            .expect("caller connection starts");
        let ConnectionOutput::SendPacket(packet) = conn.poll_output().expect("induction packet")
        else {
            panic!("caller must emit an induction packet");
        };
        let SrtPacket::Control(control) = SrtPacket::decode(&packet).expect("valid SRT packet")
        else {
            panic!("induction must be a control packet");
        };
        let handshake = HandshakePacket::decode(&control).expect("valid handshake");
        assert_eq!(handshake.get_group_extension(), Some(group));
    }

    #[test]
    fn test_loss_list_encode_decode_single() {
        // 単一のシーケンス番号
        let loss_list = vec![100, 200, 300];
        let encoded = encode_loss_list(&loss_list);
        let decoded = parse_loss_list(&encoded, loss_list.len()).expect("valid loss list");
        assert_eq!(decoded, loss_list);
    }

    #[test]
    fn test_loss_list_encode_decode_range() {
        // 連続するシーケンス番号は範囲としてエンコードされる
        let loss_list = vec![100, 101, 102, 103, 200, 201];
        let encoded = encode_loss_list(&loss_list);
        let decoded = parse_loss_list(&encoded, loss_list.len()).expect("valid loss list");
        assert_eq!(decoded, loss_list);
        // 範囲エンコードにより元の 6*4=24 バイトが 3*4=12 バイトに圧縮
        // (100-103 が 8 バイト、200-201 が 8 バイト = 16 バイト)
        assert_eq!(encoded.len(), 16);
    }

    #[test]
    fn test_loss_list_encode_decode_mixed() {
        // 単一と連続の混合
        let loss_list = vec![50, 100, 101, 102, 200];
        let encoded = encode_loss_list(&loss_list);
        let decoded = parse_loss_list(&encoded, loss_list.len()).expect("valid loss list");
        assert_eq!(decoded, loss_list);
    }

    #[test]
    fn test_loss_list_encode_empty() {
        let loss_list: Vec<u32> = vec![];
        let encoded = encode_loss_list(&loss_list);
        assert!(encoded.is_empty());
    }

    #[test]
    fn loss_list_limit_is_global_across_ranges_and_singles() {
        let mut encoded = Vec::new();
        write_u32(&mut encoded, 0x8000_0001);
        write_u32(&mut encoded, 3);
        write_u32(&mut encoded, 10);
        write_u32(&mut encoded, 11);

        let error = parse_loss_list(&encoded, 4).expect_err("fifth entry must exceed the cap");
        assert_eq!(error.kind, crate::ErrorKind::InvalidData);
        assert!(error.reason.contains("exceeds negotiated limit"));
    }

    #[test]
    fn loss_list_rejects_a_truncated_range() {
        let encoded = 0x8000_0001u32.to_be_bytes();
        let error = parse_loss_list(&encoded, 8).expect_err("range end is required");
        assert_eq!(error.kind, crate::ErrorKind::InvalidData);
    }
}
