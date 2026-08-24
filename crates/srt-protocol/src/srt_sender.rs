//! SRT 送信バッファ
//!
//! 送信パケットの保持と再送を管理する。
//!
//! ## 機能
//!
//! - 送信パケットのバッファリング (ACK 受信まで保持)
//! - NAK による再送キュー管理
//! - ACK によるバッファ解放
//! - 送信ウィンドウ管理

use std::collections::{BTreeMap, VecDeque};

use crate::srt_packet::{DataPacket, PacketPosition, SRT_HEADER_SIZE, sequence_less_than};
use crate::time::Timestamp;

/// "No configured limit" default max bandwidth, matching libsrt's own
/// `BW_INFINITE` (`srtcore/common.h`): 1 Gbps expressed in bytes/sec. Live
/// mode always paces off *some* bandwidth figure -- there is no "pacing
/// disabled" state in real SRT live mode, just a very generous default.
const DEFAULT_MAX_BANDWIDTH_BYTES_PER_SEC: u64 = 1_000_000_000 / 8;

/// Optimistic initial payload-size estimate for the pacing average, before
/// any real packets have been sent -- matches libsrt's `LiveCC` constructor
/// initializing `m_zSndAvgPayloadSize` to `maxPayloadSize()` (1500 MTU - 44
/// bytes IP/UDP/SRT overhead = 1456) rather than 0, so the first computed
/// pacing period isn't artificially tiny.
const INITIAL_AVG_PAYLOAD_SIZE_BYTES: f64 = 1456.0;

/// IIR averaging window for the payload-size estimate feeding the pacing
/// formula, matching libsrt's `avg_iir<128>` (`srtcore/congctl.cpp`,
/// `srtcore/utilities.h`): `avg = (avg * (LEN - 1) + new) / LEN`.
const AVG_PAYLOAD_SIZE_IIR_LEN: f64 = 128.0;

/// 送信パケットエントリ
#[derive(Debug, Clone)]
struct SentPacket {
    /// パケットデータ
    packet: DataPacket,
    /// 送信時刻
    sent_time: Timestamp,
    /// 再送回数
    retransmit_count: u32,
}

/// 送信バッファ
#[derive(Debug)]
pub struct SenderBuffer {
    /// 送信済みパケット (sequence_number -> SentPacket)
    packets: BTreeMap<u32, SentPacket>,

    /// 損失リスト (NAK で報告されたパケット)
    loss_list: VecDeque<u32>,

    /// 最古の未 ACK シーケンス番号
    oldest_unacked: u32,

    /// 次の送信シーケンス番号
    next_seq: u32,

    /// 次のメッセージ番号
    next_msg: u32,

    /// フローウィンドウサイズ
    flow_window: u32,

    /// 輻輳ウィンドウサイズ
    congestion_window: u32,

    /// バッファ最大サイズ (パケット数)
    #[expect(dead_code)]
    max_buffer_size: u32,

    /// レイテンシ (マイクロ秒)
    latency_us: u64,
    /// パケット送信間隔 (マイクロ秒)
    packet_send_period: u64,
    /// 最後のパケット送信時刻
    last_send_time: Option<Timestamp>,
    packet_send_period_overridden: bool,
    /// 送信パケット総数
    total_sent: u64,
    /// 送信バイト総数
    total_bytes_sent: u64,
    /// SRT datagram bytes emitted, including SRT headers and retransmissions.
    total_srt_bytes_sent: u64,
    /// Retransmitted SRT datagram bytes, including SRT headers.
    total_retransmitted_srt_bytes: u64,
    /// 送信ペイロードサイズの移動平均 (バイト、ペーシング計算用)
    avg_payload_size: f64,
    /// 最大帯域幅 (バイト/秒、`SRTO_MAXBW` 相当、ペーシング計算用)
    max_bandwidth_bytes_per_sec: u64,
    /// 再送総数 (累積、libsrt `pktRetransTotal` 相当)。`packets` に現存する
    /// エントリの `retransmit_count` 合計とは別に持つ -- ACK で購入済み
    /// パケットが `packets` から削除された後も、それが再送されていたという
    /// 事実自体は失われてはならない (低 RTT 環境では再送からごく短時間で
    /// ACK が届くため、ライブスキャン方式だと "再送は成功したのに
    /// total_retransmits はほぼ 0" という誤った統計になる -- 実際に
    /// docs/srt-pure-rust-plan.md Phase 4 の差分テストで踏んだ)。
    total_retransmits: u64,
    /// Packets declared lost by peer NAKs (cumulative).
    total_lost: u64,
    /// Locally discarded packets that exceeded the TLPKTDROP deadline.
    total_dropped: u64,
    /// Payload bytes in locally discarded TLPKTDROP packets.
    total_bytes_dropped: u64,
    /// Valid ACK control packets received from the peer.
    total_acks_received: u64,
    /// NAK control packets received from the peer.
    total_naks_received: u64,
    /// Most recent measurements advertised by a full peer ACK.
    peer_feedback: Option<PeerFeedback>,
}

#[derive(Debug, Clone, Copy)]
struct PeerFeedback {
    rtt_micros: u32,
    rtt_variance_micros: u32,
    available_buffer_packets: u32,
    receiving_rate_packets_per_second: u32,
    link_capacity_packets_per_second: u32,
    receiving_rate_bytes_per_second: u32,
}

impl SenderBuffer {
    /// 新しい送信バッファを作成
    ///
    /// LIVE モードでは輻輳ウィンドウはフローウィンドウに追従させる (TCP 風の
    /// AIMD 成長はしない) -- 実 libsrt の `LiveCC` も `m_dMaxCWndSize =
    /// flowWindowSize()`, `m_dCWndSize = m_dMaxCWndSize` としており、実際の
    /// 送信制御はペーシング (`packet_send_period`) が担う
    /// (`srtcore/congctl.cpp`)。
    pub fn new(initial_seq: u32, flow_window: u32, latency_ms: u16) -> Self {
        let mut buf = Self {
            packets: BTreeMap::new(),
            loss_list: VecDeque::new(),
            oldest_unacked: initial_seq,
            next_seq: initial_seq,
            next_msg: 1,
            flow_window,
            congestion_window: flow_window,
            max_buffer_size: 8192,
            latency_us: latency_ms as u64 * 1000,
            packet_send_period: 0,
            last_send_time: None,
            packet_send_period_overridden: false,
            total_sent: 0,
            total_bytes_sent: 0,
            total_srt_bytes_sent: 0,
            total_retransmitted_srt_bytes: 0,
            avg_payload_size: INITIAL_AVG_PAYLOAD_SIZE_BYTES,
            max_bandwidth_bytes_per_sec: DEFAULT_MAX_BANDWIDTH_BYTES_PER_SEC,
            total_retransmits: 0,
            total_lost: 0,
            total_dropped: 0,
            total_bytes_dropped: 0,
            total_acks_received: 0,
            total_naks_received: 0,
            peer_feedback: None,
        };
        buf.recompute_packet_send_period();
        buf
    }

    /// 次のシーケンス番号を取得
    pub fn next_sequence_number(&self) -> u32 {
        self.next_seq
    }

    pub(crate) fn synchronize_next_sequence_number(&mut self, sequence_number: u32) -> bool {
        if !self.packets.is_empty() {
            return false;
        }
        self.next_seq = sequence_number & 0x7FFF_FFFF;
        self.oldest_unacked = self.next_seq;
        true
    }

    /// 次のメッセージ番号を取得
    pub fn next_message_number(&self) -> u32 {
        self.next_msg
    }

    /// 送信可能かどうか (ウィンドウサイズのみチェック)
    pub fn can_send(&self) -> bool {
        let in_flight = self.packets_in_flight();
        in_flight < self.flow_window && in_flight < self.congestion_window
    }

    /// Whether an entire multi-packet message fits in the current windows.
    /// Partial messages are never admitted because their missing `Last`
    /// packet cannot be repaired by a later API call.
    pub fn can_send_message(&self, packet_count: usize) -> bool {
        let available = self
            .flow_window
            .min(self.congestion_window)
            .saturating_sub(self.packets_in_flight());
        u32::try_from(packet_count).is_ok_and(|count| count <= available)
    }

    /// 送信可能かどうか (パケットペーシングを含む)
    pub fn can_send_with_pacing(&self, now: Timestamp) -> bool {
        if !self.can_send() {
            return false;
        }

        // パケットペーシングチェック
        if self.packet_send_period > 0
            && let Some(last_time) = self.last_send_time
            && now.as_micros() < last_time.as_micros()
        {
            return false;
        }

        true
    }

    /// 次の送信可能時刻までの待機時間 (マイクロ秒)
    ///
    /// 即座に送信可能な場合は 0 を返す
    pub fn time_until_send(&self, now: Timestamp) -> u64 {
        if !self.can_send() {
            // バッファが満杯の場合は長めの待機時間を返す
            return 100_000; // 100ms
        }

        if self.packet_send_period == 0 {
            return 0;
        }

        if let Some(last_time) = self.last_send_time
            && now.as_micros() < last_time.as_micros()
        {
            return last_time.as_micros() - now.as_micros();
        }

        0
    }

    /// パケット送信間隔を設定 (マイクロ秒)
    pub fn set_packet_send_period(&mut self, period: u64) {
        self.packet_send_period = period;
        self.packet_send_period_overridden = true;
    }

    /// 送信時刻を記録
    pub fn record_send_time(&mut self, now: Timestamp) {
        self.last_send_time = Some(match (self.last_send_time, self.packet_send_period) {
            (Some(last_time), period) if period > 0 => {
                Timestamp::from_micros(last_time.as_micros().saturating_add(period))
            }
            (None, period) if period > 0 => {
                Timestamp::from_micros(now.as_micros().saturating_add(period))
            }
            _ => now,
        });
    }

    /// 送信中のパケット数
    pub fn packets_in_flight(&self) -> u32 {
        self.packets.len() as u32
    }

    /// バッファ内のパケット数
    pub fn packets_in_buffer(&self) -> usize {
        self.packets_in_flight() as usize
    }

    /// バッファが空かどうか
    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    /// 再送が必要なパケットがあるか
    pub fn has_retransmit(&self) -> bool {
        !self.loss_list.is_empty()
    }

    /// 輻輳ウィンドウを設定
    pub fn set_congestion_window(&mut self, cwnd: u32) {
        self.congestion_window = cwnd;
    }

    /// フローウィンドウを設定 (輻輳ウィンドウも追従させる、LIVE モードの
    /// 挙動は [`Self::new`] のコメント参照)
    pub fn set_flow_window(&mut self, flow_window: u32) {
        self.flow_window = flow_window;
        self.congestion_window = flow_window;
    }

    /// 最大帯域幅を設定 (`SRTO_MAXBW` 相当、バイト/秒)。ペーシング間隔を
    /// 即座に再計算する (libsrt `LiveCC::setMaxBW` -> `updatePktSndPeriod`
    /// に相当、`srtcore/congctl.cpp`)。`bytes_per_sec` が 0 の場合は
    /// libsrt 同様 `DEFAULT_MAX_BANDWIDTH_BYTES_PER_SEC` にフォールバック
    /// する。
    pub fn set_max_bandwidth(&mut self, bytes_per_sec: u64) {
        self.max_bandwidth_bytes_per_sec = if bytes_per_sec == 0 {
            DEFAULT_MAX_BANDWIDTH_BYTES_PER_SEC
        } else {
            bytes_per_sec
        };
        self.packet_send_period_overridden = false;
        self.recompute_packet_send_period();
    }

    /// 送信ペイロードサイズの移動平均を更新する (libsrt
    /// `LiveCC::updatePayloadSize` に相当、実送信のたびに呼ぶ)。
    ///
    fn record_sent_payload_size(&mut self, size: usize) {
        self.avg_payload_size = (self.avg_payload_size * (AVG_PAYLOAD_SIZE_IIR_LEN - 1.0)
            + size as f64)
            / AVG_PAYLOAD_SIZE_IIR_LEN;
        if !self.packet_send_period_overridden {
            self.recompute_packet_send_period();
        }
    }

    /// 平均ペイロードサイズと最大帯域幅からパケット送信間隔を計算する
    /// (libsrt `LiveCC::updatePktSndPeriod` に相当、`srtcore/congctl.cpp`)。
    fn recompute_packet_send_period(&mut self) {
        let period_us =
            1_000_000.0 * self.avg_payload_size / self.max_bandwidth_bytes_per_sec as f64;
        self.packet_send_period = period_us.round() as u64;
    }

    /// ペイロードをバッファに追加して送信パケットを生成
    pub fn push(
        &mut self,
        payload: Vec<u8>,
        timestamp: u32,
        dest_socket_id: u32,
        now: Timestamp,
    ) -> Option<DataPacket> {
        self.push_with_sequence(payload, timestamp, dest_socket_id, now, self.next_seq)
    }

    /// Push a packet using an externally coordinated sequence number.
    pub fn push_with_sequence(
        &mut self,
        payload: Vec<u8>,
        timestamp: u32,
        dest_socket_id: u32,
        now: Timestamp,
        sequence_number: u32,
    ) -> Option<DataPacket> {
        if !self.can_send() {
            return None;
        }

        if sequence_number != self.next_seq {
            return None;
        }

        let packet = DataPacket {
            sequence_number,
            position: PacketPosition::Single,
            order_flag: false,
            encryption_flag: 0,
            retransmitted: false,
            message_number: self.next_msg,
            timestamp,
            dest_socket_id,
            payload,
        };

        // バッファに保存
        self.packets.insert(
            sequence_number,
            SentPacket {
                packet: packet.clone(),
                sent_time: now,
                retransmit_count: 0,
            },
        );

        // 統計を更新
        self.total_sent += 1;
        self.total_bytes_sent += packet.payload.len() as u64;
        self.total_srt_bytes_sent = self
            .total_srt_bytes_sent
            .saturating_add((packet.payload.len() + SRT_HEADER_SIZE) as u64);
        self.record_sent_payload_size(packet.payload.len());

        // シーケンス番号とメッセージ番号を進める
        self.next_seq = self.next_seq.wrapping_add(1) & 0x7FFF_FFFF;
        self.next_msg = self.next_msg.wrapping_add(1) & 0x03FF_FFFF;

        Some(packet)
    }

    /// 大きなメッセージを分割して送信
    pub fn push_message(
        &mut self,
        payload: &[u8],
        max_payload_size: usize,
        timestamp: u32,
        dest_socket_id: u32,
        now: Timestamp,
    ) -> Vec<DataPacket> {
        // `slice::chunks(0)` panics. This is a public, application-supplied
        // sizing knob, so an invalid value must fail closed rather than take
        // down the process. Returning no packets matches the existing
        // backpressure behaviour of this convenience API.
        if max_payload_size == 0 {
            return Vec::new();
        }
        let chunks: Vec<&[u8]> = payload.chunks(max_payload_size).collect();
        let total_chunks = chunks.len();
        if !self.can_send_message(total_chunks) {
            return Vec::new();
        }
        let mut packets = Vec::with_capacity(total_chunks);

        for (i, chunk) in chunks.into_iter().enumerate() {
            let position = match (i, total_chunks) {
                (0, 1) => PacketPosition::Single,
                (0, _) => PacketPosition::First,
                (n, total) if n == total - 1 => PacketPosition::Last,
                _ => PacketPosition::Middle,
            };

            let packet = DataPacket {
                sequence_number: self.next_seq,
                position,
                order_flag: true, // 順序付きメッセージ
                encryption_flag: 0,
                retransmitted: false,
                message_number: self.next_msg,
                timestamp,
                dest_socket_id,
                payload: chunk.to_vec(),
            };

            self.packets.insert(
                self.next_seq,
                SentPacket {
                    packet: packet.clone(),
                    sent_time: now,
                    retransmit_count: 0,
                },
            );

            // 統計を更新
            self.total_sent += 1;
            self.total_bytes_sent += packet.payload.len() as u64;
            self.total_srt_bytes_sent = self
                .total_srt_bytes_sent
                .saturating_add((packet.payload.len() + SRT_HEADER_SIZE) as u64);
            self.record_sent_payload_size(packet.payload.len());

            self.next_seq = self.next_seq.wrapping_add(1) & 0x7FFF_FFFF;
            packets.push(packet);
        }

        // メッセージ番号は次のメッセージで進める
        if !packets.is_empty() {
            self.next_msg = self.next_msg.wrapping_add(1) & 0x03FF_FFFF;
        }

        packets
    }

    /// 再送パケットを取得
    ///
    /// `entry.sent_time` は元の送信時刻のまま更新しない (libsrt
    /// `CSndBuffer::Block::m_tsOriginTime` と同じ意図 --
    /// `srtcore/buffer_snd.h`/`.cpp` 参照。再送のたびにここを今の時刻へ
    /// 書き換えると、TLPKTDROP がシーケンス順に単調でなくなる: 再送された
    /// 古いパケットが「若返り」、一度も再送されていない新しいパケットより
    /// 後に期限切れ扱いになりかねない。それは TLPKTDROP の目的
    /// (配信期限を過ぎたら潔く諦めてレイテンシを抑える) にも反する --
    /// 再送を繰り返す限り永遠に期限切れにならなくなってしまう)。
    pub fn pop_retransmit(&mut self) -> Option<DataPacket> {
        while let Some(seq) = self.loss_list.pop_front() {
            if let Some(entry) = self.packets.get_mut(&seq) {
                entry.retransmit_count += 1;
                self.total_retransmits += 1;
                let wire_bytes = (entry.packet.payload.len() + SRT_HEADER_SIZE) as u64;
                self.total_srt_bytes_sent = self.total_srt_bytes_sent.saturating_add(wire_bytes);
                self.total_retransmitted_srt_bytes = self
                    .total_retransmitted_srt_bytes
                    .saturating_add(wire_bytes);

                let mut packet = entry.packet.clone();
                packet.retransmitted = true;
                return Some(packet);
            }
            // パケットが既に ACK されている場合はスキップ
        }
        None
    }

    /// ACK を処理してバッファを解放
    ///
    /// `ack_seq` は次に期待するシーケンス番号 (この番号未満は全て ACK)
    pub fn handle_ack(&mut self, ack_seq: u32) {
        self.total_acks_received = self.total_acks_received.saturating_add(1);
        self.discard_acked(ack_seq);
    }

    /// Discard acknowledged packets without recording a peer ACK. This is
    /// used by local sequence reconciliation paths.
    pub(crate) fn discard_acked(&mut self, ack_seq: u32) {
        // ack_seq より小さいシーケンス番号のパケットを全て削除。
        // BTreeMap::retain は削除対象キーを一時 Vec に集める必要がなく、
        // その場で不要エントリを取り除ける (毎 ACK ごとの割り当てを回避)。
        self.packets
            .retain(|&seq, _| !sequence_less_than(seq, ack_seq));

        // 損失リストからも削除
        self.loss_list
            .retain(|&seq| !sequence_less_than(seq, ack_seq));

        // oldest_unacked を更新
        if sequence_less_than(self.oldest_unacked, ack_seq) {
            self.oldest_unacked = ack_seq;
        }
    }

    /// NAK を処理して損失リストに追加
    pub fn handle_nak(&mut self, lost_sequences: &[u32]) {
        self.total_naks_received = self.total_naks_received.saturating_add(1);
        for &seq in lost_sequences {
            // バッファに存在するパケットのみ追加
            if self.packets.contains_key(&seq) && !self.loss_list.contains(&seq) {
                self.loss_list.push_back(seq);
                self.total_lost = self.total_lost.saturating_add(1);
            }
        }
    }

    /// Retain measurements carried by the most recent full ACK.
    pub(crate) fn record_peer_feedback(
        &mut self,
        rtt_micros: u32,
        rtt_variance_micros: u32,
        available_buffer_packets: u32,
        receiving_rate_packets_per_second: u32,
        link_capacity_packets_per_second: u32,
        receiving_rate_bytes_per_second: u32,
    ) {
        self.peer_feedback = Some(PeerFeedback {
            rtt_micros,
            rtt_variance_micros,
            available_buffer_packets,
            receiving_rate_packets_per_second,
            link_capacity_packets_per_second,
            receiving_rate_bytes_per_second,
        });
    }

    /// 期限切れパケットを削除 (TLPKTDROP)
    ///
    /// `oldest_unacked` から `next_seq` に向かってシーケンス順に走査し、
    /// 最初に期限切れでないパケットに達したら打ち切る -- libsrt
    /// `CSndBuffer::dropLateData` と同じ単調前方走査 (`srtcore/buffer_snd.cpp`)。
    /// `pop_retransmit` がもう `sent_time` を更新しないため (理由は
    /// そちらのドキュメント参照)、`sent_time` は送信順 = シーケンス順の
    /// まま単調に増加し続ける -- この走査の正しさの前提。`handle_ack` と
    /// 同じく `oldest_unacked` を更新するので、両者は「まだ生きている
    /// 先頭パケット」という同じ境界を共有し続け、パケット集合に穴が
    /// 生じない。
    pub fn drop_expired(&mut self, now: Timestamp) -> Vec<u32> {
        // TLPKTDROP 閾値: SRT latency の 1.25 倍、最低 1 秒
        // 仕様 (draft-sharabayko-srt.md の #too-late-packet-drop 節) の推奨値に従う。
        let threshold = (self.latency_us * 125 / 100).max(1_000_000);

        let mut dropped = Vec::new();
        let mut seq = self.oldest_unacked;
        while sequence_less_than(seq, self.next_seq) {
            match self.packets.get(&seq) {
                Some(entry) => {
                    let elapsed = now.as_micros().saturating_sub(entry.sent_time.as_micros());
                    if elapsed <= threshold {
                        break;
                    }
                    if let Some(entry) = self.packets.remove(&seq) {
                        self.total_dropped = self.total_dropped.saturating_add(1);
                        self.total_bytes_dropped = self
                            .total_bytes_dropped
                            .saturating_add(entry.packet.payload.len() as u64);
                        dropped.push(seq);
                    }
                }
                None => {
                    // 既に ACK 済みで存在しない -- 走査を継続する
                }
            }
            seq = seq.wrapping_add(1) & 0x7FFF_FFFF;
        }

        if sequence_less_than(self.oldest_unacked, seq) {
            self.oldest_unacked = seq;
        }

        // 損失リストからも削除
        self.loss_list.retain(|s| !dropped.contains(s));

        dropped
    }

    /// バッファ内の最古のパケット送信時刻を取得
    pub fn oldest_packet_time(&self) -> Option<Timestamp> {
        self.packets.values().next().map(|e| e.sent_time)
    }

    /// 統計情報を取得
    pub fn stats(&self) -> SenderStats {
        // 再送回数別カウント (こちらは意図的に現存パケットのみのライブ
        // スナップショット -- 「今バッファにあるパケットのうち何回再送
        // されたか」の分布であり、累積合計とは別の指標)
        let mut retransmits_once = 0u32;
        let mut retransmits_twice = 0u32;
        let mut retransmits_many = 0u32;
        // Accumulated in the histogram's own pass. The buffer runs to the
        // flow window (8192 packets by default) and this is sampled
        // periodically per connection, so a second walk of the same map is
        // a whole extra traversal per sample for one `sum()`.
        let mut payload_bytes_in_buffer = 0u64;
        for entry in self.packets.values() {
            payload_bytes_in_buffer += entry.packet.payload.len() as u64;
            match entry.retransmit_count {
                1 => retransmits_once += 1,
                2 => retransmits_twice += 1,
                n if n >= 3 => retransmits_many += 1,
                _ => {}
            }
        }
        let buffer_span_micros = self
            .packets
            .values()
            .next()
            .zip(self.packets.values().next_back())
            .map_or(0, |(oldest, newest)| {
                newest
                    .sent_time
                    .as_micros()
                    .saturating_sub(oldest.sent_time.as_micros())
            });
        let peer = self.peer_feedback;

        SenderStats {
            packets_in_buffer: self.packets.len() as u32,
            payload_bytes_in_buffer,
            packets_in_loss_list: self.loss_list.len() as u32,
            available_buffer_packets: self.flow_window.saturating_sub(self.packets.len() as u32),
            available_buffer_bytes: None,
            flow_window_packets: self.flow_window,
            congestion_window_packets: self.congestion_window,
            packets_in_flight: self.packets_in_flight(),
            buffer_span_micros,
            tsbpd_delay_micros: self.latency_us,
            packet_send_period_micros: self.packet_send_period,
            max_bandwidth_bytes_per_second: self.max_bandwidth_bytes_per_sec,
            peer_rtt_micros: peer.map(|feedback| feedback.rtt_micros),
            peer_rtt_variance_micros: peer.map(|feedback| feedback.rtt_variance_micros),
            peer_available_buffer_packets: peer.map(|feedback| feedback.available_buffer_packets),
            peer_receiving_rate_packets_per_second: peer
                .map(|feedback| feedback.receiving_rate_packets_per_second),
            peer_link_capacity_packets_per_second: peer
                .map(|feedback| feedback.link_capacity_packets_per_second),
            peer_link_capacity_bytes_per_second: peer.and_then(|feedback| {
                let packet_rate = u64::from(feedback.receiving_rate_packets_per_second);
                (packet_rate > 0).then(|| {
                    u64::from(feedback.link_capacity_packets_per_second)
                        .saturating_mul(u64::from(feedback.receiving_rate_bytes_per_second))
                        / packet_rate
                })
            }),
            peer_receiving_rate_bytes_per_second: peer
                .map(|feedback| feedback.receiving_rate_bytes_per_second),
            total_retransmits: self.total_retransmits,
            total_sent: self.total_sent,
            total_data_packets_sent: self.total_sent.saturating_add(self.total_retransmits),
            total_bytes_sent: self.total_bytes_sent,
            total_srt_bytes_sent: self.total_srt_bytes_sent,
            total_retransmitted_srt_bytes: self.total_retransmitted_srt_bytes,
            total_lost: self.total_lost,
            total_dropped: self.total_dropped,
            total_bytes_dropped: self.total_bytes_dropped,
            total_acks_received: self.total_acks_received,
            total_naks_received: self.total_naks_received,
            retransmits_once,
            retransmits_twice,
            retransmits_many,
        }
    }
}

/// 送信統計
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SenderStats {
    /// バッファ内のパケット数
    pub packets_in_buffer: u32,
    /// Exact payload-byte occupancy of the local send buffer.
    pub payload_bytes_in_buffer: u64,
    /// 損失リストのパケット数
    pub packets_in_loss_list: u32,
    /// Remaining local flow-window capacity, in packets.
    pub available_buffer_packets: u32,
    /// Byte capacity is unavailable because the send-buffer limit is packets.
    pub available_buffer_bytes: Option<u64>,
    /// Negotiated local flow window, in packets.
    pub flow_window_packets: u32,
    /// Current local congestion window, in packets.
    pub congestion_window_packets: u32,
    /// Packets sent but not yet cumulatively acknowledged.
    pub packets_in_flight: u32,
    /// Time span between oldest and newest buffered packets.
    pub buffer_span_micros: u64,
    /// Configured sender TSBPD delay.
    pub tsbpd_delay_micros: u64,
    /// Current pacing period between original packet sends.
    pub packet_send_period_micros: u64,
    /// Configured maximum pacing bandwidth.
    pub max_bandwidth_bytes_per_second: u64,
    /// RTT advertised by the peer's most recent full ACK.
    pub peer_rtt_micros: Option<u32>,
    /// RTT variance advertised by the peer's most recent full ACK.
    pub peer_rtt_variance_micros: Option<u32>,
    /// Peer receive-buffer availability from the most recent full ACK.
    pub peer_available_buffer_packets: Option<u32>,
    /// Peer receive rate from the most recent full ACK.
    pub peer_receiving_rate_packets_per_second: Option<u32>,
    /// Peer link-capacity estimate from the most recent full ACK.
    pub peer_link_capacity_packets_per_second: Option<u32>,
    /// Peer link-capacity estimate converted using its measured wire bytes per packet.
    pub peer_link_capacity_bytes_per_second: Option<u64>,
    /// Peer byte receive rate from the most recent full ACK.
    pub peer_receiving_rate_bytes_per_second: Option<u32>,
    /// 再送回数の合計
    pub total_retransmits: u64,
    /// Unique original DATA packets emitted.
    pub total_sent: u64,
    /// All emitted DATA packets, including retransmissions.
    pub total_data_packets_sent: u64,
    /// Payload bytes in unique original DATA packets.
    pub total_bytes_sent: u64,
    /// All emitted SRT datagram bytes, including SRT headers and retransmissions.
    ///
    /// This deliberately excludes IP and UDP headers, which belong to the
    /// caller-owned transport and vary between IPv4 and IPv6.
    pub total_srt_bytes_sent: u64,
    /// Retransmitted SRT datagram bytes, including SRT headers.
    pub total_retransmitted_srt_bytes: u64,
    /// Packets declared lost by peer NAKs.
    pub total_lost: u64,
    /// Packets locally discarded after their TLPKTDROP deadline.
    pub total_dropped: u64,
    /// Payload bytes in locally discarded packets.
    pub total_bytes_dropped: u64,
    /// Valid ACK control packets received.
    pub total_acks_received: u64,
    /// NAK control packets received.
    pub total_naks_received: u64,
    /// 1 回再送されたパケット数
    pub retransmits_once: u32,
    /// 2 回再送されたパケット数
    pub retransmits_twice: u32,
    /// 3 回以上再送されたパケット数
    pub retransmits_many: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sender_buffer_new() {
        let buf = SenderBuffer::new(1000, 8192, 120);
        assert_eq!(buf.next_sequence_number(), 1000);
        assert!(buf.can_send());
        assert!(buf.is_empty());
    }

    #[test]
    fn test_sender_buffer_push() {
        let mut buf = SenderBuffer::new(1000, 8192, 120);
        let now = Timestamp::from_micros(0);

        let packet = buf.push(vec![1, 2, 3], 100, 12345, now);
        assert!(packet.is_some());
        let pkt = packet.expect("送信パケットは Some になる想定");
        assert_eq!(pkt.sequence_number, 1000);
        assert_eq!(buf.next_sequence_number(), 1001);
        assert_eq!(buf.packets_in_flight(), 1);
    }

    #[test]
    fn fragmented_message_is_all_or_nothing_at_window_boundary() {
        let mut buf = SenderBuffer::new(1000, 2, 120);
        buf.set_congestion_window(2);
        let now = Timestamp::default();
        let before_sequence = buf.next_sequence_number();
        let before_message = buf.next_message_number();
        let packets = buf.push_message(&[7; 9], 4, 100, 1, now);
        assert!(packets.is_empty());
        assert_eq!(buf.packets_in_flight(), 0);
        assert_eq!(buf.next_sequence_number(), before_sequence);
        assert_eq!(buf.next_message_number(), before_message);
    }

    #[test]
    fn test_sender_buffer_ack() {
        let mut buf = SenderBuffer::new(1000, 8192, 120);
        let now = Timestamp::from_micros(0);

        // 3 パケット送信
        buf.push(vec![1], 100, 1, now);
        buf.push(vec![2], 100, 1, now);
        buf.push(vec![3], 100, 1, now);

        assert_eq!(buf.packets_in_flight(), 3);

        // ACK 1002 = パケット 1000, 1001 を ACK
        buf.handle_ack(1002);
        assert_eq!(buf.packets_in_flight(), 1);
    }

    #[test]
    fn test_sender_buffer_nak() {
        let mut buf = SenderBuffer::new(1000, 8192, 120);
        let now = Timestamp::from_micros(0);

        buf.push(vec![1], 100, 1, now);
        buf.push(vec![2], 100, 1, now);
        buf.push(vec![3], 100, 1, now);

        // パケット 1001 を損失報告
        buf.handle_nak(&[1001]);
        assert!(buf.has_retransmit());

        // 再送パケットを取得
        let retransmit = buf.pop_retransmit();
        assert!(retransmit.is_some());
        let pkt = retransmit.expect("再送パケットは Some になる想定");
        assert_eq!(pkt.sequence_number, 1001);
        assert!(pkt.retransmitted);
    }

    /// `stats().total_retransmits` must stay accurate after the
    /// retransmitted packet is later ACKed and purged from `packets` --
    /// it used to be computed by summing `retransmit_count` across
    /// currently-buffered packets only, so a fast ACK (as happens at low
    /// RTT, where the live differential test matrix in
    /// docs/srt-pure-rust-plan.md Phase 4 first caught this) made a
    /// successfully-recovered retransmission disappear from the stat
    /// entirely once its packet left the buffer.
    #[test]
    fn test_total_retransmits_survives_ack_purge() {
        let mut buf = SenderBuffer::new(1000, 8192, 120);
        let now = Timestamp::from_micros(0);

        buf.push(vec![1], 100, 1, now);
        buf.push(vec![2], 100, 1, now);
        buf.push(vec![3], 100, 1, now);

        buf.handle_nak(&[1001]);
        let retransmit = buf.pop_retransmit();
        assert!(retransmit.is_some());
        assert_eq!(buf.stats().total_retransmits, 1);

        // ACK past every buffered packet, including the one just
        // retransmitted -- it is now fully purged from `packets`.
        buf.handle_ack(1003);
        assert_eq!(buf.packets_in_flight(), 0);

        // The retransmission genuinely happened; the stat must still say so.
        assert_eq!(buf.stats().total_retransmits, 1);
    }

    #[test]
    fn test_sequence_less_than() {
        assert!(sequence_less_than(100, 200));
        assert!(!sequence_less_than(200, 100));
        assert!(!sequence_less_than(100, 100));

        // ラップアラウンド
        assert!(sequence_less_than(0x7FFF_FFFE, 1));
    }

    #[test]
    fn test_packet_pacing() {
        let mut buf = SenderBuffer::new(1000, 8192, 120);

        // 初期状態: パケットペーシングなし
        assert!(buf.can_send());
        assert!(buf.can_send_with_pacing(Timestamp::from_micros(0)));
        assert_eq!(buf.time_until_send(Timestamp::from_micros(0)), 0);

        // パケット送信間隔を設定 (1000 マイクロ秒 = 1ms)
        buf.set_packet_send_period(1000);

        // 送信時刻を記録
        buf.record_send_time(Timestamp::from_micros(0));

        // 直後は送信不可
        assert!(buf.can_send()); // ウィンドウのみのチェックは可
        assert!(!buf.can_send_with_pacing(Timestamp::from_micros(500))); // ペーシングで不可
        assert_eq!(buf.time_until_send(Timestamp::from_micros(500)), 500);

        // 1000μs 後は送信可能
        assert!(buf.can_send_with_pacing(Timestamp::from_micros(1000)));
        assert_eq!(buf.time_until_send(Timestamp::from_micros(1000)), 0);
    }

    #[test]
    fn test_packet_pacing_catches_up_after_late_wakeup() {
        let mut buf = SenderBuffer::new(1000, 8192, 120);
        buf.set_packet_send_period(1000);
        buf.record_send_time(Timestamp::from_micros(0));

        assert!(buf.can_send_with_pacing(Timestamp::from_micros(1500)));
        buf.record_send_time(Timestamp::from_micros(1500));
        assert!(!buf.can_send_with_pacing(Timestamp::from_micros(1999)));
        assert_eq!(buf.time_until_send(Timestamp::from_micros(1999)), 1);
        assert!(buf.can_send_with_pacing(Timestamp::from_micros(2000)));
    }

    #[test]
    fn test_packet_pacing_uses_payload_bandwidth() {
        let mut buf = SenderBuffer::new(1000, 8192, 120);
        buf.set_max_bandwidth(2_000_000);
        buf.record_send_time(Timestamp::from_micros(0));

        assert!(buf.time_until_send(Timestamp::from_micros(727)) > 0);
        assert_eq!(buf.time_until_send(Timestamp::from_micros(728)), 0);
    }

    #[test]
    fn test_handle_ack_wrap_around() {
        // BTreeMap の自然順とシーケンス番号順が一致しないラップアラウンド境界のテスト
        // take_while では途中で停止しラップ前のパケットが取りこぼされるが、
        // filter であれば全要素が巡回され正しく削除される
        let mut buf = SenderBuffer::new(0x7FFF_FFFD, 8192, 120);
        let now = Timestamp::from_micros(0);

        // 0x7FFF_FFFD, 0x7FFF_FFFE, 0x7FFF_FFFF (ラップ前)
        buf.push(vec![1], 100, 1, now);
        buf.push(vec![2], 100, 1, now);
        buf.push(vec![3], 100, 1, now);
        // 0, 1, 3 (ラップ後, 3 は ACK されずに残る)
        buf.push(vec![4], 100, 1, now);
        buf.push(vec![5], 100, 1, now);
        buf.push(vec![6], 100, 1, now);

        assert_eq!(buf.packets_in_flight(), 6);

        // ACK 2: 0, 1, 0x7FFF_FFFD, 0x7FFF_FFFE, 0x7FFF_FFFF が削除対象
        // BTreeMap 順: [0, 1, 3, 0x7FFF_FFFD, 0x7FFF_FFFE, 0x7FFF_FFFF]
        // take_while の場合: 0, 1 まで処理し 3 で停止 → ラップ前が残る
        // filter の場合: 全巡回 → ラップ前も削除される
        buf.handle_ack(2);
        assert_eq!(buf.packets_in_flight(), 1);
    }

    /// A sender whose peer has stopped ACKing must not grow without bound.
    ///
    /// This is the shape that produced 12 MB of resident memory *per
    /// connection* in the 600-connection bandwidth ladder: the receiver
    /// falls behind, ACKs dry up, `oldest_unacked` stops advancing, and the
    /// send buffer fills to the full flow window. TLPKTDROP is what is
    /// supposed to bound it -- the buffer should settle at roughly one
    /// drop-threshold worth of data (1 s floor), not at `flow_window`.
    #[test]
    fn buffer_stays_bounded_when_peer_stops_acking() {
        const BPS: u64 = 4_000_000;
        const PAYLOAD: usize = 1316;
        const FLOW_WINDOW: u32 = 8192;

        let mut buf = SenderBuffer::new(0, FLOW_WINDOW, 120);
        buf.set_max_bandwidth(BPS / 8);

        let mut high_water = 0u32;
        // 30 s of virtual time in 1 ms steps, never delivering an ACK.
        for ms in 0..30_000u64 {
            let now = Timestamp::from_micros(ms * 1000);
            while buf.can_send_with_pacing(now) {
                if buf.push(vec![0u8; PAYLOAD], ms as u32, 1, now).is_none() {
                    break;
                }
                buf.record_send_time(now);
            }
            // The ACK timer runs every 10 ms and is what drives TLPKTDROP.
            if ms % 10 == 0 {
                let _ = buf.drop_expired(now);
            }
            high_water = high_water.max(buf.packets_in_flight());
        }

        // One second of 4 Mbps is ~380 packets. Allow generous slack for the
        // 1.25x threshold and burst granularity, but nothing close to the
        // 8192-packet flow window.
        assert!(
            high_water < 2000,
            "send buffer reached {high_water} packets (flow window {FLOW_WINDOW}); \
             TLPKTDROP is not bounding it"
        );
    }

    #[test]
    fn test_drop_expired_threshold_1s_floor() {
        // latency_ms = 10 (10ms) の場合、1.25 * 10_000 = 12_500 < 1_000_000 なので
        // 閾値は 1_000_000 (1 秒) になる。
        let mut buf = SenderBuffer::new(0, 8192, 10);
        let send_time = Timestamp::from_micros(0);
        buf.push(vec![1], 100, 1, send_time);

        // elapsed = 1_000_000 は閾値と等しいので drop されない (> 判定)
        let now = Timestamp::from_micros(1_000_000);
        let dropped = buf.drop_expired(now);
        assert!(dropped.is_empty(), "等号では drop されないはず");

        // elapsed = 1_000_001 は閾値を超えるので drop される
        let now = Timestamp::from_micros(1_000_001);
        let dropped = buf.drop_expired(now);
        assert_eq!(dropped, vec![0], "閾値超過で drop されるはず");
    }

    #[test]
    fn test_drop_expired_threshold_125pct() {
        // latency_ms = 1000 (1000ms) の場合、1.25 * 1_000_000 = 1_250_000 > 1_000_000 なので
        // 閾値は 1_250_000 になる。
        let mut buf = SenderBuffer::new(0, 8192, 1000);
        let send_time = Timestamp::from_micros(0);
        buf.push(vec![1], 100, 1, send_time);

        // elapsed = 1_250_000 は閾値と等しいので drop されない (> 判定)
        let now = Timestamp::from_micros(1_250_000);
        let dropped = buf.drop_expired(now);
        assert!(dropped.is_empty(), "等号では drop されないはず");

        // elapsed = 1_250_001 は閾値を超えるので drop される
        let now = Timestamp::from_micros(1_250_001);
        let dropped = buf.drop_expired(now);
        assert_eq!(dropped, vec![0], "閾値超過で drop されるはず");
    }

    #[test]
    fn test_drop_expired_threshold_boundary() {
        // latency_ms = 800 の場合、1.25 * 800_000 = 1_000_000 = max(1_000_000, 1_000_000) = 1_000_000
        // 閾値はちょうど 1_000_000 になる (1 秒下限と 1.25 倍側の境界)。
        let mut buf = SenderBuffer::new(0, 8192, 800);
        let send_time = Timestamp::from_micros(0);
        buf.push(vec![1], 100, 1, send_time);

        // elapsed = 1_000_000 は閾値と等しいので drop されない
        let now = Timestamp::from_micros(1_000_000);
        let dropped = buf.drop_expired(now);
        assert!(dropped.is_empty(), "境界値の等号では drop されないはず");

        // elapsed = 1_000_001 は閾値を超えるので drop される
        let now = Timestamp::from_micros(1_000_001);
        let dropped = buf.drop_expired(now);
        assert_eq!(dropped, vec![0], "境界値の超過で drop されるはず");
    }

    #[test]
    fn test_retransmit_does_not_postpone_tlpktdrop() {
        // 回帰テスト: pop_retransmit が sent_time を今の時刻へ書き換えて
        // いた頃は、再送を繰り返すパケットが TLPKTDROP の対象から永遠に
        // 逃れられてしまっていた (libsrt の m_tsOriginTime は再送では
        // 更新されない -- 参照: pop_retransmit のドキュメント)。
        let mut buf = SenderBuffer::new(0, 8192, 10); // 閾値は 1 秒床
        let send_time = Timestamp::from_micros(0);
        buf.push(vec![1], 100, 1, send_time);

        buf.handle_nak(&[0]);
        // 元の送信からほぼ 1 秒経った時点で再送を試みる。
        let retransmitted = buf.pop_retransmit();
        assert!(retransmitted.is_some());

        // 元の送信から 1_000_001us -- 再送直後からはまだ 100_001us しか
        // 経っていないが、TLPKTDROP は元の送信時刻を基準にするべき。
        let now = Timestamp::from_micros(1_000_001);
        let dropped = buf.drop_expired(now);
        assert_eq!(
            dropped,
            vec![0],
            "再送しても元の送信時刻基準の期限切れ判定は変わらないはず"
        );
    }

    #[test]
    fn test_drop_expired_advances_oldest_unacked_like_handle_ack() {
        // drop_expired は handle_ack と同じ「まだ生きている先頭パケット」
        // 境界を共有するべき -- 片方だけが進むと、その境界より前に穴が
        // 残ってしまう。
        let mut buf = SenderBuffer::new(0, 8192, 10);
        buf.push(vec![1], 100, 1, Timestamp::from_micros(0));
        buf.push(vec![2], 100, 1, Timestamp::from_micros(0));
        buf.push(vec![3], 100, 1, Timestamp::from_micros(2_000_000));

        // 先頭 2 パケットだけ期限切れ、3 番目はまだ新しい。
        let dropped = buf.drop_expired(Timestamp::from_micros(1_000_001));
        assert_eq!(dropped, vec![0, 1]);
        assert_eq!(buf.packets_in_flight(), 1);

        // ACK 2 は既に drop_expired で消えた分をカバーするだけの no-op に
        // なるはずで、seq=2 (まだ生きている) には影響しない。
        buf.handle_ack(2);
        assert_eq!(buf.packets_in_flight(), 1);

        // seq=2 (シーケンス番号としては 2) を最終的に ACK すれば空になる。
        buf.handle_ack(3);
        assert_eq!(buf.packets_in_flight(), 0);
        assert!(buf.is_empty());
    }

    #[test]
    fn telemetry_counts_loss_retransmit_and_exact_srt_bytes() {
        let mut buf = SenderBuffer::new(10, 32, 10);
        buf.push(vec![1, 2, 3, 4], 0, 1, Timestamp::from_micros(0));

        buf.handle_nak(&[10]);
        buf.handle_nak(&[10]);
        let stats = buf.stats();
        assert_eq!(stats.total_naks_received, 2);
        assert_eq!(stats.total_lost, 1, "a queued loss is not counted twice");
        assert_eq!(stats.total_srt_bytes_sent, 20);

        assert!(buf.pop_retransmit().is_some());
        let stats = buf.stats();
        assert_eq!(stats.total_retransmits, 1);
        assert_eq!(stats.total_retransmitted_srt_bytes, 20);
        assert_eq!(stats.total_srt_bytes_sent, 40);
        assert_eq!(stats.total_data_packets_sent, 2);

        let dropped = buf.drop_expired(Timestamp::from_micros(1_000_001));
        assert_eq!(dropped, vec![10]);
        let stats = buf.stats();
        assert_eq!(stats.total_dropped, 1);
        assert_eq!(stats.total_bytes_dropped, 4);
        assert_eq!(stats.payload_bytes_in_buffer, 0);
    }

    #[test]
    fn push_message_with_zero_payload_limit_fails_closed() {
        let mut buf = SenderBuffer::new(0, 32, 10);
        let packets = buf.push_message(b"application supplied data", 0, 0, 1, Timestamp::default());
        assert!(packets.is_empty());
        assert!(buf.is_empty());
    }

    #[test]
    fn telemetry_retains_latest_full_ack_feedback() {
        let mut buf = SenderBuffer::new(0, 64, 120);
        buf.record_peer_feedback(5_000, 500, 60, 1_000, 2_000, 1_500_000);

        let stats = buf.stats();
        assert_eq!(stats.peer_rtt_micros, Some(5_000));
        assert_eq!(stats.peer_available_buffer_packets, Some(60));
        assert_eq!(stats.peer_link_capacity_bytes_per_second, Some(3_000_000));
    }
}
