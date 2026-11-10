//! Production-connection delivery/shutdown model: only complete, demonstrably
//! accepted messages enter the oracle. No receiver or assembler is simulated.
//!
//! Run: cargo test -p pbt --test prop_connection_delivery
//! All DATA arrives before its TSBPD deadline. The deterministic matrix includes
//! inactivity winning dispatch at the first deadline of a 129-fragment message;
//! a one-visit drain must not mistake its unread remainder for an impossible tail.

use std::collections::{HashMap, VecDeque};

use proptest::prelude::*;
use srt_proto::handshake::{ExtensionType, HandshakePacket, srt_flags};
use srt_proto::test_support::wire_checker::check_pair;
use srt_proto::wire::{ControlType, SrtPacket};
use srt_proto::{
    ConnectionEvent, ConnectionOptions, ConnectionOutput, ConnectionState, DisconnectReason,
    SrtConnection, TimerId, Timestamp,
};

const LATENCY_MICROS: u64 = 8_000_000;
const ACK_TICK_MICROS: u64 = 10_000;
const DELIVERY_TIMERS: [TimerId; 3] =
    [TimerId::Ack, TimerId::Inactivity, TimerId::DeliveryContinue];
const TIMER_ORDERS: [[TimerId; 3]; 6] = [
    [TimerId::Inactivity, TimerId::Ack, TimerId::DeliveryContinue],
    [TimerId::Inactivity, TimerId::DeliveryContinue, TimerId::Ack],
    [TimerId::Ack, TimerId::Inactivity, TimerId::DeliveryContinue],
    [TimerId::Ack, TimerId::DeliveryContinue, TimerId::Inactivity],
    [TimerId::DeliveryContinue, TimerId::Inactivity, TimerId::Ack],
    [TimerId::DeliveryContinue, TimerId::Ack, TimerId::Inactivity],
];

#[derive(Clone, Debug)]
enum Action {
    Advance(u64),
    Service(TimerId),
    Poll(u8),
    PeerShutdown,
}

fn action() -> impl Strategy<Value = Action> {
    prop_oneof![
        (0u64..=250_000).prop_map(Action::Advance),
        prop::sample::select(DELIVERY_TIMERS.to_vec()).prop_map(Action::Service),
        (0u8..=4).prop_map(Action::Poll),
        Just(Action::PeerShutdown),
    ]
}

struct AcceptedMessage {
    bytes: Vec<u8>,
    fragments: u32,
    first_sequence: u32,
    due: u64,
}

struct DeliveryModel {
    connection: SrtConnection,
    // Ordinary SetTimer/ClearTimer outputs, with one deadline per timer ID.
    timers: HashMap<TimerId, u64>,
    now: u64,
    expected: VecDeque<AcceptedMessage>,
    shutdown: Vec<u8>,
    first_due: u64,
    last_due: u64,
    accepted_packets: usize,
    delivered_messages: usize,
    terminal_states: usize,
    terminal_events: usize,
}

fn assert_no_handshake_errors(connection: &mut SrtConnection) {
    while let Some(event) = connection.poll_event() {
        assert!(!matches!(event, ConnectionEvent::Error(_)));
    }
}

impl DeliveryModel {
    fn new(
        fragments: &[usize],
        queue: u32,
        tlpktdrop: bool,
        wrap: bool,
        seed: u8,
        spacing: u64,
        tail: usize,
    ) -> Self {
        let options = ConnectionOptions {
            socket_id: 1,
            initial_seq: Some(if wrap { 0x7fff_fffd } else { 17 }),
            tsbpd_delay: 8_000,
            flow_window_packets: 1_024,
            receive_buffer_packets: 1_024,
            delivery_queue_packets: queue,
            ..ConnectionOptions::default()
        };
        let mut caller = SrtConnection::new_caller(options.clone());
        let mut receiver = SrtConnection::new_listener(ConnectionOptions {
            socket_id: 2,
            ..options
        });
        check_pair(&mut caller, &mut receiver);
        caller.connect(Timestamp::from_micros(0)).unwrap();
        let induction = packets(&drain_outputs(&mut caller)).remove(0);
        receiver
            .feed_recv_buf(&induction, Timestamp::from_micros(0))
            .unwrap();
        let response = packets(&drain_outputs(&mut receiver)).remove(0);
        let established = Timestamp::from_micros(1_000);
        caller.feed_recv_buf(&response, established).unwrap();
        let conclusion = packets(&drain_outputs(&mut caller)).remove(0);
        receiver
            .feed_recv_buf(&peer_drop_capability(conclusion, tlpktdrop), established)
            .unwrap();
        let receiver_outputs = drain_outputs(&mut receiver);
        let response = packets(&receiver_outputs).remove(0);
        caller
            .feed_recv_buf(&peer_drop_capability(response, tlpktdrop), established)
            .unwrap();
        assert_eq!(caller.state(), ConnectionState::Connected);
        assert_eq!(receiver.state(), ConnectionState::Connected);
        assert_no_handshake_errors(&mut caller);
        assert_no_handshake_errors(&mut receiver);
        drain_outputs(&mut caller);

        let mut model = Self {
            connection: receiver,
            timers: HashMap::new(),
            now: established.as_micros(),
            expected: VecDeque::new(),
            shutdown: Vec::new(),
            first_due: established.as_micros() + LATENCY_MICROS,
            last_due: established.as_micros() + LATENCY_MICROS,
            accepted_packets: 0,
            delivered_messages: 0,
            terminal_states: 0,
            terminal_events: 0,
        };
        model.record_outputs(receiver_outputs);
        let payload_size = caller.effective_max_payload_size();
        assert!((1..=payload_size).contains(&tail));
        // Five singleton successors ensure every queue cap (1..=4) can really
        // exert backpressure, independently of the fragmented message size.
        for (index, count) in fragments.iter().copied().chain([1; 5]).enumerate() {
            model.now = established.as_micros() + index as u64 * spacing;
            let length = (count - 1) * payload_size + tail;
            let bytes: Vec<_> = (0..length)
                .map(|offset| {
                    seed.wrapping_add(index as u8)
                        .wrapping_add((offset % 251) as u8)
                })
                .collect();
            let first_sequence = caller.next_sequence_number().unwrap();
            caller.send_message(&bytes, model.timestamp()).unwrap();
            let data = packets(&drain_outputs(&mut caller));
            assert_eq!(
                data.len(),
                count,
                "sender must emit the requested fragment boundary"
            );
            model.accept_datagrams(data);
            model.accepted_packets += count;
            model.last_due = model.now + LATENCY_MICROS;
            model.expected.push_back(AcceptedMessage {
                bytes,
                fragments: count as u32,
                first_sequence,
                due: model.last_due,
            });
        }
        // None of the acceptance assertions depends on application delivery.
        assert!(model.now < model.first_due);
        assert!(
            model.connection.poll_event().is_none(),
            "all DATA is initially future-due"
        );
        caller.disconnect(model.timestamp());
        let shutdowns = packets(&drain_outputs(&mut caller));
        assert_eq!(shutdowns.len(), 1);
        assert!(matches!(
            SrtPacket::decode(&shutdowns[0]).unwrap(),
            SrtPacket::Control(packet) if packet.control_type == ControlType::Shutdown
        ));
        model.shutdown = shutdowns.into_iter().next().unwrap();
        model.peer_shutdown();
        model
    }

    fn accept_datagrams(&mut self, data: Vec<Vec<u8>>) {
        for datagram in data {
            assert!(matches!(
                SrtPacket::decode(&datagram).unwrap(),
                SrtPacket::Data(_)
            ));
            let before = self.connection.receiver_stats().unwrap().total_received;
            self.connection
                .feed_recv_buf(&datagram, self.timestamp())
                .unwrap();
            let after = self.connection.receiver_stats().unwrap().total_received;
            assert_eq!(
                after,
                before + 1,
                "only accepted DATA belongs in the oracle"
            );
            self.collect_outputs();
        }
    }

    fn timestamp(&self) -> Timestamp {
        Timestamp::from_micros(self.now)
    }

    fn record_outputs(&mut self, outputs: Vec<ConnectionOutput>) {
        for output in outputs {
            match output {
                ConnectionOutput::SetTimer {
                    id,
                    duration_micros,
                } if DELIVERY_TIMERS.contains(&id) => {
                    self.timers.insert(id, self.now + duration_micros);
                }
                ConnectionOutput::ClearTimer { id } => {
                    self.timers.remove(&id);
                }
                // The peer has closed its send half; outgoing ACK/NAK/control
                // datagrams are still drained, but need no simulated response.
                _ => {}
            }
        }
    }

    fn collect_outputs(&mut self) {
        let outputs = drain_outputs(&mut self.connection);
        self.record_outputs(outputs);
    }

    fn service(&mut self, timer: TimerId) {
        if self
            .timers
            .get(&timer)
            .is_some_and(|deadline| *deadline <= self.now)
        {
            self.timers.remove(&timer);
            self.connection
                .handle_timer(timer, self.timestamp())
                .unwrap();
            self.collect_outputs();
        }
        self.invariant();
    }

    fn peer_shutdown(&mut self) {
        self.connection
            .feed_recv_buf(&self.shutdown, self.timestamp())
            .unwrap();
        self.collect_outputs();
        self.invariant();
    }

    fn poll_one(&mut self) -> bool {
        let Some(event) = self.connection.poll_event() else {
            return false;
        };
        match event {
            ConnectionEvent::DataReceived {
                payload,
                packet_count,
                sequence_number,
                ..
            } => {
                assert_eq!(self.terminal_states, 0, "DATA after terminal state");
                assert_eq!(self.terminal_events, 0, "DATA after terminal event");
                let expected = self
                    .expected
                    .pop_front()
                    .expect("unexpected/duplicate message");
                assert!(
                    self.now >= expected.due,
                    "DATA released before its source deadline"
                );
                assert_eq!(packet_count, expected.fragments);
                assert_eq!(sequence_number, expected.first_sequence);
                assert!(
                    payload
                        .chunks()
                        .flat_map(|chunk| chunk.iter())
                        .eq(expected.bytes.iter()),
                    "message {} bytes/order differ from accepted input",
                    self.delivered_messages,
                );
                self.delivered_messages += 1;
            }
            ConnectionEvent::StateChanged(ConnectionState::Disconnected) => {
                assert!(
                    self.expected.is_empty(),
                    "terminal state overtook accepted messages"
                );
                self.terminal_states += 1;
                assert_eq!(self.terminal_states, 1, "duplicate terminal state");
                assert_eq!(
                    self.terminal_events, 0,
                    "terminal event overtook state change"
                );
            }
            ConnectionEvent::Disconnected { reason } => {
                assert!(
                    self.expected.is_empty(),
                    "terminal event overtook accepted messages"
                );
                assert_eq!(reason, DisconnectReason::PeerShutdown);
                assert_eq!(self.terminal_states, 1);
                self.terminal_events += 1;
                assert_eq!(self.terminal_events, 1, "duplicate terminal event");
            }
            other => panic!("unexpected established-connection event: {other:?}"),
        }
        self.collect_outputs();
        self.invariant();
        true
    }

    fn invariant(&self) {
        if !self.expected.is_empty() {
            assert_eq!(
                self.connection.state(),
                ConnectionState::Connected,
                "shutdown truncated {} complete accepted messages",
                self.expected.len(),
            );
        }
    }

    fn apply(&mut self, action: &Action) {
        match *action {
            Action::Advance(delta) => self.now += delta,
            Action::Service(timer) => self.service(timer),
            Action::Poll(count) => {
                for _ in 0..count {
                    self.poll_one();
                }
            }
            Action::PeerShutdown => self.peer_shutdown(),
        }
        self.invariant();
    }

    fn fair_drain(mut self) {
        self.now = self.now.max(self.last_due);
        // Even queue=1 with one fragment admitted per ACK needs no more than
        // one turn per accepted packet, plus message/terminal polling slack.
        // Service only actually armed, due timers: inventing continuations
        // here would hide missing wakeups in the production connection.
        let turns = self.accepted_packets + self.expected.len() + 32;
        for _ in 0..turns {
            for timer in [TimerId::DeliveryContinue, TimerId::Ack, TimerId::Inactivity] {
                self.service(timer);
            }
            self.poll_one();
            if self.terminal_events == 1 {
                break;
            }
            self.now += ACK_TICK_MICROS;
        }
        assert!(
            self.expected.is_empty(),
            "fair drain stranded accepted messages"
        );
        assert_eq!(self.terminal_states, 1);
        assert_eq!(self.terminal_events, 1, "fair drain did not terminate");
        assert_eq!(self.connection.state(), ConnectionState::Disconnected);
        // Repeated SHUTDOWN and already-armed timer callbacks after terminal
        // must not resurrect delivery or produce another terminal notification.
        for _ in 0..4 {
            self.peer_shutdown();
            self.now += ACK_TICK_MICROS;
            for timer in DELIVERY_TIMERS {
                self.service(timer);
            }
            assert!(!self.poll_one(), "event repeated after terminal drain");
        }
    }
}

fn drain_outputs(connection: &mut SrtConnection) -> Vec<ConnectionOutput> {
    std::iter::from_fn(|| connection.poll_output().unwrap()).collect()
}

fn packets(outputs: &[ConnectionOutput]) -> Vec<Vec<u8>> {
    outputs
        .iter()
        .filter_map(|output| match output {
            ConnectionOutput::SendPacket(packet) => Some(packet.clone()),
            _ => None,
        })
        .collect()
}

// ConnectionOptions has no TLPKTDROP switch. Exercise ordinary HSREQ/HSRSP
// negotiation with that one standard peer capability cleared, not a private
// state setter, different transmission API, or custom DATA/control format.
fn peer_drop_capability(datagram: Vec<u8>, enabled: bool) -> Vec<u8> {
    if enabled {
        return datagram;
    }
    let SrtPacket::Control(control) = SrtPacket::decode(&datagram).unwrap() else {
        panic!("expected handshake control");
    };
    let mut handshake = HandshakePacket::decode(&control).unwrap();
    let extension = handshake.get_hs_extension().unwrap();
    let response = handshake
        .extensions
        .iter()
        .any(|ext| ext.ext_type == ExtensionType::HsRsp);
    handshake
        .extensions
        .retain(|ext| !matches!(ext.ext_type, ExtensionType::HsReq | ExtensionType::HsRsp));
    let flags = extension.srt_flags & !srt_flags::TLPKTDROP;
    if response {
        handshake.add_hs_response(
            extension.srt_version,
            flags,
            extension.recv_tsbpd_delay,
            extension.send_tsbpd_delay,
        );
    } else {
        handshake.add_hs_extension(
            extension.srt_version,
            flags,
            extension.recv_tsbpd_delay,
            extension.send_tsbpd_delay,
        );
    }
    let mut bytes = Vec::new();
    handshake
        .encode(control.timestamp, control.dest_socket_id)
        .encode(&mut bytes)
        .unwrap();
    bytes
}

#[test]
fn inactivity_first_preserves_129_fragment_message() {
    for queue in [1, 256] {
        for tlpktdrop in [false, true] {
            let mut model = DeliveryModel::new(&[129], queue, tlpktdrop, false, 7, 0, 17);
            model.now = model.first_due;
            model.service(TimerId::Inactivity);
            model.fair_drain();
        }
    }
}

#[test]
fn delivery_budget_backpressure_shutdown_boundary_matrix() {
    // 576 deterministic scenarios; at most 198 DATA packets per scenario.
    for fragments in [1, 63, 64, 65, 129, 193] {
        for queue in [1, 2, 4, 256] {
            for tlpktdrop in [false, true] {
                for wrap in [false, true] {
                    for order in TIMER_ORDERS {
                        let mut model =
                            DeliveryModel::new(&[fragments], queue, tlpktdrop, wrap, 29, 0, 17);
                        // First service inactivity while every message is still
                        // legitimately future-due, then at the exact deadline.
                        model.now += 5_000_000;
                        model.service(TimerId::Inactivity);
                        assert!(
                            !model.poll_one(),
                            "nothing is due at the inactivity interval"
                        );
                        model.now = model.first_due;
                        for timer in order {
                            model.service(timer);
                        }
                        // Pause application polling long enough to assemble the
                        // head even with queue=1, then saturate the event queue.
                        for _ in 0..fragments + 8 {
                            for timer in order {
                                model.service(timer);
                            }
                            model.now += ACK_TICK_MICROS;
                        }
                        if queue < 6 {
                            assert!(
                                model.connection.receiver_stats().unwrap().packets_in_buffer > 0,
                                "the unread application queue must backpressure its successors"
                            );
                        }
                        model.fair_drain();
                    }
                }
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn prop_connection_delivery_action_model(
        fragments in prop::collection::vec(prop::sample::select(vec![1usize, 63, 64, 65, 129, 193]), 1..=4),
        queue in 1u32..=4,
        tlpktdrop in any::<bool>(),
        wrap in any::<bool>(),
        seed in any::<u8>(),
        spacing in 0u64..=10_000,
        tail in 1usize..=1_456,
        order in 0usize..6,
        actions in prop::collection::vec(action(), 0..=48),
    ) {
        let mut model = DeliveryModel::new(&fragments, queue, tlpktdrop, wrap, seed, spacing, tail);
        // Up to 16 generated actions before playout (at most 4s advancement),
        // then the remaining actions interleave real due timers and app reads.
        let split = actions.len().min(16);
        for action in &actions[..split] {
            model.apply(action);
        }
        model.now = model.first_due;
        for timer in TIMER_ORDERS[order] {
            model.service(timer);
        }
        for action in &actions[split..] {
            model.apply(action);
        }
        // At most 777 accepted packets, 9 messages, 48 generated actions,
        // and 818 fair-drain turns per case; no sleeps, sockets, or wall clock.
        model.fair_drain();
    }
}
