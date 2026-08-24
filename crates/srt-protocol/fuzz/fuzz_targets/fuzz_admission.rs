#![no_main]

use std::net::SocketAddr;
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use shiguredo_srt::{
    ConnectionOptions, ConnectionOutput, GroupExtensionData, GroupType, SRTGROUP_MASK,
    SrtConnection, Timestamp,
};
use srt_transport::{
    AdmissionOptions, AdmissionResolution, BondedInputPolicy, IngressTelemetry, ListenerPeerPolicy,
    PeerTable, PeerTableConfig, PolicyOverride, RejectionReason,
};

fn next_packet(connection: &mut SrtConnection) -> Option<Vec<u8>> {
    while let Some(output) = connection.poll_output() {
        if let ConnectionOutput::SendPacket(packet) = output {
            return Some(packet);
        }
    }
    None
}

// Always drives one real handshake through the admission table, then mutates
// its routing/authorization state with arbitrary datagrams from bounded source
// populations. This reaches stateful admission paths that random bytes alone
// almost never unlock while retaining malformed-input coverage.
fuzz_target!(|data: &[u8]| {
    let selector = data.first().copied().unwrap_or_default();
    let fuzz_bonded_admission = selector & 2 != 0;
    let max_peers = usize::from(selector % 16) + 1;
    let max_per_ip = usize::from(selector.rotate_left(2) % 8) + 1;
    let mut table = PeerTable::with_config(PeerTableConfig {
        max_peers,
        max_half_open_peers: max_peers,
        max_established_peers: max_peers,
        max_peers_per_ip: max_per_ip.min(max_peers),
        half_open_timeout: Duration::from_micros(u64::from(selector) + 1),
    });
    let telemetry = IngressTelemetry::new();
    let mut options = AdmissionOptions::basic(0x2000_0001, selector as u16, selector & 1 == 0);
    options.bonded_inputs = if selector & 4 == 0 {
        BondedInputPolicy::Reject
    } else {
        BondedInputPolicy::Accept
    };
    let peer = SocketAddr::from(([127, 0, 0, 1], 10_000));

    let mut caller = SrtConnection::new_caller(ConnectionOptions {
        socket_id: 0x1000_0001,
        stream_id: Some("fuzz/admission".to_owned()),
        group_extension: fuzz_bonded_admission.then_some(GroupExtensionData {
            group_id: SRTGROUP_MASK | u32::from(selector),
            group_type: if selector & 8 == 0 {
                GroupType::Broadcast
            } else {
                GroupType::Backup
            },
            flags: 0,
            weight: u16::from(selector),
        }),
        ..ConnectionOptions::default()
    });
    if caller.connect(Timestamp::default()).is_ok()
        && let Some(induction) = next_packet(&mut caller)
    {
        let _ = table.admit(
            peer,
            &induction,
            Timestamp::default(),
            &options,
            0,
            2,
            &telemetry,
        );
        let mut outbound = Vec::new();
        table.poll_outbound(Timestamp::default(), &mut outbound);
        for (_, packet) in outbound.drain(..) {
            let _ = caller.feed_recv_buf(&packet, Timestamp::from_micros(1));
        }
        if let Some(conclusion) = next_packet(&mut caller) {
            let _ = table.admit_with_resolver(
                peer,
                &conclusion,
                Timestamp::from_micros(2),
                &options,
                0,
                2,
                &telemetry,
                |_| match (selector >> 1) & 3 {
                    0 => AdmissionResolution::Accept,
                    1 => AdmissionResolution::Reject {
                        reason: RejectionReason::UNAUTHORIZED,
                    },
                    2 => AdmissionResolution::Configure(ListenerPeerPolicy {
                        latency: PolicyOverride::Set(Duration::from_millis(u64::from(selector))),
                        ..ListenerPeerPolicy::default()
                    }),
                    _ => AdmissionResolution::Defer,
                },
            );
        }
    }

    // A group-labelled bootstrap deliberately exercises admission and
    // telemetry, not arbitrary long-lived media. Fuzzing random post-
    // handshake datagrams against a single incomplete group belongs in the
    // protocol stream target; here it can build an unbounded pending sequence
    // gap and starve this admission target's time budget.
    if fuzz_bonded_admission {
        let mut events = Vec::new();
        table.poll_events(&mut events);
        let _ = table.bonded_stats();
        return;
    }

    let mut now = 3_u64;
    for (index, chunk) in data.get(1..).unwrap_or_default().chunks(64).enumerate() {
        let address = SocketAddr::from((
            [127, 0, (index % 4) as u8, ((index / 4) % 250 + 1) as u8],
            10_001_u16.saturating_add(index as u16),
        ));
        let _ = table.admit(
            address,
            chunk,
            Timestamp::from_micros(now),
            &options,
            index % 2,
            2,
            &telemetry,
        );
        now = now.saturating_add(u64::from(chunk.first().copied().unwrap_or(1)) + 1);
        let mut outbound = Vec::new();
        table.poll_outbound(Timestamp::from_micros(now), &mut outbound);
        let mut events = Vec::new();
        table.poll_events(&mut events);
        let _ = table.bonded_stats();
    }
    let _ = table.prune_half_open(Timestamp::from_micros(now.saturating_add(1_000)));
});
