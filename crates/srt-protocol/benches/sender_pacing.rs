//! Frozen-now admit count: idle path is one packet, demand path is two.
//!
//! This is the 600-connection Route B lever (one extra packet per visit)
//! and the incast cap (never more than two at one instant).

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use shiguredo_srt::{SenderBuffer, Timestamp};

fn primed(period: u64, repay: bool) -> SenderBuffer {
    let mut buf = SenderBuffer::new(0, 8192, 120);
    buf.set_packet_send_period(period);
    buf.set_repay_pacing_debt(repay);
    buf.record_send_time(Timestamp::from_micros(0));
    buf
}

fn admit_until_blocked(buf: &mut SenderBuffer, now: Timestamp) -> u32 {
    let mut admitted = 0u32;
    while buf.can_send_with_pacing(now) {
        buf.record_send_time(now);
        admitted += 1;
        if admitted > 8 {
            break;
        }
    }
    admitted
}

fn bench_pacing_admit(c: &mut Criterion) {
    let mut group = c.benchmark_group("sender_pacing");
    group.throughput(Throughput::Elements(1));
    let late = Timestamp::from_micros(2_500);

    group.bench_function("late_visit_idle", |b| {
        b.iter(|| {
            let mut buf = primed(1_000, false);
            black_box(admit_until_blocked(&mut buf, late))
        });
    });
    group.bench_function("late_visit_demand", |b| {
        b.iter(|| {
            let mut buf = primed(1_000, true);
            black_box(admit_until_blocked(&mut buf, late))
        });
    });
    group.finish();
}

criterion_group!(benches, bench_pacing_admit);
criterion_main!(benches);
