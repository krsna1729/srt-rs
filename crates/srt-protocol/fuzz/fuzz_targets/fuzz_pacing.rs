#![no_main]

use libfuzzer_sys::fuzz_target;
use shiguredo_srt::{SenderBuffer, Timestamp};

fn admit_count(buf: &mut SenderBuffer, now: Timestamp) -> u32 {
    let mut admitted = 0u32;
    while buf.can_send_with_pacing(now) {
        buf.record_send_time(now);
        admitted += 1;
        assert!(admitted <= 2, "frozen-now admit exceeded Route B bound");
    }
    admitted
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 10 {
        return;
    }
    let demand = data[0] & 1 != 0;
    let discard = data[0] & 2 != 0;
    let period = 1 + u64::from(u16::from_le_bytes([data[1], data[2]]));
    let lateness = u64::from(u32::from_le_bytes([data[3], data[4], data[5], data[6]])) % 200_000;
    let gap_periods = 2 + u64::from(data[7] % 16);

    let mut buf = SenderBuffer::new(0, 8192, 120);
    buf.set_packet_send_period(period);
    buf.set_repay_pacing_debt(demand);
    buf.record_send_time(Timestamp::from_micros(0));

    let now = Timestamp::from_micros(period.saturating_add(lateness));
    let admitted = admit_count(&mut buf, now);
    if demand && lateness >= period {
        assert_eq!(admitted, 2);
    } else {
        assert_eq!(admitted, 1);
    }

    if discard {
        buf.discard_idle_pacing_debt(now);
        let resume = Timestamp::from_micros(
            now.as_micros()
                .saturating_add(period.saturating_mul(gap_periods)),
        );
        assert_eq!(admit_count(&mut buf, resume), 1);
    }
});
