//! The application workload, kept strictly separate from SRT's pacing.
//!
//! srt-bench historically had exactly one number called `bitrate`, and it
//! was used for two different things: the rate the benchmark's payload
//! source was nominally producing at, and `SRTO_MAXBW`, the protocol's
//! pacing ceiling. Because there was no source clock at all -- the sender
//! simply pushed payload whenever `can_send_with_pacing` said yes -- the
//! two were not merely conflated, they were the same mechanism. Every
//! "offer" figure was therefore measured against the pacing ceiling that
//! produced it, which is a tautology: it could not fail.
//!
//! They are different quantities:
//!
//! - **source payload bitrate** is a property of the workload. A camera
//!   encoding at 8 Mbit/s produces 8 Mbit/s of payload whether SRT is
//!   configured to pace at 4, 8 or 12 Mbit/s.
//! - **SRT bandwidth policy** is a property of the transport
//!   configuration: `SRTO_MAXBW`, or `SRTO_INPUTBW` + `SRTO_OHEADBW`.
//!
//! This module provides both, and the bounded queue between them.
//!
//! ## Why MAXBW below the source rate is not a lowered source
//!
//! `SRTO_MAXBW` paces on *wire* bytes: the pacing period is
//! `(avg_payload + SRT_HEADER_SIZE) / MAXBW`. A payload source at
//! `R` bit/s asks for `R / 8 / PAYLOAD_SIZE` packets per second, while
//! `MAXBW = R / 8` bytes/s permits only
//! `R / 8 / (PAYLOAD_SIZE + SRT_HEADER_SIZE)` -- about 1.2% fewer at
//! srt-bench's 1316-byte payload. The historical pairing of the two
//! (`BandwidthPolicy::LegacySourceFixed`) therefore cannot quite service
//! its own nominal source rate. That is a real, previously invisible
//! property of every srt-bench result, and it is now visible as a
//! source-offer shortfall instead of being definitionally absent.

use std::num::NonZeroU64;
use std::time::Duration;

use crate::PAYLOAD_SIZE;

/// How the benchmark configures SRT's pacing, expressed against the
/// source payload rate rather than as a second MAXBW implementation.
///
/// Resolves to [`srt_transport::Bandwidth`]; srt-bench does not compute
/// pacing itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum BandwidthPolicy {
    /// Leave SRT on its own ceiling (libsrt's 1 Gbit/s `BW_INFINITE`).
    /// The source rate then says nothing at all about pacing, which makes
    /// this the cleanest control for source-rate experiments.
    ProtocolDefault,
    /// What srt-bench has always done: `SRTO_MAXBW = source_bps / 8`
    /// bytes per second.
    ///
    /// The default, so an unchanged command line keeps producing
    /// unchanged numbers -- but recorded by name in every result row, so
    /// a row can never again be read as though the two were the same
    /// quantity. See the module doc for why this policy paces slightly
    /// below its own source rate.
    #[default]
    LegacySourceFixed,
    /// Explicit fixed `SRTO_MAXBW`, in bits per second, unrelated to the
    /// source rate.
    Fixed(u64),
    /// `SRTO_INPUTBW` = the source payload rate, with an explicit
    /// `SRTO_OHEADBW` allowance for retransmission. libsrt's own idiom
    /// for "I know my source rate; pace it with headroom".
    InputRelative { overhead_percent: u8 },
}

impl BandwidthPolicy {
    /// Parse the `--srt-bandwidth` / `srt-bandwidth` axis spelling.
    ///
    /// `protocol-default` | `legacy-source-fixed` | `fixed:<bps>` |
    /// `input-relative:<overhead-percent>`
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.split_once(':') {
            None => match value {
                "protocol-default" => Some(Self::ProtocolDefault),
                "legacy-source-fixed" => Some(Self::LegacySourceFixed),
                _ => None,
            },
            // A zero ceiling is rejected rather than accepted: SRT reads
            // MAXBW=0 as "unlimited", so `fixed:0` would silently mean the
            // exact opposite of what it says.
            Some(("fixed", bps)) => bps
                .parse()
                .ok()
                .and_then(NonZeroU64::new)
                .map(|bps| Self::Fixed(bps.get())),
            Some(("input-relative", percent)) => percent
                .parse()
                .ok()
                // libsrt accepts 5..=100; reject outside it here rather
                // than letting the protocol's validation fire mid-run.
                .filter(|p| (5..=100).contains(p))
                .map(|overhead_percent| Self::InputRelative { overhead_percent }),
            _ => None,
        }
    }

    /// How this policy is spelled back, in results and on a command line.
    #[must_use]
    pub fn name(self) -> String {
        match self {
            Self::ProtocolDefault => "protocol-default".to_string(),
            Self::LegacySourceFixed => "legacy-source-fixed".to_string(),
            Self::Fixed(bps) => format!("fixed:{bps}"),
            Self::InputRelative { overhead_percent } => {
                format!("input-relative:{overhead_percent}")
            }
        }
    }

    /// Resolve against a source payload rate to the transport crate's
    /// typed pacing bandwidth.
    ///
    /// A source rate under 8 bit/s cannot be expressed in the protocol's
    /// bytes-per-second units, so it clamps to 1 byte/s -- the smallest
    /// expressible ceiling -- rather than falling back to the protocol
    /// default. The fallback was wrong in the one direction that matters:
    /// the protocol default is libsrt's 1 Gbit/s `BW_INFINITE`, so a
    /// source-derived policy on a tiny source silently became the most
    /// permissive setting available instead of the most restrictive.
    #[must_use]
    pub fn resolve(self, source_bitrate_bps: u64) -> srt_transport::Bandwidth {
        use srt_transport::Bandwidth;
        // `max(1)`: never zero, which the protocol reads as unlimited.
        let source_bytes = || NonZeroU64::new(source_bitrate_bps / 8).unwrap_or(NonZeroU64::MIN);
        match self {
            Self::ProtocolDefault => Bandwidth::ProtocolDefault,
            Self::LegacySourceFixed => Bandwidth::BytesPerSecond(source_bytes()),
            // `Fixed(0)` cannot be constructed: `parse` rejects it.
            Self::Fixed(bps) => {
                Bandwidth::BitsPerSecond(NonZeroU64::new(bps).unwrap_or(NonZeroU64::MIN))
            }
            Self::InputRelative { overhead_percent } => Bandwidth::InputBytesPerSecond {
                input: source_bytes(),
                overhead_percent,
            },
        }
    }
}

/// What one connection's payload source did, as recorded in a result row.
///
/// Kept separate from protocol counters: these describe the *application*
/// offering work, not the transport carrying it, and the gap between them
/// is exactly what a source-rate benchmark is measuring.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SourceStats {
    /// Payload opportunities the source clock produced.
    pub generated: u64,
    /// Opportunities SRT accepted.
    pub accepted: u64,
    /// Times a send attempt found the protocol unwilling to take pending
    /// source work.
    ///
    /// Named for what it is: this counts *polls*, so it scales with how
    /// often the runtime's event loop visits the connection as well as
    /// with how blocked the source is. Two runtimes with different wake
    /// cadences will report different values for identical backpressure,
    /// so it is a diagnostic, not a workload metric. Use
    /// [`Self::blocked_streaks`] to compare across runtimes.
    pub refusal_polls: u64,
    /// Times the source went from being serviced to being refused.
    ///
    /// One per contiguous episode of backpressure, however many times the
    /// scheduler polled during it, so this does not leak the runtime's
    /// wake frequency into the workload measurement.
    pub blocked_streaks: u64,
    /// Largest the pending-source backlog ever got.
    pub backlog_hwm: u32,
    /// Opportunities dropped because the bounded backlog was full. A live
    /// source cannot buffer forever either; a benchmark that let it would
    /// be measuring its own memory growth.
    pub overflow: u64,
}

/// One connection's payload producer.
///
/// Ticks on its own clock at the configured source payload bitrate,
/// independently of SRT's pacing clock. Opportunities SRT will not take
/// accumulate in a backlog whose capacity is bounded by *configuration*,
/// never by run duration; past that they are dropped and counted.
///
/// Two properties matter and are both tested:
///
/// - **No catch-up burst.** A source that was not serviced for a while
///   does not get to fire every missed opportunity at once. The number of
///   opportunities that can be pending is the backlog capacity, full
///   stop.
/// - **No duration-dependent state.** The backlog is a counter, not a
///   queue of payloads (every packet's payload is the same constant
///   buffer), so a connection's source costs O(1) memory however long the
///   run is.
#[derive(Clone, Debug)]
pub struct SourceClock {
    /// Nanoseconds between opportunities. Always positive: a source rate
    /// is a [`NonZeroU64`], so there is no "zero means unpaced" state to
    /// confuse with "one bit per second".
    interval_nanos: u64,
    /// When the next opportunity is due, in nanoseconds since run start.
    /// Absolute rather than relative so the source rate stays exact over
    /// the run instead of drifting by one scheduling delay per tick.
    next_due_nanos: u64,
    /// The source starts when streaming is first serviced, not when the
    /// process began its handshake.
    started: bool,
    pending: u32,
    capacity: u32,
    /// Whether the last send attempt was refused, so a run of refusals
    /// counts as one blocked episode rather than one per poll.
    blocked: bool,
    stats: SourceStats,
}

impl SourceClock {
    /// Build a source producing `PAYLOAD_SIZE` payloads at
    /// `source_bitrate_bps`, with a backlog holding at most
    /// `backlog_capacity` opportunities.
    #[must_use]
    pub fn new(source_bitrate_bps: NonZeroU64, backlog_capacity: u32) -> Self {
        // Nanoseconds per payload, computed **in bits**:
        // `1e9 * 8 * PAYLOAD_SIZE / source_bps`.
        //
        // Bits, not bytes: dividing the rate by 8 first floors any source
        // under 8 bit/s to zero bytes per second, and zero used to select
        // an "unpaced" mode -- so `source_bps = 1` meant "generate as fast
        // as SRT accepts", the opposite of one bit per second. Working in
        // bits keeps 1..=7 bit/s meaning exactly that (one payload roughly
        // every three hours at 1 bit/s).
        //
        // Also expressed as a period rather than the reciprocal of an
        // integer packet rate, which would quantise an 8 Mbit/s source
        // (759.87 pkt/s) down to 759 and make the configured rate quietly
        // wrong. u128 throughout so a very slow source does not overflow
        // the intermediate; the result saturates at `u64::MAX` ns, about
        // 584 years, which is past any benchmark.
        // `max(1)`: past roughly 10.5 Tbit/s the true period floors to
        // zero nanoseconds, and a zero interval is a division by zero on
        // the very next tick. One nanosecond per payload is far beyond
        // anything reachable and keeps the field's invariant true.
        let interval_nanos = (1_000_000_000u128 * 8 * PAYLOAD_SIZE as u128
            / u128::from(source_bitrate_bps.get()))
        .clamp(1, u128::from(u64::MAX)) as u64;
        Self {
            interval_nanos,
            next_due_nanos: 0,
            started: false,
            pending: 0,
            capacity: backlog_capacity.max(1),
            blocked: false,
            stats: SourceStats::default(),
        }
    }

    /// Advance the source clock to `elapsed` since run start.
    ///
    /// O(1) regardless of how far behind the caller is: the number of
    /// newly due opportunities is computed arithmetically, then clamped to
    /// the backlog's free space, and the remainder is counted as overflow.
    /// This is what makes "no catch-up burst" a structural property rather
    /// than a hope.
    pub fn tick(&mut self, elapsed: Duration) {
        let now = elapsed.as_nanos().min(u64::MAX as u128) as u64;
        if !self.started {
            self.next_due_nanos = now;
            self.started = true;
        }
        if now < self.next_due_nanos {
            return;
        }
        let overdue = now - self.next_due_nanos;
        let due = overdue / self.interval_nanos + 1;
        // Advance the schedule by exactly the opportunities accounted for,
        // whether they were admitted or dropped: the source keeps its
        // absolute cadence, so a late tick does not shift the whole run.
        self.next_due_nanos = self
            .next_due_nanos
            .saturating_add(due.saturating_mul(self.interval_nanos));
        self.admit(due);
    }

    fn admit(&mut self, count: u64) {
        self.stats.generated = self.stats.generated.saturating_add(count);
        let free = u64::from(self.capacity - self.pending);
        let admitted = count.min(free);
        self.pending += admitted as u32;
        self.stats.overflow = self.stats.overflow.saturating_add(count - admitted);
        self.stats.backlog_hwm = self.stats.backlog_hwm.max(self.pending);
    }

    /// Opportunities waiting for SRT to accept them.
    #[must_use]
    pub fn pending(&self) -> u32 {
        self.pending
    }

    /// SRT took one payload.
    pub fn accepted(&mut self) {
        self.pending = self.pending.saturating_sub(1);
        self.stats.accepted = self.stats.accepted.saturating_add(1);
        self.blocked = false;
    }

    /// SRT refused; the opportunity stays pending. Recorded because
    /// "the source had work and the protocol would not take it" is the
    /// signal that a cell is transport-limited rather than source-limited.
    pub fn refused(&mut self) {
        self.stats.refusal_polls = self.stats.refusal_polls.saturating_add(1);
        if !self.blocked {
            self.blocked = true;
            self.stats.blocked_streaks = self.stats.blocked_streaks.saturating_add(1);
        }
    }

    /// Smallest wait to take while the transport is refusing pending work.
    ///
    /// Pacing is not the only reason a send can be refused -- an
    /// undrained output queue refuses too, and reports a pacing wait of
    /// zero while doing it. A zero wait with work still pending is then a
    /// hot spin. Before the source clock the backlog was discarded rather
    /// than retained, so the condition cleared on its own; now that
    /// pending work persists, this floor is what keeps a congested
    /// connection from burning a core on retries.
    ///
    /// Well under one pacing interval at any rate this harness runs, so a
    /// healthy sender never reaches it.
    const BLOCKED_FLOOR_MICROS: u64 = 500;

    /// Microseconds until the send path could next make progress.
    ///
    /// With work pending, that is whenever SRT's pacing next permits a
    /// send; with none, it is when the source next produces one. Waking
    /// earlier than this achieves nothing on the send path.
    #[must_use]
    pub fn wait_micros(&self, elapsed: Duration, srt_time_until_send_micros: u64) -> u64 {
        if self.pending > 0 {
            return if self.blocked {
                srt_time_until_send_micros.max(Self::BLOCKED_FLOOR_MICROS)
            } else {
                srt_time_until_send_micros
            };
        }
        if !self.started {
            return 0;
        }
        let now = elapsed.as_nanos().min(u64::MAX as u128) as u64;
        self.next_due_nanos.saturating_sub(now) / 1_000
    }

    #[must_use]
    pub fn stats(&self) -> SourceStats {
        self.stats
    }

    #[must_use]
    pub fn capacity(&self) -> u32 {
        self.capacity
    }
}

/// Default source backlog, in milliseconds of source at the configured
/// rate.
///
/// Bounded by *rate*, never by run duration, so a longer benchmark cannot
/// hide a growing backlog. 250 ms absorbs ordinary executor scheduling
/// jitter while still being far too small to absorb a sustained shortfall
/// -- a source the protocol cannot service overflows within a second or
/// two and says so.
pub const DEFAULT_SOURCE_BACKLOG_MS: u64 = 250;

/// Payload packets per second a source at `source_bitrate_bps` produces.
///
/// The one place this conversion lives. Both bounded-queue sizing rules
/// -- the source backlog here and the datapath/retry queue horizon in
/// [`crate::queue`] -- are "a horizon of the offered load", and they must
/// not be able to disagree about what that load is.
#[must_use]
pub fn packets_per_second(source_bitrate_bps: u64) -> u128 {
    u128::from(source_bitrate_bps / 8) / PAYLOAD_SIZE as u128
}

/// Backlog capacity in payload opportunities for `source_bitrate_bps`
/// held for `backlog_ms`, with a floor so a very slow source still has a
/// usable queue.
#[must_use]
pub fn backlog_capacity(source_bitrate_bps: u64, backlog_ms: u64) -> u32 {
    let capacity = packets_per_second(source_bitrate_bps) * u128::from(backlog_ms) / 1000;
    capacity.clamp(8, u32::MAX as u128) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Source rates in tests are literals; the production type is
    /// `NonZeroU64` so that "zero" cannot silently mean "unpaced".
    fn rate(bits_per_second: u64) -> NonZeroU64 {
        NonZeroU64::new(bits_per_second).expect("test source rate must be non-zero")
    }
    use proptest::prelude::*;

    fn started_clock(source_bitrate_bps: u64, capacity: u32) -> SourceClock {
        let mut clock = SourceClock::new(rate(source_bitrate_bps), capacity);
        clock.tick(Duration::ZERO);
        clock
    }

    #[test]
    fn policies_round_trip_through_their_spelling() {
        for spelling in [
            "protocol-default",
            "legacy-source-fixed",
            "fixed:4000000",
            "input-relative:25",
        ] {
            let parsed = BandwidthPolicy::parse(spelling).expect("parses");
            assert_eq!(parsed.name(), spelling);
        }
    }

    #[test]
    fn rejects_unusable_policy_spellings() {
        for spelling in [
            "",
            "legacy",
            "fixed",
            "fixed:not-a-number",
            "input-relative:4",
            "input-relative:101",
        ] {
            assert!(
                BandwidthPolicy::parse(spelling).is_none(),
                "{spelling:?} must not parse"
            );
        }
    }

    #[test]
    fn legacy_policy_reproduces_the_historical_maxbw() {
        // The whole point of keeping the mode: `max_bandwidth_bytes_per_sec
        // = source_bitrate_bps / 8`, byte for byte.
        let resolved = BandwidthPolicy::LegacySourceFixed
            .resolve(8_000_000)
            .resolve();
        assert_eq!(resolved.max_bytes_per_sec, Some(1_000_000));
        assert_eq!(resolved.input_bytes_per_sec, None);
    }

    #[test]
    fn policies_map_onto_protocol_options() {
        let default = BandwidthPolicy::ProtocolDefault
            .resolve(8_000_000)
            .resolve();
        assert_eq!(default.max_bytes_per_sec, None);
        assert_eq!(default.input_bytes_per_sec, None);

        let fixed = BandwidthPolicy::Fixed(4_000_000)
            .resolve(8_000_000)
            .resolve();
        assert_eq!(fixed.max_bytes_per_sec, Some(500_000));

        let relative = BandwidthPolicy::InputRelative {
            overhead_percent: 25,
        }
        .resolve(8_000_000)
        .resolve();
        assert_eq!(relative.max_bytes_per_sec, None);
        assert_eq!(relative.input_bytes_per_sec, Some(1_000_000));
        assert_eq!(relative.overhead_percent, 25);
    }

    #[test]
    fn source_rate_is_independent_of_the_bandwidth_policy() {
        // The headline invariant of this commit: the workload the source
        // is asked to produce does not move when pacing does.
        let baseline = started_clock(8_000_000, 64);
        for policy in [
            BandwidthPolicy::ProtocolDefault,
            BandwidthPolicy::LegacySourceFixed,
            BandwidthPolicy::Fixed(4_000_000),
            BandwidthPolicy::Fixed(12_000_000),
            BandwidthPolicy::InputRelative {
                overhead_percent: 25,
            },
        ] {
            // Resolving a policy never consults, and never changes, the
            // source clock.
            let _ = policy.resolve(8_000_000);
            let mut clock = started_clock(8_000_000, 64);
            clock.tick(Duration::from_secs(1));
            assert_eq!(
                clock.stats().generated,
                expected_generated(&baseline, Duration::from_secs(1)),
                "{policy:?} must not change the source's own schedule"
            );
        }
    }

    fn expected_generated(clock: &SourceClock, elapsed: Duration) -> u64 {
        let mut probe = clock.clone();
        probe.tick(elapsed);
        probe.stats().generated
    }

    #[test]
    fn source_produces_the_configured_packet_rate() {
        // 8 Mbit/s of 1316-byte payload = 1_000_000 / 1316 = 759 pkt/s.
        let mut clock = started_clock(8_000_000, u32::MAX);
        for ms in 1..=1000 {
            clock.tick(Duration::from_millis(ms));
            // Drain so the backlog never limits generation.
            while clock.pending() > 0 {
                clock.accepted();
            }
        }
        let generated = clock.stats().generated;
        assert!(
            (758..=761).contains(&generated),
            "expected ~759 opportunities in one second, got {generated}"
        );
    }

    #[test]
    fn backlog_is_bounded_and_overflow_is_counted() {
        let mut clock = started_clock(8_000_000, 16);
        // Never accept anything, and run far longer than the backlog.
        for ms in 1..=1000 {
            clock.tick(Duration::from_millis(ms));
        }
        let stats = clock.stats();
        assert_eq!(clock.pending(), 16, "backlog must stop at its capacity");
        assert_eq!(stats.backlog_hwm, 16);
        assert!(stats.overflow > 700, "overflow must be counted: {stats:?}");
        assert_eq!(stats.generated, stats.accepted + stats.overflow + 16);
    }

    #[test]
    fn a_long_stall_does_not_produce_a_catch_up_burst() {
        // One tick after a ten-second gap must not release ten seconds of
        // source at once -- that is the burst the bound exists to prevent.
        let mut clock = started_clock(8_000_000, 32);
        clock.tick(Duration::from_secs(10));
        assert_eq!(clock.pending(), 32);
        assert!(clock.stats().overflow > 7000);
    }

    #[test]
    fn backlog_state_does_not_grow_with_run_duration() {
        // Memory footprint is the same after one second and after an hour.
        let mut short = started_clock(8_000_000, 128);
        short.tick(Duration::from_secs(1));
        let mut long = started_clock(8_000_000, 128);
        long.tick(Duration::from_secs(3600));
        assert_eq!(short.pending(), 128);
        assert_eq!(long.pending(), 128);
        assert_eq!(short.capacity(), long.capacity());
    }

    #[test]
    fn source_keeps_its_absolute_cadence_across_late_ticks() {
        // A late tick must not shift the schedule: after 2s, a 759 pkt/s
        // source has produced ~1519 opportunities however coarsely it was
        // polled.
        let mut coarse = started_clock(8_000_000, u32::MAX);
        coarse.tick(Duration::from_millis(1900));
        coarse.tick(Duration::from_millis(2000));
        let mut fine = started_clock(8_000_000, u32::MAX);
        for ms in 1..=2000 {
            fine.tick(Duration::from_millis(ms));
        }
        let (a, b) = (coarse.stats().generated, fine.stats().generated);
        assert!(
            a.abs_diff(b) <= 1,
            "polling granularity must not change the source rate: {a} vs {b}"
        );
    }

    #[test]
    fn backpressure_is_distinct_from_overflow() {
        let mut clock = SourceClock::new(rate(8_000_000), 64);
        clock.tick(Duration::from_millis(10));
        assert!(clock.pending() > 0);
        clock.refused();
        let stats = clock.stats();
        assert_eq!(stats.refusal_polls, 1);
        assert_eq!(stats.blocked_streaks, 1);
        assert_eq!(stats.overflow, 0, "a refusal is not yet a drop");
    }

    #[test]
    fn wait_is_the_source_deadline_when_nothing_is_pending() {
        let clock = SourceClock::new(rate(8_000_000), 64);
        // Nothing ticked yet, so the first opportunity is due at t=0.
        assert_eq!(clock.wait_micros(Duration::ZERO, 5_000), 0);
        let mut clock = SourceClock::new(rate(8_000_000), 64);
        clock.tick(Duration::ZERO);
        clock.accepted();
        // Next due one interval (~1316 us) later; SRT's much longer
        // pacing wait must not be the one that is honoured.
        let wait = clock.wait_micros(Duration::ZERO, 5_000);
        assert!((1_200..=1_400).contains(&wait), "wait was {wait}");
    }

    /// A refusal that is not about pacing reports a zero pacing wait
    /// while the work stays pending, which is a hot spin. The floor only
    /// applies while actually blocked, so a healthy sender is untouched.
    #[test]
    fn a_blocked_sender_does_not_spin_on_a_zero_pacing_wait() {
        let mut clock = SourceClock::new(rate(8_000_000), 64);
        // The first tick starts the clock; the second leaves a real
        // backlog behind, which is the state the floor guards.
        clock.tick(Duration::ZERO);
        clock.tick(Duration::from_millis(100));
        assert!(clock.pending() > 1, "pending {}", clock.pending());
        // Not yet blocked: pacing says "now", so go now.
        assert_eq!(clock.wait_micros(Duration::from_millis(100), 0), 0);
        clock.refused();
        assert!(
            clock.wait_micros(Duration::from_millis(100), 0) >= 500,
            "a refused send with a zero pacing wait must still yield"
        );
        // A pacing wait longer than the floor still wins.
        assert_eq!(clock.wait_micros(Duration::from_millis(100), 9_000), 9_000);
        // Accepting clears the streak and the floor with it.
        clock.accepted();
        assert!(clock.pending() > 0);
        assert_eq!(clock.wait_micros(Duration::from_millis(100), 0), 0);
    }

    #[test]
    fn wait_is_the_pacing_deadline_when_work_is_pending() {
        let mut clock = SourceClock::new(rate(8_000_000), 64);
        clock.tick(Duration::from_millis(100));
        assert!(clock.pending() > 0);
        assert_eq!(clock.wait_micros(Duration::from_millis(100), 5_000), 5_000);
    }

    /// A source rate below 8 bit/s used to divide to zero bytes per
    /// second, and zero selected an "unpaced" mode -- so `source_bps = 1`
    /// meant "generate as fast as SRT accepts", the exact opposite of one
    /// bit per second. The cadence is now computed in bits, and the type
    /// no longer admits zero at all.
    #[test]
    fn sub_byte_source_rates_mean_what_they_say() {
        let mut clock = SourceClock::new(rate(1), u32::MAX);
        // 1 bit/s of 1316-byte payloads is one payload per 10528 seconds.
        clock.tick(Duration::ZERO);
        assert_eq!(clock.pending(), 1, "the first payload is due at t=0");
        clock.accepted();
        clock.tick(Duration::from_secs(3600));
        assert_eq!(
            clock.pending(),
            0,
            "an hour is not yet a second 1 bit/s payload"
        );
        clock.tick(Duration::from_secs(10_529));
        assert_eq!(clock.pending(), 1);
    }

    #[test]
    fn a_zero_pacing_ceiling_is_rejected_rather_than_read_as_unlimited() {
        // SRT reads MAXBW=0 as unlimited, so accepting `fixed:0` would
        // silently mean the opposite of what it says.
        assert!(BandwidthPolicy::parse("fixed:0").is_none());
    }

    /// A source too small to express in the protocol's bytes-per-second
    /// units must clamp to the *most* restrictive expressible ceiling,
    /// not fall back to libsrt's 1 Gbit/s `BW_INFINITE` default.
    #[test]
    fn sub_byte_source_rates_do_not_resolve_to_unlimited_pacing() {
        for policy in [
            BandwidthPolicy::LegacySourceFixed,
            BandwidthPolicy::InputRelative {
                overhead_percent: 25,
            },
        ] {
            let resolved = policy.resolve(1).resolve();
            assert_ne!(
                (resolved.max_bytes_per_sec, resolved.input_bytes_per_sec),
                (None, None),
                "{policy:?} fell back to the protocol default"
            );
            let configured = resolved
                .max_bytes_per_sec
                .or(resolved.input_bytes_per_sec)
                .expect("one of the two is set");
            assert_eq!(configured, 1, "smallest expressible ceiling");
        }
    }

    #[test]
    fn first_tick_starts_the_source_instead_of_counting_handshake_time() {
        let mut clock = SourceClock::new(rate(8_000_000), 64);
        clock.tick(Duration::from_secs(10));
        assert_eq!(clock.stats().generated, 1);
        assert_eq!(clock.stats().overflow, 0);
    }

    #[test]
    fn backlog_capacity_is_rate_relative_with_a_floor() {
        // 759 pkt/s for 250 ms.
        assert_eq!(backlog_capacity(8_000_000, 250), 189);
        // Rate-relative, not duration-relative: doubling the rate doubles
        // the capacity, and nothing about run length appears at all.
        assert_eq!(backlog_capacity(16_000_000, 250), 379);
        // Floor for a source too slow to fill even one packet slot.
        assert_eq!(backlog_capacity(1_000, 250), 8);
    }

    proptest! {
        #[test]
        fn arbitrary_tick_and_accept_sequences_preserve_the_backlog_bound(
            source_bps in 8u64..100_000_000,
            capacity in 1u32..512,
            steps in proptest::collection::vec((0u16..10_000, proptest::bool::ANY), 1..256),
        ) {
            let mut clock = SourceClock::new(rate(source_bps), capacity);
            let mut elapsed = Duration::ZERO;
            for (advance_micros, accept) in steps {
                elapsed = elapsed.saturating_add(Duration::from_micros(u64::from(advance_micros)));
                clock.tick(elapsed);
                if accept && clock.pending() > 0 {
                    clock.accepted();
                }
                let stats = clock.stats();
                prop_assert!(clock.pending() <= clock.capacity());
                prop_assert!(stats.backlog_hwm <= clock.capacity());
                prop_assert_eq!(
                    stats.generated,
                    stats.accepted + stats.overflow + u64::from(clock.pending())
                );
            }
        }

        #[test]
        fn generated_bandwidth_policies_round_trip(
            fixed_bps in 1u64..u64::MAX,
            overhead_percent in 5u8..=100,
        ) {
            for policy in [
                BandwidthPolicy::Fixed(fixed_bps),
                BandwidthPolicy::InputRelative { overhead_percent },
            ] {
                prop_assert_eq!(BandwidthPolicy::parse(&policy.name()), Some(policy));
            }
        }
    }
}
