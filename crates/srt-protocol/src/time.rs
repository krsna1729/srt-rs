/// A timestamp type for supplying time from outside, per the sans-I/O pattern.
///
/// Represents a moment in microseconds. The SRT protocol tracks time relative
/// to connection establishment, in microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Timestamp(pub u64);

impl Timestamp {
    /// Build a timestamp from microseconds.
    pub fn from_micros(micros: u64) -> Self {
        Self(micros)
    }

    /// Get the timestamp as microseconds.
    pub fn as_micros(&self) -> u64 {
        self.0
    }

    /// Get the timestamp as milliseconds.
    pub fn as_millis(&self) -> u64 {
        self.0 / 1000
    }

    /// Get the difference between two timestamps, in microseconds.
    pub fn saturating_sub(&self, other: Self) -> u64 {
        self.0.saturating_sub(other.0)
    }

    /// Add microseconds to the timestamp.
    pub fn add_micros(&self, micros: u64) -> Self {
        Self(self.0.saturating_add(micros))
    }

    /// Add milliseconds to the timestamp.
    pub fn add_millis(&self, millis: u64) -> Self {
        self.add_micros(millis.saturating_mul(1000))
    }
}

impl std::ops::Add<u64> for Timestamp {
    type Output = Self;

    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0.saturating_add(rhs))
    }
}

impl std::ops::Sub for Timestamp {
    type Output = u64;

    fn sub(self, rhs: Self) -> Self::Output {
        self.0.saturating_sub(rhs.0)
    }
}

#[cfg(test)]
mod tests {
    use super::Timestamp;

    #[test]
    fn add_millis_saturates_without_intermediate_overflow() {
        assert_eq!(
            Timestamp::default().add_millis(u64::MAX),
            Timestamp(u64::MAX)
        );
        assert_eq!(
            Timestamp::from_micros(u64::MAX - 500).add_millis(1),
            Timestamp(u64::MAX)
        );
    }
}
