//! Test-only support for black-box protocol fixtures.
//!
//! Compiled for this crate's own tests and, with the opt-in `test-support`
//! feature, for dependents' tests. Production builds leave the feature off
//! and carry none of it.

pub mod wire_checker;
#[cfg(test)]
pub mod work;

#[cfg(test)]
pub use work::WorkCounters;
