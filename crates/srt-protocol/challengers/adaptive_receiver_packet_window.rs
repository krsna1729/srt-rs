//! Private adaptive sparse/dense receiver packet-window challenger.
//!
//! Re-exports the production adaptive packet window implementation for
//! comparative evidence harnesses, property tests, and fuzzing.

#![allow(dead_code)]
#![allow(clippy::module_inception)]

#[path = "../src/adaptive_receiver_packet_window.rs"]
mod adaptive_receiver_packet_window;

pub use adaptive_receiver_packet_window::*;
