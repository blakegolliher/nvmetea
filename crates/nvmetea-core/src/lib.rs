//! nvmetea core: the telemetry model shared by every collector and output.
//!
//! Units are explicit in field names (`_ms`, `_us`, `_bytes`, `_per_s`).
//! Values that could not be observed are `None` with a [`quality::Reason`];
//! they are never zero-filled.

pub mod engine;
pub mod model;
pub mod nvme_engine;
pub mod quality;
pub mod rate;

pub use quality::{Obs, Quality, Reason};

#[doc(hidden)]
pub mod testrng;
