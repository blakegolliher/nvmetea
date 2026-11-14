//! nvmetea exports. Presentation only: depends on `nvmetea-core` (and
//! `nvmetea-profile` types), never on collector crates.
//!
//! - [`prom`]: Prometheus text exposition of a snapshot (`nvmetea serve`).
//! - [`capture`]: the `nvmetea.capture/1` file (`nvmetea record`).
//! - [`compare`]: comparison of two captures with LAD (`nvmetea compare`).

pub mod capture;
pub mod compare;
pub mod prom;
