//! nvmetea Level 0 collectors: NVMe topology from sysfs, lifecycle tracking,
//! block statistics from `/proc/diskstats`, and kernel uevents.
//!
//! Everything here is read-only and works without privileges.

pub mod address;
pub mod diskstats;
pub mod fixture;
pub mod names;
pub mod scan;
pub mod sysfs;
pub mod tracker;
pub mod uevent;

pub use scan::scan;
pub use sysfs::SysRoot;
pub use tracker::{Change, Tracker, Transition, TransitionSource};
