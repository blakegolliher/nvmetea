//! nvmetea per-command stage reconstruction (profile mode).
//!
//! Input: [`nvmetea_core::model::StageRecord`]s of sampled commands (Level 2
//! boundaries). Output: each command's partition into stages
//! ([`partition`]) and aggregate stage tables ([`aggregate`]), following the
//! accounting rules of `docs/latency-model.md` §6. Pure logic, no BPF.

pub mod aggregate;
pub mod partition;

pub use aggregate::{
    Dist, Excluded, FAMILIES, Group, GroupKey, Profile, QueueAgg, Timeline, size_class, size_class_label,
};
pub use partition::{Partition, Span, Stage, Variant, partition, variant_of};
