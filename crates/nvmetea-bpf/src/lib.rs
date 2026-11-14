//! nvmetea BPF support.
//!
//! Capability discovery (BTF, symbols, tracepoints, probe catalog) and the
//! CO-RE loaders of the BPF collectors: Level 1 (`core`), Level 2 (`driver`,
//! with the fentry `preflight`) and Level 3 (`tcpsock`).

pub mod bpfstats;
pub mod btf;
pub mod catalog;
pub mod core;
pub mod discovery;
pub mod driver;
pub mod preflight;
pub mod symbols;
pub mod tcpsock;
