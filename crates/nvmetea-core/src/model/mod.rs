//! Shared telemetry model. Collectors produce these types; presentation reads
//! them. No collector-specific structures appear here.

pub mod block;
pub mod nvme;
pub mod stage;
pub mod tcp;
pub mod topology;

pub use block::{BlockRates, DiskCounters, NsAccounting};
pub use nvme::{BpfCounters, Histogram, LatMetric, NvmeSample, Op, QueueCounters};
pub use stage::{Boundaries, StageRecord};
pub use tcp::{
    QueueSocket, SkMem, SockEventCounters, SocketSource, TcpEvent, TcpEventKind, TcpInfo, TcpSocket, TcpState,
};
pub use topology::{
    Controller, ControllerKey, CtrlState, FabricAddress, Namespace, NsKind, NsPath, ScanIssue, Subsystem, Topology,
};
