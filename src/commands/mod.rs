//! eBPF commands for Nushell plugin
//!
//! ## Management Commands
//!
//! - [`EbpfAttach`] - Compile and attach a closure to a probe point
//! - [`EbpfDetach`] - Detach a probe by ID
//! - [`EbpfList`] - List active probes
//!
//! ## Data Commands
//!
//! - [`EbpfTrace`] - Stream events from `emit`
//! - [`EbpfCounters`] - Display `count` aggregations
//! - [`EbpfHistogram`] - Display `histogram` data
//! - [`EbpfStacks`] - Display stack traces
//!
//! ## Closure Commands
//!
//! Used inside eBPF closures (compiled to bytecode, not executed in Nushell):
//!
//! - [`Emit`] - Send value to userspace
//! - [`Count`] - Increment counter by key
//! - [`Histogram`] - Add to log2 histogram
//! - [`ReadStr`] / [`ReadKernelStr`] - Read strings from pointers
//! - [`StartTimer`] / [`StopTimer`] - Latency measurement
//! - [`KfuncCall`] - Invoke typed kernel kfuncs

mod attach;
mod counters;
mod detach;
mod helpers;
mod histogram;
mod list;
mod setup;
mod stacks;
mod trace;

use nu_protocol::{LabeledError, Span};

/// Create the "eBPF not supported" error for non-Linux platforms
#[cfg(not(target_os = "linux"))]
pub(crate) fn linux_only_error(span: Span) -> LabeledError {
    LabeledError::new("eBPF is only supported on Linux").with_label(
        "This command requires a Linux system with eBPF support",
        span,
    )
}

/// Validate and convert a probe ID from i64 to u32
///
/// Returns an error if the ID is negative or exceeds u32::MAX
pub(crate) fn validate_probe_id(id: i64, span: Span) -> Result<u32, LabeledError> {
    u32::try_from(id).map_err(|_| {
        LabeledError::new("Invalid probe ID")
            .with_label(
                format!("Probe ID must be between 0 and {}, got {}", u32::MAX, id),
                span,
            )
            .with_help("Use 'ebpf list' to see valid probe IDs")
    })
}

pub use attach::EbpfAttach;
pub use counters::EbpfCounters;
pub use detach::EbpfDetach;
pub use helpers::{
    Count, Emit, Histogram, KfuncCall, ReadKernelStr, ReadStr, StartTimer, StopTimer,
};
pub use histogram::EbpfHistogram;
pub use list::EbpfList;
pub use setup::EbpfSetup;
pub use stacks::EbpfStacks;
pub use trace::EbpfTrace;
