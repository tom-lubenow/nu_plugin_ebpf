//! Kernel BTF (BPF Type Format) parsing
//!
//! This module provides access to kernel type information from `/sys/kernel/btf/vmlinux`.
//! It enables:
//! - Tracepoint context layout lookup
//! - Function signature queries
//! - Type annotation detection (__user pointers)
//! - Function existence validation

mod pt_regs;
mod service;
mod tracepoint;
mod types;

pub use pt_regs::{PtRegsError, PtRegsOffsets};
pub use service::{FunctionCheckResult, KernelBtf};
pub use tracepoint::TracepointContext;
pub use types::{FieldInfo, TypeInfo};
