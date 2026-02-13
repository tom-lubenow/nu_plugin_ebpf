//! eBPF plugin library for Nushell
//!
//! This library provides the core functionality for compiling Nushell closures
//! to eBPF bytecode and attaching them to kernel probe points.
//!
//! The library is used by the main binary and can be used for testing.

pub mod commands;
#[cfg(target_os = "linux")]
pub mod compiler;
#[cfg(target_os = "linux")]
pub mod kernel_btf;
#[cfg(target_os = "linux")]
pub mod loader;
#[cfg(target_os = "linux")]
pub mod symbolize;

pub use commands::*;

use nu_plugin::{Plugin, PluginCommand};

pub struct EbpfPlugin;

impl Plugin for EbpfPlugin {
    fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").into()
    }

    fn commands(&self) -> Vec<Box<dyn PluginCommand<Plugin = Self>>> {
        vec![
            // Main eBPF management commands
            Box::new(EbpfAttach),
            Box::new(EbpfCounters),
            Box::new(EbpfDetach),
            Box::new(EbpfHistogram),
            Box::new(EbpfList),
            Box::new(EbpfSetup),
            Box::new(EbpfStacks),
            Box::new(EbpfTrace),
            // Helper commands for use in eBPF closures
            Box::new(Emit),
            Box::new(Count),
            Box::new(Histogram),
            Box::new(StartTimer),
            Box::new(StopTimer),
            Box::new(ReadStr),
            Box::new(ReadKernelStr),
            Box::new(KfuncCall),
        ]
    }
}
