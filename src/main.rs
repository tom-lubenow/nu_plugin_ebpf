//! eBPF plugin for Nushell
//!
//! This plugin compiles Nushell closures to eBPF bytecode and attaches them to
//! kernel probe points for high-performance tracing.

use nu_plugin::{MsgPackSerializer, Plugin, PluginCommand, serve_plugin};

mod commands;
#[cfg(target_os = "linux")]
pub mod compiler;
#[cfg(target_os = "linux")]
pub mod kernel_btf;
#[cfg(target_os = "linux")]
pub mod loader;
#[cfg(target_os = "linux")]
pub mod symbolize;

pub use commands::*;

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
        ]
    }
}

fn main() {
    serve_plugin(&EbpfPlugin, MsgPackSerializer);
}
