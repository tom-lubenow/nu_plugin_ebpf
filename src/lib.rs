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
pub mod program_spec;
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
            Box::new(AdjustPacket),
            Box::new(AdjustMessage),
            Box::new(Redirect),
            Box::new(RedirectMap),
            Box::new(RedirectSocket),
            Box::new(AssignSocket),
            Box::new(HelperCall),
            Box::new(KfuncCall),
            Box::new(TailCall),
            Box::new(GlobalDefine),
            Box::new(GlobalGet),
            Box::new(GlobalSet),
            Box::new(MapDefine),
            Box::new(MapGet),
            Box::new(MapPut),
            Box::new(MapDelete),
            Box::new(MapContains),
            Box::new(MapPush),
            Box::new(MapPeek),
            Box::new(MapPop),
        ]
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::compiler::ProgramIntrinsic;
    use nu_protocol::SyntaxShape;

    #[test]
    fn test_plugin_exports_all_program_intrinsics() {
        let commands = EbpfPlugin.commands();
        let command_names = commands
            .iter()
            .map(|command| command.name())
            .collect::<HashSet<_>>();

        for intrinsic in ProgramIntrinsic::all() {
            assert!(
                command_names.contains(intrinsic.command_name()),
                "plugin should export intrinsic command {}",
                intrinsic.command_name()
            );
        }
    }

    #[test]
    fn test_helper_call_signature_exposes_map_kind_flag() {
        let signature = HelperCall.signature();
        let kind_flag = signature
            .named
            .iter()
            .find(|flag| flag.long == "kind")
            .expect("helper-call should expose --kind for ambiguous map helpers");
        assert!(matches!(kind_flag.arg, Some(SyntaxShape::String)));
    }
}
