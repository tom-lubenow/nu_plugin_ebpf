//! eBPF bytecode compiler
//!
//! This module handles compilation from Nushell IR to eBPF bytecode.
//!
//! ## Compilation Pipeline
//!
//! ```text
//! Nushell IR → [ir_to_mir] → MIR → [type_infer] → typed MIR
//!                                       ↓
//!                                 [cfg] → CFG analysis
//!                                       ↓
//!                              [passes/*] optimizations
//!                                       ↓
//!                         [graph_coloring] register allocation
//!                                       ↓
//!                              [mir_to_ebpf] → eBPF bytecode
//! ```

mod btf;
pub mod cfg;
mod elf;
pub mod graph_coloring;
pub mod hindley_milner;
pub mod instruction;
pub mod ir_to_mir;
pub mod mir;
pub mod mir_to_ebpf;
pub mod passes;
pub mod type_infer;

pub use elf::{
    BpfFieldType, BpfMapDef, EbpfMap, EbpfProgram, EbpfProgramType, EventSchema, MapRelocation,
    ProbeContext, SchemaField,
};
pub use instruction::{BpfHelper, EbpfInsn, EbpfReg};
pub use mir_to_ebpf::{MirCompileResult, compile_mir_to_ebpf};
pub use type_infer::{TypeError, TypeInference};

use thiserror::Error;

/// Errors that can occur during eBPF compilation
#[derive(Debug, Error)]
pub enum CompileError {
    #[error("Unsupported instruction: {0}")]
    UnsupportedInstruction(String),

    #[error("Unsupported literal type")]
    UnsupportedLiteral,

    #[error("Stack overflow: eBPF stack is limited to 512 bytes")]
    StackOverflow,

    #[error("Register exhaustion: too many live values")]
    RegisterExhaustion,

    #[error("ELF generation failed: {0}")]
    ElfError(String),

    #[error("Invalid probe specification: {0}")]
    InvalidProbeSpec(String),

    #[error("'retval' is only available on return probes (kretprobe, uretprobe)")]
    RetvalOnNonReturnProbe,

    #[error("Tracepoint field '{field}' not found. Available: {available}")]
    TracepointFieldNotFound { field: String, available: String },

    #[error("Could not load tracepoint context for '{category}/{name}': {reason}")]
    TracepointContextError {
        category: String,
        name: String,
        reason: String,
    },

    #[error("Type error: {0}")]
    TypeError(#[from] TypeError),
}
