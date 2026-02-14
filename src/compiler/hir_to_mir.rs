//! HIR to MIR lowering.
//!
//! The implementation lives in `ir_to_mir` to avoid duplication. This module
//! re-exports the entry point for pipeline clarity.

pub use super::ir_to_mir::{MirLoweringResult, lower_hir_to_mir, lower_hir_to_mir_with_hints};

#[cfg(test)]
mod tests;
