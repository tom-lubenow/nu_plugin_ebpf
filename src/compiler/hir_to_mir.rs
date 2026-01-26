//! HIR to MIR lowering.
//!
//! The implementation lives in `ir_to_mir` to avoid duplication. This module
//! re-exports the entry point for pipeline clarity.

pub use super::ir_to_mir::{lower_hir_to_mir, lower_hir_to_mir_with_hints, MirLoweringResult};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::hir::lower_ir_to_hir;
    use nu_protocol::RegId;
    use nu_protocol::ir::{Instruction, IrBlock, Literal};
    use std::sync::Arc;
    use std::collections::HashMap;

    fn make_ir_block(instructions: Vec<Instruction>) -> IrBlock {
        IrBlock {
            instructions,
            spans: vec![],
            data: Arc::from([]),
            ast: vec![],
            comments: vec![],
            register_count: 4,
            file_count: 0,
        }
    }

    #[test]
    fn test_hir_to_mir_lowering() {
        let ir = make_ir_block(vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(0),
            },
            Instruction::Return { src: RegId::new(0) },
        ]);

        let hir = lower_ir_to_hir(ir, HashMap::new(), Vec::new(), None).unwrap();
        let mir = lower_hir_to_mir(&hir, None, &HashMap::new()).unwrap();

        assert!(!mir.main.blocks.is_empty(), "HIR lowering should emit MIR");
    }
}
