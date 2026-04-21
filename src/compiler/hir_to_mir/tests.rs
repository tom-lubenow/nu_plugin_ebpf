use super::*;
use crate::compiler::hir::lower_ir_to_hir;
use crate::compiler::mir::{BinOpKind, MirInst, MirValue};
use crate::compiler::verifier_types::verify_mir;
use nu_protocol::RegId;
use nu_protocol::ir::{Instruction, IrBlock, Literal};
use std::collections::HashMap;
use std::sync::Arc;

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

#[test]
fn test_hir_to_mir_branch_result_return_join_stays_initialized() {
    let ir = make_ir_block(vec![
        Instruction::LoadLiteral {
            dst: RegId::new(0),
            lit: Literal::Int(1),
        },
        Instruction::BranchIf {
            cond: RegId::new(0),
            index: 4,
        },
        Instruction::LoadLiteral {
            dst: RegId::new(0),
            lit: Literal::Int(2),
        },
        Instruction::Jump { index: 5 },
        Instruction::LoadLiteral {
            dst: RegId::new(0),
            lit: Literal::Int(3),
        },
        Instruction::Return { src: RegId::new(0) },
    ]);

    let hir = lower_ir_to_hir(ir, HashMap::new(), Vec::new(), None).unwrap();
    let mir = lower_hir_to_mir(&hir, None, &HashMap::new()).unwrap();

    verify_mir(&mir.main, &HashMap::new())
        .expect("branch-result join lowered through an empty return block should stay initialized");
}

#[test]
fn test_hir_to_mir_if_without_else_cleanup_return_stays_initialized() {
    let ir = make_ir_block(vec![
        Instruction::LoadLiteral {
            dst: RegId::new(1),
            lit: Literal::Bool(true),
        },
        Instruction::Not {
            src_dst: RegId::new(1),
        },
        Instruction::BranchIf {
            cond: RegId::new(1),
            index: 5,
        },
        Instruction::LoadLiteral {
            dst: RegId::new(0),
            lit: Literal::Int(1),
        },
        Instruction::Jump { index: 6 },
        Instruction::Drop { src: RegId::new(0) },
        Instruction::Return { src: RegId::new(0) },
    ]);

    let hir = lower_ir_to_hir(ir, HashMap::new(), Vec::new(), None).unwrap();
    let mir = lower_hir_to_mir(&hir, None, &HashMap::new()).unwrap();

    verify_mir(&mir.main, &HashMap::new()).expect(
        "if-without-else cleanup return lowered through an empty epilogue should stay initialized",
    );
}

#[test]
fn test_hir_to_mir_for_loop_cleanup_return_stays_initialized() {
    let ir = make_ir_block(vec![
        Instruction::Drop { src: RegId::new(0) },
        Instruction::LoadLiteral {
            dst: RegId::new(2),
            lit: Literal::Int(0),
        },
        Instruction::LoadLiteral {
            dst: RegId::new(3),
            lit: Literal::Nothing,
        },
        Instruction::LoadLiteral {
            dst: RegId::new(4),
            lit: Literal::Int(0),
        },
        Instruction::LoadLiteral {
            dst: RegId::new(1),
            lit: Literal::Range {
                start: RegId::new(2),
                step: RegId::new(3),
                end: RegId::new(4),
                inclusion: nu_protocol::ast::RangeInclusion::Inclusive,
            },
        },
        Instruction::Iterate {
            dst: RegId::new(0),
            stream: RegId::new(1),
            end_index: 10,
        },
        Instruction::StoreVariable {
            var_id: nu_protocol::VarId::new(80),
            src: RegId::new(0),
        },
        Instruction::LoadLiteral {
            dst: RegId::new(0),
            lit: Literal::Int(1),
        },
        Instruction::Drain { src: RegId::new(0) },
        Instruction::Jump { index: 5 },
        Instruction::Drop { src: RegId::new(0) },
        Instruction::Return { src: RegId::new(0) },
    ]);

    let hir = lower_ir_to_hir(ir, HashMap::new(), Vec::new(), None).unwrap();
    let mir = lower_hir_to_mir(&hir, None, &HashMap::new()).unwrap();

    verify_mir(&mir.main, &HashMap::new())
        .expect("for-loop cleanup return lowered through an exit epilogue should stay initialized");
}

#[test]
fn test_hir_to_mir_return_early_lowers_like_return() {
    let ir = make_ir_block(vec![
        Instruction::LoadLiteral {
            dst: RegId::new(1),
            lit: Literal::Bool(true),
        },
        Instruction::BranchIf {
            cond: RegId::new(1),
            index: 4,
        },
        Instruction::LoadLiteral {
            dst: RegId::new(0),
            lit: Literal::Int(0),
        },
        Instruction::Return { src: RegId::new(0) },
        Instruction::LoadLiteral {
            dst: RegId::new(0),
            lit: Literal::Int(1),
        },
        Instruction::ReturnEarly { src: RegId::new(0) },
    ]);

    let hir = lower_ir_to_hir(ir, HashMap::new(), Vec::new(), None).unwrap();
    let mir = lower_hir_to_mir(&hir, None, &HashMap::new())
        .expect("return early should lower through the ordinary return path");

    verify_mir(&mir.main, &HashMap::new()).expect("return early should verify after MIR lowering");
}

#[test]
fn test_hir_to_mir_branch_if_empty_lowers_through_nothing_compare() {
    let ir = make_ir_block(vec![
        Instruction::LoadLiteral {
            dst: RegId::new(0),
            lit: Literal::Nothing,
        },
        Instruction::BranchIfEmpty {
            src: RegId::new(0),
            index: 4,
        },
        Instruction::LoadLiteral {
            dst: RegId::new(0),
            lit: Literal::Int(1),
        },
        Instruction::Return { src: RegId::new(0) },
        Instruction::LoadLiteral {
            dst: RegId::new(0),
            lit: Literal::Int(2),
        },
        Instruction::Return { src: RegId::new(0) },
    ]);

    let hir = lower_ir_to_hir(ir, HashMap::new(), Vec::new(), None).unwrap();
    let mir = lower_hir_to_mir(&hir, None, &HashMap::new())
        .expect("branch-if-empty should lower through a nothing comparison");

    let lowered_empty_check = mir.main.blocks.iter().any(|block| {
        block.instructions.iter().any(|inst| {
            matches!(
                inst,
                MirInst::BinOp {
                    op: BinOpKind::Eq,
                    lhs: MirValue::VReg(_),
                    rhs: MirValue::Const(0),
                    ..
                }
            )
        })
    });
    assert!(
        lowered_empty_check,
        "expected branch-if-empty lowering to emit a nothing-sentinel comparison"
    );

    verify_mir(&mir.main, &HashMap::new()).expect("branch-if-empty lowering should verify");
}
