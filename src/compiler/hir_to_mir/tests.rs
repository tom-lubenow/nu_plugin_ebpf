use super::*;
use crate::compiler::compile_mir_to_ebpf;
use crate::compiler::hir::{
    HirBlock, HirBlockId, HirFunction, HirLiteral, HirProgram, HirStmt, HirTerminator,
    extract_closure_block_ids, lower_ir_to_hir,
};
use crate::compiler::mir::{BinOpKind, MirInst, MirValue};
use crate::compiler::verifier_types::verify_mir;
use nu_protocol::ast::{Comparison, Expr, Expression, Math, Operator};
use nu_protocol::ir::{DataSlice, Instruction, IrBlock, Literal};
use nu_protocol::{BlockId as NuBlockId, RegId, Span, SpanId, Type, VarId};
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
fn test_extract_closure_block_ids_includes_parser_info_blocks() {
    let block_id = NuBlockId::new(7);
    let ir = make_ir_block(vec![Instruction::PushParserInfo {
        name: DataSlice::empty(),
        info: Box::new(Expression {
            expr: Expr::Closure(block_id),
            span: Span::test_data(),
            span_id: SpanId::new(0),
            ty: Type::Closure,
        }),
    }]);

    assert_eq!(extract_closure_block_ids(&ir), vec![block_id]);
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
fn test_hir_to_mir_bounded_list_accumulator_compiles() {
    let sum_var = VarId::new(80);
    let func = HirFunction {
        blocks: vec![
            HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadLiteral {
                        dst: RegId::new(0),
                        lit: HirLiteral::List { capacity: 3 },
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::Int(10),
                    },
                    HirStmt::ListPush {
                        src_dst: RegId::new(0),
                        item: RegId::new(2),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::Int(20),
                    },
                    HirStmt::ListPush {
                        src_dst: RegId::new(0),
                        item: RegId::new(2),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::Int(30),
                    },
                    HirStmt::ListPush {
                        src_dst: RegId::new(0),
                        item: RegId::new(2),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(3),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::StoreVariable {
                        var_id: sum_var,
                        src: RegId::new(3),
                    },
                ],
                terminator: HirTerminator::Iterate {
                    dst: RegId::new(1),
                    stream: RegId::new(0),
                    body: HirBlockId(1),
                    end: HirBlockId(2),
                },
            },
            HirBlock {
                id: HirBlockId(1),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(4),
                        var_id: sum_var,
                    },
                    HirStmt::BinaryOp {
                        lhs_dst: RegId::new(4),
                        op: Operator::Math(Math::Add),
                        rhs: RegId::new(1),
                    },
                    HirStmt::StoreVariable {
                        var_id: sum_var,
                        src: RegId::new(4),
                    },
                ],
                terminator: HirTerminator::Jump {
                    target: HirBlockId(0),
                },
            },
            HirBlock {
                id: HirBlockId(2),
                stmts: vec![HirStmt::LoadVariable {
                    dst: RegId::new(5),
                    var_id: sum_var,
                }],
                terminator: HirTerminator::Return { src: RegId::new(5) },
            },
        ],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 14],
        ast: vec![None; 14],
        comments: vec![],
        register_count: 6,
        file_count: 0,
    };

    let mir = lower_hir_to_mir(
        &HirProgram::new(func, HashMap::new(), vec![], None),
        None,
        &HashMap::new(),
    )
    .expect("bounded list accumulator should lower");

    compile_mir_to_ebpf(&mir, None).expect("bounded list accumulator should compile");
}

#[test]
fn test_hir_to_mir_source_break_does_not_disable_continue_backedge() {
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
            lit: Literal::Int(3),
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
            end_index: 21,
        },
        Instruction::StoreVariable {
            var_id: VarId::new(80),
            src: RegId::new(0),
        },
        Instruction::Drop { src: RegId::new(0) },
        Instruction::LoadVariable {
            dst: RegId::new(2),
            var_id: VarId::new(80),
        },
        Instruction::LoadLiteral {
            dst: RegId::new(3),
            lit: Literal::Int(1),
        },
        Instruction::BinaryOp {
            lhs_dst: RegId::new(2),
            op: Operator::Comparison(Comparison::Equal),
            rhs: RegId::new(3),
        },
        Instruction::Span {
            src_dst: RegId::new(2),
        },
        Instruction::Not {
            src_dst: RegId::new(2),
        },
        Instruction::BranchIf {
            cond: RegId::new(2),
            index: 17,
        },
        Instruction::Drop { src: RegId::new(0) },
        Instruction::Jump { index: 21 },
        Instruction::Jump { index: 19 },
        Instruction::Drop { src: RegId::new(0) },
        Instruction::Jump { index: 5 },
        Instruction::Drain { src: RegId::new(0) },
        Instruction::Jump { index: 5 },
        Instruction::Drop { src: RegId::new(0) },
        Instruction::Drain { src: RegId::new(0) },
        Instruction::LoadLiteral {
            dst: RegId::new(0),
            lit: Literal::Int(9),
        },
        Instruction::Return { src: RegId::new(0) },
    ]);

    let hir = lower_ir_to_hir(ir, HashMap::new(), Vec::new(), None).unwrap();
    let mir = lower_hir_to_mir(&hir, None, &HashMap::new()).unwrap();
    let header_block = mir
        .main
        .blocks
        .iter()
        .find_map(|block| {
            matches!(block.terminator, MirInst::LoopHeader { .. }).then_some(block.id)
        })
        .expect("expected source for-loop to lower to a loop header");

    assert!(
        mir.main.blocks.iter().any(|block| {
            matches!(
                block.terminator,
                MirInst::LoopBack { header, .. } if header == header_block
            )
        }),
        "source continue edge should remain a LoopBack after a sibling break edge"
    );
    verify_mir(&mir.main, &HashMap::new()).expect("source break/continue loop should verify");
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
