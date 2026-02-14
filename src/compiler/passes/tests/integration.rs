use super::*;

/// Integration test: Compare SSA vs non-SSA compilation produces same/similar output
#[test]
fn test_ssa_vs_non_ssa_equivalence() {
    use crate::compiler::mir::*;
    use crate::compiler::mir_to_ebpf::compile_mir_to_ebpf;

    // Helper to create the same function twice
    fn make_test_func() -> MirFunction {
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        func.entry = bb0;

        let v0 = func.alloc_vreg();
        let v1 = func.alloc_vreg();
        let v2 = func.alloc_vreg();

        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v0,
            src: MirValue::Const(5),
        });
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v1,
            src: MirValue::Const(10),
        });
        func.block_mut(bb0).instructions.push(MirInst::BinOp {
            dst: v2,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(v0),
            rhs: MirValue::VReg(v1),
        });
        func.block_mut(bb0).terminator = MirInst::Return {
            val: Some(MirValue::VReg(v2)),
        };

        func
    }

    // Compile without SSA
    let func_no_ssa = make_test_func();
    let program_no_ssa = MirProgram {
        main: func_no_ssa,
        subfunctions: vec![],
    };
    let result_no_ssa = compile_mir_to_ebpf(&program_no_ssa, None).unwrap();

    // Compile with SSA
    let mut func_ssa = make_test_func();
    optimize_with_ssa(&mut func_ssa);
    let program_ssa = MirProgram {
        main: func_ssa,
        subfunctions: vec![],
    };
    let result_ssa = compile_mir_to_ebpf(&program_ssa, None).unwrap();

    // Both should produce valid bytecode
    assert!(!result_no_ssa.bytecode.is_empty());
    assert!(!result_ssa.bytecode.is_empty());

    // For this simple case, bytecode should be similar in size
    // (SSA might have slight differences due to copy insertion/elimination)
    let size_diff = (result_ssa.bytecode.len() as i64 - result_no_ssa.bytecode.len() as i64).abs();
    assert!(
        size_diff <= 64, // Allow some difference (8 instructions worth)
        "SSA and non-SSA bytecode should be similar size: SSA={}, non-SSA={}",
        result_ssa.bytecode.len(),
        result_no_ssa.bytecode.len()
    );
}

/// Integration test: SSA with constant folding optimization
#[test]
fn test_ssa_constant_folding_integration() {
    use crate::compiler::mir::*;
    use crate::compiler::mir_to_ebpf::compile_mir_to_ebpf;

    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    func.entry = bb0;

    let v0 = func.alloc_vreg();
    let v1 = func.alloc_vreg();
    let v2 = func.alloc_vreg();

    // v0 = 5; v1 = 10; v2 = v0 + v1 (should fold to v2 = 15)
    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::Const(5),
    });
    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v1,
        src: MirValue::Const(10),
    });
    func.block_mut(bb0).instructions.push(MirInst::BinOp {
        dst: v2,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(v0),
        rhs: MirValue::VReg(v1),
    });
    func.block_mut(bb0).terminator = MirInst::Return {
        val: Some(MirValue::VReg(v2)),
    };

    // Run SSA optimization (includes constant folding)
    let _changes = optimize_with_ssa(&mut func);

    // Compile to eBPF
    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };
    let result = compile_mir_to_ebpf(&program, None).unwrap();
    assert!(!result.bytecode.is_empty());
}

#[test]
fn test_pass_convergence_conditional() {
    use crate::compiler::mir::{BinOpKind, CtxField};

    // Test that passes converge on conditional code patterns
    // This pattern was causing "reached max iterations" warning before the fix

    let mut func = MirFunction::new();
    let bb0 = func.alloc_block(); // entry: check condition
    let bb1 = func.alloc_block(); // if true branch
    let bb2 = func.alloc_block(); // if false branch
    let bb3 = func.alloc_block(); // exit
    func.entry = bb0;

    let v_pid = func.alloc_vreg();
    let v_cond = func.alloc_vreg();
    let v_large_1 = func.alloc_vreg();
    let v_large_0 = func.alloc_vreg();

    // bb0: load pid, compare, branch
    func.block_mut(bb0)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v_pid,
            field: CtxField::Pid,
            slot: None,
        });
    func.block_mut(bb0).instructions.push(MirInst::BinOp {
        dst: v_cond,
        op: BinOpKind::Gt,
        lhs: MirValue::VReg(v_pid),
        rhs: MirValue::Const(1000),
    });
    func.block_mut(bb0).terminator = MirInst::Branch {
        cond: v_cond,
        if_true: bb1,
        if_false: bb2,
    };

    // bb1: large = 1, jump to exit
    func.block_mut(bb1).instructions.push(MirInst::Copy {
        dst: v_large_1,
        src: MirValue::Const(1),
    });
    func.block_mut(bb1).terminator = MirInst::Jump { target: bb3 };

    // bb2: large = 0, jump to exit
    func.block_mut(bb2).instructions.push(MirInst::Copy {
        dst: v_large_0,
        src: MirValue::Const(0),
    });
    func.block_mut(bb2).terminator = MirInst::Jump { target: bb3 };

    // bb3: return
    func.block_mut(bb3).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    // Run optimization - should converge without hitting max iterations
    // Before the fix, const_fold was incorrectly reporting changes when
    // replacing a VReg with a Const that was already a Const (via the
    // constants hashmap), causing infinite iterations.
    let _changes = optimize_with_ssa(&mut func);

    // The test passes if we don't see "PassManager: reached max iterations"
    // printed to stderr. The fix in const_fold.rs now checks if the operand
    // is already a Const before replacing it.
}
