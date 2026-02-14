use super::*;

/// Integration test: SSA pipeline + full compilation to eBPF
#[test]
fn test_ssa_full_compilation_simple() {
    use crate::compiler::mir::*;
    use crate::compiler::mir_to_ebpf::compile_mir_to_ebpf;

    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    func.entry = bb0;

    let v0 = func.alloc_vreg();
    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::Const(42),
    });
    func.block_mut(bb0).terminator = MirInst::Return {
        val: Some(MirValue::VReg(v0)),
    };

    // Run SSA optimization
    optimize_with_ssa(&mut func);

    // Compile to eBPF
    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };
    let result = compile_mir_to_ebpf(&program, None).unwrap();
    assert!(
        !result.bytecode.is_empty(),
        "SSA + compile should produce bytecode"
    );
}

/// Integration test: SSA with diamond CFG through full compilation
#[test]
fn test_ssa_full_compilation_diamond() {
    use crate::compiler::mir::*;
    use crate::compiler::mir_to_ebpf::compile_mir_to_ebpf;

    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    let bb1 = func.alloc_block();
    let bb2 = func.alloc_block();
    let bb3 = func.alloc_block();
    func.entry = bb0;

    let v0 = func.alloc_vreg();
    let v1 = func.alloc_vreg();

    // bb0: v0 = 1; branch v0 -> bb1, bb2
    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::Const(1),
    });
    func.block_mut(bb0).terminator = MirInst::Branch {
        cond: v0,
        if_true: bb1,
        if_false: bb2,
    };

    // bb1: v1 = 10; jump bb3
    func.block_mut(bb1).instructions.push(MirInst::Copy {
        dst: v1,
        src: MirValue::Const(10),
    });
    func.block_mut(bb1).terminator = MirInst::Jump { target: bb3 };

    // bb2: v1 = 20; jump bb3
    func.block_mut(bb2).instructions.push(MirInst::Copy {
        dst: v1,
        src: MirValue::Const(20),
    });
    func.block_mut(bb2).terminator = MirInst::Jump { target: bb3 };

    // bb3: return v1
    func.block_mut(bb3).terminator = MirInst::Return {
        val: Some(MirValue::VReg(v1)),
    };

    // Run SSA optimization
    let changes = optimize_with_ssa(&mut func);
    assert!(changes > 0, "Diamond CFG should trigger SSA changes");

    // Verify no phis remain
    for block in &func.blocks {
        for inst in &block.instructions {
            assert!(
                !matches!(inst, MirInst::Phi { .. }),
                "Phi should be eliminated"
            );
        }
    }

    // Compile to eBPF
    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };
    let result = compile_mir_to_ebpf(&program, None).unwrap();
    assert!(
        !result.bytecode.is_empty(),
        "SSA diamond + compile should produce bytecode"
    );
}

/// Integration test: SSA with arithmetic operations
#[test]
fn test_ssa_full_compilation_arithmetic() {
    use crate::compiler::mir::*;
    use crate::compiler::mir_to_ebpf::compile_mir_to_ebpf;

    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    let bb1 = func.alloc_block();
    let bb2 = func.alloc_block();
    let bb3 = func.alloc_block();
    func.entry = bb0;

    let v0 = func.alloc_vreg();
    let v1 = func.alloc_vreg();
    let v2 = func.alloc_vreg();

    // bb0: v0 = 5; v1 = 10; branch v0 -> bb1, bb2
    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::Const(5),
    });
    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v1,
        src: MirValue::Const(10),
    });
    func.block_mut(bb0).terminator = MirInst::Branch {
        cond: v0,
        if_true: bb1,
        if_false: bb2,
    };

    // bb1: v2 = v0 + v1; jump bb3
    func.block_mut(bb1).instructions.push(MirInst::BinOp {
        dst: v2,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(v0),
        rhs: MirValue::VReg(v1),
    });
    func.block_mut(bb1).terminator = MirInst::Jump { target: bb3 };

    // bb2: v2 = v0 * v1; jump bb3
    func.block_mut(bb2).instructions.push(MirInst::BinOp {
        dst: v2,
        op: BinOpKind::Mul,
        lhs: MirValue::VReg(v0),
        rhs: MirValue::VReg(v1),
    });
    func.block_mut(bb2).terminator = MirInst::Jump { target: bb3 };

    // bb3: return v2
    func.block_mut(bb3).terminator = MirInst::Return {
        val: Some(MirValue::VReg(v2)),
    };

    // Run SSA optimization
    optimize_with_ssa(&mut func);

    // Compile to eBPF
    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };
    let result = compile_mir_to_ebpf(&program, None).unwrap();
    assert!(
        !result.bytecode.is_empty(),
        "SSA arithmetic + compile should produce bytecode"
    );
}

/// Integration test: SSA with nested branches
#[test]
fn test_ssa_full_compilation_nested_branches() {
    use crate::compiler::mir::*;
    use crate::compiler::mir_to_ebpf::compile_mir_to_ebpf;

    // Create: if (a) { if (b) x=1 else x=2 } else { x=3 }; return x
    let mut func = MirFunction::new();
    let bb0 = func.alloc_block(); // entry
    let bb1 = func.alloc_block(); // outer true
    let bb2 = func.alloc_block(); // outer false (x=3)
    let bb3 = func.alloc_block(); // inner true (x=1)
    let bb4 = func.alloc_block(); // inner false (x=2)
    let bb5 = func.alloc_block(); // exit
    func.entry = bb0;

    let a = func.alloc_vreg();
    let b = func.alloc_vreg();
    let x = func.alloc_vreg();

    // bb0: a = 1; b = 0; branch a -> bb1, bb2
    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: a,
        src: MirValue::Const(1),
    });
    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: b,
        src: MirValue::Const(0),
    });
    func.block_mut(bb0).terminator = MirInst::Branch {
        cond: a,
        if_true: bb1,
        if_false: bb2,
    };

    // bb1: branch b -> bb3, bb4
    func.block_mut(bb1).terminator = MirInst::Branch {
        cond: b,
        if_true: bb3,
        if_false: bb4,
    };

    // bb2: x = 3; jump bb5
    func.block_mut(bb2).instructions.push(MirInst::Copy {
        dst: x,
        src: MirValue::Const(3),
    });
    func.block_mut(bb2).terminator = MirInst::Jump { target: bb5 };

    // bb3: x = 1; jump bb5
    func.block_mut(bb3).instructions.push(MirInst::Copy {
        dst: x,
        src: MirValue::Const(1),
    });
    func.block_mut(bb3).terminator = MirInst::Jump { target: bb5 };

    // bb4: x = 2; jump bb5
    func.block_mut(bb4).instructions.push(MirInst::Copy {
        dst: x,
        src: MirValue::Const(2),
    });
    func.block_mut(bb4).terminator = MirInst::Jump { target: bb5 };

    // bb5: return x
    func.block_mut(bb5).terminator = MirInst::Return {
        val: Some(MirValue::VReg(x)),
    };

    // Run SSA optimization
    optimize_with_ssa(&mut func);

    // Compile to eBPF
    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };
    let result = compile_mir_to_ebpf(&program, None).unwrap();
    assert!(
        !result.bytecode.is_empty(),
        "SSA nested branches + compile should produce bytecode"
    );
}

/// Integration test: SSA with many variables
#[test]
fn test_ssa_full_compilation_many_variables() {
    use crate::compiler::mir::*;
    use crate::compiler::mir_to_ebpf::compile_mir_to_ebpf;

    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    let bb1 = func.alloc_block();
    let bb2 = func.alloc_block();
    let bb3 = func.alloc_block();
    func.entry = bb0;

    // Create many variables
    let vars: Vec<VReg> = (0..10).map(|_| func.alloc_vreg()).collect();

    // bb0: initialize all vars, branch on first
    for (i, &v) in vars.iter().enumerate() {
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v,
            src: MirValue::Const(i as i64),
        });
    }
    func.block_mut(bb0).terminator = MirInst::Branch {
        cond: vars[0],
        if_true: bb1,
        if_false: bb2,
    };

    // bb1: increment all vars, jump to bb3
    for &v in &vars {
        func.block_mut(bb1).instructions.push(MirInst::BinOp {
            dst: v,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(v),
            rhs: MirValue::Const(1),
        });
    }
    func.block_mut(bb1).terminator = MirInst::Jump { target: bb3 };

    // bb2: decrement all vars, jump to bb3
    for &v in &vars {
        func.block_mut(bb2).instructions.push(MirInst::BinOp {
            dst: v,
            op: BinOpKind::Sub,
            lhs: MirValue::VReg(v),
            rhs: MirValue::Const(1),
        });
    }
    func.block_mut(bb2).terminator = MirInst::Jump { target: bb3 };

    // bb3: return sum of first two vars
    let sum = func.alloc_vreg();
    func.block_mut(bb3).instructions.push(MirInst::BinOp {
        dst: sum,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(vars[0]),
        rhs: MirValue::VReg(vars[1]),
    });
    func.block_mut(bb3).terminator = MirInst::Return {
        val: Some(MirValue::VReg(sum)),
    };

    // Run SSA optimization
    optimize_with_ssa(&mut func);

    // Compile to eBPF
    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };
    let result = compile_mir_to_ebpf(&program, None).unwrap();
    assert!(
        !result.bytecode.is_empty(),
        "SSA many vars + compile should produce bytecode"
    );
}
