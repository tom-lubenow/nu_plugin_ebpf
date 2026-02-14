
use super::*;
use crate::compiler::mir::{MirFunction, MirInst, MirProgram, MirValue, SubfunctionId};

#[test]
fn test_lower_rejects_helper_call_with_too_many_args() {
    let mut main = MirFunction::new();
    let entry = main.alloc_block();
    main.entry = entry;

    let mut args = Vec::new();
    for n in 0..6 {
        let v = main.alloc_vreg();
        main.block_mut(entry).instructions.push(MirInst::Copy {
            dst: v,
            src: MirValue::Const(n),
        });
        args.push(MirValue::VReg(v));
    }
    let dst = main.alloc_vreg();
    main.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 14,
            args,
        });
    main.block_mut(entry).terminator = MirInst::Return { val: None };

    let program = MirProgram {
        main,
        subfunctions: vec![],
    };

    let err =
        lower_mir_to_lir_checked(&program).expect_err("expected helper arg-limit lowering error");
    match err {
        CompileError::UnsupportedInstruction(msg) => {
            assert!(msg.contains("at most 5 arguments"));
        }
        other => panic!("expected unsupported-instruction error, got {other}"),
    }
}

#[test]
fn test_lower_rejects_subfn_call_with_too_many_args() {
    let mut subfn = MirFunction::with_name("sub");
    subfn.param_count = 1;
    let sub_entry = subfn.alloc_block();
    subfn.entry = sub_entry;
    subfn.block_mut(sub_entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let mut main = MirFunction::new();
    let entry = main.alloc_block();
    main.entry = entry;

    let mut args = Vec::new();
    for n in 0..6 {
        let v = main.alloc_vreg();
        main.block_mut(entry).instructions.push(MirInst::Copy {
            dst: v,
            src: MirValue::Const(100 + n),
        });
        args.push(v);
    }
    let dst = main.alloc_vreg();
    main.block_mut(entry).instructions.push(MirInst::CallSubfn {
        dst,
        subfn: SubfunctionId(0),
        args,
    });
    main.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::VReg(dst)),
    };

    let program = MirProgram {
        main,
        subfunctions: vec![subfn],
    };

    let err =
        lower_mir_to_lir_checked(&program).expect_err("expected subfn arg-limit lowering error");
    match err {
        CompileError::UnsupportedInstruction(msg) => {
            assert!(msg.contains("at most 5 arguments"));
        }
        other => panic!("expected unsupported-instruction error, got {other}"),
    }
}

#[test]
fn test_lower_rejects_subfunction_with_too_many_params() {
    let mut main = MirFunction::new();
    let entry = main.alloc_block();
    main.entry = entry;
    main.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut subfn = MirFunction::with_name("too_many_params");
    subfn.param_count = 6;
    let sub_entry = subfn.alloc_block();
    subfn.entry = sub_entry;
    subfn.block_mut(sub_entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let program = MirProgram {
        main,
        subfunctions: vec![subfn],
    };

    let err = lower_mir_to_lir_checked(&program)
        .expect_err("expected subfunction param-limit lowering error");
    match err {
        CompileError::UnsupportedInstruction(msg) => {
            assert!(msg.contains("at most 5 arguments"));
        }
        other => panic!("expected unsupported-instruction error, got {other}"),
    }
}

#[test]
fn test_lower_rejects_unknown_kfunc() {
    let mut main = MirFunction::new();
    let entry = main.alloc_block();
    main.entry = entry;

    let dst = main.alloc_vreg();
    let arg = main.alloc_vreg();
    main.block_mut(entry).instructions.push(MirInst::Copy {
        dst: arg,
        src: MirValue::Const(1),
    });
    main.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "unknown_kfunc_name".to_string(),
        btf_id: None,
        args: vec![arg],
    });
    main.block_mut(entry).terminator = MirInst::Return { val: None };

    let program = MirProgram {
        main,
        subfunctions: vec![],
    };

    let err =
        lower_mir_to_lir_checked(&program).expect_err("expected unknown kfunc lowering error");
    match err {
        CompileError::UnsupportedInstruction(msg) => {
            assert!(msg.contains("unknown kfunc"));
        }
        other => panic!("expected unsupported-instruction error, got {other}"),
    }
}

#[test]
fn test_lower_kfunc_call() {
    let mut main = MirFunction::new();
    let entry = main.alloc_block();
    main.entry = entry;

    let dst = main.alloc_vreg();
    let ptr = main.alloc_vreg();
    let level = main.alloc_vreg();
    let slot = main.alloc_stack_slot(8, 8, crate::compiler::mir::StackSlotKind::StringBuffer);
    main.block_mut(entry).instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::StackSlot(slot),
    });
    main.block_mut(entry).instructions.push(MirInst::Copy {
        dst: level,
        src: MirValue::Const(0),
    });
    main.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_cgroup_ancestor".to_string(),
        btf_id: Some(99),
        args: vec![ptr, level],
    });
    main.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::VReg(dst)),
    };

    let program = MirProgram {
        main,
        subfunctions: vec![],
    };

    let lir = lower_mir_to_lir_checked(&program).expect("kfunc lowering should succeed");
    let block = lir.main.block(lir.main.entry);
    let has_kfunc = block.instructions.iter().any(|inst| {
        matches!(
            inst,
            LirInst::CallKfunc {
                kfunc,
                btf_id: Some(99),
                ..
            } if kfunc == "bpf_cgroup_ancestor"
        )
    });
    assert!(has_kfunc, "expected lowered LIR kfunc call");
}
