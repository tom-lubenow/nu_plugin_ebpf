use super::*;

#[test]
fn test_infer_constant() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0)).instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::Const(42),
    });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::I64));
}

#[test]
fn test_infer_ctx_pid() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Pid,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U32));
}

#[test]
fn test_infer_ctx_comm() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Comm,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti.infer(&func).unwrap();

    assert_eq!(
        types.get(&v0),
        Some(&MirType::Ptr {
            pointee: Box::new(MirType::Array {
                elem: Box::new(MirType::U8),
                len: 16
            }),
            address_space: AddressSpace::Stack,
        })
    );
}

#[test]
fn test_infer_binop_add() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();
    let v1 = func.alloc_vreg();
    let v2 = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::Const(10),
    });
    block.instructions.push(MirInst::Copy {
        dst: v1,
        src: MirValue::Const(20),
    });
    block.instructions.push(MirInst::BinOp {
        dst: v2,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(v0),
        rhs: MirValue::VReg(v1),
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v2), Some(&MirType::I64));
}

#[test]
fn test_infer_comparison() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();
    let v1 = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: v0,
        field: CtxField::Pid,
        slot: None,
    });
    block.instructions.push(MirInst::BinOp {
        dst: v1,
        op: BinOpKind::Eq,
        lhs: MirValue::VReg(v0),
        rhs: MirValue::Const(1234),
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v1), Some(&MirType::Bool));
}

#[test]
fn test_type_hint_mismatch_errors() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0)).instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::Const(1),
    });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let mut hints = HashMap::new();
    hints.insert(
        v0,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Stack,
        },
    );

    let mut ti = TypeInference::new_with_env(None, None, None, Some(&hints));
    assert!(ti.infer(&func).is_err());
}

#[test]
fn test_infer_uprobe_arg_is_user_ptr() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Arg(0),
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::Uprobe, "test");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    match types.get(&v0) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::User);
        }
        other => panic!("Expected user pointer, got {:?}", other),
    }
}

#[test]
fn test_infer_kprobe_arg_is_int() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Arg(0),
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::Kprobe, "test");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::I64));
}

#[test]
fn test_infer_map_lookup_returns_ptr() {
    use crate::compiler::mir::{MapKind, MapRef};

    let mut func = make_test_function();
    let v0 = func.alloc_vreg();
    let v1 = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::Const(123),
    });
    block.instructions.push(MirInst::MapLookup {
        dst: v1,
        map: MapRef {
            name: "test_map".to_string(),
            kind: MapKind::Hash,
        },
        key: v0,
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti.infer(&func).unwrap();

    match types.get(&v1) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Map);
        }
        other => panic!("Expected map pointer, got {:?}", other),
    }
}

#[test]
fn test_copy_propagates_type() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();
    let v1 = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: v0,
        field: CtxField::Timestamp,
        slot: None,
    });
    block.instructions.push(MirInst::Copy {
        dst: v1,
        src: MirValue::VReg(v0),
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti.infer(&func).unwrap();

    // Both should be U64 (timestamp type)
    assert_eq!(types.get(&v0), Some(&MirType::U64));
    assert_eq!(types.get(&v1), Some(&MirType::U64));
}

#[test]
fn test_type_propagation_through_chain() {
    // Test that types propagate through a chain of copies
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();
    let v1 = func.alloc_vreg();
    let v2 = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: v0,
        field: CtxField::Pid, // U32
        slot: None,
    });
    block.instructions.push(MirInst::Copy {
        dst: v1,
        src: MirValue::VReg(v0),
    });
    block.instructions.push(MirInst::Copy {
        dst: v2,
        src: MirValue::VReg(v1),
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti.infer(&func).unwrap();

    // All should be U32
    assert_eq!(types.get(&v0), Some(&MirType::U32));
    assert_eq!(types.get(&v1), Some(&MirType::U32));
    assert_eq!(types.get(&v2), Some(&MirType::U32));
}

#[test]
fn test_unification_through_binop() {
    // Test that types unify correctly through binary operations
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();
    let v1 = func.alloc_vreg();
    let v2 = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: v0,
        field: CtxField::Uid, // U32
        slot: None,
    });
    block.instructions.push(MirInst::Copy {
        dst: v1,
        src: MirValue::VReg(v0),
    });
    // Compare v1 (which got type from v0) with constant
    block.instructions.push(MirInst::BinOp {
        dst: v2,
        op: BinOpKind::Eq,
        lhs: MirValue::VReg(v1),
        rhs: MirValue::Const(0),
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U32));
    assert_eq!(types.get(&v1), Some(&MirType::U32));
    assert_eq!(types.get(&v2), Some(&MirType::Bool));
}
