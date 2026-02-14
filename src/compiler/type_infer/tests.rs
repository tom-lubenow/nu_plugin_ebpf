
use super::*;
use crate::compiler::mir::{AddressSpace, BlockId, MirFunction, RecordFieldDef, StackSlotKind};
use std::collections::HashMap;

fn make_test_function() -> MirFunction {
    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    func.entry = bb0;
    func
}

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

#[test]
fn test_subfn_polymorphic_id() {
    let mut subfn = MirFunction::with_name("id");
    subfn.param_count = 1;
    let entry = subfn.alloc_block();
    subfn.entry = entry;
    let arg = VReg(0);
    subfn.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::VReg(arg)),
    };

    let mut main_func = MirFunction::new();
    let main_entry = main_func.alloc_block();
    main_func.entry = main_entry;

    let int_arg = main_func.alloc_vreg();
    let comm_arg = main_func.alloc_vreg();
    let out_int = main_func.alloc_vreg();
    let out_comm = main_func.alloc_vreg();

    let block = main_func.block_mut(main_entry);
    block.instructions.push(MirInst::Copy {
        dst: int_arg,
        src: MirValue::Const(42),
    });
    block.instructions.push(MirInst::LoadCtxField {
        dst: comm_arg,
        field: CtxField::Comm,
        slot: None,
    });
    block.instructions.push(MirInst::CallSubfn {
        dst: out_int,
        subfn: SubfunctionId(0),
        args: vec![int_arg],
    });
    block.instructions.push(MirInst::CallSubfn {
        dst: out_comm,
        subfn: SubfunctionId(0),
        args: vec![comm_arg],
    });
    block.terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let subfn_schemes = infer_subfunction_schemes(&[subfn], None).unwrap();
    let mut ti = TypeInference::new_with_env(None, Some(&subfn_schemes), Some(HMType::I64), None);
    let types = ti.infer(&main_func).unwrap();

    assert_eq!(types.get(&out_int), Some(&MirType::I64));
    match types.get(&out_comm) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Stack);
        }
        other => panic!("Expected stack pointer type, got {:?}", other),
    }
}

#[test]
fn test_type_error_helper_arg_limit() {
    let mut func = make_test_function();
    let mut args = Vec::new();
    for n in 0..6 {
        let v = func.alloc_vreg();
        let block = func.block_mut(BlockId(0));
        block.instructions.push(MirInst::Copy {
            dst: v,
            src: MirValue::Const(n),
        });
        args.push(MirValue::VReg(v));
    }
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: 14,
        args,
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected helper arg-limit type error");
    assert!(
        errs.iter()
            .any(|e| e.message.contains("expects 0..=0 arguments"))
    );
}

#[test]
fn test_type_error_helper_pointer_argument_required() {
    let mut func = make_test_function();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: 16, // bpf_get_current_comm(buf, size)
        args: vec![MirValue::Const(0), MirValue::Const(16)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected pointer-argument helper type error");
    assert!(errs.iter().any(|e| e.message.contains("expects pointer")));
}

#[test]
fn test_type_error_helper_get_current_comm_rejects_small_stack_slot() {
    let mut func = make_test_function();
    let buf_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::GetCurrentComm as u32,
        args: vec![MirValue::StackSlot(buf_slot), MirValue::Const(16)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected get_current_comm stack-size error");
    assert!(
        errs.iter().any(|e| e
            .message
            .contains("helper get_current_comm dst requires 16 bytes")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_infer_helper_map_lookup_returns_pointer() {
    let mut func = make_test_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let map = func.alloc_vreg();
    let key = func.alloc_vreg();
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: map,
        src: MirValue::StackSlot(map_slot),
    });
    block.instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::StackSlot(key_slot),
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: 1, // bpf_map_lookup_elem
        args: vec![MirValue::VReg(map), MirValue::VReg(key)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti.infer(&func).unwrap();
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Map);
        }
        other => panic!("Expected helper map lookup pointer return, got {:?}", other),
    }
}

#[test]
fn test_infer_helper_sk_lookup_returns_kernel_pointer() {
    let mut func = make_test_function();
    let pid = func.alloc_vreg();
    let ctx = func.alloc_vreg();
    let tuple_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: ctx,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SkLookupTcp as u32,
        args: vec![
            MirValue::VReg(ctx),
            MirValue::StackSlot(tuple_slot),
            MirValue::Const(16),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti.infer(&func).unwrap();
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!(
            "Expected helper sk_lookup kernel pointer return, got {:?}",
            other
        ),
    }
}

#[test]
fn test_type_error_helper_sk_release_rejects_non_kernel_pointer() {
    let mut func = make_test_function();
    let sock_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let sock = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: sock,
        src: MirValue::StackSlot(sock_slot),
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SkRelease as u32,
        args: vec![MirValue::VReg(sock)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected non-kernel sk_release pointer error");
    assert!(
        errs.iter().any(|e| e
            .message
            .contains("helper sk_release sock expects pointer in [Kernel], got Stack")),
        "unexpected type errors: {:?}",
        errs
    );
}

#[test]
fn test_infer_helper_kptr_xchg_returns_kernel_pointer() {
    let mut func = make_test_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let map = func.alloc_vreg();
    let key = func.alloc_vreg();
    let dst_ptr = func.alloc_vreg();
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: map,
        src: MirValue::StackSlot(map_slot),
    });
    block.instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::StackSlot(key_slot),
    });
    block.instructions.push(MirInst::CallHelper {
        dst: dst_ptr,
        helper: BpfHelper::MapLookupElem as u32,
        args: vec![MirValue::VReg(map), MirValue::VReg(key)],
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::KptrXchg as u32,
        args: vec![MirValue::VReg(dst_ptr), MirValue::Const(0)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti.infer(&func).unwrap();
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!(
            "Expected helper kptr_xchg kernel pointer return, got {:?}",
            other
        ),
    }
}

#[test]
fn test_type_error_helper_kptr_xchg_rejects_non_map_dst_arg0() {
    let mut func = make_test_function();
    let dst_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst_ptr = func.alloc_vreg();
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: dst_ptr,
        src: MirValue::StackSlot(dst_slot),
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::KptrXchg as u32,
        args: vec![MirValue::VReg(dst_ptr), MirValue::Const(0)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected non-map kptr_xchg destination error");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper kptr_xchg dst expects pointer in [Map]")
    }));
}

#[test]
fn test_type_error_unknown_kfunc_signature() {
    let mut func = make_test_function();
    let dst = func.alloc_vreg();
    let arg = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: arg,
        src: MirValue::Const(0),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "unknown_kfunc".to_string(),
        btf_id: None,
        args: vec![arg],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected unknown-kfunc type error");
    assert!(errs.iter().any(|e| e.message.contains("unknown kfunc")));
}

#[test]
fn test_type_error_kfunc_pointer_argument_required() {
    let mut func = make_test_function();
    let dst = func.alloc_vreg();
    let scalar = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: scalar,
        src: MirValue::Const(42),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_task_release".to_string(),
        btf_id: None,
        args: vec![scalar],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected pointer-argument kfunc type error");
    assert!(errs.iter().any(|e| e.message.contains("expects pointer")));
}

#[test]
fn test_type_error_kfunc_pointer_argument_requires_kernel_space() {
    let mut func = make_test_function();
    let ptr = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::StackSlot(slot),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_task_acquire".to_string(),
        btf_id: None,
        args: vec![ptr],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected kernel-pointer kfunc type error");
    assert!(
        errs.iter()
            .any(|e| e.message.contains("arg0 expects kernel pointer")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_type_error_kfunc_list_push_front_requires_kernel_space() {
    let mut func = make_test_function();
    let head = func.alloc_vreg();
    let node = func.alloc_vreg();
    let meta = func.alloc_vreg();
    let off = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let head_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let node_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: head,
        src: MirValue::StackSlot(head_slot),
    });
    block.instructions.push(MirInst::Copy {
        dst: node,
        src: MirValue::StackSlot(node_slot),
    });
    block.instructions.push(MirInst::Copy {
        dst: meta,
        src: MirValue::Const(0),
    });
    block.instructions.push(MirInst::Copy {
        dst: off,
        src: MirValue::Const(0),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_list_push_front_impl".to_string(),
        btf_id: None,
        args: vec![head, node, meta, off],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected list-push-front kernel-pointer kfunc type error");
    assert!(
        errs.iter()
            .any(|e| e.message.contains("arg0 expects kernel pointer")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_type_error_kfunc_path_d_path_requires_kernel_path_arg() {
    let mut func = make_test_function();
    let path = func.alloc_vreg();
    let buf = func.alloc_vreg();
    let size = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let path_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let buf_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: path,
        src: MirValue::StackSlot(path_slot),
    });
    block.instructions.push(MirInst::Copy {
        dst: buf,
        src: MirValue::StackSlot(buf_slot),
    });
    block.instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(32),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_path_d_path".to_string(),
        btf_id: None,
        args: vec![path, buf, size],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected path_d_path kernel-pointer kfunc type error");
    assert!(
        errs.iter()
            .any(|e| e.message.contains("arg0 expects kernel pointer")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_type_error_kfunc_rbtree_first_requires_kernel_space() {
    let mut func = make_test_function();
    let root = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: root,
        src: MirValue::StackSlot(slot),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_rbtree_first".to_string(),
        btf_id: None,
        args: vec![root],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected rbtree_first kernel-pointer kfunc type error");
    assert!(
        errs.iter()
            .any(|e| e.message.contains("arg0 expects kernel pointer")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_infer_kfunc_cpumask_create_pointer_return() {
    let mut func = make_test_function();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_cpumask_create".to_string(),
        btf_id: None,
        args: vec![],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti
        .infer(&func)
        .expect("expected cpumask kfunc type inference");
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!("expected kernel pointer return, got {:?}", other),
    }
}

#[test]
fn test_infer_kfunc_obj_new_pointer_return() {
    let mut func = make_test_function();
    let type_id = func.alloc_vreg();
    let meta = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: meta,
        src: MirValue::Const(0),
    });
    block.instructions.push(MirInst::Copy {
        dst: type_id,
        src: MirValue::Const(1),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_obj_new_impl".to_string(),
        btf_id: None,
        args: vec![type_id, meta],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti
        .infer(&func)
        .expect("expected object-new kfunc type inference");
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!("expected kernel pointer return, got {:?}", other),
    }
}

#[test]
fn test_infer_kfunc_percpu_obj_new_pointer_return() {
    let mut func = make_test_function();
    let type_id = func.alloc_vreg();
    let meta = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: meta,
        src: MirValue::Const(0),
    });
    block.instructions.push(MirInst::Copy {
        dst: type_id,
        src: MirValue::Const(1),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_percpu_obj_new_impl".to_string(),
        btf_id: None,
        args: vec![type_id, meta],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti
        .infer(&func)
        .expect("expected percpu-object-new kfunc type inference");
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!("expected kernel pointer return, got {:?}", other),
    }
}

#[test]
fn test_infer_kfunc_get_task_exe_file_pointer_return() {
    let mut func = make_test_function();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(1),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_get_task_exe_file".to_string(),
        btf_id: None,
        args: vec![task],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti
        .infer(&func)
        .expect("expected get_task_exe_file kfunc type inference");
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!("expected kernel pointer return, got {:?}", other),
    }
}

#[test]
fn test_infer_kfunc_iter_task_vma_next_pointer_return() {
    let mut func = make_test_function();
    let it = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: it,
        src: MirValue::StackSlot(slot),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_iter_task_vma_next".to_string(),
        btf_id: None,
        args: vec![it],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti
        .infer(&func)
        .expect("expected iter_task_vma_next kfunc type inference");
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!("expected kernel pointer return, got {:?}", other),
    }
}

#[test]
fn test_type_error_kfunc_obj_drop_requires_kernel_space() {
    let mut func = make_test_function();
    let ptr = func.alloc_vreg();
    let meta = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::StackSlot(slot),
    });
    block.instructions.push(MirInst::Copy {
        dst: meta,
        src: MirValue::Const(0),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_obj_drop_impl".to_string(),
        btf_id: None,
        args: vec![ptr, meta],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected object-drop kernel-pointer kfunc type error");
    assert!(
        errs.iter()
            .any(|e| e.message.contains("arg0 expects kernel pointer")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_infer_subfunction_schemes_rejects_recursive_calls_with_guidance() {
    let mut subfn = MirFunction::with_name("rec");
    subfn.param_count = 1;
    let entry = subfn.alloc_block();
    subfn.entry = entry;
    let arg = VReg(0);
    subfn
        .block_mut(entry)
        .instructions
        .push(MirInst::CallSubfn {
            dst: arg,
            subfn: SubfunctionId(0),
            args: vec![arg],
        });
    subfn.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::VReg(arg)),
    };

    let errs = infer_subfunction_schemes(&[subfn], None)
        .expect_err("expected recursive subfunction scheme inference to fail");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("polymorphic recursion requires explicit type annotations")
    }));
}

#[test]
fn test_infer_subfunction_schemes_rejects_param_limit() {
    let mut subfn = MirFunction::with_name("too_many_params");
    subfn.param_count = 6;
    let entry = subfn.alloc_block();
    subfn.entry = entry;
    subfn.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let errs = infer_subfunction_schemes(&[subfn], None)
        .expect_err("expected subfunction param-limit error");
    assert!(
        errs.iter()
            .any(|e| e.message.contains("at most 5 arguments"))
    );
}

#[test]
fn test_type_error_pointer_add() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();
    let v1 = func.alloc_vreg();
    let v2 = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: v0,
        field: CtxField::Comm,
        slot: None,
    });
    block.instructions.push(MirInst::Copy {
        dst: v1,
        src: MirValue::VReg(v0),
    });
    block.instructions.push(MirInst::BinOp {
        dst: v2,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(v0),
        rhs: MirValue::VReg(v1),
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    assert!(ti.infer(&func).is_err());
}

#[test]
fn test_stack_pointer_add_bounded_offset() {
    let mut func = make_test_function();
    let list = func.alloc_vreg();
    let len = func.alloc_vreg();
    let scaled = func.alloc_vreg();
    let ptr = func.alloc_vreg();

    let slot = func.alloc_stack_slot(40, 8, StackSlotKind::ListBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::ListNew {
        dst: list,
        buffer: slot,
        max_len: 4,
    });
    block.instructions.push(MirInst::ListLen { dst: len, list });
    block.instructions.push(MirInst::BinOp {
        dst: scaled,
        op: BinOpKind::Mul,
        lhs: MirValue::VReg(len),
        rhs: MirValue::Const(8),
    });
    block.instructions.push(MirInst::BinOp {
        dst: ptr,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(list),
        rhs: MirValue::VReg(scaled),
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    assert!(
        ti.infer(&func).is_ok(),
        "bounded stack pointer arithmetic should type-check"
    );
}

#[test]
fn test_stack_pointer_add_unbounded_offset_errors() {
    let mut func = make_test_function();
    let ptr = func.alloc_vreg();
    let idx = func.alloc_vreg();
    let out = func.alloc_vreg();

    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::StackSlot(slot),
    });
    block.instructions.push(MirInst::LoadCtxField {
        dst: idx,
        field: CtxField::Pid,
        slot: None,
    });
    block.instructions.push(MirInst::BinOp {
        dst: out,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(ptr),
        rhs: MirValue::VReg(idx),
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    assert!(
        ti.infer(&func).is_err(),
        "unbounded stack pointer arithmetic should be rejected"
    );
}

#[test]
fn test_type_error_read_str_non_ptr() {
    use crate::compiler::mir::StackSlotKind;

    let mut func = make_test_function();
    let v0 = func.alloc_vreg();
    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::Const(123),
    });
    block.instructions.push(MirInst::ReadStr {
        dst: slot,
        ptr: v0,
        user_space: false,
        max_len: 16,
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    assert!(ti.infer(&func).is_err());
}

#[test]
fn test_type_error_emit_record_string_scalar() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::Const(7),
    });
    block.instructions.push(MirInst::EmitRecord {
        fields: vec![RecordFieldDef {
            name: "comm".to_string(),
            value: v0,
            ty: MirType::Array {
                elem: Box::new(MirType::U8),
                len: 16,
            },
        }],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    assert!(ti.infer(&func).is_err());
}
