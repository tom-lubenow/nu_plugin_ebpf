use std::collections::HashMap;

use crate::compiler::instruction::BpfHelper;
use crate::compiler::mir::{
    AddressSpace, BinOpKind, BlockId, CtxField, MirFunction, MirInst, MirType, MirValue,
    StackSlotKind, SubfunctionId, VReg,
};

pub(crate) fn unknown_kernel_ptr_ty() -> MirType {
    MirType::Ptr {
        pointee: Box::new(MirType::Unknown),
        address_space: AddressSpace::Kernel,
    }
}

#[derive(Clone, Copy)]
pub(crate) enum ExplicitNullRefKfuncCase {
    CgroupFromId,
    TaskExeFile,
    CpumaskCreate,
    CryptoCtxAcquire,
    ObjNewImpl,
    PerCpuObjNewImpl,
}

impl ExplicitNullRefKfuncCase {
    fn acquire_kfunc(self) -> &'static str {
        match self {
            Self::CgroupFromId => "bpf_cgroup_from_id",
            Self::TaskExeFile => "bpf_get_task_exe_file",
            Self::CpumaskCreate => "bpf_cpumask_create",
            Self::CryptoCtxAcquire => "bpf_crypto_ctx_acquire",
            Self::ObjNewImpl => "bpf_obj_new_impl",
            Self::PerCpuObjNewImpl => "bpf_percpu_obj_new_impl",
        }
    }

    fn release_kfunc(self) -> &'static str {
        match self {
            Self::CgroupFromId => "bpf_cgroup_release",
            Self::TaskExeFile => "bpf_put_file",
            Self::CpumaskCreate => "bpf_cpumask_release",
            Self::CryptoCtxAcquire => "bpf_crypto_ctx_release",
            Self::ObjNewImpl => "bpf_obj_drop_impl",
            Self::PerCpuObjNewImpl => "bpf_percpu_obj_drop_impl",
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::CgroupFromId => "cgroup",
            Self::TaskExeFile => "file",
            Self::CpumaskCreate => "cpumask",
            Self::CryptoCtxAcquire => "crypto_ctx",
            Self::ObjNewImpl => "object",
            Self::PerCpuObjNewImpl => "percpu_object",
        }
    }

    fn param_count(self) -> usize {
        match self {
            Self::TaskExeFile | Self::CryptoCtxAcquire => 2,
            Self::CgroupFromId
            | Self::CpumaskCreate
            | Self::ObjNewImpl
            | Self::PerCpuObjNewImpl => 1,
        }
    }

    fn push_acquire_args(
        self,
        func: &mut MirFunction,
        acquire_path: BlockId,
        types: &mut HashMap<VReg, MirType>,
    ) -> Vec<VReg> {
        match self {
            Self::CgroupFromId => {
                let cgid = func.alloc_vreg();
                func.block_mut(acquire_path)
                    .instructions
                    .push(MirInst::Copy {
                        dst: cgid,
                        src: MirValue::Const(123),
                    });
                types.insert(cgid, MirType::I64);
                vec![cgid]
            }
            Self::TaskExeFile => {
                let task = func.alloc_vreg();
                types.insert(task, unknown_kernel_ptr_ty());
                vec![task]
            }
            Self::CpumaskCreate => vec![],
            Self::CryptoCtxAcquire => {
                let crypto_ctx = func.alloc_vreg();
                types.insert(crypto_ctx, unknown_kernel_ptr_ty());
                vec![crypto_ctx]
            }
            Self::ObjNewImpl | Self::PerCpuObjNewImpl => {
                let type_id = func.alloc_vreg();
                let meta = func.alloc_vreg();
                func.block_mut(acquire_path)
                    .instructions
                    .push(MirInst::Copy {
                        dst: type_id,
                        src: MirValue::Const(1),
                    });
                func.block_mut(acquire_path)
                    .instructions
                    .push(MirInst::Copy {
                        dst: meta,
                        src: MirValue::Const(0),
                    });
                types.insert(type_id, MirType::I64);
                types.insert(meta, MirType::I64);
                vec![type_id, meta]
            }
        }
    }

    fn push_release_args(
        self,
        func: &mut MirFunction,
        release: BlockId,
        joined: VReg,
        types: &mut HashMap<VReg, MirType>,
    ) -> Vec<VReg> {
        match self {
            Self::ObjNewImpl | Self::PerCpuObjNewImpl => {
                let meta = func.alloc_vreg();
                func.block_mut(release).instructions.push(MirInst::Copy {
                    dst: meta,
                    src: MirValue::Const(0),
                });
                types.insert(meta, MirType::I64);
                vec![joined, meta]
            }
            Self::CgroupFromId
            | Self::TaskExeFile
            | Self::CpumaskCreate
            | Self::CryptoCtxAcquire => vec![joined],
        }
    }
}

pub(crate) fn explicit_null_ref_join_release_mir(
    case: ExplicitNullRefKfuncCase,
    use_phi: bool,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let acquire_path = func.alloc_block();
    let null_path = func.alloc_block();
    let join = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let mut types = HashMap::new();
    let selector = func.alloc_vreg();
    let acquire_args = case.push_acquire_args(&mut func, acquire_path, &mut types);
    let select_cond = func.alloc_vreg();
    let acquired = func.alloc_vreg();
    let null_ref = use_phi.then(|| func.alloc_vreg());
    let joined = if use_phi { func.alloc_vreg() } else { acquired };
    let release_cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.param_count = case.param_count();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: select_cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(selector),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: select_cond,
        if_true: acquire_path,
        if_false: null_path,
    };

    func.block_mut(acquire_path)
        .instructions
        .push(MirInst::CallKfunc {
            dst: acquired,
            kfunc: case.acquire_kfunc().to_string(),
            btf_id: None,
            args: acquire_args,
        });
    func.block_mut(acquire_path).terminator = MirInst::Jump { target: join };

    func.block_mut(null_path).instructions.push(MirInst::Copy {
        dst: null_ref.unwrap_or(joined),
        src: MirValue::Const(0),
    });
    func.block_mut(null_path).terminator = MirInst::Jump { target: join };

    if let Some(null_ref) = null_ref {
        func.block_mut(join).instructions.push(MirInst::Phi {
            dst: joined,
            args: vec![(acquire_path, acquired), (null_path, null_ref)],
        });
        types.insert(null_ref, MirType::I64);
    }
    func.block_mut(join).instructions.push(MirInst::BinOp {
        dst: release_cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(joined),
        rhs: MirValue::Const(0),
    });
    func.block_mut(join).terminator = MirInst::Branch {
        cond: release_cond,
        if_true: release,
        if_false: done,
    };

    let release_args = case.push_release_args(&mut func, release, joined, &mut types);
    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: case.release_kfunc().to_string(),
            btf_id: None,
            args: release_args,
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    types.insert(selector, MirType::I64);
    types.insert(select_cond, MirType::Bool);
    types.insert(acquired, unknown_kernel_ptr_ty());
    if use_phi {
        types.insert(joined, unknown_kernel_ptr_ty());
    }
    types.insert(release_cond, MirType::Bool);
    types.insert(release_ret, MirType::I64);

    (func, types)
}

pub(crate) fn xdp_get_xfrm_state_explicit_null_join_mir(
    use_phi: bool,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let acquire_path = func.alloc_block();
    let null_path = func.alloc_block();
    let join = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let selector = func.alloc_vreg();
    let select_cond = func.alloc_vreg();
    let ctx = func.alloc_vreg();
    let opts = func.alloc_vreg();
    let size = func.alloc_vreg();
    let acquired = func.alloc_vreg();
    let null_ref = use_phi.then(|| func.alloc_vreg());
    let joined = if use_phi { func.alloc_vreg() } else { acquired };
    let release_cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();
    let opts_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: select_cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(selector),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: select_cond,
        if_true: acquire_path,
        if_false: null_path,
    };

    func.block_mut(acquire_path)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(acquire_path)
        .instructions
        .push(MirInst::Copy {
            dst: opts,
            src: MirValue::StackSlot(opts_slot),
        });
    func.block_mut(acquire_path)
        .instructions
        .push(MirInst::Copy {
            dst: size,
            src: MirValue::Const(32),
        });
    func.block_mut(acquire_path)
        .instructions
        .push(MirInst::CallKfunc {
            dst: acquired,
            kfunc: "bpf_xdp_get_xfrm_state".to_string(),
            btf_id: None,
            args: vec![ctx, opts, size],
        });
    func.block_mut(acquire_path).terminator = MirInst::Jump { target: join };

    func.block_mut(null_path).instructions.push(MirInst::Copy {
        dst: null_ref.unwrap_or(joined),
        src: MirValue::Const(0),
    });
    func.block_mut(null_path).terminator = MirInst::Jump { target: join };

    if let Some(null_ref) = null_ref {
        func.block_mut(join).instructions.push(MirInst::Phi {
            dst: joined,
            args: vec![(acquire_path, acquired), (null_path, null_ref)],
        });
    }
    func.block_mut(join).instructions.push(MirInst::BinOp {
        dst: release_cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(joined),
        rhs: MirValue::Const(0),
    });
    func.block_mut(join).terminator = MirInst::Branch {
        cond: release_cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_xdp_xfrm_state_release".to_string(),
            btf_id: None,
            args: vec![joined],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(selector, MirType::I64);
    types.insert(select_cond, MirType::Bool);
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        opts,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(size, MirType::I64);
    types.insert(acquired, unknown_kernel_ptr_ty());
    if let Some(null_ref) = null_ref {
        types.insert(null_ref, MirType::I64);
        types.insert(joined, unknown_kernel_ptr_ty());
    }
    types.insert(release_cond, MirType::Bool);
    types.insert(release_ret, MirType::I64);

    (func, types)
}

fn unknown_stack_ptr_ty() -> MirType {
    MirType::Ptr {
        pointee: Box::new(MirType::Unknown),
        address_space: AddressSpace::Stack,
    }
}

fn user_ptr_ty() -> MirType {
    MirType::Ptr {
        pointee: Box::new(MirType::Unknown),
        address_space: AddressSpace::User,
    }
}

fn bpf_dynptr_stack_ptr_ty() -> MirType {
    MirType::Ptr {
        pointee: Box::new(MirType::opaque_named_struct("bpf_dynptr")),
        address_space: AddressSpace::Stack,
    }
}

fn dynptr_map_value_ptr_ty() -> MirType {
    MirType::Ptr {
        pointee: Box::new(MirType::Array {
            elem: Box::new(MirType::U8),
            len: 16,
        }),
        address_space: AddressSpace::Map,
    }
}

pub(crate) fn copy_from_user_dynptr_join_reinitialize_mir() -> (MirFunction, HashMap<VReg, MirType>)
{
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let init_path = func.alloc_block();
    let skip_init = func.alloc_block();
    let join = func.alloc_block();
    func.entry = entry;

    let cond = func.alloc_vreg();
    let src = func.alloc_vreg();
    func.param_count = 2;
    let dptr = func.alloc_vreg();
    let off = func.alloc_vreg();
    let size = func.alloc_vreg();
    let init_ret = func.alloc_vreg();
    let second_ret = func.alloc_vreg();
    let dptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: dptr,
        src: MirValue::StackSlot(dptr_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: off,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(8),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: init_path,
        if_false: skip_init,
    };
    func.block_mut(init_path)
        .instructions
        .push(MirInst::CallKfunc {
            dst: init_ret,
            kfunc: "bpf_copy_from_user_dynptr".to_string(),
            btf_id: None,
            args: vec![dptr, off, size, src],
        });
    func.block_mut(init_path).terminator = MirInst::Jump { target: join };
    func.block_mut(skip_init).terminator = MirInst::Jump { target: join };
    func.block_mut(join).instructions.push(MirInst::CallKfunc {
        dst: second_ret,
        kfunc: "bpf_copy_from_user_dynptr".to_string(),
        btf_id: None,
        args: vec![dptr, off, size, src],
    });
    func.block_mut(join).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(cond, MirType::Bool);
    types.insert(src, user_ptr_ty());
    types.insert(dptr, unknown_stack_ptr_ty());
    types.insert(off, MirType::I64);
    types.insert(size, MirType::I64);
    types.insert(init_ret, MirType::I64);
    types.insert(second_ret, MirType::I64);

    (func, types)
}

pub(crate) fn copy_from_user_task_dynptr_join_reinitialize_mir(
    kfunc: &str,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let has_task = func.alloc_block();
    let init_path = func.alloc_block();
    let skip_init = func.alloc_block();
    let join = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let cond = func.alloc_vreg();
    let src = func.alloc_vreg();
    let task = func.alloc_vreg();
    func.param_count = 3;
    let acquired = func.alloc_vreg();
    let has_task_cond = func.alloc_vreg();
    let dptr = func.alloc_vreg();
    let off = func.alloc_vreg();
    let size = func.alloc_vreg();
    let init_ret = func.alloc_vreg();
    let second_ret = func.alloc_vreg();
    let release_ret = func.alloc_vreg();
    let dptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: acquired,
        kfunc: "bpf_task_acquire".to_string(),
        btf_id: None,
        args: vec![task],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: has_task_cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(acquired),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: has_task_cond,
        if_true: has_task,
        if_false: done,
    };

    func.block_mut(has_task).instructions.push(MirInst::Copy {
        dst: dptr,
        src: MirValue::StackSlot(dptr_slot),
    });
    func.block_mut(has_task).instructions.push(MirInst::Copy {
        dst: off,
        src: MirValue::Const(0),
    });
    func.block_mut(has_task).instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(8),
    });
    func.block_mut(has_task).terminator = MirInst::Branch {
        cond,
        if_true: init_path,
        if_false: skip_init,
    };

    func.block_mut(init_path)
        .instructions
        .push(MirInst::CallKfunc {
            dst: init_ret,
            kfunc: kfunc.to_string(),
            btf_id: None,
            args: vec![dptr, off, size, src, acquired],
        });
    func.block_mut(init_path).terminator = MirInst::Jump { target: join };
    func.block_mut(skip_init).terminator = MirInst::Jump { target: join };
    func.block_mut(join).instructions.push(MirInst::CallKfunc {
        dst: second_ret,
        kfunc: kfunc.to_string(),
        btf_id: None,
        args: vec![dptr, off, size, src, acquired],
    });
    func.block_mut(join).terminator = MirInst::Jump { target: release };
    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_task_release".to_string(),
            btf_id: None,
            args: vec![acquired],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(cond, MirType::Bool);
    types.insert(src, user_ptr_ty());
    types.insert(task, unknown_kernel_ptr_ty());
    types.insert(acquired, unknown_kernel_ptr_ty());
    types.insert(has_task_cond, MirType::Bool);
    types.insert(dptr, unknown_stack_ptr_ty());
    types.insert(off, MirType::I64);
    types.insert(size, MirType::I64);
    types.insert(init_ret, MirType::I64);
    types.insert(second_ret, MirType::I64);
    types.insert(release_ret, MirType::I64);

    (func, types)
}

pub(crate) fn packet_dynptr_kfunc_join_reinitialize_mir(
    kfunc: &str,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let init_path = func.alloc_block();
    let skip_init = func.alloc_block();
    let join = func.alloc_block();
    func.entry = entry;

    let cond = func.alloc_vreg();
    func.param_count = 1;
    let ctx = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let dptr = func.alloc_vreg();
    let init_ret = func.alloc_vreg();
    let second_ret = func.alloc_vreg();
    let dptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: dptr,
        src: MirValue::StackSlot(dptr_slot),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: init_path,
        if_false: skip_init,
    };
    func.block_mut(init_path)
        .instructions
        .push(MirInst::CallKfunc {
            dst: init_ret,
            kfunc: kfunc.to_string(),
            btf_id: None,
            args: vec![ctx, flags, dptr],
        });
    func.block_mut(init_path).terminator = MirInst::Jump { target: join };
    func.block_mut(skip_init).terminator = MirInst::Jump { target: join };
    func.block_mut(join).instructions.push(MirInst::CallKfunc {
        dst: second_ret,
        kfunc: kfunc.to_string(),
        btf_id: None,
        args: vec![ctx, flags, dptr],
    });
    func.block_mut(join).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(cond, MirType::Bool);
    types.insert(ctx, unknown_kernel_ptr_ty());
    types.insert(flags, MirType::I64);
    types.insert(dptr, unknown_stack_ptr_ty());
    types.insert(init_ret, MirType::I64);
    types.insert(second_ret, MirType::I64);

    (func, types)
}

pub(crate) fn dynptr_clone_join_reinitialize_mir() -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let init_dst = func.alloc_block();
    let skip_init = func.alloc_block();
    let join = func.alloc_block();
    func.entry = entry;

    let cond = func.alloc_vreg();
    func.param_count = 1;
    let src = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let init_ret = func.alloc_vreg();
    let clone_ret = func.alloc_vreg();
    let src_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    func.entry_initialized_dynptr_slots.insert(src_slot);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: src,
        src: MirValue::StackSlot(src_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst,
        src: MirValue::StackSlot(dst_slot),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: init_dst,
        if_false: skip_init,
    };
    func.block_mut(init_dst)
        .instructions
        .push(MirInst::CallKfunc {
            dst: init_ret,
            kfunc: "bpf_dynptr_clone".to_string(),
            btf_id: None,
            args: vec![src, dst],
        });
    func.block_mut(init_dst).terminator = MirInst::Jump { target: join };
    func.block_mut(skip_init).terminator = MirInst::Jump { target: join };
    func.block_mut(join).instructions.push(MirInst::CallKfunc {
        dst: clone_ret,
        kfunc: "bpf_dynptr_clone".to_string(),
        btf_id: None,
        args: vec![src, dst],
    });
    func.block_mut(join).terminator = MirInst::Return { val: None };

    let dynptr_ty = bpf_dynptr_stack_ptr_ty();
    let mut types = HashMap::new();
    types.insert(cond, MirType::Bool);
    types.insert(src, dynptr_ty.clone());
    types.insert(dst, dynptr_ty);
    types.insert(init_ret, MirType::I64);
    types.insert(clone_ret, MirType::I64);

    (func, types)
}

pub(crate) fn dynptr_from_mem_join_reinitialize_mir() -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let has_data = func.alloc_block();
    let init_path = func.alloc_block();
    let skip_init = func.alloc_block();
    let join = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let cond = func.alloc_vreg();
    let data = func.alloc_vreg();
    func.param_count = 2;
    let has_data_cond = func.alloc_vreg();
    let init_ret = func.alloc_vreg();
    let second_ret = func.alloc_vreg();
    let dynptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: has_data_cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(data),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: has_data_cond,
        if_true: has_data,
        if_false: done,
    };
    func.block_mut(has_data).terminator = MirInst::Branch {
        cond,
        if_true: init_path,
        if_false: skip_init,
    };
    func.block_mut(init_path)
        .instructions
        .push(MirInst::CallHelper {
            dst: init_ret,
            helper: BpfHelper::DynptrFromMem as u32,
            args: vec![
                MirValue::VReg(data),
                MirValue::Const(8),
                MirValue::Const(0),
                MirValue::StackSlot(dynptr_slot),
            ],
        });
    func.block_mut(init_path).terminator = MirInst::Jump { target: join };
    func.block_mut(skip_init).terminator = MirInst::Jump { target: join };
    func.block_mut(join).instructions.push(MirInst::CallHelper {
        dst: second_ret,
        helper: BpfHelper::DynptrFromMem as u32,
        args: vec![
            MirValue::VReg(data),
            MirValue::Const(8),
            MirValue::Const(0),
            MirValue::StackSlot(dynptr_slot),
        ],
    });
    func.block_mut(join).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(cond, MirType::Bool);
    types.insert(data, dynptr_map_value_ptr_ty());
    types.insert(has_data_cond, MirType::Bool);
    types.insert(init_ret, MirType::I64);
    types.insert(second_ret, MirType::I64);

    (func, types)
}

pub(crate) struct UnknownStackObjectSubfnFixture {
    pub(crate) subfunctions: Vec<MirFunction>,
    pub(crate) subfunction_types: Vec<HashMap<VReg, MirType>>,
    pub(crate) caller: MirFunction,
    pub(crate) caller_types: HashMap<VReg, MirType>,
}

fn unknown_stack_object_init_subfn() -> (MirFunction, HashMap<VReg, MirType>) {
    let mut init = MirFunction::new();
    let init_entry = init.alloc_block();
    init.entry = init_entry;
    init.param_count = 1;
    init.vreg_count = 1;
    let init_slot = init.alloc_stack_slot(8, 8, StackSlotKind::Local);
    init.param_stack_slots.insert(0, init_slot);
    let init_ret = init.alloc_vreg();
    init.block_mut(init_entry)
        .instructions
        .push(MirInst::CallKfunc {
            dst: init_ret,
            kfunc: "__test_unknown_stack_object_init".to_string(),
            btf_id: None,
            args: vec![VReg(0)],
        });
    init.block_mut(init_entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(VReg(0), unknown_stack_ptr_ty());
    types.insert(init_ret, MirType::I64);

    (init, types)
}

fn unknown_stack_object_conditional_init_subfn() -> (MirFunction, HashMap<VReg, MirType>) {
    let mut init = MirFunction::new();
    let entry = init.alloc_block();
    let init_path = init.alloc_block();
    let done = init.alloc_block();
    init.entry = entry;
    init.param_count = 2;
    init.vreg_count = 2;
    let init_slot = init.alloc_stack_slot(8, 8, StackSlotKind::Local);
    init.param_stack_slots.insert(0, init_slot);
    init.block_mut(entry).terminator = MirInst::Branch {
        cond: VReg(1),
        if_true: init_path,
        if_false: done,
    };
    let init_ret = init.alloc_vreg();
    init.block_mut(init_path)
        .instructions
        .push(MirInst::CallKfunc {
            dst: init_ret,
            kfunc: "__test_unknown_stack_object_init".to_string(),
            btf_id: None,
            args: vec![VReg(0)],
        });
    init.block_mut(init_path).terminator = MirInst::Return { val: None };
    init.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(VReg(0), unknown_stack_ptr_ty());
    types.insert(VReg(1), MirType::Bool);
    types.insert(init_ret, MirType::I64);

    (init, types)
}

fn unknown_stack_object_destroy_subfn() -> (MirFunction, HashMap<VReg, MirType>) {
    let mut destroy = MirFunction::new();
    let destroy_entry = destroy.alloc_block();
    destroy.entry = destroy_entry;
    destroy.param_count = 1;
    destroy.vreg_count = 1;
    let destroy_slot = destroy.alloc_stack_slot(8, 8, StackSlotKind::Local);
    destroy.param_stack_slots.insert(0, destroy_slot);
    let destroy_ret = destroy.alloc_vreg();
    destroy
        .block_mut(destroy_entry)
        .instructions
        .push(MirInst::CallKfunc {
            dst: destroy_ret,
            kfunc: "__test_unknown_stack_object_destroy".to_string(),
            btf_id: None,
            args: vec![VReg(0)],
        });
    destroy.block_mut(destroy_entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(VReg(0), unknown_stack_ptr_ty());
    types.insert(destroy_ret, MirType::I64);

    (destroy, types)
}

fn unknown_stack_object_copy_subfn() -> (MirFunction, HashMap<VReg, MirType>) {
    let mut copy = MirFunction::new();
    let copy_entry = copy.alloc_block();
    copy.entry = copy_entry;
    copy.param_count = 2;
    copy.vreg_count = 2;
    let copy_src_slot = copy.alloc_stack_slot(8, 8, StackSlotKind::Local);
    let copy_dst_slot = copy.alloc_stack_slot(8, 8, StackSlotKind::Local);
    copy.param_stack_slots.insert(0, copy_src_slot);
    copy.param_stack_slots.insert(1, copy_dst_slot);
    let copy_ret = copy.alloc_vreg();
    copy.block_mut(copy_entry)
        .instructions
        .push(MirInst::CallKfunc {
            dst: copy_ret,
            kfunc: "__test_unknown_stack_object_copy".to_string(),
            btf_id: None,
            args: vec![VReg(0), VReg(1)],
        });
    copy.block_mut(copy_entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(VReg(0), unknown_stack_ptr_ty());
    types.insert(VReg(1), unknown_stack_ptr_ty());
    types.insert(copy_ret, MirType::I64);

    (copy, types)
}

pub(crate) fn unknown_stack_object_conditional_init_blocks_reinitialize_mir()
-> UnknownStackObjectSubfnFixture {
    let (init, init_types) = unknown_stack_object_conditional_init_subfn();

    let mut caller = MirFunction::new();
    let caller_entry = caller.alloc_block();
    caller.entry = caller_entry;
    caller.param_count = 1;
    caller.vreg_count = 1;
    let cond = VReg(0);
    let object = caller.alloc_vreg();
    let call_ret = caller.alloc_vreg();
    let retry_ret = caller.alloc_vreg();
    let object_slot = caller.alloc_stack_slot(8, 8, StackSlotKind::Local);
    caller
        .block_mut(caller_entry)
        .instructions
        .push(MirInst::Copy {
            dst: object,
            src: MirValue::StackSlot(object_slot),
        });
    caller
        .block_mut(caller_entry)
        .instructions
        .push(MirInst::CallSubfn {
            dst: call_ret,
            subfn: SubfunctionId(0),
            args: vec![object, cond],
        });
    caller
        .block_mut(caller_entry)
        .instructions
        .push(MirInst::CallKfunc {
            dst: retry_ret,
            kfunc: "__test_unknown_stack_object_init".to_string(),
            btf_id: None,
            args: vec![object],
        });
    caller.block_mut(caller_entry).terminator = MirInst::Return { val: None };

    let mut caller_types = HashMap::new();
    caller_types.insert(cond, MirType::Bool);
    caller_types.insert(object, unknown_stack_ptr_ty());
    caller_types.insert(call_ret, MirType::I64);
    caller_types.insert(retry_ret, MirType::I64);

    UnknownStackObjectSubfnFixture {
        subfunctions: vec![init],
        subfunction_types: vec![init_types],
        caller,
        caller_types,
    }
}

pub(crate) fn unknown_stack_object_lifecycle_composes_mir() -> UnknownStackObjectSubfnFixture {
    let (init, init_types) = unknown_stack_object_init_subfn();
    let (destroy, destroy_types) = unknown_stack_object_destroy_subfn();

    let mut caller = MirFunction::new();
    let entry = caller.alloc_block();
    caller.entry = entry;
    let object = caller.alloc_vreg();
    let init_call_ret = caller.alloc_vreg();
    let destroy_call_ret = caller.alloc_vreg();
    let object_slot = caller.alloc_stack_slot(8, 8, StackSlotKind::Local);
    caller.block_mut(entry).instructions.push(MirInst::Copy {
        dst: object,
        src: MirValue::StackSlot(object_slot),
    });
    caller
        .block_mut(entry)
        .instructions
        .push(MirInst::CallSubfn {
            dst: init_call_ret,
            subfn: SubfunctionId(0),
            args: vec![object],
        });
    caller
        .block_mut(entry)
        .instructions
        .push(MirInst::CallSubfn {
            dst: destroy_call_ret,
            subfn: SubfunctionId(1),
            args: vec![object],
        });
    caller.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut caller_types = HashMap::new();
    caller_types.insert(object, unknown_stack_ptr_ty());
    caller_types.insert(init_call_ret, MirType::I64);
    caller_types.insert(destroy_call_ret, MirType::I64);

    UnknownStackObjectSubfnFixture {
        subfunctions: vec![init, destroy],
        subfunction_types: vec![init_types, destroy_types],
        caller,
        caller_types,
    }
}

pub(crate) fn unknown_stack_object_copy_initializes_destination_mir()
-> UnknownStackObjectSubfnFixture {
    let (init, init_types) = unknown_stack_object_init_subfn();
    let (copy, copy_types) = unknown_stack_object_copy_subfn();
    let (destroy, destroy_types) = unknown_stack_object_destroy_subfn();

    let mut caller = MirFunction::new();
    let entry = caller.alloc_block();
    caller.entry = entry;
    let src = caller.alloc_vreg();
    let dst = caller.alloc_vreg();
    let init_call_ret = caller.alloc_vreg();
    let copy_call_ret = caller.alloc_vreg();
    let destroy_src_ret = caller.alloc_vreg();
    let destroy_dst_ret = caller.alloc_vreg();
    let src_slot = caller.alloc_stack_slot(8, 8, StackSlotKind::Local);
    let dst_slot = caller.alloc_stack_slot(8, 8, StackSlotKind::Local);
    caller.block_mut(entry).instructions.push(MirInst::Copy {
        dst: src,
        src: MirValue::StackSlot(src_slot),
    });
    caller.block_mut(entry).instructions.push(MirInst::Copy {
        dst,
        src: MirValue::StackSlot(dst_slot),
    });
    caller
        .block_mut(entry)
        .instructions
        .push(MirInst::CallSubfn {
            dst: init_call_ret,
            subfn: SubfunctionId(0),
            args: vec![src],
        });
    caller
        .block_mut(entry)
        .instructions
        .push(MirInst::CallSubfn {
            dst: copy_call_ret,
            subfn: SubfunctionId(1),
            args: vec![src, dst],
        });
    caller
        .block_mut(entry)
        .instructions
        .push(MirInst::CallSubfn {
            dst: destroy_src_ret,
            subfn: SubfunctionId(2),
            args: vec![src],
        });
    caller
        .block_mut(entry)
        .instructions
        .push(MirInst::CallSubfn {
            dst: destroy_dst_ret,
            subfn: SubfunctionId(2),
            args: vec![dst],
        });
    caller.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut caller_types = HashMap::new();
    caller_types.insert(src, unknown_stack_ptr_ty());
    caller_types.insert(dst, unknown_stack_ptr_ty());
    caller_types.insert(init_call_ret, MirType::I64);
    caller_types.insert(copy_call_ret, MirType::I64);
    caller_types.insert(destroy_src_ret, MirType::I64);
    caller_types.insert(destroy_dst_ret, MirType::I64);

    UnknownStackObjectSubfnFixture {
        subfunctions: vec![init, copy, destroy],
        subfunction_types: vec![init_types, copy_types, destroy_types],
        caller,
        caller_types,
    }
}

pub(crate) fn unknown_stack_object_init_blocks_reinitialize_mir() -> UnknownStackObjectSubfnFixture
{
    let (init, init_types) = unknown_stack_object_init_subfn();

    let mut caller = MirFunction::new();
    let entry = caller.alloc_block();
    caller.entry = entry;
    let object = caller.alloc_vreg();
    let first_ret = caller.alloc_vreg();
    let second_ret = caller.alloc_vreg();
    let object_slot = caller.alloc_stack_slot(8, 8, StackSlotKind::Local);
    caller.block_mut(entry).instructions.push(MirInst::Copy {
        dst: object,
        src: MirValue::StackSlot(object_slot),
    });
    caller
        .block_mut(entry)
        .instructions
        .push(MirInst::CallSubfn {
            dst: first_ret,
            subfn: SubfunctionId(0),
            args: vec![object],
        });
    caller
        .block_mut(entry)
        .instructions
        .push(MirInst::CallSubfn {
            dst: second_ret,
            subfn: SubfunctionId(0),
            args: vec![object],
        });
    caller.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut caller_types = HashMap::new();
    caller_types.insert(object, unknown_stack_ptr_ty());
    caller_types.insert(first_ret, MirType::I64);
    caller_types.insert(second_ret, MirType::I64);

    UnknownStackObjectSubfnFixture {
        subfunctions: vec![init],
        subfunction_types: vec![init_types],
        caller,
        caller_types,
    }
}
