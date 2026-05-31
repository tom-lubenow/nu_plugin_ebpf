use std::collections::HashMap;

use crate::compiler::mir::{
    AddressSpace, BinOpKind, BlockId, CtxField, MirFunction, MirInst, MirType, MirValue,
    StackSlotKind, VReg,
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
}

impl ExplicitNullRefKfuncCase {
    fn acquire_kfunc(self) -> &'static str {
        match self {
            Self::CgroupFromId => "bpf_cgroup_from_id",
            Self::TaskExeFile => "bpf_get_task_exe_file",
            Self::CpumaskCreate => "bpf_cpumask_create",
            Self::CryptoCtxAcquire => "bpf_crypto_ctx_acquire",
            Self::ObjNewImpl => "bpf_obj_new_impl",
        }
    }

    fn release_kfunc(self) -> &'static str {
        match self {
            Self::CgroupFromId => "bpf_cgroup_release",
            Self::TaskExeFile => "bpf_put_file",
            Self::CpumaskCreate => "bpf_cpumask_release",
            Self::CryptoCtxAcquire => "bpf_crypto_ctx_release",
            Self::ObjNewImpl => "bpf_obj_drop_impl",
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::CgroupFromId => "cgroup",
            Self::TaskExeFile => "file",
            Self::CpumaskCreate => "cpumask",
            Self::CryptoCtxAcquire => "crypto_ctx",
            Self::ObjNewImpl => "object",
        }
    }

    fn param_count(self) -> usize {
        match self {
            Self::TaskExeFile | Self::CryptoCtxAcquire => 2,
            Self::CgroupFromId | Self::CpumaskCreate | Self::ObjNewImpl => 1,
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
            Self::ObjNewImpl => {
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
            Self::ObjNewImpl => {
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
