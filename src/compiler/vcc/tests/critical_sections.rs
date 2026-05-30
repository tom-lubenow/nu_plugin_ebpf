use super::*;

#[derive(Clone, Copy, Debug)]
enum CriticalSectionKind {
    Rcu,
    Preempt,
    LocalIrq,
    ResSpin,
    ResSpinIrqsave,
    BpfSpin,
}

#[derive(Clone, Copy)]
struct CriticalSectionRegs {
    lock: Option<VReg>,
    flags: Option<VReg>,
}

impl CriticalSectionKind {
    fn all() -> &'static [Self] {
        &[
            Self::Rcu,
            Self::Preempt,
            Self::LocalIrq,
            Self::ResSpin,
            Self::ResSpinIrqsave,
            Self::BpfSpin,
        ]
    }

    fn requires_lock(self) -> bool {
        matches!(self, Self::ResSpin | Self::ResSpinIrqsave | Self::BpfSpin)
    }

    fn requires_flags(self) -> bool {
        matches!(self, Self::LocalIrq | Self::ResSpinIrqsave)
    }

    fn leak_error(self) -> &'static str {
        match self {
            Self::Rcu => "unreleased RCU read lock",
            Self::Preempt => "unreleased preempt disable",
            Self::LocalIrq => "unreleased local irq disable",
            Self::ResSpin => "unreleased res spin lock",
            Self::ResSpinIrqsave => "unreleased res spin lock irqsave",
            Self::BpfSpin => "unreleased bpf spin lock",
        }
    }
}

fn maybe_lock_ty(kind: CriticalSectionKind) -> Option<MirType> {
    match kind {
        CriticalSectionKind::ResSpin | CriticalSectionKind::ResSpinIrqsave => Some(MirType::Ptr {
            pointee: Box::new(MirType::bpf_res_spin_lock_struct()),
            address_space: AddressSpace::Kernel,
        }),
        CriticalSectionKind::BpfSpin => Some(MirType::Ptr {
            pointee: Box::new(MirType::bpf_spin_lock_struct()),
            address_space: AddressSpace::Map,
        }),
        CriticalSectionKind::Rcu | CriticalSectionKind::Preempt | CriticalSectionKind::LocalIrq => {
            None
        }
    }
}

fn stack_flags_ty() -> MirType {
    MirType::Ptr {
        pointee: Box::new(MirType::Unknown),
        address_space: AddressSpace::Stack,
    }
}

fn push_kfunc(func: &mut MirFunction, block: BlockId, kfunc: &str, args: Vec<VReg>) -> VReg {
    let ret = func.alloc_vreg();
    func.block_mut(block).instructions.push(MirInst::CallKfunc {
        dst: ret,
        kfunc: kfunc.to_string(),
        btf_id: None,
        args,
    });
    ret
}

fn push_bpf_spin_helper(
    func: &mut MirFunction,
    block: BlockId,
    helper: BpfHelper,
    lock: VReg,
) -> VReg {
    let ret = func.alloc_vreg();
    func.block_mut(block)
        .instructions
        .push(MirInst::CallHelper {
            dst: ret,
            helper: helper as u32,
            args: vec![MirValue::VReg(lock)],
        });
    ret
}

fn push_acquire(
    func: &mut MirFunction,
    block: BlockId,
    kind: CriticalSectionKind,
    regs: CriticalSectionRegs,
) -> VReg {
    match kind {
        CriticalSectionKind::Rcu => push_kfunc(func, block, "bpf_rcu_read_lock", vec![]),
        CriticalSectionKind::Preempt => push_kfunc(func, block, "bpf_preempt_disable", vec![]),
        CriticalSectionKind::LocalIrq => push_kfunc(
            func,
            block,
            "bpf_local_irq_save",
            vec![regs.flags.expect("local irq tests need flags")],
        ),
        CriticalSectionKind::ResSpin => push_kfunc(
            func,
            block,
            "bpf_res_spin_lock",
            vec![regs.lock.expect("res spin tests need lock")],
        ),
        CriticalSectionKind::ResSpinIrqsave => push_kfunc(
            func,
            block,
            "bpf_res_spin_lock_irqsave",
            vec![
                regs.lock.expect("res spin irqsave tests need lock"),
                regs.flags.expect("res spin irqsave tests need flags"),
            ],
        ),
        CriticalSectionKind::BpfSpin => push_bpf_spin_helper(
            func,
            block,
            BpfHelper::SpinLock,
            regs.lock.expect("bpf spin tests need lock"),
        ),
    }
}

fn push_release(
    func: &mut MirFunction,
    block: BlockId,
    kind: CriticalSectionKind,
    regs: CriticalSectionRegs,
) -> VReg {
    match kind {
        CriticalSectionKind::Rcu => push_kfunc(func, block, "bpf_rcu_read_unlock", vec![]),
        CriticalSectionKind::Preempt => push_kfunc(func, block, "bpf_preempt_enable", vec![]),
        CriticalSectionKind::LocalIrq => push_kfunc(
            func,
            block,
            "bpf_local_irq_restore",
            vec![regs.flags.expect("local irq tests need flags")],
        ),
        CriticalSectionKind::ResSpin => push_kfunc(
            func,
            block,
            "bpf_res_spin_unlock",
            vec![regs.lock.expect("res spin tests need lock")],
        ),
        CriticalSectionKind::ResSpinIrqsave => push_kfunc(
            func,
            block,
            "bpf_res_spin_unlock_irqrestore",
            vec![
                regs.lock.expect("res spin irqsave tests need lock"),
                regs.flags.expect("res spin irqsave tests need flags"),
            ],
        ),
        CriticalSectionKind::BpfSpin => push_bpf_spin_helper(
            func,
            block,
            BpfHelper::SpinUnlock,
            regs.lock.expect("bpf spin tests need lock"),
        ),
    }
}

fn insert_scalar_types(types: &mut HashMap<VReg, MirType>, regs: &[VReg]) {
    for reg in regs {
        types.insert(*reg, MirType::I64);
    }
}

fn critical_section_branch_function(
    kind: CriticalSectionKind,
    leak_left_branch: bool,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let (mut func, entry) = new_mir_function();
    let left = func.alloc_block();
    let right = func.alloc_block();
    let done = func.alloc_block();
    func.param_count = if kind.requires_lock() { 2 } else { 1 };

    let selector = func.alloc_vreg();
    let lock = kind.requires_lock().then(|| {
        let lock = func.alloc_vreg();
        func.param_non_null.insert(lock.0 as usize);
        lock
    });
    let flags = kind.requires_flags().then(|| {
        let flags = func.alloc_vreg();
        let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: flags,
            src: MirValue::StackSlot(slot),
        });
        flags
    });
    let cond = func.alloc_vreg();
    let regs = CriticalSectionRegs { lock, flags };

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Eq,
        lhs: MirValue::VReg(selector),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: left,
        if_false: right,
    };

    let left_acquire = push_acquire(&mut func, left, kind, regs);
    let left_release = (!leak_left_branch).then(|| push_release(&mut func, left, kind, regs));
    func.block_mut(left).terminator = MirInst::Jump { target: done };

    let right_acquire = push_acquire(&mut func, right, kind, regs);
    let right_release = push_release(&mut func, right, kind, regs);
    func.block_mut(right).terminator = MirInst::Jump { target: done };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(selector, MirType::I64);
    types.insert(cond, MirType::Bool);
    if let Some(lock) = lock {
        types.insert(lock, maybe_lock_ty(kind).expect("lock type"));
    }
    if let Some(flags) = flags {
        types.insert(flags, stack_flags_ty());
    }
    insert_scalar_types(
        &mut types,
        &[
            Some(left_acquire),
            left_release,
            Some(right_acquire),
            Some(right_release),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>(),
    );

    (func, types)
}

#[test]
fn test_verify_mir_critical_sections_accept_balanced_lifecycle_on_both_branches() {
    for kind in CriticalSectionKind::all() {
        let (func, types) = critical_section_branch_function(*kind, false);
        verify_mir(&func, &types)
            .unwrap_or_else(|err| panic!("expected balanced {kind:?} branches to verify: {err:?}"));
    }
}

#[test]
fn test_verify_mir_critical_sections_reject_one_branch_leak() {
    for kind in CriticalSectionKind::all() {
        let (func, types) = critical_section_branch_function(*kind, true);
        let err = match verify_mir(&func, &types) {
            Ok(()) => panic!("expected one-branch {kind:?} leak rejection"),
            Err(err) => err,
        };
        assert!(
            err.iter().any(|e| e.message.contains(kind.leak_error())),
            "unexpected {kind:?} errors: {err:?}",
        );
    }
}
