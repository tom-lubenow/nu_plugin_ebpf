#[test]
fn test_verify_mir_for_probe_context_syscall_helpers_accept_syscall_program() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let attr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let name_slot = func.alloc_stack_slot(16, 1, StackSlotKind::StringBuffer);
    let res_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let sys_bpf = func.alloc_vreg();
    let btf_find = func.alloc_vreg();
    let sys_close = func.alloc_vreg();
    let kallsyms = func.alloc_vreg();
    let kallsyms_zero_stack = func.alloc_vreg();
    let kallsyms_zero_null = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: sys_bpf,
            helper: BpfHelper::SysBpf as u32,
            args: vec![
                MirValue::Const(0),
                MirValue::StackSlot(attr_slot),
                MirValue::Const(16),
            ],
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: btf_find,
            helper: BpfHelper::BtfFindByNameKind as u32,
            args: vec![
                MirValue::StackSlot(name_slot),
                MirValue::Const(16),
                MirValue::Const(1),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: sys_close,
            helper: BpfHelper::SysClose as u32,
            args: vec![MirValue::Const(3)],
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: kallsyms,
            helper: BpfHelper::KallsymsLookupName as u32,
            args: vec![
                MirValue::StackSlot(name_slot),
                MirValue::Const(16),
                MirValue::Const(0),
                MirValue::StackSlot(res_slot),
            ],
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: kallsyms_zero_stack,
            helper: BpfHelper::KallsymsLookupName as u32,
            args: vec![
                MirValue::StackSlot(name_slot),
                MirValue::Const(0),
                MirValue::Const(0),
                MirValue::StackSlot(res_slot),
            ],
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: kallsyms_zero_null,
            helper: BpfHelper::KallsymsLookupName as u32,
            args: vec![
                MirValue::Const(0),
                MirValue::Const(0),
                MirValue::Const(0),
                MirValue::StackSlot(res_slot),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let types = HashMap::from([
        (sys_bpf, MirType::I64),
        (btf_find, MirType::I64),
        (sys_close, MirType::I64),
        (kallsyms, MirType::I64),
        (kallsyms_zero_stack, MirType::I64),
        (kallsyms_zero_null, MirType::I64),
    ]);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Syscall, "demo");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected modeled syscall helpers to verify on syscall programs");
}

#[test]
fn test_verify_mir_for_probe_context_syscall_program_rejects_unmodeled_helper() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::GetCurrentComm as u32,
            args: vec![],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let types = HashMap::from([(dst, MirType::I64)]);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Syscall, "demo");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected unmodeled syscall helper to be rejected");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_get_current_comm' is not modeled for syscall programs")
    }));
}

#[test]
fn test_verify_mir_helper_snprintf_accepts_rodata_format() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let fmt = func.alloc_vreg();
    let out_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let data_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadGlobal {
            dst: fmt,
            symbol: "__nu_rodata_fmt".to_string(),
            ty: MirType::Array {
                elem: Box::new(MirType::U8),
                len: 16,
            },
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::Snprintf as u32,
            args: vec![
                MirValue::StackSlot(out_slot),
                MirValue::Const(32),
                MirValue::VReg(fmt),
                MirValue::StackSlot(data_slot),
                MirValue::Const(16),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let types = HashMap::from([(dst, MirType::I64)]);
    verify_mir(&func, &types).expect("expected bpf_snprintf with map format to verify");
}

#[test]
fn test_verify_mir_helper_snprintf_accepts_zero_size_null_buffers() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let fmt = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadGlobal {
            dst: fmt,
            symbol: "__nu_rodata_fmt".to_string(),
            ty: MirType::Array {
                elem: Box::new(MirType::U8),
                len: 16,
            },
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::Snprintf as u32,
            args: vec![
                MirValue::Const(0),
                MirValue::Const(0),
                MirValue::VReg(fmt),
                MirValue::Const(0),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let types = HashMap::from([(dst, MirType::I64)]);
    verify_mir(&func, &types).expect("expected bpf_snprintf zero-size null buffers to verify");
}

#[test]
fn test_verify_mir_helper_snprintf_rejects_stack_format() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let out_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let fmt_slot = func.alloc_stack_slot(16, 1, StackSlotKind::StringBuffer);
    let data_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::Snprintf as u32,
            args: vec![
                MirValue::StackSlot(out_slot),
                MirValue::Const(32),
                MirValue::StackSlot(fmt_slot),
                MirValue::StackSlot(data_slot),
                MirValue::Const(16),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let types = HashMap::from([(dst, MirType::I64)]);
    let err = verify_mir(&func, &types).expect_err("expected stack fmt rejection");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper snprintf fmt expects pointer in [Map]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_snprintf_size_and_alignment() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let fmt = func.alloc_vreg();
    let out_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let data_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadGlobal {
            dst: fmt,
            symbol: "__nu_rodata_fmt".to_string(),
            ty: MirType::Array {
                elem: Box::new(MirType::U8),
                len: 16,
            },
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::Snprintf as u32,
            args: vec![
                MirValue::StackSlot(out_slot),
                MirValue::Const(-1),
                MirValue::VReg(fmt),
                MirValue::StackSlot(data_slot),
                MirValue::Const(10),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let types = HashMap::from([(dst, MirType::I64)]);
    let err = verify_mir(&func, &types).expect_err("expected snprintf size/alignment errors");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 165 arg1 must be >= 0")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_snprintf' requires arg4 to be a multiple of 8")),
        "unexpected errors: {:?}",
        err
    );
}

fn make_snprintf_verify_call(
    str_size: i64,
    data_len: i64,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let fmt = func.alloc_vreg();
    let out_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let data_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadGlobal {
            dst: fmt,
            symbol: "__nu_rodata_fmt".to_string(),
            ty: MirType::Array {
                elem: Box::new(MirType::U8),
                len: 16,
            },
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::Snprintf as u32,
            args: vec![
                MirValue::StackSlot(out_slot),
                MirValue::Const(str_size),
                MirValue::VReg(fmt),
                MirValue::StackSlot(data_slot),
                MirValue::Const(data_len),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    (func, HashMap::from([(dst, MirType::I64)]))
}

#[test]
fn test_verify_mir_helper_snprintf_rejects_size_out_of_range() {
    for (str_size, data_len, expected) in [
        (
            0x1_0000_0000,
            16,
            "snprintf helpers require arg1 str_size to be between 0 and u32::MAX",
        ),
        (
            32,
            104,
            "helper 'bpf_snprintf' requires arg4 data_len to be between 0 and MAX_BPRINTF_VARARGS * 8 (96 bytes)",
        ),
    ] {
        let (func, types) = make_snprintf_verify_call(str_size, data_len);
        let err = verify_mir(&func, &types).expect_err("expected snprintf size range error");
        assert!(
            err.iter().any(|e| e.message.contains(expected)),
            "expected {expected:?}, got {err:?}"
        );
    }
}

#[test]
fn test_verify_mir_helper_snprintf_btf_accepts_stack_buffers() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let out_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let btf_ptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SnprintfBtf as u32,
            args: vec![
                MirValue::StackSlot(out_slot),
                MirValue::Const(32),
                MirValue::StackSlot(btf_ptr_slot),
                MirValue::Const(16),
                MirValue::Const(15),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let types = HashMap::from([(dst, MirType::I64)]);
    verify_mir(&func, &types).expect("expected bpf_snprintf_btf stack buffers to verify");
}

#[test]
fn test_verify_mir_helper_snprintf_btf_rejects_zero_size() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let out_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let btf_ptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SnprintfBtf as u32,
            args: vec![
                MirValue::StackSlot(out_slot),
                MirValue::Const(0),
                MirValue::StackSlot(btf_ptr_slot),
                MirValue::Const(16),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let types = HashMap::from([(dst, MirType::I64)]);
    let err =
        verify_mir(&func, &types).expect_err("expected bpf_snprintf_btf positive str_size error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 149 arg1 must be > 0")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_snprintf_btf_rejects_size_over_u32() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let out_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let btf_ptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SnprintfBtf as u32,
            args: vec![
                MirValue::StackSlot(out_slot),
                MirValue::Const(0x1_0000_0000),
                MirValue::StackSlot(btf_ptr_slot),
                MirValue::Const(16),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let types = HashMap::from([(dst, MirType::I64)]);
    let err = verify_mir(&func, &types).expect_err("expected snprintf_btf size range error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper 'bpf_snprintf_btf' requires arg1 str_size to be between 1 and u32::MAX"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_snprintf_btf_size_and_shape() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let out_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let btf_ptr_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SnprintfBtf as u32,
            args: vec![
                MirValue::StackSlot(out_slot),
                MirValue::Const(-1),
                MirValue::StackSlot(btf_ptr_slot),
                MirValue::Const(8),
                MirValue::Const(16),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let types = HashMap::from([(dst, MirType::I64)]);
    let err = verify_mir(&func, &types).expect_err("expected snprintf_btf size/shape errors");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 149 arg1 must be >= 0")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper snprintf_btf ptr out of bounds")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_snprintf_btf' requires arg3 = 16")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_snprintf_btf' requires arg4 to contain only BTF_F_* bits")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_seq_output_helpers_accept_iter_program() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let seq = func.alloc_vreg();
    let fmt_slot = func.alloc_stack_slot(16, 1, StackSlotKind::StringBuffer);
    let data_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let write_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let btf_ptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let printf_dst = func.alloc_vreg();
    let printf_null_dst = func.alloc_vreg();
    let write_dst = func.alloc_vreg();
    let write_null_dst = func.alloc_vreg();
    let printf_btf_dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: seq,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: printf_dst,
            helper: BpfHelper::SeqPrintf as u32,
            args: vec![
                MirValue::VReg(seq),
                MirValue::StackSlot(fmt_slot),
                MirValue::Const(16),
                MirValue::StackSlot(data_slot),
                MirValue::Const(16),
            ],
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: printf_null_dst,
            helper: BpfHelper::SeqPrintf as u32,
            args: vec![
                MirValue::VReg(seq),
                MirValue::StackSlot(fmt_slot),
                MirValue::Const(16),
                MirValue::Const(0),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: write_dst,
            helper: BpfHelper::SeqWrite as u32,
            args: vec![
                MirValue::VReg(seq),
                MirValue::StackSlot(write_slot),
                MirValue::Const(8),
            ],
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: write_null_dst,
            helper: BpfHelper::SeqWrite as u32,
            args: vec![MirValue::VReg(seq), MirValue::Const(0), MirValue::Const(0)],
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: printf_btf_dst,
            helper: BpfHelper::SeqPrintfBtf as u32,
            args: vec![
                MirValue::VReg(seq),
                MirValue::StackSlot(btf_ptr_slot),
                MirValue::Const(16),
                MirValue::Const(15),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let types = HashMap::from([
        (
            seq,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Kernel,
            },
        ),
        (printf_dst, MirType::I64),
        (printf_null_dst, MirType::I64),
        (write_dst, MirType::I64),
        (write_null_dst, MirType::I64),
        (printf_btf_dst, MirType::I64),
    ]);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Iter, "task");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected seq output helpers to verify in iter programs");
}

#[test]
fn test_verify_mir_for_probe_context_seq_output_helpers_reject_non_iter_program() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let seq = func.alloc_vreg();
    let data_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: seq,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SeqWrite as u32,
            args: vec![
                MirValue::VReg(seq),
                MirValue::StackSlot(data_slot),
                MirValue::Const(8),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let types = HashMap::from([
        (
            seq,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Kernel,
            },
        ),
        (dst, MirType::I64),
    ]);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "do_sys_open");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected seq output helper program-surface error");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_seq_write' is only valid in iter programs")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_seq_output_helpers_reject_invalid_shapes() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let seq = func.alloc_vreg();
    let fmt_slot = func.alloc_stack_slot(16, 1, StackSlotKind::StringBuffer);
    let data_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let write_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let btf_ptr_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let printf_dst = func.alloc_vreg();
    let write_dst = func.alloc_vreg();
    let printf_btf_dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: seq,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: printf_dst,
            helper: BpfHelper::SeqPrintf as u32,
            args: vec![
                MirValue::VReg(seq),
                MirValue::StackSlot(fmt_slot),
                MirValue::Const(32),
                MirValue::StackSlot(data_slot),
                MirValue::Const(10),
            ],
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: write_dst,
            helper: BpfHelper::SeqWrite as u32,
            args: vec![
                MirValue::VReg(seq),
                MirValue::StackSlot(write_slot),
                MirValue::Const(-1),
            ],
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: printf_btf_dst,
            helper: BpfHelper::SeqPrintfBtf as u32,
            args: vec![
                MirValue::VReg(seq),
                MirValue::StackSlot(btf_ptr_slot),
                MirValue::Const(8),
                MirValue::Const(16),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let types = HashMap::from([
        (
            seq,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Kernel,
            },
        ),
        (printf_dst, MirType::I64),
        (write_dst, MirType::I64),
        (printf_btf_dst, MirType::I64),
    ]);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Iter, "task");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected seq output helper shape errors");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper seq_printf fmt out of bounds")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_seq_printf' requires arg4 to be a multiple of 8")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 127 arg2 must be >= 0")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_seq_printf_btf' requires arg2 = 16")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_seq_printf_btf' requires arg3 to contain only BTF_F_* bits")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_seq_output_helpers_reject_size_out_of_range() {
    let cases = [
        (
            BpfHelper::SeqPrintf,
            vec![
                MirValue::VReg(VReg(0)),
                MirValue::StackSlot(StackSlotId(0)),
                MirValue::Const(0),
                MirValue::StackSlot(StackSlotId(1)),
                MirValue::Const(16),
            ],
            16,
            16,
            "helper 126 arg2 must be > 0",
        ),
        (
            BpfHelper::SeqPrintf,
            vec![
                MirValue::VReg(VReg(0)),
                MirValue::StackSlot(StackSlotId(0)),
                MirValue::Const(0x1_0000_0000),
                MirValue::StackSlot(StackSlotId(1)),
                MirValue::Const(16),
            ],
            16,
            16,
            "helper 'bpf_seq_printf' requires arg2 fmt_size to be between 1 and u32::MAX",
        ),
        (
            BpfHelper::SeqPrintf,
            vec![
                MirValue::VReg(VReg(0)),
                MirValue::StackSlot(StackSlotId(0)),
                MirValue::Const(16),
                MirValue::StackSlot(StackSlotId(1)),
                MirValue::Const(104),
            ],
            16,
            16,
            "helper 'bpf_seq_printf' requires arg4 data_len to be between 0 and MAX_BPRINTF_VARARGS * 8 (96 bytes)",
        ),
        (
            BpfHelper::SeqWrite,
            vec![
                MirValue::VReg(VReg(0)),
                MirValue::StackSlot(StackSlotId(0)),
                MirValue::Const(0x1_0000_0000),
            ],
            16,
            0,
            "helper 'bpf_seq_write' requires arg2 len to be between 0 and u32::MAX",
        ),
    ];

    for (helper, args, first_slot_size, second_slot_size, expected) in cases {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;
        let seq = func.alloc_vreg();
        assert_eq!(seq, VReg(0));
        let first_slot = func.alloc_stack_slot(first_slot_size, 8, StackSlotKind::StringBuffer);
        assert_eq!(first_slot, StackSlotId(0));
        if second_slot_size > 0 {
            let second_slot =
                func.alloc_stack_slot(second_slot_size, 8, StackSlotKind::StringBuffer);
            assert_eq!(second_slot, StackSlotId(1));
        }
        let dst = func.alloc_vreg();

        func.block_mut(entry)
            .instructions
            .push(MirInst::LoadCtxField {
                dst: seq,
                field: CtxField::Context,
                slot: None,
            });
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: helper as u32,
                args,
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let types = HashMap::from([
            (
                seq,
                MirType::Ptr {
                    pointee: Box::new(MirType::U8),
                    address_space: AddressSpace::Kernel,
                },
            ),
            (dst, MirType::I64),
        ]);
        let probe_ctx = ProbeContext::new(EbpfProgramType::Iter, "task");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected seq helper size range error");
        assert!(
            err.iter().any(|e| e.message.contains(expected)),
            "expected {expected:?}, got {err:?}"
        );
    }
}

#[test]
fn test_verify_mir_for_probe_context_syscall_helpers_enforce_size_and_flags() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let attr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let name_slot = func.alloc_stack_slot(16, 1, StackSlotKind::StringBuffer);
    let res_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let sys_bpf = func.alloc_vreg();
    let btf_find = func.alloc_vreg();
    let kallsyms = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: sys_bpf,
            helper: BpfHelper::SysBpf as u32,
            args: vec![
                MirValue::Const(0),
                MirValue::StackSlot(attr_slot),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: btf_find,
            helper: BpfHelper::BtfFindByNameKind as u32,
            args: vec![
                MirValue::StackSlot(name_slot),
                MirValue::Const(0),
                MirValue::Const(1),
                MirValue::Const(1),
            ],
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: kallsyms,
            helper: BpfHelper::KallsymsLookupName as u32,
            args: vec![
                MirValue::StackSlot(name_slot),
                MirValue::Const(16),
                MirValue::Const(1),
                MirValue::StackSlot(res_slot),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let types = HashMap::from([
        (sys_bpf, MirType::I64),
        (btf_find, MirType::I64),
        (kallsyms, MirType::I64),
    ]);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Syscall, "demo");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected syscall helper shape errors");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 166 arg2 must be > 0"))
    );
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 167 arg1 must be > 0"))
    );
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_btf_find_by_name_kind' requires arg3 = 0")
    }));
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_kallsyms_lookup_name' requires arg2 = 0")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_syscall_helpers_reject_scalar_width_overflows() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let attr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let name_slot = func.alloc_stack_slot(16, 1, StackSlotKind::StringBuffer);
    let res_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let sys_bpf = func.alloc_vreg();
    let btf_find = func.alloc_vreg();
    let sys_close = func.alloc_vreg();
    let kallsyms = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: sys_bpf,
            helper: BpfHelper::SysBpf as u32,
            args: vec![
                MirValue::Const(0x8000_0000),
                MirValue::StackSlot(attr_slot),
                MirValue::Const(0x1_0000_0000),
            ],
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: btf_find,
            helper: BpfHelper::BtfFindByNameKind as u32,
            args: vec![
                MirValue::StackSlot(name_slot),
                MirValue::Const(0x8000_0000),
                MirValue::Const(0x1_0000_0000),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: sys_close,
            helper: BpfHelper::SysClose as u32,
            args: vec![MirValue::Const(0x1_0000_0000)],
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: kallsyms,
            helper: BpfHelper::KallsymsLookupName as u32,
            args: vec![
                MirValue::StackSlot(name_slot),
                MirValue::Const(0x8000_0000),
                MirValue::Const(0),
                MirValue::StackSlot(res_slot),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let types = HashMap::from([
        (sys_bpf, MirType::I64),
        (btf_find, MirType::I64),
        (sys_close, MirType::I64),
        (kallsyms, MirType::I64),
    ]);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Syscall, "demo");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected syscall helper scalar width errors");
    for expected in [
        "helper 'bpf_sys_bpf' requires arg0 cmd to be between 0 and i32::MAX",
        "helper 'bpf_sys_bpf' requires arg2 attr_size to be between 1 and u32::MAX",
        "helper 'bpf_btf_find_by_name_kind' requires arg1 name_sz to be between 1 and i32::MAX",
        "helper 'bpf_btf_find_by_name_kind' requires arg2 kind to be between 0 and u32::MAX",
        "helper 'bpf_sys_close' requires arg0 fd to be between 0 and u32::MAX",
        "helper 'bpf_kallsyms_lookup_name' requires arg1 name_sz to be between 0 and i32::MAX",
    ] {
        assert!(
            err.iter().any(|e| e.message.contains(expected)),
            "expected {expected:?}, got {err:?}"
        );
    }
}

#[test]
fn test_unknown_helper_rejects_more_than_five_args() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 9999,
            args: vec![
                MirValue::Const(0),
                MirValue::Const(1),
                MirValue::Const(2),
                MirValue::Const(3),
                MirValue::Const(4),
                MirValue::Const(5),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper-argument count rejection");
    assert!(
        err.iter()
            .any(|e| e.message.contains("at most 5 arguments")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_signal_helpers() {
    for helper in [BpfHelper::SendSignal, BpfHelper::SendSignalThread] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let dst = func.alloc_vreg();
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: helper as u32,
                args: vec![MirValue::Const(9)],
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(dst, MirType::I64);
        verify_mir(&func, &types).expect("expected signal helper to verify");
    }
}

#[test]
fn test_verify_mir_signal_helpers_reject_invalid_sig() {
    for helper in [BpfHelper::SendSignal, BpfHelper::SendSignalThread] {
        for sig in [-1_i64, 0x1_0000_0000] {
            let mut func = MirFunction::new();
            let entry = func.alloc_block();
            func.entry = entry;

            let dst = func.alloc_vreg();
            func.block_mut(entry)
                .instructions
                .push(MirInst::CallHelper {
                    dst,
                    helper: helper as u32,
                    args: vec![MirValue::Const(sig)],
                });
            func.block_mut(entry).terminator = MirInst::Return { val: None };

            let mut types = HashMap::new();
            types.insert(dst, MirType::I64);
            let err =
                verify_mir(&func, &types).expect_err("expected signal helper sig range error");
            assert!(
                err.iter().any(|e| e
                    .message
                    .contains("signal helpers require arg0 sig to be between 0 and u32::MAX")),
                "unexpected errors for {helper:?} sig {sig}: {:?}",
                err
            );
        }
    }
}

#[test]
fn test_verify_mir_rejects_more_than_five_params() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 6;
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let err = verify_mir(&func, &HashMap::new()).expect_err("expected param-count error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("at most 5 arguments")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_rejects_oversized_param_count_before_vreg_setup() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = (u32::MAX as usize).saturating_add(1);
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let err = verify_mir(&func, &HashMap::new())
        .expect_err("oversized param count should be rejected before vreg setup");
    assert!(
        err.iter()
            .any(|e| e.message.contains("at most 5 arguments")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_rejects_unrepresentable_stack_slot_size_before_bounds_setup() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let slot = func.alloc_stack_slot(i64::MAX as usize + 1, 8, StackSlotKind::Local);
    let ptr = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let err = verify_mir(&func, &HashMap::new())
        .expect_err("oversized stack slot should be rejected before bounds setup");
    assert!(
        err.iter()
            .any(|e| e.message.contains("representable MIR stack bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_rejects_undeclared_load_slot_reference() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::LoadSlot {
        dst,
        slot: StackSlotId(99),
        offset: 0,
        ty: MirType::I64,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let err = verify_mir(&func, &HashMap::new())
        .expect_err("undeclared stack slot should be rejected before verifier propagation");
    assert!(
        err.iter()
            .any(|e| e.message.contains("undeclared stack slot 99")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_rejects_out_of_range_vreg_def() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: VReg(99),
        src: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let err = verify_mir(&func, &HashMap::new())
        .expect_err("out-of-range virtual register should be rejected before verifier propagation");
    assert!(
        err.iter()
            .any(|e| e.message.contains("out-of-range virtual register 99")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_rejects_out_of_range_type_map_key() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let types = HashMap::from([(VReg(99), MirType::I64)]);
    let err = verify_mir(&func, &types).expect_err("out-of-range type-map key should be rejected");
    assert!(
        err.iter()
            .any(|e| e.message.contains("out-of-range virtual register 99")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_rejects_invalid_block_terminator() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let dst = func.alloc_vreg();
    func.block_mut(entry).terminator = MirInst::Copy {
        dst,
        src: MirValue::Const(0),
    };

    let err = verify_mir(&func, &HashMap::new())
        .expect_err("invalid terminator should be rejected before verifier propagation");
    assert!(
        err.iter().any(|e| e.message.contains("invalid terminator")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_rejects_out_of_range_param_metadata() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;
    func.param_non_null.insert(2);
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let err = verify_mir(&func, &HashMap::new())
        .expect_err("out-of-range parameter metadata should be rejected");
    assert!(
        err.iter()
            .any(|e| e.message.contains("out-of-range parameter 2")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_rejects_empty_map_ref_name() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::LoadMapFd {
        dst,
        map: MapRef {
            name: String::new(),
            kind: MapKind::Hash,
        },
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let err = verify_mir(&func, &HashMap::new()).expect_err("empty map name should be rejected");
    assert!(
        err.iter().any(|e| e.message.contains("empty name")),
        "unexpected errors: {:?}",
        err
    );
}
