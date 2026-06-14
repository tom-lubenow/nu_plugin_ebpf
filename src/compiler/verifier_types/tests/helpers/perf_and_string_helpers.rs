#[test]
fn test_verify_mir_perf_event_read_helpers() {
    for helper in [BpfHelper::PerfEventRead, BpfHelper::PerfEventReadValue] {
        let (func, types) = make_perf_event_read_verify_call(helper, 0, 24, 24);
        verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
            .expect("expected perf event read helper to verify");
    }
}

#[test]
fn test_verify_mir_perf_prog_read_value_helper() {
    let (func, types) = make_perf_prog_read_value_verify_call(24, 24);
    verify_mir_for_program(&func, &types, EbpfProgramType::PerfEvent.info())
        .expect("expected perf prog read value helper to verify");
}

#[test]
fn test_verify_mir_perf_prog_read_value_requires_exact_size() {
    let (func, types) = make_perf_prog_read_value_verify_call(8, 24);
    let err = verify_mir_for_program(&func, &types, EbpfProgramType::PerfEvent.info())
        .expect_err("expected perf_prog_read_value size error");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_perf_prog_read_value' requires arg2 = 24")
    }));
}

#[test]
fn test_verify_mir_perf_value_helpers_reject_zero_size() {
    let cases = [
        (
            make_perf_prog_read_value_verify_call(0, 24),
            EbpfProgramType::PerfEvent,
            "helper 56 arg2 must be > 0",
        ),
        (
            make_perf_event_read_verify_call(BpfHelper::PerfEventReadValue, 0, 0, 24),
            EbpfProgramType::Xdp,
            "helper 55 arg3 must be > 0",
        ),
    ];

    for ((func, types), program_type, expected) in cases {
        let err = verify_mir_for_program(&func, &types, program_type.info())
            .expect_err("expected perf value helper zero-size error");
        assert!(
            err.iter().any(|e| e.message.contains(expected)),
            "expected {expected:?}, got {err:?}"
        );
    }
}

#[test]
fn test_verify_mir_perf_prog_read_value_rejects_small_buffer() {
    let (func, types) = make_perf_prog_read_value_verify_call(24, 8);
    let err = verify_mir_for_program(&func, &types, EbpfProgramType::PerfEvent.info())
        .expect_err("expected perf_prog_read_value buffer bounds error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper perf_prog_read_value buf out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_perf_event_read_value_requires_exact_size() {
    let (func, types) = make_perf_event_read_verify_call(BpfHelper::PerfEventReadValue, 0, 8, 24);
    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
        .expect_err("expected perf_event_read_value size error");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_perf_event_read_value' requires arg3 = 24")
    }));
}

#[test]
fn test_verify_mir_perf_event_read_value_rejects_small_buffer() {
    let (func, types) = make_perf_event_read_verify_call(BpfHelper::PerfEventReadValue, 0, 24, 8);
    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
        .expect_err("expected perf_event_read_value buffer bounds error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper perf_event_read_value buf out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_perf_event_read_helpers_reject_invalid_flags() {
    for helper in [BpfHelper::PerfEventRead, BpfHelper::PerfEventReadValue] {
        let (func, types) = make_perf_event_read_verify_call(helper, 0x1_0000_0000, 24, 24);
        let err = verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
            .expect_err("expected perf_event_read flags error");
        assert!(
            err.iter().any(|e| e
                .message
                .contains("perf event read helpers require arg1 flags")),
            "unexpected errors for {:?}: {:?}",
            helper,
            err
        );
    }
}

fn make_get_ns_current_pid_tgid_verify_call(
    size: i64,
    buf_size: usize,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst = func.alloc_vreg();
    let nsdata_slot = func.alloc_stack_slot(buf_size, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::GetNsCurrentPidTgid as u32,
            args: vec![
                MirValue::Const(1),
                MirValue::Const(2),
                MirValue::StackSlot(nsdata_slot),
                MirValue::Const(size),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    (func, types)
}

#[test]
fn test_verify_mir_get_ns_current_pid_tgid_helper() {
    let (func, types) = make_get_ns_current_pid_tgid_verify_call(8, 8);
    verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
        .expect("expected bpf_get_ns_current_pid_tgid helper to verify");
}

#[test]
fn test_verify_mir_get_ns_current_pid_tgid_rejects_zero_size() {
    let (func, types) = make_get_ns_current_pid_tgid_verify_call(0, 8);
    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
        .expect_err("expected bpf_get_ns_current_pid_tgid zero-size error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 120 arg3 must be > 0")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_get_ns_current_pid_tgid_requires_exact_size() {
    let (func, types) = make_get_ns_current_pid_tgid_verify_call(4, 8);
    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
        .expect_err("expected bpf_get_ns_current_pid_tgid size error");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_get_ns_current_pid_tgid' requires arg3 = 8")
    }));
}

#[test]
fn test_verify_mir_get_ns_current_pid_tgid_rejects_small_buffer() {
    let (func, types) = make_get_ns_current_pid_tgid_verify_call(8, 4);
    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
        .expect_err("expected bpf_get_ns_current_pid_tgid bounds error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper get_ns_current_pid_tgid nsdata out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

fn make_strtox_verify_call(
    helper: BpfHelper,
    buf_len: i64,
    flags: i64,
    buf_size: usize,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(buf_size, 8, StackSlotKind::StringBuffer);
    let res_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: helper as u32,
            args: vec![
                MirValue::StackSlot(buf_slot),
                MirValue::Const(buf_len),
                MirValue::Const(flags),
                MirValue::StackSlot(res_slot),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    (func, types)
}

fn make_strncmp_verify_call(
    s1_len: i64,
    s1_size: usize,
    s2_on_stack: bool,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst = func.alloc_vreg();
    let s1_slot = func.alloc_stack_slot(s1_size, 8, StackSlotKind::StringBuffer);
    let s2 = if s2_on_stack {
        let s2_slot = func.alloc_stack_slot(8, 1, StackSlotKind::StringBuffer);
        MirValue::StackSlot(s2_slot)
    } else {
        let s2 = func.alloc_vreg();
        func.block_mut(entry)
            .instructions
            .push(MirInst::LoadGlobal {
                dst: s2,
                symbol: "__nu_rodata_needle".to_string(),
                ty: MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: 8,
                },
            });
        MirValue::VReg(s2)
    };
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::Strncmp as u32,
            args: vec![MirValue::StackSlot(s1_slot), MirValue::Const(s1_len), s2],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    (func, types)
}

#[test]
fn test_verify_mir_strtox_helpers() {
    for helper in [BpfHelper::Strtol, BpfHelper::Strtoul] {
        let (func, types) = make_strtox_verify_call(helper, 8, 16, 8);
        verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
            .expect("expected string conversion helper to verify");
    }
}

#[test]
fn test_verify_mir_strtox_helpers_reject_zero_buf_len() {
    for helper in [BpfHelper::Strtol, BpfHelper::Strtoul] {
        let (func, types) = make_strtox_verify_call(helper, 0, 0, 8);
        let err = verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
            .expect_err("expected string conversion positive-size error");
        assert!(
            err.iter().any(|e| e.message.contains("arg1 must be > 0")),
            "unexpected errors for {helper:?}: {:?}",
            err
        );
    }
}

#[test]
fn test_verify_mir_strncmp_helper_accepts_rodata_s2() {
    let (func, types) = make_strncmp_verify_call(8, 8, false);
    verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
        .expect("expected strncmp helper to verify");
}

#[test]
fn test_verify_mir_strncmp_helper_rejects_small_s1_buffer() {
    let (func, types) = make_strncmp_verify_call(16, 8, false);
    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
        .expect_err("expected strncmp buffer bounds error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper strncmp s1 out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_strncmp_helper_rejects_zero_s1_size() {
    let (func, types) = make_strncmp_verify_call(0, 8, false);
    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
        .expect_err("expected strncmp positive-size error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 182 arg1 must be > 0")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_strncmp_helper_rejects_s1_size_above_u32_max() {
    let (func, types) = make_strncmp_verify_call(0x1_0000_0000, 8, false);
    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
        .expect_err("expected strncmp s1 size range error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_strncmp' requires arg1 s1_sz to be between 1 and u32::MAX")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_strncmp_helper_rejects_stack_s2() {
    let (func, types) = make_strncmp_verify_call(8, 8, true);
    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
        .expect_err("expected strncmp read-only string error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper strncmp s2 expects pointer in [Map]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_strtox_helper_rejects_small_buffer() {
    let (func, types) = make_strtox_verify_call(BpfHelper::Strtol, 16, 0, 8);
    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
        .expect_err("expected string conversion buffer bounds error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper strtox buf out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_strtox_helper_rejects_invalid_flags() {
    for (helper, flags) in [(BpfHelper::Strtol, 2), (BpfHelper::Strtoul, 32)] {
        let (func, types) = make_strtox_verify_call(helper, 8, flags, 8);
        let err = verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
            .expect_err("expected string conversion flags error");
        assert!(
            err.iter().any(|e| e
                .message
                .contains("requires arg2 flags to be one of 0, 8, 10, or 16")),
            "unexpected errors: {:?}",
            err
        );
    }
}

