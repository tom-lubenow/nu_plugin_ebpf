use super::*;
use crate::compiler::mir::{CtxField, MirType, StructField};
use std::collections::HashMap;

#[test]
fn test_hello_world_creation() {
    let prog = EbpfProgram::hello_world("sys_clone");
    assert_eq!(prog.target, "sys_clone");
    assert_eq!(prog.name, "hello_world");
    assert_eq!(prog.bytecode.len(), 16); // 2 instructions * 8 bytes
}

#[test]
fn test_section_name() {
    let prog = EbpfProgram::hello_world("sys_clone");
    assert_eq!(prog.section_name(), "kprobe/sys_clone");
}

#[test]
fn test_fentry_section_name() {
    let prog = EbpfProgram::from_bytecode(EbpfProgramType::Fentry, "ksys_read", "test", vec![]);
    assert_eq!(prog.section_name(), "fentry/ksys_read");
}

#[test]
fn test_xdp_section_name() {
    let prog = EbpfProgram::from_bytecode(EbpfProgramType::Xdp, "lo", "test", vec![]);
    assert_eq!(prog.section_name(), "xdp");
}

#[test]
fn test_program_type_metadata_for_fexit() {
    let info = EbpfProgramType::Fexit.info();
    assert_eq!(info.canonical_prefix, "fexit");
    assert_eq!(info.attach_kind, ProgramAttachKind::Fexit);
    assert_eq!(info.target_kind, ProgramTargetKind::KernelFunction);
    assert_eq!(
        info.kernel_target_validation,
        Some(KernelTargetValidationKind::FexitTrampoline)
    );
    assert_eq!(info.arg_access, ProgramValueAccess::Trampoline);
    assert_eq!(info.retval_access, ProgramValueAccess::Trampoline);
    assert!(!info.is_userspace);
}

#[test]
fn test_program_type_supports_raw_tracepoint_alias() {
    assert_eq!(
        EbpfProgramType::from_spec_prefix("raw_tp"),
        Some(EbpfProgramType::RawTracepoint)
    );
    assert_eq!(
        EbpfProgramType::from_spec_prefix("xdp"),
        Some(EbpfProgramType::Xdp)
    );
}

#[test]
fn test_program_intrinsic_command_registry() {
    assert_eq!(
        ProgramIntrinsic::from_command_name("map-get"),
        Some(ProgramIntrinsic::MapGet)
    );
    assert!(ProgramIntrinsic::command_names().contains(&"emit"));
    assert_eq!(
        ProgramIntrinsic::ReadKernelStr.required_capability(),
        ProgramCapability::ReadKernelString
    );
}

#[test]
fn test_program_type_supports_probe_intrinsics() {
    assert!(EbpfProgramType::Tracepoint.supports_intrinsic(ProgramIntrinsic::Emit));
    assert!(EbpfProgramType::Fentry.supports_intrinsic(ProgramIntrinsic::KfuncCall));
}

#[test]
fn test_program_type_supports_probe_capabilities() {
    assert!(EbpfProgramType::Tracepoint.supports_capability(ProgramCapability::Emit));
    assert!(EbpfProgramType::Fentry.supports_capability(ProgramCapability::KfuncCalls));
    assert!(EbpfProgramType::Kprobe.supports_capability(ProgramCapability::StackTraces));
    assert!(!EbpfProgramType::Xdp.supports_capability(ProgramCapability::ReadUserString));
}

#[test]
fn test_elf_generation() {
    let prog = EbpfProgram::hello_world("sys_clone");
    let elf = prog.to_elf().expect("Failed to generate ELF");

    // Should start with ELF magic number
    assert_eq!(&elf[0..4], b"\x7fELF");

    // Should be little-endian (byte 5 = 1)
    assert_eq!(elf[5], 1);

    // Should be BPF architecture
    // (This is in the e_machine field at offset 18-19)
}

#[test]
fn test_probe_context_rejects_arg_on_tracepoint() {
    let ctx = ProbeContext::new(EbpfProgramType::Tracepoint, "syscalls/sys_enter_openat");
    let err = ctx
        .ctx_field_access_error(&CtxField::Arg(0))
        .expect("expected tracepoint arg access error");
    assert!(err.contains("ctx.arg0 is only available on function probes with argument access"));
}

#[test]
fn test_probe_context_rejects_tracepoint_field_on_kprobe() {
    let ctx = ProbeContext::new(EbpfProgramType::Kprobe, "do_sys_openat2");
    let err = ctx
        .ctx_field_access_error(&CtxField::TracepointField("filename".to_string()))
        .expect("expected kprobe tracepoint-field access error");
    assert!(err.contains("ctx.filename is only available on typed tracepoints"));
}

#[test]
fn test_probe_context_rejects_tracepoint_field_on_raw_tracepoint() {
    let ctx = ProbeContext::new(EbpfProgramType::RawTracepoint, "sys_enter");
    let err = ctx
        .ctx_field_access_error(&CtxField::TracepointField("filename".to_string()))
        .expect("expected raw tracepoint field access error");
    assert!(err.contains("ctx.filename is only available on typed tracepoints"));
}

#[test]
fn test_probe_context_allows_arg_on_fentry() {
    let ctx = ProbeContext::new(EbpfProgramType::Fentry, "ksys_read");
    assert!(ctx.ctx_field_access_error(&CtxField::Arg(0)).is_none());
}

#[test]
fn test_probe_context_allows_retval_on_fexit() {
    let ctx = ProbeContext::new(EbpfProgramType::Fexit, "ksys_read");
    assert!(ctx.ctx_field_access_error(&CtxField::RetVal).is_none());
}

#[test]
fn test_probe_context_rejects_pid_on_xdp() {
    let ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let err = ctx
        .ctx_field_access_error(&CtxField::Pid)
        .expect("expected xdp pid access error");
    assert!(err.contains("ctx.pid is not available on xdp programs"));
}

#[test]
fn test_probe_context_allows_cpu_and_timestamp_on_xdp() {
    let ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    assert!(ctx.ctx_field_access_error(&CtxField::Cpu).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Timestamp).is_none());
}

#[test]
fn test_counter_key_schema_filters_synthetic_padding_fields() {
    let ty = MirType::Struct {
        name: Some("padded".to_string()),
        kernel_btf_type_id: None,
        fields: vec![
            StructField {
                name: "a".to_string(),
                ty: MirType::U8,
                offset: 0,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "__layout_pad0".to_string(),
                ty: MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: 7,
                },
                offset: 1,
                synthetic: true,
                bitfield: None,
            },
            StructField {
                name: "b".to_string(),
                ty: MirType::U64,
                offset: 8,
                synthetic: false,
                bitfield: None,
            },
        ],
    };

    let schema = CounterKeySchema::from_mir_type(&ty);
    let CounterKeySchema::Record {
        name,
        fields,
        total_size,
    } = schema
    else {
        panic!("expected record schema");
    };

    assert_eq!(name.as_deref(), Some("padded"));
    assert_eq!(total_size, 16);
    assert_eq!(fields.len(), 2);
    assert_eq!(fields[0].name, "a");
    assert_eq!(fields[0].offset, 0);
    assert_eq!(fields[1].name, "b");
    assert_eq!(fields[1].offset, 8);
}

#[test]
fn test_validate_runtime_artifacts_rejects_event_schema_without_ringbuf_map() {
    let program = EbpfProgram::with_maps(
        EbpfProgramType::Kprobe,
        "sys_clone",
        "test",
        vec![],
        0,
        vec![],
        vec![],
        vec![],
        Some(EventSchema {
            fields: vec![],
            total_size: 8,
        }),
        None,
        HashMap::new(),
    );

    let err = program
        .validate_runtime_artifacts()
        .expect_err("expected missing ring buffer validation error");

    assert!(
        matches!(err, CompileError::InvalidProgram(msg) if msg.contains("event schema requires runtime map 'events'"))
    );
}

#[test]
fn test_validate_runtime_artifacts_rejects_bytes_counter_schema_size_mismatch() {
    let program = EbpfProgram::with_maps(
        EbpfProgramType::Kprobe,
        "sys_clone",
        "test",
        vec![],
        0,
        vec![EbpfMap {
            name: BYTES_COUNTER_MAP_NAME.to_string(),
            def: BpfMapDef::hash(8, 8, 10240),
        }],
        vec![],
        vec![],
        None,
        Some(CounterKeySchema::Bytes { size: 16 }),
        HashMap::new(),
    );

    let err = program
        .validate_runtime_artifacts()
        .expect_err("expected bytes_counters schema mismatch");

    assert!(
        matches!(err, CompileError::InvalidProgram(msg) if msg.contains("schema size 16") && msg.contains("key size 8"))
    );
}

#[test]
fn test_validate_runtime_artifacts_rejects_unexpected_ringbuf_name() {
    let program = EbpfProgram::with_maps(
        EbpfProgramType::Kprobe,
        "sys_clone",
        "test",
        vec![],
        0,
        vec![EbpfMap {
            name: "custom_events".to_string(),
            def: BpfMapDef::ring_buffer(4096),
        }],
        vec![],
        vec![],
        None,
        None,
        HashMap::new(),
    );

    let err = program
        .validate_runtime_artifacts()
        .expect_err("expected reserved ring buffer naming error");

    assert!(
        matches!(err, CompileError::InvalidProgram(msg) if msg.contains("ring buffer runtime maps must be named 'events'"))
    );
}

#[test]
fn test_validate_runtime_artifacts_rejects_missing_emit_capability_for_events_map() {
    const LIMITED_CAPABILITIES: &[ProgramCapability] = &[ProgramCapability::Counters];

    let limited_program = ProgramTypeInfo {
        canonical_prefix: "limited",
        supported_capabilities: LIMITED_CAPABILITIES,
        ..*EbpfProgramType::Kprobe.info()
    };
    let program = EbpfProgram::with_maps(
        EbpfProgramType::Kprobe,
        "sys_clone",
        "test",
        vec![],
        0,
        vec![EbpfMap {
            name: RINGBUF_MAP_NAME.to_string(),
            def: BpfMapDef::ring_buffer(4096),
        }],
        vec![],
        vec![],
        None,
        None,
        HashMap::new(),
    );

    let err = program
        .validate_runtime_artifacts_for_info(&limited_program)
        .expect_err("expected emit capability error");

    assert!(
        matches!(err, CompileError::InvalidProgram(msg) if msg.contains("limited programs do not support event emission"))
    );
}
