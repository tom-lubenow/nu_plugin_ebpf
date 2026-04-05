use super::*;
use crate::compiler::mir::{CtxField, MirType, StructField};
use aya_obj::{EbpfSectionKind, Object as AyaObject};
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
fn test_tc_section_name() {
    let prog = EbpfProgram::from_bytecode(EbpfProgramType::Tc, "lo:ingress", "test", vec![]);
    assert_eq!(prog.section_name(), "classifier");
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
    assert_eq!(
        EbpfProgramType::from_spec_prefix("tc"),
        Some(EbpfProgramType::Tc)
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
fn test_elf_generation_with_readonly_globals_creates_rodata_data_map() {
    let prog = EbpfProgram::hello_world("sys_clone").with_readonly_globals(vec![ReadonlyGlobal {
        name: "config".to_string(),
        data: vec![1, 2, 3, 4],
    }]);

    let elf = prog.to_elf().expect("Failed to generate ELF");
    let obj = AyaObject::parse(&elf).expect("Aya should parse readonly globals");
    let map = obj.maps.get(".rodata").expect("expected .rodata data map");

    assert_eq!(map.section_kind(), EbpfSectionKind::Rodata);
    assert_eq!(map.data(), &[1, 2, 3, 4]);
}

#[test]
fn test_elf_generation_with_data_globals_creates_data_data_map() {
    let prog = EbpfProgram::hello_world("sys_clone").with_data_globals(vec![DataGlobal {
        name: "state".to_string(),
        data: vec![5, 6, 7, 8],
    }]);

    let elf = prog.to_elf().expect("Failed to generate ELF");
    let obj = AyaObject::parse(&elf).expect("Aya should parse data globals");
    let map = obj.maps.get(".data").expect("expected .data data map");

    assert_eq!(map.section_kind(), EbpfSectionKind::Data);
    assert_eq!(map.data(), &[5, 6, 7, 8]);
}

#[test]
fn test_elf_generation_with_bss_globals_creates_bss_data_map() {
    let prog = EbpfProgram::hello_world("sys_clone").with_bss_globals(vec![BssGlobal {
        name: "state".to_string(),
        size: 4,
    }]);

    let elf = prog.to_elf().expect("Failed to generate ELF");
    let obj = AyaObject::parse(&elf).expect("Aya should parse bss globals");
    let map = obj.maps.get(".bss").expect("expected .bss data map");

    assert_eq!(map.section_kind(), EbpfSectionKind::Bss);
    assert_eq!(map.data(), &[0, 0, 0, 0]);
}

#[test]
fn test_runtime_artifacts_reject_duplicate_map_and_global_names() {
    let mut prog = EbpfProgram::hello_world("sys_clone").with_readonly_globals(vec![
        ReadonlyGlobal {
            name: "events".to_string(),
            data: vec![1],
        },
    ]);
    prog.maps.push(EbpfMap {
        name: "events".to_string(),
        def: BpfMapDef::ring_buffer(4096),
    });

    let err = prog
        .validate_runtime_artifacts()
        .expect_err("duplicate map/global names should be rejected");

    assert!(
        err.to_string().contains("duplicate global or map name 'events'"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_runtime_artifacts_reject_zero_sized_bss_global() {
    let prog = EbpfProgram::hello_world("sys_clone").with_bss_globals(vec![BssGlobal {
        name: "state".to_string(),
        size: 0,
    }]);

    let err = prog
        .validate_runtime_artifacts()
        .expect_err("zero-sized bss globals should be rejected");

    assert!(
        err.to_string()
            .contains("bss global 'state' must have a non-zero size"),
        "unexpected error: {err}"
    );
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
fn test_probe_context_allows_xdp_md_scalar_fields_on_xdp() {
    let ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    assert!(ctx.ctx_field_access_error(&CtxField::PacketLen).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Data).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::DataEnd).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::IngressIfindex)
            .is_none()
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::RxQueueIndex)
            .is_none()
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::EgressIfindex)
            .is_none()
    );
}

#[test]
fn test_probe_context_allows_packet_fields_on_tc() {
    let ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    assert!(ctx.ctx_field_access_error(&CtxField::PacketLen).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Data).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::DataEnd).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::IngressIfindex)
            .is_none()
    );
}

#[test]
fn test_probe_context_rejects_xdp_only_packet_fields_on_tc() {
    let ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let rx_err = ctx
        .ctx_field_access_error(&CtxField::RxQueueIndex)
        .expect("expected tc rx_queue_index access error");
    assert!(rx_err.contains("ctx.rx_queue_index is not available on tc programs"));

    let egress_err = ctx
        .ctx_field_access_error(&CtxField::EgressIfindex)
        .expect("expected tc egress_ifindex access error");
    assert!(egress_err.contains("ctx.egress_ifindex is not available on tc programs"));
}

#[test]
fn test_probe_context_rejects_packet_fields_on_probe_programs() {
    let ctx = ProbeContext::new(EbpfProgramType::Kprobe, "do_sys_openat2");
    let err = ctx
        .ctx_field_access_error(&CtxField::PacketLen)
        .expect("expected non-packet packet_len access error");
    assert!(err.contains("ctx.packet_len is only available on packet-context programs"));
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
