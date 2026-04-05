use super::*;
use crate::compiler::mir::{CtxField, MirType, StructField};

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
}

#[test]
fn test_program_intrinsic_command_registry() {
    assert_eq!(
        ProgramIntrinsic::from_command_name("map-get"),
        Some(ProgramIntrinsic::MapGet)
    );
    assert!(ProgramIntrinsic::command_names().contains(&"emit"));
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
