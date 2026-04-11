use super::*;
use crate::compiler::mir::{CtxField, MirType, StructField};
use crate::compiler::mir_to_ebpf::compile_mir_to_ebpf;
use crate::kernel_btf::KernelBtf;
use aya_obj::{
    EbpfSectionKind, Object as AyaObject,
    btf::{Btf, BtfKind},
};
use object::{Endianness, Object as _, ObjectSection as _};
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
    assert_eq!(
        prog.section_name()
            .expect("kprobe section name should build"),
        "kprobe/sys_clone"
    );
}

#[test]
fn test_fentry_section_name() {
    let prog = EbpfProgram::from_bytecode(EbpfProgramType::Fentry, "ksys_read", "test", vec![]);
    assert_eq!(
        prog.section_name()
            .expect("fentry section name should build"),
        "fentry/ksys_read"
    );
}

#[test]
fn test_tp_btf_section_name() {
    let prog = EbpfProgram::from_bytecode(EbpfProgramType::TpBtf, "sys_enter", "test", vec![]);
    assert_eq!(
        prog.section_name()
            .expect("tp_btf section name should build"),
        "tp_btf/sys_enter"
    );
}

#[test]
fn test_xdp_section_name() {
    let prog = EbpfProgram::from_bytecode(EbpfProgramType::Xdp, "lo", "test", vec![]);
    assert_eq!(
        prog.section_name().expect("xdp section name should build"),
        "xdp"
    );
}

#[test]
fn test_lirc_mode2_section_name() {
    let prog = EbpfProgram::from_bytecode(EbpfProgramType::LircMode2, "/dev/lirc0", "test", vec![]);
    assert_eq!(
        prog.section_name()
            .expect("lirc_mode2 section name should build"),
        "lirc_mode2"
    );
}

#[test]
fn test_socket_filter_section_name() {
    let prog = EbpfProgram::from_bytecode(
        EbpfProgramType::SocketFilter,
        "udp4:127.0.0.1:31337",
        "test",
        vec![],
    );
    assert_eq!(
        prog.section_name()
            .expect("socket_filter section name should build"),
        "socket"
    );
}

#[test]
fn test_tc_section_name() {
    let prog = EbpfProgram::from_bytecode(EbpfProgramType::Tc, "lo:ingress", "test", vec![]);
    assert_eq!(
        prog.section_name().expect("tc section name should build"),
        "classifier"
    );
}

#[test]
fn test_sk_lookup_section_name() {
    let prog = EbpfProgram::from_bytecode(
        EbpfProgramType::SkLookup,
        "/proc/self/ns/net",
        "test",
        vec![],
    );
    assert_eq!(
        prog.section_name()
            .expect("sk_lookup section name should build"),
        "sk_lookup"
    );
}

#[test]
fn test_sk_msg_section_name() {
    let prog = EbpfProgram::from_bytecode(
        EbpfProgramType::SkMsg,
        "/sys/fs/bpf/demo_sockmap",
        "test",
        vec![],
    );
    assert_eq!(
        prog.section_name()
            .expect("sk_msg section name should build"),
        "sk_msg"
    );
}

#[test]
fn test_struct_ops_section_name() {
    let prog = EbpfProgram::from_bytecode(
        EbpfProgramType::StructOps,
        "demo_select_cpu",
        "test",
        vec![],
    );
    assert_eq!(
        prog.section_name()
            .expect("struct_ops section name should build"),
        "struct_ops/demo_select_cpu"
    );
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
fn test_program_type_metadata_for_tp_btf() {
    let info = EbpfProgramType::TpBtf.info();
    assert_eq!(info.canonical_prefix, "tp_btf");
    assert_eq!(info.attach_kind, ProgramAttachKind::TpBtf);
    assert_eq!(info.target_kind, ProgramTargetKind::BtfTracepoint);
    assert_eq!(info.arg_access, ProgramValueAccess::Trampoline);
    assert_eq!(info.retval_access, ProgramValueAccess::None);
    assert!(info.supports_task_ctx_fields);
    assert!(info.supports_cpu_ctx_field);
    assert!(info.supports_timestamp_ctx_field);
}

#[test]
fn test_program_type_metadata_for_raw_tracepoint() {
    let info = EbpfProgramType::RawTracepoint.info();
    assert_eq!(info.canonical_prefix, "raw_tracepoint");
    assert_eq!(info.attach_kind, ProgramAttachKind::RawTracepoint);
    assert_eq!(info.target_kind, ProgramTargetKind::RawTracepoint);
    assert_eq!(info.arg_access, ProgramValueAccess::RawTracepoint);
    assert_eq!(info.retval_access, ProgramValueAccess::None);
    assert!(info.supports_task_ctx_fields);
    assert!(info.supports_cpu_ctx_field);
    assert!(info.supports_timestamp_ctx_field);
}

#[test]
fn test_program_type_metadata_for_sk_lookup() {
    let info = EbpfProgramType::SkLookup.info();
    assert_eq!(info.canonical_prefix, "sk_lookup");
    assert_eq!(info.attach_kind, ProgramAttachKind::SkLookup);
    assert_eq!(info.target_kind, ProgramTargetKind::NetworkNamespacePath);
    assert_eq!(info.arg_access, ProgramValueAccess::None);
    assert_eq!(info.retval_access, ProgramValueAccess::None);
    assert!(info.supports_cpu_ctx_field);
    assert!(info.supports_timestamp_ctx_field);
    assert!(info.supports_ingress_ifindex_ctx_field);
}

#[test]
fn test_program_type_metadata_for_lirc_mode2() {
    let info = EbpfProgramType::LircMode2.info();
    assert_eq!(info.canonical_prefix, "lirc_mode2");
    assert_eq!(info.attach_kind, ProgramAttachKind::LircMode2);
    assert_eq!(info.target_kind, ProgramTargetKind::LircDevicePath);
    assert_eq!(info.arg_access, ProgramValueAccess::None);
    assert_eq!(info.retval_access, ProgramValueAccess::None);
    assert!(info.supports_cpu_ctx_field);
    assert!(info.supports_timestamp_ctx_field);
}

#[test]
fn test_program_type_metadata_for_sk_msg() {
    let info = EbpfProgramType::SkMsg.info();
    assert_eq!(info.canonical_prefix, "sk_msg");
    assert_eq!(info.attach_kind, ProgramAttachKind::SkMsg);
    assert_eq!(info.target_kind, ProgramTargetKind::PinnedSockMapPath);
    assert_eq!(info.arg_access, ProgramValueAccess::None);
    assert_eq!(info.retval_access, ProgramValueAccess::None);
    assert!(info.supports_cpu_ctx_field);
    assert!(info.supports_timestamp_ctx_field);
    assert!(info.supports_packet_len_ctx_field);
    assert!(info.supports_packet_data_ctx_fields);
}

#[test]
fn test_sk_skb_section_name() {
    assert_eq!(
        EbpfProgramType::SkSkb.section_prefix(),
        "sk_skb/stream_verdict"
    );
}

#[test]
fn test_sk_skb_parser_section_name() {
    assert_eq!(
        EbpfProgramType::SkSkbParser.section_prefix(),
        "sk_skb/stream_parser"
    );
}

#[test]
fn test_program_type_metadata_for_sk_skb() {
    let info = EbpfProgramType::SkSkb.info();
    assert_eq!(info.canonical_prefix, "sk_skb");
    assert_eq!(info.attach_kind, ProgramAttachKind::SkSkb);
    assert_eq!(info.target_kind, ProgramTargetKind::PinnedSockMapPath);
    assert_eq!(info.arg_access, ProgramValueAccess::None);
    assert_eq!(info.retval_access, ProgramValueAccess::None);
    assert!(info.supports_cpu_ctx_field);
    assert!(info.supports_timestamp_ctx_field);
    assert!(info.supports_packet_len_ctx_field);
    assert!(info.supports_packet_data_ctx_fields);
    assert!(info.supports_ingress_ifindex_ctx_field);
}

#[test]
fn test_program_type_metadata_for_sk_skb_parser() {
    let info = EbpfProgramType::SkSkbParser.info();
    assert_eq!(info.canonical_prefix, "sk_skb_parser");
    assert_eq!(info.attach_kind, ProgramAttachKind::SkSkbParser);
    assert_eq!(info.target_kind, ProgramTargetKind::PinnedSockMapPath);
    assert_eq!(info.arg_access, ProgramValueAccess::None);
    assert_eq!(info.retval_access, ProgramValueAccess::None);
    assert!(info.supports_cpu_ctx_field);
    assert!(info.supports_timestamp_ctx_field);
    assert!(info.supports_packet_len_ctx_field);
    assert!(info.supports_packet_data_ctx_fields);
    assert!(info.supports_ingress_ifindex_ctx_field);
}

#[test]
fn test_program_type_metadata_for_socket_filter() {
    let info = EbpfProgramType::SocketFilter.info();
    assert_eq!(info.canonical_prefix, "socket_filter");
    assert_eq!(info.attach_kind, ProgramAttachKind::SocketFilter);
    assert_eq!(info.target_kind, ProgramTargetKind::SocketFilterTarget);
    assert_eq!(info.arg_access, ProgramValueAccess::None);
    assert_eq!(info.retval_access, ProgramValueAccess::None);
    assert!(info.supports_cpu_ctx_field);
    assert!(info.supports_timestamp_ctx_field);
    assert!(info.supports_packet_len_ctx_field);
    assert!(info.supports_packet_data_ctx_fields);
    assert!(info.supports_ingress_ifindex_ctx_field);
}

#[test]
fn test_program_type_metadata_for_cgroup_device() {
    let info = EbpfProgramType::CgroupDevice.info();
    assert_eq!(info.canonical_prefix, "cgroup_device");
    assert_eq!(info.attach_kind, ProgramAttachKind::CgroupDevice);
    assert_eq!(info.target_kind, ProgramTargetKind::CgroupPath);
    assert_eq!(info.arg_access, ProgramValueAccess::None);
    assert_eq!(info.retval_access, ProgramValueAccess::None);
    assert!(info.supports_cpu_ctx_field);
    assert!(info.supports_timestamp_ctx_field);
}

#[test]
fn test_program_type_metadata_for_sock_ops() {
    let info = EbpfProgramType::SockOps.info();
    assert_eq!(info.canonical_prefix, "sock_ops");
    assert_eq!(info.attach_kind, ProgramAttachKind::SockOps);
    assert_eq!(info.target_kind, ProgramTargetKind::CgroupPath);
    assert_eq!(info.arg_access, ProgramValueAccess::None);
    assert_eq!(info.retval_access, ProgramValueAccess::None);
    assert!(info.supports_cpu_ctx_field);
    assert!(info.supports_timestamp_ctx_field);
    assert!(!info.supports_ingress_ifindex_ctx_field);
}

#[test]
fn test_program_type_metadata_for_struct_ops() {
    let info = EbpfProgramType::StructOps.info();
    assert_eq!(info.canonical_prefix, "struct_ops");
    assert_eq!(info.attach_kind, ProgramAttachKind::StructOps);
    assert_eq!(info.target_kind, ProgramTargetKind::StructOpsCallback);
    assert_eq!(info.arg_access, ProgramValueAccess::Trampoline);
    assert_eq!(info.retval_access, ProgramValueAccess::None);
    assert!(EbpfProgramType::StructOps.supports_capability(ProgramCapability::Globals));
    assert!(EbpfProgramType::StructOps.supports_capability(ProgramCapability::KfuncCalls));
    assert!(!EbpfProgramType::StructOps.supports_capability(ProgramCapability::Emit));
}

#[test]
fn test_sched_ext_object_can_emit_without_callbacks() {
    if KernelBtf::get()
        .kernel_named_type_field_projection(
            "sched_ext_ops",
            &[crate::kernel_btf::TrampolineFieldSelector::Field(
                "name".to_string(),
            )],
        )
        .is_err()
    {
        return;
    }

    let object = StructOpsObjectSpec::zeroed_from_kernel_btf("nu_sched", "sched_ext_ops")
        .expect("expected zeroed sched_ext_ops spec")
        .with_value_field("name", StructOpsValueField::String("nu_demo".to_string()))
        .expect("expected name initializer")
        .to_object()
        .expect("expected sched_ext_ops object without callbacks");

    let elf = object.to_elf().expect("sched_ext_ops object should emit");
    let parsed = object::File::parse(&*elf).expect("emitted object should parse");
    assert!(
        parsed.section_by_name(".struct_ops").is_some(),
        "expected .struct_ops section even without callback closures"
    );
}

#[test]
fn test_probe_context_for_struct_ops_callback_preserves_value_type_name() {
    let ctx = ProbeContext::new_struct_ops_callback("sched_ext_ops", "select_cpu");

    assert_eq!(ctx.probe_type, EbpfProgramType::StructOps);
    assert_eq!(ctx.target, "select_cpu");
    assert_eq!(
        ctx.struct_ops_value_type_name.as_deref(),
        Some("sched_ext_ops")
    );
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
        EbpfProgramType::from_spec_prefix("sock_filter"),
        Some(EbpfProgramType::SocketFilter)
    );
    assert_eq!(
        EbpfProgramType::from_spec_prefix("tc"),
        Some(EbpfProgramType::Tc)
    );
    assert_eq!(
        EbpfProgramType::from_spec_prefix("struct_ops"),
        Some(EbpfProgramType::StructOps)
    );
    assert_eq!(
        EbpfProgramType::from_spec_prefix("sock_ops"),
        Some(EbpfProgramType::SockOps)
    );
    assert_eq!(
        EbpfProgramType::from_spec_prefix("cgroup_device"),
        Some(EbpfProgramType::CgroupDevice)
    );
}

#[test]
fn test_program_intrinsic_command_registry() {
    assert_eq!(
        ProgramIntrinsic::from_command_name("helper-call"),
        Some(ProgramIntrinsic::HelperCall)
    );
    assert_eq!(
        ProgramIntrinsic::from_command_name("map-get"),
        Some(ProgramIntrinsic::MapGet)
    );
    assert_eq!(
        ProgramIntrinsic::from_command_name("map-push"),
        Some(ProgramIntrinsic::MapPush)
    );
    assert_eq!(
        ProgramIntrinsic::from_command_name("global-set"),
        Some(ProgramIntrinsic::GlobalSet)
    );
    assert!(ProgramIntrinsic::command_names().contains(&"emit"));
    assert_eq!(
        ProgramIntrinsic::ReadKernelStr.required_capability(),
        ProgramCapability::ReadKernelString
    );
    assert_eq!(
        ProgramIntrinsic::HelperCall.required_capability(),
        ProgramCapability::HelperCalls
    );
    assert_eq!(
        ProgramIntrinsic::GlobalGet.required_capability(),
        ProgramCapability::Globals
    );
    assert_eq!(
        ProgramIntrinsic::MapPush.required_capability(),
        ProgramCapability::GenericMaps
    );
}

#[test]
fn test_program_type_supports_probe_intrinsics() {
    assert!(EbpfProgramType::Tracepoint.supports_intrinsic(ProgramIntrinsic::Emit));
    assert!(EbpfProgramType::Fentry.supports_intrinsic(ProgramIntrinsic::HelperCall));
    assert!(EbpfProgramType::Fentry.supports_intrinsic(ProgramIntrinsic::KfuncCall));
}

#[test]
fn test_program_type_supports_probe_capabilities() {
    assert!(EbpfProgramType::Tracepoint.supports_capability(ProgramCapability::Emit));
    assert!(EbpfProgramType::Fentry.supports_capability(ProgramCapability::HelperCalls));
    assert!(EbpfProgramType::Fentry.supports_capability(ProgramCapability::KfuncCalls));
    assert!(EbpfProgramType::Kprobe.supports_capability(ProgramCapability::StackTraces));
    assert!(EbpfProgramType::Xdp.supports_capability(ProgramCapability::HelperCalls));
    assert!(EbpfProgramType::Xdp.supports_capability(ProgramCapability::Globals));
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
fn test_struct_ops_object_emits_btf_without_generic_maps() {
    let object = EbpfObject::struct_ops("demo", "fake_ops", vec![0; 32])
        .with_callback_slot("select_cpu", 8)
        .bind_callback(
            "select_cpu",
            EbpfProgram::hello_world("sys_clone"),
            "demo_select_cpu",
        )
        .expect("callback slot should bind")
        .build();

    let elf = object.to_elf().expect("struct_ops object should emit");
    let parsed = object::File::parse(&*elf).expect("emitted object should parse");
    let btf_section = parsed
        .section_by_name(".BTF")
        .expect("expected .BTF section");
    let btf_data = btf_section.data().expect(".BTF section should be readable");
    let btf = Btf::parse(btf_data, Endianness::Little).expect("expected parsable BTF");

    assert!(
        btf.id_by_type_name_kind(".struct_ops", BtfKind::DataSec)
            .is_ok()
    );
    assert!(
        btf.id_by_type_name_kind("fake_ops", BtfKind::Struct)
            .is_ok()
    );
    assert!(btf.id_by_type_name_kind("demo", BtfKind::Var).is_ok());
    assert!(
        btf_data
            .windows(b"select_cpu\0".len())
            .any(|window| window == b"select_cpu\0"),
        "expected callback member name in emitted BTF string table"
    );
}

#[test]
fn test_struct_ops_object_btf_includes_value_members_from_kernel_layout() {
    use crate::kernel_btf::KernelBtf;

    if KernelBtf::get()
        .kernel_named_type_field_projection(
            "tcp_congestion_ops",
            &[crate::kernel_btf::TrampolineFieldSelector::Field(
                "name".to_string(),
            )],
        )
        .is_err()
    {
        return;
    }

    let object = StructOpsObjectSpec::zeroed_from_kernel_btf("nu_tcp", "tcp_congestion_ops")
        .expect("expected zeroed tcp_congestion_ops spec")
        .with_value_field("name", StructOpsValueField::String("nu_demo".to_string()))
        .expect("expected name initializer")
        .with_callback(
            "ssthresh",
            "nu_tcp_ssthresh",
            EbpfProgram::hello_world("sys_clone"),
        )
        .with_callback(
            "undo_cwnd",
            "nu_tcp_undo_cwnd",
            EbpfProgram::hello_world("sys_execve"),
        )
        .with_callback(
            "cong_avoid",
            "nu_tcp_cong_avoid",
            EbpfProgram::hello_world("sys_enter"),
        )
        .to_object()
        .expect("expected tcp_congestion_ops object");

    let elf = object
        .to_elf()
        .expect("tcp_congestion_ops object should emit");
    let parsed = object::File::parse(&*elf).expect("emitted object should parse");
    let btf_section = parsed
        .section_by_name(".BTF")
        .expect("expected .BTF section");
    let btf_data = btf_section.data().expect(".BTF section should be readable");

    assert!(
        btf_data
            .windows(b"name\0".len())
            .any(|window| window == b"name\0"),
        "expected value member name in emitted BTF string table"
    );
    assert!(
        btf_data
            .windows(b"ssthresh\0".len())
            .any(|window| window == b"ssthresh\0"),
        "expected callback member name in emitted BTF string table"
    );
}

#[test]
fn test_multi_program_object_generation_parses_in_aya() {
    use crate::compiler::instruction::{EbpfInsn, EbpfReg};

    let mut builder = crate::compiler::instruction::EbpfBuilder::new();
    builder
        .push(EbpfInsn::mov64_imm(EbpfReg::R0, 0))
        .push(EbpfInsn::exit());
    let program_one = EbpfProgram::new(EbpfProgramType::Kprobe, "sys_clone", "prog_one", builder);

    let mut builder = crate::compiler::instruction::EbpfBuilder::new();
    builder
        .push(EbpfInsn::mov64_imm(EbpfReg::R0, 0))
        .push(EbpfInsn::exit());
    let program_two = EbpfProgram::new(
        EbpfProgramType::RawTracepoint,
        "sys_enter",
        "prog_two",
        builder,
    );

    let object = EbpfObject {
        kind: EbpfObjectKind::Program,
        license: "GPL".to_string(),
        maps: vec![],
        readonly_globals: vec![],
        data_globals: vec![],
        bss_globals: vec![],
        extra_data_symbols: vec![],
        programs: vec![
            program_one.into_program_section(),
            program_two.into_program_section(),
        ],
    };

    let elf = object.to_elf().expect("multi-program object should build");
    let obj = AyaObject::parse(&elf).expect("Aya should parse multi-program object");

    assert_eq!(obj.programs.len(), 2);
    assert!(obj.programs.contains_key("prog_one"));
    assert!(obj.programs.contains_key("prog_two"));
}

#[test]
fn test_primary_program_rejects_multi_program_object() {
    let object = EbpfObject {
        kind: EbpfObjectKind::Program,
        license: "GPL".to_string(),
        maps: vec![],
        readonly_globals: vec![],
        data_globals: vec![],
        bss_globals: vec![],
        extra_data_symbols: vec![],
        programs: vec![
            EbpfProgram::hello_world("sys_clone").into_program_section(),
            EbpfProgram::hello_world("sys_execve").into_program_section(),
        ],
    };

    let err = object
        .primary_program()
        .expect_err("multi-program object should not expose a single primary program");
    assert!(
        err.to_string()
            .contains("runtime attach currently supports exactly one")
    );
}

#[test]
fn test_primary_program_rejects_struct_ops_object_kind() {
    let object = EbpfObject::struct_ops("demo", "sched_ext_ops", vec![0; 8])
        .add_callback(EbpfProgram::hello_world("sys_clone"), "demo_select_cpu")
        .build();

    let err = object
        .primary_program()
        .expect_err("struct_ops object should not expose an attachable primary program");
    assert!(err.to_string().contains("requires a program object"));
}

#[test]
fn test_struct_ops_object_rejects_non_struct_ops_section_name() {
    let object = EbpfObject::struct_ops("demo", "sched_ext_ops", vec![0; 8])
        .add_callback_section(EbpfProgram::hello_world("sys_clone").into_program_section())
        .build();

    let err = object
        .validate_runtime_artifacts()
        .expect_err("struct_ops object should require struct_ops section names");
    assert!(
        err.to_string()
            .contains("must use a struct_ops* section name")
    );
}

#[test]
fn test_struct_ops_object_emits_callback_section_override() {
    use object::{Object as _, ObjectSection as _};

    let object = EbpfObject::struct_ops("demo", "sched_ext_ops", vec![0; 8])
        .add_callback_section(
            EbpfProgram::hello_world("sys_clone")
                .into_program_section()
                .with_section_name_override("struct_ops/demo_select_cpu"),
        )
        .build();

    let elf = object
        .to_elf()
        .expect("struct_ops object with explicit callback section should build");
    let file = object::File::parse(&*elf).expect("object crate should parse generated ELF");
    let section_names: Vec<String> = file
        .sections()
        .filter_map(|section| section.name().ok().map(str::to_string))
        .collect();

    assert!(section_names.contains(&"struct_ops/demo_select_cpu".to_string()));
}

#[test]
fn test_struct_ops_object_emits_typed_callback_section() {
    use object::{Object as _, ObjectSection as _};

    let object = EbpfObject::struct_ops("demo", "sched_ext_ops", vec![0; 8])
        .add_callback(
            EbpfProgram::from_bytecode(
                EbpfProgramType::StructOps,
                "demo_select_cpu",
                "demo_select_cpu",
                vec![],
            ),
            "demo_select_cpu",
        )
        .build();

    let elf = object
        .to_elf()
        .expect("struct_ops object with typed callback section should build");
    let file = object::File::parse(&*elf).expect("object crate should parse generated ELF");
    let section_names: Vec<String> = file
        .sections()
        .filter_map(|section| section.name().ok().map(str::to_string))
        .collect();

    assert!(section_names.contains(&"struct_ops/demo_select_cpu".to_string()));
}

#[test]
fn test_struct_ops_object_emits_struct_ops_value_with_callback_relocation() {
    use object::{Object as _, ObjectSection as _, ObjectSymbol as _, RelocationTarget};

    let object = StructOpsObjectSpec::new("demo", "sched_ext_ops", vec![0; 8])
        .with_callback_slot("demo_select_cpu", 0)
        .with_callback(
            "demo_select_cpu",
            "demo_select_cpu",
            EbpfProgram::hello_world("sys_clone"),
        )
        .to_object()
        .expect("struct_ops object spec should build");

    let elf = object
        .to_elf()
        .expect("struct_ops object with value relocation should build");
    let file = object::File::parse(&*elf).expect("object crate should parse generated ELF");
    let section = file
        .section_by_name(".struct_ops")
        .expect("expected .struct_ops section");

    let mut relocations = section.relocations();
    let (offset, relocation) = relocations
        .next()
        .expect("expected one relocation in .struct_ops");
    assert_eq!(offset, 0);
    match relocation.target() {
        RelocationTarget::Symbol(symbol_idx) => {
            let symbol = file
                .symbol_by_index(symbol_idx)
                .expect("relocation symbol should exist");
            assert_eq!(
                symbol.name().expect("relocation symbol should have a name"),
                "demo_select_cpu"
            );
        }
        other => panic!("unexpected relocation target: {other:?}"),
    }
    assert!(
        relocations.next().is_none(),
        "expected exactly one relocation in .struct_ops"
    );
}

#[test]
fn test_struct_ops_object_spec_rejects_duplicate_slot_definition() {
    let err = StructOpsObjectSpec::new("demo", "sched_ext_ops", vec![0; 8])
        .with_callback_slot("demo_select_cpu", 0)
        .with_callback_slot("demo_select_cpu", 8)
        .to_object()
        .expect_err("duplicate callback slot definitions should fail");

    assert!(
        err.to_string()
            .contains("duplicate struct_ops callback slot 'demo_select_cpu'"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_struct_ops_object_spec_rejects_duplicate_slot_binding() {
    let err = StructOpsObjectSpec::new("demo", "sched_ext_ops", vec![0; 8])
        .with_callback_slot("demo_select_cpu", 0)
        .with_callback(
            "demo_select_cpu",
            "demo_select_cpu",
            EbpfProgram::hello_world("sys_clone"),
        )
        .with_callback(
            "demo_select_cpu",
            "demo_select_cpu_alt",
            EbpfProgram::hello_world("sys_execve"),
        )
        .to_object()
        .expect_err("duplicate callback bindings should fail");

    assert!(
        err.to_string()
            .contains("duplicate struct_ops callback binding for slot 'demo_select_cpu'"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_struct_ops_object_spec_preserves_shared_artifacts() {
    use object::{Object as _, ObjectSection as _};

    let object = StructOpsObjectSpec::new("demo", "sched_ext_ops", vec![0; 8])
        .with_maps(vec![EbpfMap {
            name: "state".to_string(),
            def: BpfMapDef::hash(8, 8, 16),
        }])
        .with_readonly_globals(vec![ReadonlyGlobal {
            name: "cfg".to_string(),
            data: vec![1, 2, 3, 4],
        }])
        .with_data_globals(vec![DataGlobal {
            name: "counter".to_string(),
            data: vec![0; 8],
        }])
        .with_bss_globals(vec![BssGlobal {
            name: "scratch".to_string(),
            size: 16,
        }])
        .with_callback_slot("demo_select_cpu", 0)
        .with_callback(
            "demo_select_cpu",
            "demo_select_cpu",
            EbpfProgram::hello_world("sys_clone"),
        )
        .to_object()
        .expect("struct_ops object with shared artifacts should build");

    let elf = object
        .to_elf()
        .expect("struct_ops object with shared artifacts should emit");
    let file = object::File::parse(&*elf).expect("object crate should parse generated ELF");
    let section_names: Vec<String> = file
        .sections()
        .filter_map(|section| section.name().ok().map(str::to_string))
        .collect();

    assert!(section_names.contains(&".maps".to_string()));
    assert!(section_names.contains(&".rodata".to_string()));
    assert!(section_names.contains(&".data".to_string()));
    assert!(section_names.contains(&".bss".to_string()));
}

#[test]
fn test_struct_ops_object_spec_resolves_callback_slot_from_kernel_btf() {
    use crate::kernel_btf::{KernelBtf, TrampolineFieldSelector};
    use object::{Object as _, ObjectSection as _, ObjectSymbol as _, RelocationTarget};

    let projection = KernelBtf::get()
        .kernel_named_type_field_projection(
            "file",
            &[TrampolineFieldSelector::Field("f_inode".to_string())],
        )
        .expect("expected file.f_inode projection for struct_ops callback slot");
    let offset = projection.path[0].offset_bytes;

    let object = StructOpsObjectSpec::new("demo", "file", vec![0; offset + 8])
        .with_callback(
            "f_inode",
            "demo_select_cpu",
            EbpfProgram::hello_world("sys_clone"),
        )
        .to_object()
        .expect("struct_ops object spec should resolve callback slot from kernel BTF");

    let elf = object
        .to_elf()
        .expect("struct_ops object with inferred callback slot should emit");
    let file = object::File::parse(&*elf).expect("object crate should parse generated ELF");
    let section = file
        .section_by_name(".struct_ops")
        .expect("expected .struct_ops section");

    let mut relocations = section.relocations();
    let (reloc_offset, relocation) = relocations
        .next()
        .expect("expected one relocation in inferred .struct_ops");
    assert_eq!(reloc_offset as usize, offset);
    match relocation.target() {
        RelocationTarget::Symbol(symbol_idx) => {
            let symbol = file
                .symbol_by_index(symbol_idx)
                .expect("relocation symbol should exist");
            assert_eq!(
                symbol.name().expect("relocation symbol should have a name"),
                "demo_select_cpu"
            );
        }
        other => panic!("unexpected relocation target: {other:?}"),
    }
    assert!(
        relocations.next().is_none(),
        "expected exactly one relocation in inferred .struct_ops"
    );
}

#[test]
fn test_struct_ops_object_spec_zeroed_from_kernel_btf() {
    use crate::kernel_btf::KernelBtf;

    let expected_size = KernelBtf::get()
        .kernel_named_type_size_bytes("file")
        .expect("expected named file type size");
    let object = StructOpsObjectSpec::zeroed_from_kernel_btf("demo", "file")
        .expect("expected zeroed struct_ops spec from kernel BTF")
        .with_callback(
            "f_inode",
            "demo_select_cpu",
            EbpfProgram::hello_world("sys_clone"),
        )
        .to_object()
        .expect("expected zeroed struct_ops object from kernel BTF");

    assert_eq!(object.extra_data_symbols.len(), 1);
    assert_eq!(object.extra_data_symbols[0].data.len(), expected_size);
}

#[test]
fn test_struct_ops_object_spec_initializes_scalar_value_field() {
    use crate::kernel_btf::{KernelBtf, TrampolineFieldSelector};

    let projection = KernelBtf::get()
        .kernel_named_type_field_projection(
            "task_struct",
            &[TrampolineFieldSelector::Field("pid".to_string())],
        )
        .expect("expected task_struct.pid projection");
    let offset = projection.path[0].offset_bytes;
    let size = projection.type_info.size();

    let object = StructOpsObjectSpec::zeroed_from_kernel_btf("demo", "task_struct")
        .expect("expected zeroed task_struct object spec")
        .with_value_field("pid", StructOpsValueField::Int(42))
        .expect("expected scalar value field initializer to succeed")
        .to_object()
        .expect("expected struct_ops object with scalar value field");

    let bytes = &object.extra_data_symbols[0].data[offset..offset + size];
    let value = match size {
        1 => i8::from_le_bytes([bytes[0]]) as i64,
        2 => i16::from_le_bytes([bytes[0], bytes[1]]) as i64,
        4 => i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as i64,
        8 => i64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]),
        other => panic!("unexpected integer width {}", other),
    };

    assert_eq!(value, 42);
}

#[test]
fn test_struct_ops_object_spec_initializes_string_value_field() {
    use crate::kernel_btf::{KernelBtf, TrampolineFieldSelector, TypeInfo};

    let projection = KernelBtf::get()
        .kernel_named_type_field_projection(
            "task_struct",
            &[TrampolineFieldSelector::Field("comm".to_string())],
        )
        .expect("expected task_struct.comm projection");
    let offset = projection.path[0].offset_bytes;
    let TypeInfo::Array { len, .. } = projection.type_info else {
        panic!("expected task_struct.comm to be a fixed array");
    };

    let object = StructOpsObjectSpec::zeroed_from_kernel_btf("demo", "task_struct")
        .expect("expected zeroed task_struct object spec")
        .with_value_field("comm", StructOpsValueField::String("nu".to_string()))
        .expect("expected string value field initializer to succeed")
        .to_object()
        .expect("expected struct_ops object with string value field");

    let bytes = &object.extra_data_symbols[0].data[offset..offset + len];
    assert_eq!(&bytes[..2], b"nu");
    assert!(bytes[2..].iter().all(|byte| *byte == 0));
}

#[test]
fn test_struct_ops_object_spec_initializes_integer_list_value_field() {
    use crate::kernel_btf::{KernelBtf, TrampolineFieldSelector, TypeInfo};

    let projection = KernelBtf::get()
        .kernel_named_type_field_projection(
            "task_struct",
            &[TrampolineFieldSelector::Field("comm".to_string())],
        )
        .expect("expected task_struct.comm projection");
    let offset = projection.path[0].offset_bytes;
    let TypeInfo::Array { len, .. } = projection.type_info else {
        panic!("expected task_struct.comm to be a fixed array");
    };

    let object = StructOpsObjectSpec::zeroed_from_kernel_btf("demo", "task_struct")
        .expect("expected zeroed task_struct object spec")
        .with_value_field("comm", StructOpsValueField::IntList(vec![110, 117]))
        .expect("expected integer-list value field initializer to succeed")
        .to_object()
        .expect("expected struct_ops object with integer-list value field");

    let bytes = &object.extra_data_symbols[0].data[offset..offset + len];
    assert_eq!(&bytes[..2], b"nu");
    assert!(bytes[2..].iter().all(|byte| *byte == 0));
}

#[test]
fn test_struct_ops_object_spec_rejects_oversized_string_value_field() {
    use crate::kernel_btf::{KernelBtf, TrampolineFieldSelector, TypeInfo};

    let projection = KernelBtf::get()
        .kernel_named_type_field_projection(
            "task_struct",
            &[TrampolineFieldSelector::Field("comm".to_string())],
        )
        .expect("expected task_struct.comm projection");
    let TypeInfo::Array { len, .. } = projection.type_info else {
        panic!("expected task_struct.comm to be a fixed array");
    };

    let err = StructOpsObjectSpec::zeroed_from_kernel_btf("demo", "task_struct")
        .expect("expected zeroed task_struct object spec")
        .with_value_field("comm", StructOpsValueField::String("x".repeat(len)))
        .expect_err("oversized string value field should fail");

    assert!(
        err.to_string().contains("is too long"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_struct_ops_object_spec_merges_compiled_callback_artifacts() {
    let callback_program = EbpfProgram::hello_world("sys_clone")
        .with_readonly_globals(vec![ReadonlyGlobal {
            name: "cfg".to_string(),
            data: vec![1, 2, 3, 4],
        }])
        .with_data_globals(vec![DataGlobal {
            name: "state".to_string(),
            data: vec![0; 8],
        }])
        .with_bss_globals(vec![BssGlobal {
            name: "scratch".to_string(),
            size: 16,
        }]);

    let object = StructOpsObjectSpec::zeroed_from_kernel_btf("demo", "file")
        .expect("expected zeroed struct_ops spec from kernel BTF")
        .to_object_with_compiled_callbacks(vec![CompiledStructOpsCallback {
            slot_name: "f_inode".to_string(),
            callback_name: "demo_select_cpu".to_string(),
            program: callback_program,
        }])
        .expect("compiled callback artifacts should merge into struct_ops object");

    assert_eq!(object.readonly_globals.len(), 1);
    assert_eq!(object.readonly_globals[0].name, "cfg");
    assert_eq!(object.data_globals.len(), 1);
    assert_eq!(object.data_globals[0].name, "state");
    assert_eq!(object.bss_globals.len(), 1);
    assert_eq!(object.bss_globals[0].name, "scratch");
    assert_eq!(object.programs.len(), 1);
}

#[test]
fn test_struct_ops_object_spec_accepts_callbacks_from_mir_compile_results() {
    use crate::compiler::mir::{
        BasicBlock, BlockId, MirFunction, MirInst, MirProgram, MirValue, VReg,
    };

    let mut func = MirFunction::new();
    let mut entry_block = BasicBlock::new(BlockId(0));
    entry_block.instructions.push(MirInst::Copy {
        dst: VReg(0),
        src: MirValue::Const(0),
    });
    entry_block.terminator = MirInst::Return {
        val: Some(MirValue::VReg(VReg(0))),
    };
    func.blocks.push(entry_block);
    func.vreg_count = 1;

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let callback = compile_mir_to_ebpf(&program, None)
        .expect("expected MIR callback compile result")
        .into_struct_ops_callback("f_inode", "demo_select_cpu", HashMap::new(), HashMap::new());

    let object = StructOpsObjectSpec::zeroed_from_kernel_btf("demo", "file")
        .expect("expected zeroed struct_ops spec from kernel BTF")
        .to_object_with_compiled_callbacks(vec![callback])
        .expect("expected struct_ops object from compiled callback");

    assert_eq!(object.programs.len(), 1);
    assert_eq!(
        object.programs[0]
            .section_name()
            .expect("struct_ops callback section name should build"),
        "struct_ops/demo_select_cpu"
    );
}

#[test]
fn test_struct_ops_object_spec_rejects_incompatible_compiled_callback_map() {
    let mut callback_one = EbpfProgram::hello_world("sys_clone");
    callback_one.maps.push(EbpfMap {
        name: "shared".to_string(),
        def: BpfMapDef::hash(8, 8, 16),
    });
    let mut callback_two = EbpfProgram::hello_world("sys_execve");
    callback_two.maps.push(EbpfMap {
        name: "shared".to_string(),
        def: BpfMapDef::hash(4, 8, 16),
    });

    let err = StructOpsObjectSpec::zeroed_from_kernel_btf("demo", "file")
        .expect("expected zeroed struct_ops spec from kernel BTF")
        .to_object_with_compiled_callbacks(vec![
            CompiledStructOpsCallback {
                slot_name: "f_inode".to_string(),
                callback_name: "demo_select_cpu".to_string(),
                program: callback_one,
            },
            CompiledStructOpsCallback {
                slot_name: "f_mode".to_string(),
                callback_name: "demo_enqueue".to_string(),
                program: callback_two,
            },
        ])
        .expect_err("incompatible compiled callback map definitions should fail");

    assert!(
        err.to_string()
            .contains("uses incompatible map definition for 'shared'"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_struct_ops_object_spec_rejects_non_pointer_btf_callback_member() {
    let err = StructOpsObjectSpec::zeroed_from_kernel_btf("demo", "file")
        .expect("expected zeroed struct_ops spec from kernel BTF")
        .with_callback(
            "f_mode",
            "demo_select_cpu",
            EbpfProgram::hello_world("sys_clone"),
        )
        .to_object()
        .expect_err("scalar file.f_mode should not be accepted as a callback slot");

    assert!(
        err.to_string().contains("resolved to a non-pointer member"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_struct_ops_builder_rejects_unknown_callback_slot() {
    let err = EbpfObject::struct_ops("demo", "sched_ext_ops", vec![0; 8])
        .bind_callback(
            "missing_slot",
            EbpfProgram::hello_world("sys_clone"),
            "demo_select_cpu",
        )
        .expect_err("unknown callback slot should fail");

    assert!(
        err.to_string()
            .contains("unknown struct_ops callback slot 'missing_slot'"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_struct_ops_object_rejects_mismatched_value_symbol_name() {
    let mut object = EbpfObject::struct_ops("demo", "sched_ext_ops", vec![0; 8])
        .add_callback(
            EbpfProgram::from_bytecode(
                EbpfProgramType::StructOps,
                "demo_select_cpu",
                "demo_select_cpu",
                vec![],
            ),
            "demo_select_cpu",
        )
        .build();
    object.extra_data_symbols[0].name = "other".to_string();

    let err = object
        .validate_runtime_artifacts()
        .expect_err("struct_ops value symbol name should match the object name");
    assert!(
        err.to_string()
            .contains("must use a .struct_ops value symbol with the same name"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_struct_ops_object_rejects_multiple_value_symbols() {
    let mut object = EbpfObject::struct_ops("demo", "sched_ext_ops", vec![0; 8])
        .add_callback(
            EbpfProgram::from_bytecode(
                EbpfProgramType::StructOps,
                "demo_select_cpu",
                "demo_select_cpu",
                vec![],
            ),
            "demo_select_cpu",
        )
        .build();
    object.extra_data_symbols.push(ObjectDataSymbol {
        section_name: ".struct_ops".to_string(),
        name: "demo_extra".to_string(),
        data: vec![0; 8],
        align: 8,
        writable: true,
        relocations: vec![],
    });

    let err = object
        .validate_runtime_artifacts()
        .expect_err("struct_ops object should currently allow exactly one value symbol");
    assert!(
        err.to_string()
            .contains("requires exactly one .struct_ops value symbol"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_into_struct_ops_callback_normalizes_section_metadata() {
    let section = EbpfProgram::hello_world("sys_clone").into_struct_ops_callback(
        "file",
        "demo_select_cpu",
        "demo_select_cpu",
    );

    assert_eq!(section.prog_type, EbpfProgramType::StructOps);
    assert_eq!(section.target, "demo_select_cpu");
    assert_eq!(section.name, "demo_select_cpu");
    assert_eq!(
        section
            .section_name()
            .expect("struct_ops callback section name should build"),
        "struct_ops/demo_select_cpu"
    );
}

#[test]
fn test_into_struct_ops_callback_uses_sleepable_sched_ext_section() {
    let section = EbpfProgram::hello_world("sys_clone").into_struct_ops_callback(
        "sched_ext_ops",
        "init",
        "demo_init",
    );

    assert_eq!(section.prog_type, EbpfProgramType::StructOps);
    assert_eq!(section.target, "demo_init");
    assert_eq!(section.name, "demo_init");
    assert_eq!(
        section
            .section_name()
            .expect("sleepable sched_ext callback section name should build"),
        "struct_ops.s/demo_init"
    );
}

#[test]
fn test_struct_ops_object_uses_sleepable_sched_ext_callback_section() {
    use crate::compiler::mir::{
        BasicBlock, BlockId, MirFunction, MirInst, MirProgram, MirValue, VReg,
    };

    if KernelBtf::get()
        .kernel_named_type_size_bytes("sched_ext_ops")
        .is_err()
    {
        return;
    }

    let object = StructOpsObjectSpec::zeroed_from_kernel_btf("demo", "sched_ext_ops")
        .expect("expected zeroed sched_ext_ops spec from kernel BTF")
        .to_object_with_compiled_callbacks(vec![
            compile_mir_to_ebpf(
                &{
                    let mut func = MirFunction::new();
                    let mut entry_block = BasicBlock::new(BlockId(0));
                    entry_block.instructions.push(MirInst::Copy {
                        dst: VReg(0),
                        src: MirValue::Const(0),
                    });
                    entry_block.terminator = MirInst::Return {
                        val: Some(MirValue::VReg(VReg(0))),
                    };
                    func.blocks.push(entry_block);
                    func.vreg_count = 1;
                    MirProgram {
                        main: func,
                        subfunctions: vec![],
                    }
                },
                None,
            )
            .expect("expected MIR sched_ext callback compile result")
            .into_struct_ops_callback(
                "init",
                "demo_init",
                HashMap::new(),
                HashMap::new(),
            ),
        ])
        .expect("expected struct_ops object from compiled sched_ext callback");

    assert_eq!(object.programs.len(), 1);
    assert_eq!(
        object.programs[0]
            .section_name()
            .expect("sleepable sched_ext callback section name should build"),
        "struct_ops.s/demo_init"
    );
}

#[test]
fn test_program_object_rejects_extra_data_symbols() {
    let object = EbpfObject {
        kind: EbpfObjectKind::Program,
        license: "GPL".to_string(),
        maps: vec![],
        readonly_globals: vec![],
        data_globals: vec![],
        bss_globals: vec![],
        extra_data_symbols: vec![ObjectDataSymbol {
            section_name: ".custom".to_string(),
            name: "blob".to_string(),
            data: vec![1, 2, 3, 4],
            align: 4,
            writable: false,
            relocations: vec![],
        }],
        programs: vec![EbpfProgram::hello_world("sys_clone").into_program_section()],
    };

    let err = object
        .validate_runtime_artifacts()
        .expect_err("ordinary program object should reject extra data symbols");
    assert!(
        err.to_string()
            .contains("ordinary program objects do not yet support extra data symbols"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_runtime_artifacts_reject_duplicate_map_and_global_names() {
    let mut prog =
        EbpfProgram::hello_world("sys_clone").with_readonly_globals(vec![ReadonlyGlobal {
            name: "events".to_string(),
            data: vec![1],
        }]);
    prog.maps.push(EbpfMap {
        name: "events".to_string(),
        def: BpfMapDef::ring_buffer(4096),
    });

    let err = prog
        .validate_runtime_artifacts()
        .expect_err("duplicate map/global names should be rejected");

    assert!(
        err.to_string()
            .contains("duplicate global or map name 'events'"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_runtime_artifacts_reject_program_name_conflicting_with_map_or_global() {
    let object = EbpfObject {
        kind: EbpfObjectKind::Program,
        license: "GPL".to_string(),
        maps: vec![EbpfMap {
            name: "probe_main".to_string(),
            def: BpfMapDef::hash(8, 8, 16),
        }],
        readonly_globals: vec![],
        data_globals: vec![],
        bss_globals: vec![],
        extra_data_symbols: vec![],
        programs: vec![
            EbpfProgram::hello_world("sys_clone")
                .into_program_section()
                .with_section_name_override("kprobe/sys_clone"),
        ]
        .into_iter()
        .map(|mut program| {
            program.name = "probe_main".to_string();
            program
        })
        .collect(),
    };

    let err = object
        .validate_runtime_artifacts()
        .expect_err("program symbol name should not collide with map/global symbols");

    assert!(
        err.to_string()
            .contains("conflicts with a map, global, or data symbol"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_to_elf_rejects_missing_relocation_symbol() {
    use crate::compiler::instruction::{EbpfBuilder, EbpfInsn, EbpfReg};

    let mut builder = EbpfBuilder::new();
    let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
    builder.push(insn1);
    builder.push(insn2);
    builder.push(EbpfInsn::mov64_imm(EbpfReg::R0, 0));
    builder.push(EbpfInsn::exit());
    let bytecode = builder.build();

    let program = EbpfProgram::with_maps(
        EbpfProgramType::Kprobe,
        "sys_clone",
        "missing_reloc",
        bytecode.clone(),
        bytecode.len(),
        vec![],
        vec![SymbolRelocation {
            insn_offset: 0,
            symbol_name: "__missing_symbol".to_string(),
        }],
        vec![],
        None,
        None,
        HashMap::new(),
        HashMap::new(),
    );

    let err = program
        .to_elf()
        .expect_err("missing relocation symbol should fail ELF generation");

    assert!(
        err.to_string().contains("references missing ELF symbol"),
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
    assert!(err.contains("ctx.arg0 is only available on contexts with argument access"));
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
fn test_probe_context_allows_arg_on_raw_tracepoint() {
    let ctx = ProbeContext::new(EbpfProgramType::RawTracepoint, "sys_enter");
    assert!(ctx.ctx_field_access_error(&CtxField::Arg(0)).is_none());
}

#[test]
fn test_probe_context_allows_arg_on_fentry() {
    let ctx = ProbeContext::new(EbpfProgramType::Fentry, "ksys_read");
    assert!(ctx.ctx_field_access_error(&CtxField::Arg(0)).is_none());
}

#[test]
fn test_probe_context_allows_arg_on_tp_btf() {
    let ctx = ProbeContext::new(EbpfProgramType::TpBtf, "sys_enter");
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
    assert!(ctx.ctx_field_access_error(&CtxField::PktType).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::QueueMapping)
            .is_none()
    );
    assert!(ctx.ctx_field_access_error(&CtxField::EthProtocol).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::VlanPresent).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::VlanTci).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::VlanProto).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::SkbCb).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::TcClassid).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::NapiId).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::WireLen).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::GsoSegs).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::GsoSize).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Hwtstamp).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Data).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::DataEnd).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Ifindex).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::TcIndex).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::SkbHash).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::SockMark).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::SockPriority)
            .is_none()
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::IngressIfindex)
            .is_none()
    );
}

#[test]
fn test_probe_context_allows_packet_fields_on_cgroup_skb() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:egress");
    assert!(ctx.ctx_field_access_error(&CtxField::PacketLen).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::PktType).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::QueueMapping)
            .is_none()
    );
    assert!(ctx.ctx_field_access_error(&CtxField::EthProtocol).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::VlanPresent).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::VlanTci).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::VlanProto).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::SkbCb).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::TcClassid).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::NapiId).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::WireLen).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::GsoSegs).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::GsoSize).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Hwtstamp).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Data).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::DataEnd).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Ifindex).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::TcIndex).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::SkbHash).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::SockMark).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::SockPriority)
            .is_none()
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::IngressIfindex)
            .is_none()
    );
}

#[test]
fn test_probe_context_allows_sock_fields_on_cgroup_sock() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_create");
    assert!(ctx.ctx_field_access_error(&CtxField::Socket).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Family).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::SockType).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Protocol).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::BoundDevIf).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::SockMark).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::SockPriority)
            .is_none()
    );
}

#[test]
fn test_probe_context_allows_sock_addr_fields_on_cgroup_sock_addr() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect4");
    assert!(ctx.ctx_field_access_error(&CtxField::UserFamily).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::UserIp4).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::UserPort).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Family).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::SockType).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Protocol).is_none());
}

#[test]
fn test_probe_context_allows_socket_field_on_cgroup_sockopt() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");
    assert!(ctx.ctx_field_access_error(&CtxField::Socket).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::SockoptLevel)
            .is_none()
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::SockoptOptname)
            .is_none()
    );
}

#[test]
fn test_probe_context_allows_socket_filter_packet_fields() {
    let ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");
    assert!(ctx.ctx_field_access_error(&CtxField::PacketLen).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::PktType).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::QueueMapping)
            .is_none()
    );
    assert!(ctx.ctx_field_access_error(&CtxField::EthProtocol).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::VlanPresent).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::VlanTci).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::VlanProto).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::SkbCb).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::TcClassid).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::NapiId).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::WireLen).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::GsoSegs).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::GsoSize).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Hwtstamp).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Data).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::DataEnd).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Ifindex).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::TcIndex).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::SkbHash).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::SockMark).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::SockPriority)
            .is_none()
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::IngressIfindex)
            .is_none()
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::SocketCookie)
            .is_none()
    );
}

#[test]
fn test_probe_context_allows_sk_lookup_fields() {
    let ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");
    assert!(ctx.ctx_field_access_error(&CtxField::Socket).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Family).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Protocol).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::RemoteIp4).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::RemoteIp6).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::RemotePort).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::LocalIp4).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::LocalIp6).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::LocalPort).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::IngressIfindex)
            .is_none()
    );
}

#[test]
fn test_probe_context_allows_socket_cookie_on_sock_ops() {
    let ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
    assert!(
        ctx.ctx_field_access_error(&CtxField::SocketCookie)
            .is_none()
    );
}

#[test]
fn test_probe_context_allows_socket_uid_on_tc() {
    let ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    assert!(ctx.ctx_field_access_error(&CtxField::SocketUid).is_none());
}

#[test]
fn test_probe_context_allows_packet_data_fields_on_sock_ops() {
    let ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
    assert!(ctx.ctx_field_access_error(&CtxField::PacketLen).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Data).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::DataEnd).is_none());
}

#[test]
fn test_probe_context_allows_extra_metric_fields_on_sock_ops() {
    let ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
    assert!(
        ctx.ctx_field_access_error(&CtxField::SockOpsMssCache)
            .is_none()
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::SockOpsSkTxhash)
            .is_none()
    );
}

#[test]
fn test_probe_context_allows_netns_cookie_on_sk_msg() {
    let ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");
    assert!(ctx.ctx_field_access_error(&CtxField::NetnsCookie).is_none());
}

#[test]
fn test_probe_context_allows_cgroup_id_on_xdp() {
    let ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    assert!(ctx.ctx_field_access_error(&CtxField::CgroupId).is_none());
}

#[test]
fn test_probe_context_rejects_netns_cookie_on_sk_lookup() {
    let ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");
    let err = ctx
        .ctx_field_access_error(&CtxField::NetnsCookie)
        .expect("expected netns_cookie field access error");
    assert!(err.contains(
        "ctx.netns_cookie is only available on socket_filter, tc, cgroup_skb, cgroup_sock, cgroup_sockopt, cgroup_sock_addr, sk_msg, and sock_ops programs"
    ));
}

#[test]
fn test_probe_context_rejects_socket_uid_on_sk_lookup() {
    let ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");
    let err = ctx
        .ctx_field_access_error(&CtxField::SocketUid)
        .expect("expected socket_uid field access error");
    assert!(err.contains(
        "ctx.socket_uid is only available on socket_filter, tc, cgroup_skb, and sk_skb programs"
    ));
}

#[test]
fn test_probe_context_allows_sk_msg_fields() {
    let ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");
    assert!(ctx.ctx_field_access_error(&CtxField::Socket).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::PacketLen).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Data).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::DataEnd).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Family).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::RemoteIp4).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::RemoteIp6).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::RemotePort).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::LocalIp4).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::LocalIp6).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::LocalPort).is_none());
}

#[test]
fn test_probe_context_allows_sk_skb_fields() {
    let ctx = ProbeContext::new(EbpfProgramType::SkSkb, "/sys/fs/bpf/demo_sockmap");
    assert!(ctx.ctx_field_access_error(&CtxField::PacketLen).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::PktType).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::QueueMapping)
            .is_none()
    );
    assert!(ctx.ctx_field_access_error(&CtxField::EthProtocol).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::VlanPresent).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::VlanTci).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::VlanProto).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::SkbCb).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::TcClassid).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::NapiId).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::WireLen).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::GsoSegs).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::GsoSize).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Hwtstamp).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Data).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::DataEnd).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Ifindex).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::TcIndex).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::SkbHash).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::SockMark).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::SockPriority)
            .is_none()
    );
    assert!(ctx.ctx_field_access_error(&CtxField::Family).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::RemoteIp4).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::RemoteIp6).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::RemotePort).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::LocalIp4).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::LocalIp6).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::LocalPort).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::IngressIfindex)
            .is_none()
    );
}

#[test]
fn test_probe_context_allows_sk_skb_parser_socket_fields() {
    let ctx = ProbeContext::new(EbpfProgramType::SkSkbParser, "/sys/fs/bpf/demo_sockmap");
    assert!(ctx.ctx_field_access_error(&CtxField::Family).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::PktType).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::QueueMapping)
            .is_none()
    );
    assert!(ctx.ctx_field_access_error(&CtxField::EthProtocol).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::VlanPresent).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::VlanTci).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::VlanProto).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::SkbCb).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::TcClassid).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::NapiId).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::WireLen).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::GsoSegs).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::GsoSize).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Hwtstamp).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Ifindex).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::TcIndex).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::SkbHash).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::SockMark).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::SockPriority)
            .is_none()
    );
    assert!(ctx.ctx_field_access_error(&CtxField::LocalPort).is_none());
}

#[test]
fn test_probe_context_allows_sock_ops_fields() {
    let ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
    assert!(ctx.ctx_field_access_error(&CtxField::SockOp).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::SockOpsArgs).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Family).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::RemoteIp4).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::RemoteIp6).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::RemotePort).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::LocalIp4).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::LocalIp6).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::LocalPort).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::IsFullsock).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::SockOpsSndCwnd)
            .is_none()
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::SockOpsSrttUs)
            .is_none()
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::SockOpsCbFlags)
            .is_none()
    );
    assert!(ctx.ctx_field_access_error(&CtxField::SockState).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::SockOpsRttMin)
            .is_none()
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::SockOpsSndSsthresh)
            .is_none()
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::SockOpsRcvNxt)
            .is_none()
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::SockOpsSndNxt)
            .is_none()
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::SockOpsSndUna)
            .is_none()
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::SockOpsPacketsOut)
            .is_none()
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::SockOpsRetransOut)
            .is_none()
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::SockOpsTotalRetrans)
            .is_none()
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::SockOpsBytesReceived)
            .is_none()
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::SockOpsBytesAcked)
            .is_none()
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::SockOpsSkbLen)
            .is_none()
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::SockOpsSkbTcpFlags)
            .is_none()
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::SockOpsSkbHwtstamp)
            .is_none()
    );
}

#[test]
fn test_probe_context_allows_sk_lookup_cookie_field() {
    let ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");
    assert!(
        ctx.ctx_field_access_error(&CtxField::LookupCookie)
            .is_none()
    );
}

#[test]
fn test_probe_context_allows_lirc_mode2_fields() {
    let ctx = ProbeContext::new(EbpfProgramType::LircMode2, "/dev/lirc0");
    assert!(ctx.ctx_field_access_error(&CtxField::LircSample).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::LircValue).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::LircMode).is_none());
}

#[test]
fn test_probe_context_allows_cgroup_device_fields() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupDevice, "/sys/fs/cgroup");
    assert!(
        ctx.ctx_field_access_error(&CtxField::DeviceAccessType)
            .is_none()
    );
    assert!(ctx.ctx_field_access_error(&CtxField::DeviceMajor).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::DeviceMinor).is_none());
}

#[test]
fn test_probe_context_allows_ipv6_sock_addr_fields_on_ipv6_hook() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect6");
    assert!(ctx.ctx_field_access_error(&CtxField::UserIp6).is_none());
}

#[test]
fn test_probe_context_rejects_ipv4_sock_addr_fields_on_ipv6_hooks() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect6");
    let err = ctx
        .ctx_field_access_error(&CtxField::UserIp4)
        .expect("expected ipv6 hook rejection for ctx.user_ip4");
    assert!(err.contains("IPv4 cgroup_sock_addr hooks"));
}

#[test]
fn test_probe_context_rejects_msg_source_field_on_non_msg_hook() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect4");
    let err = ctx
        .ctx_field_access_error(&CtxField::MsgSrcIp4)
        .expect("expected non-msg-hook rejection for ctx.msg_src_ip4");
    assert!(err.contains("sendmsg*/recvmsg*"));
}

#[test]
fn test_probe_context_rejects_ipv6_sock_addr_fields_on_ipv4_hooks() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect4");
    let err = ctx
        .ctx_field_access_error(&CtxField::UserIp6)
        .expect("expected ipv4 hook rejection for ctx.user_ip6");
    assert!(err.contains("IPv6 cgroup_sock_addr hooks"));
}

#[test]
fn test_probe_context_rejects_msg_source_ipv6_field_on_non_msg_hook() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect6");
    let err = ctx
        .ctx_field_access_error(&CtxField::MsgSrcIp6)
        .expect("expected non-msg-hook rejection for ctx.msg_src_ip6");
    assert!(err.contains("sendmsg*/recvmsg*"));
}

#[test]
fn test_probe_context_rejects_sock_addr_fields_on_packet_programs() {
    let ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = ctx
        .ctx_field_access_error(&CtxField::Protocol)
        .expect("expected sock addr field access error");
    assert!(err.contains(
        "ctx.protocol is only available on cgroup_sock, cgroup_sock_addr, and sk_lookup programs"
    ));
}

#[test]
fn test_probe_context_rejects_sock_ops_fields_on_packet_programs() {
    let ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = ctx
        .ctx_field_access_error(&CtxField::SockOp)
        .expect("expected sock_ops field access error");
    assert!(err.contains("ctx.op is only available on sock_ops programs"));
}

#[test]
fn test_probe_context_rejects_cgroup_device_fields_on_packet_programs() {
    let ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = ctx
        .ctx_field_access_error(&CtxField::DeviceAccessType)
        .expect("expected cgroup_device field access error");
    assert!(err.contains("ctx.access_type is only available on cgroup_device programs"));
}

#[test]
fn test_probe_context_allows_sockopt_fields_on_cgroup_sockopt_get() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");
    assert!(
        ctx.ctx_field_access_error(&CtxField::SockoptLevel)
            .is_none()
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::SockoptOptname)
            .is_none()
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::SockoptOptlen)
            .is_none()
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::SockoptRetval)
            .is_none()
    );
}

#[test]
fn test_probe_context_rejects_sockopt_retval_on_cgroup_sockopt_set() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:set");
    let err = ctx
        .ctx_field_access_error(&CtxField::SockoptRetval)
        .expect("expected cgroup_sockopt:set retval rejection");
    assert!(err.contains("cgroup_sockopt:get"));
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
fn test_cgroup_skb_section_name_uses_attach_direction() {
    let builder = crate::compiler::instruction::EbpfBuilder::new();
    let program = EbpfProgram::new(
        EbpfProgramType::CgroupSkb,
        "/sys/fs/cgroup:ingress",
        "main",
        builder,
    );
    assert_eq!(
        program
            .section_name()
            .expect("cgroup_skb section should build"),
        "cgroup_skb/ingress"
    );
}

#[test]
fn test_cgroup_sock_section_name_uses_attach_kind() {
    let builder = crate::compiler::instruction::EbpfBuilder::new();
    let program = EbpfProgram::new(
        EbpfProgramType::CgroupSock,
        "/sys/fs/cgroup:sock_create",
        "main",
        builder,
    );
    assert_eq!(
        program
            .section_name()
            .expect("cgroup_sock section should build"),
        "cgroup/sock_create"
    );
}

#[test]
fn test_cgroup_sock_addr_section_name_uses_attach_kind() {
    let builder = crate::compiler::instruction::EbpfBuilder::new();
    let program = EbpfProgram::new(
        EbpfProgramType::CgroupSockAddr,
        "/sys/fs/cgroup:connect4",
        "main",
        builder,
    );
    assert_eq!(
        program
            .section_name()
            .expect("cgroup_sock_addr section should build"),
        "cgroup/connect4"
    );
}

#[test]
fn test_sock_ops_section_name() {
    let builder = crate::compiler::instruction::EbpfBuilder::new();
    let program = EbpfProgram::new(EbpfProgramType::SockOps, "/sys/fs/cgroup", "main", builder);
    assert_eq!(
        program
            .section_name()
            .expect("sock_ops section should build"),
        "sockops"
    );
}

#[test]
fn test_cgroup_device_section_name() {
    let builder = crate::compiler::instruction::EbpfBuilder::new();
    let program = EbpfProgram::new(
        EbpfProgramType::CgroupDevice,
        "/sys/fs/cgroup",
        "main",
        builder,
    );
    assert_eq!(
        program
            .section_name()
            .expect("cgroup_device section should build"),
        "cgroup/dev"
    );
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
        HashMap::new(),
    );

    let err = program
        .validate_runtime_artifacts_for_info(&limited_program)
        .expect_err("expected emit capability error");

    assert!(
        matches!(err, CompileError::InvalidProgram(msg) if msg.contains("limited programs do not support event emission"))
    );
}
