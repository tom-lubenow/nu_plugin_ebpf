use super::*;
use crate::compiler::BpfHelper;
use crate::compiler::hindley_milner::HMType;
use crate::compiler::mir::{CtxField, CtxStoreTarget, MapKind, MirType, StructField};
use crate::compiler::mir_to_ebpf::compile_mir_to_ebpf;
use crate::compiler::{ContextFieldLoadGuard, SockOpsCallbackGuard};
use crate::kernel_btf::KernelBtf;
use crate::program_spec::ProgramSpec;
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
fn test_sleepable_btf_program_section_name_uses_program_spec() {
    let spec = ProgramSpec::parse("fentry.s:ksys_read").expect("sleepable fentry spec");
    let prog = EbpfProgram::from_bytecode(EbpfProgramType::Fentry, "ksys_read", "test", vec![])
        .with_program_spec(spec.clone());
    assert_eq!(prog.parsed_program_spec(), Some(&spec));
    assert_eq!(
        prog.section_name()
            .expect("sleepable fentry section name should build"),
        "fentry.s/ksys_read"
    );
    assert_eq!(
        prog.into_program_section()
            .section_name()
            .expect("sleepable fentry program-section name should build"),
        "fentry.s/ksys_read"
    );

    let from_full_spec = EbpfProgram::from_bytecode(
        EbpfProgramType::Fentry,
        "fentry.s:ksys_read",
        "test",
        vec![],
    );
    assert_eq!(
        from_full_spec
            .section_name()
            .expect("sleepable full-spec section name should build"),
        "fentry.s/ksys_read"
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
fn test_ebpf_program_caches_typed_program_spec() {
    let prog = EbpfProgram::from_bytecode(EbpfProgramType::Xdp, "lo", "test", vec![]);
    let section = prog.clone().into_program_section();

    assert!(matches!(
        prog.parsed_program_spec(),
        Some(ProgramSpec::Xdp { target }) if target.interface == "lo"
    ));
    assert!(matches!(
        section.parsed_program_spec(),
        Some(ProgramSpec::Xdp { target }) if target.interface == "lo"
    ));
}

#[test]
fn test_ebpf_program_preserves_noncanonical_uprobe_target_string_with_cached_program_spec() {
    let prog = EbpfProgram::from_bytecode(
        EbpfProgramType::Uprobe,
        "/usr/bin/app:main+16",
        "test",
        vec![],
    );

    assert_eq!(prog.target, "/usr/bin/app:main+16");
    assert!(matches!(
        prog.parsed_program_spec(),
        Some(ProgramSpec::Uprobe { target })
            if target.binary_path == "/usr/bin/app"
                && target.function_name.as_deref() == Some("main")
                && target.offset == 16
    ));
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
fn test_program_type_metadata_for_perf_event() {
    let info = EbpfProgramType::PerfEvent.info();
    assert_eq!(info.canonical_prefix, "perf_event");
    assert_eq!(info.attach_kind, ProgramAttachKind::PerfEvent);
    assert_eq!(info.target_kind, ProgramTargetKind::PerfEventTarget);
    assert_eq!(info.arg_access, ProgramValueAccess::PtRegs);
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
    assert!(!info.supports_packet_data_ctx_fields);
    assert!(info.supports_ingress_ifindex_ctx_field);
}

#[test]
fn test_program_type_direct_packet_write_support_follows_program_model() {
    assert!(EbpfProgramType::Xdp.supports_direct_packet_writes());
    assert!(EbpfProgramType::Tc.supports_direct_packet_writes());
    assert!(EbpfProgramType::SkSkb.supports_direct_packet_writes());
    assert!(EbpfProgramType::SkSkbParser.supports_direct_packet_writes());

    assert!(!EbpfProgramType::SocketFilter.supports_direct_packet_writes());
    assert!(!EbpfProgramType::CgroupSkb.supports_direct_packet_writes());
    assert!(!EbpfProgramType::SkMsg.supports_direct_packet_writes());
    assert!(!EbpfProgramType::SockOps.supports_direct_packet_writes());
}

#[test]
fn test_program_type_return_action_aliases_cover_const_families() {
    assert_eq!(
        EbpfProgramType::Xdp.return_action_alias("PaSs"),
        Some(ProgramReturnAlias::Const(2))
    );
    assert_eq!(
        EbpfProgramType::Tc.return_action_alias("trap"),
        Some(ProgramReturnAlias::Const(8))
    );
    assert_eq!(
        EbpfProgramType::CgroupSock.return_action_alias("reject"),
        Some(ProgramReturnAlias::Const(0))
    );
    assert_eq!(
        EbpfProgramType::SkMsg.return_action_alias("allow"),
        Some(ProgramReturnAlias::Const(1))
    );
    assert_eq!(
        EbpfProgramType::SkSkbParser.return_action_alias("allow"),
        None
    );
    assert_eq!(EbpfProgramType::Kprobe.return_action_alias("pass"), None);
}

#[test]
fn test_program_type_return_action_aliases_cover_packet_len_aliases() {
    assert_eq!(
        EbpfProgramType::SocketFilter.return_action_alias("permit"),
        Some(ProgramReturnAlias::PacketLen)
    );
    assert_eq!(
        EbpfProgramType::SocketFilter.return_action_alias("KEEP"),
        Some(ProgramReturnAlias::PacketLen)
    );
}

#[test]
fn test_program_type_uses_raw_tracepoint_arg_access() {
    assert!(EbpfProgramType::RawTracepoint.uses_raw_tracepoint_args());
    assert!(!EbpfProgramType::Kprobe.uses_raw_tracepoint_args());
    assert!(!EbpfProgramType::TpBtf.uses_raw_tracepoint_args());
}

#[test]
fn test_program_type_socket_layouts_follow_program_model() {
    assert_eq!(
        EbpfProgramType::CgroupSock.socket_family_context_layout(),
        Some(SocketContextLayout::CgroupSock)
    );
    assert_eq!(
        EbpfProgramType::CgroupSock.sock_type_context_layout(),
        Some(SocketContextLayout::CgroupSock)
    );
    assert_eq!(
        EbpfProgramType::CgroupSock.protocol_context_layout(),
        Some(SocketContextLayout::CgroupSock)
    );
    assert_eq!(
        EbpfProgramType::CgroupSock.socket_tuple_context_layout(),
        Some(SocketContextLayout::CgroupSock)
    );

    assert_eq!(
        EbpfProgramType::CgroupSkb.socket_family_context_layout(),
        Some(SocketContextLayout::SkBuff)
    );
    assert_eq!(
        EbpfProgramType::CgroupSkb.socket_tuple_context_layout(),
        Some(SocketContextLayout::SkBuff)
    );

    assert_eq!(
        EbpfProgramType::SkSkbParser.socket_family_context_layout(),
        Some(SocketContextLayout::SkBuff)
    );
    assert_eq!(
        EbpfProgramType::SkSkbParser.socket_tuple_context_layout(),
        Some(SocketContextLayout::SkBuff)
    );
    assert_eq!(
        EbpfProgramType::SkSkbParser.sock_type_context_layout(),
        None
    );
    assert_eq!(
        EbpfProgramType::SkSkbParser.protocol_context_layout(),
        Some(SocketContextLayout::SkBuff)
    );
    assert_eq!(
        EbpfProgramType::SocketFilter.protocol_context_layout(),
        Some(SocketContextLayout::SkBuff)
    );
    assert_eq!(
        EbpfProgramType::SocketFilter.socket_family_context_layout(),
        None
    );
    assert_eq!(EbpfProgramType::Tc.socket_tuple_context_layout(), None);
}

#[test]
fn test_program_type_socket_ref_layouts_follow_program_model() {
    assert_eq!(
        EbpfProgramType::SocketFilter.socket_ref_context_layout(),
        Some(SocketContextLayout::SkBuff)
    );

    assert_eq!(
        EbpfProgramType::CgroupSockAddr.socket_ref_context_layout(),
        Some(SocketContextLayout::SockAddr)
    );

    assert_eq!(
        EbpfProgramType::CgroupSockopt.socket_ref_context_layout(),
        Some(SocketContextLayout::CgroupSockopt)
    );

    assert_eq!(
        EbpfProgramType::SkMsg.socket_ref_context_layout(),
        Some(SocketContextLayout::SkMsg)
    );

    assert_eq!(
        EbpfProgramType::SockOps.socket_ref_context_layout(),
        Some(SocketContextLayout::SockOps)
    );

    assert_eq!(EbpfProgramType::Xdp.socket_ref_context_layout(), None);
}

#[test]
fn test_program_type_data_meta_layouts_follow_program_model() {
    assert_eq!(
        EbpfProgramType::Xdp.data_meta_context_kind(),
        Some(PacketContextKind::XdpMd)
    );
    assert_eq!(
        EbpfProgramType::Tc.data_meta_context_kind(),
        Some(PacketContextKind::SkBuff)
    );
    assert_eq!(EbpfProgramType::CgroupSkb.data_meta_context_kind(), None);
}

#[test]
fn test_program_type_ingress_ifindex_layouts_follow_program_model() {
    assert_eq!(
        EbpfProgramType::Xdp.ingress_ifindex_context_layout(),
        Some(IngressIfindexContextLayout::XdpMd)
    );

    assert_eq!(
        EbpfProgramType::SkLookup.ingress_ifindex_context_layout(),
        Some(IngressIfindexContextLayout::SkLookup)
    );

    assert_eq!(
        EbpfProgramType::SkSkb.ingress_ifindex_context_layout(),
        Some(IngressIfindexContextLayout::SkBuff)
    );

    assert_eq!(
        EbpfProgramType::SkMsg.ingress_ifindex_context_layout(),
        None
    );
}

#[test]
fn test_program_type_sock_mark_priority_layouts_follow_program_model() {
    assert_eq!(
        EbpfProgramType::CgroupSock.sock_mark_priority_context_layout(),
        Some(SocketContextLayout::CgroupSock)
    );

    assert_eq!(
        EbpfProgramType::Tc.sock_mark_priority_context_layout(),
        Some(SocketContextLayout::SkBuff)
    );

    assert_eq!(
        EbpfProgramType::SockOps.sock_mark_priority_context_layout(),
        None
    );
}

#[test]
fn test_program_type_sock_state_layouts_follow_program_model() {
    assert_eq!(
        EbpfProgramType::CgroupSock.sock_state_context_layout(),
        Some(SocketContextLayout::CgroupSock)
    );
    assert_eq!(
        EbpfProgramType::SockOps.sock_state_context_layout(),
        Some(SocketContextLayout::SockOps)
    );
    assert_eq!(EbpfProgramType::SkMsg.sock_state_context_layout(), None);
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
fn test_bpf_map_type_constants_match_kernel_uapi() {
    assert_eq!(BpfMapType::CgroupArray as u32, 8);
    assert_eq!(BpfMapType::DevMap as u32, 14);
    assert_eq!(BpfMapType::SockMap as u32, 15);
    assert_eq!(BpfMapType::CpuMap as u32, 16);
    assert_eq!(BpfMapType::XskMap as u32, 17);
    assert_eq!(BpfMapType::SockHash as u32, 18);
    assert_eq!(BpfMapType::SkStorage as u32, 24);
    assert_eq!(BpfMapType::DevMapHash as u32, 25);
    assert_eq!(BpfMapType::RingBuf as u32, 27);
    assert_eq!(BpfMapType::InodeStorage as u32, 28);
    assert_eq!(BpfMapType::TaskStorage as u32, 29);
    assert_eq!(BpfMapType::BloomFilter as u32, 30);
    assert_eq!(BpfMapType::CgrpStorage as u32, 32);
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

    assert_eq!(ctx.program_type(), EbpfProgramType::StructOps);
    assert_eq!(ctx.target(), "select_cpu");
    assert_eq!(ctx.struct_ops_value_type_name(), Some("sched_ext_ops"));
}

#[test]
fn test_probe_context_tracepoint_parts_use_typed_program_spec() {
    let ctx = ProbeContext::new(EbpfProgramType::Tracepoint, "sched/sched_switch");
    assert_eq!(
        ctx.tracepoint_parts(),
        Some(("sched".to_string(), "sched_switch".to_string()))
    );
}

#[test]
fn test_probe_context_btf_context_label_formats_struct_ops() {
    let ctx = ProbeContext::new_struct_ops_callback("sched_ext_ops", "select_cpu");

    assert_eq!(
        ctx.btf_context_label(),
        "struct_ops sched_ext_ops.select_cpu"
    );
    assert_eq!(
        ctx.btf_arg_name_invalid_error("missing"),
        "ctx.arg.missing is not a valid argument name for struct_ops sched_ext_ops.select_cpu"
    );
}

#[test]
fn test_probe_context_btf_context_label_preserves_sleepable_spec_prefix() {
    let fentry = ProbeContext::from_program_spec(
        ProgramSpec::parse("fentry.s:security_file_open").expect("sleepable fentry spec"),
    );
    assert_eq!(fentry.btf_context_label(), "fentry.s:security_file_open");

    let lsm = ProbeContext::from_program_spec(
        ProgramSpec::parse("lsm.s:file_open").expect("sleepable lsm spec"),
    );
    assert_eq!(
        lsm.btf_arg_name_invalid_error("missing"),
        "ctx.arg.missing is not a valid argument name for lsm.s:file_open"
    );
}

#[test]
fn test_probe_context_btf_arg_index_by_name_uses_tp_btf_lookup() {
    let tracepoint_name = "sys_enter";
    let ctx = ProbeContext::new(EbpfProgramType::TpBtf, tracepoint_name);

    assert_eq!(
        ctx.btf_arg_index_by_name("regs")
            .expect("tp_btf ctx.arg.<name> lookup should succeed"),
        KernelBtf::get()
            .tp_btf_arg_index_by_name(tracepoint_name, "regs")
            .expect("direct tp_btf arg-name lookup should succeed")
    );
}

#[test]
fn test_probe_context_tc_attach_kind_uses_typed_program_spec() {
    let ingress = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let egress = ProbeContext::new(EbpfProgramType::Tc, "lo:egress");

    assert!(matches!(
        ingress.parsed_program_spec(),
        Some(ProgramSpec::Tc { target }) if target.is_ingress()
    ));
    assert!(matches!(
        egress.parsed_program_spec(),
        Some(ProgramSpec::Tc { target }) if !target.is_ingress()
    ));
}

#[test]
fn test_probe_context_new_accepts_full_tc_spec_string() {
    let ctx = ProbeContext::new(EbpfProgramType::Tc, "tc:lo:ingress");

    assert_eq!(ctx.target(), "lo:ingress");
    assert!(matches!(
        ctx.parsed_program_spec(),
        Some(ProgramSpec::Tc { target }) if target.is_ingress()
    ));
}

#[test]
fn test_probe_context_new_ignores_mismatched_full_spec_string() {
    let ctx = ProbeContext::new(EbpfProgramType::Tc, "xdp:lo");

    assert_eq!(ctx.target(), "xdp:lo");
    assert!(ctx.parsed_program_spec().is_none());
}

#[test]
fn test_probe_context_cgroup_sock_attach_kind_uses_typed_program_spec() {
    let post_bind = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:post_bind4");
    let sock_create = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_create");

    assert!(matches!(
        post_bind.parsed_program_spec(),
        Some(ProgramSpec::CgroupSock { target }) if target.is_post_bind()
    ));
    assert!(matches!(
        sock_create.parsed_program_spec(),
        Some(ProgramSpec::CgroupSock { target }) if !target.is_post_bind()
    ));
}

#[test]
fn test_probe_context_struct_ops_callback_uses_value_type_program_spec() {
    let ctx = ProbeContext::new_struct_ops_callback("sched_ext_ops", "select_cpu");

    assert!(matches!(
        ctx.parsed_program_spec(),
        Some(ProgramSpec::StructOpsCallback {
            value_type_name,
            callback_name
        }) if value_type_name == "sched_ext_ops" && callback_name == "select_cpu"
    ));
}

#[test]
fn test_probe_context_cgroup_sysctl_uses_typed_program_spec() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSysctl, "/sys/fs/cgroup");

    assert!(matches!(
        ctx.parsed_program_spec(),
        Some(ProgramSpec::CgroupSysctl { target }) if target.cgroup_path == "/sys/fs/cgroup"
    ));
}

#[test]
fn test_probe_context_xdp_uses_typed_program_spec() {
    let ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    assert!(matches!(
        ctx.parsed_program_spec(),
        Some(ProgramSpec::Xdp { target }) if target.interface == "lo"
    ));
}

#[test]
fn test_probe_context_from_program_spec_uses_structured_target() {
    let spec = ProgramSpec::from_program_type_target(EbpfProgramType::Xdp, "lo")
        .expect("xdp program spec should parse");
    let ctx = ProbeContext::from_program_spec(spec.clone());

    assert_eq!(ctx.target(), "lo");
    assert_eq!(ctx.parsed_program_spec(), Some(&spec));
}

#[test]
fn test_program_spec_ctx_field_type_spec_respects_sockopt_attach_kind() {
    let getsockopt =
        ProgramSpec::from_program_type_target(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get")
            .expect("cgroup_sockopt:get spec should parse");
    let setsockopt =
        ProgramSpec::from_program_type_target(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:set")
            .expect("cgroup_sockopt:set spec should parse");

    assert!(
        getsockopt
            .ctx_field_type_spec(&CtxField::SockoptRetval)
            .is_some()
    );
    assert!(
        setsockopt
            .ctx_field_type_spec(&CtxField::SockoptRetval)
            .is_none()
    );
}

#[test]
fn test_program_spec_ctx_field_projection_spec_respects_sock_addr_attach_kind() {
    let connect6 = ProgramSpec::from_program_type_target(
        EbpfProgramType::CgroupSockAddr,
        "/sys/fs/cgroup:connect6",
    )
    .expect("cgroup_sock_addr connect6 spec should parse");
    let sendmsg6 = ProgramSpec::from_program_type_target(
        EbpfProgramType::CgroupSockAddr,
        "/sys/fs/cgroup:sendmsg6",
    )
    .expect("cgroup_sock_addr sendmsg6 spec should parse");

    assert!(
        connect6
            .ctx_field_projection_spec(&CtxField::MsgSrcIp6)
            .is_none()
    );
    assert!(
        sendmsg6
            .ctx_field_projection_spec(&CtxField::MsgSrcIp6)
            .is_some()
    );
}

#[test]
fn test_probe_context_new_preserves_noncanonical_uprobe_target_string() {
    let ctx = ProbeContext::new(EbpfProgramType::Uprobe, "/usr/bin/app:main+16");

    assert_eq!(ctx.target(), "/usr/bin/app:main+16");
    assert!(matches!(
        ctx.parsed_program_spec(),
        Some(ProgramSpec::Uprobe { target })
            if target.binary_path == "/usr/bin/app"
                && target.function_name.as_deref() == Some("main")
                && target.offset == 16
    ));
}

#[test]
fn test_probe_context_ctx_field_type_spec_respects_context_legality() {
    let kprobe = ProbeContext::new(EbpfProgramType::Kprobe, "do_sys_openat2");
    let tc = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let ipv6_sock_addr =
        ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect6");

    assert!(kprobe.ctx_field_type_spec(&CtxField::PacketLen).is_none());
    assert!(tc.ctx_field_type_spec(&CtxField::PacketLen).is_some());
    assert!(
        ipv6_sock_addr
            .ctx_field_type_spec(&CtxField::UserIp4)
            .is_none()
    );
}

#[test]
fn test_probe_context_ctx_field_projection_spec_respects_context_legality() {
    let kprobe = ProbeContext::new(EbpfProgramType::Kprobe, "do_sys_openat2");
    let ipv4_sock_addr =
        ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect4");
    let ipv6_sock_addr =
        ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect6");

    assert!(
        kprobe
            .ctx_field_projection_spec(&CtxField::Socket)
            .is_none()
    );
    assert!(
        ipv4_sock_addr
            .ctx_field_projection_spec(&CtxField::UserIp6)
            .is_none()
    );
    assert!(
        ipv6_sock_addr
            .ctx_field_projection_spec(&CtxField::UserIp6)
            .is_some()
    );
}

#[test]
fn test_probe_context_ctx_field_type_spec_is_program_type_aware_within_skb_family() {
    let socket_filter = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");
    let tc = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let cgroup_skb = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:ingress");
    let sk_skb = ProbeContext::new(EbpfProgramType::SkSkb, "/sys/fs/bpf/demo_sockmap");

    assert!(
        socket_filter
            .ctx_field_type_spec(&CtxField::Family)
            .is_none()
    );
    assert!(
        socket_filter
            .ctx_field_type_spec(&CtxField::RemotePort)
            .is_none()
    );
    assert!(tc.ctx_field_type_spec(&CtxField::Family).is_none());
    assert!(tc.ctx_field_type_spec(&CtxField::RemotePort).is_none());
    assert!(cgroup_skb.ctx_field_type_spec(&CtxField::Family).is_some());
    assert!(
        cgroup_skb
            .ctx_field_type_spec(&CtxField::RemotePort)
            .is_some()
    );
    assert!(sk_skb.ctx_field_type_spec(&CtxField::Family).is_some());
}

#[test]
fn test_probe_context_ctx_field_load_guard_is_program_type_aware() {
    let sock_ops = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
    let sk_msg = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");

    assert_eq!(
        sock_ops.ctx_field_load_guard(&CtxField::PacketLen),
        Some(ContextFieldLoadGuard::SockOpsCallback(
            SockOpsCallbackGuard::PacketMetadata,
        ))
    );
    assert_eq!(
        sock_ops.ctx_field_load_guard(&CtxField::Data),
        Some(ContextFieldLoadGuard::SockOpsCallback(
            SockOpsCallbackGuard::PacketData,
        ))
    );
    assert!(sk_msg.ctx_field_load_guard(&CtxField::PacketLen).is_none());
}

#[test]
fn test_program_type_ctx_field_load_guard_follows_context_family() {
    assert_eq!(
        EbpfProgramType::SockOps.ctx_field_load_guard(&CtxField::PacketLen),
        Some(ContextFieldLoadGuard::SockOpsCallback(
            SockOpsCallbackGuard::PacketMetadata,
        ))
    );
    assert!(
        EbpfProgramType::SkMsg
            .ctx_field_load_guard(&CtxField::PacketLen)
            .is_none()
    );
}

#[test]
fn test_program_type_perf_event_ctx_field_support_follows_context_family() {
    assert!(EbpfProgramType::PerfEvent.uses_perf_event_context());
    assert!(!EbpfProgramType::Xdp.uses_perf_event_context());
    assert_eq!(
        EbpfProgramType::PerfEvent.supports_perf_event_ctx_fields(),
        cfg!(target_arch = "x86_64")
    );
    assert!(!EbpfProgramType::Xdp.supports_perf_event_ctx_fields());
}

#[test]
fn test_program_type_helper_backed_cookie_field_surfaces_follow_program_model() {
    assert!(EbpfProgramType::SocketFilter.supports_socket_cookie_ctx_field());
    assert!(EbpfProgramType::CgroupSock.supports_socket_cookie_ctx_field());
    assert!(!EbpfProgramType::SkLookup.supports_socket_cookie_ctx_field());

    assert!(EbpfProgramType::SocketFilter.supports_socket_uid_ctx_field());
    assert!(EbpfProgramType::SkSkbParser.supports_socket_uid_ctx_field());
    assert!(!EbpfProgramType::SockOps.supports_socket_uid_ctx_field());

    assert!(EbpfProgramType::SkMsg.supports_netns_cookie_ctx_field());
    assert!(EbpfProgramType::CgroupSockopt.supports_netns_cookie_ctx_field());
    assert!(!EbpfProgramType::SkLookup.supports_netns_cookie_ctx_field());

    assert!(EbpfProgramType::SkLookup.supports_lookup_cookie_ctx_field());
    assert!(!EbpfProgramType::Tc.supports_lookup_cookie_ctx_field());
}

#[test]
fn test_program_type_raw_context_pointer_aliases_follow_context_family() {
    assert!(EbpfProgramType::CgroupSock.ctx_field_is_raw_context_pointer(&CtxField::Context));
    assert!(EbpfProgramType::CgroupSock.ctx_field_is_raw_context_pointer(&CtxField::Socket));
    assert!(!EbpfProgramType::CgroupSockopt.ctx_field_is_raw_context_pointer(&CtxField::Socket));
    assert!(!EbpfProgramType::SockOps.ctx_field_is_raw_context_pointer(&CtxField::Socket));
}

#[test]
fn test_program_type_ctx_field_non_null_pointer_policy_follows_context_schema() {
    assert!(EbpfProgramType::Kprobe.ctx_field_pointer_is_non_null(&CtxField::Task));
    assert!(!EbpfProgramType::Xdp.ctx_field_pointer_is_non_null(&CtxField::Task));
    assert!(EbpfProgramType::CgroupSock.ctx_field_pointer_is_non_null(&CtxField::Socket));
    assert!(!EbpfProgramType::CgroupSockopt.ctx_field_pointer_is_non_null(&CtxField::Socket));

    let kprobe = ProbeContext::new(EbpfProgramType::Kprobe, "tcp_connect");
    assert!(kprobe.ctx_field_pointer_is_non_null(&CtxField::Task));
    assert!(ProbeContext::resolve_ctx_field_pointer_is_non_null(
        Some(&kprobe),
        &CtxField::Task
    ));
}

#[test]
fn test_static_context_field_btf_runtime_type_policy_follows_schema() {
    let task_spec = ProbeContext::static_ctx_field_type_spec(&CtxField::Task)
        .expect("expected ctx.task type spec");
    assert_eq!(task_spec.kernel_btf_runtime_type_name, Some("task_struct"));

    let pid_spec = ProbeContext::static_ctx_field_type_spec(&CtxField::Pid)
        .expect("expected ctx.pid type spec");
    assert_eq!(pid_spec.kernel_btf_runtime_type_name, None);
}

#[test]
fn test_program_type_btf_callable_surface_follows_program_model() {
    assert_eq!(
        EbpfProgramType::Fentry.btf_callable_surface(),
        Some(ProgramBtfCallableSurface::FunctionTrampoline)
    );
    assert_eq!(
        EbpfProgramType::TpBtf.btf_callable_surface(),
        Some(ProgramBtfCallableSurface::TpBtf)
    );
    assert_eq!(
        EbpfProgramType::Lsm.btf_callable_surface(),
        Some(ProgramBtfCallableSurface::LsmHook)
    );
    assert_eq!(
        EbpfProgramType::StructOps.btf_callable_surface(),
        Some(ProgramBtfCallableSurface::StructOpsCallback)
    );
    assert_eq!(EbpfProgramType::Kprobe.btf_callable_surface(), None);
}

#[test]
fn test_probe_context_helper_call_error_uses_typed_attach_kind() {
    let ingress = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let egress = ProbeContext::new(EbpfProgramType::Tc, "lo:egress");
    let connect = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect4");
    let bind = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:bind4");
    let sockopt_get = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");
    let sockopt_set = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:set");
    let sk_lookup = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");
    let xdp = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    assert!(ingress.helper_call_error(BpfHelper::RedirectPeer).is_none());
    assert!(ingress.helper_call_error(BpfHelper::SkAssign).is_none());
    assert_eq!(
        ingress.helper_call_error(BpfHelper::SkbCgroupId),
        Some("helper 'bpf_skb_cgroup_id' is only valid in tc egress programs".to_string())
    );
    assert_eq!(
        ingress.helper_call_error(BpfHelper::GetRouteRealm),
        Some("helper 'bpf_get_route_realm' is only valid in tc egress programs".to_string())
    );
    assert_eq!(
        egress.helper_call_error(BpfHelper::RedirectPeer),
        Some("helper 'bpf_redirect_peer' is only valid in tc ingress programs".to_string())
    );
    assert_eq!(
        egress.helper_call_error(BpfHelper::SkAssign),
        Some("helper 'bpf_sk_assign' is only valid in tc ingress programs".to_string())
    );
    assert!(
        egress
            .helper_call_error(BpfHelper::SkbAncestorCgroupId)
            .is_none()
    );
    assert!(
        egress
            .helper_call_error(BpfHelper::GetCgroupClassid)
            .is_none()
    );
    assert!(connect.helper_call_error(BpfHelper::Bind).is_none());
    assert!(connect.helper_call_error(BpfHelper::GetSockOpt).is_none());
    assert!(connect.helper_call_error(BpfHelper::SetSockOpt).is_none());
    assert!(
        sockopt_get
            .helper_call_error(BpfHelper::GetSockOpt)
            .is_none()
    );
    assert!(
        sockopt_set
            .helper_call_error(BpfHelper::SetSockOpt)
            .is_none()
    );
    assert!(sk_lookup.helper_call_error(BpfHelper::SkAssign).is_none());
    assert!(xdp.helper_call_error(BpfHelper::SkLookupTcp).is_none());
    assert_eq!(
        bind.helper_call_error(BpfHelper::Bind),
        Some(
            "helper 'bpf_bind' is only valid on cgroup_sock_addr connect4/connect6 hooks"
                .to_string()
        )
    );
    assert_eq!(
        bind.helper_call_error(BpfHelper::GetSockOpt),
        Some(
            "helper 'bpf_getsockopt' is only valid on cgroup_sock_addr connect4/connect6 hooks"
                .to_string()
        )
    );
    assert_eq!(
        bind.helper_call_error(BpfHelper::SetSockOpt),
        Some(
            "helper 'bpf_setsockopt' is only valid on cgroup_sock_addr connect4/connect6 hooks"
                .to_string()
        )
    );
}

#[test]
fn test_program_type_helper_call_error_covers_program_only_rules() {
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::MsgApplyBytes),
        Some("helper 'bpf_msg_apply_bytes' is only valid in sk_msg programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::MsgRedirectMap),
        Some("helper 'bpf_msg_redirect_map' is only valid in sk_msg programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::MsgRedirectHash),
        Some("helper 'bpf_msg_redirect_hash' is only valid in sk_msg programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::Redirect),
        Some("helper 'bpf_redirect' is only valid in xdp and tc programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::RedirectMap),
        Some("helper 'bpf_redirect_map' is only valid in xdp programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::RedirectPeer),
        Some("helper 'bpf_redirect_peer' is only valid in tc programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::SkbUnderCgroup),
        Some("helper 'bpf_skb_under_cgroup' is only valid in tc programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::SkbCgroupId),
        Some("helper 'bpf_skb_cgroup_id' is only valid in tc programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::GetCgroupClassid),
        Some("helper 'bpf_get_cgroup_classid' is only valid in tc programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::Lsm.helper_call_error(BpfHelper::PerfEventOutput),
        Some(
            "helper 'bpf_perf_event_output' is only valid in cgroup_device, cgroup_skb, cgroup_sock, cgroup_sockopt, cgroup_sock_addr, cgroup_sysctl, kprobe, kretprobe, uprobe, uretprobe, perf_event, raw_tracepoint, tracepoint, fentry, fexit, tp_btf, socket_filter, tc, sk_lookup, sk_msg, sk_skb, sk_skb_parser, sock_ops, and xdp programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::PerfProgReadValue),
        Some("helper 'bpf_perf_prog_read_value' is only valid in perf_event programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::ReadBranchRecords),
        Some("helper 'bpf_read_branch_records' is only valid in perf_event programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::GetFuncArg),
        Some(
            "helper 'bpf_get_func_arg' is only valid in fentry, fexit, tp_btf, and lsm programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::GetFuncArgCnt),
        Some(
            "helper 'bpf_get_func_arg_cnt' is only valid in fentry, fexit, tp_btf, and lsm programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Fentry.helper_call_error(BpfHelper::GetFuncRet),
        Some("helper 'bpf_get_func_ret' is only valid in fexit programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::GetStackId),
        Some(
            "helper 'bpf_get_stackid' is only valid in kprobe, kretprobe, uprobe, uretprobe, perf_event, raw_tracepoint, tracepoint, fentry, fexit, and tp_btf programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::GetStack),
        Some(
            "helper 'bpf_get_stack' is only valid in kprobe, kretprobe, uprobe, uretprobe, perf_event, raw_tracepoint, tracepoint, fentry, fexit, and tp_btf programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::GetFuncIp),
        Some(
            "helper 'bpf_get_func_ip' is only valid in kprobe, kretprobe, uprobe, uretprobe, perf_event, raw_tracepoint, tracepoint, fentry, fexit, and tp_btf programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::GetAttachCookie),
        Some(
            "helper 'bpf_get_attach_cookie' is only valid in kprobe, kretprobe, uprobe, uretprobe, perf_event, raw_tracepoint, tracepoint, fentry, fexit, and tp_btf programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::ProbeRead),
        Some(
            "helper 'bpf_probe_read' is only valid in kprobe, kretprobe, uprobe, uretprobe, lsm, perf_event, raw_tracepoint, tracepoint, fentry, fexit, and tp_btf programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::SkLookup.helper_call_error(BpfHelper::GetSocketCookie),
        Some(
            "helper 'bpf_get_socket_cookie' is only valid in fentry, fexit, tp_btf, socket_filter, tc, cgroup_skb, cgroup_sock, cgroup_sock_addr, sock_ops, sk_skb, and sk_skb_parser programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::XdpAdjustMeta),
        Some("helper 'bpf_xdp_adjust_meta' is only valid in xdp programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::XdpLoadBytes),
        Some("helper 'bpf_xdp_load_bytes' is only valid in xdp programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::SkbPullData),
        Some(
            "helper 'bpf_skb_pull_data' is only valid in tc, sk_skb, and sk_skb_parser programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::SkbLoadBytes),
        Some(
            "helper 'bpf_skb_load_bytes' is only valid in socket_filter, tc, cgroup_skb, sk_skb, and sk_skb_parser programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::SkSkb.helper_call_error(BpfHelper::SkbLoadBytesRelative),
        Some(
            "helper 'bpf_skb_load_bytes_relative' is only valid in socket_filter, tc, and cgroup_skb programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::SkbStoreBytes),
        Some(
            "helper 'bpf_skb_store_bytes' is only valid in tc, sk_skb, and sk_skb_parser programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::CloneRedirect),
        Some(
            "helper 'bpf_clone_redirect' is only valid in tc, sk_skb, and sk_skb_parser programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::L3CsumReplace),
        Some(
            "helper 'bpf_l3_csum_replace' is only valid in tc, sk_skb, and sk_skb_parser programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::CsumDiff),
        Some("helper 'bpf_csum_diff' is only valid in xdp and tc programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::CsumDiff),
        None
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::SkRedirectMap),
        Some(
            "helper 'bpf_sk_redirect_map' is only valid in sk_skb and sk_skb_parser programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::SkRedirectHash),
        Some(
            "helper 'bpf_sk_redirect_hash' is only valid in sk_skb and sk_skb_parser programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::SysctlGetCurrentValue),
        Some(
            "helper 'bpf_sysctl_get_current_value' is only valid in cgroup_sysctl programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::Bind),
        Some("helper 'bpf_bind' is only valid in cgroup_sock_addr programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::SockOpsCbFlagsSet),
        Some("helper 'bpf_sock_ops_cb_flags_set' is only valid in sock_ops programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::SockMapUpdate),
        Some("helper 'bpf_sock_map_update' is only valid in sock_ops programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::SockHashUpdate),
        Some("helper 'bpf_sock_hash_update' is only valid in sock_ops programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::LoadHdrOpt),
        Some("helper 'bpf_load_hdr_opt' is only valid in sock_ops programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::StoreHdrOpt),
        Some("helper 'bpf_store_hdr_opt' is only valid in sock_ops programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::ReserveHdrOpt),
        Some("helper 'bpf_reserve_hdr_opt' is only valid in sock_ops programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::SkLookupTcp),
        Some(
            "helper 'bpf_sk_lookup_tcp' is only valid in xdp, tc, cgroup_skb, cgroup_sock_addr, and sk_skb programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::SkRelease),
        Some(
            "helper 'bpf_sk_release' is only valid in xdp, tc, cgroup_skb, cgroup_sock_addr, sk_lookup, and sk_skb programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::SkAssign),
        Some("helper 'bpf_sk_assign' is only valid in tc and sk_lookup programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::GetListenerSock),
        Some(
            "helper 'bpf_get_listener_sock' is only valid in tc and cgroup_skb programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::SkFullsock),
        Some("helper 'bpf_sk_fullsock' is only valid in tc and cgroup_skb programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::TcpSock),
        Some(
            "helper 'bpf_tcp_sock' is only valid in tc, cgroup_skb, cgroup_sockopt, and sock_ops programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::SkcToTcpSock),
        Some(
            "helper 'bpf_skc_to_tcp_sock' is only valid in fentry, fexit, tp_btf, sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::SkcToUnixSock),
        Some(
            "helper 'bpf_skc_to_unix_sock' is only valid in fentry, fexit, tp_btf, sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::SockFromFile),
        Some(
            "helper 'bpf_sock_from_file' is only valid in fentry, fexit, and tp_btf programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::CgroupSkb.helper_call_error(BpfHelper::GetSocketUid),
        None
    );
    assert_eq!(
        EbpfProgramType::CgroupSockopt.helper_call_error(BpfHelper::GetNetnsCookie),
        None
    );
    assert_eq!(
        EbpfProgramType::SkMsg.helper_call_error(BpfHelper::SkCgroupId),
        Some("helper 'bpf_sk_cgroup_id' is only valid in cgroup_skb programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::SkMsg.helper_call_error(BpfHelper::SkAncestorCgroupId),
        Some("helper 'bpf_sk_ancestor_cgroup_id' is only valid in cgroup_skb programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::TcpCheckSyncookie),
        Some("helper 'bpf_tcp_check_syncookie' is only valid in xdp and tc programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::TcpGenSyncookie),
        Some("helper 'bpf_tcp_gen_syncookie' is only valid in xdp and tc programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::TaskStorageGet),
        Some(
            "helper 'bpf_task_storage_get' is only valid in kprobe, kretprobe, uprobe, uretprobe, perf_event, raw_tracepoint, tracepoint, fentry, fexit, tp_btf, and lsm programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::TaskStorageDelete),
        Some(
            "helper 'bpf_task_storage_delete' is only valid in kprobe, kretprobe, uprobe, uretprobe, perf_event, raw_tracepoint, tracepoint, fentry, fexit, tp_btf, and lsm programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::GetCurrentTaskBtf),
        Some(
            "helper 'bpf_get_current_task_btf' is only valid in kprobe, kretprobe, uprobe, uretprobe, perf_event, raw_tracepoint, tracepoint, fentry, fexit, tp_btf, and lsm programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::GetCurrentTask),
        Some(
            "helper 'bpf_get_current_task' is only valid in kprobe, kretprobe, uprobe, uretprobe, perf_event, raw_tracepoint, tracepoint, fentry, fexit, tp_btf, and lsm programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::TaskPtRegs),
        Some(
            "helper 'bpf_task_pt_regs' is only valid in kprobe, kretprobe, uprobe, uretprobe, perf_event, raw_tracepoint, tracepoint, fentry, fexit, tp_btf, and lsm programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::InodeStorageGet),
        Some("helper 'bpf_inode_storage_get' is only valid in lsm programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::InodeStorageDelete),
        Some("helper 'bpf_inode_storage_delete' is only valid in lsm programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::SkStorageGet),
        Some(
            "helper 'bpf_sk_storage_get' is only valid in tc, cgroup_skb, cgroup_sock, cgroup_sock_addr, cgroup_sockopt, sock_ops, sk_msg, struct_ops, fentry, fexit, tp_btf, and lsm programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::SkStorageDelete),
        Some(
            "helper 'bpf_sk_storage_delete' is only valid in tc, cgroup_skb, cgroup_sock_addr, cgroup_sockopt, sock_ops, sk_msg, struct_ops, fentry, fexit, tp_btf, and lsm programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::CgroupSock.helper_call_error(BpfHelper::SkStorageDelete),
        Some(
            "helper 'bpf_sk_storage_delete' is only valid in tc, cgroup_skb, cgroup_sock_addr, cgroup_sockopt, sock_ops, sk_msg, struct_ops, fentry, fexit, tp_btf, and lsm programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::CgroupSysctl.helper_call_error(BpfHelper::SysctlGetCurrentValue),
        None
    );
    assert_eq!(
        EbpfProgramType::SkSkb.helper_call_error(BpfHelper::SkRedirectMap),
        None
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::RedirectMap),
        None
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::PerfEventOutput),
        None
    );
    assert_eq!(
        EbpfProgramType::SkSkbParser.helper_call_error(BpfHelper::SkRedirectHash),
        None
    );
    assert_eq!(
        EbpfProgramType::PerfEvent.helper_call_error(BpfHelper::GetStackId),
        None
    );
    assert_eq!(
        EbpfProgramType::PerfEvent.helper_call_error(BpfHelper::PerfProgReadValue),
        None
    );
    assert_eq!(
        EbpfProgramType::PerfEvent.helper_call_error(BpfHelper::ReadBranchRecords),
        None
    );
    assert_eq!(
        EbpfProgramType::Fentry.helper_call_error(BpfHelper::GetFuncArg),
        None
    );
    assert_eq!(
        EbpfProgramType::Lsm.helper_call_error(BpfHelper::GetFuncArgCnt),
        None
    );
    assert_eq!(
        EbpfProgramType::Fexit.helper_call_error(BpfHelper::GetFuncRet),
        None
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::GetStack),
        None
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::GetFuncIp),
        None
    );
    assert_eq!(
        EbpfProgramType::Tracepoint.helper_call_error(BpfHelper::GetAttachCookie),
        None
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::ProbeRead),
        None
    );
    assert_eq!(
        EbpfProgramType::SocketFilter.helper_call_error(BpfHelper::GetSocketCookie),
        None
    );
    assert_eq!(
        EbpfProgramType::Tc.helper_call_error(BpfHelper::GetSocketUid),
        None
    );
    assert_eq!(
        EbpfProgramType::SkMsg.helper_call_error(BpfHelper::GetNetnsCookie),
        None
    );
    assert_eq!(
        EbpfProgramType::Tc.helper_call_error(BpfHelper::SkbSetTstamp),
        None
    );
    assert_eq!(
        EbpfProgramType::Tc.helper_call_error(BpfHelper::SkbUnderCgroup),
        None
    );
    assert_eq!(
        EbpfProgramType::Tc.helper_call_error(BpfHelper::SkbAncestorCgroupId),
        None
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::CurrentTaskUnderCgroup),
        None
    );
    assert_eq!(
        EbpfProgramType::CgroupSkb.helper_call_error(BpfHelper::SkCgroupId),
        None
    );
    assert_eq!(
        EbpfProgramType::CgroupSkb.helper_call_error(BpfHelper::SkAncestorCgroupId),
        None
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::XdpAdjustHead),
        None
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::XdpGetBuffLen),
        None
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::XdpStoreBytes),
        None
    );
    assert_eq!(
        EbpfProgramType::Tc.helper_call_error(BpfHelper::SkbChangeHead),
        None
    );
    assert_eq!(
        EbpfProgramType::SocketFilter.helper_call_error(BpfHelper::SkbLoadBytes),
        None
    );
    assert_eq!(
        EbpfProgramType::CgroupSkb.helper_call_error(BpfHelper::SkbLoadBytesRelative),
        None
    );
    assert_eq!(
        EbpfProgramType::SkSkb.helper_call_error(BpfHelper::SkbAdjustRoom),
        None
    );
    assert_eq!(
        EbpfProgramType::SkSkb.helper_call_error(BpfHelper::SkbSetTstamp),
        Some("helper 'bpf_skb_set_tstamp' is only valid in tc programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::Tc.helper_call_error(BpfHelper::SkbStoreBytes),
        None
    );
    assert_eq!(
        EbpfProgramType::SkSkb.helper_call_error(BpfHelper::GetHashRecalc),
        None
    );
    assert_eq!(
        EbpfProgramType::SkSkbParser.helper_call_error(BpfHelper::SkbChangeTail),
        None
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::SkLookupUdp),
        None
    );
    assert_eq!(
        EbpfProgramType::SkLookup.helper_call_error(BpfHelper::SkRelease),
        None
    );
    assert_eq!(
        EbpfProgramType::Tc.helper_call_error(BpfHelper::SkAssign),
        None
    );
    assert_eq!(
        EbpfProgramType::CgroupSkb.helper_call_error(BpfHelper::GetListenerSock),
        None
    );
    assert_eq!(
        EbpfProgramType::CgroupSkb.helper_call_error(BpfHelper::SkFullsock),
        None
    );
    assert_eq!(
        EbpfProgramType::CgroupSockopt.helper_call_error(BpfHelper::TcpSock),
        None
    );
    assert_eq!(
        EbpfProgramType::SkLookup.helper_call_error(BpfHelper::SkcToTcpSock),
        None
    );
    assert_eq!(
        EbpfProgramType::Fentry.helper_call_error(BpfHelper::SkcToTcp6Sock),
        None
    );
    assert_eq!(
        EbpfProgramType::SkSkbParser.helper_call_error(BpfHelper::SkcToUnixSock),
        None
    );
    assert_eq!(
        EbpfProgramType::Fentry.helper_call_error(BpfHelper::SockFromFile),
        None
    );
    assert_eq!(
        EbpfProgramType::TpBtf.helper_call_error(BpfHelper::SockFromFile),
        None
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::TcpCheckSyncookie),
        None
    );
    assert_eq!(
        EbpfProgramType::Tc.helper_call_error(BpfHelper::TcpGenSyncookie),
        None
    );
    assert_eq!(
        EbpfProgramType::Kretprobe.helper_call_error(BpfHelper::TaskStorageGet),
        None
    );
    assert_eq!(
        EbpfProgramType::Uprobe.helper_call_error(BpfHelper::TaskStorageDelete),
        None
    );
    assert_eq!(
        EbpfProgramType::Fentry.helper_call_error(BpfHelper::TaskStorageGet),
        None
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::TaskPtRegs),
        None
    );
    assert_eq!(
        EbpfProgramType::Lsm.helper_call_error(BpfHelper::InodeStorageGet),
        None
    );
    assert_eq!(
        EbpfProgramType::Lsm.helper_call_error(BpfHelper::InodeStorageDelete),
        None
    );
    assert_eq!(
        EbpfProgramType::CgroupSock.helper_call_error(BpfHelper::SkStorageGet),
        None
    );
    assert_eq!(
        EbpfProgramType::CgroupSockopt.helper_call_error(BpfHelper::SkStorageDelete),
        None
    );
    assert_eq!(
        EbpfProgramType::Fentry.helper_call_error(BpfHelper::SkStorageGet),
        None
    );
    assert_eq!(
        EbpfProgramType::StructOps.helper_call_error(BpfHelper::SkStorageDelete),
        None
    );
}

#[test]
fn test_program_type_packet_redirect_helpers_follow_program_model() {
    assert!(matches!(
        EbpfProgramType::Xdp.packet_redirect_helper(),
        Some(BpfHelper::Redirect)
    ));
    assert!(matches!(
        EbpfProgramType::Tc.packet_redirect_helper(),
        Some(BpfHelper::Redirect)
    ));
    assert!(matches!(
        EbpfProgramType::Tc.packet_redirect_peer_helper(),
        Some(BpfHelper::RedirectPeer)
    ));
    assert!(matches!(
        EbpfProgramType::Tc.packet_redirect_neigh_helper(),
        Some(BpfHelper::RedirectNeigh)
    ));
    assert!(EbpfProgramType::Xdp.packet_redirect_peer_helper().is_none());
    assert!(EbpfProgramType::Fentry.packet_redirect_helper().is_none());
}

#[test]
fn test_program_type_packet_adjust_helpers_follow_program_model() {
    assert!(matches!(
        EbpfProgramType::Xdp.packet_adjust_helper(PacketAdjustMode::Head),
        Some(BpfHelper::XdpAdjustHead)
    ));
    assert!(matches!(
        EbpfProgramType::Xdp.packet_adjust_helper(PacketAdjustMode::Meta),
        Some(BpfHelper::XdpAdjustMeta)
    ));
    assert!(matches!(
        EbpfProgramType::Tc.packet_adjust_helper(PacketAdjustMode::Head),
        Some(BpfHelper::SkbChangeHead)
    ));
    assert!(matches!(
        EbpfProgramType::Tc.packet_adjust_helper(PacketAdjustMode::Tail),
        Some(BpfHelper::SkbChangeTail)
    ));
    assert!(matches!(
        EbpfProgramType::SkSkb.packet_adjust_helper(PacketAdjustMode::Pull),
        Some(BpfHelper::SkbPullData)
    ));
    assert!(matches!(
        EbpfProgramType::SkSkbParser.packet_adjust_helper(PacketAdjustMode::Room),
        Some(BpfHelper::SkbAdjustRoom)
    ));
    assert!(
        EbpfProgramType::Tc
            .packet_adjust_helper(PacketAdjustMode::Meta)
            .is_none()
    );
    assert!(
        EbpfProgramType::Xdp
            .packet_adjust_helper(PacketAdjustMode::Pull)
            .is_none()
    );
    assert!(
        EbpfProgramType::Fentry
            .packet_adjust_helper(PacketAdjustMode::Head)
            .is_none()
    );
}

#[test]
fn test_program_type_message_adjust_helpers_follow_program_model() {
    assert!(matches!(
        EbpfProgramType::SkMsg.message_adjust_helper(MessageAdjustMode::Apply),
        Some(BpfHelper::MsgApplyBytes)
    ));
    assert!(matches!(
        EbpfProgramType::SkMsg.message_adjust_helper(MessageAdjustMode::Cork),
        Some(BpfHelper::MsgCorkBytes)
    ));
    assert!(matches!(
        EbpfProgramType::SkMsg.message_adjust_helper(MessageAdjustMode::Pull),
        Some(BpfHelper::MsgPullData)
    ));
    assert!(matches!(
        EbpfProgramType::SkMsg.message_adjust_helper(MessageAdjustMode::Push),
        Some(BpfHelper::MsgPushData)
    ));
    assert!(matches!(
        EbpfProgramType::SkMsg.message_adjust_helper(MessageAdjustMode::Pop),
        Some(BpfHelper::MsgPopData)
    ));
    assert!(
        EbpfProgramType::Tc
            .message_adjust_helper(MessageAdjustMode::Apply)
            .is_none()
    );
}

#[test]
fn test_program_type_socket_redirect_helpers_follow_program_model() {
    assert!(matches!(
        EbpfProgramType::SkMsg.socket_redirect_helper(MapKind::SockMap),
        Some(BpfHelper::MsgRedirectMap)
    ));
    assert!(matches!(
        EbpfProgramType::SkMsg.socket_redirect_helper(MapKind::SockHash),
        Some(BpfHelper::MsgRedirectHash)
    ));
    assert!(matches!(
        EbpfProgramType::SkSkb.socket_redirect_helper(MapKind::SockMap),
        Some(BpfHelper::SkRedirectMap)
    ));
    assert!(matches!(
        EbpfProgramType::SkSkbParser.socket_redirect_helper(MapKind::SockHash),
        Some(BpfHelper::SkRedirectHash)
    ));
    assert!(
        EbpfProgramType::Xdp
            .socket_redirect_helper(MapKind::SockMap)
            .is_none()
    );
}

#[test]
fn test_program_type_helper_zero_arg_requirement_uses_program_surface() {
    assert_eq!(
        EbpfProgramType::Xdp.helper_zero_arg_requirement(BpfHelper::Redirect),
        Some((1, "helper 'bpf_redirect' requires arg1 = 0 in xdp programs"))
    );
    assert_eq!(
        EbpfProgramType::Tc.helper_zero_arg_requirement(BpfHelper::Redirect),
        None
    );
    assert_eq!(
        EbpfProgramType::Tc.helper_zero_arg_requirement(BpfHelper::SkAssign),
        Some((2, "helper 'bpf_sk_assign' requires arg2 = 0 in tc programs"))
    );
    assert_eq!(
        EbpfProgramType::SkLookup.helper_zero_arg_requirement(BpfHelper::SkAssign),
        None
    );
}

#[test]
fn test_program_type_get_socket_cookie_arg_policy_tracks_program_model() {
    assert_eq!(
        EbpfProgramType::SocketFilter.get_socket_cookie_arg_policy(),
        Some(GetSocketCookieArgPolicy::Context)
    );
    assert_eq!(
        EbpfProgramType::CgroupSock.get_socket_cookie_arg_policy(),
        Some(GetSocketCookieArgPolicy::ContextOrSocket)
    );
    assert_eq!(
        EbpfProgramType::Fentry.get_socket_cookie_arg_policy(),
        Some(GetSocketCookieArgPolicy::Socket)
    );
    assert_eq!(
        EbpfProgramType::SkLookup.get_socket_cookie_arg_policy(),
        None
    );
}

#[test]
fn test_helper_backed_ctx_field_surface_stays_within_helper_surface() {
    let programs = [
        (EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337"),
        (EbpfProgramType::Tc, "lo:ingress"),
        (EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:ingress"),
        (EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_create"),
        (EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get"),
        (EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect4"),
        (EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap"),
        (EbpfProgramType::SkSkb, "/sys/fs/bpf/demo_sockmap"),
        (EbpfProgramType::SkSkbParser, "/sys/fs/bpf/demo_sockmap"),
        (EbpfProgramType::SockOps, "/sys/fs/cgroup"),
    ];

    let helper_backed_fields = [
        (CtxField::SocketCookie, BpfHelper::GetSocketCookie),
        (CtxField::SocketUid, BpfHelper::GetSocketUid),
        (CtxField::NetnsCookie, BpfHelper::GetNetnsCookie),
    ];

    for (program_type, target) in programs {
        let ctx = ProbeContext::new(program_type, target);

        for (field, helper) in &helper_backed_fields {
            if ctx.ctx_field_access_error(&field).is_none() {
                assert!(
                    program_type.helper_call_error(*helper).is_none(),
                    "ctx.{} is available on {} but helper '{}' is rejected",
                    field.display_name(),
                    program_type.canonical_prefix(),
                    helper.name()
                );

                if *field == CtxField::SocketCookie {
                    assert!(
                        matches!(
                            program_type.get_socket_cookie_arg_policy(),
                            Some(
                                GetSocketCookieArgPolicy::Context
                                    | GetSocketCookieArgPolicy::ContextOrSocket
                            )
                        ),
                        "ctx.socket_cookie is available on {} but raw ctx is not accepted by bpf_get_socket_cookie",
                        program_type.canonical_prefix()
                    );
                }
            }
        }
    }
}

#[test]
fn test_tracing_helper_ctx_field_surface_follows_program_model() {
    for (program_type, target) in [
        (EbpfProgramType::Kprobe, "ksys_read"),
        (EbpfProgramType::Kretprobe, "ksys_read"),
        (EbpfProgramType::Uprobe, "/bin/true:main"),
        (EbpfProgramType::Uretprobe, "/bin/true:main"),
        (
            EbpfProgramType::PerfEvent,
            "software:cpu-clock:period=100000",
        ),
        (EbpfProgramType::RawTracepoint, "sched_switch"),
        (EbpfProgramType::Tracepoint, "syscalls/sys_enter_openat"),
        (EbpfProgramType::Fentry, "vfs_read"),
        (EbpfProgramType::Fexit, "vfs_read"),
        (EbpfProgramType::TpBtf, "sched_switch"),
    ] {
        let ctx = ProbeContext::new(program_type, target);
        assert!(ctx.ctx_field_access_error(&CtxField::FuncIp).is_none());
        assert!(
            ctx.ctx_field_access_error(&CtxField::AttachCookie)
                .is_none()
        );
        assert!(
            program_type
                .helper_call_error(BpfHelper::GetFuncIp)
                .is_none()
        );
        assert!(
            program_type
                .helper_call_error(BpfHelper::GetAttachCookie)
                .is_none()
        );
    }

    let xdp = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    assert!(
        xdp.ctx_field_access_error(&CtxField::FuncIp)
            .expect("expected ctx.func_ip rejection")
            .contains("ctx.func_ip is only available on kprobe")
    );
    assert!(
        xdp.ctx_field_access_error(&CtxField::AttachCookie)
            .expect("expected ctx.attach_cookie rejection")
            .contains("ctx.attach_cookie is only available on kprobe")
    );
}

#[test]
fn test_probe_context_helper_zero_arg_requirement_uses_program_type() {
    let xdp = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let tc = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let sk_lookup = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");

    assert_eq!(
        xdp.helper_zero_arg_requirement(BpfHelper::Redirect),
        Some((1, "helper 'bpf_redirect' requires arg1 = 0 in xdp programs"))
    );
    assert_eq!(tc.helper_zero_arg_requirement(BpfHelper::Redirect), None);
    assert_eq!(
        tc.helper_zero_arg_requirement(BpfHelper::SkAssign),
        Some((2, "helper 'bpf_sk_assign' requires arg2 = 0 in tc programs"))
    );
    assert_eq!(
        sk_lookup.helper_zero_arg_requirement(BpfHelper::SkAssign),
        None
    );
}

#[test]
fn test_probe_context_main_return_type_defaults_to_i64_outside_struct_ops() {
    let ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    assert_eq!(
        ctx.main_function_expected_return_type()
            .expect("non-struct_ops return contract should resolve"),
        Some(HMType::I64)
    );
}

#[test]
fn test_probe_context_kfunc_call_error_uses_sched_ext_callback_policy() {
    let dispatch = ProbeContext::new_struct_ops_callback("sched_ext_ops", "dispatch");
    let init = ProbeContext::new_struct_ops_callback("sched_ext_ops", "init");
    let select_cpu = ProbeContext::new_struct_ops_callback("sched_ext_ops", "select_cpu");

    assert_eq!(
        dispatch.kfunc_call_error("scx_bpf_create_dsq"),
        Some(
            "kfunc 'scx_bpf_create_dsq' is only valid in sleepable sched_ext_ops callbacks, not sched_ext_ops.dispatch"
                .to_string()
        )
    );
    assert!(init.kfunc_call_error("scx_bpf_create_dsq").is_none());
    assert_eq!(
        select_cpu.kfunc_call_error("scx_bpf_dispatch_nr_slots"),
        Some(
            "kfunc 'scx_bpf_dispatch_nr_slots' is only valid in sched_ext_ops.dispatch, not sched_ext_ops.select_cpu"
                .to_string()
        )
    );
}

#[test]
fn test_probe_context_socket_projection_error_uses_typed_attach_kind() {
    let post_bind4 = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:post_bind4");
    let post_bind6 = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:post_bind6");
    let sock_create = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_create");

    assert!(
        post_bind4
            .socket_projection_access_error("src_port")
            .is_none()
    );
    assert!(
        post_bind4
            .socket_projection_access_error("src_ip4")
            .is_none()
    );
    assert_eq!(
        post_bind4.socket_projection_access_error("src_ip6"),
        Some("ctx.sk.src_ip6 is only available on cgroup_sock post_bind6 hooks".to_string())
    );
    assert!(
        post_bind6
            .socket_projection_access_error("src_ip6")
            .is_none()
    );
    assert_eq!(
        post_bind6.socket_projection_access_error("src_ip4"),
        Some("ctx.sk.src_ip4 is only available on cgroup_sock post_bind4 hooks".to_string())
    );
    assert_eq!(
        sock_create.socket_projection_access_error("src_port"),
        Some(
            "ctx.sk.src_port is only available on cgroup_sock post_bind4/post_bind6 hooks"
                .to_string()
        )
    );
    assert_eq!(sock_create.socket_projection_access_error("dst_port"), None);
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
        ProgramIntrinsic::from_command_name("map-contains"),
        Some(ProgramIntrinsic::MapContains)
    );
    assert_eq!(
        ProgramIntrinsic::from_command_name("map-peek"),
        Some(ProgramIntrinsic::MapPeek)
    );
    assert_eq!(
        ProgramIntrinsic::from_command_name("map-pop"),
        Some(ProgramIntrinsic::MapPop)
    );
    assert_eq!(
        ProgramIntrinsic::from_command_name("adjust-packet"),
        Some(ProgramIntrinsic::AdjustPacket)
    );
    assert_eq!(
        ProgramIntrinsic::from_command_name("adjust-message"),
        Some(ProgramIntrinsic::AdjustMessage)
    );
    assert_eq!(
        ProgramIntrinsic::from_command_name("redirect"),
        Some(ProgramIntrinsic::Redirect)
    );
    assert_eq!(
        ProgramIntrinsic::from_command_name("redirect-map"),
        Some(ProgramIntrinsic::RedirectMap)
    );
    assert_eq!(
        ProgramIntrinsic::from_command_name("redirect-socket"),
        Some(ProgramIntrinsic::RedirectSocket)
    );
    assert_eq!(
        ProgramIntrinsic::from_command_name("assign-socket"),
        Some(ProgramIntrinsic::AssignSocket)
    );
    assert_eq!(
        ProgramIntrinsic::from_command_name("tail-call"),
        Some(ProgramIntrinsic::TailCall)
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
        ProgramIntrinsic::AdjustPacket.required_capability(),
        ProgramCapability::HelperCalls
    );
    assert_eq!(
        ProgramIntrinsic::AdjustMessage.required_capability(),
        ProgramCapability::HelperCalls
    );
    assert_eq!(
        ProgramIntrinsic::Redirect.required_capability(),
        ProgramCapability::HelperCalls
    );
    assert_eq!(
        ProgramIntrinsic::RedirectMap.required_capability(),
        ProgramCapability::HelperCalls
    );
    assert_eq!(
        ProgramIntrinsic::RedirectSocket.required_capability(),
        ProgramCapability::HelperCalls
    );
    assert_eq!(
        ProgramIntrinsic::AssignSocket.required_capability(),
        ProgramCapability::HelperCalls
    );
    assert_eq!(
        ProgramIntrinsic::TailCall.required_capability(),
        ProgramCapability::TailCalls
    );
    assert_eq!(
        ProgramIntrinsic::GlobalGet.required_capability(),
        ProgramCapability::Globals
    );
    assert_eq!(
        ProgramIntrinsic::MapPush.required_capability(),
        ProgramCapability::GenericMaps
    );
    assert_eq!(
        ProgramIntrinsic::MapContains.required_capability(),
        ProgramCapability::GenericMaps
    );
    assert_eq!(
        ProgramIntrinsic::MapPeek.required_capability(),
        ProgramCapability::GenericMaps
    );
    assert_eq!(
        ProgramIntrinsic::MapPop.required_capability(),
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
fn test_program_type_resolves_xdp_ifindex_alias() {
    assert_eq!(
        EbpfProgramType::Xdp
            .resolve_ctx_field_name("ifindex")
            .expect("xdp ifindex alias should resolve"),
        CtxField::IngressIfindex
    );
}

#[test]
fn test_program_type_resolves_skb_ifindex_alias() {
    assert_eq!(
        EbpfProgramType::SocketFilter
            .resolve_ctx_field_name("ifindex")
            .expect("socket_filter ifindex alias should resolve"),
        CtxField::Ifindex
    );
    assert_eq!(
        EbpfProgramType::Tc
            .resolve_ctx_field_name("ifindex")
            .expect("tc ifindex alias should resolve"),
        CtxField::Ifindex
    );
}

#[test]
fn test_program_type_resolves_program_specific_context_aliases() {
    assert_eq!(
        EbpfProgramType::SkMsg
            .resolve_ctx_field_name("size")
            .expect("sk_msg size alias should resolve"),
        CtxField::PacketLen
    );
    assert_eq!(
        EbpfProgramType::CgroupSockopt
            .resolve_ctx_field_name("retval")
            .expect("cgroup_sockopt retval alias should resolve"),
        CtxField::SockoptRetval
    );
    assert_eq!(
        EbpfProgramType::Kretprobe
            .resolve_ctx_field_name("retval")
            .expect("kretprobe retval should keep return-probe meaning"),
        CtxField::RetVal
    );
}

#[test]
fn test_program_type_resolves_tracepoint_specific_field_names() {
    assert_eq!(
        EbpfProgramType::Tracepoint
            .resolve_ctx_field_name("filename")
            .expect("tracepoint field should resolve"),
        CtxField::TracepointField("filename".to_string())
    );
    assert_eq!(
        EbpfProgramType::Tracepoint
            .resolve_ctx_field_name("ifindex")
            .expect("tracepoint ifindex should stay tracepoint-scoped"),
        CtxField::TracepointField("ifindex".to_string())
    );
}

#[test]
fn test_program_type_resolves_tracepoint_builtin_alias_names() {
    assert_eq!(
        EbpfProgramType::Kprobe
            .resolve_ctx_field_name("tid")
            .expect("kprobe tid should resolve as a pid alias"),
        CtxField::Pid
    );
    assert_eq!(
        EbpfProgramType::Kprobe
            .resolve_ctx_field_name("tgid")
            .expect("kprobe tgid should resolve as the thread-group id"),
        CtxField::Tgid
    );
    assert_eq!(
        EbpfProgramType::Tracepoint
            .resolve_ctx_field_name("tid")
            .expect("tracepoint tid should preserve builtin alias"),
        CtxField::Pid
    );
    assert_eq!(
        EbpfProgramType::Tracepoint
            .resolve_ctx_field_name("tgid")
            .expect("tracepoint tgid should preserve builtin alias"),
        CtxField::Tgid
    );
    assert_eq!(
        EbpfProgramType::Tracepoint
            .resolve_ctx_field_name("arg3")
            .expect("tracepoint arg3 should preserve builtin arg"),
        CtxField::Arg(3)
    );
    assert_eq!(
        EbpfProgramType::Tracepoint
            .resolve_ctx_field_name("numa_node_id")
            .expect("tracepoint numa_node_id should preserve builtin alias"),
        CtxField::NumaNode
    );
}

#[test]
fn test_program_type_resolves_task_field_name() {
    assert_eq!(
        EbpfProgramType::Kprobe
            .resolve_ctx_field_name("task")
            .expect("kprobe task should resolve"),
        CtxField::Task
    );
}

#[test]
fn test_cgroup_sock_addr_tuple_aliases_use_attach_shape() {
    let connect4 =
        ProgramSpec::parse("cgroup_sock_addr:/sys/fs/cgroup:connect4").expect("connect4 spec");
    assert_eq!(
        connect4.cgroup_sock_addr_tuple_alias_field(&CtxField::RemoteIp4),
        Some(CtxField::UserIp4)
    );
    assert_eq!(
        connect4.cgroup_sock_addr_tuple_alias_field(&CtxField::RemotePort),
        Some(CtxField::UserPort)
    );
    assert_eq!(
        connect4.cgroup_sock_addr_tuple_alias_field(&CtxField::LocalIp4),
        None
    );

    let sendmsg4 =
        ProgramSpec::parse("cgroup_sock_addr:/sys/fs/cgroup:sendmsg4").expect("sendmsg4 spec");
    assert_eq!(
        sendmsg4.cgroup_sock_addr_tuple_alias_field(&CtxField::RemoteIp4),
        Some(CtxField::UserIp4)
    );
    assert_eq!(
        sendmsg4.cgroup_sock_addr_tuple_alias_field(&CtxField::LocalIp4),
        Some(CtxField::MsgSrcIp4)
    );
    assert_eq!(
        sendmsg4.cgroup_sock_addr_tuple_alias_field(&CtxField::LocalPort),
        None
    );

    let bind6 = ProgramSpec::parse("cgroup_sock_addr:/sys/fs/cgroup:bind6").expect("bind6 spec");
    assert_eq!(
        bind6.cgroup_sock_addr_tuple_alias_field(&CtxField::LocalIp6),
        Some(CtxField::UserIp6)
    );
    assert_eq!(
        bind6.cgroup_sock_addr_tuple_alias_field(&CtxField::LocalPort),
        Some(CtxField::UserPort)
    );
    assert_eq!(
        bind6.cgroup_sock_addr_tuple_alias_field(&CtxField::RemoteIp6),
        None
    );

    let recvmsg6 =
        ProgramSpec::parse("cgroup_sock_addr:/sys/fs/cgroup:recvmsg6").expect("recvmsg6 spec");
    assert_eq!(
        recvmsg6.cgroup_sock_addr_tuple_alias_field(&CtxField::RemoteIp6),
        Some(CtxField::UserIp6)
    );
    assert_eq!(
        recvmsg6.cgroup_sock_addr_tuple_alias_field(&CtxField::LocalIp6),
        None
    );
}

#[test]
fn test_program_type_context_layouts_use_program_model_table() {
    assert_eq!(
        EbpfProgramType::Xdp.data_meta_context_kind(),
        Some(PacketContextKind::XdpMd)
    );
    assert_eq!(
        EbpfProgramType::Tc.data_meta_context_kind(),
        Some(PacketContextKind::SkBuff)
    );
    assert_eq!(
        EbpfProgramType::SocketFilter.socket_ref_context_layout(),
        Some(SocketContextLayout::SkBuff)
    );
    assert!(EbpfProgramType::SocketFilter.supports_netns_cookie_ctx_field());
    assert_eq!(
        EbpfProgramType::CgroupSkb.socket_family_context_layout(),
        Some(SocketContextLayout::SkBuff)
    );
    assert!(EbpfProgramType::CgroupSkb.supports_socket_uid_ctx_field());
    assert_eq!(
        EbpfProgramType::CgroupSock.sock_state_context_layout(),
        Some(SocketContextLayout::CgroupSock)
    );
    assert!(EbpfProgramType::CgroupSock.supports_socket_cookie_ctx_field());
    assert_eq!(
        EbpfProgramType::SkLookup.ingress_ifindex_context_layout(),
        Some(IngressIfindexContextLayout::SkLookup)
    );
    assert!(EbpfProgramType::SkLookup.supports_lookup_cookie_ctx_field());
    assert!(!EbpfProgramType::SkLookup.supports_netns_cookie_ctx_field());
    assert_eq!(EbpfProgramType::SkMsg.protocol_context_layout(), None);
    assert!(EbpfProgramType::SkMsg.supports_netns_cookie_ctx_field());
    assert_eq!(
        EbpfProgramType::CgroupSockAddr.sock_type_context_layout(),
        Some(SocketContextLayout::SockAddr)
    );
    assert_eq!(EbpfProgramType::Kprobe.socket_ref_context_layout(), None);
    assert!(!EbpfProgramType::Kprobe.supports_socket_cookie_ctx_field());
}

#[test]
fn test_program_type_resolves_sock_ops_field_names() {
    assert_eq!(
        EbpfProgramType::SockOps
            .resolve_ctx_field_name("op")
            .expect("sock_ops op should resolve"),
        CtxField::SockOp
    );
}

#[test]
fn test_program_spec_tracepoint_ctx_name_resolution_uses_program_model() {
    let spec = ProgramSpec::parse("tracepoint:syscalls/sys_enter_openat")
        .expect("tracepoint program spec should parse");

    assert_eq!(
        spec.resolve_ctx_field_name("op")
            .expect("tracepoint op should stay tracepoint-scoped"),
        CtxField::TracepointField("op".to_string())
    );
    assert_eq!(
        spec.resolve_ctx_field_name("arg3")
            .expect("tracepoint arg3 should preserve builtin arg"),
        CtxField::Arg(3)
    );
    assert_eq!(
        spec.resolve_ctx_field_name("arg_count")
            .expect("tracepoint arg_count should preserve builtin name"),
        CtxField::ArgCount
    );
}

#[test]
fn test_probe_context_prefers_tracepoint_fields_over_reserved_sock_ops_names() {
    let ctx = ProbeContext::new(EbpfProgramType::Tracepoint, "syscalls/sys_enter_openat");

    assert_eq!(
        ctx.resolve_ctx_field_name("op")
            .expect("tracepoint op should stay tracepoint-scoped"),
        CtxField::TracepointField("op".to_string())
    );
    assert_eq!(
        ctx.resolve_ctx_field_name("args")
            .expect("tracepoint args should stay tracepoint-scoped"),
        CtxField::TracepointField("args".to_string())
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
fn test_probe_context_arg_count_field_surface_follows_program_model() {
    for program_type in [
        EbpfProgramType::Fentry,
        EbpfProgramType::Fexit,
        EbpfProgramType::TpBtf,
        EbpfProgramType::Lsm,
    ] {
        let ctx = ProbeContext::new(program_type, "do_sys_openat2");
        assert!(
            ctx.ctx_field_access_error(&CtxField::ArgCount).is_none(),
            "ctx.arg_count should be allowed on {program_type:?}"
        );
    }

    let xdp = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let err = xdp
        .ctx_field_access_error(&CtxField::ArgCount)
        .expect("expected arg_count rejection on xdp");
    assert!(err.contains("ctx.arg_count is only available on BTF-backed tracing contexts"));
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
fn test_probe_context_allows_arg_on_perf_event() {
    let ctx = ProbeContext::new(
        EbpfProgramType::PerfEvent,
        "software:cpu-clock:period=100000",
    );
    assert!(ctx.ctx_field_access_error(&CtxField::Arg(0)).is_none());
}

#[test]
fn test_probe_context_resolves_sock_ops_store_targets() {
    let ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
    assert_eq!(
        ctx.resolve_ctx_store_target("reply", None)
            .expect("sock_ops reply target should resolve"),
        CtxStoreTarget::SockOpsReply
    );
    assert_eq!(
        ctx.resolve_ctx_store_target("replylong", Some(2))
            .expect("sock_ops replylong target should resolve"),
        CtxStoreTarget::SockOpsReplyLong(2)
    );
    assert_eq!(
        ctx.resolve_ctx_store_target("cb_flags", None)
            .expect("sock_ops cb_flags target should resolve"),
        CtxStoreTarget::SockOpsCbFlags
    );
    assert_eq!(
        ctx.resolve_ctx_store_target("sk_txhash", None)
            .expect("sock_ops sk_txhash target should resolve"),
        CtxStoreTarget::SockOpsSkTxhash
    );
}

#[test]
fn test_probe_context_validates_sock_ops_store_targets() {
    let ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
    assert!(
        ctx.validate_ctx_store_target(&CtxStoreTarget::SockOpsReply)
            .is_ok()
    );
    assert!(
        ctx.validate_ctx_store_target(&CtxStoreTarget::SockOpsReplyLong(2))
            .is_ok()
    );
    assert!(
        ctx.validate_ctx_store_target(&CtxStoreTarget::SockOpsCbFlags)
            .is_ok()
    );
    assert!(
        ctx.validate_ctx_store_target(&CtxStoreTarget::SockOpsSkTxhash)
            .is_ok()
    );
}

#[test]
fn test_probe_context_rejects_sock_ops_store_target_on_non_sock_ops_program() {
    let ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let err = ctx
        .validate_ctx_store_target(&CtxStoreTarget::SockOpsReply)
        .expect_err("sock_ops store target should be rejected outside sock_ops");
    assert!(
        err.to_string()
            .contains("writable sock_ops reply fields are only supported on sock_ops programs")
    );

    let err = ctx
        .validate_ctx_store_target(&CtxStoreTarget::SockOpsCbFlags)
        .expect_err("sock_ops cb_flags store target should be rejected outside sock_ops");
    assert!(
        err.to_string()
            .contains("ctx.cb_flags is only available on sock_ops programs")
    );

    let err = ctx
        .validate_ctx_store_target(&CtxStoreTarget::SockOpsSkTxhash)
        .expect_err("sock_ops sk_txhash store target should be rejected outside sock_ops");
    assert!(
        err.to_string()
            .contains("ctx.sk_txhash is only available on sock_ops programs")
    );
}

#[test]
fn test_program_type_base_ctx_store_target_error_follows_context_family() {
    assert!(
        EbpfProgramType::SockOps
            .base_ctx_store_target_error(&CtxStoreTarget::SockOpsReply)
            .is_none()
    );
    assert!(
        EbpfProgramType::SkMsg
            .base_ctx_store_target_error(&CtxStoreTarget::SockOpsReply)
            .unwrap()
            .contains("writable sock_ops reply fields are only supported on sock_ops programs")
    );
    assert!(
        EbpfProgramType::SkMsg
            .base_ctx_store_target_error(&CtxStoreTarget::SockOpsCbFlags)
            .unwrap()
            .contains("writable sock_ops cb_flags is only supported on sock_ops programs")
    );
    assert!(
        EbpfProgramType::SkMsg
            .base_ctx_store_target_error(&CtxStoreTarget::SockOpsSkTxhash)
            .unwrap()
            .contains("writable sock_ops sk_txhash is only supported on sock_ops programs")
    );
}

#[test]
fn test_probe_context_rejects_sock_ops_replylong_store_without_fixed_index() {
    let ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
    let err = ctx
        .resolve_ctx_store_target("replylong", None)
        .expect_err("replylong without index should be rejected");
    assert!(err.contains("requires a fixed index"));
}

#[test]
fn test_probe_context_resolves_cgroup_sysctl_file_pos_store_target() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSysctl, "/sys/fs/cgroup");
    assert_eq!(
        ctx.resolve_ctx_store_target("file_pos", None)
            .expect("cgroup_sysctl file_pos target should resolve"),
        CtxStoreTarget::SysctlFilePos
    );
    assert!(
        ctx.validate_ctx_store_target(&CtxStoreTarget::SysctlFilePos)
            .is_ok()
    );
}

#[test]
fn test_probe_context_resolves_skb_tstamp_store_target_on_tc() {
    let ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    assert_eq!(
        ctx.resolve_ctx_store_target("tstamp", None)
            .expect("tc tstamp target should resolve"),
        CtxStoreTarget::SkbTstamp
    );
    assert!(
        ctx.validate_ctx_store_target(&CtxStoreTarget::SkbTstamp)
            .is_ok()
    );
}

#[test]
fn test_probe_context_resolves_skb_tstamp_store_target_on_cgroup_skb_egress() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:egress");
    assert_eq!(
        ctx.resolve_ctx_store_target("tstamp", None)
            .expect("cgroup_skb egress tstamp target should resolve"),
        CtxStoreTarget::SkbTstamp
    );
    assert!(
        ctx.validate_ctx_store_target(&CtxStoreTarget::SkbTstamp)
            .is_ok()
    );
}

#[test]
fn test_probe_context_resolves_skb_mark_store_target_on_tc() {
    let ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    assert_eq!(
        ctx.resolve_ctx_store_target("mark", None)
            .expect("tc mark target should resolve"),
        CtxStoreTarget::SkbMark
    );
    assert!(
        ctx.validate_ctx_store_target(&CtxStoreTarget::SkbMark)
            .is_ok()
    );
}

#[test]
fn test_probe_context_resolves_skb_mark_store_target_on_cgroup_skb() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:ingress");
    assert_eq!(
        ctx.resolve_ctx_store_target("mark", None)
            .expect("cgroup_skb mark target should resolve"),
        CtxStoreTarget::SkbMark
    );
    assert!(
        ctx.validate_ctx_store_target(&CtxStoreTarget::SkbMark)
            .is_ok()
    );
}

#[test]
fn test_probe_context_resolves_skb_cb_store_target_on_tc() {
    let ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    assert_eq!(
        ctx.resolve_ctx_store_target("cb", Some(2))
            .expect("tc cb target should resolve"),
        CtxStoreTarget::SkbCbWord(2)
    );
    assert!(
        ctx.validate_ctx_store_target(&CtxStoreTarget::SkbCbWord(2))
            .is_ok()
    );
}

#[test]
fn test_probe_context_resolves_skb_cb_store_target_on_socket_filter() {
    let ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");
    assert_eq!(
        ctx.resolve_ctx_store_target("cb", Some(2))
            .expect("socket_filter cb target should resolve"),
        CtxStoreTarget::SkbCbWord(2)
    );
    assert!(
        ctx.validate_ctx_store_target(&CtxStoreTarget::SkbCbWord(2))
            .is_ok()
    );
}

#[test]
fn test_probe_context_resolves_skb_priority_and_tc_index_store_targets_on_sk_skb_programs() {
    let sk_skb = ProbeContext::new(EbpfProgramType::SkSkb, "/sys/fs/bpf/demo_sockmap");
    assert_eq!(
        sk_skb
            .resolve_ctx_store_target("tc_index", None)
            .expect("sk_skb tc_index target should resolve"),
        CtxStoreTarget::SkbTcIndex
    );
    assert!(
        sk_skb
            .validate_ctx_store_target(&CtxStoreTarget::SkbTcIndex)
            .is_ok()
    );

    let sk_skb_parser = ProbeContext::new(EbpfProgramType::SkSkbParser, "/sys/fs/bpf/demo_sockmap");
    assert_eq!(
        sk_skb_parser
            .resolve_ctx_store_target("priority", None)
            .expect("sk_skb_parser priority target should resolve"),
        CtxStoreTarget::SkbPriority
    );
    assert!(
        sk_skb_parser
            .validate_ctx_store_target(&CtxStoreTarget::SkbPriority)
            .is_ok()
    );
}

#[test]
fn test_probe_context_rejects_skb_cb_store_target_without_index_on_tc() {
    let ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = ctx
        .resolve_ctx_store_target("cb", None)
        .expect_err("skb cb store target without index should be rejected");
    assert!(err.contains("requires a fixed index"));
}

#[test]
fn test_probe_context_rejects_skb_tstamp_store_target_on_non_skb_program() {
    let ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let err = ctx
        .validate_ctx_store_target(&CtxStoreTarget::SkbTstamp)
        .expect_err("skb tstamp store target should be rejected outside skb-backed contexts");
    assert!(
        err.to_string().contains(
            "ctx.tstamp is only available on socket_filter, tc, cgroup_skb, sk_skb, and sk_skb_parser programs"
        )
    );
}

#[test]
fn test_probe_context_rejects_skb_tstamp_store_target_on_socket_filter() {
    let ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");
    let err = ctx
        .validate_ctx_store_target(&CtxStoreTarget::SkbTstamp)
        .expect_err("skb tstamp store target should be rejected outside tc");
    assert!(
        err.to_string()
            .contains("ctx.tstamp is only available on tc and cgroup_skb programs")
    );
}

#[test]
fn test_probe_context_rejects_skb_tstamp_store_target_on_cgroup_skb_ingress() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:ingress");
    let err = ctx
        .resolve_ctx_store_target("tstamp", None)
        .expect_err("skb tstamp store target should be rejected on cgroup_skb ingress");
    assert!(err.contains("ctx.tstamp is only writable on tc and cgroup_skb:egress programs"));
    let err = ctx
        .validate_ctx_store_target(&CtxStoreTarget::SkbTstamp)
        .expect_err("skb tstamp store target should be rejected on cgroup_skb ingress");
    assert!(
        err.to_string()
            .contains("ctx.tstamp is only writable on tc and cgroup_skb:egress programs")
    );
}

#[test]
fn test_probe_context_rejects_skb_mark_store_target_on_socket_filter() {
    let ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");
    let err = ctx
        .validate_ctx_store_target(&CtxStoreTarget::SkbMark)
        .expect_err("skb mark store target should be rejected outside tc");
    assert!(
        err.to_string()
            .contains("ctx.mark is only writable on tc and cgroup_skb programs")
    );
}

#[test]
fn test_probe_context_rejects_skb_cb_store_target_without_index_on_socket_filter() {
    let ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");
    let err = ctx
        .resolve_ctx_store_target("cb", None)
        .expect_err("skb cb store target without index should be rejected");
    assert!(err.contains("requires a fixed index"));
}

#[test]
fn test_probe_context_rejects_cgroup_sysctl_file_pos_store_target_on_non_sysctl_program() {
    let ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let err = ctx
        .validate_ctx_store_target(&CtxStoreTarget::SysctlFilePos)
        .expect_err("cgroup_sysctl file_pos store target should be rejected outside cgroup_sysctl");
    assert!(
        err.to_string()
            .contains("ctx.file_pos is only available on cgroup_sysctl programs")
    );
}

#[test]
fn test_probe_context_rejects_cgroup_sysctl_write_store_target_as_read_only() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSysctl, "/sys/fs/cgroup");
    let err = ctx
        .resolve_ctx_store_target("write", None)
        .expect_err("cgroup_sysctl write store target should be rejected as read-only");
    assert!(err.contains("ctx.write is read-only"));
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
    assert!(ctx.ctx_field_access_error(&CtxField::NumaNode).is_none());
    for field in [
        CtxField::Timestamp,
        CtxField::BootTimestamp,
        CtxField::CoarseTimestamp,
        CtxField::TaiTimestamp,
        CtxField::Jiffies,
    ] {
        assert!(ctx.ctx_field_access_error(&field).is_none());
    }
}

#[test]
fn test_probe_context_rejects_numa_node_on_struct_ops() {
    let ctx = ProbeContext::new_struct_ops_callback("sched_ext_ops", "select_cpu");
    let err = ctx
        .ctx_field_access_error(&CtxField::NumaNode)
        .expect("expected struct_ops numa_node access error");
    assert!(err.contains("ctx.numa_node is not available on struct_ops programs"));
}

#[test]
fn test_probe_context_allows_xdp_md_scalar_fields_on_xdp() {
    let ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    assert!(ctx.ctx_field_access_error(&CtxField::PacketLen).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::XdpBuffLen).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Data).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::DataMeta).is_none());
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
fn test_probe_context_rejects_xdp_buff_len_on_non_xdp() {
    let ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = ctx
        .ctx_field_access_error(&CtxField::XdpBuffLen)
        .expect("expected non-xdp xdp_buff_len access error");
    assert!(err.contains("ctx.xdp_buff_len is only available on xdp programs"));
}

#[test]
fn test_probe_context_allows_packet_fields_on_tc() {
    let ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    assert!(ctx.ctx_field_access_error(&CtxField::PacketLen).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::PktType).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::DataMeta).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::QueueMapping)
            .is_none()
    );
    assert!(ctx.ctx_field_access_error(&CtxField::EthProtocol).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Protocol).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::VlanPresent).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::VlanTci).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::VlanProto).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::SkbCb).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::TcClassid).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::NapiId).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::WireLen).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::GsoSegs).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::GsoSize).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Tstamp).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::TstampType).is_none());
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
fn test_probe_context_allows_tc_egress_helper_backed_ctx_fields_on_tc_egress() {
    let ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:egress");
    for field in [
        CtxField::CgroupClassid,
        CtxField::RouteRealm,
        CtxField::SkbCgroupId,
    ] {
        assert!(ctx.ctx_field_access_error(&field).is_none());
    }
}

#[test]
fn test_probe_context_rejects_tc_egress_helper_backed_ctx_fields_on_tc_ingress() {
    let ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    for field in [
        CtxField::CgroupClassid,
        CtxField::RouteRealm,
        CtxField::SkbCgroupId,
    ] {
        let err = ctx
            .ctx_field_access_error(&field)
            .expect("expected tc ingress access error");
        assert!(err.contains("is only available on tc egress programs"));
    }
}

#[test]
fn test_probe_context_rejects_tc_egress_helper_backed_ctx_fields_on_non_tc() {
    let ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let err = ctx
        .ctx_field_access_error(&CtxField::CgroupClassid)
        .expect("expected non-tc access error");
    assert!(err.contains("ctx.cgroup_classid is only available on tc egress programs"));
}

#[test]
fn test_probe_context_allows_csum_level_on_supported_skb_helper_programs() {
    for ctx in [
        ProbeContext::new(EbpfProgramType::Tc, "lo:ingress"),
        ProbeContext::new(EbpfProgramType::SkSkb, "/sys/fs/bpf/demo_sockmap"),
        ProbeContext::new(EbpfProgramType::SkSkbParser, "/sys/fs/bpf/demo_sockmap"),
    ] {
        assert!(ctx.ctx_field_access_error(&CtxField::CsumLevel).is_none());
        assert!(ctx.ctx_field_access_error(&CtxField::HashRecalc).is_none());
    }
}

#[test]
fn test_probe_context_rejects_csum_level_on_unsupported_skb_program() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:egress");
    let err = ctx
        .ctx_field_access_error(&CtxField::CsumLevel)
        .expect("expected unsupported csum_level access error");
    assert!(
        err.contains("ctx.csum_level is only available on tc, sk_skb, and sk_skb_parser programs")
    );

    let err = ctx
        .ctx_field_access_error(&CtxField::HashRecalc)
        .expect("expected unsupported hash_recalc access error");
    assert!(
        err.contains("ctx.hash_recalc is only available on tc, sk_skb, and sk_skb_parser programs")
    );
}

#[test]
fn test_probe_context_rejects_data_meta_on_cgroup_skb() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:egress");
    let err = ctx
        .ctx_field_access_error(&CtxField::DataMeta)
        .expect("expected cgroup_skb data_meta access error");
    assert!(err.contains("ctx.data_meta is only available on xdp and tc programs"));
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
    assert!(
        ctx.ctx_field_access_error(&CtxField::TcClassid)
            .expect("expected cgroup_skb tc_classid access error")
            .contains("ctx.tc_classid is only available on tc programs")
    );
    assert!(ctx.ctx_field_access_error(&CtxField::NapiId).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::WireLen)
            .expect("expected cgroup_skb wire_len access error")
            .contains("ctx.wire_len is only available on tc programs")
    );
    assert!(ctx.ctx_field_access_error(&CtxField::GsoSegs).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::GsoSize).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Tstamp).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::TstampType)
            .expect("expected cgroup_skb tstamp_type access error")
            .contains("ctx.tstamp_type is only available on tc programs")
    );
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
    assert!(ctx.ctx_field_access_error(&CtxField::Family).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::RemoteIp4).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::RemoteIp6).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::RemotePort).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::LocalIp4).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::LocalIp6).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::LocalPort).is_none());
}

#[test]
fn test_probe_context_rejects_direct_socket_fields_on_socket_filter_and_tc() {
    let socket_filter = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");
    let tc = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");

    assert!(
        socket_filter
            .ctx_field_access_error(&CtxField::Family)
            .expect("expected socket_filter family access error")
            .contains(
                "ctx.family is only available on cgroup_skb, cgroup_sock, cgroup_sock_addr, sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs"
            )
    );
    assert!(
        socket_filter
            .ctx_field_access_error(&CtxField::RemotePort)
            .expect("expected socket_filter remote_port access error")
            .contains(
                "ctx.remote_port is only available on cgroup_skb, sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs"
            )
    );
    assert!(
        tc.ctx_field_access_error(&CtxField::Family)
            .expect("expected tc family access error")
            .contains(
                "ctx.family is only available on cgroup_skb, cgroup_sock, cgroup_sock_addr, sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs"
            )
    );
    assert!(
        tc.ctx_field_access_error(&CtxField::RemotePort)
            .expect("expected tc remote_port access error")
            .contains(
                "ctx.remote_port is only available on cgroup_skb, sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs"
            )
    );
}

#[test]
fn test_probe_context_allows_sock_fields_on_cgroup_sock() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_create");
    assert!(ctx.ctx_field_access_error(&CtxField::Socket).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Family).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::SockType).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Protocol).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::RemoteIp4).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::RemoteIp6).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::RemotePort).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::BoundDevIf).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::SockMark).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::SockPriority)
            .is_none()
    );
    assert!(ctx.ctx_field_access_error(&CtxField::SockState).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::SockRxQueueMapping)
            .is_none()
    );
}

#[test]
fn test_probe_context_rejects_create_release_only_direct_fields_on_cgroup_sock_post_bind() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:post_bind4");

    let bound_dev_if = ctx
        .ctx_field_access_error(&CtxField::BoundDevIf)
        .expect("expected cgroup_sock post_bind bound_dev_if access rejection");
    assert!(bound_dev_if.contains("cgroup_sock sock_create/sock_release"));

    let mark = ctx
        .ctx_field_access_error(&CtxField::SockMark)
        .expect("expected cgroup_sock post_bind mark access rejection");
    assert!(mark.contains("cgroup_sock sock_create/sock_release"));

    let priority = ctx
        .ctx_field_access_error(&CtxField::SockPriority)
        .expect("expected cgroup_sock post_bind priority access rejection");
    assert!(priority.contains("cgroup_sock sock_create/sock_release"));
}

#[test]
fn test_probe_context_rejects_post_bind_only_direct_local_fields_on_cgroup_sock_create() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_create");

    let local_ip4 = ctx
        .ctx_field_access_error(&CtxField::LocalIp4)
        .expect("expected cgroup_sock sock_create local_ip4 access rejection");
    assert!(local_ip4.contains("cgroup_sock post_bind4"));

    let local_ip6 = ctx
        .ctx_field_access_error(&CtxField::LocalIp6)
        .expect("expected cgroup_sock sock_create local_ip6 access rejection");
    assert!(local_ip6.contains("cgroup_sock post_bind6"));

    let local_port = ctx
        .ctx_field_access_error(&CtxField::LocalPort)
        .expect("expected cgroup_sock sock_create local_port access rejection");
    assert!(local_port.contains("cgroup_sock post_bind4/post_bind6"));
}

#[test]
fn test_probe_context_allows_family_specific_direct_local_fields_on_cgroup_sock_post_bind() {
    let post_bind4 = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:post_bind4");
    let post_bind6 = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:post_bind6");

    assert!(
        post_bind4
            .ctx_field_access_error(&CtxField::LocalIp4)
            .is_none()
    );
    assert!(
        post_bind4
            .ctx_field_access_error(&CtxField::LocalPort)
            .is_none()
    );
    assert!(
        post_bind4
            .ctx_field_access_error(&CtxField::LocalIp6)
            .expect("expected cgroup_sock post_bind4 local_ip6 rejection")
            .contains("cgroup_sock post_bind6")
    );

    assert!(
        post_bind6
            .ctx_field_access_error(&CtxField::LocalIp6)
            .is_none()
    );
    assert!(
        post_bind6
            .ctx_field_access_error(&CtxField::LocalPort)
            .is_none()
    );
    assert!(
        post_bind6
            .ctx_field_access_error(&CtxField::LocalIp4)
            .expect("expected cgroup_sock post_bind6 local_ip4 rejection")
            .contains("cgroup_sock post_bind4")
    );
}

#[test]
fn test_probe_context_models_raw_context_pointer_aliases() {
    let cgroup_sock = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_create");
    let cgroup_sockopt = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");

    assert!(EbpfProgramType::CgroupSock.ctx_field_is_raw_context_pointer(&CtxField::Context));
    assert!(EbpfProgramType::CgroupSock.ctx_field_is_raw_context_pointer(&CtxField::Socket));
    assert!(!EbpfProgramType::CgroupSockopt.ctx_field_is_raw_context_pointer(&CtxField::Socket));
    assert!(cgroup_sock.ctx_field_is_raw_context_pointer(&CtxField::Context));
    assert!(cgroup_sock.ctx_field_is_raw_context_pointer(&CtxField::Socket));
    assert!(!cgroup_sock.ctx_field_is_raw_context_pointer(&CtxField::Family));
    assert!(!cgroup_sockopt.ctx_field_is_raw_context_pointer(&CtxField::Socket));
}

#[test]
fn test_probe_context_allows_sock_addr_fields_on_cgroup_sock_addr() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect4");
    assert!(ctx.ctx_field_access_error(&CtxField::Socket).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::UserFamily).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::UserIp4).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::UserPort).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Family).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::SockType).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Protocol).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::RemoteIp4).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::RemotePort).is_none());
}

#[test]
fn test_probe_context_allows_local_tuple_aliases_on_bind_sock_addr_hooks() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:bind4");
    assert!(ctx.ctx_field_access_error(&CtxField::LocalIp4).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::LocalPort).is_none());
}

#[test]
fn test_probe_context_rejects_wrong_tuple_side_on_sock_addr_hooks() {
    let connect = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect4");
    let bind = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:bind4");

    assert!(
        connect
            .ctx_field_access_error(&CtxField::LocalIp4)
            .expect("expected connect4 local tuple access error")
            .contains("bind4/bind6, getsockname4/getsockname6, and sendmsg4/sendmsg6")
    );
    assert!(
        bind.ctx_field_access_error(&CtxField::RemoteIp4)
            .expect("expected bind4 remote tuple access error")
            .contains("connect4/connect6, getpeername4/getpeername6, sendmsg4/sendmsg6, and recvmsg4/recvmsg6")
    );
}

#[test]
fn test_probe_context_allows_tuple_aliases_on_sendmsg_sock_addr_hooks() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:sendmsg4");
    assert!(ctx.ctx_field_access_error(&CtxField::RemoteIp4).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::RemotePort).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::LocalIp4).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::LocalPort)
            .expect("expected sendmsg4 local_port access error")
            .contains("bind4/bind6 and getsockname4/getsockname6")
    );
}

#[test]
fn test_probe_context_allows_remote_tuple_aliases_on_recvmsg_sock_addr_hooks() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:recvmsg4");
    assert!(ctx.ctx_field_access_error(&CtxField::RemoteIp4).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::RemotePort).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::LocalIp4)
            .expect("expected recvmsg4 local_ip4 access error")
            .contains("bind4/bind6, getsockname4/getsockname6, and sendmsg4/sendmsg6")
    );
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
    assert!(ctx.ctx_field_access_error(&CtxField::Socket).is_none());
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
    assert!(
        ctx.ctx_field_access_error(&CtxField::TcClassid)
            .expect("expected socket_filter tc_classid access error")
            .contains("ctx.tc_classid is only available on tc programs")
    );
    assert!(ctx.ctx_field_access_error(&CtxField::NapiId).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::WireLen)
            .expect("expected socket_filter wire_len access error")
            .contains("ctx.wire_len is only available on tc programs")
    );
    assert!(ctx.ctx_field_access_error(&CtxField::GsoSegs).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::GsoSize).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::Tstamp)
            .expect("expected socket_filter tstamp access error")
            .contains("ctx.tstamp is only available on tc and cgroup_skb programs")
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::TstampType)
            .expect("expected socket_filter tstamp_type access error")
            .contains("ctx.tstamp_type is only available on tc programs")
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::Hwtstamp)
            .expect("expected socket_filter hwtstamp access error")
            .contains("ctx.hwtstamp is only available on tc and cgroup_skb programs")
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::Data)
            .expect("expected socket_filter data access error")
            .contains("ctx.data is not available on socket_filter programs")
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::DataEnd)
            .expect("expected socket_filter data_end access error")
            .contains("ctx.data_end is not available on socket_filter programs")
    );
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
    assert!(ctx.ctx_field_access_error(&CtxField::Socket).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::SocketCookie)
            .is_none()
    );
}

#[test]
fn test_probe_context_allows_socket_field_on_skb_backed_packet_programs() {
    let socket_filter = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");
    let tc = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let cgroup_skb = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:ingress");
    let sk_skb = ProbeContext::new(EbpfProgramType::SkSkb, "/sys/fs/bpf/demo_sockmap");
    let sk_skb_parser = ProbeContext::new(EbpfProgramType::SkSkbParser, "/sys/fs/bpf/demo_sockmap");

    assert!(
        socket_filter
            .ctx_field_access_error(&CtxField::Socket)
            .is_none()
    );
    assert!(tc.ctx_field_access_error(&CtxField::Socket).is_none());
    assert!(
        cgroup_skb
            .ctx_field_access_error(&CtxField::Socket)
            .is_none()
    );
    assert!(sk_skb.ctx_field_access_error(&CtxField::Socket).is_none());
    assert!(
        sk_skb_parser
            .ctx_field_access_error(&CtxField::Socket)
            .is_none()
    );
}

#[test]
fn test_probe_context_allows_socket_uid_on_tc() {
    let ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    assert!(ctx.ctx_field_access_error(&CtxField::SocketUid).is_none());
}

#[test]
fn test_probe_context_allows_socket_uid_on_cgroup_skb_and_sk_skb_parser() {
    let cgroup_skb = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:ingress");
    let sk_skb_parser = ProbeContext::new(EbpfProgramType::SkSkbParser, "/sys/fs/bpf/demo_sockmap");

    assert!(
        cgroup_skb
            .ctx_field_access_error(&CtxField::SocketUid)
            .is_none()
    );
    assert!(
        sk_skb_parser
            .ctx_field_access_error(&CtxField::SocketUid)
            .is_none()
    );
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
fn test_probe_context_allows_netns_cookie_on_cgroup_skb_and_cgroup_sockopt() {
    let cgroup_skb = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:ingress");
    let cgroup_sockopt = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");

    assert!(
        cgroup_skb
            .ctx_field_access_error(&CtxField::NetnsCookie)
            .is_none()
    );
    assert!(
        cgroup_sockopt
            .ctx_field_access_error(&CtxField::NetnsCookie)
            .is_none()
    );
}

#[test]
fn test_probe_context_allows_cgroup_id_on_xdp() {
    let ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    assert!(ctx.ctx_field_access_error(&CtxField::CgroupId).is_none());
}

#[test]
fn test_probe_context_allows_task_on_task_aware_programs() {
    let ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    assert!(ctx.ctx_field_access_error(&CtxField::Task).is_none());
    assert!(ctx.validate_load_ctx_field(&CtxField::Task).is_ok());
}

#[test]
fn test_probe_context_rejects_task_on_packet_programs() {
    let ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let err = ctx
        .ctx_field_access_error(&CtxField::Task)
        .expect("expected ctx.task field access error");
    assert!(err.contains("ctx.task is not available on xdp programs"));
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_probe_context_allows_perf_event_specific_fields() {
    let ctx = ProbeContext::new(
        EbpfProgramType::PerfEvent,
        "software:cpu-clock:period=100000",
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::PerfSamplePeriod)
            .is_none()
    );
    assert!(ctx.ctx_field_access_error(&CtxField::PerfAddr).is_none());
}

#[test]
fn test_probe_context_allows_perf_event_helper_fields() {
    let ctx = ProbeContext::new(
        EbpfProgramType::PerfEvent,
        "software:cpu-clock:period=100000",
    );

    for field in [
        CtxField::PerfCounter,
        CtxField::PerfEnabled,
        CtxField::PerfRunning,
    ] {
        assert!(ctx.ctx_field_access_error(&field).is_none());
    }
}

#[test]
fn test_probe_context_rejects_perf_event_specific_fields_on_non_perf_event_programs() {
    let ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let sample_period_err = ctx
        .ctx_field_access_error(&CtxField::PerfSamplePeriod)
        .expect("expected sample_period field access error");
    assert!(
        sample_period_err.contains("ctx.sample_period is only available on perf_event programs")
    );

    let addr_err = ctx
        .ctx_field_access_error(&CtxField::PerfAddr)
        .expect("expected addr field access error");
    assert!(addr_err.contains("ctx.addr is only available on perf_event programs"));

    let counter_err = ctx
        .ctx_field_access_error(&CtxField::PerfCounter)
        .expect("expected perf_counter field access error");
    assert!(counter_err.contains("ctx.perf_counter is only available on perf_event programs"));
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
        "ctx.socket_uid is only available on socket_filter, tc, cgroup_skb, sk_skb, and sk_skb_parser programs"
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
    assert!(
        ctx.ctx_field_access_error(&CtxField::TcClassid)
            .expect("expected sk_skb tc_classid access error")
            .contains("ctx.tc_classid is only available on tc programs")
    );
    assert!(ctx.ctx_field_access_error(&CtxField::NapiId).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::WireLen)
            .expect("expected sk_skb wire_len access error")
            .contains("ctx.wire_len is only available on tc programs")
    );
    assert!(ctx.ctx_field_access_error(&CtxField::GsoSegs).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::GsoSize).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::Tstamp)
            .expect("expected sk_skb tstamp access error")
            .contains("ctx.tstamp is only available on tc and cgroup_skb programs")
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::TstampType)
            .expect("expected sk_skb tstamp_type access error")
            .contains("ctx.tstamp_type is only available on tc programs")
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::Hwtstamp)
            .expect("expected sk_skb hwtstamp access error")
            .contains("ctx.hwtstamp is only available on tc and cgroup_skb programs")
    );
    assert!(ctx.ctx_field_access_error(&CtxField::Data).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::DataEnd).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Ifindex).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::TcIndex).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::SkbHash).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::SockMark)
            .expect("expected sk_skb mark access error")
            .contains("ctx.mark is only available on cgroup_sock, socket_filter, tc, and cgroup_skb programs")
    );
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
    assert!(
        ctx.ctx_field_access_error(&CtxField::TcClassid)
            .expect("expected sk_skb_parser tc_classid access error")
            .contains("ctx.tc_classid is only available on tc programs")
    );
    assert!(ctx.ctx_field_access_error(&CtxField::NapiId).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::WireLen)
            .expect("expected sk_skb_parser wire_len access error")
            .contains("ctx.wire_len is only available on tc programs")
    );
    assert!(ctx.ctx_field_access_error(&CtxField::GsoSegs).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::GsoSize).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::Tstamp)
            .expect("expected sk_skb_parser tstamp access error")
            .contains("ctx.tstamp is only available on tc and cgroup_skb programs")
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::TstampType)
            .expect("expected sk_skb_parser tstamp_type access error")
            .contains("ctx.tstamp_type is only available on tc programs")
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::Hwtstamp)
            .expect("expected sk_skb_parser hwtstamp access error")
            .contains("ctx.hwtstamp is only available on tc and cgroup_skb programs")
    );
    assert!(ctx.ctx_field_access_error(&CtxField::Ifindex).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::TcIndex).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::SkbHash).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::SockMark)
            .expect("expected sk_skb_parser mark access error")
            .contains("ctx.mark is only available on cgroup_sock, socket_filter, tc, and cgroup_skb programs")
    );
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
    assert!(err.contains("sendmsg4/sendmsg6"));
}

#[test]
fn test_probe_context_rejects_msg_source_field_on_recvmsg_hook() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:recvmsg4");
    let err = ctx
        .ctx_field_access_error(&CtxField::MsgSrcIp4)
        .expect("expected recvmsg-hook rejection for ctx.msg_src_ip4");
    assert!(err.contains("sendmsg4/sendmsg6"));
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
    assert!(err.contains("sendmsg4/sendmsg6"));
}

#[test]
fn test_probe_context_rejects_sock_addr_fields_on_packet_programs() {
    let ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = ctx
        .ctx_field_access_error(&CtxField::UserFamily)
        .expect("expected sock addr field access error");
    assert!(err.contains("ctx.user_family is only available on cgroup_sock_addr programs"));
}

#[test]
fn test_probe_context_rejects_sock_type_on_packet_programs() {
    let ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = ctx
        .ctx_field_access_error(&CtxField::SockType)
        .expect("expected sock_type field access error");
    assert!(
        err.contains(
            "ctx.sock_type is only available on cgroup_sock and cgroup_sock_addr programs"
        )
    );
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
fn test_probe_context_resolves_cgroup_sockopt_retval_store_target() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");
    assert_eq!(
        ctx.resolve_ctx_store_target("sockopt_retval", None)
            .expect("cgroup_sockopt:get retval target should resolve"),
        CtxStoreTarget::SockoptRetval
    );
    assert_eq!(
        ctx.resolve_ctx_store_target("retval", None)
            .expect("cgroup_sockopt:get retval alias target should resolve"),
        CtxStoreTarget::SockoptRetval
    );
    assert!(
        ctx.validate_ctx_store_target(&CtxStoreTarget::SockoptRetval)
            .is_ok()
    );
}

#[test]
fn test_probe_context_resolves_cgroup_sockopt_scalar_store_targets() {
    let set_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:set");
    assert_eq!(
        set_ctx
            .resolve_ctx_store_target("level", None)
            .expect("cgroup_sockopt:set level target should resolve"),
        CtxStoreTarget::SockoptLevel
    );
    assert_eq!(
        set_ctx
            .resolve_ctx_store_target("optname", None)
            .expect("cgroup_sockopt:set optname target should resolve"),
        CtxStoreTarget::SockoptOptname
    );
    assert_eq!(
        set_ctx
            .resolve_ctx_store_target("optlen", None)
            .expect("cgroup_sockopt:set optlen target should resolve"),
        CtxStoreTarget::SockoptOptlen
    );
    assert!(
        set_ctx
            .validate_ctx_store_target(&CtxStoreTarget::SockoptLevel)
            .is_ok()
    );
    assert!(
        set_ctx
            .validate_ctx_store_target(&CtxStoreTarget::SockoptOptname)
            .is_ok()
    );
    assert!(
        set_ctx
            .validate_ctx_store_target(&CtxStoreTarget::SockoptOptlen)
            .is_ok()
    );

    let get_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");
    assert_eq!(
        get_ctx
            .resolve_ctx_store_target("optlen", None)
            .expect("cgroup_sockopt:get optlen target should resolve"),
        CtxStoreTarget::SockoptOptlen
    );
    assert!(
        get_ctx
            .validate_ctx_store_target(&CtxStoreTarget::SockoptOptlen)
            .is_ok()
    );
}

#[test]
fn test_probe_context_resolves_cgroup_sockopt_optval_byte_write_target() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");
    assert_eq!(
        ctx.resolve_ctx_write_target("optval", Some(2))
            .expect("cgroup_sockopt:get optval.2 target should resolve"),
        CtxWriteTarget::SockoptOptvalByte(2)
    );
}

#[test]
fn test_probe_context_rejects_cgroup_sockopt_optval_write_without_fixed_index() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");
    let err = ctx
        .resolve_ctx_write_target("optval", None)
        .expect_err("cgroup_sockopt optval write without fixed index should be rejected");
    assert!(err.contains("requires a fixed index"));
}

#[test]
fn test_probe_context_rejects_optval_write_target_outside_cgroup_sockopt() {
    let ctx = ProbeContext::new(EbpfProgramType::Kprobe, "do_sys_openat2");
    let err = ctx
        .resolve_ctx_write_target("optval", Some(0))
        .expect_err("optval writes should be rejected outside cgroup_sockopt");
    assert!(err.contains("ctx.optval is only available on cgroup_sockopt programs"));
}

#[test]
fn test_probe_context_rejects_cgroup_sockopt_set_retval_store_target() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:set");
    let err = ctx
        .resolve_ctx_store_target("sockopt_retval", None)
        .expect_err("cgroup_sockopt:set retval store target should be rejected");
    assert!(err.contains("cgroup_sockopt:get"));
}

#[test]
fn test_probe_context_rejects_cgroup_sockopt_get_level_store_target() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");
    let err = ctx
        .resolve_ctx_store_target("level", None)
        .expect_err("cgroup_sockopt:get level store target should be rejected");
    assert!(err.contains("ctx.level is only writable on cgroup_sockopt:set hooks"));
}

#[test]
fn test_probe_context_rejects_cgroup_sockopt_get_optname_store_target_validation() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");
    let err = ctx
        .validate_ctx_store_target(&CtxStoreTarget::SockoptOptname)
        .expect_err("cgroup_sockopt:get optname store target should be rejected");
    assert!(
        err.to_string()
            .contains("ctx.optname is only writable on cgroup_sockopt:set hooks")
    );
}

#[test]
fn test_probe_context_resolves_cgroup_sock_create_release_store_targets() {
    let create_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_create");
    assert_eq!(
        create_ctx
            .resolve_ctx_store_target("bound_dev_if", None)
            .expect("cgroup_sock sock_create bound_dev_if target should resolve"),
        CtxStoreTarget::CgroupSockBoundDevIf
    );
    assert_eq!(
        create_ctx
            .resolve_ctx_store_target("mark", None)
            .expect("cgroup_sock sock_create mark target should resolve"),
        CtxStoreTarget::CgroupSockMark
    );
    assert_eq!(
        create_ctx
            .resolve_ctx_store_target("priority", None)
            .expect("cgroup_sock sock_create priority target should resolve"),
        CtxStoreTarget::CgroupSockPriority
    );

    let release_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_release");
    assert!(
        release_ctx
            .validate_ctx_store_target(&CtxStoreTarget::CgroupSockBoundDevIf)
            .is_ok()
    );
    assert!(
        release_ctx
            .validate_ctx_store_target(&CtxStoreTarget::CgroupSockMark)
            .is_ok()
    );
    assert!(
        release_ctx
            .validate_ctx_store_target(&CtxStoreTarget::CgroupSockPriority)
            .is_ok()
    );
}

#[test]
fn test_probe_context_rejects_cgroup_sock_post_bind_store_targets() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:post_bind4");

    let err = ctx
        .resolve_ctx_store_target("mark", None)
        .expect_err("cgroup_sock post_bind mark store target should be rejected");
    assert!(
        err.contains("ctx.mark is only writable on cgroup_sock sock_create/sock_release hooks")
    );

    let err = ctx
        .validate_ctx_store_target(&CtxStoreTarget::CgroupSockPriority)
        .expect_err("cgroup_sock post_bind priority store target should be rejected");
    assert!(
        err.to_string().contains(
            "ctx.priority is only writable on cgroup_sock sock_create/sock_release hooks"
        )
    );
}

#[test]
fn test_probe_context_resolves_cgroup_sock_addr_ipv4_store_targets() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect4");
    assert_eq!(
        ctx.resolve_ctx_store_target("user_ip4", None)
            .expect("cgroup_sock_addr connect4 user_ip4 target should resolve"),
        CtxStoreTarget::CgroupSockAddrUserIp4
    );
    assert_eq!(
        ctx.resolve_ctx_store_target("user_port", None)
            .expect("cgroup_sock_addr connect4 user_port target should resolve"),
        CtxStoreTarget::CgroupSockAddrUserPort
    );
    assert!(
        ctx.validate_ctx_store_target(&CtxStoreTarget::CgroupSockAddrUserIp4)
            .is_ok()
    );
    assert!(
        ctx.validate_ctx_store_target(&CtxStoreTarget::CgroupSockAddrUserPort)
            .is_ok()
    );
    assert_eq!(
        ctx.resolve_ctx_store_target("remote_ip4", None)
            .expect("cgroup_sock_addr connect4 remote_ip4 target should resolve"),
        CtxStoreTarget::CgroupSockAddrUserIp4
    );
    assert_eq!(
        ctx.resolve_ctx_store_target("remote_port", None)
            .expect("cgroup_sock_addr connect4 remote_port target should resolve"),
        CtxStoreTarget::CgroupSockAddrUserPort
    );
}

#[test]
fn test_probe_context_rejects_ipv4_store_target_on_ipv6_sock_addr_hook() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect6");
    let err = ctx
        .resolve_ctx_store_target("user_ip4", None)
        .expect_err("cgroup_sock_addr connect6 user_ip4 store target should be rejected");
    assert!(err.contains("IPv4 cgroup_sock_addr hooks"));
}

#[test]
fn test_probe_context_rejects_cgroup_sock_addr_user_family_store_target_as_read_only() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect4");
    let err = ctx
        .resolve_ctx_store_target("user_family", None)
        .expect_err("cgroup_sock_addr user_family store target should be rejected as read-only");
    assert!(err.contains("ctx.user_family is read-only"));
}

#[test]
fn test_probe_context_resolves_cgroup_sock_addr_ipv6_and_msg_source_store_targets() {
    let connect6 = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect6");
    assert_eq!(
        connect6
            .resolve_ctx_store_target("user_ip6", Some(2))
            .expect("cgroup_sock_addr connect6 user_ip6.2 target should resolve"),
        CtxStoreTarget::CgroupSockAddrUserIp6Word(2)
    );
    assert!(
        connect6
            .validate_ctx_store_target(&CtxStoreTarget::CgroupSockAddrUserIp6Word(2))
            .is_ok()
    );
    assert_eq!(
        connect6
            .resolve_ctx_store_target("remote_ip6", Some(2))
            .expect("cgroup_sock_addr connect6 remote_ip6.2 target should resolve"),
        CtxStoreTarget::CgroupSockAddrUserIp6Word(2)
    );

    let sendmsg4 = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:sendmsg4");
    assert_eq!(
        sendmsg4
            .resolve_ctx_store_target("msg_src_ip4", None)
            .expect("cgroup_sock_addr sendmsg4 msg_src_ip4 target should resolve"),
        CtxStoreTarget::CgroupSockAddrMsgSrcIp4
    );
    assert_eq!(
        sendmsg4
            .resolve_ctx_store_target("remote_ip4", None)
            .expect("cgroup_sock_addr sendmsg4 remote_ip4 target should resolve"),
        CtxStoreTarget::CgroupSockAddrUserIp4
    );
    assert_eq!(
        sendmsg4
            .resolve_ctx_store_target("local_ip4", None)
            .expect("cgroup_sock_addr sendmsg4 local_ip4 target should resolve"),
        CtxStoreTarget::CgroupSockAddrMsgSrcIp4
    );

    let sendmsg6 = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:sendmsg6");
    assert_eq!(
        sendmsg6
            .resolve_ctx_store_target("msg_src_ip6", Some(3))
            .expect("cgroup_sock_addr sendmsg6 msg_src_ip6.3 target should resolve"),
        CtxStoreTarget::CgroupSockAddrMsgSrcIp6Word(3)
    );
    assert_eq!(
        sendmsg6
            .resolve_ctx_store_target("local_ip6", Some(3))
            .expect("cgroup_sock_addr sendmsg6 local_ip6.3 target should resolve"),
        CtxStoreTarget::CgroupSockAddrMsgSrcIp6Word(3)
    );

    let recvmsg4 = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:recvmsg4");
    assert_eq!(
        recvmsg4
            .resolve_ctx_store_target("remote_ip4", None)
            .expect("cgroup_sock_addr recvmsg4 remote_ip4 target should resolve"),
        CtxStoreTarget::CgroupSockAddrUserIp4
    );

    let getpeername4 = ProbeContext::new(
        EbpfProgramType::CgroupSockAddr,
        "/sys/fs/cgroup:getpeername4",
    );
    assert_eq!(
        getpeername4
            .resolve_ctx_store_target("remote_ip4", None)
            .expect("cgroup_sock_addr getpeername4 remote_ip4 target should resolve"),
        CtxStoreTarget::CgroupSockAddrUserIp4
    );

    let bind6 = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:bind6");
    assert_eq!(
        bind6
            .resolve_ctx_store_target("local_ip6", Some(1))
            .expect("cgroup_sock_addr bind6 local_ip6.1 target should resolve"),
        CtxStoreTarget::CgroupSockAddrUserIp6Word(1)
    );
    assert_eq!(
        bind6
            .resolve_ctx_store_target("local_port", None)
            .expect("cgroup_sock_addr bind6 local_port target should resolve"),
        CtxStoreTarget::CgroupSockAddrUserPort
    );

    let getsockname6 = ProbeContext::new(
        EbpfProgramType::CgroupSockAddr,
        "/sys/fs/cgroup:getsockname6",
    );
    assert_eq!(
        getsockname6
            .resolve_ctx_store_target("local_ip6", Some(1))
            .expect("cgroup_sock_addr getsockname6 local_ip6.1 target should resolve"),
        CtxStoreTarget::CgroupSockAddrUserIp6Word(1)
    );
    assert_eq!(
        getsockname6
            .resolve_ctx_store_target("local_port", None)
            .expect("cgroup_sock_addr getsockname6 local_port target should resolve"),
        CtxStoreTarget::CgroupSockAddrUserPort
    );
}

#[test]
fn test_probe_context_rejects_unavailable_tuple_alias_store_target_on_sock_addr_hook() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect4");
    let err = ctx
        .resolve_ctx_store_target("local_ip4", None)
        .expect_err("cgroup_sock_addr connect4 local_ip4 store target should be rejected");
    assert!(err.contains("bind4/bind6, getsockname4/getsockname6, and sendmsg4/sendmsg6"));
}

#[test]
fn test_probe_context_rejects_msg_source_store_target_validation_outside_msg_hooks() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect4");
    let err = ctx
        .validate_ctx_store_target(&CtxStoreTarget::CgroupSockAddrMsgSrcIp4)
        .expect_err("cgroup_sock_addr connect4 msg_src_ip4 store target should be rejected");
    assert!(err.to_string().contains("sendmsg4/sendmsg6"));
}

#[test]
fn test_probe_context_rejects_msg_source_store_target_validation_on_recvmsg_hooks() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:recvmsg4");
    let err = ctx
        .validate_ctx_store_target(&CtxStoreTarget::CgroupSockAddrMsgSrcIp4)
        .expect_err("cgroup_sock_addr recvmsg4 msg_src_ip4 store target should be rejected");
    assert!(err.to_string().contains("sendmsg4/sendmsg6"));
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
