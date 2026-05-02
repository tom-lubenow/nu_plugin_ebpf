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
use std::collections::{HashMap, HashSet};

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
fn test_lsm_cgroup_section_name() {
    let prog =
        EbpfProgram::from_bytecode(EbpfProgramType::LsmCgroup, "socket_bind", "test", vec![]);
    assert_eq!(
        prog.section_name()
            .expect("lsm_cgroup section name should build"),
        "lsm_cgroup/socket_bind"
    );
}

#[test]
fn test_kprobe_multi_section_names() {
    let entry = EbpfProgram::from_bytecode(EbpfProgramType::KprobeMulti, "vfs_*", "test", vec![]);
    assert_eq!(
        entry
            .section_name()
            .expect("kprobe.multi section name should build"),
        "kprobe.multi/vfs_*"
    );

    let exit = EbpfProgram::from_bytecode(EbpfProgramType::KretprobeMulti, "vfs_*", "test", vec![]);
    assert_eq!(
        exit.section_name()
            .expect("kretprobe.multi section name should build"),
        "kretprobe.multi/vfs_*"
    );
}

#[test]
fn test_uprobe_multi_section_names() {
    let entry = EbpfProgram::from_bytecode(
        EbpfProgramType::UprobeMulti,
        "/bin/bash:read*",
        "test",
        vec![],
    );
    assert_eq!(
        entry
            .section_name()
            .expect("uprobe.multi section name should build"),
        "uprobe.multi//bin/bash:read*"
    );

    let exit = EbpfProgram::from_bytecode(
        EbpfProgramType::UretprobeMulti,
        "/bin/bash:read*",
        "test",
        vec![],
    );
    assert_eq!(
        exit.section_name()
            .expect("uretprobe.multi section name should build"),
        "uretprobe.multi//bin/bash:read*"
    );

    let spec = ProgramSpec::parse("uprobe.multi.s:/bin/bash:read*")
        .expect("sleepable uprobe.multi spec should parse");
    let sleepable = EbpfProgram::from_bytecode(
        EbpfProgramType::UprobeMulti,
        "/bin/bash:read*",
        "test",
        vec![],
    )
    .with_program_spec(spec);
    assert_eq!(
        sleepable
            .section_name()
            .expect("sleepable uprobe.multi section name should build"),
        "uprobe.multi.s//bin/bash:read*"
    );
}

#[test]
fn test_kernel_syscall_probe_section_names() {
    let entry = EbpfProgram::from_bytecode(EbpfProgramType::Ksyscall, "nanosleep", "test", vec![]);
    assert_eq!(
        entry
            .section_name()
            .expect("ksyscall section name should build"),
        "ksyscall/nanosleep"
    );

    let exit =
        EbpfProgram::from_bytecode(EbpfProgramType::KretSyscall, "nanosleep", "test", vec![]);
    assert_eq!(
        exit.section_name()
            .expect("kretsyscall section name should build"),
        "kretsyscall/nanosleep"
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
fn test_fmod_ret_section_name() {
    let prog = EbpfProgram::from_bytecode(
        EbpfProgramType::FmodRet,
        "bpf_modify_return_test",
        "test",
        vec![],
    );
    assert_eq!(
        prog.section_name()
            .expect("fmod_ret section name should build"),
        "fmod_ret/bpf_modify_return_test"
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

    let fmod_ret =
        ProgramSpec::parse("fmod_ret.s:bpf_modify_return_test").expect("sleepable fmod_ret spec");
    let prog = EbpfProgram::from_bytecode(
        EbpfProgramType::FmodRet,
        "bpf_modify_return_test",
        "test",
        vec![],
    )
    .with_program_spec(fmod_ret);
    assert_eq!(
        prog.section_name()
            .expect("sleepable fmod_ret section name should build"),
        "fmod_ret.s/bpf_modify_return_test"
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

    let frags = EbpfProgram::from_bytecode(EbpfProgramType::Xdp, "lo:frags", "test", vec![]);
    assert_eq!(
        frags
            .section_name()
            .expect("xdp.frags section name should build"),
        "xdp.frags"
    );
}

#[test]
fn test_ebpf_program_caches_typed_program_spec() {
    let prog = EbpfProgram::from_bytecode(EbpfProgramType::Xdp, "lo", "test", vec![]);
    let section = prog.clone().into_program_section();

    assert!(matches!(
        prog.parsed_program_spec(),
        Some(ProgramSpec::Xdp { target }) if target.interface == "lo" && !target.frags
    ));
    assert!(matches!(
        section.parsed_program_spec(),
        Some(ProgramSpec::Xdp { target }) if target.interface == "lo" && !target.frags
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
        Some(ProgramSpec::Uprobe { target, .. })
            if target.binary_path == "/usr/bin/app"
                && target.function_name.as_deref() == Some("main")
                && target.offset == 16
    ));
}

#[test]
fn test_sleepable_uprobe_section_name_uses_program_spec() {
    let spec = ProgramSpec::parse("uprobe.s:/usr/bin/app:main").expect("sleepable uprobe spec");
    let prog =
        EbpfProgram::from_bytecode(EbpfProgramType::Uprobe, "/usr/bin/app:main", "test", vec![])
            .with_program_spec(spec.clone());
    assert_eq!(prog.parsed_program_spec(), Some(&spec));
    assert_eq!(
        prog.section_name()
            .expect("sleepable uprobe section name should build"),
        "uprobe.s//usr/bin/app:main"
    );

    let from_full_spec = EbpfProgram::from_bytecode(
        EbpfProgramType::Uretprobe,
        "uretprobe.s:/lib/libc.so.6:malloc",
        "test",
        vec![],
    );
    assert_eq!(
        from_full_spec
            .section_name()
            .expect("sleepable uretprobe full-spec section name should build"),
        "uretprobe.s//lib/libc.so.6:malloc"
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
fn test_tcx_section_name() {
    let ingress = EbpfProgram::from_bytecode(EbpfProgramType::Tcx, "lo:ingress", "test", vec![]);
    assert_eq!(
        ingress
            .section_name()
            .expect("tcx ingress section name should build"),
        "tcx/ingress"
    );

    let egress = EbpfProgram::from_bytecode(EbpfProgramType::Tcx, "lo:egress", "test", vec![]);
    assert_eq!(
        egress
            .section_name()
            .expect("tcx egress section name should build"),
        "tcx/egress"
    );
}

#[test]
fn test_netkit_section_name() {
    let primary =
        EbpfProgram::from_bytecode(EbpfProgramType::Netkit, "nk0:primary", "test", vec![]);
    assert_eq!(
        primary
            .section_name()
            .expect("netkit primary section name should build"),
        "netkit/primary"
    );

    let peer = EbpfProgram::from_bytecode(EbpfProgramType::Netkit, "nk0:peer", "test", vec![]);
    assert_eq!(
        peer.section_name()
            .expect("netkit peer section name should build"),
        "netkit/peer"
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
fn test_extension_section_name() {
    let prog = EbpfProgram::from_bytecode(EbpfProgramType::Extension, "replace_me", "test", vec![]);
    assert_eq!(
        prog.section_name()
            .expect("freplace section name should build"),
        "freplace/replace_me"
    );
}

#[test]
fn test_syscall_section_name() {
    let prog = EbpfProgram::from_bytecode(EbpfProgramType::Syscall, "demo", "test", vec![]);
    assert_eq!(
        prog.section_name()
            .expect("syscall section name should build"),
        "syscall"
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
    assert!(!EbpfProgramType::Fexit.is_userspace());
    assert!(EbpfProgramType::Uprobe.is_userspace());
}

#[test]
fn test_program_type_metadata_for_fmod_ret() {
    let info = EbpfProgramType::FmodRet.info();
    assert_eq!(info.canonical_prefix, "fmod_ret");
    assert_eq!(info.kernel_prog_type, "BPF_PROG_TYPE_TRACING");
    assert_eq!(info.attach_kind, ProgramAttachKind::FmodRet);
    assert_eq!(info.target_kind, ProgramTargetKind::KernelFunction);
    assert_eq!(
        info.kernel_target_validation,
        Some(KernelTargetValidationKind::FmodRetTrampoline)
    );
    assert_eq!(info.arg_access, ProgramValueAccess::Trampoline);
    assert_eq!(info.retval_access, ProgramValueAccess::Trampoline);
    assert_eq!(
        EbpfProgramType::FmodRet.btf_callable_surface(),
        Some(ProgramBtfCallableSurface::FunctionTrampoline)
    );
    assert!(!EbpfProgramType::FmodRet.is_userspace());
}

#[test]
fn test_program_type_metadata_for_kprobe_multi() {
    let entry = EbpfProgramType::KprobeMulti.info();
    assert_eq!(entry.canonical_prefix, "kprobe.multi");
    assert_eq!(entry.kernel_prog_type, "BPF_PROG_TYPE_KPROBE");
    assert_eq!(entry.attach_kind, ProgramAttachKind::KprobeMulti);
    assert_eq!(entry.target_kind, ProgramTargetKind::KernelFunctionPattern);
    assert_eq!(entry.kernel_target_validation, None);
    assert_eq!(entry.arg_access, ProgramValueAccess::PtRegs);
    assert_eq!(entry.retval_access, ProgramValueAccess::None);
    assert_eq!(EbpfProgramType::KprobeMulti.btf_callable_surface(), None);
    assert!(!EbpfProgramType::KprobeMulti.is_userspace());

    let ret = EbpfProgramType::KretprobeMulti.info();
    assert_eq!(ret.canonical_prefix, "kretprobe.multi");
    assert_eq!(ret.kernel_prog_type, "BPF_PROG_TYPE_KPROBE");
    assert_eq!(ret.attach_kind, ProgramAttachKind::KretprobeMulti);
    assert_eq!(ret.target_kind, ProgramTargetKind::KernelFunctionPattern);
    assert_eq!(ret.kernel_target_validation, None);
    assert_eq!(ret.arg_access, ProgramValueAccess::None);
    assert_eq!(ret.retval_access, ProgramValueAccess::PtRegs);
    assert_eq!(EbpfProgramType::KretprobeMulti.btf_callable_surface(), None);
    assert!(!EbpfProgramType::KretprobeMulti.is_userspace());
}

#[test]
fn test_program_type_metadata_for_uprobe_multi() {
    let entry = EbpfProgramType::UprobeMulti.info();
    assert_eq!(entry.canonical_prefix, "uprobe.multi");
    assert_eq!(entry.kernel_prog_type, "BPF_PROG_TYPE_KPROBE");
    assert_eq!(entry.attach_kind, ProgramAttachKind::UprobeMulti);
    assert_eq!(entry.target_kind, ProgramTargetKind::UserFunctionPattern);
    assert_eq!(entry.kernel_target_validation, None);
    assert_eq!(entry.arg_access, ProgramValueAccess::PtRegs);
    assert_eq!(entry.retval_access, ProgramValueAccess::None);
    assert!(EbpfProgramType::UprobeMulti.is_userspace());

    let ret = EbpfProgramType::UretprobeMulti.info();
    assert_eq!(ret.canonical_prefix, "uretprobe.multi");
    assert_eq!(ret.kernel_prog_type, "BPF_PROG_TYPE_KPROBE");
    assert_eq!(ret.attach_kind, ProgramAttachKind::UretprobeMulti);
    assert_eq!(ret.target_kind, ProgramTargetKind::UserFunctionPattern);
    assert_eq!(ret.kernel_target_validation, None);
    assert_eq!(ret.arg_access, ProgramValueAccess::None);
    assert_eq!(ret.retval_access, ProgramValueAccess::PtRegs);
    assert!(EbpfProgramType::UretprobeMulti.is_userspace());
}

#[test]
fn test_program_type_metadata_for_lsm_cgroup() {
    let info = EbpfProgramType::LsmCgroup.info();
    assert_eq!(info.canonical_prefix, "lsm_cgroup");
    assert_eq!(info.kernel_prog_type, "BPF_PROG_TYPE_LSM");
    assert_eq!(info.attach_kind, ProgramAttachKind::LsmCgroup);
    assert_eq!(info.target_kind, ProgramTargetKind::LsmHook);
    assert_eq!(
        info.kernel_target_validation,
        Some(KernelTargetValidationKind::LsmHook)
    );
    assert_eq!(info.arg_access, ProgramValueAccess::Trampoline);
    assert_eq!(info.retval_access, ProgramValueAccess::None);
    assert_eq!(
        EbpfProgramType::LsmCgroup.btf_callable_surface(),
        Some(ProgramBtfCallableSurface::LsmHook)
    );
    assert!(!EbpfProgramType::LsmCgroup.is_userspace());
}

#[test]
fn test_program_type_metadata_for_kernel_syscall_probes() {
    let entry = EbpfProgramType::Ksyscall.info();
    assert_eq!(entry.canonical_prefix, "ksyscall");
    assert_eq!(entry.kernel_prog_type, "BPF_PROG_TYPE_KPROBE");
    assert_eq!(entry.attach_kind, ProgramAttachKind::Ksyscall);
    assert_eq!(entry.target_kind, ProgramTargetKind::KernelSyscall);
    assert_eq!(entry.kernel_target_validation, None);
    assert_eq!(entry.arg_access, ProgramValueAccess::PtRegs);
    assert_eq!(entry.retval_access, ProgramValueAccess::None);
    assert_eq!(EbpfProgramType::Ksyscall.btf_callable_surface(), None);
    assert!(!EbpfProgramType::Ksyscall.is_userspace());

    let ret = EbpfProgramType::KretSyscall.info();
    assert_eq!(ret.canonical_prefix, "kretsyscall");
    assert_eq!(ret.kernel_prog_type, "BPF_PROG_TYPE_KPROBE");
    assert_eq!(ret.attach_kind, ProgramAttachKind::KretSyscall);
    assert_eq!(ret.target_kind, ProgramTargetKind::KernelSyscall);
    assert_eq!(ret.kernel_target_validation, None);
    assert_eq!(ret.arg_access, ProgramValueAccess::None);
    assert_eq!(ret.retval_access, ProgramValueAccess::PtRegs);
    assert_eq!(EbpfProgramType::KretSyscall.btf_callable_surface(), None);
    assert!(!EbpfProgramType::KretSyscall.is_userspace());
}

#[test]
fn test_program_target_kind_predicates_follow_model() {
    assert!(ProgramTargetKind::UserFunction.is_userspace_function());
    assert!(ProgramTargetKind::UserFunctionPattern.is_userspace_function());
    assert!(!ProgramTargetKind::KernelFunction.is_userspace_function());
    assert!(!ProgramTargetKind::KernelFunctionPattern.is_userspace_function());
    assert!(!ProgramTargetKind::KernelSyscall.is_userspace_function());
    assert!(ProgramTargetKind::Tracepoint.is_tracepoint());
    assert!(!ProgramTargetKind::RawTracepoint.is_tracepoint());
}

#[test]
fn test_program_type_metadata_for_tp_btf() {
    let info = EbpfProgramType::TpBtf.info();
    assert_eq!(info.canonical_prefix, "tp_btf");
    assert_eq!(info.attach_kind, ProgramAttachKind::TpBtf);
    assert_eq!(info.target_kind, ProgramTargetKind::BtfTracepoint);
    assert_eq!(info.arg_access, ProgramValueAccess::Trampoline);
    assert_eq!(info.retval_access, ProgramValueAccess::None);
}

#[test]
fn test_program_type_metadata_for_raw_tracepoint() {
    let info = EbpfProgramType::RawTracepoint.info();
    assert_eq!(info.canonical_prefix, "raw_tracepoint");
    assert_eq!(info.attach_kind, ProgramAttachKind::RawTracepoint);
    assert_eq!(info.target_kind, ProgramTargetKind::RawTracepoint);
    assert_eq!(info.arg_access, ProgramValueAccess::RawTracepoint);
    assert_eq!(info.retval_access, ProgramValueAccess::None);

    let writable = EbpfProgramType::RawTracepointWritable.info();
    assert_eq!(writable.canonical_prefix, "raw_tracepoint.w");
    assert_eq!(
        writable.attach_kind,
        ProgramAttachKind::RawTracepointWritable
    );
    assert_eq!(writable.target_kind, ProgramTargetKind::RawTracepoint);
    assert_eq!(writable.arg_access, ProgramValueAccess::RawTracepoint);
    assert_eq!(writable.retval_access, ProgramValueAccess::None);
}

#[test]
fn test_program_type_metadata_for_perf_event() {
    let info = EbpfProgramType::PerfEvent.info();
    assert_eq!(info.canonical_prefix, "perf_event");
    assert_eq!(info.attach_kind, ProgramAttachKind::PerfEvent);
    assert_eq!(info.target_kind, ProgramTargetKind::PerfEventTarget);
    assert_eq!(info.arg_access, ProgramValueAccess::PtRegs);
    assert_eq!(info.retval_access, ProgramValueAccess::None);
}

#[test]
fn test_program_type_metadata_for_sk_lookup() {
    let info = EbpfProgramType::SkLookup.info();
    assert_eq!(info.canonical_prefix, "sk_lookup");
    assert_eq!(info.attach_kind, ProgramAttachKind::SkLookup);
    assert_eq!(info.target_kind, ProgramTargetKind::NetworkNamespacePath);
    assert_eq!(info.arg_access, ProgramValueAccess::None);
    assert_eq!(info.retval_access, ProgramValueAccess::None);
}

#[test]
fn test_program_type_metadata_for_lirc_mode2() {
    let info = EbpfProgramType::LircMode2.info();
    assert_eq!(info.canonical_prefix, "lirc_mode2");
    assert_eq!(info.attach_kind, ProgramAttachKind::LircMode2);
    assert_eq!(info.target_kind, ProgramTargetKind::LircDevicePath);
    assert_eq!(info.arg_access, ProgramValueAccess::None);
    assert_eq!(info.retval_access, ProgramValueAccess::None);
}

#[test]
fn test_program_type_metadata_for_sk_msg() {
    let info = EbpfProgramType::SkMsg.info();
    assert_eq!(info.canonical_prefix, "sk_msg");
    assert_eq!(info.attach_kind, ProgramAttachKind::SkMsg);
    assert_eq!(info.target_kind, ProgramTargetKind::PinnedSockMapPath);
    assert_eq!(info.arg_access, ProgramValueAccess::None);
    assert_eq!(info.retval_access, ProgramValueAccess::None);
}

#[test]
fn test_program_type_metadata_for_tc_action() {
    let info = EbpfProgramType::TcAction.info();
    assert_eq!(info.canonical_prefix, "tc_action");
    assert_eq!(info.section_prefix, "action");
    assert_eq!(info.attach_kind, ProgramAttachKind::TcAction);
    assert_eq!(info.target_kind, ProgramTargetKind::TrafficControlAction);
    assert_eq!(info.context_family, ProgramContextFamily::SkBuffPacket);
    assert_eq!(info.arg_access, ProgramValueAccess::None);
    assert_eq!(info.retval_access, ProgramValueAccess::None);
}

#[test]
fn test_program_type_metadata_for_tcx() {
    let info = EbpfProgramType::Tcx.info();
    assert_eq!(info.canonical_prefix, "tcx");
    assert_eq!(info.kernel_prog_type, "BPF_PROG_TYPE_SCHED_CLS");
    assert_eq!(info.section_prefix, "tcx");
    assert_eq!(info.attach_kind, ProgramAttachKind::Tcx);
    assert_eq!(info.target_kind, ProgramTargetKind::TrafficControlInterface);
    assert_eq!(info.context_family, ProgramContextFamily::SkBuffPacket);
    assert_eq!(info.arg_access, ProgramValueAccess::None);
    assert_eq!(info.retval_access, ProgramValueAccess::None);
}

#[test]
fn test_program_type_metadata_for_netkit() {
    let info = EbpfProgramType::Netkit.info();
    assert_eq!(info.canonical_prefix, "netkit");
    assert_eq!(info.kernel_prog_type, "BPF_PROG_TYPE_SCHED_CLS");
    assert_eq!(info.section_prefix, "netkit");
    assert_eq!(info.attach_kind, ProgramAttachKind::Netkit);
    assert_eq!(info.target_kind, ProgramTargetKind::TrafficControlInterface);
    assert_eq!(info.context_family, ProgramContextFamily::SkBuffPacket);
    assert_eq!(info.arg_access, ProgramValueAccess::None);
    assert_eq!(info.retval_access, ProgramValueAccess::None);
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
}

#[test]
fn test_program_type_metadata_for_sk_skb_parser() {
    let info = EbpfProgramType::SkSkbParser.info();
    assert_eq!(info.canonical_prefix, "sk_skb_parser");
    assert_eq!(info.attach_kind, ProgramAttachKind::SkSkbParser);
    assert_eq!(info.target_kind, ProgramTargetKind::PinnedSockMapPath);
    assert_eq!(info.arg_access, ProgramValueAccess::None);
    assert_eq!(info.retval_access, ProgramValueAccess::None);
}

#[test]
fn test_program_type_metadata_for_socket_filter() {
    let info = EbpfProgramType::SocketFilter.info();
    assert_eq!(info.canonical_prefix, "socket_filter");
    assert_eq!(info.attach_kind, ProgramAttachKind::SocketFilter);
    assert_eq!(info.target_kind, ProgramTargetKind::SocketFilterTarget);
    assert_eq!(info.arg_access, ProgramValueAccess::None);
    assert_eq!(info.retval_access, ProgramValueAccess::None);
}

#[test]
fn test_program_type_direct_packet_write_support_follows_program_model() {
    assert!(EbpfProgramType::Xdp.supports_direct_packet_writes());
    assert!(EbpfProgramType::TcAction.supports_direct_packet_writes());
    assert!(EbpfProgramType::Tc.supports_direct_packet_writes());
    assert!(EbpfProgramType::Tcx.supports_direct_packet_writes());
    assert!(EbpfProgramType::Netkit.supports_direct_packet_writes());
    assert!(EbpfProgramType::LwtXmit.supports_direct_packet_writes());
    assert!(EbpfProgramType::SkMsg.supports_direct_packet_writes());
    assert!(EbpfProgramType::SkSkb.supports_direct_packet_writes());
    assert!(EbpfProgramType::SkSkbParser.supports_direct_packet_writes());

    assert!(!EbpfProgramType::SocketFilter.supports_direct_packet_writes());
    assert!(!EbpfProgramType::FlowDissector.supports_direct_packet_writes());
    assert!(!EbpfProgramType::CgroupSkb.supports_direct_packet_writes());
    assert!(!EbpfProgramType::LwtIn.supports_direct_packet_writes());
    assert!(!EbpfProgramType::LwtOut.supports_direct_packet_writes());
    assert!(!EbpfProgramType::LwtSeg6Local.supports_direct_packet_writes());
    assert!(!EbpfProgramType::SockOps.supports_direct_packet_writes());
}

#[test]
fn test_program_type_return_action_aliases_cover_const_families() {
    assert_eq!(
        EbpfProgramType::Xdp.return_action_alias("PaSs"),
        Some(ProgramReturnAlias::Const(2))
    );
    assert_eq!(ProgramReturnAlias::Const(2).key(), "const");
    assert_eq!(ProgramReturnAlias::Const(2).const_value(), Some(2));
    assert_eq!(ProgramReturnAlias::PacketLen.key(), "packet-len");
    assert_eq!(ProgramReturnAlias::PacketLen.const_value(), None);
    assert!(
        EbpfProgramType::Xdp
            .return_action_alias_pairs()
            .contains(&("pass", ProgramReturnAlias::Const(2)))
    );
    assert!(
        EbpfProgramType::SocketFilter
            .return_action_alias_pairs()
            .contains(&("keep", ProgramReturnAlias::PacketLen))
    );
    assert_eq!(
        EbpfProgramType::Tc.return_action_alias("trap"),
        Some(ProgramReturnAlias::Const(8))
    );
    assert_eq!(
        EbpfProgramType::TcAction.return_action_alias("drop"),
        Some(ProgramReturnAlias::Const(2))
    );
    assert_eq!(
        EbpfProgramType::Tcx.return_action_alias("next"),
        Some(ProgramReturnAlias::Const(-1))
    );
    assert_eq!(
        EbpfProgramType::Tcx.return_action_alias("pass"),
        Some(ProgramReturnAlias::Const(0))
    );
    assert_eq!(EbpfProgramType::Tcx.return_action_alias("trap"), None);
    assert_eq!(
        EbpfProgramType::Netkit.return_action_alias("next"),
        Some(ProgramReturnAlias::Const(-1))
    );
    assert_eq!(
        EbpfProgramType::Netkit.return_action_alias("redirect"),
        Some(ProgramReturnAlias::Const(7))
    );
    assert_eq!(EbpfProgramType::Netkit.return_action_alias("trap"), None);
    assert_eq!(
        EbpfProgramType::FlowDissector.return_action_alias("fallback"),
        Some(ProgramReturnAlias::Const(129))
    );
    assert_eq!(
        EbpfProgramType::FlowDissector.return_action_alias("parsed"),
        Some(ProgramReturnAlias::Const(0))
    );
    assert_eq!(
        EbpfProgramType::Netfilter.return_action_alias("accept"),
        Some(ProgramReturnAlias::Const(1))
    );
    assert_eq!(
        EbpfProgramType::Netfilter.return_action_alias("queue"),
        Some(ProgramReturnAlias::Const(3))
    );
    assert_eq!(
        EbpfProgramType::LwtIn.return_action_alias("reroute"),
        Some(ProgramReturnAlias::Const(128))
    );
    assert_eq!(
        EbpfProgramType::LwtXmit.return_action_alias("redirect"),
        Some(ProgramReturnAlias::Const(7))
    );
    assert_eq!(EbpfProgramType::LwtOut.return_action_alias("reroute"), None);
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
fn test_program_type_allow_deny_return_alias_surface_covers_policy_programs() {
    for program_type in [
        EbpfProgramType::CgroupSkb,
        EbpfProgramType::CgroupDevice,
        EbpfProgramType::CgroupSock,
        EbpfProgramType::CgroupSysctl,
        EbpfProgramType::CgroupSockopt,
        EbpfProgramType::CgroupSockAddr,
        EbpfProgramType::LsmCgroup,
        EbpfProgramType::SkLookup,
        EbpfProgramType::SkReuseport,
        EbpfProgramType::SkSkb,
        EbpfProgramType::SkMsg,
    ] {
        assert_eq!(
            program_type.return_action_alias("allow"),
            Some(ProgramReturnAlias::Const(1)),
            "{program_type:?} should accept allow/pass-style return aliases"
        );
        assert_eq!(
            program_type.return_action_alias("deny"),
            Some(ProgramReturnAlias::Const(0)),
            "{program_type:?} should accept deny/drop-style return aliases"
        );
    }

    assert_eq!(
        EbpfProgramType::SkSkbParser.return_action_alias("allow"),
        None
    );
    assert_eq!(
        EbpfProgramType::StructOps.return_action_alias("allow"),
        None
    );
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
    assert!(EbpfProgramType::RawTracepointWritable.uses_raw_tracepoint_args());
    assert!(!EbpfProgramType::Kprobe.uses_raw_tracepoint_args());
    assert!(!EbpfProgramType::TpBtf.uses_raw_tracepoint_args());
}

#[test]
fn test_program_value_access_predicates_follow_model() {
    assert!(!ProgramValueAccess::None.exposes_value());
    assert!(ProgramValueAccess::PtRegs.exposes_value());
    assert!(ProgramValueAccess::RawTracepoint.exposes_value());
    assert!(ProgramValueAccess::Trampoline.exposes_value());

    assert!(ProgramValueAccess::PtRegs.is_pt_regs());
    assert!(!ProgramValueAccess::RawTracepoint.is_pt_regs());
    assert!(ProgramValueAccess::RawTracepoint.is_raw_tracepoint());
    assert!(!ProgramValueAccess::Trampoline.is_raw_tracepoint());
    assert!(ProgramValueAccess::Trampoline.is_trampoline());
    assert!(!ProgramValueAccess::PtRegs.is_trampoline());
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
        EbpfProgramType::SkReuseport.protocol_context_layout(),
        Some(SocketContextLayout::SkReuseport)
    );
    assert_eq!(
        EbpfProgramType::FlowDissector.protocol_context_layout(),
        None
    );
    assert_eq!(
        EbpfProgramType::FlowDissector.socket_tuple_context_layout(),
        None
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

    assert_eq!(
        EbpfProgramType::SkReuseport.socket_ref_context_layout(),
        Some(SocketContextLayout::SkReuseport)
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
    assert_eq!(
        EbpfProgramType::Tcx.data_meta_context_kind(),
        Some(PacketContextKind::SkBuff)
    );
    assert_eq!(
        EbpfProgramType::Netkit.data_meta_context_kind(),
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
}

#[test]
fn test_program_type_metadata_for_sk_reuseport() {
    let info = EbpfProgramType::SkReuseport.info();
    assert_eq!(info.canonical_prefix, "sk_reuseport");
    assert_eq!(info.section_prefix, "sk_reuseport");
    assert_eq!(info.attach_kind, ProgramAttachKind::SkReuseport);
    assert_eq!(info.target_kind, ProgramTargetKind::SocketReuseportMode);
    assert_eq!(info.context_family, ProgramContextFamily::SkReuseport);
    assert_eq!(info.arg_access, ProgramValueAccess::None);
    assert_eq!(info.retval_access, ProgramValueAccess::None);
    assert!(
        info.supported_capabilities
            .contains(&ProgramCapability::Counters)
    );
}

#[test]
fn test_program_type_metadata_for_flow_dissector() {
    let info = EbpfProgramType::FlowDissector.info();
    assert_eq!(info.canonical_prefix, "flow_dissector");
    assert_eq!(info.section_prefix, "flow_dissector");
    assert_eq!(info.attach_kind, ProgramAttachKind::FlowDissector);
    assert_eq!(info.target_kind, ProgramTargetKind::NetworkNamespacePath);
    assert_eq!(info.context_family, ProgramContextFamily::FlowDissector);
    assert_eq!(info.arg_access, ProgramValueAccess::None);
    assert_eq!(info.retval_access, ProgramValueAccess::None);
    assert!(
        info.supported_capabilities
            .contains(&ProgramCapability::Counters)
    );
}

#[test]
fn test_program_type_metadata_for_netfilter() {
    let info = EbpfProgramType::Netfilter.info();
    assert_eq!(info.canonical_prefix, "netfilter");
    assert_eq!(info.section_prefix, "netfilter");
    assert_eq!(info.attach_kind, ProgramAttachKind::Netfilter);
    assert_eq!(info.target_kind, ProgramTargetKind::NetfilterHook);
    assert_eq!(info.context_family, ProgramContextFamily::Netfilter);
    assert_eq!(info.arg_access, ProgramValueAccess::None);
    assert_eq!(info.retval_access, ProgramValueAccess::None);
    assert!(
        info.supported_capabilities
            .contains(&ProgramCapability::Counters)
    );
}

#[test]
fn test_program_type_metadata_for_lwt() {
    for (program_type, section_prefix) in [
        (EbpfProgramType::LwtIn, "lwt_in"),
        (EbpfProgramType::LwtOut, "lwt_out"),
        (EbpfProgramType::LwtXmit, "lwt_xmit"),
        (EbpfProgramType::LwtSeg6Local, "lwt_seg6local"),
    ] {
        let info = program_type.info();
        assert_eq!(info.canonical_prefix, section_prefix);
        assert_eq!(info.section_prefix, section_prefix);
        assert_eq!(info.attach_kind, ProgramAttachKind::Lwt);
        assert_eq!(info.target_kind, ProgramTargetKind::LightweightTunnelRoute);
        assert_eq!(info.context_family, ProgramContextFamily::SkBuffPacket);
        assert_eq!(info.arg_access, ProgramValueAccess::None);
        assert_eq!(info.retval_access, ProgramValueAccess::None);
        assert!(
            info.supported_capabilities
                .contains(&ProgramCapability::Counters)
        );
    }
}

#[test]
fn test_program_type_metadata_for_extension() {
    let info = EbpfProgramType::Extension.info();
    assert_eq!(info.canonical_prefix, "freplace");
    assert_eq!(info.section_prefix, "freplace");
    assert_eq!(info.attach_kind, ProgramAttachKind::Extension);
    assert_eq!(info.target_kind, ProgramTargetKind::ExtensionFunction);
    assert_eq!(info.context_family, ProgramContextFamily::Extension);
    assert_eq!(info.arg_access, ProgramValueAccess::None);
    assert_eq!(info.retval_access, ProgramValueAccess::None);
    assert!(!EbpfProgramType::Extension.supports_capability(ProgramCapability::Counters));
    assert!(!EbpfProgramType::Extension.supports_capability(ProgramCapability::HelperCalls));
}

#[test]
fn test_program_type_metadata_for_syscall() {
    let info = EbpfProgramType::Syscall.info();
    assert_eq!(info.canonical_prefix, "syscall");
    assert_eq!(info.section_prefix, "syscall");
    assert_eq!(info.attach_kind, ProgramAttachKind::Syscall);
    assert_eq!(info.target_kind, ProgramTargetKind::SyscallProgram);
    assert_eq!(info.context_family, ProgramContextFamily::Syscall);
    assert_eq!(info.arg_access, ProgramValueAccess::None);
    assert_eq!(info.retval_access, ProgramValueAccess::None);
    assert!(!EbpfProgramType::Syscall.supports_capability(ProgramCapability::Counters));
    assert!(EbpfProgramType::Syscall.supports_capability(ProgramCapability::HelperCalls));
}

#[test]
fn test_program_type_metadata_for_iter() {
    let info = EbpfProgramType::Iter.info();
    assert_eq!(info.canonical_prefix, "iter");
    assert_eq!(info.section_prefix, "iter");
    assert_eq!(info.attach_kind, ProgramAttachKind::Iter);
    assert_eq!(info.target_kind, ProgramTargetKind::BpfIteratorTarget);
    assert_eq!(info.context_family, ProgramContextFamily::Iter);
    assert_eq!(info.arg_access, ProgramValueAccess::None);
    assert_eq!(info.retval_access, ProgramValueAccess::None);
    assert!(EbpfProgramType::Iter.supports_capability(ProgramCapability::Counters));
    assert!(!EbpfProgramType::Iter.supports_capability(ProgramCapability::ReadUserString));
}

#[test]
fn test_bpf_map_type_constants_match_kernel_uapi() {
    assert_eq!(BpfMapType::CgroupArray as u32, 8);
    assert_eq!(BpfMapType::ArrayOfMaps as u32, 12);
    assert_eq!(BpfMapType::HashOfMaps as u32, 13);
    assert_eq!(BpfMapType::DevMap as u32, 14);
    assert_eq!(BpfMapType::SockMap as u32, 15);
    assert_eq!(BpfMapType::CpuMap as u32, 16);
    assert_eq!(BpfMapType::XskMap as u32, 17);
    assert_eq!(BpfMapType::SockHash as u32, 18);
    assert_eq!(BpfMapType::CgroupStorage as u32, 19);
    assert_eq!(BpfMapType::ReuseportSockArray as u32, 20);
    assert_eq!(BpfMapType::PerCpuCgroupStorage as u32, 21);
    assert_eq!(BpfMapType::SkStorage as u32, 24);
    assert_eq!(BpfMapType::DevMapHash as u32, 25);
    assert_eq!(BpfMapType::StructOps as u32, 26);
    assert_eq!(BpfMapType::RingBuf as u32, 27);
    assert_eq!(BpfMapType::InodeStorage as u32, 28);
    assert_eq!(BpfMapType::TaskStorage as u32, 29);
    assert_eq!(BpfMapType::BloomFilter as u32, 30);
    assert_eq!(BpfMapType::UserRingBuf as u32, 31);
    assert_eq!(BpfMapType::CgrpStorage as u32, 32);
    assert_eq!(BpfMapType::Arena as u32, 33);
}

#[test]
fn test_program_type_metadata_for_sock_ops() {
    let info = EbpfProgramType::SockOps.info();
    assert_eq!(info.canonical_prefix, "sock_ops");
    assert_eq!(info.attach_kind, ProgramAttachKind::SockOps);
    assert_eq!(info.target_kind, ProgramTargetKind::CgroupPath);
    assert_eq!(info.arg_access, ProgramValueAccess::None);
    assert_eq!(info.retval_access, ProgramValueAccess::None);
    assert!(EbpfProgramType::SockOps.supports_capability(ProgramCapability::KfuncCalls));
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
        Some(ProgramSpec::Xdp { target }) if target.interface == "lo" && !target.frags
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
        Some(ProgramSpec::Uprobe { target, .. })
            if target.binary_path == "/usr/bin/app"
                && target.function_name.as_deref() == Some("main")
                && target.offset == 16
    ));
}

#[test]
fn test_probe_context_new_preserves_full_sleepable_uprobe_spec() {
    let ctx = ProbeContext::new(EbpfProgramType::Uprobe, "uprobe.s:/usr/bin/app:main");

    assert_eq!(ctx.target(), "/usr/bin/app:main");
    assert!(matches!(
        ctx.parsed_program_spec(),
        Some(ProgramSpec::Uprobe {
            target,
            sleepable: true
        }) if target.binary_path == "/usr/bin/app"
            && target.function_name.as_deref() == Some("main")
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
fn test_program_type_ctx_field_load_guard_follows_context_layout() {
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
    let mut context_family_keys = HashSet::new();
    for family in [
        ProgramContextFamily::Probe,
        ProgramContextFamily::PerfEvent,
        ProgramContextFamily::Xdp,
        ProgramContextFamily::SkBuffPacket,
        ProgramContextFamily::SkLookup,
        ProgramContextFamily::FlowDissector,
        ProgramContextFamily::Netfilter,
        ProgramContextFamily::SkReuseport,
        ProgramContextFamily::SkMsg,
        ProgramContextFamily::SockOps,
        ProgramContextFamily::CgroupSock,
        ProgramContextFamily::CgroupSysctl,
        ProgramContextFamily::CgroupSockopt,
        ProgramContextFamily::CgroupSockAddr,
        ProgramContextFamily::CgroupDevice,
        ProgramContextFamily::LircMode2,
        ProgramContextFamily::StructOps,
        ProgramContextFamily::Extension,
        ProgramContextFamily::Syscall,
        ProgramContextFamily::Iter,
    ] {
        assert!(
            context_family_keys.insert(family.key()),
            "program context family key repeats for {family:?}"
        );
        assert_eq!(
            family.to_string(),
            family.key(),
            "{family:?} Display should use the machine-readable key"
        );
    }

    assert!(ProgramContextFamily::PerfEvent.is_perf_event());
    assert!(!ProgramContextFamily::Probe.is_perf_event());
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
    assert!(EbpfProgramType::SkReuseport.supports_socket_cookie_ctx_field());
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
fn test_program_type_raw_context_pointer_aliases_follow_context_layout() {
    assert!(EbpfProgramType::CgroupSock.ctx_field_is_raw_context_pointer(&CtxField::Context));
    assert!(EbpfProgramType::CgroupSock.ctx_field_is_raw_context_pointer(&CtxField::Socket));
    assert!(!EbpfProgramType::CgroupSockopt.ctx_field_is_raw_context_pointer(&CtxField::Socket));
    assert!(!EbpfProgramType::SockOps.ctx_field_is_raw_context_pointer(&CtxField::Socket));
}

#[test]
fn test_program_type_ctx_field_non_null_pointer_policy_follows_context_schema() {
    assert!(EbpfProgramType::Kprobe.ctx_field_pointer_is_non_null(&CtxField::Task));
    assert!(!EbpfProgramType::Xdp.ctx_field_pointer_is_non_null(&CtxField::Task));
    assert!(!EbpfProgramType::Iter.ctx_field_pointer_is_non_null(&CtxField::IterTask));
    assert!(EbpfProgramType::Iter.ctx_field_pointer_is_non_null(&CtxField::IterMeta));
    assert!(!EbpfProgramType::Iter.ctx_field_pointer_is_non_null(&CtxField::IterFile));
    assert!(!EbpfProgramType::Iter.ctx_field_pointer_is_non_null(&CtxField::IterVma));
    assert!(!EbpfProgramType::Iter.ctx_field_pointer_is_non_null(&CtxField::IterCgroup));
    assert!(!EbpfProgramType::Iter.ctx_field_pointer_is_non_null(&CtxField::IterMap));
    assert!(!EbpfProgramType::Iter.ctx_field_pointer_is_non_null(&CtxField::IterMapKey));
    assert!(!EbpfProgramType::Iter.ctx_field_pointer_is_non_null(&CtxField::IterMapValue));
    assert!(!EbpfProgramType::Iter.ctx_field_pointer_is_non_null(&CtxField::IterProg));
    assert!(!EbpfProgramType::Iter.ctx_field_pointer_is_non_null(&CtxField::IterLink));
    assert!(!EbpfProgramType::Iter.ctx_field_pointer_is_non_null(&CtxField::IterSkCommon));
    assert!(!EbpfProgramType::Iter.ctx_field_pointer_is_non_null(&CtxField::IterUdpSk));
    assert!(!EbpfProgramType::Iter.ctx_field_pointer_is_non_null(&CtxField::IterUnixSk));
    assert!(!EbpfProgramType::Iter.ctx_field_pointer_is_non_null(&CtxField::IterDmabuf));
    assert!(!EbpfProgramType::Iter.ctx_field_pointer_is_non_null(&CtxField::IterIpv6Route));
    assert!(!EbpfProgramType::Iter.ctx_field_pointer_is_non_null(&CtxField::IterKmemCache));
    assert!(!EbpfProgramType::Iter.ctx_field_pointer_is_non_null(&CtxField::IterKsym));
    assert!(!EbpfProgramType::Iter.ctx_field_pointer_is_non_null(&CtxField::IterNetlinkSk));
    assert!(!EbpfProgramType::Iter.ctx_field_pointer_is_non_null(&CtxField::IterSock));
    assert!(EbpfProgramType::CgroupSock.ctx_field_pointer_is_non_null(&CtxField::Socket));
    assert!(!EbpfProgramType::CgroupSockopt.ctx_field_pointer_is_non_null(&CtxField::Socket));
    assert!(EbpfProgramType::SkReuseport.ctx_field_pointer_is_non_null(&CtxField::Socket));
    assert!(
        !EbpfProgramType::SkReuseport.ctx_field_pointer_is_non_null(&CtxField::MigratingSocket)
    );
    assert!(EbpfProgramType::Netfilter.ctx_field_pointer_is_non_null(&CtxField::NetfilterState));
    assert!(EbpfProgramType::Netfilter.ctx_field_pointer_is_non_null(&CtxField::NetfilterSkb));

    let kprobe = ProbeContext::new(EbpfProgramType::Kprobe, "tcp_connect");
    assert!(kprobe.ctx_field_pointer_is_non_null(&CtxField::Task));
    assert!(ProbeContext::resolve_ctx_field_pointer_is_non_null(
        Some(&kprobe),
        &CtxField::Task
    ));

    let iter_task = ProbeContext::new(EbpfProgramType::Iter, "task");
    assert!(!iter_task.ctx_field_pointer_is_non_null(&CtxField::IterTask));
    assert!(iter_task.ctx_field_pointer_is_non_null(&CtxField::IterMeta));

    let iter_task_file = ProbeContext::new(EbpfProgramType::Iter, "task_file");
    assert!(!iter_task_file.ctx_field_pointer_is_non_null(&CtxField::IterFile));

    let iter_bpf_map = ProbeContext::new(EbpfProgramType::Iter, "bpf_map");
    assert!(!iter_bpf_map.ctx_field_pointer_is_non_null(&CtxField::IterMap));

    let reuseport = ProbeContext::new(EbpfProgramType::SkReuseport, "select");
    assert!(reuseport.ctx_field_pointer_is_non_null(&CtxField::Socket));
    assert!(!reuseport.ctx_field_pointer_is_non_null(&CtxField::MigratingSocket));
}

#[test]
fn test_program_type_ctx_field_trusted_btf_pointer_policy_follows_context_schema() {
    assert!(EbpfProgramType::Kprobe.ctx_field_is_trusted_btf_kernel_pointer(&CtxField::Task));
    assert!(!EbpfProgramType::Xdp.ctx_field_is_trusted_btf_kernel_pointer(&CtxField::Task));
    assert!(!EbpfProgramType::Iter.ctx_field_is_trusted_btf_kernel_pointer(&CtxField::IterTask));
    assert!(EbpfProgramType::Iter.ctx_field_is_trusted_btf_kernel_pointer(&CtxField::IterMeta));
    assert!(!EbpfProgramType::Iter.ctx_field_is_trusted_btf_kernel_pointer(&CtxField::IterFile));
    assert!(!EbpfProgramType::Iter.ctx_field_is_trusted_btf_kernel_pointer(&CtxField::IterVma));
    assert!(!EbpfProgramType::Iter.ctx_field_is_trusted_btf_kernel_pointer(&CtxField::IterCgroup));
    assert!(!EbpfProgramType::Iter.ctx_field_is_trusted_btf_kernel_pointer(&CtxField::IterMap));
    assert!(!EbpfProgramType::Iter.ctx_field_is_trusted_btf_kernel_pointer(&CtxField::IterMapKey));
    assert!(
        !EbpfProgramType::Iter.ctx_field_is_trusted_btf_kernel_pointer(&CtxField::IterMapValue)
    );
    assert!(!EbpfProgramType::Iter.ctx_field_is_trusted_btf_kernel_pointer(&CtxField::IterProg));
    assert!(!EbpfProgramType::Iter.ctx_field_is_trusted_btf_kernel_pointer(&CtxField::IterLink));
    assert!(
        !EbpfProgramType::Iter.ctx_field_is_trusted_btf_kernel_pointer(&CtxField::IterSkCommon)
    );
    assert!(!EbpfProgramType::Iter.ctx_field_is_trusted_btf_kernel_pointer(&CtxField::IterUdpSk));
    assert!(!EbpfProgramType::Iter.ctx_field_is_trusted_btf_kernel_pointer(&CtxField::IterUnixSk));
    assert!(!EbpfProgramType::Iter.ctx_field_is_trusted_btf_kernel_pointer(&CtxField::IterDmabuf));
    assert!(
        !EbpfProgramType::Iter.ctx_field_is_trusted_btf_kernel_pointer(&CtxField::IterIpv6Route)
    );
    assert!(
        !EbpfProgramType::Iter.ctx_field_is_trusted_btf_kernel_pointer(&CtxField::IterKmemCache)
    );
    assert!(!EbpfProgramType::Iter.ctx_field_is_trusted_btf_kernel_pointer(&CtxField::IterKsym));
    assert!(
        !EbpfProgramType::Iter.ctx_field_is_trusted_btf_kernel_pointer(&CtxField::IterNetlinkSk)
    );
    assert!(!EbpfProgramType::Iter.ctx_field_is_trusted_btf_kernel_pointer(&CtxField::IterSock));
    assert!(
        EbpfProgramType::Netfilter
            .ctx_field_is_trusted_btf_kernel_pointer(&CtxField::NetfilterState)
    );
    assert!(
        EbpfProgramType::Netfilter.ctx_field_is_trusted_btf_kernel_pointer(&CtxField::NetfilterSkb)
    );
    assert!(
        !EbpfProgramType::Kprobe.ctx_field_is_trusted_btf_kernel_pointer(&CtxField::NetfilterState)
    );

    let netfilter = ProbeContext::new(EbpfProgramType::Netfilter, "ipv4:pre_routing");
    assert!(netfilter.ctx_field_is_trusted_btf_kernel_pointer(&CtxField::NetfilterState));
    assert!(
        ProbeContext::resolve_ctx_field_is_trusted_btf_kernel_pointer(
            Some(&netfilter),
            &CtxField::NetfilterSkb
        )
    );
    assert!(ProbeContext::resolve_ctx_field_is_trusted_btf_kernel_pointer(None, &CtxField::Task));
    assert!(
        !ProbeContext::resolve_ctx_field_is_trusted_btf_kernel_pointer(
            None,
            &CtxField::NetfilterState
        )
    );
}

#[test]
fn test_static_context_field_btf_runtime_type_policy_follows_schema() {
    let task_spec = ProbeContext::static_ctx_field_type_spec(&CtxField::Task)
        .expect("expected ctx.task type spec");
    assert_eq!(task_spec.kernel_btf_runtime_type_name, Some("task_struct"));

    let iter_task_spec = ProbeContext::static_ctx_field_type_spec(&CtxField::IterTask)
        .expect("expected ctx.iter_task type spec");
    assert_eq!(
        iter_task_spec.kernel_btf_runtime_type_name,
        Some("task_struct")
    );

    let iter_meta_spec = ProbeContext::static_ctx_field_type_spec(&CtxField::IterMeta)
        .expect("expected ctx.iter_meta type spec");
    assert_eq!(
        iter_meta_spec.kernel_btf_runtime_type_name,
        Some("bpf_iter_meta")
    );

    let iter_file_spec = ProbeContext::static_ctx_field_type_spec(&CtxField::IterFile)
        .expect("expected ctx.iter_file type spec");
    assert_eq!(iter_file_spec.kernel_btf_runtime_type_name, Some("file"));

    let iter_vma_spec = ProbeContext::static_ctx_field_type_spec(&CtxField::IterVma)
        .expect("expected ctx.iter_vma type spec");
    assert_eq!(
        iter_vma_spec.kernel_btf_runtime_type_name,
        Some("vm_area_struct")
    );

    let iter_cgroup_spec = ProbeContext::static_ctx_field_type_spec(&CtxField::IterCgroup)
        .expect("expected ctx.iter_cgroup type spec");
    assert_eq!(
        iter_cgroup_spec.kernel_btf_runtime_type_name,
        Some("cgroup")
    );

    let iter_map_spec = ProbeContext::static_ctx_field_type_spec(&CtxField::IterMap)
        .expect("expected ctx.iter_map type spec");
    assert_eq!(iter_map_spec.kernel_btf_runtime_type_name, Some("bpf_map"));

    let iter_key_spec = ProbeContext::static_ctx_field_type_spec(&CtxField::IterMapKey)
        .expect("expected ctx.iter_key type spec");
    assert_eq!(iter_key_spec.kernel_btf_runtime_type_name, None);

    let iter_prog_spec = ProbeContext::static_ctx_field_type_spec(&CtxField::IterProg)
        .expect("expected ctx.iter_prog type spec");
    assert_eq!(
        iter_prog_spec.kernel_btf_runtime_type_name,
        Some("bpf_prog")
    );

    let iter_link_spec = ProbeContext::static_ctx_field_type_spec(&CtxField::IterLink)
        .expect("expected ctx.iter_link type spec");
    assert_eq!(
        iter_link_spec.kernel_btf_runtime_type_name,
        Some("bpf_link")
    );

    let iter_sk_common_spec = ProbeContext::static_ctx_field_type_spec(&CtxField::IterSkCommon)
        .expect("expected ctx.iter_sk_common type spec");
    assert_eq!(
        iter_sk_common_spec.kernel_btf_runtime_type_name,
        Some("sock_common")
    );

    let iter_udp_sk_spec = ProbeContext::static_ctx_field_type_spec(&CtxField::IterUdpSk)
        .expect("expected ctx.iter_udp_sk type spec");
    assert_eq!(
        iter_udp_sk_spec.kernel_btf_runtime_type_name,
        Some("udp_sock")
    );

    let iter_unix_sk_spec = ProbeContext::static_ctx_field_type_spec(&CtxField::IterUnixSk)
        .expect("expected ctx.iter_unix_sk type spec");
    assert_eq!(
        iter_unix_sk_spec.kernel_btf_runtime_type_name,
        Some("unix_sock")
    );

    for (field, expected) in [
        (CtxField::IterDmabuf, "dma_buf"),
        (CtxField::IterIpv6Route, "fib6_info"),
        (CtxField::IterKmemCache, "kmem_cache"),
        (CtxField::IterKsym, "kallsym_iter"),
        (CtxField::IterNetlinkSk, "netlink_sock"),
        (CtxField::IterSock, "sock"),
    ] {
        let spec = ProbeContext::static_ctx_field_type_spec(&field)
            .unwrap_or_else(|| panic!("expected {field:?} type spec"));
        assert_eq!(spec.kernel_btf_runtime_type_name, Some(expected));
    }

    let nf_state_spec = ProbeContext::static_ctx_field_type_spec(&CtxField::NetfilterState)
        .expect("expected ctx.state type spec");
    assert_eq!(
        nf_state_spec.kernel_btf_runtime_type_name,
        Some("nf_hook_state")
    );

    let nf_skb_spec = ProbeContext::static_ctx_field_type_spec(&CtxField::NetfilterSkb)
        .expect("expected ctx.skb type spec");
    assert_eq!(nf_skb_spec.kernel_btf_runtime_type_name, Some("sk_buff"));

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
        EbpfProgramType::Fexit.btf_callable_surface(),
        Some(ProgramBtfCallableSurface::FunctionTrampoline)
    );
    assert_eq!(
        EbpfProgramType::FmodRet.btf_callable_surface(),
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
        EbpfProgramType::LsmCgroup.btf_callable_surface(),
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
    let tcx_ingress = ProbeContext::new(EbpfProgramType::Tcx, "lo:ingress");
    let tcx_egress = ProbeContext::new(EbpfProgramType::Tcx, "lo:egress");
    let connect = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect4");
    let connect_unix = ProbeContext::new(
        EbpfProgramType::CgroupSockAddr,
        "/sys/fs/cgroup:connect_unix",
    );
    let bind = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:bind4");
    let recvmsg = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:recvmsg4");
    let getpeername = ProbeContext::new(
        EbpfProgramType::CgroupSockAddr,
        "/sys/fs/cgroup:getpeername4",
    );
    let sockopt_get = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");
    let sockopt_set = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:set");
    let sk_lookup = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");
    let netkit = ProbeContext::new(EbpfProgramType::Netkit, "nk0:primary");
    let xdp = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    assert!(ingress.helper_call_error(BpfHelper::RedirectPeer).is_none());
    assert!(ingress.helper_call_error(BpfHelper::SkAssign).is_none());
    assert!(
        tcx_ingress
            .helper_call_error(BpfHelper::RedirectPeer)
            .is_none()
    );
    assert!(tcx_ingress.helper_call_error(BpfHelper::SkAssign).is_none());
    assert_eq!(
        ingress.helper_call_error(BpfHelper::SkbCgroupId),
        Some("helper 'bpf_skb_cgroup_id' is only valid in tc/tcx egress programs".to_string())
    );
    assert_eq!(
        ingress.helper_call_error(BpfHelper::GetRouteRealm),
        Some("helper 'bpf_get_route_realm' is only valid in tc/tcx egress programs".to_string())
    );
    assert_eq!(
        egress.helper_call_error(BpfHelper::RedirectPeer),
        Some("helper 'bpf_redirect_peer' is only valid in tc/tcx ingress programs".to_string())
    );
    assert_eq!(
        egress.helper_call_error(BpfHelper::SkAssign),
        Some("helper 'bpf_sk_assign' is only valid in tc/tcx ingress programs".to_string())
    );
    assert_eq!(
        tcx_egress.helper_call_error(BpfHelper::SkAssign),
        Some("helper 'bpf_sk_assign' is only valid in tc/tcx ingress programs".to_string())
    );
    assert_eq!(
        netkit.helper_call_error(BpfHelper::SkAssign),
        Some(
            "helper 'bpf_sk_assign' is only valid in tc_action, tc, tcx, and sk_lookup programs"
                .to_string()
        )
    );
    assert!(
        egress
            .helper_call_error(BpfHelper::SkbAncestorCgroupId)
            .is_none()
    );
    assert!(
        tcx_egress
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
    assert_eq!(
        connect_unix.helper_call_error(BpfHelper::Bind),
        Some(
            "helper 'bpf_bind' is only valid on cgroup_sock_addr connect4/connect6 hooks"
                .to_string()
        )
    );
    assert!(
        connect_unix
            .helper_call_error(BpfHelper::GetSockOpt)
            .is_none()
    );
    assert!(
        connect_unix
            .helper_call_error(BpfHelper::SetSockOpt)
            .is_none()
    );
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
    assert!(bind.helper_call_error(BpfHelper::GetSockOpt).is_none());
    assert!(bind.helper_call_error(BpfHelper::SetSockOpt).is_none());
    assert!(bind.helper_call_error(BpfHelper::GetRetval).is_none());
    assert!(connect.helper_call_error(BpfHelper::SetRetval).is_none());
    assert_eq!(
        recvmsg.helper_call_error(BpfHelper::GetRetval),
        Some(
            "helper 'bpf_get_retval' is not valid on cgroup_sock_addr recvmsg/getpeername/getsockname hooks"
                .to_string()
        )
    );
    assert_eq!(
        getpeername.helper_call_error(BpfHelper::SetRetval),
        Some(
            "helper 'bpf_set_retval' is not valid on cgroup_sock_addr recvmsg/getpeername/getsockname hooks"
                .to_string()
        )
    );
}

#[test]
fn test_program_type_helper_call_error_covers_program_only_rules() {
    assert!(
        EbpfProgramType::CgroupDevice
            .helper_call_error(BpfHelper::GetRetval)
            .is_none()
    );
    assert!(
        EbpfProgramType::CgroupSock
            .helper_call_error(BpfHelper::SetRetval)
            .is_none()
    );
    assert!(
        EbpfProgramType::CgroupSysctl
            .helper_call_error(BpfHelper::GetRetval)
            .is_none()
    );
    assert_eq!(
        EbpfProgramType::CgroupSkb.helper_call_error(BpfHelper::GetRetval),
        Some(
            "helper 'bpf_get_retval' is only valid in cgroup_device, cgroup_sock, cgroup_sockopt, cgroup_sock_addr, and cgroup_sysctl programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::SockOps.helper_call_error(BpfHelper::SetRetval),
        Some(
            "helper 'bpf_set_retval' is only valid in cgroup_device, cgroup_sock, cgroup_sockopt, cgroup_sock_addr, and cgroup_sysctl programs"
                .to_string()
        )
    );
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
        Some(
            "helper 'bpf_redirect' is only valid in xdp, tc_action, tc, tcx, netkit, and lwt_xmit programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::RedirectMap),
        Some("helper 'bpf_redirect_map' is only valid in xdp programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::RedirectPeer),
        Some(
            "helper 'bpf_redirect_peer' is only valid in tc_action, tc, tcx, and netkit programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::SkbUnderCgroup),
        Some(
            "helper 'bpf_skb_under_cgroup' is only valid in tc_action, tc, tcx, netkit, and lwt_* programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::SkbCgroupId),
        Some(
            "helper 'bpf_skb_cgroup_id' is only valid in tc_action, tc, tcx, and netkit programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::SkbCgroupClassid),
        Some(
            "helper 'bpf_skb_cgroup_classid' is only valid in tc_action, tc, tcx, and netkit programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::GetCgroupClassid),
        Some(
            "helper 'bpf_get_cgroup_classid' is only valid in tc_action, tc, tcx, netkit, and lwt_* programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::GetRouteRealm),
        Some(
            "helper 'bpf_get_route_realm' is only valid in tc_action, tc, tcx, netkit, and lwt_* programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Lsm.helper_call_error(BpfHelper::PerfEventOutput),
        Some(
            "helper 'bpf_perf_event_output' is only valid in cgroup_device, cgroup_skb, cgroup_sock, cgroup_sockopt, cgroup_sock_addr, cgroup_sysctl, kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, uprobe, uretprobe, uprobe.multi, uretprobe.multi, perf_event, raw_tracepoint, raw_tracepoint.w, tracepoint, fentry, fexit, fmod_ret, tp_btf, socket_filter, lwt_*, tc_action, tc, tcx, netkit, sk_lookup, sk_msg, sk_skb, sk_skb_parser, sock_ops, and xdp programs"
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
            "helper 'bpf_get_func_arg' is only valid in fentry, fexit, fmod_ret, tp_btf, lsm, and lsm_cgroup programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::GetFuncArgCnt),
        Some(
            "helper 'bpf_get_func_arg_cnt' is only valid in fentry, fexit, fmod_ret, tp_btf, lsm, and lsm_cgroup programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Fentry.helper_call_error(BpfHelper::GetFuncRet),
        Some("helper 'bpf_get_func_ret' is only valid in fexit and fmod_ret programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::GetStackId),
        Some(
            "helper 'bpf_get_stackid' is only valid in kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, uprobe, uretprobe, uprobe.multi, uretprobe.multi, perf_event, raw_tracepoint, raw_tracepoint.w, tracepoint, fentry, fexit, fmod_ret, and tp_btf programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::GetStack),
        Some(
            "helper 'bpf_get_stack' is only valid in kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, uprobe, uretprobe, uprobe.multi, uretprobe.multi, perf_event, raw_tracepoint, raw_tracepoint.w, tracepoint, fentry, fexit, fmod_ret, and tp_btf programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::GetFuncIp),
        Some(
            "helper 'bpf_get_func_ip' is only valid in kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, uprobe, uretprobe, uprobe.multi, uretprobe.multi, perf_event, raw_tracepoint, raw_tracepoint.w, tracepoint, fentry, fexit, fmod_ret, and tp_btf programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::GetAttachCookie),
        Some(
            "helper 'bpf_get_attach_cookie' is only valid in kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, uprobe, uretprobe, uprobe.multi, uretprobe.multi, perf_event, raw_tracepoint, raw_tracepoint.w, tracepoint, fentry, fexit, fmod_ret, and tp_btf programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::ProbeRead),
        Some(
            "helper 'bpf_probe_read' is only valid in kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, uprobe, uretprobe, uprobe.multi, uretprobe.multi, lsm, lsm_cgroup, perf_event, raw_tracepoint, raw_tracepoint.w, tracepoint, fentry, fexit, fmod_ret, and tp_btf programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::ProbeReadStr),
        Some(
            "helper 'bpf_probe_read_str' is only valid in kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, uprobe, uretprobe, uprobe.multi, uretprobe.multi, lsm, lsm_cgroup, perf_event, raw_tracepoint, raw_tracepoint.w, tracepoint, fentry, fexit, fmod_ret, and tp_btf programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::ProbeWriteUser),
        Some(
            "helper 'bpf_probe_write_user' is only valid in kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, uprobe, uretprobe, uprobe.multi, uretprobe.multi, lsm, lsm_cgroup, perf_event, raw_tracepoint, raw_tracepoint.w, tracepoint, fentry, fexit, fmod_ret, and tp_btf programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::OverrideReturn),
        Some(
            "helper 'bpf_override_return' is only valid in kprobe, kprobe.multi, and ksyscall programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kretprobe.helper_call_error(BpfHelper::OverrideReturn),
        Some(
            "helper 'bpf_override_return' is only valid in kprobe, kprobe.multi, and ksyscall programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Uprobe.helper_call_error(BpfHelper::OverrideReturn),
        Some(
            "helper 'bpf_override_return' is only valid in kprobe, kprobe.multi, and ksyscall programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::SkLookup.helper_call_error(BpfHelper::GetSocketCookie),
        Some(
            "helper 'bpf_get_socket_cookie' is only valid in fentry, fexit, fmod_ret, tp_btf, socket_filter, tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock, cgroup_sock_addr, sock_ops, sk_reuseport, sk_skb, and sk_skb_parser programs"
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
            "helper 'bpf_skb_pull_data' is only valid in lwt_*, tc_action, tc, tcx, netkit, sk_skb, and sk_skb_parser programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::SkbLoadBytes),
        Some(
            "helper 'bpf_skb_load_bytes' is only valid in flow_dissector, socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, sk_reuseport, sk_skb, and sk_skb_parser programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::SkSkb.helper_call_error(BpfHelper::SkbLoadBytesRelative),
        Some(
            "helper 'bpf_skb_load_bytes_relative' is only valid in socket_filter, tc_action, tc, tcx, netkit, cgroup_skb, and sk_reuseport programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::SkbStoreBytes),
        Some(
            "helper 'bpf_skb_store_bytes' is only valid in lwt_xmit, tc_action, tc, tcx, netkit, sk_skb, and sk_skb_parser programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::CloneRedirect),
        Some(
            "helper 'bpf_clone_redirect' is only valid in lwt_xmit, tc_action, tc, tcx, netkit, sk_skb, and sk_skb_parser programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::L3CsumReplace),
        Some(
            "helper 'bpf_l3_csum_replace' is only valid in lwt_xmit, tc_action, tc, tcx, netkit, sk_skb, and sk_skb_parser programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::CsumDiff),
        Some(
            "helper 'bpf_csum_diff' is only valid in xdp, tc_action, tc, tcx, netkit, and lwt_* programs"
                .to_string()
        )
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
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::SkSelectReuseport),
        Some("helper 'bpf_sk_select_reuseport' is only valid in sk_reuseport programs".to_string())
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
            "helper 'bpf_sk_lookup_tcp' is only valid in xdp, tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock_addr, and sk_skb programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::SkRelease),
        Some(
            "helper 'bpf_sk_release' is only valid in xdp, tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock_addr, sk_lookup, and sk_skb programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::SkAssign),
        Some(
            "helper 'bpf_sk_assign' is only valid in tc_action, tc, tcx, and sk_lookup programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::GetListenerSock),
        Some(
            "helper 'bpf_get_listener_sock' is only valid in tc_action, tc, tcx, netkit, and cgroup_skb programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::SkFullsock),
        Some(
            "helper 'bpf_sk_fullsock' is only valid in tc_action, tc, tcx, netkit, and cgroup_skb programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::TcpSock),
        Some(
            "helper 'bpf_tcp_sock' is only valid in tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sockopt, and sock_ops programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::SkcToTcpSock),
        Some(
            "helper 'bpf_skc_to_tcp_sock' is only valid in xdp, flow_dissector, socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock_addr, fentry, fexit, fmod_ret, tp_btf, sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::SkcToUnixSock),
        Some(
            "helper 'bpf_skc_to_unix_sock' is only valid in xdp, flow_dissector, socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock_addr, fentry, fexit, fmod_ret, tp_btf, sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::SockFromFile),
        Some(
            "helper 'bpf_sock_from_file' is only valid in fentry, fexit, fmod_ret, and tp_btf programs"
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
        Some(
            "helper 'bpf_tcp_check_syncookie' is only valid in xdp, tc_action, tc, tcx, and netkit programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::TcpGenSyncookie),
        Some(
            "helper 'bpf_tcp_gen_syncookie' is only valid in xdp, tc_action, tc, tcx, and netkit programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::TcpRawCheckSyncookieIpv4),
        Some(
            "helper 'bpf_tcp_raw_check_syncookie_ipv4' is only valid in xdp, tc_action, tc, tcx, and netkit programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::TcpSendAck),
        Some(
            "helper 'bpf_tcp_send_ack' is only valid in tcp_congestion_ops struct_ops programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::SysBpf),
        Some("helper 'bpf_sys_bpf' is only valid in syscall programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::Syscall.helper_call_error(BpfHelper::GetCurrentPidTgid),
        Some("helper 'bpf_get_current_pid_tgid' is not modeled for syscall programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::TaskStorageGet),
        Some(
            "helper 'bpf_task_storage_get' is only valid in kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, uprobe, uretprobe, uprobe.multi, uretprobe.multi, perf_event, raw_tracepoint, raw_tracepoint.w, tracepoint, fentry, fexit, fmod_ret, tp_btf, lsm, and lsm_cgroup programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::GetLocalStorage),
        Some(
            "helper 'bpf_get_local_storage' is only valid in cgroup_device, cgroup_skb, cgroup_sock, cgroup_sock_addr, cgroup_sockopt, cgroup_sysctl, and sock_ops programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::TaskStorageDelete),
        Some(
            "helper 'bpf_task_storage_delete' is only valid in kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, uprobe, uretprobe, uprobe.multi, uretprobe.multi, perf_event, raw_tracepoint, raw_tracepoint.w, tracepoint, fentry, fexit, fmod_ret, tp_btf, lsm, and lsm_cgroup programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::GetCurrentTaskBtf),
        Some(
            "helper 'bpf_get_current_task_btf' is only valid in kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, uprobe, uretprobe, uprobe.multi, uretprobe.multi, perf_event, raw_tracepoint, raw_tracepoint.w, tracepoint, fentry, fexit, fmod_ret, tp_btf, lsm, and lsm_cgroup programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::GetCurrentTask),
        Some(
            "helper 'bpf_get_current_task' is only valid in kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, uprobe, uretprobe, uprobe.multi, uretprobe.multi, perf_event, raw_tracepoint, raw_tracepoint.w, tracepoint, fentry, fexit, fmod_ret, tp_btf, lsm, and lsm_cgroup programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::TaskPtRegs),
        Some(
            "helper 'bpf_task_pt_regs' is only valid in kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, uprobe, uretprobe, uprobe.multi, uretprobe.multi, perf_event, raw_tracepoint, raw_tracepoint.w, tracepoint, fentry, fexit, fmod_ret, tp_btf, lsm, and lsm_cgroup programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::InodeStorageGet),
        Some(
            "helper 'bpf_inode_storage_get' is only valid in lsm and lsm_cgroup programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::InodeStorageDelete),
        Some(
            "helper 'bpf_inode_storage_delete' is only valid in lsm and lsm_cgroup programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::BprmOptsSet),
        Some("helper 'bpf_bprm_opts_set' is only valid in lsm and lsm_cgroup programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::ImaInodeHash),
        Some(
            "helper 'bpf_ima_inode_hash' is only valid in lsm and lsm_cgroup programs".to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::ImaFileHash),
        Some("helper 'bpf_ima_file_hash' is only valid in lsm and lsm_cgroup programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::SkStorageGet),
        Some(
            "helper 'bpf_sk_storage_get' is only valid in tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock, cgroup_sock_addr, cgroup_sockopt, sock_ops, sk_msg, struct_ops, fentry, fexit, fmod_ret, tp_btf, lsm, and lsm_cgroup programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::SkStorageDelete),
        Some(
            "helper 'bpf_sk_storage_delete' is only valid in tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock_addr, cgroup_sockopt, sock_ops, sk_msg, struct_ops, fentry, fexit, fmod_ret, tp_btf, lsm, and lsm_cgroup programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::CgroupSock.helper_call_error(BpfHelper::SkStorageDelete),
        Some(
            "helper 'bpf_sk_storage_delete' is only valid in tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock_addr, cgroup_sockopt, sock_ops, sk_msg, struct_ops, fentry, fexit, fmod_ret, tp_btf, lsm, and lsm_cgroup programs"
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
        EbpfProgramType::LwtOut.helper_call_error(BpfHelper::PerfEventOutput),
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
        EbpfProgramType::Fentry.helper_call_error(BpfHelper::SkbOutput),
        None
    );
    assert_eq!(
        EbpfProgramType::Tracepoint.helper_call_error(BpfHelper::XdpOutput),
        None
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::XdpOutput),
        Some(
            "helper 'bpf_xdp_output' is only valid in kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, uprobe, uretprobe, uprobe.multi, uretprobe.multi, perf_event, raw_tracepoint, raw_tracepoint.w, tracepoint, fentry, fexit, fmod_ret, and tp_btf programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::ProbeRead),
        None
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::ProbeReadStr),
        None
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::ProbeWriteUser),
        None
    );
    assert_eq!(
        EbpfProgramType::Kprobe.helper_call_error(BpfHelper::OverrideReturn),
        None
    );
    assert_eq!(
        EbpfProgramType::KprobeMulti.helper_call_error(BpfHelper::OverrideReturn),
        None
    );
    assert_eq!(
        EbpfProgramType::Ksyscall.helper_call_error(BpfHelper::OverrideReturn),
        None
    );
    assert_eq!(
        EbpfProgramType::SocketFilter.helper_call_error(BpfHelper::GetSocketCookie),
        None
    );
    assert_eq!(
        EbpfProgramType::SkReuseport.helper_call_error(BpfHelper::GetSocketCookie),
        None
    );
    assert_eq!(
        EbpfProgramType::Tc.helper_call_error(BpfHelper::GetSocketUid),
        None
    );
    assert_eq!(
        EbpfProgramType::TcAction.helper_call_error(BpfHelper::GetSocketCookie),
        None
    );
    assert_eq!(
        EbpfProgramType::TcAction.helper_call_error(BpfHelper::GetSocketUid),
        None
    );
    assert_eq!(
        EbpfProgramType::TcAction.helper_call_error(BpfHelper::GetNetnsCookie),
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
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::CheckMtu),
        None
    );
    assert_eq!(
        EbpfProgramType::Tc.helper_call_error(BpfHelper::CheckMtu),
        None
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::FibLookup),
        None
    );
    assert_eq!(
        EbpfProgramType::TcAction.helper_call_error(BpfHelper::FibLookup),
        None
    );
    assert_eq!(
        EbpfProgramType::Tc.helper_call_error(BpfHelper::SkbEcnSetCe),
        None
    );
    assert_eq!(
        EbpfProgramType::Tc.helper_call_error(BpfHelper::SkbCgroupClassid),
        None
    );
    assert_eq!(
        EbpfProgramType::Tc.helper_call_error(BpfHelper::SkbChangeProto),
        None
    );
    assert_eq!(
        EbpfProgramType::TcAction.helper_call_error(BpfHelper::SkbChangeType),
        None
    );
    assert_eq!(
        EbpfProgramType::Tc.helper_call_error(BpfHelper::SkbGetXfrmState),
        None
    );
    assert_eq!(
        EbpfProgramType::Tc.helper_call_error(BpfHelper::SkbGetTunnelKey),
        None
    );
    assert_eq!(
        EbpfProgramType::LwtXmit.helper_call_error(BpfHelper::SkbSetTunnelKey),
        None
    );
    assert_eq!(
        EbpfProgramType::TcAction.helper_call_error(BpfHelper::SkbGetTunnelOpt),
        None
    );
    assert_eq!(
        EbpfProgramType::LwtXmit.helper_call_error(BpfHelper::SkbSetTunnelOpt),
        None
    );
    assert_eq!(
        EbpfProgramType::CgroupSkb.helper_call_error(BpfHelper::SkbEcnSetCe),
        None
    );
    assert_eq!(
        EbpfProgramType::TcAction.helper_call_error(BpfHelper::CheckMtu),
        None
    );
    assert_eq!(
        EbpfProgramType::Tc.helper_call_error(BpfHelper::SkbUnderCgroup),
        None
    );
    assert_eq!(
        EbpfProgramType::LwtOut.helper_call_error(BpfHelper::SkbUnderCgroup),
        None
    );
    assert_eq!(
        EbpfProgramType::LwtOut.helper_call_error(BpfHelper::GetCgroupClassid),
        None
    );
    assert_eq!(
        EbpfProgramType::LwtOut.helper_call_error(BpfHelper::GetRouteRealm),
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
        EbpfProgramType::FlowDissector.helper_call_error(BpfHelper::SkbLoadBytes),
        None
    );
    assert_eq!(
        EbpfProgramType::LwtOut.helper_call_error(BpfHelper::SkbLoadBytes),
        None
    );
    assert_eq!(
        EbpfProgramType::CgroupSkb.helper_call_error(BpfHelper::SkbLoadBytesRelative),
        None
    );
    assert_eq!(
        EbpfProgramType::SkReuseport.helper_call_error(BpfHelper::SkbLoadBytes),
        None
    );
    assert_eq!(
        EbpfProgramType::SkReuseport.helper_call_error(BpfHelper::SkbLoadBytesRelative),
        None
    );
    assert_eq!(
        EbpfProgramType::SkSkb.helper_call_error(BpfHelper::SkbAdjustRoom),
        None
    );
    assert_eq!(
        EbpfProgramType::SkSkb.helper_call_error(BpfHelper::SkbSetTstamp),
        Some(
            "helper 'bpf_skb_set_tstamp' is only valid in tc_action, tc, tcx, and netkit programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::SkSkb.helper_call_error(BpfHelper::CheckMtu),
        Some(
            "helper 'bpf_check_mtu' is only valid in xdp, tc_action, tc, tcx, and netkit programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::SkSkb.helper_call_error(BpfHelper::SkbEcnSetCe),
        Some(
            "helper 'bpf_skb_ecn_set_ce' is only valid in tc_action, tc, tcx, netkit, and cgroup_skb programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::SkSkb.helper_call_error(BpfHelper::SkbChangeProto),
        Some(
            "helper 'bpf_skb_change_proto' is only valid in tc_action, tc, tcx, and netkit programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::CgroupSkb.helper_call_error(BpfHelper::SkbChangeType),
        Some(
            "helper 'bpf_skb_change_type' is only valid in tc_action, tc, tcx, and netkit programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::SkbGetXfrmState),
        Some(
            "helper 'bpf_skb_get_xfrm_state' is only valid in tc_action, tc, tcx, and netkit programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::LwtOut.helper_call_error(BpfHelper::SkbGetTunnelKey),
        Some(
            "helper 'bpf_skb_get_tunnel_key' is only valid in tc_action, tc, tcx, netkit, and lwt_xmit programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::SkSkb.helper_call_error(BpfHelper::SkbSetTunnelOpt),
        Some(
            "helper 'bpf_skb_set_tunnel_opt' is only valid in tc_action, tc, tcx, netkit, and lwt_xmit programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::SkSkb.helper_call_error(BpfHelper::FibLookup),
        Some(
            "helper 'bpf_fib_lookup' is only valid in xdp, tc_action, tc, tcx, and netkit programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::Tc.helper_call_error(BpfHelper::SkbStoreBytes),
        None
    );
    assert_eq!(
        EbpfProgramType::LwtXmit.helper_call_error(BpfHelper::Redirect),
        None
    );
    assert_eq!(
        EbpfProgramType::LwtXmit.helper_call_error(BpfHelper::SkbStoreBytes),
        None
    );
    assert_eq!(
        EbpfProgramType::LwtXmit.helper_call_error(BpfHelper::SkbChangeHead),
        None
    );
    assert_eq!(
        EbpfProgramType::LwtXmit.helper_call_error(BpfHelper::SkbChangeTail),
        None
    );
    assert_eq!(
        EbpfProgramType::LwtXmit.helper_call_error(BpfHelper::CloneRedirect),
        None
    );
    assert_eq!(
        EbpfProgramType::LwtXmit.helper_call_error(BpfHelper::CsumLevel),
        None
    );
    assert_eq!(
        EbpfProgramType::LwtIn.helper_call_error(BpfHelper::LwtPushEncap),
        None
    );
    assert_eq!(
        EbpfProgramType::LwtXmit.helper_call_error(BpfHelper::LwtPushEncap),
        None
    );
    assert_eq!(
        EbpfProgramType::LwtOut.helper_call_error(BpfHelper::LwtPushEncap),
        Some(
            "helper 'bpf_lwt_push_encap' is only valid in lwt_in and lwt_xmit programs".to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::LwtSeg6Local.helper_call_error(BpfHelper::LwtSeg6StoreBytes),
        None
    );
    assert_eq!(
        EbpfProgramType::LwtSeg6Local.helper_call_error(BpfHelper::LwtSeg6AdjustSrh),
        None
    );
    assert_eq!(
        EbpfProgramType::LwtSeg6Local.helper_call_error(BpfHelper::LwtSeg6Action),
        None
    );
    assert_eq!(
        EbpfProgramType::LwtXmit.helper_call_error(BpfHelper::LwtSeg6Action),
        Some("helper 'bpf_lwt_seg6_action' is only valid in lwt_seg6local programs".to_string())
    );
    assert_eq!(
        EbpfProgramType::LwtOut.helper_call_error(BpfHelper::SkbStoreBytes),
        Some(
            "helper 'bpf_skb_store_bytes' is only valid in lwt_xmit, tc_action, tc, tcx, netkit, sk_skb, and sk_skb_parser programs"
                .to_string()
        )
    );
    assert_eq!(
        EbpfProgramType::SkSkb.helper_call_error(BpfHelper::GetHashRecalc),
        None
    );
    assert_eq!(
        EbpfProgramType::LwtOut.helper_call_error(BpfHelper::SkbPullData),
        None
    );
    assert_eq!(
        EbpfProgramType::LwtOut.helper_call_error(BpfHelper::GetHashRecalc),
        None
    );
    assert_eq!(
        EbpfProgramType::LwtOut.helper_call_error(BpfHelper::CsumDiff),
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
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::SkcToTcpSock),
        None
    );
    assert_eq!(
        EbpfProgramType::Tc.helper_call_error(BpfHelper::SkcToTcpSock),
        None
    );
    assert_eq!(
        EbpfProgramType::FlowDissector.helper_call_error(BpfHelper::SkcToTcpSock),
        None
    );
    assert_eq!(
        EbpfProgramType::LwtOut.helper_call_error(BpfHelper::SkcToTcpSock),
        None
    );
    assert_eq!(
        EbpfProgramType::CgroupSockAddr.helper_call_error(BpfHelper::SkcToTcpSock),
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
        EbpfProgramType::Xdp.helper_call_error(BpfHelper::TcpRawGenSyncookieIpv4),
        None
    );
    assert_eq!(
        EbpfProgramType::Tc.helper_call_error(BpfHelper::TcpRawCheckSyncookieIpv6),
        None
    );
    assert_eq!(
        EbpfProgramType::StructOps.helper_call_error(BpfHelper::TcpSendAck),
        None
    );
    for helper in [
        BpfHelper::SysBpf,
        BpfHelper::BtfFindByNameKind,
        BpfHelper::SysClose,
        BpfHelper::KallsymsLookupName,
    ] {
        assert_eq!(
            EbpfProgramType::Syscall.helper_call_error(helper),
            None,
            "syscall should allow helper {}",
            helper.name()
        );
    }
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
        EbpfProgramType::LsmCgroup.helper_call_error(BpfHelper::InodeStorageGet),
        None
    );
    assert_eq!(
        EbpfProgramType::LsmCgroup.helper_call_error(BpfHelper::InodeStorageDelete),
        None
    );
    assert_eq!(
        EbpfProgramType::Lsm.helper_call_error(BpfHelper::BprmOptsSet),
        None
    );
    assert_eq!(
        EbpfProgramType::LsmCgroup.helper_call_error(BpfHelper::BprmOptsSet),
        None
    );
    assert_eq!(
        EbpfProgramType::Lsm.helper_call_error(BpfHelper::ImaInodeHash),
        None
    );
    assert_eq!(
        EbpfProgramType::Lsm.helper_call_error(BpfHelper::ImaFileHash),
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
    for program_type in [
        EbpfProgramType::CgroupDevice,
        EbpfProgramType::CgroupSkb,
        EbpfProgramType::CgroupSock,
        EbpfProgramType::CgroupSockAddr,
        EbpfProgramType::CgroupSockopt,
        EbpfProgramType::CgroupSysctl,
        EbpfProgramType::SockOps,
    ] {
        assert_eq!(
            program_type.helper_call_error(BpfHelper::GetLocalStorage),
            None,
            "{program_type:?} should allow bpf_get_local_storage"
        );
    }

    for helper in [
        BpfHelper::Redirect,
        BpfHelper::RedirectPeer,
        BpfHelper::RedirectNeigh,
        BpfHelper::SkbChangeProto,
        BpfHelper::SkbChangeType,
        BpfHelper::SkbGetXfrmState,
        BpfHelper::SkbGetTunnelKey,
        BpfHelper::SkbSetTunnelKey,
        BpfHelper::SkbGetTunnelOpt,
        BpfHelper::SkbSetTunnelOpt,
        BpfHelper::SkbSetTstamp,
        BpfHelper::CheckMtu,
        BpfHelper::SkbPullData,
        BpfHelper::SkbStoreBytes,
        BpfHelper::SkbChangeHead,
        BpfHelper::SkbChangeTail,
        BpfHelper::SkbAdjustRoom,
        BpfHelper::CsumDiff,
        BpfHelper::CsumLevel,
        BpfHelper::GetHashRecalc,
        BpfHelper::GetCgroupClassid,
        BpfHelper::GetRouteRealm,
        BpfHelper::SkbCgroupClassid,
        BpfHelper::SkbCgroupId,
        BpfHelper::SkbAncestorCgroupId,
        BpfHelper::SkbLoadBytes,
        BpfHelper::SkbLoadBytesRelative,
        BpfHelper::SkLookupTcp,
        BpfHelper::FibLookup,
        BpfHelper::SkRelease,
        BpfHelper::SkAssign,
        BpfHelper::GetListenerSock,
        BpfHelper::SkFullsock,
        BpfHelper::SkbEcnSetCe,
        BpfHelper::TcpSock,
        BpfHelper::SkcToTcpSock,
        BpfHelper::SkStorageGet,
        BpfHelper::SkStorageDelete,
        BpfHelper::PerfEventOutput,
    ] {
        assert_eq!(
            EbpfProgramType::TcAction.helper_call_error(helper),
            None,
            "tc_action should allow helper {}",
            helper.name()
        );
    }
}

#[test]
fn test_probe_context_helper_call_error_refines_tcp_congestion_struct_ops_helpers() {
    let tcp = ProbeContext::new_struct_ops_callback("tcp_congestion_ops", "cong_avoid");
    assert_eq!(tcp.helper_call_error(BpfHelper::TcpSendAck), None);

    let sched_ext = ProbeContext::new_struct_ops_callback("sched_ext_ops", "select_cpu");
    assert_eq!(
        sched_ext.helper_call_error(BpfHelper::TcpSendAck),
        Some(
            "helper 'bpf_tcp_send_ack' is only valid in tcp_congestion_ops struct_ops programs"
                .to_string()
        )
    );
}

#[test]
fn test_current_task_under_cgroup_is_base_helper_surface() {
    for program_type in [
        EbpfProgramType::Kprobe,
        EbpfProgramType::Kretprobe,
        EbpfProgramType::Fentry,
        EbpfProgramType::Fexit,
        EbpfProgramType::TpBtf,
        EbpfProgramType::Tracepoint,
        EbpfProgramType::RawTracepoint,
        EbpfProgramType::Uprobe,
        EbpfProgramType::Uretprobe,
        EbpfProgramType::Lsm,
        EbpfProgramType::LsmCgroup,
        EbpfProgramType::Xdp,
        EbpfProgramType::PerfEvent,
        EbpfProgramType::SocketFilter,
        EbpfProgramType::LwtIn,
        EbpfProgramType::LwtOut,
        EbpfProgramType::LwtXmit,
        EbpfProgramType::LwtSeg6Local,
        EbpfProgramType::CgroupDevice,
        EbpfProgramType::SkLookup,
        EbpfProgramType::SkMsg,
        EbpfProgramType::SkSkb,
        EbpfProgramType::SkSkbParser,
        EbpfProgramType::SockOps,
        EbpfProgramType::Tc,
        EbpfProgramType::Tcx,
        EbpfProgramType::Netkit,
        EbpfProgramType::CgroupSkb,
        EbpfProgramType::CgroupSock,
        EbpfProgramType::CgroupSysctl,
        EbpfProgramType::CgroupSockopt,
        EbpfProgramType::CgroupSockAddr,
        EbpfProgramType::LircMode2,
        EbpfProgramType::StructOps,
    ] {
        assert_eq!(
            program_type.helper_call_error(BpfHelper::CurrentTaskUnderCgroup),
            None,
            "{program_type:?} should be able to call bpf_current_task_under_cgroup"
        );
    }
}

#[test]
fn test_cgroup_array_membership_helper_follows_program_model() {
    assert!(matches!(
        EbpfProgramType::TcAction.cgroup_array_membership_helper(),
        BpfHelper::SkbUnderCgroup
    ));
    assert!(matches!(
        EbpfProgramType::Tc.cgroup_array_membership_helper(),
        BpfHelper::SkbUnderCgroup
    ));
    assert!(matches!(
        EbpfProgramType::Tcx.cgroup_array_membership_helper(),
        BpfHelper::SkbUnderCgroup
    ));
    assert!(matches!(
        EbpfProgramType::Netkit.cgroup_array_membership_helper(),
        BpfHelper::SkbUnderCgroup
    ));
    assert!(matches!(
        EbpfProgramType::LwtIn.cgroup_array_membership_helper(),
        BpfHelper::SkbUnderCgroup
    ));
    assert!(matches!(
        EbpfProgramType::LwtOut.cgroup_array_membership_helper(),
        BpfHelper::SkbUnderCgroup
    ));
    assert!(matches!(
        EbpfProgramType::LwtXmit.cgroup_array_membership_helper(),
        BpfHelper::SkbUnderCgroup
    ));
    assert!(matches!(
        EbpfProgramType::LwtSeg6Local.cgroup_array_membership_helper(),
        BpfHelper::SkbUnderCgroup
    ));
    assert!(matches!(
        EbpfProgramType::Xdp.cgroup_array_membership_helper(),
        BpfHelper::CurrentTaskUnderCgroup
    ));
    assert!(matches!(
        EbpfProgramType::Kprobe.cgroup_array_membership_helper(),
        BpfHelper::CurrentTaskUnderCgroup
    ));

    for program_type in [
        EbpfProgramType::TcAction,
        EbpfProgramType::Tc,
        EbpfProgramType::Tcx,
        EbpfProgramType::Netkit,
        EbpfProgramType::LwtIn,
        EbpfProgramType::LwtOut,
        EbpfProgramType::LwtXmit,
        EbpfProgramType::LwtSeg6Local,
        EbpfProgramType::Xdp,
        EbpfProgramType::Kprobe,
    ] {
        let helper = program_type.cgroup_array_membership_helper();
        assert_eq!(
            program_type.helper_call_error(helper),
            None,
            "{program_type:?} selected invalid cgroup-array membership helper {helper:?}"
        );
    }
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
        EbpfProgramType::Tcx.packet_redirect_helper(),
        Some(BpfHelper::Redirect)
    ));
    assert!(matches!(
        EbpfProgramType::Netkit.packet_redirect_helper(),
        Some(BpfHelper::Redirect)
    ));
    assert!(matches!(
        EbpfProgramType::TcAction.packet_redirect_helper(),
        Some(BpfHelper::Redirect)
    ));
    assert!(matches!(
        EbpfProgramType::LwtXmit.packet_redirect_helper(),
        Some(BpfHelper::Redirect)
    ));
    assert!(matches!(
        EbpfProgramType::TcAction.packet_redirect_peer_helper(),
        Some(BpfHelper::RedirectPeer)
    ));
    assert!(matches!(
        EbpfProgramType::Tc.packet_redirect_peer_helper(),
        Some(BpfHelper::RedirectPeer)
    ));
    assert!(matches!(
        EbpfProgramType::Tcx.packet_redirect_peer_helper(),
        Some(BpfHelper::RedirectPeer)
    ));
    assert!(matches!(
        EbpfProgramType::Netkit.packet_redirect_peer_helper(),
        Some(BpfHelper::RedirectPeer)
    ));
    assert!(matches!(
        EbpfProgramType::TcAction.packet_redirect_neigh_helper(),
        Some(BpfHelper::RedirectNeigh)
    ));
    assert!(matches!(
        EbpfProgramType::Tc.packet_redirect_neigh_helper(),
        Some(BpfHelper::RedirectNeigh)
    ));
    assert!(matches!(
        EbpfProgramType::Tcx.packet_redirect_neigh_helper(),
        Some(BpfHelper::RedirectNeigh)
    ));
    assert!(matches!(
        EbpfProgramType::Netkit.packet_redirect_neigh_helper(),
        Some(BpfHelper::RedirectNeigh)
    ));
    assert!(EbpfProgramType::Xdp.packet_redirect_peer_helper().is_none());
    assert!(EbpfProgramType::LwtOut.packet_redirect_helper().is_none());
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
        EbpfProgramType::TcAction.packet_adjust_helper(PacketAdjustMode::Head),
        Some(BpfHelper::SkbChangeHead)
    ));
    assert!(matches!(
        EbpfProgramType::Tc.packet_adjust_helper(PacketAdjustMode::Head),
        Some(BpfHelper::SkbChangeHead)
    ));
    assert!(matches!(
        EbpfProgramType::Tcx.packet_adjust_helper(PacketAdjustMode::Head),
        Some(BpfHelper::SkbChangeHead)
    ));
    assert!(matches!(
        EbpfProgramType::Netkit.packet_adjust_helper(PacketAdjustMode::Head),
        Some(BpfHelper::SkbChangeHead)
    ));
    assert!(matches!(
        EbpfProgramType::TcAction.packet_adjust_helper(PacketAdjustMode::Tail),
        Some(BpfHelper::SkbChangeTail)
    ));
    assert!(matches!(
        EbpfProgramType::Tc.packet_adjust_helper(PacketAdjustMode::Tail),
        Some(BpfHelper::SkbChangeTail)
    ));
    assert!(matches!(
        EbpfProgramType::Tcx.packet_adjust_helper(PacketAdjustMode::Tail),
        Some(BpfHelper::SkbChangeTail)
    ));
    assert!(matches!(
        EbpfProgramType::Netkit.packet_adjust_helper(PacketAdjustMode::Tail),
        Some(BpfHelper::SkbChangeTail)
    ));
    assert!(matches!(
        EbpfProgramType::LwtXmit.packet_adjust_helper(PacketAdjustMode::Head),
        Some(BpfHelper::SkbChangeHead)
    ));
    assert!(matches!(
        EbpfProgramType::LwtXmit.packet_adjust_helper(PacketAdjustMode::Tail),
        Some(BpfHelper::SkbChangeTail)
    ));
    assert!(matches!(
        EbpfProgramType::SkSkb.packet_adjust_helper(PacketAdjustMode::Pull),
        Some(BpfHelper::SkbPullData)
    ));
    assert!(matches!(
        EbpfProgramType::TcAction.packet_adjust_helper(PacketAdjustMode::Pull),
        Some(BpfHelper::SkbPullData)
    ));
    assert!(matches!(
        EbpfProgramType::LwtOut.packet_adjust_helper(PacketAdjustMode::Pull),
        Some(BpfHelper::SkbPullData)
    ));
    assert!(matches!(
        EbpfProgramType::TcAction.packet_adjust_helper(PacketAdjustMode::Room),
        Some(BpfHelper::SkbAdjustRoom)
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
        EbpfProgramType::LwtOut
            .packet_adjust_helper(PacketAdjustMode::Head)
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
    assert!(matches!(
        EbpfProgramType::SkReuseport.socket_redirect_helper(MapKind::ReuseportSockArray),
        Some(BpfHelper::SkSelectReuseport)
    ));
    assert!(
        EbpfProgramType::SkReuseport
            .socket_redirect_helper(MapKind::SockMap)
            .is_none()
    );
    assert!(
        EbpfProgramType::Xdp
            .socket_redirect_helper(MapKind::SockMap)
            .is_none()
    );
    assert_eq!(
        EbpfProgramType::SkMsg
            .socket_redirect_error("redirect-socket", MapKind::ReuseportSockArray)
            .as_deref(),
        Some("redirect-socket --kind reuseport-sockarray is only valid in sk_reuseport programs")
    );
    assert_eq!(
        EbpfProgramType::SkReuseport
            .socket_redirect_error("redirect-socket", MapKind::SockMap)
            .as_deref(),
        Some(
            "redirect-socket --kind sockmap/sockhash is only valid in sk_msg, sk_skb, and sk_skb_parser programs"
        )
    );
    assert_eq!(
        EbpfProgramType::Xdp
            .socket_redirect_error("redirect-socket", MapKind::SockMap)
            .as_deref(),
        Some(
            "redirect-socket is only valid in sk_msg, sk_skb, sk_skb_parser, and sk_reuseport programs"
        )
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
        EbpfProgramType::Tcx.helper_zero_arg_requirement(BpfHelper::SkAssign),
        Some((
            2,
            "helper 'bpf_sk_assign' requires arg2 = 0 in tcx programs"
        ))
    );
    assert_eq!(
        EbpfProgramType::Netkit.helper_zero_arg_requirement(BpfHelper::SkAssign),
        None
    );
    assert_eq!(
        EbpfProgramType::Xdp.helper_zero_arg_requirement(BpfHelper::CheckMtu),
        Some((
            4,
            "helper 'bpf_check_mtu' requires arg4 = 0 in xdp programs"
        ))
    );
    assert_eq!(
        EbpfProgramType::Tc.helper_zero_arg_requirement(BpfHelper::CheckMtu),
        None
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
        EbpfProgramType::TcAction.get_socket_cookie_arg_policy(),
        Some(GetSocketCookieArgPolicy::Context)
    );
    assert_eq!(
        EbpfProgramType::Tcx.get_socket_cookie_arg_policy(),
        Some(GetSocketCookieArgPolicy::Context)
    );
    assert_eq!(
        EbpfProgramType::Netkit.get_socket_cookie_arg_policy(),
        Some(GetSocketCookieArgPolicy::Context)
    );
    assert_eq!(
        EbpfProgramType::SkReuseport.get_socket_cookie_arg_policy(),
        Some(GetSocketCookieArgPolicy::Context)
    );
    assert_eq!(
        EbpfProgramType::CgroupSockAddr.get_socket_cookie_arg_policy(),
        Some(GetSocketCookieArgPolicy::Context)
    );
    assert_eq!(
        EbpfProgramType::SockOps.get_socket_cookie_arg_policy(),
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
        EbpfProgramType::Fexit.get_socket_cookie_arg_policy(),
        Some(GetSocketCookieArgPolicy::Socket)
    );
    assert_eq!(
        EbpfProgramType::FmodRet.get_socket_cookie_arg_policy(),
        Some(GetSocketCookieArgPolicy::Socket)
    );
    assert_eq!(
        EbpfProgramType::TpBtf.get_socket_cookie_arg_policy(),
        Some(GetSocketCookieArgPolicy::Socket)
    );
    assert_eq!(
        EbpfProgramType::SkLookup.get_socket_cookie_arg_policy(),
        None
    );
    assert_eq!(EbpfProgramType::Xdp.get_socket_cookie_arg_policy(), None);
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
        (EbpfProgramType::KprobeMulti, "vfs_*"),
        (EbpfProgramType::KretprobeMulti, "vfs_*"),
        (EbpfProgramType::Ksyscall, "nanosleep"),
        (EbpfProgramType::KretSyscall, "nanosleep"),
        (EbpfProgramType::Uprobe, "/bin/true:main"),
        (EbpfProgramType::Uretprobe, "/bin/true:main"),
        (EbpfProgramType::UprobeMulti, "/bin/true:main*"),
        (EbpfProgramType::UretprobeMulti, "/bin/true:main*"),
        (
            EbpfProgramType::PerfEvent,
            "software:cpu-clock:period=100000",
        ),
        (EbpfProgramType::RawTracepoint, "sched_switch"),
        (EbpfProgramType::RawTracepointWritable, "sched_switch"),
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
        xdp.helper_zero_arg_requirement(BpfHelper::CheckMtu),
        Some((
            4,
            "helper 'bpf_check_mtu' requires arg4 = 0 in xdp programs"
        ))
    );
    assert_eq!(tc.helper_zero_arg_requirement(BpfHelper::CheckMtu), None);
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
        EbpfProgramType::from_spec_prefix("raw_tp.w"),
        Some(EbpfProgramType::RawTracepointWritable)
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
        EbpfProgramType::from_spec_prefix("freplace"),
        Some(EbpfProgramType::Extension)
    );
    assert_eq!(
        EbpfProgramType::from_spec_prefix("extension"),
        Some(EbpfProgramType::Extension)
    );
    assert_eq!(
        EbpfProgramType::from_spec_prefix("syscall"),
        Some(EbpfProgramType::Syscall)
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
fn test_program_type_spec_prefix_registry_matches_alias_metadata() {
    let advertised_prefixes: std::collections::HashSet<_> =
        EbpfProgramType::supported_spec_prefixes()
            .iter()
            .copied()
            .collect();

    for program_type in EbpfProgramType::supported_program_types() {
        assert_eq!(
            program_type.to_string(),
            program_type.canonical_prefix(),
            "{program_type:?} Display should use the canonical program key"
        );
        for alias in program_type.info().spec_aliases {
            assert!(
                advertised_prefixes.contains(alias),
                "{program_type:?} alias {alias:?} should be advertised"
            );
            assert_eq!(
                EbpfProgramType::from_spec_prefix(alias),
                Some(*program_type),
                "{program_type:?} alias {alias:?} should resolve back to its program type"
            );
        }
    }

    for prefix in EbpfProgramType::supported_spec_prefixes() {
        assert!(
            EbpfProgramType::from_spec_prefix(prefix).is_some(),
            "advertised prefix {prefix:?} should resolve to a program type"
        );
    }
}

#[test]
fn test_program_type_registry_covers_current_kernel_uapi_program_types() {
    let modeled_kernel_types: std::collections::HashSet<_> =
        EbpfProgramType::supported_program_types()
            .iter()
            .map(EbpfProgramType::kernel_prog_type)
            .collect();

    for kernel_type in [
        "BPF_PROG_TYPE_SOCKET_FILTER",
        "BPF_PROG_TYPE_KPROBE",
        "BPF_PROG_TYPE_SCHED_CLS",
        "BPF_PROG_TYPE_SCHED_ACT",
        "BPF_PROG_TYPE_TRACEPOINT",
        "BPF_PROG_TYPE_XDP",
        "BPF_PROG_TYPE_PERF_EVENT",
        "BPF_PROG_TYPE_CGROUP_SKB",
        "BPF_PROG_TYPE_CGROUP_SOCK",
        "BPF_PROG_TYPE_LWT_IN",
        "BPF_PROG_TYPE_LWT_OUT",
        "BPF_PROG_TYPE_LWT_XMIT",
        "BPF_PROG_TYPE_SOCK_OPS",
        "BPF_PROG_TYPE_SK_SKB",
        "BPF_PROG_TYPE_CGROUP_DEVICE",
        "BPF_PROG_TYPE_SK_MSG",
        "BPF_PROG_TYPE_RAW_TRACEPOINT",
        "BPF_PROG_TYPE_CGROUP_SOCK_ADDR",
        "BPF_PROG_TYPE_LWT_SEG6LOCAL",
        "BPF_PROG_TYPE_LIRC_MODE2",
        "BPF_PROG_TYPE_SK_REUSEPORT",
        "BPF_PROG_TYPE_FLOW_DISSECTOR",
        "BPF_PROG_TYPE_CGROUP_SYSCTL",
        "BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE",
        "BPF_PROG_TYPE_CGROUP_SOCKOPT",
        "BPF_PROG_TYPE_TRACING",
        "BPF_PROG_TYPE_STRUCT_OPS",
        "BPF_PROG_TYPE_EXT",
        "BPF_PROG_TYPE_LSM",
        "BPF_PROG_TYPE_SK_LOOKUP",
        "BPF_PROG_TYPE_SYSCALL",
        "BPF_PROG_TYPE_NETFILTER",
    ] {
        assert!(
            modeled_kernel_types.contains(kernel_type),
            "kernel UAPI program type {kernel_type} should be represented in the program model"
        );
    }

    assert_eq!(
        EbpfProgramType::TcAction.kernel_prog_type(),
        "BPF_PROG_TYPE_SCHED_ACT"
    );
    assert_eq!(
        EbpfProgramType::Fentry.kernel_prog_type(),
        "BPF_PROG_TYPE_TRACING"
    );
    assert_eq!(
        EbpfProgramType::Ksyscall.kernel_prog_type(),
        "BPF_PROG_TYPE_KPROBE"
    );
    assert_eq!(
        EbpfProgramType::KretSyscall.kernel_prog_type(),
        "BPF_PROG_TYPE_KPROBE"
    );
    assert_eq!(
        EbpfProgramType::FmodRet.kernel_prog_type(),
        "BPF_PROG_TYPE_TRACING"
    );
    assert_eq!(
        EbpfProgramType::Extension.kernel_prog_type(),
        "BPF_PROG_TYPE_EXT"
    );
    assert_eq!(
        EbpfProgramType::Syscall.kernel_prog_type(),
        "BPF_PROG_TYPE_SYSCALL"
    );
    assert_eq!(
        EbpfProgramType::Iter.kernel_prog_type(),
        "BPF_PROG_TYPE_TRACING"
    );
}

#[test]
fn test_program_attach_kind_loader_live_support_metadata() {
    let mut target_kind_keys = HashSet::new();
    for kind in [
        ProgramTargetKind::KernelFunction,
        ProgramTargetKind::KernelFunctionPattern,
        ProgramTargetKind::KernelSyscall,
        ProgramTargetKind::BtfTracepoint,
        ProgramTargetKind::LsmHook,
        ProgramTargetKind::ExtensionFunction,
        ProgramTargetKind::SyscallProgram,
        ProgramTargetKind::BpfIteratorTarget,
        ProgramTargetKind::Tracepoint,
        ProgramTargetKind::RawTracepoint,
        ProgramTargetKind::UserFunction,
        ProgramTargetKind::UserFunctionPattern,
        ProgramTargetKind::NetworkInterface,
        ProgramTargetKind::PerfEventTarget,
        ProgramTargetKind::SocketFilterTarget,
        ProgramTargetKind::NetworkNamespacePath,
        ProgramTargetKind::NetfilterHook,
        ProgramTargetKind::LightweightTunnelRoute,
        ProgramTargetKind::SocketReuseportMode,
        ProgramTargetKind::PinnedSockMapPath,
        ProgramTargetKind::TrafficControlInterface,
        ProgramTargetKind::TrafficControlAction,
        ProgramTargetKind::CgroupPathAttachType,
        ProgramTargetKind::CgroupPathSockAttachType,
        ProgramTargetKind::CgroupPath,
        ProgramTargetKind::CgroupPathSockoptAttachType,
        ProgramTargetKind::CgroupPathSockAddrAttachType,
        ProgramTargetKind::LircDevicePath,
        ProgramTargetKind::StructOpsCallback,
    ] {
        assert!(
            target_kind_keys.insert(kind.key()),
            "program target kind key repeats for {kind:?}"
        );
        assert_eq!(
            kind.to_string(),
            kind.key(),
            "{kind:?} Display should use the machine-readable key"
        );
        assert!(
            !kind.key().is_empty(),
            "{kind:?} should have a machine-readable key"
        );
    }

    let mut attach_kind_keys = HashSet::new();
    for kind in [
        ProgramAttachKind::Kprobe,
        ProgramAttachKind::Kretprobe,
        ProgramAttachKind::KprobeMulti,
        ProgramAttachKind::KretprobeMulti,
        ProgramAttachKind::Ksyscall,
        ProgramAttachKind::KretSyscall,
        ProgramAttachKind::Fentry,
        ProgramAttachKind::Fexit,
        ProgramAttachKind::FmodRet,
        ProgramAttachKind::TpBtf,
        ProgramAttachKind::Tracepoint,
        ProgramAttachKind::RawTracepoint,
        ProgramAttachKind::RawTracepointWritable,
        ProgramAttachKind::Uprobe,
        ProgramAttachKind::Uretprobe,
        ProgramAttachKind::UprobeMulti,
        ProgramAttachKind::UretprobeMulti,
        ProgramAttachKind::Lsm,
        ProgramAttachKind::LsmCgroup,
        ProgramAttachKind::Extension,
        ProgramAttachKind::Syscall,
        ProgramAttachKind::Iter,
        ProgramAttachKind::Xdp,
        ProgramAttachKind::PerfEvent,
        ProgramAttachKind::SocketFilter,
        ProgramAttachKind::CgroupDevice,
        ProgramAttachKind::SkLookup,
        ProgramAttachKind::FlowDissector,
        ProgramAttachKind::Netfilter,
        ProgramAttachKind::Lwt,
        ProgramAttachKind::SkReuseport,
        ProgramAttachKind::SkMsg,
        ProgramAttachKind::SkSkb,
        ProgramAttachKind::SkSkbParser,
        ProgramAttachKind::SockOps,
        ProgramAttachKind::Tc,
        ProgramAttachKind::Tcx,
        ProgramAttachKind::Netkit,
        ProgramAttachKind::TcAction,
        ProgramAttachKind::CgroupSkb,
        ProgramAttachKind::CgroupSock,
        ProgramAttachKind::CgroupSysctl,
        ProgramAttachKind::CgroupSockopt,
        ProgramAttachKind::CgroupSockAddr,
        ProgramAttachKind::LircMode2,
        ProgramAttachKind::StructOps,
    ] {
        assert!(
            attach_kind_keys.insert(kind.key()),
            "program attach kind key repeats for {kind:?}"
        );
        assert_eq!(
            kind.to_string(),
            kind.key(),
            "{kind:?} Display should use the machine-readable key"
        );
        assert!(
            !kind.key().is_empty(),
            "{kind:?} should have a machine-readable key"
        );
    }

    for kind in [
        ProgramAttachKind::Kprobe,
        ProgramAttachKind::Kretprobe,
        ProgramAttachKind::Fentry,
        ProgramAttachKind::Fexit,
        ProgramAttachKind::RawTracepoint,
        ProgramAttachKind::Xdp,
        ProgramAttachKind::SocketFilter,
        ProgramAttachKind::CgroupSockAddr,
        ProgramAttachKind::LircMode2,
        ProgramAttachKind::StructOps,
    ] {
        assert!(
            kind.loader_supports_live_attach(),
            "{kind:?} should be marked live-loadable by the loader"
        );
        assert_eq!(kind.unsupported_live_attach_detail(), None);
    }

    for (kind, detail_fragment) in [
        (
            ProgramAttachKind::RawTracepointWritable,
            "writable raw-tracepoint",
        ),
        (ProgramAttachKind::FmodRet, "BPF_MODIFY_RETURN"),
        (ProgramAttachKind::LsmCgroup, "cgroup-scoped LSM"),
        (ProgramAttachKind::Netkit, "netkit attach"),
        (ProgramAttachKind::TcAction, "tc_action attach"),
        (ProgramAttachKind::SkReuseport, "sk_reuseport attach"),
        (ProgramAttachKind::FlowDissector, "flow-dissector attach"),
        (ProgramAttachKind::Netfilter, "netfilter attach"),
        (ProgramAttachKind::Lwt, "route LWT attach"),
        (
            ProgramAttachKind::Extension,
            "extension/freplace live attach",
        ),
        (ProgramAttachKind::Syscall, "BPF_PROG_TYPE_SYSCALL"),
        (ProgramAttachKind::Iter, "BPF iterator"),
    ] {
        assert!(
            !kind.loader_supports_live_attach(),
            "{kind:?} should be marked compile-only for live loader attach"
        );
        let detail = kind
            .unsupported_live_attach_detail()
            .unwrap_or_else(|| panic!("{kind:?} should explain why live attach is unsupported"));
        assert!(
            detail.contains(detail_fragment),
            "{kind:?} unsupported detail should contain {detail_fragment:?}, got {detail:?}"
        );
    }
}

#[test]
fn test_program_intrinsic_command_registry() {
    let mut command_names = HashSet::new();
    let all_capabilities = ProgramCapability::all()
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    for intrinsic in ProgramIntrinsic::all() {
        assert!(
            command_names.insert(intrinsic.command_name()),
            "program intrinsic command repeats for {intrinsic:?}"
        );
        assert_eq!(
            ProgramIntrinsic::from_command_name(intrinsic.command_name()),
            Some(*intrinsic),
            "{intrinsic:?} command should round-trip through the registry"
        );
        assert!(
            all_capabilities.contains(&intrinsic.required_capability()),
            "{intrinsic:?} should require a declared program capability"
        );
    }
    assert_eq!(ProgramIntrinsic::command_names().len(), command_names.len());

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
    assert!(EbpfProgramType::Xdp.supports_intrinsic(ProgramIntrinsic::KfuncCall));
    assert!(EbpfProgramType::Tc.supports_intrinsic(ProgramIntrinsic::KfuncCall));
    assert!(!EbpfProgramType::Syscall.supports_intrinsic(ProgramIntrinsic::KfuncCall));
    assert!(!EbpfProgramType::Extension.supports_intrinsic(ProgramIntrinsic::KfuncCall));
}

#[test]
fn test_program_type_supports_probe_capabilities() {
    assert!(EbpfProgramType::Tracepoint.supports_capability(ProgramCapability::Emit));
    assert!(EbpfProgramType::Fentry.supports_capability(ProgramCapability::HelperCalls));
    assert!(EbpfProgramType::Fentry.supports_capability(ProgramCapability::KfuncCalls));
    assert!(EbpfProgramType::Kprobe.supports_capability(ProgramCapability::StackTraces));
    assert!(EbpfProgramType::Xdp.supports_capability(ProgramCapability::HelperCalls));
    assert!(EbpfProgramType::Xdp.supports_capability(ProgramCapability::KfuncCalls));
    assert!(EbpfProgramType::Xdp.supports_capability(ProgramCapability::Globals));
    assert!(!EbpfProgramType::Xdp.supports_capability(ProgramCapability::ReadUserString));
}

#[test]
fn test_program_capability_surfaces_are_unique() {
    let mut access_keys = HashSet::new();
    for access in [
        ProgramValueAccess::None,
        ProgramValueAccess::PtRegs,
        ProgramValueAccess::RawTracepoint,
        ProgramValueAccess::Trampoline,
    ] {
        assert!(
            access_keys.insert(access.key()),
            "program value access key repeats for {access:?}"
        );
        assert_eq!(
            access.to_string(),
            access.key(),
            "{access:?} Display should use the machine-readable key"
        );
        assert!(
            !access.key().is_empty(),
            "{access:?} should have a machine-readable key"
        );
    }

    let mut capability_keys = HashSet::new();
    for capability in ProgramCapability::all() {
        assert!(
            capability_keys.insert(capability.key()),
            "program capability key repeats for {capability:?}"
        );
        assert_eq!(
            capability.to_string(),
            capability.key(),
            "{capability:?} Display should use the machine-readable key"
        );
        assert!(
            !capability.key().is_empty(),
            "{capability:?} should have a machine-readable key"
        );
        assert!(
            !capability.description().is_empty(),
            "{capability:?} should have a diagnostic description"
        );
    }

    for program_type in EbpfProgramType::supported_program_types() {
        let mut seen = HashSet::new();
        for capability in program_type.supported_capabilities() {
            assert!(
                seen.insert(*capability),
                "{} capability surface repeats {:?}",
                program_type.canonical_prefix(),
                capability
            );
        }
    }
}

#[test]
fn test_program_compatibility_requirement_surfaces_are_unique() {
    let mut requirement_keys = HashSet::new();
    for requirement in ProgramCompatibilityRequirement::all() {
        assert!(
            requirement_keys.insert(requirement.key()),
            "compatibility requirement key repeats for {requirement:?}"
        );
        assert_eq!(
            requirement.to_string(),
            requirement.key(),
            "{requirement:?} Display should use the machine-readable key"
        );
        assert!(
            !requirement.key().is_empty(),
            "{requirement:?} should have a machine-readable key"
        );
        assert!(
            !requirement.description().is_empty(),
            "{requirement:?} should have a diagnostic description"
        );
        assert!(
            !requirement.category().is_empty(),
            "{requirement:?} should have a compatibility category"
        );
        assert!(
            !requirement.default_test_lane().is_empty(),
            "{requirement:?} should have a default test lane"
        );
        assert!(
            requirement.minimum_kernel().is_some() == requirement.minimum_kernel_source().is_some(),
            "{requirement:?} should only report a minimum kernel with a source"
        );
    }

    for program_type in EbpfProgramType::supported_program_types() {
        let mut seen = HashSet::new();
        for requirement in program_type.compatibility_requirements() {
            assert!(
                seen.insert(*requirement),
                "{} compatibility surface repeats {:?}",
                program_type.canonical_prefix(),
                requirement
            );
            assert!(
                !requirement.description().is_empty(),
                "{requirement:?} should have a diagnostic description"
            );
            assert!(
                !requirement.category().is_empty(),
                "{requirement:?} should have a compatibility category"
            );
            assert!(
                !requirement.default_test_lane().is_empty(),
                "{requirement:?} should have a default test lane"
            );
        }
    }

    assert!(
        EbpfProgramType::Fentry
            .requires_compatibility_feature(ProgramCompatibilityRequirement::KernelBtf)
    );
    assert!(
        EbpfProgramType::Fentry
            .requires_compatibility_feature(ProgramCompatibilityRequirement::TracingProgram)
    );
    assert!(
        EbpfProgramType::Fentry
            .requires_compatibility_feature(ProgramCompatibilityRequirement::BpfTrampoline)
    );
    assert!(
        EbpfProgramType::TpBtf
            .requires_compatibility_feature(ProgramCompatibilityRequirement::TracingProgram)
    );
    assert!(
        EbpfProgramType::Lsm
            .requires_compatibility_feature(ProgramCompatibilityRequirement::LsmProgram)
    );
    assert!(
        EbpfProgramType::RawTracepointWritable
            .requires_compatibility_feature(ProgramCompatibilityRequirement::RawTracepointWritable)
    );
    assert!(
        EbpfProgramType::Netfilter
            .requires_compatibility_feature(ProgramCompatibilityRequirement::NetfilterLink)
    );
    assert!(
        EbpfProgramType::StructOps
            .requires_compatibility_feature(ProgramCompatibilityRequirement::StructOps)
    );
    assert!(
        EbpfProgramType::CgroupSockAddr
            .requires_compatibility_feature(ProgramCompatibilityRequirement::CgroupV2)
    );
    assert!(
        EbpfProgramType::CgroupSockAddr
            .requires_compatibility_feature(ProgramCompatibilityRequirement::CgroupSockAddrProgram)
    );
    assert!(
        EbpfProgramType::SkReuseport
            .requires_compatibility_feature(ProgramCompatibilityRequirement::SkReuseportAttach)
    );
    assert!(
        EbpfProgramType::TcAction
            .requires_compatibility_feature(ProgramCompatibilityRequirement::TcActionProgram)
    );
    assert!(
        EbpfProgramType::Kprobe
            .requires_compatibility_feature(ProgramCompatibilityRequirement::KprobeProgram)
    );
    assert!(
        EbpfProgramType::Xdp
            .requires_compatibility_feature(ProgramCompatibilityRequirement::XdpProgram)
    );
    assert!(
        EbpfProgramType::SocketFilter
            .requires_compatibility_feature(ProgramCompatibilityRequirement::SocketFilterProgram)
    );

    assert_eq!(
        ProgramCompatibilityRequirement::SocketFilterProgram.minimum_kernel(),
        Some("3.19")
    );
    assert_eq!(
        ProgramCompatibilityRequirement::KprobeProgram.minimum_kernel(),
        Some("4.1")
    );
    assert_eq!(
        ProgramCompatibilityRequirement::TracepointProgram.minimum_kernel(),
        Some("4.7")
    );
    assert_eq!(
        ProgramCompatibilityRequirement::XdpProgram.minimum_kernel(),
        Some("4.8")
    );
    assert_eq!(
        ProgramCompatibilityRequirement::PerfEventProgram.minimum_kernel(),
        Some("4.9")
    );
    assert_eq!(
        ProgramCompatibilityRequirement::RawTracepointProgram.minimum_kernel(),
        Some("4.17")
    );
    assert_eq!(
        ProgramCompatibilityRequirement::SkLookupProgram.minimum_kernel(),
        Some("5.9")
    );
    assert_eq!(
        ProgramCompatibilityRequirement::TracingProgram.minimum_kernel(),
        Some("5.5")
    );
    assert_eq!(
        ProgramCompatibilityRequirement::LsmProgram.minimum_kernel(),
        Some("5.7")
    );
    assert_eq!(
        ProgramCompatibilityRequirement::TcProgram.minimum_kernel(),
        Some("4.1")
    );
    assert_eq!(
        ProgramCompatibilityRequirement::NetfilterLink.minimum_kernel(),
        Some("6.4")
    );
    assert_eq!(
        ProgramCompatibilityRequirement::SchedExt.minimum_kernel(),
        Some("6.12")
    );
    assert_eq!(
        ProgramCompatibilityRequirement::SkReuseportAttach.minimum_kernel(),
        Some("4.19")
    );
    assert_eq!(
        ProgramCompatibilityRequirement::SkReuseportMigration.minimum_kernel(),
        Some("5.14")
    );
    assert_eq!(
        ProgramCompatibilityRequirement::RouteLwt.minimum_kernel(),
        Some("4.10")
    );
    assert_eq!(
        ProgramCompatibilityRequirement::RouteLwtSeg6Local.minimum_kernel(),
        Some("4.18")
    );
    assert_eq!(
        ProgramCompatibilityRequirement::SkMsgSockMapAttach.minimum_kernel(),
        Some("4.17")
    );
    assert_eq!(
        ProgramCompatibilityRequirement::SkSkbSockMapAttach.minimum_kernel(),
        Some("4.14")
    );
    assert_eq!(
        ProgramCompatibilityRequirement::UprobeMulti.minimum_kernel(),
        Some("6.6")
    );
    assert_eq!(
        ProgramCompatibilityRequirement::CgroupSkbProgram.minimum_kernel(),
        Some("4.10")
    );
    assert_eq!(
        ProgramCompatibilityRequirement::CgroupSockProgram.minimum_kernel(),
        Some("4.10")
    );
    assert_eq!(
        ProgramCompatibilityRequirement::CgroupDeviceProgram.minimum_kernel(),
        Some("4.15")
    );
    assert_eq!(
        ProgramCompatibilityRequirement::CgroupSockAddrProgram.minimum_kernel(),
        Some("4.17")
    );
    assert_eq!(
        ProgramCompatibilityRequirement::CgroupSysctlProgram.minimum_kernel(),
        Some("5.2")
    );
    assert_eq!(
        ProgramCompatibilityRequirement::CgroupSockoptProgram.minimum_kernel(),
        Some("5.3")
    );
    assert_eq!(
        ProgramCompatibilityRequirement::SockOpsProgram.minimum_kernel(),
        Some("4.14")
    );
    assert_eq!(
        ProgramCompatibilityRequirement::CgroupUnixSockAddr.minimum_kernel(),
        Some("6.7")
    );
    assert!(
        ProgramCompatibilityRequirement::SockMapAttach
            .minimum_kernel()
            .is_none(),
        "mixed sk_msg/sk_skb attach requirement should stay nullable until split"
    );
    assert!(
        ProgramCompatibilityRequirement::CgroupV2
            .minimum_kernel()
            .is_none(),
        "cgroup v2 remains a runtime attach-resource requirement, not a sufficient kernel-version check"
    );
    assert_eq!(
        ProgramCompatibilityRequirement::effective_minimum_kernel(&[
            ProgramCompatibilityRequirement::KernelBtf,
            ProgramCompatibilityRequirement::BpfTrampoline,
            ProgramCompatibilityRequirement::SleepableProgram,
        ]),
        Some("5.10")
    );
    assert!(ProgramCompatibilityRequirement::kernel_version_at_least(
        "6.1.12-generic",
        "5.10"
    ));
    assert!(!ProgramCompatibilityRequirement::kernel_version_at_least(
        "5.4.0", "5.10"
    ));
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
fn test_elf_map_btf_emits_declared_key_and_value_types() {
    use crate::compiler::instruction::{EbpfBuilder, EbpfInsn, EbpfReg};

    let mut builder = EbpfBuilder::new();
    builder.push(EbpfInsn::mov64_imm(EbpfReg::R0, 0));
    builder.push(EbpfInsn::exit());
    let bytecode = builder.build();
    let map_ref = MapRef {
        name: "locks".to_string(),
        kind: MapKind::Hash,
    };
    let key_ty = MirType::Struct {
        name: None,
        kernel_btf_type_id: None,
        fields: vec![
            StructField {
                name: "pid".to_string(),
                ty: MirType::U32,
                offset: 0,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "__layout_pad0".to_string(),
                ty: MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: 4,
                },
                offset: 4,
                synthetic: true,
                bitfield: None,
            },
            StructField {
                name: "cookie".to_string(),
                ty: MirType::U64,
                offset: 8,
                synthetic: false,
                bitfield: None,
            },
        ],
    };
    let value_ty = MirType::Struct {
        name: None,
        kernel_btf_type_id: None,
        fields: vec![
            StructField {
                name: "lock".to_string(),
                ty: MirType::bpf_spin_lock_struct(),
                offset: 0,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "__layout_pad0".to_string(),
                ty: MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: 4,
                },
                offset: 4,
                synthetic: true,
                bitfield: None,
            },
            StructField {
                name: "counter".to_string(),
                ty: MirType::U64,
                offset: 8,
                synthetic: false,
                bitfield: None,
            },
        ],
    };
    let program = EbpfProgram::with_maps(
        EbpfProgramType::Xdp,
        "lo",
        "typed_map",
        bytecode.clone(),
        bytecode.len(),
        vec![EbpfMap {
            name: "locks".to_string(),
            def: BpfMapDef::hash(key_ty.size() as u32, value_ty.size() as u32, 1024),
        }],
        vec![],
        vec![],
        None,
        None,
        HashMap::from([(map_ref, value_ty)]),
        HashMap::new(),
    )
    .with_generic_map_key_types(HashMap::from([(
        MapRef {
            name: "locks".to_string(),
            kind: MapKind::Hash,
        },
        key_ty,
    )]));

    let elf = program.to_elf().expect("typed map ELF should emit");
    let aya = AyaObject::parse(&elf).expect("Aya should parse typed map BTF");
    assert!(aya.maps.get("locks").is_some());

    let parsed = object::File::parse(&*elf).expect("emitted object should parse");
    let btf_section = parsed
        .section_by_name(".BTF")
        .expect("expected .BTF section");
    let btf_data = btf_section.data().expect(".BTF section should be readable");
    let btf = Btf::parse(btf_data, Endianness::Little).expect("expected parsable BTF");

    assert!(
        btf.id_by_type_name_kind("bpf_spin_lock", BtfKind::Struct)
            .is_ok()
    );
    assert!(
        btf_data.windows(b"key\0".len()).any(|w| w == b"key\0"),
        "expected BTF map definition to use a typed key member"
    );
    assert!(
        btf_data.windows(b"value\0".len()).any(|w| w == b"value\0"),
        "expected BTF map definition to use a typed value member"
    );
    assert!(
        btf_data
            .windows(b"key_size\0".len())
            .all(|w| w != b"key_size\0"),
        "typed map should not also emit a key_size member"
    );
    assert!(
        btf_data
            .windows(b"value_size\0".len())
            .all(|w| w != b"value_size\0"),
        "typed map should not also emit a value_size member"
    );
    assert!(
        btf_data
            .windows(b"__layout_pad0\0".len())
            .all(|w| w != b"__layout_pad0\0"),
        "synthetic record padding should affect map sizes without leaking into BTF members"
    );
}

#[test]
fn test_elf_map_btf_emits_kptr_value_type_tag() {
    use crate::compiler::instruction::{EbpfBuilder, EbpfInsn, EbpfReg};

    let mut builder = EbpfBuilder::new();
    builder.push(EbpfInsn::mov64_imm(EbpfReg::R0, 0));
    builder.push(EbpfInsn::exit());
    let bytecode = builder.build();
    let map_ref = MapRef {
        name: "task_slots".to_string(),
        kind: MapKind::Array,
    };
    let value_ty = MirType::Struct {
        name: None,
        kernel_btf_type_id: None,
        fields: vec![
            StructField {
                name: "task".to_string(),
                ty: MirType::bpf_kptr_slot_struct("task_struct"),
                offset: 0,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "cookie".to_string(),
                ty: MirType::U64,
                offset: 8,
                synthetic: false,
                bitfield: None,
            },
        ],
    };
    let program = EbpfProgram::with_maps(
        EbpfProgramType::Xdp,
        "lo",
        "typed_map",
        bytecode.clone(),
        bytecode.len(),
        vec![EbpfMap {
            name: "task_slots".to_string(),
            def: BpfMapDef::array(value_ty.size() as u32, 16),
        }],
        vec![],
        vec![],
        None,
        None,
        HashMap::from([(map_ref, value_ty)]),
        HashMap::new(),
    );

    let elf = program.to_elf().expect("typed map ELF should emit");
    let aya = AyaObject::parse(&elf).expect("Aya should parse kptr typed map BTF");
    assert!(aya.maps.get("task_slots").is_some());

    let parsed = object::File::parse(&*elf).expect("emitted object should parse");
    let btf_section = parsed
        .section_by_name(".BTF")
        .expect("expected .BTF section");
    let btf_data = btf_section.data().expect(".BTF section should be readable");
    let btf = Btf::parse(btf_data, Endianness::Little).expect("expected parsable BTF");

    assert!(btf.id_by_type_name_kind("__kptr", BtfKind::TypeTag).is_ok());
    assert!(
        btf.id_by_type_name_kind("task_struct", BtfKind::Fwd)
            .is_ok()
    );
    assert!(
        btf_data
            .windows(b"__nu_bpf_kptr_task_struct\0".len())
            .all(|w| w != b"__nu_bpf_kptr_task_struct\0"),
        "internal kptr slot wrapper should not leak into emitted BTF"
    );
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
    assert_eq!(object.programs[0].target, "demo_select_cpu");
    assert_eq!(
        object.programs[0].parsed_program_spec(),
        Some(&ProgramSpec::StructOpsCallback {
            value_type_name: "file".to_string(),
            callback_name: "f_inode".to_string(),
        })
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
fn test_program_object_allows_extra_data_symbols_and_program_relocations() {
    use crate::compiler::instruction::{EbpfBuilder, EbpfInsn, EbpfReg};
    use object::{Object as _, ObjectSection as _, ObjectSymbol as _, RelocationTarget};

    let mut builder = EbpfBuilder::new();
    let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
    builder.push(insn1);
    builder.push(insn2);
    builder.push(EbpfInsn::mov64_imm(EbpfReg::R0, 0));
    builder.push(EbpfInsn::exit());
    let bytecode = builder.build();

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
            data: vec![1, 2, 3, 4, 5, 6, 7, 8],
            align: 4,
            writable: false,
            relocations: vec![ObjectDataRelocation {
                offset: 0,
                field_name: None,
                symbol_name: "uses_blob".to_string(),
            }],
        }],
        programs: vec![
            EbpfProgram::with_maps(
                EbpfProgramType::Kprobe,
                "sys_clone",
                "uses_blob",
                bytecode.clone(),
                bytecode.len(),
                vec![],
                vec![SymbolRelocation {
                    insn_offset: 0,
                    symbol_name: "blob".to_string(),
                }],
                vec![],
                None,
                None,
                HashMap::new(),
                HashMap::new(),
            )
            .into_program_section(),
        ],
    };

    object
        .validate_runtime_artifacts()
        .expect("ordinary program object should allow extra data symbols");

    let elf = object
        .to_elf()
        .expect("ordinary program extra data symbol should emit");
    let file = object::File::parse(&*elf).expect("object crate should parse generated ELF");
    let data_section = file
        .section_by_name(".custom")
        .expect("expected custom data section");
    assert_eq!(
        data_section
            .data()
            .expect("custom section data should be readable"),
        &[1, 2, 3, 4, 5, 6, 7, 8]
    );

    let program_section = file
        .section_by_name("kprobe/sys_clone")
        .expect("expected program section");
    let mut relocations = program_section.relocations();
    let (reloc_offset, relocation) = relocations
        .next()
        .expect("expected program relocation to custom data symbol");
    assert_eq!(reloc_offset, 0);
    match relocation.target() {
        RelocationTarget::Symbol(symbol_idx) => {
            let symbol = file
                .symbol_by_index(symbol_idx)
                .expect("relocation symbol should exist");
            assert_eq!(
                symbol.name().expect("relocation symbol should have a name"),
                "blob"
            );
        }
        other => panic!("unexpected relocation target: {other:?}"),
    }
    assert!(
        relocations.next().is_none(),
        "expected only one program relocation"
    );

    let mut data_relocations = data_section.relocations();
    let (data_reloc_offset, data_relocation) = data_relocations
        .next()
        .expect("expected custom data relocation to program symbol");
    assert_eq!(data_reloc_offset, 0);
    match data_relocation.target() {
        RelocationTarget::Symbol(symbol_idx) => {
            let symbol = file
                .symbol_by_index(symbol_idx)
                .expect("data relocation symbol should exist");
            assert_eq!(
                symbol
                    .name()
                    .expect("data relocation symbol should have a name"),
                "uses_blob"
            );
        }
        other => panic!("unexpected data relocation target: {other:?}"),
    }
    assert!(
        data_relocations.next().is_none(),
        "expected only one data relocation"
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
fn test_object_runtime_artifacts_require_globals_for_extra_data_symbols() {
    let object = EbpfObject {
        kind: EbpfObjectKind::Program,
        license: "GPL".to_string(),
        maps: vec![],
        readonly_globals: vec![],
        data_globals: vec![],
        bss_globals: vec![],
        extra_data_symbols: vec![ObjectDataSymbol {
            section_name: ".rodata.custom".to_string(),
            name: "blob".to_string(),
            data: vec![1, 2, 3, 4],
            align: 1,
            writable: false,
            relocations: vec![],
        }],
        programs: vec![
            EbpfProgram::from_bytecode(EbpfProgramType::Extension, "replace_me", "test", vec![])
                .into_program_section(),
        ],
    };

    let err = object
        .validate_runtime_artifacts()
        .expect_err("extra data symbols should require Globals capability");

    assert!(
        err.to_string().contains(
            "freplace programs do not support program globals required by extra data symbol 'blob'"
        ),
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
fn test_to_elf_resolves_subfunction_relocation_symbols() {
    use crate::compiler::instruction::{EbpfBuilder, EbpfInsn, EbpfReg};
    use object::{Object as _, ObjectSection as _, ObjectSymbol as _, RelocationTarget};

    let mut builder = EbpfBuilder::new();
    let [insn1, insn2] = EbpfInsn::ld_imm64(EbpfReg::R1, 0);
    builder.push(insn1);
    builder.push(insn2);
    builder.push(EbpfInsn::mov64_imm(EbpfReg::R0, 0));
    builder.push(EbpfInsn::exit());
    let main_size = builder.len() * 8;

    builder.push(EbpfInsn::mov64_imm(EbpfReg::R0, 0));
    builder.push(EbpfInsn::exit());
    let bytecode = builder.build();

    let program = EbpfProgram::with_maps(
        EbpfProgramType::Kprobe,
        "sys_clone",
        "uses_subfn",
        bytecode,
        main_size,
        vec![],
        vec![SymbolRelocation {
            insn_offset: 0,
            symbol_name: "loop_cb".to_string(),
        }],
        vec![SubfunctionSymbol {
            name: "loop_cb".to_string(),
            offset: main_size,
            size: 16,
        }],
        None,
        None,
        HashMap::new(),
        HashMap::new(),
    );

    let elf = program
        .to_elf()
        .expect("subfunction relocation should resolve to a local text symbol");
    let file = object::File::parse(&*elf).expect("object crate should parse generated ELF");
    let section = file
        .section_by_name("kprobe/sys_clone")
        .expect("expected kprobe text section");
    let mut relocations = section.relocations();
    let (reloc_offset, relocation) = relocations
        .next()
        .expect("expected relocation to subfunction symbol");
    assert_eq!(reloc_offset, 0);
    match relocation.target() {
        RelocationTarget::Symbol(symbol_idx) => {
            let symbol = file
                .symbol_by_index(symbol_idx)
                .expect("subfunction relocation symbol should exist");
            assert_eq!(
                symbol
                    .name()
                    .expect("subfunction relocation symbol should have a name"),
                "loop_cb"
            );
            assert_eq!(symbol.address(), main_size as u64);
        }
        other => panic!("unexpected relocation target: {other:?}"),
    }
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
fn test_runtime_artifacts_require_globals_capability_for_global_sections() {
    let programs = vec![
        (
            "readonly global 'threshold'",
            EbpfProgram::from_bytecode(EbpfProgramType::Extension, "replace_me", "test", vec![])
                .with_readonly_globals(vec![ReadonlyGlobal {
                    name: "threshold".to_string(),
                    data: vec![1, 0, 0, 0],
                }]),
        ),
        (
            "data global 'counter'",
            EbpfProgram::from_bytecode(EbpfProgramType::Extension, "replace_me", "test", vec![])
                .with_data_globals(vec![DataGlobal {
                    name: "counter".to_string(),
                    data: vec![0; 8],
                }]),
        ),
        (
            "bss global 'state'",
            EbpfProgram::from_bytecode(EbpfProgramType::Extension, "replace_me", "test", vec![])
                .with_bss_globals(vec![BssGlobal {
                    name: "state".to_string(),
                    size: 16,
                }]),
        ),
    ];

    for (artifact, program) in programs {
        let err = program
            .validate_runtime_artifacts()
            .expect_err("global sections should require Globals capability");
        let msg = err.to_string();
        assert!(
            msg.contains("freplace programs do not support program globals")
                && msg.contains(artifact),
            "unexpected error for {artifact}: {err}"
        );
    }
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
    assert_eq!(
        EbpfProgramType::Netfilter
            .resolve_ctx_field_name("state")
            .expect("netfilter state alias should resolve"),
        CtxField::NetfilterState
    );
    assert_eq!(
        EbpfProgramType::Netfilter
            .resolve_ctx_field_name("nf_state")
            .expect("netfilter nf_state alias should resolve"),
        CtxField::NetfilterState
    );
    assert_eq!(
        EbpfProgramType::Netfilter
            .resolve_ctx_field_name("skb")
            .expect("netfilter skb alias should resolve"),
        CtxField::NetfilterSkb
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
    assert_eq!(
        EbpfProgramType::Tracepoint
            .resolve_ctx_field_name("prandom_u32")
            .expect("tracepoint prandom_u32 should preserve builtin alias"),
        CtxField::Random
    );
    assert_eq!(
        EbpfProgramType::Tracepoint
            .resolve_ctx_field_name("function_ip")
            .expect("tracepoint function_ip should preserve builtin alias"),
        CtxField::FuncIp
    );
    assert_eq!(
        EbpfProgramType::Tracepoint
            .resolve_ctx_field_name("bpf_cookie")
            .expect("tracepoint bpf_cookie should preserve builtin alias"),
        CtxField::AttachCookie
    );
    assert_eq!(
        EbpfProgramType::Tracepoint
            .resolve_ctx_field_name("current_task")
            .expect("tracepoint current_task should preserve builtin alias"),
        CtxField::Task
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
    assert_eq!(
        EbpfProgramType::Kprobe
            .resolve_ctx_field_name("current_task")
            .expect("kprobe current_task should resolve"),
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

    let connect_unix = ProgramSpec::parse("cgroup_sock_addr:/sys/fs/cgroup:connect_unix")
        .expect("connect_unix spec");
    assert_eq!(
        connect_unix.cgroup_sock_addr_tuple_alias_field(&CtxField::RemotePort),
        None
    );
    assert_eq!(
        connect_unix.cgroup_sock_addr_tuple_alias_field(&CtxField::RemoteIp4),
        None
    );
}

#[test]
fn test_program_type_context_layouts_use_program_model_table() {
    assert_eq!(
        EbpfProgramType::SocketFilter.packet_context_kind(),
        Some(PacketContextKind::SkBuff)
    );
    assert_eq!(
        EbpfProgramType::SockOps.packet_context_kind(),
        Some(PacketContextKind::SockOps)
    );
    assert_eq!(EbpfProgramType::SkLookup.packet_context_kind(), None);
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
        EbpfProgramType::LsmCgroup,
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
fn test_probe_context_stack_fields_follow_helper_policy() {
    for program_type in [
        EbpfProgramType::Kprobe,
        EbpfProgramType::Kretprobe,
        EbpfProgramType::Uprobe,
        EbpfProgramType::Uretprobe,
        EbpfProgramType::PerfEvent,
        EbpfProgramType::RawTracepoint,
        EbpfProgramType::Tracepoint,
        EbpfProgramType::Fentry,
        EbpfProgramType::Fexit,
        EbpfProgramType::TpBtf,
    ] {
        let target = if program_type == EbpfProgramType::PerfEvent {
            "software:cpu-clock:period=100000"
        } else {
            "do_sys_openat2"
        };
        let ctx = ProbeContext::new(program_type, target);
        for field in [CtxField::KStack, CtxField::UStack] {
            assert!(
                ctx.ctx_field_access_error(&field).is_none(),
                "ctx.{} should be allowed on {program_type:?}",
                field.display_name()
            );
        }
    }

    for program_type in [EbpfProgramType::Lsm, EbpfProgramType::Xdp] {
        let ctx = ProbeContext::new(program_type, "do_sys_openat2");
        for field in [CtxField::KStack, CtxField::UStack] {
            let err = ctx
                .ctx_field_access_error(&field)
                .unwrap_or_else(|| panic!("expected ctx.{} rejection", field.display_name()));
            assert!(err.contains(&format!(
                "ctx.{} is not available on {} programs",
                field.display_name(),
                program_type.canonical_prefix()
            )));
        }
    }
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
fn test_probe_context_resolves_cgroup_sysctl_new_value_write_target() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSysctl, "/sys/fs/cgroup");
    assert_eq!(
        ctx.resolve_ctx_write_target("sysctl_new_value", None)
            .expect("cgroup_sysctl sysctl_new_value write target should resolve"),
        CtxWriteTarget::SysctlNewValue
    );
    assert_eq!(
        ctx.resolve_ctx_write_target("new_value", None)
            .expect("cgroup_sysctl new_value write target should resolve"),
        CtxWriteTarget::SysctlNewValue
    );

    let err = ctx
        .resolve_ctx_write_target("new_value", Some(0))
        .expect_err("new_value indexed assignment should be rejected");
    assert!(err.contains("does not support indexed assignment"));
}

#[test]
fn test_probe_context_resolves_socket_assignment_write_target() {
    let sk_lookup = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");
    assert_eq!(
        sk_lookup
            .resolve_ctx_write_target("sk", None)
            .expect("sk_lookup ctx.sk write target should resolve"),
        CtxWriteTarget::AssignSocket
    );

    let tc_ingress = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    assert_eq!(
        tc_ingress
            .resolve_ctx_write_target("sk", None)
            .expect("tc ingress ctx.sk write target should resolve"),
        CtxWriteTarget::AssignSocket
    );

    let tc_action = ProbeContext::new(EbpfProgramType::TcAction, "demo-action");
    assert_eq!(
        tc_action
            .resolve_ctx_write_target("sk", None)
            .expect("tc_action ctx.sk write target should resolve"),
        CtxWriteTarget::AssignSocket
    );
}

#[test]
fn test_probe_context_rejects_socket_assignment_on_tc_egress() {
    let tc_egress = ProbeContext::new(EbpfProgramType::Tc, "lo:egress");
    let err = tc_egress
        .resolve_ctx_write_target("sk", None)
        .expect_err("tc egress ctx.sk write target should reject");
    assert!(err.contains("helper 'bpf_sk_assign' is only valid in tc/tcx ingress programs"));
}

#[test]
fn test_probe_context_resolves_cgroup_sock_addr_unix_sun_path_write_target() {
    let ctx = ProbeContext::new(
        EbpfProgramType::CgroupSockAddr,
        "/sys/fs/cgroup:connect_unix",
    );
    assert_eq!(
        ctx.resolve_ctx_write_target("sun_path", None)
            .expect("cgroup_sock_addr unix sun_path write target should resolve"),
        CtxWriteTarget::CgroupSockAddrSunPath
    );

    let err = ctx
        .resolve_ctx_write_target("sun_path", Some(0))
        .expect_err("sun_path indexed assignment should be rejected");
    assert!(err.contains("does not support indexed assignment"));
}

#[test]
fn test_probe_context_rejects_cgroup_sock_addr_inet_sun_path_write_target() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect4");
    let err = ctx
        .resolve_ctx_write_target("sun_path", None)
        .expect_err("inet cgroup_sock_addr sun_path write target should reject");
    assert!(err.contains("ctx.sun_path is only writable on cgroup_sock_addr UNIX hooks"));
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
fn test_probe_context_resolves_skb_queue_mapping_store_target_on_tc() {
    let ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    assert_eq!(
        ctx.resolve_ctx_store_target("queue_mapping", None)
            .expect("tc queue_mapping target should resolve"),
        CtxStoreTarget::SkbQueueMapping
    );
    assert!(
        ctx.validate_ctx_store_target(&CtxStoreTarget::SkbQueueMapping)
            .is_ok()
    );
}

#[test]
fn test_probe_context_resolves_tc_action_skb_metadata_store_targets() {
    let ctx = ProbeContext::new(EbpfProgramType::TcAction, "demo-action");
    for (field, target) in [
        ("mark", CtxStoreTarget::SkbMark),
        ("queue_mapping", CtxStoreTarget::SkbQueueMapping),
        ("priority", CtxStoreTarget::SkbPriority),
        ("tc_index", CtxStoreTarget::SkbTcIndex),
        ("tc_classid", CtxStoreTarget::SkbTcClassid),
        ("tstamp", CtxStoreTarget::SkbTstamp),
    ] {
        assert_eq!(
            ctx.resolve_ctx_store_target(field, None)
                .unwrap_or_else(|err| panic!("tc_action ctx.{field} target should resolve: {err}")),
            target
        );
        assert!(
            ctx.validate_ctx_store_target(&target).is_ok(),
            "tc_action ctx.{field} target should validate"
        );
    }

    assert_eq!(
        ctx.resolve_ctx_store_target("cb", Some(2))
            .expect("tc_action cb target should resolve"),
        CtxStoreTarget::SkbCbWord(2)
    );
    assert!(
        ctx.validate_ctx_store_target(&CtxStoreTarget::SkbCbWord(2))
            .is_ok()
    );
}

#[test]
fn test_probe_context_resolves_lwt_skb_metadata_store_targets() {
    let ctx = ProbeContext::new(EbpfProgramType::LwtXmit, "demo-route");
    for (field, target) in [
        ("mark", CtxStoreTarget::SkbMark),
        ("priority", CtxStoreTarget::SkbPriority),
    ] {
        assert_eq!(
            ctx.resolve_ctx_store_target(field, None)
                .unwrap_or_else(|err| panic!("lwt_xmit ctx.{field} target should resolve: {err}")),
            target
        );
        assert!(
            ctx.validate_ctx_store_target(&target).is_ok(),
            "lwt_xmit ctx.{field} target should validate"
        );
    }

    assert_eq!(
        ctx.resolve_ctx_store_target("cb", Some(1))
            .expect("lwt_xmit cb target should resolve"),
        CtxStoreTarget::SkbCbWord(1)
    );
    assert!(
        ctx.validate_ctx_store_target(&CtxStoreTarget::SkbCbWord(1))
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
    assert!(err.to_string().contains(
        "ctx.tstamp is only available on tc_action, tc, tcx, netkit, and cgroup_skb programs"
    ));
}

#[test]
fn test_probe_context_rejects_skb_tstamp_store_target_on_socket_filter() {
    let ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");
    let err = ctx
        .validate_ctx_store_target(&CtxStoreTarget::SkbTstamp)
        .expect_err("skb tstamp store target should be rejected outside tc");
    assert!(err.to_string().contains(
        "ctx.tstamp is only available on tc_action, tc, tcx, netkit, and cgroup_skb programs"
    ));
}

#[test]
fn test_probe_context_rejects_skb_tstamp_store_target_on_cgroup_skb_ingress() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:ingress");
    let err = ctx
        .resolve_ctx_store_target("tstamp", None)
        .expect_err("skb tstamp store target should be rejected on cgroup_skb ingress");
    assert!(err.contains(
        "ctx.tstamp is only writable on tc_action, tc, tcx, netkit, and cgroup_skb:egress programs"
    ));
    let err = ctx
        .validate_ctx_store_target(&CtxStoreTarget::SkbTstamp)
        .expect_err("skb tstamp store target should be rejected on cgroup_skb ingress");
    assert!(err.to_string().contains(
        "ctx.tstamp is only writable on tc_action, tc, tcx, netkit, and cgroup_skb:egress programs"
    ));
}

#[test]
fn test_probe_context_rejects_skb_mark_store_target_on_socket_filter() {
    let ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");
    let err = ctx
        .validate_ctx_store_target(&CtxStoreTarget::SkbMark)
        .expect_err("skb mark store target should be rejected outside tc");
    assert!(err.to_string().contains(
        "ctx.mark is only writable on lwt_*, tc_action, tc, tcx, netkit, and cgroup_skb programs"
    ));
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
    assert!(ctx.ctx_field_access_error(&CtxField::Random).is_none());
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
fn test_probe_context_rejects_runtime_fields_on_contextless_programs() {
    let contexts = [
        ProbeContext::new(EbpfProgramType::Extension, "replace_me"),
        ProbeContext::new(EbpfProgramType::Syscall, "demo"),
        ProbeContext::new_struct_ops_callback("sched_ext_ops", "select_cpu"),
    ];
    let fields = [
        CtxField::Cpu,
        CtxField::NumaNode,
        CtxField::Random,
        CtxField::Timestamp,
        CtxField::BootTimestamp,
        CtxField::CoarseTimestamp,
        CtxField::TaiTimestamp,
        CtxField::Jiffies,
    ];

    for ctx in contexts {
        for field in &fields {
            let err = ctx
                .ctx_field_access_error(field)
                .unwrap_or_else(|| panic!("expected {} access error", field.display_name()));
            assert!(
                err.contains(&format!(
                    "ctx.{} is not available on {} programs",
                    field.display_name(),
                    ctx.program_type().canonical_prefix()
                )),
                "unexpected error for {:?}/{}: {err}",
                ctx.program_type(),
                field.display_name()
            );
        }
    }
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
        assert!(err.contains("is only available on tc/tcx egress programs"));
    }
}

#[test]
fn test_probe_context_rejects_tc_egress_helper_backed_ctx_fields_on_non_tc() {
    let ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let err = ctx
        .ctx_field_access_error(&CtxField::CgroupClassid)
        .expect("expected non-tc access error");
    assert!(err.contains(
        "ctx.cgroup_classid is only available on tc_action, tc, tcx, netkit, and lwt_* programs"
    ));

    let err = ctx
        .ctx_field_access_error(&CtxField::SkbCgroupId)
        .expect("expected non-tc skb cgroup access error");
    assert!(err.contains(
        "ctx.skb_cgroup_id is only available on tc_action, tc:egress, and tcx:egress programs"
    ));
}

#[test]
fn test_probe_context_allows_lwt_helper_backed_ctx_fields() {
    let ctx = ProbeContext::new(EbpfProgramType::LwtOut, "demo-route");
    for field in [CtxField::CgroupClassid, CtxField::RouteRealm] {
        assert!(ctx.ctx_field_access_error(&field).is_none());
    }
}

#[test]
fn test_probe_context_allows_tc_action_helper_backed_ctx_fields() {
    let ctx = ProbeContext::new(EbpfProgramType::TcAction, "demo-action");
    for field in [
        CtxField::CgroupClassid,
        CtxField::RouteRealm,
        CtxField::SkbCgroupId,
    ] {
        assert!(ctx.ctx_field_access_error(&field).is_none());
    }
}

#[test]
fn test_probe_context_allows_csum_level_on_supported_skb_helper_programs() {
    for ctx in [
        ProbeContext::new(EbpfProgramType::LwtXmit, "demo-route"),
        ProbeContext::new(EbpfProgramType::TcAction, "demo-action"),
        ProbeContext::new(EbpfProgramType::Tc, "lo:ingress"),
        ProbeContext::new(EbpfProgramType::SkSkb, "/sys/fs/bpf/demo_sockmap"),
        ProbeContext::new(EbpfProgramType::SkSkbParser, "/sys/fs/bpf/demo_sockmap"),
    ] {
        assert!(ctx.ctx_field_access_error(&CtxField::CsumLevel).is_none());
        assert!(ctx.ctx_field_access_error(&CtxField::HashRecalc).is_none());
    }

    let ctx = ProbeContext::new(EbpfProgramType::LwtOut, "demo-route");
    assert!(ctx.ctx_field_access_error(&CtxField::HashRecalc).is_none());
}

#[test]
fn test_probe_context_rejects_csum_level_on_unsupported_skb_program() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:egress");
    let err = ctx
        .ctx_field_access_error(&CtxField::CsumLevel)
        .expect("expected unsupported csum_level access error");
    assert!(err.contains(
        "ctx.csum_level is only available on lwt_xmit, tc_action, tc, tcx, netkit, sk_skb, and sk_skb_parser programs"
    ));

    let err = ctx
        .ctx_field_access_error(&CtxField::HashRecalc)
        .expect("expected unsupported hash_recalc access error");
    assert!(err.contains(
        "ctx.hash_recalc is only available on lwt_*, tc_action, tc, tcx, netkit, sk_skb, and sk_skb_parser programs"
    ));
}

#[test]
fn test_probe_context_rejects_data_meta_on_cgroup_skb() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:egress");
    let err = ctx
        .ctx_field_access_error(&CtxField::DataMeta)
        .expect("expected cgroup_skb data_meta access error");
    assert!(err.contains(
        "ctx.data_meta is only available on xdp, tc_action, tc, tcx, and netkit programs"
    ));
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
            .contains(
                "ctx.tc_classid is only available on tc_action, tc, tcx, and netkit programs"
            )
    );
    assert!(ctx.ctx_field_access_error(&CtxField::NapiId).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::WireLen)
            .expect("expected cgroup_skb wire_len access error")
            .contains("ctx.wire_len is only available on tc_action, tc, tcx, and netkit programs")
    );
    assert!(ctx.ctx_field_access_error(&CtxField::GsoSegs).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::GsoSize).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Tstamp).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::TstampType)
            .expect("expected cgroup_skb tstamp_type access error")
            .contains(
                "ctx.tstamp_type is only available on tc_action, tc, tcx, and netkit programs"
            )
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
                "ctx.remote_port is only available on cgroup_skb, cgroup_sock, cgroup_sock_addr, sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs"
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
                "ctx.remote_port is only available on cgroup_skb, cgroup_sock, cgroup_sock_addr, sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs"
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
fn test_probe_context_limits_sock_addr_unix_hooks_to_common_socket_fields() {
    let ctx = ProbeContext::new(
        EbpfProgramType::CgroupSockAddr,
        "/sys/fs/cgroup:connect_unix",
    );

    assert!(ctx.ctx_field_access_error(&CtxField::Socket).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::UserFamily).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Family).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::SockType).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Protocol).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::UserIp4)
            .expect("expected unix hook rejection for ctx.user_ip4")
            .contains("IPv4 cgroup_sock_addr hooks")
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::UserIp6)
            .expect("expected unix hook rejection for ctx.user_ip6")
            .contains("IPv6 cgroup_sock_addr hooks")
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::UserPort)
            .expect("expected unix hook rejection for ctx.user_port")
            .contains("IPv4/IPv6 cgroup_sock_addr hooks")
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::RemotePort)
            .expect("expected unix hook rejection for ctx.remote_port")
            .contains("IPv4/IPv6 cgroup_sock_addr hooks")
    );
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
            .contains(
                "ctx.tc_classid is only available on tc_action, tc, tcx, and netkit programs"
            )
    );
    assert!(ctx.ctx_field_access_error(&CtxField::NapiId).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::WireLen)
            .expect("expected socket_filter wire_len access error")
            .contains("ctx.wire_len is only available on tc_action, tc, tcx, and netkit programs")
    );
    assert!(ctx.ctx_field_access_error(&CtxField::GsoSegs).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::GsoSize).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::Tstamp)
            .expect("expected socket_filter tstamp access error")
            .contains(
                "ctx.tstamp is only available on tc_action, tc, tcx, netkit, and cgroup_skb programs"
            )
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::TstampType)
            .expect("expected socket_filter tstamp_type access error")
            .contains(
                "ctx.tstamp_type is only available on tc_action, tc, tcx, and netkit programs"
            )
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::Hwtstamp)
            .expect("expected socket_filter hwtstamp access error")
            .contains(
                "ctx.hwtstamp is only available on tc_action, tc, tcx, netkit, and cgroup_skb programs"
            )
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
fn test_probe_context_allows_sk_reuseport_fields() {
    let ctx = ProbeContext::new(EbpfProgramType::SkReuseport, "select");

    assert!(ctx.ctx_field_access_error(&CtxField::PacketLen).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Data).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::DataEnd).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::EthProtocol).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Protocol).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::SkbHash).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::SocketCookie)
            .is_none()
    );
    assert!(ctx.ctx_field_access_error(&CtxField::Socket).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::BindInany).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::MigratingSocket)
            .is_none()
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::PktType)
            .expect("expected sk_reuseport pkt_type access error")
            .contains(
                "ctx.pkt_type is only available on socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, sk_skb, and sk_skb_parser programs"
            )
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::VlanTci)
            .expect("expected sk_reuseport vlan_tci access error")
            .contains(
                "ctx.vlan_tci is only available on socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, sk_skb, and sk_skb_parser programs"
            )
    );
}

#[test]
fn test_probe_context_allows_flow_dissector_fields() {
    let ctx = ProbeContext::new(EbpfProgramType::FlowDissector, "/proc/self/ns/net");

    assert!(ctx.ctx_field_access_error(&CtxField::Data).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::DataEnd).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::FlowKeys).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::PacketLen)
            .expect("expected flow_dissector packet_len access error")
            .contains("ctx.packet_len is not available on flow_dissector programs")
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::EthProtocol)
            .expect("expected flow_dissector eth_protocol access error")
            .contains("ctx.eth_protocol is not available on flow_dissector programs")
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::Protocol)
            .expect("expected flow_dissector protocol access error")
            .contains(
                "ctx.protocol is only available on skb-backed packet, lwt_*, tc_action, cgroup_sock, cgroup_sock_addr, sk_lookup, and sk_reuseport programs",
            )
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::Socket)
            .expect("expected flow_dissector sk access error")
            .contains(
                "ctx.sk is only available on socket_filter, tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock, cgroup_sock_addr, cgroup_sockopt, sk_lookup, sk_reuseport, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs"
            )
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::SkbHash)
            .expect("expected flow_dissector hash access error")
            .contains("ctx.hash is not available on flow_dissector programs")
    );
}

#[test]
fn test_probe_context_allows_netfilter_fields() {
    let ctx = ProbeContext::new(EbpfProgramType::Netfilter, "ipv4:pre_routing");

    assert!(
        ctx.ctx_field_access_error(&CtxField::NetfilterHook)
            .is_none()
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::NetfilterProtocolFamily)
            .is_none()
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::NetfilterState)
            .is_none()
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::NetfilterSkb)
            .is_none()
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::FlowKeys)
            .expect("expected flow_keys access error")
            .contains("ctx.flow_keys is only available on flow_dissector programs")
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::PacketLen)
            .expect("expected packet_len access error")
            .contains("ctx.packet_len is only available on packet-context programs")
    );
}

#[test]
fn test_probe_context_allows_lwt_skb_packet_fields_without_socket_fields() {
    let ctx = ProbeContext::new(EbpfProgramType::LwtXmit, "demo-route");

    assert!(ctx.ctx_field_access_error(&CtxField::PacketLen).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Data).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::DataEnd).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::EthProtocol).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Protocol).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::IngressIfindex)
            .is_none()
    );
    assert!(ctx.ctx_field_access_error(&CtxField::Ifindex).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::SkbHash).is_none());
    for (field, expected) in [
        (
            CtxField::TcClassid,
            "ctx.tc_classid is only available on tc_action, tc, tcx, and netkit programs",
        ),
        (
            CtxField::WireLen,
            "ctx.wire_len is only available on tc_action, tc, tcx, and netkit programs",
        ),
        (
            CtxField::Tstamp,
            "ctx.tstamp is only available on tc_action, tc, tcx, netkit, and cgroup_skb programs",
        ),
        (
            CtxField::TstampType,
            "ctx.tstamp_type is only available on tc_action, tc, tcx, and netkit programs",
        ),
        (
            CtxField::Hwtstamp,
            "ctx.hwtstamp is only available on tc_action, tc, tcx, netkit, and cgroup_skb programs",
        ),
    ] {
        assert!(
            ctx.ctx_field_access_error(&field)
                .unwrap_or_else(|| panic!("expected lwt access error for {field:?}"))
                .contains(expected)
        );
    }
    assert!(
        ctx.ctx_field_access_error(&CtxField::Socket)
            .expect("expected lwt socket access error")
            .contains(
                "ctx.sk is only available on socket_filter, tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock, cgroup_sock_addr, cgroup_sockopt, sk_lookup, sk_reuseport, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs"
            )
    );
}

#[test]
fn test_probe_context_allows_tc_action_skb_packet_fields() {
    let ctx = ProbeContext::new(EbpfProgramType::TcAction, "demo-action");

    assert!(ctx.ctx_field_access_error(&CtxField::PacketLen).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Data).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::DataEnd).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::DataMeta).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::EthProtocol).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Protocol).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::IngressIfindex)
            .is_none()
    );
    assert!(ctx.ctx_field_access_error(&CtxField::Ifindex).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::SkbHash).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Socket).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::SocketCookie)
            .is_none()
    );
    assert!(ctx.ctx_field_access_error(&CtxField::SocketUid).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::NetnsCookie).is_none());
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
fn test_probe_context_rejects_cgroup_id_on_contextless_programs() {
    for (program_type, target) in [
        (EbpfProgramType::Extension, "replace_me"),
        (EbpfProgramType::Syscall, "demo"),
        (EbpfProgramType::StructOps, "sched_ext_ops"),
    ] {
        let ctx = ProbeContext::new(program_type, target);
        let err = ctx
            .ctx_field_access_error(&CtxField::CgroupId)
            .expect("expected ctx.cgroup_id field access error");
        assert!(
            err.contains(&format!(
                "ctx.cgroup_id is not available on {} programs",
                program_type.canonical_prefix()
            )),
            "unexpected error for {program_type:?}: {err}"
        );
    }
}

#[test]
fn test_probe_context_allows_task_on_task_aware_programs() {
    let ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    assert!(ctx.ctx_field_access_error(&CtxField::Task).is_none());
    assert!(ctx.validate_load_ctx_field(&CtxField::Task).is_ok());
}

#[test]
fn test_probe_context_allows_iter_task_only_on_task_iterator() {
    let ctx = ProbeContext::new(EbpfProgramType::Iter, "task");
    assert_eq!(
        ctx.resolve_ctx_field_name("task")
            .expect("iter task alias should resolve"),
        CtxField::IterTask
    );
    assert_eq!(
        ctx.resolve_ctx_field_name("current_task")
            .expect("current_task should resolve separately"),
        CtxField::Task
    );
    assert!(ctx.ctx_field_access_error(&CtxField::IterTask).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::IterMeta).is_none());
    assert!(ctx.validate_load_ctx_field(&CtxField::IterTask).is_ok());
    assert!(ctx.validate_load_ctx_field(&CtxField::IterMeta).is_ok());
    assert!(ctx.ctx_field_access_error(&CtxField::Task).is_some());
    assert!(ctx.ctx_field_access_error(&CtxField::IterFile).is_some());
    assert!(ctx.ctx_field_access_error(&CtxField::IterVma).is_some());
}

#[test]
fn test_probe_context_allows_task_file_iterator_payload_roots() {
    let ctx = ProbeContext::new(EbpfProgramType::Iter, "task_file");
    assert!(ctx.ctx_field_access_error(&CtxField::IterTask).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::IterFd).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::IterFile).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::IterMeta).is_none());
    assert!(ctx.validate_load_ctx_field(&CtxField::IterTask).is_ok());
    assert!(ctx.validate_load_ctx_field(&CtxField::IterFd).is_ok());
    assert!(ctx.validate_load_ctx_field(&CtxField::IterFile).is_ok());
    assert!(ctx.ctx_field_access_error(&CtxField::IterVma).is_some());
}

#[test]
fn test_probe_context_allows_task_vma_iterator_payload_roots() {
    let ctx = ProbeContext::new(EbpfProgramType::Iter, "task_vma");
    assert!(ctx.ctx_field_access_error(&CtxField::IterTask).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::IterVma).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::IterMeta).is_none());
    assert!(ctx.validate_load_ctx_field(&CtxField::IterTask).is_ok());
    assert!(ctx.validate_load_ctx_field(&CtxField::IterVma).is_ok());
    assert!(ctx.ctx_field_access_error(&CtxField::IterFile).is_some());
}

#[test]
fn test_probe_context_allows_cgroup_iterator_payload_root() {
    let ctx = ProbeContext::new(EbpfProgramType::Iter, "cgroup");
    assert_eq!(
        ctx.resolve_ctx_field_name("cgroup")
            .expect("iter cgroup alias should resolve"),
        CtxField::IterCgroup
    );
    assert_eq!(
        ctx.resolve_ctx_field_name("current_cgroup")
            .expect("current_cgroup should resolve separately"),
        CtxField::Cgroup
    );
    assert!(ctx.ctx_field_access_error(&CtxField::IterCgroup).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::IterMeta).is_none());
    assert!(ctx.validate_load_ctx_field(&CtxField::IterCgroup).is_ok());
    assert!(ctx.ctx_field_access_error(&CtxField::Cgroup).is_some());
    assert!(ctx.ctx_field_access_error(&CtxField::IterTask).is_some());
}

#[test]
fn test_probe_context_allows_bpf_object_iterator_payload_roots() {
    let map = ProbeContext::new(EbpfProgramType::Iter, "bpf_map");
    assert_eq!(
        map.resolve_ctx_field_name("map")
            .expect("iter map alias should resolve"),
        CtxField::IterMap
    );
    assert!(map.ctx_field_access_error(&CtxField::IterMap).is_none());
    assert!(map.ctx_field_access_error(&CtxField::IterMapKey).is_some());

    let elem = ProbeContext::new(EbpfProgramType::Iter, "bpf_map_elem");
    assert!(elem.ctx_field_access_error(&CtxField::IterMap).is_none());
    assert!(elem.ctx_field_access_error(&CtxField::IterMapKey).is_none());
    assert!(
        elem.ctx_field_access_error(&CtxField::IterMapValue)
            .is_none()
    );
    assert!(elem.validate_load_ctx_field(&CtxField::IterMap).is_ok());
    assert!(elem.validate_load_ctx_field(&CtxField::IterMapKey).is_ok());
    assert!(
        elem.validate_load_ctx_field(&CtxField::IterMapValue)
            .is_ok()
    );

    let prog = ProbeContext::new(EbpfProgramType::Iter, "bpf_prog");
    assert!(prog.ctx_field_access_error(&CtxField::IterProg).is_none());
    assert!(prog.validate_load_ctx_field(&CtxField::IterProg).is_ok());

    let link = ProbeContext::new(EbpfProgramType::Iter, "bpf_link");
    assert!(link.ctx_field_access_error(&CtxField::IterLink).is_none());
    assert!(link.validate_load_ctx_field(&CtxField::IterLink).is_ok());

    let sk_storage = ProbeContext::new(EbpfProgramType::Iter, "bpf_sk_storage_map");
    assert!(
        sk_storage
            .ctx_field_access_error(&CtxField::IterSock)
            .is_none()
    );
    assert!(
        sk_storage
            .validate_load_ctx_field(&CtxField::IterSock)
            .is_ok()
    );

    let sockmap = ProbeContext::new(EbpfProgramType::Iter, "sockmap");
    assert!(
        sockmap
            .ctx_field_access_error(&CtxField::IterSock)
            .is_none()
    );
    assert!(sockmap.validate_load_ctx_field(&CtxField::IterSock).is_ok());
    assert!(
        sockmap
            .ctx_field_access_error(&CtxField::IterMapValue)
            .is_some()
    );
}

#[test]
fn test_probe_context_allows_network_iterator_payload_roots() {
    let tcp = ProbeContext::new(EbpfProgramType::Iter, "tcp");
    assert_eq!(
        tcp.resolve_ctx_field_name("sk_common")
            .expect("iter tcp sk_common alias should resolve"),
        CtxField::IterSkCommon
    );
    assert_eq!(
        tcp.resolve_ctx_field_name("uid")
            .expect("iter uid alias should resolve"),
        CtxField::IterUid
    );
    assert!(
        tcp.ctx_field_access_error(&CtxField::IterSkCommon)
            .is_none()
    );
    assert!(tcp.ctx_field_access_error(&CtxField::IterUid).is_none());
    assert!(tcp.validate_load_ctx_field(&CtxField::IterSkCommon).is_ok());
    assert!(tcp.validate_load_ctx_field(&CtxField::IterUid).is_ok());
    assert!(tcp.ctx_field_access_error(&CtxField::IterUdpSk).is_some());

    let udp = ProbeContext::new(EbpfProgramType::Iter, "udp");
    assert!(udp.ctx_field_access_error(&CtxField::IterUdpSk).is_none());
    assert!(udp.ctx_field_access_error(&CtxField::IterUid).is_none());
    assert!(udp.ctx_field_access_error(&CtxField::IterBucket).is_none());
    assert!(udp.validate_load_ctx_field(&CtxField::IterUdpSk).is_ok());
    assert!(udp.validate_load_ctx_field(&CtxField::IterBucket).is_ok());
    assert!(
        udp.ctx_field_access_error(&CtxField::IterSkCommon)
            .is_some()
    );

    let unix = ProbeContext::new(EbpfProgramType::Iter, "unix");
    assert!(unix.ctx_field_access_error(&CtxField::IterUnixSk).is_none());
    assert!(unix.ctx_field_access_error(&CtxField::IterUid).is_none());
    assert!(unix.validate_load_ctx_field(&CtxField::IterUnixSk).is_ok());
    assert!(unix.ctx_field_access_error(&CtxField::IterBucket).is_some());
}

#[test]
fn test_probe_context_allows_misc_single_pointer_iterator_payload_roots() {
    for (target, alias, field) in [
        ("dmabuf", "dmabuf", CtxField::IterDmabuf),
        ("ipv6_route", "rt", CtxField::IterIpv6Route),
        ("kmem_cache", "kmem_cache", CtxField::IterKmemCache),
        ("ksym", "ksym", CtxField::IterKsym),
        ("netlink", "netlink_sk", CtxField::IterNetlinkSk),
    ] {
        let ctx = ProbeContext::new(EbpfProgramType::Iter, target);
        assert_eq!(
            ctx.resolve_ctx_field_name(alias)
                .unwrap_or_else(|_| panic!("{target} alias should resolve")),
            field
        );
        assert!(ctx.ctx_field_access_error(&field).is_none());
        assert!(ctx.validate_load_ctx_field(&field).is_ok());
        assert!(ctx.ctx_field_access_error(&CtxField::IterTask).is_some());
    }
}

#[test]
fn test_probe_context_rejects_iter_payload_roots_on_unrelated_iterators() {
    let ctx = ProbeContext::new(EbpfProgramType::Iter, "map");
    let err = ctx
        .ctx_field_access_error(&CtxField::IterTask)
        .expect("expected iter task field access error");
    assert_eq!(
        err,
        "ctx.iter_task is only available on iter:task, iter:task_file, and iter:task_vma programs"
    );
    assert!(ctx.ctx_field_access_error(&CtxField::IterMeta).is_none());
    assert_eq!(
        ctx.ctx_field_access_error(&CtxField::IterFile)
            .expect("expected iter file field access error"),
        "ctx.iter_file is only available on iter:task_file programs"
    );
    assert_eq!(
        ctx.ctx_field_access_error(&CtxField::IterCgroup)
            .expect("expected iter cgroup field access error"),
        "ctx.iter_cgroup is only available on iter:cgroup programs"
    );
    assert_eq!(
        ctx.ctx_field_access_error(&CtxField::IterMap)
            .expect("expected iter map field access error"),
        "ctx.iter_map is only available on iter:bpf_map, iter:bpf_map_elem, iter:bpf_sk_storage_map, and iter:sockmap programs"
    );
    assert_eq!(
        ctx.ctx_field_access_error(&CtxField::IterUid)
            .expect("expected iter uid field access error"),
        "ctx.iter_uid is only available on iter:tcp, iter:udp, and iter:unix programs"
    );
    assert_eq!(
        ctx.ctx_field_access_error(&CtxField::IterDmabuf)
            .expect("expected iter dmabuf field access error"),
        "ctx.iter_dmabuf is only available on iter:dmabuf programs"
    );
    assert_eq!(
        ctx.ctx_field_access_error(&CtxField::IterSock)
            .expect("expected iter sock field access error"),
        "ctx.iter_sock is only available on iter:bpf_sk_storage_map and iter:sockmap programs"
    );
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
        "ctx.netns_cookie is only available on socket_filter, tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock, cgroup_sockopt, cgroup_sock_addr, sk_msg, and sock_ops programs"
    ));
}

#[test]
fn test_probe_context_rejects_socket_uid_on_sk_lookup() {
    let ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");
    let err = ctx
        .ctx_field_access_error(&CtxField::SocketUid)
        .expect("expected socket_uid field access error");
    assert!(err.contains(
        "ctx.socket_uid is only available on socket_filter, tc_action, tc, tcx, netkit, cgroup_skb, sk_skb, and sk_skb_parser programs"
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
            .contains(
                "ctx.tc_classid is only available on tc_action, tc, tcx, and netkit programs"
            )
    );
    assert!(ctx.ctx_field_access_error(&CtxField::NapiId).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::WireLen)
            .expect("expected sk_skb wire_len access error")
            .contains("ctx.wire_len is only available on tc_action, tc, tcx, and netkit programs")
    );
    assert!(ctx.ctx_field_access_error(&CtxField::GsoSegs).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::GsoSize).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::Tstamp)
            .expect("expected sk_skb tstamp access error")
            .contains(
                "ctx.tstamp is only available on tc_action, tc, tcx, netkit, and cgroup_skb programs"
            )
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::TstampType)
            .expect("expected sk_skb tstamp_type access error")
            .contains(
                "ctx.tstamp_type is only available on tc_action, tc, tcx, and netkit programs"
            )
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::Hwtstamp)
            .expect("expected sk_skb hwtstamp access error")
            .contains(
                "ctx.hwtstamp is only available on tc_action, tc, tcx, netkit, and cgroup_skb programs"
            )
    );
    assert!(ctx.ctx_field_access_error(&CtxField::Data).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::DataEnd).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::Ifindex).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::TcIndex).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::SkbHash).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::SockMark)
            .expect("expected sk_skb mark access error")
            .contains("ctx.mark is only available on cgroup_sock, socket_filter, lwt_*, tc_action, tc, tcx, netkit, and cgroup_skb programs")
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
            .contains(
                "ctx.tc_classid is only available on tc_action, tc, tcx, and netkit programs"
            )
    );
    assert!(ctx.ctx_field_access_error(&CtxField::NapiId).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::WireLen)
            .expect("expected sk_skb_parser wire_len access error")
            .contains("ctx.wire_len is only available on tc_action, tc, tcx, and netkit programs")
    );
    assert!(ctx.ctx_field_access_error(&CtxField::GsoSegs).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::GsoSize).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::Tstamp)
            .expect("expected sk_skb_parser tstamp access error")
            .contains(
                "ctx.tstamp is only available on tc_action, tc, tcx, netkit, and cgroup_skb programs"
            )
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::TstampType)
            .expect("expected sk_skb_parser tstamp_type access error")
            .contains(
                "ctx.tstamp_type is only available on tc_action, tc, tcx, and netkit programs"
            )
    );
    assert!(
        ctx.ctx_field_access_error(&CtxField::Hwtstamp)
            .expect("expected sk_skb_parser hwtstamp access error")
            .contains(
                "ctx.hwtstamp is only available on tc_action, tc, tcx, netkit, and cgroup_skb programs"
            )
    );
    assert!(ctx.ctx_field_access_error(&CtxField::Ifindex).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::TcIndex).is_none());
    assert!(ctx.ctx_field_access_error(&CtxField::SkbHash).is_none());
    assert!(
        ctx.ctx_field_access_error(&CtxField::SockMark)
            .expect("expected sk_skb_parser mark access error")
            .contains("ctx.mark is only available on cgroup_sock, socket_filter, lwt_*, tc_action, tc, tcx, netkit, and cgroup_skb programs")
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
    assert!(
        ctx.ctx_field_access_error(&CtxField::DeviceAccess)
            .is_none()
    );
    assert!(ctx.ctx_field_access_error(&CtxField::DeviceType).is_none());
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
fn test_probe_context_rejects_cgroup_sock_addr_unix_tuple_store_targets() {
    let ctx = ProbeContext::new(
        EbpfProgramType::CgroupSockAddr,
        "/sys/fs/cgroup:connect_unix",
    );

    assert!(
        ctx.resolve_ctx_store_target("user_port", None)
            .expect_err("cgroup_sock_addr unix user_port store target should be rejected")
            .contains("IPv4/IPv6 cgroup_sock_addr hooks")
    );
    assert!(
        ctx.resolve_ctx_store_target("remote_port", None)
            .expect_err("cgroup_sock_addr unix remote_port store target should be rejected")
            .contains("IPv4/IPv6 cgroup_sock_addr hooks")
    );
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

#[test]
fn test_validate_runtime_artifacts_requires_generic_maps_for_arbitrary_maps() {
    let program = EbpfProgram::with_maps(
        EbpfProgramType::Syscall,
        "demo",
        "test",
        vec![],
        0,
        vec![EbpfMap {
            name: "scratch".to_string(),
            def: BpfMapDef::hash(8, 8, 1024),
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
        .expect_err("expected generic map capability validation error");

    assert!(
        matches!(err, CompileError::InvalidProgram(msg) if msg.contains("syscall programs do not support generic map operations required by runtime map 'scratch'"))
    );
}

#[test]
fn test_validate_runtime_artifacts_accepts_arbitrary_maps_with_generic_maps() {
    let program = EbpfProgram::with_maps(
        EbpfProgramType::Xdp,
        "lo",
        "test",
        vec![],
        0,
        vec![EbpfMap {
            name: "scratch".to_string(),
            def: BpfMapDef::hash(8, 8, 1024),
        }],
        vec![],
        vec![],
        None,
        None,
        HashMap::new(),
        HashMap::new(),
    );

    program
        .validate_runtime_artifacts()
        .expect("generic-map-capable program should accept arbitrary runtime maps");
}

#[test]
fn test_bpf_map_def_reports_modeled_map_kind() {
    assert_eq!(BpfMapDef::hash(8, 8, 16).map_kind(), Some(MapKind::Hash));
    assert_eq!(
        BpfMapDef::dev_map_hash(8, 16).map_kind(),
        Some(MapKind::DevMapHash)
    );
    assert_eq!(
        BpfMapDef::reuseport_sockarray(16).map_kind(),
        Some(MapKind::ReuseportSockArray)
    );
    assert_eq!(
        BpfMapDef {
            map_type: BpfMapType::ArrayOfMaps as u32,
            key_size: 4,
            value_size: 4,
            max_entries: 1,
            map_flags: 0,
            pinning: BpfPinningType::None,
        }
        .map_kind(),
        Some(MapKind::ArrayOfMaps)
    );
    assert_eq!(
        BpfMapDef {
            map_type: BpfMapType::UserRingBuf as u32,
            key_size: 0,
            value_size: 0,
            max_entries: 4096,
            map_flags: 0,
            pinning: BpfPinningType::None,
        }
        .map_kind(),
        Some(MapKind::UserRingBuf)
    );

    let unknown = BpfMapDef {
        map_type: 999,
        key_size: 4,
        value_size: 4,
        max_entries: 1,
        map_flags: 0,
        pinning: BpfPinningType::None,
    };
    assert_eq!(unknown.map_kind(), None);
    assert_eq!(unknown.map_type_name(), "Unknown");
}

#[test]
fn test_validate_runtime_artifacts_rejects_unknown_runtime_map_type() {
    let program = EbpfProgram::with_maps(
        EbpfProgramType::Xdp,
        "lo",
        "test",
        vec![],
        0,
        vec![EbpfMap {
            name: "scratch".to_string(),
            def: BpfMapDef {
                map_type: 999,
                key_size: 4,
                value_size: 4,
                max_entries: 1,
                map_flags: 0,
                pinning: BpfPinningType::None,
            },
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
        .expect_err("expected unknown map type validation error");

    assert!(
        matches!(err, CompileError::InvalidProgram(msg) if msg.contains("runtime map 'scratch' uses unsupported map type 999"))
    );
}

#[test]
fn test_validate_runtime_artifacts_rejects_known_unmodeled_runtime_map_types() {
    for (map_type, expected) in [
        (
            BpfMapType::ArrayOfMaps,
            "requires inner-map metadata, which is not modeled",
        ),
        (
            BpfMapType::HashOfMaps,
            "requires inner-map metadata, which is not modeled",
        ),
        (BpfMapType::StructOps, "reserved for struct_ops objects"),
        (
            BpfMapType::Arena,
            "arena map_extra/mmap support is not modeled",
        ),
        (
            BpfMapType::CgroupStorage,
            "deprecated cgroup-storage map type",
        ),
        (
            BpfMapType::PerCpuCgroupStorage,
            "deprecated cgroup-storage map type",
        ),
    ] {
        let program = EbpfProgram::with_maps(
            EbpfProgramType::Xdp,
            "lo",
            "test",
            vec![],
            0,
            vec![EbpfMap {
                name: "scratch".to_string(),
                def: BpfMapDef {
                    map_type: map_type as u32,
                    key_size: 4,
                    value_size: 4,
                    max_entries: 1,
                    map_flags: 0,
                    pinning: BpfPinningType::None,
                },
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
            .expect_err("expected known unmodeled map type validation error");
        assert!(
            matches!(err, CompileError::InvalidProgram(ref msg) if msg.contains(expected)),
            "unexpected error for {map_type:?}: {err:?}"
        );
    }
}

#[test]
fn test_validate_runtime_artifacts_accepts_user_ringbuf_runtime_map() {
    let program = EbpfProgram::with_maps(
        EbpfProgramType::Xdp,
        "lo",
        "test",
        vec![],
        0,
        vec![EbpfMap {
            name: "scratch".to_string(),
            def: BpfMapDef::user_ring_buffer(4096),
        }],
        vec![],
        vec![],
        None,
        None,
        HashMap::new(),
        HashMap::new(),
    );

    program
        .validate_runtime_artifacts()
        .expect("expected user ring buffer runtime map to validate");
}

#[test]
fn test_validate_runtime_artifacts_rejects_malformed_runtime_map_shape() {
    let mut def = BpfMapDef::queue(8, 16);
    def.key_size = 4;
    let program = EbpfProgram::with_maps(
        EbpfProgramType::Xdp,
        "lo",
        "test",
        vec![],
        0,
        vec![EbpfMap {
            name: "work".to_string(),
            def,
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
        .expect_err("expected malformed map definition validation error");

    assert!(
        matches!(err, CompileError::InvalidProgram(msg) if msg.contains("runtime map 'work' (Queue) must have key_size 0, got 4"))
    );
}
