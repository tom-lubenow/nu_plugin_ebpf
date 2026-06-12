pub(super) use std::collections::BTreeSet;

pub(super) use crate::compiler::instruction::BpfHelper;
pub(super) use crate::compiler::mir::CtxField;
pub(super) use crate::compiler::{
    CompiledFeatureCompatibilityRequirement, ContextFieldCompatibilityRequirement, EbpfProgramType,
    GlobalCompatibilityRequirement, HelperCompatibilityRequirement, KfuncCompatibilityRequirement,
    MapKind, MapValueCompatibilityRequirement, ProgramCompatibilityRequirement,
};
pub(super) use crate::kernel_btf::TracepointContext;
pub(super) use crate::program_spec::{IterTargetKind, ProgramSpec};

use super::parser_support::VerifierDiffFeatureRecord;

pub(super) fn program_compatibility_verifier_feature_key(
    requirement: ProgramCompatibilityRequirement,
) -> Option<&'static str> {
    Some(match requirement {
        ProgramCompatibilityRequirement::SocketFilterProgram => {
            "program:BPF_PROG_TYPE_SOCKET_FILTER"
        }
        ProgramCompatibilityRequirement::KprobeProgram => "program:BPF_PROG_TYPE_KPROBE",
        ProgramCompatibilityRequirement::TracepointProgram => "program:BPF_PROG_TYPE_TRACEPOINT",
        ProgramCompatibilityRequirement::RawTracepointProgram => {
            "program:BPF_PROG_TYPE_RAW_TRACEPOINT"
        }
        ProgramCompatibilityRequirement::PerfEventProgram => "program:BPF_PROG_TYPE_PERF_EVENT",
        ProgramCompatibilityRequirement::XdpProgram => "program:BPF_PROG_TYPE_XDP",
        ProgramCompatibilityRequirement::XdpSkbAttachMode => "attach:xdp-skb",
        ProgramCompatibilityRequirement::XdpDrvAttachMode => "attach:xdp-drv",
        ProgramCompatibilityRequirement::XdpHwAttachMode => "attach:xdp-hw",
        ProgramCompatibilityRequirement::XdpDevmapAttach => "attach:BPF_XDP_DEVMAP",
        ProgramCompatibilityRequirement::XdpCpumapAttach => "attach:BPF_XDP_CPUMAP",
        ProgramCompatibilityRequirement::TcProgram => "program:BPF_PROG_TYPE_SCHED_CLS",
        ProgramCompatibilityRequirement::SkLookupProgram => "program:BPF_PROG_TYPE_SK_LOOKUP",
        ProgramCompatibilityRequirement::TracingProgram => "program:BPF_PROG_TYPE_TRACING",
        ProgramCompatibilityRequirement::LsmProgram => "program:BPF_PROG_TYPE_LSM",
        ProgramCompatibilityRequirement::KernelBtf => "kernel:btf-vmlinux",
        ProgramCompatibilityRequirement::BpfTrampoline => "program:bpf-trampoline",
        ProgramCompatibilityRequirement::SleepableProgram => "section:sleepable-program",
        ProgramCompatibilityRequirement::KprobeMulti => "attach:BPF_TRACE_KPROBE_MULTI",
        ProgramCompatibilityRequirement::UprobeMulti => "attach:BPF_TRACE_UPROBE_MULTI",
        ProgramCompatibilityRequirement::RawTracepointWritable => "section:raw_tracepoint.w",
        ProgramCompatibilityRequirement::CgroupLsm => "attach:BPF_LSM_CGROUP",
        ProgramCompatibilityRequirement::ExtensionProgram => "program:BPF_PROG_TYPE_EXT",
        ProgramCompatibilityRequirement::SyscallProgram => "program:BPF_PROG_TYPE_SYSCALL",
        ProgramCompatibilityRequirement::BpfIterator => "program:BPF_PROG_TYPE_TRACING-iter",
        ProgramCompatibilityRequirement::BpfIteratorTaskTarget => "iter-target:task",
        ProgramCompatibilityRequirement::BpfIteratorTaskFileTarget => "iter-target:task_file",
        ProgramCompatibilityRequirement::BpfIteratorTaskVmaTarget => "iter-target:task_vma",
        ProgramCompatibilityRequirement::BpfIteratorBpfMapTarget => "iter-target:bpf_map",
        ProgramCompatibilityRequirement::BpfIteratorCgroupTarget => "iter-target:cgroup",
        ProgramCompatibilityRequirement::BpfIteratorBpfMapElemTarget => "iter-target:bpf_map_elem",
        ProgramCompatibilityRequirement::BpfIteratorBpfSkStorageMapTarget => {
            "iter-target:bpf_sk_storage_map"
        }
        ProgramCompatibilityRequirement::BpfIteratorSockmapTarget => "iter-target:sockmap",
        ProgramCompatibilityRequirement::BpfIteratorBpfProgTarget => "iter-target:bpf_prog",
        ProgramCompatibilityRequirement::BpfIteratorBpfLinkTarget => "iter-target:bpf_link",
        ProgramCompatibilityRequirement::BpfIteratorTcpTarget => "iter-target:tcp",
        ProgramCompatibilityRequirement::BpfIteratorUdpTarget => "iter-target:udp",
        ProgramCompatibilityRequirement::BpfIteratorUnixTarget => "iter-target:unix",
        ProgramCompatibilityRequirement::BpfIteratorIpv6RouteTarget => "iter-target:ipv6_route",
        ProgramCompatibilityRequirement::BpfIteratorKsymTarget => "iter-target:ksym",
        ProgramCompatibilityRequirement::BpfIteratorNetlinkTarget => "iter-target:netlink",
        ProgramCompatibilityRequirement::BpfIteratorKmemCacheTarget => "iter-target:kmem_cache",
        ProgramCompatibilityRequirement::BpfIteratorDmabufTarget => "iter-target:dmabuf",
        ProgramCompatibilityRequirement::XdpMultiBuffer => "section:xdp.frags",
        ProgramCompatibilityRequirement::FlowDissector => "program:BPF_PROG_TYPE_FLOW_DISSECTOR",
        ProgramCompatibilityRequirement::Tcx => "attach:tcx",
        ProgramCompatibilityRequirement::Netkit => "attach:netkit",
        ProgramCompatibilityRequirement::NetfilterLink => "attach:netfilter-link",
        ProgramCompatibilityRequirement::NetfilterDefrag => "attach:netfilter-defrag",
        ProgramCompatibilityRequirement::RouteLwt => "program:BPF_PROG_TYPE_LWT",
        ProgramCompatibilityRequirement::RouteLwtSeg6Local => "program:BPF_PROG_TYPE_LWT_SEG6LOCAL",
        ProgramCompatibilityRequirement::SockMapAttach => return None,
        ProgramCompatibilityRequirement::SkMsgSockMapAttach => "program:BPF_PROG_TYPE_SK_MSG",
        ProgramCompatibilityRequirement::SkSkbSockMapAttach => "program:BPF_PROG_TYPE_SK_SKB",
        ProgramCompatibilityRequirement::SkReuseportAttach => "attach:BPF_SK_REUSEPORT_SELECT",
        ProgramCompatibilityRequirement::SkReuseportMigration => {
            "attach:BPF_SK_REUSEPORT_SELECT_OR_MIGRATE"
        }
        ProgramCompatibilityRequirement::TcActionProgram => "program:BPF_PROG_TYPE_SCHED_ACT",
        ProgramCompatibilityRequirement::CgroupSkbProgram => "program:BPF_PROG_TYPE_CGROUP_SKB",
        ProgramCompatibilityRequirement::CgroupSockProgram => "program:BPF_PROG_TYPE_CGROUP_SOCK",
        ProgramCompatibilityRequirement::CgroupDeviceProgram => {
            "program:BPF_PROG_TYPE_CGROUP_DEVICE"
        }
        ProgramCompatibilityRequirement::CgroupSockAddrProgram => {
            "program:BPF_PROG_TYPE_CGROUP_SOCK_ADDR"
        }
        ProgramCompatibilityRequirement::CgroupSysctlProgram => {
            "program:BPF_PROG_TYPE_CGROUP_SYSCTL"
        }
        ProgramCompatibilityRequirement::CgroupSockoptProgram => {
            "program:BPF_PROG_TYPE_CGROUP_SOCKOPT"
        }
        ProgramCompatibilityRequirement::SockOpsProgram => "program:BPF_PROG_TYPE_SOCK_OPS",
        ProgramCompatibilityRequirement::CgroupV2 => return None,
        ProgramCompatibilityRequirement::LircMode2 => "program:BPF_PROG_TYPE_LIRC_MODE2",
        ProgramCompatibilityRequirement::StructOps => "program:BPF_PROG_TYPE_STRUCT_OPS",
        ProgramCompatibilityRequirement::TcpCongestionOps => "struct_ops:tcp_congestion_ops",
        ProgramCompatibilityRequirement::HidBpfOps => "struct_ops:hid_bpf_ops",
        ProgramCompatibilityRequirement::SchedExt => "struct_ops:sched_ext_ops",
        ProgramCompatibilityRequirement::QdiscOps => "struct_ops:Qdisc_ops",
        ProgramCompatibilityRequirement::CgroupUnixSockAddr => "attach:BPF_CGROUP_UNIX_SOCK_ADDR",
    })
}

pub(super) fn assert_verifier_feature_record_matches_context_requirement(
    label: &str,
    requirement: &ContextFieldCompatibilityRequirement,
    record: &VerifierDiffFeatureRecord,
) {
    assert_eq!(
        record.key,
        requirement.key(),
        "scripts/verifier_diff.nu context-field feature key drifted for {label}"
    );
    assert_eq!(
        record.min_kernel,
        requirement.minimum_kernel(),
        "scripts/verifier_diff.nu context-field min_kernel drifted for {label}"
    );
    assert_eq!(
        record.source,
        requirement.minimum_kernel_source(),
        "scripts/verifier_diff.nu context-field source drifted for {label}"
    );
    assert_eq!(
        record.max_kernel_exclusive, None,
        "context-field compatibility features should not use max_kernel_exclusive"
    );
}

pub(super) fn assert_verifier_feature_record_matches_kfunc_requirement(
    name: &str,
    requirement: KfuncCompatibilityRequirement,
    record: &VerifierDiffFeatureRecord,
) {
    assert_eq!(
        record.key,
        requirement.key(),
        "scripts/verifier_diff.nu kfunc feature key drifted for {name}"
    );
    assert_eq!(
        record.min_kernel,
        requirement.minimum_kernel(),
        "scripts/verifier_diff.nu kfunc min_kernel drifted for {name}"
    );
    assert_eq!(
        record.source,
        requirement.minimum_kernel_source(),
        "scripts/verifier_diff.nu kfunc source drifted for {name}"
    );
    assert_eq!(
        record.max_kernel_exclusive.as_deref(),
        requirement.maximum_kernel_exclusive(),
        "scripts/verifier_diff.nu kfunc max_kernel_exclusive drifted for {name}"
    );
    assert_eq!(
        record.max_kernel_exclusive_source.as_deref(),
        requirement.maximum_kernel_exclusive_source(),
        "scripts/verifier_diff.nu kfunc max_kernel_exclusive_source drifted for {name}"
    );
}

pub(super) fn verifier_feature_record_matches_context_requirement(
    requirement: &ContextFieldCompatibilityRequirement,
    record: &VerifierDiffFeatureRecord,
) -> bool {
    record.key == requirement.key()
        && record.min_kernel == requirement.minimum_kernel()
        && record.source == requirement.minimum_kernel_source()
        && record.max_kernel_exclusive.is_none()
}

pub(super) fn all_modeled_tracepoint_payload_scanner_checks() -> Vec<(String, String)> {
    let mut checks = BTreeSet::new();

    for &syscall in TracepointContext::well_known_sys_enter_syscalls() {
        let enter_name = format!("sys_enter_{syscall}");
        let enter_target = format!("tracepoint:syscalls/{enter_name}");
        for field in TracepointContext::sys_enter(&enter_name).fields {
            checks.insert((enter_target.clone(), field.name));
        }

        let exit_name = format!("sys_exit_{syscall}");
        let exit_target = format!("tracepoint:syscalls/{exit_name}");
        for field in TracepointContext::sys_exit(&exit_name).fields {
            checks.insert((exit_target.clone(), field.name));
        }
    }

    checks.into_iter().collect()
}

pub(super) fn helper_feature_keys(
    helpers: impl IntoIterator<Item = BpfHelper>,
) -> BTreeSet<String> {
    helpers
        .into_iter()
        .map(|helper| {
            HelperCompatibilityRequirement::for_helper(helper)
                .unwrap_or_else(|| {
                    panic!(
                        "{} should carry helper compatibility metadata",
                        helper.name()
                    )
                })
                .key()
        })
        .collect()
}

pub(super) fn map_kind_feature_keys(kinds: impl IntoIterator<Item = MapKind>) -> BTreeSet<String> {
    kinds
        .into_iter()
        .map(|kind| kind.compatibility_requirement().key().to_string())
        .collect()
}

pub(super) fn map_value_feature_keys(
    requirements: impl IntoIterator<Item = MapValueCompatibilityRequirement>,
) -> BTreeSet<String> {
    requirements
        .into_iter()
        .map(|requirement| requirement.key().to_string())
        .collect()
}

pub(super) fn compiled_feature_keys(
    requirements: impl IntoIterator<Item = CompiledFeatureCompatibilityRequirement>,
) -> BTreeSet<String> {
    requirements
        .into_iter()
        .map(|requirement| requirement.key().to_string())
        .collect()
}

pub(super) fn global_feature_keys(
    requirements: impl IntoIterator<Item = GlobalCompatibilityRequirement>,
) -> BTreeSet<String> {
    requirements
        .into_iter()
        .map(|requirement| requirement.key().to_string())
        .collect()
}

pub(super) fn program_feature_keys(
    requirements: impl IntoIterator<Item = ProgramCompatibilityRequirement>,
) -> BTreeSet<String> {
    requirements
        .into_iter()
        .filter_map(program_compatibility_verifier_feature_key)
        .map(str::to_string)
        .collect()
}

pub(super) fn kfunc_feature_keys_for_target<'a>(
    target: &str,
    kfuncs: impl IntoIterator<Item = &'a str>,
) -> BTreeSet<String> {
    let spec = ProgramSpec::parse(target)
        .unwrap_or_else(|err| panic!("representative kfunc target {target} should parse: {err}"));
    kfuncs
        .into_iter()
        .map(|kfunc| {
            spec.kfunc_compatibility_requirement_for_name(kfunc)
                .unwrap_or_else(|| {
                    panic!(
                        "representative kfunc target {target} should expose metadata for {kfunc}"
                    )
                })
                .key()
        })
        .collect()
}
