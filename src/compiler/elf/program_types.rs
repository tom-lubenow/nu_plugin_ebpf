use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramContextFamily {
    Probe,
    PerfEvent,
    Xdp,
    SkBuffPacket,
    SkLookup,
    FlowDissector,
    Netfilter,
    SkReuseport,
    SkMsg,
    SockOps,
    CgroupSock,
    CgroupSysctl,
    CgroupSockopt,
    CgroupSockAddr,
    CgroupDevice,
    LircMode2,
    StructOps,
    Extension,
    Syscall,
    Iter,
}

impl ProgramContextFamily {
    pub fn key(self) -> &'static str {
        match self {
            Self::Probe => "probe",
            Self::PerfEvent => "perf-event",
            Self::Xdp => "xdp",
            Self::SkBuffPacket => "skbuff-packet",
            Self::SkLookup => "sk-lookup",
            Self::FlowDissector => "flow-dissector",
            Self::Netfilter => "netfilter",
            Self::SkReuseport => "sk-reuseport",
            Self::SkMsg => "sk-msg",
            Self::SockOps => "sock-ops",
            Self::CgroupSock => "cgroup-sock",
            Self::CgroupSysctl => "cgroup-sysctl",
            Self::CgroupSockopt => "cgroup-sockopt",
            Self::CgroupSockAddr => "cgroup-sock-addr",
            Self::CgroupDevice => "cgroup-device",
            Self::LircMode2 => "lirc-mode2",
            Self::StructOps => "struct-ops",
            Self::Extension => "extension",
            Self::Syscall => "syscall",
            Self::Iter => "iter",
        }
    }

    pub fn is_perf_event(self) -> bool {
        matches!(self, Self::PerfEvent)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgramTypeInfo {
    pub program_type: EbpfProgramType,
    pub kernel_prog_type: &'static str,
    pub canonical_prefix: &'static str,
    pub spec_aliases: &'static [&'static str],
    pub section_prefix: &'static str,
    pub section_uses_target: bool,
    pub context_family: ProgramContextFamily,
    pub attach_kind: ProgramAttachKind,
    pub target_kind: ProgramTargetKind,
    pub kernel_target_validation: Option<KernelTargetValidationKind>,
    pub supported_capabilities: &'static [ProgramCapability],
    pub arg_access: ProgramValueAccess,
    pub retval_access: ProgramValueAccess,
}

#[derive(Debug, Clone, Copy)]
struct ProgramBtfCallableSurfaceSpec {
    program_types: &'static [EbpfProgramType],
    surface: ProgramBtfCallableSurface,
}

#[derive(Debug, Clone, Copy)]
struct ProgramCompatibilityRequirementSurface {
    program_types: &'static [EbpfProgramType],
    requirements: &'static [ProgramCompatibilityRequirement],
}

const FUNCTION_TRAMPOLINE_BTF_CALLABLE_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::Fentry,
    EbpfProgramType::Fexit,
    EbpfProgramType::FmodRet,
];

const TP_BTF_CALLABLE_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::TpBtf];

const LSM_BTF_CALLABLE_PROGRAMS: &[EbpfProgramType] =
    &[EbpfProgramType::Lsm, EbpfProgramType::LsmCgroup];

const STRUCT_OPS_BTF_CALLABLE_PROGRAMS: &[EbpfProgramType] = &[EbpfProgramType::StructOps];

const NO_COMPATIBILITY_REQUIREMENTS: &[ProgramCompatibilityRequirement] = &[];

const BTF_TRAMPOLINE_COMPATIBILITY_REQUIREMENTS: &[ProgramCompatibilityRequirement] = &[
    ProgramCompatibilityRequirement::KernelBtf,
    ProgramCompatibilityRequirement::BpfTrampoline,
];
const TP_BTF_COMPATIBILITY_REQUIREMENTS: &[ProgramCompatibilityRequirement] =
    &[ProgramCompatibilityRequirement::KernelBtf];
const LSM_COMPATIBILITY_REQUIREMENTS: &[ProgramCompatibilityRequirement] = &[
    ProgramCompatibilityRequirement::KernelBtf,
    ProgramCompatibilityRequirement::BpfTrampoline,
];
const STRUCT_OPS_COMPATIBILITY_REQUIREMENTS: &[ProgramCompatibilityRequirement] = &[
    ProgramCompatibilityRequirement::KernelBtf,
    ProgramCompatibilityRequirement::BpfTrampoline,
    ProgramCompatibilityRequirement::StructOps,
];
const KPROBE_MULTI_COMPATIBILITY_REQUIREMENTS: &[ProgramCompatibilityRequirement] =
    &[ProgramCompatibilityRequirement::KprobeMulti];
const UPROBE_MULTI_COMPATIBILITY_REQUIREMENTS: &[ProgramCompatibilityRequirement] =
    &[ProgramCompatibilityRequirement::UprobeMulti];
const RAW_TRACEPOINT_WRITABLE_COMPATIBILITY_REQUIREMENTS: &[ProgramCompatibilityRequirement] =
    &[ProgramCompatibilityRequirement::RawTracepointWritable];
const LSM_CGROUP_COMPATIBILITY_REQUIREMENTS: &[ProgramCompatibilityRequirement] = &[
    ProgramCompatibilityRequirement::KernelBtf,
    ProgramCompatibilityRequirement::BpfTrampoline,
    ProgramCompatibilityRequirement::CgroupLsm,
];
const EXTENSION_COMPATIBILITY_REQUIREMENTS: &[ProgramCompatibilityRequirement] =
    &[ProgramCompatibilityRequirement::ExtensionProgram];
const SYSCALL_COMPATIBILITY_REQUIREMENTS: &[ProgramCompatibilityRequirement] =
    &[ProgramCompatibilityRequirement::SyscallProgram];
const ITER_COMPATIBILITY_REQUIREMENTS: &[ProgramCompatibilityRequirement] =
    &[ProgramCompatibilityRequirement::BpfIterator];
const FLOW_DISSECTOR_COMPATIBILITY_REQUIREMENTS: &[ProgramCompatibilityRequirement] =
    &[ProgramCompatibilityRequirement::FlowDissector];
const TCX_COMPATIBILITY_REQUIREMENTS: &[ProgramCompatibilityRequirement] =
    &[ProgramCompatibilityRequirement::Tcx];
const NETKIT_COMPATIBILITY_REQUIREMENTS: &[ProgramCompatibilityRequirement] =
    &[ProgramCompatibilityRequirement::Netkit];
const NETFILTER_COMPATIBILITY_REQUIREMENTS: &[ProgramCompatibilityRequirement] =
    &[ProgramCompatibilityRequirement::NetfilterLink];
const LWT_COMPATIBILITY_REQUIREMENTS: &[ProgramCompatibilityRequirement] =
    &[ProgramCompatibilityRequirement::RouteLwt];
const SOCKMAP_COMPATIBILITY_REQUIREMENTS: &[ProgramCompatibilityRequirement] =
    &[ProgramCompatibilityRequirement::SockMapAttach];
const SK_REUSEPORT_COMPATIBILITY_REQUIREMENTS: &[ProgramCompatibilityRequirement] =
    &[ProgramCompatibilityRequirement::SkReuseportAttach];
const TC_ACTION_COMPATIBILITY_REQUIREMENTS: &[ProgramCompatibilityRequirement] =
    &[ProgramCompatibilityRequirement::TcActionProgram];
const CGROUP_COMPATIBILITY_REQUIREMENTS: &[ProgramCompatibilityRequirement] =
    &[ProgramCompatibilityRequirement::CgroupV2];
const LIRC_MODE2_COMPATIBILITY_REQUIREMENTS: &[ProgramCompatibilityRequirement] =
    &[ProgramCompatibilityRequirement::LircMode2];

const BTF_CALLABLE_SURFACES: &[ProgramBtfCallableSurfaceSpec] = &[
    ProgramBtfCallableSurfaceSpec {
        program_types: FUNCTION_TRAMPOLINE_BTF_CALLABLE_PROGRAMS,
        surface: ProgramBtfCallableSurface::FunctionTrampoline,
    },
    ProgramBtfCallableSurfaceSpec {
        program_types: TP_BTF_CALLABLE_PROGRAMS,
        surface: ProgramBtfCallableSurface::TpBtf,
    },
    ProgramBtfCallableSurfaceSpec {
        program_types: LSM_BTF_CALLABLE_PROGRAMS,
        surface: ProgramBtfCallableSurface::LsmHook,
    },
    ProgramBtfCallableSurfaceSpec {
        program_types: STRUCT_OPS_BTF_CALLABLE_PROGRAMS,
        surface: ProgramBtfCallableSurface::StructOpsCallback,
    },
];

const COMPATIBILITY_REQUIREMENT_SURFACES: &[ProgramCompatibilityRequirementSurface] = &[
    ProgramCompatibilityRequirementSurface {
        program_types: FUNCTION_TRAMPOLINE_BTF_CALLABLE_PROGRAMS,
        requirements: BTF_TRAMPOLINE_COMPATIBILITY_REQUIREMENTS,
    },
    ProgramCompatibilityRequirementSurface {
        program_types: TP_BTF_CALLABLE_PROGRAMS,
        requirements: TP_BTF_COMPATIBILITY_REQUIREMENTS,
    },
    ProgramCompatibilityRequirementSurface {
        program_types: &[EbpfProgramType::Lsm],
        requirements: LSM_COMPATIBILITY_REQUIREMENTS,
    },
    ProgramCompatibilityRequirementSurface {
        program_types: &[EbpfProgramType::LsmCgroup],
        requirements: LSM_CGROUP_COMPATIBILITY_REQUIREMENTS,
    },
    ProgramCompatibilityRequirementSurface {
        program_types: STRUCT_OPS_BTF_CALLABLE_PROGRAMS,
        requirements: STRUCT_OPS_COMPATIBILITY_REQUIREMENTS,
    },
    ProgramCompatibilityRequirementSurface {
        program_types: &[
            EbpfProgramType::KprobeMulti,
            EbpfProgramType::KretprobeMulti,
        ],
        requirements: KPROBE_MULTI_COMPATIBILITY_REQUIREMENTS,
    },
    ProgramCompatibilityRequirementSurface {
        program_types: &[
            EbpfProgramType::UprobeMulti,
            EbpfProgramType::UretprobeMulti,
        ],
        requirements: UPROBE_MULTI_COMPATIBILITY_REQUIREMENTS,
    },
    ProgramCompatibilityRequirementSurface {
        program_types: &[EbpfProgramType::RawTracepointWritable],
        requirements: RAW_TRACEPOINT_WRITABLE_COMPATIBILITY_REQUIREMENTS,
    },
    ProgramCompatibilityRequirementSurface {
        program_types: &[EbpfProgramType::Extension],
        requirements: EXTENSION_COMPATIBILITY_REQUIREMENTS,
    },
    ProgramCompatibilityRequirementSurface {
        program_types: &[EbpfProgramType::Syscall],
        requirements: SYSCALL_COMPATIBILITY_REQUIREMENTS,
    },
    ProgramCompatibilityRequirementSurface {
        program_types: &[EbpfProgramType::Iter],
        requirements: ITER_COMPATIBILITY_REQUIREMENTS,
    },
    ProgramCompatibilityRequirementSurface {
        program_types: &[EbpfProgramType::FlowDissector],
        requirements: FLOW_DISSECTOR_COMPATIBILITY_REQUIREMENTS,
    },
    ProgramCompatibilityRequirementSurface {
        program_types: &[EbpfProgramType::Tcx],
        requirements: TCX_COMPATIBILITY_REQUIREMENTS,
    },
    ProgramCompatibilityRequirementSurface {
        program_types: &[EbpfProgramType::Netkit],
        requirements: NETKIT_COMPATIBILITY_REQUIREMENTS,
    },
    ProgramCompatibilityRequirementSurface {
        program_types: &[EbpfProgramType::Netfilter],
        requirements: NETFILTER_COMPATIBILITY_REQUIREMENTS,
    },
    ProgramCompatibilityRequirementSurface {
        program_types: &[
            EbpfProgramType::LwtIn,
            EbpfProgramType::LwtOut,
            EbpfProgramType::LwtXmit,
            EbpfProgramType::LwtSeg6Local,
        ],
        requirements: LWT_COMPATIBILITY_REQUIREMENTS,
    },
    ProgramCompatibilityRequirementSurface {
        program_types: &[
            EbpfProgramType::SkMsg,
            EbpfProgramType::SkSkb,
            EbpfProgramType::SkSkbParser,
        ],
        requirements: SOCKMAP_COMPATIBILITY_REQUIREMENTS,
    },
    ProgramCompatibilityRequirementSurface {
        program_types: &[EbpfProgramType::SkReuseport],
        requirements: SK_REUSEPORT_COMPATIBILITY_REQUIREMENTS,
    },
    ProgramCompatibilityRequirementSurface {
        program_types: &[EbpfProgramType::TcAction],
        requirements: TC_ACTION_COMPATIBILITY_REQUIREMENTS,
    },
    ProgramCompatibilityRequirementSurface {
        program_types: &[
            EbpfProgramType::CgroupDevice,
            EbpfProgramType::CgroupSkb,
            EbpfProgramType::CgroupSock,
            EbpfProgramType::CgroupSysctl,
            EbpfProgramType::CgroupSockopt,
            EbpfProgramType::CgroupSockAddr,
            EbpfProgramType::SockOps,
        ],
        requirements: CGROUP_COMPATIBILITY_REQUIREMENTS,
    },
    ProgramCompatibilityRequirementSurface {
        program_types: &[EbpfProgramType::LircMode2],
        requirements: LIRC_MODE2_COMPATIBILITY_REQUIREMENTS,
    },
];

pub(super) fn btf_callable_surface_for(
    program_type: EbpfProgramType,
) -> Option<ProgramBtfCallableSurface> {
    BTF_CALLABLE_SURFACES
        .iter()
        .find(|surface| surface.program_types.contains(&program_type))
        .map(|surface| surface.surface)
}

pub(super) fn compatibility_requirements_for(
    program_type: EbpfProgramType,
) -> &'static [ProgramCompatibilityRequirement] {
    COMPATIBILITY_REQUIREMENT_SURFACES
        .iter()
        .find(|surface| surface.program_types.contains(&program_type))
        .map(|surface| surface.requirements)
        .unwrap_or(NO_COMPATIBILITY_REQUIREMENTS)
}

pub(super) const KPROBE_SPEC_ALIASES: &[&str] = &["kprobe"];
pub(super) const KRETPROBE_SPEC_ALIASES: &[&str] = &["kretprobe"];
pub(super) const KPROBE_MULTI_SPEC_ALIASES: &[&str] = &["kprobe.multi"];
pub(super) const KRETPROBE_MULTI_SPEC_ALIASES: &[&str] = &["kretprobe.multi"];
pub(super) const KSYSCALL_SPEC_ALIASES: &[&str] = &["ksyscall"];
pub(super) const KRET_SYSCALL_SPEC_ALIASES: &[&str] = &["kretsyscall"];
pub(super) const FENTRY_SPEC_ALIASES: &[&str] = &["fentry", "fentry.s"];
pub(super) const FEXIT_SPEC_ALIASES: &[&str] = &["fexit", "fexit.s"];
pub(super) const FMOD_RET_SPEC_ALIASES: &[&str] = &["fmod_ret", "fmod_ret.s"];
pub(super) const TP_BTF_SPEC_ALIASES: &[&str] = &["tp_btf"];
pub(super) const TRACEPOINT_SPEC_ALIASES: &[&str] = &["tracepoint"];
pub(super) const RAW_TRACEPOINT_SPEC_ALIASES: &[&str] = &["raw_tracepoint", "raw_tp"];
pub(super) const RAW_TRACEPOINT_WRITABLE_SPEC_ALIASES: &[&str] = &["raw_tracepoint.w", "raw_tp.w"];
pub(super) const UPROBE_SPEC_ALIASES: &[&str] = &["uprobe", "uprobe.s"];
pub(super) const URETPROBE_SPEC_ALIASES: &[&str] = &["uretprobe", "uretprobe.s"];
pub(super) const UPROBE_MULTI_SPEC_ALIASES: &[&str] = &["uprobe.multi", "uprobe.multi.s"];
pub(super) const URETPROBE_MULTI_SPEC_ALIASES: &[&str] = &["uretprobe.multi", "uretprobe.multi.s"];
pub(super) const LSM_SPEC_ALIASES: &[&str] = &["lsm", "lsm.s"];
pub(super) const LSM_CGROUP_SPEC_ALIASES: &[&str] = &["lsm_cgroup"];
pub(super) const EXTENSION_SPEC_ALIASES: &[&str] = &["freplace", "extension", "ext"];
pub(super) const SYSCALL_SPEC_ALIASES: &[&str] = &["syscall"];
pub(super) const ITER_SPEC_ALIASES: &[&str] = &["iter"];
pub(super) const XDP_SPEC_ALIASES: &[&str] = &["xdp"];
pub(super) const PERF_EVENT_SPEC_ALIASES: &[&str] = &["perf_event"];
pub(super) const SOCKET_FILTER_SPEC_ALIASES: &[&str] = &["socket_filter", "sock_filter"];
pub(super) const CGROUP_DEVICE_SPEC_ALIASES: &[&str] = &["cgroup_device"];
pub(super) const SK_LOOKUP_SPEC_ALIASES: &[&str] = &["sk_lookup"];
pub(super) const FLOW_DISSECTOR_SPEC_ALIASES: &[&str] = &["flow_dissector"];
pub(super) const NETFILTER_SPEC_ALIASES: &[&str] = &["netfilter"];
pub(super) const LWT_IN_SPEC_ALIASES: &[&str] = &["lwt_in"];
pub(super) const LWT_OUT_SPEC_ALIASES: &[&str] = &["lwt_out"];
pub(super) const LWT_XMIT_SPEC_ALIASES: &[&str] = &["lwt_xmit"];
pub(super) const LWT_SEG6LOCAL_SPEC_ALIASES: &[&str] = &["lwt_seg6local"];
pub(super) const SK_REUSEPORT_SPEC_ALIASES: &[&str] = &["sk_reuseport"];
pub(super) const SK_MSG_SPEC_ALIASES: &[&str] = &["sk_msg"];
pub(super) const SK_SKB_SPEC_ALIASES: &[&str] = &["sk_skb"];
pub(super) const SK_SKB_PARSER_SPEC_ALIASES: &[&str] = &["sk_skb_parser"];
pub(super) const SOCK_OPS_SPEC_ALIASES: &[&str] = &["sock_ops", "sockops"];
pub(super) const TC_SPEC_ALIASES: &[&str] = &["tc"];
pub(super) const TCX_SPEC_ALIASES: &[&str] = &["tcx"];
pub(super) const NETKIT_SPEC_ALIASES: &[&str] = &["netkit"];
pub(super) const TC_ACTION_SPEC_ALIASES: &[&str] = &["tc_action", "action"];
pub(super) const CGROUP_SKB_SPEC_ALIASES: &[&str] = &["cgroup_skb"];
pub(super) const CGROUP_SOCK_SPEC_ALIASES: &[&str] = &["cgroup_sock"];
pub(super) const CGROUP_SYSCTL_SPEC_ALIASES: &[&str] = &["cgroup_sysctl"];
pub(super) const CGROUP_SOCKOPT_SPEC_ALIASES: &[&str] = &["cgroup_sockopt"];
pub(super) const CGROUP_SOCK_ADDR_SPEC_ALIASES: &[&str] = &["cgroup_sock_addr"];
pub(super) const LIRC_MODE2_SPEC_ALIASES: &[&str] = &["lirc_mode2"];
pub(super) const STRUCT_OPS_SPEC_ALIASES: &[&str] = &["struct_ops"];
pub(super) const DEFAULT_PROBE_CAPABILITIES: &[ProgramCapability] = &[
    ProgramCapability::Emit,
    ProgramCapability::Counters,
    ProgramCapability::Histograms,
    ProgramCapability::Timers,
    ProgramCapability::StackTraces,
    ProgramCapability::ReadUserString,
    ProgramCapability::ReadKernelString,
    ProgramCapability::HelperCalls,
    ProgramCapability::KfuncCalls,
    ProgramCapability::Globals,
    ProgramCapability::GenericMaps,
    ProgramCapability::TailCalls,
];
pub(super) const DEFAULT_XDP_CAPABILITIES: &[ProgramCapability] = &[
    ProgramCapability::Emit,
    ProgramCapability::Counters,
    ProgramCapability::Histograms,
    ProgramCapability::Timers,
    ProgramCapability::HelperCalls,
    ProgramCapability::KfuncCalls,
    ProgramCapability::Globals,
    ProgramCapability::GenericMaps,
    ProgramCapability::TailCalls,
];
pub(super) const CGROUP_SOCK_ADDR_CAPABILITIES: &[ProgramCapability] = &[
    ProgramCapability::Emit,
    ProgramCapability::Counters,
    ProgramCapability::Histograms,
    ProgramCapability::Timers,
    ProgramCapability::HelperCalls,
    ProgramCapability::KfuncCalls,
    ProgramCapability::Globals,
    ProgramCapability::GenericMaps,
    ProgramCapability::TailCalls,
];
pub(super) const SOCK_OPS_CAPABILITIES: &[ProgramCapability] = &[
    ProgramCapability::Emit,
    ProgramCapability::Counters,
    ProgramCapability::Histograms,
    ProgramCapability::Timers,
    ProgramCapability::HelperCalls,
    ProgramCapability::KfuncCalls,
    ProgramCapability::Globals,
    ProgramCapability::GenericMaps,
    ProgramCapability::TailCalls,
];

pub(super) const KPROBE_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::Kprobe,
    kernel_prog_type: "BPF_PROG_TYPE_KPROBE",
    canonical_prefix: "kprobe",
    spec_aliases: KPROBE_SPEC_ALIASES,
    section_prefix: "kprobe",
    section_uses_target: true,
    context_family: ProgramContextFamily::Probe,
    attach_kind: ProgramAttachKind::Kprobe,
    target_kind: ProgramTargetKind::KernelFunction,
    kernel_target_validation: Some(KernelTargetValidationKind::SymbolOnly),
    supported_capabilities: DEFAULT_PROBE_CAPABILITIES,
    arg_access: ProgramValueAccess::PtRegs,
    retval_access: ProgramValueAccess::None,
};

pub(super) const KRETPROBE_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::Kretprobe,
    kernel_prog_type: "BPF_PROG_TYPE_KPROBE",
    canonical_prefix: "kretprobe",
    spec_aliases: KRETPROBE_SPEC_ALIASES,
    section_prefix: "kretprobe",
    section_uses_target: true,
    context_family: ProgramContextFamily::Probe,
    attach_kind: ProgramAttachKind::Kretprobe,
    target_kind: ProgramTargetKind::KernelFunction,
    kernel_target_validation: Some(KernelTargetValidationKind::SymbolOnly),
    supported_capabilities: DEFAULT_PROBE_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::PtRegs,
};

pub(super) const KPROBE_MULTI_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::KprobeMulti,
    kernel_prog_type: "BPF_PROG_TYPE_KPROBE",
    canonical_prefix: "kprobe.multi",
    spec_aliases: KPROBE_MULTI_SPEC_ALIASES,
    section_prefix: "kprobe.multi",
    section_uses_target: true,
    context_family: ProgramContextFamily::Probe,
    attach_kind: ProgramAttachKind::KprobeMulti,
    target_kind: ProgramTargetKind::KernelFunctionPattern,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_PROBE_CAPABILITIES,
    arg_access: ProgramValueAccess::PtRegs,
    retval_access: ProgramValueAccess::None,
};

pub(super) const KRETPROBE_MULTI_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::KretprobeMulti,
    kernel_prog_type: "BPF_PROG_TYPE_KPROBE",
    canonical_prefix: "kretprobe.multi",
    spec_aliases: KRETPROBE_MULTI_SPEC_ALIASES,
    section_prefix: "kretprobe.multi",
    section_uses_target: true,
    context_family: ProgramContextFamily::Probe,
    attach_kind: ProgramAttachKind::KretprobeMulti,
    target_kind: ProgramTargetKind::KernelFunctionPattern,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_PROBE_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::PtRegs,
};

pub(super) const KSYSCALL_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::Ksyscall,
    kernel_prog_type: "BPF_PROG_TYPE_KPROBE",
    canonical_prefix: "ksyscall",
    spec_aliases: KSYSCALL_SPEC_ALIASES,
    section_prefix: "ksyscall",
    section_uses_target: true,
    context_family: ProgramContextFamily::Probe,
    attach_kind: ProgramAttachKind::Ksyscall,
    target_kind: ProgramTargetKind::KernelSyscall,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_PROBE_CAPABILITIES,
    arg_access: ProgramValueAccess::PtRegs,
    retval_access: ProgramValueAccess::None,
};

pub(super) const KRET_SYSCALL_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::KretSyscall,
    kernel_prog_type: "BPF_PROG_TYPE_KPROBE",
    canonical_prefix: "kretsyscall",
    spec_aliases: KRET_SYSCALL_SPEC_ALIASES,
    section_prefix: "kretsyscall",
    section_uses_target: true,
    context_family: ProgramContextFamily::Probe,
    attach_kind: ProgramAttachKind::KretSyscall,
    target_kind: ProgramTargetKind::KernelSyscall,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_PROBE_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::PtRegs,
};

pub(super) const FENTRY_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::Fentry,
    kernel_prog_type: "BPF_PROG_TYPE_TRACING",
    canonical_prefix: "fentry",
    spec_aliases: FENTRY_SPEC_ALIASES,
    section_prefix: "fentry",
    section_uses_target: true,
    context_family: ProgramContextFamily::Probe,
    attach_kind: ProgramAttachKind::Fentry,
    target_kind: ProgramTargetKind::KernelFunction,
    kernel_target_validation: Some(KernelTargetValidationKind::FentryTrampoline),
    supported_capabilities: DEFAULT_PROBE_CAPABILITIES,
    arg_access: ProgramValueAccess::Trampoline,
    retval_access: ProgramValueAccess::None,
};

pub(super) const FEXIT_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::Fexit,
    kernel_prog_type: "BPF_PROG_TYPE_TRACING",
    canonical_prefix: "fexit",
    spec_aliases: FEXIT_SPEC_ALIASES,
    section_prefix: "fexit",
    section_uses_target: true,
    context_family: ProgramContextFamily::Probe,
    attach_kind: ProgramAttachKind::Fexit,
    target_kind: ProgramTargetKind::KernelFunction,
    kernel_target_validation: Some(KernelTargetValidationKind::FexitTrampoline),
    supported_capabilities: DEFAULT_PROBE_CAPABILITIES,
    arg_access: ProgramValueAccess::Trampoline,
    retval_access: ProgramValueAccess::Trampoline,
};

pub(super) const FMOD_RET_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::FmodRet,
    kernel_prog_type: "BPF_PROG_TYPE_TRACING",
    canonical_prefix: "fmod_ret",
    spec_aliases: FMOD_RET_SPEC_ALIASES,
    section_prefix: "fmod_ret",
    section_uses_target: true,
    context_family: ProgramContextFamily::Probe,
    attach_kind: ProgramAttachKind::FmodRet,
    target_kind: ProgramTargetKind::KernelFunction,
    kernel_target_validation: Some(KernelTargetValidationKind::FmodRetTrampoline),
    supported_capabilities: DEFAULT_PROBE_CAPABILITIES,
    arg_access: ProgramValueAccess::Trampoline,
    retval_access: ProgramValueAccess::Trampoline,
};

pub(super) const TP_BTF_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::TpBtf,
    kernel_prog_type: "BPF_PROG_TYPE_TRACING",
    canonical_prefix: "tp_btf",
    spec_aliases: TP_BTF_SPEC_ALIASES,
    section_prefix: "tp_btf",
    section_uses_target: true,
    context_family: ProgramContextFamily::Probe,
    attach_kind: ProgramAttachKind::TpBtf,
    target_kind: ProgramTargetKind::BtfTracepoint,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_PROBE_CAPABILITIES,
    arg_access: ProgramValueAccess::Trampoline,
    retval_access: ProgramValueAccess::None,
};

pub(super) const TRACEPOINT_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::Tracepoint,
    kernel_prog_type: "BPF_PROG_TYPE_TRACEPOINT",
    canonical_prefix: "tracepoint",
    spec_aliases: TRACEPOINT_SPEC_ALIASES,
    section_prefix: "tracepoint",
    section_uses_target: true,
    context_family: ProgramContextFamily::Probe,
    attach_kind: ProgramAttachKind::Tracepoint,
    target_kind: ProgramTargetKind::Tracepoint,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_PROBE_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
};

pub(super) const RAW_TRACEPOINT_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::RawTracepoint,
    kernel_prog_type: "BPF_PROG_TYPE_RAW_TRACEPOINT",
    canonical_prefix: "raw_tracepoint",
    spec_aliases: RAW_TRACEPOINT_SPEC_ALIASES,
    section_prefix: "raw_tracepoint",
    section_uses_target: true,
    context_family: ProgramContextFamily::Probe,
    attach_kind: ProgramAttachKind::RawTracepoint,
    target_kind: ProgramTargetKind::RawTracepoint,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_PROBE_CAPABILITIES,
    arg_access: ProgramValueAccess::RawTracepoint,
    retval_access: ProgramValueAccess::None,
};

pub(super) const RAW_TRACEPOINT_WRITABLE_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::RawTracepointWritable,
    kernel_prog_type: "BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE",
    canonical_prefix: "raw_tracepoint.w",
    spec_aliases: RAW_TRACEPOINT_WRITABLE_SPEC_ALIASES,
    section_prefix: "raw_tracepoint.w",
    section_uses_target: true,
    context_family: ProgramContextFamily::Probe,
    attach_kind: ProgramAttachKind::RawTracepointWritable,
    target_kind: ProgramTargetKind::RawTracepoint,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_PROBE_CAPABILITIES,
    arg_access: ProgramValueAccess::RawTracepoint,
    retval_access: ProgramValueAccess::None,
};

pub(super) const UPROBE_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::Uprobe,
    kernel_prog_type: "BPF_PROG_TYPE_KPROBE",
    canonical_prefix: "uprobe",
    spec_aliases: UPROBE_SPEC_ALIASES,
    section_prefix: "uprobe",
    section_uses_target: true,
    context_family: ProgramContextFamily::Probe,
    attach_kind: ProgramAttachKind::Uprobe,
    target_kind: ProgramTargetKind::UserFunction,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_PROBE_CAPABILITIES,
    arg_access: ProgramValueAccess::PtRegs,
    retval_access: ProgramValueAccess::None,
};

pub(super) const URETPROBE_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::Uretprobe,
    kernel_prog_type: "BPF_PROG_TYPE_KPROBE",
    canonical_prefix: "uretprobe",
    spec_aliases: URETPROBE_SPEC_ALIASES,
    section_prefix: "uretprobe",
    section_uses_target: true,
    context_family: ProgramContextFamily::Probe,
    attach_kind: ProgramAttachKind::Uretprobe,
    target_kind: ProgramTargetKind::UserFunction,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_PROBE_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::PtRegs,
};

pub(super) const UPROBE_MULTI_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::UprobeMulti,
    kernel_prog_type: "BPF_PROG_TYPE_KPROBE",
    canonical_prefix: "uprobe.multi",
    spec_aliases: UPROBE_MULTI_SPEC_ALIASES,
    section_prefix: "uprobe.multi",
    section_uses_target: true,
    context_family: ProgramContextFamily::Probe,
    attach_kind: ProgramAttachKind::UprobeMulti,
    target_kind: ProgramTargetKind::UserFunctionPattern,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_PROBE_CAPABILITIES,
    arg_access: ProgramValueAccess::PtRegs,
    retval_access: ProgramValueAccess::None,
};

pub(super) const URETPROBE_MULTI_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::UretprobeMulti,
    kernel_prog_type: "BPF_PROG_TYPE_KPROBE",
    canonical_prefix: "uretprobe.multi",
    spec_aliases: URETPROBE_MULTI_SPEC_ALIASES,
    section_prefix: "uretprobe.multi",
    section_uses_target: true,
    context_family: ProgramContextFamily::Probe,
    attach_kind: ProgramAttachKind::UretprobeMulti,
    target_kind: ProgramTargetKind::UserFunctionPattern,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_PROBE_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::PtRegs,
};

pub(super) const LSM_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::Lsm,
    kernel_prog_type: "BPF_PROG_TYPE_LSM",
    canonical_prefix: "lsm",
    spec_aliases: LSM_SPEC_ALIASES,
    section_prefix: "lsm",
    section_uses_target: true,
    context_family: ProgramContextFamily::Probe,
    attach_kind: ProgramAttachKind::Lsm,
    target_kind: ProgramTargetKind::LsmHook,
    kernel_target_validation: Some(KernelTargetValidationKind::LsmHook),
    supported_capabilities: DEFAULT_PROBE_CAPABILITIES,
    arg_access: ProgramValueAccess::Trampoline,
    retval_access: ProgramValueAccess::None,
};

pub(super) const LSM_CGROUP_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::LsmCgroup,
    kernel_prog_type: "BPF_PROG_TYPE_LSM",
    canonical_prefix: "lsm_cgroup",
    spec_aliases: LSM_CGROUP_SPEC_ALIASES,
    section_prefix: "lsm_cgroup",
    section_uses_target: true,
    context_family: ProgramContextFamily::Probe,
    attach_kind: ProgramAttachKind::LsmCgroup,
    target_kind: ProgramTargetKind::LsmHook,
    kernel_target_validation: Some(KernelTargetValidationKind::LsmHook),
    supported_capabilities: DEFAULT_PROBE_CAPABILITIES,
    arg_access: ProgramValueAccess::Trampoline,
    retval_access: ProgramValueAccess::None,
};

pub(super) const EXTENSION_CAPABILITIES: &[ProgramCapability] = &[];

pub(super) const EXTENSION_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::Extension,
    kernel_prog_type: "BPF_PROG_TYPE_EXT",
    canonical_prefix: "freplace",
    spec_aliases: EXTENSION_SPEC_ALIASES,
    section_prefix: "freplace",
    section_uses_target: true,
    context_family: ProgramContextFamily::Extension,
    attach_kind: ProgramAttachKind::Extension,
    target_kind: ProgramTargetKind::ExtensionFunction,
    kernel_target_validation: None,
    supported_capabilities: EXTENSION_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
};

pub(super) const SYSCALL_CAPABILITIES: &[ProgramCapability] = &[ProgramCapability::HelperCalls];

pub(super) const SYSCALL_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::Syscall,
    kernel_prog_type: "BPF_PROG_TYPE_SYSCALL",
    canonical_prefix: "syscall",
    spec_aliases: SYSCALL_SPEC_ALIASES,
    section_prefix: "syscall",
    section_uses_target: false,
    context_family: ProgramContextFamily::Syscall,
    attach_kind: ProgramAttachKind::Syscall,
    target_kind: ProgramTargetKind::SyscallProgram,
    kernel_target_validation: None,
    supported_capabilities: SYSCALL_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
};

pub(super) const ITER_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::Iter,
    kernel_prog_type: "BPF_PROG_TYPE_TRACING",
    canonical_prefix: "iter",
    spec_aliases: ITER_SPEC_ALIASES,
    section_prefix: "iter",
    section_uses_target: true,
    context_family: ProgramContextFamily::Iter,
    attach_kind: ProgramAttachKind::Iter,
    target_kind: ProgramTargetKind::BpfIteratorTarget,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
};

pub(super) const XDP_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::Xdp,
    kernel_prog_type: "BPF_PROG_TYPE_XDP",
    canonical_prefix: "xdp",
    spec_aliases: XDP_SPEC_ALIASES,
    section_prefix: "xdp",
    section_uses_target: false,
    context_family: ProgramContextFamily::Xdp,
    attach_kind: ProgramAttachKind::Xdp,
    target_kind: ProgramTargetKind::NetworkInterface,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
};

pub(super) const PERF_EVENT_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::PerfEvent,
    kernel_prog_type: "BPF_PROG_TYPE_PERF_EVENT",
    canonical_prefix: "perf_event",
    spec_aliases: PERF_EVENT_SPEC_ALIASES,
    section_prefix: "perf_event",
    section_uses_target: false,
    context_family: ProgramContextFamily::PerfEvent,
    attach_kind: ProgramAttachKind::PerfEvent,
    target_kind: ProgramTargetKind::PerfEventTarget,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_PROBE_CAPABILITIES,
    arg_access: ProgramValueAccess::PtRegs,
    retval_access: ProgramValueAccess::None,
};

pub(super) const SOCKET_FILTER_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::SocketFilter,
    kernel_prog_type: "BPF_PROG_TYPE_SOCKET_FILTER",
    canonical_prefix: "socket_filter",
    spec_aliases: SOCKET_FILTER_SPEC_ALIASES,
    section_prefix: "socket",
    section_uses_target: false,
    context_family: ProgramContextFamily::SkBuffPacket,
    attach_kind: ProgramAttachKind::SocketFilter,
    target_kind: ProgramTargetKind::SocketFilterTarget,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
};

pub(super) const CGROUP_DEVICE_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::CgroupDevice,
    kernel_prog_type: "BPF_PROG_TYPE_CGROUP_DEVICE",
    canonical_prefix: "cgroup_device",
    spec_aliases: CGROUP_DEVICE_SPEC_ALIASES,
    section_prefix: "cgroup",
    section_uses_target: false,
    context_family: ProgramContextFamily::CgroupDevice,
    attach_kind: ProgramAttachKind::CgroupDevice,
    target_kind: ProgramTargetKind::CgroupPath,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
};

pub(super) const SK_LOOKUP_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::SkLookup,
    kernel_prog_type: "BPF_PROG_TYPE_SK_LOOKUP",
    canonical_prefix: "sk_lookup",
    spec_aliases: SK_LOOKUP_SPEC_ALIASES,
    section_prefix: "sk_lookup",
    section_uses_target: false,
    context_family: ProgramContextFamily::SkLookup,
    attach_kind: ProgramAttachKind::SkLookup,
    target_kind: ProgramTargetKind::NetworkNamespacePath,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
};

pub(super) const FLOW_DISSECTOR_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::FlowDissector,
    kernel_prog_type: "BPF_PROG_TYPE_FLOW_DISSECTOR",
    canonical_prefix: "flow_dissector",
    spec_aliases: FLOW_DISSECTOR_SPEC_ALIASES,
    section_prefix: "flow_dissector",
    section_uses_target: false,
    context_family: ProgramContextFamily::FlowDissector,
    attach_kind: ProgramAttachKind::FlowDissector,
    target_kind: ProgramTargetKind::NetworkNamespacePath,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
};

pub(super) const NETFILTER_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::Netfilter,
    kernel_prog_type: "BPF_PROG_TYPE_NETFILTER",
    canonical_prefix: "netfilter",
    spec_aliases: NETFILTER_SPEC_ALIASES,
    section_prefix: "netfilter",
    section_uses_target: false,
    context_family: ProgramContextFamily::Netfilter,
    attach_kind: ProgramAttachKind::Netfilter,
    target_kind: ProgramTargetKind::NetfilterHook,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
};

pub(super) const LWT_IN_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::LwtIn,
    kernel_prog_type: "BPF_PROG_TYPE_LWT_IN",
    canonical_prefix: "lwt_in",
    spec_aliases: LWT_IN_SPEC_ALIASES,
    section_prefix: "lwt_in",
    section_uses_target: false,
    context_family: ProgramContextFamily::SkBuffPacket,
    attach_kind: ProgramAttachKind::Lwt,
    target_kind: ProgramTargetKind::LightweightTunnelRoute,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
};

pub(super) const LWT_OUT_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::LwtOut,
    kernel_prog_type: "BPF_PROG_TYPE_LWT_OUT",
    canonical_prefix: "lwt_out",
    spec_aliases: LWT_OUT_SPEC_ALIASES,
    section_prefix: "lwt_out",
    section_uses_target: false,
    context_family: ProgramContextFamily::SkBuffPacket,
    attach_kind: ProgramAttachKind::Lwt,
    target_kind: ProgramTargetKind::LightweightTunnelRoute,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
};

pub(super) const LWT_XMIT_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::LwtXmit,
    kernel_prog_type: "BPF_PROG_TYPE_LWT_XMIT",
    canonical_prefix: "lwt_xmit",
    spec_aliases: LWT_XMIT_SPEC_ALIASES,
    section_prefix: "lwt_xmit",
    section_uses_target: false,
    context_family: ProgramContextFamily::SkBuffPacket,
    attach_kind: ProgramAttachKind::Lwt,
    target_kind: ProgramTargetKind::LightweightTunnelRoute,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
};

pub(super) const LWT_SEG6LOCAL_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::LwtSeg6Local,
    kernel_prog_type: "BPF_PROG_TYPE_LWT_SEG6LOCAL",
    canonical_prefix: "lwt_seg6local",
    spec_aliases: LWT_SEG6LOCAL_SPEC_ALIASES,
    section_prefix: "lwt_seg6local",
    section_uses_target: false,
    context_family: ProgramContextFamily::SkBuffPacket,
    attach_kind: ProgramAttachKind::Lwt,
    target_kind: ProgramTargetKind::LightweightTunnelRoute,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
};

pub(super) const SK_REUSEPORT_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::SkReuseport,
    kernel_prog_type: "BPF_PROG_TYPE_SK_REUSEPORT",
    canonical_prefix: "sk_reuseport",
    spec_aliases: SK_REUSEPORT_SPEC_ALIASES,
    section_prefix: "sk_reuseport",
    section_uses_target: false,
    context_family: ProgramContextFamily::SkReuseport,
    attach_kind: ProgramAttachKind::SkReuseport,
    target_kind: ProgramTargetKind::SocketReuseportMode,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
};

pub(super) const SK_MSG_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::SkMsg,
    kernel_prog_type: "BPF_PROG_TYPE_SK_MSG",
    canonical_prefix: "sk_msg",
    spec_aliases: SK_MSG_SPEC_ALIASES,
    section_prefix: "sk_msg",
    section_uses_target: false,
    context_family: ProgramContextFamily::SkMsg,
    attach_kind: ProgramAttachKind::SkMsg,
    target_kind: ProgramTargetKind::PinnedSockMapPath,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
};

pub(super) const SK_SKB_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::SkSkb,
    kernel_prog_type: "BPF_PROG_TYPE_SK_SKB",
    canonical_prefix: "sk_skb",
    spec_aliases: SK_SKB_SPEC_ALIASES,
    section_prefix: "sk_skb/stream_verdict",
    section_uses_target: false,
    context_family: ProgramContextFamily::SkBuffPacket,
    attach_kind: ProgramAttachKind::SkSkb,
    target_kind: ProgramTargetKind::PinnedSockMapPath,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
};

pub(super) const SK_SKB_PARSER_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::SkSkbParser,
    kernel_prog_type: "BPF_PROG_TYPE_SK_SKB",
    canonical_prefix: "sk_skb_parser",
    spec_aliases: SK_SKB_PARSER_SPEC_ALIASES,
    section_prefix: "sk_skb/stream_parser",
    section_uses_target: false,
    context_family: ProgramContextFamily::SkBuffPacket,
    attach_kind: ProgramAttachKind::SkSkbParser,
    target_kind: ProgramTargetKind::PinnedSockMapPath,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
};

pub(super) const SOCK_OPS_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::SockOps,
    kernel_prog_type: "BPF_PROG_TYPE_SOCK_OPS",
    canonical_prefix: "sock_ops",
    spec_aliases: SOCK_OPS_SPEC_ALIASES,
    section_prefix: "sockops",
    section_uses_target: false,
    context_family: ProgramContextFamily::SockOps,
    attach_kind: ProgramAttachKind::SockOps,
    target_kind: ProgramTargetKind::CgroupPath,
    kernel_target_validation: None,
    supported_capabilities: SOCK_OPS_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
};

pub(super) const TC_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::Tc,
    kernel_prog_type: "BPF_PROG_TYPE_SCHED_CLS",
    canonical_prefix: "tc",
    spec_aliases: TC_SPEC_ALIASES,
    section_prefix: "classifier",
    section_uses_target: false,
    context_family: ProgramContextFamily::SkBuffPacket,
    attach_kind: ProgramAttachKind::Tc,
    target_kind: ProgramTargetKind::TrafficControlInterface,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
};

pub(super) const TCX_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::Tcx,
    kernel_prog_type: "BPF_PROG_TYPE_SCHED_CLS",
    canonical_prefix: "tcx",
    spec_aliases: TCX_SPEC_ALIASES,
    section_prefix: "tcx",
    section_uses_target: false,
    context_family: ProgramContextFamily::SkBuffPacket,
    attach_kind: ProgramAttachKind::Tcx,
    target_kind: ProgramTargetKind::TrafficControlInterface,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
};

pub(super) const NETKIT_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::Netkit,
    kernel_prog_type: "BPF_PROG_TYPE_SCHED_CLS",
    canonical_prefix: "netkit",
    spec_aliases: NETKIT_SPEC_ALIASES,
    section_prefix: "netkit",
    section_uses_target: false,
    context_family: ProgramContextFamily::SkBuffPacket,
    attach_kind: ProgramAttachKind::Netkit,
    target_kind: ProgramTargetKind::TrafficControlInterface,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
};

pub(super) const TC_ACTION_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::TcAction,
    kernel_prog_type: "BPF_PROG_TYPE_SCHED_ACT",
    canonical_prefix: "tc_action",
    spec_aliases: TC_ACTION_SPEC_ALIASES,
    section_prefix: "action",
    section_uses_target: false,
    context_family: ProgramContextFamily::SkBuffPacket,
    attach_kind: ProgramAttachKind::TcAction,
    target_kind: ProgramTargetKind::TrafficControlAction,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
};

pub(super) const CGROUP_SKB_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::CgroupSkb,
    kernel_prog_type: "BPF_PROG_TYPE_CGROUP_SKB",
    canonical_prefix: "cgroup_skb",
    spec_aliases: CGROUP_SKB_SPEC_ALIASES,
    section_prefix: "cgroup_skb",
    section_uses_target: false,
    context_family: ProgramContextFamily::SkBuffPacket,
    attach_kind: ProgramAttachKind::CgroupSkb,
    target_kind: ProgramTargetKind::CgroupPathAttachType,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
};

pub(super) const CGROUP_SOCK_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::CgroupSock,
    kernel_prog_type: "BPF_PROG_TYPE_CGROUP_SOCK",
    canonical_prefix: "cgroup_sock",
    spec_aliases: CGROUP_SOCK_SPEC_ALIASES,
    section_prefix: "cgroup",
    section_uses_target: false,
    context_family: ProgramContextFamily::CgroupSock,
    attach_kind: ProgramAttachKind::CgroupSock,
    target_kind: ProgramTargetKind::CgroupPathSockAttachType,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
};

pub(super) const CGROUP_SYSCTL_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::CgroupSysctl,
    kernel_prog_type: "BPF_PROG_TYPE_CGROUP_SYSCTL",
    canonical_prefix: "cgroup_sysctl",
    spec_aliases: CGROUP_SYSCTL_SPEC_ALIASES,
    section_prefix: "cgroup",
    section_uses_target: false,
    context_family: ProgramContextFamily::CgroupSysctl,
    attach_kind: ProgramAttachKind::CgroupSysctl,
    target_kind: ProgramTargetKind::CgroupPath,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
};

pub(super) const CGROUP_SOCKOPT_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::CgroupSockopt,
    kernel_prog_type: "BPF_PROG_TYPE_CGROUP_SOCKOPT",
    canonical_prefix: "cgroup_sockopt",
    spec_aliases: CGROUP_SOCKOPT_SPEC_ALIASES,
    section_prefix: "cgroup",
    section_uses_target: false,
    context_family: ProgramContextFamily::CgroupSockopt,
    attach_kind: ProgramAttachKind::CgroupSockopt,
    target_kind: ProgramTargetKind::CgroupPathSockoptAttachType,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
};

pub(super) const CGROUP_SOCK_ADDR_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::CgroupSockAddr,
    kernel_prog_type: "BPF_PROG_TYPE_CGROUP_SOCK_ADDR",
    canonical_prefix: "cgroup_sock_addr",
    spec_aliases: CGROUP_SOCK_ADDR_SPEC_ALIASES,
    section_prefix: "cgroup",
    section_uses_target: false,
    context_family: ProgramContextFamily::CgroupSockAddr,
    attach_kind: ProgramAttachKind::CgroupSockAddr,
    target_kind: ProgramTargetKind::CgroupPathSockAddrAttachType,
    kernel_target_validation: None,
    supported_capabilities: CGROUP_SOCK_ADDR_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
};

pub(super) const LIRC_MODE2_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::LircMode2,
    kernel_prog_type: "BPF_PROG_TYPE_LIRC_MODE2",
    canonical_prefix: "lirc_mode2",
    spec_aliases: LIRC_MODE2_SPEC_ALIASES,
    section_prefix: "lirc_mode2",
    section_uses_target: false,
    context_family: ProgramContextFamily::LircMode2,
    attach_kind: ProgramAttachKind::LircMode2,
    target_kind: ProgramTargetKind::LircDevicePath,
    kernel_target_validation: None,
    supported_capabilities: DEFAULT_XDP_CAPABILITIES,
    arg_access: ProgramValueAccess::None,
    retval_access: ProgramValueAccess::None,
};

pub(super) const STRUCT_OPS_CAPABILITIES: &[ProgramCapability] = &[
    ProgramCapability::Globals,
    ProgramCapability::GenericMaps,
    ProgramCapability::HelperCalls,
    ProgramCapability::KfuncCalls,
    ProgramCapability::TailCalls,
];

pub(super) const STRUCT_OPS_INFO: ProgramTypeInfo = ProgramTypeInfo {
    program_type: EbpfProgramType::StructOps,
    kernel_prog_type: "BPF_PROG_TYPE_STRUCT_OPS",
    canonical_prefix: "struct_ops",
    spec_aliases: STRUCT_OPS_SPEC_ALIASES,
    section_prefix: "struct_ops",
    section_uses_target: true,
    context_family: ProgramContextFamily::StructOps,
    attach_kind: ProgramAttachKind::StructOps,
    target_kind: ProgramTargetKind::StructOpsCallback,
    kernel_target_validation: None,
    supported_capabilities: STRUCT_OPS_CAPABILITIES,
    arg_access: ProgramValueAccess::Trampoline,
    retval_access: ProgramValueAccess::None,
};

pub(super) const ALL_PROGRAM_TYPES: &[EbpfProgramType] = &[
    EbpfProgramType::Kprobe,
    EbpfProgramType::Kretprobe,
    EbpfProgramType::KprobeMulti,
    EbpfProgramType::KretprobeMulti,
    EbpfProgramType::Ksyscall,
    EbpfProgramType::KretSyscall,
    EbpfProgramType::Fentry,
    EbpfProgramType::Fexit,
    EbpfProgramType::FmodRet,
    EbpfProgramType::TpBtf,
    EbpfProgramType::Tracepoint,
    EbpfProgramType::RawTracepoint,
    EbpfProgramType::RawTracepointWritable,
    EbpfProgramType::Uprobe,
    EbpfProgramType::Uretprobe,
    EbpfProgramType::UprobeMulti,
    EbpfProgramType::UretprobeMulti,
    EbpfProgramType::Lsm,
    EbpfProgramType::LsmCgroup,
    EbpfProgramType::Extension,
    EbpfProgramType::Syscall,
    EbpfProgramType::Iter,
    EbpfProgramType::Xdp,
    EbpfProgramType::PerfEvent,
    EbpfProgramType::SocketFilter,
    EbpfProgramType::CgroupDevice,
    EbpfProgramType::SkLookup,
    EbpfProgramType::FlowDissector,
    EbpfProgramType::Netfilter,
    EbpfProgramType::LwtIn,
    EbpfProgramType::LwtOut,
    EbpfProgramType::LwtXmit,
    EbpfProgramType::LwtSeg6Local,
    EbpfProgramType::SkReuseport,
    EbpfProgramType::SkMsg,
    EbpfProgramType::SkSkb,
    EbpfProgramType::SkSkbParser,
    EbpfProgramType::SockOps,
    EbpfProgramType::Tc,
    EbpfProgramType::Tcx,
    EbpfProgramType::Netkit,
    EbpfProgramType::TcAction,
    EbpfProgramType::CgroupSkb,
    EbpfProgramType::CgroupSock,
    EbpfProgramType::CgroupSysctl,
    EbpfProgramType::CgroupSockopt,
    EbpfProgramType::CgroupSockAddr,
    EbpfProgramType::LircMode2,
    EbpfProgramType::StructOps,
];

pub(super) const PROGRAM_SPEC_PREFIXES: &[&str] = &[
    "kprobe",
    "kretprobe",
    "kprobe.multi",
    "kretprobe.multi",
    "ksyscall",
    "kretsyscall",
    "fentry",
    "fentry.s",
    "fexit",
    "fexit.s",
    "fmod_ret",
    "fmod_ret.s",
    "tp_btf",
    "lsm",
    "lsm.s",
    "lsm_cgroup",
    "freplace",
    "extension",
    "ext",
    "syscall",
    "iter",
    "tracepoint",
    "raw_tracepoint",
    "raw_tp",
    "raw_tracepoint.w",
    "raw_tp.w",
    "uprobe",
    "uprobe.s",
    "uretprobe",
    "uretprobe.s",
    "uprobe.multi",
    "uprobe.multi.s",
    "uretprobe.multi",
    "uretprobe.multi.s",
    "perf_event",
    "xdp",
    "socket_filter",
    "sock_filter",
    "cgroup_device",
    "sk_lookup",
    "flow_dissector",
    "netfilter",
    "lwt_in",
    "lwt_out",
    "lwt_xmit",
    "lwt_seg6local",
    "sk_reuseport",
    "sk_msg",
    "sk_skb",
    "sk_skb_parser",
    "sock_ops",
    "sockops",
    "tc",
    "tcx",
    "netkit",
    "tc_action",
    "action",
    "cgroup_skb",
    "cgroup_sock",
    "cgroup_sysctl",
    "cgroup_sockopt",
    "cgroup_sock_addr",
    "lirc_mode2",
    "struct_ops",
];

pub(super) const PROGRAM_INTRINSICS: &[ProgramIntrinsic] = &[
    ProgramIntrinsic::Emit,
    ProgramIntrinsic::Count,
    ProgramIntrinsic::Histogram,
    ProgramIntrinsic::StartTimer,
    ProgramIntrinsic::StopTimer,
    ProgramIntrinsic::ReadStr,
    ProgramIntrinsic::ReadKernelStr,
    ProgramIntrinsic::AdjustPacket,
    ProgramIntrinsic::AdjustMessage,
    ProgramIntrinsic::Redirect,
    ProgramIntrinsic::RedirectMap,
    ProgramIntrinsic::RedirectSocket,
    ProgramIntrinsic::AssignSocket,
    ProgramIntrinsic::HelperCall,
    ProgramIntrinsic::KfuncCall,
    ProgramIntrinsic::TailCall,
    ProgramIntrinsic::GlobalDefine,
    ProgramIntrinsic::GlobalGet,
    ProgramIntrinsic::GlobalSet,
    ProgramIntrinsic::MapDefine,
    ProgramIntrinsic::MapGet,
    ProgramIntrinsic::MapPut,
    ProgramIntrinsic::MapDelete,
    ProgramIntrinsic::MapContains,
    ProgramIntrinsic::MapPush,
    ProgramIntrinsic::MapPeek,
    ProgramIntrinsic::MapPop,
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_compatibility_requirement_surfaces_are_disjoint() {
        let mut program_types = HashSet::new();

        for (index, surface) in COMPATIBILITY_REQUIREMENT_SURFACES.iter().enumerate() {
            let mut requirements = HashSet::new();
            for requirement in surface.requirements {
                assert!(
                    requirements.insert(*requirement),
                    "duplicate compatibility requirement {requirement:?} in surface #{index}"
                );
            }

            for program_type in surface.program_types {
                assert!(
                    ALL_PROGRAM_TYPES.contains(program_type),
                    "{program_type:?} in compatibility surface #{index} must be supported"
                );
                assert!(
                    program_types.insert(*program_type),
                    "{program_type:?} appears in multiple compatibility surfaces"
                );
            }
        }
    }

    #[test]
    fn test_program_type_registry_prefixes_are_unique_and_complete() {
        let mut program_types = HashSet::new();
        let mut listed_prefixes = HashSet::new();
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
            assert!(
                !family.key().is_empty(),
                "{family:?} should have a machine-readable key"
            );
        }

        for prefix in PROGRAM_SPEC_PREFIXES {
            assert!(
                listed_prefixes.insert(*prefix),
                "duplicate supported program spec prefix '{prefix}'"
            );
        }

        let mut alias_prefixes = HashSet::new();
        for program_type in ALL_PROGRAM_TYPES {
            assert!(
                program_types.insert(*program_type),
                "duplicate program type {program_type:?} in ALL_PROGRAM_TYPES"
            );

            let info = program_type.info();
            assert_eq!(
                info.program_type, *program_type,
                "program info for {program_type:?} reports a different program type"
            );
            assert!(
                !info.kernel_prog_type.is_empty(),
                "{program_type:?} must have a kernel program type label"
            );
            assert!(
                !info.section_prefix.is_empty(),
                "{program_type:?} must have an ELF section prefix"
            );
            assert!(
                info.spec_aliases.contains(&info.canonical_prefix),
                "{program_type:?} canonical prefix '{}' must be one of its aliases",
                info.canonical_prefix
            );

            for alias in info.spec_aliases {
                assert!(
                    listed_prefixes.contains(alias),
                    "{program_type:?} alias '{alias}' is missing from PROGRAM_SPEC_PREFIXES"
                );
                assert!(
                    alias_prefixes.insert(*alias),
                    "program spec alias '{alias}' appears on multiple program types"
                );
                assert_eq!(
                    EbpfProgramType::from_spec_prefix(alias),
                    Some(*program_type),
                    "program spec alias '{alias}' should resolve back to {program_type:?}"
                );
            }
        }

        assert_eq!(
            listed_prefixes, alias_prefixes,
            "PROGRAM_SPEC_PREFIXES must exactly match per-program aliases"
        );
    }

    #[test]
    fn test_btf_callable_surface_table_is_unique_and_complete() {
        let mut surface_programs = HashSet::new();

        for spec in BTF_CALLABLE_SURFACES {
            assert!(
                !spec.program_types.is_empty(),
                "BTF callable surface {:?} must list at least one program type",
                spec.surface
            );
            for program_type in spec.program_types {
                assert!(
                    ALL_PROGRAM_TYPES.contains(program_type),
                    "BTF callable surface {:?} contains unsupported program type {:?}",
                    spec.surface,
                    program_type
                );
                assert!(
                    surface_programs.insert(*program_type),
                    "program type {:?} appears in more than one BTF callable surface",
                    program_type
                );
                assert_eq!(
                    btf_callable_surface_for(*program_type),
                    Some(spec.surface),
                    "program type {:?} should resolve to BTF callable surface {:?}",
                    program_type,
                    spec.surface
                );
            }
        }

        for program_type in ALL_PROGRAM_TYPES {
            if !surface_programs.contains(program_type) {
                assert_eq!(btf_callable_surface_for(*program_type), None);
            }
        }
    }

    #[test]
    fn test_program_intrinsic_registry_is_unique_and_backed_by_capabilities() {
        let mut intrinsics = HashSet::new();

        for intrinsic in PROGRAM_INTRINSICS {
            assert!(
                intrinsics.insert(*intrinsic),
                "duplicate program intrinsic {intrinsic:?}"
            );
            let capability = intrinsic.required_capability();
            assert!(
                ALL_PROGRAM_TYPES
                    .iter()
                    .any(|program_type| program_type.supports_capability(capability)),
                "program intrinsic {intrinsic:?} requires unsupported capability {capability:?}"
            );
        }
    }
}
