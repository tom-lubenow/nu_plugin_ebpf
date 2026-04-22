use super::{EbpfProgramType, GetSocketCookieArgPolicy, MessageAdjustMode, PacketAdjustMode};
use crate::compiler::instruction::BpfHelper;
use crate::compiler::mir::MapKind;
use crate::program_spec::{ProgramAttachAddressFamily, ProgramSpec};

#[derive(Debug, Clone, Copy)]
struct HelperProgramSurfaceSpec {
    family: HelperProgramSurfaceFamily,
}

#[derive(Debug, Clone, Copy)]
struct HelperZeroArgRequirementSpec {
    helper: BpfHelper,
    program_type: EbpfProgramType,
    arg_idx: usize,
    error_message: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HelperProgramSurfaceFamily {
    LircMode2,
    Xdp,
    TcSkSkb,
    XdpTc,
    Tc,
    SkbLoadBytes,
    SkbLoadBytesRelative,
    PerfEventOutput,
    PerfEvent,
    GetStackId,
    LegacyProbeRead,
    SocketCookie,
    SocketUid,
    NetnsCookie,
    CgroupSkb,
    SkMsg,
    SkSkb,
    SkReuseport,
    SocketLookup,
    SocketRelease,
    TcSkLookup,
    TcCgroupSkb,
    TcpSock,
    SocketCast,
    TaskStorage,
    Lsm,
    TrampolineArgs,
    Fexit,
    SkStorageGet,
    SkStorageDelete,
    TracingSocket,
    Sockopt,
    CgroupSockAddr,
    SockOps,
    CgroupSysctl,
}

#[derive(Debug, Clone, Copy)]
struct HelperProgramSurfaceFamilySpec {
    family: HelperProgramSurfaceFamily,
    program_types: &'static [EbpfProgramType],
    label: &'static str,
}

const HELPER_PROGRAM_SURFACE_FAMILY_SPECS: &[HelperProgramSurfaceFamilySpec] = &[
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::LircMode2,
        program_types: &[EbpfProgramType::LircMode2],
        label: "lirc_mode2",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::Xdp,
        program_types: &[EbpfProgramType::Xdp],
        label: "xdp",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::TcSkSkb,
        program_types: &[
            EbpfProgramType::Tc,
            EbpfProgramType::SkSkb,
            EbpfProgramType::SkSkbParser,
        ],
        label: "tc, sk_skb, and sk_skb_parser",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::XdpTc,
        program_types: &[EbpfProgramType::Xdp, EbpfProgramType::Tc],
        label: "xdp and tc",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::Tc,
        program_types: &[EbpfProgramType::Tc],
        label: "tc",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::SkbLoadBytes,
        program_types: &[
            EbpfProgramType::FlowDissector,
            EbpfProgramType::SocketFilter,
            EbpfProgramType::LwtIn,
            EbpfProgramType::LwtOut,
            EbpfProgramType::LwtXmit,
            EbpfProgramType::LwtSeg6Local,
            EbpfProgramType::Tc,
            EbpfProgramType::CgroupSkb,
            EbpfProgramType::SkReuseport,
            EbpfProgramType::SkSkb,
            EbpfProgramType::SkSkbParser,
        ],
        label: "flow_dissector, socket_filter, lwt_*, tc, cgroup_skb, sk_reuseport, sk_skb, and sk_skb_parser",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::SkbLoadBytesRelative,
        program_types: &[
            EbpfProgramType::SocketFilter,
            EbpfProgramType::Tc,
            EbpfProgramType::CgroupSkb,
            EbpfProgramType::SkReuseport,
        ],
        label: "socket_filter, tc, cgroup_skb, and sk_reuseport",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::PerfEventOutput,
        program_types: &[
            EbpfProgramType::CgroupDevice,
            EbpfProgramType::CgroupSkb,
            EbpfProgramType::CgroupSock,
            EbpfProgramType::CgroupSockopt,
            EbpfProgramType::CgroupSockAddr,
            EbpfProgramType::CgroupSysctl,
            EbpfProgramType::Kprobe,
            EbpfProgramType::Kretprobe,
            EbpfProgramType::KprobeMulti,
            EbpfProgramType::KretprobeMulti,
            EbpfProgramType::Ksyscall,
            EbpfProgramType::KretSyscall,
            EbpfProgramType::Uprobe,
            EbpfProgramType::Uretprobe,
            EbpfProgramType::UprobeMulti,
            EbpfProgramType::UretprobeMulti,
            EbpfProgramType::PerfEvent,
            EbpfProgramType::RawTracepoint,
            EbpfProgramType::RawTracepointWritable,
            EbpfProgramType::Tracepoint,
            EbpfProgramType::Fentry,
            EbpfProgramType::Fexit,
            EbpfProgramType::FmodRet,
            EbpfProgramType::TpBtf,
            EbpfProgramType::SocketFilter,
            EbpfProgramType::Tc,
            EbpfProgramType::SkLookup,
            EbpfProgramType::SkMsg,
            EbpfProgramType::SkSkb,
            EbpfProgramType::SkSkbParser,
            EbpfProgramType::SockOps,
            EbpfProgramType::Xdp,
        ],
        label: "cgroup_device, cgroup_skb, cgroup_sock, cgroup_sockopt, cgroup_sock_addr, cgroup_sysctl, kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, uprobe, uretprobe, uprobe.multi, uretprobe.multi, perf_event, raw_tracepoint, raw_tracepoint.w, tracepoint, fentry, fexit, fmod_ret, tp_btf, socket_filter, tc, sk_lookup, sk_msg, sk_skb, sk_skb_parser, sock_ops, and xdp",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::PerfEvent,
        program_types: &[EbpfProgramType::PerfEvent],
        label: "perf_event",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::GetStackId,
        program_types: &[
            EbpfProgramType::Kprobe,
            EbpfProgramType::Kretprobe,
            EbpfProgramType::KprobeMulti,
            EbpfProgramType::KretprobeMulti,
            EbpfProgramType::Ksyscall,
            EbpfProgramType::KretSyscall,
            EbpfProgramType::Uprobe,
            EbpfProgramType::Uretprobe,
            EbpfProgramType::UprobeMulti,
            EbpfProgramType::UretprobeMulti,
            EbpfProgramType::PerfEvent,
            EbpfProgramType::RawTracepoint,
            EbpfProgramType::RawTracepointWritable,
            EbpfProgramType::Tracepoint,
            EbpfProgramType::Fentry,
            EbpfProgramType::Fexit,
            EbpfProgramType::FmodRet,
            EbpfProgramType::TpBtf,
        ],
        label: "kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, uprobe, uretprobe, uprobe.multi, uretprobe.multi, perf_event, raw_tracepoint, raw_tracepoint.w, tracepoint, fentry, fexit, fmod_ret, and tp_btf",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::LegacyProbeRead,
        program_types: &[
            EbpfProgramType::Kprobe,
            EbpfProgramType::Kretprobe,
            EbpfProgramType::KprobeMulti,
            EbpfProgramType::KretprobeMulti,
            EbpfProgramType::Ksyscall,
            EbpfProgramType::KretSyscall,
            EbpfProgramType::Uprobe,
            EbpfProgramType::Uretprobe,
            EbpfProgramType::UprobeMulti,
            EbpfProgramType::UretprobeMulti,
            EbpfProgramType::Lsm,
            EbpfProgramType::LsmCgroup,
            EbpfProgramType::PerfEvent,
            EbpfProgramType::RawTracepoint,
            EbpfProgramType::RawTracepointWritable,
            EbpfProgramType::Tracepoint,
            EbpfProgramType::Fentry,
            EbpfProgramType::Fexit,
            EbpfProgramType::FmodRet,
            EbpfProgramType::TpBtf,
        ],
        label: "kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, uprobe, uretprobe, uprobe.multi, uretprobe.multi, lsm, lsm_cgroup, perf_event, raw_tracepoint, raw_tracepoint.w, tracepoint, fentry, fexit, fmod_ret, and tp_btf",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::SocketCookie,
        program_types: &[
            EbpfProgramType::Fentry,
            EbpfProgramType::Fexit,
            EbpfProgramType::FmodRet,
            EbpfProgramType::TpBtf,
            EbpfProgramType::SocketFilter,
            EbpfProgramType::TcAction,
            EbpfProgramType::Tc,
            EbpfProgramType::CgroupSkb,
            EbpfProgramType::CgroupSock,
            EbpfProgramType::CgroupSockAddr,
            EbpfProgramType::SockOps,
            EbpfProgramType::SkReuseport,
            EbpfProgramType::SkSkb,
            EbpfProgramType::SkSkbParser,
        ],
        label: "fentry, fexit, fmod_ret, tp_btf, socket_filter, tc_action, tc, cgroup_skb, cgroup_sock, cgroup_sock_addr, sock_ops, sk_reuseport, sk_skb, and sk_skb_parser",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::SocketUid,
        program_types: &[
            EbpfProgramType::SocketFilter,
            EbpfProgramType::TcAction,
            EbpfProgramType::Tc,
            EbpfProgramType::CgroupSkb,
            EbpfProgramType::SkSkb,
            EbpfProgramType::SkSkbParser,
        ],
        label: "socket_filter, tc_action, tc, cgroup_skb, sk_skb, and sk_skb_parser",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::NetnsCookie,
        program_types: &[
            EbpfProgramType::SocketFilter,
            EbpfProgramType::TcAction,
            EbpfProgramType::Tc,
            EbpfProgramType::CgroupSkb,
            EbpfProgramType::CgroupSock,
            EbpfProgramType::CgroupSockopt,
            EbpfProgramType::CgroupSockAddr,
            EbpfProgramType::SockOps,
            EbpfProgramType::SkMsg,
        ],
        label: "socket_filter, tc_action, tc, cgroup_skb, cgroup_sock, cgroup_sockopt, cgroup_sock_addr, sock_ops, and sk_msg",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::CgroupSkb,
        program_types: &[EbpfProgramType::CgroupSkb],
        label: "cgroup_skb",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::SkMsg,
        program_types: &[EbpfProgramType::SkMsg],
        label: "sk_msg",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::SkSkb,
        program_types: &[EbpfProgramType::SkSkb, EbpfProgramType::SkSkbParser],
        label: "sk_skb and sk_skb_parser",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::SkReuseport,
        program_types: &[EbpfProgramType::SkReuseport],
        label: "sk_reuseport",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::SocketLookup,
        program_types: &[
            EbpfProgramType::Xdp,
            EbpfProgramType::Tc,
            EbpfProgramType::CgroupSkb,
            EbpfProgramType::CgroupSockAddr,
            EbpfProgramType::SkSkb,
        ],
        label: "xdp, tc, cgroup_skb, cgroup_sock_addr, and sk_skb",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::SocketRelease,
        program_types: &[
            EbpfProgramType::Xdp,
            EbpfProgramType::Tc,
            EbpfProgramType::CgroupSkb,
            EbpfProgramType::CgroupSockAddr,
            EbpfProgramType::SkLookup,
            EbpfProgramType::SkSkb,
        ],
        label: "xdp, tc, cgroup_skb, cgroup_sock_addr, sk_lookup, and sk_skb",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::TcSkLookup,
        program_types: &[EbpfProgramType::Tc, EbpfProgramType::SkLookup],
        label: "tc and sk_lookup",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::TcCgroupSkb,
        program_types: &[EbpfProgramType::Tc, EbpfProgramType::CgroupSkb],
        label: "tc and cgroup_skb",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::TcpSock,
        program_types: &[
            EbpfProgramType::Tc,
            EbpfProgramType::CgroupSkb,
            EbpfProgramType::CgroupSockopt,
            EbpfProgramType::SockOps,
        ],
        label: "tc, cgroup_skb, cgroup_sockopt, and sock_ops",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::SocketCast,
        program_types: &[
            EbpfProgramType::Xdp,
            EbpfProgramType::FlowDissector,
            EbpfProgramType::SocketFilter,
            EbpfProgramType::LwtIn,
            EbpfProgramType::LwtOut,
            EbpfProgramType::LwtXmit,
            EbpfProgramType::LwtSeg6Local,
            EbpfProgramType::Tc,
            EbpfProgramType::CgroupSkb,
            EbpfProgramType::CgroupSockAddr,
            EbpfProgramType::Fentry,
            EbpfProgramType::Fexit,
            EbpfProgramType::FmodRet,
            EbpfProgramType::TpBtf,
            EbpfProgramType::SkLookup,
            EbpfProgramType::SkMsg,
            EbpfProgramType::SkSkb,
            EbpfProgramType::SkSkbParser,
            EbpfProgramType::SockOps,
        ],
        label: "xdp, flow_dissector, socket_filter, lwt_*, tc, cgroup_skb, cgroup_sock_addr, fentry, fexit, fmod_ret, tp_btf, sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::TaskStorage,
        program_types: &[
            EbpfProgramType::Kprobe,
            EbpfProgramType::Kretprobe,
            EbpfProgramType::KprobeMulti,
            EbpfProgramType::KretprobeMulti,
            EbpfProgramType::Ksyscall,
            EbpfProgramType::KretSyscall,
            EbpfProgramType::Uprobe,
            EbpfProgramType::Uretprobe,
            EbpfProgramType::UprobeMulti,
            EbpfProgramType::UretprobeMulti,
            EbpfProgramType::PerfEvent,
            EbpfProgramType::RawTracepoint,
            EbpfProgramType::RawTracepointWritable,
            EbpfProgramType::Tracepoint,
            EbpfProgramType::Fentry,
            EbpfProgramType::Fexit,
            EbpfProgramType::FmodRet,
            EbpfProgramType::TpBtf,
            EbpfProgramType::Lsm,
            EbpfProgramType::LsmCgroup,
        ],
        label: "kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, uprobe, uretprobe, uprobe.multi, uretprobe.multi, perf_event, raw_tracepoint, raw_tracepoint.w, tracepoint, fentry, fexit, fmod_ret, tp_btf, lsm, and lsm_cgroup",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::Lsm,
        program_types: &[EbpfProgramType::Lsm, EbpfProgramType::LsmCgroup],
        label: "lsm and lsm_cgroup",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::TrampolineArgs,
        program_types: &[
            EbpfProgramType::Fentry,
            EbpfProgramType::Fexit,
            EbpfProgramType::FmodRet,
            EbpfProgramType::TpBtf,
            EbpfProgramType::Lsm,
            EbpfProgramType::LsmCgroup,
        ],
        label: "fentry, fexit, fmod_ret, tp_btf, lsm, and lsm_cgroup",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::Fexit,
        program_types: &[EbpfProgramType::Fexit, EbpfProgramType::FmodRet],
        label: "fexit and fmod_ret",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::SkStorageGet,
        program_types: &[
            EbpfProgramType::Tc,
            EbpfProgramType::CgroupSkb,
            EbpfProgramType::CgroupSock,
            EbpfProgramType::CgroupSockAddr,
            EbpfProgramType::CgroupSockopt,
            EbpfProgramType::SockOps,
            EbpfProgramType::SkMsg,
            EbpfProgramType::StructOps,
            EbpfProgramType::Fentry,
            EbpfProgramType::Fexit,
            EbpfProgramType::FmodRet,
            EbpfProgramType::TpBtf,
            EbpfProgramType::Lsm,
            EbpfProgramType::LsmCgroup,
        ],
        label: "tc, cgroup_skb, cgroup_sock, cgroup_sock_addr, cgroup_sockopt, sock_ops, sk_msg, struct_ops, fentry, fexit, fmod_ret, tp_btf, lsm, and lsm_cgroup",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::SkStorageDelete,
        program_types: &[
            EbpfProgramType::Tc,
            EbpfProgramType::CgroupSkb,
            EbpfProgramType::CgroupSockAddr,
            EbpfProgramType::CgroupSockopt,
            EbpfProgramType::SockOps,
            EbpfProgramType::SkMsg,
            EbpfProgramType::StructOps,
            EbpfProgramType::Fentry,
            EbpfProgramType::Fexit,
            EbpfProgramType::FmodRet,
            EbpfProgramType::TpBtf,
            EbpfProgramType::Lsm,
            EbpfProgramType::LsmCgroup,
        ],
        label: "tc, cgroup_skb, cgroup_sock_addr, cgroup_sockopt, sock_ops, sk_msg, struct_ops, fentry, fexit, fmod_ret, tp_btf, lsm, and lsm_cgroup",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::TracingSocket,
        program_types: &[
            EbpfProgramType::Fentry,
            EbpfProgramType::Fexit,
            EbpfProgramType::FmodRet,
            EbpfProgramType::TpBtf,
        ],
        label: "fentry, fexit, fmod_ret, and tp_btf",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::Sockopt,
        program_types: &[
            EbpfProgramType::SockOps,
            EbpfProgramType::CgroupSockAddr,
            EbpfProgramType::CgroupSockopt,
        ],
        label: "sock_ops, cgroup_sock_addr, and cgroup_sockopt",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::CgroupSockAddr,
        program_types: &[EbpfProgramType::CgroupSockAddr],
        label: "cgroup_sock_addr",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::SockOps,
        program_types: &[EbpfProgramType::SockOps],
        label: "sock_ops",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::CgroupSysctl,
        program_types: &[EbpfProgramType::CgroupSysctl],
        label: "cgroup_sysctl",
    },
];

impl HelperProgramSurfaceFamily {
    fn spec(self) -> &'static HelperProgramSurfaceFamilySpec {
        HELPER_PROGRAM_SURFACE_FAMILY_SPECS
            .iter()
            .find(|spec| spec.family == self)
            .expect("helper program surface family must have a spec")
    }

    fn allows(self, program_type: EbpfProgramType) -> bool {
        self.spec().program_types.contains(&program_type)
    }

    fn label(self) -> &'static str {
        self.spec().label
    }
}

impl HelperProgramSurfaceSpec {
    fn allows(self, program_type: EbpfProgramType) -> bool {
        self.family.allows(program_type)
    }

    fn error(self, helper: BpfHelper) -> String {
        format!(
            "helper '{}' is only valid in {} programs",
            helper.name(),
            self.family.label()
        )
    }
}

fn helper_ids_equal(lhs: BpfHelper, rhs: BpfHelper) -> bool {
    lhs as u32 == rhs as u32
}

fn helper_list_contains(helpers: &[BpfHelper], helper: BpfHelper) -> bool {
    helpers
        .iter()
        .copied()
        .any(|candidate| helper_ids_equal(candidate, helper))
}

const TC_INGRESS_ONLY_HELPERS: &[BpfHelper] = &[BpfHelper::RedirectPeer, BpfHelper::SkAssign];
const TC_EGRESS_ONLY_HELPERS: &[BpfHelper] = &[
    BpfHelper::GetCgroupClassid,
    BpfHelper::GetRouteRealm,
    BpfHelper::SkbCgroupId,
    BpfHelper::SkbAncestorCgroupId,
];
const CGROUP_SOCK_ADDR_INET_CONNECT_ONLY_HELPERS: &[BpfHelper] = &[BpfHelper::Bind];
const CGROUP_SOCK_POST_BIND_ONLY_MEMBERS: &[&str] = &["src_port"];
const CGROUP_SOCK_POST_BIND4_ONLY_MEMBERS: &[&str] = &["src_ip4"];
const CGROUP_SOCK_POST_BIND6_ONLY_MEMBERS: &[&str] = &["src_ip6"];
const HELPER_ZERO_ARG_REQUIREMENTS: &[HelperZeroArgRequirementSpec] = &[
    HelperZeroArgRequirementSpec {
        helper: BpfHelper::Redirect,
        program_type: EbpfProgramType::Xdp,
        arg_idx: 1,
        error_message: "helper 'bpf_redirect' requires arg1 = 0 in xdp programs",
    },
    HelperZeroArgRequirementSpec {
        helper: BpfHelper::SkAssign,
        program_type: EbpfProgramType::Tc,
        arg_idx: 2,
        error_message: "helper 'bpf_sk_assign' requires arg2 = 0 in tc programs",
    },
];

fn helper_program_surface_spec(helper: BpfHelper) -> Option<HelperProgramSurfaceSpec> {
    Some(match helper {
        BpfHelper::RcRepeat | BpfHelper::RcKeydown | BpfHelper::RcPointerRel => {
            HelperProgramSurfaceSpec {
                family: HelperProgramSurfaceFamily::LircMode2,
            }
        }
        BpfHelper::XdpAdjustHead | BpfHelper::XdpAdjustMeta | BpfHelper::XdpAdjustTail => {
            HelperProgramSurfaceSpec {
                family: HelperProgramSurfaceFamily::Xdp,
            }
        }
        BpfHelper::XdpGetBuffLen | BpfHelper::XdpLoadBytes | BpfHelper::XdpStoreBytes => {
            HelperProgramSurfaceSpec {
                family: HelperProgramSurfaceFamily::Xdp,
            }
        }
        BpfHelper::RedirectMap => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::Xdp,
        },
        BpfHelper::SkbChangeTail
        | BpfHelper::SkbStoreBytes
        | BpfHelper::L3CsumReplace
        | BpfHelper::L4CsumReplace
        | BpfHelper::CloneRedirect
        | BpfHelper::GetHashRecalc
        | BpfHelper::SkbPullData
        | BpfHelper::CsumUpdate
        | BpfHelper::CsumLevel
        | BpfHelper::SetHashInvalid
        | BpfHelper::SetHash
        | BpfHelper::SkbChangeHead
        | BpfHelper::SkbVlanPush
        | BpfHelper::SkbVlanPop
        | BpfHelper::SkbAdjustRoom => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::TcSkSkb,
        },
        BpfHelper::SkbLoadBytes => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::SkbLoadBytes,
        },
        BpfHelper::SkbLoadBytesRelative => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::SkbLoadBytesRelative,
        },
        BpfHelper::CsumDiff | BpfHelper::Redirect => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::XdpTc,
        },
        BpfHelper::RedirectPeer
        | BpfHelper::RedirectNeigh
        | BpfHelper::SkbSetTstamp
        | BpfHelper::SkbUnderCgroup
        | BpfHelper::GetCgroupClassid
        | BpfHelper::GetRouteRealm
        | BpfHelper::SkbCgroupId
        | BpfHelper::SkbAncestorCgroupId => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::Tc,
        },
        BpfHelper::PerfEventOutput => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::PerfEventOutput,
        },
        BpfHelper::PerfProgReadValue | BpfHelper::ReadBranchRecords => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::PerfEvent,
        },
        BpfHelper::GetStackId
        | BpfHelper::GetStack
        | BpfHelper::GetFuncIp
        | BpfHelper::GetAttachCookie => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::GetStackId,
        },
        BpfHelper::ProbeRead => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::LegacyProbeRead,
        },
        BpfHelper::GetSocketCookie => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::SocketCookie,
        },
        BpfHelper::GetSocketUid => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::SocketUid,
        },
        BpfHelper::GetNetnsCookie => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::NetnsCookie,
        },
        BpfHelper::SkCgroupId | BpfHelper::SkAncestorCgroupId => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::CgroupSkb,
        },
        BpfHelper::MsgApplyBytes
        | BpfHelper::MsgCorkBytes
        | BpfHelper::MsgPullData
        | BpfHelper::MsgPushData
        | BpfHelper::MsgPopData
        | BpfHelper::MsgRedirectMap
        | BpfHelper::MsgRedirectHash => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::SkMsg,
        },
        BpfHelper::SkRedirectMap | BpfHelper::SkRedirectHash => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::SkSkb,
        },
        BpfHelper::SkSelectReuseport => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::SkReuseport,
        },
        BpfHelper::SkLookupTcp | BpfHelper::SkLookupUdp | BpfHelper::SkcLookupTcp => {
            HelperProgramSurfaceSpec {
                family: HelperProgramSurfaceFamily::SocketLookup,
            }
        }
        BpfHelper::TcpCheckSyncookie | BpfHelper::TcpGenSyncookie => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::XdpTc,
        },
        BpfHelper::SkRelease => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::SocketRelease,
        },
        BpfHelper::SkAssign => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::TcSkLookup,
        },
        BpfHelper::GetListenerSock | BpfHelper::SkFullsock => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::TcCgroupSkb,
        },
        BpfHelper::TcpSock => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::TcpSock,
        },
        BpfHelper::SkcToTcpSock
        | BpfHelper::SkcToTcp6Sock
        | BpfHelper::SkcToTcpTimewaitSock
        | BpfHelper::SkcToTcpRequestSock
        | BpfHelper::SkcToUdp6Sock
        | BpfHelper::SkcToUnixSock => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::SocketCast,
        },
        BpfHelper::TaskStorageGet
        | BpfHelper::TaskStorageDelete
        | BpfHelper::GetCurrentTask
        | BpfHelper::GetCurrentTaskBtf
        | BpfHelper::TaskPtRegs => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::TaskStorage,
        },
        BpfHelper::InodeStorageGet | BpfHelper::InodeStorageDelete => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::Lsm,
        },
        BpfHelper::GetFuncArg | BpfHelper::GetFuncArgCnt => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::TrampolineArgs,
        },
        BpfHelper::GetFuncRet => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::Fexit,
        },
        BpfHelper::SkStorageGet => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::SkStorageGet,
        },
        BpfHelper::SkStorageDelete => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::SkStorageDelete,
        },
        BpfHelper::SockFromFile => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::TracingSocket,
        },
        BpfHelper::SetSockOpt | BpfHelper::GetSockOpt => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::Sockopt,
        },
        BpfHelper::Bind => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::CgroupSockAddr,
        },
        BpfHelper::SockOpsCbFlagsSet
        | BpfHelper::SockMapUpdate
        | BpfHelper::SockHashUpdate
        | BpfHelper::LoadHdrOpt
        | BpfHelper::StoreHdrOpt
        | BpfHelper::ReserveHdrOpt => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::SockOps,
        },
        BpfHelper::SysctlGetName
        | BpfHelper::SysctlGetCurrentValue
        | BpfHelper::SysctlGetNewValue
        | BpfHelper::SysctlSetNewValue => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::CgroupSysctl,
        },
        _ => return None,
    })
}

impl EbpfProgramType {
    pub(crate) fn helper_call_error(&self, helper: BpfHelper) -> Option<String> {
        helper_program_surface_spec(helper)
            .filter(|spec| !spec.allows(*self))
            .map(|spec| spec.error(helper))
    }

    pub(crate) fn helper_zero_arg_requirement(
        &self,
        helper: BpfHelper,
    ) -> Option<(usize, &'static str)> {
        HELPER_ZERO_ARG_REQUIREMENTS
            .iter()
            .find(|spec| helper_ids_equal(spec.helper, helper) && spec.program_type == *self)
            .map(|spec| (spec.arg_idx, spec.error_message))
    }

    pub(crate) fn get_socket_cookie_arg_policy(&self) -> Option<GetSocketCookieArgPolicy> {
        if matches!(
            self,
            EbpfProgramType::SocketFilter
                | EbpfProgramType::TcAction
                | EbpfProgramType::Tc
                | EbpfProgramType::CgroupSkb
                | EbpfProgramType::CgroupSockAddr
                | EbpfProgramType::SockOps
                | EbpfProgramType::SkReuseport
                | EbpfProgramType::SkSkb
                | EbpfProgramType::SkSkbParser
        ) {
            Some(GetSocketCookieArgPolicy::Context)
        } else if matches!(self, EbpfProgramType::CgroupSock) {
            Some(GetSocketCookieArgPolicy::ContextOrSocket)
        } else if matches!(
            self,
            EbpfProgramType::Fentry
                | EbpfProgramType::Fexit
                | EbpfProgramType::FmodRet
                | EbpfProgramType::TpBtf
        ) {
            Some(GetSocketCookieArgPolicy::Socket)
        } else {
            None
        }
    }

    pub(crate) fn packet_redirect_helper(&self) -> Option<BpfHelper> {
        if HelperProgramSurfaceFamily::XdpTc.allows(*self) {
            Some(BpfHelper::Redirect)
        } else {
            None
        }
    }

    pub(crate) fn cgroup_array_membership_helper(&self) -> BpfHelper {
        if HelperProgramSurfaceFamily::Tc.allows(*self) {
            BpfHelper::SkbUnderCgroup
        } else {
            BpfHelper::CurrentTaskUnderCgroup
        }
    }

    pub(crate) fn packet_adjust_helper(&self, mode: PacketAdjustMode) -> Option<BpfHelper> {
        match mode {
            PacketAdjustMode::Head => {
                if HelperProgramSurfaceFamily::Xdp.allows(*self) {
                    Some(BpfHelper::XdpAdjustHead)
                } else if HelperProgramSurfaceFamily::TcSkSkb.allows(*self) {
                    Some(BpfHelper::SkbChangeHead)
                } else {
                    None
                }
            }
            PacketAdjustMode::Meta => HelperProgramSurfaceFamily::Xdp
                .allows(*self)
                .then_some(BpfHelper::XdpAdjustMeta),
            PacketAdjustMode::Tail => {
                if HelperProgramSurfaceFamily::Xdp.allows(*self) {
                    Some(BpfHelper::XdpAdjustTail)
                } else if HelperProgramSurfaceFamily::TcSkSkb.allows(*self) {
                    Some(BpfHelper::SkbChangeTail)
                } else {
                    None
                }
            }
            PacketAdjustMode::Pull => HelperProgramSurfaceFamily::TcSkSkb
                .allows(*self)
                .then_some(BpfHelper::SkbPullData),
            PacketAdjustMode::Room => HelperProgramSurfaceFamily::TcSkSkb
                .allows(*self)
                .then_some(BpfHelper::SkbAdjustRoom),
        }
    }

    pub(crate) fn message_adjust_helper(&self, mode: MessageAdjustMode) -> Option<BpfHelper> {
        HelperProgramSurfaceFamily::SkMsg
            .allows(*self)
            .then_some(match mode {
                MessageAdjustMode::Apply => BpfHelper::MsgApplyBytes,
                MessageAdjustMode::Cork => BpfHelper::MsgCorkBytes,
                MessageAdjustMode::Pull => BpfHelper::MsgPullData,
                MessageAdjustMode::Push => BpfHelper::MsgPushData,
                MessageAdjustMode::Pop => BpfHelper::MsgPopData,
            })
    }

    pub(crate) fn packet_redirect_peer_helper(&self) -> Option<BpfHelper> {
        if HelperProgramSurfaceFamily::Tc.allows(*self) {
            Some(BpfHelper::RedirectPeer)
        } else {
            None
        }
    }

    pub(crate) fn packet_redirect_neigh_helper(&self) -> Option<BpfHelper> {
        if HelperProgramSurfaceFamily::Tc.allows(*self) {
            Some(BpfHelper::RedirectNeigh)
        } else {
            None
        }
    }

    pub(crate) fn socket_redirect_helper(&self, map_kind: MapKind) -> Option<BpfHelper> {
        if HelperProgramSurfaceFamily::SkMsg.allows(*self) {
            match map_kind {
                MapKind::SockMap => Some(BpfHelper::MsgRedirectMap),
                MapKind::SockHash => Some(BpfHelper::MsgRedirectHash),
                _ => None,
            }
        } else if HelperProgramSurfaceFamily::SkSkb.allows(*self) {
            match map_kind {
                MapKind::SockMap => Some(BpfHelper::SkRedirectMap),
                MapKind::SockHash => Some(BpfHelper::SkRedirectHash),
                _ => None,
            }
        } else if HelperProgramSurfaceFamily::SkReuseport.allows(*self) {
            match map_kind {
                MapKind::ReuseportSockArray => Some(BpfHelper::SkSelectReuseport),
                _ => None,
            }
        } else {
            None
        }
    }
}

impl ProgramSpec {
    fn attach_helper_call_error(&self, helper: BpfHelper) -> Option<String> {
        let attach_shape = self.attach_shape();
        match attach_shape {
            _ if attach_shape.is_tc_egress()
                && helper_list_contains(TC_INGRESS_ONLY_HELPERS, helper) =>
            {
                Some(format!(
                    "helper '{}' is only valid in tc ingress programs",
                    helper.name()
                ))
            }
            _ if attach_shape.is_tc_ingress()
                && helper_list_contains(TC_EGRESS_ONLY_HELPERS, helper) =>
            {
                Some(format!(
                    "helper '{}' is only valid in tc egress programs",
                    helper.name()
                ))
            }
            _ if attach_shape
                .cgroup_sock_addr()
                .is_some_and(|(family, hook)| !(hook.is_connect() && family.is_inet()))
                && helper_list_contains(CGROUP_SOCK_ADDR_INET_CONNECT_ONLY_HELPERS, helper) =>
            {
                Some(format!(
                    "helper '{}' is only valid on cgroup_sock_addr connect4/connect6 hooks",
                    helper.name()
                ))
            }
            _ => None,
        }
    }

    pub(crate) fn helper_call_error(&self, helper: BpfHelper) -> Option<String> {
        self.program_type()
            .helper_call_error(helper)
            .or_else(|| self.attach_helper_call_error(helper))
    }

    pub(crate) fn socket_projection_access_error(&self, member_name: &str) -> Option<String> {
        let attach_shape = self.attach_shape();
        match member_name {
            _ if attach_shape.is_cgroup_sock_create_release()
                && CGROUP_SOCK_POST_BIND_ONLY_MEMBERS.contains(&member_name) =>
            {
                Some(format!(
                    "ctx.sk.{member_name} is only available on cgroup_sock post_bind4/post_bind6 hooks"
                ))
            }
            _ if attach_shape.is_cgroup_sock_post_bind_family(ProgramAttachAddressFamily::Ipv4)
                && CGROUP_SOCK_POST_BIND4_ONLY_MEMBERS.contains(&member_name) =>
            {
                None
            }
            _ if attach_shape.is_cgroup_sock()
                && CGROUP_SOCK_POST_BIND4_ONLY_MEMBERS.contains(&member_name) =>
            {
                Some(format!(
                    "ctx.sk.{member_name} is only available on cgroup_sock post_bind4 hooks"
                ))
            }
            _ if attach_shape.is_cgroup_sock_post_bind_family(ProgramAttachAddressFamily::Ipv6)
                && CGROUP_SOCK_POST_BIND6_ONLY_MEMBERS.contains(&member_name) =>
            {
                None
            }
            _ if attach_shape.is_cgroup_sock()
                && CGROUP_SOCK_POST_BIND6_ONLY_MEMBERS.contains(&member_name) =>
            {
                Some(format!(
                    "ctx.sk.{member_name} is only available on cgroup_sock post_bind6 hooks"
                ))
            }
            _ => None,
        }
    }
}
