use super::{
    EbpfProgramType, GetSocketCookieArgPolicy, MessageAdjustMode, PacketAdjustMode,
    ProgramIntrinsic,
};
use crate::compiler::instruction::BpfHelper;
use crate::compiler::mir::MapKind;
use crate::program_spec::{
    ProgramAttachAddressFamily, ProgramAttachSockAddrHook, ProgramSpec, StructOpsFamily,
};

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

#[derive(Debug, Clone, Copy)]
struct GetSocketCookieArgPolicySpec {
    policy: GetSocketCookieArgPolicy,
    program_types: &'static [EbpfProgramType],
}

#[derive(Debug, Clone, Copy)]
struct ProgramSpecificHelperPolicy {
    program_type: EbpfProgramType,
    label: &'static str,
    modeled_helpers: &'static [BpfHelper],
}

#[derive(Debug, Clone, Copy)]
struct SocketRedirectHelperSpec {
    map_kind: MapKind,
    family: HelperProgramSurfaceFamily,
    helper: BpfHelper,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HelperProgramSurfaceFamily {
    LircMode2,
    Xdp,
    TcSkSkb,
    TcSkSkbLwt,
    TcSkSkbLwtXmit,
    XdpTc,
    XdpTcLwt,
    XdpTcLwtXmit,
    Tc,
    TcLwt,
    TcLwtXmit,
    LwtInXmit,
    LwtSeg6Local,
    SkbLoadBytes,
    SkbLoadBytesRelative,
    PerfEventOutput,
    PerfEvent,
    GetStackId,
    LegacyProbeRead,
    KprobeOverride,
    SocketCookie,
    SocketUid,
    NetnsCookie,
    CgroupSkb,
    SkMsg,
    SkSkb,
    SkReuseport,
    SocketRedirectStream,
    SocketLookup,
    SocketRelease,
    TcSkLookup,
    TcCgroupSkb,
    TcpSock,
    TcpCongestionStructOps,
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
    CgroupRetval,
    CgroupLocalStorage,
    SpinLock,
    SockOps,
    CgroupSysctl,
    Syscall,
    Iter,
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
        family: HelperProgramSurfaceFamily::Iter,
        program_types: &[EbpfProgramType::Iter],
        label: "iter",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::TcSkSkb,
        program_types: &[
            EbpfProgramType::TcAction,
            EbpfProgramType::Tc,
            EbpfProgramType::Tcx,
            EbpfProgramType::Netkit,
            EbpfProgramType::SkSkb,
            EbpfProgramType::SkSkbParser,
        ],
        label: "tc_action, tc, tcx, netkit, sk_skb, and sk_skb_parser",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::TcSkSkbLwt,
        program_types: &[
            EbpfProgramType::LwtIn,
            EbpfProgramType::LwtOut,
            EbpfProgramType::LwtXmit,
            EbpfProgramType::LwtSeg6Local,
            EbpfProgramType::TcAction,
            EbpfProgramType::Tc,
            EbpfProgramType::Tcx,
            EbpfProgramType::Netkit,
            EbpfProgramType::SkSkb,
            EbpfProgramType::SkSkbParser,
        ],
        label: "lwt_*, tc_action, tc, tcx, netkit, sk_skb, and sk_skb_parser",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::TcSkSkbLwtXmit,
        program_types: &[
            EbpfProgramType::LwtXmit,
            EbpfProgramType::TcAction,
            EbpfProgramType::Tc,
            EbpfProgramType::Tcx,
            EbpfProgramType::Netkit,
            EbpfProgramType::SkSkb,
            EbpfProgramType::SkSkbParser,
        ],
        label: "lwt_xmit, tc_action, tc, tcx, netkit, sk_skb, and sk_skb_parser",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::XdpTc,
        program_types: &[
            EbpfProgramType::Xdp,
            EbpfProgramType::TcAction,
            EbpfProgramType::Tc,
            EbpfProgramType::Tcx,
            EbpfProgramType::Netkit,
        ],
        label: "xdp, tc_action, tc, tcx, and netkit",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::XdpTcLwt,
        program_types: &[
            EbpfProgramType::Xdp,
            EbpfProgramType::TcAction,
            EbpfProgramType::Tc,
            EbpfProgramType::Tcx,
            EbpfProgramType::Netkit,
            EbpfProgramType::LwtIn,
            EbpfProgramType::LwtOut,
            EbpfProgramType::LwtXmit,
            EbpfProgramType::LwtSeg6Local,
        ],
        label: "xdp, tc_action, tc, tcx, netkit, and lwt_*",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::XdpTcLwtXmit,
        program_types: &[
            EbpfProgramType::Xdp,
            EbpfProgramType::TcAction,
            EbpfProgramType::Tc,
            EbpfProgramType::Tcx,
            EbpfProgramType::Netkit,
            EbpfProgramType::LwtXmit,
        ],
        label: "xdp, tc_action, tc, tcx, netkit, and lwt_xmit",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::Tc,
        program_types: &[
            EbpfProgramType::TcAction,
            EbpfProgramType::Tc,
            EbpfProgramType::Tcx,
            EbpfProgramType::Netkit,
        ],
        label: "tc_action, tc, tcx, and netkit",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::TcLwt,
        program_types: &[
            EbpfProgramType::TcAction,
            EbpfProgramType::Tc,
            EbpfProgramType::Tcx,
            EbpfProgramType::Netkit,
            EbpfProgramType::LwtIn,
            EbpfProgramType::LwtOut,
            EbpfProgramType::LwtXmit,
            EbpfProgramType::LwtSeg6Local,
        ],
        label: "tc_action, tc, tcx, netkit, and lwt_*",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::TcLwtXmit,
        program_types: &[
            EbpfProgramType::TcAction,
            EbpfProgramType::Tc,
            EbpfProgramType::Tcx,
            EbpfProgramType::Netkit,
            EbpfProgramType::LwtXmit,
        ],
        label: "tc_action, tc, tcx, netkit, and lwt_xmit",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::LwtInXmit,
        program_types: &[EbpfProgramType::LwtIn, EbpfProgramType::LwtXmit],
        label: "lwt_in and lwt_xmit",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::LwtSeg6Local,
        program_types: &[EbpfProgramType::LwtSeg6Local],
        label: "lwt_seg6local",
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
            EbpfProgramType::TcAction,
            EbpfProgramType::Tc,
            EbpfProgramType::Tcx,
            EbpfProgramType::Netkit,
            EbpfProgramType::CgroupSkb,
            EbpfProgramType::SkReuseport,
            EbpfProgramType::SkSkb,
            EbpfProgramType::SkSkbParser,
        ],
        label: "flow_dissector, socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, sk_reuseport, sk_skb, and sk_skb_parser",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::SkbLoadBytesRelative,
        program_types: &[
            EbpfProgramType::SocketFilter,
            EbpfProgramType::TcAction,
            EbpfProgramType::Tc,
            EbpfProgramType::Tcx,
            EbpfProgramType::Netkit,
            EbpfProgramType::CgroupSkb,
            EbpfProgramType::SkReuseport,
        ],
        label: "socket_filter, tc_action, tc, tcx, netkit, cgroup_skb, and sk_reuseport",
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
            EbpfProgramType::LwtIn,
            EbpfProgramType::LwtOut,
            EbpfProgramType::LwtXmit,
            EbpfProgramType::LwtSeg6Local,
            EbpfProgramType::TcAction,
            EbpfProgramType::Tc,
            EbpfProgramType::Tcx,
            EbpfProgramType::Netkit,
            EbpfProgramType::SkLookup,
            EbpfProgramType::SkMsg,
            EbpfProgramType::SkSkb,
            EbpfProgramType::SkSkbParser,
            EbpfProgramType::SockOps,
            EbpfProgramType::Xdp,
        ],
        label: "cgroup_device, cgroup_skb, cgroup_sock, cgroup_sockopt, cgroup_sock_addr, cgroup_sysctl, kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, uprobe, uretprobe, uprobe.multi, uretprobe.multi, perf_event, raw_tracepoint, raw_tracepoint.w, tracepoint, fentry, fexit, fmod_ret, tp_btf, socket_filter, lwt_*, tc_action, tc, tcx, netkit, sk_lookup, sk_msg, sk_skb, sk_skb_parser, sock_ops, and xdp",
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
        family: HelperProgramSurfaceFamily::KprobeOverride,
        program_types: &[
            EbpfProgramType::Kprobe,
            EbpfProgramType::KprobeMulti,
            EbpfProgramType::Ksyscall,
        ],
        label: "kprobe, kprobe.multi, and ksyscall",
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
            EbpfProgramType::Tcx,
            EbpfProgramType::Netkit,
            EbpfProgramType::CgroupSkb,
            EbpfProgramType::CgroupSock,
            EbpfProgramType::CgroupSockAddr,
            EbpfProgramType::SockOps,
            EbpfProgramType::SkReuseport,
            EbpfProgramType::SkSkb,
            EbpfProgramType::SkSkbParser,
        ],
        label: "fentry, fexit, fmod_ret, tp_btf, socket_filter, tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock, cgroup_sock_addr, sock_ops, sk_reuseport, sk_skb, and sk_skb_parser",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::SocketUid,
        program_types: &[
            EbpfProgramType::SocketFilter,
            EbpfProgramType::TcAction,
            EbpfProgramType::Tc,
            EbpfProgramType::Tcx,
            EbpfProgramType::Netkit,
            EbpfProgramType::CgroupSkb,
            EbpfProgramType::SkSkb,
            EbpfProgramType::SkSkbParser,
        ],
        label: "socket_filter, tc_action, tc, tcx, netkit, cgroup_skb, sk_skb, and sk_skb_parser",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::NetnsCookie,
        program_types: &[
            EbpfProgramType::SocketFilter,
            EbpfProgramType::TcAction,
            EbpfProgramType::Tc,
            EbpfProgramType::Tcx,
            EbpfProgramType::Netkit,
            EbpfProgramType::CgroupSkb,
            EbpfProgramType::CgroupSock,
            EbpfProgramType::CgroupSockopt,
            EbpfProgramType::CgroupSockAddr,
            EbpfProgramType::SockOps,
            EbpfProgramType::SkMsg,
        ],
        label: "socket_filter, tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock, cgroup_sockopt, cgroup_sock_addr, sock_ops, and sk_msg",
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
        family: HelperProgramSurfaceFamily::SocketRedirectStream,
        program_types: &[
            EbpfProgramType::SkMsg,
            EbpfProgramType::SkSkb,
            EbpfProgramType::SkSkbParser,
        ],
        label: "sk_msg, sk_skb, and sk_skb_parser",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::SocketLookup,
        program_types: &[
            EbpfProgramType::Xdp,
            EbpfProgramType::TcAction,
            EbpfProgramType::Tc,
            EbpfProgramType::Tcx,
            EbpfProgramType::Netkit,
            EbpfProgramType::CgroupSkb,
            EbpfProgramType::CgroupSockAddr,
            EbpfProgramType::SkSkb,
        ],
        label: "xdp, tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock_addr, and sk_skb",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::SocketRelease,
        program_types: &[
            EbpfProgramType::Xdp,
            EbpfProgramType::TcAction,
            EbpfProgramType::Tc,
            EbpfProgramType::Tcx,
            EbpfProgramType::Netkit,
            EbpfProgramType::CgroupSkb,
            EbpfProgramType::CgroupSockAddr,
            EbpfProgramType::SkLookup,
            EbpfProgramType::SkSkb,
        ],
        label: "xdp, tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock_addr, sk_lookup, and sk_skb",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::TcSkLookup,
        program_types: &[
            EbpfProgramType::TcAction,
            EbpfProgramType::Tc,
            EbpfProgramType::Tcx,
            EbpfProgramType::SkLookup,
        ],
        label: "tc_action, tc, tcx, and sk_lookup",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::TcCgroupSkb,
        program_types: &[
            EbpfProgramType::TcAction,
            EbpfProgramType::Tc,
            EbpfProgramType::Tcx,
            EbpfProgramType::Netkit,
            EbpfProgramType::CgroupSkb,
        ],
        label: "tc_action, tc, tcx, netkit, and cgroup_skb",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::TcpSock,
        program_types: &[
            EbpfProgramType::TcAction,
            EbpfProgramType::Tc,
            EbpfProgramType::Tcx,
            EbpfProgramType::Netkit,
            EbpfProgramType::CgroupSkb,
            EbpfProgramType::CgroupSockopt,
            EbpfProgramType::SockOps,
        ],
        label: "tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sockopt, and sock_ops",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::TcpCongestionStructOps,
        program_types: &[EbpfProgramType::StructOps],
        label: "tcp_congestion_ops struct_ops",
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
            EbpfProgramType::TcAction,
            EbpfProgramType::Tc,
            EbpfProgramType::Tcx,
            EbpfProgramType::Netkit,
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
        label: "xdp, flow_dissector, socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock_addr, fentry, fexit, fmod_ret, tp_btf, sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops",
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
            EbpfProgramType::TcAction,
            EbpfProgramType::Tc,
            EbpfProgramType::Tcx,
            EbpfProgramType::Netkit,
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
        label: "tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock, cgroup_sock_addr, cgroup_sockopt, sock_ops, sk_msg, struct_ops, fentry, fexit, fmod_ret, tp_btf, lsm, and lsm_cgroup",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::SkStorageDelete,
        program_types: &[
            EbpfProgramType::TcAction,
            EbpfProgramType::Tc,
            EbpfProgramType::Tcx,
            EbpfProgramType::Netkit,
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
        label: "tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock_addr, cgroup_sockopt, sock_ops, sk_msg, struct_ops, fentry, fexit, fmod_ret, tp_btf, lsm, and lsm_cgroup",
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
        family: HelperProgramSurfaceFamily::CgroupRetval,
        program_types: &[
            EbpfProgramType::CgroupDevice,
            EbpfProgramType::CgroupSock,
            EbpfProgramType::CgroupSockopt,
            EbpfProgramType::CgroupSockAddr,
            EbpfProgramType::CgroupSysctl,
        ],
        label: "cgroup_device, cgroup_sock, cgroup_sockopt, cgroup_sock_addr, and cgroup_sysctl",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::CgroupLocalStorage,
        program_types: &[
            EbpfProgramType::CgroupDevice,
            EbpfProgramType::CgroupSkb,
            EbpfProgramType::CgroupSock,
            EbpfProgramType::CgroupSockAddr,
            EbpfProgramType::CgroupSockopt,
            EbpfProgramType::CgroupSysctl,
            EbpfProgramType::SockOps,
        ],
        label: "cgroup_device, cgroup_skb, cgroup_sock, cgroup_sock_addr, cgroup_sockopt, cgroup_sysctl, and sock_ops",
    },
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::SpinLock,
        program_types: &[
            EbpfProgramType::Xdp,
            EbpfProgramType::FlowDissector,
            EbpfProgramType::Netfilter,
            EbpfProgramType::LircMode2,
            EbpfProgramType::LwtIn,
            EbpfProgramType::LwtOut,
            EbpfProgramType::LwtXmit,
            EbpfProgramType::LwtSeg6Local,
            EbpfProgramType::TcAction,
            EbpfProgramType::Tc,
            EbpfProgramType::Tcx,
            EbpfProgramType::Netkit,
            EbpfProgramType::CgroupDevice,
            EbpfProgramType::CgroupSkb,
            EbpfProgramType::CgroupSock,
            EbpfProgramType::CgroupSockAddr,
            EbpfProgramType::CgroupSockopt,
            EbpfProgramType::CgroupSysctl,
            EbpfProgramType::SkLookup,
            EbpfProgramType::SkMsg,
            EbpfProgramType::SkSkb,
            EbpfProgramType::SkSkbParser,
            EbpfProgramType::SkReuseport,
            EbpfProgramType::SockOps,
        ],
        label: "xdp, flow_dissector, netfilter, lirc_mode2, lwt_*, tc_action, tc, tcx, netkit, cgroup_device, cgroup_skb, cgroup_sock, cgroup_sock_addr, cgroup_sockopt, cgroup_sysctl, sk_lookup, sk_msg, sk_skb, sk_skb_parser, sk_reuseport, and sock_ops",
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
    HelperProgramSurfaceFamilySpec {
        family: HelperProgramSurfaceFamily::Syscall,
        program_types: &[EbpfProgramType::Syscall],
        label: "syscall",
    },
];

const GET_SOCKET_COOKIE_ARG_POLICY_SPECS: &[GetSocketCookieArgPolicySpec] = &[
    GetSocketCookieArgPolicySpec {
        policy: GetSocketCookieArgPolicy::Context,
        program_types: &[
            EbpfProgramType::SocketFilter,
            EbpfProgramType::TcAction,
            EbpfProgramType::Tc,
            EbpfProgramType::Tcx,
            EbpfProgramType::Netkit,
            EbpfProgramType::CgroupSkb,
            EbpfProgramType::CgroupSockAddr,
            EbpfProgramType::SockOps,
            EbpfProgramType::SkReuseport,
            EbpfProgramType::SkSkb,
            EbpfProgramType::SkSkbParser,
        ],
    },
    GetSocketCookieArgPolicySpec {
        policy: GetSocketCookieArgPolicy::ContextOrSocket,
        program_types: &[EbpfProgramType::CgroupSock],
    },
    GetSocketCookieArgPolicySpec {
        policy: GetSocketCookieArgPolicy::Socket,
        program_types: &[
            EbpfProgramType::Fentry,
            EbpfProgramType::Fexit,
            EbpfProgramType::FmodRet,
            EbpfProgramType::TpBtf,
        ],
    },
];

const SOCKET_REDIRECT_HELPER_SPECS: &[SocketRedirectHelperSpec] = &[
    SocketRedirectHelperSpec {
        map_kind: MapKind::SockMap,
        family: HelperProgramSurfaceFamily::SkMsg,
        helper: BpfHelper::MsgRedirectMap,
    },
    SocketRedirectHelperSpec {
        map_kind: MapKind::SockHash,
        family: HelperProgramSurfaceFamily::SkMsg,
        helper: BpfHelper::MsgRedirectHash,
    },
    SocketRedirectHelperSpec {
        map_kind: MapKind::SockMap,
        family: HelperProgramSurfaceFamily::SkSkb,
        helper: BpfHelper::SkRedirectMap,
    },
    SocketRedirectHelperSpec {
        map_kind: MapKind::SockHash,
        family: HelperProgramSurfaceFamily::SkSkb,
        helper: BpfHelper::SkRedirectHash,
    },
    SocketRedirectHelperSpec {
        map_kind: MapKind::ReuseportSockArray,
        family: HelperProgramSurfaceFamily::SkReuseport,
        helper: BpfHelper::SkSelectReuseport,
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

fn program_specific_helper_policy(
    program_type: EbpfProgramType,
) -> Option<ProgramSpecificHelperPolicy> {
    PROGRAM_SPECIFIC_HELPER_POLICIES
        .iter()
        .copied()
        .find(|policy| policy.program_type == program_type)
}

const TC_INGRESS_ONLY_HELPERS: &[BpfHelper] = &[BpfHelper::RedirectPeer, BpfHelper::SkAssign];
const TC_EGRESS_ONLY_HELPERS: &[BpfHelper] = &[
    BpfHelper::GetCgroupClassid,
    BpfHelper::GetRouteRealm,
    BpfHelper::SkbCgroupId,
    BpfHelper::SkbAncestorCgroupId,
];
const CGROUP_SOCK_ADDR_INET_CONNECT_ONLY_HELPERS: &[BpfHelper] = &[BpfHelper::Bind];
const CGROUP_RETVAL_HELPERS: &[BpfHelper] = &[BpfHelper::GetRetval, BpfHelper::SetRetval];
const SYSCALL_MODELED_HELPERS: &[BpfHelper] = &[
    BpfHelper::SysBpf,
    BpfHelper::BtfFindByNameKind,
    BpfHelper::SysClose,
    BpfHelper::KallsymsLookupName,
];
const PROGRAM_SPECIFIC_HELPER_POLICIES: &[ProgramSpecificHelperPolicy] =
    &[ProgramSpecificHelperPolicy {
        program_type: EbpfProgramType::Syscall,
        label: "syscall",
        modeled_helpers: SYSCALL_MODELED_HELPERS,
    }];
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
    HelperZeroArgRequirementSpec {
        helper: BpfHelper::SkAssign,
        program_type: EbpfProgramType::Tcx,
        arg_idx: 2,
        error_message: "helper 'bpf_sk_assign' requires arg2 = 0 in tcx programs",
    },
    HelperZeroArgRequirementSpec {
        helper: BpfHelper::CheckMtu,
        program_type: EbpfProgramType::Xdp,
        arg_idx: 4,
        error_message: "helper 'bpf_check_mtu' requires arg4 = 0 in xdp programs",
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
        BpfHelper::SetHash
        | BpfHelper::SkbVlanPush
        | BpfHelper::SkbVlanPop
        | BpfHelper::SkbAdjustRoom => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::TcSkSkb,
        },
        BpfHelper::SkbChangeTail
        | BpfHelper::SkbStoreBytes
        | BpfHelper::L3CsumReplace
        | BpfHelper::L4CsumReplace
        | BpfHelper::CloneRedirect
        | BpfHelper::CsumUpdate
        | BpfHelper::CsumLevel
        | BpfHelper::SetHashInvalid
        | BpfHelper::SkbChangeHead => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::TcSkSkbLwtXmit,
        },
        BpfHelper::GetHashRecalc | BpfHelper::SkbPullData => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::TcSkSkbLwt,
        },
        BpfHelper::SkbLoadBytes => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::SkbLoadBytes,
        },
        BpfHelper::SkbLoadBytesRelative => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::SkbLoadBytesRelative,
        },
        BpfHelper::CsumDiff => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::XdpTcLwt,
        },
        BpfHelper::CheckMtu => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::XdpTc,
        },
        BpfHelper::Redirect => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::XdpTcLwtXmit,
        },
        BpfHelper::RedirectPeer
        | BpfHelper::RedirectNeigh
        | BpfHelper::SkbChangeProto
        | BpfHelper::SkbChangeType
        | BpfHelper::SkbSetTstamp
        | BpfHelper::SkbGetXfrmState
        | BpfHelper::SkbCgroupClassid
        | BpfHelper::SkbCgroupId
        | BpfHelper::SkbAncestorCgroupId => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::Tc,
        },
        BpfHelper::SkbUnderCgroup | BpfHelper::GetCgroupClassid | BpfHelper::GetRouteRealm => {
            HelperProgramSurfaceSpec {
                family: HelperProgramSurfaceFamily::TcLwt,
            }
        }
        BpfHelper::SkbGetTunnelKey
        | BpfHelper::SkbSetTunnelKey
        | BpfHelper::SkbGetTunnelOpt
        | BpfHelper::SkbSetTunnelOpt => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::TcLwtXmit,
        },
        BpfHelper::LwtPushEncap => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::LwtInXmit,
        },
        BpfHelper::LwtSeg6StoreBytes | BpfHelper::LwtSeg6AdjustSrh | BpfHelper::LwtSeg6Action => {
            HelperProgramSurfaceSpec {
                family: HelperProgramSurfaceFamily::LwtSeg6Local,
            }
        }
        BpfHelper::PerfEventOutput => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::PerfEventOutput,
        },
        BpfHelper::PerfProgReadValue | BpfHelper::ReadBranchRecords => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::PerfEvent,
        },
        BpfHelper::GetStackId
        | BpfHelper::GetStack
        | BpfHelper::GetFuncIp
        | BpfHelper::GetAttachCookie
        | BpfHelper::SkbOutput
        | BpfHelper::XdpOutput => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::GetStackId,
        },
        BpfHelper::ProbeRead | BpfHelper::ProbeReadStr | BpfHelper::ProbeWriteUser => {
            HelperProgramSurfaceSpec {
                family: HelperProgramSurfaceFamily::LegacyProbeRead,
            }
        }
        BpfHelper::OverrideReturn => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::KprobeOverride,
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
        BpfHelper::TcpCheckSyncookie
        | BpfHelper::TcpGenSyncookie
        | BpfHelper::TcpRawGenSyncookieIpv4
        | BpfHelper::TcpRawGenSyncookieIpv6
        | BpfHelper::TcpRawCheckSyncookieIpv4
        | BpfHelper::TcpRawCheckSyncookieIpv6 => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::XdpTc,
        },
        BpfHelper::FibLookup => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::XdpTc,
        },
        BpfHelper::SkRelease => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::SocketRelease,
        },
        BpfHelper::SkAssign => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::TcSkLookup,
        },
        BpfHelper::SkbEcnSetCe | BpfHelper::GetListenerSock | BpfHelper::SkFullsock => {
            HelperProgramSurfaceSpec {
                family: HelperProgramSurfaceFamily::TcCgroupSkb,
            }
        }
        BpfHelper::TcpSock => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::TcpSock,
        },
        BpfHelper::TcpSendAck => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::TcpCongestionStructOps,
        },
        BpfHelper::SkcToTcpSock
        | BpfHelper::SkcToTcp6Sock
        | BpfHelper::SkcToTcpTimewaitSock
        | BpfHelper::SkcToTcpRequestSock
        | BpfHelper::SkcToUdp6Sock
        | BpfHelper::SkcToMptcpSock
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
        BpfHelper::BprmOptsSet
        | BpfHelper::ImaInodeHash
        | BpfHelper::ImaFileHash
        | BpfHelper::InodeStorageGet
        | BpfHelper::InodeStorageDelete => HelperProgramSurfaceSpec {
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
        BpfHelper::GetRetval | BpfHelper::SetRetval => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::CgroupRetval,
        },
        BpfHelper::GetLocalStorage => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::CgroupLocalStorage,
        },
        BpfHelper::SpinLock | BpfHelper::SpinUnlock => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::SpinLock,
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
        BpfHelper::SysBpf
        | BpfHelper::BtfFindByNameKind
        | BpfHelper::SysClose
        | BpfHelper::KallsymsLookupName => HelperProgramSurfaceSpec {
            family: HelperProgramSurfaceFamily::Syscall,
        },
        BpfHelper::SeqPrintf | BpfHelper::SeqWrite | BpfHelper::SeqPrintfBtf => {
            HelperProgramSurfaceSpec {
                family: HelperProgramSurfaceFamily::Iter,
            }
        }
        _ => return None,
    })
}

impl EbpfProgramType {
    pub(crate) fn helper_call_error(&self, helper: BpfHelper) -> Option<String> {
        if let Some(policy) = program_specific_helper_policy(*self) {
            if !helper_list_contains(policy.modeled_helpers, helper) {
                return Some(format!(
                    "helper '{}' is not modeled for {} programs",
                    helper.name(),
                    policy.label
                ));
            }
        }
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
        GET_SOCKET_COOKIE_ARG_POLICY_SPECS
            .iter()
            .find(|spec| spec.program_types.contains(self))
            .map(|spec| spec.policy)
    }

    pub(crate) fn packet_redirect_helper(&self) -> Option<BpfHelper> {
        if HelperProgramSurfaceFamily::XdpTcLwtXmit.allows(*self) {
            Some(BpfHelper::Redirect)
        } else {
            None
        }
    }

    pub(crate) fn cgroup_array_membership_helper(&self) -> BpfHelper {
        if HelperProgramSurfaceFamily::TcLwt.allows(*self) {
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
                } else if HelperProgramSurfaceFamily::TcSkSkbLwtXmit.allows(*self) {
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
                } else if HelperProgramSurfaceFamily::TcSkSkbLwtXmit.allows(*self) {
                    Some(BpfHelper::SkbChangeTail)
                } else {
                    None
                }
            }
            PacketAdjustMode::Pull => HelperProgramSurfaceFamily::TcSkSkbLwt
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
        SOCKET_REDIRECT_HELPER_SPECS
            .iter()
            .find(|spec| spec.map_kind == map_kind && spec.family.allows(*self))
            .map(|spec| spec.helper)
    }

    pub(crate) fn socket_redirect_error(&self, context: &str, map_kind: MapKind) -> Option<String> {
        if self.socket_redirect_helper(map_kind).is_some() {
            return None;
        }

        let message = if map_kind == MapKind::ReuseportSockArray
            && HelperProgramSurfaceFamily::SocketRedirectStream.allows(*self)
        {
            format!(
                "{context} --kind reuseport-sockarray is only valid in {} programs",
                HelperProgramSurfaceFamily::SkReuseport.label()
            )
        } else if matches!(map_kind, MapKind::SockMap | MapKind::SockHash)
            && HelperProgramSurfaceFamily::SkReuseport.allows(*self)
        {
            format!(
                "{context} --kind sockmap/sockhash is only valid in {} programs",
                HelperProgramSurfaceFamily::SocketRedirectStream.label()
            )
        } else {
            format!(
                "{context} is only valid in sk_msg, sk_skb, sk_skb_parser, and sk_reuseport programs"
            )
        };

        Some(message)
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
                    "helper '{}' is only valid in tc/tcx ingress programs",
                    helper.name()
                ))
            }
            _ if attach_shape.is_tc_ingress()
                && helper_list_contains(TC_EGRESS_ONLY_HELPERS, helper) =>
            {
                Some(format!(
                    "helper '{}' is only valid in tc/tcx egress programs",
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
            _ if attach_shape.cgroup_sock_addr().is_some_and(|(_, hook)| {
                matches!(
                    hook,
                    ProgramAttachSockAddrHook::RecvMsg
                        | ProgramAttachSockAddrHook::GetPeerName
                        | ProgramAttachSockAddrHook::GetSockName
                )
            }) && helper_list_contains(CGROUP_RETVAL_HELPERS, helper) =>
            {
                Some(format!(
                    "helper '{}' is not valid on cgroup_sock_addr recvmsg/getpeername/getsockname hooks",
                    helper.name()
                ))
            }
            _ if attach_shape
                .struct_ops_callback()
                .is_some_and(|(family, _)| family != StructOpsFamily::TcpCongestion)
                && helper_ids_equal(helper, BpfHelper::TcpSendAck) =>
            {
                Some(format!(
                    "helper '{}' is only valid in tcp_congestion_ops struct_ops programs",
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

    pub(crate) fn supports_intrinsic(&self, intrinsic: ProgramIntrinsic) -> bool {
        if !self.program_type().supports_intrinsic(intrinsic) {
            return false;
        }

        if intrinsic_has_backing_helpers(intrinsic) {
            !self.intrinsic_backing_helpers(intrinsic).is_empty()
        } else {
            true
        }
    }

    fn push_intrinsic_backing_helper(&self, helpers: &mut Vec<BpfHelper>, helper: BpfHelper) {
        if self.helper_call_error(helper).is_none() && !helpers.contains(&helper) {
            helpers.push(helper);
        }
    }

    fn push_local_storage_get_backing_helpers(&self, helpers: &mut Vec<BpfHelper>) {
        for helper in [
            BpfHelper::SkStorageGet,
            BpfHelper::InodeStorageGet,
            BpfHelper::TaskStorageGet,
            BpfHelper::CgrpStorageGet,
        ] {
            self.push_intrinsic_backing_helper(helpers, helper);
        }
    }

    fn push_local_storage_delete_backing_helpers(&self, helpers: &mut Vec<BpfHelper>) {
        for helper in [
            BpfHelper::SkStorageDelete,
            BpfHelper::InodeStorageDelete,
            BpfHelper::TaskStorageDelete,
            BpfHelper::CgrpStorageDelete,
        ] {
            self.push_intrinsic_backing_helper(helpers, helper);
        }
    }

    pub(crate) fn intrinsic_backing_helpers(&self, intrinsic: ProgramIntrinsic) -> Vec<BpfHelper> {
        let mut helpers = Vec::new();
        match intrinsic {
            ProgramIntrinsic::ReadStr => {
                self.push_intrinsic_backing_helper(&mut helpers, BpfHelper::ProbeReadUserStr);
            }
            ProgramIntrinsic::ReadKernelStr => {
                self.push_intrinsic_backing_helper(&mut helpers, BpfHelper::ProbeReadKernelStr);
            }
            ProgramIntrinsic::AdjustPacket => {
                for helper in [
                    PacketAdjustMode::Head,
                    PacketAdjustMode::Meta,
                    PacketAdjustMode::Tail,
                    PacketAdjustMode::Pull,
                    PacketAdjustMode::Room,
                ]
                .into_iter()
                .filter_map(|mode| self.program_type().packet_adjust_helper(mode))
                {
                    self.push_intrinsic_backing_helper(&mut helpers, helper);
                }
            }
            ProgramIntrinsic::AdjustMessage => {
                for helper in [
                    MessageAdjustMode::Apply,
                    MessageAdjustMode::Cork,
                    MessageAdjustMode::Pull,
                    MessageAdjustMode::Push,
                    MessageAdjustMode::Pop,
                ]
                .into_iter()
                .filter_map(|mode| self.program_type().message_adjust_helper(mode))
                {
                    self.push_intrinsic_backing_helper(&mut helpers, helper);
                }
            }
            ProgramIntrinsic::Redirect => {
                for helper in [
                    self.program_type().packet_redirect_helper(),
                    self.program_type().packet_redirect_peer_helper(),
                    self.program_type().packet_redirect_neigh_helper(),
                ]
                .into_iter()
                .flatten()
                {
                    self.push_intrinsic_backing_helper(&mut helpers, helper);
                }
            }
            ProgramIntrinsic::RedirectMap => {
                self.push_intrinsic_backing_helper(&mut helpers, BpfHelper::RedirectMap);
            }
            ProgramIntrinsic::RedirectSocket => {
                for helper in [
                    MapKind::SockMap,
                    MapKind::SockHash,
                    MapKind::ReuseportSockArray,
                ]
                .into_iter()
                .filter_map(|map_kind| self.program_type().socket_redirect_helper(map_kind))
                {
                    self.push_intrinsic_backing_helper(&mut helpers, helper);
                }
            }
            ProgramIntrinsic::AssignSocket => {
                self.push_intrinsic_backing_helper(&mut helpers, BpfHelper::SkAssign);
            }
            ProgramIntrinsic::TailCall => {
                self.push_intrinsic_backing_helper(&mut helpers, BpfHelper::TailCall);
            }
            ProgramIntrinsic::MapGet => {
                self.push_intrinsic_backing_helper(&mut helpers, BpfHelper::MapLookupElem);
                self.push_local_storage_get_backing_helpers(&mut helpers);
            }
            ProgramIntrinsic::MapContains => {
                self.push_intrinsic_backing_helper(&mut helpers, BpfHelper::MapLookupElem);
                self.push_intrinsic_backing_helper(&mut helpers, BpfHelper::MapPeekElem);
                self.push_intrinsic_backing_helper(
                    &mut helpers,
                    self.program_type().cgroup_array_membership_helper(),
                );
                self.push_local_storage_get_backing_helpers(&mut helpers);
            }
            ProgramIntrinsic::MapPut => {
                self.push_intrinsic_backing_helper(&mut helpers, BpfHelper::MapUpdateElem);
                for helper in [BpfHelper::SockMapUpdate, BpfHelper::SockHashUpdate] {
                    self.push_intrinsic_backing_helper(&mut helpers, helper);
                }
            }
            ProgramIntrinsic::MapDelete => {
                self.push_intrinsic_backing_helper(&mut helpers, BpfHelper::MapDeleteElem);
                self.push_local_storage_delete_backing_helpers(&mut helpers);
            }
            ProgramIntrinsic::MapPush => {
                self.push_intrinsic_backing_helper(&mut helpers, BpfHelper::MapPushElem);
            }
            ProgramIntrinsic::MapPeek => {
                self.push_intrinsic_backing_helper(&mut helpers, BpfHelper::MapPeekElem);
            }
            ProgramIntrinsic::MapPop => {
                self.push_intrinsic_backing_helper(&mut helpers, BpfHelper::MapPopElem);
            }
            _ => {}
        }
        helpers
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

fn intrinsic_has_backing_helpers(intrinsic: ProgramIntrinsic) -> bool {
    matches!(
        intrinsic,
        ProgramIntrinsic::ReadStr
            | ProgramIntrinsic::ReadKernelStr
            | ProgramIntrinsic::AdjustPacket
            | ProgramIntrinsic::AdjustMessage
            | ProgramIntrinsic::Redirect
            | ProgramIntrinsic::RedirectMap
            | ProgramIntrinsic::RedirectSocket
            | ProgramIntrinsic::AssignSocket
            | ProgramIntrinsic::TailCall
            | ProgramIntrinsic::MapGet
            | ProgramIntrinsic::MapPut
            | ProgramIntrinsic::MapDelete
            | ProgramIntrinsic::MapContains
            | ProgramIntrinsic::MapPush
            | ProgramIntrinsic::MapPeek
            | ProgramIntrinsic::MapPop
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn assert_unique_program_types(table_name: &str, program_types: &[EbpfProgramType]) {
        let mut seen = HashSet::new();

        for program_type in program_types {
            assert!(
                seen.insert(*program_type),
                "duplicate program type {program_type:?} in {table_name}"
            );
        }
    }

    fn assert_unique_helpers(table_name: &str, helpers: &[BpfHelper]) {
        let mut seen = HashSet::new();

        for helper in helpers {
            assert!(
                seen.insert(*helper as u32),
                "duplicate helper {} in {table_name}",
                helper.name()
            );
        }
    }

    #[test]
    fn test_program_spec_intrinsic_backing_helpers_are_attach_aware() {
        let xdp = crate::program_spec::ProgramSpec::parse("xdp:lo").expect("xdp spec should parse");
        assert_eq!(
            xdp.intrinsic_backing_helpers(ProgramIntrinsic::AdjustPacket),
            vec![
                BpfHelper::XdpAdjustHead,
                BpfHelper::XdpAdjustMeta,
                BpfHelper::XdpAdjustTail,
            ]
        );
        assert_eq!(
            xdp.intrinsic_backing_helpers(ProgramIntrinsic::Redirect),
            vec![BpfHelper::Redirect]
        );

        let tc_ingress = crate::program_spec::ProgramSpec::parse("tc:lo:ingress")
            .expect("tc ingress spec should parse");
        assert_eq!(
            tc_ingress.intrinsic_backing_helpers(ProgramIntrinsic::AdjustPacket),
            vec![
                BpfHelper::SkbChangeHead,
                BpfHelper::SkbChangeTail,
                BpfHelper::SkbPullData,
                BpfHelper::SkbAdjustRoom,
            ]
        );
        assert_eq!(
            tc_ingress.intrinsic_backing_helpers(ProgramIntrinsic::Redirect),
            vec![
                BpfHelper::Redirect,
                BpfHelper::RedirectPeer,
                BpfHelper::RedirectNeigh,
            ]
        );
        assert_eq!(
            tc_ingress.intrinsic_backing_helpers(ProgramIntrinsic::AssignSocket),
            vec![BpfHelper::SkAssign]
        );
        assert!(tc_ingress.supports_intrinsic(ProgramIntrinsic::AssignSocket));
        let tc_map_contains = tc_ingress.intrinsic_backing_helpers(ProgramIntrinsic::MapContains);
        assert!(tc_map_contains.contains(&BpfHelper::MapLookupElem));
        assert!(tc_map_contains.contains(&BpfHelper::MapPeekElem));
        assert!(tc_map_contains.contains(&BpfHelper::SkbUnderCgroup));
        assert!(tc_map_contains.contains(&BpfHelper::SkStorageGet));
        assert!(!tc_map_contains.contains(&BpfHelper::CurrentTaskUnderCgroup));

        let tc_egress = crate::program_spec::ProgramSpec::parse("tc:lo:egress")
            .expect("tc egress spec should parse");
        assert!(
            tc_egress
                .intrinsic_backing_helpers(ProgramIntrinsic::AssignSocket)
                .is_empty()
        );
        assert!(!tc_egress.supports_intrinsic(ProgramIntrinsic::AssignSocket));
        assert!(
            !tc_egress
                .intrinsic_backing_helpers(ProgramIntrinsic::Redirect)
                .contains(&BpfHelper::RedirectPeer)
        );

        let lwt_xmit = crate::program_spec::ProgramSpec::parse("lwt_xmit:demo-route")
            .expect("lwt_xmit spec should parse");
        assert_eq!(
            lwt_xmit.intrinsic_backing_helpers(ProgramIntrinsic::Redirect),
            vec![BpfHelper::Redirect]
        );

        let xdp_map_contains = xdp.intrinsic_backing_helpers(ProgramIntrinsic::MapContains);
        assert!(xdp_map_contains.contains(&BpfHelper::MapLookupElem));
        assert!(xdp_map_contains.contains(&BpfHelper::MapPeekElem));
        assert!(xdp_map_contains.contains(&BpfHelper::CurrentTaskUnderCgroup));
        assert!(!xdp_map_contains.contains(&BpfHelper::SkbUnderCgroup));

        let sock_ops = crate::program_spec::ProgramSpec::parse("sock_ops:/sys/fs/cgroup")
            .expect("sock_ops spec should parse");
        let sock_ops_map_put = sock_ops.intrinsic_backing_helpers(ProgramIntrinsic::MapPut);
        assert!(sock_ops_map_put.contains(&BpfHelper::MapUpdateElem));
        assert!(sock_ops_map_put.contains(&BpfHelper::SockMapUpdate));
        assert!(sock_ops_map_put.contains(&BpfHelper::SockHashUpdate));

        let sk_msg = crate::program_spec::ProgramSpec::parse("sk_msg:/sys/fs/bpf/demo_sockmap")
            .expect("sk_msg spec should parse");
        assert_eq!(
            sk_msg.intrinsic_backing_helpers(ProgramIntrinsic::RedirectSocket),
            vec![BpfHelper::MsgRedirectMap, BpfHelper::MsgRedirectHash]
        );
    }

    #[test]
    fn test_helper_program_surface_family_specs_are_unique() {
        let mut families = Vec::new();

        for spec in HELPER_PROGRAM_SURFACE_FAMILY_SPECS {
            assert!(
                !families.contains(&spec.family),
                "duplicate helper program surface family {:?}",
                spec.family
            );
            families.push(spec.family);
            assert!(
                !spec.label.is_empty(),
                "helper program surface family {:?} must have a diagnostic label",
                spec.family
            );
            assert_unique_program_types("helper program surface family", spec.program_types);
        }
    }

    #[test]
    fn test_helper_policy_tables_are_unique() {
        let mut socket_cookie_policy_programs = HashSet::new();
        let mut socket_cookie_policies = Vec::new();
        for spec in GET_SOCKET_COOKIE_ARG_POLICY_SPECS {
            assert!(
                !socket_cookie_policies.contains(&spec.policy),
                "duplicate socket-cookie arg policy {:?}",
                spec.policy
            );
            socket_cookie_policies.push(spec.policy);
            assert_unique_program_types("socket-cookie arg policy", spec.program_types);
            for program_type in spec.program_types {
                assert!(
                    socket_cookie_policy_programs.insert(*program_type),
                    "program type {program_type:?} appears in multiple socket-cookie arg policies"
                );
            }
        }

        let mut redirect_specs = Vec::new();
        for spec in SOCKET_REDIRECT_HELPER_SPECS {
            let key = (spec.map_kind, spec.family);
            assert!(
                !redirect_specs.contains(&key),
                "duplicate socket redirect spec for {:?} / {:?}",
                spec.map_kind,
                spec.family
            );
            redirect_specs.push(key);
        }

        let mut program_specific_policies = HashSet::new();
        for policy in PROGRAM_SPECIFIC_HELPER_POLICIES {
            assert!(
                program_specific_policies.insert(policy.program_type),
                "duplicate program-specific helper policy for {:?}",
                policy.program_type
            );
            assert!(
                !policy.label.is_empty(),
                "program-specific helper policy for {:?} must have a diagnostic label",
                policy.program_type
            );
            assert_unique_helpers("program-specific helper policy", policy.modeled_helpers);
        }

        let mut zero_arg_requirements = HashSet::new();
        for requirement in HELPER_ZERO_ARG_REQUIREMENTS {
            let key = (
                requirement.helper as u32,
                requirement.program_type,
                requirement.arg_idx,
            );
            assert!(
                zero_arg_requirements.insert(key),
                "duplicate zero-arg helper requirement for {} / {:?} arg{}",
                requirement.helper.name(),
                requirement.program_type,
                requirement.arg_idx
            );
            assert!(
                !requirement.error_message.is_empty(),
                "zero-arg helper requirement must have an error message"
            );
        }

        assert_unique_helpers("tc ingress-only helpers", TC_INGRESS_ONLY_HELPERS);
        assert_unique_helpers("tc egress-only helpers", TC_EGRESS_ONLY_HELPERS);
        assert_unique_helpers(
            "cgroup_sock_addr inet-connect-only helpers",
            CGROUP_SOCK_ADDR_INET_CONNECT_ONLY_HELPERS,
        );
        assert_unique_helpers("cgroup retval helpers", CGROUP_RETVAL_HELPERS);
        assert_unique_helpers("syscall modeled helpers", SYSCALL_MODELED_HELPERS);
    }
}
