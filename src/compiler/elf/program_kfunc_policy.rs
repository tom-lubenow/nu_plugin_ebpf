use crate::compiler::EbpfProgramType;
use crate::compiler::instruction::KfuncCompatibilityRequirement;
use crate::program_spec::{ProgramSpec, StructOpsFamily};

const LINUX_NET_CORE_FILTER_C_V6_4_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v6.4/net/core/filter.c";
const LINUX_NET_CORE_FILTER_C_V6_12_SOURCE: &str =
    "https://github.com/torvalds/linux/blob/v6.12/net/core/filter.c";

const SCHED_EXT_DISPATCH_ONLY_KFUNCS: &[&str] = &[
    "scx_bpf_dispatch_nr_slots",
    "scx_bpf_dsq_move_to_local",
    "scx_bpf_dispatch_cancel",
    "scx_bpf_dsq_move",
    "scx_bpf_dsq_move_vtime",
    "scx_bpf_dsq_move_set_slice",
    "scx_bpf_dsq_move_set_vtime",
];
const SCHED_EXT_CPU_RELEASE_ONLY_KFUNCS: &[&str] = &["scx_bpf_reenqueue_local"];
const SCHED_EXT_SELECT_CPU_OR_ENQUEUE_KFUNCS: &[&str] =
    &["scx_bpf_select_cpu_dfl", "scx_bpf_select_cpu_and"];
const SCHED_EXT_DISPATCH_SELECT_CPU_ENQUEUE_KFUNCS: &[&str] = &[
    "scx_bpf_dsq_insert",
    "scx_bpf_dsq_insert___v2",
    "scx_bpf_dsq_insert_vtime",
];
const XDP_ONLY_KFUNCS: &[&str] = &[
    "bpf_dynptr_from_xdp",
    "bpf_xdp_get_xfrm_state",
    "bpf_xdp_metadata_rx_hash",
    "bpf_xdp_metadata_rx_timestamp",
    "bpf_xdp_metadata_rx_vlan_tag",
    "bpf_xdp_xfrm_state_release",
];
const SKB_PACKET_DYNPTR_KFUNCS: &[&str] = &["bpf_dynptr_from_skb"];
const SKB_PACKET_DYNPTR_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::SocketFilter,
    EbpfProgramType::Netfilter,
    EbpfProgramType::LwtIn,
    EbpfProgramType::LwtOut,
    EbpfProgramType::LwtXmit,
    EbpfProgramType::LwtSeg6Local,
    EbpfProgramType::SkSkb,
    EbpfProgramType::SkSkbParser,
    EbpfProgramType::Tc,
    EbpfProgramType::Tcx,
    EbpfProgramType::Netkit,
    EbpfProgramType::TcAction,
    EbpfProgramType::CgroupSkb,
];
const SKB_RAW_CONTEXT_DYNPTR_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::SocketFilter,
    EbpfProgramType::LwtIn,
    EbpfProgramType::LwtOut,
    EbpfProgramType::LwtXmit,
    EbpfProgramType::LwtSeg6Local,
    EbpfProgramType::SkSkb,
    EbpfProgramType::SkSkbParser,
    EbpfProgramType::Tc,
    EbpfProgramType::Tcx,
    EbpfProgramType::Netkit,
    EbpfProgramType::TcAction,
    EbpfProgramType::CgroupSkb,
];
const SKB_TRACING_DYNPTR_PROGRAMS: &[EbpfProgramType] = &[
    EbpfProgramType::Fentry,
    EbpfProgramType::Fexit,
    EbpfProgramType::FmodRet,
    EbpfProgramType::TpBtf,
];
const SKB_DYNPTR_PROGRAM_LABEL: &str = "socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, sk_skb, sk_skb_parser, netfilter, fentry, fexit, fmod_ret, and tp_btf";
const SCHED_EXT_SLEEPABLE_ONLY_KFUNCS: &[&str] = &["scx_bpf_create_dsq"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProgramKfuncCallSurface {
    pub(crate) kfunc: &'static str,
    pub(crate) policy: &'static str,
    pub(crate) note: &'static str,
}

impl ProgramKfuncCallSurface {
    const fn new(kfunc: &'static str, policy: &'static str, note: &'static str) -> Self {
        Self {
            kfunc,
            policy,
            note,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ProgramSpecificKfuncPolicy {
    program_type: EbpfProgramType,
    label: &'static str,
    modeled_kfuncs: &'static [&'static str],
}

const PROGRAM_SPECIFIC_KFUNC_POLICIES: &[ProgramSpecificKfuncPolicy] = &[
    ProgramSpecificKfuncPolicy {
        program_type: EbpfProgramType::SockOps,
        label: "sock_ops",
        modeled_kfuncs: &["bpf_sock_ops_enable_tx_tstamp"],
    },
    ProgramSpecificKfuncPolicy {
        program_type: EbpfProgramType::CgroupSockAddr,
        label: "cgroup_sock_addr",
        modeled_kfuncs: &["bpf_sock_addr_set_sun_path"],
    },
];

fn program_specific_kfunc_policy(
    program_type: EbpfProgramType,
) -> Option<ProgramSpecificKfuncPolicy> {
    PROGRAM_SPECIFIC_KFUNC_POLICIES
        .iter()
        .copied()
        .find(|policy| policy.program_type == program_type)
}

fn modeled_kfunc_policy(kfunc: &str) -> Option<ProgramSpecificKfuncPolicy> {
    PROGRAM_SPECIFIC_KFUNC_POLICIES
        .iter()
        .copied()
        .find(|policy| policy.modeled_kfuncs.contains(&kfunc))
}

fn skb_packet_dynptr_kfunc_allowed(program_type: EbpfProgramType) -> bool {
    SKB_PACKET_DYNPTR_PROGRAMS.contains(&program_type)
}

fn skb_tracing_dynptr_kfunc_allowed(program_type: EbpfProgramType) -> bool {
    SKB_TRACING_DYNPTR_PROGRAMS.contains(&program_type)
}

fn skb_dynptr_kfunc_allowed(program_type: EbpfProgramType) -> bool {
    skb_packet_dynptr_kfunc_allowed(program_type) || skb_tracing_dynptr_kfunc_allowed(program_type)
}

impl EbpfProgramType {
    pub(crate) fn kfunc_arg_accepts_raw_skb_context(self, kfunc: &str, arg_idx: usize) -> bool {
        SKB_PACKET_DYNPTR_KFUNCS.contains(&kfunc)
            && arg_idx == 0
            && SKB_RAW_CONTEXT_DYNPTR_PROGRAMS.contains(&self)
    }
}

fn format_sched_ext_callback_list(callbacks: &[&str]) -> String {
    match callbacks {
        [] => String::new(),
        [only] => format!("sched_ext_ops.{only}"),
        [left, right] => format!("sched_ext_ops.{left} or sched_ext_ops.{right}"),
        _ => {
            let mut names = callbacks
                .iter()
                .map(|callback| format!("sched_ext_ops.{callback}"))
                .collect::<Vec<_>>();
            let last = names.pop().unwrap();
            format!("{}, or {}", names.join(", "), last)
        }
    }
}

fn sched_ext_kfunc_allowed_callbacks(kfunc: &str) -> Option<&'static [&'static str]> {
    if SCHED_EXT_DISPATCH_ONLY_KFUNCS.contains(&kfunc) {
        Some(&["dispatch"])
    } else if SCHED_EXT_CPU_RELEASE_ONLY_KFUNCS.contains(&kfunc) {
        Some(&["cpu_release"])
    } else if SCHED_EXT_SELECT_CPU_OR_ENQUEUE_KFUNCS.contains(&kfunc) {
        Some(&["select_cpu", "enqueue"])
    } else if SCHED_EXT_DISPATCH_SELECT_CPU_ENQUEUE_KFUNCS.contains(&kfunc) {
        Some(&["select_cpu", "enqueue", "dispatch"])
    } else {
        None
    }
}

fn push_program_kfunc_surfaces(
    surfaces: &mut Vec<ProgramKfuncCallSurface>,
    kfuncs: &'static [&'static str],
    policy: &'static str,
    note: &'static str,
) {
    surfaces.extend(
        kfuncs
            .iter()
            .map(|kfunc| ProgramKfuncCallSurface::new(kfunc, policy, note)),
    );
}

impl ProgramSpec {
    pub(crate) fn kfunc_call_surfaces_for_spec(&self) -> Vec<ProgramKfuncCallSurface> {
        let mut surfaces = Vec::new();

        if let Some(policy) = program_specific_kfunc_policy(self.program_type()) {
            push_program_kfunc_surfaces(
                &mut surfaces,
                policy.modeled_kfuncs,
                "program-specific",
                policy.label,
            );
        }

        if self.program_type() == EbpfProgramType::Xdp {
            push_program_kfunc_surfaces(&mut surfaces, XDP_ONLY_KFUNCS, "xdp-only", "xdp");
        }

        if skb_packet_dynptr_kfunc_allowed(self.program_type()) {
            push_program_kfunc_surfaces(
                &mut surfaces,
                SKB_PACKET_DYNPTR_KFUNCS,
                "skb-packet-dynptr",
                "skb-backed program",
            );
        }
        if skb_tracing_dynptr_kfunc_allowed(self.program_type()) {
            push_program_kfunc_surfaces(
                &mut surfaces,
                SKB_PACKET_DYNPTR_KFUNCS,
                "skb-tracing-dynptr",
                "tracing program with sk_buff argument",
            );
        }

        let Some((StructOpsFamily::SchedExt, sleepable)) =
            self.attach_shape().struct_ops_callback()
        else {
            return surfaces;
        };
        let Some(callback_name) = self.struct_ops_callback_name() else {
            return surfaces;
        };

        if sleepable {
            push_program_kfunc_surfaces(
                &mut surfaces,
                SCHED_EXT_SLEEPABLE_ONLY_KFUNCS,
                "sched-ext-sleepable-callback",
                "sleepable sched_ext_ops callback",
            );
        }

        for kfuncs in [
            SCHED_EXT_DISPATCH_ONLY_KFUNCS,
            SCHED_EXT_CPU_RELEASE_ONLY_KFUNCS,
            SCHED_EXT_SELECT_CPU_OR_ENQUEUE_KFUNCS,
            SCHED_EXT_DISPATCH_SELECT_CPU_ENQUEUE_KFUNCS,
        ] {
            for kfunc in kfuncs {
                if sched_ext_kfunc_allowed_callbacks(kfunc)
                    .is_some_and(|callbacks| callbacks.contains(&callback_name))
                {
                    surfaces.push(ProgramKfuncCallSurface::new(
                        kfunc,
                        "sched-ext-callback",
                        "current sched_ext_ops callback",
                    ));
                }
            }
        }

        surfaces
    }

    pub(crate) fn kfunc_call_error(&self, kfunc: &str) -> Option<String> {
        let program_policy = program_specific_kfunc_policy(self.program_type());
        if let Some(policy) = modeled_kfunc_policy(kfunc) {
            if self.program_type() != policy.program_type {
                return Some(format!(
                    "kfunc '{}' is only valid in {} programs",
                    kfunc, policy.label
                ));
            }
        }
        if let Some(policy) = program_policy {
            if !policy.modeled_kfuncs.contains(&kfunc) {
                return Some(format!(
                    "kfunc '{}' is not modeled for {} programs",
                    kfunc, policy.label
                ));
            }
            return None;
        }
        if XDP_ONLY_KFUNCS.contains(&kfunc) && self.program_type() != EbpfProgramType::Xdp {
            return Some(format!("kfunc '{}' is only valid in xdp programs", kfunc));
        }
        if SKB_PACKET_DYNPTR_KFUNCS.contains(&kfunc)
            && !skb_dynptr_kfunc_allowed(self.program_type())
        {
            return Some(format!(
                "kfunc '{}' is only valid in {} programs",
                kfunc, SKB_DYNPTR_PROGRAM_LABEL
            ));
        }

        let Some((StructOpsFamily::SchedExt, sleepable)) =
            self.attach_shape().struct_ops_callback()
        else {
            return None;
        };
        let callback_name = self.struct_ops_callback_name()?;

        if kfunc == "scx_bpf_create_dsq" && !sleepable {
            return Some(format!(
                "kfunc '{}' is only valid in sleepable sched_ext_ops callbacks, not sched_ext_ops.{}",
                kfunc, callback_name
            ));
        }

        let allowed_callbacks = sched_ext_kfunc_allowed_callbacks(kfunc)?;
        if allowed_callbacks.contains(&callback_name) {
            return None;
        }

        let allowed = format_sched_ext_callback_list(allowed_callbacks);
        Some(format!(
            "kfunc '{}' is only valid in {}, not sched_ext_ops.{}",
            kfunc, allowed, callback_name
        ))
    }

    pub(crate) fn kfunc_compatibility_requirement_for_name(
        &self,
        kfunc: &str,
    ) -> Option<KfuncCompatibilityRequirement> {
        let requirement = KfuncCompatibilityRequirement::for_name(kfunc)?;
        Some(match (kfunc, self.program_type()) {
            ("bpf_dynptr_from_skb", program_type)
                if SKB_PACKET_DYNPTR_PROGRAMS.contains(&program_type) =>
            {
                requirement.with_minimum_kernel("6.4", LINUX_NET_CORE_FILTER_C_V6_4_SOURCE)
            }
            ("bpf_dynptr_from_skb", program_type)
                if SKB_TRACING_DYNPTR_PROGRAMS.contains(&program_type) =>
            {
                requirement.with_minimum_kernel("6.12", LINUX_NET_CORE_FILTER_C_V6_12_SOURCE)
            }
            _ => requirement,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::instruction::{KfuncCompatibilityRequirement, KfuncSignature};
    use std::collections::HashSet;

    fn assert_unique_kfunc_names(table_name: &str, kfuncs: &[&'static str]) {
        let mut seen = HashSet::new();

        for kfunc in kfuncs {
            assert!(!kfunc.is_empty(), "empty kfunc name in {table_name}");
            assert!(
                seen.insert(*kfunc),
                "duplicate kfunc '{kfunc}' in {table_name}"
            );
        }
    }

    fn assert_supported_program_type(table_name: &str, program_type: EbpfProgramType) {
        assert!(
            EbpfProgramType::supported_program_types().contains(&program_type),
            "{program_type:?} in {table_name} must be a supported program type"
        );
    }

    fn assert_kfunc_has_static_metadata(table_name: &str, kfunc: &str) {
        assert!(
            KfuncSignature::for_name(kfunc).is_some(),
            "{table_name} kfunc '{kfunc}' must have a static signature before it is advertised by ebpf spec"
        );
        assert!(
            KfuncCompatibilityRequirement::for_name(kfunc).is_some(),
            "{table_name} kfunc '{kfunc}' must have source-backed compatibility metadata before it is advertised by ebpf spec"
        );
    }

    fn kfunc_surface_names(spec: &ProgramSpec) -> Vec<&'static str> {
        spec.kfunc_call_surfaces_for_spec()
            .into_iter()
            .map(|surface| surface.kfunc)
            .collect()
    }

    #[test]
    fn test_kfunc_policy_tables_are_unique() {
        let mut policy_program_types = HashSet::new();
        let mut modeled_kfuncs = HashSet::new();

        for policy in PROGRAM_SPECIFIC_KFUNC_POLICIES {
            assert_supported_program_type("program-specific kfunc policy", policy.program_type);
            assert!(
                policy_program_types.insert(policy.program_type),
                "duplicate program-specific kfunc policy for {:?}",
                policy.program_type
            );
            assert!(
                !policy.label.is_empty(),
                "program-specific kfunc policy for {:?} must have a diagnostic label",
                policy.program_type
            );
            assert_unique_kfunc_names("program-specific kfunc policy", policy.modeled_kfuncs);
            for kfunc in policy.modeled_kfuncs {
                assert!(
                    modeled_kfuncs.insert(*kfunc),
                    "kfunc '{kfunc}' appears in multiple program-specific policies"
                );
            }
        }

        assert_unique_kfunc_names("xdp-only kfuncs", XDP_ONLY_KFUNCS);
        for kfunc in XDP_ONLY_KFUNCS {
            assert!(
                !modeled_kfuncs.contains(kfunc),
                "kfunc '{kfunc}' appears in both xdp-only and program-specific policies"
            );
        }
        assert_unique_kfunc_names("skb packet dynptr kfuncs", SKB_PACKET_DYNPTR_KFUNCS);
        for kfunc in SKB_PACKET_DYNPTR_KFUNCS {
            assert!(
                !modeled_kfuncs.contains(kfunc),
                "kfunc '{kfunc}' appears in both skb packet dynptr and program-specific policies"
            );
            assert!(
                !XDP_ONLY_KFUNCS.contains(kfunc),
                "kfunc '{kfunc}' appears in both skb packet dynptr and xdp-only policies"
            );
        }
        assert!(!SKB_PACKET_DYNPTR_PROGRAMS.is_empty());
        let mut skb_dynptr_programs = HashSet::new();
        for program_type in SKB_PACKET_DYNPTR_PROGRAMS {
            assert_supported_program_type("skb packet dynptr program list", *program_type);
            assert!(
                skb_dynptr_programs.insert(*program_type),
                "duplicate skb packet dynptr program type {:?}",
                program_type
            );
        }
        assert!(!SKB_RAW_CONTEXT_DYNPTR_PROGRAMS.is_empty());
        let mut raw_skb_context_programs = HashSet::new();
        for program_type in SKB_RAW_CONTEXT_DYNPTR_PROGRAMS {
            assert_supported_program_type("raw skb context dynptr program list", *program_type);
            assert!(
                SKB_PACKET_DYNPTR_PROGRAMS.contains(program_type),
                "raw skb context program type {:?} must be an skb packet dynptr program",
                program_type
            );
            assert!(
                raw_skb_context_programs.insert(*program_type),
                "duplicate raw skb context dynptr program type {:?}",
                program_type
            );
        }
        assert!(
            !SKB_RAW_CONTEXT_DYNPTR_PROGRAMS.contains(&EbpfProgramType::Netfilter),
            "netfilter raw context is bpf_nf_ctx; bpf_dynptr_from_skb must use ctx.skb"
        );
        assert!(!SKB_TRACING_DYNPTR_PROGRAMS.is_empty());
        for program_type in SKB_TRACING_DYNPTR_PROGRAMS {
            assert_supported_program_type("skb tracing dynptr program list", *program_type);
            assert!(
                skb_dynptr_programs.insert(*program_type),
                "duplicate skb dynptr program type {:?}",
                program_type
            );
        }

        let mut sched_ext_kfuncs = HashSet::new();
        for (table_name, kfuncs) in [
            (
                "sched_ext dispatch-only kfuncs",
                SCHED_EXT_DISPATCH_ONLY_KFUNCS,
            ),
            (
                "sched_ext cpu-release-only kfuncs",
                SCHED_EXT_CPU_RELEASE_ONLY_KFUNCS,
            ),
            (
                "sched_ext select-cpu-or-enqueue kfuncs",
                SCHED_EXT_SELECT_CPU_OR_ENQUEUE_KFUNCS,
            ),
            (
                "sched_ext dispatch/select-cpu/enqueue kfuncs",
                SCHED_EXT_DISPATCH_SELECT_CPU_ENQUEUE_KFUNCS,
            ),
        ] {
            assert_unique_kfunc_names(table_name, kfuncs);
            for kfunc in kfuncs {
                assert!(
                    !modeled_kfuncs.contains(kfunc),
                    "kfunc '{kfunc}' appears in both sched_ext and program-specific policies"
                );
                assert!(
                    !XDP_ONLY_KFUNCS.contains(kfunc),
                    "kfunc '{kfunc}' appears in both sched_ext and xdp-only policies"
                );
                assert!(
                    !SKB_PACKET_DYNPTR_KFUNCS.contains(kfunc),
                    "kfunc '{kfunc}' appears in both sched_ext and skb packet dynptr policies"
                );
                assert!(
                    sched_ext_kfuncs.insert(*kfunc),
                    "sched_ext kfunc '{kfunc}' appears in multiple callback policy tables"
                );
                assert!(
                    sched_ext_kfunc_allowed_callbacks(kfunc)
                        .is_some_and(|callbacks| !callbacks.is_empty()),
                    "sched_ext kfunc '{kfunc}' must resolve to at least one allowed callback"
                );
            }
        }

        assert_unique_kfunc_names(
            "sched_ext sleepable-only kfuncs",
            SCHED_EXT_SLEEPABLE_ONLY_KFUNCS,
        );
        for kfunc in SCHED_EXT_SLEEPABLE_ONLY_KFUNCS {
            assert!(
                !modeled_kfuncs.contains(kfunc),
                "kfunc '{kfunc}' appears in both sched_ext and program-specific policies"
            );
            assert!(
                !XDP_ONLY_KFUNCS.contains(kfunc),
                "kfunc '{kfunc}' appears in both sched_ext and xdp-only policies"
            );
            assert!(
                !SKB_PACKET_DYNPTR_KFUNCS.contains(kfunc),
                "kfunc '{kfunc}' appears in both sched_ext and skb packet dynptr policies"
            );
            assert!(
                sched_ext_kfuncs.insert(*kfunc),
                "sched_ext kfunc '{kfunc}' appears in multiple callback policy tables"
            );
        }
    }

    #[test]
    fn test_advertised_kfunc_call_surfaces_have_static_metadata() {
        for policy in PROGRAM_SPECIFIC_KFUNC_POLICIES {
            for kfunc in policy.modeled_kfuncs {
                assert_kfunc_has_static_metadata("program-specific kfunc policy", kfunc);
            }
        }

        for (table_name, kfuncs) in [
            ("xdp-only kfuncs", XDP_ONLY_KFUNCS),
            ("skb packet dynptr kfuncs", SKB_PACKET_DYNPTR_KFUNCS),
            ("skb tracing dynptr kfuncs", SKB_PACKET_DYNPTR_KFUNCS),
            (
                "sched_ext dispatch-only kfuncs",
                SCHED_EXT_DISPATCH_ONLY_KFUNCS,
            ),
            (
                "sched_ext cpu-release-only kfuncs",
                SCHED_EXT_CPU_RELEASE_ONLY_KFUNCS,
            ),
            (
                "sched_ext select-cpu-or-enqueue kfuncs",
                SCHED_EXT_SELECT_CPU_OR_ENQUEUE_KFUNCS,
            ),
            (
                "sched_ext dispatch/select-cpu/enqueue kfuncs",
                SCHED_EXT_DISPATCH_SELECT_CPU_ENQUEUE_KFUNCS,
            ),
            (
                "sched_ext sleepable-only kfuncs",
                SCHED_EXT_SLEEPABLE_ONLY_KFUNCS,
            ),
        ] {
            for kfunc in kfuncs {
                assert_kfunc_has_static_metadata(table_name, kfunc);
            }
        }
    }

    #[test]
    fn test_advertised_kfunc_call_surfaces_are_accepted_by_same_spec_policy() {
        for spec_source in [
            "xdp:lo",
            "tc:lo:ingress",
            "fentry:tcp_sendmsg",
            "sock_ops:/sys/fs/cgroup",
            "cgroup_sock_addr:/sys/fs/cgroup:connect_unix",
            "struct_ops:sched_ext_ops.dispatch",
            "struct_ops:sched_ext_ops.init",
            "struct_ops:sched_ext_ops.select_cpu",
        ] {
            let spec = ProgramSpec::parse(spec_source)
                .unwrap_or_else(|err| panic!("{spec_source} should parse: {err}"));
            for surface in spec.kfunc_call_surfaces_for_spec() {
                assert_eq!(
                    spec.kfunc_call_error(surface.kfunc),
                    None,
                    "{spec_source} advertises kfunc '{}' but rejects it through kfunc_call_error",
                    surface.kfunc
                );
                assert!(
                    !surface.policy.is_empty(),
                    "{spec_source} kfunc '{}' should report a non-empty policy label",
                    surface.kfunc
                );
                assert!(
                    !surface.note.is_empty(),
                    "{spec_source} kfunc '{}' should report a non-empty policy note",
                    surface.kfunc
                );
            }
        }
    }

    #[test]
    fn test_struct_ops_callback_program_spec_kfunc_policy_uses_sched_ext_callback_rules() {
        let dispatch = ProgramSpec::StructOpsCallback {
            value_type_name: "sched_ext_ops".to_string(),
            callback_name: "dispatch".to_string(),
        };
        let init = ProgramSpec::StructOpsCallback {
            value_type_name: "sched_ext_ops".to_string(),
            callback_name: "init".to_string(),
        };
        let select_cpu = ProgramSpec::StructOpsCallback {
            value_type_name: "sched_ext_ops".to_string(),
            callback_name: "select_cpu".to_string(),
        };

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
    fn test_struct_ops_callback_program_spec_kfunc_policy_ignores_non_sched_ext_families() {
        let tcp_congestion = ProgramSpec::StructOpsCallback {
            value_type_name: "tcp_congestion_ops".to_string(),
            callback_name: "cong_avoid".to_string(),
        };

        assert_eq!(tcp_congestion.kfunc_call_error("scx_bpf_create_dsq"), None);
        assert_eq!(
            tcp_congestion.kfunc_call_error("scx_bpf_dispatch_nr_slots"),
            None
        );
    }

    #[test]
    fn test_program_spec_kfunc_policy_limits_sock_addr_set_sun_path_to_sock_addr() {
        let sock_addr = ProgramSpec::parse("cgroup_sock_addr:/sys/fs/cgroup:connect_unix")
            .expect("expected cgroup_sock_addr unix spec");
        assert_eq!(
            sock_addr.kfunc_call_error("bpf_sock_addr_set_sun_path"),
            None
        );

        let xdp = ProgramSpec::from_program_type_target(EbpfProgramType::Xdp, "lo")
            .expect("expected xdp spec");
        assert_eq!(
            xdp.kfunc_call_error("bpf_sock_addr_set_sun_path"),
            Some(
                "kfunc 'bpf_sock_addr_set_sun_path' is only valid in cgroup_sock_addr programs"
                    .to_string()
            )
        );
        assert_eq!(
            sock_addr.kfunc_call_error("bpf_task_from_pid"),
            Some(
                "kfunc 'bpf_task_from_pid' is not modeled for cgroup_sock_addr programs"
                    .to_string()
            )
        );
    }

    #[test]
    fn test_program_spec_kfunc_policy_limits_enable_tx_tstamp_to_sock_ops() {
        let sock_ops =
            ProgramSpec::from_program_type_target(EbpfProgramType::SockOps, "/sys/fs/cgroup")
                .expect("expected sock_ops spec");
        assert_eq!(
            sock_ops.kfunc_call_error("bpf_sock_ops_enable_tx_tstamp"),
            None
        );

        let xdp = ProgramSpec::from_program_type_target(EbpfProgramType::Xdp, "lo")
            .expect("expected xdp spec");
        assert_eq!(
            xdp.kfunc_call_error("bpf_sock_ops_enable_tx_tstamp"),
            Some(
                "kfunc 'bpf_sock_ops_enable_tx_tstamp' is only valid in sock_ops programs"
                    .to_string()
            )
        );
        assert_eq!(
            sock_ops.kfunc_call_error("bpf_task_from_pid"),
            Some("kfunc 'bpf_task_from_pid' is not modeled for sock_ops programs".to_string())
        );
    }

    #[test]
    fn test_program_spec_kfunc_policy_leaves_generic_kfuncs_to_broad_surfaces() {
        let xdp = ProgramSpec::from_program_type_target(EbpfProgramType::Xdp, "lo")
            .expect("expected xdp spec");
        let tc = ProgramSpec::from_program_type_target(EbpfProgramType::Tc, "lo:ingress")
            .expect("expected tc spec");

        assert_eq!(xdp.kfunc_call_error("bpf_task_from_pid"), None);
        assert_eq!(tc.kfunc_call_error("bpf_task_from_pid"), None);
    }

    #[test]
    fn test_program_specific_kfunc_policy_is_table_driven() {
        assert_eq!(
            modeled_kfunc_policy("bpf_sock_ops_enable_tx_tstamp").map(|policy| policy.program_type),
            Some(EbpfProgramType::SockOps)
        );
        assert_eq!(
            modeled_kfunc_policy("bpf_sock_addr_set_sun_path").map(|policy| policy.program_type),
            Some(EbpfProgramType::CgroupSockAddr)
        );
        assert_eq!(
            program_specific_kfunc_policy(EbpfProgramType::SockOps)
                .map(|policy| policy.modeled_kfuncs),
            Some(&["bpf_sock_ops_enable_tx_tstamp"][..])
        );
        assert!(program_specific_kfunc_policy(EbpfProgramType::Xdp).is_none());
    }

    #[test]
    fn test_program_spec_kfunc_call_surfaces_are_program_aware() {
        let xdp = ProgramSpec::from_program_type_target(EbpfProgramType::Xdp, "lo")
            .expect("expected xdp spec");
        let xdp_kfuncs = kfunc_surface_names(&xdp);
        assert_eq!(
            xdp_kfuncs,
            vec![
                "bpf_dynptr_from_xdp",
                "bpf_xdp_get_xfrm_state",
                "bpf_xdp_metadata_rx_hash",
                "bpf_xdp_metadata_rx_timestamp",
                "bpf_xdp_metadata_rx_vlan_tag",
                "bpf_xdp_xfrm_state_release",
            ]
        );

        let tc = ProgramSpec::from_program_type_target(EbpfProgramType::Tc, "lo:ingress")
            .expect("expected tc spec");
        assert_eq!(kfunc_surface_names(&tc), vec!["bpf_dynptr_from_skb"]);

        let fentry = ProgramSpec::from_program_type_target(EbpfProgramType::Fentry, "tcp_sendmsg")
            .expect("expected fentry spec");
        assert_eq!(kfunc_surface_names(&fentry), vec!["bpf_dynptr_from_skb"]);

        let sock_ops =
            ProgramSpec::from_program_type_target(EbpfProgramType::SockOps, "/sys/fs/cgroup")
                .expect("expected sock_ops spec");
        assert_eq!(
            kfunc_surface_names(&sock_ops),
            vec!["bpf_sock_ops_enable_tx_tstamp"]
        );
    }

    #[test]
    fn test_program_spec_kfunc_call_surfaces_follow_sched_ext_callbacks() {
        let dispatch = ProgramSpec::StructOpsCallback {
            value_type_name: "sched_ext_ops".to_string(),
            callback_name: "dispatch".to_string(),
        };
        let dispatch_kfuncs = kfunc_surface_names(&dispatch);
        assert!(dispatch_kfuncs.contains(&"scx_bpf_dispatch_nr_slots"));
        assert!(dispatch_kfuncs.contains(&"scx_bpf_dsq_insert"));
        assert!(!dispatch_kfuncs.contains(&"scx_bpf_create_dsq"));

        let init = ProgramSpec::StructOpsCallback {
            value_type_name: "sched_ext_ops".to_string(),
            callback_name: "init".to_string(),
        };
        assert_eq!(kfunc_surface_names(&init), vec!["scx_bpf_create_dsq"]);

        let select_cpu = ProgramSpec::StructOpsCallback {
            value_type_name: "sched_ext_ops".to_string(),
            callback_name: "select_cpu".to_string(),
        };
        let select_cpu_kfuncs = kfunc_surface_names(&select_cpu);
        assert!(select_cpu_kfuncs.contains(&"scx_bpf_select_cpu_dfl"));
        assert!(select_cpu_kfuncs.contains(&"scx_bpf_dsq_insert"));
        assert!(!select_cpu_kfuncs.contains(&"scx_bpf_dispatch_nr_slots"));
    }

    #[test]
    fn test_program_spec_kfunc_policy_limits_xdp_kfuncs_to_xdp() {
        let xdp = ProgramSpec::from_program_type_target(EbpfProgramType::Xdp, "lo")
            .expect("expected xdp spec");
        assert_eq!(xdp.kfunc_call_error("bpf_dynptr_from_xdp"), None);
        assert_eq!(xdp.kfunc_call_error("bpf_xdp_metadata_rx_hash"), None);
        assert_eq!(xdp.kfunc_call_error("bpf_xdp_get_xfrm_state"), None);

        let tc = ProgramSpec::from_program_type_target(EbpfProgramType::Tc, "lo:ingress")
            .expect("expected tc spec");
        assert_eq!(
            tc.kfunc_call_error("bpf_xdp_metadata_rx_hash"),
            Some("kfunc 'bpf_xdp_metadata_rx_hash' is only valid in xdp programs".to_string())
        );
        assert_eq!(
            tc.kfunc_call_error("bpf_xdp_get_xfrm_state"),
            Some("kfunc 'bpf_xdp_get_xfrm_state' is only valid in xdp programs".to_string())
        );
        assert_eq!(
            tc.kfunc_call_error("bpf_dynptr_from_xdp"),
            Some("kfunc 'bpf_dynptr_from_xdp' is only valid in xdp programs".to_string())
        );
    }

    #[test]
    fn test_program_spec_kfunc_policy_limits_skb_dynptr_to_skb_programs() {
        for (program_type, target) in [
            (EbpfProgramType::SocketFilter, "tcp4:127.0.0.1:8080"),
            (
                EbpfProgramType::Netfilter,
                "ipv4:pre_routing:priority=-100:defrag",
            ),
            (EbpfProgramType::LwtIn, "demo-route"),
            (EbpfProgramType::LwtOut, "demo-route"),
            (EbpfProgramType::LwtXmit, "demo-route"),
            (EbpfProgramType::LwtSeg6Local, "demo-route"),
            (EbpfProgramType::SkSkb, "/sys/fs/bpf/demo_sockmap"),
            (EbpfProgramType::SkSkbParser, "/sys/fs/bpf/demo_sockmap"),
            (EbpfProgramType::Tc, "lo:ingress"),
            (EbpfProgramType::Tcx, "lo:ingress"),
            (EbpfProgramType::Netkit, "nk0:primary"),
            (EbpfProgramType::TcAction, "demo-action"),
            (EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:egress"),
            (EbpfProgramType::Fentry, "tcp_sendmsg"),
            (EbpfProgramType::Fexit, "tcp_sendmsg"),
            (EbpfProgramType::FmodRet, "tcp_sendmsg"),
            (EbpfProgramType::TpBtf, "sys_enter"),
        ] {
            let spec = ProgramSpec::from_program_type_target(program_type, target)
                .unwrap_or_else(|err| panic!("expected {program_type:?} spec: {err}"));
            assert_eq!(spec.kfunc_call_error("bpf_dynptr_from_skb"), None);
            assert!(
                kfunc_surface_names(&spec).contains(&"bpf_dynptr_from_skb"),
                "{program_type:?} should advertise bpf_dynptr_from_skb"
            );
        }

        for (program_type, target) in [
            (EbpfProgramType::Xdp, "lo"),
            (EbpfProgramType::RawTracepoint, "sys_enter"),
        ] {
            let spec = ProgramSpec::from_program_type_target(program_type, target)
                .unwrap_or_else(|err| panic!("expected {program_type:?} spec: {err}"));
            assert_eq!(
                spec.kfunc_call_error("bpf_dynptr_from_skb"),
                Some(format!(
                    "kfunc 'bpf_dynptr_from_skb' is only valid in {} programs",
                    SKB_DYNPTR_PROGRAM_LABEL
                ))
            );
            assert!(
                !kfunc_surface_names(&spec).contains(&"bpf_dynptr_from_skb"),
                "{program_type:?} should not advertise bpf_dynptr_from_skb"
            );
        }
    }

    #[test]
    fn test_skb_dynptr_raw_context_arg_policy_excludes_indirect_skb_programs() {
        assert!(EbpfProgramType::Tc.kfunc_arg_accepts_raw_skb_context("bpf_dynptr_from_skb", 0));
        assert!(!EbpfProgramType::Tc.kfunc_arg_accepts_raw_skb_context("bpf_dynptr_from_skb", 1));
        assert!(!EbpfProgramType::Xdp.kfunc_arg_accepts_raw_skb_context("bpf_dynptr_from_skb", 0));

        for program_type in [
            EbpfProgramType::Netfilter,
            EbpfProgramType::Fentry,
            EbpfProgramType::Fexit,
            EbpfProgramType::FmodRet,
            EbpfProgramType::TpBtf,
        ] {
            assert!(
                !program_type.kfunc_arg_accepts_raw_skb_context("bpf_dynptr_from_skb", 0),
                "{program_type:?} must pass an explicit sk_buff pointer, not raw ctx"
            );
        }
    }

    #[test]
    fn test_program_spec_kfunc_compatibility_requirement_is_program_specific() {
        let tc = ProgramSpec::from_program_type_target(EbpfProgramType::Tc, "lo:ingress")
            .expect("expected tc spec");
        let tc_requirement = tc
            .kfunc_compatibility_requirement_for_name("bpf_dynptr_from_skb")
            .expect("expected tc skb dynptr compatibility metadata");
        assert_eq!(tc_requirement.name(), "bpf_dynptr_from_skb");
        assert_eq!(tc_requirement.key(), "kfunc:bpf_dynptr_from_skb");
        assert_eq!(tc_requirement.minimum_kernel(), "6.4");
        assert!(
            tc_requirement
                .minimum_kernel_source()
                .contains("/v6.4/net/core/filter.c")
        );

        let fentry = ProgramSpec::from_program_type_target(EbpfProgramType::Fentry, "tcp_sendmsg")
            .expect("expected fentry spec");
        let fentry_requirement = fentry
            .kfunc_compatibility_requirement_for_name("bpf_dynptr_from_skb")
            .expect("expected tracing skb dynptr compatibility metadata");
        assert_eq!(fentry_requirement.name(), "bpf_dynptr_from_skb");
        assert_eq!(fentry_requirement.key(), "kfunc:bpf_dynptr_from_skb");
        assert_eq!(fentry_requirement.minimum_kernel(), "6.12");
        assert!(
            fentry_requirement
                .minimum_kernel_source()
                .contains("/v6.12/net/core/filter.c")
        );
    }
}
