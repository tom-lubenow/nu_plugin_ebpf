use crate::compiler::EbpfProgramType;
use crate::program_spec::{ProgramSpec, StructOpsFamily};

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
const SCHED_EXT_DISPATCH_SELECT_CPU_ENQUEUE_KFUNCS: &[&str] =
    &["scx_bpf_dsq_insert", "scx_bpf_dsq_insert_vtime"];

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

impl ProgramSpec {
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
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn test_kfunc_policy_tables_are_unique() {
        let mut policy_program_types = HashSet::new();
        let mut modeled_kfuncs = HashSet::new();

        for policy in PROGRAM_SPECIFIC_KFUNC_POLICIES {
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
}
