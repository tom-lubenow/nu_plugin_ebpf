use crate::program_spec::{ProgramSpec, struct_ops_callback_is_sleepable};

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
        let ProgramSpec::StructOpsCallback {
            value_type_name,
            callback_name,
        } = self
        else {
            return None;
        };

        if value_type_name != "sched_ext_ops" {
            return None;
        }

        if kfunc == "scx_bpf_create_dsq"
            && !struct_ops_callback_is_sleepable(value_type_name, callback_name)
        {
            return Some(format!(
                "kfunc '{}' is only valid in sleepable sched_ext_ops callbacks, not sched_ext_ops.{}",
                kfunc, callback_name
            ));
        }

        let allowed_callbacks = sched_ext_kfunc_allowed_callbacks(kfunc)?;
        if allowed_callbacks.contains(&callback_name.as_str()) {
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
}
