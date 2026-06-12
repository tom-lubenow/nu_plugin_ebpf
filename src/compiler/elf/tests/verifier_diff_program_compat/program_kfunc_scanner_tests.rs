use super::*;

#[test]
fn test_verifier_diff_program_kfunc_scanner_matches_rust_kfunc_keys() {
    struct KfuncScannerCheck {
        target: &'static str,
        program: &'static str,
        expected_keys: BTreeSet<String>,
    }

    let checks = [
        KfuncScannerCheck {
            target: "raw_tracepoint:sys_enter",
            program: r#"{|ctx|
  let text = "kfunc-call \"bpf_task_from_pid\" 1"
  # kfunc-call "bpf_task_from_pid" 1
  let ignored = 0 # | kfunc-call "bpf_task_from_pid" 1
  0
}"#,
            expected_keys: BTreeSet::new(),
        },
        KfuncScannerCheck {
            target: "raw_tracepoint:sys_enter",
            program: r#"{|ctx|
  kfunc-call "bpf_rcu_read_lock"
  kfunc-call "bpf_rcu_read_unlock"
  0
}"#,
            expected_keys: kfunc_feature_keys_for_target(
                "raw_tracepoint:sys_enter",
                ["bpf_rcu_read_lock", "bpf_rcu_read_unlock"],
            ),
        },
        KfuncScannerCheck {
            target: "raw_tracepoint:sys_enter",
            program: r#"{|ctx|
  kfunc-call "bpf_preempt_disable"
  kfunc-call "bpf_preempt_enable"
  0
}"#,
            expected_keys: kfunc_feature_keys_for_target(
                "raw_tracepoint:sys_enter",
                ["bpf_preempt_disable", "bpf_preempt_enable"],
            ),
        },
        KfuncScannerCheck {
            target: "raw_tracepoint:sys_enter",
            program: r#"{|ctx|
  let flags = "00000000"
  kfunc-call "bpf_local_irq_save" $flags
  kfunc-call "bpf_local_irq_restore" $flags
  0
}"#,
            expected_keys: kfunc_feature_keys_for_target(
                "raw_tracepoint:sys_enter",
                ["bpf_local_irq_save", "bpf_local_irq_restore"],
            ),
        },
        KfuncScannerCheck {
            target: "raw_tracepoint:sys_enter",
            program: r#"{|ctx|
  let flags = "00000000"
  kfunc-call "bpf_res_spin_lock" $ctx.current_task
  kfunc-call "bpf_res_spin_unlock" $ctx.current_task
  kfunc-call "bpf_res_spin_lock_irqsave" $ctx.current_task $flags
  kfunc-call "bpf_res_spin_unlock_irqrestore" $ctx.current_task $flags
  0
}"#,
            expected_keys: kfunc_feature_keys_for_target(
                "raw_tracepoint:sys_enter",
                [
                    "bpf_res_spin_lock",
                    "bpf_res_spin_unlock",
                    "bpf_res_spin_lock_irqsave",
                    "bpf_res_spin_unlock_irqrestore",
                ],
            ),
        },
        KfuncScannerCheck {
            target: "tc:lo:ingress",
            program: r#"{|ctx|
  let d = "0123456789abcdef"
  kfunc-call "bpf_dynptr_from_skb" $ctx 0 $d
  0
}"#,
            expected_keys: kfunc_feature_keys_for_target("tc:lo:ingress", ["bpf_dynptr_from_skb"]),
        },
        KfuncScannerCheck {
            target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix",
            program: r#"{|ctx|
  $ctx.sun_path = "/tmp/nu-ebpf.sock"
  "allow"
}"#,
            expected_keys: kfunc_feature_keys_for_target(
                "cgroup_sock_addr:/sys/fs/cgroup:connect_unix",
                ["bpf_sock_addr_set_sun_path"],
            ),
        },
    ];

    let nu_checks = checks
        .iter()
        .map(|check| (check.target.to_string(), check.program.to_string()))
        .collect::<Vec<_>>();
    let Some(actual) = verifier_diff_nu_program_kfunc_feature_keys(&nu_checks) else {
        return;
    };

    let mut mismatches = Vec::new();
    for (index, (check, actual_keys)) in checks.iter().zip(actual.iter()).enumerate() {
        if &check.expected_keys != actual_keys {
            mismatches.push(format!(
                "#{} {} expected {:?} actual {:?}",
                index, check.target, check.expected_keys, actual_keys
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "scripts/verifier_diff.nu program-kfunc scanner drifted from Rust kfunc metadata: {}",
        mismatches.join(", ")
    );
}
