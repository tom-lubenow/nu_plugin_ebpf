use super::*;

#[test]
fn test_verifier_diff_program_surface_scanner_matches_rust_helper_keys() {
    struct SurfaceScannerCheck {
        target: &'static str,
        program: &'static str,
        expected_keys: BTreeSet<String>,
    }

    let sk_lookup_spec = ProgramSpec::parse("sk_lookup:/proc/self/ns/net")
        .unwrap_or_else(|err| panic!("sk_lookup spec should parse: {err}"));
    let sk_lookup_ctx_sk = ContextFieldCompatibilityRequirement::for_field_on_program_spec(
        &CtxField::Socket,
        &sk_lookup_spec,
    )
    .expect("sk_lookup ctx.sk should carry compatibility metadata")
    .key();

    let mut checks = vec![
        SurfaceScannerCheck {
            target: "raw_tracepoint:sys_enter",
            program: r#"{|ctx|
  tail-call progs 0
  random int
  read-str 0 8
  read-kernel-str 0 8
  emit events { pid: 1 }
  count counts 0
  histogram latency 1
  start-timer timers 0
  stop-timer timers 0
  0
}"#,
            expected_keys: helper_feature_keys([
                BpfHelper::TailCall,
                BpfHelper::GetPrandomU32,
                BpfHelper::ProbeReadUserStr,
                BpfHelper::ProbeReadKernelStr,
                BpfHelper::RingbufOutput,
                BpfHelper::MapLookupElem,
                BpfHelper::MapUpdateElem,
                BpfHelper::GetCurrentPidTgid,
                BpfHelper::KtimeGetNs,
                BpfHelper::MapDeleteElem,
            ]),
        },
        SurfaceScannerCheck {
            target: "raw_tracepoint:sys_enter",
            program: r#"{|ctx|
  map-get counts 0 --kind hash
  map-put counts 0 1 --kind hash
  map-delete counts 0 --kind hash
  map-push queue 1 --kind queue
  map-peek queue --kind queue
  map-pop queue --kind queue
  map-contains bloom 1 --kind bloom-filter
  redirect-map devmap 0
  adjust-packet --pull 0
  0
}"#,
            expected_keys: helper_feature_keys([
                BpfHelper::MapLookupElem,
                BpfHelper::MapUpdateElem,
                BpfHelper::MapDeleteElem,
                BpfHelper::MapPushElem,
                BpfHelper::MapPeekElem,
                BpfHelper::MapPopElem,
                BpfHelper::RedirectMap,
                BpfHelper::SkbPullData,
            ]),
        },
        SurfaceScannerCheck {
            target: "sk_msg:/sys/fs/bpf/demo_sockmap",
            program: r#"{|ctx|
  adjust-message --apply 8
  adjust-message --cork 8
  adjust-message --pull 0 1
  adjust-message --push 0 1
  adjust-message --pop 0 1
  redirect-socket peers 0 --kind sockhash
  0
}"#,
            expected_keys: helper_feature_keys([
                BpfHelper::MsgApplyBytes,
                BpfHelper::MsgCorkBytes,
                BpfHelper::MsgPullData,
                BpfHelper::MsgPushData,
                BpfHelper::MsgPopData,
                BpfHelper::MsgRedirectHash,
            ]),
        },
        SurfaceScannerCheck {
            target: "sk_msg:/sys/fs/bpf/demo_sockmap",
            program: r#"{|ctx|
  helper-call "bpf_msg_redirect_hash" $ctx hash_peers "peer-a" 0
  redirect-socket hash_peers "peer-b"
  0
}"#,
            expected_keys: helper_feature_keys([BpfHelper::MsgRedirectHash]),
        },
        SurfaceScannerCheck {
            target: "sk_skb:/sys/fs/bpf/demo_sockmap",
            program: r#"{|ctx|
  redirect-socket peers 0 --kind sockmap
  redirect-socket hash_peers 0 --kind sockhash
  0
}"#,
            expected_keys: helper_feature_keys([
                BpfHelper::SkRedirectMap,
                BpfHelper::SkRedirectHash,
            ]),
        },
        SurfaceScannerCheck {
            target: "sk_reuseport:migrate",
            program: r#"{|ctx|
  redirect-socket sockets 0 --kind reuseport-sockarray
  0
}"#,
            expected_keys: helper_feature_keys([BpfHelper::SkSelectReuseport]),
        },
        SurfaceScannerCheck {
            target: "tc:lo:ingress",
            program: r#"{|ctx|
  map-contains tracked_cgroups 0 --kind cgroup-array
  0
}"#,
            expected_keys: helper_feature_keys([BpfHelper::SkbUnderCgroup]),
        },
        SurfaceScannerCheck {
            target: "raw_tracepoint:sys_enter",
            program: r#"{|ctx|
  map-contains tracked_cgroups 0 --kind cgroup-array
  0
}"#,
            expected_keys: helper_feature_keys([BpfHelper::CurrentTaskUnderCgroup]),
        },
        SurfaceScannerCheck {
            target: "sk_lookup:/proc/self/ns/net",
            program: r#"{|ctx|
  assign-socket 0 --replace
  0
}"#,
            expected_keys: helper_feature_keys([BpfHelper::SkAssign]),
        },
    ];
    checks
        .last_mut()
        .expect("expected assign-socket surface check")
        .expected_keys
        .insert(sk_lookup_ctx_sk);

    let nu_checks = checks
        .iter()
        .map(|check| (check.target.to_string(), check.program.to_string()))
        .collect::<Vec<_>>();
    let Some(actual) = verifier_diff_nu_program_surface_feature_keys(&nu_checks) else {
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
        "scripts/verifier_diff.nu program-surface scanner drifted from Rust helper metadata: {}",
        mismatches.join(", ")
    );
}

#[test]
fn test_verifier_diff_program_helper_scanner_matches_rust_helper_keys() {
    struct HelperScannerCheck {
        program: &'static str,
        expected_keys: BTreeSet<String>,
    }

    let checks = [
        HelperScannerCheck {
            program: r#"{|ctx|
  let text = "helper-call \"bpf_trace_printk\" \"ignored\" 7"
  # helper-call "bpf_map_lookup_elem" ignored key
  let ignored = 0 # | helper-call "bpf_ktime_get_ns"
  0
}"#,
            expected_keys: BTreeSet::new(),
        },
        HelperScannerCheck {
            program: r#"{|ctx|
  let arg0 = "01234567"
  let retval = "01234567"
  (helper-call "bpf_get_func_arg" $ctx 0 $arg0) | count
  (helper-call "bpf_get_func_ret" $ctx $retval) | count
  (helper-call "bpf_get_func_arg_cnt" $ctx) | count
  0
}"#,
            expected_keys: helper_feature_keys([
                BpfHelper::GetFuncArg,
                BpfHelper::GetFuncRet,
                BpfHelper::GetFuncArgCnt,
            ]),
        },
        HelperScannerCheck {
            program: r#"{|ctx|
  map-define nsdata --kind array --value-type bytes:8 --max-entries 1
  let ns = (0 | map-get nsdata)
  if $ns {
    helper-call "bpf_get_ns_current_pid_tgid" 0 0 $ns 8
  }
  0
}"#,
            expected_keys: helper_feature_keys([BpfHelper::GetNsCurrentPidTgid]),
        },
        HelperScannerCheck {
            program: r#"{|ctx|
  map-define fib_params --kind array --value-type bytes:64 --max-entries 1
  map-define mtu_len --kind array --value-type bytes:4 --max-entries 1
  let params = (0 | map-get fib_params --kind array)
  let len = (0 | map-get mtu_len --kind array)
  helper-call "bpf_skb_cgroup_classid" $ctx
  if $params { helper-call "bpf_fib_lookup" $ctx $params 64 0 }
  if $len { helper-call "bpf_check_mtu" $ctx 0 $len 0 0 }
  0
}"#,
            expected_keys: helper_feature_keys([
                BpfHelper::SkbCgroupClassid,
                BpfHelper::FibLookup,
                BpfHelper::CheckMtu,
            ]),
        },
        HelperScannerCheck {
            program: r#"{|ctx|
  let key = "01234567"
  helper-call "bpf_map_lookup_percpu_elem" per_cpu_values $key 0 --kind per-cpu-array
  let tuple = "0123456789abcdef"
  let sk = (helper-call "bpf_sk_lookup_tcp" $ctx $tuple 16 0 0)
  if $sk {
    helper-call "bpf_sk_release" $sk
  }
  "pass"
}"#,
            expected_keys: helper_feature_keys([
                BpfHelper::MapLookupPercpuElem,
                BpfHelper::SkLookupTcp,
                BpfHelper::SkRelease,
            ]),
        },
        HelperScannerCheck {
            program: r#"{|ctx|
  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"
  let entry = (0 | map-get timers --kind array)
  if $entry {
    helper-call "bpf_timer_init" $entry.timer timers 0 --kind array
    helper-call "bpf_timer_set_callback" $entry.timer {|timer key val| 0}
    helper-call "bpf_timer_start" $entry.timer 1000 0
    helper-call "bpf_timer_cancel" $entry.timer
  }
  0
}"#,
            expected_keys: helper_feature_keys([
                BpfHelper::TimerInit,
                BpfHelper::TimerSetCallback,
                BpfHelper::TimerStart,
                BpfHelper::TimerCancel,
            ]),
        },
    ];

    let programs = checks
        .iter()
        .map(|check| check.program.to_string())
        .collect::<Vec<_>>();
    let Some(actual) = verifier_diff_nu_program_helper_feature_keys(&programs) else {
        return;
    };

    let mut mismatches = Vec::new();
    for (index, (check, actual_keys)) in checks.iter().zip(actual.iter()).enumerate() {
        if &check.expected_keys != actual_keys {
            mismatches.push(format!(
                "#{} expected {:?} actual {:?}",
                index, check.expected_keys, actual_keys
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "scripts/verifier_diff.nu program-helper scanner drifted from Rust helper metadata: {}",
        mismatches.join(", ")
    );
}

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

#[test]
fn test_verifier_diff_program_struct_ops_scanner_matches_rust_sleepable_keys() {
    struct StructOpsScannerCheck {
        target: &'static str,
        program: &'static str,
        expected_keys: BTreeSet<String>,
    }

    let sleepable_keys = program_feature_keys([ProgramCompatibilityRequirement::SleepableProgram]);
    let checks = [
        StructOpsScannerCheck {
            target: "struct_ops:sched_ext_ops.init",
            program: r#"{|ctx|
  0
}"#,
            expected_keys: sleepable_keys.clone(),
        },
        StructOpsScannerCheck {
            target: "struct_ops:sched_ext_ops.select_cpu",
            program: r#"{|ctx|
  0
}"#,
            expected_keys: BTreeSet::new(),
        },
        StructOpsScannerCheck {
            target: "struct_ops:sched_ext_ops",
            program: r#"{
  init: {|ctx| 0 }
  select_cpu: {|ctx| 0 }
}"#,
            expected_keys: sleepable_keys.clone(),
        },
        StructOpsScannerCheck {
            target: "struct_ops:sched_ext_ops",
            program: r#"{
  let text = "init: {|ctx| 0 }"
  # init: {|ctx| 0 }
  select_cpu: {|ctx| 0 }
}"#,
            expected_keys: BTreeSet::new(),
        },
        StructOpsScannerCheck {
            target: "struct_ops:tcp_congestion_ops",
            program: r#"{
  init: {|ctx| 0 }
}"#,
            expected_keys: BTreeSet::new(),
        },
    ];

    let nu_checks = checks
        .iter()
        .map(|check| (check.target.to_string(), check.program.to_string()))
        .collect::<Vec<_>>();
    let Some(actual) = verifier_diff_nu_program_struct_ops_feature_keys(&nu_checks) else {
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
        "scripts/verifier_diff.nu program-struct-ops scanner drifted from Rust sleepable metadata: {}",
        mismatches.join(", ")
    );
}
