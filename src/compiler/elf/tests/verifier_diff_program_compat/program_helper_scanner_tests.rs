use super::*;

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
