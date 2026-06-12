use super::*;

#[test]
fn test_verifier_diff_program_map_value_scanner_matches_rust_map_value_keys() {
    struct MapValueScannerCheck {
        program: &'static str,
        expected_keys: BTreeSet<String>,
    }

    let checks = [
        MapValueScannerCheck {
            program: r#"{|ctx|
  let text = "map-define resources --kind hash --value-type record{lock:bpf_spin_lock}"
  # map-define resources --kind hash --value-type "record{timer:bpf_timer}"
  map-define docs --kind hash # --value-type "record{lock:bpf_spin_lock}"
  0
}"#,
            expected_keys: BTreeSet::new(),
        },
        MapValueScannerCheck {
            program: r#"{|ctx|
  map-define resources --kind hash --value-type "record{lock:bpf_spin_lock,timer:bpf_timer,task:kptr:task_struct,work:bpf_wq,refs:bpf_refcount}"
  0
}"#,
            expected_keys: map_value_feature_keys([
                MapValueCompatibilityRequirement::BpfSpinLock,
                MapValueCompatibilityRequirement::BpfTimer,
                MapValueCompatibilityRequirement::BpfKptr,
                MapValueCompatibilityRequirement::BpfWorkqueue,
                MapValueCompatibilityRequirement::BpfRefcount,
            ]),
        },
        MapValueScannerCheck {
            program: r#"{|ctx|
  map-define list_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node}"
  0
}"#,
            expected_keys: map_value_feature_keys([
                MapValueCompatibilityRequirement::BpfSpinLock,
                MapValueCompatibilityRequirement::BpfListHead,
                MapValueCompatibilityRequirement::BpfListNode,
            ]),
        },
        MapValueScannerCheck {
            program: r#"{|ctx|
  map-define list_items --kind hash --value-type "record{root:bpf_list_head:node_data:node:record{refs:bpf_refcount,cookie:u64}}"
  0
}"#,
            expected_keys: map_value_feature_keys([
                MapValueCompatibilityRequirement::BpfListHead,
                MapValueCompatibilityRequirement::BpfListNode,
                MapValueCompatibilityRequirement::BpfRefcount,
            ]),
        },
        MapValueScannerCheck {
            program: r#"{|ctx|
  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:node_data:node}"
  0
}"#,
            expected_keys: map_value_feature_keys([
                MapValueCompatibilityRequirement::BpfSpinLock,
                MapValueCompatibilityRequirement::BpfRbRoot,
                MapValueCompatibilityRequirement::BpfRbNode,
            ]),
        },
        MapValueScannerCheck {
            program: r#"{|ctx|
  map-define rb_items --kind hash --value-type "record{root:bpf_rb_root:rb_item:rb:record{refs:bpf_refcount,cookie:u64}}"
  0
}"#,
            expected_keys: map_value_feature_keys([
                MapValueCompatibilityRequirement::BpfRbRoot,
                MapValueCompatibilityRequirement::BpfRbNode,
                MapValueCompatibilityRequirement::BpfRefcount,
            ]),
        },
    ];

    let programs = checks
        .iter()
        .map(|check| check.program.to_string())
        .collect::<Vec<_>>();
    let Some(actual) = verifier_diff_nu_program_map_value_feature_keys(&programs) else {
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
        "scripts/verifier_diff.nu program-map-value scanner drifted from Rust map-value metadata: {}",
        mismatches.join(", ")
    );
}
