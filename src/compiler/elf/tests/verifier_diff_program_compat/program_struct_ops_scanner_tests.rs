use super::*;

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
