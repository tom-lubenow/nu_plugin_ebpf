use super::*;

#[test]
fn test_verifier_diff_program_language_scanner_matches_rust_compiled_feature_keys() {
    struct LanguageScannerCheck {
        program: &'static str,
        expected_keys: BTreeSet<String>,
    }

    let checks = [
        LanguageScannerCheck {
            program: r#"{|ctx|
  # def ignored [] { for ignored in 0..1 { } }
  let text = "def not_a_function [] { for item in [] { } }"
  1
}"#,
            expected_keys: BTreeSet::new(),
        },
        LanguageScannerCheck {
            program: r#"{|ctx|
  def make [] { 7 }
  make
}"#,
            expected_keys: compiled_feature_keys([
                CompiledFeatureCompatibilityRequirement::BpfSubprogramCalls,
            ]),
        },
        LanguageScannerCheck {
            program: r#"{|ctx|
  helper-call "bpf_loop" 4 {|i cb| 0 } "ctx" 0
  0
}"#,
            expected_keys: compiled_feature_keys([
                CompiledFeatureCompatibilityRequirement::BpfSubprogramCalls,
            ]),
        },
        LanguageScannerCheck {
            program: r#"{|ctx|
  kfunc-call "bpf_wq_set_callback_impl" $entry.work {|map key| 0} 0 0
  0
}"#,
            expected_keys: compiled_feature_keys([
                CompiledFeatureCompatibilityRequirement::BpfSubprogramCalls,
            ]),
        },
        LanguageScannerCheck {
            program: r#"{|ctx|
  mut sum = 0
  for i in 0..3 {
    $sum = ($sum + $i)
  }
  $sum
}"#,
            expected_keys: compiled_feature_keys([
                CompiledFeatureCompatibilityRequirement::BoundedLoops,
            ]),
        },
        LanguageScannerCheck {
            program: r#"{|ctx|
  def make [] { mut sum = 0; for i in 0..3 { $sum = ($sum + $i) }; $sum }
  make
}"#,
            expected_keys: compiled_feature_keys([
                CompiledFeatureCompatibilityRequirement::BpfSubprogramCalls,
                CompiledFeatureCompatibilityRequirement::BoundedLoops,
            ]),
        },
    ];

    let programs = checks
        .iter()
        .map(|check| check.program.to_string())
        .collect::<Vec<_>>();
    let Some(actual) = verifier_diff_nu_program_language_feature_keys(&programs) else {
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
        "scripts/verifier_diff.nu program-language scanner drifted from Rust compiled-feature metadata: {}",
        mismatches.join(", ")
    );
}
