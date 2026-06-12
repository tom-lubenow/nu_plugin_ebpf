use super::*;

#[test]
fn test_verifier_diff_program_global_scanner_matches_rust_global_keys() {
    struct GlobalScannerCheck {
        program: &'static str,
        expected_keys: BTreeSet<String>,
    }

    let global_data_sections =
        global_feature_keys([GlobalCompatibilityRequirement::BpfDataSections]);
    let checks = [
        GlobalScannerCheck {
            program: r#"{|ctx|
  let text = "global-get seen"
  # 7 | global-define --type i64 seen
  let samples = []
  let payload = 0x[]
  0
}"#,
            expected_keys: BTreeSet::new(),
        },
        GlobalScannerCheck {
            program: r#"{|ctx|
  let config = { pid: 7 samples: [11 22] }
  (($config.samples | get 1) + $config.pid) | count
  0
}"#,
            expected_keys: global_data_sections.clone(),
        },
        GlobalScannerCheck {
            program: r#"{|ctx|
  let payload = 0x[01 02]
  ($payload | get 0) | count
  0
}"#,
            expected_keys: global_data_sections.clone(),
        },
        GlobalScannerCheck {
            program: r#"{|ctx|
  let config = { pid: $ctx.pid samples: [11 22] }
  (($config.samples | get 1) + $config.pid) | count
  0
}"#,
            expected_keys: BTreeSet::new(),
        },
        GlobalScannerCheck {
            program: r#"{|ctx|
  let seed = 7
  let config = { pid: $seed samples: [11 22] }
  (($config.samples | get 1) + $config.pid) | count
}"#,
            expected_keys: global_data_sections.clone(),
        },
        GlobalScannerCheck {
            program: r#"{|ctx|
  7 | global-define --type i64 seen
  global-get seen
}"#,
            expected_keys: global_data_sections.clone(),
        },
        GlobalScannerCheck {
            program: r#"{|ctx|
  mut state: record<pid: int stats: record<hits: int ok: bool>> = {}
  ($state.pid + $state.stats.hits) | count
  0
}"#,
            expected_keys: global_data_sections,
        },
    ];

    let programs = checks
        .iter()
        .map(|check| check.program.to_string())
        .collect::<Vec<_>>();
    let Some(actual) = verifier_diff_nu_program_global_feature_keys(&programs) else {
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
        "scripts/verifier_diff.nu program-global scanner drifted from Rust global metadata: {}",
        mismatches.join(", ")
    );
}
