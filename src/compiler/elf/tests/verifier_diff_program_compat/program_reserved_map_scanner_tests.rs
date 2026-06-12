use super::*;

#[test]
fn test_verifier_diff_reserved_map_scanner_matches_rust_map_kind_keys() {
    struct ReservedMapScannerCheck {
        program: &'static str,
        expected_keys: BTreeSet<String>,
    }

    let checks = [
        ReservedMapScannerCheck {
            program: r#"{|ctx|
  let text = "helper-call \"bpf_user_ringbuf_drain\" user_events"
  # helper-call "bpf_perf_event_read" perf_events 0
  let docs = "1 | emit"
  let more_docs = "2 | count"
  let ignored = 0 # | helper-call "bpf_get_stackid" $ctx kstacks 0
  0
}"#,
            expected_keys: BTreeSet::new(),
        },
        ReservedMapScannerCheck {
            program: r#"{|ctx|
  1 | emit
  2 | count
  helper-call "bpf_user_ringbuf_drain" user_events {|dyn cb| 0 } "ctx" 0
  helper-call "bpf_perf_event_read" perf_events 0
  helper-call "bpf_get_stackid" $ctx kstacks 0
  0
}"#,
            expected_keys: map_kind_feature_keys([
                MapKind::RingBuf,
                MapKind::Hash,
                MapKind::UserRingBuf,
                MapKind::PerfEventArray,
                MapKind::StackTrace,
            ]),
        },
    ];

    let programs = checks
        .iter()
        .map(|check| check.program.to_string())
        .collect::<Vec<_>>();
    let Some(actual) = verifier_diff_nu_program_reserved_map_feature_keys(&programs) else {
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
        "scripts/verifier_diff.nu reserved-map scanner drifted from Rust map metadata: {}",
        mismatches.join(", ")
    );
}
