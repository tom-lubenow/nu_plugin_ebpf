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

#[test]
fn test_verifier_diff_program_map_scanner_matches_rust_map_kind_keys() {
    struct MapScannerCheck {
        program: &'static str,
        expected_keys: BTreeSet<String>,
    }

    let checks = [
        MapScannerCheck {
            program: r#"{|ctx|
  let text = "helper-call \"bpf_ringbuf_query\" custom_ringbuf 0"
  # helper-call "bpf_redirect_map" redirects 0 0 --kind devmap-hash
  let docs = "redirect-map tx_ports 0 --kind devmap"
  let more_docs = "map-define xsks --kind xskmap"
  let ignored = 0 # | helper-call "bpf_map_lookup_percpu_elem" values key 0 --kind lru-per-cpu-hash
  let more_ignored = 0 # | map-get values --kind queue
  0
}"#,
            expected_keys: BTreeSet::new(),
        },
        MapScannerCheck {
            program: r#"{|ctx|
  let entry = ($ctx.pid | map-get default_counts)
  if $entry { 1 | map-put default_counts $ctx.pid }
  $ctx.pid | map-delete default_counts
  0
}"#,
            expected_keys: map_kind_feature_keys([MapKind::Hash]),
        },
        MapScannerCheck {
            program: r#"{|ctx|
  map-define array_counts --kind array --key-type u32 --value-type u64
  let entry = ($ctx.pid | map-get array_counts)
  1 | map-put array_counts $ctx.pid
  0
}"#,
            expected_keys: map_kind_feature_keys([MapKind::Array]),
        },
        MapScannerCheck {
            program: r#"{|ctx|
  let entry = ($ctx.pid | map-get lru_counts --kind lru-hash)
  if $entry { 1 | map-put lru_counts $ctx.pid }
  0
}"#,
            expected_keys: map_kind_feature_keys([MapKind::LruHash]),
        },
        MapScannerCheck {
            program: r#"{|ctx|
  map-define pending --kind queue --value-type u64
  1 | map-push pending
  map-peek pending
  map-pop pending
  0
}"#,
            expected_keys: map_kind_feature_keys([MapKind::Queue]),
        },
        MapScannerCheck {
            program: r#"{|ctx|
  redirect-map tx_ports 0 --kind devmap
  redirect-map tx_ports 1
  redirect-socket peers 0 --kind sockhash
  redirect-socket peers 1
  0
}"#,
            expected_keys: map_kind_feature_keys([MapKind::DevMap, MapKind::SockHash]),
        },
        MapScannerCheck {
            program: r#"{|ctx|
  helper-call "bpf_ringbuf_query" custom_ringbuf 0
  helper-call "bpf_get_stackid" $ctx custom_stacks 0
  helper-call "bpf_sk_redirect_hash" $ctx socket_hash 0 0
  helper-call "bpf_sk_storage_get" socket_storage $ctx.sk 0 0
  helper-call "bpf_map_push_elem" queue_or_bloom 1 0 --kind bloom-filter
  0
}"#,
            expected_keys: map_kind_feature_keys([
                MapKind::RingBuf,
                MapKind::StackTrace,
                MapKind::SockHash,
                MapKind::SkStorage,
                MapKind::BloomFilter,
            ]),
        },
        MapScannerCheck {
            program: r#"{|ctx|
  tail-call progs 0
  0
}"#,
            expected_keys: map_kind_feature_keys([MapKind::ProgArray]),
        },
    ];

    let programs = checks
        .iter()
        .map(|check| check.program.to_string())
        .collect::<Vec<_>>();
    let Some(actual) = verifier_diff_nu_program_map_feature_keys(&programs) else {
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
        "scripts/verifier_diff.nu program-map scanner drifted from Rust map metadata: {}",
        mismatches.join(", ")
    );
}

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
