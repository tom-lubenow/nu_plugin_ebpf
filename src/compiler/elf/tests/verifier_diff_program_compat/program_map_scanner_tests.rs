use super::*;

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
