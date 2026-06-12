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
