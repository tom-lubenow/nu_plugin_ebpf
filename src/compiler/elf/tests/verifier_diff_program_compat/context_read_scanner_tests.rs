use super::*;

#[test]
fn test_verifier_diff_nested_record_wrapper_read_scanner_preserves_metadata() {
    let target = "kprobe:ksys_read";
    let program = r#"{|ctx|
  def wrap [event] { { event: $event } }
  def outer [event] { wrap $event }
  let rec = (outer $ctx)
  $rec.event.pid | count
  0
}"#;
    let Some(actual) = verifier_diff_nu_program_context_field_feature_keys(&[(
        target.to_string(),
        program.to_string(),
    )]) else {
        return;
    };
    let spec = ProgramSpec::parse(target)
        .unwrap_or_else(|err| panic!("representative context field target should parse: {err}"));
    let expected =
        ContextFieldCompatibilityRequirement::for_field_on_program_spec(&CtxField::Pid, &spec)
            .expect("ctx.pid should carry source-backed context metadata")
            .key();

    assert!(
        actual[0].contains(&expected),
        "nested user-function record wrappers should preserve read-side context metadata; expected {expected}, actual {:?}",
        actual[0]
    );
}

#[test]
fn test_verifier_diff_identity_wrapper_record_argument_scanner_preserves_metadata() {
    let target = "sk_lookup:/proc/self/ns/net";
    let program = r#"{|ctx|
  def id [value] { $value }
  def wrap [event] { { socket: $event } }
  let rec = (wrap (id ($ctx | get sk)))
  $rec.socket.family
  0
}"#;
    let Some(actual) = verifier_diff_nu_program_context_field_feature_keys(&[(
        target.to_string(),
        program.to_string(),
    )]) else {
        return;
    };
    let spec = ProgramSpec::parse(target)
        .unwrap_or_else(|err| panic!("representative context field target should parse: {err}"));
    let expected = BTreeSet::from([
        ContextFieldCompatibilityRequirement::for_field_on_program_spec(&CtxField::Socket, &spec)
            .expect("ctx.sk should carry source-backed context metadata")
            .key(),
        ContextFieldCompatibilityRequirement::for_field_on_program_spec(&CtxField::Family, &spec)
            .expect("ctx.sk.family should carry source-backed field metadata")
            .key(),
        BpfHelper::ProbeReadKernel
            .compatibility_requirement()
            .expect("ctx.sk.family projection helper should carry compatibility metadata")
            .key(),
    ]);

    assert_eq!(
        actual[0], expected,
        "transparent identity wrappers around record-wrapper arguments should preserve context metadata"
    );
}
