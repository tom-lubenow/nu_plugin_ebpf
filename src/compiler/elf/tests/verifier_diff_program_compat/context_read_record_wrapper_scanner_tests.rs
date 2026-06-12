use super::*;

#[test]
fn test_verifier_diff_multi_param_record_wrapper_scanner_preserves_metadata() {
    let target = "sk_lookup:/proc/self/ns/net";
    let program = r#"{|ctx|
  def wrap [ignored event] { { socket: $event.sk } }
  let rec = (wrap 0 $ctx)
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
        "multi-parameter record wrappers should preserve context metadata"
    );
}

#[test]
fn test_verifier_diff_multi_param_get_argument_record_wrapper_scanner_preserves_metadata() {
    let target = "sk_lookup:/proc/self/ns/net";
    let program = r#"{|ctx|
  def wrap [ignored event] { { socket: $event } }
  let rec = (wrap 0 ($ctx | get sk))
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
        "multi-parameter record wrappers should preserve get-pipeline context argument metadata"
    );
}

#[test]
fn test_verifier_diff_multi_param_identity_wrapper_record_argument_scanner_preserves_metadata() {
    let target = "sk_lookup:/proc/self/ns/net";
    let program = r#"{|ctx|
  def id [value] { $value }
  def wrap [ignored event] { { socket: $event } }
  let rec = (wrap 0 (id ($ctx | get sk)))
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
        "transparent identity wrappers around multi-parameter record-wrapper arguments should preserve context metadata"
    );
}

#[test]
fn test_verifier_diff_multi_param_identity_wrapper_record_field_scanner_preserves_metadata() {
    let target = "sk_lookup:/proc/self/ns/net";
    let program = r#"{|ctx|
  def id [value] { $value }
  def wrap [ignored event] { { socket: (id ($event | get sk)) } }
  let rec = (wrap 0 $ctx)
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
        "transparent identity wrappers around multi-parameter record-wrapper fields should preserve context metadata"
    );
}
