use super::*;

#[test]
fn test_verifier_diff_multi_param_alias_read_scanner_preserves_metadata() {
    let target = "sk_lookup:/proc/self/ns/net";
    let program = r#"{|ctx|
  def read_family [ignored event] {
    let sk = $event.sk
    $sk.family
  }
  read_family 0 $ctx
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
        "multi-parameter user functions should preserve context-root alias read metadata"
    );
}

#[test]
fn test_verifier_diff_multi_param_get_alias_read_scanner_preserves_metadata() {
    let target = "sk_lookup:/proc/self/ns/net";
    let program = r#"{|ctx|
  def read_family [ignored event] {
    let sk = ($event | get sk)
    $sk.family
  }
  read_family 0 $ctx
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
        "multi-parameter user functions should preserve get-derived context-root alias metadata"
    );
}
