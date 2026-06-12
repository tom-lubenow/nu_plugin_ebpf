use super::*;

#[test]
fn test_verifier_diff_multi_param_user_function_read_scanner_preserves_metadata() {
    let target = "kprobe:ksys_read";
    let program = r#"{|ctx|
  def read_pid [ignored event] { $event.pid }
  read_pid 0 $ctx
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
        ContextFieldCompatibilityRequirement::for_field_on_program_spec(&CtxField::Pid, &spec)
            .expect("ctx.pid should carry source-backed context metadata")
            .key(),
        BpfHelper::GetCurrentPidTgid
            .compatibility_requirement()
            .expect("ctx.pid backing helper should carry compatibility metadata")
            .key(),
    ]);

    assert_eq!(
        actual[0], expected,
        "multi-parameter user functions should preserve read-side context metadata"
    );
}

#[test]
fn test_verifier_diff_multi_param_user_function_get_read_scanner_preserves_metadata() {
    let target = "kprobe:ksys_read";
    let program = r#"{|ctx|
  def read_pid [ignored event] { $event | get pid }
  read_pid 0 $ctx
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
        ContextFieldCompatibilityRequirement::for_field_on_program_spec(&CtxField::Pid, &spec)
            .expect("ctx.pid should carry source-backed context metadata")
            .key(),
        BpfHelper::GetCurrentPidTgid
            .compatibility_requirement()
            .expect("ctx.pid backing helper should carry compatibility metadata")
            .key(),
    ]);

    assert_eq!(
        actual[0], expected,
        "multi-parameter user functions should preserve get-pipeline context metadata"
    );
}

#[test]
fn test_verifier_diff_multi_param_user_function_root_scanner_preserves_metadata() {
    let target = "sk_lookup:/proc/self/ns/net";
    let program = r#"{|ctx|
  def get_sk [ignored event] { $event.sk }
  let sk = (get_sk 0 $ctx)
  $sk.family
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
        "multi-parameter user functions should preserve returned context-root metadata"
    );
}

#[test]
fn test_verifier_diff_multi_param_user_function_get_root_scanner_preserves_metadata() {
    let target = "sk_lookup:/proc/self/ns/net";
    let program = r#"{|ctx|
  def get_sk [ignored event] { $event | get sk }
  let sk = (get_sk 0 $ctx)
  $sk.family
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
        "multi-parameter user functions should preserve get-pipeline returned-root metadata"
    );
}

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

#[test]
fn test_verifier_diff_multi_param_get_argument_root_scanner_preserves_metadata() {
    let target = "sk_lookup:/proc/self/ns/net";
    let program = r#"{|ctx|
  def get_it [ignored event] { $event }
  let sk = (get_it 0 ($ctx | get sk))
  $sk.family
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
        "multi-parameter user functions should preserve get-pipeline context argument metadata"
    );
}
