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
