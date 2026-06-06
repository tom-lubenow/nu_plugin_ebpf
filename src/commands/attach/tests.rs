use std::collections::{HashMap, HashSet};

use crate::compiler::hir::{
    HirBlock, HirBlockId, HirCallArgs, HirFunction, HirLiteral, HirProgram, HirStmt, HirTerminator,
};
use crate::compiler::hir_to_mir::{
    MirLoweringResult, lower_hir_to_mir_with_hints, lower_hir_to_mir_with_hints_and_maps,
};
use crate::compiler::instruction::BpfHelper;
use crate::compiler::mir::{
    AddressSpace, CtxField, KSTACK_MAP_NAME, MapKind, MapRef, MirInst, MirValue, StructField,
    USTACK_MAP_NAME,
};
use crate::compiler::passes::{ListLowering, MirPass, optimize_with_ssa_hints};
use crate::compiler::{
    BpfMapDef, CounterKeySchema, CounterKeySchemaField, EbpfProgram, EbpfProgramType, MirType,
    ProbeContext, StructOpsObjectSpec, StructOpsValueField, compile_mir_to_ebpf_with_hints,
};
use crate::kernel_btf::{KernelBtf, TrampolineFieldSelector, TypeInfo};
use crate::program_spec::ProgramSpec;
use nu_protocol::DeclId;
use nu_protocol::ast::{CellPath, Comparison, Math, Operator, PathMember, RangeInclusion};
use nu_protocol::casing::Casing;
use nu_protocol::engine::Closure;
use nu_protocol::ir::{Instruction, IrBlock};
use nu_protocol::{BlockId, Record, RegId, Span, Type, Value, VarId};

const BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: i64 = 4;
const BPF_SOCK_OPS_PARSE_HDR_OPT_CB: i64 = 13;
const BPF_SOCK_OPS_HDR_OPT_LEN_CB: i64 = 14;

fn single_annotated_global_return_ir_block() -> IrBlock {
    IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    }
}

fn one_let_then_single_annotated_global_return_ir_block() -> IrBlock {
    IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(10),
                src: RegId::new(0),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(1),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 4],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 4],
        comments: vec!["let".into(), "let".into(), "".into(), "".into()],
        register_count: 2,
        file_count: 0,
    }
}

#[test]
fn test_extract_decl_names_from_formatted_instructions_preserves_user_function_names() {
    let decl_names = super::extract_decl_names_from_formatted_instructions(&[
        r#"call                   decl 488 "global-define", %0"#.to_string(),
        r#"call                   decl 489 "project-entry", %1"#.to_string(),
        r#"call                   decl 490 "count", %2"#.to_string(),
        r#"call                   decl 491 "get", %3"#.to_string(),
    ]);

    assert_eq!(
        decl_names,
        HashMap::from([
            (DeclId::new(488), "global-define".to_string()),
            (DeclId::new(489), "project-entry".to_string()),
            (DeclId::new(490), "count".to_string()),
            (DeclId::new(491), "get".to_string()),
        ])
    );
}

#[test]
fn test_known_closure_commands_include_metadata_commands() {
    assert!(super::compilation::is_known_closure_command("transpose"));
    assert!(super::compilation::is_known_closure_command("seq date"));
}

#[test]
fn test_parse_inline_user_function_signatures_extracts_closure_local_def() {
    let source = r#"{|ctx|
            def bump [msg] { "ok" }
            let next = (bump "hi")
            $next | count
        }"#;
    let decl_ids = HashSet::from([DeclId::new(515)]);
    let decl_names = HashMap::from([(DeclId::new(515), "bump".to_string())]);

    let sigs = super::parse_inline_user_function_signatures(
        source,
        &decl_ids,
        &decl_names,
        Span::test_data(),
    )
    .expect("inline def signatures should parse");

    assert_eq!(sigs.len(), 1);
    let sig = sigs
        .get(&DeclId::new(515))
        .expect("bump signature should exist");
    assert_eq!(sig.params.len(), 2);
    assert!(matches!(
        sig.params[0],
        crate::compiler::UserParam {
            kind: crate::compiler::UserParamKind::Input,
            ..
        }
    ));
    assert!(matches!(
        sig.params[1],
        crate::compiler::UserParam {
            kind: crate::compiler::UserParamKind::Positional,
            optional: false,
            ..
        }
    ));
    assert_eq!(sig.params[1].name.as_deref(), Some("msg"));
}

#[test]
fn test_parse_inline_user_function_signatures_skips_ambiguous_names() {
    let source = r#"{|ctx| def bump [msg] { "ok" } }"#;
    let decl_ids = HashSet::from([DeclId::new(515), DeclId::new(516)]);
    let decl_names = HashMap::from([
        (DeclId::new(515), "bump".to_string()),
        (DeclId::new(516), "bump".to_string()),
    ]);

    let sigs = super::parse_inline_user_function_signatures(
        source,
        &decl_ids,
        &decl_names,
        Span::test_data(),
    )
    .expect("ambiguous inline defs should not error");

    assert!(sigs.is_empty(), "ambiguous def names should not be guessed");
}

#[test]
fn test_map_leading_annotated_mut_globals_uses_leading_declaration_order() {
    let source =
        "{|| let tmp = 1; mut state: record<pid: int ok: bool> = {pid: 0, ok: false}; $state }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(10),
                src: RegId::new(0),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(1),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 4],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 4],
        comments: vec!["let".into(), "let".into(), "".into(), "".into()],
        register_count: 2,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("leading annotated mut globals should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0].var_id, VarId::new(11));
    assert_eq!(
        globals[0].declared_type,
        Type::Record(Box::new([
            ("pid".to_string(), Type::Int),
            ("ok".to_string(), Type::Bool),
        ]))
    );
    match &globals[0].initial_value {
        Value::Record { val, .. } => {
            assert_eq!(val.get("pid").and_then(|v| v.as_int().ok()), Some(0));
            assert_eq!(val.get("ok").and_then(|v| v.as_bool().ok()), Some(false));
        }
        other => panic!("expected record initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_nushell_parse_invalid_null_initializer() {
    let source = "{|| mut state: record<pid: int ok: bool> = null; $state }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("source-level null initializer should be rejected by Nushell parsing");

    assert!(
        err.to_string()
            .contains("Failed to parse annotated mutable declaration"),
        "unexpected error: {err}"
    );
    assert!(
        err.help
            .as_deref()
            .is_some_and(|help| help.contains("Nushell rejected this typed `mut` declaration")),
        "unexpected error help: {:?}",
        err.help
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_empty_record_zero_initializer() {
    let source = "{|| mut state: record<pid: int ok: bool> = {}; $state }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("empty record initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0].var_id, VarId::new(11));
    assert_eq!(
        globals[0].declared_type,
        Type::Record(Box::new([
            ("pid".to_string(), Type::Int),
            ("ok".to_string(), Type::Bool),
        ]))
    );
    assert!(
        matches!(globals[0].initial_value, Value::Record { ref val, .. } if val.is_empty()),
        "expected empty record initializer"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_nushell_parse_invalid_partial_record_initializer()
{
    let source = "{|| mut state: record<pid: int ok: bool> = {pid: 7}; $state }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("partial record initializer should match Nushell parser rejection");

    assert!(
        err.to_string()
            .contains("Failed to parse annotated mutable declaration"),
        "unexpected error: {err}"
    );
    assert!(
        err.help
            .as_deref()
            .is_some_and(|help| help.contains("Nushell rejected this typed `mut` declaration")),
        "unexpected error help: {:?}",
        err.help
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_non_leading_annotated_mut() {
    let source = "{|| 1 | count; mut state: int = 0; $state }";
    let ir_block = IrBlock {
        instructions: vec![Instruction::StoreVariable {
            var_id: VarId::new(80),
            src: RegId::new(0),
        }],
        spans: vec![Span::test_data()],
        data: Vec::<u8>::new().into(),
        ast: vec![None],
        comments: vec!["let".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("non-leading annotated mut declarations should fail clearly");
    assert!(
        err.to_string()
            .contains("Annotated mutable globals must be declared first"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_ignores_non_leading_untyped_mut() {
    let source = "{|| 1 | count; mut state = 0; $state }";
    let ir_block = IrBlock {
        instructions: vec![Instruction::StoreVariable {
            var_id: VarId::new(80),
            src: RegId::new(0),
        }],
        spans: vec![Span::test_data()],
        data: Vec::<u8>::new().into(),
        ast: vec![None],
        comments: vec!["let".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("non-leading untyped mut should remain an ordinary local");

    assert!(globals.is_empty());
}

#[test]
fn test_map_leading_annotated_mut_globals_ignores_ordinary_lets_without_ir_stores() {
    let source = "{|ctx| let selector = $ctx.mark; let data = (if $selector == 0 { $ctx.data } else { $ctx.data }); $data }";
    let ir_block = IrBlock {
        instructions: vec![Instruction::Return { src: RegId::new(0) }],
        spans: vec![Span::test_data()],
        data: Vec::<u8>::new().into(),
        ast: vec![None],
        comments: vec!["".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("ordinary lets should not require annotated-mut declaration mapping");

    assert!(globals.is_empty());
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_record_spread_initializer() {
    let source = "{|| mut state: record<pid: int ok: bool> = {pid: 0, ...{ok: true}}; $state }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant record spread initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::Record { val, .. } => {
            assert_eq!(val.get("pid").and_then(|v| v.as_int().ok()), Some(0));
            assert_eq!(val.get("ok").and_then(|v| v.as_bool().ok()), Some(true));
        }
        other => panic!("expected record initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_record_merge_initializer() {
    let source = "{|| mut state: record<pid: int cpu: int mem: int> = ({pid: 7, cpu: 2} | merge ({pid: 9, mem: 4})); $state }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant record merge initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::Record { val, .. } => {
            assert_eq!(val.get("pid").and_then(|v| v.as_int().ok()), Some(9));
            assert_eq!(val.get("cpu").and_then(|v| v.as_int().ok()), Some(2));
            assert_eq!(val.get("mem").and_then(|v| v.as_int().ok()), Some(4));
        }
        other => panic!("expected record initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_record_merge_initializer() {
    let source = "{|| let patch = {pid: 9, mem: 4}; mut state: record<pid: int cpu: int mem: int> = ({pid: 7, cpu: 2} | merge $patch); $state }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(10),
                src: RegId::new(0),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(1),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 4],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 4],
        comments: vec!["let".into(), "let".into(), "".into(), "".into()],
        register_count: 2,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound constant record merge initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::Record { val, .. } => {
            assert_eq!(val.get("pid").and_then(|v| v.as_int().ok()), Some(9));
            assert_eq!(val.get("cpu").and_then(|v| v.as_int().ok()), Some(2));
            assert_eq!(val.get("mem").and_then(|v| v.as_int().ok()), Some(4));
        }
        other => panic!("expected record initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_record_key_initializer() {
    let source = r#"{|| let field = "pid"; mut state: record<pid: int cpu: int> = {$field: 7, cpu: 2}; $state }"#;
    let ir_block = one_let_then_single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound record key initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::Record { val, .. } => {
            assert_eq!(val.get("pid").and_then(|v| v.as_int().ok()), Some(7));
            assert_eq!(val.get("cpu").and_then(|v| v.as_int().ok()), Some(2));
        }
        other => panic!("expected record initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_integer_expression_initializer() {
    let source = "{|| let base = 40; mut value: int = ($base + 2); $value }";
    let ir_block = one_let_then_single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound integer expression initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0].initial_value.as_int().ok(), Some(42));
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_boolean_expression_initializer() {
    let source = "{|| let threshold = 4; mut ok: bool = ($threshold >= 4 and not false); $ok }";
    let ir_block = one_let_then_single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound boolean expression initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0].initial_value.as_bool().ok(), Some(true));
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_concat_expression_initializer() {
    let source = r#"{|| let suffix = "bar"; mut name: string = ("foo" ++ $suffix); $name }"#;
    let ir_block = one_let_then_single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound concat expression initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0].initial_value.as_str().ok(), Some("foobar"));
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_string_affix_comparison_initializer() {
    let source = r#"{|| let prefix = "foo"; mut ok: bool = ("foobar" starts-with $prefix and "foobar" ends-with "bar" and "foobar" not-starts-with "bar"); $ok }"#;
    let ir_block = one_let_then_single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound string affix comparison initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0].initial_value.as_bool().ok(), Some(true));
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_list_membership_initializer() {
    let source =
        "{|| let values = [1, 2, 3]; mut ok: bool = (2 in $values and 4 not-in $values); $ok }";
    let ir_block = one_let_then_single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound list membership initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0].initial_value.as_bool().ok(), Some(true));
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_record_membership_initializer() {
    let source = r#"{|| let field = "pid"; mut ok: bool = ({pid: 7, cpu: 2} has $field and {pid: 7, cpu: 2} not-has "mem"); $ok }"#;
    let ir_block = one_let_then_single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound record membership initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0].initial_value.as_bool().ok(), Some(true));
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_record_columns_initializer() {
    let source = "{|| mut fields: list<string> = ({pid: 7, cpu: 2, mem: 4} | columns); $fields }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant record columns initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            assert_eq!(vals.len(), 3);
            assert_eq!(vals[0].as_str().ok(), Some("pid"));
            assert_eq!(vals[1].as_str().ok(), Some("cpu"));
            assert_eq!(vals[2].as_str().ok(), Some("mem"));
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_record_values_initializer() {
    let source = "{|| mut vals: list<int> = ({pid: 7, cpu: 2, mem: 4} | values); $vals }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant record values initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            assert_eq!(vals.len(), 3);
            assert_eq!(vals[0].as_int().ok(), Some(7));
            assert_eq!(vals[1].as_int().ok(), Some(2));
            assert_eq!(vals[2].as_int().ok(), Some(4));
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_record_transpose_initializer() {
    let source = "{|| mut rows: list<record<column0: string column1: int>> = ({pid: 7, cpu: 2} | transpose); $rows }";
    let ir_block = single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant record transpose initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    let Value::List { vals, .. } = &globals[0].initial_value else {
        panic!(
            "expected list initializer, got {:?}",
            globals[0].initial_value
        );
    };
    assert_eq!(vals.len(), 2);

    let Value::Record { val: first, .. } = &vals[0] else {
        panic!("expected first transposed row, got {:?}", vals[0]);
    };
    assert_eq!(
        first.get("column0").and_then(|v| v.as_str().ok()),
        Some("pid")
    );
    assert_eq!(first.get("column1").and_then(|v| v.as_int().ok()), Some(7));

    let Value::Record { val: second, .. } = &vals[1] else {
        panic!("expected second transposed row, got {:?}", vals[1]);
    };
    assert_eq!(
        second.get("column0").and_then(|v| v.as_str().ok()),
        Some("cpu")
    );
    assert_eq!(second.get("column1").and_then(|v| v.as_int().ok()), Some(2));
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_record_transpose_custom_columns() {
    let source = "{|| mut rows: list<record<name: string val: int>> = ({pid: 7, cpu: 2} | transpose name val); $rows }";
    let ir_block = single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant record transpose custom columns initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    let Value::List { vals, .. } = &globals[0].initial_value else {
        panic!(
            "expected list initializer, got {:?}",
            globals[0].initial_value
        );
    };
    let Value::Record { val, .. } = &vals[1] else {
        panic!("expected transposed row, got {:?}", vals[1]);
    };
    assert_eq!(val.get("name").and_then(|v| v.as_str().ok()), Some("cpu"));
    assert_eq!(val.get("val").and_then(|v| v.as_int().ok()), Some(2));
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_record_transpose_ignore_titles() {
    let source = "{|| mut rows: list<record<column0: int>> = ({pid: 7, cpu: 2} | transpose --ignore-titles); $rows }";
    let ir_block = single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant record transpose ignore titles initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    let Value::List { vals, .. } = &globals[0].initial_value else {
        panic!(
            "expected list initializer, got {:?}",
            globals[0].initial_value
        );
    };
    let Value::Record { val, .. } = &vals[0] else {
        panic!("expected transposed row, got {:?}", vals[0]);
    };
    assert_eq!(val.len(), 1);
    assert_eq!(val.get("column0").and_then(|v| v.as_int().ok()), Some(7));
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_root_external_constant_record_transpose() {
    let source = "{|| mut rows: list<record<column0: string column1: int>> = ({pid: 7, cpu: 2} | ^transpose); $rows }";
    let ir_block = single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("root external constant record transpose initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    let Value::List { vals, .. } = &globals[0].initial_value else {
        panic!(
            "expected list initializer, got {:?}",
            globals[0].initial_value
        );
    };
    let Value::Record { val, .. } = &vals[1] else {
        panic!("expected transposed row, got {:?}", vals[1]);
    };
    assert_eq!(
        val.get("column0").and_then(|v| v.as_str().ok()),
        Some("cpu")
    );
    assert_eq!(val.get("column1").and_then(|v| v.as_int().ok()), Some(2));
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_root_external_constant_record_transpose_custom_columns()
 {
    let source = "{|| mut rows: list<record<name: string val: int>> = ({pid: 7, cpu: 2} | ^transpose name val); $rows }";
    let ir_block = single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("root external constant record transpose custom columns should map cleanly");

    assert_eq!(globals.len(), 1);
    let Value::List { vals, .. } = &globals[0].initial_value else {
        panic!(
            "expected list initializer, got {:?}",
            globals[0].initial_value
        );
    };
    let Value::Record { val, .. } = &vals[1] else {
        panic!("expected transposed row, got {:?}", vals[1]);
    };
    assert_eq!(val.get("name").and_then(|v| v.as_str().ok()), Some("cpu"));
    assert_eq!(val.get("val").and_then(|v| v.as_int().ok()), Some(2));
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_root_external_constant_record_transpose_ignore_titles()
 {
    let source = "{|| mut rows: list<record<column0: int>> = ({pid: 7, cpu: 2} | ^transpose --ignore-titles); $rows }";
    let ir_block = single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("root external constant record transpose ignore titles should map cleanly");

    assert_eq!(globals.len(), 1);
    let Value::List { vals, .. } = &globals[0].initial_value else {
        panic!(
            "expected list initializer, got {:?}",
            globals[0].initial_value
        );
    };
    let Value::Record { val, .. } = &vals[0] else {
        panic!("expected transposed row, got {:?}", vals[0]);
    };
    assert_eq!(val.len(), 1);
    assert_eq!(val.get("column0").and_then(|v| v.as_int().ok()), Some(7));
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_record_columns_initializer_arguments() {
    let source =
        "{|| mut fields: list<string> = ({pid: 7, cpu: 2, mem: 4} | columns pid); $fields }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("columns arguments should be rejected");

    assert!(
        err.labels
            .iter()
            .any(|label| label.text.contains("columns") && label.text.contains("arguments")),
        "unexpected labels: {:?}",
        err.labels
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_default_null_initializer() {
    let source = "{|| mut val: int = (null | default 9); $val }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant default null initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0].initial_value.as_int().ok(), Some(9));
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_default_empty_initializer() {
    let source = "{|| mut val: string = (\"\" | default --empty \"fallback\"); $val }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant default --empty initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0].initial_value.as_str().ok(), Some("fallback"));
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_external_default_empty_flag() {
    let source =
        r#"{|| let flag = "--empty"; mut val: string = ("" | ^default $flag "fallback"); $val }"#;
    let ir_block = one_let_then_single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound external default --empty flag should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0].initial_value.as_str().ok(), Some("fallback"));
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_default_missing_record_field() {
    let source = "{|| mut state: record<pid: int cpu: int> = ({pid: 7} | default 2 cpu); $state }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant default missing record field initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::Record { val, .. } => {
            assert_eq!(val.get("pid").and_then(|v| v.as_int().ok()), Some(7));
            assert_eq!(val.get("cpu").and_then(|v| v.as_int().ok()), Some(2));
        }
        other => panic!("expected record initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_default_null_record_field() {
    let source = "{|| mut state: record<pid: int cpu: int> = ({pid: null, cpu: 2} | default 7 pid); $state }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant default null record field initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::Record { val, .. } => {
            assert_eq!(val.get("pid").and_then(|v| v.as_int().ok()), Some(7));
            assert_eq!(val.get("cpu").and_then(|v| v.as_int().ok()), Some(2));
        }
        other => panic!("expected record initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_default_record_field_initializer() {
    let source = r#"{|| let field = "pid"; mut state: record<pid: int cpu: int> = ({cpu: 2} | default 9 $field); $state }"#;
    let ir_block = one_let_then_single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound default record field initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::Record { val, .. } => {
            assert_eq!(val.get("pid").and_then(|v| v.as_int().ok()), Some(9));
            assert_eq!(val.get("cpu").and_then(|v| v.as_int().ok()), Some(2));
        }
        other => panic!("expected record initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_default_missing_value() {
    let source = "{|| mut val: int = (null | default); $val }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("default without a value should be rejected");

    assert!(
        err.labels
            .iter()
            .any(|label| label.text.contains("requires a default value")),
        "unexpected labels: {:?}",
        err.labels
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_record_select_initializer() {
    let source = "{|| mut state: record<mem: int pid: int> = ({pid: 7, cpu: 2, mem: 4} | select mem pid); $state }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant record select initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::Record { val, .. } => {
            assert_eq!(val.len(), 2);
            assert_eq!(val.get_index(0).map(|(name, _)| name.as_str()), Some("mem"));
            assert_eq!(val.get("mem").and_then(|v| v.as_int().ok()), Some(4));
            assert_eq!(val.get_index(1).map(|(name, _)| name.as_str()), Some("pid"));
            assert_eq!(val.get("pid").and_then(|v| v.as_int().ok()), Some(7));
        }
        other => panic!("expected record initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_record_reject_initializer() {
    let source = "{|| mut state: record<pid: int mem: int> = ({pid: 7, cpu: 2, mem: 4} | reject cpu); $state }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant record reject initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::Record { val, .. } => {
            assert_eq!(val.len(), 2);
            assert_eq!(val.get("pid").and_then(|v| v.as_int().ok()), Some(7));
            assert_eq!(val.get("mem").and_then(|v| v.as_int().ok()), Some(4));
            assert!(val.get("cpu").is_none());
        }
        other => panic!("expected record initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_record_select_field_initializer() {
    let source = r#"{|| let field = "pid"; mut state: record<pid: int> = ({pid: 7, cpu: 2} | select $field); $state }"#;
    let ir_block = one_let_then_single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound record select field initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::Record { val, .. } => {
            assert_eq!(val.len(), 1);
            assert_eq!(val.get("pid").and_then(|v| v.as_int().ok()), Some(7));
        }
        other => panic!("expected record initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_record_reject_field_initializer() {
    let source = r#"{|| let field = "cpu"; mut state: record<pid: int> = ({pid: 7, cpu: 2} | reject $field); $state }"#;
    let ir_block = one_let_then_single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound record reject field initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::Record { val, .. } => {
            assert_eq!(val.len(), 1);
            assert_eq!(val.get("pid").and_then(|v| v.as_int().ok()), Some(7));
            assert!(val.get("cpu").is_none());
        }
        other => panic!("expected record initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_missing_record_select_field() {
    let source = "{|| mut state: record<pid: int> = ({pid: 7} | select missing); $state }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("missing record select field should be rejected");

    assert!(
        err.to_string()
            .contains("Unsupported annotated mutable global initializer"),
        "unexpected error: {err}"
    );
    assert!(
        err.labels
            .iter()
            .any(|label| label.text.contains("cannot find record field 'missing'")),
        "unexpected labels: {:?}",
        err.labels
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_record_rename_initializer() {
    let source = "{|| mut state: record<tid: int core: int mem: int> = ({pid: 7, cpu: 2, mem: 4} | rename tid core); $state }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant record rename initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::Record { val, .. } => {
            assert_eq!(val.get("tid").and_then(|v| v.as_int().ok()), Some(7));
            assert_eq!(val.get("core").and_then(|v| v.as_int().ok()), Some(2));
            assert_eq!(val.get("mem").and_then(|v| v.as_int().ok()), Some(4));
            assert!(val.get("pid").is_none());
            assert!(val.get("cpu").is_none());
        }
        other => panic!("expected record initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_record_rename_column_initializer() {
    let source = "{|| mut state: record<tid: int core: int mem: int> = ({pid: 7, cpu: 2, mem: 4} | rename --column ({pid: \"tid\", cpu: \"core\"})); $state }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant record rename --column initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::Record { val, .. } => {
            assert_eq!(val.get("tid").and_then(|v| v.as_int().ok()), Some(7));
            assert_eq!(val.get("core").and_then(|v| v.as_int().ok()), Some(2));
            assert_eq!(val.get("mem").and_then(|v| v.as_int().ok()), Some(4));
            assert!(val.get("pid").is_none());
            assert!(val.get("cpu").is_none());
        }
        other => panic!("expected record initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_record_rename_field_initializer() {
    let source = r#"{|| let target = "tid"; mut state: record<tid: int cpu: int> = ({pid: 7, cpu: 2} | rename $target); $state }"#;
    let ir_block = one_let_then_single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound record rename field initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::Record { val, .. } => {
            assert_eq!(val.get("tid").and_then(|v| v.as_int().ok()), Some(7));
            assert_eq!(val.get("cpu").and_then(|v| v.as_int().ok()), Some(2));
            assert!(val.get("pid").is_none());
        }
        other => panic!("expected record initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_record_rename_column_initializer() {
    let source = r#"{|| let mapping = {pid: "tid"}; mut state: record<tid: int cpu: int> = ({pid: 7, cpu: 2} | rename --column $mapping); $state }"#;
    let ir_block = one_let_then_single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound record rename --column initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::Record { val, .. } => {
            assert_eq!(val.get("tid").and_then(|v| v.as_int().ok()), Some(7));
            assert_eq!(val.get("cpu").and_then(|v| v.as_int().ok()), Some(2));
            assert!(val.get("pid").is_none());
        }
        other => panic!("expected record initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_missing_record_rename_column_field() {
    let source = "{|| mut state: record<tid: int> = ({pid: 7} | rename --column ({missing: \"tid\"})); $state }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("missing record rename --column field should be rejected");

    assert!(
        err.labels
            .iter()
            .any(|label| label.text.contains("cannot find record field 'missing'")),
        "unexpected labels: {:?}",
        err.labels
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_list_first_initializer() {
    let source = "{|| mut val: int = ([7, 2, 4] | first); $val }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant list first initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0].initial_value.as_int().ok(), Some(7));
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_list_last_initializer() {
    let source = "{|| mut val: int = ([7, 2, 4] | last); $val }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant list last initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0].initial_value.as_int().ok(), Some(4));
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_list_first_count_initializer() {
    let source = "{|| mut vals: list<int> = ([7, 2, 4] | first 2); $vals }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant list first count initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let ints = vals
                .iter()
                .map(|value| value.as_int().expect("counted first should keep integers"))
                .collect::<Vec<_>>();
            assert_eq!(ints, vec![7, 2]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_list_last_count_initializer() {
    let source = "{|| mut vals: list<int> = ([7, 2, 4] | last 2); $vals }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant list last count initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let ints = vals
                .iter()
                .map(|value| value.as_int().expect("counted last should keep integers"))
                .collect::<Vec<_>>();
            assert_eq!(ints, vec![2, 4]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_list_first_negative_count() {
    let source = "{|| mut vals: list<int> = ([7, 2, 4] | first -1); $vals }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("negative first count should be rejected");

    assert!(
        err.labels
            .iter()
            .any(|label| label.text.contains("count must be non-negative")),
        "unexpected labels: {:?}",
        err.labels
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_list_take_initializer() {
    let source = "{|| mut vals: list<int> = ([7, 2, 4] | take 2); $vals }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant list take initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let ints = vals
                .iter()
                .map(|value| value.as_int().expect("take should keep integers"))
                .collect::<Vec<_>>();
            assert_eq!(ints, vec![7, 2]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_list_skip_default_initializer() {
    let source = "{|| mut vals: list<int> = ([7, 2, 4] | skip); $vals }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant list skip initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let ints = vals
                .iter()
                .map(|value| value.as_int().expect("skip should keep integers"))
                .collect::<Vec<_>>();
            assert_eq!(ints, vec![2, 4]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_list_drop_initializer() {
    let source = "{|| mut vals: list<int> = ([7, 2, 4] | drop 1); $vals }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant list drop initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let ints = vals
                .iter()
                .map(|value| value.as_int().expect("drop should keep integers"))
                .collect::<Vec<_>>();
            assert_eq!(ints, vec![7, 2]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_list_take_missing_count() {
    let source = "{|| mut vals: list<int> = ([7, 2, 4] | take); $vals }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("take without a count should be rejected");

    assert!(
        err.labels
            .iter()
            .any(|label| label.text.contains("requires exactly one count")),
        "unexpected labels: {:?}",
        err.labels
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_list_reverse_initializer() {
    let source = "{|| mut vals: list<int> = ([7, 2, 4] | reverse); $vals }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant list reverse initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let ints = vals
                .iter()
                .map(|value| value.as_int().expect("reverse should keep integers"))
                .collect::<Vec<_>>();
            assert_eq!(ints, vec![4, 2, 7]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_list_uniq_initializer() {
    let source = "{|| mut vals: list<int> = ([7, 2, 7, 4, 2] | uniq); $vals }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant list uniq initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let ints = vals
                .iter()
                .map(|value| value.as_int().expect("uniq should keep integers"))
                .collect::<Vec<_>>();
            assert_eq!(ints, vec![7, 2, 4]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_list_reverse_arguments() {
    let source = "{|| mut vals: list<int> = ([7, 2, 4] | reverse 1); $vals }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("reverse arguments should be rejected");

    assert!(
        err.labels
            .iter()
            .any(|label| label.text.contains("reverse") && label.text.contains("arguments")),
        "unexpected labels: {:?}",
        err.labels
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_list_compact_initializer() {
    let source = "{|| mut vals: list<int> = ([7, null, 2] | compact); $vals }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant list compact initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let ints = vals
                .iter()
                .map(|value| value.as_int().expect("compact should keep integers"))
                .collect::<Vec<_>>();
            assert_eq!(ints, vec![7, 2]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_list_compact_empty_initializer() {
    let source =
        "{|| mut vals: list<string> = ([\"\", \"a\", null, \"\"] | compact --empty); $vals }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant list compact --empty initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            assert_eq!(vals.len(), 1);
            assert_eq!(vals[0].as_str().ok(), Some("a"));
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_record_list_compact_column_initializer()
{
    let source = "{|| mut vals: list<record<pid: int ok: bool>> = ([{pid: 7, ok: true}, {pid: 8, ok: null}, {pid: 9}] | compact ok); $vals }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant record-list compact column initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            assert_eq!(vals.len(), 1);
            let Value::Record { val, .. } = &vals[0] else {
                panic!("expected compacted item to be a record, got {:?}", vals[0]);
            };
            assert_eq!(
                val.get("pid").and_then(|value| value.as_int().ok()),
                Some(7)
            );
            assert_eq!(
                val.get("ok").and_then(|value| value.as_bool().ok()),
                Some(true)
            );
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_record_list_compact_column_initializer()
 {
    let source = r#"{|| let field = "ok"; mut vals: list<record<pid: int ok: bool>> = ([{pid: 7, ok: true}, {pid: 8, ok: null}] | compact $field); $vals }"#;
    let ir_block = one_let_then_single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound record-list compact column initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            assert_eq!(vals.len(), 1);
            let Value::Record { val, .. } = &vals[0] else {
                panic!("expected compacted item to be a record, got {:?}", vals[0]);
            };
            assert_eq!(
                val.get("pid").and_then(|value| value.as_int().ok()),
                Some(7)
            );
            assert_eq!(
                val.get("ok").and_then(|value| value.as_bool().ok()),
                Some(true)
            );
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_compact_column_on_non_record_list() {
    let source = "{|| mut vals: list<int> = ([7, 2, 4] | compact pid); $vals }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("compact column arguments on non-record lists should be rejected");

    assert!(
        err.labels
            .iter()
            .any(|label| label.text.contains("column arguments for non-record lists")),
        "unexpected labels: {:?}",
        err.labels
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_list_sort_initializer() {
    let source = "{|| mut vals: list<int> = ([7, 2, 4] | sort); $vals }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant list sort initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let ints = vals
                .iter()
                .map(|value| value.as_int().expect("sort should keep integers"))
                .collect::<Vec<_>>();
            assert_eq!(ints, vec![2, 4, 7]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_list_sort_reverse_initializer() {
    let source = "{|| mut vals: list<string> = ([\"a\", \"c\", \"b\"] | sort --reverse); $vals }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant list sort --reverse initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let strings = vals
                .iter()
                .map(|value| value.as_str().expect("sort should keep strings"))
                .collect::<Vec<_>>();
            assert_eq!(strings, vec!["c", "b", "a"]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_external_sort_reverse_flag() {
    let source = r#"{|| let flag = "--reverse"; mut vals: list<string> = (["a", "c", "b"] | ^sort $flag); $vals }"#;
    let ir_block = one_let_then_single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound external sort --reverse flag should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let strings = vals
                .iter()
                .map(|value| value.as_str().expect("sort should keep strings"))
                .collect::<Vec<_>>();
            assert_eq!(strings, vec!["c", "b", "a"]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_list_sort_mixed_types() {
    let source = "{|| mut vals: list<int> = ([1, \"a\"] | sort); $vals }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("mixed sort keys should be rejected");

    assert!(
        err.labels
            .iter()
            .any(|label| label.text.contains("one comparable type")),
        "unexpected labels: {:?}",
        err.labels
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_list_find_initializer() {
    let source = "{|| mut vals: list<int> = ([7, 2, 7, 4] | find 7); $vals }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant list find initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let ints = vals
                .iter()
                .map(|value| value.as_int().expect("find should keep integers"))
                .collect::<Vec<_>>();
            assert_eq!(ints, vec![7, 7]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_constant_list_find_initializer() {
    let source = "{|| let needle = \"a\"; mut vals: list<string> = ([\"a\", \"b\", \"a\"] | find $needle); $vals }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(10),
                src: RegId::new(0),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(1),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 4],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 4],
        comments: vec!["let".into(), "let".into(), "".into(), "".into()],
        register_count: 2,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound constant list find initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let strings = vals
                .iter()
                .map(|value| value.as_str().expect("find should keep strings"))
                .collect::<Vec<_>>();
            assert_eq!(strings, vec!["a", "a"]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_list_find_missing_needle() {
    let source = "{|| mut vals: list<int> = ([7, 2, 4] | find); $vals }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("find without a needle should be rejected");

    assert!(
        err.labels
            .iter()
            .any(|label| label.text.contains("requires exactly one search argument")),
        "unexpected labels: {:?}",
        err.labels
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_fill_initializer() {
    let source = r#"{|| mut value: string = ("ab" | fill --width 5 --alignment right --character "0"); $value }"#;
    let ir_block = single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant fill initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0].initial_value.as_str().ok(), Some("000ab"));
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_fill_list_initializer() {
    let source = r#"{|| mut vals: list<string> = ([1, "ab"] | fill --width 3 --alignment right --character "0"); $vals }"#;
    let ir_block = single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant fill list initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let strings = vals
                .iter()
                .map(|value| value.as_str().expect("fill should produce strings"))
                .collect::<Vec<_>>();
            assert_eq!(strings, vec!["001", "0ab"]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_external_fill_options() {
    let source = r#"{|| let opts = {width: 5, alignment: "right", character: "0"}; mut value: string = ("ab" | ^fill --width $opts.width --alignment $opts.alignment --character $opts.character); $value }"#;
    let ir_block = one_let_then_single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound external fill options should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0].initial_value.as_str().ok(), Some("000ab"));
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_math_sqrt_fill_initializer() {
    let source = r#"{|| mut value: string = (9 | math sqrt | fill --width 4 --alignment right --character "0"); $value }"#;
    let ir_block = single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant math sqrt result should feed fill cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0].initial_value.as_str().ok(), Some("0003"));
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_math_sqrt_str_join_initializer() {
    let source = r#"{|| mut value: string = ([2.25, 6.25] | math sqrt | str join ","); $value }"#;
    let ir_block = single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant math sqrt list result should feed str join cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0].initial_value.as_str().ok(), Some("1.5,2.5"));
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_external_math_sqrt_fill_initializer() {
    let source = r#"{|| let root = (9 | ^math sqrt); mut value: string = ($root | fill --width 4 --alignment right --character "0"); $value }"#;
    let ir_block = one_let_then_single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound external math sqrt result should feed fill cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0].initial_value.as_str().ok(), Some("0003"));
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_negative_constant_math_sqrt_input() {
    let source = r#"{|| mut value: string = (-1 | math sqrt | fill); $value }"#;
    let ir_block = single_annotated_global_return_ir_block();

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("math sqrt should reject negative input");

    assert!(
        format!("{err:?}").contains("requires non-negative input"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_math_float_unary_degrees_fill() {
    let source = r#"{|| mut value: string = (90 | math sin --degrees | fill --width 3 --alignment right --character "0"); $value }"#;
    let ir_block = single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant math float unary result should feed fill cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0].initial_value.as_str().ok(), Some("001"));
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_math_float_unary_list_str_join() {
    let source = r#"{|| mut value: string = ([0, 0] | math exp | str join ","); $value }"#;
    let ir_block = single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant math float unary list result should feed str join cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0].initial_value.as_str().ok(), Some("1.0,1.0"));
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_external_constant_math_float_unary_degrees_fill()
{
    let source = r#"{|| mut value: string = (90 | ^math sin --degrees | fill --width 3 --alignment right --character "0"); $value }"#;
    let ir_block = single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("external constant math float unary result should feed fill cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0].initial_value.as_str().ok(), Some("001"));
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_math_float_unary_domain() {
    let source = r#"{|| mut value: string = (0 | math ln | fill); $value }"#;
    let ir_block = single_annotated_global_return_ir_block();

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("math ln should reject non-positive input");

    assert!(
        format!("{err:?}").contains("requires positive input"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_math_log_fill_initializer() {
    let source = r#"{|| mut value: string = (100 | math log 10 | fill --width 4 --alignment right --character "0"); $value }"#;
    let ir_block = single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant math log result should feed fill cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0].initial_value.as_str().ok(), Some("0002"));
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_math_log_list_str_join_initializer() {
    let source = r#"{|| mut value: string = ([16, 8, 4] | math log 2 | str join ","); $value }"#;
    let ir_block = single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant math log list result should feed str join cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0].initial_value.as_str().ok(), Some("4.0,3.0,2.0"));
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_external_constant_math_log_fill_initializer() {
    let source = r#"{|| mut value: string = (100 | ^math log 10 | fill --width 4 --alignment right --character "0"); $value }"#;
    let ir_block = single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("external constant math log result should feed fill cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0].initial_value.as_str().ok(), Some("0002"));
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_math_log_invalid_base() {
    let source = r#"{|| mut value: string = (100 | math log 1 | fill); $value }"#;
    let ir_block = single_annotated_global_return_ir_block();

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("math log should reject base 1");

    assert!(
        format!("{err:?}").contains("base must be positive and not 1"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_math_log_invalid_input() {
    let source = r#"{|| mut value: string = (0 | math log 10 | fill); $value }"#;
    let ir_block = single_annotated_global_return_ir_block();

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("math log should reject non-positive input");

    assert!(
        format!("{err:?}").contains("requires positive input"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_length_initializer() {
    let source = "{|| mut count: int = ([7, 2, 4] | length); $count }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant length initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_int()
            .expect("length should produce an integer"),
        3
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_binary_length_initializer() {
    let source = "{|| mut count: int = (0x[01 02 03 04] | length); $count }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant binary length initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_int()
            .expect("binary length should produce an integer"),
        4
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_bytes_length_initializer() {
    let source = "{|| mut count: int = (0x[01 02 03 04] | bytes length); $count }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant bytes length initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_int()
            .expect("bytes length should produce an integer"),
        4
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_bytes_length_list_initializer() {
    let source =
        "{|| mut counts: list<int> = ([0x[01 02], 0x[03], 0x[]] | bytes length); $counts }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant bytes length list initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let lengths = vals
                .iter()
                .map(|value| value.as_int().expect("bytes length should produce ints"))
                .collect::<Vec<_>>();
            assert_eq!(lengths, vec![2, 1, 0]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_bytes_at_initializers() {
    let cases = [
        (
            "{|| mut sliced: binary = (0x[33 44 55 10 01 13 10] | bytes at 3..5); $sliced }",
            vec![0x10, 0x01, 0x13],
            "bytes at should honor inclusive end ranges",
        ),
        (
            "{|| mut sliced: binary = (0x[33 44 55 10 01 13 10] | bytes at 3..<4); $sliced }",
            vec![0x10],
            "bytes at should honor exclusive end ranges",
        ),
        (
            "{|| mut sliced: binary = (0x[33 44 55 10 01 13 10] | bytes at ..-4); $sliced }",
            vec![0x33, 0x44, 0x55, 0x10],
            "bytes at should support negative end bounds",
        ),
        (
            "{|| mut sliced: binary = (0x[01 02 03] | bytes at 10..12); $sliced }",
            Vec::<u8>::new(),
            "bytes at should clamp out-of-bounds ranges to empty slices",
        ),
    ];

    for (source, expected, message) in cases {
        let ir_block = IrBlock {
            instructions: vec![
                Instruction::StoreVariable {
                    var_id: VarId::new(11),
                    src: RegId::new(0),
                },
                Instruction::LoadVariable {
                    dst: RegId::new(0),
                    var_id: VarId::new(11),
                },
                Instruction::Return { src: RegId::new(0) },
            ],
            spans: vec![Span::test_data(); 3],
            data: Vec::<u8>::new().into(),
            ast: vec![None; 3],
            comments: vec!["let".into(), "".into(), "".into()],
            register_count: 1,
            file_count: 0,
        };

        let globals =
            super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
                .unwrap_or_else(|err| panic!("{message}: {err:?}"));

        assert_eq!(globals.len(), 1);
        assert_eq!(
            globals[0]
                .initial_value
                .as_binary()
                .expect("bytes at should produce binary"),
            expected.as_slice(),
            "{message}"
        );
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_bytes_at_list_initializer() {
    let source =
        "{|| mut sliced: list<binary> = ([0x[01 02 03], 0x[04 05]] | bytes at 1..); $sliced }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant bytes at list initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let sliced = vals
                .iter()
                .map(|value| {
                    value
                        .as_binary()
                        .expect("bytes at should produce binary")
                        .to_vec()
                })
                .collect::<Vec<_>>();
            assert_eq!(sliced, vec![vec![2, 3], vec![5]]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_constant_bytes_at_range() {
    let source =
        "{|| let range = 1..; mut sliced: binary = (0x[01 02 03] | bytes at $range); $sliced }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(10),
                src: RegId::new(0),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(1),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 4],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 4],
        comments: vec!["let".into(), "let".into(), "".into(), "".into()],
        register_count: 2,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound constant bytes at range should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_binary()
            .expect("bytes at should produce binary"),
        &[2, 3]
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_bytes_add_initializers() {
    let cases = [
        (
            "{|| mut added: binary = (0x[01 04] | bytes add --index 1 0x[02 03]); $added }",
            vec![1, 2, 3, 4],
            "bytes add --index should insert from the start",
        ),
        (
            "{|| mut added: binary = (0x[01 02 05] | bytes add --end --index 1 0x[03 04]); $added }",
            vec![1, 2, 3, 4, 5],
            "bytes add --end --index should insert relative to the end",
        ),
        (
            "{|| mut added: binary = (0x[01 02] | bytes add --index 99 0x[03]); $added }",
            vec![1, 2, 3],
            "bytes add should clamp start-relative indexes to the end",
        ),
    ];

    for (source, expected, message) in cases {
        let ir_block = single_annotated_global_return_ir_block();

        let globals =
            super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
                .unwrap_or_else(|err| panic!("{message}: {err:?}"));

        assert_eq!(globals.len(), 1);
        assert_eq!(
            globals[0]
                .initial_value
                .as_binary()
                .expect("bytes add should produce binary"),
            expected.as_slice(),
            "{message}"
        );
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_bytes_add_list_initializer() {
    let source = "{|| mut added: list<binary> = ([0x[01], 0x[02 03]] | bytes add --index 1 0x[FF]); $added }";
    let ir_block = single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant bytes add list initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let added = vals
                .iter()
                .map(|value| {
                    value
                        .as_binary()
                        .expect("bytes add should produce binary")
                        .to_vec()
                })
                .collect::<Vec<_>>();
            assert_eq!(added, vec![vec![1, 0xff], vec![2, 0xff, 3]]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_constant_bytes_add_args() {
    let source = "{|| let chunk = 0x[AA BB]; let idx = 1; mut added: binary = (0x[01 04] | bytes add --index $idx $chunk); $added }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(10),
                src: RegId::new(0),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(1),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(12),
                src: RegId::new(2),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(12),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 5],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 5],
        comments: vec![
            "let".into(),
            "let".into(),
            "let".into(),
            "".into(),
            "".into(),
        ],
        register_count: 3,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound constant bytes add args should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_binary()
            .expect("bytes add should produce binary"),
        &[1, 0xaa, 0xbb, 4]
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_external_constant_bytes_add_initializer() {
    let source = "{|| mut added: binary = (0x[01 04] | ^bytes add --index=1 0x[02 03]); $added }";
    let ir_block = single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("external constant bytes add initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_binary()
            .expect("bytes add should produce binary"),
        &[1, 2, 3, 4]
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_bytes_add_negative_index() {
    let source = "{|| mut added: binary = (0x[01 02] | bytes add --index -1 0x[03]); $added }";
    let ir_block = single_annotated_global_return_ir_block();

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("negative bytes add index should be rejected");

    assert!(
        err.labels
            .iter()
            .any(|label| label.text.contains("bytes add --index")
                && label.text.contains("non-negative")),
        "unexpected labels: {:?}",
        err.labels
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_bytes_build_initializers() {
    let cases = [
        (
            "{|| mut built: binary = (bytes build); $built }",
            Vec::<u8>::new(),
            "bytes build without arguments should produce empty binary",
        ),
        (
            "{|| mut built: binary = (bytes build 1 0x[02 03] 255); $built }",
            vec![1, 2, 3, 255],
            "bytes build should concatenate byte integers and binary chunks",
        ),
    ];

    for (source, expected, message) in cases {
        let ir_block = IrBlock {
            instructions: vec![
                Instruction::StoreVariable {
                    var_id: VarId::new(11),
                    src: RegId::new(0),
                },
                Instruction::LoadVariable {
                    dst: RegId::new(0),
                    var_id: VarId::new(11),
                },
                Instruction::Return { src: RegId::new(0) },
            ],
            spans: vec![Span::test_data(); 3],
            data: Vec::<u8>::new().into(),
            ast: vec![None; 3],
            comments: vec!["let".into(), "".into(), "".into()],
            register_count: 1,
            file_count: 0,
        };

        let globals =
            super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
                .unwrap_or_else(|err| panic!("{message}: {err:?}"));

        assert_eq!(globals.len(), 1);
        assert_eq!(
            globals[0]
                .initial_value
                .as_binary()
                .expect("bytes build should produce binary"),
            expected.as_slice(),
            "{message}"
        );
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_constant_bytes_build_chunk() {
    let source =
        "{|| let chunk = 0x[03 04]; mut built: binary = (bytes build 1 $chunk 255); $built }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(10),
                src: RegId::new(0),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(1),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 4],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 4],
        comments: vec!["let".into(), "let".into(), "".into(), "".into()],
        register_count: 2,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound constant bytes build chunk should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_binary()
            .expect("bytes build should produce binary"),
        &[1, 3, 4, 255]
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_bytes_build_out_of_range_byte() {
    let source = "{|| mut built: binary = (bytes build 256); $built }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("out-of-range bytes build byte should be rejected");

    assert!(
        format!("{err:?}").contains("out of range"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_bytes_collect_initializers() {
    let cases = [
        (
            "{|| mut collected: binary = ([0x[11], 0x[13 15]] | bytes collect); $collected }",
            vec![0x11, 0x13, 0x15],
            "bytes collect should concatenate binary list items",
        ),
        (
            "{|| mut collected: binary = ([0x[11], 0x[33], 0x[44]] | bytes collect 0x[01]); $collected }",
            vec![0x11, 0x01, 0x33, 0x01, 0x44],
            "bytes collect should insert a binary separator",
        ),
    ];

    for (source, expected, message) in cases {
        let ir_block = IrBlock {
            instructions: vec![
                Instruction::StoreVariable {
                    var_id: VarId::new(11),
                    src: RegId::new(0),
                },
                Instruction::LoadVariable {
                    dst: RegId::new(0),
                    var_id: VarId::new(11),
                },
                Instruction::Return { src: RegId::new(0) },
            ],
            spans: vec![Span::test_data(); 3],
            data: Vec::<u8>::new().into(),
            ast: vec![None; 3],
            comments: vec!["let".into(), "".into(), "".into()],
            register_count: 1,
            file_count: 0,
        };

        let globals =
            super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
                .unwrap_or_else(|err| panic!("{message}: {err:?}"));

        assert_eq!(globals.len(), 1);
        assert_eq!(
            globals[0]
                .initial_value
                .as_binary()
                .expect("bytes collect should produce binary"),
            expected.as_slice(),
            "{message}"
        );
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_constant_bytes_collect_separator() {
    let source = "{|| let sep = 0x[00 FF]; mut collected: binary = ([0x[11], 0x[22]] | bytes collect $sep); $collected }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(10),
                src: RegId::new(0),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(1),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 4],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 4],
        comments: vec!["let".into(), "let".into(), "".into(), "".into()],
        register_count: 2,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound constant bytes collect separator should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_binary()
            .expect("bytes collect should produce binary"),
        &[0x11, 0x00, 0xFF, 0x22]
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_bytes_reverse_initializer() {
    let source = "{|| mut reversed: binary = (0x[01 02 03] | bytes reverse); $reversed }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant bytes reverse initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_binary()
            .expect("bytes reverse should produce binary"),
        &[3, 2, 1]
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_bytes_reverse_list_initializer() {
    let source = "{|| mut reversed: list<binary> = ([0x[01 02], 0x[03 04 05], 0x[]] | bytes reverse); $reversed }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant bytes reverse list initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let reversed = vals
                .iter()
                .map(|value| {
                    value
                        .as_binary()
                        .expect("bytes reverse should produce binary")
                        .to_vec()
                })
                .collect::<Vec<_>>();
            assert_eq!(reversed, vec![vec![2, 1], vec![5, 4, 3], vec![]]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_bytes_predicate_initializers() {
    let cases = [
        (
            "{|| mut ok: bool = (0x[01 02 03] | bytes starts-with 0x[01 02]); $ok }",
            true,
            "bytes starts-with should match a binary prefix",
        ),
        (
            "{|| mut ok: bool = (0x[01 02 03] | bytes ends-with 0x[01 02]); $ok }",
            false,
            "bytes ends-with should reject a non-suffix binary pattern",
        ),
        (
            "{|| mut ok: bool = (0x[01 02 03] | bytes ends-with 0x[02 03]); $ok }",
            true,
            "bytes ends-with should match a binary suffix",
        ),
    ];

    for (source, expected, message) in cases {
        let ir_block = IrBlock {
            instructions: vec![
                Instruction::StoreVariable {
                    var_id: VarId::new(11),
                    src: RegId::new(0),
                },
                Instruction::LoadVariable {
                    dst: RegId::new(0),
                    var_id: VarId::new(11),
                },
                Instruction::Return { src: RegId::new(0) },
            ],
            spans: vec![Span::test_data(); 3],
            data: Vec::<u8>::new().into(),
            ast: vec![None; 3],
            comments: vec!["let".into(), "".into(), "".into()],
            register_count: 1,
            file_count: 0,
        };

        let globals =
            super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
                .unwrap_or_else(|err| panic!("{message}: {err:?}"));

        assert_eq!(globals.len(), 1);
        assert_eq!(
            globals[0]
                .initial_value
                .as_bool()
                .expect("bytes predicate should produce a boolean"),
            expected,
            "{message}"
        );
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_bytes_predicate_list_initializer() {
    let source = "{|| mut oks: list<bool> = ([0x[01 02], 0x[02 03], 0x[]] | bytes starts-with 0x[01]); $oks }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant bytes starts-with list initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let oks = vals
                .iter()
                .map(|value| {
                    value
                        .as_bool()
                        .expect("bytes predicate should produce booleans")
                })
                .collect::<Vec<_>>();
            assert_eq!(oks, vec![true, false, false]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_constant_bytes_predicate_pattern() {
    let source = "{|| let pattern = 0x[02 03]; mut ok: bool = (0x[01 02 03] | bytes ends-with $pattern); $ok }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(10),
                src: RegId::new(0),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(1),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 4],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 4],
        comments: vec!["let".into(), "let".into(), "".into(), "".into()],
        register_count: 2,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound constant bytes predicate pattern should map cleanly");

    assert_eq!(globals.len(), 1);
    assert!(
        globals[0]
            .initial_value
            .as_bool()
            .expect("bytes predicate should produce a boolean")
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_bytes_index_of_initializers() {
    let cases = [
        (
            "{|| mut offset: int = (0x[01 02 03 02] | bytes index-of 0x[02]); $offset }",
            1,
            "bytes index-of should return the first matching offset",
        ),
        (
            "{|| mut offset: int = (0x[01 02 03 02] | bytes index-of 0x[02] --end); $offset }",
            3,
            "bytes index-of --end should return the last matching offset",
        ),
        (
            "{|| mut offset: int = (0x[01 02 03] | bytes index-of 0x[04]); $offset }",
            -1,
            "bytes index-of should return -1 for missing patterns",
        ),
    ];

    for (source, expected, message) in cases {
        let ir_block = IrBlock {
            instructions: vec![
                Instruction::StoreVariable {
                    var_id: VarId::new(11),
                    src: RegId::new(0),
                },
                Instruction::LoadVariable {
                    dst: RegId::new(0),
                    var_id: VarId::new(11),
                },
                Instruction::Return { src: RegId::new(0) },
            ],
            spans: vec![Span::test_data(); 3],
            data: Vec::<u8>::new().into(),
            ast: vec![None; 3],
            comments: vec!["let".into(), "".into(), "".into()],
            register_count: 1,
            file_count: 0,
        };

        let globals =
            super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
                .unwrap_or_else(|err| panic!("{message}: {err:?}"));

        assert_eq!(globals.len(), 1);
        assert_eq!(
            globals[0]
                .initial_value
                .as_int()
                .expect("bytes index-of should produce an integer"),
            expected,
            "{message}"
        );
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_bytes_index_of_all_initializer() {
    let source = "{|| mut offsets: list<int> = (0x[01 02 03 02] | bytes index-of 0x[02] --all --end); $offsets }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant bytes index-of --all initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let offsets = vals
                .iter()
                .map(|value| {
                    value
                        .as_int()
                        .expect("bytes index-of --all should produce integers")
                })
                .collect::<Vec<_>>();
            assert_eq!(offsets, vec![3, 1]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_bytes_index_of_list_initializer() {
    let source = "{|| mut offsets: list<int> = ([0x[01 02 03], 0x[02 03 02], 0x[]] | bytes index-of 0x[02] --end); $offsets }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant bytes index-of list initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let offsets = vals
                .iter()
                .map(|value| value.as_int().expect("bytes index-of should produce ints"))
                .collect::<Vec<_>>();
            assert_eq!(offsets, vec![1, 2, -1]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_bytes_index_of_all_list_initializer() {
    let source = "{|| mut offsets: list<list<int>> = ([0x[01 02 03], 0x[02 03 02], 0x[]] | bytes index-of 0x[02] --all); $offsets }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant bytes index-of --all list initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let offsets = vals
                .iter()
                .map(|value| match value {
                    Value::List { vals, .. } => vals
                        .iter()
                        .map(|value| {
                            value
                                .as_int()
                                .expect("bytes index-of --all should produce ints")
                        })
                        .collect::<Vec<_>>(),
                    other => panic!("expected nested list item, got {other:?}"),
                })
                .collect::<Vec<_>>();
            assert_eq!(offsets, vec![vec![1], vec![0, 2], vec![]]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_constant_bytes_index_of_pattern() {
    let source = "{|| let pattern = 0x[02 03]; mut offset: int = (0x[01 02 03 02 03] | bytes index-of $pattern --end); $offset }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(10),
                src: RegId::new(0),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(1),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 4],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 4],
        comments: vec!["let".into(), "let".into(), "".into(), "".into()],
        register_count: 2,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound constant bytes index-of pattern should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_int()
            .expect("bytes index-of should produce an integer"),
        3
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_bytes_index_of_empty_pattern() {
    let source = "{|| mut offset: int = (0x[01 02] | bytes index-of 0x[]); $offset }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("empty bytes index-of pattern should be rejected");

    assert!(
        format!("{err:?}").contains("non-empty binary pattern"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_bytes_remove_initializers() {
    let cases = [
        (
            "{|| mut removed: binary = (0x[01 02 03 02] | bytes remove 0x[02]); $removed }",
            vec![1, 3, 2],
            "bytes remove should remove the first matching pattern",
        ),
        (
            "{|| mut removed: binary = (0x[01 02 03 02] | bytes remove 0x[02] --all); $removed }",
            vec![1, 3],
            "bytes remove --all should remove all non-overlapping matches",
        ),
        (
            "{|| mut removed: binary = (0x[01 02 03 02] | bytes remove 0x[02] --end); $removed }",
            vec![1, 2, 3],
            "bytes remove --end should remove the last matching pattern",
        ),
    ];

    for (source, expected, message) in cases {
        let ir_block = IrBlock {
            instructions: vec![
                Instruction::StoreVariable {
                    var_id: VarId::new(11),
                    src: RegId::new(0),
                },
                Instruction::LoadVariable {
                    dst: RegId::new(0),
                    var_id: VarId::new(11),
                },
                Instruction::Return { src: RegId::new(0) },
            ],
            spans: vec![Span::test_data(); 3],
            data: Vec::<u8>::new().into(),
            ast: vec![None; 3],
            comments: vec!["let".into(), "".into(), "".into()],
            register_count: 1,
            file_count: 0,
        };

        let globals =
            super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
                .unwrap_or_else(|err| panic!("{message}: {err:?}"));

        assert_eq!(globals.len(), 1);
        assert_eq!(
            globals[0]
                .initial_value
                .as_binary()
                .expect("bytes remove should produce binary"),
            expected.as_slice(),
            "{message}"
        );
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_bytes_remove_list_initializer() {
    let source = "{|| mut removed: list<binary> = ([0x[01 02], 0x[03 02], 0x[]] | bytes remove 0x[02]); $removed }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant bytes remove list initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let removed = vals
                .iter()
                .map(|value| {
                    value
                        .as_binary()
                        .expect("bytes remove should produce binary")
                        .to_vec()
                })
                .collect::<Vec<_>>();
            assert_eq!(removed, vec![vec![1], vec![3], vec![]]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_constant_bytes_remove_pattern() {
    let source = "{|| let pattern = 0x[01 01]; mut removed: binary = (0x[01 01 01] | bytes remove $pattern --all); $removed }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(10),
                src: RegId::new(0),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(1),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 4],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 4],
        comments: vec!["let".into(), "let".into(), "".into(), "".into()],
        register_count: 2,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound constant bytes remove pattern should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_binary()
            .expect("bytes remove should produce binary"),
        &[1]
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_bytes_replace_initializers() {
    let cases = [
        (
            "{|| mut replaced: binary = (0x[01 02 03 02] | bytes replace 0x[02] 0x[AA BB]); $replaced }",
            vec![1, 0xAA, 0xBB, 3, 2],
            "bytes replace should replace the first matching pattern",
        ),
        (
            "{|| mut replaced: binary = (0x[01 02 03 02] | bytes replace 0x[02] 0x[AA] --all); $replaced }",
            vec![1, 0xAA, 3, 0xAA],
            "bytes replace --all should replace all non-overlapping matches",
        ),
    ];

    for (source, expected, message) in cases {
        let ir_block = IrBlock {
            instructions: vec![
                Instruction::StoreVariable {
                    var_id: VarId::new(11),
                    src: RegId::new(0),
                },
                Instruction::LoadVariable {
                    dst: RegId::new(0),
                    var_id: VarId::new(11),
                },
                Instruction::Return { src: RegId::new(0) },
            ],
            spans: vec![Span::test_data(); 3],
            data: Vec::<u8>::new().into(),
            ast: vec![None; 3],
            comments: vec!["let".into(), "".into(), "".into()],
            register_count: 1,
            file_count: 0,
        };

        let globals =
            super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
                .unwrap_or_else(|err| panic!("{message}: {err:?}"));

        assert_eq!(globals.len(), 1);
        assert_eq!(
            globals[0]
                .initial_value
                .as_binary()
                .expect("bytes replace should produce binary"),
            expected.as_slice(),
            "{message}"
        );
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_bytes_replace_list_initializer() {
    let source = "{|| mut replaced: list<binary> = ([0x[01 02], 0x[03 02]] | bytes replace 0x[02] 0x[04]); $replaced }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant bytes replace list initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let replaced = vals
                .iter()
                .map(|value| {
                    value
                        .as_binary()
                        .expect("bytes replace should produce binary")
                        .to_vec()
                })
                .collect::<Vec<_>>();
            assert_eq!(replaced, vec![vec![1, 4], vec![3, 4]]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_constant_bytes_replace_args() {
    let source = "{|| let pattern = 0x[01 01]; let replacement = 0x[FF]; mut replaced: binary = (0x[01 01 01] | bytes replace $pattern $replacement --all); $replaced }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(10),
                src: RegId::new(0),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(1),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(12),
                src: RegId::new(2),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(12),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 5],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 5],
        comments: vec![
            "let".into(),
            "let".into(),
            "let".into(),
            "".into(),
            "".into(),
        ],
        register_count: 3,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound constant bytes replace args should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_binary()
            .expect("bytes replace should produce binary"),
        &[0xFF, 1]
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_bytes_transform_empty_pattern() {
    let cases = [
        "{|| mut removed: binary = (0x[01 02] | bytes remove 0x[]); $removed }",
        "{|| mut replaced: binary = (0x[01 02] | bytes replace 0x[] 0x[FF]); $replaced }",
    ];

    for source in cases {
        let ir_block = IrBlock {
            instructions: vec![
                Instruction::StoreVariable {
                    var_id: VarId::new(11),
                    src: RegId::new(0),
                },
                Instruction::LoadVariable {
                    dst: RegId::new(0),
                    var_id: VarId::new(11),
                },
                Instruction::Return { src: RegId::new(0) },
            ],
            spans: vec![Span::test_data(); 3],
            data: Vec::<u8>::new().into(),
            ast: vec![None; 3],
            comments: vec!["let".into(), "".into(), "".into()],
            register_count: 1,
            file_count: 0,
        };

        let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
            .expect_err("empty bytes transform pattern should be rejected");

        assert!(
            format!("{err:?}").contains("non-empty binary pattern"),
            "unexpected error: {err:?}"
        );
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_bytes_split_initializers() {
    let cases = [
        (
            "{|| mut chunks: list<binary> = (0x[66 6F 6F 20 62 61 72 20 62 61 7A 20] | bytes split 0x[20]); $chunks }",
            vec![
                vec![0x66, 0x6F, 0x6F],
                vec![0x62, 0x61, 0x72],
                vec![0x62, 0x61, 0x7A],
                vec![],
            ],
            "bytes split should preserve a trailing empty binary chunk",
        ),
        (
            "{|| mut chunks: list<binary> = (0x[61 2D 2D 62 2D 2D 63] | bytes split \"--\"); $chunks }",
            vec![vec![0x61], vec![0x62], vec![0x63]],
            "bytes split should accept a string separator",
        ),
        (
            "{|| mut chunks: list<binary> = (0x[01 02 03] | bytes split 0x[FF]); $chunks }",
            vec![vec![1, 2, 3]],
            "bytes split should return the original bytes when the separator is missing",
        ),
        (
            "{|| mut chunks: list<binary> = (0x[01 02 02 03] | bytes split 0x[02]); $chunks }",
            vec![vec![1], vec![], vec![3]],
            "bytes split should preserve adjacent empty binary chunks",
        ),
    ];

    for (source, expected, message) in cases {
        let ir_block = IrBlock {
            instructions: vec![
                Instruction::StoreVariable {
                    var_id: VarId::new(11),
                    src: RegId::new(0),
                },
                Instruction::LoadVariable {
                    dst: RegId::new(0),
                    var_id: VarId::new(11),
                },
                Instruction::Return { src: RegId::new(0) },
            ],
            spans: vec![Span::test_data(); 3],
            data: Vec::<u8>::new().into(),
            ast: vec![None; 3],
            comments: vec!["let".into(), "".into(), "".into()],
            register_count: 1,
            file_count: 0,
        };

        let globals =
            super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
                .unwrap_or_else(|err| panic!("{message}: {err:?}"));

        assert_eq!(globals.len(), 1);
        match &globals[0].initial_value {
            Value::List { vals, .. } => {
                let chunks = vals
                    .iter()
                    .map(|value| {
                        value
                            .as_binary()
                            .expect("bytes split should produce binary chunks")
                            .to_vec()
                    })
                    .collect::<Vec<_>>();
                assert_eq!(chunks, expected, "{message}");
            }
            other => panic!("expected list initializer, got {other:?}"),
        }
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_constant_bytes_split_separator() {
    let source = "{|| let sep = 0x[2D 2D]; mut chunks: list<binary> = (0x[61 2D 2D 62] | bytes split $sep); $chunks }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(10),
                src: RegId::new(0),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(1),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 4],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 4],
        comments: vec!["let".into(), "let".into(), "".into(), "".into()],
        register_count: 2,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound constant bytes split separator should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let chunks = vals
                .iter()
                .map(|value| {
                    value
                        .as_binary()
                        .expect("bytes split should produce binary chunks")
                        .to_vec()
                })
                .collect::<Vec<_>>();
            assert_eq!(chunks, vec![vec![0x61], vec![0x62]]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_bytes_split_empty_separator() {
    let cases = [
        "{|| mut chunks: list<binary> = (0x[01 02] | bytes split 0x[]); $chunks }",
        "{|| mut chunks: list<binary> = (0x[01 02] | bytes split \"\"); $chunks }",
    ];

    for source in cases {
        let ir_block = IrBlock {
            instructions: vec![
                Instruction::StoreVariable {
                    var_id: VarId::new(11),
                    src: RegId::new(0),
                },
                Instruction::LoadVariable {
                    dst: RegId::new(0),
                    var_id: VarId::new(11),
                },
                Instruction::Return { src: RegId::new(0) },
            ],
            spans: vec![Span::test_data(); 3],
            data: Vec::<u8>::new().into(),
            ast: vec![None; 3],
            comments: vec!["let".into(), "".into(), "".into()],
            register_count: 1,
            file_count: 0,
        };

        let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
            .expect_err("empty bytes split separator should be rejected");

        assert!(
            format!("{err:?}").contains("non-empty binary pattern"),
            "unexpected error: {err:?}"
        );
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_bits_binary_int_initializers() {
    let cases = [
        (
            "{|| mut out: int = (6 | bits and 3); $out }",
            2,
            "bits and should fold integer inputs",
        ),
        (
            "{|| mut out: int = (5 | bits or 2); $out }",
            7,
            "bits or should fold integer inputs",
        ),
        (
            "{|| mut out: int = (5 | bits xor 3); $out }",
            6,
            "bits xor should fold integer inputs",
        ),
    ];

    for (source, expected, message) in cases {
        let ir_block = IrBlock {
            instructions: vec![
                Instruction::StoreVariable {
                    var_id: VarId::new(11),
                    src: RegId::new(0),
                },
                Instruction::LoadVariable {
                    dst: RegId::new(0),
                    var_id: VarId::new(11),
                },
                Instruction::Return { src: RegId::new(0) },
            ],
            spans: vec![Span::test_data(); 3],
            data: Vec::<u8>::new().into(),
            ast: vec![None; 3],
            comments: vec!["let".into(), "".into(), "".into()],
            register_count: 1,
            file_count: 0,
        };

        let globals =
            super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
                .unwrap_or_else(|err| panic!("{message}: {err:?}"));

        assert_eq!(globals.len(), 1);
        assert_eq!(
            globals[0]
                .initial_value
                .as_int()
                .expect("bits binary command should produce an integer"),
            expected,
            "{message}"
        );
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_bits_binary_bytes_initializers() {
    let cases = [
        (
            "{|| mut out: binary = (0x[CA FE] | bits and 0x[BA BE]); $out }",
            vec![0x8A, 0xBE],
            "bits and should fold binary inputs",
        ),
        (
            "{|| mut out: binary = (0x[CA FE] | bits or 0x[BA BE]); $out }",
            vec![0xFA, 0xFE],
            "bits or should fold binary inputs",
        ),
        (
            "{|| mut out: binary = (0x[CA FE] | bits xor 0x[BA BE]); $out }",
            vec![0x70, 0x40],
            "bits xor should fold binary inputs",
        ),
        (
            "{|| mut out: binary = (0x[CA FE] | bits xor 0x[AA] --endian big); $out }",
            vec![0xCA, 0x54],
            "bits xor should left-pad unequal binary inputs for big endian",
        ),
        (
            "{|| mut out: binary = (0x[CA FE] | bits xor 0x[AA] --endian little); $out }",
            vec![0x60, 0xFE],
            "bits xor should right-pad unequal binary inputs for little endian",
        ),
    ];

    for (source, expected, message) in cases {
        let ir_block = IrBlock {
            instructions: vec![
                Instruction::StoreVariable {
                    var_id: VarId::new(11),
                    src: RegId::new(0),
                },
                Instruction::LoadVariable {
                    dst: RegId::new(0),
                    var_id: VarId::new(11),
                },
                Instruction::Return { src: RegId::new(0) },
            ],
            spans: vec![Span::test_data(); 3],
            data: Vec::<u8>::new().into(),
            ast: vec![None; 3],
            comments: vec!["let".into(), "".into(), "".into()],
            register_count: 1,
            file_count: 0,
        };

        let globals =
            super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
                .unwrap_or_else(|err| panic!("{message}: {err:?}"));

        assert_eq!(globals.len(), 1);
        assert_eq!(
            globals[0]
                .initial_value
                .as_binary()
                .expect("bits binary command should produce binary"),
            expected.as_slice(),
            "{message}"
        );
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_bits_binary_list_initializers() {
    let cases = [
        (
            "{|| mut out: list<int> = ([8, 3, 2] | bits and 2); $out }",
            vec![
                Value::int(0, Span::test_data()),
                Value::int(2, Span::test_data()),
                Value::int(2, Span::test_data()),
            ],
            "bits and should fold integer list inputs",
        ),
        (
            "{|| mut out: list<binary> = ([0x[0F F0], 0x[AA]] | bits xor 0x[FF 00]); $out }",
            vec![
                Value::binary(vec![0xF0, 0xF0], Span::test_data()),
                Value::binary(vec![0x55, 0x00], Span::test_data()),
            ],
            "bits xor should fold binary list inputs",
        ),
    ];

    for (source, expected, message) in cases {
        let ir_block = IrBlock {
            instructions: vec![
                Instruction::StoreVariable {
                    var_id: VarId::new(11),
                    src: RegId::new(0),
                },
                Instruction::LoadVariable {
                    dst: RegId::new(0),
                    var_id: VarId::new(11),
                },
                Instruction::Return { src: RegId::new(0) },
            ],
            spans: vec![Span::test_data(); 3],
            data: Vec::<u8>::new().into(),
            ast: vec![None; 3],
            comments: vec!["let".into(), "".into(), "".into()],
            register_count: 1,
            file_count: 0,
        };

        let globals =
            super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
                .unwrap_or_else(|err| panic!("{message}: {err:?}"));

        assert_eq!(globals.len(), 1);
        match &globals[0].initial_value {
            Value::List { vals, .. } => assert_eq!(vals, &expected, "{message}"),
            other => panic!("expected list initializer, got {other:?}"),
        }
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_constant_bits_binary_args() {
    let source = "{|| let target = 0x[AA]; let endian = \"big\"; mut out: binary = (0x[CA FE] | bits xor $target --endian $endian); $out }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(10),
                src: RegId::new(0),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(1),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(12),
                src: RegId::new(2),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(12),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 5],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 5],
        comments: vec![
            "let".into(),
            "let".into(),
            "let".into(),
            "".into(),
            "".into(),
        ],
        register_count: 3,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound constant bits binary args should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_binary()
            .expect("bits binary command should produce binary"),
        &[0xCA, 0x54]
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_bits_binary_mixed_types() {
    let source = "{|| mut out: binary = (0x[01] | bits and 1); $out }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("mixed bits binary input and target types should be rejected");

    assert!(
        format!("{err:?}").contains("both be integers or both be binaries"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_bits_not_int_initializers() {
    let cases = [
        (
            "{|| mut out: int = (4 | bits not); $out }",
            251,
            "bits not should use auto-width masking for positive integers",
        ),
        (
            "{|| mut out: int = (4 | bits not --signed); $out }",
            -5,
            "bits not --signed should use two's-complement negation",
        ),
        (
            "{|| mut out: int = (4 | bits not --number-bytes 2); $out }",
            65_531,
            "bits not --number-bytes should use the requested mask width",
        ),
        (
            "{|| mut out: int = (-129 | bits not); $out }",
            128,
            "bits not should leave negative integers on the signed path",
        ),
    ];

    for (source, expected, message) in cases {
        let ir_block = IrBlock {
            instructions: vec![
                Instruction::StoreVariable {
                    var_id: VarId::new(11),
                    src: RegId::new(0),
                },
                Instruction::LoadVariable {
                    dst: RegId::new(0),
                    var_id: VarId::new(11),
                },
                Instruction::Return { src: RegId::new(0) },
            ],
            spans: vec![Span::test_data(); 3],
            data: Vec::<u8>::new().into(),
            ast: vec![None; 3],
            comments: vec!["let".into(), "".into(), "".into()],
            register_count: 1,
            file_count: 0,
        };

        let globals =
            super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
                .unwrap_or_else(|err| panic!("{message}: {err:?}"));

        assert_eq!(globals.len(), 1);
        assert_eq!(
            globals[0]
                .initial_value
                .as_int()
                .expect("bits not should produce an integer"),
            expected,
            "{message}"
        );
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_bits_not_binary_initializer() {
    let source =
        "{|| mut out: binary = (0x[FF 00 7F] | bits not --signed --number-bytes 8); $out }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant bits not binary initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_binary()
            .expect("bits not should produce binary"),
        &[0x00, 0xFF, 0x80]
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_bits_not_list_initializers() {
    let cases = [
        (
            "{|| mut out: list<int> = ([4, 256, -129] | bits not); $out }",
            vec![
                Value::int(251, Span::test_data()),
                Value::int(65_279, Span::test_data()),
                Value::int(128, Span::test_data()),
            ],
            "bits not should fold integer list inputs",
        ),
        (
            "{|| mut out: list<binary> = ([0x[FF], 0x[00 7F]] | bits not); $out }",
            vec![
                Value::binary(vec![0x00], Span::test_data()),
                Value::binary(vec![0xFF, 0x80], Span::test_data()),
            ],
            "bits not should fold binary list inputs",
        ),
    ];

    for (source, expected, message) in cases {
        let ir_block = IrBlock {
            instructions: vec![
                Instruction::StoreVariable {
                    var_id: VarId::new(11),
                    src: RegId::new(0),
                },
                Instruction::LoadVariable {
                    dst: RegId::new(0),
                    var_id: VarId::new(11),
                },
                Instruction::Return { src: RegId::new(0) },
            ],
            spans: vec![Span::test_data(); 3],
            data: Vec::<u8>::new().into(),
            ast: vec![None; 3],
            comments: vec!["let".into(), "".into(), "".into()],
            register_count: 1,
            file_count: 0,
        };

        let globals =
            super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
                .unwrap_or_else(|err| panic!("{message}: {err:?}"));

        assert_eq!(globals.len(), 1);
        match &globals[0].initial_value {
            Value::List { vals, .. } => assert_eq!(vals, &expected, "{message}"),
            other => panic!("expected list initializer, got {other:?}"),
        }
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_constant_bits_not_width() {
    let source = "{|| let width = 2; mut out: int = (4 | bits not --number-bytes $width); $out }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(10),
                src: RegId::new(0),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(1),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 4],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 4],
        comments: vec!["let".into(), "let".into(), "".into(), "".into()],
        register_count: 2,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound constant bits not width should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_int()
            .expect("bits not should produce an integer"),
        65_531
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_bits_not_invalid_width() {
    let source = "{|| mut out: int = (4 | bits not --number-bytes 3); $out }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("invalid bits not --number-bytes should be rejected");

    assert!(
        format!("{err:?}").contains("--number-bytes 1, 2, 4, or 8"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_bits_shift_int_initializers() {
    let cases = [
        (
            "{|| mut out: int = (4 | bits shl 1); $out }",
            8,
            "bits shl should fold auto-width integer input",
        ),
        (
            "{|| mut out: int = (-8 | bits shr 1 --signed); $out }",
            -4,
            "bits shr --signed should fold signed integer input",
        ),
        (
            "{|| mut out: int = (255 | bits shr 1 --number-bytes 1); $out }",
            127,
            "bits shr --number-bytes should fold fixed-width integer input",
        ),
        (
            "{|| mut out: int = (127 | bits shl 1 --number-bytes 1 --signed); $out }",
            -2,
            "bits shl --signed --number-bytes should sign-extend fixed-width output",
        ),
    ];

    for (source, expected, message) in cases {
        let ir_block = IrBlock {
            instructions: vec![
                Instruction::StoreVariable {
                    var_id: VarId::new(11),
                    src: RegId::new(0),
                },
                Instruction::LoadVariable {
                    dst: RegId::new(0),
                    var_id: VarId::new(11),
                },
                Instruction::Return { src: RegId::new(0) },
            ],
            spans: vec![Span::test_data(); 3],
            data: Vec::<u8>::new().into(),
            ast: vec![None; 3],
            comments: vec!["let".into(), "".into(), "".into()],
            register_count: 1,
            file_count: 0,
        };

        let globals =
            super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
                .unwrap_or_else(|err| panic!("{message}: {err:?}"));

        assert_eq!(globals.len(), 1);
        assert_eq!(
            globals[0]
                .initial_value
                .as_int()
                .expect("bits shift should produce an integer"),
            expected,
            "{message}"
        );
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_bits_rotate_int_initializers() {
    let cases = [
        (
            "{|| mut out: int = (1 | bits rol 1 --signed); $out }",
            2,
            "bits rol --signed should fold signed integer input",
        ),
        (
            "{|| mut out: int = (1 | bits ror 1 --signed); $out }",
            i64::MIN,
            "bits ror --signed should rotate across the signed 64-bit width",
        ),
        (
            "{|| mut out: int = (1 | bits ror 64 --signed); $out }",
            1,
            "bits ror --signed should accept a full-width rotate",
        ),
        (
            "{|| mut out: int = (1 | bits ror 1 --number-bytes 1 --signed); $out }",
            -128,
            "bits ror --signed --number-bytes should sign-extend fixed-width output",
        ),
    ];

    for (source, expected, message) in cases {
        let ir_block = IrBlock {
            instructions: vec![
                Instruction::StoreVariable {
                    var_id: VarId::new(11),
                    src: RegId::new(0),
                },
                Instruction::LoadVariable {
                    dst: RegId::new(0),
                    var_id: VarId::new(11),
                },
                Instruction::Return { src: RegId::new(0) },
            ],
            spans: vec![Span::test_data(); 3],
            data: Vec::<u8>::new().into(),
            ast: vec![None; 3],
            comments: vec!["let".into(), "".into(), "".into()],
            register_count: 1,
            file_count: 0,
        };

        let globals =
            super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
                .unwrap_or_else(|err| panic!("{message}: {err:?}"));

        assert_eq!(globals.len(), 1);
        assert_eq!(
            globals[0]
                .initial_value
                .as_int()
                .expect("bits rotate should produce an integer"),
            expected,
            "{message}"
        );
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_bits_shift_rotate_binary_initializers()
{
    let cases = [
        (
            "{|| mut out: binary = (0x[4F F4] | bits shl 4); $out }",
            vec![0xFF, 0x40],
            "bits shl should fold binary input",
        ),
        (
            "{|| mut out: binary = (0x[4F F4] | bits shr 4); $out }",
            vec![0x04, 0xFF],
            "bits shr should fold binary input",
        ),
        (
            "{|| mut out: binary = (0x[FF BB 03] | bits ror 10); $out }",
            vec![0xC0, 0xFF, 0xEE],
            "bits ror should fold binary input",
        ),
    ];

    for (source, expected, message) in cases {
        let ir_block = IrBlock {
            instructions: vec![
                Instruction::StoreVariable {
                    var_id: VarId::new(11),
                    src: RegId::new(0),
                },
                Instruction::LoadVariable {
                    dst: RegId::new(0),
                    var_id: VarId::new(11),
                },
                Instruction::Return { src: RegId::new(0) },
            ],
            spans: vec![Span::test_data(); 3],
            data: Vec::<u8>::new().into(),
            ast: vec![None; 3],
            comments: vec!["let".into(), "".into(), "".into()],
            register_count: 1,
            file_count: 0,
        };

        let globals =
            super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
                .unwrap_or_else(|err| panic!("{message}: {err:?}"));

        assert_eq!(globals.len(), 1);
        assert_eq!(
            globals[0]
                .initial_value
                .as_binary()
                .expect("bits shift/rotate should produce binary"),
            expected.as_slice(),
            "{message}"
        );
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_bits_shift_rotate_list_initializers() {
    let cases = [
        (
            "{|| mut out: list<int> = ([4, 3, 2] | bits shl 1); $out }",
            vec![
                Value::int(8, Span::test_data()),
                Value::int(6, Span::test_data()),
                Value::int(4, Span::test_data()),
            ],
            "bits shl should fold integer list input",
        ),
        (
            "{|| mut out: list<int> = ([1, 2] | bits ror 1 --signed); $out }",
            vec![
                Value::int(i64::MIN, Span::test_data()),
                Value::int(1, Span::test_data()),
            ],
            "bits ror --signed should fold integer list input",
        ),
        (
            "{|| mut out: list<binary> = ([0x[4F F4], 0x[12]] | bits rol 4); $out }",
            vec![
                Value::binary(vec![0xFF, 0x44], Span::test_data()),
                Value::binary(vec![0x21], Span::test_data()),
            ],
            "bits rol should fold binary list input",
        ),
    ];

    for (source, expected, message) in cases {
        let ir_block = IrBlock {
            instructions: vec![
                Instruction::StoreVariable {
                    var_id: VarId::new(11),
                    src: RegId::new(0),
                },
                Instruction::LoadVariable {
                    dst: RegId::new(0),
                    var_id: VarId::new(11),
                },
                Instruction::Return { src: RegId::new(0) },
            ],
            spans: vec![Span::test_data(); 3],
            data: Vec::<u8>::new().into(),
            ast: vec![None; 3],
            comments: vec!["let".into(), "".into(), "".into()],
            register_count: 1,
            file_count: 0,
        };

        let globals =
            super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
                .unwrap_or_else(|err| panic!("{message}: {err:?}"));

        assert_eq!(globals.len(), 1);
        match &globals[0].initial_value {
            Value::List { vals, .. } => assert_eq!(vals, &expected, "{message}"),
            other => panic!("expected list initializer, got {other:?}"),
        }
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_constant_bits_shift_rotate_args() {
    let source = "{|| let count = 1; let width = 1; mut out: int = (127 | bits shl $count --number-bytes $width --signed); $out }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(10),
                src: RegId::new(0),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(1),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(12),
                src: RegId::new(2),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(12),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 5],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 5],
        comments: vec![
            "let".into(),
            "let".into(),
            "let".into(),
            "".into(),
            "".into(),
        ],
        register_count: 3,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound constant bits shift/rotate args should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_int()
            .expect("bits shl should produce an integer"),
        -2
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_root_external_constant_bits_shift_rotate() {
    let source = "{|| mut out: int = (4 | ^bits shl 1); $out }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("root external constant bits shift/rotate should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_int()
            .expect("bits shl should produce an integer"),
        8
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_bits_shift_rotate_invalid_count() {
    let source = "{|| mut out: int = (1 | bits ror 65 --signed); $out }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("invalid bits rotate count should be rejected");

    assert!(
        format!("{err:?}").contains("rotate count from 0 through 64"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_math_abs_int_initializers() {
    let cases = [
        (
            "{|| mut out: int = (-42 | math abs); $out }",
            42,
            "math abs should fold negative integer input",
        ),
        (
            "{|| mut out: int = (42 | math abs); $out }",
            42,
            "math abs should preserve non-negative integer input",
        ),
    ];

    for (source, expected, message) in cases {
        let ir_block = IrBlock {
            instructions: vec![
                Instruction::StoreVariable {
                    var_id: VarId::new(11),
                    src: RegId::new(0),
                },
                Instruction::LoadVariable {
                    dst: RegId::new(0),
                    var_id: VarId::new(11),
                },
                Instruction::Return { src: RegId::new(0) },
            ],
            spans: vec![Span::test_data(); 3],
            data: Vec::<u8>::new().into(),
            ast: vec![None; 3],
            comments: vec!["let".into(), "".into(), "".into()],
            register_count: 1,
            file_count: 0,
        };

        let globals =
            super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
                .unwrap_or_else(|err| panic!("{message}: {err:?}"));

        assert_eq!(globals.len(), 1);
        assert_eq!(
            globals[0]
                .initial_value
                .as_int()
                .expect("math abs should produce an integer"),
            expected,
            "{message}"
        );
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_math_abs_list_initializer() {
    let source = "{|| mut out: list<int> = ([-4, 0, 5] | math abs); $out }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant math abs list initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => assert_eq!(
            vals,
            &vec![
                Value::int(4, Span::test_data()),
                Value::int(0, Span::test_data()),
                Value::int(5, Span::test_data()),
            ]
        ),
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_constant_math_abs_input() {
    let source = "{|| let input = -7; mut out: int = ($input | math abs); $out }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(10),
                src: RegId::new(0),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(1),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 4],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 4],
        comments: vec!["let".into(), "let".into(), "".into(), "".into()],
        register_count: 2,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound constant math abs input should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_int()
            .expect("math abs should produce an integer"),
        7
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_root_external_constant_math_abs() {
    let source = "{|| mut out: int = (-9 | ^math abs); $out }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("root external constant math abs should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_int()
            .expect("math abs should produce an integer"),
        9
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_math_abs_float_initializer() {
    let source = "{|| mut out: int = (-1.5 | math abs); $out }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("math abs float output should not materialize as a mutable global");

    assert!(
        format!("{err:?}").contains("result has type float"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_math_abs_non_integer_list_item() {
    let source = "{|| mut out: list<int> = ([-1, \"bad\"] | math abs); $out }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("math abs should reject non-integer list items");

    assert!(
        format!("{err:?}").contains("integer list items"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_math_int_reduce_initializers() {
    let cases = [
        (
            "{|| mut out: int = ([1, -2, 3] | math sum); $out }",
            2,
            "math sum should fold integer list input",
        ),
        (
            "{|| mut out: int = ([1, -2, 3] | math product); $out }",
            -6,
            "math product should fold integer list input",
        ),
        (
            "{|| mut out: int = ([1, -2, 3] | math min); $out }",
            -2,
            "math min should fold integer list input",
        ),
        (
            "{|| mut out: int = ([1, -2, 3] | math max); $out }",
            3,
            "math max should fold integer list input",
        ),
    ];

    for (source, expected, message) in cases {
        let ir_block = IrBlock {
            instructions: vec![
                Instruction::StoreVariable {
                    var_id: VarId::new(11),
                    src: RegId::new(0),
                },
                Instruction::LoadVariable {
                    dst: RegId::new(0),
                    var_id: VarId::new(11),
                },
                Instruction::Return { src: RegId::new(0) },
            ],
            spans: vec![Span::test_data(); 3],
            data: Vec::<u8>::new().into(),
            ast: vec![None; 3],
            comments: vec!["let".into(), "".into(), "".into()],
            register_count: 1,
            file_count: 0,
        };

        let globals =
            super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
                .unwrap_or_else(|err| panic!("{message}: {err:?}"));

        assert_eq!(globals.len(), 1);
        assert_eq!(
            globals[0]
                .initial_value
                .as_int()
                .expect("math integer reduction should produce an integer"),
            expected,
            "{message}"
        );
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_math_min_max_mixed_numeric_integer_result()
 {
    let cases = [
        (
            "{|| mut out: int = ([1, 2.5, 3.5] | math min); $out }",
            1,
            "math min should fold mixed numeric input when the selected value is an integer",
        ),
        (
            "{|| mut out: int = ([1.5, 2.5, 3] | math max); $out }",
            3,
            "math max should fold mixed numeric input when the selected value is an integer",
        ),
        (
            "{|| mut out: int = ([1, 2, 2.0] | math max); $out }",
            2,
            "math max should preserve the existing integer selection on equal numeric values",
        ),
    ];

    for (source, expected, message) in cases {
        let ir_block = IrBlock {
            instructions: vec![
                Instruction::StoreVariable {
                    var_id: VarId::new(11),
                    src: RegId::new(0),
                },
                Instruction::LoadVariable {
                    dst: RegId::new(0),
                    var_id: VarId::new(11),
                },
                Instruction::Return { src: RegId::new(0) },
            ],
            spans: vec![Span::test_data(); 3],
            data: Vec::<u8>::new().into(),
            ast: vec![None; 3],
            comments: vec!["let".into(), "".into(), "".into()],
            register_count: 1,
            file_count: 0,
        };

        let globals =
            super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
                .unwrap_or_else(|err| panic!("{message}: {err:?}"));

        assert_eq!(globals.len(), 1);
        assert_eq!(
            globals[0]
                .initial_value
                .as_int()
                .expect("math min/max should produce an integer"),
            expected,
            "{message}"
        );
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_root_external_constant_math_int_reduce() {
    let source = "{|| mut out: int = ([4, 5, 6] | ^math sum); $out }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("root external constant math int reduction should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_int()
            .expect("math integer reduction should produce an integer"),
        15
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_math_int_reduce_empty_list() {
    let source = "{|| mut out: int = ([] | math sum); $out }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("math integer reduction should reject empty lists");

    assert!(
        format!("{err:?}").contains("non-empty list<int>"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_math_int_reduce_non_integer_item() {
    let source = "{|| mut out: int = ([1, true] | math max); $out }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("math integer reduction should reject non-integer items");

    assert!(
        format!("{err:?}").contains("integer or finite float list items"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_math_min_max_float_result() {
    let source = "{|| mut out: int = ([1.5, 2, 3] | math min); $out }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("math min/max should reject selected float materialization");

    assert!(
        format!("{err:?}").contains("result has type float"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_math_avg_filesize_initializer() {
    let source = "{|| mut out: filesize = ([1000b, 2000b] | math avg); $out }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant math avg filesize initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::Filesize { val, .. } => assert_eq!(val.get(), 1500),
        other => panic!("expected filesize initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_root_external_constant_math_avg_duration() {
    let source = "{|| mut out: duration = ([1sec, 3sec] | ^math avg); $out }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("root external constant math avg duration initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::Duration { val, .. } => assert_eq!(*val, 2_000_000_000),
        other => panic!("expected duration initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_math_unit_reductions() {
    let cases = [
        (
            "{|| mut out: filesize = ([1000b, 2000b] | math sum); $out }",
            3000,
            "math sum should fold homogeneous filesize input",
        ),
        (
            "{|| mut out: filesize = ([3000b, 1000b, 2000b] | math min); $out }",
            1000,
            "math min should fold filesize input",
        ),
        (
            "{|| mut out: filesize = ([1000b, 3000b, 2000b] | math max); $out }",
            3000,
            "math max should fold filesize input",
        ),
    ];

    for (source, expected, message) in cases {
        let ir_block = IrBlock {
            instructions: vec![
                Instruction::StoreVariable {
                    var_id: VarId::new(11),
                    src: RegId::new(0),
                },
                Instruction::LoadVariable {
                    dst: RegId::new(0),
                    var_id: VarId::new(11),
                },
                Instruction::Return { src: RegId::new(0) },
            ],
            spans: vec![Span::test_data(); 3],
            data: Vec::<u8>::new().into(),
            ast: vec![None; 3],
            comments: vec!["let".into(), "".into(), "".into()],
            register_count: 1,
            file_count: 0,
        };

        let globals =
            super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
                .unwrap_or_else(|err| panic!("{message}: {err:?}"));

        assert_eq!(globals.len(), 1);
        match &globals[0].initial_value {
            Value::Filesize { val, .. } => assert_eq!(val.get(), expected, "{message}"),
            other => panic!("expected filesize initializer, got {other:?}"),
        }
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_math_median_unit_initializers() {
    let cases = [
        (
            "{|| mut out: filesize = ([3000b, 1000b, 2000b] | math median); $out }",
            2000,
            "math median should fold odd filesize input",
        ),
        (
            "{|| mut out: filesize = ([1000b, 3000b] | math median); $out }",
            2000,
            "math median should fold even filesize input with integer average",
        ),
    ];

    for (source, expected, message) in cases {
        let ir_block = IrBlock {
            instructions: vec![
                Instruction::StoreVariable {
                    var_id: VarId::new(11),
                    src: RegId::new(0),
                },
                Instruction::LoadVariable {
                    dst: RegId::new(0),
                    var_id: VarId::new(11),
                },
                Instruction::Return { src: RegId::new(0) },
            ],
            spans: vec![Span::test_data(); 3],
            data: Vec::<u8>::new().into(),
            ast: vec![None; 3],
            comments: vec!["let".into(), "".into(), "".into()],
            register_count: 1,
            file_count: 0,
        };

        let globals =
            super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
                .unwrap_or_else(|err| panic!("{message}: {err:?}"));

        assert_eq!(globals.len(), 1);
        match &globals[0].initial_value {
            Value::Filesize { val, .. } => assert_eq!(val.get(), expected, "{message}"),
            other => panic!("expected filesize initializer, got {other:?}"),
        }
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_math_avg_mixed_units() {
    let source = "{|| mut out: filesize = ([1000b, 1sec] | math avg); $out }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("math avg should reject mixed filesize and duration units");

    assert!(
        format!("{err:?}").contains("homogeneous filesize or duration"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_math_product_unit_input() {
    let source = "{|| mut out: filesize = ([1000b, 2000b] | math product); $out }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("math product should reject filesize input");

    assert!(
        format!("{err:?}").contains("does not support filesize or duration"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_math_median_int_initializer() {
    let source = "{|| mut out: int = ([30, 10, 20] | math median); $out }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant math median integer initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_int()
            .expect("math median should produce an integer"),
        20
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_math_median_mixed_numeric_integer_result()
 {
    let source = "{|| mut out: int = ([1.5, 3, 10.5] | math median); $out }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant math median mixed numeric integer result should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_int()
            .expect("math median should produce an integer"),
        3
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_root_external_constant_math_median() {
    let source = "{|| mut out: int = ([9, 7, 8] | ^math median); $out }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("root external constant math median should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_int()
            .expect("math median should produce an integer"),
        8
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_math_median_even_list() {
    let source = "{|| mut out: int = ([1, 3] | math median); $out }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("math median should reject even-length materialized results");

    assert!(
        format!("{err:?}").contains("median has type float"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_math_median_float_result() {
    let source = "{|| mut out: int = ([1.5, 3.5, 10] | math median); $out }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("math median should reject float median materialization");

    assert!(
        format!("{err:?}").contains("median has type float"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_math_median_non_numeric_item() {
    let source = "{|| mut out: int = ([1, \"bad\", 3] | math median); $out }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("math median should reject non-numeric items");

    assert!(
        format!("{err:?}").contains("integer or finite float list items"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_math_mode_sorted_initializer() {
    let source = "{|| mut out: list<int> = ([5, 1, 5, 2, 1] | math mode); $out }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant math mode sorted initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => assert_eq!(
            vals,
            &vec![
                Value::int(1, Span::test_data()),
                Value::int(5, Span::test_data()),
            ]
        ),
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_math_mode_empty_initializer() {
    let source = "{|| mut out: list<int> = ([] | math mode); $out }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant math mode empty initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => assert!(vals.is_empty(), "expected empty list"),
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_root_external_constant_math_mode() {
    let source = "{|| mut out: list<int> = ([3, 3, 4] | ^math mode); $out }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("root external constant math mode should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => assert_eq!(vals, &vec![Value::int(3, Span::test_data())]),
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_math_mode_non_integer_item() {
    let source = "{|| mut out: list<int> = ([1, true] | math mode); $out }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("math mode should reject non-integer list items");

    assert!(
        format!("{err:?}").contains("integer list items"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_math_mode_output_over_capacity() {
    let values = (0..=60)
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let source = format!("{{|| mut out: list<int> = ([{values}] | math mode); $out }}");
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(&source, &ir_block, Span::test_data())
        .expect_err("math mode should reject mode output over the stack-list capacity");

    assert!(
        format!("{err:?}").contains("capacity 60"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_math_rounding_int_initializers() {
    let cases = [
        (
            "{|| mut out: int = (-42 | math ceil); $out }",
            -42,
            "math ceil should preserve integer input",
        ),
        (
            "{|| mut out: int = (42 | math floor); $out }",
            42,
            "math floor should preserve integer input",
        ),
        (
            "{|| mut out: int = (-42 | math round); $out }",
            -42,
            "math round should preserve integer input",
        ),
    ];

    for (source, expected, message) in cases {
        let ir_block = IrBlock {
            instructions: vec![
                Instruction::StoreVariable {
                    var_id: VarId::new(11),
                    src: RegId::new(0),
                },
                Instruction::LoadVariable {
                    dst: RegId::new(0),
                    var_id: VarId::new(11),
                },
                Instruction::Return { src: RegId::new(0) },
            ],
            spans: vec![Span::test_data(); 3],
            data: Vec::<u8>::new().into(),
            ast: vec![None; 3],
            comments: vec!["let".into(), "".into(), "".into()],
            register_count: 1,
            file_count: 0,
        };

        let globals =
            super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
                .unwrap_or_else(|err| panic!("{message}: {err:?}"));

        assert_eq!(globals.len(), 1);
        assert_eq!(
            globals[0]
                .initial_value
                .as_int()
                .expect("math rounding should produce an integer"),
            expected,
            "{message}"
        );
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_math_rounding_float_initializers() {
    let cases = [
        (
            "{|| mut out: int = (1.25 | math ceil); $out }",
            2,
            "math ceil should round positive float input upward",
        ),
        (
            "{|| mut out: int = (-1.25 | math floor); $out }",
            -2,
            "math floor should round negative float input downward",
        ),
        (
            "{|| mut out: int = (-2.5 | math round); $out }",
            -3,
            "math round should round half away from zero",
        ),
    ];

    for (source, expected, message) in cases {
        let ir_block = IrBlock {
            instructions: vec![
                Instruction::StoreVariable {
                    var_id: VarId::new(11),
                    src: RegId::new(0),
                },
                Instruction::LoadVariable {
                    dst: RegId::new(0),
                    var_id: VarId::new(11),
                },
                Instruction::Return { src: RegId::new(0) },
            ],
            spans: vec![Span::test_data(); 3],
            data: Vec::<u8>::new().into(),
            ast: vec![None; 3],
            comments: vec!["let".into(), "".into(), "".into()],
            register_count: 1,
            file_count: 0,
        };

        let globals =
            super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
                .unwrap_or_else(|err| panic!("{message}: {err:?}"));

        assert_eq!(globals.len(), 1);
        assert_eq!(
            globals[0]
                .initial_value
                .as_int()
                .expect("math rounding should produce an integer"),
            expected,
            "{message}"
        );
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_math_rounding_list_initializer() {
    let source = "{|| mut out: list<int> = ([1.25, -1.25, -2.5, 4] | math round); $out }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant math rounding list initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => assert_eq!(
            vals,
            &vec![
                Value::int(1, Span::test_data()),
                Value::int(-1, Span::test_data()),
                Value::int(-3, Span::test_data()),
                Value::int(4, Span::test_data()),
            ]
        ),
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_root_external_constant_math_rounding() {
    let source = "{|| mut out: int = (1.25 | ^math ceil); $out }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("root external constant math rounding should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_int()
            .expect("math rounding should produce an integer"),
        2
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_math_rounding_non_numeric_list_item() {
    let source = "{|| mut out: list<int> = ([1, \"bad\"] | math ceil); $out }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("math rounding should reject non-numeric list items");

    assert!(
        format!("{err:?}").contains("integer or finite float list items"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_math_rounding_precision() {
    let source = "{|| mut out: int = (1.25 | math round --precision 1); $out }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("math round precision should be rejected for mutable global materialization");

    assert!(
        format!("{err:?}").contains("does not accept arguments"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_char_initializers() {
    let cases = [
        (
            "{|| mut glyph: string = (char \"prompt\" \"ignored\" \"1f354\"); $glyph }",
            "\u{25b6}",
            "char named-character form should materialize the named glyph and ignore string extras",
        ),
        (
            "{|| mut glyph: string = (char --unicode \"1F468\" \"200D\" \"1F466\"); $glyph }",
            "\u{1f468}\u{200d}\u{1f466}",
            "char --unicode should materialize joined hexadecimal codepoints",
        ),
        (
            "{|| mut glyph: string = (char --integer 65 66); $glyph }",
            "AB",
            "char --integer should materialize joined integer codepoints",
        ),
    ];

    for (source, expected, message) in cases {
        let ir_block = IrBlock {
            instructions: vec![
                Instruction::StoreVariable {
                    var_id: VarId::new(11),
                    src: RegId::new(0),
                },
                Instruction::LoadVariable {
                    dst: RegId::new(0),
                    var_id: VarId::new(11),
                },
                Instruction::Return { src: RegId::new(0) },
            ],
            spans: vec![Span::test_data(); 3],
            data: Vec::<u8>::new().into(),
            ast: vec![None; 3],
            comments: vec!["let".into(), "".into(), "".into()],
            register_count: 1,
            file_count: 0,
        };

        let globals =
            super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
                .unwrap_or_else(|err| panic!("{message}: {err:?}"));

        assert_eq!(globals.len(), 1);
        assert_eq!(
            globals[0]
                .initial_value
                .as_str()
                .expect("char should produce a string"),
            expected,
            "{message}"
        );
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_char_nul_initializer() {
    let source = "{|| mut glyph: string = (char \"nul\"); $glyph }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("char NUL output should be rejected");

    assert!(
        format!("{err:?}").contains("NUL bytes"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_str_length_initializer() {
    let source = "{|| mut count: int = (\"abcd\" | str length); $count }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant str length initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_int()
            .expect("str length should produce an integer"),
        4
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_str_length_chars_initializer() {
    let source = "{|| mut count: int = (\"abcd\" | str length --chars); $count }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant str length --chars initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_int()
            .expect("str length --chars should produce an integer"),
        4
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_external_str_length_mode_flag() {
    let source =
        "{|| let flag = \"--chars\"; mut count: int = (\"\u{00e9}\" | ^str length $flag); $count }";
    let ir_block = one_let_then_single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound external str length mode flag should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_int()
            .expect("external str length --chars should produce an integer"),
        1
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_str_length_list_initializer() {
    let source = "{|| mut counts: list<int> = ([\"a\", \"bb\", \"\"] | str length); $counts }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant str length list initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let lengths = vals
                .iter()
                .map(|value| value.as_int().expect("str length should produce ints"))
                .collect::<Vec<_>>();
            assert_eq!(lengths, vec![1, 2, 0]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_str_starts_with_initializer() {
    let source = "{|| mut ok: bool = (\"abcdef\" | str starts-with \"abc\"); $ok }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant str starts-with initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert!(
        globals[0]
            .initial_value
            .as_bool()
            .expect("str starts-with should produce a boolean")
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_str_ends_with_ignore_case_initializer()
{
    let source = "{|| mut ok: bool = (\"abCDEF\" | str ends-with \"def\" --ignore-case); $ok }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant str ends-with --ignore-case initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert!(
        globals[0]
            .initial_value
            .as_bool()
            .expect("str ends-with should produce a boolean")
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_str_contains_list_initializer() {
    let source = "{|| mut oks: list<bool> = ([\"alpha\", \"beta\", \"alphabet\"] | str contains \"alpha\"); $oks }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant str contains list initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let values = vals
                .iter()
                .map(|value| value.as_bool().expect("str contains should produce bools"))
                .collect::<Vec<_>>();
            assert_eq!(values, vec![true, false, true]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_constant_str_contains_initializer() {
    let source = "{|| let needle = \"bc\"; mut ok: bool = (\"abcd\" | str contains $needle); $ok }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(10),
                src: RegId::new(0),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(1),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 4],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 4],
        comments: vec!["let".into(), "let".into(), "".into(), "".into()],
        register_count: 2,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound constant str contains initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert!(
        globals[0]
            .initial_value
            .as_bool()
            .expect("str contains should produce a boolean")
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_str_index_of_initializer() {
    let source = "{|| mut index: int = (\"ababa\" | str index-of \"ba\"); $index }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant str index-of initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_int()
            .expect("str index-of should produce an integer"),
        1
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_str_index_of_end_initializer() {
    let source = "{|| mut index: int = (\"ababa\" | str index-of \"ba\" --end); $index }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant str index-of --end initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_int()
            .expect("str index-of should produce an integer"),
        3
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_str_index_of_range_initializer() {
    let source = "{|| mut index: int = (\"abcabc\" | str index-of \"bc\" --range 2..5); $index }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant str index-of --range initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_int()
            .expect("str index-of should produce an integer"),
        4
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_str_index_of_grapheme_initializer() {
    let source = "{|| mut index: int = (\"🇯🇵ほげ ふが ぴよ\" | str index-of \"ふが\" --grapheme-clusters); $index }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant str index-of --grapheme-clusters initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_int()
            .expect("str index-of should produce an integer"),
        4
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_str_index_of_grapheme_range_initializer()
 {
    let source = "{|| mut index: int = (\"ほげ ふが\" | str index-of \"ふ\" --range 6..9 --grapheme-clusters); $index }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant str index-of --grapheme-clusters --range initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_int()
            .expect("str index-of should produce an integer"),
        3
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_str_index_of_list_initializer() {
    let source =
        "{|| mut indexes: list<int> = ([\"ababa\", \"xaba\"] | str index-of \"ba\"); $indexes }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant str index-of list initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let indexes = vals
                .iter()
                .map(|value| value.as_int().expect("str index-of should produce ints"))
                .collect::<Vec<_>>();
            assert_eq!(indexes, vec![1, 2]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_str_replace_initializers() {
    let cases = [
        (
            "{|| mut replaced: string = (\"abcabc\" | str replace \"ab\" \"XY\"); $replaced }",
            "XYcabc",
            "default str replace should replace first match",
        ),
        (
            "{|| mut replaced: string = (\"abcabc\" | str replace \"ab\" \"XY\" --all); $replaced }",
            "XYcXYc",
            "str replace --all should replace every match",
        ),
        (
            "{|| mut replaced: string = (\"abc\" | str replace \"zz\" \"XY\"); $replaced }",
            "abc",
            "str replace should preserve input when pattern is missing",
        ),
        (
            "{|| mut replaced: string = (\"abc123\" | str replace '([a-z]+)([0-9]+)' '${2}-${1}' --regex); $replaced }",
            "123-abc",
            "str replace --regex should expand capture groups",
        ),
        (
            "{|| mut replaced: string = (\"abc123\" | str replace '([a-z]+)([0-9]+)' '${2}-${1}' --regex --no-expand); $replaced }",
            "${2}-${1}",
            "str replace --regex --no-expand should keep replacement literal",
        ),
        (
            "{|| mut replaced: string = (\"a\\nb\\nb\" | str replace '^b' 'X' --multiline --all); $replaced }",
            "a\nX\nX",
            "str replace --multiline --all should replace line-anchored matches",
        ),
    ];

    for (source, expected, message) in cases {
        let ir_block = IrBlock {
            instructions: vec![
                Instruction::StoreVariable {
                    var_id: VarId::new(11),
                    src: RegId::new(0),
                },
                Instruction::LoadVariable {
                    dst: RegId::new(0),
                    var_id: VarId::new(11),
                },
                Instruction::Return { src: RegId::new(0) },
            ],
            spans: vec![Span::test_data(); 3],
            data: Vec::<u8>::new().into(),
            ast: vec![None; 3],
            comments: vec!["let".into(), "".into(), "".into()],
            register_count: 1,
            file_count: 0,
        };

        let globals =
            super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
                .unwrap_or_else(|err| panic!("{message}: {err:?}"));

        assert_eq!(globals.len(), 1);
        assert_eq!(
            globals[0]
                .initial_value
                .as_str()
                .expect("str replace should produce a string"),
            expected,
            "{message}"
        );
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_str_replace_list_initializer() {
    let source = "{|| mut replaced: list<string> = ([\"abc\", \"aba\"] | str replace \"a\" \"z\"); $replaced }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant str replace list initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let replaced = vals
                .iter()
                .map(|value| value.as_str().expect("str replace should produce strings"))
                .collect::<Vec<_>>();
            assert_eq!(replaced, vec!["zbc", "zba"]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_str_distance_initializer() {
    let source = "{|| mut distance: int = (\"nushell\" | str distance \"nutshell\"); $distance }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant str distance initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_int()
            .expect("str distance should produce an integer"),
        1
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_constant_str_distance_initializer() {
    let source = "{|| let compare = \"nutshell\"; mut distance: int = (\"nushell\" | str distance $compare); $distance }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(10),
                src: RegId::new(0),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(1),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 4],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 4],
        comments: vec!["let".into(), "let".into(), "".into(), "".into()],
        register_count: 2,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound constant str distance initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_int()
            .expect("str distance should produce an integer"),
        1
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_str_join_scalar_initializer() {
    let source = "{|| mut joined: string = (\"abc\" | str join \"-\"); $joined }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant str join scalar initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_str()
            .expect("str join should produce a string"),
        "abc"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_str_join_list_initializer() {
    let source = "{|| mut joined: string = ([\"a\", \"b\", \"\"] | str join \"-\"); $joined }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant str join list initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_str()
            .expect("str join should produce a string"),
        "a-b-"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_str_join_mixed_list_initializer() {
    let source = "{|| mut joined: string = ([1, true, null] | str join \"|\"); $joined }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant str join mixed-list initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_str()
            .expect("str join should produce a string"),
        "1|true|"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_constant_str_join_separator() {
    let source =
        "{|| let sep = \":\"; mut joined: string = ([\"a\", \"b\"] | str join $sep); $joined }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(10),
                src: RegId::new(0),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(1),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 4],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 4],
        comments: vec!["let".into(), "let".into(), "".into(), "".into()],
        register_count: 2,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound constant str join separator should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_str()
            .expect("str join should produce a string"),
        "a:b"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_str_stats_initializer() {
    let source = "{|| mut stats: record<lines: int words: int bytes: int chars: int graphemes: int unicode-width: int> = (\"Ame\u{301}lie Amelie\" | str stats); $stats }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant str stats initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::Record { val, .. } => {
            assert_eq!(
                val.get("lines").and_then(|value| value.as_int().ok()),
                Some(1)
            );
            assert_eq!(
                val.get("words").and_then(|value| value.as_int().ok()),
                Some(2)
            );
            assert_eq!(
                val.get("bytes").and_then(|value| value.as_int().ok()),
                Some(15)
            );
            assert_eq!(
                val.get("chars").and_then(|value| value.as_int().ok()),
                Some(14)
            );
            assert_eq!(
                val.get("graphemes").and_then(|value| value.as_int().ok()),
                Some(13)
            );
            assert_eq!(
                val.get("unicode-width")
                    .and_then(|value| value.as_int().ok()),
                Some(13)
            );
        }
        other => panic!("expected record initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_str_stats_unicode_width_initializer() {
    let source = "{|| mut stats: record<lines: int words: int bytes: int chars: int graphemes: int unicode-width: int> = (\"字\\r\\n字\" | str stats); $stats }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant str stats unicode-width initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::Record { val, .. } => {
            assert_eq!(
                val.get("lines").and_then(|value| value.as_int().ok()),
                Some(2)
            );
            assert_eq!(
                val.get("unicode-width")
                    .and_then(|value| value.as_int().ok()),
                Some(5)
            );
        }
        other => panic!("expected record initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_str_expand_initializer() {
    let source = "{|| mut expanded: list<string> = (\"A{b,c}D{e,f}G\" | str expand); $expanded }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant str expand initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let expanded = vals
                .iter()
                .map(|value| value.as_str().expect("str expand should produce strings"))
                .collect::<Vec<_>>();
            assert_eq!(expanded, vec!["AbDeG", "AbDfG", "AcDeG", "AcDfG"]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_str_expand_range_initializer() {
    let source = "{|| mut expanded: list<string> = (\"A{02..04}B\" | str expand); $expanded }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant str expand range initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let expanded = vals
                .iter()
                .map(|value| value.as_str().expect("str expand should produce strings"))
                .collect::<Vec<_>>();
            assert_eq!(expanded, vec!["A02B", "A03B", "A04B"]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_string_transform_initializers() {
    let cases = [
        ("str downcase", "AbC", "abc"),
        ("str upcase", "AbC", "ABC"),
        ("str reverse", "abc", "cba"),
        ("str capitalize", "abc", "Abc"),
        (
            "str camel-case",
            "this-is-the-first-case",
            "thisIsTheFirstCase",
        ),
        (
            "str kebab-case",
            "THIS_IS_THE_SECOND_CASE",
            "this-is-the-second-case",
        ),
        (
            "str pascal-case",
            "this_is_the_second_case",
            "ThisIsTheSecondCase",
        ),
        ("str screaming-snake-case", "NuShell", "NU_SHELL"),
        ("str snake-case", "NuShell", "nu_shell"),
        ("str title-case", "nu-shell", "Nu Shell"),
    ];

    for (command, input, expected) in cases {
        let source =
            format!("{{|| mut transformed: string = (\"{input}\" | {command}); $transformed }}");
        let ir_block = IrBlock {
            instructions: vec![
                Instruction::StoreVariable {
                    var_id: VarId::new(11),
                    src: RegId::new(0),
                },
                Instruction::LoadVariable {
                    dst: RegId::new(0),
                    var_id: VarId::new(11),
                },
                Instruction::Return { src: RegId::new(0) },
            ],
            spans: vec![Span::test_data(); 3],
            data: Vec::<u8>::new().into(),
            ast: vec![None; 3],
            comments: vec!["let".into(), "".into(), "".into()],
            register_count: 1,
            file_count: 0,
        };

        let globals =
            super::map_leading_annotated_mut_globals(&source, &ir_block, Span::test_data())
                .unwrap_or_else(|err| panic!("{command} should map cleanly: {err:?}"));

        assert_eq!(globals.len(), 1);
        assert_eq!(
            globals[0]
                .initial_value
                .as_str()
                .expect("string transform should produce a string"),
            expected,
            "{command} output mismatch"
        );
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_string_transform_list_initializer() {
    let source =
        "{|| mut transformed: list<string> = ([\"Ab\", \"Cd\"] | str downcase); $transformed }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant string transform list initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let transformed = vals
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .expect("string transform should produce strings")
                })
                .collect::<Vec<_>>();
            assert_eq!(transformed, vec!["ab", "cd"]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_str_substring_initializer() {
    let source = "{|| mut sliced: string = (\"abcdef\" | str substring 1..3); $sliced }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant str substring initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_str()
            .expect("str substring should produce a string"),
        "bcd"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_str_substring_negative_end_initializer()
{
    let source = "{|| mut sliced: string = (\"abcdef\" | str substring 1..-2); $sliced }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant str substring negative-end initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_str()
            .expect("str substring should produce a string"),
        "bcde"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_str_substring_grapheme_initializer() {
    let source = "{|| mut sliced: string = (\"🇯🇵ほげ ふが ぴよ\" | str substring 4..5 --grapheme-clusters); $sliced }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant str substring --grapheme-clusters initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_str()
            .expect("str substring should produce a string"),
        "ふが"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_str_substring_list_initializer() {
    let source =
        "{|| mut sliced: list<string> = ([\"abcd\", \"wxyz\"] | str substring 1..2); $sliced }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant str substring list initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let sliced = vals
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .expect("str substring should produce strings")
                })
                .collect::<Vec<_>>();
            assert_eq!(sliced, vec!["bc", "xy"]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_str_substring_external_initializer() {
    let source =
        "{|| mut sliced: string = (\"abcdef\" | str substring 1..3 --utf-8-bytes); $sliced }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant external str substring initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_str()
            .expect("str substring should produce a string"),
        "bcd"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_str_trim_initializer() {
    let source = "{|| mut trimmed: string = (\"  abc  \" | str trim); $trimmed }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant str trim initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_str()
            .expect("str trim should produce a string"),
        "abc"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_external_str_subcommand_initializer() {
    let source = r#"{|| let subcommand = "trim"; mut trimmed: string = ("  abc  " | ^str $subcommand); $trimmed }"#;
    let ir_block = one_let_then_single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound external str subcommand initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_str()
            .expect("external str trim should produce a string"),
        "abc"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_str_trim_left_initializer() {
    let source = "{|| mut trimmed: string = (\"  abc  \" | str trim --left); $trimmed }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant str trim --left initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_str()
            .expect("str trim should produce a string"),
        "abc  "
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_str_trim_right_char_initializer() {
    let source =
        "{|| mut trimmed: string = (\"xxabcxx\" | str trim --right --char \"x\"); $trimmed }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant str trim --right --char initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(
        globals[0]
            .initial_value
            .as_str()
            .expect("str trim should produce a string"),
        "xxabc"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_str_trim_list_initializer() {
    let source = "{|| mut trimmed: list<string> = ([\" ab \", \" cd \"] | str trim); $trimmed }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant str trim list initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let trimmed = vals
                .iter()
                .map(|value| value.as_str().expect("str trim should produce strings"))
                .collect::<Vec<_>>();
            assert_eq!(trimmed, vec!["ab", "cd"]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_split_chars_initializer() {
    let source = "{|| mut chars: list<string> = (\"abc\" | split chars); $chars }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant split chars initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let chars = vals
                .iter()
                .map(|value| value.as_str().expect("split chars should produce strings"))
                .collect::<Vec<_>>();
            assert_eq!(chars, vec!["a", "b", "c"]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_split_chars_grapheme_initializer() {
    let source =
        "{|| mut chars: list<string> = (\"a🇯🇵b\" | split chars --grapheme-clusters); $chars }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant split chars --grapheme-clusters initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let chars = vals
                .iter()
                .map(|value| value.as_str().expect("split chars should produce strings"))
                .collect::<Vec<_>>();
            assert_eq!(chars, vec!["a", "🇯🇵", "b"]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_split_chars_list_initializer() {
    let source = "{|| mut chars: list<list<string>> = ([\"ab\", \"cd\"] | split chars); $chars }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant split chars list initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let nested = vals
                .iter()
                .map(|value| match value {
                    Value::List { vals, .. } => vals
                        .iter()
                        .map(|value| value.as_str().expect("split chars should produce strings"))
                        .collect::<Vec<_>>(),
                    other => panic!("expected nested list item, got {other:?}"),
                })
                .collect::<Vec<_>>();
            assert_eq!(nested, vec![vec!["a", "b"], vec!["c", "d"]]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_split_list_initializer() {
    let source = "{|| mut groups: list<list<string>> = ([\"a\", \"b\", \"x\", \"c\"] | split list \"x\"); $groups }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant split list initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let groups = vals
                .iter()
                .map(|value| match value {
                    Value::List { vals, .. } => vals
                        .iter()
                        .map(|value| value.as_str().expect("split list should produce strings"))
                        .collect::<Vec<_>>(),
                    other => panic!("expected nested list item, got {other:?}"),
                })
                .collect::<Vec<_>>();
            assert_eq!(groups, vec![vec!["a", "b"], vec!["c"]]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_split_list_after_initializer() {
    let source = "{|| mut groups: list<list<string>> = ([\"a\", \"x\", \"c\"] | split list \"x\" --split after); $groups }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant split list --split after initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let groups = vals
                .iter()
                .map(|value| match value {
                    Value::List { vals, .. } => vals
                        .iter()
                        .map(|value| value.as_str().expect("split list should produce strings"))
                        .collect::<Vec<_>>(),
                    other => panic!("expected nested list item, got {other:?}"),
                })
                .collect::<Vec<_>>();
            assert_eq!(groups, vec![vec!["a", "x"], vec!["c"]]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_split_list_regex_initializer() {
    let source = r#"{|| mut groups: list<list<string>> = (["a", "x1", "b", "x22", "c"] | split list 'x\d+' --regex --split before); $groups }"#;
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant split list --regex initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let groups = vals
                .iter()
                .map(|value| match value {
                    Value::List { vals, .. } => vals
                        .iter()
                        .map(|value| value.as_str().expect("split list should produce strings"))
                        .collect::<Vec<_>>(),
                    other => panic!("expected nested list item, got {other:?}"),
                })
                .collect::<Vec<_>>();
            assert_eq!(groups, vec![vec!["a"], vec!["x1", "b"], vec!["x22", "c"]]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_split_row_initializer() {
    let source = "{|| mut rows: list<string> = (\"a,b,c\" | split row \",\"); $rows }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant split row initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let rows = vals
                .iter()
                .map(|value| value.as_str().expect("split row should produce strings"))
                .collect::<Vec<_>>();
            assert_eq!(rows, vec!["a", "b", "c"]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_split_row_list_initializer() {
    let source = "{|| mut rows: list<string> = ([\"a,b\", \"c,d\"] | split row \",\"); $rows }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant split row list initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let rows = vals
                .iter()
                .map(|value| value.as_str().expect("split row should produce strings"))
                .collect::<Vec<_>>();
            assert_eq!(rows, vec!["a", "b", "c", "d"]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_split_row_regex_number_initializer() {
    let source = r#"{|| mut rows: list<string> = ("a1b22c333" | split row '\d+' --regex --number 2); $rows }"#;
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant split row --regex --number initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let rows = vals
                .iter()
                .map(|value| value.as_str().expect("split row should produce strings"))
                .collect::<Vec<_>>();
            assert_eq!(rows, vec!["a", "b22c333"]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_split_words_initializer() {
    let source = "{|| mut words: list<string> = (\"hello, to the world!\" | split words); $words }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant split words initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let words = vals
                .iter()
                .map(|value| value.as_str().expect("split words should produce strings"))
                .collect::<Vec<_>>();
            assert_eq!(words, vec!["hello", "to", "the", "world"]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_split_words_grapheme_min_initializer() {
    let source = "{|| mut words: list<string> = (\"a é ee\" | split words --min-word-length 2 --grapheme-clusters); $words }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant split words --grapheme-clusters initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let words = vals
                .iter()
                .map(|value| value.as_str().expect("split words should produce strings"))
                .collect::<Vec<_>>();
            assert_eq!(words, vec!["ee"]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_split_words_list_initializer() {
    let source =
        "{|| mut words: list<list<string>> = ([\"a b\", \"c d e\"] | split words); $words }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant split words list initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let nested = vals
                .iter()
                .map(|value| match value {
                    Value::List { vals, .. } => vals
                        .iter()
                        .map(|value| value.as_str().expect("split words should produce strings"))
                        .collect::<Vec<_>>(),
                    other => panic!("expected nested list item, got {other:?}"),
                })
                .collect::<Vec<_>>();
            assert_eq!(nested, vec![vec!["a", "b"], vec!["c", "d", "e"]]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_empty_predicate_initializer() {
    let source = "{|| mut empty: bool = (\"\" | is-empty); $empty }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant is-empty initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert!(
        globals[0]
            .initial_value
            .as_bool()
            .expect("is-empty should produce a boolean")
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_non_empty_predicate_initializer() {
    let source = "{|| mut non_empty: bool = ({ a: 1 } | is-not-empty); $non_empty }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant is-not-empty initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert!(
        globals[0]
            .initial_value
            .as_bool()
            .expect("is-not-empty should produce a boolean")
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_split_list_invalid_mode() {
    let source = "{|| mut groups: list<list<string>> = ([\"a\"] | split list \"x\" --split middle); $groups }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("split list with invalid split mode should be rejected");

    assert!(
        err.labels
            .iter()
            .any(|label| label.text.contains("must be 'on', 'before', or 'after'")),
        "unexpected labels: {:?}",
        err.labels
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_split_row_missing_separator() {
    let source = "{|| mut rows: list<string> = (\"a,b\" | split row --regex); $rows }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("split row without a separator should be rejected");

    assert!(
        err.labels
            .iter()
            .any(|label| label.text.contains("requires exactly one separator")),
        "unexpected labels: {:?}",
        err.labels
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_split_words_mode_without_min() {
    let source =
        "{|| mut words: list<string> = (\"a b\" | split words --grapheme-clusters); $words }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("split words mode flags without min length should be rejected");

    assert!(
        err.labels
            .iter()
            .any(|label| label.text.contains("require `--min-word-length`")),
        "unexpected labels: {:?}",
        err.labels
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_split_chars_conflicting_flags() {
    let source = "{|| mut chars: list<string> = (\"abc\" | split chars --code-points --grapheme-clusters); $chars }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("split chars with conflicting modes should be rejected");

    assert!(
        err.labels
            .iter()
            .any(|label| label.text.contains("not both")),
        "unexpected labels: {:?}",
        err.labels
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_str_stats_arguments() {
    let source = "{|| mut stats: record<lines: int words: int bytes: int chars: int graphemes: int unicode-width: int> = (\"abc\" | str stats --all); $stats }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("str stats with arguments should be rejected");

    assert!(
        err.labels
            .iter()
            .any(|label| label.text.contains("does not accept arguments")),
        "unexpected labels: {:?}",
        err.labels
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_str_expand_without_braces() {
    let source = "{|| mut expanded: list<string> = (\"abc\" | str expand); $expanded }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("str expand without braces should be rejected");

    assert!(
        err.labels
            .iter()
            .any(|label| label.text.contains("requires at least one brace")),
        "unexpected labels: {:?}",
        err.labels
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_string_transform_arguments() {
    let source = "{|| mut transformed: string = (\"abc\" | str downcase --all); $transformed }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("string transforms with arguments should be rejected");

    assert!(
        err.labels
            .iter()
            .any(|label| label.text.contains("does not accept arguments")),
        "unexpected labels: {:?}",
        err.labels
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_str_trim_multi_char_argument() {
    let source = "{|| mut trimmed: string = (\"xxabcxx\" | str trim --char \"xx\"); $trimmed }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("str trim with multi-character --char should be rejected");

    assert!(
        err.labels
            .iter()
            .any(|label| label.text.contains("exactly one character")),
        "unexpected labels: {:?}",
        err.labels
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_str_join_extra_separator() {
    let source = "{|| mut joined: string = ([\"a\", \"b\"] | str join \":\" \";\"); $joined }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("str join with multiple separators should be rejected");

    assert!(
        err.labels
            .iter()
            .any(|label| label.text.contains("accepts at most one separator")),
        "unexpected labels: {:?}",
        err.labels
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_str_distance_missing_compare() {
    let source = "{|| mut distance: int = (\"nushell\" | str distance); $distance }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("str distance without a compare string should be rejected");

    assert!(
        err.labels
            .iter()
            .any(|label| label.text.contains("requires exactly one compare-string")),
        "unexpected labels: {:?}",
        err.labels
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_str_contains_mixed_list_initializer() {
    let source = "{|| mut oks: list<bool> = ([\"alpha\", 1] | str contains \"alpha\"); $oks }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("str contains on a mixed list should be rejected");

    assert!(
        err.labels
            .iter()
            .any(|label| label.text.contains("requires string list items")),
        "unexpected labels: {:?}",
        err.labels
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_str_length_mixed_list_initializer() {
    let source = "{|| mut counts: list<int> = ([\"a\", 1] | str length); $counts }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("str length on a mixed list should be rejected");

    assert!(
        err.labels
            .iter()
            .any(|label| label.text.contains("requires string list items")),
        "unexpected labels: {:?}",
        err.labels
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_bytes_length_mixed_list_initializer() {
    let source = "{|| mut counts: list<int> = ([0x[01], \"abc\"] | bytes length); $counts }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("bytes length on a mixed list should be rejected");

    assert!(
        err.labels
            .iter()
            .any(|label| label.text.contains("requires binary list items")),
        "unexpected labels: {:?}",
        err.labels
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_constant_length_string_initializer() {
    let source = "{|| mut count: int = (\"abc\" | length); $count }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("length on a string should be rejected");

    assert!(
        err.labels
            .iter()
            .any(|label| label.text.contains("requires list, binary, or null input")),
        "unexpected labels: {:?}",
        err.labels
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_list_spread_initializer() {
    let source = "{|| mut vals: list<int> = [1, ...[2, 3]]; $vals }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant list spread initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let ints: Vec<i64> = vals
                .iter()
                .map(|value| {
                    value
                        .as_int()
                        .expect("list spread initializer should stay numeric")
                })
                .collect();
            assert_eq!(ints, vec![1, 2, 3]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_prior_constant_let_spread_initializer() {
    let source = "{|| let tail = [{pid: 9, cpu: 3}]; mut entries: list<record<pid: int cpu: int>> = [{pid: 7, cpu: 2}, ...$tail]; $entries }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(10),
                src: RegId::new(0),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(1),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 4],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 4],
        comments: vec!["let".into(), "let".into(), "".into(), "".into()],
        register_count: 2,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant let-bound spread initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0].var_id, VarId::new(11));
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            assert_eq!(vals.len(), 2);
            let Value::Record { val, .. } = &vals[1] else {
                panic!(
                    "expected second array entry to be a record, got {:?}",
                    vals[1]
                );
            };
            assert_eq!(
                val.get("pid").and_then(|value| value.as_int().ok()),
                Some(9)
            );
            assert_eq!(
                val.get("cpu").and_then(|value| value.as_int().ok()),
                Some(3)
            );
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_rejects_prior_mutable_spread_initializer_binding() {
    let source = "{|| mut tail = [2, 3]; mut vals: list<int> = [1, ...$tail]; $vals }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(10),
                src: RegId::new(0),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(1),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 4],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 4],
        comments: vec!["let".into(), "let".into(), "".into(), "".into()],
        register_count: 2,
        file_count: 0,
    };

    let err = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect_err("mutable prior bindings should not be constant capture sources");

    assert_eq!(
        err.to_string(),
        "Unsupported annotated mutable global initializer"
    );
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_record_array_initializer() {
    let source = "{|| mut entries: list<record<pid: int cpu: int>> = [{pid: 7, cpu: 2} {pid: 9, cpu: 3}]; $entries }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant record array initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            assert_eq!(vals.len(), 2);
            let Value::Record { val, .. } = &vals[1] else {
                panic!(
                    "expected second array entry to be a record, got {:?}",
                    vals[1]
                );
            };
            assert_eq!(
                val.get("pid").and_then(|value| value.as_int().ok()),
                Some(9)
            );
            assert_eq!(
                val.get("cpu").and_then(|value| value.as_int().ok()),
                Some(3)
            );
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_nested_constant_record_array_initializer() {
    let source = "{|| mut state: record<entries: list<record<pid: int cpu: int>> total: int> = {entries: [{pid: 7, cpu: 2} {pid: 9, cpu: 3}], total: 2}; $state }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("nested constant record array initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::Record { val, .. } => {
            assert_eq!(
                val.get("total").and_then(|value| value.as_int().ok()),
                Some(2)
            );
            let Some(Value::List { vals, .. }) = val.get("entries") else {
                panic!("expected entries field to be a list");
            };
            assert_eq!(vals.len(), 2);
            let Value::Record { val, .. } = &vals[1] else {
                panic!(
                    "expected second entries element to be a record, got {:?}",
                    vals[1]
                );
            };
            assert_eq!(
                val.get("pid").and_then(|value| value.as_int().ok()),
                Some(9)
            );
            assert_eq!(
                val.get("cpu").and_then(|value| value.as_int().ok()),
                Some(3)
            );
        }
        other => panic!("expected record initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_record_upsert_initializer() {
    let source = "{|| mut state: record<pid: int ok: bool> = ({pid: 0, ok: false} | upsert pid (2 ** 3)); $state }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant record upsert initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::Record { val, .. } => {
            assert_eq!(val.get("pid").and_then(|v| v.as_int().ok()), Some(8));
            assert_eq!(val.get("ok").and_then(|v| v.as_bool().ok()), Some(false));
        }
        other => panic!("expected record initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_list_upsert_initializer() {
    let source = "{|| mut vals: list<int> = ([1, 2, 3] | upsert 1 (2 ** 4)); $vals }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant list upsert initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let ints: Vec<i64> = vals
                .iter()
                .map(|value| {
                    value
                        .as_int()
                        .expect("list upsert initializer should stay numeric")
                })
                .collect();
            assert_eq!(ints, vec![1, 16, 3]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_record_insert_initializer() {
    let source =
        "{|| mut state: record<pid: int ok: bool> = ({ok: false} | insert pid (2 ** 3)); $state }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant record insert initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::Record { val, .. } => {
            assert_eq!(val.get("pid").and_then(|v| v.as_int().ok()), Some(8));
            assert_eq!(val.get("ok").and_then(|v| v.as_bool().ok()), Some(false));
        }
        other => panic!("expected record initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_list_update_initializer() {
    let source = "{|| mut vals: list<int> = ([1, 2, 3] | update 1 (2 ** 4)); $vals }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant list update initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let ints: Vec<i64> = vals
                .iter()
                .map(|value| {
                    value
                        .as_int()
                        .expect("list update initializer should stay numeric")
                })
                .collect();
            assert_eq!(ints, vec![1, 16, 3]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_list_append_initializer() {
    let source = "{|| mut vals: list<int> = ([1, 2] | append (2 ** 3)); $vals }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant list append initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let ints: Vec<i64> = vals
                .iter()
                .map(|value| {
                    value
                        .as_int()
                        .expect("list append initializer should stay numeric")
                })
                .collect();
            assert_eq!(ints, vec![1, 2, 8]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_list_prepend_initializer() {
    let source = "{|| mut vals: list<int> = ([1, 2] | prepend 0); $vals }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant list prepend initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::List { vals, .. } => {
            let ints: Vec<i64> = vals
                .iter()
                .map(|value| {
                    value
                        .as_int()
                        .expect("list prepend initializer should stay numeric")
                })
                .collect();
            assert_eq!(ints, vec![0, 1, 2]);
        }
        other => panic!("expected list initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_record_get_initializer() {
    let source = "{|| mut pid: int = ({pid: 8, ok: false} | get pid); $pid }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant record get initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0].initial_value.as_int().ok(), Some(8));
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_record_get_path_initializer() {
    let source =
        r#"{|| let field = "pid"; mut pid: int = ({pid: 8, ok: false} | get $field); $pid }"#;
    let ir_block = one_let_then_single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound record get path initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0].initial_value.as_int().ok(), Some(8));
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_list_get_index_initializer() {
    let source = "{|| let index = 1; mut second: int = ([1, 2, 3] | get $index); $second }";
    let ir_block = one_let_then_single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound list get index initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0].initial_value.as_int().ok(), Some(2));
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_let_bound_path_mutation_initializer() {
    let source = r#"{|| let field = "pid"; mut rec: record<pid: int cpu: int> = ({pid: 7, cpu: 2} | upsert $field 9); $rec }"#;
    let ir_block = one_let_then_single_annotated_global_return_ir_block();

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("let-bound path mutation initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    match &globals[0].initial_value {
        Value::Record { val, .. } => {
            assert_eq!(val.get("pid").and_then(|v| v.as_int().ok()), Some(9));
            assert_eq!(val.get("cpu").and_then(|v| v.as_int().ok()), Some(2));
        }
        other => panic!("expected record initializer, got {other:?}"),
    }
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_arithmetic_initializer() {
    let source = "{|| mut sum: int = (2 + 3); $sum }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant arithmetic initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0].initial_value.as_int().ok(), Some(5));
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_full_cell_path_initializer() {
    let source = "{|| mut pid: int = (({pid: 8, ok: false}).pid); $pid }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant full cell-path initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0].initial_value.as_int().ok(), Some(8));
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_string_concat_initializer() {
    let source = "{|| mut msg: string = (\"hel\" + \"lo\"); $msg }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant string concat initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0].initial_value.as_str().ok(), Some("hello"));
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_not_initializer() {
    let source = "{|| mut ok: bool = (not false); $ok }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant not initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0].initial_value.as_bool().ok(), Some(true));
}

#[test]
fn test_map_leading_annotated_mut_globals_supports_constant_list_get_initializer() {
    let source = "{|| mut second: int = ([1, 2, 3] | get 1); $second }";
    let ir_block = IrBlock {
        instructions: vec![
            Instruction::StoreVariable {
                var_id: VarId::new(11),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(11),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![Span::test_data(); 3],
        data: Vec::<u8>::new().into(),
        ast: vec![None; 3],
        comments: vec!["let".into(), "".into(), "".into()],
        register_count: 1,
        file_count: 0,
    };

    let globals = super::map_leading_annotated_mut_globals(source, &ir_block, Span::test_data())
        .expect("constant list get initializer should map cleanly");

    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0].initial_value.as_int().ok(), Some(2));
}

#[test]
fn test_strip_leading_annotated_mut_initializer_stmts_removes_leading_initializer_code() {
    let mut hir = HirProgram::new(
        HirFunction {
            blocks: vec![HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadValue {
                        dst: RegId::new(0),
                        val: Box::new(Value::int(7, Span::test_data())),
                    },
                    HirStmt::StoreVariable {
                        var_id: VarId::new(10),
                        src: RegId::new(0),
                    },
                    HirStmt::LoadVariable {
                        dst: RegId::new(1),
                        var_id: VarId::new(10),
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(1) },
            }],
            entry: HirBlockId(0),
            spans: vec![Span::test_data(); 3],
            ast: vec![None; 3],
            comments: vec![],
            register_count: 2,
            file_count: 0,
        },
        HashMap::new(),
        vec![],
        None,
    );
    hir.annotated_mut_globals = vec![crate::compiler::hir::AnnotatedMutGlobal {
        var_id: VarId::new(10),
        declared_type: Type::Int,
        initial_value: Value::int(7, Span::test_data()),
    }];

    super::strip_leading_annotated_mut_initializer_stmts(&mut hir, Span::test_data())
        .expect("leading annotated mut initializer should strip cleanly");

    assert_eq!(hir.main.blocks[0].stmts.len(), 1);
    assert!(matches!(
        &hir.main.blocks[0].stmts[0],
        HirStmt::LoadVariable {
            var_id,
            dst: RegId { .. }
        } if *var_id == VarId::new(10)
    ));
}

#[test]
fn test_strip_leading_annotated_mut_initializer_stmts_keeps_following_code() {
    let mut hir = HirProgram::new(
        HirFunction {
            blocks: vec![HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadValue {
                        dst: RegId::new(0),
                        val: Box::new(Value::int(1, Span::test_data())),
                    },
                    HirStmt::StoreVariable {
                        var_id: VarId::new(10),
                        src: RegId::new(0),
                    },
                    HirStmt::LoadValue {
                        dst: RegId::new(1),
                        val: Box::new(Value::int(2, Span::test_data())),
                    },
                    HirStmt::StoreVariable {
                        var_id: VarId::new(11),
                        src: RegId::new(1),
                    },
                    HirStmt::LoadVariable {
                        dst: RegId::new(2),
                        var_id: VarId::new(99),
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(2) },
            }],
            entry: HirBlockId(0),
            spans: vec![Span::test_data(); 5],
            ast: vec![None; 5],
            comments: vec![],
            register_count: 3,
            file_count: 0,
        },
        HashMap::new(),
        vec![],
        None,
    );
    hir.annotated_mut_globals = vec![
        crate::compiler::hir::AnnotatedMutGlobal {
            var_id: VarId::new(10),
            declared_type: Type::Int,
            initial_value: Value::int(1, Span::test_data()),
        },
        crate::compiler::hir::AnnotatedMutGlobal {
            var_id: VarId::new(11),
            declared_type: Type::Int,
            initial_value: Value::int(2, Span::test_data()),
        },
    ];

    super::strip_leading_annotated_mut_initializer_stmts(&mut hir, Span::test_data())
        .expect("multiple leading annotated mut initializers should strip cleanly");

    assert_eq!(hir.main.blocks[0].stmts.len(), 1);
    assert!(matches!(
        &hir.main.blocks[0].stmts[0],
        HirStmt::LoadVariable { var_id, .. } if *var_id == VarId::new(99)
    ));
}

#[test]
fn test_strip_leading_annotated_mut_initializer_stmts_removes_initializer_cleanup() {
    let mut hir = HirProgram::new(
        HirFunction {
            blocks: vec![HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadValue {
                        dst: RegId::new(0),
                        val: Box::new(Value::int(1, Span::test_data())),
                    },
                    HirStmt::StoreVariable {
                        var_id: VarId::new(10),
                        src: RegId::new(0),
                    },
                    HirStmt::Drain { src: RegId::new(0) },
                    HirStmt::Drop { src: RegId::new(0) },
                    HirStmt::LoadVariable {
                        dst: RegId::new(1),
                        var_id: VarId::new(10),
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(1) },
            }],
            entry: HirBlockId(0),
            spans: vec![Span::test_data(); 5],
            ast: vec![None; 5],
            comments: vec![],
            register_count: 2,
            file_count: 0,
        },
        HashMap::new(),
        vec![],
        None,
    );
    hir.annotated_mut_globals = vec![crate::compiler::hir::AnnotatedMutGlobal {
        var_id: VarId::new(10),
        declared_type: Type::Int,
        initial_value: Value::int(1, Span::test_data()),
    }];

    super::strip_leading_annotated_mut_initializer_stmts(&mut hir, Span::test_data())
        .expect("leading annotated mut cleanup should strip cleanly");

    assert_eq!(hir.main.blocks[0].stmts.len(), 1);
    assert!(matches!(
        &hir.main.blocks[0].stmts[0],
        HirStmt::LoadVariable {
            var_id,
            dst: RegId { .. }
        } if *var_id == VarId::new(10)
    ));
}

#[test]
fn test_value_to_spanned_closure_accepts_closure_value() {
    let closure = Closure {
        block_id: BlockId::new(7),
        captures: vec![],
    };
    let value = Value::closure(closure.clone(), Span::test_data());

    let lowered =
        super::value_to_spanned_closure(value, Span::test_data()).expect("closure should lower");

    assert_eq!(lowered.item.block_id, closure.block_id);
}

#[test]
fn test_struct_ops_value_field_from_value_accepts_binary() {
    let field = super::struct_ops::struct_ops_value_field_from_value(
        "cookie",
        &Value::binary(vec![1, 2, 3], Span::test_data()),
    )
    .expect("binary field should lower");

    assert_eq!(field, StructOpsValueField::Bytes(vec![1, 2, 3]));
}

#[test]
fn test_struct_ops_value_field_from_value_accepts_int_list() {
    let field = super::struct_ops::struct_ops_value_field_from_value(
        "cookie",
        &Value::list(
            vec![
                Value::int(1, Span::test_data()),
                Value::int(2, Span::test_data()),
            ],
            Span::test_data(),
        ),
    )
    .expect("int-list field should lower");

    assert_eq!(field, StructOpsValueField::IntList(vec![1, 2]));
}

#[test]
fn test_struct_ops_value_field_from_value_rejects_mixed_list() {
    let err = super::struct_ops::struct_ops_value_field_from_value(
        "cookie",
        &Value::list(
            vec![
                Value::int(1, Span::test_data()),
                Value::string("oops", Span::test_data()),
            ],
            Span::test_data(),
        ),
    )
    .expect_err("mixed list should be rejected");

    assert!(
        err.to_string()
            .contains("Unsupported struct_ops value field")
    );
}

#[test]
fn test_struct_ops_value_field_from_value_rejects_record() {
    let mut record = Record::new();
    record.push("pid", Value::int(7, Span::test_data()));

    let err = super::struct_ops::struct_ops_value_field_from_value(
        "state",
        &Value::record(record, Span::test_data()),
    )
    .expect_err("record field should be rejected");

    assert!(
        err.to_string()
            .contains("Unsupported struct_ops value field")
    );
}

fn find_nested_struct_ops_value_candidate() -> Option<(String, Vec<String>, usize, usize)> {
    for (type_name, path) in [
        ("task_struct", vec!["se", "avg", "util_avg"]),
        ("task_struct", vec!["se", "avg", "load_avg"]),
        ("task_struct", vec!["thread", "pid"]),
    ] {
        let selectors: Vec<_> = path
            .iter()
            .map(|segment| TrampolineFieldSelector::Field((*segment).to_string()))
            .collect();
        let Ok(projection) =
            KernelBtf::get().kernel_named_type_field_projection(type_name, &selectors)
        else {
            continue;
        };
        if projection.path.len() <= 1
            || projection
                .path
                .iter()
                .take(projection.path.len().saturating_sub(1))
                .any(|segment| matches!(segment.type_info, TypeInfo::Ptr { .. }))
            || !matches!(projection.type_info, TypeInfo::Int { .. })
        {
            continue;
        }
        let Some(offset) = projection
            .path
            .iter()
            .try_fold(0usize, |acc, segment| acc.checked_add(segment.offset_bytes))
        else {
            continue;
        };
        return Some((
            type_name.to_string(),
            path.into_iter().map(str::to_string).collect(),
            offset,
            projection.type_info.size(),
        ));
    }
    None
}

fn find_struct_ops_array_record_candidate() -> Option<(String, usize, usize)> {
    for (type_name, path) in [(
        "task_struct",
        vec![
            TrampolineFieldSelector::Field("uclamp_req".to_string()),
            TrampolineFieldSelector::Index(0),
            TrampolineFieldSelector::Field("value".to_string()),
        ],
    )] {
        let Ok(projection) = KernelBtf::get().kernel_named_type_field_projection(type_name, &path)
        else {
            continue;
        };
        if projection.path.len() <= 2
            || projection
                .path
                .iter()
                .take(projection.path.len().saturating_sub(1))
                .any(|segment| matches!(segment.type_info, TypeInfo::Ptr { .. }))
            || !matches!(projection.type_info, TypeInfo::Int { .. })
        {
            continue;
        }
        let Some(offset) = projection
            .path
            .iter()
            .try_fold(0usize, |acc, segment| acc.checked_add(segment.offset_bytes))
        else {
            continue;
        };
        return Some((type_name.to_string(), offset, projection.type_info.size()));
    }
    None
}

fn find_struct_ops_callback_member_candidate() -> Option<(String, String)> {
    for (value_type_name, field_name) in [
        ("sched_ext_ops", "select_cpu"),
        ("tcp_congestion_ops", "cong_avoid"),
        ("tcp_congestion_ops", "ssthresh"),
    ] {
        if KernelBtf::get()
            .struct_ops_callback_ret_type_info(value_type_name, field_name)
            .is_ok()
        {
            return Some((value_type_name.to_string(), field_name.to_string()));
        }
    }
    None
}

fn find_struct_ops_value_member_candidate() -> Option<(String, String)> {
    for (value_type_name, field_name) in [
        ("tcp_congestion_ops", "name"),
        ("tcp_congestion_ops", "flags"),
        ("sched_ext_ops", "name"),
    ] {
        if KernelBtf::get()
            .struct_ops_callback_ret_type_info(value_type_name, field_name)
            .is_err()
            && KernelBtf::get()
                .kernel_named_type_field_projection(
                    value_type_name,
                    &[TrampolineFieldSelector::Field(field_name.to_string())],
                )
                .is_ok()
        {
            return Some((value_type_name.to_string(), field_name.to_string()));
        }
    }
    None
}

#[test]
fn test_apply_struct_ops_value_field_initializes_nested_record_member() {
    let Some((type_name, path, offset, size)) = find_nested_struct_ops_value_candidate() else {
        return;
    };
    let nested = path[1..]
        .iter()
        .rev()
        .fold(Value::int(7, Span::test_data()), |acc, segment| {
            let mut record = Record::new();
            record.push(segment.as_str(), acc);
            Value::record(record, Span::test_data())
        });

    let spec = StructOpsObjectSpec::zeroed_from_kernel_btf("demo", &type_name)
        .expect("expected zeroed spec for nested value-field candidate");
    let mut field_path = vec![TrampolineFieldSelector::Field(path[0].clone())];
    let spec = super::apply_struct_ops_value_field(spec, &mut field_path, &nested)
        .expect("nested struct_ops value field should lower");
    let object = spec
        .to_object()
        .expect("nested struct_ops object should build");

    let bytes = &object.extra_data_symbols[0].data[offset..offset + size];
    let value = match size {
        1 => i8::from_le_bytes([bytes[0]]) as i64,
        2 => i16::from_le_bytes([bytes[0], bytes[1]]) as i64,
        4 => i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as i64,
        8 => i64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]),
        other => panic!("unexpected integer width {}", other),
    };
    assert_eq!(value, 7);
}

#[test]
fn test_apply_struct_ops_value_field_initializes_array_of_record_member() {
    let Some((type_name, offset, size)) = find_struct_ops_array_record_candidate() else {
        return;
    };
    let mut elem = Record::new();
    elem.push("value", Value::int(17, Span::test_data()));
    let value = Value::list(
        vec![Value::record(elem, Span::test_data())],
        Span::test_data(),
    );

    let spec = StructOpsObjectSpec::zeroed_from_kernel_btf("demo", &type_name)
        .expect("expected zeroed spec for array-of-record candidate");
    let mut field_path = vec![TrampolineFieldSelector::Field("uclamp_req".to_string())];
    let spec = super::apply_struct_ops_value_field(spec, &mut field_path, &value)
        .expect("array-of-record struct_ops value field should lower");
    let object = spec
        .to_object()
        .expect("array-of-record struct_ops object should build");

    let bytes = &object.extra_data_symbols[0].data[offset..offset + size];
    let value = match size {
        1 => i8::from_le_bytes([bytes[0]]) as i64,
        2 => i16::from_le_bytes([bytes[0], bytes[1]]) as i64,
        4 => i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as i64,
        8 => i64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]),
        other => panic!("unexpected integer width {}", other),
    };
    assert_eq!(value, 17);
}

#[test]
fn test_apply_struct_ops_value_field_rejects_nested_callback() {
    let spec = StructOpsObjectSpec::zeroed_from_kernel_btf("demo", "task_struct")
        .expect("expected zeroed task_struct object spec");
    let mut nested = Record::new();
    nested.push(
        "leaf",
        Value::closure(
            Closure {
                block_id: BlockId::new(0),
                captures: vec![],
            },
            Span::test_data(),
        ),
    );
    let mut field_path = vec![TrampolineFieldSelector::Field("state".to_string())];
    let err = super::apply_struct_ops_value_field(
        spec,
        &mut field_path,
        &Value::record(nested, Span::test_data()),
    )
    .expect_err("nested callback should be rejected");
    assert!(err.to_string().contains("Invalid struct_ops object"));
}

#[test]
fn test_validate_struct_ops_top_level_field_kind_rejects_closure_on_value_member() {
    let Some((value_type_name, field_name)) = find_struct_ops_value_member_candidate() else {
        return;
    };
    let err = super::validate_struct_ops_top_level_field_kind(
        &value_type_name,
        &field_name,
        super::StructOpsTopLevelFieldKind::Callback,
        Span::test_data(),
    )
    .expect_err("value member used as callback slot should be rejected");
    assert!(
        err.labels
            .iter()
            .any(|label| label.text.contains("value member, not a callback slot"))
    );
}

#[test]
fn test_validate_struct_ops_top_level_field_kind_rejects_constant_on_callback_member() {
    let Some((value_type_name, field_name)) = find_struct_ops_callback_member_candidate() else {
        return;
    };
    let err = super::validate_struct_ops_top_level_field_kind(
        &value_type_name,
        &field_name,
        super::StructOpsTopLevelFieldKind::Value,
        Span::test_data(),
    )
    .expect_err("callback member used as value field should be rejected");
    assert!(
        err.labels
            .iter()
            .any(|label| label.text.contains("callback slot; provide a closure"))
    );
}

#[test]
fn test_validate_struct_ops_attach_safety_rejects_sched_ext_live_load_by_default() {
    let spec = ProgramSpec::parse("struct_ops:sched_ext_ops").expect("sched_ext spec should parse");
    let err = super::validate_struct_ops_attach_safety(&spec, false, false, Span::test_data())
        .expect_err("live sched_ext attach should require explicit opt-in");
    assert!(err.labels.iter().any(|label| {
        label
            .text
            .contains("live loading of struct_ops 'sched_ext_ops' is disabled by default")
            && label.text.contains("external alpha status: unsafe-opt-in")
    }));
}

#[test]
fn test_validate_struct_ops_attach_safety_rejects_known_behavior_changing_live_loads() {
    for spec_text in [
        "struct_ops:demo_ops",
        "struct_ops:hid_bpf_ops",
        "struct_ops:Qdisc_ops",
    ] {
        let spec = ProgramSpec::parse(spec_text).expect("struct_ops spec should parse");
        let err = super::validate_struct_ops_attach_safety(&spec, false, false, Span::test_data())
            .expect_err("unclassified or behavior-changing struct_ops attach should require explicit opt-in");
        assert!(
            err.labels
                .iter()
                .any(|label| label.text.contains("disabled by default")
                    && label.text.contains("external alpha status: unsafe-opt-in")),
            "unexpected safety diagnostic for {spec_text}: {err:?}"
        );
    }
}

#[test]
fn test_validate_struct_ops_attach_safety_allows_sched_ext_dry_run() {
    let spec = ProgramSpec::parse("struct_ops:sched_ext_ops").expect("sched_ext spec should parse");
    super::validate_struct_ops_attach_safety(&spec, true, false, Span::test_data())
        .expect("dry-run sched_ext attach should stay allowed");
}

#[test]
fn test_validate_struct_ops_attach_safety_allows_sched_ext_with_explicit_opt_in() {
    let spec = ProgramSpec::parse("struct_ops:sched_ext_ops").expect("sched_ext spec should parse");
    super::validate_struct_ops_attach_safety(&spec, false, true, Span::test_data())
        .expect("explicit opt-in should allow live sched_ext attach");
}

#[test]
fn test_validate_struct_ops_attach_safety_allows_lower_risk_families() {
    let spec = ProgramSpec::parse("struct_ops:tcp_congestion_ops")
        .expect("tcp_congestion_ops spec should parse");
    super::validate_struct_ops_attach_safety(&spec, false, false, Span::test_data())
        .expect("lower-risk struct_ops families should not be gated");
}

#[test]
fn test_validate_struct_ops_attach_target_rejects_callback_specs() {
    let spec = ProgramSpec::parse("struct_ops:sched_ext_ops.select_cpu")
        .expect("struct_ops callback spec should parse");
    let err = super::validate_struct_ops_attach_target(&spec, Span::test_data())
        .expect_err("callback specs should not be accepted as attach objects");

    assert_eq!(err.msg, "Invalid struct_ops attach target");
    assert!(err.labels.iter().any(|label| {
        label
            .text
            .contains("target names callback 'sched_ext_ops.select_cpu'")
    }));
    assert!(
        err.help
            .as_deref()
            .is_some_and(|help| help.contains("Attach the object with 'struct_ops:sched_ext_ops'"))
    );
}

#[test]
fn test_validate_struct_ops_attach_target_accepts_object_specs() {
    let spec = ProgramSpec::parse("struct_ops:sched_ext_ops")
        .expect("struct_ops object spec should parse");

    let value_type_name = super::validate_struct_ops_attach_target(&spec, Span::test_data())
        .expect("object specs should be accepted as attach objects");

    assert_eq!(value_type_name, "sched_ext_ops");
}

#[test]
fn test_validate_required_struct_ops_callbacks_rejects_missing_tcp_congestion_callbacks() {
    if KernelBtf::get()
        .kernel_named_type_size_bytes("tcp_congestion_ops")
        .is_err()
    {
        return;
    }

    let err = super::validate_required_struct_ops_callbacks(
        "tcp_congestion_ops",
        &HashSet::from(["ssthresh".to_string()]),
        Span::test_data(),
    )
    .expect_err("missing required tcp_congestion_ops callbacks should be rejected");
    assert!(err.labels.iter().any(|label| {
        label
            .text
            .contains("missing required callback closure(s): cong_avoid, undo_cwnd")
    }));
}

#[test]
fn test_validate_required_struct_ops_callbacks_allows_complete_tcp_congestion_callbacks() {
    if KernelBtf::get()
        .kernel_named_type_size_bytes("tcp_congestion_ops")
        .is_err()
    {
        return;
    }

    super::validate_required_struct_ops_callbacks(
        "tcp_congestion_ops",
        &HashSet::from([
            "ssthresh".to_string(),
            "cong_avoid".to_string(),
            "undo_cwnd".to_string(),
        ]),
        Span::test_data(),
    )
    .expect("complete tcp_congestion_ops callbacks should be allowed");
}

#[test]
fn test_validate_required_struct_ops_value_fields_rejects_missing_tcp_congestion_name() {
    if KernelBtf::get()
        .kernel_named_type_size_bytes("tcp_congestion_ops")
        .is_err()
    {
        return;
    }

    let err = super::validate_required_struct_ops_value_fields(
        "tcp_congestion_ops",
        &Record::new(),
        Span::test_data(),
    )
    .expect_err("missing tcp_congestion_ops name should be rejected");
    assert!(
        err.labels
            .iter()
            .any(|label| { label.text.contains("missing required value field 'name'") })
    );
}

#[test]
fn test_validate_required_struct_ops_value_fields_rejects_empty_tcp_congestion_name() {
    if KernelBtf::get()
        .kernel_named_type_size_bytes("tcp_congestion_ops")
        .is_err()
    {
        return;
    }

    let mut body = Record::new();
    body.push("name", Value::string("", Span::test_data()));

    let err = super::validate_required_struct_ops_value_fields(
        "tcp_congestion_ops",
        &body,
        Span::test_data(),
    )
    .expect_err("empty tcp_congestion_ops name should be rejected");
    assert!(err.labels.iter().any(|label| {
        label
            .text
            .contains("requires a non-empty 'name' value field")
    }));
}

#[test]
fn test_validate_required_struct_ops_value_fields_allows_non_empty_tcp_congestion_name() {
    if KernelBtf::get()
        .kernel_named_type_size_bytes("tcp_congestion_ops")
        .is_err()
    {
        return;
    }

    let mut body = Record::new();
    body.push("name", Value::string("nu_demo", Span::test_data()));

    super::validate_required_struct_ops_value_fields(
        "tcp_congestion_ops",
        &body,
        Span::test_data(),
    )
    .expect("non-empty tcp_congestion_ops name should be allowed");
}

#[test]
fn test_validate_required_struct_ops_value_fields_rejects_non_string_tcp_congestion_name() {
    if KernelBtf::get()
        .kernel_named_type_size_bytes("tcp_congestion_ops")
        .is_err()
    {
        return;
    }

    let mut body = Record::new();
    body.push("name", Value::int(7, Span::test_data()));

    let err = super::validate_required_struct_ops_value_fields(
        "tcp_congestion_ops",
        &body,
        Span::test_data(),
    )
    .expect_err("integer tcp_congestion_ops name should be rejected");
    assert!(err.labels.iter().any(|label| {
        label
            .text
            .contains("requires 'name' to be a string or binary byte buffer")
    }));
}

#[test]
fn test_validate_required_struct_ops_value_fields_rejects_too_long_tcp_congestion_name() {
    let Ok(name_capacity) = super::struct_ops::resolve_struct_ops_char_array_field_capacity(
        "tcp_congestion_ops",
        "name",
        Span::test_data(),
    ) else {
        return;
    };

    let mut body = Record::new();
    body.push(
        "name",
        Value::string("x".repeat(name_capacity), Span::test_data()),
    );

    let err = super::validate_required_struct_ops_value_fields(
        "tcp_congestion_ops",
        &body,
        Span::test_data(),
    )
    .expect_err("overlong tcp_congestion_ops name should be rejected");
    assert!(err.labels.iter().any(|label| {
        label
            .text
            .contains("struct_ops 'tcp_congestion_ops' name is too long")
    }));
}

#[test]
fn test_validate_required_struct_ops_value_fields_rejects_missing_sched_ext_name() {
    if KernelBtf::get()
        .kernel_named_type_size_bytes("sched_ext_ops")
        .is_err()
    {
        return;
    }

    let err = super::validate_required_struct_ops_value_fields(
        "sched_ext_ops",
        &Record::new(),
        Span::test_data(),
    )
    .expect_err("missing sched_ext_ops name should be rejected");
    assert!(
        err.labels
            .iter()
            .any(|label| { label.text.contains("missing required value field 'name'") })
    );
}

#[test]
fn test_validate_required_struct_ops_value_fields_rejects_empty_sched_ext_name() {
    if KernelBtf::get()
        .kernel_named_type_size_bytes("sched_ext_ops")
        .is_err()
    {
        return;
    }

    let mut body = Record::new();
    body.push("name", Value::string("", Span::test_data()));

    let err =
        super::validate_required_struct_ops_value_fields("sched_ext_ops", &body, Span::test_data())
            .expect_err("empty sched_ext_ops name should be rejected");
    assert!(err.labels.iter().any(|label| {
        label
            .text
            .contains("requires a non-empty 'name' value field")
    }));
}

#[test]
fn test_validate_required_struct_ops_value_fields_allows_non_empty_sched_ext_name() {
    if KernelBtf::get()
        .kernel_named_type_size_bytes("sched_ext_ops")
        .is_err()
    {
        return;
    }

    let mut body = Record::new();
    body.push("name", Value::string("nu_demo", Span::test_data()));

    super::validate_required_struct_ops_value_fields("sched_ext_ops", &body, Span::test_data())
        .expect("non-empty sched_ext_ops name should be allowed");
}

#[test]
fn test_validate_required_struct_ops_value_fields_rejects_non_string_sched_ext_name() {
    if KernelBtf::get()
        .kernel_named_type_size_bytes("sched_ext_ops")
        .is_err()
    {
        return;
    }

    let mut body = Record::new();
    body.push("name", Value::binary(vec![0x6e, 0x75], Span::test_data()));

    let err =
        super::validate_required_struct_ops_value_fields("sched_ext_ops", &body, Span::test_data())
            .expect_err("binary sched_ext_ops name should be rejected");
    assert!(
        err.labels
            .iter()
            .any(|label| { label.text.contains("requires 'name' to be a string") })
    );
}

#[test]
fn test_validate_required_struct_ops_value_fields_rejects_invalid_sched_ext_name_chars() {
    if KernelBtf::get()
        .kernel_named_type_size_bytes("sched_ext_ops")
        .is_err()
    {
        return;
    }

    let mut body = Record::new();
    body.push("name", Value::string("nu-demo", Span::test_data()));

    let err =
        super::validate_required_struct_ops_value_fields("sched_ext_ops", &body, Span::test_data())
            .expect_err("invalid sched_ext_ops object name chars should be rejected");
    assert!(err.labels.iter().any(|label| {
        label
            .text
            .contains("must be a valid BPF object name using only [A-Za-z0-9_.]")
    }));
}

#[test]
fn test_validate_required_struct_ops_value_fields_rejects_too_long_sched_ext_name() {
    if KernelBtf::get()
        .kernel_named_type_size_bytes("sched_ext_ops")
        .is_err()
    {
        return;
    }

    let mut body = Record::new();
    body.push("name", Value::string("x".repeat(128), Span::test_data()));

    let err =
        super::validate_required_struct_ops_value_fields("sched_ext_ops", &body, Span::test_data())
            .expect_err("overlong sched_ext_ops name should be rejected");
    assert!(err.labels.iter().any(|label| {
        label
            .text
            .contains("struct_ops 'sched_ext_ops' name is too long")
    }));
}

#[test]
fn test_validate_required_struct_ops_value_fields_allows_valid_sched_ext_object_name() {
    if KernelBtf::get()
        .kernel_named_type_size_bytes("sched_ext_ops")
        .is_err()
    {
        return;
    }

    let mut body = Record::new();
    body.push("name", Value::string("nu.demo_1", Span::test_data()));

    super::validate_required_struct_ops_value_fields("sched_ext_ops", &body, Span::test_data())
        .expect("valid sched_ext_ops object names should be allowed");
}

fn sched_ext_flag_masks() -> Option<(u64, u64)> {
    if KernelBtf::get()
        .kernel_named_type_size_bytes("sched_ext_ops")
        .is_err()
    {
        return None;
    }
    let allowed =
        super::struct_ops::resolve_sched_ext_allowed_flags_mask(Span::test_data()).ok()?;
    let known = (0..63)
        .map(|bit| 1u64 << bit)
        .find(|bit| (allowed & *bit) != 0)?;
    let unknown = (0..63)
        .map(|bit| 1u64 << bit)
        .find(|bit| (allowed & *bit) == 0)?;
    Some((known, unknown))
}

fn sched_ext_flag_bit(flag_name: &str) -> Option<u64> {
    if KernelBtf::get()
        .kernel_named_type_size_bytes("sched_ext_ops")
        .is_err()
    {
        return None;
    }
    super::struct_ops::resolve_sched_ext_flag_bit(flag_name, Span::test_data()).ok()
}

fn test_closure_value() -> Value {
    Value::closure(
        Closure {
            block_id: BlockId::new(0),
            captures: vec![],
        },
        Span::test_data(),
    )
}

fn sched_ext_callback_kfuncs(callback: &str, kfuncs: &[&str]) -> HashMap<String, HashSet<String>> {
    HashMap::from([(
        callback.to_string(),
        kfuncs.iter().map(|kfunc| (*kfunc).to_string()).collect(),
    )])
}

#[test]
fn test_validate_required_struct_ops_value_fields_rejects_non_int_sched_ext_flags() {
    if sched_ext_flag_masks().is_none() {
        return;
    }

    let mut body = Record::new();
    body.push("name", Value::string("nu.demo_1", Span::test_data()));
    body.push("flags", Value::bool(true, Span::test_data()));

    let err =
        super::validate_required_struct_ops_value_fields("sched_ext_ops", &body, Span::test_data())
            .expect_err("non-integer sched_ext_ops flags should be rejected");
    assert!(err.labels.iter().any(|label| {
        label
            .text
            .contains("requires 'flags' to be a non-negative integer bitmask")
    }));
}

#[test]
fn test_validate_required_struct_ops_value_fields_rejects_negative_sched_ext_flags() {
    if sched_ext_flag_masks().is_none() {
        return;
    }

    let mut body = Record::new();
    body.push("name", Value::string("nu.demo_1", Span::test_data()));
    body.push("flags", Value::int(-1, Span::test_data()));

    let err =
        super::validate_required_struct_ops_value_fields("sched_ext_ops", &body, Span::test_data())
            .expect_err("negative sched_ext_ops flags should be rejected");
    assert!(err.labels.iter().any(|label| {
        label
            .text
            .contains("requires 'flags' to be a non-negative integer bitmask")
    }));
}

#[test]
fn test_validate_required_struct_ops_value_fields_rejects_unknown_sched_ext_flags_bits() {
    let Some((_, unknown_flags)) = sched_ext_flag_masks() else {
        return;
    };

    let mut body = Record::new();
    body.push("name", Value::string("nu.demo_1", Span::test_data()));
    body.push(
        "flags",
        Value::int(
            i64::try_from(unknown_flags).expect("unknown flag bit should fit in i64"),
            Span::test_data(),
        ),
    );

    let err =
        super::validate_required_struct_ops_value_fields("sched_ext_ops", &body, Span::test_data())
            .expect_err("unknown sched_ext_ops flag bits should be rejected");
    assert!(
        err.labels
            .iter()
            .any(|label| { label.text.contains("flags set unknown or unsupported bits") })
    );
}

#[test]
fn test_validate_required_struct_ops_value_fields_allows_known_sched_ext_flags_bits() {
    let Some((known_flags, _)) = sched_ext_flag_masks() else {
        return;
    };

    let mut body = Record::new();
    body.push("name", Value::string("nu.demo_1", Span::test_data()));
    body.push(
        "flags",
        Value::int(
            i64::try_from(known_flags).expect("known flag bit should fit in i64"),
            Span::test_data(),
        ),
    );

    super::validate_required_struct_ops_value_fields("sched_ext_ops", &body, Span::test_data())
        .expect("known sched_ext_ops flags should be allowed");
}

#[test]
fn test_validate_required_struct_ops_value_fields_rejects_enq_last_without_enqueue() {
    let Some(enq_last) = sched_ext_flag_bit("SCX_OPS_ENQ_LAST") else {
        return;
    };

    let mut body = Record::new();
    body.push("name", Value::string("nu.demo_1", Span::test_data()));
    body.push(
        "flags",
        Value::int(
            i64::try_from(enq_last).expect("flag bit should fit in i64"),
            Span::test_data(),
        ),
    );

    let err =
        super::validate_required_struct_ops_value_fields("sched_ext_ops", &body, Span::test_data())
            .expect_err("SCX_OPS_ENQ_LAST without enqueue should be rejected");
    assert!(err.labels.iter().any(|label| {
        label
            .text
            .contains("sets SCX_OPS_ENQ_LAST without implementing 'enqueue'")
    }));
}

#[test]
fn test_validate_required_struct_ops_value_fields_allows_enq_last_with_enqueue() {
    let Some(enq_last) = sched_ext_flag_bit("SCX_OPS_ENQ_LAST") else {
        return;
    };

    let mut body = Record::new();
    body.push("name", Value::string("nu.demo_1", Span::test_data()));
    body.push(
        "flags",
        Value::int(
            i64::try_from(enq_last).expect("flag bit should fit in i64"),
            Span::test_data(),
        ),
    );
    body.push("enqueue", test_closure_value());

    super::validate_required_struct_ops_value_fields("sched_ext_ops", &body, Span::test_data())
        .expect("SCX_OPS_ENQ_LAST with enqueue should be allowed");
}

#[test]
fn test_validate_required_struct_ops_value_fields_rejects_non_int_sched_ext_timeout() {
    if KernelBtf::get()
        .kernel_named_type_size_bytes("sched_ext_ops")
        .is_err()
    {
        return;
    }

    let mut body = Record::new();
    body.push("name", Value::string("nu.demo_1", Span::test_data()));
    body.push("timeout_ms", Value::bool(true, Span::test_data()));

    let err =
        super::validate_required_struct_ops_value_fields("sched_ext_ops", &body, Span::test_data())
            .expect_err("non-integer sched_ext_ops timeout_ms should be rejected");
    assert!(err.labels.iter().any(|label| {
        label
            .text
            .contains("requires 'timeout_ms' to be a non-negative integer number of milliseconds")
    }));
}

#[test]
fn test_validate_required_struct_ops_value_fields_rejects_negative_sched_ext_timeout() {
    if KernelBtf::get()
        .kernel_named_type_size_bytes("sched_ext_ops")
        .is_err()
    {
        return;
    }

    let mut body = Record::new();
    body.push("name", Value::string("nu.demo_1", Span::test_data()));
    body.push("timeout_ms", Value::int(-1, Span::test_data()));

    let err =
        super::validate_required_struct_ops_value_fields("sched_ext_ops", &body, Span::test_data())
            .expect_err("negative sched_ext_ops timeout_ms should be rejected");
    assert!(err.labels.iter().any(|label| {
        label
            .text
            .contains("requires 'timeout_ms' to be a non-negative integer number of milliseconds")
    }));
}

#[test]
fn test_validate_required_struct_ops_value_fields_rejects_too_large_sched_ext_timeout() {
    if KernelBtf::get()
        .kernel_named_type_size_bytes("sched_ext_ops")
        .is_err()
    {
        return;
    }

    let mut body = Record::new();
    body.push("name", Value::string("nu.demo_1", Span::test_data()));
    body.push(
        "timeout_ms",
        Value::int(
            super::struct_ops::SCHED_EXT_MAX_TIMEOUT_MS + 1,
            Span::test_data(),
        ),
    );

    let err =
        super::validate_required_struct_ops_value_fields("sched_ext_ops", &body, Span::test_data())
            .expect_err("overlarge sched_ext_ops timeout_ms should be rejected");
    assert!(
        err.labels
            .iter()
            .any(|label| { label.text.contains("timeout_ms is too large") })
    );
}

#[test]
fn test_validate_required_struct_ops_value_fields_allows_sched_ext_timeout_within_limit() {
    if KernelBtf::get()
        .kernel_named_type_size_bytes("sched_ext_ops")
        .is_err()
    {
        return;
    }

    let mut body = Record::new();
    body.push("name", Value::string("nu.demo_1", Span::test_data()));
    body.push(
        "timeout_ms",
        Value::int(
            super::struct_ops::SCHED_EXT_MAX_TIMEOUT_MS,
            Span::test_data(),
        ),
    );

    super::validate_required_struct_ops_value_fields("sched_ext_ops", &body, Span::test_data())
        .expect("sched_ext_ops timeout_ms within limit should be allowed");
}

#[test]
fn test_validate_required_struct_ops_value_fields_rejects_update_idle_without_select_cpu() {
    let Some(_keep_builtin_idle) = sched_ext_flag_bit("SCX_OPS_KEEP_BUILTIN_IDLE") else {
        return;
    };

    let mut body = Record::new();
    body.push("name", Value::string("nu.demo_1", Span::test_data()));
    body.push("update_idle", test_closure_value());

    let err = super::validate_required_struct_ops_value_fields(
        "sched_ext_ops",
        &body,
        Span::test_data(),
    )
    .expect_err(
        "sched_ext_ops update_idle without select_cpu or KEEP_BUILTIN_IDLE should be rejected",
    );
    assert!(err.labels.iter().any(|label| {
        label
            .text
            .contains("must define 'select_cpu' when 'update_idle' is implemented")
    }));
}

#[test]
fn test_validate_required_struct_ops_value_fields_allows_update_idle_with_select_cpu() {
    let Some(_keep_builtin_idle) = sched_ext_flag_bit("SCX_OPS_KEEP_BUILTIN_IDLE") else {
        return;
    };

    let mut body = Record::new();
    body.push("name", Value::string("nu.demo_1", Span::test_data()));
    body.push("update_idle", test_closure_value());
    body.push("select_cpu", test_closure_value());

    super::validate_required_struct_ops_value_fields("sched_ext_ops", &body, Span::test_data())
        .expect("sched_ext_ops update_idle with select_cpu should be allowed");
}

#[test]
fn test_validate_required_struct_ops_value_fields_allows_update_idle_with_keep_builtin_idle() {
    let Some(keep_builtin_idle) = sched_ext_flag_bit("SCX_OPS_KEEP_BUILTIN_IDLE") else {
        return;
    };

    let mut body = Record::new();
    body.push("name", Value::string("nu.demo_1", Span::test_data()));
    body.push("update_idle", test_closure_value());
    body.push(
        "flags",
        Value::int(
            i64::try_from(keep_builtin_idle).expect("flag bit should fit in i64"),
            Span::test_data(),
        ),
    );

    super::validate_required_struct_ops_value_fields("sched_ext_ops", &body, Span::test_data())
        .expect("sched_ext_ops update_idle with KEEP_BUILTIN_IDLE should be allowed");
}

#[test]
fn test_validate_required_struct_ops_value_fields_rejects_builtin_idle_per_node_without_builtin_idle_enabled()
 {
    let Some(builtin_idle_per_node) = sched_ext_flag_bit("SCX_OPS_BUILTIN_IDLE_PER_NODE") else {
        return;
    };

    let mut body = Record::new();
    body.push("name", Value::string("nu.demo_1", Span::test_data()));
    body.push("update_idle", test_closure_value());
    body.push("select_cpu", test_closure_value());
    body.push(
        "flags",
        Value::int(
            i64::try_from(builtin_idle_per_node).expect("flag bit should fit in i64"),
            Span::test_data(),
        ),
    );

    let err =
        super::validate_required_struct_ops_value_fields("sched_ext_ops", &body, Span::test_data())
            .expect_err("SCX_OPS_BUILTIN_IDLE_PER_NODE without builtin idle should be rejected");
    assert!(err.labels.iter().any(|label| {
        label.text.contains(
            "sets SCX_OPS_BUILTIN_IDLE_PER_NODE without built-in CPU idle selection enabled",
        )
    }));
}

#[test]
fn test_validate_required_struct_ops_value_fields_allows_builtin_idle_per_node_with_keep_builtin_idle()
 {
    let Some(keep_builtin_idle) = sched_ext_flag_bit("SCX_OPS_KEEP_BUILTIN_IDLE") else {
        return;
    };
    let Some(builtin_idle_per_node) = sched_ext_flag_bit("SCX_OPS_BUILTIN_IDLE_PER_NODE") else {
        return;
    };

    let mut body = Record::new();
    body.push("name", Value::string("nu.demo_1", Span::test_data()));
    body.push("update_idle", test_closure_value());
    body.push(
        "flags",
        Value::int(
            i64::try_from(keep_builtin_idle | builtin_idle_per_node)
                .expect("flag bits should fit in i64"),
            Span::test_data(),
        ),
    );
    body.push("select_cpu", test_closure_value());

    super::validate_required_struct_ops_value_fields("sched_ext_ops", &body, Span::test_data())
        .expect("SCX_OPS_BUILTIN_IDLE_PER_NODE with KEEP_BUILTIN_IDLE should be allowed");
}

#[test]
fn test_validate_struct_ops_callback_kfunc_requirements_rejects_builtin_idle_kfuncs_when_update_idle_disables_builtin_idle()
 {
    let mut body = Record::new();
    body.push("name", Value::string("nu.demo_1", Span::test_data()));
    body.push("update_idle", test_closure_value());
    body.push("select_cpu", test_closure_value());

    for kfunc in [
        "scx_bpf_select_cpu_dfl",
        "scx_bpf_select_cpu_and",
        "scx_bpf_test_and_clear_cpu_idle",
        "scx_bpf_pick_idle_cpu",
        "scx_bpf_pick_idle_cpu_node",
    ] {
        let callback_kfuncs = sched_ext_callback_kfuncs("select_cpu", &[kfunc]);
        let err = super::validate_struct_ops_callback_kfunc_requirements(
            "sched_ext_ops",
            &body,
            &callback_kfuncs,
            Span::test_data(),
        )
        .expect_err(
            "builtin-idle kfunc should be rejected when update_idle disables builtin idle tracking",
        );
        assert!(
            err.labels.iter().any(|label| label.text.contains(kfunc)),
            "unexpected errors for {kfunc}: {:?}",
            err
        );
    }
}

#[test]
fn test_validate_struct_ops_callback_kfunc_requirements_allows_builtin_idle_kfuncs_with_keep_builtin_idle()
 {
    let Some(keep_builtin_idle) = sched_ext_flag_bit("SCX_OPS_KEEP_BUILTIN_IDLE") else {
        return;
    };

    let mut body = Record::new();
    body.push("name", Value::string("nu.demo_1", Span::test_data()));
    body.push("update_idle", test_closure_value());
    body.push("select_cpu", test_closure_value());
    body.push(
        "flags",
        Value::int(
            i64::try_from(keep_builtin_idle).expect("flag bit should fit in i64"),
            Span::test_data(),
        ),
    );

    for kfunc in [
        "scx_bpf_select_cpu_dfl",
        "scx_bpf_select_cpu_and",
        "scx_bpf_test_and_clear_cpu_idle",
        "scx_bpf_pick_idle_cpu",
    ] {
        let callback_kfuncs = sched_ext_callback_kfuncs("select_cpu", &[kfunc]);
        super::validate_struct_ops_callback_kfunc_requirements(
            "sched_ext_ops",
            &body,
            &callback_kfuncs,
            Span::test_data(),
        )
        .expect("KEEP_BUILTIN_IDLE should preserve builtin-idle kfunc availability");
    }
}

#[test]
fn test_validate_struct_ops_callback_kfunc_requirements_rejects_pick_idle_cpu_node_without_per_node_flag()
 {
    let Some(keep_builtin_idle) = sched_ext_flag_bit("SCX_OPS_KEEP_BUILTIN_IDLE") else {
        return;
    };

    let mut body = Record::new();
    body.push("name", Value::string("nu.demo_1", Span::test_data()));
    body.push(
        "flags",
        Value::int(
            i64::try_from(keep_builtin_idle).expect("flag bit should fit in i64"),
            Span::test_data(),
        ),
    );

    let callback_kfuncs = sched_ext_callback_kfuncs("select_cpu", &["scx_bpf_pick_idle_cpu_node"]);
    let err = super::validate_struct_ops_callback_kfunc_requirements(
        "sched_ext_ops",
        &body,
        &callback_kfuncs,
        Span::test_data(),
    )
    .expect_err("pick_idle_cpu_node should require SCX_OPS_BUILTIN_IDLE_PER_NODE");
    assert!(err.labels.iter().any(|label| {
        label
            .text
            .contains("uses 'scx_bpf_pick_idle_cpu_node' without SCX_OPS_BUILTIN_IDLE_PER_NODE")
    }));
}

#[test]
fn test_validate_struct_ops_callback_kfunc_requirements_rejects_pick_idle_cpu_with_per_node_flag() {
    let Some(keep_builtin_idle) = sched_ext_flag_bit("SCX_OPS_KEEP_BUILTIN_IDLE") else {
        return;
    };
    let Some(builtin_idle_per_node) = sched_ext_flag_bit("SCX_OPS_BUILTIN_IDLE_PER_NODE") else {
        return;
    };

    let mut body = Record::new();
    body.push("name", Value::string("nu.demo_1", Span::test_data()));
    body.push(
        "flags",
        Value::int(
            i64::try_from(keep_builtin_idle | builtin_idle_per_node)
                .expect("flag bits should fit in i64"),
            Span::test_data(),
        ),
    );

    let callback_kfuncs = sched_ext_callback_kfuncs("select_cpu", &["scx_bpf_pick_idle_cpu"]);
    let err = super::validate_struct_ops_callback_kfunc_requirements(
        "sched_ext_ops",
        &body,
        &callback_kfuncs,
        Span::test_data(),
    )
    .expect_err("pick_idle_cpu should be rejected when per-node idle masks are enabled");
    assert!(err.labels.iter().any(|label| {
            label
                .text
                .contains("uses 'scx_bpf_pick_idle_cpu', but SCX_OPS_BUILTIN_IDLE_PER_NODE enables per-node idle masks")
        }));
}

#[test]
fn test_validate_struct_ops_callback_kfunc_requirements_rejects_pick_any_cpu_with_per_node_flag() {
    let Some(keep_builtin_idle) = sched_ext_flag_bit("SCX_OPS_KEEP_BUILTIN_IDLE") else {
        return;
    };
    let Some(builtin_idle_per_node) = sched_ext_flag_bit("SCX_OPS_BUILTIN_IDLE_PER_NODE") else {
        return;
    };

    let mut body = Record::new();
    body.push("name", Value::string("nu.demo_1", Span::test_data()));
    body.push(
        "flags",
        Value::int(
            i64::try_from(keep_builtin_idle | builtin_idle_per_node)
                .expect("flag bits should fit in i64"),
            Span::test_data(),
        ),
    );

    let callback_kfuncs = sched_ext_callback_kfuncs("select_cpu", &["scx_bpf_pick_any_cpu"]);
    let err = super::validate_struct_ops_callback_kfunc_requirements(
        "sched_ext_ops",
        &body,
        &callback_kfuncs,
        Span::test_data(),
    )
    .expect_err("pick_any_cpu should be rejected when per-node idle masks are enabled");
    assert!(err.labels.iter().any(|label| {
            label
                .text
                .contains("uses 'scx_bpf_pick_any_cpu', but SCX_OPS_BUILTIN_IDLE_PER_NODE requires scx_bpf_pick_idle_cpu_node instead")
        }));
}

#[test]
fn test_validate_struct_ops_callback_kfunc_requirements_allows_pick_idle_cpu_node_with_per_node_flag()
 {
    let Some(keep_builtin_idle) = sched_ext_flag_bit("SCX_OPS_KEEP_BUILTIN_IDLE") else {
        return;
    };
    let Some(builtin_idle_per_node) = sched_ext_flag_bit("SCX_OPS_BUILTIN_IDLE_PER_NODE") else {
        return;
    };

    let mut body = Record::new();
    body.push("name", Value::string("nu.demo_1", Span::test_data()));
    body.push(
        "flags",
        Value::int(
            i64::try_from(keep_builtin_idle | builtin_idle_per_node)
                .expect("flag bits should fit in i64"),
            Span::test_data(),
        ),
    );

    let callback_kfuncs = sched_ext_callback_kfuncs("select_cpu", &["scx_bpf_pick_idle_cpu_node"]);
    super::validate_struct_ops_callback_kfunc_requirements(
        "sched_ext_ops",
        &body,
        &callback_kfuncs,
        Span::test_data(),
    )
    .expect("pick_idle_cpu_node should be allowed when per-node builtin idle masks are enabled");
}

#[test]
fn test_validate_struct_ops_callback_kfunc_requirements_is_noop_for_non_sched_ext_families() {
    let mut body = Record::new();
    body.push("name", Value::string("reno", Span::test_data()));
    let callback_kfuncs = sched_ext_callback_kfuncs("cong_control", &["scx_bpf_pick_idle_cpu"]);

    super::validate_struct_ops_callback_kfunc_requirements(
        "tcp_congestion_ops",
        &body,
        &callback_kfuncs,
        Span::test_data(),
    )
    .expect(
        "non-sched_ext struct_ops families should ignore sched_ext-specific callback-kfunc policy",
    );
}

#[test]
fn test_validate_required_struct_ops_value_fields_rejects_non_int_dispatch_max_batch() {
    if KernelBtf::get()
        .kernel_named_type_size_bytes("sched_ext_ops")
        .is_err()
    {
        return;
    }

    let mut body = Record::new();
    body.push("name", Value::string("nu.demo_1", Span::test_data()));
    body.push("dispatch_max_batch", Value::bool(true, Span::test_data()));

    let err =
        super::validate_required_struct_ops_value_fields("sched_ext_ops", &body, Span::test_data())
            .expect_err("non-integer sched_ext_ops dispatch_max_batch should be rejected");
    assert!(err.labels.iter().any(|label| {
        label
            .text
            .contains("requires 'dispatch_max_batch' to be a non-negative integer")
    }));
}

#[test]
fn test_validate_required_struct_ops_value_fields_rejects_negative_dispatch_max_batch() {
    if KernelBtf::get()
        .kernel_named_type_size_bytes("sched_ext_ops")
        .is_err()
    {
        return;
    }

    let mut body = Record::new();
    body.push("name", Value::string("nu.demo_1", Span::test_data()));
    body.push("dispatch_max_batch", Value::int(-1, Span::test_data()));

    let err =
        super::validate_required_struct_ops_value_fields("sched_ext_ops", &body, Span::test_data())
            .expect_err("negative sched_ext_ops dispatch_max_batch should be rejected");
    assert!(err.labels.iter().any(|label| {
        label
            .text
            .contains("requires 'dispatch_max_batch' to be a non-negative integer")
    }));
}

#[test]
fn test_validate_required_struct_ops_value_fields_rejects_too_large_dispatch_max_batch() {
    if KernelBtf::get()
        .kernel_named_type_size_bytes("sched_ext_ops")
        .is_err()
    {
        return;
    }

    let mut body = Record::new();
    body.push("name", Value::string("nu.demo_1", Span::test_data()));
    body.push(
        "dispatch_max_batch",
        Value::int(i64::from(u32::MAX) + 1, Span::test_data()),
    );

    let err =
        super::validate_required_struct_ops_value_fields("sched_ext_ops", &body, Span::test_data())
            .expect_err("oversized sched_ext_ops dispatch_max_batch should be rejected");
    assert!(err.labels.iter().any(|label| {
        label.text.contains("dispatch_max_batch' value")
            || label.text.contains("dispatch_max_batch")
    }));
}

#[test]
fn test_validate_required_struct_ops_value_fields_rejects_dispatch_max_batch_above_int_max() {
    if KernelBtf::get()
        .kernel_named_type_size_bytes("sched_ext_ops")
        .is_err()
    {
        return;
    }

    let mut body = Record::new();
    body.push("name", Value::string("nu.demo_1", Span::test_data()));
    body.push(
        "dispatch_max_batch",
        Value::int(
            super::struct_ops::SCHED_EXT_MAX_DISPATCH_BATCH + 1,
            Span::test_data(),
        ),
    );

    let err =
        super::validate_required_struct_ops_value_fields("sched_ext_ops", &body, Span::test_data())
            .expect_err("dispatch_max_batch above INT_MAX should be rejected");
    assert!(
        err.labels
            .iter()
            .any(|label| { label.text.contains("dispatch_max_batch is too large") })
    );
}

#[test]
fn test_validate_required_struct_ops_value_fields_allows_dispatch_max_batch_int_max() {
    if KernelBtf::get()
        .kernel_named_type_size_bytes("sched_ext_ops")
        .is_err()
    {
        return;
    }

    let mut body = Record::new();
    body.push("name", Value::string("nu.demo_1", Span::test_data()));
    body.push(
        "dispatch_max_batch",
        Value::int(
            super::struct_ops::SCHED_EXT_MAX_DISPATCH_BATCH,
            Span::test_data(),
        ),
    );

    super::validate_required_struct_ops_value_fields("sched_ext_ops", &body, Span::test_data())
        .expect("sched_ext_ops dispatch_max_batch at INT_MAX should be allowed");
}

#[test]
fn test_validate_required_struct_ops_value_fields_rejects_negative_exit_dump_len() {
    if KernelBtf::get()
        .kernel_named_type_size_bytes("sched_ext_ops")
        .is_err()
    {
        return;
    }

    let mut body = Record::new();
    body.push("name", Value::string("nu.demo_1", Span::test_data()));
    body.push("exit_dump_len", Value::int(-1, Span::test_data()));

    let err =
        super::validate_required_struct_ops_value_fields("sched_ext_ops", &body, Span::test_data())
            .expect_err("negative sched_ext_ops exit_dump_len should be rejected");
    assert!(err.labels.iter().any(|label| {
        label
            .text
            .contains("requires 'exit_dump_len' to be a non-negative integer")
    }));
}

#[test]
fn test_validate_required_struct_ops_value_fields_rejects_negative_hotplug_seq() {
    if KernelBtf::get()
        .kernel_named_type_size_bytes("sched_ext_ops")
        .is_err()
    {
        return;
    }

    let mut body = Record::new();
    body.push("name", Value::string("nu.demo_1", Span::test_data()));
    body.push("hotplug_seq", Value::int(-1, Span::test_data()));

    let err =
        super::validate_required_struct_ops_value_fields("sched_ext_ops", &body, Span::test_data())
            .expect_err("negative sched_ext_ops hotplug_seq should be rejected");
    assert!(err.labels.iter().any(|label| {
        label
            .text
            .contains("requires 'hotplug_seq' to be a non-negative integer")
    }));
}

#[test]
fn test_default_struct_ops_object_name_sanitizes_type_name() {
    assert_eq!(
        super::default_struct_ops_object_name("sched_ext_ops"),
        "nu_sched_ext_ops"
    );
    assert_eq!(
        super::default_struct_ops_object_name("weird-type/name"),
        "nu_weird_type_name"
    );
}

fn make_ctx_path_program(cell_path: CellPath) -> HirProgram {
    let ctx_var = VarId::new(0);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(cell_path)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 4],
        ast: vec![None; 4],
        comments: vec![],
        register_count: 2,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_ctx_path_non_null_program(cell_path: CellPath) -> HirProgram {
    let ctx_var = VarId::new(0);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(cell_path)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::BinaryOp {
                    lhs_dst: RegId::new(0),
                    op: Operator::Comparison(Comparison::NotEqual),
                    rhs: RegId::new(2),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 6],
        ast: vec![None; 6],
        comments: vec![],
        register_count: 3,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn string_member(name: &str) -> PathMember {
    PathMember::test_string(name.to_string(), false, Casing::Sensitive)
}

fn int_member(index: usize) -> PathMember {
    PathMember::Int {
        val: index,
        span: Span::test_data(),
        optional: false,
    }
}

fn find_function_trampoline_named_projection_candidate() -> Option<(String, String, String)> {
    for (function_name, arg_name, field_name) in [("security_file_open", "file", "f_flags")] {
        let path = [TrampolineFieldSelector::Field(field_name.to_string())];
        if let Ok(Some(arg_idx)) =
            KernelBtf::get().function_trampoline_arg_index_by_name(function_name, arg_name)
            && matches!(
                KernelBtf::get().function_trampoline_arg_field(function_name, arg_idx, &path),
                Ok(Some(_))
            )
        {
            return Some((
                function_name.to_string(),
                arg_name.to_string(),
                field_name.to_string(),
            ));
        }
    }
    None
}

fn find_function_trampoline_named_struct_leaf_candidate() -> Option<(String, String, String)> {
    for (function_name, arg_name, field_name) in [("security_file_open", "file", "f_path")] {
        let path = [TrampolineFieldSelector::Field(field_name.to_string())];
        if let Ok(Some(arg_idx)) =
            KernelBtf::get().function_trampoline_arg_index_by_name(function_name, arg_name)
            && matches!(
                KernelBtf::get().function_trampoline_arg_field(function_name, arg_idx, &path),
                Ok(Some(_))
            )
        {
            return Some((
                function_name.to_string(),
                arg_name.to_string(),
                field_name.to_string(),
            ));
        }
    }
    None
}

fn find_function_trampoline_named_root_candidate() -> Option<(String, String)> {
    for (function_name, arg_name) in [
        ("security_file_open", "file"),
        ("do_close_on_exec", "files"),
    ] {
        if matches!(
            KernelBtf::get().function_trampoline_arg_index_by_name(function_name, arg_name),
            Ok(Some(_))
        ) {
            return Some((function_name.to_string(), arg_name.to_string()));
        }
    }
    None
}

fn find_function_trampoline_named_pointer_index_candidate() -> Option<(String, String)> {
    for (function_name, arg_name) in [("do_close_on_exec", "files")] {
        let path = [
            TrampolineFieldSelector::Field("fdt".to_string()),
            TrampolineFieldSelector::Field("fd".to_string()),
            TrampolineFieldSelector::Index(0),
            TrampolineFieldSelector::Field("f_inode".to_string()),
            TrampolineFieldSelector::Field("i_ino".to_string()),
        ];
        if let Ok(Some(arg_idx)) =
            KernelBtf::get().function_trampoline_arg_index_by_name(function_name, arg_name)
            && matches!(
                KernelBtf::get().function_trampoline_arg_field(function_name, arg_idx, &path),
                Ok(Some(_))
            )
        {
            return Some((function_name.to_string(), arg_name.to_string()));
        }
    }
    None
}

fn find_tp_btf_named_projection_candidate() -> Option<(String, String, String)> {
    for (tracepoint_name, arg_name, field_name) in [
        ("sys_enter", "regs", "orig_ax"),
        ("sys_exit", "regs", "orig_ax"),
    ] {
        let path = [TrampolineFieldSelector::Field(field_name.to_string())];
        if let Ok(Some(arg_idx)) =
            KernelBtf::get().tp_btf_arg_index_by_name(tracepoint_name, arg_name)
            && matches!(
                KernelBtf::get().tp_btf_arg_field(tracepoint_name, arg_idx, &path),
                Ok(Some(_))
            )
        {
            return Some((
                tracepoint_name.to_string(),
                arg_name.to_string(),
                field_name.to_string(),
            ));
        }
    }
    None
}

fn tracepoint_field_matches(
    target: &str,
    field_name: &str,
    predicate: impl FnOnce(&TypeInfo) -> bool,
) -> bool {
    let Some((category, name)) = target.split_once('/') else {
        return false;
    };
    let Ok(ctx) = KernelBtf::get().get_tracepoint_context(category, name) else {
        return false;
    };
    ctx.get_field(field_name)
        .is_some_and(|field| predicate(&field.type_info))
}

fn find_tracepoint_pointer_field_candidate() -> Option<(String, String)> {
    for (target, field_name) in [
        ("syscalls/sys_enter_openat", "filename"),
        ("syscalls/sys_enter_openat2", "filename"),
        ("syscalls/sys_enter_execve", "filename"),
    ] {
        if tracepoint_field_matches(target, field_name, TypeInfo::is_ptr) {
            return Some((target.to_string(), field_name.to_string()));
        }
    }
    None
}

fn find_lsm_named_projection_candidate() -> Option<(String, String, String)> {
    for (hook_name, arg_name, field_name) in [("file_open", "file", "f_flags")] {
        let path = [TrampolineFieldSelector::Field(field_name.to_string())];
        if let Ok(Some(arg_idx)) = KernelBtf::get().lsm_hook_arg_index_by_name(hook_name, arg_name)
            && matches!(
                KernelBtf::get().lsm_hook_arg_field(hook_name, arg_idx, &path),
                Ok(Some(_))
            )
        {
            return Some((
                hook_name.to_string(),
                arg_name.to_string(),
                field_name.to_string(),
            ));
        }
    }
    None
}

fn find_fexit_ret_candidate() -> Option<String> {
    for function_name in ["ksys_read", "do_sys_openat2", "__jump_label_patch"] {
        if matches!(
            KernelBtf::get().function_trampoline_ret_type_info(function_name),
            Ok(Some(_))
        ) {
            return Some(function_name.to_string());
        }
    }
    None
}

fn find_fexit_ret_projection_candidate() -> Option<(String, String)> {
    for (function_name, field_name) in [("__jump_label_patch", "size")] {
        let path = [TrampolineFieldSelector::Field(field_name.to_string())];
        if matches!(
            KernelBtf::get().function_trampoline_ret_field(function_name, &path),
            Ok(Some(_))
        ) {
            return Some((function_name.to_string(), field_name.to_string()));
        }
    }
    None
}

fn make_ctx_path_call_program(cell_path: CellPath, decl_id: DeclId) -> HirProgram {
    let ctx_var = VarId::new(0);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(cell_path)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::Call {
                    decl_id,
                    src_dst: RegId::new(0),
                    args: HirCallArgs::default(),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 4],
        ast: vec![None; 4],
        comments: vec![],
        register_count: 2,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_ctx_path_discard_program(cell_path: CellPath) -> HirProgram {
    let ctx_var = VarId::new(0);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(cell_path)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(0),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(2) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 5],
        ast: vec![None; 5],
        comments: vec![],
        register_count: 3,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_random_int_count_program(random_decl_id: DeclId, count_decl_id: DeclId) -> HirProgram {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::Call {
                    decl_id: random_decl_id,
                    src_dst: RegId::new(0),
                    args: HirCallArgs::default(),
                },
                HirStmt::Call {
                    decl_id: count_decl_id,
                    src_dst: RegId::new(0),
                    args: HirCallArgs::default(),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 2],
        ast: vec![None; 2],
        comments: vec![],
        register_count: 1,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], None)
}

fn make_random_int_range_count_program(
    random_decl_id: DeclId,
    count_decl_id: DeclId,
    start: i64,
    end: i64,
) -> HirProgram {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Int(start),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(end),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::Range {
                        start: RegId::new(0),
                        step: RegId::new(1),
                        end: RegId::new(2),
                        inclusion: RangeInclusion::Inclusive,
                    },
                },
                HirStmt::Call {
                    decl_id: random_decl_id,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        positional: vec![RegId::new(3)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: count_decl_id,
                    src_dst: RegId::new(4),
                    args: HirCallArgs::default(),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(4) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 6],
        ast: vec![None; 6],
        comments: vec![],
        register_count: 5,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], None)
}

fn make_tail_call_program(tail_call_decl_id: DeclId) -> HirProgram {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String(b"dispatch_targets".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::Call {
                    decl_id: tail_call_decl_id,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1), RegId::new(2)],
                        ..HirCallArgs::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 3],
        ast: vec![None; 3],
        comments: vec![],
        register_count: 3,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], None)
}

fn make_bound_ctx_path_projection_call_program(
    root_path: CellPath,
    projection_path: CellPath,
    decl_id: DeclId,
) -> HirProgram {
    let ctx_var = VarId::new(0);
    let bound_var = VarId::new(1);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(root_path)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::StoreVariable {
                    var_id: bound_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(2),
                    var_id: bound_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::CellPath(Box::new(projection_path)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(2),
                    path: RegId::new(3),
                },
                HirStmt::Call {
                    decl_id,
                    src_dst: RegId::new(2),
                    args: HirCallArgs::default(),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(2) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 9],
        ast: vec![None; 9],
        comments: vec![],
        register_count: 4,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_ctx_path_store_program(
    cell_path: CellPath,
    new_value: HirLiteral,
    return_value: HirLiteral,
) -> HirProgram {
    let ctx_var = VarId::new(0);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(cell_path)),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: new_value,
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                    new_value: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: return_value,
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(3) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 5],
        ast: vec![None; 5],
        comments: vec![],
        register_count: 4,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_literal_return_program(lit: HirLiteral) -> HirProgram {
    let ctx_var = VarId::new(0);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![HirStmt::LoadLiteral {
                dst: RegId::new(0),
                lit,
            }],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data()],
        ast: vec![None],
        comments: vec![],
        register_count: 1,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_int_return_program(value: i64) -> HirProgram {
    make_literal_return_program(HirLiteral::Int(value))
}

fn make_intrinsic_call_return_program(
    decl_id: DeclId,
    positional: Vec<HirLiteral>,
    named: Vec<(Vec<u8>, HirLiteral)>,
    flags: Vec<Vec<u8>>,
    return_value: HirLiteral,
) -> HirProgram {
    let ctx_var = VarId::new(0);
    let mut stmts = Vec::new();
    let mut next_reg = 1u32;
    let mut positional_regs = Vec::new();
    let mut named_regs = Vec::new();

    for lit in positional {
        stmts.push(HirStmt::LoadLiteral {
            dst: RegId::new(next_reg),
            lit,
        });
        positional_regs.push(RegId::new(next_reg));
        next_reg += 1;
    }

    for (name, lit) in named {
        stmts.push(HirStmt::LoadLiteral {
            dst: RegId::new(next_reg),
            lit,
        });
        named_regs.push((name, RegId::new(next_reg)));
        next_reg += 1;
    }

    stmts.push(HirStmt::Call {
        decl_id,
        src_dst: RegId::new(0),
        args: HirCallArgs {
            positional: positional_regs,
            named: named_regs,
            flags,
            ..Default::default()
        },
    });

    let return_reg = RegId::new(next_reg);
    stmts.push(HirStmt::LoadLiteral {
        dst: return_reg,
        lit: return_value,
    });

    let stmt_count = stmts.len();
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts,
            terminator: HirTerminator::Return { src: return_reg },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); stmt_count],
        ast: vec![None; stmt_count],
        comments: vec![],
        register_count: next_reg + 1,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

struct ExpectedHelperCall {
    helper: BpfHelper,
    arg_count: usize,
    const_args: &'static [(usize, i64)],
}

fn compile_intrinsic_call_expect_helper(
    context: &str,
    command_name: &str,
    program_type: EbpfProgramType,
    target: &str,
    positional: Vec<HirLiteral>,
    named: Vec<(Vec<u8>, HirLiteral)>,
    flags: Vec<Vec<u8>>,
    return_value: HirLiteral,
    expected: ExpectedHelperCall,
) {
    let hir =
        make_intrinsic_call_return_program(DeclId::new(42), positional, named, flags, return_value);
    let probe_ctx = ProbeContext::new(program_type, target);
    let decl_names = HashMap::from([(DeclId::new(42), command_name.to_string())]);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .unwrap_or_else(|err| panic!("{context} {command_name} should lower: {err}"));

    let block = lowering.program.main.block(lowering.program.main.entry);
    assert!(
        block.instructions.iter().any(|inst| matches!(
            inst,
            MirInst::CallHelper {
                helper,
                args,
                ..
            } if *helper == expected.helper as u32
                && args.len() == expected.arg_count
                && expected.const_args.iter().all(|(idx, value)| {
                    matches!(args.get(*idx), Some(MirValue::Const(actual)) if *actual == *value)
                })
        )),
        "{context} {command_name} should call {} with expected arguments",
        expected.helper.name()
    );

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .unwrap_or_else(|err| panic!("{context} {command_name} should compile: {err}"));

    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

fn make_list_iterate_count_program(count_decl_id: DeclId) -> HirProgram {
    let ctx_var = VarId::new(0);
    let func = HirFunction {
        blocks: vec![
            HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadLiteral {
                        dst: RegId::new(0),
                        lit: HirLiteral::List { capacity: 4 },
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::Int(10),
                    },
                    HirStmt::ListPush {
                        src_dst: RegId::new(0),
                        item: RegId::new(1),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::Int(20),
                    },
                    HirStmt::ListPush {
                        src_dst: RegId::new(0),
                        item: RegId::new(2),
                    },
                ],
                terminator: HirTerminator::Jump {
                    target: HirBlockId(1),
                },
            },
            HirBlock {
                id: HirBlockId(1),
                stmts: vec![],
                terminator: HirTerminator::Iterate {
                    dst: RegId::new(3),
                    stream: RegId::new(0),
                    body: HirBlockId(2),
                    end: HirBlockId(3),
                },
            },
            HirBlock {
                id: HirBlockId(2),
                stmts: vec![HirStmt::Call {
                    decl_id: count_decl_id,
                    src_dst: RegId::new(3),
                    args: HirCallArgs::default(),
                }],
                terminator: HirTerminator::Jump {
                    target: HirBlockId(1),
                },
            },
            HirBlock {
                id: HirBlockId(3),
                stmts: vec![],
                terminator: HirTerminator::Return { src: RegId::new(3) },
            },
        ],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 6],
        ast: vec![None; 6],
        comments: vec![],
        register_count: 4,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_ctx_iterate_count_program(cell_path: CellPath, count_decl_id: DeclId) -> HirProgram {
    let ctx_var = VarId::new(0);
    let func = HirFunction {
        blocks: vec![
            HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(cell_path)),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                ],
                terminator: HirTerminator::Jump {
                    target: HirBlockId(1),
                },
            },
            HirBlock {
                id: HirBlockId(1),
                stmts: vec![],
                terminator: HirTerminator::Iterate {
                    dst: RegId::new(2),
                    stream: RegId::new(0),
                    body: HirBlockId(2),
                    end: HirBlockId(3),
                },
            },
            HirBlock {
                id: HirBlockId(2),
                stmts: vec![HirStmt::Call {
                    decl_id: count_decl_id,
                    src_dst: RegId::new(2),
                    args: HirCallArgs::default(),
                }],
                terminator: HirTerminator::Jump {
                    target: HirBlockId(1),
                },
            },
            HirBlock {
                id: HirBlockId(3),
                stmts: vec![],
                terminator: HirTerminator::Return { src: RegId::new(2) },
            },
        ],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 4],
        ast: vec![None; 4],
        comments: vec![],
        register_count: 3,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_typed_global_define_count_program(
    define_decl_id: DeclId,
    get_decl_id: DeclId,
    count_decl_id: DeclId,
    type_spec: &str,
) -> HirProgram {
    let ctx_var = VarId::new(0);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("seen_pid".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String(type_spec.into()),
                },
                HirStmt::Call {
                    decl_id: define_decl_id,
                    src_dst: RegId::new(2),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        named: vec![(b"type".to_vec(), RegId::new(1))],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: get_decl_id,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: count_decl_id,
                    src_dst: RegId::new(3),
                    args: HirCallArgs::default(),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(3) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 5],
        ast: vec![None; 5],
        comments: vec![],
        register_count: 4,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_typed_global_define_list_get_count_program(
    define_decl_id: DeclId,
    get_decl_id: DeclId,
    count_decl_id: DeclId,
    type_spec: &str,
) -> HirProgram {
    let ctx_var = VarId::new(0);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("seen_hist".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String(type_spec.into()),
                },
                HirStmt::Call {
                    decl_id: define_decl_id,
                    src_dst: RegId::new(2),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        named: vec![(b"type".to_vec(), RegId::new(1))],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: get_decl_id,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![int_member(0)],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(3),
                    path: RegId::new(4),
                },
                HirStmt::Call {
                    decl_id: count_decl_id,
                    src_dst: RegId::new(3),
                    args: HirCallArgs::default(),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(3) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 7],
        ast: vec![None; 7],
        comments: vec![],
        register_count: 5,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_typed_global_define_record_array_field_count_program(
    define_decl_id: DeclId,
    get_decl_id: DeclId,
    count_decl_id: DeclId,
) -> HirProgram {
    let ctx_var = VarId::new(0);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("seen_entries".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{record{pid:int,cpu:u32}:2}".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl_id,
                    src_dst: RegId::new(2),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        named: vec![(b"type".to_vec(), RegId::new(1))],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: get_decl_id,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![int_member(1), string_member("cpu")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(3),
                    path: RegId::new(4),
                },
                HirStmt::Call {
                    decl_id: count_decl_id,
                    src_dst: RegId::new(3),
                    args: HirCallArgs::default(),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(3) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 7],
        ast: vec![None; 7],
        comments: vec![],
        register_count: 5,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_typed_global_define_record_array_initializer_field_count_program(
    define_decl_id: DeclId,
    get_decl_id: DeclId,
    count_decl_id: DeclId,
) -> HirProgram {
    let ctx_var = VarId::new(0);
    let mut first = Record::with_capacity(2);
    first.push("pid", Value::int(7, Span::test_data()));
    first.push("cpu", Value::int(2, Span::test_data()));

    let mut second = Record::with_capacity(2);
    second.push("pid", Value::int(9, Span::test_data()));
    second.push("cpu", Value::int(3, Span::test_data()));

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadValue {
                    dst: RegId::new(0),
                    val: Box::new(Value::list(
                        vec![
                            Value::record(first, Span::test_data()),
                            Value::record(second, Span::test_data()),
                        ],
                        Span::test_data(),
                    )),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("seen_entries".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("array{record{pid:int,cpu:u32}:2}".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl_id,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        named: vec![(b"type".to_vec(), RegId::new(2))],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: get_decl_id,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![int_member(1), string_member("cpu")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(3),
                    path: RegId::new(4),
                },
                HirStmt::Call {
                    decl_id: count_decl_id,
                    src_dst: RegId::new(3),
                    args: HirCallArgs::default(),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(3) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 8],
        ast: vec![None; 8],
        comments: vec![],
        register_count: 5,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_typed_global_define_record_with_record_array_initializer_field_count_program(
    define_decl_id: DeclId,
    get_decl_id: DeclId,
    count_decl_id: DeclId,
) -> HirProgram {
    let ctx_var = VarId::new(0);
    let mut first = Record::with_capacity(2);
    first.push("pid", Value::int(7, Span::test_data()));
    first.push("cpu", Value::int(2, Span::test_data()));

    let mut second = Record::with_capacity(2);
    second.push("pid", Value::int(9, Span::test_data()));
    second.push("cpu", Value::int(3, Span::test_data()));

    let mut state = Record::with_capacity(1);
    state.push(
        "entries",
        Value::list(
            vec![
                Value::record(first, Span::test_data()),
                Value::record(second, Span::test_data()),
            ],
            Span::test_data(),
        ),
    );

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadValue {
                    dst: RegId::new(0),
                    val: Box::new(Value::record(state, Span::test_data())),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("seen_state".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String(
                        "record{entries:array{record{pid:int,cpu:u32}:2}}".into(),
                    ),
                },
                HirStmt::Call {
                    decl_id: define_decl_id,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        named: vec![(b"type".to_vec(), RegId::new(2))],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: get_decl_id,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![
                            string_member("entries"),
                            int_member(1),
                            string_member("cpu"),
                        ],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(3),
                    path: RegId::new(4),
                },
                HirStmt::Call {
                    decl_id: count_decl_id,
                    src_dst: RegId::new(3),
                    args: HirCallArgs::default(),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(3) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 8],
        ast: vec![None; 8],
        comments: vec![],
        register_count: 5,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_annotated_mut_int_count_program(count_decl_id: DeclId) -> HirProgram {
    let ctx_var = VarId::new(0);
    let global_var = VarId::new(10);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: global_var,
                },
                HirStmt::Call {
                    decl_id: count_decl_id,
                    src_dst: RegId::new(0),
                    args: HirCallArgs::default(),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 2],
        ast: vec![None; 2],
        comments: vec![],
        register_count: 1,
        file_count: 0,
    };
    let mut hir = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    hir.annotated_mut_globals = vec![crate::compiler::hir::AnnotatedMutGlobal {
        var_id: global_var,
        declared_type: Type::Int,
        initial_value: Value::int(7, Span::test_data()),
    }];
    hir
}

fn make_annotated_mut_record_list_get_count_program(
    get_decl_id: DeclId,
    count_decl_id: DeclId,
) -> HirProgram {
    let ctx_var = VarId::new(0);
    let global_var = VarId::new(10);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: global_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("vals")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::Call {
                    decl_id: get_decl_id,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: count_decl_id,
                    src_dst: RegId::new(0),
                    args: HirCallArgs::default(),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 6],
        ast: vec![None; 6],
        comments: vec![],
        register_count: 3,
        file_count: 0,
    };

    let mut record = Record::new();
    record.push(
        "vals",
        Value::list(
            vec![
                Value::int(11, Span::test_data()),
                Value::int(22, Span::test_data()),
            ],
            Span::test_data(),
        ),
    );
    record.push("pid", Value::int(0, Span::test_data()));

    let mut hir = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    hir.annotated_mut_globals = vec![crate::compiler::hir::AnnotatedMutGlobal {
        var_id: global_var,
        declared_type: Type::Record(Box::new([
            ("vals".to_string(), Type::List(Box::new(Type::Int))),
            ("pid".to_string(), Type::Int),
        ])),
        initial_value: Value::record(record, Span::test_data()),
    }];
    hir
}

fn make_annotated_mut_fixed_record_array_field_count_program(
    get_decl_id: DeclId,
    count_decl_id: DeclId,
) -> HirProgram {
    let ctx_var = VarId::new(0);
    let global_var = VarId::new(10);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: global_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::Call {
                    decl_id: get_decl_id,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("cpu")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(2),
                },
                HirStmt::Call {
                    decl_id: count_decl_id,
                    src_dst: RegId::new(0),
                    args: HirCallArgs::default(),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 6],
        ast: vec![None; 6],
        comments: vec![],
        register_count: 3,
        file_count: 0,
    };

    let mut first = Record::new();
    first.push("pid", Value::int(7, Span::test_data()));
    first.push("cpu", Value::int(2, Span::test_data()));

    let mut second = Record::new();
    second.push("pid", Value::int(9, Span::test_data()));
    second.push("cpu", Value::int(3, Span::test_data()));

    let mut hir = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    hir.annotated_mut_globals = vec![crate::compiler::hir::AnnotatedMutGlobal {
        var_id: global_var,
        declared_type: Type::List(Box::new(Type::Record(Box::new([
            ("pid".to_string(), Type::Int),
            ("cpu".to_string(), Type::Int),
        ])))),
        initial_value: Value::list(
            vec![
                Value::record(first, Span::test_data()),
                Value::record(second, Span::test_data()),
            ],
            Span::test_data(),
        ),
    }];
    hir
}

fn make_annotated_mut_record_with_fixed_record_array_field_count_program(
    count_decl_id: DeclId,
) -> HirProgram {
    let ctx_var = VarId::new(0);
    let global_var = VarId::new(10);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: global_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![
                            string_member("entries"),
                            int_member(1),
                            string_member("cpu"),
                        ],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::Call {
                    decl_id: count_decl_id,
                    src_dst: RegId::new(0),
                    args: HirCallArgs::default(),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 4],
        ast: vec![None; 4],
        comments: vec![],
        register_count: 2,
        file_count: 0,
    };

    let mut first = Record::new();
    first.push("pid", Value::int(7, Span::test_data()));
    first.push("cpu", Value::int(2, Span::test_data()));

    let mut second = Record::new();
    second.push("pid", Value::int(9, Span::test_data()));
    second.push("cpu", Value::int(3, Span::test_data()));

    let mut state = Record::new();
    state.push(
        "entries",
        Value::list(
            vec![
                Value::record(first, Span::test_data()),
                Value::record(second, Span::test_data()),
            ],
            Span::test_data(),
        ),
    );
    state.push("total", Value::int(2, Span::test_data()));

    let mut hir = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    hir.annotated_mut_globals = vec![crate::compiler::hir::AnnotatedMutGlobal {
        var_id: global_var,
        declared_type: Type::Record(Box::new([
            (
                "entries".to_string(),
                Type::List(Box::new(Type::Record(Box::new([
                    ("pid".to_string(), Type::Int),
                    ("cpu".to_string(), Type::Int),
                ])))),
            ),
            ("total".to_string(), Type::Int),
        ])),
        initial_value: Value::record(state, Span::test_data()),
    }];
    hir
}

fn make_cgroup_sock_addr_nullable_socket_branch_program(count_decl_id: DeclId) -> HirProgram {
    let ctx_var = VarId::new(0);
    let func = HirFunction {
        blocks: vec![
            HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(CellPath {
                            members: vec![string_member("sk")],
                        })),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                ],
                terminator: HirTerminator::BranchIfEmpty {
                    src: RegId::new(0),
                    if_true: HirBlockId(2),
                    if_false: HirBlockId(1),
                },
            },
            HirBlock {
                id: HirBlockId(1),
                stmts: vec![
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(CellPath {
                            members: vec![string_member("family")],
                        })),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                    HirStmt::Call {
                        decl_id: count_decl_id,
                        src_dst: RegId::new(0),
                        args: HirCallArgs::default(),
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            },
            HirBlock {
                id: HirBlockId(2),
                stmts: vec![HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(0),
                }],
                terminator: HirTerminator::ReturnEarly { src: RegId::new(2) },
            },
        ],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 7],
        ast: vec![None; 7],
        comments: vec![],
        register_count: 3,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_descending_range_iterate_count_program(count_decl_id: DeclId) -> HirProgram {
    let func = HirFunction {
        blocks: vec![
            HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadLiteral {
                        dst: RegId::new(0),
                        lit: HirLiteral::Int(3),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::Int(-1),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(3),
                        lit: HirLiteral::Range {
                            start: RegId::new(0),
                            step: RegId::new(1),
                            end: RegId::new(2),
                            inclusion: RangeInclusion::Inclusive,
                        },
                    },
                ],
                terminator: HirTerminator::Iterate {
                    dst: RegId::new(4),
                    stream: RegId::new(3),
                    body: HirBlockId(1),
                    end: HirBlockId(2),
                },
            },
            HirBlock {
                id: HirBlockId(1),
                stmts: vec![HirStmt::Call {
                    decl_id: count_decl_id,
                    src_dst: RegId::new(4),
                    args: HirCallArgs::default(),
                }],
                terminator: HirTerminator::Jump {
                    target: HirBlockId(0),
                },
            },
            HirBlock {
                id: HirBlockId(2),
                stmts: vec![],
                terminator: HirTerminator::Return { src: RegId::new(4) },
            },
        ],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 5],
        ast: vec![None; 5],
        comments: vec![],
        register_count: 5,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], None)
}

fn assert_ctx_path_count_program_compiles(
    program_type: EbpfProgramType,
    target: &str,
    cell_path: CellPath,
    context: &str,
) {
    let _ = compile_ctx_path_count_program(program_type, target, cell_path, context);
}

fn compile_ctx_path_count_program(
    program_type: EbpfProgramType,
    target: &str,
    cell_path: CellPath,
    context: &str,
) -> EbpfProgram {
    let hir = make_ctx_path_call_program(cell_path, DeclId::new(42));
    let probe_ctx = ProbeContext::new(program_type, target);
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "count".to_string());

    let lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .unwrap_or_else(|err| panic!("{context} should lower: {err}"));

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .unwrap_or_else(|err| panic!("{context} should compile: {err}"));

    assert!(
        !result.bytecode.is_empty(),
        "{context} should produce bytecode"
    );

    result.into_program(program_type, target, "main", HashMap::new(), HashMap::new())
}

fn compile_ctx_path_discard_program(
    program_type: EbpfProgramType,
    target: &str,
    cell_path: CellPath,
    context: &str,
) -> EbpfProgram {
    let hir = make_ctx_path_discard_program(cell_path);
    let probe_ctx = ProbeContext::new(program_type, target);

    let lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .unwrap_or_else(|err| panic!("{context} should lower: {err}"));

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .unwrap_or_else(|err| panic!("{context} should compile: {err}"));

    assert!(
        !result.bytecode.is_empty(),
        "{context} should produce bytecode"
    );

    result.into_program(program_type, target, "main", HashMap::new(), HashMap::new())
}

fn assert_ctx_stack_count_program_compiles(field: &str, map_name: &str, context: &str) {
    let hir = make_ctx_path_call_program(
        CellPath {
            members: vec![string_member(field)],
        },
        DeclId::new(42),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let decl_names = HashMap::from([(DeclId::new(42), "count".to_string())]);

    let lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .unwrap_or_else(|err| panic!("{context} should lower: {err}"));

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .unwrap_or_else(|err| panic!("{context} should compile: {err}"));

    let map = result
        .maps
        .iter()
        .find(|map| map.name == map_name)
        .unwrap_or_else(|| panic!("{context} should emit {map_name} stack map"));
    assert_eq!(map.def, BpfMapDef::stack_trace_map());
    assert!(
        !result.bytecode.is_empty(),
        "{context} should produce bytecode"
    );
}

fn assert_guarded_sock_ops_ctx_path_count_program_compiles(
    callback_op: i64,
    counted_path: CellPath,
    context: &str,
) {
    let hir = make_eq_guarded_ctx_path_count_program(
        CellPath {
            members: vec![string_member("op")],
        },
        HirLiteral::Int(callback_op),
        counted_path,
        DeclId::new(42),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
    let decl_names = HashMap::from([(DeclId::new(42), "count".to_string())]);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .unwrap_or_else(|err| panic!("{context} should lower through attach flow: {err}"));

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .unwrap_or_else(|err| panic!("optimized {context} should compile: {err}"));
    assert!(
        !result.bytecode.is_empty(),
        "{context} should produce bytecode"
    );
}

fn assert_attach_program_compiles(
    hir: &HirProgram,
    program_type: EbpfProgramType,
    target: &str,
    decl_names: &HashMap<DeclId, String>,
    context: &str,
) {
    let probe_ctx = ProbeContext::new(program_type, target);

    let mut lowering = lower_hir_to_mir_with_hints(
        hir,
        Some(&probe_ctx),
        decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .unwrap_or_else(|err| panic!("{context} should lower: {err}"));

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .unwrap_or_else(|err| panic!("{context} should compile: {err}"));

    assert!(
        !result.bytecode.is_empty(),
        "{context} should produce bytecode"
    );
}

fn assert_ctx_path_store_program_compiles(
    program_type: EbpfProgramType,
    target: &str,
    cell_path: CellPath,
    new_value: HirLiteral,
    return_value: HirLiteral,
    context: &str,
) {
    let hir = make_ctx_path_store_program(cell_path, new_value, return_value);
    let probe_ctx = ProbeContext::new(program_type, target);

    let lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .unwrap_or_else(|err| panic!("{context} should lower: {err}"));

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .unwrap_or_else(|err| panic!("{context} should compile: {err}"));

    assert!(
        !result.bytecode.is_empty(),
        "{context} should produce bytecode"
    );
}

fn collect_mir_kfunc_names(program: &crate::compiler::mir::MirProgram) -> HashSet<String> {
    fn collect_from_inst(inst: &MirInst, out: &mut HashSet<String>) {
        if let MirInst::CallKfunc { kfunc, .. } = inst {
            out.insert(kfunc.clone());
        }
    }

    fn collect_from_function(func: &crate::compiler::mir::MirFunction, out: &mut HashSet<String>) {
        for block in &func.blocks {
            for inst in &block.instructions {
                collect_from_inst(inst, out);
            }
            collect_from_inst(&block.terminator, out);
        }
    }

    let mut out = HashSet::new();
    collect_from_function(&program.main, &mut out);
    for subfunction in &program.subfunctions {
        collect_from_function(subfunction, &mut out);
    }
    out
}

fn compile_ctx_path_store_program(
    program_type: EbpfProgramType,
    target: &str,
    cell_path: CellPath,
    new_value: HirLiteral,
    return_value: HirLiteral,
    context: &str,
) -> EbpfProgram {
    let hir = make_ctx_path_store_program(cell_path, new_value, return_value);
    let probe_ctx = ProbeContext::new(program_type, target);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .unwrap_or_else(|err| panic!("{context} should lower: {err}"));

    let used_kfuncs = collect_mir_kfunc_names(&lowering.program);

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .unwrap_or_else(|err| panic!("{context} should compile: {err}"));

    assert!(
        !result.bytecode.is_empty(),
        "{context} should produce bytecode"
    );

    result
        .into_program(program_type, target, "main", HashMap::new(), HashMap::new())
        .with_used_kfuncs(used_kfuncs)
}

fn make_map_put_get_projection_program(
    source_path: CellPath,
    map_put_decl: DeclId,
    map_get_decl: DeclId,
    count_decl: DeclId,
) -> HirProgram {
    let ctx_var = VarId::new(0);
    let lookup_var = VarId::new(1);
    let func = HirFunction {
        blocks: vec![
            HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(source_path)),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::String(b"cached_path".to_vec()),
                    },
                    HirStmt::LoadVariable {
                        dst: RegId::new(3),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(4),
                        lit: HirLiteral::CellPath(Box::new(CellPath {
                            members: vec![string_member("pid")],
                        })),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(3),
                        path: RegId::new(4),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(5),
                        lit: HirLiteral::String(b"hash".to_vec()),
                    },
                    HirStmt::Call {
                        decl_id: map_put_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(2), RegId::new(3)],
                            named: vec![(b"kind".to_vec(), RegId::new(5))],
                            pipeline_input: Some(RegId::new(0)),
                            ..Default::default()
                        },
                    },
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(4),
                    },
                    HirStmt::Call {
                        decl_id: map_get_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(2)],
                            named: vec![(b"kind".to_vec(), RegId::new(5))],
                            ..Default::default()
                        },
                    },
                    HirStmt::StoreVariable {
                        var_id: lookup_var,
                        src: RegId::new(0),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(6),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::BinaryOp {
                        lhs_dst: RegId::new(0),
                        op: Operator::Comparison(Comparison::NotEqual),
                        rhs: RegId::new(6),
                    },
                ],
                terminator: HirTerminator::BranchIf {
                    cond: RegId::new(0),
                    if_true: HirBlockId(1),
                    if_false: HirBlockId(2),
                },
            },
            HirBlock {
                id: HirBlockId(1),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: lookup_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(CellPath {
                            members: vec![string_member("dentry"), string_member("d_flags")],
                        })),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                    HirStmt::Call {
                        decl_id: count_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs::default(),
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            },
            HirBlock {
                id: HirBlockId(2),
                stmts: vec![],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            },
        ],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 21],
        ast: vec![None; 21],
        comments: vec![],
        register_count: 7,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_map_get_whole_value_program(map_get_decl: DeclId, terminal_decl: DeclId) -> HirProgram {
    let ctx_var = VarId::new(0);
    let lookup_var = VarId::new(1);
    let func = HirFunction {
        blocks: vec![
            HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(CellPath {
                            members: vec![string_member("pid")],
                        })),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::String(b"cached_path".to_vec()),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(3),
                        lit: HirLiteral::String(b"hash".to_vec()),
                    },
                    HirStmt::Call {
                        decl_id: map_get_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(2)],
                            named: vec![(b"kind".to_vec(), RegId::new(3))],
                            ..Default::default()
                        },
                    },
                    HirStmt::StoreVariable {
                        var_id: lookup_var,
                        src: RegId::new(0),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(4),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::BinaryOp {
                        lhs_dst: RegId::new(0),
                        op: Operator::Comparison(Comparison::NotEqual),
                        rhs: RegId::new(4),
                    },
                ],
                terminator: HirTerminator::BranchIf {
                    cond: RegId::new(0),
                    if_true: HirBlockId(1),
                    if_false: HirBlockId(2),
                },
            },
            HirBlock {
                id: HirBlockId(1),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: lookup_var,
                    },
                    HirStmt::Call {
                        decl_id: terminal_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs::default(),
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            },
            HirBlock {
                id: HirBlockId(2),
                stmts: vec![],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            },
        ],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 10],
        ast: vec![None; 10],
        comments: vec![],
        register_count: 5,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_map_get_record_emit_program(map_get_decl: DeclId, emit_decl: DeclId) -> HirProgram {
    let ctx_var = VarId::new(0);
    let lookup_var = VarId::new(1);
    let func = HirFunction {
        blocks: vec![
            HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(CellPath {
                            members: vec![string_member("pid")],
                        })),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::String(b"cached_path".to_vec()),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(3),
                        lit: HirLiteral::String(b"hash".to_vec()),
                    },
                    HirStmt::Call {
                        decl_id: map_get_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(2)],
                            named: vec![(b"kind".to_vec(), RegId::new(3))],
                            ..Default::default()
                        },
                    },
                    HirStmt::StoreVariable {
                        var_id: lookup_var,
                        src: RegId::new(0),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(4),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::BinaryOp {
                        lhs_dst: RegId::new(0),
                        op: Operator::Comparison(Comparison::NotEqual),
                        rhs: RegId::new(4),
                    },
                ],
                terminator: HirTerminator::BranchIf {
                    cond: RegId::new(0),
                    if_true: HirBlockId(1),
                    if_false: HirBlockId(2),
                },
            },
            HirBlock {
                id: HirBlockId(1),
                stmts: vec![
                    HirStmt::LoadLiteral {
                        dst: RegId::new(0),
                        lit: HirLiteral::Record { capacity: 1 },
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::String(b"path".to_vec()),
                    },
                    HirStmt::LoadVariable {
                        dst: RegId::new(2),
                        var_id: lookup_var,
                    },
                    HirStmt::RecordInsert {
                        src_dst: RegId::new(0),
                        key: RegId::new(1),
                        val: RegId::new(2),
                    },
                    HirStmt::Call {
                        decl_id: emit_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs::default(),
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            },
            HirBlock {
                id: HirBlockId(2),
                stmts: vec![HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Int(0),
                }],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            },
        ],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 16],
        ast: vec![None; 16],
        comments: vec![],
        register_count: 5,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_map_push_program(map_push_decl: DeclId, flags: i64, kind: &str) -> HirProgram {
    let ctx_var = VarId::new(0);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("pid")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String(b"recent_pids".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String(kind.as_bytes().to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::Int(flags),
                },
                HirStmt::Call {
                    decl_id: map_push_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2)],
                        named: vec![
                            (b"kind".to_vec(), RegId::new(3)),
                            (b"flags".to_vec(), RegId::new(4)),
                        ],
                        pipeline_input: Some(RegId::new(0)),
                        ..Default::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 8],
        ast: vec![None; 8],
        comments: vec![],
        register_count: 5,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_literal_map_push_program(map_push_decl: DeclId, flags: i64, kind: &str) -> HirProgram {
    let ctx_var = VarId::new(0);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Int(7),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String(b"iter_values".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String(kind.as_bytes().to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::Int(flags),
                },
                HirStmt::Call {
                    decl_id: map_push_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        named: vec![
                            (b"kind".to_vec(), RegId::new(2)),
                            (b"flags".to_vec(), RegId::new(3)),
                        ],
                        pipeline_input: Some(RegId::new(0)),
                        ..Default::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 5],
        ast: vec![None; 5],
        comments: vec![],
        register_count: 4,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_map_put_program(map_put_decl: DeclId, flags: i64, kind: &str) -> HirProgram {
    let ctx_var = VarId::new(0);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("arg0"), string_member("f_path")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String(b"cached_path".to_vec()),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(3),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("pid")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(3),
                    path: RegId::new(4),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::String(kind.as_bytes().to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(6),
                    lit: HirLiteral::Int(flags),
                },
                HirStmt::Call {
                    decl_id: map_put_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2), RegId::new(3)],
                        named: vec![
                            (b"kind".to_vec(), RegId::new(5)),
                            (b"flags".to_vec(), RegId::new(6)),
                        ],
                        pipeline_input: Some(RegId::new(0)),
                        ..Default::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 11],
        ast: vec![None; 11],
        comments: vec![],
        register_count: 7,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_map_delete_program(map_delete_decl: DeclId, kind: &str) -> HirProgram {
    let ctx_var = VarId::new(0);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("pid")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String(b"cached_pids".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String(kind.as_bytes().to_vec()),
                },
                HirStmt::Call {
                    decl_id: map_delete_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2)],
                        named: vec![(b"kind".to_vec(), RegId::new(3))],
                        ..Default::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 7],
        ast: vec![None; 7],
        comments: vec![],
        register_count: 4,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_sock_ops_socket_map_put_program(
    map_put_decl: DeclId,
    map_name: &str,
    kind: &str,
    flags: i64,
) -> HirProgram {
    let ctx_var = VarId::new(0);
    let stmts = vec![
        HirStmt::LoadVariable {
            dst: RegId::new(0),
            var_id: ctx_var,
        },
        HirStmt::LoadLiteral {
            dst: RegId::new(1),
            lit: HirLiteral::String(map_name.as_bytes().to_vec()),
        },
        HirStmt::LoadVariable {
            dst: RegId::new(2),
            var_id: ctx_var,
        },
        HirStmt::LoadLiteral {
            dst: RegId::new(3),
            lit: HirLiteral::CellPath(Box::new(CellPath {
                members: vec![string_member("remote_port")],
            })),
        },
        HirStmt::FollowCellPath {
            src_dst: RegId::new(2),
            path: RegId::new(3),
        },
        HirStmt::LoadLiteral {
            dst: RegId::new(4),
            lit: HirLiteral::String(kind.as_bytes().to_vec()),
        },
        HirStmt::LoadLiteral {
            dst: RegId::new(5),
            lit: HirLiteral::Int(flags),
        },
        HirStmt::Call {
            decl_id: map_put_decl,
            src_dst: RegId::new(0),
            args: HirCallArgs {
                positional: vec![RegId::new(1), RegId::new(2)],
                named: vec![
                    (b"kind".to_vec(), RegId::new(4)),
                    (b"flags".to_vec(), RegId::new(5)),
                ],
                pipeline_input: Some(RegId::new(0)),
                ..Default::default()
            },
        },
    ];
    let stmt_count = stmts.len();
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts,
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); stmt_count],
        ast: vec![None; stmt_count],
        comments: vec![],
        register_count: 6,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_hash_map_contains_program(map_contains_decl: DeclId) -> HirProgram {
    let ctx_var = VarId::new(0);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("pid")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String(b"seen_pids".to_vec()),
                },
                HirStmt::Call {
                    decl_id: map_contains_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2)],
                        ..Default::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 5],
        ast: vec![None; 5],
        comments: vec![],
        register_count: 3,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_generic_map_contains_program(map_contains_decl: DeclId, kind: &str) -> HirProgram {
    let ctx_var = VarId::new(0);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("pid")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String(b"seen_pids".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String(kind.as_bytes().to_vec()),
                },
                HirStmt::Call {
                    decl_id: map_contains_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2)],
                        named: vec![(b"kind".to_vec(), RegId::new(3))],
                        ..Default::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 6],
        ast: vec![None; 6],
        comments: vec![],
        register_count: 4,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_bloom_filter_map_contains_program(map_contains_decl: DeclId) -> HirProgram {
    let ctx_var = VarId::new(0);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("pid")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String(b"seen_pids".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String(b"bloom-filter".to_vec()),
                },
                HirStmt::Call {
                    decl_id: map_contains_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2)],
                        named: vec![(b"kind".to_vec(), RegId::new(3))],
                        ..Default::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 6],
        ast: vec![None; 6],
        comments: vec![],
        register_count: 4,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_local_storage_map_contains_program(
    owner_path: CellPath,
    map_name: &[u8],
    kind_arg: &[u8],
    map_contains_decl: DeclId,
) -> HirProgram {
    let ctx_var = VarId::new(0);
    let owner_var = VarId::new(1);
    let func = HirFunction {
        blocks: vec![
            HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(owner_path)),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                    HirStmt::StoreVariable {
                        var_id: owner_var,
                        src: RegId::new(0),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(4),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::BinaryOp {
                        lhs_dst: RegId::new(0),
                        op: Operator::Comparison(Comparison::NotEqual),
                        rhs: RegId::new(4),
                    },
                ],
                terminator: HirTerminator::BranchIf {
                    cond: RegId::new(0),
                    if_true: HirBlockId(1),
                    if_false: HirBlockId(2),
                },
            },
            HirBlock {
                id: HirBlockId(1),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: owner_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::String(map_name.to_vec()),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(3),
                        lit: HirLiteral::String(kind_arg.to_vec()),
                    },
                    HirStmt::Call {
                        decl_id: map_contains_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(2)],
                            named: vec![(b"kind".to_vec(), RegId::new(3))],
                            ..Default::default()
                        },
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            },
            HirBlock {
                id: HirBlockId(2),
                stmts: vec![HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Int(0),
                }],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            },
        ],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 12],
        ast: vec![None; 12],
        comments: vec![],
        register_count: 5,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_task_storage_map_contains_program_with_owner(
    owner_field: &str,
    map_contains_decl: DeclId,
) -> HirProgram {
    make_local_storage_map_contains_program(
        CellPath {
            members: vec![string_member(owner_field)],
        },
        b"task_state",
        b"task-storage",
        map_contains_decl,
    )
}

fn make_task_storage_map_contains_program(map_contains_decl: DeclId) -> HirProgram {
    make_task_storage_map_contains_program_with_owner("task", map_contains_decl)
}

fn make_sk_storage_map_contains_program(map_contains_decl: DeclId) -> HirProgram {
    make_local_storage_map_contains_program(
        CellPath {
            members: vec![string_member("sk")],
        },
        b"sock_state",
        b"sk-storage",
        map_contains_decl,
    )
}

fn current_task_cgroup_path() -> CellPath {
    CellPath {
        members: vec![string_member("cgroup")],
    }
}

fn current_task_cgroup_alias_path() -> CellPath {
    CellPath {
        members: vec![string_member("current_cgroup")],
    }
}

fn make_cgrp_storage_map_contains_program_with_owner(
    owner_path: CellPath,
    map_contains_decl: DeclId,
) -> HirProgram {
    make_local_storage_map_contains_program(
        owner_path,
        b"cgrp_state",
        b"cgrp-storage",
        map_contains_decl,
    )
}

fn make_cgrp_storage_map_contains_program(map_contains_decl: DeclId) -> HirProgram {
    make_cgrp_storage_map_contains_program_with_owner(current_task_cgroup_path(), map_contains_decl)
}

fn current_file_inode_path() -> CellPath {
    CellPath {
        members: vec![string_member("arg0"), string_member("f_inode")],
    }
}

fn make_inode_storage_map_contains_program(map_contains_decl: DeclId) -> HirProgram {
    make_local_storage_map_contains_program(
        current_file_inode_path(),
        b"inode_state",
        b"inode-storage",
        map_contains_decl,
    )
}

fn make_local_storage_map_get_program(
    owner_path: CellPath,
    map_name: &[u8],
    kind_arg: &[u8],
    map_get_decl: DeclId,
) -> HirProgram {
    let ctx_var = VarId::new(0);
    let lookup_var = VarId::new(1);
    let owner_var = VarId::new(2);
    let func = HirFunction {
        blocks: vec![
            HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(owner_path)),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                    HirStmt::StoreVariable {
                        var_id: owner_var,
                        src: RegId::new(0),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(8),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::BinaryOp {
                        lhs_dst: RegId::new(0),
                        op: Operator::Comparison(Comparison::NotEqual),
                        rhs: RegId::new(8),
                    },
                ],
                terminator: HirTerminator::BranchIf {
                    cond: RegId::new(0),
                    if_true: HirBlockId(1),
                    if_false: HirBlockId(3),
                },
            },
            HirBlock {
                id: HirBlockId(1),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: owner_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::String(map_name.to_vec()),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(3),
                        lit: HirLiteral::String(kind_arg.to_vec()),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(4),
                        lit: HirLiteral::Record { capacity: 1 },
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(5),
                        lit: HirLiteral::String(b"hits".to_vec()),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(6),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::RecordInsert {
                        src_dst: RegId::new(4),
                        key: RegId::new(5),
                        val: RegId::new(6),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(7),
                        lit: HirLiteral::Int(1),
                    },
                    HirStmt::Call {
                        decl_id: map_get_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(2)],
                            named: vec![
                                (b"kind".to_vec(), RegId::new(3)),
                                (b"init".to_vec(), RegId::new(4)),
                                (b"flags".to_vec(), RegId::new(7)),
                            ],
                            ..Default::default()
                        },
                    },
                    HirStmt::StoreVariable {
                        var_id: lookup_var,
                        src: RegId::new(0),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(8),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::BinaryOp {
                        lhs_dst: RegId::new(0),
                        op: Operator::Comparison(Comparison::NotEqual),
                        rhs: RegId::new(8),
                    },
                ],
                terminator: HirTerminator::BranchIf {
                    cond: RegId::new(0),
                    if_true: HirBlockId(2),
                    if_false: HirBlockId(3),
                },
            },
            HirBlock {
                id: HirBlockId(2),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: lookup_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(CellPath {
                            members: vec![string_member("hits")],
                        })),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            },
            HirBlock {
                id: HirBlockId(3),
                stmts: vec![HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Int(0),
                }],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            },
        ],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 28],
        ast: vec![None; 28],
        comments: vec![],
        register_count: 9,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_task_storage_map_get_program(map_get_decl: DeclId) -> HirProgram {
    make_local_storage_map_get_program(
        CellPath {
            members: vec![string_member("task")],
        },
        b"task_state",
        b"task-storage",
        map_get_decl,
    )
}

fn make_sk_storage_map_get_program(map_get_decl: DeclId) -> HirProgram {
    make_local_storage_map_get_program(
        CellPath {
            members: vec![string_member("sk")],
        },
        b"sock_state",
        b"sk-storage",
        map_get_decl,
    )
}

fn make_cgrp_storage_map_get_program_with_owner(
    owner_path: CellPath,
    map_get_decl: DeclId,
) -> HirProgram {
    make_local_storage_map_get_program(owner_path, b"cgrp_state", b"cgrp-storage", map_get_decl)
}

fn make_cgrp_storage_map_get_program(map_get_decl: DeclId) -> HirProgram {
    make_cgrp_storage_map_get_program_with_owner(current_task_cgroup_path(), map_get_decl)
}

fn make_inode_storage_map_get_program(map_get_decl: DeclId) -> HirProgram {
    make_local_storage_map_get_program(
        current_file_inode_path(),
        b"inode_state",
        b"inode-storage",
        map_get_decl,
    )
}

fn make_local_storage_map_delete_program(
    owner_path: CellPath,
    map_name: &[u8],
    kind_arg: &[u8],
    map_delete_decl: DeclId,
) -> HirProgram {
    let ctx_var = VarId::new(0);
    let owner_var = VarId::new(1);
    let func = HirFunction {
        blocks: vec![
            HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(owner_path)),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                    HirStmt::StoreVariable {
                        var_id: owner_var,
                        src: RegId::new(0),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(4),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::BinaryOp {
                        lhs_dst: RegId::new(0),
                        op: Operator::Comparison(Comparison::NotEqual),
                        rhs: RegId::new(4),
                    },
                ],
                terminator: HirTerminator::BranchIf {
                    cond: RegId::new(0),
                    if_true: HirBlockId(1),
                    if_false: HirBlockId(2),
                },
            },
            HirBlock {
                id: HirBlockId(1),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: owner_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::String(map_name.to_vec()),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(3),
                        lit: HirLiteral::String(kind_arg.to_vec()),
                    },
                    HirStmt::Call {
                        decl_id: map_delete_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(2)],
                            named: vec![(b"kind".to_vec(), RegId::new(3))],
                            ..Default::default()
                        },
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            },
            HirBlock {
                id: HirBlockId(2),
                stmts: vec![HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Int(0),
                }],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            },
        ],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 14],
        ast: vec![None; 14],
        comments: vec![],
        register_count: 5,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_task_storage_map_delete_program(map_delete_decl: DeclId) -> HirProgram {
    make_local_storage_map_delete_program(
        CellPath {
            members: vec![string_member("task")],
        },
        b"task_state",
        b"task-storage",
        map_delete_decl,
    )
}

fn make_sk_storage_map_delete_program(map_delete_decl: DeclId) -> HirProgram {
    make_local_storage_map_delete_program(
        CellPath {
            members: vec![string_member("sk")],
        },
        b"sock_state",
        b"sk-storage",
        map_delete_decl,
    )
}

fn make_cgrp_storage_map_delete_program_with_owner(
    owner_path: CellPath,
    map_delete_decl: DeclId,
) -> HirProgram {
    make_local_storage_map_delete_program(
        owner_path,
        b"cgrp_state",
        b"cgrp-storage",
        map_delete_decl,
    )
}

fn make_cgrp_storage_map_delete_program(map_delete_decl: DeclId) -> HirProgram {
    make_cgrp_storage_map_delete_program_with_owner(current_task_cgroup_path(), map_delete_decl)
}

fn make_inode_storage_map_delete_program(map_delete_decl: DeclId) -> HirProgram {
    make_local_storage_map_delete_program(
        current_file_inode_path(),
        b"inode_state",
        b"inode-storage",
        map_delete_decl,
    )
}

fn make_cgroup_array_map_contains_program(map_contains_decl: DeclId) -> HirProgram {
    let ctx_var = VarId::new(0);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String(b"tracked_cgroups".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String(b"cgroup-array".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::Call {
                    decl_id: map_contains_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1), RegId::new(3)],
                        named: vec![(b"kind".to_vec(), RegId::new(2))],
                        ..Default::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(4) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 4],
        ast: vec![None; 4],
        comments: vec![],
        register_count: 5,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_seeded_map_take_count_program(
    map_push_decl: DeclId,
    map_take_decl: DeclId,
    count_decl: DeclId,
    kind: &str,
) -> HirProgram {
    let ctx_var = VarId::new(0);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("pid")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String(b"recent_pids".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String(kind.as_bytes().to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::Call {
                    decl_id: map_push_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2)],
                        named: vec![
                            (b"kind".to_vec(), RegId::new(3)),
                            (b"flags".to_vec(), RegId::new(4)),
                        ],
                        pipeline_input: Some(RegId::new(0)),
                        ..Default::default()
                    },
                },
                HirStmt::Call {
                    decl_id: map_take_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2)],
                        named: vec![(b"kind".to_vec(), RegId::new(3))],
                        ..Default::default()
                    },
                },
                HirStmt::Call {
                    decl_id: count_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs::default(),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 10],
        ast: vec![None; 10],
        comments: vec![],
        register_count: 5,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_ctx_seeded_map_take_count_return_program(
    source_path: CellPath,
    map_push_decl: DeclId,
    map_take_decl: DeclId,
    count_decl: DeclId,
    kind: &str,
    map_name: &str,
    return_value: HirLiteral,
) -> HirProgram {
    let ctx_var = VarId::new(0);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(source_path)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String(map_name.as_bytes().to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String(kind.as_bytes().to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::Call {
                    decl_id: map_push_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2)],
                        named: vec![
                            (b"kind".to_vec(), RegId::new(3)),
                            (b"flags".to_vec(), RegId::new(4)),
                        ],
                        pipeline_input: Some(RegId::new(0)),
                        ..Default::default()
                    },
                },
                HirStmt::Call {
                    decl_id: map_take_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2)],
                        named: vec![(b"kind".to_vec(), RegId::new(3))],
                        ..Default::default()
                    },
                },
                HirStmt::Call {
                    decl_id: count_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs::default(),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: return_value,
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(5) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 11],
        ast: vec![None; 11],
        comments: vec![],
        register_count: 6,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_map_take_whole_value_program(
    map_take_decl: DeclId,
    terminal_decl: DeclId,
    kind: &str,
) -> HirProgram {
    let lookup_var = VarId::new(1);
    let func = HirFunction {
        blocks: vec![
            HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadLiteral {
                        dst: RegId::new(0),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::String(b"recent_paths".to_vec()),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::String(kind.as_bytes().to_vec()),
                    },
                    HirStmt::Call {
                        decl_id: map_take_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(1)],
                            named: vec![(b"kind".to_vec(), RegId::new(2))],
                            ..Default::default()
                        },
                    },
                    HirStmt::StoreVariable {
                        var_id: lookup_var,
                        src: RegId::new(0),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(3),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::BinaryOp {
                        lhs_dst: RegId::new(0),
                        op: Operator::Comparison(Comparison::NotEqual),
                        rhs: RegId::new(3),
                    },
                ],
                terminator: HirTerminator::BranchIf {
                    cond: RegId::new(0),
                    if_true: HirBlockId(1),
                    if_false: HirBlockId(2),
                },
            },
            HirBlock {
                id: HirBlockId(1),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: lookup_var,
                    },
                    HirStmt::Call {
                        decl_id: terminal_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs::default(),
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            },
            HirBlock {
                id: HirBlockId(2),
                stmts: vec![HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Int(0),
                }],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            },
        ],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 10],
        ast: vec![None; 10],
        comments: vec![],
        register_count: 4,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], None)
}

fn make_identity_user_function() -> HirFunction {
    HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![HirStmt::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(10),
            }],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 2],
        ast: vec![None; 2],
        comments: vec![],
        register_count: 1,
        file_count: 0,
    }
}

fn make_project_inode_flags_user_function() -> HirFunction {
    HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: VarId::new(10),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("f_inode"), string_member("i_flags")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 4],
        ast: vec![None; 4],
        comments: vec![],
        register_count: 2,
        file_count: 0,
    }
}

fn make_map_get_user_function_emit_program(
    map_get_decl: DeclId,
    user_decl: DeclId,
    emit_decl: DeclId,
) -> HirProgram {
    let ctx_var = VarId::new(0);
    let lookup_var = VarId::new(1);
    let func = HirFunction {
        blocks: vec![
            HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(CellPath {
                            members: vec![string_member("pid")],
                        })),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::String(b"cached_path".to_vec()),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(3),
                        lit: HirLiteral::String(b"hash".to_vec()),
                    },
                    HirStmt::Call {
                        decl_id: map_get_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(2)],
                            named: vec![(b"kind".to_vec(), RegId::new(3))],
                            ..Default::default()
                        },
                    },
                    HirStmt::StoreVariable {
                        var_id: lookup_var,
                        src: RegId::new(0),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(4),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::BinaryOp {
                        lhs_dst: RegId::new(0),
                        op: Operator::Comparison(Comparison::NotEqual),
                        rhs: RegId::new(4),
                    },
                ],
                terminator: HirTerminator::BranchIf {
                    cond: RegId::new(0),
                    if_true: HirBlockId(1),
                    if_false: HirBlockId(2),
                },
            },
            HirBlock {
                id: HirBlockId(1),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(1),
                        var_id: lookup_var,
                    },
                    HirStmt::Call {
                        decl_id: user_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(1)],
                            ..Default::default()
                        },
                    },
                    HirStmt::Call {
                        decl_id: emit_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs::default(),
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            },
            HirBlock {
                id: HirBlockId(2),
                stmts: vec![HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Int(0),
                }],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            },
        ],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 14],
        ast: vec![None; 14],
        comments: vec![],
        register_count: 5,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_trampoline_user_function_count_program(
    source_path: CellPath,
    user_decl: DeclId,
    count_decl: DeclId,
) -> HirProgram {
    let ctx_var = VarId::new(0);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(source_path)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::Call {
                    decl_id: user_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..Default::default()
                    },
                },
                HirStmt::Call {
                    decl_id: count_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs::default(),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 6],
        ast: vec![None; 6],
        comments: vec![],
        register_count: 2,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn path_struct_schema(map_name: &str, kind: MapKind) -> HashMap<MapRef, MirType> {
    HashMap::from([(
        MapRef {
            name: map_name.to_string(),
            kind,
        },
        MirType::Struct {
            name: Some("path".to_string()),
            kernel_btf_type_id: None,
            fields: vec![
                StructField {
                    name: "mnt".to_string(),
                    ty: MirType::U64,
                    offset: 0,
                    synthetic: false,
                    bitfield: None,
                },
                StructField {
                    name: "dentry".to_string(),
                    ty: MirType::Ptr {
                        pointee: Box::new(MirType::Struct {
                            name: Some("dentry".to_string()),
                            kernel_btf_type_id: None,
                            fields: vec![StructField {
                                name: "d_flags".to_string(),
                                ty: MirType::U32,
                                offset: 0,
                                synthetic: false,
                                bitfield: None,
                            }],
                        }),
                        address_space: AddressSpace::Kernel,
                    },
                    offset: 8,
                    synthetic: false,
                    bitfield: None,
                },
            ],
        },
    )])
}

fn cached_path_struct_schema() -> HashMap<MapRef, MirType> {
    path_struct_schema("cached_path", MapKind::Hash)
}

fn recent_paths_struct_schema(kind: MapKind) -> HashMap<MapRef, MirType> {
    path_struct_schema("recent_paths", kind)
}

fn make_map_copy_projection_program(
    source_path: CellPath,
    map_put_decl: DeclId,
    map_get_decl: DeclId,
    count_decl: DeclId,
) -> HirProgram {
    let ctx_var = VarId::new(0);
    let lookup_var = VarId::new(1);
    let copied_var = VarId::new(2);
    let func = HirFunction {
        blocks: vec![
            HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(source_path)),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::String(b"cached_path".to_vec()),
                    },
                    HirStmt::LoadVariable {
                        dst: RegId::new(3),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(4),
                        lit: HirLiteral::CellPath(Box::new(CellPath {
                            members: vec![string_member("pid")],
                        })),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(3),
                        path: RegId::new(4),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(5),
                        lit: HirLiteral::String(b"hash".to_vec()),
                    },
                    HirStmt::Call {
                        decl_id: map_put_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(2), RegId::new(3)],
                            named: vec![(b"kind".to_vec(), RegId::new(5))],
                            pipeline_input: Some(RegId::new(0)),
                            ..Default::default()
                        },
                    },
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(4),
                    },
                    HirStmt::Call {
                        decl_id: map_get_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(2)],
                            named: vec![(b"kind".to_vec(), RegId::new(5))],
                            ..Default::default()
                        },
                    },
                    HirStmt::StoreVariable {
                        var_id: lookup_var,
                        src: RegId::new(0),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(6),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::BinaryOp {
                        lhs_dst: RegId::new(0),
                        op: Operator::Comparison(Comparison::NotEqual),
                        rhs: RegId::new(6),
                    },
                ],
                terminator: HirTerminator::BranchIf {
                    cond: RegId::new(0),
                    if_true: HirBlockId(1),
                    if_false: HirBlockId(3),
                },
            },
            HirBlock {
                id: HirBlockId(1),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: lookup_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(7),
                        lit: HirLiteral::String(b"copied_path".to_vec()),
                    },
                    HirStmt::LoadVariable {
                        dst: RegId::new(3),
                        var_id: ctx_var,
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(3),
                        path: RegId::new(4),
                    },
                    HirStmt::Call {
                        decl_id: map_put_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(7), RegId::new(3)],
                            named: vec![(b"kind".to_vec(), RegId::new(5))],
                            pipeline_input: Some(RegId::new(0)),
                            ..Default::default()
                        },
                    },
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(4),
                    },
                    HirStmt::Call {
                        decl_id: map_get_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(7)],
                            named: vec![(b"kind".to_vec(), RegId::new(5))],
                            ..Default::default()
                        },
                    },
                    HirStmt::StoreVariable {
                        var_id: copied_var,
                        src: RegId::new(0),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(8),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::BinaryOp {
                        lhs_dst: RegId::new(0),
                        op: Operator::Comparison(Comparison::NotEqual),
                        rhs: RegId::new(8),
                    },
                ],
                terminator: HirTerminator::BranchIf {
                    cond: RegId::new(0),
                    if_true: HirBlockId(2),
                    if_false: HirBlockId(3),
                },
            },
            HirBlock {
                id: HirBlockId(2),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: copied_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(CellPath {
                            members: vec![string_member("dentry"), string_member("d_flags")],
                        })),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                    HirStmt::Call {
                        decl_id: count_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs::default(),
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            },
            HirBlock {
                id: HirBlockId(3),
                stmts: vec![],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            },
        ],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 30],
        ast: vec![None; 30],
        comments: vec![],
        register_count: 9,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_bound_ctx_path_program(binding: CellPath, access: CellPath) -> HirProgram {
    let ctx_var = VarId::new(0);
    let bound_var = VarId::new(1);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(binding)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::StoreVariable {
                    var_id: bound_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: bound_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::CellPath(Box::new(access)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(2),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 7],
        ast: vec![None; 7],
        comments: vec![],
        register_count: 3,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_bound_ctx_get_program(binding: CellPath, access: CellPath, decl_id: DeclId) -> HirProgram {
    let ctx_var = VarId::new(0);
    let bound_var = VarId::new(1);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(binding)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::StoreVariable {
                    var_id: bound_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: bound_var,
                },
                HirStmt::Call {
                    decl_id,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::CellPath(Box::new(access)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(3),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 9],
        ast: vec![None; 9],
        comments: vec![],
        register_count: 4,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_bound_ctx_runtime_get_program(
    binding: CellPath,
    idx_binding: CellPath,
    modulus: i64,
    decl_id: DeclId,
) -> HirProgram {
    let ctx_var = VarId::new(0);
    let bound_var = VarId::new(1);
    let idx_var = VarId::new(2);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(idx_binding)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(modulus),
                },
                HirStmt::BinaryOp {
                    lhs_dst: RegId::new(0),
                    op: Operator::Math(Math::Modulo),
                    rhs: RegId::new(2),
                },
                HirStmt::StoreVariable {
                    var_id: idx_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(binding)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::StoreVariable {
                    var_id: bound_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: bound_var,
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(2),
                    var_id: idx_var,
                },
                HirStmt::Call {
                    decl_id,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2)],
                        ..HirCallArgs::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 13],
        ast: vec![None; 13],
        comments: vec![],
        register_count: 3,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_bound_ctx_runtime_get_then_call_program(
    binding: CellPath,
    idx_binding: CellPath,
    modulus: i64,
    decl_id: DeclId,
) -> HirProgram {
    let ctx_var = VarId::new(0);
    let idx_var = VarId::new(1);
    let value_var = VarId::new(2);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(idx_binding)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(modulus),
                },
                HirStmt::BinaryOp {
                    lhs_dst: RegId::new(0),
                    op: Operator::Math(Math::Modulo),
                    rhs: RegId::new(2),
                },
                HirStmt::StoreVariable {
                    var_id: idx_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(binding)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(2),
                    var_id: idx_var,
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::StoreVariable {
                    var_id: value_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: value_var,
                },
                HirStmt::Call {
                    decl_id,
                    src_dst: RegId::new(0),
                    args: HirCallArgs::default(),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 14],
        ast: vec![None; 14],
        comments: vec![],
        register_count: 3,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_bound_ctx_runtime_get_path_program(
    binding: CellPath,
    idx_binding: CellPath,
    modulus: i64,
    access: CellPath,
    decl_id: DeclId,
) -> HirProgram {
    let ctx_var = VarId::new(0);
    let bound_var = VarId::new(1);
    let idx_var = VarId::new(2);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(idx_binding)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(modulus),
                },
                HirStmt::BinaryOp {
                    lhs_dst: RegId::new(0),
                    op: Operator::Math(Math::Modulo),
                    rhs: RegId::new(2),
                },
                HirStmt::StoreVariable {
                    var_id: idx_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(binding)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::StoreVariable {
                    var_id: bound_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: bound_var,
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(2),
                    var_id: idx_var,
                },
                HirStmt::Call {
                    decl_id,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(access)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 15],
        ast: vec![None; 15],
        comments: vec![],
        register_count: 3,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_branch_refined_bound_ctx_get_program(
    scalar_binding: CellPath,
    pointer_binding: CellPath,
    access: CellPath,
    decl_id: DeclId,
) -> HirProgram {
    let ctx_var = VarId::new(0);
    let scalar_var = VarId::new(1);
    let idx_var = VarId::new(2);
    let blocks = vec![
        HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(scalar_binding)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::StoreVariable {
                    var_id: scalar_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: scalar_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::BinaryOp {
                    lhs_dst: RegId::new(0),
                    op: Operator::Comparison(Comparison::GreaterThan),
                    rhs: RegId::new(1),
                },
            ],
            terminator: HirTerminator::BranchIf {
                cond: RegId::new(0),
                if_true: HirBlockId(1),
                if_false: HirBlockId(2),
            },
        },
        HirBlock {
            id: HirBlockId(1),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: scalar_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::BinaryOp {
                    lhs_dst: RegId::new(0),
                    op: Operator::Math(Math::Subtract),
                    rhs: RegId::new(1),
                },
                HirStmt::StoreVariable {
                    var_id: idx_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(2),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::CellPath(Box::new(pointer_binding)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(2),
                    path: RegId::new(3),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: idx_var,
                },
                HirStmt::Call {
                    decl_id,
                    src_dst: RegId::new(2),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::CellPath(Box::new(access)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(2),
                    path: RegId::new(3),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(2) },
        },
        HirBlock {
            id: HirBlockId(2),
            stmts: vec![HirStmt::LoadLiteral {
                dst: RegId::new(0),
                lit: HirLiteral::Int(0),
            }],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        },
    ];
    let func = HirFunction {
        blocks,
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 19],
        ast: vec![None; 19],
        comments: vec![],
        register_count: 4,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_eq_guarded_ctx_path_count_program(
    guard_path: CellPath,
    guard_value: HirLiteral,
    counted_path: CellPath,
    count_decl: DeclId,
) -> HirProgram {
    let ctx_var = VarId::new(0);
    let blocks = vec![
        HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(guard_path)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: guard_value,
                },
                HirStmt::BinaryOp {
                    lhs_dst: RegId::new(0),
                    op: Operator::Comparison(Comparison::Equal),
                    rhs: RegId::new(2),
                },
            ],
            terminator: HirTerminator::BranchIf {
                cond: RegId::new(0),
                if_true: HirBlockId(1),
                if_false: HirBlockId(2),
            },
        },
        HirBlock {
            id: HirBlockId(1),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(counted_path)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::Call {
                    decl_id: count_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs::default(),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        },
        HirBlock {
            id: HirBlockId(2),
            stmts: vec![HirStmt::LoadLiteral {
                dst: RegId::new(0),
                lit: HirLiteral::Int(0),
            }],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        },
    ];
    let func = HirFunction {
        blocks,
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 10],
        ast: vec![None; 10],
        comments: vec![],
        register_count: 3,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_gt_zero_guarded_ctx_path_store_program(
    guard_path: CellPath,
    stored_path: CellPath,
    new_value: HirLiteral,
    return_value: HirLiteral,
) -> HirProgram {
    let ctx_var = VarId::new(0);
    let blocks = vec![
        HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(guard_path)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::BinaryOp {
                    lhs_dst: RegId::new(0),
                    op: Operator::Comparison(Comparison::GreaterThan),
                    rhs: RegId::new(2),
                },
            ],
            terminator: HirTerminator::BranchIf {
                cond: RegId::new(0),
                if_true: HirBlockId(1),
                if_false: HirBlockId(2),
            },
        },
        HirBlock {
            id: HirBlockId(1),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(stored_path)),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: new_value,
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                    new_value: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: return_value.clone(),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(3) },
        },
        HirBlock {
            id: HirBlockId(2),
            stmts: vec![HirStmt::LoadLiteral {
                dst: RegId::new(0),
                lit: return_value,
            }],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        },
    ];
    let func = HirFunction {
        blocks,
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 11],
        ast: vec![None; 11],
        comments: vec![],
        register_count: 4,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_branch_refined_bound_ctx_get_then_call_program(
    scalar_binding: CellPath,
    pointer_binding: CellPath,
    get_decl: DeclId,
    terminal_decl: DeclId,
) -> HirProgram {
    let ctx_var = VarId::new(0);
    let scalar_var = VarId::new(1);
    let idx_var = VarId::new(2);
    let value_var = VarId::new(3);
    let blocks = vec![
        HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(scalar_binding)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::StoreVariable {
                    var_id: scalar_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: scalar_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::BinaryOp {
                    lhs_dst: RegId::new(0),
                    op: Operator::Comparison(Comparison::GreaterThan),
                    rhs: RegId::new(1),
                },
            ],
            terminator: HirTerminator::BranchIf {
                cond: RegId::new(0),
                if_true: HirBlockId(1),
                if_false: HirBlockId(2),
            },
        },
        HirBlock {
            id: HirBlockId(1),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: scalar_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::BinaryOp {
                    lhs_dst: RegId::new(0),
                    op: Operator::Math(Math::Subtract),
                    rhs: RegId::new(1),
                },
                HirStmt::StoreVariable {
                    var_id: idx_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(pointer_binding)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(2),
                    var_id: idx_var,
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::StoreVariable {
                    var_id: value_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: value_var,
                },
                HirStmt::Call {
                    decl_id: terminal_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs::default(),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        },
        HirBlock {
            id: HirBlockId(2),
            stmts: vec![HirStmt::LoadLiteral {
                dst: RegId::new(0),
                lit: HirLiteral::Int(0),
            }],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        },
    ];
    let func = HirFunction {
        blocks,
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 16],
        ast: vec![None; 16],
        comments: vec![],
        register_count: 3,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

#[test]
fn test_compile_tp_btf_ctx_arg_program() {
    fn find_tp_btf_scalar_arg_candidate() -> Option<(&'static str, usize)> {
        for (tracepoint_name, arg_idx) in [
            ("sys_enter", 1usize),
            ("sys_exit", 1),
            ("sched_process_exec", 1),
            ("sched_process_fork", 0),
        ] {
            if matches!(
                KernelBtf::get().tp_btf_arg_type_info(tracepoint_name, arg_idx),
                Ok(Some(TypeInfo::Int { .. }))
            ) {
                return Some((tracepoint_name, arg_idx));
            }
        }
        None
    }

    let Some((tracepoint_name, arg_idx)) = find_tp_btf_scalar_arg_candidate() else {
        return;
    };

    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member(&format!("arg{arg_idx}"))],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::TpBtf, tracepoint_name);

    let lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("tp_btf scalar ctx.arg should lower");

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("tp_btf scalar ctx.arg should compile");

    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_tp_btf_projected_ctx_arg_program() {
    fn find_tp_btf_projection_candidate() -> Option<(&'static str, &'static str)> {
        for (tracepoint_name, field_name) in [("sys_enter", "orig_ax"), ("sys_exit", "orig_ax")] {
            let path = [TrampolineFieldSelector::Field(field_name.to_string())];
            if matches!(
                KernelBtf::get().tp_btf_arg_field(tracepoint_name, 0, &path),
                Ok(Some(_))
            ) {
                return Some((tracepoint_name, field_name));
            }
        }
        None
    }

    let Some((tracepoint_name, field_name)) = find_tp_btf_projection_candidate() else {
        return;
    };

    let hir = make_ctx_path_call_program(
        CellPath {
            members: vec![string_member("arg0"), string_member(field_name)],
        },
        DeclId::new(42),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::TpBtf, tracepoint_name);
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "count".to_string());

    let lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("tp_btf ctx.arg0 field count should lower");

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("tp_btf ctx.arg0 field count should compile");

    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_fentry_named_projected_ctx_arg_program() {
    let Some((function_name, arg_name, field_name)) =
        find_function_trampoline_named_projection_candidate()
    else {
        return;
    };

    let hir = make_ctx_path_call_program(
        CellPath {
            members: vec![
                string_member("arg"),
                string_member(&arg_name),
                string_member(&field_name),
            ],
        },
        DeclId::new(42),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, &function_name);
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "count".to_string());

    let lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("fentry named ctx.arg field count should lower");

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("fentry named ctx.arg field count should compile");

    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_tracepoint_builtin_ctx_counter_programs() {
    for field in [
        "pid",
        "tid",
        "tgid",
        "pid_tgid",
        "current_pid_tgid",
        "uid",
        "gid",
        "uid_gid",
        "current_uid_gid",
        "cpu",
        "numa_node",
        "numa_node_id",
        "random",
        "prandom_u32",
        "ktime",
        "timestamp",
        "ktime_boot",
        "boot_time",
        "ktime_tai",
        "tai_time",
        "jiffies",
        "func_ip",
        "function_ip",
        "attach_cookie",
        "bpf_cookie",
        "cgroup_id",
    ] {
        assert_ctx_path_count_program_compiles(
            EbpfProgramType::Tracepoint,
            "syscalls/sys_enter_openat",
            CellPath {
                members: vec![string_member(field)],
            },
            &format!("tracepoint ctx.{field} count"),
        );
    }
}

#[test]
fn test_compile_tracepoint_ctx_current_task_non_null_program() {
    let hir = make_ctx_path_non_null_program(CellPath {
        members: vec![string_member("current_task")],
    });
    assert_attach_program_compiles(
        &hir,
        EbpfProgramType::Tracepoint,
        "syscalls/sys_enter_openat",
        &HashMap::new(),
        "tracepoint ctx.current_task non-null check",
    );
}

#[test]
fn test_compile_tracepoint_payload_scalar_ctx_counter_program() {
    let target = "syscalls/sys_enter_openat";
    if !tracepoint_field_matches(target, "id", TypeInfo::is_int) {
        return;
    }

    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Tracepoint,
        target,
        CellPath {
            members: vec![string_member("id")],
        },
        "tracepoint ctx.id count",
    );
}

#[test]
fn test_compile_tracepoint_payload_args_index_ctx_counter_program() {
    let target = "syscalls/sys_enter_openat";
    if !tracepoint_field_matches(target, "args", |ty| matches!(ty, TypeInfo::Array { .. })) {
        return;
    }

    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Tracepoint,
        target,
        CellPath {
            members: vec![string_member("args"), int_member(0)],
        },
        "tracepoint ctx.args[0] count",
    );
}

#[test]
fn test_compile_tracepoint_payload_pointer_index_ctx_counter_program() {
    let Some((target, field_name)) = find_tracepoint_pointer_field_candidate() else {
        return;
    };

    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Tracepoint,
        &target,
        CellPath {
            members: vec![string_member(&field_name), int_member(0)],
        },
        &format!("tracepoint ctx.{field_name}[0] count"),
    );
}

#[test]
fn test_compile_fentry_ctx_arg_count_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Fentry,
        "vfs_read",
        CellPath {
            members: vec![string_member("arg_count")],
        },
        "fentry ctx.arg_count count",
    );
}

#[test]
fn test_compile_fmod_ret_named_projected_ctx_arg_program() {
    let Some((function_name, arg_name, field_name)) =
        find_function_trampoline_named_projection_candidate()
    else {
        return;
    };

    let hir = make_ctx_path_call_program(
        CellPath {
            members: vec![
                string_member("arg"),
                string_member(&arg_name),
                string_member(&field_name),
            ],
        },
        DeclId::new(42),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::FmodRet, &function_name);
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "count".to_string());

    let lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("fmod_ret named ctx.arg field count should lower");

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("fmod_ret named ctx.arg field count should compile");

    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_tp_btf_named_projected_ctx_arg_program() {
    let Some((tracepoint_name, arg_name, field_name)) = find_tp_btf_named_projection_candidate()
    else {
        return;
    };

    let hir = make_ctx_path_call_program(
        CellPath {
            members: vec![
                string_member("arg"),
                string_member(&arg_name),
                string_member(&field_name),
            ],
        },
        DeclId::new(42),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::TpBtf, &tracepoint_name);
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "count".to_string());

    let lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("tp_btf named ctx.arg field count should lower");

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("tp_btf named ctx.arg field count should compile");

    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_lsm_named_projected_ctx_arg_program() {
    let Some((hook_name, arg_name, field_name)) = find_lsm_named_projection_candidate() else {
        return;
    };

    let hir = make_ctx_path_call_program(
        CellPath {
            members: vec![
                string_member("arg"),
                string_member(&arg_name),
                string_member(&field_name),
            ],
        },
        DeclId::new(42),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Lsm, &hook_name);
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "count".to_string());

    let lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("lsm named ctx.arg field count should lower");

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("lsm named ctx.arg field count should compile");

    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_lsm_cgroup_ctx_arg_program() {
    if KernelBtf::get()
        .validate_lsm_hook_target("socket_bind")
        .is_err()
    {
        return;
    }

    assert_ctx_path_count_program_compiles(
        EbpfProgramType::LsmCgroup,
        "socket_bind",
        CellPath {
            members: vec![string_member("arg2")],
        },
        "lsm_cgroup ctx.arg2 count",
    );
}

#[test]
fn test_compile_fexit_ctx_retval_program() {
    let Some(function_name) = find_fexit_ret_candidate() else {
        return;
    };

    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("retval")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fexit, &function_name);

    let lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("fexit ctx.retval should lower");

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("fexit ctx.retval should compile");

    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_fmod_ret_ctx_retval_program() {
    let Some(function_name) = find_fexit_ret_candidate() else {
        return;
    };

    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("retval")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::FmodRet, &function_name);

    let lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("fmod_ret ctx.retval should lower");

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("fmod_ret ctx.retval should compile");

    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_ksyscall_ctx_arg_program() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("arg0")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Ksyscall, "nanosleep");

    let lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("ksyscall ctx.arg0 should lower");

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("ksyscall ctx.arg0 should compile");

    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_kretsyscall_ctx_retval_program() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("retval")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::KretSyscall, "nanosleep");

    let lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("kretsyscall ctx.retval should lower");

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("kretsyscall ctx.retval should compile");

    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_kprobe_multi_full_spec_ctx_arg_program() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("arg0")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::KprobeMulti, "kprobe.multi:vfs_*");
    assert_eq!(probe_ctx.target(), "vfs_*");

    let lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("kprobe.multi ctx.arg0 should lower");

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("kprobe.multi ctx.arg0 should compile");

    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_kretprobe_multi_full_spec_ctx_retval_program() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("retval")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::KretprobeMulti, "kretprobe.multi:vfs_*");
    assert_eq!(probe_ctx.target(), "vfs_*");

    let lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("kretprobe.multi ctx.retval should lower");

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("kretprobe.multi ctx.retval should compile");

    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_sleepable_uprobe_ctx_pid_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Uprobe,
        "uprobe.s:/bin/true:main",
        CellPath {
            members: vec![string_member("pid")],
        },
        "sleepable uprobe ctx.pid count",
    );
}

#[test]
fn test_compile_uprobe_multi_full_spec_ctx_pid_program() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("pid")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::UprobeMulti, "uprobe.multi:/bin/true:main*");
    assert_eq!(probe_ctx.target(), "/bin/true:main*");

    let lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("uprobe.multi ctx.pid should lower");

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("uprobe.multi ctx.pid should compile");

    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_sleepable_uprobe_multi_ctx_pid_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::UprobeMulti,
        "uprobe.multi.s:/bin/true:main*",
        CellPath {
            members: vec![string_member("pid")],
        },
        "sleepable uprobe.multi ctx.pid count",
    );
}

#[test]
fn test_compile_sleepable_uretprobe_ctx_retval_program() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("retval")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Uretprobe, "uretprobe.s:/bin/true:main");

    let lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sleepable uretprobe ctx.retval should lower");

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("sleepable uretprobe ctx.retval should compile");

    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_uretprobe_multi_full_spec_ctx_retval_program() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("retval")],
    });
    let probe_ctx = ProbeContext::new(
        EbpfProgramType::UretprobeMulti,
        "uretprobe.multi:/bin/true:main*",
    );
    assert_eq!(probe_ctx.target(), "/bin/true:main*");

    let lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("uretprobe.multi ctx.retval should lower");

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("uretprobe.multi ctx.retval should compile");

    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_fexit_projected_ctx_retval_program() {
    let Some((function_name, field_name)) = find_fexit_ret_projection_candidate() else {
        return;
    };

    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("retval"), string_member(&field_name)],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fexit, &function_name);

    let lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("fexit ctx.retval field projection should lower");

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("fexit ctx.retval field projection should compile");

    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_raw_tracepoint_ctx_arg_program() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("arg0")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::RawTracepoint, "sys_enter");

    let lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("raw tracepoint ctx.arg0 should lower");

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("raw tracepoint ctx.arg0 should compile");

    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_raw_tracepoint_writable_ctx_arg_program() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("arg0")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::RawTracepointWritable, "sys_enter");

    let lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("writable raw tracepoint ctx.arg0 should lower");

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("writable raw tracepoint ctx.arg0 should compile");

    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_extension_return_program() {
    let hir = make_int_return_program(0);
    assert_attach_program_compiles(
        &hir,
        EbpfProgramType::Extension,
        "replace_me",
        &HashMap::new(),
        "freplace return 0",
    );
}

#[test]
fn test_compile_syscall_return_program() {
    let hir = make_int_return_program(0);
    assert_attach_program_compiles(
        &hir,
        EbpfProgramType::Syscall,
        "demo",
        &HashMap::new(),
        "syscall return 0",
    );
}

#[test]
fn test_compile_iter_return_program() {
    let hir = make_int_return_program(0);
    assert_attach_program_compiles(
        &hir,
        EbpfProgramType::Iter,
        "task",
        &HashMap::new(),
        "iter return 0",
    );
}

#[test]
fn test_compile_iter_annotated_mut_int_count_program() {
    let hir = make_annotated_mut_int_count_program(DeclId::new(42));
    let decl_names = HashMap::from([(DeclId::new(42), "count".to_string())]);

    assert_attach_program_compiles(
        &hir,
        EbpfProgramType::Iter,
        "task",
        &decl_names,
        "iter annotated mut int count",
    );
}

#[test]
fn test_compile_iter_literal_queue_map_push_program() {
    let hir = make_literal_map_push_program(DeclId::new(42), 0, "queue");
    let decl_names = HashMap::from([(DeclId::new(42), "map-push".to_string())]);

    assert_attach_program_compiles(
        &hir,
        EbpfProgramType::Iter,
        "task",
        &decl_names,
        "iter literal queue map-push",
    );
}

#[test]
fn test_compile_action_alias_return_programs() {
    for (program_type, target, alias, context) in [
        (
            EbpfProgramType::FlowDissector,
            "/proc/self/ns/net",
            "fallback",
            "flow_dissector fallback return alias",
        ),
        (
            EbpfProgramType::FlowDissector,
            "/proc/self/ns/net",
            "parsed",
            "flow_dissector parsed return alias",
        ),
        (
            EbpfProgramType::Netfilter,
            "ipv4:pre_routing",
            "queue",
            "netfilter queue return alias",
        ),
        (
            EbpfProgramType::Netfilter,
            "ipv4:pre_routing",
            "accept",
            "netfilter accept return alias",
        ),
        (
            EbpfProgramType::LwtIn,
            "demo-route",
            "reroute",
            "lwt_in reroute return alias",
        ),
        (
            EbpfProgramType::LwtOut,
            "demo-route",
            "redirect",
            "lwt_out redirect return alias",
        ),
        (
            EbpfProgramType::LwtXmit,
            "demo-route",
            "reroute",
            "lwt_xmit reroute return alias",
        ),
        (
            EbpfProgramType::LwtSeg6Local,
            "demo-route",
            "pass",
            "lwt_seg6local pass return alias",
        ),
        (
            EbpfProgramType::Tcx,
            "lo:ingress",
            "next",
            "tcx next return alias",
        ),
        (
            EbpfProgramType::Netkit,
            "nk0:primary",
            "redirect",
            "netkit redirect return alias",
        ),
        (
            EbpfProgramType::SkReuseport,
            "select",
            "pass",
            "sk_reuseport select pass return alias",
        ),
        (
            EbpfProgramType::SkReuseport,
            "migrate",
            "drop",
            "sk_reuseport migrate drop return alias",
        ),
    ] {
        let hir = make_literal_return_program(HirLiteral::String(alias.as_bytes().to_vec()));
        assert_attach_program_compiles(&hir, program_type, target, &HashMap::new(), context);
    }
}

#[test]
fn test_compile_kprobe_ctx_tid_alias_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Kprobe,
        "ksys_read",
        CellPath {
            members: vec![string_member("tid")],
        },
        "kprobe ctx.tid count",
    );
}

#[test]
fn test_compile_kprobe_ctx_tgid_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Kprobe,
        "ksys_read",
        CellPath {
            members: vec![string_member("tgid")],
        },
        "kprobe ctx.tgid count",
    );
}

#[test]
fn test_compile_kprobe_ctx_packed_identity_counter_programs() {
    for (field, context) in [
        ("pid_tgid", "kprobe ctx.pid_tgid count"),
        ("current_pid_tgid", "kprobe ctx.current_pid_tgid count"),
        ("uid_gid", "kprobe ctx.uid_gid count"),
        ("current_uid_gid", "kprobe ctx.current_uid_gid count"),
    ] {
        assert_ctx_path_count_program_compiles(
            EbpfProgramType::Kprobe,
            "ksys_read",
            CellPath {
                members: vec![string_member(field)],
            },
            context,
        );
    }
}

#[test]
fn test_compile_kprobe_ctx_uid_gid_counter_programs() {
    for (field, context) in [
        ("uid", "kprobe ctx.uid count"),
        ("gid", "kprobe ctx.gid count"),
    ] {
        assert_ctx_path_count_program_compiles(
            EbpfProgramType::Kprobe,
            "ksys_read",
            CellPath {
                members: vec![string_member(field)],
            },
            context,
        );
    }
}

#[test]
fn test_compile_kprobe_ctx_comm_byte_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Kprobe,
        "ksys_read",
        CellPath {
            members: vec![string_member("comm"), int_member(0)],
        },
        "kprobe ctx.comm[0] count",
    );
}

#[test]
fn test_compile_kprobe_ctx_ancestor_cgroup_id_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Kprobe,
        "ksys_read",
        CellPath {
            members: vec![string_member("ancestor_cgroup_id"), int_member(0)],
        },
        "kprobe ctx.ancestor_cgroup_id.0 count",
    );
}

#[test]
fn test_compile_xdp_ctx_cgroup_id_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Xdp,
        "lo",
        CellPath {
            members: vec![string_member("cgroup_id")],
        },
        "xdp ctx.cgroup_id count",
    );
}

#[test]
fn test_compile_xdp_ctx_ancestor_cgroup_id_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Xdp,
        "lo",
        CellPath {
            members: vec![string_member("ancestor_cgroup_id"), int_member(0)],
        },
        "xdp ctx.ancestor_cgroup_id.0 count",
    );
}

#[test]
fn test_compile_kprobe_ctx_numa_node_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Kprobe,
        "ksys_read",
        CellPath {
            members: vec![string_member("numa_node")],
        },
        "kprobe ctx.numa_node count",
    );
}

#[test]
fn test_compile_kprobe_ctx_numa_node_id_alias_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Kprobe,
        "ksys_read",
        CellPath {
            members: vec![string_member("numa_node_id")],
        },
        "kprobe ctx.numa_node_id count",
    );
}

#[test]
fn test_compile_kprobe_ctx_random_counter_programs() {
    for field in ["random", "prandom_u32"] {
        assert_ctx_path_count_program_compiles(
            EbpfProgramType::Kprobe,
            "ksys_read",
            CellPath {
                members: vec![string_member(field)],
            },
            &format!("kprobe ctx.{field} count"),
        );
    }
}

#[test]
fn test_compile_kprobe_ctx_clock_counter_programs() {
    for field in [
        "ktime",
        "timestamp",
        "ktime_boot",
        "boot_ktime",
        "boot_time",
        "ktime_tai",
        "tai_ktime",
        "tai_time",
        "jiffies",
    ] {
        assert_ctx_path_count_program_compiles(
            EbpfProgramType::Kprobe,
            "ksys_read",
            CellPath {
                members: vec![string_member(field)],
            },
            &format!("kprobe ctx.{field} count"),
        );
    }
}

#[test]
fn test_compile_kprobe_ctx_function_ip_counter_programs() {
    for field in ["func_ip", "function_ip"] {
        assert_ctx_path_count_program_compiles(
            EbpfProgramType::Kprobe,
            "ksys_read",
            CellPath {
                members: vec![string_member(field)],
            },
            &format!("kprobe ctx.{field} count"),
        );
    }
}

#[test]
fn test_compile_kprobe_ctx_attach_cookie_counter_programs() {
    for field in ["attach_cookie", "bpf_cookie"] {
        assert_ctx_path_count_program_compiles(
            EbpfProgramType::Kprobe,
            "ksys_read",
            CellPath {
                members: vec![string_member(field)],
            },
            &format!("kprobe ctx.{field} count"),
        );
    }
}

#[test]
fn test_compile_kprobe_ctx_kstack_counter_program() {
    assert_ctx_stack_count_program_compiles("kstack", KSTACK_MAP_NAME, "kprobe ctx.kstack count");
}

#[test]
fn test_compile_kprobe_ctx_ustack_counter_program() {
    assert_ctx_stack_count_program_compiles("ustack", USTACK_MAP_NAME, "kprobe ctx.ustack count");
}

#[test]
fn test_compile_kprobe_tail_call_program() {
    let tail_call_decl_id = DeclId::new(42);
    let hir = make_tail_call_program(tail_call_decl_id);
    let decl_names = HashMap::from([(tail_call_decl_id, "tail-call".to_string())]);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("tail-call should lower through attach flow");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("tail-call should compile through attach flow");

    assert!(
        result
            .maps
            .iter()
            .any(|map| map.name == "dispatch_targets" && map.def == BpfMapDef::prog_array(1024)),
        "tail-call should emit a prog_array map"
    );
    assert!(
        result
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == "dispatch_targets"),
        "tail-call should emit a prog_array relocation"
    );
}

#[test]
fn test_compile_kprobe_ctx_task_non_null_program() {
    let hir = make_ctx_path_non_null_program(CellPath {
        members: vec![string_member("task")],
    });
    assert_attach_program_compiles(
        &hir,
        EbpfProgramType::Kprobe,
        "ksys_read",
        &HashMap::new(),
        "kprobe ctx.task non-null check",
    );
}

#[test]
fn test_compile_iter_task_ctx_task_nullable_program() {
    let hir = make_ctx_path_non_null_program(CellPath {
        members: vec![string_member("task")],
    });
    assert_attach_program_compiles(
        &hir,
        EbpfProgramType::Iter,
        "task",
        &HashMap::new(),
        "iter:task ctx.task nullable check",
    );
}

#[test]
fn test_compile_iter_task_ctx_meta_non_null_program() {
    let hir = make_ctx_path_non_null_program(CellPath {
        members: vec![string_member("meta")],
    });
    assert_attach_program_compiles(
        &hir,
        EbpfProgramType::Iter,
        "task",
        &HashMap::new(),
        "iter:task ctx.meta non-null check",
    );
}

#[test]
fn test_compile_iter_map_ctx_meta_non_null_program() {
    let hir = make_ctx_path_non_null_program(CellPath {
        members: vec![string_member("iter_meta")],
    });
    assert_attach_program_compiles(
        &hir,
        EbpfProgramType::Iter,
        "map",
        &HashMap::new(),
        "iter:map ctx.iter_meta non-null check",
    );
}

#[test]
fn test_compile_iter_task_file_payload_roots_programs() {
    for (path, context) in [
        (
            CellPath {
                members: vec![string_member("task")],
            },
            "iter:task_file ctx.task nullable check",
        ),
        (
            CellPath {
                members: vec![string_member("file")],
            },
            "iter:task_file ctx.file nullable check",
        ),
        (
            CellPath {
                members: vec![string_member("iter_file")],
            },
            "iter:task_file ctx.iter_file nullable check",
        ),
        (
            CellPath {
                members: vec![string_member("fd")],
            },
            "iter:task_file ctx.fd scalar check",
        ),
    ] {
        let hir = make_ctx_path_non_null_program(path);
        assert_attach_program_compiles(
            &hir,
            EbpfProgramType::Iter,
            "task_file",
            &HashMap::new(),
            context,
        );
    }
}

#[test]
fn test_compile_iter_task_vma_payload_roots_programs() {
    for (path, context) in [
        (
            CellPath {
                members: vec![string_member("task")],
            },
            "iter:task_vma ctx.task nullable check",
        ),
        (
            CellPath {
                members: vec![string_member("vma")],
            },
            "iter:task_vma ctx.vma nullable check",
        ),
        (
            CellPath {
                members: vec![string_member("iter_vma")],
            },
            "iter:task_vma ctx.iter_vma nullable check",
        ),
    ] {
        let hir = make_ctx_path_non_null_program(path);
        assert_attach_program_compiles(
            &hir,
            EbpfProgramType::Iter,
            "task_vma",
            &HashMap::new(),
            context,
        );
    }
}

#[test]
fn test_compile_iter_cgroup_payload_roots_programs() {
    for (path, context) in [
        (
            CellPath {
                members: vec![string_member("cgroup")],
            },
            "iter:cgroup ctx.cgroup nullable check",
        ),
        (
            CellPath {
                members: vec![string_member("iter_cgroup")],
            },
            "iter:cgroup ctx.iter_cgroup nullable check",
        ),
    ] {
        let hir = make_ctx_path_non_null_program(path);
        assert_attach_program_compiles(
            &hir,
            EbpfProgramType::Iter,
            "cgroup",
            &HashMap::new(),
            context,
        );
    }
}

#[test]
fn test_compile_iter_bpf_map_payload_root_program() {
    let hir = make_ctx_path_non_null_program(CellPath {
        members: vec![string_member("map")],
    });
    assert_attach_program_compiles(
        &hir,
        EbpfProgramType::Iter,
        "bpf_map",
        &HashMap::new(),
        "iter:bpf_map ctx.map nullable check",
    );
}

#[test]
fn test_compile_iter_bpf_map_elem_payload_roots_programs() {
    for (path, context) in [
        (
            CellPath {
                members: vec![string_member("map")],
            },
            "iter:bpf_map_elem ctx.map nullable check",
        ),
        (
            CellPath {
                members: vec![string_member("key")],
            },
            "iter:bpf_map_elem ctx.key nullable check",
        ),
        (
            CellPath {
                members: vec![string_member("value")],
            },
            "iter:bpf_map_elem ctx.value nullable check",
        ),
    ] {
        let hir = make_ctx_path_non_null_program(path);
        assert_attach_program_compiles(
            &hir,
            EbpfProgramType::Iter,
            "bpf_map_elem",
            &HashMap::new(),
            context,
        );
    }
}

#[test]
fn test_compile_iter_sockmap_payload_roots_programs() {
    for (path, context) in [
        (
            CellPath {
                members: vec![string_member("map")],
            },
            "iter:sockmap ctx.map nullable check",
        ),
        (
            CellPath {
                members: vec![string_member("key")],
            },
            "iter:sockmap ctx.key nullable check",
        ),
        (
            CellPath {
                members: vec![string_member("sk")],
            },
            "iter:sockmap ctx.sk nullable check",
        ),
    ] {
        let hir = make_ctx_path_non_null_program(path);
        assert_attach_program_compiles(
            &hir,
            EbpfProgramType::Iter,
            "sockmap",
            &HashMap::new(),
            context,
        );
    }
}

#[test]
fn test_compile_iter_bpf_sk_storage_map_payload_roots_programs() {
    for (path, context) in [
        (
            CellPath {
                members: vec![string_member("map")],
            },
            "iter:bpf_sk_storage_map ctx.map nullable check",
        ),
        (
            CellPath {
                members: vec![string_member("value")],
            },
            "iter:bpf_sk_storage_map ctx.value nullable check",
        ),
        (
            CellPath {
                members: vec![string_member("sk")],
            },
            "iter:bpf_sk_storage_map ctx.sk nullable check",
        ),
    ] {
        let hir = make_ctx_path_non_null_program(path);
        assert_attach_program_compiles(
            &hir,
            EbpfProgramType::Iter,
            "bpf_sk_storage_map",
            &HashMap::new(),
            context,
        );
    }
}

#[test]
fn test_compile_iter_bpf_prog_payload_root_program() {
    let hir = make_ctx_path_non_null_program(CellPath {
        members: vec![string_member("prog")],
    });
    assert_attach_program_compiles(
        &hir,
        EbpfProgramType::Iter,
        "bpf_prog",
        &HashMap::new(),
        "iter:bpf_prog ctx.prog nullable check",
    );
}

#[test]
fn test_compile_iter_bpf_link_payload_root_program() {
    let hir = make_ctx_path_non_null_program(CellPath {
        members: vec![string_member("link")],
    });
    assert_attach_program_compiles(
        &hir,
        EbpfProgramType::Iter,
        "bpf_link",
        &HashMap::new(),
        "iter:bpf_link ctx.link nullable check",
    );
}

#[test]
fn test_compile_iter_tcp_payload_roots_programs() {
    for (path, context) in [
        (
            CellPath {
                members: vec![string_member("sk_common")],
            },
            "iter:tcp ctx.sk_common nullable check",
        ),
        (
            CellPath {
                members: vec![string_member("sock_common")],
            },
            "iter:tcp ctx.sock_common nullable check",
        ),
        (
            CellPath {
                members: vec![string_member("uid")],
            },
            "iter:tcp ctx.uid scalar check",
        ),
    ] {
        let hir = make_ctx_path_non_null_program(path);
        assert_attach_program_compiles(
            &hir,
            EbpfProgramType::Iter,
            "tcp",
            &HashMap::new(),
            context,
        );
    }
}

#[test]
fn test_compile_iter_udp_payload_roots_programs() {
    for (path, context) in [
        (
            CellPath {
                members: vec![string_member("udp_sk")],
            },
            "iter:udp ctx.udp_sk nullable check",
        ),
        (
            CellPath {
                members: vec![string_member("uid")],
            },
            "iter:udp ctx.uid scalar check",
        ),
        (
            CellPath {
                members: vec![string_member("bucket")],
            },
            "iter:udp ctx.bucket scalar check",
        ),
    ] {
        let hir = make_ctx_path_non_null_program(path);
        assert_attach_program_compiles(
            &hir,
            EbpfProgramType::Iter,
            "udp",
            &HashMap::new(),
            context,
        );
    }
}

#[test]
fn test_compile_iter_unix_payload_roots_programs() {
    for (path, context) in [
        (
            CellPath {
                members: vec![string_member("unix_sk")],
            },
            "iter:unix ctx.unix_sk nullable check",
        ),
        (
            CellPath {
                members: vec![string_member("uid")],
            },
            "iter:unix ctx.uid scalar check",
        ),
    ] {
        let hir = make_ctx_path_non_null_program(path);
        assert_attach_program_compiles(
            &hir,
            EbpfProgramType::Iter,
            "unix",
            &HashMap::new(),
            context,
        );
    }
}

#[test]
fn test_compile_iter_misc_single_pointer_payload_roots_programs() {
    for (target, root, context) in [
        ("dmabuf", "dmabuf", "iter:dmabuf ctx.dmabuf nullable check"),
        ("ipv6_route", "rt", "iter:ipv6_route ctx.rt nullable check"),
        (
            "kmem_cache",
            "kmem_cache",
            "iter:kmem_cache ctx.kmem_cache nullable check",
        ),
        ("ksym", "ksym", "iter:ksym ctx.ksym nullable check"),
        (
            "netlink",
            "netlink_sk",
            "iter:netlink ctx.netlink_sk nullable check",
        ),
    ] {
        let hir = make_ctx_path_non_null_program(CellPath {
            members: vec![string_member(root)],
        });
        assert_attach_program_compiles(
            &hir,
            EbpfProgramType::Iter,
            target,
            &HashMap::new(),
            context,
        );
    }
}

fn task_struct_pid_projection_available() -> bool {
    let path = [TrampolineFieldSelector::Field("pid".to_string())];
    matches!(
        KernelBtf::get().kernel_named_type_field_projection("task_struct", &path),
        Ok(projection) if matches!(projection.type_info, TypeInfo::Int { .. })
    )
}

fn iter_meta_seq_num_projection_available() -> bool {
    let path = [TrampolineFieldSelector::Field("seq_num".to_string())];
    matches!(
        KernelBtf::get().kernel_named_type_field_projection("bpf_iter_meta", &path),
        Ok(projection) if matches!(projection.type_info, TypeInfo::Int { .. })
    )
}

fn file_f_mode_projection_available() -> bool {
    let path = [TrampolineFieldSelector::Field("f_mode".to_string())];
    matches!(
        KernelBtf::get().kernel_named_type_field_projection("file", &path),
        Ok(projection) if matches!(projection.type_info, TypeInfo::Int { .. })
    )
}

fn vma_vm_start_projection_available() -> bool {
    let path = [TrampolineFieldSelector::Field("vm_start".to_string())];
    matches!(
        KernelBtf::get().kernel_named_type_field_projection("vm_area_struct", &path),
        Ok(projection) if matches!(projection.type_info, TypeInfo::Int { .. })
    )
}

fn cgroup_level_projection_available() -> bool {
    let path = [TrampolineFieldSelector::Field("level".to_string())];
    matches!(
        KernelBtf::get().kernel_named_type_field_projection("cgroup", &path),
        Ok(projection) if matches!(projection.type_info, TypeInfo::Int { .. })
    )
}

fn bpf_map_id_projection_available() -> bool {
    let path = [TrampolineFieldSelector::Field("id".to_string())];
    matches!(
        KernelBtf::get().kernel_named_type_field_projection("bpf_map", &path),
        Ok(projection) if matches!(projection.type_info, TypeInfo::Int { .. })
    )
}

fn bpf_prog_len_projection_available() -> bool {
    let path = [TrampolineFieldSelector::Field("len".to_string())];
    matches!(
        KernelBtf::get().kernel_named_type_field_projection("bpf_prog", &path),
        Ok(projection) if matches!(projection.type_info, TypeInfo::Int { .. })
    )
}

fn bpf_link_id_projection_available() -> bool {
    let path = [TrampolineFieldSelector::Field("id".to_string())];
    matches!(
        KernelBtf::get().kernel_named_type_field_projection("bpf_link", &path),
        Ok(projection) if matches!(projection.type_info, TypeInfo::Int { .. })
    )
}

fn sock_common_skc_family_projection_available() -> bool {
    let path = [TrampolineFieldSelector::Field("skc_family".to_string())];
    matches!(
        KernelBtf::get().kernel_named_type_field_projection("sock_common", &path),
        Ok(projection) if matches!(projection.type_info, TypeInfo::Int { .. })
    )
}

fn sock_skc_family_projection_available() -> bool {
    let path = [
        TrampolineFieldSelector::Field("__sk_common".to_string()),
        TrampolineFieldSelector::Field("skc_family".to_string()),
    ];
    matches!(
        KernelBtf::get().kernel_named_type_field_projection("sock", &path),
        Ok(projection) if matches!(projection.type_info, TypeInfo::Int { .. })
    )
}

fn udp_sock_skc_family_projection_available() -> bool {
    let path = [
        TrampolineFieldSelector::Field("inet".to_string()),
        TrampolineFieldSelector::Field("sk".to_string()),
        TrampolineFieldSelector::Field("__sk_common".to_string()),
        TrampolineFieldSelector::Field("skc_family".to_string()),
    ];
    matches!(
        KernelBtf::get().kernel_named_type_field_projection("udp_sock", &path),
        Ok(projection) if matches!(projection.type_info, TypeInfo::Int { .. })
    )
}

fn unix_sock_skc_family_projection_available() -> bool {
    let path = [
        TrampolineFieldSelector::Field("sk".to_string()),
        TrampolineFieldSelector::Field("__sk_common".to_string()),
        TrampolineFieldSelector::Field("skc_family".to_string()),
    ];
    matches!(
        KernelBtf::get().kernel_named_type_field_projection("unix_sock", &path),
        Ok(projection) if matches!(projection.type_info, TypeInfo::Int { .. })
    )
}

fn ctx_task_pid_path(root: &str) -> CellPath {
    CellPath {
        members: vec![string_member(root), string_member("pid")],
    }
}

fn ctx_iter_meta_seq_num_path(root: &str) -> CellPath {
    CellPath {
        members: vec![string_member(root), string_member("seq_num")],
    }
}

fn ctx_file_f_mode_path(root: &str) -> CellPath {
    CellPath {
        members: vec![string_member(root), string_member("f_mode")],
    }
}

fn ctx_vma_vm_start_path(root: &str) -> CellPath {
    CellPath {
        members: vec![string_member(root), string_member("vm_start")],
    }
}

fn ctx_cgroup_level_path(root: &str) -> CellPath {
    CellPath {
        members: vec![string_member(root), string_member("level")],
    }
}

fn ctx_bpf_map_id_path(root: &str) -> CellPath {
    CellPath {
        members: vec![string_member(root), string_member("id")],
    }
}

fn ctx_bpf_prog_len_path(root: &str) -> CellPath {
    CellPath {
        members: vec![string_member(root), string_member("len")],
    }
}

fn ctx_bpf_link_id_path(root: &str) -> CellPath {
    CellPath {
        members: vec![string_member(root), string_member("id")],
    }
}

fn ctx_sock_common_skc_family_path(root: &str) -> CellPath {
    CellPath {
        members: vec![string_member(root), string_member("skc_family")],
    }
}

fn ctx_sock_skc_family_path(root: &str) -> CellPath {
    CellPath {
        members: vec![
            string_member(root),
            string_member("__sk_common"),
            string_member("skc_family"),
        ],
    }
}

fn ctx_udp_sock_skc_family_path(root: &str) -> CellPath {
    CellPath {
        members: vec![
            string_member(root),
            string_member("inet"),
            string_member("sk"),
            string_member("__sk_common"),
            string_member("skc_family"),
        ],
    }
}

fn ctx_unix_sock_skc_family_path(root: &str) -> CellPath {
    CellPath {
        members: vec![
            string_member(root),
            string_member("sk"),
            string_member("__sk_common"),
            string_member("skc_family"),
        ],
    }
}

fn pt_regs_offsets_available() -> bool {
    KernelBtf::get().pt_regs_offsets().is_ok()
}

fn ctx_task_pt_regs_arg0_path(root: &str) -> CellPath {
    CellPath {
        members: vec![
            string_member(root),
            string_member("pt_regs"),
            string_member("arg0"),
        ],
    }
}

type AttachProgramFixture = (EbpfProgramType, &'static str, &'static str);

fn representative_task_context_programs() -> [AttachProgramFixture; 3] {
    [
        (EbpfProgramType::Fentry, "security_file_open", "fentry"),
        (
            EbpfProgramType::RawTracepointWritable,
            "sys_enter",
            "raw_tracepoint.w",
        ),
        (EbpfProgramType::LsmCgroup, "socket_bind", "lsm_cgroup"),
    ]
}

fn representative_task_context_programs_with_kprobe() -> [AttachProgramFixture; 4] {
    [
        (EbpfProgramType::Kprobe, "ksys_read", "kprobe"),
        (EbpfProgramType::Fentry, "security_file_open", "fentry"),
        (
            EbpfProgramType::RawTracepointWritable,
            "sys_enter",
            "raw_tracepoint.w",
        ),
        (EbpfProgramType::LsmCgroup, "socket_bind", "lsm_cgroup"),
    ]
}

fn count_decl_names() -> HashMap<DeclId, String> {
    HashMap::from([(DeclId::new(42), "count".to_string())])
}

#[test]
fn test_compile_kprobe_ctx_task_pid_counter_program() {
    if !task_struct_pid_projection_available() {
        return;
    }

    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Kprobe,
        "ksys_read",
        ctx_task_pid_path("task"),
        "kprobe ctx.task.pid count",
    );
}

#[test]
fn test_compile_iter_task_ctx_task_pid_counter_program() {
    if !task_struct_pid_projection_available() {
        return;
    }

    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Iter,
        "task",
        ctx_task_pid_path("task"),
        "iter:task ctx.task.pid count",
    );
}

#[test]
fn test_compile_iter_task_ctx_iter_task_pid_counter_program() {
    if !task_struct_pid_projection_available() {
        return;
    }

    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Iter,
        "task",
        ctx_task_pid_path("iter_task"),
        "iter:task ctx.iter_task.pid count",
    );
}

#[test]
fn test_compile_iter_task_file_ctx_task_pid_counter_program() {
    if !task_struct_pid_projection_available() {
        return;
    }

    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Iter,
        "task_file",
        ctx_task_pid_path("task"),
        "iter:task_file ctx.task.pid count",
    );
}

#[test]
fn test_compile_iter_task_vma_ctx_task_pid_counter_program() {
    if !task_struct_pid_projection_available() {
        return;
    }

    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Iter,
        "task_vma",
        ctx_task_pid_path("task"),
        "iter:task_vma ctx.task.pid count",
    );
}

#[test]
fn test_compile_iter_task_file_ctx_file_f_mode_counter_program() {
    if !file_f_mode_projection_available() {
        return;
    }

    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Iter,
        "task_file",
        ctx_file_f_mode_path("file"),
        "iter:task_file ctx.file.f_mode count",
    );
}

#[test]
fn test_compile_iter_task_vma_ctx_vma_vm_start_counter_program() {
    if !vma_vm_start_projection_available() {
        return;
    }

    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Iter,
        "task_vma",
        ctx_vma_vm_start_path("vma"),
        "iter:task_vma ctx.vma.vm_start count",
    );
}

#[test]
fn test_compile_iter_cgroup_ctx_cgroup_level_counter_program() {
    if !cgroup_level_projection_available() {
        return;
    }

    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Iter,
        "cgroup",
        ctx_cgroup_level_path("cgroup"),
        "iter:cgroup ctx.cgroup.level count",
    );
}

#[test]
fn test_compile_iter_bpf_map_ctx_map_id_counter_program() {
    if !bpf_map_id_projection_available() {
        return;
    }

    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Iter,
        "bpf_map",
        ctx_bpf_map_id_path("map"),
        "iter:bpf_map ctx.map.id count",
    );
}

#[test]
fn test_compile_iter_bpf_map_elem_ctx_map_id_counter_program() {
    if !bpf_map_id_projection_available() {
        return;
    }

    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Iter,
        "bpf_map_elem",
        ctx_bpf_map_id_path("map"),
        "iter:bpf_map_elem ctx.map.id count",
    );
}

#[test]
fn test_compile_iter_bpf_prog_ctx_prog_len_counter_program() {
    if !bpf_prog_len_projection_available() {
        return;
    }

    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Iter,
        "bpf_prog",
        ctx_bpf_prog_len_path("prog"),
        "iter:bpf_prog ctx.prog.len count",
    );
}

#[test]
fn test_compile_iter_bpf_link_ctx_link_id_counter_program() {
    if !bpf_link_id_projection_available() {
        return;
    }

    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Iter,
        "bpf_link",
        ctx_bpf_link_id_path("link"),
        "iter:bpf_link ctx.link.id count",
    );
}

#[test]
fn test_compile_iter_bpf_sk_storage_map_ctx_map_id_counter_program() {
    if !bpf_map_id_projection_available() {
        return;
    }

    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Iter,
        "bpf_sk_storage_map",
        ctx_bpf_map_id_path("map"),
        "iter:bpf_sk_storage_map ctx.map.id count",
    );
}

#[test]
fn test_compile_iter_sockmap_ctx_map_id_counter_program() {
    if !bpf_map_id_projection_available() {
        return;
    }

    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Iter,
        "sockmap",
        ctx_bpf_map_id_path("map"),
        "iter:sockmap ctx.map.id count",
    );
}

#[test]
fn test_compile_iter_bpf_sk_storage_map_ctx_sk_skc_family_counter_program() {
    if !sock_skc_family_projection_available() {
        return;
    }

    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Iter,
        "bpf_sk_storage_map",
        ctx_sock_skc_family_path("sk"),
        "iter:bpf_sk_storage_map ctx.sk.__sk_common.skc_family count",
    );
}

#[test]
fn test_compile_iter_sockmap_ctx_sk_skc_family_counter_program() {
    if !sock_skc_family_projection_available() {
        return;
    }

    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Iter,
        "sockmap",
        ctx_sock_skc_family_path("sk"),
        "iter:sockmap ctx.sk.__sk_common.skc_family count",
    );
}

#[test]
fn test_compile_iter_tcp_ctx_uid_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Iter,
        "tcp",
        CellPath {
            members: vec![string_member("uid")],
        },
        "iter:tcp ctx.uid count",
    );
}

#[test]
fn test_compile_iter_tcp_ctx_sk_common_skc_family_counter_program() {
    if !sock_common_skc_family_projection_available() {
        return;
    }

    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Iter,
        "tcp",
        ctx_sock_common_skc_family_path("sk_common"),
        "iter:tcp ctx.sk_common.skc_family count",
    );
}

#[test]
fn test_compile_iter_udp_ctx_bucket_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Iter,
        "udp",
        CellPath {
            members: vec![string_member("bucket")],
        },
        "iter:udp ctx.bucket count",
    );
}

#[test]
fn test_compile_iter_udp_ctx_udp_sk_skc_family_counter_program() {
    if !udp_sock_skc_family_projection_available() {
        return;
    }

    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Iter,
        "udp",
        ctx_udp_sock_skc_family_path("udp_sk"),
        "iter:udp ctx.udp_sk.inet.sk.__sk_common.skc_family count",
    );
}

#[test]
fn test_compile_iter_unix_ctx_uid_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Iter,
        "unix",
        CellPath {
            members: vec![string_member("uid")],
        },
        "iter:unix ctx.uid count",
    );
}

#[test]
fn test_compile_iter_unix_ctx_unix_sk_skc_family_counter_program() {
    if !unix_sock_skc_family_projection_available() {
        return;
    }

    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Iter,
        "unix",
        ctx_unix_sock_skc_family_path("unix_sk"),
        "iter:unix ctx.unix_sk.sk.__sk_common.skc_family count",
    );
}

#[test]
fn test_compile_iter_task_ctx_meta_seq_num_counter_program() {
    if !iter_meta_seq_num_projection_available() {
        return;
    }

    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Iter,
        "task",
        ctx_iter_meta_seq_num_path("meta"),
        "iter:task ctx.meta.seq_num count",
    );
}

#[test]
fn test_compile_iter_map_ctx_iter_meta_seq_num_counter_program() {
    if !iter_meta_seq_num_projection_available() {
        return;
    }

    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Iter,
        "map",
        ctx_iter_meta_seq_num_path("iter_meta"),
        "iter:map ctx.iter_meta.seq_num count",
    );
}

#[test]
fn test_compile_tracepoint_ctx_current_task_pid_counter_program() {
    if !task_struct_pid_projection_available() {
        return;
    }

    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Tracepoint,
        "syscalls/sys_enter_openat",
        ctx_task_pid_path("current_task"),
        "tracepoint ctx.current_task.pid count",
    );
}

#[test]
fn test_compile_task_context_ctx_task_pid_counter_programs() {
    if !task_struct_pid_projection_available() {
        return;
    }

    for (program_type, target, label) in representative_task_context_programs() {
        assert_ctx_path_count_program_compiles(
            program_type,
            target,
            ctx_task_pid_path("task"),
            &format!("{label} ctx.task.pid count"),
        );
    }
}

#[test]
fn test_compile_kprobe_ctx_task_pt_regs_arg_counter_program() {
    if !pt_regs_offsets_available() {
        return;
    }

    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Kprobe,
        "ksys_read",
        ctx_task_pt_regs_arg0_path("task"),
        "kprobe ctx.task.pt_regs.arg0 count",
    );
}

#[test]
fn test_compile_tracepoint_ctx_current_task_pt_regs_arg_counter_program() {
    if !pt_regs_offsets_available() {
        return;
    }

    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Tracepoint,
        "syscalls/sys_enter_openat",
        ctx_task_pt_regs_arg0_path("current_task"),
        "tracepoint ctx.current_task.pt_regs.arg0 count",
    );
}

#[test]
fn test_compile_task_context_ctx_task_pt_regs_arg_counter_programs() {
    if !pt_regs_offsets_available() {
        return;
    }

    for (program_type, target, label) in representative_task_context_programs() {
        assert_ctx_path_count_program_compiles(
            program_type,
            target,
            ctx_task_pt_regs_arg0_path("task"),
            &format!("{label} ctx.task.pt_regs.arg0 count"),
        );
    }
}

#[test]
fn test_compile_kprobe_bound_ctx_task_pid_counter_program() {
    if !task_struct_pid_projection_available() {
        return;
    }

    let hir = make_bound_ctx_path_projection_call_program(
        CellPath {
            members: vec![string_member("task")],
        },
        CellPath {
            members: vec![string_member("pid")],
        },
        DeclId::new(42),
    );
    let decl_names = count_decl_names();
    assert_attach_program_compiles(
        &hir,
        EbpfProgramType::Kprobe,
        "ksys_read",
        &decl_names,
        "bound kprobe ctx.task.pid count",
    );
}

#[test]
fn test_compile_tracepoint_bound_ctx_current_task_pid_counter_program() {
    if !task_struct_pid_projection_available() {
        return;
    }

    let hir = make_bound_ctx_path_projection_call_program(
        CellPath {
            members: vec![string_member("current_task")],
        },
        CellPath {
            members: vec![string_member("pid")],
        },
        DeclId::new(42),
    );
    let decl_names = count_decl_names();
    assert_attach_program_compiles(
        &hir,
        EbpfProgramType::Tracepoint,
        "syscalls/sys_enter_openat",
        &decl_names,
        "bound tracepoint ctx.current_task.pid count",
    );
}

#[test]
fn test_compile_task_context_bound_ctx_task_pid_counter_programs() {
    if !task_struct_pid_projection_available() {
        return;
    }

    let decl_names = count_decl_names();
    for (program_type, target, label) in representative_task_context_programs() {
        let hir = make_bound_ctx_path_projection_call_program(
            CellPath {
                members: vec![string_member("task")],
            },
            CellPath {
                members: vec![string_member("pid")],
            },
            DeclId::new(42),
        );
        assert_attach_program_compiles(
            &hir,
            program_type,
            target,
            &decl_names,
            &format!("bound {label} ctx.task.pid count"),
        );
    }
}

#[test]
fn test_compile_kprobe_bound_ctx_task_pt_regs_arg_counter_program() {
    if !pt_regs_offsets_available() {
        return;
    }

    let hir = make_bound_ctx_path_projection_call_program(
        CellPath {
            members: vec![string_member("task")],
        },
        CellPath {
            members: vec![string_member("pt_regs"), string_member("arg0")],
        },
        DeclId::new(42),
    );
    let decl_names = count_decl_names();
    assert_attach_program_compiles(
        &hir,
        EbpfProgramType::Kprobe,
        "ksys_read",
        &decl_names,
        "bound kprobe ctx.task.pt_regs.arg0 count",
    );
}

#[test]
fn test_compile_tracepoint_bound_ctx_current_task_pt_regs_arg_counter_program() {
    if !pt_regs_offsets_available() {
        return;
    }

    let hir = make_bound_ctx_path_projection_call_program(
        CellPath {
            members: vec![string_member("current_task")],
        },
        CellPath {
            members: vec![string_member("pt_regs"), string_member("arg0")],
        },
        DeclId::new(42),
    );
    let decl_names = count_decl_names();
    assert_attach_program_compiles(
        &hir,
        EbpfProgramType::Tracepoint,
        "syscalls/sys_enter_openat",
        &decl_names,
        "bound tracepoint ctx.current_task.pt_regs.arg0 count",
    );
}

#[test]
fn test_compile_task_context_bound_ctx_task_pt_regs_arg_counter_programs() {
    if !pt_regs_offsets_available() {
        return;
    }

    let decl_names = count_decl_names();
    for (program_type, target, label) in representative_task_context_programs() {
        let hir = make_bound_ctx_path_projection_call_program(
            CellPath {
                members: vec![string_member("task")],
            },
            CellPath {
                members: vec![string_member("pt_regs"), string_member("arg0")],
            },
            DeclId::new(42),
        );
        assert_attach_program_compiles(
            &hir,
            program_type,
            target,
            &decl_names,
            &format!("bound {label} ctx.task.pt_regs.arg0 count"),
        );
    }
}

#[test]
fn test_compile_perf_event_ctx_cpu_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::PerfEvent,
        "software:cpu-clock:period=100000",
        CellPath {
            members: vec![string_member("cpu")],
        },
        "perf_event ctx.cpu count",
    );
}

#[test]
fn test_compile_perf_event_ctx_perf_counter_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::PerfEvent,
        "software:cpu-clock:period=100000",
        CellPath {
            members: vec![string_member("perf_counter")],
        },
        "perf_event ctx.perf_counter count",
    );
}

#[test]
fn test_compile_perf_event_ctx_perf_enabled_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::PerfEvent,
        "software:cpu-clock:period=100000",
        CellPath {
            members: vec![string_member("perf_enabled")],
        },
        "perf_event ctx.perf_enabled count",
    );
}

#[test]
fn test_compile_perf_event_ctx_perf_running_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::PerfEvent,
        "software:cpu-clock:period=100000",
        CellPath {
            members: vec![string_member("perf_running")],
        },
        "perf_event ctx.perf_running count",
    );
}

#[test]
fn test_compile_perf_event_ctx_arg0_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::PerfEvent,
        "software:cpu-clock:period=100000",
        CellPath {
            members: vec![string_member("arg0")],
        },
        "perf_event ctx.arg0 count",
    );
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_compile_perf_event_ctx_sample_period_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::PerfEvent,
        "software:cpu-clock:period=100000",
        CellPath {
            members: vec![string_member("sample_period")],
        },
        "perf_event ctx.sample_period count",
    );
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_compile_perf_event_ctx_addr_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::PerfEvent,
        "software:cpu-clock:period=100000",
        CellPath {
            members: vec![string_member("addr")],
        },
        "perf_event ctx.addr count",
    );
}

#[test]
fn test_compile_socket_filter_ctx_packet_len_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::SocketFilter,
        "udp4:127.0.0.1:31337",
        CellPath {
            members: vec![string_member("packet_len")],
        },
        "socket_filter ctx.packet_len count",
    );
}

#[test]
fn test_compile_socket_filter_ctx_len_alias_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::SocketFilter,
        "udp4:127.0.0.1:31337",
        CellPath {
            members: vec![string_member("len")],
        },
        "socket_filter ctx.len count",
    );
}

#[test]
fn test_compile_socket_filter_ctx_socket_uid_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::SocketFilter,
        "udp4:127.0.0.1:31337",
        CellPath {
            members: vec![string_member("socket_uid")],
        },
        "socket_filter ctx.socket_uid count",
    );
}

#[test]
fn test_compile_socket_filter_ctx_pkt_type_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::SocketFilter,
        "udp4:127.0.0.1:31337",
        CellPath {
            members: vec![string_member("pkt_type")],
        },
        "socket_filter ctx.pkt_type count",
    );
}

#[test]
fn test_compile_socket_filter_ctx_protocol_alias_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::SocketFilter,
        "udp4:127.0.0.1:31337",
        CellPath {
            members: vec![string_member("protocol")],
        },
        "socket_filter ctx.protocol count",
    );
}

#[test]
fn test_compile_socket_filter_ctx_vlan_tci_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::SocketFilter,
        "udp4:127.0.0.1:31337",
        CellPath {
            members: vec![string_member("vlan_tci")],
        },
        "socket_filter ctx.vlan_tci count",
    );
}

#[test]
fn test_compile_socket_filter_ctx_vlan_proto_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::SocketFilter,
        "udp4:127.0.0.1:31337",
        CellPath {
            members: vec![string_member("vlan_proto")],
        },
        "socket_filter ctx.vlan_proto count",
    );
}

#[test]
fn test_compile_socket_filter_ctx_napi_id_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::SocketFilter,
        "udp4:127.0.0.1:31337",
        CellPath {
            members: vec![string_member("napi_id")],
        },
        "socket_filter ctx.napi_id count",
    );
}

#[test]
fn test_compile_socket_filter_ctx_gso_segs_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::SocketFilter,
        "udp4:127.0.0.1:31337",
        CellPath {
            members: vec![string_member("gso_segs")],
        },
        "socket_filter ctx.gso_segs count",
    );
}

#[test]
fn test_compile_socket_filter_ctx_gso_size_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::SocketFilter,
        "udp4:127.0.0.1:31337",
        CellPath {
            members: vec![string_member("gso_size")],
        },
        "socket_filter ctx.gso_size count",
    );
}

#[test]
fn test_compile_cgroup_sock_ctx_family_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::CgroupSock,
        "/sys/fs/cgroup:sock_create",
        CellPath {
            members: vec![string_member("family")],
        },
        "cgroup_sock ctx.family count",
    );
}

#[test]
fn test_compile_cgroup_sock_ctx_rx_queue_mapping_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::CgroupSock,
        "/sys/fs/cgroup",
        CellPath {
            members: vec![string_member("rx_queue_mapping")],
        },
        "cgroup_sock ctx.rx_queue_mapping count",
    );
}

#[test]
fn test_compile_cgroup_sock_sock_release_ctx_bound_dev_if_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::CgroupSock,
        "/sys/fs/cgroup:sock_release",
        CellPath {
            members: vec![string_member("bound_dev_if")],
        },
        "cgroup_sock:sock_release ctx.bound_dev_if count",
    );
}

#[test]
fn test_compile_cgroup_sock_sock_release_ctx_priority_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::CgroupSock,
        "/sys/fs/cgroup:sock_release",
        CellPath {
            members: vec![string_member("priority")],
        },
        "cgroup_sock:sock_release ctx.priority count",
    );
}

#[test]
fn test_compile_cgroup_sock_addr_ctx_user_port_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::CgroupSockAddr,
        "/sys/fs/cgroup:connect4",
        CellPath {
            members: vec![string_member("user_port")],
        },
        "cgroup_sock_addr ctx.user_port count",
    );
}

#[test]
fn test_compile_cgroup_sock_addr_connect_unix_ctx_family_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::CgroupSockAddr,
        "/sys/fs/cgroup:connect_unix",
        CellPath {
            members: vec![string_member("family")],
        },
        "cgroup_sock_addr:connect_unix ctx.family count",
    );
}

#[test]
fn test_compile_cgroup_sockopt_get_ctx_sockopt_retval_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::CgroupSockopt,
        "/sys/fs/cgroup:get",
        CellPath {
            members: vec![string_member("sockopt_retval")],
        },
        "cgroup_sockopt:get ctx.sockopt_retval count",
    );
}

#[test]
fn test_compile_cgroup_sockopt_get_ctx_retval_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::CgroupSockopt,
        "/sys/fs/cgroup:get",
        CellPath {
            members: vec![string_member("retval")],
        },
        "cgroup_sockopt:get ctx.retval count",
    );
}

#[test]
fn test_compile_cgroup_sockopt_get_ctx_optlen_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::CgroupSockopt,
        "/sys/fs/cgroup:get",
        CellPath {
            members: vec![string_member("optlen")],
        },
        "cgroup_sockopt:get ctx.optlen count",
    );
}

#[test]
fn test_compile_cgroup_sockopt_get_ctx_netns_cookie_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::CgroupSockopt,
        "/sys/fs/cgroup:get",
        CellPath {
            members: vec![string_member("netns_cookie")],
        },
        "cgroup_sockopt:get ctx.netns_cookie count",
    );
}

#[test]
fn test_compile_socket_helper_ctx_projection_programs() {
    let cases = [
        (
            EbpfProgramType::CgroupSockopt,
            "/sys/fs/cgroup:get",
            vec![
                string_member("sk"),
                string_member("tcp"),
                string_member("snd_cwnd"),
            ],
            "cgroup_sockopt:get ctx.sk.tcp.snd_cwnd count",
        ),
        (
            EbpfProgramType::CgroupSockopt,
            "/sys/fs/cgroup:get",
            vec![
                string_member("sock"),
                string_member("tcp"),
                string_member("snd_cwnd"),
            ],
            "cgroup_sockopt:get ctx.sock.tcp.snd_cwnd count",
        ),
        (
            EbpfProgramType::CgroupSockopt,
            "/sys/fs/cgroup:get",
            vec![
                string_member("socket"),
                string_member("tcp"),
                string_member("delivered_ce"),
            ],
            "cgroup_sockopt:get ctx.socket.tcp.delivered_ce count",
        ),
        (
            EbpfProgramType::Tc,
            "lo:ingress",
            vec![
                string_member("sock"),
                string_member("full"),
                string_member("family"),
            ],
            "tc ctx.sock.full.family count",
        ),
        (
            EbpfProgramType::CgroupSkb,
            "/sys/fs/cgroup:ingress",
            vec![
                string_member("socket"),
                string_member("listener"),
                string_member("family"),
            ],
            "cgroup_skb ctx.socket.listener.family count",
        ),
    ];

    for (program_type, target, members, context) in cases {
        assert_ctx_path_count_program_compiles(program_type, target, CellPath { members }, context);
    }
}

#[test]
fn test_compile_cgroup_socket_root_alias_projection_programs() {
    let cases = [
        (
            EbpfProgramType::CgroupSock,
            "/sys/fs/cgroup:sock_create",
            vec![string_member("sock"), string_member("family")],
            "cgroup_sock ctx.sock.family count",
        ),
        (
            EbpfProgramType::CgroupSock,
            "/sys/fs/cgroup:post_bind4",
            vec![string_member("socket"), string_member("local_port")],
            "cgroup_sock ctx.socket.local_port count",
        ),
        (
            EbpfProgramType::CgroupSockopt,
            "/sys/fs/cgroup:get",
            vec![string_member("socket"), string_member("family")],
            "cgroup_sockopt:get ctx.socket.family count",
        ),
        (
            EbpfProgramType::CgroupSockAddr,
            "/sys/fs/cgroup:connect4",
            vec![string_member("sock"), string_member("family")],
            "cgroup_sock_addr ctx.sock.family count",
        ),
    ];

    for (program_type, target, members, context) in cases {
        assert_ctx_path_count_program_compiles(program_type, target, CellPath { members }, context);
    }
}

#[test]
fn test_compile_bound_socket_helper_ctx_projection_program() {
    let hir = make_bound_ctx_path_projection_call_program(
        CellPath {
            members: vec![string_member("sk")],
        },
        CellPath {
            members: vec![string_member("tcp"), string_member("icsk_retransmits")],
        },
        DeclId::new(42),
    );
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "count".to_string());
    assert_attach_program_compiles(
        &hir,
        EbpfProgramType::CgroupSockopt,
        "/sys/fs/cgroup:get",
        &decl_names,
        "bound cgroup_sockopt:get ctx.sk.tcp.icsk_retransmits count",
    );
}

#[test]
fn test_compile_bound_socket_helper_pointer_field_projection_programs() {
    let cases = [
        (
            EbpfProgramType::CgroupSockopt,
            "/sys/fs/cgroup:get",
            vec![string_member("sk"), string_member("tcp")],
            vec![string_member("snd_cwnd")],
            "bound cgroup_sockopt:get ctx.sk.tcp.snd_cwnd",
        ),
        (
            EbpfProgramType::Tc,
            "lo:ingress",
            vec![string_member("sk"), string_member("full")],
            vec![string_member("family")],
            "bound tc ctx.sk.full.family",
        ),
        (
            EbpfProgramType::CgroupSkb,
            "/sys/fs/cgroup:egress",
            vec![string_member("sk"), string_member("listener")],
            vec![string_member("family")],
            "bound cgroup_skb ctx.sk.listener.family",
        ),
    ];

    for (program_type, target, binding_members, access_members, context) in cases {
        let hir = make_bound_ctx_path_program(
            CellPath {
                members: binding_members,
            },
            CellPath {
                members: access_members,
            },
        );
        assert_attach_program_compiles(&hir, program_type, target, &HashMap::new(), context);
    }
}

#[test]
fn test_compile_sk_lookup_ctx_scalar_counter_programs() {
    for (field, context) in [
        ("family", "sk_lookup ctx.family count"),
        ("protocol", "sk_lookup ctx.protocol count"),
        ("cookie", "sk_lookup ctx.cookie count"),
        ("remote_ip4", "sk_lookup ctx.remote_ip4 count"),
        ("remote_port", "sk_lookup ctx.remote_port count"),
        ("local_ip4", "sk_lookup ctx.local_ip4 count"),
        ("local_port", "sk_lookup ctx.local_port count"),
        ("ingress_ifindex", "sk_lookup ctx.ingress_ifindex count"),
    ] {
        assert_ctx_path_count_program_compiles(
            EbpfProgramType::SkLookup,
            "/proc/self/ns/net",
            CellPath {
                members: vec![string_member(field)],
            },
            context,
        );
    }
}

#[test]
fn test_compile_sk_lookup_ctx_array_and_socket_projection_counter_programs() {
    for (members, context) in [
        (
            vec![string_member("remote_ip6"), int_member(3)],
            "sk_lookup ctx.remote_ip6[3] count",
        ),
        (
            vec![string_member("local_ip6"), int_member(0)],
            "sk_lookup ctx.local_ip6[0] count",
        ),
        (
            vec![string_member("sk"), string_member("bound_dev_if")],
            "sk_lookup ctx.sk.bound_dev_if count",
        ),
        (
            vec![string_member("sock"), string_member("family")],
            "sk_lookup ctx.sock.family count",
        ),
        (
            vec![string_member("socket"), string_member("dst_port")],
            "sk_lookup ctx.socket.dst_port count",
        ),
        (
            vec![string_member("sk"), string_member("src_ip4")],
            "sk_lookup ctx.sk.src_ip4 count",
        ),
        (
            vec![string_member("sk"), string_member("src_ip6"), int_member(0)],
            "sk_lookup ctx.sk.src_ip6[0] count",
        ),
    ] {
        assert_ctx_path_count_program_compiles(
            EbpfProgramType::SkLookup,
            "/proc/self/ns/net",
            CellPath { members },
            context,
        );
    }
}

#[test]
fn test_compile_flow_dissector_ctx_packet_byte_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::FlowDissector,
        "/proc/self/ns/net",
        CellPath {
            members: vec![string_member("data"), int_member(0)],
        },
        "flow_dissector ctx.data[0] count",
    );
}

#[test]
fn test_compile_flow_dissector_ctx_flow_keys_counter_program() {
    for (members, context) in [
        (
            vec![string_member("flow_keys"), string_member("nhoff")],
            "flow_dissector ctx.flow_keys.nhoff count",
        ),
        (
            vec![string_member("flow_keys"), string_member("thoff")],
            "flow_dissector ctx.flow_keys.thoff count",
        ),
        (
            vec![string_member("flow_keys"), string_member("addr_proto")],
            "flow_dissector ctx.flow_keys.addr_proto count",
        ),
        (
            vec![string_member("flow_keys"), string_member("is_frag")],
            "flow_dissector ctx.flow_keys.is_frag count",
        ),
        (
            vec![string_member("flow_keys"), string_member("is_first_frag")],
            "flow_dissector ctx.flow_keys.is_first_frag count",
        ),
        (
            vec![string_member("flow_keys"), string_member("is_encap")],
            "flow_dissector ctx.flow_keys.is_encap count",
        ),
        (
            vec![string_member("flow_keys"), string_member("ip_proto")],
            "flow_dissector ctx.flow_keys.ip_proto count",
        ),
        (
            vec![string_member("flow_keys"), string_member("n_proto")],
            "flow_dissector ctx.flow_keys.n_proto count",
        ),
        (
            vec![string_member("flow_keys"), string_member("sport")],
            "flow_dissector ctx.flow_keys.sport count",
        ),
        (
            vec![string_member("flow_keys"), string_member("dport")],
            "flow_dissector ctx.flow_keys.dport count",
        ),
        (
            vec![string_member("flow_keys"), string_member("ipv4_src")],
            "flow_dissector ctx.flow_keys.ipv4_src count",
        ),
        (
            vec![string_member("flow_keys"), string_member("ipv4_dst")],
            "flow_dissector ctx.flow_keys.ipv4_dst count",
        ),
        (
            vec![
                string_member("flow_keys"),
                string_member("ipv6_src"),
                int_member(0),
            ],
            "flow_dissector ctx.flow_keys.ipv6_src[0] count",
        ),
        (
            vec![
                string_member("flow_keys"),
                string_member("ipv6_dst"),
                int_member(3),
            ],
            "flow_dissector ctx.flow_keys.ipv6_dst[3] count",
        ),
        (
            vec![string_member("flow_keys"), string_member("flags")],
            "flow_dissector ctx.flow_keys.flags count",
        ),
        (
            vec![string_member("flow_keys"), string_member("flow_label")],
            "flow_dissector ctx.flow_keys.flow_label count",
        ),
    ] {
        assert_ctx_path_count_program_compiles(
            EbpfProgramType::FlowDissector,
            "/proc/self/ns/net",
            CellPath { members },
            context,
        );
    }
}

#[test]
fn test_compile_flow_dissector_ctx_flow_key_alias_counter_program() {
    for (members, context) in [
        (
            vec![
                string_member("flow_keys"),
                string_member("transport_header_offset"),
            ],
            "flow_dissector ctx.flow_keys.transport_header_offset count",
        ),
        (
            vec![string_member("flow_keys"), string_member("protocol")],
            "flow_dissector ctx.flow_keys.protocol count",
        ),
        (
            vec![string_member("flow_keys"), string_member("src_port")],
            "flow_dissector ctx.flow_keys.src_port count",
        ),
        (
            vec![string_member("flow_keys"), string_member("destination_ip4")],
            "flow_dissector ctx.flow_keys.destination_ip4 count",
        ),
        (
            vec![
                string_member("flow_keys"),
                string_member("dst_ip6"),
                int_member(3),
            ],
            "flow_dissector ctx.flow_keys.dst_ip6[3] count",
        ),
    ] {
        assert_ctx_path_count_program_compiles(
            EbpfProgramType::FlowDissector,
            "/proc/self/ns/net",
            CellPath { members },
            context,
        );
    }
}

#[test]
fn test_compile_netfilter_ctx_scalar_counter_programs() {
    for (field, context) in [
        ("hook", "netfilter ctx.hook count"),
        ("pf", "netfilter ctx.pf count"),
        ("protocol_family", "netfilter ctx.protocol_family count"),
    ] {
        assert_ctx_path_count_program_compiles(
            EbpfProgramType::Netfilter,
            "ipv4:pre_routing",
            CellPath {
                members: vec![string_member(field)],
            },
            context,
        );
    }
}

#[test]
fn test_compile_netfilter_ctx_typed_pointer_counter_programs() {
    for (members, context) in [
        (
            vec![string_member("state"), string_member("hook")],
            "netfilter ctx.state.hook count",
        ),
        (
            vec![string_member("state"), string_member("pf")],
            "netfilter ctx.state.pf count",
        ),
        (
            vec![string_member("nf_state"), string_member("pf")],
            "netfilter ctx.nf_state.pf count",
        ),
        (
            vec![
                string_member("state"),
                string_member("in"),
                string_member("ifindex"),
            ],
            "netfilter ctx.state.in.ifindex count",
        ),
        (
            vec![
                string_member("nf_state"),
                string_member("in"),
                string_member("ifindex"),
            ],
            "netfilter ctx.nf_state.in.ifindex count",
        ),
        (
            vec![
                string_member("state"),
                string_member("out"),
                string_member("ifindex"),
            ],
            "netfilter ctx.state.out.ifindex count",
        ),
        (
            vec![string_member("skb"), string_member("len")],
            "netfilter ctx.skb.len count",
        ),
    ] {
        assert_ctx_path_count_program_compiles(
            EbpfProgramType::Netfilter,
            "ipv4:pre_routing",
            CellPath { members },
            context,
        );
    }
}

#[test]
fn test_compile_netfilter_bound_typed_pointer_counter_programs() {
    for (root, projection, context) in [
        (
            vec![string_member("state")],
            vec![string_member("in"), string_member("ifindex")],
            "bound netfilter ctx.state.in.ifindex count",
        ),
        (
            vec![string_member("nf_state")],
            vec![string_member("out"), string_member("ifindex")],
            "bound netfilter ctx.nf_state.out.ifindex count",
        ),
        (
            vec![string_member("skb")],
            vec![string_member("len")],
            "bound netfilter ctx.skb.len count",
        ),
    ] {
        let hir = make_bound_ctx_path_projection_call_program(
            CellPath { members: root },
            CellPath {
                members: projection,
            },
            DeclId::new(42),
        );
        let decl_names = HashMap::from([(DeclId::new(42), "count".to_string())]);
        assert_attach_program_compiles(
            &hir,
            EbpfProgramType::Netfilter,
            "ipv4:pre_routing",
            &decl_names,
            context,
        );
    }
}

#[test]
fn test_compile_lwt_ctx_scalar_counter_programs() {
    for (program_type, target, field, context) in [
        (
            EbpfProgramType::LwtIn,
            "demo-route",
            "packet_len",
            "lwt_in ctx.packet_len count",
        ),
        (
            EbpfProgramType::LwtOut,
            "demo-route",
            "eth_protocol",
            "lwt_out ctx.eth_protocol count",
        ),
        (
            EbpfProgramType::LwtXmit,
            "demo-route",
            "hash",
            "lwt_xmit ctx.hash count",
        ),
        (
            EbpfProgramType::LwtSeg6Local,
            "demo-route",
            "ifindex",
            "lwt_seg6local ctx.ifindex count",
        ),
        (
            EbpfProgramType::LwtIn,
            "demo-route",
            "len",
            "lwt_in ctx.len count",
        ),
        (
            EbpfProgramType::LwtOut,
            "demo-route",
            "protocol",
            "lwt_out ctx.protocol count",
        ),
        (
            EbpfProgramType::LwtSeg6Local,
            "demo-route",
            "ingress_ifindex",
            "lwt_seg6local ctx.ingress_ifindex count",
        ),
        (
            EbpfProgramType::LwtIn,
            "demo-route",
            "cgroup_classid",
            "lwt_in ctx.cgroup_classid count",
        ),
        (
            EbpfProgramType::LwtOut,
            "demo-route",
            "route_realm",
            "lwt_out ctx.route_realm count",
        ),
        (
            EbpfProgramType::LwtXmit,
            "demo-route",
            "hash_recalc",
            "lwt_xmit ctx.hash_recalc count",
        ),
        (
            EbpfProgramType::LwtXmit,
            "demo-route",
            "csum_level",
            "lwt_xmit ctx.csum_level count",
        ),
        (
            EbpfProgramType::LwtXmit,
            "demo-route",
            "mark",
            "lwt_xmit ctx.mark count",
        ),
        (
            EbpfProgramType::LwtSeg6Local,
            "demo-route",
            "priority",
            "lwt_seg6local ctx.priority count",
        ),
    ] {
        assert_ctx_path_count_program_compiles(
            program_type,
            target,
            CellPath {
                members: vec![string_member(field)],
            },
            context,
        );
    }
}

#[test]
fn test_compile_lwt_ctx_packet_and_cb_counter_programs() {
    for (program_type, members, context) in [
        (
            EbpfProgramType::LwtIn,
            vec![string_member("data"), int_member(0)],
            "lwt_in ctx.data[0] count",
        ),
        (
            EbpfProgramType::LwtOut,
            vec![string_member("cb"), int_member(0)],
            "lwt_out ctx.cb[0] count",
        ),
    ] {
        assert_ctx_path_count_program_compiles(
            program_type,
            "demo-route",
            CellPath { members },
            context,
        );
    }
}

#[test]
fn test_compile_tc_action_ctx_scalar_counter_programs() {
    for (field, context) in [
        ("packet_len", "tc_action ctx.packet_len count"),
        ("len", "tc_action ctx.len count"),
        ("eth_protocol", "tc_action ctx.eth_protocol count"),
        ("protocol", "tc_action ctx.protocol count"),
        ("hash", "tc_action ctx.hash count"),
        ("ifindex", "tc_action ctx.ifindex count"),
        ("ingress_ifindex", "tc_action ctx.ingress_ifindex count"),
        ("mark", "tc_action ctx.mark count"),
        ("priority", "tc_action ctx.priority count"),
        ("tc_classid", "tc_action ctx.tc_classid count"),
        ("cgroup_classid", "tc_action ctx.cgroup_classid count"),
        ("route_realm", "tc_action ctx.route_realm count"),
        ("csum_level", "tc_action ctx.csum_level count"),
        ("skb_cgroup_id", "tc_action ctx.skb_cgroup_id count"),
        ("hash_recalc", "tc_action ctx.hash_recalc count"),
        ("wire_len", "tc_action ctx.wire_len count"),
        ("tstamp_type", "tc_action ctx.tstamp_type count"),
        ("pkt_type", "tc_action ctx.pkt_type count"),
        ("vlan_tci", "tc_action ctx.vlan_tci count"),
        ("napi_id", "tc_action ctx.napi_id count"),
        ("socket_cookie", "tc_action ctx.socket_cookie count"),
        ("socket_uid", "tc_action ctx.socket_uid count"),
        ("netns_cookie", "tc_action ctx.netns_cookie count"),
    ] {
        assert_ctx_path_count_program_compiles(
            EbpfProgramType::TcAction,
            "demo-action",
            CellPath {
                members: vec![string_member(field)],
            },
            context,
        );
    }
}

#[test]
fn test_compile_tc_action_ctx_packet_pointer_counter_programs() {
    for (members, context) in [
        (
            vec![string_member("data"), int_member(0)],
            "tc_action ctx.data[0] count",
        ),
        (
            vec![string_member("data_meta"), int_member(0)],
            "tc_action ctx.data_meta[0] count",
        ),
    ] {
        assert_ctx_path_count_program_compiles(
            EbpfProgramType::TcAction,
            "demo-action",
            CellPath { members },
            context,
        );
    }
}

#[test]
fn test_compile_tcx_ctx_scalar_and_packet_pointer_programs() {
    for (members, context) in [
        (
            vec![string_member("packet_len")],
            "tcx ingress ctx.packet_len count",
        ),
        (
            vec![string_member("data"), int_member(0)],
            "tcx ingress ctx.data[0] count",
        ),
        (
            vec![string_member("data_meta"), int_member(0)],
            "tcx ingress ctx.data_meta[0] count",
        ),
        (
            vec![string_member("sk"), string_member("family")],
            "tcx ingress ctx.sk.family count",
        ),
    ] {
        assert_ctx_path_count_program_compiles(
            EbpfProgramType::Tcx,
            "lo:ingress",
            CellPath { members },
            context,
        );
    }
}

#[test]
fn test_compile_netkit_ctx_scalar_and_packet_pointer_programs() {
    for (members, context) in [
        (
            vec![string_member("packet_len")],
            "netkit primary ctx.packet_len count",
        ),
        (
            vec![string_member("data"), int_member(0)],
            "netkit primary ctx.data[0] count",
        ),
        (
            vec![string_member("data_meta"), int_member(0)],
            "netkit primary ctx.data_meta[0] count",
        ),
        (
            vec![string_member("sk"), string_member("family")],
            "netkit primary ctx.sk.family count",
        ),
    ] {
        assert_ctx_path_count_program_compiles(
            EbpfProgramType::Netkit,
            "nk0:primary",
            CellPath { members },
            context,
        );
    }
}

#[test]
fn test_compile_tc_action_ctx_socket_projection_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::TcAction,
        "demo-action",
        CellPath {
            members: vec![string_member("sk"), string_member("family")],
        },
        "tc_action ctx.sk.family count",
    );
}

#[test]
fn test_compile_tc_action_ctx_recalc_hash_alias_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::TcAction,
        "demo-action",
        CellPath {
            members: vec![string_member("recalc_hash")],
        },
        "tc_action ctx.recalc_hash count",
    );
}

#[test]
fn test_compile_tc_action_ctx_skb_ancestor_cgroup_id_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::TcAction,
        "demo-action",
        CellPath {
            members: vec![string_member("skb_ancestor_cgroup_id"), int_member(0)],
        },
        "tc_action ctx.skb_ancestor_cgroup_id.0 count",
    );
}

#[test]
fn test_compile_sk_reuseport_ctx_scalar_counter_programs() {
    for (field, context) in [
        ("packet_len", "sk_reuseport ctx.packet_len count"),
        ("eth_protocol", "sk_reuseport ctx.eth_protocol count"),
        ("ip_protocol", "sk_reuseport ctx.ip_protocol count"),
        ("protocol", "sk_reuseport ctx.protocol count"),
        ("hash", "sk_reuseport ctx.hash count"),
        ("len", "sk_reuseport ctx.len count"),
        ("socket_cookie", "sk_reuseport ctx.socket_cookie count"),
        ("bind_inany", "sk_reuseport ctx.bind_inany count"),
    ] {
        assert_ctx_path_count_program_compiles(
            EbpfProgramType::SkReuseport,
            "select",
            CellPath {
                members: vec![string_member(field)],
            },
            context,
        );
    }
}

#[test]
fn test_compile_sk_reuseport_ctx_packet_and_socket_projection_counter_programs() {
    for (target, members, context) in [
        (
            "select",
            vec![string_member("data"), int_member(0)],
            "sk_reuseport:select ctx.data[0] count",
        ),
        (
            "select",
            vec![string_member("sk"), string_member("bound_dev_if")],
            "sk_reuseport:select ctx.sk.bound_dev_if count",
        ),
        (
            "select",
            vec![string_member("sock"), string_member("family")],
            "sk_reuseport:select ctx.sock.family count",
        ),
        (
            "select",
            vec![string_member("socket"), string_member("priority")],
            "sk_reuseport:select ctx.socket.priority count",
        ),
        (
            "migrate",
            vec![string_member("migrating_sk"), string_member("bound_dev_if")],
            "sk_reuseport:migrate ctx.migrating_sk.bound_dev_if count",
        ),
        (
            "migrate",
            vec![
                string_member("migrating_socket"),
                string_member("remote_port"),
            ],
            "sk_reuseport:migrate ctx.migrating_socket.remote_port count",
        ),
    ] {
        assert_ctx_path_count_program_compiles(
            EbpfProgramType::SkReuseport,
            target,
            CellPath { members },
            context,
        );
    }
}

#[test]
fn test_compile_xdp_ctx_rx_queue_index_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Xdp,
        "lo",
        CellPath {
            members: vec![string_member("rx_queue_index")],
        },
        "xdp ctx.rx_queue_index count",
    );
}

#[test]
fn test_compile_xdp_ctx_ifindex_alias_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Xdp,
        "lo",
        CellPath {
            members: vec![string_member("ifindex")],
        },
        "xdp ctx.ifindex count",
    );
}

#[test]
fn test_compile_xdp_ctx_egress_ifindex_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Xdp,
        "devmap",
        CellPath {
            members: vec![string_member("egress_ifindex")],
        },
        "xdp devmap ctx.egress_ifindex count",
    );

    for (target, label) in [("lo", "ordinary xdp"), ("cpumap", "xdp cpumap secondary")] {
        let hir = make_ctx_path_call_program(
            CellPath {
                members: vec![string_member("egress_ifindex")],
            },
            DeclId::new(42),
        );
        let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, target);
        let decl_names = HashMap::from([(DeclId::new(42), "count".to_string())]);
        let err = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &decl_names,
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .expect_err("non-devmap XDP should reject ctx.egress_ifindex");
        assert!(
            err.to_string()
                .contains("ctx.egress_ifindex is only available on xdp:devmap secondary programs"),
            "{label} should reject ctx.egress_ifindex with a target-aware error: {err}"
        );
    }
}

#[test]
fn test_compile_xdp_ctx_xdp_buffer_len_alias_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Xdp,
        "lo",
        CellPath {
            members: vec![string_member("xdp_buffer_len")],
        },
        "xdp ctx.xdp_buffer_len count",
    );
}

#[test]
fn test_compile_xdp_ctx_len_alias_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Xdp,
        "lo",
        CellPath {
            members: vec![string_member("len")],
        },
        "xdp ctx.len count",
    );
}

#[test]
fn test_compile_xdp_ctx_data_byte_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Xdp,
        "lo",
        CellPath {
            members: vec![string_member("data"), int_member(0)],
        },
        "xdp ctx.data[0] count",
    );
}

#[test]
fn test_compile_xdp_ctx_data_meta_byte_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Xdp,
        "lo",
        CellPath {
            members: vec![string_member("data_meta"), int_member(0)],
        },
        "xdp ctx.data_meta[0] count",
    );
}

#[test]
fn test_compile_xdp_metadata_kfunc_reports_kfunc_compatibility() {
    let ctx_var = VarId::new(0);
    let kfunc_decl = DeclId::new(42);
    let hir = HirProgram::new(
        HirFunction {
            blocks: vec![HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::String(b"bpf_xdp_metadata_rx_timestamp".to_vec()),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::String(b"01234567".to_vec()),
                    },
                    HirStmt::Call {
                        decl_id: kfunc_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(1), RegId::new(2)],
                            pipeline_input: Some(RegId::new(0)),
                            ..Default::default()
                        },
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(3),
                        lit: HirLiteral::Int(2),
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(3) },
            }],
            entry: HirBlockId(0),
            spans: vec![Span::test_data(); 5],
            ast: vec![None; 5],
            comments: vec![],
            register_count: 4,
            file_count: 0,
        },
        HashMap::new(),
        vec![],
        Some(ctx_var),
    );
    let decl_names = HashMap::from([(kfunc_decl, "kfunc-call".to_string())]);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("XDP metadata kfunc should lower");
    let used_kfuncs = collect_mir_kfunc_names(&lowering.program);

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("XDP metadata kfunc should compile");

    let program = result
        .into_program(
            EbpfProgramType::Xdp,
            "lo",
            "main",
            HashMap::new(),
            HashMap::new(),
        )
        .with_used_kfuncs(used_kfuncs);
    assert_eq!(
        program.used_kfuncs(),
        vec!["bpf_xdp_metadata_rx_timestamp".to_string()]
    );
    assert_eq!(program.kfunc_compatibility_minimum_kernel(), Some("6.3"));
    let requirement = program
        .kfunc_compatibility_requirements()
        .into_iter()
        .find(|requirement| requirement.name() == "bpf_xdp_metadata_rx_timestamp")
        .expect("XDP metadata timestamp should report kfunc compatibility");
    assert_eq!(requirement.key(), "kfunc:bpf_xdp_metadata_rx_timestamp");
}

#[test]
fn test_compile_xdp_random_int_counter_program() {
    let random_decl_id = DeclId::new(42);
    let count_decl_id = DeclId::new(43);
    let hir = make_random_int_count_program(random_decl_id, count_decl_id);
    let decl_names = HashMap::from([
        (random_decl_id, "random int".to_string()),
        (count_decl_id, "count".to_string()),
    ]);

    assert_attach_program_compiles(
        &hir,
        EbpfProgramType::Xdp,
        "lo",
        &decl_names,
        "xdp random int count",
    );
}

#[test]
fn test_compile_xdp_random_int_range_counter_program() {
    let random_decl_id = DeclId::new(42);
    let count_decl_id = DeclId::new(43);
    let hir = make_random_int_range_count_program(random_decl_id, count_decl_id, 10, 20);
    let decl_names = HashMap::from([
        (random_decl_id, "random int".to_string()),
        (count_decl_id, "count".to_string()),
    ]);

    assert_attach_program_compiles(
        &hir,
        EbpfProgramType::Xdp,
        "lo",
        &decl_names,
        "xdp random int bounded range count",
    );
}

#[test]
fn test_compile_tc_ctx_wire_len_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Tc,
        "lo:ingress",
        CellPath {
            members: vec![string_member("wire_len")],
        },
        "tc ctx.wire_len count",
    );
}

#[test]
fn test_compile_tc_ctx_protocol_alias_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Tc,
        "lo:ingress",
        CellPath {
            members: vec![string_member("protocol")],
        },
        "tc ctx.protocol count",
    );
}

#[test]
fn test_compile_tc_ctx_recalc_hash_alias_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Tc,
        "lo:ingress",
        CellPath {
            members: vec![string_member("recalc_hash")],
        },
        "tc ctx.recalc_hash count",
    );
}

#[test]
fn test_compile_lwt_ctx_recalc_hash_alias_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::LwtOut,
        "demo-route",
        CellPath {
            members: vec![string_member("recalc_hash")],
        },
        "lwt ctx.recalc_hash count",
    );
}

#[test]
fn test_compile_tc_egress_ctx_skb_ancestor_cgroup_id_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Tc,
        "lo:egress",
        CellPath {
            members: vec![string_member("skb_ancestor_cgroup_id"), int_member(0)],
        },
        "tc egress ctx.skb_ancestor_cgroup_id.0 count",
    );
}

#[test]
fn test_compile_cgroup_skb_ctx_mark_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::CgroupSkb,
        "/sys/fs/cgroup:ingress",
        CellPath {
            members: vec![string_member("mark")],
        },
        "cgroup_skb ctx.mark count",
    );
}

#[test]
fn test_compile_cgroup_skb_ctx_protocol_alias_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::CgroupSkb,
        "/sys/fs/cgroup:ingress",
        CellPath {
            members: vec![string_member("protocol")],
        },
        "cgroup_skb ctx.protocol count",
    );
}

#[test]
fn test_compile_cgroup_skb_ctx_remote_ip4_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::CgroupSkb,
        "/sys/fs/cgroup:ingress",
        CellPath {
            members: vec![string_member("remote_ip4")],
        },
        "cgroup_skb ctx.remote_ip4 count",
    );
}

#[test]
fn test_compile_cgroup_skb_ctx_local_port_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::CgroupSkb,
        "/sys/fs/cgroup:egress",
        CellPath {
            members: vec![string_member("local_port")],
        },
        "cgroup_skb ctx.local_port count",
    );
}

#[test]
fn test_compile_cgroup_skb_ctx_sk_cgroup_id_counter_program() {
    for (root, context) in [
        ("sk", "cgroup_skb ctx.sk.cgroup_id count"),
        ("sock", "cgroup_skb ctx.sock.cgroup_id count"),
        ("socket", "cgroup_skb ctx.socket.cgroup_id count"),
    ] {
        assert_ctx_path_count_program_compiles(
            EbpfProgramType::CgroupSkb,
            "/sys/fs/cgroup:ingress",
            CellPath {
                members: vec![string_member(root), string_member("cgroup_id")],
            },
            context,
        );
    }
}

#[test]
fn test_compile_cgroup_skb_ctx_sk_ancestor_cgroup_id_counter_program() {
    for (root, context) in [
        ("sk", "cgroup_skb ctx.sk.ancestor_cgroup_id.0 count"),
        ("sock", "cgroup_skb ctx.sock.ancestor_cgroup_id.0 count"),
        ("socket", "cgroup_skb ctx.socket.ancestor_cgroup_id.0 count"),
    ] {
        assert_ctx_path_count_program_compiles(
            EbpfProgramType::CgroupSkb,
            "/sys/fs/cgroup:egress",
            CellPath {
                members: vec![
                    string_member(root),
                    string_member("ancestor_cgroup_id"),
                    int_member(0),
                ],
            },
            context,
        );
    }
}

#[test]
fn test_compile_cgroup_sock_post_bind4_ctx_local_port_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::CgroupSock,
        "/sys/fs/cgroup:post_bind4",
        CellPath {
            members: vec![string_member("local_port")],
        },
        "cgroup_sock:post_bind4 ctx.local_port count",
    );
}

#[test]
fn test_compile_cgroup_sock_post_bind6_ctx_local_ip6_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::CgroupSock,
        "/sys/fs/cgroup:post_bind6",
        CellPath {
            members: vec![string_member("local_ip6"), int_member(1)],
        },
        "cgroup_sock:post_bind6 ctx.local_ip6[1] count",
    );
}

#[test]
fn test_compile_cgroup_device_ctx_major_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::CgroupDevice,
        "/sys/fs/cgroup",
        CellPath {
            members: vec![string_member("major")],
        },
        "cgroup_device ctx.major count",
    );
}

#[test]
fn test_compile_cgroup_device_ctx_access_type_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::CgroupDevice,
        "/sys/fs/cgroup",
        CellPath {
            members: vec![string_member("access_type")],
        },
        "cgroup_device ctx.access_type count",
    );
}

#[test]
fn test_compile_cgroup_device_ctx_device_access_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::CgroupDevice,
        "/sys/fs/cgroup",
        CellPath {
            members: vec![string_member("device_access")],
        },
        "cgroup_device ctx.device_access count",
    );
}

#[test]
fn test_compile_cgroup_device_ctx_device_type_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::CgroupDevice,
        "/sys/fs/cgroup",
        CellPath {
            members: vec![string_member("device_type")],
        },
        "cgroup_device ctx.device_type count",
    );
}

#[test]
fn test_compile_cgroup_device_ctx_minor_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::CgroupDevice,
        "/sys/fs/cgroup",
        CellPath {
            members: vec![string_member("minor")],
        },
        "cgroup_device ctx.minor count",
    );
}

#[test]
fn test_compile_cgroup_sysctl_ctx_write_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::CgroupSysctl,
        "/sys/fs/cgroup",
        CellPath {
            members: vec![string_member("write")],
        },
        "cgroup_sysctl ctx.write count",
    );
}

#[test]
fn test_compile_cgroup_sysctl_ctx_name_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::CgroupSysctl,
        "/sys/fs/cgroup",
        CellPath {
            members: vec![string_member("sysctl_name")],
        },
        "cgroup_sysctl ctx.sysctl_name count",
    );
}

#[test]
fn test_compile_cgroup_sysctl_ctx_base_name_alias_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::CgroupSysctl,
        "/sys/fs/cgroup",
        CellPath {
            members: vec![string_member("base_name"), int_member(0)],
        },
        "cgroup_sysctl ctx.base_name[0] count",
    );
}

#[test]
fn test_compile_cgroup_sysctl_ctx_current_value_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::CgroupSysctl,
        "/sys/fs/cgroup",
        CellPath {
            members: vec![string_member("sysctl_current_value")],
        },
        "cgroup_sysctl ctx.sysctl_current_value count",
    );
}

#[test]
fn test_compile_cgroup_sysctl_ctx_new_value_alias_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::CgroupSysctl,
        "/sys/fs/cgroup",
        CellPath {
            members: vec![string_member("new_value"), int_member(0)],
        },
        "cgroup_sysctl ctx.new_value[0] count",
    );
}

#[test]
fn test_compile_cgroup_sockopt_set_ctx_level_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::CgroupSockopt,
        "/sys/fs/cgroup:set",
        CellPath {
            members: vec![string_member("level")],
        },
        "cgroup_sockopt:set ctx.level count",
    );
}

#[test]
fn test_compile_cgroup_sock_addr_connect6_ctx_user_ip6_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::CgroupSockAddr,
        "/sys/fs/cgroup:connect6",
        CellPath {
            members: vec![string_member("user_ip6"), int_member(2)],
        },
        "cgroup_sock_addr:connect6 ctx.user_ip6[2] count",
    );
}

#[test]
fn test_compile_cgroup_sock_addr_getpeername4_ctx_remote_ip4_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::CgroupSockAddr,
        "/sys/fs/cgroup:getpeername4",
        CellPath {
            members: vec![string_member("remote_ip4")],
        },
        "cgroup_sock_addr:getpeername4 ctx.remote_ip4 count",
    );
}

#[test]
fn test_compile_cgroup_sock_addr_getsockname6_ctx_local_ip6_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::CgroupSockAddr,
        "/sys/fs/cgroup:getsockname6",
        CellPath {
            members: vec![string_member("local_ip6"), int_member(1)],
        },
        "cgroup_sock_addr:getsockname6 ctx.local_ip6[1] count",
    );
}

#[test]
fn test_compile_cgroup_sock_addr_sendmsg4_ctx_msg_src_ip4_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::CgroupSockAddr,
        "/sys/fs/cgroup:sendmsg4",
        CellPath {
            members: vec![string_member("msg_src_ip4")],
        },
        "cgroup_sock_addr:sendmsg4 ctx.msg_src_ip4 count",
    );
}

#[test]
fn test_compile_cgroup_sock_addr_sendmsg6_ctx_msg_src_ip6_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::CgroupSockAddr,
        "/sys/fs/cgroup:sendmsg6",
        CellPath {
            members: vec![string_member("msg_src_ip6"), int_member(3)],
        },
        "cgroup_sock_addr:sendmsg6 ctx.msg_src_ip6[3] count",
    );
}

#[test]
fn test_compile_sock_ops_ctx_op_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::SockOps,
        "/sys/fs/cgroup",
        CellPath {
            members: vec![string_member("op")],
        },
        "sock_ops ctx.op count",
    );
}

#[test]
fn test_compile_sk_msg_ctx_data_byte_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::SkMsg,
        "/sys/fs/bpf/demo_sockmap",
        CellPath {
            members: vec![string_member("data"), int_member(0)],
        },
        "sk_msg ctx.data[0] count",
    );
}

#[test]
fn test_compile_sock_ops_guarded_ctx_packet_len_counter_program() {
    assert_guarded_sock_ops_ctx_path_count_program_compiles(
        BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB,
        CellPath {
            members: vec![string_member("packet_len")],
        },
        "guarded sock_ops ctx.packet_len count",
    );
}

#[test]
fn test_compile_sock_ops_guarded_ctx_len_alias_counter_program() {
    assert_guarded_sock_ops_ctx_path_count_program_compiles(
        BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB,
        CellPath {
            members: vec![string_member("len")],
        },
        "guarded sock_ops ctx.len count",
    );
}

#[test]
fn test_compile_sock_ops_guarded_ctx_data_byte_counter_program() {
    assert_guarded_sock_ops_ctx_path_count_program_compiles(
        BPF_SOCK_OPS_PARSE_HDR_OPT_CB,
        CellPath {
            members: vec![string_member("data"), int_member(0)],
        },
        "guarded sock_ops ctx.data[0] count",
    );
}

#[test]
fn test_compile_sock_ops_guarded_ctx_skb_tcp_flags_counter_program() {
    assert_guarded_sock_ops_ctx_path_count_program_compiles(
        BPF_SOCK_OPS_HDR_OPT_LEN_CB,
        CellPath {
            members: vec![string_member("skb_tcp_flags")],
        },
        "guarded sock_ops ctx.skb_tcp_flags count",
    );
}

#[test]
fn test_compile_sk_msg_ctx_packet_len_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::SkMsg,
        "/sys/fs/bpf/demo_sockmap",
        CellPath {
            members: vec![string_member("packet_len")],
        },
        "sk_msg ctx.packet_len count",
    );
}

#[test]
fn test_compile_sk_msg_ctx_len_alias_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::SkMsg,
        "/sys/fs/bpf/demo_sockmap",
        CellPath {
            members: vec![string_member("len")],
        },
        "sk_msg ctx.len count",
    );
}

#[test]
fn test_compile_sk_msg_ctx_size_alias_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::SkMsg,
        "/sys/fs/bpf/demo_sockmap",
        CellPath {
            members: vec![string_member("size")],
        },
        "sk_msg ctx.size count",
    );
}

#[test]
fn test_compile_sk_msg_ctx_netns_cookie_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::SkMsg,
        "/sys/fs/bpf/demo_sockmap",
        CellPath {
            members: vec![string_member("netns_cookie")],
        },
        "sk_msg ctx.netns_cookie count",
    );
}

#[test]
fn test_compile_stream_socket_root_alias_projection_programs() {
    let cases = [
        (
            EbpfProgramType::SockOps,
            "/sys/fs/cgroup",
            vec![string_member("sock"), string_member("state")],
            "sock_ops ctx.sock.state count",
        ),
        (
            EbpfProgramType::SockOps,
            "/sys/fs/cgroup",
            vec![string_member("socket"), string_member("rx_queue_mapping")],
            "sock_ops ctx.socket.rx_queue_mapping count",
        ),
        (
            EbpfProgramType::SkMsg,
            "/sys/fs/bpf/demo_sockmap",
            vec![string_member("socket"), string_member("family")],
            "sk_msg ctx.socket.family count",
        ),
        (
            EbpfProgramType::SkSkb,
            "/sys/fs/bpf/demo_sockmap",
            vec![string_member("sock"), string_member("local_port")],
            "sk_skb ctx.sock.local_port count",
        ),
        (
            EbpfProgramType::SkSkbParser,
            "/sys/fs/bpf/demo_sockmap",
            vec![string_member("socket"), string_member("remote_port")],
            "sk_skb_parser ctx.socket.remote_port count",
        ),
    ];

    for (program_type, target, members, context) in cases {
        assert_ctx_path_count_program_compiles(program_type, target, CellPath { members }, context);
    }
}

#[test]
fn test_compile_sk_skb_ctx_packet_len_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::SkSkb,
        "/sys/fs/bpf/demo_sockmap",
        CellPath {
            members: vec![string_member("packet_len")],
        },
        "sk_skb ctx.packet_len count",
    );
}

#[test]
fn test_compile_sk_skb_ctx_len_alias_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::SkSkb,
        "/sys/fs/bpf/demo_sockmap",
        CellPath {
            members: vec![string_member("len")],
        },
        "sk_skb ctx.len count",
    );
}

#[test]
fn test_compile_sk_skb_ctx_protocol_alias_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::SkSkb,
        "/sys/fs/bpf/demo_sockmap",
        CellPath {
            members: vec![string_member("protocol")],
        },
        "sk_skb ctx.protocol count",
    );
}

#[test]
fn test_compile_sk_skb_ctx_remote_port_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::SkSkb,
        "/sys/fs/bpf/demo_sockmap",
        CellPath {
            members: vec![string_member("remote_port")],
        },
        "sk_skb ctx.remote_port count",
    );
}

#[test]
fn test_compile_sk_skb_parser_ctx_packet_len_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::SkSkbParser,
        "/sys/fs/bpf/demo_sockmap",
        CellPath {
            members: vec![string_member("packet_len")],
        },
        "sk_skb_parser ctx.packet_len count",
    );
}

#[test]
fn test_compile_sk_skb_parser_ctx_protocol_alias_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::SkSkbParser,
        "/sys/fs/bpf/demo_sockmap",
        CellPath {
            members: vec![string_member("protocol")],
        },
        "sk_skb_parser ctx.protocol count",
    );
}

#[test]
fn test_compile_sk_skb_parser_ctx_remote_ip6_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::SkSkbParser,
        "/sys/fs/bpf/demo_sockmap",
        CellPath {
            members: vec![string_member("remote_ip6"), int_member(2)],
        },
        "sk_skb_parser ctx.remote_ip6.2 count",
    );
}

#[test]
fn test_compile_sk_skb_parser_ctx_socket_uid_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::SkSkbParser,
        "/sys/fs/bpf/demo_sockmap",
        CellPath {
            members: vec![string_member("socket_uid")],
        },
        "sk_skb_parser ctx.socket_uid count",
    );
}

#[test]
fn test_compile_lirc_mode2_ctx_value_counter_program() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::LircMode2,
        "/dev/null",
        CellPath {
            members: vec![string_member("value")],
        },
        "lirc_mode2 ctx.value count",
    );
}

#[test]
fn test_compile_lirc_mode2_ctx_sample_and_mode_counter_programs() {
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::LircMode2,
        "/dev/null",
        CellPath {
            members: vec![string_member("sample")],
        },
        "lirc_mode2 ctx.sample count",
    );
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::LircMode2,
        "/dev/null",
        CellPath {
            members: vec![string_member("raw")],
        },
        "lirc_mode2 ctx.raw count",
    );
    assert_ctx_path_count_program_compiles(
        EbpfProgramType::LircMode2,
        "/dev/null",
        CellPath {
            members: vec![string_member("mode")],
        },
        "lirc_mode2 ctx.mode count",
    );
}

#[test]
fn test_compile_tc_ctx_mark_store_program() {
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::Tc,
        "lo:ingress",
        CellPath {
            members: vec![string_member("mark")],
        },
        HirLiteral::Int(7),
        HirLiteral::Int(0),
        "tc ctx.mark store",
    );
}

#[test]
fn test_compile_tc_ctx_data_byte_store_program() {
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::Tc,
        "lo:ingress",
        CellPath {
            members: vec![string_member("data"), int_member(0)],
        },
        HirLiteral::Int(42),
        HirLiteral::Int(0),
        "tc ctx.data[0] store",
    );
}

#[test]
fn test_compile_tc_ctx_cb_word_store_program() {
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::Tc,
        "lo:ingress",
        CellPath {
            members: vec![string_member("cb"), int_member(2)],
        },
        HirLiteral::Int(7),
        HirLiteral::Int(0),
        "tc ctx.cb[2] store",
    );
}

#[test]
fn test_compile_socket_filter_ctx_cb_word_store_program() {
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::SocketFilter,
        "udp4:127.0.0.1:31337",
        CellPath {
            members: vec![string_member("cb"), int_member(1)],
        },
        HirLiteral::Int(9),
        HirLiteral::Int(0),
        "socket_filter ctx.cb[1] store",
    );
}

#[test]
fn test_compile_cgroup_skb_egress_ctx_priority_store_program() {
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::CgroupSkb,
        "/sys/fs/cgroup:egress",
        CellPath {
            members: vec![string_member("priority")],
        },
        HirLiteral::Int(3),
        HirLiteral::Int(1),
        "cgroup_skb:egress ctx.priority store",
    );
}

#[test]
fn test_compile_cgroup_skb_egress_ctx_cb_word_store_program() {
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::CgroupSkb,
        "/sys/fs/cgroup:egress",
        CellPath {
            members: vec![string_member("cb"), int_member(3)],
        },
        HirLiteral::Int(11),
        HirLiteral::Int(1),
        "cgroup_skb:egress ctx.cb[3] store",
    );
}

#[test]
fn test_compile_cgroup_skb_egress_ctx_tstamp_store_program() {
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::CgroupSkb,
        "/sys/fs/cgroup:egress",
        CellPath {
            members: vec![string_member("tstamp")],
        },
        HirLiteral::Int(123),
        HirLiteral::Int(1),
        "cgroup_skb:egress ctx.tstamp store",
    );
}

#[test]
fn test_compile_remaining_skb_metadata_store_programs() {
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::Tc,
        "lo:ingress",
        CellPath {
            members: vec![string_member("queue_mapping")],
        },
        HirLiteral::Int(4),
        HirLiteral::Int(0),
        "tc ctx.queue_mapping store",
    );
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::Tc,
        "lo:ingress",
        CellPath {
            members: vec![string_member("priority")],
        },
        HirLiteral::Int(3),
        HirLiteral::Int(0),
        "tc ctx.priority store",
    );
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::Tc,
        "lo:ingress",
        CellPath {
            members: vec![string_member("tc_index")],
        },
        HirLiteral::Int(7),
        HirLiteral::Int(0),
        "tc ctx.tc_index store",
    );
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::Tc,
        "lo:ingress",
        CellPath {
            members: vec![string_member("tc_classid")],
        },
        HirLiteral::Int(9),
        HirLiteral::Int(0),
        "tc ctx.tc_classid store",
    );
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::Tc,
        "lo:ingress",
        CellPath {
            members: vec![string_member("tstamp")],
        },
        HirLiteral::Int(123),
        HirLiteral::Int(0),
        "tc ctx.tstamp store",
    );
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::CgroupSkb,
        "/sys/fs/cgroup:ingress",
        CellPath {
            members: vec![string_member("mark")],
        },
        HirLiteral::Int(5),
        HirLiteral::Int(1),
        "cgroup_skb:ingress ctx.mark store",
    );
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::LwtIn,
        "demo-route",
        CellPath {
            members: vec![string_member("mark")],
        },
        HirLiteral::Int(5),
        HirLiteral::String(b"ok".to_vec()),
        "lwt_in ctx.mark store",
    );
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::LwtOut,
        "demo-route",
        CellPath {
            members: vec![string_member("priority")],
        },
        HirLiteral::Int(6),
        HirLiteral::String(b"ok".to_vec()),
        "lwt_out ctx.priority store",
    );
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::LwtXmit,
        "demo-route",
        CellPath {
            members: vec![string_member("cb"), int_member(1)],
        },
        HirLiteral::Int(7),
        HirLiteral::String(b"ok".to_vec()),
        "lwt_xmit ctx.cb[1] store",
    );
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::LwtSeg6Local,
        "demo-route",
        CellPath {
            members: vec![string_member("cb"), int_member(4)],
        },
        HirLiteral::Int(8),
        HirLiteral::String(b"ok".to_vec()),
        "lwt_seg6local ctx.cb[4] store",
    );
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::SkSkb,
        "/sys/fs/bpf/demo_sockmap",
        CellPath {
            members: vec![string_member("priority")],
        },
        HirLiteral::Int(3),
        HirLiteral::Int(0),
        "sk_skb ctx.priority store",
    );
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::SkSkbParser,
        "/sys/fs/bpf/demo_sockmap",
        CellPath {
            members: vec![string_member("tc_index")],
        },
        HirLiteral::Int(7),
        HirLiteral::Int(0),
        "sk_skb_parser ctx.tc_index store",
    );
}

#[test]
fn test_compile_tc_action_skb_metadata_store_programs() {
    for (field, value) in [
        ("mark", 7),
        ("queue_mapping", 4),
        ("priority", 3),
        ("tc_index", 5),
        ("tc_classid", 9),
        ("tstamp", 123),
    ] {
        assert_ctx_path_store_program_compiles(
            EbpfProgramType::TcAction,
            "demo-action",
            CellPath {
                members: vec![string_member(field)],
            },
            HirLiteral::Int(value),
            HirLiteral::Int(0),
            &format!("tc_action ctx.{field} store"),
        );
    }

    assert_ctx_path_store_program_compiles(
        EbpfProgramType::TcAction,
        "demo-action",
        CellPath {
            members: vec![string_member("cb"), int_member(2)],
        },
        HirLiteral::Int(7),
        HirLiteral::Int(0),
        "tc_action ctx.cb[2] store",
    );
}

#[test]
fn test_compile_xdp_ctx_ethertype_store_program() {
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::Xdp,
        "lo",
        CellPath {
            members: vec![
                string_member("data"),
                string_member("eth"),
                string_member("ethertype"),
            ],
        },
        HirLiteral::Int(0x86dd),
        HirLiteral::Int(2),
        "xdp ctx.data.eth.ethertype store",
    );
}

#[test]
fn test_compile_xdp_ctx_packet_header_alias_store_program() {
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::Xdp,
        "lo",
        CellPath {
            members: vec![
                string_member("data"),
                string_member("eth"),
                string_member("h_proto"),
            ],
        },
        HirLiteral::Int(0x86dd),
        HirLiteral::Int(2),
        "xdp ctx.data.eth.h_proto store",
    );
}

#[test]
fn test_compile_xdp_ctx_eth_ipv6_udp_dst_store_program() {
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::Xdp,
        "lo",
        CellPath {
            members: vec![
                string_member("data"),
                string_member("eth"),
                string_member("ipv6"),
                string_member("udp"),
                string_member("dst"),
            ],
        },
        HirLiteral::Int(53),
        HirLiteral::Int(2),
        "xdp ctx.data.eth.ipv6.udp.dst store",
    );
}

#[test]
fn test_compile_xdp_ctx_data_meta_byte_store_program() {
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::Xdp,
        "lo",
        CellPath {
            members: vec![string_member("data_meta"), int_member(0)],
        },
        HirLiteral::Int(7),
        HirLiteral::Int(2),
        "xdp ctx.data_meta[0] store",
    );
}

#[test]
fn test_compile_additional_direct_packet_write_programs() {
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::TcAction,
        "demo-action",
        CellPath {
            members: vec![string_member("data"), int_member(0)],
        },
        HirLiteral::Int(7),
        HirLiteral::Int(0),
        "tc_action ctx.data[0] store",
    );
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::TcAction,
        "demo-action",
        CellPath {
            members: vec![string_member("data_meta"), int_member(0)],
        },
        HirLiteral::Int(7),
        HirLiteral::Int(0),
        "tc_action ctx.data_meta[0] store",
    );
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::Tc,
        "lo:ingress",
        CellPath {
            members: vec![string_member("data_meta"), int_member(0)],
        },
        HirLiteral::Int(7),
        HirLiteral::Int(0),
        "tc ctx.data_meta[0] store",
    );
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::LwtXmit,
        "demo-route",
        CellPath {
            members: vec![string_member("data"), int_member(0)],
        },
        HirLiteral::Int(7),
        HirLiteral::String(b"ok".to_vec()),
        "lwt_xmit ctx.data[0] store",
    );
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::SkMsg,
        "/sys/fs/bpf/demo_sockmap",
        CellPath {
            members: vec![string_member("data"), int_member(0)],
        },
        HirLiteral::Int(7),
        HirLiteral::String(b"pass".to_vec()),
        "sk_msg ctx.data[0] store",
    );
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::SkSkb,
        "/sys/fs/bpf/demo_sockmap",
        CellPath {
            members: vec![string_member("data"), int_member(0)],
        },
        HirLiteral::Int(7),
        HirLiteral::String(b"pass".to_vec()),
        "sk_skb ctx.data[0] store",
    );
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::SkSkbParser,
        "/sys/fs/bpf/demo_sockmap",
        CellPath {
            members: vec![string_member("data"), int_member(0)],
        },
        HirLiteral::Int(7),
        HirLiteral::Int(0),
        "sk_skb_parser ctx.data[0] store",
    );
}

#[test]
fn test_compile_cgroup_sock_sock_create_ctx_mark_store_program() {
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::CgroupSock,
        "/sys/fs/cgroup:sock_create",
        CellPath {
            members: vec![string_member("mark")],
        },
        HirLiteral::Int(7),
        HirLiteral::Int(1),
        "cgroup_sock:sock_create ctx.mark store",
    );
}

#[test]
fn test_compile_cgroup_sock_sock_release_ctx_bound_dev_if_store_program() {
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::CgroupSock,
        "/sys/fs/cgroup:sock_release",
        CellPath {
            members: vec![string_member("bound_dev_if")],
        },
        HirLiteral::Int(7),
        HirLiteral::Int(1),
        "cgroup_sock:sock_release ctx.bound_dev_if store",
    );
}

#[test]
fn test_compile_cgroup_sock_sock_release_ctx_priority_store_program() {
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::CgroupSock,
        "/sys/fs/cgroup:sock_release",
        CellPath {
            members: vec![string_member("priority")],
        },
        HirLiteral::Int(7),
        HirLiteral::Int(1),
        "cgroup_sock:sock_release ctx.priority store",
    );
}

#[test]
fn test_compile_cgroup_sysctl_ctx_file_pos_store_program() {
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::CgroupSysctl,
        "/sys/fs/cgroup",
        CellPath {
            members: vec![string_member("file_pos")],
        },
        HirLiteral::Int(4),
        HirLiteral::Int(1),
        "cgroup_sysctl ctx.file_pos store",
    );
}

#[test]
fn test_compile_cgroup_sysctl_ctx_new_value_store_program() {
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::CgroupSysctl,
        "/sys/fs/cgroup",
        CellPath {
            members: vec![string_member("new_value")],
        },
        HirLiteral::String(b"1".to_vec()),
        HirLiteral::String(b"allow".to_vec()),
        "cgroup_sysctl ctx.new_value store",
    );
}

#[test]
fn test_compile_sock_ops_ctx_reply_store_program() {
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::SockOps,
        "/sys/fs/cgroup",
        CellPath {
            members: vec![string_member("reply")],
        },
        HirLiteral::Int(1),
        HirLiteral::Int(1),
        "sock_ops ctx.reply store",
    );
}

#[test]
fn test_compile_sock_ops_ctx_replylong_word_store_program() {
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::SockOps,
        "/sys/fs/cgroup",
        CellPath {
            members: vec![string_member("replylong"), int_member(2)],
        },
        HirLiteral::Int(7),
        HirLiteral::Int(1),
        "sock_ops ctx.replylong[2] store",
    );
}

#[test]
fn test_compile_sock_ops_ctx_cb_flags_store_program() {
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::SockOps,
        "/sys/fs/cgroup",
        CellPath {
            members: vec![string_member("cb_flags")],
        },
        HirLiteral::Int(1),
        HirLiteral::Int(1),
        "sock_ops ctx.cb_flags store",
    );
}

#[test]
fn test_compile_sock_ops_ctx_sk_txhash_store_program() {
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::SockOps,
        "/sys/fs/cgroup",
        CellPath {
            members: vec![string_member("sk_txhash")],
        },
        HirLiteral::Int(7),
        HirLiteral::Int(1),
        "sock_ops ctx.sk_txhash store",
    );
}

#[test]
fn test_compile_sock_ops_enable_tx_tstamp_kfunc_program() {
    let ctx_var = VarId::new(0);
    let hir = HirProgram::new(
        HirFunction {
            blocks: vec![HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::String(b"bpf_sock_ops_enable_tx_tstamp".to_vec()),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::Call {
                        decl_id: DeclId::new(42),
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(1), RegId::new(2)],
                            pipeline_input: Some(RegId::new(0)),
                            ..Default::default()
                        },
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(3),
                        lit: HirLiteral::Int(1),
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(3) },
            }],
            entry: HirBlockId(0),
            spans: vec![Span::test_data(); 5],
            ast: vec![None; 5],
            comments: vec![],
            register_count: 4,
            file_count: 0,
        },
        HashMap::new(),
        vec![],
        Some(ctx_var),
    );
    let decl_names = HashMap::from([(DeclId::new(42), "kfunc-call".to_string())]);

    assert_attach_program_compiles(
        &hir,
        EbpfProgramType::SockOps,
        "/sys/fs/cgroup",
        &decl_names,
        "sock_ops bpf_sock_ops_enable_tx_tstamp kfunc",
    );
}

#[test]
fn test_compile_cgroup_sock_addr_connect6_ctx_user_ip6_store_program() {
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::CgroupSockAddr,
        "/sys/fs/cgroup:connect6",
        CellPath {
            members: vec![string_member("user_ip6"), int_member(2)],
        },
        HirLiteral::Int(42),
        HirLiteral::Int(1),
        "cgroup_sock_addr:connect6 ctx.user_ip6[2] store",
    );
}

#[test]
fn test_compile_cgroup_sock_addr_getpeername4_ctx_remote_ip4_store_program() {
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::CgroupSockAddr,
        "/sys/fs/cgroup:getpeername4",
        CellPath {
            members: vec![string_member("remote_ip4")],
        },
        HirLiteral::Int(0x7f000001),
        HirLiteral::Int(1),
        "cgroup_sock_addr:getpeername4 ctx.remote_ip4 store",
    );
}

#[test]
fn test_compile_cgroup_sock_addr_getsockname6_ctx_local_ip6_store_program() {
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::CgroupSockAddr,
        "/sys/fs/cgroup:getsockname6",
        CellPath {
            members: vec![string_member("local_ip6"), int_member(1)],
        },
        HirLiteral::Int(42),
        HirLiteral::Int(1),
        "cgroup_sock_addr:getsockname6 ctx.local_ip6[1] store",
    );
}

#[test]
fn test_compile_cgroup_sock_addr_sendmsg6_ctx_msg_src_ip6_store_program() {
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::CgroupSockAddr,
        "/sys/fs/cgroup:sendmsg6",
        CellPath {
            members: vec![string_member("msg_src_ip6"), int_member(3)],
        },
        HirLiteral::Int(42),
        HirLiteral::Int(1),
        "cgroup_sock_addr:sendmsg6 ctx.msg_src_ip6[3] store",
    );
}

#[test]
fn test_compile_cgroup_sock_addr_unix_ctx_sun_path_store_program() {
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::CgroupSockAddr,
        "/sys/fs/cgroup:connect_unix",
        CellPath {
            members: vec![string_member("sun_path")],
        },
        HirLiteral::String(b"/tmp/nu-ebpf.sock".to_vec()),
        HirLiteral::String(b"allow".to_vec()),
        "cgroup_sock_addr:connect_unix ctx.sun_path store",
    );
}

#[test]
fn test_context_write_program_reports_direct_field_compatibility() {
    for (program_type, target, cell_path, new_value, return_value, field, minimum_kernel) in [
        (
            EbpfProgramType::CgroupSock,
            "/sys/fs/cgroup:sock_create",
            CellPath {
                members: vec![string_member("bound_dev_if")],
            },
            HirLiteral::Int(2),
            HirLiteral::String(b"allow".to_vec()),
            CtxField::BoundDevIf,
            "4.10",
        ),
        (
            EbpfProgramType::CgroupSock,
            "/sys/fs/cgroup:sock_create",
            CellPath {
                members: vec![string_member("mark")],
            },
            HirLiteral::Int(42),
            HirLiteral::String(b"allow".to_vec()),
            CtxField::SockMark,
            "4.14",
        ),
        (
            EbpfProgramType::CgroupSockAddr,
            "/sys/fs/cgroup:connect4",
            CellPath {
                members: vec![string_member("remote_ip4")],
            },
            HirLiteral::Int(0x7f000001),
            HirLiteral::String(b"allow".to_vec()),
            CtxField::RemoteIp4,
            "4.17",
        ),
        (
            EbpfProgramType::CgroupSockAddr,
            "/sys/fs/cgroup:connect6",
            CellPath {
                members: vec![string_member("remote_ip6"), int_member(0)],
            },
            HirLiteral::Int(1),
            HirLiteral::String(b"allow".to_vec()),
            CtxField::RemoteIp6,
            "4.17",
        ),
        (
            EbpfProgramType::CgroupSockAddr,
            "/sys/fs/cgroup:sendmsg4",
            CellPath {
                members: vec![string_member("local_ip4")],
            },
            HirLiteral::Int(0x7f000001),
            HirLiteral::String(b"allow".to_vec()),
            CtxField::LocalIp4,
            "4.18",
        ),
        (
            EbpfProgramType::CgroupSockAddr,
            "/sys/fs/cgroup:sendmsg6",
            CellPath {
                members: vec![string_member("local_ip6"), int_member(1)],
            },
            HirLiteral::Int(1),
            HirLiteral::String(b"allow".to_vec()),
            CtxField::LocalIp6,
            "4.18",
        ),
        (
            EbpfProgramType::TcAction,
            "demo-action",
            CellPath {
                members: vec![string_member("mark")],
            },
            HirLiteral::Int(42),
            HirLiteral::Int(0),
            CtxField::SockMark,
            "4.1",
        ),
        (
            EbpfProgramType::TcAction,
            "demo-action",
            CellPath {
                members: vec![string_member("queue_mapping")],
            },
            HirLiteral::Int(4),
            HirLiteral::Int(0),
            CtxField::QueueMapping,
            "4.1",
        ),
        (
            EbpfProgramType::TcAction,
            "demo-action",
            CellPath {
                members: vec![string_member("tc_index")],
            },
            HirLiteral::Int(5),
            HirLiteral::Int(0),
            CtxField::TcIndex,
            "4.7",
        ),
        (
            EbpfProgramType::TcAction,
            "demo-action",
            CellPath {
                members: vec![string_member("cb"), int_member(2)],
            },
            HirLiteral::Int(7),
            HirLiteral::Int(0),
            CtxField::SkbCb,
            "4.7",
        ),
        (
            EbpfProgramType::TcAction,
            "demo-action",
            CellPath {
                members: vec![string_member("tc_classid")],
            },
            HirLiteral::Int(9),
            HirLiteral::Int(0),
            CtxField::TcClassid,
            "4.7",
        ),
        (
            EbpfProgramType::TcAction,
            "demo-action",
            CellPath {
                members: vec![string_member("tstamp")],
            },
            HirLiteral::Int(123),
            HirLiteral::Int(0),
            CtxField::Tstamp,
            "5.0",
        ),
        (
            EbpfProgramType::LwtXmit,
            "demo-route",
            CellPath {
                members: vec![string_member("mark")],
            },
            HirLiteral::Int(42),
            HirLiteral::String(b"reroute".to_vec()),
            CtxField::SockMark,
            "4.1",
        ),
        (
            EbpfProgramType::LwtXmit,
            "demo-route",
            CellPath {
                members: vec![string_member("priority")],
            },
            HirLiteral::Int(3),
            HirLiteral::String(b"reroute".to_vec()),
            CtxField::SockPriority,
            "4.1",
        ),
        (
            EbpfProgramType::LwtXmit,
            "demo-route",
            CellPath {
                members: vec![string_member("cb"), int_member(1)],
            },
            HirLiteral::Int(7),
            HirLiteral::String(b"reroute".to_vec()),
            CtxField::SkbCb,
            "4.7",
        ),
        (
            EbpfProgramType::SockOps,
            "/sys/fs/cgroup",
            CellPath {
                members: vec![string_member("reply")],
            },
            HirLiteral::Int(1),
            HirLiteral::Int(1),
            CtxField::SockOpsReply,
            "4.14",
        ),
        (
            EbpfProgramType::SockOps,
            "/sys/fs/cgroup",
            CellPath {
                members: vec![string_member("replylong"), int_member(2)],
            },
            HirLiteral::Int(7),
            HirLiteral::Int(1),
            CtxField::SockOpsReplyLong,
            "4.14",
        ),
        (
            EbpfProgramType::SockOps,
            "/sys/fs/cgroup",
            CellPath {
                members: vec![string_member("sk_txhash")],
            },
            HirLiteral::Int(42),
            HirLiteral::Int(1),
            CtxField::SockOpsSkTxhash,
            "4.16",
        ),
    ] {
        let program = compile_ctx_path_store_program(
            program_type,
            target,
            cell_path,
            new_value,
            return_value,
            "context write direct field compatibility",
        );
        let requirements = program.context_field_compatibility_requirements();
        let requirement = requirements
            .iter()
            .find(|requirement| requirement.field() == &field)
            .unwrap_or_else(|| {
                panic!(
                    "expected context field compatibility for {}",
                    field.display_name()
                )
            });
        assert_eq!(requirement.minimum_kernel(), minimum_kernel);
        assert!(
            requirement
                .minimum_kernel_source()
                .contains(&format!("/v{minimum_kernel}/"))
        );
    }
}

#[test]
fn test_context_write_program_reports_backing_helper_compatibility() {
    for (
        program_type,
        target,
        cell_path,
        new_value,
        return_value,
        helper,
        minimum_kernel,
        context_field,
        context_minimum_kernel,
    ) in [
        (
            EbpfProgramType::CgroupSysctl,
            "/sys/fs/cgroup",
            CellPath {
                members: vec![string_member("new_value")],
            },
            HirLiteral::String(b"1".to_vec()),
            HirLiteral::String(b"allow".to_vec()),
            BpfHelper::SysctlSetNewValue,
            "5.2",
            CtxField::SysctlNewValue,
            "5.2",
        ),
        (
            EbpfProgramType::SockOps,
            "/sys/fs/cgroup",
            CellPath {
                members: vec![string_member("cb_flags")],
            },
            HirLiteral::Int(1),
            HirLiteral::Int(1),
            BpfHelper::SockOpsCbFlagsSet,
            "4.16",
            CtxField::SockOpsCbFlags,
            "4.16",
        ),
        (
            EbpfProgramType::SkLookup,
            "/proc/self/ns/net",
            CellPath {
                members: vec![string_member("sk")],
            },
            HirLiteral::Int(0),
            HirLiteral::Int(1),
            BpfHelper::SkAssign,
            "5.7",
            CtxField::Socket,
            "5.9",
        ),
    ] {
        let program = compile_ctx_path_store_program(
            program_type,
            target,
            cell_path,
            new_value,
            return_value,
            "context write helper compatibility",
        );
        let requirements = program.helper_compatibility_requirements();
        let requirement = requirements
            .iter()
            .find(|requirement| requirement.helper() == helper)
            .unwrap_or_else(|| panic!("expected helper compatibility for {}", helper.name()));
        assert_eq!(requirement.minimum_kernel(), minimum_kernel);
        assert!(
            requirement
                .minimum_kernel_source()
                .contains(&format!("/v{minimum_kernel}/"))
        );

        let context_requirements = program.context_field_compatibility_requirements();
        let context_requirement = context_requirements
            .iter()
            .find(|requirement| requirement.field() == &context_field)
            .unwrap_or_else(|| {
                panic!(
                    "expected context field compatibility for {}",
                    context_field.display_name()
                )
            });
        assert_eq!(context_requirement.minimum_kernel(), context_minimum_kernel);
        assert!(
            context_requirement
                .minimum_kernel_source()
                .contains(&format!("/v{context_minimum_kernel}/"))
        );
    }
}

#[test]
fn test_context_path_program_reports_backing_helper_compatibility() {
    for (program_type, target, cell_path, helper, minimum_kernel) in [
        (
            EbpfProgramType::Kprobe,
            "ksys_read",
            CellPath {
                members: vec![string_member("ancestor_cgroup_id"), int_member(0)],
            },
            BpfHelper::GetCurrentAncestorCgroupId,
            "5.7",
        ),
        (
            EbpfProgramType::Tc,
            "lo:egress",
            CellPath {
                members: vec![string_member("skb_cgroup_id")],
            },
            BpfHelper::SkbCgroupId,
            "4.18",
        ),
        (
            EbpfProgramType::Tc,
            "lo:egress",
            CellPath {
                members: vec![string_member("skb_ancestor_cgroup_id"), int_member(0)],
            },
            BpfHelper::SkbAncestorCgroupId,
            "4.19",
        ),
        (
            EbpfProgramType::CgroupSkb,
            "/sys/fs/cgroup:egress",
            CellPath {
                members: vec![
                    string_member("sk"),
                    string_member("ancestor_cgroup_id"),
                    int_member(0),
                ],
            },
            BpfHelper::SkAncestorCgroupId,
            "5.8",
        ),
    ] {
        let program = compile_ctx_path_count_program(
            program_type,
            target,
            cell_path,
            "context path helper compatibility",
        );
        let requirements = program.helper_compatibility_requirements();
        let requirement = requirements
            .iter()
            .find(|requirement| requirement.helper() == helper)
            .unwrap_or_else(|| panic!("expected helper compatibility for {}", helper.name()));
        assert_eq!(requirement.minimum_kernel(), minimum_kernel);
        assert!(
            requirement
                .minimum_kernel_source()
                .contains(&format!("/v{minimum_kernel}/"))
        );
    }
}

#[test]
fn test_socket_projection_context_path_reports_context_field_compatibility() {
    let program = compile_ctx_path_count_program(
        EbpfProgramType::Tc,
        "lo:ingress",
        CellPath {
            members: vec![string_member("sk"), string_member("family")],
        },
        "tc ctx.sk.family context field compatibility",
    );

    let requirements = program.context_field_compatibility_requirements();
    for (field, minimum_kernel) in [(CtxField::Socket, "5.1"), (CtxField::Family, "4.14")] {
        let requirement = requirements
            .iter()
            .find(|requirement| requirement.field() == &field)
            .unwrap_or_else(|| {
                panic!(
                    "expected ctx.sk.family to report {} compatibility",
                    field.display_name()
                )
            });
        assert_eq!(requirement.minimum_kernel(), minimum_kernel);
        assert!(
            requirement
                .minimum_kernel_source()
                .contains(&format!("/v{minimum_kernel}/"))
        );
    }
}

#[test]
fn test_current_cgroup_context_path_reports_context_field_compatibility() {
    for (program_type, target, field_name) in [
        (EbpfProgramType::Kprobe, "ksys_read", "cgroup"),
        (EbpfProgramType::Kprobe, "ksys_read", "current_cgroup"),
        (
            EbpfProgramType::Tracepoint,
            "syscalls/sys_enter_openat",
            "current_cgroup",
        ),
    ] {
        let program = compile_ctx_path_discard_program(
            program_type,
            target,
            CellPath {
                members: vec![string_member(field_name)],
            },
            "current cgroup context field compatibility",
        );

        assert!(
            program.used_context_fields().contains(&CtxField::Cgroup),
            "expected ctx.{field_name} to preserve source-level cgroup context usage"
        );

        let requirements = program.context_field_compatibility_requirements();
        let requirement = requirements
            .iter()
            .find(|requirement| requirement.field() == &CtxField::Cgroup)
            .unwrap_or_else(|| {
                panic!("expected ctx.{field_name} to report cgroup context compatibility")
            });
        assert_eq!(requirement.key(), "ctx:cgroup");
        assert_eq!(requirement.minimum_kernel(), "5.11");
        assert!(
            requirement
                .minimum_kernel_source()
                .contains("/v5.11/include/uapi/linux/bpf.h")
        );
    }
}

#[test]
fn test_context_write_program_reports_backing_kfunc_compatibility() {
    let program = compile_ctx_path_store_program(
        EbpfProgramType::CgroupSockAddr,
        "/sys/fs/cgroup:connect_unix",
        CellPath {
            members: vec![string_member("sun_path")],
        },
        HirLiteral::String(b"/tmp/nu-ebpf.sock".to_vec()),
        HirLiteral::String(b"allow".to_vec()),
        "cgroup_sock_addr:connect_unix ctx.sun_path store",
    );

    let requirements = program.kfunc_compatibility_requirements();
    let requirement = requirements
        .iter()
        .find(|requirement| requirement.name() == "bpf_sock_addr_set_sun_path")
        .expect("expected sun_path kfunc compatibility");
    assert_eq!(requirement.minimum_kernel(), "6.7");
    assert!(
        requirement
            .minimum_kernel_source()
            .contains("/v6.7/net/core/filter.c")
    );
}

#[test]
fn test_compile_cgroup_sockopt_set_ctx_level_store_program() {
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::CgroupSockopt,
        "/sys/fs/cgroup:set",
        CellPath {
            members: vec![string_member("level")],
        },
        HirLiteral::Int(1),
        HirLiteral::Int(1),
        "cgroup_sockopt:set ctx.level store",
    );
}

#[test]
fn test_compile_cgroup_sockopt_set_ctx_optlen_store_program() {
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::CgroupSockopt,
        "/sys/fs/cgroup:set",
        CellPath {
            members: vec![string_member("optlen")],
        },
        HirLiteral::Int(4),
        HirLiteral::Int(1),
        "cgroup_sockopt:set ctx.optlen store",
    );
}

#[test]
fn test_compile_cgroup_sockopt_get_ctx_retval_store_program() {
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::CgroupSockopt,
        "/sys/fs/cgroup:get",
        CellPath {
            members: vec![string_member("retval")],
        },
        HirLiteral::Int(0),
        HirLiteral::Int(1),
        "cgroup_sockopt:get ctx.retval store",
    );
}

#[test]
fn test_compile_remaining_cgroup_socket_scalar_store_programs() {
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::CgroupSockopt,
        "/sys/fs/cgroup:set",
        CellPath {
            members: vec![string_member("optname")],
        },
        HirLiteral::Int(2),
        HirLiteral::Int(1),
        "cgroup_sockopt:set ctx.optname store",
    );
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::CgroupSockopt,
        "/sys/fs/cgroup:get",
        CellPath {
            members: vec![string_member("optlen")],
        },
        HirLiteral::Int(4),
        HirLiteral::Int(1),
        "cgroup_sockopt:get ctx.optlen store",
    );
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::CgroupSockopt,
        "/sys/fs/cgroup:get",
        CellPath {
            members: vec![string_member("sockopt_retval")],
        },
        HirLiteral::Int(0),
        HirLiteral::Int(1),
        "cgroup_sockopt:get ctx.sockopt_retval store",
    );
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::CgroupSockAddr,
        "/sys/fs/cgroup:bind4",
        CellPath {
            members: vec![string_member("local_port")],
        },
        HirLiteral::Int(8080),
        HirLiteral::Int(1),
        "cgroup_sock_addr:bind4 ctx.local_port store",
    );
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::CgroupSockAddr,
        "/sys/fs/cgroup:sendmsg4",
        CellPath {
            members: vec![string_member("local_ip4")],
        },
        HirLiteral::Int(0x7f000001),
        HirLiteral::Int(1),
        "cgroup_sock_addr:sendmsg4 ctx.local_ip4 store",
    );
}

#[test]
fn test_compile_cgroup_sockopt_get_guarded_ctx_optval_byte_store_program() {
    let hir = make_gt_zero_guarded_ctx_path_store_program(
        CellPath {
            members: vec![string_member("optlen")],
        },
        CellPath {
            members: vec![string_member("optval"), int_member(0)],
        },
        HirLiteral::Int(42),
        HirLiteral::Int(1),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("guarded cgroup_sockopt:get ctx.optval[0] store should lower through attach flow");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized guarded cgroup_sockopt:get ctx.optval[0] store should compile");
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_cgroup_sockopt_get_branch_refined_ctx_optval_get_count_program() {
    let hir = make_branch_refined_bound_ctx_get_then_call_program(
        CellPath {
            members: vec![string_member("optlen")],
        },
        CellPath {
            members: vec![string_member("optval")],
        },
        DeclId::new(42),
        DeclId::new(43),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");
    let decl_names = HashMap::from([
        (DeclId::new(42), "get".to_string()),
        (DeclId::new(43), "count".to_string()),
    ]);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect(
        "branch-refined cgroup_sockopt:get ctx.optval get/count should lower through attach flow",
    );

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized branch-refined cgroup_sockopt:get ctx.optval get/count should compile");
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_sk_skb_parser_ctx_priority_store_program() {
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::SkSkbParser,
        "/sys/fs/bpf/demo_sockmap",
        CellPath {
            members: vec![string_member("priority")],
        },
        HirLiteral::Int(3),
        HirLiteral::Int(0),
        "sk_skb_parser ctx.priority store",
    );
}

#[test]
fn test_compile_sk_skb_ctx_tc_index_store_program() {
    assert_ctx_path_store_program_compiles(
        EbpfProgramType::SkSkb,
        "/sys/fs/bpf/demo_sockmap",
        CellPath {
            members: vec![string_member("tc_index")],
        },
        HirLiteral::Int(7),
        HirLiteral::Int(0),
        "sk_skb ctx.tc_index store",
    );
}

#[test]
fn test_recover_optimized_type_hints_for_pointer_hop_trampoline_projection() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![
            string_member("arg0"),
            string_member("f_inode"),
            string_member("i_ino"),
        ],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("pointer-hop field projection should lower");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );
    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized pointer-hop field projection should compile");
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_recover_optimized_type_hints_for_struct_leaf_counter_schema() {
    let hir = make_ctx_path_call_program(
        CellPath {
            members: vec![string_member("arg0"), string_member("f_path")],
        },
        DeclId::new(42),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "count".to_string());

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("struct-leaf count should lower");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );
    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized struct-leaf count should compile");
    assert_eq!(
        result.bytes_counter_key_schema,
        Some(CounterKeySchema::Record {
            name: Some("path".to_string()),
            fields: vec![
                CounterKeySchemaField {
                    name: "mnt".to_string(),
                    schema: CounterKeySchema::Int {
                        size: 8,
                        signed: false,
                    },
                    offset: 0,
                    bitfield: None,
                },
                CounterKeySchemaField {
                    name: "dentry".to_string(),
                    schema: CounterKeySchema::Int {
                        size: 8,
                        signed: false,
                    },
                    offset: 8,
                    bitfield: None,
                },
            ],
            total_size: 16,
        })
    );
}

#[test]
fn test_compile_optimized_typed_map_get_projection() {
    let hir = make_map_put_get_projection_program(
        CellPath {
            members: vec![string_member("arg0"), string_member("f_path")],
        },
        DeclId::new(42),
        DeclId::new(43),
        DeclId::new(44),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "map-put".to_string());
    decl_names.insert(DeclId::new(43), "map-get".to_string());
    decl_names.insert(DeclId::new(44), "count".to_string());

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("typed map put/get projection should lower");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized typed map get projection should compile");

    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
    assert!(
        result.maps.iter().any(|map| map.name == "cached_path"),
        "expected generic map definition for cached_path"
    );
}

#[test]
fn test_compile_optimized_named_typed_map_get_projection() {
    let Some((function_name, arg_name, field_name)) =
        find_function_trampoline_named_struct_leaf_candidate()
    else {
        return;
    };

    let hir = make_map_put_get_projection_program(
        CellPath {
            members: vec![
                string_member("arg"),
                string_member(&arg_name),
                string_member(&field_name),
            ],
        },
        DeclId::new(42),
        DeclId::new(43),
        DeclId::new(44),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, &function_name);
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "map-put".to_string());
    decl_names.insert(DeclId::new(43), "map-get".to_string());
    decl_names.insert(DeclId::new(44), "count".to_string());

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("named typed map put/get projection should lower");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );
    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized named typed map get projection should compile");

    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
    assert!(
        result.maps.iter().any(|map| map.name == "cached_path"),
        "expected generic map definition for cached_path"
    );
}

#[test]
fn test_compile_optimized_queue_map_push_program() {
    let hir = make_map_push_program(DeclId::new(42), 1, "queue");
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let decl_names = HashMap::from([(DeclId::new(42), "map-push".to_string())]);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("queue map-push should lower through attach flow");

    assert!(
        lowering
            .type_hints
            .generic_map_value_types
            .contains_key(&MapRef {
                name: "recent_pids".to_string(),
                kind: MapKind::Queue,
            })
    );

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized queue map-push should compile");

    let map = result
        .maps
        .iter()
        .find(|map| map.name == "recent_pids")
        .expect("expected queue runtime map artifact");
    assert!(
        result
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == map.name)
    );
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_generic_map_put_specialized_kinds() {
    let decl_names = HashMap::from([(DeclId::new(42), "map-put".to_string())]);

    for (context, kind_arg, expected_kind, expected_def) in [
        (
            "per-cpu hash map-put",
            "per-cpu-hash",
            MapKind::PerCpuHash,
            BpfMapDef::per_cpu_hash(4, 16, 10240),
        ),
        (
            "lru hash map-put",
            "lru-hash",
            MapKind::LruHash,
            BpfMapDef::lru_hash(4, 16, 10240),
        ),
        (
            "lpm trie map-put",
            "lpm-trie",
            MapKind::LpmTrie,
            BpfMapDef::lpm_trie(4, 16, 10240),
        ),
        (
            "lru per-cpu hash map-put",
            "lru-per-cpu-hash",
            MapKind::LruPerCpuHash,
            BpfMapDef::lru_per_cpu_hash(4, 16, 10240),
        ),
    ] {
        let hir = make_map_put_program(DeclId::new(42), 1, kind_arg);
        let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");

        let mut lowering = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &decl_names,
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap_or_else(|err| panic!("{context} should lower through attach flow: {err}"));

        assert!(
            lowering
                .program
                .main
                .blocks
                .iter()
                .flat_map(|block| block.instructions.iter())
                .any(|inst| matches!(
                    inst,
                    MirInst::MapUpdate {
                        map: MapRef { name, kind },
                        flags,
                        ..
                    } if name == "cached_path" && *kind == expected_kind && *flags == 1
                )),
            "{context} should lower to a map update with the expected kind"
        );

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );

        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .unwrap_or_else(|err| panic!("optimized {context} should compile: {err}"));

        let map = result
            .maps
            .iter()
            .find(|map| map.name == "cached_path")
            .unwrap_or_else(|| panic!("{context} should emit cached_path map"));
        assert_eq!(map.def.map_type, expected_def.map_type);
        assert_eq!(map.def.key_size, expected_def.key_size);
        assert_eq!(map.def.value_size, expected_def.value_size);
        assert_eq!(map.def.max_entries, expected_def.max_entries);
        assert_eq!(map.def.map_flags, expected_def.map_flags);
        assert!(
            result
                .relocations
                .iter()
                .any(|reloc| reloc.symbol_name == map.name),
            "{context} should emit a map relocation"
        );
        assert!(!result.bytecode.is_empty(), "Should produce bytecode");
    }
}

#[test]
fn test_compile_generic_map_delete_lookup_kinds() {
    let decl_names = HashMap::from([(DeclId::new(42), "map-delete".to_string())]);

    for (context, kind_arg, expected_kind, expected_def) in [
        (
            "hash map-delete",
            "hash",
            MapKind::Hash,
            BpfMapDef::hash(4, 8, 10240),
        ),
        (
            "lpm trie map-delete",
            "lpm-trie",
            MapKind::LpmTrie,
            BpfMapDef::lpm_trie(4, 8, 10240),
        ),
        (
            "lru hash map-delete",
            "lru-hash",
            MapKind::LruHash,
            BpfMapDef::lru_hash(4, 8, 10240),
        ),
        (
            "per-cpu hash map-delete",
            "per-cpu-hash",
            MapKind::PerCpuHash,
            BpfMapDef::per_cpu_hash(4, 8, 10240),
        ),
        (
            "lru per-cpu hash map-delete",
            "lru-per-cpu-hash",
            MapKind::LruPerCpuHash,
            BpfMapDef::lru_per_cpu_hash(4, 8, 10240),
        ),
    ] {
        let hir = make_map_delete_program(DeclId::new(42), kind_arg);
        let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");

        let mut lowering = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &decl_names,
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap_or_else(|err| panic!("{context} should lower through attach flow: {err}"));

        assert!(
            lowering
                .program
                .main
                .blocks
                .iter()
                .flat_map(|block| block.instructions.iter())
                .any(|inst| matches!(
                    inst,
                    MirInst::MapDelete {
                        map: MapRef { name, kind },
                        ..
                    } if name == "cached_pids" && *kind == expected_kind
                )),
            "{context} should lower to a map delete with the expected kind"
        );

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );

        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .unwrap_or_else(|err| panic!("optimized {context} should compile: {err}"));

        let map = result
            .maps
            .iter()
            .find(|map| map.name == "cached_pids")
            .unwrap_or_else(|| panic!("{context} should emit cached_pids map"));
        assert_eq!(map.def.map_type, expected_def.map_type);
        assert_eq!(map.def.key_size, expected_def.key_size);
        assert_eq!(map.def.value_size, expected_def.value_size);
        assert_eq!(map.def.max_entries, expected_def.max_entries);
        assert_eq!(map.def.map_flags, expected_def.map_flags);
        assert!(
            result
                .relocations
                .iter()
                .any(|reloc| reloc.symbol_name == map.name),
            "{context} should emit a map relocation"
        );
        assert!(!result.bytecode.is_empty(), "Should produce bytecode");
    }
}

#[test]
fn test_compile_bloom_filter_map_push_program() {
    let hir = make_map_push_program(DeclId::new(42), 0, "bloom-filter");
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let decl_names = HashMap::from([(DeclId::new(42), "map-push".to_string())]);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("bloom-filter map-push should lower through attach flow");

    assert!(
        lowering
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::MapPush {
                    map: MapRef { name, kind },
                    ..
                } if name == "recent_pids" && *kind == MapKind::BloomFilter
            )),
        "expected bloom-filter map-push MIR instruction"
    );

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized bloom-filter map-push should compile");

    let map = result
        .maps
        .iter()
        .find(|map| map.name == "recent_pids")
        .expect("expected bloom-filter runtime map artifact");
    assert_eq!(map.def.key_size, 0);
    assert_eq!(map.def.value_size, 4);
    assert!(
        result
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == map.name)
    );
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_bloom_filter_map_contains_program() {
    let hir = make_bloom_filter_map_contains_program(DeclId::new(42));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let decl_names = HashMap::from([(DeclId::new(42), "map-contains".to_string())]);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("bloom-filter map-contains should lower through attach flow");

    assert!(
        lowering
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::LoadMapFd {
                    map: MapRef { name, kind },
                    ..
                } if name == "seen_pids" && *kind == MapKind::BloomFilter
            )),
        "expected bloom-filter map fd load"
    );
    assert!(
        lowering
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::CallHelper { helper, args, .. }
                    if *helper == BpfHelper::MapPeekElem as u32 && args.len() == 2
            )),
        "expected bloom-filter membership helper call"
    );

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized bloom-filter map-contains should compile");

    let map = result
        .maps
        .iter()
        .find(|map| map.name == "seen_pids")
        .expect("expected bloom-filter runtime map artifact");
    assert_eq!(map.def.key_size, 0);
    assert_eq!(map.def.value_size, 4);
    assert!(
        result
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == map.name)
    );
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_fentry_task_storage_map_get_program() {
    let hir = make_task_storage_map_get_program(DeclId::new(42));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let decl_names = HashMap::from([(DeclId::new(42), "map-get".to_string())]);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("task-storage map-get should lower through attach flow");

    assert!(
        lowering
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::LoadMapFd {
                    map: MapRef {
                        name,
                        kind: MapKind::TaskStorage,
                    },
                    ..
                } if name == "task_state"
            )),
        "expected task-storage map fd load"
    );
    assert!(
        lowering
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::CallHelper { helper, args, .. }
                    if *helper == BpfHelper::TaskStorageGet as u32
                        && args.len() == 4
                        && matches!(args[3], MirValue::Const(1))
            )),
        "expected task-storage get helper call with explicit flags"
    );
    assert!(matches!(
        lowering.type_hints.generic_map_value_types.get(&MapRef {
            name: "task_state".to_string(),
            kind: MapKind::TaskStorage,
        }),
        Some(MirType::Struct { fields, .. })
            if fields.len() == 1 && fields[0].name == "hits" && fields[0].ty == MirType::I64
    ));

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized task-storage map-get should compile");

    let map = result
        .maps
        .iter()
        .find(|map| map.name == "task_state")
        .expect("expected task-storage runtime map artifact");
    assert_eq!(map.def, BpfMapDef::task_storage(8));
    assert!(
        result
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == map.name)
    );
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_fentry_task_storage_map_delete_program() {
    let hir = make_task_storage_map_delete_program(DeclId::new(42));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let decl_names = HashMap::from([(DeclId::new(42), "map-delete".to_string())]);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("task-storage map-delete should lower through attach flow");

    assert!(
        lowering
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::LoadMapFd {
                    map: MapRef {
                        name,
                        kind: MapKind::TaskStorage,
                    },
                    ..
                } if name == "task_state"
            )),
        "expected task-storage map fd load"
    );
    assert!(
        lowering
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::CallHelper { helper, args, .. }
                    if *helper == BpfHelper::TaskStorageDelete as u32 && args.len() == 2
            )),
        "expected task-storage delete helper call"
    );

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized task-storage map-delete should compile");

    let map = result
        .maps
        .iter()
        .find(|map| map.name == "task_state")
        .expect("expected task-storage runtime map artifact");
    assert_eq!(map.def, BpfMapDef::task_storage(8));
    assert!(
        result
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == map.name)
    );
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_fentry_task_storage_map_contains_program() {
    let hir = make_task_storage_map_contains_program(DeclId::new(42));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let decl_names = HashMap::from([(DeclId::new(42), "map-contains".to_string())]);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("task-storage map-contains should lower through attach flow");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized task-storage map-contains should compile");

    let map = result
        .maps
        .iter()
        .find(|map| map.name == "task_state")
        .expect("expected task-storage runtime map artifact");
    assert_eq!(map.def.map_type, BpfMapDef::task_storage(8).map_type);
    assert!(
        result
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == map.name)
    );
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_tracepoint_current_task_storage_map_contains_program() {
    let hir = make_task_storage_map_contains_program_with_owner("current_task", DeclId::new(42));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tracepoint, "syscalls/sys_enter_openat");
    let decl_names = HashMap::from([(DeclId::new(42), "map-contains".to_string())]);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("current_task task-storage map-contains should lower through attach flow");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized current_task task-storage map-contains should compile");

    let map = result
        .maps
        .iter()
        .find(|map| map.name == "task_state")
        .expect("expected task-storage runtime map artifact");
    assert_eq!(map.def.map_type, BpfMapDef::task_storage(8).map_type);
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_cgroup_sock_sk_storage_map_get_program() {
    let hir = make_sk_storage_map_get_program(DeclId::new(42));
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:post_bind4");
    let decl_names = HashMap::from([(DeclId::new(42), "map-get".to_string())]);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sk-storage map-get should lower through attach flow");

    assert!(
        lowering
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::LoadMapFd {
                    map: MapRef {
                        name,
                        kind: MapKind::SkStorage,
                    },
                    ..
                } if name == "sock_state"
            )),
        "expected sk-storage map fd load"
    );
    assert!(
        lowering
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::CallHelper { helper, args, .. }
                    if *helper == BpfHelper::SkStorageGet as u32
                        && args.len() == 4
                        && matches!(args[3], MirValue::Const(1))
            )),
        "expected sk-storage get helper call with explicit flags"
    );
    assert!(matches!(
        lowering.type_hints.generic_map_value_types.get(&MapRef {
            name: "sock_state".to_string(),
            kind: MapKind::SkStorage,
        }),
        Some(MirType::Struct { fields, .. })
            if fields.len() == 1 && fields[0].name == "hits" && fields[0].ty == MirType::I64
    ));

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized sk-storage map-get should compile");

    let map = result
        .maps
        .iter()
        .find(|map| map.name == "sock_state")
        .expect("expected sk-storage runtime map artifact");
    assert_eq!(map.def, BpfMapDef::sk_storage(8));
    assert!(
        result
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == map.name)
    );
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_cgroup_sockopt_sk_storage_map_delete_program() {
    let hir = make_sk_storage_map_delete_program(DeclId::new(42));
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");
    let decl_names = HashMap::from([(DeclId::new(42), "map-delete".to_string())]);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sk-storage map-delete should lower through attach flow");

    assert!(
        lowering
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::LoadMapFd {
                    map: MapRef {
                        name,
                        kind: MapKind::SkStorage,
                    },
                    ..
                } if name == "sock_state"
            )),
        "expected sk-storage map fd load"
    );
    assert!(
        lowering
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::CallHelper { helper, args, .. }
                    if *helper == BpfHelper::SkStorageDelete as u32 && args.len() == 2
            )),
        "expected sk-storage delete helper call"
    );

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized sk-storage map-delete should compile");

    let map = result
        .maps
        .iter()
        .find(|map| map.name == "sock_state")
        .expect("expected sk-storage runtime map artifact");
    assert_eq!(map.def, BpfMapDef::sk_storage(8));
    assert!(
        result
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == map.name)
    );
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_cgroup_sock_sk_storage_map_contains_program() {
    let hir = make_sk_storage_map_contains_program(DeclId::new(42));
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:post_bind4");
    let decl_names = HashMap::from([(DeclId::new(42), "map-contains".to_string())]);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sk-storage map-contains should lower through attach flow");

    assert!(
        lowering
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::CallHelper { helper, args, .. }
                    if *helper == BpfHelper::SkStorageGet as u32
                        && args.len() == 4
                        && matches!(args[2], MirValue::Const(0))
                        && matches!(args[3], MirValue::Const(0))
            )),
        "expected lookup-only sk-storage get helper call"
    );

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized sk-storage map-contains should compile");

    let map = result
        .maps
        .iter()
        .find(|map| map.name == "sock_state")
        .expect("expected sk-storage runtime map artifact");
    assert_eq!(map.def.map_type, BpfMapDef::sk_storage(8).map_type);
    assert!(
        result
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == map.name)
    );
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

fn assert_kprobe_cgrp_storage_program_compiles(
    hir: HirProgram,
    decl_name: &str,
    context: &str,
    assert_exact_map_def: bool,
    check_lowering: impl FnOnce(&MirLoweringResult),
) {
    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let decl_names = HashMap::from([(DeclId::new(42), decl_name.to_string())]);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .unwrap_or_else(|err| panic!("{context} should lower through attach flow: {err:?}"));

    assert!(
        lowering
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::LoadMapFd {
                    map: MapRef {
                        name,
                        kind: MapKind::CgrpStorage,
                    },
                    ..
                } if name == "cgrp_state"
            )),
        "{context} should load cgrp-storage map fd"
    );
    check_lowering(&lowering);

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .unwrap_or_else(|err| panic!("optimized {context} should compile: {err:?}"));

    let map = result
        .maps
        .iter()
        .find(|map| map.name == "cgrp_state")
        .expect("expected cgrp-storage runtime map artifact");
    let expected_def = BpfMapDef::cgrp_storage(8);
    if assert_exact_map_def {
        assert_eq!(map.def, expected_def);
    } else {
        assert_eq!(map.def.map_type, expected_def.map_type);
    }
    assert!(
        result
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == map.name),
        "{context} should emit a map relocation"
    );
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

fn assert_cgrp_storage_value_type(lowering: &MirLoweringResult) {
    assert!(matches!(
        lowering.type_hints.generic_map_value_types.get(&MapRef {
            name: "cgrp_state".to_string(),
            kind: MapKind::CgrpStorage,
        }),
        Some(MirType::Struct { fields, .. })
            if fields.len() == 1 && fields[0].name == "hits" && fields[0].ty == MirType::I64
    ));
}

fn assert_cgrp_storage_owner_is_cgroup_ptr(lowering: &MirLoweringResult) {
    let cgroup_arg_ty = lowering
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::CallHelper { helper, args, .. }
                if *helper == BpfHelper::CgrpStorageGet as u32 =>
            {
                match args.get(1) {
                    Some(MirValue::VReg(vreg)) => lowering.type_hints.main.get(vreg),
                    _ => None,
                }
            }
            _ => None,
        });
    assert!(
        cgroup_arg_ty.is_some_and(MirType::is_cgroup_ptr),
        "expected cgrp-storage owner to type as cgroup pointer, got {:?}",
        cgroup_arg_ty
    );
}

fn assert_cgrp_storage_get_helper_call(lowering: &MirLoweringResult) {
    assert!(
        lowering
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::CallHelper { helper, args, .. }
                    if *helper == BpfHelper::CgrpStorageGet as u32
                        && args.len() == 4
                        && matches!(args[3], MirValue::Const(1))
            )),
        "expected cgrp-storage get helper call with explicit create flag"
    );
}

fn assert_cgrp_storage_delete_helper_call(lowering: &MirLoweringResult) {
    assert!(
        lowering
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::CallHelper { helper, args, .. }
                    if *helper == BpfHelper::CgrpStorageDelete as u32 && args.len() == 2
            )),
        "expected cgrp-storage delete helper call"
    );
}

fn assert_cgrp_storage_contains_helper_call(lowering: &MirLoweringResult) {
    assert!(
        lowering
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::CallHelper { helper, args, .. }
                    if *helper == BpfHelper::CgrpStorageGet as u32
                        && args.len() == 4
                        && matches!(args[2], MirValue::Const(0))
                        && matches!(args[3], MirValue::Const(0))
            )),
        "expected lookup-only cgrp-storage get helper call"
    );
}

#[test]
fn test_compile_kprobe_cgrp_storage_map_get_program() {
    let hir = make_cgrp_storage_map_get_program(DeclId::new(42));
    assert_kprobe_cgrp_storage_program_compiles(
        hir,
        "map-get",
        "cgrp-storage map-get",
        true,
        |lowering| {
            assert_cgrp_storage_get_helper_call(lowering);
            assert_cgrp_storage_owner_is_cgroup_ptr(lowering);
            assert_cgrp_storage_value_type(lowering);
        },
    );
}

#[test]
fn test_compile_kprobe_current_cgroup_storage_map_get_program() {
    let hir = make_cgrp_storage_map_get_program_with_owner(
        current_task_cgroup_alias_path(),
        DeclId::new(42),
    );
    assert_kprobe_cgrp_storage_program_compiles(
        hir,
        "map-get",
        "current_cgroup cgrp-storage map-get",
        true,
        |lowering| {
            assert_cgrp_storage_get_helper_call(lowering);
            assert_cgrp_storage_owner_is_cgroup_ptr(lowering);
            assert_cgrp_storage_value_type(lowering);
        },
    );
}

#[test]
fn test_compile_kprobe_cgrp_storage_map_delete_program() {
    let hir = make_cgrp_storage_map_delete_program(DeclId::new(42));
    assert_kprobe_cgrp_storage_program_compiles(
        hir,
        "map-delete",
        "cgrp-storage map-delete",
        true,
        assert_cgrp_storage_delete_helper_call,
    );
}

#[test]
fn test_compile_kprobe_current_cgroup_storage_map_delete_program() {
    let hir = make_cgrp_storage_map_delete_program_with_owner(
        current_task_cgroup_alias_path(),
        DeclId::new(42),
    );
    assert_kprobe_cgrp_storage_program_compiles(
        hir,
        "map-delete",
        "current_cgroup cgrp-storage map-delete",
        true,
        assert_cgrp_storage_delete_helper_call,
    );
}

#[test]
fn test_compile_kprobe_cgrp_storage_map_contains_program() {
    let hir = make_cgrp_storage_map_contains_program(DeclId::new(42));
    assert_kprobe_cgrp_storage_program_compiles(
        hir,
        "map-contains",
        "cgrp-storage map-contains",
        false,
        assert_cgrp_storage_contains_helper_call,
    );
}

#[test]
fn test_compile_kprobe_current_cgroup_storage_map_contains_program() {
    let hir = make_cgrp_storage_map_contains_program_with_owner(
        current_task_cgroup_alias_path(),
        DeclId::new(42),
    );
    assert_kprobe_cgrp_storage_program_compiles(
        hir,
        "map-contains",
        "current_cgroup cgrp-storage map-contains",
        false,
        assert_cgrp_storage_contains_helper_call,
    );
}

fn current_cgroup_kn_id_projection_available() -> bool {
    let projection_path = [
        TrampolineFieldSelector::Field("kn".to_string()),
        TrampolineFieldSelector::Field("id".to_string()),
    ];
    matches!(
        KernelBtf::get().kernel_named_type_field_projection("cgroup", &projection_path),
        Ok(projection) if matches!(projection.type_info, TypeInfo::Int { size: 8, .. })
    )
}

fn cgroup_kn_id_path(root: &str) -> CellPath {
    CellPath {
        members: vec![
            string_member(root),
            string_member("kn"),
            string_member("id"),
        ],
    }
}

fn current_cgroup_kn_id_path() -> CellPath {
    cgroup_kn_id_path("current_cgroup")
}

#[test]
fn test_compile_kprobe_current_cgroup_btf_projection_program() {
    if !current_cgroup_kn_id_projection_available() {
        return;
    }

    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Kprobe,
        "ksys_read",
        current_cgroup_kn_id_path(),
        "current_cgroup BTF field projection",
    );
}

#[test]
fn test_compile_tracepoint_current_cgroup_btf_projection_program() {
    if !current_cgroup_kn_id_projection_available() {
        return;
    }

    assert_ctx_path_count_program_compiles(
        EbpfProgramType::Tracepoint,
        "syscalls/sys_enter_openat",
        current_cgroup_kn_id_path(),
        "tracepoint current_cgroup BTF field projection",
    );
}

#[test]
fn test_compile_task_context_current_cgroup_btf_projection_programs() {
    if !current_cgroup_kn_id_projection_available() {
        return;
    }

    for (program_type, target, label) in representative_task_context_programs() {
        assert_ctx_path_count_program_compiles(
            program_type,
            target,
            current_cgroup_kn_id_path(),
            &format!("{label} current_cgroup BTF field projection"),
        );
    }
}

#[test]
fn test_compile_task_context_cgroup_alias_btf_projection_programs() {
    if !current_cgroup_kn_id_projection_available() {
        return;
    }

    for (program_type, target, label) in representative_task_context_programs_with_kprobe() {
        assert_ctx_path_count_program_compiles(
            program_type,
            target,
            cgroup_kn_id_path("cgroup"),
            &format!("{label} cgroup alias BTF field projection"),
        );
    }
}

#[test]
fn test_compile_kprobe_bound_current_cgroup_btf_projection_program() {
    if !current_cgroup_kn_id_projection_available() {
        return;
    }

    let hir = make_bound_ctx_path_program(
        CellPath {
            members: vec![string_member("current_cgroup")],
        },
        CellPath {
            members: vec![string_member("kn"), string_member("id")],
        },
    );
    assert_attach_program_compiles(
        &hir,
        EbpfProgramType::Kprobe,
        "ksys_read",
        &HashMap::new(),
        "bound current_cgroup BTF field projection",
    );
}

#[test]
fn test_compile_tracepoint_bound_current_cgroup_btf_projection_program() {
    if !current_cgroup_kn_id_projection_available() {
        return;
    }

    let hir = make_bound_ctx_path_program(
        CellPath {
            members: vec![string_member("current_cgroup")],
        },
        CellPath {
            members: vec![string_member("kn"), string_member("id")],
        },
    );
    assert_attach_program_compiles(
        &hir,
        EbpfProgramType::Tracepoint,
        "syscalls/sys_enter_openat",
        &HashMap::new(),
        "tracepoint bound current_cgroup BTF field projection",
    );
}

#[test]
fn test_compile_task_context_bound_current_cgroup_btf_projection_programs() {
    if !current_cgroup_kn_id_projection_available() {
        return;
    }

    for (program_type, target, label) in representative_task_context_programs() {
        let hir = make_bound_ctx_path_program(
            CellPath {
                members: vec![string_member("current_cgroup")],
            },
            CellPath {
                members: vec![string_member("kn"), string_member("id")],
            },
        );
        assert_attach_program_compiles(
            &hir,
            program_type,
            target,
            &HashMap::new(),
            &format!("{label} bound current_cgroup BTF field projection"),
        );
    }
}

#[test]
fn test_compile_task_context_bound_cgroup_alias_btf_projection_programs() {
    if !current_cgroup_kn_id_projection_available() {
        return;
    }

    for (program_type, target, label) in representative_task_context_programs_with_kprobe() {
        let hir = make_bound_ctx_path_program(
            CellPath {
                members: vec![string_member("cgroup")],
            },
            CellPath {
                members: vec![string_member("kn"), string_member("id")],
            },
        );
        assert_attach_program_compiles(
            &hir,
            program_type,
            target,
            &HashMap::new(),
            &format!("{label} bound cgroup alias BTF field projection"),
        );
    }
}

#[test]
fn test_compile_lsm_inode_storage_map_get_program() {
    let hir = make_inode_storage_map_get_program(DeclId::new(42));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Lsm, "file_open");
    let decl_names = HashMap::from([(DeclId::new(42), "map-get".to_string())]);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("inode-storage map-get should lower through attach flow");

    assert!(
        lowering
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::LoadMapFd {
                    map: MapRef {
                        name,
                        kind: MapKind::InodeStorage,
                    },
                    ..
                } if name == "inode_state"
            )),
        "expected inode-storage map fd load"
    );
    assert!(
        lowering
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::CallHelper { helper, args, .. }
                    if *helper == BpfHelper::InodeStorageGet as u32
                        && args.len() == 4
                        && matches!(args[3], MirValue::Const(1))
            )),
        "expected inode-storage get helper call with explicit flags"
    );
    let inode_arg_ty = lowering
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::CallHelper { helper, args, .. }
                if *helper == BpfHelper::InodeStorageGet as u32 =>
            {
                match args.get(1) {
                    Some(MirValue::VReg(vreg)) => lowering.type_hints.main.get(vreg),
                    _ => None,
                }
            }
            _ => None,
        });
    assert!(
        inode_arg_ty.is_some_and(MirType::is_inode_ptr),
        "expected inode-storage owner to type as inode pointer, got {:?}",
        inode_arg_ty
    );
    assert!(
        !lowering
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::CallHelper { helper, .. }
                    if *helper == BpfHelper::ProbeReadKernel as u32
            )),
        "inode-storage owner should preserve trusted BTF pointer provenance without probe_read"
    );
    assert!(matches!(
        lowering.type_hints.generic_map_value_types.get(&MapRef {
            name: "inode_state".to_string(),
            kind: MapKind::InodeStorage,
        }),
        Some(MirType::Struct { fields, .. })
            if fields.len() == 1 && fields[0].name == "hits" && fields[0].ty == MirType::I64
    ));

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized inode-storage map-get should compile");

    let map = result
        .maps
        .iter()
        .find(|map| map.name == "inode_state")
        .expect("expected inode-storage runtime map artifact");
    assert_eq!(map.def, BpfMapDef::inode_storage(8));
    assert!(
        result
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == map.name)
    );
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_lsm_inode_storage_map_delete_program() {
    let hir = make_inode_storage_map_delete_program(DeclId::new(42));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Lsm, "file_open");
    let decl_names = HashMap::from([(DeclId::new(42), "map-delete".to_string())]);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("inode-storage map-delete should lower through attach flow");

    assert!(
        lowering
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::LoadMapFd {
                    map: MapRef {
                        name,
                        kind: MapKind::InodeStorage,
                    },
                    ..
                } if name == "inode_state"
            )),
        "expected inode-storage map fd load"
    );
    assert!(
        lowering
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::CallHelper { helper, args, .. }
                    if *helper == BpfHelper::InodeStorageDelete as u32 && args.len() == 2
            )),
        "expected inode-storage delete helper call"
    );

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized inode-storage map-delete should compile");

    let map = result
        .maps
        .iter()
        .find(|map| map.name == "inode_state")
        .expect("expected inode-storage runtime map artifact");
    assert_eq!(map.def, BpfMapDef::inode_storage(8));
    assert!(
        result
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == map.name)
    );
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_lsm_inode_storage_map_contains_program() {
    let hir = make_inode_storage_map_contains_program(DeclId::new(42));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Lsm, "file_open");
    let decl_names = HashMap::from([(DeclId::new(42), "map-contains".to_string())]);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("inode-storage map-contains should lower through attach flow");

    assert!(
        lowering
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::CallHelper { helper, args, .. }
                    if *helper == BpfHelper::InodeStorageGet as u32
                        && args.len() == 4
                        && matches!(args[2], MirValue::Const(0))
                        && matches!(args[3], MirValue::Const(0))
            )),
        "expected lookup-only inode-storage get helper call"
    );

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized inode-storage map-contains should compile");

    let map = result
        .maps
        .iter()
        .find(|map| map.name == "inode_state")
        .expect("expected inode-storage runtime map artifact");
    assert_eq!(map.def.map_type, BpfMapDef::inode_storage(8).map_type);
    assert!(
        result
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == map.name)
    );
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_kprobe_hash_map_contains_program() {
    let hir = make_hash_map_contains_program(DeclId::new(42));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let decl_names = HashMap::from([(DeclId::new(42), "map-contains".to_string())]);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("hash map-contains should lower through attach flow");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized hash map-contains should compile");

    let map = result
        .maps
        .iter()
        .find(|map| map.name == "seen_pids")
        .expect("expected hash runtime map artifact");
    assert_eq!(map.def.map_type, BpfMapDef::hash(8, 1, 1024).map_type);
    assert!(
        result
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == map.name)
    );
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_generic_map_contains_lookup_kinds() {
    let decl_names = HashMap::from([(DeclId::new(42), "map-contains".to_string())]);

    for (context, kind_arg, expected_kind, expected_def) in [
        (
            "hash map-contains",
            "hash",
            MapKind::Hash,
            BpfMapDef::hash(4, 1, 10240),
        ),
        (
            "array map-contains",
            "array",
            MapKind::Array,
            BpfMapDef::array(1, 10240),
        ),
        (
            "lpm trie map-contains",
            "lpm-trie",
            MapKind::LpmTrie,
            BpfMapDef::lpm_trie(4, 1, 10240),
        ),
        (
            "lru hash map-contains",
            "lru-hash",
            MapKind::LruHash,
            BpfMapDef::lru_hash(4, 1, 10240),
        ),
        (
            "per-cpu hash map-contains",
            "per-cpu-hash",
            MapKind::PerCpuHash,
            BpfMapDef::per_cpu_hash(4, 1, 10240),
        ),
        (
            "per-cpu array map-contains",
            "per-cpu-array",
            MapKind::PerCpuArray,
            BpfMapDef::per_cpu_array(1, 10240),
        ),
        (
            "lru per-cpu hash map-contains",
            "lru-per-cpu-hash",
            MapKind::LruPerCpuHash,
            BpfMapDef::lru_per_cpu_hash(4, 1, 10240),
        ),
    ] {
        let hir = make_generic_map_contains_program(DeclId::new(42), kind_arg);
        let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");

        let mut lowering = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &decl_names,
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap_or_else(|err| panic!("{context} should lower through attach flow: {err}"));

        assert!(
            lowering
                .program
                .main
                .blocks
                .iter()
                .flat_map(|block| block.instructions.iter())
                .any(|inst| matches!(
                    inst,
                    MirInst::MapLookup {
                        map: MapRef { name, kind },
                        ..
                    } if name == "seen_pids" && *kind == expected_kind
                )),
            "{context} should lower to a map lookup with the expected kind"
        );

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );

        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .unwrap_or_else(|err| panic!("optimized {context} should compile: {err}"));

        let map = result
            .maps
            .iter()
            .find(|map| map.name == "seen_pids")
            .unwrap_or_else(|| panic!("{context} should emit seen_pids map"));
        assert_eq!(map.def.map_type, expected_def.map_type);
        assert_eq!(map.def.key_size, expected_def.key_size);
        assert_eq!(map.def.value_size, expected_def.value_size);
        assert_eq!(map.def.max_entries, expected_def.max_entries);
        assert_eq!(map.def.map_flags, expected_def.map_flags);
        assert!(
            result
                .relocations
                .iter()
                .any(|reloc| reloc.symbol_name == map.name),
            "{context} should emit a map relocation"
        );
        assert!(!result.bytecode.is_empty(), "Should produce bytecode");
    }
}

#[test]
fn test_compile_tc_cgroup_array_map_contains_program() {
    let hir = make_cgroup_array_map_contains_program(DeclId::new(42));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let decl_names = HashMap::from([(DeclId::new(42), "map-contains".to_string())]);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("tc cgroup-array map-contains should lower through attach flow");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized tc cgroup-array map-contains should compile");

    assert!(
        result.maps.iter().any(|map| map.name == "tracked_cgroups"),
        "expected cgroup-array runtime map artifact"
    );
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_tc_action_cgroup_array_map_contains_program() {
    let hir = make_cgroup_array_map_contains_program(DeclId::new(42));
    let probe_ctx = ProbeContext::new(EbpfProgramType::TcAction, "demo-action");
    let decl_names = HashMap::from([(DeclId::new(42), "map-contains".to_string())]);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("tc_action cgroup-array map-contains should lower through attach flow");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized tc_action cgroup-array map-contains should compile");

    assert!(
        result.maps.iter().any(|map| map.name == "tracked_cgroups"),
        "expected cgroup-array runtime map artifact"
    );
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_lwt_cgroup_array_map_contains_program() {
    let hir = make_cgroup_array_map_contains_program(DeclId::new(42));
    let probe_ctx = ProbeContext::new(EbpfProgramType::LwtOut, "demo-route");
    let decl_names = HashMap::from([(DeclId::new(42), "map-contains".to_string())]);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("lwt cgroup-array map-contains should lower through attach flow");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized lwt cgroup-array map-contains should compile");

    assert!(
        result.maps.iter().any(|map| map.name == "tracked_cgroups"),
        "expected cgroup-array runtime map artifact"
    );
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_kprobe_cgroup_array_map_contains_program() {
    let hir = make_cgroup_array_map_contains_program(DeclId::new(42));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let decl_names = HashMap::from([(DeclId::new(42), "map-contains".to_string())]);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("kprobe cgroup-array map-contains should lower through attach flow");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized kprobe cgroup-array map-contains should compile");

    assert!(
        result.maps.iter().any(|map| map.name == "tracked_cgroups"),
        "expected cgroup-array runtime map artifact"
    );
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_xdp_cgroup_array_map_contains_program() {
    let hir = make_cgroup_array_map_contains_program(DeclId::new(42));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let decl_names = HashMap::from([(DeclId::new(42), "map-contains".to_string())]);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("xdp cgroup-array map-contains should lower through attach flow");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized xdp cgroup-array map-contains should compile");

    assert!(
        result.maps.iter().any(|map| map.name == "tracked_cgroups"),
        "expected cgroup-array runtime map artifact"
    );
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

fn assert_cgroup_array_map_contains_program_uses_helper(
    program_type: EbpfProgramType,
    target: &str,
    context: &str,
    expected_helper: BpfHelper,
    expected_arg_count: usize,
) {
    let hir = make_cgroup_array_map_contains_program(DeclId::new(42));
    let probe_ctx = ProbeContext::new(program_type, target);
    let decl_names = HashMap::from([(DeclId::new(42), "map-contains".to_string())]);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .unwrap_or_else(|err| panic!("{context} should lower through attach flow: {err}"));

    let expected_helper_id = expected_helper as u32;
    assert!(
        lowering
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::CallHelper { helper, args, .. }
                    if *helper == expected_helper_id && args.len() == expected_arg_count
            )),
        "{context} should lower through the expected cgroup-array membership helper"
    );

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .unwrap_or_else(|err| panic!("optimized {context} should compile: {err}"));

    assert!(
        result.maps.iter().any(|map| map.name == "tracked_cgroups"),
        "{context} should emit the cgroup-array runtime map artifact"
    );
    assert!(
        !result.bytecode.is_empty(),
        "{context} should produce bytecode"
    );
}

#[test]
fn test_compile_tcx_netkit_cgroup_array_map_contains_programs() {
    for (program_type, target, context) in [
        (
            EbpfProgramType::Tcx,
            "lo:ingress",
            "tcx cgroup-array map-contains",
        ),
        (
            EbpfProgramType::Netkit,
            "nk0:primary",
            "netkit cgroup-array map-contains",
        ),
    ] {
        assert_cgroup_array_map_contains_program_uses_helper(
            program_type,
            target,
            context,
            BpfHelper::SkbUnderCgroup,
            3,
        );
    }
}

#[test]
fn test_compile_task_context_cgroup_array_map_contains_programs() {
    for (program_type, target, label) in representative_task_context_programs() {
        assert_cgroup_array_map_contains_program_uses_helper(
            program_type,
            target,
            &format!("{label} cgroup-array map-contains"),
            BpfHelper::CurrentTaskUnderCgroup,
            2,
        );
    }
}

#[test]
fn test_compile_optimized_queue_map_peek_count_program() {
    let hir = make_seeded_map_take_count_program(
        DeclId::new(42),
        DeclId::new(43),
        DeclId::new(44),
        "queue",
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let decl_names = HashMap::from([
        (DeclId::new(42), "map-push".to_string()),
        (DeclId::new(43), "map-peek".to_string()),
        (DeclId::new(44), "count".to_string()),
    ]);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("queue map-peek count should lower through attach flow");

    assert!(
        lowering
            .type_hints
            .generic_map_value_types
            .contains_key(&MapRef {
                name: "recent_pids".to_string(),
                kind: MapKind::Queue,
            })
    );

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized queue map-peek count should compile");

    let map = result
        .maps
        .iter()
        .find(|map| map.name == "recent_pids")
        .expect("expected queue runtime map artifact");
    assert!(
        result
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == map.name)
    );
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_optimized_stack_map_pop_count_program() {
    let hir = make_seeded_map_take_count_program(
        DeclId::new(42),
        DeclId::new(43),
        DeclId::new(44),
        "stack",
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let decl_names = HashMap::from([
        (DeclId::new(42), "map-push".to_string()),
        (DeclId::new(43), "map-pop".to_string()),
        (DeclId::new(44), "count".to_string()),
    ]);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("stack map-pop count should lower through attach flow");

    assert!(
        lowering
            .type_hints
            .generic_map_value_types
            .contains_key(&MapRef {
                name: "recent_pids".to_string(),
                kind: MapKind::Stack,
            })
    );

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized stack map-pop count should compile");

    let map = result
        .maps
        .iter()
        .find(|map| map.name == "recent_pids")
        .expect("expected stack runtime map artifact");
    assert!(
        result
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == map.name)
    );
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_optimized_cgroup_sysctl_queue_map_peek_count_program() {
    let hir = make_ctx_seeded_map_take_count_return_program(
        CellPath {
            members: vec![string_member("write")],
        },
        DeclId::new(42),
        DeclId::new(43),
        DeclId::new(44),
        "queue",
        "recent_values",
        HirLiteral::Int(1),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSysctl, "/sys/fs/cgroup");
    let decl_names = HashMap::from([
        (DeclId::new(42), "map-push".to_string()),
        (DeclId::new(43), "map-peek".to_string()),
        (DeclId::new(44), "count".to_string()),
    ]);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sysctl queue map-peek count should lower through attach flow");

    assert!(
        lowering
            .type_hints
            .generic_map_value_types
            .contains_key(&MapRef {
                name: "recent_values".to_string(),
                kind: MapKind::Queue,
            })
    );

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized cgroup_sysctl queue map-peek count should compile");

    let map = result
        .maps
        .iter()
        .find(|map| map.name == "recent_values")
        .expect("expected queue runtime map artifact");
    assert!(
        result
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == map.name)
    );
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_optimized_sock_ops_stack_map_pop_count_program() {
    let hir = make_ctx_seeded_map_take_count_return_program(
        CellPath {
            members: vec![string_member("op")],
        },
        DeclId::new(42),
        DeclId::new(43),
        DeclId::new(44),
        "stack",
        "recent_values",
        HirLiteral::Int(1),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
    let decl_names = HashMap::from([
        (DeclId::new(42), "map-push".to_string()),
        (DeclId::new(43), "map-pop".to_string()),
        (DeclId::new(44), "count".to_string()),
    ]);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sock_ops stack map-pop count should lower through attach flow");

    assert!(
        lowering
            .type_hints
            .generic_map_value_types
            .contains_key(&MapRef {
                name: "recent_values".to_string(),
                kind: MapKind::Stack,
            })
    );

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized sock_ops stack map-pop count should compile");

    let map = result
        .maps
        .iter()
        .find(|map| map.name == "recent_values")
        .expect("expected stack runtime map artifact");
    assert!(
        result
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == map.name)
    );
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_xdp_typed_global_define_type_int_program() {
    let hir = make_typed_global_define_count_program(
        DeclId::new(40),
        DeclId::new(41),
        DeclId::new(42),
        "int",
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let decl_names = HashMap::from([
        (DeclId::new(40), "global-define".to_string()),
        (DeclId::new(41), "global-get".to_string()),
        (DeclId::new(42), "count".to_string()),
    ]);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("typed global-define int alias should lower through attach flow");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("typed global-define int alias should compile through attach flow");

    assert!(
        !result.bytecode.is_empty(),
        "typed global-define int alias should produce bytecode"
    );
}

#[test]
fn test_compile_xdp_typed_global_define_type_list_int_program() {
    let hir = make_typed_global_define_list_get_count_program(
        DeclId::new(40),
        DeclId::new(41),
        DeclId::new(42),
        "list:int:4",
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let decl_names = HashMap::from([
        (DeclId::new(40), "global-define".to_string()),
        (DeclId::new(41), "global-get".to_string()),
        (DeclId::new(42), "count".to_string()),
    ]);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("typed global-define list:int alias should lower through attach flow");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("typed global-define list:int alias should compile through attach flow");

    assert!(
        !result.bytecode.is_empty(),
        "typed global-define list:int alias should produce bytecode"
    );
}

#[test]
fn test_compile_xdp_typed_global_define_type_fixed_array_program() {
    let hir = make_typed_global_define_list_get_count_program(
        DeclId::new(40),
        DeclId::new(41),
        DeclId::new(42),
        "array{u32:4}",
    );
    let decl_names = HashMap::from([
        (DeclId::new(40), "global-define".to_string()),
        (DeclId::new(41), "global-get".to_string()),
        (DeclId::new(42), "count".to_string()),
    ]);

    assert_attach_program_compiles(
        &hir,
        EbpfProgramType::Xdp,
        "lo",
        &decl_names,
        "typed global-define fixed array should compile through attach flow",
    );
}

#[test]
fn test_compile_xdp_typed_global_define_type_fixed_record_array_program() {
    let hir = make_typed_global_define_record_array_field_count_program(
        DeclId::new(40),
        DeclId::new(41),
        DeclId::new(42),
    );
    let decl_names = HashMap::from([
        (DeclId::new(40), "global-define".to_string()),
        (DeclId::new(41), "global-get".to_string()),
        (DeclId::new(42), "count".to_string()),
    ]);

    assert_attach_program_compiles(
        &hir,
        EbpfProgramType::Xdp,
        "lo",
        &decl_names,
        "typed global-define fixed record array should compile through attach flow",
    );
}

#[test]
fn test_compile_xdp_typed_global_define_type_fixed_record_array_initializer_program() {
    let hir = make_typed_global_define_record_array_initializer_field_count_program(
        DeclId::new(40),
        DeclId::new(41),
        DeclId::new(42),
    );
    let decl_names = HashMap::from([
        (DeclId::new(40), "global-define".to_string()),
        (DeclId::new(41), "global-get".to_string()),
        (DeclId::new(42), "count".to_string()),
    ]);

    assert_attach_program_compiles(
        &hir,
        EbpfProgramType::Xdp,
        "lo",
        &decl_names,
        "typed global-define initialized fixed record array should compile through attach flow",
    );
}

#[test]
fn test_compile_xdp_typed_global_define_type_nested_fixed_record_array_initializer_program() {
    let hir = make_typed_global_define_record_with_record_array_initializer_field_count_program(
        DeclId::new(40),
        DeclId::new(41),
        DeclId::new(42),
    );
    let decl_names = HashMap::from([
        (DeclId::new(40), "global-define".to_string()),
        (DeclId::new(41), "global-get".to_string()),
        (DeclId::new(42), "count".to_string()),
    ]);

    assert_attach_program_compiles(
        &hir,
        EbpfProgramType::Xdp,
        "lo",
        &decl_names,
        "typed global-define nested initialized fixed record array should compile through attach flow",
    );
}

#[test]
fn test_compile_xdp_annotated_mut_int_count_program() {
    let hir = make_annotated_mut_int_count_program(DeclId::new(42));
    let decl_names = HashMap::from([(DeclId::new(42), "count".to_string())]);

    assert_attach_program_compiles(
        &hir,
        EbpfProgramType::Xdp,
        "lo",
        &decl_names,
        "annotated mut int should compile through attach flow",
    );
}

#[test]
fn test_compile_xdp_annotated_mut_record_list_get_count_program() {
    let hir = make_annotated_mut_record_list_get_count_program(DeclId::new(41), DeclId::new(42));
    let decl_names = HashMap::from([
        (DeclId::new(41), "get".to_string()),
        (DeclId::new(42), "count".to_string()),
    ]);

    assert_attach_program_compiles(
        &hir,
        EbpfProgramType::Xdp,
        "lo",
        &decl_names,
        "annotated mut record list field get/count should compile through attach flow",
    );
}

#[test]
fn test_compile_xdp_annotated_mut_fixed_record_array_field_count_program() {
    let hir =
        make_annotated_mut_fixed_record_array_field_count_program(DeclId::new(41), DeclId::new(42));
    let decl_names = HashMap::from([
        (DeclId::new(41), "get".to_string()),
        (DeclId::new(42), "count".to_string()),
    ]);

    assert_attach_program_compiles(
        &hir,
        EbpfProgramType::Xdp,
        "lo",
        &decl_names,
        "annotated mut fixed record array field count should compile through attach flow",
    );
}

#[test]
fn test_compile_xdp_annotated_mut_record_with_fixed_record_array_field_count_program() {
    let hir =
        make_annotated_mut_record_with_fixed_record_array_field_count_program(DeclId::new(42));
    let decl_names = HashMap::from([(DeclId::new(42), "count".to_string())]);

    assert_attach_program_compiles(
        &hir,
        EbpfProgramType::Xdp,
        "lo",
        &decl_names,
        "annotated mut nested fixed record array field count should compile through attach flow",
    );
}

#[test]
fn test_compile_xdp_bounded_list_iterate_count_program() {
    let hir = make_list_iterate_count_program(DeclId::new(42));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let decl_names = HashMap::from([(DeclId::new(42), "count".to_string())]);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("bounded list iterate count should lower through attach flow");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("bounded list iterate count should compile through attach flow");

    assert!(
        !result.bytecode.is_empty(),
        "bounded list iterate count should produce bytecode"
    );
}

#[test]
fn test_optimize_xdp_bounded_list_iterate_count_program_lowers_all_list_ops() {
    let hir = make_list_iterate_count_program(DeclId::new(42));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let decl_names = HashMap::from([(DeclId::new(42), "count".to_string())]);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("bounded list iterate count should lower through attach flow");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let cfg = crate::compiler::cfg::CFG::build(&lowering.program.main);
    let pass = ListLowering;
    let _ = pass.run(&mut lowering.program.main, &cfg);

    let remaining: Vec<_> = lowering
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| {
            block
                .instructions
                .iter()
                .chain(std::iter::once(&block.terminator))
        })
        .filter(|inst| {
            matches!(
                inst,
                MirInst::ListNew { .. }
                    | MirInst::ListPush { .. }
                    | MirInst::ListLen { .. }
                    | MirInst::ListGet { .. }
            )
        })
        .cloned()
        .collect();

    assert!(
        remaining.is_empty(),
        "expected no list ops after list lowering, found {remaining:?} in blocks {:?}",
        lowering.program.main.blocks
    );
}

#[test]
fn test_compile_cgroup_sock_addr_nullable_socket_branch_program() {
    let hir = make_cgroup_sock_addr_nullable_socket_branch_program(DeclId::new(42));
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "connect4");
    let decl_names = HashMap::from([(DeclId::new(42), "count".to_string())]);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("nullable cgroup_sock_addr ctx.sk branch should lower through attach flow");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("nullable cgroup_sock_addr ctx.sk branch should compile through attach flow");

    assert!(
        !result.bytecode.is_empty(),
        "nullable cgroup_sock_addr ctx.sk branch should produce bytecode"
    );
}

#[test]
fn test_compile_xdp_descending_range_iterate_count_program() {
    let hir = make_descending_range_iterate_count_program(DeclId::new(42));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let decl_names = HashMap::from([(DeclId::new(42), "count".to_string())]);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("descending range iterate count should lower through attach flow");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("descending range iterate count should compile through attach flow");

    assert!(
        !result.bytecode.is_empty(),
        "descending range iterate count should produce bytecode"
    );
}

#[test]
fn test_compile_sk_lookup_socket_src_ip6_iterate_count_program() {
    let hir = make_ctx_iterate_count_program(
        CellPath {
            members: vec![string_member("sk"), string_member("src_ip6")],
        },
        DeclId::new(42),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");
    let decl_names = HashMap::from([(DeclId::new(42), "count".to_string())]);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sk_lookup ctx.sk.src_ip6 iterate/count should lower through attach flow");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("sk_lookup ctx.sk.src_ip6 iterate/count should compile through attach flow");

    assert!(
        !result.bytecode.is_empty(),
        "sk_lookup ctx.sk.src_ip6 iterate/count should produce bytecode"
    );
}

#[test]
fn test_compile_sk_lookup_assign_socket_null_program() {
    let hir = make_intrinsic_call_return_program(
        DeclId::new(42),
        vec![HirLiteral::Int(0)],
        vec![],
        vec![b"replace".to_vec()],
        HirLiteral::Int(1),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");
    let decl_names = HashMap::from([(DeclId::new(42), "assign-socket".to_string())]);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sk_lookup assign-socket null should lower through attach flow");

    let block = lowering.program.main.block(lowering.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::CallHelper {
            helper,
            args,
            ..
        } if *helper == BpfHelper::SkAssign as u32
            && args.len() == 3
            && matches!(args.get(2), Some(crate::compiler::mir::MirValue::Const(1)))
    )));

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("sk_lookup assign-socket null should compile through attach flow");

    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_sk_lookup_ctx_sk_assignment_null_program() {
    for field_name in ["sk", "sock", "socket"] {
        let hir = make_ctx_path_store_program(
            CellPath {
                members: vec![string_member(field_name)],
            },
            HirLiteral::Int(0),
            HirLiteral::Int(1),
        );
        let probe_ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");

        let mut lowering = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &HashMap::new(),
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap_or_else(|err| {
            panic!(
                "sk_lookup ctx.{field_name} assignment null should lower through attach flow: {err}"
            )
        });

        let block = lowering.program.main.block(lowering.program.main.entry);
        assert!(block.instructions.iter().any(|inst| matches!(
            inst,
            MirInst::CallHelper {
                helper,
                args,
                ..
            } if *helper == BpfHelper::SkAssign as u32
                && args.len() == 3
                && matches!(args.get(2), Some(crate::compiler::mir::MirValue::Const(0)))
        )));

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );

        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .unwrap_or_else(|err| {
            panic!("sk_lookup ctx.{field_name} assignment null should compile through attach flow: {err}")
        });

        assert!(
            !result.bytecode.is_empty(),
            "ctx.{field_name} assignment should produce bytecode"
        );
    }
}

#[test]
fn test_compile_packet_intrinsic_programs() {
    for (context, command_name, program_type, target, positional, flags, return_value, expected) in [
        (
            "xdp adjust-packet --meta",
            "adjust-packet",
            EbpfProgramType::Xdp,
            "lo",
            vec![HirLiteral::Int(-4)],
            vec![b"meta".to_vec()],
            HirLiteral::Int(2),
            ExpectedHelperCall {
                helper: BpfHelper::XdpAdjustMeta,
                arg_count: 2,
                const_args: &[],
            },
        ),
        (
            "lwt adjust-packet --pull",
            "adjust-packet",
            EbpfProgramType::LwtOut,
            "demo-route",
            vec![HirLiteral::Int(64)],
            vec![b"pull".to_vec()],
            HirLiteral::Int(2),
            ExpectedHelperCall {
                helper: BpfHelper::SkbPullData,
                arg_count: 2,
                const_args: &[],
            },
        ),
        (
            "lwt_xmit adjust-packet --head",
            "adjust-packet",
            EbpfProgramType::LwtXmit,
            "demo-route",
            vec![HirLiteral::Int(8)],
            vec![b"head".to_vec()],
            HirLiteral::Int(0),
            ExpectedHelperCall {
                helper: BpfHelper::SkbChangeHead,
                arg_count: 3,
                const_args: &[(2, 0)],
            },
        ),
        (
            "tc_action adjust-packet --head",
            "adjust-packet",
            EbpfProgramType::TcAction,
            "demo-action",
            vec![HirLiteral::Int(8)],
            vec![b"head".to_vec()],
            HirLiteral::Int(0),
            ExpectedHelperCall {
                helper: BpfHelper::SkbChangeHead,
                arg_count: 3,
                const_args: &[(2, 0)],
            },
        ),
        (
            "tcx adjust-packet --head",
            "adjust-packet",
            EbpfProgramType::Tcx,
            "lo:ingress",
            vec![HirLiteral::Int(8)],
            vec![b"head".to_vec()],
            HirLiteral::Int(0),
            ExpectedHelperCall {
                helper: BpfHelper::SkbChangeHead,
                arg_count: 3,
                const_args: &[(2, 0)],
            },
        ),
        (
            "netkit adjust-packet --head",
            "adjust-packet",
            EbpfProgramType::Netkit,
            "nk0:primary",
            vec![HirLiteral::Int(8)],
            vec![b"head".to_vec()],
            HirLiteral::Int(0),
            ExpectedHelperCall {
                helper: BpfHelper::SkbChangeHead,
                arg_count: 3,
                const_args: &[(2, 0)],
            },
        ),
        (
            "tc redirect --peer",
            "redirect",
            EbpfProgramType::Tc,
            "lo:ingress",
            vec![HirLiteral::Int(9)],
            vec![b"peer".to_vec()],
            HirLiteral::Int(0),
            ExpectedHelperCall {
                helper: BpfHelper::RedirectPeer,
                arg_count: 2,
                const_args: &[(1, 0)],
            },
        ),
        (
            "tcx redirect --peer",
            "redirect",
            EbpfProgramType::Tcx,
            "lo:ingress",
            vec![HirLiteral::Int(9)],
            vec![b"peer".to_vec()],
            HirLiteral::Int(0),
            ExpectedHelperCall {
                helper: BpfHelper::RedirectPeer,
                arg_count: 2,
                const_args: &[(1, 0)],
            },
        ),
        (
            "tcx redirect --neigh",
            "redirect",
            EbpfProgramType::Tcx,
            "lo:ingress",
            vec![HirLiteral::Int(9)],
            vec![b"neigh".to_vec()],
            HirLiteral::Int(0),
            ExpectedHelperCall {
                helper: BpfHelper::RedirectNeigh,
                arg_count: 4,
                const_args: &[(1, 0), (2, 0), (3, 0)],
            },
        ),
        (
            "lwt_xmit redirect",
            "redirect",
            EbpfProgramType::LwtXmit,
            "demo-route",
            vec![HirLiteral::Int(9)],
            vec![],
            HirLiteral::Int(0),
            ExpectedHelperCall {
                helper: BpfHelper::Redirect,
                arg_count: 2,
                const_args: &[(1, 0)],
            },
        ),
        (
            "tc_action redirect",
            "redirect",
            EbpfProgramType::TcAction,
            "demo-action",
            vec![HirLiteral::Int(9)],
            vec![],
            HirLiteral::Int(0),
            ExpectedHelperCall {
                helper: BpfHelper::Redirect,
                arg_count: 2,
                const_args: &[(1, 0)],
            },
        ),
        (
            "tc_action redirect --peer",
            "redirect",
            EbpfProgramType::TcAction,
            "demo-action",
            vec![HirLiteral::Int(9)],
            vec![b"peer".to_vec()],
            HirLiteral::Int(0),
            ExpectedHelperCall {
                helper: BpfHelper::RedirectPeer,
                arg_count: 2,
                const_args: &[(1, 0)],
            },
        ),
        (
            "tc_action redirect --neigh",
            "redirect",
            EbpfProgramType::TcAction,
            "demo-action",
            vec![HirLiteral::Int(9)],
            vec![b"neigh".to_vec()],
            HirLiteral::Int(0),
            ExpectedHelperCall {
                helper: BpfHelper::RedirectNeigh,
                arg_count: 4,
                const_args: &[(1, 0), (2, 0), (3, 0)],
            },
        ),
        (
            "netkit redirect",
            "redirect",
            EbpfProgramType::Netkit,
            "nk0:primary",
            vec![HirLiteral::Int(9)],
            vec![],
            HirLiteral::Int(0),
            ExpectedHelperCall {
                helper: BpfHelper::Redirect,
                arg_count: 2,
                const_args: &[(1, 0)],
            },
        ),
        (
            "netkit redirect --peer",
            "redirect",
            EbpfProgramType::Netkit,
            "nk0:primary",
            vec![HirLiteral::Int(9)],
            vec![b"peer".to_vec()],
            HirLiteral::Int(0),
            ExpectedHelperCall {
                helper: BpfHelper::RedirectPeer,
                arg_count: 2,
                const_args: &[(1, 0)],
            },
        ),
        (
            "netkit redirect --neigh",
            "redirect",
            EbpfProgramType::Netkit,
            "nk0:primary",
            vec![HirLiteral::Int(9)],
            vec![b"neigh".to_vec()],
            HirLiteral::Int(0),
            ExpectedHelperCall {
                helper: BpfHelper::RedirectNeigh,
                arg_count: 4,
                const_args: &[(1, 0), (2, 0), (3, 0)],
            },
        ),
    ] {
        compile_intrinsic_call_expect_helper(
            context,
            command_name,
            program_type,
            target,
            positional,
            vec![],
            flags,
            return_value,
            expected,
        );
    }
}

#[test]
fn test_compile_xdp_redirect_map_kind_programs() {
    let decl_names = HashMap::from([(DeclId::new(42), "redirect-map".to_string())]);

    for (map_name, map_kind_arg, expected_kind, expected_def) in [
        (
            "demo_devmap",
            "devmap",
            MapKind::DevMap,
            BpfMapDef::dev_map(10240),
        ),
        (
            "demo_devmap_hash",
            "devmap-hash",
            MapKind::DevMapHash,
            BpfMapDef::dev_map_hash(4, 10240),
        ),
        (
            "demo_cpumap",
            "cpumap",
            MapKind::CpuMap,
            BpfMapDef::cpu_map(10240),
        ),
        (
            "demo_xskmap",
            "xskmap",
            MapKind::XskMap,
            BpfMapDef::xsk_map(10240),
        ),
    ] {
        let hir = make_intrinsic_call_return_program(
            DeclId::new(42),
            vec![
                HirLiteral::String(map_name.as_bytes().to_vec()),
                HirLiteral::Int(7),
            ],
            vec![(b"kind".to_vec(), HirLiteral::String(map_kind_arg.into()))],
            vec![],
            HirLiteral::Int(2),
        );
        let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");

        let mut lowering = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &decl_names,
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap_or_else(|err| panic!("xdp redirect-map --kind {map_kind_arg} should lower: {err}"));

        let block = lowering.program.main.block(lowering.program.main.entry);
        assert!(
            block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadMapFd {
                    map: MapRef { name, kind },
                    ..
                } if name == map_name && *kind == expected_kind
            )),
            "xdp redirect-map --kind {map_kind_arg} should load the expected map fd"
        );
        assert!(
            block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::CallHelper {
                    helper,
                    args,
                    ..
                } if *helper == BpfHelper::RedirectMap as u32
                    && args.len() == 3
                    && matches!(args.get(2), Some(crate::compiler::mir::MirValue::Const(0)))
            )),
            "xdp redirect-map --kind {map_kind_arg} should call bpf_redirect_map"
        );

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );

        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .unwrap_or_else(|err| {
            panic!("xdp redirect-map --kind {map_kind_arg} should compile: {err}")
        });

        assert!(!result.bytecode.is_empty(), "Should produce bytecode");
        let map = result
            .maps
            .iter()
            .find(|map| map.name == map_name)
            .unwrap_or_else(|| {
                panic!("xdp redirect-map --kind {map_kind_arg} should emit map {map_name}")
            });
        assert_eq!(map.def.map_type, expected_def.map_type);
        assert_eq!(map.def.key_size, expected_def.key_size);
        assert_eq!(map.def.value_size, expected_def.value_size);
        assert_eq!(map.def.max_entries, expected_def.max_entries);
        assert!(
            result
                .relocations
                .iter()
                .any(|reloc| reloc.symbol_name == map_name),
            "xdp redirect-map --kind {map_kind_arg} should emit a map relocation"
        );
    }
}

#[test]
fn test_compile_sk_msg_adjust_message_pull_program() {
    let hir = make_intrinsic_call_return_program(
        DeclId::new(42),
        vec![HirLiteral::Int(0), HirLiteral::Int(8)],
        vec![(b"flags".to_vec(), HirLiteral::Int(0))],
        vec![b"pull".to_vec()],
        HirLiteral::Int(1),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");
    let decl_names = HashMap::from([(DeclId::new(42), "adjust-message".to_string())]);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sk_msg adjust-message --pull should lower through attach flow");

    let block = lowering.program.main.block(lowering.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::CallHelper {
            helper,
            args,
            ..
        } if *helper == BpfHelper::MsgPullData as u32
            && args.len() == 4
            && matches!(args.get(3), Some(crate::compiler::mir::MirValue::Const(0)))
    )));

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("sk_msg adjust-message --pull should compile through attach flow");

    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_socket_redirect_kind_programs() {
    let decl_names = HashMap::from([(DeclId::new(42), "redirect-socket".to_string())]);

    for (
        context,
        program_type,
        target,
        map_name,
        map_kind_arg,
        key,
        expected_kind,
        expected_helper,
        expected_flags,
    ) in [
        (
            "sk_msg sockmap",
            EbpfProgramType::SkMsg,
            "/sys/fs/bpf/demo_sockmap",
            "demo_msg_sockmap",
            "sockmap",
            HirLiteral::Int(3),
            MapKind::SockMap,
            BpfHelper::MsgRedirectMap,
            0,
        ),
        (
            "sk_msg sockhash",
            EbpfProgramType::SkMsg,
            "/sys/fs/bpf/demo_sockhash",
            "demo_msg_sockhash",
            "sockhash",
            HirLiteral::String(b"peer-a".to_vec()),
            MapKind::SockHash,
            BpfHelper::MsgRedirectHash,
            1,
        ),
        (
            "sk_skb sockmap",
            EbpfProgramType::SkSkb,
            "/sys/fs/bpf/demo_sockmap",
            "demo_skb_sockmap",
            "sockmap",
            HirLiteral::Int(4),
            MapKind::SockMap,
            BpfHelper::SkRedirectMap,
            0,
        ),
        (
            "sk_skb sockhash",
            EbpfProgramType::SkSkb,
            "/sys/fs/bpf/demo_sockmap",
            "demo_skb_sockhash",
            "sockhash",
            HirLiteral::String(b"peer-b".to_vec()),
            MapKind::SockHash,
            BpfHelper::SkRedirectHash,
            1,
        ),
        (
            "sk_skb_parser sockmap",
            EbpfProgramType::SkSkbParser,
            "/sys/fs/bpf/demo_sockmap",
            "demo_parser_sockmap",
            "sockmap",
            HirLiteral::Int(5),
            MapKind::SockMap,
            BpfHelper::SkRedirectMap,
            0,
        ),
        (
            "sk_skb_parser sockhash",
            EbpfProgramType::SkSkbParser,
            "/sys/fs/bpf/demo_sockmap",
            "demo_parser_sockhash",
            "sockhash",
            HirLiteral::String(b"peer-c".to_vec()),
            MapKind::SockHash,
            BpfHelper::SkRedirectHash,
            1,
        ),
        (
            "sk_reuseport reuseport-sockarray",
            EbpfProgramType::SkReuseport,
            "select",
            "demo_reuseport",
            "reuseport-sockarray",
            HirLiteral::Int(0),
            MapKind::ReuseportSockArray,
            BpfHelper::SkSelectReuseport,
            0,
        ),
    ] {
        let hir = make_intrinsic_call_return_program(
            DeclId::new(42),
            vec![HirLiteral::String(map_name.as_bytes().to_vec()), key],
            vec![
                (b"kind".to_vec(), HirLiteral::String(map_kind_arg.into())),
                (b"flags".to_vec(), HirLiteral::Int(expected_flags)),
            ],
            vec![],
            HirLiteral::Int(1),
        );
        let probe_ctx = ProbeContext::new(program_type, target);

        let mut lowering = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &decl_names,
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap_or_else(|err| panic!("{context} redirect-socket should lower: {err}"));

        let block = lowering.program.main.block(lowering.program.main.entry);
        assert!(
            block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadMapFd {
                    map: MapRef { name, kind },
                    ..
                } if name == map_name && *kind == expected_kind
            )),
            "{context} redirect-socket should load the expected map fd"
        );
        assert!(
            block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::CallHelper {
                    helper,
                    args,
                    ..
                } if *helper == expected_helper as u32
                    && args.len() == 4
                    && matches!(
                        args.get(3),
                        Some(crate::compiler::mir::MirValue::Const(flags)) if *flags == expected_flags
                    )
            )),
            "{context} redirect-socket should call the expected socket redirect helper"
        );

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );

        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .unwrap_or_else(|err| panic!("{context} redirect-socket should compile: {err}"));

        assert!(!result.bytecode.is_empty(), "Should produce bytecode");
        let map = result
            .maps
            .iter()
            .find(|map| map.name == map_name)
            .unwrap_or_else(|| panic!("{context} redirect-socket should emit map {map_name}"));
        let expected_def = match expected_kind {
            MapKind::SockMap => BpfMapDef::sock_map(10240),
            MapKind::SockHash => BpfMapDef::sock_hash(map.def.key_size, 10240),
            MapKind::ReuseportSockArray => BpfMapDef::reuseport_sockarray(10240),
            _ => unreachable!("socket redirect only accepts sockmap/sockhash/reuseport-sockarray"),
        };
        assert_eq!(map.def.map_type, expected_def.map_type);
        assert_eq!(map.def.value_size, expected_def.value_size);
        assert_eq!(map.def.max_entries, expected_def.max_entries);
        if matches!(
            expected_kind,
            MapKind::SockMap | MapKind::ReuseportSockArray
        ) {
            assert_eq!(map.def.key_size, expected_def.key_size);
        } else {
            assert!(
                map.def.key_size > 1,
                "{context} sockhash should infer key size from the key value"
            );
        }
        assert!(
            result
                .relocations
                .iter()
                .any(|reloc| reloc.symbol_name == map_name),
            "{context} redirect-socket should emit a map relocation"
        );
    }
}

#[test]
fn test_compile_socket_redirect_rejects_reuseport_nonzero_flags() {
    let decl_names = HashMap::from([(DeclId::new(42), "redirect-socket".to_string())]);
    let hir = make_intrinsic_call_return_program(
        DeclId::new(42),
        vec![
            HirLiteral::String(b"demo_reuseport".to_vec()),
            HirLiteral::Int(0),
        ],
        vec![
            (
                b"kind".to_vec(),
                HirLiteral::String(b"reuseport-sockarray".to_vec()),
            ),
            (b"flags".to_vec(), HirLiteral::Int(1)),
        ],
        vec![],
        HirLiteral::Int(1),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkReuseport, "select");

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("reuseport redirect-socket should lower before helper flags validation");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let err = match compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    ) {
        Ok(_) => panic!("reuseport redirect-socket should reject nonzero flags"),
        Err(err) => err,
    };
    let message = err.to_string();
    assert!(
        message.contains("helper 'bpf_sk_select_reuseport' requires arg3 flags to be 0"),
        "{message}"
    );
}

#[test]
fn test_compile_sock_ops_socket_map_update_programs() {
    let decl_names = HashMap::from([(DeclId::new(42), "map-put".to_string())]);

    for (context, map_name, kind_arg, expected_kind, expected_helper, expected_flags) in [
        (
            "sock_ops sockmap",
            "active_sockmap",
            "sockmap",
            MapKind::SockMap,
            BpfHelper::SockMapUpdate,
            2,
        ),
        (
            "sock_ops sockhash",
            "active_sockhash",
            "sockhash",
            MapKind::SockHash,
            BpfHelper::SockHashUpdate,
            0,
        ),
    ] {
        let hir = make_sock_ops_socket_map_put_program(
            DeclId::new(42),
            map_name,
            kind_arg,
            expected_flags,
        );
        let probe_ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");

        let mut lowering = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &decl_names,
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap_or_else(|err| panic!("{context} map-put should lower: {err}"));

        let block = lowering.program.main.block(lowering.program.main.entry);
        assert!(
            block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadMapFd {
                    map: MapRef { name, kind },
                    ..
                } if name == map_name && *kind == expected_kind
            )),
            "{context} map-put should load the expected socket map fd"
        );
        assert!(
            block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::CallHelper {
                    helper,
                    args,
                    ..
                } if *helper == expected_helper as u32
                    && args.len() == 4
                    && matches!(
                        args.get(3),
                        Some(crate::compiler::mir::MirValue::Const(flags)) if *flags == expected_flags
                    )
            )),
            "{context} map-put should call the expected socket-map update helper"
        );

        optimize_with_ssa_hints(
            &mut lowering.program.main,
            Some(&probe_ctx),
            &mut lowering.type_hints.main,
            &lowering.type_hints.main_stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );

        let result = compile_mir_to_ebpf_with_hints(
            &lowering.program,
            Some(&probe_ctx),
            Some(&lowering.type_hints),
        )
        .unwrap_or_else(|err| panic!("{context} map-put should compile: {err}"));

        assert!(!result.bytecode.is_empty(), "Should produce bytecode");
        let map = result
            .maps
            .iter()
            .find(|map| map.name == map_name)
            .unwrap_or_else(|| panic!("{context} map-put should emit map {map_name}"));
        let expected_def = match expected_kind {
            MapKind::SockMap => BpfMapDef::sock_map(10240),
            MapKind::SockHash => BpfMapDef::sock_hash(map.def.key_size, 10240),
            _ => unreachable!("socket map update only accepts sockmap/sockhash"),
        };
        assert_eq!(map.def.map_type, expected_def.map_type);
        assert_eq!(map.def.value_size, expected_def.value_size);
        assert_eq!(map.def.max_entries, expected_def.max_entries);
        if expected_kind == MapKind::SockMap {
            assert_eq!(map.def.key_size, expected_def.key_size);
        } else {
            assert!(
                map.def.key_size > 1,
                "{context} sockhash should infer key size from the socket key"
            );
        }
        assert!(
            result
                .relocations
                .iter()
                .any(|reloc| reloc.symbol_name == map_name),
            "{context} map-put should emit a map relocation"
        );
    }
}

#[test]
fn test_compile_optimized_external_queue_map_peek_whole_struct_emit() {
    let hir = make_map_take_whole_value_program(DeclId::new(43), DeclId::new(44), "queue");
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let decl_names = HashMap::from([
        (DeclId::new(43), "map-peek".to_string()),
        (DeclId::new(44), "emit".to_string()),
    ]);
    let external_schema = recent_paths_struct_schema(MapKind::Queue);

    let mut lowering = lower_hir_to_mir_with_hints_and_maps(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        Some(&external_schema),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("external queue map-peek whole-struct emit should lower");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized external queue map-peek whole-struct emit should compile");

    let schema = result
        .event_schema
        .expect("whole-struct queue map-peek emit should preserve an event schema");
    assert!(
        schema
            .fields
            .iter()
            .map(|field| field.name.as_str())
            .eq(["mnt", "dentry"].into_iter()),
        "whole-struct queue map-peek emit should preserve top-level record fields"
    );
}

#[test]
fn test_compile_optimized_external_stack_map_pop_whole_struct_count() {
    let hir = make_map_take_whole_value_program(DeclId::new(43), DeclId::new(44), "stack");
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let decl_names = HashMap::from([
        (DeclId::new(43), "map-pop".to_string()),
        (DeclId::new(44), "count".to_string()),
    ]);
    let external_schema = recent_paths_struct_schema(MapKind::Stack);

    let mut lowering = lower_hir_to_mir_with_hints_and_maps(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        Some(&external_schema),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("external stack map-pop whole-struct count should lower");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized external stack map-pop whole-struct count should compile");

    let schema = result
        .bytes_counter_key_schema
        .expect("whole-struct stack map-pop count should preserve a key schema");
    assert!(matches!(
        schema,
        CounterKeySchema::Record { ref fields, .. }
            if fields.len() == 2
                && fields[0].name == "mnt"
                && fields[1].name == "dentry"
    ));
}

#[test]
fn test_compile_optimized_external_typed_map_get_whole_struct_count() {
    let hir = make_map_get_whole_value_program(DeclId::new(43), DeclId::new(44));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(43), "map-get".to_string());
    decl_names.insert(DeclId::new(44), "count".to_string());
    let external_schema = cached_path_struct_schema();

    let mut lowering = lower_hir_to_mir_with_hints_and_maps(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        Some(&external_schema),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("whole-value typed map-get count should lower");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );
    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized whole-value typed map-get count should compile");
    let schema = result
        .bytes_counter_key_schema
        .expect("whole-value count should preserve a record key schema");
    assert!(matches!(
        schema,
        CounterKeySchema::Record { ref fields, .. }
            if fields.len() == 2
                && fields[0].name == "mnt"
                && fields[1].name == "dentry"
    ));
}

#[test]
fn test_compile_optimized_external_typed_map_get_whole_struct_emit() {
    let hir = make_map_get_whole_value_program(DeclId::new(43), DeclId::new(44));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(43), "map-get".to_string());
    decl_names.insert(DeclId::new(44), "emit".to_string());
    let external_schema = cached_path_struct_schema();

    let mut lowering = lower_hir_to_mir_with_hints_and_maps(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        Some(&external_schema),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("whole-value typed map-get emit should lower");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized whole-value typed map-get emit should compile");
    let schema = result
        .event_schema
        .expect("whole-value emit should preserve a structured event schema");
    assert!(
        schema
            .fields
            .iter()
            .map(|field| field.name.as_str())
            .eq(["mnt", "dentry"].into_iter()),
        "whole-value emit should preserve top-level record fields"
    );
}

#[test]
fn test_compile_optimized_external_typed_map_get_record_emit() {
    let hir = make_map_get_record_emit_program(DeclId::new(43), DeclId::new(44));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(43), "map-get".to_string());
    decl_names.insert(DeclId::new(44), "emit".to_string());
    let external_schema = cached_path_struct_schema();

    let mut lowering = lower_hir_to_mir_with_hints_and_maps(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        Some(&external_schema),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("record emit around typed map-get should lower");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized record emit around typed map-get should compile");
    let schema = result
        .event_schema
        .expect("record emit should preserve a structured event schema");
    assert!(matches!(
        schema.fields.as_slice(),
        [crate::compiler::SchemaField {
            name,
            field_type: crate::compiler::BpfFieldType::Bytes(16),
            value_schema: Some(CounterKeySchema::Record { fields, .. }),
            ..
        }] if name == "path"
            && fields.len() == 2
            && fields[0].name == "mnt"
            && fields[1].name == "dentry"
    ));
}

#[test]
fn test_compile_optimized_external_typed_map_get_user_function_emit() {
    let hir =
        make_map_get_user_function_emit_program(DeclId::new(43), DeclId::new(90), DeclId::new(44));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(43), "map-get".to_string());
    decl_names.insert(DeclId::new(44), "emit".to_string());
    decl_names.insert(DeclId::new(90), "project-entry".to_string());
    let external_schema = cached_path_struct_schema();
    let user_functions = HashMap::from([(DeclId::new(90), make_identity_user_function())]);

    let mut lowering = lower_hir_to_mir_with_hints_and_maps(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        Some(&external_schema),
        &user_functions,
        &HashMap::new(),
    )
    .expect("typed map-get through user function should lower");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );
    for ((subfn, hints), stack_slots) in lowering
        .program
        .subfunctions
        .iter_mut()
        .zip(lowering.type_hints.subfunctions.iter_mut())
        .zip(lowering.type_hints.subfunction_stack_slots.iter())
    {
        optimize_with_ssa_hints(
            subfn,
            Some(&probe_ctx),
            hints,
            stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );
    }

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized typed map-get through user function should compile");
    let schema = result
        .event_schema
        .expect("user-function emit should preserve a structured event schema");
    assert!(
        schema
            .fields
            .iter()
            .map(|field| field.name.as_str())
            .eq(["mnt", "dentry"].into_iter()),
        "user-function emit should preserve top-level record fields, got {:?}",
        schema
    );
}

#[test]
fn test_compile_optimized_typed_trampoline_user_function_projection() {
    let hir = make_trampoline_user_function_count_program(
        CellPath {
            members: vec![string_member("arg0")],
        },
        DeclId::new(90),
        DeclId::new(44),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(44), "count".to_string());
    decl_names.insert(DeclId::new(90), "project-inode-flags".to_string());
    let user_functions =
        HashMap::from([(DeclId::new(90), make_project_inode_flags_user_function())]);

    let mut lowering = lower_hir_to_mir_with_hints_and_maps(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        None,
        &user_functions,
        &HashMap::new(),
    )
    .expect("typed trampoline arg through user function should lower");
    assert!(
        lowering.program.subfunctions.is_empty(),
        "trusted BTF pointer arguments should inline user functions instead of losing provenance at the BPF subfunction ABI"
    );

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );
    for ((subfn, hints), stack_slots) in lowering
        .program
        .subfunctions
        .iter_mut()
        .zip(lowering.type_hints.subfunctions.iter_mut())
        .zip(lowering.type_hints.subfunction_stack_slots.iter())
    {
        optimize_with_ssa_hints(
            subfn,
            Some(&probe_ctx),
            hints,
            stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );
    }

    compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized typed trampoline projection through user function should compile");
}

#[test]
fn test_compile_optimized_named_typed_trampoline_user_function_projection() {
    let Some((function_name, arg_name)) = find_function_trampoline_named_root_candidate() else {
        return;
    };

    let hir = make_trampoline_user_function_count_program(
        CellPath {
            members: vec![string_member("arg"), string_member(&arg_name)],
        },
        DeclId::new(90),
        DeclId::new(44),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, &function_name);
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(44), "count".to_string());
    decl_names.insert(DeclId::new(90), "project-inode-flags".to_string());
    let user_functions =
        HashMap::from([(DeclId::new(90), make_project_inode_flags_user_function())]);

    let mut lowering = lower_hir_to_mir_with_hints_and_maps(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        None,
        &user_functions,
        &HashMap::new(),
    )
    .expect("named typed trampoline arg through user function should lower");
    assert!(
        lowering.program.subfunctions.is_empty(),
        "trusted named BTF pointer arguments should inline user functions instead of losing provenance at the BPF subfunction ABI"
    );

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );
    for ((subfn, hints), stack_slots) in lowering
        .program
        .subfunctions
        .iter_mut()
        .zip(lowering.type_hints.subfunctions.iter_mut())
        .zip(lowering.type_hints.subfunction_stack_slots.iter())
    {
        optimize_with_ssa_hints(
            subfn,
            Some(&probe_ctx),
            hints,
            stack_slots,
            &lowering.type_hints.generic_map_value_types,
        );
    }

    compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized named typed trampoline projection through user function should compile");
}

#[test]
fn test_compile_optimized_map_to_map_copy_projection() {
    let hir = make_map_copy_projection_program(
        CellPath {
            members: vec![string_member("arg0"), string_member("f_path")],
        },
        DeclId::new(42),
        DeclId::new(43),
        DeclId::new(44),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "map-put".to_string());
    decl_names.insert(DeclId::new(43), "map-get".to_string());
    decl_names.insert(DeclId::new(44), "count".to_string());

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("map-to-map copy projection should lower");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized map-to-map copy projection should compile");

    assert!(
        result.maps.iter().any(|map| map.name == "copied_path"),
        "expected generic map definition for copied_path"
    );
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_optimized_named_map_to_map_copy_projection() {
    let Some((function_name, arg_name, field_name)) =
        find_function_trampoline_named_struct_leaf_candidate()
    else {
        return;
    };

    let hir = make_map_copy_projection_program(
        CellPath {
            members: vec![
                string_member("arg"),
                string_member(&arg_name),
                string_member(&field_name),
            ],
        },
        DeclId::new(42),
        DeclId::new(43),
        DeclId::new(44),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, &function_name);
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "map-put".to_string());
    decl_names.insert(DeclId::new(43), "map-get".to_string());
    decl_names.insert(DeclId::new(44), "count".to_string());

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("named map-to-map copy projection should lower");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized named map-to-map copy projection should compile");

    assert!(
        result.maps.iter().any(|map| map.name == "copied_path"),
        "expected generic map definition for copied_path"
    );
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_recover_optimized_type_hints_for_direct_pointer_index_projection() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![
            string_member("arg0"),
            string_member("fdt"),
            string_member("fd"),
            PathMember::Int {
                val: 0,
                span: Span::test_data(),
                optional: false,
            },
            string_member("f_inode"),
            string_member("i_ino"),
        ],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "do_close_on_exec");

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("direct pointer-index projection should lower");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized direct pointer-index projection should compile");
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_recover_optimized_type_hints_for_named_direct_pointer_index_projection() {
    let Some((function_name, arg_name)) = find_function_trampoline_named_pointer_index_candidate()
    else {
        return;
    };

    let hir = make_ctx_path_program(CellPath {
        members: vec![
            string_member("arg"),
            string_member(&arg_name),
            string_member("fdt"),
            string_member("fd"),
            PathMember::Int {
                val: 0,
                span: Span::test_data(),
                optional: false,
            },
            string_member("f_inode"),
            string_member("i_ino"),
        ],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, &function_name);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("named direct pointer-index projection should lower");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized named direct pointer-index projection should compile");
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_recover_optimized_type_hints_for_bound_pointer_index_projection() {
    let hir = make_bound_ctx_path_program(
        CellPath {
            members: vec![
                string_member("arg0"),
                string_member("fdt"),
                string_member("fd"),
            ],
        },
        CellPath {
            members: vec![
                PathMember::Int {
                    val: 0,
                    span: Span::test_data(),
                    optional: false,
                },
                string_member("f_inode"),
                string_member("i_ino"),
            ],
        },
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "do_close_on_exec");

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("bound pointer-index projection should lower");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized bound pointer-index projection should compile");
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_recover_optimized_type_hints_for_named_bound_pointer_index_projection() {
    let Some((function_name, arg_name)) = find_function_trampoline_named_pointer_index_candidate()
    else {
        return;
    };

    let hir = make_bound_ctx_path_program(
        CellPath {
            members: vec![
                string_member("arg"),
                string_member(&arg_name),
                string_member("fdt"),
                string_member("fd"),
            ],
        },
        CellPath {
            members: vec![
                PathMember::Int {
                    val: 0,
                    span: Span::test_data(),
                    optional: false,
                },
                string_member("f_inode"),
                string_member("i_ino"),
            ],
        },
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, &function_name);

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("named bound pointer-index projection should lower");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized named bound pointer-index projection should compile");
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_recover_optimized_type_hints_for_bound_numeric_get_projection() {
    let hir = make_bound_ctx_get_program(
        CellPath {
            members: vec![
                string_member("arg0"),
                string_member("fdt"),
                string_member("fd"),
            ],
        },
        CellPath {
            members: vec![string_member("f_inode"), string_member("i_ino")],
        },
        DeclId::new(42),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "do_close_on_exec");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "get".to_string());

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("bound numeric get projection should lower");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized bound numeric get projection should compile");
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_recover_optimized_type_hints_for_named_bound_numeric_get_projection() {
    let Some((function_name, arg_name)) = find_function_trampoline_named_pointer_index_candidate()
    else {
        return;
    };

    let hir = make_bound_ctx_get_program(
        CellPath {
            members: vec![
                string_member("arg"),
                string_member(&arg_name),
                string_member("fdt"),
                string_member("fd"),
            ],
        },
        CellPath {
            members: vec![string_member("f_inode"), string_member("i_ino")],
        },
        DeclId::new(42),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, &function_name);
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "get".to_string());

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("named bound numeric get projection should lower");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized named bound numeric get projection should compile");
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_recover_optimized_type_hints_for_branch_refined_bound_numeric_get_projection() {
    let hir = make_branch_refined_bound_ctx_get_program(
        CellPath {
            members: vec![
                string_member("arg0"),
                string_member("fdt"),
                string_member("max_fds"),
            ],
        },
        CellPath {
            members: vec![
                string_member("arg0"),
                string_member("fdt"),
                string_member("fd"),
            ],
        },
        CellPath {
            members: vec![string_member("f_inode"), string_member("i_ino")],
        },
        DeclId::new(42),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "do_close_on_exec");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "get".to_string());

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("branch-refined bound numeric get projection should lower");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized branch-refined bound numeric get projection should compile");
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_recover_optimized_type_hints_for_named_branch_refined_bound_numeric_get_projection() {
    let Some((function_name, arg_name)) = find_function_trampoline_named_pointer_index_candidate()
    else {
        return;
    };

    let hir = make_branch_refined_bound_ctx_get_program(
        CellPath {
            members: vec![
                string_member("arg"),
                string_member(&arg_name),
                string_member("fdt"),
                string_member("max_fds"),
            ],
        },
        CellPath {
            members: vec![
                string_member("arg"),
                string_member(&arg_name),
                string_member("fdt"),
                string_member("fd"),
            ],
        },
        CellPath {
            members: vec![string_member("f_inode"), string_member("i_ino")],
        },
        DeclId::new(42),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, &function_name);
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "get".to_string());

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("named branch-refined bound numeric get projection should lower");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized named branch-refined bound numeric get projection should compile");
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_recover_optimized_type_hints_for_stack_backed_array_numeric_get() {
    let hir = make_bound_ctx_runtime_get_program(
        CellPath {
            members: vec![string_member("arg0"), string_member("comm")],
        },
        CellPath {
            members: vec![string_member("pid")],
        },
        2,
        DeclId::new(42),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "wake_up_new_task");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "get".to_string());

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("stack-backed array numeric get should lower");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized stack-backed array numeric get should compile");
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_recover_optimized_type_hints_for_stack_backed_bitfield_projection_after_numeric_get() {
    let hir = make_bound_ctx_runtime_get_path_program(
        CellPath {
            members: vec![string_member("arg0"), string_member("uclamp_req")],
        },
        CellPath {
            members: vec![string_member("pid")],
        },
        2,
        CellPath {
            members: vec![string_member("bucket_id")],
        },
        DeclId::new(42),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "wake_up_new_task");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "get".to_string());

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("stack-backed bitfield projection after numeric get should lower");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized stack-backed bitfield projection after numeric get should compile");
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_recover_optimized_type_hints_for_stack_backed_bitfield_struct_count_after_numeric_get() {
    let hir = make_bound_ctx_runtime_get_then_call_program(
        CellPath {
            members: vec![string_member("arg0"), string_member("uclamp_req")],
        },
        CellPath {
            members: vec![string_member("pid")],
        },
        2,
        DeclId::new(43),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "wake_up_new_task");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "get".to_string());
    decl_names.insert(DeclId::new(43), "count".to_string());

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("stack-backed bitfield struct count after numeric get should lower");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized stack-backed bitfield struct count should compile");
    assert!(
        matches!(
            result.bytes_counter_key_schema,
            Some(CounterKeySchema::Record { .. })
        ),
        "bitfield struct count should preserve a record schema"
    );
}

#[test]
fn test_recover_optimized_type_hints_for_stack_backed_bitfield_struct_emit_after_numeric_get() {
    let hir = make_bound_ctx_runtime_get_then_call_program(
        CellPath {
            members: vec![string_member("arg0"), string_member("uclamp_req")],
        },
        CellPath {
            members: vec![string_member("pid")],
        },
        2,
        DeclId::new(43),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "wake_up_new_task");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "get".to_string());
    decl_names.insert(DeclId::new(43), "emit".to_string());

    let mut lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("stack-backed bitfield struct emit after numeric get should lower");

    optimize_with_ssa_hints(
        &mut lowering.program.main,
        Some(&probe_ctx),
        &mut lowering.type_hints.main,
        &lowering.type_hints.main_stack_slots,
        &lowering.type_hints.generic_map_value_types,
    );

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("optimized stack-backed bitfield struct emit should compile");
    let schema = result
        .event_schema
        .expect("single-value emit should preserve a schema");
    assert!(
        schema.fields.iter().map(|field| field.name.as_str()).eq([
            "value",
            "bucket_id",
            "active",
            "user_defined"
        ]
        .into_iter()),
        "bitfield struct emit should preserve top-level record fields"
    );
    assert!(
        schema.fields[0].bitfield.is_some() && schema.fields[1].bitfield.is_some(),
        "bitfield struct emit should preserve bitfield metadata"
    );
}
