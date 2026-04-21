use super::*;
use nu_protocol::DeclId;
use nu_protocol::RegId;
use nu_protocol::ir::{DataSlice, Instruction};
use nu_protocol::{Record, Span, Value, VarId};
use std::sync::Arc;

#[test]
fn test_hir_call_args_folded() {
    let data: Arc<[u8]> = Arc::from(b"emit".as_slice());
    let ir = IrBlock {
        instructions: vec![
            Instruction::PushFlag {
                name: DataSlice { start: 0, len: 4 },
            },
            Instruction::Call {
                decl_id: DeclId::new(1),
                src_dst: RegId::new(0),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![],
        data,
        ast: vec![],
        comments: vec![],
        register_count: 1,
        file_count: 0,
    };

    let hir = HirFunction::from_ir_block(ir).unwrap();
    let block = &hir.blocks[0];
    match &block.stmts[0] {
        HirStmt::Call { args, .. } => {
            assert_eq!(args.flags.len(), 1);
            assert_eq!(args.flags[0], b"emit");
        }
        _ => panic!("Expected Call with folded args"),
    }
}

#[test]
fn test_supports_constant_value_for_record_with_nested_numeric_list() {
    let mut record = Record::new();
    record.push(
        "numbers",
        Value::list(
            vec![
                Value::int(1, Span::test_data()),
                Value::duration(2, Span::test_data()),
                Value::bool(true, Span::test_data()),
            ],
            Span::test_data(),
        ),
    );

    assert!(supports_constant_value(&Value::record(
        record,
        Span::test_data()
    )));
}

#[test]
fn test_supports_constant_value_for_binary_and_nested_binary_record() {
    assert!(supports_constant_value(&Value::binary(
        vec![1, 2, 3],
        Span::test_data()
    )));

    let mut record = Record::new();
    record.push("payload", Value::binary(vec![1, 2], Span::test_data()));
    assert!(supports_constant_value(&Value::record(
        record,
        Span::test_data()
    )));
}

#[test]
fn test_supports_constant_value_for_top_level_homogeneous_record_array() {
    let mut first = Record::new();
    first.push("pid", Value::int(7, Span::test_data()));
    first.push("cpu", Value::int(2, Span::test_data()));

    let mut second = Record::new();
    second.push("pid", Value::int(9, Span::test_data()));
    second.push("cpu", Value::int(3, Span::test_data()));

    assert!(supports_constant_value(&Value::list(
        vec![
            Value::record(first, Span::test_data()),
            Value::record(second, Span::test_data()),
        ],
        Span::test_data()
    )));
}

#[test]
fn test_infer_ctx_param_from_leading_collect_store_pattern() {
    let ctx_var = VarId::new(80);
    let ir = IrBlock {
        instructions: vec![
            Instruction::Collect {
                src_dst: RegId::new(0),
            },
            Instruction::Clone {
                dst: RegId::new(1),
                src: RegId::new(0),
            },
            Instruction::StoreVariable {
                var_id: ctx_var,
                src: RegId::new(1),
            },
            Instruction::LoadVariable {
                dst: RegId::new(2),
                var_id: ctx_var,
            },
            Instruction::Return { src: RegId::new(2) },
        ],
        spans: vec![],
        data: Arc::from([]),
        ast: vec![],
        comments: vec![],
        register_count: 3,
        file_count: 0,
    };

    assert_eq!(infer_ctx_param(&ir), Some(ctx_var));
}
