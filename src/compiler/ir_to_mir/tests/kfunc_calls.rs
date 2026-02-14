use super::*;

#[test]
fn test_kfunc_call_lowers_with_explicit_btf_id() {
    use nu_protocol::ir::{DataSlice, Instruction, IrBlock, Literal};
    use nu_protocol::{DeclId, RegId};
    use std::sync::Arc;

    let kfunc_name = b"bpf_cgroup_ancestor";
    let named_arg = b"btf-id";
    let mut data = Vec::new();
    let kfunc_start = data.len();
    data.extend_from_slice(kfunc_name);
    let named_start = data.len();
    data.extend_from_slice(named_arg);
    let data: Arc<[u8]> = data.into();

    let main_ir = IrBlock {
        instructions: vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(123),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::String(DataSlice {
                    start: kfunc_start as u32,
                    len: kfunc_name.len() as u32,
                }),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(2),
                lit: Literal::Int(7),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(3),
                lit: Literal::Int(4242),
            },
            Instruction::PushPositional { src: RegId::new(1) },
            Instruction::PushPositional { src: RegId::new(2) },
            Instruction::PushNamed {
                name: DataSlice {
                    start: named_start as u32,
                    len: named_arg.len() as u32,
                },
                src: RegId::new(3),
            },
            Instruction::Call {
                decl_id: DeclId::new(42),
                src_dst: RegId::new(0),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![],
        data,
        ast: vec![],
        comments: vec![],
        register_count: 4,
        file_count: 0,
    };

    let hir_program = HirProgram::new(
        HirFunction::from_ir_block(main_ir).unwrap(),
        HashMap::new(),
        vec![],
        None,
    );

    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "kfunc-call".to_string());

    let result = lower_hir_to_mir_with_hints(
        &hir_program,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("kfunc-call lowering should succeed");

    let entry = result.program.main.entry;
    let block = result.program.main.block(entry);
    let call = block
        .instructions
        .iter()
        .find_map(|inst| match inst {
            MirInst::CallKfunc {
                kfunc,
                btf_id,
                args,
                ..
            } => Some((kfunc, btf_id, args)),
            _ => None,
        })
        .expect("expected lowered kfunc call");

    assert_eq!(call.0, "bpf_cgroup_ancestor");
    assert_eq!(*call.1, Some(4242));
    assert_eq!(call.2.len(), 2, "pipeline input + 1 positional arg");
}

#[test]
fn test_kfunc_call_without_pipeline_does_not_inject_src_dst() {
    use nu_protocol::ir::{DataSlice, Instruction, IrBlock, Literal};
    use nu_protocol::{DeclId, RegId};
    use std::sync::Arc;

    let kfunc_name = b"bpf_task_release";
    let data: Arc<[u8]> = kfunc_name.to_vec().into();

    let main_ir = IrBlock {
        instructions: vec![
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::String(DataSlice {
                    start: 0,
                    len: kfunc_name.len() as u32,
                }),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(2),
                lit: Literal::Int(99),
            },
            Instruction::PushPositional { src: RegId::new(1) },
            Instruction::PushPositional { src: RegId::new(2) },
            Instruction::Call {
                decl_id: DeclId::new(42),
                src_dst: RegId::new(0),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![],
        data,
        ast: vec![],
        comments: vec![],
        register_count: 3,
        file_count: 0,
    };

    let hir_program = HirProgram::new(
        HirFunction::from_ir_block(main_ir).unwrap(),
        HashMap::new(),
        vec![],
        None,
    );

    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "kfunc-call".to_string());

    let result = lower_hir_to_mir_with_hints(
        &hir_program,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("kfunc-call lowering should succeed");

    let entry = result.program.main.entry;
    let block = result.program.main.block(entry);
    let call = block
        .instructions
        .iter()
        .find_map(|inst| match inst {
            MirInst::CallKfunc { args, .. } => Some(args),
            _ => None,
        })
        .expect("expected lowered kfunc call");

    assert_eq!(
        call.len(),
        1,
        "only explicit positional arg should be passed"
    );
}

#[test]
fn test_kfunc_call_requires_literal_string_name() {
    use nu_protocol::ir::{Instruction, IrBlock, Literal};
    use nu_protocol::{DeclId, RegId};
    use std::sync::Arc;

    let main_ir = IrBlock {
        instructions: vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(1),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::Int(99),
            },
            Instruction::PushPositional { src: RegId::new(1) },
            Instruction::Call {
                decl_id: DeclId::new(42),
                src_dst: RegId::new(0),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![],
        data: Arc::from([]),
        ast: vec![],
        comments: vec![],
        register_count: 2,
        file_count: 0,
    };

    let hir_program = HirProgram::new(
        HirFunction::from_ir_block(main_ir).unwrap(),
        HashMap::new(),
        vec![],
        None,
    );

    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "kfunc-call".to_string());

    match lower_hir_to_mir_with_hints(
        &hir_program,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    ) {
        Err(CompileError::UnsupportedInstruction(msg)) => {
            assert!(msg.contains("first positional argument to be a string literal"));
        }
        Err(other) => panic!("unexpected error: {other:?}"),
        Ok(_) => panic!("expected literal string error"),
    }
}
