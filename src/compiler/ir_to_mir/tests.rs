use super::*;

#[test]
fn test_mir_function_creation() {
    let mut func = MirFunction::new();
    let v0 = func.alloc_vreg();
    let v1 = func.alloc_vreg();

    assert_eq!(v0.0, 0);
    assert_eq!(v1.0, 1);
    assert_eq!(func.vreg_count, 2);
}

#[test]
fn test_basic_block_creation() {
    let mut func = MirFunction::new();
    let b0 = func.alloc_block();
    let b1 = func.alloc_block();

    assert_eq!(b0.0, 0);
    assert_eq!(b1.0, 1);
    assert_eq!(func.blocks.len(), 2);
}

#[test]
fn test_list_instructions_creation() {
    // Test that list MIR instructions can be created correctly
    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    func.entry = bb0;

    // Allocate virtual registers
    let list_ptr = func.alloc_vreg();
    let item1 = func.alloc_vreg();
    let item2 = func.alloc_vreg();
    let len = func.alloc_vreg();
    let result = func.alloc_vreg();

    // Allocate stack slot for list buffer
    let slot = func.alloc_stack_slot(72, 8, StackSlotKind::ListBuffer); // 8 + 8*8 = 72 bytes

    // Create list instructions
    func.block_mut(bb0).instructions.push(MirInst::ListNew {
        dst: list_ptr,
        buffer: slot,
        max_len: 8,
    });

    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: item1,
        src: MirValue::Const(42),
    });

    func.block_mut(bb0).instructions.push(MirInst::ListPush {
        list: list_ptr,
        item: item1,
    });

    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: item2,
        src: MirValue::Const(100),
    });

    func.block_mut(bb0).instructions.push(MirInst::ListPush {
        list: list_ptr,
        item: item2,
    });

    func.block_mut(bb0).instructions.push(MirInst::ListLen {
        dst: len,
        list: list_ptr,
    });

    func.block_mut(bb0).instructions.push(MirInst::ListGet {
        dst: result,
        list: list_ptr,
        idx: MirValue::Const(0),
    });

    func.block_mut(bb0).terminator = MirInst::Return {
        val: Some(MirValue::VReg(result)),
    };

    // Verify instructions were created
    assert_eq!(func.block(bb0).instructions.len(), 7);

    // Verify list instructions have correct structure
    match &func.block(bb0).instructions[0] {
        MirInst::ListNew {
            dst,
            buffer,
            max_len,
        } => {
            assert_eq!(*dst, list_ptr);
            assert_eq!(*buffer, slot);
            assert_eq!(*max_len, 8);
        }
        _ => panic!("Expected ListNew instruction"),
    }

    match &func.block(bb0).instructions[2] {
        MirInst::ListPush { list, item } => {
            assert_eq!(*list, list_ptr);
            assert_eq!(*item, item1);
        }
        _ => panic!("Expected ListPush instruction"),
    }

    match &func.block(bb0).instructions[5] {
        MirInst::ListLen { dst, list } => {
            assert_eq!(*dst, len);
            assert_eq!(*list, list_ptr);
        }
        _ => panic!("Expected ListLen instruction"),
    }

    match &func.block(bb0).instructions[6] {
        MirInst::ListGet { dst, list, idx } => {
            assert_eq!(*dst, result);
            assert_eq!(*list, list_ptr);
            match idx {
                MirValue::Const(0) => {}
                _ => panic!("Expected constant index 0"),
            }
        }
        _ => panic!("Expected ListGet instruction"),
    }
}

#[test]
fn test_list_def_and_uses() {
    // Test that list instructions correctly report definitions and uses
    let mut func = MirFunction::new();
    let list_ptr = func.alloc_vreg();
    let item = func.alloc_vreg();
    let len = func.alloc_vreg();
    let result = func.alloc_vreg();
    let slot = func.alloc_stack_slot(72, 8, StackSlotKind::ListBuffer);

    // ListNew defines dst
    let inst = MirInst::ListNew {
        dst: list_ptr,
        buffer: slot,
        max_len: 8,
    };
    assert_eq!(inst.def(), Some(list_ptr));
    assert!(inst.uses().is_empty());

    // ListPush uses both list and item, defines nothing
    let inst = MirInst::ListPush {
        list: list_ptr,
        item,
    };
    assert_eq!(inst.def(), None);
    let uses = inst.uses();
    assert_eq!(uses.len(), 2);
    assert!(uses.contains(&list_ptr));
    assert!(uses.contains(&item));

    // ListLen defines dst, uses list
    let inst = MirInst::ListLen {
        dst: len,
        list: list_ptr,
    };
    assert_eq!(inst.def(), Some(len));
    let uses = inst.uses();
    assert_eq!(uses.len(), 1);
    assert!(uses.contains(&list_ptr));

    // ListGet defines dst, uses list (and maybe idx if VReg)
    let inst = MirInst::ListGet {
        dst: result,
        list: list_ptr,
        idx: MirValue::Const(0),
    };
    assert_eq!(inst.def(), Some(result));
    let uses = inst.uses();
    assert_eq!(uses.len(), 1);
    assert!(uses.contains(&list_ptr));

    // ListGet with VReg index
    let idx_vreg = func.alloc_vreg();
    let inst = MirInst::ListGet {
        dst: result,
        list: list_ptr,
        idx: MirValue::VReg(idx_vreg),
    };
    let uses = inst.uses();
    assert_eq!(uses.len(), 2);
    assert!(uses.contains(&list_ptr));
    assert!(uses.contains(&idx_vreg));
}

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

#[test]
fn test_user_function_call_lowers_to_subfn() {
    use nu_protocol::ir::{Instruction, IrBlock, Literal};
    use nu_protocol::{DeclId, RegId, VarId};
    use std::sync::Arc;

    let user_ir = IrBlock {
        instructions: vec![
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(10),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![],
        data: Arc::from([]),
        ast: vec![],
        comments: vec![],
        register_count: 1,
        file_count: 0,
    };

    let main_ir = IrBlock {
        instructions: vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(7),
            },
            Instruction::PushPositional { src: RegId::new(0) },
            Instruction::Call {
                decl_id: DeclId::new(1),
                src_dst: RegId::new(1),
            },
            Instruction::Return { src: RegId::new(1) },
        ],
        spans: vec![],
        data: Arc::from([]),
        ast: vec![],
        comments: vec![],
        register_count: 2,
        file_count: 0,
    };

    let user_func = HirFunction::from_ir_block(user_ir).unwrap();
    let hir_program = HirProgram::new(
        HirFunction::from_ir_block(main_ir).unwrap(),
        HashMap::new(),
        vec![],
        None,
    );

    let mut user_functions = HashMap::new();
    user_functions.insert(DeclId::new(1), user_func);

    let result = lower_hir_to_mir_with_hints(
        &hir_program,
        None,
        &HashMap::new(),
        None,
        &user_functions,
        &HashMap::new(),
    )
    .unwrap();

    assert_eq!(result.program.subfunctions.len(), 1);
    assert_eq!(result.program.subfunctions[0].param_count, 1);

    let mut saw_call = false;
    for block in &result.program.main.blocks {
        for inst in &block.instructions {
            if let MirInst::CallSubfn { args, .. } = inst {
                saw_call = true;
                assert_eq!(args.len(), 1);
            }
        }
    }
    assert!(saw_call, "Expected CallSubfn in main function");
}

#[test]
fn test_user_function_allows_unused_params_with_signature() {
    use nu_protocol::ir::{Instruction, IrBlock, Literal};
    use nu_protocol::{DeclId, RegId, VarId};
    use std::sync::Arc;

    let user_ir = IrBlock {
        instructions: vec![
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(10),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![],
        data: Arc::from([]),
        ast: vec![],
        comments: vec![],
        register_count: 1,
        file_count: 0,
    };

    let main_ir = IrBlock {
        instructions: vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(7),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::Int(9),
            },
            Instruction::PushPositional { src: RegId::new(0) },
            Instruction::PushPositional { src: RegId::new(1) },
            Instruction::Call {
                decl_id: DeclId::new(1),
                src_dst: RegId::new(2),
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

    let user_func = HirFunction::from_ir_block(user_ir).unwrap();
    let hir_program = HirProgram::new(
        HirFunction::from_ir_block(main_ir).unwrap(),
        HashMap::new(),
        vec![],
        None,
    );

    let mut user_functions = HashMap::new();
    user_functions.insert(DeclId::new(1), user_func);

    let mut signatures = HashMap::new();
    signatures.insert(
        DeclId::new(1),
        UserFunctionSig {
            params: vec![
                UserParam {
                    name: Some("a".into()),
                    kind: UserParamKind::Positional,
                    optional: false,
                },
                UserParam {
                    name: Some("b".into()),
                    kind: UserParamKind::Positional,
                    optional: false,
                },
            ],
        },
    );

    let result = lower_hir_to_mir_with_hints(
        &hir_program,
        None,
        &HashMap::new(),
        None,
        &user_functions,
        &signatures,
    )
    .unwrap();

    assert_eq!(result.program.subfunctions.len(), 1);
    assert_eq!(result.program.subfunctions[0].param_count, 2);
}

#[test]
fn test_user_function_named_flag_signature() {
    use nu_protocol::ir::{DataSlice, Instruction, IrBlock};
    use nu_protocol::{DeclId, RegId, VarId};
    use std::sync::Arc;

    let user_ir = IrBlock {
        instructions: vec![
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(10),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![],
        data: Arc::from([]),
        ast: vec![],
        comments: vec![],
        register_count: 1,
        file_count: 0,
    };

    let data: Arc<[u8]> = Arc::from(b"verbose".as_slice());
    let main_ir = IrBlock {
        instructions: vec![
            Instruction::PushFlag {
                name: DataSlice { start: 0, len: 7 },
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

    let user_func = HirFunction::from_ir_block(user_ir).unwrap();
    let hir_program = HirProgram::new(
        HirFunction::from_ir_block(main_ir).unwrap(),
        HashMap::new(),
        vec![],
        None,
    );

    let mut user_functions = HashMap::new();
    user_functions.insert(DeclId::new(1), user_func);

    let mut signatures = HashMap::new();
    signatures.insert(
        DeclId::new(1),
        UserFunctionSig {
            params: vec![UserParam {
                name: Some("verbose".into()),
                kind: UserParamKind::Switch,
                optional: true,
            }],
        },
    );

    let result = lower_hir_to_mir_with_hints(
        &hir_program,
        None,
        &HashMap::new(),
        None,
        &user_functions,
        &signatures,
    )
    .unwrap();

    assert_eq!(result.program.subfunctions.len(), 1);
    assert_eq!(result.program.subfunctions[0].param_count, 1);
}
