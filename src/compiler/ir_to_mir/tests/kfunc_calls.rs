use super::*;
use crate::compiler::instruction::BpfHelper;

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
fn test_helper_call_zero_arg_does_not_inject_src_dst() {
    use nu_protocol::ir::{DataSlice, Instruction, IrBlock, Literal};
    use nu_protocol::{DeclId, RegId};
    use std::sync::Arc;

    let helper_name = b"bpf_get_current_pid_tgid";
    let data: Arc<[u8]> = helper_name.to_vec().into();

    let main_ir = IrBlock {
        instructions: vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(99),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::String(DataSlice {
                    start: 0,
                    len: helper_name.len() as u32,
                }),
            },
            Instruction::PushPositional { src: RegId::new(1) },
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
    decl_names.insert(DeclId::new(42), "helper-call".to_string());

    let result = lower_hir_to_mir_with_hints(
        &hir_program,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("helper-call lowering should succeed");

    let entry = result.program.main.entry;
    let block = result.program.main.block(entry);
    let call = block
        .instructions
        .iter()
        .find_map(|inst| match inst {
            MirInst::CallHelper { helper, args, .. } => Some((helper, args)),
            _ => None,
        })
        .expect("expected lowered helper call");

    assert_eq!(*call.0, BpfHelper::GetCurrentPidTgid as u32);
    assert_eq!(
        call.1.len(),
        0,
        "zero-arg helper should not inherit src_dst"
    );
}

#[test]
fn test_helper_call_without_pipeline_uses_explicit_positional_args_only() {
    use nu_protocol::ir::{DataSlice, Instruction, IrBlock, Literal};
    use nu_protocol::{DeclId, RegId};
    use std::sync::Arc;

    let helper_name = b"bpf_get_socket_cookie";
    let data: Arc<[u8]> = helper_name.to_vec().into();

    let main_ir = IrBlock {
        instructions: vec![
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::String(DataSlice {
                    start: 0,
                    len: helper_name.len() as u32,
                }),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(2),
                lit: Literal::Int(7),
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
    decl_names.insert(DeclId::new(42), "helper-call".to_string());

    let result = lower_hir_to_mir_with_hints(
        &hir_program,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("helper-call lowering should succeed");

    let entry = result.program.main.entry;
    let block = result.program.main.block(entry);
    let call = block
        .instructions
        .iter()
        .find_map(|inst| match inst {
            MirInst::CallHelper { helper, args, .. } => Some((helper, args)),
            _ => None,
        })
        .expect("expected lowered helper call");

    assert_eq!(*call.0, BpfHelper::GetSocketCookie as u32);
    assert_eq!(
        call.1.len(),
        1,
        "helper-call should only pass explicit positional args when there is no pipeline input"
    );
}

#[test]
fn test_kfunc_call_does_not_inject_drained_src_dst() {
    use nu_protocol::ir::{DataSlice, Instruction, IrBlock, Literal};
    use nu_protocol::{DeclId, RegId};
    use std::sync::Arc;

    let kfunc_name = b"scx_bpf_select_cpu_dfl";
    let data: Arc<[u8]> = kfunc_name.to_vec().into();

    let main_ir = IrBlock {
        instructions: vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(1),
            },
            Instruction::StoreVariable {
                var_id: nu_protocol::VarId::new(80),
                src: RegId::new(0),
            },
            Instruction::Drain { src: RegId::new(0) },
            Instruction::Drop { src: RegId::new(0) },
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(2),
            },
            Instruction::StoreVariable {
                var_id: nu_protocol::VarId::new(81),
                src: RegId::new(0),
            },
            Instruction::Drain { src: RegId::new(0) },
            Instruction::Drop { src: RegId::new(0) },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::String(DataSlice {
                    start: 0,
                    len: kfunc_name.len() as u32,
                }),
            },
            Instruction::LoadVariable {
                dst: RegId::new(2),
                var_id: nu_protocol::VarId::new(80),
            },
            Instruction::LoadVariable {
                dst: RegId::new(3),
                var_id: nu_protocol::VarId::new(81),
            },
            Instruction::PushPositional { src: RegId::new(1) },
            Instruction::PushPositional { src: RegId::new(2) },
            Instruction::PushPositional { src: RegId::new(3) },
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
            MirInst::CallKfunc { args, .. } => Some(args),
            _ => None,
        })
        .expect("expected lowered kfunc call");

    assert_eq!(
        call.len(),
        2,
        "drained src_dst should not be injected as an implicit pipeline input"
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
fn test_kfunc_call_zero_arg_chain_does_not_reuse_src_dst() {
    use nu_protocol::ir::{DataSlice, Instruction, IrBlock, Literal};
    use nu_protocol::{DeclId, RegId};
    use std::sync::Arc;

    let kfunc_lock = b"bpf_rcu_read_lock";
    let kfunc_unlock = b"bpf_rcu_read_unlock";
    let mut data = Vec::new();
    let lock_start = data.len();
    data.extend_from_slice(kfunc_lock);
    let unlock_start = data.len();
    data.extend_from_slice(kfunc_unlock);
    let data: Arc<[u8]> = data.into();

    let main_ir = IrBlock {
        instructions: vec![
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::String(DataSlice {
                    start: lock_start as u32,
                    len: kfunc_lock.len() as u32,
                }),
            },
            Instruction::PushPositional { src: RegId::new(1) },
            Instruction::Call {
                decl_id: DeclId::new(42),
                src_dst: RegId::new(0),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(2),
                lit: Literal::String(DataSlice {
                    start: unlock_start as u32,
                    len: kfunc_unlock.len() as u32,
                }),
            },
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
    let calls: Vec<(String, Vec<VReg>)> = block
        .instructions
        .iter()
        .filter_map(|inst| match inst {
            MirInst::CallKfunc { kfunc, args, .. } => Some((kfunc.clone(), args.clone())),
            _ => None,
        })
        .collect();

    assert_eq!(calls.len(), 2, "expected two lowered kfunc calls");
    assert_eq!(calls[0].0, "bpf_rcu_read_lock");
    assert_eq!(calls[1].0, "bpf_rcu_read_unlock");
    assert_eq!(calls[0].1.len(), 0, "lock call should remain zero-arg");
    assert_eq!(calls[1].1.len(), 0, "unlock call should remain zero-arg");
}

#[test]
fn test_kfunc_call_materializes_direct_variable_backed_named_out_arg() {
    use crate::compiler::mir::AddressSpace;
    use nu_protocol::ir::{DataSlice, Instruction, IrBlock, Literal};
    use nu_protocol::{DeclId, RegId, VarId};
    use std::sync::Arc;

    let kfunc_name = b"scx_bpf_select_cpu_dfl";
    let data: Arc<[u8]> = kfunc_name.to_vec().into();

    let main_ir = IrBlock {
        instructions: vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Bool(false),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(80),
                src: RegId::new(0),
            },
            Instruction::Drain { src: RegId::new(0) },
            Instruction::Drop { src: RegId::new(0) },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::String(DataSlice {
                    start: 0,
                    len: kfunc_name.len() as u32,
                }),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(2),
                lit: Literal::Int(1),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(3),
                lit: Literal::Int(2),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(4),
                lit: Literal::Int(3),
            },
            Instruction::LoadVariable {
                dst: RegId::new(5),
                var_id: VarId::new(80),
            },
            Instruction::PushPositional { src: RegId::new(1) },
            Instruction::PushPositional { src: RegId::new(2) },
            Instruction::PushPositional { src: RegId::new(3) },
            Instruction::PushPositional { src: RegId::new(4) },
            Instruction::PushPositional { src: RegId::new(5) },
            Instruction::Call {
                decl_id: DeclId::new(42),
                src_dst: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(6),
                var_id: VarId::new(80),
            },
            Instruction::Return { src: RegId::new(6) },
        ],
        spans: vec![],
        data,
        ast: vec![],
        comments: vec![],
        register_count: 7,
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
    let call_idx = block
        .instructions
        .iter()
        .position(|inst| matches!(inst, MirInst::CallKfunc { .. }))
        .expect("expected lowered kfunc call");
    let call_args = match &block.instructions[call_idx] {
        MirInst::CallKfunc { args, .. } => args,
        _ => unreachable!(),
    };
    assert_eq!(call_args.len(), 4, "expected four explicit kfunc arguments");
    assert!(matches!(
        result.type_hints.main.get(&call_args[3]),
        Some(MirType::Ptr {
            address_space: AddressSpace::Stack,
            ..
        })
    ));
    assert!(
        block.instructions[..call_idx].iter().any(|inst| matches!(
            inst,
            MirInst::StoreSlot {
                ty: MirType::Bool,
                ..
            }
        )),
        "expected direct variable bool out-arg to be materialized into a stack slot"
    );
    assert!(
        block.instructions[call_idx + 1..]
            .iter()
            .any(|inst| matches!(
                inst,
                MirInst::LoadSlot {
                    ty: MirType::Bool,
                    ..
                }
            )),
        "expected named out-arg to be reloaded from the stack slot after the kfunc call"
    );
}

#[test]
fn test_kfunc_call_does_not_materialize_derived_named_out_arg() {
    use nu_protocol::ir::{DataSlice, Instruction, IrBlock, Literal};
    use nu_protocol::{DeclId, RegId, VarId};
    use std::sync::Arc;

    let kfunc_name = b"scx_bpf_select_cpu_dfl";
    let data: Arc<[u8]> = kfunc_name.to_vec().into();

    let main_ir = IrBlock {
        instructions: vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Bool(false),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(80),
                src: RegId::new(0),
            },
            Instruction::Drain { src: RegId::new(0) },
            Instruction::Drop { src: RegId::new(0) },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::String(DataSlice {
                    start: 0,
                    len: kfunc_name.len() as u32,
                }),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(2),
                lit: Literal::Int(1),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(3),
                lit: Literal::Int(2),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(4),
                lit: Literal::Int(3),
            },
            Instruction::LoadVariable {
                dst: RegId::new(5),
                var_id: VarId::new(80),
            },
            Instruction::Not {
                src_dst: RegId::new(5),
            },
            Instruction::PushPositional { src: RegId::new(1) },
            Instruction::PushPositional { src: RegId::new(2) },
            Instruction::PushPositional { src: RegId::new(3) },
            Instruction::PushPositional { src: RegId::new(4) },
            Instruction::PushPositional { src: RegId::new(5) },
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
        register_count: 6,
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
    let call_idx = block
        .instructions
        .iter()
        .position(|inst| matches!(inst, MirInst::CallKfunc { .. }))
        .expect("expected lowered kfunc call");
    let call_args = match &block.instructions[call_idx] {
        MirInst::CallKfunc { args, .. } => args,
        _ => unreachable!(),
    };
    assert_eq!(call_args.len(), 4, "expected four explicit kfunc arguments");
    assert!(
        !matches!(
            result.type_hints.main.get(&call_args[3]),
            Some(MirType::Ptr { .. })
        ),
        "derived values should not be treated as direct writable variable storage"
    );
    assert!(
        !block.instructions[..call_idx].iter().any(|inst| matches!(
            inst,
            MirInst::StoreSlot {
                ty: MirType::Bool,
                ..
            }
        )),
        "derived values should not be materialized into writable out-arg stack slots"
    );
}
