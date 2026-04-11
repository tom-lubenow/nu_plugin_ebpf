use super::*;
use crate::compiler::EbpfProgramType;
use crate::compiler::compile_mir_to_ebpf_with_hints;
use crate::compiler::hir::{HirBlock, infer_ctx_param};
use crate::compiler::hir_type_infer::infer_hir_types;
use crate::compiler::instruction::BpfHelper;
use crate::compiler::passes::optimize_with_ssa_hints;
use nu_protocol::{DeclId, RegId, VarId};

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
fn test_helper_call_with_ctx_variable_lowers_real_context_pointer() {
    let ctx_var = VarId::new(7);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String(b"bpf_get_socket_cookie".to_vec()),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(2),
                    var_id: ctx_var,
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1), RegId::new(2)],
                        ..Default::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![],
        ast: vec![],
        comments: vec![],
        register_count: 3,
        file_count: 0,
    };

    let hir_program = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "helper-call".to_string());
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");

    let result = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("helper-call with raw ctx should lower");

    let entry = result.program.main.entry;
    let block = result.program.main.block(entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::Context,
            ..
        }
    )));
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::CallHelper {
            helper,
            args,
            ..
        } if *helper == BpfHelper::GetSocketCookie as u32 && args.len() == 1
    )));
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
fn test_helper_call_with_live_src_dst_does_not_prepend_implicit_arg_when_explicit_args_exist() {
    use nu_protocol::ir::{DataSlice, Instruction, IrBlock, Literal};
    use nu_protocol::{DeclId, RegId};
    use std::sync::Arc;

    let helper_name = b"bpf_get_socket_cookie";
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
        "helper-call should not prepend a live src_dst when explicit positional args are present"
    );
}

#[test]
fn test_helper_call_with_explicit_ctx_arg_skips_ambient_pipeline_input() {
    use nu_protocol::ir::{DataSlice, Instruction, IrBlock, Literal};
    use std::sync::Arc;

    let helper_name = b"bpf_msg_cork_bytes";
    let result_name = b"pass";
    let mut data = Vec::new();
    let helper_start = data.len();
    data.extend_from_slice(helper_name);
    data.extend_from_slice(result_name);
    let data: Arc<[u8]> = data.into();
    let ctx_var = VarId::new(80);

    let main_ir = IrBlock {
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
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::String(DataSlice {
                    start: helper_start as u32,
                    len: helper_name.len() as u32,
                }),
            },
            Instruction::LoadVariable {
                dst: RegId::new(2),
                var_id: ctx_var,
            },
            Instruction::LoadLiteral {
                dst: RegId::new(3),
                lit: Literal::Int(8),
            },
            Instruction::PushPositional { src: RegId::new(1) },
            Instruction::PushPositional { src: RegId::new(2) },
            Instruction::PushPositional { src: RegId::new(3) },
            Instruction::Call {
                decl_id: DeclId::new(42),
                src_dst: RegId::new(0),
            },
            Instruction::DropVariable { var_id: ctx_var },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![],
        data,
        ast: vec![],
        comments: vec![],
        register_count: 4,
        file_count: 0,
    };

    let ctx_param = infer_ctx_param(&main_ir);
    let hir_program = HirProgram::new(
        HirFunction::from_ir_block(main_ir).unwrap(),
        HashMap::new(),
        vec![],
        ctx_param,
    );
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "helper-call".to_string());
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");

    let result = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
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

    assert_eq!(*call.0, BpfHelper::MsgCorkBytes as u32);
    assert_eq!(
        call.1.len(),
        2,
        "helper-call should use the explicit ctx arg and scalar size only"
    );
}

#[test]
fn test_helper_call_exact_attach_ir_with_ctx_arg_typechecks_and_lowers() {
    use nu_protocol::ir::{DataSlice, Instruction, IrBlock, Literal};
    use std::sync::Arc;

    let helper_name = b"bpf_msg_cork_bytes";
    let result_name = b"pass";
    let mut data = Vec::new();
    let helper_start = data.len();
    data.extend_from_slice(helper_name);
    let result_start = data.len();
    data.extend_from_slice(result_name);
    let data: Arc<[u8]> = data.into();
    let ctx_var = VarId::new(80);

    let main_ir = IrBlock {
        instructions: vec![
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::String(DataSlice {
                    start: helper_start as u32,
                    len: helper_name.len() as u32,
                }),
            },
            Instruction::LoadVariable {
                dst: RegId::new(2),
                var_id: ctx_var,
            },
            Instruction::LoadLiteral {
                dst: RegId::new(3),
                lit: Literal::Int(8),
            },
            Instruction::PushPositional { src: RegId::new(1) },
            Instruction::PushPositional { src: RegId::new(2) },
            Instruction::PushPositional { src: RegId::new(3) },
            Instruction::Call {
                decl_id: DeclId::new(42),
                src_dst: RegId::new(0),
            },
            Instruction::Drain { src: RegId::new(0) },
            Instruction::Drop { src: RegId::new(0) },
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::String(DataSlice {
                    start: result_start as u32,
                    len: result_name.len() as u32,
                }),
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

    let ctx_param = infer_ctx_param(&main_ir);
    assert_eq!(ctx_param, Some(ctx_var));
    let hir_program = HirProgram::new(
        HirFunction::from_ir_block(main_ir).unwrap(),
        HashMap::new(),
        vec![],
        ctx_param,
    );
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "helper-call".to_string());
    let hir_types = infer_hir_types(&hir_program, &decl_names)
        .expect("exact attach-style helper call should type-check");
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");

    let mut result = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("exact attach-style helper call should lower");

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

    assert_eq!(*call.0, BpfHelper::MsgCorkBytes as u32);
    assert_eq!(call.1.len(), 2);

    optimize_with_ssa_hints(
        &mut result.program.main,
        Some(&probe_ctx),
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );
    compile_mir_to_ebpf_with_hints(&result.program, Some(&probe_ctx), Some(&result.type_hints))
        .expect("exact attach-style helper call should compile after SSA");
}

#[test]
fn test_helper_call_exact_attach_ir_with_ctx_and_three_scalars_typechecks_and_lowers() {
    use nu_protocol::ir::{DataSlice, Instruction, IrBlock, Literal};
    use std::sync::Arc;

    let helper_name = b"bpf_msg_pull_data";
    let result_name = b"pass";
    let mut data = Vec::new();
    let helper_start = data.len();
    data.extend_from_slice(helper_name);
    let result_start = data.len();
    data.extend_from_slice(result_name);
    let data: Arc<[u8]> = data.into();
    let ctx_var = VarId::new(81);

    let main_ir = IrBlock {
        instructions: vec![
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::String(DataSlice {
                    start: helper_start as u32,
                    len: helper_name.len() as u32,
                }),
            },
            Instruction::LoadVariable {
                dst: RegId::new(2),
                var_id: ctx_var,
            },
            Instruction::LoadLiteral {
                dst: RegId::new(3),
                lit: Literal::Int(0),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(4),
                lit: Literal::Int(8),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(5),
                lit: Literal::Int(0),
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
            Instruction::Drain { src: RegId::new(0) },
            Instruction::Drop { src: RegId::new(0) },
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::String(DataSlice {
                    start: result_start as u32,
                    len: result_name.len() as u32,
                }),
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

    let ctx_param = infer_ctx_param(&main_ir);
    assert_eq!(ctx_param, Some(ctx_var));
    let hir_program = HirProgram::new(
        HirFunction::from_ir_block(main_ir).unwrap(),
        HashMap::new(),
        vec![],
        ctx_param,
    );
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "helper-call".to_string());
    let hir_types = infer_hir_types(&hir_program, &decl_names)
        .expect("exact attach-style helper call should type-check");
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");

    let mut result = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("exact attach-style helper call should lower");

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

    assert_eq!(*call.0, BpfHelper::MsgPullData as u32);
    assert_eq!(call.1.len(), 4);

    optimize_with_ssa_hints(
        &mut result.program.main,
        Some(&probe_ctx),
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );
    compile_mir_to_ebpf_with_hints(&result.program, Some(&probe_ctx), Some(&result.type_hints))
        .expect("exact attach-style helper call should compile after SSA");
}

#[test]
fn test_reused_register_load_variable_freshens_before_ctx_socket_projection() {
    let ctx_var = VarId::new(82);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String(b"bpf_sk_cgroup_id".to_vec()),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(1),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![nu_protocol::ast::PathMember::test_string(
                            "sk".to_string(),
                            false,
                            nu_protocol::casing::Casing::Sensitive,
                        )],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(1),
                    path: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String(b"pass".to_vec()),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![],
        ast: vec![],
        comments: vec![],
        register_count: 3,
        file_count: 0,
    };

    let hir_program = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");

    let result = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("reused register ctx.sk projection should lower");

    let block = result.program.main.block(result.program.main.entry);
    let string_vreg = block
        .instructions
        .iter()
        .find_map(|inst| match inst {
            MirInst::Copy {
                dst,
                src: MirValue::StackSlot(_),
            } => Some(*dst),
            _ => None,
        })
        .expect("expected stack-backed string literal materialization");
    let socket_vreg = block
        .instructions
        .iter()
        .find_map(|inst| match inst {
            MirInst::LoadCtxField {
                dst,
                field: CtxField::Socket,
                ..
            } => Some(*dst),
            _ => None,
        })
        .expect("expected ctx.sk load");

    assert_ne!(
        string_vreg, socket_vreg,
        "LoadVariable should freshen reused registers before ctx path lowering"
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
