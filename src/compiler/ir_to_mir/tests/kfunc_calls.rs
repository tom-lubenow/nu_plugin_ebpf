use super::*;
use crate::compiler::EbpfProgramType;
use crate::compiler::compile_mir_to_ebpf_with_hints;
use crate::compiler::elf::BpfMapType;
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
fn test_helper_call_exact_attach_ir_with_sysctl_buffer_typechecks_and_lowers() {
    use nu_protocol::ir::{DataSlice, Instruction, IrBlock, Literal};
    use std::sync::Arc;

    let helper_name = b"bpf_sysctl_get_current_value";
    let value = b"1";
    let result_name = b"pass";
    let mut data = Vec::new();
    let helper_start = data.len();
    data.extend_from_slice(helper_name);
    let value_start = data.len();
    data.extend_from_slice(value);
    let result_start = data.len();
    data.extend_from_slice(result_name);
    let data: Arc<[u8]> = data.into();
    let ctx_var = VarId::new(82);

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
                lit: Literal::String(DataSlice {
                    start: value_start as u32,
                    len: value.len() as u32,
                }),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(4),
                lit: Literal::Int(1),
            },
            Instruction::PushPositional { src: RegId::new(1) },
            Instruction::PushPositional { src: RegId::new(2) },
            Instruction::PushPositional { src: RegId::new(3) },
            Instruction::PushPositional { src: RegId::new(4) },
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
        register_count: 5,
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
    let hir_types =
        infer_hir_types(&hir_program, &decl_names).expect("sysctl helper-call should type-check");
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSysctl, "/sys/fs/cgroup");

    let mut result = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sysctl helper-call should lower");

    let entry = result.program.main.entry;
    let block = result.program.main.block(entry);
    let call = block
        .instructions
        .iter()
        .find_map(|inst| match inst {
            MirInst::CallHelper { helper, args, .. } => Some((helper, args)),
            _ => None,
        })
        .expect("expected lowered sysctl helper call");

    assert_eq!(*call.0, BpfHelper::SysctlGetCurrentValue as u32);
    assert_eq!(call.1.len(), 3);

    optimize_with_ssa_hints(
        &mut result.program.main,
        Some(&probe_ctx),
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );
    compile_mir_to_ebpf_with_hints(&result.program, Some(&probe_ctx), Some(&result.type_hints))
        .expect("sysctl helper-call should compile after SSA");
}

#[test]
fn test_reused_register_load_variable_freshens_before_ctx_socket_projection() {
    let ctx_var = VarId::new(83);
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
fn test_reused_register_move_freshens_destination_vreg() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String(b"stale".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(7),
                },
                HirStmt::Move {
                    dst: RegId::new(1),
                    src: RegId::new(2),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(1) },
        }],
        entry: HirBlockId(0),
        spans: vec![],
        ast: vec![],
        comments: vec![],
        register_count: 3,
        file_count: 0,
    };

    let result = lower_hir_to_mir_with_hints(
        &HirProgram::new(func, HashMap::new(), vec![], None),
        None,
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("reused-register move should lower");

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
    let moved_vreg = block
        .instructions
        .iter()
        .find_map(|inst| match inst {
            MirInst::Copy {
                dst,
                src: MirValue::VReg(_),
            } if *dst != string_vreg => Some(*dst),
            _ => None,
        })
        .expect("expected move copy into destination register");

    assert_ne!(
        string_vreg, moved_vreg,
        "Move should freshen reused destination registers"
    );
}

#[test]
fn test_reused_register_clone_cell_path_freshens_destination_vreg() {
    let ctx_var = VarId::new(83);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String(b"stale".to_vec()),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(2),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![nu_protocol::ast::PathMember::test_string(
                            "sk".to_string(),
                            false,
                            nu_protocol::casing::Casing::Sensitive,
                        )],
                    })),
                },
                HirStmt::CloneCellPath {
                    dst: RegId::new(1),
                    src: RegId::new(2),
                    path: RegId::new(3),
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
        register_count: 4,
        file_count: 0,
    };

    let result = lower_hir_to_mir_with_hints(
        &HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var)),
        Some(&ProbeContext::new(
            EbpfProgramType::SkMsg,
            "/sys/fs/bpf/demo_sockmap",
        )),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("reused-register clone-cell-path should lower");

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
        "CloneCellPath should freshen reused destination registers"
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

#[test]
fn test_helper_call_sockmap_literal_lowers_and_compiles() {
    let ctx_var = VarId::new(91);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String(b"bpf_sk_redirect_map".to_vec()),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(2),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String(b"demo_sockmap".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::Int(3),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![
                            RegId::new(1),
                            RegId::new(2),
                            RegId::new(3),
                            RegId::new(4),
                            RegId::new(5),
                        ],
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
        register_count: 6,
        file_count: 0,
    };

    let hir_program = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "helper-call".to_string());
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkSkb, "/sys/fs/bpf/demo_sockmap");
    let hir_types =
        infer_hir_types(&hir_program, &decl_names).expect("sockmap helper-call should type-check");

    let mut result = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sockmap helper-call should lower");

    let entry = result.program.main.entry;
    let block = result.program.main.block(entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadMapFd {
            map: MapRef { name, kind: MapKind::SockMap },
            ..
        } if name == "demo_sockmap"
    )));
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::CallHelper {
            helper,
            args,
            ..
        } if *helper == BpfHelper::SkRedirectMap as u32 && args.len() == 4
    )));

    optimize_with_ssa_hints(
        &mut result.program.main,
        Some(&probe_ctx),
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );
    let compiled =
        compile_mir_to_ebpf_with_hints(&result.program, Some(&probe_ctx), Some(&result.type_hints))
            .expect("sockmap helper-call should compile");

    assert!(compiled.maps.iter().any(|map| {
        map.name == "demo_sockmap" && map.def.map_type == BpfMapType::SockMap as u32
    }));
    assert!(
        compiled
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == "demo_sockmap"),
        "expected sockmap relocation"
    );
}

#[test]
fn test_helper_call_sockhash_literal_lowers_and_compiles() {
    let ctx_var = VarId::new(92);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String(b"bpf_msg_redirect_hash".to_vec()),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(2),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String(b"demo_sockhash".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::String(b"peer-a".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![
                            RegId::new(1),
                            RegId::new(2),
                            RegId::new(3),
                            RegId::new(4),
                            RegId::new(5),
                        ],
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
        register_count: 6,
        file_count: 0,
    };

    let hir_program = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "helper-call".to_string());
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockhash");
    let hir_types =
        infer_hir_types(&hir_program, &decl_names).expect("sockhash helper-call should type-check");

    let mut result = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sockhash helper-call should lower");

    let entry = result.program.main.entry;
    let block = result.program.main.block(entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadMapFd {
            map: MapRef { name, kind: MapKind::SockHash },
            ..
        } if name == "demo_sockhash"
    )));

    optimize_with_ssa_hints(
        &mut result.program.main,
        Some(&probe_ctx),
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );
    let compiled =
        compile_mir_to_ebpf_with_hints(&result.program, Some(&probe_ctx), Some(&result.type_hints))
            .expect("sockhash helper-call should compile");

    let map = compiled
        .maps
        .iter()
        .find(|map| map.name == "demo_sockhash")
        .expect("expected sockhash runtime artifact");
    assert_eq!(map.def.map_type, BpfMapType::SockHash as u32);
    assert!(map.def.key_size > 1, "expected inferred sockhash key size");
    assert!(
        compiled
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == "demo_sockhash"),
        "expected sockhash relocation"
    );
}

#[test]
fn test_redirect_socket_intrinsic_lowers_to_sk_redirect_map_and_compiles() {
    let ctx_var = VarId::new(101);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String(b"demo_sockmap".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(3),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String(b"sockmap".to_vec()),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1), RegId::new(2)],
                        named: vec![(b"kind".to_vec(), RegId::new(3))],
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
        register_count: 4,
        file_count: 0,
    };

    let hir_program = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "redirect-socket".to_string());
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkSkb, "/sys/fs/bpf/demo_sockmap");
    let hir_types = infer_hir_types(&hir_program, &decl_names)
        .expect("redirect-socket intrinsic should type-check on sk_skb");

    let mut result = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("redirect-socket intrinsic should lower on sk_skb");

    let entry = result.program.main.entry;
    let block = result.program.main.block(entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadMapFd {
            map: MapRef { name, kind: MapKind::SockMap },
            ..
        } if name == "demo_sockmap"
    )));
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::CallHelper {
            helper,
            args,
            ..
        } if *helper == BpfHelper::SkRedirectMap as u32 && args.len() == 4
    )));

    optimize_with_ssa_hints(
        &mut result.program.main,
        Some(&probe_ctx),
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );
    let compiled =
        compile_mir_to_ebpf_with_hints(&result.program, Some(&probe_ctx), Some(&result.type_hints))
            .expect("redirect-socket intrinsic should compile on sk_skb");

    assert!(compiled.maps.iter().any(|map| {
        map.name == "demo_sockmap" && map.def.map_type == BpfMapType::SockMap as u32
    }));
    assert!(
        compiled
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == "demo_sockmap"),
        "expected sockmap relocation"
    );
}

#[test]
fn test_assign_socket_intrinsic_lowers_to_sk_assign_and_compiles() {
    let ctx_var = VarId::new(101);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        flags: vec![b"replace".to_vec(), b"no-reuseport".to_vec()],
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
        register_count: 2,
        file_count: 0,
    };

    let hir_program = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let decl_names = HashMap::from([(DeclId::new(42), "assign-socket".to_string())]);
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");
    let hir_types = infer_hir_types(&hir_program, &decl_names)
        .expect("assign-socket intrinsic should type-check before lowering");

    let mut result = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("assign-socket intrinsic should lower on sk_lookup");

    let entry = result.program.main.entry;
    let block = result.program.main.block(entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::CallHelper {
            helper,
            args,
            ..
        } if *helper == BpfHelper::SkAssign as u32
            && args.len() == 3
            && matches!(args[0], MirValue::VReg(_))
            && matches!(args[1], MirValue::VReg(_))
            && args[2] == MirValue::Const(3)
    )));

    optimize_with_ssa_hints(
        &mut result.program.main,
        Some(&probe_ctx),
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );
    let compiled =
        compile_mir_to_ebpf_with_hints(&result.program, Some(&probe_ctx), Some(&result.type_hints))
            .expect("assign-socket intrinsic should compile on sk_lookup");

    assert!(!compiled.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_assign_socket_intrinsic_rejects_nonzero_tc_flags() {
    let ctx_var = VarId::new(101);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        flags: vec![b"replace".to_vec()],
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
        register_count: 2,
        file_count: 0,
    };

    let hir_program = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let decl_names = HashMap::from([(DeclId::new(42), "assign-socket".to_string())]);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let hir_types = infer_hir_types(&hir_program, &decl_names)
        .expect("assign-socket intrinsic should type-check before attach-aware lowering");

    let err = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("assign-socket should reject non-zero tc flags");

    match err {
        CompileError::UnsupportedInstruction(msg) => {
            assert!(msg.contains("helper 'bpf_sk_assign' requires arg2 = 0 in tc programs"));
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

#[test]
fn test_redirect_socket_intrinsic_lowers_to_msg_redirect_hash_and_compiles() {
    let ctx_var = VarId::new(102);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String(b"demo_sockhash".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String(b"peer-a".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String(b"sockhash".to_vec()),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1), RegId::new(2)],
                        named: vec![(b"kind".to_vec(), RegId::new(3))],
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
        register_count: 4,
        file_count: 0,
    };

    let hir_program = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "redirect-socket".to_string());
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockhash");
    let hir_types = infer_hir_types(&hir_program, &decl_names)
        .expect("redirect-socket intrinsic should type-check on sk_msg");

    let mut result = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("redirect-socket intrinsic should lower on sk_msg");

    let entry = result.program.main.entry;
    let block = result.program.main.block(entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadMapFd {
            map: MapRef { name, kind: MapKind::SockHash },
            ..
        } if name == "demo_sockhash"
    )));
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::CallHelper {
            helper,
            args,
            ..
        } if *helper == BpfHelper::MsgRedirectHash as u32 && args.len() == 4
    )));

    optimize_with_ssa_hints(
        &mut result.program.main,
        Some(&probe_ctx),
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );
    let compiled =
        compile_mir_to_ebpf_with_hints(&result.program, Some(&probe_ctx), Some(&result.type_hints))
            .expect("redirect-socket intrinsic should compile on sk_msg");

    let map = compiled
        .maps
        .iter()
        .find(|map| map.name == "demo_sockhash")
        .expect("expected sockhash runtime artifact");
    assert_eq!(map.def.map_type, BpfMapType::SockHash as u32);
    assert!(map.def.key_size > 1, "expected inferred sockhash key size");
    assert!(
        compiled
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == "demo_sockhash"),
        "expected sockhash relocation"
    );
}

#[test]
fn test_redirect_socket_intrinsic_rejects_non_socket_redirect_programs() {
    let ctx_var = VarId::new(103);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String(b"demo_sockmap".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(3),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String(b"sockmap".to_vec()),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1), RegId::new(2)],
                        named: vec![(b"kind".to_vec(), RegId::new(3))],
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
        register_count: 4,
        file_count: 0,
    };

    let hir_program = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "redirect-socket".to_string());
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let hir_types = infer_hir_types(&hir_program, &decl_names)
        .expect("redirect-socket intrinsic should still type-check before lowering");

    let err = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("redirect-socket should be rejected outside sk_msg/sk_skb");

    match err {
        CompileError::UnsupportedInstruction(msg) => {
            assert!(
                msg.contains(
                    "redirect-socket is only valid in sk_msg, sk_skb, and sk_skb_parser programs"
                ),
                "{msg}"
            );
        }
        other => panic!("unexpected lowering error: {other:?}"),
    }
}

#[test]
fn test_helper_call_redirect_map_literal_requires_explicit_kind_and_compiles() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String(b"bpf_redirect_map".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String(b"demo_redirect_map".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::Int(7),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::String(b"devmap-hash".to_vec()),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![
                            RegId::new(1),
                            RegId::new(2),
                            RegId::new(3),
                            RegId::new(4),
                        ],
                        named: vec![(b"kind".to_vec(), RegId::new(5))],
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
        register_count: 6,
        file_count: 0,
    };

    let hir_program = HirProgram::new(func, HashMap::new(), vec![], None);
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "helper-call".to_string());
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let hir_types = infer_hir_types(&hir_program, &decl_names)
        .expect("redirect_map helper-call should type-check");

    let mut result = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("redirect_map helper-call should lower");

    let entry = result.program.main.entry;
    let block = result.program.main.block(entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadMapFd {
            map: MapRef { name, kind: MapKind::DevMapHash },
            ..
        } if name == "demo_redirect_map"
    )));
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::CallHelper {
            helper,
            args,
            ..
        } if *helper == BpfHelper::RedirectMap as u32 && args.len() == 3
    )));

    optimize_with_ssa_hints(
        &mut result.program.main,
        Some(&probe_ctx),
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );
    let compiled =
        compile_mir_to_ebpf_with_hints(&result.program, Some(&probe_ctx), Some(&result.type_hints))
            .expect("redirect_map helper-call should compile");

    let map = compiled
        .maps
        .iter()
        .find(|map| map.name == "demo_redirect_map")
        .expect("expected redirect-map runtime artifact");
    assert_eq!(map.def.map_type, BpfMapType::DevMapHash as u32);
    assert_eq!(map.def.key_size, 4);
    assert_eq!(map.def.value_size, 8);
    assert!(
        compiled
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == "demo_redirect_map"),
        "expected redirect-map relocation"
    );
}

#[test]
fn test_adjust_packet_intrinsic_lowers_to_xdp_adjust_meta_and_compiles() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(-4),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        flags: vec![b"meta".to_vec()],
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
        register_count: 2,
        file_count: 0,
    };

    let ctx_var = VarId::new(0);
    let hir_program = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "adjust-packet".to_string());
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let hir_types = infer_hir_types(&hir_program, &decl_names)
        .expect("adjust-packet intrinsic should type-check on xdp");

    let mut result = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("adjust-packet intrinsic should lower on xdp");

    let entry = result.program.main.entry;
    let block = result.program.main.block(entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::CallHelper {
            helper,
            args,
            ..
        } if *helper == BpfHelper::XdpAdjustMeta as u32 && args.len() == 2
    )));

    optimize_with_ssa_hints(
        &mut result.program.main,
        Some(&probe_ctx),
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );
    compile_mir_to_ebpf_with_hints(&result.program, Some(&probe_ctx), Some(&result.type_hints))
        .expect("adjust-packet intrinsic should compile on xdp");
}

#[test]
fn test_adjust_packet_intrinsic_rejects_conflicting_mode_flags() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(8),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        flags: vec![b"head".to_vec(), b"tail".to_vec()],
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
        register_count: 2,
        file_count: 0,
    };

    let ctx_var = VarId::new(0);
    let hir_program = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "adjust-packet".to_string());
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let hir_types = infer_hir_types(&hir_program, &decl_names)
        .expect("adjust-packet intrinsic should type-check on xdp");

    let err = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("adjust-packet should reject conflicting mode flags");

    match err {
        CompileError::UnsupportedInstruction(msg) => {
            assert!(
                msg.contains(
                    "adjust-packet requires exactly one of --head, --meta, --tail, --pull, or --room"
                ),
                "{msg}"
            );
        }
        other => panic!("unexpected lowering error: {other:?}"),
    }
}

#[test]
fn test_adjust_packet_intrinsic_lowers_to_skb_change_head_on_tc_and_compiles() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(8),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        flags: vec![b"head".to_vec()],
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
        register_count: 2,
        file_count: 0,
    };

    let ctx_var = VarId::new(0);
    let hir_program = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "adjust-packet".to_string());
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let hir_types = infer_hir_types(&hir_program, &decl_names)
        .expect("adjust-packet intrinsic should type-check on tc");

    let mut result = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("adjust-packet --head should lower to skb_change_head on tc");

    let entry = result.program.main.entry;
    let block = result.program.main.block(entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::CallHelper {
            helper,
            args,
            ..
        } if *helper == BpfHelper::SkbChangeHead as u32
            && args.len() == 3
            && matches!(args.get(2), Some(MirValue::Const(0)))
    )));

    optimize_with_ssa_hints(
        &mut result.program.main,
        Some(&probe_ctx),
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );
    compile_mir_to_ebpf_with_hints(&result.program, Some(&probe_ctx), Some(&result.type_hints))
        .expect("adjust-packet --head should compile on tc");
}

#[test]
fn test_adjust_packet_intrinsic_lowers_to_skb_pull_data_on_sk_skb() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(64),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        flags: vec![b"pull".to_vec()],
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
        register_count: 2,
        file_count: 0,
    };

    let ctx_var = VarId::new(0);
    let hir_program = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "adjust-packet".to_string());
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkSkb, "/sys/fs/bpf/demo_sockmap");
    let hir_types = infer_hir_types(&hir_program, &decl_names)
        .expect("adjust-packet intrinsic should type-check on sk_skb");

    let result = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("adjust-packet --pull should lower on sk_skb");

    let entry = result.program.main.entry;
    let block = result.program.main.block(entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::CallHelper {
            helper,
            args,
            ..
        } if *helper == BpfHelper::SkbPullData as u32 && args.len() == 2
    )));
}

#[test]
fn test_adjust_packet_intrinsic_lowers_to_skb_adjust_room_on_tc() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(32),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::Int(2),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        named: vec![
                            (b"mode".to_vec(), RegId::new(2)),
                            (b"flags".to_vec(), RegId::new(3)),
                        ],
                        flags: vec![b"room".to_vec()],
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
        register_count: 4,
        file_count: 0,
    };

    let ctx_var = VarId::new(0);
    let hir_program = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "adjust-packet".to_string());
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let hir_types = infer_hir_types(&hir_program, &decl_names)
        .expect("adjust-packet intrinsic should type-check on tc");

    let result = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("adjust-packet --room should lower on tc");

    let entry = result.program.main.entry;
    let block = result.program.main.block(entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::CallHelper {
            helper,
            args,
            ..
        } if *helper == BpfHelper::SkbAdjustRoom as u32
            && args.len() == 4
            && matches!(args.get(2), Some(MirValue::Const(1)))
            && matches!(args.get(3), Some(MirValue::Const(2)))
    )));
}

#[test]
fn test_adjust_packet_intrinsic_rejects_room_without_mode() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(8),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        flags: vec![b"room".to_vec()],
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
        register_count: 2,
        file_count: 0,
    };

    let ctx_var = VarId::new(0);
    let hir_program = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "adjust-packet".to_string());
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let hir_types = infer_hir_types(&hir_program, &decl_names)
        .expect("adjust-packet intrinsic should type-check on tc");

    let err = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("adjust-packet --room should require --mode");

    match err {
        CompileError::UnsupportedInstruction(msg) => {
            assert!(
                msg.contains("adjust-packet --room requires --mode"),
                "{msg}"
            );
        }
        other => panic!("unexpected lowering error: {other:?}"),
    }
}

#[test]
fn test_adjust_packet_intrinsic_rejects_meta_on_tc_programs() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(8),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        flags: vec![b"meta".to_vec()],
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
        register_count: 2,
        file_count: 0,
    };

    let ctx_var = VarId::new(0);
    let hir_program = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "adjust-packet".to_string());
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let hir_types = infer_hir_types(&hir_program, &decl_names)
        .expect("adjust-packet intrinsic should type-check before lowering");

    let err = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("adjust-packet --meta should be rejected on tc");

    match err {
        CompileError::UnsupportedInstruction(msg) => {
            assert!(
                msg.contains("adjust-packet --meta is only valid in xdp programs"),
                "{msg}"
            );
        }
        other => panic!("unexpected lowering error: {other:?}"),
    }
}

#[test]
fn test_adjust_message_intrinsic_lowers_to_msg_cork_bytes_and_compiles() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(8),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        flags: vec![b"cork".to_vec()],
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
        register_count: 2,
        file_count: 0,
    };

    let ctx_var = VarId::new(0);
    let hir_program = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "adjust-message".to_string());
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");
    let hir_types = infer_hir_types(&hir_program, &decl_names)
        .expect("adjust-message intrinsic should type-check on sk_msg");

    let mut result = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("adjust-message intrinsic should lower on sk_msg");

    let entry = result.program.main.entry;
    let block = result.program.main.block(entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::CallHelper {
            helper,
            args,
            ..
        } if *helper == BpfHelper::MsgCorkBytes as u32 && args.len() == 2
    )));

    optimize_with_ssa_hints(
        &mut result.program.main,
        Some(&probe_ctx),
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );
    compile_mir_to_ebpf_with_hints(&result.program, Some(&probe_ctx), Some(&result.type_hints))
        .expect("adjust-message intrinsic should compile on sk_msg");
}

#[test]
fn test_adjust_message_intrinsic_lowers_to_msg_pull_data_on_sk_msg() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(8),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1), RegId::new(2)],
                        named: vec![(b"flags".to_vec(), RegId::new(3))],
                        flags: vec![b"pull".to_vec()],
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
        register_count: 4,
        file_count: 0,
    };

    let ctx_var = VarId::new(0);
    let hir_program = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "adjust-message".to_string());
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");
    let hir_types = infer_hir_types(&hir_program, &decl_names)
        .expect("adjust-message intrinsic should type-check on sk_msg");

    let result = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("adjust-message --pull should lower on sk_msg");

    let entry = result.program.main.entry;
    let block = result.program.main.block(entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::CallHelper {
            helper,
            args,
            ..
        } if *helper == BpfHelper::MsgPullData as u32
            && args.len() == 4
            && matches!(args.get(3), Some(MirValue::Const(0)))
    )));
}

#[test]
fn test_adjust_message_intrinsic_rejects_conflicting_mode_flags() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(8),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        flags: vec![b"apply".to_vec(), b"cork".to_vec()],
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
        register_count: 2,
        file_count: 0,
    };

    let ctx_var = VarId::new(0);
    let hir_program = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "adjust-message".to_string());
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");
    let hir_types = infer_hir_types(&hir_program, &decl_names)
        .expect("adjust-message intrinsic should type-check on sk_msg");

    let err = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("adjust-message should reject conflicting mode flags");

    match err {
        CompileError::UnsupportedInstruction(msg) => {
            assert!(
                msg.contains(
                    "adjust-message requires exactly one of --apply, --cork, --pull, --push, or --pop"
                ),
                "{msg}"
            );
        }
        other => panic!("unexpected lowering error: {other:?}"),
    }
}

#[test]
fn test_adjust_message_intrinsic_rejects_non_sk_msg_programs() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(8),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        flags: vec![b"apply".to_vec()],
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
        register_count: 2,
        file_count: 0,
    };

    let ctx_var = VarId::new(0);
    let hir_program = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "adjust-message".to_string());
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let hir_types = infer_hir_types(&hir_program, &decl_names)
        .expect("adjust-message intrinsic should type-check before lowering");

    let err = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("adjust-message should be rejected outside sk_msg");

    match err {
        CompileError::UnsupportedInstruction(msg) => {
            assert!(
                msg.contains("adjust-message --apply is only valid in sk_msg programs"),
                "{msg}"
            );
        }
        other => panic!("unexpected lowering error: {other:?}"),
    }
}

#[test]
fn test_redirect_intrinsic_lowers_to_xdp_redirect_and_compiles() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(7),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
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
        register_count: 2,
        file_count: 0,
    };

    let hir_program = HirProgram::new(func, HashMap::new(), vec![], None);
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "redirect".to_string());
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let hir_types =
        infer_hir_types(&hir_program, &decl_names).expect("redirect intrinsic should type-check");

    let mut result = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("redirect intrinsic should lower on xdp");

    let entry = result.program.main.entry;
    let block = result.program.main.block(entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::CallHelper {
            helper,
            args,
            ..
        } if *helper == BpfHelper::Redirect as u32 && args.len() == 2
    )));

    optimize_with_ssa_hints(
        &mut result.program.main,
        Some(&probe_ctx),
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );
    compile_mir_to_ebpf_with_hints(&result.program, Some(&probe_ctx), Some(&result.type_hints))
        .expect("redirect intrinsic should compile on xdp");
}

#[test]
fn test_redirect_intrinsic_lowers_to_redirect_peer_on_tc_ingress() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(9),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        flags: vec![b"peer".to_vec()],
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
        register_count: 2,
        file_count: 0,
    };

    let hir_program = HirProgram::new(func, HashMap::new(), vec![], None);
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "redirect".to_string());
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let hir_types =
        infer_hir_types(&hir_program, &decl_names).expect("redirect intrinsic should type-check");

    let result = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("redirect intrinsic should lower to redirect_peer on tc ingress");

    let entry = result.program.main.entry;
    let block = result.program.main.block(entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::CallHelper {
            helper,
            args,
            ..
        } if *helper == BpfHelper::RedirectPeer as u32 && args.len() == 2
    )));
}

#[test]
fn test_redirect_intrinsic_lowers_to_redirect_neigh_on_tc() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(11),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        flags: vec![b"neigh".to_vec()],
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
        register_count: 2,
        file_count: 0,
    };

    let hir_program = HirProgram::new(func, HashMap::new(), vec![], None);
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "redirect".to_string());
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let hir_types =
        infer_hir_types(&hir_program, &decl_names).expect("redirect intrinsic should type-check");

    let result = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("redirect intrinsic should lower to redirect_neigh on tc");

    let entry = result.program.main.entry;
    let block = result.program.main.block(entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::CallHelper {
            helper,
            args,
            ..
        } if *helper == BpfHelper::RedirectNeigh as u32
            && args.len() == 4
            && matches!(args.get(1), Some(MirValue::Const(0)))
            && matches!(args.get(2), Some(MirValue::Const(0)))
    )));
}

#[test]
fn test_redirect_intrinsic_rejects_nonzero_flags_on_xdp() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(7),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        named: vec![(b"flags".to_vec(), RegId::new(2))],
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

    let hir_program = HirProgram::new(func, HashMap::new(), vec![], None);
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "redirect".to_string());
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let hir_types =
        infer_hir_types(&hir_program, &decl_names).expect("redirect intrinsic should type-check");

    let err = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("redirect should reject non-zero flags on xdp");

    match err {
        CompileError::UnsupportedInstruction(msg) => {
            assert!(
                msg.contains("helper 'bpf_redirect' requires arg1 = 0 in xdp programs"),
                "{msg}"
            );
        }
        other => panic!("unexpected lowering error: {other:?}"),
    }
}

#[test]
fn test_redirect_intrinsic_rejects_conflicting_mode_flags() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(7),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        flags: vec![b"peer".to_vec(), b"neigh".to_vec()],
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
        register_count: 2,
        file_count: 0,
    };

    let hir_program = HirProgram::new(func, HashMap::new(), vec![], None);
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "redirect".to_string());
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let hir_types =
        infer_hir_types(&hir_program, &decl_names).expect("redirect intrinsic should type-check");

    let err = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("redirect should reject conflicting mode flags");

    match err {
        CompileError::UnsupportedInstruction(msg) => {
            assert!(
                msg.contains("redirect accepts at most one of --peer or --neigh"),
                "{msg}"
            );
        }
        other => panic!("unexpected lowering error: {other:?}"),
    }
}

#[test]
fn test_redirect_intrinsic_rejects_non_packet_programs() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(7),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
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
        register_count: 2,
        file_count: 0,
    };

    let hir_program = HirProgram::new(func, HashMap::new(), vec![], None);
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "redirect".to_string());
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let hir_types =
        infer_hir_types(&hir_program, &decl_names).expect("redirect intrinsic should type-check");

    let err = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("redirect should be rejected outside xdp/tc");

    match err {
        CompileError::UnsupportedInstruction(msg) => {
            assert!(
                msg.contains("helper 'bpf_redirect' is only valid in xdp and tc programs"),
                "{msg}"
            );
        }
        other => panic!("unexpected lowering error: {other:?}"),
    }
}

#[test]
fn test_redirect_map_intrinsic_requires_explicit_kind_and_compiles() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String(b"demo_redirect_map".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(7),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String(b"devmap-hash".to_vec()),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1), RegId::new(2)],
                        named: vec![(b"kind".to_vec(), RegId::new(3))],
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
        register_count: 4,
        file_count: 0,
    };

    let hir_program = HirProgram::new(func, HashMap::new(), vec![], None);
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "redirect-map".to_string());
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let hir_types = infer_hir_types(&hir_program, &decl_names)
        .expect("redirect-map intrinsic should type-check");

    let mut result = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("redirect-map intrinsic should lower");

    let entry = result.program.main.entry;
    let block = result.program.main.block(entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadMapFd {
            map: MapRef { name, kind: MapKind::DevMapHash },
            ..
        } if name == "demo_redirect_map"
    )));
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::CallHelper {
            helper,
            args,
            ..
        } if *helper == BpfHelper::RedirectMap as u32 && args.len() == 3
    )));

    optimize_with_ssa_hints(
        &mut result.program.main,
        Some(&probe_ctx),
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );
    let compiled =
        compile_mir_to_ebpf_with_hints(&result.program, Some(&probe_ctx), Some(&result.type_hints))
            .expect("redirect-map intrinsic should compile");

    let map = compiled
        .maps
        .iter()
        .find(|map| map.name == "demo_redirect_map")
        .expect("expected redirect-map runtime artifact");
    assert_eq!(map.def.map_type, BpfMapType::DevMapHash as u32);
    assert_eq!(map.def.key_size, 4);
    assert_eq!(map.def.value_size, 8);
    assert!(
        compiled
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == "demo_redirect_map"),
        "expected redirect-map relocation"
    );
}

#[test]
fn test_tail_call_intrinsic_lowers_to_terminator_and_compiles() {
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

    let hir_program = HirProgram::new(func, HashMap::new(), vec![], None);
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "tail-call".to_string());
    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let hir_types =
        infer_hir_types(&hir_program, &decl_names).expect("tail-call intrinsic should type-check");

    let mut result = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("tail-call intrinsic should lower");

    let entry = result.program.main.entry;
    let block = result.program.main.block(entry);
    assert!(matches!(
        &block.terminator,
        MirInst::TailCall {
            prog_map: MapRef { name, kind: MapKind::ProgArray },
            index: MirValue::VReg(_),
        } if name == "dispatch_targets"
    ));

    optimize_with_ssa_hints(
        &mut result.program.main,
        Some(&probe_ctx),
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );
    let compiled =
        compile_mir_to_ebpf_with_hints(&result.program, Some(&probe_ctx), Some(&result.type_hints))
            .expect("tail-call intrinsic should compile");

    let map = compiled
        .maps
        .iter()
        .find(|map| map.name == "dispatch_targets")
        .expect("expected prog-array runtime artifact");
    assert_eq!(map.def.map_type, BpfMapType::ProgArray as u32);
    assert!(
        compiled
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == "dispatch_targets"),
        "expected prog-array relocation"
    );
}

#[test]
fn test_tail_call_intrinsic_rejects_following_non_cleanup_statement() {
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
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1), RegId::new(2)],
                        ..Default::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::Int(1),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![],
        ast: vec![],
        comments: vec![],
        register_count: 4,
        file_count: 0,
    };

    let hir_program = HirProgram::new(func, HashMap::new(), vec![], None);
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "tail-call".to_string());
    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let hir_types =
        infer_hir_types(&hir_program, &decl_names).expect("tail-call intrinsic should type-check");

    let err = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("tail-call followed by code should be rejected");

    match err {
        CompileError::UnsupportedInstruction(msg) => assert!(
            msg.contains("terminal eBPF command must be the final expression"),
            "{msg}"
        ),
        other => panic!("unexpected lowering error: {other:?}"),
    }
}

#[test]
fn test_redirect_map_intrinsic_rejects_non_xdp_programs() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String(b"demo_redirect_map".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(7),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String(b"devmap".to_vec()),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1), RegId::new(2)],
                        named: vec![(b"kind".to_vec(), RegId::new(3))],
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
        register_count: 4,
        file_count: 0,
    };

    let hir_program = HirProgram::new(func, HashMap::new(), vec![], None);
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "redirect-map".to_string());
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let hir_types = infer_hir_types(&hir_program, &decl_names)
        .expect("redirect-map intrinsic should still type-check before lowering");

    let err = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("redirect-map should be rejected outside xdp");

    match err {
        CompileError::UnsupportedInstruction(msg) => {
            assert!(
                msg.contains("helper 'bpf_redirect_map' is only valid in xdp programs"),
                "{msg}"
            );
        }
        other => panic!("unexpected lowering error: {other:?}"),
    }
}

#[test]
fn test_helper_call_ringbuf_query_literal_lowers_and_compiles() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String(b"bpf_ringbuf_query".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String(b"demo_ringbuf".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1), RegId::new(2), RegId::new(3)],
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
        register_count: 4,
        file_count: 0,
    };

    let hir_program = HirProgram::new(func, HashMap::new(), vec![], None);
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "helper-call".to_string());
    let hir_types = infer_hir_types(&hir_program, &decl_names)
        .expect("ringbuf_query helper-call should type-check");

    let mut result = lower_hir_to_mir_with_hints(
        &hir_program,
        None,
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("ringbuf_query helper-call should lower");

    let entry = result.program.main.entry;
    let block = result.program.main.block(entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadMapFd {
            map: MapRef { name, kind: MapKind::RingBuf },
            ..
        } if name == "demo_ringbuf"
    )));
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::CallHelper {
            helper,
            args,
            ..
        } if *helper == BpfHelper::RingbufQuery as u32 && args.len() == 2
    )));

    optimize_with_ssa_hints(
        &mut result.program.main,
        None,
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );
    let compiled = compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("ringbuf_query helper-call should compile");

    assert!(compiled.maps.iter().any(|map| {
        map.name == "demo_ringbuf" && map.def.map_type == BpfMapType::RingBuf as u32
    }));
    assert!(
        compiled
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == "demo_ringbuf"),
        "expected ringbuf relocation"
    );
}

#[test]
fn test_helper_call_task_storage_literal_lowers_and_compiles() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String(b"bpf_get_current_task_btf".to_vec()),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(2),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        ..Default::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String(b"bpf_task_storage_get".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::String(b"demo_task_storage".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(6),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(7),
                    args: HirCallArgs {
                        positional: vec![
                            RegId::new(3),
                            RegId::new(4),
                            RegId::new(2),
                            RegId::new(5),
                            RegId::new(6),
                        ],
                        ..Default::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(6) },
        }],
        entry: HirBlockId(0),
        spans: vec![],
        ast: vec![],
        comments: vec![],
        register_count: 8,
        file_count: 0,
    };

    let hir_program = HirProgram::new(func, HashMap::new(), vec![], None);
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "helper-call".to_string());
    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "tcp_connect");

    let mut result = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("task_storage_get helper-call should lower");

    let entry = result.program.main.entry;
    let block = result.program.main.block(entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadMapFd {
            map: MapRef { name, kind: MapKind::TaskStorage },
            ..
        } if name == "demo_task_storage"
    )));
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::CallHelper {
            helper,
            args,
            ..
        } if *helper == BpfHelper::TaskStorageGet as u32 && args.len() == 4
    )));

    optimize_with_ssa_hints(
        &mut result.program.main,
        Some(&probe_ctx),
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );
    let compiled =
        compile_mir_to_ebpf_with_hints(&result.program, Some(&probe_ctx), Some(&result.type_hints))
            .expect("task_storage_get helper-call should compile");

    let map = compiled
        .maps
        .iter()
        .find(|map| map.name == "demo_task_storage")
        .expect("expected task-storage runtime map");
    assert_eq!(map.def.map_type, BpfMapType::TaskStorage as u32);
    assert_eq!(map.def.key_size, 4);
    assert_eq!(map.def.value_size, 8);
    assert_eq!(map.def.max_entries, 0);
    assert_eq!(map.def.map_flags, 1);
    assert!(
        compiled
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == "demo_task_storage"),
        "expected task-storage map relocation"
    );
}

#[test]
fn test_helper_call_cgrp_storage_literal_lowers_and_compiles() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String(b"bpf_cgrp_storage_get".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String(b"demo_cgrp_storage".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(6),
                    args: HirCallArgs {
                        positional: vec![
                            RegId::new(1),
                            RegId::new(2),
                            RegId::new(3),
                            RegId::new(4),
                            RegId::new(5),
                        ],
                        ..Default::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(5) },
        }],
        entry: HirBlockId(0),
        spans: vec![],
        ast: vec![],
        comments: vec![],
        register_count: 7,
        file_count: 0,
    };

    let hir_program = HirProgram::new(func, HashMap::new(), vec![], None);
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "helper-call".to_string());
    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "tcp_connect");

    let mut result = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgrp_storage_get helper-call should lower");

    let entry = result.program.main.entry;
    let block = result.program.main.block(entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadMapFd {
            map: MapRef { name, kind: MapKind::CgrpStorage },
            ..
        } if name == "demo_cgrp_storage"
    )));
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::CallHelper {
            helper,
            args,
            ..
        } if *helper == BpfHelper::CgrpStorageGet as u32 && args.len() == 4
    )));

    optimize_with_ssa_hints(
        &mut result.program.main,
        Some(&probe_ctx),
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );
    let compiled =
        compile_mir_to_ebpf_with_hints(&result.program, Some(&probe_ctx), Some(&result.type_hints))
            .expect("cgrp_storage_get helper-call should compile");

    let map = compiled
        .maps
        .iter()
        .find(|map| map.name == "demo_cgrp_storage")
        .expect("expected cgrp-storage runtime map");
    assert_eq!(map.def.map_type, BpfMapType::CgrpStorage as u32);
    assert_eq!(map.def.key_size, 4);
    assert_eq!(map.def.value_size, 8);
    assert_eq!(map.def.max_entries, 0);
    assert_eq!(map.def.map_flags, 1);
    assert!(
        compiled
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == "demo_cgrp_storage"),
        "expected cgrp-storage map relocation"
    );
}

#[test]
fn test_helper_call_task_storage_init_value_shapes_map_layout() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String(b"bpf_get_current_task_btf".to_vec()),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(2),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        ..Default::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String(b"bpf_task_storage_get".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::String(b"demo_task_storage".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::String(b"storage-seed-value".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(6),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(7),
                    args: HirCallArgs {
                        positional: vec![
                            RegId::new(3),
                            RegId::new(4),
                            RegId::new(2),
                            RegId::new(5),
                            RegId::new(6),
                        ],
                        ..Default::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(6) },
        }],
        entry: HirBlockId(0),
        spans: vec![],
        ast: vec![],
        comments: vec![],
        register_count: 8,
        file_count: 0,
    };

    let hir_program = HirProgram::new(func, HashMap::new(), vec![], None);
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "helper-call".to_string());
    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "tcp_connect");
    let hir_types = infer_hir_types(&hir_program, &decl_names)
        .expect("task_storage_get helper-call should type-check");

    let mut result = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("task_storage_get helper-call should lower");

    let map_ref = MapRef {
        name: "demo_task_storage".to_string(),
        kind: MapKind::TaskStorage,
    };
    let map_value_ty = result
        .type_hints
        .generic_map_value_types
        .get(&map_ref)
        .expect("expected task-storage init to seed map value type");
    assert!(map_value_ty.size() > 8);

    optimize_with_ssa_hints(
        &mut result.program.main,
        Some(&probe_ctx),
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );
    let compiled =
        compile_mir_to_ebpf_with_hints(&result.program, Some(&probe_ctx), Some(&result.type_hints))
            .expect("task_storage_get helper-call should compile");

    let map = compiled
        .maps
        .iter()
        .find(|map| map.name == "demo_task_storage")
        .expect("expected task-storage runtime map");
    assert_eq!(map.def.map_type, BpfMapType::TaskStorage as u32);
    assert_eq!(map.def.value_size as usize, map_value_ty.size());
}

#[test]
fn test_helper_call_map_push_literal_queue_lowers_and_compiles() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String(b"bpf_map_push_elem".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String(b"demo_queue".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String(b"job".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::String(b"queue".to_vec()),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![
                            RegId::new(1),
                            RegId::new(2),
                            RegId::new(3),
                            RegId::new(4),
                        ],
                        named: vec![(b"kind".to_vec(), RegId::new(5))],
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
        register_count: 6,
        file_count: 0,
    };

    let hir_program = HirProgram::new(func, HashMap::new(), vec![], None);
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "helper-call".to_string());
    let hir_types =
        infer_hir_types(&hir_program, &decl_names).expect("map_push helper-call should type-check");

    let mut result = lower_hir_to_mir_with_hints(
        &hir_program,
        None,
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("map_push helper-call should lower");

    let entry = result.program.main.entry;
    let block = result.program.main.block(entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadMapFd {
            map: MapRef { name, kind: MapKind::Queue },
            ..
        } if name == "demo_queue"
    )));
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::CallHelper {
            helper,
            args,
            ..
        } if *helper == BpfHelper::MapPushElem as u32 && args.len() == 3
    )));

    optimize_with_ssa_hints(
        &mut result.program.main,
        None,
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );
    let compiled = compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("map_push helper-call should compile");

    let map = compiled
        .maps
        .iter()
        .find(|map| map.name == "demo_queue")
        .expect("expected queue runtime artifact");
    assert_eq!(map.def.map_type, BpfMapType::Queue as u32);
    assert!(map.def.value_size >= 3);
    assert!(
        compiled
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == "demo_queue"),
        "expected queue relocation"
    );
}

#[test]
fn test_helper_call_map_lookup_percpu_literal_lowers_and_compiles() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String(b"bpf_map_lookup_percpu_elem".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String(b"demo_percpu_hash".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String(b"key0".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::String(b"per-cpu-hash".to_vec()),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(6),
                    args: HirCallArgs {
                        positional: vec![
                            RegId::new(1),
                            RegId::new(2),
                            RegId::new(3),
                            RegId::new(4),
                        ],
                        named: vec![(b"kind".to_vec(), RegId::new(5))],
                        ..Default::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Int(0),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![],
        ast: vec![],
        comments: vec![],
        register_count: 7,
        file_count: 0,
    };

    let hir_program = HirProgram::new(func, HashMap::new(), vec![], None);
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "helper-call".to_string());
    let hir_types = infer_hir_types(&hir_program, &decl_names)
        .expect("map_lookup_percpu helper-call should type-check");

    let mut result = lower_hir_to_mir_with_hints(
        &hir_program,
        None,
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("map_lookup_percpu helper-call should lower");

    let entry = result.program.main.entry;
    let block = result.program.main.block(entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadMapFd {
            map: MapRef { name, kind: MapKind::PerCpuHash },
            ..
        } if name == "demo_percpu_hash"
    )));
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::CallHelper {
            helper,
            args,
            ..
        } if *helper == BpfHelper::MapLookupPercpuElem as u32 && args.len() == 3
    )));

    optimize_with_ssa_hints(
        &mut result.program.main,
        None,
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );
    let compiled = compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("map_lookup_percpu helper-call should compile");

    let map = compiled
        .maps
        .iter()
        .find(|map| map.name == "demo_percpu_hash")
        .expect("expected per-cpu hash runtime map");
    assert_eq!(map.def.map_type, BpfMapType::PerCpuHash as u32);
    assert!(
        compiled
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == "demo_percpu_hash"),
        "expected per-cpu hash relocation"
    );
}

#[test]
fn test_helper_call_map_lookup_percpu_literal_requires_kind() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String(b"bpf_map_lookup_percpu_elem".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String(b"demo_percpu_hash".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String(b"key0".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![
                            RegId::new(1),
                            RegId::new(2),
                            RegId::new(3),
                            RegId::new(4),
                        ],
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
        register_count: 5,
        file_count: 0,
    };

    let hir_program = HirProgram::new(func, HashMap::new(), vec![], None);
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "helper-call".to_string());
    let hir_types = infer_hir_types(&hir_program, &decl_names)
        .expect("map_lookup_percpu helper-call should type-check");

    let err = lower_hir_to_mir_with_hints(
        &hir_program,
        None,
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("map_lookup_percpu helper-call should require an explicit map kind");

    match err {
        CompileError::UnsupportedInstruction(msg) => {
            assert!(
                msg.contains("requires --kind per-cpu-hash"),
                "unexpected error: {msg}"
            );
        }
        other => panic!("unexpected lowering error: {other:?}"),
    }
}

#[test]
fn test_map_contains_bloom_filter_lowers_and_compiles() {
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
                    lit: HirLiteral::String(b"demo_bloom".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String(b"bloom-filter".to_vec()),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        named: vec![(b"kind".to_vec(), RegId::new(2))],
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

    let hir_program = HirProgram::new(func, HashMap::new(), vec![], None);
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "map-contains".to_string());
    let hir_types =
        infer_hir_types(&hir_program, &decl_names).expect("map-contains should type-check");

    let mut result = lower_hir_to_mir_with_hints(
        &hir_program,
        None,
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("map-contains should lower");

    let entry = result.program.main.entry;
    let block = result.program.main.block(entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::StoreSlot {
            val: MirValue::VReg(_),
            ty: MirType::I64,
            ..
        }
    )));
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadMapFd {
            map: MapRef { name, kind: MapKind::BloomFilter },
            ..
        } if name == "demo_bloom"
    )));
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::CallHelper {
            helper,
            args,
            ..
        } if *helper == BpfHelper::MapPeekElem as u32 && args.len() == 2
    )));
    assert_eq!(result.type_hints.main.get(&VReg(0)), Some(&MirType::Bool));

    optimize_with_ssa_hints(
        &mut result.program.main,
        None,
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );
    let compiled = compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("map-contains should compile");

    let map = compiled
        .maps
        .iter()
        .find(|map| map.name == "demo_bloom")
        .expect("expected bloom-filter runtime map");
    assert_eq!(map.def.map_type, BpfMapType::BloomFilter as u32);
    assert_eq!(map.def.key_size, 0);
    assert_eq!(map.def.value_size, 8);
}

fn make_cgroup_array_map_contains_hir() -> HirProgram {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Int(0),
                },
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
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1), RegId::new(3)],
                        named: vec![(b"kind".to_vec(), RegId::new(2))],
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
        register_count: 4,
        file_count: 0,
    };

    HirProgram::new(func, HashMap::new(), vec![], None)
}

#[test]
fn test_map_contains_cgroup_array_uses_skb_helper_on_tc() {
    let hir_program = make_cgroup_array_map_contains_hir();
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "map-contains".to_string());
    let hir_types =
        infer_hir_types(&hir_program, &decl_names).expect("map-contains should type-check");
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");

    let mut result = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup-array map-contains should lower");

    let entry = result.program.main.entry;
    let block = result.program.main.block(entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadMapFd {
            map: MapRef { name, kind: MapKind::CgroupArray },
            ..
        } if name == "tracked_cgroups"
    )));
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::CallHelper {
            helper,
            args,
            ..
        } if *helper == BpfHelper::SkbUnderCgroup as u32 && args.len() == 3
    )));
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::BinOp {
            op: BinOpKind::Eq,
            rhs: MirValue::Const(1),
            ..
        }
    )));
    assert_eq!(result.type_hints.main.get(&VReg(0)), Some(&MirType::Bool));

    optimize_with_ssa_hints(
        &mut result.program.main,
        Some(&probe_ctx),
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );
    let compiled =
        compile_mir_to_ebpf_with_hints(&result.program, Some(&probe_ctx), Some(&result.type_hints))
            .expect("tc cgroup-array map-contains should compile");

    let map = compiled
        .maps
        .iter()
        .find(|map| map.name == "tracked_cgroups")
        .expect("expected cgroup-array runtime map");
    assert_eq!(map.def.map_type, BpfMapType::CgroupArray as u32);
    assert_eq!(map.def.key_size, 4);
    assert_eq!(map.def.value_size, 4);
}

#[test]
fn test_map_contains_cgroup_array_uses_current_task_helper_off_tc() {
    let hir_program = make_cgroup_array_map_contains_hir();
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "map-contains".to_string());
    let hir_types =
        infer_hir_types(&hir_program, &decl_names).expect("map-contains should type-check");
    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");

    let mut result = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup-array map-contains should lower");

    let entry = result.program.main.entry;
    let block = result.program.main.block(entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::CallHelper {
            helper,
            args,
            ..
        } if *helper == BpfHelper::CurrentTaskUnderCgroup as u32 && args.len() == 2
    )));
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::BinOp {
            op: BinOpKind::Eq,
            rhs: MirValue::Const(1),
            ..
        }
    )));
    assert_eq!(result.type_hints.main.get(&VReg(0)), Some(&MirType::Bool));

    optimize_with_ssa_hints(
        &mut result.program.main,
        Some(&probe_ctx),
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );
    let compiled =
        compile_mir_to_ebpf_with_hints(&result.program, Some(&probe_ctx), Some(&result.type_hints))
            .expect("current-task cgroup-array map-contains should compile");

    let map = compiled
        .maps
        .iter()
        .find(|map| map.name == "tracked_cgroups")
        .expect("expected cgroup-array runtime map");
    assert_eq!(map.def.map_type, BpfMapType::CgroupArray as u32);
    assert_eq!(map.def.key_size, 4);
    assert_eq!(map.def.value_size, 4);
}

#[test]
fn test_map_contains_requires_membership_map_kind() {
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
                    lit: HirLiteral::String(b"demo_hash".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String(b"hash".to_vec()),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        named: vec![(b"kind".to_vec(), RegId::new(2))],
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

    let hir_program = HirProgram::new(func, HashMap::new(), vec![], None);
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "map-contains".to_string());
    let hir_types =
        infer_hir_types(&hir_program, &decl_names).expect("map-contains should type-check");

    let err = lower_hir_to_mir_with_hints(
        &hir_program,
        None,
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("map-contains should reject unsupported map kinds");

    match err {
        CompileError::UnsupportedInstruction(msg) => {
            assert!(
                msg.contains("requires --kind bloom-filter or --kind cgroup-array"),
                "{msg}"
            );
        }
        other => panic!("unexpected lowering error: {other:?}"),
    }
}
