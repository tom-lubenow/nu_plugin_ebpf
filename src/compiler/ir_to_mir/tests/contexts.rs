use super::helpers::*;
use super::*;
use crate::compiler::EbpfProgramType;
use crate::compiler::hir::{
    HirBlock, HirBlockId, HirFunction, HirLiteral, HirProgram, HirStmt, HirTerminator,
};
use crate::compiler::instruction::BpfHelper;
use crate::compiler::mir::{AddressSpace, CtxStoreTarget};
use crate::compiler::mir_to_ebpf::compile_mir_to_ebpf_with_hints;
use crate::compiler::passes::optimize_with_ssa_hints;
use crate::kernel_btf::{KernelBtf, TrampolineFieldSelector, TypeInfo};
use nu_protocol::ast::{CellPath, PathMember};
use nu_protocol::{DeclId, RegId, VarId};
use std::collections::HashMap;

#[test]
fn test_lower_xdp_action_alias_return_to_const() {
    let hir = make_return_literal_program(HirLiteral::String(b"pass".to_vec()));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("xdp action alias should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(matches!(
        block.terminator,
        MirInst::Return {
            val: Some(MirValue::Const(2))
        }
    ));
}

#[test]
fn test_lower_socket_filter_pass_alias_return_to_packet_len() {
    let hir = make_return_literal_program(HirLiteral::String(b"pass".to_vec()));
    let probe_ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("socket_filter pass alias should lower");

    let block = result.program.main.block(result.program.main.entry);
    let packet_len_vreg = block
        .instructions
        .iter()
        .find_map(|inst| match inst {
            MirInst::LoadCtxField {
                dst,
                field: CtxField::PacketLen,
                ..
            } => Some(*dst),
            _ => None,
        })
        .expect("expected socket_filter pass alias to load ctx.packet_len");

    assert!(matches!(
        block.terminator,
        MirInst::Return {
            val: Some(MirValue::VReg(vreg))
        } if vreg == packet_len_vreg
    ));
}

#[test]
fn test_lower_socket_filter_permit_alias_return_to_packet_len() {
    let hir = make_return_literal_program(HirLiteral::String(b"permit".to_vec()));
    let probe_ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("socket_filter permit alias should lower");

    let block = result.program.main.block(result.program.main.entry);
    let packet_len_vreg = block
        .instructions
        .iter()
        .find_map(|inst| match inst {
            MirInst::LoadCtxField {
                dst,
                field: CtxField::PacketLen,
                ..
            } => Some(*dst),
            _ => None,
        })
        .expect("expected socket_filter permit alias to load ctx.packet_len");

    assert!(matches!(
        block.terminator,
        MirInst::Return {
            val: Some(MirValue::VReg(vreg))
        } if vreg == packet_len_vreg
    ));
}

#[test]
fn test_lower_tc_action_alias_return_to_const() {
    let hir = make_return_literal_program(HirLiteral::String(b"ok".to_vec()));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("tc action alias should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(matches!(
        block.terminator,
        MirInst::Return {
            val: Some(MirValue::Const(0))
        }
    ));
}

#[test]
fn test_lower_cgroup_skb_action_alias_return_to_const() {
    let hir = make_return_literal_program(HirLiteral::String(b"allow".to_vec()));
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:egress");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_skb action alias should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(matches!(
        block.terminator,
        MirInst::Return {
            val: Some(MirValue::Const(1))
        }
    ));
}

#[test]
fn test_lower_cgroup_skb_ctx_sk_cgroup_id_projection_calls_helper() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("sk"), string_member("cgroup_id")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:ingress");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_skb ctx.sk.cgroup_id should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::Socket,
            ..
        }
    )));
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::Copy {
            src: MirValue::Const(0),
            ..
        }
    )));
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::BinOp {
            op: BinOpKind::Ne,
            rhs: MirValue::Const(0),
            ..
        }
    )));
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::CallHelper {
                    helper,
                    args,
                    ..
                } if *helper == BpfHelper::SkCgroupId as u32 && args.len() == 1
            )))
    );
    let helper_dst = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::CallHelper { dst, helper, .. } if *helper == BpfHelper::SkCgroupId as u32 => {
                Some(*dst)
            }
            _ => None,
        })
        .expect("expected socket cgroup helper destination");
    assert_eq!(result.type_hints.main.get(&helper_dst), Some(&MirType::U64));

    let compiled =
        compile_mir_to_ebpf_with_hints(&result.program, Some(&probe_ctx), Some(&result.type_hints))
            .expect("ctx.sk.cgroup_id should compile");
    let program = compiled.into_program(
        EbpfProgramType::CgroupSkb,
        "/sys/fs/cgroup:ingress",
        "main",
        HashMap::new(),
        HashMap::new(),
    );
    let requirement = program
        .helper_compatibility_requirements()
        .into_iter()
        .find(|requirement| requirement.helper() == BpfHelper::SkCgroupId)
        .expect("ctx.sk.cgroup_id should report bpf_sk_cgroup_id compatibility");
    assert_eq!(requirement.minimum_kernel(), "5.8");
}

#[test]
fn test_lower_bound_cgroup_skb_ctx_sk_cgroup_id_projection_calls_helper() {
    let hir = make_bound_ctx_path_program(
        CellPath {
            members: vec![string_member("sk")],
        },
        CellPath {
            members: vec![string_member("cgroup_id")],
        },
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:ingress");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("bound cgroup_skb ctx.sk cgroup_id should lower");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::CallHelper {
                    helper,
                    args,
                    ..
                } if *helper == BpfHelper::SkCgroupId as u32 && args.len() == 1
            )))
    );
}

#[test]
fn test_lower_cgroup_skb_ctx_sk_ancestor_cgroup_id_projection_calls_helper() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![
            string_member("sk"),
            string_member("ancestor_cgroup_id"),
            int_member(1),
        ],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:egress");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_skb ctx.sk.ancestor_cgroup_id.1 should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::Copy {
            src: MirValue::Const(0),
            ..
        }
    )));
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::CallHelper {
                    helper,
                    args,
                    ..
                } if *helper == BpfHelper::SkAncestorCgroupId as u32
                    && matches!(args.as_slice(), [MirValue::VReg(_), MirValue::Const(1)])
            )))
    );
    let helper_dst = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::CallHelper { dst, helper, .. }
                if *helper == BpfHelper::SkAncestorCgroupId as u32 =>
            {
                Some(*dst)
            }
            _ => None,
        })
        .expect("expected socket ancestor cgroup helper destination");
    assert_eq!(result.type_hints.main.get(&helper_dst), Some(&MirType::U64));
}

#[test]
fn test_lower_cgroup_skb_ctx_sk_ancestor_cgroup_id_projection_rejects_missing_level() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("sk"), string_member("ancestor_cgroup_id")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:egress");

    let err = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("ctx.sk.ancestor_cgroup_id without a level should be rejected");

    assert!(
        err.to_string()
            .contains("requires a constant numeric ancestor level")
    );
}

#[test]
fn test_lower_sk_msg_ctx_sk_ancestor_cgroup_id_projection_rejected() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![
            string_member("sk"),
            string_member("ancestor_cgroup_id"),
            int_member(0),
        ],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");

    let err = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("sk_msg ctx.sk.ancestor_cgroup_id should be rejected");

    assert!(
        err.to_string()
            .contains("helper 'bpf_sk_ancestor_cgroup_id' is only valid in cgroup_skb programs")
    );
}

#[test]
fn test_lower_sk_msg_ctx_sk_cgroup_id_projection_rejected() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("sk"), string_member("cgroup_id")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");

    let err = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("sk_msg ctx.sk.cgroup_id should be rejected");

    assert!(
        err.to_string()
            .contains("helper 'bpf_sk_cgroup_id' is only valid in cgroup_skb programs")
    );
}

fn assert_ctx_sk_helper_projection_lowers(
    program_type: EbpfProgramType,
    target: &str,
    members: Vec<PathMember>,
    expected_helper: BpfHelper,
    context: &str,
) {
    let hir = make_ctx_path_program(CellPath { members });
    let probe_ctx = ProbeContext::new(program_type, target);
    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .unwrap_or_else(|err| panic!("{context} should lower: {err}"));

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::Socket,
                    ..
                }
            )))
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::CallHelper {
                    helper: helper_id,
                    args,
                    ..
                } if *helper_id == expected_helper as u32 && args.len() == 1
            )))
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::Copy {
                    src: MirValue::Const(0),
                    ..
                }
            ))),
        "{context} should default to zero on null helper paths"
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadSlot {
                    ty: MirType::U32,
                    ..
                }
            ))),
        "{context} should load a scalar field from the helper-returned socket layout"
    );

    let compiled =
        compile_mir_to_ebpf_with_hints(&result.program, Some(&probe_ctx), Some(&result.type_hints))
            .unwrap_or_else(|err| panic!("{context} should compile: {err}"));
    let program =
        compiled.into_program(program_type, target, "main", HashMap::new(), HashMap::new());
    let requirement = program
        .helper_compatibility_requirements()
        .into_iter()
        .find(|requirement| requirement.helper() == expected_helper)
        .unwrap_or_else(|| {
            panic!(
                "{context} should report {} compatibility metadata",
                expected_helper.name()
            )
        });
    assert_eq!(requirement.minimum_kernel(), "5.1");
}

#[test]
fn test_lower_cgroup_sockopt_ctx_sk_tcp_metric_projection_calls_helper() {
    assert_ctx_sk_helper_projection_lowers(
        EbpfProgramType::CgroupSockopt,
        "/sys/fs/cgroup:get",
        vec![
            string_member("sk"),
            string_member("tcp"),
            string_member("snd_cwnd"),
        ],
        BpfHelper::TcpSock,
        "cgroup_sockopt ctx.sk.tcp.snd_cwnd",
    );
}

#[test]
fn test_lower_bound_cgroup_sockopt_ctx_sk_tcp_metric_projection_calls_helper() {
    let hir = make_bound_ctx_path_program(
        CellPath {
            members: vec![string_member("sk")],
        },
        CellPath {
            members: vec![string_member("tcp"), string_member("snd_cwnd")],
        },
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("bound cgroup_sockopt ctx.sk tcp metric should lower");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                    inst,
                    MirInst::CallHelper {
                        helper,
                        args,
                        ..
                    } if *helper == BpfHelper::TcpSock as u32 && args.len() == 1
            ))),
        "bound socket projection should call bpf_tcp_sock"
    );
    let compiled =
        compile_mir_to_ebpf_with_hints(&result.program, Some(&probe_ctx), Some(&result.type_hints))
            .expect("bound ctx.sk.tcp projection should compile");
    let program = compiled.into_program(
        EbpfProgramType::CgroupSockopt,
        "/sys/fs/cgroup:get",
        "main",
        HashMap::new(),
        HashMap::new(),
    );
    let helper_requirements = program.helper_compatibility_requirements();
    let helper_requirement = helper_requirements
        .iter()
        .find(|requirement| requirement.helper() == BpfHelper::TcpSock)
        .expect("bound ctx.sk.tcp projection should report bpf_tcp_sock compatibility");
    assert_eq!(helper_requirement.minimum_kernel(), "5.1");
    let probe_read_requirement = helper_requirements
        .iter()
        .find(|requirement| requirement.helper() == BpfHelper::ProbeReadKernel)
        .expect("bound ctx.sk.tcp field read should report probe_read_kernel compatibility");
    assert_eq!(probe_read_requirement.minimum_kernel(), "5.5");
    assert_eq!(program.helper_compatibility_minimum_kernel(), Some("5.5"));

    let socket_requirement = program
        .context_field_compatibility_requirements()
        .into_iter()
        .find(|requirement| requirement.key() == "ctx:sk")
        .expect("bound ctx.sk.tcp projection should preserve ctx.sk compatibility metadata");
    assert_eq!(socket_requirement.minimum_kernel(), "5.3");
    assert_eq!(
        program.context_field_compatibility_minimum_kernel(),
        Some("5.3")
    );
    assert_eq!(program.compatibility_minimum_kernel(), Some("5.5"));
}

#[test]
fn test_lower_tc_ctx_sk_full_projection_calls_helper() {
    assert_ctx_sk_helper_projection_lowers(
        EbpfProgramType::Tc,
        "lo:ingress",
        vec![
            string_member("sk"),
            string_member("full"),
            string_member("family"),
        ],
        BpfHelper::SkFullsock,
        "tc ctx.sk.full.family",
    );
}

#[test]
fn test_lower_cgroup_skb_ctx_sk_listener_projection_calls_helper() {
    assert_ctx_sk_helper_projection_lowers(
        EbpfProgramType::CgroupSkb,
        "/sys/fs/cgroup:ingress",
        vec![
            string_member("sk"),
            string_member("listener"),
            string_member("family"),
        ],
        BpfHelper::GetListenerSock,
        "cgroup_skb ctx.sk.listener.family",
    );
}

#[test]
fn test_lower_kprobe_ctx_task_pt_regs_arg_projection_calls_helper() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![
            string_member("task"),
            string_member("pt_regs"),
            string_member("arg0"),
        ],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "tcp_connect");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("kprobe ctx.task.pt_regs.arg0 should lower");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::Task,
                    ..
                }
            ))),
        "projection should load ctx.task"
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::CallHelper {
                    helper,
                    args,
                    ..
                } if *helper == BpfHelper::TaskPtRegs as u32 && args.len() == 1
            ))),
        "projection should call bpf_task_pt_regs"
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::CallHelper { helper, args, .. }
                    if *helper == BpfHelper::ProbeReadKernel as u32 && args.len() == 3
            ))),
        "projection should read the selected register through probe_read_kernel"
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadSlot {
                    ty: MirType::U64,
                    ..
                }
            ))),
        "projection should load a u64 register value"
    );
}

#[test]
fn test_lower_ctx_sk_tcp_projection_rejects_missing_metric() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("sk"), string_member("tcp")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");

    let err = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("bare ctx.sk.tcp should be rejected");

    assert!(
        err.to_string()
            .contains("requires a socket field after ctx.sk.tcp")
    );
}

#[test]
fn test_lower_sk_lookup_ctx_sk_tcp_projection_rejected() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![
            string_member("sk"),
            string_member("tcp"),
            string_member("snd_cwnd"),
        ],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");

    let err = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("sk_lookup ctx.sk.tcp.snd_cwnd should be rejected");

    assert!(
        err.to_string()
            .contains("helper 'bpf_tcp_sock' is only valid")
    );
}

#[test]
fn test_lower_cgroup_sock_action_alias_return_to_const() {
    let hir = make_return_literal_program(HirLiteral::String(b"allow".to_vec()));
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_create");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sock action alias should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(matches!(
        block.terminator,
        MirInst::Return {
            val: Some(MirValue::Const(1))
        }
    ));
}

#[test]
fn test_lower_cgroup_sock_addr_action_alias_return_to_const() {
    let hir = make_return_literal_program(HirLiteral::String(b"deny".to_vec()));
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect4");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sock_addr action alias should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(matches!(
        block.terminator,
        MirInst::Return {
            val: Some(MirValue::Const(0))
        }
    ));
}

#[test]
fn test_lower_cgroup_sysctl_action_alias_return_to_const() {
    let hir = make_return_literal_program(HirLiteral::String(b"allow".to_vec()));
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSysctl, "/sys/fs/cgroup");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sysctl action alias should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(matches!(
        block.terminator,
        MirInst::Return {
            val: Some(MirValue::Const(1))
        }
    ));
}

#[test]
fn test_lower_cgroup_sysctl_ctx_write_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("write")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSysctl, "/sys/fs/cgroup");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sysctl ctx.write should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::SysctlWrite,
            ..
        }
    )));
}

#[test]
fn test_lower_cgroup_sysctl_ctx_name_fields() {
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSysctl, "/sys/fs/cgroup");

    for (field_name, expected_field) in [
        ("sysctl_name", CtxField::SysctlName),
        ("name", CtxField::SysctlName),
        ("sysctl_base_name", CtxField::SysctlBaseName),
        ("base_name", CtxField::SysctlBaseName),
        ("sysctl_current_value", CtxField::SysctlCurrentValue),
        ("current_value", CtxField::SysctlCurrentValue),
        ("sysctl_new_value", CtxField::SysctlNewValue),
        ("new_value", CtxField::SysctlNewValue),
    ] {
        let hir = make_ctx_path_program(CellPath {
            members: vec![string_member(field_name)],
        });

        let result = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &HashMap::new(),
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap_or_else(|err| panic!("cgroup_sysctl ctx.{field_name} should lower: {err}"));

        let block = result.program.main.block(result.program.main.entry);
        assert!(block.instructions.iter().any(|inst| matches!(
            inst,
            MirInst::LoadCtxField {
                field,
                slot: Some(_),
                ..
            } if field == &expected_field
        )));
    }
}

#[test]
fn test_lower_cgroup_sysctl_ctx_file_pos_assignment() {
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
                        members: vec![string_member("file_pos")],
                    })),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(4),
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                    new_value: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String(b"allow".to_vec()),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(3) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 4,
        file_count: 0,
    };
    let hir = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSysctl, "/sys/fs/cgroup");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sysctl ctx.file_pos assignment should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::StoreCtxField {
            target: CtxStoreTarget::SysctlFilePos,
            ty: MirType::U32,
            ..
        }
    )));
}

#[test]
fn test_lower_cgroup_sysctl_ctx_new_value_assignment() {
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
                        members: vec![string_member("new_value")],
                    })),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String(b"1".to_vec()),
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                    new_value: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String(b"allow".to_vec()),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(3) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 4,
        file_count: 0,
    };
    let hir = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSysctl, "/sys/fs/cgroup");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sysctl ctx.new_value assignment should lower");

    assert!(
        result
            .type_hints
            .used_ctx_fields
            .contains(&CtxField::SysctlNewValue),
        "ctx.new_value assignment should preserve source-level context compatibility metadata"
    );

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::CallHelper {
            helper,
            args,
            ..
        } if *helper == BpfHelper::SysctlSetNewValue as u32
            && matches!(args.as_slice(), [
                MirValue::VReg(_),
                MirValue::VReg(_),
                MirValue::Const(1),
            ])
    )));

    let compiled =
        compile_mir_to_ebpf_with_hints(&result.program, Some(&probe_ctx), Some(&result.type_hints))
            .expect("cgroup_sysctl ctx.new_value assignment should compile");
    assert!(compiled.used_ctx_fields.contains(&CtxField::SysctlNewValue));

    let program = compiled.into_program(
        EbpfProgramType::CgroupSysctl,
        "/sys/fs/cgroup",
        "main",
        HashMap::new(),
        HashMap::new(),
    );
    let helper_requirement = program
        .helper_compatibility_requirements()
        .into_iter()
        .find(|requirement| requirement.helper() == BpfHelper::SysctlSetNewValue)
        .expect("ctx.new_value assignment should report bpf_sysctl_set_new_value metadata");
    assert_eq!(helper_requirement.minimum_kernel(), "5.2");
    let context_requirement = program
        .context_field_compatibility_requirements()
        .into_iter()
        .find(|requirement| requirement.field() == &CtxField::SysctlNewValue)
        .expect("ctx.new_value assignment should report sysctl_new_value context metadata");
    assert_eq!(context_requirement.minimum_kernel(), "5.2");
    assert_eq!(program.helper_compatibility_minimum_kernel(), Some("5.2"));
    assert_eq!(program.compatibility_minimum_kernel(), Some("5.2"));
}

#[test]
fn test_lower_cgroup_sysctl_ctx_alias_new_value_assignment_preserves_metadata() {
    let ctx_var = VarId::new(0);
    let alias_var = VarId::new(1);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: ctx_var,
                },
                HirStmt::StoreVariable {
                    var_id: alias_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: alias_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("new_value")],
                    })),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String(b"1".to_vec()),
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                    new_value: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String(b"allow".to_vec()),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(3) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 4,
        file_count: 0,
    };
    let hir = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSysctl, "/sys/fs/cgroup");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sysctl aliased ctx.new_value assignment should lower");

    assert!(
        result
            .type_hints
            .used_ctx_fields
            .contains(&CtxField::SysctlNewValue),
        "aliased ctx.new_value assignment should preserve context compatibility metadata"
    );

    let compiled =
        compile_mir_to_ebpf_with_hints(&result.program, Some(&probe_ctx), Some(&result.type_hints))
            .expect("cgroup_sysctl aliased ctx.new_value assignment should compile");
    assert!(compiled.used_ctx_fields.contains(&CtxField::SysctlNewValue));

    let program = compiled.into_program(
        EbpfProgramType::CgroupSysctl,
        "/sys/fs/cgroup",
        "main",
        HashMap::new(),
        HashMap::new(),
    );
    assert!(
        program
            .helper_compatibility_requirements()
            .into_iter()
            .any(|requirement| requirement.helper() == BpfHelper::SysctlSetNewValue)
    );
    assert!(
        program
            .context_field_compatibility_requirements()
            .into_iter()
            .any(|requirement| requirement.field() == &CtxField::SysctlNewValue)
    );
}

#[test]
fn test_lower_cgroup_sysctl_ctx_alias_new_value_read_preserves_metadata() {
    let ctx_var = VarId::new(0);
    let alias_var = VarId::new(1);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: ctx_var,
                },
                HirStmt::StoreVariable {
                    var_id: alias_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: alias_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("new_value")],
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
            ],
            terminator: HirTerminator::Return { src: RegId::new(2) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 3,
        file_count: 0,
    };
    let hir = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSysctl, "/sys/fs/cgroup");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sysctl aliased ctx.new_value read should lower");

    assert!(
        result.program.main.blocks.iter().any(|block| {
            block.instructions.iter().any(|inst| {
                matches!(
                    inst,
                    MirInst::LoadCtxField {
                        field: CtxField::SysctlNewValue,
                        slot: Some(_),
                        ..
                    }
                )
            })
        }),
        "aliased ctx.new_value read should lower to a helper-backed context load"
    );

    let compiled =
        compile_mir_to_ebpf_with_hints(&result.program, Some(&probe_ctx), Some(&result.type_hints))
            .expect("cgroup_sysctl aliased ctx.new_value read should compile");
    assert!(
        compiled.used_ctx_fields.contains(&CtxField::SysctlNewValue),
        "compiled aliased ctx.new_value read should preserve context compatibility metadata"
    );

    let program = compiled.into_program(
        EbpfProgramType::CgroupSysctl,
        "/sys/fs/cgroup",
        "main",
        HashMap::new(),
        HashMap::new(),
    );
    assert!(
        program
            .helper_compatibility_requirements()
            .into_iter()
            .any(|requirement| requirement.helper() == BpfHelper::SysctlGetNewValue)
    );
    assert!(
        program
            .context_field_compatibility_requirements()
            .into_iter()
            .any(|requirement| requirement.field() == &CtxField::SysctlNewValue)
    );
}

#[test]
fn test_lower_cgroup_sock_addr_ctx_sun_path_assignment_records_kfunc_metadata() {
    let hir = make_ctx_upsert_program(
        CellPath {
            members: vec![string_member("sun_path")],
        },
        HirLiteral::String(b"/tmp/nu-ebpf.sock".to_vec()),
    );
    let probe_ctx = ProbeContext::new(
        EbpfProgramType::CgroupSockAddr,
        "/sys/fs/cgroup:connect_unix",
    );

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sock_addr ctx.sun_path assignment should lower");

    assert!(result.program.main.blocks.iter().any(|block| {
        block.instructions.iter().any(|inst| {
            matches!(
                inst,
                MirInst::CallKfunc { kfunc, .. } if kfunc == "bpf_sock_addr_set_sun_path"
            )
        })
    }));

    let compiled =
        compile_mir_to_ebpf_with_hints(&result.program, Some(&probe_ctx), Some(&result.type_hints))
            .expect("cgroup_sock_addr ctx.sun_path assignment should compile");
    assert!(compiled.used_kfuncs.contains("bpf_sock_addr_set_sun_path"));

    let program = compiled.into_program(
        EbpfProgramType::CgroupSockAddr,
        "/sys/fs/cgroup:connect_unix",
        "main",
        HashMap::new(),
        HashMap::new(),
    );
    let requirement = program
        .kfunc_compatibility_requirements()
        .into_iter()
        .find(|requirement| requirement.name() == "bpf_sock_addr_set_sun_path")
        .expect("ctx.sun_path assignment should report bpf_sock_addr_set_sun_path metadata");
    assert_eq!(requirement.minimum_kernel(), "6.7");
    assert_eq!(program.kfunc_compatibility_minimum_kernel(), Some("6.7"));
    assert_eq!(program.compatibility_minimum_kernel(), Some("6.7"));
}

#[test]
fn test_lower_cgroup_sock_ctx_family_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("family")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_create");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sock ctx.family should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::Family,
            ..
        }
    )));
}

#[test]
fn test_lower_cgroup_sock_ctx_socket_family_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("sk"), string_member("family")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_create");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sock ctx.sk.family should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::Socket,
            ..
        }
    )));
}

#[test]
fn test_lower_cgroup_sock_ctx_state_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("state")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_create");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sock ctx.state should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::SockState,
            ..
        }
    )));
}

#[test]
fn test_lower_cgroup_sock_release_ctx_bound_dev_if_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("bound_dev_if")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_release");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sock sock_release ctx.bound_dev_if should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::BoundDevIf,
            ..
        }
    )));
}

#[test]
fn test_lower_cgroup_sock_release_ctx_priority_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("priority")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_release");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sock sock_release ctx.priority should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::SockPriority,
            ..
        }
    )));
}

#[test]
fn test_lower_tc_ctx_socket_family_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("sk"), string_member("family")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("tc ctx.sk.family should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::Socket,
            ..
        }
    )));
}

#[test]
fn test_tc_ctx_socket_projection_reports_kernel_read_compatibility() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("sk"), string_member("family")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("tc ctx.sk.family should lower");
    let compiled =
        compile_mir_to_ebpf_with_hints(&result.program, Some(&probe_ctx), Some(&result.type_hints))
            .expect("tc ctx.sk.family should compile");
    let program = compiled.into_program(
        EbpfProgramType::Tc,
        "lo:ingress",
        "main",
        HashMap::new(),
        HashMap::new(),
    );

    let helper_requirement = program
        .helper_compatibility_requirements()
        .into_iter()
        .find(|requirement| requirement.helper() == BpfHelper::ProbeReadKernel)
        .expect("ctx.sk.family should report probe_read_kernel compatibility");
    assert_eq!(helper_requirement.minimum_kernel(), "5.5");
    assert_eq!(program.helper_compatibility_minimum_kernel(), Some("5.5"));
    assert_eq!(program.compatibility_minimum_kernel(), Some("5.5"));
}

#[test]
fn test_lower_tc_ctx_tstamp_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("tstamp")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("tc ctx.tstamp should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::Tstamp,
            ..
        }
    )));
}

#[test]
fn test_lower_tc_ctx_tstamp_type_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("tstamp_type")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("tc ctx.tstamp_type should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::TstampType,
            ..
        }
    )));
}

#[test]
fn test_lower_kprobe_reserved_sock_ops_name_reports_sock_ops_error() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("op")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "do_sys_openat2");

    let err = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("kprobe ctx.op should be rejected through sock_ops context validation");

    assert!(
        err.to_string()
            .contains("ctx.op is only available on sock_ops programs")
    );
}

#[test]
fn test_lower_kprobe_reserved_cgroup_device_name_reports_device_error() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("access_type")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "do_sys_openat2");

    let err = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("kprobe ctx.access_type should be rejected through cgroup_device validation");

    assert!(
        err.to_string()
            .contains("ctx.access_type is only available on cgroup_device programs")
    );
}

#[test]
fn test_lower_kprobe_ifindex_alias_reports_packet_context_error() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("ifindex")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "do_sys_openat2");

    let err = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("kprobe ctx.ifindex should be rejected through packet-context validation");

    assert!(err
        .to_string()
        .contains("ctx.ifindex is only available on socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, sk_skb, and sk_skb_parser programs"));
}

#[test]
fn test_lower_tracepoint_reserved_sock_ops_name_stays_tracepoint_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("op")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tracepoint, "sched/sched_switch");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("typed tracepoint ctx.op should still lower as a tracepoint field");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::TracepointField(name),
            ..
        } if name == "op"
    )));
}

#[test]
fn test_lower_raw_tracepoint_ctx_arg_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("arg0")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::RawTracepoint, "sys_enter");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("raw tracepoint ctx.arg0 should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::Arg(0),
            ..
        }
    )));
}

#[test]
fn test_lower_raw_tracepoint_writable_ctx_arg_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("arg0")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::RawTracepointWritable, "sys_enter");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("writable raw tracepoint ctx.arg0 should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::Arg(0),
            ..
        }
    )));
}

#[test]
fn test_lower_perf_event_ctx_arg_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("arg0")],
    });
    let probe_ctx = ProbeContext::new(
        EbpfProgramType::PerfEvent,
        "software:cpu-clock:period=100000",
    );

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("perf_event ctx.arg0 should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::Arg(0),
            ..
        }
    )));
}

#[test]
fn test_lower_cgroup_sock_post_bind_ctx_socket_src_port_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("sk"), string_member("src_port")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:post_bind4");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sock post_bind4 ctx.sk.src_port should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::Socket,
            ..
        }
    )));
}

#[test]
fn test_lower_cgroup_sock_post_bind_ctx_socket_local_alias_fields() {
    for (member, expected_field) in [
        ("local_port", CtxField::LocalPort),
        ("local_ip4", CtxField::LocalIp4),
        ("remote_port", CtxField::RemotePort),
        ("remote_ip4", CtxField::RemoteIp4),
    ] {
        let hir = make_ctx_path_program(CellPath {
            members: vec![string_member("sk"), string_member(member)],
        });
        let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:post_bind4");

        let result = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &HashMap::new(),
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap_or_else(|err| panic!("cgroup_sock post_bind4 ctx.sk.{member} should lower: {err}"));

        assert!(
            result.type_hints.used_ctx_fields.contains(&expected_field),
            "ctx.sk.{member} should imply {expected_field:?} compatibility metadata"
        );
        compile_mir_to_ebpf_with_hints(&result.program, Some(&probe_ctx), Some(&result.type_hints))
            .unwrap_or_else(|err| panic!("cgroup_sock ctx.sk.{member} should compile: {err}"));
    }
}

#[test]
fn test_lower_sk_reuseport_migrating_socket_remote_alias_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("migrating_sk"), string_member("remote_port")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkReuseport, "migrate");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sk_reuseport ctx.migrating_sk.remote_port should lower");

    assert!(
        result
            .type_hints
            .used_ctx_fields
            .contains(&CtxField::RemotePort),
        "ctx.migrating_sk.remote_port should imply remote_port compatibility metadata"
    );
    compile_mir_to_ebpf_with_hints(&result.program, Some(&probe_ctx), Some(&result.type_hints))
        .expect("sk_reuseport ctx.migrating_sk.remote_port should compile");
}

#[test]
fn test_lower_ctx_socket_projection_records_implied_context_compatibility_fields() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("sk"), string_member("mark")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_create");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sock ctx.sk.mark should lower");

    assert!(
        result
            .type_hints
            .used_ctx_fields
            .contains(&CtxField::SockMark)
    );

    let compiled =
        compile_mir_to_ebpf_with_hints(&result.program, Some(&probe_ctx), Some(&result.type_hints))
            .expect("ctx.sk.mark should compile");
    let program = compiled.into_program(
        EbpfProgramType::CgroupSock,
        "/sys/fs/cgroup:sock_create",
        "main",
        HashMap::new(),
        HashMap::new(),
    );
    let requirements = program.context_field_compatibility_requirements();

    let mark = requirements
        .iter()
        .find(|requirement| requirement.key() == "ctx:mark")
        .expect("ctx.sk.mark should imply ctx.mark compatibility metadata");
    assert_eq!(mark.minimum_kernel(), "4.14");
    assert_eq!(
        program.context_field_compatibility_minimum_kernel(),
        Some("4.14")
    );

    let rx_hir = make_ctx_path_program(CellPath {
        members: vec![string_member("sk"), string_member("rx_queue_mapping")],
    });
    let sock_ops_ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
    let rx_result = lower_hir_to_mir_with_hints(
        &rx_hir,
        Some(&sock_ops_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sock_ops ctx.sk.rx_queue_mapping should lower");

    assert!(
        rx_result
            .type_hints
            .used_ctx_fields
            .contains(&CtxField::SockRxQueueMapping)
    );
    let rx_compiled = compile_mir_to_ebpf_with_hints(
        &rx_result.program,
        Some(&sock_ops_ctx),
        Some(&rx_result.type_hints),
    )
    .expect("ctx.sk.rx_queue_mapping should compile");
    let rx_program = rx_compiled.into_program(
        EbpfProgramType::SockOps,
        "/sys/fs/cgroup",
        "main",
        HashMap::new(),
        HashMap::new(),
    );
    assert_eq!(
        rx_program.context_field_compatibility_minimum_kernel(),
        Some("5.8")
    );
}

#[test]
fn test_lower_cgroup_sock_ctx_remote_port_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("remote_port")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_create");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sock ctx.remote_port should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::RemotePort,
            ..
        }
    )));
}

#[test]
fn test_lower_cgroup_sock_ctx_rx_queue_mapping_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("rx_queue_mapping")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_create");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sock ctx.rx_queue_mapping should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::SockRxQueueMapping,
            ..
        }
    )));
}

#[test]
fn test_lower_cgroup_sock_post_bind_ctx_local_port_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("local_port")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:post_bind4");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sock post_bind4 ctx.local_port should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::LocalPort,
            ..
        }
    )));
}

#[test]
fn test_lower_ctx_pid_type_hint_is_u32() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("pid")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "sys_clone");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("ctx.pid should lower");

    let block = result.program.main.block(result.program.main.entry);
    let pid_vreg = block
        .instructions
        .iter()
        .find_map(|inst| match inst {
            MirInst::LoadCtxField {
                dst,
                field: CtxField::Pid,
                ..
            } => Some(*dst),
            _ => None,
        })
        .expect("expected ctx.pid load");

    assert_eq!(result.type_hints.main.get(&pid_vreg), Some(&MirType::U32));
}

#[test]
fn test_lower_cgroup_sock_create_ctx_socket_src_port_rejected() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("sk"), string_member("src_port")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_create");

    let err = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("cgroup_sock sock_create ctx.sk.src_port should be rejected");

    let msg = err.to_string();
    assert!(
        msg.contains(
            "ctx.sk.src_port is only available on cgroup_sock post_bind4/post_bind6 hooks"
        ),
        "unexpected error: {msg}"
    );
}

#[test]
fn test_lower_cgroup_sock_create_ctx_socket_dst_port_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("sk"), string_member("dst_port")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_create");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sock sock_create ctx.sk.dst_port should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::Socket,
            ..
        }
    )));
}

#[test]
fn test_lower_cgroup_sock_post_bind4_ctx_socket_src_ip6_rejected() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("sk"), string_member("src_ip6"), int_member(0)],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:post_bind4");

    let err = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("cgroup_sock post_bind4 ctx.sk.src_ip6 should be rejected");

    assert!(
        err.to_string()
            .contains("ctx.sk.src_ip6 is only available on cgroup_sock post_bind6 hooks")
    );
}

#[test]
fn test_lower_cgroup_sock_post_bind4_ctx_socket_local_ip6_alias_rejected() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![
            string_member("sk"),
            string_member("local_ip6"),
            int_member(0),
        ],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:post_bind4");

    let err = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("cgroup_sock post_bind4 ctx.sk.local_ip6 should be rejected");

    assert!(
        err.to_string()
            .contains("ctx.sk.local_ip6 is only available on cgroup_sock post_bind6 hooks")
    );
}

#[test]
fn test_lower_cgroup_sock_create_ctx_local_port_rejected() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("local_port")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_create");

    let err = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("cgroup_sock sock_create ctx.local_port should be rejected");

    assert!(
        err.to_string().contains(
            "ctx.local_port is only available on cgroup_sock post_bind4/post_bind6 hooks"
        )
    );
}

#[test]
fn test_lower_sk_msg_ctx_socket_state_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("sk"), string_member("state")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sk_msg ctx.sk.state should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::Socket,
            ..
        }
    )));
}

#[test]
fn test_lower_cgroup_sockopt_action_alias_return_to_const() {
    let hir = make_return_literal_program(HirLiteral::String(b"allow".to_vec()));
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sockopt action alias should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(matches!(
        block.terminator,
        MirInst::Return {
            val: Some(MirValue::Const(1))
        }
    ));
}

#[test]
fn test_lower_cgroup_sockopt_ctx_socket_family_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("sk"), string_member("family")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sockopt ctx.sk.family should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::Socket,
            ..
        }
    )));
}

#[test]
fn test_lower_cgroup_sock_addr_ctx_socket_family_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("sk"), string_member("family")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect4");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sock_addr ctx.sk.family should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::Socket,
            ..
        }
    )));
}

#[test]
fn test_lower_cgroup_sockopt_ctx_sockopt_retval_assignment() {
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
                        members: vec![string_member("sockopt_retval")],
                    })),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                    new_value: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String(b"allow".to_vec()),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(3) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 4,
        file_count: 0,
    };
    let hir = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sockopt ctx.sockopt_retval assignment should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::StoreCtxField {
            target: CtxStoreTarget::SockoptRetval,
            ty: MirType::I32,
            ..
        }
    )));
}

#[test]
fn test_lower_cgroup_sockopt_ctx_retval_alias_assignment() {
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
                        members: vec![string_member("retval")],
                    })),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                    new_value: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String(b"allow".to_vec()),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(3) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 4,
        file_count: 0,
    };
    let hir = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sockopt ctx.retval assignment should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::StoreCtxField {
            target: CtxStoreTarget::SockoptRetval,
            ty: MirType::I32,
            ..
        }
    )));
}

#[test]
fn test_lower_cgroup_sockopt_ctx_level_and_optname_assignment() {
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
                        members: vec![string_member("level")],
                    })),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                    new_value: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("optname")],
                    })),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::Int(2),
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(3),
                    new_value: RegId::new(4),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::String(b"allow".to_vec()),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(5) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 6,
        file_count: 0,
    };
    let hir = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:set");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sockopt ctx.level/ctx.optname assignment should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::StoreCtxField {
            target: CtxStoreTarget::SockoptLevel,
            ty: MirType::I32,
            ..
        }
    )));
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::StoreCtxField {
            target: CtxStoreTarget::SockoptOptname,
            ty: MirType::I32,
            ..
        }
    )));
}

#[test]
fn test_lower_cgroup_sockopt_ctx_optlen_assignment() {
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
                        members: vec![string_member("optlen")],
                    })),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(8),
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                    new_value: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String(b"allow".to_vec()),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(3) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 4,
        file_count: 0,
    };
    let hir = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sockopt ctx.optlen assignment should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::StoreCtxField {
            target: CtxStoreTarget::SockoptOptlen,
            ty: MirType::I32,
            ..
        }
    )));
}

#[test]
fn test_lower_cgroup_sock_addr_ctx_user_ip4_assignment() {
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
                        members: vec![string_member("user_ip4")],
                    })),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(0x7f000001),
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                    new_value: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String(b"allow".to_vec()),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(3) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 4,
        file_count: 0,
    };
    let hir = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect4");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sock_addr ctx.user_ip4 assignment should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::StoreCtxField {
            target: CtxStoreTarget::CgroupSockAddrUserIp4,
            ty: MirType::U32,
            ..
        }
    )));
}

#[test]
fn test_lower_cgroup_sock_addr_ctx_user_port_assignment() {
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
                        members: vec![string_member("user_port")],
                    })),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(8080),
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                    new_value: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String(b"allow".to_vec()),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(3) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 4,
        file_count: 0,
    };
    let hir = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect4");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sock_addr ctx.user_port assignment should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::StoreCtxField {
            target: CtxStoreTarget::CgroupSockAddrUserPort,
            ty: MirType::U32,
            ..
        }
    )));
}

#[test]
fn test_lower_cgroup_sock_addr_ctx_user_ip6_index_assignment() {
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
                        members: vec![string_member("user_ip6"), int_member(0)],
                    })),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(0x20010db8),
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                    new_value: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String(b"allow".to_vec()),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(3) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 4,
        file_count: 0,
    };
    let hir = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect6");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sock_addr ctx.user_ip6.0 assignment should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::StoreCtxField {
            target: CtxStoreTarget::CgroupSockAddrUserIp6Word(0),
            ty: MirType::U32,
            ..
        }
    )));
}

#[test]
fn test_lower_cgroup_sock_addr_ctx_msg_src_ip4_assignment() {
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
                        members: vec![string_member("msg_src_ip4")],
                    })),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(0x7f000001),
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                    new_value: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String(b"allow".to_vec()),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(3) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 4,
        file_count: 0,
    };
    let hir = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:sendmsg4");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sock_addr ctx.msg_src_ip4 assignment should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::StoreCtxField {
            target: CtxStoreTarget::CgroupSockAddrMsgSrcIp4,
            ty: MirType::U32,
            ..
        }
    )));
}

#[test]
fn test_lower_cgroup_sock_addr_ctx_remote_ip4_assignment_uses_user_ip4_store_target() {
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
                        members: vec![string_member("remote_ip4")],
                    })),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(0x7f000001),
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                    new_value: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String(b"allow".to_vec()),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(3) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 4,
        file_count: 0,
    };
    let hir = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect4");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sock_addr ctx.remote_ip4 assignment should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::StoreCtxField {
            target: CtxStoreTarget::CgroupSockAddrUserIp4,
            ty: MirType::U32,
            ..
        }
    )));
}

#[test]
fn test_lower_cgroup_sock_addr_ctx_remote_ip4_assignment_on_recvmsg_uses_user_ip4_store_target() {
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
                        members: vec![string_member("remote_ip4")],
                    })),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(0x7f000001),
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                    new_value: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String(b"allow".to_vec()),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(3) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 4,
        file_count: 0,
    };
    let hir = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:recvmsg4");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sock_addr recvmsg4 ctx.remote_ip4 assignment should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::StoreCtxField {
            target: CtxStoreTarget::CgroupSockAddrUserIp4,
            ty: MirType::U32,
            ..
        }
    )));
}

#[test]
fn test_lower_cgroup_sock_addr_ctx_local_ip4_assignment_on_sendmsg_uses_msg_src_ip4_store_target() {
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
                        members: vec![string_member("local_ip4")],
                    })),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(0x7f000001),
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                    new_value: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String(b"allow".to_vec()),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(3) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 4,
        file_count: 0,
    };
    let hir = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:sendmsg4");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sock_addr sendmsg4 ctx.local_ip4 assignment should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::StoreCtxField {
            target: CtxStoreTarget::CgroupSockAddrMsgSrcIp4,
            ty: MirType::U32,
            ..
        }
    )));
}

#[test]
fn test_lower_cgroup_sock_addr_ctx_local_port_assignment_uses_user_port_store_target() {
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
                        members: vec![string_member("local_port")],
                    })),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(8080),
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                    new_value: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String(b"allow".to_vec()),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(3) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 4,
        file_count: 0,
    };
    let hir = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:bind4");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sock_addr ctx.local_port assignment should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::StoreCtxField {
            target: CtxStoreTarget::CgroupSockAddrUserPort,
            ty: MirType::U32,
            ..
        }
    )));
}

#[test]
fn test_lower_sk_lookup_action_alias_return_to_const() {
    let hir = make_return_literal_program(HirLiteral::String(b"pass".to_vec()));
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sk_lookup action alias should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(matches!(
        block.terminator,
        MirInst::Return {
            val: Some(MirValue::Const(1))
        }
    ));
}

#[test]
fn test_lower_flow_dissector_action_alias_return_to_const() {
    let hir = make_return_literal_program(HirLiteral::String(b"fallback".to_vec()));
    let probe_ctx = ProbeContext::new(EbpfProgramType::FlowDissector, "/proc/self/ns/net");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("flow_dissector action alias should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(matches!(
        block.terminator,
        MirInst::Return {
            val: Some(MirValue::Const(129))
        }
    ));
}

#[test]
fn test_lower_netfilter_action_alias_return_to_const() {
    let hir = make_return_literal_program(HirLiteral::String(b"queue".to_vec()));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Netfilter, "ipv4:pre_routing");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("netfilter action alias should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(matches!(
        block.terminator,
        MirInst::Return {
            val: Some(MirValue::Const(3))
        }
    ));
}

#[test]
fn test_lower_lwt_action_alias_return_to_const() {
    let hir = make_return_literal_program(HirLiteral::String(b"reroute".to_vec()));
    let probe_ctx = ProbeContext::new(EbpfProgramType::LwtXmit, "demo-route");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("lwt action alias should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(matches!(
        block.terminator,
        MirInst::Return {
            val: Some(MirValue::Const(128))
        }
    ));
}

#[test]
fn test_lower_sk_lookup_ctx_local_port_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("local_port")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sk_lookup ctx.local_port should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::LocalPort,
            ..
        }
    )));
}

#[test]
fn test_lower_sk_lookup_ctx_cookie_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("cookie")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sk_lookup ctx.cookie should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::LookupCookie,
            ..
        }
    )));
}

#[test]
fn test_lower_lirc_mode2_ctx_value_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("value")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::LircMode2, "/dev/lirc0");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("lirc_mode2 ctx.value should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::LircValue,
            ..
        }
    )));
}

#[test]
fn test_lower_sk_lookup_ctx_socket_bound_dev_if_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("sk"), string_member("bound_dev_if")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sk_lookup ctx.sk.bound_dev_if should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::Socket,
            ..
        }
    )));
}

#[test]
fn test_lower_sk_lookup_ctx_sk_assignment_calls_sk_assign() {
    let hir = make_ctx_upsert_program(
        CellPath {
            members: vec![string_member("sk")],
        },
        HirLiteral::Int(0),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");

    let mut result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sk_lookup ctx.sk assignment should lower to bpf_sk_assign");

    assert!(
        result
            .type_hints
            .used_ctx_fields
            .contains(&CtxField::Socket),
        "ctx.sk assignment should preserve source-level socket context compatibility metadata"
    );

    assert!(result.program.main.blocks.iter().any(|block| {
        block.instructions.iter().any(|inst| {
            matches!(
                inst,
                MirInst::CallHelper {
                    helper,
                    args,
                    ..
                } if *helper == BpfHelper::SkAssign as u32
                    && args.len() == 3
                    && matches!(args.get(2), Some(MirValue::Const(0)))
            )
        })
    }));

    optimize_with_ssa_hints(
        &mut result.program.main,
        Some(&probe_ctx),
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );
    let compiled =
        compile_mir_to_ebpf_with_hints(&result.program, Some(&probe_ctx), Some(&result.type_hints))
            .expect("sk_lookup ctx.sk assignment should compile");
    assert!(compiled.used_ctx_fields.contains(&CtxField::Socket));

    let program = compiled.into_program(
        EbpfProgramType::SkLookup,
        "/proc/self/ns/net",
        "main",
        HashMap::new(),
        HashMap::new(),
    );
    let helper_requirement = program
        .helper_compatibility_requirements()
        .into_iter()
        .find(|requirement| requirement.helper() == BpfHelper::SkAssign)
        .expect("ctx.sk assignment should report bpf_sk_assign metadata");
    assert_eq!(helper_requirement.minimum_kernel(), "5.7");
    let context_requirement = program
        .context_field_compatibility_requirements()
        .into_iter()
        .find(|requirement| requirement.field() == &CtxField::Socket)
        .expect("ctx.sk assignment should report socket context metadata");
    assert_eq!(context_requirement.minimum_kernel(), "5.9");
    assert_eq!(program.helper_compatibility_minimum_kernel(), Some("5.7"));
    assert_eq!(program.compatibility_minimum_kernel(), Some("5.9"));
}

#[test]
fn test_lower_tc_egress_ctx_sk_assignment_rejects_sk_assign() {
    let hir = make_ctx_upsert_program(
        CellPath {
            members: vec![string_member("sk")],
        },
        HirLiteral::Int(0),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:egress");

    let err = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("tc egress ctx.sk assignment should reject bpf_sk_assign");

    assert!(
        err.to_string()
            .contains("helper 'bpf_sk_assign' is only valid in tc/tcx ingress programs")
    );
}

#[test]
fn test_lower_netkit_ctx_sk_assignment_rejects_sk_assign() {
    let hir = make_ctx_upsert_program(
        CellPath {
            members: vec![string_member("sk")],
        },
        HirLiteral::Int(0),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Netkit, "nk0:primary");

    let err = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("netkit ctx.sk assignment should reject bpf_sk_assign");

    assert!(err.to_string().contains(
        "helper 'bpf_sk_assign' is only valid in tc_action, tc, tcx, and sk_lookup programs"
    ));
}

#[test]
fn test_lower_sk_lookup_ctx_socket_src_ip4_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("sk"), string_member("src_ip4")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sk_lookup ctx.sk.src_ip4 should lower");

    let blocks = &result.program.main.blocks;
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::Socket,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadSlot {
                    ty: MirType::U32,
                    ..
                }
            )))
    );
}

#[test]
fn test_lower_sk_lookup_ctx_socket_src_ip6_index_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("sk"), string_member("src_ip6"), int_member(0)],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sk_lookup ctx.sk.src_ip6[0] should lower");

    let blocks = &result.program.main.blocks;
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::Socket,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadSlot {
                    ty: MirType::U32,
                    ..
                }
            )))
    );
}

#[test]
fn test_lower_sk_lookup_ctx_socket_local_ip6_alias_index_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![
            string_member("sk"),
            string_member("local_ip6"),
            int_member(0),
        ],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sk_lookup ctx.sk.local_ip6[0] should lower");

    assert!(
        result
            .type_hints
            .used_ctx_fields
            .contains(&CtxField::LocalIp6)
    );
    compile_mir_to_ebpf_with_hints(&result.program, Some(&probe_ctx), Some(&result.type_hints))
        .expect("sk_lookup ctx.sk.local_ip6[0] should compile");
}

#[test]
fn test_lower_sk_lookup_ctx_socket_src_ip6_iterate_count() {
    let hir = make_ctx_iterate_count_program(
        CellPath {
            members: vec![string_member("sk"), string_member("src_ip6")],
        },
        DeclId::new(42),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");
    let decl_names = HashMap::from([(DeclId::new(42), "count".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sk_lookup ctx.sk.src_ip6 iterate/count should lower");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .any(|block| matches!(block.terminator, MirInst::LoopHeader { .. })),
        "expected fixed-array iterate lowering to emit a bounded loop header"
    );
}

#[test]
fn test_lower_sk_msg_ctx_socket_family_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("sk"), string_member("family")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sk_msg ctx.sk.family should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::Socket,
            ..
        }
    )));
}

#[test]
fn test_lower_sk_msg_ctx_socket_src_port_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("sk"), string_member("src_port")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sk_msg ctx.sk.src_port should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::Socket,
            ..
        }
    )));
}

#[test]
fn test_lower_sock_ops_ctx_op_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("op")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sock_ops ctx.op should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::SockOp,
            ..
        }
    )));
}

#[test]
fn test_lower_sock_ops_ctx_args_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("args")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sock_ops ctx.args should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::SockOpsArgs,
            ..
        }
    )));
}

#[test]
fn test_lower_sock_ops_ctx_reply_fields() {
    for (field_name, expected_field) in [
        ("reply", CtxField::SockOpsReply),
        ("replylong", CtxField::SockOpsReplyLong),
    ] {
        let hir = make_ctx_path_program(CellPath {
            members: vec![string_member(field_name)],
        });
        let probe_ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");

        let result = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &HashMap::new(),
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap_or_else(|err| panic!("sock_ops ctx.{field_name} should lower: {err}"));

        let block = result.program.main.block(result.program.main.entry);
        assert!(block.instructions.iter().any(|inst| matches!(
            inst,
            MirInst::LoadCtxField { field, .. } if field == &expected_field
        )));
    }
}

#[test]
fn test_lower_sock_ops_ctx_reply_assignment() {
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
                        members: vec![string_member("reply")],
                    })),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                    new_value: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::Int(1),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(3) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 4,
        file_count: 0,
    };
    let hir = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let probe_ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sock_ops ctx.reply assignment should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::StoreCtxField {
            target: CtxStoreTarget::SockOpsReply,
            ty: MirType::U32,
            ..
        }
    )));
}

#[test]
fn test_lower_sock_ops_ctx_replylong_element_assignment() {
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
                        members: vec![string_member("replylong"), int_member(2)],
                    })),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(7),
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                    new_value: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::Int(1),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(3) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 4,
        file_count: 0,
    };
    let hir = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let probe_ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sock_ops ctx.replylong assignment should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::StoreCtxField {
            target: CtxStoreTarget::SockOpsReplyLong(2),
            ty: MirType::U32,
            ..
        }
    )));
}

#[test]
fn test_lower_sock_ops_ctx_cb_flags_assignment() {
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
                        members: vec![string_member("cb_flags")],
                    })),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(7),
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                    new_value: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::Int(1),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(3) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 4,
        file_count: 0,
    };
    let hir = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let probe_ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sock_ops ctx.cb_flags assignment should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::StoreCtxField {
            target: CtxStoreTarget::SockOpsCbFlags,
            ty: MirType::U32,
            ..
        }
    )));

    let compiled =
        compile_mir_to_ebpf_with_hints(&result.program, Some(&probe_ctx), Some(&result.type_hints))
            .expect("sock_ops ctx.cb_flags assignment should compile");
    assert!(compiled.used_ctx_fields.contains(&CtxField::SockOpsCbFlags));

    let program = compiled.into_program(
        EbpfProgramType::SockOps,
        "/sys/fs/cgroup",
        "main",
        HashMap::new(),
        HashMap::new(),
    );
    let helper_requirement = program
        .helper_compatibility_requirements()
        .into_iter()
        .find(|requirement| requirement.helper() == BpfHelper::SockOpsCbFlagsSet)
        .expect("ctx.cb_flags assignment should report bpf_sock_ops_cb_flags_set metadata");
    assert_eq!(helper_requirement.minimum_kernel(), "4.16");

    let ctx_requirement = program
        .context_field_compatibility_requirements()
        .into_iter()
        .find(|requirement| requirement.key() == "ctx:cb_flags")
        .expect("ctx.cb_flags assignment should report ctx.cb_flags metadata");
    assert_eq!(ctx_requirement.minimum_kernel(), "4.16");
}

#[test]
fn test_lower_sock_ops_ctx_sk_txhash_assignment() {
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
                        members: vec![string_member("sk_txhash")],
                    })),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(7),
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                    new_value: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::Int(1),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(3) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 4,
        file_count: 0,
    };
    let hir = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let probe_ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sock_ops ctx.sk_txhash assignment should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::StoreCtxField {
            target: CtxStoreTarget::SockOpsSkTxhash,
            ty: MirType::U32,
            ..
        }
    )));
}

#[test]
fn test_lower_sock_ops_ctx_snd_cwnd_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("snd_cwnd")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sock_ops ctx.snd_cwnd should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::SockOpsSndCwnd,
            ..
        }
    )));
}

#[test]
fn test_lower_sock_ops_ctx_snd_nxt_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("snd_nxt")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sock_ops ctx.snd_nxt should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::SockOpsSndNxt,
            ..
        }
    )));
}

#[test]
fn test_lower_sock_ops_ctx_skb_len_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("skb_len")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sock_ops ctx.skb_len should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::SockOpsSkbLen,
            ..
        }
    )));
}

#[test]
fn test_lower_sock_ops_ctx_socket_state_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("sk"), string_member("state")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sock_ops ctx.sk.state should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::Socket,
            ..
        }
    )));
}

#[test]
fn test_lower_sock_ops_ctx_packet_len_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("packet_len")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sock_ops ctx.packet_len should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::PacketLen,
            ..
        }
    )));
}

#[test]
fn test_lower_sock_ops_ctx_bytes_acked_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("bytes_acked")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sock_ops ctx.bytes_acked should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::SockOpsBytesAcked,
            ..
        }
    )));
}

#[test]
fn test_lower_sock_ops_ctx_mss_cache_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("mss_cache")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sock_ops ctx.mss_cache should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::SockOpsMssCache,
            ..
        }
    )));
}

#[test]
fn test_lower_sock_ops_data_byte_projection_adds_guarded_packet_load() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("data"), int_member(0)],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sock_ops data byte projection should lower");

    let blocks = &result.program.main.blocks;
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::Data,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::DataEnd,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::BinOp {
                    op: BinOpKind::Le,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::Load {
                    ty: MirType::U8,
                    ..
                }
            )))
    );
}

#[test]
fn test_lower_sk_msg_ctx_packet_len_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("packet_len")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sk_msg ctx.packet_len should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::PacketLen,
            ..
        }
    )));
}

#[test]
fn test_lower_sk_msg_ctx_size_alias_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("size")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sk_msg ctx.size should lower as packet_len");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::PacketLen,
            ..
        }
    )));
}

#[test]
fn test_lower_sk_msg_data_byte_projection_adds_guarded_packet_load() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("data"), int_member(0)],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sk_msg data byte projection should lower");

    let blocks = &result.program.main.blocks;
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::Data,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::DataEnd,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::BinOp {
                    op: BinOpKind::Le,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::Load {
                    ty: MirType::U8,
                    ..
                }
            )))
    );
}

#[test]
fn test_lower_sk_msg_ctx_remote_ip4_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("remote_ip4")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sk_msg ctx.remote_ip4 should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::RemoteIp4,
            ..
        }
    )));
}

#[test]
fn test_lower_sk_skb_ctx_local_port_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("local_port")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkSkb, "/sys/fs/bpf/demo_sockmap");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sk_skb ctx.local_port should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::LocalPort,
            ..
        }
    )));
}

#[test]
fn test_lower_socket_filter_ctx_packet_len_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("packet_len")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("socket_filter ctx.packet_len should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::PacketLen,
            ..
        }
    )));
}

#[test]
fn test_lower_xdp_ctx_xdp_buff_len_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("xdp_buff_len")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("xdp ctx.xdp_buff_len should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::XdpBuffLen,
            ..
        }
    )));
}

#[test]
fn test_lower_socket_filter_ctx_socket_cookie_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("socket_cookie")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("socket_filter ctx.socket_cookie should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::SocketCookie,
            ..
        }
    )));
}

#[test]
fn test_lower_socket_filter_ctx_socket_uid_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("socket_uid")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("socket_filter ctx.socket_uid should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::SocketUid,
            ..
        }
    )));
}

#[test]
fn test_lower_sk_skb_ctx_protocol_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("protocol")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkSkb, "/sys/fs/bpf/demo_sockmap");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sk_skb ctx.protocol should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::Protocol,
            ..
        }
    )));
}

#[test]
fn test_lower_sk_skb_parser_ctx_socket_uid_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("socket_uid")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkSkbParser, "/sys/fs/bpf/demo_sockmap");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sk_skb_parser ctx.socket_uid should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::SocketUid,
            ..
        }
    )));
}

#[test]
fn test_lower_cgroup_sock_ctx_socket_cookie_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("socket_cookie")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_create");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sock ctx.socket_cookie should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::SocketCookie,
            ..
        }
    )));
}

#[test]
fn test_lower_sk_msg_ctx_netns_cookie_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("netns_cookie")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sk_msg ctx.netns_cookie should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::NetnsCookie,
            ..
        }
    )));
}

#[test]
fn test_lower_cgroup_sockopt_ctx_netns_cookie_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("netns_cookie")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sockopt ctx.netns_cookie should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::NetnsCookie,
            ..
        }
    )));
}

#[test]
fn test_lower_tc_egress_helper_backed_ctx_fields() {
    for (field_name, expected_field) in [
        ("cgroup_classid", CtxField::CgroupClassid),
        ("route_realm", CtxField::RouteRealm),
        ("skb_cgroup_id", CtxField::SkbCgroupId),
    ] {
        let hir = make_ctx_path_program(CellPath {
            members: vec![string_member(field_name)],
        });
        let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:egress");

        let result = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &HashMap::new(),
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap_or_else(|_| panic!("tc egress ctx.{field_name} should lower"));

        let block = result.program.main.block(result.program.main.entry);
        assert!(block.instructions.iter().any(|inst| matches!(
            inst,
            MirInst::LoadCtxField { field, .. } if field == &expected_field
        )));
    }
}

#[test]
fn test_lower_tc_egress_skb_ancestor_cgroup_id_projection_calls_helper() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("skb_ancestor_cgroup_id"), int_member(3)],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:egress");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("tc egress ctx.skb_ancestor_cgroup_id.3 should lower");

    let block = result.program.main.block(result.program.main.entry);
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
        } if *helper == BpfHelper::SkbAncestorCgroupId as u32
            && matches!(args.as_slice(), [MirValue::VReg(_), MirValue::Const(3)])
    )));
    let helper_dst = block
        .instructions
        .iter()
        .find_map(|inst| match inst {
            MirInst::CallHelper { dst, helper, .. }
                if *helper == BpfHelper::SkbAncestorCgroupId as u32 =>
            {
                Some(*dst)
            }
            _ => None,
        })
        .expect("expected skb ancestor cgroup helper destination");
    assert_eq!(result.type_hints.main.get(&helper_dst), Some(&MirType::U64));
}

#[test]
fn test_lower_tc_ingress_skb_ancestor_cgroup_id_projection_rejected() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("skb_ancestor_cgroup_id"), int_member(0)],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");

    let err = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("tc ingress ctx.skb_ancestor_cgroup_id.0 should be rejected");

    assert!(
        err.to_string().contains(
            "helper 'bpf_skb_ancestor_cgroup_id' is only valid in tc/tcx egress programs"
        )
    );
}

#[test]
fn test_lower_tc_ctx_csum_level_field() {
    for (field_name, expected_field) in [
        ("csum_level", CtxField::CsumLevel),
        ("hash_recalc", CtxField::HashRecalc),
    ] {
        let hir = make_ctx_path_program(CellPath {
            members: vec![string_member(field_name)],
        });
        let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");

        let result = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &HashMap::new(),
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap_or_else(|_| panic!("tc ctx.{field_name} should lower"));

        let block = result.program.main.block(result.program.main.entry);
        assert!(block.instructions.iter().any(|inst| matches!(
            inst,
            MirInst::LoadCtxField { field, .. } if field == &expected_field
        )));
    }
}

#[test]
fn test_lower_kprobe_ctx_cgroup_id_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("cgroup_id")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("kprobe ctx.cgroup_id should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::CgroupId,
            ..
        }
    )));
}

#[test]
fn test_lower_kprobe_ctx_cgroup_alias_projects_current_task_default_cgroup() {
    let projection_path = [
        TrampolineFieldSelector::Field("cgroups".to_string()),
        TrampolineFieldSelector::Field("dfl_cgrp".to_string()),
    ];
    if !matches!(
        KernelBtf::get().kernel_named_type_field_projection("task_struct", &projection_path),
        Ok(projection) if matches!(projection.type_info, TypeInfo::Ptr { .. })
    ) {
        return;
    }

    for alias in ["cgroup", "current_cgroup"] {
        let hir = make_ctx_path_program(CellPath {
            members: vec![string_member(alias)],
        });
        let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");

        let result = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &HashMap::new(),
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .expect("kprobe ctx.cgroup alias should lower");

        let block = result.program.main.block(result.program.main.entry);
        assert!(block.instructions.iter().any(|inst| matches!(
            inst,
            MirInst::LoadCtxField {
                field: CtxField::Task,
                ..
            }
        )));
        let instructions: Vec<&MirInst> = result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .collect();
        assert!(
            !instructions.iter().any(|inst| matches!(
                inst,
                MirInst::CallHelper { helper, .. }
                    if *helper == BpfHelper::ProbeReadKernel as u32
            )),
            "expected {alias} to preserve trusted BTF pointer provenance without probe_read"
        );
        assert!(
            instructions
                .iter()
                .filter(|inst| matches!(
                    inst,
                    MirInst::Load {
                        ty: MirType::Ptr {
                            address_space: AddressSpace::Kernel,
                            ..
                        },
                        ..
                    }
                ))
                .count()
                >= 2,
            "expected {alias} to use direct trusted BTF pointer field loads"
        );
        assert!(
            result.type_hints.main.values().any(MirType::is_cgroup_ptr),
            "expected {alias} to type as a cgroup pointer"
        );
        assert!(
            result
                .type_hints
                .used_ctx_fields
                .contains(&CtxField::Cgroup),
            "expected {alias} to preserve source-level cgroup context compatibility metadata"
        );
    }
}

#[test]
fn test_lower_tracepoint_current_cgroup_alias_projects_builtin_default_cgroup() {
    let projection_path = [
        TrampolineFieldSelector::Field("cgroups".to_string()),
        TrampolineFieldSelector::Field("dfl_cgrp".to_string()),
    ];
    if !matches!(
        KernelBtf::get().kernel_named_type_field_projection("task_struct", &projection_path),
        Ok(projection) if matches!(projection.type_info, TypeInfo::Ptr { .. })
    ) {
        return;
    }

    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("current_cgroup")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tracepoint, "syscalls/sys_enter_openat");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("tracepoint ctx.current_cgroup should preserve builtin resolution");

    let instructions: Vec<&MirInst> = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .collect();
    assert!(instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::Task,
            ..
        }
    )));
    assert!(
        !instructions.iter().any(|inst| matches!(
            inst,
            MirInst::CallHelper { helper, .. }
                if *helper == BpfHelper::ProbeReadKernel as u32
        )),
        "expected tracepoint current_cgroup to preserve trusted BTF pointer provenance"
    );
    assert!(
        result.type_hints.main.values().any(MirType::is_cgroup_ptr),
        "expected current_cgroup to type as a cgroup pointer"
    );
    assert!(
        result
            .type_hints
            .used_ctx_fields
            .contains(&CtxField::Cgroup),
        "expected current_cgroup to preserve source-level cgroup context compatibility metadata"
    );
}

#[test]
fn test_lower_bound_current_cgroup_btf_projection_preserves_trusted_provenance() {
    let task_projection_path = [
        TrampolineFieldSelector::Field("cgroups".to_string()),
        TrampolineFieldSelector::Field("dfl_cgrp".to_string()),
    ];
    if !matches!(
        KernelBtf::get().kernel_named_type_field_projection("task_struct", &task_projection_path),
        Ok(projection) if matches!(projection.type_info, TypeInfo::Ptr { .. })
    ) {
        return;
    }
    let cgroup_projection_path = [
        TrampolineFieldSelector::Field("kn".to_string()),
        TrampolineFieldSelector::Field("id".to_string()),
    ];
    let expected_ty = match KernelBtf::get()
        .kernel_named_type_field_projection("cgroup", &cgroup_projection_path)
    {
        Ok(projection) => match projection.type_info {
            TypeInfo::Int {
                size: 8,
                signed: false,
            } => MirType::U64,
            TypeInfo::Int {
                size: 8,
                signed: true,
            } => MirType::I64,
            _ => return,
        },
        Err(_) => return,
    };

    let hir = make_bound_ctx_path_program(
        CellPath {
            members: vec![string_member("current_cgroup")],
        },
        CellPath {
            members: vec![string_member("kn"), string_member("id")],
        },
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("bound current_cgroup BTF projection should lower");

    let instructions: Vec<&MirInst> = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .collect();
    assert!(instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::Task,
            ..
        }
    )));
    assert!(
        instructions
            .iter()
            .filter(|inst| matches!(
                inst,
                MirInst::Load {
                    ty: MirType::Ptr {
                        address_space: AddressSpace::Kernel,
                        ..
                    },
                    ..
                }
            ))
            .count()
            >= 3,
        "expected bound current_cgroup projection to preserve trusted BTF provenance through the follow-up cgroup.kn pointer load"
    );
    assert!(
        result.type_hints.main.values().any(|ty| ty == &expected_ty),
        "expected bound current_cgroup projection to type as {expected_ty:?}"
    );
}

#[test]
fn test_lower_packet_program_rejects_ctx_cgroup_alias() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("cgroup")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    let err = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("packet programs should reject ctx.cgroup pointer alias");

    assert!(
        err.to_string()
            .contains("ctx.cgroup is not available on xdp programs"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_lower_packet_program_rejects_current_cgroup_alias_with_source_name() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("current_cgroup")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    let err = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("packet programs should reject ctx.current_cgroup pointer alias");

    assert!(
        err.to_string()
            .contains("ctx.current_cgroup is not available on xdp programs"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_lower_packet_program_rejects_current_task_alias_with_source_name() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("current_task")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    let err = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("packet programs should reject ctx.current_task alias");

    assert!(
        err.to_string()
            .contains("ctx.current_task is not available on xdp programs"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_lower_contextless_program_rejects_current_task_cgroup_fields() {
    for (path, expected_field) in [
        (
            CellPath {
                members: vec![string_member("cgroup_id")],
            },
            "cgroup_id",
        ),
        (
            CellPath {
                members: vec![string_member("ancestor_cgroup_id"), int_member(0)],
            },
            "ancestor_cgroup_id",
        ),
    ] {
        for (program_type, target) in [
            (EbpfProgramType::Extension, "replace_me"),
            (EbpfProgramType::StructOps, "sched_ext_ops"),
        ] {
            let hir = make_ctx_path_program(path.clone());
            let probe_ctx = ProbeContext::new(program_type, target);

            let err = lower_hir_to_mir_with_hints(
                &hir,
                Some(&probe_ctx),
                &HashMap::new(),
                None,
                &HashMap::new(),
                &HashMap::new(),
            )
            .expect_err("contextless programs should reject current-task cgroup fields");

            assert!(
                err.to_string().contains(&format!(
                    "ctx.{expected_field} is not available on {} programs",
                    program_type.canonical_prefix()
                )),
                "unexpected error for {program_type:?}: {err}"
            );
        }
    }
}

#[test]
fn test_lower_kprobe_ctx_ancestor_cgroup_id_projection_calls_helper() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("ancestor_cgroup_id"), int_member(2)],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("kprobe ctx.ancestor_cgroup_id.2 should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::CallHelper {
            helper,
            args,
            ..
        } if *helper == BpfHelper::GetCurrentAncestorCgroupId as u32
            && args == &[MirValue::Const(2)]
    )));
    let helper_dst = block
        .instructions
        .iter()
        .find_map(|inst| match inst {
            MirInst::CallHelper { dst, helper, .. }
                if *helper == BpfHelper::GetCurrentAncestorCgroupId as u32 =>
            {
                Some(*dst)
            }
            _ => None,
        })
        .expect("expected current ancestor cgroup helper destination");
    assert_eq!(result.type_hints.main.get(&helper_dst), Some(&MirType::U64));
}

#[test]
fn test_lower_kprobe_ctx_ancestor_cgroup_id_projection_rejects_missing_level() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("ancestor_cgroup_id")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");

    let err = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("ctx.ancestor_cgroup_id without a level should be rejected");

    assert!(
        err.to_string()
            .contains("ctx.ancestor_cgroup_id requires a constant numeric ancestor level")
    );
}

#[test]
fn test_lower_kprobe_time_ctx_fields() {
    for (field_name, expected_field) in [
        ("ktime", CtxField::Timestamp),
        ("ktime_boot", CtxField::BootTimestamp),
        ("ktime_coarse", CtxField::CoarseTimestamp),
        ("ktime_tai", CtxField::TaiTimestamp),
        ("jiffies", CtxField::Jiffies),
    ] {
        let hir = make_ctx_path_program(CellPath {
            members: vec![string_member(field_name)],
        });
        let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");

        let result = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &HashMap::new(),
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap_or_else(|_| panic!("kprobe ctx.{field_name} should lower"));

        let block = result.program.main.block(result.program.main.entry);
        assert!(block.instructions.iter().any(|inst| matches!(
            inst,
            MirInst::LoadCtxField { field, .. } if field == &expected_field
        )));
    }
}

#[test]
fn test_lower_kprobe_numa_node_ctx_field() {
    for field_name in ["numa_node", "numa_node_id"] {
        let hir = make_ctx_path_program(CellPath {
            members: vec![string_member(field_name)],
        });
        let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");

        let result = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &HashMap::new(),
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap_or_else(|_| panic!("kprobe ctx.{field_name} should lower"));

        let block = result.program.main.block(result.program.main.entry);
        assert!(block.instructions.iter().any(|inst| matches!(
            inst,
            MirInst::LoadCtxField {
                field: CtxField::NumaNode,
                ..
            }
        )));
    }
}

#[test]
fn test_lower_kprobe_random_ctx_field() {
    for field_name in ["random", "prandom_u32"] {
        let hir = make_ctx_path_program(CellPath {
            members: vec![string_member(field_name)],
        });
        let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");

        let result = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &HashMap::new(),
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap_or_else(|_| panic!("kprobe ctx.{field_name} should lower"));

        let block = result.program.main.block(result.program.main.entry);
        assert!(block.instructions.iter().any(|inst| matches!(
            inst,
            MirInst::LoadCtxField {
                field: CtxField::Random,
                ..
            }
        )));
    }
}

#[test]
fn test_lower_kprobe_tracing_helper_ctx_fields() {
    for (field_name, expected_field) in [
        ("func_ip", CtxField::FuncIp),
        ("attach_cookie", CtxField::AttachCookie),
    ] {
        let hir = make_ctx_path_program(CellPath {
            members: vec![string_member(field_name)],
        });
        let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");

        let result = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &HashMap::new(),
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap_or_else(|_| panic!("kprobe ctx.{field_name} should lower"));

        let block = result.program.main.block(result.program.main.entry);
        assert!(block.instructions.iter().any(|inst| matches!(
            inst,
            MirInst::LoadCtxField { field, .. } if field == &expected_field
        )));
    }
}

#[test]
fn test_lower_fentry_arg_count_ctx_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("arg_count")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "do_sys_openat2");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("fentry ctx.arg_count should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::ArgCount,
            ..
        }
    )));
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_lower_perf_event_ctx_sample_period_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("sample_period")],
    });
    let probe_ctx = ProbeContext::new(
        EbpfProgramType::PerfEvent,
        "software:cpu-clock:period=100000",
    );

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("perf_event ctx.sample_period should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::PerfSamplePeriod,
            ..
        }
    )));
}

#[test]
fn test_lower_perf_event_helper_ctx_fields() {
    for (field_name, expected_field) in [
        ("perf_counter", CtxField::PerfCounter),
        ("perf_enabled", CtxField::PerfEnabled),
        ("perf_running", CtxField::PerfRunning),
    ] {
        let hir = make_ctx_path_program(CellPath {
            members: vec![string_member(field_name)],
        });
        let probe_ctx = ProbeContext::new(
            EbpfProgramType::PerfEvent,
            "software:cpu-clock:period=100000",
        );

        let result = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &HashMap::new(),
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap_or_else(|_| panic!("perf_event ctx.{field_name} should lower"));

        let block = result.program.main.block(result.program.main.entry);
        assert!(block.instructions.iter().any(|inst| matches!(
            inst,
            MirInst::LoadCtxField { field, .. } if field == &expected_field
        )));
    }
}

#[test]
fn test_lower_socket_filter_ctx_mark_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("mark")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("socket_filter ctx.mark should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::SockMark,
            ..
        }
    )));
}

#[test]
fn test_lower_cgroup_device_ctx_access_type_field() {
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupDevice, "/sys/fs/cgroup");

    for (field_name, expected_field) in [
        ("access_type", CtxField::DeviceAccessType),
        ("device_access", CtxField::DeviceAccess),
        ("device_type", CtxField::DeviceType),
    ] {
        let hir = make_ctx_path_program(CellPath {
            members: vec![string_member(field_name)],
        });

        let result = lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &HashMap::new(),
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap_or_else(|err| panic!("cgroup_device ctx.{field_name} should lower: {err}"));

        let block = result.program.main.block(result.program.main.entry);
        assert!(block.instructions.iter().any(|inst| matches!(
            inst,
            MirInst::LoadCtxField { field, .. } if field == &expected_field
        )));
    }
}

#[test]
fn test_lower_cgroup_sockopt_ctx_optname_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("optname")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sockopt ctx.optname should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::SockoptOptname,
            ..
        }
    )));
}

#[test]
fn test_lower_cgroup_sockopt_ctx_optval_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("optval")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sockopt ctx.optval should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::SockoptOptval,
            ..
        }
    )));
}

#[test]
fn test_lower_cgroup_sockopt_ctx_optval_byte_projection() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("optval"), int_member(0)],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sockopt ctx.optval[0] should lower");

    let blocks = &result.program.main.blocks;
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::SockoptOptval,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::SockoptOptvalEnd,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::Load {
                    ty: MirType::U8,
                    ..
                }
            )))
    );
}

#[test]
fn test_lower_cgroup_sockopt_ctx_optval_runtime_get_uses_guarded_load() {
    let hir = make_bound_ctx_runtime_get_program(
        CellPath {
            members: vec![string_member("optval")],
        },
        CellPath {
            members: vec![string_member("sk"), string_member("family")],
        },
        2,
        DeclId::new(42),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "get".to_string());

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sockopt ctx.optval | get $idx should lower");

    let blocks = &result.program.main.blocks;
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::SockoptOptval,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::SockoptOptvalEnd,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::Load {
                    ty: MirType::U8,
                    ..
                }
            )))
    );
}

#[test]
fn test_lower_cgroup_sockopt_ctx_optval_byte_assignment() {
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
                        members: vec![string_member("optval"), int_member(0)],
                    })),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(42),
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                    new_value: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String(b"allow".to_vec()),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(3) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 4,
        file_count: 0,
    };
    let hir = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sockopt ctx.optval[0] assignment should lower");

    let blocks = &result.program.main.blocks;
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::SockoptOptval,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::SockoptOptvalEnd,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::Store {
                    ty: MirType::U8,
                    ..
                }
            )))
    );
}

#[test]
fn test_lower_tc_ctx_data_byte_assignment_adds_guarded_packet_store() {
    let hir = make_ctx_upsert_program(
        CellPath {
            members: vec![string_member("data"), int_member(0)],
        },
        HirLiteral::Int(42),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("tc ctx.data byte assignment should lower");

    let blocks = &result.program.main.blocks;
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::Data,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::DataEnd,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::Store {
                    ty: MirType::U8,
                    ..
                }
            )))
    );
}

#[test]
fn test_lower_xdp_ctx_ethertype_assignment_adds_be_guarded_packet_store() {
    let hir = make_ctx_upsert_program(
        CellPath {
            members: vec![
                string_member("data"),
                string_member("eth"),
                string_member("ethertype"),
            ],
        },
        HirLiteral::Int(0x86dd),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("xdp ctx.data.eth.ethertype assignment should lower");

    let blocks = &result.program.main.blocks;
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::DataEnd,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::Store {
                    ty: MirType::U16,
                    ..
                }
            )))
    );
}

#[test]
fn test_lower_xdp_ctx_eth_ipv6_udp_dst_assignment_uses_dynamic_header_steps() {
    let hir = make_ctx_upsert_program(
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
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("xdp ctx.data.eth.ipv6.udp.dst assignment should lower");

    let blocks = &result.program.main.blocks;
    assert!(
        blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::BinOp {
                    op: BinOpKind::Add,
                    rhs: MirValue::Const(40),
                    ..
                }
            ))
    );
    assert!(
        blocks
            .iter()
            .any(|block| matches!(block.terminator, MirInst::Branch { .. }))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::Load {
                    ty: MirType::U8,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::Store {
                    ty: MirType::U16,
                    ..
                }
            )))
    );
}

#[test]
fn test_lower_xdp_ctx_data_meta_byte_assignment_uses_data_guard() {
    let hir = make_ctx_upsert_program(
        CellPath {
            members: vec![string_member("data_meta"), int_member(0)],
        },
        HirLiteral::Int(7),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("xdp ctx.data_meta byte assignment should lower");

    let blocks = &result.program.main.blocks;
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::DataMeta,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::Data,
                    ..
                }
            )))
    );
    assert!(
        !blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::DataEnd,
                    ..
                }
            )))
    );
}

#[test]
fn test_lower_tc_action_ctx_data_meta_byte_assignment_uses_data_guard() {
    let hir = make_ctx_upsert_program(
        CellPath {
            members: vec![string_member("data_meta"), int_member(0)],
        },
        HirLiteral::Int(7),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::TcAction, "demo-action");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("tc_action ctx.data_meta byte assignment should lower");

    let blocks = &result.program.main.blocks;
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::DataMeta,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::Data,
                    ..
                }
            )))
    );
    assert!(
        !blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::DataEnd,
                    ..
                }
            )))
    );
}

#[test]
fn test_lower_tc_ctx_tstamp_assignment() {
    let hir = make_ctx_upsert_program(
        CellPath {
            members: vec![string_member("tstamp")],
        },
        HirLiteral::Int(7),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("tc ctx.tstamp assignment should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::StoreCtxField {
            target: CtxStoreTarget::SkbTstamp,
            ty: MirType::U64,
            ..
        }
    )));
}

#[test]
fn test_lower_ctx_assignment_records_context_compatibility_fields() {
    let hir = make_ctx_upsert_program(
        CellPath {
            members: vec![string_member("tstamp")],
        },
        HirLiteral::Int(7),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("tc ctx.tstamp assignment should lower");

    let compiled =
        compile_mir_to_ebpf_with_hints(&result.program, Some(&probe_ctx), Some(&result.type_hints))
            .expect("tc ctx.tstamp assignment should compile");
    assert!(compiled.used_ctx_fields.contains(&CtxField::Tstamp));

    let program = compiled.into_program(
        EbpfProgramType::Tc,
        "lo:ingress",
        "main",
        HashMap::new(),
        HashMap::new(),
    );
    let requirements = program.context_field_compatibility_requirements();

    let tstamp = requirements
        .iter()
        .find(|requirement| requirement.key() == "ctx:tstamp")
        .expect("ctx.tstamp assignment should imply ctx.tstamp compatibility metadata");
    assert_eq!(tstamp.minimum_kernel(), "5.0");
    assert_eq!(
        program.context_field_compatibility_minimum_kernel(),
        Some("5.0")
    );
}

#[test]
fn test_lower_cgroup_skb_egress_ctx_tstamp_assignment() {
    let hir = make_ctx_upsert_program(
        CellPath {
            members: vec![string_member("tstamp")],
        },
        HirLiteral::Int(7),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:egress");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_skb egress ctx.tstamp assignment should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::StoreCtxField {
            target: CtxStoreTarget::SkbTstamp,
            ty: MirType::U64,
            ..
        }
    )));
}

#[test]
fn test_lower_cgroup_skb_ingress_ctx_tstamp_assignment_is_rejected() {
    let hir = make_ctx_upsert_program(
        CellPath {
            members: vec![string_member("tstamp")],
        },
        HirLiteral::Int(7),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:ingress");

    let err = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("cgroup_skb ingress ctx.tstamp assignment should be rejected");

    assert!(err.to_string().contains(
        "ctx.tstamp is only writable on tc_action, tc, tcx, netkit, and cgroup_skb:egress programs"
    ));
}

#[test]
fn test_lower_tc_ctx_mark_assignment() {
    let hir = make_ctx_upsert_program(
        CellPath {
            members: vec![string_member("mark")],
        },
        HirLiteral::Int(7),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("tc ctx.mark assignment should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::StoreCtxField {
            target: CtxStoreTarget::SkbMark,
            ty: MirType::U32,
            ..
        }
    )));
}

#[test]
fn test_lower_tc_action_ctx_queue_mapping_assignment() {
    let hir = make_ctx_upsert_program(
        CellPath {
            members: vec![string_member("queue_mapping")],
        },
        HirLiteral::Int(7),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::TcAction, "demo-action");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("tc_action ctx.queue_mapping assignment should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::StoreCtxField {
            target: CtxStoreTarget::SkbQueueMapping,
            ty: MirType::U32,
            ..
        }
    )));
}

#[test]
fn test_lower_cgroup_skb_ctx_mark_assignment() {
    let hir = make_ctx_upsert_program(
        CellPath {
            members: vec![string_member("mark")],
        },
        HirLiteral::Int(7),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:ingress");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_skb ctx.mark assignment should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::StoreCtxField {
            target: CtxStoreTarget::SkbMark,
            ty: MirType::U32,
            ..
        }
    )));
}

#[test]
fn test_lower_lwt_xmit_ctx_cb_assignment() {
    let hir = make_ctx_upsert_program(
        CellPath {
            members: vec![string_member("cb"), int_member(1)],
        },
        HirLiteral::Int(7),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::LwtXmit, "demo-route");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("lwt_xmit ctx.cb[1] assignment should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::StoreCtxField {
            target: CtxStoreTarget::SkbCbWord(1),
            ty: MirType::U32,
            ..
        }
    )));
}

#[test]
fn test_lower_cgroup_sock_ctx_mark_assignment_on_sock_create() {
    let hir = make_ctx_upsert_program(
        CellPath {
            members: vec![string_member("mark")],
        },
        HirLiteral::Int(7),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_create");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sock sock_create ctx.mark assignment should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::StoreCtxField {
            target: CtxStoreTarget::CgroupSockMark,
            ty: MirType::U32,
            ..
        }
    )));
}

#[test]
fn test_lower_cgroup_sock_ctx_bound_dev_if_assignment_on_sock_release() {
    let hir = make_ctx_upsert_program(
        CellPath {
            members: vec![string_member("bound_dev_if")],
        },
        HirLiteral::Int(7),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_release");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sock sock_release ctx.bound_dev_if assignment should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::StoreCtxField {
            target: CtxStoreTarget::CgroupSockBoundDevIf,
            ty: MirType::U32,
            ..
        }
    )));
}

#[test]
fn test_lower_cgroup_sock_ctx_priority_assignment_on_sock_release() {
    let hir = make_ctx_upsert_program(
        CellPath {
            members: vec![string_member("priority")],
        },
        HirLiteral::Int(7),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_release");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sock sock_release ctx.priority assignment should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::StoreCtxField {
            target: CtxStoreTarget::CgroupSockPriority,
            ty: MirType::U32,
            ..
        }
    )));
}

#[test]
fn test_lower_cgroup_sock_ctx_mark_assignment_on_post_bind_is_rejected() {
    let hir = make_ctx_upsert_program(
        CellPath {
            members: vec![string_member("mark")],
        },
        HirLiteral::Int(7),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:post_bind4");

    let err = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("cgroup_sock post_bind ctx.mark assignment should be rejected");

    assert!(
        err.to_string()
            .contains("ctx.mark is only writable on cgroup_sock sock_create/sock_release hooks")
    );
}

#[test]
fn test_lower_tc_ctx_cb_assignment() {
    let hir = make_ctx_upsert_program(
        CellPath {
            members: vec![string_member("cb"), int_member(2)],
        },
        HirLiteral::Int(7),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("tc ctx.cb[2] assignment should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::StoreCtxField {
            target: CtxStoreTarget::SkbCbWord(2),
            ty: MirType::U32,
            ..
        }
    )));
}

#[test]
fn test_lower_socket_filter_ctx_cb_assignment() {
    let hir = make_ctx_upsert_program(
        CellPath {
            members: vec![string_member("cb"), int_member(2)],
        },
        HirLiteral::Int(7),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("socket_filter ctx.cb[2] assignment should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::StoreCtxField {
            target: CtxStoreTarget::SkbCbWord(2),
            ty: MirType::U32,
            ..
        }
    )));
}

#[test]
fn test_lower_sk_skb_ctx_tc_index_assignment() {
    let hir = make_ctx_upsert_program(
        CellPath {
            members: vec![string_member("tc_index")],
        },
        HirLiteral::Int(7),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkSkb, "/sys/fs/bpf/demo_sockmap");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sk_skb ctx.tc_index assignment should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::StoreCtxField {
            target: CtxStoreTarget::SkbTcIndex,
            ty: MirType::U32,
            ..
        }
    )));
}

#[test]
fn test_lower_lwt_xmit_ctx_data_byte_assignment() {
    let hir = make_ctx_upsert_program(
        CellPath {
            members: vec![string_member("data"), int_member(0)],
        },
        HirLiteral::Int(1),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::LwtXmit, "demo-route");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("lwt_xmit ctx.data byte assignment should lower");

    let blocks = &result.program.main.blocks;
    assert!(blocks.iter().any(|block| {
        block.instructions.iter().any(|inst| {
            matches!(
                inst,
                MirInst::Store {
                    ty: MirType::U8,
                    ..
                }
            )
        })
    }));
}

#[test]
fn test_lower_sk_msg_ctx_data_byte_assignment() {
    let hir = make_ctx_upsert_program(
        CellPath {
            members: vec![string_member("data"), int_member(0)],
        },
        HirLiteral::Int(1),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sk_msg ctx.data byte assignment should lower");

    let blocks = &result.program.main.blocks;
    assert!(blocks.iter().any(|block| {
        block.instructions.iter().any(|inst| {
            matches!(
                inst,
                MirInst::Store {
                    ty: MirType::U8,
                    ..
                }
            )
        })
    }));
}
