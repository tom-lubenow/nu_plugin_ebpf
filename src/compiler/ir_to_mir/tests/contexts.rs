use super::helpers::*;
use super::*;
use crate::compiler::EbpfProgramType;
use crate::compiler::hir::{
    HirBlock, HirBlockId, HirFunction, HirLiteral, HirProgram, HirStmt, HirTerminator,
};
use crate::compiler::mir::CtxStoreTarget;
use nu_protocol::ast::CellPath;
use nu_protocol::{RegId, VarId};
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
        .contains("ctx.ifindex is only available on socket_filter, tc, cgroup_skb, sk_skb, and sk_skb_parser programs"));
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
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("access_type")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupDevice, "/sys/fs/cgroup");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_device ctx.access_type should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::DeviceAccessType,
            ..
        }
    )));
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
