use super::*;
use crate::compiler::mir::CtxStoreTarget;
use crate::compiler::{EbpfProgramType, ProbeContext};
use crate::kernel_btf::KernelBtf;

fn find_void_fexit_candidate() -> String {
    let mut attempts = Vec::new();
    for func_name in ["wake_up_new_task", "security_file_open", "__audit_free"] {
        match KernelBtf::get().function_trampoline_ret_type_info(func_name) {
            Ok(None) => return func_name.to_string(),
            Ok(Some(spec)) => attempts.push(format!("{func_name}: {:?}", spec)),
            Err(err) => attempts.push(format!("{func_name}: {err}")),
        }
    }
    panic!(
        "expected a void fexit candidate on this kernel; tried: {}",
        attempts.join(", ")
    );
}

#[test]
fn test_verify_mir_for_probe_context_rejects_invalid_tracepoint_field_load() {
    let (mut func, entry) = new_mir_function();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst,
            field: CtxField::TracepointField("filename".to_string()),
            slot: None,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "do_sys_openat2");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected tracepoint field load to be rejected on kprobe");
    assert!(err.iter().any(|e| {
        e.message
            .contains("ctx.filename is only available on typed tracepoints")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_rejects_unavailable_trampoline_arg_load() {
    let (mut func, entry) = new_mir_function();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst,
            field: CtxField::Arg(99),
            slot: None,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "do_close_on_exec");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected unavailable trampoline arg to be rejected");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("ctx.arg99 is not available on fentry:do_close_on_exec")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_rejects_void_trampoline_retval_load() {
    let (mut func, entry) = new_mir_function();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst,
            field: CtxField::RetVal,
            slot: None,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let func_name = find_void_fexit_candidate();
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fexit, &func_name);
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected void trampoline retval to be rejected");
    assert!(
        err.iter().any(|e| {
            e.message.contains(&format!(
                "ctx.retval is not available on fexit:{} because the target returns void",
                func_name
            ))
        }),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_rejects_sockopt_retval_store_on_set_hook() {
    let (mut func, entry) = new_mir_function();
    func.block_mut(entry)
        .instructions
        .push(MirInst::StoreCtxField {
            target: CtxStoreTarget::SockoptRetval,
            val: MirValue::Const(0),
            ty: MirType::I32,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:set");
    let err = verify_mir_for_probe_context(&func, &HashMap::new(), &probe_ctx)
        .expect_err("expected sockopt_retval store to be rejected on set hook");
    assert!(err.iter().any(|e| {
        e.message
            .contains("ctx.sockopt_retval is only available on cgroup_sockopt:get hooks")
    }));
}
