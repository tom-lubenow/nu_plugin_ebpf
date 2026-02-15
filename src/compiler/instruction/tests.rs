use super::*;

#[test]
fn test_mov64_imm_encoding() {
    let insn = EbpfInsn::mov64_imm(EbpfReg::R0, 0);
    let bytes = insn.encode();
    // opcode=0xb7, regs=0x00, offset=0x0000, imm=0x00000000
    assert_eq!(bytes, [0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
}

#[test]
fn test_mov64_imm_with_value() {
    let insn = EbpfInsn::mov64_imm(EbpfReg::R1, 42);
    let bytes = insn.encode();
    // opcode=0xb7, regs=0x01 (dst=1), offset=0x0000, imm=42
    assert_eq!(bytes, [0xb7, 0x01, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00]);
}

#[test]
fn test_exit_encoding() {
    let insn = EbpfInsn::exit();
    let bytes = insn.encode();
    // opcode=0x95
    assert_eq!(bytes, [0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
}

#[test]
fn test_call_helper() {
    let insn = EbpfInsn::call(BpfHelper::TracePrintk);
    let bytes = insn.encode();
    // opcode=0x85, imm=6 (TracePrintk helper number)
    assert_eq!(bytes, [0x85, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00]);
}

#[test]
fn test_call_kfunc() {
    let insn = EbpfInsn::call_kfunc(1234);
    let bytes = insn.encode();
    // opcode=0x85, src_reg=2 (BPF_PSEUDO_KFUNC_CALL), imm=1234
    assert_eq!(bytes, [0x85, 0x20, 0x00, 0x00, 0xd2, 0x04, 0x00, 0x00]);
}

#[test]
fn test_helper_signature_kptr_xchg() {
    let sig = HelperSignature::for_id(BpfHelper::KptrXchg as u32)
        .expect("expected bpf_kptr_xchg helper signature");
    assert_eq!(sig.min_args, 2);
    assert_eq!(sig.max_args, 2);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(sig.ret_kind, HelperRetKind::PointerMaybeNull);
}

#[test]
fn test_helper_signature_probe_read_helpers() {
    let helpers = [
        (BpfHelper::ProbeRead, "bpf_probe_read"),
        (BpfHelper::ProbeReadUser, "bpf_probe_read_user"),
        (BpfHelper::ProbeReadKernel, "bpf_probe_read_kernel"),
        (BpfHelper::ProbeReadUserStr, "bpf_probe_read_user_str"),
        (BpfHelper::ProbeReadKernelStr, "bpf_probe_read_kernel_str"),
    ];

    for (helper, name) in helpers {
        let sig = HelperSignature::for_id(helper as u32)
            .unwrap_or_else(|| panic!("expected {name} helper signature"));
        assert_eq!(sig.min_args, 3);
        assert_eq!(sig.max_args, 3);
        assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
        assert_eq!(sig.arg_kind(1), HelperArgKind::Scalar);
        assert_eq!(sig.arg_kind(2), HelperArgKind::Pointer);
        assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
    }
}

#[test]
fn test_helper_signature_map_queue_helpers() {
    let sig = HelperSignature::for_id(BpfHelper::MapPushElem as u32)
        .expect("expected bpf_map_push_elem helper signature");
    assert_eq!(sig.min_args, 3);
    assert_eq!(sig.max_args, 3);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);

    let sig = HelperSignature::for_id(BpfHelper::MapPopElem as u32)
        .expect("expected bpf_map_pop_elem helper signature");
    assert_eq!(sig.min_args, 2);
    assert_eq!(sig.max_args, 2);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);

    let sig = HelperSignature::for_id(BpfHelper::MapPeekElem as u32)
        .expect("expected bpf_map_peek_elem helper signature");
    assert_eq!(sig.min_args, 2);
    assert_eq!(sig.max_args, 2);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
}

#[test]
fn test_helper_signature_sk_storage_helpers() {
    let sig = HelperSignature::for_id(BpfHelper::SkStorageGet as u32)
        .expect("expected bpf_sk_storage_get helper signature");
    assert_eq!(sig.min_args, 4);
    assert_eq!(sig.max_args, 4);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(2), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(3), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::PointerMaybeNull);

    let sig = HelperSignature::for_id(BpfHelper::SkStorageDelete as u32)
        .expect("expected bpf_sk_storage_delete helper signature");
    assert_eq!(sig.min_args, 2);
    assert_eq!(sig.max_args, 2);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);

    let sig = HelperSignature::for_id(BpfHelper::TaskStorageGet as u32)
        .expect("expected bpf_task_storage_get helper signature");
    assert_eq!(sig.min_args, 4);
    assert_eq!(sig.max_args, 4);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(2), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(3), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::PointerMaybeNull);

    let sig = HelperSignature::for_id(BpfHelper::TaskStorageDelete as u32)
        .expect("expected bpf_task_storage_delete helper signature");
    assert_eq!(sig.min_args, 2);
    assert_eq!(sig.max_args, 2);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);

    let sig = HelperSignature::for_id(BpfHelper::InodeStorageGet as u32)
        .expect("expected bpf_inode_storage_get helper signature");
    assert_eq!(sig.min_args, 4);
    assert_eq!(sig.max_args, 4);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(2), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(3), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::PointerMaybeNull);

    let sig = HelperSignature::for_id(BpfHelper::InodeStorageDelete as u32)
        .expect("expected bpf_inode_storage_delete helper signature");
    assert_eq!(sig.min_args, 2);
    assert_eq!(sig.max_args, 2);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
}

#[test]
fn test_helper_signature_ringbuf_query() {
    let sig = HelperSignature::for_id(BpfHelper::RingbufQuery as u32)
        .expect("expected bpf_ringbuf_query helper signature");
    assert_eq!(sig.min_args, 2);
    assert_eq!(sig.max_args, 2);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
}

#[test]
fn test_helper_signature_socket_helpers() {
    let sig = HelperSignature::for_id(BpfHelper::SkLookupTcp as u32)
        .expect("expected bpf_sk_lookup_tcp helper signature");
    assert_eq!(sig.min_args, 5);
    assert_eq!(sig.max_args, 5);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::PointerMaybeNull);

    let sig = HelperSignature::for_id(BpfHelper::SkcLookupTcp as u32)
        .expect("expected bpf_skc_lookup_tcp helper signature");
    assert_eq!(sig.min_args, 5);
    assert_eq!(sig.max_args, 5);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::PointerMaybeNull);

    let sig = HelperSignature::for_id(BpfHelper::TcpCheckSyncookie as u32)
        .expect("expected bpf_tcp_check_syncookie helper signature");
    assert_eq!(sig.min_args, 5);
    assert_eq!(sig.max_args, 5);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(3), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(4), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);

    let sig = HelperSignature::for_id(BpfHelper::TcpGenSyncookie as u32)
        .expect("expected bpf_tcp_gen_syncookie helper signature");
    assert_eq!(sig.min_args, 5);
    assert_eq!(sig.max_args, 5);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(3), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(4), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);

    let sig = HelperSignature::for_id(BpfHelper::SkAssign as u32)
        .expect("expected bpf_sk_assign helper signature");
    assert_eq!(sig.min_args, 3);
    assert_eq!(sig.max_args, 3);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);

    let sig = HelperSignature::for_id(BpfHelper::SkRelease as u32)
        .expect("expected bpf_sk_release helper signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);

    let sig = HelperSignature::for_id(BpfHelper::SkFullsock as u32)
        .expect("expected bpf_sk_fullsock helper signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.ret_kind, HelperRetKind::PointerMaybeNull);

    let sig = HelperSignature::for_id(BpfHelper::TcpSock as u32)
        .expect("expected bpf_tcp_sock helper signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.ret_kind, HelperRetKind::PointerMaybeNull);

    let sig = HelperSignature::for_id(BpfHelper::SkcToTcpSock as u32)
        .expect("expected bpf_skc_to_tcp_sock helper signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.ret_kind, HelperRetKind::PointerMaybeNull);

    let sig = HelperSignature::for_id(BpfHelper::SkcToTcp6Sock as u32)
        .expect("expected bpf_skc_to_tcp6_sock helper signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.ret_kind, HelperRetKind::PointerMaybeNull);

    let sig = HelperSignature::for_id(BpfHelper::SkcToTcpTimewaitSock as u32)
        .expect("expected bpf_skc_to_tcp_timewait_sock helper signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.ret_kind, HelperRetKind::PointerMaybeNull);

    let sig = HelperSignature::for_id(BpfHelper::SkcToTcpRequestSock as u32)
        .expect("expected bpf_skc_to_tcp_request_sock helper signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.ret_kind, HelperRetKind::PointerMaybeNull);

    let sig = HelperSignature::for_id(BpfHelper::SkcToUdp6Sock as u32)
        .expect("expected bpf_skc_to_udp6_sock helper signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.ret_kind, HelperRetKind::PointerMaybeNull);

    let sig = HelperSignature::for_id(BpfHelper::SkcToUnixSock as u32)
        .expect("expected bpf_skc_to_unix_sock helper signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.ret_kind, HelperRetKind::PointerMaybeNull);

    let sig = HelperSignature::for_id(BpfHelper::SockFromFile as u32)
        .expect("expected bpf_sock_from_file helper signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.ret_kind, HelperRetKind::PointerMaybeNull);

    let sig = HelperSignature::for_id(BpfHelper::TaskPtRegs as u32)
        .expect("expected bpf_task_pt_regs helper signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.ret_kind, HelperRetKind::PointerMaybeNull);

    let sig = HelperSignature::for_id(BpfHelper::GetListenerSock as u32)
        .expect("expected bpf_get_listener_sock helper signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.ret_kind, HelperRetKind::PointerMaybeNull);
}

#[test]
fn test_helper_ref_kind_mappings() {
    assert_eq!(
        helper_acquire_ref_kind(BpfHelper::SkLookupTcp),
        Some(KfuncRefKind::Socket)
    );
    assert_eq!(
        helper_acquire_ref_kind(BpfHelper::SkLookupUdp),
        Some(KfuncRefKind::Socket)
    );
    assert_eq!(
        helper_acquire_ref_kind(BpfHelper::SkcLookupTcp),
        Some(KfuncRefKind::Socket)
    );
    assert_eq!(
        helper_release_ref_kind(BpfHelper::SkRelease),
        Some(KfuncRefKind::Socket)
    );
    assert_eq!(
        helper_pointer_arg_ref_kind(BpfHelper::SkRelease, 0),
        Some(KfuncRefKind::Socket)
    );
    assert_eq!(
        helper_pointer_arg_ref_kind(BpfHelper::TcpCheckSyncookie, 0),
        Some(KfuncRefKind::Socket)
    );
    assert_eq!(
        helper_pointer_arg_ref_kind(BpfHelper::TcpGenSyncookie, 0),
        Some(KfuncRefKind::Socket)
    );
    assert_eq!(
        helper_pointer_arg_ref_kind(BpfHelper::SkStorageGet, 1),
        Some(KfuncRefKind::Socket)
    );
    assert_eq!(
        helper_pointer_arg_ref_kind(BpfHelper::SkStorageDelete, 1),
        Some(KfuncRefKind::Socket)
    );
    assert_eq!(
        helper_pointer_arg_ref_kind(BpfHelper::SkAssign, 1),
        Some(KfuncRefKind::Socket)
    );
    assert_eq!(
        helper_pointer_arg_ref_kind(BpfHelper::TaskStorageGet, 1),
        Some(KfuncRefKind::Task)
    );
    assert_eq!(
        helper_pointer_arg_ref_kind(BpfHelper::TaskStorageDelete, 1),
        Some(KfuncRefKind::Task)
    );
    assert_eq!(
        helper_pointer_arg_ref_kind(BpfHelper::InodeStorageGet, 1),
        Some(KfuncRefKind::Inode)
    );
    assert_eq!(
        helper_pointer_arg_ref_kind(BpfHelper::InodeStorageDelete, 1),
        Some(KfuncRefKind::Inode)
    );
    assert_eq!(
        helper_pointer_arg_ref_kind(BpfHelper::SkcToTcpSock, 0),
        Some(KfuncRefKind::Socket)
    );
    assert_eq!(
        helper_pointer_arg_ref_kind(BpfHelper::SkcToTcp6Sock, 0),
        Some(KfuncRefKind::Socket)
    );
    assert_eq!(
        helper_pointer_arg_ref_kind(BpfHelper::SkcToTcpTimewaitSock, 0),
        Some(KfuncRefKind::Socket)
    );
    assert_eq!(
        helper_pointer_arg_ref_kind(BpfHelper::SkcToTcpRequestSock, 0),
        Some(KfuncRefKind::Socket)
    );
    assert_eq!(
        helper_pointer_arg_ref_kind(BpfHelper::SkcToUdp6Sock, 0),
        Some(KfuncRefKind::Socket)
    );
    assert_eq!(
        helper_pointer_arg_ref_kind(BpfHelper::SkcToUnixSock, 0),
        Some(KfuncRefKind::Socket)
    );
    assert_eq!(
        helper_pointer_arg_ref_kind(BpfHelper::SockFromFile, 0),
        Some(KfuncRefKind::File)
    );
    assert_eq!(
        helper_pointer_arg_ref_kind(BpfHelper::TaskPtRegs, 0),
        Some(KfuncRefKind::Task)
    );
    assert_eq!(helper_pointer_arg_ref_kind(BpfHelper::SkRelease, 1), None);
}

#[test]
fn test_kfunc_signature_task_from_pid() {
    let sig = KfuncSignature::for_name("bpf_task_from_pid")
        .expect("expected bpf_task_from_pid kfunc signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Scalar);
    assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);
}

#[test]
fn test_kfunc_signature_cgroup_release() {
    let sig = KfuncSignature::for_name("bpf_cgroup_release")
        .expect("expected bpf_cgroup_release kfunc signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::Void);
}

#[test]
fn test_kfunc_signature_cpumask_create() {
    let sig = KfuncSignature::for_name("bpf_cpumask_create")
        .expect("expected bpf_cpumask_create kfunc signature");
    assert_eq!(sig.min_args, 0);
    assert_eq!(sig.max_args, 0);
    assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);
}

#[test]
fn test_kfunc_signature_object_impls() {
    let sig = KfuncSignature::for_name("bpf_obj_new_impl")
        .expect("expected bpf_obj_new_impl kfunc signature");
    assert_eq!(sig.min_args, 2);
    assert_eq!(sig.max_args, 2);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Scalar);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Scalar);
    assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);

    let sig = KfuncSignature::for_name("bpf_obj_drop_impl")
        .expect("expected bpf_obj_drop_impl kfunc signature");
    assert_eq!(sig.min_args, 2);
    assert_eq!(sig.max_args, 2);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Scalar);
    assert_eq!(sig.ret_kind, KfuncRetKind::Void);

    let sig = KfuncSignature::for_name("bpf_refcount_acquire_impl")
        .expect("expected bpf_refcount_acquire_impl kfunc signature");
    assert_eq!(sig.min_args, 2);
    assert_eq!(sig.max_args, 2);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Scalar);
    assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);
}

#[test]
fn test_kfunc_signature_file_kfuncs() {
    let sig = KfuncSignature::for_name("bpf_get_task_exe_file")
        .expect("expected bpf_get_task_exe_file kfunc signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);

    let sig =
        KfuncSignature::for_name("bpf_put_file").expect("expected bpf_put_file kfunc signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::Void);
}

#[test]
fn test_kfunc_signature_crypto_ctx_kfuncs() {
    let sig = KfuncSignature::for_name("bpf_crypto_ctx_acquire")
        .expect("expected bpf_crypto_ctx_acquire kfunc signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);

    let sig = KfuncSignature::for_name("bpf_crypto_ctx_create")
        .expect("expected bpf_crypto_ctx_create kfunc signature");
    assert_eq!(sig.min_args, 3);
    assert_eq!(sig.max_args, 3);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Scalar);
    assert_eq!(sig.arg_kind(2), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);

    let sig = KfuncSignature::for_name("bpf_crypto_ctx_release")
        .expect("expected bpf_crypto_ctx_release kfunc signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::Void);

    let sig = KfuncSignature::for_name("bpf_crypto_encrypt")
        .expect("expected bpf_crypto_encrypt kfunc signature");
    assert_eq!(sig.min_args, 4);
    assert_eq!(sig.max_args, 4);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(2), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(3), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::Scalar);

    let sig = KfuncSignature::for_name("bpf_crypto_decrypt")
        .expect("expected bpf_crypto_decrypt kfunc signature");
    assert_eq!(sig.min_args, 4);
    assert_eq!(sig.max_args, 4);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(2), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(3), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::Scalar);
}

#[test]
fn test_kfunc_signature_kptr_container_impls() {
    let sig = KfuncSignature::for_name("bpf_percpu_obj_new_impl")
        .expect("expected bpf_percpu_obj_new_impl kfunc signature");
    assert_eq!(sig.min_args, 2);
    assert_eq!(sig.max_args, 2);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Scalar);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Scalar);
    assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);

    let sig = KfuncSignature::for_name("bpf_list_push_back_impl")
        .expect("expected bpf_list_push_back_impl kfunc signature");
    assert_eq!(sig.min_args, 4);
    assert_eq!(sig.max_args, 4);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(2), KfuncArgKind::Scalar);
    assert_eq!(sig.arg_kind(3), KfuncArgKind::Scalar);
    assert_eq!(sig.ret_kind, KfuncRetKind::Scalar);

    let sig = KfuncSignature::for_name("bpf_rbtree_first")
        .expect("expected bpf_rbtree_first kfunc signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);

    let sig = KfuncSignature::for_name("bpf_list_front")
        .expect("expected bpf_list_front kfunc signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);

    let sig =
        KfuncSignature::for_name("bpf_list_back").expect("expected bpf_list_back kfunc signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);

    let sig = KfuncSignature::for_name("bpf_rbtree_root")
        .expect("expected bpf_rbtree_root kfunc signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);

    let sig = KfuncSignature::for_name("bpf_rbtree_left")
        .expect("expected bpf_rbtree_left kfunc signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);

    let sig = KfuncSignature::for_name("bpf_rbtree_right")
        .expect("expected bpf_rbtree_right kfunc signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);
}

#[test]
fn test_kfunc_signature_task_vma_iter_kfuncs() {
    let sig = KfuncSignature::for_name("bpf_iter_task_vma_new")
        .expect("expected bpf_iter_task_vma_new kfunc signature");
    assert_eq!(sig.min_args, 3);
    assert_eq!(sig.max_args, 3);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(2), KfuncArgKind::Scalar);
    assert_eq!(sig.ret_kind, KfuncRetKind::Scalar);

    let sig = KfuncSignature::for_name("bpf_iter_task_vma_next")
        .expect("expected bpf_iter_task_vma_next kfunc signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);

    let sig = KfuncSignature::for_name("bpf_iter_task_vma_destroy")
        .expect("expected bpf_iter_task_vma_destroy kfunc signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::Void);
}

#[test]
fn test_kfunc_signature_task_iter_kfuncs() {
    let sig = KfuncSignature::for_name("bpf_iter_task_new")
        .expect("expected bpf_iter_task_new kfunc signature");
    assert_eq!(sig.min_args, 3);
    assert_eq!(sig.max_args, 3);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(2), KfuncArgKind::Scalar);
    assert_eq!(sig.ret_kind, KfuncRetKind::Scalar);

    let sig = KfuncSignature::for_name("bpf_iter_task_next")
        .expect("expected bpf_iter_task_next kfunc signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);

    let sig = KfuncSignature::for_name("bpf_iter_task_destroy")
        .expect("expected bpf_iter_task_destroy kfunc signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::Void);
}

#[test]
fn test_kfunc_signature_scx_dsq_iter_kfuncs() {
    let sig = KfuncSignature::for_name("bpf_iter_scx_dsq_new")
        .expect("expected bpf_iter_scx_dsq_new kfunc signature");
    assert_eq!(sig.min_args, 3);
    assert_eq!(sig.max_args, 3);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Scalar);
    assert_eq!(sig.arg_kind(2), KfuncArgKind::Scalar);
    assert_eq!(sig.ret_kind, KfuncRetKind::Scalar);

    let sig = KfuncSignature::for_name("bpf_iter_scx_dsq_next")
        .expect("expected bpf_iter_scx_dsq_next kfunc signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);

    let sig = KfuncSignature::for_name("bpf_iter_scx_dsq_destroy")
        .expect("expected bpf_iter_scx_dsq_destroy kfunc signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::Void);
}

#[test]
fn test_kfunc_signature_iter_num_kfuncs() {
    let sig = KfuncSignature::for_name("bpf_iter_num_new")
        .expect("expected bpf_iter_num_new kfunc signature");
    assert_eq!(sig.min_args, 3);
    assert_eq!(sig.max_args, 3);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Scalar);
    assert_eq!(sig.arg_kind(2), KfuncArgKind::Scalar);
    assert_eq!(sig.ret_kind, KfuncRetKind::Scalar);

    let sig = KfuncSignature::for_name("bpf_iter_num_next")
        .expect("expected bpf_iter_num_next kfunc signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);

    let sig = KfuncSignature::for_name("bpf_iter_num_destroy")
        .expect("expected bpf_iter_num_destroy kfunc signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::Void);
}

#[test]
fn test_kfunc_signature_iter_bits_kfuncs() {
    let sig = KfuncSignature::for_name("bpf_iter_bits_new")
        .expect("expected bpf_iter_bits_new kfunc signature");
    assert_eq!(sig.min_args, 3);
    assert_eq!(sig.max_args, 3);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(2), KfuncArgKind::Scalar);
    assert_eq!(sig.ret_kind, KfuncRetKind::Scalar);

    let sig = KfuncSignature::for_name("bpf_iter_bits_next")
        .expect("expected bpf_iter_bits_next kfunc signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);

    let sig = KfuncSignature::for_name("bpf_iter_bits_destroy")
        .expect("expected bpf_iter_bits_destroy kfunc signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::Void);
}

#[test]
fn test_kfunc_signature_iter_css_kfuncs() {
    let sig = KfuncSignature::for_name("bpf_iter_css_new")
        .expect("expected bpf_iter_css_new kfunc signature");
    assert_eq!(sig.min_args, 3);
    assert_eq!(sig.max_args, 3);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(2), KfuncArgKind::Scalar);
    assert_eq!(sig.ret_kind, KfuncRetKind::Scalar);

    let sig = KfuncSignature::for_name("bpf_iter_css_next")
        .expect("expected bpf_iter_css_next kfunc signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);

    let sig = KfuncSignature::for_name("bpf_iter_css_destroy")
        .expect("expected bpf_iter_css_destroy kfunc signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::Void);
}

#[test]
fn test_kfunc_signature_iter_css_task_kfuncs() {
    let sig = KfuncSignature::for_name("bpf_iter_css_task_new")
        .expect("expected bpf_iter_css_task_new kfunc signature");
    assert_eq!(sig.min_args, 3);
    assert_eq!(sig.max_args, 3);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(2), KfuncArgKind::Scalar);
    assert_eq!(sig.ret_kind, KfuncRetKind::Scalar);

    let sig = KfuncSignature::for_name("bpf_iter_css_task_next")
        .expect("expected bpf_iter_css_task_next kfunc signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);

    let sig = KfuncSignature::for_name("bpf_iter_css_task_destroy")
        .expect("expected bpf_iter_css_task_destroy kfunc signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::Void);
}

#[test]
fn test_kfunc_signature_iter_dmabuf_kfuncs() {
    let sig = KfuncSignature::for_name("bpf_iter_dmabuf_new")
        .expect("expected bpf_iter_dmabuf_new kfunc signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::Scalar);

    let sig = KfuncSignature::for_name("bpf_iter_dmabuf_next")
        .expect("expected bpf_iter_dmabuf_next kfunc signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);

    let sig = KfuncSignature::for_name("bpf_iter_dmabuf_destroy")
        .expect("expected bpf_iter_dmabuf_destroy kfunc signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::Void);
}

#[test]
fn test_kfunc_signature_iter_kmem_cache_kfuncs() {
    let sig = KfuncSignature::for_name("bpf_iter_kmem_cache_new")
        .expect("expected bpf_iter_kmem_cache_new kfunc signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::Scalar);

    let sig = KfuncSignature::for_name("bpf_iter_kmem_cache_next")
        .expect("expected bpf_iter_kmem_cache_next kfunc signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);

    let sig = KfuncSignature::for_name("bpf_iter_kmem_cache_destroy")
        .expect("expected bpf_iter_kmem_cache_destroy kfunc signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::Void);
}

#[test]
fn test_kfunc_signature_cpumask_and() {
    let populate = KfuncSignature::for_name("bpf_cpumask_populate")
        .expect("expected bpf_cpumask_populate kfunc signature");
    assert_eq!(populate.min_args, 3);
    assert_eq!(populate.max_args, 3);
    assert_eq!(populate.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(populate.arg_kind(1), KfuncArgKind::Pointer);
    assert_eq!(populate.arg_kind(2), KfuncArgKind::Scalar);
    assert_eq!(populate.ret_kind, KfuncRetKind::Scalar);

    let release_dtor = KfuncSignature::for_name("bpf_cpumask_release_dtor")
        .expect("expected bpf_cpumask_release_dtor kfunc signature");
    assert_eq!(release_dtor.min_args, 1);
    assert_eq!(release_dtor.max_args, 1);
    assert_eq!(release_dtor.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(release_dtor.ret_kind, KfuncRetKind::Void);

    let sig = KfuncSignature::for_name("bpf_cpumask_and")
        .expect("expected bpf_cpumask_and kfunc signature");
    assert_eq!(sig.min_args, 3);
    assert_eq!(sig.max_args, 3);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(2), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::Scalar);
}

#[test]
fn test_kfunc_signature_rcu_read_lock_helpers() {
    let lock = KfuncSignature::for_name("bpf_rcu_read_lock")
        .expect("expected bpf_rcu_read_lock kfunc signature");
    assert_eq!(lock.min_args, 0);
    assert_eq!(lock.max_args, 0);
    assert_eq!(lock.ret_kind, KfuncRetKind::Void);

    let unlock = KfuncSignature::for_name("bpf_rcu_read_unlock")
        .expect("expected bpf_rcu_read_unlock kfunc signature");
    assert_eq!(unlock.min_args, 0);
    assert_eq!(unlock.max_args, 0);
    assert_eq!(unlock.ret_kind, KfuncRetKind::Void);

    let disable = KfuncSignature::for_name("bpf_preempt_disable")
        .expect("expected bpf_preempt_disable kfunc signature");
    assert_eq!(disable.min_args, 0);
    assert_eq!(disable.max_args, 0);
    assert_eq!(disable.ret_kind, KfuncRetKind::Void);

    let enable = KfuncSignature::for_name("bpf_preempt_enable")
        .expect("expected bpf_preempt_enable kfunc signature");
    assert_eq!(enable.min_args, 0);
    assert_eq!(enable.max_args, 0);
    assert_eq!(enable.ret_kind, KfuncRetKind::Void);

    let irq_save = KfuncSignature::for_name("bpf_local_irq_save")
        .expect("expected bpf_local_irq_save kfunc signature");
    assert_eq!(irq_save.min_args, 1);
    assert_eq!(irq_save.max_args, 1);
    assert_eq!(irq_save.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(irq_save.ret_kind, KfuncRetKind::Void);

    let irq_restore = KfuncSignature::for_name("bpf_local_irq_restore")
        .expect("expected bpf_local_irq_restore kfunc signature");
    assert_eq!(irq_restore.min_args, 1);
    assert_eq!(irq_restore.max_args, 1);
    assert_eq!(irq_restore.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(irq_restore.ret_kind, KfuncRetKind::Void);

    let spin_lock = KfuncSignature::for_name("bpf_res_spin_lock")
        .expect("expected bpf_res_spin_lock kfunc signature");
    assert_eq!(spin_lock.min_args, 1);
    assert_eq!(spin_lock.max_args, 1);
    assert_eq!(spin_lock.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(spin_lock.ret_kind, KfuncRetKind::Scalar);

    let spin_unlock = KfuncSignature::for_name("bpf_res_spin_unlock")
        .expect("expected bpf_res_spin_unlock kfunc signature");
    assert_eq!(spin_unlock.min_args, 1);
    assert_eq!(spin_unlock.max_args, 1);
    assert_eq!(spin_unlock.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(spin_unlock.ret_kind, KfuncRetKind::Void);

    let spin_lock_irqsave = KfuncSignature::for_name("bpf_res_spin_lock_irqsave")
        .expect("expected bpf_res_spin_lock_irqsave kfunc signature");
    assert_eq!(spin_lock_irqsave.min_args, 2);
    assert_eq!(spin_lock_irqsave.max_args, 2);
    assert_eq!(spin_lock_irqsave.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(spin_lock_irqsave.arg_kind(1), KfuncArgKind::Pointer);
    assert_eq!(spin_lock_irqsave.ret_kind, KfuncRetKind::Scalar);

    let spin_unlock_irqrestore = KfuncSignature::for_name("bpf_res_spin_unlock_irqrestore")
        .expect("expected bpf_res_spin_unlock_irqrestore kfunc signature");
    assert_eq!(spin_unlock_irqrestore.min_args, 2);
    assert_eq!(spin_unlock_irqrestore.max_args, 2);
    assert_eq!(spin_unlock_irqrestore.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(spin_unlock_irqrestore.arg_kind(1), KfuncArgKind::Pointer);
    assert_eq!(spin_unlock_irqrestore.ret_kind, KfuncRetKind::Void);
}

#[test]
fn test_kfunc_signature_map_sum_elem_count() {
    let sig = KfuncSignature::for_name("bpf_map_sum_elem_count")
        .expect("expected bpf_map_sum_elem_count kfunc signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::Scalar);
}

#[test]
fn test_kfunc_signature_copy_from_user_strs() {
    let sig = KfuncSignature::for_name("bpf_copy_from_user_str")
        .expect("expected bpf_copy_from_user_str kfunc signature");
    assert_eq!(sig.min_args, 4);
    assert_eq!(sig.max_args, 4);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Scalar);
    assert_eq!(sig.arg_kind(2), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(3), KfuncArgKind::Scalar);
    assert_eq!(sig.ret_kind, KfuncRetKind::Scalar);

    let sig = KfuncSignature::for_name("bpf_copy_from_user_dynptr")
        .expect("expected bpf_copy_from_user_dynptr kfunc signature");
    assert_eq!(sig.min_args, 4);
    assert_eq!(sig.max_args, 4);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Scalar);
    assert_eq!(sig.arg_kind(2), KfuncArgKind::Scalar);
    assert_eq!(sig.arg_kind(3), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::Scalar);

    let sig = KfuncSignature::for_name("bpf_copy_from_user_task_str")
        .expect("expected bpf_copy_from_user_task_str kfunc signature");
    assert_eq!(sig.min_args, 5);
    assert_eq!(sig.max_args, 5);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Scalar);
    assert_eq!(sig.arg_kind(2), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(3), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(4), KfuncArgKind::Scalar);
    assert_eq!(sig.ret_kind, KfuncRetKind::Scalar);

    let sig = KfuncSignature::for_name("bpf_copy_from_user_task_dynptr")
        .expect("expected bpf_copy_from_user_task_dynptr kfunc signature");
    assert_eq!(sig.min_args, 5);
    assert_eq!(sig.max_args, 5);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Scalar);
    assert_eq!(sig.arg_kind(2), KfuncArgKind::Scalar);
    assert_eq!(sig.arg_kind(3), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(4), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::Scalar);

    let sig = KfuncSignature::for_name("bpf_copy_from_user_task_str_dynptr")
        .expect("expected bpf_copy_from_user_task_str_dynptr kfunc signature");
    assert_eq!(sig.min_args, 5);
    assert_eq!(sig.max_args, 5);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Scalar);
    assert_eq!(sig.arg_kind(2), KfuncArgKind::Scalar);
    assert_eq!(sig.arg_kind(3), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(4), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::Scalar);
}

#[test]
fn test_kfunc_signature_dynptr_core_kfuncs() {
    let sig =
        KfuncSignature::for_name("bpf_dynptr_adjust").expect("expected bpf_dynptr_adjust sig");
    assert_eq!(sig.min_args, 3);
    assert_eq!(sig.max_args, 3);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Scalar);
    assert_eq!(sig.arg_kind(2), KfuncArgKind::Scalar);
    assert_eq!(sig.ret_kind, KfuncRetKind::Scalar);

    let sig = KfuncSignature::for_name("bpf_dynptr_clone").expect("expected bpf_dynptr_clone sig");
    assert_eq!(sig.min_args, 2);
    assert_eq!(sig.max_args, 2);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::Scalar);

    let sig = KfuncSignature::for_name("bpf_dynptr_copy").expect("expected bpf_dynptr_copy sig");
    assert_eq!(sig.min_args, 5);
    assert_eq!(sig.max_args, 5);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Scalar);
    assert_eq!(sig.arg_kind(2), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(3), KfuncArgKind::Scalar);
    assert_eq!(sig.arg_kind(4), KfuncArgKind::Scalar);
    assert_eq!(sig.ret_kind, KfuncRetKind::Scalar);

    let sig =
        KfuncSignature::for_name("bpf_dynptr_size").expect("expected bpf_dynptr_size signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::Scalar);

    let sig = KfuncSignature::for_name("bpf_dynptr_is_null")
        .expect("expected bpf_dynptr_is_null signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::Scalar);

    let sig = KfuncSignature::for_name("bpf_dynptr_is_rdonly")
        .expect("expected bpf_dynptr_is_rdonly signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::Scalar);

    let sig =
        KfuncSignature::for_name("bpf_dynptr_memset").expect("expected bpf_dynptr_memset sig");
    assert_eq!(sig.min_args, 4);
    assert_eq!(sig.max_args, 4);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Scalar);
    assert_eq!(sig.arg_kind(2), KfuncArgKind::Scalar);
    assert_eq!(sig.arg_kind(3), KfuncArgKind::Scalar);
    assert_eq!(sig.ret_kind, KfuncRetKind::Scalar);

    let sig = KfuncSignature::for_name("bpf_dynptr_slice").expect("expected bpf_dynptr_slice sig");
    assert_eq!(sig.min_args, 4);
    assert_eq!(sig.max_args, 4);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Scalar);
    assert_eq!(sig.arg_kind(2), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(3), KfuncArgKind::Scalar);
    assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);

    let sig = KfuncSignature::for_name("bpf_dynptr_slice_rdwr")
        .expect("expected bpf_dynptr_slice_rdwr sig");
    assert_eq!(sig.min_args, 4);
    assert_eq!(sig.max_args, 4);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Scalar);
    assert_eq!(sig.arg_kind(2), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(3), KfuncArgKind::Scalar);
    assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);
}

#[test]
fn test_unknown_kfunc_signature_message_for_missing_symbol() {
    let msg = unknown_kfunc_signature_message("__nu_plugin_ebpf_missing_kfunc_for_test__");
    assert!(msg.contains("unknown kfunc '__nu_plugin_ebpf_missing_kfunc_for_test__'"));
    assert!(msg.contains("typed signature required"));
}

#[test]
fn test_kfunc_signature_for_name_or_kernel_btf_prefers_builtin() {
    let sig = KfuncSignature::for_name_or_kernel_btf("bpf_task_from_pid")
        .expect("expected built-in bpf_task_from_pid signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Scalar);
    assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);
}

#[test]
fn test_kfunc_signature_for_name_or_kernel_btf_missing_symbol() {
    assert!(
        KfuncSignature::for_name_or_kernel_btf("__nu_plugin_ebpf_missing_kfunc_for_test__")
            .is_none()
    );
}

#[test]
fn test_kfunc_scalar_arg_requires_known_const_static_mapping() {
    assert!(kfunc_scalar_arg_requires_known_const("bpf_dynptr_slice", 3));
    assert!(kfunc_scalar_arg_requires_known_const(
        "bpf_dynptr_slice_rdwr",
        3
    ));
    assert!(!kfunc_scalar_arg_requires_known_const(
        "bpf_dynptr_slice",
        2
    ));
}

#[test]
fn test_kfunc_scalar_arg_requires_positive_static_mapping() {
    assert!(kfunc_scalar_arg_requires_positive("bpf_path_d_path", 2));
    assert!(kfunc_scalar_arg_requires_positive("scx_bpf_events", 1));
    assert!(kfunc_scalar_arg_requires_positive("bpf_dynptr_slice", 3));
    assert!(!kfunc_scalar_arg_requires_positive("bpf_dynptr_slice", 2));
}

#[test]
fn test_kfunc_pointer_arg_size_from_scalar_static_mapping() {
    assert_eq!(
        kfunc_pointer_arg_size_from_scalar("bpf_path_d_path", 1),
        Some(2)
    );
    assert_eq!(
        kfunc_pointer_arg_size_from_scalar("bpf_copy_from_user_str", 0),
        Some(1)
    );
    assert_eq!(
        kfunc_pointer_arg_size_from_scalar("bpf_dynptr_size", 0),
        None
    );
}

#[test]
fn test_kfunc_pointer_arg_fixed_size_static_mapping() {
    assert_eq!(kfunc_pointer_arg_fixed_size("bpf_dynptr_size", 0), Some(16));
    assert_eq!(
        kfunc_pointer_arg_fixed_size("bpf_dynptr_clone", 0),
        Some(16)
    );
    assert_eq!(kfunc_pointer_arg_fixed_size("bpf_path_d_path", 1), None);
}

#[test]
fn test_kfunc_signature_scx_dsq_insert() {
    let sig = KfuncSignature::for_name("scx_bpf_dsq_insert")
        .expect("expected scx_bpf_dsq_insert kfunc signature");
    assert_eq!(sig.min_args, 4);
    assert_eq!(sig.max_args, 4);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::Void);
}

#[test]
fn test_kfunc_signature_scx_task_cgroup_and_select_cpu() {
    let sig = KfuncSignature::for_name("scx_bpf_task_cgroup")
        .expect("expected scx_bpf_task_cgroup kfunc signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);

    let sig = KfuncSignature::for_name("scx_bpf_select_cpu_and")
        .expect("expected scx_bpf_select_cpu_and kfunc signature");
    assert_eq!(sig.min_args, 5);
    assert_eq!(sig.max_args, 5);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Scalar);
    assert_eq!(sig.arg_kind(2), KfuncArgKind::Scalar);
    assert_eq!(sig.arg_kind(3), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(4), KfuncArgKind::Scalar);
    assert_eq!(sig.ret_kind, KfuncRetKind::Scalar);

    let sig = KfuncSignature::for_name("scx_bpf_select_cpu_dfl")
        .expect("expected scx_bpf_select_cpu_dfl kfunc signature");
    assert_eq!(sig.min_args, 4);
    assert_eq!(sig.max_args, 4);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Scalar);
    assert_eq!(sig.arg_kind(2), KfuncArgKind::Scalar);
    assert_eq!(sig.arg_kind(3), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::Scalar);

    let sig = KfuncSignature::for_name("scx_bpf_dsq_move")
        .expect("expected scx_bpf_dsq_move kfunc signature");
    assert_eq!(sig.min_args, 4);
    assert_eq!(sig.max_args, 4);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(2), KfuncArgKind::Scalar);
    assert_eq!(sig.arg_kind(3), KfuncArgKind::Scalar);
    assert_eq!(sig.ret_kind, KfuncRetKind::Scalar);

    let sig = KfuncSignature::for_name("scx_bpf_dsq_move_vtime")
        .expect("expected scx_bpf_dsq_move_vtime kfunc signature");
    assert_eq!(sig.min_args, 4);
    assert_eq!(sig.max_args, 4);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(2), KfuncArgKind::Scalar);
    assert_eq!(sig.arg_kind(3), KfuncArgKind::Scalar);
    assert_eq!(sig.ret_kind, KfuncRetKind::Scalar);

    let sig = KfuncSignature::for_name("scx_bpf_dsq_move_set_slice")
        .expect("expected scx_bpf_dsq_move_set_slice kfunc signature");
    assert_eq!(sig.min_args, 2);
    assert_eq!(sig.max_args, 2);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Scalar);
    assert_eq!(sig.ret_kind, KfuncRetKind::Void);

    let sig = KfuncSignature::for_name("scx_bpf_dsq_move_set_vtime")
        .expect("expected scx_bpf_dsq_move_set_vtime kfunc signature");
    assert_eq!(sig.min_args, 2);
    assert_eq!(sig.max_args, 2);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Scalar);
    assert_eq!(sig.ret_kind, KfuncRetKind::Void);

    let sig = KfuncSignature::for_name("scx_bpf_cpu_rq")
        .expect("expected scx_bpf_cpu_rq kfunc signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Scalar);
    assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);

    let sig = KfuncSignature::for_name("scx_bpf_dump_bstr")
        .expect("expected scx_bpf_dump_bstr kfunc signature");
    assert_eq!(sig.min_args, 3);
    assert_eq!(sig.max_args, 3);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(2), KfuncArgKind::Scalar);
    assert_eq!(sig.ret_kind, KfuncRetKind::Void);

    let sig = KfuncSignature::for_name("scx_bpf_error_bstr")
        .expect("expected scx_bpf_error_bstr kfunc signature");
    assert_eq!(sig.min_args, 3);
    assert_eq!(sig.max_args, 3);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(2), KfuncArgKind::Scalar);
    assert_eq!(sig.ret_kind, KfuncRetKind::Void);

    let sig = KfuncSignature::for_name("scx_bpf_events")
        .expect("expected scx_bpf_events kfunc signature");
    assert_eq!(sig.min_args, 2);
    assert_eq!(sig.max_args, 2);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Scalar);
    assert_eq!(sig.ret_kind, KfuncRetKind::Void);

    let sig = KfuncSignature::for_name("scx_bpf_exit_bstr")
        .expect("expected scx_bpf_exit_bstr kfunc signature");
    assert_eq!(sig.min_args, 4);
    assert_eq!(sig.max_args, 4);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Scalar);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(2), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(3), KfuncArgKind::Scalar);
    assert_eq!(sig.ret_kind, KfuncRetKind::Void);

    let sig = KfuncSignature::for_name("scx_bpf_get_online_cpumask")
        .expect("expected scx_bpf_get_online_cpumask kfunc signature");
    assert_eq!(sig.min_args, 0);
    assert_eq!(sig.max_args, 0);
    assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);

    let sig = KfuncSignature::for_name("scx_bpf_get_possible_cpumask")
        .expect("expected scx_bpf_get_possible_cpumask kfunc signature");
    assert_eq!(sig.min_args, 0);
    assert_eq!(sig.max_args, 0);
    assert_eq!(sig.ret_kind, KfuncRetKind::PointerMaybeNull);

    let sig = KfuncSignature::for_name("scx_bpf_put_cpumask")
        .expect("expected scx_bpf_put_cpumask kfunc signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::Void);

    let sig = KfuncSignature::for_name("scx_bpf_put_idle_cpumask")
        .expect("expected scx_bpf_put_idle_cpumask kfunc signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.ret_kind, KfuncRetKind::Void);
}

#[test]
fn test_kfunc_ref_kind_mappings() {
    assert_eq!(
        kfunc_acquire_ref_kind("bpf_task_from_pid"),
        Some(KfuncRefKind::Task)
    );
    assert_eq!(
        kfunc_acquire_ref_kind("bpf_cgroup_from_id"),
        Some(KfuncRefKind::Cgroup)
    );
    assert_eq!(
        kfunc_acquire_ref_kind("bpf_get_task_exe_file"),
        Some(KfuncRefKind::File)
    );
    assert_eq!(
        kfunc_acquire_ref_kind("bpf_crypto_ctx_acquire"),
        Some(KfuncRefKind::CryptoCtx)
    );
    assert_eq!(
        kfunc_acquire_ref_kind("bpf_crypto_ctx_create"),
        Some(KfuncRefKind::CryptoCtx)
    );
    assert_eq!(
        kfunc_acquire_ref_kind("bpf_obj_new_impl"),
        Some(KfuncRefKind::Object)
    );
    assert_eq!(
        kfunc_acquire_ref_kind("bpf_percpu_obj_new_impl"),
        Some(KfuncRefKind::Object)
    );
    assert_eq!(
        kfunc_acquire_ref_kind("bpf_list_pop_front"),
        Some(KfuncRefKind::Object)
    );
    assert_eq!(
        kfunc_acquire_ref_kind("bpf_rbtree_remove"),
        Some(KfuncRefKind::Object)
    );
    assert_eq!(
        kfunc_acquire_ref_kind("scx_bpf_task_cgroup"),
        Some(KfuncRefKind::Cgroup)
    );
    assert_eq!(
        kfunc_acquire_ref_kind("scx_bpf_get_online_cpumask"),
        Some(KfuncRefKind::Cpumask)
    );
    assert_eq!(
        kfunc_acquire_ref_kind("scx_bpf_get_idle_cpumask"),
        Some(KfuncRefKind::Cpumask)
    );
    assert_eq!(
        kfunc_release_ref_kind("bpf_task_release"),
        Some(KfuncRefKind::Task)
    );
    assert_eq!(
        kfunc_release_ref_kind("bpf_cgroup_release"),
        Some(KfuncRefKind::Cgroup)
    );
    assert_eq!(
        kfunc_release_ref_kind("bpf_put_file"),
        Some(KfuncRefKind::File)
    );
    assert_eq!(
        kfunc_release_ref_kind("bpf_crypto_ctx_release"),
        Some(KfuncRefKind::CryptoCtx)
    );
    assert_eq!(
        kfunc_release_ref_kind("bpf_obj_drop_impl"),
        Some(KfuncRefKind::Object)
    );
    assert_eq!(
        kfunc_release_ref_kind("bpf_percpu_obj_drop_impl"),
        Some(KfuncRefKind::Object)
    );
    assert_eq!(
        kfunc_release_ref_kind("bpf_list_push_front_impl"),
        Some(KfuncRefKind::Object)
    );
    assert_eq!(
        kfunc_release_ref_kind("bpf_rbtree_add_impl"),
        Some(KfuncRefKind::Object)
    );
    assert_eq!(
        kfunc_release_ref_kind("bpf_cpumask_release"),
        Some(KfuncRefKind::Cpumask)
    );
    assert_eq!(
        kfunc_release_ref_kind("bpf_cpumask_release_dtor"),
        Some(KfuncRefKind::Cpumask)
    );
    assert_eq!(
        kfunc_release_ref_kind("scx_bpf_put_cpumask"),
        Some(KfuncRefKind::Cpumask)
    );
    assert_eq!(
        kfunc_release_ref_kind("scx_bpf_put_idle_cpumask"),
        Some(KfuncRefKind::Cpumask)
    );
    assert_eq!(kfunc_release_ref_arg_index("bpf_task_release"), Some(0));
    assert_eq!(kfunc_release_ref_arg_index("bpf_obj_drop_impl"), Some(0));
    assert_eq!(
        kfunc_release_ref_arg_index("bpf_list_push_front_impl"),
        Some(1)
    );
    assert_eq!(kfunc_release_ref_arg_index("bpf_rbtree_add_impl"), Some(1));
}

#[test]
fn test_kfunc_pointer_arg_ref_kind_mappings() {
    assert_eq!(
        kfunc_pointer_arg_ref_kind("bpf_task_under_cgroup", 0),
        Some(KfuncRefKind::Task)
    );
    assert_eq!(
        kfunc_pointer_arg_ref_kind("bpf_get_task_exe_file", 0),
        Some(KfuncRefKind::Task)
    );
    assert_eq!(
        kfunc_pointer_arg_ref_kind("bpf_iter_task_vma_new", 1),
        Some(KfuncRefKind::Task)
    );
    assert_eq!(
        kfunc_pointer_arg_ref_kind("bpf_iter_task_new", 1),
        Some(KfuncRefKind::Task)
    );
    assert_eq!(
        kfunc_pointer_arg_ref_kind("bpf_task_under_cgroup", 1),
        Some(KfuncRefKind::Cgroup)
    );
    assert_eq!(
        kfunc_pointer_arg_ref_kind("bpf_iter_css_new", 1),
        Some(KfuncRefKind::Cgroup)
    );
    assert_eq!(
        kfunc_pointer_arg_ref_kind("bpf_iter_css_task_new", 1),
        Some(KfuncRefKind::Cgroup)
    );
    assert_eq!(
        kfunc_pointer_arg_ref_kind("bpf_put_file", 0),
        Some(KfuncRefKind::File)
    );
    assert_eq!(
        kfunc_pointer_arg_ref_kind("bpf_crypto_ctx_acquire", 0),
        Some(KfuncRefKind::CryptoCtx)
    );
    assert_eq!(
        kfunc_pointer_arg_ref_kind("bpf_crypto_ctx_release", 0),
        Some(KfuncRefKind::CryptoCtx)
    );
    assert_eq!(
        kfunc_pointer_arg_ref_kind("bpf_crypto_encrypt", 0),
        Some(KfuncRefKind::CryptoCtx)
    );
    assert_eq!(
        kfunc_pointer_arg_ref_kind("bpf_crypto_decrypt", 0),
        Some(KfuncRefKind::CryptoCtx)
    );
    assert_eq!(
        kfunc_pointer_arg_ref_kind("bpf_obj_drop_impl", 0),
        Some(KfuncRefKind::Object)
    );
    assert_eq!(
        kfunc_pointer_arg_ref_kind("bpf_percpu_obj_drop_impl", 0),
        Some(KfuncRefKind::Object)
    );
    assert_eq!(
        kfunc_pointer_arg_ref_kind("bpf_list_push_front_impl", 1),
        Some(KfuncRefKind::Object)
    );
    assert_eq!(
        kfunc_pointer_arg_ref_kind("bpf_list_push_back_impl", 1),
        Some(KfuncRefKind::Object)
    );
    assert_eq!(
        kfunc_pointer_arg_ref_kind("bpf_rbtree_add_impl", 1),
        Some(KfuncRefKind::Object)
    );
    assert_eq!(
        kfunc_pointer_arg_ref_kind("bpf_cpumask_release", 0),
        Some(KfuncRefKind::Cpumask)
    );
    assert_eq!(
        kfunc_pointer_arg_ref_kind("bpf_cpumask_release_dtor", 0),
        Some(KfuncRefKind::Cpumask)
    );
    assert_eq!(
        kfunc_pointer_arg_ref_kind("bpf_cpumask_populate", 0),
        Some(KfuncRefKind::Cpumask)
    );
    assert_eq!(
        kfunc_pointer_arg_ref_kind("bpf_cpumask_test_cpu", 1),
        Some(KfuncRefKind::Cpumask)
    );
    assert_eq!(
        kfunc_pointer_arg_ref_kind("scx_bpf_task_cpu", 0),
        Some(KfuncRefKind::Task)
    );
    assert_eq!(
        kfunc_pointer_arg_ref_kind("scx_bpf_task_cgroup", 0),
        Some(KfuncRefKind::Task)
    );
    assert_eq!(
        kfunc_pointer_arg_ref_kind("bpf_copy_from_user_task_str", 3),
        Some(KfuncRefKind::Task)
    );
    assert_eq!(
        kfunc_pointer_arg_ref_kind("bpf_copy_from_user_task_dynptr", 4),
        Some(KfuncRefKind::Task)
    );
    assert_eq!(
        kfunc_pointer_arg_ref_kind("bpf_copy_from_user_task_str_dynptr", 4),
        Some(KfuncRefKind::Task)
    );
    assert_eq!(
        kfunc_pointer_arg_ref_kind("scx_bpf_select_cpu_and", 0),
        Some(KfuncRefKind::Task)
    );
    assert_eq!(
        kfunc_pointer_arg_ref_kind("scx_bpf_dsq_move", 1),
        Some(KfuncRefKind::Task)
    );
    assert_eq!(
        kfunc_pointer_arg_ref_kind("scx_bpf_dsq_move_vtime", 1),
        Some(KfuncRefKind::Task)
    );
    assert_eq!(
        kfunc_pointer_arg_ref_kind("scx_bpf_dsq_move_set_slice", 0),
        None
    );
    assert_eq!(
        kfunc_pointer_arg_ref_kind("scx_bpf_dsq_move_set_vtime", 0),
        None
    );
    assert_eq!(
        kfunc_pointer_arg_ref_kind("scx_bpf_pick_idle_cpu", 0),
        Some(KfuncRefKind::Cpumask)
    );
    assert_eq!(
        kfunc_pointer_arg_ref_kind("scx_bpf_select_cpu_and", 3),
        Some(KfuncRefKind::Cpumask)
    );
    assert_eq!(
        kfunc_pointer_arg_ref_kind("scx_bpf_select_cpu_dfl", 3),
        Some(KfuncRefKind::Cpumask)
    );
    assert_eq!(
        kfunc_pointer_arg_ref_kind("scx_bpf_put_cpumask", 0),
        Some(KfuncRefKind::Cpumask)
    );
    assert_eq!(
        kfunc_pointer_arg_ref_kind("scx_bpf_put_idle_cpumask", 0),
        Some(KfuncRefKind::Cpumask)
    );
    assert_eq!(kfunc_pointer_arg_ref_kind("bpf_task_from_pid", 0), None);
}

#[test]
fn test_kfunc_pointer_arg_requires_kernel_mappings() {
    assert!(kfunc_pointer_arg_requires_kernel("bpf_task_release", 0));
    assert!(kfunc_pointer_arg_requires_kernel("bpf_put_file", 0));
    assert!(kfunc_pointer_arg_requires_kernel(
        "bpf_crypto_ctx_release",
        0
    ));
    assert!(kfunc_pointer_arg_requires_kernel("bpf_crypto_encrypt", 0));
    assert!(kfunc_pointer_arg_requires_kernel(
        "bpf_list_push_front_impl",
        0
    ));
    assert!(kfunc_pointer_arg_requires_kernel(
        "bpf_list_push_front_impl",
        1
    ));
    assert!(kfunc_pointer_arg_requires_kernel("bpf_list_front", 0));
    assert!(kfunc_pointer_arg_requires_kernel("bpf_list_back", 0));
    assert!(kfunc_pointer_arg_requires_kernel("bpf_rbtree_first", 0));
    assert!(kfunc_pointer_arg_requires_kernel("bpf_rbtree_root", 0));
    assert!(kfunc_pointer_arg_requires_kernel("bpf_rbtree_left", 0));
    assert!(kfunc_pointer_arg_requires_kernel("bpf_rbtree_right", 0));
    assert!(kfunc_pointer_arg_requires_kernel("bpf_path_d_path", 0));
    assert!(kfunc_pointer_arg_requires_kernel(
        "bpf_map_sum_elem_count",
        0
    ));
    assert!(kfunc_pointer_arg_requires_kernel(
        "bpf_iter_task_vma_new",
        1
    ));
    assert!(kfunc_pointer_arg_requires_kernel("bpf_iter_css_new", 1));
    assert!(kfunc_pointer_arg_requires_kernel(
        "bpf_iter_css_task_new",
        1
    ));
    assert!(!kfunc_pointer_arg_requires_kernel(
        "scx_bpf_dsq_move_set_slice",
        0
    ));
    assert!(!kfunc_pointer_arg_requires_kernel(
        "scx_bpf_dsq_move_set_vtime",
        0
    ));
    assert!(kfunc_pointer_arg_requires_kernel(
        "scx_bpf_select_cpu_dfl",
        3
    ));
    assert!(kfunc_pointer_arg_requires_kernel(
        "bpf_copy_from_user_task_str",
        3
    ));
    assert!(kfunc_pointer_arg_requires_kernel(
        "bpf_copy_from_user_task_dynptr",
        4
    ));
    assert!(kfunc_pointer_arg_requires_kernel(
        "bpf_copy_from_user_task_str_dynptr",
        4
    ));
    assert!(!kfunc_pointer_arg_requires_kernel(
        "bpf_iter_task_vma_new",
        0
    ));
    assert!(!kfunc_pointer_arg_requires_kernel(
        "bpf_list_push_front_impl",
        2
    ));
    assert!(!kfunc_pointer_arg_requires_kernel(
        "bpf_copy_from_user_task_str",
        2
    ));
    assert!(!kfunc_pointer_arg_requires_kernel(
        "bpf_copy_from_user_task_dynptr",
        3
    ));
    assert!(!kfunc_pointer_arg_requires_kernel("bpf_obj_new_impl", 1));
    assert!(!kfunc_pointer_arg_requires_kernel("bpf_local_irq_save", 0));
    assert!(!kfunc_pointer_arg_requires_kernel(
        "bpf_local_irq_restore",
        0
    ));
    assert!(kfunc_pointer_arg_requires_kernel("bpf_res_spin_lock", 0));
    assert!(kfunc_pointer_arg_requires_kernel("bpf_res_spin_unlock", 0));
    assert!(kfunc_pointer_arg_requires_kernel(
        "bpf_res_spin_lock_irqsave",
        0
    ));
    assert!(kfunc_pointer_arg_requires_kernel(
        "bpf_res_spin_unlock_irqrestore",
        0
    ));
}

#[test]
fn test_kfunc_pointer_arg_requires_user_mappings() {
    assert!(kfunc_pointer_arg_requires_user("bpf_copy_from_user_str", 2));
    assert!(kfunc_pointer_arg_requires_user(
        "bpf_copy_from_user_task_str",
        2
    ));
    assert!(kfunc_pointer_arg_requires_user(
        "bpf_copy_from_user_dynptr",
        3
    ));
    assert!(kfunc_pointer_arg_requires_user(
        "bpf_copy_from_user_task_dynptr",
        3
    ));
    assert!(kfunc_pointer_arg_requires_user(
        "bpf_copy_from_user_task_str_dynptr",
        3
    ));
    assert!(!kfunc_pointer_arg_requires_user(
        "bpf_copy_from_user_str",
        0
    ));
    assert!(!kfunc_pointer_arg_requires_user("bpf_task_release", 0));
}

#[test]
fn test_kfunc_pointer_arg_requires_stack_mappings() {
    assert!(kfunc_pointer_arg_requires_stack("bpf_local_irq_save", 0));
    assert!(kfunc_pointer_arg_requires_stack("bpf_local_irq_restore", 0));
    assert!(!kfunc_pointer_arg_requires_stack("bpf_local_irq_save", 1));
    assert!(kfunc_pointer_arg_requires_stack(
        "bpf_res_spin_lock_irqsave",
        1
    ));
    assert!(kfunc_pointer_arg_requires_stack(
        "bpf_res_spin_unlock_irqrestore",
        1
    ));
    assert!(kfunc_pointer_arg_requires_stack("bpf_iter_task_vma_new", 0));
    assert!(kfunc_pointer_arg_requires_stack(
        "bpf_iter_task_vma_next",
        0
    ));
    assert!(kfunc_pointer_arg_requires_stack(
        "bpf_iter_task_vma_destroy",
        0
    ));
    assert!(kfunc_pointer_arg_requires_stack("bpf_iter_task_new", 0));
    assert!(kfunc_pointer_arg_requires_stack("bpf_iter_task_next", 0));
    assert!(kfunc_pointer_arg_requires_stack("bpf_iter_task_destroy", 0));
    assert!(kfunc_pointer_arg_requires_stack("bpf_iter_scx_dsq_new", 0));
    assert!(kfunc_pointer_arg_requires_stack("bpf_iter_scx_dsq_next", 0));
    assert!(kfunc_pointer_arg_requires_stack(
        "bpf_iter_scx_dsq_destroy",
        0
    ));
    assert!(kfunc_pointer_arg_requires_stack(
        "bpf_copy_from_user_dynptr",
        0
    ));
    assert!(kfunc_pointer_arg_requires_stack(
        "bpf_copy_from_user_task_dynptr",
        0
    ));
    assert!(kfunc_pointer_arg_requires_stack(
        "bpf_copy_from_user_task_str_dynptr",
        0
    ));
    assert!(kfunc_pointer_arg_requires_stack("bpf_dynptr_adjust", 0));
    assert!(kfunc_pointer_arg_requires_stack("bpf_dynptr_clone", 0));
    assert!(kfunc_pointer_arg_requires_stack("bpf_dynptr_clone", 1));
    assert!(kfunc_pointer_arg_requires_stack("bpf_dynptr_copy", 0));
    assert!(kfunc_pointer_arg_requires_stack("bpf_dynptr_copy", 2));
    assert!(kfunc_pointer_arg_requires_stack("bpf_dynptr_size", 0));
    assert!(kfunc_pointer_arg_requires_stack("bpf_dynptr_is_null", 0));
    assert!(kfunc_pointer_arg_requires_stack("bpf_dynptr_is_rdonly", 0));
    assert!(kfunc_pointer_arg_requires_stack("bpf_dynptr_memset", 0));
    assert!(kfunc_pointer_arg_requires_stack("bpf_dynptr_slice", 0));
    assert!(kfunc_pointer_arg_requires_stack("bpf_dynptr_slice_rdwr", 0));
    assert!(kfunc_pointer_arg_requires_stack("scx_bpf_dsq_move", 0));
    assert!(kfunc_pointer_arg_requires_stack(
        "scx_bpf_dsq_move_set_slice",
        0
    ));
    assert!(kfunc_pointer_arg_requires_stack(
        "scx_bpf_dsq_move_set_vtime",
        0
    ));
    assert!(kfunc_pointer_arg_requires_stack(
        "scx_bpf_dsq_move_vtime",
        0
    ));
    assert!(kfunc_pointer_arg_requires_stack("bpf_iter_num_new", 0));
    assert!(kfunc_pointer_arg_requires_stack("bpf_iter_num_next", 0));
    assert!(kfunc_pointer_arg_requires_stack("bpf_iter_num_destroy", 0));
    assert!(kfunc_pointer_arg_requires_stack("bpf_iter_bits_new", 0));
    assert!(kfunc_pointer_arg_requires_stack("bpf_iter_bits_next", 0));
    assert!(kfunc_pointer_arg_requires_stack("bpf_iter_bits_destroy", 0));
    assert!(kfunc_pointer_arg_requires_stack("bpf_iter_css_new", 0));
    assert!(kfunc_pointer_arg_requires_stack("bpf_iter_css_next", 0));
    assert!(kfunc_pointer_arg_requires_stack("bpf_iter_css_destroy", 0));
    assert!(kfunc_pointer_arg_requires_stack("bpf_iter_css_task_new", 0));
    assert!(kfunc_pointer_arg_requires_stack(
        "bpf_iter_css_task_next",
        0
    ));
    assert!(kfunc_pointer_arg_requires_stack(
        "bpf_iter_css_task_destroy",
        0
    ));
    assert!(kfunc_pointer_arg_requires_stack("bpf_iter_dmabuf_new", 0));
    assert!(kfunc_pointer_arg_requires_stack("bpf_iter_dmabuf_next", 0));
    assert!(kfunc_pointer_arg_requires_stack(
        "bpf_iter_dmabuf_destroy",
        0
    ));
    assert!(kfunc_pointer_arg_requires_stack(
        "bpf_iter_kmem_cache_new",
        0
    ));
    assert!(kfunc_pointer_arg_requires_stack(
        "bpf_iter_kmem_cache_next",
        0
    ));
    assert!(kfunc_pointer_arg_requires_stack(
        "bpf_iter_kmem_cache_destroy",
        0
    ));
    assert!(!kfunc_pointer_arg_requires_stack("bpf_res_spin_lock", 0));
    assert!(!kfunc_pointer_arg_requires_stack("bpf_task_release", 0));
    assert!(!kfunc_pointer_arg_requires_stack(
        "bpf_iter_task_vma_new",
        1
    ));
    assert!(!kfunc_pointer_arg_requires_stack("bpf_iter_task_new", 1));
    assert!(!kfunc_pointer_arg_requires_stack("bpf_iter_scx_dsq_new", 1));
    assert!(!kfunc_pointer_arg_requires_stack("bpf_iter_num_new", 1));
    assert!(!kfunc_pointer_arg_requires_stack("bpf_iter_bits_new", 1));
    assert!(!kfunc_pointer_arg_requires_stack("bpf_iter_css_new", 1));
    assert!(!kfunc_pointer_arg_requires_stack(
        "bpf_iter_css_task_new",
        1
    ));
    assert!(!kfunc_pointer_arg_requires_stack("scx_bpf_dsq_move", 1));
    assert!(!kfunc_pointer_arg_requires_stack(
        "scx_bpf_dsq_move_set_slice",
        1
    ));
    assert!(!kfunc_pointer_arg_requires_stack(
        "scx_bpf_dsq_move_set_vtime",
        1
    ));
    assert!(!kfunc_pointer_arg_requires_stack(
        "scx_bpf_dsq_move_vtime",
        1
    ));
    assert!(!kfunc_pointer_arg_requires_stack(
        "bpf_copy_from_user_dynptr",
        3
    ));
    assert!(!kfunc_pointer_arg_requires_stack(
        "bpf_copy_from_user_task_dynptr",
        4
    ));
    assert!(!kfunc_pointer_arg_requires_stack("bpf_dynptr_adjust", 1));
    assert!(!kfunc_pointer_arg_requires_stack("bpf_dynptr_clone", 2));
    assert!(!kfunc_pointer_arg_requires_stack("bpf_dynptr_copy", 4));
    assert!(!kfunc_pointer_arg_requires_stack("bpf_dynptr_memset", 3));
    assert!(!kfunc_pointer_arg_requires_stack("bpf_dynptr_slice", 2));
    assert!(!kfunc_pointer_arg_requires_stack(
        "bpf_dynptr_slice_rdwr",
        2
    ));
    assert!(!kfunc_pointer_arg_requires_stack("bpf_iter_dmabuf_new", 1));
    assert!(!kfunc_pointer_arg_requires_stack(
        "bpf_iter_kmem_cache_new",
        1
    ));
}

#[test]
fn test_kfunc_pointer_arg_requires_stack_slot_base_mappings() {
    assert!(kfunc_pointer_arg_requires_stack_slot_base(
        "bpf_path_d_path",
        1
    ));
    assert!(kfunc_pointer_arg_requires_stack_slot_base(
        "scx_bpf_events",
        0
    ));
    assert!(kfunc_pointer_arg_requires_stack_slot_base(
        "bpf_copy_from_user_str",
        0
    ));
    assert!(kfunc_pointer_arg_requires_stack_slot_base(
        "bpf_copy_from_user_task_str",
        0
    ));
    assert!(kfunc_pointer_arg_requires_stack_slot_base(
        "bpf_copy_from_user_dynptr",
        0
    ));
    assert!(kfunc_pointer_arg_requires_stack_slot_base(
        "bpf_copy_from_user_task_dynptr",
        0
    ));
    assert!(kfunc_pointer_arg_requires_stack_slot_base(
        "bpf_copy_from_user_task_str_dynptr",
        0
    ));
    assert!(kfunc_pointer_arg_requires_stack_slot_base(
        "bpf_dynptr_adjust",
        0
    ));
    assert!(kfunc_pointer_arg_requires_stack_slot_base(
        "bpf_dynptr_clone",
        0
    ));
    assert!(kfunc_pointer_arg_requires_stack_slot_base(
        "bpf_dynptr_clone",
        1
    ));
    assert!(kfunc_pointer_arg_requires_stack_slot_base(
        "bpf_dynptr_copy",
        0
    ));
    assert!(kfunc_pointer_arg_requires_stack_slot_base(
        "bpf_dynptr_copy",
        2
    ));
    assert!(kfunc_pointer_arg_requires_stack_slot_base(
        "bpf_dynptr_size",
        0
    ));
    assert!(kfunc_pointer_arg_requires_stack_slot_base(
        "bpf_dynptr_is_null",
        0
    ));
    assert!(kfunc_pointer_arg_requires_stack_slot_base(
        "bpf_dynptr_is_rdonly",
        0
    ));
    assert!(kfunc_pointer_arg_requires_stack_slot_base(
        "bpf_dynptr_memset",
        0
    ));
    assert!(kfunc_pointer_arg_requires_stack_slot_base(
        "bpf_dynptr_slice",
        0
    ));
    assert!(kfunc_pointer_arg_requires_stack_slot_base(
        "bpf_dynptr_slice",
        2
    ));
    assert!(kfunc_pointer_arg_requires_stack_slot_base(
        "bpf_dynptr_slice_rdwr",
        0
    ));
    assert!(kfunc_pointer_arg_requires_stack_slot_base(
        "bpf_dynptr_slice_rdwr",
        2
    ));
    assert!(kfunc_pointer_arg_requires_stack_slot_base(
        "bpf_crypto_ctx_create",
        0
    ));
    assert!(kfunc_pointer_arg_requires_stack_slot_base(
        "bpf_crypto_ctx_create",
        2
    ));
    assert!(kfunc_pointer_arg_requires_stack_slot_base(
        "bpf_crypto_encrypt",
        1
    ));
    assert!(kfunc_pointer_arg_requires_stack_slot_base(
        "bpf_crypto_encrypt",
        2
    ));
    assert!(kfunc_pointer_arg_requires_stack_slot_base(
        "bpf_crypto_encrypt",
        3
    ));
    assert!(kfunc_pointer_arg_requires_stack_slot_base(
        "bpf_crypto_decrypt",
        1
    ));
    assert!(kfunc_pointer_arg_requires_stack_slot_base(
        "bpf_crypto_decrypt",
        2
    ));
    assert!(kfunc_pointer_arg_requires_stack_slot_base(
        "bpf_crypto_decrypt",
        3
    ));
    assert!(kfunc_pointer_arg_requires_stack_slot_base(
        "scx_bpf_dump_bstr",
        0
    ));
    assert!(kfunc_pointer_arg_requires_stack_slot_base(
        "scx_bpf_dump_bstr",
        1
    ));
    assert!(kfunc_pointer_arg_requires_stack_slot_base(
        "scx_bpf_error_bstr",
        0
    ));
    assert!(kfunc_pointer_arg_requires_stack_slot_base(
        "scx_bpf_error_bstr",
        1
    ));
    assert!(kfunc_pointer_arg_requires_stack_slot_base(
        "scx_bpf_exit_bstr",
        1
    ));
    assert!(kfunc_pointer_arg_requires_stack_slot_base(
        "scx_bpf_exit_bstr",
        2
    ));
    assert!(!kfunc_pointer_arg_requires_stack_slot_base(
        "bpf_path_d_path",
        0
    ));
    assert!(!kfunc_pointer_arg_requires_stack_slot_base(
        "bpf_copy_from_user_str",
        2
    ));
    assert!(!kfunc_pointer_arg_requires_stack_slot_base(
        "bpf_copy_from_user_dynptr",
        3
    ));
    assert!(!kfunc_pointer_arg_requires_stack_slot_base(
        "bpf_dynptr_clone",
        2
    ));
    assert!(!kfunc_pointer_arg_requires_stack_slot_base(
        "bpf_dynptr_slice",
        1
    ));
    assert!(!kfunc_pointer_arg_requires_stack_slot_base(
        "bpf_crypto_ctx_create",
        1
    ));
    assert!(!kfunc_pointer_arg_requires_stack_slot_base(
        "bpf_crypto_encrypt",
        0
    ));
    assert!(!kfunc_pointer_arg_requires_stack_slot_base(
        "scx_bpf_exit_bstr",
        0
    ));
}

#[test]
fn test_kfunc_pointer_arg_allows_const_zero_mappings() {
    assert!(kfunc_pointer_arg_allows_const_zero("bpf_crypto_encrypt", 3));
    assert!(kfunc_pointer_arg_allows_const_zero("bpf_crypto_decrypt", 3));
    assert!(kfunc_pointer_arg_allows_const_zero("bpf_iter_task_new", 1));
    assert!(kfunc_pointer_arg_allows_const_zero("bpf_dynptr_slice", 2));
    assert!(kfunc_pointer_arg_allows_const_zero(
        "bpf_dynptr_slice_rdwr",
        2
    ));
    assert!(!kfunc_pointer_arg_allows_const_zero(
        "bpf_crypto_encrypt",
        2
    ));
    assert!(!kfunc_pointer_arg_allows_const_zero("bpf_iter_task_new", 0));
    assert!(!kfunc_pointer_arg_allows_const_zero(
        "bpf_crypto_decrypt",
        2
    ));
    assert!(!kfunc_pointer_arg_allows_const_zero("bpf_path_d_path", 1));
    assert!(!kfunc_pointer_arg_allows_const_zero("bpf_dynptr_slice", 0));
}

#[test]
fn test_kfunc_semantics_path_d_path_buffer_rule() {
    let semantics = kfunc_semantics("bpf_path_d_path");
    assert_eq!(semantics.positive_size_args, &[2]);
    assert_eq!(semantics.ptr_arg_rules.len(), 1);

    let rule = semantics.ptr_arg_rules[0];
    assert_eq!(rule.arg_idx, 1);
    assert_eq!(rule.op, "kfunc path_d_path buffer");
    assert!(rule.allowed.allow_stack);
    assert!(rule.allowed.allow_map);
    assert!(!rule.allowed.allow_kernel);
    assert!(!rule.allowed.allow_user);
    assert_eq!(rule.size_from_arg, Some(2));
}

#[test]
fn test_kfunc_semantics_copy_from_user_str_rules() {
    let semantics = kfunc_semantics("bpf_copy_from_user_str");
    assert_eq!(semantics.positive_size_args, &[1]);
    assert_eq!(semantics.ptr_arg_rules.len(), 2);

    let dst = semantics.ptr_arg_rules[0];
    assert_eq!(dst.arg_idx, 0);
    assert_eq!(dst.op, "kfunc bpf_copy_from_user_str dst");
    assert!(dst.allowed.allow_stack);
    assert!(dst.allowed.allow_map);
    assert!(!dst.allowed.allow_kernel);
    assert!(!dst.allowed.allow_user);
    assert_eq!(dst.size_from_arg, Some(1));

    let src = semantics.ptr_arg_rules[1];
    assert_eq!(src.arg_idx, 2);
    assert_eq!(src.op, "kfunc bpf_copy_from_user_str src");
    assert!(!src.allowed.allow_stack);
    assert!(!src.allowed.allow_map);
    assert!(!src.allowed.allow_kernel);
    assert!(src.allowed.allow_user);
    assert_eq!(src.size_from_arg, Some(1));
}

#[test]
fn test_kfunc_semantics_copy_from_user_dynptr_rules() {
    let semantics = kfunc_semantics("bpf_copy_from_user_dynptr");
    assert_eq!(semantics.positive_size_args, &[2]);
    assert_eq!(semantics.ptr_arg_rules.len(), 2);

    let dptr = semantics.ptr_arg_rules[0];
    assert_eq!(dptr.arg_idx, 0);
    assert_eq!(dptr.op, "kfunc bpf_copy_from_user_dynptr dptr");
    assert!(dptr.allowed.allow_stack);
    assert!(!dptr.allowed.allow_map);
    assert!(!dptr.allowed.allow_kernel);
    assert!(!dptr.allowed.allow_user);
    assert_eq!(dptr.fixed_size, Some(16));

    let src = semantics.ptr_arg_rules[1];
    assert_eq!(src.arg_idx, 3);
    assert_eq!(src.op, "kfunc bpf_copy_from_user_dynptr src");
    assert!(!src.allowed.allow_stack);
    assert!(!src.allowed.allow_map);
    assert!(!src.allowed.allow_kernel);
    assert!(src.allowed.allow_user);
    assert_eq!(src.size_from_arg, Some(2));
}

#[test]
fn test_kfunc_semantics_dynptr_core_rules() {
    let clone = kfunc_semantics("bpf_dynptr_clone");
    assert!(clone.positive_size_args.is_empty());
    assert_eq!(clone.ptr_arg_rules.len(), 2);
    assert_eq!(clone.ptr_arg_rules[0].arg_idx, 0);
    assert_eq!(clone.ptr_arg_rules[0].op, "kfunc bpf_dynptr_clone src");
    assert_eq!(clone.ptr_arg_rules[0].fixed_size, Some(16));
    assert!(clone.ptr_arg_rules[0].allowed.allow_stack);
    assert!(!clone.ptr_arg_rules[0].allowed.allow_map);
    assert_eq!(clone.ptr_arg_rules[1].arg_idx, 1);
    assert_eq!(clone.ptr_arg_rules[1].op, "kfunc bpf_dynptr_clone dst");
    assert_eq!(clone.ptr_arg_rules[1].fixed_size, Some(16));

    let copy = kfunc_semantics("bpf_dynptr_copy");
    assert!(copy.positive_size_args.is_empty());
    assert_eq!(copy.ptr_arg_rules.len(), 2);
    assert_eq!(copy.ptr_arg_rules[0].arg_idx, 0);
    assert_eq!(copy.ptr_arg_rules[0].op, "kfunc bpf_dynptr_copy dst");
    assert_eq!(copy.ptr_arg_rules[0].fixed_size, Some(16));
    assert_eq!(copy.ptr_arg_rules[1].arg_idx, 2);
    assert_eq!(copy.ptr_arg_rules[1].op, "kfunc bpf_dynptr_copy src");
    assert_eq!(copy.ptr_arg_rules[1].fixed_size, Some(16));

    let size = kfunc_semantics("bpf_dynptr_size");
    assert_eq!(size.ptr_arg_rules.len(), 1);
    assert_eq!(size.ptr_arg_rules[0].arg_idx, 0);
    assert_eq!(size.ptr_arg_rules[0].fixed_size, Some(16));

    let slice = kfunc_semantics("bpf_dynptr_slice");
    assert!(slice.positive_size_args.is_empty());
    assert_eq!(slice.ptr_arg_rules.len(), 2);
    assert_eq!(slice.ptr_arg_rules[0].arg_idx, 0);
    assert_eq!(slice.ptr_arg_rules[0].fixed_size, Some(16));
    assert_eq!(slice.ptr_arg_rules[1].arg_idx, 2);
    assert_eq!(slice.ptr_arg_rules[1].op, "kfunc bpf_dynptr_slice buffer");
    assert!(slice.ptr_arg_rules[1].allowed.allow_stack);
    assert!(slice.ptr_arg_rules[1].allowed.allow_map);
    assert_eq!(slice.ptr_arg_rules[1].size_from_arg, Some(3));
}

#[test]
fn test_kfunc_semantics_copy_from_user_task_str_rules() {
    let semantics = kfunc_semantics("bpf_copy_from_user_task_str");
    assert_eq!(semantics.positive_size_args, &[1]);
    assert_eq!(semantics.ptr_arg_rules.len(), 2);

    let dst = semantics.ptr_arg_rules[0];
    assert_eq!(dst.arg_idx, 0);
    assert_eq!(dst.op, "kfunc bpf_copy_from_user_task_str dst");
    assert!(dst.allowed.allow_stack);
    assert!(dst.allowed.allow_map);
    assert!(!dst.allowed.allow_kernel);
    assert!(!dst.allowed.allow_user);
    assert_eq!(dst.size_from_arg, Some(1));

    let src = semantics.ptr_arg_rules[1];
    assert_eq!(src.arg_idx, 2);
    assert_eq!(src.op, "kfunc bpf_copy_from_user_task_str src");
    assert!(!src.allowed.allow_stack);
    assert!(!src.allowed.allow_map);
    assert!(!src.allowed.allow_kernel);
    assert!(src.allowed.allow_user);
    assert_eq!(src.size_from_arg, Some(1));
}

#[test]
fn test_kfunc_semantics_crypto_ctx_create_rules() {
    let semantics = kfunc_semantics("bpf_crypto_ctx_create");
    assert_eq!(semantics.positive_size_args, &[1]);
    assert_eq!(semantics.ptr_arg_rules.len(), 2);

    let params = semantics.ptr_arg_rules[0];
    assert_eq!(params.arg_idx, 0);
    assert_eq!(params.op, "kfunc bpf_crypto_ctx_create params");
    assert!(params.allowed.allow_stack);
    assert!(params.allowed.allow_map);
    assert!(!params.allowed.allow_kernel);
    assert!(!params.allowed.allow_user);
    assert_eq!(params.size_from_arg, Some(1));

    let err = semantics.ptr_arg_rules[1];
    assert_eq!(err.arg_idx, 2);
    assert_eq!(err.op, "kfunc bpf_crypto_ctx_create err");
    assert!(err.allowed.allow_stack);
    assert!(err.allowed.allow_map);
    assert!(!err.allowed.allow_kernel);
    assert!(!err.allowed.allow_user);
    assert_eq!(err.fixed_size, Some(4));
    assert_eq!(err.size_from_arg, None);
}

#[test]
fn test_kfunc_semantics_crypto_encrypt_rules() {
    let semantics = kfunc_semantics("bpf_crypto_encrypt");
    assert!(semantics.positive_size_args.is_empty());
    assert_eq!(semantics.ptr_arg_rules.len(), 3);

    let src = semantics.ptr_arg_rules[0];
    assert_eq!(src.arg_idx, 1);
    assert_eq!(src.op, "kfunc bpf_crypto_encrypt src");
    assert!(src.allowed.allow_stack);
    assert!(src.allowed.allow_map);
    assert!(!src.allowed.allow_kernel);
    assert!(!src.allowed.allow_user);
    assert_eq!(src.fixed_size, Some(16));

    let dst = semantics.ptr_arg_rules[1];
    assert_eq!(dst.arg_idx, 2);
    assert_eq!(dst.op, "kfunc bpf_crypto_encrypt dst");
    assert_eq!(dst.fixed_size, Some(16));

    let siv = semantics.ptr_arg_rules[2];
    assert_eq!(siv.arg_idx, 3);
    assert_eq!(siv.op, "kfunc bpf_crypto_encrypt siv");
    assert_eq!(siv.fixed_size, Some(16));
}

#[test]
fn test_kfunc_semantics_crypto_decrypt_rules() {
    let semantics = kfunc_semantics("bpf_crypto_decrypt");
    assert!(semantics.positive_size_args.is_empty());
    assert_eq!(semantics.ptr_arg_rules.len(), 3);

    let src = semantics.ptr_arg_rules[0];
    assert_eq!(src.arg_idx, 1);
    assert_eq!(src.op, "kfunc bpf_crypto_decrypt src");
    assert_eq!(src.fixed_size, Some(16));

    let dst = semantics.ptr_arg_rules[1];
    assert_eq!(dst.arg_idx, 2);
    assert_eq!(dst.op, "kfunc bpf_crypto_decrypt dst");
    assert_eq!(dst.fixed_size, Some(16));

    let siv = semantics.ptr_arg_rules[2];
    assert_eq!(siv.arg_idx, 3);
    assert_eq!(siv.op, "kfunc bpf_crypto_decrypt siv");
    assert_eq!(siv.fixed_size, Some(16));
}

#[test]
fn test_kfunc_semantics_scx_events_buffer_rule() {
    let semantics = kfunc_semantics("scx_bpf_events");
    assert_eq!(semantics.positive_size_args, &[1]);
    assert_eq!(semantics.ptr_arg_rules.len(), 1);

    let rule = semantics.ptr_arg_rules[0];
    assert_eq!(rule.arg_idx, 0);
    assert_eq!(rule.op, "kfunc scx_bpf_events events");
    assert!(rule.allowed.allow_stack);
    assert!(rule.allowed.allow_map);
    assert!(!rule.allowed.allow_kernel);
    assert!(!rule.allowed.allow_user);
    assert_eq!(rule.size_from_arg, Some(1));
}

#[test]
fn test_kfunc_semantics_scx_dump_bstr_rules() {
    let semantics = kfunc_semantics("scx_bpf_dump_bstr");
    assert_eq!(semantics.positive_size_args, &[2]);
    assert_eq!(semantics.ptr_arg_rules.len(), 2);

    let fmt = semantics.ptr_arg_rules[0];
    assert_eq!(fmt.arg_idx, 0);
    assert_eq!(fmt.op, "kfunc scx_bpf_dump_bstr fmt");
    assert!(fmt.allowed.allow_stack);
    assert!(fmt.allowed.allow_map);
    assert!(!fmt.allowed.allow_kernel);
    assert!(!fmt.allowed.allow_user);
    assert_eq!(fmt.fixed_size, Some(1));
    assert_eq!(fmt.size_from_arg, None);

    let data = semantics.ptr_arg_rules[1];
    assert_eq!(data.arg_idx, 1);
    assert_eq!(data.op, "kfunc scx_bpf_dump_bstr data");
    assert!(data.allowed.allow_stack);
    assert!(data.allowed.allow_map);
    assert!(!data.allowed.allow_kernel);
    assert!(!data.allowed.allow_user);
    assert_eq!(data.fixed_size, None);
    assert_eq!(data.size_from_arg, Some(2));
}

#[test]
fn test_kfunc_semantics_scx_error_bstr_rules() {
    let semantics = kfunc_semantics("scx_bpf_error_bstr");
    assert_eq!(semantics.positive_size_args, &[2]);
    assert_eq!(semantics.ptr_arg_rules.len(), 2);

    let fmt = semantics.ptr_arg_rules[0];
    assert_eq!(fmt.arg_idx, 0);
    assert_eq!(fmt.op, "kfunc scx_bpf_error_bstr fmt");
    assert!(fmt.allowed.allow_stack);
    assert!(fmt.allowed.allow_map);
    assert!(!fmt.allowed.allow_kernel);
    assert!(!fmt.allowed.allow_user);
    assert_eq!(fmt.fixed_size, Some(1));
    assert_eq!(fmt.size_from_arg, None);

    let data = semantics.ptr_arg_rules[1];
    assert_eq!(data.arg_idx, 1);
    assert_eq!(data.op, "kfunc scx_bpf_error_bstr data");
    assert!(data.allowed.allow_stack);
    assert!(data.allowed.allow_map);
    assert!(!data.allowed.allow_kernel);
    assert!(!data.allowed.allow_user);
    assert_eq!(data.fixed_size, None);
    assert_eq!(data.size_from_arg, Some(2));
}

#[test]
fn test_kfunc_semantics_scx_exit_bstr_rules() {
    let semantics = kfunc_semantics("scx_bpf_exit_bstr");
    assert_eq!(semantics.positive_size_args, &[3]);
    assert_eq!(semantics.ptr_arg_rules.len(), 2);

    let fmt = semantics.ptr_arg_rules[0];
    assert_eq!(fmt.arg_idx, 1);
    assert_eq!(fmt.op, "kfunc scx_bpf_exit_bstr fmt");
    assert!(fmt.allowed.allow_stack);
    assert!(fmt.allowed.allow_map);
    assert!(!fmt.allowed.allow_kernel);
    assert!(!fmt.allowed.allow_user);
    assert_eq!(fmt.fixed_size, Some(1));
    assert_eq!(fmt.size_from_arg, None);

    let data = semantics.ptr_arg_rules[1];
    assert_eq!(data.arg_idx, 2);
    assert_eq!(data.op, "kfunc scx_bpf_exit_bstr data");
    assert!(data.allowed.allow_stack);
    assert!(data.allowed.allow_map);
    assert!(!data.allowed.allow_kernel);
    assert!(!data.allowed.allow_user);
    assert_eq!(data.fixed_size, None);
    assert_eq!(data.size_from_arg, Some(3));
}

#[test]
fn test_kfunc_semantics_default_empty() {
    let semantics = kfunc_semantics("bpf_task_release");
    assert!(semantics.ptr_arg_rules.is_empty());
    assert!(semantics.positive_size_args.is_empty());
}

#[test]
fn test_builder() {
    let mut builder = EbpfBuilder::new();
    builder
        .push(EbpfInsn::mov64_imm(EbpfReg::R0, 0))
        .push(EbpfInsn::exit());

    let bytecode = builder.build();
    assert_eq!(bytecode.len(), 16); // 2 instructions * 8 bytes
}
