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
fn test_unknown_kfunc_signature_message_for_missing_symbol() {
    let msg = unknown_kfunc_signature_message("__nu_plugin_ebpf_missing_kfunc_for_test__");
    assert!(msg.contains("unknown kfunc '__nu_plugin_ebpf_missing_kfunc_for_test__'"));
    assert!(msg.contains("typed signature required"));
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
        kfunc_pointer_arg_ref_kind("bpf_task_under_cgroup", 1),
        Some(KfuncRefKind::Cgroup)
    );
    assert_eq!(
        kfunc_pointer_arg_ref_kind("bpf_put_file", 0),
        Some(KfuncRefKind::File)
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
        kfunc_pointer_arg_ref_kind("scx_bpf_pick_idle_cpu", 0),
        Some(KfuncRefKind::Cpumask)
    );
    assert_eq!(
        kfunc_pointer_arg_ref_kind("scx_bpf_select_cpu_and", 3),
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
    assert!(!kfunc_pointer_arg_requires_kernel(
        "bpf_iter_task_vma_new",
        0
    ));
    assert!(!kfunc_pointer_arg_requires_kernel(
        "bpf_list_push_front_impl",
        2
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
    assert!(!kfunc_pointer_arg_requires_stack("bpf_res_spin_lock", 0));
    assert!(!kfunc_pointer_arg_requires_stack("bpf_task_release", 0));
    assert!(!kfunc_pointer_arg_requires_stack(
        "bpf_iter_task_vma_new",
        1
    ));
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
