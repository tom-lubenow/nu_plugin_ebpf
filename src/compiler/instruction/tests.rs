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
fn test_bpf_helper_name_roundtrip() {
    assert_eq!(
        BpfHelper::GetCurrentPidTgid.name(),
        "bpf_get_current_pid_tgid"
    );
    assert!(matches!(
        BpfHelper::from_name("bpf_get_current_pid_tgid"),
        Some(BpfHelper::GetCurrentPidTgid)
    ));
    assert!(matches!(
        BpfHelper::from_name("get_current_pid_tgid"),
        Some(BpfHelper::GetCurrentPidTgid)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_get_prandom_u32"),
        Some(BpfHelper::GetPrandomU32)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_get_numa_node_id"),
        Some(BpfHelper::GetNumaNodeId)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_redirect"),
        Some(BpfHelper::Redirect)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_redirect_map"),
        Some(BpfHelper::RedirectMap)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_map_lookup_percpu_elem"),
        Some(BpfHelper::MapLookupPercpuElem)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_redirect_neigh"),
        Some(BpfHelper::RedirectNeigh)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_redirect_peer"),
        Some(BpfHelper::RedirectPeer)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_get_socket_uid"),
        Some(BpfHelper::GetSocketUid)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_setsockopt"),
        Some(BpfHelper::SetSockOpt)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_sk_redirect_map"),
        Some(BpfHelper::SkRedirectMap)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_sock_map_update"),
        Some(BpfHelper::SockMapUpdate)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_getsockopt"),
        Some(BpfHelper::GetSockOpt)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_sock_ops_cb_flags_set"),
        Some(BpfHelper::SockOpsCbFlagsSet)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_msg_redirect_map"),
        Some(BpfHelper::MsgRedirectMap)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_sock_hash_update"),
        Some(BpfHelper::SockHashUpdate)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_msg_redirect_hash"),
        Some(BpfHelper::MsgRedirectHash)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_sk_redirect_hash"),
        Some(BpfHelper::SkRedirectHash)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_sk_select_reuseport"),
        Some(BpfHelper::SkSelectReuseport)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_load_hdr_opt"),
        Some(BpfHelper::LoadHdrOpt)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_store_hdr_opt"),
        Some(BpfHelper::StoreHdrOpt)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_reserve_hdr_opt"),
        Some(BpfHelper::ReserveHdrOpt)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_bind"),
        Some(BpfHelper::Bind)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_msg_apply_bytes"),
        Some(BpfHelper::MsgApplyBytes)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_msg_cork_bytes"),
        Some(BpfHelper::MsgCorkBytes)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_msg_pull_data"),
        Some(BpfHelper::MsgPullData)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_skb_change_tail"),
        Some(BpfHelper::SkbChangeTail)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_skb_load_bytes"),
        Some(BpfHelper::SkbLoadBytes)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_skb_load_bytes_relative"),
        Some(BpfHelper::SkbLoadBytesRelative)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_skb_pull_data"),
        Some(BpfHelper::SkbPullData)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_clone_redirect"),
        Some(BpfHelper::CloneRedirect)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_skb_vlan_push"),
        Some(BpfHelper::SkbVlanPush)
    ));
    assert!(matches!(
        BpfHelper::from_name("skb_vlan_pop"),
        Some(BpfHelper::SkbVlanPop)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_skb_get_tunnel_key"),
        Some(BpfHelper::SkbGetTunnelKey)
    ));
    assert!(matches!(
        BpfHelper::from_name("skb_set_tunnel_key"),
        Some(BpfHelper::SkbSetTunnelKey)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_skb_change_head"),
        Some(BpfHelper::SkbChangeHead)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_set_hash"),
        Some(BpfHelper::SetHash)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_csum_level"),
        Some(BpfHelper::CsumLevel)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_skb_change_proto"),
        Some(BpfHelper::SkbChangeProto)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_skb_change_type"),
        Some(BpfHelper::SkbChangeType)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_csum_diff"),
        Some(BpfHelper::CsumDiff)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_skb_get_tunnel_opt"),
        Some(BpfHelper::SkbGetTunnelOpt)
    ));
    assert!(matches!(
        BpfHelper::from_name("skb_set_tunnel_opt"),
        Some(BpfHelper::SkbSetTunnelOpt)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_fib_lookup"),
        Some(BpfHelper::FibLookup)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_lwt_push_encap"),
        Some(BpfHelper::LwtPushEncap)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_lwt_seg6_store_bytes"),
        Some(BpfHelper::LwtSeg6StoreBytes)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_lwt_seg6_adjust_srh"),
        Some(BpfHelper::LwtSeg6AdjustSrh)
    ));
    assert!(matches!(
        BpfHelper::from_name("lwt_seg6_action"),
        Some(BpfHelper::LwtSeg6Action)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_skb_output"),
        Some(BpfHelper::SkbOutput)
    ));
    assert!(matches!(
        BpfHelper::from_name("xdp_output"),
        Some(BpfHelper::XdpOutput)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_perf_event_read"),
        Some(BpfHelper::PerfEventRead)
    ));
    assert!(matches!(
        BpfHelper::from_name("perf_event_read_value"),
        Some(BpfHelper::PerfEventReadValue)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_get_ns_current_pid_tgid"),
        Some(BpfHelper::GetNsCurrentPidTgid)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_strtol"),
        Some(BpfHelper::Strtol)
    ));
    assert!(matches!(
        BpfHelper::from_name("strtoul"),
        Some(BpfHelper::Strtoul)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_send_signal"),
        Some(BpfHelper::SendSignal)
    ));
    assert!(matches!(
        BpfHelper::from_name("send_signal_thread"),
        Some(BpfHelper::SendSignalThread)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_copy_from_user"),
        Some(BpfHelper::CopyFromUser)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_probe_write_user"),
        Some(BpfHelper::ProbeWriteUser)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_tcp_send_ack"),
        Some(BpfHelper::TcpSendAck)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_snprintf"),
        Some(BpfHelper::Snprintf)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_snprintf_btf"),
        Some(BpfHelper::SnprintfBtf)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_sys_bpf"),
        Some(BpfHelper::SysBpf)
    ));
    assert!(matches!(
        BpfHelper::from_name("btf_find_by_name_kind"),
        Some(BpfHelper::BtfFindByNameKind)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_sys_close"),
        Some(BpfHelper::SysClose)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_kallsyms_lookup_name"),
        Some(BpfHelper::KallsymsLookupName)
    ));
    assert!(matches!(
        BpfHelper::from_name("copy_from_user_task"),
        Some(BpfHelper::CopyFromUserTask)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_get_stack"),
        Some(BpfHelper::GetStack)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_skb_adjust_room"),
        Some(BpfHelper::SkbAdjustRoom)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_skb_set_tstamp"),
        Some(BpfHelper::SkbSetTstamp)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_skb_ecn_set_ce"),
        Some(BpfHelper::SkbEcnSetCe)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_check_mtu"),
        Some(BpfHelper::CheckMtu)
    ));
    assert!(matches!(
        BpfHelper::from_name("check_mtu"),
        Some(BpfHelper::CheckMtu)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_msg_push_data"),
        Some(BpfHelper::MsgPushData)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_msg_pop_data"),
        Some(BpfHelper::MsgPopData)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_skb_get_xfrm_state"),
        Some(BpfHelper::SkbGetXfrmState)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_xdp_get_buff_len"),
        Some(BpfHelper::XdpGetBuffLen)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_xdp_load_bytes"),
        Some(BpfHelper::XdpLoadBytes)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_xdp_store_bytes"),
        Some(BpfHelper::XdpStoreBytes)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_sysctl_get_name"),
        Some(BpfHelper::SysctlGetName)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_sysctl_get_current_value"),
        Some(BpfHelper::SysctlGetCurrentValue)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_sysctl_get_new_value"),
        Some(BpfHelper::SysctlGetNewValue)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_sysctl_set_new_value"),
        Some(BpfHelper::SysctlSetNewValue)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_sk_cgroup_id"),
        Some(BpfHelper::SkCgroupId)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_sk_ancestor_cgroup_id"),
        Some(BpfHelper::SkAncestorCgroupId)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_skb_cgroup_id"),
        Some(BpfHelper::SkbCgroupId)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_skb_cgroup_classid"),
        Some(BpfHelper::SkbCgroupClassid)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_skb_ancestor_cgroup_id"),
        Some(BpfHelper::SkbAncestorCgroupId)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_get_current_ancestor_cgroup_id"),
        Some(BpfHelper::GetCurrentAncestorCgroupId)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_get_retval"),
        Some(BpfHelper::GetRetval)
    ));
    assert!(matches!(
        BpfHelper::from_name("set_retval"),
        Some(BpfHelper::SetRetval)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_get_cgroup_classid"),
        Some(BpfHelper::GetCgroupClassid)
    ));
    assert!(matches!(
        BpfHelper::from_name("get_route_realm"),
        Some(BpfHelper::GetRouteRealm)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_get_current_task_btf"),
        Some(BpfHelper::GetCurrentTaskBtf)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_cgrp_storage_get"),
        Some(BpfHelper::CgrpStorageGet)
    ));
    assert!(matches!(
        BpfHelper::from_name("cgroup_storage_delete"),
        Some(BpfHelper::CgrpStorageDelete)
    ));
    assert!(matches!(
        BpfHelper::from_name("get_current_task_btf"),
        Some(BpfHelper::GetCurrentTaskBtf)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_get_current_task"),
        Some(BpfHelper::GetCurrentTask)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_override_return"),
        Some(BpfHelper::OverrideReturn)
    ));
    assert!(matches!(
        BpfHelper::from_name("ktime_get_boot_ns"),
        Some(BpfHelper::KtimeGetBootNs)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_ktime_get_coarse_ns"),
        Some(BpfHelper::KtimeGetCoarseNs)
    ));
    assert!(matches!(
        BpfHelper::from_name("ktime_get_tai_ns"),
        Some(BpfHelper::KtimeGetTaiNs)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_jiffies64"),
        Some(BpfHelper::Jiffies64)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_get_func_ip"),
        Some(BpfHelper::GetFuncIp)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_get_attach_cookie"),
        Some(BpfHelper::GetAttachCookie)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_get_func_arg"),
        Some(BpfHelper::GetFuncArg)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_get_func_ret"),
        Some(BpfHelper::GetFuncRet)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_get_func_arg_cnt"),
        Some(BpfHelper::GetFuncArgCnt)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_perf_prog_read_value"),
        Some(BpfHelper::PerfProgReadValue)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_read_branch_records"),
        Some(BpfHelper::ReadBranchRecords)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_get_branch_snapshot"),
        Some(BpfHelper::GetBranchSnapshot)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_get_task_stack"),
        Some(BpfHelper::GetTaskStack)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_d_path"),
        Some(BpfHelper::DPath)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_bprm_opts_set"),
        Some(BpfHelper::BprmOptsSet)
    ));
    assert!(matches!(
        BpfHelper::from_name("bpf_ima_inode_hash"),
        Some(BpfHelper::ImaInodeHash)
    ));
    assert!(matches!(
        BpfHelper::from_name("ima_file_hash"),
        Some(BpfHelper::ImaFileHash)
    ));
    assert!(matches!(
        BpfHelper::from_name("rc_repeat"),
        Some(BpfHelper::RcRepeat)
    ));
    assert!(BpfHelper::from_name("bpf_not_a_real_helper").is_none());
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
        (BpfHelper::ProbeReadStr, "bpf_probe_read_str"),
        (BpfHelper::ProbeReadUser, "bpf_probe_read_user"),
        (BpfHelper::ProbeReadKernel, "bpf_probe_read_kernel"),
        (BpfHelper::CopyFromUser, "bpf_copy_from_user"),
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
fn test_helper_signature_copy_from_user_task() {
    let sig = HelperSignature::for_id(BpfHelper::CopyFromUserTask as u32)
        .expect("expected bpf_copy_from_user_task helper signature");
    assert_eq!(sig.min_args, 5);
    assert_eq!(sig.max_args, 5);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(2), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(3), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(4), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
}

#[test]
fn test_helper_signature_snprintf_btf() {
    let sig = HelperSignature::for_id(BpfHelper::SnprintfBtf as u32)
        .expect("expected bpf_snprintf_btf helper signature");
    assert_eq!(sig.min_args, 5);
    assert_eq!(sig.max_args, 5);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(2), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(3), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(4), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
}

#[test]
fn test_helper_signature_probe_write_user() {
    let sig = HelperSignature::for_id(BpfHelper::ProbeWriteUser as u32)
        .expect("expected bpf_probe_write_user helper signature");
    assert_eq!(sig.min_args, 3);
    assert_eq!(sig.max_args, 3);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
}

#[test]
fn test_helper_signatures_sysctl_helpers() {
    let get_name = HelperSignature::for_id(BpfHelper::SysctlGetName as u32)
        .expect("expected bpf_sysctl_get_name helper signature");
    assert_eq!(get_name.min_args, 4);
    assert_eq!(get_name.max_args, 4);
    assert_eq!(get_name.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(get_name.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(get_name.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(get_name.arg_kind(3), HelperArgKind::Scalar);
    assert_eq!(get_name.ret_kind, HelperRetKind::Scalar);
    assert_eq!(
        BpfHelper::SysctlGetName.scalar_arg_range_requirement(3),
        Some((
            0,
            1,
            "helper 'bpf_sysctl_get_name' requires arg3 flags to contain only BPF_F_SYSCTL_* bits (0x01)"
        ))
    );

    for helper in [
        BpfHelper::SysctlGetCurrentValue,
        BpfHelper::SysctlGetNewValue,
        BpfHelper::SysctlSetNewValue,
    ] {
        let sig = HelperSignature::for_id(helper as u32)
            .unwrap_or_else(|| panic!("expected {} helper signature", helper.name()));
        assert_eq!(sig.min_args, 3);
        assert_eq!(sig.max_args, 3);
        assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
        assert_eq!(sig.arg_kind(1), HelperArgKind::Pointer);
        assert_eq!(sig.arg_kind(2), HelperArgKind::Scalar);
        assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
    }
}

#[test]
fn test_helper_signature_strtox_helpers() {
    for helper in [BpfHelper::Strtol, BpfHelper::Strtoul] {
        let sig = HelperSignature::for_id(helper as u32)
            .unwrap_or_else(|| panic!("expected {} helper signature", helper.name()));
        assert_eq!(sig.min_args, 4);
        assert_eq!(sig.max_args, 4);
        assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
        assert_eq!(sig.arg_kind(1), HelperArgKind::Scalar);
        assert_eq!(sig.arg_kind(2), HelperArgKind::Scalar);
        assert_eq!(sig.arg_kind(3), HelperArgKind::Pointer);
        assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
    }
}

#[test]
fn test_strtox_helper_contracts() {
    for helper in [BpfHelper::Strtol, BpfHelper::Strtoul] {
        let (allowed_flags, message) = helper
            .scalar_arg_allowed_values_requirement(2)
            .expect("expected strtox flags requirement");
        assert_eq!(allowed_flags, &[0, 8, 10, 16]);
        assert!(message.contains("requires arg2 flags to be one of 0, 8, 10, or 16"));

        let semantics = helper.semantics();
        assert_eq!(semantics.positive_size_args, &[1]);
        assert_eq!(semantics.ptr_arg_rules.len(), 2);

        let buf = semantics.ptr_arg_rules[0];
        assert_eq!(buf.arg_idx, 0);
        assert_eq!(buf.op, "helper strtox buf");
        assert!(buf.allowed.allow_stack);
        assert!(buf.allowed.allow_map);
        assert!(!buf.allowed.allow_kernel);
        assert_eq!(buf.size_from_arg, Some(1));

        let res = semantics.ptr_arg_rules[1];
        assert_eq!(res.arg_idx, 3);
        assert_eq!(res.op, "helper strtox res");
        assert!(res.allowed.allow_stack);
        assert!(res.allowed.allow_map);
        assert!(!res.allowed.allow_kernel);
        assert_eq!(res.fixed_size, Some(8));
        assert_eq!(res.size_from_arg, None);
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
fn test_helper_signature_map_lookup_percpu_elem() {
    let sig = HelperSignature::for_id(BpfHelper::MapLookupPercpuElem as u32)
        .expect("expected bpf_map_lookup_percpu_elem helper signature");
    assert_eq!(sig.min_args, 3);
    assert_eq!(sig.max_args, 3);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::PointerMaybeNull);
}

#[test]
fn test_helper_signature_get_socket_cookie() {
    let sig = HelperSignature::for_id(BpfHelper::GetSocketCookie as u32)
        .expect("expected bpf_get_socket_cookie helper signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
}

#[test]
fn test_helper_signature_get_socket_uid() {
    let sig = HelperSignature::for_id(BpfHelper::GetSocketUid as u32)
        .expect("expected bpf_get_socket_uid helper signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
}

#[test]
fn test_helper_signatures_setsockopt_and_getsockopt() {
    let bind_sig = HelperSignature::for_id(BpfHelper::Bind as u32)
        .expect("expected bpf_bind helper signature");
    assert_eq!(bind_sig.min_args, 3);
    assert_eq!(bind_sig.max_args, 3);
    assert_eq!(bind_sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(bind_sig.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(bind_sig.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(bind_sig.ret_kind, HelperRetKind::Scalar);

    let set_sig = HelperSignature::for_id(BpfHelper::SetSockOpt as u32)
        .expect("expected bpf_setsockopt helper signature");
    assert_eq!(set_sig.min_args, 5);
    assert_eq!(set_sig.max_args, 5);
    assert_eq!(set_sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(set_sig.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(set_sig.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(set_sig.arg_kind(3), HelperArgKind::Pointer);
    assert_eq!(set_sig.arg_kind(4), HelperArgKind::Scalar);
    assert_eq!(set_sig.ret_kind, HelperRetKind::Scalar);

    let get_sig = HelperSignature::for_id(BpfHelper::GetSockOpt as u32)
        .expect("expected bpf_getsockopt helper signature");
    assert_eq!(get_sig.min_args, 5);
    assert_eq!(get_sig.max_args, 5);
    assert_eq!(get_sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(get_sig.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(get_sig.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(get_sig.arg_kind(3), HelperArgKind::Pointer);
    assert_eq!(get_sig.arg_kind(4), HelperArgKind::Scalar);
    assert_eq!(get_sig.ret_kind, HelperRetKind::Scalar);

    let cb_flags_sig = HelperSignature::for_id(BpfHelper::SockOpsCbFlagsSet as u32)
        .expect("expected bpf_sock_ops_cb_flags_set helper signature");
    assert_eq!(cb_flags_sig.min_args, 2);
    assert_eq!(cb_flags_sig.max_args, 2);
    assert_eq!(cb_flags_sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(cb_flags_sig.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(cb_flags_sig.ret_kind, HelperRetKind::Scalar);

    let load_hdr_sig = HelperSignature::for_id(BpfHelper::LoadHdrOpt as u32)
        .expect("expected bpf_load_hdr_opt helper signature");
    assert_eq!(load_hdr_sig.min_args, 4);
    assert_eq!(load_hdr_sig.max_args, 4);
    assert_eq!(load_hdr_sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(load_hdr_sig.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(load_hdr_sig.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(load_hdr_sig.arg_kind(3), HelperArgKind::Scalar);
    assert_eq!(load_hdr_sig.ret_kind, HelperRetKind::Scalar);

    let store_hdr_sig = HelperSignature::for_id(BpfHelper::StoreHdrOpt as u32)
        .expect("expected bpf_store_hdr_opt helper signature");
    assert_eq!(store_hdr_sig.min_args, 4);
    assert_eq!(store_hdr_sig.max_args, 4);
    assert_eq!(store_hdr_sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(store_hdr_sig.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(store_hdr_sig.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(store_hdr_sig.arg_kind(3), HelperArgKind::Scalar);
    assert_eq!(store_hdr_sig.ret_kind, HelperRetKind::Scalar);

    let reserve_hdr_sig = HelperSignature::for_id(BpfHelper::ReserveHdrOpt as u32)
        .expect("expected bpf_reserve_hdr_opt helper signature");
    assert_eq!(reserve_hdr_sig.min_args, 3);
    assert_eq!(reserve_hdr_sig.max_args, 3);
    assert_eq!(reserve_hdr_sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(reserve_hdr_sig.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(reserve_hdr_sig.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(reserve_hdr_sig.ret_kind, HelperRetKind::Scalar);
}

#[test]
fn test_helper_signatures_socket_map_helpers() {
    let redirect_map_sig = HelperSignature::for_id(BpfHelper::RedirectMap as u32)
        .expect("expected bpf_redirect_map helper signature");
    assert_eq!(redirect_map_sig.min_args, 3);
    assert_eq!(redirect_map_sig.max_args, 3);
    assert_eq!(redirect_map_sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(redirect_map_sig.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(redirect_map_sig.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(redirect_map_sig.ret_kind, HelperRetKind::Scalar);

    let sk_redirect_map_sig = HelperSignature::for_id(BpfHelper::SkRedirectMap as u32)
        .expect("expected bpf_sk_redirect_map helper signature");
    assert_eq!(sk_redirect_map_sig.min_args, 4);
    assert_eq!(sk_redirect_map_sig.max_args, 4);
    assert_eq!(sk_redirect_map_sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sk_redirect_map_sig.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(sk_redirect_map_sig.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(sk_redirect_map_sig.arg_kind(3), HelperArgKind::Scalar);
    assert_eq!(sk_redirect_map_sig.ret_kind, HelperRetKind::Scalar);

    let sock_map_update_sig = HelperSignature::for_id(BpfHelper::SockMapUpdate as u32)
        .expect("expected bpf_sock_map_update helper signature");
    assert_eq!(sock_map_update_sig.min_args, 4);
    assert_eq!(sock_map_update_sig.max_args, 4);
    assert_eq!(sock_map_update_sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sock_map_update_sig.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(sock_map_update_sig.arg_kind(2), HelperArgKind::Pointer);
    assert_eq!(sock_map_update_sig.arg_kind(3), HelperArgKind::Scalar);
    assert_eq!(sock_map_update_sig.ret_kind, HelperRetKind::Scalar);

    let msg_redirect_map_sig = HelperSignature::for_id(BpfHelper::MsgRedirectMap as u32)
        .expect("expected bpf_msg_redirect_map helper signature");
    assert_eq!(msg_redirect_map_sig.min_args, 4);
    assert_eq!(msg_redirect_map_sig.max_args, 4);
    assert_eq!(msg_redirect_map_sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(msg_redirect_map_sig.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(msg_redirect_map_sig.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(msg_redirect_map_sig.arg_kind(3), HelperArgKind::Scalar);
    assert_eq!(msg_redirect_map_sig.ret_kind, HelperRetKind::Scalar);

    let sock_hash_update_sig = HelperSignature::for_id(BpfHelper::SockHashUpdate as u32)
        .expect("expected bpf_sock_hash_update helper signature");
    assert_eq!(sock_hash_update_sig.min_args, 4);
    assert_eq!(sock_hash_update_sig.max_args, 4);
    assert_eq!(sock_hash_update_sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sock_hash_update_sig.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(sock_hash_update_sig.arg_kind(2), HelperArgKind::Pointer);
    assert_eq!(sock_hash_update_sig.arg_kind(3), HelperArgKind::Scalar);
    assert_eq!(sock_hash_update_sig.ret_kind, HelperRetKind::Scalar);

    let msg_redirect_hash_sig = HelperSignature::for_id(BpfHelper::MsgRedirectHash as u32)
        .expect("expected bpf_msg_redirect_hash helper signature");
    assert_eq!(msg_redirect_hash_sig.min_args, 4);
    assert_eq!(msg_redirect_hash_sig.max_args, 4);
    assert_eq!(msg_redirect_hash_sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(msg_redirect_hash_sig.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(msg_redirect_hash_sig.arg_kind(2), HelperArgKind::Pointer);
    assert_eq!(msg_redirect_hash_sig.arg_kind(3), HelperArgKind::Scalar);
    assert_eq!(msg_redirect_hash_sig.ret_kind, HelperRetKind::Scalar);

    let sk_redirect_hash_sig = HelperSignature::for_id(BpfHelper::SkRedirectHash as u32)
        .expect("expected bpf_sk_redirect_hash helper signature");
    assert_eq!(sk_redirect_hash_sig.min_args, 4);
    assert_eq!(sk_redirect_hash_sig.max_args, 4);
    assert_eq!(sk_redirect_hash_sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sk_redirect_hash_sig.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(sk_redirect_hash_sig.arg_kind(2), HelperArgKind::Pointer);
    assert_eq!(sk_redirect_hash_sig.arg_kind(3), HelperArgKind::Scalar);
    assert_eq!(sk_redirect_hash_sig.ret_kind, HelperRetKind::Scalar);

    let sk_select_reuseport_sig = HelperSignature::for_id(BpfHelper::SkSelectReuseport as u32)
        .expect("expected bpf_sk_select_reuseport helper signature");
    assert_eq!(sk_select_reuseport_sig.min_args, 4);
    assert_eq!(sk_select_reuseport_sig.max_args, 4);
    assert_eq!(sk_select_reuseport_sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sk_select_reuseport_sig.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(sk_select_reuseport_sig.arg_kind(2), HelperArgKind::Pointer);
    assert_eq!(sk_select_reuseport_sig.arg_kind(3), HelperArgKind::Scalar);
    assert_eq!(sk_select_reuseport_sig.ret_kind, HelperRetKind::Scalar);
}

#[test]
fn test_reuseport_helper_uses_fixed_map_kind() {
    assert_eq!(
        BpfHelper::SkSelectReuseport.local_helper_map_arg_index(),
        Some(1)
    );
    assert_eq!(
        BpfHelper::SkSelectReuseport.helper_map_arg_kind(1),
        Some(MapKind::ReuseportSockArray)
    );
    assert!(BpfHelper::SkSelectReuseport.supports_local_helper_map_fd(1));
    assert!(!BpfHelper::SkSelectReuseport.helper_requires_explicit_map_kind(1));
}

#[test]
fn test_redirect_map_helper_uses_explicit_redirect_map_kind_family() {
    assert_eq!(BpfHelper::RedirectMap.local_helper_map_arg_index(), Some(0));
    assert_eq!(
        BpfHelper::RedirectMap.helper_explicit_map_kind_family(0),
        Some(HelperExplicitMapKindFamily::RedirectMap)
    );
    assert!(BpfHelper::RedirectMap.helper_requires_explicit_map_kind(0));
    assert!(BpfHelper::RedirectMap.supports_local_helper_map_fd(0));
    assert_eq!(BpfHelper::RedirectMap.helper_map_arg_kind(0), None);
}

#[test]
fn test_map_lookup_percpu_helper_uses_explicit_per_cpu_map_kind_family() {
    assert_eq!(
        BpfHelper::MapLookupPercpuElem.local_helper_map_arg_index(),
        Some(0)
    );
    assert_eq!(
        BpfHelper::MapLookupPercpuElem.helper_explicit_map_kind_family(0),
        Some(HelperExplicitMapKindFamily::PerCpuLookupMap)
    );
    assert!(BpfHelper::MapLookupPercpuElem.helper_requires_explicit_map_kind(0));
    assert!(BpfHelper::MapLookupPercpuElem.supports_local_helper_map_fd(0));
    assert_eq!(BpfHelper::MapLookupPercpuElem.helper_map_arg_kind(0), None);
}

#[test]
fn test_queue_stack_helpers_use_expected_explicit_map_kind_families() {
    assert_eq!(
        BpfHelper::MapPushElem.helper_explicit_map_kind_family(0),
        Some(HelperExplicitMapKindFamily::QueueStackBloom)
    );
    assert_eq!(
        BpfHelper::MapPeekElem.helper_explicit_map_kind_family(0),
        Some(HelperExplicitMapKindFamily::QueueStackBloom)
    );
    assert_eq!(
        BpfHelper::MapPopElem.helper_explicit_map_kind_family(0),
        Some(HelperExplicitMapKindFamily::QueueStack)
    );
}

#[test]
fn test_cgroup_array_helpers_use_fixed_map_kind() {
    for (helper, arg_idx) in [
        (BpfHelper::SkbUnderCgroup, 1),
        (BpfHelper::CurrentTaskUnderCgroup, 0),
    ] {
        assert_eq!(helper.local_helper_map_arg_index(), Some(arg_idx));
        assert_eq!(
            helper.helper_map_arg_kind(arg_idx),
            Some(MapKind::CgroupArray)
        );
        assert!(helper.supports_local_helper_map_fd(arg_idx));
        assert!(!helper.helper_requires_explicit_map_kind(arg_idx));
    }
}

#[test]
fn test_packet_output_helpers_use_perf_event_array_map_arg() {
    for helper in [BpfHelper::SkbOutput, BpfHelper::XdpOutput] {
        assert_eq!(helper.local_helper_map_arg_index(), Some(1));
        assert_eq!(helper.helper_map_arg_kind(1), Some(MapKind::PerfEventArray));
        assert!(helper.supports_local_helper_map_fd(1));
        assert!(!helper.helper_requires_explicit_map_kind(1));
    }
}

#[test]
fn test_perf_event_read_helpers_use_perf_event_array_map_arg() {
    for helper in [BpfHelper::PerfEventRead, BpfHelper::PerfEventReadValue] {
        assert_eq!(helper.local_helper_map_arg_index(), Some(0));
        assert_eq!(helper.helper_map_arg_kind(0), Some(MapKind::PerfEventArray));
        assert!(helper.supports_local_helper_map_fd(0));
        assert!(!helper.helper_requires_explicit_map_kind(0));
    }
}

#[test]
fn test_cgroup_membership_helper_signatures() {
    let skb_sig = HelperSignature::for_id(BpfHelper::SkbUnderCgroup as u32)
        .expect("expected bpf_skb_under_cgroup helper signature");
    assert_eq!(skb_sig.min_args, 3);
    assert_eq!(skb_sig.max_args, 3);
    assert_eq!(skb_sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(skb_sig.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(skb_sig.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(skb_sig.ret_kind, HelperRetKind::Scalar);

    let task_sig = HelperSignature::for_id(BpfHelper::CurrentTaskUnderCgroup as u32)
        .expect("expected bpf_current_task_under_cgroup helper signature");
    assert_eq!(task_sig.min_args, 2);
    assert_eq!(task_sig.max_args, 2);
    assert_eq!(task_sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(task_sig.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(task_sig.ret_kind, HelperRetKind::Scalar);
}

#[test]
fn test_storage_helpers_use_fixed_local_storage_map_kinds() {
    for (helper, kind) in [
        (BpfHelper::SkStorageGet, MapKind::SkStorage),
        (BpfHelper::SkStorageDelete, MapKind::SkStorage),
        (BpfHelper::TaskStorageGet, MapKind::TaskStorage),
        (BpfHelper::TaskStorageDelete, MapKind::TaskStorage),
        (BpfHelper::InodeStorageGet, MapKind::InodeStorage),
        (BpfHelper::InodeStorageDelete, MapKind::InodeStorage),
        (BpfHelper::CgrpStorageGet, MapKind::CgrpStorage),
        (BpfHelper::CgrpStorageDelete, MapKind::CgrpStorage),
    ] {
        assert_eq!(helper.local_helper_map_arg_index(), Some(0));
        assert_eq!(helper.helper_map_arg_kind(0), Some(kind));
        assert!(helper.supports_local_helper_map_fd(0));
        assert!(!helper.helper_requires_explicit_map_kind(0));
    }
}

#[test]
fn test_helper_signature_get_netns_cookie() {
    let sig = HelperSignature::for_id(BpfHelper::GetNetnsCookie as u32)
        .expect("expected bpf_get_netns_cookie helper signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
}

#[test]
fn test_helper_signature_get_current_cgroup_id() {
    let sig = HelperSignature::for_id(BpfHelper::GetCurrentCgroupId as u32)
        .expect("expected bpf_get_current_cgroup_id helper signature");
    assert_eq!(sig.min_args, 0);
    assert_eq!(sig.max_args, 0);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);

    let sig = HelperSignature::for_id(BpfHelper::GetCurrentAncestorCgroupId as u32)
        .expect("expected bpf_get_current_ancestor_cgroup_id helper signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);

    let sig = HelperSignature::for_id(BpfHelper::GetNsCurrentPidTgid as u32)
        .expect("expected bpf_get_ns_current_pid_tgid helper signature");
    assert_eq!(sig.min_args, 4);
    assert_eq!(sig.max_args, 4);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(2), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(3), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
}

#[test]
fn test_helper_signature_get_current_task_btf() {
    for helper in [BpfHelper::GetCurrentTask, BpfHelper::GetCurrentTaskBtf] {
        let sig =
            HelperSignature::for_id(helper as u32).expect("expected current task helper signature");
        assert_eq!(sig.min_args, 0);
        assert_eq!(sig.max_args, 0);
        assert_eq!(sig.ret_kind, HelperRetKind::PointerNonNull);
    }
}

#[test]
fn test_helper_signature_override_return() {
    let sig = HelperSignature::for_id(BpfHelper::OverrideReturn as u32)
        .expect("expected bpf_override_return helper signature");
    assert_eq!(sig.min_args, 2);
    assert_eq!(sig.max_args, 2);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
}

#[test]
fn test_helper_signatures_tracing_context_helpers() {
    for (helper, name) in [
        (BpfHelper::GetFuncIp, "bpf_get_func_ip"),
        (BpfHelper::GetAttachCookie, "bpf_get_attach_cookie"),
    ] {
        let sig = HelperSignature::for_id(helper as u32)
            .unwrap_or_else(|| panic!("expected {name} helper signature"));
        assert_eq!(sig.min_args, 1);
        assert_eq!(sig.max_args, 1);
        assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
        assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
    }
}

#[test]
fn test_helper_signatures_packet_output_helpers() {
    for helper in [BpfHelper::SkbOutput, BpfHelper::XdpOutput] {
        let sig = HelperSignature::for_id(helper as u32).expect("expected packet output signature");
        assert_eq!(sig.min_args, 5);
        assert_eq!(sig.max_args, 5);
        assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
        assert_eq!(sig.arg_kind(1), HelperArgKind::Pointer);
        assert_eq!(sig.arg_kind(2), HelperArgKind::Scalar);
        assert_eq!(sig.arg_kind(3), HelperArgKind::Pointer);
        assert_eq!(sig.arg_kind(4), HelperArgKind::Scalar);
        assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
    }
}

#[test]
fn test_helper_signature_perf_prog_read_value() {
    let sig = HelperSignature::for_id(BpfHelper::PerfProgReadValue as u32)
        .expect("expected bpf_perf_prog_read_value helper signature");
    assert_eq!(sig.min_args, 3);
    assert_eq!(sig.max_args, 3);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
}

#[test]
fn test_helper_signature_perf_event_read_helpers() {
    let read = HelperSignature::for_id(BpfHelper::PerfEventRead as u32)
        .expect("expected bpf_perf_event_read helper signature");
    assert_eq!(read.min_args, 2);
    assert_eq!(read.max_args, 2);
    assert_eq!(read.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(read.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(read.ret_kind, HelperRetKind::Scalar);

    let read_value = HelperSignature::for_id(BpfHelper::PerfEventReadValue as u32)
        .expect("expected bpf_perf_event_read_value helper signature");
    assert_eq!(read_value.min_args, 4);
    assert_eq!(read_value.max_args, 4);
    assert_eq!(read_value.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(read_value.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(read_value.arg_kind(2), HelperArgKind::Pointer);
    assert_eq!(read_value.arg_kind(3), HelperArgKind::Scalar);
    assert_eq!(read_value.ret_kind, HelperRetKind::Scalar);
}

#[test]
fn test_helper_signature_read_branch_records() {
    let sig = HelperSignature::for_id(BpfHelper::ReadBranchRecords as u32)
        .expect("expected bpf_read_branch_records helper signature");
    assert_eq!(sig.min_args, 4);
    assert_eq!(sig.max_args, 4);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(3), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
}

#[test]
fn test_helper_signature_signal_helpers() {
    for helper in [BpfHelper::SendSignal, BpfHelper::SendSignalThread] {
        let sig = HelperSignature::for_id(helper as u32).expect("expected signal helper signature");
        assert_eq!(sig.min_args, 1);
        assert_eq!(sig.max_args, 1);
        assert_eq!(sig.arg_kind(0), HelperArgKind::Scalar);
        assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
        assert_eq!(helper.semantics().ptr_arg_rules.len(), 0);
    }
}

#[test]
fn test_helper_signature_get_branch_snapshot() {
    let sig = HelperSignature::for_id(BpfHelper::GetBranchSnapshot as u32)
        .expect("expected bpf_get_branch_snapshot helper signature");
    assert_eq!(sig.min_args, 3);
    assert_eq!(sig.max_args, 3);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
}

#[test]
fn test_helper_signature_d_path() {
    let sig =
        HelperSignature::for_id(BpfHelper::DPath as u32).expect("expected bpf_d_path signature");
    assert_eq!(sig.min_args, 3);
    assert_eq!(sig.max_args, 3);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
}

#[test]
fn test_helper_signature_bprm_opts_set() {
    let sig = HelperSignature::for_id(BpfHelper::BprmOptsSet as u32)
        .expect("expected bpf_bprm_opts_set signature");
    assert_eq!(sig.min_args, 2);
    assert_eq!(sig.max_args, 2);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
}

#[test]
fn test_helper_signature_ima_hash_helpers() {
    for helper in [BpfHelper::ImaInodeHash, BpfHelper::ImaFileHash] {
        let sig = HelperSignature::for_id(helper as u32).expect("expected IMA helper signature");
        assert_eq!(sig.min_args, 3);
        assert_eq!(sig.max_args, 3);
        assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
        assert_eq!(sig.arg_kind(1), HelperArgKind::Pointer);
        assert_eq!(sig.arg_kind(2), HelperArgKind::Scalar);
        assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
    }
}

#[test]
fn test_helper_signatures_trampoline_arg_helpers() {
    let arg = HelperSignature::for_id(BpfHelper::GetFuncArg as u32)
        .expect("expected bpf_get_func_arg helper signature");
    assert_eq!(arg.min_args, 3);
    assert_eq!(arg.max_args, 3);
    assert_eq!(arg.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(arg.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(arg.arg_kind(2), HelperArgKind::Pointer);
    assert_eq!(arg.ret_kind, HelperRetKind::Scalar);

    let ret = HelperSignature::for_id(BpfHelper::GetFuncRet as u32)
        .expect("expected bpf_get_func_ret helper signature");
    assert_eq!(ret.min_args, 2);
    assert_eq!(ret.max_args, 2);
    assert_eq!(ret.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(ret.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(ret.ret_kind, HelperRetKind::Scalar);

    let count = HelperSignature::for_id(BpfHelper::GetFuncArgCnt as u32)
        .expect("expected bpf_get_func_arg_cnt helper signature");
    assert_eq!(count.min_args, 1);
    assert_eq!(count.max_args, 1);
    assert_eq!(count.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(count.ret_kind, HelperRetKind::Scalar);
}

#[test]
fn test_helper_signatures_prandom_boot_and_lirc_helpers() {
    for (helper, name) in [
        (BpfHelper::GetPrandomU32, "bpf_get_prandom_u32"),
        (BpfHelper::GetNumaNodeId, "bpf_get_numa_node_id"),
        (BpfHelper::KtimeGetBootNs, "bpf_ktime_get_boot_ns"),
        (BpfHelper::KtimeGetCoarseNs, "bpf_ktime_get_coarse_ns"),
        (BpfHelper::KtimeGetTaiNs, "bpf_ktime_get_tai_ns"),
        (BpfHelper::Jiffies64, "bpf_jiffies64"),
    ] {
        let sig = HelperSignature::for_id(helper as u32)
            .unwrap_or_else(|| panic!("expected {name} helper signature"));
        assert_eq!(sig.min_args, 0);
        assert_eq!(sig.max_args, 0);
        assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
    }

    let sig = HelperSignature::for_id(BpfHelper::RcRepeat as u32)
        .expect("expected bpf_rc_repeat helper signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);

    let sig = HelperSignature::for_id(BpfHelper::RcKeydown as u32)
        .expect("expected bpf_rc_keydown helper signature");
    assert_eq!(sig.min_args, 4);
    assert_eq!(sig.max_args, 4);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(3), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);

    let sig = HelperSignature::for_id(BpfHelper::RcPointerRel as u32)
        .expect("expected bpf_rc_pointer_rel helper signature");
    assert_eq!(sig.min_args, 3);
    assert_eq!(sig.max_args, 3);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
}

#[test]
fn test_helper_signatures_msg_apply_and_cork_bytes() {
    let sig = HelperSignature::for_id(BpfHelper::MsgApplyBytes as u32)
        .expect("expected bpf_msg_apply_bytes helper signature");
    assert_eq!(sig.min_args, 2);
    assert_eq!(sig.max_args, 2);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);

    let sig = HelperSignature::for_id(BpfHelper::MsgCorkBytes as u32)
        .expect("expected bpf_msg_cork_bytes helper signature");
    assert_eq!(sig.min_args, 2);
    assert_eq!(sig.max_args, 2);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
}

#[test]
fn test_helper_signatures_msg_pull_and_push_data() {
    let sig = HelperSignature::for_id(BpfHelper::MsgPullData as u32)
        .expect("expected bpf_msg_pull_data helper signature");
    assert_eq!(sig.min_args, 4);
    assert_eq!(sig.max_args, 4);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(3), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);

    let sig = HelperSignature::for_id(BpfHelper::MsgPushData as u32)
        .expect("expected bpf_msg_push_data helper signature");
    assert_eq!(sig.min_args, 4);
    assert_eq!(sig.max_args, 4);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(3), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);

    let sig = HelperSignature::for_id(BpfHelper::MsgPopData as u32)
        .expect("expected bpf_msg_pop_data helper signature");
    assert_eq!(sig.min_args, 4);
    assert_eq!(sig.max_args, 4);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(3), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
}

#[test]
fn test_helper_signatures_sk_cgroup_helpers() {
    let sig = HelperSignature::for_id(BpfHelper::SkCgroupId as u32)
        .expect("expected bpf_sk_cgroup_id helper signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);

    let sig = HelperSignature::for_id(BpfHelper::SkAncestorCgroupId as u32)
        .expect("expected bpf_sk_ancestor_cgroup_id helper signature");
    assert_eq!(sig.min_args, 2);
    assert_eq!(sig.max_args, 2);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);

    let sig = HelperSignature::for_id(BpfHelper::SkbCgroupId as u32)
        .expect("expected bpf_skb_cgroup_id helper signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);

    let sig = HelperSignature::for_id(BpfHelper::SkbAncestorCgroupId as u32)
        .expect("expected bpf_skb_ancestor_cgroup_id helper signature");
    assert_eq!(sig.min_args, 2);
    assert_eq!(sig.max_args, 2);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
}

#[test]
fn test_helper_signatures_cgroup_retval_helpers() {
    let get = HelperSignature::for_id(BpfHelper::GetRetval as u32)
        .expect("expected bpf_get_retval helper signature");
    assert_eq!(get.min_args, 0);
    assert_eq!(get.max_args, 0);
    assert_eq!(get.ret_kind, HelperRetKind::Scalar);

    let set = HelperSignature::for_id(BpfHelper::SetRetval as u32)
        .expect("expected bpf_set_retval helper signature");
    assert_eq!(set.min_args, 1);
    assert_eq!(set.max_args, 1);
    assert_eq!(set.arg_kind(0), HelperArgKind::Scalar);
    assert_eq!(set.ret_kind, HelperRetKind::Scalar);
}

#[test]
fn test_helper_signatures_tc_egress_skb_metadata_helpers() {
    for helper in [
        BpfHelper::GetCgroupClassid,
        BpfHelper::GetRouteRealm,
        BpfHelper::SkbEcnSetCe,
        BpfHelper::SkbCgroupClassid,
    ] {
        let sig =
            HelperSignature::for_id(helper as u32).expect("expected skb metadata helper signature");
        assert_eq!(sig.min_args, 1);
        assert_eq!(sig.max_args, 1);
        assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
        assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
    }
}

#[test]
fn test_helper_signatures_skb_packet_mutation_helpers() {
    for helper in [
        BpfHelper::SkbChangeTail,
        BpfHelper::SkbChangeHead,
        BpfHelper::SkbChangeProto,
        BpfHelper::CloneRedirect,
        BpfHelper::SkbVlanPush,
    ] {
        let sig =
            HelperSignature::for_id(helper as u32).expect("expected skb mutation helper signature");
        assert_eq!(sig.min_args, 3);
        assert_eq!(sig.max_args, 3);
        assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
        assert_eq!(sig.arg_kind(1), HelperArgKind::Scalar);
        assert_eq!(sig.arg_kind(2), HelperArgKind::Scalar);
        assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
    }

    let sig = HelperSignature::for_id(BpfHelper::SkbPullData as u32)
        .expect("expected bpf_skb_pull_data helper signature");
    assert_eq!(sig.min_args, 2);
    assert_eq!(sig.max_args, 2);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);

    let sig = HelperSignature::for_id(BpfHelper::SkbVlanPop as u32)
        .expect("expected bpf_skb_vlan_pop helper signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);

    for helper in [
        BpfHelper::SetHash,
        BpfHelper::CsumUpdate,
        BpfHelper::CsumLevel,
        BpfHelper::SkbChangeType,
    ] {
        let sig =
            HelperSignature::for_id(helper as u32).expect("expected two-arg skb helper signature");
        assert_eq!(sig.min_args, 2);
        assert_eq!(sig.max_args, 2);
        assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
        assert_eq!(sig.arg_kind(1), HelperArgKind::Scalar);
        assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
    }

    let sig = HelperSignature::for_id(BpfHelper::SkbAdjustRoom as u32)
        .expect("expected bpf_skb_adjust_room helper signature");
    assert_eq!(sig.min_args, 4);
    assert_eq!(sig.max_args, 4);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(3), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);

    let sig = HelperSignature::for_id(BpfHelper::SkbSetTstamp as u32)
        .expect("expected bpf_skb_set_tstamp helper signature");
    assert_eq!(sig.min_args, 3);
    assert_eq!(sig.max_args, 3);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);

    let sig = HelperSignature::for_id(BpfHelper::SkbLoadBytes as u32)
        .expect("expected bpf_skb_load_bytes helper signature");
    assert_eq!(sig.min_args, 4);
    assert_eq!(sig.max_args, 4);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(2), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(3), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);

    let sig = HelperSignature::for_id(BpfHelper::SkbLoadBytesRelative as u32)
        .expect("expected bpf_skb_load_bytes_relative helper signature");
    assert_eq!(sig.min_args, 5);
    assert_eq!(sig.max_args, 5);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(2), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(3), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(4), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);

    let sig = HelperSignature::for_id(BpfHelper::CsumDiff as u32)
        .expect("expected bpf_csum_diff helper signature");
    assert_eq!(sig.min_args, 5);
    assert_eq!(sig.max_args, 5);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(2), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(3), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(4), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);

    let sig = HelperSignature::for_id(BpfHelper::FibLookup as u32)
        .expect("expected bpf_fib_lookup helper signature");
    assert_eq!(sig.min_args, 4);
    assert_eq!(sig.max_args, 4);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(3), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);

    for helper in [
        BpfHelper::LwtPushEncap,
        BpfHelper::LwtSeg6StoreBytes,
        BpfHelper::LwtSeg6Action,
    ] {
        let sig =
            HelperSignature::for_id(helper as u32).expect("expected lwt buffer helper signature");
        assert_eq!(sig.min_args, 4);
        assert_eq!(sig.max_args, 4);
        assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
        assert_eq!(sig.arg_kind(1), HelperArgKind::Scalar);
        assert_eq!(sig.arg_kind(2), HelperArgKind::Pointer);
        assert_eq!(sig.arg_kind(3), HelperArgKind::Scalar);
        assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
    }

    let sig = HelperSignature::for_id(BpfHelper::LwtSeg6AdjustSrh as u32)
        .expect("expected bpf_lwt_seg6_adjust_srh helper signature");
    assert_eq!(sig.min_args, 3);
    assert_eq!(sig.max_args, 3);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);

    let sig = HelperSignature::for_id(BpfHelper::SkbGetXfrmState as u32)
        .expect("expected bpf_skb_get_xfrm_state helper signature");
    assert_eq!(sig.min_args, 5);
    assert_eq!(sig.max_args, 5);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(2), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(3), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(4), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);

    for helper in [BpfHelper::SkbGetTunnelKey, BpfHelper::SkbSetTunnelKey] {
        let sig =
            HelperSignature::for_id(helper as u32).expect("expected skb tunnel key signature");
        assert_eq!(sig.min_args, 4);
        assert_eq!(sig.max_args, 4);
        assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
        assert_eq!(sig.arg_kind(1), HelperArgKind::Pointer);
        assert_eq!(sig.arg_kind(2), HelperArgKind::Scalar);
        assert_eq!(sig.arg_kind(3), HelperArgKind::Scalar);
        assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
    }

    for helper in [BpfHelper::SkbGetTunnelOpt, BpfHelper::SkbSetTunnelOpt] {
        let sig =
            HelperSignature::for_id(helper as u32).expect("expected skb tunnel opt signature");
        assert_eq!(sig.min_args, 3);
        assert_eq!(sig.max_args, 3);
        assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
        assert_eq!(sig.arg_kind(1), HelperArgKind::Pointer);
        assert_eq!(sig.arg_kind(2), HelperArgKind::Scalar);
        assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
    }

    let sig = HelperSignature::for_id(BpfHelper::CheckMtu as u32)
        .expect("expected bpf_check_mtu helper signature");
    assert_eq!(sig.min_args, 5);
    assert_eq!(sig.max_args, 5);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(2), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(3), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(4), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
}

#[test]
fn test_helper_signature_get_stack() {
    let sig = HelperSignature::for_id(BpfHelper::GetStack as u32)
        .expect("expected bpf_get_stack helper signature");
    assert_eq!(sig.min_args, 4);
    assert_eq!(sig.max_args, 4);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(3), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
}

#[test]
fn test_helper_signature_redirect() {
    let sig = HelperSignature::for_id(BpfHelper::Redirect as u32)
        .expect("expected bpf_redirect helper signature");
    assert_eq!(sig.min_args, 2);
    assert_eq!(sig.max_args, 2);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
}

#[test]
fn test_helper_signature_redirect_neigh() {
    let sig = HelperSignature::for_id(BpfHelper::RedirectNeigh as u32)
        .expect("expected bpf_redirect_neigh helper signature");
    assert_eq!(sig.min_args, 4);
    assert_eq!(sig.max_args, 4);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(3), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
}

#[test]
fn test_helper_signature_redirect_peer() {
    let sig = HelperSignature::for_id(BpfHelper::RedirectPeer as u32)
        .expect("expected bpf_redirect_peer helper signature");
    assert_eq!(sig.min_args, 2);
    assert_eq!(sig.max_args, 2);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
}

#[test]
fn test_helper_signatures_xdp_adjust_helpers() {
    for helper in [
        BpfHelper::XdpAdjustHead,
        BpfHelper::XdpAdjustMeta,
        BpfHelper::XdpAdjustTail,
    ] {
        let sig =
            HelperSignature::for_id(helper as u32).expect("expected xdp adjust helper signature");
        assert_eq!(sig.min_args, 2);
        assert_eq!(sig.max_args, 2);
        assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
        assert_eq!(sig.arg_kind(1), HelperArgKind::Scalar);
        assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
    }

    let sig = HelperSignature::for_id(BpfHelper::XdpGetBuffLen as u32)
        .expect("expected bpf_xdp_get_buff_len helper signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);

    for helper in [BpfHelper::XdpLoadBytes, BpfHelper::XdpStoreBytes] {
        let sig =
            HelperSignature::for_id(helper as u32).expect("expected xdp bytes helper signature");
        assert_eq!(sig.min_args, 4);
        assert_eq!(sig.max_args, 4);
        assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
        assert_eq!(sig.arg_kind(1), HelperArgKind::Scalar);
        assert_eq!(sig.arg_kind(2), HelperArgKind::Pointer);
        assert_eq!(sig.arg_kind(3), HelperArgKind::Scalar);
        assert_eq!(sig.ret_kind, HelperRetKind::Scalar);
    }
}

#[test]
fn test_helpers_with_packet_pointer_invalidation() {
    for helper in [
        BpfHelper::SkbChangeTail,
        BpfHelper::SkbStoreBytes,
        BpfHelper::L3CsumReplace,
        BpfHelper::L4CsumReplace,
        BpfHelper::CloneRedirect,
        BpfHelper::SkbPullData,
        BpfHelper::SkbChangeHead,
        BpfHelper::SkbChangeProto,
        BpfHelper::LwtPushEncap,
        BpfHelper::LwtSeg6Action,
        BpfHelper::LwtSeg6AdjustSrh,
        BpfHelper::LwtSeg6StoreBytes,
        BpfHelper::SkbVlanPush,
        BpfHelper::SkbVlanPop,
        BpfHelper::XdpAdjustHead,
        BpfHelper::XdpAdjustMeta,
        BpfHelper::SkbAdjustRoom,
        BpfHelper::XdpAdjustTail,
        BpfHelper::MsgPullData,
    ] {
        assert!(
            helper.invalidates_packet_pointers(),
            "{} should invalidate packet pointers",
            helper.name()
        );
    }

    for helper in [
        BpfHelper::Redirect,
        BpfHelper::MsgApplyBytes,
        BpfHelper::MsgPushData,
        BpfHelper::MsgPopData,
        BpfHelper::SetHash,
        BpfHelper::CsumLevel,
        BpfHelper::SkbEcnSetCe,
        BpfHelper::SkbChangeType,
        BpfHelper::SkbGetTunnelKey,
        BpfHelper::SkbSetTunnelKey,
        BpfHelper::SkbGetTunnelOpt,
        BpfHelper::SkbSetTunnelOpt,
        BpfHelper::SkbGetXfrmState,
    ] {
        assert!(
            !helper.invalidates_packet_pointers(),
            "{} should not invalidate packet pointers",
            helper.name()
        );
    }
}

#[test]
fn test_helpers_with_reserved_zero_flags() {
    assert_eq!(
        BpfHelper::SkbChangeTail.zero_scalar_arg_requirement(),
        Some((2, "helper 'bpf_skb_change_tail' requires arg2 = 0"))
    );
    assert_eq!(
        BpfHelper::SkbChangeHead.zero_scalar_arg_requirement(),
        Some((2, "helper 'bpf_skb_change_head' requires arg2 = 0"))
    );
    assert_eq!(
        BpfHelper::SkbChangeProto.zero_scalar_arg_requirement(),
        Some((2, "helper 'bpf_skb_change_proto' requires arg2 = 0"))
    );
    assert_eq!(BpfHelper::SkbPullData.zero_scalar_arg_requirement(), None);
    assert_eq!(BpfHelper::SkbAdjustRoom.zero_scalar_arg_requirement(), None);
    assert_eq!(BpfHelper::SkbSetTstamp.zero_scalar_arg_requirement(), None);
    assert_eq!(BpfHelper::SkbChangeType.zero_scalar_arg_requirement(), None);
    assert_eq!(BpfHelper::CheckMtu.zero_scalar_arg_requirement(), None);
    assert_eq!(
        BpfHelper::SkbGetTunnelKey.zero_scalar_arg_requirement(),
        None
    );
    assert_eq!(
        BpfHelper::SkbSetTunnelKey.zero_scalar_arg_requirement(),
        None
    );
    assert_eq!(
        BpfHelper::SkbGetXfrmState.zero_scalar_arg_requirement(),
        Some((4, "helper 'bpf_skb_get_xfrm_state' requires arg4 = 0"))
    );
    assert_eq!(
        BpfHelper::SkbSetTstamp.zero_scalar_arg_requirement_when_arg_zero(),
        Some((
            1,
            2,
            "helper 'bpf_skb_set_tstamp' requires arg1 = 0 when arg2 is 0"
        ))
    );
}

#[test]
fn test_fib_lookup_helper_contract() {
    let semantics = BpfHelper::FibLookup.semantics();
    assert_eq!(semantics.positive_size_args, &[2]);
    assert_eq!(semantics.ptr_arg_rules.len(), 2);

    let ctx = semantics.ptr_arg_rules[0];
    assert_eq!(ctx.arg_idx, 0);
    assert_eq!(ctx.op, "helper fib_lookup ctx");
    assert!(ctx.allowed.allow_kernel);
    assert!(!ctx.allowed.allow_stack);
    assert!(!ctx.allowed.allow_map);
    assert!(!ctx.allowed.allow_user);
    assert_eq!(ctx.fixed_size, None);
    assert_eq!(ctx.size_from_arg, None);

    let params = semantics.ptr_arg_rules[1];
    assert_eq!(params.arg_idx, 1);
    assert_eq!(params.op, "helper fib_lookup params");
    assert!(params.allowed.allow_stack);
    assert!(params.allowed.allow_map);
    assert!(!params.allowed.allow_kernel);
    assert!(!params.allowed.allow_user);
    assert_eq!(params.fixed_size, None);
    assert_eq!(params.size_from_arg, Some(2));
}

#[test]
fn test_skb_tunnel_helpers_contract() {
    for helper in [
        BpfHelper::SkbGetTunnelKey,
        BpfHelper::SkbSetTunnelKey,
        BpfHelper::SkbGetTunnelOpt,
        BpfHelper::SkbSetTunnelOpt,
    ] {
        let semantics = helper.semantics();
        assert_eq!(semantics.positive_size_args, &[2]);
        assert_eq!(semantics.ptr_arg_rules.len(), 2);

        let skb = semantics.ptr_arg_rules[0];
        assert_eq!(skb.arg_idx, 0);
        assert_eq!(skb.op, "helper skb_tunnel skb");
        assert!(skb.allowed.allow_kernel);
        assert!(!skb.allowed.allow_stack);
        assert!(!skb.allowed.allow_map);
        assert!(!skb.allowed.allow_user);
        assert_eq!(skb.fixed_size, None);
        assert_eq!(skb.size_from_arg, None);

        let buffer = semantics.ptr_arg_rules[1];
        assert_eq!(buffer.arg_idx, 1);
        assert_eq!(buffer.op, "helper skb_tunnel buffer");
        assert!(buffer.allowed.allow_stack);
        assert!(buffer.allowed.allow_map);
        assert!(!buffer.allowed.allow_kernel);
        assert!(!buffer.allowed.allow_user);
        assert_eq!(buffer.fixed_size, None);
        assert_eq!(buffer.size_from_arg, Some(2));
    }
}

#[test]
fn test_skb_get_xfrm_state_helper_contract() {
    let semantics = BpfHelper::SkbGetXfrmState.semantics();
    assert_eq!(semantics.positive_size_args, &[3]);
    assert_eq!(semantics.ptr_arg_rules.len(), 2);

    let skb = semantics.ptr_arg_rules[0];
    assert_eq!(skb.arg_idx, 0);
    assert_eq!(skb.op, "helper skb_get_xfrm_state skb");
    assert!(skb.allowed.allow_kernel);
    assert!(!skb.allowed.allow_stack);
    assert!(!skb.allowed.allow_map);
    assert!(!skb.allowed.allow_user);
    assert_eq!(skb.fixed_size, None);
    assert_eq!(skb.size_from_arg, None);

    let xfrm_state = semantics.ptr_arg_rules[1];
    assert_eq!(xfrm_state.arg_idx, 2);
    assert_eq!(xfrm_state.op, "helper skb_get_xfrm_state xfrm_state");
    assert!(xfrm_state.allowed.allow_stack);
    assert!(xfrm_state.allowed.allow_map);
    assert!(!xfrm_state.allowed.allow_kernel);
    assert!(!xfrm_state.allowed.allow_user);
    assert_eq!(xfrm_state.fixed_size, None);
    assert_eq!(xfrm_state.size_from_arg, Some(3));
}

#[test]
fn test_lwt_helpers_contract() {
    for helper in [
        BpfHelper::LwtPushEncap,
        BpfHelper::LwtSeg6StoreBytes,
        BpfHelper::LwtSeg6Action,
    ] {
        let semantics = helper.semantics();
        assert_eq!(semantics.positive_size_args, &[3]);
        assert_eq!(semantics.ptr_arg_rules.len(), 2);

        let skb = semantics.ptr_arg_rules[0];
        assert_eq!(skb.arg_idx, 0);
        assert_eq!(skb.op, "helper lwt skb");
        assert!(skb.allowed.allow_kernel);
        assert!(!skb.allowed.allow_stack);
        assert!(!skb.allowed.allow_map);
        assert!(!skb.allowed.allow_user);
        assert_eq!(skb.fixed_size, None);
        assert_eq!(skb.size_from_arg, None);

        let buffer = semantics.ptr_arg_rules[1];
        assert_eq!(buffer.arg_idx, 2);
        assert_eq!(buffer.op, "helper lwt buffer");
        assert!(buffer.allowed.allow_stack);
        assert!(buffer.allowed.allow_map);
        assert!(!buffer.allowed.allow_kernel);
        assert!(!buffer.allowed.allow_user);
        assert_eq!(buffer.fixed_size, None);
        assert_eq!(buffer.size_from_arg, Some(3));
    }

    let semantics = BpfHelper::LwtSeg6AdjustSrh.semantics();
    assert!(semantics.positive_size_args.is_empty());
    assert_eq!(semantics.ptr_arg_rules.len(), 1);

    let skb = semantics.ptr_arg_rules[0];
    assert_eq!(skb.arg_idx, 0);
    assert_eq!(skb.op, "helper lwt skb");
    assert!(skb.allowed.allow_kernel);
    assert!(!skb.allowed.allow_stack);
    assert!(!skb.allowed.allow_map);
    assert!(!skb.allowed.allow_user);
    assert_eq!(skb.fixed_size, None);
    assert_eq!(skb.size_from_arg, None);
}

#[test]
fn test_packet_output_helpers_contract() {
    for helper in [BpfHelper::SkbOutput, BpfHelper::XdpOutput] {
        let semantics = helper.semantics();
        assert_eq!(semantics.positive_size_args, &[4]);
        assert_eq!(semantics.ptr_arg_rules.len(), 3);

        let ctx = semantics.ptr_arg_rules[0];
        assert_eq!(ctx.arg_idx, 0);
        assert_eq!(ctx.op, "helper packet_output ctx");
        assert!(ctx.allowed.allow_kernel);
        assert!(!ctx.allowed.allow_stack);
        assert!(!ctx.allowed.allow_map);
        assert!(!ctx.allowed.allow_user);
        assert_eq!(ctx.fixed_size, None);
        assert_eq!(ctx.size_from_arg, None);

        let map = semantics.ptr_arg_rules[1];
        assert_eq!(map.arg_idx, 1);
        assert_eq!(map.op, "helper packet_output map");
        assert!(map.allowed.allow_stack);
        assert!(!map.allowed.allow_map);
        assert!(!map.allowed.allow_kernel);
        assert!(!map.allowed.allow_user);
        assert_eq!(map.fixed_size, None);
        assert_eq!(map.size_from_arg, None);

        let data = semantics.ptr_arg_rules[2];
        assert_eq!(data.arg_idx, 3);
        assert_eq!(data.op, "helper packet_output data");
        assert!(data.allowed.allow_stack);
        assert!(data.allowed.allow_map);
        assert!(!data.allowed.allow_kernel);
        assert!(!data.allowed.allow_user);
        assert_eq!(data.fixed_size, None);
        assert_eq!(data.size_from_arg, Some(4));
    }
}

#[test]
fn test_check_mtu_helper_contract() {
    let semantics = BpfHelper::CheckMtu.semantics();
    assert!(semantics.positive_size_args.is_empty());
    assert_eq!(semantics.ptr_arg_rules.len(), 2);

    let ctx = semantics.ptr_arg_rules[0];
    assert_eq!(ctx.arg_idx, 0);
    assert_eq!(ctx.op, "helper check_mtu ctx");
    assert!(ctx.allowed.allow_kernel);
    assert!(!ctx.allowed.allow_stack);
    assert!(!ctx.allowed.allow_map);
    assert!(!ctx.allowed.allow_user);
    assert_eq!(ctx.fixed_size, None);
    assert_eq!(ctx.size_from_arg, None);

    let mtu_len = semantics.ptr_arg_rules[1];
    assert_eq!(mtu_len.arg_idx, 2);
    assert_eq!(mtu_len.op, "helper check_mtu mtu_len");
    assert!(mtu_len.allowed.allow_stack);
    assert!(mtu_len.allowed.allow_map);
    assert!(!mtu_len.allowed.allow_kernel);
    assert!(!mtu_len.allowed.allow_user);
    assert_eq!(mtu_len.fixed_size, Some(4));
    assert_eq!(mtu_len.size_from_arg, None);
}

#[test]
fn test_helper_csum_diff_zero_size_pointer_contract() {
    assert_eq!(
        BpfHelper::CsumDiff.zero_size_pointer_arg_size_arg(0),
        Some(1)
    );
    assert_eq!(
        BpfHelper::CsumDiff.zero_size_pointer_arg_size_arg(2),
        Some(3)
    );
    assert_eq!(
        BpfHelper::CsumDiff.scalar_arg_multiple_of_requirement(1),
        Some((
            4,
            "helper 'bpf_csum_diff' requires arg1 to be a multiple of 4"
        ))
    );
    assert_eq!(
        BpfHelper::CsumDiff.scalar_arg_multiple_of_requirement(3),
        Some((
            4,
            "helper 'bpf_csum_diff' requires arg3 to be a multiple of 4"
        ))
    );
}

#[test]
fn test_snprintf_helper_contract() {
    let sig = HelperSignature::for_id(BpfHelper::Snprintf as u32)
        .expect("expected bpf_snprintf helper signature");
    assert_eq!(sig.min_args, 5);
    assert_eq!(sig.max_args, 5);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(2), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(3), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(4), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);

    assert_eq!(
        BpfHelper::Snprintf.scalar_arg_nonnegative_requirement(1),
        Some("helper 'bpf_snprintf' requires arg1 to be >= 0")
    );
    assert_eq!(
        BpfHelper::Snprintf.scalar_arg_nonnegative_requirement(4),
        Some("helper 'bpf_snprintf' requires arg4 to be >= 0")
    );
    assert_eq!(
        BpfHelper::Snprintf.scalar_arg_multiple_of_requirement(4),
        Some((
            8,
            "helper 'bpf_snprintf' requires arg4 to be a multiple of 8"
        ))
    );

    let semantics = BpfHelper::Snprintf.semantics();
    assert!(semantics.positive_size_args.is_empty());
    assert_eq!(semantics.ptr_arg_rules.len(), 3);

    let out = semantics.ptr_arg_rules[0];
    assert_eq!(out.arg_idx, 0);
    assert_eq!(out.op, "helper snprintf str");
    assert!(out.allowed.allow_stack);
    assert!(out.allowed.allow_map);
    assert_eq!(out.size_from_arg, Some(1));

    let fmt = semantics.ptr_arg_rules[1];
    assert_eq!(fmt.arg_idx, 2);
    assert_eq!(fmt.op, "helper snprintf fmt");
    assert!(!fmt.allowed.allow_stack);
    assert!(fmt.allowed.allow_map);
    assert!(!fmt.allowed.allow_kernel);
    assert!(!fmt.allowed.allow_user);
    assert_eq!(fmt.fixed_size, None);
    assert_eq!(fmt.size_from_arg, None);

    let data = semantics.ptr_arg_rules[2];
    assert_eq!(data.arg_idx, 3);
    assert_eq!(data.op, "helper snprintf data");
    assert!(data.allowed.allow_stack);
    assert!(data.allowed.allow_map);
    assert_eq!(data.size_from_arg, Some(4));
}

#[test]
fn test_snprintf_btf_helper_contract() {
    assert_eq!(
        BpfHelper::SnprintfBtf.scalar_arg_nonnegative_requirement(1),
        Some("helper 'bpf_snprintf_btf' requires arg1 to be >= 0")
    );
    assert_eq!(
        BpfHelper::SnprintfBtf.scalar_arg_const_requirement(),
        Some((3, 16, "helper 'bpf_snprintf_btf' requires arg3 = 16"))
    );
    assert_eq!(
        BpfHelper::SnprintfBtf.scalar_arg_range_requirement(4),
        Some((
            0,
            15,
            "helper 'bpf_snprintf_btf' requires arg4 to contain only BTF_F_* bits (0x0f)"
        ))
    );

    let semantics = BpfHelper::SnprintfBtf.semantics();
    assert!(semantics.positive_size_args.is_empty());
    assert_eq!(semantics.ptr_arg_rules.len(), 2);

    let out = semantics.ptr_arg_rules[0];
    assert_eq!(out.arg_idx, 0);
    assert_eq!(out.op, "helper snprintf_btf str");
    assert!(out.allowed.allow_stack);
    assert!(out.allowed.allow_map);
    assert_eq!(out.fixed_size, None);
    assert_eq!(out.size_from_arg, Some(1));

    let ptr = semantics.ptr_arg_rules[1];
    assert_eq!(ptr.arg_idx, 2);
    assert_eq!(ptr.op, "helper snprintf_btf ptr");
    assert!(ptr.allowed.allow_stack);
    assert!(ptr.allowed.allow_map);
    assert!(!ptr.allowed.allow_kernel);
    assert!(!ptr.allowed.allow_user);
    assert_eq!(ptr.fixed_size, Some(16));
    assert_eq!(ptr.size_from_arg, None);
}

#[test]
fn test_read_branch_records_zero_size_pointer_contract() {
    assert_eq!(
        BpfHelper::ReadBranchRecords.zero_size_pointer_arg_size_arg(1),
        Some(2)
    );
    assert_eq!(
        BpfHelper::ReadBranchRecords.scalar_arg_range_requirement(3),
        Some((
            0,
            1,
            "helper 'bpf_read_branch_records' requires arg3 flags to contain only BPF_F_GET_BRANCH_RECORDS_SIZE (0x01)"
        ))
    );
    assert_eq!(
        BpfHelper::ReadBranchRecords.zero_size_pointer_arg_size_arg(0),
        None
    );
}

#[test]
fn test_get_branch_snapshot_zero_size_and_flag_contract() {
    assert_eq!(
        BpfHelper::GetBranchSnapshot.zero_size_pointer_arg_size_arg(0),
        Some(1)
    );
    assert_eq!(
        BpfHelper::GetBranchSnapshot.zero_scalar_arg_requirement(),
        Some((2, "helper 'bpf_get_branch_snapshot' requires arg2 = 0"))
    );
}

#[test]
fn test_get_task_stack_buffer_contract() {
    assert_eq!(
        BpfHelper::GetTaskStack.zero_size_pointer_arg_size_arg(1),
        Some(2)
    );
    assert_eq!(
        BpfHelper::GetTaskStack.scalar_arg_nonnegative_requirement(2),
        Some("helper 'bpf_get_task_stack' requires arg2 to be >= 0")
    );
}

#[test]
fn test_copy_from_user_buffer_contracts() {
    assert_eq!(
        BpfHelper::CopyFromUser.zero_size_pointer_arg_size_arg(0),
        Some(1)
    );
    assert_eq!(
        BpfHelper::CopyFromUser.scalar_arg_nonnegative_requirement(1),
        Some("helper 'bpf_copy_from_user' requires arg1 to be >= 0")
    );
    assert_eq!(
        BpfHelper::CopyFromUserTask.zero_size_pointer_arg_size_arg(0),
        Some(1)
    );
    assert_eq!(
        BpfHelper::CopyFromUserTask.scalar_arg_nonnegative_requirement(1),
        Some("helper 'bpf_copy_from_user_task' requires arg1 to be >= 0")
    );
    assert_eq!(
        BpfHelper::CopyFromUserTask.zero_scalar_arg_requirement(),
        Some((4, "helper 'bpf_copy_from_user_task' requires arg4 = 0"))
    );
}

#[test]
fn test_d_path_buffer_contract() {
    assert_eq!(BpfHelper::DPath.zero_size_pointer_arg_size_arg(1), Some(2));
    assert_eq!(
        BpfHelper::DPath.scalar_arg_nonnegative_requirement(2),
        Some("helper 'bpf_d_path' requires arg2 to be >= 0")
    );
}

#[test]
fn test_helper_get_stack_buffer_contract() {
    assert_eq!(
        BpfHelper::GetStack.scalar_arg_nonnegative_requirement(2),
        Some("helper 'bpf_get_stack' requires arg2 to be >= 0")
    );

    let semantics = BpfHelper::GetStack.semantics();
    assert!(semantics.positive_size_args.is_empty());
    assert_eq!(semantics.ptr_arg_rules.len(), 2);

    let ctx = semantics.ptr_arg_rules[0];
    assert_eq!(ctx.arg_idx, 0);
    assert_eq!(ctx.op, "helper get_stack ctx");
    assert!(ctx.allowed.allow_kernel);
    assert!(!ctx.allowed.allow_user);
    assert_eq!(ctx.size_from_arg, None);

    let buf = semantics.ptr_arg_rules[1];
    assert_eq!(buf.arg_idx, 1);
    assert_eq!(buf.op, "helper get_stack buf");
    assert!(buf.allowed.allow_stack);
    assert!(buf.allowed.allow_map);
    assert!(!buf.allowed.allow_kernel);
    assert!(!buf.allowed.allow_user);
    assert_eq!(buf.size_from_arg, Some(2));
}

#[test]
fn test_tracing_context_helper_contracts() {
    for (helper, op) in [
        (BpfHelper::GetFuncIp, "helper get_func_ip ctx"),
        (BpfHelper::GetAttachCookie, "helper get_attach_cookie ctx"),
    ] {
        let semantics = helper.semantics();
        assert!(semantics.positive_size_args.is_empty());
        assert_eq!(semantics.ptr_arg_rules.len(), 1);

        let ctx = semantics.ptr_arg_rules[0];
        assert_eq!(ctx.arg_idx, 0);
        assert_eq!(ctx.op, op);
        assert!(ctx.allowed.allow_kernel);
        assert!(!ctx.allowed.allow_user);
        assert_eq!(ctx.fixed_size, None);
        assert_eq!(ctx.size_from_arg, None);
    }
}

#[test]
fn test_perf_prog_read_value_helper_contract() {
    let semantics = BpfHelper::PerfProgReadValue.semantics();
    assert_eq!(semantics.positive_size_args, &[2]);
    assert_eq!(semantics.ptr_arg_rules.len(), 2);

    let ctx = semantics.ptr_arg_rules[0];
    assert_eq!(ctx.arg_idx, 0);
    assert_eq!(ctx.op, "helper perf_prog_read_value ctx");
    assert!(ctx.allowed.allow_kernel);
    assert!(!ctx.allowed.allow_stack);
    assert_eq!(ctx.size_from_arg, None);

    let buf = semantics.ptr_arg_rules[1];
    assert_eq!(buf.arg_idx, 1);
    assert_eq!(buf.op, "helper perf_prog_read_value buf");
    assert!(buf.allowed.allow_stack);
    assert!(buf.allowed.allow_map);
    assert!(!buf.allowed.allow_kernel);
    assert_eq!(buf.size_from_arg, Some(2));
}

#[test]
fn test_perf_event_read_helper_contracts() {
    let read = BpfHelper::PerfEventRead.semantics();
    assert!(read.positive_size_args.is_empty());
    assert_eq!(read.ptr_arg_rules.len(), 1);
    let map = read.ptr_arg_rules[0];
    assert_eq!(map.arg_idx, 0);
    assert_eq!(map.op, "helper perf_event_read map");
    assert!(map.allowed.allow_stack);
    assert!(!map.allowed.allow_map);
    assert!(!map.allowed.allow_kernel);
    assert_eq!(map.size_from_arg, None);

    let read_value = BpfHelper::PerfEventReadValue.semantics();
    assert_eq!(read_value.positive_size_args, &[3]);
    assert_eq!(read_value.ptr_arg_rules.len(), 2);
    let map = read_value.ptr_arg_rules[0];
    assert_eq!(map.arg_idx, 0);
    assert_eq!(map.op, "helper perf_event_read_value map");
    assert!(map.allowed.allow_stack);
    assert!(!map.allowed.allow_map);
    assert!(!map.allowed.allow_kernel);
    assert_eq!(map.size_from_arg, None);
    let buf = read_value.ptr_arg_rules[1];
    assert_eq!(buf.arg_idx, 2);
    assert_eq!(buf.op, "helper perf_event_read_value buf");
    assert!(buf.allowed.allow_stack);
    assert!(buf.allowed.allow_map);
    assert!(!buf.allowed.allow_kernel);
    assert_eq!(buf.size_from_arg, Some(3));

    assert_eq!(
        BpfHelper::PerfEventReadValue.scalar_arg_const_requirement(),
        Some((
            3,
            24,
            "helper 'bpf_perf_event_read_value' requires arg3 = 24"
        ))
    );
}

#[test]
fn test_get_ns_current_pid_tgid_helper_contract() {
    let semantics = BpfHelper::GetNsCurrentPidTgid.semantics();
    assert_eq!(semantics.positive_size_args, &[3]);
    assert_eq!(semantics.ptr_arg_rules.len(), 1);
    let nsdata = semantics.ptr_arg_rules[0];
    assert_eq!(nsdata.arg_idx, 2);
    assert_eq!(nsdata.op, "helper get_ns_current_pid_tgid nsdata");
    assert!(nsdata.allowed.allow_stack);
    assert!(nsdata.allowed.allow_map);
    assert!(!nsdata.allowed.allow_kernel);
    assert_eq!(nsdata.size_from_arg, Some(3));
    assert_eq!(
        BpfHelper::GetNsCurrentPidTgid.scalar_arg_const_requirement(),
        Some((
            3,
            8,
            "helper 'bpf_get_ns_current_pid_tgid' requires arg3 = 8"
        ))
    );
}

#[test]
fn test_read_branch_records_helper_contract() {
    let semantics = BpfHelper::ReadBranchRecords.semantics();
    assert!(semantics.positive_size_args.is_empty());
    assert_eq!(semantics.ptr_arg_rules.len(), 2);

    let ctx = semantics.ptr_arg_rules[0];
    assert_eq!(ctx.arg_idx, 0);
    assert_eq!(ctx.op, "helper read_branch_records ctx");
    assert!(ctx.allowed.allow_kernel);
    assert!(!ctx.allowed.allow_stack);
    assert_eq!(ctx.size_from_arg, None);

    let buf = semantics.ptr_arg_rules[1];
    assert_eq!(buf.arg_idx, 1);
    assert_eq!(buf.op, "helper read_branch_records buf");
    assert!(buf.allowed.allow_stack);
    assert!(buf.allowed.allow_map);
    assert!(!buf.allowed.allow_kernel);
    assert_eq!(buf.size_from_arg, Some(2));
}

#[test]
fn test_get_branch_snapshot_helper_contract() {
    let semantics = BpfHelper::GetBranchSnapshot.semantics();
    assert!(semantics.positive_size_args.is_empty());
    assert_eq!(semantics.ptr_arg_rules.len(), 1);

    let entries = semantics.ptr_arg_rules[0];
    assert_eq!(entries.arg_idx, 0);
    assert_eq!(entries.op, "helper get_branch_snapshot entries");
    assert!(entries.allowed.allow_stack);
    assert!(entries.allowed.allow_map);
    assert!(!entries.allowed.allow_kernel);
    assert!(!entries.allowed.allow_user);
    assert_eq!(entries.size_from_arg, Some(1));
}

#[test]
fn test_get_task_stack_helper_contract() {
    let semantics = BpfHelper::GetTaskStack.semantics();
    assert!(semantics.positive_size_args.is_empty());
    assert_eq!(semantics.ptr_arg_rules.len(), 2);

    let task = semantics.ptr_arg_rules[0];
    assert_eq!(task.arg_idx, 0);
    assert_eq!(task.op, "helper get_task_stack task");
    assert!(task.allowed.allow_kernel);
    assert!(!task.allowed.allow_stack);
    assert_eq!(task.size_from_arg, None);

    let buf = semantics.ptr_arg_rules[1];
    assert_eq!(buf.arg_idx, 1);
    assert_eq!(buf.op, "helper get_task_stack buf");
    assert!(buf.allowed.allow_stack);
    assert!(buf.allowed.allow_map);
    assert!(!buf.allowed.allow_kernel);
    assert_eq!(buf.size_from_arg, Some(2));
}

#[test]
fn test_copy_from_user_helper_contracts() {
    let write_semantics = BpfHelper::ProbeWriteUser.semantics();
    assert_eq!(write_semantics.positive_size_args, &[2]);
    assert_eq!(write_semantics.ptr_arg_rules.len(), 2);

    let user_dst = write_semantics.ptr_arg_rules[0];
    assert_eq!(user_dst.arg_idx, 0);
    assert_eq!(user_dst.op, "helper probe_write_user dst");
    assert!(user_dst.allowed.allow_user);
    assert!(!user_dst.allowed.allow_stack);
    assert_eq!(user_dst.size_from_arg, Some(2));

    let write_src = write_semantics.ptr_arg_rules[1];
    assert_eq!(write_src.arg_idx, 1);
    assert_eq!(write_src.op, "helper probe_write_user src");
    assert!(write_src.allowed.allow_stack);
    assert!(write_src.allowed.allow_map);
    assert!(!write_src.allowed.allow_user);
    assert_eq!(write_src.size_from_arg, Some(2));

    let semantics = BpfHelper::CopyFromUser.semantics();
    assert!(semantics.positive_size_args.is_empty());
    assert_eq!(semantics.ptr_arg_rules.len(), 2);

    let dst = semantics.ptr_arg_rules[0];
    assert_eq!(dst.arg_idx, 0);
    assert_eq!(dst.op, "helper copy_from_user dst");
    assert!(dst.allowed.allow_stack);
    assert!(dst.allowed.allow_map);
    assert!(!dst.allowed.allow_user);
    assert_eq!(dst.size_from_arg, Some(1));

    let src = semantics.ptr_arg_rules[1];
    assert_eq!(src.arg_idx, 2);
    assert_eq!(src.op, "helper copy_from_user src");
    assert!(src.allowed.allow_user);
    assert!(!src.allowed.allow_stack);
    assert!(!src.allowed.allow_kernel);
    assert_eq!(src.size_from_arg, Some(1));

    let task_semantics = BpfHelper::CopyFromUserTask.semantics();
    assert!(task_semantics.positive_size_args.is_empty());
    assert_eq!(task_semantics.ptr_arg_rules.len(), 3);

    let task_src = task_semantics.ptr_arg_rules[1];
    assert_eq!(task_src.arg_idx, 2);
    assert_eq!(task_src.op, "helper copy_from_user_task src");
    assert!(task_src.allowed.allow_user);
    assert!(!task_src.allowed.allow_stack);

    let task = task_semantics.ptr_arg_rules[2];
    assert_eq!(task.arg_idx, 3);
    assert_eq!(task.op, "helper copy_from_user_task task");
    assert!(task.allowed.allow_kernel);
    assert!(!task.allowed.allow_user);
    assert_eq!(task.size_from_arg, None);
}

#[test]
fn test_d_path_helper_contract() {
    let semantics = BpfHelper::DPath.semantics();
    assert!(semantics.positive_size_args.is_empty());
    assert_eq!(semantics.ptr_arg_rules.len(), 2);

    let path = semantics.ptr_arg_rules[0];
    assert_eq!(path.arg_idx, 0);
    assert_eq!(path.op, "helper d_path path");
    assert!(path.allowed.allow_kernel);
    assert!(!path.allowed.allow_stack);
    assert_eq!(path.size_from_arg, None);

    let buf = semantics.ptr_arg_rules[1];
    assert_eq!(buf.arg_idx, 1);
    assert_eq!(buf.op, "helper d_path buf");
    assert!(buf.allowed.allow_stack);
    assert!(buf.allowed.allow_map);
    assert!(!buf.allowed.allow_kernel);
    assert_eq!(buf.size_from_arg, Some(2));
}

#[test]
fn test_bprm_opts_set_helper_contract() {
    let override_semantics = BpfHelper::OverrideReturn.semantics();
    assert!(override_semantics.positive_size_args.is_empty());
    assert_eq!(override_semantics.ptr_arg_rules.len(), 1);

    let ctx = override_semantics.ptr_arg_rules[0];
    assert_eq!(ctx.arg_idx, 0);
    assert_eq!(ctx.op, "helper override_return ctx");
    assert!(ctx.allowed.allow_kernel);
    assert!(!ctx.allowed.allow_stack);
    assert!(!ctx.allowed.allow_user);
    assert_eq!(ctx.size_from_arg, None);

    let semantics = BpfHelper::BprmOptsSet.semantics();
    assert!(semantics.positive_size_args.is_empty());
    assert_eq!(semantics.ptr_arg_rules.len(), 1);
    assert_eq!(
        BpfHelper::BprmOptsSet.scalar_arg_range_requirement(1),
        Some((
            0,
            1,
            "helper 'bpf_bprm_opts_set' requires arg1 flags to contain only BPF_F_BPRM_* bits (0x01)"
        ))
    );

    let bprm = semantics.ptr_arg_rules[0];
    assert_eq!(bprm.arg_idx, 0);
    assert_eq!(bprm.op, "helper bprm_opts_set bprm");
    assert!(bprm.allowed.allow_kernel);
    assert!(!bprm.allowed.allow_stack);
    assert!(!bprm.allowed.allow_user);
    assert_eq!(bprm.size_from_arg, None);
}

#[test]
fn test_ima_hash_helper_contracts() {
    let inode_semantics = BpfHelper::ImaInodeHash.semantics();
    assert_eq!(inode_semantics.positive_size_args, &[2]);
    assert_eq!(inode_semantics.ptr_arg_rules.len(), 2);

    let inode = inode_semantics.ptr_arg_rules[0];
    assert_eq!(inode.arg_idx, 0);
    assert_eq!(inode.op, "helper ima_inode_hash inode");
    assert!(inode.allowed.allow_kernel);
    assert!(!inode.allowed.allow_stack);

    let inode_dst = inode_semantics.ptr_arg_rules[1];
    assert_eq!(inode_dst.arg_idx, 1);
    assert_eq!(inode_dst.op, "helper ima_inode_hash dst");
    assert!(inode_dst.allowed.allow_stack);
    assert!(inode_dst.allowed.allow_map);
    assert_eq!(inode_dst.size_from_arg, Some(2));

    let file_semantics = BpfHelper::ImaFileHash.semantics();
    assert_eq!(file_semantics.positive_size_args, &[2]);
    assert_eq!(file_semantics.ptr_arg_rules.len(), 2);
    assert_eq!(
        file_semantics.ptr_arg_rules[0].op,
        "helper ima_file_hash file"
    );
    assert_eq!(
        file_semantics.ptr_arg_rules[1].op,
        "helper ima_file_hash dst"
    );
    assert_eq!(file_semantics.ptr_arg_rules[1].size_from_arg, Some(2));
}

#[test]
fn test_trampoline_arg_helper_contracts() {
    let arg = BpfHelper::GetFuncArg.semantics();
    assert_eq!(arg.ptr_arg_rules.len(), 2);
    assert_eq!(arg.ptr_arg_rules[0].op, "helper get_func_arg ctx");
    assert!(arg.ptr_arg_rules[0].allowed.allow_kernel);
    assert_eq!(arg.ptr_arg_rules[1].op, "helper get_func_arg value");
    assert!(arg.ptr_arg_rules[1].allowed.allow_stack);
    assert!(arg.ptr_arg_rules[1].allowed.allow_map);
    assert_eq!(arg.ptr_arg_rules[1].fixed_size, Some(8));

    let ret = BpfHelper::GetFuncRet.semantics();
    assert_eq!(ret.ptr_arg_rules.len(), 2);
    assert_eq!(ret.ptr_arg_rules[0].op, "helper get_func_ret ctx");
    assert!(ret.ptr_arg_rules[0].allowed.allow_kernel);
    assert_eq!(ret.ptr_arg_rules[1].op, "helper get_func_ret value");
    assert!(ret.ptr_arg_rules[1].allowed.allow_stack);
    assert!(ret.ptr_arg_rules[1].allowed.allow_map);
    assert_eq!(ret.ptr_arg_rules[1].fixed_size, Some(8));

    let count = BpfHelper::GetFuncArgCnt.semantics();
    assert_eq!(count.ptr_arg_rules.len(), 1);
    assert_eq!(count.ptr_arg_rules[0].op, "helper get_func_arg_cnt ctx");
    assert!(count.ptr_arg_rules[0].allowed.allow_kernel);
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

    let sig = HelperSignature::for_id(BpfHelper::CgrpStorageGet as u32)
        .expect("expected bpf_cgrp_storage_get helper signature");
    assert_eq!(sig.min_args, 4);
    assert_eq!(sig.max_args, 4);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(2), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(3), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::PointerMaybeNull);

    let sig = HelperSignature::for_id(BpfHelper::CgrpStorageDelete as u32)
        .expect("expected bpf_cgrp_storage_delete helper signature");
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
fn test_ringbuf_helper_flag_contracts() {
    assert_eq!(
        BpfHelper::RingbufOutput.scalar_arg_range_requirement(3),
        Some((
            0,
            3,
            "helper 'bpf_ringbuf_output' requires arg3 flags to contain only BPF_RB_* wakeup bits (0x03)"
        ))
    );
    assert_eq!(
        BpfHelper::RingbufReserve.scalar_arg_range_requirement(2),
        Some((
            0,
            0,
            "helper 'bpf_ringbuf_reserve' requires arg2 flags to be 0"
        ))
    );
    assert_eq!(
        BpfHelper::RingbufSubmit.scalar_arg_range_requirement(1),
        Some((
            0,
            3,
            "helper 'bpf_ringbuf_submit' requires arg1 flags to contain only BPF_RB_* wakeup bits (0x03)"
        ))
    );
    assert_eq!(
        BpfHelper::RingbufDiscard.scalar_arg_range_requirement(1),
        Some((
            0,
            3,
            "helper 'bpf_ringbuf_discard' requires arg1 flags to contain only BPF_RB_* wakeup bits (0x03)"
        ))
    );
    assert_eq!(
        BpfHelper::RingbufQuery.scalar_arg_range_requirement(1),
        Some((
            0,
            3,
            "helper 'bpf_ringbuf_query' requires arg1 flags to be one of BPF_RB_* query selectors (0..3)"
        ))
    );
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

    let sig = HelperSignature::for_id(BpfHelper::TcpSendAck as u32)
        .expect("expected bpf_tcp_send_ack helper signature");
    assert_eq!(sig.min_args, 2);
    assert_eq!(sig.max_args, 2);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Scalar);
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

    let sig = HelperSignature::for_id(BpfHelper::GetTaskStack as u32)
        .expect("expected bpf_get_task_stack helper signature");
    assert_eq!(sig.min_args, 4);
    assert_eq!(sig.max_args, 4);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(sig.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(sig.arg_kind(3), HelperArgKind::Scalar);
    assert_eq!(sig.ret_kind, HelperRetKind::Scalar);

    let sig = HelperSignature::for_id(BpfHelper::GetListenerSock as u32)
        .expect("expected bpf_get_listener_sock helper signature");
    assert_eq!(sig.min_args, 1);
    assert_eq!(sig.max_args, 1);
    assert_eq!(sig.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(sig.ret_kind, HelperRetKind::PointerMaybeNull);
}

#[test]
fn test_tcp_send_ack_helper_contract() {
    let semantics = BpfHelper::TcpSendAck.semantics();
    assert!(semantics.positive_size_args.is_empty());
    assert_eq!(semantics.ptr_arg_rules.len(), 1);
    let tp = semantics.ptr_arg_rules[0];
    assert_eq!(tp.arg_idx, 0);
    assert_eq!(tp.op, "helper tcp_send_ack tp");
    assert!(tp.allowed.allow_kernel);
    assert!(!tp.allowed.allow_stack);
    assert!(!tp.allowed.allow_map);
    assert!(!tp.allowed.allow_user);
}

#[test]
fn test_helper_signature_syscall_helpers() {
    let sys_bpf = HelperSignature::for_id(BpfHelper::SysBpf as u32)
        .expect("expected bpf_sys_bpf helper signature");
    assert_eq!(sys_bpf.min_args, 3);
    assert_eq!(sys_bpf.max_args, 3);
    assert_eq!(sys_bpf.arg_kind(0), HelperArgKind::Scalar);
    assert_eq!(sys_bpf.arg_kind(1), HelperArgKind::Pointer);
    assert_eq!(sys_bpf.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(sys_bpf.ret_kind, HelperRetKind::Scalar);

    let btf_find = HelperSignature::for_id(BpfHelper::BtfFindByNameKind as u32)
        .expect("expected bpf_btf_find_by_name_kind helper signature");
    assert_eq!(btf_find.min_args, 4);
    assert_eq!(btf_find.max_args, 4);
    assert_eq!(btf_find.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(btf_find.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(btf_find.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(btf_find.arg_kind(3), HelperArgKind::Scalar);
    assert_eq!(btf_find.ret_kind, HelperRetKind::Scalar);

    let sys_close = HelperSignature::for_id(BpfHelper::SysClose as u32)
        .expect("expected bpf_sys_close helper signature");
    assert_eq!(sys_close.min_args, 1);
    assert_eq!(sys_close.max_args, 1);
    assert_eq!(sys_close.arg_kind(0), HelperArgKind::Scalar);
    assert_eq!(sys_close.ret_kind, HelperRetKind::Scalar);

    let kallsyms = HelperSignature::for_id(BpfHelper::KallsymsLookupName as u32)
        .expect("expected bpf_kallsyms_lookup_name helper signature");
    assert_eq!(kallsyms.min_args, 4);
    assert_eq!(kallsyms.max_args, 4);
    assert_eq!(kallsyms.arg_kind(0), HelperArgKind::Pointer);
    assert_eq!(kallsyms.arg_kind(1), HelperArgKind::Scalar);
    assert_eq!(kallsyms.arg_kind(2), HelperArgKind::Scalar);
    assert_eq!(kallsyms.arg_kind(3), HelperArgKind::Pointer);
    assert_eq!(kallsyms.ret_kind, HelperRetKind::Scalar);
}

#[test]
fn test_syscall_helper_contracts() {
    let sys_bpf = BpfHelper::SysBpf.semantics();
    assert_eq!(sys_bpf.positive_size_args, &[2]);
    assert_eq!(sys_bpf.ptr_arg_rules.len(), 1);
    assert_eq!(sys_bpf.ptr_arg_rules[0].arg_idx, 1);
    assert_eq!(sys_bpf.ptr_arg_rules[0].op, "helper sys_bpf attr");
    assert!(sys_bpf.ptr_arg_rules[0].allowed.allow_stack);
    assert!(sys_bpf.ptr_arg_rules[0].allowed.allow_map);
    assert_eq!(sys_bpf.ptr_arg_rules[0].size_from_arg, Some(2));

    let btf_find = BpfHelper::BtfFindByNameKind.semantics();
    assert_eq!(btf_find.positive_size_args, &[1]);
    assert_eq!(btf_find.ptr_arg_rules.len(), 1);
    assert_eq!(
        btf_find.ptr_arg_rules[0].op,
        "helper btf_find_by_name_kind name"
    );
    assert_eq!(btf_find.ptr_arg_rules[0].size_from_arg, Some(1));
    assert_eq!(
        BpfHelper::BtfFindByNameKind.zero_scalar_arg_requirement(),
        Some((3, "helper 'bpf_btf_find_by_name_kind' requires arg3 = 0"))
    );

    let kallsyms = BpfHelper::KallsymsLookupName.semantics();
    assert_eq!(kallsyms.positive_size_args, &[1]);
    assert_eq!(kallsyms.ptr_arg_rules.len(), 2);
    assert_eq!(
        kallsyms.ptr_arg_rules[0].op,
        "helper kallsyms_lookup_name name"
    );
    assert_eq!(kallsyms.ptr_arg_rules[0].size_from_arg, Some(1));
    assert_eq!(
        kallsyms.ptr_arg_rules[1].op,
        "helper kallsyms_lookup_name res"
    );
    assert_eq!(kallsyms.ptr_arg_rules[1].fixed_size, Some(8));
    assert_eq!(
        BpfHelper::KallsymsLookupName.zero_scalar_arg_requirement(),
        Some((2, "helper 'bpf_kallsyms_lookup_name' requires arg2 = 0"))
    );
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
        helper_pointer_arg_ref_kind(BpfHelper::TcpSendAck, 0),
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
        helper_pointer_arg_ref_kind(BpfHelper::CgrpStorageGet, 1),
        Some(KfuncRefKind::Cgroup)
    );
    assert_eq!(
        helper_pointer_arg_ref_kind(BpfHelper::CgrpStorageDelete, 1),
        Some(KfuncRefKind::Cgroup)
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
        helper_pointer_arg_ref_kind(BpfHelper::ImaFileHash, 0),
        Some(KfuncRefKind::File)
    );
    assert_eq!(
        helper_pointer_arg_ref_kind(BpfHelper::ImaInodeHash, 0),
        Some(KfuncRefKind::Inode)
    );
    assert_eq!(
        helper_pointer_arg_ref_kind(BpfHelper::TaskPtRegs, 0),
        Some(KfuncRefKind::Task)
    );
    assert_eq!(
        helper_pointer_arg_ref_kind(BpfHelper::GetTaskStack, 0),
        Some(KfuncRefKind::Task)
    );
    assert_eq!(
        helper_pointer_arg_ref_kind(BpfHelper::CopyFromUserTask, 3),
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
fn test_kfunc_signature_sock_addr_set_sun_path() {
    let sig = KfuncSignature::for_name("bpf_sock_addr_set_sun_path")
        .expect("expected bpf_sock_addr_set_sun_path kfunc signature");
    assert_eq!(sig.min_args, 3);
    assert_eq!(sig.max_args, 3);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(2), KfuncArgKind::Scalar);
    assert_eq!(sig.ret_kind, KfuncRetKind::Scalar);
}

#[test]
fn test_kfunc_signature_sock_ops_enable_tx_tstamp() {
    let sig = KfuncSignature::for_name("bpf_sock_ops_enable_tx_tstamp")
        .expect("expected bpf_sock_ops_enable_tx_tstamp kfunc signature");
    assert_eq!(sig.min_args, 2);
    assert_eq!(sig.max_args, 2);
    assert_eq!(sig.arg_kind(0), KfuncArgKind::Pointer);
    assert_eq!(sig.arg_kind(1), KfuncArgKind::Scalar);
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
    assert_eq!(
        kfunc_acquire_ref_kind("__nu_plugin_ebpf_missing_kfunc__"),
        None
    );
    assert_eq!(
        kfunc_release_ref_kind("__nu_plugin_ebpf_missing_kfunc__"),
        None
    );
    assert_eq!(kfunc_release_ref_arg_index("bpf_task_release"), Some(0));
    assert_eq!(kfunc_release_ref_arg_index("bpf_obj_drop_impl"), Some(0));
    assert_eq!(
        kfunc_release_ref_arg_index("bpf_list_push_front_impl"),
        Some(1)
    );
    assert_eq!(kfunc_release_ref_arg_index("bpf_rbtree_add_impl"), Some(1));
    assert_eq!(
        kfunc_release_ref_arg_index("__nu_plugin_ebpf_missing_kfunc__"),
        None
    );
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
        None
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
    assert_eq!(
        kfunc_pointer_arg_ref_kind("__nu_plugin_ebpf_missing_kfunc__", 0),
        None
    );
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
        "bpf_sock_ops_enable_tx_tstamp",
        0
    ));
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
    assert!(!kfunc_pointer_arg_requires_kernel(
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
    assert!(!kfunc_pointer_arg_requires_kernel(
        "__nu_plugin_ebpf_missing_kfunc__",
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
        "scx_bpf_select_cpu_dfl",
        3
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
    assert!(!kfunc_pointer_arg_requires_stack(
        "__nu_plugin_ebpf_missing_kfunc__",
        0
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
    assert!(kfunc_pointer_arg_requires_stack_slot_base(
        "scx_bpf_select_cpu_dfl",
        3
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
    assert!(!kfunc_pointer_arg_requires_stack_slot_base(
        "__nu_plugin_ebpf_missing_kfunc__",
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
fn test_kfunc_semantics_sock_addr_set_sun_path_rules() {
    let semantics = kfunc_semantics("bpf_sock_addr_set_sun_path");
    assert_eq!(semantics.positive_size_args, &[2]);
    assert_eq!(semantics.ptr_arg_rules.len(), 1);

    let rule = semantics.ptr_arg_rules[0];
    assert_eq!(rule.arg_idx, 1);
    assert_eq!(rule.op, "kfunc bpf_sock_addr_set_sun_path path");
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
    assert_eq!(slice.positive_size_args, &[3]);
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
fn test_kfunc_semantics_scx_select_cpu_dfl_is_idle_rule() {
    let semantics = kfunc_semantics("scx_bpf_select_cpu_dfl");
    assert_eq!(semantics.positive_size_args, &[] as &[usize]);
    assert_eq!(semantics.ptr_arg_rules.len(), 1);

    let rule = semantics.ptr_arg_rules[0];
    assert_eq!(rule.arg_idx, 3);
    assert_eq!(rule.op, "kfunc scx_bpf_select_cpu_dfl is_idle");
    assert!(rule.allowed.allow_stack);
    assert!(!rule.allowed.allow_map);
    assert!(!rule.allowed.allow_kernel);
    assert!(!rule.allowed.allow_user);
    assert_eq!(rule.fixed_size, Some(1));
    assert_eq!(rule.size_from_arg, None);
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
