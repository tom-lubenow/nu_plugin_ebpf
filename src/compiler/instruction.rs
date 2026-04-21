//! eBPF instruction encoding
//!
//! eBPF instructions are 64-bit fixed-length, encoded as:
//! ```text
//! opcode:8 src_reg:4 dst_reg:4 offset:16 imm:32
//! ```
//!
//! Some instructions (like 64-bit immediate loads) use two 64-bit slots.

use crate::compiler::mir::MapKind;

/// eBPF register identifiers (r0-r10)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EbpfReg {
    /// Return value from functions, exit value for eBPF program
    R0 = 0,
    /// First argument to BPF helpers, also context pointer
    R1 = 1,
    /// Second argument to BPF helpers
    R2 = 2,
    /// Third argument to BPF helpers
    R3 = 3,
    /// Fourth argument to BPF helpers
    R4 = 4,
    /// Fifth argument to BPF helpers
    R5 = 5,
    /// Callee-saved register
    R6 = 6,
    /// Callee-saved register
    R7 = 7,
    /// Callee-saved register
    R8 = 8,
    /// Callee-saved register
    R9 = 9,
    /// Frame pointer (read-only)
    R10 = 10,
}

impl EbpfReg {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// BPF helper function numbers
///
/// These are the kernel helper functions that eBPF programs can call.
/// See: https://man7.org/linux/man-pages/man7/bpf-helpers.7.html
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum BpfHelper {
    /// void *bpf_map_lookup_elem(map, key)
    MapLookupElem = 1,
    /// int bpf_map_update_elem(map, key, value, flags)
    MapUpdateElem = 2,
    /// int bpf_map_delete_elem(map, key)
    MapDeleteElem = 3,
    /// int bpf_probe_read(dst, size, src)
    ProbeRead = 4,
    /// long bpf_probe_read_user(dst, size, unsafe_ptr)
    ProbeReadUser = 112,
    /// long bpf_probe_read_kernel(dst, size, unsafe_ptr)
    ProbeReadKernel = 113,
    /// u64 bpf_ktime_get_ns(void)
    KtimeGetNs = 5,
    /// int bpf_trace_printk(fmt, fmt_size, ...)
    TracePrintk = 6,
    /// u32 bpf_get_prandom_u32(void)
    GetPrandomU32 = 7,
    /// u32 bpf_get_smp_processor_id(void)
    GetSmpProcessorId = 8,
    /// long bpf_skb_store_bytes(skb, offset, from, len, flags)
    SkbStoreBytes = 9,
    /// long bpf_l3_csum_replace(skb, offset, from, to, size)
    L3CsumReplace = 10,
    /// long bpf_l4_csum_replace(skb, offset, from, to, flags)
    L4CsumReplace = 11,
    /// long bpf_skb_under_cgroup(skb, cgroup_array_map, index)
    SkbUnderCgroup = 33,
    /// long bpf_skb_change_tail(skb, len, flags)
    SkbChangeTail = 38,
    /// long bpf_current_task_under_cgroup(cgroup_array_map, index)
    CurrentTaskUnderCgroup = 37,
    /// long bpf_skb_pull_data(skb, len)
    SkbPullData = 39,
    /// u32 bpf_get_hash_recalc(skb)
    GetHashRecalc = 34,
    /// u64 bpf_get_current_task(void)
    GetCurrentTask = 35,
    /// s64 bpf_csum_update(skb, csum)
    CsumUpdate = 40,
    /// void bpf_set_hash_invalid(skb)
    SetHashInvalid = 41,
    /// long bpf_get_numa_node_id(void)
    GetNumaNodeId = 42,
    /// long bpf_set_hash(skb, hash)
    SetHash = 48,
    /// long bpf_skb_change_head(skb, len, flags)
    SkbChangeHead = 43,
    /// long bpf_xdp_adjust_head(xdp_md, delta)
    XdpAdjustHead = 44,
    /// long bpf_redirect(ifindex, flags)
    Redirect = 23,
    /// long bpf_redirect_map(map, key, flags)
    RedirectMap = 51,
    /// long bpf_redirect_neigh(ifindex, params, plen, flags)
    RedirectNeigh = 152,
    /// long bpf_redirect_peer(ifindex, flags)
    RedirectPeer = 155,
    /// long bpf_xdp_adjust_meta(xdp_md, delta)
    XdpAdjustMeta = 54,
    /// long bpf_tail_call(ctx, prog_array_map, index)
    TailCall = 12,
    /// long bpf_clone_redirect(skb, ifindex, flags)
    CloneRedirect = 13,
    /// u64 bpf_get_current_pid_tgid(void)
    GetCurrentPidTgid = 14,
    /// u64 bpf_get_current_uid_gid(void)
    GetCurrentUidGid = 15,
    /// u64 bpf_get_current_cgroup_id(void)
    GetCurrentCgroupId = 80,
    /// u64 bpf_get_current_ancestor_cgroup_id(int ancestor_level)
    GetCurrentAncestorCgroupId = 123,
    /// int bpf_get_current_comm(buf, size)
    GetCurrentComm = 16,
    /// u32 bpf_get_cgroup_classid(skb)
    GetCgroupClassid = 17,
    /// long bpf_skb_vlan_push(skb, vlan_proto, vlan_tci)
    SkbVlanPush = 18,
    /// long bpf_skb_vlan_pop(skb)
    SkbVlanPop = 19,
    /// u32 bpf_get_route_realm(skb)
    GetRouteRealm = 24,
    /// long bpf_msg_apply_bytes(msg, bytes)
    MsgApplyBytes = 61,
    /// long bpf_msg_cork_bytes(msg, bytes)
    MsgCorkBytes = 62,
    /// long bpf_msg_pull_data(msg, start, end, flags)
    MsgPullData = 63,
    /// long bpf_bind(ctx, addr, addr_len)
    Bind = 64,
    /// u64 bpf_get_socket_cookie(ctx)
    GetSocketCookie = 46,
    /// u32 bpf_get_socket_uid(ctx)
    GetSocketUid = 47,
    /// long bpf_skb_adjust_room(skb, len_diff, mode, flags)
    SkbAdjustRoom = 50,
    /// long bpf_skb_set_tstamp(skb, tstamp, tstamp_type)
    SkbSetTstamp = 192,
    /// long bpf_setsockopt(ctx, level, optname, optval, optlen)
    SetSockOpt = 49,
    /// long bpf_sk_redirect_map(skb, map, key, flags)
    SkRedirectMap = 52,
    /// long bpf_sock_map_update(skops, map, key, flags)
    SockMapUpdate = 53,
    /// long bpf_getsockopt(ctx, level, optname, optval, optlen)
    GetSockOpt = 57,
    /// long bpf_sock_ops_cb_flags_set(bpf_sock, argval)
    SockOpsCbFlagsSet = 59,
    /// long bpf_msg_redirect_map(msg, map, key, flags)
    MsgRedirectMap = 60,
    /// u64 bpf_get_netns_cookie(ctx)
    GetNetnsCookie = 122,
    /// u64 bpf_skb_cgroup_id(skb)
    SkbCgroupId = 79,
    /// u64 bpf_skb_ancestor_cgroup_id(skb, ancestor_level)
    SkbAncestorCgroupId = 83,
    /// long bpf_sock_hash_update(skops, map, key, flags)
    SockHashUpdate = 70,
    /// long bpf_msg_redirect_hash(msg, map, key, flags)
    MsgRedirectHash = 71,
    /// long bpf_sk_redirect_hash(skb, map, key, flags)
    SkRedirectHash = 72,
    /// u64 bpf_ktime_get_boot_ns(void)
    KtimeGetBootNs = 125,
    /// long bpf_load_hdr_opt(skops, searchby_res, len, flags)
    LoadHdrOpt = 142,
    /// long bpf_store_hdr_opt(skops, from, len, flags)
    StoreHdrOpt = 143,
    /// long bpf_reserve_hdr_opt(skops, len, flags)
    ReserveHdrOpt = 144,
    /// int bpf_perf_event_output(ctx, map, flags, data, size)
    PerfEventOutput = 25,
    /// long bpf_skb_load_bytes(skb, offset, to, len)
    SkbLoadBytes = 26,
    /// long bpf_get_stackid(ctx, map, flags)
    GetStackId = 27,
    /// long bpf_skb_load_bytes_relative(skb, offset, to, len, start_header)
    SkbLoadBytesRelative = 68,
    /// struct bpf_sock *bpf_sk_lookup_tcp(ctx, tuple, tuple_size, netns, flags)
    SkLookupTcp = 84,
    /// struct bpf_sock *bpf_sk_lookup_udp(ctx, tuple, tuple_size, netns, flags)
    SkLookupUdp = 85,
    /// void bpf_sk_release(sock)
    SkRelease = 86,
    /// long bpf_map_push_elem(map, value, flags)
    MapPushElem = 87,
    /// long bpf_map_pop_elem(map, value)
    MapPopElem = 88,
    /// long bpf_map_peek_elem(map, value)
    MapPeekElem = 89,
    /// long bpf_msg_push_data(msg, start, len, flags)
    MsgPushData = 90,
    /// long bpf_msg_pop_data(msg, start, len, flags)
    MsgPopData = 91,
    /// long bpf_xdp_adjust_tail(xdp_md, delta)
    XdpAdjustTail = 65,
    /// u64 bpf_xdp_get_buff_len(xdp_md)
    XdpGetBuffLen = 188,
    /// long bpf_xdp_load_bytes(xdp_md, offset, buf, len)
    XdpLoadBytes = 189,
    /// long bpf_xdp_store_bytes(xdp_md, offset, buf, len)
    XdpStoreBytes = 190,
    /// struct bpf_sock *bpf_sk_fullsock(sk)
    SkFullsock = 95,
    /// long bpf_rc_repeat(ctx)
    RcRepeat = 77,
    /// long bpf_rc_keydown(ctx, protocol, scancode, toggle)
    RcKeydown = 78,
    /// long bpf_rc_pointer_rel(ctx, rel_x, rel_y)
    RcPointerRel = 92,
    /// struct bpf_tcp_sock *bpf_tcp_sock(sk)
    TcpSock = 96,
    /// struct bpf_sock *bpf_get_listener_sock(sk)
    GetListenerSock = 98,
    /// struct bpf_sock *bpf_skc_lookup_tcp(ctx, tuple, tuple_size, netns, flags)
    SkcLookupTcp = 99,
    /// long bpf_tcp_check_syncookie(sk, iph, iph_len, th, th_len)
    TcpCheckSyncookie = 100,
    /// long bpf_sysctl_get_name(ctx, buf, buf_len, flags)
    SysctlGetName = 101,
    /// long bpf_sysctl_get_current_value(ctx, buf, buf_len)
    SysctlGetCurrentValue = 102,
    /// long bpf_sysctl_get_new_value(ctx, buf, buf_len)
    SysctlGetNewValue = 103,
    /// long bpf_sysctl_set_new_value(ctx, buf, buf_len)
    SysctlSetNewValue = 104,
    /// void *bpf_sk_storage_get(map, sk, value, flags)
    SkStorageGet = 107,
    /// long bpf_sk_storage_delete(map, sk)
    SkStorageDelete = 108,
    /// s64 bpf_tcp_gen_syncookie(sk, iph, iph_len, th, th_len)
    TcpGenSyncookie = 110,
    /// long bpf_sk_assign(ctx, sk, flags)
    SkAssign = 124,
    /// u64 bpf_sk_cgroup_id(sk)
    SkCgroupId = 128,
    /// u64 bpf_sk_ancestor_cgroup_id(sk, ancestor_level)
    SkAncestorCgroupId = 129,
    /// void *bpf_task_storage_get(map, task, value, flags)
    TaskStorageGet = 156,
    /// long bpf_task_storage_delete(map, task)
    TaskStorageDelete = 157,
    /// struct task_struct *bpf_get_current_task_btf(void)
    GetCurrentTaskBtf = 158,
    /// struct tcp6_sock *bpf_skc_to_tcp6_sock(sk)
    SkcToTcp6Sock = 136,
    /// struct tcp_sock *bpf_skc_to_tcp_sock(sk)
    SkcToTcpSock = 137,
    /// struct tcp_timewait_sock *bpf_skc_to_tcp_timewait_sock(sk)
    SkcToTcpTimewaitSock = 138,
    /// struct tcp_request_sock *bpf_skc_to_tcp_request_sock(sk)
    SkcToTcpRequestSock = 139,
    /// struct udp6_sock *bpf_skc_to_udp6_sock(sk)
    SkcToUdp6Sock = 140,
    /// struct unix_sock *bpf_skc_to_unix_sock(sk)
    SkcToUnixSock = 178,
    /// void *bpf_inode_storage_get(map, inode, value, flags)
    InodeStorageGet = 145,
    /// long bpf_inode_storage_delete(map, inode)
    InodeStorageDelete = 146,
    /// void *bpf_cgrp_storage_get(map, cgroup, value, flags)
    CgrpStorageGet = 210,
    /// long bpf_cgrp_storage_delete(map, cgroup)
    CgrpStorageDelete = 211,
    /// struct socket *bpf_sock_from_file(file)
    SockFromFile = 162,
    /// struct pt_regs *bpf_task_pt_regs(task)
    TaskPtRegs = 175,
    /// long bpf_ringbuf_output(map, data, size, flags)
    RingbufOutput = 130,
    /// void *bpf_ringbuf_reserve(map, size, flags)
    RingbufReserve = 131,
    /// void bpf_ringbuf_submit(data, flags)
    RingbufSubmit = 132,
    /// void bpf_ringbuf_discard(data, flags)
    RingbufDiscard = 133,
    /// u64 bpf_ringbuf_query(map, flags)
    RingbufQuery = 134,
    /// long bpf_csum_level(skb, level)
    CsumLevel = 135,
    /// void *bpf_kptr_xchg(dst, ptr)
    KptrXchg = 194,
    /// long bpf_probe_read_user_str(dst, size, unsafe_ptr)
    ProbeReadUserStr = 114,
    /// long bpf_probe_read_kernel_str(dst, size, unsafe_ptr)
    ProbeReadKernelStr = 115,
}

impl BpfHelper {
    pub const fn name(self) -> &'static str {
        match self {
            BpfHelper::MapLookupElem => "bpf_map_lookup_elem",
            BpfHelper::MapUpdateElem => "bpf_map_update_elem",
            BpfHelper::MapDeleteElem => "bpf_map_delete_elem",
            BpfHelper::ProbeRead => "bpf_probe_read",
            BpfHelper::ProbeReadUser => "bpf_probe_read_user",
            BpfHelper::ProbeReadKernel => "bpf_probe_read_kernel",
            BpfHelper::KtimeGetNs => "bpf_ktime_get_ns",
            BpfHelper::TracePrintk => "bpf_trace_printk",
            BpfHelper::GetPrandomU32 => "bpf_get_prandom_u32",
            BpfHelper::GetSmpProcessorId => "bpf_get_smp_processor_id",
            BpfHelper::SkbStoreBytes => "bpf_skb_store_bytes",
            BpfHelper::L3CsumReplace => "bpf_l3_csum_replace",
            BpfHelper::L4CsumReplace => "bpf_l4_csum_replace",
            BpfHelper::SkbUnderCgroup => "bpf_skb_under_cgroup",
            BpfHelper::SkbChangeTail => "bpf_skb_change_tail",
            BpfHelper::CurrentTaskUnderCgroup => "bpf_current_task_under_cgroup",
            BpfHelper::SkbPullData => "bpf_skb_pull_data",
            BpfHelper::GetHashRecalc => "bpf_get_hash_recalc",
            BpfHelper::GetCurrentTask => "bpf_get_current_task",
            BpfHelper::CsumUpdate => "bpf_csum_update",
            BpfHelper::SetHashInvalid => "bpf_set_hash_invalid",
            BpfHelper::GetNumaNodeId => "bpf_get_numa_node_id",
            BpfHelper::SetHash => "bpf_set_hash",
            BpfHelper::SkbChangeHead => "bpf_skb_change_head",
            BpfHelper::XdpAdjustHead => "bpf_xdp_adjust_head",
            BpfHelper::Redirect => "bpf_redirect",
            BpfHelper::RedirectMap => "bpf_redirect_map",
            BpfHelper::RedirectNeigh => "bpf_redirect_neigh",
            BpfHelper::RedirectPeer => "bpf_redirect_peer",
            BpfHelper::XdpAdjustMeta => "bpf_xdp_adjust_meta",
            BpfHelper::TailCall => "bpf_tail_call",
            BpfHelper::CloneRedirect => "bpf_clone_redirect",
            BpfHelper::GetCurrentPidTgid => "bpf_get_current_pid_tgid",
            BpfHelper::GetCurrentUidGid => "bpf_get_current_uid_gid",
            BpfHelper::GetCurrentCgroupId => "bpf_get_current_cgroup_id",
            BpfHelper::GetCurrentAncestorCgroupId => "bpf_get_current_ancestor_cgroup_id",
            BpfHelper::GetCurrentComm => "bpf_get_current_comm",
            BpfHelper::GetCgroupClassid => "bpf_get_cgroup_classid",
            BpfHelper::SkbVlanPush => "bpf_skb_vlan_push",
            BpfHelper::SkbVlanPop => "bpf_skb_vlan_pop",
            BpfHelper::GetRouteRealm => "bpf_get_route_realm",
            BpfHelper::MsgApplyBytes => "bpf_msg_apply_bytes",
            BpfHelper::MsgCorkBytes => "bpf_msg_cork_bytes",
            BpfHelper::MsgPullData => "bpf_msg_pull_data",
            BpfHelper::Bind => "bpf_bind",
            BpfHelper::GetSocketCookie => "bpf_get_socket_cookie",
            BpfHelper::GetSocketUid => "bpf_get_socket_uid",
            BpfHelper::SkbAdjustRoom => "bpf_skb_adjust_room",
            BpfHelper::SkbSetTstamp => "bpf_skb_set_tstamp",
            BpfHelper::SetSockOpt => "bpf_setsockopt",
            BpfHelper::SkRedirectMap => "bpf_sk_redirect_map",
            BpfHelper::SockMapUpdate => "bpf_sock_map_update",
            BpfHelper::GetSockOpt => "bpf_getsockopt",
            BpfHelper::SockOpsCbFlagsSet => "bpf_sock_ops_cb_flags_set",
            BpfHelper::MsgRedirectMap => "bpf_msg_redirect_map",
            BpfHelper::GetNetnsCookie => "bpf_get_netns_cookie",
            BpfHelper::SkbCgroupId => "bpf_skb_cgroup_id",
            BpfHelper::SkbAncestorCgroupId => "bpf_skb_ancestor_cgroup_id",
            BpfHelper::SockHashUpdate => "bpf_sock_hash_update",
            BpfHelper::MsgRedirectHash => "bpf_msg_redirect_hash",
            BpfHelper::SkRedirectHash => "bpf_sk_redirect_hash",
            BpfHelper::KtimeGetBootNs => "bpf_ktime_get_boot_ns",
            BpfHelper::LoadHdrOpt => "bpf_load_hdr_opt",
            BpfHelper::StoreHdrOpt => "bpf_store_hdr_opt",
            BpfHelper::ReserveHdrOpt => "bpf_reserve_hdr_opt",
            BpfHelper::PerfEventOutput => "bpf_perf_event_output",
            BpfHelper::SkbLoadBytes => "bpf_skb_load_bytes",
            BpfHelper::GetStackId => "bpf_get_stackid",
            BpfHelper::SkbLoadBytesRelative => "bpf_skb_load_bytes_relative",
            BpfHelper::SkLookupTcp => "bpf_sk_lookup_tcp",
            BpfHelper::SkLookupUdp => "bpf_sk_lookup_udp",
            BpfHelper::SkRelease => "bpf_sk_release",
            BpfHelper::MapPushElem => "bpf_map_push_elem",
            BpfHelper::MapPopElem => "bpf_map_pop_elem",
            BpfHelper::MapPeekElem => "bpf_map_peek_elem",
            BpfHelper::MsgPushData => "bpf_msg_push_data",
            BpfHelper::MsgPopData => "bpf_msg_pop_data",
            BpfHelper::XdpAdjustTail => "bpf_xdp_adjust_tail",
            BpfHelper::XdpGetBuffLen => "bpf_xdp_get_buff_len",
            BpfHelper::XdpLoadBytes => "bpf_xdp_load_bytes",
            BpfHelper::XdpStoreBytes => "bpf_xdp_store_bytes",
            BpfHelper::RcRepeat => "bpf_rc_repeat",
            BpfHelper::RcKeydown => "bpf_rc_keydown",
            BpfHelper::RcPointerRel => "bpf_rc_pointer_rel",
            BpfHelper::SkFullsock => "bpf_sk_fullsock",
            BpfHelper::TcpSock => "bpf_tcp_sock",
            BpfHelper::GetListenerSock => "bpf_get_listener_sock",
            BpfHelper::SkcLookupTcp => "bpf_skc_lookup_tcp",
            BpfHelper::TcpCheckSyncookie => "bpf_tcp_check_syncookie",
            BpfHelper::SysctlGetName => "bpf_sysctl_get_name",
            BpfHelper::SysctlGetCurrentValue => "bpf_sysctl_get_current_value",
            BpfHelper::SysctlGetNewValue => "bpf_sysctl_get_new_value",
            BpfHelper::SysctlSetNewValue => "bpf_sysctl_set_new_value",
            BpfHelper::SkStorageGet => "bpf_sk_storage_get",
            BpfHelper::SkStorageDelete => "bpf_sk_storage_delete",
            BpfHelper::TcpGenSyncookie => "bpf_tcp_gen_syncookie",
            BpfHelper::SkAssign => "bpf_sk_assign",
            BpfHelper::SkCgroupId => "bpf_sk_cgroup_id",
            BpfHelper::SkAncestorCgroupId => "bpf_sk_ancestor_cgroup_id",
            BpfHelper::TaskStorageGet => "bpf_task_storage_get",
            BpfHelper::TaskStorageDelete => "bpf_task_storage_delete",
            BpfHelper::GetCurrentTaskBtf => "bpf_get_current_task_btf",
            BpfHelper::SkcToTcp6Sock => "bpf_skc_to_tcp6_sock",
            BpfHelper::SkcToTcpSock => "bpf_skc_to_tcp_sock",
            BpfHelper::SkcToTcpTimewaitSock => "bpf_skc_to_tcp_timewait_sock",
            BpfHelper::SkcToTcpRequestSock => "bpf_skc_to_tcp_request_sock",
            BpfHelper::SkcToUdp6Sock => "bpf_skc_to_udp6_sock",
            BpfHelper::SkcToUnixSock => "bpf_skc_to_unix_sock",
            BpfHelper::InodeStorageGet => "bpf_inode_storage_get",
            BpfHelper::InodeStorageDelete => "bpf_inode_storage_delete",
            BpfHelper::CgrpStorageGet => "bpf_cgrp_storage_get",
            BpfHelper::CgrpStorageDelete => "bpf_cgrp_storage_delete",
            BpfHelper::SockFromFile => "bpf_sock_from_file",
            BpfHelper::TaskPtRegs => "bpf_task_pt_regs",
            BpfHelper::RingbufOutput => "bpf_ringbuf_output",
            BpfHelper::RingbufReserve => "bpf_ringbuf_reserve",
            BpfHelper::RingbufSubmit => "bpf_ringbuf_submit",
            BpfHelper::RingbufDiscard => "bpf_ringbuf_discard",
            BpfHelper::RingbufQuery => "bpf_ringbuf_query",
            BpfHelper::CsumLevel => "bpf_csum_level",
            BpfHelper::KptrXchg => "bpf_kptr_xchg",
            BpfHelper::ProbeReadUserStr => "bpf_probe_read_user_str",
            BpfHelper::ProbeReadKernelStr => "bpf_probe_read_kernel_str",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        let canonical = if let Some(stripped) = name.strip_prefix("bpf_") {
            stripped
        } else {
            name
        };
        match canonical {
            "map_lookup_elem" => Some(Self::MapLookupElem),
            "map_update_elem" => Some(Self::MapUpdateElem),
            "map_delete_elem" => Some(Self::MapDeleteElem),
            "probe_read" => Some(Self::ProbeRead),
            "probe_read_user" => Some(Self::ProbeReadUser),
            "probe_read_kernel" => Some(Self::ProbeReadKernel),
            "ktime_get_ns" => Some(Self::KtimeGetNs),
            "trace_printk" => Some(Self::TracePrintk),
            "get_prandom_u32" => Some(Self::GetPrandomU32),
            "get_smp_processor_id" => Some(Self::GetSmpProcessorId),
            "skb_store_bytes" => Some(Self::SkbStoreBytes),
            "l3_csum_replace" => Some(Self::L3CsumReplace),
            "l4_csum_replace" => Some(Self::L4CsumReplace),
            "skb_under_cgroup" => Some(Self::SkbUnderCgroup),
            "skb_change_tail" => Some(Self::SkbChangeTail),
            "current_task_under_cgroup" => Some(Self::CurrentTaskUnderCgroup),
            "skb_pull_data" => Some(Self::SkbPullData),
            "get_hash_recalc" => Some(Self::GetHashRecalc),
            "get_current_task" => Some(Self::GetCurrentTask),
            "csum_update" => Some(Self::CsumUpdate),
            "set_hash_invalid" => Some(Self::SetHashInvalid),
            "get_numa_node_id" => Some(Self::GetNumaNodeId),
            "set_hash" => Some(Self::SetHash),
            "skb_change_head" => Some(Self::SkbChangeHead),
            "xdp_adjust_head" => Some(Self::XdpAdjustHead),
            "redirect" => Some(Self::Redirect),
            "redirect_map" => Some(Self::RedirectMap),
            "redirect_neigh" => Some(Self::RedirectNeigh),
            "redirect_peer" => Some(Self::RedirectPeer),
            "xdp_adjust_meta" => Some(Self::XdpAdjustMeta),
            "tail_call" => Some(Self::TailCall),
            "clone_redirect" => Some(Self::CloneRedirect),
            "get_current_pid_tgid" => Some(Self::GetCurrentPidTgid),
            "get_current_uid_gid" => Some(Self::GetCurrentUidGid),
            "get_current_cgroup_id" => Some(Self::GetCurrentCgroupId),
            "get_current_ancestor_cgroup_id" => Some(Self::GetCurrentAncestorCgroupId),
            "get_current_comm" => Some(Self::GetCurrentComm),
            "get_cgroup_classid" => Some(Self::GetCgroupClassid),
            "skb_vlan_push" => Some(Self::SkbVlanPush),
            "skb_vlan_pop" => Some(Self::SkbVlanPop),
            "get_route_realm" => Some(Self::GetRouteRealm),
            "msg_apply_bytes" => Some(Self::MsgApplyBytes),
            "msg_cork_bytes" => Some(Self::MsgCorkBytes),
            "msg_pull_data" => Some(Self::MsgPullData),
            "bind" => Some(Self::Bind),
            "get_socket_cookie" => Some(Self::GetSocketCookie),
            "get_socket_uid" => Some(Self::GetSocketUid),
            "skb_adjust_room" => Some(Self::SkbAdjustRoom),
            "skb_set_tstamp" => Some(Self::SkbSetTstamp),
            "setsockopt" => Some(Self::SetSockOpt),
            "sk_redirect_map" => Some(Self::SkRedirectMap),
            "sock_map_update" => Some(Self::SockMapUpdate),
            "getsockopt" => Some(Self::GetSockOpt),
            "sock_ops_cb_flags_set" => Some(Self::SockOpsCbFlagsSet),
            "msg_redirect_map" => Some(Self::MsgRedirectMap),
            "get_netns_cookie" => Some(Self::GetNetnsCookie),
            "skb_cgroup_id" => Some(Self::SkbCgroupId),
            "skb_ancestor_cgroup_id" => Some(Self::SkbAncestorCgroupId),
            "sock_hash_update" => Some(Self::SockHashUpdate),
            "msg_redirect_hash" => Some(Self::MsgRedirectHash),
            "sk_redirect_hash" => Some(Self::SkRedirectHash),
            "ktime_get_boot_ns" => Some(Self::KtimeGetBootNs),
            "load_hdr_opt" => Some(Self::LoadHdrOpt),
            "store_hdr_opt" => Some(Self::StoreHdrOpt),
            "reserve_hdr_opt" => Some(Self::ReserveHdrOpt),
            "perf_event_output" => Some(Self::PerfEventOutput),
            "skb_load_bytes" => Some(Self::SkbLoadBytes),
            "get_stackid" => Some(Self::GetStackId),
            "skb_load_bytes_relative" => Some(Self::SkbLoadBytesRelative),
            "sk_lookup_tcp" => Some(Self::SkLookupTcp),
            "sk_lookup_udp" => Some(Self::SkLookupUdp),
            "sk_release" => Some(Self::SkRelease),
            "map_push_elem" => Some(Self::MapPushElem),
            "map_pop_elem" => Some(Self::MapPopElem),
            "map_peek_elem" => Some(Self::MapPeekElem),
            "msg_push_data" => Some(Self::MsgPushData),
            "msg_pop_data" => Some(Self::MsgPopData),
            "xdp_adjust_tail" => Some(Self::XdpAdjustTail),
            "xdp_get_buff_len" => Some(Self::XdpGetBuffLen),
            "xdp_load_bytes" => Some(Self::XdpLoadBytes),
            "xdp_store_bytes" => Some(Self::XdpStoreBytes),
            "rc_repeat" => Some(Self::RcRepeat),
            "rc_keydown" => Some(Self::RcKeydown),
            "rc_pointer_rel" => Some(Self::RcPointerRel),
            "sk_fullsock" => Some(Self::SkFullsock),
            "tcp_sock" => Some(Self::TcpSock),
            "get_listener_sock" => Some(Self::GetListenerSock),
            "skc_lookup_tcp" => Some(Self::SkcLookupTcp),
            "tcp_check_syncookie" => Some(Self::TcpCheckSyncookie),
            "sysctl_get_name" => Some(Self::SysctlGetName),
            "sysctl_get_current_value" => Some(Self::SysctlGetCurrentValue),
            "sysctl_get_new_value" => Some(Self::SysctlGetNewValue),
            "sysctl_set_new_value" => Some(Self::SysctlSetNewValue),
            "sk_storage_get" => Some(Self::SkStorageGet),
            "sk_storage_delete" => Some(Self::SkStorageDelete),
            "tcp_gen_syncookie" => Some(Self::TcpGenSyncookie),
            "sk_assign" => Some(Self::SkAssign),
            "sk_cgroup_id" => Some(Self::SkCgroupId),
            "sk_ancestor_cgroup_id" => Some(Self::SkAncestorCgroupId),
            "task_storage_get" => Some(Self::TaskStorageGet),
            "task_storage_delete" => Some(Self::TaskStorageDelete),
            "get_current_task_btf" => Some(Self::GetCurrentTaskBtf),
            "skc_to_tcp6_sock" => Some(Self::SkcToTcp6Sock),
            "skc_to_tcp_sock" => Some(Self::SkcToTcpSock),
            "skc_to_tcp_timewait_sock" => Some(Self::SkcToTcpTimewaitSock),
            "skc_to_tcp_request_sock" => Some(Self::SkcToTcpRequestSock),
            "skc_to_udp6_sock" => Some(Self::SkcToUdp6Sock),
            "skc_to_unix_sock" => Some(Self::SkcToUnixSock),
            "inode_storage_get" => Some(Self::InodeStorageGet),
            "inode_storage_delete" => Some(Self::InodeStorageDelete),
            "cgrp_storage_get" | "cgroup_storage_get" => Some(Self::CgrpStorageGet),
            "cgrp_storage_delete" | "cgroup_storage_delete" => Some(Self::CgrpStorageDelete),
            "sock_from_file" => Some(Self::SockFromFile),
            "task_pt_regs" => Some(Self::TaskPtRegs),
            "ringbuf_output" => Some(Self::RingbufOutput),
            "ringbuf_reserve" => Some(Self::RingbufReserve),
            "ringbuf_submit" => Some(Self::RingbufSubmit),
            "ringbuf_discard" => Some(Self::RingbufDiscard),
            "ringbuf_query" => Some(Self::RingbufQuery),
            "csum_level" => Some(Self::CsumLevel),
            "kptr_xchg" => Some(Self::KptrXchg),
            "probe_read_user_str" => Some(Self::ProbeReadUserStr),
            "probe_read_kernel_str" => Some(Self::ProbeReadKernelStr),
            _ => None,
        }
    }

    pub const fn helper_map_arg_kind(self, arg_idx: usize) -> Option<MapKind> {
        match (self, arg_idx) {
            (Self::TailCall, 1) => Some(MapKind::ProgArray),
            (Self::PerfEventOutput, 1) => Some(MapKind::PerfEventArray),
            (Self::GetStackId, 1) => Some(MapKind::StackTrace),
            (Self::SkbUnderCgroup, 1) | (Self::CurrentTaskUnderCgroup, 0) => {
                Some(MapKind::CgroupArray)
            }
            (Self::RingbufOutput | Self::RingbufReserve | Self::RingbufQuery, 0) => {
                Some(MapKind::RingBuf)
            }
            (Self::SkRedirectMap | Self::SockMapUpdate | Self::MsgRedirectMap, 1) => {
                Some(MapKind::SockMap)
            }
            (Self::SockHashUpdate | Self::MsgRedirectHash | Self::SkRedirectHash, 1) => {
                Some(MapKind::SockHash)
            }
            (Self::SkStorageGet | Self::SkStorageDelete, 0) => Some(MapKind::SkStorage),
            (Self::TaskStorageGet | Self::TaskStorageDelete, 0) => Some(MapKind::TaskStorage),
            (Self::InodeStorageGet | Self::InodeStorageDelete, 0) => Some(MapKind::InodeStorage),
            (Self::CgrpStorageGet | Self::CgrpStorageDelete, 0) => Some(MapKind::CgrpStorage),
            _ => None,
        }
    }

    pub const fn local_helper_map_arg_index(self) -> Option<usize> {
        match self {
            Self::TailCall | Self::PerfEventOutput | Self::GetStackId | Self::SkbUnderCgroup => {
                Some(1)
            }
            Self::CurrentTaskUnderCgroup => Some(0),
            Self::RingbufOutput
            | Self::RingbufReserve
            | Self::RingbufQuery
            | Self::MapPushElem
            | Self::MapPopElem
            | Self::MapPeekElem
            | Self::RedirectMap => Some(0),
            Self::SkRedirectMap
            | Self::SockMapUpdate
            | Self::MsgRedirectMap
            | Self::SockHashUpdate
            | Self::MsgRedirectHash
            | Self::SkRedirectHash => Some(1),
            Self::SkStorageGet
            | Self::SkStorageDelete
            | Self::TaskStorageGet
            | Self::TaskStorageDelete
            | Self::InodeStorageGet
            | Self::InodeStorageDelete
            | Self::CgrpStorageGet
            | Self::CgrpStorageDelete => Some(0),
            _ => None,
        }
    }

    pub const fn helper_explicit_map_kind_family(
        self,
        arg_idx: usize,
    ) -> Option<HelperExplicitMapKindFamily> {
        match self.local_helper_map_arg_index() {
            Some(idx) if idx == arg_idx => match self {
                Self::MapPushElem | Self::MapPeekElem => {
                    Some(HelperExplicitMapKindFamily::QueueStackBloom)
                }
                Self::MapPopElem => Some(HelperExplicitMapKindFamily::QueueStack),
                Self::RedirectMap => Some(HelperExplicitMapKindFamily::RedirectMap),
                _ => None,
            },
            _ => None,
        }
    }

    pub const fn helper_requires_explicit_map_kind(self, arg_idx: usize) -> bool {
        self.helper_explicit_map_kind_family(arg_idx).is_some()
    }

    pub const fn invalidates_packet_pointers(self) -> bool {
        matches!(
            self,
            Self::SkbChangeTail
                | Self::SkbStoreBytes
                | Self::L3CsumReplace
                | Self::L4CsumReplace
                | Self::CloneRedirect
                | Self::SkbPullData
                | Self::SkbChangeHead
                | Self::SkbVlanPush
                | Self::SkbVlanPop
                | Self::XdpAdjustHead
                | Self::XdpAdjustMeta
                | Self::SkbAdjustRoom
                | Self::XdpAdjustTail
                | Self::MsgPullData
        )
    }

    pub const fn supports_local_helper_map_fd(self, arg_idx: usize) -> bool {
        match self.local_helper_map_arg_index() {
            Some(idx) => idx == arg_idx,
            None => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperArgKind {
    Scalar,
    Pointer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperExplicitMapKindFamily {
    QueueStack,
    QueueStackBloom,
    RedirectMap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperRetKind {
    Scalar,
    PointerNonNull,
    PointerMaybeNull,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KfuncArgKind {
    Scalar,
    Pointer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KfuncRetKind {
    Scalar,
    PointerMaybeNull,
    Void,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KfuncRefKind {
    Task,
    Cgroup,
    Inode,
    Cpumask,
    CryptoCtx,
    Object,
    File,
    Socket,
}

impl KfuncRefKind {
    pub const fn label(self) -> &'static str {
        match self {
            KfuncRefKind::Task => "task",
            KfuncRefKind::Cgroup => "cgroup",
            KfuncRefKind::Inode => "inode",
            KfuncRefKind::Cpumask => "cpumask",
            KfuncRefKind::CryptoCtx => "crypto_ctx",
            KfuncRefKind::Object => "object",
            KfuncRefKind::File => "file",
            KfuncRefKind::Socket => "socket",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelperAllowedPtrSpaces {
    pub allow_stack: bool,
    pub allow_map: bool,
    pub allow_kernel: bool,
    pub allow_user: bool,
}

impl HelperAllowedPtrSpaces {
    pub const fn new(
        allow_stack: bool,
        allow_map: bool,
        allow_kernel: bool,
        allow_user: bool,
    ) -> Self {
        Self {
            allow_stack,
            allow_map,
            allow_kernel,
            allow_user,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelperPtrArgRule {
    pub arg_idx: usize,
    pub op: &'static str,
    pub allowed: HelperAllowedPtrSpaces,
    pub fixed_size: Option<usize>,
    pub size_from_arg: Option<usize>,
}

#[derive(Debug, Clone, Copy)]
pub struct HelperSemantics {
    pub ptr_arg_rules: &'static [HelperPtrArgRule],
    pub positive_size_args: &'static [usize],
    pub ringbuf_record_arg0: bool,
}

impl HelperSemantics {
    pub const EMPTY: Self = Self {
        ptr_arg_rules: &[],
        positive_size_args: &[],
        ringbuf_record_arg0: false,
    };
}

#[derive(Debug, Clone, Copy)]
pub struct HelperSignature {
    pub min_args: usize,
    pub max_args: usize,
    pub arg_kinds: [HelperArgKind; 5],
    pub ret_kind: HelperRetKind,
}

impl HelperSignature {
    pub const fn for_id(helper_id: u32) -> Option<Self> {
        match BpfHelper::from_u32(helper_id) {
            Some(helper) => Some(helper.signature()),
            None => None,
        }
    }

    pub const fn arg_kind(&self, idx: usize) -> HelperArgKind {
        self.arg_kinds[idx]
    }
}

#[derive(Debug, Clone, Copy)]
pub struct KfuncSignature {
    pub min_args: usize,
    pub max_args: usize,
    pub arg_kinds: [KfuncArgKind; 5],
    pub ret_kind: KfuncRetKind,
}

#[path = "instruction/kfunc_signature.rs"]
mod kfunc_signature;

#[path = "instruction/ref_kinds.rs"]
mod ref_kinds;

pub use kfunc_signature::unknown_kfunc_signature_message;
pub use ref_kinds::{
    KfuncAllowedPtrSpaces, KfuncIterFamily, KfuncIterLifecycleOp, KfuncPtrArgRule, KfuncSemantics,
    KfuncUnknownDynptrArg, KfuncUnknownDynptrArgRole, KfuncUnknownDynptrCopy,
    KfuncUnknownIterLifecycle, KfuncUnknownStackObjectCopy, KfuncUnknownStackObjectLifecycle,
    KfuncUnknownStackObjectLifecycleOp, helper_acquire_ref_kind, helper_pointer_arg_ref_kind,
    helper_release_ref_kind, kfunc_acquire_ref_kind, kfunc_pointer_arg_allows_const_zero,
    kfunc_pointer_arg_fixed_size, kfunc_pointer_arg_min_access_size, kfunc_pointer_arg_ref_kind,
    kfunc_pointer_arg_requires_kernel, kfunc_pointer_arg_requires_stack,
    kfunc_pointer_arg_requires_stack_or_map, kfunc_pointer_arg_requires_stack_slot_base,
    kfunc_pointer_arg_requires_user, kfunc_pointer_arg_size_from_scalar,
    kfunc_release_ref_arg_index, kfunc_release_ref_kind, kfunc_scalar_arg_requires_known_const,
    kfunc_scalar_arg_requires_positive, kfunc_semantics, kfunc_unknown_dynptr_args,
    kfunc_unknown_dynptr_copy, kfunc_unknown_iter_lifecycle, kfunc_unknown_stack_object_copy,
    kfunc_unknown_stack_object_lifecycle,
};

#[path = "instruction/helper_metadata.rs"]
mod helper_metadata;

#[path = "instruction/encoding.rs"]
mod encoding;

/// eBPF instruction opcodes
pub mod opcode {
    // Instruction classes (3 bits)
    pub const BPF_LD: u8 = 0x00;
    pub const BPF_LDX: u8 = 0x01;
    pub const BPF_ST: u8 = 0x02;
    pub const BPF_STX: u8 = 0x03;
    pub const BPF_ALU: u8 = 0x04;
    pub const BPF_JMP: u8 = 0x05;
    pub const BPF_JMP32: u8 = 0x06;
    pub const BPF_ALU64: u8 = 0x07;

    // Size modifiers (2 bits)
    pub const BPF_W: u8 = 0x00; // 32-bit
    pub const BPF_H: u8 = 0x08; // 16-bit
    pub const BPF_B: u8 = 0x10; // 8-bit
    pub const BPF_DW: u8 = 0x18; // 64-bit

    // Source modifiers
    pub const BPF_K: u8 = 0x00; // Immediate
    pub const BPF_X: u8 = 0x08; // Register

    // ALU operations (4 bits, shifted left by 4)
    pub const BPF_ADD: u8 = 0x00;
    pub const BPF_SUB: u8 = 0x10;
    pub const BPF_MUL: u8 = 0x20;
    pub const BPF_DIV: u8 = 0x30;
    pub const BPF_OR: u8 = 0x40;
    pub const BPF_AND: u8 = 0x50;
    pub const BPF_LSH: u8 = 0x60;
    pub const BPF_RSH: u8 = 0x70;
    pub const BPF_NEG: u8 = 0x80;
    pub const BPF_MOD: u8 = 0x90;
    pub const BPF_XOR: u8 = 0xa0;
    pub const BPF_MOV: u8 = 0xb0;
    pub const BPF_ARSH: u8 = 0xc0; // Arithmetic right shift
    pub const BPF_END: u8 = 0xd0; // Endianness conversion

    // Jump operations
    pub const BPF_JA: u8 = 0x00; // Jump always
    pub const BPF_JEQ: u8 = 0x10; // Jump if equal
    pub const BPF_JGT: u8 = 0x20; // Jump if greater than
    pub const BPF_JGE: u8 = 0x30; // Jump if greater or equal
    pub const BPF_JSET: u8 = 0x40; // Jump if set (bitwise AND)
    pub const BPF_JNE: u8 = 0x50; // Jump if not equal
    pub const BPF_JSGT: u8 = 0x60; // Jump if signed greater than
    pub const BPF_JSGE: u8 = 0x70; // Jump if signed greater or equal
    pub const BPF_CALL: u8 = 0x80; // Function call
    pub const BPF_EXIT: u8 = 0x90; // Exit program
    pub const BPF_JLT: u8 = 0xa0; // Jump if less than
    pub const BPF_JLE: u8 = 0xb0; // Jump if less or equal
    pub const BPF_JSLT: u8 = 0xc0; // Jump if signed less than
    pub const BPF_JSLE: u8 = 0xd0; // Jump if signed less or equal

    // Memory modes
    pub const BPF_IMM: u8 = 0x00;
    pub const BPF_ABS: u8 = 0x20;
    pub const BPF_IND: u8 = 0x40;
    pub const BPF_MEM: u8 = 0x60;

    // Composite opcodes for common operations
    pub const MOV64_IMM: u8 = BPF_ALU64 | BPF_MOV | BPF_K; // 0xb7
    pub const MOV64_REG: u8 = BPF_ALU64 | BPF_MOV | BPF_X; // 0xbf
    pub const ADD64_IMM: u8 = BPF_ALU64 | BPF_ADD | BPF_K; // 0x07
    pub const ADD64_REG: u8 = BPF_ALU64 | BPF_ADD | BPF_X; // 0x0f
    pub const SUB64_IMM: u8 = BPF_ALU64 | BPF_SUB | BPF_K; // 0x17
    pub const SUB64_REG: u8 = BPF_ALU64 | BPF_SUB | BPF_X; // 0x1f
    pub const MUL64_IMM: u8 = BPF_ALU64 | BPF_MUL | BPF_K; // 0x27
    pub const MUL64_REG: u8 = BPF_ALU64 | BPF_MUL | BPF_X; // 0x2f
    pub const DIV64_IMM: u8 = BPF_ALU64 | BPF_DIV | BPF_K; // 0x37
    pub const DIV64_REG: u8 = BPF_ALU64 | BPF_DIV | BPF_X; // 0x3f
    pub const MOD64_IMM: u8 = BPF_ALU64 | BPF_MOD | BPF_K; // 0x97
    pub const MOD64_REG: u8 = BPF_ALU64 | BPF_MOD | BPF_X; // 0x9f
    pub const OR64_IMM: u8 = BPF_ALU64 | BPF_OR | BPF_K; // 0x47
    pub const OR64_REG: u8 = BPF_ALU64 | BPF_OR | BPF_X; // 0x4f
    pub const AND64_IMM: u8 = BPF_ALU64 | BPF_AND | BPF_K; // 0x57
    pub const AND64_REG: u8 = BPF_ALU64 | BPF_AND | BPF_X; // 0x5f
    pub const XOR64_IMM: u8 = BPF_ALU64 | BPF_XOR | BPF_K; // 0xa7
    pub const XOR64_REG: u8 = BPF_ALU64 | BPF_XOR | BPF_X; // 0xaf
    pub const LSH64_IMM: u8 = BPF_ALU64 | BPF_LSH | BPF_K; // 0x67
    pub const LSH64_REG: u8 = BPF_ALU64 | BPF_LSH | BPF_X; // 0x6f
    pub const RSH64_IMM: u8 = BPF_ALU64 | BPF_RSH | BPF_K; // 0x77
    pub const RSH64_REG: u8 = BPF_ALU64 | BPF_RSH | BPF_X; // 0x7f
    pub const CALL: u8 = BPF_JMP | BPF_CALL; // 0x85
    pub const EXIT: u8 = BPF_JMP | BPF_EXIT; // 0x95
    pub const LD_DW_IMM: u8 = BPF_LD | BPF_DW | BPF_IMM; // 0x18 (64-bit immediate load)
}

/// A single eBPF instruction (64-bit)
#[derive(Debug, Clone, Copy)]
pub struct EbpfInsn {
    /// Operation code
    pub opcode: u8,
    /// Destination register (4 bits, lower nibble)
    pub dst_reg: u8,
    /// Source register (4 bits, upper nibble)
    pub src_reg: u8,
    /// Signed offset for memory/branch operations
    pub offset: i16,
    /// Signed immediate value
    pub imm: i32,
}

/// Builder for constructing eBPF programs
#[derive(Debug, Default)]
pub struct EbpfBuilder {
    instructions: Vec<EbpfInsn>,
}

#[cfg(test)]
mod tests;
