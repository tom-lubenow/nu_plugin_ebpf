//! eBPF instruction encoding
//!
//! eBPF instructions are 64-bit fixed-length, encoded as:
//! ```text
//! opcode:8 src_reg:4 dst_reg:4 offset:16 imm:32
//! ```
//!
//! Some instructions (like 64-bit immediate loads) use two 64-bit slots.

use crate::compiler::mir::{MapKind, MirType, ScalarValueRange};

const STRTOX_BASE_FLAGS: &[i64] = &[0, 8, 10, 16];
const SKB_GET_TUNNEL_KEY_FLAGS: &[i64] = &[0, 1, 16, 17];
const SKB_TUNNEL_KEY_SIZES: &[i64] = &[8, 22, 24, 28, 44];
const MAP_UPDATE_FLAGS: &[i64] = &[0, 1, 2];
const MAP_PUSH_FLAGS: &[i64] = &[0, 2];
const TIMER_INIT_FLAGS: &[i64] = &[0, 1, 7];
const LWT_SEG6_ACTIONS: &[i64] = &[2, 3, 9, 10];
const BPF_CSUM_LEVELS: &[i64] = &[0, 1, 2, 3];
const BPF_ANCESTOR_CGROUP_LEVEL_MAX: i64 = i32::MAX as i64;
const SKB_CHANGE_PROTO_PROTOCOLS: &[i64] = &[0x0800, 0x86dd];
const BPF_F_HDR_FIELD_MASK: i64 = 0x0f;
const BPF_F_HDR_FIELD_SIZE_BIT_0: i64 = 1 << 0;
const BPF_F_HDR_FIELD_SIZE_BIT_1: i64 = 1 << 1;
const BPF_F_HDR_FIELD_SIZE_BIT_2: i64 = 1 << 2;
const BPF_F_HDR_FIELD_SIZE_BIT_3: i64 = 1 << 3;
const BPF_F_PSEUDO_HDR: i64 = 1 << 4;
const BPF_F_MARK_MANGLED_0: i64 = 1 << 5;
const BPF_F_MARK_ENFORCE: i64 = 1 << 6;
const BPF_F_IPV6: i64 = 1 << 7;
const BPF_F_L4_CSUM_REPLACE_ALLOWED_MASK: i64 = BPF_F_HDR_FIELD_MASK
    | BPF_F_PSEUDO_HDR
    | BPF_F_MARK_MANGLED_0
    | BPF_F_MARK_ENFORCE
    | BPF_F_IPV6;
const BPF_CSUM_DIFF_MAX_U32: i64 = u32::MAX as i64;
const BPF_CSUM_UPDATE_CSUM_MAX_U32: i64 = u32::MAX as i64;
const BPF_GET_CURRENT_COMM_SIZE_MAX_U32: i64 = u32::MAX as i64;
const BPF_COPY_FROM_USER_SIZE_MAX_U32: i64 = u32::MAX as i64;
const BPF_PROBE_MEM_SIZE_MAX_U32: i64 = u32::MAX as i64;
const BPF_MAX_LOOPS: i64 = 8 * 1024 * 1024;
const BPF_TAIL_CALL_INDEX_MAX_U32: i64 = u32::MAX as i64;
const BPF_CPU_INDEX_MAX_U32: i64 = u32::MAX as i64;
const BPF_CGROUP_ARRAY_INDEX_MAX_U32: i64 = u32::MAX as i64;
const BPF_FIB_LOOKUP_DIRECT: i64 = 1 << 0;
const BPF_FIB_LOOKUP_TBID: i64 = 1 << 3;
const BPF_FIB_LOOKUP_MARK: i64 = 1 << 5;
const BPF_FIB_LOOKUP_SIZE: i64 = 64;
pub(crate) const BPF_MTU_CHK_SEGS: i64 = 1 << 0;
const BPF_F_ADJ_ROOM_ENCAP_L3_IPV4: i64 = 1 << 1;
const BPF_F_ADJ_ROOM_ENCAP_L3_IPV6: i64 = 1 << 2;
const BPF_F_ADJ_ROOM_ENCAP_L4_GRE: i64 = 1 << 3;
const BPF_F_ADJ_ROOM_ENCAP_L4_UDP: i64 = 1 << 4;
const BPF_F_ADJ_ROOM_DECAP_L3_IPV4: i64 = 1 << 7;
const BPF_F_ADJ_ROOM_DECAP_L3_IPV6: i64 = 1 << 8;
const BPF_ADJ_ROOM_ENCAP_L2_MASK: u64 = 0xff;
const BPF_ADJ_ROOM_ENCAP_L2_SHIFT: u32 = 56;
const BPF_F_ADJ_ROOM_ALLOWED_MASK: i64 =
    (0x1ffu64 | (BPF_ADJ_ROOM_ENCAP_L2_MASK << BPF_ADJ_ROOM_ENCAP_L2_SHIFT)) as i64;
const BPF_SKB_ADJUST_ROOM_MAX_LEN_DIFF: i64 = 0xfff;
const BPF_SKB_BYTE_MAX_OFFSET: i64 = i32::MAX as i64;
const BPF_SKB_STORE_BYTES_MAX_LEN: i64 = u32::MAX as i64;
const BPF_SKB_LOAD_BYTES_MAX_LEN: i64 = u32::MAX as i64;
const BPF_SKB_PULL_DATA_MAX_LEN: i64 = u32::MAX as i64;
const BPF_SKB_CHANGE_TAIL_MAX_NEW_LEN: i64 = i32::MAX as i64;
const BPF_SKB_CHANGE_HEAD_MAX_HEAD_ROOM: i64 = i32::MAX as i64;
const BPF_SKB_LOAD_BYTES_RELATIVE_MAX_OFFSET: i64 = 0xffff;
const BPF_SKB_TUNNEL_OPT_MAX_SIZE: i64 = u32::MAX as i64;
const BPF_SKB_VLAN_MAX_U16: i64 = u16::MAX as i64;
const BPF_SKB_XFRM_STATE_MAX_U32: i64 = u32::MAX as i64;
const BPF_SET_HASH_MAX_U32: i64 = u32::MAX as i64;
const BPF_SIGNAL_MAX_U32: i64 = u32::MAX as i64;
const BPF_XDP_BYTE_MAX_OFFSET_OR_LEN: i64 = 0xffff;
const BPF_MSG_DATA_MAX_U32: i64 = u32::MAX as i64;
const BPF_SOCKET_REDIRECT_MAP_KEY_MAX_U32: i64 = u32::MAX as i64;
const BPF_REDIRECT_IFINDEX_MAX_U32: i64 = u32::MAX as i64;
const BPF_REDIRECT_NEIGH_PLEN_MAX_I32: i64 = i32::MAX as i64;
const BPF_LWT_BUFFER_SIZE_MAX_U32: i64 = u32::MAX as i64;
const BPF_LWT_SEG6_OFFSET_MAX_U32: i64 = u32::MAX as i64;
const BPF_FORMAT_SIZE_MAX_U32: i64 = u32::MAX as i64;
const BPF_BUFFER_SIZE_MAX_U32: i64 = u32::MAX as i64;
const BPF_IMA_HASH_SIZE_MAX_U32: i64 = u32::MAX as i64;
const BPF_HDR_OPT_LEN_MAX_U32: i64 = u32::MAX as i64;
const BPF_SOCKET_HELPER_LEN_MAX_I32: i64 = i32::MAX as i64;
const BPF_STRNCMP_SIZE_MAX_U32: i64 = u32::MAX as i64;
const BPF_RINGBUF_DYNPTR_RESERVE_SIZE_MAX_U32: i64 = u32::MAX as i64;
const BPF_SYSCALL_CMD_MAX_I32: i64 = i32::MAX as i64;
const BPF_SYSCALL_ATTR_SIZE_MAX_U32: i64 = u32::MAX as i64;
const BPF_SYSCALL_FD_MAX_U32: i64 = u32::MAX as i64;
const BPF_SYSCALL_NAME_SIZE_MAX_I32: i64 = i32::MAX as i64;
const BPF_BTF_KIND_MAX_U32: i64 = u32::MAX as i64;
const BPF_SET_RETVAL_MIN_I32: i64 = i32::MIN as i64;
const BPF_SET_RETVAL_MAX_I32: i64 = i32::MAX as i64;
const BPF_CHECK_MTU_IFINDEX_MAX_U32: i64 = u32::MAX as i64;
const BPF_CHECK_MTU_LEN_DIFF_MIN_I32: i64 = i32::MIN as i64;
const BPF_CHECK_MTU_LEN_DIFF_MAX_I32: i64 = i32::MAX as i64;
const BPF_SOCKET_LOOKUP_TUPLE_SIZE_MAX_U32: i64 = u32::MAX as i64;
const BPF_SYNCOOKIE_HEADER_LEN_MAX_U32: i64 = u32::MAX as i64;
const BPF_FUNC_ARG_INDEX_MAX_U32: i64 = u32::MAX as i64;
const BPF_TCP_SEND_ACK_RCV_NXT_MAX_U32: i64 = u32::MAX as i64;
const PACKET_OTHERHOST: i64 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScalarArgBitCombinationRequirement {
    pub trigger_mask: i64,
    pub required_mask: i64,
    pub forbidden_mask: i64,
    pub message: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScalarArgConstRequirementWhenArgConst {
    pub arg_idx: usize,
    pub expected: i64,
    pub trigger_arg_idx: usize,
    pub trigger_expected: i64,
    pub message: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScalarArgConstRequirementWhenArgMaskedConst {
    pub arg_idx: usize,
    pub expected: i64,
    pub trigger_arg_idx: usize,
    pub trigger_mask: i64,
    pub trigger_expected: i64,
    pub message: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScalarArgGreaterThanRequirement {
    pub arg_idx: usize,
    pub lower_bound_arg_idx: usize,
    pub message: &'static str,
}

const FIB_LOOKUP_FLAG_COMBINATIONS: &[ScalarArgBitCombinationRequirement] = &[
    ScalarArgBitCombinationRequirement {
        trigger_mask: BPF_FIB_LOOKUP_TBID,
        required_mask: BPF_FIB_LOOKUP_DIRECT,
        forbidden_mask: 0,
        message: "helper 'bpf_fib_lookup' requires BPF_FIB_LOOKUP_TBID to be used with BPF_FIB_LOOKUP_DIRECT",
    },
    ScalarArgBitCombinationRequirement {
        trigger_mask: BPF_FIB_LOOKUP_MARK,
        required_mask: 0,
        forbidden_mask: BPF_FIB_LOOKUP_DIRECT,
        message: "helper 'bpf_fib_lookup' requires BPF_FIB_LOOKUP_MARK not to be used with BPF_FIB_LOOKUP_DIRECT",
    },
];

const SKB_ADJUST_ROOM_FLAG_COMBINATIONS: &[ScalarArgBitCombinationRequirement] = &[
    ScalarArgBitCombinationRequirement {
        trigger_mask: BPF_F_ADJ_ROOM_ENCAP_L3_IPV4,
        required_mask: 0,
        forbidden_mask: BPF_F_ADJ_ROOM_ENCAP_L3_IPV6,
        message: "helper 'bpf_skb_adjust_room' requires at most one BPF_F_ADJ_ROOM_ENCAP_L3_* flag",
    },
    ScalarArgBitCombinationRequirement {
        trigger_mask: BPF_F_ADJ_ROOM_ENCAP_L4_GRE,
        required_mask: 0,
        forbidden_mask: BPF_F_ADJ_ROOM_ENCAP_L4_UDP,
        message: "helper 'bpf_skb_adjust_room' requires at most one BPF_F_ADJ_ROOM_ENCAP_L4_* flag",
    },
    ScalarArgBitCombinationRequirement {
        trigger_mask: BPF_F_ADJ_ROOM_DECAP_L3_IPV4,
        required_mask: 0,
        forbidden_mask: BPF_F_ADJ_ROOM_DECAP_L3_IPV6,
        message: "helper 'bpf_skb_adjust_room' requires at most one BPF_F_ADJ_ROOM_DECAP_L3_* flag",
    },
];

const CSUM_REPLACE_HDR_FIELD_COMBINATIONS: &[ScalarArgBitCombinationRequirement] = &[
    ScalarArgBitCombinationRequirement {
        trigger_mask: BPF_F_HDR_FIELD_SIZE_BIT_0,
        required_mask: 0,
        forbidden_mask: BPF_F_HDR_FIELD_SIZE_BIT_0,
        message: "checksum replacement helpers require BPF_F_HDR_FIELD_MASK size to be 0, 2, or 4",
    },
    ScalarArgBitCombinationRequirement {
        trigger_mask: BPF_F_HDR_FIELD_SIZE_BIT_3,
        required_mask: 0,
        forbidden_mask: BPF_F_HDR_FIELD_SIZE_BIT_3,
        message: "checksum replacement helpers require BPF_F_HDR_FIELD_MASK size to be 0, 2, or 4",
    },
    ScalarArgBitCombinationRequirement {
        trigger_mask: BPF_F_HDR_FIELD_SIZE_BIT_1,
        required_mask: 0,
        forbidden_mask: BPF_F_HDR_FIELD_SIZE_BIT_2,
        message: "checksum replacement helpers require BPF_F_HDR_FIELD_MASK size to be 0, 2, or 4",
    },
];

const CSUM_REPLACE_FROM_REQUIREMENTS: &[ScalarArgConstRequirementWhenArgMaskedConst] = &[
    ScalarArgConstRequirementWhenArgMaskedConst {
        arg_idx: 2,
        expected: 0,
        trigger_arg_idx: 4,
        trigger_mask: BPF_F_HDR_FIELD_MASK,
        trigger_expected: 0,
        message: "checksum replacement helpers require arg2 from to be 0 when BPF_F_HDR_FIELD_MASK size is 0",
    },
];

const MSG_PULL_DATA_ARG_ORDER_REQUIREMENTS: &[ScalarArgGreaterThanRequirement] =
    &[ScalarArgGreaterThanRequirement {
        arg_idx: 2,
        lower_bound_arg_idx: 1,
        message: "helper 'bpf_msg_pull_data' requires arg2 end to be greater than arg1 start",
    }];

const LWT_SEG6_ACTION_PARAM_LEN_REQUIREMENTS: &[ScalarArgConstRequirementWhenArgConst] = &[
    ScalarArgConstRequirementWhenArgConst {
        arg_idx: 3,
        expected: 16,
        trigger_arg_idx: 1,
        trigger_expected: 2,
        message: "helper 'bpf_lwt_seg6_action' requires arg3 param_len = 16 for SEG6_LOCAL_ACTION_END_X",
    },
    ScalarArgConstRequirementWhenArgConst {
        arg_idx: 3,
        expected: 4,
        trigger_arg_idx: 1,
        trigger_expected: 3,
        message: "helper 'bpf_lwt_seg6_action' requires arg3 param_len = 4 for SEG6_LOCAL_ACTION_END_T",
    },
];

pub(crate) fn scalar_range_contains_only_allowed_values(
    min: i64,
    max: i64,
    allowed_values: &[i64],
) -> bool {
    if min > max {
        return false;
    }
    let range_len = i128::from(max) - i128::from(min) + 1;
    if range_len > allowed_values.len() as i128 {
        return false;
    }

    let mut value = min;
    loop {
        if !allowed_values.contains(&value) {
            return false;
        }
        if value == max {
            return true;
        }
        value += 1;
    }
}

pub(crate) fn scalar_range_contains_only_bitmask(min: i64, max: i64, mask: i64) -> bool {
    if min > max {
        return false;
    }
    if let Some(next) = mask.checked_add(1)
        && mask >= 0
        && min >= 0
        && mask & next == 0
    {
        return max <= mask;
    }
    let range_len = i128::from(max) - i128::from(min) + 1;
    if range_len > 4096 {
        return false;
    }

    let mut value = min;
    let mask_bits = mask as u64;
    loop {
        if (value as u64) & !mask_bits != 0 {
            return false;
        }
        if value == max {
            return true;
        }
        value += 1;
    }
}

pub(crate) fn scalar_value_satisfies_bit_combination(
    value: i64,
    requirement: ScalarArgBitCombinationRequirement,
) -> bool {
    let value_bits = value as u64;
    let trigger_mask = requirement.trigger_mask as u64;
    let required_mask = requirement.required_mask as u64;
    let forbidden_mask = requirement.forbidden_mask as u64;
    if value_bits & trigger_mask == 0 {
        return true;
    }
    value_bits & required_mask == required_mask && value_bits & forbidden_mask == 0
}

pub(crate) fn scalar_range_satisfies_bit_combination(
    min: i64,
    max: i64,
    requirement: ScalarArgBitCombinationRequirement,
) -> bool {
    if min > max {
        return false;
    }
    let range_len = i128::from(max) - i128::from(min) + 1;
    if range_len > 4096 {
        return false;
    }

    let mut value = min;
    loop {
        if !scalar_value_satisfies_bit_combination(value, requirement) {
            return false;
        }
        if value == max {
            return true;
        }
        value += 1;
    }
}

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum BpfHelper {
    /// void *bpf_map_lookup_elem(map, key)
    MapLookupElem = 1,
    /// void *bpf_map_lookup_percpu_elem(map, key, cpu)
    MapLookupPercpuElem = 195,
    /// int bpf_map_update_elem(map, key, value, flags)
    MapUpdateElem = 2,
    /// int bpf_map_delete_elem(map, key)
    MapDeleteElem = 3,
    /// int bpf_probe_read(dst, size, src)
    ProbeRead = 4,
    /// long bpf_probe_read_str(dst, size, unsafe_ptr)
    ProbeReadStr = 45,
    /// long bpf_probe_read_user(dst, size, unsafe_ptr)
    ProbeReadUser = 112,
    /// long bpf_probe_read_kernel(dst, size, unsafe_ptr)
    ProbeReadKernel = 113,
    /// long bpf_probe_write_user(user_dst, src, len)
    ProbeWriteUser = 36,
    /// long bpf_copy_from_user(dst, size, user_ptr)
    CopyFromUser = 148,
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
    /// long bpf_skb_change_proto(skb, proto, flags)
    SkbChangeProto = 31,
    /// long bpf_skb_change_type(skb, type)
    SkbChangeType = 32,
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
    /// long bpf_override_return(ctx, rc)
    OverrideReturn = 58,
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
    /// void *bpf_per_cpu_ptr(percpu_ptr, cpu)
    PerCpuPtr = 153,
    /// void *bpf_this_cpu_ptr(percpu_ptr)
    ThisCpuPtr = 154,
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
    /// void *bpf_get_local_storage(map, flags)
    GetLocalStorage = 81,
    /// long bpf_get_ns_current_pid_tgid(dev, ino, nsdata, size)
    GetNsCurrentPidTgid = 120,
    /// u64 bpf_get_current_ancestor_cgroup_id(int ancestor_level)
    GetCurrentAncestorCgroupId = 123,
    /// int bpf_get_retval(void)
    GetRetval = 186,
    /// int bpf_set_retval(int retval)
    SetRetval = 187,
    /// int bpf_get_current_comm(buf, size)
    GetCurrentComm = 16,
    /// u32 bpf_get_cgroup_classid(skb)
    GetCgroupClassid = 17,
    /// long bpf_skb_vlan_push(skb, vlan_proto, vlan_tci)
    SkbVlanPush = 18,
    /// long bpf_skb_vlan_pop(skb)
    SkbVlanPop = 19,
    /// long bpf_skb_get_tunnel_key(skb, key, size, flags)
    SkbGetTunnelKey = 20,
    /// long bpf_skb_set_tunnel_key(skb, key, size, flags)
    SkbSetTunnelKey = 21,
    /// u64 bpf_perf_event_read(map, flags)
    PerfEventRead = 22,
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
    /// u64 bpf_skb_cgroup_classid(skb)
    SkbCgroupClassid = 151,
    /// long bpf_ima_file_hash(file, dst, size)
    ImaFileHash = 193,
    /// long bpf_copy_from_user_task(dst, size, user_ptr, task, flags)
    CopyFromUserTask = 191,
    /// long bpf_snprintf_btf(str, str_size, ptr, btf_ptr_size, flags)
    SnprintfBtf = 149,
    /// long bpf_seq_printf_btf(seq, ptr, ptr_size, flags)
    SeqPrintfBtf = 150,
    /// long bpf_setsockopt(ctx, level, optname, optval, optlen)
    SetSockOpt = 49,
    /// long bpf_sk_redirect_map(skb, map, key, flags)
    SkRedirectMap = 52,
    /// long bpf_sock_map_update(skops, map, key, flags)
    SockMapUpdate = 53,
    /// long bpf_getsockopt(ctx, level, optname, optval, optlen)
    GetSockOpt = 57,
    /// long bpf_perf_prog_read_value(ctx, buf, buf_size)
    PerfProgReadValue = 56,
    /// long bpf_perf_event_read_value(map, flags, buf, buf_size)
    PerfEventReadValue = 55,
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
    /// long bpf_sk_select_reuseport(ctx, map, key, flags)
    SkSelectReuseport = 82,
    /// u64 bpf_ktime_get_boot_ns(void)
    KtimeGetBootNs = 125,
    /// long bpf_seq_printf(seq, fmt, fmt_size, data, data_len)
    SeqPrintf = 126,
    /// long bpf_seq_write(seq, data, len)
    SeqWrite = 127,
    /// u64 bpf_ktime_get_coarse_ns(void)
    KtimeGetCoarseNs = 160,
    /// long bpf_check_mtu(ctx, ifindex, mtu_len, len_diff, flags)
    CheckMtu = 163,
    /// long bpf_for_each_map_elem(map, callback_fn, callback_ctx, flags)
    ForEachMapElem = 164,
    /// u64 bpf_ktime_get_tai_ns(void)
    KtimeGetTaiNs = 208,
    /// u64 bpf_jiffies64(void)
    Jiffies64 = 118,
    /// long bpf_read_branch_records(ctx, buf, size, flags)
    ReadBranchRecords = 119,
    /// u64 bpf_get_func_ip(void *ctx)
    GetFuncIp = 173,
    /// u64 bpf_get_attach_cookie(void *ctx)
    GetAttachCookie = 174,
    /// long bpf_get_branch_snapshot(entries, size, flags)
    GetBranchSnapshot = 176,
    /// long bpf_trace_vprintk(fmt, fmt_size, data, data_len)
    TraceVPrintk = 177,
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
    /// long bpf_get_stack(ctx, buf, size, flags)
    GetStack = 67,
    /// long bpf_d_path(path, buf, size)
    DPath = 147,
    /// s64 bpf_csum_diff(from, from_size, to, to_size, seed)
    CsumDiff = 28,
    /// long bpf_skb_get_tunnel_opt(skb, opt, size)
    SkbGetTunnelOpt = 29,
    /// long bpf_skb_set_tunnel_opt(skb, opt, size)
    SkbSetTunnelOpt = 30,
    /// long bpf_fib_lookup(ctx, params, plen, flags)
    FibLookup = 69,
    /// long bpf_lwt_push_encap(skb, type, hdr, len)
    LwtPushEncap = 73,
    /// long bpf_lwt_seg6_store_bytes(skb, offset, from, len)
    LwtSeg6StoreBytes = 74,
    /// long bpf_lwt_seg6_adjust_srh(skb, offset, delta)
    LwtSeg6AdjustSrh = 75,
    /// long bpf_lwt_seg6_action(skb, action, param, param_len)
    LwtSeg6Action = 76,
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
    /// long bpf_spin_lock(lock)
    SpinLock = 93,
    /// long bpf_spin_unlock(lock)
    SpinUnlock = 94,
    /// long bpf_xdp_adjust_tail(xdp_md, delta)
    XdpAdjustTail = 65,
    /// long bpf_skb_get_xfrm_state(skb, index, xfrm_state, size, flags)
    SkbGetXfrmState = 66,
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
    /// long bpf_skb_ecn_set_ce(skb)
    SkbEcnSetCe = 97,
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
    /// long bpf_strtol(buf, buf_len, flags, res)
    Strtol = 105,
    /// long bpf_strtoul(buf, buf_len, flags, res)
    Strtoul = 106,
    /// long bpf_strncmp(s1, s1_sz, s2)
    Strncmp = 182,
    /// void *bpf_sk_storage_get(map, sk, value, flags)
    SkStorageGet = 107,
    /// long bpf_sk_storage_delete(map, sk)
    SkStorageDelete = 108,
    /// s64 bpf_tcp_gen_syncookie(sk, iph, iph_len, th, th_len)
    TcpGenSyncookie = 110,
    /// s64 bpf_tcp_raw_gen_syncookie_ipv4(iph, th, th_len)
    TcpRawGenSyncookieIpv4 = 204,
    /// s64 bpf_tcp_raw_gen_syncookie_ipv6(iph, th, th_len)
    TcpRawGenSyncookieIpv6 = 205,
    /// long bpf_tcp_raw_check_syncookie_ipv4(iph, th)
    TcpRawCheckSyncookieIpv4 = 206,
    /// long bpf_tcp_raw_check_syncookie_ipv6(iph, th)
    TcpRawCheckSyncookieIpv6 = 207,
    /// long bpf_send_signal(sig)
    SendSignal = 109,
    /// long bpf_tcp_send_ack(tp, rcv_nxt)
    TcpSendAck = 116,
    /// long bpf_send_signal_thread(sig)
    SendSignalThread = 117,
    /// long bpf_skb_output(ctx, map, flags, data, size)
    SkbOutput = 111,
    /// long bpf_xdp_output(ctx, map, flags, data, size)
    XdpOutput = 121,
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
    /// long bpf_bprm_opts_set(bprm, flags)
    BprmOptsSet = 159,
    /// long bpf_ima_inode_hash(inode, dst, size)
    ImaInodeHash = 161,
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
    /// struct mptcp_sock *bpf_skc_to_mptcp_sock(sk)
    SkcToMptcpSock = 196,
    /// long bpf_get_task_stack(task, buf, size, flags)
    GetTaskStack = 141,
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
    /// long bpf_snprintf(str, str_size, fmt, data, data_len)
    Snprintf = 165,
    /// long bpf_sys_bpf(cmd, attr, attr_size)
    SysBpf = 166,
    /// long bpf_btf_find_by_name_kind(name, name_sz, kind, flags)
    BtfFindByNameKind = 167,
    /// long bpf_sys_close(fd)
    SysClose = 168,
    /// long bpf_timer_init(timer, map, flags)
    TimerInit = 169,
    /// long bpf_timer_set_callback(timer, callback_fn)
    TimerSetCallback = 170,
    /// long bpf_timer_start(timer, nsecs, flags)
    TimerStart = 171,
    /// long bpf_timer_cancel(timer)
    TimerCancel = 172,
    /// struct pt_regs *bpf_task_pt_regs(task)
    TaskPtRegs = 175,
    /// long bpf_kallsyms_lookup_name(name, name_sz, flags, res)
    KallsymsLookupName = 179,
    /// long bpf_find_vma(task, addr, callback_fn, callback_ctx, flags)
    FindVma = 180,
    /// long bpf_loop(nr_loops, callback_fn, callback_ctx, flags)
    BpfLoop = 181,
    /// long bpf_get_func_arg(ctx, n, value)
    GetFuncArg = 183,
    /// long bpf_get_func_ret(ctx, value)
    GetFuncRet = 184,
    /// long bpf_get_func_arg_cnt(ctx)
    GetFuncArgCnt = 185,
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
    /// long bpf_dynptr_from_mem(data, size, flags, ptr)
    DynptrFromMem = 197,
    /// long bpf_ringbuf_reserve_dynptr(ringbuf, size, flags, ptr)
    RingbufReserveDynptr = 198,
    /// void bpf_ringbuf_submit_dynptr(ptr, flags)
    RingbufSubmitDynptr = 199,
    /// void bpf_ringbuf_discard_dynptr(ptr, flags)
    RingbufDiscardDynptr = 200,
    /// long bpf_dynptr_read(dst, len, src, offset, flags)
    DynptrRead = 201,
    /// long bpf_dynptr_write(dst, offset, src, len, flags)
    DynptrWrite = 202,
    /// void *bpf_dynptr_data(ptr, offset, len)
    DynptrData = 203,
    /// long bpf_user_ringbuf_drain(map, callback_fn, ctx, flags)
    UserRingbufDrain = 209,
    /// long bpf_probe_read_user_str(dst, size, unsafe_ptr)
    ProbeReadUserStr = 114,
    /// long bpf_probe_read_kernel_str(dst, size, unsafe_ptr)
    ProbeReadKernelStr = 115,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperDynptrArgRole {
    In,
    Out,
    RingbufReservationOut,
    RingbufReservationRelease,
}

impl BpfHelper {
    pub const fn name(self) -> &'static str {
        match self {
            BpfHelper::MapLookupElem => "bpf_map_lookup_elem",
            BpfHelper::MapLookupPercpuElem => "bpf_map_lookup_percpu_elem",
            BpfHelper::MapUpdateElem => "bpf_map_update_elem",
            BpfHelper::MapDeleteElem => "bpf_map_delete_elem",
            BpfHelper::ProbeRead => "bpf_probe_read",
            BpfHelper::ProbeReadStr => "bpf_probe_read_str",
            BpfHelper::ProbeReadUser => "bpf_probe_read_user",
            BpfHelper::ProbeReadKernel => "bpf_probe_read_kernel",
            BpfHelper::ProbeWriteUser => "bpf_probe_write_user",
            BpfHelper::CopyFromUser => "bpf_copy_from_user",
            BpfHelper::KtimeGetNs => "bpf_ktime_get_ns",
            BpfHelper::TracePrintk => "bpf_trace_printk",
            BpfHelper::GetPrandomU32 => "bpf_get_prandom_u32",
            BpfHelper::GetSmpProcessorId => "bpf_get_smp_processor_id",
            BpfHelper::SkbStoreBytes => "bpf_skb_store_bytes",
            BpfHelper::L3CsumReplace => "bpf_l3_csum_replace",
            BpfHelper::L4CsumReplace => "bpf_l4_csum_replace",
            BpfHelper::SkbChangeProto => "bpf_skb_change_proto",
            BpfHelper::SkbChangeType => "bpf_skb_change_type",
            BpfHelper::SkbUnderCgroup => "bpf_skb_under_cgroup",
            BpfHelper::SkbChangeTail => "bpf_skb_change_tail",
            BpfHelper::CurrentTaskUnderCgroup => "bpf_current_task_under_cgroup",
            BpfHelper::SkbPullData => "bpf_skb_pull_data",
            BpfHelper::GetHashRecalc => "bpf_get_hash_recalc",
            BpfHelper::GetCurrentTask => "bpf_get_current_task",
            BpfHelper::OverrideReturn => "bpf_override_return",
            BpfHelper::CsumUpdate => "bpf_csum_update",
            BpfHelper::SetHashInvalid => "bpf_set_hash_invalid",
            BpfHelper::GetNumaNodeId => "bpf_get_numa_node_id",
            BpfHelper::SetHash => "bpf_set_hash",
            BpfHelper::SkbChangeHead => "bpf_skb_change_head",
            BpfHelper::XdpAdjustHead => "bpf_xdp_adjust_head",
            BpfHelper::Redirect => "bpf_redirect",
            BpfHelper::RedirectMap => "bpf_redirect_map",
            BpfHelper::RedirectNeigh => "bpf_redirect_neigh",
            BpfHelper::PerCpuPtr => "bpf_per_cpu_ptr",
            BpfHelper::ThisCpuPtr => "bpf_this_cpu_ptr",
            BpfHelper::RedirectPeer => "bpf_redirect_peer",
            BpfHelper::XdpAdjustMeta => "bpf_xdp_adjust_meta",
            BpfHelper::TailCall => "bpf_tail_call",
            BpfHelper::CloneRedirect => "bpf_clone_redirect",
            BpfHelper::GetCurrentPidTgid => "bpf_get_current_pid_tgid",
            BpfHelper::GetCurrentUidGid => "bpf_get_current_uid_gid",
            BpfHelper::GetCurrentCgroupId => "bpf_get_current_cgroup_id",
            BpfHelper::GetLocalStorage => "bpf_get_local_storage",
            BpfHelper::GetNsCurrentPidTgid => "bpf_get_ns_current_pid_tgid",
            BpfHelper::GetCurrentAncestorCgroupId => "bpf_get_current_ancestor_cgroup_id",
            BpfHelper::GetRetval => "bpf_get_retval",
            BpfHelper::SetRetval => "bpf_set_retval",
            BpfHelper::GetCurrentComm => "bpf_get_current_comm",
            BpfHelper::GetCgroupClassid => "bpf_get_cgroup_classid",
            BpfHelper::SkbVlanPush => "bpf_skb_vlan_push",
            BpfHelper::SkbVlanPop => "bpf_skb_vlan_pop",
            BpfHelper::SkbGetTunnelKey => "bpf_skb_get_tunnel_key",
            BpfHelper::SkbSetTunnelKey => "bpf_skb_set_tunnel_key",
            BpfHelper::PerfEventRead => "bpf_perf_event_read",
            BpfHelper::GetRouteRealm => "bpf_get_route_realm",
            BpfHelper::MsgApplyBytes => "bpf_msg_apply_bytes",
            BpfHelper::MsgCorkBytes => "bpf_msg_cork_bytes",
            BpfHelper::MsgPullData => "bpf_msg_pull_data",
            BpfHelper::Bind => "bpf_bind",
            BpfHelper::GetSocketCookie => "bpf_get_socket_cookie",
            BpfHelper::GetSocketUid => "bpf_get_socket_uid",
            BpfHelper::SkbAdjustRoom => "bpf_skb_adjust_room",
            BpfHelper::SkbSetTstamp => "bpf_skb_set_tstamp",
            BpfHelper::SkbCgroupClassid => "bpf_skb_cgroup_classid",
            BpfHelper::ImaFileHash => "bpf_ima_file_hash",
            BpfHelper::CopyFromUserTask => "bpf_copy_from_user_task",
            BpfHelper::SnprintfBtf => "bpf_snprintf_btf",
            BpfHelper::SeqPrintfBtf => "bpf_seq_printf_btf",
            BpfHelper::SetSockOpt => "bpf_setsockopt",
            BpfHelper::SkRedirectMap => "bpf_sk_redirect_map",
            BpfHelper::SockMapUpdate => "bpf_sock_map_update",
            BpfHelper::GetSockOpt => "bpf_getsockopt",
            BpfHelper::PerfProgReadValue => "bpf_perf_prog_read_value",
            BpfHelper::PerfEventReadValue => "bpf_perf_event_read_value",
            BpfHelper::SockOpsCbFlagsSet => "bpf_sock_ops_cb_flags_set",
            BpfHelper::MsgRedirectMap => "bpf_msg_redirect_map",
            BpfHelper::GetNetnsCookie => "bpf_get_netns_cookie",
            BpfHelper::SkbCgroupId => "bpf_skb_cgroup_id",
            BpfHelper::SkbAncestorCgroupId => "bpf_skb_ancestor_cgroup_id",
            BpfHelper::SockHashUpdate => "bpf_sock_hash_update",
            BpfHelper::MsgRedirectHash => "bpf_msg_redirect_hash",
            BpfHelper::SkRedirectHash => "bpf_sk_redirect_hash",
            BpfHelper::SkSelectReuseport => "bpf_sk_select_reuseport",
            BpfHelper::KtimeGetBootNs => "bpf_ktime_get_boot_ns",
            BpfHelper::SeqPrintf => "bpf_seq_printf",
            BpfHelper::SeqWrite => "bpf_seq_write",
            BpfHelper::KtimeGetCoarseNs => "bpf_ktime_get_coarse_ns",
            BpfHelper::CheckMtu => "bpf_check_mtu",
            BpfHelper::ForEachMapElem => "bpf_for_each_map_elem",
            BpfHelper::KtimeGetTaiNs => "bpf_ktime_get_tai_ns",
            BpfHelper::Jiffies64 => "bpf_jiffies64",
            BpfHelper::ReadBranchRecords => "bpf_read_branch_records",
            BpfHelper::GetFuncIp => "bpf_get_func_ip",
            BpfHelper::GetAttachCookie => "bpf_get_attach_cookie",
            BpfHelper::GetBranchSnapshot => "bpf_get_branch_snapshot",
            BpfHelper::TraceVPrintk => "bpf_trace_vprintk",
            BpfHelper::LoadHdrOpt => "bpf_load_hdr_opt",
            BpfHelper::StoreHdrOpt => "bpf_store_hdr_opt",
            BpfHelper::ReserveHdrOpt => "bpf_reserve_hdr_opt",
            BpfHelper::PerfEventOutput => "bpf_perf_event_output",
            BpfHelper::SkbLoadBytes => "bpf_skb_load_bytes",
            BpfHelper::GetStackId => "bpf_get_stackid",
            BpfHelper::GetStack => "bpf_get_stack",
            BpfHelper::DPath => "bpf_d_path",
            BpfHelper::CsumDiff => "bpf_csum_diff",
            BpfHelper::SkbGetTunnelOpt => "bpf_skb_get_tunnel_opt",
            BpfHelper::SkbSetTunnelOpt => "bpf_skb_set_tunnel_opt",
            BpfHelper::FibLookup => "bpf_fib_lookup",
            BpfHelper::LwtPushEncap => "bpf_lwt_push_encap",
            BpfHelper::LwtSeg6StoreBytes => "bpf_lwt_seg6_store_bytes",
            BpfHelper::LwtSeg6AdjustSrh => "bpf_lwt_seg6_adjust_srh",
            BpfHelper::LwtSeg6Action => "bpf_lwt_seg6_action",
            BpfHelper::SkbLoadBytesRelative => "bpf_skb_load_bytes_relative",
            BpfHelper::SkLookupTcp => "bpf_sk_lookup_tcp",
            BpfHelper::SkLookupUdp => "bpf_sk_lookup_udp",
            BpfHelper::SkRelease => "bpf_sk_release",
            BpfHelper::MapPushElem => "bpf_map_push_elem",
            BpfHelper::MapPopElem => "bpf_map_pop_elem",
            BpfHelper::MapPeekElem => "bpf_map_peek_elem",
            BpfHelper::MsgPushData => "bpf_msg_push_data",
            BpfHelper::MsgPopData => "bpf_msg_pop_data",
            BpfHelper::SpinLock => "bpf_spin_lock",
            BpfHelper::SpinUnlock => "bpf_spin_unlock",
            BpfHelper::XdpAdjustTail => "bpf_xdp_adjust_tail",
            BpfHelper::SkbGetXfrmState => "bpf_skb_get_xfrm_state",
            BpfHelper::XdpGetBuffLen => "bpf_xdp_get_buff_len",
            BpfHelper::XdpLoadBytes => "bpf_xdp_load_bytes",
            BpfHelper::XdpStoreBytes => "bpf_xdp_store_bytes",
            BpfHelper::RcRepeat => "bpf_rc_repeat",
            BpfHelper::RcKeydown => "bpf_rc_keydown",
            BpfHelper::RcPointerRel => "bpf_rc_pointer_rel",
            BpfHelper::SkFullsock => "bpf_sk_fullsock",
            BpfHelper::TcpSock => "bpf_tcp_sock",
            BpfHelper::SkbEcnSetCe => "bpf_skb_ecn_set_ce",
            BpfHelper::GetListenerSock => "bpf_get_listener_sock",
            BpfHelper::SkcLookupTcp => "bpf_skc_lookup_tcp",
            BpfHelper::TcpCheckSyncookie => "bpf_tcp_check_syncookie",
            BpfHelper::SysctlGetName => "bpf_sysctl_get_name",
            BpfHelper::SysctlGetCurrentValue => "bpf_sysctl_get_current_value",
            BpfHelper::SysctlGetNewValue => "bpf_sysctl_get_new_value",
            BpfHelper::SysctlSetNewValue => "bpf_sysctl_set_new_value",
            BpfHelper::Strtol => "bpf_strtol",
            BpfHelper::Strtoul => "bpf_strtoul",
            BpfHelper::Strncmp => "bpf_strncmp",
            BpfHelper::SkStorageGet => "bpf_sk_storage_get",
            BpfHelper::SkStorageDelete => "bpf_sk_storage_delete",
            BpfHelper::TcpGenSyncookie => "bpf_tcp_gen_syncookie",
            BpfHelper::TcpRawGenSyncookieIpv4 => "bpf_tcp_raw_gen_syncookie_ipv4",
            BpfHelper::TcpRawGenSyncookieIpv6 => "bpf_tcp_raw_gen_syncookie_ipv6",
            BpfHelper::TcpRawCheckSyncookieIpv4 => "bpf_tcp_raw_check_syncookie_ipv4",
            BpfHelper::TcpRawCheckSyncookieIpv6 => "bpf_tcp_raw_check_syncookie_ipv6",
            BpfHelper::SendSignal => "bpf_send_signal",
            BpfHelper::TcpSendAck => "bpf_tcp_send_ack",
            BpfHelper::SendSignalThread => "bpf_send_signal_thread",
            BpfHelper::SkbOutput => "bpf_skb_output",
            BpfHelper::XdpOutput => "bpf_xdp_output",
            BpfHelper::SkAssign => "bpf_sk_assign",
            BpfHelper::SkCgroupId => "bpf_sk_cgroup_id",
            BpfHelper::SkAncestorCgroupId => "bpf_sk_ancestor_cgroup_id",
            BpfHelper::TaskStorageGet => "bpf_task_storage_get",
            BpfHelper::TaskStorageDelete => "bpf_task_storage_delete",
            BpfHelper::GetCurrentTaskBtf => "bpf_get_current_task_btf",
            BpfHelper::BprmOptsSet => "bpf_bprm_opts_set",
            BpfHelper::ImaInodeHash => "bpf_ima_inode_hash",
            BpfHelper::SkcToTcp6Sock => "bpf_skc_to_tcp6_sock",
            BpfHelper::SkcToTcpSock => "bpf_skc_to_tcp_sock",
            BpfHelper::SkcToTcpTimewaitSock => "bpf_skc_to_tcp_timewait_sock",
            BpfHelper::SkcToTcpRequestSock => "bpf_skc_to_tcp_request_sock",
            BpfHelper::SkcToUdp6Sock => "bpf_skc_to_udp6_sock",
            BpfHelper::SkcToMptcpSock => "bpf_skc_to_mptcp_sock",
            BpfHelper::GetTaskStack => "bpf_get_task_stack",
            BpfHelper::SkcToUnixSock => "bpf_skc_to_unix_sock",
            BpfHelper::InodeStorageGet => "bpf_inode_storage_get",
            BpfHelper::InodeStorageDelete => "bpf_inode_storage_delete",
            BpfHelper::CgrpStorageGet => "bpf_cgrp_storage_get",
            BpfHelper::CgrpStorageDelete => "bpf_cgrp_storage_delete",
            BpfHelper::SockFromFile => "bpf_sock_from_file",
            BpfHelper::Snprintf => "bpf_snprintf",
            BpfHelper::SysBpf => "bpf_sys_bpf",
            BpfHelper::BtfFindByNameKind => "bpf_btf_find_by_name_kind",
            BpfHelper::SysClose => "bpf_sys_close",
            BpfHelper::TimerInit => "bpf_timer_init",
            BpfHelper::TimerSetCallback => "bpf_timer_set_callback",
            BpfHelper::TimerStart => "bpf_timer_start",
            BpfHelper::TimerCancel => "bpf_timer_cancel",
            BpfHelper::TaskPtRegs => "bpf_task_pt_regs",
            BpfHelper::KallsymsLookupName => "bpf_kallsyms_lookup_name",
            BpfHelper::FindVma => "bpf_find_vma",
            BpfHelper::BpfLoop => "bpf_loop",
            BpfHelper::GetFuncArg => "bpf_get_func_arg",
            BpfHelper::GetFuncRet => "bpf_get_func_ret",
            BpfHelper::GetFuncArgCnt => "bpf_get_func_arg_cnt",
            BpfHelper::RingbufOutput => "bpf_ringbuf_output",
            BpfHelper::RingbufReserve => "bpf_ringbuf_reserve",
            BpfHelper::RingbufSubmit => "bpf_ringbuf_submit",
            BpfHelper::RingbufDiscard => "bpf_ringbuf_discard",
            BpfHelper::RingbufQuery => "bpf_ringbuf_query",
            BpfHelper::CsumLevel => "bpf_csum_level",
            BpfHelper::KptrXchg => "bpf_kptr_xchg",
            BpfHelper::DynptrFromMem => "bpf_dynptr_from_mem",
            BpfHelper::RingbufReserveDynptr => "bpf_ringbuf_reserve_dynptr",
            BpfHelper::RingbufSubmitDynptr => "bpf_ringbuf_submit_dynptr",
            BpfHelper::RingbufDiscardDynptr => "bpf_ringbuf_discard_dynptr",
            BpfHelper::DynptrRead => "bpf_dynptr_read",
            BpfHelper::DynptrWrite => "bpf_dynptr_write",
            BpfHelper::DynptrData => "bpf_dynptr_data",
            BpfHelper::UserRingbufDrain => "bpf_user_ringbuf_drain",
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
            "map_lookup_percpu_elem" => Some(Self::MapLookupPercpuElem),
            "map_update_elem" => Some(Self::MapUpdateElem),
            "map_delete_elem" => Some(Self::MapDeleteElem),
            "probe_read" => Some(Self::ProbeRead),
            "probe_read_str" => Some(Self::ProbeReadStr),
            "probe_read_user" => Some(Self::ProbeReadUser),
            "probe_read_kernel" => Some(Self::ProbeReadKernel),
            "probe_write_user" => Some(Self::ProbeWriteUser),
            "copy_from_user" => Some(Self::CopyFromUser),
            "ktime_get_ns" => Some(Self::KtimeGetNs),
            "trace_printk" => Some(Self::TracePrintk),
            "get_prandom_u32" => Some(Self::GetPrandomU32),
            "get_smp_processor_id" => Some(Self::GetSmpProcessorId),
            "skb_store_bytes" => Some(Self::SkbStoreBytes),
            "l3_csum_replace" => Some(Self::L3CsumReplace),
            "l4_csum_replace" => Some(Self::L4CsumReplace),
            "skb_change_proto" => Some(Self::SkbChangeProto),
            "skb_change_type" => Some(Self::SkbChangeType),
            "skb_under_cgroup" => Some(Self::SkbUnderCgroup),
            "skb_change_tail" => Some(Self::SkbChangeTail),
            "current_task_under_cgroup" => Some(Self::CurrentTaskUnderCgroup),
            "skb_pull_data" => Some(Self::SkbPullData),
            "get_hash_recalc" => Some(Self::GetHashRecalc),
            "get_current_task" => Some(Self::GetCurrentTask),
            "override_return" => Some(Self::OverrideReturn),
            "csum_update" => Some(Self::CsumUpdate),
            "set_hash_invalid" => Some(Self::SetHashInvalid),
            "get_numa_node_id" => Some(Self::GetNumaNodeId),
            "set_hash" => Some(Self::SetHash),
            "skb_change_head" => Some(Self::SkbChangeHead),
            "xdp_adjust_head" => Some(Self::XdpAdjustHead),
            "redirect" => Some(Self::Redirect),
            "redirect_map" => Some(Self::RedirectMap),
            "redirect_neigh" => Some(Self::RedirectNeigh),
            "per_cpu_ptr" => Some(Self::PerCpuPtr),
            "this_cpu_ptr" => Some(Self::ThisCpuPtr),
            "redirect_peer" => Some(Self::RedirectPeer),
            "xdp_adjust_meta" => Some(Self::XdpAdjustMeta),
            "tail_call" => Some(Self::TailCall),
            "clone_redirect" => Some(Self::CloneRedirect),
            "get_current_pid_tgid" => Some(Self::GetCurrentPidTgid),
            "get_current_uid_gid" => Some(Self::GetCurrentUidGid),
            "get_current_cgroup_id" => Some(Self::GetCurrentCgroupId),
            "get_local_storage" => Some(Self::GetLocalStorage),
            "get_ns_current_pid_tgid" => Some(Self::GetNsCurrentPidTgid),
            "get_current_ancestor_cgroup_id" => Some(Self::GetCurrentAncestorCgroupId),
            "get_retval" => Some(Self::GetRetval),
            "set_retval" => Some(Self::SetRetval),
            "get_current_comm" => Some(Self::GetCurrentComm),
            "get_cgroup_classid" => Some(Self::GetCgroupClassid),
            "skb_vlan_push" => Some(Self::SkbVlanPush),
            "skb_vlan_pop" => Some(Self::SkbVlanPop),
            "skb_get_tunnel_key" => Some(Self::SkbGetTunnelKey),
            "skb_set_tunnel_key" => Some(Self::SkbSetTunnelKey),
            "perf_event_read" => Some(Self::PerfEventRead),
            "get_route_realm" => Some(Self::GetRouteRealm),
            "msg_apply_bytes" => Some(Self::MsgApplyBytes),
            "msg_cork_bytes" => Some(Self::MsgCorkBytes),
            "msg_pull_data" => Some(Self::MsgPullData),
            "bind" => Some(Self::Bind),
            "get_socket_cookie" => Some(Self::GetSocketCookie),
            "get_socket_uid" => Some(Self::GetSocketUid),
            "skb_adjust_room" => Some(Self::SkbAdjustRoom),
            "skb_set_tstamp" => Some(Self::SkbSetTstamp),
            "skb_cgroup_classid" => Some(Self::SkbCgroupClassid),
            "ima_file_hash" => Some(Self::ImaFileHash),
            "copy_from_user_task" => Some(Self::CopyFromUserTask),
            "snprintf_btf" => Some(Self::SnprintfBtf),
            "seq_printf_btf" => Some(Self::SeqPrintfBtf),
            "setsockopt" => Some(Self::SetSockOpt),
            "sk_redirect_map" => Some(Self::SkRedirectMap),
            "sock_map_update" => Some(Self::SockMapUpdate),
            "getsockopt" => Some(Self::GetSockOpt),
            "perf_prog_read_value" => Some(Self::PerfProgReadValue),
            "perf_event_read_value" => Some(Self::PerfEventReadValue),
            "sock_ops_cb_flags_set" => Some(Self::SockOpsCbFlagsSet),
            "msg_redirect_map" => Some(Self::MsgRedirectMap),
            "get_netns_cookie" => Some(Self::GetNetnsCookie),
            "skb_cgroup_id" => Some(Self::SkbCgroupId),
            "skb_ancestor_cgroup_id" => Some(Self::SkbAncestorCgroupId),
            "sock_hash_update" => Some(Self::SockHashUpdate),
            "msg_redirect_hash" => Some(Self::MsgRedirectHash),
            "sk_redirect_hash" => Some(Self::SkRedirectHash),
            "sk_select_reuseport" => Some(Self::SkSelectReuseport),
            "ktime_get_boot_ns" => Some(Self::KtimeGetBootNs),
            "seq_printf" => Some(Self::SeqPrintf),
            "seq_write" => Some(Self::SeqWrite),
            "ktime_get_coarse_ns" => Some(Self::KtimeGetCoarseNs),
            "check_mtu" => Some(Self::CheckMtu),
            "for_each_map_elem" => Some(Self::ForEachMapElem),
            "ktime_get_tai_ns" => Some(Self::KtimeGetTaiNs),
            "jiffies64" => Some(Self::Jiffies64),
            "read_branch_records" => Some(Self::ReadBranchRecords),
            "get_func_ip" => Some(Self::GetFuncIp),
            "get_attach_cookie" => Some(Self::GetAttachCookie),
            "get_branch_snapshot" => Some(Self::GetBranchSnapshot),
            "trace_vprintk" => Some(Self::TraceVPrintk),
            "load_hdr_opt" => Some(Self::LoadHdrOpt),
            "store_hdr_opt" => Some(Self::StoreHdrOpt),
            "reserve_hdr_opt" => Some(Self::ReserveHdrOpt),
            "perf_event_output" => Some(Self::PerfEventOutput),
            "skb_load_bytes" => Some(Self::SkbLoadBytes),
            "get_stackid" => Some(Self::GetStackId),
            "get_stack" => Some(Self::GetStack),
            "d_path" => Some(Self::DPath),
            "csum_diff" => Some(Self::CsumDiff),
            "skb_get_tunnel_opt" => Some(Self::SkbGetTunnelOpt),
            "skb_set_tunnel_opt" => Some(Self::SkbSetTunnelOpt),
            "fib_lookup" => Some(Self::FibLookup),
            "lwt_push_encap" => Some(Self::LwtPushEncap),
            "lwt_seg6_store_bytes" => Some(Self::LwtSeg6StoreBytes),
            "lwt_seg6_adjust_srh" => Some(Self::LwtSeg6AdjustSrh),
            "lwt_seg6_action" => Some(Self::LwtSeg6Action),
            "skb_load_bytes_relative" => Some(Self::SkbLoadBytesRelative),
            "sk_lookup_tcp" => Some(Self::SkLookupTcp),
            "sk_lookup_udp" => Some(Self::SkLookupUdp),
            "sk_release" => Some(Self::SkRelease),
            "map_push_elem" => Some(Self::MapPushElem),
            "map_pop_elem" => Some(Self::MapPopElem),
            "map_peek_elem" => Some(Self::MapPeekElem),
            "msg_push_data" => Some(Self::MsgPushData),
            "msg_pop_data" => Some(Self::MsgPopData),
            "spin_lock" => Some(Self::SpinLock),
            "spin_unlock" => Some(Self::SpinUnlock),
            "xdp_adjust_tail" => Some(Self::XdpAdjustTail),
            "skb_get_xfrm_state" => Some(Self::SkbGetXfrmState),
            "xdp_get_buff_len" => Some(Self::XdpGetBuffLen),
            "xdp_load_bytes" => Some(Self::XdpLoadBytes),
            "xdp_store_bytes" => Some(Self::XdpStoreBytes),
            "rc_repeat" => Some(Self::RcRepeat),
            "rc_keydown" => Some(Self::RcKeydown),
            "rc_pointer_rel" => Some(Self::RcPointerRel),
            "sk_fullsock" => Some(Self::SkFullsock),
            "tcp_sock" => Some(Self::TcpSock),
            "skb_ecn_set_ce" => Some(Self::SkbEcnSetCe),
            "get_listener_sock" => Some(Self::GetListenerSock),
            "skc_lookup_tcp" => Some(Self::SkcLookupTcp),
            "tcp_check_syncookie" => Some(Self::TcpCheckSyncookie),
            "sysctl_get_name" => Some(Self::SysctlGetName),
            "sysctl_get_current_value" => Some(Self::SysctlGetCurrentValue),
            "sysctl_get_new_value" => Some(Self::SysctlGetNewValue),
            "sysctl_set_new_value" => Some(Self::SysctlSetNewValue),
            "strtol" => Some(Self::Strtol),
            "strtoul" => Some(Self::Strtoul),
            "strncmp" => Some(Self::Strncmp),
            "sk_storage_get" => Some(Self::SkStorageGet),
            "sk_storage_delete" => Some(Self::SkStorageDelete),
            "tcp_gen_syncookie" => Some(Self::TcpGenSyncookie),
            "tcp_raw_gen_syncookie_ipv4" => Some(Self::TcpRawGenSyncookieIpv4),
            "tcp_raw_gen_syncookie_ipv6" => Some(Self::TcpRawGenSyncookieIpv6),
            "tcp_raw_check_syncookie_ipv4" => Some(Self::TcpRawCheckSyncookieIpv4),
            "tcp_raw_check_syncookie_ipv6" => Some(Self::TcpRawCheckSyncookieIpv6),
            "send_signal" => Some(Self::SendSignal),
            "tcp_send_ack" => Some(Self::TcpSendAck),
            "send_signal_thread" => Some(Self::SendSignalThread),
            "skb_output" => Some(Self::SkbOutput),
            "xdp_output" => Some(Self::XdpOutput),
            "sk_assign" => Some(Self::SkAssign),
            "sk_cgroup_id" => Some(Self::SkCgroupId),
            "sk_ancestor_cgroup_id" => Some(Self::SkAncestorCgroupId),
            "task_storage_get" => Some(Self::TaskStorageGet),
            "task_storage_delete" => Some(Self::TaskStorageDelete),
            "get_current_task_btf" => Some(Self::GetCurrentTaskBtf),
            "bprm_opts_set" => Some(Self::BprmOptsSet),
            "ima_inode_hash" => Some(Self::ImaInodeHash),
            "skc_to_tcp6_sock" => Some(Self::SkcToTcp6Sock),
            "skc_to_tcp_sock" => Some(Self::SkcToTcpSock),
            "skc_to_tcp_timewait_sock" => Some(Self::SkcToTcpTimewaitSock),
            "skc_to_tcp_request_sock" => Some(Self::SkcToTcpRequestSock),
            "skc_to_udp6_sock" => Some(Self::SkcToUdp6Sock),
            "skc_to_mptcp_sock" => Some(Self::SkcToMptcpSock),
            "get_task_stack" => Some(Self::GetTaskStack),
            "skc_to_unix_sock" => Some(Self::SkcToUnixSock),
            "inode_storage_get" => Some(Self::InodeStorageGet),
            "inode_storage_delete" => Some(Self::InodeStorageDelete),
            "cgrp_storage_get" | "cgroup_storage_get" => Some(Self::CgrpStorageGet),
            "cgrp_storage_delete" | "cgroup_storage_delete" => Some(Self::CgrpStorageDelete),
            "sock_from_file" => Some(Self::SockFromFile),
            "snprintf" => Some(Self::Snprintf),
            "sys_bpf" => Some(Self::SysBpf),
            "btf_find_by_name_kind" => Some(Self::BtfFindByNameKind),
            "sys_close" => Some(Self::SysClose),
            "timer_init" => Some(Self::TimerInit),
            "timer_set_callback" => Some(Self::TimerSetCallback),
            "timer_start" => Some(Self::TimerStart),
            "timer_cancel" => Some(Self::TimerCancel),
            "task_pt_regs" => Some(Self::TaskPtRegs),
            "kallsyms_lookup_name" => Some(Self::KallsymsLookupName),
            "find_vma" => Some(Self::FindVma),
            "loop" => Some(Self::BpfLoop),
            "get_func_arg" => Some(Self::GetFuncArg),
            "get_func_ret" => Some(Self::GetFuncRet),
            "get_func_arg_cnt" => Some(Self::GetFuncArgCnt),
            "ringbuf_output" => Some(Self::RingbufOutput),
            "ringbuf_reserve" => Some(Self::RingbufReserve),
            "ringbuf_submit" => Some(Self::RingbufSubmit),
            "ringbuf_discard" => Some(Self::RingbufDiscard),
            "ringbuf_query" => Some(Self::RingbufQuery),
            "csum_level" => Some(Self::CsumLevel),
            "kptr_xchg" => Some(Self::KptrXchg),
            "dynptr_from_mem" => Some(Self::DynptrFromMem),
            "ringbuf_reserve_dynptr" => Some(Self::RingbufReserveDynptr),
            "ringbuf_submit_dynptr" => Some(Self::RingbufSubmitDynptr),
            "ringbuf_discard_dynptr" => Some(Self::RingbufDiscardDynptr),
            "dynptr_read" => Some(Self::DynptrRead),
            "dynptr_write" => Some(Self::DynptrWrite),
            "dynptr_data" => Some(Self::DynptrData),
            "user_ringbuf_drain" => Some(Self::UserRingbufDrain),
            "probe_read_user_str" => Some(Self::ProbeReadUserStr),
            "probe_read_kernel_str" => Some(Self::ProbeReadKernelStr),
            _ => None,
        }
    }

    pub const fn requires_callback_subprogram(self) -> bool {
        matches!(
            self,
            Self::ForEachMapElem
                | Self::TimerSetCallback
                | Self::FindVma
                | Self::BpfLoop
                | Self::UserRingbufDrain
        )
    }

    pub const fn supports_modeled_callback_subprogram(self) -> bool {
        matches!(
            self,
            Self::ForEachMapElem
                | Self::TimerSetCallback
                | Self::FindVma
                | Self::BpfLoop
                | Self::UserRingbufDrain
        )
    }

    pub const fn callback_subprogram_signature_message(self) -> Option<&'static str> {
        match self {
            Self::ForEachMapElem => Some(
                "helper 'bpf_for_each_map_elem' callback must have signature fn(bpf_map*, *map, *map, *stack) -> scalar",
            ),
            Self::TimerSetCallback => Some(
                "helper 'bpf_timer_set_callback' callback must have signature fn(bpf_map*, *map, *map) -> scalar",
            ),
            Self::FindVma => Some(
                "helper 'bpf_find_vma' callback must have signature fn(task_struct*, vm_area_struct*, *stack) -> scalar",
            ),
            Self::BpfLoop => {
                Some("helper 'bpf_loop' callback must have signature fn(u64, *stack) -> scalar")
            }
            Self::UserRingbufDrain => Some(
                "helper 'bpf_user_ringbuf_drain' callback must have signature fn(*stack /* dynptr */, *stack) -> scalar",
            ),
            _ => None,
        }
    }

    pub const fn callback_return_range_requirement(self) -> Option<ScalarValueRange> {
        match self {
            Self::ForEachMapElem | Self::FindVma | Self::BpfLoop | Self::UserRingbufDrain => {
                Some(ScalarValueRange::new(0, 1))
            }
            Self::TimerSetCallback => Some(ScalarValueRange::new(0, 0)),
            _ => None,
        }
    }

    pub fn callback_subprogram_type_error(
        self,
        arg_idx: usize,
        arg_ty: &MirType,
    ) -> Option<String> {
        let MirType::Subprogram { args, ret } = arg_ty else {
            return Some(format!(
                "helper '{}' arg{} expects callback subprogram, got {:?}",
                self.name(),
                arg_idx,
                arg_ty
            ));
        };

        let valid = match self {
            Self::ForEachMapElem => {
                args.len() == 4
                    && args.first().is_some_and(MirType::is_bpf_map_ptr)
                    && args.get(1).is_some_and(MirType::is_map_ptr)
                    && args.get(2).is_some_and(MirType::is_map_ptr)
                    && args.get(3).is_some_and(MirType::is_stack_ptr)
                    && ret.is_scalar_like()
            }
            Self::TimerSetCallback => {
                args.len() == 3
                    && args.first().is_some_and(MirType::is_bpf_map_ptr)
                    && args.get(1).is_some_and(MirType::is_map_ptr)
                    && args.get(2).is_some_and(MirType::is_map_ptr)
                    && ret.is_scalar_like()
            }
            Self::FindVma => {
                args.len() == 3
                    && args.first().is_some_and(MirType::is_task_struct_ptr)
                    && args.get(1).is_some_and(MirType::is_vm_area_struct_ptr)
                    && args.get(2).is_some_and(MirType::is_stack_ptr)
                    && ret.is_scalar_like()
            }
            Self::BpfLoop => {
                args.len() == 2
                    && args.first().is_some_and(MirType::is_scalar_like)
                    && args.get(1).is_some_and(MirType::is_stack_ptr)
                    && ret.is_scalar_like()
            }
            Self::UserRingbufDrain => {
                args.len() == 2
                    && args.first().is_some_and(MirType::is_dynptr_stack_ptr)
                    && args.get(1).is_some_and(MirType::is_stack_ptr)
                    && ret.is_scalar_like()
            }
            _ => return None,
        };

        if valid {
            None
        } else {
            self.callback_subprogram_signature_message()
                .map(ToOwned::to_owned)
        }
    }

    pub const fn zero_size_pointer_arg_size_arg(self, arg_idx: usize) -> Option<usize> {
        match (self, arg_idx) {
            (Self::CsumDiff, 0) => Some(1),
            (Self::CsumDiff, 2) => Some(3),
            (Self::ReadBranchRecords, 1) => Some(2),
            (Self::GetBranchSnapshot, 0) => Some(1),
            (Self::GetTaskStack, 1) => Some(2),
            (Self::CopyFromUser | Self::CopyFromUserTask, 0) => Some(1),
            (Self::DPath, 1) => Some(2),
            (Self::SeqPrintf, 3) => Some(4),
            _ => None,
        }
    }

    /// Helper pointer arguments that accept a known literal null without
    /// requiring program-context-specific policy.
    pub const fn pointer_arg_allows_static_const_zero(self, arg_idx: usize) -> bool {
        matches!(
            (self, arg_idx),
            (Self::KptrXchg, 1) | (Self::RedirectNeigh, 1) | (Self::SkAssign, 1)
        ) || self.pointer_arg_allows_static_maybe_null(arg_idx)
            || self.zero_size_pointer_arg_size_arg(arg_idx).is_some()
    }

    /// Helper pointer arguments that accept nullable pointer values without
    /// requiring program-context-specific policy.
    pub const fn pointer_arg_allows_static_maybe_null(self, arg_idx: usize) -> bool {
        matches!(
            (self, arg_idx),
            (Self::SkStorageGet, 2)
                | (Self::InodeStorageGet, 2)
                | (Self::TaskStorageGet, 2)
                | (Self::CgrpStorageGet, 1)
                | (Self::CgrpStorageGet, 2)
                | (Self::CgrpStorageDelete, 1)
                | (Self::ForEachMapElem, 2)
                | (Self::FindVma, 3)
                | (Self::BpfLoop, 2)
                | (Self::UserRingbufDrain, 2)
        )
    }

    pub const fn scalar_arg_multiple_of_requirement(
        self,
        arg_idx: usize,
    ) -> Option<(i64, &'static str)> {
        match (self, arg_idx) {
            (Self::CsumDiff, 1) => Some((
                4,
                "helper 'bpf_csum_diff' requires arg1 to be a multiple of 4",
            )),
            (Self::CsumDiff, 3) => Some((
                4,
                "helper 'bpf_csum_diff' requires arg3 to be a multiple of 4",
            )),
            (Self::L3CsumReplace | Self::L4CsumReplace, 1) => Some((
                2,
                "checksum replacement helpers require arg1 offset to be even",
            )),
            (Self::Snprintf, 4) => Some((
                8,
                "helper 'bpf_snprintf' requires arg4 to be a multiple of 8",
            )),
            (Self::SeqPrintf, 4) => Some((
                8,
                "helper 'bpf_seq_printf' requires arg4 to be a multiple of 8",
            )),
            (Self::TraceVPrintk, 3) => Some((
                8,
                "helper 'bpf_trace_vprintk' requires arg3 to be a multiple of 8",
            )),
            _ => None,
        }
    }

    pub const fn scalar_arg_nonnegative_requirement(self, arg_idx: usize) -> Option<&'static str> {
        match (self, arg_idx) {
            (Self::GetStack, 2) => Some("helper 'bpf_get_stack' requires arg2 to be >= 0"),
            (Self::GetTaskStack, 2) => Some("helper 'bpf_get_task_stack' requires arg2 to be >= 0"),
            (Self::DPath, 2) => Some("helper 'bpf_d_path' requires arg2 to be >= 0"),
            (Self::CopyFromUser, 1) => Some("helper 'bpf_copy_from_user' requires arg1 to be >= 0"),
            (Self::CopyFromUserTask, 1) => {
                Some("helper 'bpf_copy_from_user_task' requires arg1 to be >= 0")
            }
            (Self::SnprintfBtf, 1) => Some("helper 'bpf_snprintf_btf' requires arg1 to be >= 0"),
            (Self::Snprintf, 1) => Some("helper 'bpf_snprintf' requires arg1 to be >= 0"),
            (Self::Snprintf, 4) => Some("helper 'bpf_snprintf' requires arg4 to be >= 0"),
            (Self::SeqPrintf, 4) => Some("helper 'bpf_seq_printf' requires arg4 to be >= 0"),
            (Self::SeqWrite, 2) => Some("helper 'bpf_seq_write' requires arg2 to be >= 0"),
            (Self::TraceVPrintk, 3) => Some("helper 'bpf_trace_vprintk' requires arg3 to be >= 0"),
            (Self::TcpRawGenSyncookieIpv4 | Self::TcpRawGenSyncookieIpv6, 2) => {
                Some("raw syncookie helpers require arg2 to be >= 0")
            }
            (Self::RedirectNeigh, 2) => {
                Some("helper 'bpf_redirect_neigh' requires arg2 plen to be >= 0")
            }
            _ => None,
        }
    }

    pub const fn scalar_arg_range_requirement(
        self,
        arg_idx: usize,
    ) -> Option<(i64, i64, &'static str)> {
        match (self, arg_idx) {
            (Self::SnprintfBtf, 4) => Some((
                0,
                15,
                "helper 'bpf_snprintf_btf' requires arg4 to contain only BTF_F_* bits (0x0f)",
            )),
            (Self::SeqPrintfBtf, 3) => Some((
                0,
                15,
                "helper 'bpf_seq_printf_btf' requires arg3 to contain only BTF_F_* bits (0x0f)",
            )),
            (Self::BprmOptsSet, 1) => Some((
                0,
                1,
                "helper 'bpf_bprm_opts_set' requires arg1 flags to contain only BPF_F_BPRM_* bits (0x01)",
            )),
            (Self::ForEachMapElem, 3) => Some((
                0,
                0,
                "helper 'bpf_for_each_map_elem' requires arg3 flags to be 0",
            )),
            (Self::TimerStart, 2) => Some((
                0,
                3,
                "helper 'bpf_timer_start' requires arg2 flags to contain only BPF_F_TIMER_* bits (0x03)",
            )),
            (Self::FindVma, 4) => Some((0, 0, "helper 'bpf_find_vma' requires arg4 flags to be 0")),
            (Self::BpfLoop, 0) => Some((
                0,
                BPF_MAX_LOOPS,
                "helper 'bpf_loop' requires arg0 nr_loops to be between 0 and BPF_MAX_LOOPS (8 * 1024 * 1024)",
            )),
            (Self::BpfLoop, 3) => Some((0, 0, "helper 'bpf_loop' requires arg3 flags to be 0")),
            (Self::TailCall, 2) => Some((
                0,
                BPF_TAIL_CALL_INDEX_MAX_U32,
                "helper 'bpf_tail_call' requires arg2 index to be between 0 and u32::MAX",
            )),
            (Self::SysBpf, 0) => Some((
                0,
                BPF_SYSCALL_CMD_MAX_I32,
                "helper 'bpf_sys_bpf' requires arg0 cmd to be between 0 and i32::MAX",
            )),
            (Self::SysBpf, 2) => Some((
                0,
                BPF_SYSCALL_ATTR_SIZE_MAX_U32,
                "helper 'bpf_sys_bpf' requires arg2 attr_size to be between 0 and u32::MAX",
            )),
            (Self::BtfFindByNameKind, 1) => Some((
                0,
                BPF_SYSCALL_NAME_SIZE_MAX_I32,
                "helper 'bpf_btf_find_by_name_kind' requires arg1 name_sz to be between 0 and i32::MAX",
            )),
            (Self::BtfFindByNameKind, 2) => Some((
                0,
                BPF_BTF_KIND_MAX_U32,
                "helper 'bpf_btf_find_by_name_kind' requires arg2 kind to be between 0 and u32::MAX",
            )),
            (Self::SysClose, 0) => Some((
                0,
                BPF_SYSCALL_FD_MAX_U32,
                "helper 'bpf_sys_close' requires arg0 fd to be between 0 and u32::MAX",
            )),
            (Self::KallsymsLookupName, 1) => Some((
                0,
                BPF_SYSCALL_NAME_SIZE_MAX_I32,
                "helper 'bpf_kallsyms_lookup_name' requires arg1 name_sz to be between 0 and i32::MAX",
            )),
            (Self::SetRetval, 0) => Some((
                BPF_SET_RETVAL_MIN_I32,
                BPF_SET_RETVAL_MAX_I32,
                "helper 'bpf_set_retval' requires arg0 retval to be between i32::MIN and i32::MAX",
            )),
            (Self::GetFuncArg, 1) => Some((
                0,
                BPF_FUNC_ARG_INDEX_MAX_U32,
                "helper 'bpf_get_func_arg' requires arg1 n to be between 0 and u32::MAX",
            )),
            (Self::MapLookupPercpuElem, 2) => Some((
                0,
                BPF_CPU_INDEX_MAX_U32,
                "helper 'bpf_map_lookup_percpu_elem' requires arg2 cpu to be between 0 and u32::MAX",
            )),
            (Self::PerCpuPtr, 1) => Some((
                0,
                BPF_CPU_INDEX_MAX_U32,
                "helper 'bpf_per_cpu_ptr' requires arg1 cpu to be between 0 and u32::MAX",
            )),
            (Self::GetCurrentComm, 1) => Some((
                0,
                BPF_GET_CURRENT_COMM_SIZE_MAX_U32,
                "helper 'bpf_get_current_comm' requires arg1 size to be between 0 and u32::MAX",
            )),
            (Self::GetStack | Self::GetTaskStack, 2) => Some((
                0,
                BPF_BUFFER_SIZE_MAX_U32,
                "stack-copy helpers require arg2 size to be between 0 and u32::MAX",
            )),
            (Self::DPath, 2) => Some((
                0,
                BPF_BUFFER_SIZE_MAX_U32,
                "helper 'bpf_d_path' requires arg2 size to be between 0 and u32::MAX",
            )),
            (Self::GetBranchSnapshot, 1) => Some((
                0,
                BPF_BUFFER_SIZE_MAX_U32,
                "helper 'bpf_get_branch_snapshot' requires arg1 size to be between 0 and u32::MAX",
            )),
            (Self::ReadBranchRecords, 2) => Some((
                0,
                BPF_BUFFER_SIZE_MAX_U32,
                "helper 'bpf_read_branch_records' requires arg2 size to be between 0 and u32::MAX",
            )),
            (Self::ImaInodeHash | Self::ImaFileHash, 2) => Some((
                0,
                BPF_IMA_HASH_SIZE_MAX_U32,
                "IMA hash helpers require arg2 size to be between 0 and u32::MAX",
            )),
            (Self::TracePrintk | Self::TraceVPrintk, 1) => Some((
                0,
                BPF_FORMAT_SIZE_MAX_U32,
                "trace print helpers require arg1 fmt_size to be between 0 and u32::MAX",
            )),
            (Self::TraceVPrintk, 3) => Some((
                0,
                BPF_FORMAT_SIZE_MAX_U32,
                "helper 'bpf_trace_vprintk' requires arg3 data_len to be between 0 and u32::MAX",
            )),
            (Self::Snprintf | Self::SnprintfBtf, 1) => Some((
                0,
                BPF_FORMAT_SIZE_MAX_U32,
                "snprintf helpers require arg1 str_size to be between 0 and u32::MAX",
            )),
            (Self::Snprintf, 4) => Some((
                0,
                BPF_FORMAT_SIZE_MAX_U32,
                "helper 'bpf_snprintf' requires arg4 data_len to be between 0 and u32::MAX",
            )),
            (Self::SeqPrintf, 2) => Some((
                0,
                BPF_FORMAT_SIZE_MAX_U32,
                "helper 'bpf_seq_printf' requires arg2 fmt_size to be between 0 and u32::MAX",
            )),
            (Self::SeqPrintf, 4) => Some((
                0,
                BPF_FORMAT_SIZE_MAX_U32,
                "helper 'bpf_seq_printf' requires arg4 data_len to be between 0 and u32::MAX",
            )),
            (Self::SeqWrite, 2) => Some((
                0,
                BPF_FORMAT_SIZE_MAX_U32,
                "helper 'bpf_seq_write' requires arg2 len to be between 0 and u32::MAX",
            )),
            (Self::CopyFromUser | Self::CopyFromUserTask, 1) => Some((
                0,
                BPF_COPY_FROM_USER_SIZE_MAX_U32,
                "copy-from-user helpers require arg1 size to be between 0 and u32::MAX",
            )),
            (Self::Strncmp, 1) => Some((
                0,
                BPF_STRNCMP_SIZE_MAX_U32,
                "helper 'bpf_strncmp' requires arg1 s1_sz to be between 0 and u32::MAX",
            )),
            (
                Self::ProbeRead
                | Self::ProbeReadStr
                | Self::ProbeReadUser
                | Self::ProbeReadKernel
                | Self::ProbeReadUserStr
                | Self::ProbeReadKernelStr,
                1,
            ) => Some((
                0,
                BPF_PROBE_MEM_SIZE_MAX_U32,
                "probe read helpers require arg1 size to be between 0 and u32::MAX",
            )),
            (Self::ProbeWriteUser, 2) => Some((
                0,
                BPF_PROBE_MEM_SIZE_MAX_U32,
                "helper 'bpf_probe_write_user' requires arg2 size to be between 0 and u32::MAX",
            )),
            (Self::GetCurrentAncestorCgroupId, 0)
            | (Self::SkAncestorCgroupId | Self::SkbAncestorCgroupId, 1) => Some((
                0,
                BPF_ANCESTOR_CGROUP_LEVEL_MAX,
                "ancestor cgroup helpers require ancestor_level to be between 0 and i32::MAX",
            )),
            (Self::SkbUnderCgroup, 2) | (Self::CurrentTaskUnderCgroup, 1) => Some((
                0,
                BPF_CGROUP_ARRAY_INDEX_MAX_U32,
                "cgroup membership helpers require idx to be between 0 and u32::MAX",
            )),
            (Self::SkbChangeType, 1) => Some((
                0,
                PACKET_OTHERHOST,
                "helper 'bpf_skb_change_type' requires arg1 type to be PACKET_HOST, PACKET_BROADCAST, PACKET_MULTICAST, or PACKET_OTHERHOST",
            )),
            (Self::SysctlGetName, 3) => Some((
                0,
                1,
                "helper 'bpf_sysctl_get_name' requires arg3 flags to contain only BPF_F_SYSCTL_* bits (0x01)",
            )),
            (Self::ReadBranchRecords, 3) => Some((
                0,
                1,
                "helper 'bpf_read_branch_records' requires arg3 flags to contain only BPF_F_GET_BRANCH_RECORDS_SIZE (0x01)",
            )),
            (Self::RingbufOutput, 3) => Some((
                0,
                3,
                "helper 'bpf_ringbuf_output' requires arg3 flags to contain only BPF_RB_* wakeup bits (0x03)",
            )),
            (Self::RingbufReserve, 2) => Some((
                0,
                0,
                "helper 'bpf_ringbuf_reserve' requires arg2 flags to be 0",
            )),
            (Self::RingbufReserveDynptr, 2) => Some((
                0,
                0,
                "helper 'bpf_ringbuf_reserve_dynptr' requires arg2 flags to be 0",
            )),
            (Self::RingbufReserveDynptr, 1) => Some((
                0,
                BPF_RINGBUF_DYNPTR_RESERVE_SIZE_MAX_U32,
                "helper 'bpf_ringbuf_reserve_dynptr' requires arg1 size to be between 0 and u32::MAX",
            )),
            (Self::RingbufSubmit, 1) => Some((
                0,
                3,
                "helper 'bpf_ringbuf_submit' requires arg1 flags to contain only BPF_RB_* wakeup bits (0x03)",
            )),
            (Self::RingbufDiscard, 1) => Some((
                0,
                3,
                "helper 'bpf_ringbuf_discard' requires arg1 flags to contain only BPF_RB_* wakeup bits (0x03)",
            )),
            (Self::RingbufSubmitDynptr, 1) => Some((
                0,
                3,
                "helper 'bpf_ringbuf_submit_dynptr' requires arg1 flags to contain only BPF_RB_* wakeup bits (0x03)",
            )),
            (Self::RingbufDiscardDynptr, 1) => Some((
                0,
                3,
                "helper 'bpf_ringbuf_discard_dynptr' requires arg1 flags to contain only BPF_RB_* wakeup bits (0x03)",
            )),
            (Self::UserRingbufDrain, 3) => Some((
                0,
                3,
                "helper 'bpf_user_ringbuf_drain' requires arg3 flags to contain only BPF_RB_* wakeup bits (0x03)",
            )),
            (Self::RingbufQuery, 1) => Some((
                0,
                3,
                "helper 'bpf_ringbuf_query' requires arg1 flags to be one of BPF_RB_* query selectors (0..3)",
            )),
            (Self::DynptrFromMem, 2) => Some((
                0,
                0,
                "helper 'bpf_dynptr_from_mem' requires arg2 flags to be 0",
            )),
            (Self::DynptrRead, 4) => {
                Some((0, 0, "helper 'bpf_dynptr_read' requires arg4 flags to be 0"))
            }
            (Self::DynptrWrite, 4) => Some((
                0,
                0,
                "helper 'bpf_dynptr_write' requires arg4 flags to be 0 for modeled dynptr sources",
            )),
            (Self::Redirect, 0) => Some((
                0,
                BPF_REDIRECT_IFINDEX_MAX_U32,
                "helper 'bpf_redirect' requires arg0 ifindex to be between 0 and u32::MAX",
            )),
            (Self::Redirect, 1) => Some((
                0,
                1,
                "helper 'bpf_redirect' requires arg1 flags to contain only BPF_F_INGRESS (0x01)",
            )),
            (Self::RedirectPeer, 0) => Some((
                0,
                BPF_REDIRECT_IFINDEX_MAX_U32,
                "helper 'bpf_redirect_peer' requires arg0 ifindex to be between 0 and u32::MAX",
            )),
            (Self::RedirectNeigh, 0) => Some((
                0,
                BPF_REDIRECT_IFINDEX_MAX_U32,
                "helper 'bpf_redirect_neigh' requires arg0 ifindex to be between 0 and u32::MAX",
            )),
            (Self::RedirectNeigh, 2) => Some((
                0,
                BPF_REDIRECT_NEIGH_PLEN_MAX_I32,
                "helper 'bpf_redirect_neigh' requires arg2 plen to be between 0 and i32::MAX",
            )),
            (Self::CloneRedirect, 1) => Some((
                0,
                BPF_REDIRECT_IFINDEX_MAX_U32,
                "helper 'bpf_clone_redirect' requires arg1 ifindex to be between 0 and u32::MAX",
            )),
            (Self::CloneRedirect, 2) => Some((
                0,
                1,
                "skb/message redirect helpers require flags to contain only BPF_F_INGRESS (0x01)",
            )),
            (
                Self::SkRedirectMap
                | Self::MsgRedirectMap
                | Self::SkRedirectHash
                | Self::MsgRedirectHash,
                3,
            ) => Some((
                0,
                1,
                "skb/message redirect helpers require flags to contain only BPF_F_INGRESS (0x01)",
            )),
            (Self::SkRedirectMap | Self::MsgRedirectMap, 2) => Some((
                0,
                BPF_SOCKET_REDIRECT_MAP_KEY_MAX_U32,
                "socket redirect map helpers require arg2 key to be between 0 and u32::MAX",
            )),
            (Self::SkSelectReuseport, 3) => Some((
                0,
                0,
                "helper 'bpf_sk_select_reuseport' requires arg3 flags to be 0",
            )),
            (Self::SkAssign, 2) => Some((
                0,
                3,
                "helper 'bpf_sk_assign' requires arg2 flags to contain only BPF_SK_LOOKUP_F_REPLACE/BPF_SK_LOOKUP_F_NO_REUSEPORT bits (0x03)",
            )),
            (Self::SkLookupTcp | Self::SkLookupUdp | Self::SkcLookupTcp, 2) => Some((
                0,
                BPF_SOCKET_LOOKUP_TUPLE_SIZE_MAX_U32,
                "socket lookup helpers require arg2 tuple_size to be between 0 and u32::MAX",
            )),
            (Self::TcpCheckSyncookie | Self::TcpGenSyncookie, 2) => Some((
                0,
                BPF_SYNCOOKIE_HEADER_LEN_MAX_U32,
                "TCP syncookie helpers require arg2 iph_len to be between 0 and u32::MAX",
            )),
            (Self::TcpCheckSyncookie | Self::TcpGenSyncookie, 4) => Some((
                0,
                BPF_SYNCOOKIE_HEADER_LEN_MAX_U32,
                "TCP syncookie helpers require arg4 th_len to be between 0 and u32::MAX",
            )),
            (Self::TcpRawGenSyncookieIpv4 | Self::TcpRawGenSyncookieIpv6, 2) => Some((
                0,
                BPF_SYNCOOKIE_HEADER_LEN_MAX_U32,
                "raw syncookie helpers require arg2 th_len to be between 0 and u32::MAX",
            )),
            (Self::TcpSendAck, 1) => Some((
                0,
                BPF_TCP_SEND_ACK_RCV_NXT_MAX_U32,
                "helper 'bpf_tcp_send_ack' requires arg1 rcv_nxt to be between 0 and u32::MAX",
            )),
            (Self::PerfEventRead | Self::PerfEventReadValue, 1) => Some((
                0,
                0xffff_ffff,
                "perf event read helpers require arg1 flags to fit BPF_F_INDEX_MASK/BPF_F_CURRENT_CPU (0xffffffff)",
            )),
            (Self::CheckMtu, 1) => Some((
                0,
                BPF_CHECK_MTU_IFINDEX_MAX_U32,
                "helper 'bpf_check_mtu' requires arg1 ifindex to be between 0 and u32::MAX",
            )),
            (Self::CheckMtu, 3) => Some((
                BPF_CHECK_MTU_LEN_DIFF_MIN_I32,
                BPF_CHECK_MTU_LEN_DIFF_MAX_I32,
                "helper 'bpf_check_mtu' requires arg3 len_diff to be between i32::MIN and i32::MAX",
            )),
            (Self::FibLookup, 2) => Some((
                BPF_FIB_LOOKUP_SIZE,
                i64::MAX,
                "helper 'bpf_fib_lookup' requires arg2 plen to be at least sizeof(struct bpf_fib_lookup) (64 bytes)",
            )),
            (Self::SkbSetTunnelKey, 3) => Some((
                0,
                31,
                "helper 'bpf_skb_set_tunnel_key' requires arg3 flags to contain only BPF_F_TUNINFO_IPV6/BPF_F_ZERO_CSUM_TX/BPF_F_DONT_FRAGMENT/BPF_F_SEQ_NUMBER/BPF_F_NO_TUNNEL_KEY bits (0x1f)",
            )),
            (Self::SkbGetTunnelOpt | Self::SkbSetTunnelOpt, 2) => Some((
                0,
                BPF_SKB_TUNNEL_OPT_MAX_SIZE,
                "skb tunnel option helpers require arg2 size to be between 0 and u32::MAX",
            )),
            (Self::SkbGetXfrmState, 1) => Some((
                0,
                BPF_SKB_XFRM_STATE_MAX_U32,
                "helper 'bpf_skb_get_xfrm_state' requires arg1 index to be between 0 and u32::MAX",
            )),
            (Self::SkbGetXfrmState, 3) => Some((
                0,
                BPF_SKB_XFRM_STATE_MAX_U32,
                "helper 'bpf_skb_get_xfrm_state' requires arg3 size to be between 0 and u32::MAX",
            )),
            (Self::SkbStoreBytes, 4) => Some((
                0,
                3,
                "helper 'bpf_skb_store_bytes' requires arg4 flags to contain only BPF_F_RECOMPUTE_CSUM/BPF_F_INVALIDATE_HASH bits (0x03)",
            )),
            (Self::SkbStoreBytes | Self::SkbLoadBytes, 1) => Some((
                0,
                BPF_SKB_BYTE_MAX_OFFSET,
                "skb byte helpers require arg1 offset to be between 0 and i32::MAX",
            )),
            (Self::SkbStoreBytes, 3) => Some((
                0,
                BPF_SKB_STORE_BYTES_MAX_LEN,
                "helper 'bpf_skb_store_bytes' requires arg3 len to be between 0 and u32::MAX",
            )),
            (Self::SkbLoadBytes | Self::SkbLoadBytesRelative, 3) => Some((
                0,
                BPF_SKB_LOAD_BYTES_MAX_LEN,
                "skb load byte helpers require arg3 len to be between 0 and u32::MAX",
            )),
            (Self::SkbPullData, 1) => Some((
                0,
                BPF_SKB_PULL_DATA_MAX_LEN,
                "helper 'bpf_skb_pull_data' requires arg1 len to be between 0 and u32::MAX",
            )),
            (Self::SkbChangeTail, 1) => Some((
                0,
                BPF_SKB_CHANGE_TAIL_MAX_NEW_LEN,
                "helper 'bpf_skb_change_tail' requires arg1 new_len to be between 0 and i32::MAX",
            )),
            (Self::SkbChangeHead, 1) => Some((
                0,
                BPF_SKB_CHANGE_HEAD_MAX_HEAD_ROOM,
                "helper 'bpf_skb_change_head' requires arg1 head_room to be between 0 and i32::MAX",
            )),
            (Self::SkbLoadBytesRelative, 1) => Some((
                0,
                BPF_SKB_LOAD_BYTES_RELATIVE_MAX_OFFSET,
                "helper 'bpf_skb_load_bytes_relative' requires arg1 offset to be between 0 and 0xffff",
            )),
            (Self::SkbLoadBytesRelative, 4) => Some((
                0,
                1,
                "helper 'bpf_skb_load_bytes_relative' requires arg4 start_header to be BPF_HDR_START_MAC or BPF_HDR_START_NET",
            )),
            (Self::SkbVlanPush, 1) => Some((
                0,
                BPF_SKB_VLAN_MAX_U16,
                "helper 'bpf_skb_vlan_push' requires arg1 vlan_proto to be between 0 and u16::MAX",
            )),
            (Self::SkbVlanPush, 2) => Some((
                0,
                BPF_SKB_VLAN_MAX_U16,
                "helper 'bpf_skb_vlan_push' requires arg2 vlan_tci to be between 0 and u16::MAX",
            )),
            (Self::SetHash, 1) => Some((
                0,
                BPF_SET_HASH_MAX_U32,
                "helper 'bpf_set_hash' requires arg1 hash to be between 0 and u32::MAX",
            )),
            (Self::SendSignal | Self::SendSignalThread, 0) => Some((
                0,
                BPF_SIGNAL_MAX_U32,
                "signal helpers require arg0 sig to be between 0 and u32::MAX",
            )),
            (Self::MsgApplyBytes | Self::MsgCorkBytes, 1) => Some((
                0,
                BPF_MSG_DATA_MAX_U32,
                "message byte-count helpers require arg1 bytes to be between 0 and u32::MAX",
            )),
            (Self::MsgPullData, 1) => Some((
                0,
                BPF_MSG_DATA_MAX_U32,
                "helper 'bpf_msg_pull_data' requires arg1 start to be between 0 and u32::MAX",
            )),
            (Self::MsgPullData, 2) => Some((
                0,
                BPF_MSG_DATA_MAX_U32,
                "helper 'bpf_msg_pull_data' requires arg2 end to be between 0 and u32::MAX",
            )),
            (Self::MsgPushData | Self::MsgPopData, 1) => Some((
                0,
                BPF_MSG_DATA_MAX_U32,
                "message data reshaping helpers require arg1 start to be between 0 and u32::MAX",
            )),
            (Self::MsgPushData | Self::MsgPopData, 2) => Some((
                0,
                BPF_MSG_DATA_MAX_U32,
                "message data reshaping helpers require arg2 len to be between 0 and u32::MAX",
            )),
            (Self::SetSockOpt | Self::GetSockOpt, 4) => Some((
                0,
                BPF_SOCKET_HELPER_LEN_MAX_I32,
                "socket option helpers require arg4 optlen to be between 0 and i32::MAX",
            )),
            (Self::Bind, 2) => Some((
                0,
                BPF_SOCKET_HELPER_LEN_MAX_I32,
                "helper 'bpf_bind' requires arg2 addr_len to be between 0 and i32::MAX",
            )),
            (Self::LoadHdrOpt | Self::StoreHdrOpt, 2) => Some((
                0,
                BPF_HDR_OPT_LEN_MAX_U32,
                "TCP header option helpers require arg2 len to be between 0 and u32::MAX",
            )),
            (Self::ReserveHdrOpt, 1) => Some((
                0,
                BPF_HDR_OPT_LEN_MAX_U32,
                "helper 'bpf_reserve_hdr_opt' requires arg1 len to be between 0 and u32::MAX",
            )),
            (Self::XdpLoadBytes | Self::XdpStoreBytes, 1) => Some((
                0,
                BPF_XDP_BYTE_MAX_OFFSET_OR_LEN,
                "xdp byte helpers require arg1 offset to be between 0 and 0xffff",
            )),
            (Self::XdpLoadBytes | Self::XdpStoreBytes, 3) => Some((
                0,
                BPF_XDP_BYTE_MAX_OFFSET_OR_LEN,
                "xdp byte helpers require arg3 len to be between 0 and 0xffff",
            )),
            (Self::SkbAdjustRoom, 1) => Some((
                -BPF_SKB_ADJUST_ROOM_MAX_LEN_DIFF,
                BPF_SKB_ADJUST_ROOM_MAX_LEN_DIFF,
                "helper 'bpf_skb_adjust_room' requires arg1 len_diff to be between -0xfff and 0xfff",
            )),
            (Self::SkbAdjustRoom, 2) => Some((
                0,
                1,
                "helper 'bpf_skb_adjust_room' requires arg2 mode to be BPF_ADJ_ROOM_NET or BPF_ADJ_ROOM_MAC",
            )),
            (Self::LwtPushEncap, 1) => Some((
                0,
                2,
                "helper 'bpf_lwt_push_encap' requires arg1 type to be BPF_LWT_ENCAP_SEG6, BPF_LWT_ENCAP_SEG6_INLINE, or BPF_LWT_ENCAP_IP",
            )),
            (Self::LwtPushEncap | Self::LwtSeg6StoreBytes | Self::LwtSeg6Action, 3) => Some((
                0,
                BPF_LWT_BUFFER_SIZE_MAX_U32,
                "lwt buffer helpers require arg3 size to be between 0 and u32::MAX",
            )),
            (Self::LwtSeg6StoreBytes | Self::LwtSeg6AdjustSrh, 1) => Some((
                0,
                BPF_LWT_SEG6_OFFSET_MAX_U32,
                "lwt seg6 helpers require arg1 offset to be between 0 and u32::MAX",
            )),
            (Self::L3CsumReplace | Self::L4CsumReplace, 1) => Some((
                0,
                0xffff,
                "checksum replacement helpers require arg1 offset to be between 0 and 0xffff",
            )),
            (Self::CsumDiff, 1) => Some((
                0,
                BPF_CSUM_DIFF_MAX_U32,
                "helper 'bpf_csum_diff' requires arg1 from_size to be between 0 and u32::MAX",
            )),
            (Self::CsumDiff, 3) => Some((
                0,
                BPF_CSUM_DIFF_MAX_U32,
                "helper 'bpf_csum_diff' requires arg3 to_size to be between 0 and u32::MAX",
            )),
            (Self::CsumDiff, 4) => Some((
                0,
                BPF_CSUM_DIFF_MAX_U32,
                "helper 'bpf_csum_diff' requires arg4 seed to be between 0 and u32::MAX",
            )),
            (Self::CsumUpdate, 1) => Some((
                0,
                BPF_CSUM_UPDATE_CSUM_MAX_U32,
                "helper 'bpf_csum_update' requires arg1 csum to be between 0 and u32::MAX",
            )),
            (Self::SkbSetTstamp, 2) => Some((
                0,
                1,
                "helper 'bpf_skb_set_tstamp' requires arg2 tstamp_type to be BPF_SKB_TSTAMP_UNSPEC or BPF_SKB_TSTAMP_DELIVERY_MONO",
            )),
            (
                Self::SkStorageGet
                | Self::TaskStorageGet
                | Self::InodeStorageGet
                | Self::CgrpStorageGet,
                3,
            ) => Some((
                0,
                1,
                "storage get helpers require arg3 flags to be 0 or BPF_LOCAL_STORAGE_GET_F_CREATE",
            )),
            _ => None,
        }
    }

    pub const fn scalar_arg_bitmask_requirement(
        self,
        arg_idx: usize,
    ) -> Option<(i64, &'static str)> {
        match (self, arg_idx) {
            (Self::GetStackId, 2) => Some((
                0x07ff,
                "helper 'bpf_get_stackid' requires arg2 flags to contain only BPF_F_SKIP_FIELD_MASK/BPF_F_USER_STACK/BPF_F_FAST_STACK_CMP/BPF_F_REUSE_STACKID bits (0x07ff)",
            )),
            (Self::GetStack | Self::GetTaskStack, 3) => Some((
                0x09ff,
                "stack-copy helpers require flags to contain only BPF_F_SKIP_FIELD_MASK/BPF_F_USER_STACK/BPF_F_USER_BUILD_ID bits (0x09ff)",
            )),
            (Self::RedirectMap, 2) => Some((
                0x1b,
                "helper 'bpf_redirect_map' requires arg2 flags to contain only fallback return-code bits plus BPF_F_BROADCAST/BPF_F_EXCLUDE_INGRESS (0x1b)",
            )),
            (Self::L3CsumReplace, 4) => Some((
                BPF_F_HDR_FIELD_MASK,
                "helper 'bpf_l3_csum_replace' requires arg4 flags to contain only BPF_F_HDR_FIELD_MASK bits (0x0f)",
            )),
            (Self::L4CsumReplace, 4) => Some((
                BPF_F_L4_CSUM_REPLACE_ALLOWED_MASK,
                "helper 'bpf_l4_csum_replace' requires arg4 flags to contain only BPF_F_MARK_MANGLED_0/BPF_F_MARK_ENFORCE/BPF_F_PSEUDO_HDR/BPF_F_HDR_FIELD_MASK/BPF_F_IPV6 bits (0xff)",
            )),
            (Self::FibLookup, 3) => Some((
                0x3f,
                "helper 'bpf_fib_lookup' requires arg3 flags to contain only modeled BPF_FIB_LOOKUP_* bits (0x3f)",
            )),
            (Self::CheckMtu, 4) => Some((
                0x01,
                "helper 'bpf_check_mtu' requires arg4 flags to contain only BPF_MTU_CHK_SEGS (0x01)",
            )),
            (Self::SkbAdjustRoom, 3) => Some((
                BPF_F_ADJ_ROOM_ALLOWED_MASK,
                "helper 'bpf_skb_adjust_room' requires arg3 flags to contain only modeled BPF_F_ADJ_ROOM_* bits (0x1ff plus BPF_F_ADJ_ROOM_ENCAP_L2(len))",
            )),
            (Self::LoadHdrOpt, 3) => Some((
                0x01,
                "helper 'bpf_load_hdr_opt' requires arg3 flags to contain only BPF_LOAD_HDR_OPT_TCP_SYN (0x01)",
            )),
            _ => None,
        }
    }

    pub const fn scalar_arg_bit_combination_requirements(
        self,
        arg_idx: usize,
    ) -> &'static [ScalarArgBitCombinationRequirement] {
        match (self, arg_idx) {
            (Self::FibLookup, 3) => FIB_LOOKUP_FLAG_COMBINATIONS,
            (Self::SkbAdjustRoom, 3) => SKB_ADJUST_ROOM_FLAG_COMBINATIONS,
            (Self::L3CsumReplace | Self::L4CsumReplace, 4) => CSUM_REPLACE_HDR_FIELD_COMBINATIONS,
            _ => &[],
        }
    }

    pub const fn zero_scalar_arg_requirement_when_arg_const(
        self,
    ) -> Option<(usize, usize, i64, &'static str)> {
        match self {
            Self::CheckMtu => Some((
                3,
                4,
                BPF_MTU_CHK_SEGS,
                "helper 'bpf_check_mtu' requires arg3 len_diff to be 0 when arg4 has BPF_MTU_CHK_SEGS",
            )),
            _ => None,
        }
    }

    pub const fn scalar_arg_const_requirements_when_arg_const(
        self,
    ) -> &'static [ScalarArgConstRequirementWhenArgConst] {
        match self {
            Self::LwtSeg6Action => LWT_SEG6_ACTION_PARAM_LEN_REQUIREMENTS,
            _ => &[],
        }
    }

    pub const fn scalar_arg_const_requirements_when_arg_masked_const(
        self,
    ) -> &'static [ScalarArgConstRequirementWhenArgMaskedConst] {
        match self {
            Self::L3CsumReplace | Self::L4CsumReplace => CSUM_REPLACE_FROM_REQUIREMENTS,
            _ => &[],
        }
    }

    pub const fn scalar_arg_greater_than_requirements(
        self,
    ) -> &'static [ScalarArgGreaterThanRequirement] {
        match self {
            Self::MsgPullData => MSG_PULL_DATA_ARG_ORDER_REQUIREMENTS,
            _ => &[],
        }
    }

    pub const fn scalar_arg_allowed_values_requirement(
        self,
        arg_idx: usize,
    ) -> Option<(&'static [i64], &'static str)> {
        match (self, arg_idx) {
            (Self::Strtol, 2) => Some((
                STRTOX_BASE_FLAGS,
                "helper 'bpf_strtol' requires arg2 flags to be one of 0, 8, 10, or 16",
            )),
            (Self::Strtoul, 2) => Some((
                STRTOX_BASE_FLAGS,
                "helper 'bpf_strtoul' requires arg2 flags to be one of 0, 8, 10, or 16",
            )),
            (Self::SkbGetTunnelKey, 3) => Some((
                SKB_GET_TUNNEL_KEY_FLAGS,
                "helper 'bpf_skb_get_tunnel_key' requires arg3 flags to be one of 0, BPF_F_TUNINFO_IPV6, BPF_F_TUNINFO_FLAGS, or both",
            )),
            (Self::SkbGetTunnelKey | Self::SkbSetTunnelKey, 2) => Some((
                SKB_TUNNEL_KEY_SIZES,
                "skb tunnel key helpers require arg2 size to be one of 8, 22, 24, 28, or 44 bytes",
            )),
            (Self::SkbChangeProto, 1) => Some((
                SKB_CHANGE_PROTO_PROTOCOLS,
                "helper 'bpf_skb_change_proto' requires arg1 proto to be ETH_P_IP or ETH_P_IPV6",
            )),
            (Self::MapUpdateElem, 3) => Some((
                MAP_UPDATE_FLAGS,
                "helper 'bpf_map_update_elem' requires arg3 flags to be BPF_ANY, BPF_NOEXIST, or BPF_EXIST",
            )),
            (Self::SockMapUpdate | Self::SockHashUpdate, 3) => Some((
                MAP_UPDATE_FLAGS,
                "socket map update helpers require arg3 flags to be BPF_ANY, BPF_NOEXIST, or BPF_EXIST",
            )),
            (Self::MapPushElem, 2) => Some((
                MAP_PUSH_FLAGS,
                "helper 'bpf_map_push_elem' requires arg2 flags to be 0 or BPF_EXIST",
            )),
            (Self::TimerInit, 2) => Some((
                TIMER_INIT_FLAGS,
                "helper 'bpf_timer_init' requires arg2 flags to be CLOCK_REALTIME, CLOCK_MONOTONIC, or CLOCK_BOOTTIME",
            )),
            (Self::LwtSeg6Action, 1) => Some((
                LWT_SEG6_ACTIONS,
                "helper 'bpf_lwt_seg6_action' requires arg1 action to be SEG6_LOCAL_ACTION_END_X, SEG6_LOCAL_ACTION_END_T, SEG6_LOCAL_ACTION_END_B6, or SEG6_LOCAL_ACTION_END_B6_ENCAP",
            )),
            (Self::CsumLevel, 1) => Some((
                BPF_CSUM_LEVELS,
                "helper 'bpf_csum_level' requires arg1 level to be BPF_CSUM_LEVEL_QUERY, BPF_CSUM_LEVEL_INC, BPF_CSUM_LEVEL_DEC, or BPF_CSUM_LEVEL_RESET",
            )),
            _ => None,
        }
    }

    pub const fn scalar_arg_const_requirement(self) -> Option<(usize, i64, &'static str)> {
        match self {
            Self::PerfProgReadValue => Some((
                2,
                24,
                "helper 'bpf_perf_prog_read_value' requires arg2 = 24",
            )),
            Self::PerfEventReadValue => Some((
                3,
                24,
                "helper 'bpf_perf_event_read_value' requires arg3 = 24",
            )),
            Self::GetNsCurrentPidTgid => Some((
                3,
                8,
                "helper 'bpf_get_ns_current_pid_tgid' requires arg3 = 8",
            )),
            Self::SnprintfBtf => Some((3, 16, "helper 'bpf_snprintf_btf' requires arg3 = 16")),
            Self::SeqPrintfBtf => Some((2, 16, "helper 'bpf_seq_printf_btf' requires arg2 = 16")),
            Self::GetLocalStorage => Some((
                1,
                0,
                "helper 'bpf_get_local_storage' requires arg1 flags to be 0",
            )),
            _ => None,
        }
    }

    pub const fn scalar_arg_known_const_requirement(self, arg_idx: usize) -> Option<&'static str> {
        match (self, arg_idx) {
            (Self::DynptrData, 2) => Some("helper 'bpf_dynptr_data' arg2 must be known constant"),
            (Self::SkbGetTunnelKey | Self::SkbSetTunnelKey, 2) => {
                Some("skb tunnel key helpers require arg2 size to be a known constant")
            }
            _ => None,
        }
    }

    pub const fn dynptr_arg_role(self, arg_idx: usize) -> Option<HelperDynptrArgRole> {
        match (self, arg_idx) {
            (Self::DynptrFromMem, 3) => Some(HelperDynptrArgRole::Out),
            (Self::RingbufReserveDynptr, 3) => Some(HelperDynptrArgRole::RingbufReservationOut),
            (Self::RingbufSubmitDynptr | Self::RingbufDiscardDynptr, 0) => {
                Some(HelperDynptrArgRole::RingbufReservationRelease)
            }
            (Self::DynptrRead, 2) | (Self::DynptrWrite, 0) | (Self::DynptrData, 0) => {
                Some(HelperDynptrArgRole::In)
            }
            _ => None,
        }
    }

    pub const fn helper_map_arg_kind(self, arg_idx: usize) -> Option<MapKind> {
        match (self, arg_idx) {
            (Self::TailCall, 1) => Some(MapKind::ProgArray),
            (Self::PerfEventOutput | Self::SkbOutput | Self::XdpOutput, 1) => {
                Some(MapKind::PerfEventArray)
            }
            (Self::PerfEventRead | Self::PerfEventReadValue, 0) => Some(MapKind::PerfEventArray),
            (Self::GetStackId, 1) => Some(MapKind::StackTrace),
            (Self::SkbUnderCgroup, 1) | (Self::CurrentTaskUnderCgroup, 0) => {
                Some(MapKind::CgroupArray)
            }
            (
                Self::RingbufOutput
                | Self::RingbufReserve
                | Self::RingbufReserveDynptr
                | Self::RingbufQuery,
                0,
            ) => Some(MapKind::RingBuf),
            (Self::UserRingbufDrain, 0) => Some(MapKind::UserRingBuf),
            (Self::SkRedirectMap | Self::SockMapUpdate | Self::MsgRedirectMap, 1) => {
                Some(MapKind::SockMap)
            }
            (Self::SockHashUpdate | Self::MsgRedirectHash | Self::SkRedirectHash, 1) => {
                Some(MapKind::SockHash)
            }
            (Self::SkSelectReuseport, 1) => Some(MapKind::ReuseportSockArray),
            (Self::SkStorageGet | Self::SkStorageDelete, 0) => Some(MapKind::SkStorage),
            (Self::TaskStorageGet | Self::TaskStorageDelete, 0) => Some(MapKind::TaskStorage),
            (Self::InodeStorageGet | Self::InodeStorageDelete, 0) => Some(MapKind::InodeStorage),
            (Self::CgrpStorageGet | Self::CgrpStorageDelete, 0) => Some(MapKind::CgrpStorage),
            (Self::GetLocalStorage, 0) => Some(MapKind::DeprecatedCgroupStorage),
            _ => None,
        }
    }

    pub const fn local_storage_get_for_map_kind(map_kind: MapKind) -> Option<Self> {
        match map_kind {
            MapKind::SkStorage => Some(Self::SkStorageGet),
            MapKind::InodeStorage => Some(Self::InodeStorageGet),
            MapKind::TaskStorage => Some(Self::TaskStorageGet),
            MapKind::CgrpStorage => Some(Self::CgrpStorageGet),
            _ => None,
        }
    }

    pub const fn local_storage_delete_for_map_kind(map_kind: MapKind) -> Option<Self> {
        match map_kind {
            MapKind::SkStorage => Some(Self::SkStorageDelete),
            MapKind::InodeStorage => Some(Self::InodeStorageDelete),
            MapKind::TaskStorage => Some(Self::TaskStorageDelete),
            MapKind::CgrpStorage => Some(Self::CgrpStorageDelete),
            _ => None,
        }
    }

    pub const fn socket_map_update_for_map_kind(map_kind: MapKind) -> Option<Self> {
        match map_kind {
            MapKind::SockMap => Some(Self::SockMapUpdate),
            MapKind::SockHash => Some(Self::SockHashUpdate),
            _ => None,
        }
    }

    pub const fn local_helper_map_arg_index(self) -> Option<usize> {
        match self {
            Self::TailCall
            | Self::PerfEventOutput
            | Self::GetStackId
            | Self::SkbUnderCgroup
            | Self::SkbOutput
            | Self::XdpOutput => Some(1),
            Self::CurrentTaskUnderCgroup => Some(0),
            Self::RingbufOutput
            | Self::RingbufReserve
            | Self::RingbufReserveDynptr
            | Self::RingbufQuery
            | Self::UserRingbufDrain
            | Self::ForEachMapElem
            | Self::MapLookupPercpuElem
            | Self::MapPushElem
            | Self::MapPopElem
            | Self::MapPeekElem
            | Self::RedirectMap => Some(0),
            Self::TimerInit => Some(1),
            Self::SkRedirectMap
            | Self::SockMapUpdate
            | Self::MsgRedirectMap
            | Self::SockHashUpdate
            | Self::MsgRedirectHash
            | Self::SkRedirectHash
            | Self::SkSelectReuseport => Some(1),
            Self::SkStorageGet
            | Self::SkStorageDelete
            | Self::TaskStorageGet
            | Self::TaskStorageDelete
            | Self::InodeStorageGet
            | Self::InodeStorageDelete
            | Self::CgrpStorageGet
            | Self::CgrpStorageDelete
            | Self::GetLocalStorage => Some(0),
            Self::PerfEventRead | Self::PerfEventReadValue => Some(0),
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
                Self::MapLookupPercpuElem => Some(HelperExplicitMapKindFamily::PerCpuLookupMap),
                Self::ForEachMapElem => Some(HelperExplicitMapKindFamily::ForEachMapElem),
                Self::TimerInit => Some(HelperExplicitMapKindFamily::TimerMap),
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
                | Self::SkbChangeProto
                | Self::LwtPushEncap
                | Self::LwtSeg6Action
                | Self::LwtSeg6AdjustSrh
                | Self::LwtSeg6StoreBytes
                | Self::SkbVlanPush
                | Self::SkbVlanPop
                | Self::MsgPopData
                | Self::MsgPushData
                | Self::StoreHdrOpt
                | Self::XdpAdjustHead
                | Self::XdpAdjustMeta
                | Self::SkbAdjustRoom
                | Self::XdpAdjustTail
                | Self::MsgPullData
                | Self::TailCall
        )
    }

    pub const fn changes_packet_data_in_subprogram(self) -> bool {
        self.invalidates_packet_pointers()
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
    Subprogram,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperExplicitMapKindFamily {
    QueueStack,
    QueueStackBloom,
    RedirectMap,
    PerCpuLookupMap,
    ForEachMapElem,
    TimerMap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperRetKind {
    Scalar,
    Void,
    PointerNonNull,
    PointerMaybeNull,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KfuncArgKind {
    Scalar,
    Pointer,
    Subprogram,
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
    XfrmState,
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
            KfuncRefKind::XfrmState => "xfrm_state",
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

#[path = "instruction/kfunc_metadata.rs"]
mod kfunc_metadata;

#[path = "instruction/ref_kinds.rs"]
mod ref_kinds;

pub use kfunc_metadata::KfuncCompatibilityRequirement;
pub use kfunc_signature::unknown_kfunc_signature_message;
pub use ref_kinds::{
    HelperNamedArgShape, KfuncAllowedPtrSpaces, KfuncIterFamily, KfuncIterLifecycleOp,
    KfuncPtrArgRule, KfuncSemantics, KfuncUnknownDynptrArg, KfuncUnknownDynptrArgRole,
    KfuncUnknownDynptrCopy, KfuncUnknownIterLifecycle, KfuncUnknownStackObjectCopy,
    KfuncUnknownStackObjectLifecycle, KfuncUnknownStackObjectLifecycleOp, helper_acquire_ref_kind,
    helper_named_arg_shape, helper_pointer_arg_ref_kind, helper_release_ref_kind,
    kfunc_acquire_ref_kind, kfunc_allowed_while_lock_held, kfunc_arg_accepts_skb_pointee_name,
    kfunc_arg_pointee_mismatch, kfunc_arg_requires_known_zero,
    kfunc_arg_requires_skb_context_or_pointer, kfunc_bpf_spin_lock_protected_graph_root_arg,
    kfunc_iter_lifecycle, kfunc_pointer_arg_allows_const_zero, kfunc_pointer_arg_fixed_size,
    kfunc_pointer_arg_min_access_size, kfunc_pointer_arg_ref_kind,
    kfunc_pointer_arg_requires_kernel, kfunc_pointer_arg_requires_raw_context,
    kfunc_pointer_arg_requires_stack, kfunc_pointer_arg_requires_stack_or_map,
    kfunc_pointer_arg_requires_stack_slot_base, kfunc_pointer_arg_requires_user,
    kfunc_pointer_arg_size_from_scalar, kfunc_ref_kind_from_bpf_type_name,
    kfunc_release_ref_arg_index, kfunc_release_ref_kind, kfunc_requires_bpf_spin_lock_held,
    kfunc_scalar_arg_requires_known_const, kfunc_scalar_arg_requires_positive, kfunc_semantics,
    kfunc_supports_local_map_fd, kfunc_unknown_dynptr_args, kfunc_unknown_dynptr_copy,
    kfunc_unknown_iter_lifecycle, kfunc_unknown_stack_object_copy,
    kfunc_unknown_stack_object_lifecycle,
};

#[path = "instruction/helper_metadata.rs"]
mod helper_metadata;

pub use helper_metadata::HelperCompatibilityRequirement;

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
    pub const ARSH64_IMM: u8 = BPF_ALU64 | BPF_ARSH | BPF_K; // 0xc7
    pub const ARSH64_REG: u8 = BPF_ALU64 | BPF_ARSH | BPF_X; // 0xcf
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
