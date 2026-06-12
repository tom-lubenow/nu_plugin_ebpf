const KERNEL_FEATURE_BPF_PROBE_READ = {
    key: "helper:bpf_probe_read"
    min_kernel: "4.1"
    source: "https://github.com/torvalds/linux/blob/v4.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_PROBE_READ_STR = {
    key: "helper:bpf_probe_read_str"
    min_kernel: "4.11"
    source: "https://github.com/torvalds/linux/blob/v4.11/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_PROBE_READ_USER = {
    key: "helper:bpf_probe_read_user"
    min_kernel: "5.5"
    source: "https://github.com/torvalds/linux/blob/v5.5/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_PROBE_READ_KERNEL = {
    key: "helper:bpf_probe_read_kernel"
    min_kernel: "5.5"
    source: "https://github.com/torvalds/linux/blob/v5.5/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_PROBE_READ_USER_STR = {
    key: "helper:bpf_probe_read_user_str"
    min_kernel: "5.5"
    source: "https://github.com/torvalds/linux/blob/v5.5/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_PROBE_READ_KERNEL_STR = {
    key: "helper:bpf_probe_read_kernel_str"
    min_kernel: "5.5"
    source: "https://github.com/torvalds/linux/blob/v5.5/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_GET_PRANDOM_U32 = {
    key: "helper:bpf_get_prandom_u32"
    min_kernel: "4.1"
    source: "https://github.com/torvalds/linux/blob/v4.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_RINGBUF_QUERY = {
    key: "helper:bpf_ringbuf_query"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_RINGBUF_OUTPUT = {
    key: "helper:bpf_ringbuf_output"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_RINGBUF_RESERVE = {
    key: "helper:bpf_ringbuf_reserve"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_RINGBUF_SUBMIT = {
    key: "helper:bpf_ringbuf_submit"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_RINGBUF_DISCARD = {
    key: "helper:bpf_ringbuf_discard"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_GET_STACKID = {
    key: "helper:bpf_get_stackid"
    min_kernel: "4.6"
    source: "https://github.com/torvalds/linux/blob/v4.6/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_GET_STACK = {
    key: "helper:bpf_get_stack"
    min_kernel: "4.18"
    source: "https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SKB_UNDER_CGROUP = {
    key: "helper:bpf_skb_under_cgroup"
    min_kernel: "4.8"
    source: "https://github.com/torvalds/linux/blob/v4.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_CURRENT_TASK_UNDER_CGROUP = {
    key: "helper:bpf_current_task_under_cgroup"
    min_kernel: "4.9"
    source: "https://github.com/torvalds/linux/blob/v4.9/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SKB_LOAD_BYTES = {
    key: "helper:bpf_skb_load_bytes"
    min_kernel: "4.5"
    source: "https://github.com/torvalds/linux/blob/v4.5/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_FIB_LOOKUP = {
    key: "helper:bpf_fib_lookup"
    min_kernel: "4.18"
    source: "https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_CSUM_DIFF = {
    key: "helper:bpf_csum_diff"
    min_kernel: "4.6"
    source: "https://github.com/torvalds/linux/blob/v4.6/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_GET_HASH_RECALC = {
    key: "helper:bpf_get_hash_recalc"
    min_kernel: "4.8"
    source: "https://github.com/torvalds/linux/blob/v4.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_CSUM_LEVEL = {
    key: "helper:bpf_csum_level"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_REDIRECT_NEIGH = {
    key: "helper:bpf_redirect_neigh"
    min_kernel: "5.10"
    source: "https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_REDIRECT_PEER = {
    key: "helper:bpf_redirect_peer"
    min_kernel: "5.10"
    source: "https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_LOAD_HDR_OPT = {
    key: "helper:bpf_load_hdr_opt"
    min_kernel: "5.10"
    source: "https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_STORE_HDR_OPT = {
    key: "helper:bpf_store_hdr_opt"
    min_kernel: "5.10"
    source: "https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_RESERVE_HDR_OPT = {
    key: "helper:bpf_reserve_hdr_opt"
    min_kernel: "5.10"
    source: "https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SOCK_OPS_CB_FLAGS_SET = {
    key: "helper:bpf_sock_ops_cb_flags_set"
    min_kernel: "4.16"
    source: "https://github.com/torvalds/linux/blob/v4.16/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_XDP_ADJUST_HEAD = {
    key: "helper:bpf_xdp_adjust_head"
    min_kernel: "4.10"
    source: "https://github.com/torvalds/linux/blob/v4.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_XDP_ADJUST_META = {
    key: "helper:bpf_xdp_adjust_meta"
    min_kernel: "4.15"
    source: "https://github.com/torvalds/linux/blob/v4.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_XDP_ADJUST_TAIL = {
    key: "helper:bpf_xdp_adjust_tail"
    min_kernel: "4.18"
    source: "https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_XDP_GET_BUFF_LEN = {
    key: "helper:bpf_xdp_get_buff_len"
    min_kernel: "5.18"
    source: "https://github.com/torvalds/linux/blob/v5.18/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_REDIRECT = {
    key: "helper:bpf_redirect"
    min_kernel: "4.4"
    source: "https://github.com/torvalds/linux/blob/v4.4/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_REDIRECT_MAP = {
    key: "helper:bpf_redirect_map"
    min_kernel: "4.14"
    source: "https://github.com/torvalds/linux/blob/v4.14/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_CHECK_MTU = {
    key: "helper:bpf_check_mtu"
    min_kernel: "5.12"
    source: "https://github.com/torvalds/linux/blob/v5.12/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_TAIL_CALL = {
    key: "helper:bpf_tail_call"
    min_kernel: "4.2"
    source: "https://github.com/torvalds/linux/blob/v4.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_PERF_EVENT_READ = {
    key: "helper:bpf_perf_event_read"
    min_kernel: "4.3"
    source: "https://github.com/torvalds/linux/blob/v4.3/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_PERF_EVENT_READ_VALUE = {
    key: "helper:bpf_perf_event_read_value"
    min_kernel: "4.15"
    source: "https://github.com/torvalds/linux/blob/v4.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_PERF_PROG_READ_VALUE = {
    key: "helper:bpf_perf_prog_read_value"
    min_kernel: "4.15"
    source: "https://github.com/torvalds/linux/blob/v4.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_OVERRIDE_RETURN = {
    key: "helper:bpf_override_return"
    min_kernel: "4.16"
    source: "https://github.com/torvalds/linux/blob/v4.16/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SYS_BPF = {
    key: "helper:bpf_sys_bpf"
    min_kernel: "5.14"
    source: "https://github.com/torvalds/linux/blob/v5.14/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SYS_CLOSE = {
    key: "helper:bpf_sys_close"
    min_kernel: "5.14"
    source: "https://github.com/torvalds/linux/blob/v5.14/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_BTF_FIND_BY_NAME_KIND = {
    key: "helper:bpf_btf_find_by_name_kind"
    min_kernel: "5.14"
    source: "https://github.com/torvalds/linux/blob/v5.14/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_GET_FUNC_IP = {
    key: "helper:bpf_get_func_ip"
    min_kernel: "5.15"
    source: "https://github.com/torvalds/linux/blob/v5.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_GET_ATTACH_COOKIE = {
    key: "helper:bpf_get_attach_cookie"
    min_kernel: "5.15"
    source: "https://github.com/torvalds/linux/blob/v5.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_KALLSYMS_LOOKUP_NAME = {
    key: "helper:bpf_kallsyms_lookup_name"
    min_kernel: "5.16"
    source: "https://github.com/torvalds/linux/blob/v5.16/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_BPRM_OPTS_SET = {
    key: "helper:bpf_bprm_opts_set"
    min_kernel: "5.11"
    source: "https://github.com/torvalds/linux/blob/v5.11/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_GET_CURRENT_TASK_BTF = {
    key: "helper:bpf_get_current_task_btf"
    min_kernel: "5.11"
    source: "https://github.com/torvalds/linux/blob/v5.11/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_TASK_PT_REGS = {
    key: "helper:bpf_task_pt_regs"
    min_kernel: "5.15"
    source: "https://github.com/torvalds/linux/blob/v5.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SPIN_LOCK = {
    key: "helper:bpf_spin_lock"
    min_kernel: "5.1"
    source: "https://github.com/torvalds/linux/blob/v5.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SPIN_UNLOCK = {
    key: "helper:bpf_spin_unlock"
    min_kernel: "5.1"
    source: "https://github.com/torvalds/linux/blob/v5.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SK_ASSIGN = {
    key: "helper:bpf_sk_assign"
    min_kernel: "5.7"
    source: "https://github.com/torvalds/linux/blob/v5.7/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SK_LOOKUP_TCP = {
    key: "helper:bpf_sk_lookup_tcp"
    min_kernel: "4.20"
    source: "https://github.com/torvalds/linux/blob/v4.20/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SK_LOOKUP_UDP = {
    key: "helper:bpf_sk_lookup_udp"
    min_kernel: "4.20"
    source: "https://github.com/torvalds/linux/blob/v4.20/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SK_RELEASE = {
    key: "helper:bpf_sk_release"
    min_kernel: "4.20"
    source: "https://github.com/torvalds/linux/blob/v4.20/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SKC_LOOKUP_TCP = {
    key: "helper:bpf_skc_lookup_tcp"
    min_kernel: "5.2"
    source: "https://github.com/torvalds/linux/blob/v5.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SYSCTL_SET_NEW_VALUE = {
    key: "helper:bpf_sysctl_set_new_value"
    min_kernel: "5.2"
    source: "https://github.com/torvalds/linux/blob/v5.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SYSCTL_GET_NAME = {
    key: "helper:bpf_sysctl_get_name"
    min_kernel: "5.2"
    source: "https://github.com/torvalds/linux/blob/v5.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SYSCTL_GET_CURRENT_VALUE = {
    key: "helper:bpf_sysctl_get_current_value"
    min_kernel: "5.2"
    source: "https://github.com/torvalds/linux/blob/v5.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SYSCTL_GET_NEW_VALUE = {
    key: "helper:bpf_sysctl_get_new_value"
    min_kernel: "5.2"
    source: "https://github.com/torvalds/linux/blob/v5.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_GET_FUNC_ARG_CNT = {
    key: "helper:bpf_get_func_arg_cnt"
    min_kernel: "5.17"
    source: "https://github.com/torvalds/linux/blob/v5.17/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_MSG_APPLY_BYTES = {
    key: "helper:bpf_msg_apply_bytes"
    min_kernel: "4.17"
    source: "https://github.com/torvalds/linux/blob/v4.17/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_MSG_CORK_BYTES = {
    key: "helper:bpf_msg_cork_bytes"
    min_kernel: "4.17"
    source: "https://github.com/torvalds/linux/blob/v4.17/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_MSG_PULL_DATA = {
    key: "helper:bpf_msg_pull_data"
    min_kernel: "4.17"
    source: "https://github.com/torvalds/linux/blob/v4.17/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_MSG_PUSH_DATA = {
    key: "helper:bpf_msg_push_data"
    min_kernel: "4.20"
    source: "https://github.com/torvalds/linux/blob/v4.20/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_MSG_POP_DATA = {
    key: "helper:bpf_msg_pop_data"
    min_kernel: "5.0"
    source: "https://github.com/torvalds/linux/blob/v5.0/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_MSG_REDIRECT_MAP = {
    key: "helper:bpf_msg_redirect_map"
    min_kernel: "4.17"
    source: "https://github.com/torvalds/linux/blob/v4.17/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_MSG_REDIRECT_HASH = {
    key: "helper:bpf_msg_redirect_hash"
    min_kernel: "4.18"
    source: "https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SKB_PULL_DATA = {
    key: "helper:bpf_skb_pull_data"
    min_kernel: "4.9"
    source: "https://github.com/torvalds/linux/blob/v4.9/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SKB_ADJUST_ROOM = {
    key: "helper:bpf_skb_adjust_room"
    min_kernel: "4.13"
    source: "https://github.com/torvalds/linux/blob/v4.13/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SKB_CHANGE_HEAD = {
    key: "helper:bpf_skb_change_head"
    min_kernel: "4.10"
    source: "https://github.com/torvalds/linux/blob/v4.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SKB_CHANGE_TAIL = {
    key: "helper:bpf_skb_change_tail"
    min_kernel: "4.9"
    source: "https://github.com/torvalds/linux/blob/v4.9/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SK_REDIRECT_MAP = {
    key: "helper:bpf_sk_redirect_map"
    min_kernel: "4.14"
    source: "https://github.com/torvalds/linux/blob/v4.14/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SK_REDIRECT_HASH = {
    key: "helper:bpf_sk_redirect_hash"
    min_kernel: "4.18"
    source: "https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SK_SELECT_REUSEPORT = {
    key: "helper:bpf_sk_select_reuseport"
    min_kernel: "4.19"
    source: "https://github.com/torvalds/linux/blob/v4.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_TIMER_INIT = {
    key: "helper:bpf_timer_init"
    min_kernel: "5.15"
    source: "https://github.com/torvalds/linux/blob/v5.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_TIMER_SET_CALLBACK = {
    key: "helper:bpf_timer_set_callback"
    min_kernel: "5.15"
    source: "https://github.com/torvalds/linux/blob/v5.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_TIMER_START = {
    key: "helper:bpf_timer_start"
    min_kernel: "5.15"
    source: "https://github.com/torvalds/linux/blob/v5.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_TIMER_CANCEL = {
    key: "helper:bpf_timer_cancel"
    min_kernel: "5.15"
    source: "https://github.com/torvalds/linux/blob/v5.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_LOOP = {
    key: "helper:bpf_loop"
    min_kernel: "5.17"
    source: "https://github.com/torvalds/linux/blob/v5.17/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_FOR_EACH_MAP_ELEM = {
    key: "helper:bpf_for_each_map_elem"
    min_kernel: "5.13"
    source: "https://github.com/torvalds/linux/blob/v5.13/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SEQ_PRINTF = {
    key: "helper:bpf_seq_printf"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SEQ_WRITE = {
    key: "helper:bpf_seq_write"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_RINGBUF_RESERVE_DYNPTR = {
    key: "helper:bpf_ringbuf_reserve_dynptr"
    min_kernel: "5.19"
    source: "https://github.com/torvalds/linux/blob/v5.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_RINGBUF_SUBMIT_DYNPTR = {
    key: "helper:bpf_ringbuf_submit_dynptr"
    min_kernel: "5.19"
    source: "https://github.com/torvalds/linux/blob/v5.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_RINGBUF_DISCARD_DYNPTR = {
    key: "helper:bpf_ringbuf_discard_dynptr"
    min_kernel: "5.19"
    source: "https://github.com/torvalds/linux/blob/v5.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_DYNPTR_DATA = {
    key: "helper:bpf_dynptr_data"
    min_kernel: "5.19"
    source: "https://github.com/torvalds/linux/blob/v5.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_KFUNC_BPF_DYNPTR_SIZE = {
    key: "kfunc:bpf_dynptr_size"
    min_kernel: "6.5"
    source: "https://github.com/torvalds/linux/blob/v6.5/kernel/bpf/helpers.c"
}
const KERNEL_FEATURE_KFUNC_BPF_DYNPTR_SLICE = {
    key: "kfunc:bpf_dynptr_slice"
    min_kernel: "6.4"
    source: "https://github.com/torvalds/linux/blob/v6.4/kernel/bpf/helpers.c"
}
const KERNEL_FEATURE_KFUNC_BPF_DYNPTR_CLONE = {
    key: "kfunc:bpf_dynptr_clone"
    min_kernel: "6.5"
    source: "https://github.com/torvalds/linux/blob/v6.5/kernel/bpf/helpers.c"
}
