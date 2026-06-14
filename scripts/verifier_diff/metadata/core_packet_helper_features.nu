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
