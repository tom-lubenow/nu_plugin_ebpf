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
