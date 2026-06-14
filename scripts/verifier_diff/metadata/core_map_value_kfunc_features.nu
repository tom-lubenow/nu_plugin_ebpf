const KERNEL_FEATURE_MAP_VALUE_BPF_SPIN_LOCK = {
    key: "map-value:bpf_spin_lock"
    min_kernel: "5.1"
    source: "https://github.com/torvalds/linux/blob/v5.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_VALUE_BPF_TIMER = {
    key: "map-value:bpf_timer"
    min_kernel: "5.15"
    source: "https://github.com/torvalds/linux/blob/v5.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_VALUE_KPTR = {
    key: "map-value:kptr"
    min_kernel: "5.19"
    source: "https://github.com/torvalds/linux/blob/v5.19/kernel/bpf/verifier.c"
}
const KERNEL_FEATURE_MAP_VALUE_BPF_WQ = {
    key: "map-value:bpf_wq"
    min_kernel: "6.10"
    source: "https://github.com/torvalds/linux/blob/v6.10/include/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_VALUE_BPF_REFCOUNT = {
    key: "map-value:bpf_refcount"
    min_kernel: "6.4"
    source: "https://github.com/torvalds/linux/blob/v6.4/kernel/bpf/btf.c"
}
const KERNEL_FEATURE_MAP_VALUE_BPF_LIST_HEAD = {
    key: "map-value:bpf_list_head"
    min_kernel: "6.2"
    source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/btf.c"
}
const KERNEL_FEATURE_MAP_VALUE_BPF_LIST_NODE = {
    key: "map-value:bpf_list_node"
    min_kernel: "6.2"
    source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/btf.c"
}
const KERNEL_FEATURE_MAP_VALUE_BPF_RB_ROOT = {
    key: "map-value:bpf_rb_root"
    min_kernel: "6.4"
    source: "https://github.com/torvalds/linux/blob/v6.4/kernel/bpf/btf.c"
}
const KERNEL_FEATURE_MAP_VALUE_BPF_RB_NODE = {
    key: "map-value:bpf_rb_node"
    min_kernel: "6.4"
    source: "https://github.com/torvalds/linux/blob/v6.4/kernel/bpf/btf.c"
}
const KERNEL_FEATURE_BPF_USER_RINGBUF_DRAIN = {
    key: "helper:bpf_user_ringbuf_drain"
    min_kernel: "6.1"
    source: "https://github.com/torvalds/linux/blob/v6.1/include/uapi/linux/bpf.h"
}
