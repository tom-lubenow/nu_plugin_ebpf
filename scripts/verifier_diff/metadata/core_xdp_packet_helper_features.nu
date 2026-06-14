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
