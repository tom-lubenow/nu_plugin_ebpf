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
