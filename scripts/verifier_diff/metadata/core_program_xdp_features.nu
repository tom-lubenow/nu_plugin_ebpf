const KERNEL_FEATURE_PROG_XDP = {
    key: "program:BPF_PROG_TYPE_XDP"
    min_kernel: "4.8"
    source: "https://github.com/torvalds/linux/blob/v4.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_XDP_ATTACH_SKB = {
    key: "attach:xdp-skb"
    min_kernel: "4.12"
    source: "https://github.com/torvalds/linux/blob/v4.12/include/uapi/linux/if_link.h"
}
const KERNEL_FEATURE_XDP_ATTACH_DRV = {
    key: "attach:xdp-drv"
    min_kernel: "4.12"
    source: "https://github.com/torvalds/linux/blob/v4.12/include/uapi/linux/if_link.h"
}
const KERNEL_FEATURE_XDP_ATTACH_HW = {
    key: "attach:xdp-hw"
    min_kernel: "4.13"
    source: "https://github.com/torvalds/linux/blob/v4.13/include/uapi/linux/if_link.h"
}
const KERNEL_FEATURE_XDP_ATTACH_DEVMAP = {
    key: "attach:BPF_XDP_DEVMAP"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_XDP_ATTACH_CPUMAP = {
    key: "attach:BPF_XDP_CPUMAP"
    min_kernel: "5.9"
    source: "https://github.com/torvalds/linux/blob/v5.9/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_XDP_MULTI_BUFFER = {
    key: "section:xdp.frags"
    min_kernel: "5.18"
    source: "https://github.com/torvalds/linux/blob/v5.18/include/uapi/linux/bpf.h"
}
