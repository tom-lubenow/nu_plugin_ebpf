const KERNEL_FEATURE_CTX_XDP_PACKET_LEN = {
    key: "ctx:packet_len"
    min_kernel: "4.8"
    source: "https://github.com/torvalds/linux/blob/v4.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_XDP_DATA = {
    key: "ctx:data"
    min_kernel: "4.8"
    source: "https://github.com/torvalds/linux/blob/v4.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_XDP_DATA_END = {
    key: "ctx:data_end"
    min_kernel: "4.8"
    source: "https://github.com/torvalds/linux/blob/v4.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_XDP_INGRESS_IFINDEX = {
    key: "ctx:ingress_ifindex"
    min_kernel: "4.16"
    source: "https://github.com/torvalds/linux/blob/v4.16/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_XDP_RX_QUEUE_INDEX = {
    key: "ctx:rx_queue_index"
    min_kernel: "4.16"
    source: "https://github.com/torvalds/linux/blob/v4.16/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_DATA_META = {
    key: "ctx:data_meta"
    min_kernel: "4.15"
    source: "https://github.com/torvalds/linux/blob/v4.15/include/uapi/linux/bpf.h"
}
