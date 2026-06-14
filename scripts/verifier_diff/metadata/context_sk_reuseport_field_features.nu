const KERNEL_FEATURE_CTX_SK_REUSEPORT_PACKET_LEN = {
    key: "ctx:packet_len"
    min_kernel: "4.19"
    source: "https://github.com/torvalds/linux/blob/v4.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SK_REUSEPORT_DATA = {
    key: "ctx:data"
    min_kernel: "4.19"
    source: "https://github.com/torvalds/linux/blob/v4.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SK_REUSEPORT_DATA_END = {
    key: "ctx:data_end"
    min_kernel: "4.19"
    source: "https://github.com/torvalds/linux/blob/v4.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SK_REUSEPORT_ETH_PROTOCOL = {
    key: "ctx:eth_protocol"
    min_kernel: "4.19"
    source: "https://github.com/torvalds/linux/blob/v4.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SK_REUSEPORT_PROTOCOL = {
    key: "ctx:protocol"
    min_kernel: "4.19"
    source: "https://github.com/torvalds/linux/blob/v4.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SK_REUSEPORT_BIND_INANY = {
    key: "ctx:bind_inany"
    min_kernel: "4.19"
    source: "https://github.com/torvalds/linux/blob/v4.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SK_REUSEPORT_HASH = {
    key: "ctx:hash"
    min_kernel: "4.19"
    source: "https://github.com/torvalds/linux/blob/v4.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SK_REUSEPORT_SK = {
    key: "ctx:sk"
    min_kernel: "5.14"
    source: "https://github.com/torvalds/linux/blob/v5.14/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SK_REUSEPORT_MIGRATING_SK = {
    key: "ctx:migrating_sk"
    min_kernel: "5.14"
    source: "https://github.com/torvalds/linux/blob/v5.14/include/uapi/linux/bpf.h"
}
