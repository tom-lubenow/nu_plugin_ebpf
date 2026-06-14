const KERNEL_FEATURE_CTX_FLOW_KEYS = {
    key: "ctx:flow_keys"
    min_kernel: "4.20"
    source: "https://github.com/torvalds/linux/blob/v4.20/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_TSTAMP = {
    key: "ctx:tstamp"
    min_kernel: "5.0"
    source: "https://github.com/torvalds/linux/blob/v5.0/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_WIRE_LEN = {
    key: "ctx:wire_len"
    min_kernel: "5.0"
    source: "https://github.com/torvalds/linux/blob/v5.0/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_GSO_SEGS = {
    key: "ctx:gso_segs"
    min_kernel: "5.1"
    source: "https://github.com/torvalds/linux/blob/v5.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_GSO_SIZE = {
    key: "ctx:gso_size"
    min_kernel: "5.7"
    source: "https://github.com/torvalds/linux/blob/v5.7/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_EGRESS_IFINDEX = {
    key: "ctx:egress_ifindex"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SOCK_OPS_PACKET_LEN = {
    key: "ctx:packet_len"
    min_kernel: "5.10"
    source: "https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SOCK_OPS_DATA = {
    key: "ctx:data"
    min_kernel: "5.10"
    source: "https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SOCK_OPS_DATA_END = {
    key: "ctx:data_end"
    min_kernel: "5.10"
    source: "https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SK_LOOKUP_SK = {
    key: "ctx:sk"
    min_kernel: "5.9"
    source: "https://github.com/torvalds/linux/blob/v5.9/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SKB_SK = {
    key: "ctx:sk"
    min_kernel: "5.1"
    source: "https://github.com/torvalds/linux/blob/v5.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SK_SKB_SK = {
    key: "ctx:sk"
    min_kernel: "5.1"
    source: "https://github.com/torvalds/linux/blob/v5.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_CGROUP_SOCK_SK = {
    key: "ctx:sk"
    min_kernel: "4.10"
    source: "https://github.com/torvalds/linux/blob/v4.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_SK = {
    key: "ctx:sk"
    min_kernel: "5.3"
    source: "https://github.com/torvalds/linux/blob/v5.3/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_CGROUP_SOCKOPT_SK = {
    key: "ctx:sk"
    min_kernel: "5.3"
    source: "https://github.com/torvalds/linux/blob/v5.3/include/uapi/linux/bpf.h"
}
