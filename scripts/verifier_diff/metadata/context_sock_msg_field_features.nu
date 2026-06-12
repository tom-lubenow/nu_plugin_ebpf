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
const KERNEL_FEATURE_CTX_SK_MSG_DATA = {
    key: "ctx:data"
    min_kernel: "4.17"
    source: "https://github.com/torvalds/linux/blob/v4.17/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SK_MSG_DATA_END = {
    key: "ctx:data_end"
    min_kernel: "4.17"
    source: "https://github.com/torvalds/linux/blob/v4.17/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SK_MSG_FAMILY = {
    key: "ctx:family"
    min_kernel: "4.18"
    source: "https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SK_MSG_REMOTE_IP4 = {
    key: "ctx:remote_ip4"
    min_kernel: "4.18"
    source: "https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SK_MSG_REMOTE_IP6 = {
    key: "ctx:remote_ip6"
    min_kernel: "4.18"
    source: "https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SK_MSG_REMOTE_PORT = {
    key: "ctx:remote_port"
    min_kernel: "4.18"
    source: "https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SK_MSG_LOCAL_IP4 = {
    key: "ctx:local_ip4"
    min_kernel: "4.18"
    source: "https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SK_MSG_LOCAL_IP6 = {
    key: "ctx:local_ip6"
    min_kernel: "4.18"
    source: "https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SK_MSG_LOCAL_PORT = {
    key: "ctx:local_port"
    min_kernel: "4.18"
    source: "https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SK_MSG_PACKET_LEN = {
    key: "ctx:packet_len"
    min_kernel: "5.0"
    source: "https://github.com/torvalds/linux/blob/v5.0/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SK_MSG_SK = {
    key: "ctx:sk"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h"
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
