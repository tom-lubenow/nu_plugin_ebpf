const KERNEL_FEATURE_CTX_SK_LOOKUP_FAMILY = {
    key: "ctx:family"
    min_kernel: "5.9"
    source: "https://github.com/torvalds/linux/blob/v5.9/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SK_LOOKUP_PROTOCOL = {
    key: "ctx:protocol"
    min_kernel: "5.9"
    source: "https://github.com/torvalds/linux/blob/v5.9/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SK_LOOKUP_REMOTE_IP4 = {
    key: "ctx:remote_ip4"
    min_kernel: "5.9"
    source: "https://github.com/torvalds/linux/blob/v5.9/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SK_LOOKUP_REMOTE_IP6 = {
    key: "ctx:remote_ip6"
    min_kernel: "5.9"
    source: "https://github.com/torvalds/linux/blob/v5.9/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SK_LOOKUP_REMOTE_PORT = {
    key: "ctx:remote_port"
    min_kernel: "5.9"
    source: "https://github.com/torvalds/linux/blob/v5.9/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SK_LOOKUP_LOCAL_IP4 = {
    key: "ctx:local_ip4"
    min_kernel: "5.9"
    source: "https://github.com/torvalds/linux/blob/v5.9/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SK_LOOKUP_LOCAL_IP6 = {
    key: "ctx:local_ip6"
    min_kernel: "5.9"
    source: "https://github.com/torvalds/linux/blob/v5.9/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SK_LOOKUP_LOCAL_PORT = {
    key: "ctx:local_port"
    min_kernel: "5.9"
    source: "https://github.com/torvalds/linux/blob/v5.9/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SK_LOOKUP_COOKIE = {
    key: "ctx:cookie"
    min_kernel: "5.13"
    source: "https://github.com/torvalds/linux/blob/v5.13/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SK_LOOKUP_INGRESS_IFINDEX = {
    key: "ctx:ingress_ifindex"
    min_kernel: "5.17"
    source: "https://github.com/torvalds/linux/blob/v5.17/include/uapi/linux/bpf.h"
}
