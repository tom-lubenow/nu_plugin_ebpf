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
const KERNEL_FEATURE_CTX_CGROUP_SOCK_BOUND_DEV_IF = {
    key: "ctx:bound_dev_if"
    min_kernel: "4.10"
    source: "https://github.com/torvalds/linux/blob/v4.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_CGROUP_SOCK_FAMILY = {
    key: "ctx:family"
    min_kernel: "4.10"
    source: "https://github.com/torvalds/linux/blob/v4.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_CGROUP_SOCK_SOCK_TYPE = {
    key: "ctx:sock_type"
    min_kernel: "4.10"
    source: "https://github.com/torvalds/linux/blob/v4.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_CGROUP_SOCK_PROTOCOL = {
    key: "ctx:protocol"
    min_kernel: "4.10"
    source: "https://github.com/torvalds/linux/blob/v4.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_FAMILY = {
    key: "ctx:family"
    min_kernel: "4.14"
    source: "https://github.com/torvalds/linux/blob/v4.14/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_NAPI_ID = {
    key: "ctx:napi_id"
    min_kernel: "4.14"
    source: "https://github.com/torvalds/linux/blob/v4.14/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_REMOTE_IP4 = {
    key: "ctx:remote_ip4"
    min_kernel: "4.14"
    source: "https://github.com/torvalds/linux/blob/v4.14/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_REMOTE_IP6 = {
    key: "ctx:remote_ip6"
    min_kernel: "4.14"
    source: "https://github.com/torvalds/linux/blob/v4.14/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_REMOTE_PORT = {
    key: "ctx:remote_port"
    min_kernel: "4.14"
    source: "https://github.com/torvalds/linux/blob/v4.14/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_LOCAL_IP4 = {
    key: "ctx:local_ip4"
    min_kernel: "4.14"
    source: "https://github.com/torvalds/linux/blob/v4.14/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_LOCAL_IP6 = {
    key: "ctx:local_ip6"
    min_kernel: "4.14"
    source: "https://github.com/torvalds/linux/blob/v4.14/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_LOCAL_PORT = {
    key: "ctx:local_port"
    min_kernel: "4.14"
    source: "https://github.com/torvalds/linux/blob/v4.14/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_CGROUP_SOCK_MARK = {
    key: "ctx:mark"
    min_kernel: "4.14"
    source: "https://github.com/torvalds/linux/blob/v4.14/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_CGROUP_SOCK_PRIORITY = {
    key: "ctx:priority"
    min_kernel: "4.14"
    source: "https://github.com/torvalds/linux/blob/v4.14/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_DATA_META = {
    key: "ctx:data_meta"
    min_kernel: "4.15"
    source: "https://github.com/torvalds/linux/blob/v4.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_DEVICE_ACCESS_TYPE = {
    key: "ctx:access_type"
    min_kernel: "4.15"
    source: "https://github.com/torvalds/linux/blob/v4.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_DEVICE_ACCESS = {
    key: "ctx:device_access"
    min_kernel: "4.15"
    source: "https://github.com/torvalds/linux/blob/v4.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_DEVICE_TYPE = {
    key: "ctx:device_type"
    min_kernel: "4.15"
    source: "https://github.com/torvalds/linux/blob/v4.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_DEVICE_MAJOR = {
    key: "ctx:major"
    min_kernel: "4.15"
    source: "https://github.com/torvalds/linux/blob/v4.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_DEVICE_MINOR = {
    key: "ctx:minor"
    min_kernel: "4.15"
    source: "https://github.com/torvalds/linux/blob/v4.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_RX_QUEUE_INDEX = {
    key: "ctx:rx_queue_index"
    min_kernel: "4.16"
    source: "https://github.com/torvalds/linux/blob/v4.16/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_CGROUP_SOCK_LOCAL_IP4 = {
    key: "ctx:local_ip4"
    min_kernel: "4.17"
    source: "https://github.com/torvalds/linux/blob/v4.17/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_CGROUP_SOCK_LOCAL_IP6 = {
    key: "ctx:local_ip6"
    min_kernel: "4.17"
    source: "https://github.com/torvalds/linux/blob/v4.17/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_CGROUP_SOCK_LOCAL_PORT = {
    key: "ctx:local_port"
    min_kernel: "4.17"
    source: "https://github.com/torvalds/linux/blob/v4.17/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_CGROUP_SOCK_REMOTE_IP4 = {
    key: "ctx:remote_ip4"
    min_kernel: "5.1"
    source: "https://github.com/torvalds/linux/blob/v5.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_CGROUP_SOCK_REMOTE_IP6 = {
    key: "ctx:remote_ip6"
    min_kernel: "5.1"
    source: "https://github.com/torvalds/linux/blob/v5.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_CGROUP_SOCK_REMOTE_PORT = {
    key: "ctx:remote_port"
    min_kernel: "5.1"
    source: "https://github.com/torvalds/linux/blob/v5.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_CGROUP_SOCK_STATE = {
    key: "ctx:state"
    min_kernel: "5.1"
    source: "https://github.com/torvalds/linux/blob/v5.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_CGROUP_SOCK_RX_QUEUE_MAPPING = {
    key: "ctx:rx_queue_mapping"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_BPF_SOCK_RX_QUEUE_MAPPING = {
    key: "ctx:rx_queue_mapping"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h"
}
