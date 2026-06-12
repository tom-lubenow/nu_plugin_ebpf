const VERIFIER_DIFF_CONTEXT_METADATA_DIR = (path self | path dirname)
const KERNEL_FEATURE_CTX_PACKET_LEN = {
    key: "ctx:packet_len"
    min_kernel: "4.1"
    source: "https://github.com/torvalds/linux/blob/v4.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_PKT_TYPE = {
    key: "ctx:pkt_type"
    min_kernel: "4.1"
    source: "https://github.com/torvalds/linux/blob/v4.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_QUEUE_MAPPING = {
    key: "ctx:queue_mapping"
    min_kernel: "4.1"
    source: "https://github.com/torvalds/linux/blob/v4.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_ETH_PROTOCOL = {
    key: "ctx:eth_protocol"
    min_kernel: "4.1"
    source: "https://github.com/torvalds/linux/blob/v4.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_PROTOCOL = {
    key: "ctx:protocol"
    min_kernel: "4.1"
    source: "https://github.com/torvalds/linux/blob/v4.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_VLAN_PRESENT = {
    key: "ctx:vlan_present"
    min_kernel: "4.1"
    source: "https://github.com/torvalds/linux/blob/v4.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_VLAN_TCI = {
    key: "ctx:vlan_tci"
    min_kernel: "4.1"
    source: "https://github.com/torvalds/linux/blob/v4.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_VLAN_PROTO = {
    key: "ctx:vlan_proto"
    min_kernel: "4.1"
    source: "https://github.com/torvalds/linux/blob/v4.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_MARK = {
    key: "ctx:mark"
    min_kernel: "4.1"
    source: "https://github.com/torvalds/linux/blob/v4.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_PRIORITY = {
    key: "ctx:priority"
    min_kernel: "4.1"
    source: "https://github.com/torvalds/linux/blob/v4.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_IFINDEX = {
    key: "ctx:ifindex"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_INGRESS_IFINDEX = {
    key: "ctx:ingress_ifindex"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_TC_INDEX = {
    key: "ctx:tc_index"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_HASH = {
    key: "ctx:hash"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_CB = {
    key: "ctx:cb"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_TC_CLASSID = {
    key: "ctx:tc_classid"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_DATA = {
    key: "ctx:data"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_DATA_END = {
    key: "ctx:data_end"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/include/uapi/linux/bpf.h"
}
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
const KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_FAMILY = {
    key: "ctx:family"
    min_kernel: "4.17"
    source: "https://github.com/torvalds/linux/blob/v4.17/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_SOCK_TYPE = {
    key: "ctx:sock_type"
    min_kernel: "4.17"
    source: "https://github.com/torvalds/linux/blob/v4.17/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_PROTOCOL = {
    key: "ctx:protocol"
    min_kernel: "4.17"
    source: "https://github.com/torvalds/linux/blob/v4.17/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_USER_FAMILY = {
    key: "ctx:user_family"
    min_kernel: "4.17"
    source: "https://github.com/torvalds/linux/blob/v4.17/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_USER_IP4 = {
    key: "ctx:user_ip4"
    min_kernel: "4.17"
    source: "https://github.com/torvalds/linux/blob/v4.17/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_USER_IP6 = {
    key: "ctx:user_ip6"
    min_kernel: "4.17"
    source: "https://github.com/torvalds/linux/blob/v4.17/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_USER_PORT = {
    key: "ctx:user_port"
    min_kernel: "4.17"
    source: "https://github.com/torvalds/linux/blob/v4.17/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_REMOTE_IP4 = {
    key: "ctx:remote_ip4"
    min_kernel: "4.17"
    source: "https://github.com/torvalds/linux/blob/v4.17/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_REMOTE_IP6 = {
    key: "ctx:remote_ip6"
    min_kernel: "4.17"
    source: "https://github.com/torvalds/linux/blob/v4.17/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_REMOTE_PORT = {
    key: "ctx:remote_port"
    min_kernel: "4.17"
    source: "https://github.com/torvalds/linux/blob/v4.17/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_LOCAL_IP4 = {
    key: "ctx:local_ip4"
    min_kernel: "4.17"
    source: "https://github.com/torvalds/linux/blob/v4.17/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_LOCAL_IP6 = {
    key: "ctx:local_ip6"
    min_kernel: "4.17"
    source: "https://github.com/torvalds/linux/blob/v4.17/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_LOCAL_PORT = {
    key: "ctx:local_port"
    min_kernel: "4.17"
    source: "https://github.com/torvalds/linux/blob/v4.17/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_MSG_SRC_IP4 = {
    key: "ctx:msg_src_ip4"
    min_kernel: "4.18"
    source: "https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_MSG_SRC_IP6 = {
    key: "ctx:msg_src_ip6"
    min_kernel: "4.18"
    source: "https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h"
}
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
const KERNEL_FEATURE_CTX_ITER_META = {
    key: "ctx:iter_meta"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/include/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_ITER_TASK = {
    key: "ctx:iter_task"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/kernel/bpf/task_iter.c"
}
const KERNEL_FEATURE_CTX_ITER_TASK_VMA_TASK = {
    key: "ctx:iter_task"
    min_kernel: "5.12"
    source: "https://github.com/torvalds/linux/blob/v5.12/kernel/bpf/task_iter.c"
}
const KERNEL_FEATURE_CTX_ITER_FD = {
    key: "ctx:iter_fd"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/kernel/bpf/task_iter.c"
}
const KERNEL_FEATURE_CTX_ITER_FILE = {
    key: "ctx:iter_file"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/kernel/bpf/task_iter.c"
}
const KERNEL_FEATURE_CTX_ITER_VMA = {
    key: "ctx:iter_vma"
    min_kernel: "5.12"
    source: "https://github.com/torvalds/linux/blob/v5.12/kernel/bpf/task_iter.c"
}
const KERNEL_FEATURE_CTX_ITER_CGROUP = {
    key: "ctx:iter_cgroup"
    min_kernel: "6.1"
    source: "https://github.com/torvalds/linux/blob/v6.1/kernel/bpf/cgroup_iter.c"
}
const KERNEL_FEATURE_CTX_ITER_MAP = {
    key: "ctx:iter_map"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/kernel/bpf/map_iter.c"
}
const KERNEL_FEATURE_CTX_ITER_MAP_ELEM_MAP = {
    key: "ctx:iter_map"
    min_kernel: "5.9"
    source: "https://github.com/torvalds/linux/blob/v5.9/kernel/bpf/map_iter.c"
}
const KERNEL_FEATURE_CTX_ITER_MAP_KEY = {
    key: "ctx:iter_key"
    min_kernel: "5.9"
    source: "https://github.com/torvalds/linux/blob/v5.9/kernel/bpf/map_iter.c"
}
const KERNEL_FEATURE_CTX_ITER_MAP_VALUE = {
    key: "ctx:iter_value"
    min_kernel: "5.9"
    source: "https://github.com/torvalds/linux/blob/v5.9/kernel/bpf/map_iter.c"
}
const KERNEL_FEATURE_CTX_ITER_SK_STORAGE_MAP = {
    key: "ctx:iter_map"
    min_kernel: "5.9"
    source: "https://github.com/torvalds/linux/blob/v5.9/net/core/bpf_sk_storage.c"
}
const KERNEL_FEATURE_CTX_ITER_SK_STORAGE_VALUE = {
    key: "ctx:iter_value"
    min_kernel: "5.9"
    source: "https://github.com/torvalds/linux/blob/v5.9/net/core/bpf_sk_storage.c"
}
const KERNEL_FEATURE_CTX_ITER_SK_STORAGE_SOCK = {
    key: "ctx:iter_sock"
    min_kernel: "5.9"
    source: "https://github.com/torvalds/linux/blob/v5.9/net/core/bpf_sk_storage.c"
}
const KERNEL_FEATURE_CTX_ITER_SOCKMAP_MAP = {
    key: "ctx:iter_map"
    min_kernel: "5.10"
    source: "https://github.com/torvalds/linux/blob/v5.10/net/core/sock_map.c"
}
const KERNEL_FEATURE_CTX_ITER_SOCKMAP_KEY = {
    key: "ctx:iter_key"
    min_kernel: "5.10"
    source: "https://github.com/torvalds/linux/blob/v5.10/net/core/sock_map.c"
}
const KERNEL_FEATURE_CTX_ITER_SOCKMAP_SOCK = {
    key: "ctx:iter_sock"
    min_kernel: "5.10"
    source: "https://github.com/torvalds/linux/blob/v5.10/net/core/sock_map.c"
}
const KERNEL_FEATURE_CTX_ITER_PROG = {
    key: "ctx:iter_prog"
    min_kernel: "5.9"
    source: "https://github.com/torvalds/linux/blob/v5.9/kernel/bpf/prog_iter.c"
}
const KERNEL_FEATURE_CTX_ITER_LINK = {
    key: "ctx:iter_link"
    min_kernel: "5.19"
    source: "https://github.com/torvalds/linux/blob/v5.19/kernel/bpf/link_iter.c"
}
const KERNEL_FEATURE_CTX_ITER_TCP_SK_COMMON = {
    key: "ctx:iter_sk_common"
    min_kernel: "5.9"
    source: "https://github.com/torvalds/linux/blob/v5.9/net/ipv4/tcp_ipv4.c"
}
const KERNEL_FEATURE_CTX_ITER_TCP_UID = {
    key: "ctx:iter_uid"
    min_kernel: "5.9"
    source: "https://github.com/torvalds/linux/blob/v5.9/net/ipv4/tcp_ipv4.c"
}
const KERNEL_FEATURE_CTX_ITER_UDP_SK = {
    key: "ctx:iter_udp_sk"
    min_kernel: "5.9"
    source: "https://github.com/torvalds/linux/blob/v5.9/net/ipv4/udp.c"
}
const KERNEL_FEATURE_CTX_ITER_UDP_UID = {
    key: "ctx:iter_uid"
    min_kernel: "5.9"
    source: "https://github.com/torvalds/linux/blob/v5.9/net/ipv4/udp.c"
}
const KERNEL_FEATURE_CTX_ITER_UDP_BUCKET = {
    key: "ctx:iter_bucket"
    min_kernel: "5.9"
    source: "https://github.com/torvalds/linux/blob/v5.9/net/ipv4/udp.c"
}
const KERNEL_FEATURE_CTX_ITER_UNIX_SK = {
    key: "ctx:iter_unix_sk"
    min_kernel: "5.15"
    source: "https://github.com/torvalds/linux/blob/v5.15/net/unix/af_unix.c"
}
const KERNEL_FEATURE_CTX_ITER_UNIX_UID = {
    key: "ctx:iter_uid"
    min_kernel: "5.15"
    source: "https://github.com/torvalds/linux/blob/v5.15/net/unix/af_unix.c"
}
const KERNEL_FEATURE_CTX_ITER_IPV6_ROUTE = {
    key: "ctx:iter_ipv6_route"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/net/ipv6/route.c"
}
const KERNEL_FEATURE_CTX_ITER_KSYM = {
    key: "ctx:iter_ksym"
    min_kernel: "6.0"
    source: "https://github.com/torvalds/linux/blob/v6.0/kernel/kallsyms.c"
}
const KERNEL_FEATURE_CTX_ITER_NETLINK_SK = {
    key: "ctx:iter_netlink_sk"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/net/netlink/af_netlink.c"
}
const KERNEL_FEATURE_CTX_ITER_KMEM_CACHE = {
    key: "ctx:iter_kmem_cache"
    min_kernel: "6.13"
    source: "https://github.com/torvalds/linux/blob/v6.13/kernel/bpf/kmem_cache_iter.c"
}
const KERNEL_FEATURE_CTX_ITER_DMABUF = {
    key: "ctx:iter_dmabuf"
    min_kernel: "6.16"
    source: "https://github.com/torvalds/linux/blob/v6.16/kernel/bpf/dmabuf_iter.c"
}
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
const KERNEL_FEATURE_CTX_SOCK_OPS_SKB_LEN = {
    key: "ctx:skb_len"
    min_kernel: "5.10"
    source: "https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SOCK_OPS_SKB_TCP_FLAGS = {
    key: "ctx:skb_tcp_flags"
    min_kernel: "5.10"
    source: "https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_HWTSTAMP = {
    key: "ctx:hwtstamp"
    min_kernel: "5.16"
    source: "https://github.com/torvalds/linux/blob/v5.16/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_TSTAMP_TYPE = {
    key: "ctx:tstamp_type"
    min_kernel: "5.18"
    source: "https://github.com/torvalds/linux/blob/v5.18/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SKB_HWTSTAMP = {
    key: "ctx:skb_hwtstamp"
    min_kernel: "6.2"
    source: "https://github.com/torvalds/linux/blob/v6.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_NETFILTER_STATE = {
    key: "ctx:state"
    min_kernel: "6.4"
    source: "https://github.com/torvalds/linux/blob/v6.4/net/netfilter/nf_bpf_link.c"
}
const KERNEL_FEATURE_CTX_NETFILTER_SKB = {
    key: "ctx:skb"
    min_kernel: "6.4"
    source: "https://github.com/torvalds/linux/blob/v6.4/net/netfilter/nf_bpf_link.c"
}
const KERNEL_FEATURE_CTX_NETFILTER_HOOK = {
    key: "ctx:hook"
    min_kernel: "6.4"
    source: "https://github.com/torvalds/linux/blob/v6.4/net/netfilter/nf_bpf_link.c"
}
const KERNEL_FEATURE_CTX_NETFILTER_PROTOCOL_FAMILY = {
    key: "ctx:pf"
    min_kernel: "6.4"
    source: "https://github.com/torvalds/linux/blob/v6.4/net/netfilter/nf_bpf_link.c"
}
const KERNEL_FEATURE_CTX_LIRC_SAMPLE = {
    key: "ctx:sample"
    min_kernel: "4.18"
    source: "https://github.com/torvalds/linux/blob/v4.18/drivers/media/rc/bpf-lirc.c"
}
const KERNEL_FEATURE_CTX_LIRC_VALUE = {
    key: "ctx:value"
    min_kernel: "4.18"
    source: "https://github.com/torvalds/linux/blob/v4.18/drivers/media/rc/bpf-lirc.c"
}
const KERNEL_FEATURE_CTX_LIRC_MODE = {
    key: "ctx:mode"
    min_kernel: "4.18"
    source: "https://github.com/torvalds/linux/blob/v4.18/drivers/media/rc/bpf-lirc.c"
}
const KERNEL_FEATURE_CTX_PERF_SAMPLE_PERIOD = {
    key: "ctx:sample_period"
    min_kernel: "4.9"
    source: "https://github.com/torvalds/linux/blob/v4.9/include/uapi/linux/bpf_perf_event.h"
}
const KERNEL_FEATURE_CTX_PERF_ADDR = {
    key: "ctx:addr"
    min_kernel: "5.0"
    source: "https://github.com/torvalds/linux/blob/v5.0/include/uapi/linux/bpf_perf_event.h"
}
source ($VERIFIER_DIFF_CONTEXT_METADATA_DIR | path join context_generic_field_features.nu)

const ITER_TARGET_KERNEL_FEATURES = [
    { target: "task", feature: $KERNEL_FEATURE_ITER_TARGET_TASK }
    { target: "task_file", feature: $KERNEL_FEATURE_ITER_TARGET_TASK_FILE }
    { target: "task_vma", feature: $KERNEL_FEATURE_ITER_TARGET_TASK_VMA }
    { target: "bpf_map", feature: $KERNEL_FEATURE_ITER_TARGET_BPF_MAP }
    { target: "cgroup", feature: $KERNEL_FEATURE_ITER_TARGET_CGROUP }
    { target: "bpf_map_elem", feature: $KERNEL_FEATURE_ITER_TARGET_BPF_MAP_ELEM }
    { target: "bpf_sk_storage_map", feature: $KERNEL_FEATURE_ITER_TARGET_BPF_SK_STORAGE_MAP }
    { target: "sockmap", feature: $KERNEL_FEATURE_ITER_TARGET_SOCKMAP }
    { target: "bpf_prog", feature: $KERNEL_FEATURE_ITER_TARGET_BPF_PROG }
    { target: "bpf_link", feature: $KERNEL_FEATURE_ITER_TARGET_BPF_LINK }
    { target: "tcp", feature: $KERNEL_FEATURE_ITER_TARGET_TCP }
    { target: "udp", feature: $KERNEL_FEATURE_ITER_TARGET_UDP }
    { target: "unix", feature: $KERNEL_FEATURE_ITER_TARGET_UNIX }
    { target: "ipv6_route", feature: $KERNEL_FEATURE_ITER_TARGET_IPV6_ROUTE }
    { target: "ksym", feature: $KERNEL_FEATURE_ITER_TARGET_KSYM }
    { target: "netlink", feature: $KERNEL_FEATURE_ITER_TARGET_NETLINK }
    { target: "kmem_cache", feature: $KERNEL_FEATURE_ITER_TARGET_KMEM_CACHE }
    { target: "dmabuf", feature: $KERNEL_FEATURE_ITER_TARGET_DMABUF }
]

const MAP_KIND_KERNEL_FEATURES = [
    { kind: "array", feature: $KERNEL_FEATURE_MAP_ARRAY }
    { kind: "array-of-maps", feature: $KERNEL_FEATURE_MAP_ARRAY_OF_MAPS }
    { kind: "arena", feature: $KERNEL_FEATURE_MAP_ARENA }
    { kind: "bloom-filter", feature: $KERNEL_FEATURE_MAP_BLOOM_FILTER }
    { kind: "cgroup-storage", feature: $KERNEL_FEATURE_MAP_CGRP_STORAGE }
    { kind: "cgroup-array", feature: $KERNEL_FEATURE_MAP_CGROUP_ARRAY }
    { kind: "cgrp-storage", feature: $KERNEL_FEATURE_MAP_CGRP_STORAGE }
    { kind: "cpumap", feature: $KERNEL_FEATURE_MAP_CPUMAP }
    { kind: "deprecated-cgroup-storage", feature: $KERNEL_FEATURE_MAP_CGROUP_STORAGE }
    { kind: "devmap", feature: $KERNEL_FEATURE_MAP_DEVMAP }
    { kind: "devmap-hash", feature: $KERNEL_FEATURE_MAP_DEVMAP_HASH }
    { kind: "hash", feature: $KERNEL_FEATURE_MAP_HASH }
    { kind: "hash-of-maps", feature: $KERNEL_FEATURE_MAP_HASH_OF_MAPS }
    { kind: "inode-storage", feature: $KERNEL_FEATURE_MAP_INODE_STORAGE }
    { kind: "lpm-trie", feature: $KERNEL_FEATURE_MAP_LPM_TRIE }
    { kind: "lru-hash", feature: $KERNEL_FEATURE_MAP_LRU_HASH }
    { kind: "lru-per-cpu-hash", feature: $KERNEL_FEATURE_MAP_LRU_PERCPU_HASH }
    { kind: "per-cpu-array", feature: $KERNEL_FEATURE_MAP_PERCPU_ARRAY }
    { kind: "per-cpu-cgroup-storage", feature: $KERNEL_FEATURE_MAP_PERCPU_CGROUP_STORAGE }
    { kind: "per-cpu-hash", feature: $KERNEL_FEATURE_MAP_PERCPU_HASH }
    { kind: "perf-event-array", feature: $KERNEL_FEATURE_MAP_PERF_EVENT_ARRAY }
    { kind: "prog-array", feature: $KERNEL_FEATURE_MAP_PROG_ARRAY }
    { kind: "queue", feature: $KERNEL_FEATURE_MAP_QUEUE }
    { kind: "reuseport-sockarray", feature: $KERNEL_FEATURE_MAP_REUSEPORT_SOCKARRAY }
    { kind: "ringbuf", feature: $KERNEL_FEATURE_MAP_RINGBUF }
    { kind: "sk-storage", feature: $KERNEL_FEATURE_MAP_SK_STORAGE }
    { kind: "sockhash", feature: $KERNEL_FEATURE_MAP_SOCKHASH }
    { kind: "sockmap", feature: $KERNEL_FEATURE_MAP_SOCKMAP }
    { kind: "stack", feature: $KERNEL_FEATURE_MAP_STACK }
    { kind: "stack-trace", feature: $KERNEL_FEATURE_MAP_STACK_TRACE }
    { kind: "struct-ops", feature: $KERNEL_FEATURE_MAP_STRUCT_OPS }
    { kind: "task-storage", feature: $KERNEL_FEATURE_MAP_TASK_STORAGE }
    { kind: "user-ringbuf", feature: $KERNEL_FEATURE_MAP_USER_RINGBUF }
    { kind: "xskmap", feature: $KERNEL_FEATURE_MAP_XSKMAP }
]

const MAP_VALUE_KERNEL_FEATURES = [
    { token: "bpf_spin_lock", feature: $KERNEL_FEATURE_MAP_VALUE_BPF_SPIN_LOCK }
    { token: "bpf_timer", feature: $KERNEL_FEATURE_MAP_VALUE_BPF_TIMER }
    { token: "kptr:", feature: $KERNEL_FEATURE_MAP_VALUE_KPTR }
    { token: "bpf_wq", feature: $KERNEL_FEATURE_MAP_VALUE_BPF_WQ }
    { token: "bpf_refcount", feature: $KERNEL_FEATURE_MAP_VALUE_BPF_REFCOUNT }
    { token: "bpf_list_head", feature: $KERNEL_FEATURE_MAP_VALUE_BPF_LIST_HEAD }
    { token: "bpf_list_node", feature: $KERNEL_FEATURE_MAP_VALUE_BPF_LIST_NODE }
    { token: "bpf_rb_root", feature: $KERNEL_FEATURE_MAP_VALUE_BPF_RB_ROOT }
    { token: "bpf_rb_node", feature: $KERNEL_FEATURE_MAP_VALUE_BPF_RB_NODE }
]

const HELPER_CALL_EXPLICIT_MAP_KIND_FEATURES = [
    { helper: "bpf_map_push_elem", map_arg: 0, kinds: ["queue" "stack" "bloom-filter"] }
    { helper: "bpf_map_peek_elem", map_arg: 0, kinds: ["queue" "stack" "bloom-filter"] }
    { helper: "bpf_map_pop_elem", map_arg: 0, kinds: ["queue" "stack"] }
    { helper: "bpf_redirect_map", map_arg: 0, kinds: ["devmap" "devmap-hash" "cpumap" "xskmap"] }
    { helper: "bpf_map_lookup_percpu_elem", map_arg: 0, kinds: ["per-cpu-hash" "per-cpu-array" "lru-per-cpu-hash"] }
    { helper: "bpf_for_each_map_elem", map_arg: 0, kinds: ["hash" "array" "lru-hash" "per-cpu-hash" "per-cpu-array" "lru-per-cpu-hash"] }
    { helper: "bpf_timer_init", map_arg: 1, kinds: ["hash" "array" "lru-hash"] }
]

const HELPER_CALL_FIXED_MAP_KIND_FEATURES = [
    { helper: "bpf_tail_call", map_arg: 1, kind: "prog-array" }
    { helper: "bpf_perf_event_output", map_arg: 1, kind: "perf-event-array" }
    { helper: "bpf_skb_output", map_arg: 1, kind: "perf-event-array" }
    { helper: "bpf_xdp_output", map_arg: 1, kind: "perf-event-array" }
    { helper: "bpf_perf_event_read", map_arg: 0, kind: "perf-event-array" }
    { helper: "bpf_perf_event_read_value", map_arg: 0, kind: "perf-event-array" }
    { helper: "bpf_get_stackid", map_arg: 1, kind: "stack-trace" }
    { helper: "bpf_skb_under_cgroup", map_arg: 1, kind: "cgroup-array" }
    { helper: "bpf_current_task_under_cgroup", map_arg: 0, kind: "cgroup-array" }
    { helper: "bpf_ringbuf_output", map_arg: 0, kind: "ringbuf" }
    { helper: "bpf_ringbuf_reserve", map_arg: 0, kind: "ringbuf" }
    { helper: "bpf_ringbuf_reserve_dynptr", map_arg: 0, kind: "ringbuf" }
    { helper: "bpf_ringbuf_query", map_arg: 0, kind: "ringbuf" }
    { helper: "bpf_user_ringbuf_drain", map_arg: 0, kind: "user-ringbuf" }
    { helper: "bpf_sk_redirect_map", map_arg: 1, kind: "sockmap" }
    { helper: "bpf_sock_map_update", map_arg: 1, kind: "sockmap" }
    { helper: "bpf_msg_redirect_map", map_arg: 1, kind: "sockmap" }
    { helper: "bpf_sock_hash_update", map_arg: 1, kind: "sockhash" }
    { helper: "bpf_msg_redirect_hash", map_arg: 1, kind: "sockhash" }
    { helper: "bpf_sk_redirect_hash", map_arg: 1, kind: "sockhash" }
    { helper: "bpf_sk_select_reuseport", map_arg: 1, kind: "reuseport-sockarray" }
    { helper: "bpf_sk_storage_get", map_arg: 0, kind: "sk-storage" }
    { helper: "bpf_sk_storage_delete", map_arg: 0, kind: "sk-storage" }
    { helper: "bpf_task_storage_get", map_arg: 0, kind: "task-storage" }
    { helper: "bpf_task_storage_delete", map_arg: 0, kind: "task-storage" }
    { helper: "bpf_inode_storage_get", map_arg: 0, kind: "inode-storage" }
    { helper: "bpf_inode_storage_delete", map_arg: 0, kind: "inode-storage" }
    { helper: "bpf_cgrp_storage_get", map_arg: 0, kind: "cgrp-storage" }
    { helper: "bpf_cgrp_storage_delete", map_arg: 0, kind: "cgrp-storage" }
    { helper: "bpf_get_local_storage", map_arg: 0, kind: "deprecated-cgroup-storage" }
]

const BPF_HELPER_KERNEL_FLOORS_BY_MAX_ID = [
    { max_id: 3, min_kernel: "3.19" }
    { max_id: 11, min_kernel: "4.1" }
    { max_id: 16, min_kernel: "4.2" }
    { max_id: 22, min_kernel: "4.3" }
    { max_id: 25, min_kernel: "4.4" }
    { max_id: 26, min_kernel: "4.5" }
    { max_id: 30, min_kernel: "4.6" }
    { max_id: 36, min_kernel: "4.8" }
    { max_id: 41, min_kernel: "4.9" }
    { max_id: 44, min_kernel: "4.10" }
    { max_id: 45, min_kernel: "4.11" }
    { max_id: 47, min_kernel: "4.12" }
    { max_id: 50, min_kernel: "4.13" }
    { max_id: 53, min_kernel: "4.14" }
    { max_id: 57, min_kernel: "4.15" }
    { max_id: 59, min_kernel: "4.16" }
    { max_id: 64, min_kernel: "4.17" }
    { max_id: 80, min_kernel: "4.18" }
    { max_id: 83, min_kernel: "4.19" }
    { max_id: 90, min_kernel: "4.20" }
    { max_id: 92, min_kernel: "5.0" }
    { max_id: 98, min_kernel: "5.1" }
    { max_id: 108, min_kernel: "5.2" }
    { max_id: 109, min_kernel: "5.3" }
    { max_id: 110, min_kernel: "5.4" }
    { max_id: 115, min_kernel: "5.5" }
    { max_id: 118, min_kernel: "5.6" }
    { max_id: 124, min_kernel: "5.7" }
    { max_id: 135, min_kernel: "5.8" }
    { max_id: 141, min_kernel: "5.9" }
    { max_id: 155, min_kernel: "5.10" }
    { max_id: 162, min_kernel: "5.11" }
    { max_id: 163, min_kernel: "5.12" }
    { max_id: 165, min_kernel: "5.13" }
    { max_id: 168, min_kernel: "5.14" }
    { max_id: 175, min_kernel: "5.15" }
    { max_id: 179, min_kernel: "5.16" }
    { max_id: 185, min_kernel: "5.17" }
    { max_id: 193, min_kernel: "5.18" }
    { max_id: 203, min_kernel: "5.19" }
    { max_id: 207, min_kernel: "6.0" }
    { max_id: 209, min_kernel: "6.1" }
    { max_id: 211, min_kernel: "6.2" }
]

source ($VERIFIER_DIFF_CONTEXT_METADATA_DIR | path join context_bpf_helper_ids.nu)

const HELPER_KERNEL_FEATURES = [
    { name: "bpf_map_lookup_elem", feature: $KERNEL_FEATURE_BPF_MAP_LOOKUP_ELEM }
    { name: "bpf_map_update_elem", feature: $KERNEL_FEATURE_BPF_MAP_UPDATE_ELEM }
    { name: "bpf_map_delete_elem", feature: $KERNEL_FEATURE_BPF_MAP_DELETE_ELEM }
    { name: "bpf_map_push_elem", feature: $KERNEL_FEATURE_BPF_MAP_PUSH_ELEM }
    { name: "bpf_map_pop_elem", feature: $KERNEL_FEATURE_BPF_MAP_POP_ELEM }
    { name: "bpf_map_peek_elem", feature: $KERNEL_FEATURE_BPF_MAP_PEEK_ELEM }
    { name: "bpf_sock_map_update", feature: $KERNEL_FEATURE_BPF_SOCK_MAP_UPDATE }
    { name: "bpf_sock_hash_update", feature: $KERNEL_FEATURE_BPF_SOCK_HASH_UPDATE }
    { name: "bpf_sk_storage_get", feature: $KERNEL_FEATURE_BPF_SK_STORAGE_GET }
    { name: "bpf_sk_storage_delete", feature: $KERNEL_FEATURE_BPF_SK_STORAGE_DELETE }
    { name: "bpf_inode_storage_get", feature: $KERNEL_FEATURE_BPF_INODE_STORAGE_GET }
    { name: "bpf_inode_storage_delete", feature: $KERNEL_FEATURE_BPF_INODE_STORAGE_DELETE }
    { name: "bpf_task_storage_get", feature: $KERNEL_FEATURE_BPF_TASK_STORAGE_GET }
    { name: "bpf_task_storage_delete", feature: $KERNEL_FEATURE_BPF_TASK_STORAGE_DELETE }
    { name: "bpf_cgrp_storage_get", feature: $KERNEL_FEATURE_BPF_CGRP_STORAGE_GET }
    { name: "bpf_cgrp_storage_delete", feature: $KERNEL_FEATURE_BPF_CGRP_STORAGE_DELETE }
    { name: "bpf_ktime_get_ns", feature: $KERNEL_FEATURE_BPF_KTIME_GET_NS }
    { name: "bpf_ktime_get_boot_ns", feature: $KERNEL_FEATURE_BPF_KTIME_GET_BOOT_NS }
    { name: "bpf_ktime_get_coarse_ns", feature: $KERNEL_FEATURE_BPF_KTIME_GET_COARSE_NS }
    { name: "bpf_ktime_get_tai_ns", feature: $KERNEL_FEATURE_BPF_KTIME_GET_TAI_NS }
    { name: "bpf_jiffies64", feature: $KERNEL_FEATURE_BPF_JIFFIES64 }
    { name: "bpf_get_current_pid_tgid", feature: $KERNEL_FEATURE_BPF_GET_CURRENT_PID_TGID }
    { name: "bpf_get_current_uid_gid", feature: $KERNEL_FEATURE_BPF_GET_CURRENT_UID_GID }
    { name: "bpf_get_current_comm", feature: $KERNEL_FEATURE_BPF_GET_CURRENT_COMM }
    { name: "bpf_get_smp_processor_id", feature: $KERNEL_FEATURE_BPF_GET_SMP_PROCESSOR_ID }
    { name: "bpf_get_cgroup_classid", feature: $KERNEL_FEATURE_BPF_GET_CGROUP_CLASSID }
    { name: "bpf_get_route_realm", feature: $KERNEL_FEATURE_BPF_GET_ROUTE_REALM }
    { name: "bpf_get_numa_node_id", feature: $KERNEL_FEATURE_BPF_GET_NUMA_NODE_ID }
    { name: "bpf_get_socket_cookie", feature: $KERNEL_FEATURE_BPF_GET_SOCKET_COOKIE }
    { name: "bpf_get_socket_uid", feature: $KERNEL_FEATURE_BPF_GET_SOCKET_UID }
    { name: "bpf_get_current_cgroup_id", feature: $KERNEL_FEATURE_BPF_GET_CURRENT_CGROUP_ID }
    { name: "bpf_get_current_ancestor_cgroup_id", feature: $KERNEL_FEATURE_BPF_GET_CURRENT_ANCESTOR_CGROUP_ID }
    { name: "bpf_get_ns_current_pid_tgid", feature: $KERNEL_FEATURE_BPF_GET_NS_CURRENT_PID_TGID }
    { name: "bpf_skb_cgroup_id", feature: $KERNEL_FEATURE_BPF_SKB_CGROUP_ID }
    { name: "bpf_skb_ancestor_cgroup_id", feature: $KERNEL_FEATURE_BPF_SKB_ANCESTOR_CGROUP_ID }
    { name: "bpf_skb_cgroup_classid", feature: $KERNEL_FEATURE_BPF_SKB_CGROUP_CLASSID }
    { name: "bpf_sk_cgroup_id", feature: $KERNEL_FEATURE_BPF_SK_CGROUP_ID }
    { name: "bpf_sk_ancestor_cgroup_id", feature: $KERNEL_FEATURE_BPF_SK_ANCESTOR_CGROUP_ID }
    { name: "bpf_sk_fullsock", feature: $KERNEL_FEATURE_BPF_SK_FULLSOCK }
    { name: "bpf_tcp_sock", feature: $KERNEL_FEATURE_BPF_TCP_SOCK }
    { name: "bpf_get_listener_sock", feature: $KERNEL_FEATURE_BPF_GET_LISTENER_SOCK }
    { name: "bpf_get_netns_cookie", feature: $KERNEL_FEATURE_BPF_GET_NETNS_COOKIE }
    { name: "bpf_probe_read", feature: $KERNEL_FEATURE_BPF_PROBE_READ }
    { name: "bpf_probe_read_str", feature: $KERNEL_FEATURE_BPF_PROBE_READ_STR }
    { name: "bpf_probe_read_user", feature: $KERNEL_FEATURE_BPF_PROBE_READ_USER }
    { name: "bpf_probe_read_kernel", feature: $KERNEL_FEATURE_BPF_PROBE_READ_KERNEL }
    { name: "bpf_probe_read_user_str", feature: $KERNEL_FEATURE_BPF_PROBE_READ_USER_STR }
    { name: "bpf_probe_read_kernel_str", feature: $KERNEL_FEATURE_BPF_PROBE_READ_KERNEL_STR }
    { name: "bpf_get_prandom_u32", feature: $KERNEL_FEATURE_BPF_GET_PRANDOM_U32 }
    { name: "bpf_tail_call", feature: $KERNEL_FEATURE_BPF_TAIL_CALL }
    { name: "bpf_perf_event_read", feature: $KERNEL_FEATURE_BPF_PERF_EVENT_READ }
    { name: "bpf_perf_event_read_value", feature: $KERNEL_FEATURE_BPF_PERF_EVENT_READ_VALUE }
    { name: "bpf_perf_prog_read_value", feature: $KERNEL_FEATURE_BPF_PERF_PROG_READ_VALUE }
    { name: "bpf_override_return", feature: $KERNEL_FEATURE_BPF_OVERRIDE_RETURN }
    { name: "bpf_redirect", feature: $KERNEL_FEATURE_BPF_REDIRECT }
    { name: "bpf_get_stackid", feature: $KERNEL_FEATURE_BPF_GET_STACKID }
    { name: "bpf_get_stack", feature: $KERNEL_FEATURE_BPF_GET_STACK }
    { name: "bpf_csum_diff", feature: $KERNEL_FEATURE_BPF_CSUM_DIFF }
    { name: "bpf_get_hash_recalc", feature: $KERNEL_FEATURE_BPF_GET_HASH_RECALC }
    { name: "bpf_csum_level", feature: $KERNEL_FEATURE_BPF_CSUM_LEVEL }
    { name: "bpf_skb_load_bytes", feature: $KERNEL_FEATURE_BPF_SKB_LOAD_BYTES }
    { name: "bpf_fib_lookup", feature: $KERNEL_FEATURE_BPF_FIB_LOOKUP }
    { name: "bpf_skb_under_cgroup", feature: $KERNEL_FEATURE_BPF_SKB_UNDER_CGROUP }
    { name: "bpf_current_task_under_cgroup", feature: $KERNEL_FEATURE_BPF_CURRENT_TASK_UNDER_CGROUP }
    { name: "bpf_skb_pull_data", feature: $KERNEL_FEATURE_BPF_SKB_PULL_DATA }
    { name: "bpf_skb_adjust_room", feature: $KERNEL_FEATURE_BPF_SKB_ADJUST_ROOM }
    { name: "bpf_skb_change_head", feature: $KERNEL_FEATURE_BPF_SKB_CHANGE_HEAD }
    { name: "bpf_skb_change_tail", feature: $KERNEL_FEATURE_BPF_SKB_CHANGE_TAIL }
    { name: "bpf_xdp_adjust_head", feature: $KERNEL_FEATURE_BPF_XDP_ADJUST_HEAD }
    { name: "bpf_xdp_adjust_meta", feature: $KERNEL_FEATURE_BPF_XDP_ADJUST_META }
    { name: "bpf_xdp_adjust_tail", feature: $KERNEL_FEATURE_BPF_XDP_ADJUST_TAIL }
    { name: "bpf_xdp_get_buff_len", feature: $KERNEL_FEATURE_BPF_XDP_GET_BUFF_LEN }
    { name: "bpf_redirect_map", feature: $KERNEL_FEATURE_BPF_REDIRECT_MAP }
    { name: "bpf_check_mtu", feature: $KERNEL_FEATURE_BPF_CHECK_MTU }
    { name: "bpf_sk_redirect_map", feature: $KERNEL_FEATURE_BPF_SK_REDIRECT_MAP }
    { name: "bpf_sk_redirect_hash", feature: $KERNEL_FEATURE_BPF_SK_REDIRECT_HASH }
    { name: "bpf_msg_apply_bytes", feature: $KERNEL_FEATURE_BPF_MSG_APPLY_BYTES }
    { name: "bpf_msg_cork_bytes", feature: $KERNEL_FEATURE_BPF_MSG_CORK_BYTES }
    { name: "bpf_msg_pull_data", feature: $KERNEL_FEATURE_BPF_MSG_PULL_DATA }
    { name: "bpf_msg_push_data", feature: $KERNEL_FEATURE_BPF_MSG_PUSH_DATA }
    { name: "bpf_msg_pop_data", feature: $KERNEL_FEATURE_BPF_MSG_POP_DATA }
    { name: "bpf_msg_redirect_map", feature: $KERNEL_FEATURE_BPF_MSG_REDIRECT_MAP }
    { name: "bpf_msg_redirect_hash", feature: $KERNEL_FEATURE_BPF_MSG_REDIRECT_HASH }
    { name: "bpf_sk_assign", feature: $KERNEL_FEATURE_BPF_SK_ASSIGN }
    { name: "bpf_sk_lookup_tcp", feature: $KERNEL_FEATURE_BPF_SK_LOOKUP_TCP }
    { name: "bpf_sk_lookup_udp", feature: $KERNEL_FEATURE_BPF_SK_LOOKUP_UDP }
    { name: "bpf_sk_release", feature: $KERNEL_FEATURE_BPF_SK_RELEASE }
    { name: "bpf_skc_lookup_tcp", feature: $KERNEL_FEATURE_BPF_SKC_LOOKUP_TCP }
    { name: "bpf_sysctl_set_new_value", feature: $KERNEL_FEATURE_BPF_SYSCTL_SET_NEW_VALUE }
    { name: "bpf_sysctl_get_name", feature: $KERNEL_FEATURE_BPF_SYSCTL_GET_NAME }
    { name: "bpf_sysctl_get_current_value", feature: $KERNEL_FEATURE_BPF_SYSCTL_GET_CURRENT_VALUE }
    { name: "bpf_sysctl_get_new_value", feature: $KERNEL_FEATURE_BPF_SYSCTL_GET_NEW_VALUE }
    { name: "bpf_sk_select_reuseport", feature: $KERNEL_FEATURE_BPF_SK_SELECT_REUSEPORT }
    { name: "bpf_ringbuf_output", feature: $KERNEL_FEATURE_BPF_RINGBUF_OUTPUT }
    { name: "bpf_ringbuf_reserve", feature: $KERNEL_FEATURE_BPF_RINGBUF_RESERVE }
    { name: "bpf_ringbuf_submit", feature: $KERNEL_FEATURE_BPF_RINGBUF_SUBMIT }
    { name: "bpf_ringbuf_discard", feature: $KERNEL_FEATURE_BPF_RINGBUF_DISCARD }
    { name: "bpf_ringbuf_query", feature: $KERNEL_FEATURE_BPF_RINGBUF_QUERY }
    { name: "bpf_redirect_neigh", feature: $KERNEL_FEATURE_BPF_REDIRECT_NEIGH }
    { name: "bpf_redirect_peer", feature: $KERNEL_FEATURE_BPF_REDIRECT_PEER }
    { name: "bpf_load_hdr_opt", feature: $KERNEL_FEATURE_BPF_LOAD_HDR_OPT }
    { name: "bpf_store_hdr_opt", feature: $KERNEL_FEATURE_BPF_STORE_HDR_OPT }
    { name: "bpf_reserve_hdr_opt", feature: $KERNEL_FEATURE_BPF_RESERVE_HDR_OPT }
    { name: "bpf_sock_ops_cb_flags_set", feature: $KERNEL_FEATURE_BPF_SOCK_OPS_CB_FLAGS_SET }
    { name: "bpf_bprm_opts_set", feature: $KERNEL_FEATURE_BPF_BPRM_OPTS_SET }
    { name: "bpf_spin_lock", feature: $KERNEL_FEATURE_BPF_SPIN_LOCK }
    { name: "bpf_spin_unlock", feature: $KERNEL_FEATURE_BPF_SPIN_UNLOCK }
    { name: "bpf_for_each_map_elem", feature: $KERNEL_FEATURE_BPF_FOR_EACH_MAP_ELEM }
    { name: "bpf_seq_printf", feature: $KERNEL_FEATURE_BPF_SEQ_PRINTF }
    { name: "bpf_seq_write", feature: $KERNEL_FEATURE_BPF_SEQ_WRITE }
    { name: "bpf_sys_bpf", feature: $KERNEL_FEATURE_BPF_SYS_BPF }
    { name: "bpf_sys_close", feature: $KERNEL_FEATURE_BPF_SYS_CLOSE }
    { name: "bpf_btf_find_by_name_kind", feature: $KERNEL_FEATURE_BPF_BTF_FIND_BY_NAME_KIND }
    { name: "bpf_get_current_task_btf", feature: $KERNEL_FEATURE_BPF_GET_CURRENT_TASK_BTF }
    { name: "bpf_task_pt_regs", feature: $KERNEL_FEATURE_BPF_TASK_PT_REGS }
    { name: "bpf_get_func_ip", feature: $KERNEL_FEATURE_BPF_GET_FUNC_IP }
    { name: "bpf_get_attach_cookie", feature: $KERNEL_FEATURE_BPF_GET_ATTACH_COOKIE }
    { name: "bpf_get_func_arg_cnt", feature: $KERNEL_FEATURE_BPF_GET_FUNC_ARG_CNT }
    { name: "bpf_timer_init", feature: $KERNEL_FEATURE_BPF_TIMER_INIT }
    { name: "bpf_timer_set_callback", feature: $KERNEL_FEATURE_BPF_TIMER_SET_CALLBACK }
    { name: "bpf_timer_start", feature: $KERNEL_FEATURE_BPF_TIMER_START }
    { name: "bpf_timer_cancel", feature: $KERNEL_FEATURE_BPF_TIMER_CANCEL }
    { name: "bpf_kallsyms_lookup_name", feature: $KERNEL_FEATURE_BPF_KALLSYMS_LOOKUP_NAME }
    { name: "bpf_loop", feature: $KERNEL_FEATURE_BPF_LOOP }
    { name: "bpf_kptr_xchg", feature: $KERNEL_FEATURE_BPF_KPTR_XCHG }
    { name: "bpf_ringbuf_reserve_dynptr", feature: $KERNEL_FEATURE_BPF_RINGBUF_RESERVE_DYNPTR }
    { name: "bpf_ringbuf_submit_dynptr", feature: $KERNEL_FEATURE_BPF_RINGBUF_SUBMIT_DYNPTR }
    { name: "bpf_ringbuf_discard_dynptr", feature: $KERNEL_FEATURE_BPF_RINGBUF_DISCARD_DYNPTR }
    { name: "bpf_dynptr_data", feature: $KERNEL_FEATURE_BPF_DYNPTR_DATA }
    { name: "bpf_user_ringbuf_drain", feature: $KERNEL_FEATURE_BPF_USER_RINGBUF_DRAIN }
]

const KFUNC_KERNEL_FEATURES = [
    { name: "bpf_dynptr_size", feature: $KERNEL_FEATURE_KFUNC_BPF_DYNPTR_SIZE }
    { name: "bpf_dynptr_slice", feature: $KERNEL_FEATURE_KFUNC_BPF_DYNPTR_SLICE }
    { name: "bpf_dynptr_clone", feature: $KERNEL_FEATURE_KFUNC_BPF_DYNPTR_CLONE }
    { name: "bpf_task_acquire", feature: $KERNEL_FEATURE_KFUNC_BPF_TASK_ACQUIRE }
    { name: "bpf_task_from_pid", feature: $KERNEL_FEATURE_KFUNC_BPF_TASK_FROM_PID }
    { name: "bpf_task_release", feature: $KERNEL_FEATURE_KFUNC_BPF_TASK_RELEASE }
    { name: "bpf_cgroup_acquire", feature: $KERNEL_FEATURE_KFUNC_BPF_CGROUP_ACQUIRE }
    { name: "bpf_cgroup_ancestor", feature: $KERNEL_FEATURE_KFUNC_BPF_CGROUP_ANCESTOR }
    { name: "bpf_cgroup_from_id", feature: $KERNEL_FEATURE_KFUNC_BPF_CGROUP_FROM_ID }
    { name: "bpf_cgroup_release", feature: $KERNEL_FEATURE_KFUNC_BPF_CGROUP_RELEASE }
    { name: "bpf_get_task_exe_file", feature: $KERNEL_FEATURE_KFUNC_BPF_GET_TASK_EXE_FILE }
    { name: "bpf_put_file", feature: $KERNEL_FEATURE_KFUNC_BPF_PUT_FILE }
    { name: "bpf_cpumask_create", feature: $KERNEL_FEATURE_KFUNC_BPF_CPUMASK_CREATE }
    { name: "bpf_cpumask_acquire", feature: $KERNEL_FEATURE_KFUNC_BPF_CPUMASK_ACQUIRE }
    { name: "bpf_cpumask_release", feature: $KERNEL_FEATURE_KFUNC_BPF_CPUMASK_RELEASE }
    { name: "bpf_cpumask_first", feature: $KERNEL_FEATURE_KFUNC_BPF_CPUMASK_FIRST }
    { name: "bpf_cpumask_set_cpu", feature: $KERNEL_FEATURE_KFUNC_BPF_CPUMASK_SET_CPU }
    { name: "bpf_res_spin_lock", feature: $KERNEL_FEATURE_KFUNC_BPF_RES_SPIN_LOCK }
    { name: "bpf_res_spin_unlock", feature: $KERNEL_FEATURE_KFUNC_BPF_RES_SPIN_UNLOCK }
    { name: "bpf_res_spin_lock_irqsave", feature: $KERNEL_FEATURE_KFUNC_BPF_RES_SPIN_LOCK_IRQSAVE }
    { name: "bpf_res_spin_unlock_irqrestore", feature: $KERNEL_FEATURE_KFUNC_BPF_RES_SPIN_UNLOCK_IRQRESTORE }
    { name: "bpf_sock_addr_set_sun_path", feature: $KERNEL_FEATURE_KFUNC_BPF_SOCK_ADDR_SET_SUN_PATH }
    { name: "bpf_sock_ops_enable_tx_tstamp", feature: $KERNEL_FEATURE_KFUNC_BPF_SOCK_OPS_ENABLE_TX_TSTAMP }
    { name: "scx_bpf_dsq_insert", feature: $KERNEL_FEATURE_KFUNC_SCX_BPF_DSQ_INSERT }
    { name: "scx_bpf_dsq_insert___v2", feature: $KERNEL_FEATURE_KFUNC_SCX_BPF_DSQ_INSERT_V2 }
    { name: "scx_bpf_dsq_insert_vtime", feature: $KERNEL_FEATURE_KFUNC_SCX_BPF_DSQ_INSERT_VTIME }
    { name: "scx_bpf_reenqueue_local", feature: $KERNEL_FEATURE_KFUNC_SCX_BPF_REENQUEUE_LOCAL }
    { name: "scx_bpf_reenqueue_local___v2", feature: $KERNEL_FEATURE_KFUNC_SCX_BPF_REENQUEUE_LOCAL_V2 }
    { name: "scx_bpf_get_idle_cpumask", feature: $KERNEL_FEATURE_KFUNC_SCX_BPF_GET_IDLE_CPUMASK }
    { name: "scx_bpf_get_idle_smtmask", feature: $KERNEL_FEATURE_KFUNC_SCX_BPF_GET_IDLE_SMTMASK }
    { name: "scx_bpf_pick_any_cpu", feature: $KERNEL_FEATURE_KFUNC_SCX_BPF_PICK_ANY_CPU }
    { name: "scx_bpf_put_idle_cpumask", feature: $KERNEL_FEATURE_KFUNC_SCX_BPF_PUT_IDLE_CPUMASK }
    { name: "scx_bpf_cpu_node", feature: $KERNEL_FEATURE_KFUNC_SCX_BPF_CPU_NODE }
    { name: "scx_bpf_get_idle_cpumask_node", feature: $KERNEL_FEATURE_KFUNC_SCX_BPF_GET_IDLE_CPUMASK_NODE }
    { name: "scx_bpf_get_idle_smtmask_node", feature: $KERNEL_FEATURE_KFUNC_SCX_BPF_GET_IDLE_SMTMASK_NODE }
    { name: "scx_bpf_pick_any_cpu_node", feature: $KERNEL_FEATURE_KFUNC_SCX_BPF_PICK_ANY_CPU_NODE }
    { name: "scx_bpf_pick_idle_cpu_node", feature: $KERNEL_FEATURE_KFUNC_SCX_BPF_PICK_IDLE_CPU_NODE }
]

# Keep this table aligned with `KfuncCompatibilityRequirement` in Rust.
# Explicit records above still win when the harness needs a named feature constant.
const KFUNC_KERNEL_FEATURE_FALLBACKS = [
    { name: "bpf_cgroup_acquire", min_kernel: "6.2", source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/helpers.c" }
    { name: "bpf_cgroup_ancestor", min_kernel: "6.2", source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/helpers.c" }
    { name: "bpf_cgroup_from_id", min_kernel: "6.4", source: "https://github.com/torvalds/linux/blob/v6.4/kernel/bpf/helpers.c" }
    { name: "bpf_cgroup_release", min_kernel: "6.2", source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/helpers.c" }
    { name: "bpf_copy_from_user_dynptr", min_kernel: "6.16", source: "https://github.com/torvalds/linux/blob/v6.16/kernel/bpf/helpers.c" }
    { name: "bpf_copy_from_user_str", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/bpf/helpers.c" }
    { name: "bpf_copy_from_user_task_dynptr", min_kernel: "6.16", source: "https://github.com/torvalds/linux/blob/v6.16/kernel/bpf/helpers.c" }
    { name: "bpf_copy_from_user_task_str", min_kernel: "6.15", source: "https://github.com/torvalds/linux/blob/v6.15/kernel/bpf/helpers.c" }
    { name: "bpf_copy_from_user_task_str_dynptr", min_kernel: "6.16", source: "https://github.com/torvalds/linux/blob/v6.16/kernel/bpf/helpers.c" }
    { name: "bpf_cpumask_acquire", min_kernel: "6.3", source: "https://github.com/torvalds/linux/blob/v6.3/kernel/bpf/cpumask.c" }
    { name: "bpf_cpumask_and", min_kernel: "6.3", source: "https://github.com/torvalds/linux/blob/v6.3/kernel/bpf/cpumask.c" }
    { name: "bpf_cpumask_any_and_distribute", min_kernel: "6.5", source: "https://github.com/torvalds/linux/blob/v6.5/kernel/bpf/cpumask.c" }
    { name: "bpf_cpumask_any_distribute", min_kernel: "6.5", source: "https://github.com/torvalds/linux/blob/v6.5/kernel/bpf/cpumask.c" }
    { name: "bpf_cpumask_clear", min_kernel: "6.3", source: "https://github.com/torvalds/linux/blob/v6.3/kernel/bpf/cpumask.c" }
    { name: "bpf_cpumask_clear_cpu", min_kernel: "6.3", source: "https://github.com/torvalds/linux/blob/v6.3/kernel/bpf/cpumask.c" }
    { name: "bpf_cpumask_copy", min_kernel: "6.3", source: "https://github.com/torvalds/linux/blob/v6.3/kernel/bpf/cpumask.c" }
    { name: "bpf_cpumask_create", min_kernel: "6.3", source: "https://github.com/torvalds/linux/blob/v6.3/kernel/bpf/cpumask.c" }
    { name: "bpf_cpumask_empty", min_kernel: "6.3", source: "https://github.com/torvalds/linux/blob/v6.3/kernel/bpf/cpumask.c" }
    { name: "bpf_cpumask_equal", min_kernel: "6.3", source: "https://github.com/torvalds/linux/blob/v6.3/kernel/bpf/cpumask.c" }
    { name: "bpf_cpumask_first", min_kernel: "6.3", source: "https://github.com/torvalds/linux/blob/v6.3/kernel/bpf/cpumask.c" }
    { name: "bpf_cpumask_first_and", min_kernel: "6.5", source: "https://github.com/torvalds/linux/blob/v6.5/kernel/bpf/cpumask.c" }
    { name: "bpf_cpumask_first_zero", min_kernel: "6.3", source: "https://github.com/torvalds/linux/blob/v6.3/kernel/bpf/cpumask.c" }
    { name: "bpf_cpumask_full", min_kernel: "6.3", source: "https://github.com/torvalds/linux/blob/v6.3/kernel/bpf/cpumask.c" }
    { name: "bpf_cpumask_intersects", min_kernel: "6.3", source: "https://github.com/torvalds/linux/blob/v6.3/kernel/bpf/cpumask.c" }
    { name: "bpf_cpumask_or", min_kernel: "6.3", source: "https://github.com/torvalds/linux/blob/v6.3/kernel/bpf/cpumask.c" }
    { name: "bpf_cpumask_populate", min_kernel: "6.18", source: "https://github.com/torvalds/linux/blob/v6.18/kernel/bpf/cpumask.c" }
    { name: "bpf_cpumask_release", min_kernel: "6.3", source: "https://github.com/torvalds/linux/blob/v6.3/kernel/bpf/cpumask.c" }
    { name: "bpf_cpumask_release_dtor", min_kernel: "6.8", source: "https://github.com/torvalds/linux/blob/v6.8/kernel/bpf/cpumask.c" }
    { name: "bpf_cpumask_set_cpu", min_kernel: "6.3", source: "https://github.com/torvalds/linux/blob/v6.3/kernel/bpf/cpumask.c" }
    { name: "bpf_cpumask_setall", min_kernel: "6.3", source: "https://github.com/torvalds/linux/blob/v6.3/kernel/bpf/cpumask.c" }
    { name: "bpf_cpumask_subset", min_kernel: "6.3", source: "https://github.com/torvalds/linux/blob/v6.3/kernel/bpf/cpumask.c" }
    { name: "bpf_cpumask_test_and_clear_cpu", min_kernel: "6.3", source: "https://github.com/torvalds/linux/blob/v6.3/kernel/bpf/cpumask.c" }
    { name: "bpf_cpumask_test_and_set_cpu", min_kernel: "6.3", source: "https://github.com/torvalds/linux/blob/v6.3/kernel/bpf/cpumask.c" }
    { name: "bpf_cpumask_test_cpu", min_kernel: "6.3", source: "https://github.com/torvalds/linux/blob/v6.3/kernel/bpf/cpumask.c" }
    { name: "bpf_cpumask_weight", min_kernel: "6.8", source: "https://github.com/torvalds/linux/blob/v6.8/kernel/bpf/cpumask.c" }
    { name: "bpf_cpumask_xor", min_kernel: "6.3", source: "https://github.com/torvalds/linux/blob/v6.3/kernel/bpf/cpumask.c" }
    { name: "bpf_crypto_ctx_acquire", min_kernel: "6.10", source: "https://github.com/torvalds/linux/blob/v6.10/kernel/bpf/crypto.c" }
    { name: "bpf_crypto_ctx_create", min_kernel: "6.10", source: "https://github.com/torvalds/linux/blob/v6.10/kernel/bpf/crypto.c" }
    { name: "bpf_crypto_ctx_release", min_kernel: "6.10", source: "https://github.com/torvalds/linux/blob/v6.10/kernel/bpf/crypto.c" }
    { name: "bpf_crypto_decrypt", min_kernel: "6.10", source: "https://github.com/torvalds/linux/blob/v6.10/kernel/bpf/crypto.c" }
    { name: "bpf_crypto_encrypt", min_kernel: "6.10", source: "https://github.com/torvalds/linux/blob/v6.10/kernel/bpf/crypto.c" }
    { name: "bpf_dynptr_adjust", min_kernel: "6.5", source: "https://github.com/torvalds/linux/blob/v6.5/kernel/bpf/helpers.c" }
    { name: "bpf_dynptr_clone", min_kernel: "6.5", source: "https://github.com/torvalds/linux/blob/v6.5/kernel/bpf/helpers.c" }
    { name: "bpf_dynptr_copy", min_kernel: "6.15", source: "https://github.com/torvalds/linux/blob/v6.15/kernel/bpf/helpers.c" }
    { name: "bpf_dynptr_from_skb", min_kernel: "6.4", source: "https://github.com/torvalds/linux/blob/v6.4/net/core/filter.c" }
    { name: "bpf_dynptr_from_xdp", min_kernel: "6.4", source: "https://github.com/torvalds/linux/blob/v6.4/net/core/filter.c" }
    { name: "bpf_dynptr_is_null", min_kernel: "6.5", source: "https://github.com/torvalds/linux/blob/v6.5/kernel/bpf/helpers.c" }
    { name: "bpf_dynptr_is_rdonly", min_kernel: "6.5", source: "https://github.com/torvalds/linux/blob/v6.5/kernel/bpf/helpers.c" }
    { name: "bpf_dynptr_memset", min_kernel: "6.17", source: "https://github.com/torvalds/linux/blob/v6.17/kernel/bpf/helpers.c" }
    { name: "bpf_dynptr_size", min_kernel: "6.5", source: "https://github.com/torvalds/linux/blob/v6.5/kernel/bpf/helpers.c" }
    { name: "bpf_dynptr_slice", min_kernel: "6.4", source: "https://github.com/torvalds/linux/blob/v6.4/kernel/bpf/helpers.c" }
    { name: "bpf_dynptr_slice_rdwr", min_kernel: "6.4", source: "https://github.com/torvalds/linux/blob/v6.4/kernel/bpf/helpers.c" }
    { name: "bpf_get_task_exe_file", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/fs/bpf_fs_kfuncs.c" }
    { name: "bpf_iter_bits_destroy", min_kernel: "6.11", source: "https://github.com/torvalds/linux/blob/v6.11/kernel/bpf/helpers.c" }
    { name: "bpf_iter_bits_new", min_kernel: "6.11", source: "https://github.com/torvalds/linux/blob/v6.11/kernel/bpf/helpers.c" }
    { name: "bpf_iter_bits_next", min_kernel: "6.11", source: "https://github.com/torvalds/linux/blob/v6.11/kernel/bpf/helpers.c" }
    { name: "bpf_iter_css_destroy", min_kernel: "6.7", source: "https://github.com/torvalds/linux/blob/v6.7/kernel/bpf/helpers.c" }
    { name: "bpf_iter_css_new", min_kernel: "6.7", source: "https://github.com/torvalds/linux/blob/v6.7/kernel/bpf/helpers.c" }
    { name: "bpf_iter_css_next", min_kernel: "6.7", source: "https://github.com/torvalds/linux/blob/v6.7/kernel/bpf/helpers.c" }
    { name: "bpf_iter_css_task_destroy", min_kernel: "6.7", source: "https://github.com/torvalds/linux/blob/v6.7/kernel/bpf/helpers.c" }
    { name: "bpf_iter_css_task_new", min_kernel: "6.7", source: "https://github.com/torvalds/linux/blob/v6.7/kernel/bpf/helpers.c" }
    { name: "bpf_iter_css_task_next", min_kernel: "6.7", source: "https://github.com/torvalds/linux/blob/v6.7/kernel/bpf/helpers.c" }
    { name: "bpf_iter_dmabuf_destroy", min_kernel: "6.16", source: "https://github.com/torvalds/linux/blob/v6.16/kernel/bpf/helpers.c" }
    { name: "bpf_iter_dmabuf_new", min_kernel: "6.16", source: "https://github.com/torvalds/linux/blob/v6.16/kernel/bpf/helpers.c" }
    { name: "bpf_iter_dmabuf_next", min_kernel: "6.16", source: "https://github.com/torvalds/linux/blob/v6.16/kernel/bpf/helpers.c" }
    { name: "bpf_iter_kmem_cache_destroy", min_kernel: "6.13", source: "https://github.com/torvalds/linux/blob/v6.13/kernel/bpf/helpers.c" }
    { name: "bpf_iter_kmem_cache_new", min_kernel: "6.13", source: "https://github.com/torvalds/linux/blob/v6.13/kernel/bpf/helpers.c" }
    { name: "bpf_iter_kmem_cache_next", min_kernel: "6.13", source: "https://github.com/torvalds/linux/blob/v6.13/kernel/bpf/helpers.c" }
    { name: "bpf_iter_num_destroy", min_kernel: "6.4", source: "https://github.com/torvalds/linux/blob/v6.4/kernel/bpf/helpers.c" }
    { name: "bpf_iter_num_new", min_kernel: "6.4", source: "https://github.com/torvalds/linux/blob/v6.4/kernel/bpf/helpers.c" }
    { name: "bpf_iter_num_next", min_kernel: "6.4", source: "https://github.com/torvalds/linux/blob/v6.4/kernel/bpf/helpers.c" }
    { name: "bpf_iter_scx_dsq_destroy", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "bpf_iter_scx_dsq_new", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "bpf_iter_scx_dsq_next", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "bpf_iter_task_destroy", min_kernel: "6.7", source: "https://github.com/torvalds/linux/blob/v6.7/kernel/bpf/helpers.c" }
    { name: "bpf_iter_task_new", min_kernel: "6.7", source: "https://github.com/torvalds/linux/blob/v6.7/kernel/bpf/helpers.c" }
    { name: "bpf_iter_task_next", min_kernel: "6.7", source: "https://github.com/torvalds/linux/blob/v6.7/kernel/bpf/helpers.c" }
    { name: "bpf_iter_task_vma_destroy", min_kernel: "6.7", source: "https://github.com/torvalds/linux/blob/v6.7/kernel/bpf/helpers.c" }
    { name: "bpf_iter_task_vma_new", min_kernel: "6.7", source: "https://github.com/torvalds/linux/blob/v6.7/kernel/bpf/helpers.c" }
    { name: "bpf_iter_task_vma_next", min_kernel: "6.7", source: "https://github.com/torvalds/linux/blob/v6.7/kernel/bpf/helpers.c" }
    { name: "bpf_list_back", min_kernel: "6.16", source: "https://github.com/torvalds/linux/blob/v6.16/kernel/bpf/helpers.c" }
    { name: "bpf_list_front", min_kernel: "6.16", source: "https://github.com/torvalds/linux/blob/v6.16/kernel/bpf/helpers.c" }
    { name: "bpf_list_pop_back", min_kernel: "6.2", source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/helpers.c" }
    { name: "bpf_list_pop_front", min_kernel: "6.2", source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/helpers.c" }
    { name: "bpf_list_push_back_impl", min_kernel: "6.4", source: "https://github.com/torvalds/linux/blob/v6.4/kernel/bpf/helpers.c" }
    { name: "bpf_list_push_front_impl", min_kernel: "6.4", source: "https://github.com/torvalds/linux/blob/v6.4/kernel/bpf/helpers.c" }
    { name: "bpf_local_irq_restore", min_kernel: "6.14", source: "https://github.com/torvalds/linux/blob/v6.14/kernel/bpf/helpers.c" }
    { name: "bpf_local_irq_save", min_kernel: "6.14", source: "https://github.com/torvalds/linux/blob/v6.14/kernel/bpf/helpers.c" }
    { name: "bpf_map_sum_elem_count", min_kernel: "6.6", source: "https://github.com/torvalds/linux/blob/v6.6/kernel/bpf/map_iter.c" }
    { name: "bpf_wq_init", min_kernel: "6.10", source: "https://github.com/torvalds/linux/blob/v6.10/kernel/bpf/helpers.c" }
    { name: "bpf_wq_set_callback_impl", min_kernel: "6.10", source: "https://github.com/torvalds/linux/blob/v6.10/kernel/bpf/helpers.c" }
    { name: "bpf_wq_start", min_kernel: "6.10", source: "https://github.com/torvalds/linux/blob/v6.10/kernel/bpf/helpers.c" }
    { name: "bpf_obj_drop_impl", min_kernel: "6.2", source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/helpers.c" }
    { name: "bpf_obj_new_impl", min_kernel: "6.2", source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/helpers.c" }
    { name: "bpf_path_d_path", min_kernel: "6.18", source: "https://github.com/torvalds/linux/blob/v6.18/fs/bpf_fs_kfuncs.c" }
    { name: "bpf_percpu_obj_drop_impl", min_kernel: "6.7", source: "https://github.com/torvalds/linux/blob/v6.7/kernel/bpf/helpers.c" }
    { name: "bpf_percpu_obj_new_impl", min_kernel: "6.7", source: "https://github.com/torvalds/linux/blob/v6.7/kernel/bpf/helpers.c" }
    { name: "bpf_preempt_disable", min_kernel: "6.10", source: "https://github.com/torvalds/linux/blob/v6.10/kernel/bpf/helpers.c" }
    { name: "bpf_preempt_enable", min_kernel: "6.10", source: "https://github.com/torvalds/linux/blob/v6.10/kernel/bpf/helpers.c" }
    { name: "bpf_put_file", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/fs/bpf_fs_kfuncs.c" }
    { name: "bpf_rbtree_add_impl", min_kernel: "6.4", source: "https://github.com/torvalds/linux/blob/v6.4/kernel/bpf/helpers.c" }
    { name: "bpf_rbtree_first", min_kernel: "6.3", source: "https://github.com/torvalds/linux/blob/v6.3/kernel/bpf/helpers.c" }
    { name: "bpf_rbtree_left", min_kernel: "6.16", source: "https://github.com/torvalds/linux/blob/v6.16/kernel/bpf/helpers.c" }
    { name: "bpf_rbtree_remove", min_kernel: "6.3", source: "https://github.com/torvalds/linux/blob/v6.3/kernel/bpf/helpers.c" }
    { name: "bpf_rbtree_right", min_kernel: "6.16", source: "https://github.com/torvalds/linux/blob/v6.16/kernel/bpf/helpers.c" }
    { name: "bpf_rbtree_root", min_kernel: "6.16", source: "https://github.com/torvalds/linux/blob/v6.16/kernel/bpf/helpers.c" }
    { name: "bpf_rcu_read_lock", min_kernel: "6.2", source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/helpers.c" }
    { name: "bpf_rcu_read_unlock", min_kernel: "6.2", source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/helpers.c" }
    { name: "bpf_refcount_acquire_impl", min_kernel: "6.4", source: "https://github.com/torvalds/linux/blob/v6.4/kernel/bpf/helpers.c" }
    { name: "bpf_res_spin_lock", min_kernel: "6.15", source: "https://github.com/torvalds/linux/blob/v6.15/kernel/bpf/verifier.c" }
    { name: "bpf_res_spin_lock_irqsave", min_kernel: "6.15", source: "https://github.com/torvalds/linux/blob/v6.15/kernel/bpf/verifier.c" }
    { name: "bpf_res_spin_unlock", min_kernel: "6.15", source: "https://github.com/torvalds/linux/blob/v6.15/kernel/bpf/verifier.c" }
    { name: "bpf_res_spin_unlock_irqrestore", min_kernel: "6.15", source: "https://github.com/torvalds/linux/blob/v6.15/kernel/bpf/verifier.c" }
    { name: "bpf_sock_addr_set_sun_path", min_kernel: "6.7", source: "https://github.com/torvalds/linux/blob/v6.7/net/core/filter.c" }
    { name: "bpf_sock_ops_enable_tx_tstamp", min_kernel: "6.18", source: "https://github.com/torvalds/linux/blob/v6.18/net/core/filter.c" }
    { name: "bpf_task_acquire", min_kernel: "6.2", source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/helpers.c" }
    { name: "bpf_task_from_pid", min_kernel: "6.2", source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/helpers.c" }
    { name: "bpf_task_from_vpid", min_kernel: "6.13", source: "https://github.com/torvalds/linux/blob/v6.13/kernel/bpf/helpers.c" }
    { name: "bpf_task_get_cgroup1", min_kernel: "6.8", source: "https://github.com/torvalds/linux/blob/v6.8/kernel/bpf/helpers.c" }
    { name: "bpf_task_release", min_kernel: "6.2", source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/helpers.c" }
    { name: "bpf_task_under_cgroup", min_kernel: "6.5", source: "https://github.com/torvalds/linux/blob/v6.5/kernel/bpf/helpers.c" }
    { name: "bpf_throw", min_kernel: "6.7", source: "https://github.com/torvalds/linux/blob/v6.7/kernel/bpf/helpers.c" }
    { name: "bpf_xdp_get_xfrm_state", min_kernel: "6.8", source: "https://github.com/torvalds/linux/blob/v6.8/net/xfrm/xfrm_state_bpf.c" }
    { name: "bpf_xdp_metadata_rx_hash", min_kernel: "6.3", source: "https://github.com/torvalds/linux/blob/v6.3/net/core/xdp.c" }
    { name: "bpf_xdp_metadata_rx_timestamp", min_kernel: "6.3", source: "https://github.com/torvalds/linux/blob/v6.3/net/core/xdp.c" }
    { name: "bpf_xdp_metadata_rx_vlan_tag", min_kernel: "6.8", source: "https://github.com/torvalds/linux/blob/v6.8/net/core/xdp.c" }
    { name: "bpf_xdp_xfrm_state_release", min_kernel: "6.8", source: "https://github.com/torvalds/linux/blob/v6.8/net/xfrm/xfrm_state_bpf.c" }
    { name: "scx_bpf_cpu_node", min_kernel: "6.15", source: "https://github.com/torvalds/linux/blob/v6.15/kernel/sched/ext_idle.c" }
    { name: "scx_bpf_cpu_rq", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_cpuperf_cap", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_cpuperf_cur", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_cpuperf_set", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_create_dsq", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_destroy_dsq", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_dispatch_cancel", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_dispatch_nr_slots", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_dsq_insert", min_kernel: "6.13", source: "https://github.com/torvalds/linux/blob/v6.13/kernel/sched/ext.c", max_kernel_exclusive: "6.23", max_kernel_exclusive_source: "https://kernel.googlesource.com/pub/scm/linux/kernel/git/mic/linux/+/a7423e6ea2f8f6f453de79213c26f7a36c86d9a2/kernel/sched/ext.c" }
    { name: "scx_bpf_dsq_insert___v2", min_kernel: "6.19", source: "https://github.com/torvalds/linux/blob/v6.19/kernel/sched/ext.c" }
    { name: "scx_bpf_dsq_insert_vtime", min_kernel: "6.13", source: "https://github.com/torvalds/linux/blob/v6.13/kernel/sched/ext.c", max_kernel_exclusive: "6.23", max_kernel_exclusive_source: "https://kernel.googlesource.com/pub/scm/linux/kernel/git/mic/linux/+/a7423e6ea2f8f6f453de79213c26f7a36c86d9a2/kernel/sched/ext.c" }
    { name: "scx_bpf_dsq_move", min_kernel: "6.13", source: "https://github.com/torvalds/linux/blob/v6.13/kernel/sched/ext.c" }
    { name: "scx_bpf_dsq_move_set_slice", min_kernel: "6.13", source: "https://github.com/torvalds/linux/blob/v6.13/kernel/sched/ext.c" }
    { name: "scx_bpf_dsq_move_set_vtime", min_kernel: "6.13", source: "https://github.com/torvalds/linux/blob/v6.13/kernel/sched/ext.c" }
    { name: "scx_bpf_dsq_move_to_local", min_kernel: "6.13", source: "https://github.com/torvalds/linux/blob/v6.13/kernel/sched/ext.c" }
    { name: "scx_bpf_dsq_move_vtime", min_kernel: "6.13", source: "https://github.com/torvalds/linux/blob/v6.13/kernel/sched/ext.c" }
    { name: "scx_bpf_dsq_nr_queued", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_dump_bstr", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_error_bstr", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_events", min_kernel: "6.15", source: "https://github.com/torvalds/linux/blob/v6.15/kernel/sched/ext.c" }
    { name: "scx_bpf_exit_bstr", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_get_idle_cpumask", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_get_idle_cpumask_node", min_kernel: "6.15", source: "https://github.com/torvalds/linux/blob/v6.15/kernel/sched/ext_idle.c" }
    { name: "scx_bpf_get_idle_smtmask", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_get_idle_smtmask_node", min_kernel: "6.15", source: "https://github.com/torvalds/linux/blob/v6.15/kernel/sched/ext_idle.c" }
    { name: "scx_bpf_get_online_cpumask", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_get_possible_cpumask", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_kick_cpu", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_now", min_kernel: "6.14", source: "https://github.com/torvalds/linux/blob/v6.14/kernel/sched/ext.c" }
    { name: "scx_bpf_nr_cpu_ids", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_nr_node_ids", min_kernel: "6.15", source: "https://github.com/torvalds/linux/blob/v6.15/kernel/sched/ext.c" }
    { name: "scx_bpf_pick_any_cpu", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_pick_any_cpu_node", min_kernel: "6.15", source: "https://github.com/torvalds/linux/blob/v6.15/kernel/sched/ext_idle.c" }
    { name: "scx_bpf_pick_idle_cpu", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_pick_idle_cpu_node", min_kernel: "6.15", source: "https://github.com/torvalds/linux/blob/v6.15/kernel/sched/ext_idle.c" }
    { name: "scx_bpf_put_cpumask", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_put_idle_cpumask", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_reenqueue_local", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c", max_kernel_exclusive: "6.23", max_kernel_exclusive_source: "https://kernel.googlesource.com/pub/scm/linux/kernel/git/mic/linux/+/a7423e6ea2f8f6f453de79213c26f7a36c86d9a2/kernel/sched/ext.c" }
    { name: "scx_bpf_reenqueue_local___v2", min_kernel: "6.19", source: "https://github.com/torvalds/linux/blob/v6.19/kernel/sched/ext.c" }
    { name: "scx_bpf_select_cpu_and", min_kernel: "6.16", source: "https://github.com/torvalds/linux/blob/v6.16/kernel/sched/ext.c" }
    { name: "scx_bpf_select_cpu_dfl", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_task_cgroup", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_task_cpu", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_task_running", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_test_and_clear_cpu_idle", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
]

const CONTEXT_FIELD_KERNEL_FEATURES = [
    { field: "packet_len", feature: $KERNEL_FEATURE_CTX_PACKET_LEN }
    { field: "len", feature: $KERNEL_FEATURE_CTX_PACKET_LEN }
    { field: "pkt_type", feature: $KERNEL_FEATURE_CTX_PKT_TYPE }
    { field: "queue_mapping", feature: $KERNEL_FEATURE_CTX_QUEUE_MAPPING }
    { field: "eth_protocol", feature: $KERNEL_FEATURE_CTX_ETH_PROTOCOL }
    { field: "protocol", feature: $KERNEL_FEATURE_CTX_PROTOCOL }
    { field: "ip_protocol", feature: $KERNEL_FEATURE_CTX_PROTOCOL }
    { field: "vlan_present", feature: $KERNEL_FEATURE_CTX_VLAN_PRESENT }
    { field: "vlan_tci", feature: $KERNEL_FEATURE_CTX_VLAN_TCI }
    { field: "vlan_proto", feature: $KERNEL_FEATURE_CTX_VLAN_PROTO }
    { field: "mark", feature: $KERNEL_FEATURE_CTX_MARK }
    { field: "priority", feature: $KERNEL_FEATURE_CTX_PRIORITY }
    { field: "ifindex", feature: $KERNEL_FEATURE_CTX_IFINDEX }
    { field: "ingress_ifindex", feature: $KERNEL_FEATURE_CTX_INGRESS_IFINDEX }
    { field: "tc_index", feature: $KERNEL_FEATURE_CTX_TC_INDEX }
    { field: "hash", feature: $KERNEL_FEATURE_CTX_HASH }
    { field: "cb", feature: $KERNEL_FEATURE_CTX_CB }
    { field: "tc_classid", feature: $KERNEL_FEATURE_CTX_TC_CLASSID }
    { field: "data", feature: $KERNEL_FEATURE_CTX_DATA }
    { field: "data_end", feature: $KERNEL_FEATURE_CTX_DATA_END }
    { field: "family", feature: $KERNEL_FEATURE_CTX_FAMILY }
    { field: "napi_id", feature: $KERNEL_FEATURE_CTX_NAPI_ID }
    { field: "remote_ip4", feature: $KERNEL_FEATURE_CTX_REMOTE_IP4 }
    { field: "remote_ip6", feature: $KERNEL_FEATURE_CTX_REMOTE_IP6 }
    { field: "remote_port", feature: $KERNEL_FEATURE_CTX_REMOTE_PORT }
    { field: "local_ip4", feature: $KERNEL_FEATURE_CTX_LOCAL_IP4 }
    { field: "local_ip6", feature: $KERNEL_FEATURE_CTX_LOCAL_IP6 }
    { field: "local_port", feature: $KERNEL_FEATURE_CTX_LOCAL_PORT }
    { field: "data_meta", feature: $KERNEL_FEATURE_CTX_DATA_META }
    { field: "rx_queue_index", feature: $KERNEL_FEATURE_CTX_RX_QUEUE_INDEX }
    { field: "flow_keys", feature: $KERNEL_FEATURE_CTX_FLOW_KEYS }
    { field: "tstamp", feature: $KERNEL_FEATURE_CTX_TSTAMP }
    { field: "wire_len", feature: $KERNEL_FEATURE_CTX_WIRE_LEN }
    { field: "gso_segs", feature: $KERNEL_FEATURE_CTX_GSO_SEGS }
    { field: "gso_size", feature: $KERNEL_FEATURE_CTX_GSO_SIZE }
    { field: "egress_ifindex", feature: $KERNEL_FEATURE_CTX_EGRESS_IFINDEX }
    { field: "skb_len", feature: $KERNEL_FEATURE_CTX_SOCK_OPS_SKB_LEN }
    { field: "skb_tcp_flags", feature: $KERNEL_FEATURE_CTX_SOCK_OPS_SKB_TCP_FLAGS }
    { field: "hwtstamp", feature: $KERNEL_FEATURE_CTX_HWTSTAMP }
    { field: "tstamp_type", feature: $KERNEL_FEATURE_CTX_TSTAMP_TYPE }
    { field: "skb_hwtstamp", feature: $KERNEL_FEATURE_CTX_SKB_HWTSTAMP }
    { field: "pid", feature: $KERNEL_FEATURE_CTX_PID }
    { field: "tid", feature: $KERNEL_FEATURE_CTX_PID }
    { field: "tgid", feature: $KERNEL_FEATURE_CTX_TGID }
    { field: "pid_tgid", feature: $KERNEL_FEATURE_CTX_PID_TGID }
    { field: "current_pid_tgid", feature: $KERNEL_FEATURE_CTX_PID_TGID }
    { field: "uid", feature: $KERNEL_FEATURE_CTX_UID }
    { field: "gid", feature: $KERNEL_FEATURE_CTX_GID }
    { field: "uid_gid", feature: $KERNEL_FEATURE_CTX_UID_GID }
    { field: "current_uid_gid", feature: $KERNEL_FEATURE_CTX_UID_GID }
    { field: "comm", feature: $KERNEL_FEATURE_CTX_COMM }
    { field: "cgroup_classid", feature: $KERNEL_FEATURE_CTX_CGROUP_CLASSID }
    { field: "route_realm", feature: $KERNEL_FEATURE_CTX_ROUTE_REALM }
    { field: "cpu", feature: $KERNEL_FEATURE_CTX_CPU }
    { field: "numa_node", feature: $KERNEL_FEATURE_CTX_NUMA_NODE }
    { field: "numa_node_id", feature: $KERNEL_FEATURE_CTX_NUMA_NODE }
    { field: "random", feature: $KERNEL_FEATURE_CTX_RANDOM }
    { field: "prandom_u32", feature: $KERNEL_FEATURE_CTX_RANDOM }
    { field: "ktime", feature: $KERNEL_FEATURE_CTX_TIMESTAMP }
    { field: "timestamp", feature: $KERNEL_FEATURE_CTX_TIMESTAMP }
    { field: "task", feature: $KERNEL_FEATURE_CTX_TASK }
    { field: "current_task", feature: $KERNEL_FEATURE_CTX_TASK }
    { field: "cgroup", feature: $KERNEL_FEATURE_CTX_CGROUP }
    { field: "current_cgroup", feature: $KERNEL_FEATURE_CTX_CGROUP }
    { field: "ktime_boot", feature: $KERNEL_FEATURE_CTX_KTIME_BOOT }
    { field: "boot_ktime", feature: $KERNEL_FEATURE_CTX_KTIME_BOOT }
    { field: "boot_time", feature: $KERNEL_FEATURE_CTX_KTIME_BOOT }
    { field: "ktime_coarse", feature: $KERNEL_FEATURE_CTX_KTIME_COARSE }
    { field: "coarse_ktime", feature: $KERNEL_FEATURE_CTX_KTIME_COARSE }
    { field: "coarse_time", feature: $KERNEL_FEATURE_CTX_KTIME_COARSE }
    { field: "ktime_tai", feature: $KERNEL_FEATURE_CTX_KTIME_TAI }
    { field: "tai_ktime", feature: $KERNEL_FEATURE_CTX_KTIME_TAI }
    { field: "tai_time", feature: $KERNEL_FEATURE_CTX_KTIME_TAI }
    { field: "jiffies", feature: $KERNEL_FEATURE_CTX_JIFFIES }
    { field: "func_ip", feature: $KERNEL_FEATURE_CTX_FUNC_IP }
    { field: "function_ip", feature: $KERNEL_FEATURE_CTX_FUNC_IP }
    { field: "attach_cookie", feature: $KERNEL_FEATURE_CTX_ATTACH_COOKIE }
    { field: "bpf_cookie", feature: $KERNEL_FEATURE_CTX_ATTACH_COOKIE }
    { field: "cgroup_id", feature: $KERNEL_FEATURE_CTX_CGROUP_ID }
    { field: "perf_counter", feature: $KERNEL_FEATURE_CTX_PERF_COUNTER }
    { field: "perf_enabled", feature: $KERNEL_FEATURE_CTX_PERF_ENABLED }
    { field: "perf_running", feature: $KERNEL_FEATURE_CTX_PERF_RUNNING }
    { field: "socket_cookie", feature: $KERNEL_FEATURE_CTX_SOCKET_COOKIE }
    { field: "socket_uid", feature: $KERNEL_FEATURE_CTX_SOCKET_UID }
    { field: "netns_cookie", feature: $KERNEL_FEATURE_CTX_NETNS_COOKIE }
    { field: "csum_level", feature: $KERNEL_FEATURE_CTX_CSUM_LEVEL }
    { field: "hash_recalc", feature: $KERNEL_FEATURE_CTX_HASH_RECALC }
    { field: "recalc_hash", feature: $KERNEL_FEATURE_CTX_HASH_RECALC }
    { field: "skb_cgroup_id", feature: $KERNEL_FEATURE_CTX_SKB_CGROUP_ID }
    { field: "xdp_buff_len", feature: $KERNEL_FEATURE_CTX_XDP_BUFF_LEN }
    { field: "xdp_buffer_len", feature: $KERNEL_FEATURE_CTX_XDP_BUFF_LEN }
    { field: "sysctl_name", feature: $KERNEL_FEATURE_CTX_SYSCTL_NAME }
    { field: "sysctl_base_name", feature: $KERNEL_FEATURE_CTX_SYSCTL_BASE_NAME }
    { field: "sysctl_current_value", feature: $KERNEL_FEATURE_CTX_SYSCTL_CURRENT_VALUE }
    { field: "sysctl_new_value", feature: $KERNEL_FEATURE_CTX_SYSCTL_NEW_VALUE }
    { field: "arg_count", feature: $KERNEL_FEATURE_CTX_ARG_COUNT }
    { field: "kstack", feature: $KERNEL_FEATURE_CTX_KSTACK }
    { field: "ustack", feature: $KERNEL_FEATURE_CTX_USTACK }
]
