const KERNEL_FEATURE_BPF_KTIME_GET_NS = {
    key: "helper:bpf_ktime_get_ns"
    min_kernel: "4.1"
    source: "https://github.com/torvalds/linux/blob/v4.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_KTIME_GET_BOOT_NS = {
    key: "helper:bpf_ktime_get_boot_ns"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_KTIME_GET_COARSE_NS = {
    key: "helper:bpf_ktime_get_coarse_ns"
    min_kernel: "5.11"
    source: "https://github.com/torvalds/linux/blob/v5.11/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_KTIME_GET_TAI_NS = {
    key: "helper:bpf_ktime_get_tai_ns"
    min_kernel: "6.1"
    source: "https://github.com/torvalds/linux/blob/v6.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_JIFFIES64 = {
    key: "helper:bpf_jiffies64"
    min_kernel: "5.6"
    source: "https://github.com/torvalds/linux/blob/v5.6/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_GET_CURRENT_PID_TGID = {
    key: "helper:bpf_get_current_pid_tgid"
    min_kernel: "4.2"
    source: "https://github.com/torvalds/linux/blob/v4.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_GET_CURRENT_UID_GID = {
    key: "helper:bpf_get_current_uid_gid"
    min_kernel: "4.2"
    source: "https://github.com/torvalds/linux/blob/v4.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_GET_CURRENT_COMM = {
    key: "helper:bpf_get_current_comm"
    min_kernel: "4.2"
    source: "https://github.com/torvalds/linux/blob/v4.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_GET_SMP_PROCESSOR_ID = {
    key: "helper:bpf_get_smp_processor_id"
    min_kernel: "4.1"
    source: "https://github.com/torvalds/linux/blob/v4.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_GET_CGROUP_CLASSID = {
    key: "helper:bpf_get_cgroup_classid"
    min_kernel: "4.3"
    source: "https://github.com/torvalds/linux/blob/v4.3/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_GET_ROUTE_REALM = {
    key: "helper:bpf_get_route_realm"
    min_kernel: "4.4"
    source: "https://github.com/torvalds/linux/blob/v4.4/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_GET_NUMA_NODE_ID = {
    key: "helper:bpf_get_numa_node_id"
    min_kernel: "4.10"
    source: "https://github.com/torvalds/linux/blob/v4.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_GET_SOCKET_COOKIE = {
    key: "helper:bpf_get_socket_cookie"
    min_kernel: "4.12"
    source: "https://github.com/torvalds/linux/blob/v4.12/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_GET_SOCKET_UID = {
    key: "helper:bpf_get_socket_uid"
    min_kernel: "4.12"
    source: "https://github.com/torvalds/linux/blob/v4.12/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_GET_CURRENT_CGROUP_ID = {
    key: "helper:bpf_get_current_cgroup_id"
    min_kernel: "4.18"
    source: "https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_GET_CURRENT_ANCESTOR_CGROUP_ID = {
    key: "helper:bpf_get_current_ancestor_cgroup_id"
    min_kernel: "5.7"
    source: "https://github.com/torvalds/linux/blob/v5.7/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_GET_NS_CURRENT_PID_TGID = {
    key: "helper:bpf_get_ns_current_pid_tgid"
    min_kernel: "5.7"
    source: "https://github.com/torvalds/linux/blob/v5.7/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SKB_CGROUP_ID = {
    key: "helper:bpf_skb_cgroup_id"
    min_kernel: "4.18"
    source: "https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SKB_ANCESTOR_CGROUP_ID = {
    key: "helper:bpf_skb_ancestor_cgroup_id"
    min_kernel: "4.19"
    source: "https://github.com/torvalds/linux/blob/v4.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SKB_CGROUP_CLASSID = {
    key: "helper:bpf_skb_cgroup_classid"
    min_kernel: "5.10"
    source: "https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SK_CGROUP_ID = {
    key: "helper:bpf_sk_cgroup_id"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SK_ANCESTOR_CGROUP_ID = {
    key: "helper:bpf_sk_ancestor_cgroup_id"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SK_FULLSOCK = {
    key: "helper:bpf_sk_fullsock"
    min_kernel: "5.1"
    source: "https://github.com/torvalds/linux/blob/v5.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_TCP_SOCK = {
    key: "helper:bpf_tcp_sock"
    min_kernel: "5.1"
    source: "https://github.com/torvalds/linux/blob/v5.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_GET_LISTENER_SOCK = {
    key: "helper:bpf_get_listener_sock"
    min_kernel: "5.1"
    source: "https://github.com/torvalds/linux/blob/v5.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_GET_NETNS_COOKIE = {
    key: "helper:bpf_get_netns_cookie"
    min_kernel: "5.7"
    source: "https://github.com/torvalds/linux/blob/v5.7/include/uapi/linux/bpf.h"
}
