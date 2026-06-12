const KERNEL_FEATURE_CTX_PID = {
    key: "ctx:pid"
    min_kernel: "4.2"
    source: "https://github.com/torvalds/linux/blob/v4.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_TGID = {
    key: "ctx:tgid"
    min_kernel: "4.2"
    source: "https://github.com/torvalds/linux/blob/v4.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_PID_TGID = {
    key: "ctx:pid_tgid"
    min_kernel: "4.2"
    source: "https://github.com/torvalds/linux/blob/v4.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_UID = {
    key: "ctx:uid"
    min_kernel: "4.2"
    source: "https://github.com/torvalds/linux/blob/v4.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_GID = {
    key: "ctx:gid"
    min_kernel: "4.2"
    source: "https://github.com/torvalds/linux/blob/v4.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_UID_GID = {
    key: "ctx:uid_gid"
    min_kernel: "4.2"
    source: "https://github.com/torvalds/linux/blob/v4.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_COMM = {
    key: "ctx:comm"
    min_kernel: "4.2"
    source: "https://github.com/torvalds/linux/blob/v4.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_CGROUP_CLASSID = {
    key: "ctx:cgroup_classid"
    min_kernel: "4.3"
    source: "https://github.com/torvalds/linux/blob/v4.3/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_ROUTE_REALM = {
    key: "ctx:route_realm"
    min_kernel: "4.4"
    source: "https://github.com/torvalds/linux/blob/v4.4/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_CPU = {
    key: "ctx:cpu"
    min_kernel: "4.1"
    source: "https://github.com/torvalds/linux/blob/v4.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_NUMA_NODE = {
    key: "ctx:numa_node"
    min_kernel: "4.10"
    source: "https://github.com/torvalds/linux/blob/v4.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_RANDOM = {
    key: "ctx:random"
    min_kernel: "4.1"
    source: "https://github.com/torvalds/linux/blob/v4.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_TIMESTAMP = {
    key: "ctx:timestamp"
    min_kernel: "4.1"
    source: "https://github.com/torvalds/linux/blob/v4.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_TASK = {
    key: "ctx:task"
    min_kernel: "5.11"
    source: "https://github.com/torvalds/linux/blob/v5.11/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_CGROUP = {
    key: "ctx:cgroup"
    min_kernel: "5.11"
    source: "https://github.com/torvalds/linux/blob/v5.11/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_KTIME_BOOT = {
    key: "ctx:ktime_boot"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_KTIME_COARSE = {
    key: "ctx:ktime_coarse"
    min_kernel: "5.11"
    source: "https://github.com/torvalds/linux/blob/v5.11/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_KTIME_TAI = {
    key: "ctx:ktime_tai"
    min_kernel: "6.1"
    source: "https://github.com/torvalds/linux/blob/v6.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_JIFFIES = {
    key: "ctx:jiffies"
    min_kernel: "5.6"
    source: "https://github.com/torvalds/linux/blob/v5.6/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_FUNC_IP = {
    key: "ctx:func_ip"
    min_kernel: "5.15"
    source: "https://github.com/torvalds/linux/blob/v5.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_ATTACH_COOKIE = {
    key: "ctx:attach_cookie"
    min_kernel: "5.15"
    source: "https://github.com/torvalds/linux/blob/v5.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_CGROUP_ID = {
    key: "ctx:cgroup_id"
    min_kernel: "4.18"
    source: "https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_PERF_COUNTER = {
    key: "ctx:perf_counter"
    min_kernel: "4.15"
    source: "https://github.com/torvalds/linux/blob/v4.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_PERF_ENABLED = {
    key: "ctx:perf_enabled"
    min_kernel: "4.15"
    source: "https://github.com/torvalds/linux/blob/v4.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_PERF_RUNNING = {
    key: "ctx:perf_running"
    min_kernel: "4.15"
    source: "https://github.com/torvalds/linux/blob/v4.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SOCKET_COOKIE = {
    key: "ctx:socket_cookie"
    min_kernel: "4.12"
    source: "https://github.com/torvalds/linux/blob/v4.12/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SOCKET_UID = {
    key: "ctx:socket_uid"
    min_kernel: "4.12"
    source: "https://github.com/torvalds/linux/blob/v4.12/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_NETNS_COOKIE = {
    key: "ctx:netns_cookie"
    min_kernel: "5.7"
    source: "https://github.com/torvalds/linux/blob/v5.7/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_CSUM_LEVEL = {
    key: "ctx:csum_level"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_HASH_RECALC = {
    key: "ctx:hash_recalc"
    min_kernel: "4.8"
    source: "https://github.com/torvalds/linux/blob/v4.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SKB_CGROUP_ID = {
    key: "ctx:skb_cgroup_id"
    min_kernel: "4.18"
    source: "https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_XDP_BUFF_LEN = {
    key: "ctx:xdp_buff_len"
    min_kernel: "5.18"
    source: "https://github.com/torvalds/linux/blob/v5.18/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SYSCTL_NAME = {
    key: "ctx:sysctl_name"
    min_kernel: "5.2"
    source: "https://github.com/torvalds/linux/blob/v5.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SYSCTL_BASE_NAME = {
    key: "ctx:sysctl_base_name"
    min_kernel: "5.2"
    source: "https://github.com/torvalds/linux/blob/v5.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SYSCTL_CURRENT_VALUE = {
    key: "ctx:sysctl_current_value"
    min_kernel: "5.2"
    source: "https://github.com/torvalds/linux/blob/v5.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SYSCTL_NEW_VALUE = {
    key: "ctx:sysctl_new_value"
    min_kernel: "5.2"
    source: "https://github.com/torvalds/linux/blob/v5.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SYSCTL_WRITE = {
    key: "ctx:write"
    min_kernel: "5.2"
    source: "https://github.com/torvalds/linux/blob/v5.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SYSCTL_FILE_POS = {
    key: "ctx:file_pos"
    min_kernel: "5.2"
    source: "https://github.com/torvalds/linux/blob/v5.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SOCKOPT_LEVEL = {
    key: "ctx:level"
    min_kernel: "5.3"
    source: "https://github.com/torvalds/linux/blob/v5.3/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SOCKOPT_OPTNAME = {
    key: "ctx:optname"
    min_kernel: "5.3"
    source: "https://github.com/torvalds/linux/blob/v5.3/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SOCKOPT_OPTLEN = {
    key: "ctx:optlen"
    min_kernel: "5.3"
    source: "https://github.com/torvalds/linux/blob/v5.3/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SOCKOPT_OPTVAL = {
    key: "ctx:optval"
    min_kernel: "5.3"
    source: "https://github.com/torvalds/linux/blob/v5.3/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SOCKOPT_OPTVAL_END = {
    key: "ctx:optval_end"
    min_kernel: "5.3"
    source: "https://github.com/torvalds/linux/blob/v5.3/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_SOCKOPT_RETVAL = {
    key: "ctx:sockopt_retval"
    min_kernel: "5.3"
    source: "https://github.com/torvalds/linux/blob/v5.3/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_RETVAL_PT_REGS = {
    key: "ctx:retval"
    min_kernel: "4.1"
    source: "https://github.com/torvalds/linux/blob/v4.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_RETVAL_TRAMPOLINE = {
    key: "ctx:retval"
    min_kernel: "5.5"
    source: "https://github.com/torvalds/linux/blob/v5.5/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_ARG_COUNT = {
    key: "ctx:arg_count"
    min_kernel: "5.17"
    source: "https://github.com/torvalds/linux/blob/v5.17/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_KSTACK = {
    key: "ctx:kstack"
    min_kernel: "4.6"
    source: "https://github.com/torvalds/linux/blob/v4.6/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_CTX_USTACK = {
    key: "ctx:ustack"
    min_kernel: "4.6"
    source: "https://github.com/torvalds/linux/blob/v4.6/include/uapi/linux/bpf.h"
}
