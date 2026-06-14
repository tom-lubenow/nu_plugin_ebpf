const KERNEL_FEATURE_PROG_CGROUP_SKB = {
    key: "program:BPF_PROG_TYPE_CGROUP_SKB"
    min_kernel: "4.10"
    source: "https://github.com/torvalds/linux/blob/v4.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_PROG_CGROUP_SOCK = {
    key: "program:BPF_PROG_TYPE_CGROUP_SOCK"
    min_kernel: "4.10"
    source: "https://github.com/torvalds/linux/blob/v4.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_PROG_CGROUP_DEVICE = {
    key: "program:BPF_PROG_TYPE_CGROUP_DEVICE"
    min_kernel: "4.15"
    source: "https://github.com/torvalds/linux/blob/v4.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_PROG_CGROUP_SOCK_ADDR = {
    key: "program:BPF_PROG_TYPE_CGROUP_SOCK_ADDR"
    min_kernel: "4.17"
    source: "https://github.com/torvalds/linux/blob/v4.17/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_PROG_CGROUP_SYSCTL = {
    key: "program:BPF_PROG_TYPE_CGROUP_SYSCTL"
    min_kernel: "5.2"
    source: "https://github.com/torvalds/linux/blob/v5.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_PROG_CGROUP_SOCKOPT = {
    key: "program:BPF_PROG_TYPE_CGROUP_SOCKOPT"
    min_kernel: "5.3"
    source: "https://github.com/torvalds/linux/blob/v5.3/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_PROG_SOCK_OPS = {
    key: "program:BPF_PROG_TYPE_SOCK_OPS"
    min_kernel: "4.14"
    source: "https://github.com/torvalds/linux/blob/v4.14/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_ATTACH_UPROBE_MULTI = {
    key: "attach:BPF_TRACE_UPROBE_MULTI"
    min_kernel: "6.6"
    source: "https://github.com/torvalds/linux/blob/v6.6/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_ATTACH_CGROUP_UNIX_SOCK_ADDR = {
    key: "attach:BPF_CGROUP_UNIX_SOCK_ADDR"
    min_kernel: "6.7"
    source: "https://github.com/torvalds/linux/blob/v6.7/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_PROG_LIRC_MODE2 = {
    key: "program:BPF_PROG_TYPE_LIRC_MODE2"
    min_kernel: "4.18"
    source: "https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_PROG_LSM_CGROUP = {
    key: "attach:BPF_LSM_CGROUP"
    min_kernel: "6.0"
    source: "https://github.com/torvalds/linux/blob/v6.0/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_PROG_EXTENSION = {
    key: "program:BPF_PROG_TYPE_EXT"
    min_kernel: "5.6"
    source: "https://github.com/torvalds/linux/blob/v5.6/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_PROG_SYSCALL = {
    key: "program:BPF_PROG_TYPE_SYSCALL"
    min_kernel: "5.14"
    source: "https://github.com/torvalds/linux/blob/v5.14/include/uapi/linux/bpf.h"
}
