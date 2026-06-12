const VERIFIER_DIFF_METADATA_DIR = (path self | path dirname)
const BPFFS = "/sys/fs/bpf"
const VALID_TIERS = ["fast" "btf" "kernel" "vm-only"]
const VALID_TEST_LANES = ["host-safe" "host-gated" "dry-run" "vm-only"]
const VALID_HOST_FEATURES = [
    "cgroup-v2"
    "kernel-btf"
    "lirc-device"
    "loopback-interface"
    "netns-self"
    "tracefs"
]
const HOST_FEATURE_PREFIX_KERNEL_BTF_KFUNC = "kernel-btf-kfunc:"

def test-lane-description [lane: string] {
    if $lane == "host-safe" {
        "safe for default host integration-test lanes"
    } else if $lane == "host-gated" {
        "requires explicit host resources, elevated privileges, or host-specific setup"
    } else if $lane == "dry-run" {
        "compile/dry-run coverage only; live attach is not modeled as safe"
    } else if $lane == "vm-only" {
        "behavior-changing or high-risk coverage should run in an isolated VM"
    } else {
        ""
    }
}

const KERNEL_FEATURE_PROG_RAW_TRACEPOINT = {
    key: "program:BPF_PROG_TYPE_RAW_TRACEPOINT"
    min_kernel: "4.17"
    source: "https://github.com/torvalds/linux/blob/v4.17/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_PROG_RAW_TRACEPOINT_WRITABLE = {
    key: "section:raw_tracepoint.w"
    min_kernel: "5.2"
    source: "https://github.com/torvalds/linux/blob/v5.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_PROG_SOCKET_FILTER = {
    key: "program:BPF_PROG_TYPE_SOCKET_FILTER"
    min_kernel: "3.19"
    source: "https://github.com/torvalds/linux/blob/v3.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_PROG_KPROBE = {
    key: "program:BPF_PROG_TYPE_KPROBE"
    min_kernel: "4.1"
    source: "https://github.com/torvalds/linux/blob/v4.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SUBPROGRAM_CALLS = {
    key: "compiled:bpf-subprogram-calls"
    min_kernel: "4.16"
    source: "https://github.com/torvalds/linux/blob/v4.16/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BOUNDED_LOOPS = {
    key: "compiled:bounded-loops"
    min_kernel: "5.3"
    source: "https://github.com/torvalds/linux/blob/v5.3/kernel/bpf/verifier.c"
}
const KERNEL_FEATURE_PROG_SCHED_CLS = {
    key: "program:BPF_PROG_TYPE_SCHED_CLS"
    min_kernel: "4.1"
    source: "https://github.com/torvalds/linux/blob/v4.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_PROG_TRACEPOINT = {
    key: "program:BPF_PROG_TYPE_TRACEPOINT"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_PROG_PERF_EVENT = {
    key: "program:BPF_PROG_TYPE_PERF_EVENT"
    min_kernel: "4.9"
    source: "https://github.com/torvalds/linux/blob/v4.9/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_PROG_TRACING = {
    key: "program:BPF_PROG_TYPE_TRACING"
    min_kernel: "5.5"
    source: "https://github.com/torvalds/linux/blob/v5.5/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_PROG_LSM = {
    key: "program:BPF_PROG_TYPE_LSM"
    min_kernel: "5.7"
    source: "https://github.com/torvalds/linux/blob/v5.7/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_KERNEL_BTF = {
    key: "kernel:btf-vmlinux"
    min_kernel: "5.2"
    source: "https://github.com/torvalds/linux/blob/v5.2/scripts/link-vmlinux.sh"
}
const KERNEL_FEATURE_BPF_TRAMPOLINE = {
    key: "program:bpf-trampoline"
    min_kernel: "5.5"
    source: "https://github.com/torvalds/linux/blob/v5.5/kernel/bpf/trampoline.c"
}
const KERNEL_FEATURE_SLEEPABLE_PROGRAM = {
    key: "section:sleepable-program"
    min_kernel: "5.10"
    source: "https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_ATTACH_KPROBE_MULTI = {
    key: "attach:BPF_TRACE_KPROBE_MULTI"
    min_kernel: "5.18"
    source: "https://github.com/torvalds/linux/blob/v5.18/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_PROG_XDP = {
    key: "program:BPF_PROG_TYPE_XDP"
    min_kernel: "4.8"
    source: "https://github.com/torvalds/linux/blob/v4.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_XDP_ATTACH_SKB = {
    key: "attach:xdp-skb"
    min_kernel: "4.12"
    source: "https://github.com/torvalds/linux/blob/v4.12/include/uapi/linux/if_link.h"
}
const KERNEL_FEATURE_XDP_ATTACH_DRV = {
    key: "attach:xdp-drv"
    min_kernel: "4.12"
    source: "https://github.com/torvalds/linux/blob/v4.12/include/uapi/linux/if_link.h"
}
const KERNEL_FEATURE_XDP_ATTACH_HW = {
    key: "attach:xdp-hw"
    min_kernel: "4.13"
    source: "https://github.com/torvalds/linux/blob/v4.13/include/uapi/linux/if_link.h"
}
const KERNEL_FEATURE_XDP_ATTACH_DEVMAP = {
    key: "attach:BPF_XDP_DEVMAP"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_XDP_ATTACH_CPUMAP = {
    key: "attach:BPF_XDP_CPUMAP"
    min_kernel: "5.9"
    source: "https://github.com/torvalds/linux/blob/v5.9/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_XDP_MULTI_BUFFER = {
    key: "section:xdp.frags"
    min_kernel: "5.18"
    source: "https://github.com/torvalds/linux/blob/v5.18/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_PROG_SCHED_ACT = {
    key: "program:BPF_PROG_TYPE_SCHED_ACT"
    min_kernel: "4.1"
    source: "https://github.com/torvalds/linux/blob/v4.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_PROG_FLOW_DISSECTOR = {
    key: "program:BPF_PROG_TYPE_FLOW_DISSECTOR"
    min_kernel: "4.20"
    source: "https://github.com/torvalds/linux/blob/v4.20/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_ATTACH_TCX = {
    key: "attach:tcx"
    min_kernel: "6.6"
    source: "https://github.com/torvalds/linux/blob/v6.6/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_ATTACH_NETKIT = {
    key: "attach:netkit"
    min_kernel: "6.7"
    source: "https://github.com/torvalds/linux/blob/v6.7/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_NETFILTER_LINK = {
    key: "attach:netfilter-link"
    min_kernel: "6.4"
    source: "https://github.com/torvalds/linux/blob/v6.4/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_NETFILTER_DEFRAG = {
    key: "attach:netfilter-defrag"
    min_kernel: "6.6"
    source: "https://github.com/torvalds/linux/blob/v6.6/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_PROG_LWT = {
    key: "program:BPF_PROG_TYPE_LWT"
    min_kernel: "4.10"
    source: "https://github.com/torvalds/linux/blob/v4.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_PROG_LWT_SEG6LOCAL = {
    key: "program:BPF_PROG_TYPE_LWT_SEG6LOCAL"
    min_kernel: "4.18"
    source: "https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_PROG_SK_LOOKUP = {
    key: "program:BPF_PROG_TYPE_SK_LOOKUP"
    min_kernel: "5.9"
    source: "https://github.com/torvalds/linux/blob/v5.9/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_PROG_SK_MSG = {
    key: "program:BPF_PROG_TYPE_SK_MSG"
    min_kernel: "4.17"
    source: "https://github.com/torvalds/linux/blob/v4.17/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_PROG_SK_SKB = {
    key: "program:BPF_PROG_TYPE_SK_SKB"
    min_kernel: "4.14"
    source: "https://github.com/torvalds/linux/blob/v4.14/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_SK_REUSEPORT_ATTACH = {
    key: "attach:BPF_SK_REUSEPORT_SELECT"
    min_kernel: "4.19"
    source: "https://github.com/torvalds/linux/blob/v4.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_SK_REUSEPORT_MIGRATION = {
    key: "attach:BPF_SK_REUSEPORT_SELECT_OR_MIGRATE"
    min_kernel: "5.14"
    source: "https://github.com/torvalds/linux/blob/v5.14/include/uapi/linux/bpf.h"
}
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
const KERNEL_FEATURE_PROG_STRUCT_OPS = {
    key: "program:BPF_PROG_TYPE_STRUCT_OPS"
    min_kernel: "5.6"
    source: "https://github.com/torvalds/linux/blob/v5.6/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_STRUCT_OPS_TCP_CONGESTION = {
    key: "struct_ops:tcp_congestion_ops"
    min_kernel: "5.6"
    source: "https://github.com/torvalds/linux/blob/v5.6/net/ipv4/bpf_tcp_ca.c"
}
const KERNEL_FEATURE_STRUCT_OPS_HID_BPF = {
    key: "struct_ops:hid_bpf_ops"
    min_kernel: "6.11"
    source: "https://github.com/torvalds/linux/blob/v6.11/drivers/hid/bpf/hid_bpf_struct_ops.c"
}
const KERNEL_FEATURE_STRUCT_OPS_SCHED_EXT = {
    key: "struct_ops:sched_ext_ops"
    min_kernel: "6.12"
    source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c"
}
const KERNEL_FEATURE_STRUCT_OPS_QDISC = {
    key: "struct_ops:Qdisc_ops"
    min_kernel: "6.16"
    source: "https://github.com/torvalds/linux/blob/v6.16/net/sched/bpf_qdisc.c"
}
const SCHED_EXT_SLEEPABLE_CALLBACKS = [
    init_task
    cgroup_init
    cgroup_exit
    cgroup_prep_move
    cpu_online
    cpu_offline
    init
    exit
]
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
const KERNEL_FEATURE_PROG_ITER = {
    key: "program:BPF_PROG_TYPE_TRACING-iter"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_ITER_TARGET_TASK = {
    key: "iter-target:task"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/kernel/bpf/task_iter.c"
}
const KERNEL_FEATURE_ITER_TARGET_TASK_FILE = {
    key: "iter-target:task_file"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/kernel/bpf/task_iter.c"
}
const KERNEL_FEATURE_ITER_TARGET_TASK_VMA = {
    key: "iter-target:task_vma"
    min_kernel: "5.12"
    source: "https://github.com/torvalds/linux/blob/v5.12/kernel/bpf/task_iter.c"
}
const KERNEL_FEATURE_ITER_TARGET_BPF_MAP = {
    key: "iter-target:bpf_map"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/kernel/bpf/map_iter.c"
}
const KERNEL_FEATURE_ITER_TARGET_CGROUP = {
    key: "iter-target:cgroup"
    min_kernel: "6.1"
    source: "https://github.com/torvalds/linux/blob/v6.1/kernel/bpf/cgroup_iter.c"
}
const KERNEL_FEATURE_ITER_TARGET_BPF_MAP_ELEM = {
    key: "iter-target:bpf_map_elem"
    min_kernel: "5.9"
    source: "https://github.com/torvalds/linux/blob/v5.9/kernel/bpf/map_iter.c"
}
const KERNEL_FEATURE_ITER_TARGET_BPF_SK_STORAGE_MAP = {
    key: "iter-target:bpf_sk_storage_map"
    min_kernel: "5.9"
    source: "https://github.com/torvalds/linux/blob/v5.9/net/core/bpf_sk_storage.c"
}
const KERNEL_FEATURE_ITER_TARGET_SOCKMAP = {
    key: "iter-target:sockmap"
    min_kernel: "5.10"
    source: "https://github.com/torvalds/linux/blob/v5.10/net/core/sock_map.c"
}
const KERNEL_FEATURE_ITER_TARGET_BPF_PROG = {
    key: "iter-target:bpf_prog"
    min_kernel: "5.9"
    source: "https://github.com/torvalds/linux/blob/v5.9/kernel/bpf/prog_iter.c"
}
const KERNEL_FEATURE_ITER_TARGET_BPF_LINK = {
    key: "iter-target:bpf_link"
    min_kernel: "5.19"
    source: "https://github.com/torvalds/linux/blob/v5.19/kernel/bpf/link_iter.c"
}
const KERNEL_FEATURE_ITER_TARGET_TCP = {
    key: "iter-target:tcp"
    min_kernel: "5.9"
    source: "https://github.com/torvalds/linux/blob/v5.9/net/ipv4/tcp_ipv4.c"
}
const KERNEL_FEATURE_ITER_TARGET_UDP = {
    key: "iter-target:udp"
    min_kernel: "5.9"
    source: "https://github.com/torvalds/linux/blob/v5.9/net/ipv4/udp.c"
}
const KERNEL_FEATURE_ITER_TARGET_UNIX = {
    key: "iter-target:unix"
    min_kernel: "5.15"
    source: "https://github.com/torvalds/linux/blob/v5.15/net/unix/af_unix.c"
}
const KERNEL_FEATURE_ITER_TARGET_IPV6_ROUTE = {
    key: "iter-target:ipv6_route"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/net/ipv6/route.c"
}
const KERNEL_FEATURE_ITER_TARGET_KSYM = {
    key: "iter-target:ksym"
    min_kernel: "6.0"
    source: "https://github.com/torvalds/linux/blob/v6.0/kernel/kallsyms.c"
}
const KERNEL_FEATURE_ITER_TARGET_NETLINK = {
    key: "iter-target:netlink"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/net/netlink/af_netlink.c"
}
const KERNEL_FEATURE_ITER_TARGET_KMEM_CACHE = {
    key: "iter-target:kmem_cache"
    min_kernel: "6.13"
    source: "https://github.com/torvalds/linux/blob/v6.13/kernel/bpf/kmem_cache_iter.c"
}
const KERNEL_FEATURE_ITER_TARGET_DMABUF = {
    key: "iter-target:dmabuf"
    min_kernel: "6.16"
    source: "https://github.com/torvalds/linux/blob/v6.16/kernel/bpf/dmabuf_iter.c"
}
const PROGRAM_TARGET_KERNEL_FEATURE_EXPECTATIONS = [
    { target: "fentry:security_file_open" feature_keys: ["kernel:btf-vmlinux" "program:BPF_PROG_TYPE_TRACING" "program:bpf-trampoline"] }
    { target: "fentry.s:security_file_open" feature_keys: ["kernel:btf-vmlinux" "program:BPF_PROG_TYPE_TRACING" "program:bpf-trampoline" "section:sleepable-program"] }
    { target: "fexit:ksys_read" feature_keys: ["kernel:btf-vmlinux" "program:BPF_PROG_TYPE_TRACING" "program:bpf-trampoline"] }
    { target: "fexit.s:ksys_read" feature_keys: ["kernel:btf-vmlinux" "program:BPF_PROG_TYPE_TRACING" "program:bpf-trampoline" "section:sleepable-program"] }
    { target: "fmod_ret:security_file_open" feature_keys: ["kernel:btf-vmlinux" "program:BPF_PROG_TYPE_TRACING" "program:bpf-trampoline"] }
    { target: "fmod_ret.s:security_file_open" feature_keys: ["kernel:btf-vmlinux" "program:BPF_PROG_TYPE_TRACING" "program:bpf-trampoline" "section:sleepable-program"] }
    { target: "tp_btf:sys_enter" feature_keys: ["kernel:btf-vmlinux" "program:BPF_PROG_TYPE_TRACING"] }
    { target: "lsm:file_open" feature_keys: ["kernel:btf-vmlinux" "program:BPF_PROG_TYPE_TRACING" "program:bpf-trampoline" "program:BPF_PROG_TYPE_LSM"] }
    { target: "lsm_cgroup:socket_bind" feature_keys: ["kernel:btf-vmlinux" "program:BPF_PROG_TYPE_TRACING" "program:bpf-trampoline" "program:BPF_PROG_TYPE_LSM" "attach:BPF_LSM_CGROUP"] }
    { target: "lsm.s:file_open" feature_keys: ["kernel:btf-vmlinux" "program:BPF_PROG_TYPE_TRACING" "program:bpf-trampoline" "program:BPF_PROG_TYPE_LSM" "section:sleepable-program"] }
    { target: "struct_ops:sched_ext_ops.init" feature_keys: ["kernel:btf-vmlinux" "program:bpf-trampoline" "program:BPF_PROG_TYPE_STRUCT_OPS" "struct_ops:sched_ext_ops" "section:sleepable-program"] }
    { target: "struct_ops:tcp_congestion_ops" feature_keys: ["kernel:btf-vmlinux" "program:bpf-trampoline" "program:BPF_PROG_TYPE_STRUCT_OPS" "struct_ops:tcp_congestion_ops"] }
    { target: "kprobe.multi:vfs_*" feature_keys: ["program:BPF_PROG_TYPE_KPROBE" "attach:BPF_TRACE_KPROBE_MULTI"] }
    { target: "kretprobe.multi:vfs_*" feature_keys: ["program:BPF_PROG_TYPE_KPROBE" "attach:BPF_TRACE_KPROBE_MULTI"] }
    { target: "uprobe.s:/bin/bash:main" feature_keys: ["program:BPF_PROG_TYPE_KPROBE" "section:sleepable-program"] }
    { target: "uretprobe.s:/lib/libc.so.6:malloc" feature_keys: ["program:BPF_PROG_TYPE_KPROBE" "section:sleepable-program"] }
    { target: "uprobe.multi:/bin/bash:read*" feature_keys: ["program:BPF_PROG_TYPE_KPROBE" "attach:BPF_TRACE_UPROBE_MULTI"] }
    { target: "uretprobe.multi:/bin/bash:read*" feature_keys: ["program:BPF_PROG_TYPE_KPROBE" "attach:BPF_TRACE_UPROBE_MULTI"] }
    { target: "uprobe.multi.s:/bin/bash:read*" feature_keys: ["program:BPF_PROG_TYPE_KPROBE" "attach:BPF_TRACE_UPROBE_MULTI" "section:sleepable-program"] }
    { target: "uretprobe.multi.s:/bin/bash:read*" feature_keys: ["program:BPF_PROG_TYPE_KPROBE" "attach:BPF_TRACE_UPROBE_MULTI" "section:sleepable-program"] }
    { target: "raw_tracepoint.w:sys_enter" feature_keys: ["program:BPF_PROG_TYPE_RAW_TRACEPOINT" "section:raw_tracepoint.w"] }
    { target: "tracepoint:syscalls/sys_enter_openat" feature_keys: ["program:BPF_PROG_TYPE_TRACEPOINT"] }
    { target: "perf_event:software:cpu-clock:period=100000" feature_keys: ["program:BPF_PROG_TYPE_PERF_EVENT"] }
    { target: "xdp:lo" feature_keys: ["program:BPF_PROG_TYPE_XDP" "attach:xdp-skb"] }
    { target: "xdp:lo:drv:frags" feature_keys: ["program:BPF_PROG_TYPE_XDP" "attach:xdp-drv" "section:xdp.frags"] }
    { target: "xdp:lo:hw" feature_keys: ["program:BPF_PROG_TYPE_XDP" "attach:xdp-hw"] }
    { target: "xdp:devmap" feature_keys: ["program:BPF_PROG_TYPE_XDP" "attach:BPF_XDP_DEVMAP"] }
    { target: "xdp:cpumap" feature_keys: ["program:BPF_PROG_TYPE_XDP" "attach:BPF_XDP_CPUMAP"] }
    { target: "socket_filter:tcp4:127.0.0.1:8080" feature_keys: ["program:BPF_PROG_TYPE_SOCKET_FILTER"] }
    { target: "tc:lo:ingress" feature_keys: ["program:BPF_PROG_TYPE_SCHED_CLS"] }
    { target: "tc_action:demo-action" feature_keys: ["program:BPF_PROG_TYPE_SCHED_ACT"] }
    { target: "tcx:lo:egress" feature_keys: ["attach:tcx"] }
    { target: "netkit:lo:peer" feature_keys: ["attach:netkit"] }
    { target: "flow_dissector:/proc/self/ns/net" feature_keys: ["program:BPF_PROG_TYPE_FLOW_DISSECTOR"] }
    { target: "netfilter:ipv4:pre_routing" feature_keys: ["attach:netfilter-link"] }
    { target: "netfilter:ipv4:pre_routing:priority=-100:defrag" feature_keys: ["attach:netfilter-link" "attach:netfilter-defrag"] }
    { target: "lwt_seg6local:demo-route" feature_keys: ["program:BPF_PROG_TYPE_LWT" "program:BPF_PROG_TYPE_LWT_SEG6LOCAL"] }
    { target: "sk_lookup:/proc/self/ns/net" feature_keys: ["program:BPF_PROG_TYPE_SK_LOOKUP"] }
    { target: "sk_msg:/sys/fs/bpf/demo_sockmap" feature_keys: ["program:BPF_PROG_TYPE_SK_MSG"] }
    { target: "sk_skb:/sys/fs/bpf/demo_sockmap" feature_keys: ["program:BPF_PROG_TYPE_SK_SKB"] }
    { target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap" feature_keys: ["program:BPF_PROG_TYPE_SK_SKB"] }
    { target: "sk_reuseport:select" feature_keys: ["attach:BPF_SK_REUSEPORT_SELECT"] }
    { target: "sk_reuseport:migrate" feature_keys: ["attach:BPF_SK_REUSEPORT_SELECT" "attach:BPF_SK_REUSEPORT_SELECT_OR_MIGRATE"] }
    { target: "cgroup_skb:/sys/fs/cgroup:egress" feature_keys: ["program:BPF_PROG_TYPE_CGROUP_SKB"] }
    { target: "cgroup_sock_addr:/sys/fs/cgroup:connect4" feature_keys: ["program:BPF_PROG_TYPE_CGROUP_SOCK_ADDR"] }
    { target: "cgroup_sock_addr:/sys/fs/cgroup_unix:connect4" feature_keys: ["program:BPF_PROG_TYPE_CGROUP_SOCK_ADDR"] }
    { target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix" feature_keys: ["program:BPF_PROG_TYPE_CGROUP_SOCK_ADDR" "attach:BPF_CGROUP_UNIX_SOCK_ADDR"] }
    { target: "cgroup_sockopt:/sys/fs/cgroup:get" feature_keys: ["program:BPF_PROG_TYPE_CGROUP_SOCKOPT"] }
    { target: "cgroup_sock:/sys/fs/cgroup:sock_create" feature_keys: ["program:BPF_PROG_TYPE_CGROUP_SOCK"] }
    { target: "cgroup_device:/sys/fs/cgroup" feature_keys: ["program:BPF_PROG_TYPE_CGROUP_DEVICE"] }
    { target: "cgroup_sysctl:/sys/fs/cgroup" feature_keys: ["program:BPF_PROG_TYPE_CGROUP_SYSCTL"] }
    { target: "sock_ops:/sys/fs/cgroup" feature_keys: ["program:BPF_PROG_TYPE_SOCK_OPS"] }
    { target: "lirc_mode2:/dev/lirc0" feature_keys: ["program:BPF_PROG_TYPE_LIRC_MODE2"] }
    { target: "iter:task_vma" feature_keys: ["program:BPF_PROG_TYPE_TRACING-iter" "iter-target:task_vma"] }
    { target: "syscall:demo" feature_keys: ["program:BPF_PROG_TYPE_SYSCALL"] }
    { target: "freplace:replace_me" feature_keys: ["program:BPF_PROG_TYPE_EXT"] }
]

const PROGRAM_LANGUAGE_KERNEL_FEATURE_EXPECTATIONS = [
    {
        program: [
            '{|ctx|'
            '  def make [] { 7 }'
            '  make'
            '}'
        ]
        feature_keys: ["compiled:bpf-subprogram-calls"]
    }
    {
        program: [
            '{|ctx|'
            '  helper-call "bpf_loop" 4 {|i cb| 0 } "ctx" 0'
            '  0'
            '}'
        ]
        feature_keys: ["compiled:bpf-subprogram-calls"]
    }
    {
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_wq_set_callback_impl" $entry.work {|map key| 0} 0 0'
            '  0'
            '}'
        ]
        feature_keys: ["compiled:bpf-subprogram-calls"]
    }
    {
        program: [
            '{|ctx|'
            '  mut sum = 0'
            '  for i in 0..3 {'
            '    $sum = ($sum + $i)'
            '  }'
            '  $sum'
            '}'
        ]
        feature_keys: ["compiled:bounded-loops"]
    }
    {
        program: [
            '{|ctx|'
            '  # def ignored [] { for ignored in 0..1 { } }'
            '  let text = "def not_a_function [] { for item in [] { } }"'
            '  1'
            '}'
        ]
        feature_keys: []
    }
    {
        program: [
            '{|ctx|'
            '  if true { for i in 0..3 { $i | count } }'
            '  0'
            '}'
        ]
        feature_keys: ["compiled:bounded-loops"]
    }
    {
        program: [
            '{|ctx|'
            '  def make [] { mut sum = 0; for i in 0..3 { $sum = ($sum + $i) }; $sum }'
            '  make'
            '}'
        ]
        feature_keys: ["compiled:bpf-subprogram-calls" "compiled:bounded-loops"]
    }
]

const PROGRAM_MAP_KERNEL_FEATURE_EXPECTATIONS = [
    {
        program: [
            '{|ctx|'
            '  let text = "helper-call \"bpf_ringbuf_query\" custom_ringbuf 0"'
            '  # helper-call "bpf_redirect_map" redirects 0 0 --kind devmap-hash'
            '  let docs = "redirect-map tx_ports 0 --kind devmap"'
            '  let more_docs = "map-define xsks --kind xskmap"'
            '  let ignored = 0 # | helper-call "bpf_map_lookup_percpu_elem" values key 0 --kind lru-per-cpu-hash'
            '  let more_ignored = 0 # | map-get values --kind queue'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        program: [
            '{|ctx|'
            '  let entry = ($ctx.pid | map-get default_counts)'
            '  if $entry { $entry | count }'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_HASH"]
    }
    {
        program: [
            '{|ctx|'
            '  map-define array_counts --kind array --key-type u32 --value-type u64'
            '  let entry = ($ctx.pid | map-get array_counts)'
            '  1 | map-put array_counts $ctx.pid'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_ARRAY"]
    }
    {
        program: [
            '{|ctx|'
            '  let entry = ($ctx.pid | map-get lru_counts --kind lru-hash)'
            '  if $entry { 1 | map-put lru_counts $ctx.pid }'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_LRU_HASH"]
    }
    {
        program: [
            '{|ctx|'
            '  let inner = ($ctx.pid | map-get outer_maps --kind array-of-maps)'
            '  if $inner { $ctx.pid | map-get $inner }'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_ARRAY_OF_MAPS"]
    }
    {
        program: [
            '{|ctx|'
            '  redirect-map tx_ports 0 --kind devmap'
            '  redirect-map tx_hash 0 --kind devmap-hash'
            '  redirect-map cpu_targets 0 --kind cpumap'
            '  redirect-map xsks 0 --kind xskmap'
            '  0'
            '}'
        ]
        feature_keys: [
            "map:BPF_MAP_TYPE_DEVMAP"
            "map:BPF_MAP_TYPE_DEVMAP_HASH"
            "map:BPF_MAP_TYPE_CPUMAP"
            "map:BPF_MAP_TYPE_XSKMAP"
        ]
    }
    {
        program: [
            '{|ctx|'
            '  redirect-socket peers 0 --kind sockmap'
            '  redirect-socket hash_peers 0 --kind sockhash'
            '  redirect-socket sockets 0 --kind reuseport-sockarray'
            '  0'
            '}'
        ]
        feature_keys: [
            "map:BPF_MAP_TYPE_SOCKMAP"
            "map:BPF_MAP_TYPE_SOCKHASH"
            "map:BPF_MAP_TYPE_REUSEPORT_SOCKARRAY"
        ]
    }
    {
        program: [
            '{|ctx|'
            '  helper-call "bpf_redirect_map" redirects 0 0 --kind devmap-hash'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_DEVMAP_HASH"]
    }
    {
        program: [
            '{|ctx|'
            '  helper-call "bpf_map_lookup_percpu_elem" per_cpu_values key0 0 --kind lru-per-cpu-hash'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_LRU_PERCPU_HASH"]
    }
    {
        program: [
            '{|ctx|'
            '  helper-call "bpf_for_each_map_elem" elems {|m k v cb| 0 } "ctx" 0 --kind per-cpu-array'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_PERCPU_ARRAY"]
    }
    {
        program: [
            '{|ctx|'
            '  helper-call "bpf_timer_init" timer timers 0 --kind array'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_ARRAY"]
    }
    {
        program: [
            '{|ctx|'
            '  helper-call "bpf_map_push_elem" queue_or_bloom 1 0 --kind bloom-filter'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_BLOOM_FILTER"]
    }
    {
        program: [
            '{|ctx|'
            '  helper-call "bpf_ringbuf_query" custom_ringbuf 0'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_RINGBUF"]
    }
    {
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_stackid" $ctx custom_stacks 0'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_STACK_TRACE"]
    }
    {
        program: [
            '{|ctx|'
            '  helper-call "bpf_sk_redirect_hash" $ctx socket_hash 0 0'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_SOCKHASH"]
    }
    {
        program: [
            '{|ctx|'
            '  helper-call "bpf_sk_storage_get" socket_storage $ctx.sk 0 0'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_SK_STORAGE"]
    }
    {
        program: [
            '{|ctx|'
            '  helper-call "bpf_perf_event_output" $ctx custom_perf_out 0 "abcd" 4'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_PERF_EVENT_ARRAY"]
    }
    {
        program: [
            '{|ctx|'
            '  $ctx.task | map-get task_state --kind task-storage --init { hits: 0 }'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_TASK_STORAGE"]
    }
    {
        program: [
            '{|ctx|'
            '  $ctx.arg.file.f_inode | map-delete inode_state --kind inode-storage'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_INODE_STORAGE"]
    }
    {
        program: [
            '{|ctx|'
            '  $ctx.current_cgroup | map-contains cgrp_state --kind cgrp-storage'
            '  0'
            '}'
        ]
        feature_keys: ["map:BPF_MAP_TYPE_CGRP_STORAGE"]
    }
    {
        program: [
            '{|ctx|'
            '  map-define inner_seen --kind hash --key-type u32 --value-type u64'
            '  map-define outer_array --kind array-of-maps --inner-map inner_seen --max-entries 4'
            '  map-define outer_hash --kind hash-of-maps --key-type u32 --inner-map inner_seen --max-entries 4'
            '  0'
            '}'
        ]
        feature_keys: [
            "map:BPF_MAP_TYPE_HASH"
            "map:BPF_MAP_TYPE_ARRAY_OF_MAPS"
            "map:BPF_MAP_TYPE_HASH_OF_MAPS"
        ]
    }
]

const PROGRAM_RESERVED_MAP_KERNEL_FEATURE_EXPECTATIONS = [
    {
        program: [
            '{|ctx|'
            '  let docs = "emit events user_events perf_events kstacks ustacks .kstack .ustack"'
            '  # emit events user_events perf_events kstacks ustacks .kstack .ustack'
            '  let ignored = 0 # | emit | count | histogram | start-timer | stop-timer'
            '  let more_ignored = 0 # events user_events perf_events kstacks ustacks .kstack .ustack'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        program: [
            '{|ctx|'
            '  1 | emit'
            '  2 | count'
            '  helper-call "bpf_user_ringbuf_drain" user_events {|dyn cb| 0 } "ctx" 0'
            '  helper-call "bpf_perf_event_read" perf_events 0'
            '  helper-call "bpf_get_stackid" $ctx kstacks 0'
            '  0'
            '}'
        ]
        feature_keys: [
            "map:BPF_MAP_TYPE_RINGBUF"
            "map:BPF_MAP_TYPE_HASH"
            "map:BPF_MAP_TYPE_USER_RINGBUF"
            "map:BPF_MAP_TYPE_PERF_EVENT_ARRAY"
            "map:BPF_MAP_TYPE_STACK_TRACE"
        ]
    }
]

const PROGRAM_MAP_VALUE_KERNEL_FEATURE_EXPECTATIONS = [
    {
        program: [
            '{|ctx|'
            '  let text = "map-define resources --kind hash --value-type record{lock:bpf_spin_lock}"'
            '  # map-define resources --kind hash --value-type "record{timer:bpf_timer}"'
            '  map-define docs --kind hash # --value-type "record{lock:bpf_spin_lock}"'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        program: [
            '{|ctx|'
            '  map-define resources --kind hash --value-type "record{lock:bpf_spin_lock,timer:bpf_timer,task:kptr:task_struct,work:bpf_wq,refs:bpf_refcount}"'
            '  0'
            '}'
        ]
        feature_keys: [
            "map-value:bpf_spin_lock"
            "map-value:bpf_timer"
            "map-value:kptr"
            "map-value:bpf_wq"
            "map-value:bpf_refcount"
        ]
    }
    {
        program: [
            '{|ctx|'
            '  map-define list_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_list_head:node_data:node}"'
            '  0'
            '}'
        ]
        feature_keys: [
            "map-value:bpf_spin_lock"
            "map-value:bpf_list_head"
            "map-value:bpf_list_node"
        ]
    }
    {
        program: [
            '{|ctx|'
            '  map-define list_items --kind hash --value-type "record{root:bpf_list_head:node_data:node:record{refs:bpf_refcount,cookie:u64}}"'
            '  0'
            '}'
        ]
        feature_keys: [
            "map-value:bpf_list_head"
            "map-value:bpf_list_node"
            "map-value:bpf_refcount"
        ]
    }
    {
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{lock:bpf_spin_lock,root:bpf_rb_root:node_data:node}"'
            '  0'
            '}'
        ]
        feature_keys: [
            "map-value:bpf_spin_lock"
            "map-value:bpf_rb_root"
            "map-value:bpf_rb_node"
        ]
    }
    {
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{root:bpf_rb_root:rb_item:rb:record{refs:bpf_refcount,cookie:u64}}"'
            '  0'
            '}'
        ]
        feature_keys: [
            "map-value:bpf_rb_root"
            "map-value:bpf_rb_node"
            "map-value:bpf_refcount"
        ]
    }
]

const PROGRAM_GLOBAL_KERNEL_FEATURE_EXPECTATIONS = [
    {
        program: [
            '{|ctx|'
            '  let config = { pid: 7 samples: [11 22] }'
            '  (($config.samples | get 1) + $config.pid) | count'
            '  0'
            '}'
        ]
        feature_keys: ["global:bpf-data-sections"]
    }
    {
        program: [
            '{|ctx|'
            '  let payload = 0x[01 02]'
            '  ($payload | get 0) | count'
            '  0'
            '}'
        ]
        feature_keys: ["global:bpf-data-sections"]
    }
    {
        program: [
            '{|ctx|'
            '  let config = ({ pid: 7 samples: [11 22] })'
            '  (($config.samples | get 1) + $config.pid) | count'
            '  0'
            '}'
        ]
        feature_keys: ["global:bpf-data-sections"]
    }
    {
        program: [
            '{|ctx|'
            '  let samples = []'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        program: [
            '{|ctx|'
            '  let payload = 0x[]'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        program: [
            '{|ctx|'
            '  7 | global-define --type i64 seen'
            '  global-get seen'
            '}'
        ]
        feature_keys: ["global:bpf-data-sections"]
    }
    {
        program: [
            '{|ctx|'
            '  mut state: record<pid: int stats: record<hits: int ok: bool>> = {}'
            '  ($state.pid + $state.stats.hits) | count'
            '  0'
            '}'
        ]
        feature_keys: ["global:bpf-data-sections"]
    }
    {
        program: [
            '{|ctx| mut state: int = 0; $state | count }'
        ]
        feature_keys: ["global:bpf-data-sections"]
    }
    {
        program: [
            '{|ctx| let config = { pid: 7 samples: [11 22] }; (($config.samples | get 1) + $config.pid) | count }'
        ]
        feature_keys: ["global:bpf-data-sections"]
    }
    {
        program: [
            '{|ctx| let seed = 7; let config = { pid: $seed samples: [11 22] }; (($config.samples | get 1) + $config.pid) | count }'
        ]
        feature_keys: ["global:bpf-data-sections"]
    }
    {
        program: [
            '{|ctx|'
            '  let text = "global-get seen"'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        program: [
            '{|ctx|'
            '  let rec = { root: $ctx nf: $ctx.nf_state }'
            '  $rec.nf.hook | count'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        program: [
            '{|ctx|'
            '  let state = $ctx.nf_state'
            '  let rec = { state: $state }'
            '  $rec.state.hook | count'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        program: [
            '{|ctx|'
            '  let base = { state: $ctx.nf_state }'
            '  let rec = { ok: true, ...$base }'
            '  $rec.state.hook | count'
            '  0'
            '}'
        ]
        feature_keys: []
    }
]

source ($VERIFIER_DIFF_METADATA_DIR | path join core_map_features.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_map_helper_features.nu)
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
const KERNEL_FEATURE_BPF_PROBE_READ = {
    key: "helper:bpf_probe_read"
    min_kernel: "4.1"
    source: "https://github.com/torvalds/linux/blob/v4.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_PROBE_READ_STR = {
    key: "helper:bpf_probe_read_str"
    min_kernel: "4.11"
    source: "https://github.com/torvalds/linux/blob/v4.11/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_PROBE_READ_USER = {
    key: "helper:bpf_probe_read_user"
    min_kernel: "5.5"
    source: "https://github.com/torvalds/linux/blob/v5.5/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_PROBE_READ_KERNEL = {
    key: "helper:bpf_probe_read_kernel"
    min_kernel: "5.5"
    source: "https://github.com/torvalds/linux/blob/v5.5/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_PROBE_READ_USER_STR = {
    key: "helper:bpf_probe_read_user_str"
    min_kernel: "5.5"
    source: "https://github.com/torvalds/linux/blob/v5.5/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_PROBE_READ_KERNEL_STR = {
    key: "helper:bpf_probe_read_kernel_str"
    min_kernel: "5.5"
    source: "https://github.com/torvalds/linux/blob/v5.5/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_GET_PRANDOM_U32 = {
    key: "helper:bpf_get_prandom_u32"
    min_kernel: "4.1"
    source: "https://github.com/torvalds/linux/blob/v4.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_RINGBUF_QUERY = {
    key: "helper:bpf_ringbuf_query"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_RINGBUF_OUTPUT = {
    key: "helper:bpf_ringbuf_output"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_RINGBUF_RESERVE = {
    key: "helper:bpf_ringbuf_reserve"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_RINGBUF_SUBMIT = {
    key: "helper:bpf_ringbuf_submit"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_RINGBUF_DISCARD = {
    key: "helper:bpf_ringbuf_discard"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_GET_STACKID = {
    key: "helper:bpf_get_stackid"
    min_kernel: "4.6"
    source: "https://github.com/torvalds/linux/blob/v4.6/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_GET_STACK = {
    key: "helper:bpf_get_stack"
    min_kernel: "4.18"
    source: "https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SKB_UNDER_CGROUP = {
    key: "helper:bpf_skb_under_cgroup"
    min_kernel: "4.8"
    source: "https://github.com/torvalds/linux/blob/v4.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_CURRENT_TASK_UNDER_CGROUP = {
    key: "helper:bpf_current_task_under_cgroup"
    min_kernel: "4.9"
    source: "https://github.com/torvalds/linux/blob/v4.9/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SKB_LOAD_BYTES = {
    key: "helper:bpf_skb_load_bytes"
    min_kernel: "4.5"
    source: "https://github.com/torvalds/linux/blob/v4.5/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_FIB_LOOKUP = {
    key: "helper:bpf_fib_lookup"
    min_kernel: "4.18"
    source: "https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_CSUM_DIFF = {
    key: "helper:bpf_csum_diff"
    min_kernel: "4.6"
    source: "https://github.com/torvalds/linux/blob/v4.6/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_GET_HASH_RECALC = {
    key: "helper:bpf_get_hash_recalc"
    min_kernel: "4.8"
    source: "https://github.com/torvalds/linux/blob/v4.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_CSUM_LEVEL = {
    key: "helper:bpf_csum_level"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_REDIRECT_NEIGH = {
    key: "helper:bpf_redirect_neigh"
    min_kernel: "5.10"
    source: "https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_REDIRECT_PEER = {
    key: "helper:bpf_redirect_peer"
    min_kernel: "5.10"
    source: "https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_LOAD_HDR_OPT = {
    key: "helper:bpf_load_hdr_opt"
    min_kernel: "5.10"
    source: "https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_STORE_HDR_OPT = {
    key: "helper:bpf_store_hdr_opt"
    min_kernel: "5.10"
    source: "https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_RESERVE_HDR_OPT = {
    key: "helper:bpf_reserve_hdr_opt"
    min_kernel: "5.10"
    source: "https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SOCK_OPS_CB_FLAGS_SET = {
    key: "helper:bpf_sock_ops_cb_flags_set"
    min_kernel: "4.16"
    source: "https://github.com/torvalds/linux/blob/v4.16/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_XDP_ADJUST_HEAD = {
    key: "helper:bpf_xdp_adjust_head"
    min_kernel: "4.10"
    source: "https://github.com/torvalds/linux/blob/v4.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_XDP_ADJUST_META = {
    key: "helper:bpf_xdp_adjust_meta"
    min_kernel: "4.15"
    source: "https://github.com/torvalds/linux/blob/v4.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_XDP_ADJUST_TAIL = {
    key: "helper:bpf_xdp_adjust_tail"
    min_kernel: "4.18"
    source: "https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_XDP_GET_BUFF_LEN = {
    key: "helper:bpf_xdp_get_buff_len"
    min_kernel: "5.18"
    source: "https://github.com/torvalds/linux/blob/v5.18/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_REDIRECT = {
    key: "helper:bpf_redirect"
    min_kernel: "4.4"
    source: "https://github.com/torvalds/linux/blob/v4.4/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_REDIRECT_MAP = {
    key: "helper:bpf_redirect_map"
    min_kernel: "4.14"
    source: "https://github.com/torvalds/linux/blob/v4.14/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_CHECK_MTU = {
    key: "helper:bpf_check_mtu"
    min_kernel: "5.12"
    source: "https://github.com/torvalds/linux/blob/v5.12/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_TAIL_CALL = {
    key: "helper:bpf_tail_call"
    min_kernel: "4.2"
    source: "https://github.com/torvalds/linux/blob/v4.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_PERF_EVENT_READ = {
    key: "helper:bpf_perf_event_read"
    min_kernel: "4.3"
    source: "https://github.com/torvalds/linux/blob/v4.3/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_PERF_EVENT_READ_VALUE = {
    key: "helper:bpf_perf_event_read_value"
    min_kernel: "4.15"
    source: "https://github.com/torvalds/linux/blob/v4.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_PERF_PROG_READ_VALUE = {
    key: "helper:bpf_perf_prog_read_value"
    min_kernel: "4.15"
    source: "https://github.com/torvalds/linux/blob/v4.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_OVERRIDE_RETURN = {
    key: "helper:bpf_override_return"
    min_kernel: "4.16"
    source: "https://github.com/torvalds/linux/blob/v4.16/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SYS_BPF = {
    key: "helper:bpf_sys_bpf"
    min_kernel: "5.14"
    source: "https://github.com/torvalds/linux/blob/v5.14/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SYS_CLOSE = {
    key: "helper:bpf_sys_close"
    min_kernel: "5.14"
    source: "https://github.com/torvalds/linux/blob/v5.14/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_BTF_FIND_BY_NAME_KIND = {
    key: "helper:bpf_btf_find_by_name_kind"
    min_kernel: "5.14"
    source: "https://github.com/torvalds/linux/blob/v5.14/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_GET_FUNC_IP = {
    key: "helper:bpf_get_func_ip"
    min_kernel: "5.15"
    source: "https://github.com/torvalds/linux/blob/v5.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_GET_ATTACH_COOKIE = {
    key: "helper:bpf_get_attach_cookie"
    min_kernel: "5.15"
    source: "https://github.com/torvalds/linux/blob/v5.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_KALLSYMS_LOOKUP_NAME = {
    key: "helper:bpf_kallsyms_lookup_name"
    min_kernel: "5.16"
    source: "https://github.com/torvalds/linux/blob/v5.16/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_BPRM_OPTS_SET = {
    key: "helper:bpf_bprm_opts_set"
    min_kernel: "5.11"
    source: "https://github.com/torvalds/linux/blob/v5.11/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_GET_CURRENT_TASK_BTF = {
    key: "helper:bpf_get_current_task_btf"
    min_kernel: "5.11"
    source: "https://github.com/torvalds/linux/blob/v5.11/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_TASK_PT_REGS = {
    key: "helper:bpf_task_pt_regs"
    min_kernel: "5.15"
    source: "https://github.com/torvalds/linux/blob/v5.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SPIN_LOCK = {
    key: "helper:bpf_spin_lock"
    min_kernel: "5.1"
    source: "https://github.com/torvalds/linux/blob/v5.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SPIN_UNLOCK = {
    key: "helper:bpf_spin_unlock"
    min_kernel: "5.1"
    source: "https://github.com/torvalds/linux/blob/v5.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SK_ASSIGN = {
    key: "helper:bpf_sk_assign"
    min_kernel: "5.7"
    source: "https://github.com/torvalds/linux/blob/v5.7/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SK_LOOKUP_TCP = {
    key: "helper:bpf_sk_lookup_tcp"
    min_kernel: "4.20"
    source: "https://github.com/torvalds/linux/blob/v4.20/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SK_LOOKUP_UDP = {
    key: "helper:bpf_sk_lookup_udp"
    min_kernel: "4.20"
    source: "https://github.com/torvalds/linux/blob/v4.20/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SK_RELEASE = {
    key: "helper:bpf_sk_release"
    min_kernel: "4.20"
    source: "https://github.com/torvalds/linux/blob/v4.20/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SKC_LOOKUP_TCP = {
    key: "helper:bpf_skc_lookup_tcp"
    min_kernel: "5.2"
    source: "https://github.com/torvalds/linux/blob/v5.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SYSCTL_SET_NEW_VALUE = {
    key: "helper:bpf_sysctl_set_new_value"
    min_kernel: "5.2"
    source: "https://github.com/torvalds/linux/blob/v5.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SYSCTL_GET_NAME = {
    key: "helper:bpf_sysctl_get_name"
    min_kernel: "5.2"
    source: "https://github.com/torvalds/linux/blob/v5.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SYSCTL_GET_CURRENT_VALUE = {
    key: "helper:bpf_sysctl_get_current_value"
    min_kernel: "5.2"
    source: "https://github.com/torvalds/linux/blob/v5.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SYSCTL_GET_NEW_VALUE = {
    key: "helper:bpf_sysctl_get_new_value"
    min_kernel: "5.2"
    source: "https://github.com/torvalds/linux/blob/v5.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_GET_FUNC_ARG_CNT = {
    key: "helper:bpf_get_func_arg_cnt"
    min_kernel: "5.17"
    source: "https://github.com/torvalds/linux/blob/v5.17/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_MSG_APPLY_BYTES = {
    key: "helper:bpf_msg_apply_bytes"
    min_kernel: "4.17"
    source: "https://github.com/torvalds/linux/blob/v4.17/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_MSG_CORK_BYTES = {
    key: "helper:bpf_msg_cork_bytes"
    min_kernel: "4.17"
    source: "https://github.com/torvalds/linux/blob/v4.17/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_MSG_PULL_DATA = {
    key: "helper:bpf_msg_pull_data"
    min_kernel: "4.17"
    source: "https://github.com/torvalds/linux/blob/v4.17/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_MSG_PUSH_DATA = {
    key: "helper:bpf_msg_push_data"
    min_kernel: "4.20"
    source: "https://github.com/torvalds/linux/blob/v4.20/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_MSG_POP_DATA = {
    key: "helper:bpf_msg_pop_data"
    min_kernel: "5.0"
    source: "https://github.com/torvalds/linux/blob/v5.0/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_MSG_REDIRECT_MAP = {
    key: "helper:bpf_msg_redirect_map"
    min_kernel: "4.17"
    source: "https://github.com/torvalds/linux/blob/v4.17/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_MSG_REDIRECT_HASH = {
    key: "helper:bpf_msg_redirect_hash"
    min_kernel: "4.18"
    source: "https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SKB_PULL_DATA = {
    key: "helper:bpf_skb_pull_data"
    min_kernel: "4.9"
    source: "https://github.com/torvalds/linux/blob/v4.9/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SKB_ADJUST_ROOM = {
    key: "helper:bpf_skb_adjust_room"
    min_kernel: "4.13"
    source: "https://github.com/torvalds/linux/blob/v4.13/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SKB_CHANGE_HEAD = {
    key: "helper:bpf_skb_change_head"
    min_kernel: "4.10"
    source: "https://github.com/torvalds/linux/blob/v4.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SKB_CHANGE_TAIL = {
    key: "helper:bpf_skb_change_tail"
    min_kernel: "4.9"
    source: "https://github.com/torvalds/linux/blob/v4.9/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SK_REDIRECT_MAP = {
    key: "helper:bpf_sk_redirect_map"
    min_kernel: "4.14"
    source: "https://github.com/torvalds/linux/blob/v4.14/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SK_REDIRECT_HASH = {
    key: "helper:bpf_sk_redirect_hash"
    min_kernel: "4.18"
    source: "https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SK_SELECT_REUSEPORT = {
    key: "helper:bpf_sk_select_reuseport"
    min_kernel: "4.19"
    source: "https://github.com/torvalds/linux/blob/v4.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_TIMER_INIT = {
    key: "helper:bpf_timer_init"
    min_kernel: "5.15"
    source: "https://github.com/torvalds/linux/blob/v5.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_TIMER_SET_CALLBACK = {
    key: "helper:bpf_timer_set_callback"
    min_kernel: "5.15"
    source: "https://github.com/torvalds/linux/blob/v5.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_TIMER_START = {
    key: "helper:bpf_timer_start"
    min_kernel: "5.15"
    source: "https://github.com/torvalds/linux/blob/v5.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_TIMER_CANCEL = {
    key: "helper:bpf_timer_cancel"
    min_kernel: "5.15"
    source: "https://github.com/torvalds/linux/blob/v5.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_LOOP = {
    key: "helper:bpf_loop"
    min_kernel: "5.17"
    source: "https://github.com/torvalds/linux/blob/v5.17/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_FOR_EACH_MAP_ELEM = {
    key: "helper:bpf_for_each_map_elem"
    min_kernel: "5.13"
    source: "https://github.com/torvalds/linux/blob/v5.13/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SEQ_PRINTF = {
    key: "helper:bpf_seq_printf"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SEQ_WRITE = {
    key: "helper:bpf_seq_write"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_RINGBUF_RESERVE_DYNPTR = {
    key: "helper:bpf_ringbuf_reserve_dynptr"
    min_kernel: "5.19"
    source: "https://github.com/torvalds/linux/blob/v5.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_RINGBUF_SUBMIT_DYNPTR = {
    key: "helper:bpf_ringbuf_submit_dynptr"
    min_kernel: "5.19"
    source: "https://github.com/torvalds/linux/blob/v5.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_RINGBUF_DISCARD_DYNPTR = {
    key: "helper:bpf_ringbuf_discard_dynptr"
    min_kernel: "5.19"
    source: "https://github.com/torvalds/linux/blob/v5.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_DYNPTR_DATA = {
    key: "helper:bpf_dynptr_data"
    min_kernel: "5.19"
    source: "https://github.com/torvalds/linux/blob/v5.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_KFUNC_BPF_DYNPTR_SIZE = {
    key: "kfunc:bpf_dynptr_size"
    min_kernel: "6.5"
    source: "https://github.com/torvalds/linux/blob/v6.5/kernel/bpf/helpers.c"
}
const KERNEL_FEATURE_KFUNC_BPF_DYNPTR_SLICE = {
    key: "kfunc:bpf_dynptr_slice"
    min_kernel: "6.4"
    source: "https://github.com/torvalds/linux/blob/v6.4/kernel/bpf/helpers.c"
}
const KERNEL_FEATURE_KFUNC_BPF_DYNPTR_CLONE = {
    key: "kfunc:bpf_dynptr_clone"
    min_kernel: "6.5"
    source: "https://github.com/torvalds/linux/blob/v6.5/kernel/bpf/helpers.c"
}
const KERNEL_FEATURE_MAP_VALUE_BPF_SPIN_LOCK = {
    key: "map-value:bpf_spin_lock"
    min_kernel: "5.1"
    source: "https://github.com/torvalds/linux/blob/v5.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_VALUE_BPF_TIMER = {
    key: "map-value:bpf_timer"
    min_kernel: "5.15"
    source: "https://github.com/torvalds/linux/blob/v5.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_VALUE_KPTR = {
    key: "map-value:kptr"
    min_kernel: "5.19"
    source: "https://github.com/torvalds/linux/blob/v5.19/kernel/bpf/verifier.c"
}
const KERNEL_FEATURE_MAP_VALUE_BPF_WQ = {
    key: "map-value:bpf_wq"
    min_kernel: "6.10"
    source: "https://github.com/torvalds/linux/blob/v6.10/include/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_VALUE_BPF_REFCOUNT = {
    key: "map-value:bpf_refcount"
    min_kernel: "6.4"
    source: "https://github.com/torvalds/linux/blob/v6.4/kernel/bpf/btf.c"
}
const KERNEL_FEATURE_MAP_VALUE_BPF_LIST_HEAD = {
    key: "map-value:bpf_list_head"
    min_kernel: "6.2"
    source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/btf.c"
}
const KERNEL_FEATURE_MAP_VALUE_BPF_LIST_NODE = {
    key: "map-value:bpf_list_node"
    min_kernel: "6.2"
    source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/btf.c"
}
const KERNEL_FEATURE_MAP_VALUE_BPF_RB_ROOT = {
    key: "map-value:bpf_rb_root"
    min_kernel: "6.4"
    source: "https://github.com/torvalds/linux/blob/v6.4/kernel/bpf/btf.c"
}
const KERNEL_FEATURE_MAP_VALUE_BPF_RB_NODE = {
    key: "map-value:bpf_rb_node"
    min_kernel: "6.4"
    source: "https://github.com/torvalds/linux/blob/v6.4/kernel/bpf/btf.c"
}
const KERNEL_FEATURE_BPF_KPTR_XCHG = {
    key: "helper:bpf_kptr_xchg"
    min_kernel: "5.19"
    source: "https://github.com/torvalds/linux/blob/v5.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_KFUNC_BPF_TASK_ACQUIRE = {
    key: "kfunc:bpf_task_acquire"
    min_kernel: "6.2"
    source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/helpers.c"
}
const KERNEL_FEATURE_KFUNC_BPF_TASK_FROM_PID = {
    key: "kfunc:bpf_task_from_pid"
    min_kernel: "6.2"
    source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/helpers.c"
}
const KERNEL_FEATURE_KFUNC_BPF_TASK_RELEASE = {
    key: "kfunc:bpf_task_release"
    min_kernel: "6.2"
    source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/helpers.c"
}
const KERNEL_FEATURE_KFUNC_BPF_CGROUP_ACQUIRE = {
    key: "kfunc:bpf_cgroup_acquire"
    min_kernel: "6.2"
    source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/helpers.c"
}
const KERNEL_FEATURE_KFUNC_BPF_CGROUP_ANCESTOR = {
    key: "kfunc:bpf_cgroup_ancestor"
    min_kernel: "6.2"
    source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/helpers.c"
}
const KERNEL_FEATURE_KFUNC_BPF_CGROUP_FROM_ID = {
    key: "kfunc:bpf_cgroup_from_id"
    min_kernel: "6.4"
    source: "https://github.com/torvalds/linux/blob/v6.4/kernel/bpf/helpers.c"
}
const KERNEL_FEATURE_KFUNC_BPF_CGROUP_RELEASE = {
    key: "kfunc:bpf_cgroup_release"
    min_kernel: "6.2"
    source: "https://github.com/torvalds/linux/blob/v6.2/kernel/bpf/helpers.c"
}
const KERNEL_FEATURE_KFUNC_BPF_GET_TASK_EXE_FILE = {
    key: "kfunc:bpf_get_task_exe_file"
    min_kernel: "6.12"
    source: "https://github.com/torvalds/linux/blob/v6.12/fs/bpf_fs_kfuncs.c"
}
const KERNEL_FEATURE_KFUNC_BPF_PUT_FILE = {
    key: "kfunc:bpf_put_file"
    min_kernel: "6.12"
    source: "https://github.com/torvalds/linux/blob/v6.12/fs/bpf_fs_kfuncs.c"
}
const KERNEL_FEATURE_KFUNC_BPF_CPUMASK_CREATE = {
    key: "kfunc:bpf_cpumask_create"
    min_kernel: "6.3"
    source: "https://github.com/torvalds/linux/blob/v6.3/kernel/bpf/cpumask.c"
}
const KERNEL_FEATURE_KFUNC_BPF_CPUMASK_ACQUIRE = {
    key: "kfunc:bpf_cpumask_acquire"
    min_kernel: "6.3"
    source: "https://github.com/torvalds/linux/blob/v6.3/kernel/bpf/cpumask.c"
}
const KERNEL_FEATURE_KFUNC_BPF_CPUMASK_RELEASE = {
    key: "kfunc:bpf_cpumask_release"
    min_kernel: "6.3"
    source: "https://github.com/torvalds/linux/blob/v6.3/kernel/bpf/cpumask.c"
}
const KERNEL_FEATURE_KFUNC_BPF_CPUMASK_FIRST = {
    key: "kfunc:bpf_cpumask_first"
    min_kernel: "6.3"
    source: "https://github.com/torvalds/linux/blob/v6.3/kernel/bpf/cpumask.c"
}
const KERNEL_FEATURE_KFUNC_BPF_CPUMASK_SET_CPU = {
    key: "kfunc:bpf_cpumask_set_cpu"
    min_kernel: "6.3"
    source: "https://github.com/torvalds/linux/blob/v6.3/kernel/bpf/cpumask.c"
}
const KERNEL_FEATURE_KFUNC_BPF_RES_SPIN_LOCK = {
    key: "kfunc:bpf_res_spin_lock"
    min_kernel: "6.15"
    source: "https://github.com/torvalds/linux/blob/v6.15/kernel/bpf/verifier.c"
}
const KERNEL_FEATURE_KFUNC_BPF_RES_SPIN_UNLOCK = {
    key: "kfunc:bpf_res_spin_unlock"
    min_kernel: "6.15"
    source: "https://github.com/torvalds/linux/blob/v6.15/kernel/bpf/verifier.c"
}
const KERNEL_FEATURE_KFUNC_BPF_RES_SPIN_LOCK_IRQSAVE = {
    key: "kfunc:bpf_res_spin_lock_irqsave"
    min_kernel: "6.15"
    source: "https://github.com/torvalds/linux/blob/v6.15/kernel/bpf/verifier.c"
}
const KERNEL_FEATURE_KFUNC_BPF_RES_SPIN_UNLOCK_IRQRESTORE = {
    key: "kfunc:bpf_res_spin_unlock_irqrestore"
    min_kernel: "6.15"
    source: "https://github.com/torvalds/linux/blob/v6.15/kernel/bpf/verifier.c"
}
const KERNEL_FEATURE_KFUNC_BPF_SOCK_ADDR_SET_SUN_PATH = {
    key: "kfunc:bpf_sock_addr_set_sun_path"
    min_kernel: "6.7"
    source: "https://github.com/torvalds/linux/blob/v6.7/net/core/filter.c"
}
const KERNEL_FEATURE_KFUNC_BPF_SOCK_OPS_ENABLE_TX_TSTAMP = {
    key: "kfunc:bpf_sock_ops_enable_tx_tstamp"
    min_kernel: "6.18"
    source: "https://github.com/torvalds/linux/blob/v6.18/net/core/filter.c"
}
const KERNEL_FEATURE_KFUNC_SCX_BPF_DSQ_INSERT = {
    key: "kfunc:scx_bpf_dsq_insert"
    min_kernel: "6.13"
    max_kernel_exclusive: "6.23"
    max_kernel_exclusive_source: "https://kernel.googlesource.com/pub/scm/linux/kernel/git/mic/linux/+/a7423e6ea2f8f6f453de79213c26f7a36c86d9a2/kernel/sched/ext.c"
    source: "https://github.com/torvalds/linux/blob/v6.13/kernel/sched/ext.c"
}
const KERNEL_FEATURE_KFUNC_SCX_BPF_DSQ_INSERT_V2 = {
    key: "kfunc:scx_bpf_dsq_insert___v2"
    min_kernel: "6.19"
    source: "https://github.com/torvalds/linux/blob/v6.19/kernel/sched/ext.c"
}
const KERNEL_FEATURE_KFUNC_SCX_BPF_DSQ_INSERT_VTIME = {
    key: "kfunc:scx_bpf_dsq_insert_vtime"
    min_kernel: "6.13"
    max_kernel_exclusive: "6.23"
    max_kernel_exclusive_source: "https://kernel.googlesource.com/pub/scm/linux/kernel/git/mic/linux/+/a7423e6ea2f8f6f453de79213c26f7a36c86d9a2/kernel/sched/ext.c"
    source: "https://github.com/torvalds/linux/blob/v6.13/kernel/sched/ext.c"
}
const KERNEL_FEATURE_KFUNC_SCX_BPF_REENQUEUE_LOCAL = {
    key: "kfunc:scx_bpf_reenqueue_local"
    min_kernel: "6.12"
    max_kernel_exclusive: "6.23"
    max_kernel_exclusive_source: "https://kernel.googlesource.com/pub/scm/linux/kernel/git/mic/linux/+/a7423e6ea2f8f6f453de79213c26f7a36c86d9a2/kernel/sched/ext.c"
    source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c"
}
const KERNEL_FEATURE_KFUNC_SCX_BPF_REENQUEUE_LOCAL_V2 = {
    key: "kfunc:scx_bpf_reenqueue_local___v2"
    min_kernel: "6.19"
    source: "https://github.com/torvalds/linux/blob/v6.19/kernel/sched/ext.c"
}
const KERNEL_FEATURE_KFUNC_SCX_BPF_GET_IDLE_CPUMASK = {
    key: "kfunc:scx_bpf_get_idle_cpumask"
    min_kernel: "6.12"
    source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c"
}
const KERNEL_FEATURE_KFUNC_SCX_BPF_GET_IDLE_SMTMASK = {
    key: "kfunc:scx_bpf_get_idle_smtmask"
    min_kernel: "6.12"
    source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c"
}
const KERNEL_FEATURE_KFUNC_SCX_BPF_PICK_ANY_CPU = {
    key: "kfunc:scx_bpf_pick_any_cpu"
    min_kernel: "6.12"
    source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c"
}
const KERNEL_FEATURE_KFUNC_SCX_BPF_PUT_IDLE_CPUMASK = {
    key: "kfunc:scx_bpf_put_idle_cpumask"
    min_kernel: "6.12"
    source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c"
}
const KERNEL_FEATURE_KFUNC_SCX_BPF_CPU_NODE = {
    key: "kfunc:scx_bpf_cpu_node"
    min_kernel: "6.15"
    source: "https://github.com/torvalds/linux/blob/v6.15/kernel/sched/ext_idle.c"
}
const KERNEL_FEATURE_KFUNC_SCX_BPF_GET_IDLE_CPUMASK_NODE = {
    key: "kfunc:scx_bpf_get_idle_cpumask_node"
    min_kernel: "6.15"
    source: "https://github.com/torvalds/linux/blob/v6.15/kernel/sched/ext_idle.c"
}
const KERNEL_FEATURE_KFUNC_SCX_BPF_GET_IDLE_SMTMASK_NODE = {
    key: "kfunc:scx_bpf_get_idle_smtmask_node"
    min_kernel: "6.15"
    source: "https://github.com/torvalds/linux/blob/v6.15/kernel/sched/ext_idle.c"
}
const KERNEL_FEATURE_KFUNC_SCX_BPF_PICK_ANY_CPU_NODE = {
    key: "kfunc:scx_bpf_pick_any_cpu_node"
    min_kernel: "6.15"
    source: "https://github.com/torvalds/linux/blob/v6.15/kernel/sched/ext_idle.c"
}
const KERNEL_FEATURE_KFUNC_SCX_BPF_PICK_IDLE_CPU_NODE = {
    key: "kfunc:scx_bpf_pick_idle_cpu_node"
    min_kernel: "6.15"
    source: "https://github.com/torvalds/linux/blob/v6.15/kernel/sched/ext_idle.c"
}
const KERNEL_FEATURE_BPF_USER_RINGBUF_DRAIN = {
    key: "helper:bpf_user_ringbuf_drain"
    min_kernel: "6.1"
    source: "https://github.com/torvalds/linux/blob/v6.1/include/uapi/linux/bpf.h"
}
