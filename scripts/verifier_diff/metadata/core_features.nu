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

source ($VERIFIER_DIFF_METADATA_DIR | path join core_program_map_expectations.nu)

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

source ($VERIFIER_DIFF_METADATA_DIR | path join core_program_global_expectations.nu)

source ($VERIFIER_DIFF_METADATA_DIR | path join core_map_features.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_map_helper_features.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_context_helper_features.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_helper_features.nu)
source ($VERIFIER_DIFF_METADATA_DIR | path join core_map_value_kfunc_features.nu)
