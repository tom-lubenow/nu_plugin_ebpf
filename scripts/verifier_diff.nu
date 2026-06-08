#!/usr/bin/env nu

const REPO_ROOT = (path self | path dirname | path dirname)
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

const KERNEL_FEATURE_MAP_HASH = {
    key: "map:BPF_MAP_TYPE_HASH"
    min_kernel: "3.19"
    source: "https://github.com/torvalds/linux/blob/v3.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_ARRAY = {
    key: "map:BPF_MAP_TYPE_ARRAY"
    min_kernel: "3.19"
    source: "https://github.com/torvalds/linux/blob/v3.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_CGROUP_ARRAY = {
    key: "map:BPF_MAP_TYPE_CGROUP_ARRAY"
    min_kernel: "4.8"
    source: "https://github.com/torvalds/linux/blob/v4.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_LRU_HASH = {
    key: "map:BPF_MAP_TYPE_LRU_HASH"
    min_kernel: "4.10"
    source: "https://github.com/torvalds/linux/blob/v4.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_LPM_TRIE = {
    key: "map:BPF_MAP_TYPE_LPM_TRIE"
    min_kernel: "4.11"
    source: "https://github.com/torvalds/linux/blob/v4.11/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_PERCPU_HASH = {
    key: "map:BPF_MAP_TYPE_PERCPU_HASH"
    min_kernel: "4.6"
    source: "https://github.com/torvalds/linux/blob/v4.6/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_PERCPU_ARRAY = {
    key: "map:BPF_MAP_TYPE_PERCPU_ARRAY"
    min_kernel: "4.6"
    source: "https://github.com/torvalds/linux/blob/v4.6/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_LRU_PERCPU_HASH = {
    key: "map:BPF_MAP_TYPE_LRU_PERCPU_HASH"
    min_kernel: "4.10"
    source: "https://github.com/torvalds/linux/blob/v4.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_PERF_EVENT_ARRAY = {
    key: "map:BPF_MAP_TYPE_PERF_EVENT_ARRAY"
    min_kernel: "4.3"
    source: "https://github.com/torvalds/linux/blob/v4.3/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_STACK_TRACE = {
    key: "map:BPF_MAP_TYPE_STACK_TRACE"
    min_kernel: "4.6"
    source: "https://github.com/torvalds/linux/blob/v4.6/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_ARRAY_OF_MAPS = {
    key: "map:BPF_MAP_TYPE_ARRAY_OF_MAPS"
    min_kernel: "4.12"
    source: "https://github.com/torvalds/linux/blob/v4.12/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_HASH_OF_MAPS = {
    key: "map:BPF_MAP_TYPE_HASH_OF_MAPS"
    min_kernel: "4.12"
    source: "https://github.com/torvalds/linux/blob/v4.12/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_QUEUE = {
    key: "map:BPF_MAP_TYPE_QUEUE"
    min_kernel: "4.20"
    source: "https://github.com/torvalds/linux/blob/v4.20/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_STACK = {
    key: "map:BPF_MAP_TYPE_STACK"
    min_kernel: "4.20"
    source: "https://github.com/torvalds/linux/blob/v4.20/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_BLOOM_FILTER = {
    key: "map:BPF_MAP_TYPE_BLOOM_FILTER"
    min_kernel: "5.16"
    source: "https://github.com/torvalds/linux/blob/v5.16/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_RINGBUF = {
    key: "map:BPF_MAP_TYPE_RINGBUF"
    min_kernel: "5.8"
    source: "https://github.com/torvalds/linux/blob/v5.8/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_USER_RINGBUF = {
    key: "map:BPF_MAP_TYPE_USER_RINGBUF"
    min_kernel: "6.1"
    source: "https://github.com/torvalds/linux/blob/v6.1/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_DEVMAP = {
    key: "map:BPF_MAP_TYPE_DEVMAP"
    min_kernel: "4.14"
    source: "https://github.com/torvalds/linux/blob/v4.14/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_DEVMAP_HASH = {
    key: "map:BPF_MAP_TYPE_DEVMAP_HASH"
    min_kernel: "5.4"
    source: "https://github.com/torvalds/linux/blob/v5.4/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_CPUMAP = {
    key: "map:BPF_MAP_TYPE_CPUMAP"
    min_kernel: "4.15"
    source: "https://github.com/torvalds/linux/blob/v4.15/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_XSKMAP = {
    key: "map:BPF_MAP_TYPE_XSKMAP"
    min_kernel: "4.18"
    source: "https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_PROG_ARRAY = {
    key: "map:BPF_MAP_TYPE_PROG_ARRAY"
    min_kernel: "4.2"
    source: "https://github.com/torvalds/linux/blob/v4.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_SOCKMAP = {
    key: "map:BPF_MAP_TYPE_SOCKMAP"
    min_kernel: "4.14"
    source: "https://github.com/torvalds/linux/blob/v4.14/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_SOCKHASH = {
    key: "map:BPF_MAP_TYPE_SOCKHASH"
    min_kernel: "4.18"
    source: "https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_CGROUP_STORAGE = {
    key: "map:BPF_MAP_TYPE_CGROUP_STORAGE"
    min_kernel: "4.19"
    source: "https://github.com/torvalds/linux/blob/v4.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_REUSEPORT_SOCKARRAY = {
    key: "map:BPF_MAP_TYPE_REUSEPORT_SOCKARRAY"
    min_kernel: "4.19"
    source: "https://github.com/torvalds/linux/blob/v4.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_PERCPU_CGROUP_STORAGE = {
    key: "map:BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE"
    min_kernel: "4.20"
    source: "https://github.com/torvalds/linux/blob/v4.20/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_SK_STORAGE = {
    key: "map:BPF_MAP_TYPE_SK_STORAGE"
    min_kernel: "5.2"
    source: "https://github.com/torvalds/linux/blob/v5.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_STRUCT_OPS = {
    key: "map:BPF_MAP_TYPE_STRUCT_OPS"
    min_kernel: "5.6"
    source: "https://github.com/torvalds/linux/blob/v5.6/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_INODE_STORAGE = {
    key: "map:BPF_MAP_TYPE_INODE_STORAGE"
    min_kernel: "5.10"
    source: "https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_TASK_STORAGE = {
    key: "map:BPF_MAP_TYPE_TASK_STORAGE"
    min_kernel: "5.11"
    source: "https://github.com/torvalds/linux/blob/v5.11/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_CGRP_STORAGE = {
    key: "map:BPF_MAP_TYPE_CGRP_STORAGE"
    min_kernel: "6.2"
    source: "https://github.com/torvalds/linux/blob/v6.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_MAP_ARENA = {
    key: "map:BPF_MAP_TYPE_ARENA"
    min_kernel: "6.9"
    source: "https://github.com/torvalds/linux/blob/v6.9/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_GLOBAL_DATA_SECTIONS = {
    key: "global:bpf-data-sections"
    min_kernel: "5.2"
    source: "https://github.com/torvalds/linux/commit/d8eca5bbb2be9bc7546f9e733786fa2f1a594c67"
}
const KERNEL_FEATURE_BPF_MAP_LOOKUP_ELEM = {
    key: "helper:bpf_map_lookup_elem"
    min_kernel: "3.19"
    source: "https://github.com/torvalds/linux/blob/v3.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_MAP_UPDATE_ELEM = {
    key: "helper:bpf_map_update_elem"
    min_kernel: "3.19"
    source: "https://github.com/torvalds/linux/blob/v3.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_MAP_DELETE_ELEM = {
    key: "helper:bpf_map_delete_elem"
    min_kernel: "3.19"
    source: "https://github.com/torvalds/linux/blob/v3.19/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_MAP_PUSH_ELEM = {
    key: "helper:bpf_map_push_elem"
    min_kernel: "4.20"
    source: "https://github.com/torvalds/linux/blob/v4.20/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_MAP_POP_ELEM = {
    key: "helper:bpf_map_pop_elem"
    min_kernel: "4.20"
    source: "https://github.com/torvalds/linux/blob/v4.20/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_MAP_PEEK_ELEM = {
    key: "helper:bpf_map_peek_elem"
    min_kernel: "4.20"
    source: "https://github.com/torvalds/linux/blob/v4.20/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SOCK_MAP_UPDATE = {
    key: "helper:bpf_sock_map_update"
    min_kernel: "4.14"
    source: "https://github.com/torvalds/linux/blob/v4.14/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SOCK_HASH_UPDATE = {
    key: "helper:bpf_sock_hash_update"
    min_kernel: "4.18"
    source: "https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SK_STORAGE_GET = {
    key: "helper:bpf_sk_storage_get"
    min_kernel: "5.2"
    source: "https://github.com/torvalds/linux/blob/v5.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_SK_STORAGE_DELETE = {
    key: "helper:bpf_sk_storage_delete"
    min_kernel: "5.2"
    source: "https://github.com/torvalds/linux/blob/v5.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_INODE_STORAGE_GET = {
    key: "helper:bpf_inode_storage_get"
    min_kernel: "5.10"
    source: "https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_INODE_STORAGE_DELETE = {
    key: "helper:bpf_inode_storage_delete"
    min_kernel: "5.10"
    source: "https://github.com/torvalds/linux/blob/v5.10/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_TASK_STORAGE_GET = {
    key: "helper:bpf_task_storage_get"
    min_kernel: "5.11"
    source: "https://github.com/torvalds/linux/blob/v5.11/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_TASK_STORAGE_DELETE = {
    key: "helper:bpf_task_storage_delete"
    min_kernel: "5.11"
    source: "https://github.com/torvalds/linux/blob/v5.11/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_CGRP_STORAGE_GET = {
    key: "helper:bpf_cgrp_storage_get"
    min_kernel: "6.2"
    source: "https://github.com/torvalds/linux/blob/v6.2/include/uapi/linux/bpf.h"
}
const KERNEL_FEATURE_BPF_CGRP_STORAGE_DELETE = {
    key: "helper:bpf_cgrp_storage_delete"
    min_kernel: "6.2"
    source: "https://github.com/torvalds/linux/blob/v6.2/include/uapi/linux/bpf.h"
}
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
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_READ_FD = {
    key: "tracepoint:syscalls/sys_enter_read:field:fd"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_READ_BUF = {
    key: "tracepoint:syscalls/sys_enter_read:field:buf"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_READ_COUNT = {
    key: "tracepoint:syscalls/sys_enter_read:field:count"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_WRITE_FD = {
    key: "tracepoint:syscalls/sys_enter_write:field:fd"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_WRITE_BUF = {
    key: "tracepoint:syscalls/sys_enter_write:field:buf"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_WRITE_COUNT = {
    key: "tracepoint:syscalls/sys_enter_write:field:count"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_CLOSE_FD = {
    key: "tracepoint:syscalls/sys_enter_close:field:fd"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT_DFD = {
    key: "tracepoint:syscalls/sys_enter_openat:field:dfd"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/include/trace/events/syscalls.h"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT_FILENAME = {
    key: "tracepoint:syscalls/sys_enter_openat:field:filename"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/include/trace/events/syscalls.h"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT_FLAGS = {
    key: "tracepoint:syscalls/sys_enter_openat:field:flags"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/include/trace/events/syscalls.h"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT_MODE = {
    key: "tracepoint:syscalls/sys_enter_openat:field:mode"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/include/trace/events/syscalls.h"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT2_DFD = {
    key: "tracepoint:syscalls/sys_enter_openat2:field:dfd"
    min_kernel: "5.6"
    source: "https://github.com/torvalds/linux/blob/v5.6/fs/open.c"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT2_FILENAME = {
    key: "tracepoint:syscalls/sys_enter_openat2:field:filename"
    min_kernel: "5.6"
    source: "https://github.com/torvalds/linux/blob/v5.6/fs/open.c"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT2_HOW = {
    key: "tracepoint:syscalls/sys_enter_openat2:field:how"
    min_kernel: "5.6"
    source: "https://github.com/torvalds/linux/blob/v5.6/fs/open.c"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT2_USIZE = {
    key: "tracepoint:syscalls/sys_enter_openat2:field:usize"
    min_kernel: "5.6"
    source: "https://github.com/torvalds/linux/blob/v5.6/fs/open.c"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_EXECVE_FILENAME = {
    key: "tracepoint:syscalls/sys_enter_execve:field:filename"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/fs/exec.c"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_EXECVE_ARGV = {
    key: "tracepoint:syscalls/sys_enter_execve:field:argv"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/fs/exec.c"
}
const KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_EXECVE_ENVP = {
    key: "tracepoint:syscalls/sys_enter_execve:field:envp"
    min_kernel: "4.7"
    source: "https://github.com/torvalds/linux/blob/v4.7/fs/exec.c"
}
const FILE_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["open"]
        fields: ["filename" "flags" "mode"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["creat"]
        fields: ["pathname" "mode"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["access"]
        fields: ["filename" "mode"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["faccessat"]
        fields: ["dfd" "filename" "mode"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["faccessat2"]
        fields: ["dfd" "filename" "mode" "flags"]
        min_kernel: "5.8"
        source: "https://github.com/torvalds/linux/blob/v5.8/fs/open.c"
    }
    {
        syscalls: ["truncate" "truncate64"]
        fields: ["path" "length"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["ftruncate" "ftruncate64"]
        fields: ["fd" "length"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["chmod"]
        fields: ["filename" "mode"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["fchmod"]
        fields: ["fd" "mode"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["fchmodat"]
        fields: ["dfd" "filename" "mode"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["fchmodat2"]
        fields: ["dfd" "filename" "mode" "flags"]
        min_kernel: "6.6"
        source: "https://github.com/torvalds/linux/blob/v6.6/fs/open.c"
    }
    {
        syscalls: ["chown" "lchown"]
        fields: ["filename" "user" "group"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["fchown"]
        fields: ["fd" "user" "group"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["fchownat"]
        fields: ["dfd" "filename" "user" "group" "flag"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
]

const FILE_DATA_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["pread64" "pwrite64"]
        fields: ["fd" "buf" "count" "pos"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
    }
    {
        syscalls: ["readv" "writev"]
        fields: ["fd" "vec" "vlen"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
    }
    {
        syscalls: ["preadv" "pwritev"]
        fields: ["fd" "vec" "vlen" "pos_l" "pos_h"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
    }
    {
        syscalls: ["preadv2" "pwritev2"]
        fields: ["fd" "vec" "vlen" "pos_l" "pos_h" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
    }
    {
        syscalls: ["sendfile" "sendfile64"]
        fields: ["out_fd" "in_fd" "offset" "count"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
    }
    {
        syscalls: ["copy_file_range"]
        fields: ["fd_in" "off_in" "fd_out" "off_out" "len" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
    }
    {
        syscalls: ["splice"]
        fields: ["fd_in" "off_in" "fd_out" "off_out" "len" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/splice.c"
    }
    {
        syscalls: ["tee"]
        fields: ["fdin" "fdout" "len" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/splice.c"
    }
    {
        syscalls: ["vmsplice"]
        fields: ["fd" "iov" "nr_segs" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/splice.c"
    }
    {
        syscalls: ["cachestat"]
        fields: ["fd" "cstat_range" "cstat" "flags"]
        min_kernel: "6.5"
        source: "https://github.com/torvalds/linux/blob/v6.5/mm/filemap.c"
    }
]

const SOCKET_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["socket"]
        fields: ["family" "type" "protocol"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["socketpair"]
        fields: ["family" "type" "protocol" "usockvec"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["bind"]
        fields: ["fd" "umyaddr" "addrlen"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["listen"]
        fields: ["fd" "backlog"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["accept"]
        fields: ["fd" "upeer_sockaddr" "upeer_addrlen"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["connect"]
        fields: ["fd" "uservaddr" "addrlen"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["sendto"]
        fields: ["fd" "buff" "len" "flags" "addr" "addr_len"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["recvfrom"]
        fields: ["fd" "ubuf" "size" "flags" "addr" "addr_len"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["accept4"]
        fields: ["fd" "upeer_sockaddr" "upeer_addrlen" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["setsockopt"]
        fields: ["fd" "level" "optname" "optval" "optlen"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["getsockopt"]
        fields: ["fd" "level" "optname" "optval" "optlen"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["getsockname" "getpeername"]
        fields: ["fd" "usockaddr" "usockaddr_len"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["shutdown"]
        fields: ["fd" "how"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["sendmsg"]
        fields: ["fd" "msg" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["recvmsg"]
        fields: ["fd" "msg" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["sendmmsg"]
        fields: ["fd" "mmsg" "vlen" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
    {
        syscalls: ["recvmmsg"]
        fields: ["fd" "mmsg" "vlen" "flags" "timeout"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/net/socket.c"
    }
]
const PATH_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["chdir" "chroot"]
        fields: ["filename"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["fchdir"]
        fields: ["fd"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["getcwd"]
        fields: ["buf" "size"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/dcache.c"
    }
    {
        syscalls: ["readlink"]
        fields: ["path" "buf" "bufsiz"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/stat.c"
    }
    {
        syscalls: ["readlinkat"]
        fields: ["dfd" "pathname" "buf" "bufsiz"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/stat.c"
    }
    {
        syscalls: ["statfs"]
        fields: ["pathname" "buf"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/statfs.c"
    }
    {
        syscalls: ["fstatfs"]
        fields: ["fd" "buf"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/statfs.c"
    }
    {
        syscalls: ["getdents" "getdents64"]
        fields: ["fd" "dirent" "count"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/readdir.c"
    }
    {
        syscalls: ["name_to_handle_at"]
        fields: ["dfd" "name" "handle" "mnt_id" "flag"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/fhandle.c"
    }
    {
        syscalls: ["open_by_handle_at"]
        fields: ["mountdirfd" "handle" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/fhandle.c"
    }
    {
        syscalls: ["stat" "lstat" "newstat" "newlstat" "stat64" "lstat64"]
        fields: ["filename" "statbuf"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/stat.c"
    }
    {
        syscalls: ["fstat" "newfstat" "fstat64"]
        fields: ["fd" "statbuf"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/stat.c"
    }
    {
        syscalls: ["newfstatat" "fstatat64"]
        fields: ["dfd" "filename" "statbuf" "flag"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/stat.c"
    }
    {
        syscalls: ["statx"]
        fields: ["dfd" "filename" "flags" "mask" "buffer"]
        min_kernel: "4.11"
        source: "https://github.com/torvalds/linux/blob/v4.11/fs/stat.c"
    }
    {
        syscalls: ["file_getattr" "file_setattr"]
        fields: ["dfd" "filename" "ufattr" "usize" "at_flags"]
        min_kernel: "6.17"
        source: "https://github.com/torvalds/linux/blob/v6.17/fs/file_attr.c"
    }
    {
        syscalls: ["mknod"]
        fields: ["filename" "mode" "dev"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namei.c"
    }
    {
        syscalls: ["mknodat"]
        fields: ["dfd" "filename" "mode" "dev"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namei.c"
    }
    {
        syscalls: ["mkdir"]
        fields: ["pathname" "mode"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namei.c"
    }
    {
        syscalls: ["mkdirat"]
        fields: ["dfd" "pathname" "mode"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namei.c"
    }
    {
        syscalls: ["rmdir" "unlink"]
        fields: ["pathname"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namei.c"
    }
    {
        syscalls: ["unlinkat"]
        fields: ["dfd" "pathname" "flag"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namei.c"
    }
    {
        syscalls: ["symlink" "link" "rename"]
        fields: ["oldname" "newname"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namei.c"
    }
    {
        syscalls: ["symlinkat"]
        fields: ["oldname" "newdfd" "newname"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namei.c"
    }
    {
        syscalls: ["linkat"]
        fields: ["olddfd" "oldname" "newdfd" "newname" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namei.c"
    }
    {
        syscalls: ["renameat"]
        fields: ["olddfd" "oldname" "newdfd" "newname"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namei.c"
    }
    {
        syscalls: ["renameat2"]
        fields: ["olddfd" "oldname" "newdfd" "newname" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namei.c"
    }
    {
        syscalls: ["setxattr" "lsetxattr"]
        fields: ["pathname" "name" "value" "size" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/xattr.c"
    }
    {
        syscalls: ["fsetxattr"]
        fields: ["fd" "name" "value" "size" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/xattr.c"
    }
    {
        syscalls: ["getxattr" "lgetxattr"]
        fields: ["pathname" "name" "value" "size"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/xattr.c"
    }
    {
        syscalls: ["fgetxattr"]
        fields: ["fd" "name" "value" "size"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/xattr.c"
    }
    {
        syscalls: ["listxattr" "llistxattr"]
        fields: ["pathname" "list" "size"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/xattr.c"
    }
    {
        syscalls: ["flistxattr"]
        fields: ["fd" "list" "size"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/xattr.c"
    }
    {
        syscalls: ["removexattr" "lremovexattr"]
        fields: ["pathname" "name"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/xattr.c"
    }
    {
        syscalls: ["fremovexattr"]
        fields: ["fd" "name"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/xattr.c"
    }
    {
        syscalls: ["setxattrat" "getxattrat"]
        fields: ["dfd" "pathname" "at_flags" "name" "uargs" "usize"]
        min_kernel: "6.13"
        source: "https://github.com/torvalds/linux/blob/v6.13/fs/xattr.c"
    }
    {
        syscalls: ["listxattrat"]
        fields: ["dfd" "pathname" "at_flags" "list" "size"]
        min_kernel: "6.13"
        source: "https://github.com/torvalds/linux/blob/v6.13/fs/xattr.c"
    }
    {
        syscalls: ["removexattrat"]
        fields: ["dfd" "pathname" "at_flags" "name"]
        min_kernel: "6.13"
        source: "https://github.com/torvalds/linux/blob/v6.13/fs/xattr.c"
    }
    {
        syscalls: ["open_tree"]
        fields: ["dfd" "filename" "flags"]
        min_kernel: "5.2"
        source: "https://github.com/torvalds/linux/blob/v5.2/fs/namespace.c"
    }
    {
        syscalls: ["move_mount"]
        fields: ["from_dfd" "from_pathname" "to_dfd" "to_pathname" "flags"]
        min_kernel: "5.2"
        source: "https://github.com/torvalds/linux/blob/v5.2/fs/namespace.c"
    }
    {
        syscalls: ["fsopen"]
        fields: ["_fs_name" "flags"]
        min_kernel: "5.2"
        source: "https://github.com/torvalds/linux/blob/v5.2/fs/fsopen.c"
    }
    {
        syscalls: ["fsconfig"]
        fields: ["fd" "cmd" "_key" "_value" "aux"]
        min_kernel: "5.2"
        source: "https://github.com/torvalds/linux/blob/v5.2/fs/fsopen.c"
    }
    {
        syscalls: ["fsmount"]
        fields: ["fs_fd" "flags" "attr_flags"]
        min_kernel: "5.2"
        source: "https://github.com/torvalds/linux/blob/v5.2/fs/namespace.c"
    }
    {
        syscalls: ["fspick"]
        fields: ["dfd" "path" "flags"]
        min_kernel: "5.2"
        source: "https://github.com/torvalds/linux/blob/v5.2/fs/fsopen.c"
    }
    {
        syscalls: ["mount_setattr"]
        fields: ["dfd" "path" "flags" "uattr" "usize"]
        min_kernel: "5.12"
        source: "https://github.com/torvalds/linux/blob/v5.12/fs/namespace.c"
    }
    {
        syscalls: ["statmount"]
        fields: ["req" "buf" "bufsize" "flags"]
        min_kernel: "6.8"
        source: "https://github.com/torvalds/linux/blob/v6.8/fs/namespace.c"
    }
    {
        syscalls: ["listmount"]
        fields: ["req" "mnt_ids" "nr_mnt_ids" "flags"]
        min_kernel: "6.8"
        source: "https://github.com/torvalds/linux/blob/v6.8/fs/namespace.c"
    }
    {
        syscalls: ["open_tree_attr"]
        fields: ["dfd" "filename" "flags" "uattr" "usize"]
        min_kernel: "6.15"
        source: "https://github.com/torvalds/linux/blob/v6.15/fs/namespace.c"
    }
    {
        syscalls: ["mount"]
        fields: ["dev_name" "dir_name" "type" "flags" "data"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namespace.c"
    }
    {
        syscalls: ["umount"]
        fields: ["name" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namespace.c"
    }
    {
        syscalls: ["pivot_root"]
        fields: ["new_root" "put_old"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/namespace.c"
    }
    {
        syscalls: ["ustat"]
        fields: ["dev" "ubuf"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/statfs.c"
    }
]
const QUOTA_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["quotactl"]
        fields: ["cmd" "special" "id" "addr"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/quota/quota.c"
    }
    {
        syscalls: ["quotactl_fd"]
        fields: ["fd" "cmd" "id" "addr"]
        min_kernel: "5.14"
        source: "https://github.com/torvalds/linux/blob/v5.14/fs/quota/quota.c"
    }
]
const PROCESS_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["execveat"]
        fields: ["fd" "filename" "argv" "envp" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/exec.c"
    }
    {
        syscalls: ["exit" "exit_group"]
        fields: ["error_code"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/exit.c"
    }
    {
        syscalls: ["waitid"]
        fields: ["which" "upid" "infop" "options" "ru"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/exit.c"
    }
    {
        syscalls: ["wait4"]
        fields: ["upid" "stat_addr" "options" "ru"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/exit.c"
    }
    {
        syscalls: ["unshare"]
        fields: ["unshare_flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/fork.c"
    }
    {
        syscalls: ["clone"]
        fields: ["clone_flags" "newsp" "parent_tidptr" "child_tidptr" "tls"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/fork.c"
    }
    {
        syscalls: ["clone3"]
        fields: ["uargs" "size"]
        min_kernel: "5.3"
        source: "https://github.com/torvalds/linux/blob/v5.3/kernel/fork.c"
    }
    {
        syscalls: ["setns"]
        fields: ["fd" "nstype"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/nsproxy.c"
    }
    {
        syscalls: ["init_module"]
        fields: ["umod" "len" "uargs"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/module.c"
    }
    {
        syscalls: ["finit_module"]
        fields: ["fd" "uargs" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/module.c"
    }
    {
        syscalls: ["delete_module"]
        fields: ["name_user" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/module.c"
    }
    {
        syscalls: ["kexec_load"]
        fields: ["entry" "nr_segments" "segments" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/kexec.c"
    }
    {
        syscalls: ["kexec_file_load"]
        fields: ["kernel_fd" "initrd_fd" "cmdline_len" "cmdline_ptr" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/kexec_file.c"
    }
    {
        syscalls: ["reboot"]
        fields: ["magic1" "magic2" "cmd"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/reboot.c"
    }
    {
        syscalls: ["acct"]
        fields: ["name"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/acct.c"
    }
    {
        syscalls: ["set_tid_address"]
        fields: ["tidptr"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/fork.c"
    }
    {
        syscalls: ["kcmp"]
        fields: ["pid1" "pid2" "type" "idx1" "idx2"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/kcmp.c"
    }
]
const FD_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["lseek"]
        fields: ["fd" "offset" "whence"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/read_write.c"
    }
    {
        syscalls: ["fadvise64"]
        fields: ["fd" "offset" "len" "advice"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/fadvise.c"
    }
    {
        syscalls: ["readahead"]
        fields: ["fd" "offset" "count"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/readahead.c"
    }
    {
        syscalls: ["fallocate"]
        fields: ["fd" "mode" "offset" "len"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    }
    {
        syscalls: ["syncfs" "fsync" "fdatasync"]
        fields: ["fd"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/sync.c"
    }
    {
        syscalls: ["sync_file_range"]
        fields: ["fd" "offset" "nbytes" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/sync.c"
    }
    {
        syscalls: ["fcntl"]
        fields: ["fd" "cmd"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/fcntl.c"
    }
    {
        syscalls: ["flock"]
        fields: ["fd" "cmd"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/locks.c"
    }
    {
        syscalls: ["ioctl"]
        fields: ["fd" "cmd"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/ioctl.c"
    }
    {
        syscalls: ["dup"]
        fields: ["fildes"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/file.c"
    }
    {
        syscalls: ["dup2"]
        fields: ["oldfd" "newfd"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/file.c"
    }
    {
        syscalls: ["dup3"]
        fields: ["oldfd" "newfd" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/file.c"
    }
    {
        syscalls: ["pipe"]
        fields: ["fildes"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/pipe.c"
    }
    {
        syscalls: ["pipe2"]
        fields: ["fildes" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/pipe.c"
    }
    {
        syscalls: ["eventfd"]
        fields: ["count"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/eventfd.c"
    }
    {
        syscalls: ["eventfd2"]
        fields: ["count" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/eventfd.c"
    }
    {
        syscalls: ["close_range"]
        fields: ["fd" "max_fd" "flags"]
        min_kernel: "5.9"
        source: "https://github.com/torvalds/linux/blob/v5.9/fs/open.c"
    }
    {
        syscalls: ["epoll_create"]
        fields: ["size"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/eventpoll.c"
    }
    {
        syscalls: ["epoll_create1"]
        fields: ["flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/eventpoll.c"
    }
    {
        syscalls: ["epoll_ctl"]
        fields: ["epfd" "op" "fd" "event"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/eventpoll.c"
    }
    {
        syscalls: ["epoll_wait"]
        fields: ["epfd" "events" "maxevents" "timeout"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/eventpoll.c"
    }
    {
        syscalls: ["epoll_pwait"]
        fields: ["epfd" "events" "maxevents" "timeout" "sigmask" "sigsetsize"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/eventpoll.c"
    }
    {
        syscalls: ["epoll_pwait2"]
        fields: ["epfd" "events" "maxevents" "timeout" "sigmask" "sigsetsize"]
        min_kernel: "5.11"
        source: "https://github.com/torvalds/linux/blob/v5.11/fs/eventpoll.c"
    }
    {
        syscalls: ["inotify_init1"]
        fields: ["flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/notify/inotify/inotify_user.c"
    }
    {
        syscalls: ["inotify_add_watch"]
        fields: ["fd" "pathname" "mask"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/notify/inotify/inotify_user.c"
    }
    {
        syscalls: ["inotify_rm_watch"]
        fields: ["fd" "wd"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/notify/inotify/inotify_user.c"
    }
    {
        syscalls: ["fanotify_init"]
        fields: ["flags" "event_f_flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/notify/fanotify/fanotify_user.c"
    }
    {
        syscalls: ["fanotify_mark"]
        fields: ["fanotify_fd" "flags" "mask" "dfd" "pathname"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/notify/fanotify/fanotify_user.c"
    }
    {
        syscalls: ["poll"]
        fields: ["ufds" "nfds" "timeout_msecs"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/select.c"
    }
    {
        syscalls: ["ppoll"]
        fields: ["ufds" "nfds" "tsp" "sigmask" "sigsetsize"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/select.c"
    }
    {
        syscalls: ["select"]
        fields: ["n" "inp" "outp" "exp" "tvp"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/select.c"
    }
    {
        syscalls: ["pselect6"]
        fields: ["n" "inp" "outp" "exp" "tsp" "sig"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/select.c"
    }
]
const MM_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["brk"]
        fields: ["brk"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mmap.c"
    }
    {
        syscalls: ["mmap"]
        fields: ["addr" "len" "prot" "flags" "fd" "off"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/arch/x86/kernel/sys_x86_64.c"
    }
    {
        syscalls: ["mmap_pgoff"]
        fields: ["addr" "len" "prot" "flags" "fd" "pgoff"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mmap.c"
    }
    {
        syscalls: ["munmap"]
        fields: ["addr" "len"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mmap.c"
    }
    {
        syscalls: ["remap_file_pages"]
        fields: ["start" "size" "prot" "pgoff" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mmap.c"
    }
    {
        syscalls: ["mprotect"]
        fields: ["start" "len" "prot"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mprotect.c"
    }
    {
        syscalls: ["pkey_mprotect"]
        fields: ["start" "len" "prot" "pkey"]
        min_kernel: "4.9"
        source: "https://github.com/torvalds/linux/blob/v4.9/mm/mprotect.c"
    }
    {
        syscalls: ["pkey_alloc"]
        fields: ["flags" "init_val"]
        min_kernel: "4.9"
        source: "https://github.com/torvalds/linux/blob/v4.9/mm/mprotect.c"
    }
    {
        syscalls: ["pkey_free"]
        fields: ["pkey"]
        min_kernel: "4.9"
        source: "https://github.com/torvalds/linux/blob/v4.9/mm/mprotect.c"
    }
    {
        syscalls: ["mremap"]
        fields: ["addr" "old_len" "new_len" "flags" "new_addr"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mremap.c"
    }
    {
        syscalls: ["madvise"]
        fields: ["start" "len_in" "behavior"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/madvise.c"
    }
    {
        syscalls: ["process_vm_readv" "process_vm_writev"]
        fields: ["lvec" "liovcnt" "rvec" "riovcnt" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/process_vm_access.c"
    }
    {
        syscalls: ["process_madvise"]
        fields: ["pidfd" "vec" "vlen" "behavior" "flags"]
        min_kernel: "5.10"
        source: "https://github.com/torvalds/linux/blob/v5.10/mm/madvise.c"
    }
    {
        syscalls: ["process_mrelease"]
        fields: ["pidfd" "flags"]
        min_kernel: "5.15"
        source: "https://github.com/torvalds/linux/blob/v5.15/mm/oom_kill.c"
    }
    {
        syscalls: ["mlock" "munlock"]
        fields: ["start" "len"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mlock.c"
    }
    {
        syscalls: ["mlock2"]
        fields: ["start" "len" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mlock.c"
    }
    {
        syscalls: ["mlockall"]
        fields: ["flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mlock.c"
    }
    {
        syscalls: ["mincore"]
        fields: ["start" "len" "vec"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mincore.c"
    }
    {
        syscalls: ["msync"]
        fields: ["start" "len" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/msync.c"
    }
    {
        syscalls: ["mseal"]
        fields: ["start" "len" "flags"]
        min_kernel: "6.10"
        source: "https://github.com/torvalds/linux/blob/v6.10/mm/mseal.c"
    }
    {
        syscalls: ["munlockall"]
        fields: []
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mlock.c"
    }
    {
        syscalls: ["swapon"]
        fields: ["specialfile" "swap_flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/swapfile.c"
    }
    {
        syscalls: ["swapoff"]
        fields: ["specialfile"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/swapfile.c"
    }
    {
        syscalls: ["memfd_create"]
        fields: ["uname" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/shmem.c"
    }
    {
        syscalls: ["memfd_secret"]
        fields: ["flags"]
        min_kernel: "5.14"
        source: "https://github.com/torvalds/linux/blob/v5.14/mm/secretmem.c"
    }
    {
        syscalls: ["mbind"]
        fields: ["start" "len" "mode" "nmask" "maxnode" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mempolicy.c"
    }
    {
        syscalls: ["set_mempolicy"]
        fields: ["mode" "nmask" "maxnode"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mempolicy.c"
    }
    {
        syscalls: ["get_mempolicy"]
        fields: ["policy" "nmask" "maxnode" "addr" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mempolicy.c"
    }
    {
        syscalls: ["migrate_pages"]
        fields: ["maxnode" "old_nodes" "new_nodes"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/mempolicy.c"
    }
    {
        syscalls: ["move_pages"]
        fields: ["nr_pages" "pages" "nodes" "status" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/mm/migrate.c"
    }
    {
        syscalls: ["set_mempolicy_home_node"]
        fields: ["start" "len" "home_node" "flags"]
        min_kernel: "5.17"
        source: "https://github.com/torvalds/linux/blob/v5.17/mm/mempolicy.c"
    }
]
const TIME_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["utime"]
        fields: ["filename" "times"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/utimes.c"
    }
    {
        syscalls: ["utimes"]
        fields: ["filename" "utimes"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/utimes.c"
    }
    {
        syscalls: ["futimesat"]
        fields: ["dfd" "filename" "utimes"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/utimes.c"
    }
    {
        syscalls: ["utimensat"]
        fields: ["dfd" "filename" "utimes" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/utimes.c"
    }
    {
        syscalls: ["time"]
        fields: ["tloc"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/time.c"
    }
    {
        syscalls: ["gettimeofday" "settimeofday"]
        fields: ["tv" "tz"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/time.c"
    }
    {
        syscalls: ["adjtimex"]
        fields: ["txc_p"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/time.c"
    }
    {
        syscalls: ["alarm"]
        fields: ["seconds"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/timer.c"
    }
    {
        syscalls: ["getitimer"]
        fields: ["which" "value"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/itimer.c"
    }
    {
        syscalls: ["setitimer"]
        fields: ["which" "value" "ovalue"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/itimer.c"
    }
    {
        syscalls: ["nanosleep"]
        fields: ["rqtp" "rmtp"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/hrtimer.c"
    }
    {
        syscalls: ["timer_create"]
        fields: ["which_clock" "timer_event_spec" "created_timer_id"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/posix-timers.c"
    }
    {
        syscalls: ["timer_gettime"]
        fields: ["timer_id" "setting"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/posix-timers.c"
    }
    {
        syscalls: ["timer_getoverrun" "timer_delete"]
        fields: ["timer_id"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/posix-timers.c"
    }
    {
        syscalls: ["timer_settime"]
        fields: ["timer_id" "flags" "new_setting" "old_setting"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/posix-timers.c"
    }
    {
        syscalls: ["clock_settime" "clock_gettime" "clock_getres"]
        fields: ["which_clock" "tp"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/posix-timers.c"
    }
    {
        syscalls: ["clock_adjtime"]
        fields: ["which_clock" "utx"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/posix-timers.c"
    }
    {
        syscalls: ["clock_nanosleep"]
        fields: ["which_clock" "flags" "rqtp" "rmtp"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/time/posix-timers.c"
    }
    {
        syscalls: ["timerfd_create"]
        fields: ["clockid" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/timerfd.c"
    }
    {
        syscalls: ["timerfd_settime"]
        fields: ["ufd" "flags" "utmr" "otmr"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/timerfd.c"
    }
    {
        syscalls: ["timerfd_gettime"]
        fields: ["ufd" "otmr"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/timerfd.c"
    }
]
const IO_URING_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["io_uring_setup"]
        fields: ["entries" "params"]
        min_kernel: "5.1"
        source: "https://github.com/torvalds/linux/blob/v5.1/fs/io_uring.c"
    }
    {
        syscalls: ["io_uring_enter"]
        fields: ["fd" "to_submit" "min_complete" "flags" "sig" "sigsz"]
        min_kernel: "5.1"
        source: "https://github.com/torvalds/linux/blob/v5.1/fs/io_uring.c"
    }
    {
        syscalls: ["io_uring_register"]
        fields: ["fd" "opcode" "nr_args"]
        min_kernel: "5.1"
        source: "https://github.com/torvalds/linux/blob/v5.1/fs/io_uring.c"
    }
]
const AIO_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["io_setup"]
        fields: ["nr_events" "ctxp"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/aio.c"
    }
    {
        syscalls: ["io_destroy"]
        fields: ["ctx"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/aio.c"
    }
    {
        syscalls: ["io_submit"]
        fields: ["ctx_id" "nr" "iocbpp"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/aio.c"
    }
    {
        syscalls: ["io_cancel"]
        fields: ["ctx_id" "iocb" "result"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/aio.c"
    }
    {
        syscalls: ["io_getevents"]
        fields: ["ctx_id" "min_nr" "nr" "events" "timeout"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/aio.c"
    }
    {
        syscalls: ["io_pgetevents"]
        fields: ["ctx_id" "min_nr" "nr" "events" "timeout" "usig"]
        min_kernel: "4.18"
        source: "https://github.com/torvalds/linux/blob/v4.18/fs/aio.c"
    }
]
const IOPRIO_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["ioprio_set"]
        fields: ["which" "who" "ioprio"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/block/ioprio.c"
    }
    {
        syscalls: ["ioprio_get"]
        fields: ["which" "who"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/block/ioprio.c"
    }
]
const KEY_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["add_key"]
        fields: ["_type" "_description" "_payload" "plen" "ringid"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/security/keys/keyctl.c"
    }
    {
        syscalls: ["request_key"]
        fields: ["_type" "_description" "_callout_info" "destringid"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/security/keys/keyctl.c"
    }
    {
        syscalls: ["keyctl"]
        fields: ["option"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/security/keys/keyctl.c"
    }
]
const SIGNAL_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["rt_sigprocmask"]
        fields: ["how" "nset" "oset" "sigsetsize"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/signal.c"
    }
    {
        syscalls: ["rt_sigpending"]
        fields: ["uset" "sigsetsize"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/signal.c"
    }
    {
        syscalls: ["rt_sigtimedwait"]
        fields: ["uthese" "uinfo" "uts" "sigsetsize"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/signal.c"
    }
    {
        syscalls: ["kill" "tkill"]
        fields: ["sig"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/signal.c"
    }
    {
        syscalls: ["tgkill"]
        fields: ["sig"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/signal.c"
    }
    {
        syscalls: ["rt_sigqueueinfo"]
        fields: ["sig" "uinfo"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/signal.c"
    }
    {
        syscalls: ["rt_tgsigqueueinfo"]
        fields: ["sig" "uinfo"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/signal.c"
    }
    {
        syscalls: ["sigaltstack"]
        fields: ["uss" "uoss"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/signal.c"
    }
    {
        syscalls: ["rt_sigaction"]
        fields: ["sig" "act" "oact" "sigsetsize"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/signal.c"
    }
    {
        syscalls: ["rt_sigsuspend"]
        fields: ["unewset" "sigsetsize"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/signal.c"
    }
    {
        syscalls: ["signalfd"]
        fields: ["ufd" "user_mask" "sizemask"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/signalfd.c"
    }
    {
        syscalls: ["signalfd4"]
        fields: ["ufd" "user_mask" "sizemask" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/signalfd.c"
    }
    {
        syscalls: ["pidfd_send_signal"]
        fields: ["pidfd" "sig" "info" "flags"]
        min_kernel: "5.1"
        source: "https://github.com/torvalds/linux/blob/v5.1/kernel/signal.c"
    }
    {
        syscalls: ["pidfd_open"]
        fields: ["flags"]
        min_kernel: "5.3"
        source: "https://github.com/torvalds/linux/blob/v5.3/kernel/pid.c"
    }
    {
        syscalls: ["pidfd_getfd"]
        fields: ["pidfd" "fd" "flags"]
        min_kernel: "5.6"
        source: "https://github.com/torvalds/linux/blob/v5.6/kernel/pid.c"
    }
]
const LANDLOCK_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["landlock_create_ruleset"]
        fields: ["attr" "size" "flags"]
        min_kernel: "5.13"
        source: "https://github.com/torvalds/linux/blob/v5.13/security/landlock/syscalls.c"
    }
    {
        syscalls: ["landlock_add_rule"]
        fields: ["ruleset_fd" "rule_type" "rule_attr" "flags"]
        min_kernel: "5.13"
        source: "https://github.com/torvalds/linux/blob/v5.13/security/landlock/syscalls.c"
    }
    {
        syscalls: ["landlock_restrict_self"]
        fields: ["ruleset_fd" "flags"]
        min_kernel: "5.13"
        source: "https://github.com/torvalds/linux/blob/v5.13/security/landlock/syscalls.c"
    }
]
const LSM_SYSCALL_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["lsm_get_self_attr"]
        fields: ["attr" "ctx" "size" "flags"]
        min_kernel: "6.8"
        source: "https://github.com/torvalds/linux/blob/v6.8/security/lsm_syscalls.c"
    }
    {
        syscalls: ["lsm_set_self_attr"]
        fields: ["attr" "ctx" "size" "flags"]
        min_kernel: "6.8"
        source: "https://github.com/torvalds/linux/blob/v6.8/security/lsm_syscalls.c"
    }
    {
        syscalls: ["lsm_list_modules"]
        fields: ["ids" "size" "flags"]
        min_kernel: "6.8"
        source: "https://github.com/torvalds/linux/blob/v6.8/security/lsm_syscalls.c"
    }
]
const IDENTITY_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["setpriority"]
        fields: ["which" "who" "niceval"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["getpriority"]
        fields: ["which" "who"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["setregid"]
        fields: ["rgid" "egid"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["setreuid"]
        fields: ["ruid" "euid"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["setresuid"]
        fields: ["ruid" "euid" "suid"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["getresuid"]
        fields: ["ruidp" "euidp" "suidp"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["setresgid"]
        fields: ["rgid" "egid" "sgid"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["getresgid"]
        fields: ["rgidp" "egidp" "sgidp"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["setpgid"]
        fields: ["pgid"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["sethostname" "gethostname" "setdomainname"]
        fields: ["name" "len"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["getrlimit" "setrlimit"]
        fields: ["resource" "rlim"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["getrusage"]
        fields: ["who" "ru"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["prlimit64"]
        fields: ["resource" "new_rlim" "old_rlim"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["umask"]
        fields: ["mask"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["prctl"]
        fields: ["option"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["getcpu"]
        fields: ["cpup" "nodep" "unused"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["getrandom"]
        fields: ["buf" "count" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/drivers/char/random.c"
    }
    {
        syscalls: ["times"]
        fields: ["tbuf"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["newuname"]
        fields: ["name"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["sysinfo"]
        fields: ["info"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sys.c"
    }
    {
        syscalls: ["personality"]
        fields: ["personality"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/exec_domain.c"
    }
    {
        syscalls: ["membarrier"]
        fields: ["cmd" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/membarrier.c"
    }
    {
        syscalls: ["syslog"]
        fields: ["type" "buf" "len"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/printk/printk.c"
    }
    {
        syscalls: ["sysfs"]
        fields: ["option"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/filesystems.c"
    }
    {
        syscalls: ["rseq"]
        fields: ["rseq" "rseq_len" "flags" "sig"]
        min_kernel: "4.18"
        source: "https://github.com/torvalds/linux/blob/v4.18/kernel/rseq.c"
    }
    {
        syscalls: ["bpf"]
        fields: ["cmd" "uattr" "size"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/bpf/syscall.c"
    }
    {
        syscalls: ["perf_event_open"]
        fields: ["attr_uptr" "group_fd" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/events/core.c"
    }
    {
        syscalls: ["ptrace"]
        fields: ["request" "addr" "data"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/ptrace.c"
    }
    {
        syscalls: ["seccomp"]
        fields: ["op" "flags" "uargs"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/seccomp.c"
    }
    {
        syscalls: ["userfaultfd"]
        fields: ["flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/fs/userfaultfd.c"
    }
    {
        syscalls: ["getgroups" "setgroups"]
        fields: ["gidsetsize" "grouplist"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/groups.c"
    }
    {
        syscalls: ["capget"]
        fields: ["header" "dataptr"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/capability.c"
    }
    {
        syscalls: ["capset"]
        fields: ["header" "data"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/capability.c"
    }
]
const SCHED_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["nice"]
        fields: ["increment"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sched/core.c"
    }
    {
        syscalls: ["sched_setscheduler"]
        fields: ["policy" "param"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sched/core.c"
    }
    {
        syscalls: ["sched_setparam" "sched_getparam"]
        fields: ["param"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sched/core.c"
    }
    {
        syscalls: ["sched_setattr"]
        fields: ["uattr" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sched/core.c"
    }
    {
        syscalls: ["sched_getattr"]
        fields: ["uattr" "size" "flags"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sched/core.c"
    }
    {
        syscalls: ["sched_setaffinity" "sched_getaffinity"]
        fields: ["len" "user_mask_ptr"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sched/core.c"
    }
    {
        syscalls: ["sched_get_priority_max" "sched_get_priority_min"]
        fields: ["policy"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sched/core.c"
    }
    {
        syscalls: ["sched_rr_get_interval"]
        fields: ["interval"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/sched/core.c"
    }
]
const FUTEX_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["futex"]
        fields: ["uaddr" "op" "val" "utime" "uaddr2" "val3"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/futex.c"
    }
    {
        syscalls: ["futex_waitv"]
        fields: ["waiters" "nr_futexes" "flags" "timeout" "clockid"]
        min_kernel: "5.16"
        source: "https://github.com/torvalds/linux/blob/v5.16/kernel/futex/syscalls.c"
    }
    {
        syscalls: ["futex_wake"]
        fields: ["uaddr" "mask" "nr" "flags"]
        min_kernel: "6.7"
        source: "https://github.com/torvalds/linux/blob/v6.7/kernel/futex/syscalls.c"
    }
    {
        syscalls: ["futex_wait"]
        fields: ["uaddr" "val" "mask" "flags" "timeout" "clockid"]
        min_kernel: "6.7"
        source: "https://github.com/torvalds/linux/blob/v6.7/kernel/futex/syscalls.c"
    }
    {
        syscalls: ["futex_requeue"]
        fields: ["waiters" "flags" "nr_wake" "nr_requeue"]
        min_kernel: "6.7"
        source: "https://github.com/torvalds/linux/blob/v6.7/kernel/futex/syscalls.c"
    }
    {
        syscalls: ["set_robust_list"]
        fields: ["head" "len"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/futex.c"
    }
    {
        syscalls: ["get_robust_list"]
        fields: ["head_ptr" "len_ptr"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/kernel/futex.c"
    }
]
const MQUEUE_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["mq_open"]
        fields: ["u_name" "oflag" "mode" "u_attr"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/mqueue.c"
    }
    {
        syscalls: ["mq_unlink"]
        fields: ["u_name"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/mqueue.c"
    }
    {
        syscalls: ["mq_timedsend"]
        fields: ["mqdes" "u_msg_ptr" "msg_len" "msg_prio" "u_abs_timeout"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/mqueue.c"
    }
    {
        syscalls: ["mq_timedreceive"]
        fields: ["mqdes" "u_msg_ptr" "msg_len" "u_msg_prio" "u_abs_timeout"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/mqueue.c"
    }
    {
        syscalls: ["mq_notify"]
        fields: ["mqdes" "u_notification"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/mqueue.c"
    }
    {
        syscalls: ["mq_getsetattr"]
        fields: ["mqdes" "u_mqstat" "u_omqstat"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/mqueue.c"
    }
]
const IPC_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["msgget"]
        fields: ["key" "msgflg"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/msg.c"
    }
    {
        syscalls: ["msgctl"]
        fields: ["msqid" "cmd" "buf"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/msg.c"
    }
    {
        syscalls: ["msgsnd"]
        fields: ["msqid" "msgp" "msgsz" "msgflg"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/msg.c"
    }
    {
        syscalls: ["msgrcv"]
        fields: ["msqid" "msgp" "msgsz" "msgtyp" "msgflg"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/msg.c"
    }
    {
        syscalls: ["semget"]
        fields: ["key" "nsems" "semflg"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/sem.c"
    }
    {
        syscalls: ["semctl"]
        fields: ["semid" "semnum" "cmd"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/sem.c"
    }
    {
        syscalls: ["semtimedop"]
        fields: ["semid" "tsops" "nsops" "timeout"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/sem.c"
    }
    {
        syscalls: ["semop"]
        fields: ["semid" "tsops" "nsops"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/sem.c"
    }
    {
        syscalls: ["shmget"]
        fields: ["key" "size" "shmflg"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/shm.c"
    }
    {
        syscalls: ["shmctl"]
        fields: ["shmid" "cmd" "buf"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/shm.c"
    }
    {
        syscalls: ["shmat"]
        fields: ["shmid" "shmaddr" "shmflg"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/shm.c"
    }
    {
        syscalls: ["shmdt"]
        fields: ["shmaddr"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/ipc/shm.c"
    }
]
const X86_TRACEPOINT_FIELD_SPECS = [
    {
        syscalls: ["arch_prctl"]
        fields: ["option"]
        min_kernel: "5.0"
        source: "https://github.com/torvalds/linux/blob/v5.0/arch/x86/kernel/process_64.c"
    }
    {
        syscalls: ["ioperm"]
        fields: ["from" "num" "turn_on"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/arch/x86/kernel/ioport.c"
    }
    {
        syscalls: ["iopl"]
        fields: ["level"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/arch/x86/kernel/ioport.c"
    }
    {
        syscalls: ["modify_ldt"]
        fields: ["func" "ptr" "bytecount"]
        min_kernel: "4.7"
        source: "https://github.com/torvalds/linux/blob/v4.7/arch/x86/kernel/ldt.c"
    }
    {
        syscalls: ["map_shadow_stack"]
        fields: ["addr" "size" "flags"]
        min_kernel: "6.6"
        source: "https://github.com/torvalds/linux/blob/v6.6/arch/x86/kernel/shstk.c"
    }
]
const TRACEPOINT_FIELD_KERNEL_FEATURES = [
    { target: "tracepoint:syscalls/sys_enter_read" field: "fd" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_READ_FD }
    { target: "tracepoint:syscalls/sys_enter_read" field: "buf" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_READ_BUF }
    { target: "tracepoint:syscalls/sys_enter_read" field: "count" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_READ_COUNT }
    { target: "tracepoint:syscalls/sys_enter_write" field: "fd" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_WRITE_FD }
    { target: "tracepoint:syscalls/sys_enter_write" field: "buf" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_WRITE_BUF }
    { target: "tracepoint:syscalls/sys_enter_write" field: "count" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_WRITE_COUNT }
    { target: "tracepoint:syscalls/sys_enter_close" field: "fd" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_CLOSE_FD }
    { target: "tracepoint:syscalls/sys_enter_openat" field: "dfd" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT_DFD }
    { target: "tracepoint:syscalls/sys_enter_openat" field: "filename" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT_FILENAME }
    { target: "tracepoint:syscalls/sys_enter_openat" field: "flags" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT_FLAGS }
    { target: "tracepoint:syscalls/sys_enter_openat" field: "mode" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT_MODE }
    { target: "tracepoint:syscalls/sys_enter_openat2" field: "dfd" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT2_DFD }
    { target: "tracepoint:syscalls/sys_enter_openat2" field: "filename" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT2_FILENAME }
    { target: "tracepoint:syscalls/sys_enter_openat2" field: "how" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT2_HOW }
    { target: "tracepoint:syscalls/sys_enter_openat2" field: "usize" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_OPENAT2_USIZE }
    { target: "tracepoint:syscalls/sys_enter_execve" field: "filename" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_EXECVE_FILENAME }
    { target: "tracepoint:syscalls/sys_enter_execve" field: "argv" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_EXECVE_ARGV }
    { target: "tracepoint:syscalls/sys_enter_execve" field: "envp" feature: $KERNEL_FEATURE_TRACEPOINT_SYS_ENTER_EXECVE_ENVP }
]
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

# Keep this table aligned with `BpfHelper::name` / helper IDs in Rust.
# The floor table above mirrors the append-only Linux UAPI helper batches.
const BPF_HELPER_IDS = [
    { name: "bpf_bind", id: 64 }
    { name: "bpf_bprm_opts_set", id: 159 }
    { name: "bpf_btf_find_by_name_kind", id: 167 }
    { name: "bpf_cgrp_storage_delete", id: 211 }
    { name: "bpf_cgrp_storage_get", id: 210 }
    { name: "bpf_check_mtu", id: 163 }
    { name: "bpf_clone_redirect", id: 13 }
    { name: "bpf_copy_from_user", id: 148 }
    { name: "bpf_copy_from_user_task", id: 191 }
    { name: "bpf_csum_diff", id: 28 }
    { name: "bpf_csum_level", id: 135 }
    { name: "bpf_csum_update", id: 40 }
    { name: "bpf_current_task_under_cgroup", id: 37 }
    { name: "bpf_d_path", id: 147 }
    { name: "bpf_dynptr_data", id: 203 }
    { name: "bpf_dynptr_from_mem", id: 197 }
    { name: "bpf_dynptr_read", id: 201 }
    { name: "bpf_dynptr_write", id: 202 }
    { name: "bpf_fib_lookup", id: 69 }
    { name: "bpf_find_vma", id: 180 }
    { name: "bpf_for_each_map_elem", id: 164 }
    { name: "bpf_get_attach_cookie", id: 174 }
    { name: "bpf_get_branch_snapshot", id: 176 }
    { name: "bpf_get_cgroup_classid", id: 17 }
    { name: "bpf_get_current_ancestor_cgroup_id", id: 123 }
    { name: "bpf_get_current_cgroup_id", id: 80 }
    { name: "bpf_get_current_comm", id: 16 }
    { name: "bpf_get_current_pid_tgid", id: 14 }
    { name: "bpf_get_current_task", id: 35 }
    { name: "bpf_get_current_task_btf", id: 158 }
    { name: "bpf_get_current_uid_gid", id: 15 }
    { name: "bpf_get_func_arg", id: 183 }
    { name: "bpf_get_func_arg_cnt", id: 185 }
    { name: "bpf_get_func_ip", id: 173 }
    { name: "bpf_get_func_ret", id: 184 }
    { name: "bpf_get_hash_recalc", id: 34 }
    { name: "bpf_get_listener_sock", id: 98 }
    { name: "bpf_get_local_storage", id: 81 }
    { name: "bpf_get_netns_cookie", id: 122 }
    { name: "bpf_get_ns_current_pid_tgid", id: 120 }
    { name: "bpf_get_numa_node_id", id: 42 }
    { name: "bpf_get_prandom_u32", id: 7 }
    { name: "bpf_get_retval", id: 186 }
    { name: "bpf_get_route_realm", id: 24 }
    { name: "bpf_get_smp_processor_id", id: 8 }
    { name: "bpf_get_socket_cookie", id: 46 }
    { name: "bpf_get_socket_uid", id: 47 }
    { name: "bpf_get_stack", id: 67 }
    { name: "bpf_get_stackid", id: 27 }
    { name: "bpf_get_task_stack", id: 141 }
    { name: "bpf_getsockopt", id: 57 }
    { name: "bpf_ima_file_hash", id: 193 }
    { name: "bpf_ima_inode_hash", id: 161 }
    { name: "bpf_inode_storage_delete", id: 146 }
    { name: "bpf_inode_storage_get", id: 145 }
    { name: "bpf_jiffies64", id: 118 }
    { name: "bpf_kallsyms_lookup_name", id: 179 }
    { name: "bpf_kptr_xchg", id: 194 }
    { name: "bpf_ktime_get_boot_ns", id: 125 }
    { name: "bpf_ktime_get_coarse_ns", id: 160 }
    { name: "bpf_ktime_get_ns", id: 5 }
    { name: "bpf_ktime_get_tai_ns", id: 208 }
    { name: "bpf_l3_csum_replace", id: 10 }
    { name: "bpf_l4_csum_replace", id: 11 }
    { name: "bpf_load_hdr_opt", id: 142 }
    { name: "bpf_loop", id: 181 }
    { name: "bpf_lwt_push_encap", id: 73 }
    { name: "bpf_lwt_seg6_action", id: 76 }
    { name: "bpf_lwt_seg6_adjust_srh", id: 75 }
    { name: "bpf_lwt_seg6_store_bytes", id: 74 }
    { name: "bpf_map_delete_elem", id: 3 }
    { name: "bpf_map_lookup_elem", id: 1 }
    { name: "bpf_map_lookup_percpu_elem", id: 195 }
    { name: "bpf_map_peek_elem", id: 89 }
    { name: "bpf_map_pop_elem", id: 88 }
    { name: "bpf_map_push_elem", id: 87 }
    { name: "bpf_map_update_elem", id: 2 }
    { name: "bpf_msg_apply_bytes", id: 61 }
    { name: "bpf_msg_cork_bytes", id: 62 }
    { name: "bpf_msg_pop_data", id: 91 }
    { name: "bpf_msg_pull_data", id: 63 }
    { name: "bpf_msg_push_data", id: 90 }
    { name: "bpf_msg_redirect_hash", id: 71 }
    { name: "bpf_msg_redirect_map", id: 60 }
    { name: "bpf_override_return", id: 58 }
    { name: "bpf_per_cpu_ptr", id: 153 }
    { name: "bpf_perf_event_output", id: 25 }
    { name: "bpf_perf_event_read", id: 22 }
    { name: "bpf_perf_event_read_value", id: 55 }
    { name: "bpf_perf_prog_read_value", id: 56 }
    { name: "bpf_probe_read", id: 4 }
    { name: "bpf_probe_read_kernel", id: 113 }
    { name: "bpf_probe_read_kernel_str", id: 115 }
    { name: "bpf_probe_read_str", id: 45 }
    { name: "bpf_probe_read_user", id: 112 }
    { name: "bpf_probe_read_user_str", id: 114 }
    { name: "bpf_probe_write_user", id: 36 }
    { name: "bpf_rc_keydown", id: 78 }
    { name: "bpf_rc_pointer_rel", id: 92 }
    { name: "bpf_rc_repeat", id: 77 }
    { name: "bpf_read_branch_records", id: 119 }
    { name: "bpf_redirect", id: 23 }
    { name: "bpf_redirect_map", id: 51 }
    { name: "bpf_redirect_neigh", id: 152 }
    { name: "bpf_redirect_peer", id: 155 }
    { name: "bpf_reserve_hdr_opt", id: 144 }
    { name: "bpf_ringbuf_discard", id: 133 }
    { name: "bpf_ringbuf_discard_dynptr", id: 200 }
    { name: "bpf_ringbuf_output", id: 130 }
    { name: "bpf_ringbuf_query", id: 134 }
    { name: "bpf_ringbuf_reserve", id: 131 }
    { name: "bpf_ringbuf_reserve_dynptr", id: 198 }
    { name: "bpf_ringbuf_submit", id: 132 }
    { name: "bpf_ringbuf_submit_dynptr", id: 199 }
    { name: "bpf_send_signal", id: 109 }
    { name: "bpf_send_signal_thread", id: 117 }
    { name: "bpf_seq_printf", id: 126 }
    { name: "bpf_seq_printf_btf", id: 150 }
    { name: "bpf_seq_write", id: 127 }
    { name: "bpf_set_hash", id: 48 }
    { name: "bpf_set_hash_invalid", id: 41 }
    { name: "bpf_set_retval", id: 187 }
    { name: "bpf_setsockopt", id: 49 }
    { name: "bpf_sk_ancestor_cgroup_id", id: 129 }
    { name: "bpf_sk_assign", id: 124 }
    { name: "bpf_sk_cgroup_id", id: 128 }
    { name: "bpf_sk_fullsock", id: 95 }
    { name: "bpf_sk_lookup_tcp", id: 84 }
    { name: "bpf_sk_lookup_udp", id: 85 }
    { name: "bpf_sk_redirect_hash", id: 72 }
    { name: "bpf_sk_redirect_map", id: 52 }
    { name: "bpf_sk_release", id: 86 }
    { name: "bpf_sk_select_reuseport", id: 82 }
    { name: "bpf_sk_storage_delete", id: 108 }
    { name: "bpf_sk_storage_get", id: 107 }
    { name: "bpf_skb_adjust_room", id: 50 }
    { name: "bpf_skb_ancestor_cgroup_id", id: 83 }
    { name: "bpf_skb_cgroup_classid", id: 151 }
    { name: "bpf_skb_cgroup_id", id: 79 }
    { name: "bpf_skb_change_head", id: 43 }
    { name: "bpf_skb_change_proto", id: 31 }
    { name: "bpf_skb_change_tail", id: 38 }
    { name: "bpf_skb_change_type", id: 32 }
    { name: "bpf_skb_ecn_set_ce", id: 97 }
    { name: "bpf_skb_get_tunnel_key", id: 20 }
    { name: "bpf_skb_get_tunnel_opt", id: 29 }
    { name: "bpf_skb_get_xfrm_state", id: 66 }
    { name: "bpf_skb_load_bytes", id: 26 }
    { name: "bpf_skb_load_bytes_relative", id: 68 }
    { name: "bpf_skb_output", id: 111 }
    { name: "bpf_skb_pull_data", id: 39 }
    { name: "bpf_skb_set_tstamp", id: 192 }
    { name: "bpf_skb_set_tunnel_key", id: 21 }
    { name: "bpf_skb_set_tunnel_opt", id: 30 }
    { name: "bpf_skb_store_bytes", id: 9 }
    { name: "bpf_skb_under_cgroup", id: 33 }
    { name: "bpf_skb_vlan_pop", id: 19 }
    { name: "bpf_skb_vlan_push", id: 18 }
    { name: "bpf_skc_lookup_tcp", id: 99 }
    { name: "bpf_skc_to_mptcp_sock", id: 196 }
    { name: "bpf_skc_to_tcp6_sock", id: 136 }
    { name: "bpf_skc_to_tcp_request_sock", id: 139 }
    { name: "bpf_skc_to_tcp_sock", id: 137 }
    { name: "bpf_skc_to_tcp_timewait_sock", id: 138 }
    { name: "bpf_skc_to_udp6_sock", id: 140 }
    { name: "bpf_skc_to_unix_sock", id: 178 }
    { name: "bpf_snprintf", id: 165 }
    { name: "bpf_snprintf_btf", id: 149 }
    { name: "bpf_sock_from_file", id: 162 }
    { name: "bpf_sock_hash_update", id: 70 }
    { name: "bpf_sock_map_update", id: 53 }
    { name: "bpf_sock_ops_cb_flags_set", id: 59 }
    { name: "bpf_spin_lock", id: 93 }
    { name: "bpf_spin_unlock", id: 94 }
    { name: "bpf_store_hdr_opt", id: 143 }
    { name: "bpf_strncmp", id: 182 }
    { name: "bpf_strtol", id: 105 }
    { name: "bpf_strtoul", id: 106 }
    { name: "bpf_sys_bpf", id: 166 }
    { name: "bpf_sys_close", id: 168 }
    { name: "bpf_sysctl_get_current_value", id: 102 }
    { name: "bpf_sysctl_get_name", id: 101 }
    { name: "bpf_sysctl_get_new_value", id: 103 }
    { name: "bpf_sysctl_set_new_value", id: 104 }
    { name: "bpf_tail_call", id: 12 }
    { name: "bpf_task_pt_regs", id: 175 }
    { name: "bpf_task_storage_delete", id: 157 }
    { name: "bpf_task_storage_get", id: 156 }
    { name: "bpf_tcp_check_syncookie", id: 100 }
    { name: "bpf_tcp_gen_syncookie", id: 110 }
    { name: "bpf_tcp_raw_check_syncookie_ipv4", id: 206 }
    { name: "bpf_tcp_raw_check_syncookie_ipv6", id: 207 }
    { name: "bpf_tcp_raw_gen_syncookie_ipv4", id: 204 }
    { name: "bpf_tcp_raw_gen_syncookie_ipv6", id: 205 }
    { name: "bpf_tcp_send_ack", id: 116 }
    { name: "bpf_tcp_sock", id: 96 }
    { name: "bpf_this_cpu_ptr", id: 154 }
    { name: "bpf_timer_cancel", id: 172 }
    { name: "bpf_timer_init", id: 169 }
    { name: "bpf_timer_set_callback", id: 170 }
    { name: "bpf_timer_start", id: 171 }
    { name: "bpf_trace_printk", id: 6 }
    { name: "bpf_trace_vprintk", id: 177 }
    { name: "bpf_user_ringbuf_drain", id: 209 }
    { name: "bpf_xdp_adjust_head", id: 44 }
    { name: "bpf_xdp_adjust_meta", id: 54 }
    { name: "bpf_xdp_adjust_tail", id: 65 }
    { name: "bpf_xdp_get_buff_len", id: 188 }
    { name: "bpf_xdp_load_bytes", id: 189 }
    { name: "bpf_xdp_output", id: 121 }
    { name: "bpf_xdp_store_bytes", id: 190 }
]

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

const TARGET_CONTEXT_FIELD_KERNEL_FEATURE_EXPECTATIONS = [
    { target: "kretprobe:ksys_read" field: "retval" feature: $KERNEL_FEATURE_CTX_RETVAL_PT_REGS }
    { target: "fexit:ksys_read" field: "retval" feature: $KERNEL_FEATURE_CTX_RETVAL_TRAMPOLINE }
    { target: "xdp:lo" field: "packet_len" feature: $KERNEL_FEATURE_CTX_XDP_PACKET_LEN }
    { target: "xdp:lo" field: "data" feature: $KERNEL_FEATURE_CTX_XDP_DATA }
    { target: "xdp:lo" field: "data_end" feature: $KERNEL_FEATURE_CTX_XDP_DATA_END }
    { target: "xdp:lo" field: "ifindex" feature: $KERNEL_FEATURE_CTX_XDP_INGRESS_IFINDEX }
    { target: "xdp:lo" field: "rx_queue_index" feature: $KERNEL_FEATURE_CTX_XDP_RX_QUEUE_INDEX }
    { target: "sk_msg:/sys/fs/bpf/demo_sockmap" field: "data" feature: $KERNEL_FEATURE_CTX_SK_MSG_DATA }
    { target: "sk_msg:/sys/fs/bpf/demo_sockmap" field: "data_end" feature: $KERNEL_FEATURE_CTX_SK_MSG_DATA_END }
    { target: "sk_msg:/sys/fs/bpf/demo_sockmap" field: "family" feature: $KERNEL_FEATURE_CTX_SK_MSG_FAMILY }
    { target: "sk_msg:/sys/fs/bpf/demo_sockmap" field: "size" feature: $KERNEL_FEATURE_CTX_SK_MSG_PACKET_LEN }
    { target: "sk_msg:/sys/fs/bpf/demo_sockmap" field: "packet_len" feature: $KERNEL_FEATURE_CTX_SK_MSG_PACKET_LEN }
    { target: "sk_msg:/sys/fs/bpf/demo_sockmap" field: "sk" feature: $KERNEL_FEATURE_CTX_SK_MSG_SK }
    { target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap" field: "sk" feature: $KERNEL_FEATURE_CTX_SK_SKB_SK }
    { target: "tc:lo:ingress" field: "sk" feature: $KERNEL_FEATURE_CTX_SKB_SK }
    { target: "sk_reuseport:select" field: "data" feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_DATA }
    { target: "sk_reuseport:select" field: "data_end" feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_DATA_END }
    { target: "sk_reuseport:select" field: "protocol" feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_PROTOCOL }
    { target: "sk_reuseport:select" field: "bind_inany" feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_BIND_INANY }
    { target: "sk_reuseport:migrate" field: "migrating_sk" feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_MIGRATING_SK }
    { target: "sock_ops:/sys/fs/cgroup" field: "packet_len" feature: $KERNEL_FEATURE_CTX_SOCK_OPS_PACKET_LEN }
    { target: "sock_ops:/sys/fs/cgroup" field: "data" feature: $KERNEL_FEATURE_CTX_SOCK_OPS_DATA }
    { target: "sock_ops:/sys/fs/cgroup" field: "data_end" feature: $KERNEL_FEATURE_CTX_SOCK_OPS_DATA_END }
    { target: "netfilter:ipv4:pre_routing:priority=-100:defrag" field: "state" feature: $KERNEL_FEATURE_CTX_NETFILTER_STATE }
    { target: "netfilter:ipv4:pre_routing:priority=-100:defrag" field: "skb" feature: $KERNEL_FEATURE_CTX_NETFILTER_SKB }
    { target: "netfilter:ipv4:pre_routing:priority=-100:defrag" field: "hook" feature: $KERNEL_FEATURE_CTX_NETFILTER_HOOK }
    { target: "netfilter:ipv4:pre_routing:priority=-100:defrag" field: "pf" feature: $KERNEL_FEATURE_CTX_NETFILTER_PROTOCOL_FAMILY }
    { target: "lirc_mode2:/dev/lirc0" field: "sample" feature: $KERNEL_FEATURE_CTX_LIRC_SAMPLE }
    { target: "lirc_mode2:/dev/lirc0" field: "value" feature: $KERNEL_FEATURE_CTX_LIRC_VALUE }
    { target: "lirc_mode2:/dev/lirc0" field: "mode" feature: $KERNEL_FEATURE_CTX_LIRC_MODE }
    { target: "perf_event:software:cpu-clock:period=100000" field: "sample_period" feature: $KERNEL_FEATURE_CTX_PERF_SAMPLE_PERIOD }
    { target: "perf_event:software:cpu-clock:period=100000" field: "addr" feature: $KERNEL_FEATURE_CTX_PERF_ADDR }
    { target: "cgroup_device:/sys/fs/cgroup" field: "access_type" feature: $KERNEL_FEATURE_CTX_DEVICE_ACCESS_TYPE }
    { target: "cgroup_device:/sys/fs/cgroup" field: "device_type" feature: $KERNEL_FEATURE_CTX_DEVICE_TYPE }
    { target: "cgroup_device:/sys/fs/cgroup" field: "major" feature: $KERNEL_FEATURE_CTX_DEVICE_MAJOR }
    { target: "cgroup_device:/sys/fs/cgroup" field: "minor" feature: $KERNEL_FEATURE_CTX_DEVICE_MINOR }
    { target: "cgroup_sysctl:/sys/fs/cgroup" field: "write" feature: $KERNEL_FEATURE_CTX_SYSCTL_WRITE }
    { target: "cgroup_sysctl:/sys/fs/cgroup" field: "file_pos" feature: $KERNEL_FEATURE_CTX_SYSCTL_FILE_POS }
    { target: "cgroup_sysctl:/sys/fs/cgroup" field: "base_name" feature: $KERNEL_FEATURE_CTX_SYSCTL_BASE_NAME }
    { target: "cgroup_sockopt:/sys/fs/cgroup:get" field: "optval" feature: $KERNEL_FEATURE_CTX_SOCKOPT_OPTVAL }
    { target: "cgroup_sockopt:/sys/fs/cgroup:get" field: "optval_end" feature: $KERNEL_FEATURE_CTX_SOCKOPT_OPTVAL_END }
    { target: "cgroup_sockopt:/sys/fs/cgroup:get" field: "retval" feature: $KERNEL_FEATURE_CTX_SOCKOPT_RETVAL }
    { target: "cgroup_sockopt:/sys/fs/cgroup:get" field: "socket" feature: $KERNEL_FEATURE_CTX_CGROUP_SOCKOPT_SK }
    { target: "cgroup_sock:/sys/fs/cgroup:sock_create" field: "bound_dev_if" feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_BOUND_DEV_IF }
    { target: "cgroup_sock:/sys/fs/cgroup:sock_create" field: "family" feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_FAMILY }
    { target: "cgroup_sock:/sys/fs/cgroup:sock_create" field: "remote_port" feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_REMOTE_PORT }
    { target: "cgroup_sock:/sys/fs/cgroup:sock_create" field: "state" feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_STATE }
    { target: "cgroup_sock:/sys/fs/cgroup:sock_create" field: "rx_queue_mapping" feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_RX_QUEUE_MAPPING }
    { target: "cgroup_sock:/sys/fs/cgroup:sock_create" field: "sock" feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_SK }
    { target: "sk_lookup:/proc/self/ns/net" field: "family" feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_FAMILY }
    { target: "sk_lookup:/proc/self/ns/net" field: "ingress_ifindex" feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_INGRESS_IFINDEX }
    { target: "sk_lookup:/proc/self/ns/net" field: "cookie" feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_COOKIE }
    { target: "sk_lookup:/proc/self/ns/net" field: "sk" feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_SK }
    { target: "cgroup_sock_addr:/sys/fs/cgroup:connect4" field: "family" feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_FAMILY }
    { target: "cgroup_sock_addr:/sys/fs/cgroup:connect4" field: "user_ip4" feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_USER_IP4 }
    { target: "cgroup_sock_addr:/sys/fs/cgroup:connect4" field: "remote_port" feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_REMOTE_PORT }
    { target: "cgroup_sock_addr:/sys/fs/cgroup:connect4" field: "sock" feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_SK }
    { target: "iter:task_vma" field: "task" feature: $KERNEL_FEATURE_CTX_ITER_TASK_VMA_TASK }
    { target: "iter:bpf_map_elem" field: "map" feature: $KERNEL_FEATURE_CTX_ITER_MAP_ELEM_MAP }
    { target: "iter:bpf_map_elem" field: "key" feature: $KERNEL_FEATURE_CTX_ITER_MAP_KEY }
    { target: "iter:bpf_map_elem" field: "value" feature: $KERNEL_FEATURE_CTX_ITER_MAP_VALUE }
    { target: "iter:task_file" field: "fd" feature: $KERNEL_FEATURE_CTX_ITER_FD }
    { target: "iter:task_file" field: "file" feature: $KERNEL_FEATURE_CTX_ITER_FILE }
    { target: "iter:sockmap" field: "sk" feature: $KERNEL_FEATURE_CTX_ITER_SOCKMAP_SOCK }
    { target: "iter:udp" field: "bucket" feature: $KERNEL_FEATURE_CTX_ITER_UDP_BUCKET }
    { target: "iter:unix" field: "uid" feature: $KERNEL_FEATURE_CTX_ITER_UNIX_UID }
    { target: "iter:dmabuf" field: "dmabuf" feature: $KERNEL_FEATURE_CTX_ITER_DMABUF }
]

const CONTEXT_FIELD_HELPER_KERNEL_FEATURE_EXPECTATIONS = [
    { target: "raw_tracepoint:sys_enter" field: "pid" feature: $KERNEL_FEATURE_BPF_GET_CURRENT_PID_TGID }
    { target: "raw_tracepoint:sys_enter" field: "task" feature: $KERNEL_FEATURE_BPF_GET_CURRENT_TASK_BTF }
    { target: "raw_tracepoint:sys_enter" field: "current_task" feature: $KERNEL_FEATURE_BPF_GET_CURRENT_TASK_BTF }
    { target: "raw_tracepoint:sys_enter" field: "cgroup" feature: $KERNEL_FEATURE_BPF_GET_CURRENT_TASK_BTF }
    { target: "raw_tracepoint:sys_enter" field: "current_cgroup" feature: $KERNEL_FEATURE_BPF_GET_CURRENT_TASK_BTF }
    { target: "raw_tracepoint:sys_enter" field: "uid" feature: $KERNEL_FEATURE_BPF_GET_CURRENT_UID_GID }
    { target: "raw_tracepoint:sys_enter" field: "comm" feature: $KERNEL_FEATURE_BPF_GET_CURRENT_COMM }
    { target: "raw_tracepoint:sys_enter" field: "cpu" feature: $KERNEL_FEATURE_BPF_GET_SMP_PROCESSOR_ID }
    { target: "raw_tracepoint:sys_enter" field: "numa_node" feature: $KERNEL_FEATURE_BPF_GET_NUMA_NODE_ID }
    { target: "raw_tracepoint:sys_enter" field: "random" feature: $KERNEL_FEATURE_BPF_GET_PRANDOM_U32 }
    { target: "tc:lo:ingress" field: "cgroup_classid" feature: $KERNEL_FEATURE_BPF_GET_CGROUP_CLASSID }
    { target: "tc:lo:ingress" field: "route_realm" feature: $KERNEL_FEATURE_BPF_GET_ROUTE_REALM }
    { target: "tc:lo:ingress" field: "csum_level" feature: $KERNEL_FEATURE_BPF_CSUM_LEVEL }
    { target: "tc:lo:ingress" field: "hash_recalc" feature: $KERNEL_FEATURE_BPF_GET_HASH_RECALC }
    { target: "raw_tracepoint:sys_enter" field: "cgroup_id" feature: $KERNEL_FEATURE_BPF_GET_CURRENT_CGROUP_ID }
    { target: "tc:lo:ingress" field: "skb_cgroup_id" feature: $KERNEL_FEATURE_BPF_SKB_CGROUP_ID }
    { target: "tc:lo:ingress" field: "socket_cookie" feature: $KERNEL_FEATURE_BPF_GET_SOCKET_COOKIE }
    { target: "tc:lo:ingress" field: "socket_uid" feature: $KERNEL_FEATURE_BPF_GET_SOCKET_UID }
    { target: "sk_lookup:/proc/self/ns/net" field: "netns_cookie" feature: $KERNEL_FEATURE_BPF_GET_NETNS_COOKIE }
    { target: "raw_tracepoint:sys_enter" field: "ktime" feature: $KERNEL_FEATURE_BPF_KTIME_GET_NS }
    { target: "raw_tracepoint:sys_enter" field: "ktime_boot" feature: $KERNEL_FEATURE_BPF_KTIME_GET_BOOT_NS }
    { target: "tc:lo:ingress" field: "ktime_coarse" feature: $KERNEL_FEATURE_BPF_KTIME_GET_COARSE_NS }
    { target: "raw_tracepoint:sys_enter" field: "ktime_tai" feature: $KERNEL_FEATURE_BPF_KTIME_GET_TAI_NS }
    { target: "raw_tracepoint:sys_enter" field: "jiffies" feature: $KERNEL_FEATURE_BPF_JIFFIES64 }
    { target: "fentry:security_file_open" field: "func_ip" feature: $KERNEL_FEATURE_BPF_GET_FUNC_IP }
    { target: "fentry:security_file_open" field: "attach_cookie" feature: $KERNEL_FEATURE_BPF_GET_ATTACH_COOKIE }
    { target: "perf_event:software:cpu-clock:period=100000" field: "perf_counter" feature: $KERNEL_FEATURE_BPF_PERF_PROG_READ_VALUE }
    { target: "xdp:lo" field: "xdp_buff_len" feature: $KERNEL_FEATURE_BPF_XDP_GET_BUFF_LEN }
    { target: "cgroup_sysctl:/sys/fs/cgroup" field: "name" feature: $KERNEL_FEATURE_BPF_SYSCTL_GET_NAME }
    { target: "cgroup_sysctl:/sys/fs/cgroup" field: "current_value" feature: $KERNEL_FEATURE_BPF_SYSCTL_GET_CURRENT_VALUE }
    { target: "cgroup_sysctl:/sys/fs/cgroup" field: "new_value" feature: $KERNEL_FEATURE_BPF_SYSCTL_GET_NEW_VALUE }
    { target: "fentry:security_file_open" field: "arg_count" feature: $KERNEL_FEATURE_BPF_GET_FUNC_ARG_CNT }
    { target: "raw_tracepoint:sys_enter" field: "kstack" feature: $KERNEL_FEATURE_BPF_GET_STACKID }
    { target: "raw_tracepoint:sys_enter" field: "ustack" feature: $KERNEL_FEATURE_BPF_GET_STACKID }
]

const CONTEXT_PROJECTION_KERNEL_FEATURE_EXPECTATIONS = [
    { target: "cgroup_skb:/sys/fs/cgroup:egress" raw_access: "sk.cgroup_id" helper: "bpf_sk_cgroup_id" feature: $KERNEL_FEATURE_BPF_SK_CGROUP_ID }
    { target: "cgroup_skb:/sys/fs/cgroup:egress" raw_access: "sk.ancestor_cgroup_id.0" helper: "bpf_sk_ancestor_cgroup_id" feature: $KERNEL_FEATURE_BPF_SK_ANCESTOR_CGROUP_ID }
    { target: "tc:lo:ingress" raw_access: "sk.full" helper: "bpf_sk_fullsock" feature: $KERNEL_FEATURE_BPF_SK_FULLSOCK }
    { target: "cgroup_skb:/sys/fs/cgroup:egress" raw_access: "sk.tcp" helper: "bpf_tcp_sock" feature: $KERNEL_FEATURE_BPF_TCP_SOCK }
    { target: "cgroup_skb:/sys/fs/cgroup:egress" raw_access: "sk.listener" helper: "bpf_get_listener_sock" feature: $KERNEL_FEATURE_BPF_GET_LISTENER_SOCK }
    { target: "cgroup_sock:/sys/fs/cgroup:post_bind4" raw_access: "sk.local_ip4" helper: "" feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_LOCAL_IP4 }
    { target: "cgroup_sock:/sys/fs/cgroup:sock_create" raw_access: "sk.remote_port" helper: "" feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_REMOTE_PORT }
    { target: "flow_dissector:/proc/self/ns/net" raw_access: "flow_keys.ip_proto" helper: "" feature: $KERNEL_FEATURE_CTX_FLOW_KEYS }
]

const PROGRAM_CONTEXT_FIELD_KERNEL_FEATURE_EXPECTATIONS = [
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let docs = "$ctx.pid $ctx.sk.family"'
            '  # $ctx.pid $ctx.sk.family'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  let rec = { root: $ctx }'
            '  let docs = "$sk.family $rec.root.sk.family"'
            '  # $sk.family $rec.root.sk.family'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:sk"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = { socket: $ctx.sk }'
            '  let sk = ($rec | get socket)'
            '  $sk.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = { socket: $ctx.sk }'
            '  $rec | get socket | get family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = { ok: true, socket: $ctx.sk }'
            '  $rec | rename keep sock | get sock | get family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def wrap [sock] { { socket: $sock } }'
            '  wrap $ctx.sk | get socket | get family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ ok: true } | insert socket ($ctx | get sk))'
            '  $rec | get socket | get family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:sk" "ctx:family" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ socket: ($ctx | get sk) } | rename sock)'
            '  $rec | get sock | get family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:sk" "ctx:family" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ ok: true } | merge { socket: ($ctx | get sk) })'
            '  $rec | get socket | get family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:sk" "ctx:family" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ ok: true } | default ($ctx | get sk) socket)'
            '  $rec | get socket | get family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:sk" "ctx:family" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ socket: $ctx.sk } | update socket ($ctx | get sk))'
            '  $rec | get socket | get family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:sk" "ctx:family" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx | get packet_len | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:packet_len"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx | get data | get 0 | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx | get sk | get family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let sk = ($ctx | get sk)'
            '  $sk.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = { socket: ($ctx | get sk) }'
            '  $rec.socket.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def get_sk [c] { $c | get sk }'
            '  let sk = (get_sk $ctx)'
            '  $sk.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def wrap [c] { { socket: ($c | get sk) } }'
            '  wrap $ctx | get socket | get family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def read_packet [event] {'
            '    $event | get packet_len | count'
            '    0'
            '  }'
            '  read_packet $ctx'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:packet_len"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def read_family [event] {'
            '    let sk = ($event | get sk)'
            '    $sk | get family | count'
            '    0'
            '  }'
            '  read_family $ctx'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx| $ctx | get sk | get family | count; 0}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx | get sk.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|event|'
            '  $event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def id [x] { $x }'
            '  let event = (id $ctx)'
            '  $event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def id [x] { ($x) }'
            '  let event = (id ($ctx))'
            '  $event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def read_pid [event] {'
            '    $event.pid | count'
            '    0'
            '  }'
            '  let seen = (read_pid $ctx)'
            '  $seen | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def passthrough [event] {'
            '    let actual = $event'
            '    $actual'
            '  }'
            '  let event = (passthrough $ctx)'
            '  $event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "kretprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.retval | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:retval"]
    }
    {
        target: "fexit:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.retval | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:retval"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let rec = { event: $ctx }'
            '  $rec.event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def id [x] { $x }'
            '  let rec = { event: (id $ctx) }'
            '  $rec.event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|event| let rec = { event: $event }; $rec.event.pid | count }'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|event| let base = { event: $event }; let rec = { ok: true, ...$base }; $rec.event.pid | count }'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let base = { event: $ctx }'
            '  let rec = { ok: true, ...$base }'
            '  $rec.event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut rec = { event: null }'
            '  $rec.event = $ctx'
            '  $rec.event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.event = $ctx'
            '  $rec.event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def wrap [event] { { event: $event } }'
            '  let rec = (wrap $ctx)'
            '  $rec.event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def wrap [event] {'
            '    mut rec = { event: null }'
            '    $rec.event = $event'
            '    $rec'
            '  }'
            '  let rec = (wrap $ctx)'
            '  $rec.event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def wrap [event] {'
            '    mut rec = {}'
            '    $rec.event = $event'
            '    $rec'
            '  }'
            '  let rec = (wrap $ctx)'
            '  $rec.event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def wrap [event] {'
            '    let base = { event: $event }'
            '    let rec = { ok: true, ...$base }'
            '    $rec'
            '  }'
            '  let rec = (wrap $ctx)'
            '  $rec.event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  def wrap [event] {'
            '    let base = { event: $event }'
            '    { ok: true, ...$base }'
            '  }'
            '  let rec = (wrap $ctx)'
            '  $rec.event.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def read_pid [c] {'
            '    $c.pid | count'
            '    0'
            '  }'
            '  read_pid $ctx'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def id [x] { $x }'
            '  def read_pid [c] {'
            '    let actual = (id $c)'
            '    $actual.pid | count'
            '    0'
            '  }'
            '  read_pid $ctx'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def id [x] { $x }'
            '  def id2 [x] { id $x }'
            '  def read_pid [c] {'
            '    let actual = (id2 $c)'
            '    $actual.pid | count'
            '    0'
            '  }'
            '  read_pid $ctx'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def id [x] { $x }'
            '  def id2 [x] { id ($x) }'
            '  def read_pid [c] {'
            '    let actual = (id2 $c)'
            '    $actual.pid | count'
            '    0'
            '  }'
            '  read_pid $ctx'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "raw_tracepoint.w:sys_enter"
        program: [
            '{|ctx|'
            '  ($ctx.pid + $ctx.ktime) | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pid" "ctx:timestamp" "helper:bpf_get_current_pid_tgid" "helper:bpf_ktime_get_ns"]
    }
    {
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  $sk.rx_queue_mapping | count'
            '  1'
            '}'
        ]
        feature_keys: ["ctx:rx_queue_mapping" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let sk = ($ctx.sk)'
            '  $sk.tcp.snd_cwnd | count'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:sk" "helper:bpf_tcp_sock" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx.sk.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def id [x] { $x }'
            '  let sk = (id $ctx.sk)'
            '  $sk.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def id [x] { $x }'
            '  let sk = $ctx.sk'
            '  let same = (id $sk)'
            '  $same.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def get_sk [event] { $event.sk }'
            '  let sk = (get_sk $ctx)'
            '  $sk.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def wrap [ignored event] { { socket: ($event | get sk) } }'
            '  let rec = (wrap 0 $ctx)'
            '  $rec.socket.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def read_family [sk] {'
            '    $sk.family | count'
            '    0'
            '  }'
            '  let sk = $ctx.sk'
            '  let seen = (read_family $sk)'
            '  $seen | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = { socket: $ctx.sk }'
            '  $rec.socket.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def id [x] { $x }'
            '  let rec = { socket: (id $ctx.sk) }'
            '  $rec.socket.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = { socket: ($ctx.sk) }'
            '  $rec.socket.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = { root: $ctx socket: $ctx.sk }'
            '  $rec.socket.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  let rec = { socket: $sk }'
            '  $rec.socket.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def wrap_socket [sock] { { socket: $sock } }'
            '  def wrap_event [event] {'
            '    let sock = $event.sk'
            '    let base = (wrap_socket $sock)'
            '    { ok: true, ...$base }'
            '  }'
            '  let rec = (wrap_event $ctx)'
            '  $rec.socket.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let inserted = ({ ok: true } | insert socket $ctx.sk)'
            '  let base = { socket: null }'
            '  let updated = ($base | update socket $ctx.sk)'
            '  let upserted = ({ ok: true } | upsert socket $ctx.sk)'
            '  $inserted.socket.family | count'
            '  $updated.socket.family | count'
            '  $upserted.socket.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let base = { socket: $ctx.sk }'
            '  let rec = ($base | upsert ok true)'
            '  $rec.socket.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ socket: $ctx.sk, keep: 1 } | merge { ok: true } | select socket ok | reject ok | rename sock)'
            '  $rec.sock.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let rec = ({ ok: true } | default $ctx.sk socket)'
            '  $rec.socket.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let base = { socket: $ctx.sk }'
            '  let rec = ({ ...$base } | rename sock)'
            '  $rec.sock.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def wrap [sock] { { ok: true } | upsert socket $sock }'
            '  let rec = (wrap $ctx.sk)'
            '  $rec.socket.family | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  $sk.tcp.snd_cwnd | count'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:sk" "helper:bpf_tcp_sock" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let tcp = $ctx.socket.tcp'
            '  if $tcp { $tcp.snd_cwnd | count }'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:sk" "helper:bpf_tcp_sock" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let tcp = $ctx.sk.tcp'
            '  if $tcp { $tcp.snd_cwnd | count }'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:sk" "helper:bpf_tcp_sock" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let tcp = $ctx.sk.tcp'
            '  let rec = { tcp: $tcp }'
            '  if $rec.tcp { $rec.tcp.snd_cwnd | count }'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:sk" "helper:bpf_tcp_sock" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.retval = 0'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:sockopt_retval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:optval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut optval = $ctx.optval'
            '  $optval.2 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:optval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut optval = ($ctx | get optval)'
            '  $optval.2 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:optval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  def get_optval [event] { $event | get optval }'
            '  mut optval = (get_optval $ctx)'
            '  $optval.2 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:optval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let base = { optval: $ctx.optval }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:optval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut rec = { optval: ($ctx | get optval) }'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:optval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | upsert optval ($ctx | get optval))'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:optval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  def wrap [optval] { { optval: $optval } }'
            '  let optval = $ctx.optval'
            '  mut rec = (wrap $optval)'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:optval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  def wrap [optval] {'
            '    let base = { optval: $optval }'
            '    { ok: true, ...$base }'
            '  }'
            '  let optval = $ctx.optval'
            '  mut rec = (wrap $optval)'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:optval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  def wrap [optval] { { optval: $optval } }'
            '  def outer [event] {'
            '    let optval = $event.optval'
            '    let base = (wrap $optval)'
            '    { ok: true, ...$base }'
            '  }'
            '  mut rec = (outer $ctx)'
            '  $rec.optval.2 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:optval"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:set"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.level = 1'
            '  $ctx.optname = 2'
            '  $ctx.optlen = 4'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:level" "ctx:optname" "ctx:optlen"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:getpeername4"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.remote_ip4 = 2130706433'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:remote_ip4"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:getsockname6"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.local_ip6.1 = 42'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:local_ip6"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:sendmsg6"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.msg_src_ip6.3 = 42'
            '  $ctx.local_ip6.2 = 24'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:msg_src_ip6" "ctx:local_ip6"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let full = $ctx.sk.full'
            '  if $full { $full.family | count }'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:sk" "helper:bpf_sk_fullsock" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  let listener = $ctx.sk.listener'
            '  if $listener { $listener.family | count }'
            '  "pass"'
            '}'
        ]
        feature_keys: ["ctx:sk" "helper:bpf_get_listener_sock" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let task = $ctx.task'
            '  $task.pt_regs.arg0 | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:task" "helper:bpf_get_current_task_btf" "helper:bpf_task_pt_regs"]
    }
    {
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let cg = $ctx.current_cgroup'
            '  $cg.kn.id | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:cgroup" "helper:bpf_get_current_task_btf"]
    }
    {
        target: "tracepoint:syscalls/sys_enter_openat"
        program: [
            '{|ctx|'
            '  $ctx.current_task.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:task" "helper:bpf_get_current_task_btf"]
    }
    {
        target: "tracepoint:syscalls/sys_enter_openat"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { 1 | count }'
            '  ($ctx.dfd + $ctx.flags + $ctx.mode) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_openat:field:filename"
            "tracepoint:syscalls/sys_enter_openat:field:dfd"
            "tracepoint:syscalls/sys_enter_openat:field:flags"
            "tracepoint:syscalls/sys_enter_openat:field:mode"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_openat2"
        program: [
            '{|ctx|'
            '  let how = $ctx.how'
            '  if $how { 1 | count }'
            '  ($ctx.dfd + $ctx.usize) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_openat2:field:how"
            "tracepoint:syscalls/sys_enter_openat2:field:dfd"
            "tracepoint:syscalls/sys_enter_openat2:field:usize"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_open"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { 1 | count }'
            '  ($ctx.flags + $ctx.mode) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_open:field:filename"
            "tracepoint:syscalls/sys_enter_open:field:flags"
            "tracepoint:syscalls/sys_enter_open:field:mode"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_fchmodat2"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { 1 | count }'
            '  ($ctx.dfd + $ctx.mode + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_fchmodat2:field:filename"
            "tracepoint:syscalls/sys_enter_fchmodat2:field:dfd"
            "tracepoint:syscalls/sys_enter_fchmodat2:field:mode"
            "tracepoint:syscalls/sys_enter_fchmodat2:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_utimensat"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  let utimes = $ctx.utimes'
            '  if $filename { 1 | count }'
            '  if $utimes { 1 | count }'
            '  ($ctx.dfd + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_utimensat:field:filename"
            "tracepoint:syscalls/sys_enter_utimensat:field:utimes"
            "tracepoint:syscalls/sys_enter_utimensat:field:dfd"
            "tracepoint:syscalls/sys_enter_utimensat:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_ppoll"
        program: [
            '{|ctx|'
            '  let ufds = $ctx.ufds'
            '  let tsp = $ctx.tsp'
            '  let sigmask = $ctx.sigmask'
            '  if $ufds { 1 | count }'
            '  if $tsp { 1 | count }'
            '  if $sigmask { 1 | count }'
            '  ($ctx.nfds + $ctx.sigsetsize) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_ppoll:field:ufds"
            "tracepoint:syscalls/sys_enter_ppoll:field:tsp"
            "tracepoint:syscalls/sys_enter_ppoll:field:sigmask"
            "tracepoint:syscalls/sys_enter_ppoll:field:nfds"
            "tracepoint:syscalls/sys_enter_ppoll:field:sigsetsize"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_epoll_pwait2"
        program: [
            '{|ctx|'
            '  let events = $ctx.events'
            '  let timeout = $ctx.timeout'
            '  let sigmask = $ctx.sigmask'
            '  if $events { 1 | count }'
            '  if $timeout { 1 | count }'
            '  if $sigmask { 1 | count }'
            '  ($ctx.epfd + $ctx.maxevents + $ctx.sigsetsize) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_epoll_pwait2:field:events"
            "tracepoint:syscalls/sys_enter_epoll_pwait2:field:timeout"
            "tracepoint:syscalls/sys_enter_epoll_pwait2:field:sigmask"
            "tracepoint:syscalls/sys_enter_epoll_pwait2:field:epfd"
            "tracepoint:syscalls/sys_enter_epoll_pwait2:field:maxevents"
            "tracepoint:syscalls/sys_enter_epoll_pwait2:field:sigsetsize"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_fanotify_mark"
        program: [
            '{|ctx|'
            '  let pathname = $ctx.pathname'
            '  if $pathname { 1 | count }'
            '  ($ctx.fanotify_fd + $ctx.flags + $ctx.mask + $ctx.dfd) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_fanotify_mark:field:pathname"
            "tracepoint:syscalls/sys_enter_fanotify_mark:field:fanotify_fd"
            "tracepoint:syscalls/sys_enter_fanotify_mark:field:flags"
            "tracepoint:syscalls/sys_enter_fanotify_mark:field:mask"
            "tracepoint:syscalls/sys_enter_fanotify_mark:field:dfd"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_sync_file_range"
        program: [
            '{|ctx|'
            '  ($ctx.fd + $ctx.offset + $ctx.nbytes + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_sync_file_range:field:fd"
            "tracepoint:syscalls/sys_enter_sync_file_range:field:offset"
            "tracepoint:syscalls/sys_enter_sync_file_range:field:nbytes"
            "tracepoint:syscalls/sys_enter_sync_file_range:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_ioctl"
        program: [
            '{|ctx|'
            '  ($ctx.fd + $ctx.cmd) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_ioctl:field:fd"
            "tracepoint:syscalls/sys_enter_ioctl:field:cmd"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_readlinkat"
        program: [
            '{|ctx|'
            '  let pathname = $ctx.pathname'
            '  let buf = $ctx.buf'
            '  if $pathname { 1 | count }'
            '  if $buf { 1 | count }'
            '  ($ctx.dfd + $ctx.bufsiz) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_readlinkat:field:pathname"
            "tracepoint:syscalls/sys_enter_readlinkat:field:buf"
            "tracepoint:syscalls/sys_enter_readlinkat:field:dfd"
            "tracepoint:syscalls/sys_enter_readlinkat:field:bufsiz"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_name_to_handle_at"
        program: [
            '{|ctx|'
            '  let name = $ctx.name'
            '  let handle = $ctx.handle'
            '  let mnt_id = $ctx.mnt_id'
            '  if $name { 1 | count }'
            '  if $handle { 1 | count }'
            '  if $mnt_id { 1 | count }'
            '  ($ctx.dfd + $ctx.flag) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_name_to_handle_at:field:name"
            "tracepoint:syscalls/sys_enter_name_to_handle_at:field:handle"
            "tracepoint:syscalls/sys_enter_name_to_handle_at:field:mnt_id"
            "tracepoint:syscalls/sys_enter_name_to_handle_at:field:dfd"
            "tracepoint:syscalls/sys_enter_name_to_handle_at:field:flag"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_fchownat"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { 1 | count }'
            '  ($ctx.dfd + $ctx.user + $ctx.group + $ctx.flag) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_fchownat:field:filename"
            "tracepoint:syscalls/sys_enter_fchownat:field:dfd"
            "tracepoint:syscalls/sys_enter_fchownat:field:user"
            "tracepoint:syscalls/sys_enter_fchownat:field:group"
            "tracepoint:syscalls/sys_enter_fchownat:field:flag"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_mknod"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { 1 | count }'
            '  ($ctx.mode + $ctx.dev) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_mknod:field:filename"
            "tracepoint:syscalls/sys_enter_mknod:field:mode"
            "tracepoint:syscalls/sys_enter_mknod:field:dev"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_read"
        program: [
            '{|ctx|'
            '  let buf = $ctx.buf'
            '  if $buf { 1 | count }'
            '  ($ctx.fd + $ctx.count) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_read:field:buf"
            "tracepoint:syscalls/sys_enter_read:field:fd"
            "tracepoint:syscalls/sys_enter_read:field:count"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_write"
        program: [
            '{|ctx|'
            '  let buf = $ctx.buf'
            '  if $buf { 1 | count }'
            '  ($ctx.fd + $ctx.count) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_write:field:buf"
            "tracepoint:syscalls/sys_enter_write:field:fd"
            "tracepoint:syscalls/sys_enter_write:field:count"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_pread64"
        program: [
            '{|ctx|'
            '  let buf = $ctx.buf'
            '  if $buf { 1 | count }'
            '  ($ctx.fd + $ctx.count + $ctx.pos) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_pread64:field:buf"
            "tracepoint:syscalls/sys_enter_pread64:field:fd"
            "tracepoint:syscalls/sys_enter_pread64:field:count"
            "tracepoint:syscalls/sys_enter_pread64:field:pos"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_readv"
        program: [
            '{|ctx|'
            '  let vec = $ctx.vec'
            '  if $vec { 1 | count }'
            '  ($ctx.fd + $ctx.vlen) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_readv:field:vec"
            "tracepoint:syscalls/sys_enter_readv:field:fd"
            "tracepoint:syscalls/sys_enter_readv:field:vlen"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_preadv2"
        program: [
            '{|ctx|'
            '  let vec = $ctx.vec'
            '  if $vec { 1 | count }'
            '  ($ctx.fd + $ctx.vlen + $ctx.pos_l + $ctx.pos_h + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_preadv2:field:vec"
            "tracepoint:syscalls/sys_enter_preadv2:field:fd"
            "tracepoint:syscalls/sys_enter_preadv2:field:vlen"
            "tracepoint:syscalls/sys_enter_preadv2:field:pos_l"
            "tracepoint:syscalls/sys_enter_preadv2:field:pos_h"
            "tracepoint:syscalls/sys_enter_preadv2:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_copy_file_range"
        program: [
            '{|ctx|'
            '  let off_in = $ctx.off_in'
            '  if $off_in { 1 | count }'
            '  let off_out = $ctx.off_out'
            '  if $off_out { 1 | count }'
            '  ($ctx.fd_in + $ctx.fd_out + $ctx.len + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_copy_file_range:field:off_in"
            "tracepoint:syscalls/sys_enter_copy_file_range:field:off_out"
            "tracepoint:syscalls/sys_enter_copy_file_range:field:fd_in"
            "tracepoint:syscalls/sys_enter_copy_file_range:field:fd_out"
            "tracepoint:syscalls/sys_enter_copy_file_range:field:len"
            "tracepoint:syscalls/sys_enter_copy_file_range:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_splice"
        program: [
            '{|ctx|'
            '  let off_in = $ctx.off_in'
            '  if $off_in { 1 | count }'
            '  let off_out = $ctx.off_out'
            '  if $off_out { 1 | count }'
            '  ($ctx.fd_in + $ctx.fd_out + $ctx.len + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_splice:field:off_in"
            "tracepoint:syscalls/sys_enter_splice:field:off_out"
            "tracepoint:syscalls/sys_enter_splice:field:fd_in"
            "tracepoint:syscalls/sys_enter_splice:field:fd_out"
            "tracepoint:syscalls/sys_enter_splice:field:len"
            "tracepoint:syscalls/sys_enter_splice:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_setxattr"
        program: [
            '{|ctx|'
            '  let pathname = $ctx.pathname'
            '  if $pathname { 1 | count }'
            '  let name = $ctx.name'
            '  if $name { 1 | count }'
            '  let value = $ctx.value'
            '  if $value { 1 | count }'
            '  ($ctx.size + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_setxattr:field:pathname"
            "tracepoint:syscalls/sys_enter_setxattr:field:name"
            "tracepoint:syscalls/sys_enter_setxattr:field:value"
            "tracepoint:syscalls/sys_enter_setxattr:field:size"
            "tracepoint:syscalls/sys_enter_setxattr:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_fgetxattr"
        program: [
            '{|ctx|'
            '  let name = $ctx.name'
            '  if $name { 1 | count }'
            '  let value = $ctx.value'
            '  if $value { 1 | count }'
            '  ($ctx.fd + $ctx.size) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_fgetxattr:field:name"
            "tracepoint:syscalls/sys_enter_fgetxattr:field:value"
            "tracepoint:syscalls/sys_enter_fgetxattr:field:fd"
            "tracepoint:syscalls/sys_enter_fgetxattr:field:size"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_listxattr"
        program: [
            '{|ctx|'
            '  let pathname = $ctx.pathname'
            '  if $pathname { 1 | count }'
            '  let list = $ctx.list'
            '  if $list { 1 | count }'
            '  $ctx.size | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_listxattr:field:pathname"
            "tracepoint:syscalls/sys_enter_listxattr:field:list"
            "tracepoint:syscalls/sys_enter_listxattr:field:size"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_setxattrat"
        program: [
            '{|ctx|'
            '  let pathname = $ctx.pathname'
            '  if $pathname { 1 | count }'
            '  let name = $ctx.name'
            '  if $name { 1 | count }'
            '  let uargs = $ctx.uargs'
            '  if $uargs { 1 | count }'
            '  ($ctx.dfd + $ctx.at_flags + $ctx.usize) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_setxattrat:field:pathname"
            "tracepoint:syscalls/sys_enter_setxattrat:field:name"
            "tracepoint:syscalls/sys_enter_setxattrat:field:uargs"
            "tracepoint:syscalls/sys_enter_setxattrat:field:dfd"
            "tracepoint:syscalls/sys_enter_setxattrat:field:at_flags"
            "tracepoint:syscalls/sys_enter_setxattrat:field:usize"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_listxattrat"
        program: [
            '{|ctx|'
            '  let pathname = $ctx.pathname'
            '  if $pathname { 1 | count }'
            '  let list = $ctx.list'
            '  if $list { 1 | count }'
            '  ($ctx.dfd + $ctx.at_flags + $ctx.size) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_listxattrat:field:pathname"
            "tracepoint:syscalls/sys_enter_listxattrat:field:list"
            "tracepoint:syscalls/sys_enter_listxattrat:field:dfd"
            "tracepoint:syscalls/sys_enter_listxattrat:field:at_flags"
            "tracepoint:syscalls/sys_enter_listxattrat:field:size"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_close"
        program: [
            '{|ctx|'
            '  $ctx.fd | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_close:field:fd"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_execve"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { 1 | count }'
            '  let argv = $ctx.argv'
            '  if $argv { 1 | count }'
            '  let envp = $ctx.envp'
            '  if $envp { 1 | count }'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_execve:field:filename"
            "tracepoint:syscalls/sys_enter_execve:field:argv"
            "tracepoint:syscalls/sys_enter_execve:field:envp"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_execve"
        program: [
            '{|ctx|'
            '  let event = $ctx'
            '  let rec = { root: $ctx }'
            '  $event.filename | count'
            '  $rec.root.argv | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_execve:field:filename"
            "tracepoint:syscalls/sys_enter_execve:field:argv"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_execve"
        program: [
            '{|ctx|'
            '  def read_env [event] {'
            '    $event.envp | count'
            '    0'
            '  }'
            '  read_env $ctx'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_execve:field:envp"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_connect"
        program: [
            '{|ctx|'
            '  let addr = $ctx.uservaddr'
            '  if $addr { 1 | count }'
            '  ($ctx.fd + $ctx.addrlen) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_connect:field:uservaddr"
            "tracepoint:syscalls/sys_enter_connect:field:fd"
            "tracepoint:syscalls/sys_enter_connect:field:addrlen"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_sendto"
        program: [
            '{|ctx|'
            '  let buff = $ctx.buff'
            '  if $buff { 1 | count }'
            '  let addr = $ctx.addr'
            '  if $addr { 1 | count }'
            '  ($ctx.fd + $ctx.len + $ctx.flags + $ctx.addr_len) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_sendto:field:buff"
            "tracepoint:syscalls/sys_enter_sendto:field:addr"
            "tracepoint:syscalls/sys_enter_sendto:field:fd"
            "tracepoint:syscalls/sys_enter_sendto:field:len"
            "tracepoint:syscalls/sys_enter_sendto:field:flags"
            "tracepoint:syscalls/sys_enter_sendto:field:addr_len"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_recvfrom"
        program: [
            '{|ctx|'
            '  let ubuf = $ctx.ubuf'
            '  if $ubuf { 1 | count }'
            '  let addr = $ctx.addr'
            '  if $addr { 1 | count }'
            '  let addr_len = $ctx.addr_len'
            '  if $addr_len { 1 | count }'
            '  ($ctx.fd + $ctx.size + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_recvfrom:field:ubuf"
            "tracepoint:syscalls/sys_enter_recvfrom:field:addr"
            "tracepoint:syscalls/sys_enter_recvfrom:field:addr_len"
            "tracepoint:syscalls/sys_enter_recvfrom:field:fd"
            "tracepoint:syscalls/sys_enter_recvfrom:field:size"
            "tracepoint:syscalls/sys_enter_recvfrom:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_accept4"
        program: [
            '{|ctx|'
            '  let sockaddr = $ctx.upeer_sockaddr'
            '  if $sockaddr { 1 | count }'
            '  let addrlen = $ctx.upeer_addrlen'
            '  if $addrlen { 1 | count }'
            '  ($ctx.fd + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_accept4:field:upeer_sockaddr"
            "tracepoint:syscalls/sys_enter_accept4:field:upeer_addrlen"
            "tracepoint:syscalls/sys_enter_accept4:field:fd"
            "tracepoint:syscalls/sys_enter_accept4:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_socket"
        program: [
            '{|ctx|'
            '  ($ctx.family + $ctx.type + $ctx.protocol) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_socket:field:family"
            "tracepoint:syscalls/sys_enter_socket:field:type"
            "tracepoint:syscalls/sys_enter_socket:field:protocol"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_bind"
        program: [
            '{|ctx|'
            '  let addr = $ctx.umyaddr'
            '  if $addr { 1 | count }'
            '  ($ctx.fd + $ctx.addrlen) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_bind:field:umyaddr"
            "tracepoint:syscalls/sys_enter_bind:field:fd"
            "tracepoint:syscalls/sys_enter_bind:field:addrlen"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_setsockopt"
        program: [
            '{|ctx|'
            '  let optval = $ctx.optval'
            '  if $optval { 1 | count }'
            '  ($ctx.fd + $ctx.level + $ctx.optname + $ctx.optlen) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_setsockopt:field:optval"
            "tracepoint:syscalls/sys_enter_setsockopt:field:fd"
            "tracepoint:syscalls/sys_enter_setsockopt:field:level"
            "tracepoint:syscalls/sys_enter_setsockopt:field:optname"
            "tracepoint:syscalls/sys_enter_setsockopt:field:optlen"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_recvmmsg"
        program: [
            '{|ctx|'
            '  let mmsg = $ctx.mmsg'
            '  if $mmsg { 1 | count }'
            '  let timeout = $ctx.timeout'
            '  if $timeout { 1 | count }'
            '  ($ctx.fd + $ctx.vlen + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_recvmmsg:field:mmsg"
            "tracepoint:syscalls/sys_enter_recvmmsg:field:timeout"
            "tracepoint:syscalls/sys_enter_recvmmsg:field:fd"
            "tracepoint:syscalls/sys_enter_recvmmsg:field:vlen"
            "tracepoint:syscalls/sys_enter_recvmmsg:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_getpeername"
        program: [
            '{|ctx|'
            '  let usockaddr = $ctx.usockaddr'
            '  let usockaddr_len = $ctx.usockaddr_len'
            '  if $usockaddr { 1 | count }'
            '  if $usockaddr_len { 1 | count }'
            '  $ctx.fd | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_getpeername:field:usockaddr"
            "tracepoint:syscalls/sys_enter_getpeername:field:usockaddr_len"
            "tracepoint:syscalls/sys_enter_getpeername:field:fd"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_getrandom"
        program: [
            '{|ctx|'
            '  let buf = $ctx.buf'
            '  if $buf { 1 | count }'
            '  ($ctx.count + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_getrandom:field:buf"
            "tracepoint:syscalls/sys_enter_getrandom:field:count"
            "tracepoint:syscalls/sys_enter_getrandom:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_signalfd4"
        program: [
            '{|ctx|'
            '  let user_mask = $ctx.user_mask'
            '  if $user_mask { 1 | count }'
            '  ($ctx.ufd + $ctx.sizemask + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_signalfd4:field:user_mask"
            "tracepoint:syscalls/sys_enter_signalfd4:field:ufd"
            "tracepoint:syscalls/sys_enter_signalfd4:field:sizemask"
            "tracepoint:syscalls/sys_enter_signalfd4:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_io_pgetevents"
        program: [
            '{|ctx|'
            '  let events = $ctx.events'
            '  let timeout = $ctx.timeout'
            '  let usig = $ctx.usig'
            '  if $events { 1 | count }'
            '  if $timeout { 1 | count }'
            '  if $usig { 1 | count }'
            '  ($ctx.ctx_id + $ctx.min_nr + $ctx.nr) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_io_pgetevents:field:events"
            "tracepoint:syscalls/sys_enter_io_pgetevents:field:timeout"
            "tracepoint:syscalls/sys_enter_io_pgetevents:field:usig"
            "tracepoint:syscalls/sys_enter_io_pgetevents:field:ctx_id"
            "tracepoint:syscalls/sys_enter_io_pgetevents:field:min_nr"
            "tracepoint:syscalls/sys_enter_io_pgetevents:field:nr"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_ioprio_set"
        program: [
            '{|ctx|'
            '  ($ctx.which + $ctx.who + $ctx.ioprio) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_ioprio_set:field:which"
            "tracepoint:syscalls/sys_enter_ioprio_set:field:who"
            "tracepoint:syscalls/sys_enter_ioprio_set:field:ioprio"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_add_key"
        program: [
            '{|ctx|'
            '  let key_type = $ctx._type'
            '  let description = $ctx._description'
            '  let payload = $ctx._payload'
            '  if $key_type { 1 | count }'
            '  if $description { 1 | count }'
            '  if $payload { 1 | count }'
            '  ($ctx.plen + $ctx.ringid) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_add_key:field:_type"
            "tracepoint:syscalls/sys_enter_add_key:field:_description"
            "tracepoint:syscalls/sys_enter_add_key:field:_payload"
            "tracepoint:syscalls/sys_enter_add_key:field:plen"
            "tracepoint:syscalls/sys_enter_add_key:field:ringid"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_mbind"
        program: [
            '{|ctx|'
            '  let nmask = $ctx.nmask'
            '  if $nmask { 1 | count }'
            '  ($ctx.start + $ctx.len + $ctx.mode + $ctx.maxnode + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_mbind:field:nmask"
            "tracepoint:syscalls/sys_enter_mbind:field:start"
            "tracepoint:syscalls/sys_enter_mbind:field:len"
            "tracepoint:syscalls/sys_enter_mbind:field:mode"
            "tracepoint:syscalls/sys_enter_mbind:field:maxnode"
            "tracepoint:syscalls/sys_enter_mbind:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_move_pages"
        program: [
            '{|ctx|'
            '  let pages = $ctx.pages'
            '  let nodes = $ctx.nodes'
            '  let status = $ctx.status'
            '  if $pages { 1 | count }'
            '  if $nodes { 1 | count }'
            '  if $status { 1 | count }'
            '  ($ctx.nr_pages + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_move_pages:field:pages"
            "tracepoint:syscalls/sys_enter_move_pages:field:nodes"
            "tracepoint:syscalls/sys_enter_move_pages:field:status"
            "tracepoint:syscalls/sys_enter_move_pages:field:nr_pages"
            "tracepoint:syscalls/sys_enter_move_pages:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_set_mempolicy_home_node"
        program: [
            '{|ctx|'
            '  ($ctx.start + $ctx.len + $ctx.home_node + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_set_mempolicy_home_node:field:start"
            "tracepoint:syscalls/sys_enter_set_mempolicy_home_node:field:len"
            "tracepoint:syscalls/sys_enter_set_mempolicy_home_node:field:home_node"
            "tracepoint:syscalls/sys_enter_set_mempolicy_home_node:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_mq_open"
        program: [
            '{|ctx|'
            '  let name = $ctx.u_name'
            '  let attr = $ctx.u_attr'
            '  if $name { 1 | count }'
            '  if $attr { 1 | count }'
            '  ($ctx.oflag + $ctx.mode) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_mq_open:field:u_name"
            "tracepoint:syscalls/sys_enter_mq_open:field:u_attr"
            "tracepoint:syscalls/sys_enter_mq_open:field:oflag"
            "tracepoint:syscalls/sys_enter_mq_open:field:mode"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_mq_timedreceive"
        program: [
            '{|ctx|'
            '  let msg = $ctx.u_msg_ptr'
            '  let prio = $ctx.u_msg_prio'
            '  let timeout = $ctx.u_abs_timeout'
            '  if $msg { 1 | count }'
            '  if $prio { 1 | count }'
            '  if $timeout { 1 | count }'
            '  ($ctx.mqdes + $ctx.msg_len) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_mq_timedreceive:field:u_msg_ptr"
            "tracepoint:syscalls/sys_enter_mq_timedreceive:field:u_msg_prio"
            "tracepoint:syscalls/sys_enter_mq_timedreceive:field:u_abs_timeout"
            "tracepoint:syscalls/sys_enter_mq_timedreceive:field:mqdes"
            "tracepoint:syscalls/sys_enter_mq_timedreceive:field:msg_len"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_mq_getsetattr"
        program: [
            '{|ctx|'
            '  let mqstat = $ctx.u_mqstat'
            '  let omqstat = $ctx.u_omqstat'
            '  if $mqstat { 1 | count }'
            '  if $omqstat { 1 | count }'
            '  $ctx.mqdes | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_mq_getsetattr:field:u_mqstat"
            "tracepoint:syscalls/sys_enter_mq_getsetattr:field:u_omqstat"
            "tracepoint:syscalls/sys_enter_mq_getsetattr:field:mqdes"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_process_vm_readv"
        program: [
            '{|ctx|'
            '  let lvec = $ctx.lvec'
            '  let rvec = $ctx.rvec'
            '  if $lvec { 1 | count }'
            '  if $rvec { 1 | count }'
            '  ($ctx.liovcnt + $ctx.riovcnt + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_process_vm_readv:field:lvec"
            "tracepoint:syscalls/sys_enter_process_vm_readv:field:rvec"
            "tracepoint:syscalls/sys_enter_process_vm_readv:field:liovcnt"
            "tracepoint:syscalls/sys_enter_process_vm_readv:field:riovcnt"
            "tracepoint:syscalls/sys_enter_process_vm_readv:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_pkey_mprotect"
        program: [
            '{|ctx|'
            '  ($ctx.start + $ctx.len + $ctx.prot + $ctx.pkey) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_pkey_mprotect:field:start"
            "tracepoint:syscalls/sys_enter_pkey_mprotect:field:len"
            "tracepoint:syscalls/sys_enter_pkey_mprotect:field:prot"
            "tracepoint:syscalls/sys_enter_pkey_mprotect:field:pkey"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_prlimit64"
        program: [
            '{|ctx|'
            '  let new_rlim = $ctx.new_rlim'
            '  let old_rlim = $ctx.old_rlim'
            '  if $new_rlim { 1 | count }'
            '  if $old_rlim { 1 | count }'
            '  $ctx.resource | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_prlimit64:field:new_rlim"
            "tracepoint:syscalls/sys_enter_prlimit64:field:old_rlim"
            "tracepoint:syscalls/sys_enter_prlimit64:field:resource"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_get_robust_list"
        program: [
            '{|ctx|'
            '  let head_ptr = $ctx.head_ptr'
            '  let len_ptr = $ctx.len_ptr'
            '  if $head_ptr { 1 | count }'
            '  if $len_ptr { 1 | count }'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_get_robust_list:field:head_ptr"
            "tracepoint:syscalls/sys_enter_get_robust_list:field:len_ptr"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_rseq"
        program: [
            '{|ctx|'
            '  let user_rseq = $ctx.rseq'
            '  if $user_rseq { 1 | count }'
            '  ($ctx.rseq_len + $ctx.flags + $ctx.sig) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_rseq:field:rseq"
            "tracepoint:syscalls/sys_enter_rseq:field:rseq_len"
            "tracepoint:syscalls/sys_enter_rseq:field:flags"
            "tracepoint:syscalls/sys_enter_rseq:field:sig"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_init_module"
        program: [
            '{|ctx|'
            '  let umod = $ctx.umod'
            '  let uargs = $ctx.uargs'
            '  if $umod { 1 | count }'
            '  if $uargs { 1 | count }'
            '  $ctx.len | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_init_module:field:umod"
            "tracepoint:syscalls/sys_enter_init_module:field:uargs"
            "tracepoint:syscalls/sys_enter_init_module:field:len"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_kexec_file_load"
        program: [
            '{|ctx|'
            '  let cmdline = $ctx.cmdline_ptr'
            '  if $cmdline { 1 | count }'
            '  ($ctx.kernel_fd + $ctx.initrd_fd + $ctx.cmdline_len + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_kexec_file_load:field:cmdline_ptr"
            "tracepoint:syscalls/sys_enter_kexec_file_load:field:kernel_fd"
            "tracepoint:syscalls/sys_enter_kexec_file_load:field:initrd_fd"
            "tracepoint:syscalls/sys_enter_kexec_file_load:field:cmdline_len"
            "tracepoint:syscalls/sys_enter_kexec_file_load:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_swapon"
        program: [
            '{|ctx|'
            '  let specialfile = $ctx.specialfile'
            '  if $specialfile { 1 | count }'
            '  $ctx.swap_flags | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_swapon:field:specialfile"
            "tracepoint:syscalls/sys_enter_swapon:field:swap_flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_bpf"
        program: [
            '{|ctx|'
            '  let uattr = $ctx.uattr'
            '  if $uattr { 1 | count }'
            '  ($ctx.cmd + $ctx.size) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_bpf:field:uattr"
            "tracepoint:syscalls/sys_enter_bpf:field:cmd"
            "tracepoint:syscalls/sys_enter_bpf:field:size"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_perf_event_open"
        program: [
            '{|ctx|'
            '  let attr = $ctx.attr_uptr'
            '  if $attr { 1 | count }'
            '  ($ctx.group_fd + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_perf_event_open:field:attr_uptr"
            "tracepoint:syscalls/sys_enter_perf_event_open:field:group_fd"
            "tracepoint:syscalls/sys_enter_perf_event_open:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_seccomp"
        program: [
            '{|ctx|'
            '  let uargs = $ctx.uargs'
            '  if $uargs { 1 | count }'
            '  ($ctx.op + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_seccomp:field:uargs"
            "tracepoint:syscalls/sys_enter_seccomp:field:op"
            "tracepoint:syscalls/sys_enter_seccomp:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_clone"
        program: [
            '{|ctx|'
            '  let parent_tidptr = $ctx.parent_tidptr'
            '  let child_tidptr = $ctx.child_tidptr'
            '  if $parent_tidptr { 1 | count }'
            '  if $child_tidptr { 1 | count }'
            '  ($ctx.clone_flags + $ctx.newsp + $ctx.tls) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_clone:field:parent_tidptr"
            "tracepoint:syscalls/sys_enter_clone:field:child_tidptr"
            "tracepoint:syscalls/sys_enter_clone:field:clone_flags"
            "tracepoint:syscalls/sys_enter_clone:field:newsp"
            "tracepoint:syscalls/sys_enter_clone:field:tls"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_syslog"
        program: [
            '{|ctx|'
            '  let buf = $ctx.buf'
            '  if $buf { 1 | count }'
            '  ($ctx.type + $ctx.len) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_syslog:field:buf"
            "tracepoint:syscalls/sys_enter_syslog:field:type"
            "tracepoint:syscalls/sys_enter_syslog:field:len"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_personality"
        program: [
            '{|ctx|'
            '  $ctx.personality | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_personality:field:personality"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_openat"
        program: [
            '{|ctx|'
            '  ($ctx.id + ($ctx.args | get 0)) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_openat:field:id"
            "tracepoint:syscalls/sys_enter_openat:field:args"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_exit_openat2"
        program: [
            '{|ctx|'
            '  ($ctx.id + $ctx.ret) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_exit_openat2:field:id"
            "tracepoint:syscalls/sys_exit_openat2:field:ret"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_openat"
        program: [
            '{|ctx|'
            '  $ctx.ifindex | count'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  $ctx.flow_keys.ip_proto | count'
            '  "fallback"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.flow_keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut keys = $ctx.flow_keys'
            '  $keys.ip_proto = 17'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut keys = ($ctx | get flow_keys)'
            '  $keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  def get_keys [event] { $event | get flow_keys }'
            '  mut keys = (get_keys $ctx)'
            '  $keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = { keys: $ctx.flow_keys }'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = { keys: ($ctx | get flow_keys) }'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | upsert keys ($ctx | get flow_keys))'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | insert keys ($ctx | get flow_keys))'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | merge { keys: ($ctx | get flow_keys) })'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | default ($ctx | get flow_keys) keys)'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ keys: null } | update keys ($ctx | get flow_keys))'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut rec = ({ keys: ($ctx | get flow_keys), keep: 1 } | select keys keep | reject keep | rename parsed)'
            '  $rec.parsed.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  let base = { keys: $ctx.flow_keys }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  def wrap [keys] { { keys: $keys } }'
            '  let keys = $ctx.flow_keys'
            '  mut rec = (wrap $keys)'
            '  $rec.keys.ip_proto = 6'
            '  "parsed"'
            '}'
        ]
        feature_keys: ["ctx:flow_keys"]
    }
    {
        target: "netfilter:ipv4:pre_routing:priority=-100:defrag"
        program: [
            '{|ctx|'
            '  ($ctx.state.in.ifindex + $ctx.skb.len) | count'
            '  "accept"'
            '}'
        ]
        feature_keys: ["ctx:state" "ctx:skb"]
    }
    {
        target: "netfilter:ipv4:pre_routing:priority=-100:defrag"
        program: [
            '{|ctx|'
            '  let state = ($ctx.nf_state)'
            '  let skb = $ctx.skb'
            '  ($state.in.ifindex + $skb.len) | count'
            '  "accept"'
            '}'
        ]
        feature_keys: ["ctx:state" "ctx:skb"]
    }
    {
        target: "netfilter:ipv4:pre_routing:priority=-100:defrag"
        program: [
            '{|ctx|'
            '  let input = $ctx.state.in'
            '  $input.ifindex | count'
            '  "accept"'
            '}'
        ]
        feature_keys: ["ctx:state"]
    }
    {
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.arg.file.f_flags | count'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  let file = $ctx.arg.file'
            '  $file.f_flags | count'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0.orig_ax | count'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_probe_read_kernel"]
    }
    {
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  let regs = $ctx.arg0'
            '  $regs.orig_ax | count'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_probe_read_kernel"]
    }
    {
        target: "perf_event:software:cpu-clock:period=100000"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | count'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "lirc_mode2:/dev/lirc0"
        program: [
            '{|ctx|'
            '  ($ctx.cpu + $ctx.ktime + $ctx.cgroup_id) | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:cpu" "ctx:timestamp" "ctx:cgroup_id" "helper:bpf_get_smp_processor_id" "helper:bpf_ktime_get_ns" "helper:bpf_get_current_cgroup_id"]
    }
    {
        target: "cgroup_device:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  ($ctx.cpu + $ctx.ktime + $ctx.cgroup_id) | count'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:cpu" "ctx:timestamp" "ctx:cgroup_id" "helper:bpf_get_smp_processor_id" "helper:bpf_ktime_get_ns" "helper:bpf_get_current_cgroup_id"]
    }
    {
        target: "cgroup_device:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  ($ctx.access_type + $ctx.device_access + $ctx.device_type + $ctx.major + $ctx.minor) | count'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:access_type" "ctx:device_access" "ctx:device_type" "ctx:major" "ctx:minor"]
    }
    {
        target: "cgroup_sock:/sys/fs/cgroup:sock_create"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  ($ctx.family + $ctx.sock_type + $ctx.protocol + $ctx.state + $ctx.rx_queue_mapping + $ctx.socket_cookie + $ctx.netns_cookie + $ctx.sk.family) | count'
            '  $ctx.bound_dev_if = 1'
            '  $ctx.mark = 7'
            '  $ctx.priority = 3'
            '  "allow"'
            '}'
        ]
        feature_keys: [
            "ctx:bound_dev_if"
            "ctx:family"
            "ctx:mark"
            "ctx:netns_cookie"
            "ctx:priority"
            "ctx:protocol"
            "ctx:rx_queue_mapping"
            "ctx:sk"
            "ctx:sock_type"
            "ctx:socket_cookie"
            "ctx:state"
            "helper:bpf_get_netns_cookie"
            "helper:bpf_get_socket_cookie"
            "helper:bpf_probe_read_kernel"
        ]
    }
    {
        target: "cgroup_sock:/sys/fs/cgroup:post_bind6"
        program: [
            '{|ctx|'
            '  (($ctx.local_ip6 | get 1) + ($ctx.sk.local_ip6 | get 1) + $ctx.local_port + $ctx.sk.remote_port) | count'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:local_ip6" "ctx:local_port" "ctx:remote_port" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_sock:/sys/fs/cgroup:post_bind4"
        program: [
            '{|ctx|'
            '  ($ctx.sock.local_port + $ctx.socket.remote_port) | count'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:local_port" "ctx:remote_port" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect4"
        program: [
            '{|ctx|'
            '  ($ctx.user_ip4 + $ctx.user_port + $ctx.remote_ip4 + $ctx.remote_port + $ctx.sk.family) | count'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:remote_ip4" "ctx:remote_port" "ctx:sk" "ctx:user_ip4" "ctx:user_port" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect4"
        program: [
            '{|ctx|'
            '  ($ctx.sock.family + $ctx.socket.remote_port) | count'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:family" "ctx:remote_port" "ctx:sk" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  ($ctx.level + $ctx.optname + $ctx.optlen + $ctx.retval + $ctx.netns_cookie) | count'
            '  if $ctx.optval { 1 | count }'
            '  if $ctx.optval_end { 1 | count }'
            '  "allow"'
            '}'
        ]
        feature_keys: [
            "ctx:level"
            "ctx:netns_cookie"
            "ctx:optlen"
            "ctx:optname"
            "ctx:optval"
            "ctx:optval_end"
            "ctx:sockopt_retval"
            "helper:bpf_get_netns_cookie"
        ]
    }
    {
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.file_pos = 0'
            '  $ctx.new_value = "1"'
            '  $ctx.name | count'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:file_pos" "ctx:sysctl_name" "ctx:sysctl_new_value" "helper:bpf_sysctl_get_name"]
    }
    {
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  ($ctx.write + $ctx.file_pos) | count'
            '  $ctx.base_name | count'
            '  $ctx.current_value | count'
            '  $ctx.new_value | count'
            '  "allow"'
            '}'
        ]
        feature_keys: [
            "ctx:file_pos"
            "ctx:sysctl_base_name"
            "ctx:sysctl_current_value"
            "ctx:sysctl_new_value"
            "ctx:write"
            "helper:bpf_sysctl_get_current_value"
            "helper:bpf_sysctl_get_name"
            "helper:bpf_sysctl_get_new_value"
        ]
    }
    {
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  ($ctx.op + ($ctx.args | get 0) + $ctx.reply + ($ctx.replylong | get 0) + $ctx.family + $ctx.remote_port + $ctx.socket_cookie + $ctx.netns_cookie + $ctx.sk.family) | count'
            '  $ctx.reply = 1'
            '  $ctx.replylong.0 = 7'
            '  $ctx.cb_flags = 1'
            '  $ctx.sk_txhash = 7'
            '  1'
            '}'
        ]
        feature_keys: [
            "ctx:args"
            "ctx:cb_flags"
            "ctx:family"
            "ctx:netns_cookie"
            "ctx:op"
            "ctx:remote_port"
            "ctx:reply"
            "ctx:replylong"
            "ctx:sk"
            "ctx:sk_txhash"
            "ctx:socket_cookie"
            "helper:bpf_get_netns_cookie"
            "helper:bpf_get_socket_cookie"
            "helper:bpf_probe_read_kernel"
        ]
    }
    {
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  ($ctx.is_fullsock + $ctx.snd_cwnd + $ctx.srtt_us + $ctx.state + $ctx.rtt_min + $ctx.snd_ssthresh + $ctx.rcv_nxt + $ctx.snd_nxt) | count'
            '  ($ctx.snd_una + $ctx.mss_cache + $ctx.ecn_flags + $ctx.rate_delivered + $ctx.rate_interval_us + $ctx.packets_out + $ctx.retrans_out + $ctx.total_retrans) | count'
            '  ($ctx.segs_in + $ctx.data_segs_in + $ctx.segs_out + $ctx.data_segs_out + $ctx.lost_out + $ctx.sacked_out + ($ctx.bytes_received mod 1024) + ($ctx.bytes_acked mod 1024)) | count'
            '  1'
            '}'
        ]
        feature_keys: [
            "ctx:bytes_acked"
            "ctx:bytes_received"
            "ctx:data_segs_in"
            "ctx:data_segs_out"
            "ctx:ecn_flags"
            "ctx:is_fullsock"
            "ctx:lost_out"
            "ctx:mss_cache"
            "ctx:packets_out"
            "ctx:rate_delivered"
            "ctx:rate_interval_us"
            "ctx:rcv_nxt"
            "ctx:retrans_out"
            "ctx:rtt_min"
            "ctx:sacked_out"
            "ctx:segs_in"
            "ctx:segs_out"
            "ctx:snd_cwnd"
            "ctx:snd_nxt"
            "ctx:snd_ssthresh"
            "ctx:snd_una"
            "ctx:srtt_us"
            "ctx:state"
            "ctx:total_retrans"
        ]
    }
    {
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  ($ctx.family + $ctx.protocol + $ctx.ip_protocol + $ctx.remote_ip4 + $ctx.local_ip4 + $ctx.remote_port + $ctx.local_port + $ctx.cookie + $ctx.ingress_ifindex) | count'
            '  (($ctx.remote_ip6 | get 0) + ($ctx.local_ip6 | get 3)) | count'
            '  "pass"'
            '}'
        ]
        feature_keys: [
            "ctx:cookie"
            "ctx:family"
            "ctx:ingress_ifindex"
            "ctx:local_ip4"
            "ctx:local_ip6"
            "ctx:local_port"
            "ctx:protocol"
            "ctx:remote_ip4"
            "ctx:remote_ip6"
            "ctx:remote_port"
        ]
    }
    {
        target: "lsm_cgroup:socket_bind"
        program: [
            '{|ctx|'
            '  $ctx.arg.address.sa_family | count'
            '  1'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let readable = ($ctx)'
            '  $readable.new_value | count'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:sysctl_new_value" "helper:bpf_sysctl_get_new_value"]
    }
    {
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut writable = $ctx'
            '  $writable.new_value = "1"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["ctx:sysctl_new_value"]
    }
    {
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  (($ctx.data | get 0) + $ctx.packet_len + $ctx.eth_protocol + $ctx.protocol + $ctx.hash + $ctx.bind_inany + $ctx.socket_cookie) | count'
            '  ($ctx.sk.family + $ctx.sk.mark + $ctx.sk.priority + $ctx.sk.rx_queue_mapping) | count'
            '  "pass"'
            '}'
        ]
        feature_keys: ["ctx:data" "ctx:packet_len" "ctx:eth_protocol" "ctx:protocol" "ctx:hash" "ctx:bind_inany" "ctx:socket_cookie" "ctx:sk" "ctx:family" "ctx:mark" "ctx:priority" "ctx:rx_queue_mapping" "helper:bpf_get_socket_cookie" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut data = $ctx.data'
            '  $data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut data = ($ctx | get data)'
            '  $data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def get_data [event] { $event | get data }'
            '  mut data = (get_data $ctx)'
            '  $data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | upsert data ($ctx | get data))'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | insert data ($ctx | get data))'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | merge { data: ($ctx | get data) })'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | default ($ctx | get data) data)'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = ({ data: null } | update data ($ctx | get data))'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = ({ data: ($ctx | get data), keep: 1 } | select data keep | reject keep | rename packet)'
            '  $rec.packet.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = { data: $ctx.data }'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut rec = { data: ($ctx | get data) }'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def id [x] { $x }'
            '  mut rec = { data: (id ($ctx | get data)) }'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let base = { data: $ctx.data }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  def wrap [data] { { data: $data } }'
            '  let data = $ctx.data'
            '  mut rec = (wrap $data)'
            '  $rec.data.0 = 42'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:data"]
    }
    {
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut rec = { meta: $ctx.data_meta }'
            '  $rec.meta.0 = 7'
            '  "pass"'
            '}'
        ]
        feature_keys: ["ctx:data_meta"]
    }
    {
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut rec = { meta: ($ctx | get data_meta) }'
            '  $rec.meta.0 = 7'
            '  "pass"'
            '}'
        ]
        feature_keys: ["ctx:data_meta"]
    }
    {
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut rec = ({ ok: true } | upsert meta ($ctx | get data_meta))'
            '  $rec.meta.0 = 7'
            '  "pass"'
            '}'
        ]
        feature_keys: ["ctx:data_meta"]
    }
    {
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  mut meta = ($ctx | get data_meta)'
            '  $meta.0 = 7'
            '  "pass"'
            '}'
        ]
        feature_keys: ["ctx:data_meta"]
    }
    {
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  def get_meta [event] { $event | get data_meta }'
            '  mut meta = (get_meta $ctx)'
            '  $meta.0 = 7'
            '  "pass"'
            '}'
        ]
        feature_keys: ["ctx:data_meta"]
    }
    {
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let base = { meta: $ctx.data_meta }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.meta.0 = 7'
            '  "pass"'
            '}'
        ]
        feature_keys: ["ctx:data_meta"]
    }
    {
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  def wrap [meta] { { meta: $meta } }'
            '  let meta = $ctx.data_meta'
            '  mut rec = (wrap $meta)'
            '  $rec.meta.0 = 7'
            '  "pass"'
            '}'
        ]
        feature_keys: ["ctx:data_meta"]
    }
    {
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  ($ctx.pkt_type + $ctx.queue_mapping + $ctx.vlan_present + $ctx.vlan_tci + $ctx.vlan_proto + $ctx.hash_recalc + $ctx.csum_level) | count'
            '  ($ctx.socket_cookie + $ctx.socket_uid + $ctx.sk.family + $ctx.cb.2) | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:pkt_type" "ctx:queue_mapping" "ctx:vlan_present" "ctx:vlan_tci" "ctx:vlan_proto" "ctx:hash_recalc" "ctx:csum_level" "ctx:socket_cookie" "ctx:socket_uid" "ctx:sk" "ctx:family" "ctx:cb" "helper:bpf_get_hash_recalc" "helper:bpf_csum_level" "helper:bpf_get_socket_cookie" "helper:bpf_get_socket_uid" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  ($ctx.pkt_type + $ctx.queue_mapping + $ctx.vlan_present + $ctx.vlan_tci + $ctx.vlan_proto + $ctx.hash_recalc + $ctx.csum_level + $ctx.cgroup_classid + $ctx.route_realm + $ctx.cb.3) | count'
            '  "reroute"'
            '}'
        ]
        feature_keys: ["ctx:pkt_type" "ctx:queue_mapping" "ctx:vlan_present" "ctx:vlan_tci" "ctx:vlan_proto" "ctx:hash_recalc" "ctx:csum_level" "ctx:cgroup_classid" "ctx:route_realm" "ctx:cb" "helper:bpf_get_hash_recalc" "helper:bpf_csum_level" "helper:bpf_get_cgroup_classid" "helper:bpf_get_route_realm"]
    }
    {
        target: "tc_action:demo"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.queue_mapping = 1'
            '  $ctx.cb.2 = 9'
            '  $ctx.tc_classid = 42'
            '  $ctx.tstamp = 123'
            '  "ok"'
            '}'
        ]
        feature_keys: ["ctx:queue_mapping" "ctx:cb" "ctx:tc_classid" "ctx:tstamp"]
    }
    {
        target: "tc_action:demo"
        program: [
            '{|ctx|'
            '  mut rec = { event: $ctx }'
            '  $rec.event.tstamp = 123'
            '  "ok"'
            '}'
        ]
        feature_keys: ["ctx:tstamp"]
    }
    {
        target: "tc_action:demo"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.event = $ctx'
            '  $rec.event.tstamp = 123'
            '  "ok"'
            '}'
        ]
        feature_keys: ["ctx:tstamp"]
    }
    {
        target: "tc_action:demo"
        program: [
            '{|ctx|'
            '  let base = { event: $ctx }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.event.tstamp = 123'
            '  "ok"'
            '}'
        ]
        feature_keys: ["ctx:tstamp"]
    }
    {
        target: "tc_action:demo"
        program: [
            '{|ctx|'
            '  def wrap [event] { { event: $event } }'
            '  mut rec = (wrap $ctx)'
            '  $rec.event.tstamp = 123'
            '  "ok"'
            '}'
        ]
        feature_keys: ["ctx:tstamp"]
    }
    {
        target: "tc_action:demo"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.mark = (if $ctx.pid == 0 { 7 } else { 1 })'
            '  "ok"'
            '}'
        ]
        feature_keys: ["ctx:mark" "ctx:pid" "helper:bpf_get_current_pid_tgid"]
    }
    {
        target: "lwt_xmit:demo-route"
        program: [
            '{|event|'
            '  mut event = $event'
            '  $event.mark = 7'
            '  $event.priority = 3'
            '  $event.cb.1 = 9'
            '  "reroute"'
            '}'
        ]
        feature_keys: ["ctx:mark" "ctx:priority" "ctx:cb"]
    }
    {
        target: "iter:task"
        program: [
            '{|ctx|'
            '  let meta = $ctx.iter_meta'
            '  $meta.seq_num | count'
            '  if $ctx.iter_task { $ctx.iter_task.pid | count }'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:iter_meta" "ctx:iter_task" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "iter:task_file"
        program: [
            '{|ctx|'
            '  if $ctx.file { $ctx.file.f_mode | count }'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:iter_file" "helper:bpf_probe_read_kernel"]
    }
]

const PROGRAM_SURFACE_KERNEL_FEATURE_EXPECTATIONS = [
    {
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let text = "tail-call random int read-str read-kernel-str | emit | count | histogram start-timer stop-timer map-get map-put map-delete map-contains map-push map-peek map-pop redirect-map assign-socket adjust-message --pull adjust-packet --head redirect-socket redirect --peer"'
            '  # tail-call random int read-str read-kernel-str | emit | count | histogram start-timer stop-timer map-get map-put map-delete map-contains map-push map-peek map-pop redirect-map assign-socket adjust-message --pull adjust-packet --head redirect-socket redirect --peer'
            '  let ignored = 0 # | tail-call prog 0 | emit | count | histogram | start-timer | stop-timer | adjust-message --pull 0 1 | adjust-packet --head 0 | redirect-socket peers 0 --kind sockhash | redirect --peer'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  redirect-map tx_ports 0 --kind devmap'
            '  "pass"'
            '}'
        ]
        feature_keys: ["helper:bpf_redirect_map"]
    }
    {
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  adjust-packet --head 0'
            '  adjust-packet --meta 0'
            '  adjust-packet --tail 0'
            '  "pass"'
            '}'
        ]
        feature_keys: [
            "helper:bpf_xdp_adjust_head"
            "helper:bpf_xdp_adjust_meta"
            "helper:bpf_xdp_adjust_tail"
        ]
    }
    {
        target: "tc_action:demo"
        program: [
            '{|ctx|'
            '  adjust-packet --pull 0'
            '  adjust-packet --head 0'
            '  adjust-packet --tail 0'
            '  adjust-packet --room 0 --mode 0'
            '  "ok"'
            '}'
        ]
        feature_keys: [
            "helper:bpf_skb_pull_data"
            "helper:bpf_skb_change_head"
            "helper:bpf_skb_change_tail"
            "helper:bpf_skb_adjust_room"
        ]
    }
    {
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-message --apply 8'
            '  adjust-message --cork 8'
            '  adjust-message --pull 0 1'
            '  adjust-message --push 0 1'
            '  adjust-message --pop 0 1'
            '  redirect-socket peers 0 --kind sockmap'
            '  redirect-socket hash_peers 0 --kind sockhash'
            '  "pass"'
            '}'
        ]
        feature_keys: [
            "helper:bpf_msg_apply_bytes"
            "helper:bpf_msg_cork_bytes"
            "helper:bpf_msg_pull_data"
            "helper:bpf_msg_push_data"
            "helper:bpf_msg_pop_data"
            "helper:bpf_msg_redirect_map"
            "helper:bpf_msg_redirect_hash"
        ]
    }
    {
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  redirect-socket hash_peers 0 --kind sockhash'
            '  redirect-socket hash_peers 1'
            '  "pass"'
            '}'
        ]
        feature_keys: ["helper:bpf_msg_redirect_hash"]
    }
    {
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  helper-call "bpf_msg_redirect_hash" $ctx hash_peers "peer-a" 0'
            '  redirect-socket hash_peers "peer-b"'
            '  "pass"'
            '}'
        ]
        feature_keys: ["helper:bpf_msg_redirect_hash"]
    }
    {
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  redirect-socket peers 0 --kind sockmap'
            '  redirect-socket hash_peers 0 --kind sockhash'
            '  "pass"'
            '}'
        ]
        feature_keys: [
            "helper:bpf_sk_redirect_map"
            "helper:bpf_sk_redirect_hash"
        ]
    }
    {
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  redirect-socket sockets 0 --kind reuseport-sockarray'
            '  "select"'
            '}'
        ]
        feature_keys: ["helper:bpf_sk_select_reuseport"]
    }
    {
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|event|'
            '  assign-socket 0 --replace'
            '  "pass"'
            '}'
        ]
        feature_keys: ["ctx:sk" "helper:bpf_sk_assign"]
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let text = "$ctx.sk = 0; $ctx.sk == 0"'
            '  # $ctx.sk = 0'
            '  if $ctx.sk == 0 { 0 }'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "tc:lo:ingress"
        program: [
            '{|event|'
            '  assign-socket 0'
            '  "ok"'
            '}'
        ]
        feature_keys: ["ctx:sk" "helper:bpf_sk_assign"]
    }
    {
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|event|'
            '  $event.new_value = "1"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["helper:bpf_sysctl_set_new_value"]
    }
    {
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut writable = $ctx'
            '  $writable.new_value = "1"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["helper:bpf_sysctl_set_new_value"]
    }
    {
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut writable = ($ctx)'
            '  $writable.new_value = "1"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["helper:bpf_sysctl_set_new_value"]
    }
    {
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  def passthrough [event] {'
            '    let actual = $event'
            '    $actual'
            '  }'
            '  mut writable = (passthrough $ctx)'
            '  $writable.new_value = "1"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["helper:bpf_sysctl_set_new_value"]
    }
    {
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut rec = { event: $ctx }'
            '  $rec.event.new_value = "1"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["helper:bpf_sysctl_set_new_value"]
    }
    {
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let text = "$ctx.new_value = 1"'
            '  # $ctx.new_value = 1'
            '  if $ctx.new_value == 1 { 0 }'
            '  "allow"'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "tc_action:demo"
        program: [
            '{|event|'
            '  $event.sk = 0'
            '  1'
            '}'
        ]
        feature_keys: ["helper:bpf_sk_assign"]
    }
    {
        target: "tc_action:demo"
        program: [
            '{|ctx|'
            '  mut rec = { event: $ctx }'
            '  $rec.event.sk = 0'
            '  1'
            '}'
        ]
        feature_keys: ["helper:bpf_sk_assign"]
    }
    {
        target: "tc_action:demo"
        program: [
            '{|ctx|'
            '  def passthrough [event] {'
            '    let actual = $event'
            '    $actual'
            '  }'
            '  mut event = (passthrough $ctx)'
            '  $event.sk = 0'
            '  1'
            '}'
        ]
        feature_keys: ["helper:bpf_sk_assign"]
    }
    {
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|event|'
            '  $event.cb_flags = 1'
            '  1'
            '}'
        ]
        feature_keys: ["helper:bpf_sock_ops_cb_flags_set"]
    }
    {
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut rec = { event: $ctx }'
            '  $rec.event.cb_flags = 1'
            '  1'
            '}'
        ]
        feature_keys: ["helper:bpf_sock_ops_cb_flags_set"]
    }
    {
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  def passthrough [event] {'
            '    let actual = $event'
            '    $actual'
            '  }'
            '  mut event = (passthrough $ctx)'
            '  $event.cb_flags = 1'
            '  1'
            '}'
        ]
        feature_keys: ["helper:bpf_sock_ops_cb_flags_set"]
    }
    {
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|event|'
            '  let text = "$event.cb_flags = 1"'
            '  # $event.cb_flags = 1'
            '  if $event.cb_flags == 1 { 0 }'
            '  1'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.task | map-get task_state --kind task-storage --init { hits: 0 }'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_task_storage_get"]
    }
    {
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  map-define task_state --kind task-storage --value-type "record{hits:u64}"'
            '  $ctx.task | map-get task_state --init { hits: 0 }'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_task_storage_get"]
    }
    {
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.task | map-delete task_state --kind task-storage'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_task_storage_delete"]
    }
    {
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.task | map-contains task_state --kind task-storage'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_task_storage_get"]
    }
    {
        target: "cgroup_sock:/sys/fs/cgroup:post_bind4"
        program: [
            '{|ctx|'
            '  $ctx.sk | map-get sock_state --kind sk-storage --init { hits: 0 }'
            '  "allow"'
            '}'
        ]
        feature_keys: ["helper:bpf_sk_storage_get"]
    }
    {
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  $ctx.sk | map-delete sock_state --kind sk-storage'
            '  "allow"'
            '}'
        ]
        feature_keys: ["helper:bpf_sk_storage_delete"]
    }
    {
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  $ctx.arg.file.f_inode | map-get inode_state --kind inode-storage --init { hits: 0 }'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_inode_storage_get"]
    }
    {
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  $ctx.arg.file.f_inode | map-delete inode_state --kind inode-storage'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_inode_storage_delete"]
    }
    {
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.current_cgroup | map-get cgrp_state --kind cgrp-storage --init { hits: 0 }'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_cgrp_storage_get"]
    }
    {
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.current_cgroup | map-delete cgrp_state --kind cgrp-storage'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_cgrp_storage_delete"]
    }
]

const PROGRAM_HELPER_KERNEL_FEATURE_EXPECTATIONS = [
    {
        program: [
            '{|ctx|'
            '  let text = "helper-call \"bpf_trace_printk\" \"ignored\" 7"'
            '  # helper-call "bpf_map_lookup_elem" ignored key'
            '  let ignored = 0 # | helper-call "bpf_ktime_get_ns"'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        program: [
            '{|ctx|'
            '  let arg0 = "01234567"'
            '  let retval = "01234567"'
            '  (helper-call "bpf_get_func_arg" $ctx 0 $arg0) | count'
            '  (helper-call "bpf_get_func_ret" $ctx $retval) | count'
            '  (helper-call "bpf_get_func_arg_cnt" $ctx) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "helper:bpf_get_func_arg"
            "helper:bpf_get_func_ret"
            "helper:bpf_get_func_arg_cnt"
        ]
    }
    {
        program: [
            '{|ctx|'
            '  map-define nsdata --kind array --value-type bytes:8 --max-entries 1'
            '  let ns = (0 | map-get nsdata)'
            '  if $ns {'
            '    helper-call "bpf_get_ns_current_pid_tgid" 0 0 $ns 8'
            '  }'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_get_ns_current_pid_tgid"]
    }
    {
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_cgroup_classid" $ctx'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_skb_cgroup_classid"]
    }
    {
        program: [
            '{|ctx|'
            '  map-define fib_params --kind array --value-type bytes:64 --max-entries 1'
            '  let params = (0 | map-get fib_params --kind array)'
            '  if $params { helper-call "bpf_fib_lookup" $ctx $params 64 0 }'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_fib_lookup"]
    }
    {
        program: [
            '{|ctx|'
            '  map-define mtu_len --kind array --value-type bytes:4 --max-entries 1'
            '  let len = (0 | map-get mtu_len --kind array)'
            '  if $len { helper-call "bpf_check_mtu" $ctx 0 $len 0 0 }'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_check_mtu"]
    }
    {
        program: [
            '{|ctx|'
            '  let key = "01234567"'
            '  helper-call "bpf_map_lookup_percpu_elem" per_cpu_values $key 0 --kind per-cpu-array'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_map_lookup_percpu_elem"]
    }
    {
        program: [
            '{|ctx|'
            '  let tuple = "0123456789abcdef"'
            '  let sk = (helper-call "bpf_sk_lookup_tcp" $ctx $tuple 16 0 0)'
            '  if $sk {'
            '    helper-call "bpf_sk_release" $sk'
            '  }'
            '  "pass"'
            '}'
        ]
        feature_keys: ["helper:bpf_sk_lookup_tcp" "helper:bpf_sk_release"]
    }
    {
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers --kind array)'
            '  if $entry {'
            '    helper-call "bpf_timer_init" $entry.timer timers 0 --kind array'
            '    helper-call "bpf_timer_set_callback" $entry.timer {|timer key val| 0}'
            '    helper-call "bpf_timer_start" $entry.timer 1000 0'
            '    helper-call "bpf_timer_cancel" $entry.timer'
            '  }'
            '  0'
            '}'
        ]
        feature_keys: [
            "helper:bpf_timer_init"
            "helper:bpf_timer_set_callback"
            "helper:bpf_timer_start"
            "helper:bpf_timer_cancel"
        ]
    }
]

const PROGRAM_KFUNC_KERNEL_FEATURE_EXPECTATIONS = [
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let text = "kfunc-call \"bpf_task_from_pid\" 1"'
            '  # kfunc-call "bpf_task_from_pid" 1'
            '  let ignored = 0 # | kfunc-call "bpf_task_from_pid" 1'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_rcu_read_lock"'
            '  kfunc-call "bpf_rcu_read_unlock"'
            '  0'
            '}'
        ]
        feature_keys: ["kfunc:bpf_rcu_read_lock" "kfunc:bpf_rcu_read_unlock"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_preempt_disable"'
            '  kfunc-call "bpf_preempt_enable"'
            '  0'
            '}'
        ]
        feature_keys: ["kfunc:bpf_preempt_disable" "kfunc:bpf_preempt_enable"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let flags = "00000000"'
            '  kfunc-call "bpf_local_irq_save" $flags'
            '  kfunc-call "bpf_local_irq_restore" $flags'
            '  0'
            '}'
        ]
        feature_keys: ["kfunc:bpf_local_irq_save" "kfunc:bpf_local_irq_restore"]
    }
    {
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let flags = "00000000"'
            '  kfunc-call "bpf_res_spin_lock" $ctx.current_task'
            '  kfunc-call "bpf_res_spin_unlock" $ctx.current_task'
            '  kfunc-call "bpf_res_spin_lock_irqsave" $ctx.current_task $flags'
            '  kfunc-call "bpf_res_spin_unlock_irqrestore" $ctx.current_task $flags'
            '  0'
            '}'
        ]
        feature_keys: [
            "kfunc:bpf_res_spin_lock"
            "kfunc:bpf_res_spin_unlock"
            "kfunc:bpf_res_spin_lock_irqsave"
            "kfunc:bpf_res_spin_unlock_irqrestore"
        ]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup_unix:connect4"
        program: [
            '{|event|'
            '  $event.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        feature_keys: []
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|event|'
            '  $event.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["kfunc:bpf_sock_addr_set_sun_path"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  mut rec = { event: $ctx }'
            '  $rec.event.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["kfunc:bpf_sock_addr_set_sun_path"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  mut rec = {}'
            '  $rec.event = $ctx'
            '  $rec.event.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["kfunc:bpf_sock_addr_set_sun_path"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  let base = { event: $ctx }'
            '  mut rec = { ok: true, ...$base }'
            '  $rec.event.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["kfunc:bpf_sock_addr_set_sun_path"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  def wrap [event] { { event: $event } }'
            '  mut rec = (wrap $ctx)'
            '  $rec.event.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        feature_keys: ["kfunc:bpf_sock_addr_set_sun_path"]
    }
    {
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|event|'
            '  let text = "$event.sun_path = /tmp/nu-ebpf.sock"'
            '  # $event.sun_path = /tmp/nu-ebpf.sock'
            '  if $event.sun_path == "/tmp/nu-ebpf.sock" { 0 }'
            '  "allow"'
            '}'
        ]
        feature_keys: []
    }
]

const PROGRAM_KFUNC_KERNEL_FEATURE_DETAIL_EXPECTATIONS = [
    {
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_skb" $ctx 0 $d'
            '  0'
            '}'
        ]
        feature: {
            key: "kfunc:bpf_dynptr_from_skb"
            min_kernel: "6.4"
            source: "https://github.com/torvalds/linux/blob/v6.4/net/core/filter.c"
        }
    }
    {
        target: "fentry:tcp_v4_rcv"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_from_skb" $ctx.arg0 0 $d'
            '  0'
            '}'
        ]
        feature: {
            key: "kfunc:bpf_dynptr_from_skb"
            min_kernel: "6.12"
            source: "https://github.com/torvalds/linux/blob/v6.12/net/core/filter.c"
        }
    }
]

const PROGRAM_CALLBACK_BTF_KERNEL_FEATURE_EXPECTATIONS = [
    {
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers --kind array)'
            '  if $entry {'
            '    helper-call "bpf_timer_set_callback" $entry.timer {|timer key val|'
            '      $timer.id | count'
            '      0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        program: [
            '{|ctx|'
            '  map-define elems --kind array --value-type "record{seen:u64}"'
            '  helper-call "bpf_for_each_map_elem" elems {|m k v cb|'
            '    $m.id | count'
            '    0'
            '  } "ctx" 0 --kind array'
            '  0'
            '}'
        ]
        feature_keys: []
    }
    {
        program: [
            '{|ctx|'
            '  helper-call "bpf_find_vma" $ctx.current_task 0 {|task vma cb|'
            '    $vma.vm_start | count'
            '    0'
            '  } "ctx" 0'
            '  0'
            '}'
        ]
        feature_keys: []
    }
]

source ($REPO_ROOT | path join scripts verifier_diff fixtures.nu)

def fail [msg: string] {
    error make { msg: $msg }
}

def path-is-filelike [path: string] {
    let kind = ($path | path type)
    $kind == "file" or $kind == "symlink"
}

def newest-existing [label: string candidates: list<string>] {
    let existing = (
        $candidates
        | where {|candidate| path-is-filelike $candidate }
        | each {|candidate|
            let meta = (ls -D $candidate | first)
            { path: $candidate, modified: $meta.modified }
        }
        | sort-by modified
        | reverse
    )

    if (($existing | length) == 0) {
        fail $"could not find ($label); checked: ($candidates | str join ', ')"
    }

    $existing | get 0.path
}

def newest-modified [label: string paths: list<string>] {
    let existing = (
        $paths
        | where {|path| path-is-filelike $path }
        | each {|path| ls -D $path | first | get modified }
        | sort
        | reverse
    )

    if (($existing | length) == 0) {
        fail $"could not find ($label); checked: ($paths | str join ', ')"
    }

    $existing | get 0
}

def plugin-source-inputs [repo_root: string] {
    let rust_sources = (
        glob ($repo_root | path join "src/**/*.rs")
        | where {|path| not (($path | str contains "/tests/") or ($path | str ends-with "/tests.rs")) }
    )
    $rust_sources | append [
        ($repo_root | path join Cargo.toml)
        ($repo_root | path join Cargo.lock)
        ($repo_root | path join build.rs)
    ]
}

def assert-plugin-fresh [repo_root: string plugin_bin: string] {
    let plugin_modified = (ls -D $plugin_bin | first | get modified)
    let source_modified = (newest-modified "plugin source input" (plugin-source-inputs $repo_root))

    if $source_modified > $plugin_modified {
        fail $"plugin binary appears stale: ($plugin_bin) was modified ($plugin_modified), but plugin source inputs were modified ($source_modified); run `cargo build` or set PLUGIN_BIN"
    }
}

def resolve-plugin-bin [repo_root: string] {
    let override = ($env | get -o PLUGIN_BIN)

    if $override != null {
        if not (path-is-filelike $override) {
            fail $"plugin binary not found: ($override)"
        }
        return $override
    }

    let plugin_bin = (newest-existing "plugin binary" [
        ($repo_root | path join target debug nu_plugin_ebpf)
        ($repo_root | path join target release nu_plugin_ebpf)
    ])

    assert-plugin-fresh $repo_root $plugin_bin
    $plugin_bin
}

def current-nu-bin [] {
    $nu.current-exe
}

def command-exists [name: string] {
    ((which $name | length) > 0)
}

def is-root [] {
    ((^id -u | str trim | into int) == 0)
}

def parse-kernel-version [version: string] {
    let core = ($version | split row "-" | first)
    let parts = ($core | split row ".")
    {
        major: (($parts | get 0) | into int)
        minor: (($parts | get -o 1 | default "0") | into int)
        patch: (($parts | get -o 2 | default "0") | into int)
    }
}

def kernel-version-at-least [current: string required: string] {
    (kernel-version-compare $current $required) >= 0
}

def kernel-version-before [current: string maximum_exclusive: string] {
    (kernel-version-compare $current $maximum_exclusive) < 0
}

def kernel-version-compare [left: string right: string] {
    let have = (parse-kernel-version $left)
    let need = (parse-kernel-version $right)

    if $have.major != $need.major {
        if $have.major > $need.major { return 1 }
        return (-1)
    }
    if $have.minor != $need.minor {
        if $have.minor > $need.minor { return 1 }
        return (-1)
    }
    if $have.patch != $need.patch {
        if $have.patch > $need.patch { return 1 }
        return (-1)
    }

    0
}

def kernel-version-max [versions: list<string>] {
    mut max = ""
    mut has_max = false

    for version in $versions {
        if not $has_max {
            $max = $version
            $has_max = true
        } else if (kernel-version-compare $version $max) > 0 {
            $max = $version
        }
    }

    if $has_max { $max } else { null }
}

def kernel-version-min [versions: list<string>] {
    mut min = ""
    mut has_min = false

    for version in $versions {
        if not $has_min {
            $min = $version
            $has_min = true
        } else if (kernel-version-compare $version $min) < 0 {
            $min = $version
        }
    }

    if $has_min { $min } else { null }
}

def current-kernel-release [] {
    ^uname -r | str trim
}

def run-nu-with-plugin-complete [plugin_bin: string code: string] {
    run-external (current-nu-bin) "--no-config-file" "--plugins" $"[($plugin_bin)]" "-c" $code | complete
}

def default-local-jobs [] {
    let value = ($env | get -o VERIFIER_DIFF_JOBS)
    if $value == null {
        4
    } else {
        $value | into int
    }
}

def resolve-local-jobs [jobs] {
    let resolved = if $jobs == null { default-local-jobs } else { $jobs }
    if $resolved < 1 {
        fail $"--jobs must be at least 1, got ($resolved)"
    }
    $resolved
}

def fixture-program [fixture] {
    let program = $fixture.program
    if (($program | describe) | str starts-with "list") {
        $program | str join (char nl)
    } else {
        $program
    }
}

def dry-run-describe-code [fixture] {
    let target = ($fixture.target | to nuon)
    let program = (fixture-program $fixture)
    $"ebpf attach --dry-run ($target) ($program) | describe"
}

def dry-run-save-code [fixture output_path: string] {
    let target = ($fixture.target | to nuon)
    let path = ($output_path | to nuon)
    let program = (fixture-program $fixture)
    $"ebpf attach --dry-run ($target) ($program) | save -f ($path)"
}

def combined-output [result] {
    $"($result.stdout)($result.stderr)"
}

def optional [record field fallback] {
    let value = ($record | get -o $field)
    if $value == null { $fallback } else { $value }
}

def append-missing-kernel-features [features additions] {
    mut result = $features

    for feature in $additions {
        let key = ($feature | get key)
        let exists = ($result | any {|existing| ($existing | get key) == $key })
        if not $exists {
            $result = ($result | append $feature)
        }
    }

    $result
}

def map-kind-kernel-feature [kind: string] {
    let matches = ($MAP_KIND_KERNEL_FEATURES | where {|entry| $entry.kind == $kind })
    if ($matches | is-empty) {
        null
    } else {
        $matches | first | get feature
    }
}

def outside-simple-string? [text: string] {
    let double_parts = ($text | split row "\"")
    let single_parts = ($text | split row "'")
    (($double_parts | length) mod 2) == 1 and (($single_parts | length) mod 2) == 1
}

def line-contains-outside-simple-string? [line: string marker: string] {
    let parts = ($line | split row $marker)
    if ($parts | length) <= 1 {
        return false
    }

    for part in ($parts | enumerate) {
        if $part.index == 0 {
            continue
        }

        let before = ($parts | first $part.index | str join $marker)
        if (outside-simple-string? $before) {
            return true
        }
    }

    false
}

def marker-tails-outside-simple-string [line: string marker: string] {
    let trimmed = ($line | str trim)
    if $trimmed == "" or ($trimmed | str starts-with "#") {
        return []
    }
    if not ($trimmed | str contains $marker) {
        return []
    }

    let parts = ($trimmed | split row $marker)
    if ($parts | length) <= 1 {
        return []
    }

    mut tails = []
    for part in ($parts | enumerate) {
        if $part.index == 0 {
            continue
        }

        let before = ($parts | first $part.index | str join $marker)
        if (outside-simple-string? $before) and not (line-contains-outside-simple-string? $before "#") {
            $tails = ($tails | append $part.item)
        }
    }

    $tails
}

def line-contains-code-marker? [line: string marker: string] {
    not ((marker-tails-outside-simple-string $line $marker) | is-empty)
}

def command-tail-after-token [raw_after: string] {
    if $raw_after == "" {
        return ""
    }
    if ($raw_after | str starts-with " ") {
        return ($raw_after | str substring 1..)
    }
    for delimiter in [")" "}" "]" ";"] {
        if ($raw_after | str starts-with $delimiter) {
            return ""
        }
    }

    null
}

def command-invocation-tails [line: string command: string] {
    let trimmed = ($line | str trim)
    if $trimmed == "" or ($trimmed | str starts-with "#") {
        return []
    }
    if not ($trimmed | str contains $command) {
        return []
    }

    mut tails = []
    let command_len = ($command | str length)
    if ($trimmed | str starts-with $command) {
        let tail = (command-tail-after-token ($trimmed | str substring $command_len..))
        if $tail != null {
            $tails = ($tails | append $tail)
        }
    }

    for prefix in ["| " "; " "{ " "( " "("] {
        let marker = $"($prefix)($command)"
        let parts = ($trimmed | split row $marker)
        if ($parts | length) <= 1 {
            continue
        }

        for part in ($parts | enumerate) {
            if $part.index == 0 {
                continue
            }

            let before = ($parts | first $part.index | str join $marker)
            if not (outside-simple-string? $before) {
                continue
            }
            if (line-contains-outside-simple-string? $before "#") {
                continue
            }

            let tail = (command-tail-after-token $part.item)
            if $tail != null {
                $tails = ($tails | append $tail)
            }
        }
    }

    $tails
}

def line-invokes-command? [line: string command: string] {
    not ((command-invocation-tails $line $command) | is-empty)
}

def line-invokes-command-with-tail-prefix? [line: string command: string tail_prefix: string] {
    for tail in (command-invocation-tails $line $command) {
        if ($tail | str trim | str starts-with $tail_prefix) {
            return true
        }
    }

    false
}

def source-invokes-command? [source: string command: string] {
    if not ($source | str contains $command) {
        return false
    }

    for line in ($source | lines) {
        if (line-invokes-command? $line $command) {
            return true
        }
    }

    false
}

def source-invokes-command-with-tail-prefix? [source: string command: string tail_prefix: string] {
    if not ($source | str contains $command) {
        return false
    }

    for line in ($source | lines) {
        if (line-invokes-command-with-tail-prefix? $line $command $tail_prefix) {
            return true
        }
    }

    false
}

def source-line-helper-call-name [line: string] {
    let tails = (command-invocation-tails $line "helper-call")
    if ($tails | is-empty) {
        return null
    }

    let raw_helper = (($tails | first) | str trim | split row " " | first)
    normalize-helper-name-token $raw_helper
}

def helper-call-map-kind-entry [line: string] {
    let helper_name = (source-line-helper-call-name $line)
    if $helper_name == null {
        return null
    }

    let fixed_matches = ($HELPER_CALL_FIXED_MAP_KIND_FEATURES | where {|entry| $entry.helper == $helper_name })
    if not ($fixed_matches | is-empty) {
        return ($fixed_matches | first)
    }

    let explicit_matches = ($HELPER_CALL_EXPLICIT_MAP_KIND_FEATURES | where {|entry| $entry.helper == $helper_name })
    if not ($explicit_matches | is-empty) {
        return ($explicit_matches | first)
    }

    null
}

def source-line-helper-call-map-name [line: string entry] {
    let tails = (command-invocation-tails $line "helper-call")
    if ($tails | is-empty) {
        return null
    }

    let tokens = (
        ($tails | first)
        | str trim
        | split row " "
        | each {|token| $token | str trim }
        | where {|token| $token != "" }
    )
    let arg_idx = (($entry | get map_arg) + 1)
    if $arg_idx >= ($tokens | length) {
        return null
    }

    let name = (normalize-map-name-token ($tokens | get $arg_idx))
    if $name == "" or ($name | str starts-with "$") {
        null
    } else {
        $name
    }
}

def helper-call-effective-map-kind [line: string bindings] {
    let entry = (helper-call-map-kind-entry $line)
    if $entry == null {
        return null
    }

    let fixed_kind = ($entry | get -o kind)
    if $fixed_kind != null and $fixed_kind != "" {
        return $fixed_kind
    }

    let supported_kinds = ($entry | get -o kinds | default [])
    let explicit_kind = (source-line-map-kind $line "")
    if $explicit_kind != "" {
        if $explicit_kind in $supported_kinds {
            return $explicit_kind
        }
        return null
    }

    let map_name = (source-line-helper-call-map-name $line $entry)
    let inferred_kind = (map-kind-binding $bindings $map_name)
    if $inferred_kind != null and ($inferred_kind in $supported_kinds) {
        return $inferred_kind
    }

    null
}

def helper-call-map-kind-kernel-feature [line: string bindings] {
    let kind = (helper-call-effective-map-kind $line $bindings)
    if $kind == null or $kind == "" {
        return null
    }

    map-kind-kernel-feature $kind
}

def source-line-map-kind [line: string default_kind: string] {
    for raw_tail in (marker-tails-outside-simple-string $line "--kind ") {
        let raw_kind = ($raw_tail | str trim | split row " " | first)
        return (normalize-map-kind-token $raw_kind)
    }

    $default_kind
}

def source-line-command-map-name [line: string command: string] {
    let tails = (command-invocation-tails $line $command)
    if ($tails | is-empty) {
        return null
    }

    let raw_name = (($tails | first) | str trim | split row " " | first)
    let name = (normalize-map-name-token $raw_name)
    if $name == "" or ($name | str starts-with "$") {
        null
    } else {
        $name
    }
}

def source-line-map-kind-surface [line: string] {
    for command in [
        "map-define"
        "map-get"
        "map-put"
        "map-delete"
        "map-contains"
        "map-push"
        "map-peek"
        "map-pop"
        "redirect-map"
        "redirect-socket"
    ] {
        if (line-invokes-command? $line $command) {
            return {
                command: $command
                name: (source-line-command-map-name $line $command)
            }
        }
    }

    null
}

def map-command-default-kind [command: string] {
    if $command in ["map-define" "map-get" "map-put" "map-delete" "map-contains"] {
        "hash"
    } else {
        ""
    }
}

def map-kind-binding [bindings name] {
    if $name == null or $name == "" {
        return null
    }

    let matches = ($bindings | where {|entry| $entry.name == $name })
    if ($matches | is-empty) {
        null
    } else {
        $matches | first | get kind
    }
}

def bind-map-kind [bindings name kind] {
    if $name == null or $name == "" or $kind == null or $kind == "" {
        return $bindings
    }

    $bindings
    | where {|entry| $entry.name != $name }
    | append { name: $name kind: $kind }
}

def source-line-effective-map-kind [line: string bindings] {
    let surface = (source-line-map-kind-surface $line)
    if $surface == null {
        return null
    }

    let explicit_kind = (source-line-map-kind $line "")
    if $explicit_kind != "" {
        return $explicit_kind
    }

    let name = ($surface | get name)
    if $name == null {
        return null
    }

    let inferred_kind = (map-kind-binding $bindings $name)
    if $inferred_kind != null {
        return $inferred_kind
    }

    let default_kind = (map-command-default-kind ($surface | get command))
    if $default_kind == "" {
        null
    } else {
        $default_kind
    }
}

def update-map-kind-bindings-for-line [bindings line: string] {
    let surface = (source-line-map-kind-surface $line)
    if $surface == null {
        return $bindings
    }

    let name = ($surface | get name)
    if $name == null {
        return $bindings
    }

    let kind = (source-line-effective-map-kind $line $bindings)
    bind-map-kind $bindings $name $kind
}

def update-helper-call-map-kind-bindings-for-line [bindings line: string] {
    let entry = (helper-call-map-kind-entry $line)
    if $entry == null {
        return $bindings
    }

    let name = (source-line-helper-call-map-name $line $entry)
    let kind = (helper-call-effective-map-kind $line $bindings)
    bind-map-kind $bindings $name $kind
}

def line-invokes-map-kind-surface? [line: string] {
    for command in [
        "map-define"
        "map-get"
        "map-put"
        "map-delete"
        "map-contains"
        "map-push"
        "map-peek"
        "map-pop"
        "redirect-map"
        "redirect-socket"
    ] {
        if (line-invokes-command? $line $command) {
            return true
        }
    }

    false
}

def generic-map-lookup-kind? [kind: string] {
    $kind in [
        "hash"
        "array"
        "lpm-trie"
        "lru-hash"
        "per-cpu-hash"
        "per-cpu-array"
        "lru-per-cpu-hash"
    ]
}

def generic-map-update-kind? [kind: string] {
    $kind in [
        "hash"
        "array"
        "lpm-trie"
        "lru-hash"
        "per-cpu-hash"
        "per-cpu-array"
        "lru-per-cpu-hash"
    ]
}

def generic-map-delete-kind? [kind: string] {
    $kind in [
        "hash"
        "lpm-trie"
        "lru-hash"
        "per-cpu-hash"
        "lru-per-cpu-hash"
    ]
}

def local-storage-get-helper-kernel-feature [kind: string] {
    if $kind == "sk-storage" {
        return $KERNEL_FEATURE_BPF_SK_STORAGE_GET
    }
    if $kind == "inode-storage" {
        return $KERNEL_FEATURE_BPF_INODE_STORAGE_GET
    }
    if $kind == "task-storage" {
        return $KERNEL_FEATURE_BPF_TASK_STORAGE_GET
    }
    if $kind == "cgrp-storage" {
        return $KERNEL_FEATURE_BPF_CGRP_STORAGE_GET
    }

    null
}

def local-storage-delete-helper-kernel-feature [kind: string] {
    if $kind == "sk-storage" {
        return $KERNEL_FEATURE_BPF_SK_STORAGE_DELETE
    }
    if $kind == "inode-storage" {
        return $KERNEL_FEATURE_BPF_INODE_STORAGE_DELETE
    }
    if $kind == "task-storage" {
        return $KERNEL_FEATURE_BPF_TASK_STORAGE_DELETE
    }
    if $kind == "cgrp-storage" {
        return $KERNEL_FEATURE_BPF_CGRP_STORAGE_DELETE
    }

    null
}

def helper-kernel-feature [name: string] {
    let matches = ($HELPER_KERNEL_FEATURES | where {|entry| $entry.name == $name })
    if not ($matches | is-empty) {
        return ($matches | first | get feature)
    }

    let helper_ids = ($BPF_HELPER_IDS | where {|entry| $entry.name == $name })
    if ($helper_ids | is-empty) {
        return null
    }

    let helper_id = ($helper_ids | first | get id)
    let floors = ($BPF_HELPER_KERNEL_FLOORS_BY_MAX_ID | where {|floor| $helper_id <= $floor.max_id })
    if ($floors | is-empty) {
        return null
    }

    let floor = ($floors | first)
    let min_kernel = ($floor | get min_kernel)
    {
        key: $"helper:($name)"
        min_kernel: $min_kernel
        source: $"https://github.com/torvalds/linux/blob/v($min_kernel)/include/uapi/linux/bpf.h"
    }
}

def kfunc-kernel-feature [name: string] {
    let matches = ($KFUNC_KERNEL_FEATURES | where {|entry| $entry.name == $name })
    if not ($matches | is-empty) {
        return ($matches | first | get feature)
    }

    let fallback = ($KFUNC_KERNEL_FEATURE_FALLBACKS | where {|entry| $entry.name == $name })
    if ($fallback | is-empty) {
        return null
    }

    let entry = ($fallback | first)
    mut feature = {
        key: $"kfunc:($name)"
        min_kernel: ($entry | get min_kernel)
        source: ($entry | get source)
    }

    let max_kernel = ($entry | get -o max_kernel_exclusive)
    if $max_kernel != null and $max_kernel != "" {
        $feature = ($feature | insert max_kernel_exclusive $max_kernel)
        let max_kernel_source = ($entry | get -o max_kernel_exclusive_source)
        if $max_kernel_source != null and $max_kernel_source != "" {
            $feature = ($feature | insert max_kernel_exclusive_source $max_kernel_source)
        }
    }

    $feature
}

def target-uses-bpf-tracing-prog-type [target] {
    let target_text = ($target | default "")
    [
        ($target_text | str starts-with "fentry:")
        ($target_text | str starts-with "fentry.s:")
        ($target_text | str starts-with "fexit:")
        ($target_text | str starts-with "fexit.s:")
        ($target_text | str starts-with "fmod_ret:")
        ($target_text | str starts-with "fmod_ret.s:")
        ($target_text | str starts-with "tp_btf:")
    ] | any {|matches| $matches }
}

def program-kfunc-kernel-feature [name: string target] {
    if $name == "bpf_dynptr_from_skb" and (target-uses-bpf-tracing-prog-type $target) {
        return {
            key: "kfunc:bpf_dynptr_from_skb"
            min_kernel: "6.12"
            source: "https://github.com/torvalds/linux/blob/v6.12/net/core/filter.c"
        }
    }

    kfunc-kernel-feature $name
}

def sock-ops-context-field-kernel-feature [field: string] {
    if $field in ["op" "reply" "replylong"] {
        return {
            key: $"ctx:($field)"
            min_kernel: "4.14"
            source: "https://github.com/torvalds/linux/blob/v4.14/include/uapi/linux/bpf.h"
        }
    }

    if $field in [
        "args"
        "is_fullsock"
        "snd_cwnd"
        "srtt_us"
        "cb_flags"
        "state"
        "rtt_min"
        "snd_ssthresh"
        "rcv_nxt"
        "snd_nxt"
        "snd_una"
        "mss_cache"
        "ecn_flags"
        "rate_delivered"
        "rate_interval_us"
        "packets_out"
        "retrans_out"
        "total_retrans"
        "segs_in"
        "data_segs_in"
        "segs_out"
        "data_segs_out"
        "lost_out"
        "sacked_out"
        "sk_txhash"
        "bytes_received"
        "bytes_acked"
    ] {
        return {
            key: $"ctx:($field)"
            min_kernel: "4.16"
            source: "https://github.com/torvalds/linux/blob/v4.16/include/uapi/linux/bpf.h"
        }
    }

    if $field in ["sk" "sock" "socket"] {
        return {
            key: "ctx:sk"
            min_kernel: "5.3"
            source: "https://github.com/torvalds/linux/blob/v5.3/include/uapi/linux/bpf.h"
        }
    }

    null
}

def target-context-field-alias-kernel-feature [field: string target] {
    let target_text = ($target | default "")

    if $field == "retval" {
        if (
            ($target_text | str starts-with "kretprobe:")
            or ($target_text | str starts-with "kretprobe.multi:")
            or ($target_text | str starts-with "kretsyscall:")
            or ($target_text | str starts-with "uretprobe:")
            or ($target_text | str starts-with "uretprobe.s:")
            or ($target_text | str starts-with "uretprobe.multi:")
            or ($target_text | str starts-with "uretprobe.multi.s:")
        ) {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_RETVAL_PT_REGS }
        }
        if (
            ($target_text | str starts-with "fexit:")
            or ($target_text | str starts-with "fexit.s:")
            or ($target_text | str starts-with "fmod_ret:")
            or ($target_text | str starts-with "fmod_ret.s:")
        ) {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_RETVAL_TRAMPOLINE }
        }
    }

    if ($target_text | str starts-with "xdp:") {
        if $field == "packet_len" or $field == "len" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_XDP_PACKET_LEN }
        }
        if $field == "data" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_XDP_DATA }
        }
        if $field == "data_end" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_XDP_DATA_END }
        }
        if $field == "ingress_ifindex" or $field == "ifindex" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_XDP_INGRESS_IFINDEX }
        }
        if $field == "rx_queue_index" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_XDP_RX_QUEUE_INDEX }
        }
    }
    if ($target_text | str starts-with "sk_msg:") {
        if $field == "data" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_MSG_DATA }
        }
        if $field == "data_end" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_MSG_DATA_END }
        }
        if $field == "family" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_MSG_FAMILY }
        }
        if $field == "remote_ip4" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_MSG_REMOTE_IP4 }
        }
        if $field == "remote_ip6" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_MSG_REMOTE_IP6 }
        }
        if $field == "remote_port" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_MSG_REMOTE_PORT }
        }
        if $field == "local_ip4" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_MSG_LOCAL_IP4 }
        }
        if $field == "local_ip6" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_MSG_LOCAL_IP6 }
        }
        if $field == "local_port" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_MSG_LOCAL_PORT }
        }
        if $field == "size" or $field == "packet_len" or $field == "len" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_MSG_PACKET_LEN }
        }
        if $field in ["sk" "sock" "socket"] {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_MSG_SK }
        }
    }
    if (
        ($target_text | str starts-with "sk_skb:")
        or ($target_text | str starts-with "sk_skb_parser:")
    ) and ($field in ["sk" "sock" "socket"]) {
        return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_SKB_SK }
    }
    if (
        ($target_text | str starts-with "socket_filter:")
        or ($target_text | str starts-with "tc_action:")
        or ($target_text | str starts-with "tc:")
        or ($target_text | str starts-with "tcx:")
        or ($target_text | str starts-with "netkit:")
        or ($target_text | str starts-with "cgroup_skb:")
    ) and ($field in ["sk" "sock" "socket"]) {
        return { matched: true, feature: $KERNEL_FEATURE_CTX_SKB_SK }
    }
    if ($target_text | str starts-with "sk_reuseport:") {
        if $field == "packet_len" or $field == "len" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_PACKET_LEN }
        }
        if $field == "data" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_DATA }
        }
        if $field == "data_end" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_DATA_END }
        }
        if $field == "eth_protocol" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_ETH_PROTOCOL }
        }
        if $field == "protocol" or $field == "ip_protocol" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_PROTOCOL }
        }
        if $field == "bind_inany" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_BIND_INANY }
        }
        if $field == "hash" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_HASH }
        }
        if $field in ["sk" "sock" "socket"] {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_SK }
        }
        if $field == "migrating_sk" or $field == "migrating_socket" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_MIGRATING_SK }
        }
    }
    if ($target_text | str starts-with "sock_ops:") {
        let sock_ops_feature = (sock-ops-context-field-kernel-feature $field)
        if $sock_ops_feature != null {
            return { matched: true, feature: $sock_ops_feature }
        }
        if $field == "packet_len" or $field == "len" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SOCK_OPS_PACKET_LEN }
        }
        if $field == "data" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SOCK_OPS_DATA }
        }
        if $field == "data_end" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SOCK_OPS_DATA_END }
        }
    }
    if ($target_text | str starts-with "netfilter:") {
        if $field == "state" or $field == "nf_state" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_NETFILTER_STATE }
        }
        if $field == "skb" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_NETFILTER_SKB }
        }
        if $field == "hook" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_NETFILTER_HOOK }
        }
        if $field == "pf" or $field == "protocol_family" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_NETFILTER_PROTOCOL_FAMILY }
        }
    }
    if ($target_text | str starts-with "lirc_mode2:") {
        if $field == "sample" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_LIRC_SAMPLE }
        }
        if $field == "value" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_LIRC_VALUE }
        }
        if $field == "mode" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_LIRC_MODE }
        }
    }
    if ($target_text | str starts-with "perf_event:") {
        if $field == "sample_period" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_PERF_SAMPLE_PERIOD }
        }
        if $field == "addr" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_PERF_ADDR }
        }
    }
    if ($target_text | str starts-with "cgroup_device:") {
        if $field == "access_type" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_DEVICE_ACCESS_TYPE }
        }
        if $field == "device_access" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_DEVICE_ACCESS }
        }
        if $field == "device_type" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_DEVICE_TYPE }
        }
        if $field == "major" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_DEVICE_MAJOR }
        }
        if $field == "minor" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_DEVICE_MINOR }
        }
    }
    if ($target_text | str starts-with "cgroup_sysctl:") {
        if $field == "name" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SYSCTL_NAME }
        }
        if $field == "base_name" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SYSCTL_BASE_NAME }
        }
        if $field == "current_value" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SYSCTL_CURRENT_VALUE }
        }
        if $field == "new_value" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SYSCTL_NEW_VALUE }
        }
        if $field == "write" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SYSCTL_WRITE }
        }
        if $field == "file_pos" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SYSCTL_FILE_POS }
        }
    }
    if ($target_text | str starts-with "cgroup_sockopt:") {
        if $field in ["sk" "sock" "socket"] {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCKOPT_SK }
        }
        if $field == "level" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SOCKOPT_LEVEL }
        }
        if $field == "optname" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SOCKOPT_OPTNAME }
        }
        if $field == "optlen" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SOCKOPT_OPTLEN }
        }
        if $field == "optval" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SOCKOPT_OPTVAL }
        }
        if $field == "optval_end" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SOCKOPT_OPTVAL_END }
        }
        if $field == "retval" or $field == "sockopt_retval" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SOCKOPT_RETVAL }
        }
    }
    if ($target_text | str starts-with "cgroup_sock:") {
        if $field in ["sk" "sock" "socket"] {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_SK }
        }
        if $field == "bound_dev_if" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_BOUND_DEV_IF }
        }
        if $field == "family" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_FAMILY }
        }
        if $field == "sock_type" or $field == "type" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_SOCK_TYPE }
        }
        if $field == "protocol" or $field == "ip_protocol" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_PROTOCOL }
        }
        if $field == "mark" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_MARK }
        }
        if $field == "priority" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_PRIORITY }
        }
        if $field == "local_ip4" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_LOCAL_IP4 }
        }
        if $field == "local_ip6" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_LOCAL_IP6 }
        }
        if $field == "local_port" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_LOCAL_PORT }
        }
        if $field == "remote_ip4" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_REMOTE_IP4 }
        }
        if $field == "remote_ip6" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_REMOTE_IP6 }
        }
        if $field == "remote_port" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_REMOTE_PORT }
        }
        if $field == "state" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_STATE }
        }
        if $field == "rx_queue_mapping" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_RX_QUEUE_MAPPING }
        }
    }
    if ($target_text | str starts-with "sk_lookup:") {
        if $field in ["sk" "sock" "socket"] {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_SK }
        }
        if $field == "family" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_FAMILY }
        }
        if $field == "protocol" or $field == "ip_protocol" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_PROTOCOL }
        }
        if $field == "remote_ip4" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_REMOTE_IP4 }
        }
        if $field == "remote_ip6" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_REMOTE_IP6 }
        }
        if $field == "remote_port" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_REMOTE_PORT }
        }
        if $field == "local_ip4" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_LOCAL_IP4 }
        }
        if $field == "local_ip6" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_LOCAL_IP6 }
        }
        if $field == "local_port" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_LOCAL_PORT }
        }
        if $field == "cookie" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_COOKIE }
        }
        if $field == "ingress_ifindex" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_INGRESS_IFINDEX }
        }
    }
    if ($target_text | str starts-with "cgroup_sock_addr:") {
        if $field in ["sk" "sock" "socket"] {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_SK }
        }
        if $field == "family" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_FAMILY }
        }
        if $field == "sock_type" or $field == "type" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_SOCK_TYPE }
        }
        if $field == "protocol" or $field == "ip_protocol" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_PROTOCOL }
        }
        if $field == "user_family" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_USER_FAMILY }
        }
        if $field == "user_ip4" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_USER_IP4 }
        }
        if $field == "user_ip6" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_USER_IP6 }
        }
        if $field == "user_port" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_USER_PORT }
        }
        if $field == "remote_ip4" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_REMOTE_IP4 }
        }
        if $field == "remote_ip6" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_REMOTE_IP6 }
        }
        if $field == "remote_port" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_REMOTE_PORT }
        }
        if $field == "local_ip4" {
            if ($target_text | str ends-with ":sendmsg4") {
                return {
                    matched: true
                    feature: {
                        key: "ctx:local_ip4"
                        min_kernel: ($KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_MSG_SRC_IP4 | get min_kernel)
                        source: ($KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_MSG_SRC_IP4 | get source)
                    }
                }
            }
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_LOCAL_IP4 }
        }
        if $field == "local_ip6" {
            if ($target_text | str ends-with ":sendmsg6") {
                return {
                    matched: true
                    feature: {
                        key: "ctx:local_ip6"
                        min_kernel: ($KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_MSG_SRC_IP6 | get min_kernel)
                        source: ($KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_MSG_SRC_IP6 | get source)
                    }
                }
            }
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_LOCAL_IP6 }
        }
        if $field == "local_port" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_LOCAL_PORT }
        }
        if $field == "msg_src_ip4" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_MSG_SRC_IP4 }
        }
        if $field == "msg_src_ip6" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_MSG_SRC_IP6 }
        }
    }

    if ($target_text | str starts-with "iter:") {
        let iter_target = ($target_text | split row ":" | get 1)

        if $field == "meta" or $field == "iter_meta" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_META }
        }
        if $field == "task" or $field == "iter_task" {
            if $iter_target == "task_vma" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_TASK_VMA_TASK }
            }
            if $iter_target in ["task" "task_file"] {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_TASK }
            }
        }
        if ($field == "fd" or $field == "iter_fd") and $iter_target == "task_file" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_FD }
        }
        if ($field == "file" or $field == "iter_file") and $iter_target == "task_file" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_FILE }
        }
        if ($field == "vma" or $field == "iter_vma") and $iter_target == "task_vma" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_VMA }
        }
        if ($field == "cgroup" or $field == "iter_cgroup") and $iter_target == "cgroup" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_CGROUP }
        }
        if $field == "map" or $field == "iter_map" {
            if $iter_target == "bpf_map" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_MAP }
            }
            if $iter_target == "bpf_map_elem" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_MAP_ELEM_MAP }
            }
            if $iter_target == "bpf_sk_storage_map" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_SK_STORAGE_MAP }
            }
            if $iter_target == "sockmap" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_SOCKMAP_MAP }
            }
        }
        if $field == "key" or $field == "iter_key" {
            if $iter_target == "bpf_map_elem" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_MAP_KEY }
            }
            if $iter_target == "sockmap" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_SOCKMAP_KEY }
            }
        }
        if $field == "value" or $field == "iter_value" {
            if $iter_target == "bpf_map_elem" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_MAP_VALUE }
            }
            if $iter_target == "bpf_sk_storage_map" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_SK_STORAGE_VALUE }
            }
        }
        if $field == "sk" or $field == "sock" or $field == "iter_sock" {
            if $iter_target == "bpf_sk_storage_map" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_SK_STORAGE_SOCK }
            }
            if $iter_target == "sockmap" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_SOCKMAP_SOCK }
            }
        }
        if ($field == "prog" or $field == "iter_prog") and $iter_target == "bpf_prog" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_PROG }
        }
        if ($field == "link" or $field == "iter_link") and $iter_target == "bpf_link" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_LINK }
        }
        if ($field == "sk_common" or $field == "sock_common" or $field == "iter_sk_common") and $iter_target == "tcp" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_TCP_SK_COMMON }
        }
        if ($field == "udp_sk" or $field == "iter_udp_sk") and $iter_target == "udp" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_UDP_SK }
        }
        if ($field == "unix_sk" or $field == "iter_unix_sk") and $iter_target == "unix" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_UNIX_SK }
        }
        if $field == "uid" or $field == "iter_uid" {
            if $iter_target == "tcp" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_TCP_UID }
            }
            if $iter_target == "udp" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_UDP_UID }
            }
            if $iter_target == "unix" {
                return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_UNIX_UID }
            }
        }
        if ($field == "bucket" or $field == "iter_bucket") and $iter_target == "udp" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_UDP_BUCKET }
        }
        if ($field == "rt" or $field == "route" or $field == "ipv6_route" or $field == "iter_ipv6_route") and $iter_target == "ipv6_route" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_IPV6_ROUTE }
        }
        if ($field == "ksym" or $field == "iter_ksym") and $iter_target == "ksym" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_KSYM }
        }
        if ($field == "netlink_sk" or $field == "iter_netlink_sk") and $iter_target == "netlink" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_NETLINK_SK }
        }
        if ($field == "cache" or $field == "kmem_cache" or $field == "iter_kmem_cache") and $iter_target == "kmem_cache" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_KMEM_CACHE }
        }
        if ($field == "dmabuf" or $field == "iter_dmabuf") and $iter_target == "dmabuf" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_ITER_DMABUF }
        }
    }

    { matched: false, feature: null }
}

def context-field-kernel-feature [field: string target] {
    let target_text = ($target | default "")
    if ($target_text | str starts-with "tracepoint:") and not (tracepoint-built-in-context-field? $field) {
        return null
    }

    let target_alias = (target-context-field-alias-kernel-feature $field $target)
    if $target_alias.matched {
        return $target_alias.feature
    }

    let matches = ($CONTEXT_FIELD_KERNEL_FEATURES | where {|entry| $entry.field == $field })
    if ($matches | is-empty) {
        null
    } else {
        $matches | first | get feature
    }
}

def syscall-tracepoint-fallback-field-kernel-feature [field: string target] {
    let target_text = ($target | default "")
    if not ($target_text | str starts-with "tracepoint:syscalls/") {
        return null
    }

    let name = ($target_text | str replace "tracepoint:syscalls/" "")
    let syscall = if ($name | str starts-with "sys_enter_") {
        if $field not-in ["id" "args"] {
            return null
        }
        $name | str replace "sys_enter_" ""
    } else if ($name | str starts-with "sys_exit_") {
        if $field not-in ["id" "ret"] {
            return null
        }
        $name | str replace "sys_exit_" ""
    } else {
        return null
    }

    let min_kernel = if $syscall == "openat2" {
        "5.6"
    } else if $syscall == "faccessat2" {
        "5.8"
    } else if $syscall == "fchmodat2" {
        "6.6"
    } else if $syscall == "close_range" {
        "5.9"
    } else if $syscall == "epoll_pwait2" {
        "5.11"
    } else if $syscall in ["open_tree" "move_mount" "fsmount" "fsopen" "fsconfig" "fspick"] {
        "5.2"
    } else if $syscall == "mount_setattr" {
        "5.12"
    } else if $syscall in ["statmount" "listmount"] {
        "6.8"
    } else if $syscall == "open_tree_attr" {
        "6.15"
    } else if $syscall == "quotactl_fd" {
        "5.14"
    } else if $syscall == "pidfd_send_signal" {
        "5.1"
    } else if $syscall == "pidfd_open" {
        "5.3"
    } else if $syscall == "pidfd_getfd" {
        "5.6"
    } else if $syscall in ["landlock_create_ruleset" "landlock_add_rule" "landlock_restrict_self"] {
        "5.13"
    } else if $syscall in ["lsm_get_self_attr" "lsm_set_self_attr" "lsm_list_modules"] {
        "6.8"
    } else if $syscall in ["setxattrat" "getxattrat" "listxattrat" "removexattrat"] {
        "6.13"
    } else if $syscall == "futex_waitv" {
        "5.16"
    } else if $syscall in ["futex_wake" "futex_wait" "futex_requeue"] {
        "6.7"
    } else if $syscall == "arch_prctl" {
        "5.0"
    } else if $syscall == "map_shadow_stack" {
        "6.6"
    } else if $syscall == "uretprobe" {
        "6.14"
    } else if $syscall == "cachestat" {
        "6.5"
    } else if $syscall == "mseal" {
        "6.10"
    } else if $syscall in ["file_getattr" "file_setattr"] {
        "6.17"
    } else if $syscall == "clone3" {
        "5.3"
    } else if $syscall in ["pkey_mprotect" "pkey_alloc" "pkey_free"] {
        "4.9"
    } else if $syscall in ["io_uring_setup" "io_uring_enter" "io_uring_register"] {
        "5.1"
    } else if $syscall == "io_pgetevents" {
        "4.18"
    } else if $syscall == "memfd_secret" {
        "5.14"
    } else if $syscall == "process_madvise" {
        "5.10"
    } else if $syscall == "process_mrelease" {
        "5.15"
    } else if $syscall == "set_mempolicy_home_node" {
        "5.17"
    } else if $syscall == "rseq" {
        "4.18"
    } else if $syscall == "statx" {
        "4.11"
    } else {
        "4.7"
    }
    let source = if $syscall == "openat2" {
        "https://github.com/torvalds/linux/blob/v5.6/fs/open.c"
    } else if $syscall == "faccessat2" {
        "https://github.com/torvalds/linux/blob/v5.8/fs/open.c"
    } else if $syscall == "fchmodat2" {
        "https://github.com/torvalds/linux/blob/v6.6/fs/open.c"
    } else if $syscall == "close_range" {
        "https://github.com/torvalds/linux/blob/v5.9/fs/open.c"
    } else if $syscall == "epoll_pwait2" {
        "https://github.com/torvalds/linux/blob/v5.11/fs/eventpoll.c"
    } else if $syscall in ["open_tree" "move_mount" "fsmount"] {
        "https://github.com/torvalds/linux/blob/v5.2/fs/namespace.c"
    } else if $syscall in ["fsopen" "fsconfig" "fspick"] {
        "https://github.com/torvalds/linux/blob/v5.2/fs/fsopen.c"
    } else if $syscall == "mount_setattr" {
        "https://github.com/torvalds/linux/blob/v5.12/fs/namespace.c"
    } else if $syscall in ["statmount" "listmount"] {
        "https://github.com/torvalds/linux/blob/v6.8/fs/namespace.c"
    } else if $syscall == "open_tree_attr" {
        "https://github.com/torvalds/linux/blob/v6.15/fs/namespace.c"
    } else if $syscall in ["mount" "umount" "pivot_root"] {
        "https://github.com/torvalds/linux/blob/v4.7/fs/namespace.c"
    } else if $syscall == "quotactl" {
        "https://github.com/torvalds/linux/blob/v4.7/fs/quota/quota.c"
    } else if $syscall == "quotactl_fd" {
        "https://github.com/torvalds/linux/blob/v5.14/fs/quota/quota.c"
    } else if $syscall == "ustat" {
        "https://github.com/torvalds/linux/blob/v4.7/fs/statfs.c"
    } else if $syscall == "pidfd_send_signal" {
        "https://github.com/torvalds/linux/blob/v5.1/kernel/signal.c"
    } else if $syscall == "pidfd_open" {
        "https://github.com/torvalds/linux/blob/v5.3/kernel/pid.c"
    } else if $syscall == "pidfd_getfd" {
        "https://github.com/torvalds/linux/blob/v5.6/kernel/pid.c"
    } else if $syscall in ["landlock_create_ruleset" "landlock_add_rule" "landlock_restrict_self"] {
        "https://github.com/torvalds/linux/blob/v5.13/security/landlock/syscalls.c"
    } else if $syscall in ["lsm_get_self_attr" "lsm_set_self_attr" "lsm_list_modules"] {
        "https://github.com/torvalds/linux/blob/v6.8/security/lsm_syscalls.c"
    } else if $syscall in ["setxattrat" "getxattrat" "listxattrat" "removexattrat"] {
        "https://github.com/torvalds/linux/blob/v6.13/fs/xattr.c"
    } else if $syscall == "futex_waitv" {
        "https://github.com/torvalds/linux/blob/v5.16/kernel/futex/syscalls.c"
    } else if $syscall in ["futex_wake" "futex_wait" "futex_requeue"] {
        "https://github.com/torvalds/linux/blob/v6.7/kernel/futex/syscalls.c"
    } else if $syscall == "arch_prctl" {
        "https://github.com/torvalds/linux/blob/v5.0/arch/x86/kernel/process_64.c"
    } else if $syscall in ["ioperm" "iopl"] {
        "https://github.com/torvalds/linux/blob/v4.7/arch/x86/kernel/ioport.c"
    } else if $syscall == "modify_ldt" {
        "https://github.com/torvalds/linux/blob/v4.7/arch/x86/kernel/ldt.c"
    } else if $syscall == "rt_sigreturn" {
        "https://github.com/torvalds/linux/blob/v4.7/arch/x86/kernel/signal.c"
    } else if $syscall == "map_shadow_stack" {
        "https://github.com/torvalds/linux/blob/v6.6/arch/x86/kernel/shstk.c"
    } else if $syscall == "uretprobe" {
        "https://github.com/torvalds/linux/blob/v6.14/arch/x86/kernel/uprobes.c"
    } else if $syscall == "kcmp" {
        "https://github.com/torvalds/linux/blob/v4.7/kernel/kcmp.c"
    } else if $syscall == "cachestat" {
        "https://github.com/torvalds/linux/blob/v6.5/mm/filemap.c"
    } else if $syscall == "mseal" {
        "https://github.com/torvalds/linux/blob/v6.10/mm/mseal.c"
    } else if $syscall in ["file_getattr" "file_setattr"] {
        "https://github.com/torvalds/linux/blob/v6.17/fs/file_attr.c"
    } else if $syscall == "clone3" {
        "https://github.com/torvalds/linux/blob/v5.3/kernel/fork.c"
    } else if $syscall in ["fork" "vfork" "clone" "set_tid_address"] {
        "https://github.com/torvalds/linux/blob/v4.7/kernel/fork.c"
    } else if $syscall == "personality" {
        "https://github.com/torvalds/linux/blob/v4.7/kernel/exec_domain.c"
    } else if $syscall == "vhangup" {
        "https://github.com/torvalds/linux/blob/v4.7/fs/open.c"
    } else if $syscall == "alarm" {
        "https://github.com/torvalds/linux/blob/v4.7/kernel/time/timer.c"
    } else if $syscall in ["pause" "restart_syscall"] {
        "https://github.com/torvalds/linux/blob/v4.7/kernel/signal.c"
    } else if $syscall == "syslog" {
        "https://github.com/torvalds/linux/blob/v4.7/kernel/printk/printk.c"
    } else if $syscall == "sysfs" {
        "https://github.com/torvalds/linux/blob/v4.7/fs/filesystems.c"
    } else if $syscall in ["pkey_mprotect" "pkey_alloc" "pkey_free"] {
        "https://github.com/torvalds/linux/blob/v4.9/mm/mprotect.c"
    } else if $syscall in ["io_uring_setup" "io_uring_enter" "io_uring_register"] {
        "https://github.com/torvalds/linux/blob/v5.1/fs/io_uring.c"
    } else if $syscall == "io_pgetevents" {
        "https://github.com/torvalds/linux/blob/v4.18/fs/aio.c"
    } else if $syscall == "memfd_secret" {
        "https://github.com/torvalds/linux/blob/v5.14/mm/secretmem.c"
    } else if $syscall == "process_madvise" {
        "https://github.com/torvalds/linux/blob/v5.10/mm/madvise.c"
    } else if $syscall == "process_mrelease" {
        "https://github.com/torvalds/linux/blob/v5.15/mm/oom_kill.c"
    } else if $syscall == "set_mempolicy_home_node" {
        "https://github.com/torvalds/linux/blob/v5.17/mm/mempolicy.c"
    } else if $syscall == "rseq" {
        "https://github.com/torvalds/linux/blob/v4.18/kernel/rseq.c"
    } else if $syscall == "statx" {
        "https://github.com/torvalds/linux/blob/v4.11/fs/stat.c"
    } else {
        "https://github.com/torvalds/linux/blob/v4.7/include/trace/events/syscalls.h"
    }

    {
        key: $"tracepoint:syscalls/($name):field:($field)"
        min_kernel: $min_kernel
        source: $source
    }
}

def source-backed-sys-enter-tracepoint-field-kernel-feature [field: string target specs] {
    let target_text = ($target | default "")
    if not ($target_text | str starts-with "tracepoint:syscalls/sys_enter_") {
        return null
    }

    let syscall = ($target_text | str replace "tracepoint:syscalls/sys_enter_" "")
    let matches = (
        $specs
        | where {|entry| $syscall in $entry.syscalls and $field in $entry.fields }
    )
    if ($matches | is-empty) {
        return null
    }

    let spec = ($matches | first)
    {
        key: $"tracepoint:syscalls/sys_enter_($syscall):field:($field)"
        min_kernel: $spec.min_kernel
        source: $spec.source
    }
}

def tracepoint-payload-field-kernel-feature [field: string target] {
    let target_text = ($target | default "")
    if not ($target_text | str starts-with "tracepoint:") {
        return null
    }
    if (tracepoint-built-in-context-field? $field) {
        return null
    }

    let fallback = (syscall-tracepoint-fallback-field-kernel-feature $field $target)
    if $fallback != null {
        return $fallback
    }

    let source_backed_syscall_specs = (
        $FILE_TRACEPOINT_FIELD_SPECS
        | append $FILE_DATA_TRACEPOINT_FIELD_SPECS
        | append $SOCKET_TRACEPOINT_FIELD_SPECS
        | append $PATH_TRACEPOINT_FIELD_SPECS
        | append $QUOTA_TRACEPOINT_FIELD_SPECS
        | append $PROCESS_TRACEPOINT_FIELD_SPECS
        | append $FD_TRACEPOINT_FIELD_SPECS
        | append $MM_TRACEPOINT_FIELD_SPECS
        | append $TIME_TRACEPOINT_FIELD_SPECS
        | append $IO_URING_TRACEPOINT_FIELD_SPECS
        | append $AIO_TRACEPOINT_FIELD_SPECS
        | append $IOPRIO_TRACEPOINT_FIELD_SPECS
        | append $KEY_TRACEPOINT_FIELD_SPECS
        | append $SIGNAL_TRACEPOINT_FIELD_SPECS
        | append $LANDLOCK_TRACEPOINT_FIELD_SPECS
        | append $LSM_SYSCALL_TRACEPOINT_FIELD_SPECS
        | append $IDENTITY_TRACEPOINT_FIELD_SPECS
        | append $SCHED_TRACEPOINT_FIELD_SPECS
        | append $FUTEX_TRACEPOINT_FIELD_SPECS
        | append $MQUEUE_TRACEPOINT_FIELD_SPECS
        | append $IPC_TRACEPOINT_FIELD_SPECS
        | append $X86_TRACEPOINT_FIELD_SPECS
    )
    let source_backed_feature = (
        source-backed-sys-enter-tracepoint-field-kernel-feature $field $target $source_backed_syscall_specs
    )
    if $source_backed_feature != null {
        return $source_backed_feature
    }

    let matches = (
        $TRACEPOINT_FIELD_KERNEL_FEATURES
        | where {|entry| $entry.target == $target_text and $entry.field == $field }
    )
    if ($matches | is-empty) {
        null
    } else {
        $matches | first | get feature
    }
}

def context-field-helper-kernel-feature [field: string target] {
    let target_text = ($target | default "")

    if ($target_text | str starts-with "tracepoint:") and not (tracepoint-built-in-context-field? $field) {
        return null
    }
    if $field in ["pid" "tid" "tgid" "pid_tgid" "current_pid_tgid"] {
        return $KERNEL_FEATURE_BPF_GET_CURRENT_PID_TGID
    }
    if $field == "current_task" {
        return $KERNEL_FEATURE_BPF_GET_CURRENT_TASK_BTF
    }
    if $field == "task" and not ($target_text | str starts-with "iter:") {
        return $KERNEL_FEATURE_BPF_GET_CURRENT_TASK_BTF
    }
    if $field == "current_cgroup" {
        return $KERNEL_FEATURE_BPF_GET_CURRENT_TASK_BTF
    }
    if $field == "cgroup" and not ($target_text | str starts-with "iter:") {
        return $KERNEL_FEATURE_BPF_GET_CURRENT_TASK_BTF
    }
    if $field in ["uid" "gid" "uid_gid" "current_uid_gid"] {
        return $KERNEL_FEATURE_BPF_GET_CURRENT_UID_GID
    }
    if $field == "comm" {
        return $KERNEL_FEATURE_BPF_GET_CURRENT_COMM
    }
    if $field in ["cpu" "processor_id" "smp_processor_id"] {
        return $KERNEL_FEATURE_BPF_GET_SMP_PROCESSOR_ID
    }
    if $field in ["numa_node" "numa_node_id"] {
        return $KERNEL_FEATURE_BPF_GET_NUMA_NODE_ID
    }
    if $field in ["random" "prandom_u32"] {
        return $KERNEL_FEATURE_BPF_GET_PRANDOM_U32
    }
    if $field == "cgroup_classid" {
        return $KERNEL_FEATURE_BPF_GET_CGROUP_CLASSID
    }
    if $field == "route_realm" {
        return $KERNEL_FEATURE_BPF_GET_ROUTE_REALM
    }
    if $field == "csum_level" {
        return $KERNEL_FEATURE_BPF_CSUM_LEVEL
    }
    if $field in ["hash_recalc" "recalc_hash"] {
        return $KERNEL_FEATURE_BPF_GET_HASH_RECALC
    }
    if $field == "cgroup_id" {
        return $KERNEL_FEATURE_BPF_GET_CURRENT_CGROUP_ID
    }
    if $field == "ancestor_cgroup_id" {
        return $KERNEL_FEATURE_BPF_GET_CURRENT_ANCESTOR_CGROUP_ID
    }
    if $field == "skb_cgroup_id" {
        return $KERNEL_FEATURE_BPF_SKB_CGROUP_ID
    }
    if $field == "skb_ancestor_cgroup_id" {
        return $KERNEL_FEATURE_BPF_SKB_ANCESTOR_CGROUP_ID
    }
    if $field == "socket_cookie" {
        return $KERNEL_FEATURE_BPF_GET_SOCKET_COOKIE
    }
    if $field == "socket_uid" {
        return $KERNEL_FEATURE_BPF_GET_SOCKET_UID
    }
    if $field == "netns_cookie" {
        return $KERNEL_FEATURE_BPF_GET_NETNS_COOKIE
    }
    if $field == "ktime" or $field == "timestamp" {
        return $KERNEL_FEATURE_BPF_KTIME_GET_NS
    }
    if $field in ["ktime_boot" "boot_ktime" "boot_time"] {
        return $KERNEL_FEATURE_BPF_KTIME_GET_BOOT_NS
    }
    if $field in ["ktime_coarse" "coarse_ktime" "coarse_time"] {
        return $KERNEL_FEATURE_BPF_KTIME_GET_COARSE_NS
    }
    if $field in ["ktime_tai" "tai_ktime" "tai_time"] {
        return $KERNEL_FEATURE_BPF_KTIME_GET_TAI_NS
    }
    if $field == "jiffies" {
        return $KERNEL_FEATURE_BPF_JIFFIES64
    }
    if $field in ["func_ip" "function_ip"] {
        return $KERNEL_FEATURE_BPF_GET_FUNC_IP
    }
    if $field in ["attach_cookie" "bpf_cookie"] {
        return $KERNEL_FEATURE_BPF_GET_ATTACH_COOKIE
    }
    if $field in ["perf_counter" "perf_enabled" "perf_running"] {
        return $KERNEL_FEATURE_BPF_PERF_PROG_READ_VALUE
    }
    if $field in ["xdp_buff_len" "xdp_buffer_len"] {
        return $KERNEL_FEATURE_BPF_XDP_GET_BUFF_LEN
    }
    if ($target_text | str starts-with "cgroup_sysctl:") {
        if $field in ["sysctl_name" "name" "sysctl_base_name" "base_name"] {
            return $KERNEL_FEATURE_BPF_SYSCTL_GET_NAME
        }
        if $field in ["sysctl_current_value" "current_value"] {
            return $KERNEL_FEATURE_BPF_SYSCTL_GET_CURRENT_VALUE
        }
        if $field in ["sysctl_new_value" "new_value"] {
            return $KERNEL_FEATURE_BPF_SYSCTL_GET_NEW_VALUE
        }
    }
    if $field == "arg_count" {
        return $KERNEL_FEATURE_BPF_GET_FUNC_ARG_CNT
    }
    if $field in ["kstack" "ustack"] {
        return $KERNEL_FEATURE_BPF_GET_STACKID
    }

    null
}

def iter-target-kernel-feature [target: string] {
    let matches = ($ITER_TARGET_KERNEL_FEATURES | where {|entry| $entry.target == $target })
    if ($matches | is-empty) {
        null
    } else {
        $matches | first | get feature
    }
}

def normalize-map-kind-token [token: string] {
    $token
    | str trim
    | str replace --all ")" ""
    | str replace --all "," ""
    | str replace --all "\"" ""
    | str replace --all "'" ""
}

def normalize-map-name-token [token: string] {
    $token
    | str trim
    | str replace --all ")" ""
    | str replace --all "(" ""
    | str replace --all "," ""
    | str replace --all "\"" ""
    | str replace --all "'" ""
    | str replace --all "}" ""
    | str replace --all "]" ""
    | str replace --all ";" ""
}

def normalize-helper-name-token [token: string] {
    $token
    | str trim
    | str replace --all ")" ""
    | str replace --all "," ""
    | str replace --all "\"" ""
    | str replace --all "'" ""
}

def normalize-kfunc-name-token [token: string] {
    normalize-helper-name-token $token
}

def normalize-context-field-token [token: string] {
    $token
    | str trim
    | split row " "
    | first
    | split row "."
    | first
    | str replace --all ")" ""
    | str replace --all "(" ""
    | str replace --all "," ""
    | str replace --all "\"" ""
    | str replace --all "'" ""
    | str replace --all "}" ""
    | str replace --all "]" ""
    | str replace --all ";" ""
}

def normalize-context-path-token [token: string] {
    $token
    | str trim
    | split row " "
    | first
    | str replace --all ")" ""
    | str replace --all "(" ""
    | str replace --all "," ""
    | str replace --all "\"" ""
    | str replace --all "'" ""
    | str replace --all "}" ""
    | str replace --all "]" ""
    | str replace --all ";" ""
}

def context-field-access-is-assignment-lhs? [raw_access: string field: string] {
    let compact = ($raw_access | str trim | str replace --all " " "")
    if not ($compact | str contains "=") {
        return false
    }
    let parts = ($compact | split row "=")
    if ($parts | length) < 2 {
        return false
    }

    let rhs_after_first_equals = ($parts | skip 1 | first)
    if $rhs_after_first_equals == "" {
        return false
    }

    let lhs = ($parts | first)

    ($lhs == $field) or ($lhs | str starts-with $"($field).")
}

def line-assigns-context-field? [line: string context_names fields] {
    let trimmed = ($line | str trim)
    for context_name in $context_names {
        for field in $fields {
            let marker = $"$($context_name).($field)"
            for raw_tail in (marker-tails-outside-simple-string $trimmed $marker) {
                let tail = ($raw_tail | str trim)
                if not ($tail | str starts-with "=") {
                    continue
                }
                if ($tail | str starts-with "==") {
                    continue
                }

                let rhs = ($tail | str substring 1.. | str trim)
                if $rhs != "" {
                    return true
                }
            }
        }
    }

    false
}

def line-assigns-record-context-field? [line: string aliases fields roots] {
    let trimmed = ($line | str trim)
    for alias in $aliases {
        let root = ($alias | get -o root | default "")
        if $root not-in $roots {
            continue
        }

        for field in $fields {
            let marker = $"$($alias.name).($alias.field).($field)"
            for raw_tail in (marker-tails-outside-simple-string $trimmed $marker) {
                let tail = ($raw_tail | str trim)
                if not ($tail | str starts-with "=") {
                    continue
                }
                if ($tail | str starts-with "==") {
                    continue
                }

                let rhs = ($tail | str substring 1.. | str trim)
                if $rhs != "" {
                    return true
                }
            }
        }
    }

    false
}

def iter-btf-context-projection-root? [root: string] {
    $root in [
        "meta"
        "iter_meta"
        "task"
        "iter_task"
        "file"
        "iter_file"
        "vma"
        "iter_vma"
        "cgroup"
        "iter_cgroup"
        "map"
        "iter_map"
        "prog"
        "iter_prog"
        "link"
        "iter_link"
        "sk_common"
        "sock_common"
        "iter_sk_common"
        "udp_sk"
        "iter_udp_sk"
        "unix_sk"
        "iter_unix_sk"
        "rt"
        "route"
        "ipv6_route"
        "iter_ipv6_route"
        "cache"
        "kmem_cache"
        "iter_kmem_cache"
        "ksym"
        "iter_ksym"
        "netlink_sk"
        "iter_netlink_sk"
        "dmabuf"
        "iter_dmabuf"
        "sk"
        "sock"
        "socket"
        "iter_sock"
    ]
}

def iter-trusted-btf-context-projection-root? [root: string] {
    $root in [
        "meta"
        "iter_meta"
    ]
}

def context-projection-root? [root: string] {
    if (iter-btf-context-projection-root? $root) {
        return true
    }

    $root in [
        "sk"
        "sock"
        "socket"
        "migrating_sk"
        "migrating_socket"
        "arg"
        "arg0"
        "arg1"
        "arg2"
        "arg3"
        "arg4"
        "arg5"
        "retval"
        "task"
        "current_task"
        "cgroup"
        "current_cgroup"
        "state"
        "nf_state"
        "skb"
        "flow_keys"
    ]
}

def target-uses-btf-context-args? [target] {
    let target_text = ($target | default "")

    [
        "fentry:"
        "fentry.s:"
        "fexit:"
        "fexit.s:"
        "fmod_ret:"
        "fmod_ret.s:"
        "tp_btf:"
        "lsm:"
        "lsm.s:"
        "lsm_cgroup:"
        "struct_ops:"
    ] | any {|prefix| $target_text | str starts-with $prefix }
}

def target-uses-trusted-btf-context-args? [target] {
    let target_text = ($target | default "")

    [
        "fentry:"
        "fentry.s:"
        "fexit:"
        "fexit.s:"
        "fmod_ret:"
        "fmod_ret.s:"
        "lsm:"
        "lsm.s:"
        "lsm_cgroup:"
        "struct_ops:"
    ] | any {|prefix| $target_text | str starts-with $prefix }
}

def context-projection-parts [token: string] {
    let cleaned = (
        $token
        | str trim
        | split row " "
        | first
        | str replace --all ")" ""
        | str replace --all "(" ""
        | str replace --all "," ""
        | str replace --all "\"" ""
        | str replace --all "'" ""
        | str replace --all "}" ""
        | str replace --all "]" ""
        | str replace --all ";" ""
    )
    let parts = ($cleaned | split row ".")
    if ($parts | length) < 2 {
        return []
    }

    let root = ($parts | first)
    if not (context-projection-root? $root) {
        return []
    }

    $parts
}

def tracepoint-built-in-context-field? [field: string] {
    $field in [
        "pid"
        "tid"
        "tgid"
        "pid_tgid"
        "current_pid_tgid"
        "uid"
        "gid"
        "uid_gid"
        "current_uid_gid"
        "comm"
        "current_task"
        "current_cgroup"
        "cpu"
        "numa_node"
        "numa_node_id"
        "random"
        "prandom_u32"
        "ktime"
        "timestamp"
        "ktime_boot"
        "boot_ktime"
        "boot_time"
        "ktime_coarse"
        "coarse_ktime"
        "coarse_time"
        "ktime_tai"
        "tai_ktime"
        "tai_time"
        "jiffies"
        "func_ip"
        "function_ip"
        "attach_cookie"
        "bpf_cookie"
        "cgroup_id"
        "kstack"
        "ustack"
    ]
}

def bpf-sock-projection-context-field [member: string] {
    if $member == "bound_dev_if" {
        return "bound_dev_if"
    }
    if $member == "family" {
        return "family"
    }
    if $member == "type" or $member == "sock_type" {
        return "sock_type"
    }
    if $member == "protocol" or $member == "ip_protocol" {
        return "protocol"
    }
    if $member == "mark" {
        return "mark"
    }
    if $member == "priority" {
        return "priority"
    }
    if $member == "src_ip4" or $member == "local_ip4" {
        return "local_ip4"
    }
    if $member == "src_ip6" or $member == "local_ip6" {
        return "local_ip6"
    }
    if $member == "src_port" or $member == "local_port" {
        return "local_port"
    }
    if $member == "dst_ip4" or $member == "remote_ip4" {
        return "remote_ip4"
    }
    if $member == "dst_ip6" or $member == "remote_ip6" {
        return "remote_ip6"
    }
    if $member == "dst_port" or $member == "remote_port" {
        return "remote_port"
    }
    if $member == "state" {
        return "state"
    }
    if $member == "rx_queue_mapping" {
        return "rx_queue_mapping"
    }

    null
}

def context-projection-kernel-feature [raw_access: string target] {
    let parts = (context-projection-parts $raw_access)
    if ($parts | length) < 2 {
        return null
    }
    let root = ($parts | first)
    let member = ($parts | get 1)
    let target_text = ($target | default "")
    let socket_projection_root = (
        ($root in ["sk" "sock" "socket" "migrating_sk" "migrating_socket"])
        and not ($target_text | str starts-with "iter:")
    )

    if $socket_projection_root and $member == "cgroup_id" {
        return $KERNEL_FEATURE_BPF_SK_CGROUP_ID
    }
    if $socket_projection_root and $member == "ancestor_cgroup_id" {
        return $KERNEL_FEATURE_BPF_SK_ANCESTOR_CGROUP_ID
    }
    if $socket_projection_root and ($member in ["tcp" "tcp_sock"]) {
        return $KERNEL_FEATURE_BPF_TCP_SOCK
    }
    if $socket_projection_root and ($member in ["full" "fullsock" "full_sock"]) {
        return $KERNEL_FEATURE_BPF_SK_FULLSOCK
    }
    if $socket_projection_root and $member == "listener" {
        return $KERNEL_FEATURE_BPF_GET_LISTENER_SOCK
    }
    if $root == "flow_keys" {
        return (context-field-kernel-feature "flow_keys" $target)
    }
    if not $socket_projection_root {
        return null
    }

    let field = (bpf-sock-projection-context-field $member)
    if $field == null {
        return null
    }

    let feature = (context-field-kernel-feature $field $target)
    if $feature != null {
        return $feature
    }
    if $field == "rx_queue_mapping" {
        return $KERNEL_FEATURE_CTX_BPF_SOCK_RX_QUEUE_MAPPING
    }

    null
}

def trusted-btf-projection-kernel-read? [parts target] {
    if ($parts | length) < 2 {
        return false
    }

    let target_text = ($target | default "")
    let root = ($parts | first)
    let first_member = ($parts | get 1)

    if ($target_text | str starts-with "iter:") and (iter-trusted-btf-context-projection-root? $root) {
        return true
    }
    if $root in ["current_task" "current_cgroup"] {
        return true
    }
    if $root in ["task" "cgroup"] {
        if ($target_text | str starts-with "tracepoint:") {
            return false
        }
        if $root == "task" and $first_member == "pt_regs" {
            return false
        }
        return true
    }
    if ($target_text | str starts-with "netfilter:") and ($root in ["state" "nf_state" "skb"]) {
        return true
    }
    if (target-uses-trusted-btf-context-args? $target_text) {
        if $root == "arg" and ($parts | length) >= 3 {
            return true
        }
        if ($root in ["arg0" "arg1" "arg2" "arg3" "arg4" "arg5" "retval"]) and ($parts | length) >= 2 {
            return true
        }
    }

    false
}

def btf-context-arg-projection? [parts target] {
    if ($parts | length) < 2 {
        return false
    }

    let target_text = ($target | default "")
    if not (target-uses-btf-context-args? $target_text) {
        return false
    }

    let root = ($parts | first)
    if $root == "arg" and ($parts | length) >= 3 {
        return true
    }
    if ($root in ["arg0" "arg1" "arg2" "arg3" "arg4" "arg5" "retval"]) and ($parts | length) >= 2 {
        return true
    }

    false
}

def context-projection-kernel-read-feature [raw_access: string target] {
    let parts = (context-projection-parts $raw_access)
    if ($parts | length) < 2 {
        return null
    }

    let root = ($parts | first)
    let member = ($parts | get 1)
    let target_text = ($target | default "")
    if (bpf-sock-projection-context-field $member) != null {
        return $KERNEL_FEATURE_BPF_PROBE_READ_KERNEL
    }
    let helper_backed_socket_projection = (
        ($parts | length) >= 3
        and ($member in ["tcp" "tcp_sock" "full" "fullsock" "full_sock" "listener"])
    )
    if $helper_backed_socket_projection {
        return $KERNEL_FEATURE_BPF_PROBE_READ_KERNEL
    }
    if (
        ($target_text | str starts-with "iter:")
        and (iter-btf-context-projection-root? $root)
        and not (iter-trusted-btf-context-projection-root? $root)
    ) {
        return $KERNEL_FEATURE_BPF_PROBE_READ_KERNEL
    }
    if (trusted-btf-projection-kernel-read? $parts $target) {
        # Trusted kernel-BTF scalar projections lower as direct loads. Aggregate
        # projections that still need a helper should declare that explicitly.
        return null
    }
    if (btf-context-arg-projection? $parts $target) {
        return $KERNEL_FEATURE_BPF_PROBE_READ_KERNEL
    }

    null
}

def context-task-pt-regs-kernel-feature [raw_access: string] {
    let cleaned = (
        $raw_access
        | str trim
        | split row " "
        | first
        | str replace --all ")" ""
        | str replace --all "(" ""
        | str replace --all "," ""
        | str replace --all "\"" ""
        | str replace --all "'" ""
        | str replace --all "}" ""
        | str replace --all "]" ""
        | str replace --all ";" ""
    )
    let parts = ($cleaned | split row ".")
    if ($parts | length) < 3 {
        return null
    }

    let root = ($parts | first)
    if $root not-in ["task" "current_task"] {
        return null
    }
    if ($parts | get 1) != "pt_regs" {
        return null
    }
    if ($parts | get 2) not-in ["arg0" "arg1" "arg2" "arg3" "arg4" "arg5" "retval"] {
        return null
    }

    $KERNEL_FEATURE_BPF_TASK_PT_REGS
}

def append-unique-name [names name: string] {
    if $name == "" or $name in $names {
        $names
    } else {
        $names | append $name
    }
}

def trim-simple-parentheses [text: string] {
    mut value = ($text | str trim)

    loop {
        if ($value | str length) < 2 {
            break
        }
        if not (($value | str starts-with "(") and ($value | str ends-with ")")) {
            break
        }

        $value = ($value | str substring 1..-2 | str trim)
    }

    $value
}

def split-pipeline-segments [raw: string] {
    let text = (trim-simple-parentheses ($raw | str trim))
    mut segments = []
    mut current = ""
    mut paren_depth = 0
    mut brace_depth = 0
    mut bracket_depth = 0
    mut in_single = false
    mut in_double = false

    for ch in ($text | split chars) {
        if ($ch == "'" and (not $in_double)) {
            $in_single = not $in_single
            $current = $"($current)($ch)"
            continue
        }
        if ($ch == '"' and (not $in_single)) {
            $in_double = not $in_double
            $current = $"($current)($ch)"
            continue
        }

        if (
            $ch == "|"
            and (not $in_single)
            and (not $in_double)
            and $paren_depth == 0
            and $brace_depth == 0
            and $bracket_depth == 0
        ) {
            $segments = ($segments | append ($current | str trim))
            $current = ""
            continue
        }

        if (not $in_single) and (not $in_double) {
            if $ch == "(" {
                $paren_depth = $paren_depth + 1
            } else if $ch == ")" {
                if $paren_depth > 0 {
                    $paren_depth = $paren_depth - 1
                }
            } else if $ch == "{" {
                $brace_depth = $brace_depth + 1
            } else if $ch == "}" {
                if $brace_depth > 0 {
                    $brace_depth = $brace_depth - 1
                }
            } else if $ch == "[" {
                $bracket_depth = $bracket_depth + 1
            } else if $ch == "]" {
                if $bracket_depth > 0 {
                    $bracket_depth = $bracket_depth - 1
                }
            }
        }

        $current = $"($current)($ch)"
    }

    $segments | append ($current | str trim)
}

def declaration-binding-name [raw_name: string] {
    $raw_name
    | str trim
    | split row ":"
    | first
    | str trim
    | split row " "
    | first
    | str trim
}

def declaration-assignment-from-body [body: string] {
    let assignment_parts = ($body | split row "=")
    if ($assignment_parts | length) < 2 {
        return null
    }

    let name = (declaration-binding-name ($assignment_parts | first))
    if $name == "" {
        return null
    }

    {
        name: $name
        rhs: ($assignment_parts | skip 1 | str join "=" | str trim)
    }
}

def declaration-assignments [line: string] {
    let trimmed = ($line | str trim)
    mut assignments = []

    for command in ["let" "mut"] {
        for tail in (command-invocation-tails $trimmed $command) {
            let assignment = (declaration-assignment-from-body ($tail | str trim))
            if $assignment != null {
                $assignments = ($assignments | append $assignment)
            }
        }
    }

    $assignments
}

def declaration-assignment [line: string] {
    declaration-assignments $line | first
}

def declaration-rhs-token [assignment] {
    trim-simple-parentheses (($assignment.rhs | split row ";" | first) | str trim)
}

def two-token-invocation [raw: string] {
    let tokens = (
        $raw
        | split row " "
        | each {|part| $part | str trim }
        | where {|part| $part != "" }
    )
    if ($tokens | length) < 2 {
        return null
    }

    {
        callee: ($tokens | get 0)
        arg: (trim-simple-parentheses ($tokens | skip 1 | str join " "))
    }
}

def context-variable-binding [line: string context_names identity_wrappers] {
    for assignment in (declaration-assignments $line) {
        let rhs = (declaration-rhs-token $assignment)
        for context_name in $context_names {
            if $rhs == $"$($context_name)" {
                return $assignment.name
            }
        }

        let invocation = (two-token-invocation $rhs)
        if $invocation != null {
            if $invocation.callee in $identity_wrappers {
                for context_name in $context_names {
                    if $invocation.arg == $"$($context_name)" {
                        return $assignment.name
                    }
                }
            }
        }
    }

    null
}

def source-may-bind-derived-context-variable? [source: string] {
    (
        ($source | str contains "def ")
        or ($source | str contains " get ")
        or ($source | str contains "| get")
        or (($source | str contains "= $") and ($source | str contains "."))
        or (($source | str contains "= ($") and ($source | str contains "."))
    )
}

def program-context-variable-names [source: string] {
    mut names = ["ctx"]
    mut found_closure = false
    let identity_wrappers = (identity-wrapper-definitions $source)

    for line in ($source | lines) {
        if $found_closure {
            continue
        }

        let parts = ($line | split row "{|")
        if ($parts | length) <= 1 {
            continue
        }

        let raw_closure = ($parts | skip 1 | first)
        let closure_parts = ($raw_closure | split row "|")
        if ($closure_parts | length) == 0 {
            continue
        }

        let raw_params = ($closure_parts | first)
        for raw_param in ($raw_params | split row ",") {
            let name = (
                $raw_param
                | str trim
                | split row ":"
                | first
                | str trim
                | split row " "
                | first
                | str trim
            )
            $names = (append-unique-name $names $name)
        }
        $found_closure = true
    }

    for line in ($source | lines) {
        let binding = (context-variable-binding $line $names $identity_wrappers)
        if $binding != null {
            $names = (append-unique-name $names $binding)
        }
    }

    if (source-may-bind-derived-context-variable? $source) {
        for alias in (program-bound-context-root-aliases $source $names) {
            if (($alias | get -o root | default "") == "") {
                $names = (append-unique-name $names $alias.name)
            }
        }
    }

    $names
}

def context-root-from-wrapper-invocation [invocation context_names bound_aliases identity_wrappers root_wrapper_defs] {
    for wrapper in ($root_wrapper_defs | where {|wrapper| $wrapper.name == $invocation.callee }) {
        let root = (context-root-from-argument-token $invocation.arg $context_names $bound_aliases $identity_wrappers)
        if $root == null {
            continue
        }

        return (combine-context-roots $root ($wrapper | get -o root | default ""))
    }

    null
}

def context-root-from-multi-param-wrapper-invocation [raw_value: string context_names bound_aliases identity_wrappers wrapper_defs] {
    let trimmed = (trim-simple-parentheses ($raw_value | str trim))
    let callee = (
        $trimmed
        | split row " "
        | first
        | str trim
    )
    if $callee == "" {
        return null
    }

    let tail = (
        $trimmed
        | str substring ($callee | str length)..
        | str trim
    )
    let args = (command-tail-positional-args $tail)
    for wrapper in ($wrapper_defs | where {|wrapper| $wrapper.name == $callee }) {
        let arg = ($args | get -o $wrapper.param_index)
        if $arg == null {
            continue
        }

        let root = (context-root-from-argument-token $arg $context_names $bound_aliases $identity_wrappers)
        if $root == null {
            continue
        }

        return (combine-context-roots $root ($wrapper | get -o root | default ""))
    }

    null
}

def context-root-binding [line: string context_names bound_aliases identity_wrappers root_wrapper_defs multi_param_root_wrapper_defs] {
    for assignment in (declaration-assignments $line) {
        let rhs = (declaration-rhs-token $assignment)
        let direct_root = (context-root-from-value-token $rhs $context_names $bound_aliases)
        if $direct_root != null and $direct_root != "" {
            return { name: $assignment.name root: $direct_root }
        }

        let get_root = (context-root-from-get-pipeline $rhs $context_names $bound_aliases)
        if $get_root != null and $get_root != "" {
            return { name: $assignment.name root: $get_root }
        }

        let invocation = (two-token-invocation $rhs)
        if $invocation != null {
            if $invocation.callee in $identity_wrappers {
                let root_path = (
                    context-root-from-record-value-token
                        $invocation.arg
                        $context_names
                        $bound_aliases
                        $identity_wrappers
                        $root_wrapper_defs
                )
                if $root_path != null and $root_path != "" {
                    return { name: $assignment.name root: $root_path }
                }
            }

            let wrapper_root = (
                context-root-from-wrapper-invocation
                    $invocation
                    $context_names
                    $bound_aliases
                    $identity_wrappers
                    $root_wrapper_defs
            )
            if $wrapper_root != null {
                return { name: $assignment.name root: $wrapper_root }
            }
        }

        let multi_param_wrapper_root = (
            context-root-from-multi-param-wrapper-invocation
                $rhs
                $context_names
                $bound_aliases
                $identity_wrappers
                $multi_param_root_wrapper_defs
        )
        if $multi_param_wrapper_root != null {
            return { name: $assignment.name root: $multi_param_wrapper_root }
        }

        for context_name in $context_names {
            let prefix = $"$($context_name)."
            if not ($rhs | str starts-with $prefix) {
                continue
            }

            let root_path = (normalize-context-path-token ($rhs | str substring ($prefix | str length)..))
            let root = ($root_path | split row "." | first)
            if (context-projection-root? $root) {
                return { name: $assignment.name root: $root_path }
            }
        }
    }

    null
}

def context-root-record-extraction-binding [line: string record_aliases record_wrapper_defs context_names bound_aliases identity_wrappers root_wrapper_defs] {
    for assignment in (declaration-assignments $line) {
        let rhs = (declaration-rhs-token $assignment)

        for parsed in (
            $rhs
            | parse --regex '^\$(?P<record>[A-Za-z_][A-Za-z0-9_-]*)\.(?P<field>[A-Za-z_][A-Za-z0-9_-]*)$'
        ) {
            for alias in (
                $record_aliases
                | where {|alias| $alias.name == $parsed.record and $alias.field == $parsed.field }
            ) {
                return {
                    name: $assignment.name
                    root: ($alias | get -o root | default "")
                }
            }
        }

        let segments = (split-pipeline-segments $rhs)
        if ($segments | length) < 2 {
            continue
        }
        let input = (($segments | first) | str trim)
        mut roots = []
        mut prefix_segments = []

        for segment in ($segments | skip 1) {
            let parsed = (get-command-field-tail $segment)
            if $parsed == null {
                if ($roots | is-empty) {
                    $prefix_segments = ($prefix_segments | append ($segment | str trim))
                }
                continue
            }

            mut root = (
                context-root-from-record-get
                    $input
                    $parsed.field
                    $record_aliases
                    $record_wrapper_defs
                    $context_names
                    $bound_aliases
                    $identity_wrappers
                    $root_wrapper_defs
            )
            if $root == null {
                $root = (
                    context-root-from-record-pipeline-get
                        $input
                        $prefix_segments
                        $parsed.field
                        $record_aliases
                        $context_names
                        $bound_aliases
                        $identity_wrappers
                        $root_wrapper_defs
                )
            }
            if $root == null {
                continue
            }

            $roots = ($roots | append $root)
        }

        if ($roots | length) == 1 {
            return {
                name: $assignment.name
                root: ($roots | first)
            }
        }
    }

    null
}

def context-root-from-record-get [input: string get_field: string record_aliases record_wrapper_defs context_names bound_aliases identity_wrappers root_wrapper_defs] {
    let field_name = (normalize-context-path-token $get_field)
    if $field_name == "" {
        return null
    }
    let normalized_input = (trim-simple-parentheses ($input | str trim))
    let variable_input = (
        $normalized_input
        | str replace --all "(" ""
        | str replace --all ")" ""
        | str trim
    )

    for parsed in (
        $variable_input
        | parse --regex '^\$(?P<record>[A-Za-z_][A-Za-z0-9_-]*)$'
    ) {
        for alias in (
            $record_aliases
            | where {|alias| $alias.name == $parsed.record and $alias.field == $field_name }
        ) {
            return ($alias | get -o root | default "")
        }
    }

    let invocation = (two-token-invocation $normalized_input)
    if $invocation != null {
        for wrapper in (
            $record_wrapper_defs
            | where {|wrapper| $wrapper.name == $invocation.callee and $wrapper.field == $field_name }
        ) {
            let root = (
                context-root-from-record-wrapper-invocation
                    $invocation
                    $wrapper
                    $context_names
                    $bound_aliases
                    $identity_wrappers
            )
            if $root == null {
                continue
            }
            return (combine-context-roots $root ($wrapper | get -o root | default ""))
        }
    }

    for field in (
        record-literal-context-fields
            $normalized_input
            $context_names
            $bound_aliases
            $identity_wrappers
            $root_wrapper_defs
    ) {
        if $field.field == $field_name {
            return ($field | get -o root | default "")
        }
    }

    for field in (record-literal-spread-context-fields $normalized_input $record_aliases) {
        if $field.field == $field_name {
            return ($field | get -o root | default "")
        }
    }

    null
}

def context-root-from-record-pipeline-get [input: string prefix_segments get_field: string record_aliases context_names bound_aliases identity_wrappers root_wrapper_defs] {
    if ($prefix_segments | is-empty) {
        return null
    }

    let raw = (
        [$input]
        | append $prefix_segments
        | str join " | "
    )
    let field_name = (normalize-context-path-token $get_field)
    for field in (
        record-pipeline-flow-context-fields
            $raw
            $context_names
            $bound_aliases
            $identity_wrappers
            $root_wrapper_defs
            $record_aliases
    ) {
        if $field.field == $field_name {
            return ($field | get -o root | default "")
        }
    }

    null
}

def program-bound-context-root-aliases-base [source: string context_names] {
    mut aliases = []
    let identity_wrappers = (identity-wrapper-definitions $source)
    let root_wrapper_defs = (context-root-wrapper-definitions $source)
    let multi_param_root_wrapper_defs = (multi-param-context-root-wrapper-definitions $source)

    for line in ($source | lines) {
        let binding = (
            context-root-binding
                $line
                $context_names
                $aliases
                $identity_wrappers
                $root_wrapper_defs
                $multi_param_root_wrapper_defs
        )
        if $binding == null {
            continue
        }

        let existing = ($aliases | where {|alias| $alias.name == $binding.name })
        if ($existing | is-empty) {
            $aliases = ($aliases | append $binding)
        } else {
            $aliases = (
                $aliases
                | each {|alias|
                    if $alias.name == $binding.name { $binding } else { $alias }
                }
            )
        }
    }

    $aliases
}

def program-bound-context-root-aliases [source: string context_names] {
    mut aliases = (program-bound-context-root-aliases-base $source $context_names)
    let identity_wrappers = (identity-wrapper-definitions $source)
    let root_wrapper_defs = (context-root-wrapper-definitions $source)
    let record_aliases = (program-record-context-aliases $source $context_names)
    let record_wrapper_defs = (
        record-wrapper-definitions $source
        | append (record-context-wrapper-definitions $source)
        | append (multi-param-record-wrapper-definitions $source)
    )
    mut changed = true

    loop {
        if not $changed {
            break
        }
        $changed = false

        for line in ($source | lines) {
            let binding = (
                context-root-record-extraction-binding
                    $line
                    $record_aliases
                    $record_wrapper_defs
                    $context_names
                    $aliases
                    $identity_wrappers
                    $root_wrapper_defs
            )
            if $binding == null {
                continue
            }

            let existing = ($aliases | where {|alias| $alias.name == $binding.name })
            if ($existing | is-empty) {
                $aliases = ($aliases | append $binding)
                $changed = true
            } else {
                let current = ($existing | first)
                if (($current | get -o root | default "") != ($binding | get -o root | default "")) {
                    $aliases = (
                        $aliases
                        | each {|alias|
                            if $alias.name == $binding.name { $binding } else { $alias }
                        }
                    )
                    $changed = true
                }
            }
        }
    }

    $aliases
}

def context-root-from-record-value-token [raw_value: string context_names bound_aliases identity_wrappers root_wrapper_defs] {
    let direct_root = (context-root-from-value-token $raw_value $context_names $bound_aliases)
    if $direct_root != null {
        return $direct_root
    }

    let get_root = (context-root-from-get-pipeline $raw_value $context_names $bound_aliases)
    if $get_root != null {
        return $get_root
    }

    let invocation = (two-token-invocation (trim-simple-parentheses ($raw_value | str trim)))
    if $invocation != null and $invocation.callee in $identity_wrappers {
        let root = (context-root-from-get-pipeline $invocation.arg $context_names $bound_aliases)
        if $root != null {
            return $root
        }

        return (context-root-from-value-token $invocation.arg $context_names $bound_aliases)
    }
    if $invocation != null {
        return (
            context-root-from-wrapper-invocation
                $invocation
                $context_names
                $bound_aliases
                $identity_wrappers
                $root_wrapper_defs
        )
    }

    null
}

def record-literal-context-fields [raw: string context_names bound_aliases identity_wrappers root_wrapper_defs] {
    let trimmed = ($raw | str trim)
    if not (($trimmed | str starts-with "{") and ($trimmed | str ends-with "}")) {
        return []
    }

    let inner = ($trimmed | str substring 1..-2)
    mut fields = []
    for parsed_field in (
        $inner
        | parse --regex '(?P<field>[A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(?P<value>\(?\$[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\)?|\(?[A-Za-z_][A-Za-z0-9_-]*\s+\(?\$[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\)?\)?)'
    ) {
        let field_name = ($parsed_field.field | str trim)
        let root = (
            context-root-from-record-value-token
                $parsed_field.value
                $context_names
                $bound_aliases
                $identity_wrappers
                $root_wrapper_defs
        )
        if $root != null {
            $fields = ($fields | append {
                field: $field_name
                root: $root
            })
        }
    }

    for parsed_field in (
        $inner
        | parse --regex '(?P<field>[A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(?P<value>\([^)]*\|\s*get\s+[^)]*\))'
    ) {
        let field_name = ($parsed_field.field | str trim)
        let root = (
            context-root-from-record-value-token
                $parsed_field.value
                $context_names
                $bound_aliases
                $identity_wrappers
                $root_wrapper_defs
        )
        if $root != null {
            $fields = ($fields | append {
                field: $field_name
                root: $root
            })
        }
    }

    for parsed_field in (
        $inner
        | parse --regex '(?P<field>[A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(?P<value>\(?[A-Za-z_][A-Za-z0-9_-]*\s+\([^)]*\|\s*get\s+[^)]*\)\)?)'
    ) {
        let field_name = ($parsed_field.field | str trim)
        let root = (
            context-root-from-record-value-token
                $parsed_field.value
                $context_names
                $bound_aliases
                $identity_wrappers
                $root_wrapper_defs
        )
        if $root != null {
            $fields = ($fields | append {
                field: $field_name
                root: $root
            })
        }
    }

    $fields
}

def record-context-bindings [line: string context_names bound_aliases identity_wrappers root_wrapper_defs] {
    mut bindings = []
    for assignment in (declaration-assignments $line) {
        let rhs = (declaration-rhs-token $assignment)
        let order = (record-literal-field-names $rhs)
        for field in (
            record-literal-context-fields
                $rhs
                $context_names
                $bound_aliases
                $identity_wrappers
                $root_wrapper_defs
        ) {
            $bindings = ($bindings | append {
                name: $assignment.name
                field: $field.field
                root: $field.root
                order: $order
            })
        }
    }

    $bindings
}

def record-wrapper-definitions [source: string] {
    mut wrappers = []

    for line in ($source | lines) {
        for parsed in (
            $line
            | parse --regex '^\s*def\s+(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\s+\[\s*(?P<param>[A-Za-z_][A-Za-z0-9_-]*)\s*\]\s*\{\s*\{\s*(?P<field>[A-Za-z_][A-Za-z0-9_-]*)\s*:\s*\$(?P<value>[A-Za-z_][A-Za-z0-9_-]*)\s*\}\s*\}\s*$'
        ) {
            if $parsed.param != $parsed.value {
                continue
            }
            if (
                $wrappers
                | any {|wrapper| $wrapper.name == $parsed.name and $wrapper.field == $parsed.field }
            ) {
                continue
            }
            $wrappers = ($wrappers | append {
                name: $parsed.name
                field: $parsed.field
            })
        }
    }

    $wrappers
}

def context-root-from-record-wrapper-invocation [invocation wrapper context_names bound_aliases identity_wrappers] {
    let param_index = ($wrapper | get -o param_index)
    if $param_index == null {
        return (context-root-from-argument-token $invocation.arg $context_names $bound_aliases $identity_wrappers)
    }

    let args = (command-tail-positional-args $invocation.arg)
    let arg = ($args | get -o $param_index)
    if $arg == null {
        return null
    }

    context-root-from-argument-token $arg $context_names $bound_aliases $identity_wrappers
}

def context-root-from-value-token [raw_value: string context_names bound_aliases] {
    let field_value = (trim-simple-parentheses ($raw_value | str trim))
    for context_name in $context_names {
        let context_token = (["$" $context_name] | str join "")
        if $field_value == $context_token {
            return ""
        }

        let context_prefix = $"($context_token)."
        if not ($field_value | str starts-with $context_prefix) {
            continue
        }

        let root_path = (
            normalize-context-path-token (
                $field_value | str substring ($context_prefix | str length)..
            )
        )
        let root = ($root_path | split row "." | first)
        if (context-projection-root? $root) {
            return $root_path
        }
    }

    for alias in $bound_aliases {
        let alias_token = (["$" $alias.name] | str join "")
        if $field_value == $alias_token {
            return $alias.root
        }

        let alias_prefix = $"($alias_token)."
        if not ($field_value | str starts-with $alias_prefix) {
            continue
        }

        let tail = (
            normalize-context-path-token (
                $field_value | str substring ($alias_prefix | str length)..
            )
        )
        return $"($alias.root).($tail)"
    }

    null
}

def context-root-from-argument-token [raw_value: string context_names bound_aliases identity_wrappers] {
    mut root = (context-root-from-get-pipeline $raw_value $context_names $bound_aliases)
    if $root == null {
        $root = (context-root-from-value-token $raw_value $context_names $bound_aliases)
    }
    if $root == null {
        let invocation = (two-token-invocation (trim-simple-parentheses ($raw_value | str trim)))
        if $invocation != null and $invocation.callee in $identity_wrappers {
            $root = (context-root-from-argument-token $invocation.arg $context_names $bound_aliases $identity_wrappers)
        }
    }

    $root
}

def combine-context-roots [base: string wrapper: string] {
    if $wrapper == "" {
        return $base
    }
    if $base == "" {
        return $wrapper
    }

    $"($base).($wrapper)"
}

def context-root-from-get-pipeline [raw: string context_names bound_aliases] {
    let trimmed = (trim-simple-parentheses ($raw | str trim))
    if (not ($trimmed | str contains "get")) or (not ($trimmed | str contains "|")) {
        return null
    }

    let segments = (split-pipeline-segments $trimmed)
    if ($segments | length) < 2 {
        return null
    }

    mut root = (
        context-root-from-value-token
            (($segments | first) | str trim)
            $context_names
            $bound_aliases
    )
    if $root == null {
        return null
    }

    mut saw_get = false
    for segment in ($segments | skip 1) {
        let parsed = (get-command-field-tail $segment)
        if $parsed == null {
            return null
        }

        let field_path = (normalize-context-path-token $parsed.field)
        if $field_path == "" {
            return null
        }
        $root = if $root == "" { $field_path } else { $"($root).($field_path)" }
        $saw_get = true

        let tail_path = (get-segment-cell-path-tail $parsed.tail)
        if $tail_path != "" {
            $root = if $root == "" { $tail_path } else { $"($root).($tail_path)" }
        }
    }

    if $saw_get { $root } else { null }
}

def record-wrapper-context-bindings [line: string context_names bound_aliases identity_wrappers wrapper_defs] {
    mut bindings = []
    for assignment in (declaration-assignments $line) {
        let rhs = (declaration-rhs-token $assignment)
        let invocation = (two-token-invocation $rhs)
        if $invocation == null {
            continue
        }

        for wrapper in ($wrapper_defs | where {|wrapper| $wrapper.name == $invocation.callee }) {
            let root = (
                context-root-from-record-wrapper-invocation
                    $invocation
                    $wrapper
                    $context_names
                    $bound_aliases
                    $identity_wrappers
            )
            if $root == null {
                continue
            }
            let wrapper_root = ($wrapper | get -o root | default "")
            $bindings = ($bindings | append {
                name: $assignment.name
                field: $wrapper.field
                root: (combine-context-roots $root $wrapper_root)
            })
        }
    }

    $bindings
}

def record-upsert-context-bindings [line: string context_names bound_aliases] {
    mut bindings = []

    for parsed in (
        $line
        | parse --regex '^\s*\$(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\.(?P<field>[A-Za-z_][A-Za-z0-9_-]*)\s*=\s*(?P<value>\(?\$[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\)?)'
    ) {
        let root = (context-root-from-value-token $parsed.value $context_names $bound_aliases)
        if $root != null {
            $bindings = ($bindings | append {
                name: $parsed.name
                field: $parsed.field
                root: $root
            })
        }
    }

    $bindings
}

def record-command-field-value [tail: string] {
    let parsed = (
        $tail
        | str trim
        | parse --regex '^(?P<field>[A-Za-z_][A-Za-z0-9_-]*)\s+(?P<value>.+)$'
    )
    if ($parsed | is-empty) {
        return null
    }

    let result = ($parsed | first)
    {
        field: ($result.field | str trim)
        value: ($result.value | str trim)
    }
}

def record-default-field-value [tail: string] {
    let parts = (
        $tail
        | str trim
        | split row " "
        | each {|part| $part | str trim }
        | where {|part| $part != "" }
    )
    if ($parts | length) < 2 {
        return null
    }

    let field = (normalize-context-path-token ($parts | last))
    let value = (
        $parts
        | first (($parts | length) - 1)
        | str join " "
        | str trim
    )
    if $field == "" or $value == "" {
        return null
    }

    {
        field: $field
        value: $value
    }
}

def record-pipeline-input-token [raw: string] {
    let input = (
        split-pipeline-segments $raw
        | first
        | str trim
    )
    trim-simple-parentheses $input
}

def unique-record-context-fields [fields] {
    mut unique = []

    for field in $fields {
        if (
            $unique
            | any {|existing|
                (
                    $existing.field == $field.field
                    and (($existing | get -o root | default "") == ($field | get -o root | default ""))
                )
            }
        ) {
            continue
        }
        $unique = ($unique | append {
            field: $field.field
            root: ($field | get -o root | default "")
        })
    }

    $unique
}

def record-literal-field-names [raw: string] {
    let trimmed = ($raw | str trim)
    if not (($trimmed | str starts-with "{") and ($trimmed | str ends-with "}")) {
        return []
    }

    mut names = []
    let inner = ($trimmed | str substring 1..-2)
    for parsed in (
        $inner
        | parse --regex '(?P<field>[A-Za-z_][A-Za-z0-9_-]*)\s*:'
    ) {
        if $parsed.field not-in $names {
            $names = ($names | append $parsed.field)
        }
    }

    $names
}

def record-literal-spread-field-names [raw: string aliases] {
    let trimmed = ($raw | str trim)
    if not (($trimmed | str starts-with "{") and ($trimmed | str ends-with "}")) {
        return []
    }

    mut names = []
    let inner = ($trimmed | str substring 1..-2)
    for parsed in (
        $inner
        | parse --regex '\.\.\.\$(?P<name>[A-Za-z_][A-Za-z0-9_-]*)'
    ) {
        for alias in ($aliases | where {|alias| $alias.name == $parsed.name }) {
            if $alias.field not-in $names {
                $names = ($names | append $alias.field)
            }
        }
    }

    $names
}

def record-literal-null-field-names [raw: string] {
    let trimmed = ($raw | str trim)
    if not (($trimmed | str starts-with "{") and ($trimmed | str ends-with "}")) {
        return []
    }

    mut names = []
    let inner = ($trimmed | str substring 1..-2)
    for parsed in (
        $inner
        | parse --regex '(?P<field>[A-Za-z_][A-Za-z0-9_-]*)\s*:\s*null(?:\s|,|$)'
    ) {
        if $parsed.field not-in $names {
            $names = ($names | append $parsed.field)
        }
    }

    $names
}

def record-field-name-list [raw: string] {
    mut names = []

    for token in (
        $raw
        | str trim
        | split row " "
        | each {|part| normalize-context-path-token $part }
        | where {|part| $part != "" }
    ) {
        let name = ($token | split row "." | first)
        if $name != "" and $name not-in $names {
            $names = ($names | append $name)
        }
    }

    $names
}

def record-literal-argument [raw: string] {
    let parsed = (
        $raw
        | str trim
        | parse --regex '^(?P<record>\{.*\})\s*\)*$'
    )
    if ($parsed | is-empty) {
        return null
    }

    ($parsed | first).record
}

def record-pipeline-input-context-fields [raw: string context_names bound_aliases identity_wrappers root_wrapper_defs aliases] {
    let input = (record-pipeline-input-token $raw)
    mut fields = (
        record-literal-context-fields
            $input
            $context_names
            $bound_aliases
            $identity_wrappers
            $root_wrapper_defs
    )
    $fields = (
        $fields
        | append (record-literal-spread-context-fields $input $aliases)
    )

    for parsed in (
        $input
        | parse --regex '^\$(?P<name>[A-Za-z_][A-Za-z0-9_-]*)$'
    ) {
        for alias in ($aliases | where {|alias| $alias.name == $parsed.name }) {
            $fields = ($fields | append {
                field: $alias.field
                root: ($alias | get -o root | default "")
            })
        }
    }

    unique-record-context-fields $fields
}

def record-pipeline-input-field-order [raw: string aliases] {
    let input = (record-pipeline-input-token $raw)
    let literal_order = (record-literal-field-names $input)
    let spread_order = (record-literal-spread-field-names $input $aliases)

    if ($spread_order | is-empty) and not ($literal_order | is-empty) {
        return $literal_order
    }
    if ($literal_order | is-empty) and not ($spread_order | is-empty) {
        return $spread_order
    }

    for parsed in (
        $input
        | parse --regex '^\$(?P<name>[A-Za-z_][A-Za-z0-9_-]*)$'
    ) {
        for alias in ($aliases | where {|alias| $alias.name == $parsed.name }) {
            let order = ($alias | get -o order | default [])
            if not ($order | is-empty) {
                return $order
            }
        }
    }

    null
}

def record-pipeline-input-null-fields [raw: string] {
    let input = (record-pipeline-input-token $raw)
    let literal_nulls = (record-literal-null-field-names $input)
    if not ($literal_nulls | is-empty) {
        return $literal_nulls
    }

    []
}

def remove-record-context-field [fields field_name: string] {
    $fields | where {|field| $field.field != $field_name }
}

def remove-field-name [fields field_name: string] {
    $fields | where {|field| $field != $field_name }
}

def append-field-name [fields field_name: string] {
    if $field_name in $fields {
        return $fields
    }

    $fields | append $field_name
}

def value-token-null? [raw: string] {
    (normalize-context-path-token (trim-simple-parentheses ($raw | str trim))) == "null"
}

def append-record-context-field [fields field_name: string root: string] {
    unique-record-context-fields (
        $fields
        | append {
            field: $field_name
            root: $root
        }
    )
}

def replace-record-context-field [fields field_name: string root] {
    mut next = (remove-record-context-field $fields $field_name)
    if $root != null {
        $next = (append-record-context-field $next $field_name $root)
    }

    $next
}

def has-record-context-field? [fields field_name: string] {
    $fields | any {|field| $field.field == $field_name }
}

def record-field-index [order field_name: string] {
    if $order == null {
        return null
    }

    for entry in ($order | enumerate) {
        if $entry.item == $field_name {
            return $entry.index
        }
    }

    null
}

def record-field-name-at-index [names index: int fallback: string] {
    if $index < ($names | length) {
        return ($names | get $index)
    }

    $fallback
}

def rename-record-context-fields [fields order rename_names] {
    if $order == null {
        return $fields
    }

    mut renamed = []
    for field in $fields {
        let index = (record-field-index $order $field.field)
        let next_name = if $index == null {
            $field.field
        } else {
            record-field-name-at-index $rename_names $index $field.field
        }
        $renamed = ($renamed | append {
            field: $next_name
            root: ($field | get -o root | default "")
        })
    }

    unique-record-context-fields $renamed
}

def rename-record-field-order [order rename_names] {
    if $order == null {
        return null
    }

    mut renamed = []
    for field in ($order | enumerate) {
        let next_name = (record-field-name-at-index $rename_names $field.index $field.item)
        $renamed = ($renamed | append $next_name)
    }

    $renamed
}

def merge-record-field-order [order merge_fields] {
    if $order == null {
        return null
    }

    mut next = $order
    for field in $merge_fields {
        if $field not-in $next {
            $next = ($next | append $field)
        }
    }

    $next
}

def upsert-record-field-order [order field_name: string] {
    if $order == null {
        return null
    }
    if $field_name in $order {
        return $order
    }

    $order | append $field_name
}

def record-pipeline-flow-context-fields [raw: string context_names bound_aliases identity_wrappers root_wrapper_defs aliases] {
    let parts = (split-pipeline-segments $raw)
    if ($parts | length) <= 1 {
        return []
    }

    mut fields = (
        record-pipeline-input-context-fields
            $raw
            $context_names
            $bound_aliases
            $identity_wrappers
            $root_wrapper_defs
            $aliases
    )
    mut field_order = (record-pipeline-input-field-order $raw $aliases)
    mut null_fields = (record-pipeline-input-null-fields $raw)

    for segment in ($parts | skip 1) {
        let trimmed = ($segment | str trim)

        for command in [insert update upsert] {
            if not (($trimmed == $command) or ($trimmed | str starts-with $"($command) ")) {
                continue
            }

            let tail = ($trimmed | str substring ($command | str length).. | str trim)
            let field_value = (record-command-field-value $tail)
            if $field_value == null {
                continue
            }

            let root = (
                context-root-from-record-value-token
                    $field_value.value
                    $context_names
                    $bound_aliases
                    $identity_wrappers
                    $root_wrapper_defs
            )
            $fields = (replace-record-context-field $fields $field_value.field $root)
            $field_order = (upsert-record-field-order $field_order $field_value.field)
            $null_fields = if (value-token-null? $field_value.value) {
                append-field-name $null_fields $field_value.field
            } else {
                remove-field-name $null_fields $field_value.field
            }
        }

        if ($trimmed | str starts-with "merge ") {
            let merge_arg = (record-literal-argument ($trimmed | str substring 5.. | str trim))
            if $merge_arg == null {
                continue
            }

            let merge_fields = (record-literal-field-names $merge_arg)
            for field in $merge_fields {
                $fields = (remove-record-context-field $fields $field)
                $null_fields = (remove-field-name $null_fields $field)
            }
            $fields = (unique-record-context-fields (
                $fields
                | append (
                    record-literal-context-fields
                        $merge_arg
                        $context_names
                        $bound_aliases
                        $identity_wrappers
                        $root_wrapper_defs
                )
            ))
            for field in (record-literal-null-field-names $merge_arg) {
                $null_fields = (append-field-name $null_fields $field)
            }
            $field_order = (merge-record-field-order $field_order $merge_fields)
        }

        if ($trimmed | str starts-with "select ") {
            let selected = (record-field-name-list ($trimmed | str substring 6..))
            $fields = ($fields | where {|field| $field.field in $selected })
            $field_order = $selected
            $null_fields = ($null_fields | where {|field| $field in $selected })
        }

        if ($trimmed | str starts-with "reject ") {
            let rejected = (record-field-name-list ($trimmed | str substring 6..))
            $fields = ($fields | where {|field| $field.field not-in $rejected })
            $null_fields = ($null_fields | where {|field| $field not-in $rejected })
            if $field_order != null {
                $field_order = ($field_order | where {|field| $field not-in $rejected })
            }
        }

        if ($trimmed | str starts-with "rename ") {
            let rename_names = (record-field-name-list ($trimmed | str substring 6..))
            $fields = (rename-record-context-fields $fields $field_order $rename_names)
            $null_fields = (rename-record-field-order $null_fields $rename_names)
            $field_order = (rename-record-field-order $field_order $rename_names)
        }

        if ($trimmed | str starts-with "default ") {
            let field_value = (record-default-field-value ($trimmed | str substring 7..))
            if $field_value == null {
                continue
            }

            let field_exists = ($field_order != null and $field_value.field in $field_order)
            let can_fill_field = (
                not (has-record-context-field? $fields $field_value.field)
                and (not $field_exists or $field_value.field in $null_fields)
            )
            if not $can_fill_field {
                continue
            }

            let root = (
                context-root-from-record-value-token
                    $field_value.value
                    $context_names
                    $bound_aliases
                    $identity_wrappers
                    $root_wrapper_defs
            )
            $fields = (replace-record-context-field $fields $field_value.field $root)
            $field_order = (upsert-record-field-order $field_order $field_value.field)
            $null_fields = if (value-token-null? $field_value.value) {
                append-field-name $null_fields $field_value.field
            } else {
                remove-field-name $null_fields $field_value.field
            }
        }
    }

    unique-record-context-fields $fields
}

def record-pipeline-flow-context-bindings [line: string context_names bound_aliases identity_wrappers root_wrapper_defs aliases] {
    mut bindings = []

    for assignment in (declaration-assignments $line) {
        for field in (
            record-pipeline-flow-context-fields
                (declaration-rhs-token $assignment)
                $context_names
                $bound_aliases
                $identity_wrappers
                $root_wrapper_defs
                $aliases
        ) {
            $bindings = ($bindings | append {
                name: $assignment.name
                field: $field.field
                root: ($field | get -o root | default "")
            })
        }
    }

    $bindings
}

def record-literal-spread-context-fields [raw: string aliases] {
    let trimmed = ($raw | str trim)
    if not (($trimmed | str starts-with "{") and ($trimmed | str ends-with "}")) {
        return []
    }

    mut fields = []
    let inner = ($trimmed | str substring 1..-2)
    for parsed in (
        $inner
        | parse --regex '\.\.\.\$(?P<name>[A-Za-z_][A-Za-z0-9_-]*)'
    ) {
        for alias in ($aliases | where {|alias| $alias.name == $parsed.name }) {
            $fields = ($fields | append {
                field: $alias.field
                root: ($alias | get -o root | default "")
            })
        }
    }

    $fields
}

def record-spread-context-bindings [line: string aliases] {
    mut bindings = []
    for assignment in (declaration-assignments $line) {
        for field in (record-literal-spread-context-fields (declaration-rhs-token $assignment) $aliases) {
            $bindings = ($bindings | append {
                name: $assignment.name
                field: $field.field
                root: ($field | get -o root | default "")
            })
        }
    }

    $bindings
}

def identity-wrapper-definitions [source: string] {
    mut identities = []
    mut changed = true

    loop {
        if not $changed {
            break
        }
        $changed = false

        for line in ($source | lines) {
            for parsed in (
                $line
                | parse --regex '^\s*def\s+(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\s+\[\s*(?P<param>[A-Za-z_][A-Za-z0-9_-]*)\s*\]\s*\{\s*\(?\s*\$(?P<value>[A-Za-z_][A-Za-z0-9_-]*)\s*\)?\s*\}\s*$'
            ) {
                if $parsed.param != $parsed.value {
                    continue
                }
                if $parsed.name not-in $identities {
                    $identities = ($identities | append $parsed.name)
                    $changed = true
                }
            }

            for parsed in (
                $line
                | parse --regex '^\s*def\s+(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\s+\[\s*(?P<param>[A-Za-z_][A-Za-z0-9_-]*)\s*\]\s*\{\s*(?P<callee>[A-Za-z_][A-Za-z0-9_-]*)\s+\(?\s*\$(?P<value>[A-Za-z_][A-Za-z0-9_-]*)\s*\)?\s*\}\s*$'
            ) {
                if $parsed.param != $parsed.value {
                    continue
                }
                if $parsed.callee not-in $identities {
                    continue
                }
                if $parsed.name not-in $identities {
                    $identities = ($identities | append $parsed.name)
                    $changed = true
                }
            }
        }
    }

    $identities
}

def function-record-context-aliases [body param: string identity_wrappers root_wrapper_defs root_aliases] {
    mut aliases = []

    for line in $body {
        let bindings = (
            (record-context-bindings $line [$param] $root_aliases $identity_wrappers $root_wrapper_defs)
            | append (record-upsert-context-bindings $line [$param] $root_aliases)
            | append (record-pipeline-flow-context-bindings $line [$param] $root_aliases $identity_wrappers $root_wrapper_defs $aliases)
            | append (record-spread-context-bindings $line $aliases)
        )
        for binding in $bindings {
            if (
                $aliases
                | any {|alias|
                    (
                        $alias.name == $binding.name
                        and $alias.field == $binding.field
                        and (($alias | get -o root | default "") == ($binding | get -o root | default ""))
                    )
                }
            ) {
                continue
            }
            $aliases = ($aliases | append $binding)
        }
    }

    $aliases
}

def context-root-from-returned-record-get-pipeline [returned: string record_aliases param: string root_aliases identity_wrappers root_wrapper_defs] {
    let segments = (split-pipeline-segments $returned)
    if ($segments | length) < 2 {
        return null
    }

    let input = (($segments | first) | str trim)
    mut roots = []
    mut prefix_segments = []

    for segment in ($segments | skip 1) {
        let parsed = (get-command-field-tail $segment)
        if $parsed == null {
            if ($roots | is-empty) {
                $prefix_segments = ($prefix_segments | append ($segment | str trim))
            }
            continue
        }

        mut root = (
            context-root-from-record-get
                $input
                $parsed.field
                $record_aliases
                []
                [$param]
                $root_aliases
                $identity_wrappers
                $root_wrapper_defs
        )
        if $root == null {
            $root = (
                context-root-from-record-pipeline-get
                    $input
                    $prefix_segments
                    $parsed.field
                    $record_aliases
                    [$param]
                    $root_aliases
                    $identity_wrappers
                    $root_wrapper_defs
            )
        }
        if $root == null {
            continue
        }

        $roots = ($roots | append $root)
    }

    if ($roots | length) == 1 {
        return ($roots | first)
    }

    null
}

def function-return-context-root [function identity_wrappers root_wrapper_defs] {
    let param = $function.param
    let aliases = (
        function-context-root-aliases
            $function.body
            $param
            $identity_wrappers
            $root_wrapper_defs
    )
    let record_aliases = (
        function-record-context-aliases
            $function.body
            $param
            $identity_wrappers
            $root_wrapper_defs
            $aliases
    )
    let return_lines = (
        $function.body
        | each {|line| $line | str trim }
        | where {|line|
            (
                $line != ""
                and not ($line | str starts-with "#")
                and not ($line | str contains "=")
            )
        }
    )
    if ($return_lines | is-empty) {
        return null
    }

    let returned = ($return_lines | last)
    if ($returned | str contains "|") {
        let root = (context-root-from-get-pipeline $returned [$param] $aliases)
        if $root != null {
            return $root
        }

        let record_root = (
            context-root-from-returned-record-get-pipeline
                $returned
                $record_aliases
                $param
                $aliases
                $identity_wrappers
                $root_wrapper_defs
        )
        if $record_root != null {
            return $record_root
        }

        return null
    }

    mut root = (context-root-from-value-token $returned [$param] $aliases)
    if $root != null {
        return $root
    }

    let invocation = (two-token-invocation $returned)
    if $invocation == null {
        return null
    }

    if $invocation.callee in $identity_wrappers {
        $root = (context-root-from-get-pipeline $invocation.arg [$param] $aliases)
        if $root != null {
            return $root
        }

        $root = (context-root-from-value-token $invocation.arg [$param] $aliases)
        if $root != null {
            return $root
        }
    }

    context-root-from-wrapper-invocation $invocation [$param] $aliases $identity_wrappers $root_wrapper_defs
}

def context-root-wrapper-definitions [source: string] {
    let identity_wrappers = (identity-wrapper-definitions $source)
    mut wrappers = []
    mut changed = true

    loop {
        if not $changed {
            break
        }
        $changed = false

        for function in (one-param-user-functions $source) {
            let root = (function-return-context-root $function $identity_wrappers $wrappers)
            if $root == null {
                continue
            }
            if (
                $wrappers
                | any {|wrapper| $wrapper.name == $function.name and (($wrapper | get -o root | default "") == $root) }
            ) {
                continue
            }

            $wrappers = ($wrappers | append {
                name: $function.name
                root: $root
            })
            $changed = true
        }
    }

    $wrappers
}

def one-param-user-functions [source: string] {
    mut functions = []
    mut in_function = false
    mut current_name = ""
    mut current_param = ""
    mut current_body = []

    for line in ($source | lines) {
        let trimmed = ($line | str trim)

        if not $in_function {
            let one_line = (
                $line
                | parse --regex '^\s*def\s+(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\s+\[\s*(?P<param>[A-Za-z_][A-Za-z0-9_-]*)\s*\]\s*\{\s*(?P<body>.*?)\s*\}\s*$'
            )
            if not ($one_line | is-empty) {
                let parsed = ($one_line | first)
                $functions = ($functions | append {
                    name: $parsed.name
                    param: $parsed.param
                    body: [$parsed.body]
                })
                continue
            }

            let header = (
                $line
                | parse --regex '^\s*def\s+(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\s+\[\s*(?P<param>[A-Za-z_][A-Za-z0-9_-]*)\s*\]\s*\{\s*$'
            )
            if not ($header | is-empty) {
                let parsed = ($header | first)
                $in_function = true
                $current_name = $parsed.name
                $current_param = $parsed.param
                $current_body = []
            }
            continue
        }

        if $trimmed == "}" {
            $functions = ($functions | append {
                name: $current_name
                param: $current_param
                body: $current_body
            })
            $in_function = false
            $current_name = ""
            $current_param = ""
            $current_body = []
            continue
        }

        $current_body = ($current_body | append $line)
    }

    $functions
}

def record-context-wrapper-definitions [source: string] {
    mut wrappers = []
    let identity_wrappers = (identity-wrapper-definitions $source)
    let root_wrapper_defs = (context-root-wrapper-definitions $source)
    let base_wrapper_defs = (record-wrapper-definitions $source)

    for function in (one-param-user-functions $source) {
        mut aliases = []
        mut returned_names = []
        let root_aliases = (
            function-context-root-aliases
                $function.body
                $function.param
                $identity_wrappers
                $root_wrapper_defs
        )

        for line in $function.body {
            let trimmed = ($line | str trim)
            let bindings = (
                (record-context-bindings $line [$function.param] $root_aliases $identity_wrappers $root_wrapper_defs)
                | append (record-wrapper-context-bindings $line [$function.param] $root_aliases $identity_wrappers $base_wrapper_defs)
                | append (record-upsert-context-bindings $line [$function.param] $root_aliases)
                | append (record-pipeline-flow-context-bindings $line [$function.param] $root_aliases $identity_wrappers $root_wrapper_defs $aliases)
                | append (record-spread-context-bindings $line $aliases)
            )
            for binding in $bindings {
                let existing = (
                    $aliases
                    | where {|alias|
                        (
                            $alias.name == $binding.name
                            and $alias.field == $binding.field
                            and (($alias | get -o root | default "") == ($binding | get -o root | default ""))
                        )
                    }
                )
                if ($existing | is-empty) {
                    $aliases = ($aliases | append $binding)
                }
            }

            for parsed in (
                $line
                | parse --regex '^\s*\$(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\s*$'
            ) {
                $returned_names = ($returned_names | append $parsed.name)
            }

            mut returned_fields = (
                (record-literal-context-fields $trimmed [$function.param] $root_aliases $identity_wrappers $root_wrapper_defs)
                | append (record-literal-spread-context-fields $trimmed $aliases)
                | append (record-pipeline-flow-context-fields $trimmed [$function.param] $root_aliases $identity_wrappers $root_wrapper_defs $aliases)
            )
            let invocation = (two-token-invocation $trimmed)
            if $invocation != null {
                for wrapper in ($base_wrapper_defs | where {|wrapper| $wrapper.name == $invocation.callee }) {
                    let root = (context-root-from-value-token $invocation.arg [$function.param] $root_aliases)
                    if $root == null {
                        continue
                    }
                    $returned_fields = ($returned_fields | append {
                        field: $wrapper.field
                        root: (combine-context-roots $root ($wrapper | get -o root | default ""))
                    })
                }
            }
            for field in $returned_fields {
                if (
                    $wrappers
                    | any {|wrapper|
                        (
                            $wrapper.name == $function.name
                            and $wrapper.field == $field.field
                            and (($wrapper | get -o root | default "") == ($field | get -o root | default ""))
                        )
                    }
                ) {
                    continue
                }
                $wrappers = ($wrappers | append {
                    name: $function.name
                    field: $field.field
                    root: ($field | get -o root | default "")
                })
            }
        }

        for alias in $aliases {
            if $alias.name not-in $returned_names {
                continue
            }
            if (
                $wrappers
                | any {|wrapper|
                    (
                        $wrapper.name == $function.name
                        and $wrapper.field == $alias.field
                        and (($wrapper | get -o root | default "") == ($alias | get -o root | default ""))
                    )
                }
            ) {
                continue
            }
            $wrappers = ($wrappers | append {
                name: $function.name
                field: $alias.field
                root: ($alias | get -o root | default "")
            })
        }
    }

    $wrappers
}

def upsert-context-root-alias [aliases name: string root: string] {
    if ($aliases | any {|alias| $alias.name == $name }) {
        $aliases | each {|alias|
            if $alias.name == $name {
                { name: $name root: $root }
            } else {
                $alias
            }
        }
    } else {
        $aliases | append { name: $name root: $root }
    }
}

def function-context-root-aliases [body param: string identity_wrappers root_wrapper_defs] {
    mut aliases = []

    for line in $body {
        for assignment in (declaration-assignments $line) {
            let rhs = (declaration-rhs-token $assignment)
            mut root = (context-root-from-argument-token $rhs [$param] $aliases $identity_wrappers)
            if $root == null {
                let invocation = (two-token-invocation $rhs)
                if $invocation != null {
                    $root = (
                        context-root-from-wrapper-invocation
                            $invocation
                            [$param]
                            $aliases
                            $identity_wrappers
                            $root_wrapper_defs
                    )
                }
            }

            if $root != null {
                $aliases = (upsert-context-root-alias $aliases $assignment.name $root)
            }
        }
    }

    $aliases
}

def append-function-context-field-access [accesses function_name: string raw_access: string] {
    let field = (normalize-context-field-token $raw_access)
    if $field == "" {
        return $accesses
    }
    if (
        $accesses
        | any {|access| $access.name == $function_name and $access.raw_access == $raw_access }
    ) {
        return $accesses
    }

    $accesses | append {
        name: $function_name
        raw_access: $raw_access
    }
}

def function-context-field-accesses [function identity_wrappers root_wrapper_defs] {
    mut accesses = []
    let param = $function.param
    let aliases = (
        function-context-root-aliases
            $function.body
            $param
            $identity_wrappers
            $root_wrapper_defs
    )
    let roots = ([{ name: $param root: "" }] | append $aliases)

    for line in $function.body {
        for root in $roots {
            let prefix = $"$($root.name)."
            for raw_tail in (marker-tails-outside-simple-string $line $prefix) {
                let raw_access = if $root.root == "" {
                    $raw_tail
                } else {
                    $"($root.root).($raw_tail)"
                }
                let field = (normalize-context-field-token $raw_access)
                if $field == "" {
                    continue
                }
                $accesses = (append-function-context-field-access $accesses $function.name $raw_access)
            }
        }

        for candidate in (record-get-candidate-lines $line) {
            let segments = (split-pipeline-segments ($candidate | str trim))
            if ($segments | length) < 2 {
                continue
            }

            mut input = (($segments | first) | str trim)
            if ($input | str contains "=") {
                $input = (($input | split row "=" | last) | str trim)
            }
            mut root = null

            for segment in ($segments | skip 1) {
                let parsed = (get-command-field-tail $segment)
                if $parsed == null {
                    continue
                }

                if $root == null {
                    $root = (context-root-from-get-input $input [$param] $aliases)
                    if $root == null {
                        continue
                    }
                }

                let field_path = (normalize-context-path-token $parsed.field)
                if $field_path != "" {
                    let raw_access = if $root == "" { $field_path } else { $"($root).($field_path)" }
                    $accesses = (append-function-context-field-access $accesses $function.name $raw_access)
                    $root = $raw_access
                }

                let tail_path = (get-segment-cell-path-tail $parsed.tail)
                if $tail_path != "" {
                    let raw_access = if $root == "" { $tail_path } else { $"($root).($tail_path)" }
                    $accesses = (append-function-context-field-access $accesses $function.name $raw_access)
                    $root = $raw_access
                }
            }
        }
    }

    $accesses
}

def user-function-context-field-accesses [source: string] {
    mut accesses = []
    let identity_wrappers = (identity-wrapper-definitions $source)
    let root_wrapper_defs = (context-root-wrapper-definitions $source)

    for function in (one-param-user-functions $source) {
        $accesses = (
            $accesses
            | append (function-context-field-accesses $function $identity_wrappers $root_wrapper_defs)
        )
    }

    $accesses
}

def simple-function-param-names [raw_params: string] {
    let parts = (
        $raw_params
        | split row " "
        | each {|part| $part | str trim }
        | where {|part| $part != "" }
    )
    if (
        $parts
        | any {|part|
            (
                ($part | str contains ":")
                or ($part | str starts-with "-")
                or ($part | str starts-with "...")
            )
        }
    ) {
        return []
    }

    $parts
    | each {|part|
        $part
        | str replace --all "," ""
        | str replace --all "?" ""
        | split row ":"
        | first
        | str trim
    }
    | where {|name| $name != "" and not ($name | str starts-with "-") }
}

def positional-user-functions [source: string] {
    mut functions = []
    mut in_function = false
    mut current_name = ""
    mut current_params = []
    mut current_body = []

    for line in ($source | lines) {
        let trimmed = ($line | str trim)

        if not $in_function {
            let one_line = (
                $line
                | parse --regex '^\s*def\s+(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\s+\[\s*(?P<params>[^\]]*)\s*\]\s*\{\s*(?P<body>.*?)\s*\}\s*$'
            )
            if not ($one_line | is-empty) {
                let parsed = ($one_line | first)
                let params = (simple-function-param-names $parsed.params)
                if not ($params | is-empty) {
                    $functions = ($functions | append {
                        name: $parsed.name
                        params: $params
                        body: [$parsed.body]
                    })
                }
                continue
            }

            let header = (
                $line
                | parse --regex '^\s*def\s+(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\s+\[\s*(?P<params>[^\]]*)\s*\]\s*\{\s*$'
            )
            if not ($header | is-empty) {
                let parsed = ($header | first)
                let params = (simple-function-param-names $parsed.params)
                if ($params | is-empty) {
                    continue
                }
                $in_function = true
                $current_name = $parsed.name
                $current_params = $params
                $current_body = []
            }
            continue
        }

        if $trimmed == "}" {
            $functions = ($functions | append {
                name: $current_name
                params: $current_params
                body: $current_body
            })
            $in_function = false
            $current_name = ""
            $current_params = []
            $current_body = []
            continue
        }

        $current_body = ($current_body | append $line)
    }

    $functions
}

def multi-param-context-root-wrapper-definitions [source: string] {
    mut wrappers = []

    for function in (positional-user-functions $source) {
        if ($function.params | length) <= 1 {
            continue
        }

        let return_lines = (
            $function.body
            | each {|line| $line | str trim }
            | where {|line|
                (
                    $line != ""
                    and not ($line | str starts-with "#")
                    and not ($line | str contains "=")
                )
            }
        )
        if ($return_lines | is-empty) {
            continue
        }

        let returned = ($return_lines | last)
        for param in ($function.params | enumerate) {
            mut root = (context-root-from-get-pipeline $returned [$param.item] [])
            if $root == null {
                $root = (context-root-from-value-token $returned [$param.item] [])
            }
            if $root == null {
                continue
            }
            let final_root = $root
            if (
                $wrappers
                | any {|wrapper|
                    (
                        $wrapper.name == $function.name
                        and $wrapper.param_index == $param.index
                        and (($wrapper | get -o root | default "") == $final_root)
                    )
                }
            ) {
                continue
            }

            $wrappers = ($wrappers | append {
                name: $function.name
                param_index: $param.index
                root: $final_root
            })
        }
    }

    $wrappers
}

def multi-param-record-wrapper-definitions [source: string] {
    mut wrappers = []
    let identity_wrappers = (identity-wrapper-definitions $source)
    let root_wrapper_defs = (context-root-wrapper-definitions $source)

    for function in (positional-user-functions $source) {
        if ($function.params | length) <= 1 {
            continue
        }

        for line in $function.body {
            let trimmed = ($line | str trim)
            if $trimmed == "" or ($trimmed | str starts-with "#") {
                continue
            }

            for param in ($function.params | enumerate) {
                for field in (record-literal-context-fields $trimmed [$param.item] [] $identity_wrappers $root_wrapper_defs) {
                    if (
                        $wrappers
                        | any {|wrapper|
                            (
                                $wrapper.name == $function.name
                                and $wrapper.field == $field.field
                                and $wrapper.param_index == $param.index
                                and (($wrapper | get -o root | default "") == ($field | get -o root | default ""))
                            )
                        }
                    ) {
                        continue
                    }

                    $wrappers = ($wrappers | append {
                        name: $function.name
                        field: $field.field
                        param_index: $param.index
                        root: ($field | get -o root | default "")
                    })
                }
            }
        }
    }

    $wrappers
}

def command-tail-positional-args [raw_tail: string] {
    let text = ($raw_tail | str trim)
    if $text == "" {
        return []
    }

    mut args = []
    mut current = ""
    mut paren_depth = 0
    mut brace_depth = 0
    mut bracket_depth = 0
    mut in_single = false
    mut in_double = false

    for ch in ($text | split chars) {
        if ($ch == "'" and (not $in_double)) {
            $in_single = not $in_single
            $current = $"($current)($ch)"
            continue
        }
        if ($ch == '"' and (not $in_single)) {
            $in_double = not $in_double
            $current = $"($current)($ch)"
            continue
        }

        let at_top = (
            (not $in_single)
            and (not $in_double)
            and $paren_depth == 0
            and $brace_depth == 0
            and $bracket_depth == 0
        )
        if $at_top and $ch == ";" {
            break
        }
        if $at_top and ($ch == " " or $ch == "\t") {
            let arg = ($current | str trim)
            if $arg != "" {
                $args = ($args | append $arg)
            }
            $current = ""
            continue
        }

        if (not $in_single) and (not $in_double) {
            if $ch == "(" {
                $paren_depth = $paren_depth + 1
            } else if $ch == ")" and $paren_depth > 0 {
                $paren_depth = $paren_depth - 1
            } else if $ch == "{" {
                $brace_depth = $brace_depth + 1
            } else if $ch == "}" and $brace_depth > 0 {
                $brace_depth = $brace_depth - 1
            } else if $ch == "[" {
                $bracket_depth = $bracket_depth + 1
            } else if $ch == "]" and $bracket_depth > 0 {
                $bracket_depth = $bracket_depth - 1
            }
        }

        $current = $"($current)($ch)"
    }

    let arg = ($current | str trim)
    if $arg != "" {
        $args = ($args | append $arg)
    }

    $args
}

def multi-param-function-context-field-accesses [source: string] {
    mut accesses = []
    let identity_wrappers = (identity-wrapper-definitions $source)
    let root_wrapper_defs = (context-root-wrapper-definitions $source)

    for function in (positional-user-functions $source) {
        if ($function.params | length) <= 1 {
            continue
        }

        for param in ($function.params | enumerate) {
            let aliases = (
                function-context-root-aliases
                    $function.body
                    $param.item
                    $identity_wrappers
                    $root_wrapper_defs
            )
            let roots = ([{ name: $param.item root: "" }] | append $aliases)
            for line in $function.body {
                for root_info in $roots {
                    let prefix = $"$($root_info.name)."
                    for raw_tail in (marker-tails-outside-simple-string $line $prefix) {
                        let root_path = ($root_info | get -o root | default "")
                        let raw_access = if $root_path == "" {
                            $raw_tail
                        } else {
                            $"($root_path).($raw_tail)"
                        }
                        let field = (normalize-context-field-token $raw_access)
                        if $field == "" {
                            continue
                        }
                        if (
                            $accesses
                            | any {|access|
                                (
                                    $access.name == $function.name
                                    and $access.param_index == $param.index
                                    and $access.raw_access == $raw_access
                                )
                            }
                        ) {
                            continue
                        }
                        $accesses = ($accesses | append {
                            name: $function.name
                            param_index: $param.index
                            raw_access: $raw_access
                        })
                    }
                }

                for candidate in (record-get-candidate-lines $line) {
                    let segments = (split-pipeline-segments ($candidate | str trim))
                    if ($segments | length) < 2 {
                        continue
                    }

                    mut input = (($segments | first) | str trim)
                    if ($input | str contains "=") {
                        $input = (($input | split row "=" | last) | str trim)
                    }
                    mut root = null

                    for segment in ($segments | skip 1) {
                        let parsed = (get-command-field-tail $segment)
                        if $parsed == null {
                            continue
                        }

                        if $root == null {
                            $root = (context-root-from-get-input $input [$param.item] $aliases)
                            if $root == null {
                                continue
                            }
                        }

                        let field_path = (normalize-context-path-token $parsed.field)
                        if $field_path != "" {
                            let raw_access = if $root == "" { $field_path } else { $"($root).($field_path)" }
                            if not (
                                $accesses
                                | any {|access|
                                    (
                                        $access.name == $function.name
                                        and $access.param_index == $param.index
                                        and $access.raw_access == $raw_access
                                    )
                                }
                            ) {
                                $accesses = ($accesses | append {
                                    name: $function.name
                                    param_index: $param.index
                                    raw_access: $raw_access
                                })
                            }
                            $root = $raw_access
                        }

                        let tail_path = (get-segment-cell-path-tail $parsed.tail)
                        if $tail_path != "" {
                            let raw_access = if $root == "" { $tail_path } else { $"($root).($tail_path)" }
                            if not (
                                $accesses
                                | any {|access|
                                    (
                                        $access.name == $function.name
                                        and $access.param_index == $param.index
                                        and $access.raw_access == $raw_access
                                    )
                                }
                            ) {
                                $accesses = ($accesses | append {
                                    name: $function.name
                                    param_index: $param.index
                                    raw_access: $raw_access
                                })
                            }
                            $root = $raw_access
                        }
                    }
                }
            }
        }
    }

    $accesses
}

def multi-param-user-function-context-field-kernel-features [source: string target context_names] {
    if not ($source | str contains "def ") {
        return []
    }

    mut features = []
    let accesses = (multi-param-function-context-field-accesses $source)
    if ($accesses | is-empty) {
        return $features
    }

    let bound_aliases = (program-bound-context-root-aliases $source $context_names)
    let identity_wrappers = (identity-wrapper-definitions $source)

    for line in ($source | lines) {
        let trimmed = ($line | str trim)
        if $trimmed == "" or ($trimmed | str starts-with "#") or ($trimmed | str starts-with "def ") {
            continue
        }

        for access in $accesses {
            for raw_tail in (command-invocation-tails $trimmed $access.name) {
                let args = (command-tail-positional-args $raw_tail)
                let arg = ($args | get -o $access.param_index)
                if $arg == null {
                    continue
                }

                let root = (context-root-from-argument-token $arg $context_names $bound_aliases $identity_wrappers)
                if $root == null {
                    continue
                }
                let raw_access = if $root == "" {
                    $access.raw_access
                } else {
                    $"($root).($access.raw_access)"
                }
                $features = (
                    append-missing-kernel-features
                        $features
                        (context-access-kernel-features $raw_access $target)
                )
            }
        }
    }

    $features
}

def context-access-kernel-features [raw_access: string target] {
    mut features = []
    let field = (normalize-context-field-token $raw_access)
    if $field == "" {
        return $features
    }

    let feature = (context-field-kernel-feature $field $target)
    if $feature != null {
        $features = (append-missing-kernel-features $features [$feature])
    }
    let tracepoint_feature = (tracepoint-payload-field-kernel-feature $field $target)
    if $tracepoint_feature != null {
        $features = (append-missing-kernel-features $features [$tracepoint_feature])
    }
    if not (context-field-access-is-assignment-lhs? $raw_access $field) {
        let helper_feature = (context-field-helper-kernel-feature $field $target)
        if $helper_feature != null {
            $features = (append-missing-kernel-features $features [$helper_feature])
        }
    }
    let projection_feature = (context-projection-kernel-feature $raw_access $target)
    if $projection_feature != null {
        $features = (append-missing-kernel-features $features [$projection_feature])
    }
    let read_feature = (context-projection-kernel-read-feature $raw_access $target)
    if $read_feature != null {
        $features = (append-missing-kernel-features $features [$read_feature])
    }
    let task_pt_regs_feature = (context-task-pt-regs-kernel-feature $raw_access)
    if $task_pt_regs_feature != null {
        $features = (append-missing-kernel-features $features [$task_pt_regs_feature])
    }

    $features
}

def user-function-context-field-kernel-features [source: string target context_names] {
    if not ($source | str contains "def ") {
        return []
    }

    mut features = []
    let accesses = (user-function-context-field-accesses $source)
    if ($accesses | is-empty) {
        return $features
    }

    let bound_aliases = (program-bound-context-root-aliases $source $context_names)

    for line in ($source | lines) {
        let trimmed = ($line | str trim)
        if $trimmed == "" or ($trimmed | str starts-with "#") or ($trimmed | str starts-with "def ") {
            continue
        }

        for access in $accesses {
            for raw_tail in (command-invocation-tails $trimmed $access.name) {
                let arg = (normalize-context-path-token $raw_tail)
                let root = (context-root-from-value-token $arg $context_names $bound_aliases)
                if $root == null {
                    continue
                }
                let raw_access = if $root == "" {
                    $access.raw_access
                } else {
                    $"($root).($access.raw_access)"
                }
                $features = (
                    append-missing-kernel-features
                        $features
                        (context-access-kernel-features $raw_access $target)
                )
            }
        }
    }

    $features
}

def program-record-context-aliases [source: string context_names] {
    mut aliases = []
    let bound_aliases = (program-bound-context-root-aliases-base $source $context_names)
    let identity_wrappers = (identity-wrapper-definitions $source)
    let root_wrapper_defs = (context-root-wrapper-definitions $source)
    let wrapper_defs = (
        record-wrapper-definitions $source
        | append (record-context-wrapper-definitions $source)
        | append (multi-param-record-wrapper-definitions $source)
    )

    mut changed = true
    loop {
        if not $changed {
            break
        }
        $changed = false

        for line in ($source | lines) {
            let bindings = (
                (record-context-bindings $line $context_names $bound_aliases $identity_wrappers $root_wrapper_defs)
                | append (record-wrapper-context-bindings $line $context_names $bound_aliases $identity_wrappers $wrapper_defs)
                | append (record-upsert-context-bindings $line $context_names $bound_aliases)
                | append (record-pipeline-flow-context-bindings $line $context_names $bound_aliases $identity_wrappers $root_wrapper_defs $aliases)
                | append (record-spread-context-bindings $line $aliases)
            )
            for binding in $bindings {
                let existing = (
                    $aliases
                    | where {|alias|
                        (
                            $alias.name == $binding.name
                            and $alias.field == $binding.field
                            and (($alias | get -o root | default "") == ($binding | get -o root | default ""))
                        )
                    }
                )
                if ($existing | is-empty) {
                    $aliases = ($aliases | append $binding)
                    $changed = true
                }
            }
        }
    }

    $aliases
}

def source-has-non-context-record-projection? [source: string context_names] {
    for line in ($source | lines) {
        for parsed in (
            $line
            | parse --regex '\$(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\.[A-Za-z_][A-Za-z0-9_-]*\.'
        ) {
            if $parsed.name not-in $context_names {
                return true
            }
        }
    }

    false
}

def record-context-projection-kernel-features [source: string target context_names] {
    if (
        not ($source | str contains "let")
        and not ($source | str contains "mut")
        and not ($source | str contains "def ")
    ) {
        return []
    }
    if not (source-has-non-context-record-projection? $source $context_names) {
        return []
    }

    mut features = []
    let aliases = (program-record-context-aliases $source $context_names)
    if ($aliases | is-empty) {
        return $features
    }

    for line in ($source | lines) {
        for alias in $aliases {
            let prefix = $"$($alias.name).($alias.field)."
            let root = ($alias | get -o root | default "")
            for raw_tail in (marker-tails-outside-simple-string $line $prefix) {
                let raw_access = if $root == "" {
                    $raw_tail
                } else {
                    $"($root).($raw_tail)"
                }
                $features = (
                    append-missing-kernel-features
                        $features
                        (context-access-kernel-features $raw_access $target)
                )
            }
        }
    }

    $features
}

def get-command-field-tail [segment: string] {
    let parsed = (
        $segment
        | str trim
        | parse --regex '^get\s+(?P<field>[A-Za-z_][A-Za-z0-9_-]*)(?P<tail>.*)$'
    )
    if ($parsed | is-empty) {
        return null
    }

    let row = ($parsed | first)
    {
        field: ($row.field | str trim)
        tail: ($row.tail | str trim)
    }
}

def context-root-from-get-input [input: string context_names bound_aliases] {
    let normalized_input = (trim-simple-parentheses ($input | str trim))
    let root = (context-root-from-value-token $normalized_input $context_names $bound_aliases)
    if $root != null {
        return $root
    }

    null
}

def get-segment-cell-path-tail [tail: string] {
    let parsed = (
        $tail
        | str trim
        | parse --regex '^[\)\s]*\.(?P<path>[A-Za-z_][A-Za-z0-9_.-]*)'
    )
    if ($parsed | is-empty) {
        return ""
    }

    normalize-context-path-token (($parsed | first).path)
}

def strip-leading-closure-header [line: string] {
    let trimmed = ($line | str trim)
    if not ($trimmed | str starts-with "{|") {
        return $trimmed
    }

    let parts = (($trimmed | str substring 2..) | split row "|")
    if ($parts | length) < 2 {
        return $trimmed
    }

    $parts | skip 1 | str join "|" | str trim
}

def context-get-projection-kernel-features [source: string target context_names] {
    if (not ($source | str contains "get")) or (not ($source | str contains "|")) {
        return []
    }
    let candidate_lines = (record-get-candidate-lines $source)
    if ($candidate_lines | is-empty) {
        return []
    }

    mut features = []
    let bound_aliases = (program-bound-context-root-aliases $source $context_names)

    for line in $candidate_lines {
        let trimmed = ($line | str trim)
        let segments = (split-pipeline-segments $trimmed)

        mut input = (($segments | first) | str trim)
        if ($input | str contains "=") {
            $input = (($input | split row "=" | last) | str trim)
        }
        mut root = null

        for segment in ($segments | skip 1) {
            let parsed = (get-command-field-tail $segment)
            if $parsed == null {
                continue
            }

            if $root == null {
                $root = (context-root-from-get-input $input $context_names $bound_aliases)
                if $root == null {
                    continue
                }
            }

            let field_path = (normalize-context-path-token $parsed.field)
            if $field_path != "" {
                $features = (
                    append-missing-kernel-features
                        $features
                        (context-access-kernel-features-from-root-path $root $field_path $target)
                )
                $root = if $root == "" { $field_path } else { $"($root).($field_path)" }
            }

            let tail_path = (get-segment-cell-path-tail $parsed.tail)
            if $tail_path != "" {
                $features = (
                    append-missing-kernel-features
                        $features
                        (context-access-kernel-features-from-root-path $root $tail_path $target)
                )
                $root = if $root == "" { $tail_path } else { $"($root).($tail_path)" }
            }
        }
    }

    $features
}

def context-access-kernel-features-from-root-path [root path: string target] {
    let normalized_path = (normalize-context-path-token $path)
    let raw_access = if $normalized_path == "" {
        $root
    } else if $root == "" {
        $normalized_path
    } else {
        $"($root).($normalized_path)"
    }
    if $raw_access == "" {
        return []
    }

    context-access-kernel-features $raw_access $target
}

def record-get-candidate-lines [source: string] {
    mut candidates = []

    for line in ($source | lines) {
        let trimmed = ($line | str trim)
        if $trimmed == "" or ($trimmed | str starts-with "#") {
            continue
        }
        let pipeline_line = (strip-leading-closure-header $trimmed)
        if (not ($pipeline_line | str contains "get")) or (not ($pipeline_line | str contains "|")) {
            continue
        }
        if not (line-invokes-command? $pipeline_line "get") {
            continue
        }

        let segments = (split-pipeline-segments $pipeline_line)
        if ($segments | length) < 2 {
            continue
        }

        mut input = (($segments | first) | str trim)
        if ($input | str contains "=") {
            $input = (($input | split row "=" | last) | str trim)
        }
        let normalized_input = (trim-simple-parentheses $input)
        if (
            ($normalized_input | str starts-with "$")
            or ($normalized_input | str starts-with "($")
            or ($normalized_input | str starts-with "{")
            or ($normalized_input | str starts-with "({")
            or not ((two-token-invocation $normalized_input) == null)
        ) {
            $candidates = ($candidates | append $pipeline_line)
        }
    }

    $candidates
}

def record-get-projection-kernel-features [source: string target context_names] {
    if (not ($source | str contains "get")) or (not ($source | str contains "|")) {
        return []
    }
    let candidate_lines = (record-get-candidate-lines $source)
    if ($candidate_lines | is-empty) {
        return []
    }

    mut features = []
    let bound_aliases = (program-bound-context-root-aliases $source $context_names)
    let record_aliases = (program-record-context-aliases $source $context_names)
    let identity_wrappers = (identity-wrapper-definitions $source)
    let root_wrapper_defs = (context-root-wrapper-definitions $source)
    let record_wrapper_defs = (
        record-wrapper-definitions $source
        | append (record-context-wrapper-definitions $source)
        | append (multi-param-record-wrapper-definitions $source)
    )

    for line in $candidate_lines {
        let trimmed = ($line | str trim)
        let segments = (split-pipeline-segments $trimmed)

        mut input = (($segments | first) | str trim)
        if ($input | str contains "=") {
            $input = (($input | split row "=" | last) | str trim)
        }
        mut root = null
        mut prefix_segments = []

        for segment in ($segments | skip 1) {
            let parsed = (get-command-field-tail $segment)
            if $parsed == null {
                if $root == null {
                    $prefix_segments = ($prefix_segments | append ($segment | str trim))
                }
                continue
            }

            if $root == null {
                $root = (
                    context-root-from-record-get
                        $input
                        $parsed.field
                        $record_aliases
                        $record_wrapper_defs
                        $context_names
                        $bound_aliases
                        $identity_wrappers
                        $root_wrapper_defs
                )
                if $root == null {
                    $root = (
                        context-root-from-record-pipeline-get
                            $input
                            $prefix_segments
                            $parsed.field
                            $record_aliases
                            $context_names
                            $bound_aliases
                            $identity_wrappers
                            $root_wrapper_defs
                    )
                }
                if $root == null {
                    continue
                }

                $features = (
                    append-missing-kernel-features
                        $features
                        (context-access-kernel-features-from-root-path $root "" $target)
                )
            } else {
                $features = (
                    append-missing-kernel-features
                        $features
                        (context-access-kernel-features-from-root-path $root $parsed.field $target)
                )
                let field_path = (normalize-context-path-token $parsed.field)
                if $field_path != "" {
                    $root = if $root == "" { $field_path } else { $"($root).($field_path)" }
                }
            }

            let tail_path = (get-segment-cell-path-tail $parsed.tail)
            if $tail_path != "" {
                $features = (
                    append-missing-kernel-features
                        $features
                        (context-access-kernel-features-from-root-path $root $tail_path $target)
                )
                $root = if $root == "" { $tail_path } else { $"($root).($tail_path)" }
            }
        }
    }

    $features
}

def source-has-context-root-projection? [source: string context_names] {
    for line in ($source | lines) {
        for context_name in $context_names {
            for raw_tail in (marker-tails-outside-simple-string $line $"$($context_name).") {
                let root = (normalize-context-field-token $raw_tail)
                if (context-projection-root? $root) {
                    return true
                }
            }
        }
    }

    if ($source | str contains "get") and ($source | str contains "|") {
        let aliases = (program-bound-context-root-aliases-base $source $context_names)
        if not ($aliases | is-empty) {
            return true
        }

        for line in (record-get-candidate-lines $source) {
            let segments = (split-pipeline-segments ($line | str trim))
            if ($segments | length) < 2 {
                continue
            }

            mut input = (($segments | first) | str trim)
            if ($input | str contains "=") {
                $input = (($input | split row "=" | last) | str trim)
            }
            if (context-root-from-get-input $input $context_names $aliases) != null {
                return true
            }
        }
    }

    if ($source | str contains "def ") {
        let root_wrappers = (context-root-wrapper-definitions $source)
        if not ($root_wrappers | is-empty) {
            return true
        }
    }

    false
}

def bound-context-projection-kernel-features [source: string target context_names] {
    if not ($source | str contains "let") and not ($source | str contains "mut") {
        return []
    }
    if not (source-has-context-root-projection? $source $context_names) {
        return []
    }

    mut features = []
    let aliases = (program-bound-context-root-aliases $source $context_names)
    if ($aliases | is-empty) {
        return $features
    }

    for line in ($source | lines) {
        for alias in $aliases {
            let prefix = $"$($alias.name)."
            for raw_tail in (marker-tails-outside-simple-string $line $prefix) {
                let raw_access = if $alias.root == "" {
                    $raw_tail
                } else {
                    $"($alias.root).($raw_tail)"
                }
                $features = (
                    append-missing-kernel-features
                        $features
                        (context-access-kernel-features $raw_access $target)
                )
            }
        }
    }

    $features
}

def program-kfunc-names [source: string] {
    mut names = []

    for line in ($source | lines) {
        for raw_call in (command-invocation-tails $line "kfunc-call") {
            let raw_name = ($raw_call | str trim | split row " " | first)
            let kfunc_name = (normalize-kfunc-name-token $raw_name)
            if $kfunc_name not-in $names {
                $names = ($names | append $kfunc_name)
            }
        }
    }

    $names
}

def program-helper-names [source: string] {
    mut names = []

    for line in ($source | lines) {
        for raw_call in (command-invocation-tails $line "helper-call") {
            let raw_name = ($raw_call | str trim | split row " " | first)
            let helper_name = (normalize-helper-name-token $raw_name)
            if $helper_name not-in $names {
                $names = ($names | append $helper_name)
            }
        }
    }

    $names
}

def program-map-kernel-features [source: string] {
    mut features = []
    mut map_kind_bindings = []

    for line in ($source | lines) {
        let trimmed = ($line | str trim)
        if $trimmed == "" or ($trimmed | str starts-with "#") {
            continue
        }

        if (line-invokes-command? $trimmed "helper-call") {
            let feature = (helper-call-map-kind-kernel-feature $trimmed $map_kind_bindings)
            if $feature != null {
                $features = (append-missing-kernel-features $features [$feature])
            }
            $map_kind_bindings = (update-helper-call-map-kind-bindings-for-line $map_kind_bindings $trimmed)
            continue
        }

        if not (line-invokes-map-kind-surface? $trimmed) {
            continue
        }

        let kind = (source-line-effective-map-kind $trimmed $map_kind_bindings)
        if $kind != null and $kind != "" {
            let feature = (map-kind-kernel-feature $kind)
            if $feature != null {
                $features = (append-missing-kernel-features $features [$feature])
            }
        }
        $map_kind_bindings = (update-map-kind-bindings-for-line $map_kind_bindings $trimmed)
    }

    if (source-invokes-command? $source "tail-call") {
        $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_MAP_PROG_ARRAY])
    }

    $features
}

def program-reserved-map-kernel-features [source: string] {
    mut features = []

    for line in ($source | lines) {
        let trimmed = ($line | str trim)
        if $trimmed == "" or ($trimmed | str starts-with "#") {
            continue
        }

        if (
            (line-invokes-command? $trimmed "emit")
            or (line-contains-code-marker? $trimmed " events")
        ) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_MAP_RINGBUF])
        }
        if (
            (line-invokes-command? $trimmed "count")
            or (line-invokes-command? $trimmed "histogram")
            or (line-invokes-command? $trimmed "start-timer")
            or (line-invokes-command? $trimmed "stop-timer")
        ) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_MAP_HASH])
        }
        if (line-contains-code-marker? $trimmed " user_events") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_MAP_USER_RINGBUF])
        }
        if (line-contains-code-marker? $trimmed " perf_events") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_MAP_PERF_EVENT_ARRAY])
        }
        if (
            (line-contains-code-marker? $trimmed " kstacks")
            or (line-contains-code-marker? $trimmed " ustacks")
            or (line-contains-code-marker? $trimmed ".kstack")
            or (line-contains-code-marker? $trimmed ".ustack")
        ) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_MAP_STACK_TRACE])
        }
    }

    $features
}

def program-map-value-kernel-features [source: string] {
    mut features = []

    for line in ($source | lines) {
        let trimmed = ($line | str trim)
        if not ((line-invokes-command? $trimmed "map-define") and (line-contains-code-marker? $trimmed "--value-type")) {
            continue
        }

        for entry in $MAP_VALUE_KERNEL_FEATURES {
            if ($trimmed | str contains $entry.token) {
                $features = (append-missing-kernel-features $features [$entry.feature])
            }
        }
        if ($trimmed | str contains "bpf_list_head:") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_MAP_VALUE_BPF_LIST_NODE])
        }
        if ($trimmed | str contains "bpf_rb_root:") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_MAP_VALUE_BPF_RB_NODE])
        }
    }

    $features
}

def variable-token-used-outside-simple-string? [text: string name: string] {
    for tail in (marker-tails-outside-simple-string $text $"$($name)") {
        if $tail == "" {
            return true
        }
        let first = ($tail | str substring 0..0)
        if $first in [" " "\t" "." "," ":" ")" "}" "]" "|" ";"] {
            return true
        }
    }

    false
}

def aggregate-rhs-contains-context-token? [rhs: string context_names context_root_aliases] {
    for context_name in $context_names {
        if (variable-token-used-outside-simple-string? $rhs $context_name) {
            return true
        }
    }

    for alias in $context_root_aliases {
        let name = ($alias | get -o name)
        if $name != null and (variable-token-used-outside-simple-string? $rhs $name) {
            return true
        }
    }

    false
}

def line-declares-readonly-aggregate-constant? [line: string context_names context_root_aliases] {
    let trimmed = ($line | str trim)
    if not (line-invokes-command? $trimmed "let") {
        return false
    }

    for assignment in (declaration-assignments $trimmed) {
        let rhs = (declaration-rhs-token $assignment)
        let aggregate_rhs = (trim-simple-parentheses $rhs)
        if (aggregate-rhs-contains-context-token? $aggregate_rhs $context_names $context_root_aliases) {
            continue
        }
        let compact = ($aggregate_rhs | str replace --all " " "")

        if (($compact | str starts-with "{") and $compact != "{}") {
            return true
        }
        if (($compact | str starts-with "[") and $compact != "[]") {
            return true
        }
        if (($compact | str starts-with "0x[") and $compact != "0x[]") {
            return true
        }
    }

    false
}

def line-declares-aggregate-literal? [line: string] {
    let trimmed = ($line | str trim)
    if not (line-invokes-command? $trimmed "let") {
        return false
    }

    for assignment in (declaration-assignments $trimmed) {
        let aggregate_rhs = (trim-simple-parentheses (declaration-rhs-token $assignment))
        let compact = ($aggregate_rhs | str replace --all " " "")

        if (($compact | str starts-with "{") and $compact != "{}") {
            return true
        }
        if (($compact | str starts-with "[") and $compact != "[]") {
            return true
        }
        if (($compact | str starts-with "0x[") and $compact != "0x[]") {
            return true
        }
    }

    false
}

def line-declares-aggregate-literal-with-variable? [line: string] {
    let trimmed = ($line | str trim)
    if not (line-invokes-command? $trimmed "let") {
        return false
    }

    for assignment in (declaration-assignments $trimmed) {
        let aggregate_rhs = (trim-simple-parentheses (declaration-rhs-token $assignment))
        let compact = ($aggregate_rhs | str replace --all " " "")

        if (
            (($compact | str starts-with "{") and $compact != "{}")
            or (($compact | str starts-with "[") and $compact != "[]")
            or (($compact | str starts-with "0x[") and $compact != "0x[]")
        ) and (line-contains-code-marker? $aggregate_rhs "$") {
            return true
        }
    }

    false
}

def line-invokes-global-command? [line: string] {
    for command in ["global-define" "global-get" "global-set"] {
        if (line-invokes-command? $line $command) {
            return true
        }
    }

    false
}

def line-declares-annotated-mut-global? [line: string] {
    for tail in (command-invocation-tails $line "mut") {
        let lhs = ($tail | split row "=" | first | str trim)
        if ($lhs | str contains ":") {
            return true
        }
    }

    false
}

def program-global-kernel-features [source: string] {
    mut variable_aggregate_lines = []

    for line in ($source | lines) {
        let trimmed = ($line | str trim)
        if ($trimmed | str starts-with "#") {
            continue
        }

        if (line-invokes-global-command? $trimmed) {
            return [$KERNEL_FEATURE_GLOBAL_DATA_SECTIONS]
        }

        if (line-declares-annotated-mut-global? $trimmed) {
            return [$KERNEL_FEATURE_GLOBAL_DATA_SECTIONS]
        }

        if not (line-declares-aggregate-literal? $trimmed) {
            continue
        }

        if not (line-declares-aggregate-literal-with-variable? $trimmed) {
            return [$KERNEL_FEATURE_GLOBAL_DATA_SECTIONS]
        }

        $variable_aggregate_lines = ($variable_aggregate_lines | append $trimmed)
    }

    if ($variable_aggregate_lines | is-empty) {
        return []
    }

    let context_names = (program-context-variable-names $source)
    let context_root_aliases = (program-bound-context-root-aliases $source $context_names)
    mut context_aliases = $context_root_aliases
    mut record_context_aliases_loaded = false

    for trimmed in $variable_aggregate_lines {
        if not (line-declares-readonly-aggregate-constant? $trimmed $context_names $context_aliases) {
            continue
        }

        if not $record_context_aliases_loaded {
            $context_aliases = (
                $context_aliases
                | append (program-record-context-aliases $source $context_names)
            )
            $record_context_aliases_loaded = true
        }
        if not (line-declares-readonly-aggregate-constant? $trimmed $context_names $context_aliases) {
            continue
        }

        return [$KERNEL_FEATURE_GLOBAL_DATA_SECTIONS]
    }

    []
}

def program-helper-kernel-features [source: string] {
    mut features = []

    for helper_name in (program-helper-names $source) {
        let feature = (helper-kernel-feature $helper_name)
        if $feature != null {
            $features = (append-missing-kernel-features $features [$feature])
        }
    }

    $features
}

def program-kfunc-kernel-features [source: string target] {
    mut features = []
    let target_text = ($target | default "")
    let cgroup_sock_addr_hook = if ($target_text | str starts-with "cgroup_sock_addr:") {
        $target_text | split row ":" | last
    } else {
        ""
    }
    let has_kfunc_call = ($source | str contains "kfunc-call")
    let may_assign_unix_sun_path = (
        ($target_text | str starts-with "cgroup_sock_addr:")
        and ($cgroup_sock_addr_hook | str ends-with "_unix")
        and ($source | str contains "sun_path")
    )

    if not $has_kfunc_call and not $may_assign_unix_sun_path {
        return []
    }

    if $has_kfunc_call {
        for kfunc_name in (program-kfunc-names $source) {
            let feature = (program-kfunc-kernel-feature $kfunc_name $target_text)
            if $feature != null {
                $features = (append-missing-kernel-features $features [$feature])
            }
        }
    }

    if not $may_assign_unix_sun_path {
        return $features
    }

    let context_names = (program-context-variable-names $source)
    let record_context_aliases = (program-record-context-aliases $source $context_names)

    for line in ($source | lines) {
        let trimmed = ($line | str trim)
        if (
            (line-assigns-context-field? $trimmed $context_names ["sun_path"])
            or (line-assigns-record-context-field? $trimmed $record_context_aliases ["sun_path"] [""])
        ) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_KFUNC_BPF_SOCK_ADDR_SET_SUN_PATH])
        }
    }

    $features
}

def callback-trusted-btf-param-indexes [helper_name: string] {
    if $helper_name in ["bpf_timer_set_callback" "bpf_for_each_map_elem"] {
        return [0]
    }
    if $helper_name == "bpf_find_vma" {
        return [0 1]
    }

    []
}

def helper-call-name-from-line [line: string] {
    let tails = (command-invocation-tails $line "helper-call")
    if ($tails | is-empty) {
        return null
    }

    normalize-helper-name-token (($tails | first | str trim | split row " " | first))
}

def closure-param-names-from-line [line: string] {
    let closure_parts = ($line | split row "{|")
    if ($closure_parts | length) <= 1 {
        return []
    }

    let raw_closure = ($closure_parts | skip 1 | first)
    let param_parts = ($raw_closure | split row "|")
    if ($param_parts | length) == 0 {
        return []
    }

    $param_parts
    | first
    | str replace --all "," " "
    | split row " "
    | each {|param| $param | str trim }
    | where {|param| $param != "" }
}

def helper-call-trusted-btf-callback-roots [line: string] {
    let helper_name = (helper-call-name-from-line $line)
    if $helper_name == null {
        return []
    }

    let trusted_indexes = (callback-trusted-btf-param-indexes $helper_name)
    if ($trusted_indexes | is-empty) {
        return []
    }

    let params = (closure-param-names-from-line $line)
    if ($params | is-empty) {
        return []
    }

    mut roots = []
    for idx in $trusted_indexes {
        if $idx < ($params | length) {
            let param = ($params | get $idx)
            if $param not-in $roots {
                $roots = ($roots | append $param)
            }
        }
    }

    $roots
}

def program-callback-btf-kernel-features [source: string] {
    mut features = []
    mut trusted_roots = []

    for line in ($source | lines) {
        let callback_roots = (helper-call-trusted-btf-callback-roots $line)
        if not ($callback_roots | is-empty) {
            $trusted_roots = $callback_roots
        }

        for root in $trusted_roots {
            let prefix = $"$($root)."
            let parts = ($line | split row $prefix)
            if ($parts | length) <= 1 {
                continue
            }

            for raw_tail in ($parts | skip 1) {
                let field = (normalize-context-field-token $raw_tail)
                if $field != "" {
                    # Trusted-BTF callback scalar projections lower as direct
                    # loads, not probe_read_kernel helper calls.
                    continue
                }
            }
        }

        let trimmed = ($line | str trim)
        if not ($trusted_roots | is-empty) and ($trimmed | str starts-with "}") {
            $trusted_roots = []
        }
    }

    $features
}

def program-context-field-kernel-features [source: string target] {
    mut features = []
    let context_names = (program-context-variable-names $source)

    for line in ($source | lines) {
        for context_name in $context_names {
            for raw_access in (marker-tails-outside-simple-string $line $"$($context_name).") {
                let field = (normalize-context-field-token $raw_access)
                if $field == "" {
                    continue
                }

                $features = (
                    append-missing-kernel-features
                        $features
                        (context-access-kernel-features $raw_access $target)
                )
            }
        }
    }

    $features = (append-missing-kernel-features $features (user-function-context-field-kernel-features $source $target $context_names))
    $features = (append-missing-kernel-features $features (multi-param-user-function-context-field-kernel-features $source $target $context_names))
    $features = (append-missing-kernel-features $features (bound-context-projection-kernel-features $source $target $context_names))
    $features = (append-missing-kernel-features $features (record-context-projection-kernel-features $source $target $context_names))
    $features = (append-missing-kernel-features $features (context-get-projection-kernel-features $source $target $context_names))
    $features = (append-missing-kernel-features $features (record-get-projection-kernel-features $source $target $context_names))

    $features
}

def program-surface-kernel-features [source: string target] {
    mut features = []
    let target_text = ($target | default "")
    let context_names = (program-context-variable-names $source)
    mut record_context_aliases = []
    mut record_context_aliases_loaded = false
    mut map_kind_bindings = []
    let target_uses_skb_cgroup_helper = (
        ($target_text | str starts-with "tc_action:")
        or ($target_text | str starts-with "tc:")
        or ($target_text | str starts-with "tcx:")
        or ($target_text | str starts-with "netkit:")
        or ($target_text | str starts-with "lwt_in:")
        or ($target_text | str starts-with "lwt_out:")
        or ($target_text | str starts-with "lwt_xmit:")
        or ($target_text | str starts-with "lwt_seg6local:")
    )

    if (source-invokes-command? $source "tail-call") {
        $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_TAIL_CALL])
    }
    if (source-invokes-command-with-tail-prefix? $source "random" "int") {
        $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_GET_PRANDOM_U32])
    }
    if (source-invokes-command? $source "read-str") {
        $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_PROBE_READ_USER_STR])
    }
    if (source-invokes-command? $source "read-kernel-str") {
        $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_PROBE_READ_KERNEL_STR])
    }
    if (source-invokes-command? $source "emit") {
        $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_RINGBUF_OUTPUT])
    }
    if ((source-invokes-command? $source "count") or (source-invokes-command? $source "histogram")) {
        $features = (append-missing-kernel-features $features [
            $KERNEL_FEATURE_BPF_MAP_LOOKUP_ELEM
            $KERNEL_FEATURE_BPF_MAP_UPDATE_ELEM
        ])
    }
    if (source-invokes-command? $source "start-timer") {
        $features = (append-missing-kernel-features $features [
            $KERNEL_FEATURE_BPF_GET_CURRENT_PID_TGID
            $KERNEL_FEATURE_BPF_KTIME_GET_NS
            $KERNEL_FEATURE_BPF_MAP_UPDATE_ELEM
        ])
    }
    if (source-invokes-command? $source "stop-timer") {
        $features = (append-missing-kernel-features $features [
            $KERNEL_FEATURE_BPF_GET_CURRENT_PID_TGID
            $KERNEL_FEATURE_BPF_MAP_LOOKUP_ELEM
            $KERNEL_FEATURE_BPF_KTIME_GET_NS
            $KERNEL_FEATURE_BPF_MAP_DELETE_ELEM
        ])
    }
    for line in ($source | lines) {
        if (line-invokes-command? $line "helper-call") {
            $map_kind_bindings = (
                update-helper-call-map-kind-bindings-for-line
                    $map_kind_bindings
                    ($line | str trim)
            )
            continue
        }

        let trimmed = ($line | str trim)
        let assigns_sysctl_new_value = (
            line-assigns-context-field? $trimmed $context_names ["new_value" "sysctl_new_value"]
        )
        let target_supports_ctx_sk_assign = (
            ($target_text | str starts-with "sk_lookup:")
            or ($target_text | str starts-with "tc_action:")
            or (($target_text | str starts-with "tc:") and ($target_text | str contains ":ingress"))
            or (($target_text | str starts-with "tcx:") and ($target_text | str contains ":ingress"))
        )
        let may_have_record_context_helper_write = (
            (($target_text | str starts-with "cgroup_sysctl:") and (
                ($trimmed | str contains ".new_value")
                or ($trimmed | str contains ".sysctl_new_value")
            ))
            or ($target_supports_ctx_sk_assign and (
                ($trimmed | str contains ".sk")
                or ($trimmed | str contains ".sock")
                or ($trimmed | str contains ".socket")
            ))
            or (($target_text | str starts-with "sock_ops:") and ($trimmed | str contains ".cb_flags"))
        )
        if $may_have_record_context_helper_write and not $record_context_aliases_loaded {
            $record_context_aliases = (program-record-context-aliases $source $context_names)
            $record_context_aliases_loaded = true
        }
        let assigns_ctx_sk = (
            line-assigns-context-field? $trimmed $context_names ["sk" "sock" "socket"]
        )
        let assigns_record_ctx_sk = (
            $target_supports_ctx_sk_assign
            and (line-assigns-record-context-field? $trimmed $record_context_aliases ["sk" "sock" "socket"] [""])
        )
        let assigns_record_sysctl_new_value = (
            ($target_text | str starts-with "cgroup_sysctl:")
            and (line-assigns-record-context-field? $trimmed $record_context_aliases ["new_value" "sysctl_new_value"] [""])
        )
        let assigns_record_sock_ops_cb_flags = (
            ($target_text | str starts-with "sock_ops:")
            and (line-assigns-record-context-field? $trimmed $record_context_aliases ["cb_flags"] [""])
        )
        let inferred_map_kind = (source-line-effective-map-kind $trimmed $map_kind_bindings)
        let map_kind = if $inferred_map_kind == null { "hash" } else { $inferred_map_kind }
        if (line-invokes-command? $trimmed "map-get") and (generic-map-lookup-kind? $map_kind) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MAP_LOOKUP_ELEM])
        }
        if (line-invokes-command? $trimmed "map-put") and (generic-map-update-kind? $map_kind) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MAP_UPDATE_ELEM])
        }
        if ($target_text | str starts-with "sock_ops:") and (line-invokes-command? $trimmed "map-put") {
            if $map_kind == "sockmap" {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SOCK_MAP_UPDATE])
            } else if $map_kind == "sockhash" {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SOCK_HASH_UPDATE])
            }
        }
        if (line-invokes-command? $trimmed "map-delete") and (generic-map-delete-kind? $map_kind) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MAP_DELETE_ELEM])
        }
        if ((line-invokes-command? $trimmed "map-get") or (line-invokes-command? $trimmed "map-contains")) {
            let local_storage_feature = (local-storage-get-helper-kernel-feature $map_kind)
            if $local_storage_feature != null {
                $features = (append-missing-kernel-features $features [$local_storage_feature])
            }
        }
        if (line-invokes-command? $trimmed "map-delete") {
            let local_storage_feature = (local-storage-delete-helper-kernel-feature $map_kind)
            if $local_storage_feature != null {
                $features = (append-missing-kernel-features $features [$local_storage_feature])
            }
        }
        if (line-invokes-command? $trimmed "map-push") and ($map_kind in ["queue" "stack" "bloom-filter"]) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MAP_PUSH_ELEM])
        }
        if (line-invokes-command? $trimmed "map-peek") and ($map_kind in ["queue" "stack"]) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MAP_PEEK_ELEM])
        }
        if (line-invokes-command? $trimmed "map-pop") and ($map_kind in ["queue" "stack"]) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MAP_POP_ELEM])
        }
        if (line-invokes-command? $trimmed "map-contains") {
            if $map_kind == "bloom-filter" {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MAP_PEEK_ELEM])
            } else if (generic-map-lookup-kind? $map_kind) {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MAP_LOOKUP_ELEM])
            }
        }
        if (line-invokes-command? $trimmed "redirect-map") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_REDIRECT_MAP])
        }
        if (line-invokes-command? $trimmed "map-contains") and ($map_kind == "cgroup-array") {
            if $target_uses_skb_cgroup_helper {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SKB_UNDER_CGROUP])
            } else {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_CURRENT_TASK_UNDER_CGROUP])
            }
        }
        if (line-invokes-command? $trimmed "assign-socket") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SK_ASSIGN])
            let socket_context_feature = (context-field-kernel-feature "sk" $target)
            if $socket_context_feature != null {
                $features = (append-missing-kernel-features $features [$socket_context_feature])
            }
        }
        if ($target_text | str starts-with "cgroup_sysctl:") and ($assigns_sysctl_new_value or $assigns_record_sysctl_new_value) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SYSCTL_SET_NEW_VALUE])
        }
        if $target_supports_ctx_sk_assign and ($assigns_ctx_sk or $assigns_record_ctx_sk) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SK_ASSIGN])
        }
        if (line-invokes-command-with-tail-prefix? $trimmed "adjust-message" "--apply") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MSG_APPLY_BYTES])
        }
        if (line-invokes-command-with-tail-prefix? $trimmed "adjust-message" "--cork") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MSG_CORK_BYTES])
        }
        if (line-invokes-command-with-tail-prefix? $trimmed "adjust-message" "--pull") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MSG_PULL_DATA])
        }
        if (line-invokes-command-with-tail-prefix? $trimmed "adjust-message" "--push") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MSG_PUSH_DATA])
        }
        if (line-invokes-command-with-tail-prefix? $trimmed "adjust-message" "--pop") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MSG_POP_DATA])
        }
        if (line-invokes-command-with-tail-prefix? $trimmed "adjust-packet" "--pull") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SKB_PULL_DATA])
        }
        if (line-invokes-command? $trimmed "redirect-socket") {
            if ($target_text | str starts-with "sk_msg:") {
                if $map_kind == "sockhash" {
                    $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MSG_REDIRECT_HASH])
                } else {
                    $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MSG_REDIRECT_MAP])
                }
            } else if ($target_text | str starts-with "sk_skb:") or ($target_text | str starts-with "sk_skb_parser:") {
                if $map_kind == "sockhash" {
                    $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SK_REDIRECT_HASH])
                } else {
                    $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SK_REDIRECT_MAP])
                }
            } else if ($target_text | str starts-with "sk_reuseport:") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SK_SELECT_REUSEPORT])
            }
        }
        if ($target_text | str starts-with "sock_ops:") and ((line-assigns-context-field? $trimmed $context_names ["cb_flags"]) or $assigns_record_sock_ops_cb_flags) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SOCK_OPS_CB_FLAGS_SET])
        }
        if ($target_text | str starts-with "xdp:") {
            if (line-invokes-command-with-tail-prefix? $trimmed "adjust-packet" "--head") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_XDP_ADJUST_HEAD])
            }
            if (line-invokes-command-with-tail-prefix? $trimmed "adjust-packet" "--meta") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_XDP_ADJUST_META])
            }
            if (line-invokes-command-with-tail-prefix? $trimmed "adjust-packet" "--tail") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_XDP_ADJUST_TAIL])
            }
        } else {
            if (line-invokes-command-with-tail-prefix? $trimmed "adjust-packet" "--head") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SKB_CHANGE_HEAD])
            }
            if (line-invokes-command-with-tail-prefix? $trimmed "adjust-packet" "--tail") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SKB_CHANGE_TAIL])
            }
            if (line-invokes-command-with-tail-prefix? $trimmed "adjust-packet" "--room") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SKB_ADJUST_ROOM])
            }
        }
        if (line-invokes-command? $trimmed "redirect") {
            if ($trimmed | str contains "--peer") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_REDIRECT_PEER])
            } else if ($trimmed | str contains "--neigh") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_REDIRECT_NEIGH])
            } else if (
                ($target_text | str starts-with "xdp:")
                or ($target_text | str starts-with "tc_action:")
                or ($target_text | str starts-with "tc:")
                or ($target_text | str starts-with "tcx:")
                or ($target_text | str starts-with "netkit:")
                or ($target_text | str starts-with "lwt_xmit:")
            ) {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_REDIRECT])
            }
        }
        $map_kind_bindings = (update-map-kind-bindings-for-line $map_kind_bindings $trimmed)
    }

    $features
}

def struct-ops-target-sleepable? [target: string] {
    if not ($target | str starts-with "struct_ops:sched_ext_ops.") {
        return false
    }

    let callback = (
        $target
        | split row "struct_ops:sched_ext_ops."
        | get 1
        | split row ":"
        | first
    )

    $callback in $SCHED_EXT_SLEEPABLE_CALLBACKS
}

def program-struct-ops-kernel-features [source: string target] {
    let target_text = ($target | default "")
    if not ($target_text | str starts-with "struct_ops:sched_ext_ops") {
        return []
    }

    mut features = []
    if (struct-ops-target-sleepable? $target_text) {
        $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_SLEEPABLE_PROGRAM])
    }

    for line in ($source | lines) {
        let trimmed = ($line | str trim)
        for callback in $SCHED_EXT_SLEEPABLE_CALLBACKS {
            if ($trimmed | str starts-with $"($callback):") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_SLEEPABLE_PROGRAM])
            }
        }
    }

    $features
}

def target-kernel-features [target] {
    if $target == null {
        return []
    }

    mut features = []

    if ($target | str starts-with "fentry.s:") or ($target | str starts-with "fexit.s:") or ($target | str starts-with "fmod_ret.s:") {
        $features = ($features | append $KERNEL_FEATURE_KERNEL_BTF)
        $features = ($features | append $KERNEL_FEATURE_PROG_TRACING)
        $features = ($features | append $KERNEL_FEATURE_BPF_TRAMPOLINE)
        $features = ($features | append $KERNEL_FEATURE_SLEEPABLE_PROGRAM)
    } else if ($target | str starts-with "fentry:") or ($target | str starts-with "fexit:") or ($target | str starts-with "fmod_ret:") {
        $features = ($features | append $KERNEL_FEATURE_KERNEL_BTF)
        $features = ($features | append $KERNEL_FEATURE_PROG_TRACING)
        $features = ($features | append $KERNEL_FEATURE_BPF_TRAMPOLINE)
    } else if ($target | str starts-with "tp_btf:") {
        $features = ($features | append $KERNEL_FEATURE_KERNEL_BTF)
        $features = ($features | append $KERNEL_FEATURE_PROG_TRACING)
    } else if ($target | str starts-with "lsm_cgroup:") {
        $features = ($features | append $KERNEL_FEATURE_KERNEL_BTF)
        $features = ($features | append $KERNEL_FEATURE_PROG_TRACING)
        $features = ($features | append $KERNEL_FEATURE_BPF_TRAMPOLINE)
        $features = ($features | append $KERNEL_FEATURE_PROG_LSM)
        $features = ($features | append $KERNEL_FEATURE_PROG_LSM_CGROUP)
    } else if ($target | str starts-with "lsm.s:") {
        $features = ($features | append $KERNEL_FEATURE_KERNEL_BTF)
        $features = ($features | append $KERNEL_FEATURE_PROG_TRACING)
        $features = ($features | append $KERNEL_FEATURE_BPF_TRAMPOLINE)
        $features = ($features | append $KERNEL_FEATURE_PROG_LSM)
        $features = ($features | append $KERNEL_FEATURE_SLEEPABLE_PROGRAM)
    } else if ($target | str starts-with "lsm:") {
        $features = ($features | append $KERNEL_FEATURE_KERNEL_BTF)
        $features = ($features | append $KERNEL_FEATURE_PROG_TRACING)
        $features = ($features | append $KERNEL_FEATURE_BPF_TRAMPOLINE)
        $features = ($features | append $KERNEL_FEATURE_PROG_LSM)
    } else if ($target | str starts-with "struct_ops:") {
        $features = ($features | append $KERNEL_FEATURE_KERNEL_BTF)
        $features = ($features | append $KERNEL_FEATURE_BPF_TRAMPOLINE)
        $features = ($features | append $KERNEL_FEATURE_PROG_STRUCT_OPS)
        if ($target | str contains "tcp_congestion_ops") {
            $features = ($features | append $KERNEL_FEATURE_STRUCT_OPS_TCP_CONGESTION)
        }
        if ($target | str contains "hid_bpf_ops") {
            $features = ($features | append $KERNEL_FEATURE_STRUCT_OPS_HID_BPF)
        }
        if ($target | str contains "sched_ext_ops") {
            $features = ($features | append $KERNEL_FEATURE_STRUCT_OPS_SCHED_EXT)
        }
        if ($target | str contains "Qdisc_ops") {
            $features = ($features | append $KERNEL_FEATURE_STRUCT_OPS_QDISC)
        }
        if (struct-ops-target-sleepable? $target) {
            $features = ($features | append $KERNEL_FEATURE_SLEEPABLE_PROGRAM)
        }
    } else if ($target | str starts-with "kprobe.multi:") or ($target | str starts-with "kretprobe.multi:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_KPROBE)
        $features = ($features | append $KERNEL_FEATURE_ATTACH_KPROBE_MULTI)
    } else if ($target | str starts-with "kprobe:") or ($target | str starts-with "kretprobe:") or ($target | str starts-with "ksyscall:") or ($target | str starts-with "kretsyscall:") or ($target | str starts-with "uprobe:") or ($target | str starts-with "uprobe.s:") or ($target | str starts-with "uretprobe:") or ($target | str starts-with "uretprobe.s:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_KPROBE)
        if ($target | str starts-with "uprobe.s:") or ($target | str starts-with "uretprobe.s:") {
            $features = ($features | append $KERNEL_FEATURE_SLEEPABLE_PROGRAM)
        }
    } else if ($target | str starts-with "uprobe.multi:") or ($target | str starts-with "uprobe.multi.s:") or ($target | str starts-with "uretprobe.multi:") or ($target | str starts-with "uretprobe.multi.s:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_KPROBE)
        $features = ($features | append $KERNEL_FEATURE_ATTACH_UPROBE_MULTI)
        if ($target | str starts-with "uprobe.multi.s:") or ($target | str starts-with "uretprobe.multi.s:") {
            $features = ($features | append $KERNEL_FEATURE_SLEEPABLE_PROGRAM)
        }
    } else if ($target | str starts-with "raw_tracepoint.w:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_RAW_TRACEPOINT)
        $features = ($features | append $KERNEL_FEATURE_PROG_RAW_TRACEPOINT_WRITABLE)
    } else if ($target | str starts-with "raw_tracepoint:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_RAW_TRACEPOINT)
    } else if ($target | str starts-with "tracepoint:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_TRACEPOINT)
    } else if ($target | str starts-with "perf_event:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_PERF_EVENT)
    } else if ($target | str starts-with "xdp:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_XDP)
        let xdp_parts = ($target | split row ":")
        if ("devmap" in $xdp_parts) {
            $features = ($features | append $KERNEL_FEATURE_XDP_ATTACH_DEVMAP)
        } else if ("cpumap" in $xdp_parts) {
            $features = ($features | append $KERNEL_FEATURE_XDP_ATTACH_CPUMAP)
        } else if ("hw" in $xdp_parts) or ("hardware" in $xdp_parts) or ("offload" in $xdp_parts) {
            $features = ($features | append $KERNEL_FEATURE_XDP_ATTACH_HW)
        } else if ("drv" in $xdp_parts) or ("driver" in $xdp_parts) or ("native" in $xdp_parts) {
            $features = ($features | append $KERNEL_FEATURE_XDP_ATTACH_DRV)
        } else {
            $features = ($features | append $KERNEL_FEATURE_XDP_ATTACH_SKB)
        }
        if ("frags" in $xdp_parts) {
            $features = ($features | append $KERNEL_FEATURE_XDP_MULTI_BUFFER)
        }
    } else if ($target | str starts-with "socket_filter:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_SOCKET_FILTER)
    } else if ($target | str starts-with "tc:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_SCHED_CLS)
    } else if ($target | str starts-with "tc_action:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_SCHED_ACT)
    } else if ($target | str starts-with "tcx:") {
        $features = ($features | append $KERNEL_FEATURE_ATTACH_TCX)
    } else if ($target | str starts-with "netkit:") {
        $features = ($features | append $KERNEL_FEATURE_ATTACH_NETKIT)
    } else if ($target | str starts-with "flow_dissector:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_FLOW_DISSECTOR)
    } else if ($target | str starts-with "netfilter:") {
        $features = ($features | append $KERNEL_FEATURE_NETFILTER_LINK)
        let netfilter_parts = ($target | split row ":")
        if ("defrag" in $netfilter_parts) {
            $features = ($features | append $KERNEL_FEATURE_NETFILTER_DEFRAG)
        }
    } else if ($target | str starts-with "lwt_seg6local:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_LWT)
        $features = ($features | append $KERNEL_FEATURE_PROG_LWT_SEG6LOCAL)
    } else if ($target | str starts-with "lwt_in:") or ($target | str starts-with "lwt_out:") or ($target | str starts-with "lwt_xmit:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_LWT)
    } else if ($target | str starts-with "sk_lookup:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_SK_LOOKUP)
    } else if ($target | str starts-with "sk_msg:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_SK_MSG)
    } else if ($target | str starts-with "sk_skb:") or ($target | str starts-with "sk_skb_parser:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_SK_SKB)
    } else if ($target | str starts-with "sk_reuseport:") {
        $features = ($features | append $KERNEL_FEATURE_SK_REUSEPORT_ATTACH)
        let sk_reuseport_parts = ($target | split row ":")
        if ("migrate" in $sk_reuseport_parts) {
            $features = ($features | append $KERNEL_FEATURE_SK_REUSEPORT_MIGRATION)
        }
    } else if ($target | str starts-with "cgroup_skb:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_CGROUP_SKB)
    } else if ($target | str starts-with "cgroup_sock_addr:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_CGROUP_SOCK_ADDR)
        let cgroup_sock_addr_hook = ($target | split row ":" | last)
        if ($cgroup_sock_addr_hook | str ends-with "_unix") {
            $features = ($features | append $KERNEL_FEATURE_ATTACH_CGROUP_UNIX_SOCK_ADDR)
        }
    } else if ($target | str starts-with "cgroup_sockopt:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_CGROUP_SOCKOPT)
    } else if ($target | str starts-with "cgroup_sock:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_CGROUP_SOCK)
    } else if ($target | str starts-with "cgroup_device:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_CGROUP_DEVICE)
    } else if ($target | str starts-with "cgroup_sysctl:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_CGROUP_SYSCTL)
    } else if ($target | str starts-with "sock_ops:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_SOCK_OPS)
    } else if ($target | str starts-with "lirc_mode2:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_LIRC_MODE2)
    } else if ($target | str starts-with "iter:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_ITER)
        let iter_target = ($target | split row ":" | get 1)
        let iter_feature = (iter-target-kernel-feature $iter_target)
        if $iter_feature != null {
            $features = ($features | append $iter_feature)
        }
    } else if ($target | str starts-with "syscall:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_SYSCALL)
    } else if ($target | str starts-with "freplace:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_EXTENSION)
    }

    $features
}

def source-statement-lines [source: string] {
    $source
    | lines
    | each {|line| $line | str trim }
    | where {|line| $line != "" and not ($line | str starts-with "#") }
}

def line-has-statement-keyword? [line: string keyword: string] {
    not ((command-invocation-tails $line $keyword) | is-empty)
}

def line-has-callback-subprogram-literal? [line: string] {
    for command in ["helper-call" "kfunc-call"] {
        for raw_call in (command-invocation-tails $line $command) {
            if (line-contains-code-marker? $raw_call "{|") {
                return true
            }
        }
    }

    false
}

def program-language-kernel-features [source: string] {
    mut features = []

    for line in (source-statement-lines $source) {
        if (line-has-statement-keyword? $line "def") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SUBPROGRAM_CALLS])
        }

        if (line-has-callback-subprogram-literal? $line) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SUBPROGRAM_CALLS])
        }

        if (line-has-statement-keyword? $line "for") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BOUNDED_LOOPS])
        }
    }

    $features
}

def fixture-kernel-features [fixture] {
    mut features = (optional $fixture kernel_features [])
    $features = (append-missing-kernel-features $features (target-kernel-features ($fixture | get -o target)))
    let program = (fixture-program $fixture)
    $features = (append-missing-kernel-features $features (program-language-kernel-features $program))
    $features = (append-missing-kernel-features $features (program-map-kernel-features $program))
    $features = (append-missing-kernel-features $features (program-reserved-map-kernel-features $program))
    $features = (append-missing-kernel-features $features (program-map-value-kernel-features $program))
    $features = (append-missing-kernel-features $features (program-global-kernel-features $program))
    $features = (append-missing-kernel-features $features (program-helper-kernel-features $program))
    $features = (append-missing-kernel-features $features (program-kfunc-kernel-features $program ($fixture | get -o target)))
    $features = (append-missing-kernel-features $features (program-callback-btf-kernel-features $program))
    $features = (append-missing-kernel-features $features (program-context-field-kernel-features $program ($fixture | get -o target)))
    $features = (append-missing-kernel-features $features (program-surface-kernel-features $program ($fixture | get -o target)))
    $features = (append-missing-kernel-features $features (program-struct-ops-kernel-features $program ($fixture | get -o target)))

    let legacy_min_kernel = ($fixture | get -o min_kernel)
    let legacy_min_kernel_source = ($fixture | get -o min_kernel_source)
    if $legacy_min_kernel != null {
        $features = (
            $features
            | append {
                key: "fixture"
                min_kernel: $legacy_min_kernel
                source: $legacy_min_kernel_source
            }
        )
    }

    $features
}

def effective-min-kernel-from-features [features] {
    let versions = (
        $features
        | each {|feature| $feature.min_kernel }
    )

    kernel-version-max $versions
}

def effective-max-kernel-exclusive-from-features [features] {
    let versions = (
        $features
        | each {|feature| $feature | get -o max_kernel_exclusive }
        | where {|version| $version != null and $version != "" }
    )

    kernel-version-min $versions
}

def effective-max-kernel-exclusive-sources-from-features [features] {
    let max_kernel = (effective-max-kernel-exclusive-from-features $features)
    if $max_kernel == null {
        return []
    }

    $features
    | where {|feature| ($feature | get -o max_kernel_exclusive) == $max_kernel }
    | each {|feature| $feature | get -o max_kernel_exclusive_source }
    | where {|source| $source != null and $source != "" }
    | uniq
}

def effective-min-kernel-sources-from-features [features] {
    let min_kernel = (effective-min-kernel-from-features $features)
    if $min_kernel == null {
        return []
    }

    $features
    | where {|feature| $feature.min_kernel == $min_kernel }
    | each {|feature| $feature.source }
    | uniq
}

def kernel-feature-compatibility [min_kernel max_kernel kernel_release] {
    if $kernel_release == null or ($min_kernel == null and $max_kernel == null) {
        return {
            compatible: true
            required: ""
            reason: ""
        }
    }

    let too_old = ($min_kernel != null and not (kernel-version-at-least $kernel_release $min_kernel))
    let too_new = ($max_kernel != null and not (kernel-version-before $kernel_release $max_kernel))
    let compatible = (not $too_old and not $too_new)
    let reason = if $too_old {
        $"kernel>=($min_kernel)"
    } else if $too_new {
        $"kernel<($max_kernel)"
    } else {
        ""
    }
    {
        compatible: $compatible
        required: ($min_kernel | default "")
        maximum_exclusive: ($max_kernel | default "")
        reason: $reason
    }
}

def fixture-effective-min-kernel [fixture] {
    effective-min-kernel-from-features (fixture-kernel-features $fixture)
}

def fixture-effective-max-kernel-exclusive [fixture] {
    effective-max-kernel-exclusive-from-features (fixture-kernel-features $fixture)
}

def fixture-effective-min-kernel-sources [fixture] {
    effective-min-kernel-sources-from-features (fixture-kernel-features $fixture)
}

def fixture-kernel-compatibility [fixture kernel_release] {
    let features = (fixture-kernel-features $fixture)
    kernel-feature-compatibility (effective-min-kernel-from-features $features) (effective-max-kernel-exclusive-from-features $features) $kernel_release
}

def test-lane-rank [lane: string] {
    if $lane == "host-safe" {
        0
    } else if $lane == "host-gated" {
        1
    } else if $lane == "dry-run" {
        2
    } else if $lane == "vm-only" {
        3
    } else {
        0
    }
}

def stricter-test-lane [left: string right: string] {
    if (test-lane-rank $right) > (test-lane-rank $left) {
        $right
    } else {
        $left
    }
}

def aggregate-test-lanes [lanes] {
    mut lane = "host-safe"

    for candidate in $lanes {
        if $candidate != null and $candidate != "" {
            $lane = (stricter-test-lane $lane $candidate)
        }
    }

    $lane
}

def kernel-feature-default-test-lane [feature] {
    let key = ($feature | get -o key | default "")

    if ($key | str starts-with "struct_ops:") {
        return "vm-only"
    }

    if $key in [
        "program:BPF_PROG_TYPE_STRUCT_OPS"
        "program:BPF_PROG_TYPE_LWT"
        "attach:netfilter-link"
    ] {
        return "vm-only"
    }

    if $key in [
        "program:BPF_PROG_TYPE_EXT"
        "program:BPF_PROG_TYPE_SYSCALL"
    ] {
        return "dry-run"
    }

    if $key in [
        "section:raw_tracepoint.w"
        "program:BPF_PROG_TYPE_SOCKET_FILTER"
        "program:BPF_PROG_TYPE_XDP"
        "attach:xdp-skb"
        "attach:xdp-drv"
        "attach:xdp-hw"
        "attach:BPF_XDP_DEVMAP"
        "attach:BPF_XDP_CPUMAP"
        "section:xdp.frags"
        "program:BPF_PROG_TYPE_SCHED_CLS"
        "program:BPF_PROG_TYPE_SCHED_ACT"
        "program:BPF_PROG_TYPE_SK_LOOKUP"
        "attach:BPF_LSM_CGROUP"
        "program:BPF_PROG_TYPE_FLOW_DISSECTOR"
        "attach:tcx"
        "attach:netkit"
        "attach:netfilter-defrag"
        "program:BPF_PROG_TYPE_LWT_SEG6LOCAL"
        "program:BPF_PROG_TYPE_SK_MSG"
        "program:BPF_PROG_TYPE_SK_SKB"
        "attach:BPF_SK_REUSEPORT_SELECT"
        "attach:BPF_SK_REUSEPORT_SELECT_OR_MIGRATE"
        "program:BPF_PROG_TYPE_CGROUP_SKB"
        "program:BPF_PROG_TYPE_CGROUP_SOCK"
        "program:BPF_PROG_TYPE_CGROUP_DEVICE"
        "program:BPF_PROG_TYPE_CGROUP_SOCK_ADDR"
        "program:BPF_PROG_TYPE_CGROUP_SYSCTL"
        "program:BPF_PROG_TYPE_CGROUP_SOCKOPT"
        "program:BPF_PROG_TYPE_SOCK_OPS"
        "attach:BPF_CGROUP_UNIX_SOCK_ADDR"
        "program:BPF_PROG_TYPE_LIRC_MODE2"
    ] {
        return "host-gated"
    }

    "host-safe"
}

def fixture-default-test-lane-from-features [fixture features] {
    let explicit = ($fixture | get -o default_test_lane)
    if $explicit != null {
        return $explicit
    }

    let lanes = (
        $features
        | each {|feature| kernel-feature-default-test-lane $feature }
    )
    aggregate-test-lanes $lanes
}

def fixture-default-test-lane [fixture] {
    fixture-default-test-lane-from-features $fixture (fixture-kernel-features $fixture)
}

def kernel-feature-labels [features] {
    $features
    | each {|feature|
        let max_kernel = ($feature | get -o max_kernel_exclusive)
        if $max_kernel == null or $max_kernel == "" {
            $"($feature.key)>=($feature.min_kernel)"
        } else {
            $"($feature.key)>=($feature.min_kernel),<($max_kernel)"
        }
    }
}

def fixture-tier [fixture] {
    let explicit = ($fixture | get -o tier)
    if $explicit != null {
        return $explicit
    }

    let requirements = (
        optional $fixture requires []
        | append (optional $fixture kernel_requires [])
    )

    if ($requirements | any {|feature| ($feature in ["kernel-btf" "tracefs"]) or ($feature | str starts-with $HOST_FEATURE_PREFIX_KERNEL_BTF_KFUNC) }) {
        "btf"
    } else {
        "fast"
    }
}

def fixture-summary [fixture compat_kernel] {
    let kernel_features = (fixture-kernel-features $fixture)
    fixture-summary-from-derived (fixture-derived-metadata $fixture $kernel_features) $compat_kernel
}

def fixture-derived-metadata [fixture kernel_features] {
    let effective_min_kernel = (effective-min-kernel-from-features $kernel_features)
    let effective_max_kernel_exclusive = (effective-max-kernel-exclusive-from-features $kernel_features)
    let default_test_lane = (fixture-default-test-lane-from-features $fixture $kernel_features)

    {
        fixture: $fixture
        name: $fixture.name
        target: (optional $fixture target "")
        category: (optional $fixture category "")
        tier: (fixture-tier $fixture)
        local: $fixture.local
        kernel: $fixture.kernel
        requires: (optional $fixture requires [])
        kernel_requires: (optional $fixture kernel_requires [])
        kernel_features: $kernel_features
        default_test_lane: $default_test_lane
        default_test_lane_description: (test-lane-description $default_test_lane)
        effective_min_kernel_raw: $effective_min_kernel
        effective_max_kernel_exclusive_raw: $effective_max_kernel_exclusive
        effective_min_kernel_sources: (effective-min-kernel-sources-from-features $kernel_features)
        effective_max_kernel_exclusive_sources: (effective-max-kernel-exclusive-sources-from-features $kernel_features)
        min_kernel: (optional $fixture min_kernel "")
        min_kernel_source: (optional $fixture min_kernel_source "")
        tags: (optional $fixture tags [])
    }
}

def fixture-summary-from-derived [derived compat_kernel] {
    let compatibility = (
        kernel-feature-compatibility
            $derived.effective_min_kernel_raw
            $derived.effective_max_kernel_exclusive_raw
            $compat_kernel
    )

    {
        name: $derived.name
        target: $derived.target
        category: $derived.category
        tier: $derived.tier
        local: $derived.local
        kernel: $derived.kernel
        requires: $derived.requires
        kernel_requires: $derived.kernel_requires
        kernel_features: $derived.kernel_features
        default_test_lane: $derived.default_test_lane
        default_test_lane_description: $derived.default_test_lane_description
        effective_min_kernel: ($derived.effective_min_kernel_raw | default "")
        effective_max_kernel_exclusive: ($derived.effective_max_kernel_exclusive_raw | default "")
        effective_min_kernel_sources: $derived.effective_min_kernel_sources
        effective_max_kernel_exclusive_sources: $derived.effective_max_kernel_exclusive_sources
        compat_kernel: ($compat_kernel | default "")
        compatible_with_compat_kernel: $compatibility.compatible
        compat_kernel_reason: $compatibility.reason
        min_kernel: $derived.min_kernel
        min_kernel_source: $derived.min_kernel_source
        tags: $derived.tags
    }
}

def fixture-status-count [fixtures field: string status: string] {
    $fixtures
    | where {|fixture| ($fixture | get $field) == $status }
    | length
}

def fixture-has-effective-min-kernel [fixture] {
    (fixture-effective-min-kernel $fixture) != null
}

def kernel-accept-versioned-count [fixtures versioned: bool] {
    $fixtures
    | where {|fixture| $fixture.kernel == "accept" }
    | where {|fixture| (fixture-has-effective-min-kernel $fixture) == $versioned }
    | length
}

def kernel-accept-compatible-count [fixtures kernel_release compatible: bool] {
    $fixtures
    | where {|fixture| $fixture.kernel == "accept" }
    | where {|fixture| fixture-has-effective-min-kernel $fixture }
    | where {|fixture| (fixture-kernel-compatibility $fixture $kernel_release).compatible == $compatible }
    | length
}

def kernel-accept-compat-reason-count [fixtures kernel_release reason_prefix: string] {
    $fixtures
    | where {|fixture| $fixture.kernel == "accept" }
    | where {|fixture| ((fixture-kernel-compatibility $fixture $kernel_release).reason | str starts-with $reason_prefix) }
    | length
}

def fixture-test-lane-count [fixtures lane: string] {
    $fixtures
    | where {|fixture| (fixture-default-test-lane $fixture) == $lane }
    | length
}

def fixture-matrix-summary [fixture compat_kernel] {
    let kernel_features = (fixture-kernel-features $fixture)
    fixture-matrix-summary-from-derived (fixture-derived-metadata $fixture $kernel_features) $compat_kernel
}

def fixture-matrix-summary-from-derived [derived compat_kernel] {
    let compatibility = (
        kernel-feature-compatibility
            $derived.effective_min_kernel_raw
            $derived.effective_max_kernel_exclusive_raw
            $compat_kernel
    )

    {
        tier: $derived.tier
        category: $derived.category
        local: $derived.local
        kernel: $derived.kernel
        default_test_lane: $derived.default_test_lane
        has_effective_min_kernel: ($derived.effective_min_kernel_raw != null)
        has_effective_max_kernel_exclusive: ($derived.effective_max_kernel_exclusive_raw != null)
        compatible_with_compat_kernel: $compatibility.compatible
        compat_kernel_reason: $compatibility.reason
    }
}

def matrix-status-count [fixtures field: string status: string] {
    $fixtures
    | where {|fixture| ($fixture | get $field) == $status }
    | length
}

def matrix-kernel-accept-versioned-count [fixtures versioned: bool] {
    $fixtures
    | where {|fixture| $fixture.kernel == "accept" }
    | where {|fixture| $fixture.has_effective_min_kernel == $versioned }
    | length
}

def matrix-kernel-accept-bounded-count [fixtures bounded: bool] {
    $fixtures
    | where {|fixture| $fixture.kernel == "accept" }
    | where {|fixture| $fixture.has_effective_max_kernel_exclusive == $bounded }
    | length
}

def matrix-kernel-accept-compatible-count [fixtures compatible: bool] {
    $fixtures
    | where {|fixture| $fixture.kernel == "accept" }
    | where {|fixture| $fixture.has_effective_min_kernel }
    | where {|fixture| $fixture.compatible_with_compat_kernel == $compatible }
    | length
}

def matrix-kernel-accept-compat-reason-count [fixtures reason_prefix: string] {
    $fixtures
    | where {|fixture| $fixture.kernel == "accept" }
    | where {|fixture| ($fixture.compat_kernel_reason | str starts-with $reason_prefix) }
    | length
}

def matrix-test-lane-count [fixtures lane: string] {
    $fixtures
    | where {|fixture| $fixture.default_test_lane == $lane }
    | length
}

def fixture-matrix-rows [fixtures compat_kernel] {
    let matrix_fixtures = (
        $fixtures
        | each {|fixture| fixture-matrix-summary $fixture $compat_kernel }
    )

    fixture-matrix-rows-from-matrix-summaries $matrix_fixtures $compat_kernel
}

def fixture-matrix-rows-from-derived [derived_fixtures compat_kernel] {
    let matrix_fixtures = (
        $derived_fixtures
        | each {|fixture| fixture-matrix-summary-from-derived $fixture $compat_kernel }
    )

    fixture-matrix-rows-from-matrix-summaries $matrix_fixtures $compat_kernel
}

def fixture-matrix-rows-from-matrix-summaries [matrix_fixtures compat_kernel] {
    mut rows = []

    for tier in $VALID_TIERS {
        let tier_fixtures = (
            $matrix_fixtures
            | where {|fixture| $fixture.tier == $tier }
        )

        if (($tier_fixtures | length) == 0) {
            continue
        }

        let categories = (
            $tier_fixtures
            | each {|fixture| optional $fixture category "" }
            | uniq
            | sort
        )

        for category in $categories {
            let category_fixtures = (
                $tier_fixtures
                | where {|fixture| (optional $fixture category "") == $category }
            )

            let base = {
                tier: $tier
                category: $category
                total: ($category_fixtures | length)
                local_accept: (matrix-status-count $category_fixtures local accept)
                local_reject: (matrix-status-count $category_fixtures local reject)
                local_skip: (matrix-status-count $category_fixtures local skip)
                kernel_accept: (matrix-status-count $category_fixtures kernel accept)
                kernel_reject: (matrix-status-count $category_fixtures kernel reject)
                kernel_skip: (matrix-status-count $category_fixtures kernel skip)
                kernel_accept_versioned: (matrix-kernel-accept-versioned-count $category_fixtures true)
                kernel_accept_unversioned: (matrix-kernel-accept-versioned-count $category_fixtures false)
                kernel_accept_bounded: (matrix-kernel-accept-bounded-count $category_fixtures true)
                kernel_accept_unbounded: (matrix-kernel-accept-bounded-count $category_fixtures false)
                lane_host_safe: (matrix-test-lane-count $category_fixtures "host-safe")
                lane_host_gated: (matrix-test-lane-count $category_fixtures "host-gated")
                lane_dry_run: (matrix-test-lane-count $category_fixtures "dry-run")
                lane_vm_only: (matrix-test-lane-count $category_fixtures "vm-only")
            }

            let row = if $compat_kernel == null {
                $base
            } else {
                $base
                | upsert compat_kernel $compat_kernel
                | upsert kernel_accept_compatible (matrix-kernel-accept-compatible-count $category_fixtures true)
                | upsert kernel_accept_incompatible (matrix-kernel-accept-compatible-count $category_fixtures false)
                | upsert kernel_accept_requires_newer (matrix-kernel-accept-compat-reason-count $category_fixtures "kernel>=")
                | upsert kernel_accept_requires_older (matrix-kernel-accept-compat-reason-count $category_fixtures "kernel<")
            }

            $rows = ($rows | append $row)
        }
    }

    $rows
}

def print-fixture-matrix [fixtures compat_kernel] {
    for row in (fixture-matrix-rows $fixtures $compat_kernel) {
        print-fixture-matrix-row $row
    }
}

def print-fixture-matrix-from-derived [derived_fixtures compat_kernel] {
    for row in (fixture-matrix-rows-from-derived $derived_fixtures $compat_kernel) {
        print-fixture-matrix-row $row
    }
}

def print-fixture-matrix-row [row] {
    let compat_text = if (($row | get -o compat_kernel) == null) {
        ""
    } else {
        $" compat_kernel=($row.compat_kernel) kernel_accept_compatible=($row.kernel_accept_compatible) kernel_accept_incompatible=($row.kernel_accept_incompatible) kernel_accept_requires_newer=($row.kernel_accept_requires_newer) kernel_accept_requires_older=($row.kernel_accept_requires_older)"
    }
    print $"tier=($row.tier) category=($row.category) total=($row.total) local_accept=($row.local_accept) local_reject=($row.local_reject) local_skip=($row.local_skip) kernel_accept=($row.kernel_accept) kernel_reject=($row.kernel_reject) kernel_skip=($row.kernel_skip) kernel_accept_versioned=($row.kernel_accept_versioned) kernel_accept_unversioned=($row.kernel_accept_unversioned) kernel_accept_bounded=($row.kernel_accept_bounded) kernel_accept_unbounded=($row.kernel_accept_unbounded) lane_host_safe=($row.lane_host_safe) lane_host_gated=($row.lane_host_gated) lane_dry_run=($row.lane_dry_run) lane_vm_only=($row.lane_vm_only)($compat_text)"
}

def validate-tier-option [label: string value] {
    if $value == null {
        return
    }

    if $value not-in $VALID_TIERS {
        fail $"invalid ($label) tier '($value)'; expected one of ($VALID_TIERS | str join ', ')"
    }
}

def validate-test-lane-option [label: string value] {
    if $value == null {
        return
    }

    if $value not-in $VALID_TEST_LANES {
        fail $"invalid ($label) test lane '($value)'; expected one of ($VALID_TEST_LANES | str join ', ')"
    }
}

def validate-status-option [label: string value] {
    if $value == null {
        return
    }

    if $value not-in [accept reject skip] {
        fail $"invalid ($label) status '($value)'; expected accept, reject, or skip"
    }
}

def validate-host-features [fixture field: string] {
    for feature in (optional $fixture $field []) {
        if ($feature | str starts-with "tracepoint:") {
            continue
        }
        if ($feature | str starts-with $HOST_FEATURE_PREFIX_KERNEL_BTF_KFUNC) {
            let kfunc = ($feature | str substring ($HOST_FEATURE_PREFIX_KERNEL_BTF_KFUNC | str length)..)
            if $kfunc == "" {
                fail $"fixture ($fixture.name) declares empty ($HOST_FEATURE_PREFIX_KERNEL_BTF_KFUNC) host feature in ($field)"
            }
            continue
        }
        if $feature not-in $VALID_HOST_FEATURES {
            fail $"fixture ($fixture.name) declares unknown ($field) feature '($feature)'; expected one of ($VALID_HOST_FEATURES | str join ', '), tracepoint:<system>/<event>, or ($HOST_FEATURE_PREFIX_KERNEL_BTF_KFUNC)<symbol>"
        }
    }
}

def validate-fixture-tags [fixture] {
    let tags = (optional $fixture tags [])
    for tag in $tags {
        if (($tag | describe) != "string") {
            fail $"fixture ($fixture.name) declares non-string tag value '($tag)'"
        }
        if ($tag | str trim) == "" {
            fail $"fixture ($fixture.name) declares an empty tag"
        }
    }

    for tag in ($tags | uniq) {
        let count = ($tags | where {|candidate| $candidate == $tag } | length)
        if $count > 1 {
            fail $"fixture ($fixture.name) declares duplicate tag '($tag)'"
        }
    }
}

def validate-kernel-feature-key-uniqueness [fixture_name: string origin: string features] {
    let keys = ($features | each {|feature| $feature | get -o key })

    for key in ($keys | uniq) {
        if $key == null or $key == "" {
            fail $"fixture ($fixture_name) ($origin) declares a kernel feature without key"
        }

        let count = ($keys | where {|candidate| $candidate == $key } | length)
        if $count > 1 {
            fail $"fixture ($fixture_name) ($origin) declares duplicate kernel feature key: ($key)"
        }
    }
}

def validate-kernel-feature-record [fixture_name: string origin: string feature] {
    let key = ($feature | get -o key)
    let min_kernel = ($feature | get -o min_kernel)
    let max_kernel = ($feature | get -o max_kernel_exclusive)
    let max_kernel_source = ($feature | get -o max_kernel_exclusive_source)
    let source = ($feature | get -o source)

    if $key == null or $key == "" {
        fail $"fixture ($fixture_name) ($origin) declares a kernel feature without key"
    }
    if $min_kernel == null or $min_kernel == "" {
        fail $"fixture ($fixture_name) ($origin) kernel feature ($key) missing min_kernel"
    }
    if $source == null or $source == "" {
        fail $"fixture ($fixture_name) ($origin) kernel feature ($key) missing source"
    }

    parse-kernel-version $min_kernel | ignore
    if $max_kernel != null and $max_kernel != "" {
        parse-kernel-version $max_kernel | ignore
        if $max_kernel_source == null or $max_kernel_source == "" {
            fail $"fixture ($fixture_name) ($origin) kernel feature ($key) with max_kernel_exclusive=($max_kernel) missing max_kernel_exclusive_source"
        }
        if (kernel-version-compare $max_kernel $min_kernel) <= 0 {
            fail $"fixture ($fixture_name) ($origin) kernel feature ($key) max_kernel_exclusive=($max_kernel) must be greater than min_kernel=($min_kernel)"
        }
    } else if $max_kernel_source != null and $max_kernel_source != "" {
        fail $"fixture ($fixture_name) ($origin) kernel feature ($key) declares max_kernel_exclusive_source without max_kernel_exclusive"
    }
}

def validate-kernel-feature-metadata [fixture] {
    let features = (optional $fixture kernel_features [])
    let keys = ($features | each {|feature| $feature | get -o key })
    validate-kernel-feature-key-uniqueness $fixture.name "explicit kernel_features" $features

    for feature in $features {
        validate-kernel-feature-record $fixture.name "explicit kernel_features" $feature
    }

    for helper_name in (program-helper-names (fixture-program $fixture)) {
        let key = $"helper:($helper_name)"
        let known_feature = (helper-kernel-feature $helper_name)
        let explicit_feature = ($keys | any {|candidate| $candidate == $key })
        if $known_feature == null and not $explicit_feature {
            fail $"fixture ($fixture.name) calls helper ($helper_name) without source-backed kernel metadata; add it to BPF_HELPER_IDS/HELPER_KERNEL_FEATURES or declare explicit kernel_features metadata"
        }
    }

    for kfunc_name in (program-kfunc-names (fixture-program $fixture)) {
        let key = $"kfunc:($kfunc_name)"
        let known_feature = (kfunc-kernel-feature $kfunc_name)
        let explicit_feature = ($keys | any {|candidate| $candidate == $key })
        if $known_feature == null and not $explicit_feature {
            fail $"fixture ($fixture.name) calls kfunc ($kfunc_name) without source-backed kernel metadata; add it to KFUNC_KERNEL_FEATURES/KFUNC_KERNEL_FEATURE_FALLBACKS or declare explicit kernel_features metadata"
        }
    }

    let effective_features = (fixture-kernel-features $fixture)
    validate-kernel-feature-key-uniqueness $fixture.name "effective kernel_features" $effective_features
    for feature in $effective_features {
        validate-kernel-feature-record $fixture.name "effective kernel_features" $feature
    }

    $effective_features
}

def validate-kernel-feature-key-expectation [label: string expected_keys actual_keys] {
    let expected_keys = ($expected_keys | sort)
    let actual_keys = ($actual_keys | sort)
    let missing = ($expected_keys | where {|key| $key not-in $actual_keys })
    let unexpected = ($actual_keys | where {|key| $key not-in $expected_keys })

    if (($missing | length) > 0) or (($unexpected | length) > 0) {
        fail $"($label) drifted: missing=($missing | str join ',') unexpected=($unexpected | str join ',') actual=($actual_keys | str join ',')"
    }
}

def validate-program-target-kernel-feature-expectations [] {
    for expectation in $PROGRAM_TARGET_KERNEL_FEATURE_EXPECTATIONS {
        let target = $expectation.target
        let actual_keys = (
            target-kernel-features $target
            | each {|feature| $feature.key }
        )

        validate-kernel-feature-key-expectation $"target-kernel-features for ($target)" $expectation.feature_keys $actual_keys
    }
}

def validate-program-language-kernel-feature-expectations [] {
    for expectation in $PROGRAM_LANGUAGE_KERNEL_FEATURE_EXPECTATIONS {
        let program = ($expectation.program | str join "\n")
        let actual_keys = (
            program-language-kernel-features $program
            | each {|feature| $feature.key }
        )

        validate-kernel-feature-key-expectation "program-language-kernel-features" $expectation.feature_keys $actual_keys
    }
}

def validate-program-map-kernel-feature-expectations [] {
    for expectation in $PROGRAM_MAP_KERNEL_FEATURE_EXPECTATIONS {
        let program = ($expectation.program | str join "\n")
        let actual_keys = (
            program-map-kernel-features $program
            | each {|feature| $feature.key }
        )

        validate-kernel-feature-key-expectation "program-map-kernel-features" $expectation.feature_keys $actual_keys
    }
}

def validate-program-reserved-map-kernel-feature-expectations [] {
    for expectation in $PROGRAM_RESERVED_MAP_KERNEL_FEATURE_EXPECTATIONS {
        let program = ($expectation.program | str join "\n")
        let actual_keys = (
            program-reserved-map-kernel-features $program
            | each {|feature| $feature.key }
        )

        validate-kernel-feature-key-expectation "program-reserved-map-kernel-features" $expectation.feature_keys $actual_keys
    }
}

def validate-program-map-value-kernel-feature-expectations [] {
    for expectation in $PROGRAM_MAP_VALUE_KERNEL_FEATURE_EXPECTATIONS {
        let program = ($expectation.program | str join "\n")
        let actual_keys = (
            program-map-value-kernel-features $program
            | each {|feature| $feature.key }
        )

        validate-kernel-feature-key-expectation "program-map-value-kernel-features" $expectation.feature_keys $actual_keys
    }
}

def validate-program-global-kernel-feature-expectations [] {
    for expectation in $PROGRAM_GLOBAL_KERNEL_FEATURE_EXPECTATIONS {
        let program = ($expectation.program | str join "\n")
        let actual_keys = (
            program-global-kernel-features $program
            | each {|feature| $feature.key }
        )

        validate-kernel-feature-key-expectation "program-global-kernel-features" $expectation.feature_keys $actual_keys
    }
}

def validate-target-context-field-kernel-feature-expectations [] {
    for expectation in $TARGET_CONTEXT_FIELD_KERNEL_FEATURE_EXPECTATIONS {
        let target = $expectation.target
        let field = $expectation.field
        let expected = $expectation.feature
        let actual = (context-field-kernel-feature $field $target)

        if $actual == null {
            fail $"context-field-kernel-feature missing expected target-aware metadata for ($target) ctx.($field)"
        }

        for key in [key min_kernel source max_kernel_exclusive max_kernel_exclusive_source] {
            let expected_value = ($expected | get -o $key)
            let actual_value = ($actual | get -o $key)
            if $expected_value != $actual_value {
                fail $"context-field-kernel-feature drifted for ($target) ctx.($field): ($key) expected=($expected_value) actual=($actual_value)"
            }
        }
    }
}

def validate-context-field-helper-kernel-feature-expectations [] {
    for expectation in $CONTEXT_FIELD_HELPER_KERNEL_FEATURE_EXPECTATIONS {
        let target = $expectation.target
        let field = $expectation.field
        let expected = $expectation.feature
        let actual = (context-field-helper-kernel-feature $field $target)

        if $actual == null {
            fail $"context-field-helper-kernel-feature missing expected metadata for ($target) ctx.($field)"
        }

        for key in [key min_kernel source max_kernel_exclusive max_kernel_exclusive_source] {
            let expected_value = ($expected | get -o $key)
            let actual_value = ($actual | get -o $key)
            if $expected_value != $actual_value {
                fail $"context-field-helper-kernel-feature drifted for ($target) ctx.($field): ($key) expected=($expected_value) actual=($actual_value)"
            }
        }
    }
}

def validate-context-projection-kernel-feature-expectations [] {
    for expectation in $CONTEXT_PROJECTION_KERNEL_FEATURE_EXPECTATIONS {
        let target = $expectation.target
        let raw_access = $expectation.raw_access
        let expected = $expectation.feature
        let actual = (context-projection-kernel-feature $raw_access $target)

        if $actual == null {
            fail $"context-projection-kernel-feature missing expected metadata for ($target) ctx.($raw_access)"
        }

        for key in [key min_kernel source max_kernel_exclusive max_kernel_exclusive_source] {
            let expected_value = ($expected | get -o $key)
            let actual_value = ($actual | get -o $key)
            if $expected_value != $actual_value {
                fail $"context-projection-kernel-feature drifted for ($target) ctx.($raw_access): ($key) expected=($expected_value) actual=($actual_value)"
            }
        }
    }
}

def validate-program-context-field-kernel-feature-expectations [] {
    for expectation in $PROGRAM_CONTEXT_FIELD_KERNEL_FEATURE_EXPECTATIONS {
        let target = $expectation.target
        let program = ($expectation.program | str join "\n")
        let actual_keys = (
            program-context-field-kernel-features $program $target
            | each {|feature| $feature.key }
        )

        validate-kernel-feature-key-expectation $"program-context-field-kernel-features for ($target)" $expectation.feature_keys $actual_keys
    }
}

def validate-program-surface-kernel-feature-expectations [] {
    for expectation in $PROGRAM_SURFACE_KERNEL_FEATURE_EXPECTATIONS {
        let target = $expectation.target
        let program = ($expectation.program | str join "\n")
        let actual_keys = (
            program-surface-kernel-features $program $target
            | each {|feature| $feature.key }
        )

        validate-kernel-feature-key-expectation $"program-surface-kernel-features for ($target)" $expectation.feature_keys $actual_keys
    }
}

def validate-program-helper-kernel-feature-expectations [] {
    for expectation in $PROGRAM_HELPER_KERNEL_FEATURE_EXPECTATIONS {
        let program = ($expectation.program | str join "\n")
        let actual_keys = (
            program-helper-kernel-features $program
            | each {|feature| $feature.key }
        )

        validate-kernel-feature-key-expectation "program-helper-kernel-features" $expectation.feature_keys $actual_keys
    }
}

def validate-program-kfunc-kernel-feature-expectations [] {
    for expectation in $PROGRAM_KFUNC_KERNEL_FEATURE_EXPECTATIONS {
        let target = $expectation.target
        let program = ($expectation.program | str join "\n")
        let actual_keys = (
            program-kfunc-kernel-features $program $target
            | each {|feature| $feature.key }
        )

        validate-kernel-feature-key-expectation $"program-kfunc-kernel-features for ($target)" $expectation.feature_keys $actual_keys
    }
}

def validate-program-kfunc-kernel-feature-detail-expectations [] {
    for expectation in $PROGRAM_KFUNC_KERNEL_FEATURE_DETAIL_EXPECTATIONS {
        let target = $expectation.target
        let program = ($expectation.program | str join "\n")
        let expected = $expectation.feature
        let expected_key = $expected.key
        let matches = (
            program-kfunc-kernel-features $program $target
            | where {|feature| $feature.key == $expected_key }
        )

        if ($matches | is-empty) {
            fail $"program-kfunc-kernel-features for ($target) missing expected metadata for ($expected_key)"
        }

        let actual = ($matches | first)
        for key in [key min_kernel source max_kernel_exclusive max_kernel_exclusive_source] {
            let expected_value = ($expected | get -o $key)
            let actual_value = ($actual | get -o $key)
            if $expected_value != $actual_value {
                fail $"program-kfunc-kernel-features for ($target) ($expected_key) drifted: ($key) expected=($expected_value) actual=($actual_value)"
            }
        }
    }
}

def validate-program-callback-btf-kernel-feature-expectations [] {
    for expectation in $PROGRAM_CALLBACK_BTF_KERNEL_FEATURE_EXPECTATIONS {
        let program = ($expectation.program | str join "\n")
        let actual_keys = (
            program-callback-btf-kernel-features $program
            | each {|feature| $feature.key }
        )

        validate-kernel-feature-key-expectation "program-callback-btf-kernel-features" $expectation.feature_keys $actual_keys
    }
}

def validate-fixture-metadata [fixtures] {
    validate-program-target-kernel-feature-expectations
    validate-program-language-kernel-feature-expectations
    validate-program-map-kernel-feature-expectations
    validate-program-reserved-map-kernel-feature-expectations
    validate-program-map-value-kernel-feature-expectations
    validate-program-global-kernel-feature-expectations
    validate-target-context-field-kernel-feature-expectations
    validate-context-field-helper-kernel-feature-expectations
    validate-context-projection-kernel-feature-expectations
    validate-program-context-field-kernel-feature-expectations
    validate-program-surface-kernel-feature-expectations
    validate-program-helper-kernel-feature-expectations
    validate-program-kfunc-kernel-feature-expectations
    validate-program-kfunc-kernel-feature-detail-expectations
    validate-program-callback-btf-kernel-feature-expectations

    let names = ($fixtures | each {|fixture| $fixture.name })

    for name in ($names | uniq) {
        let count = ($names | where {|candidate| $candidate == $name } | length)
        if $count > 1 {
            fail $"duplicate verifier fixture name: ($name)"
        }
    }

    mut derived = []

    for fixture in $fixtures {
        validate-tier-option $"fixture ($fixture.name)" ($fixture | get -o tier)
        validate-test-lane-option $"fixture ($fixture.name)" ($fixture | get -o default_test_lane)
        validate-status-option $"fixture ($fixture.name) local" $fixture.local
        validate-status-option $"fixture ($fixture.name) kernel" $fixture.kernel
        if $fixture.local != "accept" and $fixture.kernel != "skip" {
            fail $"fixture ($fixture.name) declares kernel=($fixture.kernel), but kernel checks only run after local accept; use kernel=skip for local ($fixture.local) fixtures"
        }
        validate-fixture-tags $fixture
        validate-host-features $fixture requires
        validate-host-features $fixture kernel_requires
        let kernel_features = (validate-kernel-feature-metadata $fixture)

        let min_kernel = ($fixture | get -o min_kernel)
        let min_kernel_source = ($fixture | get -o min_kernel_source)

        if $min_kernel != null and ($min_kernel_source == null or $min_kernel_source == "") {
            fail $"fixture ($fixture.name) declares min_kernel=($min_kernel) without min_kernel_source"
        }

        if $min_kernel == null and $min_kernel_source != null {
            fail $"fixture ($fixture.name) declares min_kernel_source without min_kernel"
        }

        if $min_kernel != null {
            parse-kernel-version $min_kernel | ignore
        }

        $derived = ($derived | append (fixture-derived-metadata $fixture $kernel_features))
    }

    $derived
}

def fixture-has-tag [fixture tag] {
    if $tag == null {
        return true
    }

    optional $fixture tags [] | any {|fixture_tag| $fixture_tag == $tag }
}

def fixture-matches-filters [fixture category tag tier exclude_tier local_status kernel_status test_lane] {
    (
        ($category == null or (optional $fixture category "") == $category)
        and (fixture-has-tag $fixture $tag)
        and ($tier == null or (fixture-tier $fixture) == $tier)
        and ($exclude_tier == null or (fixture-tier $fixture) != $exclude_tier)
        and ($local_status == null or $fixture.local == $local_status)
        and ($kernel_status == null or $fixture.kernel == $kernel_status)
        and ($test_lane == null or (fixture-default-test-lane $fixture) == $test_lane)
    )
}

def check-local-fixture [plugin_bin: string fixture] {
    let result = (run-nu-with-plugin-complete $plugin_bin (dry-run-describe-code $fixture))
    let stdout = ($result.stdout | str trim)
    let output = (combined-output $result)
    let accepted = ($result.exit_code == 0 and $stdout == "binary")
    let actual = if $accepted { "accept" } else { "reject" }

    if $actual != $fixture.local {
        fail $"fixture ($fixture.name) expected local ($fixture.local), got ($actual): ($output | str trim)"
    }

    let expected_fragment = ($fixture | get -o error_contains)
    if $fixture.local == "reject" and $expected_fragment != null and not ($output | str contains $expected_fragment) {
        fail $"fixture ($fixture.name) rejected, but error did not contain expected fragment: ($expected_fragment)"
    }

    { name: $fixture.name, local: $actual, output: $output }
}

def check-local-fixtures [plugin_bin: string fixtures jobs: int] {
    mut results = []

    for batch in ($fixtures | chunks $jobs) {
        let batch_results = if $jobs == 1 {
            $batch | each {|fixture| check-local-fixture $plugin_bin $fixture }
        } else {
            $batch | par-each --keep-order --threads $jobs {|fixture| check-local-fixture $plugin_bin $fixture }
        }

        for result in $batch_results {
            print $"local  ($result.local)  ($result.name)"
        }
        $results = ($results | append $batch_results)
    }

    $results
}

def kernel-preflight [] {
    mut reasons = []

    if not (command-exists bpftool) {
        $reasons = ($reasons | append "bpftool is not installed")
    }

    if not (is-root) {
        $reasons = ($reasons | append "not running as root")
    }

    if not ($BPFFS | path exists) {
        $reasons = ($reasons | append $"($BPFFS) does not exist")
    } else if (($BPFFS | path type) != "dir") {
        $reasons = ($reasons | append $"($BPFFS) is not a directory")
    } else if (command-exists findmnt) {
        let mount = (^findmnt -rn -T $BPFFS -o FSTYPE | complete)
        if $mount.exit_code != 0 {
            $reasons = ($reasons | append $"could not inspect ($BPFFS) mount type")
        } else if (($mount.stdout | str trim) != "bpf") {
            $reasons = ($reasons | append $"($BPFFS) is not mounted as bpffs")
        }
    }

    { available: (($reasons | length) == 0), reasons: $reasons }
}

def host-sys-enter-syscalls [] {
    let events_dir = "/sys/kernel/tracing/events/syscalls"
    if not ($events_dir | path exists) {
        fail $"($events_dir) does not exist; mount tracefs before checking host syscall tracepoint coverage"
    }
    if (($events_dir | path type) != "dir") {
        fail $"($events_dir) is not a directory"
    }

    ls $events_dir
    | where type == dir
    | get name
    | each {|path| $path | path basename }
    | where {|name| $name | str starts-with "sys_enter_" }
    | each {|name| $name | str replace "sys_enter_" "" }
    | sort
    | uniq
}

def modeled-sys-enter-syscalls [] {
    let tracepoint_rs = ([$REPO_ROOT "src" "kernel_btf" "tracepoint.rs"] | path join)
    mut in_list = false
    mut names = []

    for line in (open $tracepoint_rs | lines) {
        let trimmed = ($line | str trim)
        if $trimmed == "const WELL_KNOWN_SYS_ENTER_SYSCALLS: &[&str] = &[" {
            $in_list = true
            continue
        }
        if $in_list and $trimmed == "];" {
            break
        }
        if not $in_list {
            continue
        }

        let parsed = ($trimmed | parse --regex '^"(?P<name>[^"]+)",?$')
        if ($parsed | is-empty) {
            continue
        }

        $names = ($names | append ($parsed | first | get name))
    }

    if ($names | is-empty) {
        fail $"could not parse WELL_KNOWN_SYS_ENTER_SYSCALLS from ($tracepoint_rs)"
    }

    $names | sort | uniq
}

def check-host-syscall-tracepoint-coverage [] {
    let host = (host-sys-enter-syscalls)
    let modeled = (modeled-sys-enter-syscalls)
    let missing = ($host | where {|name| $name not-in $modeled })
    let extra = ($modeled | where {|name| $name not-in $host })

    if not ($missing | is-empty) {
        print "missing modeled sys_enter fallbacks for host tracepoints:"
        for name in $missing {
            print $"  ($name)"
        }
        fail $"($missing | length) host sys_enter tracepoint fallback gaps"
    }

    print $"ok: 0 host sys_enter tracepoint gaps; (($host | length)) host syscalls, (($modeled | length)) modeled fallbacks, (($extra | length)) modeled fallbacks not present on this host"
}

def host-feature-available [feature: string] {
    if $feature == "loopback-interface" {
        "/sys/class/net/lo" | path exists
    } else if $feature == "kernel-btf" {
        "/sys/kernel/btf/vmlinux" | path exists
    } else if ($feature | str starts-with $HOST_FEATURE_PREFIX_KERNEL_BTF_KFUNC) {
        let kfunc = ($feature | str substring ($HOST_FEATURE_PREFIX_KERNEL_BTF_KFUNC | str length)..)
        if $kfunc == "" or not ("/sys/kernel/btf/vmlinux" | path exists) or not (command-exists bpftool) {
            return false
        }
        let dump = (^bpftool btf dump file /sys/kernel/btf/vmlinux format raw | complete)
        if $dump.exit_code != 0 {
            return false
        }
        $dump.stdout | lines | any {|line| $line | str contains $"FUNC '($kfunc)'" }
    } else if $feature == "tracefs" {
        "/sys/kernel/tracing/events" | path exists
    } else if $feature == "cgroup-v2" {
        "/sys/fs/cgroup/cgroup.controllers" | path exists
    } else if $feature == "netns-self" {
        "/proc/self/ns/net" | path exists
    } else if $feature == "lirc-device" {
        "/dev/lirc0" | path exists
    } else if ($feature | str starts-with "tracepoint:") {
        let event = ($feature | str substring 11..)
        ("/sys/kernel/tracing/events" | path join $event) | path exists
    } else {
        false
    }
}

def fixture-missing-requirements [fixture] {
    optional $fixture requires []
    | where {|feature| not (host-feature-available $feature) }
}

def fixture-missing-kernel-requirements [fixture] {
    mut missing = (fixture-missing-requirements $fixture)

    let kernel_features = (
        optional $fixture kernel_requires []
        | where {|feature| not (host-feature-available $feature) }
    )
    $missing = ($missing | append $kernel_features)

    let min_kernel = (fixture-effective-min-kernel $fixture)
    if $min_kernel != null {
        let current = (current-kernel-release)
        if not (kernel-version-at-least $current $min_kernel) {
            $missing = ($missing | append $"kernel>=($min_kernel),current=($current)")
        }
    }
    let max_kernel = (fixture-effective-max-kernel-exclusive $fixture)
    if $max_kernel != null {
        let current = (current-kernel-release)
        if not (kernel-version-before $current $max_kernel) {
            $missing = ($missing | append $"kernel<($max_kernel),current=($current)")
        }
    }

    $missing
}

def write-dry-run-object [plugin_bin: string fixture obj_path: string] {
    let result = (run-nu-with-plugin-complete $plugin_bin (dry-run-save-code $fixture $obj_path))

    if $result.exit_code != 0 {
        fail $"fixture ($fixture.name) failed while writing dry-run object: ((combined-output $result) | str trim)"
    }
}

def bpftool-load [obj_path: string pin_path: string] {
    ^bpftool prog load $obj_path $pin_path | complete
}

def cleanup-pin [pin_path: string] {
    if ($pin_path | path exists) {
        try {
            rm -f $pin_path
        } catch { |_| null }
    }
}

def run-kernel-fixture [plugin_bin: string fixture tmp_dir: string] {
    if $fixture.kernel == "skip" {
        return { name: $fixture.name, kernel: "skip", reason: "fixture is local-only" }
    }

    let obj_path = ($tmp_dir | path join $"($fixture.name).o")
    let pin_path = ($BPFFS | path join $"nu_plugin_ebpf_verifier_diff_($fixture.name)_(random uuid)")

    write-dry-run-object $plugin_bin $fixture $obj_path

    let result = (bpftool-load $obj_path $pin_path)
    cleanup-pin $pin_path

    let actual = if $result.exit_code == 0 { "accept" } else { "reject" }
    if $actual != $fixture.kernel {
        fail $"fixture ($fixture.name) expected kernel ($fixture.kernel), got ($actual): ((combined-output $result) | str trim)"
    }

    let expected_fragment = ($fixture | get -o kernel_error_contains)
    let output = (combined-output $result)
    if $fixture.kernel == "reject" and $expected_fragment != null and not ($output | str contains $expected_fragment) {
        fail $"fixture ($fixture.name) kernel rejected, but log did not contain expected fragment: ($expected_fragment)"
    }

    { name: $fixture.name, kernel: $actual, output: (combined-output $result) }
}

def select-kernel-fixtures [fixtures require_kernel: bool] {
    select-fixtures-with-requirements $fixtures $require_kernel "kernel"
}

def select-fixtures-with-requirements [fixtures require_features: bool phase: string] {
    mut selected = []

    for fixture in $fixtures {
        let missing = if $phase == "kernel" {
            fixture-missing-kernel-requirements $fixture
        } else {
            fixture-missing-requirements $fixture
        }
        if (($missing | length) == 0) {
            $selected = ($selected | append $fixture)
        } else {
            let reason = ($missing | str join ",")
            if $require_features {
                fail $"fixture ($fixture.name) missing required host features: ($reason)"
            }
            print $"($phase) skip fixture ($fixture.name): missing ($reason)"
        }
    }

    $selected
}

def select-fixtures [fixture_names category tag tier exclude_tier local_status kernel_status test_lane] {
    validate-tier-option "selected" $tier
    validate-tier-option "excluded" $exclude_tier
    validate-test-lane-option "selected" $test_lane
    validate-status-option "local" $local_status
    validate-status-option "kernel" $kernel_status

    let fixtures = if $fixture_names == null {
        $FIXTURES
    } else {
        let missing = (
            $fixture_names
            | where {|fixture_name|
                not ($FIXTURES | any {|fixture| $fixture.name == $fixture_name })
            }
        )
        if (($missing | length) > 0) {
            fail $"unknown verifier fixtures: ($missing | str join ',')"
        }
        $FIXTURES | where {|fixture| $fixture.name in $fixture_names }
    }

    let selected = (
        $fixtures
        | where {|fixture| fixture-matches-filters $fixture $category $tag $tier $exclude_tier $local_status $kernel_status $test_lane }
    )

    if (($selected | length) == 0) {
        fail "no verifier fixtures matched the selected filters"
    }

    $selected
}

def has-explicit-fixture-selection [
    fixture
    fixtures
    category
    tag
    tier
    exclude_tier
    test_lane
    local_status
    kernel_status
    fast: bool
    smoke: bool
    full: bool
] {
    (
        $fixture != null
        or $fixtures != null
        or $category != null
        or $tag != null
        or $tier != null
        or $exclude_tier != null
        or $test_lane != null
        or $local_status != null
        or $kernel_status != null
        or $fast
        or $smoke
        or $full
    )
}

def default-main-options [] {
    {
        help: false
        validate: false
        check_host_syscall_tracepoints: false
        list: false
        matrix: false
        json: false
        compat_kernel: null
        kernel: false
        no_kernel: false
        smoke: false
        fast: false
        full: false
        fixture: null
        fixtures: null
        category: null
        tag: null
        tier: null
        exclude_tier: null
        test_lane: null
        local_status: null
        kernel_status: null
        jobs: null
    }
}

def print-main-help [] {
    [
        "Usage:"
        "  > verifier_diff.nu {flags}"
        ""
        "Flags:"
        "  -h, --help: Display this help message"
        "  --validate: Validate fixture metadata and exit without resolving or running the plugin."
        "  --check-host-syscall-tracepoints: Compare this host's sys_enter tracepoints with modeled fallback coverage and exit."
        "  --list: List verifier fixtures and exit."
        "  --matrix: Print verifier fixture counts by tier and category, then exit."
        "  --json: Emit JSON for --list or --matrix."
        "  --compat-kernel <string>: With --list or --matrix, compare effective minimums against this kernel release."
        "  --kernel: Require kernel verifier checks instead of auto-skipping missing prerequisites."
        "  --no-kernel: Run only local dry-run compiler/VCC checks."
        "  --smoke: Run the default smoke lane: fast-tier, host-safe fixtures."
        "  --fast: Run only fixtures in the fast tier."
        "  --full: Run all fixtures when no narrower filter is selected."
        "  --fixture <string>: Run a fixture by exact name. May be repeated."
        "  --fixtures <list<string>>: Run one or more fixtures by exact name, for example --fixtures [a b]."
        "  --category <string>: Run fixtures with an exact category."
        "  --tag <string>: Run fixtures containing a tag."
        "  --tier <string>: Run fixtures in a tier: fast, btf, kernel, or vm-only."
        "  --exclude-tier <string>: Exclude fixtures in a tier: fast, btf, kernel, or vm-only."
        "  --test-lane <string>: Run fixtures in a default test lane: host-safe, host-gated, dry-run, or vm-only."
        "  --local-status <string>: Run fixtures whose expected local status is accept, reject, or skip."
        "  --kernel-status <string>: Run fixtures whose expected kernel status is accept, reject, or skip."
        "  --jobs <int>: Number of local fixture dry-run jobs. Defaults to VERIFIER_DIFF_JOBS or 4."
    ] | str join "\n" | print
}

def trim-surrounding-quotes [value: string] {
    let trimmed = ($value | str trim)
    if ($trimmed | str starts-with '"') and ($trimmed | str ends-with '"') {
        return ($trimmed | str replace -r '^"' "" | str replace -r '"$' "")
    }
    if ($trimmed | str starts-with "'") and ($trimmed | str ends-with "'") {
        return ($trimmed | str replace -r "^'" "" | str replace -r "'$" "")
    }

    $value
}

def flag-assignment [arg: string] {
    let parts = ($arg | split row "=")
    if (($parts | length) <= 1) {
        return { flag: $arg, has_value: false, value: null }
    }

    {
        flag: ($parts | first)
        has_value: true
        value: (trim-surrounding-quotes ($parts | skip 1 | str join "="))
    }
}

def require-flag-value [args idx: int flag: string] {
    let value_idx = ($idx + 1)
    if $value_idx >= ($args | length) {
        fail $"($flag) requires a value"
    }

    let value = ($args | get $value_idx)
    if (($value | describe) == "string") and ($value | str starts-with "--") {
        fail $"($flag) requires a value"
    }

    $value
}

def string-flag-value [value] {
    $value | into string
}

def fixture-flag-values [value] {
    if (($value | describe) | str starts-with "list") {
        return ($value | each {|item| $item | into string })
    }

    [($value | into string)]
}

def list-string-flag-value [flag: string value] {
    if (($value | describe) | str starts-with "list") {
        return ($value | each {|item| $item | into string })
    }

    if (($value | describe) == "string") and ($value | str starts-with "[") {
        let parsed = try {
            $value | from nuon
        } catch {
            null
        }

        if $parsed != null and (($parsed | describe) | str starts-with "list") {
            return ($parsed | each {|item| $item | into string })
        }

        if ($value | str ends-with "]") {
            let inner = (
                $value
                | str trim
                | str replace -r '^\[' ""
                | str replace -r '\]$' ""
            )
            let items = if ($inner | str contains ",") {
                $inner | split row ","
            } else {
                $inner | split row " "
            }
            let normalized = (
                $items
                | each {|item| $item | str trim }
                | where {|item| $item != "" }
            )

            if (($normalized | length) > 0) {
                return $normalized
            }
        }
    }

    fail $"($flag) expects a Nushell list, for example: ($flag) [fixture-a fixture-b]"
}

def int-flag-value [flag: string value] {
    if (($value | describe) == "int") {
        return $value
    }

    try {
        $value | into int
    } catch {
        fail $"($flag) expects an integer"
    }
}

def append-option-list [options key: string values] {
    let current = if ($options | get $key) == null { [] } else { $options | get $key }
    $options | upsert $key ($current | append $values)
}

def parse-main-args [args] {
    mut options = (default-main-options)
    mut i = 0
    while $i < ($args | length) {
        let raw_arg = ($args | get $i)
        if (($raw_arg | describe) != "string") {
            fail $"unexpected positional argument: ($raw_arg)"
        }

        let parsed = (flag-assignment $raw_arg)
        let arg = $parsed.flag
        let has_value = $parsed.has_value

        if $arg in ["-h" "--help"] {
            if $has_value {
                fail $"($arg) does not take a value"
            }
            $options = ($options | upsert help true)
            $i = ($i + 1)
        } else if $arg in ["--validate" "--check-host-syscall-tracepoints" "--list" "--matrix" "--json" "--kernel" "--no-kernel" "--smoke" "--fast" "--full"] {
            if $has_value {
                fail $"($arg) does not take a value"
            }

            let key = ($arg | str substring 2.. | str replace --all "-" "_")
            $options = ($options | upsert $key true)
            $i = ($i + 1)
        } else if $arg in ["--compat-kernel" "--category" "--tag" "--tier" "--exclude-tier" "--test-lane" "--local-status" "--kernel-status"] {
            let value = if $has_value { $parsed.value } else { require-flag-value $args $i $arg }
            let key = ($arg | str substring 2.. | str replace --all "-" "_")
            $options = ($options | upsert $key (string-flag-value $value))
            $i = if $has_value { ($i + 1) } else { ($i + 2) }
        } else if $arg == "--fixture" {
            let value = if $has_value { $parsed.value } else { require-flag-value $args $i $arg }
            $options = (append-option-list $options fixture (fixture-flag-values $value))
            $i = if $has_value { ($i + 1) } else { ($i + 2) }
        } else if $arg == "--fixtures" {
            let value = if $has_value { $parsed.value } else { require-flag-value $args $i $arg }
            $options = (append-option-list $options fixtures (list-string-flag-value $arg $value))
            $i = if $has_value { ($i + 1) } else { ($i + 2) }
        } else if $arg == "--jobs" {
            let value = if $has_value { $parsed.value } else { require-flag-value $args $i $arg }
            $options = ($options | upsert jobs (int-flag-value $arg $value))
            $i = if $has_value { ($i + 1) } else { ($i + 2) }
        } else {
            fail $"unknown argument: ($raw_arg)"
        }
    }

    $options
}

def --wrapped main [...args] {
    if (($env | get -o VERIFIER_DIFF_SOURCE_ONLY) == "1") {
        return
    }

    let options = (parse-main-args $args)
    if $options.help {
        print-main-help
        return
    }

    verifier-diff-main $options
}

def verifier-diff-main [options] {
    let validate = $options.validate
    let check_host_syscall_tracepoints = $options.check_host_syscall_tracepoints
    let list = $options.list
    let matrix = $options.matrix
    let json = $options.json
    let compat_kernel = $options.compat_kernel
    let kernel = $options.kernel
    let no_kernel = $options.no_kernel
    let smoke = $options.smoke
    let fast = $options.fast
    let full = $options.full
    let fixture = $options.fixture
    let fixtures = $options.fixtures
    let category = $options.category
    let tag = $options.tag
    let tier = $options.tier
    let exclude_tier = $options.exclude_tier
    let test_lane = $options.test_lane
    let local_status = $options.local_status
    let kernel_status = $options.kernel_status
    let jobs = $options.jobs

    if $kernel and $no_kernel {
        fail "--kernel and --no-kernel are mutually exclusive"
    }
    if $list and $matrix {
        fail "--list and --matrix are mutually exclusive"
    }
    if $validate and ($list or $matrix) {
        fail "--validate cannot be combined with --list or --matrix"
    }
    if $check_host_syscall_tracepoints and ($validate or $list or $matrix) {
        fail "--check-host-syscall-tracepoints cannot be combined with --validate, --list, or --matrix"
    }
    if $json and not ($list or $matrix) {
        fail "--json is only supported with --list or --matrix"
    }
    if $compat_kernel != null and not ($list or $matrix) {
        fail "--compat-kernel is only supported with --list or --matrix"
    }
    if $fast and $tier != null {
        fail "--fast and --tier are mutually exclusive"
    }
    if $fast and $exclude_tier != null {
        fail "--fast and --exclude-tier are mutually exclusive"
    }
    if $smoke and $fast {
        fail "--smoke and --fast are mutually exclusive"
    }
    if $smoke and $full {
        fail "--smoke and --full are mutually exclusive"
    }
    if $fast and $full {
        fail "--fast and --full are mutually exclusive"
    }
    if $smoke and $tier != null {
        fail "--smoke and --tier are mutually exclusive"
    }
    if $smoke and $exclude_tier != null {
        fail "--smoke and --exclude-tier are mutually exclusive"
    }
    if $smoke and $test_lane != null {
        fail "--smoke and --test-lane are mutually exclusive"
    }
    if $fixture != null and $fixtures != null {
        fail "--fixture and --fixtures are mutually exclusive"
    }

    if $check_host_syscall_tracepoints and (
        $kernel
        or $no_kernel
        or $smoke
        or $fast
        or $full
        or $fixture != null
        or $fixtures != null
        or $category != null
        or $tag != null
        or $tier != null
        or $exclude_tier != null
        or $test_lane != null
        or $local_status != null
        or $kernel_status != null
    ) {
        fail "--check-host-syscall-tracepoints is a standalone host coverage audit and cannot be combined with fixture selection or run-mode flags"
    }

    if $validate and (
        $kernel
        or $no_kernel
        or $smoke
        or $fast
        or $full
        or $fixture != null
        or $fixtures != null
        or $category != null
        or $tag != null
        or $tier != null
        or $exclude_tier != null
        or $test_lane != null
        or $local_status != null
        or $kernel_status != null
    ) {
        fail "--validate checks all fixture metadata and cannot be combined with fixture selection or run-mode flags"
    }

    if $validate {
        let _validated_fixtures = (validate-fixture-metadata $FIXTURES)
        print $"ok: (($FIXTURES | length)) verifier fixtures metadata-valid"
        return
    }

    if $check_host_syscall_tracepoints {
        check-host-syscall-tracepoint-coverage
        return
    }

    if $compat_kernel != null {
        parse-kernel-version $compat_kernel | ignore
    }

    let explicit_selection = (
        has-explicit-fixture-selection
            $fixture
            $fixtures
            $category
            $tag
            $tier
            $exclude_tier
            $test_lane
            $local_status
            $kernel_status
            $fast
            $smoke
            $full
    )
    let default_smoke = (not ($list or $matrix) and not $explicit_selection)
    let selected_tier = if ($smoke or $default_smoke or $fast) { "fast" } else { $tier }
    let selected_test_lane = if ($smoke or $default_smoke) { "host-safe" } else { $test_lane }
    let fixture_names = if $fixture == null { $fixtures } else { $fixture }
    let fixtures = (select-fixtures $fixture_names $category $tag $selected_tier $exclude_tier $local_status $kernel_status $selected_test_lane)
    let validated_fixtures = (validate-fixture-metadata $fixtures)

    if $list {
        let summaries = ($validated_fixtures | each {|fixture| fixture-summary-from-derived $fixture $compat_kernel })
        if $json {
            print ($summaries | to json)
            return
        }

        for summary in $summaries {
            let compat_text = if $compat_kernel == null {
                ""
            } else {
                $" compat_kernel=($summary.compat_kernel) compatible=($summary.compatible_with_compat_kernel) compat_reason=($summary.compat_kernel_reason)"
            }
            print $"($summary.name) target=($summary.target) local=($summary.local) kernel=($summary.kernel) category=($summary.category) tier=($summary.tier) default_test_lane=($summary.default_test_lane) requires=($summary.requires | str join ',') kernel_requires=($summary.kernel_requires | str join ',') effective_min_kernel=($summary.effective_min_kernel) effective_max_kernel_exclusive=($summary.effective_max_kernel_exclusive) kernel_features=(kernel-feature-labels $summary.kernel_features | str join ',') tags=($summary.tags | str join ',')($compat_text)"
        }
        return
    }
    if $matrix {
        if $json {
            print ((fixture-matrix-rows-from-derived $validated_fixtures $compat_kernel) | to json)
        } else {
            print-fixture-matrix-from-derived $validated_fixtures $compat_kernel
        }
        return
    }

    let local_jobs = (resolve-local-jobs $jobs)
    let plugin_bin = (resolve-plugin-bin $REPO_ROOT)
    print $"Using plugin: ($plugin_bin)"
    if $local_jobs > 1 {
        print $"Using local fixture jobs: ($local_jobs)"
    }
    if $default_smoke {
        print "Using default smoke lane: --tier fast --test-lane host-safe. Pass --full for the complete fixture sweep."
    }

    let local_fixtures = (select-fixtures-with-requirements $fixtures $kernel "local")
    if (($local_fixtures | length) == 0) {
        print "ok: 0 local fixtures"
        return
    }

    let local_results = (check-local-fixtures $plugin_bin $local_fixtures $local_jobs)

    let local_accepts = (
        $local_fixtures
        | zip $local_results
        | where {|pair| ($pair.1 | get local) == "accept" }
        | each {|pair| $pair.0 }
    )

    if $no_kernel {
        print $"ok: (($local_fixtures | length)) local fixtures, kernel checks disabled"
        return
    }

    let kernel_candidates = (
        $local_accepts
        | where {|fixture| $fixture.kernel != "skip" }
    )
    let kernel_fixtures = (select-kernel-fixtures $kernel_candidates $kernel)
    if (($kernel_fixtures | length) == 0) {
        print $"ok: (($local_fixtures | length)) local fixtures, no kernel fixtures"
        return
    }

    let preflight = (kernel-preflight)
    if not $preflight.available {
        let reason = ($preflight.reasons | str join "; ")
        if $kernel {
            fail $"kernel verifier checks requested but unavailable: ($reason)"
        }
        print $"kernel skip: ($reason)"
        print $"ok: (($local_fixtures | length)) local fixtures"
        return
    }

    let tmp_dir = (^mktemp -d | str trim)
    try {
        $kernel_fixtures
        | each {|fixture|
            let result = (run-kernel-fixture $plugin_bin $fixture $tmp_dir)
            print $"kernel ($result.kernel)  ($fixture.name)"
            $result
        }
        | ignore
        rm -rf $tmp_dir
    } catch { |err|
        try { rm -rf $tmp_dir } catch { |_| null }
        error make $err
    }

    print $"ok: (($local_fixtures | length)) local fixtures, (($kernel_fixtures | length)) kernel fixtures"
}
