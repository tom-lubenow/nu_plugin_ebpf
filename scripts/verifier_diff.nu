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
    { target: "fentry.s:security_file_open" feature_keys: ["kernel:btf-vmlinux" "program:BPF_PROG_TYPE_TRACING" "program:bpf-trampoline" "section:sleepable-program"] }
    { target: "tp_btf:sys_enter" feature_keys: ["kernel:btf-vmlinux" "program:BPF_PROG_TYPE_TRACING"] }
    { target: "lsm_cgroup:socket_bind" feature_keys: ["kernel:btf-vmlinux" "program:BPF_PROG_TYPE_TRACING" "program:bpf-trampoline" "program:BPF_PROG_TYPE_LSM" "attach:BPF_LSM_CGROUP"] }
    { target: "lsm.s:file_open" feature_keys: ["kernel:btf-vmlinux" "program:BPF_PROG_TYPE_TRACING" "program:bpf-trampoline" "program:BPF_PROG_TYPE_LSM" "section:sleepable-program"] }
    { target: "struct_ops:sched_ext_ops.init" feature_keys: ["kernel:btf-vmlinux" "program:bpf-trampoline" "program:BPF_PROG_TYPE_STRUCT_OPS" "struct_ops:sched_ext_ops" "section:sleepable-program"] }
    { target: "struct_ops:tcp_congestion_ops" feature_keys: ["kernel:btf-vmlinux" "program:bpf-trampoline" "program:BPF_PROG_TYPE_STRUCT_OPS" "struct_ops:tcp_congestion_ops"] }
    { target: "kprobe.multi:vfs_*" feature_keys: ["program:BPF_PROG_TYPE_KPROBE" "attach:BPF_TRACE_KPROBE_MULTI"] }
    { target: "uprobe.s:/bin/bash:main" feature_keys: ["program:BPF_PROG_TYPE_KPROBE" "section:sleepable-program"] }
    { target: "uprobe.multi.s:/bin/bash:read*" feature_keys: ["program:BPF_PROG_TYPE_KPROBE" "attach:BPF_TRACE_UPROBE_MULTI" "section:sleepable-program"] }
    { target: "raw_tracepoint.w:sys_enter" feature_keys: ["program:BPF_PROG_TYPE_RAW_TRACEPOINT" "section:raw_tracepoint.w"] }
    { target: "tracepoint:syscalls/sys_enter_openat" feature_keys: ["program:BPF_PROG_TYPE_TRACEPOINT"] }
    { target: "perf_event:software:cpu-clock:period=100000" feature_keys: ["program:BPF_PROG_TYPE_PERF_EVENT"] }
    { target: "xdp:lo:drv:frags" feature_keys: ["program:BPF_PROG_TYPE_XDP" "attach:xdp-drv" "section:xdp.frags"] }
    { target: "xdp:devmap" feature_keys: ["program:BPF_PROG_TYPE_XDP" "attach:BPF_XDP_DEVMAP"] }
    { target: "xdp:cpumap" feature_keys: ["program:BPF_PROG_TYPE_XDP" "attach:BPF_XDP_CPUMAP"] }
    { target: "socket_filter:tcp4:127.0.0.1:8080" feature_keys: ["program:BPF_PROG_TYPE_SOCKET_FILTER"] }
    { target: "tc:lo:ingress" feature_keys: ["program:BPF_PROG_TYPE_SCHED_CLS"] }
    { target: "tc_action:demo-action" feature_keys: ["program:BPF_PROG_TYPE_SCHED_ACT"] }
    { target: "tcx:lo:egress" feature_keys: ["attach:tcx"] }
    { target: "netkit:lo:peer" feature_keys: ["attach:netkit"] }
    { target: "flow_dissector:/proc/self/ns/net" feature_keys: ["program:BPF_PROG_TYPE_FLOW_DISSECTOR"] }
    { target: "netfilter:ipv4:pre_routing:priority=-100:defrag" feature_keys: ["attach:netfilter-link" "attach:netfilter-defrag"] }
    { target: "lwt_seg6local:demo-route" feature_keys: ["program:BPF_PROG_TYPE_LWT" "program:BPF_PROG_TYPE_LWT_SEG6LOCAL"] }
    { target: "sk_lookup:/proc/self/ns/net" feature_keys: ["program:BPF_PROG_TYPE_SK_LOOKUP"] }
    { target: "sk_msg:/sys/fs/bpf/demo_sockmap" feature_keys: ["program:BPF_PROG_TYPE_SK_MSG"] }
    { target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap" feature_keys: ["program:BPF_PROG_TYPE_SK_SKB"] }
    { target: "sk_reuseport:migrate" feature_keys: ["attach:BPF_SK_REUSEPORT_SELECT" "attach:BPF_SK_REUSEPORT_SELECT_OR_MIGRATE"] }
    { target: "cgroup_skb:/sys/fs/cgroup:egress" feature_keys: ["program:BPF_PROG_TYPE_CGROUP_SKB"] }
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
const PROGRAM_MAP_KERNEL_FEATURE_EXPECTATIONS = [
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
    source: "https://github.com/torvalds/linux/blob/v6.13/kernel/sched/ext.c"
}
const KERNEL_FEATURE_KFUNC_SCX_BPF_REENQUEUE_LOCAL = {
    key: "kfunc:scx_bpf_reenqueue_local"
    min_kernel: "6.12"
    max_kernel_exclusive: "6.23"
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
    { helper: "bpf_map_push_elem", kinds: ["queue" "stack" "bloom-filter"] }
    { helper: "bpf_map_peek_elem", kinds: ["queue" "stack" "bloom-filter"] }
    { helper: "bpf_map_pop_elem", kinds: ["queue" "stack"] }
    { helper: "bpf_redirect_map", kinds: ["devmap" "devmap-hash" "cpumap" "xskmap"] }
    { helper: "bpf_map_lookup_percpu_elem", kinds: ["per-cpu-hash" "per-cpu-array" "lru-per-cpu-hash"] }
    { helper: "bpf_for_each_map_elem", kinds: ["hash" "array" "lru-hash" "per-cpu-hash" "per-cpu-array" "lru-per-cpu-hash"] }
    { helper: "bpf_timer_init", kinds: ["hash" "array" "lru-hash"] }
]

const HELPER_CALL_FIXED_MAP_KIND_FEATURES = [
    { helper: "bpf_tail_call", kind: "prog-array" }
    { helper: "bpf_perf_event_output", kind: "perf-event-array" }
    { helper: "bpf_skb_output", kind: "perf-event-array" }
    { helper: "bpf_xdp_output", kind: "perf-event-array" }
    { helper: "bpf_perf_event_read", kind: "perf-event-array" }
    { helper: "bpf_perf_event_read_value", kind: "perf-event-array" }
    { helper: "bpf_get_stackid", kind: "stack-trace" }
    { helper: "bpf_skb_under_cgroup", kind: "cgroup-array" }
    { helper: "bpf_current_task_under_cgroup", kind: "cgroup-array" }
    { helper: "bpf_ringbuf_output", kind: "ringbuf" }
    { helper: "bpf_ringbuf_reserve", kind: "ringbuf" }
    { helper: "bpf_ringbuf_reserve_dynptr", kind: "ringbuf" }
    { helper: "bpf_ringbuf_query", kind: "ringbuf" }
    { helper: "bpf_user_ringbuf_drain", kind: "user-ringbuf" }
    { helper: "bpf_sk_redirect_map", kind: "sockmap" }
    { helper: "bpf_sock_map_update", kind: "sockmap" }
    { helper: "bpf_msg_redirect_map", kind: "sockmap" }
    { helper: "bpf_sock_hash_update", kind: "sockhash" }
    { helper: "bpf_msg_redirect_hash", kind: "sockhash" }
    { helper: "bpf_sk_redirect_hash", kind: "sockhash" }
    { helper: "bpf_sk_select_reuseport", kind: "reuseport-sockarray" }
    { helper: "bpf_sk_storage_get", kind: "sk-storage" }
    { helper: "bpf_sk_storage_delete", kind: "sk-storage" }
    { helper: "bpf_task_storage_get", kind: "task-storage" }
    { helper: "bpf_task_storage_delete", kind: "task-storage" }
    { helper: "bpf_inode_storage_get", kind: "inode-storage" }
    { helper: "bpf_inode_storage_delete", kind: "inode-storage" }
    { helper: "bpf_cgrp_storage_get", kind: "cgrp-storage" }
    { helper: "bpf_cgrp_storage_delete", kind: "cgrp-storage" }
    { helper: "bpf_get_local_storage", kind: "deprecated-cgroup-storage" }
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
    { name: "bpf_skb_cgroup_id", feature: $KERNEL_FEATURE_BPF_SKB_CGROUP_ID }
    { name: "bpf_skb_ancestor_cgroup_id", feature: $KERNEL_FEATURE_BPF_SKB_ANCESTOR_CGROUP_ID }
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
    { name: "scx_bpf_cpu_node", min_kernel: "6.15", source: "https://github.com/torvalds/linux/blob/v6.15/kernel/sched/ext_idle.c" }
    { name: "scx_bpf_cpu_rq", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_cpuperf_cap", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_cpuperf_cur", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_cpuperf_set", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_create_dsq", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_destroy_dsq", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_dispatch_cancel", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_dispatch_nr_slots", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c" }
    { name: "scx_bpf_dsq_insert", min_kernel: "6.13", source: "https://github.com/torvalds/linux/blob/v6.13/kernel/sched/ext.c", max_kernel_exclusive: "6.23" }
    { name: "scx_bpf_dsq_insert___v2", min_kernel: "6.19", source: "https://github.com/torvalds/linux/blob/v6.19/kernel/sched/ext.c" }
    { name: "scx_bpf_dsq_insert_vtime", min_kernel: "6.13", source: "https://github.com/torvalds/linux/blob/v6.13/kernel/sched/ext.c", max_kernel_exclusive: "6.23" }
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
    { name: "scx_bpf_reenqueue_local", min_kernel: "6.12", source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c", max_kernel_exclusive: "6.23" }
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
    { target: "xdp:lo" field: "packet_len" feature: $KERNEL_FEATURE_CTX_XDP_PACKET_LEN }
    { target: "xdp:lo" field: "data" feature: $KERNEL_FEATURE_CTX_XDP_DATA }
    { target: "sk_msg:/sys/fs/bpf/demo_sockmap" field: "packet_len" feature: $KERNEL_FEATURE_CTX_SK_MSG_PACKET_LEN }
    { target: "sk_msg:/sys/fs/bpf/demo_sockmap" field: "sk" feature: $KERNEL_FEATURE_CTX_SK_MSG_SK }
    { target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap" field: "sk" feature: $KERNEL_FEATURE_CTX_SK_SKB_SK }
    { target: "tc:lo:ingress" field: "sk" feature: $KERNEL_FEATURE_CTX_SKB_SK }
    { target: "sk_reuseport:migrate" field: "migrating_sk" feature: $KERNEL_FEATURE_CTX_SK_REUSEPORT_MIGRATING_SK }
    { target: "sock_ops:/sys/fs/cgroup" field: "packet_len" feature: $KERNEL_FEATURE_CTX_SOCK_OPS_PACKET_LEN }
    { target: "netfilter:ipv4:pre_routing:priority=-100:defrag" field: "hook" feature: $KERNEL_FEATURE_CTX_NETFILTER_HOOK }
    { target: "lirc_mode2:/dev/lirc0" field: "sample" feature: $KERNEL_FEATURE_CTX_LIRC_SAMPLE }
    { target: "perf_event:software:cpu-clock:period=100000" field: "addr" feature: $KERNEL_FEATURE_CTX_PERF_ADDR }
    { target: "cgroup_device:/sys/fs/cgroup" field: "major" feature: $KERNEL_FEATURE_CTX_DEVICE_MAJOR }
    { target: "cgroup_sysctl:/sys/fs/cgroup" field: "write" feature: $KERNEL_FEATURE_CTX_SYSCTL_WRITE }
    { target: "cgroup_sockopt:/sys/fs/cgroup:get" field: "optval" feature: $KERNEL_FEATURE_CTX_SOCKOPT_OPTVAL }
    { target: "cgroup_sock:/sys/fs/cgroup:sock_create" field: "state" feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_STATE }
    { target: "sk_lookup:/proc/self/ns/net" field: "cookie" feature: $KERNEL_FEATURE_CTX_SK_LOOKUP_COOKIE }
    { target: "cgroup_sock_addr:/sys/fs/cgroup:connect4" field: "user_ip4" feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_USER_IP4 }
    { target: "iter:task_vma" field: "task" feature: $KERNEL_FEATURE_CTX_ITER_TASK_VMA_TASK }
    { target: "iter:bpf_map_elem" field: "map" feature: $KERNEL_FEATURE_CTX_ITER_MAP_ELEM_MAP }
    { target: "iter:sockmap" field: "sk" feature: $KERNEL_FEATURE_CTX_ITER_SOCKMAP_SOCK }
    { target: "iter:unix" field: "uid" feature: $KERNEL_FEATURE_CTX_ITER_UNIX_UID }
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
    { target: "raw_tracepoint:sys_enter" field: "ktime_coarse" feature: $KERNEL_FEATURE_BPF_KTIME_GET_COARSE_NS }
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
]

const PROGRAM_CONTEXT_FIELD_KERNEL_FEATURE_EXPECTATIONS = [
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
        feature_keys: ["ctx:rx_queue_mapping" "ctx:sk"]
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
        feature_keys: ["ctx:sk" "helper:bpf_probe_read_kernel"]
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
        target: "kprobe:sys_clone"
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
        target: "tracepoint:syscalls/sys_enter_openat"
        program: [
            '{|ctx|'
            '  $ctx.current_task.pid | count'
            '  0'
            '}'
        ]
        feature_keys: ["ctx:task" "helper:bpf_get_current_task_btf" "helper:bpf_probe_read_kernel"]
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
        target: "netfilter:ipv4:pre_routing:priority=-100:defrag"
        program: [
            '{|ctx|'
            '  ($ctx.state.in.ifindex + $ctx.skb.len) | count'
            '  "accept"'
            '}'
        ]
        feature_keys: ["ctx:state" "ctx:skb" "helper:bpf_probe_read_kernel"]
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
        feature_keys: ["ctx:state" "ctx:skb" "helper:bpf_probe_read_kernel"]
    }
    {
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.arg.file.f_flags | count'
            '  0'
            '}'
        ]
        feature_keys: ["helper:bpf_probe_read_kernel"]
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
]

const PROGRAM_SURFACE_KERNEL_FEATURE_EXPECTATIONS = [
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
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|event|'
            '  $event.cb_flags = 1'
            '  1'
            '}'
        ]
        feature_keys: ["helper:bpf_sock_ops_cb_flags_set"]
    }
]

const PROGRAM_KFUNC_KERNEL_FEATURE_EXPECTATIONS = [
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
]

const FIXTURES = [
    {
        name: "raw-tracepoint-count"
        category: "tracing"
        tags: [raw-tracepoint counter]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  ($ctx.arg0 + $ctx.arg1) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-tracepoint-context-param-alias"
        category: "context-surface"
        tags: [raw-tracepoint context source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|event|'
            '  $event.pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-tracepoint-random-context"
        category: "context-surface"
        tags: [raw-tracepoint context random]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  ($ctx.random + $ctx.prandom_u32) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-tracepoint-time-context"
        category: "context-surface"
        tags: [raw-tracepoint context time]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  ($ctx.ktime + $ctx.ktime_boot + $ctx.ktime_coarse + $ctx.ktime_tai + $ctx.jiffies) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "kprobe-multi-context"
        category: "tracing"
        tags: [kprobe-multi context]
        target: "kprobe.multi:vfs_*"
        program: [
            '{|ctx|'
            '  ($ctx.arg0 + $ctx.func_ip + $ctx.attach_cookie) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "uprobe-multi-context"
        category: "tracing"
        tags: [uprobe-multi context]
        target: "uprobe.multi:/bin/true:*"
        program: [
            '{|ctx|'
            '  ($ctx.pid + $ctx.func_ip + $ctx.attach_cookie) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "kretprobe-context"
        category: "tracing"
        tags: [kretprobe context]
        target: "kretprobe:sys_clone"
        program: [
            '{|ctx|'
            '  ($ctx.retval + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "ksyscall-context"
        category: "tracing"
        tags: [ksyscall context]
        target: "ksyscall:nanosleep"
        program: [
            '{|ctx|'
            '  ($ctx.arg0 + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "kretsyscall-context"
        category: "tracing"
        tags: [kretsyscall context]
        target: "kretsyscall:nanosleep"
        program: [
            '{|ctx|'
            '  ($ctx.retval + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "tracepoint-openat-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_openat"
        program: [
            '{|ctx|'
            '  ($ctx.id + ($ctx.args | get 1) + $ctx.current_task.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "perf-event-context"
        category: "tracing"
        tags: [perf-event context]
        target: "perf_event:software:cpu-clock:period=100000"
        program: [
            '{|ctx|'
            '  ($ctx.cpu + $ctx.sample_period + $ctx.addr + $ctx.perf_counter) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "perf-event-hardware-frequency-context"
        category: "context-surface"
        tags: [perf-event context hardware freq]
        target: "perf_event:hardware:instructions:freq=99"
        program: [
            '{|ctx|'
            '  ($ctx.perf_counter + $ctx.perf_enabled + $ctx.perf_running + $ctx.cpu) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "tp-btf-context"
        category: "tracing"
        tags: [tp-btf context]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  ($ctx.arg0.orig_ax + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "fentry-context"
        category: "tracing"
        tags: [fentry context]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  ($ctx.arg.file.f_flags + $ctx.pid + $ctx.arg_count) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lsm-context"
        category: "tracing"
        tags: [lsm context]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  ($ctx.arg.file.f_flags + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lsm-cgroup-context"
        category: "tracing"
        tags: [lsm-cgroup context]
        requires: [kernel-btf]
        target: "lsm_cgroup:socket_bind"
        program: [
            '{|ctx|'
            '  ($ctx.arg2 + $ctx.arg_count + $ctx.pid) | count'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "syscall-helper-context"
        category: "tracing"
        tags: [syscall helper-call]
        target: "syscall:demo"
        program: [
            '{||'
            '  helper-call "bpf_sys_close" 0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "freplace-context"
        category: "tracing"
        tags: [freplace context]
        target: "freplace:replace_me"
        program: [
            '{|ctx|'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "xdp-packet-count"
        category: "packet"
        tags: [xdp counter]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx.packet_len | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-frags-driver-context"
        category: "context-surface"
        tags: [xdp context frags]
        requires: [loopback-interface]
        target: "xdp:lo:drv:frags"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.rx_queue_index + $ctx.xdp_buff_len + $ctx.ancestor_cgroup_id.0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "xdp-devmap-secondary-context"
        category: "program-model"
        tags: [xdp devmap context]
        target: "xdp:devmap"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.egress_ifindex) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "xdp-cpumap-secondary-context"
        category: "program-model"
        tags: [xdp cpumap context]
        target: "xdp:cpumap"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.rx_queue_index) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "map-put-get-null-checked"
        category: "maps"
        tags: [hash-map null-check]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-put seen_args 0 --kind hash'
            '  let entry = (0 | map-get seen_args --kind hash)'
            '  if $entry {'
            '    $entry | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-direct-pointer-branch"
        category: "maps"
        tags: [hash-map null-check branch]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-put direct_seen_args 0 --kind hash'
            '  let entry = (0 | map-get direct_seen_args --kind hash)'
            '  if $entry {'
            '    $entry | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-record-key-put-get"
        category: "maps"
        tags: [maps map-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define keyed --kind hash --key-type "record{pid:int,cookie:int}" --value-type int'
            '  let key = { pid: 1, cookie: 7 }'
            '  42 | map-put keyed $key --kind hash'
            '  let entry = ($key | map-get keyed --kind hash)'
            '  if $entry {'
            '    $entry | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "map-define-aligned-record-key-put-get"
        category: "maps"
        tags: [maps map-define records alignment accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define keyed_aligned --kind hash --key-type "record{tag:int,flag:bool}" --value-type int'
            '  let key = { tag: 7, flag: true }'
            '  42 | map-put keyed_aligned $key --kind hash'
            '  let entry = ($key | map-get keyed_aligned --kind hash)'
            '  if $entry {'
            '    $entry | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "annotated-mut-record-alignment"
        category: "globals"
        tags: [globals records alignment accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut state: record<tag: bool count: int> = { tag: true, count: 7 }'
            '  $state.count | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "map-define-null-only-lookup-keeps-value-layout"
        category: "maps"
        tags: [maps map-define accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define null_only --kind hash --value-type int'
            '  42 | map-put null_only 0 --kind hash'
            '  let entry = (0 | map-get null_only --kind hash)'
            '  if $entry { 0 }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "map-define-max-entries"
        category: "maps"
        tags: [maps map-define max-entries accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define small_seen --kind hash --value-type int --max-entries 32'
            '  42 | map-put small_seen 0 --kind hash'
            '  let entry = (0 | map-get small_seen --kind hash)'
            '  if $entry { $entry | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "queue-map-push-peek-record"
        category: "maps"
        tags: [maps queue map-push map-peek records accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { pid: $ctx.arg0, cookie: 7 } | map-push recent_args --kind queue'
            '  let entry = (map-peek recent_args --kind queue)'
            '  if $entry {'
            '    $entry.pid | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "stack-map-push-pop-record"
        category: "maps"
        tags: [maps stack map-push map-pop records accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { pid: $ctx.arg0, cookie: 7 } | map-push recent_args --kind stack'
            '  let entry = (map-pop recent_args --kind stack)'
            '  if $entry {'
            '    $entry.cookie | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "bloom-filter-push-contains"
        category: "maps"
        tags: [maps bloom-filter map-push map-contains accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-push seen_args --kind bloom-filter'
            '  $ctx.arg0 | map-contains seen_args --kind bloom-filter'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "per-cpu-hash-map-put-get"
        category: "maps"
        tags: [maps per-cpu-hash map-put map-get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-put cpu_seen 0 --kind per-cpu-hash'
            '  let entry = (0 | map-get cpu_seen --kind per-cpu-hash)'
            '  if $entry {'
            '    $entry | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lru-per-cpu-hash-map-put-delete"
        category: "maps"
        tags: [maps lru-per-cpu-hash map-put map-delete accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-put lru_cpu_seen 0 --kind lru-per-cpu-hash'
            '  0 | map-delete lru_cpu_seen --kind lru-per-cpu-hash'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "task-storage-map-get-init"
        category: "maps"
        tags: [maps local-storage task-storage map-get accept]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  let state = ($ctx.task | map-get task_state --kind task-storage --init { hits: 0 })'
            '  if $state {'
            '    $state.hits | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "task-storage-map-delete"
        category: "maps"
        tags: [maps local-storage task-storage map-delete accept]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.task | map-delete task_state --kind task-storage'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "sk-storage-map-contains"
        category: "maps"
        tags: [maps local-storage sk-storage map-contains accept]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:post_bind4"
        program: [
            '{|ctx|'
            '  $ctx.sk | map-contains sock_state --kind sk-storage'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "inode-storage-map-delete"
        category: "maps"
        tags: [maps local-storage inode-storage map-delete accept]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  $ctx.arg.file.f_inode | map-delete inode_state --kind inode-storage'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "cgrp-storage-map-contains"
        category: "maps"
        tags: [maps local-storage cgrp-storage map-contains accept]
        requires: [kernel-btf]
        target: "fentry:security_file_open"
        program: [
            '{|ctx|'
            '  $ctx.current_cgroup | map-contains cgrp_state --kind cgrp-storage'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "typed-map-to-map-copy"
        category: "maps"
        tags: [maps records map-put map-get accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  { pid: $ctx.arg0, cookie: 7 } | map-put src_records 0 --kind hash'
            '  let entry = (0 | map-get src_records --kind hash)'
            '  if $entry {'
            '    $entry | map-put dst_records 0 --kind hash'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "ringbuf-query-built-in-events"
        category: "maps"
        tags: [helper-call ringbuf reserved-name]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_ringbuf_query" events 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "ringbuf-reserve-submit-balanced"
        category: "helper-state"
        tags: [ringbuf ref-lifetime]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let rec = (helper-call "bpf_ringbuf_reserve" events 8 0)'
            '  if $rec {'
            '    helper-call "bpf_ringbuf_submit" $rec 0'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "ringbuf-reserve-discard-balanced"
        category: "helper-state"
        tags: [ringbuf ref-lifetime]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let rec = (helper-call "bpf_ringbuf_reserve" events 8 0)'
            '  if $rec {'
            '    helper-call "bpf_ringbuf_discard" $rec 0'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "ringbuf-reserve-rejects-leak"
        category: "helper-state"
        tags: [ringbuf ref-lifetime reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let rec = (helper-call "bpf_ringbuf_reserve" events 8 0)'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased ringbuf record reference"
    }
    {
        name: "ringbuf-reserve-rejects-double-submit"
        category: "helper-state"
        tags: [ringbuf ref-lifetime reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let rec = (helper-call "bpf_ringbuf_reserve" events 8 0)'
            '  if $rec {'
            '    helper-call "bpf_ringbuf_submit" $rec 0'
            '    helper-call "bpf_ringbuf_submit" $rec 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ringbuf record already released"
    }
    {
        name: "ringbuf-reserve-rejects-submit-after-discard"
        category: "helper-state"
        tags: [ringbuf ref-lifetime reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let rec = (helper-call "bpf_ringbuf_reserve" events 8 0)'
            '  if $rec {'
            '    helper-call "bpf_ringbuf_discard" $rec 0'
            '    helper-call "bpf_ringbuf_submit" $rec 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ringbuf record already released"
    }
    {
        name: "ringbuf-dynptr-reserve-submit-balanced"
        category: "helper-state"
        tags: [ringbuf dynptr ref-lifetime]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "ringbuf-dynptr-reserve-discard-balanced"
        category: "helper-state"
        tags: [ringbuf dynptr ref-lifetime]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "ringbuf-dynptr-rejects-leak"
        category: "helper-state"
        tags: [ringbuf dynptr ref-lifetime reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased ringbuf dynptr reservation"
    }
    {
        name: "ringbuf-dynptr-allows-slot-reuse-after-submit"
        category: "helper-state"
        tags: [ringbuf dynptr ref-lifetime]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "ringbuf-dynptr-allows-slot-reuse-after-discard"
        category: "helper-state"
        tags: [ringbuf dynptr ref-lifetime]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 0'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "ringbuf-dynptr-rejects-double-submit"
        category: "helper-state"
        tags: [ringbuf dynptr ref-lifetime reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ringbuf dynptr reservation already released"
    }
    {
        name: "ringbuf-dynptr-rejects-submit-after-discard"
        category: "helper-state"
        tags: [ringbuf dynptr ref-lifetime reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 0'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ringbuf dynptr reservation already released"
    }
    {
        name: "dynptr-data-rejects-uninitialized"
        category: "helper-state"
        tags: [dynptr reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_dynptr_data" $d 0 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires initialized dynptr stack object"
    }
    {
        name: "dynptr-from-mem-initializes-map-value"
        category: "helper-state"
        tags: [dynptr accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  "abcdefgh" | map-put dynptr_buffers 0 --kind array'
            '  let entry = (0 | map-get dynptr_buffers --kind array)'
            '  if $entry {'
            '    let d = "0123456789abcdef"'
            '    helper-call "bpf_dynptr_from_mem" $entry 8 0 $d'
            '    let ptr = (helper-call "bpf_dynptr_data" $d 0 4)'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "dynptr-from-mem-rejects-reinitialize"
        category: "helper-state"
        tags: [dynptr reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  "abcdefgh" | map-put dynptr_reinit_buffers 0 --kind array'
            '  let entry = (0 | map-get dynptr_reinit_buffers --kind array)'
            '  if $entry {'
            '    let d = "0123456789abcdef"'
            '    helper-call "bpf_dynptr_from_mem" $entry 8 0 $d'
            '    helper-call "bpf_dynptr_from_mem" $entry 8 0 $d'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_dynptr_from_mem' arg3 requires uninitialized dynptr stack object slot"
    }
    {
        name: "dynptr-read-write-initialized-from-mem"
        category: "helper-state"
        tags: [dynptr accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  "abcdefgh" | map-put dynptr_rw_buffers 0 --kind array'
            '  let entry = (0 | map-get dynptr_rw_buffers --kind array)'
            '  if $entry {'
            '    let d = "0123456789abcdef"'
            '    let out = "0000"'
            '    let src = "wxyz"'
            '    helper-call "bpf_dynptr_from_mem" $entry 8 0 $d'
            '    helper-call "bpf_dynptr_write" $d 0 $src 4 0'
            '    helper-call "bpf_dynptr_read" $out 4 $d 0 0'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "dynptr-read-rejects-uninitialized"
        category: "helper-state"
        tags: [dynptr reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let out = "0000"'
            '  helper-call "bpf_dynptr_read" $out 4 $d 0 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_dynptr_read' arg2 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-write-rejects-uninitialized"
        category: "helper-state"
        tags: [dynptr reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let src = "wxyz"'
            '  helper-call "bpf_dynptr_write" $d 0 $src 4 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_dynptr_write' arg0 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-kfunc-copy-from-user-initializes-dynptr"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    let d = "0123456789abcdef"'
            '    kfunc-call "bpf_copy_from_user_dynptr" $d 0 4 $ptr'
            '    let size = (kfunc-call "bpf_dynptr_size" $d)'
            '    $size | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "dynptr-kfunc-copy-from-user-rejects-reinitialize"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    let d = "0123456789abcdef"'
            '    kfunc-call "bpf_copy_from_user_dynptr" $d 0 4 $ptr'
            '    kfunc-call "bpf_copy_from_user_dynptr" $d 0 4 $ptr'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_copy_from_user_dynptr' arg0 requires uninitialized dynptr stack object slot"
    }
    {
        name: "dynptr-kfunc-copy-from-user-task-initializes-dynptr"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    let d = "0123456789abcdef"'
            '    kfunc-call "bpf_copy_from_user_task_dynptr" $d 0 4 $ptr $ctx.current_task'
            '    let size = (kfunc-call "bpf_dynptr_size" $d)'
            '    $size | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "dynptr-kfunc-copy-from-user-task-str-initializes-dynptr"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    let d = "0123456789abcdef"'
            '    kfunc-call "bpf_copy_from_user_task_str_dynptr" $d 0 4 $ptr $ctx.current_task'
            '    let size = (kfunc-call "bpf_dynptr_size" $d)'
            '    $size | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "dynptr-kfunc-size-initialized-ringbuf"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  let size = (kfunc-call "bpf_dynptr_size" $d)'
            '  $size | count'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "dynptr-kfunc-size-rejects-uninitialized"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_size" $d'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_size' arg0 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-kfunc-slice-initialized-ringbuf"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  let ptr = (kfunc-call "bpf_dynptr_slice" $d 0 0 4)'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "dynptr-kfunc-slice-rejects-nonzero-buffer"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  let ptr = (kfunc-call "bpf_dynptr_slice" $d 0 1 4)'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_slice' arg2 expects null (0) or pointer"
    }
    {
        name: "dynptr-kfunc-slice-rejects-dynamic-size"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  let size = (helper-call "bpf_get_prandom_u32")'
            '  let ptr = (kfunc-call "bpf_dynptr_slice" $d 0 0 $size)'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_slice' arg3 must be known constant"
    }
    {
        name: "dynptr-kfunc-slice-rejects-uninitialized"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let ptr = (kfunc-call "bpf_dynptr_slice" $d 0 0 4)'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_slice' arg0 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-kfunc-slice-rdwr-initialized-ringbuf"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  let ptr = (kfunc-call "bpf_dynptr_slice_rdwr" $d 0 0 4)'
            '  helper-call "bpf_ringbuf_discard_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "dynptr-kfunc-slice-rdwr-rejects-uninitialized"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let ptr = (kfunc-call "bpf_dynptr_slice_rdwr" $d 0 0 4)'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_slice_rdwr' arg0 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-kfunc-adjust-initialized-ringbuf"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  kfunc-call "bpf_dynptr_adjust" $d 0 4'
            '  let size = (kfunc-call "bpf_dynptr_size" $d)'
            '  $size | count'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "dynptr-kfunc-adjust-rejects-uninitialized"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_adjust" $d 0 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_adjust' arg0 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-kfunc-memset-initialized-ringbuf"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  kfunc-call "bpf_dynptr_memset" $d 0 0 4'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "dynptr-kfunc-memset-rejects-uninitialized"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  kfunc-call "bpf_dynptr_memset" $d 0 0 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_memset' arg0 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-kfunc-null-rdonly-queries-initialized-ringbuf"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  let is_null = (kfunc-call "bpf_dynptr_is_null" $d)'
            '  let is_rdonly = (kfunc-call "bpf_dynptr_is_rdonly" $d)'
            '  $is_null | count'
            '  $is_rdonly | count'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "dynptr-kfunc-copy-initialized-ringbuf"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let dst = "0123456789abcdef"'
            '  let src = "fedcba9876543210"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $dst'
            '  kfunc-call "bpf_dynptr_clone" $dst $src'
            '  kfunc-call "bpf_dynptr_copy" $dst 0 $src 0 4'
            '  helper-call "bpf_ringbuf_submit_dynptr" $dst 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "dynptr-kfunc-copy-rejects-uninitialized-destination"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let dst = "0123456789abcdef"'
            '  let src = "fedcba9876543210"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $src'
            '  kfunc-call "bpf_dynptr_copy" $dst 0 $src 0 4'
            '  helper-call "bpf_ringbuf_discard_dynptr" $src 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_copy' arg0 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-kfunc-copy-rejects-uninitialized-source"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let dst = "0123456789abcdef"'
            '  let src = "fedcba9876543210"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $dst'
            '  kfunc-call "bpf_dynptr_copy" $dst 0 $src 0 4'
            '  helper-call "bpf_ringbuf_discard_dynptr" $dst 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_copy' arg2 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-kfunc-clone-initializes-destination"
        category: "helper-state"
        tags: [kfunc dynptr accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let clone = "fedcba9876543210"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  kfunc-call "bpf_dynptr_clone" $d $clone'
            '  let size = (kfunc-call "bpf_dynptr_size" $clone)'
            '  $size | count'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "dynptr-kfunc-clone-rejects-uninitialized-source"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let clone = "fedcba9876543210"'
            '  kfunc-call "bpf_dynptr_clone" $d $clone'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_clone' arg0 requires initialized dynptr stack object"
    }
    {
        name: "dynptr-kfunc-clone-rejects-use-after-ringbuf-submit"
        category: "helper-state"
        tags: [kfunc dynptr reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let d = "0123456789abcdef"'
            '  let clone = "fedcba9876543210"'
            '  helper-call "bpf_ringbuf_reserve_dynptr" events 8 0 $d'
            '  kfunc-call "bpf_dynptr_clone" $d $clone'
            '  helper-call "bpf_ringbuf_submit_dynptr" $d 0'
            '  kfunc-call "bpf_dynptr_size" $clone'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_dynptr_size' arg0 requires initialized dynptr stack object"
    }
    {
        name: "stackid-built-in-kstacks"
        category: "maps"
        tags: [helper-call stack-trace reserved-name]
        target: "kprobe:sys_clone"
        program: [
            '{|ctx|'
            '  helper-call "bpf_get_stackid" $ctx kstacks 0 | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "stackid-context-fields"
        category: "context-surface"
        tags: [context stack-trace kstack ustack accept]
        target: "kprobe:sys_clone"
        program: [
            '{|ctx|'
            '  ($ctx.kstack + $ctx.ustack) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "task-pt-regs-context"
        category: "context-surface"
        tags: [context task pt-regs helper-backed accept]
        requires: [kernel-btf]
        target: "kprobe:sys_clone"
        program: [
            '{|ctx|'
            '  $ctx.task.pt_regs.arg0 | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "task-pt-regs-bound-context"
        category: "context-surface"
        tags: [context task pt-regs helper-backed source metadata accept]
        requires: [kernel-btf]
        target: "kprobe:sys_clone"
        program: [
            '{|ctx|'
            '  let task = $ctx.task'
            '  $task.pt_regs.arg0 | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "global-scalar-mut"
        category: "globals"
        tags: [data-global scalar]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  mut hits: int = 0'
            '  $hits = ($hits + 1)'
            '  $hits | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-action-cgroup-array-contains"
        category: "packet"
        tags: [tc-action cgroup-array helper-policy]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  map-contains tracked_cgroups 0 --kind cgroup-array'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "xdp-cgroup-array-contains"
        category: "packet"
        tags: [xdp cgroup-array helper-policy]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-contains tracked_cgroups 0 --kind cgroup-array'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tc-action-skb-context"
        category: "context-surface"
        tags: [tc-action context packet]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.protocol + $ctx.mark + $ctx.priority + $ctx.tc_classid + $ctx.hash + $ctx.netns_cookie + $ctx.sk.family) | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "tc-action-skb-context-write"
        category: "context-surface"
        tags: [tc-action context packet writable]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.mark = 7'
            '  $ctx.queue_mapping = 1'
            '  $ctx.priority = 3'
            '  $ctx.tc_index = 2'
            '  $ctx.cb.2 = 9'
            '  $ctx.tc_classid = 42'
            '  $ctx.tstamp = 123'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "tc-action-context-socket-write"
        category: "context-surface"
        tags: [tc-action context writable socket source metadata]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sk = 0'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "tc-helper-backed-socket-projections"
        category: "context-surface"
        tags: [tc context socket helper-backed]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  ($ctx.sk.tcp.snd_cwnd + $ctx.sk.full.family + $ctx.sk.listener.family) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "tc-ingress-skb-context-write"
        category: "context-surface"
        tags: [tc context packet writable]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.protocol + $ctx.mark + $ctx.priority + $ctx.tc_classid + $ctx.hash + $ctx.netns_cookie + $ctx.sk.family) | count'
            '  $ctx.mark = 7'
            '  $ctx.priority = 3'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "tc-egress-helper-backed-context"
        category: "context-surface"
        tags: [tc context helper-backed egress]
        requires: [loopback-interface]
        target: "tc:lo:egress"
        program: [
            '{|ctx|'
            '  ($ctx.skb_cgroup_id + $ctx.skb_ancestor_cgroup_id.0 + $ctx.route_realm + $ctx.cgroup_classid + $ctx.netns_cookie) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "tc-ingress-rejects-egress-context"
        category: "context-policy"
        tags: [tc context reject egress-only]
        requires: [loopback-interface]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx.skb_cgroup_id | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.skb_cgroup_id is only available on tc/tcx egress programs"
    }
    {
        name: "tcx-ingress-skb-context-write"
        category: "context-surface"
        tags: [tcx context packet writable]
        requires: [loopback-interface]
        target: "tcx:lo:ingress"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.protocol + $ctx.mark + $ctx.priority + $ctx.tc_classid + $ctx.hash + $ctx.netns_cookie + $ctx.sk.family) | count'
            '  $ctx.mark = 7'
            '  $ctx.priority = 3'
            '  "next"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "tcx-egress-helper-backed-context"
        category: "context-surface"
        tags: [tcx context helper-backed egress]
        requires: [loopback-interface]
        target: "tcx:lo:egress"
        program: [
            '{|ctx|'
            '  ($ctx.skb_cgroup_id + $ctx.skb_ancestor_cgroup_id.0 + $ctx.route_realm + $ctx.cgroup_classid + $ctx.netns_cookie) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "tcx-ingress-rejects-egress-context"
        category: "context-policy"
        tags: [tcx context reject egress-only]
        requires: [loopback-interface]
        target: "tcx:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx.skb_cgroup_id | count'
            '  "next"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.skb_cgroup_id is only available on tc/tcx egress programs"
    }
    {
        name: "netkit-primary-skb-context-write"
        category: "context-surface"
        tags: [netkit context packet writable]
        requires: [loopback-interface]
        target: "netkit:lo:primary"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.protocol + $ctx.mark + $ctx.priority + $ctx.tc_classid + $ctx.hash + $ctx.netns_cookie + $ctx.sk.family) | count'
            '  $ctx.mark = 7'
            '  $ctx.priority = 3'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "netkit-peer-skb-context"
        category: "context-surface"
        tags: [netkit context packet]
        requires: [loopback-interface]
        target: "netkit:lo:peer"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.protocol + $ctx.hash + $ctx.ingress_ifindex + $ctx.queue_mapping) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "netkit-rejects-egress-context"
        category: "context-policy"
        tags: [netkit context reject egress-only]
        requires: [loopback-interface]
        target: "netkit:lo:primary"
        program: [
            '{|ctx|'
            '  $ctx.skb_cgroup_id | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.skb_cgroup_id is only available on tc_action, tc:egress, and tcx:egress programs"
    }
    {
        name: "xdp-rejects-pid-context"
        category: "context-policy"
        tags: [xdp reject]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx.pid | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.pid is not available on xdp programs"
    }
    {
        name: "xdp-rejects-egress-ifindex-on-interface"
        category: "context-policy"
        tags: [xdp reject devmap]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx.egress_ifindex | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.egress_ifindex is only available on xdp:devmap secondary programs"
    }
    {
        name: "xdp-rejects-egress-ifindex-on-cpumap"
        category: "context-policy"
        tags: [xdp reject cpumap devmap]
        target: "xdp:cpumap"
        program: [
            '{|ctx|'
            '  $ctx.egress_ifindex | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.egress_ifindex is only available on xdp:devmap secondary programs"
    }
    {
        name: "socket-filter-rejects-direct-data"
        category: "context-policy"
        tags: [socket-filter reject]
        target: "socket_filter:udp4:127.0.0.1:31337"
        program: [
            '{|ctx|'
            '  $ctx.data | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.data is not available on socket_filter programs"
    }
    {
        name: "socket-filter-tcp6-context"
        category: "context-surface"
        tags: [socket-filter context ipv6]
        target: "socket_filter:tcp6:[::1]:8080"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.protocol + $ctx.socket_cookie + $ctx.sk.family) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "cgroup-skb-egress-context"
        category: "context-surface"
        tags: [cgroup-skb context]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.protocol + $ctx.mark + $ctx.priority + $ctx.remote_ip4 + $ctx.local_port + $ctx.sk.cgroup_id + $ctx.sk.ancestor_cgroup_id.0) | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "cgroup-skb-egress-timestamp-context-write"
        category: "context-surface"
        tags: [cgroup-skb context writable timestamp egress]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:egress"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  ($ctx.tstamp + $ctx.hwtstamp + $ctx.priority) | count'
            '  $ctx.tstamp = 123'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "cgroup-skb-ingress-rejects-tstamp-write"
        category: "context-policy"
        tags: [cgroup-skb context reject writable ingress]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:ingress"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.tstamp = 123'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.tstamp is only writable on tc_action, tc, tcx, netkit, and cgroup_skb:egress programs"
    }
    {
        name: "cgroup-skb-ingress-writable-context"
        category: "context-surface"
        tags: [cgroup-skb context writable]
        requires: [cgroup-v2]
        target: "cgroup_skb:/sys/fs/cgroup:ingress"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.mark = 7'
            '  $ctx.priority = 3'
            '  $ctx.cb.0 = 1'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "cgroup-sock-create-context-write"
        category: "context-surface"
        tags: [cgroup-sock context writable]
        requires: [cgroup-v2]
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
        local: "accept"
        kernel: "skip"
    }
    {
        name: "cgroup-sock-post-bind6-context"
        category: "context-surface"
        tags: [cgroup-sock context ipv6]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:post_bind6"
        program: [
            '{|ctx|'
            '  (($ctx.local_ip6 | get 1) + ($ctx.sk.local_ip6 | get 1) + $ctx.local_port + $ctx.sk.remote_port) | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "cgroup-sock-rejects-post-bind-mark-write"
        category: "context-policy"
        tags: [cgroup-sock reject writable]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:post_bind4"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.mark = 7'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.mark is only writable on cgroup_sock sock_create/sock_release hooks"
    }
    {
        name: "cgroup-sock-rejects-create-local-ip4"
        category: "context-policy"
        tags: [cgroup-sock reject]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:sock_create"
        program: [
            '{|ctx|'
            '  $ctx.local_ip4 | count'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.local_ip4 is only available on cgroup_sock post_bind4"
    }
    {
        name: "cgroup-sock-rejects-post-bind4-src-ip6"
        category: "context-policy"
        tags: [cgroup-sock reject ipv6]
        requires: [cgroup-v2]
        target: "cgroup_sock:/sys/fs/cgroup:post_bind4"
        program: [
            '{|ctx|'
            '  ($ctx.sk.src_ip6 | get 0) | count'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.sk.src_ip6 is only available on cgroup_sock post_bind6 hooks"
    }
    {
        name: "cgroup-sock-addr-rejects-connect4-local-port"
        category: "context-policy"
        tags: [cgroup-sock-addr reject]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect4"
        program: [
            '{|ctx|'
            '  $ctx.local_port | count'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.local_port is only available on cgroup_sock_addr bind4/bind6 and getsockname4/getsockname6 hooks"
    }
    {
        name: "cgroup-sock-addr-connect4-context"
        category: "context-surface"
        tags: [cgroup-sock-addr context]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect4"
        program: [
            '{|ctx|'
            '  ($ctx.user_ip4 + $ctx.user_port + $ctx.remote_ip4 + $ctx.remote_port + $ctx.sk.family) | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "cgroup-sock-addr-connect4-writable-context"
        category: "context-surface"
        tags: [cgroup-sock-addr context writable]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect4"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.remote_ip4 = 2130706433'
            '  $ctx.remote_port = 8080'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "cgroup-sock-addr-connect6-indexed-context"
        category: "context-surface"
        tags: [cgroup-sock-addr context ipv6]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect6"
        program: [
            '{|ctx|'
            '  (($ctx.user_ip6 | get 3) + ($ctx.remote_ip6 | get 3) + $ctx.user_port + $ctx.remote_port) | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "cgroup-sock-addr-unix-sun-path-write"
        category: "context-surface"
        tags: [cgroup-sock-addr context unix writable kfunc source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sock_addr:/sys/fs/cgroup:connect_unix"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.sun_path = "/tmp/nu-ebpf.sock"'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "flow-dissector-flow-key-context"
        category: "context-surface"
        tags: [flow-dissector context]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  ($ctx.flow_keys.ip_proto + $ctx.flow_keys.nhoff + $ctx.flow_keys.thoff + ($ctx.flow_keys.ipv6_dst | get 3)) | count'
            '  "fallback"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "flow-dissector-packet-context"
        category: "context-surface"
        tags: [flow-dissector context packet]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  ($ctx.data | get 0) | count'
            '  "fallback"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "flow-dissector-rejects-flow-keys-helper-buffer"
        category: "context-policy"
        tags: [flow-dissector reject helper-call]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  helper-call "bpf_skb_load_bytes" $ctx 0 $ctx.flow_keys 4'
            '  "fallback"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects pointer in [Stack, Map], got Context"
    }
    {
        name: "flow-dissector-rejects-flow-keys-kernel-helper-arg"
        category: "context-policy"
        tags: [flow-dissector reject helper-call]
        requires: [netns-self]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  map-define kptr_slots --kind hash --value-type "record{task:kptr:task_struct}"'
            '  let entry = (0 | map-get kptr_slots --kind hash)'
            '  if $entry { helper-call "bpf_kptr_xchg" $entry.task $ctx.flow_keys | count }'
            '  "fallback"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper kptr_xchg ptr expects pointer in [Kernel], got Context"
    }
    {
        name: "netfilter-state-context"
        category: "context-surface"
        tags: [netfilter context]
        target: "netfilter:ipv4:pre_routing:priority=-100:defrag"
        program: [
            '{|ctx|'
            '  ($ctx.hook + $ctx.pf + $ctx.protocol_family + $ctx.state.in.ifindex + $ctx.nf_state.out.ifindex + $ctx.skb.len) | count'
            '  "accept"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "netfilter-bound-state-context"
        category: "context-surface"
        tags: [netfilter context alias]
        target: "netfilter:ipv4:pre_routing:priority=-100:defrag"
        program: [
            '{|ctx|'
            '  let state = ($ctx.nf_state)'
            '  let skb = $ctx.skb'
            '  ($state.in.ifindex + $skb.len) | count'
            '  "accept"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "cgroup-sockopt-retval-write"
        category: "context-surface"
        tags: [cgroup-sockopt context writable]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.retval = 0'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "cgroup-sockopt-bound-tcp-socket-projection"
        category: "context-surface"
        tags: [cgroup-sockopt context source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  $sk.tcp.snd_cwnd | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "cgroup-sockopt-bound-parenthesized-tcp-socket-projection"
        category: "context-surface"
        tags: [cgroup-sockopt context alias parenthesized source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  let sk = ($ctx.sk)'
            '  $sk.tcp.snd_cwnd | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "cgroup-device-context"
        category: "context-surface"
        tags: [cgroup-device context]
        requires: [cgroup-v2]
        target: "cgroup_device:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  ($ctx.access_type + $ctx.device_access + $ctx.device_type + $ctx.major + $ctx.minor) | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "cgroup-sysctl-new-value-write"
        category: "context-surface"
        tags: [cgroup-sysctl context writable]
        requires: [cgroup-v2]
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
        local: "accept"
        kernel: "skip"
    }
    {
        name: "cgroup-sysctl-new-value-alias-write"
        category: "context-surface"
        tags: [cgroup-sysctl context writable alias]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut writable = $ctx'
            '  $writable.new_value = "1"'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "cgroup-sysctl-new-value-parenthesized-alias-write"
        category: "context-surface"
        tags: [cgroup-sysctl context writable alias parenthesized source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut writable = ($ctx)'
            '  $writable.new_value = "1"'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "cgroup-sysctl-current-value-context"
        category: "context-surface"
        tags: [cgroup-sysctl context helper-backed]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  $ctx.current_value | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "cgroup-sysctl-new-value-context"
        category: "context-surface"
        tags: [cgroup-sysctl context helper-backed]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  $ctx.new_value | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "cgroup-sysctl-new-value-parenthesized-alias-read"
        category: "context-surface"
        tags: [cgroup-sysctl context helper-backed alias parenthesized source metadata]
        requires: [cgroup-v2]
        target: "cgroup_sysctl:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let readable = ($ctx)'
            '  $readable.new_value | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "sock-ops-basic-context-write"
        category: "context-surface"
        tags: [sock-ops context writable]
        requires: [cgroup-v2]
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
        local: "accept"
        kernel: "skip"
    }
    {
        name: "sock-ops-cb-flags-helper-backed-write"
        category: "context-surface"
        tags: [sock-ops context writable source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.cb_flags = 1'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "sock-ops-bound-socket-projection-context"
        category: "context-surface"
        tags: [sock-ops context source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let sk = $ctx.sk'
            '  $sk.rx_queue_mapping | count'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "sock-ops-bound-socket-parenthesized-projection-context"
        category: "context-surface"
        tags: [sock-ops context alias parenthesized source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let sk = ($ctx.sk)'
            '  $sk.rx_queue_mapping | count'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "sock-ops-enable-tx-tstamp-kfunc"
        category: "kfunc"
        tags: [sock-ops kfunc timestamp source metadata]
        requires: [cgroup-v2 kernel-btf]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_sock_ops_enable_tx_tstamp" $ctx 0'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "sock-ops-hdr-opt-helpers"
        category: "helper-state"
        tags: [sock-ops helper-call hdr-opt source metadata]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  let opt = "0123456789abcdef"'
            '  helper-call "bpf_load_hdr_opt" $ctx $opt 16 0'
            '  helper-call "bpf_store_hdr_opt" $ctx $opt 16 0'
            '  helper-call "bpf_reserve_hdr_opt" $ctx 16 0'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "sock-ops-packet-metadata-requires-op-guard"
        category: "context-policy"
        tags: [sock-ops context packet reject]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.skb_len + $ctx.skb_tcp_flags) | count'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.packet_len on sock_ops requires proving a packet-aware ctx.op callback before use"
    }
    {
        name: "sock-ops-packet-metadata-op-guard"
        category: "context-surface"
        tags: [sock-ops context packet accept]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  if ($ctx.op == 13) {'
            '    ($ctx.packet_len + $ctx.skb_len + $ctx.skb_tcp_flags) | count'
            '  }'
            '  if ($ctx.op == 16) {'
            '    ($ctx.packet_len + $ctx.skb_len + ($ctx.skb_hwtstamp mod 1024)) | count'
            '  }'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "sock-ops-packet-data-requires-op-guard"
        category: "context-policy"
        tags: [sock-ops context packet reject]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  ($ctx.data | get 0) | count'
            '  1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.data on sock_ops requires proving a packet-aware ctx.op callback before use"
    }
    {
        name: "sock-ops-packet-data-op-guard"
        category: "context-surface"
        tags: [sock-ops context packet accept]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  if ($ctx.op == 13) {'
            '    if ($ctx.data_end != 0) {'
            '      ($ctx.data | get 0) | count'
            '    }'
            '  }'
            '  1'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "sk-reuseport-select-context"
        category: "context-surface"
        tags: [sk-reuseport context]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  ($ctx.hash + $ctx.socket_cookie + $ctx.sk.family) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "sk-reuseport-select-packet-context"
        category: "context-surface"
        tags: [sk-reuseport context packet]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  (($ctx.data | get 0) + $ctx.packet_len + $ctx.sk.bound_dev_if) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "sk-reuseport-migrate-context"
        category: "context-surface"
        tags: [sk-reuseport context]
        target: "sk_reuseport:migrate"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.protocol + $ctx.hash + $ctx.bind_inany + $ctx.socket_cookie + $ctx.sk.bound_dev_if + $ctx.migrating_sk.bound_dev_if) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "sk-lookup-context-clear-socket"
        category: "context-surface"
        tags: [sk-lookup context writable]
        requires: [netns-self]
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  ($ctx.family + $ctx.ip_protocol + $ctx.local_port + $ctx.remote_port + $ctx.cookie + $ctx.ingress_ifindex + $ctx.sk.family) | count'
            '  $ctx.sk = 0'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "sk-msg-basic-context"
        category: "context-surface"
        tags: [sk-msg context]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  ($ctx.size + $ctx.family + $ctx.local_port + $ctx.remote_port + $ctx.netns_cookie + $ctx.sk.family) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "sk-msg-data-context-write"
        category: "context-surface"
        tags: [sk-msg context packet writable]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  ($ctx.data | get 0) | count'
            '  $ctx.data.0 = 42'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "sk-msg-rejects-fullsock-projection"
        category: "context-policy"
        tags: [sk-msg reject socket helper-backed]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  $ctx.sk.full.family | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_sk_fullsock' is only valid"
    }
    {
        name: "sk-skb-basic-context"
        category: "context-surface"
        tags: [sk-skb context]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.eth_protocol + $ctx.local_port + $ctx.socket_uid + $ctx.sk.family) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "sk-skb-data-context-write"
        category: "context-surface"
        tags: [sk-skb context packet writable]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  (($ctx.data | get 0) + $ctx.protocol + $ctx.priority) | count'
            '  $ctx.data.0 = 42'
            '  $ctx.priority = 3'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "sk-skb-parser-basic-context"
        category: "context-surface"
        tags: [sk-skb-parser context]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  ($ctx.eth_protocol + $ctx.local_port + $ctx.sk.family) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "sk-skb-parser-data-context-write"
        category: "context-surface"
        tags: [sk-skb-parser context packet writable]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  (($ctx.data | get 0) + $ctx.protocol + $ctx.priority) | count'
            '  $ctx.data.0 = 42'
            '  $ctx.priority = 3'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-xmit-helper-context"
        category: "context-surface"
        tags: [lwt context helper-backed]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.protocol + $ctx.hash + $ctx.hash_recalc + $ctx.csum_level + $ctx.cgroup_classid + $ctx.route_realm) | count'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-xmit-packet-context-write"
        category: "context-surface"
        tags: [lwt context packet writable]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  (($ctx.data | get 0) + $ctx.mark) | count'
            '  $ctx.data.0 = 42'
            '  $ctx.cb.1 = 7'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-in-helper-context"
        category: "context-surface"
        tags: [lwt context helper-backed]
        target: "lwt_in:demo-route"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.ingress_ifindex + $ctx.mark) | count'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-in-context-write"
        category: "context-surface"
        tags: [lwt context writable]
        target: "lwt_in:demo-route"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.mark = 7'
            '  "reroute"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-out-helper-context"
        category: "context-surface"
        tags: [lwt context helper-backed]
        target: "lwt_out:demo-route"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.queue_mapping + $ctx.protocol + $ctx.priority) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-out-context-write"
        category: "context-surface"
        tags: [lwt context writable]
        target: "lwt_out:demo-route"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.priority = 3'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-seg6local-helper-context"
        category: "context-surface"
        tags: [lwt context helper-backed seg6local]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.hash + $ctx.route_realm + $ctx.gso_size) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-seg6local-context-write"
        category: "context-surface"
        tags: [lwt context writable seg6local]
        target: "lwt_seg6local:demo-route"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  $ctx.cb.4 = 7'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lwt-push-encap-rejects-non-lwt-program"
        category: "helper-policy"
        tags: [lwt helper-call reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_lwt_push_encap" $ctx 0 0 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_lwt_push_encap' is only valid in lwt_in and lwt_xmit programs"
    }
    {
        name: "lirc-mode2-context"
        category: "context-surface"
        tags: [lirc context]
        requires: [lirc-device]
        target: "lirc_mode2:/dev/lirc0"
        program: [
            '{|ctx|'
            '  ($ctx.sample + $ctx.value + $ctx.mode) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "raw-tracepoint-writable-args"
        category: "context-surface"
        tags: [raw-tracepoint-w context]
        target: "raw_tracepoint.w:sys_enter"
        program: [
            '{|ctx|'
            '  ($ctx.arg0 + $ctx.arg1) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "raw-tracepoint-writable-current-context"
        category: "context-surface"
        tags: [raw-tracepoint-w context current]
        target: "raw_tracepoint.w:sys_enter"
        program: [
            '{|ctx|'
            '  ($ctx.pid + $ctx.ktime + $ctx.cpu) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "iter-task-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:task"
        program: [
            '{|ctx|'
            '  if $ctx.meta { 1 | count }'
            '  if $ctx.task { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "iter-task-file-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:task_file"
        program: [
            '{|ctx|'
            '  $ctx.fd | count'
            '  if $ctx.task { 1 | count }'
            '  if $ctx.file { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "iter-task-vma-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:task_vma"
        program: [
            '{|ctx|'
            '  if $ctx.task { 1 | count }'
            '  if $ctx.vma { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "iter-cgroup-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:cgroup"
        program: [
            '{|ctx|'
            '  if $ctx.cgroup { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "iter-bpf-map-context"
        category: "context-surface"
        tags: [iter context map]
        target: "iter:bpf_map"
        program: [
            '{|ctx|'
            '  if $ctx.map { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "iter-bpf-map-elem-context"
        category: "context-surface"
        tags: [iter context map]
        target: "iter:bpf_map_elem"
        program: [
            '{|ctx|'
            '  if $ctx.map { 1 | count }'
            '  if $ctx.key { 1 | count }'
            '  if $ctx.value { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "iter-bpf-sk-storage-map-context"
        category: "context-surface"
        tags: [iter context map socket]
        target: "iter:bpf_sk_storage_map"
        program: [
            '{|ctx|'
            '  if $ctx.map { 1 | count }'
            '  if $ctx.value { 1 | count }'
            '  if $ctx.sk { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "iter-sockmap-context"
        category: "context-surface"
        tags: [iter context map socket]
        target: "iter:sockmap"
        program: [
            '{|ctx|'
            '  if $ctx.map { 1 | count }'
            '  if $ctx.key { 1 | count }'
            '  if $ctx.sk { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "iter-bpf-prog-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:bpf_prog"
        program: [
            '{|ctx|'
            '  if $ctx.prog { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "iter-bpf-link-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:bpf_link"
        program: [
            '{|ctx|'
            '  if $ctx.link { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "iter-tcp-context"
        category: "context-surface"
        tags: [iter context socket]
        target: "iter:tcp"
        program: [
            '{|ctx|'
            '  $ctx.uid | count'
            '  if $ctx.sk_common { 1 | count }'
            '  if $ctx.sock_common { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "iter-udp-context"
        category: "context-surface"
        tags: [iter context socket]
        target: "iter:udp"
        program: [
            '{|ctx|'
            '  ($ctx.uid + $ctx.bucket) | count'
            '  if $ctx.udp_sk { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "iter-unix-context"
        category: "context-surface"
        tags: [iter context socket]
        target: "iter:unix"
        program: [
            '{|ctx|'
            '  $ctx.uid | count'
            '  if $ctx.unix_sk { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "iter-dmabuf-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:dmabuf"
        program: [
            '{|ctx|'
            '  if $ctx.dmabuf { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "iter-ipv6-route-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:ipv6_route"
        program: [
            '{|ctx|'
            '  if $ctx.rt { 1 | count }'
            '  if $ctx.ipv6_route { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "iter-kmem-cache-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:kmem_cache"
        program: [
            '{|ctx|'
            '  if $ctx.kmem_cache { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "iter-ksym-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:ksym"
        program: [
            '{|ctx|'
            '  if $ctx.ksym { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "iter-netlink-context"
        category: "context-surface"
        tags: [iter context socket]
        target: "iter:netlink"
        program: [
            '{|ctx|'
            '  if $ctx.netlink_sk { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "map-get-rejects-queue"
        category: "maps"
        tags: [queue reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | map-get q --kind queue'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-get is not supported for map kind queue"
    }
    {
        name: "map-define-kptr-slot"
        category: "maps"
        tags: [maps map-define kptr accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define task_slots --kind array --value-type "record{task:kptr:task_struct,cookie:u64}" --max-entries 1'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "map-define-kptr-slot-rejects-queue"
        category: "maps"
        tags: [maps map-define kptr reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define task_slots --kind queue --value-type "record{task:kptr:task_struct,cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kptr fields, which are currently supported for hash, array, and lru-hash maps"
    }
    {
        name: "map-define-bpf-wq-slot"
        category: "maps"
        tags: [maps map-define bpf_wq accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work:bpf_wq,cookie:u64}" --max-entries 1'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "map-define-bpf-wq-slot-rejects-queue"
        category: "maps"
        tags: [maps map-define bpf_wq reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind queue --value-type "record{work:bpf_wq,cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "contains bpf_wq, which is only supported for hash, array, and lru-hash maps"
    }
    {
        name: "map-define-bpf-wq-rejects-array-field"
        category: "maps"
        tags: [maps map-define bpf_wq reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define work_items --kind array --value-type "record{work_items:array{bpf_wq:2},cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arrays of verifier-managed bpf_wq"
    }
    {
        name: "map-define-bpf-refcount-slot"
        category: "maps"
        tags: [maps map-define bpf_refcount accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define refcounted_items --kind array --value-type "record{refs:bpf_refcount,cookie:u64}" --max-entries 1'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "map-define-bpf-refcount-rejects-queue"
        category: "maps"
        tags: [maps map-define bpf_refcount reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define refcounted_items --kind queue --value-type "record{refs:bpf_refcount,cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "contains bpf_refcount, which is currently supported for hash, array, and lru-hash maps"
    }
    {
        name: "map-define-bpf-refcount-rejects-array-field"
        category: "maps"
        tags: [maps map-define bpf_refcount reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define refcounted_items --kind array --value-type "record{refs:array{bpf_refcount:2},cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arrays of verifier-managed bpf_refcount"
    }
    {
        name: "map-define-graph-root-schema"
        category: "maps"
        tags: [maps map-define graph accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node,cookie:u64}"'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "map-define-rejects-bare-graph-root"
        category: "maps"
        tags: [maps map-define graph reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head,cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map value graph type spec"
    }
    {
        name: "map-define-rejects-bare-rbtree-node"
        category: "maps"
        tags: [maps map-define graph reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{node:bpf_rb_node,cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "matching bpf_list_node/bpf_rb_node object fields"
    }
    {
        name: "timer-map-define-lowers-init-start-cancel"
        category: "helper-state"
        tags: [timer map-define accept]
        target: "raw_tracepoint:sys_enter"
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
        local: "accept"
        kernel: "skip"
    }
    {
        name: "timer-init-rejects-invalid-clock-flags"
        category: "helper-state"
        tags: [timer helper-call flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers --kind array)'
            '  if $entry {'
            '    helper-call "bpf_timer_init" $entry.timer timers 99 --kind array'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_timer_init' requires arg2 flags to be CLOCK_REALTIME, CLOCK_MONOTONIC, or CLOCK_BOOTTIME"
    }
    {
        name: "timer-start-rejects-invalid-flags"
        category: "helper-state"
        tags: [timer helper-call flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define timers --kind array --value-type "record{timer:bpf_timer,cookie:u64}"'
            '  let entry = (0 | map-get timers --kind array)'
            '  if $entry {'
            '    helper-call "bpf_timer_start" $entry.timer 1000 4'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_timer_start' requires arg2 flags to contain only BPF_F_TIMER_* bits"
    }
    {
        name: "source-kfunc-task-ref-release"
        category: "helper-state"
        tags: [kfunc ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  if $task {'
            '    kfunc-call "bpf_task_release" $task'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-task-ref-rejects-leak"
        category: "helper-state"
        tags: [kfunc ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-obj-new-drop"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '  if $obj {'
            '    kfunc-call "bpf_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-obj-new-rejects-leak"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-obj-new-rejects-dynamic-type-id"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let type_id = ($ctx.pid + 1)'
            '  let obj = (kfunc-call "bpf_obj_new_impl" $type_id 0)'
            '  if $obj {'
            '    kfunc-call "bpf_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg0 must be known constant"
    }
    {
        name: "source-kfunc-obj-new-rejects-zero-type-id"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_obj_new_impl" 0 0)'
            '  if $obj {'
            '    kfunc-call "bpf_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg0 must be > 0"
    }
    {
        name: "source-kfunc-obj-new-rejects-dynamic-meta"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let meta = ($ctx.pid + 1)'
            '  let obj = (kfunc-call "bpf_obj_new_impl" 1 $meta)'
            '  if $obj {'
            '    kfunc-call "bpf_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg1 must be known zero"
    }
    {
        name: "source-kfunc-obj-drop-rejects-nonzero-meta"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '  if $obj {'
            '    kfunc-call "bpf_obj_drop_impl" $obj 1'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg1 must be known zero"
    }
    {
        name: "source-kfunc-refcount-acquire-rejects-map-field"
        category: "helper-state"
        tags: [kfunc object bpf_refcount ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define ref_items --kind hash --value-type "record{refs:bpf_refcount,cookie:u64}"'
            '  let entry = (0 | map-get ref_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_refcount_acquire_impl" $entry.refs 0)'
            '    if $obj {'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects kernel pointer, got Map"
    }
    {
        name: "source-kfunc-percpu-obj-new-drop"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_percpu_obj_new_impl" 1 0)'
            '  if $obj {'
            '    kfunc-call "bpf_percpu_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-percpu-obj-new-rejects-leak"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_percpu_obj_new_impl" 1 0)'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-percpu-obj-new-rejects-dynamic-type-id"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let type_id = ($ctx.pid + 1)'
            '  let obj = (kfunc-call "bpf_percpu_obj_new_impl" $type_id 0)'
            '  if $obj {'
            '    kfunc-call "bpf_percpu_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg0 must be known constant"
    }
    {
        name: "source-kfunc-percpu-obj-new-rejects-zero-type-id"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_percpu_obj_new_impl" 0 0)'
            '  if $obj {'
            '    kfunc-call "bpf_percpu_obj_drop_impl" $obj 0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg0 must be > 0"
    }
    {
        name: "source-kfunc-percpu-obj-drop-rejects-dynamic-meta"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let obj = (kfunc-call "bpf_percpu_obj_new_impl" 1 0)'
            '  if $obj {'
            '    let meta = ($ctx.pid + 1)'
            '    kfunc-call "bpf_percpu_obj_drop_impl" $obj $meta'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg1 must be known zero"
    }
    {
        name: "source-kfunc-percpu-obj-drop-rejects-task-ref"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  if $task {'
            '    kfunc-call "bpf_percpu_obj_drop_impl" $task 0'
            '    kfunc-call "bpf_task_release" $task'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects object reference"
    }
    {
        name: "source-kfunc-obj-drop-rejects-task-ref"
        category: "helper-state"
        tags: [kfunc object ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  if $task {'
            '    kfunc-call "bpf_obj_drop_impl" $task 0'
            '    kfunc-call "bpf_task_release" $task'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects object reference"
    }
    {
        name: "source-kfunc-list-push-front-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '    if $obj {'
            '      kfunc-call "bpf_list_push_front_impl" $entry.root $obj 0 0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-list-push-front-rejects-dynamic-meta"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '    if $obj {'
            '      let meta = ($ctx.pid + 1)'
            '      kfunc-call "bpf_list_push_front_impl" $entry.root $obj $meta 0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg2 must be known zero"
    }
    {
        name: "source-kfunc-list-push-back-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '    if $obj {'
            '      kfunc-call "bpf_list_push_back_impl" $entry.root $obj 0 0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-list-pop-front-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_list_pop_front" $entry.root)'
            '    if $obj {'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-list-pop-back-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_list_pop_back" $entry.root)'
            '    if $obj {'
            '      kfunc-call "bpf_obj_drop_impl" $obj 0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-list-front-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_list_front" $entry.root)'
            '    if $obj {'
            '      0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-list-back-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_list_back" $entry.root)'
            '    if $obj {'
            '      0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-rbtree-first-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_rbtree_first" $entry.root)'
            '    if $obj {'
            '      0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-rbtree-remove-map-root"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    let node = (kfunc-call "bpf_rbtree_first" $entry.root)'
            '    if $node {'
            '      let obj = (kfunc-call "bpf_rbtree_remove" $entry.root $node)'
            '      if $obj {'
            '        kfunc-call "bpf_obj_drop_impl" $obj 0'
            '      }'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-rbtree-root-from-node"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    let node = (kfunc-call "bpf_rbtree_first" $entry.root)'
            '    if $node {'
            '      let root = (kfunc-call "bpf_rbtree_root" $node)'
            '      if $root {'
            '        0'
            '      }'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-rbtree-left-from-node"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    let node = (kfunc-call "bpf_rbtree_first" $entry.root)'
            '    if $node {'
            '      let left = (kfunc-call "bpf_rbtree_left" $node)'
            '      if $left {'
            '        0'
            '      }'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-rbtree-right-from-node"
        category: "helper-state"
        tags: [kfunc object graph source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    let node = (kfunc-call "bpf_rbtree_first" $entry.root)'
            '    if $node {'
            '      let right = (kfunc-call "bpf_rbtree_right" $node)'
            '      if $right {'
            '        0'
            '      }'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-rbtree-root-rejects-map-root"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    let root = (kfunc-call "bpf_rbtree_root" $entry.root)'
            '    if $root {'
            '      0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects kernel pointer, got Map"
    }
    {
        name: "source-kfunc-rbtree-left-rejects-list-node"
        category: "helper-state"
        tags: [kfunc object graph source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node,cookie:u64}"'
            '  let entry = (0 | map-get graph_items --kind hash)'
            '  if $entry {'
            '    let node = (kfunc-call "bpf_list_front" $entry.root)'
            '    if $node {'
            '      let left = (kfunc-call "bpf_rbtree_left" $node)'
            '      if $left {'
            '        0'
            '      }'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "expects bpf_rb_node pointer"
    }
    {
        name: "source-kfunc-rbtree-add-map-root"
        category: "helper-state"
        tags: [kfunc object graph callback source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '    if $obj {'
            '      kfunc-call "bpf_rbtree_add_impl" $entry.root $obj {|a b| 0} 0 0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-rbtree-add-rejects-dynamic-meta"
        category: "helper-state"
        tags: [kfunc object graph callback source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '    if $obj {'
            '      let meta = ($ctx.pid + 1)'
            '      kfunc-call "bpf_rbtree_add_impl" $entry.root $obj {|a b| 0} $meta 0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arg3 must be known zero"
    }
    {
        name: "source-kfunc-rbtree-add-callback-uses-node-args"
        category: "helper-state"
        tags: [kfunc object graph callback source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '    if $obj {'
            '      kfunc-call "bpf_rbtree_add_impl" $entry.root $obj {|a b| if $a { if $b { 1 } else { 0 } } else { 0 }} 0 0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-rbtree-add-rejects-non-callback"
        category: "helper-state"
        tags: [kfunc object graph callback source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define rb_items --kind hash --value-type "record{root:bpf_rb_root:rb_item:rb,cookie:u64}"'
            '  let entry = (0 | map-get rb_items --kind hash)'
            '  if $entry {'
            '    let obj = (kfunc-call "bpf_obj_new_impl" 1 0)'
            '    if $obj {'
            '      kfunc-call "bpf_rbtree_add_impl" $entry.root $obj 0 0 0'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a closure or block literal callback"
    }
    {
        name: "source-kfunc-task-acquire-release"
        category: "helper-state"
        tags: [kfunc ref-lifetime source accept]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_acquire" $ctx.task)'
            '  if $task {'
            '    $task | kfunc-call "bpf_task_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-task-acquire-rejects-leak"
        category: "helper-state"
        tags: [kfunc ref-lifetime source reject]
        requires: [kernel-btf]
        target: "tp_btf:sys_enter"
        program: [
            '{|ctx|'
            '  let task = (kfunc-call "bpf_task_acquire" $ctx.task)'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-file-ref-release"
        category: "helper-state"
        tags: [kfunc file ref-lifetime source accept]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let file = (kfunc-call "bpf_get_task_exe_file" $ctx.current_task)'
            '  if $file {'
            '    $file | kfunc-call "bpf_put_file"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-file-ref-rejects-leak"
        category: "helper-state"
        tags: [kfunc file ref-lifetime source reject]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  let file = (kfunc-call "bpf_get_task_exe_file" $ctx.current_task)'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-cgroup-acquire-release"
        category: "helper-state"
        tags: [kfunc cgroup ref-lifetime source accept]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  let cgrp = (kfunc-call "bpf_cgroup_acquire" $ctx.cgroup)'
            '  if $cgrp {'
            '    $cgrp | kfunc-call "bpf_cgroup_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-cgroup-acquire-rejects-leak"
        category: "helper-state"
        tags: [kfunc cgroup ref-lifetime source reject]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  let cgrp = (kfunc-call "bpf_cgroup_acquire" $ctx.cgroup)'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-cgroup-from-id-release"
        category: "helper-state"
        tags: [kfunc cgroup ref-lifetime source accept]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  let cgrp = (kfunc-call "bpf_cgroup_from_id" 1)'
            '  if $cgrp {'
            '    $cgrp | kfunc-call "bpf_cgroup_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-cgroup-ancestor-release"
        category: "helper-state"
        tags: [kfunc cgroup ref-lifetime source accept]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  let cgrp = (kfunc-call "bpf_cgroup_from_id" 1)'
            '  if $cgrp {'
            '    let parent = (kfunc-call "bpf_cgroup_ancestor" $cgrp 0)'
            '    if $parent {'
            '      $parent | kfunc-call "bpf_cgroup_release"'
            '    }'
            '    $cgrp | kfunc-call "bpf_cgroup_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-cpumask-ref-release"
        category: "helper-state"
        tags: [kfunc cpumask ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let mask = (kfunc-call "bpf_cpumask_create")'
            '  if $mask {'
            '    $mask | kfunc-call "bpf_cpumask_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-cpumask-ref-rejects-leak"
        category: "helper-state"
        tags: [kfunc cpumask ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let mask = (kfunc-call "bpf_cpumask_create")'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-cpumask-acquire-release"
        category: "helper-state"
        tags: [kfunc cpumask ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let mask = (kfunc-call "bpf_cpumask_create")'
            '  if $mask {'
            '    let owned = (kfunc-call "bpf_cpumask_acquire" $mask)'
            '    if $owned {'
            '      $owned | kfunc-call "bpf_cpumask_release"'
            '    }'
            '    $mask | kfunc-call "bpf_cpumask_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-cpumask-acquire-rejects-owned-leak"
        category: "helper-state"
        tags: [kfunc cpumask ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let mask = (kfunc-call "bpf_cpumask_create")'
            '  if $mask {'
            '    let owned = (kfunc-call "bpf_cpumask_acquire" $mask)'
            '    $mask | kfunc-call "bpf_cpumask_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kfunc-cpumask-set-first-release"
        category: "helper-state"
        tags: [kfunc cpumask source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let mask = (kfunc-call "bpf_cpumask_create")'
            '  if $mask {'
            '    kfunc-call "bpf_cpumask_set_cpu" 0 $mask'
            '    let first = (kfunc-call "bpf_cpumask_first" $mask)'
            '    $first | count'
            '    $mask | kfunc-call "bpf_cpumask_release"'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kptr-xchg-task-ref-transfer"
        category: "helper-state"
        tags: [kfunc helper-call kptr ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define task_slots --kind array --key-type u32 --value-type "record{task:kptr:task_struct,cookie:u64}" --max-entries 1'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  if $task {'
            '    let entry = (0 | map-get task_slots --kind array)'
            '    if $entry {'
            '      let old = (helper-call "bpf_kptr_xchg" $entry.task $task)'
            '      if $old {'
            '        $old | kfunc-call "bpf_task_release"'
            '      }'
            '    } else {'
            '      $task | kfunc-call "bpf_task_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kptr-xchg-rejects-old-ref-leak"
        category: "helper-state"
        tags: [kfunc helper-call kptr ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define task_slots --kind array --key-type u32 --value-type "record{task:kptr:task_struct,cookie:u64}" --max-entries 1'
            '  let task = (kfunc-call "bpf_task_from_pid" 1)'
            '  if $task {'
            '    let entry = (0 | map-get task_slots --kind array)'
            '    if $entry {'
            '      let old = (helper-call "bpf_kptr_xchg" $entry.task $task)'
            '      0'
            '    } else {'
            '      $task | kfunc-call "bpf_task_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kptr-xchg-cpumask-ref-transfer"
        category: "helper-state"
        tags: [kfunc helper-call kptr cpumask ref-lifetime source accept]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define mask_slots --kind array --key-type u32 --value-type "record{mask:kptr:bpf_cpumask,cookie:u64}" --max-entries 1'
            '  let mask = (kfunc-call "bpf_cpumask_create")'
            '  if $mask {'
            '    let entry = (0 | map-get mask_slots --kind array)'
            '    if $entry {'
            '      let old = (helper-call "bpf_kptr_xchg" $entry.mask $mask)'
            '      if $old {'
            '        $old | kfunc-call "bpf_cpumask_release"'
            '      }'
            '    } else {'
            '      $mask | kfunc-call "bpf_cpumask_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kptr-xchg-cpumask-rejects-old-ref-leak"
        category: "helper-state"
        tags: [kfunc helper-call kptr cpumask ref-lifetime source reject]
        requires: [kernel-btf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define mask_slots --kind array --key-type u32 --value-type "record{mask:kptr:bpf_cpumask,cookie:u64}" --max-entries 1'
            '  let mask = (kfunc-call "bpf_cpumask_create")'
            '  if $mask {'
            '    let entry = (0 | map-get mask_slots --kind array)'
            '    if $entry {'
            '      let old = (helper-call "bpf_kptr_xchg" $entry.mask $mask)'
            '      0'
            '    } else {'
            '      $mask | kfunc-call "bpf_cpumask_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kptr-xchg-file-ref-transfer"
        category: "helper-state"
        tags: [kfunc helper-call kptr file ref-lifetime source accept]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  map-define file_slots --kind array --key-type u32 --value-type "record{file:kptr:file,cookie:u64}" --max-entries 1'
            '  let file = (kfunc-call "bpf_get_task_exe_file" $ctx.current_task)'
            '  if $file {'
            '    let entry = (0 | map-get file_slots --kind array)'
            '    if $entry {'
            '      let old = (helper-call "bpf_kptr_xchg" $entry.file $file)'
            '      if $old {'
            '        $old | kfunc-call "bpf_put_file"'
            '      }'
            '    } else {'
            '      $file | kfunc-call "bpf_put_file"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kptr-xchg-file-rejects-old-ref-leak"
        category: "helper-state"
        tags: [kfunc helper-call kptr file ref-lifetime source reject]
        requires: [kernel-btf]
        target: "lsm:file_open"
        program: [
            '{|ctx|'
            '  map-define file_slots --kind array --key-type u32 --value-type "record{file:kptr:file,cookie:u64}" --max-entries 1'
            '  let file = (kfunc-call "bpf_get_task_exe_file" $ctx.current_task)'
            '  if $file {'
            '    let entry = (0 | map-get file_slots --kind array)'
            '    if $entry {'
            '      let old = (helper-call "bpf_kptr_xchg" $entry.file $file)'
            '      0'
            '    } else {'
            '      $file | kfunc-call "bpf_put_file"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kptr-xchg-cgroup-ref-transfer"
        category: "helper-state"
        tags: [kfunc helper-call kptr cgroup ref-lifetime source accept]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  map-define cgroup_slots --kind array --key-type u32 --value-type "record{cgrp:kptr:cgroup,cookie:u64}" --max-entries 1'
            '  let cgrp = (kfunc-call "bpf_cgroup_from_id" 1)'
            '  if $cgrp {'
            '    let entry = (0 | map-get cgroup_slots --kind array)'
            '    if $entry {'
            '      let old = (helper-call "bpf_kptr_xchg" $entry.cgrp $cgrp)'
            '      if $old {'
            '        $old | kfunc-call "bpf_cgroup_release"'
            '      }'
            '    } else {'
            '      $cgrp | kfunc-call "bpf_cgroup_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kptr-xchg-cgroup-clear-release"
        category: "helper-state"
        tags: [kfunc helper-call kptr cgroup ref-lifetime source accept]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  map-define cgroup_slots --kind array --key-type u32 --value-type "record{cgrp:kptr:cgroup,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get cgroup_slots --kind array)'
            '  if $entry {'
            '    let old = (helper-call "bpf_kptr_xchg" $entry.cgrp 0)'
            '    if $old {'
            '      $old | kfunc-call "bpf_cgroup_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kptr-xchg-cgroup-clear-rejects-old-ref-leak"
        category: "helper-state"
        tags: [kfunc helper-call kptr cgroup ref-lifetime source reject]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  map-define cgroup_slots --kind array --key-type u32 --value-type "record{cgrp:kptr:cgroup,cookie:u64}" --max-entries 1'
            '  let entry = (0 | map-get cgroup_slots --kind array)'
            '  if $entry {'
            '    let old = (helper-call "bpf_kptr_xchg" $entry.cgrp 0)'
            '    0'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased kfunc reference at function exit"
    }
    {
        name: "source-kptr-xchg-rejects-pointee-mismatch"
        category: "helper-state"
        tags: [kfunc helper-call kptr cgroup ref-lifetime source reject]
        requires: [kernel-btf]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  map-define task_slots --kind array --key-type u32 --value-type "record{task:kptr:task_struct,cookie:u64}" --max-entries 1'
            '  let cgrp = (kfunc-call "bpf_cgroup_from_id" 1)'
            '  if $cgrp {'
            '    let entry = (0 | map-get task_slots --kind array)'
            '    if $entry {'
            '      helper-call "bpf_kptr_xchg" $entry.task $cgrp'
            '    } else {'
            '      $cgrp | kfunc-call "bpf_cgroup_release"'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot store cgroup pointer in kptr:task_struct slot"
    }
    {
        name: "source-kfunc-res-spin-rejects-non-kernel-pointer"
        category: "helper-state"
        tags: [kfunc res-spin-lock source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_res_spin_lock" 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kfunc 'bpf_res_spin_lock' arg0 expects pointer"
    }
    {
        name: "source-kfunc-rcu-read-lock-unlock"
        category: "helper-state"
        tags: [kfunc rcu source accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_rcu_read_lock"'
            '  kfunc-call "bpf_rcu_read_unlock"'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-rcu-read-unlock-rejects-unmatched"
        category: "helper-state"
        tags: [kfunc rcu source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_rcu_read_unlock"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a matching bpf_rcu_read_lock"
    }
    {
        name: "source-kfunc-rcu-read-lock-rejects-leak"
        category: "helper-state"
        tags: [kfunc rcu source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_rcu_read_lock"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased RCU read lock"
    }
    {
        name: "source-kfunc-rcu-read-unlock-rejects-mixed-join"
        category: "helper-state"
        tags: [kfunc rcu source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    kfunc-call "bpf_rcu_read_lock"'
            '  }'
            '  kfunc-call "bpf_rcu_read_unlock"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a matching bpf_rcu_read_lock"
    }
    {
        name: "source-kfunc-preempt-disable-enable"
        category: "helper-state"
        tags: [kfunc preempt source accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_preempt_disable"'
            '  kfunc-call "bpf_preempt_enable"'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-preempt-enable-rejects-unmatched"
        category: "helper-state"
        tags: [kfunc preempt source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_preempt_enable"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a matching bpf_preempt_disable"
    }
    {
        name: "source-kfunc-preempt-disable-rejects-leak"
        category: "helper-state"
        tags: [kfunc preempt source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_preempt_disable"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased preempt disable"
    }
    {
        name: "source-kfunc-preempt-enable-rejects-mixed-join"
        category: "helper-state"
        tags: [kfunc preempt source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    kfunc-call "bpf_preempt_disable"'
            '  }'
            '  kfunc-call "bpf_preempt_enable"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a matching bpf_preempt_disable"
    }
    {
        name: "source-kfunc-local-irq-save-restore"
        category: "helper-state"
        tags: [kfunc irq source accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let flags = "00000000"'
            '  kfunc-call "bpf_local_irq_save" $flags'
            '  kfunc-call "bpf_local_irq_restore" $flags'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-local-irq-restore-rejects-unmatched"
        category: "helper-state"
        tags: [kfunc irq source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let flags = "00000000"'
            '  kfunc-call "bpf_local_irq_restore" $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a matching bpf_local_irq_save"
    }
    {
        name: "source-kfunc-local-irq-save-rejects-leak"
        category: "helper-state"
        tags: [kfunc irq source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let flags = "00000000"'
            '  kfunc-call "bpf_local_irq_save" $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased local irq disable"
    }
    {
        name: "source-kfunc-local-irq-restore-rejects-slot-mismatch"
        category: "helper-state"
        tags: [kfunc irq source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let saved_flags = "00000000"'
            '  let other_flags = "11111111"'
            '  kfunc-call "bpf_local_irq_save" $saved_flags'
            '  kfunc-call "bpf_local_irq_restore" $other_flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a matching bpf_local_irq_save"
    }
    {
        name: "source-kfunc-local-irq-restore-rejects-mixed-join"
        category: "helper-state"
        tags: [kfunc irq source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let flags = "00000000"'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    kfunc-call "bpf_local_irq_save" $flags'
            '  }'
            '  kfunc-call "bpf_local_irq_restore" $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a matching bpf_local_irq_save"
    }
    {
        name: "source-kfunc-res-spin-lock-unlock"
        category: "helper-state"
        tags: [kfunc res-spin-lock source accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_res_spin_lock" $ctx.current_task'
            '  kfunc-call "bpf_res_spin_unlock" $ctx.current_task'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-res-spin-unlock-rejects-unmatched"
        category: "helper-state"
        tags: [kfunc res-spin-lock source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_res_spin_unlock" $ctx.current_task'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a matching bpf_res_spin_lock"
    }
    {
        name: "source-kfunc-res-spin-lock-rejects-leak"
        category: "helper-state"
        tags: [kfunc res-spin-lock source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  kfunc-call "bpf_res_spin_lock" $ctx.current_task'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased res spin lock"
    }
    {
        name: "source-kfunc-res-spin-unlock-rejects-mixed-join"
        category: "helper-state"
        tags: [kfunc res-spin-lock source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    kfunc-call "bpf_res_spin_lock" $ctx.current_task'
            '  }'
            '  kfunc-call "bpf_res_spin_unlock" $ctx.current_task'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a matching bpf_res_spin_lock"
    }
    {
        name: "source-kfunc-res-spin-irqsave-unlock-irqrestore"
        category: "helper-state"
        tags: [kfunc res-spin-lock irq source accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let flags = "00000000"'
            '  kfunc-call "bpf_res_spin_lock_irqsave" $ctx.current_task $flags'
            '  kfunc-call "bpf_res_spin_unlock_irqrestore" $ctx.current_task $flags'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-res-spin-irqrestore-rejects-unmatched"
        category: "helper-state"
        tags: [kfunc res-spin-lock irq source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let flags = "00000000"'
            '  kfunc-call "bpf_res_spin_unlock_irqrestore" $ctx.current_task $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a matching bpf_res_spin_lock_irqsave"
    }
    {
        name: "source-kfunc-res-spin-irqsave-rejects-leak"
        category: "helper-state"
        tags: [kfunc res-spin-lock irq source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let flags = "00000000"'
            '  kfunc-call "bpf_res_spin_lock_irqsave" $ctx.current_task $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased res spin lock irqsave"
    }
    {
        name: "source-kfunc-res-spin-irqrestore-rejects-slot-mismatch"
        category: "helper-state"
        tags: [kfunc res-spin-lock irq source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let saved_flags = "00000000"'
            '  let other_flags = "11111111"'
            '  kfunc-call "bpf_res_spin_lock_irqsave" $ctx.current_task $saved_flags'
            '  kfunc-call "bpf_res_spin_unlock_irqrestore" $ctx.current_task $other_flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a matching bpf_res_spin_lock_irqsave"
    }
    {
        name: "source-kfunc-res-spin-irqrestore-rejects-mixed-join"
        category: "helper-state"
        tags: [kfunc res-spin-lock irq source reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let flags = "00000000"'
            '  let selector = (helper-call "bpf_get_prandom_u32")'
            '  if $selector == 0 {'
            '    kfunc-call "bpf_res_spin_lock_irqsave" $ctx.current_task $flags'
            '  }'
            '  kfunc-call "bpf_res_spin_unlock_irqrestore" $ctx.current_task $flags'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a matching bpf_res_spin_lock_irqsave"
    }
    {
        name: "source-kfunc-sched-ext-node-min-kernel"
        category: "kfunc"
        tags: [kfunc sched-ext source metadata]
        target: "struct_ops:sched_ext_ops"
        program: [
            '{'
            '    name: "nu.demo_1"'
            '    select_cpu: {|ctx|'
            '        let prev = $ctx.arg.prev_cpu'
            '        kfunc-call "scx_bpf_cpu_node" $prev'
            '    }'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "source-kfunc-sched-ext-compat-window"
        category: "kfunc"
        tags: [kfunc sched-ext source metadata compat-window]
        target: "struct_ops:sched_ext_ops"
        program: [
            '{'
            '    name: "nu.demo_1"'
            '    cpu_release: {|ctx|'
            '        let ignored = (kfunc-call "scx_bpf_reenqueue_local")'
            '        0'
            '    }'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "struct-ops-callback-target-rejects-attach"
        category: "program-model"
        tags: [struct-ops callback attach reject]
        target: "struct_ops:sched_ext_ops.select_cpu"
        program: [
            '{'
            '    name: "nu.demo_1"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "struct_ops attach expects an object value type"
    }
    {
        name: "struct-ops-tcp-congestion-target-metadata"
        category: "program-model"
        tags: [struct-ops tcp-congestion metadata]
        target: "struct_ops:tcp_congestion_ops"
        program: [
            '{'
            '    name: "nu.demo_1"'
            '    ssthresh: {|ctx| 2 }'
            '    cong_avoid: {|ctx| 0 }'
            '    undo_cwnd: {|ctx| 2 }'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "struct-ops-sleepable-callback-target-metadata"
        category: "program-model"
        tags: [struct-ops callback sleepable metadata attach reject]
        target: "struct_ops:sched_ext_ops.init"
        program: [
            '{'
            '    name: "nu.demo_1"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "struct_ops attach expects an object value type"
    }
    {
        name: "struct-ops-object-sleepable-callback-source-metadata"
        category: "program-model"
        tags: [struct-ops callback sleepable source metadata]
        target: "struct_ops:sched_ext_ops"
        program: [
            '{'
            '    name: "nu.demo_1"'
            '    init: {|ctx|'
            '        0'
            '    }'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "timer-init-rejects-non-map-timer"
        category: "helper-state"
        tags: [timer reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_timer_init" 0 timers 0 --kind array'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires arg0 to be a bpf_timer field projected from a concrete map value"
    }
    {
        name: "spin-lock-map-define-lock-unlock"
        category: "helper-state"
        tags: [spin-lock map-define accept]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define locks --kind hash --value-type "record{lock:bpf_spin_lock,counter:u64}"'
            '  let entry = (0 | map-get locks --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "spin-lock-rejects-unreleased"
        category: "helper-state"
        tags: [spin-lock map-define reject]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define locks --kind hash --value-type "record{lock:bpf_spin_lock,counter:u64}"'
            '  let entry = (0 | map-get locks --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "unreleased bpf spin lock"
    }
    {
        name: "spin-lock-rejects-double-lock"
        category: "helper-state"
        tags: [spin-lock map-define reject]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define locks --kind hash --value-type "record{lock:bpf_spin_lock,counter:u64}"'
            '  let entry = (0 | map-get locks --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot acquire a second bpf_spin_lock"
    }
    {
        name: "spin-lock-rejects-unlock-after-mixed-join"
        category: "helper-state"
        tags: [spin-lock map-define reject]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define locks --kind hash --value-type "record{lock:bpf_spin_lock,counter:u64}"'
            '  let entry = (0 | map-get locks --kind hash)'
            '  if $entry {'
            '    let selector = (helper-call "bpf_get_prandom_u32")'
            '    if $selector == 0 {'
            '      helper-call "bpf_spin_lock" $entry.lock'
            '    }'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires a matching bpf_spin_lock"
    }
    {
        name: "spin-lock-rejects-helper-while-held"
        category: "helper-state"
        tags: [spin-lock map-define reject]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  map-define locks --kind hash --value-type "record{lock:bpf_spin_lock,counter:u64}"'
            '  let entry = (0 | map-get locks --kind hash)'
            '  if $entry {'
            '    helper-call "bpf_spin_lock" $entry.lock'
            '    helper-call "bpf_get_prandom_u32"'
            '    helper-call "bpf_spin_unlock" $entry.lock'
            '  }'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot be called while bpf_spin_lock is held"
    }
    {
        name: "spin-lock-map-define-rejects-lru-hash"
        category: "helper-state"
        tags: [spin-lock map-define reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define locks --kind lru-hash --value-type "record{lock:bpf_spin_lock,counter:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bpf_spin_lock, which is only supported for hash and array maps"
    }
    {
        name: "timer-set-callback-rejects-non-map-timer"
        category: "helper-state"
        tags: [timer callback reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_timer_set_callback" 0 {|timer key val| 0}'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires arg0 to be a bpf_timer field projected from a concrete map value"
    }
    {
        name: "timer-start-rejects-non-map-timer"
        category: "helper-state"
        tags: [timer reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{||'
            '  helper-call "bpf_timer_start" 0 1000 0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires arg0 to be a bpf_timer field projected from a concrete map value"
    }
    {
        name: "timer-cancel-rejects-non-map-timer"
        category: "helper-state"
        tags: [timer reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_timer_cancel" 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires arg0 to be a bpf_timer field projected from a concrete map value"
    }
    {
        name: "ringbuf-query-rejects-invalid-flags"
        category: "helper-state"
        tags: [ringbuf flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_ringbuf_query" events 99'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_ringbuf_query' requires arg1 flags"
    }
    {
        name: "bpf-loop-rejects-invalid-flags"
        category: "helper-state"
        tags: [bpf-loop flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_loop" 4 {|i cb| $i } "ctx" 99'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_loop' requires arg3 flags to be 0"
    }
    {
        name: "user-ringbuf-drain-rejects-invalid-flags"
        category: "helper-state"
        tags: [user-ringbuf flags reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_user_ringbuf_drain" user_events {|dyn cb| 0 } "ctx" 99'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_user_ringbuf_drain' requires arg3 flags"
    }
    {
        name: "perf-event-read-helpers"
        category: "helper-state"
        tags: [perf-event helper-call]
        target: "perf_event:software:cpu-clock:period=100000"
        program: [
            '{|ctx|'
            '  let value = "012345678901234567890123"'
            '  helper-call "bpf_perf_event_read" perf_events 0'
            '  helper-call "bpf_perf_event_read_value" perf_events 0 $value 24'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "perf-event-read-rejects-invalid-flags"
        category: "helper-state"
        tags: [perf-event flags reject]
        target: "perf_event:software:cpu-clock:period=100000"
        program: [
            '{|ctx|'
            '  helper-call "bpf_perf_event_read" perf_events 4294967296'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "perf event read helpers require arg1 flags to fit BPF_F_INDEX_MASK/BPF_F_CURRENT_CPU"
    }
    {
        name: "perf-event-read-value-rejects-size"
        category: "helper-state"
        tags: [perf-event scalar-policy reject]
        target: "perf_event:software:cpu-clock:period=100000"
        program: [
            '{|ctx|'
            '  let value = "01234567"'
            '  helper-call "bpf_perf_event_read_value" perf_events 0 $value 8'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_perf_event_read_value' requires arg3 = 24"
    }
    {
        name: "syscall-helpers"
        category: "helper-state"
        tags: [syscall helper-call]
        target: "syscall:demo"
        program: [
            '{||'
            '  let attr = "01234567"'
            '  let name = "init_task\u{0}"'
            '  let out = "00000000"'
            '  helper-call "bpf_sys_bpf" 0 $attr 8'
            '  helper-call "bpf_kallsyms_lookup_name" $name 10 0 $out'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "syscall-helper-rejects-zero-attr-size"
        category: "helper-state"
        tags: [syscall scalar-policy reject]
        target: "syscall:demo"
        program: [
            '{||'
            '  let attr = "01234567"'
            '  helper-call "bpf_sys_bpf" 0 $attr 0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 166 arg2 must be > 0"
    }
    {
        name: "syscall-helper-rejects-kallsyms-flags"
        category: "helper-state"
        tags: [syscall flags reject]
        target: "syscall:demo"
        program: [
            '{||'
            '  let name = "init_task\u{0}"'
            '  let out = "00000000"'
            '  helper-call "bpf_kallsyms_lookup_name" $name 10 1 $out'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_kallsyms_lookup_name' requires arg2 = 0"
    }
    {
        name: "lsm-bprm-opts-set"
        category: "helper-state"
        tags: [lsm helper-call]
        requires: [kernel-btf]
        target: "lsm:bprm_check_security"
        program: [
            '{|ctx|'
            '  helper-call "bpf_bprm_opts_set" $ctx.arg.bprm 1'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "lsm-bprm-opts-set-rejects-flags"
        category: "helper-state"
        tags: [lsm flags reject]
        requires: [kernel-btf]
        target: "lsm:bprm_check_security"
        program: [
            '{|ctx|'
            '  helper-call "bpf_bprm_opts_set" $ctx.arg.bprm 2'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_bprm_opts_set' requires arg1 flags to contain only BPF_F_BPRM_* bits"
    }
    {
        name: "kprobe-override-return"
        category: "helper-state"
        tags: [kprobe helper-call]
        target: "kprobe:sys_clone"
        program: [
            '{|ctx|'
            '  helper-call "bpf_override_return" $ctx 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "kretprobe-rejects-override-return"
        category: "helper-state"
        tags: [kretprobe helper-call reject]
        target: "kretprobe:sys_clone"
        program: [
            '{|ctx|'
            '  helper-call "bpf_override_return" $ctx 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_override_return' is only valid in kprobe, kprobe.multi, and ksyscall programs"
    }
    {
        name: "seq-write-iter-meta"
        category: "helper-state"
        tags: [iter helper-call seq]
        requires: [kernel-btf]
        target: "iter:task"
        program: [
            '{|ctx|'
            '  let data = "abcd"'
            '  helper-call "bpf_seq_write" $ctx.meta.seq $data 4'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "seq-write-rejects-non-iter"
        category: "helper-state"
        tags: [raw-tracepoint helper-call seq reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let data = "abcd"'
            '  helper-call "bpf_seq_write" 0 $data 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_seq_write' is only valid in iter programs"
    }
    {
        name: "seq-printf-allows-null-zero-data"
        category: "helper-state"
        tags: [iter helper-call seq]
        requires: [kernel-btf]
        target: "iter:task"
        program: [
            '{|ctx|'
            '  let fmt = "value\u{0}"'
            '  helper-call "bpf_seq_printf" $ctx.meta.seq $fmt 6 0 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "seq-printf-rejects-unaligned-data-len"
        category: "helper-state"
        tags: [iter helper-call seq reject]
        requires: [kernel-btf]
        target: "iter:task"
        program: [
            '{|ctx|'
            '  let fmt = "value\u{0}"'
            '  let data = "01234567"'
            '  helper-call "bpf_seq_printf" $ctx.meta.seq $fmt 6 $data 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_seq_printf' requires arg4 to be a multiple of 8"
    }
    {
        name: "callback-bpf-loop"
        category: "callbacks"
        tags: [helper-call callback bpf-loop]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_loop" 4 {|i cb| $i } "ctx" 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "callback-for-each-map-elem"
        category: "callbacks"
        tags: [helper-call callback map array]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_for_each_map_elem" elems {|m k v cb| 0 } "ctx" 0 --kind array'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "callback-user-ringbuf-drain"
        category: "callbacks"
        tags: [helper-call callback dynptr user-ringbuf]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_user_ringbuf_drain" user_events {|dyn cb| 0 } "ctx" 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "reserved-events-rejects-user-ringbuf"
        category: "maps"
        tags: [helper-call callback user-ringbuf reject reserved-name]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_user_ringbuf_drain" events {|dyn cb| 0 } "ctx" 0'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map name 'events' is reserved"
    }
    {
        name: "helper-call-kind-rejects-implied-map-kind"
        category: "maps"
        tags: [helper-call map-kind reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  helper-call "bpf_ringbuf_query" demo_ringbuf 0 --kind ringbuf'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper-call --kind is only supported for helpers whose map family is ambiguous"
    }
    {
        name: "csum-diff-allows-null-zero-side"
        category: "helper-state"
        tags: [csum null-pointer tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  helper-call "bpf_csum_diff" 0 0 0 0 0 | count'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "csum-diff-rejects-null-nonzero-side"
        category: "helper-state"
        tags: [csum null-pointer reject tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  helper-call "bpf_csum_diff" 0 4 0 0 0'
            '  "ok"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 28 arg0 requires arg1 = 0 when arg0 is null"
    }
    {
        name: "csum-diff-rejects-unaligned-size"
        category: "helper-state"
        tags: [csum scalar-policy reject tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  helper-call "bpf_csum_diff" 0 2 0 0 0'
            '  "ok"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_csum_diff' requires arg1 to be a multiple of 4"
    }
    {
        name: "redirect-neigh-allows-null-params"
        category: "helper-state"
        tags: [redirect-neigh null-pointer tc]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_redirect_neigh" 1 0 0 0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-neigh-rejects-null-nonzero-plen"
        category: "helper-state"
        tags: [redirect-neigh null-pointer reject tc]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  helper-call "bpf_redirect_neigh" 1 0 4 0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_redirect_neigh' requires arg2 = 0 when arg1 is null"
    }
    {
        name: "adjust-packet-xdp-head"
        category: "language-surface"
        tags: [adjust-packet xdp]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  adjust-packet --head 0'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-xdp-meta"
        category: "language-surface"
        tags: [adjust-packet xdp]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  adjust-packet --meta 0'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-xdp-meta-rejects-stale-data"
        category: "language-surface"
        tags: [adjust-packet xdp packet-bounds reject]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  adjust-packet --meta 0'
            '  ($data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "adjust-packet-xdp-meta-allows-reloaded-data"
        category: "language-surface"
        tags: [adjust-packet xdp packet-bounds accept]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  adjust-packet --meta 0'
            '  ($ctx.data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "adjust-packet-xdp-tail"
        category: "language-surface"
        tags: [adjust-packet xdp]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  adjust-packet --tail 0'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-tc-action-room"
        category: "language-surface"
        tags: [adjust-packet tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  adjust-packet --room 0 --mode 0'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "adjust-packet-lwt-in-pull"
        category: "language-surface"
        tags: [adjust-packet lwt]
        target: "lwt_in:demo-route"
        program: [
            '{|ctx|'
            '  adjust-packet --pull 0'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "adjust-packet-lwt-xmit-head"
        category: "language-surface"
        tags: [adjust-packet lwt]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  adjust-packet --head 0'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "redirect-xdp-ifindex"
        category: "language-surface"
        tags: [redirect xdp]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  redirect 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-tc-action-ifindex"
        category: "language-surface"
        tags: [redirect tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  redirect 1'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-tc-action-peer"
        category: "language-surface"
        tags: [redirect peer tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  redirect --peer 1'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "redirect-tc-action-neigh"
        category: "language-surface"
        tags: [redirect neigh tc-action]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  redirect --neigh 1'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "redirect-tc-egress-rejects-peer"
        category: "language-surface"
        tags: [redirect peer reject tc]
        target: "tc:lo:egress"
        program: [
            '{|ctx|'
            '  redirect --peer 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_redirect_peer' is only valid in tc/tcx ingress programs"
    }
    {
        name: "redirect-tcx-egress-rejects-peer"
        category: "language-surface"
        tags: [redirect peer reject tcx]
        target: "tcx:lo:egress"
        program: [
            '{|ctx|'
            '  redirect --peer 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_redirect_peer' is only valid in tc/tcx ingress programs"
    }
    {
        name: "redirect-lwt-xmit-ifindex"
        category: "language-surface"
        tags: [redirect lwt]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  redirect 1'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "redirect-map-xdp-devmap"
        category: "language-surface"
        tags: [redirect-map xdp map]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  redirect-map tx_ports 0 --kind devmap'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-map-xdp-devmap-hash"
        category: "language-surface"
        tags: [redirect-map xdp map devmap-hash]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  redirect-map tx_ports 0 --kind devmap-hash'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-map-xdp-cpumap"
        category: "language-surface"
        tags: [redirect-map xdp map cpumap]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  redirect-map cpu_targets 0 --kind cpumap'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-map-xdp-xskmap"
        category: "language-surface"
        tags: [redirect-map xdp map xskmap]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  redirect-map xsks 0 --kind xskmap'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tail-call-prog-array"
        category: "language-surface"
        tags: [tail-call prog-array]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | tail-call jumps'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "emit-ringbuf-output-surface"
        category: "language-surface"
        tags: [emit ringbuf helper metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | emit'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "histogram-helper-surface"
        category: "language-surface"
        tags: [histogram map helper metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  42 | histogram'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "start-timer-helper-surface"
        category: "language-surface"
        tags: [start-timer map helper metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  start-timer'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "stop-timer-helper-surface"
        category: "language-surface"
        tags: [stop-timer map helper metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let delta = (stop-timer)'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "random-int-helper-surface"
        category: "language-surface"
        tags: [random helper metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let value = (random int)'
            '  $value | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "read-str-user-pointer"
        category: "language-surface"
        tags: [read-str helper metadata]
        target: "uprobe:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    $ptr | read-str --max-len 64 | emit'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "read-kernel-str-kernel-pointer"
        category: "language-surface"
        tags: [read-kernel-str helper metadata]
        target: "kprobe:do_exit"
        program: [
            '{|ctx|'
            '  $ctx.current_task | read-kernel-str --max-len 64 | emit'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "assign-socket-sk-lookup-clear"
        category: "language-surface"
        tags: [assign-socket sk-lookup]
        requires: [netns-self]
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  assign-socket 0 --replace'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "assign-socket-tc-ingress-clear"
        category: "language-surface"
        tags: [assign-socket tc]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  assign-socket 0'
            '  "ok"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "assign-socket-tc-action-rejects-flags"
        category: "language-surface"
        tags: [assign-socket tc-action reject flags]
        target: "tc_action:diff-action"
        program: [
            '{|ctx|'
            '  assign-socket 0 --replace'
            '  "ok"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "helper 'bpf_sk_assign' requires arg2 = 0 in tc_action programs"
    }
    {
        name: "adjust-message-sk-msg-apply"
        category: "language-surface"
        tags: [adjust-message sk-msg]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-message --apply 8'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-message-rejects-non-sk-msg"
        category: "language-surface"
        tags: [adjust-message reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  adjust-message --apply 8'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "adjust-message is not supported on raw_tracepoint programs"
    }
    {
        name: "adjust-message-sk-msg-cork"
        category: "language-surface"
        tags: [adjust-message sk-msg]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-message --cork 8'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-message-sk-msg-pull"
        category: "language-surface"
        tags: [adjust-message sk-msg]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-message --pull 0 1'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-message-sk-msg-push"
        category: "language-surface"
        tags: [adjust-message sk-msg]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-message --push 0 1'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-message-sk-msg-pop"
        category: "language-surface"
        tags: [adjust-message sk-msg]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-message --pop 0 1'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-socket-sk-msg-sockmap"
        category: "language-surface"
        tags: [redirect-socket sk-msg sockmap]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  redirect-socket peers 0 --kind sockmap'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-socket-sk-msg-sockhash"
        category: "language-surface"
        tags: [redirect-socket sk-msg sockhash]
        target: "sk_msg:/sys/fs/bpf/demo_sockhash"
        program: [
            '{|ctx|'
            '  redirect-socket peers 0 --kind sockhash'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "map-put-sock-ops-sockmap"
        category: "language-surface"
        tags: [maps map-put sock-ops sockmap]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  $ctx | map-put active_sockmap $ctx.remote_port --kind sockmap --flags 2'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "map-put-sock-ops-sockhash"
        category: "language-surface"
        tags: [maps map-put sock-ops sockhash]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  $ctx | map-put active_sockhash $ctx.remote_port --kind sockhash'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "adjust-packet-sk-skb-pull"
        category: "language-surface"
        tags: [adjust-packet sk-skb]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-packet --pull 0'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-socket-sk-skb-sockmap"
        category: "language-surface"
        tags: [redirect-socket sk-skb sockmap]
        target: "sk_skb:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  redirect-socket peers 0 --kind sockmap'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-socket-sk-skb-sockhash"
        category: "language-surface"
        tags: [redirect-socket sk-skb sockhash]
        target: "sk_skb:/sys/fs/bpf/demo_sockhash"
        program: [
            '{|ctx|'
            '  redirect-socket peers 0 --kind sockhash'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "redirect-socket-sk-reuseport-sockarray"
        category: "language-surface"
        tags: [redirect-socket sk-reuseport reuseport-sockarray]
        target: "sk_reuseport:select"
        program: [
            '{|ctx|'
            '  redirect-socket sockets 0 --kind reuseport-sockarray'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "adjust-packet-sk-skb-parser-pull"
        category: "language-surface"
        tags: [adjust-packet sk-skb-parser]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-packet --pull 0'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "redirect-socket-sk-skb-parser-sockhash"
        category: "language-surface"
        tags: [redirect-socket sk-skb-parser sockhash]
        target: "sk_skb_parser:/sys/fs/bpf/demo_sockhash"
        program: [
            '{|ctx|'
            '  redirect-socket peers 0 --kind sockhash'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
]

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

def resolve-plugin-bin [repo_root: string] {
    let override = ($env | get -o PLUGIN_BIN)

    if $override != null {
        if (path-is-filelike $override) {
            $override
        } else {
            fail $"plugin binary not found: ($override)"
        }
    } else {
        newest-existing "plugin binary" [
            ($repo_root | path join target debug nu_plugin_ebpf)
            ($repo_root | path join target release nu_plugin_ebpf)
        ]
    }
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

def source-line-helper-call-name [line: string] {
    if not ($line | str contains "helper-call ") {
        return null
    }

    let parts = ($line | split row "helper-call ")
    if ($parts | length) <= 1 {
        return null
    }

    let raw_helper = (($parts | get 1) | str trim | split row " " | first)
    normalize-helper-name-token $raw_helper
}

def helper-call-fixed-map-kind-kernel-feature [line: string] {
    let helper_name = (source-line-helper-call-name $line)
    if $helper_name == null {
        return null
    }

    let matches = ($HELPER_CALL_FIXED_MAP_KIND_FEATURES | where {|entry| $entry.helper == $helper_name })
    if ($matches | is-empty) {
        return null
    }

    let kind = ($matches | first | get kind)
    map-kind-kernel-feature $kind
}

def helper-call-explicit-map-kind-kernel-feature [line: string] {
    if not (($line | str contains "helper-call ") and ($line | str contains "--kind ")) {
        return null
    }

    let helper_name = (source-line-helper-call-name $line)
    if $helper_name == null {
        return null
    }

    let matches = ($HELPER_CALL_EXPLICIT_MAP_KIND_FEATURES | where {|entry| $entry.helper == $helper_name })
    if ($matches | is-empty) {
        return null
    }

    let kind = (source-line-map-kind $line "")
    let supported_kinds = ($matches | first | get kinds)
    if $kind not-in $supported_kinds {
        return null
    }

    map-kind-kernel-feature $kind
}

def source-line-map-kind [line: string default_kind: string] {
    let parts = ($line | split row "--kind ")
    if ($parts | length) <= 1 {
        return $default_kind
    }

    let raw_kind = (($parts | get 1) | str trim | split row " " | first)
    normalize-map-kind-token $raw_kind
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
    }

    $feature
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

    if $field == "sk" {
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
        if $field == "sk" {
            return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_MSG_SK }
        }
    }
    if (
        ($target_text | str starts-with "sk_skb:")
        or ($target_text | str starts-with "sk_skb_parser:")
    ) and $field == "sk" {
        return { matched: true, feature: $KERNEL_FEATURE_CTX_SK_SKB_SK }
    }
    if (
        ($target_text | str starts-with "socket_filter:")
        or ($target_text | str starts-with "tc_action:")
        or ($target_text | str starts-with "tc:")
        or ($target_text | str starts-with "tcx:")
        or ($target_text | str starts-with "netkit:")
        or ($target_text | str starts-with "cgroup_skb:")
    ) and $field == "sk" {
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
        if $field == "sk" {
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
        if $field == "sk" {
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
        if $field == "sk" {
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
        if $field == "sk" {
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
        if $field == "sk" {
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
            return { matched: true, feature: $KERNEL_FEATURE_CTX_CGROUP_SOCK_ADDR_LOCAL_IP4 }
        }
        if $field == "local_ip6" {
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

def context-field-access-is-assignment-lhs? [raw_access: string field: string] {
    let compact = ($raw_access | str trim | str replace --all " " "")
    let assign_prefix = $"($field)="
    let equality_prefix = $"($field)=="

    ($compact | str starts-with $assign_prefix) and not ($compact | str starts-with $equality_prefix)
}

def line-assigns-context-field? [line: string context_names fields] {
    let trimmed = ($line | str trim)
    for context_name in $context_names {
        for field in $fields {
            if (
                ($trimmed | str contains $"$($context_name).($field) =")
                or ($trimmed | str contains $"$($context_name).($field)=")
            ) {
                return true
            }
        }
    }

    false
}

def context-projection-root? [root: string] {
    $root in [
        "sk"
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

def normalize-context-projection-token [token: string] {
    let parts = (context-projection-parts $token)
    if ($parts | length) < 2 {
        return null
    }

    $parts | get 1
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
    let member = (normalize-context-projection-token $raw_access)
    if $member == null {
        return null
    }

    if $member == "cgroup_id" {
        return $KERNEL_FEATURE_BPF_SK_CGROUP_ID
    }
    if $member == "ancestor_cgroup_id" {
        return $KERNEL_FEATURE_BPF_SK_ANCESTOR_CGROUP_ID
    }
    if ($member in ["tcp" "tcp_sock"]) {
        return $KERNEL_FEATURE_BPF_TCP_SOCK
    }
    if ($member in ["full" "fullsock" "full_sock"]) {
        return $KERNEL_FEATURE_BPF_SK_FULLSOCK
    }
    if $member == "listener" {
        return $KERNEL_FEATURE_BPF_GET_LISTENER_SOCK
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
    if (target-uses-btf-context-args? $target_text) {
        if $root == "arg" and ($parts | length) >= 3 {
            return true
        }
        if ($root in ["arg0" "arg1" "arg2" "arg3" "arg4" "arg5" "retval"]) and ($parts | length) >= 2 {
            return true
        }
    }

    false
}

def context-projection-kernel-read-feature [raw_access: string target] {
    let parts = (context-projection-parts $raw_access)
    if ($parts | length) < 2 {
        return null
    }

    let member = ($parts | get 1)
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
    if (trusted-btf-projection-kernel-read? $parts $target) {
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

def declaration-assignment [line: string] {
    let trimmed = ($line | str trim)
    let prefix = if ($trimmed | str starts-with "let ") {
        "let "
    } else if ($trimmed | str starts-with "mut ") {
        "mut "
    } else {
        return null
    }

    let body = ($trimmed | str substring ($prefix | str length)..)
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

def declaration-rhs-token [assignment] {
    trim-simple-parentheses (($assignment.rhs | split row ";" | first) | str trim)
}

def context-variable-binding [line: string context_names] {
    let assignment = (declaration-assignment $line)
    if $assignment == null {
        return null
    }

    let rhs = (declaration-rhs-token $assignment)
    for context_name in $context_names {
        if $rhs == $"$($context_name)" {
            return $assignment.name
        }
    }

    null
}

def program-context-variable-names [source: string] {
    mut names = ["ctx"]
    mut found_closure = false

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
        let binding = (context-variable-binding $line $names)
        if $binding != null {
            $names = (append-unique-name $names $binding)
        }
    }

    $names
}

def context-root-binding [line: string context_names] {
    let assignment = (declaration-assignment $line)
    if $assignment == null {
        return null
    }

    let rhs = (declaration-rhs-token $assignment)
    for context_name in $context_names {
        let prefix = $"$($context_name)."
        if not ($rhs | str starts-with $prefix) {
            continue
        }

        let root = (normalize-context-field-token ($rhs | str substring ($prefix | str length)..))
        if (context-projection-root? $root) {
            return { name: $assignment.name root: $root }
        }
    }

    null
}

def program-bound-context-root-aliases [source: string context_names] {
    mut aliases = []

    for line in ($source | lines) {
        let binding = (context-root-binding $line $context_names)
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

def bound-context-projection-kernel-features [source: string target context_names] {
    mut features = []
    let aliases = (program-bound-context-root-aliases $source $context_names)
    if ($aliases | is-empty) {
        return $features
    }

    for line in ($source | lines) {
        for alias in $aliases {
            let prefix = $"$($alias.name)."
            let parts = ($line | split row $prefix)
            if ($parts | length) <= 1 {
                continue
            }

            for raw_tail in ($parts | skip 1) {
                let raw_access = $"($alias.root).($raw_tail)"
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
            }
        }
    }

    $features
}

def program-kfunc-names [source: string] {
    mut names = []

    for line in ($source | lines) {
        let parts = ($line | split row "kfunc-call ")
        if ($parts | length) <= 1 {
            continue
        }

        for raw_call in ($parts | skip 1) {
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
        let parts = ($line | split row "helper-call ")
        if ($parts | length) <= 1 {
            continue
        }

        for raw_call in ($parts | skip 1) {
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

    for line in ($source | lines) {
        if ($line | str contains "helper-call ") {
            let fixed_feature = (helper-call-fixed-map-kind-kernel-feature $line)
            if $fixed_feature != null {
                $features = (append-missing-kernel-features $features [$fixed_feature])
            }
            let feature = (helper-call-explicit-map-kind-kernel-feature $line)
            if $feature != null {
                $features = (append-missing-kernel-features $features [$feature])
            }
            continue
        }

        let parts = ($line | split row "--kind ")
        if ($parts | length) > 1 {
            let raw_kind = (($parts | get 1) | str trim | split row " " | first)
            let kind = (normalize-map-kind-token $raw_kind)
            let feature = (map-kind-kernel-feature $kind)
            if $feature != null {
                $features = (append-missing-kernel-features $features [$feature])
            }
        }
    }

    if ($source | str contains "tail-call") {
        $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_MAP_PROG_ARRAY])
    }

    $features
}

def program-reserved-map-kernel-features [source: string] {
    mut features = []

    for line in ($source | lines) {
        if (($line | str contains "| emit") or ($line | str contains " events")) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_MAP_RINGBUF])
        }
        if (
            ($line | str contains "| count")
            or ($line | str contains "| histogram")
            or ($line | str contains "start-timer")
            or ($line | str contains "stop-timer")
        ) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_MAP_HASH])
        }
        if (
            (($line | str contains "map-get ") or ($line | str contains "map-put ") or ($line | str contains "map-delete ") or ($line | str contains "map-contains "))
            and not ($line | str contains "--kind ")
        ) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_MAP_HASH])
        }
        if ($line | str contains " user_events") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_MAP_USER_RINGBUF])
        }
        if ($line | str contains " perf_events") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_MAP_PERF_EVENT_ARRAY])
        }
        if (
            ($line | str contains " kstacks")
            or ($line | str contains " ustacks")
            or ($line | str contains ".kstack")
            or ($line | str contains ".ustack")
        ) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_MAP_STACK_TRACE])
        }
    }

    $features
}

def program-map-value-kernel-features [source: string] {
    mut features = []

    for line in ($source | lines) {
        if not (($line | str contains "map-define ") and ($line | str contains "--value-type")) {
            continue
        }

        for entry in $MAP_VALUE_KERNEL_FEATURES {
            if ($line | str contains $entry.token) {
                $features = (append-missing-kernel-features $features [$entry.feature])
            }
        }
        if ($line | str contains "bpf_list_head:") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_MAP_VALUE_BPF_LIST_NODE])
        }
        if ($line | str contains "bpf_rb_root:") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_MAP_VALUE_BPF_RB_NODE])
        }
    }

    $features
}

def program-global-kernel-features [source: string] {
    for line in ($source | lines) {
        let trimmed = ($line | str trim)
        if ($trimmed | str starts-with "#") {
            continue
        }

        if (($trimmed | str contains "global-define") or ($trimmed | str contains "global-get") or ($trimmed | str contains "global-set")) {
            return [$KERNEL_FEATURE_GLOBAL_DATA_SECTIONS]
        }

        if (($trimmed | str starts-with "mut ") and ($trimmed | str contains ":")) {
            return [$KERNEL_FEATURE_GLOBAL_DATA_SECTIONS]
        }
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
    let context_names = (program-context-variable-names $source)

    for kfunc_name in (program-kfunc-names $source) {
        let feature = (kfunc-kernel-feature $kfunc_name)
        if $feature != null {
            $features = (append-missing-kernel-features $features [$feature])
        }
    }

    for line in ($source | lines) {
        let trimmed = ($line | str trim)
        if (
            ($target_text | str starts-with "cgroup_sock_addr:")
            and ($target_text | str contains "_unix")
            and (line-assigns-context-field? $trimmed $context_names ["sun_path"])
        ) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_KFUNC_BPF_SOCK_ADDR_SET_SUN_PATH])
        }
    }

    $features
}

def program-context-field-kernel-features [source: string target] {
    mut features = []
    let context_names = (program-context-variable-names $source)

    for line in ($source | lines) {
        for context_name in $context_names {
            let parts = ($line | split row $"$($context_name).")
            if ($parts | length) <= 1 {
                continue
            }

            for raw_access in ($parts | skip 1) {
                let field = (normalize-context-field-token $raw_access)
                if $field == "" {
                    continue
                }

                let feature = (context-field-kernel-feature $field $target)
                if $feature != null {
                    $features = (append-missing-kernel-features $features [$feature])
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
            }
        }
    }

    $features = (append-missing-kernel-features $features (bound-context-projection-kernel-features $source $target $context_names))

    $features
}

def program-surface-kernel-features [source: string target] {
    mut features = []
    let target_text = ($target | default "")
    let context_names = (program-context-variable-names $source)
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

    if ($source | str contains "tail-call") {
        $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_TAIL_CALL])
    }
    if ($source | str contains "random int") {
        $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_GET_PRANDOM_U32])
    }
    if ($source | str contains "read-str") {
        $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_PROBE_READ_USER_STR])
    }
    if ($source | str contains "read-kernel-str") {
        $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_PROBE_READ_KERNEL_STR])
    }
    if ($source | str contains "| emit") {
        $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_RINGBUF_OUTPUT])
    }
    if (($source | str contains "| count") or ($source | str contains "| histogram")) {
        $features = (append-missing-kernel-features $features [
            $KERNEL_FEATURE_BPF_MAP_LOOKUP_ELEM
            $KERNEL_FEATURE_BPF_MAP_UPDATE_ELEM
        ])
    }
    if ($source | str contains "start-timer") {
        $features = (append-missing-kernel-features $features [
            $KERNEL_FEATURE_BPF_GET_CURRENT_PID_TGID
            $KERNEL_FEATURE_BPF_KTIME_GET_NS
            $KERNEL_FEATURE_BPF_MAP_UPDATE_ELEM
        ])
    }
    if ($source | str contains "stop-timer") {
        $features = (append-missing-kernel-features $features [
            $KERNEL_FEATURE_BPF_GET_CURRENT_PID_TGID
            $KERNEL_FEATURE_BPF_MAP_LOOKUP_ELEM
            $KERNEL_FEATURE_BPF_KTIME_GET_NS
            $KERNEL_FEATURE_BPF_MAP_DELETE_ELEM
        ])
    }
    for line in ($source | lines) {
        if ($line | str contains "helper-call ") {
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
        let assigns_ctx_sk = (
            line-assigns-context-field? $trimmed $context_names ["sk"]
        )
        let map_kind = (source-line-map-kind $line "hash")
        if ($line | str contains "map-get ") and (generic-map-lookup-kind? $map_kind) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MAP_LOOKUP_ELEM])
        }
        if ($line | str contains "map-put ") and (generic-map-update-kind? $map_kind) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MAP_UPDATE_ELEM])
        }
        if ($target_text | str starts-with "sock_ops:") and ($line | str contains "map-put ") {
            if $map_kind == "sockmap" {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SOCK_MAP_UPDATE])
            } else if $map_kind == "sockhash" {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SOCK_HASH_UPDATE])
            }
        }
        if ($line | str contains "map-delete ") and (generic-map-delete-kind? $map_kind) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MAP_DELETE_ELEM])
        }
        if (($line | str contains "map-get ") or ($line | str contains "map-contains ")) {
            let local_storage_feature = (local-storage-get-helper-kernel-feature $map_kind)
            if $local_storage_feature != null {
                $features = (append-missing-kernel-features $features [$local_storage_feature])
            }
        }
        if ($line | str contains "map-delete ") {
            let local_storage_feature = (local-storage-delete-helper-kernel-feature $map_kind)
            if $local_storage_feature != null {
                $features = (append-missing-kernel-features $features [$local_storage_feature])
            }
        }
        if ($line | str contains "map-push ") and ($map_kind in ["queue" "stack" "bloom-filter"]) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MAP_PUSH_ELEM])
        }
        if ($line | str contains "map-peek ") and ($map_kind in ["queue" "stack"]) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MAP_PEEK_ELEM])
        }
        if ($line | str contains "map-pop ") and ($map_kind in ["queue" "stack"]) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MAP_POP_ELEM])
        }
        if ($line | str contains "map-contains ") {
            if $map_kind == "bloom-filter" {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MAP_PEEK_ELEM])
            } else if (generic-map-lookup-kind? $map_kind) {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MAP_LOOKUP_ELEM])
            }
        }
        if ($line | str contains "redirect-map ") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_REDIRECT_MAP])
        }
        if ($line | str contains "map-contains ") and ($line | str contains "--kind cgroup-array") {
            if $target_uses_skb_cgroup_helper {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SKB_UNDER_CGROUP])
            } else {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_CURRENT_TASK_UNDER_CGROUP])
            }
        }
        if ($line | str contains "assign-socket ") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SK_ASSIGN])
            let socket_context_feature = (context-field-kernel-feature "sk" $target)
            if $socket_context_feature != null {
                $features = (append-missing-kernel-features $features [$socket_context_feature])
            }
        }
        if ($target_text | str starts-with "cgroup_sysctl:") and $assigns_sysctl_new_value {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SYSCTL_SET_NEW_VALUE])
        }
        if $target_supports_ctx_sk_assign and $assigns_ctx_sk {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SK_ASSIGN])
        }
        if ($line | str contains "adjust-message --apply") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MSG_APPLY_BYTES])
        }
        if ($line | str contains "adjust-message --cork") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MSG_CORK_BYTES])
        }
        if ($line | str contains "adjust-message --pull") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MSG_PULL_DATA])
        }
        if ($line | str contains "adjust-message --push") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MSG_PUSH_DATA])
        }
        if ($line | str contains "adjust-message --pop") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MSG_POP_DATA])
        }
        if ($line | str contains "adjust-packet --pull") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SKB_PULL_DATA])
        }
        if ($line | str contains "redirect-socket ") {
            if ($target_text | str starts-with "sk_msg:") {
                if ($line | str contains "--kind sockhash") {
                    $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MSG_REDIRECT_HASH])
                } else {
                    $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_MSG_REDIRECT_MAP])
                }
            } else if ($target_text | str starts-with "sk_skb:") or ($target_text | str starts-with "sk_skb_parser:") {
                if ($line | str contains "--kind sockhash") {
                    $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SK_REDIRECT_HASH])
                } else {
                    $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SK_REDIRECT_MAP])
                }
            } else if ($target_text | str starts-with "sk_reuseport:") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SK_SELECT_REUSEPORT])
            }
        }
        if ($target_text | str starts-with "sock_ops:") and (line-assigns-context-field? $trimmed $context_names ["cb_flags"]) {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SOCK_OPS_CB_FLAGS_SET])
        }
        if ($target_text | str starts-with "xdp:") {
            if ($line | str contains "adjust-packet --head") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_XDP_ADJUST_HEAD])
            }
            if ($line | str contains "adjust-packet --meta") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_XDP_ADJUST_META])
            }
            if ($line | str contains "adjust-packet --tail") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_XDP_ADJUST_TAIL])
            }
        } else {
            if ($line | str contains "adjust-packet --head") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SKB_CHANGE_HEAD])
            }
            if ($line | str contains "adjust-packet --tail") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SKB_CHANGE_TAIL])
            }
            if ($line | str contains "adjust-packet --room") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_SKB_ADJUST_ROOM])
            }
        }
        if ($line | str contains "redirect ") and not ($line | str contains "redirect-map") and not ($line | str contains "redirect-socket") {
            if ($line | str contains "--peer") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_REDIRECT_PEER])
            } else if ($line | str contains "--neigh") {
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
        if ($target | str contains ":frags") {
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
        if ($target | str contains ":defrag") {
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
        if ($target | str contains ":migrate") {
            $features = ($features | append $KERNEL_FEATURE_SK_REUSEPORT_MIGRATION)
        }
    } else if ($target | str starts-with "cgroup_skb:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_CGROUP_SKB)
    } else if ($target | str starts-with "cgroup_sock_addr:") {
        $features = ($features | append $KERNEL_FEATURE_PROG_CGROUP_SOCK_ADDR)
        if ($target | str contains "_unix") {
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

def fixture-kernel-features [fixture] {
    mut features = (optional $fixture kernel_features [])
    $features = (append-missing-kernel-features $features (target-kernel-features ($fixture | get -o target)))
    let program = (fixture-program $fixture)
    $features = (append-missing-kernel-features $features (program-map-kernel-features $program))
    $features = (append-missing-kernel-features $features (program-reserved-map-kernel-features $program))
    $features = (append-missing-kernel-features $features (program-map-value-kernel-features $program))
    $features = (append-missing-kernel-features $features (program-global-kernel-features $program))
    $features = (append-missing-kernel-features $features (program-helper-kernel-features $program))
    $features = (append-missing-kernel-features $features (program-kfunc-kernel-features $program ($fixture | get -o target)))
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

def fixture-effective-min-kernel [fixture] {
    let versions = (
        fixture-kernel-features $fixture
        | each {|feature| $feature.min_kernel }
    )

    kernel-version-max $versions
}

def fixture-effective-max-kernel-exclusive [fixture] {
    let versions = (
        fixture-kernel-features $fixture
        | each {|feature| $feature | get -o max_kernel_exclusive }
        | where {|version| $version != null and $version != "" }
    )

    kernel-version-min $versions
}

def fixture-effective-min-kernel-sources [fixture] {
    let min_kernel = (fixture-effective-min-kernel $fixture)
    if $min_kernel == null {
        return []
    }

    fixture-kernel-features $fixture
    | where {|feature| $feature.min_kernel == $min_kernel }
    | each {|feature| $feature.source }
    | uniq
}

def fixture-kernel-compatibility [fixture kernel_release] {
    let min_kernel = (fixture-effective-min-kernel $fixture)
    let max_kernel = (fixture-effective-max-kernel-exclusive $fixture)

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

def fixture-default-test-lane [fixture] {
    let explicit = ($fixture | get -o default_test_lane)
    if $explicit != null {
        return $explicit
    }

    let lanes = (
        fixture-kernel-features $fixture
        | each {|feature| kernel-feature-default-test-lane $feature }
    )
    aggregate-test-lanes $lanes
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

    if ($requirements | any {|feature| $feature in ["kernel-btf" "tracefs"] }) {
        "btf"
    } else {
        "fast"
    }
}

def fixture-summary [fixture compat_kernel] {
    let compatibility = (fixture-kernel-compatibility $fixture $compat_kernel)
    let default_test_lane = (fixture-default-test-lane $fixture)

    {
        name: $fixture.name
        target: (optional $fixture target "")
        category: (optional $fixture category "")
        tier: (fixture-tier $fixture)
        local: $fixture.local
        kernel: $fixture.kernel
        requires: (optional $fixture requires [])
        kernel_requires: (optional $fixture kernel_requires [])
        kernel_features: (fixture-kernel-features $fixture)
        default_test_lane: $default_test_lane
        default_test_lane_description: (test-lane-description $default_test_lane)
        effective_min_kernel: (fixture-effective-min-kernel $fixture | default "")
        effective_max_kernel_exclusive: (fixture-effective-max-kernel-exclusive $fixture | default "")
        effective_min_kernel_sources: (fixture-effective-min-kernel-sources $fixture)
        compat_kernel: ($compat_kernel | default "")
        compatible_with_compat_kernel: $compatibility.compatible
        compat_kernel_reason: $compatibility.reason
        min_kernel: (optional $fixture min_kernel "")
        min_kernel_source: (optional $fixture min_kernel_source "")
        tags: (optional $fixture tags [])
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

def fixture-matrix-rows [fixtures compat_kernel] {
    mut rows = []

    for tier in $VALID_TIERS {
        let tier_fixtures = (
            $fixtures
            | where {|fixture| (fixture-tier $fixture) == $tier }
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
                local_accept: (fixture-status-count $category_fixtures local accept)
                local_reject: (fixture-status-count $category_fixtures local reject)
                local_skip: (fixture-status-count $category_fixtures local skip)
                kernel_accept: (fixture-status-count $category_fixtures kernel accept)
                kernel_reject: (fixture-status-count $category_fixtures kernel reject)
                kernel_skip: (fixture-status-count $category_fixtures kernel skip)
                kernel_accept_versioned: (kernel-accept-versioned-count $category_fixtures true)
                kernel_accept_unversioned: (kernel-accept-versioned-count $category_fixtures false)
                lane_host_safe: (fixture-test-lane-count $category_fixtures "host-safe")
                lane_host_gated: (fixture-test-lane-count $category_fixtures "host-gated")
                lane_dry_run: (fixture-test-lane-count $category_fixtures "dry-run")
                lane_vm_only: (fixture-test-lane-count $category_fixtures "vm-only")
            }

            let row = if $compat_kernel == null {
                $base
            } else {
                $base
                | upsert compat_kernel $compat_kernel
                | upsert kernel_accept_compatible (kernel-accept-compatible-count $category_fixtures $compat_kernel true)
                | upsert kernel_accept_incompatible (kernel-accept-compatible-count $category_fixtures $compat_kernel false)
                | upsert kernel_accept_requires_newer (kernel-accept-compat-reason-count $category_fixtures $compat_kernel "kernel>=")
                | upsert kernel_accept_requires_older (kernel-accept-compat-reason-count $category_fixtures $compat_kernel "kernel<")
            }

            $rows = ($rows | append $row)
        }
    }

    $rows
}

def print-fixture-matrix [fixtures compat_kernel] {
    for row in (fixture-matrix-rows $fixtures $compat_kernel) {
        let compat_text = if (($row | get -o compat_kernel) == null) {
            ""
        } else {
            $" compat_kernel=($row.compat_kernel) kernel_accept_compatible=($row.kernel_accept_compatible) kernel_accept_incompatible=($row.kernel_accept_incompatible) kernel_accept_requires_newer=($row.kernel_accept_requires_newer) kernel_accept_requires_older=($row.kernel_accept_requires_older)"
        }
        print $"tier=($row.tier) category=($row.category) total=($row.total) local_accept=($row.local_accept) local_reject=($row.local_reject) local_skip=($row.local_skip) kernel_accept=($row.kernel_accept) kernel_reject=($row.kernel_reject) kernel_skip=($row.kernel_skip) kernel_accept_versioned=($row.kernel_accept_versioned) kernel_accept_unversioned=($row.kernel_accept_unversioned) lane_host_safe=($row.lane_host_safe) lane_host_gated=($row.lane_host_gated) lane_dry_run=($row.lane_dry_run) lane_vm_only=($row.lane_vm_only)($compat_text)"
    }
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
        if $feature not-in $VALID_HOST_FEATURES {
            fail $"fixture ($fixture.name) declares unknown ($field) feature '($feature)'; expected one of ($VALID_HOST_FEATURES | str join ', ')"
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
        if (kernel-version-compare $max_kernel $min_kernel) <= 0 {
            fail $"fixture ($fixture_name) ($origin) kernel feature ($key) max_kernel_exclusive=($max_kernel) must be greater than min_kernel=($min_kernel)"
        }
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
}

def validate-program-target-kernel-feature-expectations [] {
    for expectation in $PROGRAM_TARGET_KERNEL_FEATURE_EXPECTATIONS {
        let target = $expectation.target
        let expected_keys = ($expectation.feature_keys | sort)
        let actual_keys = (
            target-kernel-features $target
            | each {|feature| $feature.key }
            | sort
        )
        let missing = ($expected_keys | where {|key| $key not-in $actual_keys })
        let unexpected = ($actual_keys | where {|key| $key not-in $expected_keys })

        if (($missing | length) > 0) or (($unexpected | length) > 0) {
            fail $"target-kernel-features drifted for ($target): missing=($missing | str join ',') unexpected=($unexpected | str join ',')"
        }
    }
}

def validate-program-map-kernel-feature-expectations [] {
    for expectation in $PROGRAM_MAP_KERNEL_FEATURE_EXPECTATIONS {
        let program = ($expectation.program | str join "\n")
        let expected_keys = ($expectation.feature_keys | sort)
        let actual_keys = (
            program-map-kernel-features $program
            | each {|feature| $feature.key }
            | sort
        )
        let missing = ($expected_keys | where {|key| $key not-in $actual_keys })

        if ($missing | length) > 0 {
            fail $"program-map-kernel-features drifted: missing=($missing | str join ',') actual=($actual_keys | str join ',')"
        }
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

        for key in [key min_kernel source max_kernel_exclusive] {
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

        for key in [key min_kernel source max_kernel_exclusive] {
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

        for key in [key min_kernel source max_kernel_exclusive] {
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
        let expected_keys = ($expectation.feature_keys | sort)
        let actual_keys = (
            program-context-field-kernel-features $program $target
            | each {|feature| $feature.key }
            | sort
        )
        let missing = ($expected_keys | where {|key| $key not-in $actual_keys })

        if ($missing | length) > 0 {
            fail $"program-context-field-kernel-features drifted for ($target): missing=($missing | str join ',') actual=($actual_keys | str join ',')"
        }
    }
}

def validate-program-surface-kernel-feature-expectations [] {
    for expectation in $PROGRAM_SURFACE_KERNEL_FEATURE_EXPECTATIONS {
        let target = $expectation.target
        let program = ($expectation.program | str join "\n")
        let expected_keys = ($expectation.feature_keys | sort)
        let actual_keys = (
            program-surface-kernel-features $program $target
            | each {|feature| $feature.key }
            | sort
        )
        let missing = ($expected_keys | where {|key| $key not-in $actual_keys })

        if ($missing | length) > 0 {
            fail $"program-surface-kernel-features drifted for ($target): missing=($missing | str join ',') actual=($actual_keys | str join ',')"
        }
    }
}

def validate-program-kfunc-kernel-feature-expectations [] {
    for expectation in $PROGRAM_KFUNC_KERNEL_FEATURE_EXPECTATIONS {
        let target = $expectation.target
        let program = ($expectation.program | str join "\n")
        let expected_keys = ($expectation.feature_keys | sort)
        let actual_keys = (
            program-kfunc-kernel-features $program $target
            | each {|feature| $feature.key }
            | sort
        )
        let missing = ($expected_keys | where {|key| $key not-in $actual_keys })

        if ($missing | length) > 0 {
            fail $"program-kfunc-kernel-features drifted for ($target): missing=($missing | str join ',') actual=($actual_keys | str join ',')"
        }
    }
}

def validate-fixture-metadata [fixtures] {
    validate-program-target-kernel-feature-expectations
    validate-program-map-kernel-feature-expectations
    validate-target-context-field-kernel-feature-expectations
    validate-context-field-helper-kernel-feature-expectations
    validate-context-projection-kernel-feature-expectations
    validate-program-context-field-kernel-feature-expectations
    validate-program-surface-kernel-feature-expectations
    validate-program-kfunc-kernel-feature-expectations

    let names = ($fixtures | each {|fixture| $fixture.name })

    for name in ($names | uniq) {
        let count = ($names | where {|candidate| $candidate == $name } | length)
        if $count > 1 {
            fail $"duplicate verifier fixture name: ($name)"
        }
    }

    for fixture in $fixtures {
        validate-tier-option $"fixture ($fixture.name)" ($fixture | get -o tier)
        validate-test-lane-option $"fixture ($fixture.name)" ($fixture | get -o default_test_lane)
        validate-status-option $"fixture ($fixture.name) local" $fixture.local
        validate-status-option $"fixture ($fixture.name) kernel" $fixture.kernel
        validate-host-features $fixture requires
        validate-host-features $fixture kernel_requires
        validate-kernel-feature-metadata $fixture

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
    }
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

def host-feature-available [feature: string] {
    if $feature == "loopback-interface" {
        "/sys/class/net/lo" | path exists
    } else if $feature == "kernel-btf" {
        "/sys/kernel/btf/vmlinux" | path exists
    } else if $feature == "tracefs" {
        "/sys/kernel/tracing/events" | path exists
    } else if $feature == "cgroup-v2" {
        "/sys/fs/cgroup/cgroup.controllers" | path exists
    } else if $feature == "netns-self" {
        "/proc/self/ns/net" | path exists
    } else if $feature == "lirc-device" {
        "/dev/lirc0" | path exists
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

def select-fixtures [fixture_name category tag tier exclude_tier local_status kernel_status test_lane] {
    validate-tier-option "selected" $tier
    validate-tier-option "excluded" $exclude_tier
    validate-test-lane-option "selected" $test_lane
    validate-status-option "local" $local_status
    validate-status-option "kernel" $kernel_status

    let fixtures = if $fixture_name == null {
        $FIXTURES
    } else {
        let matches = ($FIXTURES | where {|fixture| $fixture.name == $fixture_name })
        if (($matches | length) == 0) {
            fail $"unknown verifier fixture: ($fixture_name)"
        }
        $matches
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

def main [
    --list         # List verifier fixtures and exit.
    --matrix       # Print verifier fixture counts by tier and category, then exit.
    --json         # Emit JSON for --list or --matrix.
    --compat-kernel: string # With --list or --matrix, compare effective minimums against this kernel release.
    --kernel       # Require kernel verifier checks instead of auto-skipping missing prerequisites.
    --no-kernel    # Run only local dry-run compiler/VCC checks.
    --fast         # Run only fixtures in the fast tier.
    --fixture: string # Run one fixture by exact name.
    --category: string # Run fixtures with an exact category.
    --tag: string # Run fixtures containing a tag.
    --tier: string # Run fixtures in a tier: fast, btf, kernel, or vm-only.
    --exclude-tier: string # Exclude fixtures in a tier: fast, btf, kernel, or vm-only.
    --test-lane: string # Run fixtures in a default test lane: host-safe, host-gated, dry-run, or vm-only.
    --local-status: string # Run fixtures whose expected local status is accept, reject, or skip.
    --kernel-status: string # Run fixtures whose expected kernel status is accept, reject, or skip.
] {
    if $kernel and $no_kernel {
        fail "--kernel and --no-kernel are mutually exclusive"
    }
    if $list and $matrix {
        fail "--list and --matrix are mutually exclusive"
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

    validate-fixture-metadata $FIXTURES
    if $compat_kernel != null {
        parse-kernel-version $compat_kernel | ignore
    }

    let selected_tier = if $fast { "fast" } else { $tier }
    let fixtures = (select-fixtures $fixture $category $tag $selected_tier $exclude_tier $local_status $kernel_status $test_lane)

    if $list {
        let summaries = ($fixtures | each {|fixture| fixture-summary $fixture $compat_kernel })
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
            print ((fixture-matrix-rows $fixtures $compat_kernel) | to json)
        } else {
            print-fixture-matrix $fixtures $compat_kernel
        }
        return
    }

    let plugin_bin = (resolve-plugin-bin $REPO_ROOT)
    print $"Using plugin: ($plugin_bin)"

    let local_fixtures = (select-fixtures-with-requirements $fixtures $kernel "local")
    if (($local_fixtures | length) == 0) {
        print "ok: 0 local fixtures"
        return
    }

    let local_results = (
        $local_fixtures
        | each {|fixture|
            let result = (check-local-fixture $plugin_bin $fixture)
            print $"local  ($result.local)  ($fixture.name)"
            $result
        }
    )

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
