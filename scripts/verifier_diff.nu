#!/usr/bin/env nu

const REPO_ROOT = (path self | path dirname | path dirname)
const BPFFS = "/sys/fs/bpf"
const VALID_TIERS = ["fast" "btf" "kernel" "vm-only"]
const VALID_HOST_FEATURES = [
    "cgroup-v2"
    "kernel-btf"
    "lirc-device"
    "loopback-interface"
    "netns-self"
    "tracefs"
]

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
const KERNEL_FEATURE_STRUCT_OPS_SCHED_EXT = {
    key: "struct_ops:sched_ext_ops"
    min_kernel: "6.12"
    source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c"
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
const KERNEL_FEATURE_KFUNC_SCX_BPF_GET_IDLE_CPUMASK = {
    key: "kfunc:scx_bpf_get_idle_cpumask"
    min_kernel: "6.12"
    max_kernel_exclusive: "6.15"
    source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c"
}
const KERNEL_FEATURE_KFUNC_SCX_BPF_GET_IDLE_SMTMASK = {
    key: "kfunc:scx_bpf_get_idle_smtmask"
    min_kernel: "6.12"
    max_kernel_exclusive: "6.15"
    source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c"
}
const KERNEL_FEATURE_KFUNC_SCX_BPF_PICK_ANY_CPU = {
    key: "kfunc:scx_bpf_pick_any_cpu"
    min_kernel: "6.12"
    max_kernel_exclusive: "6.15"
    source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c"
}
const KERNEL_FEATURE_KFUNC_SCX_BPF_PUT_IDLE_CPUMASK = {
    key: "kfunc:scx_bpf_put_idle_cpumask"
    min_kernel: "6.12"
    max_kernel_exclusive: "6.15"
    source: "https://github.com/torvalds/linux/blob/v6.12/kernel/sched/ext.c"
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
    min_kernel: "4.17"
    source: "https://github.com/torvalds/linux/blob/v4.17/include/uapi/linux/bpf.h"
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
]

const HELPER_KERNEL_FEATURES = [
    { name: "bpf_map_lookup_elem", feature: $KERNEL_FEATURE_BPF_MAP_LOOKUP_ELEM }
    { name: "bpf_map_update_elem", feature: $KERNEL_FEATURE_BPF_MAP_UPDATE_ELEM }
    { name: "bpf_map_delete_elem", feature: $KERNEL_FEATURE_BPF_MAP_DELETE_ELEM }
    { name: "bpf_get_prandom_u32", feature: $KERNEL_FEATURE_BPF_GET_PRANDOM_U32 }
    { name: "bpf_tail_call", feature: $KERNEL_FEATURE_BPF_TAIL_CALL }
    { name: "bpf_perf_event_read", feature: $KERNEL_FEATURE_BPF_PERF_EVENT_READ }
    { name: "bpf_perf_event_read_value", feature: $KERNEL_FEATURE_BPF_PERF_EVENT_READ_VALUE }
    { name: "bpf_override_return", feature: $KERNEL_FEATURE_BPF_OVERRIDE_RETURN }
    { name: "bpf_redirect", feature: $KERNEL_FEATURE_BPF_REDIRECT }
    { name: "bpf_get_stackid", feature: $KERNEL_FEATURE_BPF_GET_STACKID }
    { name: "bpf_get_stack", feature: $KERNEL_FEATURE_BPF_GET_STACK }
    { name: "bpf_csum_diff", feature: $KERNEL_FEATURE_BPF_CSUM_DIFF }
    { name: "bpf_skb_load_bytes", feature: $KERNEL_FEATURE_BPF_SKB_LOAD_BYTES }
    { name: "bpf_skb_under_cgroup", feature: $KERNEL_FEATURE_BPF_SKB_UNDER_CGROUP }
    { name: "bpf_skb_pull_data", feature: $KERNEL_FEATURE_BPF_SKB_PULL_DATA }
    { name: "bpf_skb_adjust_room", feature: $KERNEL_FEATURE_BPF_SKB_ADJUST_ROOM }
    { name: "bpf_skb_change_head", feature: $KERNEL_FEATURE_BPF_SKB_CHANGE_HEAD }
    { name: "bpf_skb_change_tail", feature: $KERNEL_FEATURE_BPF_SKB_CHANGE_TAIL }
    { name: "bpf_xdp_adjust_head", feature: $KERNEL_FEATURE_BPF_XDP_ADJUST_HEAD }
    { name: "bpf_xdp_adjust_meta", feature: $KERNEL_FEATURE_BPF_XDP_ADJUST_META }
    { name: "bpf_xdp_adjust_tail", feature: $KERNEL_FEATURE_BPF_XDP_ADJUST_TAIL }
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
    { name: "bpf_sk_select_reuseport", feature: $KERNEL_FEATURE_BPF_SK_SELECT_REUSEPORT }
    { name: "bpf_ringbuf_output", feature: $KERNEL_FEATURE_BPF_RINGBUF_OUTPUT }
    { name: "bpf_ringbuf_reserve", feature: $KERNEL_FEATURE_BPF_RINGBUF_RESERVE }
    { name: "bpf_ringbuf_submit", feature: $KERNEL_FEATURE_BPF_RINGBUF_SUBMIT }
    { name: "bpf_ringbuf_discard", feature: $KERNEL_FEATURE_BPF_RINGBUF_DISCARD }
    { name: "bpf_ringbuf_query", feature: $KERNEL_FEATURE_BPF_RINGBUF_QUERY }
    { name: "bpf_redirect_neigh", feature: $KERNEL_FEATURE_BPF_REDIRECT_NEIGH }
    { name: "bpf_redirect_peer", feature: $KERNEL_FEATURE_BPF_REDIRECT_PEER }
    { name: "bpf_bprm_opts_set", feature: $KERNEL_FEATURE_BPF_BPRM_OPTS_SET }
    { name: "bpf_spin_lock", feature: $KERNEL_FEATURE_BPF_SPIN_LOCK }
    { name: "bpf_spin_unlock", feature: $KERNEL_FEATURE_BPF_SPIN_UNLOCK }
    { name: "bpf_for_each_map_elem", feature: $KERNEL_FEATURE_BPF_FOR_EACH_MAP_ELEM }
    { name: "bpf_seq_printf", feature: $KERNEL_FEATURE_BPF_SEQ_PRINTF }
    { name: "bpf_seq_write", feature: $KERNEL_FEATURE_BPF_SEQ_WRITE }
    { name: "bpf_sys_bpf", feature: $KERNEL_FEATURE_BPF_SYS_BPF }
    { name: "bpf_sys_close", feature: $KERNEL_FEATURE_BPF_SYS_CLOSE }
    { name: "bpf_btf_find_by_name_kind", feature: $KERNEL_FEATURE_BPF_BTF_FIND_BY_NAME_KIND }
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
    { name: "scx_bpf_get_idle_cpumask", feature: $KERNEL_FEATURE_KFUNC_SCX_BPF_GET_IDLE_CPUMASK }
    { name: "scx_bpf_get_idle_smtmask", feature: $KERNEL_FEATURE_KFUNC_SCX_BPF_GET_IDLE_SMTMASK }
    { name: "scx_bpf_pick_any_cpu", feature: $KERNEL_FEATURE_KFUNC_SCX_BPF_PICK_ANY_CPU }
    { name: "scx_bpf_put_idle_cpumask", feature: $KERNEL_FEATURE_KFUNC_SCX_BPF_PUT_IDLE_CPUMASK }
]

const CONTEXT_FIELD_KERNEL_FEATURES = [
    { field: "packet_len", feature: $KERNEL_FEATURE_CTX_PACKET_LEN }
    { field: "len", feature: $KERNEL_FEATURE_CTX_PACKET_LEN }
    { field: "pkt_type", feature: $KERNEL_FEATURE_CTX_PKT_TYPE }
    { field: "queue_mapping", feature: $KERNEL_FEATURE_CTX_QUEUE_MAPPING }
    { field: "eth_protocol", feature: $KERNEL_FEATURE_CTX_ETH_PROTOCOL }
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
            '  ($ctx.arg.file.f_flags + $ctx.pid) | count'
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
            '  ($ctx.arg2 + $ctx.pid) | count'
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
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.rx_queue_index) | count'
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
        kernel_features: [$KERNEL_FEATURE_MAP_HASH]
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
        kernel_features: [$KERNEL_FEATURE_MAP_HASH]
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
        kernel_features: [$KERNEL_FEATURE_BPF_RINGBUF_QUERY]
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
        kernel_features: [$KERNEL_FEATURE_BPF_RINGBUF_RESERVE]
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
        kernel_features: [$KERNEL_FEATURE_BPF_RINGBUF_DISCARD]
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
        kernel_features: [
            $KERNEL_FEATURE_BPF_RINGBUF_RESERVE_DYNPTR
            $KERNEL_FEATURE_BPF_RINGBUF_SUBMIT_DYNPTR
        ]
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
        kernel_features: [
            $KERNEL_FEATURE_BPF_RINGBUF_RESERVE_DYNPTR
            $KERNEL_FEATURE_BPF_RINGBUF_DISCARD_DYNPTR
        ]
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
        kernel_features: [$KERNEL_FEATURE_BPF_RINGBUF_RESERVE_DYNPTR]
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
        kernel_features: [
            $KERNEL_FEATURE_BPF_RINGBUF_RESERVE_DYNPTR
            $KERNEL_FEATURE_BPF_RINGBUF_SUBMIT_DYNPTR
        ]
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
        kernel_features: [
            $KERNEL_FEATURE_BPF_RINGBUF_RESERVE_DYNPTR
            $KERNEL_FEATURE_BPF_RINGBUF_DISCARD_DYNPTR
            $KERNEL_FEATURE_BPF_RINGBUF_SUBMIT_DYNPTR
        ]
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
        kernel_features: [
            $KERNEL_FEATURE_BPF_RINGBUF_RESERVE_DYNPTR
            $KERNEL_FEATURE_BPF_RINGBUF_SUBMIT_DYNPTR
        ]
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
        kernel_features: [
            $KERNEL_FEATURE_BPF_RINGBUF_RESERVE_DYNPTR
            $KERNEL_FEATURE_BPF_RINGBUF_DISCARD_DYNPTR
            $KERNEL_FEATURE_BPF_RINGBUF_SUBMIT_DYNPTR
        ]
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
        kernel_features: [$KERNEL_FEATURE_BPF_DYNPTR_DATA]
        error_contains: "requires initialized dynptr stack object"
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
        kernel_features: [
            $KERNEL_FEATURE_BPF_RINGBUF_RESERVE_DYNPTR
            $KERNEL_FEATURE_BPF_RINGBUF_SUBMIT_DYNPTR
            $KERNEL_FEATURE_KFUNC_BPF_DYNPTR_SIZE
        ]
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
        kernel_features: [
            $KERNEL_FEATURE_BPF_RINGBUF_RESERVE_DYNPTR
            $KERNEL_FEATURE_BPF_RINGBUF_DISCARD_DYNPTR
            $KERNEL_FEATURE_KFUNC_BPF_DYNPTR_SLICE
        ]
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
        kernel_features: [$KERNEL_FEATURE_KFUNC_BPF_DYNPTR_SLICE]
        error_contains: "kfunc 'bpf_dynptr_slice' arg0 requires initialized dynptr stack object"
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
        kernel_features: [
            $KERNEL_FEATURE_BPF_RINGBUF_RESERVE_DYNPTR
            $KERNEL_FEATURE_BPF_RINGBUF_SUBMIT_DYNPTR
            $KERNEL_FEATURE_KFUNC_BPF_DYNPTR_CLONE
            $KERNEL_FEATURE_KFUNC_BPF_DYNPTR_SIZE
        ]
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
        kernel_features: [$KERNEL_FEATURE_KFUNC_BPF_DYNPTR_CLONE]
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
        kernel_features: [
            $KERNEL_FEATURE_BPF_RINGBUF_RESERVE_DYNPTR
            $KERNEL_FEATURE_BPF_RINGBUF_SUBMIT_DYNPTR
            $KERNEL_FEATURE_KFUNC_BPF_DYNPTR_CLONE
            $KERNEL_FEATURE_KFUNC_BPF_DYNPTR_SIZE
        ]
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
        kernel_features: [$KERNEL_FEATURE_BPF_GET_STACKID]
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
        kernel_features: [$KERNEL_FEATURE_GLOBAL_DATA_SECTIONS]
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
        kernel_features: [
            $KERNEL_FEATURE_PROG_SCHED_ACT
            $KERNEL_FEATURE_MAP_CGROUP_ARRAY
            $KERNEL_FEATURE_BPF_SKB_UNDER_CGROUP
        ]
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
            '  ($ctx.packet_len + $ctx.protocol + $ctx.mark + $ctx.priority + $ctx.remote_ip4 + $ctx.local_port + $ctx.sk.cgroup_id) | count'
            '  "allow"'
            '}'
        ]
        local: "accept"
        kernel: "skip"
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
            '  (($ctx.local_ip6 | get 1) + ($ctx.sk.src_ip6 | get 1) + $ctx.local_port + $ctx.remote_port) | count'
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
        tags: [cgroup-sock-addr context unix writable kfunc]
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
        name: "sock-ops-basic-context-write"
        category: "context-surface"
        tags: [sock-ops context writable]
        requires: [cgroup-v2]
        target: "sock_ops:/sys/fs/cgroup"
        program: [
            '{|ctx|'
            '  mut ctx = $ctx'
            '  ($ctx.op + ($ctx.args | get 0) + $ctx.family + $ctx.remote_port + $ctx.socket_cookie + $ctx.netns_cookie + $ctx.sk.family) | count'
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
            '  ($ctx.family + $ctx.protocol + $ctx.local_port + $ctx.remote_port + $ctx.cookie + $ctx.sk.family) | count'
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
        name: "lwt-xmit-helper-context"
        category: "context-surface"
        tags: [lwt context helper-backed]
        target: "lwt_xmit:demo-route"
        program: [
            '{|ctx|'
            '  ($ctx.packet_len + $ctx.ifindex + $ctx.protocol + $ctx.hash + $ctx.hash_recalc + $ctx.cgroup_classid + $ctx.route_realm) | count'
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
        name: "map-define-rejects-bare-graph-field"
        category: "maps"
        tags: [maps map-define graph reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define graph_items --kind hash --value-type "record{root:bpf_list_head:node_data:node,cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map value graph type spec"
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
        kernel_features: [
            $KERNEL_FEATURE_BPF_TIMER_INIT
            $KERNEL_FEATURE_BPF_TIMER_SET_CALLBACK
            $KERNEL_FEATURE_BPF_TIMER_START
            $KERNEL_FEATURE_BPF_TIMER_CANCEL
        ]
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
        kernel_features: [
            $KERNEL_FEATURE_KFUNC_BPF_TASK_FROM_PID
            $KERNEL_FEATURE_KFUNC_BPF_TASK_RELEASE
        ]
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
        kernel_features: [$KERNEL_FEATURE_KFUNC_BPF_TASK_FROM_PID]
        error_contains: "unreleased kfunc reference at function exit"
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
        kernel_features: [
            $KERNEL_FEATURE_KFUNC_BPF_TASK_ACQUIRE
            $KERNEL_FEATURE_KFUNC_BPF_TASK_RELEASE
        ]
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
        kernel_features: [
            $KERNEL_FEATURE_KFUNC_BPF_GET_TASK_EXE_FILE
            $KERNEL_FEATURE_KFUNC_BPF_PUT_FILE
        ]
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
        kernel_features: [$KERNEL_FEATURE_KFUNC_BPF_GET_TASK_EXE_FILE]
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
        kernel_features: [
            $KERNEL_FEATURE_KFUNC_BPF_CGROUP_ACQUIRE
            $KERNEL_FEATURE_KFUNC_BPF_CGROUP_RELEASE
        ]
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
        kernel_features: [$KERNEL_FEATURE_KFUNC_BPF_CGROUP_ACQUIRE]
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
        kernel_features: [
            $KERNEL_FEATURE_KFUNC_BPF_CGROUP_FROM_ID
            $KERNEL_FEATURE_KFUNC_BPF_CGROUP_RELEASE
        ]
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
        kernel_features: [
            $KERNEL_FEATURE_KFUNC_BPF_CGROUP_FROM_ID
            $KERNEL_FEATURE_KFUNC_BPF_CGROUP_ANCESTOR
            $KERNEL_FEATURE_KFUNC_BPF_CGROUP_RELEASE
        ]
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
        kernel_features: [
            $KERNEL_FEATURE_KFUNC_BPF_CPUMASK_CREATE
            $KERNEL_FEATURE_KFUNC_BPF_CPUMASK_RELEASE
        ]
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
        kernel_features: [$KERNEL_FEATURE_KFUNC_BPF_CPUMASK_CREATE]
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
        kernel_features: [
            $KERNEL_FEATURE_KFUNC_BPF_CPUMASK_CREATE
            $KERNEL_FEATURE_KFUNC_BPF_CPUMASK_ACQUIRE
            $KERNEL_FEATURE_KFUNC_BPF_CPUMASK_RELEASE
        ]
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
        kernel_features: [
            $KERNEL_FEATURE_KFUNC_BPF_CPUMASK_CREATE
            $KERNEL_FEATURE_KFUNC_BPF_CPUMASK_ACQUIRE
            $KERNEL_FEATURE_KFUNC_BPF_CPUMASK_RELEASE
        ]
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
        kernel_features: [
            $KERNEL_FEATURE_KFUNC_BPF_CPUMASK_CREATE
            $KERNEL_FEATURE_KFUNC_BPF_CPUMASK_SET_CPU
            $KERNEL_FEATURE_KFUNC_BPF_CPUMASK_FIRST
            $KERNEL_FEATURE_KFUNC_BPF_CPUMASK_RELEASE
        ]
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
        kernel_features: [
            $KERNEL_FEATURE_MAP_VALUE_KPTR
            $KERNEL_FEATURE_BPF_KPTR_XCHG
            $KERNEL_FEATURE_KFUNC_BPF_TASK_FROM_PID
            $KERNEL_FEATURE_KFUNC_BPF_TASK_RELEASE
        ]
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
        kernel_features: [
            $KERNEL_FEATURE_MAP_VALUE_KPTR
            $KERNEL_FEATURE_BPF_KPTR_XCHG
            $KERNEL_FEATURE_KFUNC_BPF_TASK_FROM_PID
            $KERNEL_FEATURE_KFUNC_BPF_TASK_RELEASE
        ]
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
        kernel_features: [
            $KERNEL_FEATURE_MAP_VALUE_KPTR
            $KERNEL_FEATURE_BPF_KPTR_XCHG
            $KERNEL_FEATURE_KFUNC_BPF_CPUMASK_CREATE
            $KERNEL_FEATURE_KFUNC_BPF_CPUMASK_RELEASE
        ]
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
        kernel_features: [
            $KERNEL_FEATURE_MAP_VALUE_KPTR
            $KERNEL_FEATURE_BPF_KPTR_XCHG
            $KERNEL_FEATURE_KFUNC_BPF_CPUMASK_CREATE
            $KERNEL_FEATURE_KFUNC_BPF_CPUMASK_RELEASE
        ]
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
        kernel_features: [
            $KERNEL_FEATURE_MAP_VALUE_KPTR
            $KERNEL_FEATURE_BPF_KPTR_XCHG
            $KERNEL_FEATURE_KFUNC_BPF_GET_TASK_EXE_FILE
            $KERNEL_FEATURE_KFUNC_BPF_PUT_FILE
        ]
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
        kernel_features: [
            $KERNEL_FEATURE_MAP_VALUE_KPTR
            $KERNEL_FEATURE_BPF_KPTR_XCHG
            $KERNEL_FEATURE_KFUNC_BPF_GET_TASK_EXE_FILE
            $KERNEL_FEATURE_KFUNC_BPF_PUT_FILE
        ]
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
        kernel_features: [
            $KERNEL_FEATURE_MAP_VALUE_KPTR
            $KERNEL_FEATURE_BPF_KPTR_XCHG
            $KERNEL_FEATURE_KFUNC_BPF_CGROUP_FROM_ID
            $KERNEL_FEATURE_KFUNC_BPF_CGROUP_RELEASE
        ]
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
        kernel_features: [
            $KERNEL_FEATURE_MAP_VALUE_KPTR
            $KERNEL_FEATURE_BPF_KPTR_XCHG
            $KERNEL_FEATURE_KFUNC_BPF_CGROUP_RELEASE
        ]
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
        kernel_features: [
            $KERNEL_FEATURE_MAP_VALUE_KPTR
            $KERNEL_FEATURE_BPF_KPTR_XCHG
        ]
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
        kernel_features: [
            $KERNEL_FEATURE_MAP_VALUE_KPTR
            $KERNEL_FEATURE_BPF_KPTR_XCHG
            $KERNEL_FEATURE_KFUNC_BPF_CGROUP_FROM_ID
            $KERNEL_FEATURE_KFUNC_BPF_CGROUP_RELEASE
        ]
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
        kernel_features: [$KERNEL_FEATURE_BPF_TIMER_INIT]
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
        kernel_features: [$KERNEL_FEATURE_BPF_TIMER_SET_CALLBACK]
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
        kernel_features: [$KERNEL_FEATURE_BPF_TIMER_START]
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
        kernel_features: [$KERNEL_FEATURE_BPF_TIMER_CANCEL]
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
        kernel_features: [$KERNEL_FEATURE_BPF_USER_RINGBUF_DRAIN]
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
        kernel_features: [$KERNEL_FEATURE_BPF_LOOP]
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
        kernel_features: [$KERNEL_FEATURE_BPF_FOR_EACH_MAP_ELEM]
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
        kernel_features: [$KERNEL_FEATURE_BPF_USER_RINGBUF_DRAIN]
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
        kernel_features: [$KERNEL_FEATURE_BPF_USER_RINGBUF_DRAIN]
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
        kernel_features: [$KERNEL_FEATURE_BPF_CSUM_DIFF]
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
        kernel_features: [$KERNEL_FEATURE_BPF_REDIRECT_NEIGH]
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

def helper-kernel-feature [name: string] {
    let matches = ($HELPER_KERNEL_FEATURES | where {|entry| $entry.name == $name })
    if ($matches | is-empty) {
        null
    } else {
        $matches | first | get feature
    }
}

def kfunc-kernel-feature [name: string] {
    let matches = ($KFUNC_KERNEL_FEATURES | where {|entry| $entry.name == $name })
    if ($matches | is-empty) {
        null
    } else {
        $matches | first | get feature
    }
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

    if ($target_text | str starts-with "xdp:") and $field == "ifindex" {
        return { matched: true, feature: $KERNEL_FEATURE_CTX_INGRESS_IFINDEX }
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
        if $field == "protocol" {
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
        if $field == "protocol" {
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
        if $field == "protocol" {
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

def program-map-kernel-features [source: string] {
    mut features = []

    for line in ($source | lines) {
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
    }

    $features
}

def program-helper-kernel-features [source: string] {
    mut features = []

    for line in ($source | lines) {
        let parts = ($line | split row "helper-call ")
        if ($parts | length) <= 1 {
            continue
        }

        for raw_call in ($parts | skip 1) {
            let raw_name = ($raw_call | str trim | split row " " | first)
            let helper_name = (normalize-helper-name-token $raw_name)
            let feature = (helper-kernel-feature $helper_name)
            if $feature != null {
                $features = (append-missing-kernel-features $features [$feature])
            }
        }
    }

    $features
}

def program-kfunc-kernel-features [source: string] {
    mut features = []

    for kfunc_name in (program-kfunc-names $source) {
        let feature = (kfunc-kernel-feature $kfunc_name)
        if $feature != null {
            $features = (append-missing-kernel-features $features [$feature])
        }
    }

    $features
}

def program-context-field-kernel-features [source: string target] {
    mut features = []

    for line in ($source | lines) {
        let parts = ($line | split row '$ctx.')
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
        }
    }

    $features
}

def program-surface-helper-kernel-features [source: string target] {
    mut features = []
    let target_text = ($target | default "")

    if ($source | str contains "tail-call") {
        $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_TAIL_CALL])
    }

    for line in ($source | lines) {
        if ($line | str contains "helper-call ") {
            continue
        }

        if ($line | str contains "redirect-map ") {
            $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_REDIRECT_MAP])
        }
        if ($line | str contains "assign-socket ") {
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
            } else if ($target_text | str starts-with "xdp:") or ($target_text | str starts-with "tc:") or ($target_text | str starts-with "tcx:") or ($target_text | str starts-with "netkit:") {
                $features = (append-missing-kernel-features $features [$KERNEL_FEATURE_BPF_REDIRECT])
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
        if ($target | str contains "sched_ext_ops") {
            $features = ($features | append $KERNEL_FEATURE_STRUCT_OPS_SCHED_EXT)
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
    $features = (append-missing-kernel-features $features (program-map-value-kernel-features $program))
    $features = (append-missing-kernel-features $features (program-helper-kernel-features $program))
    $features = (append-missing-kernel-features $features (program-kfunc-kernel-features $program))
    $features = (append-missing-kernel-features $features (program-context-field-kernel-features $program ($fixture | get -o target)))
    $features = (append-missing-kernel-features $features (program-surface-helper-kernel-features $program ($fixture | get -o target)))

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

    {
        name: $fixture.name
        category: (optional $fixture category "")
        tier: (fixture-tier $fixture)
        local: $fixture.local
        kernel: $fixture.kernel
        requires: (optional $fixture requires [])
        kernel_requires: (optional $fixture kernel_requires [])
        kernel_features: (fixture-kernel-features $fixture)
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
        print $"tier=($row.tier) category=($row.category) total=($row.total) local_accept=($row.local_accept) local_reject=($row.local_reject) local_skip=($row.local_skip) kernel_accept=($row.kernel_accept) kernel_reject=($row.kernel_reject) kernel_skip=($row.kernel_skip) kernel_accept_versioned=($row.kernel_accept_versioned) kernel_accept_unversioned=($row.kernel_accept_unversioned)($compat_text)"
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

def validate-kernel-feature-metadata [fixture] {
    let features = (optional $fixture kernel_features [])
    let keys = ($features | each {|feature| $feature | get -o key })

    for key in ($keys | uniq) {
        if $key == null or $key == "" {
            fail $"fixture ($fixture.name) declares a kernel feature without key"
        }

        let count = ($keys | where {|candidate| $candidate == $key } | length)
        if $count > 1 {
            fail $"fixture ($fixture.name) declares duplicate kernel feature key: ($key)"
        }
    }

    for feature in $features {
        let key = ($feature | get -o key)
        let min_kernel = ($feature | get -o min_kernel)
        let max_kernel = ($feature | get -o max_kernel_exclusive)
        let source = ($feature | get -o source)

        if $key == null or $key == "" {
            fail $"fixture ($fixture.name) declares a kernel feature without key"
        }
        if $min_kernel == null or $min_kernel == "" {
            fail $"fixture ($fixture.name) kernel feature ($key) missing min_kernel"
        }
        if $source == null or $source == "" {
            fail $"fixture ($fixture.name) kernel feature ($key) missing source"
        }

        parse-kernel-version $min_kernel | ignore
        if $max_kernel != null and $max_kernel != "" {
            parse-kernel-version $max_kernel | ignore
            if (kernel-version-compare $max_kernel $min_kernel) <= 0 {
                fail $"fixture ($fixture.name) kernel feature ($key) max_kernel_exclusive=($max_kernel) must be greater than min_kernel=($min_kernel)"
            }
        }
    }

    for kfunc_name in (program-kfunc-names (fixture-program $fixture)) {
        let key = $"kfunc:($kfunc_name)"
        let known_feature = (kfunc-kernel-feature $kfunc_name)
        let explicit_feature = ($keys | any {|candidate| $candidate == $key })
        if $known_feature == null and not $explicit_feature {
            fail $"fixture ($fixture.name) calls kfunc ($kfunc_name) without source-backed kernel metadata; add it to KFUNC_KERNEL_FEATURES or declare explicit kernel_features metadata"
        }
    }
}

def validate-fixture-metadata [fixtures] {
    let names = ($fixtures | each {|fixture| $fixture.name })

    for name in ($names | uniq) {
        let count = ($names | where {|candidate| $candidate == $name } | length)
        if $count > 1 {
            fail $"duplicate verifier fixture name: ($name)"
        }
    }

    for fixture in $fixtures {
        validate-tier-option $"fixture ($fixture.name)" ($fixture | get -o tier)
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

def fixture-matches-filters [fixture category tag tier exclude_tier local_status kernel_status] {
    (
        ($category == null or (optional $fixture category "") == $category)
        and (fixture-has-tag $fixture $tag)
        and ($tier == null or (fixture-tier $fixture) == $tier)
        and ($exclude_tier == null or (fixture-tier $fixture) != $exclude_tier)
        and ($local_status == null or $fixture.local == $local_status)
        and ($kernel_status == null or $fixture.kernel == $kernel_status)
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

def select-fixtures [fixture_name category tag tier exclude_tier local_status kernel_status] {
    validate-tier-option "selected" $tier
    validate-tier-option "excluded" $exclude_tier
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
        | where {|fixture| fixture-matches-filters $fixture $category $tag $tier $exclude_tier $local_status $kernel_status }
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
    let fixtures = (select-fixtures $fixture $category $tag $selected_tier $exclude_tier $local_status $kernel_status)

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
            print $"($summary.name) local=($summary.local) kernel=($summary.kernel) category=($summary.category) tier=($summary.tier) requires=($summary.requires | str join ',') kernel_requires=($summary.kernel_requires | str join ',') effective_min_kernel=($summary.effective_min_kernel) effective_max_kernel_exclusive=($summary.effective_max_kernel_exclusive) kernel_features=(kernel-feature-labels $summary.kernel_features | str join ',') tags=($summary.tags | str join ',')($compat_text)"
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
