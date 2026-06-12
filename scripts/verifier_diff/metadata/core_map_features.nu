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
