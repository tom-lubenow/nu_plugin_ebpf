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
